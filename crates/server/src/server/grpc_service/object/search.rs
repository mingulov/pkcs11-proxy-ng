use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_types::CkRv;

use super::super::super::context_manager::ClientContextId;
use super::super::super::context_manager::ObjectMetadata;
use super::super::HandlerContext;
use super::super::convert_template;
use super::super::service_utils::{
    ck_rv_only, register_object_handles, resolve_object_authz_context, resolve_session,
    spawn_backend,
};

pub(super) async fn find_objects_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::FindObjectsInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::FindObjectsInitResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsInitResponse {
                ck_rv: error.0,
            }));
        }
    };

    let template = match convert_template_opt(&req.template, req.template_null) {
        Ok(template) => template,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsInitResponse {
                ck_rv: error,
            }));
        }
    };

    let backend = ctx.backend.clone();
    let result = spawn_backend(move || backend.find_objects_init(session, &template)).await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsInitResponse { ck_rv: ck_rv_only(result) }))
}

pub(super) async fn find_objects(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::FindObjectsRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::FindObjectsResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);
    // Save the virtual session handle; resolve_session copies the u64 (Copy type),
    // so the raw value is still needed for resolve_object_authz_context later.
    let virtual_session = req.session_handle;

    let session = match resolve_session(&ctx.context_manager, &ctx_id, virtual_session).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
                ck_rv: error.0,
                object_handles: vec![],
            }));
        }
    };

    let max_count = req.max_object_count;

    // Transparency path: neither per_object_active() nor per_class_active() →
    // no grant anywhere restricts by uid or class; every principal is unrestricted.
    // Single backend call, no filter — byte-identical to pre-filter.
    if !ctx.token_policy.per_object_active() && !ctx.token_policy.per_class_active() {
        let backend = ctx.backend.clone();
        // CkSessionHandle is Copy; the move closure copies it.
        let result = spawn_backend(move || backend.find_objects(session, max_count)).await?;
        return match result {
            Ok(backend_objects) => {
                // COUNT ONLY — never log the labels/IDs/values (design V15/D9 redaction).
                if crate::server::resilience::observe_find_result(backend_objects.len()) {
                    tracing::warn!(
                        object_count = backend_objects.len(),
                        "pathological object population: C_FindObjects result exceeds resilience threshold"
                    );
                }
                match register_object_handles(&ctx.context_manager, &ctx_id, &backend_objects).await
                {
                    Some(object_handles) => {
                        Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
                            ck_rv: CkRv::OK.0,
                            object_handles,
                        }))
                    }
                    None => Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
                        ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
                        object_handles: vec![],
                    })),
                }
            }
            Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
                ck_rv: error.0,
                object_handles: vec![],
            })),
        };
    }

    // Per-object / per-class enumeration filter (G3-PR2/G3-PR3, ADR-0012).
    // Resolve identity + (label, serial) ONCE before the inner loop.
    // Fail-closed: if the authz context cannot be resolved, return an empty
    // result with CKR_OK — indistinguishable from "template matched nothing".
    let Some((identity, label, serial)) =
        resolve_object_authz_context(ctx, &ctx_id, virtual_session).await
    else {
        return Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
            ck_rv: CkRv::OK.0,
            object_handles: vec![],
        }));
    };

    // Inner loop: pull successive backend batches, filtering each.
    // Returns accumulated kept objects as soon as ≥1 is found (a non-empty result
    // may be fewer than max_count — that is legal C_FindObjects behaviour; the
    // client continues looping). Returns empty ONLY when the backend itself returns
    // an empty batch (genuine exhaustion), which is the correct loop-terminator a
    // client can rely on. This prevents a fully-denied batch from being returned as
    // 0 to the client, which would be indistinguishable from end-of-search and would
    // silently hide authorized objects appearing later in the backend's enumeration.
    let mut kept_backends = Vec::new();
    let mut kept_metas: Vec<ObjectMetadata> = Vec::new();
    loop {
        let batch_backend = ctx.backend.clone();
        // CkSessionHandle and u32 are Copy; the move closure copies them.
        let batch =
            match spawn_backend(move || batch_backend.find_objects(session, max_count)).await? {
                Ok(objects) => objects,
                Err(ck_error) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
                        ck_rv: ck_error.0,
                        object_handles: vec![],
                    }));
                }
            };

        // COUNT ONLY — never log the labels/IDs/values (design V15/D9 redaction).
        // observe_find_result sees each backend batch independently so resilience
        // monitors the backend population size regardless of what the filter keeps.
        if crate::server::resilience::observe_find_result(batch.len()) {
            tracing::warn!(
                object_count = batch.len(),
                "pathological object population: C_FindObjects result exceeds resilience threshold"
            );
        }

        if batch.is_empty() {
            // Backend is genuinely exhausted — return whatever was accumulated.
            // An empty kept set here means the search is truly over (correct 0).
            break;
        }

        for &backend_object in &batch {
            let meta =
                super::super::authorization::fetch_object_metadata(ctx, session, backend_object)
                    .await;
            // I2 fix: keep the object only when uid check AND class check both pass.
            // M2: meta.class is Option — None is fail-closed when per_class_active().
            match meta {
                Some(meta)
                    if !meta.unique_id.is_empty()
                        && ctx.token_policy.allows_object_use(
                            &identity,
                            &label,
                            &serial,
                            &meta.unique_id,
                        )
                        && (!ctx.token_policy.per_class_active()
                            || meta.class.is_some_and(|c| {
                                ctx.token_policy.allows_class(&identity, &label, &serial, c)
                            })) =>
                {
                    kept_backends.push(backend_object);
                    kept_metas.push(meta);
                }
                // Fail-closed: empty/absent uid, fetch failure, denied uid, denied/absent class.
                _ => {}
            }
        }

        if !kept_backends.is_empty() {
            // At least one authorized object found — return now. Returning fewer
            // than max_count is legal; the client loops until it receives an empty
            // response (which this server now only sends on genuine exhaustion).
            break;
        }
        // The entire batch was denied — pull the next backend batch rather than
        // returning 0, which the client would mistake for end-of-search.
    }

    match register_object_handles(&ctx.context_manager, &ctx_id, &kept_backends).await {
        Some(virtual_handles) => {
            // Cache each kept object's metadata under its new virtual handle so
            // use-time gates (gate_object_handle) skip the re-fetch.
            // cache_object_metadata internally skips token objects (I2 fix).
            for (&virtual_id, meta) in virtual_handles.iter().zip(kept_metas) {
                ctx.context_manager.cache_object_metadata(&ctx_id, virtual_id, meta).await;
            }
            Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
                ck_rv: CkRv::OK.0,
                object_handles: virtual_handles,
            }))
        }
        None => Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
            object_handles: vec![],
        })),
    }
}

pub(super) async fn find_objects_final(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::FindObjectsFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::FindObjectsFinalResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsFinalResponse {
                ck_rv: error.0,
            }));
        }
    };

    let backend = ctx.backend.clone();
    let result = spawn_backend(move || backend.find_objects_final(session)).await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsFinalResponse { ck_rv: ck_rv_only(result) }))
}

// ── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend, mock::MockAttributeSlot};
    use pkcs11_proxy_ng_types::*;
    use tonic::Request;

    use crate::config::{
        AuthConfig, ExtractPolicyConfig, GrantSpec, PolicyEntry, RichGrantConfig, TokenAccessSpec,
    };
    use crate::server::auth::policy::TokenPolicy;
    use crate::server::context_manager::ContextManager;
    use crate::server::grpc_service::HandlerContext;
    use crate::server::handle_map::BackendHandle;

    // Object A: in the confined-principal's allowed list.
    const UID_A_HEX: &str = "aabbcc";
    const UID_A_BYTES: [u8; 3] = [0xaa, 0xbb, 0xcc];
    // Object B: NOT in the confined list.
    const UID_B_BYTES: [u8; 3] = [0x11, 0x22, 0x33];
    const CONFINED_IDENTITY: &str = "uid=1000";
    const UNCONFINED_IDENTITY: &str = "uid=2000";

    /// Build a TokenPolicy where `confined_identity` is restricted to objects
    /// with `allowed_uid_hex` on the token labelled `token_label`.
    /// Any other identity has no matching grant and is therefore unrestricted.
    fn confined_policy(
        confined_identity: &str,
        token_label: &str,
        allowed_uid_hex: &str,
    ) -> Arc<TokenPolicy> {
        Arc::new(
            TokenPolicy::from_config(&AuthConfig {
                allow_all_authenticated: false,
                anonymous_principal: None,
                policy: vec![PolicyEntry {
                    identity: confined_identity.into(),
                    tokens: TokenAccessSpec::Specific(vec![GrantSpec::Rich(RichGrantConfig {
                        token: format!("label:{token_label}"),
                        classes: None,
                        mechanisms: None,
                        extract: ExtractPolicyConfig::Allow,
                        objects: Some(vec![crate::config::ObjectAclSpec::Bare(
                            allowed_uid_hex.into(),
                        )]),
                    })]),
                }],
            })
            .expect("policy must parse"),
        )
    }

    /// Shared test setup: two backend objects (A = uid_A, B = uid_B), a
    /// find_objects_init already called, and the mock override set to return
    /// [obj_a, obj_b]. Returns (ctx, ctx_id, virtual_session, obj_a, obj_b).
    async fn setup_two_object_find(
        policy: Arc<TokenPolicy>,
        identity: Option<String>,
    ) -> (
        HandlerContext,
        crate::server::context_manager::ClientContextId,
        u64,
        CkObjectHandle,
        CkObjectHandle,
    ) {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();

        // Create two objects and attach their UIDs. Also set CLASS and TOKEN so
        // fetch_object_metadata's 3-element template succeeds (conformant backend).
        let obj_a = mock.create_object(backend_session, &[]).unwrap();
        mock.set_attribute(
            obj_a,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(
                pkcs11_proxy_ng_types::CkObjectClass::SECRET_KEY.0,
            )),
        );
        mock.set_attribute(
            obj_a,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            obj_a,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_A_BYTES.to_vec())),
        );
        let obj_b = mock.create_object(backend_session, &[]).unwrap();
        mock.set_attribute(
            obj_b,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(
                pkcs11_proxy_ng_types::CkObjectClass::SECRET_KEY.0,
            )),
        );
        mock.set_attribute(
            obj_b,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            obj_b,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_B_BYTES.to_vec())),
        );

        // Prime the mock search state so find_objects_impl accepts the call.
        mock.find_objects_init(backend_session, &[]).unwrap();
        mock.set_find_objects_result(vec![obj_a, obj_b]);

        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx_id = ctx_mgr.create_context(identity).await.unwrap();

        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;

        (ctx, ctx_id, virtual_session.0, obj_a, obj_b)
    }

    /// Helper: build and send a FindObjectsRequest, return the inner response.
    async fn run_find_objects(
        ctx: &HandlerContext,
        ctx_id: &crate::server::context_manager::ClientContextId,
        virtual_session: u64,
    ) -> pkcs11_proxy_ng_proto::FindObjectsResponse {
        super::find_objects(
            ctx,
            Request::new(pkcs11_proxy_ng_proto::FindObjectsRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: virtual_session,
                max_object_count: 32,
            }),
        )
        .await
        .expect("find_objects must not return a transport error")
        .into_inner()
    }

    // ── Test 1: confined principal sees only its allowed object ───────────────

    #[tokio::test]
    async fn find_objects_confined_principal_receives_only_allowed_object() {
        let policy = confined_policy(CONFINED_IDENTITY, "MockToken", UID_A_HEX);
        let (ctx, ctx_id, vs, obj_a, _obj_b) =
            setup_two_object_find(policy, Some(CONFINED_IDENTITY.into())).await;

        let resp = run_find_objects(&ctx, &ctx_id, vs).await;

        assert_eq!(resp.ck_rv, CkRv::OK.0, "must return CKR_OK");
        assert_eq!(resp.object_handles.len(), 1, "confined principal must see exactly 1 object");

        // The returned virtual handle must resolve to obj_a (uid_A in allowed list).
        let virtual_handle = resp.object_handles[0];
        let resolved = ctx
            .context_manager
            .get_context(&ctx_id, |c| {
                c.object_handles.resolve(crate::server::handle_map::VirtualHandle(virtual_handle))
            })
            .await
            .flatten();
        assert_eq!(
            resolved.map(|h| h.0),
            Some(obj_a.0),
            "the single returned handle must map to obj_a (uid_A)"
        );
    }

    // ── Test 2: unconfined principal sees all objects ─────────────────────────

    #[tokio::test]
    async fn find_objects_unconfined_principal_sees_all_objects() {
        // per_object_active==true (because CONFINED_IDENTITY has objects=[uid_A]),
        // but UNCONFINED_IDENTITY has no matching grant → allows_object_use==true → no filter.
        let policy = confined_policy(CONFINED_IDENTITY, "MockToken", UID_A_HEX);
        let (ctx, ctx_id, vs, _obj_a, _obj_b) =
            setup_two_object_find(policy, Some(UNCONFINED_IDENTITY.into())).await;

        let resp = run_find_objects(&ctx, &ctx_id, vs).await;

        assert_eq!(resp.ck_rv, CkRv::OK.0);
        assert_eq!(
            resp.object_handles.len(),
            2,
            "unconfined principal must see both objects even when per_object_active==true"
        );
    }

    // ── Test 3: transparency path — per_object_active()==false ────────────────

    #[tokio::test]
    async fn find_objects_transparent_when_per_object_inactive() {
        let policy = Arc::new(TokenPolicy::from_config(&AuthConfig::default()).unwrap());
        assert!(!policy.per_object_active(), "default policy must have per_object_active()==false");
        let (ctx, ctx_id, vs, _obj_a, _obj_b) =
            setup_two_object_find(policy, Some(CONFINED_IDENTITY.into())).await;

        let resp = run_find_objects(&ctx, &ctx_id, vs).await;

        assert_eq!(resp.ck_rv, CkRv::OK.0);
        assert_eq!(
            resp.object_handles.len(),
            2,
            "with per_object_active()==false all backend objects pass through unchanged"
        );
    }

    // ── Test 4: fail-closed on absent CKA_UNIQUE_ID ───────────────────────────

    #[tokio::test]
    async fn find_objects_fail_closed_on_absent_unique_id() {
        // An object with no CKA_UNIQUE_ID must be dropped even if the principal
        // is the token owner — fail-closed at empty/absent uid.
        let policy = confined_policy(CONFINED_IDENTITY, "MockToken", UID_A_HEX);

        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        // Object created with CLASS and TOKEN but NO CKA_UNIQUE_ID.
        let obj_no_uid = mock.create_object(backend_session, &[]).unwrap();
        mock.set_attribute(
            obj_no_uid,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(
                pkcs11_proxy_ng_types::CkObjectClass::SECRET_KEY.0,
            )),
        );
        mock.set_attribute(
            obj_no_uid,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );

        mock.find_objects_init(backend_session, &[]).unwrap();
        mock.set_find_objects_result(vec![obj_no_uid]);

        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx_id = ctx_mgr.create_context(Some(CONFINED_IDENTITY.into())).await.unwrap();
        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();
        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;

        let resp = super::find_objects(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::FindObjectsRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: virtual_session.0,
                max_object_count: 32,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(resp.ck_rv, CkRv::OK.0, "must return CKR_OK (no oracle)");
        assert_eq!(
            resp.object_handles.len(),
            0,
            "object with absent CKA_UNIQUE_ID must be fail-closed (dropped)"
        );
    }

    // ── Test 5: metadata cached on kept handle after find ────────────────────

    #[tokio::test]
    async fn find_objects_caches_metadata_for_kept_object() {
        // After find_objects, the kept object's metadata (uid, class, is_token)
        // must be pre-cached under its new virtual handle so use-time
        // gate_object_handle skips the re-fetch.
        let policy = confined_policy(CONFINED_IDENTITY, "MockToken", UID_A_HEX);
        let (ctx, ctx_id, vs, _obj_a, _obj_b) =
            setup_two_object_find(policy, Some(CONFINED_IDENTITY.into())).await;

        let resp = run_find_objects(&ctx, &ctx_id, vs).await;
        assert_eq!(resp.ck_rv, CkRv::OK.0);
        assert_eq!(resp.object_handles.len(), 1);

        let virtual_id = resp.object_handles[0];
        let cached = ctx.context_manager.object_metadata(&ctx_id, virtual_id).await;
        assert_eq!(
            cached.map(|m| m.unique_id),
            Some(UID_A_BYTES.to_vec()),
            "kept object's uid must be pre-cached under its virtual handle"
        );
    }

    // ── Test 6: inner loop pulls past a fully-denied batch ────────────────────

    #[tokio::test]
    async fn find_objects_inner_loop_pulls_past_fully_denied_batch() {
        // Regression test for the premature-0 bug: when the first backend batch
        // contains only denied objects, the server must pull the next batch rather
        // than returning 0 (which a client reads as end-of-search).
        //
        // Setup: 3 objects in the mock — obj_d1 and obj_d2 have uid_B (denied),
        // obj_a has uid_A (allowed). With max_object_count=2, the mock cursor
        // returns batch1=[obj_d1, obj_d2] then batch2=[obj_a] then [].
        // The inner loop must see batch1 entirely denied, pull batch2, find obj_a
        // allowed, and return its virtual handle — NOT 0 (premature end-of-search).
        let policy = confined_policy(CONFINED_IDENTITY, "MockToken", UID_A_HEX);

        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();

        // Two denied objects with uid_B, then the allowed object with uid_A.
        // Set CLASS and TOKEN on each (required by fetch_object_metadata).
        let obj_d1 = mock.create_object(backend_session, &[]).unwrap();
        mock.set_attribute(
            obj_d1,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(
                pkcs11_proxy_ng_types::CkObjectClass::SECRET_KEY.0,
            )),
        );
        mock.set_attribute(
            obj_d1,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            obj_d1,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_B_BYTES.to_vec())),
        );
        let obj_d2 = mock.create_object(backend_session, &[]).unwrap();
        mock.set_attribute(
            obj_d2,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(
                pkcs11_proxy_ng_types::CkObjectClass::SECRET_KEY.0,
            )),
        );
        mock.set_attribute(
            obj_d2,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            obj_d2,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_B_BYTES.to_vec())),
        );
        let obj_a = mock.create_object(backend_session, &[]).unwrap();
        mock.set_attribute(
            obj_a,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(
                pkcs11_proxy_ng_types::CkObjectClass::SECRET_KEY.0,
            )),
        );
        mock.set_attribute(
            obj_a,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            obj_a,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_A_BYTES.to_vec())),
        );

        // Prime the multi-part op and configure the cursor-based result list.
        // With max_object_count=2: batch1=[obj_d1,obj_d2], batch2=[obj_a], then [].
        mock.find_objects_init(backend_session, &[]).unwrap();
        mock.set_find_objects_result(vec![obj_d1, obj_d2, obj_a]);

        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx_id = ctx_mgr.create_context(Some(CONFINED_IDENTITY.into())).await.unwrap();
        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();
        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;

        let resp = super::find_objects(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::FindObjectsRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: virtual_session.0,
                // Small batch size to force multi-batch: 2 < 3 total objects.
                max_object_count: 2,
            }),
        )
        .await
        .expect("find_objects must not return a transport error")
        .into_inner();

        assert_eq!(resp.ck_rv, CkRv::OK.0, "must return CKR_OK");
        assert_eq!(
            resp.object_handles.len(),
            1,
            "inner loop must pull past the all-denied batch1 and return obj_a from batch2"
        );

        // The returned virtual handle must resolve to obj_a (uid_A in allowed list).
        let virtual_handle = resp.object_handles[0];
        let resolved = ctx
            .context_manager
            .get_context(&ctx_id, |c| {
                c.object_handles.resolve(crate::server::handle_map::VirtualHandle(virtual_handle))
            })
            .await
            .flatten();
        assert_eq!(
            resolved.map(|h| h.0),
            Some(obj_a.0),
            "the returned handle must map to obj_a (uid_A), not the denied obj_d1/obj_d2"
        );
    }

    // ── Test 7: genuine backend exhaustion returns 0 handles ──────────────────

    #[tokio::test]
    async fn find_objects_genuine_exhaustion_returns_zero_handles() {
        // When the backend is immediately exhausted (returns [] on first call),
        // the inner loop must terminate correctly and return 0 handles with CKR_OK.
        // This distinguishes the "real end-of-search" 0 from the "premature-0" bug.
        let policy = confined_policy(CONFINED_IDENTITY, "MockToken", UID_A_HEX);

        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();

        // No set_find_objects_result → mock default returns [] immediately (exhausted).
        mock.find_objects_init(backend_session, &[]).unwrap();

        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx_id = ctx_mgr.create_context(Some(CONFINED_IDENTITY.into())).await.unwrap();
        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();
        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;

        let resp = super::find_objects(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::FindObjectsRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: virtual_session.0,
                max_object_count: 32,
            }),
        )
        .await
        .expect("find_objects must not return a transport error")
        .into_inner();

        assert_eq!(resp.ck_rv, CkRv::OK.0, "genuine exhaustion must return CKR_OK");
        assert_eq!(
            resp.object_handles.len(),
            0,
            "genuine backend exhaustion must return 0 handles — the correct loop-terminator"
        );
    }

    // ── Test 8: I2 — class-confined principal cannot enumerate denied-class objects ─

    /// Build a class-only policy (no uid restriction) for the given identity.
    fn class_confined_policy(
        identity: &str,
        token_label: &str,
        allowed_class: &str,
    ) -> Arc<TokenPolicy> {
        Arc::new(
            TokenPolicy::from_config(&AuthConfig {
                allow_all_authenticated: false,
                anonymous_principal: None,
                policy: vec![PolicyEntry {
                    identity: identity.into(),
                    tokens: TokenAccessSpec::Specific(vec![GrantSpec::Rich(RichGrantConfig {
                        token: format!("label:{token_label}"),
                        classes: Some(vec![allowed_class.into()]),
                        mechanisms: None,
                        extract: ExtractPolicyConfig::Allow,
                        objects: None, // no uid restriction — pure class gate
                    })]),
                }],
            })
            .expect("class-confined policy must parse"),
        )
    }

    #[tokio::test]
    async fn i2_class_confined_find_returns_only_allowed_class_objects() {
        // I2 fix: a class-confined principal (classes=["secret_key"], objects:None)
        // must see only SECRET_KEY objects from find_objects. The PUBLIC_KEY object
        // must be invisible (silently dropped). per_object_active()==false but
        // per_class_active()==true → the filter must still run (I2 fix).
        let policy = class_confined_policy(CONFINED_IDENTITY, "MockToken", "secret_key");
        assert!(
            policy.per_class_active(),
            "class-confined policy must have per_class_active==true"
        );
        assert!(
            !policy.per_object_active(),
            "class-only policy must have per_object_active==false"
        );

        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();

        // obj_sk: SECRET_KEY — allowed class.
        let obj_sk = mock.create_object(backend_session, &[]).unwrap();
        mock.set_attribute(
            obj_sk,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        );
        mock.set_attribute(
            obj_sk,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            obj_sk,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_A_BYTES.to_vec())),
        );

        // obj_pk: PUBLIC_KEY — denied class; must be invisible.
        let obj_pk = mock.create_object(backend_session, &[]).unwrap();
        mock.set_attribute(
            obj_pk,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(CkObjectClass::PUBLIC_KEY.0)),
        );
        mock.set_attribute(
            obj_pk,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            obj_pk,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_B_BYTES.to_vec())),
        );

        mock.find_objects_init(backend_session, &[]).unwrap();
        mock.set_find_objects_result(vec![obj_sk, obj_pk]);

        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx_id = ctx_mgr.create_context(Some(CONFINED_IDENTITY.into())).await.unwrap();

        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;

        let resp = super::find_objects(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::FindObjectsRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: virtual_session.0,
                max_object_count: 32,
            }),
        )
        .await
        .expect("find_objects must not return a transport error")
        .into_inner();

        assert_eq!(resp.ck_rv, CkRv::OK.0, "must return CKR_OK");
        assert_eq!(
            resp.object_handles.len(),
            1,
            "I2: class-confined principal must see only secret_key objects (public_key absent)"
        );

        // The returned handle must resolve to obj_sk (SECRET_KEY), not obj_pk.
        let virtual_handle = resp.object_handles[0];
        let resolved = ctx
            .context_manager
            .get_context(&ctx_id, |c| {
                c.object_handles.resolve(crate::server::handle_map::VirtualHandle(virtual_handle))
            })
            .await
            .flatten();
        assert_eq!(
            resolved.map(|h| h.0),
            Some(obj_sk.0),
            "I2: the returned handle must map to obj_sk (SECRET_KEY), not obj_pk (PUBLIC_KEY)"
        );
    }

    #[tokio::test]
    async fn i2_transparent_when_neither_per_object_nor_per_class_active() {
        // Regression guard: when neither per_object_active() nor per_class_active(),
        // the transparency path must still return all objects unchanged (no filter).
        let policy = Arc::new(TokenPolicy::from_config(&AuthConfig::default()).unwrap());
        assert!(!policy.per_object_active());
        assert!(!policy.per_class_active());
        let (ctx, ctx_id, vs, _obj_a, _obj_b) =
            setup_two_object_find(policy, Some(CONFINED_IDENTITY.into())).await;

        let resp = run_find_objects(&ctx, &ctx_id, vs).await;

        assert_eq!(resp.ck_rv, CkRv::OK.0);
        assert_eq!(
            resp.object_handles.len(),
            2,
            "transparency path: neither gate active → all objects pass through"
        );
    }
}
