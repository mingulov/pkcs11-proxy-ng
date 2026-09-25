use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_types::CkRv;

use super::super::super::context_manager::ClientContextId;
use super::super::super::context_manager::ObjectMetadata;
use super::super::HandlerContext;
use super::super::convert_template_opt;
use super::super::service_utils::{
    backend_object_known_public, ck_rv_only, context_maps_backend_object,
    find_result_visible_to_context, register_object_handles, resolve_object_authz_context,
    resolve_session, session_slot_login_state, spawn_backend,
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
    let result =
        spawn_backend(move || backend.find_objects_init(session, template.as_deref())).await?;

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

    // F-04: the QUERYING context's login state gates private-object
    // visibility. A logged-out context must not observe private objects
    // (bare handles or counts) even while another tenant holds the backend
    // logged in — reads and USE already refuse; this closes the existence
    // oracle. Logged-in behavior is bit-for-bit unchanged (no extra calls).
    let logged_in =
        session_slot_login_state(&ctx.context_manager, &ctx_id, virtual_session).await.is_some();

    // Transparency path: neither per_object_active() nor per_class_active() →
    // no grant anywhere restricts by uid or class; every principal is unrestricted.
    // CROSS-PROC-001: still filters by session-object ownership (a context
    // must not observe another context's session objects — the backend
    // application is shared, so unfiltered enumeration leaks across
    // tenants). Same loop contract as below: pull past fully-filtered
    // batches, return empty ONLY on genuine backend exhaustion.
    // (Logged-out callers take the F-04 loop below instead.)
    if !ctx.token_policy.per_object_active() && !ctx.token_policy.per_class_active() && logged_in {
        let mut kept_backends = Vec::new();
        loop {
            let batch_backend = ctx.backend.clone();
            // CkSessionHandle and u32 are Copy; the move closure copies them.
            let batch = match spawn_backend(move || batch_backend.find_objects(session, max_count))
                .await?
            {
                Ok(objects) => objects,
                Err(ck_error) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
                        ck_rv: ck_error.0,
                        object_handles: vec![],
                    }));
                }
            };

            // COUNT ONLY — never log the labels/IDs/values (design V15/D9 redaction).
            if crate::server::resilience::observe_find_result(batch.len()) {
                tracing::warn!(
                    object_count = batch.len(),
                    "pathological object population: C_FindObjects result exceeds resilience threshold"
                );
            }

            if batch.is_empty() {
                break;
            }

            for &backend_object in &batch {
                if find_result_visible_to_context(ctx, &ctx_id, session, backend_object).await {
                    kept_backends.push(backend_object);
                }
            }

            if !kept_backends.is_empty() {
                break;
            }
        }

        return match register_object_handles(&ctx.context_manager, &ctx_id, &kept_backends).await {
            Some(object_handles) => Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
                ck_rv: CkRv::OK.0,
                object_handles,
            })),
            None => Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
                ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
                object_handles: vec![],
            })),
        };
    }

    // F-04 logged-out transparency path: no uid/class policy is active, but
    // the caller is logged out, so each batch is filtered to known-public
    // objects (fail-closed: probe failure hides). Same loop contract as the
    // authz filter below — pull past fully-filtered batches and return empty
    // ONLY on genuine backend exhaustion, so a filtered batch is never
    // mistaken for end-of-search. Resilience observes each backend batch
    // (population size), never the kept subset.
    if !ctx.token_policy.per_object_active() && !ctx.token_policy.per_class_active() {
        let mut kept_backends = Vec::new();
        loop {
            let batch_backend = ctx.backend.clone();
            // CkSessionHandle and u32 are Copy; the move closure copies them.
            let batch = match spawn_backend(move || batch_backend.find_objects(session, max_count))
                .await?
            {
                Ok(objects) => objects,
                Err(ck_error) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
                        ck_rv: ck_error.0,
                        object_handles: vec![],
                    }));
                }
            };

            // COUNT ONLY — never log the labels/IDs/values (design V15/D9 redaction).
            if crate::server::resilience::observe_find_result(batch.len()) {
                tracing::warn!(
                    object_count = batch.len(),
                    "pathological object population: C_FindObjects result exceeds resilience threshold"
                );
            }

            if batch.is_empty() {
                break;
            }

            for &backend_object in &batch {
                // CROSS-PROC-001 first (ownership is the cheaper check for
                // mapped handles and hides foreign session objects before
                // the privacy probe spends a backend call on them).
                if find_result_visible_to_context(ctx, &ctx_id, session, backend_object).await
                    && backend_object_known_public(ctx, session, backend_object).await
                {
                    kept_backends.push(backend_object);
                }
            }

            if !kept_backends.is_empty() {
                break;
            }
        }

        return match register_object_handles(&ctx.context_manager, &ctx_id, &kept_backends).await {
            Some(object_handles) => Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
                ck_rv: CkRv::OK.0,
                object_handles,
            })),
            None => Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
                ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
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
            // (collapsible_match is un-actionable here: the nested F-04 probe
            // awaits, and `.await` is illegal in a match guard.)
            #[allow(clippy::collapsible_match)]
            match meta {
                Some(meta)
                    if !meta.unique_id.is_empty()
                        && meta.unique_id.expose(|raw| {
                            ctx.token_policy.allows_object_use(&identity, &label, &serial, raw)
                        })
                        && (!ctx.token_policy.per_class_active()
                            || meta.class.is_some_and(|c| {
                                ctx.token_policy.allows_class(&identity, &label, &serial, c)
                            })) =>
                {
                    // CROSS-PROC-001: authz-kept session objects additionally
                    // require context ownership (no extra probe: meta already
                    // carries is_token; mapped handles were minted or vetted
                    // here). Ordered before the login probe so foreign
                    // session objects cost no privacy call.
                    let owned_or_token = meta.is_token
                        || context_maps_backend_object(
                            &ctx.context_manager,
                            &ctx_id,
                            backend_object,
                        )
                        .await;
                    // F-04: authz-kept objects are additionally login-filtered —
                    // a logged-out caller sees only known-public objects (probe
                    // failure hides). Ordered after authz so denied objects cost
                    // no probe; logged-in callers short-circuit with no extra call.
                    if owned_or_token
                        && (logged_in
                            || backend_object_known_public(ctx, session, backend_object).await)
                    {
                        kept_backends.push(backend_object);
                        kept_metas.push(meta);
                    }
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
    use crate::server::context_manager::{ContextManager, LoginState};
    use crate::server::grpc_service::HandlerContext;
    use crate::server::handle_map::BackendHandle;
    use crate::server::slot_map::BackendSlotId;

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
        // F-04: both declare CKA_PRIVATE=false (the native default for objects
        // created without it) so the logged-out login filter keeps them and
        // these authz/transparency tests keep testing what they claim.
        let obj_a = mock.create_object(backend_session, Some(&[])).unwrap();
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
            CkAttributeType::PRIVATE,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            obj_a,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_A_BYTES.to_vec().into())),
        );
        let obj_b = mock.create_object(backend_session, Some(&[])).unwrap();
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
            CkAttributeType::PRIVATE,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            obj_b,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_B_BYTES.to_vec().into())),
        );

        // Prime the mock search state so find_objects_impl accepts the call.
        mock.find_objects_init(backend_session, Some(&[])).unwrap();
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

        // CROSS-PROC-001: these fixtures model same-context objects, so
        // pre-register them (unmapped session objects are now hidden as
        // foreign-owned; these tests target authz/login filtering, not
        // ownership).
        ctx_mgr
            .get_context(&ctx_id, |c| {
                c.object_handles.insert(BackendHandle(obj_a.0));
                c.object_handles.insert(BackendHandle(obj_b.0));
            })
            .await;

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
        let obj_no_uid = mock.create_object(backend_session, Some(&[])).unwrap();
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

        mock.find_objects_init(backend_session, Some(&[])).unwrap();
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
            Some(UID_A_BYTES.to_vec().into()),
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
        // F-04: all three declare CKA_PRIVATE=false (native default) so the
        // logged-out login filter keeps the authz-allowed one.
        let obj_d1 = mock.create_object(backend_session, Some(&[])).unwrap();
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
            CkAttributeType::PRIVATE,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            obj_d1,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_B_BYTES.to_vec().into())),
        );
        let obj_d2 = mock.create_object(backend_session, Some(&[])).unwrap();
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
            CkAttributeType::PRIVATE,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            obj_d2,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_B_BYTES.to_vec().into())),
        );
        let obj_a = mock.create_object(backend_session, Some(&[])).unwrap();
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
            CkAttributeType::PRIVATE,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            obj_a,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_A_BYTES.to_vec().into())),
        );

        // Prime the multi-part op and configure the cursor-based result list.
        // With max_object_count=2: batch1=[obj_d1,obj_d2], batch2=[obj_a], then [].
        mock.find_objects_init(backend_session, Some(&[])).unwrap();
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
        // CROSS-PROC-001: fixtures model same-context objects (this test
        // targets authz pull-past, not ownership).
        ctx_mgr
            .get_context(&ctx_id, |c| {
                c.object_handles.insert(BackendHandle(obj_d1.0));
                c.object_handles.insert(BackendHandle(obj_d2.0));
                c.object_handles.insert(BackendHandle(obj_a.0));
            })
            .await;
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
        mock.find_objects_init(backend_session, Some(&[])).unwrap();

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
        // F-04: declares CKA_PRIVATE=false (native default) so the logged-out
        // login filter keeps it and this test keeps testing class gating.
        let obj_sk = mock.create_object(backend_session, Some(&[])).unwrap();
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
            CkAttributeType::PRIVATE,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            obj_sk,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_A_BYTES.to_vec().into())),
        );

        // obj_pk: PUBLIC_KEY — denied class; must be invisible.
        let obj_pk = mock.create_object(backend_session, Some(&[])).unwrap();
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
            CkAttributeType::PRIVATE,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            obj_pk,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_B_BYTES.to_vec().into())),
        );

        mock.find_objects_init(backend_session, Some(&[])).unwrap();
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
        // CROSS-PROC-001: fixtures model same-context objects (this test
        // targets per-class authz, not ownership).
        ctx_mgr
            .get_context(&ctx_id, |c| {
                c.object_handles.insert(BackendHandle(obj_sk.0));
                c.object_handles.insert(BackendHandle(obj_pk.0));
            })
            .await;

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

    // ── F-04: find-enumeration login filtering ────────────────────────────────

    /// Set the F-04 privacy bit plus the CLASS/TOKEN attributes every
    /// conformant-backend fixture object carries.
    fn set_privacy_fixture(mock: &MockBackend, object: CkObjectHandle, is_private: bool) {
        mock.set_attribute(
            object,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        );
        mock.set_attribute(
            object,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            object,
            CkAttributeType::PRIVATE,
            MockAttributeSlot::Value(CkAttributeValue::Bool(is_private)),
        );
    }

    /// Shared F-04 setup: two backend objects — the first private, the second
    /// public — with the mock find cursor primed to `[private, public]`.
    /// The querying context is LOGGED OUT (no `login_state` entry), emulating
    /// the oracle scenario where another tenant holds the backend logged in.
    /// Returns (ctx, ctx_id, virtual_session, obj_priv, obj_pub).
    async fn setup_privacy_find(
        policy: Arc<TokenPolicy>,
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

        let obj_priv = mock.create_object(backend_session, Some(&[])).unwrap();
        set_privacy_fixture(&mock, obj_priv, true);
        let obj_pub = mock.create_object(backend_session, Some(&[])).unwrap();
        set_privacy_fixture(&mock, obj_pub, false);

        mock.find_objects_init(backend_session, Some(&[])).unwrap();
        mock.set_find_objects_result(vec![obj_priv, obj_pub]);

        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(BackendSlotId(CkSlotId(0)), "MockToken".into(), "0001".into());
        let ctx_id = ctx_mgr.create_context(Some(CONFINED_IDENTITY.into())).await.unwrap();

        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(BackendHandle(backend_session.0), BackendSlotId(CkSlotId(0)))
            })
            .await
            .unwrap();

        // CROSS-PROC-001: these fixtures model same-context objects, so
        // pre-register them (unmapped session objects are now hidden as
        // foreign-owned; these tests target login filtering, not ownership).
        ctx_mgr
            .get_context(&ctx_id, |c| {
                c.object_handles.insert(BackendHandle(obj_priv.0));
                c.object_handles.insert(BackendHandle(obj_pub.0));
            })
            .await;

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;

        (ctx, ctx_id, virtual_session.0, obj_priv, obj_pub)
    }

    /// Resolve a returned virtual handle back to its backend handle.
    async fn resolve_virtual(
        ctx: &HandlerContext,
        ctx_id: &crate::server::context_manager::ClientContextId,
        virtual_handle: u64,
    ) -> Option<u64> {
        ctx.context_manager
            .get_context(ctx_id, |c| {
                c.object_handles.resolve(crate::server::handle_map::VirtualHandle(virtual_handle))
            })
            .await
            .flatten()
            .map(|h| h.0)
    }

    /// Log the fixture context in on slot 0 (the F-04 "unchanged" control).
    async fn log_in_fixture(
        ctx: &HandlerContext,
        ctx_id: &crate::server::context_manager::ClientContextId,
    ) {
        ctx.context_manager
            .get_context(ctx_id, |c| {
                c.login_state.insert(BackendSlotId(CkSlotId(0)), LoginState::User)
            })
            .await;
    }

    /// Helper: run find with an explicit max_count, return the inner response.
    async fn run_find_objects_with_max(
        ctx: &HandlerContext,
        ctx_id: &crate::server::context_manager::ClientContextId,
        virtual_session: u64,
        max_object_count: u32,
    ) -> pkcs11_proxy_ng_proto::FindObjectsResponse {
        super::find_objects(
            ctx,
            Request::new(pkcs11_proxy_ng_proto::FindObjectsRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: virtual_session,
                max_object_count,
            }),
        )
        .await
        .expect("find_objects must not return a transport error")
        .into_inner()
    }

    // ── F-04 Test 1: logged-out transparency path hides private objects ──────

    #[tokio::test]
    async fn f04_logged_out_hides_private_objects_transparency_path() {
        // Oracle scenario on the transparency path (no per-object/class
        // policy): a logged-out context must observe neither the private
        // object's bare handle nor its count. max_count=1 forces two backend
        // batches ([priv] then [pub]) so the test also proves the filter
        // pulls past a fully-filtered batch instead of returning a
        // premature end-of-search 0.
        let policy = Arc::new(TokenPolicy::from_config(&AuthConfig::default()).unwrap());
        let (ctx, ctx_id, vs, obj_priv, obj_pub) = setup_privacy_find(policy).await;

        let resp = run_find_objects_with_max(&ctx, &ctx_id, vs, 1).await;

        assert_eq!(resp.ck_rv, CkRv::OK.0, "filtering must not surface an error");
        assert_eq!(
            resp.object_handles.len(),
            1,
            "logged-out context must see exactly the public object (no count oracle)"
        );
        assert_eq!(
            resolve_virtual(&ctx, &ctx_id, resp.object_handles[0]).await,
            Some(obj_pub.0),
            "the single returned handle must map to obj_pub, never obj_priv {obj_priv:?}"
        );
    }

    // ── F-04 Test 2: logged-in transparency path bit-for-bit unchanged ───────

    #[tokio::test]
    async fn f04_logged_in_sees_all_objects_transparency_path() {
        // Control: the identical logged-IN enumeration returns both objects
        // unchanged (single backend batch, no filtering).
        let policy = Arc::new(TokenPolicy::from_config(&AuthConfig::default()).unwrap());
        let (ctx, ctx_id, vs, obj_priv, obj_pub) = setup_privacy_find(policy).await;
        log_in_fixture(&ctx, &ctx_id).await;

        let resp = run_find_objects(&ctx, &ctx_id, vs).await;

        assert_eq!(resp.ck_rv, CkRv::OK.0);
        assert_eq!(resp.object_handles.len(), 2, "logged-in behavior must be unchanged");
        let mut resolved = Vec::new();
        for vh in &resp.object_handles {
            resolved.push(resolve_virtual(&ctx, &ctx_id, *vh).await);
        }
        assert!(
            resolved.contains(&Some(obj_priv.0)) && resolved.contains(&Some(obj_pub.0)),
            "logged-in enumeration must return both objects unchanged"
        );
    }

    // ── F-04 Test 3: probe failure hides (fail-closed) ───────────────────────

    #[tokio::test]
    async fn f04_logged_out_probe_failure_hides_object() {
        // An object whose CKA_PRIVATE probe fails (attribute absent on a
        // nonconformant backend) has unknown privacy: a logged-out context
        // must not observe it. Fail-closed matches the authz filter in this
        // same function (fetch failure drops); unlike USE there is no
        // backend verdict to fall back to.
        let policy = Arc::new(TokenPolicy::from_config(&AuthConfig::default()).unwrap());

        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        // CLASS + TOKEN only: no CKA_PRIVATE, so the probe fails with
        // ATTRIBUTE_TYPE_INVALID.
        let obj_unknown = mock.create_object(backend_session, Some(&[])).unwrap();
        mock.set_attribute(
            obj_unknown,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        );
        mock.set_attribute(
            obj_unknown,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.find_objects_init(backend_session, Some(&[])).unwrap();
        mock.set_find_objects_result(vec![obj_unknown]);

        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(BackendSlotId(CkSlotId(0)), "MockToken".into(), "0001".into());
        let ctx_id = ctx_mgr.create_context(Some(CONFINED_IDENTITY.into())).await.unwrap();
        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(BackendHandle(backend_session.0), BackendSlotId(CkSlotId(0)))
            })
            .await
            .unwrap();
        // CROSS-PROC-001: pre-register so the object passes ownership — this
        // test targets the F-04 privacy-probe filter, not ownership.
        ctx_mgr
            .get_context(&ctx_id, |c| {
                c.object_handles.insert(BackendHandle(obj_unknown.0));
            })
            .await;
        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;

        let resp = run_find_objects(&ctx, &ctx_id, virtual_session.0).await;

        assert_eq!(resp.ck_rv, CkRv::OK.0, "must return CKR_OK (no oracle)");
        assert_eq!(
            resp.object_handles.len(),
            0,
            "unknown-privacy object must be fail-closed (dropped) for logged-out callers"
        );
    }

    // ── F-04 Test 4: login filter composes with the authz filter ─────────────

    #[tokio::test]
    async fn f04_logged_out_hides_private_under_authz_filter() {
        // Authz-allowed but private objects must still be hidden from a
        // logged-out caller: both objects carry the allowed uid_A, so the
        // authz filter keeps both and only the login filter drops obj_priv.
        let policy = confined_policy(CONFINED_IDENTITY, "MockToken", UID_A_HEX);

        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        let obj_priv = mock.create_object(backend_session, Some(&[])).unwrap();
        set_privacy_fixture(&mock, obj_priv, true);
        mock.set_attribute(
            obj_priv,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_A_BYTES.to_vec().into())),
        );
        let obj_pub = mock.create_object(backend_session, Some(&[])).unwrap();
        set_privacy_fixture(&mock, obj_pub, false);
        mock.set_attribute(
            obj_pub,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_A_BYTES.to_vec().into())),
        );
        mock.find_objects_init(backend_session, Some(&[])).unwrap();
        mock.set_find_objects_result(vec![obj_priv, obj_pub]);

        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(BackendSlotId(CkSlotId(0)), "MockToken".into(), "0001".into());
        let ctx_id = ctx_mgr.create_context(Some(CONFINED_IDENTITY.into())).await.unwrap();
        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(BackendHandle(backend_session.0), BackendSlotId(CkSlotId(0)))
            })
            .await
            .unwrap();
        // CROSS-PROC-001: fixtures model same-context objects (see above).
        ctx_mgr
            .get_context(&ctx_id, |c| {
                c.object_handles.insert(BackendHandle(obj_priv.0));
                c.object_handles.insert(BackendHandle(obj_pub.0));
            })
            .await;
        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;

        let resp = run_find_objects(&ctx, &ctx_id, virtual_session.0).await;

        assert_eq!(resp.ck_rv, CkRv::OK.0);
        assert_eq!(
            resp.object_handles.len(),
            1,
            "logged-out caller must see only the public object even when both pass authz"
        );
        assert_eq!(
            resolve_virtual(&ctx, &ctx_id, resp.object_handles[0]).await,
            Some(obj_pub.0),
            "the kept handle must map to obj_pub"
        );
    }

    #[tokio::test]
    async fn i2_transparent_when_neither_per_object_nor_per_class_active() {
        // Regression guard: when neither per_object_active() nor per_class_active(),
        // the transparency path keeps both objects (login filter keeps both: fixtures are public).
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

    // ── CROSS-PROC-001: cross-context session-object isolation ──────────────

    /// Set CLASS + TOKEN + PRIVATE + UNIQUE_ID on a fixture object
    /// (conformant-backend shape; both fixtures carry the allowed uid so
    /// authz is not a factor and only ownership filters).
    fn set_ownership_fixture(mock: &MockBackend, object: CkObjectHandle, is_token: bool) {
        mock.set_attribute(
            object,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(CkObjectClass::DATA.0)),
        );
        mock.set_attribute(
            object,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(is_token)),
        );
        mock.set_attribute(
            object,
            CkAttributeType::PRIVATE,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            object,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_A_BYTES.to_vec().into())),
        );
    }

    /// Shared ownership setup: two backend objects UNKNOWN to the querying
    /// context — one session-scoped, one token-scoped (both public, so the
    /// login filter is not a factor) — cursor primed to [session, token].
    /// Returns (ctx, ctx_id, virtual_session, obj_sess, obj_tok).
    async fn setup_ownership_find(
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

        let obj_sess = mock.create_object(backend_session, Some(&[])).unwrap();
        set_ownership_fixture(&mock, obj_sess, false);
        let obj_tok = mock.create_object(backend_session, Some(&[])).unwrap();
        set_ownership_fixture(&mock, obj_tok, true);

        mock.find_objects_init(backend_session, Some(&[])).unwrap();
        mock.set_find_objects_result(vec![obj_sess, obj_tok]);

        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(BackendSlotId(CkSlotId(0)), "MockToken".into(), "0001".into());
        let ctx_id = ctx_mgr.create_context(identity).await.unwrap();

        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(BackendHandle(backend_session.0), BackendSlotId(CkSlotId(0)))
            })
            .await
            .unwrap();

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;

        (ctx, ctx_id, virtual_session.0, obj_sess, obj_tok)
    }

    /// Pre-register a backend object in the context (models "minted here").
    async fn register_owned(
        ctx: &HandlerContext,
        ctx_id: &crate::server::context_manager::ClientContextId,
        backend_object: CkObjectHandle,
    ) {
        ctx.context_manager
            .get_context(ctx_id, |c| {
                c.object_handles.insert(BackendHandle(backend_object.0));
            })
            .await;
    }

    fn default_policy() -> Arc<TokenPolicy> {
        Arc::new(TokenPolicy::from_config(&AuthConfig::default()).unwrap())
    }

    #[tokio::test]
    async fn ownership_transparency_hides_foreign_session_object() {
        // Logged-in, no policy: the unknown session object belongs to
        // another context and must be hidden; the token object is shown.
        let (ctx, ctx_id, vs, _sess, obj_tok) =
            setup_ownership_find(default_policy(), Some(CONFINED_IDENTITY.into())).await;
        log_in_fixture(&ctx, &ctx_id).await;

        let resp = run_find_objects(&ctx, &ctx_id, vs).await;

        assert_eq!(resp.ck_rv, CkRv::OK.0);
        assert_eq!(resp.object_handles.len(), 1, "foreign session object must be hidden");
        assert_eq!(
            resolve_virtual(&ctx, &ctx_id, resp.object_handles[0]).await,
            Some(obj_tok.0),
            "the kept handle must map to the token object"
        );
    }

    #[tokio::test]
    async fn ownership_transparency_pulls_past_fully_filtered_batch() {
        // max_count=1: first backend batch is [foreign session] (filtered),
        // so the transparency path must pull the next batch ([token])
        // instead of returning 0 (which the client would read as
        // end-of-search).
        let (ctx, ctx_id, vs, _sess, obj_tok) =
            setup_ownership_find(default_policy(), Some(CONFINED_IDENTITY.into())).await;
        log_in_fixture(&ctx, &ctx_id).await;

        let resp = run_find_objects_with_max(&ctx, &ctx_id, vs, 1).await;

        assert_eq!(resp.ck_rv, CkRv::OK.0);
        assert_eq!(resp.object_handles.len(), 1, "must pull past the filtered batch");
        assert_eq!(
            resolve_virtual(&ctx, &ctx_id, resp.object_handles[0]).await,
            Some(obj_tok.0),
            "the kept handle must map to the token object"
        );
    }

    #[tokio::test]
    async fn ownership_transparency_shows_own_session_object() {
        // Same-context session objects (any session) stay visible:
        // pre-registered session object + unknown token object → both shown.
        let (ctx, ctx_id, vs, obj_sess, _tok) =
            setup_ownership_find(default_policy(), Some(CONFINED_IDENTITY.into())).await;
        register_owned(&ctx, &ctx_id, obj_sess).await;
        log_in_fixture(&ctx, &ctx_id).await;

        let resp = run_find_objects(&ctx, &ctx_id, vs).await;

        assert_eq!(resp.ck_rv, CkRv::OK.0);
        assert_eq!(resp.object_handles.len(), 2, "own session object must stay visible");
    }

    #[tokio::test]
    async fn ownership_logged_out_hides_foreign_public_session_object() {
        // Logged-out, no policy: both fixtures are public (login filter
        // keeps both), but the foreign session object must still hide.
        let (ctx, ctx_id, vs, _sess, obj_tok) =
            setup_ownership_find(default_policy(), Some(CONFINED_IDENTITY.into())).await;

        let resp = run_find_objects(&ctx, &ctx_id, vs).await;

        assert_eq!(resp.ck_rv, CkRv::OK.0);
        assert_eq!(
            resp.object_handles.len(),
            1,
            "foreign session object must hide even when public"
        );
        assert_eq!(
            resolve_virtual(&ctx, &ctx_id, resp.object_handles[0]).await,
            Some(obj_tok.0),
            "the kept handle must map to the token object"
        );
    }

    #[tokio::test]
    async fn ownership_authz_hides_unmapped_session_object() {
        // Authz path: both fixtures carry the allowed uid (authz keeps
        // both), logged in (login filter keeps both) — only ownership
        // drops the unmapped session object, with no extra probe (meta).
        let policy = confined_policy(CONFINED_IDENTITY, "MockToken", UID_A_HEX);
        let (ctx, ctx_id, vs, _sess, obj_tok) =
            setup_ownership_find(policy, Some(CONFINED_IDENTITY.into())).await;
        log_in_fixture(&ctx, &ctx_id).await;

        let resp = run_find_objects(&ctx, &ctx_id, vs).await;

        assert_eq!(resp.ck_rv, CkRv::OK.0);
        assert_eq!(
            resp.object_handles.len(),
            1,
            "unmapped session object must hide under the authz filter"
        );
        assert_eq!(
            resolve_virtual(&ctx, &ctx_id, resp.object_handles[0]).await,
            Some(obj_tok.0),
            "the kept handle must map to the token object"
        );
    }
}
