use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_types::CkRv;

use super::super::super::context_manager::ClientContextId;
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

    let template = match convert_template(&req.template) {
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
    let backend = ctx.backend.clone();
    // CkSessionHandle is Copy; the move closure copies it so `session` remains
    // available for the per-object filter below.
    let result = spawn_backend(move || backend.find_objects(session, max_count)).await?;

    match result {
        Ok(backend_objects) => {
            // COUNT ONLY — never log the labels/IDs/values (design V15/D9 redaction).
            // observe_find_result sees the FULL backend count (resilience monitors
            // the backend population size, independent of what the filter keeps).
            if crate::server::resilience::observe_find_result(backend_objects.len()) {
                tracing::warn!(
                    object_count = backend_objects.len(),
                    "pathological object population: C_FindObjects result exceeds resilience threshold"
                );
            }

            // Transparency path: per_object_active()==false means no grant anywhere
            // in the loaded config has an `objects` restriction, so every principal
            // is unrestricted. Skip all authz work — byte-identical to pre-filter.
            if !ctx.token_policy.per_object_active() {
                return match register_object_handles(
                    &ctx.context_manager,
                    &ctx_id,
                    &backend_objects,
                )
                .await
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
                };
            }

            // Per-object enumeration filter (G3-PR2, ADR-0012).
            // Resolve identity + (label, serial) once for all objects in this batch.
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

            // For each backend object: fetch its CKA_UNIQUE_ID and apply the policy.
            // Fail-closed: absent/empty uid or a deny → silently drop the object.
            // The spec allows find_objects to return fewer than max_object_count
            // when some matches are filtered; callers loop until they get 0 (C4).
            let mut kept_backends = Vec::new();
            let mut kept_uids: Vec<Vec<u8>> = Vec::new();
            for &backend_object in &backend_objects {
                let uid = super::super::authorization::fetch_object_unique_id(
                    ctx,
                    session,
                    backend_object,
                )
                .await;
                match uid {
                    Some(uid)
                        if !uid.is_empty()
                            && ctx
                                .token_policy
                                .allows_object_use(&identity, &label, &serial, &uid) =>
                    {
                        kept_backends.push(backend_object);
                        kept_uids.push(uid);
                    }
                    // Fail-closed: empty/absent uid, or deny — drop.
                    _ => {}
                }
            }

            match register_object_handles(&ctx.context_manager, &ctx_id, &kept_backends).await {
                Some(virtual_handles) => {
                    // Cache each kept object's uid under its new virtual handle so
                    // use-time gates (gate_object_handle) skip the re-fetch.
                    for (&virtual_id, uid) in virtual_handles.iter().zip(kept_uids) {
                        ctx.context_manager.cache_object_unique_id(&ctx_id, virtual_id, uid).await;
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
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
            ck_rv: error.0,
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
                        objects: Some(vec![allowed_uid_hex.into()]),
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

        // Create two objects and attach their UIDs.
        let obj_a = mock.create_object(backend_session, &[]).unwrap();
        mock.set_attribute(
            obj_a,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(UID_A_BYTES.to_vec())),
        );
        let obj_b = mock.create_object(backend_session, &[]).unwrap();
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
        ctx_mgr.register_slot(CkSlotId(0)).await;
        ctx_mgr.cache_token_info(CkSlotId(0), "MockToken".into(), "0001".into());
        let ctx_id = ctx_mgr.create_context(identity).await.unwrap();

        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(BackendHandle(backend_session.0), CkSlotId(0))
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
        // Object created with NO CKA_UNIQUE_ID.
        let obj_no_uid = mock.create_object(backend_session, &[]).unwrap();

        mock.find_objects_init(backend_session, &[]).unwrap();
        mock.set_find_objects_result(vec![obj_no_uid]);

        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(CkSlotId(0)).await;
        ctx_mgr.cache_token_info(CkSlotId(0), "MockToken".into(), "0001".into());
        let ctx_id = ctx_mgr.create_context(Some(CONFINED_IDENTITY.into())).await.unwrap();
        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(BackendHandle(backend_session.0), CkSlotId(0))
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

    // ── Test 5: uid cached on kept handle after find ──────────────────────────

    #[tokio::test]
    async fn find_objects_caches_uid_for_kept_object() {
        // After find_objects, the kept object's CKA_UNIQUE_ID must be pre-cached
        // under its new virtual handle so use-time gate_object_handle skips re-fetch.
        let policy = confined_policy(CONFINED_IDENTITY, "MockToken", UID_A_HEX);
        let (ctx, ctx_id, vs, _obj_a, _obj_b) =
            setup_two_object_find(policy, Some(CONFINED_IDENTITY.into())).await;

        let resp = run_find_objects(&ctx, &ctx_id, vs).await;
        assert_eq!(resp.ck_rv, CkRv::OK.0);
        assert_eq!(resp.object_handles.len(), 1);

        let virtual_id = resp.object_handles[0];
        let cached = ctx.context_manager.object_unique_id(&ctx_id, virtual_id).await;
        assert_eq!(
            cached,
            Some(UID_A_BYTES.to_vec()),
            "kept object's uid must be pre-cached under its virtual handle"
        );
    }
}
