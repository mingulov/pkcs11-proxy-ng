use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_types::{CkAttribute, CkAttributeType, CkAttributeValue, CkRv};

use super::super::super::context_manager::ClientContextId;
use super::super::super::handle_map::VirtualHandle;
use super::super::HandlerContext;
use super::super::convert_template_opt;
use super::super::service_utils::{
    backend_object_token_state, ck_rv_only, ensure_private_mint_allowed, object_is_private,
    register_session_object_handle, resolve_session, resolve_session_and_object, spawn_backend,
    template_declares_private_object, template_declares_token_object, template_has_private_attr,
};

pub(super) async fn create_object(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::CreateObjectRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CreateObjectResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::CreateObjectResponse {
                ck_rv: error.0,
                object_handle: 0,
            }));
        }
    };

    let template = match convert_template_opt(&req.template, req.template_null) {
        Ok(template) => template,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::CreateObjectResponse {
                ck_rv: error,
                object_handle: 0,
            }));
        }
    };

    // A NULL template carries no attributes; classification treats it as empty.
    let template_view = template.as_deref().unwrap_or(&[]);

    // D6(1): refuse minting a private object while logically logged out.
    if let Err(rv) = ensure_private_mint_allowed(
        &ctx.context_manager,
        &ctx_id,
        req.session_handle,
        template_view,
    )
    .await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::CreateObjectResponse {
            ck_rv: rv.0,
            object_handle: 0,
        }));
    }

    // W1-L7-05: mint-time class gate — a class-confined principal must not
    // persist a denied-class object (the USE-time gate alone leaves the
    // object on the token). Denied before the backend runs.
    if !super::super::authorization::class_mint_permitted(
        ctx,
        &ctx_id,
        req.session_handle,
        template_view,
        None,
    )
    .await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::CreateObjectResponse {
            ck_rv: CkRv::ATTRIBUTE_VALUE_INVALID.0,
            object_handle: 0,
        }));
    }

    // Classify before the template is moved into the backend call: a session
    // object's handle is evicted when its session closes; a token object's
    // handle persists across sessions (B2). The privacy bit is recorded for
    // the D6(1) USE enforcement.
    let is_token_object = template_declares_token_object(template_view);
    let is_private = template_declares_private_object(template_view);
    let virtual_session = VirtualHandle(req.session_handle);
    let backend = ctx.backend.clone();
    let result = spawn_backend(move || backend.create_object(session, template.as_deref())).await?;

    match result {
        Ok(object) => Ok(Response::new(pkcs11_proxy_ng_proto::CreateObjectResponse {
            ck_rv: CkRv::OK.0,
            object_handle: register_session_object_handle(
                &ctx.context_manager,
                &ctx_id,
                virtual_session,
                object,
                is_token_object,
                Some(is_private),
            )
            .await,
        })),
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::CreateObjectResponse {
            ck_rv: error.0,
            object_handle: 0,
        })),
    }
}

/// Only one explicitly encoded CK_BBOOL is reliable fallback evidence.
/// Duplicate, absent, NULL, wrong-width, and non-boolean values remain unknown;
/// the template itself is still forwarded verbatim for the provider to decide.
fn explicit_copy_token_flag(template: &[CkAttribute]) -> Option<bool> {
    let mut attributes = template.iter().filter(|attr| attr.attr_type == CkAttributeType::TOKEN);
    let value = attributes.next()?.value.as_ref()?;
    if attributes.next().is_some() {
        return None;
    }
    match value {
        CkAttributeValue::Bool(token) => Some(*token),
        CkAttributeValue::Bytes(bytes) | CkAttributeValue::String(bytes) => {
            bytes.expose(|raw| match raw {
                [0] => Some(false),
                [1] => Some(true),
                _ => None,
            })
        }
        _ => None,
    }
}

pub(super) async fn copy_object(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::CopyObjectRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CopyObjectResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, object) =
        match resolve_session_and_object(ctx, &ctx_id, req.session_handle, req.object_handle).await
        {
            Ok(handles) => handles,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::CopyObjectResponse {
                    ck_rv: error.0,
                    new_object_handle: 0,
                }));
            }
        };

    let template = match convert_template_opt(&req.template, req.template_null) {
        Ok(template) => template,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::CopyObjectResponse {
                ck_rv: error,
                new_object_handle: 0,
            }));
        }
    };

    // A NULL template carries no attributes; classification treats it as empty.
    let template_view = template.as_deref().unwrap_or(&[]);

    // D6(1): refuse copying TO a private object while logically logged out.
    // (Copying FROM a private source is refused by the USE check inside
    // resolve_session_and_object above.)
    if let Err(rv) = ensure_private_mint_allowed(
        &ctx.context_manager,
        &ctx_id,
        req.session_handle,
        template_view,
    )
    .await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::CopyObjectResponse {
            ck_rv: rv.0,
            new_object_handle: 0,
        }));
    }

    // W1-L7-05: mint-time class gate (see create_object). A copy without a
    // class override inherits its (USE-allowed) source's class.
    if !super::super::authorization::class_mint_permitted(
        ctx,
        &ctx_id,
        req.session_handle,
        template_view,
        None,
    )
    .await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::CopyObjectResponse {
            ck_rv: CkRv::ATTRIBUTE_VALUE_INVALID.0,
            new_object_handle: 0,
        }));
    }

    let token_override = explicit_copy_token_flag(template_view);
    // The copy's privacy, computed before the template moves into the backend
    // call: template-declared when present (an explicit CKA_PRIVATE=False
    // makes a public copy even of a private source), else inherited from the
    // source object (our recorded bit, else one read-only backend probe) so
    // later USE of the copy needs no probe.
    let new_is_private = if template_has_private_attr(template_view) {
        template_declares_private_object(template_view)
    } else {
        object_is_private(ctx, &ctx_id, req.object_handle, session, object).await
    };
    let virtual_session = VirtualHandle(req.session_handle);
    let backend = ctx.backend.clone();
    let result =
        spawn_backend(move || backend.copy_object(session, object, template.as_deref())).await?;

    match result {
        Ok(new_object) => {
            // Copy templates inherit omitted attributes; unlike creation, an
            // absent CKA_TOKEN is not false. Classify the actual copied object
            // so explicit overrides and discovered source handles work alike.
            // Unknown metadata falls back only to a valid explicit CK_BBOOL.
            // A positively observed false always wins over a true override.
            // With neither evidence, retain conservative session ownership;
            // never replace native success or lose the new virtual handle.
            let is_token = backend_object_token_state(ctx, session, new_object)
                .await
                .or(token_override)
                .unwrap_or(false);
            Ok(Response::new(pkcs11_proxy_ng_proto::CopyObjectResponse {
                ck_rv: CkRv::OK.0,
                new_object_handle: register_session_object_handle(
                    &ctx.context_manager,
                    &ctx_id,
                    virtual_session,
                    new_object,
                    is_token,
                    Some(new_is_private),
                )
                .await,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::CopyObjectResponse {
            ck_rv: error.0,
            new_object_handle: 0,
        })),
    }
}

pub(super) async fn destroy_object(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DestroyObjectRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DestroyObjectResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, object) =
        match resolve_session_and_object(ctx, &ctx_id, req.session_handle, req.object_handle).await
        {
            Ok(handles) => handles,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::DestroyObjectResponse {
                    ck_rv: error.0,
                }));
            }
        };

    let backend = ctx.backend.clone();
    let result = spawn_backend(move || backend.destroy_object(session, object)).await?;

    // On successful destroy, evict the virtual→backend mapping, the cached
    // unique ID, the created-set entry, the recorded privacy bit, and all
    // cached attribute entries so a recycled virtual handle cannot alias stale
    // data, inherit created-status or privacy, or serve stale coalesced
    // attributes for the now-destroyed object (B2, G3, G3-PR3 Task 2, R2 I1,
    // D6(1)), and record a destroy tombstone so later uses answer the
    // handle-invalid family locally (T20). Revoke the daemon-wide authz
    // generation (W1-L13-18): the freed backend handle may be recycled by
    // another context's create, which must invalidate every context's
    // cached token-object metadata.
    if result.is_ok() {
        let virtual_object = VirtualHandle(req.object_handle);
        let _ = ctx
            .context_manager
            .get_context(&ctx_id, |client_ctx| {
                client_ctx.object_handles.remove(virtual_object);
                // T20 tombstone: later uses of this handle answer the
                // handle-invalid family locally (forward-0's backend
                // verdict is backend-specific). Mirrors the removal above.
                client_ctx.destroyed_objects.insert(virtual_object);
                client_ctx.object_metadata.remove(&virtual_object);
                client_ctx.token_object_metadata.remove(&virtual_object);
                client_ctx.created_objects.remove(&virtual_object);
                client_ctx.object_private.remove(&virtual_object);
                // I1: evict cached attribute entries for this object (R2 coalescer).
                // Mirrors object_metadata + created_objects eviction so a recycled
                // virtual handle cannot return stale cached attributes. Matches the
                // eviction contract documented on the attr_cache field (context_manager.rs).
                client_ctx.attr_cache.retain(|(vh, _), _| *vh != virtual_object);
            })
            .await;
        ctx.context_manager.revoke_authz_generation();
    }

    Ok(Response::new(pkcs11_proxy_ng_proto::DestroyObjectResponse { ck_rv: ck_rv_only(result) }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tonic::Request;

    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use pkcs11_proxy_ng_types::*;

    use crate::server::context_manager::{CachedAttr, ContextManager, ObjectMetadata};
    use crate::server::grpc_service::HandlerContext;
    use crate::server::handle_map::BackendHandle;

    /// I1: a successful C_DestroyObject must evict all attr_cache entries for the
    /// destroyed virtual object handle so the coalescer cannot serve stale cached
    /// attributes via a recycled virtual handle (R2 I1 fix).
    #[tokio::test]
    async fn destroy_object_evicts_attr_cache_entry() {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();

        // Open a real backend session and create an object.
        let backend_session = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let backend_object = mock.create_object(backend_session, Some(&[])).unwrap();

        // Set up ContextManager with virtual slot, session, and object.
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let backend_slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        let (session_vh, obj_vh) = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                let svh = ctx.register_session(BackendHandle(backend_session.0), backend_slot);
                let ovh = ctx.object_handles.insert(BackendHandle(backend_object.0));
                (svh, ovh)
            })
            .await
            .unwrap();

        // Pre-populate attr_cache for the object (simulates a coalescer cache hit).
        ctx_mgr
            .attr_cache_put(
                &ctx_id,
                obj_vh.0,
                CkAttributeType::ID,
                CachedAttr { value: SecretBytes::new(b"obj-id".to_vec()), ck_rv: CkRv::OK.0 },
            )
            .await;
        assert!(
            ctx_mgr.attr_cache_get(&ctx_id, obj_vh.0, CkAttributeType::ID).await.is_some(),
            "attr_cache must be populated before destroy"
        );

        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        let resp = super::destroy_object(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::DestroyObjectRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session_vh.0,
                object_handle: obj_vh.0,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(resp.ck_rv, CkRv::OK.0, "destroy_object must succeed");
        assert!(
            ctx_mgr.attr_cache_get(&ctx_id, obj_vh.0, CkAttributeType::ID).await.is_none(),
            "attr_cache entry for destroyed object must be evicted (I1 fix)"
        );
    }

    /// W1-L13-18: a successful C_DestroyObject revokes the daemon-wide authz
    /// generation (the freed backend handle may be recycled by another
    /// context's create) and evicts the destroyed handle's token entry.
    #[tokio::test]
    async fn destroy_object_revokes_authz_generation() {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();

        let backend_session = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let backend_object = mock.create_object(backend_session, Some(&[])).unwrap();

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let backend_slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        let (session_vh, obj_vh) = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                let svh = ctx.register_session(BackendHandle(backend_session.0), backend_slot);
                let ovh = ctx.object_handles.insert(BackendHandle(backend_object.0));
                (svh, ovh)
            })
            .await
            .unwrap();

        // Seed token-metadata entries for the object and an unrelated handle.
        for vh in [obj_vh.0, 999] {
            ctx_mgr
                .cache_object_metadata(
                    &ctx_id,
                    vh,
                    ObjectMetadata {
                        unique_id: b"tok-uid".to_vec().into(),
                        class: Some(CkObjectClass::SECRET_KEY),
                        is_token: true,
                    },
                )
                .await;
        }
        assert!(
            ctx_mgr.object_metadata(&ctx_id, obj_vh.0).await.is_some(),
            "token entry must be cached before destroy"
        );
        let generation_before = ctx_mgr.authz_generation();

        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        let resp = super::destroy_object(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::DestroyObjectRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session_vh.0,
                object_handle: obj_vh.0,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(resp.ck_rv, CkRv::OK.0, "destroy_object must succeed");
        assert_eq!(
            ctx_mgr.authz_generation(),
            generation_before + 1,
            "successful destroy must revoke the authz generation"
        );
        assert!(
            ctx_mgr.object_metadata(&ctx_id, 999).await.is_none(),
            "revocation must invalidate unrelated cached token entries"
        );
    }

    /// I1 negative: a failed destroy_object must NOT evict the attr_cache entry.
    #[tokio::test]
    async fn failed_destroy_object_keeps_attr_cache_entry() {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();

        let backend_session = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let backend_slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        // Register session but use a backend object handle that does NOT exist
        // in the mock — mock will return OBJECT_HANDLE_INVALID.
        let (session_vh, obj_vh) = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                let svh = ctx.register_session(BackendHandle(backend_session.0), backend_slot);
                // Object 999 does not exist in the mock.
                let ovh = ctx.object_handles.insert(BackendHandle(999));
                (svh, ovh)
            })
            .await
            .unwrap();

        ctx_mgr
            .attr_cache_put(
                &ctx_id,
                obj_vh.0,
                CkAttributeType::TOKEN,
                CachedAttr { value: SecretBytes::new(vec![0x01]), ck_rv: CkRv::OK.0 },
            )
            .await;

        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        let resp = super::destroy_object(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::DestroyObjectRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session_vh.0,
                object_handle: obj_vh.0,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        // The destroy should fail (non-existent backend object).
        assert_ne!(resp.ck_rv, CkRv::OK.0, "destroying a non-existent object must return an error");
        // Cache must be intact — no successful destroy occurred.
        assert!(
            ctx_mgr.attr_cache_get(&ctx_id, obj_vh.0, CkAttributeType::TOKEN).await.is_some(),
            "attr_cache must be intact after a failed destroy_object"
        );
    }

    /// T5-m1-followup: a session-bound private handle (the post-fix
    /// virtualized OUT-handle state) destroyed from a fresh logged-out
    /// session after the owner session closed reports
    /// `CKR_OBJECT_HANDLE_INVALID` (130) — the backend verdict for the
    /// evicted handle — not the stale mapping's `CKR_USER_NOT_LOGGED_IN`.
    #[tokio::test]
    async fn destroy_object_after_owner_session_close_reports_handle_invalid() {
        use super::register_session_object_handle;

        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();

        let backend_session = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let backend_object = mock.create_object(backend_session, Some(&[])).unwrap();

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let backend_slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        let owner_session = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(BackendHandle(backend_session.0), backend_slot)
            })
            .await
            .unwrap();
        // Session-bound + recorded private: the post-fix virtualized OUT
        // state (never logged in).
        let virtual_object = register_session_object_handle(
            &ctx_mgr,
            &ctx_id,
            owner_session,
            backend_object,
            false,
            Some(true),
        )
        .await;

        // Owner session closes on both layers.
        mock.close_session(backend_session).unwrap();
        ctx_mgr.get_context(&ctx_id, |ctx| ctx.remove_session(owner_session)).await;

        let fresh_backend = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let fresh_session = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(BackendHandle(fresh_backend.0), backend_slot)
            })
            .await
            .unwrap();

        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        let resp = super::destroy_object(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::DestroyObjectRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: fresh_session.0,
                object_handle: virtual_object,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(
            resp.ck_rv,
            CkRv::OBJECT_HANDLE_INVALID.0,
            "post-close destroy of an evicted session handle must report 130, not 257"
        );
    }

    /// T20 tombstone fixture: one mock session/object pair with both
    /// handles registered in a fresh context.
    async fn setup_destroy_fixture() -> (
        Arc<ContextManager>,
        Arc<dyn Pkcs11Backend>,
        crate::server::context_manager::ClientContextId,
        u64,
        u64,
    ) {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let backend_session = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let backend_object = mock.create_object(backend_session, Some(&[])).unwrap();

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let backend_slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let (session_vh, obj_vh) = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                let svh = ctx.register_session(BackendHandle(backend_session.0), backend_slot);
                let ovh = ctx.object_handles.insert(BackendHandle(backend_object.0));
                (svh, ovh)
            })
            .await
            .unwrap();
        (ctx_mgr, backend, ctx_id, session_vh.0, obj_vh.0)
    }

    /// T20 tombstones: copy-after-destroy answers OBJECT_HANDLE_INVALID
    /// locally instead of forwarding 0 (bouncyhsm answers copy-of-0 with
    /// DEVICE_ERROR, copy-of-destroyed with OBJECT_HANDLE_INVALID).
    #[tokio::test]
    async fn destroy_then_copy_reports_object_handle_invalid() {
        let (ctx_mgr, backend, ctx_id, session_vh, obj_vh) = setup_destroy_fixture().await;
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);

        let destroy = super::destroy_object(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::DestroyObjectRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session_vh,
                object_handle: obj_vh,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(destroy.ck_rv, CkRv::OK.0, "destroy must succeed");

        let copy = super::copy_object(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::CopyObjectRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session_vh,
                object_handle: obj_vh,
                template: Vec::new(),
                template_null: true,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            copy.ck_rv,
            CkRv::OBJECT_HANDLE_INVALID.0,
            "copy-after-destroy must report OBJECT_HANDLE_INVALID, not forward 0"
        );
        assert_eq!(copy.new_object_handle, 0, "failed copy must not mint a handle");
    }

    /// T20 tombstones: double destroy answers OBJECT_HANDLE_INVALID.
    #[tokio::test]
    async fn double_destroy_reports_object_handle_invalid() {
        let (ctx_mgr, backend, ctx_id, session_vh, obj_vh) = setup_destroy_fixture().await;
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);

        let first = super::destroy_object(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::DestroyObjectRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session_vh,
                object_handle: obj_vh,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(first.ck_rv, CkRv::OK.0, "first destroy must succeed");

        let second = super::destroy_object(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::DestroyObjectRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session_vh,
                object_handle: obj_vh,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            second.ck_rv,
            CkRv::OBJECT_HANDLE_INVALID.0,
            "double destroy must report OBJECT_HANDLE_INVALID"
        );
    }

    /// T20 tombstones: resolver flavors (object vs key) and forward-0
    /// preserved for never-existed handles.
    #[tokio::test]
    async fn tombstone_flavors_and_forward_zero() {
        use super::super::super::service_utils::{
            resolve_session_and_key, resolve_session_and_object, resolve_session_and_two_objects,
        };

        let (ctx_mgr, backend, ctx_id, session_vh, obj_vh) = setup_destroy_fixture().await;
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);

        let destroy = super::destroy_object(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::DestroyObjectRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session_vh,
                object_handle: obj_vh,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(destroy.ck_rv, CkRv::OK.0, "destroy must succeed");

        // Tombstoned handle: flavor follows the resolver (object vs key).
        assert_eq!(
            resolve_session_and_object(&ctx, &ctx_id, session_vh, obj_vh).await,
            Err(CkRv::OBJECT_HANDLE_INVALID),
            "object-flavored resolve of a destroyed handle must refuse locally"
        );
        assert_eq!(
            resolve_session_and_key(&ctx, &ctx_id, session_vh, obj_vh).await,
            Err(CkRv::KEY_HANDLE_INVALID),
            "key-flavored resolve of a destroyed handle must refuse locally"
        );
        assert_eq!(
            resolve_session_and_two_objects(&ctx, &ctx_id, session_vh, obj_vh, obj_vh).await,
            Err(CkRv::KEY_HANDLE_INVALID),
            "two-object resolve of a destroyed handle must refuse locally"
        );
        // Never-existed handle: still forwarded as 0 for the backend verdict.
        let (_, backend_object) =
            resolve_session_and_object(&ctx, &ctx_id, session_vh, 9999).await.unwrap();
        assert_eq!(
            backend_object,
            CkObjectHandle(0),
            "never-existed handles must keep the forward-0 semantic"
        );
    }

    #[tokio::test]
    async fn copy_with_unknown_token_metadata_preserves_success_and_session_cleanup() {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let session = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let source = mock.create_object(session, Some(&[])).unwrap();
        let manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        let id = manager.create_context(None).await.unwrap();
        let slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
        let (session_vh, source_vh) = manager
            .get_context(&id, |c| {
                let session_vh = c.register_session(BackendHandle(session.0), slot);
                let source_vh = c.object_handles.insert(BackendHandle(source.0));
                (session_vh, source_vh)
            })
            .await
            .unwrap();
        // This mock stores only the copy template. A storage-class result
        // without TOKEN therefore returns ATTRIBUTE_TYPE_INVALID to the
        // lifetime probe. It models the probe failure, not native inheritance
        // (which is covered by the real SoftHSM integration regression).
        let response = super::copy_object(
            &HandlerContext::for_test(&manager, &backend),
            Request::new(pkcs11_proxy_ng_proto::CopyObjectRequest {
                client_context_id: id.0.clone(),
                session_handle: session_vh.0,
                object_handle: source_vh.0,
                template: vec![pkcs11_proxy_ng_proto::Attribute {
                    attr_type: CkAttributeType::CLASS.0,
                    value: Some(pkcs11_proxy_ng_proto::attribute::Value::UlongValue(
                        CkObjectClass::DATA.0,
                    )),
                }],
                template_null: false,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            response.ck_rv,
            CkRv::OK.0,
            "metadata failure must not replace native copy success"
        );
        assert_ne!(
            response.new_object_handle, 0,
            "successful copy must still return its virtual handle"
        );
        let copied = crate::server::handle_map::VirtualHandle(response.new_object_handle);
        assert!(
            manager.get_context(&id, |c| c.object_handles.resolve(copied).is_some()).await.unwrap()
        );
        let response = crate::server::grpc_service::session::close_session(
            &HandlerContext::for_test(&manager, &backend),
            Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
                client_context_id: id.0.clone(),
                session_handle: session_vh.0,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(response.ck_rv, CkRv::OK.0);
        assert!(
            manager.get_context(&id, |c| c.object_handles.resolve(copied).is_none()).await.unwrap(),
            "unknown copied-object lifetime keeps conservative session cleanup"
        );
    }

    #[tokio::test]
    async fn copied_token_metadata_failure_preserves_only_unambiguous_explicit_lifetime() {
        use pkcs11_proxy_ng_proto::attribute::Value;
        for (name, overrides, observed, survives) in [
            ("bool true unreadable", vec![Value::BoolValue(true)], Err(CkRv::DEVICE_ERROR), true),
            (
                "byte true unreadable",
                vec![Value::BytesValue(vec![1])],
                Err(CkRv::DEVICE_ERROR),
                true,
            ),
            (
                "string true unreadable",
                vec![Value::StringValue(String::from("\u{1}"))],
                Err(CkRv::DEVICE_ERROR),
                true,
            ),
            (
                "string false unreadable",
                vec![Value::StringValue(String::from("\0"))],
                Err(CkRv::DEVICE_ERROR),
                false,
            ),
            (
                "bool false unreadable",
                vec![Value::BoolValue(false)],
                Err(CkRv::DEVICE_ERROR),
                false,
            ),
            (
                "byte false unreadable",
                vec![Value::BytesValue(vec![0])],
                Err(CkRv::DEVICE_ERROR),
                false,
            ),
            (
                "duplicate true unreadable",
                vec![Value::BoolValue(true), Value::BoolValue(true)],
                Err(CkRv::DEVICE_ERROR),
                false,
            ),
            (
                "conflicting unreadable",
                vec![Value::BoolValue(true), Value::BoolValue(false)],
                Err(CkRv::DEVICE_ERROR),
                false,
            ),
            (
                "empty bytes unreadable",
                vec![Value::BytesValue(vec![])],
                Err(CkRv::DEVICE_ERROR),
                false,
            ),
            (
                "wide bytes unreadable",
                vec![Value::BytesValue(vec![1, 0])],
                Err(CkRv::DEVICE_ERROR),
                false,
            ),
            (
                "nonboolean byte unreadable",
                vec![Value::BytesValue(vec![2])],
                Err(CkRv::DEVICE_ERROR),
                false,
            ),
            ("ulong unreadable", vec![Value::UlongValue(1)], Err(CkRv::DEVICE_ERROR), false),
            (
                "observed false wins",
                vec![Value::BoolValue(true)],
                Ok(CkAttributeValue::Bool(false)),
                false,
            ),
            (
                "observed true wins",
                vec![Value::BoolValue(false)],
                Ok(CkAttributeValue::Bool(true)),
                true,
            ),
        ] {
            let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
            let backend: Arc<dyn Pkcs11Backend> = mock.clone();
            let session = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let other = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let source = mock.create_object(session, Some(&[])).unwrap();
            mock.set_attribute_read_override(CkAttributeType::TOKEN, observed);
            let manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
            let id = manager.create_context(None).await.unwrap();
            let slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
            let (session_vh, source_vh) = manager
                .get_context(&id, |c| {
                    let session_vh = c.register_session(BackendHandle(session.0), slot);
                    c.register_session(BackendHandle(other.0), slot);
                    let source_vh = c.object_handles.insert(BackendHandle(source.0));
                    (session_vh, source_vh)
                })
                .await
                .unwrap();
            let response = super::copy_object(
                &HandlerContext::for_test(&manager, &backend),
                Request::new(pkcs11_proxy_ng_proto::CopyObjectRequest {
                    client_context_id: id.0.clone(),
                    session_handle: session_vh.0,
                    object_handle: source_vh.0,
                    template: overrides
                        .into_iter()
                        .map(|value| pkcs11_proxy_ng_proto::Attribute {
                            attr_type: CkAttributeType::TOKEN.0,
                            value: Some(value),
                        })
                        .collect(),
                    template_null: false,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(
                response.ck_rv,
                CkRv::OK.0,
                "{name}: metadata must not replace native copy success"
            );
            let copied = crate::server::handle_map::VirtualHandle(response.new_object_handle);
            assert_ne!(copied.0, 0, "{name}: native success must return a handle");
            assert!(
                manager
                    .get_context(&id, |c| c.object_handles.resolve(copied).is_some())
                    .await
                    .unwrap(),
                "{name}: copied handle must resolve before closing its session"
            );
            let response = crate::server::grpc_service::session::close_session(
                &HandlerContext::for_test(&manager, &backend),
                Request::new(pkcs11_proxy_ng_proto::CloseSessionRequest {
                    client_context_id: id.0.clone(),
                    session_handle: session_vh.0,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(response.ck_rv, CkRv::OK.0);
            assert_eq!(
                manager
                    .get_context(&id, |c| c.object_handles.resolve(copied).is_some())
                    .await
                    .unwrap(),
                survives,
                "{name}: virtual lifetime after closing creator with another session open"
            );
        }
    }
}
