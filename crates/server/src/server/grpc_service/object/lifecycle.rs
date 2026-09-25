use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_types::CkRv;

use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::super::handle_map::VirtualHandle;
use super::super::convert_template;
use super::super::service_utils::{
    ck_rv_only, ensure_private_mint_allowed, object_is_private, register_session_object_handle,
    resolve_session, resolve_session_and_object, spawn_backend, template_declares_private_object,
    template_declares_token_object, template_has_private_attr,
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

    // A copied object is a session object unless its template marks CKA_TOKEN (B2).
    let is_token = template_declares_token_object(template_view);
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
        Ok(new_object) => Ok(Response::new(pkcs11_proxy_ng_proto::CopyObjectResponse {
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
        })),
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

    // On successful destroy, evict the virtual->backend mapping so a recycled
    // backend object number can never alias this now-stale handle (B2).
    if result.is_ok() {
        let virtual_object = VirtualHandle(req.object_handle);
        let _ = ctx_mgr.get_context(&ctx_id, |ctx| ctx.object_handles.remove(virtual_object)).await;
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

    use crate::server::context_manager::{CachedAttr, ContextManager};
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
}
