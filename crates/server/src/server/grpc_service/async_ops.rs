//! gRPC handlers for PKCS#11 3.2 async operations (Wave 5, Option B: polling only).
//!
//! - `C_AsyncComplete` — real handler, passes through `CKR_PENDING`
//! - `C_AsyncGetID` — always returns `CKR_STATE_UNSAVEABLE`
//! - `C_AsyncJoin` — always returns `CKR_SAVED_STATE_INVALID`

// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain;
use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::info;

use pkcs11_proxy_ng_types::*;

use super::super::context_manager::ClientContextId;
use super::service_utils::{resolve_session, spawn_backend};

// ---------------------------------------------------------------------------
// C_AsyncComplete — forwards to backend, passes through CKR_PENDING
// ---------------------------------------------------------------------------

use crate::server::grpc_service::HandlerContext;
pub(crate) async fn async_complete(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::AsyncCompleteRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::AsyncCompleteResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::AsyncCompleteResponse {
                ck_rv: rv.0,
                async_data: None,
            }));
        }
    };

    let function_name = req.function_name;
    info!(context_id = %ctx_id.0, function_name = %function_name, "AsyncComplete");

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.async_complete(session, &function_name)).await?;

    match result {
        Ok((version, value, value_len, object_handle, additional_object_handle)) => {
            Ok(Response::new(pkcs11_proxy_ng_proto::AsyncCompleteResponse {
                ck_rv: CkRv::OK.0,
                async_data: Some(pkcs11_proxy_ng_proto::AsyncData {
                    version,
                    value: secret_to_plain(&value),
                    value_len,
                    object_handle: object_handle.0,
                    additional_object_handle: additional_object_handle.0,
                }),
            }))
        }
        Err(e) => {
            // Pass through CKR_PENDING and other error codes as-is.
            Ok(Response::new(pkcs11_proxy_ng_proto::AsyncCompleteResponse {
                ck_rv: e.0,
                async_data: None,
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// C_AsyncGetID — always returns CKR_STATE_UNSAVEABLE (Option B)
// ---------------------------------------------------------------------------

pub(crate) async fn async_get_id(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::AsyncGetIdRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::AsyncGetIdResponse>, Status> {
    // W1-C1-11: read the request first — unknown contexts and bad sessions
    // get native-precedence RVs before the fixed Option-B RV.
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);
    if let Err(rv) = resolve_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::AsyncGetIdResponse {
            ck_rv: rv.0,
            operation_id: 0,
        }));
    }
    Ok(Response::new(pkcs11_proxy_ng_proto::AsyncGetIdResponse {
        ck_rv: CkRv::STATE_UNSAVEABLE.0,
        operation_id: 0,
    }))
}

// ---------------------------------------------------------------------------
// C_AsyncJoin — always returns CKR_SAVED_STATE_INVALID (Option B)
// ---------------------------------------------------------------------------

pub(crate) async fn async_join(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::AsyncJoinRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::AsyncJoinResponse>, Status> {
    // W1-C1-11: read the request first — unknown contexts and bad sessions
    // get native-precedence RVs before the fixed Option-B RV.
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);
    if let Err(rv) = resolve_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::AsyncJoinResponse {
            ck_rv: rv.0,
            data: Vec::new(),
        }));
    }
    Ok(Response::new(pkcs11_proxy_ng_proto::AsyncJoinResponse {
        ck_rv: CkRv::SAVED_STATE_INVALID.0,
        data: Vec::new(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::context_manager::ContextManager;
    use crate::server::handle_map::BackendHandle;
    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};

    async fn setup_session() -> (Arc<ContextManager>, Arc<dyn Pkcs11Backend>, ClientContextId, u64)
    {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let backend_session = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let vs = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();
        (ctx_mgr, backend, ctx_id, vs.0)
    }

    /// W1-C1-11: `async_get_id` must read the request — unknown contexts get
    /// `CRYPTOKI_NOT_INITIALIZED` and bad sessions get
    /// `SESSION_HANDLE_INVALID` (native precedence) before the fixed Option-B RV.
    #[tokio::test]
    async fn async_get_id_native_precedence_rvs() {
        let (ctx_mgr, backend, ctx_id, vs) = setup_session().await;
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);

        let unknown_ctx = async_get_id(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::AsyncGetIdRequest {
                client_context_id: "no-such-context".into(),
                session_handle: vs,
                function_name: "C_Sign".into(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(unknown_ctx.ck_rv, CkRv::CRYPTOKI_NOT_INITIALIZED.0);

        let bad_session = async_get_id(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::AsyncGetIdRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: 9999,
                function_name: "C_Sign".into(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(bad_session.ck_rv, CkRv::SESSION_HANDLE_INVALID.0);

        let valid = async_get_id(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::AsyncGetIdRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: vs,
                function_name: "C_Sign".into(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(valid.ck_rv, CkRv::STATE_UNSAVEABLE.0);
    }

    /// W1-C1-11: same native-precedence contract for `async_join`.
    #[tokio::test]
    async fn async_join_native_precedence_rvs() {
        let (ctx_mgr, backend, ctx_id, vs) = setup_session().await;
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);

        let unknown_ctx = async_join(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::AsyncJoinRequest {
                client_context_id: "no-such-context".into(),
                session_handle: vs,
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(unknown_ctx.ck_rv, CkRv::CRYPTOKI_NOT_INITIALIZED.0);

        let bad_session = async_join(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::AsyncJoinRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: 9999,
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(bad_session.ck_rv, CkRv::SESSION_HANDLE_INVALID.0);

        let valid = async_join(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::AsyncJoinRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: vs,
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(valid.ck_rv, CkRv::SAVED_STATE_INVALID.0);
    }
}
