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
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    _sanitize_inputs: bool,
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
    _ctx_mgr: &Arc<ContextManager>,
    _backend: &Arc<dyn Pkcs11Backend>,
    _sanitize_inputs: bool,
    _request: Request<pkcs11_proxy_ng_proto::AsyncGetIdRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::AsyncGetIdResponse>, Status> {
    Ok(Response::new(pkcs11_proxy_ng_proto::AsyncGetIdResponse {
        ck_rv: CkRv::STATE_UNSAVEABLE.0,
        operation_id: 0,
    }))
}

// ---------------------------------------------------------------------------
// C_AsyncJoin — always returns CKR_SAVED_STATE_INVALID (Option B)
// ---------------------------------------------------------------------------

pub(crate) async fn async_join(
    _ctx_mgr: &Arc<ContextManager>,
    _backend: &Arc<dyn Pkcs11Backend>,
    _sanitize_inputs: bool,
    _request: Request<pkcs11_proxy_ng_proto::AsyncJoinRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::AsyncJoinResponse>, Status> {
    Ok(Response::new(pkcs11_proxy_ng_proto::AsyncJoinResponse {
        ck_rv: CkRv::SAVED_STATE_INVALID.0,
        data: Vec::new(),
    }))
}
