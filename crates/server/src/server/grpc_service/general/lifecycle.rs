use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::debug;

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::super::context_manager::{ClientContextId, ContextManager};

pub(super) async fn initialize(
    ctx_mgr: &Arc<ContextManager>,
    _backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::InitializeRequest>,
    tcp_auth_mode: crate::config::TcpAuthMode,
) -> Result<Response<pkcs11_proxy_ng_proto::InitializeResponse>, Status> {
    let identity =
        crate::server::auth::request_identity::identity_from_request(&request, tcp_auth_mode)?;
    let ctx_id = match ctx_mgr.create_context(Some(identity.to_string())).await {
        Ok(id) => id,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::InitializeResponse {
                ck_rv: rv.0,
                client_context_id: String::new(),
            }));
        }
    };
    debug!(context_id = %ctx_id.0, "Initialize: created context");
    Ok(Response::new(pkcs11_proxy_ng_proto::InitializeResponse {
        ck_rv: CkRv::OK.0,
        client_context_id: ctx_id.0,
    }))
}

pub(super) async fn finalize(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::FinalizeRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::FinalizeResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let maybe_ctx = ctx_mgr.remove_context(&ctx_id).await;
    let ck_rv = match maybe_ctx {
        Some(mut ctx) => {
            let backend_sessions = ctx.teardown();
            let session_count = backend_sessions.len();
            if !backend_sessions.is_empty() {
                let backend = backend_ref.clone();
                tokio::task::spawn_blocking(move || {
                    for backend_handle in backend_sessions {
                        let _ = backend.close_session(CkSessionHandle(backend_handle));
                    }
                })
                .await
                .map_err(|e| Status::internal(format!("spawn_blocking panic: {e}")))?;
            }
            debug!(context_id = %ctx_id.0, sessions_closed = session_count, "Finalize: context removed");
            CkRv::OK.0
        }
        None => CkRv::CRYPTOKI_NOT_INITIALIZED.0,
    };
    Ok(Response::new(pkcs11_proxy_ng_proto::FinalizeResponse { ck_rv }))
}
