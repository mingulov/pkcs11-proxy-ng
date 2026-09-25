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
    unix_auth_mode: crate::config::UnixAuthMode,
) -> Result<Response<pkcs11_proxy_ng_proto::InitializeResponse>, Status> {
    let identity = crate::server::auth::request_identity::identity_from_request(
        &request,
        tcp_auth_mode,
        unix_auth_mode,
    )?;
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

    let maybe_ctx = ctx_mgr.remove_context(&ctx_id);
    let ck_rv = match maybe_ctx {
        Some(mut ctx) => {
            // D6(2)/D9 shared teardown path: refcount-checked session reaping
            // plus last-holder backend logout (best-effort; never fails the
            // Finalize itself and never disturbs live tenants).
            let plan = ctx_mgr.plan_removed_context_teardown(&mut ctx);
            let session_count = plan.sessions_to_close.len();
            let logout_count = plan.slot_logouts.len();
            ctx_mgr.execute_teardown_plans(backend_ref, vec![plan]).await;
            debug!(
                context_id = %ctx_id.0,
                sessions_closed = session_count,
                logouts = logout_count,
                "Finalize: context removed"
            );
            CkRv::OK.0
        }
        None => CkRv::CRYPTOKI_NOT_INITIALIZED.0,
    };
    Ok(Response::new(pkcs11_proxy_ng_proto::FinalizeResponse { ck_rv }))
}
