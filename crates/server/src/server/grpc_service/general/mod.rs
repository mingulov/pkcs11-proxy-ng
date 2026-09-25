use std::sync::Arc;
use std::time::Instant;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_audit::EventClass;
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::context_manager::{ClientContextId, ContextManager};
use super::audit_events::emit_auth_event;

mod info;
mod interface_caps;
mod lifecycle;

use crate::server::grpc_service::HandlerContext;
pub(super) async fn initialize(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::InitializeRequest>,
    tcp_auth_mode: crate::config::TcpAuthMode,
    unix_auth_mode: crate::config::UnixAuthMode,
) -> Result<Response<pkcs11_proxy_ng_proto::InitializeResponse>, Status> {
    lifecycle::initialize(ctx_mgr, backend_ref, request, tcp_auth_mode, unix_auth_mode).await
}

/// Finalize a client context, emitting a fail-closed `System` audit record.
///
/// Note: the context is removed inside `lifecycle::finalize`, so
/// `emit_auth_event` will see `identity = None` for the ctx_id after the call.
/// This is acceptable — the `System` record still carries the ctx_id's prior
/// identity if it was looked up before finalize ran, but to keep the code simple
/// and avoid a TOCTOU between lookup and removal, we accept `identity: None` for
/// `C_Finalize` records.
pub(super) async fn finalize(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::FinalizeRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::FinalizeResponse>, Status> {
    let started = Instant::now();
    let ctx_id = ClientContextId(request.get_ref().client_context_id.clone());

    let response = lifecycle::finalize(&ctx.context_manager, &ctx.backend, request).await?;
    let ck_rv = response.get_ref().ck_rv;

    if emit_auth_event(ctx, &ctx_id, "C_Finalize", EventClass::System, None, None, ck_rv, started)
        .is_err()
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::FinalizeResponse {
            ck_rv: CkRv::FUNCTION_FAILED.0,
        }));
    }

    Ok(response)
}

pub(super) async fn get_info(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetInfoRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetInfoResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    info::get_info(ctx_mgr, backend_ref, request).await
}

pub(super) async fn get_backend_interfaces(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    registry_source: &crate::mechanism_registry_source::MechanismRegistrySource,
    request: Request<pkcs11_proxy_ng_proto::GetBackendInterfacesRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetBackendInterfacesResponse>, Status> {
    interface_caps::get_backend_interfaces(ctx_mgr, backend_ref, registry_source, request).await
}
