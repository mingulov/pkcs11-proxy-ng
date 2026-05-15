#![allow(unused_imports)]

use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;

use super::super::context_manager::ContextManager;

mod info;
mod interface_caps;
mod lifecycle;

pub(super) async fn initialize(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::InitializeRequest>,
    tcp_auth_mode: crate::config::TcpAuthMode,
) -> Result<Response<pkcs11_proxy_ng_proto::InitializeResponse>, Status> {
    lifecycle::initialize(ctx_mgr, backend_ref, request, tcp_auth_mode).await
}

pub(super) async fn finalize(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::FinalizeRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::FinalizeResponse>, Status> {
    lifecycle::finalize(ctx_mgr, backend_ref, request).await
}

pub(super) async fn get_info(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GetInfoRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetInfoResponse>, Status> {
    info::get_info(ctx_mgr, backend_ref, request).await
}

pub(super) async fn get_backend_interfaces(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GetBackendInterfacesRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetBackendInterfacesResponse>, Status> {
    interface_caps::get_backend_interfaces(ctx_mgr, backend_ref, request).await
}
