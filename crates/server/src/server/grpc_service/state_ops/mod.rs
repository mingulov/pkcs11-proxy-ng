use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;

use super::super::context_manager::ContextManager;

mod operation_state;
mod random;
mod slot_event;

pub(super) async fn generate_random(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GenerateRandomRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GenerateRandomResponse>, Status> {
    random::generate_random(ctx_mgr, backend_ref, request).await
}

pub(super) async fn wait_for_slot_event(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::WaitForSlotEventRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::WaitForSlotEventResponse>, Status> {
    slot_event::wait_for_slot_event(ctx_mgr, backend_ref, request).await
}

pub(super) async fn get_operation_state(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GetOperationStateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetOperationStateResponse>, Status> {
    operation_state::get_operation_state(ctx_mgr, backend_ref, request).await
}

pub(super) async fn set_operation_state(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SetOperationStateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SetOperationStateResponse>, Status> {
    operation_state::set_operation_state(ctx_mgr, backend_ref, request).await
}

pub(super) async fn seed_random(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SeedRandomRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SeedRandomResponse>, Status> {
    random::seed_random(ctx_mgr, backend_ref, request).await
}
