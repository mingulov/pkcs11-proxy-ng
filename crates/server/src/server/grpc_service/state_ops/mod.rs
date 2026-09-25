use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;

use super::super::auth::policy::TokenPolicy;
use super::super::context_manager::ContextManager;

mod operation_state;
mod random;
mod slot_event;

use crate::server::grpc_service::HandlerContext;
pub(super) async fn generate_random(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GenerateRandomRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GenerateRandomResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    random::generate_random(ctx_mgr, backend_ref, request).await
}

pub(super) async fn wait_for_slot_event_with_policy(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::WaitForSlotEventRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::WaitForSlotEventResponse>, Status> {
    slot_event::wait_for_slot_event(ctx_mgr, backend_ref, token_policy, request).await
}

#[cfg(test)]
pub(super) async fn wait_for_slot_event_with_policy_and_grace(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::WaitForSlotEventRequest>,
    nonblocking_grace: std::time::Duration,
) -> Result<Response<pkcs11_proxy_ng_proto::WaitForSlotEventResponse>, Status> {
    slot_event::wait_for_slot_event_with_grace(
        ctx_mgr,
        backend_ref,
        token_policy,
        request,
        nonblocking_grace,
    )
    .await
}

pub(super) async fn get_operation_state(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::GetOperationStateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetOperationStateResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    operation_state::get_operation_state(ctx_mgr, backend_ref, request).await
}

pub(super) async fn set_operation_state(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SetOperationStateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SetOperationStateResponse>, Status> {
    let sanitize_inputs = ctx.sanitize_inputs;
    operation_state::set_operation_state(ctx, sanitize_inputs, request).await
}

pub(super) async fn seed_random(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SeedRandomRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SeedRandomResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    random::seed_random(ctx_mgr, backend_ref, sanitize_inputs, request).await
}
