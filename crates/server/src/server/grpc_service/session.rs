#![allow(unused_imports)]
use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::auth::policy::TokenPolicy;
use super::super::context_manager::{ClientContextId, ContextManager};
#[path = "session_handlers/auth.rs"]
mod auth;
#[path = "session_handlers/lifecycle.rs"]
mod lifecycle;
#[path = "session_handlers/management.rs"]
mod management;

fn default_token_policy() -> TokenPolicy {
    TokenPolicy::from_config(&crate::config::AuthConfig::default()).expect("default policy")
}

#[allow(dead_code)]
pub(super) async fn open_session(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::OpenSessionRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::OpenSessionResponse>, Status> {
    let token_policy = default_token_policy();
    open_session_with_policy(ctx_mgr, backend_ref, &token_policy, request).await
}

pub(super) async fn open_session_with_policy(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::OpenSessionRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::OpenSessionResponse>, Status> {
    lifecycle::open_session(ctx_mgr, backend_ref, token_policy, request).await
}

pub(super) async fn close_session(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::CloseSessionRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CloseSessionResponse>, Status> {
    lifecycle::close_session(ctx_mgr, backend_ref, request).await
}

#[allow(dead_code)]
pub(super) async fn close_all_sessions(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::CloseAllSessionsRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CloseAllSessionsResponse>, Status> {
    let token_policy = default_token_policy();
    close_all_sessions_with_policy(ctx_mgr, backend_ref, &token_policy, request).await
}

pub(super) async fn close_all_sessions_with_policy(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::CloseAllSessionsRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CloseAllSessionsResponse>, Status> {
    lifecycle::close_all_sessions(ctx_mgr, backend_ref, token_policy, request).await
}

pub(super) async fn get_session_info(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GetSessionInfoRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetSessionInfoResponse>, Status> {
    lifecycle::get_session_info(ctx_mgr, backend_ref, request).await
}

pub(super) async fn login(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::LoginRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::LoginResponse>, Status> {
    auth::login(ctx_mgr, backend_ref, request).await
}

pub(super) async fn logout(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::LogoutRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::LogoutResponse>, Status> {
    auth::logout(ctx_mgr, backend_ref, request).await
}

#[allow(dead_code)]
pub(super) async fn init_token(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::InitTokenRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::InitTokenResponse>, Status> {
    let token_policy = default_token_policy();
    init_token_with_policy(ctx_mgr, backend_ref, &token_policy, request).await
}

pub(super) async fn init_token_with_policy(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::InitTokenRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::InitTokenResponse>, Status> {
    management::init_token(ctx_mgr, backend_ref, token_policy, request).await
}

pub(super) async fn init_pin(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::InitPinRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::InitPinResponse>, Status> {
    management::init_pin(ctx_mgr, backend_ref, request).await
}

pub(super) async fn set_pin(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SetPinRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SetPinResponse>, Status> {
    management::set_pin(ctx_mgr, backend_ref, request).await
}

pub(super) async fn get_function_status(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GetFunctionStatusRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetFunctionStatusResponse>, Status> {
    lifecycle::get_function_status(ctx_mgr, backend_ref, request).await
}

pub(super) async fn cancel_function(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::CancelFunctionRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CancelFunctionResponse>, Status> {
    lifecycle::cancel_function(ctx_mgr, backend_ref, request).await
}

#[cfg(test)]
mod tests;
