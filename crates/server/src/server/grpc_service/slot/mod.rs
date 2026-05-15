#![allow(unused_imports)]

use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;

use super::super::auth::policy::TokenPolicy;
use super::super::context_manager::ContextManager;

mod discovery;
mod mechanisms;

pub(super) async fn get_slot_list_with_policy(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::GetSlotListRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetSlotListResponse>, Status> {
    discovery::get_slot_list(ctx_mgr, backend_ref, token_policy, request).await
}

pub(super) async fn get_slot_info_with_policy(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::GetSlotInfoRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetSlotInfoResponse>, Status> {
    discovery::get_slot_info(ctx_mgr, backend_ref, token_policy, request).await
}

pub(super) async fn get_token_info_with_policy(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::GetTokenInfoRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetTokenInfoResponse>, Status> {
    discovery::get_token_info(ctx_mgr, backend_ref, token_policy, request).await
}

pub(super) async fn get_mechanism_list_with_policy(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::GetMechanismListRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetMechanismListResponse>, Status> {
    mechanisms::get_mechanism_list(ctx_mgr, backend_ref, token_policy, request).await
}

pub(super) async fn get_mechanism_info_with_policy(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::GetMechanismInfoRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetMechanismInfoResponse>, Status> {
    mechanisms::get_mechanism_info(ctx_mgr, backend_ref, token_policy, request).await
}
