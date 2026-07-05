#![allow(unused_imports)]

use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;

use super::super::context_manager::ContextManager;

mod decrypt_digest;
mod sign_encrypt;

use crate::server::grpc_service::HandlerContext;
pub(super) async fn digest_encrypt_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DigestEncryptUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DigestEncryptUpdateResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    sign_encrypt::digest_encrypt_update(ctx_mgr, backend_ref, request).await
}

pub(super) async fn decrypt_digest_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DecryptDigestUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptDigestUpdateResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    decrypt_digest::decrypt_digest_update(ctx_mgr, backend_ref, request).await
}

pub(super) async fn sign_encrypt_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignEncryptUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignEncryptUpdateResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    sign_encrypt::sign_encrypt_update(ctx_mgr, backend_ref, request).await
}

pub(super) async fn decrypt_verify_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DecryptVerifyUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptVerifyUpdateResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    decrypt_digest::decrypt_verify_update(ctx_mgr, backend_ref, request).await
}
