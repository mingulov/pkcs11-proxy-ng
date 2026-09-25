use tonic::{Request, Response, Status};

mod decrypt_digest;
mod sign_encrypt;

use crate::server::grpc_service::HandlerContext;

pub(super) async fn digest_encrypt_update(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    _sanitize_inputs: bool,
    request: Request<pkcs11_proxy_ng_proto::DigestEncryptUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DigestEncryptUpdateResponse>, Status> {
    sign_encrypt::digest_encrypt_update(ctx, request).await
}

pub(super) async fn decrypt_digest_update(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    _sanitize_inputs: bool,
    request: Request<pkcs11_proxy_ng_proto::DecryptDigestUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptDigestUpdateResponse>, Status> {
    decrypt_digest::decrypt_digest_update(ctx, request).await
}

pub(super) async fn sign_encrypt_update(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    _sanitize_inputs: bool,
    request: Request<pkcs11_proxy_ng_proto::SignEncryptUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignEncryptUpdateResponse>, Status> {
    sign_encrypt::sign_encrypt_update(ctx, request).await
}

pub(super) async fn decrypt_verify_update(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    _sanitize_inputs: bool,
    request: Request<pkcs11_proxy_ng_proto::DecryptVerifyUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptVerifyUpdateResponse>, Status> {
    decrypt_digest::decrypt_verify_update(ctx, request).await
}
