// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain;
use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_types::*;

use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::super::handle_map::VirtualHandle;
use super::super::HandlerContext;
use super::super::{ck_result_to_rv, service_utils::spawn_backend};

async fn resolve_backend_session(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    session_handle: u64,
) -> Result<CkSessionHandle, CkRv> {
    let backend_session = ctx_mgr
        .get_context(ctx_id, |ctx| ctx.session_handles.resolve(VirtualHandle(session_handle)))
        .await;
    match backend_session {
        None => Err(CkRv::CRYPTOKI_NOT_INITIALIZED),
        Some(None) => Err(CkRv::SESSION_HANDLE_INVALID),
        Some(Some(handle)) => Ok(CkSessionHandle(handle.0 as u64)),
    }
}

// NOTE: legacy per-op RPC — not used by the shim; NULL-input class not forwarded (ADR-0010 Scope 2 covers the *_exact paths).
pub(super) async fn digest_encrypt_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DigestEncryptUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DigestEncryptUpdateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);
    let session =
        match resolve_backend_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
            Ok(session) => session,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::DigestEncryptUpdateResponse {
                    ck_rv: error.0,
                    encrypted_part: vec![],
                }));
            }
        };

    let part = req.part;
    let backend = ctx.backend.clone();
    let result =
        spawn_backend(move || backend.digest_encrypt_update(session, CkInBuf::Bytes(&part)))
            .await?;
    let (ck_rv, encrypted_part) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::DigestEncryptUpdateResponse {
        ck_rv,
        encrypted_part: secret_to_plain(&encrypted_part.unwrap_or_default()),
    }))
}

// NOTE: legacy per-op RPC — not used by the shim; NULL-input class not forwarded (ADR-0010 Scope 2 covers the *_exact paths).
pub(super) async fn sign_encrypt_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignEncryptUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignEncryptUpdateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);
    let session =
        match resolve_backend_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
            Ok(session) => session,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::SignEncryptUpdateResponse {
                    ck_rv: error.0,
                    encrypted_part: vec![],
                }));
            }
        };

    let part = req.part;
    let backend = ctx.backend.clone();
    let result =
        spawn_backend(move || backend.sign_encrypt_update(session, CkInBuf::Bytes(&part))).await?;
    let (ck_rv, encrypted_part) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::SignEncryptUpdateResponse {
        ck_rv,
        encrypted_part: secret_to_plain(&encrypted_part.unwrap_or_default()),
    }))
}
