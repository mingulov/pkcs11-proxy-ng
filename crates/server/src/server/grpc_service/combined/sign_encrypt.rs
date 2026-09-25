// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_types::*;

use super::super::super::context_manager::ClientContextId;
use super::super::HandlerContext;
use super::super::{
    ck_result_to_rv,
    service_utils::{resolve_session, spawn_backend},
};

// NOTE: legacy per-op RPC (W1-L11-21 retention; see service.proto) — not used by the shim; NULL-input class not forwarded (ADR-0010 Scope 2 covers the *_exact paths).
pub(super) async fn digest_encrypt_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DigestEncryptUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DigestEncryptUpdateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);
    let session = match resolve_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DigestEncryptUpdateResponse {
                ck_rv: error.0,
                encrypted_part: vec![],
            }));
        }
    };

    let part = SecretBytes::new(req.part);
    let backend = ctx.backend.clone();
    let result = spawn_backend(move || {
        part.expose(|raw| backend.digest_encrypt_update(session, CkInBuf::Bytes(raw)))
    })
    .await?;
    let (ck_rv, encrypted_part) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::DigestEncryptUpdateResponse {
        ck_rv,
        encrypted_part: secret_to_plain(&encrypted_part.unwrap_or_default()),
    }))
}

// NOTE: legacy per-op RPC (W1-L11-21 retention; see service.proto) — not used by the shim; NULL-input class not forwarded (ADR-0010 Scope 2 covers the *_exact paths).
pub(super) async fn sign_encrypt_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignEncryptUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignEncryptUpdateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);
    let session = match resolve_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignEncryptUpdateResponse {
                ck_rv: error.0,
                encrypted_part: vec![],
            }));
        }
    };

    let part = SecretBytes::new(req.part);
    let backend = ctx.backend.clone();
    let result = spawn_backend(move || {
        part.expose(|raw| backend.sign_encrypt_update(session, CkInBuf::Bytes(raw)))
    })
    .await?;
    let (ck_rv, encrypted_part) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::SignEncryptUpdateResponse {
        ck_rv,
        encrypted_part: secret_to_plain(&encrypted_part.unwrap_or_default()),
    }))
}
