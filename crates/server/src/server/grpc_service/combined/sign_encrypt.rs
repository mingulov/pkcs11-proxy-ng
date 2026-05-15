use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::super::handle_map::VirtualHandle;
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
        Some(Some(handle)) => Ok(CkSessionHandle(handle.0)),
    }
}

pub(super) async fn digest_encrypt_update(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DigestEncryptUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DigestEncryptUpdateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);
    let session = match resolve_backend_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DigestEncryptUpdateResponse {
                ck_rv: error.0,
                encrypted_part: vec![],
            }));
        }
    };

    let part = req.part;
    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.digest_encrypt_update(session, &part)).await?;
    let (ck_rv, encrypted_part) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::DigestEncryptUpdateResponse {
        ck_rv,
        encrypted_part: encrypted_part.unwrap_or_default(),
    }))
}

pub(super) async fn sign_encrypt_update(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SignEncryptUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignEncryptUpdateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);
    let session = match resolve_backend_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignEncryptUpdateResponse {
                ck_rv: error.0,
                encrypted_part: vec![],
            }));
        }
    };

    let part = req.part;
    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.sign_encrypt_update(session, &part)).await?;
    let (ck_rv, encrypted_part) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::SignEncryptUpdateResponse {
        ck_rv,
        encrypted_part: encrypted_part.unwrap_or_default(),
    }))
}
