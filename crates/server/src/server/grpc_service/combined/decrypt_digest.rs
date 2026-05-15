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

pub(super) async fn decrypt_digest_update(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DecryptDigestUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptDigestUpdateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);
    let session = match resolve_backend_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptDigestUpdateResponse {
                ck_rv: error.0,
                part: vec![],
            }));
        }
    };

    let encrypted_part = req.encrypted_part;
    let backend = backend_ref.clone();
    let result =
        spawn_backend(move || backend.decrypt_digest_update(session, &encrypted_part)).await?;
    let (ck_rv, part) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::DecryptDigestUpdateResponse {
        ck_rv,
        part: part.unwrap_or_default(),
    }))
}

pub(super) async fn decrypt_verify_update(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DecryptVerifyUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptVerifyUpdateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);
    let session = match resolve_backend_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptVerifyUpdateResponse {
                ck_rv: error.0,
                part: vec![],
            }));
        }
    };

    let encrypted_part = req.encrypted_part;
    let backend = backend_ref.clone();
    let result =
        spawn_backend(move || backend.decrypt_verify_update(session, &encrypted_part)).await?;
    let (ck_rv, part) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::DecryptVerifyUpdateResponse {
        ck_rv,
        part: part.unwrap_or_default(),
    }))
}
