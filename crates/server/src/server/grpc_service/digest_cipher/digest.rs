use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;

use super::super::ck_result_to_rv;
use super::super::service_utils::{
    ck_rv_only, parse_mechanism, resolve_session, resolve_session_and_key, spawn_backend,
};
use crate::server::context_manager::{ClientContextId, ContextManager};

pub(crate) async fn digest_init(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DigestInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DigestInitResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DigestInitResponse { ck_rv: rv.0 }));
        }
    };

    if req.mechanism.is_none() {
        let backend = Arc::clone(backend_ref);
        let result = spawn_backend(move || backend.digest_init_cancel(session)).await?;
        return Ok(Response::new(pkcs11_proxy_ng_proto::DigestInitResponse {
            ck_rv: ck_rv_only(result),
        }));
    }

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DigestInitResponse { ck_rv: rv.0 }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.digest_init(session, &mechanism)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::DigestInitResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn digest(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DigestRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DigestResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DigestResponse {
                ck_rv: rv.0,
                digest: Vec::new(),
            }));
        }
    };

    let data = req.data;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.digest(session, &data)).await?;
    let (ck_rv, digest) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::DigestResponse {
        ck_rv,
        digest: digest.unwrap_or_default(),
    }))
}

pub(crate) async fn digest_update(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DigestUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DigestUpdateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DigestUpdateResponse { ck_rv: rv.0 }));
        }
    };

    let part = req.part;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.digest_update(session, &part)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::DigestUpdateResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn digest_key(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DigestKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DigestKeyResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, key) =
        match resolve_session_and_key(ctx_mgr, &ctx_id, req.session_handle, req.key_handle).await {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::DigestKeyResponse { ck_rv: rv.0 }));
            }
        };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.digest_key(session, key)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::DigestKeyResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn digest_final(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DigestFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DigestFinalResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DigestFinalResponse {
                ck_rv: rv.0,
                digest: Vec::new(),
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.digest_final(session)).await?;
    let (ck_rv, digest) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::DigestFinalResponse {
        ck_rv,
        digest: digest.unwrap_or_default(),
    }))
}
