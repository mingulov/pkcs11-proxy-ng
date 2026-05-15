use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;

use super::super::ck_result_to_rv;
use super::super::service_utils::{
    ck_rv_only, parse_mechanism, resolve_session, resolve_session_and_key, spawn_backend,
};
use crate::server::context_manager::{ClientContextId, ContextManager};

pub(crate) async fn sign_init(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SignInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignInitResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, key) =
        match resolve_session_and_key(ctx_mgr, &ctx_id, req.session_handle, req.key_handle).await {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse { ck_rv: rv.0 }));
            }
        };

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse { ck_rv: rv.0 }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.sign_init(session, &mechanism, key)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn sign(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SignRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignResponse {
                ck_rv: rv.0,
                signature: Vec::new(),
            }));
        }
    };

    let data = req.data;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.sign(session, &data)).await?;
    let (ck_rv, signature) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::SignResponse {
        ck_rv,
        signature: signature.unwrap_or_default(),
    }))
}

pub(crate) async fn sign_update(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SignUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignUpdateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignUpdateResponse { ck_rv: rv.0 }));
        }
    };

    let part = req.part;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.sign_update(session, &part)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::SignUpdateResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn sign_final(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SignFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignFinalResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignFinalResponse {
                ck_rv: rv.0,
                signature: Vec::new(),
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.sign_final(session)).await?;
    let (ck_rv, signature) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::SignFinalResponse {
        ck_rv,
        signature: signature.unwrap_or_default(),
    }))
}

pub(crate) async fn sign_recover_init(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SignRecoverInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignRecoverInitResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, key) =
        match resolve_session_and_key(ctx_mgr, &ctx_id, req.session_handle, req.key_handle).await {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse {
                ck_rv: rv.0,
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.sign_recover_init(session, &mechanism, key)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn sign_recover(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SignRecoverRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignRecoverResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverResponse {
                ck_rv: rv.0,
                signature: Vec::new(),
            }));
        }
    };

    let data = req.data;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.sign_recover(session, &data)).await?;
    let (ck_rv, signature) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverResponse {
        ck_rv,
        signature: signature.unwrap_or_default(),
    }))
}
