use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;

use super::super::service_utils::{
    ck_rv_only, parse_mechanism, resolve_session, resolve_session_and_key, spawn_backend,
};
use crate::server::context_manager::{ClientContextId, ContextManager};

pub(crate) async fn verify_init(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::VerifyInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyInitResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, key) =
        match resolve_session_and_key(ctx_mgr, &ctx_id, req.session_handle, req.key_handle).await {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyInitResponse { ck_rv: rv.0 }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.verify_init(session, &mechanism, key)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyInitResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn verify(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::VerifyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyResponse { ck_rv: rv.0 })),
    };

    let data = req.data;
    let signature = req.signature;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.verify(session, &data, &signature)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn verify_update(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::VerifyUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyUpdateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyUpdateResponse { ck_rv: rv.0 }));
        }
    };

    let part = req.part;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.verify_update(session, &part)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyUpdateResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn verify_final(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::VerifyFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyFinalResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyFinalResponse { ck_rv: rv.0 }));
        }
    };

    let signature = req.signature;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.verify_final(session, &signature)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyFinalResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn verify_recover_init(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::VerifyRecoverInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyRecoverInitResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, key) =
        match resolve_session_and_key(ctx_mgr, &ctx_id, req.session_handle, req.key_handle).await {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyRecoverInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyRecoverInitResponse {
                ck_rv: rv.0,
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.verify_recover_init(session, &mechanism, key)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyRecoverInitResponse {
        ck_rv: ck_rv_only(result),
    }))
}

pub(crate) async fn verify_recover(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::VerifyRecoverRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyRecoverResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyRecoverResponse {
                ck_rv: rv.0,
                data: Vec::new(),
            }));
        }
    };

    let signature = req.signature;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.verify_recover(session, &signature)).await?;
    let (ck_rv, data) = super::super::ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyRecoverResponse {
        ck_rv,
        data: data.unwrap_or_default(),
    }))
}
