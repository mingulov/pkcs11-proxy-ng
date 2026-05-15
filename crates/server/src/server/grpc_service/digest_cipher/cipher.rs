use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::CkMechanism;

use super::super::ck_result_to_rv;
use super::super::service_utils::{
    ck_rv_only, parse_mechanism, resolve_session, resolve_session_and_key, spawn_backend,
};
use crate::server::context_manager::{ClientContextId, ContextManager};

pub(crate) async fn encrypt_init(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::EncryptInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncryptInitResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, key) =
        match resolve_session_and_key(ctx_mgr, &ctx_id, req.session_handle, req.key_handle).await {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptInitResponse {
                    ck_rv: rv.0,
                    mechanism_out: None,
                }));
            }
        };

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptInitResponse {
                ck_rv: rv.0,
                mechanism_out: None,
            }));
        }
    };

    let mechanism_type = mechanism.mechanism_type;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.encrypt_init(session, &mechanism, key)).await?;
    let (ck_rv, params) = ck_result_to_rv(result);
    let mechanism_out = params.flatten().map(|params| {
        pkcs11_proxy_ng_proto::Mechanism::from(&CkMechanism {
            mechanism_type,
            params: Some(params),
        })
    });
    Ok(Response::new(pkcs11_proxy_ng_proto::EncryptInitResponse { ck_rv, mechanism_out }))
}

pub(crate) async fn encrypt(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::EncryptRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncryptResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptResponse {
                ck_rv: rv.0,
                encrypted_data: Vec::new(),
            }));
        }
    };

    let data = req.data;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.encrypt(session, &data)).await?;
    let (ck_rv, encrypted_data) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::EncryptResponse {
        ck_rv,
        encrypted_data: encrypted_data.unwrap_or_default(),
    }))
}

pub(crate) async fn encrypt_update(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::EncryptUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncryptUpdateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptUpdateResponse {
                ck_rv: rv.0,
                encrypted_part: Vec::new(),
            }));
        }
    };

    let part = req.part;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.encrypt_update(session, &part)).await?;
    let (ck_rv, encrypted_part) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::EncryptUpdateResponse {
        ck_rv,
        encrypted_part: encrypted_part.unwrap_or_default(),
    }))
}

pub(crate) async fn encrypt_final(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::EncryptFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncryptFinalResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptFinalResponse {
                ck_rv: rv.0,
                last_encrypted_part: Vec::new(),
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.encrypt_final(session)).await?;
    let (ck_rv, last_encrypted_part) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::EncryptFinalResponse {
        ck_rv,
        last_encrypted_part: last_encrypted_part.unwrap_or_default(),
    }))
}

pub(crate) async fn decrypt_init(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DecryptInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptInitResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, key) =
        match resolve_session_and_key(ctx_mgr, &ctx_id, req.session_handle, req.key_handle).await {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptInitResponse { ck_rv: rv.0 }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.decrypt_init(session, &mechanism, key)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::DecryptInitResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn decrypt(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DecryptRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptResponse {
                ck_rv: rv.0,
                data: Vec::new(),
            }));
        }
    };

    let encrypted_data = req.encrypted_data;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.decrypt(session, &encrypted_data)).await?;
    let (ck_rv, data) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::DecryptResponse {
        ck_rv,
        data: data.unwrap_or_default(),
    }))
}

pub(crate) async fn decrypt_update(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DecryptUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptUpdateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptUpdateResponse {
                ck_rv: rv.0,
                part: Vec::new(),
            }));
        }
    };

    let encrypted_part = req.encrypted_part;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.decrypt_update(session, &encrypted_part)).await?;
    let (ck_rv, part) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::DecryptUpdateResponse {
        ck_rv,
        part: part.unwrap_or_default(),
    }))
}

pub(crate) async fn decrypt_final(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DecryptFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptFinalResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptFinalResponse {
                ck_rv: rv.0,
                last_part: Vec::new(),
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.decrypt_final(session)).await?;
    let (ck_rv, last_part) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::DecryptFinalResponse {
        ck_rv,
        last_part: last_part.unwrap_or_default(),
    }))
}
