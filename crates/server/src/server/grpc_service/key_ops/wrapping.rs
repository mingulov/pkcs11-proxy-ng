use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::{CkObjectHandle, CkRv};

use super::super::ck_result_to_rv;
use super::super::convert_template;
use super::super::service_utils::{
    parse_mechanism, register_object_handle, resolve_session_and_object,
    resolve_session_and_two_objects, spawn_backend,
};
use crate::server::context_manager::{ClientContextId, ContextManager};

pub(crate) async fn wrap_key(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::WrapKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::WrapKeyResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, wrapping_key, key) = match resolve_session_and_two_objects(
        ctx_mgr,
        &ctx_id,
        req.session_handle,
        req.wrapping_key_handle,
        req.key_handle,
    )
    .await
    {
        Ok(handles) => handles,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyResponse {
                ck_rv: rv.0,
                wrapped_key: Vec::new(),
            }));
        }
    };

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyResponse {
                ck_rv: rv.0,
                wrapped_key: Vec::new(),
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.wrap_key(session, &mechanism, wrapping_key, key)).await?;
    let (ck_rv, wrapped_key) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyResponse {
        ck_rv,
        wrapped_key: wrapped_key.unwrap_or_default(),
    }))
}

pub(crate) async fn unwrap_key(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::UnwrapKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::UnwrapKeyResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, unwrapping_key) = match resolve_session_and_object(
        ctx_mgr,
        &ctx_id,
        req.session_handle,
        req.unwrapping_key_handle,
    )
    .await
    {
        Ok(handles) => handles,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
            }));
        }
    };

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
            }));
        }
    };

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
                ck_rv: rv,
                key_handle: 0,
            }));
        }
    };

    let wrapped_key = req.wrapped_key;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.unwrap_key(session, &mechanism, unwrapping_key, &wrapped_key, &template)
    })
    .await?;

    match result {
        Ok(object) => {
            let key_handle =
                register_object_handle(ctx_mgr, &ctx_id, CkObjectHandle(object.0)).await;
            Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
                ck_rv: CkRv::OK.0,
                key_handle,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
            ck_rv: error.0,
            key_handle: 0,
        })),
    }
}
