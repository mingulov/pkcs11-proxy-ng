//! gRPC handlers for PKCS#11 3.2 authenticated wrap/unwrap operations (Wave 5).
//!
//! - `C_WrapKeyAuthenticated`
//! - `C_UnwrapKeyAuthenticated`

use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::{CkObjectHandle, CkRv};

use super::super::convert_template;
use super::super::service_utils::{
    parse_mechanism, register_object_handle, resolve_session_and_two_objects, spawn_backend,
};
use crate::server::context_manager::{ClientContextId, ContextManager};

pub(crate) async fn wrap_key_authenticated(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::WrapKeyAuthenticatedRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::WrapKeyAuthenticatedResponse>, Status> {
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
            return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyAuthenticatedResponse {
                ck_rv: rv.0,
                wrapped_key: Vec::new(),
                mechanism_parameter_out: Vec::new(),
            }));
        }
    };

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyAuthenticatedResponse {
                ck_rv: rv.0,
                wrapped_key: Vec::new(),
                mechanism_parameter_out: Vec::new(),
            }));
        }
    };

    let aad = req.associated_data;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.wrap_key_authenticated(session, &mechanism, wrapping_key, key, &aad)
    })
    .await?;

    match result {
        Ok((wrapped_key, mechanism_parameter_out)) => {
            Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyAuthenticatedResponse {
                ck_rv: CkRv::OK.0,
                wrapped_key,
                mechanism_parameter_out,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyAuthenticatedResponse {
            ck_rv: error.0,
            wrapped_key: Vec::new(),
            mechanism_parameter_out: Vec::new(),
        })),
    }
}

pub(crate) async fn unwrap_key_authenticated(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, unwrapping_key) = match super::super::service_utils::resolve_session_and_object(
        ctx_mgr,
        &ctx_id,
        req.session_handle,
        req.unwrapping_key_handle,
    )
    .await
    {
        Ok(handles) => handles,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedResponse {
                ck_rv: rv.0,
                key_handle: 0,
                mechanism_parameter_out: Vec::new(),
            }));
        }
    };

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedResponse {
                ck_rv: rv.0,
                key_handle: 0,
                mechanism_parameter_out: Vec::new(),
            }));
        }
    };

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedResponse {
                ck_rv: rv,
                key_handle: 0,
                mechanism_parameter_out: Vec::new(),
            }));
        }
    };

    let wrapped_key = req.wrapped_key;
    let aad = req.associated_data;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.unwrap_key_authenticated(
            session,
            &mechanism,
            unwrapping_key,
            &wrapped_key,
            &template,
            &aad,
        )
    })
    .await?;

    match result {
        Ok((key, mechanism_parameter_out)) => {
            let key_handle = register_object_handle(ctx_mgr, &ctx_id, CkObjectHandle(key.0)).await;
            Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedResponse {
                ck_rv: CkRv::OK.0,
                key_handle,
                mechanism_parameter_out,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedResponse {
            ck_rv: error.0,
            key_handle: 0,
            mechanism_parameter_out: Vec::new(),
        })),
    }
}
