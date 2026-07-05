use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_types::{CkObjectHandle, CkRv};

use super::super::ck_result_to_rv;
use super::super::convert_template;
use super::super::mechanism_handles::remap_mechanism_handles;
use super::super::service_utils::{
    check_sanitize, input_from_wire, parse_mechanism, register_session_object_handle,
    resolve_session_and_object, resolve_session_and_two_objects, spawn_backend,
    template_declares_token_object,
};
use crate::server::context_manager::ClientContextId;
use crate::server::handle_map::VirtualHandle;

use crate::server::grpc_service::HandlerContext;
pub(crate) async fn wrap_key(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::WrapKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::WrapKeyResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
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

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyResponse {
                ck_rv: rv.0,
                wrapped_key: Vec::new(),
            }));
        }
    };

    // B1: remap object handles embedded in the mechanism parameters.
    if let Err(rv) = remap_mechanism_handles(ctx_mgr, &ctx_id, &mut mechanism).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::WrapKeyResponse {
            ck_rv: rv.0,
            wrapped_key: Vec::new(),
        }));
    }

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
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::UnwrapKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::UnwrapKeyResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
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

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
            }));
        }
    };

    // B1: remap object handles embedded in the mechanism parameters.
    if let Err(rv) = remap_mechanism_handles(ctx_mgr, &ctx_id, &mut mechanism).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
        }));
    }

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
                ck_rv: rv,
                key_handle: 0,
            }));
        }
    };

    // An unwrapped key is a session object unless CKA_TOKEN is set (B2).
    let is_token = template_declares_token_object(&template);
    let virtual_session = VirtualHandle(req.session_handle);
    let wrapped_key = req.wrapped_key;
    let wrapped_key_null_len = req.wrapped_key_null_len;
    // ADR-0010 sanitize_inputs: validate NULL wrapped_key pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, wrapped_key_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::UnwrapKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.unwrap_key(
            session,
            &mechanism,
            unwrapping_key,
            input_from_wire(&wrapped_key, wrapped_key_null_len),
            &template,
        )
    })
    .await?;

    match result {
        Ok(object) => {
            let key_handle = register_session_object_handle(
                ctx_mgr,
                &ctx_id,
                virtual_session,
                CkObjectHandle(object.0 as u64),
                is_token,
            )
            .await;
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
