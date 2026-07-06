use std::sync::Arc;

use tonic::{Request, Response, Status};

use super::super::ck_result_to_rv;
use super::super::mechanism_handles::remap_mechanism_handles;
use super::super::service_utils::{
    check_sanitize, ck_rv_only, input_from_wire, parse_mechanism, resolve_session,
    resolve_session_and_key, spawn_backend,
};
use crate::server::context_manager::ClientContextId;

use crate::server::grpc_service::HandlerContext;
pub(crate) async fn sign_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // ADR-0010 sanitize_inputs: reject NULL mechanism before reaching the module.
    if sanitize_inputs && req.mechanism.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD.0,
        }));
    }

    if req.mechanism.is_none() {
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(session) => session,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse { ck_rv: rv.0 }));
            }
        };
        let backend = Arc::clone(backend_ref);
        let result = spawn_backend(move || backend.sign_init_cancel(session)).await?;
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse {
            ck_rv: ck_rv_only(result),
        }));
    }

    let (session, key) =
        match resolve_session_and_key(ctx, &ctx_id, req.session_handle, req.key_handle).await {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse { ck_rv: rv.0 }));
            }
        };

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse { ck_rv: rv.0 }));
        }
    };

    // B1: remap object handles embedded in the mechanism parameters.
    if let Err(rv) = remap_mechanism_handles(ctx_mgr, &ctx_id, &mut mechanism).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse { ck_rv: rv.0 }));
    }

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.sign_init(session, &mechanism, key)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn sign(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
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
    let data_null_len = req.data_null_len;
    // ADR-0010 sanitize_inputs: validate NULL data pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, data_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignResponse {
            ck_rv: rv.0,
            signature: Vec::new(),
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.sign(session, input_from_wire(&data, data_null_len))).await?;
    let (ck_rv, signature) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::SignResponse {
        ck_rv,
        signature: signature.unwrap_or_default(),
    }))
}

pub(crate) async fn sign_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignUpdateResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignUpdateResponse { ck_rv: rv.0 }));
        }
    };

    let part = req.part;
    let part_null_len = req.part_null_len;
    // ADR-0010 sanitize_inputs: validate NULL data pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, part_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignUpdateResponse { ck_rv: rv.0 }));
    }
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.sign_update(session, input_from_wire(&part, part_null_len)))
            .await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::SignUpdateResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn sign_final(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignFinalResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
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
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignRecoverInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignRecoverInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // ADR-0010 sanitize_inputs: reject NULL mechanism before reaching the module.
    if sanitize_inputs && req.mechanism.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD.0,
        }));
    }

    if req.mechanism.is_none() {
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(session) => session,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };
        let backend = Arc::clone(backend_ref);
        let result = spawn_backend(move || backend.sign_recover_init_cancel(session)).await?;
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse {
            ck_rv: ck_rv_only(result),
        }));
    }

    let (session, key) =
        match resolve_session_and_key(ctx, &ctx_id, req.session_handle, req.key_handle).await {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse {
                ck_rv: rv.0,
            }));
        }
    };

    // B1: remap object handles embedded in the mechanism parameters.
    if let Err(rv) = remap_mechanism_handles(ctx_mgr, &ctx_id, &mut mechanism).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse { ck_rv: rv.0 }));
    }

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.sign_recover_init(session, &mechanism, key)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn sign_recover(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignRecoverRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignRecoverResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
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
    let data_null_len = req.data_null_len;
    // ADR-0010 sanitize_inputs: validate NULL data pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, data_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverResponse {
            ck_rv: rv.0,
            signature: Vec::new(),
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.sign_recover(session, input_from_wire(&data, data_null_len)))
            .await?;
    let (ck_rv, signature) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverResponse {
        ck_rv,
        signature: signature.unwrap_or_default(),
    }))
}
