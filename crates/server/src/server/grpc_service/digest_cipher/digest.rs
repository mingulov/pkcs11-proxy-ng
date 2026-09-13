use std::sync::Arc;
use std::time::Instant;

use pkcs11_proxy_ng_audit::EventClass;
use tonic::{Request, Response, Status};

use super::super::authorization::mechanism_permitted;
use super::super::ck_result_to_rv;
use super::super::service_utils::{
    check_sanitize, ck_rv_only, input_from_wire, parse_mechanism, resolve_session,
    resolve_session_and_key, spawn_backend,
};
use crate::server::context_manager::ClientContextId;
use crate::server::grpc_service::audit_events::emit_auth_event;

use crate::server::grpc_service::HandlerContext;
pub(crate) async fn digest_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DigestInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DigestInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // ADR-0010 sanitize_inputs: reject NULL mechanism before reaching the module.
    if sanitize_inputs && req.mechanism.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DigestInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD.0,
        }));
    }

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

    if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DigestInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID.0,
        }));
    }

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.digest_init(session, &mechanism)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::DigestInitResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn digest(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DigestRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DigestResponse>, Status> {
    let started = Instant::now();
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
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
    let data_null_len = req.data_null_len;
    // ADR-0010 sanitize_inputs: validate before moving into spawn_backend closure.
    if let Err(rv) = check_sanitize(sanitize_inputs, data_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DigestResponse {
            ck_rv: rv.0,
            digest: Vec::new(),
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.digest(session, input_from_wire(&data, data_null_len)))
            .await?;
    let (ck_rv, digest) = ck_result_to_rv(result);
    // Opt-in data-plane audit: emit fail-open; never reject the op on a dropped record.
    if ctx.audit.as_ref().is_some_and(|a| a.data_plane_enabled()) {
        let _ = emit_auth_event(
            ctx,
            &ctx_id,
            "C_Digest",
            EventClass::DataPlane,
            None,
            Some(req.session_handle),
            ck_rv,
            started,
        );
    }
    Ok(Response::new(pkcs11_proxy_ng_proto::DigestResponse {
        ck_rv,
        digest: digest.unwrap_or_default(),
    }))
}

pub(crate) async fn digest_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DigestUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DigestUpdateResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DigestUpdateResponse { ck_rv: rv.0 }));
        }
    };

    let part = req.part;
    let part_null_len = req.part_null_len;
    // ADR-0010 sanitize_inputs: validate NULL data pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, part_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DigestUpdateResponse { ck_rv: rv.0 }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.digest_update(session, input_from_wire(&part, part_null_len))
    })
    .await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::DigestUpdateResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn digest_key(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DigestKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DigestKeyResponse>, Status> {
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, key) =
        match resolve_session_and_key(ctx, &ctx_id, req.session_handle, req.key_handle).await {
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
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DigestFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DigestFinalResponse>, Status> {
    let started = Instant::now();
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
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
    // Opt-in data-plane audit: emit fail-open; never reject the op on a dropped record.
    if ctx.audit.as_ref().is_some_and(|a| a.data_plane_enabled()) {
        let _ = emit_auth_event(
            ctx,
            &ctx_id,
            "C_Digest",
            EventClass::DataPlane,
            None,
            Some(req.session_handle),
            ck_rv,
            started,
        );
    }
    Ok(Response::new(pkcs11_proxy_ng_proto::DigestFinalResponse {
        ck_rv,
        digest: digest.unwrap_or_default(),
    }))
}
