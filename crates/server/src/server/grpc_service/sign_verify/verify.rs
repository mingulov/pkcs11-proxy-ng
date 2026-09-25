// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain;
use std::sync::Arc;
use std::time::Instant;

use pkcs11_proxy_ng_audit::EventClass;
use pkcs11_proxy_ng_types::SecretBytes;
use tonic::{Request, Response, Status};

use super::super::authorization::mechanism_permitted;
use super::super::mechanism_handles::remap_mechanism_handles;
use super::super::service_utils::{
    check_sanitize, ck_rv_only, input_from_wire, parse_mechanism, resolve_session,
    resolve_session_and_key, spawn_backend,
};
use crate::server::context_manager::ClientContextId;
use crate::server::grpc_service::audit_events::emit_auth_event;

use crate::server::grpc_service::HandlerContext;
pub(crate) async fn verify_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::VerifyInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // ADR-0010 sanitize_inputs: reject NULL mechanism before reaching the module.
    if sanitize_inputs && req.mechanism.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD.0,
        }));
    }

    if req.mechanism.is_none() {
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(session) => session,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };
        let backend = Arc::clone(backend_ref);
        let result = spawn_backend(move || backend.verify_init_cancel(session)).await?;
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyInitResponse {
            ck_rv: ck_rv_only(result),
        }));
    }

    let (session, key) =
        match resolve_session_and_key(ctx, &ctx_id, req.session_handle, req.key_handle).await {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyInitResponse { ck_rv: rv.0 }));
        }
    };

    // B1: remap object handles embedded in the mechanism parameters;
    // gate each through per-object authz when active (C1).
    if let Err(rv) =
        remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyInitResponse { ck_rv: rv.0 }));
    }

    // Mechanism policy gate (G3-PR3 Task 3).
    if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID.0,
        }));
    }

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.verify_init(session, &mechanism, key)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyInitResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn verify(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::VerifyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyResponse>, Status> {
    let started = Instant::now();
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyResponse { ck_rv: rv.0 })),
    };

    let data = SecretBytes::new(req.data);
    let data_null_len = req.data_null_len;
    let signature = req.signature;
    let signature_null_len = req.signature_null_len;
    // ADR-0010 sanitize_inputs: validate NULL data/signature pointers before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, data_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyResponse { ck_rv: rv.0 }));
    }
    if let Err(rv) = check_sanitize(sanitize_inputs, signature_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyResponse { ck_rv: rv.0 }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        data.expose(|data_raw| {
            backend.verify(
                session,
                input_from_wire(data_raw, data_null_len),
                input_from_wire(&signature, signature_null_len),
            )
        })
    })
    .await?;
    let ck_rv = ck_rv_only(result);
    // Opt-in data-plane audit: emit fail-open; never reject the op on a dropped record.
    if ctx.audit.as_ref().is_some_and(|a| a.data_plane_enabled()) {
        let _ = emit_auth_event(
            ctx,
            &ctx_id,
            "C_Verify",
            EventClass::DataPlane,
            None,
            Some(req.session_handle),
            ck_rv,
            started,
        );
    }
    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyResponse { ck_rv }))
}

pub(crate) async fn verify_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::VerifyUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyUpdateResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyUpdateResponse { ck_rv: rv.0 }));
        }
    };

    let part = SecretBytes::new(req.part);
    let part_null_len = req.part_null_len;
    // ADR-0010 sanitize_inputs: validate NULL data pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, part_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyUpdateResponse { ck_rv: rv.0 }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        part.expose(|raw| backend.verify_update(session, input_from_wire(raw, part_null_len)))
    })
    .await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyUpdateResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn verify_final(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::VerifyFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyFinalResponse>, Status> {
    let started = Instant::now();
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyFinalResponse { ck_rv: rv.0 }));
        }
    };

    let signature = req.signature;
    let signature_null_len = req.signature_null_len;
    // ADR-0010 sanitize_inputs: validate NULL signature pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, signature_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyFinalResponse { ck_rv: rv.0 }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.verify_final(session, input_from_wire(&signature, signature_null_len))
    })
    .await?;
    let ck_rv = ck_rv_only(result);
    // Opt-in data-plane audit: emit fail-open; never reject the op on a dropped record.
    if ctx.audit.as_ref().is_some_and(|a| a.data_plane_enabled()) {
        let _ = emit_auth_event(
            ctx,
            &ctx_id,
            "C_Verify",
            EventClass::DataPlane,
            None,
            Some(req.session_handle),
            ck_rv,
            started,
        );
    }
    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyFinalResponse { ck_rv }))
}

pub(crate) async fn verify_recover_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::VerifyRecoverInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyRecoverInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // ADR-0010 sanitize_inputs: reject NULL mechanism before reaching the module.
    if sanitize_inputs && req.mechanism.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyRecoverInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD.0,
        }));
    }

    if req.mechanism.is_none() {
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(session) => session,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyRecoverInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };
        let backend = Arc::clone(backend_ref);
        let result = spawn_backend(move || backend.verify_recover_init_cancel(session)).await?;
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyRecoverInitResponse {
            ck_rv: ck_rv_only(result),
        }));
    }

    let (session, key) =
        match resolve_session_and_key(ctx, &ctx_id, req.session_handle, req.key_handle).await {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyRecoverInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyRecoverInitResponse {
                ck_rv: rv.0,
            }));
        }
    };

    // B1: remap object handles embedded in the mechanism parameters;
    // gate each through per-object authz when active (C1).
    if let Err(rv) =
        remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyRecoverInitResponse { ck_rv: rv.0 }));
    }

    // Mechanism policy gate (G3-PR3 Task 3).
    if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyRecoverInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID.0,
        }));
    }

    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.verify_recover_init(session, &mechanism, key)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyRecoverInitResponse {
        ck_rv: ck_rv_only(result),
    }))
}

pub(crate) async fn verify_recover(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::VerifyRecoverRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyRecoverResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
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
    let signature_null_len = req.signature_null_len;
    // ADR-0010 sanitize_inputs: validate NULL signature pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, signature_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyRecoverResponse {
            ck_rv: rv.0,
            data: Vec::new(),
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.verify_recover(session, input_from_wire(&signature, signature_null_len))
    })
    .await?;
    let (ck_rv, data) = super::super::ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyRecoverResponse {
        ck_rv,
        data: secret_to_plain(&data.unwrap_or_default()),
    }))
}
