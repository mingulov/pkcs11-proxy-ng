//! gRPC handlers for PKCS#11 3.2 VerifySignature operations (Wave 5).
//!
//! - `C_VerifySignatureInit` (optional mechanism — None = cancel)
//! - `C_VerifySignature` (single-part)
//! - `C_VerifySignatureUpdate` (multi-part data feed)
//! - `C_VerifySignatureFinal` (completes multi-part)

use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{info, warn};

use pkcs11_proxy_ng_types::*;

use super::super::super::context_manager::ClientContextId;
use super::super::authorization::mechanism_permitted;
use super::super::service_utils::{
    check_sanitize, ck_rv_only, input_from_wire, parse_mechanism, resolve_session,
    resolve_session_and_key, spawn_backend,
};

// ---------------------------------------------------------------------------
// C_VerifySignatureInit — optional mechanism (None = cancel)
// ---------------------------------------------------------------------------

use crate::server::grpc_service::HandlerContext;
pub(crate) async fn verify_signature_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::VerifySignatureInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifySignatureInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // ADR-0010 sanitize_inputs: reject NULL mechanism before reaching the module.
    if sanitize_inputs && req.mechanism.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifySignatureInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD.0,
        }));
    }

    if req.mechanism.is_some() {
        // Normal init path: resolve session + key, parse mechanism.
        let (session, key) =
            match resolve_session_and_key(ctx, &ctx_id, req.session_handle, req.key_handle).await {
                Ok(handles) => handles,
                Err(rv) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::VerifySignatureInitResponse {
                        ck_rv: rv.0,
                    }));
                }
            };

        let mechanism = match parse_mechanism(req.mechanism) {
            Ok(m) => m,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::VerifySignatureInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

        if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifySignatureInitResponse {
                ck_rv: CkRv::MECHANISM_INVALID.0,
            }));
        }

        let signature = req.signature;
        let signature_null_len = req.signature_null_len;
        // ADR-0010 sanitize_inputs: validate NULL signature pointer before backend call.
        if let Err(rv) = check_sanitize(sanitize_inputs, signature_null_len) {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifySignatureInitResponse {
                ck_rv: rv.0,
            }));
        }
        let backend = Arc::clone(backend_ref);
        let result = spawn_backend(move || {
            backend.verify_signature_init(
                session,
                Some(&mechanism),
                key,
                input_from_wire(&signature, signature_null_len),
            )
        })
        .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "VerifySignatureInit succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "VerifySignatureInit failed");
                error.0
            }
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::VerifySignatureInitResponse { ck_rv }))
    } else {
        // Cancel path: mechanism absent, key_handle and signature are ignored.
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(s) => s,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::VerifySignatureInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

        let backend = Arc::clone(backend_ref);
        let result = spawn_backend(move || {
            backend.verify_signature_init(session, None, CkObjectHandle(0), CkInBuf::Bytes(&[]))
        })
        .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "VerifySignatureInit (cancel) succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "VerifySignatureInit (cancel) failed");
                error.0
            }
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::VerifySignatureInitResponse { ck_rv }))
    }
}

// ---------------------------------------------------------------------------
// C_VerifySignature — single-part verify (session + data)
// ---------------------------------------------------------------------------

pub(crate) async fn verify_signature(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::VerifySignatureRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifySignatureResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifySignatureResponse {
                ck_rv: rv.0,
            }));
        }
    };

    let data = req.data;
    let data_null_len = req.data_null_len;
    // ADR-0010 sanitize_inputs: validate NULL data pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, data_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifySignatureResponse { ck_rv: rv.0 }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.verify_signature(session, input_from_wire(&data, data_null_len))
    })
    .await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::VerifySignatureResponse { ck_rv: ck_rv_only(result) }))
}

// ---------------------------------------------------------------------------
// C_VerifySignatureUpdate — multi-part data feed (session + data_part)
// ---------------------------------------------------------------------------

pub(crate) async fn verify_signature_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::VerifySignatureUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifySignatureUpdateResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifySignatureUpdateResponse {
                ck_rv: rv.0,
            }));
        }
    };

    let data_part = req.data_part;
    let data_part_null_len = req.data_part_null_len;
    // ADR-0010 sanitize_inputs: validate NULL data_part pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, data_part_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifySignatureUpdateResponse {
            ck_rv: rv.0,
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.verify_signature_update(session, input_from_wire(&data_part, data_part_null_len))
    })
    .await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::VerifySignatureUpdateResponse {
        ck_rv: ck_rv_only(result),
    }))
}

// ---------------------------------------------------------------------------
// C_VerifySignatureFinal — completes multi-part (session-only)
// ---------------------------------------------------------------------------

pub(crate) async fn verify_signature_final(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::VerifySignatureFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifySignatureFinalResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifySignatureFinalResponse {
                ck_rv: rv.0,
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.verify_signature_final(session)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::VerifySignatureFinalResponse {
        ck_rv: ck_rv_only(result),
    }))
}
