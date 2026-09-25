//! Handlers for PKCS#11 3.0 message-based crypto RPCs.
//!
//! Init/final handlers:
//! - `C_MessageEncryptInit` / `C_MessageEncryptFinal`
//! - `C_MessageDecryptInit` / `C_MessageDecryptFinal`
//! - `C_MessageSignInit` / `C_MessageSignFinal`
//! - `C_MessageVerifyInit` / `C_MessageVerifyFinal`
//!
//! One-shot / begin / next handlers:
//! - `C_EncryptMessage` / `C_EncryptMessageBegin` / `C_EncryptMessageNext`
//! - `C_DecryptMessage` / `C_DecryptMessageBegin` / `C_DecryptMessageNext`
//! - `C_SignMessage` / `C_SignMessageBegin` / `C_SignMessageNext`
//! - `C_VerifyMessage` / `C_VerifyMessageBegin` / `C_VerifyMessageNext`

use pkcs11_proxy_ng_proto::convert::message_effects::ParameterEffectCallMode;
use std::sync::Arc;
use std::time::Duration;

use tonic::{Request, Response, Status};
use tracing::{info, warn};

use pkcs11_proxy_ng_proto::convert::message_params::MessageParameter;
use pkcs11_proxy_ng_types::*;

use super::super::context_manager::ClientContextId;
use super::authorization::mechanism_permitted;
use super::mechanism_handles::remap_mechanism_handles;
use super::service_utils::{
    check_sanitize, ck_rv_only, input_from_wire, parse_mechanism, resolve_session,
    resolve_session_and_key, spawn_backend,
};

// ---------------------------------------------------------------------------
// Message Encrypt Init (optional mechanism — None means cancel)
// ---------------------------------------------------------------------------

use crate::server::grpc_service::HandlerContext;
pub(crate) async fn message_encrypt_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::MessageEncryptInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageEncryptInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // ADR-0010 sanitize_inputs: reject NULL mechanism before reaching the module.
    if sanitize_inputs && req.mechanism.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD.0,
        }));
    }

    if req.mechanism.is_some() {
        // Normal init path: resolve session + key, parse mechanism.
        let (session, key) =
            match resolve_session_and_key(ctx, &ctx_id, req.session_handle, req.key_handle).await {
                Ok(handles) => handles,
                Err(rv) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
                        ck_rv: rv.0,
                        ..Default::default()
                    }));
                }
            };

        let mut mechanism = match parse_mechanism(req.mechanism) {
            Ok(m) => m,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
                    ck_rv: rv.0,
                    ..Default::default()
                }));
            }
        };

        // B1: remap object handles embedded in the mechanism parameters;
        // gate each through per-object authz when active (C1).
        if let Err(rv) =
            remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism)
                .await
        {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
                ck_rv: rv.0,
            }));
        }

        // Mechanism policy gate (G3-PR3 Task 3).
        if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
                ck_rv: pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID.0,
            }));
        }

        let init_param =
            match req.init_message_parameter.as_ref().map(MessageParameter::try_from).transpose() {
                Ok(p) => p,
                Err(rv) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
                        ck_rv: rv.0,
                    }));
                }
            };

        let backend = Arc::clone(backend_ref);
        let result = spawn_backend(move || {
            backend.message_encrypt_init(session, Some(&mechanism), init_param.as_ref(), key)
        })
        .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "MessageEncryptInit succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "MessageEncryptInit failed");
                error.0
            }
        };
        let (parameter_result, init_message_parameter) = if result.is_ok()
            && let Some(contract) = contract
        {
            (
                Some(parameter_ack(&contract.caller_spec)),
                init_param_for_response.as_ref().map(Into::into),
            )
        } else {
            (None, None)
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
            ck_rv,
            parameter_result,
            init_message_parameter,
            parameter_shape: result.is_ok().then_some(installed_shape.to_proto_i32()),
        }))
    } else {
        // Cancel path: mechanism absent, key_handle is ignored.
        if req.parameter_shape.is_some()
            || req.parameter_out_spec.is_some()
            || req.init_message_parameter.is_some()
        {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
                ck_rv: CkRv::MECHANISM_PARAM_INVALID.0,
                ..Default::default()
            }));
        }
        let operation_lock = match ctx_mgr
            .message_operation_lock(
                &ctx_id,
                VirtualHandle(req.session_handle),
                ServerMessageOperation::Encrypt,
            )
            .await
        {
            Ok(lock) => lock,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
                    ck_rv: error.0,
                    ..Default::default()
                }));
            }
        };
        let operation = operation_lock.lock_owned().await;
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(s) => s,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
                    ck_rv: rv.0,
                    ..Default::default()
                }));
            }
        };

        let backend = Arc::clone(backend_ref);
        let result = spawn_backend(move || {
            backend.message_encrypt_init(session, None, None, CkObjectHandle(0))
        })
        .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "MessageEncryptInit (cancel) succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "MessageEncryptInit (cancel) failed");
                error.0
            }
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
            ck_rv,
            ..Default::default()
        }))
    }
}

// ---------------------------------------------------------------------------
// Message Encrypt Final (session-only cleanup)
// ---------------------------------------------------------------------------

pub(crate) async fn message_encrypt_final(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::MessageEncryptFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageEncryptFinalResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let operation_lock = match ctx_mgr
        .message_operation_lock(
            &ctx_id,
            VirtualHandle(req.session_handle),
            ServerMessageOperation::Encrypt,
        )
        .await
    {
        Ok(lock) => lock,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptFinalResponse {
                ck_rv: error.0,
            }));
        }
    };
    let operation = operation_lock.lock_owned().await;

    if operation.shape.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptFinalResponse {
            ck_rv: CkRv::OPERATION_NOT_INITIALIZED.0,
        }));
    }

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptFinalResponse {
                ck_rv: rv.0,
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let mut transition = MessageOperationTransition::begin(operation);
    let result = spawn_backend_with_optional_timeout(timeout_override, move || {
        transition.mark_started();
        let result = backend.message_encrypt_final(session);
        transition.settle(&result, None);
        result
    })
    .await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptFinalResponse {
        ck_rv: ck_rv_only(result),
    }))
}

// ---------------------------------------------------------------------------
// Message Decrypt Init (optional mechanism — None means cancel)
// ---------------------------------------------------------------------------

pub(crate) async fn message_decrypt_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::MessageDecryptInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageDecryptInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // ADR-0010 sanitize_inputs: reject NULL mechanism before reaching the module.
    if sanitize_inputs && req.mechanism.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD.0,
        }));
    }

    if req.mechanism.is_some() {
        // Normal init path: resolve session + key, parse mechanism.
        let (session, key) =
            match resolve_session_and_key(ctx, &ctx_id, req.session_handle, req.key_handle).await {
                Ok(handles) => handles,
                Err(rv) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
                        ck_rv: rv.0,
                        ..Default::default()
                    }));
                }
            };

        let mut mechanism = match parse_mechanism(req.mechanism) {
            Ok(m) => m,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
                    ck_rv: rv.0,
                    ..Default::default()
                }));
            }
        };

        // B1: remap object handles embedded in the mechanism parameters;
        // gate each through per-object authz when active (C1).
        if let Err(rv) =
            remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism)
                .await
        {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
                ck_rv: rv.0,
            }));
        }

        // Mechanism policy gate (G3-PR3 Task 3).
        if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
                ck_rv: pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID.0,
            }));
        }

        let init_param =
            match req.init_message_parameter.as_ref().map(MessageParameter::try_from).transpose() {
                Ok(p) => p,
                Err(rv) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
                        ck_rv: rv.0,
                    }));
                }
            };

        let backend = Arc::clone(backend_ref);
        let result = spawn_backend(move || {
            backend.message_decrypt_init(session, Some(&mechanism), init_param.as_ref(), key)
        })
        .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "MessageDecryptInit succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "MessageDecryptInit failed");
                error.0
            }
        };
        let (parameter_result, init_message_parameter) = if result.is_ok()
            && let Some(contract) = contract
        {
            (
                Some(parameter_ack(&contract.caller_spec)),
                init_param_for_response.as_ref().map(Into::into),
            )
        } else {
            (None, None)
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
            ck_rv,
            parameter_result,
            init_message_parameter,
            parameter_shape: result.is_ok().then_some(installed_shape.to_proto_i32()),
        }))
    } else {
        // Cancel path: mechanism absent, key_handle is ignored.
        if req.parameter_shape.is_some()
            || req.parameter_out_spec.is_some()
            || req.init_message_parameter.is_some()
        {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
                ck_rv: CkRv::MECHANISM_PARAM_INVALID.0,
                ..Default::default()
            }));
        }
        let operation_lock = match ctx_mgr
            .message_operation_lock(
                &ctx_id,
                VirtualHandle(req.session_handle),
                ServerMessageOperation::Decrypt,
            )
            .await
        {
            Ok(lock) => lock,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
                    ck_rv: error.0,
                    ..Default::default()
                }));
            }
        };
        let operation = operation_lock.lock_owned().await;
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(s) => s,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
                    ck_rv: rv.0,
                    ..Default::default()
                }));
            }
        };

        let backend = Arc::clone(backend_ref);
        let result = spawn_backend(move || {
            backend.message_decrypt_init(session, None, None, CkObjectHandle(0))
        })
        .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "MessageDecryptInit (cancel) succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "MessageDecryptInit (cancel) failed");
                error.0
            }
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
            ck_rv,
            ..Default::default()
        }))
    }
}

// ---------------------------------------------------------------------------
// Message Decrypt Final (session-only cleanup)
// ---------------------------------------------------------------------------

pub(crate) async fn message_decrypt_final(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::MessageDecryptFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageDecryptFinalResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let operation_lock = match ctx_mgr
        .message_operation_lock(
            &ctx_id,
            VirtualHandle(req.session_handle),
            ServerMessageOperation::Decrypt,
        )
        .await
    {
        Ok(lock) => lock,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptFinalResponse {
                ck_rv: error.0,
            }));
        }
    };
    let operation = operation_lock.lock_owned().await;

    if operation.shape.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptFinalResponse {
            ck_rv: CkRv::OPERATION_NOT_INITIALIZED.0,
        }));
    }

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptFinalResponse {
                ck_rv: rv.0,
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let mut transition = MessageOperationTransition::begin(operation);
    let result = spawn_backend_with_optional_timeout(timeout_override, move || {
        transition.mark_started();
        let result = backend.message_decrypt_final(session);
        transition.settle(&result, None);
        result
    })
    .await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptFinalResponse {
        ck_rv: ck_rv_only(result),
    }))
}

// ---------------------------------------------------------------------------
// Message Sign Init (optional mechanism — None means cancel)
// ---------------------------------------------------------------------------

pub(crate) async fn message_sign_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::MessageSignInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageSignInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // ADR-0010 sanitize_inputs: reject NULL mechanism before reaching the module.
    if sanitize_inputs && req.mechanism.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD.0,
        }));
    }

    if req.mechanism.is_some() {
        // Normal init path: resolve session + key, parse mechanism.
        let (session, key) =
            match resolve_session_and_key(ctx, &ctx_id, req.session_handle, req.key_handle).await {
                Ok(handles) => handles,
                Err(rv) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignInitResponse {
                        ck_rv: rv.0,
                    }));
                }
            };

        let mut mechanism = match parse_mechanism(req.mechanism) {
            Ok(m) => m,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

        // B1: remap object handles embedded in the mechanism parameters;
        // gate each through per-object authz when active (C1).
        if let Err(rv) =
            remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism)
                .await
        {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignInitResponse {
                ck_rv: rv.0,
            }));
        }

        // Mechanism policy gate (G3-PR3 Task 3).
        if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignInitResponse {
                ck_rv: pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID.0,
            }));
        }

        let backend = Arc::clone(backend_ref);
        let mut transition = MessageOperationTransition::begin(operation);
        let result = spawn_backend(move || {
            transition.mark_started();
            let result = backend.message_sign_init(session, Some(&mechanism), key);
            transition.settle(&result, Some(MessageParameterShape::Unmodeled));
            result
        })
        .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "MessageSignInit succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "MessageSignInit failed");
                error.0
            }
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignInitResponse { ck_rv }))
    } else {
        // Cancel path: mechanism absent, key_handle is ignored.
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(s) => s,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

        let backend = Arc::clone(backend_ref);
        let mut transition = MessageOperationTransition::begin(operation);
        let result = spawn_backend(move || {
            transition.mark_started();
            let result = backend.message_sign_init(session, None, CkObjectHandle(0));
            transition.settle(&result, None);
            result
        })
        .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "MessageSignInit (cancel) succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "MessageSignInit (cancel) failed");
                error.0
            }
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignInitResponse { ck_rv }))
    }
}

// ---------------------------------------------------------------------------
// Message Sign Final (session-only cleanup)
// ---------------------------------------------------------------------------

pub(crate) async fn message_sign_final(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::MessageSignFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageSignFinalResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let operation_lock = match ctx_mgr
        .message_operation_lock(
            &ctx_id,
            VirtualHandle(req.session_handle),
            ServerMessageOperation::Sign,
        )
        .await
    {
        Ok(lock) => lock,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignFinalResponse {
                ck_rv: error.0,
            }));
        }
    };
    let operation = operation_lock.lock_owned().await;

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignFinalResponse {
                ck_rv: rv.0,
            }));
        }
    };

    if operation.shape.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignFinalResponse {
            ck_rv: CkRv::OPERATION_NOT_INITIALIZED.0,
        }));
    }
    let backend = Arc::clone(backend_ref);
    let mut transition = MessageOperationTransition::begin(operation);
    let result = spawn_backend(move || {
        transition.mark_started();
        let result = backend.message_sign_final(session);
        transition.settle(&result, None);
        result
    })
    .await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignFinalResponse { ck_rv: ck_rv_only(result) }))
}

// ---------------------------------------------------------------------------
// Message Verify Init (optional mechanism — None means cancel)
// ---------------------------------------------------------------------------

pub(crate) async fn message_verify_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::MessageVerifyInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageVerifyInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // ADR-0010 sanitize_inputs: reject NULL mechanism before reaching the module.
    if sanitize_inputs && req.mechanism.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD.0,
        }));
    }

    if req.mechanism.is_some() {
        // Normal init path: resolve session + key, parse mechanism.
        let (session, key) =
            match resolve_session_and_key(ctx, &ctx_id, req.session_handle, req.key_handle).await {
                Ok(handles) => handles,
                Err(rv) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyInitResponse {
                        ck_rv: rv.0,
                    }));
                }
            };

        let mut mechanism = match parse_mechanism(req.mechanism) {
            Ok(m) => m,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

        // B1: remap object handles embedded in the mechanism parameters;
        // gate each through per-object authz when active (C1).
        if let Err(rv) =
            remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism)
                .await
        {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyInitResponse {
                ck_rv: rv.0,
            }));
        }

        // Mechanism policy gate (G3-PR3 Task 3).
        if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyInitResponse {
                ck_rv: pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID.0,
            }));
        }

        let backend = Arc::clone(backend_ref);
        let mut transition = MessageOperationTransition::begin(operation);
        let result = spawn_backend(move || {
            transition.mark_started();
            let result = backend.message_verify_init(session, Some(&mechanism), key);
            transition.settle(&result, Some(MessageParameterShape::Unmodeled));
            result
        })
        .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "MessageVerifyInit succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "MessageVerifyInit failed");
                error.0
            }
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyInitResponse { ck_rv }))
    } else {
        // Cancel path: mechanism absent, key_handle is ignored.
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(s) => s,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

        let backend = Arc::clone(backend_ref);
        let mut transition = MessageOperationTransition::begin(operation);
        let result = spawn_backend(move || {
            transition.mark_started();
            let result = backend.message_verify_init(session, None, CkObjectHandle(0));
            transition.settle(&result, None);
            result
        })
        .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "MessageVerifyInit (cancel) succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "MessageVerifyInit (cancel) failed");
                error.0
            }
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyInitResponse { ck_rv }))
    }
}

// ---------------------------------------------------------------------------
// Message Verify Final (session-only cleanup)
// ---------------------------------------------------------------------------

pub(crate) async fn message_verify_final(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::MessageVerifyFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageVerifyFinalResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let operation_lock = match ctx_mgr
        .message_operation_lock(
            &ctx_id,
            VirtualHandle(req.session_handle),
            ServerMessageOperation::Verify,
        )
        .await
    {
        Ok(lock) => lock,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyFinalResponse {
                ck_rv: error.0,
            }));
        }
    };
    let operation = operation_lock.lock_owned().await;

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyFinalResponse {
                ck_rv: rv.0,
            }));
        }
    };

    if operation.shape.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyFinalResponse {
            ck_rv: CkRv::OPERATION_NOT_INITIALIZED.0,
        }));
    }
    let backend = Arc::clone(backend_ref);
    let mut transition = MessageOperationTransition::begin(operation);
    let result = spawn_backend(move || {
        transition.mark_started();
        let result = backend.message_verify_final(session);
        transition.settle(&result, None);
        result
    })
    .await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyFinalResponse {
        ck_rv: ck_rv_only(result),
    }))
}

// ===========================================================================
// One-shot / Begin / Next handlers
// ===========================================================================

// ---------------------------------------------------------------------------
// C_EncryptMessage — one-shot encrypt with parameter_out + ciphertext
// ---------------------------------------------------------------------------

pub(crate) async fn encrypt_message(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::EncryptMessageRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncryptMessageResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let operation_lock = match ctx_mgr
        .message_operation_lock(
            &ctx_id,
            VirtualHandle(req.session_handle),
            ServerMessageOperation::Encrypt,
        )
        .await
    {
        Ok(lock) => lock,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageResponse {
                ck_rv: error.0,
                parameter_out: Vec::new(),
                ciphertext: Vec::new(),
            }));
        }
    };
    let operation = operation_lock.lock_owned().await;
    if !req.parameter.is_empty() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageResponse {
            ck_rv: CkRv::MECHANISM_PARAM_INVALID.0,
            parameter_out: Vec::new(),
            ciphertext: Vec::new(),
        }));
    }
    let installed_shape = match operation.shape {
        Some(shape) => shape,
        None => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageResponse {
                ck_rv: CkRv::OPERATION_NOT_INITIALIZED.0,
                parameter_out: Vec::new(),
                ciphertext: Vec::new(),
            }));
        }
    };

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
                ciphertext: Vec::new(),
            }));
        }
    };

    let mut parameter = req.parameter;
    let aad = req.associated_data;
    let aad_null_len = req.associated_data_null_len;
    let plaintext = req.plaintext;
    let plaintext_null_len = req.plaintext_null_len;
    // ADR-0010 sanitize_inputs: validate NULL aad/plaintext pointers before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, aad_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageResponse {
            ck_rv: rv.0,
            parameter_out: Vec::new(),
            ciphertext: Vec::new(),
        }));
    }
    if let Err(rv) = check_sanitize(sanitize_inputs, plaintext_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageResponse {
            ck_rv: rv.0,
            parameter_out: Vec::new(),
            ciphertext: Vec::new(),
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.encrypt_message(
            session,
            &mut parameter,
            input_from_wire(&aad, aad_null_len),
            input_from_wire(&plaintext, plaintext_null_len),
        )
    })
    .await?;

    match result {
        Ok(ciphertext) => Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageResponse {
            ck_rv: CkRv::OK.0,
            parameter_out: Vec::new(),
            ciphertext: secret_to_plain(&ciphertext),
        })),
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
            ciphertext: Vec::new(),
        })),
    }
}

// ---------------------------------------------------------------------------
// C_EncryptMessageBegin — returns parameter_out only
// ---------------------------------------------------------------------------

pub(crate) async fn encrypt_message_begin(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::EncryptMessageBeginRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncryptMessageBeginResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageBeginResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
            }));
        }
    };

    let mut parameter = req.parameter;
    let aad = req.associated_data;
    let aad_null_len = req.associated_data_null_len;
    // ADR-0010 sanitize_inputs: validate NULL aad pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, aad_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageBeginResponse {
            ck_rv: rv.0,
            parameter_out: Vec::new(),
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.encrypt_message_begin(session, &mut parameter, input_from_wire(&aad, aad_null_len))
    })
    .await?;

    match result {
        Ok(parameter_out) => {
            Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageBeginResponse {
                ck_rv: CkRv::OK.0,
                parameter_out,
            }))
        }
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageBeginResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
        })),
    }
    let ctx_id = ClientContextId(req.client_context_id);
    let result = execute_message_begin(
        ctx,
        ctx_id,
        req.session_handle,
        ServerMessageOperation::Encrypt,
        SecretBytes::new(req.parameter),
        SecretBytes::new(req.associated_data),
        req.associated_data_null_len,
        req.parameter_out_spec,
        req.message_parameter,
    )
    .await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageBeginResponse {
        ck_rv: result.ck_rv,
        parameter_out: result.parameter_out,
        parameter_result: result.parameter_result,
        message_parameter_out: result.message_parameter_out,
        message_effects: result.message_effects,
    }))
}

// ---------------------------------------------------------------------------
// C_EncryptMessageNext — returns parameter_out + ciphertext_part
// ---------------------------------------------------------------------------

pub(crate) async fn encrypt_message_next(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::EncryptMessageNextRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncryptMessageNextResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let operation_lock = match ctx_mgr
        .message_operation_lock(
            &ctx_id,
            VirtualHandle(req.session_handle),
            ServerMessageOperation::Encrypt,
        )
        .await
    {
        Ok(lock) => lock,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageNextResponse {
                ck_rv: error.0,
                parameter_out: Vec::new(),
                ciphertext_part: Vec::new(),
            }));
        }
    };
    let operation = operation_lock.lock_owned().await;
    if !req.parameter.is_empty() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageNextResponse {
            ck_rv: CkRv::MECHANISM_PARAM_INVALID.0,
            parameter_out: Vec::new(),
            ciphertext_part: Vec::new(),
        }));
    }
    let installed_shape = match operation.shape {
        Some(shape) => shape,
        None => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageNextResponse {
                ck_rv: CkRv::OPERATION_NOT_INITIALIZED.0,
                parameter_out: Vec::new(),
                ciphertext_part: Vec::new(),
            }));
        }
    };

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageNextResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
                ciphertext_part: Vec::new(),
            }));
        }
    };

    let mut parameter = req.parameter;
    let plaintext_part = req.plaintext_part;
    let plaintext_part_null_len = req.plaintext_part_null_len;
    let flags = CkFlags(req.flags as u64);
    // ADR-0010 sanitize_inputs: validate NULL plaintext_part pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, plaintext_part_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageNextResponse {
            ck_rv: rv.0,
            parameter_out: Vec::new(),
            ciphertext_part: Vec::new(),
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.encrypt_message_next(
            session,
            &mut parameter,
            input_from_wire(&plaintext_part, plaintext_part_null_len),
            flags,
        )
    })
    .await?;

    match result {
        Ok(ciphertext_part) => {
            Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageNextResponse {
                ck_rv: CkRv::OK.0,
                parameter_out: Vec::new(),
                ciphertext_part: secret_to_plain(&ciphertext_part),
            }))
        }
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageNextResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
            ciphertext_part: Vec::new(),
        })),
    }
}

// ---------------------------------------------------------------------------
// C_DecryptMessage — one-shot decrypt with parameter_out + plaintext
// ---------------------------------------------------------------------------

pub(crate) async fn decrypt_message(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DecryptMessageRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptMessageResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let operation_lock = match ctx_mgr
        .message_operation_lock(
            &ctx_id,
            VirtualHandle(req.session_handle),
            ServerMessageOperation::Decrypt,
        )
        .await
    {
        Ok(lock) => lock,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageResponse {
                ck_rv: error.0,
                parameter_out: Vec::new(),
                plaintext: Vec::new(),
            }));
        }
    };
    let operation = operation_lock.lock_owned().await;
    if !req.parameter.is_empty() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageResponse {
            ck_rv: CkRv::MECHANISM_PARAM_INVALID.0,
            parameter_out: Vec::new(),
            plaintext: Vec::new(),
        }));
    }
    let installed_shape = match operation.shape {
        Some(shape) => shape,
        None => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageResponse {
                ck_rv: CkRv::OPERATION_NOT_INITIALIZED.0,
                parameter_out: Vec::new(),
                plaintext: Vec::new(),
            }));
        }
    };

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
                plaintext: Vec::new(),
            }));
        }
    };

    let mut parameter = req.parameter;
    let aad = req.associated_data;
    let aad_null_len = req.associated_data_null_len;
    let ciphertext = req.ciphertext;
    let ciphertext_null_len = req.ciphertext_null_len;
    // ADR-0010 sanitize_inputs: validate NULL aad/ciphertext pointers before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, aad_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageResponse {
            ck_rv: rv.0,
            parameter_out: Vec::new(),
            plaintext: Vec::new(),
        }));
    }
    if let Err(rv) = check_sanitize(sanitize_inputs, ciphertext_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageResponse {
            ck_rv: rv.0,
            parameter_out: Vec::new(),
            plaintext: Vec::new(),
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.decrypt_message(
            session,
            &mut parameter,
            input_from_wire(&aad, aad_null_len),
            input_from_wire(&ciphertext, ciphertext_null_len),
        )
    })
    .await?;

    match result {
        Ok(plaintext) => Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageResponse {
            ck_rv: CkRv::OK.0,
            parameter_out: Vec::new(),
            plaintext: secret_to_plain(&plaintext),
        })),
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
            plaintext: Vec::new(),
        })),
    }
}

// ---------------------------------------------------------------------------
// C_DecryptMessageBegin — returns parameter_out only
// ---------------------------------------------------------------------------

pub(crate) async fn decrypt_message_begin(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DecryptMessageBeginRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptMessageBeginResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageBeginResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
            }));
        }
    };

    let mut parameter = req.parameter;
    let aad = req.associated_data;
    let aad_null_len = req.associated_data_null_len;
    // ADR-0010 sanitize_inputs: validate NULL aad pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, aad_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageBeginResponse {
            ck_rv: rv.0,
            parameter_out: Vec::new(),
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.decrypt_message_begin(session, &mut parameter, input_from_wire(&aad, aad_null_len))
    })
    .await?;

    match result {
        Ok(parameter_out) => {
            Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageBeginResponse {
                ck_rv: CkRv::OK.0,
                parameter_out,
            }))
        }
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageBeginResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
        })),
    }
    let ctx_id = ClientContextId(req.client_context_id);
    let result = execute_message_begin(
        ctx,
        ctx_id,
        req.session_handle,
        ServerMessageOperation::Decrypt,
        SecretBytes::new(req.parameter),
        SecretBytes::new(req.associated_data),
        req.associated_data_null_len,
        req.parameter_out_spec,
        req.message_parameter,
    )
    .await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageBeginResponse {
        ck_rv: result.ck_rv,
        parameter_out: result.parameter_out,
        parameter_result: result.parameter_result,
        message_parameter_out: result.message_parameter_out,
        message_effects: result.message_effects,
    }))
}

// ---------------------------------------------------------------------------
// C_DecryptMessageNext — returns parameter_out + plaintext_part
// ---------------------------------------------------------------------------

pub(crate) async fn decrypt_message_next(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DecryptMessageNextRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptMessageNextResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let operation_lock = match ctx_mgr
        .message_operation_lock(
            &ctx_id,
            VirtualHandle(req.session_handle),
            ServerMessageOperation::Decrypt,
        )
        .await
    {
        Ok(lock) => lock,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageNextResponse {
                ck_rv: error.0,
                parameter_out: Vec::new(),
                plaintext_part: Vec::new(),
            }));
        }
    };
    let operation = operation_lock.lock_owned().await;
    if !req.parameter.is_empty() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageNextResponse {
            ck_rv: CkRv::MECHANISM_PARAM_INVALID.0,
            parameter_out: Vec::new(),
            plaintext_part: Vec::new(),
        }));
    }
    let installed_shape = match operation.shape {
        Some(shape) => shape,
        None => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageNextResponse {
                ck_rv: CkRv::OPERATION_NOT_INITIALIZED.0,
                parameter_out: Vec::new(),
                plaintext_part: Vec::new(),
            }));
        }
    };

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageNextResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
                plaintext_part: Vec::new(),
            }));
        }
    };

    let ciphertext_part = req.ciphertext_part;
    let ciphertext_part_null_len = req.ciphertext_part_null_len;
    let flags = CkFlags(req.flags as u64);
    // ADR-0010 sanitize_inputs: validate NULL ciphertext_part pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, ciphertext_part_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageNextResponse {
            ck_rv: rv.0,
            parameter_out: Vec::new(),
            plaintext_part: Vec::new(),
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.decrypt_message_next(
            session,
            &mut parameter,
            input_from_wire(&ciphertext_part, ciphertext_part_null_len),
            flags,
        )
    })
    .await?;

    match result {
        Ok(plaintext_part) => {
            Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageNextResponse {
                ck_rv: CkRv::OK.0,
                parameter_out: Vec::new(),
                plaintext_part: secret_to_plain(&plaintext_part),
            }))
        }
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageNextResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
            plaintext_part: Vec::new(),
        })),
    }
}

// ---------------------------------------------------------------------------
// C_SignMessage — one-shot sign with parameter_out + signature
// ---------------------------------------------------------------------------

pub(crate) async fn sign_message(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignMessageRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignMessageResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let operation_lock = match ctx_mgr
        .message_operation_lock(
            &ctx_id,
            VirtualHandle(req.session_handle),
            ServerMessageOperation::Sign,
        )
        .await
    {
        Ok(lock) => lock,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageResponse {
                ck_rv: error.0,
                parameter_out: Vec::new(),
                signature: Vec::new(),
            }));
        }
    };
    let operation = operation_lock.lock_owned().await;
    if !req.parameter.is_empty() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageResponse {
            ck_rv: CkRv::MECHANISM_PARAM_INVALID.0,
            parameter_out: Vec::new(),
            signature: Vec::new(),
        }));
    }
    let installed_shape = match operation.shape {
        Some(shape) => shape,
        None => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageResponse {
                ck_rv: CkRv::OPERATION_NOT_INITIALIZED.0,
                parameter_out: Vec::new(),
                signature: Vec::new(),
            }));
        }
    };

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
                signature: Vec::new(),
            }));
        }
    };

    let mut parameter = req.parameter;
    let data = req.data;
    let data_null_len = req.data_null_len;
    // ADR-0010 sanitize_inputs: validate NULL data pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, data_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageResponse {
            ck_rv: rv.0,
            parameter_out: Vec::new(),
            signature: Vec::new(),
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.sign_message(session, &mut parameter, input_from_wire(&data, data_null_len))
    })
    .await?;

    match result {
        Ok(signature) => Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageResponse {
            ck_rv: CkRv::OK.0,
            parameter_out: Vec::new(),
            signature: secret_to_plain(&signature),
        })),
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
            signature: Vec::new(),
        })),
    }
}

// ---------------------------------------------------------------------------
// C_SignMessageBegin — returns parameter_out only
// ---------------------------------------------------------------------------

pub(crate) async fn sign_message_begin(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignMessageBeginRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignMessageBeginResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let operation_lock = match ctx_mgr
        .message_operation_lock(
            &ctx_id,
            VirtualHandle(req.session_handle),
            ServerMessageOperation::Sign,
        )
        .await
    {
        Ok(lock) => lock,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageBeginResponse {
                ck_rv: error.0,
                parameter_out: Vec::new(),
                parameter_result: None,
            }));
        }
    };
    let operation = operation_lock.lock_owned().await;

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageBeginResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
                parameter_result: None,
            }));
        }
    };
    if operation.shape.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageBeginResponse {
            ck_rv: CkRv::OPERATION_NOT_INITIALIZED.0,
            parameter_out: Vec::new(),
            parameter_result: None,
        }));
    }
    let contract = match validate_empty_message_parameter_contract(
        &req.parameter,
        req.parameter_out_spec.as_ref(),
    ) {
        Ok(contract) => contract,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageBeginResponse {
                ck_rv: error.0,
                parameter_out: Vec::new(),
                parameter_result: None,
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let mut transition = MessageOperationTransition::begin(operation);
    if let Some(spec) = contract {
        let response_spec = spec.clone();
        let result = spawn_backend(move || {
            transition.mark_started();
            match backend.sign_message_begin_exact(session, &spec) {
                Ok(ack) if parameter_result_matches_spec(&ack, &spec) => {
                    let outcome = Ok(());
                    transition.settle(&outcome, Some(MessageParameterShape::Unmodeled));
                    outcome
                }
                Ok(_) => {
                    transition.settle_ambiguous();
                    Err(CkRv::DEVICE_ERROR)
                }
                Err(error) => {
                    let outcome = Err(error);
                    transition.settle(&outcome, Some(MessageParameterShape::Unmodeled));
                    outcome
                }
            }
        })
        .await?;
        let (ck_rv, parameter_result) = match result {
            Ok(()) => (CkRv::OK.0, Some(parameter_ack(&response_spec))),
            Err(error) => (error.0, None),
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageBeginResponse {
            ck_rv,
            parameter_out: Vec::new(),
            parameter_result,
        }))
    } else {
        let result = spawn_backend(move || {
            transition.mark_started();
            let mut parameter = Vec::new();
            let result = backend.sign_message_begin(session, &mut parameter);
            match result {
                Ok(parameter_out) if parameter_out.is_empty() => {
                    let outcome = Ok(());
                    transition.settle(&outcome, Some(MessageParameterShape::Unmodeled));
                    outcome
                }
                Ok(_) => {
                    transition.settle_ambiguous();
                    Err(CkRv::DEVICE_ERROR)
                }
                Err(error) => {
                    let outcome = Err(error);
                    transition.settle(&outcome, Some(MessageParameterShape::Unmodeled));
                    outcome
                }
            }
        })
        .await?;
        Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageBeginResponse {
            ck_rv: ck_rv_only(result),
            parameter_out: Vec::new(),
            parameter_result: None,
        }))
    }
}

// ---------------------------------------------------------------------------
// C_SignMessageNext — returns parameter_out + signature (may be empty)
// ---------------------------------------------------------------------------

pub(crate) async fn sign_message_next(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignMessageNextRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignMessageNextResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let operation_lock = match ctx_mgr
        .message_operation_lock(
            &ctx_id,
            VirtualHandle(req.session_handle),
            ServerMessageOperation::Sign,
        )
        .await
    {
        Ok(lock) => lock,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageNextResponse {
                ck_rv: error.0,
                parameter_out: Vec::new(),
                signature: Vec::new(),
                parameter_result: None,
            }));
        }
    };
    let operation = operation_lock.lock_owned().await;

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageNextResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
                signature: Vec::new(),
                parameter_result: None,
            }));
        }
    };

    let mut parameter = req.parameter;
    let data_part = req.data_part;
    let data_part_null_len = req.data_part_null_len;
    let request_signature = req.request_signature;
    // ADR-0010 sanitize_inputs: validate NULL data_part pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, data_part_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageNextResponse {
            ck_rv: rv.0,
            parameter_out: Vec::new(),
            signature: Vec::new(),
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.sign_message_next(
            session,
            &mut parameter,
            input_from_wire(&data_part, data_part_null_len),
            request_signature,
        )
    })
    .await?;

    match result {
        Ok((parameter_out, signature)) => {
            Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageNextResponse {
                ck_rv: CkRv::OK.0,
                parameter_out,
                signature,
            }))
        }
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageNextResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
            signature: Vec::new(),
            parameter_result: None,
        }));
    }
    let contract = match validate_empty_message_parameter_contract(
        &req.parameter,
        req.parameter_out_spec.as_ref(),
    ) {
        Ok(Some(_)) if req.request_signature => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageNextResponse {
                ck_rv: CkRv::MECHANISM_PARAM_INVALID.0,
                parameter_out: Vec::new(),
                signature: Vec::new(),
                parameter_result: None,
            }));
        }
        Ok(contract) => contract,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageNextResponse {
                ck_rv: error.0,
                parameter_out: Vec::new(),
                signature: Vec::new(),
                parameter_result: None,
            }));
        }
    };
    let data_part = SecretBytes::new(req.data_part);
    let data_part_null_len = req.data_part_null_len;
    let request_signature = req.request_signature;
    // ADR-0010 sanitize_inputs: validate NULL data_part pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, data_part_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageNextResponse {
            ck_rv: rv.0,
            parameter_out: Vec::new(),
            signature: Vec::new(),
            parameter_result: None,
        }));
    }
    let backend = Arc::clone(backend_ref);
    let mut transition = MessageOperationTransition::begin(operation);
    if let Some(spec) = contract {
        let response_spec = spec.clone();
        let result = spawn_backend(move || {
            data_part.expose(|dp_raw| {
                transition.mark_started();
                match backend.sign_message_next_feed_exact(
                    session,
                    input_from_wire(dp_raw, data_part_null_len),
                    &spec,
                ) {
                    Ok(ack) if parameter_result_matches_spec(&ack, &spec) => {
                        let outcome = Ok(());
                        transition.settle(&outcome, Some(MessageParameterShape::Unmodeled));
                        outcome
                    }
                    Ok(_) => {
                        transition.settle_ambiguous();
                        Err(CkRv::DEVICE_ERROR)
                    }
                    Err(error) => {
                        let outcome = Err(error);
                        transition.settle(&outcome, Some(MessageParameterShape::Unmodeled));
                        outcome
                    }
                }
            })
        })
        .await?;
        let (ck_rv, parameter_result) = match result {
            Ok(()) => (CkRv::OK.0, Some(parameter_ack(&response_spec))),
            Err(error) => (error.0, None),
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageNextResponse {
            ck_rv,
            parameter_out: Vec::new(),
            signature: Vec::new(),
            parameter_result,
        }))
    } else {
        let result = spawn_backend(move || {
            data_part.expose(|dp_raw| {
                transition.mark_started();
                let mut parameter = Vec::new();
                match backend.sign_message_next(
                    session,
                    &mut parameter,
                    input_from_wire(dp_raw, data_part_null_len),
                    request_signature,
                ) {
                    Ok((parameter_out, signature))
                        if parameter_out.is_empty()
                            && (request_signature || signature.is_empty()) =>
                    {
                        let outcome = Ok(());
                        transition.settle(&outcome, Some(MessageParameterShape::Unmodeled));
                        Ok(signature)
                    }
                    Ok(_) => {
                        transition.settle_ambiguous();
                        Err(CkRv::DEVICE_ERROR)
                    }
                    Err(error) => {
                        let outcome: CkResult<()> = Err(error);
                        transition.settle(&outcome, Some(MessageParameterShape::Unmodeled));
                        Err(error)
                    }
                }
            })
        })
        .await?;
        match result {
            Ok(signature) => Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageNextResponse {
                ck_rv: CkRv::OK.0,
                parameter_out: Vec::new(),
                signature: secret_to_plain(&signature),
                parameter_result: None,
            })),
            Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageNextResponse {
                ck_rv: error.0,
                parameter_out: Vec::new(),
                signature: Vec::new(),
                parameter_result: None,
            })),
        }
    }
}

// ---------------------------------------------------------------------------
// C_VerifyMessage — no output buffer, parameter is input-only
// ---------------------------------------------------------------------------

pub(crate) async fn verify_message(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::VerifyMessageRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyMessageResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let operation_lock = match ctx_mgr
        .message_operation_lock(
            &ctx_id,
            VirtualHandle(req.session_handle),
            ServerMessageOperation::Verify,
        )
        .await
    {
        Ok(lock) => lock,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageResponse {
                ck_rv: error.0,
                parameter_result: None,
            }));
        }
    };
    let operation = operation_lock.lock_owned().await;

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageResponse {
                ck_rv: rv.0,
                parameter_result: None,
            }));
        }
    };

    let parameter = req.parameter;
    let data = req.data;
    let data_null_len = req.data_null_len;
    let signature = req.signature;
    let signature_null_len = req.signature_null_len;
    // ADR-0010 sanitize_inputs: validate NULL data/signature pointers before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, data_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageResponse { ck_rv: rv.0 }));
    }
    if let Err(rv) = check_sanitize(sanitize_inputs, signature_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageResponse { ck_rv: rv.0 }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.verify_message(
            session,
            &parameter,
            input_from_wire(&data, data_null_len),
            input_from_wire(&signature, signature_null_len),
        )
    })
    .await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageResponse { ck_rv: ck_rv_only(result) }))
}

// ---------------------------------------------------------------------------
// C_VerifyMessageBegin — no output, parameter is input-only
// ---------------------------------------------------------------------------

pub(crate) async fn verify_message_begin(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::VerifyMessageBeginRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyMessageBeginResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let operation_lock = match ctx_mgr
        .message_operation_lock(
            &ctx_id,
            VirtualHandle(req.session_handle),
            ServerMessageOperation::Verify,
        )
        .await
    {
        Ok(lock) => lock,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageBeginResponse {
                ck_rv: error.0,
                parameter_out: Vec::new(),
                parameter_result: None,
            }));
        }
    };
    let operation = operation_lock.lock_owned().await;

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageBeginResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
                parameter_result: None,
            }));
        }
    };

    if operation.shape.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageBeginResponse {
            ck_rv: CkRv::OPERATION_NOT_INITIALIZED.0,
            parameter_out: Vec::new(),
            parameter_result: None,
        }));
    }
    let contract = match validate_empty_message_parameter_contract(
        &req.parameter,
        req.parameter_out_spec.as_ref(),
    ) {
        Ok(contract) => contract,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageBeginResponse {
                ck_rv: error.0,
                parameter_out: Vec::new(),
                parameter_result: None,
            }));
        }
    };
    let backend = Arc::clone(backend_ref);
    let mut transition = MessageOperationTransition::begin(operation);
    if let Some(spec) = contract {
        let response_spec = spec.clone();
        let result = spawn_backend(move || {
            transition.mark_started();
            match backend.verify_message_begin_exact(session, &spec) {
                Ok(ack) if parameter_result_matches_spec(&ack, &spec) => {
                    let outcome = Ok(());
                    transition.settle(&outcome, Some(MessageParameterShape::Unmodeled));
                    outcome
                }
                Ok(_) => {
                    transition.settle_ambiguous();
                    Err(CkRv::DEVICE_ERROR)
                }
                Err(error) => {
                    let outcome = Err(error);
                    transition.settle(&outcome, Some(MessageParameterShape::Unmodeled));
                    outcome
                }
            }
        })
        .await?;
        let (ck_rv, parameter_result) = match result {
            Ok(()) => (CkRv::OK.0, Some(parameter_ack(&response_spec))),
            Err(error) => (error.0, None),
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageBeginResponse {
            ck_rv,
            parameter_out: Vec::new(),
            parameter_result,
        }))
    } else {
        let result = spawn_backend(move || {
            transition.mark_started();
            let result = backend.verify_message_begin(session, &[]);
            transition.settle(&result, Some(MessageParameterShape::Unmodeled));
            result
        })
        .await?;
        Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageBeginResponse {
            ck_rv: ck_rv_only(result),
            parameter_out: Vec::new(),
            parameter_result: None,
        }))
    }
}

// ---------------------------------------------------------------------------
// C_VerifyMessageNext — no output buffer
// ---------------------------------------------------------------------------

pub(crate) async fn verify_message_next(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::VerifyMessageNextRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyMessageNextResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let operation_lock = match ctx_mgr
        .message_operation_lock(
            &ctx_id,
            VirtualHandle(req.session_handle),
            ServerMessageOperation::Verify,
        )
        .await
    {
        Ok(lock) => lock,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageNextResponse {
                ck_rv: error.0,
                parameter_result: None,
            }));
        }
    };
    let operation = operation_lock.lock_owned().await;

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageNextResponse {
                ck_rv: rv.0,
                parameter_result: None,
            }));
        }
    };

    let parameter = req.parameter;
    let data_part = req.data_part;
    let data_part_null_len = req.data_part_null_len;
    let is_final = req.is_final;
    let signature = req.signature;
    let signature_null_len = req.signature_null_len;
    // ADR-0010 sanitize_inputs: validate NULL data_part/signature pointers before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, data_part_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageNextResponse { ck_rv: rv.0 }));
    }
    if let Err(rv) = check_sanitize(sanitize_inputs, signature_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageNextResponse { ck_rv: rv.0 }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.verify_message_next(
            session,
            &parameter,
            input_from_wire(&data_part, data_part_null_len),
            is_final,
            input_from_wire(&signature, signature_null_len),
        )
    })
    .await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageNextResponse {
        ck_rv: ck_rv_only(result),
    }))
}
