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

use pkcs11_proxy_ng_proto::convert::message_params::{
    MessageParameter, MessageParameterShape, validate_structured_wire_parameter,
};
// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain;
use pkcs11_proxy_ng_proto::version::{
    exact_effects_version_rejected, exact_output_effects_version_supported,
};
use pkcs11_proxy_ng_types::*;

use super::super::context_manager::{
    ClientContextId, MessageOperation as ServerMessageOperation, MessageOperationTransition,
};
use super::super::handle_map::VirtualHandle;
use super::authorization::mechanism_permitted;
use super::mechanism_handles::remap_mechanism_handles;
use super::service_utils::{
    check_sanitize, ck_rv_only, input_from_wire, parse_mechanism, resolve_session,
    resolve_session_and_key, spawn_backend, spawn_backend_with_optional_timeout,
};

// ---------------------------------------------------------------------------
// Message Encrypt Init (optional mechanism — None means cancel)
// ---------------------------------------------------------------------------

use crate::server::grpc_service::HandlerContext;

async fn execute_empty_legacy_message_output<F>(
    mut transition: MessageOperationTransition,
    installed_shape: MessageParameterShape,
    operation: F,
) -> Result<CkResult<SecretBytes>, Status>
where
    F: FnOnce() -> CkResult<(SecretBytes, SecretBytes)> + Send + 'static,
{
    spawn_backend(move || {
        transition.mark_started();
        match operation() {
            Ok((parameter_out, output)) if parameter_out.is_empty() => {
                let outcome = Ok(());
                transition.settle(&outcome, Some(installed_shape));
                Ok(output)
            }
            Ok(_) => {
                transition.settle_ambiguous();
                Err(CkRv::DEVICE_ERROR)
            }
            Err(error) => {
                let outcome: CkResult<()> = Err(error);
                transition.settle(&outcome, Some(installed_shape));
                Err(error)
            }
        }
    })
    .await
}

struct MessageInitContract {
    shape: MessageParameterShape,
    caller_spec: CkParameterRoundtripSpec,
    provider_spec: CkParameterRoundtripSpec,
}

fn decode_structured_message_parameter(
    wire: Option<&pkcs11_proxy_ng_proto::MessageParameter>,
) -> CkResult<Option<MessageParameter>> {
    wire.map(|parameter| {
        validate_structured_wire_parameter(parameter)?;
        MessageParameter::try_from(parameter)
    })
    .transpose()
}

fn message_parameter_has_null_positive(parameter: &MessageParameter) -> bool {
    match parameter {
        MessageParameter::Raw(_) => true,
        MessageParameter::GcmMessage(params) => {
            params.iv_null_len.is_some_and(|len| len > 0)
                || (params.tag_null_len.is_some() && params.tag_bits > 0)
        }
        MessageParameter::CcmMessage(params) => {
            params.nonce_null_len.is_some_and(|len| len > 0)
                || (params.mac_null_len.is_some() && params.mac_len > 0)
        }
        MessageParameter::SalaChacha(params) => {
            params.nonce_null_len.is_some() && params.nonce_bits > 0
                || params.tag_null_len.is_some()
        }
    }
}

fn native_message_parameter_len(parameter: &MessageParameter) -> u64 {
    match parameter {
        MessageParameter::GcmMessage(_) => {
            std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>() as u64
        }
        MessageParameter::CcmMessage(_) => {
            std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>() as u64
        }
        MessageParameter::SalaChacha(_) => {
            std::mem::size_of::<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>() as u64
        }
        MessageParameter::Raw(_) => 0,
    }
}

fn validate_message_init_contract(
    ctx: &HandlerContext,
    mechanism_type: CkMechanismType,
    mechanism_had_params: bool,
    wire_shape: Option<i32>,
    wire_spec: Option<&pkcs11_proxy_ng_proto::ParameterRoundtripSpec>,
    init_param: Option<&MessageParameter>,
) -> CkResult<Option<MessageInitContract>> {
    if mechanism_had_params {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    let uses_contract = wire_shape.is_some() || wire_spec.is_some() || init_param.is_some();
    if !uses_contract {
        return Ok(None);
    }
    let requested_shape = MessageParameterShape::try_from_proto_i32(
        wire_shape.ok_or(CkRv::MECHANISM_PARAM_INVALID)?,
    )?;
    // W1-C3-26: a poisoned registry lock fails closed with
    // DEVICE_ERROR (internal daemon fault), never a panic.
    let registry =
        ctx.mechanism_registry_source.current_registry().map_err(|_| CkRv::DEVICE_ERROR)?;
    let derived_shape =
        MessageParameterShape::from_registry_name(registry.param_shape(mechanism_type.0));
    if requested_shape != derived_shape {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    let wire_spec = wire_spec.ok_or(CkRv::MECHANISM_PARAM_INVALID)?;
    if wire_spec.value.is_some() {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    let caller_spec = CkParameterRoundtripSpec {
        buffer_present: wire_spec.buffer_present,
        buffer_len: wire_spec.buffer_len,
        value: None,
    };
    let provider_spec = if let Some(parameter) = init_param {
        parameter.validate_structured_shape(derived_shape)?;
        if !caller_spec.buffer_present || caller_spec.buffer_len == 0 {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        if ctx.sanitize_inputs && message_parameter_has_null_positive(parameter) {
            return Err(CkRv::ARGUMENTS_BAD);
        }
        CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: native_message_parameter_len(parameter),
            value: None,
        }
    } else {
        if caller_spec.buffer_present && caller_spec.buffer_len > 0 {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        if ctx.sanitize_inputs && !caller_spec.buffer_present && caller_spec.buffer_len > 0 {
            return Err(CkRv::ARGUMENTS_BAD);
        }
        caller_spec.clone()
    };
    Ok(Some(MessageInitContract { shape: derived_shape, caller_spec, provider_spec }))
}

fn parameter_result_matches_spec(
    result: &CkParameterRoundtripResult,
    spec: &CkParameterRoundtripSpec,
) -> bool {
    result.ck_rv == CkRv::OK
        && result.returned_len == spec.buffer_len
        && result.value == spec.buffer_present.then(Vec::new).map(SecretBytes::new)
}

fn parameter_ack(
    spec: &CkParameterRoundtripSpec,
) -> pkcs11_proxy_ng_proto::ParameterRoundtripResult {
    (&CkParameterRoundtripResult {
        ck_rv: CkRv::OK,
        returned_len: spec.buffer_len,
        value: spec.buffer_present.then(Vec::new).map(SecretBytes::new),
    })
        .into()
}

fn validate_empty_message_parameter_contract(
    legacy_parameter: &[u8],
    wire_spec: Option<&pkcs11_proxy_ng_proto::ParameterRoundtripSpec>,
) -> CkResult<Option<CkParameterRoundtripSpec>> {
    if !legacy_parameter.is_empty() {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    let Some(wire_spec) = wire_spec else {
        return Ok(None);
    };
    let spec = CkParameterRoundtripSpec {
        buffer_present: wire_spec.buffer_present,
        buffer_len: wire_spec.buffer_len,
        value: wire_spec.value.clone().map(SecretBytes::new),
    };
    if spec.buffer_len > 0 || spec.value.is_some() {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    Ok(Some(spec))
}

struct MessageBeginContract {
    caller_spec: CkParameterRoundtripSpec,
    provider_spec: CkParameterRoundtripSpec,
    parameter: Option<MessageParameter>,
}

#[derive(Default)]
struct MessageBeginWireResult {
    ck_rv: u64,
    parameter_out: Vec<u8>,
    parameter_result: Option<pkcs11_proxy_ng_proto::ParameterRoundtripResult>,
    message_parameter_out: Option<pkcs11_proxy_ng_proto::MessageParameter>,
    message_effects: Option<pkcs11_proxy_ng_proto::pkcs11_proxy_ng::v1::MessageParameterEffects>,
}

fn message_begin_error(error: CkRv) -> MessageBeginWireResult {
    MessageBeginWireResult { ck_rv: error.0, ..Default::default() }
}

fn validate_message_begin_contract(
    sanitize_inputs: bool,
    installed_shape: MessageParameterShape,
    legacy_parameter: &[u8],
    wire_spec: Option<&pkcs11_proxy_ng_proto::ParameterRoundtripSpec>,
    wire_parameter: Option<&pkcs11_proxy_ng_proto::MessageParameter>,
) -> CkResult<Option<MessageBeginContract>> {
    if !legacy_parameter.is_empty() {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    if wire_spec.is_none() && wire_parameter.is_none() {
        return Ok(None);
    }
    let wire_spec = wire_spec.ok_or(CkRv::MECHANISM_PARAM_INVALID)?;
    if wire_spec.value.is_some() {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    let caller_spec = CkParameterRoundtripSpec {
        buffer_present: wire_spec.buffer_present,
        buffer_len: wire_spec.buffer_len,
        value: None,
    };
    let parameter = decode_structured_message_parameter(wire_parameter)?;
    let provider_spec = if let Some(parameter) = parameter.as_ref() {
        parameter.validate_structured_shape(installed_shape)?;
        if !caller_spec.buffer_present || caller_spec.buffer_len == 0 {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        if sanitize_inputs && message_parameter_has_null_positive(parameter) {
            return Err(CkRv::ARGUMENTS_BAD);
        }
        CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: native_message_parameter_len(parameter),
            value: None,
        }
    } else {
        if caller_spec.buffer_present && caller_spec.buffer_len > 0 {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        if sanitize_inputs && !caller_spec.buffer_present && caller_spec.buffer_len > 0 {
            return Err(CkRv::ARGUMENTS_BAD);
        }
        caller_spec.clone()
    };
    Ok(Some(MessageBeginContract { caller_spec, provider_spec, parameter }))
}

#[allow(clippy::too_many_arguments)]
async fn execute_message_begin(
    ctx: &HandlerContext,
    ctx_id: ClientContextId,
    virtual_session: u64,
    operation_kind: ServerMessageOperation,
    legacy_parameter: SecretBytes,
    aad: SecretBytes,
    aad_null_len: Option<u64>,
    wire_spec: Option<pkcs11_proxy_ng_proto::ParameterRoundtripSpec>,
    wire_parameter: Option<pkcs11_proxy_ng_proto::MessageParameter>,
) -> Result<MessageBeginWireResult, Status> {
    let operation_lock = match ctx
        .context_manager
        .message_operation_lock(&ctx_id, VirtualHandle(virtual_session), operation_kind)
        .await
    {
        Ok(lock) => lock,
        Err(error) => return Ok(message_begin_error(error)),
    };
    let operation = operation_lock.lock_owned().await;
    let session = match resolve_session(&ctx.context_manager, &ctx_id, virtual_session).await {
        Ok(session) => session,
        Err(error) => return Ok(message_begin_error(error)),
    };
    if let Err(error) = check_sanitize(ctx.sanitize_inputs, aad_null_len) {
        return Ok(message_begin_error(error));
    }
    let installed_shape = match operation.shape {
        Some(shape) => shape,
        None => return Ok(message_begin_error(CkRv::OPERATION_NOT_INITIALIZED)),
    };
    let contract = match legacy_parameter.expose(|legacy_raw| {
        validate_message_begin_contract(
            ctx.sanitize_inputs,
            installed_shape,
            legacy_raw,
            wire_spec.as_ref(),
            wire_parameter.as_ref(),
        )
    }) {
        Ok(contract) => contract,
        Err(error) => return Ok(message_begin_error(error)),
    };

    let acknowledge_contract = contract.is_some();
    let contract = contract.unwrap_or_else(|| {
        // The validated empty legacy Vec previously supplied a non-NULL,
        // zero-length parameter. Preserve that pointer class without losing
        // native completion origin through the legacy CkResult adapter.
        let spec = CkParameterRoundtripSpec { buffer_present: true, buffer_len: 0, value: None };
        MessageBeginContract { caller_spec: spec.clone(), provider_spec: spec, parameter: None }
    });
    let backend = Arc::clone(&ctx.backend);
    let mut transition = MessageOperationTransition::begin(operation);
    let result = super::service_utils::spawn_backend_exact(move || {
        aad.expose(|aad_raw| {
            transition.mark_started();
            let request_parameter = contract.parameter.clone();
            let provider_result = match (operation_kind, contract.parameter.as_ref()) {
                (ServerMessageOperation::Encrypt, Some(parameter)) => backend
                    .encrypt_message_begin_msg(
                        session,
                        parameter,
                        input_from_wire(aad_raw, aad_null_len),
                        &contract.provider_spec,
                    )
                    .map(|(ack, parameter)| (ack, Some(parameter))),
                (ServerMessageOperation::Decrypt, Some(parameter)) => backend
                    .decrypt_message_begin_msg(
                        session,
                        parameter,
                        input_from_wire(aad_raw, aad_null_len),
                        &contract.provider_spec,
                    )
                    .map(|(ack, parameter)| (ack, Some(parameter))),
                (ServerMessageOperation::Encrypt, None) => backend
                    .encrypt_message_begin_exact(
                        session,
                        input_from_wire(aad_raw, aad_null_len),
                        &contract.provider_spec,
                    )
                    .map(|ack| (ack, None)),
                (ServerMessageOperation::Decrypt, None) => backend
                    .decrypt_message_begin_exact(
                        session,
                        input_from_wire(aad_raw, aad_null_len),
                        &contract.provider_spec,
                    )
                    .map(|ack| (ack, None)),
                _ => Err(CkRv::FUNCTION_NOT_SUPPORTED),
            };
            super::service_utils::ExactCompletion::capture(provider_result).map_result(|provider_result| match provider_result {
                Ok((provider_ack, returned_parameter)) => {
                    let native_rv = provider_ack.ck_rv;
                    let valid_parameter =
                        match (request_parameter.as_ref(), returned_parameter.as_ref()) {
                            (Some(request), Some(returned)) => {
                                returned.validate_for(request, pkcs11_proxy_ng_proto::convert::message_effects::MessageEffectContext { mode: ParameterEffectCallMode::Begin,
                                    encrypt: operation_kind == ServerMessageOperation::Encrypt,
                                    generated_stage: true, auth_stage: false, rv: native_rv,
                                }).is_ok()
                            }
                            (None, None) => true,
                            _ => false,
                        };
                    if provider_ack.returned_len != contract.provider_spec.buffer_len
                        || provider_ack.value != contract.provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new)
                        || !valid_parameter
                    {
                        tracing::warn!(provider_rv = native_rv.0, "native Begin output contract violation; suppressing all effects");
                        transition.settle_ambiguous();
                        return Ok(message_begin_error(CkRv::DEVICE_ERROR));
                    }
                    let outcome = if native_rv == CkRv::OK { Ok(()) } else { Err(native_rv) };
                    transition.settle(&outcome, Some(installed_shape));
                    Ok(MessageBeginWireResult {
                        ck_rv: native_rv.0,
                        parameter_out: Vec::new(),
                        parameter_result: acknowledge_contract.then(|| (&CkParameterRoundtripResult { ck_rv: native_rv, returned_len: contract.caller_spec.buffer_len, value: contract.caller_spec.buffer_present.then(Vec::new).map(SecretBytes::new) }).into()),
                        message_parameter_out: None,
                        message_effects: returned_parameter.as_ref().map(TryInto::try_into).transpose()?,
                    })
                }
                Err(error) => {
                    let outcome: CkResult<()> = Err(error);
                    transition.settle(&outcome, Some(installed_shape));
                    Ok(message_begin_error(error))
                }
            })
        })
        }).await?;
    Ok(match result {
        Ok(result) => result,
        Err(error) => message_begin_error(error),
    })
}
pub(crate) async fn message_encrypt_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::MessageEncryptInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageEncryptInitResponse>, Status> {
    message_encrypt_init_with_timeout(ctx, request, None).await
}

async fn message_encrypt_init_with_timeout(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::MessageEncryptInitRequest>,
    timeout_override: Option<Duration>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageEncryptInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if let Some(mechanism_proto) = req.mechanism.as_ref() {
        let mechanism_type = CkMechanismType(mechanism_proto.mechanism_type);
        let mechanism_had_params = mechanism_proto.params.is_some();
        let wire_shape = req.parameter_shape;
        let wire_spec = req.parameter_out_spec.clone();
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

        // Validate the attacker-controlled message-parameter contract before
        // resolving the key. Per-object/per-class key policy may read provider
        // metadata, so malformed wire requests must stop on this side of that
        // trust boundary.
        let init_param =
            match decode_structured_message_parameter(req.init_message_parameter.as_ref()) {
                Ok(p) => p,
                Err(rv) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
                        ck_rv: rv.0,
                        ..Default::default()
                    }));
                }
            };

        let contract = match validate_message_init_contract(
            ctx,
            mechanism_type,
            mechanism_had_params,
            wire_shape,
            wire_spec.as_ref(),
            init_param.as_ref(),
        ) {
            Ok(contract) => contract,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
                    ck_rv: rv.0,
                    ..Default::default()
                }));
            }
        };

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

        // Mechanism policy gate (G3-PR3 Task 3).
        // W1-C1-13: the gate runs before remap on every init handler so identical
        // dual-defect requests yield the same RV regardless of op.
        if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
                ck_rv: pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID.0,
                ..Default::default()
            }));
        }

        // B1: remap object handles embedded in the mechanism parameters;
        // gate each through per-object authz when active (C1).
        if let Err(rv) =
            remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism)
                .await
        {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
                ck_rv: rv.0,
                ..Default::default()
            }));
        }

        let backend = Arc::clone(backend_ref);
        let init_param_for_response = init_param.clone();
        // W1-C3-26: a poisoned registry lock fails closed with
        // DEVICE_ERROR (internal daemon fault), never a panic. The lock
        // is still only acquired when no contract supplied the shape.
        let installed_shape = match contract.as_ref() {
            Some(contract) => contract.shape,
            None => {
                let registry = match ctx.mechanism_registry_source.current_registry() {
                    Ok(registry) => registry,
                    Err(_) => {
                        return Ok(Response::new(
                            pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
                                ck_rv: CkRv::DEVICE_ERROR.0,
                                ..Default::default()
                            },
                        ));
                    }
                };
                MessageParameterShape::from_registry_name(
                    registry.param_shape(mechanism.mechanism_type.0),
                )
            }
        };
        let mut transition = MessageOperationTransition::begin(operation);
        let result = if let Some(ref contract) = contract {
            let provider_spec = contract.provider_spec.clone();
            spawn_backend_with_optional_timeout(timeout_override, move || {
                transition.mark_started();
                let provider_result = backend.message_encrypt_init_contract(
                    session,
                    &mechanism,
                    init_param.as_ref(),
                    key,
                    &provider_spec,
                );
                match provider_result {
                    Ok(result) if parameter_result_matches_spec(&result, &provider_spec) => {
                        let outcome = Ok(());
                        transition.settle(&outcome, Some(installed_shape));
                        outcome
                    }
                    Ok(_) => {
                        transition.settle_ambiguous();
                        Err(CkRv::DEVICE_ERROR)
                    }
                    Err(error) => {
                        let outcome = Err(error);
                        transition.settle(&outcome, Some(installed_shape));
                        outcome
                    }
                }
            })
            .await?
        } else {
            spawn_backend_with_optional_timeout(timeout_override, move || {
                transition.mark_started();
                let result = backend.message_encrypt_init(
                    session,
                    Some(&mechanism),
                    init_param.as_ref(),
                    key,
                );
                transition.settle(&result, Some(installed_shape));
                result
            })
            .await?
        };

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
        let mut transition = MessageOperationTransition::begin(operation);
        let result = spawn_backend_with_optional_timeout(timeout_override, move || {
            transition.mark_started();
            let result = backend.message_encrypt_init(session, None, None, CkObjectHandle(0));
            transition.settle(&result, None);
            result
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
    message_encrypt_final_with_timeout(ctx, request, None).await
}

async fn message_encrypt_final_with_timeout(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::MessageEncryptFinalRequest>,
    timeout_override: Option<Duration>,
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
    message_decrypt_init_with_timeout(ctx, request, None).await
}

async fn message_decrypt_init_with_timeout(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::MessageDecryptInitRequest>,
    timeout_override: Option<Duration>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageDecryptInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if let Some(mechanism_proto) = req.mechanism.as_ref() {
        let mechanism_type = CkMechanismType(mechanism_proto.mechanism_type);
        let mechanism_had_params = mechanism_proto.params.is_some();
        let wire_shape = req.parameter_shape;
        let wire_spec = req.parameter_out_spec.clone();
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

        // Keep malformed message-parameter contracts entirely pre-provider,
        // including when object policy would otherwise fetch key metadata.
        let init_param =
            match decode_structured_message_parameter(req.init_message_parameter.as_ref()) {
                Ok(p) => p,
                Err(rv) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
                        ck_rv: rv.0,
                        ..Default::default()
                    }));
                }
            };

        let contract = match validate_message_init_contract(
            ctx,
            mechanism_type,
            mechanism_had_params,
            wire_shape,
            wire_spec.as_ref(),
            init_param.as_ref(),
        ) {
            Ok(contract) => contract,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
                    ck_rv: rv.0,
                    ..Default::default()
                }));
            }
        };

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

        // Mechanism policy gate (G3-PR3 Task 3).
        // W1-C1-13: the gate runs before remap on every init handler so identical
        // dual-defect requests yield the same RV regardless of op.
        if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
                ck_rv: pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID.0,
                ..Default::default()
            }));
        }

        // B1: remap object handles embedded in the mechanism parameters;
        // gate each through per-object authz when active (C1).
        if let Err(rv) =
            remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism)
                .await
        {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
                ck_rv: rv.0,
                ..Default::default()
            }));
        }

        let backend = Arc::clone(backend_ref);
        let init_param_for_response = init_param.clone();
        // W1-C3-26: a poisoned registry lock fails closed with
        // DEVICE_ERROR (internal daemon fault), never a panic. The lock
        // is still only acquired when no contract supplied the shape.
        let installed_shape = match contract.as_ref() {
            Some(contract) => contract.shape,
            None => {
                let registry = match ctx.mechanism_registry_source.current_registry() {
                    Ok(registry) => registry,
                    Err(_) => {
                        return Ok(Response::new(
                            pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
                                ck_rv: CkRv::DEVICE_ERROR.0,
                                ..Default::default()
                            },
                        ));
                    }
                };
                MessageParameterShape::from_registry_name(
                    registry.param_shape(mechanism.mechanism_type.0),
                )
            }
        };
        let mut transition = MessageOperationTransition::begin(operation);
        let result = if let Some(ref contract) = contract {
            let provider_spec = contract.provider_spec.clone();
            spawn_backend_with_optional_timeout(timeout_override, move || {
                transition.mark_started();
                let provider_result = backend.message_decrypt_init_contract(
                    session,
                    &mechanism,
                    init_param.as_ref(),
                    key,
                    &provider_spec,
                );
                match provider_result {
                    Ok(result) if parameter_result_matches_spec(&result, &provider_spec) => {
                        let outcome = Ok(());
                        transition.settle(&outcome, Some(installed_shape));
                        outcome
                    }
                    Ok(_) => {
                        transition.settle_ambiguous();
                        Err(CkRv::DEVICE_ERROR)
                    }
                    Err(error) => {
                        let outcome = Err(error);
                        transition.settle(&outcome, Some(installed_shape));
                        outcome
                    }
                }
            })
            .await?
        } else {
            spawn_backend_with_optional_timeout(timeout_override, move || {
                transition.mark_started();
                let result = backend.message_decrypt_init(
                    session,
                    Some(&mechanism),
                    init_param.as_ref(),
                    key,
                );
                transition.settle(&result, Some(installed_shape));
                result
            })
            .await?
        };

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
        let mut transition = MessageOperationTransition::begin(operation);
        let result = spawn_backend_with_optional_timeout(timeout_override, move || {
            transition.mark_started();
            let result = backend.message_decrypt_init(session, None, None, CkObjectHandle(0));
            transition.settle(&result, None);
            result
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
    message_decrypt_final_with_timeout(ctx, request, None).await
}

async fn message_decrypt_final_with_timeout(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::MessageDecryptFinalRequest>,
    timeout_override: Option<Duration>,
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
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignInitResponse {
                ck_rv: error.0,
            }));
        }
    };
    let operation = operation_lock.lock_owned().await;

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

        // Mechanism policy gate (G3-PR3 Task 3).
        // W1-C1-13: the gate runs before remap on every init handler so identical
        // dual-defect requests yield the same RV regardless of op.
        if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignInitResponse {
                ck_rv: pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID.0,
            }));
        }

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
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyInitResponse {
                ck_rv: error.0,
            }));
        }
    };
    let operation = operation_lock.lock_owned().await;

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

        // Mechanism policy gate (G3-PR3 Task 3).
        // W1-C1-13: the gate runs before remap on every init handler so identical
        // dual-defect requests yield the same RV regardless of op.
        if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyInitResponse {
                ck_rv: pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID.0,
            }));
        }

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

    let aad = SecretBytes::new(req.associated_data);
    let aad_null_len = req.associated_data_null_len;
    let plaintext = SecretBytes::new(req.plaintext);
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
    let result = execute_empty_legacy_message_output(
        MessageOperationTransition::begin(operation),
        installed_shape,
        move || {
            aad.expose(|aad_raw| {
                plaintext.expose(|pt_raw| {
                    let mut parameter = [];
                    backend.encrypt_message(
                        session,
                        &mut parameter,
                        input_from_wire(aad_raw, aad_null_len),
                        input_from_wire(pt_raw, plaintext_null_len),
                    )
                })
            })
        },
    )
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
    let req = request.into_inner();
    // W1-L5-04: compatibility-range gate, never an equality literal.
    if req.parameter_out_spec.is_some()
        && !exact_output_effects_version_supported(req.exact_output_effects_version)
    {
        return Err(exact_effects_version_rejected(req.exact_output_effects_version));
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

    let plaintext_part = SecretBytes::new(req.plaintext_part);
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
    let result = execute_empty_legacy_message_output(
        MessageOperationTransition::begin(operation),
        installed_shape,
        move || {
            plaintext_part.expose(|pp_raw| {
                let mut parameter = [];
                backend.encrypt_message_next(
                    session,
                    &mut parameter,
                    input_from_wire(pp_raw, plaintext_part_null_len),
                    flags,
                )
            })
        },
    )
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

    let aad = SecretBytes::new(req.associated_data);
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
    let result = execute_empty_legacy_message_output(
        MessageOperationTransition::begin(operation),
        installed_shape,
        move || {
            aad.expose(|aad_raw| {
                let mut parameter = [];
                backend.decrypt_message(
                    session,
                    &mut parameter,
                    input_from_wire(aad_raw, aad_null_len),
                    input_from_wire(&ciphertext, ciphertext_null_len),
                )
            })
        },
    )
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
    let req = request.into_inner();
    // W1-L5-04: compatibility-range gate, never an equality literal.
    if req.parameter_out_spec.is_some()
        && !exact_output_effects_version_supported(req.exact_output_effects_version)
    {
        return Err(exact_effects_version_rejected(req.exact_output_effects_version));
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
    let result = execute_empty_legacy_message_output(
        MessageOperationTransition::begin(operation),
        installed_shape,
        move || {
            let mut parameter = [];
            backend.decrypt_message_next(
                session,
                &mut parameter,
                input_from_wire(&ciphertext_part, ciphertext_part_null_len),
                flags,
            )
        },
    )
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

    let data = SecretBytes::new(req.data);
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
    let result = execute_empty_legacy_message_output(
        MessageOperationTransition::begin(operation),
        installed_shape,
        move || {
            data.expose(|d_raw| {
                let mut parameter = [];
                backend.sign_message(session, &mut parameter, input_from_wire(d_raw, data_null_len))
            })
        },
    )
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

    if operation.shape.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageNextResponse {
            ck_rv: CkRv::OPERATION_NOT_INITIALIZED.0,
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

    if operation.shape.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageResponse {
            ck_rv: CkRv::OPERATION_NOT_INITIALIZED.0,
            parameter_result: None,
        }));
    }
    let contract = match validate_empty_message_parameter_contract(
        &req.parameter,
        req.parameter_out_spec.as_ref(),
    ) {
        Ok(contract) => contract,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageResponse {
                ck_rv: error.0,
                parameter_result: None,
            }));
        }
    };
    let data = SecretBytes::new(req.data);
    let data_null_len = req.data_null_len;
    let signature = req.signature;
    let signature_null_len = req.signature_null_len;
    // ADR-0010 sanitize_inputs: validate NULL data/signature pointers before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, data_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageResponse {
            ck_rv: rv.0,
            parameter_result: None,
        }));
    }
    if let Err(rv) = check_sanitize(sanitize_inputs, signature_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageResponse {
            ck_rv: rv.0,
            parameter_result: None,
        }));
    }
    let backend = Arc::clone(backend_ref);
    let mut transition = MessageOperationTransition::begin(operation);
    if let Some(spec) = contract {
        let response_spec = spec.clone();
        let result = spawn_backend(move || {
            data.expose(|d_raw| {
                transition.mark_started();
                match backend.verify_message_exact(
                    session,
                    input_from_wire(d_raw, data_null_len),
                    input_from_wire(&signature, signature_null_len),
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
        Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageResponse { ck_rv, parameter_result }))
    } else {
        let result = spawn_backend(move || {
            data.expose(|d_raw| {
                transition.mark_started();
                let result = backend.verify_message(
                    session,
                    &[],
                    input_from_wire(d_raw, data_null_len),
                    input_from_wire(&signature, signature_null_len),
                );
                transition.settle(&result, Some(MessageParameterShape::Unmodeled));
                result
            })
        })
        .await?;
        Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageResponse {
            ck_rv: ck_rv_only(result),
            parameter_result: None,
        }))
    }
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

    if operation.shape.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageNextResponse {
            ck_rv: CkRv::OPERATION_NOT_INITIALIZED.0,
            parameter_result: None,
        }));
    }
    let contract = match validate_empty_message_parameter_contract(
        &req.parameter,
        req.parameter_out_spec.as_ref(),
    ) {
        Ok(contract) => contract,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageNextResponse {
                ck_rv: error.0,
                parameter_result: None,
            }));
        }
    };
    let data_part = SecretBytes::new(req.data_part);
    let data_part_null_len = req.data_part_null_len;
    let is_final = req.is_final;
    let signature = req.signature;
    let signature_null_len = req.signature_null_len;
    // ADR-0010 sanitize_inputs: validate NULL data_part/signature pointers before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, data_part_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageNextResponse {
            ck_rv: rv.0,
            parameter_result: None,
        }));
    }
    if let Err(rv) = check_sanitize(sanitize_inputs, signature_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageNextResponse {
            ck_rv: rv.0,
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
                match backend.verify_message_next_exact(
                    session,
                    input_from_wire(dp_raw, data_part_null_len),
                    is_final,
                    input_from_wire(&signature, signature_null_len),
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
        Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageNextResponse {
            ck_rv,
            parameter_result,
        }))
    } else {
        let result = spawn_backend(move || {
            data_part.expose(|dp_raw| {
                transition.mark_started();
                let result = backend.verify_message_next(
                    session,
                    &[],
                    input_from_wire(dp_raw, data_part_null_len),
                    is_final,
                    input_from_wire(&signature, signature_null_len),
                );
                transition.settle(&result, Some(MessageParameterShape::Unmodeled));
                result
            })
        })
        .await?;
        Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageNextResponse {
            ck_rv: ck_rv_only(result),
            parameter_result: None,
        }))
    }
}

#[cfg(test)]
mod empty_sign_verify_contract_tests {
    use super::*;

    fn wire_spec(
        buffer_present: bool,
        buffer_len: u64,
        value: Option<Vec<u8>>,
    ) -> pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
        pkcs11_proxy_ng_proto::ParameterRoundtripSpec { buffer_present, buffer_len, value }
    }

    #[test]
    fn empty_contract_preserves_zero_length_pointer_class() {
        for buffer_present in [false, true] {
            let spec = wire_spec(buffer_present, 0, None);
            let decoded =
                validate_empty_message_parameter_contract(&[], Some(&spec)).unwrap().unwrap();
            assert_eq!(decoded.buffer_present, buffer_present);
            assert_eq!(decoded.buffer_len, 0);
            assert_eq!(decoded.value, None);
        }
    }

    #[test]
    fn empty_contract_rejects_positive_raw_or_materialized_values() {
        assert_eq!(
            validate_empty_message_parameter_contract(&[], Some(&wire_spec(false, 1, None))),
            Err(CkRv::MECHANISM_PARAM_INVALID)
        );
        assert_eq!(
            validate_empty_message_parameter_contract(&[0xA5], None),
            Err(CkRv::MECHANISM_PARAM_INVALID)
        );
        assert_eq!(
            validate_empty_message_parameter_contract(
                &[],
                Some(&wire_spec(true, 0, Some(Vec::new())))
            ),
            Err(CkRv::MECHANISM_PARAM_INVALID)
        );
    }
}

#[cfg(test)]
mod lifecycle_transition_tests {
    use super::*;
    use crate::config::{
        AuthConfig, ExtractPolicyConfig, GrantSpec, ObjectAclSpec, PolicyEntry, RichGrantConfig,
        TokenAccessSpec,
    };
    use crate::server::auth::policy::TokenPolicy;
    use crate::server::context_manager::ContextManager;
    use crate::server::grpc_service::service_utils::register_session_handle;
    use crate::server::handle_map::BackendHandle;
    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend, mock::MockMessageLifecycleAction};

    #[derive(Clone, Copy, Debug)]
    enum Direction {
        Encrypt,
        Decrypt,
    }

    #[derive(Clone, Copy, Debug)]
    enum Endpoint {
        Cancel,
        Final,
    }

    async fn setup(
        direction: Direction,
    ) -> (HandlerContext, Arc<MockBackend>, ClientContextId, u64) {
        setup_with_lease(direction, Duration::from_secs(300)).await
    }

    async fn setup_with_lease(
        direction: Direction,
        lease_duration: Duration,
    ) -> (HandlerContext, Arc<MockBackend>, ClientContextId, u64) {
        let mock = Arc::new(MockBackend::default_test());
        mock.initialize().unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let manager = Arc::new(ContextManager::new(lease_duration, 0));
        manager.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let context_id = manager.create_context(None).await.unwrap();
        let raw_session =
            mock.open_session(CkSlotId(0), CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).unwrap();
        let virtual_session = register_session_handle(
            &manager,
            &context_id,
            raw_session,
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
        )
        .await
        .unwrap();
        let operation = manager
            .message_operation_lock(
                &context_id,
                VirtualHandle(virtual_session),
                match direction {
                    Direction::Encrypt => ServerMessageOperation::Encrypt,
                    Direction::Decrypt => ServerMessageOperation::Decrypt,
                },
            )
            .await
            .unwrap();
        operation.lock().await.shape = Some(MessageParameterShape::Gcm);
        (HandlerContext::for_test(&manager, &backend), mock, context_id, virtual_session)
    }

    async fn setup_raw_handler(
        operation: ServerMessageOperation,
    ) -> (HandlerContext, Arc<MockBackend>, ClientContextId, u64) {
        let mock = Arc::new(MockBackend::default_test());
        mock.initialize().unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        manager.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let context_id = manager.create_context(None).await.unwrap();
        let raw_session =
            mock.open_session(CkSlotId(0), CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).unwrap();
        let virtual_session = register_session_handle(
            &manager,
            &context_id,
            raw_session,
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
        )
        .await
        .unwrap();
        manager
            .message_operation_lock(&context_id, VirtualHandle(virtual_session), operation)
            .await
            .unwrap()
            .lock()
            .await
            .shape = Some(MessageParameterShape::Unmodeled);
        (HandlerContext::for_test(&manager, &backend), mock, context_id, virtual_session)
    }

    async fn setup_init_contract_ordering()
    -> (HandlerContext, Arc<MockBackend>, ClientContextId, u64, u64) {
        const IDENTITY: &str = "uid=1000";
        let mock = Arc::new(MockBackend::default_test());
        mock.initialize().unwrap();
        let backend_session =
            mock.open_session(CkSlotId(0), CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        manager.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let context_id = manager.create_context(Some(IDENTITY.into())).await.unwrap();
        let (virtual_session, virtual_key) = manager
            .get_context(&context_id, |context| {
                let session = context.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                );
                let key = context.object_handles.insert(BackendHandle(42));
                (session, key)
            })
            .await
            .unwrap();

        let policy = TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: false,
            anonymous_principal: None,
            policy: vec![PolicyEntry {
                identity: IDENTITY.into(),
                tokens: TokenAccessSpec::Specific(vec![GrantSpec::Rich(RichGrantConfig {
                    token: "label:MockToken".into(),
                    classes: None,
                    mechanisms: None,
                    extract: ExtractPolicyConfig::Allow,
                    objects: Some(vec![ObjectAclSpec::Bare("a5".into())]),
                })]),
            }],
        })
        .unwrap();
        assert!(policy.per_object_active());
        let mut ctx = HandlerContext::for_test(&manager, &backend);
        ctx.token_policy = Arc::new(policy);
        (ctx, mock, context_id, virtual_session.0, virtual_key.0)
    }

    fn backend_observation_counts(mock: &MockBackend) -> (usize, usize, usize, usize, usize) {
        (
            mock.token_info_call_count(),
            mock.attr_get_call_count(),
            mock.attr_get_exact_call_count(),
            mock.message_lifecycle_call_count(),
            mock.message_init_contract_call_count(),
        )
    }

    fn type_only_aes_gcm() -> pkcs11_proxy_ng_proto::Mechanism {
        pkcs11_proxy_ng_proto::Mechanism {
            mechanism_type: CkMechanismType::AES_GCM.0,
            params: None,
        }
    }

    fn valid_gcm_wire_parameter() -> pkcs11_proxy_ng_proto::MessageParameter {
        pkcs11_proxy_ng_proto::MessageParameter {
            params: Some(pkcs11_proxy_ng_proto::message_parameter::Params::GcmMessageParams(
                pkcs11_proxy_ng_proto::GcmMessageParams {
                    iv: vec![0x11; 12],
                    iv_fixed_bits: 96,
                    iv_generator: 0,
                    tag: vec![0; 16],
                    tag_bits: 128,
                    iv_null_len: None,
                    tag_null_len: None,
                },
            )),
        }
    }

    fn valid_ccm_wire_parameter() -> pkcs11_proxy_ng_proto::MessageParameter {
        pkcs11_proxy_ng_proto::MessageParameter {
            params: Some(pkcs11_proxy_ng_proto::message_parameter::Params::CcmMessageParams(
                pkcs11_proxy_ng_proto::CcmMessageParams {
                    data_len: 32,
                    nonce: vec![0x22; 12],
                    nonce_fixed_bits: 96,
                    nonce_generator: 0,
                    mac: vec![0; 16],
                    mac_len: 16,
                    nonce_null_len: None,
                    mac_null_len: None,
                },
            )),
        }
    }

    fn valid_salsa_wire_parameter() -> pkcs11_proxy_ng_proto::MessageParameter {
        pkcs11_proxy_ng_proto::MessageParameter {
            params: Some(
                pkcs11_proxy_ng_proto::message_parameter::Params::SalsaChachaMessageParams(
                    pkcs11_proxy_ng_proto::Salsa20ChaCha20Poly1305MessageParams {
                        nonce: vec![0x33; 12],
                        nonce_bits: 96,
                        tag: vec![0; 16],
                        nonce_null_len: None,
                        tag_null_len: None,
                    },
                ),
            ),
        }
    }

    #[tokio::test]
    async fn sign_message_next_null_pul_len_wire_form_remains_a_feed_call() {
        let (ctx, mock, context_id, session) =
            setup_raw_handler(ServerMessageOperation::Sign).await;
        let data_calls_before = mock.data_op_call_count();
        let parameter_calls_before = mock.message_parameter_call_count();

        // `request_signature = false` is the dedicated wire form emitted by
        // C_SignMessageNext when `pulSignatureLen == NULL`. It must not be
        // reclassified as an exact-output request with a missing length pointer.
        let response = sign_message_next(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::SignMessageNextRequest {
                client_context_id: context_id.0.clone(),
                session_handle: session,
                parameter: Vec::new(),
                data_part: b"more".to_vec(),
                request_signature: false,
                data_part_null_len: None,
                parameter_out_spec: Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                    buffer_present: false,
                    buffer_len: 0,
                    value: None,
                }),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(response.ck_rv, CkRv::OK.0);
        assert!(response.signature.is_empty());
        assert_eq!(mock.data_op_call_count(), data_calls_before + 1);
        assert_eq!(mock.message_parameter_call_count(), parameter_calls_before + 1);
        assert_eq!(
            ctx.context_manager
                .message_operation_lock(
                    &context_id,
                    VirtualHandle(session),
                    ServerMessageOperation::Sign,
                )
                .await
                .unwrap()
                .lock()
                .await
                .shape,
            Some(MessageParameterShape::Unmodeled),
        );
    }

    async fn shape(
        ctx: &HandlerContext,
        context_id: &ClientContextId,
        session: u64,
        direction: Direction,
    ) -> Option<MessageParameterShape> {
        ctx.context_manager
            .message_operation_lock(
                context_id,
                VirtualHandle(session),
                match direction {
                    Direction::Encrypt => ServerMessageOperation::Encrypt,
                    Direction::Decrypt => ServerMessageOperation::Decrypt,
                },
            )
            .await
            .unwrap()
            .lock()
            .await
            .shape
    }

    async fn call(
        ctx: &HandlerContext,
        context_id: &ClientContextId,
        session: u64,
        direction: Direction,
        endpoint: Endpoint,
        timeout: Option<Duration>,
    ) -> Result<u64, Status> {
        match (direction, endpoint) {
            (Direction::Encrypt, Endpoint::Cancel) => message_encrypt_init_with_timeout(
                ctx,
                Request::new(pkcs11_proxy_ng_proto::MessageEncryptInitRequest {
                    client_context_id: context_id.0.clone(),
                    session_handle: session,
                    mechanism: None,
                    key_handle: 0,
                    init_message_parameter: None,
                    parameter_out_spec: None,
                    parameter_shape: None,
                }),
                timeout,
            )
            .await
            .map(|response| response.into_inner().ck_rv),
            (Direction::Decrypt, Endpoint::Cancel) => message_decrypt_init_with_timeout(
                ctx,
                Request::new(pkcs11_proxy_ng_proto::MessageDecryptInitRequest {
                    client_context_id: context_id.0.clone(),
                    session_handle: session,
                    mechanism: None,
                    key_handle: 0,
                    init_message_parameter: None,
                    parameter_out_spec: None,
                    parameter_shape: None,
                }),
                timeout,
            )
            .await
            .map(|response| response.into_inner().ck_rv),
            (Direction::Encrypt, Endpoint::Final) => message_encrypt_final_with_timeout(
                ctx,
                Request::new(pkcs11_proxy_ng_proto::MessageEncryptFinalRequest {
                    client_context_id: context_id.0.clone(),
                    session_handle: session,
                }),
                timeout,
            )
            .await
            .map(|response| response.into_inner().ck_rv),
            (Direction::Decrypt, Endpoint::Final) => message_decrypt_final_with_timeout(
                ctx,
                Request::new(pkcs11_proxy_ng_proto::MessageDecryptFinalRequest {
                    client_context_id: context_id.0.clone(),
                    session_handle: session,
                }),
                timeout,
            )
            .await
            .map(|response| response.into_inner().ck_rv),
        }
    }

    #[tokio::test]
    async fn encrypt_decrypt_cancel_and_final_settle_every_endpoint_outcome() {
        for direction in [Direction::Encrypt, Direction::Decrypt] {
            for endpoint in [Endpoint::Cancel, Endpoint::Final] {
                for (action, timeout, expected_call, expected_shape) in [
                    (MockMessageLifecycleAction::Return(CkRv::OK), None, Ok(CkRv::OK.0), None),
                    (
                        MockMessageLifecycleAction::Return(CkRv::FUNCTION_FAILED),
                        None,
                        Ok(CkRv::FUNCTION_FAILED.0),
                        Some(MessageParameterShape::Gcm),
                    ),
                    (
                        MockMessageLifecycleAction::Return(CkRv::DEVICE_ERROR),
                        None,
                        Ok(CkRv::DEVICE_ERROR.0),
                        None,
                    ),
                    (
                        MockMessageLifecycleAction::Delay(Duration::from_millis(60), CkRv::OK),
                        Some(Duration::from_millis(5)),
                        Ok(CkRv::FUNCTION_FAILED.0),
                        None,
                    ),
                    (
                        MockMessageLifecycleAction::Delay(
                            Duration::from_millis(60),
                            CkRv::FUNCTION_FAILED,
                        ),
                        Some(Duration::from_millis(5)),
                        Ok(CkRv::FUNCTION_FAILED.0),
                        Some(MessageParameterShape::Gcm),
                    ),
                    (MockMessageLifecycleAction::Panic, None, Err(()), None),
                ] {
                    let (ctx, mock, context_id, session) = setup(direction).await;
                    let calls_before = mock.message_lifecycle_call_count();
                    mock.set_next_message_lifecycle_action(action);
                    let result =
                        call(&ctx, &context_id, session, direction, endpoint, timeout).await;
                    match expected_call {
                        Ok(rv) => {
                            assert_eq!(result.unwrap(), rv, "{direction:?} {endpoint:?} {action:?}",)
                        }
                        Err(()) => assert!(
                            result.is_err(),
                            "{direction:?} {endpoint:?} panic must be a transport error",
                        ),
                    }
                    assert_eq!(
                        shape(&ctx, &context_id, session, direction).await,
                        expected_shape,
                        "{direction:?} {endpoint:?} {action:?}",
                    );
                    assert_eq!(
                        mock.message_lifecycle_call_count(),
                        calls_before + 1,
                        "{direction:?} {endpoint:?} must call the provider exactly once",
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn structured_init_settles_every_provider_outcome_after_timeout_or_panic() {
        for direction in [Direction::Encrypt, Direction::Decrypt] {
            for (action, timeout, expected_rv, expected_shape) in [
                (
                    MockMessageLifecycleAction::Return(CkRv::FUNCTION_FAILED),
                    None,
                    Some(CkRv::FUNCTION_FAILED),
                    Some(MessageParameterShape::Ccm),
                ),
                (
                    MockMessageLifecycleAction::Return(CkRv::DEVICE_ERROR),
                    None,
                    Some(CkRv::DEVICE_ERROR),
                    None,
                ),
                (
                    MockMessageLifecycleAction::Delay(Duration::from_millis(60), CkRv::OK),
                    Some(Duration::from_millis(5)),
                    Some(CkRv::FUNCTION_FAILED),
                    Some(MessageParameterShape::Gcm),
                ),
                (
                    MockMessageLifecycleAction::Delay(
                        Duration::from_millis(60),
                        CkRv::FUNCTION_FAILED,
                    ),
                    Some(Duration::from_millis(5)),
                    Some(CkRv::FUNCTION_FAILED),
                    Some(MessageParameterShape::Ccm),
                ),
                (MockMessageLifecycleAction::Panic, None, None, None),
            ] {
                let (ctx, mock, context_id, session) = setup(direction).await;
                let operation = ctx
                    .context_manager
                    .message_operation_lock(
                        &context_id,
                        VirtualHandle(session),
                        match direction {
                            Direction::Encrypt => ServerMessageOperation::Encrypt,
                            Direction::Decrypt => ServerMessageOperation::Decrypt,
                        },
                    )
                    .await
                    .unwrap();
                operation.lock().await.shape = Some(MessageParameterShape::Ccm);
                let calls_before = mock.message_lifecycle_call_count();
                mock.set_next_message_lifecycle_action(action);

                let result = match direction {
                    Direction::Encrypt => message_encrypt_init_with_timeout(
                        &ctx,
                        Request::new(pkcs11_proxy_ng_proto::MessageEncryptInitRequest {
                            client_context_id: context_id.0.clone(),
                            session_handle: session,
                            mechanism: Some(type_only_aes_gcm()),
                            key_handle: 0,
                            init_message_parameter: Some(valid_gcm_wire_parameter()),
                            parameter_out_spec: Some(
                                pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                                    buffer_present: true,
                                    buffer_len: 32,
                                    value: None,
                                },
                            ),
                            parameter_shape: Some(MessageParameterShape::Gcm.to_proto_i32()),
                        }),
                        timeout,
                    )
                    .await
                    .map(|response| response.into_inner().ck_rv),
                    Direction::Decrypt => message_decrypt_init_with_timeout(
                        &ctx,
                        Request::new(pkcs11_proxy_ng_proto::MessageDecryptInitRequest {
                            client_context_id: context_id.0.clone(),
                            session_handle: session,
                            mechanism: Some(type_only_aes_gcm()),
                            key_handle: 0,
                            init_message_parameter: Some(valid_gcm_wire_parameter()),
                            parameter_out_spec: Some(
                                pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                                    buffer_present: true,
                                    buffer_len: 32,
                                    value: None,
                                },
                            ),
                            parameter_shape: Some(MessageParameterShape::Gcm.to_proto_i32()),
                        }),
                        timeout,
                    )
                    .await
                    .map(|response| response.into_inner().ck_rv),
                };
                match expected_rv {
                    Some(expected) => assert_eq!(
                        result.unwrap(),
                        expected.0,
                        "{direction:?} structured Init {action:?}",
                    ),
                    None => assert!(
                        result.is_err(),
                        "{direction:?} structured Init panic must be a transport error",
                    ),
                }
                assert_eq!(
                    tokio::time::timeout(
                        Duration::from_secs(1),
                        shape(&ctx, &context_id, session, direction),
                    )
                    .await
                    .expect("provider transition must settle"),
                    expected_shape,
                    "{direction:?} structured Init {action:?}",
                );
                assert_eq!(
                    mock.message_lifecycle_call_count(),
                    calls_before + 1,
                    "{direction:?} structured Init provider call count",
                );
            }
        }
    }

    #[tokio::test]
    async fn null_cancel_is_valid_with_sanitization_enabled() {
        for direction in [Direction::Encrypt, Direction::Decrypt] {
            let (mut ctx, mock, context_id, session) = setup(direction).await;
            ctx.sanitize_inputs = true;
            mock.set_next_message_lifecycle_action(MockMessageLifecycleAction::Return(CkRv::OK));
            assert_eq!(
                call(&ctx, &context_id, session, direction, Endpoint::Cancel, None).await.unwrap(),
                CkRv::OK.0,
            );
            assert_eq!(shape(&ctx, &context_id, session, direction).await, None);
        }
    }

    #[tokio::test]
    async fn timed_out_message_call_keeps_one_context_guard_until_provider_returns() {
        use crate::server::grpc_service::service_utils::scope_context_operation;

        let direction = Direction::Encrypt;
        let (ctx, mock, context_id, session) = setup_with_lease(direction, Duration::ZERO).await;
        let calls_before = mock.close_session_call_count();
        mock.set_next_message_lifecycle_action(MockMessageLifecycleAction::Delay(
            Duration::from_millis(80),
            CkRv::OK,
        ));
        let guard = ctx
            .context_manager
            .begin_operation_capped(&context_id, 1)
            .expect("under cap")
            .expect("context exists");

        let rv = scope_context_operation(
            Some(guard),
            call(
                &ctx,
                &context_id,
                session,
                direction,
                Endpoint::Final,
                Some(Duration::from_millis(5)),
            ),
        )
        .await
        .unwrap();
        assert_eq!(rv, CkRv::FUNCTION_FAILED.0);
        assert_eq!(
            ctx.context_manager
                .get_context(&context_id, |context| {
                    context.in_flight.load(std::sync::atomic::Ordering::Relaxed)
                })
                .await,
            Some(1),
            "the timed-out provider closure must share, not duplicate or release, the capped guard",
        );

        let evicted = ctx.context_manager.evict_expired(&ctx.backend).await;
        assert!(evicted.is_empty(), "the reaper must not tear down a timed-out provider call");
        assert_eq!(
            mock.close_session_call_count(),
            calls_before,
            "the reaper must not close the provider session while the call is still running",
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if ctx
                    .context_manager
                    .get_context(&context_id, |context| {
                        context.in_flight.load(std::sync::atomic::Ordering::Relaxed)
                    })
                    .await
                    == Some(0)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("provider completion must release the shared context guard");

        tokio::time::sleep(Duration::from_millis(2)).await;
        let evicted = ctx.context_manager.evict_expired(&ctx.backend).await;
        assert_eq!(evicted, vec![context_id]);
        assert_eq!(mock.close_session_call_count(), calls_before + 1);
    }

    #[tokio::test]
    async fn old_client_unsafe_encrypt_decrypt_init_precedes_provider_policy_reads() {
        for direction in [Direction::Encrypt, Direction::Decrypt] {
            for case in 0..12 {
                let (ctx, mock, context_id, session, key) = setup_init_contract_ordering().await;
                let operation = ctx
                    .context_manager
                    .message_operation_lock(
                        &context_id,
                        VirtualHandle(session),
                        match direction {
                            Direction::Encrypt => ServerMessageOperation::Encrypt,
                            Direction::Decrypt => ServerMessageOperation::Decrypt,
                        },
                    )
                    .await
                    .unwrap();
                operation.lock().await.shape = Some(MessageParameterShape::SalsaChacha);
                let mut mechanism = type_only_aes_gcm();
                let mut parameter_out_spec = None;
                let mut parameter_shape = None;
                let mut init_message_parameter = None;
                let expected_rv = match case {
                    0 => {
                        mechanism.params =
                            Some(pkcs11_proxy_ng_proto::mechanism::Params::RawMechanismParams(
                                pkcs11_proxy_ng_proto::RawMechanismParams { data: vec![0xA5] },
                            ));
                        CkRv::MECHANISM_PARAM_INVALID
                    }
                    1 => {
                        parameter_out_spec = Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                            buffer_present: false,
                            buffer_len: 0,
                            value: None,
                        });
                        CkRv::MECHANISM_PARAM_INVALID
                    }
                    2 => {
                        parameter_shape = Some(MessageParameterShape::Gcm.to_proto_i32());
                        init_message_parameter =
                            Some(pkcs11_proxy_ng_proto::MessageParameter { params: None });
                        CkRv::ARGUMENTS_BAD
                    }
                    3 => {
                        // A pre-contract client cannot send a structured field
                        // without the new discriminator and envelope.
                        init_message_parameter = Some(valid_gcm_wire_parameter());
                        CkRv::MECHANISM_PARAM_INVALID
                    }
                    4 => {
                        // Raw mechanism parameters beside the new structured
                        // contract are a forbidden dual representation.
                        mechanism.params =
                            Some(pkcs11_proxy_ng_proto::mechanism::Params::RawMechanismParams(
                                pkcs11_proxy_ng_proto::RawMechanismParams { data: vec![0xA5] },
                            ));
                        parameter_out_spec = Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                            buffer_present: true,
                            buffer_len: 32,
                            value: None,
                        });
                        parameter_shape = Some(MessageParameterShape::Gcm.to_proto_i32());
                        init_message_parameter = Some(valid_gcm_wire_parameter());
                        CkRv::MECHANISM_PARAM_INVALID
                    }
                    5 | 6 => {
                        parameter_out_spec = Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                            buffer_present: true,
                            buffer_len: 32,
                            value: None,
                        });
                        parameter_shape = Some(MessageParameterShape::Gcm.to_proto_i32());
                        init_message_parameter = Some(pkcs11_proxy_ng_proto::MessageParameter {
                            params: Some(pkcs11_proxy_ng_proto::message_parameter::Params::Raw(
                                if case == 5 { Vec::new() } else { vec![0xA5] },
                            )),
                        });
                        CkRv::MECHANISM_PARAM_INVALID
                    }
                    7 | 8 => {
                        parameter_out_spec = Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                            buffer_present: false,
                            buffer_len: 0,
                            value: Some(if case == 7 { Vec::new() } else { vec![0xA5] }),
                        });
                        parameter_shape = Some(MessageParameterShape::Gcm.to_proto_i32());
                        CkRv::MECHANISM_PARAM_INVALID
                    }
                    9 => {
                        parameter_out_spec = Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                            buffer_present: true,
                            buffer_len: 32,
                            value: Some(vec![0xA5]),
                        });
                        parameter_shape = Some(MessageParameterShape::Gcm.to_proto_i32());
                        init_message_parameter = Some(valid_gcm_wire_parameter());
                        CkRv::MECHANISM_PARAM_INVALID
                    }
                    10 => {
                        // A stale shim registry cannot select a layout that
                        // differs from the daemon's current AES-GCM entry.
                        parameter_out_spec = Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                            buffer_present: true,
                            buffer_len: 32,
                            value: None,
                        });
                        parameter_shape = Some(MessageParameterShape::Ccm.to_proto_i32());
                        init_message_parameter = Some(valid_ccm_wire_parameter());
                        CkRv::MECHANISM_PARAM_INVALID
                    }
                    11 => {
                        // Even with the right discriminator, the structured
                        // variant cannot override the registry-selected shape.
                        parameter_out_spec = Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                            buffer_present: true,
                            buffer_len: 32,
                            value: None,
                        });
                        parameter_shape = Some(MessageParameterShape::Gcm.to_proto_i32());
                        init_message_parameter = Some(valid_ccm_wire_parameter());
                        CkRv::MECHANISM_PARAM_INVALID
                    }
                    _ => unreachable!(),
                };
                let before = backend_observation_counts(&mock);
                let ck_rv = match direction {
                    Direction::Encrypt => {
                        message_encrypt_init(
                            &ctx,
                            Request::new(pkcs11_proxy_ng_proto::MessageEncryptInitRequest {
                                client_context_id: context_id.0.clone(),
                                session_handle: session,
                                mechanism: Some(mechanism),
                                key_handle: key,
                                init_message_parameter,
                                parameter_out_spec,
                                parameter_shape,
                            }),
                        )
                        .await
                        .unwrap()
                        .into_inner()
                        .ck_rv
                    }
                    Direction::Decrypt => {
                        message_decrypt_init(
                            &ctx,
                            Request::new(pkcs11_proxy_ng_proto::MessageDecryptInitRequest {
                                client_context_id: context_id.0.clone(),
                                session_handle: session,
                                mechanism: Some(mechanism),
                                key_handle: key,
                                init_message_parameter,
                                parameter_out_spec,
                                parameter_shape,
                            }),
                        )
                        .await
                        .unwrap()
                        .into_inner()
                        .ck_rv
                    }
                };
                assert_eq!(ck_rv, expected_rv.0, "{direction:?} malformed case {case}");
                assert_eq!(
                    backend_observation_counts(&mock),
                    before,
                    "{direction:?} malformed case {case} must fail before provider metadata or init",
                );
                assert_eq!(
                    shape(&ctx, &context_id, session, direction).await,
                    Some(MessageParameterShape::SalsaChacha),
                    "{direction:?} malformed case {case} must preserve prior server state",
                );
            }
        }
    }

    #[tokio::test]
    async fn legacy_encrypt_decrypt_init_success_acknowledges_server_derived_shape() {
        for direction in [Direction::Encrypt, Direction::Decrypt] {
            let (ctx, mock, context_id, session) = setup(direction).await;
            let operation = ctx
                .context_manager
                .message_operation_lock(
                    &context_id,
                    VirtualHandle(session),
                    match direction {
                        Direction::Encrypt => ServerMessageOperation::Encrypt,
                        Direction::Decrypt => ServerMessageOperation::Decrypt,
                    },
                )
                .await
                .unwrap();
            operation.lock().await.shape = None;
            mock.set_next_message_lifecycle_action(MockMessageLifecycleAction::Return(CkRv::OK));
            let calls_before = mock.message_lifecycle_call_count();

            let response = match direction {
                Direction::Encrypt => {
                    let response = message_encrypt_init(
                        &ctx,
                        Request::new(pkcs11_proxy_ng_proto::MessageEncryptInitRequest {
                            client_context_id: context_id.0.clone(),
                            session_handle: session,
                            mechanism: Some(type_only_aes_gcm()),
                            key_handle: 0,
                            init_message_parameter: None,
                            parameter_out_spec: None,
                            parameter_shape: None,
                        }),
                    )
                    .await
                    .unwrap()
                    .into_inner();
                    (
                        response.ck_rv,
                        response.parameter_result,
                        response.init_message_parameter,
                        response.parameter_shape,
                    )
                }
                Direction::Decrypt => {
                    let response = message_decrypt_init(
                        &ctx,
                        Request::new(pkcs11_proxy_ng_proto::MessageDecryptInitRequest {
                            client_context_id: context_id.0.clone(),
                            session_handle: session,
                            mechanism: Some(type_only_aes_gcm()),
                            key_handle: 0,
                            init_message_parameter: None,
                            parameter_out_spec: None,
                            parameter_shape: None,
                        }),
                    )
                    .await
                    .unwrap()
                    .into_inner();
                    (
                        response.ck_rv,
                        response.parameter_result,
                        response.init_message_parameter,
                        response.parameter_shape,
                    )
                }
            };
            assert_eq!(response.0, CkRv::OK.0, "{direction:?}");
            assert_eq!(response.1, None, "legacy response has no envelope ack");
            assert_eq!(response.2, None, "legacy response has no structured ack");
            assert_eq!(
                response.3,
                Some(MessageParameterShape::Gcm.to_proto_i32()),
                "legacy response must add the server-derived shape",
            );
            assert_eq!(
                shape(&ctx, &context_id, session, direction).await,
                Some(MessageParameterShape::Gcm),
            );
            assert_eq!(
                mock.message_lifecycle_call_count(),
                calls_before + 1,
                "legacy-safe {direction:?} Init must invoke the provider exactly once",
            );
        }
    }

    #[tokio::test]
    async fn null_positive_outer_parameter_is_transparent_by_default_and_sanitized_pre_provider() {
        use crate::server::grpc_service::parameter_output_exact::parameter_output_exact;

        for sanitize in [false, true] {
            for direction in [Direction::Encrypt, Direction::Decrypt] {
                for endpoint in ["Init", "one-shot", "Begin", "Next"] {
                    let (mut ctx, mock, context_id, session) = setup(direction).await;
                    ctx.sanitize_inputs = sanitize;
                    if endpoint == "Init" {
                        mock.set_next_message_lifecycle_action(MockMessageLifecycleAction::Return(
                            CkRv::OK,
                        ));
                        let operation = ctx
                            .context_manager
                            .message_operation_lock(
                                &context_id,
                                VirtualHandle(session),
                                match direction {
                                    Direction::Encrypt => ServerMessageOperation::Encrypt,
                                    Direction::Decrypt => ServerMessageOperation::Decrypt,
                                },
                            )
                            .await
                            .unwrap();
                        operation.lock().await.shape = None;
                    }
                    let wire_spec = pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                        buffer_present: false,
                        buffer_len: 7,
                        value: None,
                    };
                    let calls_before = match endpoint {
                        "Init" => mock.message_init_contract_call_count(),
                        "Begin" => mock.message_begin_call_count(),
                        _ => mock.message_parameter_call_count(),
                    };

                    let (ck_rv, parameter_result) = match endpoint {
                        "Init" => match direction {
                            Direction::Encrypt => {
                                let response = message_encrypt_init(
                                    &ctx,
                                    Request::new(
                                        pkcs11_proxy_ng_proto::MessageEncryptInitRequest {
                                            client_context_id: context_id.0.clone(),
                                            session_handle: session,
                                            mechanism: Some(type_only_aes_gcm()),
                                            key_handle: 0,
                                            init_message_parameter: None,
                                            parameter_out_spec: Some(wire_spec.clone()),
                                            parameter_shape: Some(
                                                MessageParameterShape::Gcm.to_proto_i32(),
                                            ),
                                        },
                                    ),
                                )
                                .await
                                .unwrap()
                                .into_inner();
                                (response.ck_rv, response.parameter_result)
                            }
                            Direction::Decrypt => {
                                let response = message_decrypt_init(
                                    &ctx,
                                    Request::new(
                                        pkcs11_proxy_ng_proto::MessageDecryptInitRequest {
                                            client_context_id: context_id.0.clone(),
                                            session_handle: session,
                                            mechanism: Some(type_only_aes_gcm()),
                                            key_handle: 0,
                                            init_message_parameter: None,
                                            parameter_out_spec: Some(wire_spec.clone()),
                                            parameter_shape: Some(
                                                MessageParameterShape::Gcm.to_proto_i32(),
                                            ),
                                        },
                                    ),
                                )
                                .await
                                .unwrap()
                                .into_inner();
                                (response.ck_rv, response.parameter_result)
                            }
                        },
                        "Begin" => match direction {
                            Direction::Encrypt => {
                                let response = encrypt_message_begin(
                                    &ctx,
                                    Request::new(
                                        pkcs11_proxy_ng_proto::EncryptMessageBeginRequest {
                                            exact_output_effects_version: 1,
                                            client_context_id: context_id.0.clone(),
                                            session_handle: session,
                                            parameter: Vec::new(),
                                            associated_data: Vec::new(),
                                            associated_data_null_len: None,
                                            parameter_out_spec: Some(wire_spec.clone()),
                                            message_parameter: None,
                                        },
                                    ),
                                )
                                .await
                                .unwrap()
                                .into_inner();
                                (response.ck_rv, response.parameter_result)
                            }
                            Direction::Decrypt => {
                                let response = decrypt_message_begin(
                                    &ctx,
                                    Request::new(
                                        pkcs11_proxy_ng_proto::DecryptMessageBeginRequest {
                                            exact_output_effects_version: 1,
                                            client_context_id: context_id.0.clone(),
                                            session_handle: session,
                                            parameter: Vec::new(),
                                            associated_data: Vec::new(),
                                            associated_data_null_len: None,
                                            parameter_out_spec: Some(wire_spec.clone()),
                                            message_parameter: None,
                                        },
                                    ),
                                )
                                .await
                                .unwrap()
                                .into_inner();
                                (response.ck_rv, response.parameter_result)
                            }
                        },
                        "one-shot" | "Next" => {
                            let function = match (direction, endpoint) {
                                (Direction::Encrypt, "one-shot") => {
                                    ParameterOutputFunction::EncryptMessage
                                }
                                (Direction::Decrypt, "one-shot") => {
                                    ParameterOutputFunction::DecryptMessage
                                }
                                (Direction::Encrypt, "Next") => {
                                    ParameterOutputFunction::EncryptMessageNext
                                }
                                (Direction::Decrypt, "Next") => {
                                    ParameterOutputFunction::DecryptMessageNext
                                }
                                _ => unreachable!(),
                            };
                            let response = parameter_output_exact(
                                &ctx,
                                Request::new(
                                    pkcs11_proxy_ng_proto::ParameterOutputExactRequest { exact_output_effects_version: 1,
                                        authenticated_parameters: None,
                                        client_context_id: context_id.0.clone(),
                                        session_handle: session,
                                        function: pkcs11_proxy_ng_proto::convert::output::parameter_output_function_to_i32(function),
                                        output_spec: Some(
                                            pkcs11_proxy_ng_proto::OutputBufferSpec {
                                                buffer_present: true,
                                                buffer_len: 1,
                                                length_pointer_null: false,
                                            },
                                        ),
                                        input_data: vec![0x31],
                                        associated_data: Vec::new(),
                                        parameter: Vec::new(),
                                        parameter_out_spec: Some(wire_spec.clone()),
                                        flags: 0,
                                        mechanism: None,
                                        wrapping_key_handle: 0,
                                        key_handle: 0,
                                        message_parameter: None,
                                        input_data_null_len: None,
                                        associated_data_null_len: None,
                                    },
                                ),
                            )
                            .await
                            .unwrap()
                            .into_inner();
                            (response.output_result.unwrap().ck_rv, response.parameter_result)
                        }
                        _ => unreachable!(),
                    };

                    let expected_rv = if sanitize { CkRv::ARGUMENTS_BAD } else { CkRv::OK };
                    assert_eq!(
                        ck_rv, expected_rv.0,
                        "{direction:?} {endpoint} sanitize={sanitize}"
                    );
                    let calls_after = match endpoint {
                        "Init" => mock.message_init_contract_call_count(),
                        "Begin" => mock.message_begin_call_count(),
                        _ => mock.message_parameter_call_count(),
                    };
                    assert_eq!(
                        calls_after,
                        calls_before + usize::from(!sanitize),
                        "{direction:?} {endpoint} sanitize={sanitize} provider count",
                    );
                    if sanitize {
                        assert!(parameter_result.as_ref().is_none_or(|result| {
                            result.ck_rv == CkRv::ARGUMENTS_BAD.0
                                && result.returned_len == 0
                                && result.value.is_none()
                        }));
                    } else {
                        let acknowledgement = parameter_result.expect("outer parameter ack");
                        assert_eq!(acknowledgement.ck_rv, CkRv::OK.0);
                        assert_eq!(acknowledgement.returned_len, 7);
                        assert_eq!(acknowledgement.value, None);
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn later_message_variant_mismatch_fails_before_provider_and_preserves_shape() {
        use crate::server::grpc_service::parameter_output_exact::parameter_output_exact;

        let malformed_cases = [
            ("wrong structured variant", valid_ccm_wire_parameter(), CkRv::MECHANISM_PARAM_INVALID),
            (
                "malformed oneof",
                pkcs11_proxy_ng_proto::MessageParameter { params: None },
                CkRv::ARGUMENTS_BAD,
            ),
            (
                "raw empty",
                pkcs11_proxy_ng_proto::MessageParameter {
                    params: Some(pkcs11_proxy_ng_proto::message_parameter::Params::Raw(Vec::new())),
                },
                CkRv::MECHANISM_PARAM_INVALID,
            ),
            (
                "raw nonempty",
                pkcs11_proxy_ng_proto::MessageParameter {
                    params: Some(pkcs11_proxy_ng_proto::message_parameter::Params::Raw(vec![0xA5])),
                },
                CkRv::MECHANISM_PARAM_INVALID,
            ),
        ];

        for direction in [Direction::Encrypt, Direction::Decrypt] {
            let (ctx, mock, context_id, session) = setup(direction).await;
            for (label, wire_parameter, expected_rv) in &malformed_cases {
                let begin_before = mock.message_begin_call_count();
                let begin_rv = match direction {
                    Direction::Encrypt => {
                        encrypt_message_begin(
                            &ctx,
                            Request::new(pkcs11_proxy_ng_proto::EncryptMessageBeginRequest {
                                exact_output_effects_version: 1,
                                client_context_id: context_id.0.clone(),
                                session_handle: session,
                                parameter: Vec::new(),
                                associated_data: Vec::new(),
                                associated_data_null_len: None,
                                parameter_out_spec: Some(
                                    pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                                        buffer_present: true,
                                        buffer_len: 32,
                                        value: None,
                                    },
                                ),
                                message_parameter: Some(wire_parameter.clone()),
                            }),
                        )
                        .await
                        .unwrap()
                        .into_inner()
                        .ck_rv
                    }
                    Direction::Decrypt => {
                        decrypt_message_begin(
                            &ctx,
                            Request::new(pkcs11_proxy_ng_proto::DecryptMessageBeginRequest {
                                exact_output_effects_version: 1,
                                client_context_id: context_id.0.clone(),
                                session_handle: session,
                                parameter: Vec::new(),
                                associated_data: Vec::new(),
                                associated_data_null_len: None,
                                parameter_out_spec: Some(
                                    pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                                        buffer_present: true,
                                        buffer_len: 32,
                                        value: None,
                                    },
                                ),
                                message_parameter: Some(wire_parameter.clone()),
                            }),
                        )
                        .await
                        .unwrap()
                        .into_inner()
                        .ck_rv
                    }
                };
                assert_eq!(begin_rv, expected_rv.0, "{direction:?} Begin {label}");
                assert_eq!(
                    mock.message_begin_call_count(),
                    begin_before,
                    "{direction:?} Begin {label} must not reach the provider",
                );
                assert_eq!(
                    shape(&ctx, &context_id, session, direction).await,
                    Some(MessageParameterShape::Gcm),
                    "{direction:?} Begin {label} must preserve cached state",
                );

                let exact_before = mock.message_parameter_call_count();
                let function = match direction {
                    Direction::Encrypt => ParameterOutputFunction::EncryptMessage,
                    Direction::Decrypt => ParameterOutputFunction::DecryptMessage,
                };
                let exact = parameter_output_exact(
                    &ctx,
                    Request::new(pkcs11_proxy_ng_proto::ParameterOutputExactRequest { exact_output_effects_version: 1,
                        authenticated_parameters: None,
                        client_context_id: context_id.0.clone(),
                        session_handle: session,
                        function: pkcs11_proxy_ng_proto::convert::output::parameter_output_function_to_i32(function),
                        output_spec: Some(pkcs11_proxy_ng_proto::OutputBufferSpec {
                            buffer_present: true,
                            buffer_len: 8,
                            length_pointer_null: false,
                        }),
                        input_data: vec![0x33; 8],
                        associated_data: Vec::new(),
                        parameter: Vec::new(),
                        parameter_out_spec: Some(
                            pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                                buffer_present: true,
                                buffer_len: 32,
                                value: None,
                            },
                        ),
                        flags: 0,
                        mechanism: None,
                        wrapping_key_handle: 0,
                        key_handle: 0,
                        message_parameter: Some(wire_parameter.clone()),
                        input_data_null_len: None,
                        associated_data_null_len: None,
                    }),
                )
                .await
                .unwrap()
                .into_inner();
                assert_eq!(
                    exact.output_result.unwrap().ck_rv,
                    expected_rv.0,
                    "{direction:?} exact {label}",
                );
                assert_eq!(
                    mock.message_parameter_call_count(),
                    exact_before,
                    "{direction:?} exact {label} must not reach the provider",
                );
                assert_eq!(
                    shape(&ctx, &context_id, session, direction).await,
                    Some(MessageParameterShape::Gcm),
                    "{direction:?} exact {label} must preserve cached state",
                );
            }
        }
    }

    #[tokio::test]
    async fn backend_variant_mismatch_is_ambiguous_and_clears_shape() {
        use crate::server::grpc_service::parameter_output_exact::parameter_output_exact;

        for direction in [Direction::Encrypt, Direction::Decrypt] {
            let (ctx, mock, context_id, session) = setup(direction).await;
            let wrong_parameter = MessageParameter::try_from(&valid_ccm_wire_parameter()).unwrap();

            mock.set_next_message_parameter_response(wrong_parameter.clone());
            let begin_before = mock.message_begin_call_count();
            let begin_rv = match direction {
                Direction::Encrypt => {
                    encrypt_message_begin(
                        &ctx,
                        Request::new(pkcs11_proxy_ng_proto::EncryptMessageBeginRequest {
                            exact_output_effects_version: 1,
                            client_context_id: context_id.0.clone(),
                            session_handle: session,
                            parameter: Vec::new(),
                            associated_data: Vec::new(),
                            associated_data_null_len: None,
                            parameter_out_spec: Some(
                                pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                                    buffer_present: true,
                                    buffer_len: 32,
                                    value: None,
                                },
                            ),
                            message_parameter: Some(valid_gcm_wire_parameter()),
                        }),
                    )
                    .await
                    .unwrap()
                    .into_inner()
                    .ck_rv
                }
                Direction::Decrypt => {
                    decrypt_message_begin(
                        &ctx,
                        Request::new(pkcs11_proxy_ng_proto::DecryptMessageBeginRequest {
                            exact_output_effects_version: 1,
                            client_context_id: context_id.0.clone(),
                            session_handle: session,
                            parameter: Vec::new(),
                            associated_data: Vec::new(),
                            associated_data_null_len: None,
                            parameter_out_spec: Some(
                                pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                                    buffer_present: true,
                                    buffer_len: 32,
                                    value: None,
                                },
                            ),
                            message_parameter: Some(valid_gcm_wire_parameter()),
                        }),
                    )
                    .await
                    .unwrap()
                    .into_inner()
                    .ck_rv
                }
            };
            assert_eq!(begin_rv, CkRv::DEVICE_ERROR.0, "{direction:?} Begin");
            assert_eq!(mock.message_begin_call_count(), begin_before + 1);
            assert_eq!(shape(&ctx, &context_id, session, direction).await, None);

            let operation = ctx
                .context_manager
                .message_operation_lock(
                    &context_id,
                    VirtualHandle(session),
                    match direction {
                        Direction::Encrypt => ServerMessageOperation::Encrypt,
                        Direction::Decrypt => ServerMessageOperation::Decrypt,
                    },
                )
                .await
                .unwrap();
            operation.lock().await.shape = Some(MessageParameterShape::Gcm);
            mock.set_next_message_parameter_response(wrong_parameter.clone());
            let exact_before = mock.message_parameter_call_count();
            let function = match direction {
                Direction::Encrypt => ParameterOutputFunction::EncryptMessage,
                Direction::Decrypt => ParameterOutputFunction::DecryptMessage,
            };
            let exact = parameter_output_exact(
                &ctx,
                Request::new(pkcs11_proxy_ng_proto::ParameterOutputExactRequest {
                    exact_output_effects_version: 1,
                    authenticated_parameters: None,
                    client_context_id: context_id.0.clone(),
                    session_handle: session,
                    function:
                        pkcs11_proxy_ng_proto::convert::output::parameter_output_function_to_i32(
                            function,
                        ),
                    output_spec: Some(pkcs11_proxy_ng_proto::OutputBufferSpec {
                        buffer_present: true,
                        buffer_len: 8,
                        length_pointer_null: false,
                    }),
                    input_data: vec![0x33; 8],
                    associated_data: Vec::new(),
                    parameter: Vec::new(),
                    parameter_out_spec: Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                        buffer_present: true,
                        buffer_len: 32,
                        value: None,
                    }),
                    flags: 0,
                    mechanism: None,
                    wrapping_key_handle: 0,
                    key_handle: 0,
                    message_parameter: Some(valid_gcm_wire_parameter()),
                    input_data_null_len: None,
                    associated_data_null_len: None,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(
                exact.output_result.unwrap().ck_rv,
                CkRv::DEVICE_ERROR.0,
                "{direction:?} exact",
            );
            assert_eq!(mock.message_parameter_call_count(), exact_before + 1);
            assert_eq!(shape(&ctx, &context_id, session, direction).await, None);
        }
    }

    #[tokio::test]
    async fn message_shape_state_isolated_by_context_session_and_operation() {
        use crate::server::grpc_service::parameter_output_exact::parameter_output_exact;

        let mock = Arc::new(MockBackend::default_test());
        mock.initialize().unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        manager.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let context_a = manager.create_context(None).await.unwrap();
        let context_b = manager.create_context(None).await.unwrap();

        let backend_a1 =
            mock.open_session(CkSlotId(0), CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).unwrap();
        let backend_a2 =
            mock.open_session(CkSlotId(0), CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).unwrap();
        let backend_b1 =
            mock.open_session(CkSlotId(0), CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).unwrap();
        let session_a1 = register_session_handle(
            &manager,
            &context_a,
            backend_a1,
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
        )
        .await
        .unwrap();
        let session_a2 = register_session_handle(
            &manager,
            &context_a,
            backend_a2,
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
        )
        .await
        .unwrap();
        let session_b1 = register_session_handle(
            &manager,
            &context_b,
            backend_b1,
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
        )
        .await
        .unwrap();
        assert_eq!(
            session_a1, session_b1,
            "independent contexts deliberately reuse the same virtual handle",
        );
        assert_ne!(session_a1, session_a2);

        for (context_id, session, operation, installed_shape) in [
            (&context_a, session_a1, ServerMessageOperation::Encrypt, MessageParameterShape::Gcm),
            (&context_a, session_a1, ServerMessageOperation::Decrypt, MessageParameterShape::Ccm),
            (
                &context_a,
                session_a2,
                ServerMessageOperation::Encrypt,
                MessageParameterShape::SalsaChacha,
            ),
            (&context_b, session_b1, ServerMessageOperation::Encrypt, MessageParameterShape::Ccm),
        ] {
            manager
                .message_operation_lock(context_id, VirtualHandle(session), operation)
                .await
                .unwrap()
                .lock()
                .await
                .shape = Some(installed_shape);
        }
        let ctx = HandlerContext::for_test(&manager, &backend);

        let begin_before = mock.message_begin_call_count();
        let gcm_wire = valid_gcm_wire_parameter();
        let gcm = MessageParameter::try_from(&gcm_wire).unwrap();
        let a_gcm = encrypt_message_begin(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::EncryptMessageBeginRequest {
                exact_output_effects_version: 1,
                client_context_id: context_a.0.clone(),
                session_handle: session_a1,
                parameter: Vec::new(),
                associated_data: Vec::new(),
                associated_data_null_len: None,
                parameter_out_spec: Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                    buffer_present: true,
                    buffer_len: 32,
                    value: None,
                }),
                message_parameter: Some(gcm_wire),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(a_gcm.ck_rv, CkRv::OK.0);
        assert_eq!(mock.last_message_parameter_call(), Some(gcm));

        let ccm_wire = valid_ccm_wire_parameter();
        let ccm = MessageParameter::try_from(&ccm_wire).unwrap();
        let b_ccm = encrypt_message_begin(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::EncryptMessageBeginRequest {
                exact_output_effects_version: 1,
                client_context_id: context_b.0.clone(),
                session_handle: session_b1,
                parameter: Vec::new(),
                associated_data: Vec::new(),
                associated_data_null_len: None,
                parameter_out_spec: Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                    buffer_present: true,
                    buffer_len: 32,
                    value: None,
                }),
                message_parameter: Some(ccm_wire),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(b_ccm.ck_rv, CkRv::OK.0);
        assert_eq!(mock.last_message_parameter_call(), Some(ccm.clone()));
        assert_eq!(mock.message_begin_call_count(), begin_before + 2);

        let exact_before = mock.message_parameter_call_count();
        let a_decrypt = parameter_output_exact(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::ParameterOutputExactRequest {
                exact_output_effects_version: 1,
                authenticated_parameters: None,
                client_context_id: context_a.0.clone(),
                session_handle: session_a1,
                function: pkcs11_proxy_ng_proto::convert::output::parameter_output_function_to_i32(
                    ParameterOutputFunction::DecryptMessage,
                ),
                output_spec: Some(pkcs11_proxy_ng_proto::OutputBufferSpec {
                    buffer_present: true,
                    buffer_len: 8,
                    length_pointer_null: false,
                }),
                input_data: vec![0x44; 8],
                associated_data: Vec::new(),
                parameter: Vec::new(),
                parameter_out_spec: Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                    buffer_present: true,
                    buffer_len: 32,
                    value: None,
                }),
                flags: 0,
                mechanism: None,
                wrapping_key_handle: 0,
                key_handle: 0,
                message_parameter: Some((&ccm).into()),
                input_data_null_len: None,
                associated_data_null_len: None,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(a_decrypt.output_result.unwrap().ck_rv, CkRv::OK.0);
        assert_eq!(mock.last_message_parameter_call(), Some(ccm));

        let salsa_wire = valid_salsa_wire_parameter();
        let salsa = MessageParameter::try_from(&salsa_wire).unwrap();
        let a2_encrypt = parameter_output_exact(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::ParameterOutputExactRequest {
                exact_output_effects_version: 1,
                authenticated_parameters: None,
                client_context_id: context_a.0.clone(),
                session_handle: session_a2,
                function: pkcs11_proxy_ng_proto::convert::output::parameter_output_function_to_i32(
                    ParameterOutputFunction::EncryptMessage,
                ),
                output_spec: Some(pkcs11_proxy_ng_proto::OutputBufferSpec {
                    buffer_present: true,
                    buffer_len: 8,
                    length_pointer_null: false,
                }),
                input_data: vec![0x55; 8],
                associated_data: Vec::new(),
                parameter: Vec::new(),
                parameter_out_spec: Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                    buffer_present: true,
                    buffer_len: 32,
                    value: None,
                }),
                flags: 0,
                mechanism: None,
                wrapping_key_handle: 0,
                key_handle: 0,
                message_parameter: Some(salsa_wire),
                input_data_null_len: None,
                associated_data_null_len: None,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(a2_encrypt.output_result.unwrap().ck_rv, CkRv::OK.0);
        assert_eq!(mock.last_message_parameter_call(), Some(salsa));
        assert_eq!(mock.message_parameter_call_count(), exact_before + 2);

        let begin_mismatch_before = mock.message_begin_call_count();
        let begin_mismatch = encrypt_message_begin(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::EncryptMessageBeginRequest {
                exact_output_effects_version: 1,
                client_context_id: context_a.0.clone(),
                session_handle: session_a1,
                parameter: Vec::new(),
                associated_data: Vec::new(),
                associated_data_null_len: None,
                parameter_out_spec: Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                    buffer_present: true,
                    buffer_len: 32,
                    value: None,
                }),
                message_parameter: Some(valid_ccm_wire_parameter()),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(begin_mismatch.ck_rv, CkRv::MECHANISM_PARAM_INVALID.0);
        assert_eq!(mock.message_begin_call_count(), begin_mismatch_before);

        let exact_mismatch_before = mock.message_parameter_call_count();
        let exact_mismatch = parameter_output_exact(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::ParameterOutputExactRequest {
                exact_output_effects_version: 1,
                authenticated_parameters: None,
                client_context_id: context_a.0.clone(),
                session_handle: session_a1,
                function: pkcs11_proxy_ng_proto::convert::output::parameter_output_function_to_i32(
                    ParameterOutputFunction::DecryptMessage,
                ),
                output_spec: Some(pkcs11_proxy_ng_proto::OutputBufferSpec {
                    buffer_present: true,
                    buffer_len: 8,
                    length_pointer_null: false,
                }),
                input_data: vec![0x66; 8],
                associated_data: Vec::new(),
                parameter: Vec::new(),
                parameter_out_spec: Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                    buffer_present: true,
                    buffer_len: 32,
                    value: None,
                }),
                flags: 0,
                mechanism: None,
                wrapping_key_handle: 0,
                key_handle: 0,
                message_parameter: Some(valid_gcm_wire_parameter()),
                input_data_null_len: None,
                associated_data_null_len: None,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(exact_mismatch.output_result.unwrap().ck_rv, CkRv::MECHANISM_PARAM_INVALID.0,);
        assert_eq!(mock.message_parameter_call_count(), exact_mismatch_before);

        for (context_id, session, direction, expected_shape) in [
            (&context_a, session_a1, Direction::Encrypt, MessageParameterShape::Gcm),
            (&context_a, session_a1, Direction::Decrypt, MessageParameterShape::Ccm),
            (&context_a, session_a2, Direction::Encrypt, MessageParameterShape::SalsaChacha),
            (&context_b, session_b1, Direction::Encrypt, MessageParameterShape::Ccm),
        ] {
            assert_eq!(
                shape(&ctx, context_id, session, direction).await,
                Some(expected_shape),
                "state must be isolated by context, session and operation",
            );
        }
    }

    #[tokio::test]
    async fn dedicated_legacy_message_handlers_reject_raw_parameter_before_provider() {
        for case in 0..5 {
            let operation = match case {
                0 | 1 => ServerMessageOperation::Encrypt,
                2 | 3 => ServerMessageOperation::Decrypt,
                4 => ServerMessageOperation::Sign,
                _ => unreachable!(),
            };
            let (ctx, mock, context_id, session) = setup_raw_handler(operation).await;
            let calls_before = mock.data_op_call_count();
            let rv = match case {
                0 => {
                    encrypt_message(
                        &ctx,
                        Request::new(pkcs11_proxy_ng_proto::EncryptMessageRequest {
                            client_context_id: context_id.0.clone(),
                            session_handle: session,
                            parameter: vec![0xA5],
                            associated_data: Vec::new(),
                            plaintext: vec![1],
                            associated_data_null_len: None,
                            plaintext_null_len: None,
                        }),
                    )
                    .await
                    .unwrap()
                    .into_inner()
                    .ck_rv
                }
                1 => {
                    encrypt_message_next(
                        &ctx,
                        Request::new(pkcs11_proxy_ng_proto::EncryptMessageNextRequest {
                            client_context_id: context_id.0.clone(),
                            session_handle: session,
                            parameter: vec![0xA5],
                            plaintext_part: vec![1],
                            flags: 0,
                            plaintext_part_null_len: None,
                        }),
                    )
                    .await
                    .unwrap()
                    .into_inner()
                    .ck_rv
                }
                2 => {
                    decrypt_message(
                        &ctx,
                        Request::new(pkcs11_proxy_ng_proto::DecryptMessageRequest {
                            client_context_id: context_id.0.clone(),
                            session_handle: session,
                            parameter: vec![0xA5],
                            associated_data: Vec::new(),
                            ciphertext: vec![1],
                            associated_data_null_len: None,
                            ciphertext_null_len: None,
                        }),
                    )
                    .await
                    .unwrap()
                    .into_inner()
                    .ck_rv
                }
                3 => {
                    decrypt_message_next(
                        &ctx,
                        Request::new(pkcs11_proxy_ng_proto::DecryptMessageNextRequest {
                            client_context_id: context_id.0.clone(),
                            session_handle: session,
                            parameter: vec![0xA5],
                            ciphertext_part: vec![1],
                            flags: 0,
                            ciphertext_part_null_len: None,
                        }),
                    )
                    .await
                    .unwrap()
                    .into_inner()
                    .ck_rv
                }
                4 => {
                    sign_message(
                        &ctx,
                        Request::new(pkcs11_proxy_ng_proto::SignMessageRequest {
                            client_context_id: context_id.0.clone(),
                            session_handle: session,
                            parameter: vec![0xA5],
                            data: vec![1],
                            data_null_len: None,
                        }),
                    )
                    .await
                    .unwrap()
                    .into_inner()
                    .ck_rv
                }
                _ => unreachable!(),
            };
            assert_eq!(rv, CkRv::MECHANISM_PARAM_INVALID.0, "legacy handler case {case}");
            assert_eq!(
                mock.data_op_call_count(),
                calls_before,
                "legacy handler case {case} must reject poison bytes before provider",
            );
            let retained = ctx
                .context_manager
                .message_operation_lock(&context_id, VirtualHandle(session), operation)
                .await
                .unwrap()
                .lock()
                .await
                .shape;
            assert_eq!(retained, Some(MessageParameterShape::Unmodeled));
        }
    }

    #[tokio::test]
    async fn invalid_message_sessions_do_not_allocate_state_or_call_provider() {
        let mock = Arc::new(MockBackend::default_test());
        mock.initialize().unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        manager.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let context_id = manager.create_context(None).await.unwrap();
        let ctx = HandlerContext::for_test(&manager, &backend);
        let calls_before = mock.message_lifecycle_call_count();

        for session_handle in 10_000..10_100 {
            let response = message_encrypt_final(
                &ctx,
                Request::new(pkcs11_proxy_ng_proto::MessageEncryptFinalRequest {
                    client_context_id: context_id.0.clone(),
                    session_handle,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(response.ck_rv, CkRv::SESSION_HANDLE_INVALID.0);
        }

        assert_eq!(mock.message_lifecycle_call_count(), calls_before);
        assert_eq!(
            manager.get_context(&context_id, |context| context.message_operations.len()).await,
            Some(0),
            "invalid client-selected handles must not grow operation state",
        );
    }
}
