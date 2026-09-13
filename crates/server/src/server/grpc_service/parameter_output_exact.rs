use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_proto::convert::message_params::{
    MessageParameter, MessageParameterShape, validate_structured_wire_parameter,
};
use pkcs11_proxy_ng_proto::convert::output::parameter_output_function_from_i32;
use pkcs11_proxy_ng_types::{
    CkFlags, CkInBuf, CkOutputBufferResult, CkOutputBufferSpec, CkParameterRoundtripResult,
    CkParameterRoundtripSpec, CkResult, CkRv, ParameterOutputFunction,
};

use super::super::context_manager::{
    ClientContextId, MessageOperation, MessageOperationTransition,
};
use super::super::handle_map::VirtualHandle;
use super::service_utils::{check_sanitize, input_from_wire, resolve_session, spawn_backend};

use crate::server::grpc_service::HandlerContext;

const MAX_EXACT_OUTPUT_BYTES: u64 = 512 * 1024 * 1024;

fn native_message_parameter_len(parameter: &MessageParameter) -> CkResult<u64> {
    match parameter {
        MessageParameter::GcmMessage(_) => {
            Ok(std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>() as u64)
        }
        MessageParameter::CcmMessage(_) => {
            Ok(std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>() as u64)
        }
        MessageParameter::SalaChacha(_) => {
            Ok(std::mem::size_of::<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>() as u64)
        }
        MessageParameter::Raw(_) => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

fn parameter_ack_matches(
    result: &CkParameterRoundtripResult,
    spec: &CkParameterRoundtripSpec,
    expected_rv: CkRv,
) -> bool {
    result.ck_rv == expected_rv
        && result.returned_len == spec.buffer_len
        && result.value == spec.buffer_present.then(Vec::new)
}

fn translate_parameter_ack(
    output: &CkOutputBufferResult,
    caller_spec: &CkParameterRoundtripSpec,
) -> CkParameterRoundtripResult {
    CkParameterRoundtripResult {
        ck_rv: output.ck_rv,
        returned_len: caller_spec.buffer_len,
        value: caller_spec.buffer_present.then(Vec::new),
    }
}

fn message_parameter_has_null_positive(parameter: &MessageParameter) -> bool {
    match parameter {
        MessageParameter::Raw(_) => true,
        MessageParameter::GcmMessage(params) => {
            params.iv_null_len.is_some_and(|len| len > 0)
                || params.tag_null_len.is_some_and(|len| len > 0)
        }
        MessageParameter::CcmMessage(params) => {
            params.nonce_null_len.is_some_and(|len| len > 0)
                || params.mac_null_len.is_some_and(|len| len > 0)
        }
        MessageParameter::SalaChacha(params) => {
            params.nonce_null_len.is_some_and(|len| len > 0)
                || params.tag_null_len.is_some_and(|len| len > 0)
        }
    }
}

pub(super) async fn parameter_output_exact(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::ParameterOutputExactRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::ParameterOutputExactResponse>, Status> {
    let started = std::time::Instant::now();
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let mut req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // Parse the function discriminator
    let function = match parameter_output_function_from_i32(req.function) {
        Some(f) => f,
        None => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
                output_result: None,
                parameter_result: None,
                message_parameter_out: None,
            }));
        }
    };

    let output_spec_present = req.output_spec.is_some();
    let parameter_spec_present = req.parameter_out_spec.is_some();

    // Build the output buffer spec
    let output_spec =
        req.output_spec.as_ref().map(CkOutputBufferSpec::from).unwrap_or(CkOutputBufferSpec {
            buffer_present: false,
            buffer_len: 0,
            length_pointer_null: false,
        });

    // Build the parameter roundtrip spec
    let param_out_spec = req
        .parameter_out_spec
        .take()
        .map(|s| CkParameterRoundtripSpec {
            buffer_present: s.buffer_present,
            buffer_len: s.buffer_len,
            value: s.value,
        })
        .unwrap_or(CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None });

    let input_data = req.input_data;
    let input_data_null_len = req.input_data_null_len;
    let associated_data = req.associated_data;
    let associated_data_null_len = req.associated_data_null_len;
    let parameter = req.parameter;
    let flags = CkFlags(req.flags as u64);

    match function {
        ParameterOutputFunction::WrapKeyAuthenticated => {
            let outcome = async {
                let p = match super::key_ops::wrap_preparation::prepare_wrap(
                    ctx,
                    &ctx_id,
                    req.session_handle,
                    req.wrapping_key_handle,
                    req.key_handle,
                    req.mechanism,
                )
                .await?
                {
                    Ok(p) => p,
                    Err(rv) => return Ok(Err(rv)),
                };
                if let Err(rv) = check_sanitize(sanitize_inputs, associated_data_null_len) {
                    return Ok(Err(rv));
                }
                let backend = backend_ref.clone();
                spawn_backend(move || {
                    backend.wrap_key_authenticated_exact(
                        p.session,
                        &p.mechanism,
                        p.wrapping_key,
                        p.key,
                        input_from_wire(&associated_data, associated_data_null_len),
                        &output_spec,
                        &param_out_spec,
                    )
                })
                .await
            }
            .await;
            let result = super::audit_events::audit_key_outcome(
                ctx,
                &ctx_id,
                "C_WrapKeyAuthenticated",
                req.session_handle,
                started,
                outcome,
                |(output, _)| output.ck_rv,
            )?;
            Ok(Response::new(result_to_proto(result)))
        }

        // Canonical Encrypt/Decrypt one-shot and Next paths. Their active Init
        // state selects the only legal structured shape before provider access.
        ParameterOutputFunction::EncryptMessage
        | ParameterOutputFunction::DecryptMessage
        | ParameterOutputFunction::EncryptMessageNext
        | ParameterOutputFunction::DecryptMessageNext => {
            let operation_kind = match function {
                ParameterOutputFunction::EncryptMessage
                | ParameterOutputFunction::EncryptMessageNext => MessageOperation::Encrypt,
                ParameterOutputFunction::DecryptMessage
                | ParameterOutputFunction::DecryptMessageNext => MessageOperation::Decrypt,
                _ => unreachable!(),
            };
            let operation_lock = match ctx_mgr
                .message_operation_lock(&ctx_id, VirtualHandle(req.session_handle), operation_kind)
                .await
            {
                Ok(lock) => lock,
                Err(error) => {
                    return Ok(Response::new(error_response(error)));
                }
            };
            let operation = operation_lock.lock_owned().await;
            let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
                Ok(s) => s,
                Err(error) => {
                    return Ok(Response::new(error_response(error)));
                }
            };

            if !output_spec_present
                || !parameter_spec_present
                || output_spec.buffer_len > MAX_EXACT_OUTPUT_BYTES
                || !parameter.is_empty()
                || param_out_spec.value.is_some()
            {
                return Ok(Response::new(error_response(CkRv::MECHANISM_PARAM_INVALID)));
            }
            if let Err(rv) = check_sanitize(sanitize_inputs, associated_data_null_len) {
                return Ok(Response::new(error_response(rv)));
            }
            if let Err(rv) = check_sanitize(sanitize_inputs, input_data_null_len) {
                return Ok(Response::new(error_response(rv)));
            }

            let installed_shape = match operation.shape {
                Some(shape) => shape,
                None => {
                    return Ok(Response::new(error_response(CkRv::OPERATION_NOT_INITIALIZED)));
                }
            };
            let msg_param = match req
                .message_parameter
                .as_ref()
                .map(|parameter| {
                    validate_structured_wire_parameter(parameter)?;
                    MessageParameter::try_from(parameter)
                })
                .transpose()
            {
                Ok(parameter) => parameter,
                Err(error) => return Ok(Response::new(error_response(error))),
            };
            let provider_spec = match (installed_shape, msg_param.as_ref()) {
                (_, None) => {
                    if param_out_spec.buffer_present && param_out_spec.buffer_len > 0 {
                        return Ok(Response::new(error_response(CkRv::MECHANISM_PARAM_INVALID)));
                    }
                    if sanitize_inputs
                        && !param_out_spec.buffer_present
                        && param_out_spec.buffer_len > 0
                    {
                        return Ok(Response::new(error_response(CkRv::ARGUMENTS_BAD)));
                    }
                    param_out_spec.clone()
                }
                (MessageParameterShape::Unmodeled, Some(_)) => {
                    return Ok(Response::new(error_response(CkRv::MECHANISM_PARAM_INVALID)));
                }
                (shape, Some(parameter)) => {
                    if parameter.validate_structured_shape(shape).is_err()
                        || !param_out_spec.buffer_present
                        || param_out_spec.buffer_len == 0
                    {
                        return Ok(Response::new(error_response(CkRv::MECHANISM_PARAM_INVALID)));
                    }
                    if sanitize_inputs && message_parameter_has_null_positive(parameter) {
                        return Ok(Response::new(error_response(CkRv::ARGUMENTS_BAD)));
                    }
                    CkParameterRoundtripSpec {
                        buffer_present: true,
                        buffer_len: match native_message_parameter_len(parameter) {
                            Ok(len) => len,
                            Err(error) => return Ok(Response::new(error_response(error))),
                        },
                        value: None,
                    }
                }
            };

            let backend = backend_ref.clone();
            let mut transition = MessageOperationTransition::begin(operation);
            let result = if let Some(mp) = msg_param {
                let request_parameter = mp.clone();
                let result = spawn_backend(move || {
                    transition.mark_started();
                    let provider_result = match function {
                        ParameterOutputFunction::EncryptMessage
                        | ParameterOutputFunction::DecryptMessage => dispatch_message_oneshot_msg(
                            function,
                            &*backend,
                            session,
                            &mp,
                            input_from_wire(&associated_data, associated_data_null_len),
                            input_from_wire(&input_data, input_data_null_len),
                            &output_spec,
                            &provider_spec,
                        ),
                        ParameterOutputFunction::EncryptMessageNext
                        | ParameterOutputFunction::DecryptMessageNext => dispatch_message_next_msg(
                            function,
                            &*backend,
                            session,
                            &mp,
                            input_from_wire(&input_data, input_data_null_len),
                            flags,
                            &output_spec,
                            &provider_spec,
                        ),
                        _ => unreachable!(),
                    };
                    match provider_result {
                        Ok((output, parameter_result, returned_parameter))
                            if parameter_ack_matches(
                                &parameter_result,
                                &provider_spec,
                                output.ck_rv,
                            ) && returned_parameter
                                .validate_structured_shape(installed_shape)
                                .is_ok()
                                && request_parameter
                                    .same_layout_and_scalars(&returned_parameter) =>
                        {
                            let response_parameter = if matches!(
                                function,
                                ParameterOutputFunction::DecryptMessage
                                    | ParameterOutputFunction::DecryptMessageNext
                            ) {
                                request_parameter
                            } else {
                                returned_parameter
                            };
                            let caller_ack = translate_parameter_ack(&output, &param_out_spec);
                            let outcome = Ok(());
                            transition.settle(&outcome, Some(installed_shape));
                            Ok((output, caller_ack, response_parameter))
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
                .await?;
                return Ok(Response::new(result_to_proto_msg(result)));
            } else {
                spawn_backend(move || {
                    transition.mark_started();
                    let provider_result = match function {
                        ParameterOutputFunction::EncryptMessage
                        | ParameterOutputFunction::DecryptMessage => dispatch_message_oneshot(
                            function,
                            &*backend,
                            session,
                            &parameter,
                            input_from_wire(&associated_data, associated_data_null_len),
                            input_from_wire(&input_data, input_data_null_len),
                            &output_spec,
                            &provider_spec,
                        ),
                        ParameterOutputFunction::EncryptMessageNext
                        | ParameterOutputFunction::DecryptMessageNext => dispatch_message_next(
                            function,
                            &*backend,
                            session,
                            &parameter,
                            input_from_wire(&input_data, input_data_null_len),
                            flags,
                            &output_spec,
                            &provider_spec,
                        ),
                        _ => unreachable!(),
                    };
                    match provider_result {
                        Ok((output, parameter_result))
                            if parameter_ack_matches(
                                &parameter_result,
                                &provider_spec,
                                output.ck_rv,
                            ) =>
                        {
                            let outcome = Ok(());
                            transition.settle(&outcome, Some(installed_shape));
                            Ok((output, parameter_result))
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
                .await?
            };
            Ok(Response::new(result_to_proto(result)))
        }

        // Sign remains empty-only; structured or materialized parameters are
        // rejected before the backend. The zero-length pointer class is kept.
        ParameterOutputFunction::SignMessage | ParameterOutputFunction::SignMessageNext => {
            let operation_lock = match ctx_mgr
                .message_operation_lock(
                    &ctx_id,
                    VirtualHandle(req.session_handle),
                    MessageOperation::Sign,
                )
                .await
            {
                Ok(lock) => lock,
                Err(error) => {
                    return Ok(Response::new(error_response(error)));
                }
            };
            let operation = operation_lock.lock_owned().await;
            if !output_spec_present
                || !parameter_spec_present
                || output_spec.buffer_len > MAX_EXACT_OUTPUT_BYTES
                || !parameter.is_empty()
                || req.message_parameter.is_some()
                || param_out_spec.value.is_some()
                || param_out_spec.buffer_len > 0
            {
                return Ok(Response::new(error_response(CkRv::MECHANISM_PARAM_INVALID)));
            }
            let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
                Ok(session) => session,
                Err(error) => return Ok(Response::new(error_response(error))),
            };
            if operation.shape.is_none() {
                return Ok(Response::new(error_response(CkRv::OPERATION_NOT_INITIALIZED)));
            }
            if let Err(rv) = check_sanitize(sanitize_inputs, input_data_null_len) {
                return Ok(Response::new(error_response(rv)));
            }
            let backend = backend_ref.clone();
            let mut transition = MessageOperationTransition::begin(operation);
            let result = spawn_backend(move || {
                transition.mark_started();
                let provider_result = match function {
                    ParameterOutputFunction::SignMessage => dispatch_message_oneshot(
                        function,
                        &*backend,
                        session,
                        &parameter,
                        input_from_wire(&associated_data, associated_data_null_len),
                        input_from_wire(&input_data, input_data_null_len),
                        &output_spec,
                        &param_out_spec,
                    ),
                    ParameterOutputFunction::SignMessageNext => dispatch_message_next(
                        function,
                        &*backend,
                        session,
                        &parameter,
                        input_from_wire(&input_data, input_data_null_len),
                        flags,
                        &output_spec,
                        &param_out_spec,
                    ),
                    _ => unreachable!(),
                };
                match provider_result {
                    Ok((output, parameter_result))
                        if parameter_ack_matches(
                            &parameter_result,
                            &param_out_spec,
                            output.ck_rv,
                        ) =>
                    {
                        let outcome = Ok(());
                        transition.settle(&outcome, Some(MessageParameterShape::Unmodeled));
                        Ok((output, parameter_result))
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
            .await?;
            Ok(Response::new(result_to_proto(result)))
        }
    }
}

fn dispatch_message_oneshot(
    function: ParameterOutputFunction,
    backend: &dyn Pkcs11Backend,
    session: pkcs11_proxy_ng_types::CkSessionHandle,
    parameter: &[u8],
    associated_data: CkInBuf<'_>,
    input_data: CkInBuf<'_>,
    output_spec: &CkOutputBufferSpec,
    param_out_spec: &CkParameterRoundtripSpec,
) -> pkcs11_proxy_ng_types::CkResult<(
    pkcs11_proxy_ng_types::CkOutputBufferResult,
    pkcs11_proxy_ng_types::CkParameterRoundtripResult,
)> {
    match function {
        ParameterOutputFunction::EncryptMessage => backend.encrypt_message_exact(
            session,
            parameter,
            associated_data,
            input_data,
            output_spec,
            param_out_spec,
        ),
        ParameterOutputFunction::DecryptMessage => backend.decrypt_message_exact(
            session,
            parameter,
            associated_data,
            input_data,
            output_spec,
            param_out_spec,
        ),
        ParameterOutputFunction::SignMessage => {
            backend.sign_message_exact(session, parameter, input_data, output_spec, param_out_spec)
        }
        // Defensive: parent dispatch routes only matching variants here; a future
        // variant added without updating the parent would otherwise panic across
        // the gRPC boundary. Return CKR_FUNCTION_NOT_SUPPORTED instead.
        _ => Err(pkcs11_proxy_ng_types::CkRv::FUNCTION_NOT_SUPPORTED),
    }
}

fn dispatch_message_next(
    function: ParameterOutputFunction,
    backend: &dyn Pkcs11Backend,
    session: pkcs11_proxy_ng_types::CkSessionHandle,
    parameter: &[u8],
    input_data: CkInBuf<'_>,
    flags: CkFlags,
    output_spec: &CkOutputBufferSpec,
    param_out_spec: &CkParameterRoundtripSpec,
) -> pkcs11_proxy_ng_types::CkResult<(
    pkcs11_proxy_ng_types::CkOutputBufferResult,
    pkcs11_proxy_ng_types::CkParameterRoundtripResult,
)> {
    match function {
        ParameterOutputFunction::EncryptMessageNext => backend.encrypt_message_next_exact(
            session,
            parameter,
            input_data,
            flags,
            output_spec,
            param_out_spec,
        ),
        ParameterOutputFunction::DecryptMessageNext => backend.decrypt_message_next_exact(
            session,
            parameter,
            input_data,
            flags,
            output_spec,
            param_out_spec,
        ),
        ParameterOutputFunction::SignMessageNext => backend.sign_message_next_exact(
            session,
            parameter,
            input_data,
            output_spec,
            param_out_spec,
        ),
        // Defensive: see `dispatch_message_oneshot` for rationale.
        _ => Err(pkcs11_proxy_ng_types::CkRv::FUNCTION_NOT_SUPPORTED),
    }
}

fn dispatch_message_oneshot_msg(
    function: ParameterOutputFunction,
    backend: &dyn Pkcs11Backend,
    session: pkcs11_proxy_ng_types::CkSessionHandle,
    msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    associated_data: CkInBuf<'_>,
    input_data: CkInBuf<'_>,
    output_spec: &CkOutputBufferSpec,
    provider_spec: &CkParameterRoundtripSpec,
) -> pkcs11_proxy_ng_types::CkResult<(
    pkcs11_proxy_ng_types::CkOutputBufferResult,
    pkcs11_proxy_ng_types::CkParameterRoundtripResult,
    pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
)> {
    match function {
        ParameterOutputFunction::EncryptMessage => backend.encrypt_message_exact_msg(
            session,
            msg_param,
            associated_data,
            input_data,
            output_spec,
            provider_spec,
        ),
        ParameterOutputFunction::DecryptMessage => backend.decrypt_message_exact_msg(
            session,
            msg_param,
            associated_data,
            input_data,
            output_spec,
            provider_spec,
        ),
        ParameterOutputFunction::SignMessage => Err(CkRv::FUNCTION_NOT_SUPPORTED),
        // Defensive: parent dispatch routes only matching variants here; a future
        // variant added without updating the parent would otherwise panic across
        // the gRPC boundary. Return CKR_FUNCTION_NOT_SUPPORTED instead.
        _ => Err(pkcs11_proxy_ng_types::CkRv::FUNCTION_NOT_SUPPORTED),
    }
}

fn dispatch_message_next_msg(
    function: ParameterOutputFunction,
    backend: &dyn Pkcs11Backend,
    session: pkcs11_proxy_ng_types::CkSessionHandle,
    msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    input_data: CkInBuf<'_>,
    flags: CkFlags,
    output_spec: &CkOutputBufferSpec,
    provider_spec: &CkParameterRoundtripSpec,
) -> pkcs11_proxy_ng_types::CkResult<(
    pkcs11_proxy_ng_types::CkOutputBufferResult,
    pkcs11_proxy_ng_types::CkParameterRoundtripResult,
    pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
)> {
    match function {
        ParameterOutputFunction::EncryptMessageNext => backend.encrypt_message_next_exact_msg(
            session,
            msg_param,
            input_data,
            flags,
            output_spec,
            provider_spec,
        ),
        ParameterOutputFunction::DecryptMessageNext => backend.decrypt_message_next_exact_msg(
            session,
            msg_param,
            input_data,
            flags,
            output_spec,
            provider_spec,
        ),
        ParameterOutputFunction::SignMessageNext => Err(CkRv::FUNCTION_NOT_SUPPORTED),
        // Defensive: see `dispatch_message_oneshot` for rationale.
        _ => Err(pkcs11_proxy_ng_types::CkRv::FUNCTION_NOT_SUPPORTED),
    }
}

fn result_to_proto_msg(
    result: pkcs11_proxy_ng_types::CkResult<(
        pkcs11_proxy_ng_types::CkOutputBufferResult,
        pkcs11_proxy_ng_types::CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    )>,
) -> pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
    match result {
        Ok((output, parameter, msg_param)) => pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult::from(&output)),
            parameter_result: Some(pkcs11_proxy_ng_proto::ParameterRoundtripResult::from(
                &parameter,
            )),
            message_parameter_out: Some(pkcs11_proxy_ng_proto::MessageParameter::from(&msg_param)),
        },
        Err(error) => pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                ck_rv: error.0,
                returned_len: 0,
                value: None,
            }),
            parameter_result: Some(pkcs11_proxy_ng_proto::ParameterRoundtripResult {
                ck_rv: error.0,
                returned_len: 0,
                value: None,
            }),
            message_parameter_out: None,
        },
    }
}

fn result_to_proto(
    result: pkcs11_proxy_ng_types::CkResult<(
        pkcs11_proxy_ng_types::CkOutputBufferResult,
        pkcs11_proxy_ng_types::CkParameterRoundtripResult,
    )>,
) -> pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
    match result {
        Ok((output, param)) => pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult::from(&output)),
            parameter_result: Some(pkcs11_proxy_ng_proto::ParameterRoundtripResult::from(&param)),
            message_parameter_out: None,
        },
        Err(error) => pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                ck_rv: error.0,
                returned_len: 0,
                value: None,
            }),
            parameter_result: Some(pkcs11_proxy_ng_proto::ParameterRoundtripResult {
                ck_rv: error.0,
                returned_len: 0,
                value: None,
            }),
            message_parameter_out: None,
        },
    }
}

fn error_response(
    error: pkcs11_proxy_ng_types::CkRv,
) -> pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
    pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
        output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
            ck_rv: error.0,
            returned_len: 0,
            value: None,
        }),
        parameter_result: Some(pkcs11_proxy_ng_proto::ParameterRoundtripResult {
            ck_rv: error.0,
            returned_len: 0,
            value: None,
        }),
        message_parameter_out: None,
    }
}

#[cfg(test)]
mod ambiguity_tests {
    use super::*;
    use crate::server::context_manager::ContextManager;
    use crate::server::grpc_service::service_utils::{
        register_session_handle, register_session_object_handle,
    };
    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use pkcs11_proxy_ng_proto::convert::message_params::GcmMessageParams;
    use pkcs11_proxy_ng_types::{CkMechanismType, CkSessionFlags, CkSlotId};
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn missing_output_length_is_forwarded_to_parameter_output_backend_once() {
        let mock = Arc::new(MockBackend::default_test());
        mock.initialize().unwrap();
        let backend_session =
            mock.open_session(CkSlotId(0), CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).unwrap();
        let wrapping_key = mock.create_object(backend_session, &[]).unwrap();
        let key = mock.create_object(backend_session, &[]).unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        manager.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let context_id = manager.create_context(None).await.unwrap();
        let virtual_session = register_session_handle(
            &manager,
            &context_id,
            backend_session,
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
        )
        .await
        .unwrap();
        let virtual_session = VirtualHandle(virtual_session);
        let virtual_wrapping_key = register_session_object_handle(
            &manager,
            &context_id,
            virtual_session,
            wrapping_key,
            false,
        )
        .await;
        let virtual_key =
            register_session_object_handle(&manager, &context_id, virtual_session, key, false)
                .await;
        let before = mock.data_op_call_count();

        let response = parameter_output_exact(
            &HandlerContext::for_test(&manager, &backend),
            Request::new(pkcs11_proxy_ng_proto::ParameterOutputExactRequest {
                client_context_id: context_id.0.clone(),
                session_handle: virtual_session.0,
                function: pkcs11_proxy_ng_proto::convert::output::parameter_output_function_to_i32(
                    ParameterOutputFunction::WrapKeyAuthenticated,
                ),
                output_spec: Some(pkcs11_proxy_ng_proto::OutputBufferSpec {
                    buffer_present: true,
                    buffer_len: 0,
                    length_pointer_null: true,
                }),
                parameter_out_spec: Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                    buffer_present: false,
                    buffer_len: 0,
                    value: None,
                }),
                mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                    mechanism_type: CkMechanismType::RSA_PKCS.0,
                    params: None,
                }),
                wrapping_key_handle: virtual_wrapping_key,
                key_handle: virtual_key,
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .into_inner();

        let output = response.output_result.unwrap();
        assert_eq!(output.ck_rv, CkRv::ARGUMENTS_BAD.0);
        assert_eq!(output.returned_len, 0);
        assert_eq!(output.value, None);
        let parameter = response.parameter_result.unwrap();
        assert_eq!(parameter.ck_rv, CkRv::ARGUMENTS_BAD.0);
        assert_eq!(parameter.returned_len, 0);
        assert_eq!(parameter.value, None);
        assert_eq!(mock.data_op_call_count(), before + 1);
    }

    #[tokio::test]
    async fn malformed_post_provider_ack_returns_ambiguity_and_clears_server_shape() {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_GCM]));
        mock.initialize().unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        manager.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let context_id = manager.create_context(None).await.unwrap();
        let backend_session =
            mock.open_session(CkSlotId(0), CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).unwrap();
        let virtual_session = register_session_handle(
            &manager,
            &context_id,
            backend_session,
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
        )
        .await
        .unwrap();
        let operation = manager
            .message_operation_lock(
                &context_id,
                VirtualHandle(virtual_session),
                MessageOperation::Encrypt,
            )
            .await
            .unwrap();
        operation.lock().await.shape = Some(MessageParameterShape::Gcm);

        let parameter = MessageParameter::GcmMessage(GcmMessageParams {
            iv: vec![0x11; 12],
            iv_null_len: None,
            iv_fixed_bits: 96,
            iv_generator: 0,
            tag: vec![0; 16],
            tag_null_len: None,
            tag_bits: 128,
        });
        let provider_len = native_message_parameter_len(&parameter).unwrap();
        mock.set_next_message_parameter_ack(CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: provider_len + 1,
            value: Some(Vec::new()),
        });
        let calls_before = mock.message_parameter_call_count();
        let response = parameter_output_exact(
            &HandlerContext::for_test(&manager, &backend),
            Request::new(pkcs11_proxy_ng_proto::ParameterOutputExactRequest {
                client_context_id: context_id.0.clone(),
                session_handle: virtual_session,
                function: pkcs11_proxy_ng_proto::convert::output::parameter_output_function_to_i32(
                    ParameterOutputFunction::EncryptMessage,
                ),
                output_spec: Some(pkcs11_proxy_ng_proto::OutputBufferSpec {
                    buffer_present: true,
                    buffer_len: 8,
                    length_pointer_null: false,
                }),
                input_data: vec![0x22; 8],
                associated_data: Vec::new(),
                parameter: Vec::new(),
                parameter_out_spec: Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
                    buffer_present: true,
                    buffer_len: provider_len,
                    value: None,
                }),
                flags: 0,
                mechanism: None,
                wrapping_key_handle: 0,
                key_handle: 0,
                message_parameter: Some((&parameter).into()),
                input_data_null_len: None,
                associated_data_null_len: None,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(
            response.output_result.unwrap().ck_rv,
            CkRv::DEVICE_ERROR.0,
            "post-provider contract failure must be exposed as outcome ambiguity",
        );
        assert_eq!(mock.message_parameter_call_count(), calls_before + 1);
        assert_eq!(operation.lock().await.shape, None);
    }
}
