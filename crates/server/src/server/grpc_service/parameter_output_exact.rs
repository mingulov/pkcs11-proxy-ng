use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_proto::convert::output::parameter_output_function_from_i32;
use pkcs11_proxy_ng_types::{
    CkFlags, CkOutputBufferSpec, CkParameterRoundtripSpec, ParameterOutputFunction,
};

use super::super::context_manager::{ClientContextId, ContextManager};
use super::service_utils::{
    parse_mechanism, resolve_session, resolve_session_and_two_objects, spawn_backend,
};

pub(super) async fn parameter_output_exact(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::ParameterOutputExactRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::ParameterOutputExactResponse>, Status> {
    let req = request.into_inner();
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

    // Build the output buffer spec
    let output_spec = req
        .output_spec
        .as_ref()
        .map(|s| CkOutputBufferSpec { buffer_present: s.buffer_present, buffer_len: s.buffer_len })
        .unwrap_or(CkOutputBufferSpec { buffer_present: false, buffer_len: 0 });

    // Build the parameter roundtrip spec
    let param_out_spec = req
        .parameter_out_spec
        .as_ref()
        .map(|s| CkParameterRoundtripSpec {
            buffer_present: s.buffer_present,
            buffer_len: s.buffer_len,
            value: s.value.clone(),
        })
        .unwrap_or(CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None });

    let input_data = req.input_data;
    let associated_data = req.associated_data;
    let parameter = req.parameter;
    let flags = CkFlags(req.flags);

    match function {
        ParameterOutputFunction::WrapKeyAuthenticated => {
            let mechanism = match parse_mechanism(req.mechanism) {
                Ok(m) => m,
                Err(error) => {
                    return Ok(Response::new(error_response(error)));
                }
            };

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
                Err(error) => {
                    return Ok(Response::new(error_response(error)));
                }
            };

            let backend = backend_ref.clone();
            let result = spawn_backend(move || {
                backend.wrap_key_authenticated_exact(
                    session,
                    &mechanism,
                    wrapping_key,
                    key,
                    &associated_data,
                    &output_spec,
                    &param_out_spec,
                )
            })
            .await?;

            Ok(Response::new(result_to_proto(result)))
        }

        // Message functions: (session, parameter, aad, data, output_spec, param_out_spec)
        ParameterOutputFunction::EncryptMessage
        | ParameterOutputFunction::DecryptMessage
        | ParameterOutputFunction::SignMessage => {
            let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
                Ok(s) => s,
                Err(error) => {
                    return Ok(Response::new(error_response(error)));
                }
            };

            // If a structured message_parameter is present, use the safe _msg path
            // that reconstructs the C struct with local pointers.
            let msg_param = req.message_parameter.as_ref().and_then(|mp| {
                pkcs11_proxy_ng_proto::convert::message_params::MessageParameter::try_from(mp).ok()
            });

            if let Some(mp) = msg_param {
                let backend = backend_ref.clone();
                let result = spawn_backend(move || {
                    dispatch_message_oneshot_msg(
                        function,
                        &*backend,
                        session,
                        &mp,
                        &associated_data,
                        &input_data,
                        &output_spec,
                    )
                })
                .await?;
                return Ok(Response::new(result_to_proto_msg(result)));
            }

            // Fallback: raw parameter bytes (legacy / non-struct parameters)
            let backend = backend_ref.clone();
            let result = spawn_backend(move || {
                dispatch_message_oneshot(
                    function,
                    &*backend,
                    session,
                    &parameter,
                    &associated_data,
                    &input_data,
                    &output_spec,
                    &param_out_spec,
                )
            })
            .await?;

            Ok(Response::new(result_to_proto(result)))
        }

        // Next functions: also take flags
        ParameterOutputFunction::EncryptMessageNext
        | ParameterOutputFunction::DecryptMessageNext
        | ParameterOutputFunction::SignMessageNext => {
            let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
                Ok(s) => s,
                Err(error) => {
                    return Ok(Response::new(error_response(error)));
                }
            };

            let msg_param = req.message_parameter.as_ref().and_then(|mp| {
                pkcs11_proxy_ng_proto::convert::message_params::MessageParameter::try_from(mp).ok()
            });

            if let Some(mp) = msg_param {
                let backend = backend_ref.clone();
                let result = spawn_backend(move || {
                    dispatch_message_next_msg(
                        function,
                        &*backend,
                        session,
                        &mp,
                        &input_data,
                        flags,
                        &output_spec,
                    )
                })
                .await?;
                return Ok(Response::new(result_to_proto_msg(result)));
            }

            let backend = backend_ref.clone();
            let result = spawn_backend(move || {
                dispatch_message_next(
                    function,
                    &*backend,
                    session,
                    &parameter,
                    &input_data,
                    flags,
                    &output_spec,
                    &param_out_spec,
                )
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
    associated_data: &[u8],
    input_data: &[u8],
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
        _ => unreachable!("only one-shot message variants reach this function"),
    }
}

fn dispatch_message_next(
    function: ParameterOutputFunction,
    backend: &dyn Pkcs11Backend,
    session: pkcs11_proxy_ng_types::CkSessionHandle,
    parameter: &[u8],
    input_data: &[u8],
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
        _ => unreachable!("only *_next variants reach this function"),
    }
}

fn dispatch_message_oneshot_msg(
    function: ParameterOutputFunction,
    backend: &dyn Pkcs11Backend,
    session: pkcs11_proxy_ng_types::CkSessionHandle,
    msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    associated_data: &[u8],
    input_data: &[u8],
    output_spec: &CkOutputBufferSpec,
) -> pkcs11_proxy_ng_types::CkResult<(
    pkcs11_proxy_ng_types::CkOutputBufferResult,
    pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
)> {
    match function {
        ParameterOutputFunction::EncryptMessage => backend.encrypt_message_exact_msg(
            session,
            msg_param,
            associated_data,
            input_data,
            output_spec,
        ),
        ParameterOutputFunction::DecryptMessage => backend.decrypt_message_exact_msg(
            session,
            msg_param,
            associated_data,
            input_data,
            output_spec,
        ),
        ParameterOutputFunction::SignMessage => {
            backend.sign_message_exact_msg(session, msg_param, input_data, output_spec)
        }
        _ => unreachable!("only one-shot message variants reach this function"),
    }
}

fn dispatch_message_next_msg(
    function: ParameterOutputFunction,
    backend: &dyn Pkcs11Backend,
    session: pkcs11_proxy_ng_types::CkSessionHandle,
    msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    input_data: &[u8],
    flags: CkFlags,
    output_spec: &CkOutputBufferSpec,
) -> pkcs11_proxy_ng_types::CkResult<(
    pkcs11_proxy_ng_types::CkOutputBufferResult,
    pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
)> {
    match function {
        ParameterOutputFunction::EncryptMessageNext => backend.encrypt_message_next_exact_msg(
            session,
            msg_param,
            input_data,
            flags,
            output_spec,
        ),
        ParameterOutputFunction::DecryptMessageNext => backend.decrypt_message_next_exact_msg(
            session,
            msg_param,
            input_data,
            flags,
            output_spec,
        ),
        ParameterOutputFunction::SignMessageNext => {
            backend.sign_message_next_exact_msg(session, msg_param, input_data, output_spec)
        }
        _ => unreachable!("only *_next variants reach this function"),
    }
}

fn result_to_proto_msg(
    result: pkcs11_proxy_ng_types::CkResult<(
        pkcs11_proxy_ng_types::CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    )>,
) -> pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
    match result {
        Ok((output, msg_param)) => pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult::from(&output)),
            parameter_result: Some(pkcs11_proxy_ng_proto::ParameterRoundtripResult {
                ck_rv: pkcs11_proxy_ng_types::CkRv::OK.0,
                returned_len: 0,
                value: None,
            }),
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
