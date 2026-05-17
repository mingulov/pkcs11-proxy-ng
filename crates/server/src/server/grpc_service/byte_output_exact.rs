use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_proto::convert::output::byte_output_function_from_i32;
use pkcs11_proxy_ng_types::{
    ByteOutputFunction, CkOutputBufferResult, CkOutputBufferSpec, CkResult,
};

use super::super::context_manager::{ClientContextId, ContextManager};
use super::service_utils::{
    mechanism_output_to_proto, parse_mechanism, resolve_session, resolve_session_and_two_objects,
    spawn_backend,
};

pub(super) async fn byte_output_exact(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::ByteOutputExactRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::ByteOutputExactResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // Parse the function discriminator
    let function = match byte_output_function_from_i32(req.function) {
        Some(f) => f,
        None => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::ByteOutputExactResponse {
                result: None,
                mechanism_out: None,
            }));
        }
    };

    // Build the output buffer spec
    let spec = req
        .output_spec
        .as_ref()
        .map(|s| CkOutputBufferSpec { buffer_present: s.buffer_present, buffer_len: s.buffer_len })
        .unwrap_or(CkOutputBufferSpec { buffer_present: false, buffer_len: 0 });

    let input_data = req.input_data;

    match function {
        // Shape: (session, mechanism, wrapping_key, key, spec) -> wrap_key_exact
        ByteOutputFunction::WrapKey => {
            let mechanism = match parse_mechanism(req.mechanism) {
                Ok(m) => m,
                Err(error) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::ByteOutputExactResponse {
                        result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                            ck_rv: error.0,
                            returned_len: 0,
                            value: None,
                        }),
                        mechanism_out: None,
                    }));
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
                    return Ok(Response::new(pkcs11_proxy_ng_proto::ByteOutputExactResponse {
                        result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                            ck_rv: error.0,
                            returned_len: 0,
                            value: None,
                        }),
                        mechanism_out: None,
                    }));
                }
            };

            let backend = backend_ref.clone();
            let result = spawn_backend(move || {
                backend.wrap_key_exact_with_output(session, &mechanism, wrapping_key, key, &spec)
            })
            .await?;
            let (wrap_result, mechanism_out) = match result {
                Ok((output, mech_out)) => (Ok(output), mech_out),
                Err(error) => (Err(error), None),
            };

            Ok(Response::new(pkcs11_proxy_ng_proto::ByteOutputExactResponse {
                result: Some(result_to_proto(wrap_result)),
                mechanism_out: mechanism_out.and_then(mechanism_output_to_proto),
            }))
        }

        // Shape: (session, spec) -> *_final_exact / get_operation_state_exact
        ByteOutputFunction::SignFinal
        | ByteOutputFunction::DigestFinal
        | ByteOutputFunction::EncryptFinal
        | ByteOutputFunction::DecryptFinal
        | ByteOutputFunction::GetOperationState => {
            let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
                Ok(s) => s,
                Err(error) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::ByteOutputExactResponse {
                        result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                            ck_rv: error.0,
                            returned_len: 0,
                            value: None,
                        }),
                        mechanism_out: None,
                    }));
                }
            };

            let backend = backend_ref.clone();
            let result =
                spawn_backend(move || dispatch_session_only(function, &*backend, session, &spec))
                    .await?;

            Ok(Response::new(pkcs11_proxy_ng_proto::ByteOutputExactResponse {
                result: Some(result_to_proto(result)),
                mechanism_out: None,
            }))
        }

        // Shape: (session, data, spec) -> all remaining functions
        _ => {
            let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
                Ok(s) => s,
                Err(error) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::ByteOutputExactResponse {
                        result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                            ck_rv: error.0,
                            returned_len: 0,
                            value: None,
                        }),
                        mechanism_out: None,
                    }));
                }
            };

            let backend = backend_ref.clone();
            let (result, mechanism_out) = if function == ByteOutputFunction::Encrypt {
                let result = spawn_backend(move || {
                    backend.encrypt_exact_with_output(session, &input_data, &spec)
                })
                .await?;
                match result {
                    Ok((output, mechanism_out)) => (Ok(output), mechanism_out),
                    Err(error) => (Err(error), None),
                }
            } else {
                let result = spawn_backend(move || {
                    dispatch_session_data(function, &*backend, session, &input_data, &spec)
                })
                .await?;
                (result, None)
            };

            Ok(Response::new(pkcs11_proxy_ng_proto::ByteOutputExactResponse {
                result: Some(result_to_proto(result)),
                mechanism_out: mechanism_out.and_then(mechanism_output_to_proto),
            }))
        }
    }
}

fn dispatch_session_only(
    function: ByteOutputFunction,
    backend: &dyn Pkcs11Backend,
    session: pkcs11_proxy_ng_types::CkSessionHandle,
    spec: &CkOutputBufferSpec,
) -> pkcs11_proxy_ng_types::CkResult<pkcs11_proxy_ng_types::CkOutputBufferResult> {
    match function {
        ByteOutputFunction::SignFinal => backend.sign_final_exact(session, spec),
        ByteOutputFunction::DigestFinal => backend.digest_final_exact(session, spec),
        ByteOutputFunction::EncryptFinal => backend.encrypt_final_exact(session, spec),
        ByteOutputFunction::DecryptFinal => backend.decrypt_final_exact(session, spec),
        ByteOutputFunction::GetOperationState => backend.get_operation_state_exact(session, spec),
        _ => unreachable!("only session-only variants reach this function"),
    }
}

fn dispatch_session_data(
    function: ByteOutputFunction,
    backend: &dyn Pkcs11Backend,
    session: pkcs11_proxy_ng_types::CkSessionHandle,
    data: &[u8],
    spec: &CkOutputBufferSpec,
) -> pkcs11_proxy_ng_types::CkResult<pkcs11_proxy_ng_types::CkOutputBufferResult> {
    match function {
        ByteOutputFunction::Sign => backend.sign_exact(session, data, spec),
        ByteOutputFunction::SignRecover => backend.sign_recover_exact(session, data, spec),
        ByteOutputFunction::VerifyRecover => backend.verify_recover_exact(session, data, spec),
        ByteOutputFunction::Digest => backend.digest_exact(session, data, spec),
        ByteOutputFunction::Encrypt => backend.encrypt_exact(session, data, spec),
        ByteOutputFunction::EncryptUpdate => backend.encrypt_update_exact(session, data, spec),
        ByteOutputFunction::Decrypt => backend.decrypt_exact(session, data, spec),
        ByteOutputFunction::DecryptUpdate => backend.decrypt_update_exact(session, data, spec),
        ByteOutputFunction::DigestEncryptUpdate => {
            backend.digest_encrypt_update_exact(session, data, spec)
        }
        ByteOutputFunction::DecryptDigestUpdate => {
            backend.decrypt_digest_update_exact(session, data, spec)
        }
        ByteOutputFunction::SignEncryptUpdate => {
            backend.sign_encrypt_update_exact(session, data, spec)
        }
        ByteOutputFunction::DecryptVerifyUpdate => {
            backend.decrypt_verify_update_exact(session, data, spec)
        }
        _ => unreachable!("only session+data variants reach this function"),
    }
}

fn result_to_proto(
    result: CkResult<CkOutputBufferResult>,
) -> pkcs11_proxy_ng_proto::OutputBufferResult {
    match result {
        Ok(r) => pkcs11_proxy_ng_proto::OutputBufferResult::from(&r),
        Err(error) => pkcs11_proxy_ng_proto::OutputBufferResult {
            ck_rv: error.0,
            returned_len: 0,
            value: None,
        },
    }
}

// `mechanism_output_to_proto` has moved to `service_utils` so the
// simple Encrypt/Decrypt handlers can share the same conversion.
