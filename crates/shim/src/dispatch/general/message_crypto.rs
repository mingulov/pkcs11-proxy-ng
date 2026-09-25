use cryptoki_sys::*;
use pkcs11_proxy_ng_proto::convert::message_params::MessageParameter;
use pkcs11_proxy_ng_types::*;

use crate::state;

use super::helpers::*;

/// Read a message-based encrypt/decrypt init mechanism.
///
/// PKCS#11 v3.0 passes the AEAD parameters (`CK_GCM_MESSAGE_PARAMS`,
/// `CK_CCM_MESSAGE_PARAMS`, …) to `C_Message{Encrypt,Decrypt}Init` — but the
/// same mechanism type (`CKM_AES_GCM`, …) is also used by classic single-shot
/// encryption with a *different* parameter struct, so the param shape cannot be
/// inferred from the mechanism type via the registry. In the message-init path
/// we therefore interpret the params as the message variant: when a recognised
/// `CK_*_MESSAGE_PARAMS` struct is present we send the mechanism TYPE only plus
/// the structured `MessageParameter`, which the backend reconstructs into the
/// correct C struct. A NULL mechanism is the cancel path; a parameterless or
/// unrecognised param falls back to the classic `read_mechanism` behaviour.
///
/// Returns the mechanism (None = cancel) and the optional structured init param,
/// or a `CK_RV` to return directly.
///
/// # Safety
/// `p_mechanism` is either NULL or a valid `CK_MECHANISM`.
unsafe fn read_message_init_mechanism(
    p_mechanism: CK_MECHANISM_PTR,
) -> Result<(Option<CkMechanism>, Option<MessageParameter>), CK_RV> {
    if p_mechanism.is_null() {
        return Ok((None, None)); // cancel path
    }
    let rv = unsafe { validate_mechanism(p_mechanism) };
    if rv != rv_ok() {
        return Err(rv);
    }
    let c_mech = unsafe { &*p_mechanism };
    let msg_param =
        unsafe { try_read_message_parameter(c_mech.pParameter as *const _, c_mech.ulParameterLen) }
            .map_err(rv_err)?;
    match msg_param {
        // Recognised AEAD message params: ship the mechanism type only and let
        // the backend rebuild the CK_*_MESSAGE_PARAMS struct from this.
        Some(mp) if !matches!(mp, MessageParameter::Raw(_)) => Ok((
            Some(CkMechanism { mechanism_type: CkMechanismType(c_mech.mechanism), params: None }),
            Some(mp),
        )),
        // Parameterless / unrecognised: preserve the classic shim behaviour.
        _ => Ok((Some(unsafe { read_mechanism(p_mechanism) }), None)),
    }
}

// ---------------------------------------------------------------------------
// C_MessageEncryptInit — mechanism is nullable (NULL = cancel active state)
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_message_encrypt_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panics(|| {
        let (mech, init_param) = match unsafe { read_message_init_mechanism(p_mechanism) } {
            Ok(parts) => parts,
            Err(rv) => return rv,
        };
        let result = with_client!(client => client.message_encrypt_init(
            CkSessionHandle(h_session),
            mech.as_ref(),
            init_param.as_ref(),
            CkObjectHandle(h_key),
        ));
        if result.is_ok() {
            state::clear_message_encrypt_output_cache(h_session);
            state::clear_operation_state_cache(h_session);
        }
        unit_result_to_rv(result)
    })
}

// ---------------------------------------------------------------------------
// C_MessageEncryptFinal — session-only cleanup
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_message_encrypt_final(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Encrypt);
        let mut operation = operation.lock().expect("message encrypt state poisoned");
        if operation.shape.is_none() {
            return rv_err(CkRv::OPERATION_NOT_INITIALIZED);
        }
        let saved_shape = operation.shape.take();
        match with_client!(client => client.message_encrypt_final_stateful(CkSessionHandle(h_session as u64)))
        {
            Ok(()) => {
                state::clear_message_encrypt_output_cache(h_session);
                state::clear_operation_state_cache(h_session);
                rv_ok()
            }
            Err(error) => {
                if error.origin == MessageCallErrorOrigin::Backend
                    && error.ck_rv != CkRv::DEVICE_ERROR
                {
                    operation.shape = saved_shape;
                }
                rv_err(error.ck_rv)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// C_MessageDecryptInit — mechanism is nullable (NULL = cancel active state)
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_message_decrypt_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panics(|| {
        let (mech, init_param) = match unsafe { read_message_init_mechanism(p_mechanism) } {
            Ok(parts) => parts,
            Err(rv) => return rv,
        };
        let result = with_client!(client => client.message_decrypt_init(
            CkSessionHandle(h_session),
            mech.as_ref(),
            init_param.as_ref(),
            CkObjectHandle(h_key),
        ));
        if result.is_ok() {
            state::clear_message_decrypt_output_cache(h_session);
            state::clear_operation_state_cache(h_session);
        }
        unit_result_to_rv(result)
    })
}

// ---------------------------------------------------------------------------
// C_MessageDecryptFinal — session-only cleanup
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_message_decrypt_final(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Decrypt);
        let mut operation = operation.lock().expect("message decrypt state poisoned");
        if operation.shape.is_none() {
            return rv_err(CkRv::OPERATION_NOT_INITIALIZED);
        }
        let saved_shape = operation.shape.take();
        match with_client!(client => client.message_decrypt_final_stateful(CkSessionHandle(h_session as u64)))
        {
            Ok(()) => {
                state::clear_message_decrypt_output_cache(h_session);
                state::clear_operation_state_cache(h_session);
                rv_ok()
            }
            Err(error) => rv_err(settle_message_init_error(&mut operation, saved_shape, &error)),
        }
    })
}

// ---------------------------------------------------------------------------
// C_MessageSignInit — mechanism is nullable (NULL = cancel active state)
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_message_sign_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Sign);
        let mut operation = operation.lock().expect("message sign state poisoned");
        let mech = if p_mechanism.is_null() {
            None // cancel path
        } else {
            let rv = unsafe { validate_mechanism(p_mechanism) };
            if rv != rv_ok() {
                return rv;
            }
            Some(unsafe { read_mechanism(p_mechanism) })
        };
        let successful_shape = mech.as_ref().map(|_| MessageParameterShape::Unmodeled);
        let saved_shape = operation.shape.take();
        let result = with_client!(client => client.message_sign_init_stateful(
            CkSessionHandle(h_session as u64),
            mech.as_ref(),
            CkObjectHandle(h_key as u64),
        ));
        match result {
            Ok(()) => {
                operation.shape = successful_shape;
                state::clear_message_sign_output_cache(h_session);
                state::clear_operation_state_cache(h_session);
                rv_ok()
            }
            Err(error) => rv_err(settle_message_init_error(&mut operation, saved_shape, &error)),
        }
    })
}

// ---------------------------------------------------------------------------
// C_MessageSignFinal — session-only cleanup
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_message_sign_final(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Sign);
        let mut operation = operation.lock().expect("message sign state poisoned");
        if operation.shape.is_none() {
            return rv_err(CkRv::OPERATION_NOT_INITIALIZED);
        }
        let saved_shape = operation.shape.take();
        match with_client!(client => client.message_sign_final_stateful(CkSessionHandle(h_session as u64)))
        {
            Ok(()) => rv_ok(),
            Err(error) => {
                if error.origin == MessageCallErrorOrigin::Backend
                    && error.ck_rv != CkRv::DEVICE_ERROR
                {
                    operation.shape = saved_shape;
                }
                rv_err(error.ck_rv)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// C_MessageVerifyInit — mechanism is nullable (NULL = cancel active state)
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_message_verify_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Verify);
        let mut operation = operation.lock().expect("message verify state poisoned");
        let mech = if p_mechanism.is_null() {
            None // cancel path
        } else {
            let rv = unsafe { validate_mechanism(p_mechanism) };
            if rv != rv_ok() {
                return rv;
            }
            Some(unsafe { read_mechanism(p_mechanism) })
        };
        let successful_shape = mech.as_ref().map(|_| MessageParameterShape::Unmodeled);
        let saved_shape = operation.shape.take();
        match with_client!(client => client.message_verify_init_stateful(
            CkSessionHandle(h_session as u64),
            mech.as_ref(),
            CkObjectHandle(h_key as u64),
        )) {
            Ok(()) => {
                operation.shape = successful_shape;
                state::clear_operation_state_cache(h_session);
                rv_ok()
            }
            Err(error) => {
                if error.origin == MessageCallErrorOrigin::Backend
                    && error.ck_rv != CkRv::DEVICE_ERROR
                {
                    operation.shape = saved_shape;
                }
                rv_err(error.ck_rv)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// C_MessageVerifyFinal — session-only cleanup
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_message_verify_final(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Verify);
        let mut operation = operation.lock().expect("message verify state poisoned");
        if operation.shape.is_none() {
            return rv_err(CkRv::OPERATION_NOT_INITIALIZED);
        }
        let saved_shape = operation.shape.take();
        match with_client!(client => client.message_verify_final_stateful(CkSessionHandle(h_session as u64)))
        {
            Ok(()) => rv_ok(),
            Err(error) => {
                if error.origin == MessageCallErrorOrigin::Backend
                    && error.ck_rv != CkRv::DEVICE_ERROR
                {
                    operation.shape = saved_shape;
                }
                rv_err(error.ck_rv)
            }
        }
    })
}

// ===========================================================================
// One-shot / Begin / Next dispatch functions
// ===========================================================================

// ---------------------------------------------------------------------------
// C_EncryptMessage — one-shot encrypt
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_encrypt_message(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
    p_associated_data: *mut CK_BYTE,
    ul_associated_data_len: CK_ULONG,
    p_plaintext: *mut CK_BYTE,
    ul_plaintext_len: CK_ULONG,
    p_ciphertext: *mut CK_BYTE,
    pul_ciphertext_len: *mut CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Encrypt);
        let mut operation = operation.lock().expect("message encrypt state poisoned");
        let shape = match operation.shape {
            Some(shape) => shape,
            None => return rv_err(CkRv::OPERATION_NOT_INITIALIZED),
        };
        let aad = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_associated_data, ul_associated_data_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        let plaintext = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_plaintext, ul_plaintext_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        let output_spec = unsafe { output_buffer_spec(p_ciphertext, pul_ciphertext_len) };
        let param_out_spec =
            match unsafe { message_parameter_roundtrip_spec(p_parameter, ul_parameter_len) } {
                Ok(spec) => spec,
                Err(error) => return rv_err(error),
            };
        let parameter_call = match unsafe {
            read_message_parameter_call_for_shape_with_memory(
                p_parameter.cast_const(),
                ul_parameter_len,
                shape,
                MessageParameterDirection::Encrypt,
                MessageParameterStage::OneShot,
                MessageCallMemory::output(
                    p_associated_data,
                    ul_associated_data_len,
                    p_plaintext,
                    ul_plaintext_len,
                    p_ciphertext,
                    output_spec.buffer_len,
                    pul_ciphertext_len,
                ),
            )
        } {
            Ok(call) => call,
            Err(error) => return rv_err(error),
        };
        let result = with_client!(client => client.parameter_output_exact_contract(
            CkSessionHandle(h_session as u64),
            ParameterOutputFunction::EncryptMessage,
            &output_spec,
            plaintext,
            aad,
            &[],
            &param_out_spec,
            0,
            None,
            0,
            0,
            parameter_call.parameter(),
        ));

        match result {
            Ok((output_result, param_result, msg_param_out)) => {
                let rv = unsafe {
                    write_exact_message_output(
                        &output_spec,
                        &param_out_spec,
                        &parameter_call,
                        &output_result,
                        &param_result,
                        msg_param_out.as_ref(),
                        p_ciphertext,
                        pul_ciphertext_len,
                    )
                };
                if output_result.ck_rv == CkRv::DEVICE_ERROR || rv != rv_err(output_result.ck_rv) {
                    operation.shape = None;
                }
                rv
            }
            Err(error) => {
                if error.origin != MessageCallErrorOrigin::Backend
                    || error.ck_rv == CkRv::DEVICE_ERROR
                {
                    operation.shape = None;
                }
                rv_err(error.ck_rv)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// C_EncryptMessageBegin — returns parameter_out only (no output buffer)
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_encrypt_message_begin(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
    p_associated_data: *mut CK_BYTE,
    ul_associated_data_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Encrypt);
        let mut operation = operation.lock().expect("message encrypt state poisoned");
        let shape = match operation.shape {
            Some(shape) => shape,
            None => return rv_err(CkRv::OPERATION_NOT_INITIALIZED),
        };
        let aad = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_associated_data, ul_associated_data_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        let envelope =
            match unsafe { message_parameter_roundtrip_spec(p_parameter, ul_parameter_len) } {
                Ok(spec) => spec,
                Err(error) => return rv_err(error),
            };
        let parameter_call = match unsafe {
            read_message_parameter_call_for_shape_with_memory(
                p_parameter.cast_const(),
                ul_parameter_len,
                shape,
                MessageParameterDirection::Encrypt,
                MessageParameterStage::Begin,
                MessageCallMemory::begin(p_associated_data, ul_associated_data_len),
            )
        } {
            Ok(call) => call,
            Err(error) => return rv_err(error),
        };

        let result = with_client!(client => client.encrypt_message_begin_contract(
            CkSessionHandle(h_session as u64),
            &envelope,
            parameter_call.parameter(),
            aad,
        ));

        match result {
            Ok((parameter_result, response_parameter)) => {
                let rv = unsafe {
                    write_message_begin_output(
                        &envelope,
                        &parameter_call,
                        &parameter_result,
                        response_parameter.as_ref(),
                    )
                };
                if parameter_result.ck_rv == CkRv::DEVICE_ERROR
                    || rv != rv_err(parameter_result.ck_rv)
                {
                    operation.shape = None;
                }
                rv
            }
            Err(error) => {
                if error.origin != MessageCallErrorOrigin::Backend
                    || error.ck_rv == CkRv::DEVICE_ERROR
                {
                    operation.shape = None;
                }
                rv_err(error.ck_rv)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// C_EncryptMessageNext — returns parameter_out + ciphertext_part
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_encrypt_message_next(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
    p_plaintext_part: *mut CK_BYTE,
    ul_plaintext_part_len: CK_ULONG,
    p_ciphertext_part: *mut CK_BYTE,
    pul_ciphertext_part_len: *mut CK_ULONG,
    flags: CK_FLAGS,
) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Encrypt);
        let mut operation = operation.lock().expect("message encrypt state poisoned");
        let shape = match operation.shape {
            Some(shape) => shape,
            None => return rv_err(CkRv::OPERATION_NOT_INITIALIZED),
        };
        let plaintext_part = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_plaintext_part, ul_plaintext_part_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        let output_spec = unsafe { output_buffer_spec(p_ciphertext_part, pul_ciphertext_part_len) };
        let param_out_spec =
            match unsafe { message_parameter_roundtrip_spec(p_parameter, ul_parameter_len) } {
                Ok(spec) => spec,
                Err(error) => return rv_err(error),
            };
        let parameter_call = match unsafe {
            read_message_parameter_call_for_shape_with_memory(
                p_parameter.cast_const(),
                ul_parameter_len,
                shape,
                MessageParameterDirection::Encrypt,
                MessageParameterStage::Next { final_part: flags & CKF_END_OF_MESSAGE != 0 },
                MessageCallMemory::output(
                    std::ptr::null(),
                    0,
                    p_plaintext_part,
                    ul_plaintext_part_len,
                    p_ciphertext_part,
                    output_spec.buffer_len,
                    pul_ciphertext_part_len,
                ),
            )
        } {
            Ok(call) => call,
            Err(error) => return rv_err(error),
        };
        let result = with_client!(client => client.parameter_output_exact_contract(
            CkSessionHandle(h_session as u64),
            ParameterOutputFunction::EncryptMessageNext,
            &output_spec,
            plaintext_part,
            CkInBuf::Bytes(&[]),
            &[],
            &param_out_spec,
            flags.into(),
            None,
            0,
            0,
            parameter_call.parameter(),
        ));

        match result {
            Ok((output_result, param_result, msg_param_out)) => {
                let rv = unsafe {
                    write_exact_message_output(
                        &output_spec,
                        &param_out_spec,
                        &parameter_call,
                        &output_result,
                        &param_result,
                        msg_param_out.as_ref(),
                        p_ciphertext_part,
                        pul_ciphertext_part_len,
                    )
                };
                if output_result.ck_rv == CkRv::DEVICE_ERROR || rv != rv_err(output_result.ck_rv) {
                    operation.shape = None;
                }
                rv
            }
            Err(error) => {
                if error.origin != MessageCallErrorOrigin::Backend
                    || error.ck_rv == CkRv::DEVICE_ERROR
                {
                    operation.shape = None;
                }
                rv_err(error.ck_rv)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// C_DecryptMessage — one-shot decrypt
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_decrypt_message(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
    p_associated_data: *mut CK_BYTE,
    ul_associated_data_len: CK_ULONG,
    p_ciphertext: *mut CK_BYTE,
    ul_ciphertext_len: CK_ULONG,
    p_plaintext: *mut CK_BYTE,
    pul_plaintext_len: *mut CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Decrypt);
        let mut operation = operation.lock().expect("message decrypt state poisoned");
        let shape = match operation.shape {
            Some(shape) => shape,
            None => return rv_err(CkRv::OPERATION_NOT_INITIALIZED),
        };
        let aad = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_associated_data, ul_associated_data_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        let ciphertext = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_ciphertext, ul_ciphertext_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        let output_spec = unsafe { output_buffer_spec(p_plaintext, pul_plaintext_len) };
        let param_out_spec =
            match unsafe { message_parameter_roundtrip_spec(p_parameter, ul_parameter_len) } {
                Ok(spec) => spec,
                Err(error) => return rv_err(error),
            };
        let parameter_call = match unsafe {
            read_message_parameter_call_for_shape_with_memory(
                p_parameter.cast_const(),
                ul_parameter_len,
                shape,
                MessageParameterDirection::Decrypt,
                MessageParameterStage::OneShot,
                MessageCallMemory::output(
                    p_associated_data,
                    ul_associated_data_len,
                    p_ciphertext,
                    ul_ciphertext_len,
                    p_plaintext,
                    output_spec.buffer_len,
                    pul_plaintext_len,
                ),
            )
        } {
            Ok(call) => call,
            Err(error) => return rv_err(error),
        };
        let result = with_client!(client => client.parameter_output_exact_contract(
            CkSessionHandle(h_session as u64),
            ParameterOutputFunction::DecryptMessage,
            &output_spec,
            ciphertext,
            aad,
            &[],
            &param_out_spec,
            0,
            None,
            0,
            0,
            parameter_call.parameter(),
        ));

        match result {
            Ok((output_result, param_result, msg_param_out)) => {
                let rv = unsafe {
                    write_exact_message_output(
                        &output_spec,
                        &param_out_spec,
                        &parameter_call,
                        &output_result,
                        &param_result,
                        msg_param_out.as_ref(),
                        p_plaintext,
                        pul_plaintext_len,
                    )
                };
                if output_result.ck_rv == CkRv::DEVICE_ERROR || rv != rv_err(output_result.ck_rv) {
                    operation.shape = None;
                }
                rv
            }
            Err(error) => {
                if error.origin != MessageCallErrorOrigin::Backend
                    || error.ck_rv == CkRv::DEVICE_ERROR
                {
                    operation.shape = None;
                }
                rv_err(error.ck_rv)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// C_DecryptMessageBegin — returns parameter_out only
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_decrypt_message_begin(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
    p_associated_data: *mut CK_BYTE,
    ul_associated_data_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Decrypt);
        let mut operation = operation.lock().expect("message decrypt state poisoned");
        let shape = match operation.shape {
            Some(shape) => shape,
            None => return rv_err(CkRv::OPERATION_NOT_INITIALIZED),
        };
        let aad = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_associated_data, ul_associated_data_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        let envelope =
            match unsafe { message_parameter_roundtrip_spec(p_parameter, ul_parameter_len) } {
                Ok(spec) => spec,
                Err(error) => return rv_err(error),
            };
        let parameter_call = match unsafe {
            read_message_parameter_call_for_shape_with_memory(
                p_parameter.cast_const(),
                ul_parameter_len,
                shape,
                MessageParameterDirection::Decrypt,
                MessageParameterStage::Begin,
                MessageCallMemory::begin(p_associated_data, ul_associated_data_len),
            )
        } {
            Ok(call) => call,
            Err(error) => return rv_err(error),
        };

        let result = with_client!(client => client.decrypt_message_begin_contract(
            CkSessionHandle(h_session as u64),
            &envelope,
            parameter_call.parameter(),
            aad,
        ));

        match result {
            Ok((parameter_result, response_parameter)) => {
                let rv = unsafe {
                    write_message_begin_output(
                        &envelope,
                        &parameter_call,
                        &parameter_result,
                        response_parameter.as_ref(),
                    )
                };
                if parameter_result.ck_rv == CkRv::DEVICE_ERROR
                    || rv != rv_err(parameter_result.ck_rv)
                {
                    operation.shape = None;
                }
                rv
            }
            Err(error) => {
                if error.origin != MessageCallErrorOrigin::Backend
                    || error.ck_rv == CkRv::DEVICE_ERROR
                {
                    operation.shape = None;
                }
                rv_err(error.ck_rv)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// C_DecryptMessageNext — returns parameter_out + plaintext_part
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_decrypt_message_next(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
    p_ciphertext_part: *mut CK_BYTE,
    ul_ciphertext_part_len: CK_ULONG,
    p_plaintext_part: *mut CK_BYTE,
    pul_plaintext_part_len: *mut CK_ULONG,
    flags: CK_FLAGS,
) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Decrypt);
        let mut operation = operation.lock().expect("message decrypt state poisoned");
        let shape = match operation.shape {
            Some(shape) => shape,
            None => return rv_err(CkRv::OPERATION_NOT_INITIALIZED),
        };
        let ciphertext_part = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_ciphertext_part, ul_ciphertext_part_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        let output_spec = unsafe { output_buffer_spec(p_plaintext_part, pul_plaintext_part_len) };
        let param_out_spec =
            match unsafe { message_parameter_roundtrip_spec(p_parameter, ul_parameter_len) } {
                Ok(spec) => spec,
                Err(error) => return rv_err(error),
            };
        let parameter_call = match unsafe {
            read_message_parameter_call_for_shape_with_memory(
                p_parameter.cast_const(),
                ul_parameter_len,
                shape,
                MessageParameterDirection::Decrypt,
                MessageParameterStage::Next { final_part: flags & CKF_END_OF_MESSAGE != 0 },
                MessageCallMemory::output(
                    std::ptr::null(),
                    0,
                    p_ciphertext_part,
                    ul_ciphertext_part_len,
                    p_plaintext_part,
                    output_spec.buffer_len,
                    pul_plaintext_part_len,
                ),
            )
        } {
            Ok(call) => call,
            Err(error) => return rv_err(error),
        };
        let result = with_client!(client => client.parameter_output_exact_contract(
            CkSessionHandle(h_session as u64),
            ParameterOutputFunction::DecryptMessageNext,
            &output_spec,
            ciphertext_part,
            CkInBuf::Bytes(&[]),
            &[],
            &param_out_spec,
            flags.into(),
            None,
            0,
            0,
            parameter_call.parameter(),
        ));

        match result {
            Ok((output_result, param_result, msg_param_out)) => {
                let rv = unsafe {
                    write_exact_message_output(
                        &output_spec,
                        &param_out_spec,
                        &parameter_call,
                        &output_result,
                        &param_result,
                        msg_param_out.as_ref(),
                        p_plaintext_part,
                        pul_plaintext_part_len,
                    )
                };
                if output_result.ck_rv == CkRv::DEVICE_ERROR || rv != rv_err(output_result.ck_rv) {
                    operation.shape = None;
                }
                rv
            }
            Err(error) => {
                if error.origin != MessageCallErrorOrigin::Backend
                    || error.ck_rv == CkRv::DEVICE_ERROR
                {
                    operation.shape = None;
                }
                rv_err(error.ck_rv)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// C_SignMessage — one-shot sign
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_sign_message(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
    p_data: *mut CK_BYTE,
    ul_data_len: CK_ULONG,
    p_signature: *mut CK_BYTE,
    pul_signature_len: *mut CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Sign);
        let mut operation = operation.lock().expect("message sign state poisoned");
        if operation.shape.is_none() {
            return rv_err(CkRv::OPERATION_NOT_INITIALIZED);
        }
        let param_out_spec = match unsafe {
            empty_message_parameter_roundtrip_spec(p_parameter, ul_parameter_len)
        } {
            Ok(spec) => spec,
            Err(error) => return rv_err(error),
        };
        let data = match input_buf_to_ck_in_buf(unsafe { classify_input(p_data, ul_data_len) }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        let output_spec = unsafe { output_buffer_spec(p_signature, pul_signature_len) };
        let parameter_call = empty_message_parameter_call(
            MessageParameterDirection::Encrypt,
            MessageParameterStage::OneShot,
        );

        let result = with_client!(client => client.parameter_output_exact_contract(
            CkSessionHandle(h_session as u64),
            ParameterOutputFunction::SignMessage,
            &output_spec,
            data,
            CkInBuf::Bytes(&[]),
            &[],
            &param_out_spec,
            0,
            None,
            0,
            0,
            None,
        ));

        match result {
            Ok((output_result, param_result, msg_param_out)) => {
                let rv = unsafe {
                    write_exact_message_output(
                        &output_spec,
                        &param_out_spec,
                        &parameter_call,
                        &output_result,
                        &param_result,
                        msg_param_out.as_ref(),
                        p_signature,
                        pul_signature_len,
                    )
                };
                if output_result.ck_rv == CkRv::DEVICE_ERROR || rv != rv_err(output_result.ck_rv) {
                    operation.shape = None;
                }
                rv
            }
            Err(error) => {
                if error.origin != MessageCallErrorOrigin::Backend
                    || error.ck_rv == CkRv::DEVICE_ERROR
                {
                    operation.shape = None;
                }
                rv_err(error.ck_rv)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// C_SignMessageBegin — returns parameter_out only
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_sign_message_begin(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Sign);
        let mut operation = operation.lock().expect("message sign state poisoned");
        if operation.shape.is_none() {
            return rv_err(CkRv::OPERATION_NOT_INITIALIZED);
        }
        let envelope = match unsafe {
            empty_message_parameter_roundtrip_spec(p_parameter, ul_parameter_len)
        } {
            Ok(spec) => spec,
            Err(error) => return rv_err(error),
        };
        let parameter_call = empty_message_parameter_call(
            MessageParameterDirection::Encrypt,
            MessageParameterStage::Begin,
        );

        let result = with_client!(client => client.sign_message_begin_contract(
            CkSessionHandle(h_session as u64),
            &envelope,
        ));

        match result {
            Ok(parameter_result) => {
                let rv = unsafe {
                    write_message_begin_output(&envelope, &parameter_call, &parameter_result, None)
                };
                if rv != rv_ok() {
                    operation.shape = None;
                }
                rv
            }
            Err(error) => {
                if error.origin != MessageCallErrorOrigin::Backend
                    || error.ck_rv == CkRv::DEVICE_ERROR
                {
                    operation.shape = None;
                }
                rv_err(error.ck_rv)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// C_SignMessageNext — returns parameter_out + signature
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_sign_message_next(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
    p_data_part: *mut CK_BYTE,
    ul_data_part_len: CK_ULONG,
    p_signature: *mut CK_BYTE,
    pul_signature_len: *mut CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Sign);
        let mut operation = operation.lock().expect("message sign state poisoned");
        if operation.shape.is_none() {
            return rv_err(CkRv::OPERATION_NOT_INITIALIZED);
        }
        let envelope = match unsafe {
            empty_message_parameter_roundtrip_spec(p_parameter, ul_parameter_len)
        } {
            Ok(spec) => spec,
            Err(error) => return rv_err(error),
        };
        let data_part = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_data_part, ul_data_part_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };

        // If pul_signature_len is NULL => "more data" mode, request_signature = false
        let request_signature = !pul_signature_len.is_null();

        if !request_signature {
            let result = with_client!(client => client.sign_message_next_feed_contract(
                CkSessionHandle(h_session as u64),
                &envelope,
                data_part,
            ));

            return match result {
                Ok(parameter_result) => {
                    let parameter_call = empty_message_parameter_call(
                        MessageParameterDirection::Encrypt,
                        MessageParameterStage::Next { final_part: false },
                    );
                    let rv = unsafe {
                        write_message_begin_output(
                            &envelope,
                            &parameter_call,
                            &parameter_result,
                            None,
                        )
                    };
                    if rv != rv_ok() {
                        operation.shape = None;
                    }
                    rv
                }
                Err(error) => {
                    if error.origin != MessageCallErrorOrigin::Backend
                        || error.ck_rv == CkRv::DEVICE_ERROR
                    {
                        operation.shape = None;
                    }
                    rv_err(error.ck_rv)
                }
            };
        }

        // Final call: request_signature = true, use exact output path
        let output_spec = unsafe { output_buffer_spec(p_signature, pul_signature_len) };
        let parameter_call = empty_message_parameter_call(
            MessageParameterDirection::Encrypt,
            MessageParameterStage::Next { final_part: true },
        );

        let result = with_client!(client => client.parameter_output_exact_contract(
            CkSessionHandle(h_session as u64),
            ParameterOutputFunction::SignMessageNext,
            &output_spec,
            data_part,
            CkInBuf::Bytes(&[]),
            &[],
            &envelope,
            0,
            None,
            0,
            0,
            None,
        ));

        match result {
            Ok((output_result, parameter_result, msg_param_out)) => {
                let rv = unsafe {
                    write_exact_message_output(
                        &output_spec,
                        &envelope,
                        &parameter_call,
                        &output_result,
                        &parameter_result,
                        msg_param_out.as_ref(),
                        p_signature,
                        pul_signature_len,
                    )
                };
                if output_result.ck_rv == CkRv::DEVICE_ERROR || rv != rv_err(output_result.ck_rv) {
                    operation.shape = None;
                }
                rv
            }
            Err(error) => {
                if error.origin != MessageCallErrorOrigin::Backend
                    || error.ck_rv == CkRv::DEVICE_ERROR
                {
                    operation.shape = None;
                }
                rv_err(error.ck_rv)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// C_VerifyMessage — no output buffer, parameter is input-only
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_verify_message(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
    p_data: *mut CK_BYTE,
    ul_data_len: CK_ULONG,
    p_signature: *mut CK_BYTE,
    ul_signature_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Verify);
        let mut operation = operation.lock().expect("message verify state poisoned");
        if operation.shape.is_none() {
            return rv_err(CkRv::OPERATION_NOT_INITIALIZED);
        }
        let envelope = match unsafe {
            empty_message_parameter_roundtrip_spec(p_parameter, ul_parameter_len)
        } {
            Ok(spec) => spec,
            Err(error) => return rv_err(error),
        };
        let data = match input_buf_to_ck_in_buf(unsafe { classify_input(p_data, ul_data_len) }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        let signature = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_signature, ul_signature_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };

        match with_client!(client => client.verify_message_contract(
            CkSessionHandle(h_session as u64),
            &envelope,
            data,
            signature,
        )) {
            Ok(_) => rv_ok(),
            Err(error) => {
                if error.origin != MessageCallErrorOrigin::Backend
                    || error.ck_rv == CkRv::DEVICE_ERROR
                {
                    operation.shape = None;
                }
                rv_err(error.ck_rv)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// C_VerifyMessageBegin — no output, parameter is input-only
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_verify_message_begin(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Verify);
        let mut operation = operation.lock().expect("message verify state poisoned");
        if operation.shape.is_none() {
            return rv_err(CkRv::OPERATION_NOT_INITIALIZED);
        }
        let envelope = match unsafe {
            empty_message_parameter_roundtrip_spec(p_parameter, ul_parameter_len)
        } {
            Ok(spec) => spec,
            Err(error) => return rv_err(error),
        };

        match with_client!(client => client.verify_message_begin_contract(
            CkSessionHandle(h_session as u64),
            &envelope,
        )) {
            Ok(_) => rv_ok(),
            Err(error) => {
                if error.origin != MessageCallErrorOrigin::Backend
                    || error.ck_rv == CkRv::DEVICE_ERROR
                {
                    operation.shape = None;
                }
                rv_err(error.ck_rv)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// C_VerifyMessageNext — no output buffer
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_verify_message_next(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *mut ::std::os::raw::c_void,
    ul_parameter_len: CK_ULONG,
    p_data_part: *mut CK_BYTE,
    ul_data_part_len: CK_ULONG,
    p_signature: *mut CK_BYTE,
    ul_signature_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        if let Some(rv) = pointer_safe_message_capability_error() {
            return rv;
        }
        let operation = state::message_operation_state(h_session, state::MessageOperation::Verify);
        let mut operation = operation.lock().expect("message verify state poisoned");
        if operation.shape.is_none() {
            return rv_err(CkRv::OPERATION_NOT_INITIALIZED);
        }
        let envelope = match unsafe {
            empty_message_parameter_roundtrip_spec(p_parameter, ul_parameter_len)
        } {
            Ok(spec) => spec,
            Err(error) => return rv_err(error),
        };
        let data_part = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_data_part, ul_data_part_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };

        // If pSignature is NULL, this is a "feed more data" call (is_final = false)
        let is_final = !p_signature.is_null();
        let signature = if is_final {
            match input_buf_to_ck_in_buf(unsafe { classify_input(p_signature, ul_signature_len) }) {
                Ok(buf) => buf,
                Err(e) => return rv_err(e),
            }
        } else {
            CkInBuf::Bytes(&[])
        };

        match with_client!(client => client.verify_message_next_contract(
            CkSessionHandle(h_session as u64),
            &envelope,
            data_part,
            is_final,
            signature,
        )) {
            Ok(_) => rv_ok(),
            Err(error) => {
                if error.origin != MessageCallErrorOrigin::Backend
                    || error.ck_rv == CkRv::DEVICE_ERROR
                {
                    operation.shape = None;
                }
                rv_err(error.ck_rv)
            }
        }
    })
}

#[cfg(test)]
mod init_ack_state_tests {
    use super::*;
    use pkcs11_proxy_ng_client::MessageCallError;

    #[test]
    fn byte_mutated_init_ack_protocol_error_clears_shape_without_caller_writes() {
        let mut operation = state::MessageOperationState::default();
        let saved_shape = Some(MessageParameterShape::Gcm);
        let iv = [0x11_u8; 12];
        let tag = [0xA5_u8; 16];
        let error = MessageCallError {
            ck_rv: CkRv::FUNCTION_NOT_SUPPORTED,
            origin: MessageCallErrorOrigin::Protocol,
        };

        let rv = settle_message_init_error(&mut operation, saved_shape, &error);

        assert_eq!(rv, CkRv::FUNCTION_NOT_SUPPORTED);
        assert_eq!(operation.shape, None, "protocol ambiguity must not restore the old shape");
        assert_eq!(iv, [0x11; 12], "Init acknowledgement failure must not write the caller IV");
        assert_eq!(tag, [0xA5; 16], "Init acknowledgement failure must not write the caller tag");
    }

    #[test]
    fn stale_registry_rejection_restores_the_shim_shape() {
        let mut operation = state::MessageOperationState::default();
        let saved_shape = Some(MessageParameterShape::Ccm);
        let error = MessageCallError {
            ck_rv: CkRv::MECHANISM_PARAM_INVALID,
            origin: MessageCallErrorOrigin::Backend,
        };

        let rv = settle_message_init_error(&mut operation, saved_shape, &error);

        assert_eq!(rv, CkRv::MECHANISM_PARAM_INVALID);
        assert_eq!(
            operation.shape, saved_shape,
            "a pre-provider daemon rejection must preserve the shim's prior operation state",
        );
    }

    #[test]
    fn device_error_or_transport_failure_clears_the_shim_shape() {
        for error in [
            MessageCallError { ck_rv: CkRv::DEVICE_ERROR, origin: MessageCallErrorOrigin::Backend },
            MessageCallError {
                ck_rv: CkRv::FUNCTION_FAILED,
                origin: MessageCallErrorOrigin::Transport,
            },
        ] {
            let mut operation = state::MessageOperationState::default();
            let saved_shape = Some(MessageParameterShape::Gcm);

            let rv = settle_message_init_error(&mut operation, saved_shape, &error);

            assert_eq!(rv, error.ck_rv);
            assert_eq!(operation.shape, None, "{:?} must clear stale state", error.origin);
        }
    }
}
