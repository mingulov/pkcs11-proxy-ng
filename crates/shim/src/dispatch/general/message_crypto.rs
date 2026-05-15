use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use crate::state;

use super::helpers::*;

// ---------------------------------------------------------------------------
// C_MessageEncryptInit — mechanism is nullable (NULL = cancel active state)
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_message_encrypt_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panics(|| {
        let mech = if p_mechanism.is_null() {
            None // cancel path
        } else {
            let rv = unsafe { validate_mechanism(p_mechanism) };
            if rv != rv_ok() {
                return rv;
            }
            Some(unsafe { read_mechanism(p_mechanism) })
        };
        let result = with_client!(client => client.message_encrypt_init(
            CkSessionHandle(h_session),
            mech.as_ref(),
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
        unit_result_to_rv(
            with_client!(client => client.message_encrypt_final(CkSessionHandle(h_session))),
        )
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
        let mech = if p_mechanism.is_null() {
            None // cancel path
        } else {
            let rv = unsafe { validate_mechanism(p_mechanism) };
            if rv != rv_ok() {
                return rv;
            }
            Some(unsafe { read_mechanism(p_mechanism) })
        };
        let result = with_client!(client => client.message_decrypt_init(
            CkSessionHandle(h_session),
            mech.as_ref(),
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
        unit_result_to_rv(
            with_client!(client => client.message_decrypt_final(CkSessionHandle(h_session))),
        )
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
        let mech = if p_mechanism.is_null() {
            None // cancel path
        } else {
            let rv = unsafe { validate_mechanism(p_mechanism) };
            if rv != rv_ok() {
                return rv;
            }
            Some(unsafe { read_mechanism(p_mechanism) })
        };
        let result = with_client!(client => client.message_sign_init(
            CkSessionHandle(h_session),
            mech.as_ref(),
            CkObjectHandle(h_key),
        ));
        if result.is_ok() {
            state::clear_message_sign_output_cache(h_session);
            state::clear_operation_state_cache(h_session);
        }
        unit_result_to_rv(result)
    })
}

// ---------------------------------------------------------------------------
// C_MessageSignFinal — session-only cleanup
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_message_sign_final(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(
            with_client!(client => client.message_sign_final(CkSessionHandle(h_session))),
        )
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
        let mech = if p_mechanism.is_null() {
            None // cancel path
        } else {
            let rv = unsafe { validate_mechanism(p_mechanism) };
            if rv != rv_ok() {
                return rv;
            }
            Some(unsafe { read_mechanism(p_mechanism) })
        };
        unit_result_to_rv(with_client!(client => client.message_verify_init(
            CkSessionHandle(h_session),
            mech.as_ref(),
            CkObjectHandle(h_key),
        )))
    })
}

// ---------------------------------------------------------------------------
// C_MessageVerifyFinal — session-only cleanup
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_message_verify_final(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(
            with_client!(client => client.message_verify_final(CkSessionHandle(h_session))),
        )
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
        if pul_ciphertext_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let aad = unsafe { read_input_slice(p_associated_data, ul_associated_data_len) };
        let plaintext = unsafe { read_input_slice(p_plaintext, ul_plaintext_len) };
        let output_spec = unsafe { output_buffer_spec(p_ciphertext, pul_ciphertext_len) };
        let param_out_spec =
            match unsafe { message_parameter_roundtrip_spec(p_parameter, ul_parameter_len) } {
                Ok(spec) => spec,
                Err(error) => return rv_err(error),
            };
        let msg_param = match unsafe {
            try_read_message_parameter(p_parameter as *const _, ul_parameter_len)
        } {
            Ok(param) => param,
            Err(error) => return rv_err(error),
        };

        let result = with_client!(client => client.parameter_output_exact(
            CkSessionHandle(h_session),
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
            msg_param.as_ref(),
        ));

        match result {
            Ok((output_result, _param_result, msg_param_out)) => {
                if let Some(ref mp) = msg_param_out {
                    unsafe {
                        write_message_parameter_back(mp, p_parameter, ul_parameter_len);
                    }
                }
                unsafe { write_exact_output(&output_result, p_ciphertext, pul_ciphertext_len) }
            }
            Err(e) => rv_err(e),
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
        let parameter = unsafe { read_input_slice(p_parameter as *const u8, ul_parameter_len) };
        let aad = unsafe { read_input_slice(p_associated_data, ul_associated_data_len) };

        let result = with_client!(client => client.encrypt_message_begin(
            CkSessionHandle(h_session),
            parameter,
            aad,
        ));

        match result {
            Ok(parameter_out) => {
                unsafe { write_parameter_out(&parameter_out, p_parameter, ul_parameter_len) };
                rv_ok()
            }
            Err(e) => rv_err(e),
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
        if pul_ciphertext_part_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let plaintext_part = unsafe { read_input_slice(p_plaintext_part, ul_plaintext_part_len) };
        let output_spec = unsafe { output_buffer_spec(p_ciphertext_part, pul_ciphertext_part_len) };
        let param_out_spec =
            match unsafe { message_parameter_roundtrip_spec(p_parameter, ul_parameter_len) } {
                Ok(spec) => spec,
                Err(error) => return rv_err(error),
            };
        let msg_param = match unsafe {
            try_read_message_parameter(p_parameter as *const _, ul_parameter_len)
        } {
            Ok(param) => param,
            Err(error) => return rv_err(error),
        };

        let result = with_client!(client => client.parameter_output_exact(
            CkSessionHandle(h_session),
            ParameterOutputFunction::EncryptMessageNext,
            &output_spec,
            plaintext_part,
            &[],
            &[],
            &param_out_spec,
            flags,
            None,
            0,
            0,
            msg_param.as_ref(),
        ));

        match result {
            Ok((output_result, _param_result, msg_param_out)) => {
                if let Some(ref mp) = msg_param_out {
                    unsafe {
                        write_message_parameter_back(mp, p_parameter, ul_parameter_len);
                    }
                }
                unsafe {
                    write_exact_output(&output_result, p_ciphertext_part, pul_ciphertext_part_len)
                }
            }
            Err(e) => rv_err(e),
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
        if pul_plaintext_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let aad = unsafe { read_input_slice(p_associated_data, ul_associated_data_len) };
        let ciphertext = unsafe { read_input_slice(p_ciphertext, ul_ciphertext_len) };
        let output_spec = unsafe { output_buffer_spec(p_plaintext, pul_plaintext_len) };
        let param_out_spec =
            match unsafe { message_parameter_roundtrip_spec(p_parameter, ul_parameter_len) } {
                Ok(spec) => spec,
                Err(error) => return rv_err(error),
            };
        let msg_param = match unsafe {
            try_read_message_parameter(p_parameter as *const _, ul_parameter_len)
        } {
            Ok(param) => param,
            Err(error) => return rv_err(error),
        };

        let result = with_client!(client => client.parameter_output_exact(
            CkSessionHandle(h_session),
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
            msg_param.as_ref(),
        ));

        match result {
            Ok((output_result, _param_result, msg_param_out)) => {
                if let Some(ref mp) = msg_param_out {
                    unsafe {
                        write_message_parameter_back(mp, p_parameter, ul_parameter_len);
                    }
                }
                unsafe { write_exact_output(&output_result, p_plaintext, pul_plaintext_len) }
            }
            Err(e) => rv_err(e),
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
        let parameter = unsafe { read_input_slice(p_parameter as *const u8, ul_parameter_len) };
        let aad = unsafe { read_input_slice(p_associated_data, ul_associated_data_len) };

        let result = with_client!(client => client.decrypt_message_begin(
            CkSessionHandle(h_session),
            parameter,
            aad,
        ));

        match result {
            Ok(parameter_out) => {
                unsafe { write_parameter_out(&parameter_out, p_parameter, ul_parameter_len) };
                rv_ok()
            }
            Err(e) => rv_err(e),
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
        if pul_plaintext_part_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let ciphertext_part =
            unsafe { read_input_slice(p_ciphertext_part, ul_ciphertext_part_len) };
        let output_spec = unsafe { output_buffer_spec(p_plaintext_part, pul_plaintext_part_len) };
        let param_out_spec =
            match unsafe { message_parameter_roundtrip_spec(p_parameter, ul_parameter_len) } {
                Ok(spec) => spec,
                Err(error) => return rv_err(error),
            };
        let msg_param = match unsafe {
            try_read_message_parameter(p_parameter as *const _, ul_parameter_len)
        } {
            Ok(param) => param,
            Err(error) => return rv_err(error),
        };

        let result = with_client!(client => client.parameter_output_exact(
            CkSessionHandle(h_session),
            ParameterOutputFunction::DecryptMessageNext,
            &output_spec,
            ciphertext_part,
            &[],
            &[],
            &param_out_spec,
            flags,
            None,
            0,
            0,
            msg_param.as_ref(),
        ));

        match result {
            Ok((output_result, _param_result, msg_param_out)) => {
                if let Some(ref mp) = msg_param_out {
                    unsafe {
                        write_message_parameter_back(mp, p_parameter, ul_parameter_len);
                    }
                }
                unsafe {
                    write_exact_output(&output_result, p_plaintext_part, pul_plaintext_part_len)
                }
            }
            Err(e) => rv_err(e),
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
        if pul_signature_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let data = unsafe { read_input_slice(p_data, ul_data_len) };
        let output_spec = unsafe { output_buffer_spec(p_signature, pul_signature_len) };
        let param_out_spec =
            match unsafe { message_parameter_roundtrip_spec(p_parameter, ul_parameter_len) } {
                Ok(spec) => spec,
                Err(error) => return rv_err(error),
            };
        let msg_param = match unsafe {
            try_read_message_parameter(p_parameter as *const _, ul_parameter_len)
        } {
            Ok(param) => param,
            Err(error) => return rv_err(error),
        };

        let result = with_client!(client => client.parameter_output_exact(
            CkSessionHandle(h_session),
            ParameterOutputFunction::SignMessage,
            &output_spec,
            data,
            &[],
            &[],
            &param_out_spec,
            0,
            None,
            0,
            0,
            msg_param.as_ref(),
        ));

        match result {
            Ok((output_result, _param_result, msg_param_out)) => {
                if let Some(ref mp) = msg_param_out {
                    unsafe {
                        write_message_parameter_back(mp, p_parameter, ul_parameter_len);
                    }
                }
                unsafe { write_exact_output(&output_result, p_signature, pul_signature_len) }
            }
            Err(e) => rv_err(e),
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
        let parameter = unsafe { read_input_slice(p_parameter as *const u8, ul_parameter_len) };

        let result = with_client!(client => client.sign_message_begin(
            CkSessionHandle(h_session),
            parameter,
        ));

        match result {
            Ok(parameter_out) => {
                unsafe { write_parameter_out(&parameter_out, p_parameter, ul_parameter_len) };
                rv_ok()
            }
            Err(e) => rv_err(e),
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
        let parameter = unsafe { read_input_slice(p_parameter as *const u8, ul_parameter_len) };
        let data_part = unsafe { read_input_slice(p_data_part, ul_data_part_len) };

        // If pul_signature_len is NULL => "more data" mode, request_signature = false
        let request_signature = !pul_signature_len.is_null();

        if !request_signature {
            // Feed more data — no output. Use existing convenience path.
            let result = with_client!(client => client.sign_message_next(
                CkSessionHandle(h_session),
                parameter,
                data_part,
                false,
            ));

            return match result {
                Ok((param_out, _)) => {
                    unsafe {
                        write_parameter_out(&param_out, p_parameter, ul_parameter_len);
                    }
                    rv_ok()
                }
                Err(e) => rv_err(e),
            };
        }

        // Final call: request_signature = true, use exact output path
        let output_spec = unsafe { output_buffer_spec(p_signature, pul_signature_len) };
        let param_out_spec =
            match unsafe { message_parameter_roundtrip_spec(p_parameter, ul_parameter_len) } {
                Ok(spec) => spec,
                Err(error) => return rv_err(error),
            };
        let msg_param = match unsafe {
            try_read_message_parameter(p_parameter as *const _, ul_parameter_len)
        } {
            Ok(param) => param,
            Err(error) => return rv_err(error),
        };

        let result = with_client!(client => client.parameter_output_exact(
            CkSessionHandle(h_session),
            ParameterOutputFunction::SignMessageNext,
            &output_spec,
            data_part,
            &[],
            &[],
            &param_out_spec,
            0,
            None,
            0,
            0,
            msg_param.as_ref(),
        ));

        match result {
            Ok((output_result, _param_result, msg_param_out)) => {
                if let Some(ref mp) = msg_param_out {
                    unsafe {
                        write_message_parameter_back(mp, p_parameter, ul_parameter_len);
                    }
                }
                unsafe { write_exact_output(&output_result, p_signature, pul_signature_len) }
            }
            Err(e) => rv_err(e),
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
        let parameter = unsafe { read_input_slice(p_parameter as *const u8, ul_parameter_len) };
        let data = unsafe { read_input_slice(p_data, ul_data_len) };
        let signature = unsafe { read_input_slice(p_signature, ul_signature_len) };

        unit_result_to_rv(with_client!(client => client.verify_message(
            CkSessionHandle(h_session),
            parameter,
            data,
            signature,
        )))
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
        let parameter = unsafe { read_input_slice(p_parameter as *const u8, ul_parameter_len) };

        unit_result_to_rv(with_client!(client => client.verify_message_begin(
            CkSessionHandle(h_session),
            parameter,
        )))
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
        let parameter = unsafe { read_input_slice(p_parameter as *const u8, ul_parameter_len) };
        let data_part = unsafe { read_input_slice(p_data_part, ul_data_part_len) };

        // If pSignature is NULL, this is a "feed more data" call (is_final = false)
        let is_final = !p_signature.is_null();
        let signature =
            if is_final { unsafe { read_input_slice(p_signature, ul_signature_len) } } else { &[] };

        unit_result_to_rv(with_client!(client => client.verify_message_next(
            CkSessionHandle(h_session),
            parameter,
            data_part,
            is_final,
            signature,
        )))
    })
}
