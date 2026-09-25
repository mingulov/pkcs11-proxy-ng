//! Shim dispatch for PKCS#11 3.2 authenticated wrap/unwrap operations (Wave 5).
//!
//! Typed, pointer-safe authenticated wrap/unwrap and exact caller outputs.

// CK_ULONG is u64 on 64-bit and u32 on 32-bit; `as u64` casts are intentional
// for cross-platform PKCS#11 portability.
#![allow(clippy::unnecessary_cast)]

use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use super::helpers::*;

// ---------------------------------------------------------------------------
// C_WrapKeyAuthenticated — exactly one native call for the caller's buffer.
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_wrap_key_authenticated(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_wrapping_key: CK_OBJECT_HANDLE,
    h_key: CK_OBJECT_HANDLE,
    p_aad: CK_BYTE_PTR,
    ul_aad_len: CK_ULONG,
    p_wrapped_key: CK_BYTE_PTR,
    pul_wrapped_key_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if p_mechanism.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let output_spec = unsafe { output_buffer_spec(p_wrapped_key, pul_wrapped_key_len) };
        let call = match unsafe {
            AuthenticatedCall::read(
                p_mechanism,
                MessageParameterDirection::Encrypt,
                MessageCallMemory::output(
                    p_aad,
                    ul_aad_len,
                    std::ptr::null(),
                    0,
                    p_wrapped_key,
                    output_spec.buffer_len,
                    pul_wrapped_key_len,
                ),
            )
        } {
            Ok(call) => call,
            Err(rv) => return rv_err(rv),
        };
        let aad = match input_buf_to_ck_in_buf(unsafe { classify_input(p_aad, ul_aad_len) }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };

        let result = with_client!(client => client.wrap_key_authenticated_exact_typed(
            CkSessionHandle(h_session as u64),
            &call.mechanism,
            call.parameter(),
            CkObjectHandle(h_wrapping_key as u64),
            CkObjectHandle(h_key as u64),
            aad,
            &output_spec,
        ));

        match result {
            Ok((output_result, parameter)) => unsafe {
                call.write_output(
                    &output_spec,
                    &output_result,
                    &parameter,
                    p_wrapped_key,
                    pul_wrapped_key_len,
                )
            },
            Err(e) => rv_err(e),
        }
    })
}

// ---------------------------------------------------------------------------
// C_UnwrapKeyAuthenticated — returns key handle + mechanism_parameter_out
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_unwrap_key_authenticated(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_unwrapping_key: CK_OBJECT_HANDLE,
    p_wrapped_key: CK_BYTE_PTR,
    ul_wrapped_key_len: CK_ULONG,
    p_template: CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
    p_aad: CK_BYTE_PTR,
    ul_aad_len: CK_ULONG,
    ph_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_panics(|| {
        if p_mechanism.is_null() || ph_key.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let template = match unsafe { ck_attrs_to_rust_checked(p_template, ul_count) } {
            Ok(template) => template,
            Err(e) => return rv_err(e),
        };
        let call = match unsafe {
            AuthenticatedCall::read(
                p_mechanism,
                MessageParameterDirection::Decrypt,
                MessageCallMemory::output(
                    p_aad,
                    ul_aad_len,
                    p_wrapped_key,
                    ul_wrapped_key_len,
                    ph_key.cast(),
                    std::mem::size_of::<CK_OBJECT_HANDLE>() as u64,
                    std::ptr::null_mut(),
                ),
            )
        } {
            Ok(call) => call,
            Err(rv) => return rv_err(rv),
        };
        let wrapped_key = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_wrapped_key, ul_wrapped_key_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        let aad = match input_buf_to_ck_in_buf(unsafe { classify_input(p_aad, ul_aad_len) }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };

        match with_client!(client => client.unwrap_key_authenticated_typed(
            CkSessionHandle(h_session as u64),
            &call.mechanism,
            call.parameter(),
            CkObjectHandle(h_unwrapping_key as u64),
            wrapped_key,
            template_opt,
            aad,
        )) {
            Ok((key_handle, output)) => {
                let rv = unsafe { call.write_parameter(&output) };
                if rv != CKR_OK {
                    return rv;
                }
                unsafe { write_object_handle_output(key_handle, ph_key) };
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput;
    use pkcs11_proxy_ng_proto::convert::message_params::MessageParameter;

    #[test]
    fn authenticated_gcm_writes_only_captured_iv_and_tag_buffers() {
        let mut iv = [0; 12];
        let mut tag = [0; 16];
        let mut parameter = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: 12,
            ulIvFixedBits: 0,
            ivGenerator: CKG_GENERATE_RANDOM,
            pTag: tag.as_mut_ptr(),
            ulTagBits: 128,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: (&mut parameter as *mut CK_GCM_MESSAGE_PARAMS).cast(),
            ulParameterLen: std::mem::size_of_val(&parameter) as CK_ULONG,
        };
        let call = unsafe {
            AuthenticatedCall::read(
                &mut mechanism,
                MessageParameterDirection::Encrypt,
                MessageCallMemory::none(),
            )
        }
        .unwrap();
        assert!(
            call.mechanism.params.is_none(),
            "message layout must not enter the generic/raw mechanism channel"
        );
        let Some(MessageParameter::GcmMessage(mut output)) = call.parameter().cloned() else {
            panic!("expected message shape");
        };
        output.iv.fill(0xa5);
        output.tag.fill(0x5a);
        let mut length = 0;
        let rv = unsafe {
            call.write_output(
                &CkOutputBufferSpec {
                    buffer_present: true,
                    buffer_len: 0,
                    length_pointer_null: false,
                },
                &pkcs11_proxy_ng_types::CkOutputBufferResult {
                    ck_rv: CkRv::OK,
                    returned_len: Some(0),
                    value: Some(Vec::new()),
                },
                &AuthenticatedOutput::Message(MessageParameter::GcmMessage(output)),
                std::ptr::NonNull::<u8>::dangling().as_ptr(),
                &mut length,
            )
        };
        assert_eq!(rv, CKR_OK);
        assert!(iv == [0xa5; 12] && tag == [0x5a; 16]);
        assert!(parameter.pIv == iv.as_mut_ptr() && parameter.pTag == tag.as_mut_ptr());
        assert_eq!(
            (
                parameter.ulIvLen,
                parameter.ulIvFixedBits,
                parameter.ivGenerator,
                parameter.ulTagBits
            ),
            (12, 0, CKG_GENERATE_RANDOM, 128)
        );
    }

    #[test]
    fn authenticated_malformed_response_leaves_every_caller_output_untouched() {
        let mut iv = [1; 12];
        let mut tag = [2; 16];
        let mut bytes = [3; 8];
        let mut length = 8;
        let mut parameter = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: 12,
            ulIvFixedBits: 0,
            ivGenerator: CKG_NO_GENERATE,
            pTag: tag.as_mut_ptr(),
            ulTagBits: 128,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: (&mut parameter as *mut CK_GCM_MESSAGE_PARAMS).cast(),
            ulParameterLen: std::mem::size_of_val(&parameter) as CK_ULONG,
        };
        let call = unsafe {
            AuthenticatedCall::read(
                &mut mechanism,
                MessageParameterDirection::Encrypt,
                MessageCallMemory::output(
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    bytes.as_mut_ptr(),
                    8,
                    &mut length,
                ),
            )
        }
        .unwrap();
        let Some(MessageParameter::GcmMessage(mut output)) = call.parameter().cloned() else {
            panic!("expected message shape");
        };
        output.iv.fill(0xa5);
        output.tag.fill(0x5a);
        output.tag_bits = 64;
        let rv = unsafe {
            call.write_output(
                &CkOutputBufferSpec {
                    buffer_present: true,
                    buffer_len: 8,
                    length_pointer_null: false,
                },
                &CkOutputBufferResult {
                    ck_rv: CkRv::OK,
                    returned_len: Some(4),
                    value: Some(vec![4; 4]),
                },
                &AuthenticatedOutput::Message(MessageParameter::GcmMessage(output)),
                bytes.as_mut_ptr(),
                &mut length,
            )
        };
        assert_eq!(rv, CKR_GENERAL_ERROR);
        assert!(iv == [1; 12] && tag == [2; 16] && bytes == [3; 8]);
        assert_eq!(length, 8);
    }

    #[test]
    fn authenticated_gcm_rejects_aliasing_before_read_or_write() {
        let mut shared = [0; 16];
        let mut parameter = CK_GCM_MESSAGE_PARAMS {
            pIv: shared.as_mut_ptr(),
            ulIvLen: 12,
            ulIvFixedBits: 0,
            ivGenerator: CKG_GENERATE_RANDOM,
            pTag: shared.as_mut_ptr(),
            ulTagBits: 128,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: (&mut parameter as *mut CK_GCM_MESSAGE_PARAMS).cast(),
            ulParameterLen: std::mem::size_of_val(&parameter) as CK_ULONG,
        };
        let call = unsafe {
            AuthenticatedCall::read(
                &mut mechanism,
                MessageParameterDirection::Encrypt,
                MessageCallMemory::none(),
            )
        };
        assert!(matches!(call, Err(CkRv::MECHANISM_PARAM_INVALID)));
    }

    #[test]
    fn authenticated_response_preserves_caller_pointers_and_virtual_gost_handle() {
        crate::state::replace_mechanism_registry(MechanismRegistry::load(None).unwrap());
        let mut oid = [1; 3];
        let mut ukm = [2; 8];
        let mut parameter = CK_GOSTR3410_KEY_WRAP_PARAMS {
            pWrapOID: oid.as_mut_ptr(),
            ulWrapOIDLen: 3,
            pUKM: ukm.as_mut_ptr(),
            ulUKMLen: 8,
            hKey: 17,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_GOSTR3410_KEY_WRAP,
            pParameter: (&mut parameter as *mut CK_GOSTR3410_KEY_WRAP_PARAMS).cast(),
            ulParameterLen: std::mem::size_of_val(&parameter) as CK_ULONG,
        };
        let pointer = mechanism.pParameter;
        let mut length = 0;
        let call = unsafe {
            AuthenticatedCall::read(
                &mut mechanism,
                MessageParameterDirection::Encrypt,
                MessageCallMemory::none(),
            )
        }
        .unwrap();
        let rv = unsafe {
            call.write_output(
                &CkOutputBufferSpec {
                    buffer_present: false,
                    buffer_len: 0,
                    length_pointer_null: false,
                },
                &CkOutputBufferResult { ck_rv: CkRv::OK, returned_len: Some(8), value: None },
                &pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput::Unchanged,
                std::ptr::null_mut(),
                &mut length,
            )
        };
        assert_eq!(rv, CKR_OK);
        assert!(parameter.pWrapOID == oid.as_mut_ptr(), "caller OID pointer must be preserved");
        assert!(parameter.pUKM == ukm.as_mut_ptr(), "caller UKM pointer must be preserved");
        assert!(mechanism.pParameter == pointer, "caller outer pointer must be preserved");
        // E0793: params structs are packed on Windows; assert on a by-value copy.
        let h_key = parameter.hKey;
        assert_eq!(h_key, 17);
        assert_eq!(length, 8);
        // Keep the mechanism mutable: the real C API accepts CK_MECHANISM_PTR.
        let _ = &mut mechanism;
    }
}
