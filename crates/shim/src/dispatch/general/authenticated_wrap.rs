//! Shim dispatch for PKCS#11 3.2 authenticated wrap/unwrap operations (Wave 5).
//!
//! - `C_WrapKeyAuthenticated` — two-call cache for wrapped_key + mechanism_parameter_out
//! - `C_UnwrapKeyAuthenticated` — returns key handle + mechanism_parameter_out

// CK_ULONG is u64 on 64-bit and u32 on 32-bit; `as u64` casts are intentional
// for cross-platform PKCS#11 portability.
#![allow(clippy::unnecessary_cast)]

use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use super::helpers::*;

// ---------------------------------------------------------------------------
// C_WrapKeyAuthenticated — two-call cache for wrapped_key
// The mechanism_parameter_out is written back to the mechanism's pParameter
// buffer (tag/IV write-back), similar to message encrypt APIs.
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
        if p_mechanism.is_null() || pul_wrapped_key_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        let aad = unsafe { read_input_slice(p_aad, ul_aad_len) };

        // The mechanism's pParameter is the dual-purpose buffer for write-back
        let c_mech = unsafe { &*p_mechanism };
        let output_spec = unsafe { output_buffer_spec(p_wrapped_key, pul_wrapped_key_len) };
        let param_out_spec =
            unsafe { parameter_roundtrip_spec(c_mech.pParameter, c_mech.ulParameterLen) };

        let result = with_client!(client => client.parameter_output_exact(
            CkSessionHandle(h_session),
            ParameterOutputFunction::WrapKeyAuthenticated,
            &output_spec,
            &[],
            aad,
            param_out_spec.value.as_deref().unwrap_or(&[]),
            &param_out_spec,
            0,
            Some(&mech),
            h_wrapping_key as u64,
            h_key as u64,
            None,
        ));

        match result {
            Ok((output_result, param_result, _)) => unsafe {
                write_exact_parameter_output(
                    &output_result,
                    &param_result,
                    p_wrapped_key,
                    pul_wrapped_key_len,
                    c_mech.pParameter,
                    c_mech.ulParameterLen,
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
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        let wrapped_key = unsafe { read_input_slice(p_wrapped_key, ul_wrapped_key_len) };
        let template = unsafe { ck_attrs_to_rust(p_template, ul_count) };
        let aad = unsafe { read_input_slice(p_aad, ul_aad_len) };

        match with_client!(client => client.unwrap_key_authenticated(
            CkSessionHandle(h_session),
            &mech,
            CkObjectHandle(h_unwrapping_key),
            wrapped_key,
            &template,
            aad,
        )) {
            Ok((key_handle, mech_param_out)) => {
                unsafe { write_object_handle_output(key_handle, ph_key) };
                // Write mechanism_parameter_out back to the caller's mechanism pParameter buffer
                if !mech_param_out.is_empty() {
                    let c_mech = unsafe { &*p_mechanism };
                    unsafe {
                        write_parameter_out(
                            &mech_param_out,
                            c_mech.pParameter,
                            c_mech.ulParameterLen,
                        );
                    }
                }
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}
