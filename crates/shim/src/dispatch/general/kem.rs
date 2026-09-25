//! Shim dispatch for PKCS#11 3.2 KEM operations (Wave 2).
//!
//! - `C_EncapsulateKey` — exact output path via `EncapsulateKeyExact` RPC.
//! - `C_DecapsulateKey` — single call returning a key handle.

use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use super::helpers::*;

unsafe fn write_exact_kem_output(
    spec: &CkOutputBufferSpec,
    result: CkOutputAndHandleResult,
    p_ciphertext: CK_BYTE_PTR,
    pul_ciphertext_len: CK_ULONG_PTR,
    ph_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let handle = match result.object_handle {
        Some(handle) if result.ck_rv == CkRv::OK && !ph_key.is_null() => {
            match CK_OBJECT_HANDLE::try_from(handle.0) {
                Ok(handle) => Some(handle),
                Err(_) => return rv_err(CkRv::GENERAL_ERROR),
            }
        }
        None => None,
        _ => return rv_err(CkRv::GENERAL_ERROR),
    };
    let buf_result = CkOutputBufferResult {
        ck_rv: result.ck_rv,
        returned_len: result.returned_len,
        value: result.value,
    };
    let output_rv =
        unsafe { write_exact_output(spec, &buf_result, p_ciphertext, pul_ciphertext_len) };
    // Commit the handle only after the main output envelope validates.
    if output_rv == rv_ok()
        && let Some(handle) = handle
    {
        unsafe { ph_key.write(handle) };
    }
    output_rv
}

pub unsafe extern "C" fn c_encapsulate_key(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_public_key: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
    p_ciphertext: CK_BYTE_PTR,
    pul_ciphertext_len: CK_ULONG_PTR,
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
        let template_opt = null_preserving_template(&template, p_template);
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        let spec = unsafe { output_buffer_spec(p_ciphertext, pul_ciphertext_len) };

        let result = with_client!(client => client.encapsulate_key_exact(
            CkSessionHandle(h_session as u64),
            &mech,
            CkObjectHandle(h_public_key as u64),
            template_opt,
            &spec,
        ));

        match result {
            Ok(r) => unsafe {
                write_exact_kem_output(&spec, r, p_ciphertext, pul_ciphertext_len, ph_key)
            },
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_decapsulate_key(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_private_key: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
    p_ciphertext: CK_BYTE_PTR,
    ul_ciphertext_len: CK_ULONG,
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
        let template_opt = null_preserving_template(&template, p_template);
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        let ciphertext = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_ciphertext, ul_ciphertext_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        match with_client!(client => client.decapsulate_key(
            CkSessionHandle(h_session as u64),
            &mech,
            CkObjectHandle(h_private_key as u64),
            template_opt,
            ciphertext,
        )) {
            Ok(key_handle) => {
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

    #[test]
    fn malformed_missing_length_success_does_not_commit_kem_outputs() {
        let spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true };
        let result = CkOutputAndHandleResult {
            ck_rv: CkRv::OK,
            returned_len: Some(1),
            value: None,
            object_handle: Some(CkObjectHandle(0x44)),
        };
        let mut ciphertext_canary = 0xa5;
        let handle_canary = 0xa5a5 as CK_OBJECT_HANDLE;
        let mut key_handle = handle_canary;

        let rv = unsafe {
            write_exact_kem_output(
                &spec,
                result,
                &mut ciphertext_canary,
                std::ptr::null_mut(),
                &mut key_handle,
            )
        };

        assert_eq!(rv, CKR_GENERAL_ERROR as CK_RV);
        assert_eq!(ciphertext_canary, 0xa5);
        assert_eq!(key_handle, handle_canary);
    }
}
