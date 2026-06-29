//! Shim dispatch for PKCS#11 3.2 KEM operations (Wave 2).
//!
//! - `C_EncapsulateKey` — exact output path via `EncapsulateKeyExact` RPC.
//! - `C_DecapsulateKey` — single call returning a key handle.

use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use super::helpers::*;

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
        if p_mechanism.is_null() || pul_ciphertext_len.is_null() || ph_key.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let template = match unsafe { ck_attrs_to_rust_checked(p_template, ul_count) } {
            Ok(template) => template,
            Err(e) => return rv_err(e),
        };
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
            &template,
            &spec,
        ));

        match result {
            Ok(r) => {
                let buf_result = CkOutputBufferResult {
                    ck_rv: r.ck_rv,
                    returned_len: r.returned_len,
                    value: r.value,
                };
                let output_rv =
                    unsafe { write_exact_output(&buf_result, p_ciphertext, pul_ciphertext_len) };
                // Write key handle only on success
                if r.ck_rv == CkRv::OK {
                    unsafe { *ph_key = r.object_handle.0 as CK_OBJECT_HANDLE };
                }
                output_rv
            }
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
            &template,
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
