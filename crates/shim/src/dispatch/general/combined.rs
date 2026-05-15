use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

#[allow(unused_imports)]
use super::*;

pub unsafe extern "C" fn c_digest_encrypt_update(
    h_session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    ul_part_len: CK_ULONG,
    p_encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if pul_encrypted_part_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let part = unsafe { read_input_slice(p_part, ul_part_len) };
        let spec = unsafe { output_buffer_spec(p_encrypted_part, pul_encrypted_part_len) };
        let result = with_client!(client => client.byte_output_exact(
            CkSessionHandle(h_session),
            ByteOutputFunction::DigestEncryptUpdate,
            &spec,
            part,
            None,
            0,
            0,
        ));
        match result {
            Ok(r) => unsafe { write_exact_output(&r, p_encrypted_part, pul_encrypted_part_len) },
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_decrypt_digest_update(
    h_session: CK_SESSION_HANDLE,
    p_encrypted_part: CK_BYTE_PTR,
    ul_encrypted_part_len: CK_ULONG,
    p_part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if pul_part_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let encrypted_part = unsafe { read_input_slice(p_encrypted_part, ul_encrypted_part_len) };
        let spec = unsafe { output_buffer_spec(p_part, pul_part_len) };
        let result = with_client!(client => client.byte_output_exact(
            CkSessionHandle(h_session),
            ByteOutputFunction::DecryptDigestUpdate,
            &spec,
            encrypted_part,
            None,
            0,
            0,
        ));
        match result {
            Ok(r) => unsafe { write_exact_output(&r, p_part, pul_part_len) },
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_sign_encrypt_update(
    h_session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    ul_part_len: CK_ULONG,
    p_encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if pul_encrypted_part_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let part = unsafe { read_input_slice(p_part, ul_part_len) };
        let spec = unsafe { output_buffer_spec(p_encrypted_part, pul_encrypted_part_len) };
        let result = with_client!(client => client.byte_output_exact(
            CkSessionHandle(h_session),
            ByteOutputFunction::SignEncryptUpdate,
            &spec,
            part,
            None,
            0,
            0,
        ));
        match result {
            Ok(r) => unsafe { write_exact_output(&r, p_encrypted_part, pul_encrypted_part_len) },
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_decrypt_verify_update(
    h_session: CK_SESSION_HANDLE,
    p_encrypted_part: CK_BYTE_PTR,
    ul_encrypted_part_len: CK_ULONG,
    p_part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if pul_part_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let encrypted_part = unsafe { read_input_slice(p_encrypted_part, ul_encrypted_part_len) };
        let spec = unsafe { output_buffer_spec(p_part, pul_part_len) };
        let result = with_client!(client => client.byte_output_exact(
            CkSessionHandle(h_session),
            ByteOutputFunction::DecryptVerifyUpdate,
            &spec,
            encrypted_part,
            None,
            0,
            0,
        ));
        match result {
            Ok(r) => unsafe { write_exact_output(&r, p_part, pul_part_len) },
            Err(e) => rv_err(e),
        }
    })
}
