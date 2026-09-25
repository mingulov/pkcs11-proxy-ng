use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use super::helpers::{catch_panics, dispatch_byte_output_exact};

pub unsafe extern "C" fn c_digest_encrypt_update(
    h_session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    ul_part_len: CK_ULONG,
    p_encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| unsafe {
        dispatch_byte_output_exact(
            h_session,
            ByteOutputFunction::DigestEncryptUpdate,
            p_part,
            ul_part_len,
            p_encrypted_part,
            pul_encrypted_part_len,
        )
    })
}

pub unsafe extern "C" fn c_decrypt_digest_update(
    h_session: CK_SESSION_HANDLE,
    p_encrypted_part: CK_BYTE_PTR,
    ul_encrypted_part_len: CK_ULONG,
    p_part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| unsafe {
        dispatch_byte_output_exact(
            h_session,
            ByteOutputFunction::DecryptDigestUpdate,
            p_encrypted_part,
            ul_encrypted_part_len,
            p_part,
            pul_part_len,
        )
    })
}

pub unsafe extern "C" fn c_sign_encrypt_update(
    h_session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    ul_part_len: CK_ULONG,
    p_encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| unsafe {
        dispatch_byte_output_exact(
            h_session,
            ByteOutputFunction::SignEncryptUpdate,
            p_part,
            ul_part_len,
            p_encrypted_part,
            pul_encrypted_part_len,
        )
    })
}

pub unsafe extern "C" fn c_decrypt_verify_update(
    h_session: CK_SESSION_HANDLE,
    p_encrypted_part: CK_BYTE_PTR,
    ul_encrypted_part_len: CK_ULONG,
    p_part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| unsafe {
        dispatch_byte_output_exact(
            h_session,
            ByteOutputFunction::DecryptVerifyUpdate,
            p_encrypted_part,
            ul_encrypted_part_len,
            p_part,
            pul_part_len,
        )
    })
}
