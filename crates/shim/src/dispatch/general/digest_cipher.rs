// CK_ULONG is u64 on 64-bit and u32 on 32-bit; `as u64` casts are intentional
// for cross-platform PKCS#11 portability.
#![allow(clippy::unnecessary_cast)]

use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use crate::state;

use super::helpers::{
    catch_panics, classify_input, dispatch_byte_output_exact, dispatch_byte_output_exact_no_input,
    input_buf_to_ck_in_buf, read_mechanism, rv_err, rv_ok, unit_result_to_rv, validate_mechanism,
    with_client, write_mechanism_output_params,
};

pub unsafe extern "C" fn c_digest_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
) -> CK_RV {
    catch_panics(|| {
        if p_mechanism.is_null() {
            let result = with_client!(client => client.digest_init_cancel(CkSessionHandle(h_session as u64)));
            if result.is_ok() {
                state::clear_digest_output_caches(h_session);
                state::clear_operation_state_cache(h_session);
            }
            return unit_result_to_rv(result);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = match unsafe { read_mechanism(p_mechanism) } {
            Ok(mech) => mech,
            Err(e) => return rv_err(e),
        };
        let result =
            with_client!(client => client.digest_init(CkSessionHandle(h_session as u64), &mech));
        if result.is_ok() {
            state::clear_digest_output_caches(h_session);
            state::clear_operation_state_cache(h_session);
        }
        unit_result_to_rv(result)
    })
}

pub unsafe extern "C" fn c_digest(
    h_session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_digest: CK_BYTE_PTR,
    pul_digest_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| unsafe {
        dispatch_byte_output_exact(
            h_session,
            ByteOutputFunction::Digest,
            p_data,
            ul_data_len,
            p_digest,
            pul_digest_len,
        )
    })
}

pub unsafe extern "C" fn c_digest_update(
    h_session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    ul_part_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let part = match input_buf_to_ck_in_buf(unsafe { classify_input(p_part, ul_part_len) }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        unit_result_to_rv(
            with_client!(client => client.digest_update(CkSessionHandle(h_session as u64), part)),
        )
    })
}

pub unsafe extern "C" fn c_digest_key(
    h_session: CK_SESSION_HANDLE,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(with_client!(client => client.digest_key(
            CkSessionHandle(h_session as u64),
            CkObjectHandle(h_key as u64),
        )))
    })
}

pub unsafe extern "C" fn c_digest_final(
    h_session: CK_SESSION_HANDLE,
    p_digest: CK_BYTE_PTR,
    pul_digest_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| unsafe {
        dispatch_byte_output_exact_no_input(
            h_session,
            ByteOutputFunction::DigestFinal,
            p_digest,
            pul_digest_len,
        )
    })
}

// ---------------------------------------------------------------------------
// Encryption / Decryption
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_encrypt_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panics(|| {
        if p_mechanism.is_null() {
            let result = with_client!(client => client.encrypt_init_cancel(CkSessionHandle(h_session as u64)));
            if result.is_ok() {
                state::clear_encrypt_output_caches(h_session);
                state::clear_operation_state_cache(h_session);
            }
            return unit_result_to_rv(result);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = match unsafe { read_mechanism(p_mechanism) } {
            Ok(mech) => mech,
            Err(e) => return rv_err(e),
        };
        let result = with_client!(client => client.encrypt_init(
            CkSessionHandle(h_session as u64),
            &mech,
            CkObjectHandle(h_key as u64),
        ));
        match result {
            Ok(output_params) => {
                // W1-C6-01: the generated GCM IV is delivered here, inside
                // the call whose caller memory is live. No caller address
                // is retained: C_Encrypt receives no mechanism pointer, so
                // there is no live target a later write could use.
                if let Some(params) = output_params {
                    unsafe { write_mechanism_output_params(p_mechanism, &params) };
                }
                state::clear_encrypt_output_caches(h_session);
                state::clear_operation_state_cache(h_session);
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_encrypt(
    h_session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_encrypted_data: CK_BYTE_PTR,
    pul_encrypted_data_len: CK_ULONG_PTR,
) -> CK_RV {
    // W1-C6-01: plain byte_output_exact — Encrypt-time mechanism_out is
    // deliberately not consumed. The generated GCM IV is delivered at
    // Init (see c_encrypt_init); writing it here would mean writing to
    // Init-scope caller memory through a retained address (use-after-scope).
    catch_panics(|| unsafe {
        dispatch_byte_output_exact(
            h_session,
            ByteOutputFunction::Encrypt,
            p_data,
            ul_data_len,
            p_encrypted_data,
            pul_encrypted_data_len,
        )
    })
}

pub unsafe extern "C" fn c_encrypt_update(
    h_session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    ul_part_len: CK_ULONG,
    p_encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| unsafe {
        dispatch_byte_output_exact(
            h_session,
            ByteOutputFunction::EncryptUpdate,
            p_part,
            ul_part_len,
            p_encrypted_part,
            pul_encrypted_part_len,
        )
    })
}

pub unsafe extern "C" fn c_encrypt_final(
    h_session: CK_SESSION_HANDLE,
    p_last_encrypted_part: CK_BYTE_PTR,
    pul_last_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| unsafe {
        dispatch_byte_output_exact_no_input(
            h_session,
            ByteOutputFunction::EncryptFinal,
            p_last_encrypted_part,
            pul_last_encrypted_part_len,
        )
    })
}

pub unsafe extern "C" fn c_decrypt_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panics(|| {
        if p_mechanism.is_null() {
            let result = with_client!(client => client.decrypt_init_cancel(CkSessionHandle(h_session as u64)));
            if result.is_ok() {
                state::clear_decrypt_output_caches(h_session);
                state::clear_operation_state_cache(h_session);
            }
            return unit_result_to_rv(result);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = match unsafe { read_mechanism(p_mechanism) } {
            Ok(mech) => mech,
            Err(e) => return rv_err(e),
        };
        let result = with_client!(client => client.decrypt_init(
            CkSessionHandle(h_session as u64),
            &mech,
            CkObjectHandle(h_key as u64),
        ));
        if result.is_ok() {
            state::clear_decrypt_output_caches(h_session);
            state::clear_operation_state_cache(h_session);
        }
        unit_result_to_rv(result)
    })
}

pub unsafe extern "C" fn c_decrypt(
    h_session: CK_SESSION_HANDLE,
    p_encrypted_data: CK_BYTE_PTR,
    ul_encrypted_data_len: CK_ULONG,
    p_data: CK_BYTE_PTR,
    pul_data_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| unsafe {
        dispatch_byte_output_exact(
            h_session,
            ByteOutputFunction::Decrypt,
            p_encrypted_data,
            ul_encrypted_data_len,
            p_data,
            pul_data_len,
        )
    })
}

pub unsafe extern "C" fn c_decrypt_update(
    h_session: CK_SESSION_HANDLE,
    p_encrypted_part: CK_BYTE_PTR,
    ul_encrypted_part_len: CK_ULONG,
    p_part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| unsafe {
        dispatch_byte_output_exact(
            h_session,
            ByteOutputFunction::DecryptUpdate,
            p_encrypted_part,
            ul_encrypted_part_len,
            p_part,
            pul_part_len,
        )
    })
}

pub unsafe extern "C" fn c_decrypt_final(
    h_session: CK_SESSION_HANDLE,
    p_last_part: CK_BYTE_PTR,
    pul_last_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| unsafe {
        dispatch_byte_output_exact_no_input(
            h_session,
            ByteOutputFunction::DecryptFinal,
            p_last_part,
            pul_last_part_len,
        )
    })
}

// ---------------------------------------------------------------------------
// Slot events
// ---------------------------------------------------------------------------
