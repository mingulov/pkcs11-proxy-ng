// CK_ULONG is u64 on 64-bit and u32 on 32-bit; `as u64` casts are intentional
// for cross-platform PKCS#11 portability.
#![allow(clippy::unnecessary_cast)]

use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use crate::state;

#[allow(unused_imports)]
use super::*;

pub unsafe extern "C" fn c_digest_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
) -> CK_RV {
    catch_panics(|| {
        if p_mechanism.is_null() {
            let result =
                with_client!(client => client.digest_init_cancel(CkSessionHandle(h_session)));
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
        let mech = unsafe { read_mechanism(p_mechanism) };
        let result = with_client!(client => client.digest_init(CkSessionHandle(h_session), &mech));
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
    catch_panics(|| {
        if pul_digest_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let data = unsafe { read_input_slice(p_data, ul_data_len) };
        let spec = unsafe { output_buffer_spec(p_digest, pul_digest_len) };
        let result = with_client!(client => client.byte_output_exact(
            CkSessionHandle(h_session),
            ByteOutputFunction::Digest,
            &spec,
            data,
            None,
            0,
            0,
        ));
        match result {
            Ok(r) => unsafe { write_exact_output(&r, p_digest, pul_digest_len) },
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_digest_update(
    h_session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    ul_part_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let part = unsafe { read_input_slice(p_part, ul_part_len) };
        unit_result_to_rv(
            with_client!(client => client.digest_update(CkSessionHandle(h_session), part)),
        )
    })
}

pub unsafe extern "C" fn c_digest_key(
    h_session: CK_SESSION_HANDLE,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(with_client!(client => client.digest_key(
            CkSessionHandle(h_session),
            CkObjectHandle(h_key),
        )))
    })
}

pub unsafe extern "C" fn c_digest_final(
    h_session: CK_SESSION_HANDLE,
    p_digest: CK_BYTE_PTR,
    pul_digest_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if pul_digest_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let spec = unsafe { output_buffer_spec(p_digest, pul_digest_len) };
        let result = with_client!(client => client.byte_output_exact(
            CkSessionHandle(h_session),
            ByteOutputFunction::DigestFinal,
            &spec,
            &[],
            None,
            0,
            0,
        ));
        match result {
            Ok(r) => unsafe { write_exact_output(&r, p_digest, pul_digest_len) },
            Err(e) => rv_err(e),
        }
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
            let result =
                with_client!(client => client.encrypt_init_cancel(CkSessionHandle(h_session)));
            if result.is_ok() {
                state::clear_delayed_gcm_writeback(h_session);
                state::clear_encrypt_output_caches(h_session);
                state::clear_operation_state_cache(h_session);
            }
            return unit_result_to_rv(result);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        let delayed_gcm_param = unsafe { delayed_gcm_parameter_addr(p_mechanism) };
        state::clear_delayed_gcm_writeback(h_session);
        let result = with_client!(client => client.encrypt_init(
            CkSessionHandle(h_session),
            &mech,
            CkObjectHandle(h_key),
        ));
        match result {
            Ok(output_params) => {
                if let Some(param_addr) = delayed_gcm_param {
                    state::remember_delayed_gcm_writeback(h_session, param_addr);
                }
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
    catch_panics(|| {
        if pul_encrypted_data_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let data = unsafe { read_input_slice(p_data, ul_data_len) };
        let spec = unsafe { output_buffer_spec(p_encrypted_data, pul_encrypted_data_len) };
        let result = with_client!(client => client.byte_output_exact_with_mechanism_out(
            CkSessionHandle(h_session),
            ByteOutputFunction::Encrypt,
            &spec,
            data,
            None,
            0,
            0,
        ));
        match result {
            Ok((r, mechanism_out)) => {
                let rv =
                    unsafe { write_exact_output(&r, p_encrypted_data, pul_encrypted_data_len) };
                if rv == rv_ok() && spec.buffer_present {
                    let delayed_gcm_param = state::take_delayed_gcm_writeback(h_session);
                    if let (Some(param_addr), Some(params)) = (delayed_gcm_param, mechanism_out) {
                        unsafe { write_delayed_gcm_output_params(param_addr, &params) };
                    }
                }
                rv
            }
            Err(e) => rv_err(e),
        }
    })
}

pub(super) unsafe fn delayed_gcm_parameter_addr(p_mechanism: CK_MECHANISM_PTR) -> Option<usize> {
    if p_mechanism.is_null() {
        return None;
    }
    let mechanism = unsafe { &*p_mechanism };
    if mechanism.mechanism != CKM_AES_GCM
        || mechanism.pParameter.is_null()
        || mechanism.ulParameterLen < std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG
    {
        return None;
    }

    let gcm = unsafe { &*(mechanism.pParameter as *const CK_GCM_PARAMS) };
    if gcm.pIv.is_null() {
        return None;
    }
    let capacity = if gcm.ulIvLen > 0 {
        gcm.ulIvLen as usize
    } else {
        (((gcm.ulIvBits as u64).saturating_add(7)) / 8) as usize
    };
    if capacity == 0 { None } else { Some(mechanism.pParameter as usize) }
}

pub(super) unsafe fn write_delayed_gcm_output_params(
    param_addr: usize,
    params: &CkMechanismParams,
) {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: param_addr as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    unsafe { write_mechanism_output_params(&mut mechanism, params) };
}

pub unsafe extern "C" fn c_encrypt_update(
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
            ByteOutputFunction::EncryptUpdate,
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

pub unsafe extern "C" fn c_encrypt_final(
    h_session: CK_SESSION_HANDLE,
    p_last_encrypted_part: CK_BYTE_PTR,
    pul_last_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if pul_last_encrypted_part_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let spec =
            unsafe { output_buffer_spec(p_last_encrypted_part, pul_last_encrypted_part_len) };
        let result = with_client!(client => client.byte_output_exact(
            CkSessionHandle(h_session),
            ByteOutputFunction::EncryptFinal,
            &spec,
            &[],
            None,
            0,
            0,
        ));
        match result {
            Ok(r) => unsafe {
                write_exact_output(&r, p_last_encrypted_part, pul_last_encrypted_part_len)
            },
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_decrypt_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panics(|| {
        if p_mechanism.is_null() {
            let result =
                with_client!(client => client.decrypt_init_cancel(CkSessionHandle(h_session)));
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
        let mech = unsafe { read_mechanism(p_mechanism) };
        let result = with_client!(client => client.decrypt_init(
            CkSessionHandle(h_session),
            &mech,
            CkObjectHandle(h_key),
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
    catch_panics(|| {
        if pul_data_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let encrypted_data = unsafe { read_input_slice(p_encrypted_data, ul_encrypted_data_len) };
        let spec = unsafe { output_buffer_spec(p_data, pul_data_len) };
        let result = with_client!(client => client.byte_output_exact(
            CkSessionHandle(h_session),
            ByteOutputFunction::Decrypt,
            &spec,
            encrypted_data,
            None,
            0,
            0,
        ));
        match result {
            Ok(r) => unsafe { write_exact_output(&r, p_data, pul_data_len) },
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_decrypt_update(
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
            ByteOutputFunction::DecryptUpdate,
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

pub unsafe extern "C" fn c_decrypt_final(
    h_session: CK_SESSION_HANDLE,
    p_last_part: CK_BYTE_PTR,
    pul_last_part_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if pul_last_part_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let spec = unsafe { output_buffer_spec(p_last_part, pul_last_part_len) };
        let result = with_client!(client => client.byte_output_exact(
            CkSessionHandle(h_session),
            ByteOutputFunction::DecryptFinal,
            &spec,
            &[],
            None,
            0,
            0,
        ));
        match result {
            Ok(r) => unsafe { write_exact_output(&r, p_last_part, pul_last_part_len) },
            Err(e) => rv_err(e),
        }
    })
}

// ---------------------------------------------------------------------------
// Slot events
// ---------------------------------------------------------------------------
