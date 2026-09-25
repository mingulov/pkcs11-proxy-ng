use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use crate::state;

#[allow(unused_imports)]
use super::*;

pub unsafe extern "C" fn c_sign_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panics(|| {
        if p_mechanism.is_null() {
            let result =
                with_client!(client => client.sign_init_cancel(CkSessionHandle(h_session as u64)));
            if result.is_ok() {
                state::clear_sign_output_caches(h_session);
                state::clear_operation_state_cache(h_session);
            }
            return unit_result_to_rv(result);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        let result = with_client!(client => client.sign_init(
            CkSessionHandle(h_session as u64),
            &mech,
            CkObjectHandle(h_key as u64),
        ));
        if result.is_ok() {
            state::clear_sign_output_caches(h_session);
            state::clear_operation_state_cache(h_session);
        }
        unit_result_to_rv(result)
    })
}

pub unsafe extern "C" fn c_sign(
    h_session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_signature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if pul_signature_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let data = match input_buf_to_ck_in_buf(unsafe { classify_input(p_data, ul_data_len) }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        let spec = unsafe { output_buffer_spec(p_signature, pul_signature_len) };
        let result = with_client!(client => client.byte_output_exact(
            CkSessionHandle(h_session as u64),
            ByteOutputFunction::Sign,
            &spec,
            data,
            None,
            0,
            0,
        ));
        match result {
            Ok(r) => unsafe { write_exact_output(&spec, &r, p_signature, pul_signature_len) },
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_sign_update(
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
            with_client!(client => client.sign_update(CkSessionHandle(h_session as u64), part)),
        )
    })
}

pub unsafe extern "C" fn c_sign_final(
    h_session: CK_SESSION_HANDLE,
    p_signature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        let spec = unsafe { output_buffer_spec(p_signature, pul_signature_len) };
        let result = with_client!(client => client.byte_output_exact(
            CkSessionHandle(h_session as u64),
            ByteOutputFunction::SignFinal,
            &spec,
            CkInBuf::Bytes(&[]),
            None,
            0,
            0,
        ));
        match result {
            Ok(r) => unsafe { write_exact_output(&spec, &r, p_signature, pul_signature_len) },
            Err(e) => rv_err(e),
        }
    })
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_verify_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panics(|| {
        if p_mechanism.is_null() {
            let result = with_client!(client => client.verify_init_cancel(CkSessionHandle(h_session as u64)));
            if result.is_ok() {
                state::clear_operation_state_cache(h_session);
            }
            return unit_result_to_rv(result);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        unit_result_to_rv(with_client!(client => client.verify_init(
            CkSessionHandle(h_session as u64),
            &mech,
            CkObjectHandle(h_key as u64),
        )))
    })
}

pub unsafe extern "C" fn c_verify(
    h_session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_signature: CK_BYTE_PTR,
    ul_signature_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
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
        unit_result_to_rv(with_client!(client => client.verify(
            CkSessionHandle(h_session as u64),
            data,
            signature,
        )))
    })
}

pub unsafe extern "C" fn c_verify_update(
    h_session: CK_SESSION_HANDLE,
    p_part: CK_BYTE_PTR,
    ul_part_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let part = match input_buf_to_ck_in_buf(unsafe { classify_input(p_part, ul_part_len) }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        unit_result_to_rv(with_client!(client => client.verify_update(
            CkSessionHandle(h_session as u64),
            part,
        )))
    })
}

pub unsafe extern "C" fn c_verify_final(
    h_session: CK_SESSION_HANDLE,
    p_signature: CK_BYTE_PTR,
    ul_signature_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let signature = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_signature, ul_signature_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        unit_result_to_rv(with_client!(client => client.verify_final(
            CkSessionHandle(h_session as u64),
            signature,
        )))
    })
}

// ---------------------------------------------------------------------------
// Recovery signatures
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_sign_recover_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panics(|| {
        if p_mechanism.is_null() {
            let result = with_client!(client => client.sign_recover_init_cancel(CkSessionHandle(h_session as u64)));
            if result.is_ok() {
                state::clear_sign_recover_output_cache(h_session);
                state::clear_operation_state_cache(h_session);
            }
            return unit_result_to_rv(result);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        let result = with_client!(client => client.sign_recover_init(
            CkSessionHandle(h_session as u64),
            &mech,
            CkObjectHandle(h_key as u64),
        ));
        if result.is_ok() {
            state::clear_sign_recover_output_cache(h_session);
            state::clear_operation_state_cache(h_session);
        }
        unit_result_to_rv(result)
    })
}

pub unsafe extern "C" fn c_sign_recover(
    h_session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_signature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if pul_signature_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let data = match input_buf_to_ck_in_buf(unsafe { classify_input(p_data, ul_data_len) }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        let spec = unsafe { output_buffer_spec(p_signature, pul_signature_len) };
        let result = with_client!(client => client.byte_output_exact(
            CkSessionHandle(h_session as u64),
            ByteOutputFunction::SignRecover,
            &spec,
            data,
            None,
            0,
            0,
        ));
        match result {
            Ok(r) => unsafe { write_exact_output(&spec, &r, p_signature, pul_signature_len) },
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_verify_recover_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panics(|| {
        if p_mechanism.is_null() {
            let result = with_client!(client => client.verify_recover_init_cancel(
                CkSessionHandle(h_session as u64)
            ));
            if result.is_ok() {
                state::clear_verify_recover_output_cache(h_session);
                state::clear_operation_state_cache(h_session);
            }
            return unit_result_to_rv(result);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        let result = with_client!(client => client.verify_recover_init(
            CkSessionHandle(h_session as u64),
            &mech,
            CkObjectHandle(h_key as u64),
        ));
        if result.is_ok() {
            state::clear_verify_recover_output_cache(h_session);
            state::clear_operation_state_cache(h_session);
        }
        unit_result_to_rv(result)
    })
}

pub unsafe extern "C" fn c_verify_recover(
    h_session: CK_SESSION_HANDLE,
    p_signature: CK_BYTE_PTR,
    ul_signature_len: CK_ULONG,
    p_data: CK_BYTE_PTR,
    pul_data_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if pul_data_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let signature = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_signature, ul_signature_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        let spec = unsafe { output_buffer_spec(p_data, pul_data_len) };
        let result = with_client!(client => client.byte_output_exact(
            CkSessionHandle(h_session as u64),
            ByteOutputFunction::VerifyRecover,
            &spec,
            signature,
            None,
            0,
            0,
        ));
        match result {
            Ok(r) => unsafe { write_exact_output(&spec, &r, p_data, pul_data_len) },
            Err(e) => rv_err(e),
        }
    })
}

// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------
