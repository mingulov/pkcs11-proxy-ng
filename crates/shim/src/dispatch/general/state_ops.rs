use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use crate::state;

#[allow(unused_imports)]
use super::*;

pub unsafe extern "C" fn c_wait_for_slot_event(
    flags: CK_FLAGS,
    p_slot: CK_SLOT_ID_PTR,
    _p_reserved: CK_VOID_PTR,
) -> CK_RV {
    catch_panics(|| {
        if p_slot.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        match with_client!(client => client.wait_for_slot_event(flags)) {
            Ok(slot) => {
                unsafe {
                    *p_slot = slot.0 as CK_SLOT_ID;
                }
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

// ---------------------------------------------------------------------------
// State management
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_get_operation_state(
    h_session: CK_SESSION_HANDLE,
    p_operation_state: CK_BYTE_PTR,
    pul_operation_state_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if pul_operation_state_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let spec = unsafe { output_buffer_spec(p_operation_state, pul_operation_state_len) };
        let result = with_client!(client => client.byte_output_exact(
            CkSessionHandle(h_session),
            ByteOutputFunction::GetOperationState,
            &spec,
            &[],
            None,
            0,
            0,
        ));
        match result {
            Ok(r) => unsafe { write_exact_output(&r, p_operation_state, pul_operation_state_len) },
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_set_operation_state(
    h_session: CK_SESSION_HANDLE,
    p_operation_state: CK_BYTE_PTR,
    ul_operation_state_len: CK_ULONG,
    h_encryption_key: CK_OBJECT_HANDLE,
    h_authentication_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panics(|| {
        if p_operation_state.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let state_bytes = unsafe { read_input_slice(p_operation_state, ul_operation_state_len) };
        let result = with_client!(client => client.set_operation_state(
            CkSessionHandle(h_session),
            state_bytes,
            CkObjectHandle(h_encryption_key),
            CkObjectHandle(h_authentication_key),
        ));
        if result.is_ok() {
            state::evict_session_caches(h_session);
        }
        unit_result_to_rv(result)
    })
}

// ---------------------------------------------------------------------------
// Key management / RNG
// ---------------------------------------------------------------------------
