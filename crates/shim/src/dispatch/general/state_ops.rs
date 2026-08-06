use cryptoki_sys::*;
use pkcs11_proxy_ng_client::MessageCallErrorOrigin;
use pkcs11_proxy_ng_types::*;

use crate::state;

#[allow(unused_imports)]
use super::*;

pub unsafe extern "C" fn c_wait_for_slot_event(
    flags: CK_FLAGS,
    p_slot: CK_SLOT_ID_PTR,
    p_reserved: CK_VOID_PTR,
) -> CK_RV {
    catch_panics(|| {
        if p_slot.is_null() || !p_reserved.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        match with_client!(client => client.wait_for_slot_event(flags.into())) {
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
            CkSessionHandle(h_session as u64),
            ByteOutputFunction::GetOperationState,
            &spec,
            CkInBuf::Bytes(&[]),
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
        let operation_states = [
            state::MessageOperation::Encrypt,
            state::MessageOperation::Decrypt,
            state::MessageOperation::Sign,
            state::MessageOperation::Verify,
        ]
        .map(|operation| state::message_operation_state(h_session, operation));
        let mut operation_guards = Vec::with_capacity(operation_states.len());
        for operation_state in &operation_states {
            let Ok(guard) = operation_state.lock() else {
                return rv_err(CkRv::GENERAL_ERROR);
            };
            operation_guards.push(guard);
        }
        let state_bytes = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_operation_state, ul_operation_state_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        let saved_shapes =
            operation_guards.iter_mut().map(|operation| operation.shape.take()).collect::<Vec<_>>();
        let result = with_client!(client => client.set_operation_state_stateful(
            CkSessionHandle(h_session as u64),
            state_bytes,
            CkObjectHandle(h_encryption_key as u64),
            CkObjectHandle(h_authentication_key as u64),
        ));
        if result.is_ok() {
            state::evict_session_output_caches(h_session);
        } else if let Err(error) = &result
            && error.origin == MessageCallErrorOrigin::Backend
            && error.ck_rv != CkRv::DEVICE_ERROR
        {
            for (operation, saved_shape) in
                operation_guards.iter_mut().zip(saved_shapes.into_iter())
            {
                operation.shape = saved_shape;
            }
        }
        unit_result_to_rv(result.map_err(|error| error.ck_rv))
    })
}

// ---------------------------------------------------------------------------
// Key management / RNG
// ---------------------------------------------------------------------------
