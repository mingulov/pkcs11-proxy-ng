use cryptoki_sys::*;
use pkcs11_proxy_ng_client::MessageCallErrorOrigin;
use pkcs11_proxy_ng_types::*;

use crate::state;

use super::helpers::{
    catch_panics, classify_input, dispatch_byte_output_exact_no_input, input_buf_to_ck_in_buf,
    rv_err, rv_ok, unit_result_to_rv, with_client,
};

pub unsafe extern "C" fn c_wait_for_slot_event(
    flags: CK_FLAGS,
    p_slot: CK_SLOT_ID_PTR,
    p_reserved: CK_VOID_PTR,
) -> CK_RV {
    catch_panics(|| {
        if p_slot.is_null() || !p_reserved.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        // Ownership §"Slot-event scope": the response RV and — on success —
        // the virtual slot are checked against the CALLER width before
        // anything is written. Unrepresentable values answer local
        // FUNCTION_FAILED with pSlot untouched; a nonzero wide error is
        // never truncated into CKR_OK, and a wide slot never into a wrong
        // slot. Error paths never touch the output-only caller buffer.
        match with_client!(client => client.wait_for_slot_event(flags.into())) {
            Ok(slot) => {
                let Some(narrow) = pkcs11_proxy_ng_types::width::checked_narrow_to_width(
                    slot.0,
                    std::mem::size_of::<CK_SLOT_ID>(),
                ) else {
                    return rv_err(CkRv::FUNCTION_FAILED);
                };
                unsafe {
                    *p_slot = narrow as CK_SLOT_ID;
                }
                rv_ok()
            }
            Err(e) => {
                if pkcs11_proxy_ng_types::width::checked_narrow_to_width(
                    e.0,
                    std::mem::size_of::<CK_RV>(),
                )
                .is_none()
                {
                    return rv_err(CkRv::FUNCTION_FAILED);
                }
                rv_err(e)
            }
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
    catch_panics(|| unsafe {
        dispatch_byte_output_exact_no_input(
            h_session,
            ByteOutputFunction::GetOperationState,
            p_operation_state,
            pul_operation_state_len,
        )
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
