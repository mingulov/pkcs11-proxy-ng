//! Shim dispatch for PKCS#11 3.0/3.2 session extension functions (Wave 1).
//!
//! - `C_LoginUser`
//! - `C_SessionCancel`
//! - `C_GetSessionValidationFlags`

use cryptoki_sys::*;
use pkcs11_proxy_ng_client::MessageCallErrorOrigin;
use pkcs11_proxy_ng_types::*;

use crate::state;

use super::helpers::*;

pub unsafe extern "C" fn c_login_user(
    h_session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    p_pin: *mut CK_UTF8CHAR,
    ul_pin_len: CK_ULONG,
    p_username: *mut CK_UTF8CHAR,
    ul_username_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let ut = match CkUserType::from_raw(user_type.into()) {
            Some(ut) => ut,
            None => return rv_err(CkRv::USER_TYPE_INVALID),
        };
        let pin = unsafe { read_input_slice(p_pin, ul_pin_len) };
        let username = unsafe { read_input_slice(p_username, ul_username_len) };
        unit_result_to_rv(
            with_client!(client => client.login_user(CkSessionHandle(h_session as u64), ut, username, pin)),
        )
    })
}

pub unsafe extern "C" fn c_session_cancel(h_session: CK_SESSION_HANDLE, flags: CK_FLAGS) -> CK_RV {
    catch_panics(|| {
        if !state::is_initialized() {
            return rv_err(CkRv::CRYPTOKI_NOT_INITIALIZED);
        }
        let message_flags =
            CKF_MESSAGE_ENCRYPT | CKF_MESSAGE_DECRYPT | CKF_MESSAGE_SIGN | CKF_MESSAGE_VERIFY;
        if flags & message_flags != 0 && !crate::interface_probe::pointer_safe_message_parameters()
        {
            return rv_err(CkRv::FUNCTION_NOT_SUPPORTED);
        }
        let operation_states = [
            (CKF_MESSAGE_ENCRYPT, state::MessageOperation::Encrypt),
            (CKF_MESSAGE_DECRYPT, state::MessageOperation::Decrypt),
            (CKF_MESSAGE_SIGN, state::MessageOperation::Sign),
            (CKF_MESSAGE_VERIFY, state::MessageOperation::Verify),
        ]
        .into_iter()
        .filter(|(flag, _)| flags & *flag != 0)
        .map(|(_, operation)| state::message_operation_state(h_session, operation))
        .collect::<Vec<_>>();
        let mut operation_guards = Vec::with_capacity(operation_states.len());
        for operation_state in &operation_states {
            let Ok(guard) = operation_state.lock() else {
                return rv_err(CkRv::GENERAL_ERROR);
            };
            operation_guards.push(guard);
        }
        let saved_shapes =
            operation_guards.iter_mut().map(|operation| operation.shape.take()).collect::<Vec<_>>();

        let result = with_client!(client => client.session_cancel_stateful(
            CkSessionHandle(h_session as u64),
            CkFlags(flags as u64),
        ));
        if let Err(error) = &result
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

pub unsafe extern "C" fn c_get_session_validation_flags(
    h_session: CK_SESSION_HANDLE,
    flags_type: CK_SESSION_VALIDATION_FLAGS_TYPE,
    p_flags: *mut CK_FLAGS,
) -> CK_RV {
    catch_panics(|| {
        if p_flags.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        match with_client!(client => client.get_session_validation_flags(
            CkSessionHandle(h_session as u64), flags_type.into()
        )) {
            Ok(flags) => {
                // CK_FLAGS is u32 on narrow-CK_ULONG targets; flags are 32-bit
                // bitmasks per spec, so the wire u64 narrows losslessly.
                unsafe { *p_flags = flags as CK_FLAGS };
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}
