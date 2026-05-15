//! Shim dispatch for PKCS#11 3.0/3.2 session extension functions (Wave 1).
//!
//! - `C_LoginUser`
//! - `C_SessionCancel`
//! - `C_GetSessionValidationFlags`

use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

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
        let ut = match CkUserType::from_raw(user_type) {
            Some(ut) => ut,
            None => return rv_err(CkRv::USER_TYPE_INVALID),
        };
        let pin = unsafe { read_input_slice(p_pin, ul_pin_len) };
        let username = unsafe { read_input_slice(p_username, ul_username_len) };
        unit_result_to_rv(
            with_client!(client => client.login_user(CkSessionHandle(h_session), ut, username, pin)),
        )
    })
}

pub unsafe extern "C" fn c_session_cancel(h_session: CK_SESSION_HANDLE, flags: CK_FLAGS) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(
            with_client!(client => client.session_cancel(CkSessionHandle(h_session), CkFlags(flags))),
        )
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
            CkSessionHandle(h_session), flags_type
        )) {
            Ok(flags) => {
                unsafe { *p_flags = flags };
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}
