use super::{FfiBackend, call_3x_fn};
use pkcs11_proxy_ng_types::*;

impl FfiBackend {
    pub(super) fn ffi_login_user(
        &self,
        session: CkSessionHandle,
        user_type: CkUserType,
        username: &[u8],
        pin: &[u8],
    ) -> CkResult<()> {
        // C_LoginUser(hSession, userType, pPin, ulPinLen, pUsername, ulUsernameLen)
        // PIN comes before username per OASIS PKCS#11 3.0 spec.
        call_3x_fn!(
            self,
            func_list_3_0,
            C_LoginUser,
            Self::session_handle(session),
            user_type as cryptoki_sys::CK_USER_TYPE,
            pin.as_ptr() as *mut cryptoki_sys::CK_UTF8CHAR,
            Self::ulong_len(pin.len()),
            username.as_ptr() as *mut cryptoki_sys::CK_UTF8CHAR,
            Self::ulong_len(username.len())
        )
    }

    pub(super) fn ffi_session_cancel(
        &self,
        session: CkSessionHandle,
        flags: CkFlags,
    ) -> CkResult<()> {
        call_3x_fn!(
            self,
            func_list_3_0,
            C_SessionCancel,
            Self::session_handle(session),
            flags.0 as cryptoki_sys::CK_FLAGS
        )
    }

    pub(super) fn ffi_get_session_validation_flags(
        &self,
        session: CkSessionHandle,
        flags_type: u64,
    ) -> CkResult<u64> {
        let mut flags: cryptoki_sys::CK_FLAGS = 0;
        call_3x_fn!(
            self,
            func_list_3_2,
            C_GetSessionValidationFlags,
            Self::session_handle(session),
            flags_type as cryptoki_sys::CK_SESSION_VALIDATION_FLAGS_TYPE,
            &mut flags
        )?;
        Ok(flags as u64)
    }
}
