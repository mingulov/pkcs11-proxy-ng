use super::{FfiBackend, call_3x_fn, ffi_conversion::narrow_wire_ulong};
use pkcs11_proxy_ng_types::*;

impl FfiBackend {
    pub(super) fn ffi_login_user(
        &self,
        session: CkSessionHandle,
        user_type: CkUserType,
        username: &[u8],
        pin: &[u8],
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        // C_LoginUser(hSession, userType, pPin, ulPinLen, pUsername, ulUsernameLen)
        // PIN comes before username per OASIS PKCS#11 3.0 spec.
        let _session_fence = self.session_fences.enter(&admission, session)?;
        call_3x_fn!(
            &admission,
            self,
            func_list_3_0,
            C_LoginUser,
            Self::session_handle(session)?,
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
        let flags = narrow_wire_ulong(flags.0)?;
        call_3x_fn!(self, func_list_3_0, C_SessionCancel, Self::session_handle(session)?, flags)
    }

    pub(super) fn ffi_get_session_validation_flags(
        &self,
        session: CkSessionHandle,
        flags_type: u64,
    ) -> CkResult<u64> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let mut flags: cryptoki_sys::CK_FLAGS = 0;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        call_3x_fn!(
            &admission,
            self,
            func_list_3_2,
            C_GetSessionValidationFlags,
            Self::session_handle(session)?,
            flags_type as cryptoki_sys::CK_SESSION_VALIDATION_FLAGS_TYPE,
            &mut flags
        )?;
        Ok(flags as u64)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SESSION_CANCEL_PROVIDER_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn counted_session_cancel(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _flags: cryptoki_sys::CK_FLAGS,
    ) -> cryptoki_sys::CK_RV {
        SESSION_CANCEL_PROVIDER_CALLS.fetch_add(1, Ordering::SeqCst);
        cryptoki_sys::CKR_OK
    }

    fn backend_with_session_cancel()
    -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>, Box<cryptoki_sys::CK_FUNCTION_LIST_3_0>)
    {
        let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_0::default());
        functions.C_SessionCancel = Some(counted_session_cancel);
        let backend = FfiBackend {
            _lib: libloading::os::unix::Library::this().into(),
            func_list: base.as_mut(),
            func_list_3_0: Some(functions.as_ref()),
            func_list_3_2: None,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            // Test-local backend: bypasses the process reservation without
            // consuming it; never backs production dispatch (C3M.4).
            construction: crate::ffi::native_domain::ConstructionPermit::unmanaged_test_only(),
            lifecycle: Default::default(),
        };
        (backend, base, functions)
    }

    #[test]
    fn session_cancel_flags_wider_than_native_are_rejected_before_provider_call() {
        SESSION_CANCEL_PROVIDER_CALLS.store(0, Ordering::SeqCst);
        let (backend, _base, _functions) = backend_with_session_cancel();
        let over_u32 = u32::MAX as u64 + 1;

        let result = backend.ffi_session_cancel(CkSessionHandle(7), CkFlags(over_u32));

        if std::mem::size_of::<cryptoki_sys::CK_ULONG>() == 4 {
            assert_eq!(result, Err(CkRv::FUNCTION_FAILED));
            assert_eq!(SESSION_CANCEL_PROVIDER_CALLS.load(Ordering::SeqCst), 0);
        } else {
            assert_eq!(result, Ok(()));
            assert_eq!(SESSION_CANCEL_PROVIDER_CALLS.load(Ordering::SeqCst), 1);
        }
    }
}
