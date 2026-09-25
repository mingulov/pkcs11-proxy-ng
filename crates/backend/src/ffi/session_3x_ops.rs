use super::{FfiBackend, call_3x_fn, ffi_conversion::narrow_wire_ulong};
use pkcs11_proxy_ng_types::*;

impl FfiBackend {
    pub(super) fn ffi_login_user(
        &self,
        session: CkSessionHandle,
        user_type: CkUserType,
        username: Option<&[u8]>,
        pin: Option<&[u8]>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        // C_LoginUser(hSession, userType, pPin, ulPinLen, pUsername, ulUsernameLen)
        // PIN comes before username per OASIS PKCS#11 3.0 spec.
        // W1-C6-07: NULL pin/username (protected path) stays NULL at the
        // provider boundary, exactly like `ffi_login` — never an empty slice.
        let (pin_ptr, pin_len) = match pin {
            Some(p) => (p.as_ptr() as *mut cryptoki_sys::CK_UTF8CHAR, Self::ulong_len(p.len())),
            None => (std::ptr::null_mut(), 0),
        };
        let (username_ptr, username_len) = match username {
            Some(u) => (u.as_ptr() as *mut cryptoki_sys::CK_UTF8CHAR, Self::ulong_len(u.len())),
            None => (std::ptr::null_mut(), 0),
        };
        let _session_fence = self.session_fences.enter(&admission, session)?;
        call_3x_fn!(
            &admission,
            self,
            func_list_3_0,
            C_LoginUser,
            Self::session_handle(session)?,
            user_type as cryptoki_sys::CK_USER_TYPE,
            pin_ptr,
            pin_len,
            username_ptr,
            username_len
        )
    }

    pub(super) fn ffi_session_cancel(
        &self,
        session: CkSessionHandle,
        flags: CkFlags,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let flags = narrow_wire_ulong(flags.0)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        call_3x_fn!(
            &admission,
            self,
            func_list_3_0,
            C_SessionCancel,
            Self::session_handle(session)?,
            flags
        )
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
    // The cancel counter is process-wide while tests run on parallel
    // threads: every test asserting absolute counts holds this lock from
    // reset through final read (repo-wide TEST_LOCK convention).
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe extern "C" fn counted_session_cancel(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _flags: cryptoki_sys::CK_FLAGS,
    ) -> cryptoki_sys::CK_RV {
        SESSION_CANCEL_PROVIDER_CALLS.fetch_add(1, Ordering::SeqCst);
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn login_user_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _user_type: cryptoki_sys::CK_USER_TYPE,
        _pin: cryptoki_sys::CK_UTF8CHAR_PTR,
        _pin_len: cryptoki_sys::CK_ULONG,
        _username: cryptoki_sys::CK_UTF8CHAR_PTR,
        _username_len: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    /// Per-call provider observations: (pin_is_null, pin_len, username_is_null,
    /// username_len). Presence + lengths only — the provider stub never
    /// retains credential bytes. Guarded by TEST_LOCK like the cancel counter.
    static LOGIN_USER_OBSERVED: std::sync::Mutex<Vec<(bool, u64, bool, u64)>> =
        std::sync::Mutex::new(Vec::new());

    unsafe extern "C" fn login_user_capture(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _user_type: cryptoki_sys::CK_USER_TYPE,
        pin: cryptoki_sys::CK_UTF8CHAR_PTR,
        pin_len: cryptoki_sys::CK_ULONG,
        username: cryptoki_sys::CK_UTF8CHAR_PTR,
        username_len: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        LOGIN_USER_OBSERVED.lock().unwrap().push((
            pin.is_null(),
            pin_len as u64,
            username.is_null(),
            username_len as u64,
        ));
        cryptoki_sys::CKR_OK
    }

    fn backend_with_session_cancel()
    -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>, Box<cryptoki_sys::CK_FUNCTION_LIST_3_0>)
    {
        let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_0::default());
        functions.C_SessionCancel = Some(counted_session_cancel);
        functions.C_LoginUser = Some(login_user_ok);
        let backend =
            FfiBackend::test_backend_with_tables(base.as_mut(), Some(functions.as_ref()), None);
        (backend, base, functions)
    }

    #[test]
    fn session_cancel_flags_wider_than_native_are_rejected_before_provider_call() {
        let _lock = TEST_LOCK.lock().unwrap();
        SESSION_CANCEL_PROVIDER_CALLS.store(0, Ordering::SeqCst);
        let (backend, _base, _functions) = backend_with_session_cancel();
        // Cancel paths are ordinary: establish post-Initialize state
        // (admission precedes checked narrowing at the boundary).
        backend.lifecycle_domain.open_for_tests();
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

    #[test]
    fn login_user_denied_before_lifecycle_open() {
        // TF01b `call_3x_fn!` ordinary proof (3.0 session op): no admission
        // pre-Init.
        let (backend, _base, _functions) = backend_with_session_cancel();
        assert_eq!(
            backend
                .ffi_login_user(CkSessionHandle(7), CkUserType::User, Some(b"name"), Some(b"1234"))
                .unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn login_user_admitted_after_lifecycle_open() {
        // Control: the same call reaches the stub once the domain is open.
        let (backend, _base, _functions) = backend_with_session_cancel();
        backend.lifecycle_domain.open_for_tests();
        backend
            .ffi_login_user(CkSessionHandle(7), CkUserType::User, Some(b"name"), Some(b"1234"))
            .unwrap();
    }

    /// W1-C6-07: None pin/username must reach the provider as NULL with
    /// zero length (the `ffi_login` convention), while Some reaches it as
    /// a live pointer — the two classes stay distinguishable at the FFI
    /// boundary, exactly like `C_Login`.
    #[test]
    fn login_user_none_reaches_provider_as_null() {
        let _lock = TEST_LOCK.lock().unwrap();
        LOGIN_USER_OBSERVED.lock().unwrap().clear();
        let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_0::default());
        functions.C_LoginUser = Some(login_user_capture);
        let backend =
            FfiBackend::test_backend_with_tables(base.as_mut(), Some(functions.as_ref()), None);
        backend.lifecycle_domain.open_for_tests();

        backend.ffi_login_user(CkSessionHandle(7), CkUserType::User, None, None).unwrap();
        backend.ffi_login_user(CkSessionHandle(7), CkUserType::User, Some(b""), Some(b"")).unwrap();
        backend
            .ffi_login_user(CkSessionHandle(7), CkUserType::User, Some(b"name"), Some(b"1234"))
            .unwrap();

        assert_eq!(
            *LOGIN_USER_OBSERVED.lock().unwrap(),
            vec![(true, 0, true, 0), (false, 0, false, 0), (false, 4, false, 4)],
            "None must arrive as NULL+0, Some as live pointer + len"
        );
    }

    #[test]
    fn session_cancel_denied_before_lifecycle_open() {
        // TF01b cancel re-home (fence-read session activity): no admission
        // pre-Init.
        let _lock = TEST_LOCK.lock().unwrap();
        SESSION_CANCEL_PROVIDER_CALLS.store(0, Ordering::SeqCst);
        let (backend, _base, _functions) = backend_with_session_cancel();
        assert_eq!(
            backend.ffi_session_cancel(CkSessionHandle(7), CkFlags(0)).unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
        assert_eq!(SESSION_CANCEL_PROVIDER_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn session_cancel_admitted_after_lifecycle_open() {
        // Control: the same call reaches the stub once the domain is open.
        let _lock = TEST_LOCK.lock().unwrap();
        SESSION_CANCEL_PROVIDER_CALLS.store(0, Ordering::SeqCst);
        let (backend, _base, _functions) = backend_with_session_cancel();
        backend.lifecycle_domain.open_for_tests();
        backend.ffi_session_cancel(CkSessionHandle(7), CkFlags(0)).unwrap();
        assert_eq!(SESSION_CANCEL_PROVIDER_CALLS.load(Ordering::SeqCst), 1);
    }
}
