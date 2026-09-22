use super::*;

impl FfiBackend {
    pub(super) fn ffi_get_info(&self) -> CkResult<CkInfo> {
        let mut info = cryptoki_sys::CK_INFO::default();
        // Control choke: stateless probe query, forwarded regardless of
        // domain state (providers may still return
        // CKR_CRYPTOKI_NOT_INITIALIZED); retains nothing, needs no admission.
        Self::call_control_unit(unsafe { (*self.func_list).C_GetInfo }, |function| unsafe {
            function(&mut info)
        })?;
        Ok(info_from_ck(&info))
    }

    pub(super) fn ffi_get_slot_list(&self, token_present: bool) -> CkResult<Vec<CkSlotId>> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let token_present_flag =
            if token_present { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE };
        let slots = Self::call_array::<_, cryptoki_sys::CK_SLOT_ID, _>(
            &admission,
            unsafe { (*self.func_list).C_GetSlotList },
            |function, slots, count| unsafe { function(token_present_flag, slots, count) },
        )?;
        Ok(slots.into_iter().map(|x| CkSlotId(x as u64)).collect())
    }

    pub(super) fn ffi_get_slot_info(&self, slot_id: CkSlotId) -> CkResult<CkSlotInfo> {
        let mut info = cryptoki_sys::CK_SLOT_INFO::default();
        let h_slot = Self::slot_id(slot_id)?;
        // Control choke: stateless probe query, forwarded regardless of
        // domain state (providers may still return
        // CKR_CRYPTOKI_NOT_INITIALIZED); retains nothing, needs no admission.
        Self::call_control_unit(unsafe { (*self.func_list).C_GetSlotInfo }, |function| unsafe {
            function(h_slot, &mut info)
        })?;
        Ok(slot_info_from_ck(&info))
    }

    pub(super) fn ffi_get_token_info(&self, slot_id: CkSlotId) -> CkResult<CkTokenInfo> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let mut info = cryptoki_sys::CK_TOKEN_INFO::default();
        let h_slot = Self::slot_id(slot_id)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_GetTokenInfo },
            |function| unsafe { function(h_slot, &mut info) },
        )?;
        Ok(token_info_from_ck(&info))
    }

    pub(super) fn ffi_get_mechanism_list(
        &self,
        slot_id: CkSlotId,
    ) -> CkResult<Vec<CkMechanismType>> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_slot = Self::slot_id(slot_id)?;
        let mechanisms = Self::call_array::<_, cryptoki_sys::CK_MECHANISM_TYPE, _>(
            &admission,
            unsafe { (*self.func_list).C_GetMechanismList },
            |function, mechanisms, count| unsafe { function(h_slot, mechanisms, count) },
        )?;
        Ok(mechanisms.into_iter().map(|x| CkMechanismType(x as u64)).collect())
    }

    pub(super) fn ffi_get_mechanism_info(
        &self,
        slot_id: CkSlotId,
        mech: CkMechanismType,
    ) -> CkResult<CkMechanismInfo> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let mut info = cryptoki_sys::CK_MECHANISM_INFO::default();
        let h_slot = Self::slot_id(slot_id)?;
        let h_mech = Self::mechanism_type(mech)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_GetMechanismInfo },
            |function| unsafe { function(h_slot, h_mech, &mut info) },
        )?;
        Ok(mechanism_info_from_ck(&info))
    }

    pub(super) fn ffi_init_token(
        &self,
        slot_id: CkSlotId,
        so_pin: Option<&[u8]>,
        label: &str,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        // W1-L11-12: the shared types helper is the single padding impl.
        let mut label_buf = [0u8; 32];
        pkcs11_proxy_ng_types::space_pad_into(&mut label_buf, label);
        let (pin_ptr, pin_len) = match so_pin {
            Some(p) => (p.as_ptr() as *mut _, Self::ulong_len(p.len())?),
            None => (std::ptr::null_mut(), 0),
        };
        let h_slot = Self::slot_id(slot_id)?;
        Self::call_unit(&admission, unsafe { (*self.func_list).C_InitToken }, |function| unsafe {
            function(h_slot, pin_ptr, pin_len, label_buf.as_mut_ptr())
        })
    }

    pub(super) fn ffi_init_pin(
        &self,
        session: CkSessionHandle,
        pin: Option<&[u8]>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (pin_ptr, pin_len) = match pin {
            Some(p) => (p.as_ptr() as *mut _, Self::ulong_len(p.len())?),
            None => (std::ptr::null_mut(), 0),
        };
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(&admission, unsafe { (*self.func_list).C_InitPIN }, |function| unsafe {
            function(h_session, pin_ptr, pin_len)
        })
    }

    pub(super) fn ffi_set_pin(
        &self,
        session: CkSessionHandle,
        old_pin: Option<&[u8]>,
        new_pin: Option<&[u8]>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (old_ptr, old_len) = match old_pin {
            Some(p) => (p.as_ptr() as *mut _, Self::ulong_len(p.len())?),
            None => (std::ptr::null_mut(), 0),
        };
        let (new_ptr, new_len) = match new_pin {
            Some(p) => (p.as_ptr() as *mut _, Self::ulong_len(p.len())?),
            None => (std::ptr::null_mut(), 0),
        };
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(&admission, unsafe { (*self.func_list).C_SetPIN }, |function| unsafe {
            function(h_session, old_ptr, old_len, new_ptr, new_len)
        })
    }

    pub(super) fn ffi_open_session(
        &self,
        slot_id: CkSlotId,
        flags: CkSessionFlags,
    ) -> CkResult<CkSessionHandle> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_slot = Self::slot_id(slot_id)?;
        let handle = Self::call_session_output(
            &admission,
            unsafe { (*self.func_list).C_OpenSession },
            |function, handle| unsafe {
                function(
                    h_slot,
                    flags.0 as cryptoki_sys::CK_FLAGS,
                    std::ptr::null_mut(),
                    None,
                    handle,
                )
            },
        )?;
        // Record the session->slot binding so we can drop per-slot
        // `mech_cache` entries in `C_CloseAllSessions`.
        self.remember_session_slot(handle, slot_id);
        self.lifecycle.note_session_opened();
        Ok(handle)
    }

    pub(super) fn ffi_close_session(&self, session: CkSessionHandle) -> CkResult<()> {
        // Session-fenced close (TF01b/I4): ordinary admission plus close
        // ownership of S's fence, excluding in-flight ops on S across the
        // native close and the settlement (cache eviction) below.
        let admission = self.lifecycle_domain.admit_ordinary()?;
        // Enter with owners live: retire the family's retained graphs and the
        // slot mapping only after the native close proves terminal cleanup
        // (C3M.4). A failed close — or a pre-entry refusal below — keeps the
        // session's owners, marker and mapping so the still-owned incarnation
        // remains usable; the open count likewise stays high (fail-closed
        // toward slot poisoning on Drop).
        let h_session = Self::session_handle(session)?;
        // Nothing fallible between fence entry and settlement: both outcome
        // arms settle the fence explicitly (commit on success, reopen on
        // failure — including `FUNCTION_NOT_SUPPORTED` for a missing entry
        // point, which likewise proves nothing about the session).
        let close_fence = self.session_fences.enter_write(&admission, session)?;
        // Hook-gated fault injection (TO26b group 3; compiled out of
        // normal builds): an armed injector fails this close WITHOUT
        // native entry, settling the fence exactly like a native close
        // failure (reopen — owners, marker and mapping kept, session
        // remains usable). FUNCTION_FAILED is the codebase's transient
        // close failure (server keeps the mapping for retry; the shim
        // keeps authoritative state), mirroring the mock's
        // `inject_close_error` precedent. One-shot; the control plane
        // arms it per close.
        #[cfg(feature = "native-owner-test-hooks")]
        if crate::test_hooks::take_fail_next_close() {
            self.session_fences.reopen(&close_fence);
            return Err(CkRv::FUNCTION_FAILED);
        }
        let outcome = Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_CloseSession },
            |function| unsafe { function(h_session) },
        );
        match outcome {
            Ok(()) => {
                self.session_fences.commit_close(&close_fence);
                self.drop_mech_cache_session(session);
                self.forget_session_slot(session);
                // Count only provider-confirmed closes.
                self.lifecycle.note_sessions_closed(1);
                Ok(())
            }
            Err(rv) => {
                self.session_fences.reopen(&close_fence);
                Err(rv)
            }
        }
    }

    pub(super) fn ffi_close_all_sessions(&self, slot_id: CkSlotId) -> CkResult<()> {
        // Session-fenced close-all (TF01b/I4): close ownership over every
        // known session on the slot in ascending handle order (enforced
        // inside `enter_write_all`), excluding their in-flight ops across
        // the one native call and the per-slot settlement below.
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let known: Vec<u64> = self
            .slot_sessions
            .get(&slot_id.0)
            .map(|sessions| sessions.iter().copied().collect())
            .unwrap_or_default();
        let known_open = known.len();
        // Keep all target-slot owners through the one native call and clear
        // only after CKR_OK (C3M.4). A failed close preserves target-slot
        // ownership/index, and other slots remain untouched either way.
        let h_slot = Self::slot_id(slot_id)?;
        // Nothing fallible between fence entry and settlement (see
        // `ffi_close_session`).
        let close_fences = self.session_fences.enter_write_all(&admission, &known);
        let outcome = Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_CloseAllSessions },
            |function| unsafe { function(h_slot) },
        );
        match outcome {
            Ok(()) => {
                self.session_fences.commit_close_all(&close_fences);
                self.drop_mech_cache_for_slot(slot_id);
                self.lifecycle.note_sessions_closed(known_open);
                Ok(())
            }
            Err(rv) => {
                self.session_fences.reopen_all(&close_fences);
                Err(rv)
            }
        }
    }

    pub(super) fn ffi_get_session_info(&self, session: CkSessionHandle) -> CkResult<CkSessionInfo> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let mut info = cryptoki_sys::CK_SESSION_INFO::default();
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_GetSessionInfo },
            |function| unsafe { function(h_session, &mut info) },
        )?;
        Ok(session_info_from_ck(&info))
    }

    pub(super) fn ffi_login(
        &self,
        session: CkSessionHandle,
        user_type: CkUserType,
        pin: Option<&[u8]>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (pin_ptr, pin_len) = match pin {
            Some(p) => (p.as_ptr() as *mut _, Self::ulong_len(p.len())?),
            None => (std::ptr::null_mut(), 0),
        };
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(&admission, unsafe { (*self.func_list).C_Login }, |function| unsafe {
            function(h_session, user_type as cryptoki_sys::CK_USER_TYPE, pin_ptr, pin_len)
        })
    }

    pub(super) fn ffi_logout(&self, session: CkSessionHandle) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(&admission, unsafe { (*self.func_list).C_Logout }, |function| unsafe {
            function(h_session)
        })
    }

    pub(super) fn ffi_get_function_status(&self, session: CkSessionHandle) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_GetFunctionStatus },
            |function| unsafe { function(h_session) },
        )
    }

    pub(super) fn ffi_cancel_function(&self, session: CkSessionHandle) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_CancelFunction },
            |function| unsafe { function(h_session) },
        )
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;

    unsafe extern "C" fn close_session_fails(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_FUNCTION_FAILED
    }

    unsafe extern "C" fn close_session_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn close_all_sessions_fails(
        _slot: cryptoki_sys::CK_SLOT_ID,
    ) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_FUNCTION_FAILED
    }

    fn backend_with_close(
        close: cryptoki_sys::CK_C_CloseSession,
    ) -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_CloseSession = close;
        let backend = FfiBackend::test_backend_with_tables(functions.as_mut(), None, None);
        // Close tests exercise ordinary paths: establish post-Initialize state.
        backend.lifecycle_domain.open_for_tests();
        (backend, functions)
    }

    fn seed_sign_slot(backend: &FfiBackend, session: CkSessionHandle, slot: CkSlotId) {
        let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
        let ffi_mechanism = super::super::ffi_conversion::mechanism_to_ffi(&mechanism).unwrap();
        backend.mech_cache.insert((session.0, OperationFamily::Sign), ffi_mechanism);
        backend.last_init_family.insert(session.0, OperationFamily::Sign);
        backend.remember_session_slot(session, slot);
    }

    #[cfg(feature = "native-owner-test-hooks")]
    static INJECTED_CLOSE_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    #[cfg(feature = "native-owner-test-hooks")]
    unsafe extern "C" fn close_session_counting_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        INJECTED_CLOSE_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        cryptoki_sys::CKR_OK
    }

    /// TO26b group 3: the armed close injector fails WITHOUT native entry
    /// and settles like a native failure (owners kept); one-shot — the
    /// next close reaches native and succeeds. Hook builds only.
    #[test]
    #[cfg(feature = "native-owner-test-hooks")]
    fn hook_injected_close_failure_skips_native_and_keeps_owners() {
        use std::sync::atomic::Ordering;
        INJECTED_CLOSE_CALLS.store(0, Ordering::SeqCst);
        crate::test_hooks::set_fail_next_close(false);
        let (backend, _functions) = backend_with_close(Some(close_session_counting_ok));
        let session = CkSessionHandle(21);
        seed_sign_slot(&backend, session, CkSlotId(11));

        crate::test_hooks::set_fail_next_close(true);
        assert_eq!(backend.ffi_close_session(session).unwrap_err(), CkRv::FUNCTION_FAILED);
        assert_eq!(INJECTED_CLOSE_CALLS.load(Ordering::SeqCst), 0, "no native entry");
        assert!(backend.mech_cache.contains_key(&(session.0, OperationFamily::Sign)));
        assert_eq!(backend.session_slot_map.get(&session.0).as_deref(), Some(&11));

        assert!(backend.ffi_close_session(session).is_ok(), "one-shot: next close proceeds");
        assert_eq!(INJECTED_CLOSE_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_close_session_keeps_owners_live() {
        let (backend, _functions) = backend_with_close(Some(close_session_fails));
        let session = CkSessionHandle(21);
        seed_sign_slot(&backend, session, CkSlotId(11));

        assert_eq!(backend.ffi_close_session(session).unwrap_err(), CkRv::FUNCTION_FAILED);

        // No proven terminal cleanup: the failed close must not retire the
        // family's retained graph, the last-Init marker, or the slot mapping.
        assert!(backend.mech_cache.contains_key(&(session.0, OperationFamily::Sign)));
        assert_eq!(
            backend.last_init_family.get(&session.0).as_deref(),
            Some(&OperationFamily::Sign)
        );
        assert_eq!(backend.session_slot_map.get(&session.0).as_deref(), Some(&11));
    }

    #[cfg_attr(miri, ignore = "Miri cannot dlopen; covered natively")]
    #[test]
    fn native_owner_close_all_isolates_slots() {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_CloseAllSessions = Some(close_all_sessions_fails);
        let backend = FfiBackend::test_backend_with_tables(functions.as_mut(), None, None);
        // Close tests exercise ordinary paths: establish post-Initialize state.
        backend.lifecycle_domain.open_for_tests();
        let session = CkSessionHandle(23);
        seed_sign_slot(&backend, session, CkSlotId(11));
        // A bystander session on another slot proves isolation.
        let other = CkSessionHandle(24);
        seed_sign_slot(&backend, other, CkSlotId(22));

        assert_eq!(
            backend.ffi_close_all_sessions(CkSlotId(11)).unwrap_err(),
            CkRv::FUNCTION_FAILED
        );

        // No CKR_OK: target-slot owners, marker and mappings are preserved.
        assert!(backend.mech_cache.contains_key(&(session.0, OperationFamily::Sign)));
        assert_eq!(
            backend.last_init_family.get(&session.0).as_deref(),
            Some(&OperationFamily::Sign)
        );
        assert_eq!(backend.session_slot_map.get(&session.0).as_deref(), Some(&11));
        assert!(backend.slot_sessions.get(&11).is_some());
        // The other slot is untouched: its owner, marker and mappings stay whole.
        assert!(backend.mech_cache.contains_key(&(other.0, OperationFamily::Sign)));
        assert_eq!(backend.last_init_family.get(&other.0).as_deref(), Some(&OperationFamily::Sign));
        assert_eq!(backend.session_slot_map.get(&other.0).as_deref(), Some(&22));
        assert!(backend.slot_sessions.get(&22).is_some());
    }

    #[test]
    fn successful_close_session_retires_owners() {
        let (backend, _functions) = backend_with_close(Some(close_session_ok));
        let session = CkSessionHandle(22);
        seed_sign_slot(&backend, session, CkSlotId(11));

        backend.ffi_close_session(session).unwrap();

        // Proven terminal cleanup: every family slot, the marker and the
        // slot mapping for the closed session are gone.
        assert!(backend.mech_cache.is_empty());
        assert!(backend.last_init_family.get(&session.0).is_none());
        assert!(backend.session_slot_map.get(&session.0).is_none());
    }

    unsafe extern "C" fn token_info_ok(
        _slot: cryptoki_sys::CK_SLOT_ID,
        info: cryptoki_sys::CK_TOKEN_INFO_PTR,
    ) -> cryptoki_sys::CK_RV {
        if !info.is_null() {
            unsafe { *info = cryptoki_sys::CK_TOKEN_INFO::default() };
        }
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn get_info_ok(info: cryptoki_sys::CK_INFO_PTR) -> cryptoki_sys::CK_RV {
        if !info.is_null() {
            unsafe { *info = cryptoki_sys::CK_INFO::default() };
        }
        cryptoki_sys::CKR_OK
    }

    fn backend_with_info_stubs() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_GetTokenInfo = Some(token_info_ok);
        functions.C_GetInfo = Some(get_info_ok);
        let backend = FfiBackend::test_backend_with_tables(functions.as_mut(), None, None);
        (backend, functions)
    }

    #[test]
    fn token_info_denied_before_lifecycle_open() {
        // TF01a `call_unit` ordinary proof: no admission before Initialize.
        let (backend, _functions) = backend_with_info_stubs();
        assert_eq!(
            backend.ffi_get_token_info(CkSlotId(11)).unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn token_info_admitted_after_lifecycle_open() {
        // Control: the same call reaches the stub once the domain is open.
        let (backend, _functions) = backend_with_info_stubs();
        backend.lifecycle_domain.open_for_tests();
        backend.ffi_get_token_info(CkSlotId(11)).unwrap();
    }

    unsafe extern "C" fn open_session_ok(
        _slot: cryptoki_sys::CK_SLOT_ID,
        _flags: cryptoki_sys::CK_FLAGS,
        _application: cryptoki_sys::CK_VOID_PTR,
        _notify: cryptoki_sys::CK_NOTIFY,
        session: *mut cryptoki_sys::CK_SESSION_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        if !session.is_null() {
            unsafe { *session = 41 };
        }
        cryptoki_sys::CKR_OK
    }

    fn backend_with_open_session() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_OpenSession = Some(open_session_ok);
        let backend = FfiBackend::test_backend_with_tables(functions.as_mut(), None, None);
        (backend, functions)
    }

    #[test]
    fn open_session_denied_before_lifecycle_open() {
        // TF01b `call_session_output` ordinary proof: no admission pre-Init.
        let (backend, _functions) = backend_with_open_session();
        assert_eq!(
            backend
                .ffi_open_session(CkSlotId(11), CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
                .unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    unsafe extern "C" fn slot_list_ok(
        _token_present: cryptoki_sys::CK_BBOOL,
        slots: *mut cryptoki_sys::CK_SLOT_ID,
        count: *mut cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        if count.is_null() {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }
        if slots.is_null() {
            unsafe { *count = 2 };
            return cryptoki_sys::CKR_OK;
        }
        let n = unsafe { *count }.min(2) as usize;
        unsafe { std::ptr::copy_nonoverlapping([3, 5].as_ptr(), slots, n) };
        unsafe { *count = n as cryptoki_sys::CK_ULONG };
        cryptoki_sys::CKR_OK
    }

    fn backend_with_slot_list() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_GetSlotList = Some(slot_list_ok);
        let backend = FfiBackend::test_backend_with_tables(functions.as_mut(), None, None);
        (backend, functions)
    }

    #[test]
    fn slot_list_denied_before_lifecycle_open() {
        // TF01b `call_array` ordinary proof: no admission pre-Init.
        let (backend, _functions) = backend_with_slot_list();
        assert_eq!(backend.ffi_get_slot_list(false).unwrap_err(), CkRv::CRYPTOKI_NOT_INITIALIZED);
    }

    #[test]
    fn slot_list_admitted_after_lifecycle_open() {
        // Control: the same call reaches the stub once the domain is open.
        let (backend, _functions) = backend_with_slot_list();
        backend.lifecycle_domain.open_for_tests();
        assert_eq!(backend.ffi_get_slot_list(false).unwrap(), vec![CkSlotId(3), CkSlotId(5)]);
    }

    // Blocked-stub exclusion shape (`call_array` family): a parked ordinary
    // call blocks control settlement until release.
    static SLOT_PARK_GATE: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>> = Mutex::new(None);

    unsafe extern "C" fn slot_list_parkable(
        _token_present: cryptoki_sys::CK_BBOOL,
        slots: *mut cryptoki_sys::CK_SLOT_ID,
        count: *mut cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        if count.is_null() {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }
        if slots.is_null() {
            unsafe { *count = 1 };
            return cryptoki_sys::CKR_OK;
        }
        let gate = SLOT_PARK_GATE.lock().unwrap().take();
        match gate {
            Some((entered, release)) => {
                let _ = entered.send(());
                match release.recv_timeout(Duration::from_secs(10)) {
                    Ok(()) => {
                        unsafe { *slots = 9 };
                        unsafe { *count = 1 };
                        cryptoki_sys::CKR_OK
                    }
                    // Test bug (release never came): fail loudly, never hang.
                    Err(_) => cryptoki_sys::CKR_FUNCTION_FAILED,
                }
            }
            None => cryptoki_sys::CKR_FUNCTION_FAILED,
        }
    }

    #[test]
    fn parked_slot_list_blocks_control_until_release() {
        let (backend, _functions) = backend_with_slot_list();
        backend.lifecycle_domain.open_for_tests();
        unsafe { (*backend.func_list).C_GetSlotList = Some(slot_list_parkable) };
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *SLOT_PARK_GATE.lock().unwrap() = Some((entered_tx, release_rx));
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| backend.ffi_get_slot_list(false));
            entered_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("worker parks inside the stub holding its guard");
            scope.spawn(|| {
                let ticket = backend.lifecycle_domain.begin_initialize().expect("control proceeds");
                done_tx.send(()).expect("report control settlement");
                backend.lifecycle_domain.abandon_initialize(ticket);
            });
            assert!(
                done_rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "control must not settle while an ordinary call is parked"
            );
            release_tx.send(()).expect("release the parked stub");
            done_rx.recv_timeout(Duration::from_secs(5)).expect("control proceeds after release");
            worker.join().expect("worker joins").expect("parked call succeeds");
        });
    }

    #[test]
    fn open_session_admitted_after_lifecycle_open() {
        // Control: the same call reaches the stub once the domain is open.
        let (backend, _functions) = backend_with_open_session();
        backend.lifecycle_domain.open_for_tests();
        assert_eq!(
            backend
                .ffi_open_session(CkSlotId(11), CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
                .unwrap(),
            CkSessionHandle(41)
        );
    }

    #[test]
    fn get_info_reaches_provider_before_lifecycle_open() {
        // TF01a control-split proof: stateless probe queries ride the
        // unguarded control choke, so they need no admission.
        let (backend, _functions) = backend_with_info_stubs();
        backend.ffi_get_info().unwrap();
    }

    // Blocked-stub exclusion shape (`call_unit` family): mirrors the
    // `call_bytes` proof — a parked ordinary call blocks control
    // settlement until release.
    static TOKEN_PARK_GATE: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>> =
        Mutex::new(None);

    unsafe extern "C" fn token_info_parkable(
        _slot: cryptoki_sys::CK_SLOT_ID,
        info: cryptoki_sys::CK_TOKEN_INFO_PTR,
    ) -> cryptoki_sys::CK_RV {
        let gate = TOKEN_PARK_GATE.lock().unwrap().take();
        match gate {
            Some((entered, release)) => {
                let _ = entered.send(());
                match release.recv_timeout(Duration::from_secs(10)) {
                    Ok(()) => {
                        if !info.is_null() {
                            unsafe { *info = cryptoki_sys::CK_TOKEN_INFO::default() };
                        }
                        cryptoki_sys::CKR_OK
                    }
                    // Test bug (release never came): fail loudly, never hang.
                    Err(_) => cryptoki_sys::CKR_FUNCTION_FAILED,
                }
            }
            None => cryptoki_sys::CKR_FUNCTION_FAILED,
        }
    }

    // Session-fence integration (TF01b/I4): close-vs-op exclusion, fail-fast
    // entrants during a close, and reopen-after-failed-close.
    static FENCE_INFO_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static FENCE_CLOSE_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static FENCE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe extern "C" fn fence_session_info_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        info: cryptoki_sys::CK_SESSION_INFO_PTR,
    ) -> cryptoki_sys::CK_RV {
        FENCE_INFO_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if !info.is_null() {
            unsafe { *info = cryptoki_sys::CK_SESSION_INFO::default() };
        }
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn fence_close_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        FENCE_CLOSE_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        cryptoki_sys::CKR_OK
    }

    fn backend_with_fence_stubs() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_GetSessionInfo = Some(fence_session_info_ok);
        functions.C_CloseSession = Some(fence_close_ok);
        let backend = FfiBackend::test_backend_with_tables(functions.as_mut(), None, None);
        backend.lifecycle_domain.open_for_tests();
        (backend, functions)
    }

    static FENCE_INFO_PARK_GATE: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>> =
        Mutex::new(None);

    unsafe extern "C" fn fence_session_info_parkable(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        info: cryptoki_sys::CK_SESSION_INFO_PTR,
    ) -> cryptoki_sys::CK_RV {
        FENCE_INFO_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let gate = FENCE_INFO_PARK_GATE.lock().unwrap().take();
        match gate {
            Some((entered, release)) => {
                let _ = entered.send(());
                match release.recv_timeout(Duration::from_secs(10)) {
                    Ok(()) => {
                        if !info.is_null() {
                            unsafe { *info = cryptoki_sys::CK_SESSION_INFO::default() };
                        }
                        cryptoki_sys::CKR_OK
                    }
                    // Test bug (release never came): fail loudly, never hang.
                    Err(_) => cryptoki_sys::CKR_FUNCTION_FAILED,
                }
            }
            None => cryptoki_sys::CKR_FUNCTION_FAILED,
        }
    }

    static FENCE_CLOSE_PARK_GATE: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>> =
        Mutex::new(None);

    unsafe extern "C" fn fence_close_parkable(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        FENCE_CLOSE_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let gate = FENCE_CLOSE_PARK_GATE.lock().unwrap().take();
        match gate {
            Some((entered, release)) => {
                let _ = entered.send(());
                match release.recv_timeout(Duration::from_secs(10)) {
                    Ok(()) => cryptoki_sys::CKR_OK,
                    // Test bug (release never came): fail loudly, never hang.
                    Err(_) => cryptoki_sys::CKR_FUNCTION_FAILED,
                }
            }
            None => cryptoki_sys::CKR_FUNCTION_FAILED,
        }
    }

    #[test]
    fn parked_session_op_blocks_close_until_release() {
        // I4 close-vs-op exclusion: a parked op on S holds S's fence, so
        // close(S) cannot settle until release; it proceeds after.
        let _serial = FENCE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (backend, _functions) = backend_with_fence_stubs();
        unsafe { (*backend.func_list).C_GetSessionInfo = Some(fence_session_info_parkable) };
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *FENCE_INFO_PARK_GATE.lock().unwrap() = Some((entered_tx, release_rx));
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| backend.ffi_get_session_info(CkSessionHandle(7)));
            entered_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("worker parks inside the stub holding op + fence");
            scope.spawn(|| {
                done_tx
                    .send(backend.ffi_close_session(CkSessionHandle(7)))
                    .expect("report close outcome");
            });
            assert!(
                done_rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "close must not settle while an op on the session is parked"
            );
            release_tx.send(()).expect("release the parked op");
            done_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("close proceeds after release")
                .expect("close succeeds");
            worker.join().expect("worker joins").expect("parked op succeeds");
        });
    }

    #[test]
    fn op_during_close_fails_fast_without_native_entry() {
        // I4 fail-fast entrants: an op arriving while close(S) owns the fence
        // is refused without native entry; the close itself proceeds.
        let _serial = FENCE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        FENCE_INFO_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        let (backend, _functions) = backend_with_fence_stubs();
        unsafe { (*backend.func_list).C_CloseSession = Some(fence_close_parkable) };
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *FENCE_CLOSE_PARK_GATE.lock().unwrap() = Some((entered_tx, release_rx));
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                done_tx
                    .send(backend.ffi_close_session(CkSessionHandle(7)))
                    .expect("report close outcome");
            });
            entered_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("closer parks inside the close stub holding the fence");
            assert_eq!(
                backend.ffi_get_session_info(CkSessionHandle(7)).unwrap_err(),
                CkRv::SESSION_HANDLE_INVALID,
                "op during close fails fast"
            );
            assert_eq!(
                FENCE_INFO_CALLS.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "failed-fast op must not reach the provider"
            );
            release_tx.send(()).expect("release the parked close");
            done_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("close proceeds after release")
                .expect("close succeeds");
        });
    }

    #[test]
    fn failed_close_reopens_session_usable() {
        // A failed close proves nothing: the fence reopens and the session
        // stays live and fenced.
        let _serial = FENCE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (backend, _functions) = backend_with_fence_stubs();
        unsafe { (*backend.func_list).C_CloseSession = Some(close_session_fails) };
        assert_eq!(
            backend.ffi_close_session(CkSessionHandle(7)).unwrap_err(),
            CkRv::FUNCTION_FAILED
        );
        backend
            .ffi_get_session_info(CkSessionHandle(7))
            .expect("session usable after failed close");
        // And a later close still goes through (fence healthy, entry live).
        unsafe { (*backend.func_list).C_CloseSession = Some(fence_close_ok) };
        backend.ffi_close_session(CkSessionHandle(7)).expect("close succeeds after reopen");
    }

    #[test]
    fn parked_token_info_blocks_control_until_release() {
        let (backend, _functions) = backend_with_info_stubs();
        backend.lifecycle_domain.open_for_tests();
        unsafe { (*backend.func_list).C_GetTokenInfo = Some(token_info_parkable) };
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *TOKEN_PARK_GATE.lock().unwrap() = Some((entered_tx, release_rx));
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| backend.ffi_get_token_info(CkSlotId(11)));
            entered_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("worker parks inside the stub holding its guard");
            scope.spawn(|| {
                let ticket = backend.lifecycle_domain.begin_initialize().expect("control proceeds");
                done_tx.send(()).expect("report control settlement");
                backend.lifecycle_domain.abandon_initialize(ticket);
            });
            assert!(
                done_rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "control must not settle while an ordinary call is parked"
            );
            release_tx.send(()).expect("release the parked stub");
            done_rx.recv_timeout(Duration::from_secs(5)).expect("control proceeds after release");
            worker.join().expect("worker joins").expect("parked call succeeds");
        });
    }
}
