use super::*;

/// Upper bound on the number of object handles a single `C_FindObjects` call
/// may allocate, mirroring the array cap in `call_helpers` (512 MiB worth of
/// `CK_OBJECT_HANDLE`). PKCS#11 permits returning fewer than `ulMaxObjectCount`
/// per call, so a caller wanting more simply calls `C_FindObjects` again.
pub(super) const MAX_FIND_OBJECTS_PER_CALL: usize = super::call_helpers::MAX_OUTPUT_BUFFER_BYTES
    as usize
    / std::mem::size_of::<cryptoki_sys::CK_OBJECT_HANDLE>();

/// Clamp a client-supplied `ulMaxObjectCount` to a bounded allocation size so
/// one request cannot drive a multi-GB allocation in the shared daemon.
pub(super) fn cap_find_objects_count(max_count: u32) -> usize {
    (max_count as usize).min(MAX_FIND_OBJECTS_PER_CALL)
}

impl FfiBackend {
    pub(super) fn ffi_find_objects_init(
        &self,
        session: CkSessionHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let ffi_attrs = FfiAttrs::from_opt_slice(template)?;
        let ck_attrs = &ffi_attrs.attrs;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_FindObjectsInit },
            |function| unsafe {
                function(h_session, Self::ffi_attr_ptr(&ffi_attrs), Self::ulong_len(ck_attrs.len()))
            },
        )
    }

    pub(super) fn ffi_find_objects(
        &self,
        session: CkSessionHandle,
        max_count: u32,
    ) -> CkResult<Vec<CkObjectHandle>> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let cap = cap_find_objects_count(max_count);
        let mut handles = vec![0 as cryptoki_sys::CK_OBJECT_HANDLE; cap];
        let mut found: cryptoki_sys::CK_ULONG = 0;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_FindObjects },
            |function| unsafe {
                function(h_session, handles.as_mut_ptr(), cap as cryptoki_sys::CK_ULONG, &mut found)
            },
        )?;
        // A conformant backend writes at most `cap` handles; clamp `found`
        // defensively so a buggy backend cannot drive an out-of-bounds slice.
        let n = (found as usize).min(cap);
        Ok(handles[..n].iter().map(|&h| CkObjectHandle(h as u64)).collect())
    }

    pub(super) fn ffi_find_objects_final(&self, session: CkSessionHandle) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_FindObjectsFinal },
            |function| unsafe { function(h_session) },
        )
    }

    pub(super) fn ffi_get_attribute_value(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &mut [CkAttribute],
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let mut ffi_attrs = FfiAttrs::from_slice(template)?;
        let h_session = Self::session_handle(session)?;
        let h_object = Self::object_handle(object)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        let rv = Self::call_raw(
            &admission,
            unsafe { (*self.func_list).C_GetAttributeValue },
            |function| unsafe {
                function(
                    h_session,
                    h_object,
                    ffi_attrs.attrs.as_mut_ptr(),
                    Self::ulong_len(ffi_attrs.attrs.len()),
                )
            },
        )?;
        update_template_from_ffi(template, &ffi_attrs.attrs);
        Self::ck_result(rv)
    }

    /// Exact attribute read with faithful overall-RV pass-through (W1-L3-09).
    ///
    /// The backend's overall RV is returned unmodified — a lenient backend's
    /// `OK` is never promoted to `BUFFER_TOO_SMALL` from per-result markers
    /// (no RV synthesis; AGENTS.md "preserve exact `CK_RV` values").
    /// Per-result too-small markers are preserved as observed per-attribute
    /// truth with observed lengths untouched: a lenient `OK` + required
    /// length reaches the caller exactly as the backend reported it, and a
    /// strict backend's native 336 + `CK_UNAVAILABLE_INFORMATION` likewise
    /// flows through verbatim.
    pub(super) fn ffi_get_attribute_value_exact(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        queries: &[CkAttributeQuery],
    ) -> CkResult<(CkRv, Vec<CkAttributeQueryResult>)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let mut ffi_queries = FfiAttributeQueries::from_queries(queries)?;
        let h_session = Self::session_handle(session)?;
        let h_object = Self::object_handle(object)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        let rv = Self::call_raw(
            &admission,
            unsafe { (*self.func_list).C_GetAttributeValue },
            |function| unsafe {
                function(
                    h_session,
                    h_object,
                    ffi_queries.attrs.as_mut_ptr(),
                    Self::ulong_len(ffi_queries.attrs.len()),
                )
            },
        )?;
        let backend_rv = CkRv(rv as u64);
        let results = ffi_queries.readback(queries, backend_rv);
        Ok((backend_rv, results))
    }

    pub(super) fn ffi_create_object(
        &self,
        session: CkSessionHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let ffi_attrs = FfiAttrs::from_opt_slice(template)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_object_output(
            &admission,
            unsafe { (*self.func_list).C_CreateObject },
            |function, handle| unsafe {
                function(
                    h_session,
                    Self::ffi_attr_ptr(&ffi_attrs),
                    Self::ffi_attr_len(&ffi_attrs),
                    handle,
                )
            },
        )
    }

    pub(super) fn ffi_copy_object(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let ffi_attrs = FfiAttrs::from_opt_slice(template)?;
        let h_session = Self::session_handle(session)?;
        let h_object = Self::object_handle(object)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_object_output(
            &admission,
            unsafe { (*self.func_list).C_CopyObject },
            |function, new_handle| unsafe {
                function(
                    h_session,
                    h_object,
                    Self::ffi_attr_ptr(&ffi_attrs),
                    Self::ffi_attr_len(&ffi_attrs),
                    new_handle,
                )
            },
        )
    }

    pub(super) fn ffi_destroy_object(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        let h_object = Self::object_handle(object)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_DestroyObject },
            |function| unsafe { function(h_session, h_object) },
        )
    }

    /// Drop-path destroy: rides the enclosing op's exclusion via the control
    /// choke instead of admitting (a nested `admit_ordinary` under the live
    /// guard would deadlock behind a queued Finalize writer). Debug-pins the
    /// enclosing guard via `debug_assert_admitted`, and skips fence-enter:
    /// the destroy runs on the enclosing op's own session whose fence-read
    /// it already holds.
    pub(super) fn ffi_destroy_object_unadmitted(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> CkResult<()> {
        super::native_domain::debug_assert_admitted();
        let h_session = Self::session_handle(session)?;
        let h_object = Self::object_handle(object)?;
        Self::call_control_unit(unsafe { (*self.func_list).C_DestroyObject }, |function| unsafe {
            function(h_session, h_object)
        })
    }

    pub(super) fn ffi_get_object_size(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> CkResult<u64> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        let h_object = Self::object_handle(object)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_ulong_output(
            &admission,
            unsafe { (*self.func_list).C_GetObjectSize },
            |function, size| unsafe { function(h_session, h_object, size) },
        )
    }

    pub(super) fn ffi_set_attribute_value(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let ffi_attrs = FfiAttrs::from_opt_slice(template)?;
        let h_session = Self::session_handle(session)?;
        let h_object = Self::object_handle(object)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_SetAttributeValue },
            |function| unsafe {
                function(
                    h_session,
                    h_object,
                    Self::ffi_attr_ptr(&ffi_attrs),
                    Self::ffi_attr_len(&ffi_attrs),
                )
            },
        )
    }
}

#[cfg(all(test, unix))]
mod lifecycle_output_tests {
    use super::*;
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;

    unsafe extern "C" fn create_object_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _template: cryptoki_sys::CK_ATTRIBUTE_PTR,
        _count: cryptoki_sys::CK_ULONG,
        handle: *mut cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        if !handle.is_null() {
            unsafe { *handle = 43 };
        }
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn object_size_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _object: cryptoki_sys::CK_OBJECT_HANDLE,
        size: *mut cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        if !size.is_null() {
            unsafe { *size = 17 };
        }
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn destroy_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _object: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    fn backend_with_object_stubs() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_CreateObject = Some(create_object_ok);
        functions.C_GetObjectSize = Some(object_size_ok);
        functions.C_DestroyObject = Some(destroy_ok);
        let backend = FfiBackend::test_backend_with_tables(functions.as_mut(), None, None);
        (backend, functions)
    }

    #[test]
    fn create_object_denied_before_lifecycle_open() {
        // TF01b `call_object_output` ordinary proof: no admission pre-Init.
        let (backend, _functions) = backend_with_object_stubs();
        assert_eq!(
            backend.ffi_create_object(CkSessionHandle(7), None).unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn create_object_admitted_after_lifecycle_open() {
        // Control: the same call reaches the stub once the domain is open.
        let (backend, _functions) = backend_with_object_stubs();
        backend.lifecycle_domain.open_for_tests();
        assert_eq!(
            backend.ffi_create_object(CkSessionHandle(7), None).unwrap(),
            CkObjectHandle(43)
        );
    }

    #[test]
    fn object_size_denied_before_lifecycle_open() {
        // TF01b `call_ulong_output` ordinary proof: no admission pre-Init.
        let (backend, _functions) = backend_with_object_stubs();
        assert_eq!(
            backend.ffi_get_object_size(CkSessionHandle(7), CkObjectHandle(9)).unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn object_size_admitted_after_lifecycle_open() {
        // Control: the same call reaches the stub once the domain is open.
        let (backend, _functions) = backend_with_object_stubs();
        backend.lifecycle_domain.open_for_tests();
        assert_eq!(backend.ffi_get_object_size(CkSessionHandle(7), CkObjectHandle(9)).unwrap(), 17);
    }

    unsafe extern "C" fn get_attr_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _object: cryptoki_sys::CK_OBJECT_HANDLE,
        _template: cryptoki_sys::CK_ATTRIBUTE_PTR,
        _count: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    fn backend_with_get_attr() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let (backend, functions) = backend_with_object_stubs();
        unsafe { (*backend.func_list).C_GetAttributeValue = Some(get_attr_ok) };
        (backend, functions)
    }

    #[test]
    fn get_attribute_value_denied_before_lifecycle_open() {
        // TF01b `call_raw` ordinary proof: no admission pre-Init.
        let (backend, _functions) = backend_with_get_attr();
        let mut template = [];
        assert_eq!(
            backend
                .ffi_get_attribute_value(CkSessionHandle(7), CkObjectHandle(9), &mut template)
                .unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn get_attribute_value_admitted_after_lifecycle_open() {
        // Control: the same call reaches the stub once the domain is open.
        let (backend, _functions) = backend_with_get_attr();
        backend.lifecycle_domain.open_for_tests();
        let mut template = [];
        backend
            .ffi_get_attribute_value(CkSessionHandle(7), CkObjectHandle(9), &mut template)
            .unwrap();
    }

    // Blocked-stub exclusion shape (`call_object_output` family): a parked
    // ordinary call blocks control settlement until release.
    static CREATE_PARK_GATE: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>> =
        Mutex::new(None);

    unsafe extern "C" fn create_object_parkable(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _template: cryptoki_sys::CK_ATTRIBUTE_PTR,
        _count: cryptoki_sys::CK_ULONG,
        handle: *mut cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        let gate = CREATE_PARK_GATE.lock().unwrap().take();
        match gate {
            Some((entered, release)) => {
                let _ = entered.send(());
                match release.recv_timeout(Duration::from_secs(10)) {
                    Ok(()) => {
                        if !handle.is_null() {
                            unsafe { *handle = 43 };
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

    #[test]
    fn parked_create_object_blocks_control_until_release() {
        let (backend, _functions) = backend_with_object_stubs();
        backend.lifecycle_domain.open_for_tests();
        unsafe { (*backend.func_list).C_CreateObject = Some(create_object_parkable) };
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *CREATE_PARK_GATE.lock().unwrap() = Some((entered_tx, release_rx));
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| backend.ffi_create_object(CkSessionHandle(7), None));
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

    // TF01b Drop audit: destructor cleanup must ride the enclosing op's
    // exclusion via the control choke, never admit (a nested admit under
    // the live guard trips the tripwire in debug and deadlocks behind a
    // queued writer in release). First the hazard, pinned as a tripwire
    // self-test: the full-admit path under a live guard must panic.
    #[test]
    #[should_panic(expected = "nested ordinary admission")]
    fn drop_destroy_via_full_admit_path_nests_and_trips() {
        use crate::traits::Pkcs11Backend;
        let (backend, _functions) = backend_with_object_stubs();
        backend.lifecycle_domain.open_for_tests();
        let _enclosing = backend.lifecycle_domain.admit_ordinary().unwrap();
        let _ = backend.destroy_object(CkSessionHandle(7), CkObjectHandle(9));
    }

    // ... then the Drop-safe path: same setup, no panic, stub reached.
    #[test]
    fn drop_destroy_rides_enclosing_guard_without_nesting() {
        use crate::traits::Pkcs11Backend;
        let (backend, _functions) = backend_with_object_stubs();
        backend.lifecycle_domain.open_for_tests();
        let enclosing = backend.lifecycle_domain.admit_ordinary().unwrap();
        backend
            .destroy_quarantined_object(CkSessionHandle(7), CkObjectHandle(9))
            .expect("Drop-path destroy rides the enclosing guard");
        drop(enclosing);
    }
}

#[cfg(test)]
mod find_objects_cap_tests {
    use super::{MAX_FIND_OBJECTS_PER_CALL, cap_find_objects_count};

    #[test]
    fn caps_absurd_count_to_bound() {
        // A malicious uint32 (~4.29 billion handles ≈ 34 GB) must be clamped.
        assert_eq!(cap_find_objects_count(u32::MAX), MAX_FIND_OBJECTS_PER_CALL);
    }

    #[test]
    fn passes_through_reasonable_count() {
        assert_eq!(cap_find_objects_count(10), 10);
        assert_eq!(cap_find_objects_count(0), 0);
    }

    #[test]
    fn bound_is_a_tiny_fraction_of_u32_max() {
        assert!(MAX_FIND_OBJECTS_PER_CALL < u32::MAX as usize);
        assert_eq!(
            MAX_FIND_OBJECTS_PER_CALL,
            512 * 1024 * 1024 / std::mem::size_of::<cryptoki_sys::CK_OBJECT_HANDLE>()
        );
    }
}

#[cfg(test)]
mod faithful_overall_rv_tests {
    // W1-L3-09: the backend's overall RV passes through unmodified — a
    // lenient backend's OK is never promoted to BUFFER_TOO_SMALL from
    // per-result markers. Markers are preserved as observed (per-attribute
    // truth), with observed lengths untouched.
    use super::FfiBackend;
    use pkcs11_proxy_ng_types::{
        CkAttributeQuery, CkAttributeType, CkObjectHandle, CkRv, CkSessionHandle,
    };

    /// Lenient backend: writes the required length into the length cell and
    /// answers CKR_OK (the T4-FIX NULL-for-empty / strict-vs-lenient shape).
    unsafe extern "C" fn lenient_ok_with_too_small_shape(
        _: cryptoki_sys::CK_SESSION_HANDLE,
        _: cryptoki_sys::CK_OBJECT_HANDLE,
        attrs: cryptoki_sys::CK_ATTRIBUTE_PTR,
        count: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        assert_eq!(count, 2);
        unsafe {
            (*attrs.add(0)).ulValueLen = 8; // query buffer_len 4 -> too-small marker
            (*attrs.add(1)).ulValueLen = 8; // query buffer_len 8 -> fits
        }
        cryptoki_sys::CKR_OK
    }

    /// Failing backend: hard error overall, lengths untouched.
    unsafe extern "C" fn device_error_backend(
        _: cryptoki_sys::CK_SESSION_HANDLE,
        _: cryptoki_sys::CK_OBJECT_HANDLE,
        _: cryptoki_sys::CK_ATTRIBUTE_PTR,
        _: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_DEVICE_ERROR
    }

    /// Strict backend: sentinel length + CKR_BUFFER_TOO_SMALL overall.
    unsafe extern "C" fn strict_buffer_too_small(
        _: cryptoki_sys::CK_SESSION_HANDLE,
        _: cryptoki_sys::CK_OBJECT_HANDLE,
        attrs: cryptoki_sys::CK_ATTRIBUTE_PTR,
        count: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        assert_eq!(count, 2);
        unsafe {
            (*attrs.add(0)).ulValueLen = cryptoki_sys::CK_UNAVAILABLE_INFORMATION;
            (*attrs.add(1)).ulValueLen = 8;
        }
        cryptoki_sys::CKR_BUFFER_TOO_SMALL
    }

    fn backend_with(
        get_attr: cryptoki_sys::CK_C_GetAttributeValue,
    ) -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        base.C_GetAttributeValue = get_attr;
        // SAFETY: the table outlives the backend (both live in the test body).
        let backend = FfiBackend::test_backend_with_tables(
            (&mut *base) as *mut cryptoki_sys::CK_FUNCTION_LIST,
            None,
            None,
        );
        backend.lifecycle_domain.open_for_tests();
        (backend, base)
    }

    fn two_queries() -> Vec<CkAttributeQuery> {
        vec![
            CkAttributeQuery {
                attr_type: CkAttributeType::LABEL,
                buffer_present: true,
                buffer_len: 4,
                nested: None,
            },
            CkAttributeQuery {
                attr_type: CkAttributeType::ID,
                buffer_present: true,
                buffer_len: 8,
                nested: None,
            },
        ]
    }

    #[test]
    fn lenient_backend_ok_passes_through_with_markers_preserved() {
        let (backend, _table) = backend_with(Some(lenient_ok_with_too_small_shape));
        let (overall, results) = backend
            .ffi_get_attribute_value_exact(CkSessionHandle(1), CkObjectHandle(1), &two_queries())
            .unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(
            overall,
            CkRv::OK,
            "W1-L3-09: lenient backend OK must pass through unmodified, \
             never promoted to BUFFER_TOO_SMALL"
        );
        assert_eq!(
            results[0].ck_rv,
            Some(CkRv::BUFFER_TOO_SMALL),
            "per-result too-small marker is preserved as observed"
        );
        assert_eq!(
            results[0].returned_len, 8,
            "observed required length is preserved, not rewritten to a sentinel"
        );
        assert_eq!(results[1].ck_rv, None, "fitting result stays unmarked");
    }

    #[test]
    fn device_error_passes_through_unmodified() {
        let (backend, _table) = backend_with(Some(device_error_backend));
        let (overall, results) = backend
            .ffi_get_attribute_value_exact(CkSessionHandle(1), CkObjectHandle(1), &two_queries())
            .unwrap();
        assert_eq!(overall, CkRv::DEVICE_ERROR, "hard backend errors pass through");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn strict_backend_buffer_too_small_passes_through_unchanged() {
        let (backend, _table) = backend_with(Some(strict_buffer_too_small));
        let (overall, results) = backend
            .ffi_get_attribute_value_exact(CkSessionHandle(1), CkObjectHandle(1), &two_queries())
            .unwrap();
        assert_eq!(
            overall,
            CkRv::BUFFER_TOO_SMALL,
            "strict backend 336 passes through (characterization: unchanged by W1-L3-09)"
        );
        assert_eq!(results.len(), 2);
    }
}
