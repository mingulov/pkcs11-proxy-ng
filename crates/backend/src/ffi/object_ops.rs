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
        let cap = cap_find_objects_count(max_count);
        let mut handles = vec![0 as cryptoki_sys::CK_OBJECT_HANDLE; cap];
        let mut found: cryptoki_sys::CK_ULONG = 0;
        Self::call_unit(unsafe { (*self.func_list).C_FindObjects }, |function| unsafe {
            function(
                Self::session_handle(session),
                handles.as_mut_ptr(),
                cap as cryptoki_sys::CK_ULONG,
                &mut found,
            )
        })?;
        // A conformant backend writes at most `cap` handles; clamp `found`
        // defensively so a buggy backend cannot drive an out-of-bounds slice.
        let n = (found as usize).min(cap);
        Ok(handles[..n].iter().map(|&h| CkObjectHandle(h)).collect())
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
        let mut results = ffi_queries.readback(queries, backend_rv);
        let overall_rv = promote_overall_rv(backend_rv, &results);
        if backend_rv == CkRv::OK && overall_rv == CkRv::BUFFER_TOO_SMALL {
            canonicalize_promoted_lengths(&mut results);
        }
        Ok((overall_rv, results))
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
        let backend = FfiBackend {
            _lib: crate::ffi::loading::test_library_handle(),
            func_list: functions.as_mut(),
            func_list_3_0: None,
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
            lifecycle_domain: Default::default(),
            session_fences: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
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
mod promote_overall_rv_tests {
    use super::promote_overall_rv;
    use pkcs11_proxy_ng_types::{CkAttributeQueryResult, CkAttributeType, CkRv};

    fn result_with(ck_rv: Option<CkRv>) -> CkAttributeQueryResult {
        CkAttributeQueryResult {
            attr_type: CkAttributeType::CLASS,
            returned_len: 8,
            apply_returned_len: true,
            apply_type: false,
            value: None,
            ck_rv,
            nested: None,
        }
    }

    #[test]
    fn ok_with_too_small_marker_promotes_to_buffer_too_small() {
        let results = vec![result_with(Some(CkRv::BUFFER_TOO_SMALL))];
        assert_eq!(promote_overall_rv(CkRv::OK, &results), CkRv::BUFFER_TOO_SMALL);
    }

    #[test]
    fn ok_with_all_fit_stays_ok() {
        let results = vec![result_with(None), result_with(None)];
        assert_eq!(promote_overall_rv(CkRv::OK, &results), CkRv::OK);
    }

    #[test]
    fn ok_with_size_query_results_stays_ok() {
        // Size queries never set the marker (`too_small` needs
        // `buffer_present`), so a lenient OK+len size answer is untouched.
        let results = vec![CkAttributeQueryResult {
            attr_type: CkAttributeType::CLASS,
            returned_len: 8,
            apply_returned_len: true,
            apply_type: false,
            value: None,
            ck_rv: None,
            nested: None,
        }];
        assert_eq!(promote_overall_rv(CkRv::OK, &results), CkRv::OK);
    }

    #[test]
    fn strict_buffer_too_small_passes_through() {
        let results = vec![result_with(Some(CkRv::BUFFER_TOO_SMALL))];
        assert_eq!(promote_overall_rv(CkRv::BUFFER_TOO_SMALL, &results), CkRv::BUFFER_TOO_SMALL);
    }

    #[test]
    fn device_error_passes_through() {
        let results = vec![result_with(Some(CkRv::BUFFER_TOO_SMALL))];
        assert_eq!(promote_overall_rv(CkRv::DEVICE_ERROR, &results), CkRv::DEVICE_ERROR);
    }

    #[test]
    fn nested_only_marker_does_not_promote() {
        // Top-level results only: a nested-sub 336 without a top-level
        // marker keeps pre-existing semantics (out of scope).
        let mut top = result_with(None);
        top.nested = Some(vec![result_with(Some(CkRv::BUFFER_TOO_SMALL))]);
        assert_eq!(promote_overall_rv(CkRv::OK, &[top]), CkRv::OK);
    }
}

#[cfg(test)]
mod canonicalize_promoted_lengths_tests {
    use super::canonicalize_promoted_lengths;
    use pkcs11_proxy_ng_types::{CkAttributeQueryResult, CkAttributeType, CkRv};

    fn result_with(ck_rv: Option<CkRv>, returned_len: u64) -> CkAttributeQueryResult {
        CkAttributeQueryResult {
            attr_type: CkAttributeType::CLASS,
            returned_len,
            apply_returned_len: true,
            apply_type: false,
            value: None,
            ck_rv,
            nested: None,
        }
    }

    #[test]
    fn marked_results_get_sentinel_unmarked_keep_length() {
        let mut results = vec![result_with(Some(CkRv::BUFFER_TOO_SMALL), 8), result_with(None, 4)];
        canonicalize_promoted_lengths(&mut results);
        assert_eq!(results[0].returned_len, pkcs11_proxy_ng_types::width::CANONICAL_UNAVAILABLE);
        assert_eq!(results[1].returned_len, 4);
        // Markers themselves are untouched.
        assert_eq!(results[0].ck_rv, Some(CkRv::BUFFER_TOO_SMALL));
        assert_eq!(results[1].ck_rv, None);
    }

    #[test]
    fn no_markers_leaves_results_untouched() {
        let mut results = vec![result_with(None, 8)];
        canonicalize_promoted_lengths(&mut results);
        assert_eq!(results[0].returned_len, 8);
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
        assert_eq!(MAX_FIND_OBJECTS_PER_CALL, 512 * 1024 * 1024 / 8);
    }
}
