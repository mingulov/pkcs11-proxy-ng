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
        let ck_attrs_len = Self::ulong_len(ck_attrs.len())?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_FindObjectsInit },
            |function| unsafe { function(h_session, Self::ffi_attr_ptr(&ffi_attrs), ck_attrs_len) },
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
        let found_handles: Vec<CkObjectHandle> =
            handles[..n].iter().map(|&h| CkObjectHandle(h as u64)).collect();
        for handle in &found_handles {
            self.record_object_lifetime_if_absent(session, *handle);
        }
        Ok(found_handles)
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
        let ck_attrs_len = Self::ulong_len(ffi_attrs.attrs.len())?;
        let rv = Self::call_raw(
            &admission,
            unsafe { (*self.func_list).C_GetAttributeValue },
            |function| unsafe {
                function(h_session, h_object, ffi_attrs.attrs.as_mut_ptr(), ck_attrs_len)
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
        queries: Option<&[CkAttributeQuery]>,
    ) -> CkResult<(CkRv, Vec<CkAttributeQueryResult>)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        // FIX-1: None materializes a NULL template pointer (the caller
        // passed (NULL, 0)); Some materializes (ptr, len), including
        // Some(&[]) as a non-NULL pointer with zero count. Backends such
        // as kryoptic distinguish the two (ARGUMENTS_BAD vs OK).
        let queries_slice = queries.unwrap_or(&[]);
        let mut ffi_queries = FfiAttributeQueries::from_queries(queries_slice)?;
        let h_session = Self::session_handle(session)?;
        let h_object = Self::object_handle(object)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        let ck_queries_len = Self::ulong_len(ffi_queries.attrs.len())?;
        let template_ptr =
            if queries.is_none() { std::ptr::null_mut() } else { ffi_queries.attrs.as_mut_ptr() };
        let rv = Self::call_raw(
            &admission,
            unsafe { (*self.func_list).C_GetAttributeValue },
            |function| unsafe { function(h_session, h_object, template_ptr, ck_queries_len) },
        )?;
        let backend_rv = CkRv(rv as u64);
        let results = ffi_queries.readback(queries_slice, backend_rv);
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
        let ck_attr_len = Self::ffi_attr_len(&ffi_attrs)?;
        self.call_object_output(
            session,
            &admission,
            unsafe { (*self.func_list).C_CreateObject },
            |function, handle| unsafe {
                function(h_session, Self::ffi_attr_ptr(&ffi_attrs), ck_attr_len, handle)
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
        let ck_attr_len = Self::ffi_attr_len(&ffi_attrs)?;
        self.call_object_output(
            session,
            &admission,
            unsafe { (*self.func_list).C_CopyObject },
            |function, new_handle| unsafe {
                function(
                    h_session,
                    h_object,
                    Self::ffi_attr_ptr(&ffi_attrs),
                    ck_attr_len,
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
        // Hold the lifetime table across the native destroy + removal
        // so a bound destroy's check cannot interleave with this
        // destroy/recreate pair.
        let mut lifetimes = self.object_lifetimes.lock_for_destroy();
        let result = Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_DestroyObject },
            |function| unsafe { function(h_session, h_object) },
        );
        if result.is_ok() {
            // The object is gone under every session (token objects
            // are visible across sessions): drop all its entries so
            // no stale lifetime survives under another session.
            lifetimes.retain(|&(_, obj), _| obj != object.0);
        }
        result
    }

    /// Incarnation-bound destroy for detached late-mint settlement
    /// (P2-13): the fence entry is checked against `incarnation`
    /// before any native call, so a destroy minted under a session
    /// that has since closed refuses without native entry even when
    /// the provider recycled both the session and object handles.
    /// `None` keeps the legacy raw-handle destroy for callers that
    /// captured no incarnation.
    pub(super) fn ffi_destroy_object_if_incarnation(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        incarnation: Option<u64>,
    ) -> CkResult<()> {
        // Incarnation-only legacy entry (settlement uses the
        // fail-safe `ffi_destroy_object_if_bound`): check the fence,
        // then destroy without the lifetime leg, mirroring the
        // trait-default and mock compositions of this entry.
        let Some(expected) = incarnation else {
            return self.ffi_destroy_object(session, object);
        };
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        let h_object = Self::object_handle(object)?;
        let _session_fence = self.session_fences.enter_checked(&admission, session, expected)?;
        let mut lifetimes = self.object_lifetimes.lock_for_destroy();
        let result = Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_DestroyObject },
            |function| unsafe { function(h_session, h_object) },
        );
        if result.is_ok() {
            lifetimes.retain(|&(_, obj), _| obj != object.0);
        }
        result
    }

    pub(super) fn ffi_object_lifetime(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> Option<u64> {
        self.object_lifetimes.lifetime(session, object)
    }

    /// Incarnation- and object-lifetime-bound destroy for detached
    /// late-mint settlement: the fence entry is checked against
    /// `incarnation` and the lifetime entry against the captured
    /// lifetime before any native call. The lifetime table lock is
    /// held across the check, the native destroy, and the entry
    /// removal, so a destroy/recreate pair cannot slip a fresh
    /// lifetime in between. The lifetime leg is fail-safe (see the
    /// trait contract on
    /// [`crate::traits::Pkcs11Backend::destroy_object_if_bound`]):
    /// only an exact match — or no capture against an untracked
    /// object — destroys; every other combination refuses with
    /// `OBJECT_HANDLE_INVALID` and issues no native destroy.
    pub(super) fn ffi_destroy_object_if_bound(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        incarnation: Option<u64>,
        object_lifetime: Option<u64>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        let h_object = Self::object_handle(object)?;
        let _session_fence = match incarnation {
            Some(expected) => self.session_fences.enter_checked(&admission, session, expected)?,
            None => self.session_fences.enter(&admission, session)?,
        };
        let mut lifetimes = self.object_lifetimes.lock_for_destroy();
        match (object_lifetime, lifetimes.get(&(session.0, object.0)).copied()) {
            (Some(expected), Some(current)) if current == expected => {}
            (Some(_), Some(_)) => return Err(CkRv::OBJECT_HANDLE_INVALID),
            (Some(_), None) => return Err(CkRv::OBJECT_HANDLE_INVALID),
            (None, Some(_)) => return Err(CkRv::OBJECT_HANDLE_INVALID),
            (None, None) => {}
        }
        let result = Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_DestroyObject },
            |function| unsafe { function(h_session, h_object) },
        );
        if result.is_ok() {
            lifetimes.retain(|&(_, obj), _| obj != object.0);
        }
        result
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
        let mut lifetimes = self.object_lifetimes.lock_for_destroy();
        let result = Self::call_control_unit(
            unsafe { (*self.func_list).C_DestroyObject },
            |function| unsafe { function(h_session, h_object) },
        );
        if result.is_ok() {
            lifetimes.retain(|&(_, obj), _| obj != object.0);
        }
        result
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
        let ck_attr_len = Self::ffi_attr_len(&ffi_attrs)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_SetAttributeValue },
            |function| unsafe {
                function(h_session, h_object, Self::ffi_attr_ptr(&ffi_attrs), ck_attr_len)
            },
        )
    }
}

#[cfg(all(test, unix))]
mod lifecycle_output_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
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

    static BOUND_DESTROY_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn destroy_counting(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _object: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        BOUND_DESTROY_CALLS.fetch_add(1, Ordering::SeqCst);
        cryptoki_sys::CKR_OK
    }

    /// Object-lifetime binding (FFI): a bound destroy captured against
    /// a minted object refuses (OBJECT_HANDLE_INVALID, no native
    /// destroy) after the handle is destroyed and re-minted within the
    /// same session, and still destroys while the lifetime matches.
    #[test]
    fn bound_destroy_refuses_stale_object_lifetime() {
        use crate::traits::Pkcs11Backend;
        BOUND_DESTROY_CALLS.store(0, Ordering::SeqCst);
        let (backend, _functions) = backend_with_object_stubs();
        unsafe { (*backend.func_list).C_DestroyObject = Some(destroy_counting) };
        backend.lifecycle_domain.open_for_tests();
        let session = CkSessionHandle(7);

        let handle = backend.create_object(session, Some(&[])).unwrap();
        let incarnation = backend.session_incarnation(session);
        let lifetime =
            backend.object_lifetime(session, handle).expect("minted object must carry a lifetime");

        backend.destroy_object(session, handle).unwrap();
        assert_eq!(BOUND_DESTROY_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(backend.object_lifetime(session, handle), None);

        // The stub re-mints the same numeric handle (provider reuse).
        let replacement = backend.create_object(session, Some(&[])).unwrap();
        assert_eq!(replacement, handle);
        let replacement_lifetime = backend
            .object_lifetime(session, replacement)
            .expect("replacement must carry a lifetime");
        assert_ne!(lifetime, replacement_lifetime);

        assert_eq!(
            backend.destroy_object_if_bound(session, replacement, incarnation, Some(lifetime)),
            Err(CkRv::OBJECT_HANDLE_INVALID),
            "stale lifetime must refuse the bound destroy"
        );
        assert_eq!(
            BOUND_DESTROY_CALLS.load(Ordering::SeqCst),
            1,
            "stale-lifetime refusal must issue no native destroy"
        );

        backend
            .destroy_object_if_bound(session, replacement, incarnation, Some(replacement_lifetime))
            .unwrap();
        assert_eq!(BOUND_DESTROY_CALLS.load(Ordering::SeqCst), 2);
        assert_eq!(backend.object_lifetime(session, replacement), None);
    }

    static FAILSAFE_DESTROY_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn destroy_counting_failsafe(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _object: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        FAILSAFE_DESTROY_CALLS.fetch_add(1, Ordering::SeqCst);
        cryptoki_sys::CKR_OK
    }

    /// Fail-safe settlement (FFI parity): no capture against a tracked
    /// object, and a captured lifetime whose entry is gone, both
    /// refuse without any native destroy.
    #[test]
    fn bound_destroy_failsafe_combinations_refuse_without_native_destroy() {
        use crate::traits::Pkcs11Backend;
        FAILSAFE_DESTROY_CALLS.store(0, Ordering::SeqCst);
        let (backend, _functions) = backend_with_object_stubs();
        unsafe { (*backend.func_list).C_DestroyObject = Some(destroy_counting_failsafe) };
        backend.lifecycle_domain.open_for_tests();
        let session = CkSessionHandle(7);
        let incarnation = backend.session_incarnation(session);

        let handle = backend.create_object(session, Some(&[])).unwrap();
        let lifetime = backend.object_lifetime(session, handle).expect("tracked mint");

        // Captured None + current Some: missed capture, refuse.
        assert_eq!(
            backend.destroy_object_if_bound(session, handle, incarnation, None),
            Err(CkRv::OBJECT_HANDLE_INVALID),
        );
        assert_eq!(FAILSAFE_DESTROY_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(backend.object_lifetime(session, handle), Some(lifetime));

        // Destroy plainly, then captured Some + current None: refuse.
        backend.destroy_object(session, handle).unwrap();
        assert_eq!(FAILSAFE_DESTROY_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(
            backend.destroy_object_if_bound(session, handle, incarnation, Some(lifetime)),
            Err(CkRv::OBJECT_HANDLE_INVALID),
        );
        assert_eq!(
            FAILSAFE_DESTROY_CALLS.load(Ordering::SeqCst),
            1,
            "refusals must issue no native destroy"
        );
    }

    static MINT_CAPTURE_DESTROY_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn destroy_counting_mint_capture(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _object: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        MINT_CAPTURE_DESTROY_CALLS.fetch_add(1, Ordering::SeqCst);
        cryptoki_sys::CKR_OK
    }

    /// Atomic mint capture (FFI parity): the pair reported at the
    /// fresh-record site still names the original lifetime after a
    /// destroy+recreate, so settlement refuses and issues no destroy.
    #[test]
    fn mint_capture_binds_original_lifetime_after_recreate() {
        use crate::traits::Pkcs11Backend;
        MINT_CAPTURE_DESTROY_CALLS.store(0, Ordering::SeqCst);
        let (backend, _functions) = backend_with_object_stubs();
        unsafe { (*backend.func_list).C_DestroyObject = Some(destroy_counting_mint_capture) };
        backend.lifecycle_domain.open_for_tests();
        let session = CkSessionHandle(7);

        let capture = crate::mint_capture::begin(session);
        let handle = backend.create_object(session, Some(&[])).unwrap();
        let captured = capture.captured();
        drop(capture);
        let lifetime = backend.object_lifetime(session, handle).expect("tracked mint");
        assert_eq!(captured, vec![(handle, lifetime)]);

        backend.destroy_object(session, handle).unwrap();
        assert_eq!(MINT_CAPTURE_DESTROY_CALLS.load(Ordering::SeqCst), 1);
        let replacement = backend.create_object(session, Some(&[])).unwrap();
        assert_eq!(replacement, handle, "stub re-mints the same numeric handle");
        assert_eq!(
            backend.destroy_object_if_bound(
                session,
                replacement,
                backend.session_incarnation(session),
                captured.first().map(|(_, l)| *l),
            ),
            Err(CkRv::OBJECT_HANDLE_INVALID),
        );
        assert_eq!(MINT_CAPTURE_DESTROY_CALLS.load(Ordering::SeqCst), 1);
        assert!(backend.object_lifetime(session, replacement).is_some());
    }

    static CONTENDED_MINT_DESTROY_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn destroy_counting_contended(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _object: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        CONTENDED_MINT_DESTROY_CALLS.fetch_add(1, Ordering::SeqCst);
        cryptoki_sys::CKR_OK
    }

    /// Contention poison (Defect A): a competitor FindObjects-record,
    /// destroy and recreate landing BEFORE the original mint's
    /// fresh record must poison that mint's capture. The table still
    /// updates to the newest id, but the capture reports nothing, so
    /// settlement (None against Some) refuses and the valid
    /// replacement survives with no native destroy.
    #[test]
    fn contended_mint_capture_is_poisoned_and_replacement_survives() {
        use crate::traits::Pkcs11Backend;
        CONTENDED_MINT_DESTROY_CALLS.store(0, Ordering::SeqCst);
        let (backend, _functions) = backend_with_object_stubs();
        unsafe { (*backend.func_list).C_DestroyObject = Some(destroy_counting_contended) };
        backend.lifecycle_domain.open_for_tests();
        let session = CkSessionHandle(7);
        let handle = CkObjectHandle(43);

        // Original mint: capture begins, native handle is known, but
        // its fresh record has not run yet (delayed record below).
        let capture = crate::mint_capture::begin(session);
        // Competitor interleaving on another thread, simulated with a
        // nested capture so its mint report cannot leak into the
        // original capture (captures are thread-local in production).
        // The competitor works through a DIFFERENT session, proving
        // contention detection is under any session.
        {
            let other = CkSessionHandle(8);
            let competitor = crate::mint_capture::begin(other);
            backend.record_object_lifetime_if_absent(other, handle);
            backend.destroy_object(other, handle).unwrap();
            let replacement = backend.create_object(other, Some(&[])).unwrap();
            assert_eq!(replacement, handle, "stub re-mints the same numeric handle");
            drop(competitor);
        }
        assert_eq!(CONTENDED_MINT_DESTROY_CALLS.load(Ordering::SeqCst), 1);

        // Original mint's late fresh record.
        backend.record_object_lifetime_fresh(session, handle);
        let captured = capture.captured();
        let captured_lifetime = capture.lifetime_for(handle);
        drop(capture);

        assert_eq!(
            captured,
            Vec::<(CkObjectHandle, u64)>::new(),
            "contended mint capture must be poisoned (report nothing)"
        );
        assert_eq!(captured_lifetime, None, "poisoned capture carries None for the handle");
        assert!(
            backend.object_lifetime(session, handle).is_some(),
            "table must still update its entry to the newest fresh id"
        );

        let destroys_before = CONTENDED_MINT_DESTROY_CALLS.load(Ordering::SeqCst);
        assert_eq!(
            backend.destroy_object_if_bound(
                session,
                handle,
                backend.session_incarnation(session),
                captured_lifetime,
            ),
            Err(CkRv::OBJECT_HANDLE_INVALID),
            "poisoned settlement (None against a tracking backend) must refuse"
        );
        assert_eq!(
            CONTENDED_MINT_DESTROY_CALLS.load(Ordering::SeqCst),
            destroys_before,
            "poisoned settlement must issue no native destroy"
        );
        assert!(
            backend.object_lifetime(session, handle).is_some(),
            "valid replacement must survive poisoned settlement"
        );
    }

    static UNDISTURBED_MINT_DESTROY_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn destroy_counting_undisturbed(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _object: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        UNDISTURBED_MINT_DESTROY_CALLS.fetch_add(1, Ordering::SeqCst);
        cryptoki_sys::CKR_OK
    }

    /// Positive control: an undisturbed mint still captures its
    /// lifetime and settles exactly once.
    #[test]
    fn undisturbed_mint_capture_still_settles_exactly_once() {
        use crate::traits::Pkcs11Backend;
        UNDISTURBED_MINT_DESTROY_CALLS.store(0, Ordering::SeqCst);
        let (backend, _functions) = backend_with_object_stubs();
        unsafe { (*backend.func_list).C_DestroyObject = Some(destroy_counting_undisturbed) };
        backend.lifecycle_domain.open_for_tests();
        let session = CkSessionHandle(7);

        let capture = crate::mint_capture::begin(session);
        let handle = backend.create_object(session, Some(&[])).unwrap();
        let captured = capture.captured();
        let captured_lifetime = capture.lifetime_for(handle);
        drop(capture);
        let lifetime = backend.object_lifetime(session, handle).expect("tracked mint");
        assert_eq!(captured, vec![(handle, lifetime)]);
        assert_eq!(captured_lifetime, Some(lifetime));

        backend
            .destroy_object_if_bound(
                session,
                handle,
                backend.session_incarnation(session),
                captured_lifetime,
            )
            .unwrap();
        assert_eq!(UNDISTURBED_MINT_DESTROY_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(backend.object_lifetime(session, handle), None);
        // Second settle refuses and destroys nothing more.
        assert_eq!(
            backend.destroy_object_if_bound(
                session,
                handle,
                backend.session_incarnation(session),
                captured_lifetime,
            ),
            Err(CkRv::OBJECT_HANDLE_INVALID),
        );
        assert_eq!(UNDISTURBED_MINT_DESTROY_CALLS.load(Ordering::SeqCst), 1);
    }

    /// Destroy invalidation (FFI parity): destroying through another
    /// session drops the entry under ALL sessions.
    #[test]
    fn destroy_through_other_session_invalidates_origin_entry() {
        use crate::traits::Pkcs11Backend;
        let (backend, _functions) = backend_with_object_stubs();
        backend.lifecycle_domain.open_for_tests();
        let origin = CkSessionHandle(7);
        let other = CkSessionHandle(8);

        let handle = backend.create_object(origin, Some(&[])).unwrap();
        assert!(backend.object_lifetime(origin, handle).is_some());
        // Simulate the object surfacing in the other session (find).
        backend.record_object_lifetime_if_absent(other, handle);
        assert!(backend.object_lifetime(other, handle).is_some());

        backend.destroy_object(other, handle).unwrap();
        assert_eq!(backend.object_lifetime(origin, handle), None);
        assert_eq!(backend.object_lifetime(other, handle), None);
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

    /// #26 canary shape: 0x82, writes `ulValueLen`, no value bytes.
    /// The provider reports 17 against a 64-byte buffer so the pin proves
    /// length propagation instead of echoing the input length.
    unsafe extern "C" fn get_attr_handle_invalid_len_only(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _object: cryptoki_sys::CK_OBJECT_HANDLE,
        attrs: cryptoki_sys::CK_ATTRIBUTE_PTR,
        count: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        if !attrs.is_null() && count >= 1 {
            unsafe { std::ptr::addr_of_mut!((*attrs).ulValueLen).write(17) };
        }
        cryptoki_sys::CKR_OBJECT_HANDLE_INVALID
    }

    /// #26: a provider 0x82 that writes `ulValueLen` but no value
    /// bytes must surface len-only results — never the zero-filled
    /// daemon buffer as a "value". At a48b60b the mapping attached
    /// daemon bytes regardless of RV and the shim wrote them, zeroing
    /// the caller canary.
    #[test]
    fn get_attribute_value_exact_handle_invalid_carries_len_only() {
        use crate::traits::Pkcs11Backend;
        let (backend, _functions) = backend_with_object_stubs();
        unsafe {
            (*backend.func_list).C_GetAttributeValue = Some(get_attr_handle_invalid_len_only)
        };
        backend.lifecycle_domain.open_for_tests();
        let queries = [CkAttributeQuery {
            attr_type: CkAttributeType::VALUE,
            buffer_present: true,
            buffer_len: 64,
            nested: None,
        }];
        let (rv, results) = backend
            .get_attribute_value_exact(CkSessionHandle(7), CkObjectHandle(9), Some(&queries))
            .unwrap();
        assert_eq!(rv, CkRv::OBJECT_HANDLE_INVALID);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].returned_len, 17, "provider len 17 must propagate, not echo 64");
        assert!(results[0].apply_returned_len, "provider len write must surface");
        assert!(results[0].value.is_none(), "no value bytes on 0x82 — never daemon zeros");
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
            .ffi_get_attribute_value_exact(
                CkSessionHandle(1),
                CkObjectHandle(1),
                Some(&two_queries()),
            )
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
            .ffi_get_attribute_value_exact(
                CkSessionHandle(1),
                CkObjectHandle(1),
                Some(&two_queries()),
            )
            .unwrap();
        assert_eq!(overall, CkRv::DEVICE_ERROR, "hard backend errors pass through");
        assert_eq!(results.len(), 2);
    }

    /// RED (FIX-1): a None query set must reach the backend as a NULL
    /// template pointer with zero count — backends such as kryoptic
    /// answer ARGUMENTS_BAD for NULL and OK for a non-NULL empty
    /// template, so the two must stay distinguishable end to end.
    unsafe extern "C" fn null_asserting_backend(
        _: cryptoki_sys::CK_SESSION_HANDLE,
        _: cryptoki_sys::CK_OBJECT_HANDLE,
        attrs: cryptoki_sys::CK_ATTRIBUTE_PTR,
        count: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        assert!(attrs.is_null(), "None queries must forward a NULL template pointer");
        assert_eq!(count, 0);
        cryptoki_sys::CKR_OK
    }

    /// RED (FIX-1): an explicit empty query set must reach the backend
    /// as a non-NULL template pointer with zero count.
    unsafe extern "C" fn non_null_asserting_backend(
        _: cryptoki_sys::CK_SESSION_HANDLE,
        _: cryptoki_sys::CK_OBJECT_HANDLE,
        attrs: cryptoki_sys::CK_ATTRIBUTE_PTR,
        count: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        assert!(!attrs.is_null(), "Some(&[]) queries must forward a non-NULL pointer");
        assert_eq!(count, 0);
        cryptoki_sys::CKR_OK
    }

    #[test]
    fn none_queries_forward_null_template_pointer() {
        let (backend, _table) = backend_with(Some(null_asserting_backend));
        let (overall, results) = backend
            .ffi_get_attribute_value_exact(CkSessionHandle(1), CkObjectHandle(1), None)
            .unwrap();
        assert_eq!(overall, CkRv::OK);
        assert!(results.is_empty());
    }

    #[test]
    fn empty_queries_forward_non_null_template_pointer() {
        let (backend, _table) = backend_with(Some(non_null_asserting_backend));
        let (overall, results) = backend
            .ffi_get_attribute_value_exact(CkSessionHandle(1), CkObjectHandle(1), Some(&[]))
            .unwrap();
        assert_eq!(overall, CkRv::OK);
        assert!(results.is_empty());
    }

    #[test]
    fn strict_backend_buffer_too_small_passes_through_unchanged() {
        let (backend, _table) = backend_with(Some(strict_buffer_too_small));
        let (overall, results) = backend
            .ffi_get_attribute_value_exact(
                CkSessionHandle(1),
                CkObjectHandle(1),
                Some(&two_queries()),
            )
            .unwrap();
        assert_eq!(
            overall,
            CkRv::BUFFER_TOO_SMALL,
            "strict backend 336 passes through (characterization: unchanged by W1-L3-09)"
        );
        assert_eq!(results.len(), 2);
    }
}
