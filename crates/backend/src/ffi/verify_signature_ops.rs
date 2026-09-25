use super::ffi_conversion::mechanism_to_ffi;
use super::{FfiBackend, call_3x_fn};
use pkcs11_proxy_ng_types::*;

impl FfiBackend {
    pub(super) fn ffi_verify_signature_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        match mechanism {
            Some(mech) => {
                let ffi_mech = mechanism_to_ffi(mech)?;
                let (sig_ptr, sig_len) = signature.as_ptr_len();
                let _session_fence = self.session_fences.enter(&admission, session)?;
                call_3x_fn!(
                    &admission,
                    self,
                    func_list_3_2,
                    C_VerifySignatureInit,
                    Self::session_handle(session)?,
                    ffi_mech.ck_mechanism_ptr(),
                    Self::object_handle(key)?,
                    sig_ptr as *mut cryptoki_sys::CK_BYTE,
                    Self::ulong_len_u64(sig_len)
                )
            }
            None => {
                // NULL mechanism = cancel active verify-signature state
                call_3x_fn!(
                    &admission,
                    self,
                    func_list_3_2,
                    C_VerifySignatureInit,
                    Self::session_handle(session)?,
                    std::ptr::null_mut::<cryptoki_sys::CK_MECHANISM>(),
                    Self::object_handle(key)?,
                    std::ptr::null_mut::<cryptoki_sys::CK_BYTE>(),
                    0 as cryptoki_sys::CK_ULONG
                )
            }
        }
    }

    pub(super) fn ffi_verify_signature(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (data_ptr, data_len) = data.as_ptr_len();
        let _session_fence = self.session_fences.enter(&admission, session)?;
        call_3x_fn!(
            &admission,
            self,
            func_list_3_2,
            C_VerifySignature,
            Self::session_handle(session)?,
            data_ptr as *mut cryptoki_sys::CK_BYTE,
            Self::ulong_len_u64(data_len)
        )
    }

    pub(super) fn ffi_verify_signature_update(
        &self,
        session: CkSessionHandle,
        data_part: CkInBuf<'_>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (dp_ptr, dp_len) = data_part.as_ptr_len();
        let _session_fence = self.session_fences.enter(&admission, session)?;
        call_3x_fn!(
            &admission,
            self,
            func_list_3_2,
            C_VerifySignatureUpdate,
            Self::session_handle(session)?,
            dp_ptr as *mut cryptoki_sys::CK_BYTE,
            Self::ulong_len_u64(dp_len)
        )
    }

    pub(super) fn ffi_verify_signature_final(&self, session: CkSessionHandle) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        call_3x_fn!(
            &admission,
            self,
            func_list_3_2,
            C_VerifySignatureFinal,
            Self::session_handle(session)?
        )
    }
}

#[cfg(all(test, unix))]
mod lifecycle_macro_tests {
    use super::*;
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;

    unsafe extern "C" fn verify_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _data: cryptoki_sys::CK_BYTE_PTR,
        _data_len: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    fn backend_with_verify_sig(
        stub: unsafe extern "C" fn(
            cryptoki_sys::CK_SESSION_HANDLE,
            cryptoki_sys::CK_BYTE_PTR,
            cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    ) -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>, Box<cryptoki_sys::CK_FUNCTION_LIST_3_2>)
    {
        let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_2::default());
        functions.C_VerifySignature = Some(stub);
        let backend = FfiBackend {
            _lib: crate::ffi::loading::test_library_handle(),
            func_list: base.as_mut(),
            func_list_3_0: None,
            func_list_3_2: Some(functions.as_ref()),
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
        (backend, base, functions)
    }

    #[test]
    fn verify_signature_denied_before_lifecycle_open() {
        // TF01b `call_3x_fn!` ordinary proof: no admission pre-Init.
        let (backend, _base, _functions) = backend_with_verify_sig(verify_ok);
        assert_eq!(
            backend.ffi_verify_signature(CkSessionHandle(7), CkInBuf::Bytes(b"data")).unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn verify_signature_admitted_after_lifecycle_open() {
        // Control: the same call reaches the stub once the domain is open.
        let (backend, _base, _functions) = backend_with_verify_sig(verify_ok);
        backend.lifecycle_domain.open_for_tests();
        backend.ffi_verify_signature(CkSessionHandle(7), CkInBuf::Bytes(b"data")).unwrap();
    }

    // Blocked-stub exclusion shape (`call_3x_fn!` family): a parked ordinary
    // call blocks control settlement until release.
    static VERIFY_PARK_GATE: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>> =
        Mutex::new(None);

    unsafe extern "C" fn verify_parkable(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _data: cryptoki_sys::CK_BYTE_PTR,
        _data_len: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        let gate = VERIFY_PARK_GATE.lock().unwrap().take();
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
    fn parked_verify_signature_blocks_control_until_release() {
        let (backend, _base, _functions) = backend_with_verify_sig(verify_parkable);
        backend.lifecycle_domain.open_for_tests();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *VERIFY_PARK_GATE.lock().unwrap() = Some((entered_tx, release_rx));
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                backend.ffi_verify_signature(CkSessionHandle(7), CkInBuf::Bytes(b"data"))
            });
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
