//! Native-boundary counters; no returned secrets or mechanism bytes are observed.
use super::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

static LOCK: Mutex<()> = Mutex::new(());
static CALLS: Mutex<Vec<(bool, Option<u64>)>> = Mutex::new(Vec::new());
static FAIL_SIZING: AtomicBool = AtomicBool::new(false);

unsafe fn output(
    output: cryptoki_sys::CK_BYTE_PTR,
    length: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    let capacity = if length.is_null() { None } else { Some(unsafe { *length } as u64) };
    CALLS.lock().unwrap().push((!output.is_null(), capacity));
    if length.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }
    if output.is_null() && FAIL_SIZING.load(Ordering::SeqCst) {
        return cryptoki_sys::CKR_DEVICE_ERROR;
    }
    let size = unsafe { *length };
    unsafe {
        *length = 8;
    }
    if output.is_null() {
        return cryptoki_sys::CKR_OK;
    }
    if size < 8 {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }
    unsafe {
        std::ptr::write_bytes(output, 0xa5, 8);
    }
    cryptoki_sys::CKR_OK
}

unsafe extern "C" fn wrap(
    _: cryptoki_sys::CK_SESSION_HANDLE,
    _: cryptoki_sys::CK_MECHANISM_PTR,
    _: cryptoki_sys::CK_OBJECT_HANDLE,
    _: cryptoki_sys::CK_OBJECT_HANDLE,
    out: cryptoki_sys::CK_BYTE_PTR,
    len: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    unsafe { output(out, len) }
}
unsafe extern "C" fn authenticated(
    _: cryptoki_sys::CK_SESSION_HANDLE,
    _: cryptoki_sys::CK_MECHANISM_PTR,
    _: cryptoki_sys::CK_OBJECT_HANDLE,
    _: cryptoki_sys::CK_OBJECT_HANDLE,
    _: cryptoki_sys::CK_BYTE_PTR,
    _: cryptoki_sys::CK_ULONG,
    out: cryptoki_sys::CK_BYTE_PTR,
    len: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    unsafe { output(out, len) }
}

fn backend()
-> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>, Box<cryptoki_sys::CK_FUNCTION_LIST_3_2>) {
    let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
    base.C_WrapKey = Some(wrap);
    let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_2::default());
    functions.C_WrapKeyAuthenticated = Some(authenticated);
    let backend = FfiBackend {
        _lib: libloading::os::unix::Library::this().into(),
        func_list: base.as_mut(),
        func_list_3_0: None,
        func_list_3_2: Some(functions.as_ref()),
        initialize_args: None,
        mech_cache: DashMap::new(),
        last_init_family: DashMap::new(),
        session_slot_map: DashMap::new(),
        slot_sessions: DashMap::new(),
        object_cleanup: Default::default(),
        // Test-local backend: bypasses the process reservation without
        // consuming it; never backs production dispatch (C3M.4).
        construction: crate::ffi::native_domain::ConstructionPermit::unmanaged_test_only(),
        lifecycle: Default::default(),
    };
    (backend, base, functions)
}
fn mechanism() -> CkMechanism {
    CkMechanism {
        mechanism_type: CkMechanismType::AES_CBC,
        params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0x11; 16] })),
    }
}

#[test]
fn exact_wrap_native_pointer_classes_each_call_once() {
    let _guard = LOCK.lock().unwrap();
    FAIL_SIZING.store(false, Ordering::SeqCst);
    let (b, _base, _functions) = backend();
    for auth in [false, true] {
        for (present, len, null_len, want) in [
            (false, 0, false, CkRv::OK),
            (true, 0, false, CkRv::BUFFER_TOO_SMALL),
            (true, 1, false, CkRv::BUFFER_TOO_SMALL),
            (true, 8, false, CkRv::OK),
            (false, 0, true, CkRv::ARGUMENTS_BAD),
            (true, 0, true, CkRv::ARGUMENTS_BAD),
            (true, 8, true, CkRv::ARGUMENTS_BAD),
        ] {
            CALLS.lock().unwrap().clear();
            let spec = CkOutputBufferSpec {
                buffer_present: present,
                buffer_len: len,
                length_pointer_null: null_len,
            };
            let rv = if auth {
                b.ffi_wrap_key_authenticated_exact(
                    CkSessionHandle(4),
                    &mechanism(),
                    CkObjectHandle(8),
                    CkObjectHandle(9),
                    CkInBuf::Bytes(&[]),
                    &spec,
                    &CkParameterRoundtripSpec { buffer_present: true, buffer_len: 16, value: None },
                )
                .map(|r| r.0.ck_rv)
            } else {
                b.ffi_wrap_key_exact_with_output(
                    CkSessionHandle(4),
                    &mechanism(),
                    CkObjectHandle(8),
                    CkObjectHandle(9),
                    &spec,
                )
                .map(|r| r.0.ck_rv)
            }
            .unwrap_or_else(|rv| rv);
            assert_eq!(
                rv, want,
                "auth={auth}, present={present}, capacity={len}, null length={null_len}"
            );
            assert_eq!(*CALLS.lock().unwrap(), vec![(present, (!null_len).then_some(len))]);
        }
    }
}

#[test]
fn ordinary_wrap_native_sizing_calls_twice_and_stops_on_error() {
    let _guard = LOCK.lock().unwrap();
    let (b, _base, _functions) = backend();
    for auth in [false, true] {
        for fail in [false, true] {
            FAIL_SIZING.store(fail, Ordering::SeqCst);
            CALLS.lock().unwrap().clear();
            let result = if auth {
                b.ffi_wrap_key_authenticated(
                    CkSessionHandle(4),
                    &mechanism(),
                    CkObjectHandle(8),
                    CkObjectHandle(9),
                    CkInBuf::Bytes(&[]),
                )
                .map(|r| r.0)
            } else {
                b.ffi_wrap_key(
                    CkSessionHandle(4),
                    &mechanism(),
                    CkObjectHandle(8),
                    CkObjectHandle(9),
                )
            };
            if fail {
                assert_eq!(result.unwrap_err(), CkRv::DEVICE_ERROR);
                assert_eq!(*CALLS.lock().unwrap(), vec![(false, Some(0))]);
            } else {
                assert_eq!(result.unwrap().len(), 8);
                assert_eq!(*CALLS.lock().unwrap(), vec![(false, Some(0)), (true, Some(8))]);
            }
        }
    }
    FAIL_SIZING.store(false, Ordering::SeqCst);
}
