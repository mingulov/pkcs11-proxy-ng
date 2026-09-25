//! Native-boundary counters; no returned secrets or mechanism bytes are observed.
use super::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

static LOCK: Mutex<()> = Mutex::new(());
static CALLS: Mutex<Vec<(bool, Option<u64>)>> = Mutex::new(Vec::new());
static FAIL_SIZING: AtomicBool = AtomicBool::new(false);
static MUTATE_SIZING_INPUTS: AtomicBool = AtomicBool::new(false);

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
    mechanism: cryptoki_sys::CK_MECHANISM_PTR,
    _: cryptoki_sys::CK_OBJECT_HANDLE,
    _: cryptoki_sys::CK_OBJECT_HANDLE,
    _: cryptoki_sys::CK_BYTE_PTR,
    _: cryptoki_sys::CK_ULONG,
    out: cryptoki_sys::CK_BYTE_PTR,
    len: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    // Row-11 fault injection: poison the mechanism root during the sizing
    // call so the typed path's post-sizing validation must refuse the fill.
    if MUTATE_SIZING_INPUTS.load(Ordering::SeqCst) && out.is_null() && !mechanism.is_null() {
        unsafe {
            (*mechanism).pParameter = std::ptr::null_mut();
        }
    }
    unsafe { output(out, len) }
}

unsafe extern "C" fn unwrap_authenticated(
    _: cryptoki_sys::CK_SESSION_HANDLE,
    _: cryptoki_sys::CK_MECHANISM_PTR,
    _: cryptoki_sys::CK_OBJECT_HANDLE,
    _: cryptoki_sys::CK_BYTE_PTR,
    _: cryptoki_sys::CK_ULONG,
    _: cryptoki_sys::CK_ATTRIBUTE_PTR,
    _: cryptoki_sys::CK_ULONG,
    _: cryptoki_sys::CK_BYTE_PTR,
    _: cryptoki_sys::CK_ULONG,
    handle: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    if !handle.is_null() {
        unsafe { *handle = 77 };
    }
    cryptoki_sys::CKR_OK
}

fn backend()
-> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>, Box<cryptoki_sys::CK_FUNCTION_LIST_3_2>) {
    let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
    base.C_WrapKey = Some(wrap);
    let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_2::default());
    functions.C_WrapKeyAuthenticated = Some(authenticated);
    functions.C_UnwrapKeyAuthenticated = Some(unwrap_authenticated);
    let backend =
        FfiBackend::test_backend_with_tables(base.as_mut(), None, Some(functions.as_ref()));
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
    // Wrap paths are ordinary: establish post-Initialize state.
    b.lifecycle_domain.open_for_tests();
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
    // Wrap paths are ordinary: establish post-Initialize state.
    b.lifecycle_domain.open_for_tests();
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

#[cfg_attr(miri, ignore = "Miri cannot dlopen; covered natively")]
#[test]
fn native_owner_authenticated_validation_precedes_second_call() {
    // C3M.6 row 11: the typed authenticated path validates the mechanism
    // root after the sizing call and before the fill. A provider-mutated
    // input must stop the sequence after exactly one native entry with
    // DEVICE_ERROR — the fill must never observe the poisoned pointer.
    // Already-green invariant kept as a named regression.
    let _guard = LOCK.lock().unwrap();
    MUTATE_SIZING_INPUTS.store(true, Ordering::SeqCst);
    CALLS.lock().unwrap().clear();
    let (b, _base, _functions) = backend();
    // Wrap paths are ordinary: establish post-Initialize state.
    b.lifecycle_domain.open_for_tests();
    let err = b
        .ffi_wrap_authenticated_typed(
            CkSessionHandle(4),
            &mechanism(),
            None,
            CkObjectHandle(8),
            CkObjectHandle(9),
            CkInBuf::Bytes(&[]),
        )
        .map(|r| r.0)
        .unwrap_err();
    assert_eq!(err, CkRv::DEVICE_ERROR);
    assert_eq!(*CALLS.lock().unwrap(), vec![(false, Some(0))]);
    MUTATE_SIZING_INPUTS.store(false, Ordering::SeqCst);
}

unsafe extern "C" fn wrap_gcm_error(
    _: cryptoki_sys::CK_SESSION_HANDLE,
    mechanism: cryptoki_sys::CK_MECHANISM_PTR,
    _: cryptoki_sys::CK_OBJECT_HANDLE,
    _: cryptoki_sys::CK_OBJECT_HANDLE,
    _: cryptoki_sys::CK_BYTE_PTR,
    length: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    if !mechanism.is_null() {
        // Benign native-provider effect: write within an initialized owned IV.
        let gcm = unsafe { &*(*mechanism).pParameter.cast::<cryptoki_sys::CK_GCM_PARAMS>() };
        unsafe { gcm.pIv.write(0x42) };
    }
    if !length.is_null() {
        unsafe { length.write(7) };
    }
    cryptoki_sys::CKR_FUNCTION_FAILED
}

fn gcm_error_backend() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
    let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
    base.C_WrapKey = Some(wrap_gcm_error);
    let backend = FfiBackend::test_backend_with_tables(base.as_mut(), None, None);
    // Wrap paths are ordinary: establish post-Initialize state.
    backend.lifecycle_domain.open_for_tests();
    (backend, base)
}

#[cfg_attr(miri, ignore = "Miri cannot dlopen; covered natively")]
#[test]
fn ordinary_wrap_error_iv_effect_matches_one_shot_rule() {
    let _guard = LOCK.lock().unwrap();
    let (b, _base) = gcm_error_backend();
    let mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv: vec![0x11; 12],
            iv_bits: 96,
            iv_buffer_len: 12,
            aad: vec![].into(),
            tag_bits: 128,

            iv_null: false,
            aad_null: false,
        })),
    };
    let (output, effects) = b
        .ffi_wrap_key_exact_with_output(
            CkSessionHandle(4),
            &mechanism,
            CkObjectHandle(8),
            CkObjectHandle(9),
            &CkOutputBufferSpec { buffer_present: true, buffer_len: 4, length_pointer_null: false },
        )
        .unwrap();
    assert_eq!(output.ck_rv, CkRv::FUNCTION_FAILED);
    assert_eq!(output.returned_len, Some(7));
    let Some(CkMechanismParams::Gcm(gcm)) = effects else {
        panic!("failed wrap must surface the mutated owned GCM IV");
    };
    assert_eq!(gcm.iv[0], 0x42);
    let (output, effects) = b
        .ffi_wrap_key_exact_with_output(
            CkSessionHandle(4),
            &mechanism,
            CkObjectHandle(8),
            CkObjectHandle(9),
            &CkOutputBufferSpec {
                buffer_present: false,
                buffer_len: 0,
                length_pointer_null: false,
            },
        )
        .unwrap();
    assert_eq!(output.ck_rv, CkRv::FUNCTION_FAILED);
    assert_eq!(effects, None);
}

#[test]
fn wrap_authenticated_exact_typed_denied_before_lifecycle_open() {
    // TF01b `single_call_bytes_exact` (3.x typed) ordinary proof: no
    // admission pre-Init.
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (b, _base, _functions) = backend();
    let spec =
        CkOutputBufferSpec { buffer_present: true, buffer_len: 8, length_pointer_null: false };
    assert_eq!(
        b.ffi_wrap_authenticated_exact_typed(
            CkSessionHandle(4),
            &mechanism(),
            None,
            CkObjectHandle(8),
            CkObjectHandle(9),
            CkInBuf::Bytes(&[]),
            &spec,
        )
        .unwrap_err(),
        CkRv::CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
fn wrap_authenticated_exact_typed_admitted_after_lifecycle_open() {
    // Control: the same call reaches the stub once the domain is open.
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (b, _base, _functions) = backend();
    b.lifecycle_domain.open_for_tests();
    let spec =
        CkOutputBufferSpec { buffer_present: true, buffer_len: 8, length_pointer_null: false };
    let (output, _effects) = b
        .ffi_wrap_authenticated_exact_typed(
            CkSessionHandle(4),
            &mechanism(),
            None,
            CkObjectHandle(8),
            CkObjectHandle(9),
            CkInBuf::Bytes(&[]),
            &spec,
        )
        .unwrap();
    assert_eq!(output.ck_rv, CkRv::OK);
}

#[test]
fn wrap_authenticated_typed_denied_before_lifecycle_open() {
    // TF01b wrap convenience (no-retry two-call) ordinary proof: no admission
    // pre-Init.
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    FAIL_SIZING.store(false, Ordering::SeqCst);
    MUTATE_SIZING_INPUTS.store(false, Ordering::SeqCst);
    let (b, _base, _functions) = backend();
    assert_eq!(
        b.ffi_wrap_authenticated_typed(
            CkSessionHandle(4),
            &mechanism(),
            None,
            CkObjectHandle(8),
            CkObjectHandle(9),
            CkInBuf::Bytes(&[]),
        )
        .unwrap_err(),
        CkRv::CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
fn wrap_authenticated_typed_admitted_after_lifecycle_open() {
    // Control: the same call reaches the stub once the domain is open.
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    FAIL_SIZING.store(false, Ordering::SeqCst);
    MUTATE_SIZING_INPUTS.store(false, Ordering::SeqCst);
    let (b, _base, _functions) = backend();
    b.lifecycle_domain.open_for_tests();
    let (wrapped, _effects) = b
        .ffi_wrap_authenticated_typed(
            CkSessionHandle(4),
            &mechanism(),
            None,
            CkObjectHandle(8),
            CkObjectHandle(9),
            CkInBuf::Bytes(&[]),
        )
        .unwrap();
    assert_eq!(wrapped.expose(|raw| raw.len()), 8);
}

#[test]
fn unwrap_authenticated_typed_denied_before_lifecycle_open() {
    // TF01b unwrap (single direct, routed via `call_object_output`) ordinary
    // proof: no admission pre-Init.
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (b, _base, _functions) = backend();
    assert_eq!(
        b.ffi_unwrap_authenticated_typed(
            CkSessionHandle(4),
            &mechanism(),
            None,
            CkObjectHandle(8),
            CkInBuf::Bytes(&[0u8; 8]),
            None,
            CkInBuf::Bytes(&[]),
        )
        .unwrap_err(),
        CkRv::CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
fn unwrap_authenticated_typed_admitted_after_lifecycle_open() {
    // Control: the same call reaches the stub once the domain is open.
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (b, _base, _functions) = backend();
    b.lifecycle_domain.open_for_tests();
    let (handle, _effects) = b
        .ffi_unwrap_authenticated_typed(
            CkSessionHandle(4),
            &mechanism(),
            None,
            CkObjectHandle(8),
            CkInBuf::Bytes(&[0u8; 8]),
            None,
            CkInBuf::Bytes(&[]),
        )
        .unwrap();
    assert_eq!(handle, CkObjectHandle(77));
}
