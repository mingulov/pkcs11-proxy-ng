#![cfg(not(miri))] // Miri does not support real sockets for the dial-count listener.

//! Pre-init behavior contract (T07, C-B2): fresh-process tests proving that
//! operations requiring initialization return `CKR_CRYPTOKI_NOT_INITIALIZED`
//! before touching the mechanism registry or the daemon.
//!
//! This binary NEVER calls `C_Initialize`, so every test here runs pre-init
//! (no `OnceLock` reset tricks — the process itself is the isolation). A
//! single sequential `#[test]` drives the whole contract so environment and
//! dial-count observations stay deterministic under the harness's parallel
//! runner.

use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use cryptoki_sys::*;
use pkcs11_proxy_ng_shim::__test_api::{is_initialized, try_mechanism_registry};
use pkcs11_proxy_ng_types::CkRv;

/// Spawn an accept-and-count drain on `listener`: every accepted connection
/// is counted and immediately closed (it is never a real daemon — the TCP
/// handshake succeeds, the gRPC handshake then fails fast).
fn spawn_dial_counter(listener: TcpListener, stop: Arc<AtomicBool>) -> Arc<AtomicUsize> {
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = Arc::clone(&count);
    listener.set_nonblocking(true).expect("listener nonblocking");
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    count_clone.fetch_add(1, Ordering::Relaxed);
                    drop(stream);
                }
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    });
    count
}

fn wait_for_dials(count: &AtomicUsize, at_least: usize, timeout: Duration) {
    let start = Instant::now();
    while count.load(Ordering::Relaxed) < at_least {
        assert!(start.elapsed() < timeout, "timed out waiting for the probe dial");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn function_list_240() -> *mut CK_FUNCTION_LIST {
    let mut list: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let rv = unsafe { pkcs11_proxy_ng_shim::C_GetFunctionList(&mut list) };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!list.is_null());
    list
}

fn function_list_3_2() -> *mut CK_FUNCTION_LIST_3_2 {
    let mut iface: *mut CK_INTERFACE = std::ptr::null_mut();
    let mut version = CK_VERSION { major: 3, minor: 2 };
    let rv = unsafe {
        pkcs11_proxy_ng_shim::C_GetInterface(
            c"PKCS 11".as_ptr() as *mut CK_UTF8CHAR,
            &mut version,
            &mut iface,
            0,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert!(!iface.is_null());
    let p_functions = unsafe { (*iface).pFunctionList };
    assert!(!p_functions.is_null());
    p_functions as *mut CK_FUNCTION_LIST_3_2
}

#[test]
fn pre_init_calls_return_not_initialized_without_dialing() {
    // Fresh process: not initialized and no registry installed (the
    // fallible accessor reports NOT_INITIALIZED instead of panicking).
    assert!(!is_initialized());
    assert!(matches!(try_mechanism_registry(), Err(CkRv::CRYPTOKI_NOT_INITIALIZED)));

    // Point the shim at a listener we own so any dial is observable, and
    // pin the probe to a single fast-failing attempt.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind dial-count listener");
    let port = listener.local_addr().expect("listener addr").port();
    let stop = Arc::new(AtomicBool::new(false));
    let dials = spawn_dial_counter(listener, Arc::clone(&stop));
    unsafe {
        std::env::set_var("PKCS11_PROXY_ENDPOINT", format!("http://127.0.0.1:{port}"));
        std::env::set_var("PKCS11_PROXY_CONNECT_ATTEMPTS", "1");
        std::env::remove_var("PKCS11_PROXY_SOCKET");
    }

    // Pre-init introspection keeps working (T07 preserves it): fetch both
    // function lists up front. The best-effort probes dial and fail fast
    // against our non-daemon listener; tonic may also lazily reconnect
    // when a later probe drives the runtime, so settle before snapshotting
    // — after the snapshot only guard-returning data calls run, and those
    // never touch the runtime, so no reconnect can be driven.
    let list = function_list_240();
    let list_3_2 = function_list_3_2();
    wait_for_dials(&dials, 1, Duration::from_secs(10));
    std::thread::sleep(Duration::from_millis(500));
    let dials_after_probe = dials.load(Ordering::Relaxed);

    // Valid accessible argument storage for every call below.
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut token_false: CK_BBOOL = CK_FALSE;
    let mut template = [CK_ATTRIBUTE {
        type_: CKA_TOKEN,
        pValue: (&mut token_false as *mut CK_BBOOL).cast(),
        ulValueLen: 1,
    }];
    let mut out_buf = [0u8; 64];
    let mut out_len: CK_ULONG = out_buf.len() as CK_ULONG;
    let mut wrapped = [0xABu8; 32];
    let mut handle: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    let mut handle2: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    let mut op_state = [0xCDu8; 16];
    const NOT_INIT: CK_RV = CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV;

    unsafe {
        let fl = &*list;
        assert_eq!(
            fl.C_WrapKey.unwrap()(0, &mut mechanism, 0, 0, out_buf.as_mut_ptr(), &mut out_len),
            NOT_INIT,
            "C_WrapKey pre-init"
        );
        assert_eq!(
            fl.C_UnwrapKey.unwrap()(
                0,
                &mut mechanism,
                0,
                wrapped.as_mut_ptr(),
                wrapped.len() as CK_ULONG,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut handle
            ),
            NOT_INIT,
            "C_UnwrapKey pre-init"
        );
        assert_eq!(
            fl.C_DeriveKey.unwrap()(
                0,
                &mut mechanism,
                0,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut handle
            ),
            NOT_INIT,
            "C_DeriveKey pre-init"
        );
        assert_eq!(
            fl.C_GenerateKey.unwrap()(
                0,
                &mut mechanism,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut handle
            ),
            NOT_INIT,
            "C_GenerateKey pre-init"
        );
        assert_eq!(
            fl.C_GenerateKeyPair.unwrap()(
                0,
                &mut mechanism,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut handle,
                &mut handle2
            ),
            NOT_INIT,
            "C_GenerateKeyPair pre-init"
        );
        assert_eq!(
            fl.C_SetOperationState.unwrap()(
                0,
                op_state.as_mut_ptr(),
                op_state.len() as CK_ULONG,
                0,
                0
            ),
            NOT_INIT,
            "C_SetOperationState pre-init"
        );

        let fl32 = &*list_3_2;
        assert_eq!(
            fl32.C_EncapsulateKey.unwrap()(
                0,
                &mut mechanism,
                0,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                out_buf.as_mut_ptr(),
                &mut out_len,
                &mut handle
            ),
            NOT_INIT,
            "C_EncapsulateKey pre-init"
        );
        assert_eq!(
            fl32.C_DecapsulateKey.unwrap()(
                0,
                &mut mechanism,
                0,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                wrapped.as_mut_ptr(),
                wrapped.len() as CK_ULONG,
                &mut handle
            ),
            NOT_INIT,
            "C_DecapsulateKey pre-init"
        );
    }

    // No data-plane call dialed: a regression that reached the transport
    // would have added a localhost dial within milliseconds.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        dials.load(Ordering::Relaxed),
        dials_after_probe,
        "pre-init data calls must not dial the daemon"
    );
    stop.store(true, Ordering::Relaxed);
}
