// W1-L12-03: test diagnostics (skip notices, progress, summaries) go to
// stderr by design; the workspace lint table denies this sink elsewhere.
#![allow(clippy::print_stderr)]
//! Live retained-oracle topology test (C3M.6 row 12).
//!
//! Drives the **loaded shim C ABI** against an out-of-process daemon whose
//! backend is the deliberately retaining oracle (`retained_mechanisms`
//! cdylib): `C_EncryptInit` with a parameter-bearing mechanism, then
//! repeated `C_Encrypt` calls through the retained root, then close.
//! The oracle runs with `RETAINED_ORACLE_FAIL_UNLESS_PTR_EQUAL=1`, so a
//! backend that failed to keep the Init allocation alive observes
//! `CKR_DEVICE_ERROR` instead of `CKR_OK` — the roundtrip is a genuine
//! retention proof, not a status-code echo.
//!
//! Ignored by default: requires a live oracle daemon plus
//! `PKCS11_PROXY_CROSS_TEST=1` and `PKCS11_PROXY_ENDPOINT` (same harness
//! contract as `cross_width_live`; the row-12 runner starts the daemon
//! with the oracle module and the steering env).

use super::*;

fn oracle_test_enabled() -> bool {
    if std::env::var("PKCS11_PROXY_CROSS_TEST").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipping: PKCS11_PROXY_CROSS_TEST=1 not set (needs a live oracle daemon)");
    false
}

const ORACLE_CANARY: [u8; 16] = [0xC3; 16];

/// Which oracle scenario the runner armed in the daemon's environment:
/// `roundtrip` (default) serves the canary with the ptr gate on;
/// `error` fails every `C_Encrypt` with `CKR_DEVICE_ERROR`.
fn oracle_leg() -> String {
    std::env::var("RETAINED_ORACLE_LEG").unwrap_or_else(|_| "roundtrip".into())
}

/// TO26b group 3: the caller process must not load the oracle itself —
/// the oracle lives in the daemon (the runner proves that side via the
/// daemon's maps); a caller-side copy would pretend to control it.
#[cfg(target_os = "linux")]
fn assert_caller_has_no_oracle_loaded() {
    let maps = std::fs::read_to_string("/proc/self/maps").expect("read own maps");
    assert!(
        !maps.contains("retained_mechanism_oracle"),
        "caller must not load the oracle; it lives in the daemon process"
    );
}

#[cfg(not(target_os = "linux"))]
fn assert_caller_has_no_oracle_loaded() {}

#[test]
#[ignore = "needs a live oracle daemon; run via the row-12 runner"]
fn live_retained_oracle_encrypt_roundtrip() {
    if !oracle_test_enabled() || oracle_leg() != "roundtrip" {
        return;
    }
    // Marker for the runner (--nocapture): distinguishes a real execution
    // from a leg-gated early return, which also reports ok.
    eprintln!("retained-oracle-executed=roundtrip");
    assert_caller_has_no_oracle_loaded();
    let _guard = shim_state_test_guard();

    let rv = unsafe { dispatch::general::c_initialize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Initialize against the oracle daemon");

    let mut slot_count: CK_ULONG = 0;
    let rv = unsafe {
        dispatch::general::c_get_slot_list(CK_TRUE, std::ptr::null_mut(), &mut slot_count)
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetSlotList(count)");
    assert!(slot_count > 0, "oracle daemon must expose its synthetic slot");
    let mut slots = vec![0 as CK_SLOT_ID; slot_count as usize];
    let rv =
        unsafe { dispatch::general::c_get_slot_list(CK_TRUE, slots.as_mut_ptr(), &mut slot_count) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetSlotList(data)");
    let slot = slots[0];

    let mut session = CK_INVALID_HANDLE;
    let rv = unsafe {
        dispatch::general::c_open_session(
            slot,
            CKF_SERIAL_SESSION,
            std::ptr::null_mut(),
            None,
            &mut session,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_OpenSession");

    // Parameter-bearing mechanism: the backend must keep this allocation
    // (and its IV extent) alive across the native entries below.
    let mut iv = [0x11u8; 16];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC,
        pParameter: iv.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: iv.len() as CK_ULONG,
    };
    let rv = unsafe { dispatch::general::c_encrypt_init(session, &mut mechanism, 1) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_EncryptInit captures the retained root");

    let data = b"retained-oracle-7";
    // Size query through the retained root (ptr gate #1).
    let mut out_len: CK_ULONG = 0;
    let rv = unsafe {
        dispatch::general::c_encrypt(
            session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut out_len,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Encrypt(size) through the retained root");
    assert_eq!(out_len as usize, ORACLE_CANARY.len(), "oracle canned length");

    // Fill through the retained root: exact canary bytes (ptr gate #2 +
    // typed output effects end to end).
    let mut out = [0u8; 16];
    let mut fill_len: CK_ULONG = out.len() as CK_ULONG;
    let rv = unsafe {
        dispatch::general::c_encrypt(
            session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut fill_len,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Encrypt(data) through the retained root");
    assert_eq!(fill_len as usize, ORACLE_CANARY.len());
    assert_eq!(out, ORACLE_CANARY, "oracle canary bytes cross the wire intact");

    // A later operation through the same root, then clean teardown.
    let mut again_len: CK_ULONG = 0;
    let rv = unsafe {
        dispatch::general::c_encrypt(
            session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut again_len,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "second C_Encrypt through the retained root");
    assert_eq!(again_len as usize, ORACLE_CANARY.len());

    let rv = unsafe { dispatch::general::c_close_session(session) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseSession");
    let rv = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Finalize");
}

#[test]
#[ignore = "needs a live oracle daemon; run via the row-12 runner"]
fn live_retained_oracle_error_effects_and_cleanup() {
    // Row-12 error leg: with the daemon's scenario failing every
    // C_Encrypt, the exact provider RV must surface, and close plus
    // re-Init must still work afterwards (cleanup after error).
    if !oracle_test_enabled() || oracle_leg() != "error" {
        return;
    }
    // Marker for the runner (--nocapture): distinguishes a real execution
    // from a leg-gated early return, which also reports ok.
    eprintln!("retained-oracle-executed=error");
    assert_caller_has_no_oracle_loaded();
    let _guard = shim_state_test_guard();

    let rv = unsafe { dispatch::general::c_initialize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Initialize against the oracle daemon");

    let mut slot_count: CK_ULONG = 0;
    let rv = unsafe {
        dispatch::general::c_get_slot_list(CK_TRUE, std::ptr::null_mut(), &mut slot_count)
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetSlotList(count)");
    assert!(slot_count > 0, "oracle daemon must expose its synthetic slot");
    let mut slots = vec![0 as CK_SLOT_ID; slot_count as usize];
    let rv =
        unsafe { dispatch::general::c_get_slot_list(CK_TRUE, slots.as_mut_ptr(), &mut slot_count) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetSlotList(data)");

    let mut session = CK_INVALID_HANDLE;
    let rv = unsafe {
        dispatch::general::c_open_session(
            slots[0],
            CKF_SERIAL_SESSION,
            std::ptr::null_mut(),
            None,
            &mut session,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_OpenSession");

    let mut iv = [0x11u8; 16];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC,
        pParameter: iv.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: iv.len() as CK_ULONG,
    };
    let rv = unsafe { dispatch::general::c_encrypt_init(session, &mut mechanism, 1) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_EncryptInit still succeeds");

    let mut out_len: CK_ULONG = 0;
    let rv = unsafe {
        dispatch::general::c_encrypt(
            session,
            b"err".as_ptr() as CK_BYTE_PTR,
            3,
            std::ptr::null_mut(),
            &mut out_len,
        )
    };
    assert_eq!(rv, CKR_DEVICE_ERROR as CK_RV, "scenario RV surfaces exactly");

    let rv = unsafe { dispatch::general::c_close_session(session) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseSession works after the error");

    // Fresh session + Init after the error: the failed operation left no
    // poisoned owner behind.
    let mut session2 = CK_INVALID_HANDLE;
    let rv = unsafe {
        dispatch::general::c_open_session(
            slots[0],
            CKF_SERIAL_SESSION,
            std::ptr::null_mut(),
            None,
            &mut session2,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_OpenSession after error");
    let rv = unsafe { dispatch::general::c_encrypt_init(session2, &mut mechanism, 1) };
    assert_eq!(rv, CKR_OK as CK_RV, "re-Init after error");
    let rv = unsafe { dispatch::general::c_close_session(session2) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseSession(final)");
    let rv = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Finalize");
}
