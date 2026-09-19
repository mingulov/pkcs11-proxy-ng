//! Live cross-width topology test (ADR-0011 Phase A).
//!
//! Runs the shim against an **out-of-process** daemon so the client and
//! backend `CK_ULONG` widths can genuinely differ — the in-process
//! TestDaemon suites are always same-width. When this test binary is
//! built for `i686-unknown-linux-gnu` and the daemon is the native
//! x86_64 build, the width bridge is engaged for real
//! (client width 4, advertised backend width 8).
//!
//! Ignored by default: requires `scripts/run-cross-width-live-test.sh`
//! (or an operator) to start a daemon and set both
//! `PKCS11_PROXY_CROSS_TEST=1` and `PKCS11_PROXY_ENDPOINT`.

use super::*;

fn cross_test_enabled() -> bool {
    if std::env::var("PKCS11_PROXY_CROSS_TEST").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipping: PKCS11_PROXY_CROSS_TEST=1 not set (needs a live daemon)");
    false
}

#[test]
#[ignore = "needs a live daemon; run via scripts/run-cross-width-live-test.sh"]
fn live_probe_records_backend_ulong_width() {
    if !cross_test_enabled() {
        return;
    }
    eprintln!("cross-width-executed=probe-width");
    let _guard = shim_state_test_guard();
    let rv = unsafe { dispatch::general::c_initialize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Initialize against the live daemon");
    let width = crate::interface_probe::backend_ulong_size();
    let rv = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Finalize");
    let expected: usize = std::env::var("PKCS11_PROXY_CROSS_EXPECT_BACKEND_WIDTH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);
    assert_eq!(
        width, expected,
        "the daemon-advertised CK_ULONG width must be recorded by C_Initialize (D2)"
    );
}

#[test]
#[ignore = "needs a live daemon; run via scripts/run-cross-width-live-test.sh"]
fn live_daemon_bridges_ulong_widths_end_to_end() {
    if !cross_test_enabled() {
        return;
    }
    eprintln!("cross-width-executed=bridge-end-to-end");
    let _guard = shim_state_test_guard();

    let rv = unsafe { dispatch::general::c_initialize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Initialize against the live daemon");

    // Two-call slot list (tokens present only).
    let mut slot_count: CK_ULONG = 0;
    let rv = unsafe {
        dispatch::general::c_get_slot_list(CK_TRUE, std::ptr::null_mut(), &mut slot_count)
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetSlotList(count)");
    assert!(slot_count > 0, "live daemon should expose an initialized token");
    let mut slots = vec![0 as CK_SLOT_ID; slot_count as usize];
    let rv =
        unsafe { dispatch::general::c_get_slot_list(CK_TRUE, slots.as_mut_ptr(), &mut slot_count) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetSlotList(data)");
    let slot = slots[0];

    // Token info: every CK_ULONG field must arrive either as the
    // client-width CK_UNAVAILABLE_INFORMATION sentinel (D10) or as a
    // plausible small value — never as a truncated wide value.
    let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    let rv = unsafe { dispatch::general::c_get_token_info(slot, &mut info) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetTokenInfo");
    for (name, v) in [
        ("ulMaxSessionCount", info.ulMaxSessionCount),
        ("ulSessionCount", info.ulSessionCount),
        ("ulMaxRwSessionCount", info.ulMaxRwSessionCount),
        ("ulRwSessionCount", info.ulRwSessionCount),
        ("ulTotalPublicMemory", info.ulTotalPublicMemory),
        ("ulFreePublicMemory", info.ulFreePublicMemory),
        ("ulTotalPrivateMemory", info.ulTotalPrivateMemory),
        ("ulFreePrivateMemory", info.ulFreePrivateMemory),
    ] {
        assert!(
            v == CK_UNAVAILABLE_INFORMATION
                || v == CK_EFFECTIVELY_INFINITE
                || (v as u64) < (1 << 31),
            "{name} = {v:#x} is neither a client-width sentinel nor plausible"
        );
    }

    let mut session = CK_INVALID_HANDLE;
    let rv = unsafe {
        dispatch::general::c_open_session(
            slot,
            CKF_SERIAL_SESSION | CKF_RW_SESSION,
            std::ptr::null_mut(),
            None,
            &mut session,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_OpenSession");

    // Public session data object — no login required.
    let mut class: CK_ULONG = CKO_DATA;
    let mut token_false: CK_BBOOL = CK_FALSE;
    let mut private_false: CK_BBOOL = CK_FALSE;
    let mut value = *b"cross-width probe";
    let mut template = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &mut class as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN,
            pValue: &mut token_false as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: 1,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE,
            pValue: &mut private_false as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: 1,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE,
            pValue: value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: value.len() as CK_ULONG,
        },
    ];
    let mut object = CK_INVALID_HANDLE;
    let rv = unsafe {
        dispatch::general::c_create_object(
            session,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut object,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CreateObject(session data object)");

    // THE bridge discriminator: the backend natively reports
    // sizeof(backend CK_ULONG) for a CKA_CLASS size query. The client
    // must observe its own width instead (4 on i686, unbridged would be 8).
    let mut attr = CK_ATTRIBUTE { type_: CKA_CLASS, pValue: std::ptr::null_mut(), ulValueLen: 0 };
    let rv = unsafe { dispatch::general::c_get_attribute_value(session, object, &mut attr, 1) };
    assert_eq!(rv, CKR_OK as CK_RV, "CKA_CLASS size query");
    assert_eq!(
        attr.ulValueLen as usize,
        std::mem::size_of::<CK_ULONG>(),
        "CKA_CLASS size must be the CLIENT's CK_ULONG width"
    );

    // Exact-fit data query: value bytes re-encoded to client width.
    let mut class_buf = [0u8; std::mem::size_of::<CK_ULONG>()];
    let mut attr = CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: class_buf.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: class_buf.len() as CK_ULONG,
    };
    let rv = unsafe { dispatch::general::c_get_attribute_value(session, object, &mut attr, 1) };
    assert_eq!(rv, CKR_OK as CK_RV, "CKA_CLASS data query");
    assert_eq!(attr.ulValueLen as usize, class_buf.len());
    assert_eq!(CK_ULONG::from_ne_bytes(class_buf), CKO_DATA, "CKA_CLASS value");

    // Too-small buffer: exact/raw semantics forward the backend's
    // CKR_BUFFER_TOO_SMALL, and the CK_UNAVAILABLE_INFORMATION length
    // sentinel must arrive at the CLIENT's width (D10 end-to-end).
    let mut tiny = [0u8; 2];
    let mut attr = CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: tiny.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: tiny.len() as CK_ULONG,
    };
    let rv = unsafe { dispatch::general::c_get_attribute_value(session, object, &mut attr, 1) };
    assert_eq!(rv, CKR_BUFFER_TOO_SMALL as CK_RV, "too-small CKA_CLASS query");
    // E0793: CK_ATTRIBUTE is packed on Windows; assert on a by-value copy.
    let ul_value_len = attr.ulValueLen;
    assert_eq!(
        ul_value_len, CK_UNAVAILABLE_INFORMATION,
        "sentinel must be the client-width all-ones value"
    );

    let rv = unsafe { dispatch::general::c_close_session(session) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseSession");
    let rv = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Finalize");
}

#[test]
#[ignore = "needs a live daemon; run via scripts/run-cross-width-live-test.sh"]
fn live_wait_nonblocking_event_path() {
    // TO26b groups 3+7: the nonblocking event path against a REAL provider
    // at this leg's widths — a genuine `C_WaitForSlotEvent` round trip,
    // not a status echo. Per-provider classification (ownership §7 rule):
    // SoftHSM2 serves NO_EVENT when idle (event path qualified); NSS
    // softokn natively answers FUNCTION_NOT_SUPPORTED (its own
    // unsupported Wait proves no event path — inferred from end-to-end
    // passthrough + mapped-module receipt).
    // Either way the caller cell keeps its canary. The runner declares
    // the provider via PKCS11_PROXY_CROSS_PROVIDER; anything else fails
    // loudly (no silent default — an unclassified provider proves nothing).
    if !cross_test_enabled() {
        return;
    }
    eprintln!("cross-width-executed=wait-no-event");
    let _guard = shim_state_test_guard();
    let expected: CK_RV = match std::env::var("PKCS11_PROXY_CROSS_PROVIDER").as_deref() {
        Ok("softhsm2") => CKR_NO_EVENT as CK_RV,
        Ok("nss") => CKR_FUNCTION_NOT_SUPPORTED as CK_RV,
        other => panic!(
            "unclassified wait provider (runner must set PKCS11_PROXY_CROSS_PROVIDER): {other:?}"
        ),
    };

    let rv = unsafe { dispatch::general::c_initialize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Initialize against the live daemon");

    let mut slot: CK_SLOT_ID = CK_SLOT_ID::MAX - 3;
    let rv = unsafe {
        dispatch::general::c_wait_for_slot_event(CKF_DONT_BLOCK, &mut slot, std::ptr::null_mut())
    };
    assert_eq!(rv, expected, "classified nonblocking wait outcome");
    assert_eq!(slot, CK_SLOT_ID::MAX - 3, "a non-OK wait must not write the caller slot");

    let rv = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Finalize");
}
