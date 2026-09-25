//! Live control-channel test (TO26b group 3).
//!
//! Drives the hook-gated daemon control plane end to end over its Unix
//! socket: the instance identity is stable and nonzero within the leg,
//! arming `fail-next-close` fails one `C_CloseSession` transiently with
//! `CKR_FUNCTION_FAILED` (no native entry), the session stays usable
//! afterwards (owners kept — a `C_Encrypt` size query still answers),
//! and the next close succeeds (one-shot consumed).
//!
//! Ignored by default: needs a hook-enabled daemon plus
//! `PKCS11_PROXY_CROSS_TEST=1`, `PKCS11_PROXY_ENDPOINT` and
//! `PKCS11_PROXY_TEST_HOOKS_CONTROL_SOCKET` (same harness contract as the oracle
//! legs; the row-12 runner provides all three). Unix-only: the control
//! plane is a Unix socket.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::*;

fn control_test_enabled() -> Option<String> {
    if std::env::var("PKCS11_PROXY_CROSS_TEST").as_deref() != Ok("1") {
        eprintln!("skipping: PKCS11_PROXY_CROSS_TEST=1 not set (needs a live hook daemon)");
        return None;
    }
    match std::env::var("PKCS11_PROXY_TEST_HOOKS_CONTROL_SOCKET") {
        Ok(path) if !path.is_empty() => Some(path),
        _ => {
            eprintln!(
                "skipping: PKCS11_PROXY_TEST_HOOKS_CONTROL_SOCKET not set (needs a hook daemon)"
            );
            None
        }
    }
}

fn control_round_trip(socket: &str, request: &str) -> String {
    let mut stream = UnixStream::connect(socket).expect("connect control socket");
    stream.set_read_timeout(Some(Duration::from_secs(5))).expect("read timeout");
    stream.write_all(request.as_bytes()).expect("write control request");
    stream.flush().expect("flush control request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read control response");
    response
}

fn control_get(socket: &str, path: &str) -> String {
    control_round_trip(socket, &format!("GET {path} HTTP/1.1\r\n\r\n"))
}

fn control_post(socket: &str, path: &str) -> String {
    control_round_trip(socket, &format!("POST {path} HTTP/1.1\r\nContent-Length: 0\r\n\r\n"))
}

fn instance_id_from(response: &str) -> u64 {
    assert!(response.starts_with("HTTP/1.1 200 OK"), "control instance 200, got: {response}");
    let body = response.lines().last().expect("instance body");
    body.trim_start_matches("{\"instance_id\":")
        .trim_end_matches('}')
        .parse()
        .expect("instance body parses")
}

#[test]
#[ignore = "needs a live hook-enabled daemon; run via the row-12 runner"]
fn live_control_channel_close_fault_loop() {
    let Some(socket) = control_test_enabled() else {
        return;
    };
    // Marker for the runner (--nocapture): distinguishes a real execution
    // from a leg-gated early return, which also reports ok.
    eprintln!("control-channel-executed=close-loop");
    let _guard = shim_state_test_guard();

    // The channel terminates in THIS daemon: stable nonzero identity.
    let first = control_get(&socket, "/hooks/instance");
    let second = control_get(&socket, "/hooks/instance");
    let id: u64 = instance_id_from(&first);
    assert_ne!(id, 0, "daemon instance id must be nonzero");
    assert_eq!(first, second, "instance id must be stable within one daemon");

    let rv = unsafe { dispatch::general::c_initialize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Initialize against the hook daemon");

    let mut slot_count: CK_ULONG = 0;
    let rv = unsafe {
        dispatch::general::c_get_slot_list(CK_TRUE, std::ptr::null_mut(), &mut slot_count)
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetSlotList(count)");
    assert!(slot_count > 0, "hook daemon must expose its synthetic slot");
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

    // Arm the injector over the control channel: the next close fails
    // transiently WITHOUT native entry and the session stays usable.
    let armed = control_post(&socket, "/hooks/fail-next-close");
    assert!(armed.starts_with("HTTP/1.1 200 OK"), "arm 200, got: {armed}");
    assert!(armed.ends_with("{\"armed\":true}\n"), "arm body, got: {armed}");
    let rv = unsafe { dispatch::general::c_close_session(session) };
    assert_eq!(rv, CKR_FUNCTION_FAILED as CK_RV, "injected close must fail transiently");

    // Owners kept: an encrypt size query through the session still answers
    // (roundtrip steering serves the canned length).
    let mut iv = [0x11u8; 16];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC,
        pParameter: iv.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: iv.len() as CK_ULONG,
    };
    let rv = unsafe { dispatch::general::c_encrypt_init(session, &mut mechanism, 1) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_EncryptInit after injected close failure");
    let data = b"control-channel-7";
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
    assert_eq!(rv, CKR_OK as CK_RV, "C_Encrypt(size) after injected close failure");
    assert_eq!(out_len as usize, 16, "oracle canned length");

    // One-shot consumed: the next close reaches native and succeeds.
    let rv = unsafe { dispatch::general::c_close_session(session) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseSession after injector consumed");
    let rv = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Finalize");
}
