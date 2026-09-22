// W1-L12-03: test diagnostics (skip notices, progress, summaries) go to
// stderr by design; the workspace lint table denies this sink elsewhere.
#![allow(clippy::print_stderr)]
//! PIN-leak integration test.
//!
//! Drives the daemon at TRACE level with deliberately unique PIN canary
//! strings, captures every tracing event into an in-memory buffer, and
//! then asserts none of the canaries appear in the captured output —
//! neither in message bodies nor in structured fields. A regression here
//! is a security-class failure.
//!
//! Scope:
//!   - Tracing emitted by daemon handlers (`tracing::info!`, `warn!`,
//!     `debug!`, `trace!`) at TRACE filter level.
//!   - Operations covered: C_InitToken, C_Login (all user types),
//!     C_Logout, C_InitPIN, C_SetPIN, C_LoginUser. These are the
//!     PIN-bearing PKCS#11 calls.
//!
//! Out of scope here (covered by a compiler-enforced gate, not this test):
//!   - Direct `println!`/`eprintln!`/`dbg!` writes — not captured by
//!     tracing-subscriber. W1-L12-03 + W1-L2-08 deny those sinks
//!     workspace-wide via `[workspace.lints.clippy]` in the root
//!     `Cargo.toml`, so a new sink fails `cargo clippy --all-targets
//!     --all-features`; `print_sink_gate.rs` (same directory) audits the
//!     enumerated allow set and every sink/allow pair under plain `cargo
//!     test`, with negative controls. No review carve-out remains.
//!   - PINs that leave the daemon over the gRPC response wire — handled
//!     by transport-layer mTLS; not in scope for this test.

use std::io::{self, Write};
use std::sync::{Arc, Mutex, OnceLock};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

mod common_3x;

// ---- canaries --------------------------------------------------------------
// Each PIN canary is a high-entropy unique string. Substring matching is
// strict: if the canary or any 16-byte prefix appears anywhere in captured
// log output, the test fails.

const USER_PIN_CANARY: &[u8] = b"PINLEAK-USER-PIN-7c3b9f4e2a1d8e6f-canary";
const SO_PIN_CANARY: &[u8] = b"PINLEAK-SO-PIN-3a8c4e7b9d2f1e6c-canary";
const NEW_PIN_CANARY: &[u8] = b"PINLEAK-NEW-PIN-bb44ee77cc11ff88-canary";
const USERNAME_CANARY: &[u8] = b"PINLEAK-USERNAME-aa55cc33dd99ee11-canary";

// 16-byte prefixes — also banned, so even a partial leak (e.g. truncated
// debug output) is caught.
const CANARY_PREFIXES: &[&[u8]] = &[
    b"PINLEAK-USER-PIN",
    b"PINLEAK-SO-PIN",
    b"PINLEAK-NEW-PIN",
    // W1-C2-10: without the username prefix, a truncated username leak
    // shorter than the full canary evaded the prefix scan.
    b"PINLEAK-USERNAME",
];

// ---- shared buffer + MakeWriter -------------------------------------------

#[derive(Clone)]
struct CaptureBuf(Arc<Mutex<Vec<u8>>>);

impl CaptureBuf {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }
    fn snapshot(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

impl Write for CaptureBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CaptureBuf {
    type Writer = CaptureBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

// The capture buffer is process-global because `tracing` installs a
// single global subscriber. We initialise it lazily once.
static GLOBAL_BUF: OnceLock<CaptureBuf> = OnceLock::new();

fn install_global_capture() -> CaptureBuf {
    GLOBAL_BUF
        .get_or_init(|| {
            let buf = CaptureBuf::new();
            tracing_subscriber::fmt()
                .with_writer(buf.clone())
                // Force TRACE level regardless of RUST_LOG so this test
                // exercises the worst-case "operator turned verbosity to
                // maximum" scenario.
                .with_env_filter(EnvFilter::new("trace"))
                .with_target(true)
                .json()
                .try_init()
                .ok();
            buf
        })
        .clone()
}

// ---- canary scanning ------------------------------------------------------

fn assert_no_canary_in_logs(label: &str, captured: &[u8]) {
    let canaries: &[&[u8]] = &[USER_PIN_CANARY, SO_PIN_CANARY, NEW_PIN_CANARY, USERNAME_CANARY];

    // Direct substring scan (exact match on raw bytes).
    for canary in canaries {
        assert!(
            !memmem(captured, canary),
            "SECURITY REGRESSION: canary {:?} found in captured logs after {label}.\n--- captured ---\n{}\n--- end ---",
            String::from_utf8_lossy(canary),
            String::from_utf8_lossy(captured),
        );
    }

    // Prefix scan — catches truncated debug output that drops the trailing
    // bytes but still emits the recognisable prefix.
    for prefix in CANARY_PREFIXES {
        assert!(
            !memmem(captured, prefix),
            "SECURITY REGRESSION: canary prefix {:?} found in logs after {label}",
            String::from_utf8_lossy(prefix),
        );
    }

    // Hex-escaped scan: if a Vec<u8> was Debug-formatted, bytes might be
    // rendered as e.g. `[82, 49, 49, ...]` or `\x52\x31...`. Catch the
    // first 6 bytes of any canary rendered as decimal-bracket Debug.
    for canary in canaries {
        let prefix_six = &canary[..6.min(canary.len())];
        let decimal_form: String =
            prefix_six.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", ");
        assert!(
            !memmem(captured, decimal_form.as_bytes()),
            "SECURITY REGRESSION: canary rendered as decimal Debug ({decimal_form}) found in logs after {label}"
        );
    }
}

/// Trivial byte substring search.  Avoids pulling in `memchr`.
fn memmem(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn truncated_username_leak_trips_prefix_scan() {
    // W1-C2-10: a username truncated past the full canary must still trip
    // the 16-byte PINLEAK-USERNAME prefix scan.
    assert_eq!(b"PINLEAK-USERNAME".len(), 16);
    assert!(USERNAME_CANARY.starts_with(b"PINLEAK-USERNAME"));
    let truncated_leak = b"op=user_login user=PINLEAK-USERNAME-aa55 (truncated)";
    assert!(
        CANARY_PREFIXES.iter().any(|p| memmem(truncated_leak, p)),
        "truncated PINLEAK-USERNAME leak must trip CANARY_PREFIXES"
    );
}

// ---- the actual test ------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn pins_never_appear_in_trace_logs() {
    let buf = install_global_capture();

    // Pre-test invariant: buffer is non-empty after some tracing fires,
    // and contains no canaries to start with. This catches a wiring
    // failure where the subscriber silently drops events.
    {
        tracing::info!(test = "pin_leak_test", "subscriber wiring check");
        // Give the subscriber a moment to flush.
        tokio::task::yield_now().await;
        let snap = buf.snapshot();
        assert!(
            memmem(&snap, b"subscriber wiring check"),
            "tracing subscriber did not capture sentinel log line — test would be vacuous",
        );
    }

    let backend = Arc::new(common_3x::mock(&[0], &[CkMechanismType::RSA_PKCS.0]));
    let (endpoint, _shutdown) = common_3x::mock_daemon(backend as Arc<dyn Pkcs11Backend>).await;
    let mut client = common_3x::init_client(&endpoint).await;

    // Use the virtual slot ID published by the daemon, not the raw
    // backend slot ID. ContextManager maps the two.
    let slots = client.get_slot_list(false).await.expect("get_slot_list");
    let slot = *slots.first().expect("at least one slot");

    // 1. C_InitToken — SO PIN as canary.
    let _ = client.init_token(slot, Some(SO_PIN_CANARY), "leak-test-token").await;
    tokio::task::yield_now().await;
    assert_no_canary_in_logs("init_token", &buf.snapshot());

    // 2. Open SO session, login SO, init user PIN.
    let session = client
        .open_session(
            slot,
            CkSessionFlags(CkSessionFlags::SERIAL_SESSION | CkSessionFlags::RW_SESSION),
        )
        .await
        .expect("open_session");

    let _ = client.login(session, CkUserType::So, Some(SO_PIN_CANARY)).await;
    tokio::task::yield_now().await;
    assert_no_canary_in_logs("login(SO)", &buf.snapshot());

    let _ = client.init_pin(session, Some(USER_PIN_CANARY)).await;
    tokio::task::yield_now().await;
    assert_no_canary_in_logs("init_pin", &buf.snapshot());

    let _ = client.logout(session).await;

    // 3. Login as USER, then C_SetPIN (old → new) and C_Login with USER PIN.
    let _ = client.login(session, CkUserType::User, Some(USER_PIN_CANARY)).await;
    tokio::task::yield_now().await;
    assert_no_canary_in_logs("login(USER)", &buf.snapshot());

    let _ = client.set_pin(session, Some(USER_PIN_CANARY), Some(NEW_PIN_CANARY)).await;
    tokio::task::yield_now().await;
    assert_no_canary_in_logs("set_pin", &buf.snapshot());

    let _ = client.logout(session).await;

    // 4. C_LoginUser (PKCS#11 3.0) — username + PIN both as canaries.
    // The mock backend rejects any pin != b"1234", so this will fail; the
    // failure path exercises both warn-level logging and the error
    // response code path. Both must redact PIN/username.
    let _ = client
        .login_user(session, CkUserType::User, Some(USERNAME_CANARY), Some(USER_PIN_CANARY))
        .await;
    tokio::task::yield_now().await;
    assert_no_canary_in_logs("login_user", &buf.snapshot());

    // 5. Negative-PIN paths — pass garbage non-canary so the error
    // formatter path is exercised without contaminating our canary scan.
    let _ = client.login(session, CkUserType::User, Some(b"garbage")).await;
    tokio::task::yield_now().await;
    assert_no_canary_in_logs("login(garbage)", &buf.snapshot());

    let _ = client.close_session(session).await;
    let _ = client.finalize().await;

    // Final whole-run scan.
    let final_snap = buf.snapshot();
    assert_no_canary_in_logs("full run", &final_snap);

    // Document the size of the captured corpus so CI logs show the
    // scan actually had bytes to search.
    eprintln!(
        "pin_leak_test: scanned {} bytes of captured tracing output; no canary leaks detected",
        final_snap.len(),
    );
    assert!(
        final_snap.len() > 256,
        "captured log corpus is suspiciously small ({} bytes); subscriber may have dropped events",
        final_snap.len(),
    );
}
