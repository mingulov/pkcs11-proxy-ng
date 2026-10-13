//! Native-owner test hooks (C3M.6 row 18).
//!
//! Compiled only behind the `native-owner-test-hooks` feature (default
//! off). Normal builds must observe [`crate::NATIVE_OWNER_TEST_HOOKS_ENABLED`]
//! as `false` with no hook symbols and no control listener; the daemon
//! control plane arrives behind this same feature.
//!
//! The surface behind this gate is deliberately narrow: a daemon instance
//! identity (so subprocess/topology fault-injection tests can tell daemon
//! restarts apart), a last-mechanism echo (so tests can assert exactly
//! which `(mech, param)` bytes a native owner received), and a fault
//! injector (so tests can force failing closes without a hostile HSM).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

/// Monotonic hook-call sequence shared by every hook in this module.
static HOOK_SEQ: AtomicU64 = AtomicU64::new(0);

/// Process-unique daemon backend instance identity.
///
/// Assigned once per process from process id, wall-clock nanos, and the
/// hook-call sequence, so that two daemon processes (or a restarted daemon
/// under a subprocess runner) never share an identity, while repeated reads
/// in one process are stable. (A bare in-process counter is NOT enough: a
/// fresh process would restart the counter at the same value — caught by
/// the subprocess topology test.)
pub fn daemon_instance_id() -> u64 {
    static INSTANCE: OnceLock<u64> = OnceLock::new();
    *INSTANCE.get_or_init(|| {
        let pid = std::process::id() as u64;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x1234_5678);
        let seq = HOOK_SEQ.fetch_add(1, Ordering::Relaxed);
        pid.wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(nanos ^ nanos.wrapping_shr(32))
            .wrapping_add(seq.wrapping_mul(0xBF58_476D_1CE4_E5B9))
            | 1
    })
}

/// Last `(mechanism, parameter)` bytes observed crossing into a native
/// owner, for hook-enabled echo assertions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MechanismEcho {
    /// Hook-call sequence number of the observation.
    pub seq: u64,
    /// Raw `CK_MECHANISM_TYPE`.
    pub mechanism: u64,
    /// Copied mechanism parameter bytes.
    pub parameter: Vec<u8>,
}

static LAST_ECHO: Mutex<Option<MechanismEcho>> = Mutex::new(None);

/// Record a mechanism observation. Returns the assigned sequence number.
pub fn record_mechanism(mechanism: u64, parameter: &[u8]) -> u64 {
    let seq = HOOK_SEQ.fetch_add(1, Ordering::Relaxed);
    *LAST_ECHO.lock().expect("hook echo lock") =
        Some(MechanismEcho { seq, mechanism, parameter: parameter.to_vec() });
    seq
}

/// Take (and clear) the last mechanism observation, if any.
pub fn take_last_mechanism() -> Option<MechanismEcho> {
    LAST_ECHO.lock().expect("hook echo lock").take()
}

/// Fault-injection switch for native-owner closes.
///
/// When armed, the next FFI `C_CloseSession` fails with the transient
/// `FUNCTION_FAILED` WITHOUT native entry, settling its fence exactly
/// like a native close failure (reopen — owners, marker and mapping
/// kept, session remains usable and retryable). Lets topology tests
/// drive the control channel end to end without a hostile provider.
/// One-shot; normal builds compile the check out entirely.
pub fn set_fail_next_close(fail: bool) {
    FAIL_NEXT_CLOSE.store(fail, Ordering::SeqCst);
}

/// Consume one pending injected close failure, if armed.
pub fn take_fail_next_close() -> bool {
    FAIL_NEXT_CLOSE.swap(false, Ordering::SeqCst)
}

static FAIL_NEXT_CLOSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// A native session-lifecycle entry observed crossing into a real
/// provider (Q01 loaded oracle): counted, ordered proof of which native
/// calls the proxy issued. Recorded at native ENTRY (before the call),
/// so an entry proves the call started; completion is observed
/// separately (daemon mapping state, session info).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeSessionEvent {
    /// Native `C_OpenSession` entry on `slot`.
    OpenSession { slot: u64 },
    /// Native `C_CloseSession` entry for `session`.
    CloseSession { session: u64 },
    /// Native `C_CloseSession` completion for `session`: the provider
    /// call returned (either outcome). Pairs with the entry above and
    /// lets cancellation tests wait for true native completion instead
    /// of inferring it.
    CloseSessionCompleted { session: u64 },
    /// Native `C_CloseAllSessions` entry on `slot`.
    CloseAllSessions { slot: u64 },
    /// Native `C_Login` entry for `session`.
    Login { session: u64 },
    /// Native `C_Logout` entry for `session`.
    Logout { session: u64 },
}

static NATIVE_SESSION_EVENTS: Mutex<Vec<(u64, NativeSessionEvent)>> = Mutex::new(Vec::new());

/// Record a native session-lifecycle entry. Returns the assigned
/// hook-call sequence number (orders entries across kinds).
pub fn record_native_session_event(event: NativeSessionEvent) -> u64 {
    let seq = HOOK_SEQ.fetch_add(1, Ordering::Relaxed);
    NATIVE_SESSION_EVENTS.lock().expect("hook events lock").push((seq, event));
    seq
}

/// Take (and clear) all recorded native session-lifecycle entries, in
/// recording order. Callers clear before each measurement; the log is
/// process-global, so hook-gated suites run single-threaded.
pub fn take_native_session_events() -> Vec<(u64, NativeSessionEvent)> {
    std::mem::take(&mut *NATIVE_SESSION_EVENTS.lock().expect("hook events lock"))
}

/// One-shot wedge for the next native `C_CloseSession` entry (Q01 loaded
/// oracle): the entering close sleeps `delay` BEFORE the native call,
/// so cancellation tests can cancel provably in flight (the entry is
/// recorded before the sleep). Consumed at entry; normal builds compile
/// the check out entirely.
pub fn set_native_close_delay_once(delay: std::time::Duration) {
    *NATIVE_CLOSE_DELAY.lock().expect("hook delay lock") = Some(delay);
}

/// Consume one pending native close-entry wedge, if armed.
pub fn take_native_close_delay() -> Option<std::time::Duration> {
    NATIVE_CLOSE_DELAY.lock().expect("hook delay lock").take()
}

static NATIVE_CLOSE_DELAY: Mutex<Option<std::time::Duration>> = Mutex::new(None);

#[cfg(test)]
mod presence_tests {
    use super::*;

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn feature_flag_reports_enabled() {
        assert!(
            crate::NATIVE_OWNER_TEST_HOOKS_ENABLED,
            "hook build must report the hook surface as enabled"
        );
    }

    #[test]
    fn instance_id_is_stable_within_process() {
        assert_eq!(daemon_instance_id(), daemon_instance_id());
        assert_ne!(daemon_instance_id(), 0);
    }

    #[test]
    fn mechanism_echo_round_trips() {
        assert_eq!(take_last_mechanism(), None);
        let seq = record_mechanism(0x1082, &[1, 2, 3]);
        let echo = take_last_mechanism().expect("echo must be recorded");
        assert_eq!(echo.seq, seq);
        assert_eq!(echo.mechanism, 0x1082);
        assert_eq!(echo.parameter, vec![1, 2, 3]);
        assert_eq!(take_last_mechanism(), None);
    }

    #[test]
    fn close_fault_injector_arms_and_consumes() {
        assert!(!take_fail_next_close());
        set_fail_next_close(true);
        assert!(take_fail_next_close());
        assert!(!take_fail_next_close());
    }

    #[test]
    fn native_session_events_round_trip_in_order() {
        let _ = take_native_session_events();
        let first = record_native_session_event(NativeSessionEvent::CloseSession { session: 7 });
        let second = record_native_session_event(NativeSessionEvent::Logout { session: 7 });
        assert!(second > first, "sequence numbers must order entries");
        let events = take_native_session_events();
        assert_eq!(
            events,
            vec![
                (first, NativeSessionEvent::CloseSession { session: 7 }),
                (second, NativeSessionEvent::Logout { session: 7 }),
            ]
        );
        assert!(take_native_session_events().is_empty());
    }

    #[test]
    fn native_close_delay_wedge_arms_and_consumes() {
        assert_eq!(take_native_close_delay(), None);
        set_native_close_delay_once(std::time::Duration::from_millis(5));
        assert_eq!(take_native_close_delay(), Some(std::time::Duration::from_millis(5)));
        assert_eq!(take_native_close_delay(), None);
    }
}
