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
/// When `true`, hook-aware close paths fail closed with `false` instead
/// of calling into the native owner, letting topology tests exercise the
/// retire-on-failed-close path without a hostile provider.
pub fn set_fail_next_close(fail: bool) {
    FAIL_NEXT_CLOSE.store(fail, Ordering::SeqCst);
}

/// Consume one pending injected close failure, if armed.
pub fn take_fail_next_close() -> bool {
    FAIL_NEXT_CLOSE.swap(false, Ordering::SeqCst)
}

static FAIL_NEXT_CLOSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

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
}
