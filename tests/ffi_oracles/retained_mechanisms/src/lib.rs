//! Deliberately retaining native provider oracle (C3M.6).
//!
//! Unlike well-behaved providers, this oracle retains the `CK_MECHANISM`
//! root address (and its parameter extent) received at `C_EncryptInit` and
//! reads back through that same root during the later `C_Encrypt` call —
//! emulating backends (e.g. OpenCryptoki) that store mechanism pointers.
//! It never copies parameters into private substitute buffers.
//!
//! The observation records addresses and values read through the retained
//! root; pointer-identity equality is computed test-side from those
//! recorded addresses. The oracle itself never dereferences foreign
//! pointers and never carries secret material: outputs are a fixed canary.
//!
//! Dual fixture: this module compiles in-process into backend contract
//! tests (default suite) and as an unpublished cdylib for
//! dlopen/subprocess/topology rows. Neither fixture substitutes for the
//! other; Miri cannot establish real dlopen provider behavior.
//!
//! Gate/phase controls (`ArmGate`/`ReleaseGate`, daemon-resident control
//! socket) arrive with the row-9 barrier slice, not here.
#![allow(non_snake_case, clippy::missing_safety_doc, clippy::unnecessary_cast)]
use cryptoki_sys::*;
use std::sync::Mutex;

#[cfg(not(test))]
mod provider;
#[cfg(test)]
pub mod provider;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RetainedOracleScenario {
    /// Raw CK_RV returned by C_Encrypt.
    pub encrypt_rv: u64,
    /// Canned output length produced by C_Encrypt.
    pub output_len: u64,
    /// When nonzero, C_Encrypt fails closed with CKR_DEVICE_ERROR unless
    /// the retained root reproduces the Init root (row-12 E2E retention
    /// proof through the plain C API).
    pub fail_unless_ptr_equal: u64,
}

/// Operation selector for [`RetainedOracle_ArmGate`]. Only Encrypt is gated
/// in this slice; further operations arrive with their rows.
pub const RETAINED_OP_ENCRYPT: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RetainedOracleObservation {
    pub init_calls: u64,
    pub encrypt_calls: u64,
    /// CK_MECHANISM address received at C_EncryptInit (0 when none).
    pub init_mech_ptr: u64,
    /// CK_MECHANISM address used at C_Encrypt (the retained root).
    pub encrypt_mech_ptr: u64,
    /// ulParameterLen read through the root at Init time.
    pub init_param_len: u64,
    /// ulParameterLen re-read through the retained root at Encrypt time.
    pub encrypt_param_len: u64,
    /// mechanism type re-read through the retained root at Encrypt time.
    pub encrypt_mech_type: u64,
    /// 1 when both calls observed one identical nonzero root.
    pub ptr_equal: u32,
    /// Currently armed gate operation (0 when open).
    pub gate_armed_op: u32,
    /// Native entries currently held at the gate.
    pub gate_holds_current: u64,
    /// Total entries ever held at the gate.
    pub gate_holds_total: u64,
}

struct ProviderState {
    retained_mech: u64,
    initialized: bool,
    next_session: u64,
}

static STATE: Mutex<(RetainedOracleScenario, RetainedOracleObservation, ProviderState)> =
    Mutex::new((
        RetainedOracleScenario { encrypt_rv: 0, output_len: 0, fail_unless_ptr_equal: 0 },
        RetainedOracleObservation {
            init_calls: 0,
            encrypt_calls: 0,
            init_mech_ptr: 0,
            encrypt_mech_ptr: 0,
            init_param_len: 0,
            encrypt_param_len: 0,
            encrypt_mech_type: 0,
            ptr_equal: 0,
            gate_armed_op: 0,
            gate_holds_current: 0,
            gate_holds_total: 0,
        },
        ProviderState { retained_mech: 0, initialized: false, next_session: 1 },
    ));

fn lock_state() -> std::sync::MutexGuard<
    'static,
    (RetainedOracleScenario, RetainedOracleObservation, ProviderState),
> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Process-global test serialization for every suite that drives this
/// oracle instance.
///
/// The sources compile both into the oracle's own test suite and (via
/// `#[path]`) into the backend contract-test binary, where the backend's
/// contract tests share the same instance state. Both groups must take
/// this one lock — separate per-file mutexes do not exclude each other
/// and produce order-dependent count/gate failures.
#[cfg(test)]
static TEST_SERIAL: Mutex<()> = Mutex::new(());

/// Acquire the oracle test serialization lock.
#[cfg(test)]
pub fn acquire_test_serial() -> std::sync::MutexGuard<'static, ()> {
    TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Observable entry barrier (row-9 mechanics).
///
/// While armed for an operation, every matching native entry waits here —
/// entered but not returned — until [`RetainedOracle_ReleaseGate`] opens
/// the gate. Lock order is always GATE then STATE, so observers reading
/// through [`RetainedOracle_GetObservation`] never deadlock against held
/// entries. Poisoning resolves to `into_inner` (non-unwinding); a poisoned
/// gate still opens on release.
struct GateState {
    armed_op: u32,
    holders: u64,
    total_holds: u64,
}

static GATE: Mutex<GateState> = Mutex::new(GateState { armed_op: 0, holders: 0, total_holds: 0 });
static GATE_CVAR: std::sync::Condvar = std::sync::Condvar::new();

fn sync_gate_observation(armed_op: u32, holders: u64, total_holds: u64) {
    let mut state = lock_state();
    state.1.gate_armed_op = armed_op;
    state.1.gate_holds_current = holders;
    state.1.gate_holds_total = total_holds;
}

/// Block the calling native entry while the gate is armed for `op`.
/// Never holds the STATE lock across the wait.
fn wait_at_gate(op: u32) {
    let mut gate = GATE.lock().unwrap_or_else(|e| e.into_inner());
    if gate.armed_op != op {
        return;
    }
    gate.holders += 1;
    gate.total_holds += 1;
    sync_gate_observation(gate.armed_op, gate.holders, gate.total_holds);
    while gate.armed_op == op {
        gate = GATE_CVAR.wait(gate).unwrap_or_else(|e| e.into_inner());
    }
    // Saturating: a mid-hold reset opens the gate and zeroes the count, so
    // a woken entry must not underflow it.
    gate.holders = gate.holders.saturating_sub(1);
    sync_gate_observation(gate.armed_op, gate.holders, gate.total_holds);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn RetainedOracle_ArmGate(op: u32) -> u32 {
    let mut gate = GATE.lock().unwrap_or_else(|e| e.into_inner());
    gate.armed_op = op;
    sync_gate_observation(gate.armed_op, gate.holders, gate.total_holds);
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn RetainedOracle_ReleaseGate() -> u32 {
    let mut gate = GATE.lock().unwrap_or_else(|e| e.into_inner());
    gate.armed_op = 0;
    GATE_CVAR.notify_all();
    sync_gate_observation(gate.armed_op, gate.holders, gate.total_holds);
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn RetainedOracle_SetScenario(
    scenario: *const RetainedOracleScenario,
) -> u32 {
    if scenario.is_null() {
        return 1;
    }
    lock_state().0 = unsafe { *scenario };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn RetainedOracle_ResetObservation() -> u32 {
    // Every observation counter is per-period (since the last reset), so
    // the gate lifetime counters reset here too; opening the gate with a
    // broadcast keeps a mid-hold reset from stranding entries.
    let mut gate = GATE.lock().unwrap_or_else(|e| e.into_inner());
    gate.armed_op = 0;
    gate.holders = 0;
    gate.total_holds = 0;
    GATE_CVAR.notify_all();
    drop(gate);
    let mut state = lock_state();
    state.1 = RetainedOracleObservation::default();
    state.2.retained_mech = 0;
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn RetainedOracle_GetObservation(
    observation: *mut RetainedOracleObservation,
) -> u32 {
    if observation.is_null() {
        return 1;
    }
    unsafe { observation.write(lock_state().1) };
    0
}

#[cfg(test)]
mod state_machine_tests {
    use super::*;
    use std::time::Duration;

    fn observation() -> RetainedOracleObservation {
        let mut observation = RetainedOracleObservation::default();
        assert_eq!(unsafe { RetainedOracle_GetObservation(&mut observation) }, 0);
        observation
    }

    /// Full hermetic start: gate open, default scenario, zeroed observation.
    /// Every test starts this way because scenario persists across resets.
    fn reset_full() {
        assert_eq!(unsafe { RetainedOracle_ReleaseGate() }, 0);
        assert_eq!(unsafe { RetainedOracle_SetScenario(&RetainedOracleScenario::default()) }, 0);
        assert_eq!(RetainedOracle_ResetObservation(), 0);
    }

    fn wait_for_holders(expected: u64) {
        let start = std::time::Instant::now();
        loop {
            let holders = GATE.lock().unwrap_or_else(|e| e.into_inner()).holders;
            if holders == expected {
                return;
            }
            if start.elapsed() > Duration::from_secs(10) {
                panic!("gate holders did not reach {expected}");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn scenario_roundtrip_preserves_values() {
        let _guard = acquire_test_serial();
        let scenario =
            RetainedOracleScenario { encrypt_rv: 7, output_len: 42, fail_unless_ptr_equal: 1 };
        assert_eq!(unsafe { RetainedOracle_SetScenario(&scenario) }, 0);
        assert_eq!(lock_state().0.encrypt_rv, 7);
        assert_eq!(lock_state().0.output_len, 42);
        assert_eq!(lock_state().0.fail_unless_ptr_equal, 1);
        reset_full();
    }

    #[test]
    fn null_control_arguments_rejected_without_panic() {
        let _guard = acquire_test_serial();
        assert_eq!(unsafe { RetainedOracle_SetScenario(std::ptr::null()) }, 1);
        assert_eq!(unsafe { RetainedOracle_GetObservation(std::ptr::null_mut()) }, 1);
    }

    #[test]
    fn reset_zeroes_counters_and_opens_gate() {
        let _guard = acquire_test_serial();
        reset_full();
        assert_eq!(unsafe { RetainedOracle_ArmGate(RETAINED_OP_ENCRYPT) }, 0);
        assert_eq!(observation().gate_armed_op, RETAINED_OP_ENCRYPT);
        assert_eq!(RetainedOracle_ResetObservation(), 0);
        let observation = observation();
        assert_eq!(observation.gate_armed_op, 0);
        assert_eq!(observation.gate_holds_current, 0);
        assert_eq!(observation.gate_holds_total, 0);
        assert_eq!(observation.init_calls, 0);
        assert_eq!(observation.encrypt_calls, 0);
        assert_eq!(unsafe { RetainedOracle_ReleaseGate() }, 0);
    }

    #[test]
    fn gate_holds_entry_until_released() {
        let _guard = acquire_test_serial();
        reset_full();
        assert_eq!(unsafe { RetainedOracle_ArmGate(RETAINED_OP_ENCRYPT) }, 0);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let mut length: CK_ULONG = 0;
                let rv = unsafe {
                    provider::encrypt(1, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut length)
                };
                done_tx.send((rv, length)).unwrap();
            });
            wait_for_holders(1);
            assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
            assert_eq!(unsafe { RetainedOracle_ReleaseGate() }, 0);
            let (rv, length) = done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            assert_eq!(rv, CKR_OK);
            assert_eq!(length, 0);
        });
        let observation = observation();
        assert_eq!(observation.encrypt_calls, 1);
        assert_eq!(observation.gate_holds_current, 0);
        assert_eq!(observation.gate_holds_total, 1);
        assert_eq!(unsafe { RetainedOracle_ReleaseGate() }, 0);
    }

    #[test]
    fn fail_unless_ptr_equal_rejects_mismatched_root() {
        // Row-12 E2E vehicle: with the gate armed, an Encrypt whose
        // retained root does not reproduce the Init root must fail
        // closed instead of returning the scenario RV.
        let _guard = acquire_test_serial();
        reset_full();
        assert_eq!(
            unsafe {
                RetainedOracle_SetScenario(&RetainedOracleScenario {
                    encrypt_rv: 0,
                    output_len: 16,
                    fail_unless_ptr_equal: 1,
                })
            },
            0
        );
        // No Init performed: the retained root is null, so the identity
        // check fails and the call fails closed.
        let mut length: CK_ULONG = 0;
        let rv = unsafe {
            provider::encrypt(1, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut length)
        };
        assert_eq!(rv, CKR_DEVICE_ERROR);
        reset_full();
    }

    #[test]
    fn fail_unless_ptr_equal_passes_matched_root() {
        // Positive control: Init followed by Encrypt through the live
        // root satisfies the gate and returns the scenario RV.
        let _guard = acquire_test_serial();
        reset_full();
        assert_eq!(
            unsafe {
                RetainedOracle_SetScenario(&RetainedOracleScenario {
                    encrypt_rv: 0,
                    output_len: 16,
                    fail_unless_ptr_equal: 1,
                })
            },
            0
        );
        let mechanism = CK_MECHANISM {
            mechanism: CKM_AES_CBC as CK_MECHANISM_TYPE,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        assert_eq!(
            unsafe { provider::encrypt_init(1, &mechanism as *const _ as CK_MECHANISM_PTR, 0) },
            CKR_OK
        );
        let mut length: CK_ULONG = 0;
        let rv = unsafe {
            provider::encrypt(1, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut length)
        };
        assert_eq!(rv, CKR_OK);
        assert_eq!(length, 16);
        reset_full();
    }

    #[test]
    fn initialize_applies_env_scenario_overrides() {
        // Row-12 E2E vehicle: the cdylib merges test-only
        // RETAINED_ORACLE_* env overrides at C_Initialize so an
        // out-of-process runner can steer the scenario without a
        // same-process SetScenario call. Absent or invalid values keep
        // the current scenario.
        let _guard = acquire_test_serial();
        reset_full();
        unsafe {
            std::env::set_var("RETAINED_ORACLE_OUTPUT_LEN", "16");
            std::env::set_var("RETAINED_ORACLE_ENCRYPT_RV", "0");
            std::env::set_var("RETAINED_ORACLE_FAIL_UNLESS_PTR_EQUAL", "yes");
        }
        assert_eq!(unsafe { provider::initialize(std::ptr::null_mut()) }, CKR_OK);
        assert_eq!(lock_state().0.output_len, 16);
        assert_eq!(lock_state().0.encrypt_rv, 0);
        // "yes" is not a u64: invalid values are ignored.
        assert_eq!(lock_state().0.fail_unless_ptr_equal, 0);
        unsafe {
            std::env::remove_var("RETAINED_ORACLE_OUTPUT_LEN");
            std::env::remove_var("RETAINED_ORACLE_ENCRYPT_RV");
            std::env::remove_var("RETAINED_ORACLE_FAIL_UNLESS_PTR_EQUAL");
        }
        reset_full();
    }

    #[test]
    fn reset_during_hold_opens_gate_without_stranding() {
        let _guard = acquire_test_serial();
        reset_full();
        assert_eq!(unsafe { RetainedOracle_ArmGate(RETAINED_OP_ENCRYPT) }, 0);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let mut length: CK_ULONG = 0;
                let rv = unsafe {
                    provider::encrypt(1, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut length)
                };
                done_tx.send((rv, length)).unwrap();
            });
            wait_for_holders(1);
            // No explicit release: the reset broadcast must open the gate.
            assert_eq!(RetainedOracle_ResetObservation(), 0);
            let (rv, _) = done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            assert_eq!(rv, CKR_OK);
        });
        assert_eq!(observation().gate_holds_current, 0);
        assert_eq!(unsafe { RetainedOracle_ReleaseGate() }, 0);
    }
}
