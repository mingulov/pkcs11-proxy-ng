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
        RetainedOracleScenario { encrypt_rv: 0, output_len: 0 },
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
