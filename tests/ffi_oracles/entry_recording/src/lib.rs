//! Native entry-recording provider oracle (Q07 / MAINT-02).
//!
//! A minimal PKCS#11 provider whose only job is to record, independently of
//! any return value, whether native C entry was reached: every `C_EncryptInit`
//! call increments [`EntryRecordingObservation::encrypt_init_calls`] and
//! snapshots the mechanism type and parameter length, then returns the
//! scenario RV verbatim — including error RVs such as
//! `CKR_MECHANISM_PARAM_INVALID` that are bit-identical to server-local and
//! backend-local rejects. The entry count is what distinguishes "the provider
//! said no" from "we never got there"; no RV alone can.
//!
//! Dual fixture: this module compiles in-process into the shape-evidence
//! integration tests (for the `#[repr(C)]` scenario/observation types, via
//! `#[path]`) and as an unpublished cdylib driven through `dlopen` by those
//! same tests. The dlopen'd copy owns the observed state; the in-process
//! copy's state is never read. There are deliberately no `#[test]` items in
//! this file: they would also compile into every including test binary.
//! Oracle correctness is proven by the `shape_evidence_test.rs` controls.
//!
//! The oracle implements just enough provider surface for the controls:
//! initialize/finalize, one synthetic slot with a canned token, sessions,
//! canned object creation, and `C_EncryptInit`. It performs no cryptography.
#![allow(non_snake_case, clippy::missing_safety_doc, clippy::unnecessary_cast)]
use cryptoki_sys::*;
use std::sync::Mutex;

#[cfg(not(test))]
mod provider;
#[cfg(test)]
pub mod provider;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct EntryRecordingScenario {
    /// Raw CK_RV returned verbatim by C_EncryptInit.
    pub init_rv: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EntryRecordingObservation {
    /// Native C_EncryptInit entries since the last reset.
    pub encrypt_init_calls: u64,
    /// Mechanism type of the most recent entry (0 when none).
    pub init_mech_type: u64,
    /// ulParameterLen of the most recent entry.
    pub init_param_len: u64,
}

struct ProviderState {
    initialized: bool,
    next_session: u64,
    next_object: u64,
}

static STATE: Mutex<(EntryRecordingScenario, EntryRecordingObservation, ProviderState)> =
    Mutex::new((
        EntryRecordingScenario { init_rv: 0 },
        EntryRecordingObservation { encrypt_init_calls: 0, init_mech_type: 0, init_param_len: 0 },
        ProviderState { initialized: false, next_session: 1, next_object: 41 },
    ));

fn lock_state() -> std::sync::MutexGuard<
    'static,
    (EntryRecordingScenario, EntryRecordingObservation, ProviderState),
> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn EntryRecording_SetScenario(
    scenario: *const EntryRecordingScenario,
) -> u32 {
    if scenario.is_null() {
        return 1;
    }
    lock_state().0 = unsafe { *scenario };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn EntryRecording_ResetObservation() -> u32 {
    lock_state().1 = EntryRecordingObservation::default();
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn EntryRecording_GetObservation(
    observation: *mut EntryRecordingObservation,
) -> u32 {
    if observation.is_null() {
        return 1;
    }
    unsafe { observation.write(lock_state().1) };
    0
}
