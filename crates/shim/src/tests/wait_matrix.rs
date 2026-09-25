//! Loaded-shim slot-event matrix (TO26b group 2).
//!
//! Drives the real `C_WaitForSlotEvent` entry against the in-process
//! [`TestDaemon`] (real gRPC, mock backend): pointer rules, canary
//! preservation on every error path, mapped-slot delivery, backend-error
//! passthrough, and caller-width checks. The width-failure branches run
//! natively under `--target i686` (narrow `CK_RV`/`CK_SLOT_ID`); the pure
//! narrowing helper is exhaustively unit-tested host-side in
//! `pkcs11_proxy_ng_types::width`.

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::{CkRv, CkSlotId};

use super::output_semantics::{ShimSession, TestDaemon};
use super::*;

const CANARY_SLOT: CK_SLOT_ID = CK_SLOT_ID::MAX - 7;

fn wait_flags() -> CK_FLAGS {
    CKF_DONT_BLOCK
}

/// The shared mock starts uninitialized and only the wait path reads the
/// flag; initialize once for queue-driven waits (later calls report
/// already-initialized and change nothing). Guard-serialized like every
/// other shared-daemon user, so the one-time queue/state clear cannot
/// interleave with another test.
fn ensure_mock_initialized(daemon: &TestDaemon) {
    let _ = daemon.backend.initialize();
}

#[test]
fn wait_null_slot_before_initialize_returns_bad_args() {
    // Doc row 1: pSlot == NULL refuses ARGUMENTS_BAD even before shim
    // initialization (the pointer check precedes the init gate).
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe {
        dispatch::general::c_wait_for_slot_event(0, std::ptr::null_mut(), std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn wait_uninitialized_shim_refuses_without_rpc() {
    // Doc row 2: valid pointers but uninitialized shim → NOT_INITIALIZED,
    // no RPC, canary intact.
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let daemon = TestDaemon::shared();
    let waits_before = daemon.backend.wait_call_count();
    let mut slot = CANARY_SLOT;
    let rv = unsafe {
        dispatch::general::c_wait_for_slot_event(wait_flags(), &mut slot, std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
    assert_eq!(slot, CANARY_SLOT, "refusal must not touch the output cell");
    assert_eq!(
        daemon.backend.wait_call_count(),
        waits_before,
        "uninitialized shim must issue no RPC"
    );
}

#[test]
fn wait_no_event_leaves_canary_intact() {
    // Empty queue → NO_EVENT; the output-only caller buffer keeps its
    // canary (never read, never written on error).
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    ensure_mock_initialized(daemon);
    let _session = ShimSession::with_endpoint(&daemon.endpoint);
    let mut slot = CANARY_SLOT;
    let rv = unsafe {
        dispatch::general::c_wait_for_slot_event(wait_flags(), &mut slot, std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_NO_EVENT as CK_RV);
    assert_eq!(slot, CANARY_SLOT, "NO_EVENT must not write the caller slot");
}

#[test]
fn wait_event_delivers_mapped_virtual_slot() {
    // An event for backend slot 0 publishes OK with its mapped virtual
    // slot (TestDaemon registers mock slots [0, 1] in order from virtual
    // id 1, so backend 0 → virtual 1).
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    ensure_mock_initialized(daemon);
    let _session = ShimSession::with_endpoint(&daemon.endpoint);
    daemon.backend.enqueue_slot_event(CkSlotId(0));
    let mut slot = CANARY_SLOT;
    let rv = unsafe {
        dispatch::general::c_wait_for_slot_event(wait_flags(), &mut slot, std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_OK as CK_RV);
    assert_eq!(slot, 1, "authorized event must deliver its mapped virtual slot");
}

#[test]
fn wait_backend_errors_preserve_canary() {
    // Backend wait errors (contention refusal, sentinel RV) pass through
    // verbatim with the caller cell untouched.
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    ensure_mock_initialized(daemon);
    let _session = ShimSession::with_endpoint(&daemon.endpoint);
    for scripted in [CkRv::FUNCTION_FAILED, CkRv(0xDEAD_BEEF)] {
        daemon.backend.set_next_wait_outcome(Err(scripted));
        let mut slot = CANARY_SLOT;
        let rv = unsafe {
            dispatch::general::c_wait_for_slot_event(wait_flags(), &mut slot, std::ptr::null_mut())
        };
        assert_eq!(rv, scripted.0 as CK_RV, "backend error must pass through verbatim");
        assert_eq!(slot, CANARY_SLOT, "backend error must not write the caller slot");
    }
}

#[test]
fn wait_wide_response_rv_checked_against_caller_width() {
    // Doc rule: a response RV the caller CK_RV cannot represent answers
    // local FUNCTION_FAILED (never a truncation — 2^32 would truncate to
    // CKR_OK) with the cell untouched. On wide callers the value fits and
    // passes through.
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    ensure_mock_initialized(daemon);
    let _session = ShimSession::with_endpoint(&daemon.endpoint);
    daemon.backend.set_next_wait_outcome(Err(CkRv(1u64 << 32)));
    let mut slot = CANARY_SLOT;
    let rv = unsafe {
        dispatch::general::c_wait_for_slot_event(wait_flags(), &mut slot, std::ptr::null_mut())
    };
    #[cfg(target_pointer_width = "64")]
    assert_eq!(rv, (1u64 << 32) as CK_RV, "representable RV passes through");
    #[cfg(target_pointer_width = "32")]
    assert_eq!(rv, CKR_FUNCTION_FAILED as CK_RV, "wide RV must refuse on narrow callers");
    assert_eq!(slot, CANARY_SLOT, "RV path must not write the caller slot");
}

#[test]
fn wait_unmapped_wide_backend_slot_suppresses_to_no_event() {
    // A wide backend slot id has no virtual mapping, so the service
    // answers NO_EVENT (a protobuf error's zero slot is not a write
    // instruction): canary intact on every width. The shim's own slot
    // narrowing is defense-in-depth behind the mapping (helper-tested);
    // virtual ids are small ordinals by construction.
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared();
    ensure_mock_initialized(daemon);
    let _session = ShimSession::with_endpoint(&daemon.endpoint);
    daemon.backend.set_next_wait_outcome(Ok(CkSlotId(1u64 << 40)));
    let mut slot = CANARY_SLOT;
    let rv = unsafe {
        dispatch::general::c_wait_for_slot_event(wait_flags(), &mut slot, std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_NO_EVENT as CK_RV);
    assert_eq!(slot, CANARY_SLOT, "suppressed event must not write the caller slot");
}
