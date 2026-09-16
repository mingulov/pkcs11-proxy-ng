//! Row-19 constructor-domain gates (C3M.6 order item 19, in-process subset).
//!
//! One live project-managed provider chain per embedding process: a second
//! reservation while one is held must fail locally with zero loader or
//! provider attempts, and a failed `dlopen` must roll back so later loads
//! can still proceed. State-transition coverage runs against local
//! registries so parallel test threads cannot observe each other; exactly
//! one test touches the process-global registry, serialized by
//! [`serial_domain_test_guard`]. Subprocess contention/epoch/isolation proofs
//! arrive with the topology runner.

use super::FfiBackend;
use super::native_domain::*;

fn fresh() -> DomainRegistry {
    DomainRegistry::fresh_for_tests()
}

#[test]
fn native_domain_second_reservation_fails_without_loader_attempt() {
    let mut registry = fresh();
    let first = registry.reserve().expect("first reservation succeeds");
    match registry.reserve() {
        Err(DomainError::AlreadyReserved { .. }) => {}
        Err(other) => panic!("second reservation must report AlreadyReserved, got {other:?}"),
        Ok(_) => panic!("second reservation must fail while the first is held"),
    }
    registry.rollback(first.epoch);
    registry.reserve().expect("rollback frees the reservation");
}

#[test]
fn native_domain_full_lifecycle_advances_epochs() {
    let mut registry = fresh();
    let first = registry.reserve().expect("first reservation succeeds");
    assert_eq!(first.epoch, 0, "epochs start at zero");
    registry.activate(first.epoch).expect("owner activates");
    assert!(registry.release_if_owner(first.epoch), "owner retires its slot");
    let second = registry.reserve().expect("slot is reusable after release");
    assert_eq!(second.epoch, 1, "epochs advance monotonically");
}

#[test]
fn native_domain_stale_handles_change_nothing() {
    let mut registry = fresh();
    let first = registry.reserve().expect("first reservation succeeds");
    let stale_epoch = first.epoch.wrapping_add(1);
    assert!(!registry.release_if_owner(stale_epoch), "stale release takes nothing");
    assert!(registry.activate(stale_epoch).is_err(), "stale handle cannot activate");
    registry.rollback(stale_epoch);
    assert!(
        matches!(registry.reserve(), Err(DomainError::AlreadyReserved { .. })),
        "stale rollback must not free the live epoch"
    );
    registry.poison(stale_epoch);
    assert!(
        matches!(registry.reserve(), Err(DomainError::AlreadyReserved { .. })),
        "stale poison must not deny the live epoch"
    );
}

#[test]
fn native_domain_poison_denies_until_restart() {
    let mut registry = fresh();
    let first = registry.reserve().expect("first reservation succeeds");
    registry.poison(first.epoch);
    assert!(
        matches!(registry.reserve(), Err(DomainError::Poisoned)),
        "poisoned registry denies new chains"
    );
}

#[test]
fn native_domain_exhaustion_rejects_without_wrapping() {
    let mut registry = DomainRegistry::at_epoch_for_tests(u64::MAX);
    assert!(
        matches!(registry.reserve(), Err(DomainError::EpochExhausted)),
        "exhausted epochs reject instead of wrapping"
    );
}

#[test]
fn native_domain_global_serial_second_load_rejected_and_rollback() {
    if cfg!(miri) {
        eprintln!("skipping: real dlopen is unsupported under Miri; covered natively");
        return;
    }
    let _serial = serial_domain_test_guard();
    let first = reserve_for_construction().expect("first reservation succeeds");
    let missing = std::path::Path::new("/nonexistent-pkcs11-proxy-ng-test-module.so");
    let err = FfiBackend::load(missing).map(|_| ()).expect_err("held reservation rejects load");
    assert!(
        err.contains("already reserved"),
        "held reservation must reject before any loader attempt, got: {err}"
    );
    first.rollback_before_native();
    let retry_err =
        FfiBackend::load(missing).map(|_| ()).expect_err("retry after rollback still fails");
    assert!(
        retry_err.contains("native module load failed"),
        "rolled-back registry must attempt loading again, got: {retry_err}"
    );
}

#[test]
fn native_domain_holds_registry_slot_scopes_guard_to_managed() {
    let mut registry = fresh();
    let managed = registry.reserve().expect("vacant registry reserves");
    assert!(managed.holds_registry_slot(), "registry-issued permits must hold the slot");
    assert!(
        !ConstructionPermit::unmanaged_test_only().holds_registry_slot(),
        "unmanaged test permits must not hold the slot"
    );
}

#[test]
fn native_domain_lifecycle_fresh_backend_releases() {
    let tracker = LifecycleTracker::default();
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Release);
}

#[test]
fn native_domain_lifecycle_initialized_without_finalize_poisons() {
    let tracker = LifecycleTracker::default();
    tracker.note_initialized();
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Poison);
}

#[test]
fn native_domain_lifecycle_finalize_restores_release() {
    let tracker = LifecycleTracker::default();
    tracker.note_initialized();
    tracker.note_session_opened();
    tracker.note_session_opened();
    tracker.note_finalized();
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Release);
}

#[test]
fn native_domain_lifecycle_open_sessions_block_release_until_closed() {
    let tracker = LifecycleTracker::default();
    tracker.note_initialized();
    tracker.note_finalized();
    tracker.note_session_opened();
    assert_eq!(
        tracker.retirement_decision(),
        RetirementDecision::Poison,
        "a live open session blocks release even after finalize"
    );
    tracker.note_sessions_closed(1);
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Release);
    tracker.note_initialized();
    tracker.note_session_opened();
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Poison);
    tracker.note_sessions_closed(1);
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Poison);
    tracker.note_finalized();
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Release);
}

#[test]
fn native_domain_lifecycle_generation_advances_per_initialization_cycle() {
    // C3M.4/row 10: each initialization cycle gets a fresh generation so
    // stale work cannot publish into a reinitialized domain. Re-affirming
    // an already-open incarnation is not a new cycle.
    let tracker = LifecycleTracker::default();
    assert_eq!(tracker.current_generation(), 0);
    tracker.note_initialized();
    assert_eq!(tracker.current_generation(), 1);
    tracker.note_initialized();
    assert_eq!(tracker.current_generation(), 1);
    tracker.note_finalized();
    tracker.note_initialized();
    assert_eq!(tracker.current_generation(), 2);
}

#[test]
fn native_domain_lifecycle_close_surprise_never_hides_sessions() {
    let tracker = LifecycleTracker::default();
    tracker.note_initialized();
    tracker.note_session_opened();
    tracker.note_sessions_closed(5);
    assert_eq!(
        tracker.retirement_decision(),
        RetirementDecision::Poison,
        "underflow surprise keeps the count high"
    );
    tracker.note_sessions_closed(1);
    tracker.note_finalized();
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Release);
}

#[test]
fn native_domain_lifecycle_reinitialize_clears_finalized() {
    let tracker = LifecycleTracker::default();
    tracker.note_initialized();
    tracker.note_finalized();
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Release);
    tracker.note_initialized();
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Poison);
}

#[test]
fn native_domain_current_host_reports_qualified_or_refuses() {
    let reported = check_native_platform();
    assert_eq!(
        reported.is_ok(),
        NATIVE_FFI_QUALIFIED,
        "platform gate and build-time qualifier must agree"
    );
    if !reported.is_ok() {
        assert!(
            matches!(reported, Err(DomainError::UnsupportedPlatform { .. })),
            "platform gate must only pass or refuse by platform, got {reported:?}"
        );
    }
}
