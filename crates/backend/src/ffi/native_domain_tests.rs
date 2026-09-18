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
fn native_domain_lifecycle_init_attempt_without_success_poisons() {
    // C3M steps 4-5: a recorded Initialize attempt without a later
    // success means native code may have run — never recycle. Only a
    // successful Finalize re-earns release.
    let tracker = LifecycleTracker::default();
    tracker.note_init_attempted();
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Poison);
    tracker.note_initialized().expect("in-contract cycle records");
    assert_eq!(
        tracker.retirement_decision(),
        RetirementDecision::Poison,
        "initialized without finalize still poisons"
    );
    tracker.note_finalized();
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Release);
}

#[test]
fn native_domain_lifecycle_initialized_without_finalize_poisons() {
    let tracker = LifecycleTracker::default();
    tracker.note_initialized().expect("in-contract cycle records");
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Poison);
}

#[test]
fn native_domain_lifecycle_finalize_restores_release() {
    let tracker = LifecycleTracker::default();
    tracker.note_initialized().expect("in-contract cycle records");
    tracker.note_session_opened();
    tracker.note_session_opened();
    tracker.note_finalized();
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Release);
}

#[test]
fn native_domain_lifecycle_open_sessions_block_release_until_closed() {
    let tracker = LifecycleTracker::default();
    tracker.note_initialized().expect("in-contract cycle records");
    tracker.note_finalized();
    tracker.note_session_opened();
    assert_eq!(
        tracker.retirement_decision(),
        RetirementDecision::Poison,
        "a live open session blocks release even after finalize"
    );
    tracker.note_sessions_closed(1);
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Release);
    tracker.note_initialized().expect("in-contract cycle records");
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
    tracker.note_initialized().expect("in-contract cycle records");
    assert_eq!(tracker.current_generation(), 1);
    tracker.note_initialized().expect("in-contract cycle records");
    assert_eq!(tracker.current_generation(), 1);
    tracker.note_finalized();
    tracker.note_initialized().expect("in-contract cycle records");
    assert_eq!(tracker.current_generation(), 2);
}

#[test]
fn native_domain_lifecycle_generation_exhaustion_refuses_without_wrapping() {
    // F-08/MISS 1: the lifecycle generation is checked — at `u64::MAX` no
    // new cycle opens, and the counter never wraps back to the pre-initial
    // identity 0. Precedent: `native_domain_exhaustion_rejects_without_wrapping`.
    // Exhaustion blocks only NEW cycles: re-affirming the live `u64::MAX`
    // incarnation needs no fresh identity, so it still records.
    let tracker = LifecycleTracker::default();
    tracker.set_generation_for_tests(u64::MAX - 1);
    tracker.note_initialized().expect("MAX-1 advances to MAX");
    assert_eq!(tracker.current_generation(), u64::MAX);
    tracker.check_reinitialize().expect("live MAX incarnation re-affirms");
    tracker.note_initialized().expect("re-affirm needs no fresh identity");
    assert_eq!(tracker.current_generation(), u64::MAX);
    tracker.note_finalized();
    assert_eq!(tracker.check_reinitialize().unwrap_err(), LifecycleRefusal::GenerationExhausted);
    assert_eq!(tracker.note_initialized().unwrap_err(), LifecycleRefusal::GenerationExhausted);
    assert_eq!(tracker.current_generation(), u64::MAX, "exhausted counter never wraps");
    assert_eq!(
        tracker.retirement_decision(),
        RetirementDecision::Release,
        "refused cycle consumes no finalized evidence"
    );
}

#[test]
fn native_domain_lifecycle_reinitialize_after_failed_finalize_is_refused() {
    // F-08/MISS 2 at the tracker: a failed Finalize can never satisfy a new
    // cycle — the gate and the recorder both refuse, and the retained
    // evidence (generation, open count) is untouched. Recovery stays
    // possible: a later successful Finalize satisfies re-init again.
    let tracker = LifecycleTracker::default();
    tracker.note_initialized().expect("first cycle opens");
    tracker.note_session_opened();
    tracker.note_finalize_failed();
    assert_eq!(
        tracker.check_reinitialize().unwrap_err(),
        LifecycleRefusal::FailedFinalizeUnresolved
    );
    assert_eq!(tracker.note_initialized().unwrap_err(), LifecycleRefusal::FailedFinalizeUnresolved);
    assert_eq!(tracker.current_generation(), 1);
    assert_eq!(tracker.open_session_count_for_tests(), 1);
    tracker.note_finalized();
    tracker.check_reinitialize().expect("successful finalize re-satisfies re-init");
    tracker.note_initialized().expect("new cycle opens after successful finalize");
    assert_eq!(tracker.current_generation(), 2);
    assert_eq!(tracker.open_session_count_for_tests(), 0);
}

#[test]
fn native_domain_lifecycle_close_surprise_never_hides_sessions() {
    let tracker = LifecycleTracker::default();
    tracker.note_initialized().expect("in-contract cycle records");
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
    tracker.note_initialized().expect("in-contract cycle records");
    tracker.note_finalized();
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Release);
    tracker.note_initialized().expect("in-contract cycle records");
    assert_eq!(tracker.retirement_decision(), RetirementDecision::Poison);
}

#[test]
fn native_domain_begin_retirement_occupies_until_vacant() {
    // C3M step 7: the Release path publishes `Retiring` (still occupied)
    // for the dependent-retirement window; only the completed unload
    // publishes the next `Vacant`.
    let mut registry = fresh();
    let first = registry.reserve().expect("first reservation succeeds");
    registry.activate(first.epoch).expect("owner activates");
    assert!(registry.begin_retirement(first.epoch), "owner enters Retiring");
    match registry.reserve() {
        Err(DomainError::AlreadyReserved { epoch }) => {
            assert_eq!(epoch, first.epoch, "Retiring denies for the live epoch");
        }
        Err(other) => panic!("Retiring must deny with AlreadyReserved, got {other:?}"),
        Ok(_) => panic!("Retiring must stay occupied until Vacant"),
    }
    assert!(registry.release_if_owner(first.epoch), "completed unload publishes Vacant");
    let second = registry.reserve().expect("slot is reusable after Vacant");
    assert_eq!(second.epoch, 1, "epochs advance monotonically");
}

#[test]
fn native_domain_stale_begin_retirement_changes_nothing() {
    let mut registry = fresh();
    assert!(!registry.begin_retirement(0), "Vacant has no epoch to retire");
    let first = registry.reserve().expect("first reservation succeeds");
    assert!(!registry.begin_retirement(first.epoch), "Reserved is not Active");
    registry.activate(first.epoch).expect("owner activates");
    let stale = first.epoch.wrapping_add(1);
    assert!(!registry.begin_retirement(stale), "stale epoch changes nothing");
    assert!(
        matches!(registry.reserve(), Err(DomainError::AlreadyReserved { .. })),
        "stale begin_retirement must not free the live epoch"
    );
    registry.poison(first.epoch);
    assert!(!registry.begin_retirement(first.epoch), "Poisoned never re-enters Retiring");
    assert!(
        matches!(registry.reserve(), Err(DomainError::Poisoned)),
        "poisoned registry denies new chains"
    );
}

#[test]
fn native_domain_unmanaged_sentinel_drop_touches_nothing() {
    // The unmanaged sentinel pairs with unmanaged test backends: its
    // epoch matches no live reservation, so dropping it never mutates
    // the registry (a stale release is a pure no-op).
    let _serial = serial_domain_test_guard();
    drop(RetirementSentinel::unmanaged_test_only());
    reserve_for_construction().expect("slot untouched").rollback_before_native();
}

#[test]
fn native_domain_global_serial_release_drop_recycles_after_full_retirement() {
    // C3M step 7 end-state pin: dropping a never-initialized managed
    // backend (Release path) leaves the slot Vacant and reusable once
    // every field — dependent graphs, `dlclose`, permit, lifecycle,
    // sentinel — has retired.
    let _serial = serial_domain_test_guard();
    let permit = reserve_for_construction().expect("first reservation succeeds");
    permit.activate().expect("owner activates");
    let first_epoch = permit.epoch;
    {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        let backend = FfiBackend {
            _lib: super::loading::test_library_handle(),
            func_list: functions.as_mut() as *mut cryptoki_sys::CK_FUNCTION_LIST,
            func_list_3_0: None,
            func_list_3_2: None,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            retirement_sentinel: RetirementSentinel::for_permit(&permit),
            construction: permit,
            lifecycle: Default::default(),
        };
        drop(backend);
    }
    let second = reserve_for_construction().expect("slot is reusable after full retirement");
    assert_eq!(second.epoch, first_epoch + 1, "epochs advance monotonically");
    second.rollback_before_native();
}

#[test]
fn native_domain_unsupported_platform_display_names_macos_hosts() {
    // M-3: macOS aarch64/x86_64 joined the v0.2 native-FFI qualification
    // boundary; the refusal message must name it alongside the Linux and
    // Windows arms.
    let msg = DomainError::UnsupportedPlatform { detail: "test-detail" }.to_string();
    assert!(
        msg.contains("macOS on aarch64 or x86_64"),
        "Display must name macOS hosts, got: {msg}"
    );
    assert!(msg.contains("test-detail"), "Display must carry the detail, got: {msg}");
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
