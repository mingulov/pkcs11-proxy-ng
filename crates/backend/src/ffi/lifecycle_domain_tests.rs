//! LifecycleDomain state-machine tests (TF01a slice 1).
//!
//! Covers the F-01 admission core per the FIX-D §5 sketch: the 7-state
//! module machine, ordinary admission under the read acquisition that
//! seals it, initialize-side control transitions with epoch-checked
//! settlement, fail-closed poison policy, and the blocked-control
//! exclusion shape (parked ordinary ⇒ control waits ⇒ release ⇒
//! proceeds). Finalize seal/drain, session fences and the remaining
//! choke families land in TF01b; tests that need those states use the
//! test-only state injection below the production API.

use super::native_domain::*;
use pkcs11_proxy_ng_types::CkRv;
use std::time::Duration;

fn open_domain() -> LifecycleDomain {
    let domain = LifecycleDomain::new();
    let init = domain.begin_initialize().expect("begin on fresh domain");
    domain.publish_open(init).expect("publish on fresh domain");
    domain
}

#[test]
fn fresh_domain_denies_ordinary_before_open() {
    let domain = LifecycleDomain::new();
    assert_eq!(domain.state_for_tests(), ModuleState::LoadedUninitialized);
    assert_eq!(
        domain.admit_ordinary().unwrap_err(),
        CkRv::CRYPTOKI_NOT_INITIALIZED,
        "ordinary work before Initialize must be denied, never admitted"
    );
}

#[test]
fn begin_publish_cycle_opens_and_admits_with_stamped_epoch() {
    let domain = LifecycleDomain::new();
    let init = domain.begin_initialize().expect("begin succeeds");
    assert_eq!(domain.state_for_tests(), ModuleState::Initializing);
    // Admission is denied while a control transition is mid-flight.
    assert_eq!(domain.admit_ordinary().unwrap_err(), CkRv::CRYPTOKI_NOT_INITIALIZED);
    domain.publish_open(init).expect("publish succeeds");
    assert_eq!(domain.state_for_tests(), ModuleState::Open);
    let guard = domain.admit_ordinary().expect("open domain admits");
    assert_eq!(guard.epoch_for_tests(), 2, "begin + publish each advance the epoch");
}

#[test]
fn admit_denied_in_every_non_open_state() {
    let domain = LifecycleDomain::new();
    for state in [
        ModuleState::LoadedUninitialized,
        ModuleState::Initializing,
        ModuleState::Open,
        ModuleState::Draining,
        ModuleState::Finalizing,
        ModuleState::Finalized,
        ModuleState::Uncertain,
    ] {
        domain.set_state_for_tests(state, 7);
        match domain.admit_ordinary() {
            Ok(_) => assert_eq!(state, ModuleState::Open, "only Open admits, got {state:?}"),
            Err(rv) => {
                assert_ne!(state, ModuleState::Open, "Open must admit");
                let expected = match state {
                    ModuleState::Uncertain => CkRv::GENERAL_ERROR,
                    _ => CkRv::CRYPTOKI_NOT_INITIALIZED,
                };
                assert_eq!(rv, expected, "denial RV for {state:?}");
            }
        }
    }
}

#[test]
fn begin_denied_while_sealed_for_finalize() {
    let domain = LifecycleDomain::new();
    for state in [ModuleState::Draining, ModuleState::Finalizing] {
        domain.set_state_for_tests(state, 7);
        assert_eq!(
            domain.begin_initialize().unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED,
            "no new Initialize cycle may start from {state:?}"
        );
        assert_eq!(domain.state_for_tests(), state, "denied begin changes nothing");
    }
}

#[test]
fn abandon_restores_prior_stable_state() {
    let domain = open_domain();
    let epoch_before = 2;
    let init = domain.begin_initialize().expect("begin from Open");
    assert_eq!(domain.state_for_tests(), ModuleState::Initializing);
    domain.abandon_initialize(init);
    assert_eq!(domain.state_for_tests(), ModuleState::Open);
    assert!(
        domain.epoch_for_tests() > epoch_before,
        "control transitions always advance the epoch"
    );
    domain.admit_ordinary().expect("restored Open admits again");
}

#[test]
fn ticket_drop_abandons_unsettled_begin() {
    let domain = LifecycleDomain::new();
    {
        let _init = domain.begin_initialize().expect("begin succeeds");
        // Dropped without publish: the backstop must restore, never wedge.
    }
    assert_eq!(domain.state_for_tests(), ModuleState::LoadedUninitialized);
    // The domain still works afterwards.
    let init = domain.begin_initialize().expect("begin after drop-abandon");
    domain.publish_open(init).expect("publish after drop-abandon");
    domain.admit_ordinary().expect("admits after drop-abandon cycle");
}

#[test]
fn stale_abandon_after_publish_is_noop_epoch_mismatch() {
    // Two concurrent control attempts: A publishes while B is mid-flight.
    // B's ticket is stale (epoch mismatch); abandoning it must NOT clobber
    // A's published Open — the later control op owns the outcome.
    let domain = LifecycleDomain::new();
    let first = domain.begin_initialize().expect("first begin");
    let second = domain.begin_initialize().expect("second begin");
    domain.publish_open(first).expect("first publish wins");
    assert_eq!(domain.state_for_tests(), ModuleState::Open);
    let epoch_after_publish = domain.epoch_for_tests();
    domain.abandon_initialize(second);
    assert_eq!(domain.state_for_tests(), ModuleState::Open, "stale abandon is a no-op");
    assert_eq!(
        domain.epoch_for_tests(),
        epoch_after_publish,
        "stale abandon does not consume an epoch"
    );
    domain.admit_ordinary().expect("published Open still admits");
}

#[test]
fn abandon_transient_prior_goes_uncertain_fail_closed() {
    // B began from A's mid-flight Initializing: B's prior is transient, so
    // a matching abandon cannot restore it — Uncertain, fail-closed.
    let domain = LifecycleDomain::new();
    let first = domain.begin_initialize().expect("first begin");
    let second = domain.begin_initialize().expect("second begin");
    domain.abandon_initialize(second);
    assert_eq!(domain.state_for_tests(), ModuleState::Uncertain);
    assert_eq!(domain.admit_ordinary().unwrap_err(), CkRv::GENERAL_ERROR);
    // The first ticket is now stale too: no-op, stays Uncertain.
    domain.abandon_initialize(first);
    assert_eq!(domain.state_for_tests(), ModuleState::Uncertain);
}

#[test]
fn publish_last_writer_wins() {
    let domain = LifecycleDomain::new();
    let first = domain.begin_initialize().expect("first begin");
    let second = domain.begin_initialize().expect("second begin");
    domain.publish_open(first).expect("first publish");
    let epoch_after_first = domain.epoch_for_tests();
    domain.publish_open(second).expect("second publish also succeeds");
    assert_eq!(domain.state_for_tests(), ModuleState::Open);
    assert!(domain.epoch_for_tests() > epoch_after_first, "each publish consumes an epoch");
}

#[test]
fn admission_epoch_advances_across_control_cycles() {
    let domain = open_domain();
    let first = domain.admit_ordinary().expect("admits at epoch 2");
    assert_eq!(first.epoch_for_tests(), 2);
    drop(first);
    let init = domain.begin_initialize().expect("re-begin");
    domain.publish_open(init).expect("re-publish");
    let second = domain.admit_ordinary().expect("admits after re-cycle");
    assert_eq!(second.epoch_for_tests(), 4);
    assert_ne!(
        second.epoch_for_tests(),
        2,
        "a stale guard epoch never equals the current one after a control cycle"
    );
}

#[test]
fn begin_denied_at_epoch_exhaustion() {
    let domain = LifecycleDomain::new();
    domain.set_state_for_tests(ModuleState::Open, u64::MAX);
    assert_eq!(domain.begin_initialize().unwrap_err(), CkRv::GENERAL_ERROR);
    assert_eq!(domain.state_for_tests(), ModuleState::Open, "denied begin changes nothing");
    assert_eq!(domain.epoch_for_tests(), u64::MAX, "denied begin consumes no epoch");
}

#[test]
fn publish_at_exhaustion_fails_closed_to_uncertain() {
    let domain = LifecycleDomain::new();
    domain.set_state_for_tests(ModuleState::LoadedUninitialized, u64::MAX - 1);
    let init = domain.begin_initialize().expect("begin consumes the last epoch");
    assert_eq!(domain.epoch_for_tests(), u64::MAX);
    assert_eq!(domain.publish_open(init).unwrap_err(), CkRv::GENERAL_ERROR);
    assert_eq!(domain.state_for_tests(), ModuleState::Uncertain);
    assert_eq!(domain.admit_ordinary().unwrap_err(), CkRv::GENERAL_ERROR);
}

#[test]
fn abandon_at_exhaustion_restores_without_bump() {
    let domain = LifecycleDomain::new();
    domain.set_state_for_tests(ModuleState::Open, u64::MAX - 1);
    let init = domain.begin_initialize().expect("begin consumes the last epoch");
    domain.abandon_initialize(init);
    assert_eq!(domain.state_for_tests(), ModuleState::Open, "matching abandon restores");
    assert_eq!(domain.epoch_for_tests(), u64::MAX, "no epoch left to consume");
    domain.admit_ordinary().expect("restored Open admits");
    assert_eq!(
        domain.begin_initialize().unwrap_err(),
        CkRv::GENERAL_ERROR,
        "no further control cycles once exhausted"
    );
}

#[test]
fn poisoned_domain_denies_admit_and_begin_fail_closed() {
    // Only a writer panic poisons `std::sync::RwLock`; readers unwind
    // cleanly. The helper holds write across the panic, simulating a
    // panic inside a control section.
    let domain = open_domain();
    std::thread::scope(|scope| {
        let parked = scope.spawn(|| {
            domain.hold_write_across_for_tests(|| panic!("intentional LifecycleDomain poison"))
        });
        assert!(parked.join().is_err(), "poisoning thread must panic");
    });
    assert_eq!(domain.admit_ordinary().unwrap_err(), CkRv::GENERAL_ERROR);
    assert_eq!(domain.begin_initialize().unwrap_err(), CkRv::GENERAL_ERROR);
}

#[test]
fn reader_panic_does_not_poison() {
    // `std` semantics pin: a settlement panic unwinding through an
    // ordinary guard releases read WITHOUT wedging the domain.
    let domain = open_domain();
    std::thread::scope(|scope| {
        let parked = scope.spawn(|| {
            let _guard = domain.admit_ordinary().expect("admits before panic");
            panic!("intentional reader panic (must not poison)");
        });
        assert!(parked.join().is_err(), "reader thread must panic");
    });
    domain.admit_ordinary().expect("domain still admits after reader panic");
    let init = domain.begin_initialize().expect("control still works after reader panic");
    domain.publish_open(init).expect("publish still works after reader panic");
}

#[test]
fn unsettled_ticket_drops_safely_when_poisoned() {
    let domain = open_domain();
    let init = domain.begin_initialize().expect("begin succeeds");
    std::thread::scope(|scope| {
        // Poison through the write lock. The outstanding control ticket's
        // Drop backstop must not panic; the domain stays fail-closed.
        let parked = scope.spawn(|| {
            domain.hold_write_across_for_tests(|| panic!("intentional LifecycleDomain poison"))
        });
        assert!(parked.join().is_err(), "poisoning thread must panic");
    });
    drop(init);
    assert_eq!(domain.admit_ordinary().unwrap_err(), CkRv::GENERAL_ERROR);
}

#[test]
fn control_write_blocks_while_ordinary_parked_then_proceeds() {
    // Blocked-stub exclusion shape at domain level: a parked ordinary
    // holder (standing in for a thread inside a provider call) blocks
    // control settlement until release; the control proceeds after.
    let domain = open_domain();
    let guard = domain.admit_ordinary().expect("admits while open");
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let ticket = domain.begin_initialize().expect("control proceeds after release");
            done_tx.send(ticket.epoch_for_tests()).expect("report control success");
        });
        assert!(
            done_rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "control must not settle while an ordinary guard is parked"
        );
        drop(guard);
        done_rx.recv_timeout(Duration::from_secs(5)).expect("control proceeds after release");
    });
}
