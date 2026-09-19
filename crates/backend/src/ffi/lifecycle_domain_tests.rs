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
use std::sync::mpsc;
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
fn publish_with_purge_runs_purge_and_advances_epoch() {
    // I2 success path: the purge closure runs exactly once, the domain
    // opens, and the epoch advances exactly as a plain publish would.
    let domain = LifecycleDomain::new();
    let init = domain.begin_initialize().expect("begin succeeds");
    let purged = std::sync::atomic::AtomicBool::new(false);
    domain
        .publish_open_with_purge(init, || purged.store(true, std::sync::atomic::Ordering::SeqCst))
        .expect("publish succeeds");
    assert!(purged.load(std::sync::atomic::Ordering::SeqCst), "purge must run");
    assert_eq!(domain.state_for_tests(), ModuleState::Open);
    let guard = domain.admit_ordinary().expect("open domain admits");
    assert_eq!(guard.epoch_for_tests(), 2, "begin + publish each advance the epoch");
}

#[test]
fn publish_purge_runs_inside_write_exclusion() {
    // I2 exclusion pin: a gated purge holds the publish write lock, so no
    // admission — the post-publish kind the old code raced — can complete
    // until the purge finishes.
    let domain = open_domain();
    let init = domain.begin_initialize().expect("begin succeeds");
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (admit_tx, admit_rx) = mpsc::channel();
    let domain = &domain;
    std::thread::scope(|scope| {
        scope.spawn(move || {
            domain
                .publish_open_with_purge(init, || {
                    entered_tx.send(()).expect("report purge entered");
                    release_rx.recv_timeout(Duration::from_secs(5)).expect("wait for release");
                })
                .expect("publish succeeds");
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).expect("purge entered under write");
        scope.spawn(|| {
            admit_tx.send(domain.admit_ordinary().is_ok()).expect("report admission");
        });
        assert!(
            admit_rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "no admission may complete while the purge holds publish write"
        );
        release_tx.send(()).expect("release the purge");
        assert!(
            admit_rx.recv_timeout(Duration::from_secs(5)).expect("admission resolves"),
            "post-purge admission succeeds against Open"
        );
    });
}

#[test]
fn publish_with_purge_at_exhaustion_skips_purge_fail_closed() {
    // I2 exhaustion path: no next identity means no publish and NO purge —
    // a refused cycle purges nothing; the domain fails closed to Uncertain.
    let domain = LifecycleDomain::new();
    domain.set_state_for_tests(ModuleState::LoadedUninitialized, u64::MAX - 1);
    let init = domain.begin_initialize().expect("begin consumes the last epoch");
    let purged = std::sync::atomic::AtomicBool::new(false);
    assert_eq!(
        domain
            .publish_open_with_purge(init, || purged
                .store(true, std::sync::atomic::Ordering::SeqCst))
            .unwrap_err(),
        CkRv::GENERAL_ERROR
    );
    assert!(!purged.load(std::sync::atomic::Ordering::SeqCst), "exhausted publish must not purge");
    assert_eq!(domain.state_for_tests(), ModuleState::Uncertain);
    assert_eq!(domain.admit_ordinary().unwrap_err(), CkRv::GENERAL_ERROR);
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
fn queued_writer_stalls_new_admissions() {
    // I1 fairness pin: `std::sync::RwLock` is writer-preferring — while a
    // control write is queued behind a parked reader, NEW ordinary
    // admissions stall behind it instead of barging ahead. TF01b's Finalize
    // drain relies on this for termination (see the Finalize paragraph in
    // the design block); if a platform ever stops preferring writers, this
    // test fails loudly instead of the drain hanging silently.
    let domain = open_domain();
    let guard = domain.admit_ordinary().expect("admits while open");
    let (began_tx, began_rx) = mpsc::channel();
    let (abandon_tx, abandon_rx) = mpsc::channel();
    let (admit_tx, admit_rx) = mpsc::channel();
    // Share a borrow: the writer closure below is `move` (the abandon
    // `Receiver` is !Sync), so it must capture `&LifecycleDomain`.
    let domain = &domain;
    std::thread::scope(|scope| {
        // Queued writer: blocks in begin behind the parked guard, then
        // waits for the test to release it so the state it publishes
        // (`Initializing`) stays put while the late reader resolves.
        scope.spawn(move || {
            let ticket = domain.begin_initialize().expect("control proceeds after release");
            began_tx.send(()).expect("report control begin");
            abandon_rx.recv_timeout(Duration::from_secs(5)).expect("wait for abandon signal");
            domain.abandon_initialize(ticket);
        });
        // The writer cannot be observed queuing; 200ms of parked-guard
        // block guarantees it is queued before the late reader attempts.
        std::thread::sleep(Duration::from_millis(200));
        scope.spawn(|| {
            let outcome = domain.admit_ordinary().map(|admitted| admitted.epoch_for_tests());
            admit_tx.send(outcome).expect("report late admission");
        });
        // The attempt itself must be in flight before the guard drops, or a
        // slow spawn could resolve post-begin and mask a fairness regression.
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            admit_rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "new admission must stall behind the queued writer, not barge ahead"
        );
        drop(guard);
        began_rx.recv_timeout(Duration::from_secs(5)).expect("writer begins after release");
        // The late reader now resolves against `Initializing`: denied, and
        // the denial proves it never slipped in ahead of the writer (an
        // admitted-while-Open reader would report `Ok`).
        assert_eq!(
            admit_rx.recv_timeout(Duration::from_secs(5)).expect("late reader resolves"),
            Err(CkRv::CRYPTOKI_NOT_INITIALIZED),
            "late reader resolves after the writer, against Initializing"
        );
        abandon_tx.send(()).expect("release the writer");
    });
    domain.admit_ordinary().expect("abandoned domain admits again");
}

/// conc-M2 tripwire self-test: nested admission must fail loudly, never
/// deadlock silently behind a queued writer. `cfg(debug_assertions)`-gated:
/// the tripwire is a debug-only mechanism (release keeps today's nested-read
/// behavior, and no production path nests — audited).
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "nested ordinary admission")]
fn tripwire_fires_on_nested_admit() {
    let domain = open_domain();
    let _outer = domain.admit_ordinary().expect("outer admits");
    // Must panic via the tripwire, never return (and never hang: the assert
    // runs before the read acquisition).
    let _inner = domain.admit_ordinary();
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

// --- TF01b Finalize seal/drain (I3) ---
//
// Drain-then-seal: the begin acquisition IS the drain (no in-flight
// reader survives it); the Draining flip under that write is the seal.
// `enter_finalizing` marks the exclusive native call in flight, and
// publish lands `Finalized`. Every step denies new admission.

#[test]
fn finalize_begin_enter_publish_cycle_seals_and_denies() {
    let domain = open_domain();
    let seal = domain.begin_finalize().expect("begin from Open");
    assert_eq!(domain.state_for_tests(), ModuleState::Draining);
    assert_eq!(
        domain.admit_ordinary().unwrap_err(),
        CkRv::CRYPTOKI_NOT_INITIALIZED,
        "sealed admission denies from Draining"
    );
    seal.enter_finalizing().expect("enter exclusive phase");
    assert_eq!(domain.state_for_tests(), ModuleState::Finalizing);
    assert_eq!(
        domain.admit_ordinary().unwrap_err(),
        CkRv::CRYPTOKI_NOT_INITIALIZED,
        "sealed admission denies from Finalizing"
    );
    domain.publish_finalized_with_purge(seal, || {}).expect("publish succeeds");
    assert_eq!(domain.state_for_tests(), ModuleState::Finalized);
    assert_eq!(
        domain.admit_ordinary().unwrap_err(),
        CkRv::CRYPTOKI_NOT_INITIALIZED,
        "sealed admission denies from Finalized"
    );
    assert_eq!(
        domain.epoch_for_tests(),
        4,
        "begin + publish advance; enter reuses the begin cycle"
    );
}

#[test]
fn finalize_begin_denied_from_non_open_states() {
    let domain = LifecycleDomain::new();
    for state in [
        ModuleState::LoadedUninitialized,
        ModuleState::Initializing,
        ModuleState::Draining,
        ModuleState::Finalizing,
        ModuleState::Finalized,
        ModuleState::Uncertain,
    ] {
        domain.set_state_for_tests(state, 7);
        let expected = match state {
            ModuleState::Uncertain => CkRv::GENERAL_ERROR,
            _ => CkRv::CRYPTOKI_NOT_INITIALIZED,
        };
        assert_eq!(domain.begin_finalize().unwrap_err(), expected, "denial RV from {state:?}");
        assert_eq!(domain.state_for_tests(), state, "denied begin changes nothing");
        assert_eq!(domain.epoch_for_tests(), 7, "denied begin consumes no epoch");
    }
}

#[test]
fn finalize_abandon_restores_open_and_admits() {
    let domain = open_domain();
    let seal = domain.begin_finalize().expect("begin from Open");
    seal.enter_finalizing().expect("enter exclusive phase");
    domain.abandon_finalize(seal);
    assert_eq!(domain.state_for_tests(), ModuleState::Open);
    domain.admit_ordinary().expect("restored Open admits again");
    assert!(domain.epoch_for_tests() > 2, "control transitions always advance the epoch");
}

#[test]
fn finalize_ticket_drop_abandons_unsettled_seal() {
    let domain = open_domain();
    {
        let _seal = domain.begin_finalize().expect("begin succeeds");
        // Dropped without publish: the backstop must restore, never wedge.
    }
    assert_eq!(domain.state_for_tests(), ModuleState::Open);
    domain.admit_ordinary().expect("backstop restores admission");
}

#[test]
fn finalize_stale_abandon_is_noop_epoch_mismatch() {
    // A later control cycle moved the domain past the ticket's epoch: the
    // stale abandon must not clobber the newer outcome. (Unreachable
    // without injection — every other begin is denied from a sealed
    // domain — so the newer cycle is simulated; the guard itself is real.)
    let domain = open_domain();
    let seal = domain.begin_finalize().expect("begin succeeds");
    let seal_epoch = seal.epoch_for_tests();
    domain.set_state_for_tests(ModuleState::Draining, seal_epoch + 1);
    domain.abandon_finalize(seal);
    assert_eq!(domain.state_for_tests(), ModuleState::Draining, "stale abandon is a no-op");
    assert_eq!(domain.epoch_for_tests(), seal_epoch + 1, "stale abandon consumes nothing");
}

#[test]
fn finalize_begin_denied_at_epoch_exhaustion() {
    let domain = open_domain();
    domain.set_state_for_tests(ModuleState::Open, u64::MAX);
    assert_eq!(domain.begin_finalize().unwrap_err(), CkRv::GENERAL_ERROR);
    assert_eq!(domain.state_for_tests(), ModuleState::Open, "denied begin changes nothing");
    assert_eq!(domain.epoch_for_tests(), u64::MAX, "denied begin consumes no epoch");
    domain.admit_ordinary().expect("unmoved Open still admits");
}

#[test]
fn finalize_publish_with_purge_runs_purge_and_lands_finalized() {
    // Purge/publish ordering (I2 mirror): the purge runs exactly once,
    // inside the publish write section, and the domain lands Finalized.
    let domain = open_domain();
    let seal = domain.begin_finalize().expect("begin succeeds");
    seal.enter_finalizing().expect("enter exclusive phase");
    let purged = std::sync::atomic::AtomicBool::new(false);
    domain
        .publish_finalized_with_purge(seal, || {
            purged.store(true, std::sync::atomic::Ordering::SeqCst)
        })
        .expect("publish succeeds");
    assert!(purged.load(std::sync::atomic::Ordering::SeqCst), "purge must run");
    assert_eq!(domain.state_for_tests(), ModuleState::Finalized);
}

#[test]
fn finalize_publish_at_exhaustion_skips_purge_fail_closed() {
    // Exhaustion path: no next identity means no publish and NO purge —
    // a refused cycle purges nothing; the domain fails closed to Uncertain.
    let domain = open_domain();
    domain.set_state_for_tests(ModuleState::Open, u64::MAX - 1);
    let seal = domain.begin_finalize().expect("begin consumes the last epoch");
    seal.enter_finalizing().expect("enter exclusive phase");
    let purged = std::sync::atomic::AtomicBool::new(false);
    assert_eq!(
        domain
            .publish_finalized_with_purge(seal, || purged
                .store(true, std::sync::atomic::Ordering::SeqCst))
            .unwrap_err(),
        CkRv::GENERAL_ERROR
    );
    assert!(!purged.load(std::sync::atomic::Ordering::SeqCst), "exhausted publish must not purge");
    assert_eq!(domain.state_for_tests(), ModuleState::Uncertain);
    assert_eq!(domain.admit_ordinary().unwrap_err(), CkRv::GENERAL_ERROR);
}

#[test]
fn finalize_poisoned_domain_denies_begin_fail_closed() {
    // Mirror of the Initialize poison pin: only a writer panic poisons;
    // the sealer denies without touching the provider, and the unsettled
    // ticket's Drop backstop stays panic-free.
    let domain = open_domain();
    let seal = domain.begin_finalize().expect("begin succeeds");
    std::thread::scope(|scope| {
        let parked = scope.spawn(|| {
            domain.hold_write_across_for_tests(|| panic!("intentional LifecycleDomain poison"))
        });
        assert!(parked.join().is_err(), "poisoning thread must panic");
    });
    assert_eq!(domain.begin_finalize().unwrap_err(), CkRv::GENERAL_ERROR);
    assert!(seal.enter_finalizing().is_err(), "enter on poison fails closed");
    drop(seal);
    assert_eq!(domain.admit_ordinary().unwrap_err(), CkRv::GENERAL_ERROR);
}

#[test]
fn drop_quiescence_quiet_domain_not_poisoned() {
    // I4/conc-M3 Drop probe: a domain that ran ordinary + control cycles
    // without a writer panic reports clean from every settled state.
    let domain = open_domain();
    domain.admit_ordinary().expect("ordinary cycle");
    assert!(!domain.quiescence_poisoned(), "open quiet domain is clean");
    let seal = domain.begin_finalize().expect("begin succeeds");
    seal.enter_finalizing().expect("enter exclusive phase");
    domain.publish_finalized_with_purge(seal, || {}).expect("publish succeeds");
    assert!(!domain.quiescence_poisoned(), "finalized quiet domain is clean");
}

#[test]
fn drop_quiescence_poisoned_domain_reports_poison() {
    // Only a writer panic poisons; the probe observes exactly that (the
    // sole `Drop`-time signal — `WouldBlock` is unreachable there and
    // deliberately has no arm).
    let domain = open_domain();
    std::thread::scope(|scope| {
        let parked = scope.spawn(|| {
            domain.hold_write_across_for_tests(|| panic!("intentional LifecycleDomain poison"))
        });
        assert!(parked.join().is_err(), "poisoning thread must panic");
    });
    assert!(domain.quiescence_poisoned(), "poisoned domain reports poison");
}
