use super::output_semantics::TestDaemon;
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

unsafe extern "C" fn dummy_create_mutex(_: *mut CK_VOID_PTR) -> CK_RV {
    CKR_GENERAL_ERROR as CK_RV
}

unsafe extern "C" fn dummy_destroy_mutex(_: CK_VOID_PTR) -> CK_RV {
    CKR_GENERAL_ERROR as CK_RV
}

unsafe extern "C" fn dummy_lock_mutex(_: CK_VOID_PTR) -> CK_RV {
    CKR_GENERAL_ERROR as CK_RV
}

unsafe extern "C" fn dummy_unlock_mutex(_: CK_VOID_PTR) -> CK_RV {
    CKR_GENERAL_ERROR as CK_RV
}

#[test]
fn initialize_p_reserved_nonnull_returns_bad_args() {
    let _guard = shim_state_test_guard();
    let mut args = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: 0,
        pReserved: std::ptr::dangling_mut::<std::ffi::c_void>(),
    };
    let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn finalize_p_reserved_nonnull_returns_bad_args() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_finalize(std::ptr::dangling_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn initialize_custom_mutex_callbacks_returns_cant_lock() {
    let _guard = shim_state_test_guard();
    let mut args = CK_C_INITIALIZE_ARGS {
        CreateMutex: Some(dummy_create_mutex),
        DestroyMutex: Some(dummy_destroy_mutex),
        LockMutex: Some(dummy_lock_mutex),
        UnlockMutex: Some(dummy_unlock_mutex),
        flags: 0,
        pReserved: std::ptr::null_mut(),
    };
    let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
    assert_eq!(rv, CKR_CANT_LOCK as CK_RV);
}

#[test]
fn initialize_os_locking_ok_flag_accepted_before_server() {
    let _guard = shim_state_test_guard();
    let mut args = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: CKF_OS_LOCKING_OK,
        pReserved: std::ptr::null_mut(),
    };
    let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
    assert_ne!(rv, CKR_ARGUMENTS_BAD as CK_RV);
    assert_ne!(rv, CKR_CANT_LOCK as CK_RV);
    if rv == CKR_OK as CK_RV {
        let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    }
}

#[test]
fn initialize_connect_failure_is_not_device_error() {
    // CKR_DEVICE_ERROR is NOT in the OASIS-permitted return set for
    // C_Initialize; a failed daemon connection must surface as the
    // lifecycle-class CKR_GENERAL_ERROR so the shim is indistinguishable
    // from a native module's error contract.
    let _guard = shim_state_test_guard();
    let mut args = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: CKF_OS_LOCKING_OK,
        pReserved: std::ptr::null_mut(),
    };
    let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
    assert_ne!(rv, CKR_DEVICE_ERROR as CK_RV, "C_Initialize must never return CKR_DEVICE_ERROR");
    if rv == CKR_OK as CK_RV {
        let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    } else {
        assert_eq!(
            rv, CKR_GENERAL_ERROR as CK_RV,
            "a C_Initialize connect failure must be CKR_GENERAL_ERROR"
        );
    }
}

#[test]
fn initialize_rejects_library_cant_create_os_threads() {
    // The shim runs a tokio runtime that spawns OS worker threads, so it cannot
    // honor a caller that forbids library threads. Per PKCS#11 §5.4 this must
    // be reported up front as CKR_NEED_TO_CREATE_THREADS, not silently accepted.
    let _guard = shim_state_test_guard();
    let mut args = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: CKF_LIBRARY_CANT_CREATE_OS_THREADS,
        pReserved: std::ptr::null_mut(),
    };
    let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
    assert_eq!(
        rv, CKR_NEED_TO_CREATE_THREADS as CK_RV,
        "CKF_LIBRARY_CANT_CREATE_OS_THREADS must be rejected"
    );
    if rv == CKR_OK as CK_RV {
        let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    }
}

#[test]
fn initialize_mutex_callbacks_with_os_locking_ok_accepted() {
    let _guard = shim_state_test_guard();
    let mut args = CK_C_INITIALIZE_ARGS {
        CreateMutex: Some(dummy_create_mutex),
        DestroyMutex: Some(dummy_destroy_mutex),
        LockMutex: Some(dummy_lock_mutex),
        UnlockMutex: Some(dummy_unlock_mutex),
        flags: CKF_OS_LOCKING_OK,
        pReserved: std::ptr::null_mut(),
    };
    let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
    assert_ne!(rv, CKR_ARGUMENTS_BAD as CK_RV);
    assert_ne!(rv, CKR_CANT_LOCK as CK_RV);
    if rv == CKR_OK as CK_RV {
        let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    }
}

// Q02 (COR-03): PKCS#11 requires CKR_ARGUMENTS_BAD when some, but not
// all, mutex callbacks are supplied. The 14 proper nonempty subsets
// (masks 1..=14) must be rejected before any local initialization or
// network state changes, with OS locking both allowed and absent.
// Failures are collected across every mask so one bad mask cannot hide
// the rest.

static COUNT_CREATE_MUTEX: AtomicUsize = AtomicUsize::new(0);
static COUNT_DESTROY_MUTEX: AtomicUsize = AtomicUsize::new(0);
static COUNT_LOCK_MUTEX: AtomicUsize = AtomicUsize::new(0);
static COUNT_UNLOCK_MUTEX: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn counting_create_mutex(_: *mut CK_VOID_PTR) -> CK_RV {
    COUNT_CREATE_MUTEX.fetch_add(1, Ordering::SeqCst);
    CKR_OK as CK_RV
}

unsafe extern "C" fn counting_destroy_mutex(_: CK_VOID_PTR) -> CK_RV {
    COUNT_DESTROY_MUTEX.fetch_add(1, Ordering::SeqCst);
    CKR_OK as CK_RV
}

unsafe extern "C" fn counting_lock_mutex(_: CK_VOID_PTR) -> CK_RV {
    COUNT_LOCK_MUTEX.fetch_add(1, Ordering::SeqCst);
    CKR_OK as CK_RV
}

unsafe extern "C" fn counting_unlock_mutex(_: CK_VOID_PTR) -> CK_RV {
    COUNT_UNLOCK_MUTEX.fetch_add(1, Ordering::SeqCst);
    CKR_OK as CK_RV
}

fn reset_callback_counters() {
    COUNT_CREATE_MUTEX.store(0, Ordering::SeqCst);
    COUNT_DESTROY_MUTEX.store(0, Ordering::SeqCst);
    COUNT_LOCK_MUTEX.store(0, Ordering::SeqCst);
    COUNT_UNLOCK_MUTEX.store(0, Ordering::SeqCst);
}

fn callback_invocations() -> usize {
    COUNT_CREATE_MUTEX.load(Ordering::SeqCst)
        + COUNT_DESTROY_MUTEX.load(Ordering::SeqCst)
        + COUNT_LOCK_MUTEX.load(Ordering::SeqCst)
        + COUNT_UNLOCK_MUTEX.load(Ordering::SeqCst)
}

fn client_holds_context() -> bool {
    // Flag-INDEPENDENT: `try_client` observes the stored server context
    // id directly instead of trusting the init flag, so an
    // admit-then-cleanup defect (admit, finalize, clear the flag,
    // return BAD) cannot hide behind a cleared flag. `None` before the
    // first successful connect (no client constructed yet) reads as
    // "holds nothing".
    state::try_client()
        .map(|m| state::runtime().block_on(async { m.lock().await.context_id_opt().is_some() }))
        .unwrap_or(false)
}

/// Sorted daemon live-context ids: the per-mask live-set snapshot. The
/// shared daemon is process-global, so callers snapshot this BEFORE the
/// loop and require set-equality after every mask (other suites'
/// contexts, if any leak, are part of the baseline, not the delta).
fn daemon_live_sorted(daemon: &TestDaemon) -> Vec<String> {
    let mut ids: Vec<String> = daemon.live_context_ids().iter().map(|id| id.0.clone()).collect();
    ids.sort();
    ids
}

fn args_for_mask(mask: u8, flags: CK_FLAGS) -> CK_C_INITIALIZE_ARGS {
    CK_C_INITIALIZE_ARGS {
        CreateMutex: if mask & 1 != 0 { Some(counting_create_mutex) } else { None },
        DestroyMutex: if mask & 2 != 0 { Some(counting_destroy_mutex) } else { None },
        LockMutex: if mask & 4 != 0 { Some(counting_lock_mutex) } else { None },
        UnlockMutex: if mask & 8 != 0 { Some(counting_unlock_mutex) } else { None },
        flags,
        pReserved: std::ptr::null_mut(),
    }
}

/// Run all 14 proper nonempty callback subsets against `flags` and
/// return one failure line per case that was not cleanly rejected
/// before initialization. Accepted inits are finalized immediately so
/// no state leaks into the next mask. The daemon live set must equal
/// `baseline_live` after every mask; cumulative admission/removal/dial
/// totals are asserted by the caller (they need before/after
/// snapshots, and folding every signal into one report keeps a red run
/// diagnostic: per-mask lines stay silent under admit-then-cleanup
/// while the totals lines fire).
fn partial_mask_failures(
    flags: CK_FLAGS,
    daemon: &TestDaemon,
    baseline_live: &[String],
) -> Vec<String> {
    let mut failures = Vec::new();
    for mask in 1u8..15 {
        let mut args = args_for_mask(mask, flags);
        let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
        let initialized = state::is_initialized();
        let context_held = client_holds_context();
        let live = daemon_live_sorted(daemon);
        if rv == CKR_OK as CK_RV {
            let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
        }
        if rv != CKR_ARGUMENTS_BAD as CK_RV {
            failures.push(format!("mask {mask:#06b}: rv = {rv:#X}, want CKR_ARGUMENTS_BAD"));
        }
        if initialized {
            failures.push(format!("mask {mask:#06b}: shim marked initialized"));
        }
        if context_held {
            failures.push(format!("mask {mask:#06b}: client holds a server context id"));
        }
        if live != baseline_live {
            failures.push(format!(
                "mask {mask:#06b}: daemon live contexts changed: {live:?} vs baseline {baseline_live:?}"
            ));
        }
    }
    failures
}

fn use_shared_daemon() -> &'static TestDaemon {
    let daemon = TestDaemon::shared();
    unsafe {
        std::env::set_var("PKCS11_PROXY_ENDPOINT", &daemon.endpoint);
    }
    daemon
}

/// Fold the cumulative no-admission signals into `failures`: daemon
/// admission/removal totals (monotonic — an admit-then-cleanup defect
/// that returns the live set to baseline still shows here), the
/// dial-series counter (rejections happen before any connect), and the
/// caller-callback counters. Deltas are computed against caller
/// snapshots so the shared daemon's history from other suites cannot
/// pollute this matrix.
fn push_cumulative_no_admission_failures(
    failures: &mut Vec<String>,
    daemon: &TestDaemon,
    created_before: u64,
    removed_before: u64,
    series_before: u32,
) {
    let created = daemon.total_contexts_created() - created_before;
    if created != 0 {
        failures.push(format!(
            "cumulative daemon admissions across 14 masks: +{created}, want +0 (admit-then-cleanup-proof)"
        ));
    }
    let removed = daemon.total_contexts_removed() - removed_before;
    if removed != 0 {
        failures.push(format!(
            "cumulative daemon removals across 14 masks: +{removed}, want +0 (admit-then-cleanup-proof)"
        ));
    }
    let series = state::connect_series_count() - series_before;
    if series != 0 {
        failures.push(format!(
            "dial series across 14 masks: +{series}, want +0 (rejections must not dial)"
        ));
    }
    let callbacks = callback_invocations();
    if callbacks != 0 {
        failures.push(format!(
            "rejected inits must not invoke caller mutex callbacks: {callbacks} invocations"
        ));
    }
}

#[test]
fn initialize_rejects_partial_callback_masks_with_os_locking() {
    let _guard = shim_state_test_guard();
    let daemon = use_shared_daemon();
    assert!(!state::is_initialized(), "test requires pre-init state");
    reset_callback_counters();
    let baseline_live = daemon_live_sorted(daemon);
    let created_before = daemon.total_contexts_created();
    let removed_before = daemon.total_contexts_removed();
    let series_before = state::connect_series_count();
    let mut failures = partial_mask_failures(CKF_OS_LOCKING_OK, daemon, &baseline_live);
    push_cumulative_no_admission_failures(
        &mut failures,
        daemon,
        created_before,
        removed_before,
        series_before,
    );
    assert!(
        failures.is_empty(),
        "partial callback sets with OS locking must be rejected before init:\n{}",
        failures.join("\n")
    );
}

#[test]
fn initialize_rejects_partial_callback_masks_without_os_locking() {
    let _guard = shim_state_test_guard();
    let daemon = use_shared_daemon();
    assert!(!state::is_initialized(), "test requires pre-init state");
    reset_callback_counters();
    let baseline_live = daemon_live_sorted(daemon);
    let created_before = daemon.total_contexts_created();
    let removed_before = daemon.total_contexts_removed();
    let series_before = state::connect_series_count();
    let mut failures = partial_mask_failures(0, daemon, &baseline_live);
    push_cumulative_no_admission_failures(
        &mut failures,
        daemon,
        created_before,
        removed_before,
        series_before,
    );
    assert!(
        failures.is_empty(),
        "partial callback sets without OS locking must be rejected before init:\n{}",
        failures.join("\n")
    );
}

/// Positive controls (null/empty/all shapes must fully initialize
/// against the live daemon, proving matrix rejections are real) plus
/// retained rejection-precedence pins. The four accepted legs each mint
/// exactly one daemon context and finalize removes it, so the closing
/// +4/+4 accounting proves the counters are live AND the three refusal
/// legs minted nothing (any refusal-leg admission would push the
/// totals past +4/+4).
#[test]
fn initialize_callback_controls_and_rejection_precedence() {
    let _guard = shim_state_test_guard();
    let daemon = use_shared_daemon();
    assert!(!state::is_initialized(), "test requires pre-init state");
    reset_callback_counters();
    let baseline_live = daemon_live_sorted(daemon);
    let created_before = daemon.total_contexts_created();
    let removed_before = daemon.total_contexts_removed();

    // Null args: accepted and fully initialized.
    let rv = unsafe { dispatch::general::c_initialize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "null pInitArgs must initialize");
    assert!(state::is_initialized(), "null pInitArgs must set the init flag");
    assert!(client_holds_context(), "null pInitArgs must admit a server context");
    assert_eq!(
        daemon.live_context_count(),
        baseline_live.len() + 1,
        "null pInitArgs must mint exactly one daemon context"
    );
    let rv = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "control finalize must succeed");
    assert!(!state::is_initialized(), "finalize must clear the init flag");
    assert!(!client_holds_context(), "finalize must release the server context");
    assert_eq!(
        daemon_live_sorted(daemon),
        baseline_live,
        "finalize must remove the daemon context"
    );

    // Empty callback set, single-threaded flags: accepted.
    let mut args = args_for_mask(0, 0);
    let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
    assert_eq!(rv, CKR_OK as CK_RV, "empty callbacks without OS locking must initialize");
    assert!(state::is_initialized(), "empty callbacks must set the init flag");
    assert!(client_holds_context(), "empty callbacks must admit a server context");
    let rv = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "control finalize must succeed");

    // Empty callback set with OS locking: accepted.
    let mut args = args_for_mask(0, CKF_OS_LOCKING_OK);
    let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
    assert_eq!(rv, CKR_OK as CK_RV, "empty callbacks with OS locking must initialize");
    assert!(state::is_initialized(), "empty callbacks must set the init flag");
    assert!(client_holds_context(), "empty callbacks must admit a server context");
    let rv = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "control finalize must succeed");

    // Complete callback set with OS locking: accepted (GnuTLS/p11-kit shape).
    let mut args = args_for_mask(0xF, CKF_OS_LOCKING_OK);
    let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
    assert_eq!(rv, CKR_OK as CK_RV, "complete callbacks with OS locking must initialize");
    assert!(state::is_initialized(), "complete callbacks must set the init flag");
    assert!(client_holds_context(), "complete callbacks must admit a server context");
    let rv = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_OK as CK_RV, "control finalize must succeed");

    // Complete callback set without OS locking: still CANT_LOCK.
    let mut args = args_for_mask(0xF, 0);
    let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
    assert_eq!(rv, CKR_CANT_LOCK as CK_RV, "complete callbacks without OS locking stay CANT_LOCK");
    assert!(!state::is_initialized(), "CANT_LOCK must not initialize");
    assert!(!client_holds_context(), "CANT_LOCK must not admit a server context");
    assert_eq!(
        daemon_live_sorted(daemon),
        baseline_live,
        "CANT_LOCK must not mint a daemon context"
    );

    // Precedence pin: complete callbacks without OS locking beat the
    // no-library-threads refusal (existing CANT_LOCK-first order).
    let mut args = args_for_mask(0xF, CKF_LIBRARY_CANT_CREATE_OS_THREADS);
    let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
    assert_eq!(
        rv, CKR_CANT_LOCK as CK_RV,
        "complete callbacks without OS locking keep CANT_LOCK precedence over NEED_TO_CREATE_THREADS"
    );
    assert!(!state::is_initialized(), "precedence refusal must not initialize");
    assert!(!client_holds_context(), "precedence refusal must not admit a server context");
    assert_eq!(
        daemon_live_sorted(daemon),
        baseline_live,
        "precedence refusal must not mint a daemon context"
    );

    // Precedence pin: a malformed partial set is ARGUMENTS_BAD even when
    // the no-library-threads flag is also present (shape validation runs
    // before capability refusal).
    let mut args = args_for_mask(0x1, CKF_LIBRARY_CANT_CREATE_OS_THREADS);
    let rv = unsafe { dispatch::general::c_initialize(&mut args as *mut _ as CK_VOID_PTR) };
    assert_eq!(
        rv, CKR_ARGUMENTS_BAD as CK_RV,
        "partial callbacks stay ARGUMENTS_BAD despite NEED_TO_CREATE_THREADS flag"
    );
    assert!(!state::is_initialized(), "partial-set refusal must not initialize");
    assert!(!client_holds_context(), "partial-set refusal must not admit a server context");
    assert_eq!(
        daemon_live_sorted(daemon),
        baseline_live,
        "partial-set refusal must not mint a daemon context"
    );

    // Closing accounting: exactly the four accepted legs admitted and
    // released one context each; the refusal legs added nothing.
    assert_eq!(
        daemon.total_contexts_created() - created_before,
        4,
        "controls must show exactly four cumulative admissions"
    );
    assert_eq!(
        daemon.total_contexts_removed() - removed_before,
        4,
        "controls must show exactly four cumulative removals"
    );
    assert_eq!(
        daemon_live_sorted(daemon),
        baseline_live,
        "controls must leave the daemon live set at baseline"
    );
    assert_eq!(callback_invocations(), 0, "inits must not invoke caller mutex callbacks");
}
