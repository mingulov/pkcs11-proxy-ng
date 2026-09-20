#![cfg(all(test, unix))]
//! Child-process scenarios for abnormal native-lifetime stop (STOP-C1).
//!
//! Re-spawn harness: each parent test re-runs this lib test binary via
//! `current_exe` with `--exact <child-entry> --nocapture` plus a scenario
//! selector env var. No `fork()`: the child needs multiple live threads.
//! STOP-C2 owns marker files; this fragment asserts only exit status (70),
//! no-signal/no-core, pipe EOF (output collected), and reaping.

use super::FfiBackend;
use crate::traits::Pkcs11Backend;
use std::io::Write as _;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex};

/// Scenario selector env var (design Q4 full name; contains NATIVE_STOP_CHILD).
const CHILD_ENV: &str = "PKCS11_PROXY_NATIVE_STOP_CHILD";
/// Exact child entry test path within the lib test binary.
const CHILD_TEST_PATH: &str = "ffi::native_stop_tests::native_stop_child_entry";
/// Cap on concurrent stop children (task: max 3-5).
const MAX_CONCURRENT_CHILDREN: u32 = 4;

static SEM_COUNT: Mutex<u32> = Mutex::new(0);
static SEM_CVAR: Condvar = Condvar::new();

/// Held from spawn until the child is reaped; caps concurrent children.
struct ChildPermit {
    _private: (),
}

fn acquire_child_permit() -> ChildPermit {
    let mut count = SEM_COUNT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    while *count >= MAX_CONCURRENT_CHILDREN {
        count = SEM_CVAR.wait(count).unwrap_or_else(|poisoned| poisoned.into_inner());
    }
    *count += 1;
    ChildPermit { _private: () }
}

impl Drop for ChildPermit {
    fn drop(&mut self) {
        let mut count = SEM_COUNT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *count = count.saturating_sub(1);
        SEM_CVAR.notify_one();
    }
}

/// Spawn the lib test binary as a stop child for `scenario`.
fn spawn_stop_child(scenario: &str) -> (Child, ChildPermit) {
    spawn_stop_child_with_env(scenario, &[])
}

/// Spawn with extra env pairs (e.g. controller grace override for S8).
fn spawn_stop_child_with_env(scenario: &str, extra_env: &[(&str, &str)]) -> (Child, ChildPermit) {
    let permit = acquire_child_permit();
    let exe = std::env::current_exe().expect("current test exe");
    let mut cmd = Command::new(exe);
    cmd.arg("--exact")
        .arg(CHILD_TEST_PATH)
        .arg("--nocapture")
        .env(CHILD_ENV, scenario)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    let child = cmd.spawn().expect("spawn stop child");
    (child, permit)
}

/// Assert the abnormal-stop record: normal exit 70, no signal/core, READY pipe.
fn assert_stop_status(output: &Output, scenario: &str) {
    assert_eq!(
        output.status.code(),
        Some(70),
        "scenario {scenario}: normal exit status 70, got {:?}",
        output.status
    );
    assert_eq!(output.status.signal(), None, "scenario {scenario}: no terminating signal");
    assert!(!output.status.core_dumped(), "scenario {scenario}: no core");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("READY"),
        "scenario {scenario}: READY line missing (pipe EOF proof), stdout={stdout:?}"
    );
}

/// Assert a control record: normal exit 0 (no stop), no signal/core, READY.
fn assert_control_status(output: &Output, scenario: &str) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "scenario {scenario}: normal exit status 0, got {:?}",
        output.status
    );
    assert_eq!(output.status.signal(), None, "scenario {scenario}: no terminating signal");
    assert!(!output.status.core_dumped(), "scenario {scenario}: no core");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("READY"), "scenario {scenario}: READY line missing, stdout={stdout:?}");
}

/// Child entry: vacuously passes in-process; diverges in the re-spawned child.
#[test]
fn native_stop_child_entry() {
    let Ok(scenario) = std::env::var(CHILD_ENV) else {
        return;
    };
    run_stop_child(&scenario);
}

/// Child dispatch. Never panics: setup failures exit with distinct codes
/// (11 bad scenario, 12 reserve failed, 13 activate failed, 14 initialize
/// failed, 15 no-new-privs failed, 16 seccomp failed, 17 thread spawn failed,
/// 18 handoff failed, 19 sync timeout, 20 stop did not fire, 21 unexpected
/// worker completion, 22 mech failed, 23 controller did not fire, 24
/// initialize unexpectedly succeeded, 25 finalize unexpectedly succeeded,
/// 99 fell through the denied stop).
fn run_stop_child(scenario: &str) -> ! {
    match scenario {
        "s1-main" => run_s1_main(),
        "s2-worker" => run_s2_worker(),
        "s3-race" => run_s3_race(),
        "s4a-join-timeout" => run_s4a_join_timeout(),
        "s4b-leak-detached" => run_s4b_leak_detached(),
        "s5-retained" => run_s5_retained(),
        "s6-poisoned" => run_s6_poisoned(),
        "s7-pending" => run_s7_pending(),
        "s8-finalize-deadline" => run_s8_finalize_deadline(),
        "s9-unknown" => run_s9_unknown(),
        "s10-unsettled" => run_s10_unsettled(),
        "s11-gated" => run_s11_gated(),
        "s12-failed-init" => run_s12_failed_init(),
        "s13-stuck-call" => run_s13_stuck_call(),
        "s14-proof-invalidated" => run_s14_proof_invalidated(),
        "s15-failed-finalize" => run_s15_failed_finalize(),
        "s16-handler-installed" => run_s16_handler_installed(),
        "s17-genuine-waiter" => run_s17_genuine_waiter(),
        "c1-never-init" => run_c1_never_init(),
        "c2-unmanaged" => run_c2_unmanaged(),
        "n1-seccomp" => run_n1_seccomp(),
        "n1-worker" => run_n1_worker(),
        _ => std::process::exit(11),
    }
}

// Child-side provider stubs: pure returns, no locks, no panic paths.
unsafe extern "C" fn child_initialize_ok(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
    cryptoki_sys::CKR_OK
}

unsafe extern "C" fn child_finalize_ok(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
    cryptoki_sys::CKR_OK
}

/// Failing Initialize stub for S12: native entered, error RV, no session.
unsafe extern "C" fn child_initialize_fails(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
    cryptoki_sys::CKR_GENERAL_ERROR
}

/// Never-returning Finalize stub for S8: parks forever holding no locks.
unsafe extern "C" fn child_finalize_stuck(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
    loop {
        std::thread::park();
    }
}

/// Build a managed backend (real permit, hand-written function list).
/// The function list is leaked: the child exits via the group stop, so no
/// dangling `func_list` can outlive the backend on the stop path.
fn child_backend_managed(
    initialize: cryptoki_sys::CK_C_Initialize,
    finalize: cryptoki_sys::CK_C_Finalize,
) -> FfiBackend {
    let permit = match super::native_domain::reserve_for_construction() {
        Ok(permit) => permit,
        Err(_) => std::process::exit(12),
    };
    if permit.activate().is_err() {
        std::process::exit(13);
    }
    let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
    functions.C_Initialize = initialize;
    functions.C_Finalize = finalize;
    let func_list = Box::leak(functions) as *mut cryptoki_sys::CK_FUNCTION_LIST;
    FfiBackend {
        _lib: super::loading::test_library_handle(),
        func_list,
        func_list_3_0: None,
        func_list_3_2: None,
        initialize_args: None,
        mech_cache: dashmap::DashMap::new(),
        last_init_family: dashmap::DashMap::new(),
        session_slot_map: dashmap::DashMap::new(),
        slot_sessions: dashmap::DashMap::new(),
        object_cleanup: Default::default(),
        retirement_sentinel: super::native_domain::RetirementSentinel::for_permit(&permit),
        construction: permit,
        lifecycle: Default::default(),
        lifecycle_domain: Default::default(),
        session_fences: Default::default(),
    }
}

/// Spawn one parked worker (holds no locks); exits 17 if the OS refuses.
fn spawn_parked_worker(name: String, barrier: Arc<Barrier>) {
    let spawned = std::thread::Builder::new().name(name).spawn(move || {
        barrier.wait();
        loop {
            std::thread::park();
        }
    });
    if spawned.is_err() {
        std::process::exit(17);
    }
}

/// Spin until `flag` sets, with a 5 s fail-fast budget (exits 19 on timeout).
/// Yield-only spin: no sleep, so the documented settle windows stay minimal.
fn wait_flag_5s(flag: &AtomicBool) {
    let start = std::time::Instant::now();
    while !flag.load(Ordering::SeqCst) {
        if start.elapsed() > std::time::Duration::from_secs(5) {
            std::process::exit(19);
        }
        std::thread::yield_now();
    }
}

/// S1 child: minimal dirty, 3 parked workers, main thread drops.
fn run_s1_main() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let barrier = Arc::new(Barrier::new(4));
    for index in 0..3 {
        spawn_parked_worker(format!("stop-park-{index}"), barrier.clone());
    }
    barrier.wait();
    let _ = writeln!(std::io::stdout(), "READY s1-main");
    let _ = std::io::stdout().flush();
    drop(backend);
    // Reached only if the guard did not stop (unexpected Release).
    std::process::exit(20);
}

/// S2 child: worker #0 (non-TGID) drops while main + others park.
fn run_s2_worker() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let (tx, rx) = std::sync::mpsc::channel::<FfiBackend>();
    let main_parked = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(4));
    // Worker #0: receives the dirty owner, waits for parked main, drops.
    {
        let flag = main_parked.clone();
        let gate = barrier.clone();
        let spawned =
            std::thread::Builder::new().name("stop-worker-0".to_owned()).spawn(move || {
                gate.wait();
                let owner = match rx.recv() {
                    Ok(owner) => owner,
                    Err(_) => std::process::exit(18),
                };
                wait_flag_5s(&flag);
                let _ = writeln!(std::io::stdout(), "READY s2-worker");
                let _ = std::io::stdout().flush();
                drop(owner);
                std::process::exit(20);
            });
        if spawned.is_err() {
            std::process::exit(17);
        }
    }
    for index in 1..3 {
        spawn_parked_worker(format!("stop-park-{index}"), barrier.clone());
    }
    barrier.wait();
    if tx.send(backend).is_err() {
        std::process::exit(18);
    }
    main_parked.store(true, Ordering::SeqCst);
    loop {
        std::thread::park();
    }
}

/// S3 child: two workers race to take and drop the shared dirty owner.
fn run_s3_race() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let shared = Arc::new(Mutex::new(Some(backend)));
    let main_parked = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(3));
    for index in 0..2 {
        let slot = shared.clone();
        let flag = main_parked.clone();
        let gate = barrier.clone();
        let spawned =
            std::thread::Builder::new().name(format!("stop-racer-{index}")).spawn(move || {
                gate.wait();
                wait_flag_5s(&flag);
                let taken = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
                match taken {
                    Some(owner) => {
                        let _ = writeln!(std::io::stdout(), "READY s3-race");
                        let _ = std::io::stdout().flush();
                        drop(owner);
                        std::process::exit(20);
                    }
                    None => loop {
                        std::thread::park();
                    },
                }
            });
        if spawned.is_err() {
            std::process::exit(17);
        }
    }
    barrier.wait();
    main_parked.store(true, Ordering::SeqCst);
    loop {
        std::thread::park();
    }
}

/// S4a child: stuck worker observed via a 200 ms join-timeout, then stop.
fn run_s4a_join_timeout() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let started = Arc::new(AtomicBool::new(false));
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    {
        let flag = started.clone();
        let spawned = std::thread::Builder::new().name("stop-stuck".to_owned()).spawn(move || {
            // Hold `tx` so the join times out instead of disconnecting.
            let _held = tx;
            flag.store(true, Ordering::SeqCst);
            loop {
                std::thread::park();
            }
        });
        if spawned.is_err() {
            std::process::exit(17);
        }
    }
    wait_flag_5s(&started);
    match rx.recv_timeout(std::time::Duration::from_millis(200)) {
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        _ => std::process::exit(21),
    }
    let _ = writeln!(std::io::stdout(), "READY s4a-join-timeout");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// S4b child: leak-detached stuck worker plus a 100 ms documented settle.
fn run_s4b_leak_detached() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let started = Arc::new(AtomicBool::new(false));
    {
        let flag = started.clone();
        let spawned = std::thread::Builder::new().name("stop-stuck".to_owned()).spawn(move || {
            flag.store(true, Ordering::SeqCst);
            loop {
                std::thread::park();
            }
        });
        match spawned {
            Ok(handle) => std::mem::forget(handle),
            Err(_) => std::process::exit(17),
        }
    }
    wait_flag_5s(&started);
    // Documented settle window: let the detached worker park before the stop.
    std::thread::sleep(std::time::Duration::from_millis(100));
    let _ = writeln!(std::io::stdout(), "READY s4b-leak-detached");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// S5 child: retained Encrypt-family graph plus parked workers, main drops.
fn run_s5_retained() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let mechanism = pkcs11_proxy_ng_types::CkMechanism {
        mechanism_type: pkcs11_proxy_ng_types::CkMechanismType::RSA_PKCS,
        params: None,
    };
    let retained = match super::ffi_conversion::mechanism_to_ffi(&mechanism) {
        Ok(retained) => retained,
        Err(_) => std::process::exit(22),
    };
    backend.mech_cache.insert((7, super::OperationFamily::Encrypt), retained);
    backend.last_init_family.insert(7, super::OperationFamily::Encrypt);
    let barrier = Arc::new(Barrier::new(4));
    for index in 0..3 {
        spawn_parked_worker(format!("stop-park-{index}"), barrier.clone());
    }
    barrier.wait();
    let _ = writeln!(std::io::stdout(), "READY s5-retained");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// S6 child: registry poisoned after activation; dirty owner still stops.
fn run_s6_poisoned() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    // Stale-poison path: the structural managed flag still scopes the guard.
    backend.construction.poison();
    let barrier = Arc::new(Barrier::new(4));
    for index in 0..3 {
        spawn_parked_worker(format!("stop-park-{index}"), barrier.clone());
    }
    barrier.wait();
    let _ = writeln!(std::io::stdout(), "READY s6-poisoned");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// S7 child: pending graph (initialized plus one open session, no close).
fn run_s7_pending() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    backend.lifecycle.note_session_opened();
    let barrier = Arc::new(Barrier::new(4));
    for index in 0..3 {
        spawn_parked_worker(format!("stop-park-{index}"), barrier.clone());
    }
    barrier.wait();
    let _ = writeln!(std::io::stdout(), "READY s7-pending");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// S8 child: stuck Finalize vs the shared controller deadline (200 ms grace
/// via parent env). The controller fires past the stuck call; a 5 s watchdog
/// exits 23 if it never does (fail-fast instead of hanging the parent).
fn run_s8_finalize_deadline() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_stuck));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    {
        let spawned = std::thread::Builder::new().name("stop-watchdog".to_owned()).spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(5));
            std::process::exit(23);
        });
        if spawned.is_err() {
            std::process::exit(17);
        }
    }
    let _ = writeln!(std::io::stdout(), "READY s8-finalize-deadline");
    let _ = std::io::stdout().flush();
    // Arms the shared controller with the 200 ms grace, then never returns:
    // the controller stops the group at 70. Any return means it did not fire.
    let _ = backend.finalize();
    std::process::exit(23);
}

/// S9 child: unknown entry (unresolved failed Finalize, re-init refused).
fn run_s9_unknown() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    // F-08: a failed Finalize can no longer turn the incarnation over — the
    // re-init is refused and the drop below stops from the unresolved
    // failed-Finalize state with retained evidence.
    backend.lifecycle.note_finalize_failed();
    let _ = backend.lifecycle.note_initialized();
    let barrier = Arc::new(Barrier::new(4));
    for index in 0..3 {
        spawn_parked_worker(format!("stop-park-{index}"), barrier.clone());
    }
    barrier.wait();
    let _ = writeln!(std::io::stdout(), "READY s9-unknown");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// S10 child: returned-but-unsettled (retained handle plus open count).
fn run_s10_unsettled() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    // The native call returned OK but settlement was withheld: the owner
    // stays retained in its family slot with the open count high.
    let mechanism = pkcs11_proxy_ng_types::CkMechanism {
        mechanism_type: pkcs11_proxy_ng_types::CkMechanismType::RSA_PKCS,
        params: None,
    };
    let retained = match super::ffi_conversion::mechanism_to_ffi(&mechanism) {
        Ok(retained) => retained,
        Err(_) => std::process::exit(22),
    };
    backend.mech_cache.insert((9, super::OperationFamily::Sign), retained);
    backend.last_init_family.insert(9, super::OperationFamily::Sign);
    backend.lifecycle.note_session_opened();
    let barrier = Arc::new(Barrier::new(4));
    for index in 0..3 {
        spawn_parked_worker(format!("stop-park-{index}"), barrier.clone());
    }
    barrier.wait();
    let _ = writeln!(std::io::stdout(), "READY s10-unsettled");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// S11 child: gated DONT_BLOCK waiter outstanding at drop (gate never opens).
fn run_s11_gated() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let entered = Arc::new(AtomicBool::new(false));
    {
        let flag = entered.clone();
        let spawned = std::thread::Builder::new().name("stop-gated".to_owned()).spawn(move || {
            flag.store(true, Ordering::SeqCst);
            // Gate never opens: parked until the group stop kills the waiter.
            loop {
                std::thread::park();
            }
        });
        if spawned.is_err() {
            std::process::exit(17);
        }
    }
    let barrier = Arc::new(Barrier::new(3));
    for index in 0..2 {
        spawn_parked_worker(format!("stop-park-{index}"), barrier.clone());
    }
    barrier.wait();
    wait_flag_5s(&entered);
    let _ = writeln!(std::io::stdout(), "READY s11-gated");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// Set by the S17 gated wait stub on native entry: the waiter holds a
/// genuine reservation plus ordinary admission inside C when the drop
/// fires (TO26b I1 — S11's parked thread holds neither).
static S17_ENTERED: AtomicBool = AtomicBool::new(false);

/// Never-returning wait stub for S17: signals native entry, then parks
/// forever holding the waiter's reservation and ordinary guard. Touches
/// only a process-static flag — no backend state after entry.
unsafe extern "C" fn child_wait_gated(
    _flags: cryptoki_sys::CK_FLAGS,
    _slot: *mut cryptoki_sys::CK_SLOT_ID,
    _reserved: *mut std::ffi::c_void,
) -> cryptoki_sys::CK_RV {
    S17_ENTERED.store(true, Ordering::SeqCst);
    loop {
        std::thread::park();
    }
}

/// S17 child: a GENUINE gated DONT_BLOCK waiter (real reservation, real
/// admission, parked inside native C) outstanding when the sole owner
/// drops — the group stops at 70. Main becomes the waiter; an
/// independent controller thread drops the sole `Box` owner once native
/// entry is proven. The waiter performs no backend access after parking
/// and main's drop stop-fires lock-free at its first statement
/// (initialized-never-finalized ⇒ Poison), so no access can recur before
/// `exit_group` ends every thread — the documented direct-embedder shape
/// (whole-process stop with borrowed-reference workers).
fn run_s17_genuine_waiter() -> ! {
    let backend =
        Box::new(child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok)));
    unsafe { (*backend.func_list).C_WaitForSlotEvent = Some(child_wait_gated) };
    let leaked: &'static FfiBackend = Box::leak(backend);
    if leaked.initialize().is_err() {
        std::process::exit(14);
    }
    {
        let spawned = std::thread::Builder::new().name("stop-controller".to_owned()).spawn(|| {
            wait_flag_5s(&S17_ENTERED);
            let _ = writeln!(std::io::stdout(), "READY s17-genuine-waiter");
            let _ = std::io::stdout().flush();
            let owned = unsafe { Box::from_raw(leaked as *const FfiBackend as *mut FfiBackend) };
            drop(owned);
            // Unreachable: the drop stops the group at 70.
            std::process::exit(20);
        });
        if spawned.is_err() {
            std::process::exit(17);
        }
    }
    let barrier = Arc::new(Barrier::new(3));
    for index in 0..2 {
        spawn_parked_worker(format!("stop-park-{index}"), barrier.clone());
    }
    barrier.wait();
    // Main becomes the genuine waiter. Never returns: the gate never opens.
    let _ = leaked.ffi_wait_for_slot_event(cryptoki_sys::CKF_DONT_BLOCK as u64);
    std::process::exit(21);
}

/// S12 child: failed Initialize (native entered, error RV) on a managed
/// backend, then drop. C3M steps 4-5: the attempt poisons, so the
/// final-owner guard stops the group at 70 instead of recycling.
fn run_s12_failed_init() -> ! {
    let backend = child_backend_managed(Some(child_initialize_fails), Some(child_finalize_ok));
    if backend.initialize().is_ok() {
        std::process::exit(24);
    }
    let barrier = Arc::new(Barrier::new(4));
    for index in 0..3 {
        spawn_parked_worker(format!("stop-park-{index}"), barrier.clone());
    }
    barrier.wait();
    let _ = writeln!(std::io::stdout(), "READY s12-failed-init");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// Set by the S13 stuck slot-list stub on native entry (worker is inside C
/// holding ordinary admission when main starts Finalize).
static S13_ENTERED: AtomicBool = AtomicBool::new(false);

/// Never-returning ordinary stub for S13: signals entry, then parks
/// forever holding the worker's ordinary guard (no locks held).
unsafe extern "C" fn child_slot_list_stuck(
    _token_present: cryptoki_sys::CK_BBOOL,
    _slots: *mut cryptoki_sys::CK_SLOT_ID,
    _count: *mut cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    S13_ENTERED.store(true, Ordering::SeqCst);
    loop {
        std::thread::park();
    }
}

/// S13 child: a stuck ordinary native call cannot block the independent
/// stop. The worker parks inside C holding its guard; main Finalizes with
/// the 200 ms grace (parent env) and the sealer suicides at the deadline
/// past the stuck call. A 5 s watchdog exits 23 if nothing fires.
fn run_s13_stuck_call() -> ! {
    let backend =
        Arc::new(child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok)));
    unsafe { (*backend.func_list).C_GetSlotList = Some(child_slot_list_stuck) };
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    {
        let spawned = std::thread::Builder::new().name("stop-watchdog".to_owned()).spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(5));
            std::process::exit(23);
        });
        if spawned.is_err() {
            std::process::exit(17);
        }
    }
    let barrier = Arc::new(Barrier::new(4));
    {
        let owned = backend.clone();
        let gate = barrier.clone();
        let spawned =
            std::thread::Builder::new().name("stop-stuck-call".to_owned()).spawn(move || {
                gate.wait();
                let _ = owned.ffi_get_slot_list(false);
                // The stuck call must never return.
                std::process::exit(21);
            });
        if spawned.is_err() {
            std::process::exit(17);
        }
    }
    for index in 0..2 {
        spawn_parked_worker(format!("stop-park-{index}"), barrier.clone());
    }
    barrier.wait();
    wait_flag_5s(&S13_ENTERED);
    let _ = writeln!(std::io::stdout(), "READY s13-stuck-call");
    let _ = std::io::stdout().flush();
    // The seal cannot drain the stuck reader: the 200 ms deadline stops
    // the group at 70. Any return means nothing fired.
    let _ = backend.finalize();
    std::process::exit(23);
}

/// Counts S14 Initialize entries: the first succeeds, every later one
/// fails natively (the failed re-Initialize after a clean Finalize).
static S14_INIT_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Succeed-once Initialize stub for S14 (proof invalidation).
unsafe extern "C" fn child_initialize_once_then_fails(
    _: *mut std::ffi::c_void,
) -> cryptoki_sys::CK_RV {
    if S14_INIT_CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
        cryptoki_sys::CKR_OK
    } else {
        cryptoki_sys::CKR_GENERAL_ERROR
    }
}

/// S14 child: init→finalize→failed re-init invalidates the destruction
/// proof — the drop stops the group at 70 instead of recycling the
/// reservation (TO26a proof-invalidation fix at stop level).
fn run_s14_proof_invalidated() -> ! {
    let backend =
        child_backend_managed(Some(child_initialize_once_then_fails), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    if backend.finalize().is_err() {
        std::process::exit(32);
    }
    if backend.initialize().is_ok() {
        std::process::exit(24);
    }
    let barrier = Arc::new(Barrier::new(4));
    for index in 0..3 {
        spawn_parked_worker(format!("stop-park-{index}"), barrier.clone());
    }
    barrier.wait();
    let _ = writeln!(std::io::stdout(), "READY s14-proof-invalidated");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// Counts S15 Finalize entries: exactly one native entry, error RV.
static S15_FINALIZE_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Failing Finalize stub for S15: native entered, error RV.
unsafe extern "C" fn child_finalize_fails(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
    S15_FINALIZE_CALLS.fetch_add(1, Ordering::SeqCst);
    cryptoki_sys::CKR_GENERAL_ERROR
}

/// S15 child: a native Finalize error (not a simulated marker) leaves the
/// incarnation uncertain with retained bindings, so the drop stops the
/// group at 70 instead of recycling.
fn run_s15_failed_finalize() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_fails));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    if backend.finalize().is_ok() {
        std::process::exit(25);
    }
    // TO26b Fidelity-M2: the failed Finalize entered native exactly
    // once — the uncertainty is observed, not simulated.
    if S15_FINALIZE_CALLS.load(Ordering::SeqCst) != 1 {
        std::process::exit(26);
    }
    let barrier = Arc::new(Barrier::new(4));
    for index in 0..3 {
        spawn_parked_worker(format!("stop-park-{index}"), barrier.clone());
    }
    barrier.wait();
    let _ = writeln!(std::io::stdout(), "READY s15-failed-finalize");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// S16 child: a returning SIGABRT handler is installed, proven functional
/// (raise → fires → returns), and still installed when the dirty-owner
/// drop stops the group at 70 — the handler neither diverts nor blocks
/// the stop. Reuses the M6 handler decls (separate process, no state
/// shared with the M6 control child).
fn run_s16_handler_installed() -> ! {
    let _ = unsafe { signal(M6_SIGABRT, Some(m6_sigabrt_handler)) };
    if unsafe { raise(M6_SIGABRT) } != 0 {
        std::process::exit(33);
    }
    if !M6_FIRED.load(Ordering::Relaxed) {
        std::process::exit(34);
    }
    M6_FIRED.store(false, Ordering::Relaxed);
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let barrier = Arc::new(Barrier::new(4));
    for index in 0..3 {
        spawn_parked_worker(format!("stop-park-{index}"), barrier.clone());
    }
    barrier.wait();
    let _ = writeln!(std::io::stdout(), "READY s16-handler-installed");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// Build an unmanaged backend (test-only sentinel, no registry reservation).
fn child_backend_unmanaged(
    initialize: cryptoki_sys::CK_C_Initialize,
    finalize: cryptoki_sys::CK_C_Finalize,
) -> FfiBackend {
    let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
    functions.C_Initialize = initialize;
    functions.C_Finalize = finalize;
    let func_list = Box::leak(functions) as *mut cryptoki_sys::CK_FUNCTION_LIST;
    FfiBackend {
        _lib: super::loading::test_library_handle(),
        func_list,
        func_list_3_0: None,
        func_list_3_2: None,
        initialize_args: None,
        mech_cache: dashmap::DashMap::new(),
        last_init_family: dashmap::DashMap::new(),
        session_slot_map: dashmap::DashMap::new(),
        slot_sessions: dashmap::DashMap::new(),
        object_cleanup: Default::default(),
        construction: super::native_domain::ConstructionPermit::unmanaged_test_only(),
        lifecycle: Default::default(),
        lifecycle_domain: Default::default(),
        session_fences: Default::default(),
        retirement_sentinel: super::native_domain::RetirementSentinel::unmanaged_test_only(),
    }
}

/// C1 child: never initialized, normal Drop (Release), exit 0, no stop.
fn run_c1_never_init() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    let _ = writeln!(std::io::stdout(), "READY c1-never-init");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(0);
}

/// C2 child: dirty lifecycle on an unmanaged permit, normal Drop, exit 0.
fn run_c2_unmanaged() -> ! {
    let backend = child_backend_unmanaged(Some(child_initialize_ok), Some(child_finalize_ok));
    // Poison-state lifecycle (initialized, no finalize) that must NOT stop:
    // the unmanaged sentinel holds no registry slot.
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let _ = writeln!(std::io::stdout(), "READY c2-unmanaged");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(0);
}

// N1 seccomp denial (Linux-only, no libc): classic-BPF `BPF_DENY` on
// `__NR_exit_group` via raw `prctl` (same arch cfg as the stop stubs).

#[cfg(target_os = "linux")]
#[repr(C)]
struct N1SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct N1SockFprog {
    len: u16,
    filter: *const N1SockFilter,
}

#[cfg(target_os = "linux")]
const N1_PR_SET_NO_NEW_PRIVS: usize = 38;
#[cfg(target_os = "linux")]
const N1_PR_SET_SECCOMP: usize = 22;
#[cfg(target_os = "linux")]
const N1_SECCOMP_MODE_FILTER: usize = 2;
#[cfg(target_os = "linux")]
const N1_SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
#[cfg(target_os = "linux")]
const N1_BPF_DENY: u32 = 0x0005_0000 | 1; // SECCOMP_RET_ERRNO | EPERM
#[cfg(target_os = "linux")]
const N1_BPF_LD_W_ABS: u16 = 0x20;
#[cfg(target_os = "linux")]
const N1_BPF_JMP_JEQ_K: u16 = 0x15;
#[cfg(target_os = "linux")]
const N1_BPF_RET_K: u16 = 0x06;

// Manual `prctl(2)` decl: no `libc` dev-dep needed (like the M3 `atexit`
// decl). Direct libc linkage means no `dlopen`, so N1 also works on
// static musl. Raw syscalls would need ESI/EDI on i686, which LLVM
// reserves for inline asm.
#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn prctl(option: std::ffi::c_int, ...) -> std::ffi::c_int;
}

/// Install `BPF_DENY` on `__NR_exit_group`; exits 15/16 when refused.
#[cfg(target_os = "linux")]
fn install_exit_group_errno_deny() {
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    let nr_exit_group: u32 = 231;
    #[cfg(all(target_arch = "x86", target_pointer_width = "32"))]
    let nr_exit_group: u32 = 252;
    #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
    let nr_exit_group: u32 = 94;
    #[cfg(not(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "x86", target_pointer_width = "32"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    )))]
    let nr_exit_group: u32 = 0;
    // `if (nr == exit_group) return BPF_DENY; return ALLOW;`
    let filter = [
        N1SockFilter { code: N1_BPF_LD_W_ABS, jt: 0, jf: 0, k: 0 },
        N1SockFilter { code: N1_BPF_JMP_JEQ_K, jt: 0, jf: 1, k: nr_exit_group },
        N1SockFilter { code: N1_BPF_RET_K, jt: 0, jf: 0, k: N1_BPF_DENY },
        N1SockFilter { code: N1_BPF_RET_K, jt: 0, jf: 0, k: N1_SECCOMP_RET_ALLOW },
    ];
    let prog = N1SockFprog { len: filter.len() as u16, filter: filter.as_ptr() };
    // SAFETY: libc `prctl` with C calling convention; the filter program
    // outlives the installing call (kernel copies it).
    let no_new_privs =
        unsafe { prctl(N1_PR_SET_NO_NEW_PRIVS as i32, 1usize, 0usize, 0usize, 0usize) };
    if no_new_privs != 0 {
        std::process::exit(15);
    }
    let prog_ptr = &prog as *const N1SockFprog as usize;
    let seccomp = unsafe {
        prctl(N1_PR_SET_SECCOMP as i32, N1_SECCOMP_MODE_FILTER, prog_ptr, 0usize, 0usize)
    };
    if seccomp != 0 {
        std::process::exit(16);
    }
}

/// N1 child: deny `exit_group`, then stop — must spin, never fall through.
#[cfg(target_os = "linux")]
fn run_n1_seccomp() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    install_exit_group_errno_deny();
    let _ = writeln!(std::io::stdout(), "READY n1-seccomp");
    let _ = std::io::stdout().flush();
    drop(backend);
    // Fallthrough: the denied stop returned (or Release) — parent kills.
    std::process::exit(99);
}

#[cfg(not(target_os = "linux"))]
fn run_n1_seccomp() -> ! {
    std::process::exit(16);
}

/// N1-worker child: the denied stop must spin (never fall through) from a
/// nonleader worker too — seccomp filters are per-thread, so the
/// worker-thread denial is its own case. Mirrors S2's handoff shape.
#[cfg(target_os = "linux")]
fn run_n1_worker() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    install_exit_group_errno_deny();
    let (tx, rx) = std::sync::mpsc::channel::<FfiBackend>();
    let main_parked = Arc::new(AtomicBool::new(false));
    {
        let flag = main_parked.clone();
        let spawned =
            std::thread::Builder::new().name("stop-worker-0".to_owned()).spawn(move || {
                let owner = match rx.recv() {
                    Ok(owner) => owner,
                    Err(_) => std::process::exit(18),
                };
                wait_flag_5s(&flag);
                let _ = writeln!(std::io::stdout(), "READY n1-worker");
                let _ = std::io::stdout().flush();
                drop(owner);
                // Fallthrough: the denied stop returned (or Release) — parent kills.
                std::process::exit(99);
            });
        if spawned.is_err() {
            std::process::exit(17);
        }
    }
    if tx.send(backend).is_err() {
        std::process::exit(18);
    }
    main_parked.store(true, Ordering::SeqCst);
    loop {
        std::thread::park();
    }
}

#[cfg(not(target_os = "linux"))]
fn run_n1_worker() -> ! {
    std::process::exit(16);
}

/// S1: main-thread stop with parked workers (minimal dirty).
#[test]
fn native_stop_s1_main_thread_stop() {
    let (child, _permit) = spawn_stop_child("s1-main");
    // `wait_with_output` reaps (no zombie) and drains pipes to EOF.
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s1-main");
}

/// S2: nonleader-worker stop with main parking (minimal dirty).
#[test]
fn native_stop_s2_nonleader_worker_stop() {
    let (child, _permit) = spawn_stop_child("s2-worker");
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s2-worker");
}

/// S3: two racing workers (minimal dirty).
#[test]
fn native_stop_s3_racing_workers_stop() {
    let (child, _permit) = spawn_stop_child("s3-race");
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s3-race");
}

/// S4a: stuck worker via join-timeout path (minimal dirty).
#[test]
fn native_stop_s4a_stuck_worker_join_timeout() {
    let (child, _permit) = spawn_stop_child("s4a-join-timeout");
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s4a-join-timeout");
}

/// S4b: leak-detached stuck worker plus brief settle (minimal dirty).
#[test]
fn native_stop_s4b_leak_detached_stuck_worker() {
    let (child, _permit) = spawn_stop_child("s4b-leak-detached");
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s4b-leak-detached");
}

/// S5: retained graph (Encrypt family slot occupied).
#[test]
fn native_stop_s5_retained_graph_stop() {
    let (child, _permit) = spawn_stop_child("s5-retained");
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s5-retained");
}

/// S6: poisoned registry with live dirty owner.
#[test]
fn native_stop_s6_poisoned_registry_stop() {
    let (child, _permit) = spawn_stop_child("s6-poisoned");
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s6-poisoned");
}

/// S7: pending graph (open session, no close).
#[test]
fn native_stop_s7_pending_graph_stop() {
    let (child, _permit) = spawn_stop_child("s7-pending");
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s7-pending");
}

/// S8: stuck Finalize vs controller deadline (shared controller).
#[test]
fn native_stop_s8_failed_finalize_controller_deadline() {
    let (child, _permit) = spawn_stop_child_with_env(
        "s8-finalize-deadline",
        &[("PKCS11_PROXY_NATIVE_STOP_GRACE_MS", "200")],
    );
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s8-finalize-deadline");
}

/// S9: unknown entry (unresolved failed Finalize; re-init refused, F-08).
#[test]
fn native_stop_s9_unknown_entry_stop() {
    let (child, _permit) = spawn_stop_child("s9-unknown");
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s9-unknown");
}

/// S10: returned-but-unsettled owner (retained handle, count high).
#[test]
fn native_stop_s10_returned_but_unsettled_stop() {
    let (child, _permit) = spawn_stop_child("s10-unsettled");
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s10-unsettled");
}

/// S11: gated DONT_BLOCK waiter outstanding at drop.
#[test]
fn native_stop_s11_gated_waiter_stop() {
    let (child, _permit) = spawn_stop_child("s11-gated");
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s11-gated");
}

/// S12: failed Initialize poisons (native entered) — the drop stops.
#[test]
fn native_stop_s12_failed_initialize_stop() {
    let (child, _permit) = spawn_stop_child("s12-failed-init");
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s12-failed-init");
}

/// S13: a stuck ordinary native call cannot block the independent stop —
/// the Finalize sealer suicides at the 200 ms grace past the stuck call.
#[test]
fn native_stop_s13_stuck_ordinary_call_deadline_stop() {
    let (child, _permit) = spawn_stop_child_with_env(
        "s13-stuck-call",
        &[("PKCS11_PROXY_NATIVE_STOP_GRACE_MS", "200")],
    );
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s13-stuck-call");
}

/// S14: init→finalize→failed re-init invalidates the proof — the drop
/// stops instead of recycling (stop-level proof of the TO26a fix).
#[test]
fn native_stop_s14_proof_invalidation_stop() {
    let (child, _permit) = spawn_stop_child("s14-proof-invalidated");
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s14-proof-invalidated");
}

/// S15: a native Finalize error (not simulated) leaves uncertainty — the
/// drop stops instead of recycling.
#[test]
fn native_stop_s15_failed_finalize_stop() {
    let (child, _permit) = spawn_stop_child("s15-failed-finalize");
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s15-failed-finalize");
}

/// S16: an installed, proven-functional returning SIGABRT handler neither
/// diverts nor blocks the stop — the group still exits 70.
#[test]
fn native_stop_s16_sigabrt_handler_installed_stop() {
    let (child, _permit) = spawn_stop_child("s16-handler-installed");
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s16-handler-installed");
}

/// S17 (TO26b I1): a GENUINE gated DONT_BLOCK waiter — real reservation,
/// real admission, parked inside native C (proven by native entry before
/// READY) — outstanding when the sole owner drops: the group exits 70.
/// This replaces S11's parked-thread analog as waiter coverage.
#[test]
fn native_stop_s17_genuine_waiter_stop() {
    let (child, _permit) = spawn_stop_child("s17-genuine-waiter");
    let output = child.wait_with_output().expect("reap stop child");
    assert_stop_status(&output, "s17-genuine-waiter");
}

/// C1: never-initialized control (normal Drop, child exit 0, no stop).
#[test]
fn native_stop_c1_never_initialized_normal_drop() {
    let (child, _permit) = spawn_stop_child("c1-never-init");
    let output = child.wait_with_output().expect("reap stop child");
    assert_control_status(&output, "c1-never-init");
}

/// C2: poisoned-unmanaged permit control (normal Drop, child exit 0).
#[test]
fn native_stop_c2_poisoned_unmanaged_normal_drop() {
    let (child, _permit) = spawn_stop_child("c2-unmanaged");
    let output = child.wait_with_output().expect("reap stop child");
    assert_control_status(&output, "c2-unmanaged");
}

/// Assert a seccomp-denied child spins (never falls through): the parent
/// observes 5 s of aliveness, then SIGKILLs (external-parent termination)
/// and reaps. Shared by the main-thread and worker-thread denials.
#[cfg(target_os = "linux")]
fn assert_denied_child_spins(scenario: &str) {
    let (mut child, _permit) = spawn_stop_child(scenario);
    // 5 s budget: the denied child must stay alive (spinning, not exiting).
    let start = std::time::Instant::now();
    let budget = std::time::Duration::from_secs(5);
    loop {
        match child.try_wait().expect("poll stop child") {
            None => {
                if start.elapsed() >= budget {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Some(status) => {
                panic!("{scenario}: child must NOT exit (fell through?), got {status:?}");
            }
        }
    }
    match child.try_wait().expect("confirm child alive") {
        None => {}
        Some(status) => {
            panic!("{scenario}: child exited during kill window, got {status:?}");
        }
    }
    child.kill().expect("SIGKILL denied child");
    let output = child.wait_with_output().expect("reap denied child");
    // 9 is SIGKILL: killed, never exited 70/0/99 (no fallthrough).
    assert_eq!(output.status.signal(), Some(9), "{scenario}: SIGKILL, got {:?}", output.status);
    assert_eq!(output.status.code(), None, "{scenario}: no exit code when killed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("READY"), "{scenario}: READY missing, stdout={stdout:?}");
}

/// N1: seccomp errno-denial on `exit_group` — child must NOT fall through.
/// Unsupported-environment: with `exit_group` denied (`BPF_DENY`), the stop
/// retry loop spins forever (never 70, never fallthrough exit 99); the parent
/// observes 5 s of aliveness, then SIGKILLs and reaps. Linux-only (seccomp).
#[cfg(target_os = "linux")]
#[test]
fn native_stop_n1_seccomp_errno_denial_unsupported_environment() {
    assert_denied_child_spins("n1-seccomp");
}

/// N1-worker: the same errno-denial from a nonleader worker — seccomp
/// filters are per-thread, so the worker-thread denial spins too (never
/// falls through to Drop), needing the same external-parent termination.
/// Linux-only (seccomp).
#[cfg(target_os = "linux")]
#[test]
fn native_stop_n1_worker_seccomp_errno_denial_unsupported_environment() {
    assert_denied_child_spins("n1-worker");
}

// STOP-C2 marker tests + positive controls (file-based).
//
// Each marker proves a cleanup did NOT run on the stop path (marker file
// ABSENT after a 70 stop); each positive control proves the marker mechanism
// works (marker PRESENT with expected bytes after a normal exit). The parent
// creates a fresh outcome dir per test (seeding count/order files with fresh
// values) and passes it via OUTCOME_ENV. Marker children never panic on
// setup: 30 = outcome dir missing/unusable, 31 = atexit registration
// refused, 32 = control finalize failed, 33 = raise failed, 34 = SIGABRT
// handler did not fire (11/12/13/14/20 reused from STOP-C1).
/// Marker scenario selector env var (STOP-C2 entry; separate from CHILD_ENV).
const MARKER_ENV: &str = "PKCS11_PROXY_NATIVE_STOP_MARKER";
/// Outcome dir env var: parent-seeded temp dir for marker files.
const OUTCOME_ENV: &str = "PKCS11_PROXY_NATIVE_STOP_OUTCOME_PATH";
/// Exact marker child entry test path within the lib test binary.
const MARKER_TEST_PATH: &str = "ffi::native_stop_tests::native_stop_marker_child_entry";

/// Per-process sequence so parallel parent tests get unique outcome dirs.
static OUTCOME_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Create a fresh outcome dir for `tag` (pid + sequence unique). The caller
/// removes it after asserting; removal failure is ignored.
fn fresh_outcome_dir(tag: &str) -> std::path::PathBuf {
    let seq = OUTCOME_SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("pkcs11-stop-{tag}-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create outcome dir");
    dir
}

/// Spawn the lib test binary as a marker child for `scenario` with `dir`.
fn spawn_marker_child(scenario: &str, dir: &std::path::Path) -> (Child, ChildPermit) {
    let permit = acquire_child_permit();
    let exe = std::env::current_exe().expect("current test exe");
    let mut cmd = Command::new(exe);
    cmd.arg("--exact")
        .arg(MARKER_TEST_PATH)
        .arg("--nocapture")
        .env(MARKER_ENV, scenario)
        .env(OUTCOME_ENV, dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().expect("spawn marker child");
    (child, permit)
}

/// Child-side outcome dir (exits 30 when missing or not a dir).
fn child_outcome_dir() -> std::path::PathBuf {
    let dir = std::env::var_os(OUTCOME_ENV).map(std::path::PathBuf::from).unwrap_or_default();
    if dir.as_os_str().is_empty() || !dir.is_dir() {
        std::process::exit(30);
    }
    dir
}

/// Assert `path` does not exist (cleanup did not run).
fn assert_marker_absent(path: &std::path::Path, scenario: &str) {
    assert!(!path.exists(), "scenario {scenario}: marker must be ABSENT, found {}", path.display());
}

/// Assert `path` holds exactly `expected` (control mechanism works).
fn assert_marker_bytes(path: &std::path::Path, expected: &[u8], scenario: &str) {
    let actual = std::fs::read(path)
        .unwrap_or_else(|_| panic!("scenario {scenario}: marker missing at {}", path.display()));
    assert_eq!(actual, expected, "scenario {scenario}: marker bytes");
}

/// Marker child entry: vacuously passes in-process; diverges in the child.
#[test]
fn native_stop_marker_child_entry() {
    let Ok(scenario) = std::env::var(MARKER_ENV) else {
        return;
    };
    run_marker_child(&scenario);
}

/// Marker child dispatch (never returns). Marker-child setup codes: 30
/// outcome dir missing/unusable, 31 atexit/on-exit registration refused,
/// 32 control finalize failed, 33 raise failed, 34 SIGABRT handler did
/// not fire, 35 unexpected provider-callback enrollment or session setup
/// failure (11/12/13/14/20 reused from STOP-C1).
fn run_marker_child(scenario: &str) -> ! {
    match scenario {
        "m1-drop-stop" => run_m1_drop_stop(),
        "m1-drop-control" => run_m1_drop_control(),
        "m2-hook-stop" => run_m2_hook_stop(),
        "m2-hook-control" => run_m2_hook_control(),
        "m3-atexit-stop" => run_m3_atexit_stop(),
        "m3-atexit-control" => run_m3_atexit_control(),
        "m4-elf-stop" => run_m4_elf_stop(),
        "m4-elf-control" => run_m4_elf_control(),
        "m5-finalize-stop" => run_m5_finalize_stop(),
        "m5-finalize-control" => run_m5_finalize_control(),
        "m6-sigabrt-control" => run_m6_sigabrt_control(),
        "m7-poisoned-domain-stop" => run_m7_poisoned_domain_stop(),
        "m7-poisoned-domain-control" => run_m7_poisoned_domain_control(),
        "m8-tls-stop" => run_m8_tls_stop(),
        "m8-tls-control" => run_m8_tls_control(),
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        "m9-onexit-stop" => run_m9_onexit_stop(),
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        "m9-onexit-control" => run_m9_onexit_control(),
        "m10-callback-stop" => run_m10_callback_stop(),
        "m10-callback-control" => run_m10_callback_control(),
        "m11-domain-stop" => run_m11_domain_stop(),
        "m11-domain-control" => run_m11_domain_control(),
        _ => std::process::exit(11),
    }
}

/// Expected bytes of the M1 Drop-sentinel marker.
const M1_BYTES: &[u8] = b"rust-drop-fired";

/// M1 sentinel: its `Drop` would write the marker. Lives in the child main
/// scope across the stop; the stop must preempt it.
struct M1Guard {
    path: std::path::PathBuf,
}

impl Drop for M1Guard {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.path, M1_BYTES);
    }
}

/// M1 stop child: Drop sentinel live across a dirty-owner drop (the stop).
fn run_m1_drop_stop() -> ! {
    let dir = child_outcome_dir();
    let sentinel = M1Guard { path: dir.join("rust_drop.marker") };
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let _ = writeln!(std::io::stdout(), "READY m1-drop-stop");
    let _ = std::io::stdout().flush();
    drop(backend);
    // The sentinel must still be alive here (stop preempted everything), but
    // reaching this line means the guard did not stop: fail loudly without
    // running the sentinel (forget it, then exit 20).
    std::mem::forget(sentinel);
    std::process::exit(20);
}

/// M1 control child: never-initialized backend + explicit sentinel drop.
fn run_m1_drop_control() -> ! {
    let dir = child_outcome_dir();
    let sentinel = M1Guard { path: dir.join("rust_drop.marker") };
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    let _ = writeln!(std::io::stdout(), "READY m1-drop-control");
    let _ = std::io::stdout().flush();
    drop(sentinel);
    drop(backend);
    std::process::exit(0);
}

/// M1: Rust Drop sentinel must NOT run when the stop fires.
#[test]
fn native_stop_m1_rust_drop_absent_on_stop() {
    let dir = fresh_outcome_dir("m1-stop");
    let (child, _permit) = spawn_marker_child("m1-drop-stop", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_stop_status(&output, "m1-drop-stop");
    assert_marker_absent(&dir.join("rust_drop.marker"), "m1-drop-stop");
    let _ = std::fs::remove_dir_all(&dir);
}

/// M1 positive control: normal exit runs the Drop sentinel.
#[test]
fn native_stop_m1_rust_drop_control_present() {
    let dir = fresh_outcome_dir("m1-control");
    let (child, _permit) = spawn_marker_child("m1-drop-control", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_control_status(&output, "m1-drop-control");
    assert_marker_bytes(&dir.join("rust_drop.marker"), b"rust-drop-fired", "m1-drop-control");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Expected bytes of the M2 panic-hook marker.
const M2_BYTES: &[u8] = b"panic-hook-fired";

/// Install the M2 panic hook: any panic writes the marker. The hook itself
/// never panics (write errors ignored).
fn install_m2_hook(dir: &std::path::Path) {
    let path = dir.join("panic_hook.marker");
    std::panic::set_hook(Box::new(move |_| {
        let _ = std::fs::write(&path, M2_BYTES);
    }));
}

/// M2 stop child: hook installed, then a dirty-owner drop (the stop). The
/// child must stop, never panic, so the hook never fires.
fn run_m2_hook_stop() -> ! {
    let dir = child_outcome_dir();
    install_m2_hook(&dir);
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let _ = writeln!(std::io::stdout(), "READY m2-hook-stop");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// M2 control child: hook installed, clean (never-initialized, quiescent)
/// backend on the stack, then panic. Unwinding drops the backend via the
/// normal Release path; the hook fires; the test binary exits 101.
fn run_m2_hook_control() -> ! {
    let dir = child_outcome_dir();
    install_m2_hook(&dir);
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    let _ = writeln!(std::io::stdout(), "READY m2-hook-control");
    let _ = std::io::stdout().flush();
    // Keep the clean backend alive across the panic so unwinding exercises
    // the real Release drop (never dirty: not initialized).
    let _held = &backend;
    panic!("m2 control panic");
}

/// M2: the panic hook must NOT run when the stop fires (the child stops, it
/// must not panic).
#[test]
fn native_stop_m2_panic_hook_absent_on_stop() {
    let dir = fresh_outcome_dir("m2-stop");
    let (child, _permit) = spawn_marker_child("m2-hook-stop", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_stop_status(&output, "m2-hook-stop");
    assert_marker_absent(&dir.join("panic_hook.marker"), "m2-hook-stop");
    let _ = std::fs::remove_dir_all(&dir);
}

/// M2 positive control: a panicking child with a clean backend fires the hook
/// (nonzero, non-70 exit) and the marker is present.
#[test]
fn native_stop_m2_panic_hook_control_present() {
    let dir = fresh_outcome_dir("m2-control");
    let (child, _permit) = spawn_marker_child("m2-hook-control", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    let code = output.status.code();
    assert!(
        code != Some(0) && code != Some(70),
        "scenario m2-hook-control: nonzero-non-70 panic exit, got {:?}",
        output.status
    );
    // Intended-path guard (C3M Task 4 m2 concern): READY proves the child
    // reached the deliberate post-construction panic, so the hook did not
    // merely fire on an earlier setup panic (as the musl `dlopen` panic did).
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("READY"),
        "scenario m2-hook-control: READY line missing, stdout={stdout:?}"
    );
    assert_marker_bytes(&dir.join("panic_hook.marker"), b"panic-hook-fired", "m2-hook-control");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Expected bytes of the M3 C-atexit marker.
const M3_BYTES: &[u8] = b"c-atexit-fired";

// Manual `atexit(3)` declaration: no `libc` dev-dep needed. The manual decl
// satisfies E0204 (primitive `c_int` return) and clippy, so the `libc`
// fallback was not taken.
unsafe extern "C" {
    fn atexit(callback: Option<unsafe extern "C" fn()>) -> std::ffi::c_int;
}

/// Outcome dir for the M3 atexit callback (C callbacks capture nothing).
static M3_OUTCOME: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// M3 atexit callback: writes the marker. Never panics.
unsafe extern "C" fn m3_atexit_callback() {
    if let Some(dir) = M3_OUTCOME.get() {
        let _ = std::fs::write(dir.join("c_atexit.marker"), M3_BYTES);
    }
}

/// Register the M3 atexit callback (exits 31 when libc refuses).
fn install_m3_atexit(dir: &std::path::Path) {
    let _ = M3_OUTCOME.set(dir.to_path_buf());
    let registered = unsafe { atexit(Some(m3_atexit_callback)) };
    if registered != 0 {
        std::process::exit(31);
    }
}

/// M3 stop child: atexit registered, then a dirty-owner drop (the stop).
/// `exit_group` preempts the atexit chain, so the marker stays absent.
fn run_m3_atexit_stop() -> ! {
    let dir = child_outcome_dir();
    install_m3_atexit(&dir);
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let _ = writeln!(std::io::stdout(), "READY m3-atexit-stop");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// M3 control child: atexit registered, then `process::exit(0)` — which runs
/// the atexit chain while skipping Rust drops — so the marker is present.
fn run_m3_atexit_control() -> ! {
    let dir = child_outcome_dir();
    install_m3_atexit(&dir);
    let _ = writeln!(std::io::stdout(), "READY m3-atexit-control");
    let _ = std::io::stdout().flush();
    std::process::exit(0);
}

/// M3: the C atexit handler must NOT run when the stop fires.
#[test]
fn native_stop_m3_c_atexit_absent_on_stop() {
    let dir = fresh_outcome_dir("m3-stop");
    let (child, _permit) = spawn_marker_child("m3-atexit-stop", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_stop_status(&output, "m3-atexit-stop");
    assert_marker_absent(&dir.join("c_atexit.marker"), "m3-atexit-stop");
    let _ = std::fs::remove_dir_all(&dir);
}

/// M3 positive control: `process::exit(0)` runs atexit (skipping Rust drops),
/// so the marker is present.
#[test]
fn native_stop_m3_c_atexit_control_present() {
    let dir = fresh_outcome_dir("m3-control");
    let (child, _permit) = spawn_marker_child("m3-atexit-control", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_control_status(&output, "m3-atexit-control");
    assert_marker_bytes(&dir.join("c_atexit.marker"), b"c-atexit-fired", "m3-atexit-control");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Expected bytes of the M4 subsumption marker.
const M4_BYTES: &[u8] = b"elf-unload-subsumed";

// M4 subsumption rationale (design fallback; reviewer rules). Primary-plan
// fixture check: `tests/ffi_oracles/retained_mechanisms` could gain a
// `.fini_array` entry with no new deps, but the stop child would have to
// `dlopen` a prebuilt cdylib found only via `PKCS11_PROXY_RETAINED_ORACLE_LIB`
// — which default `cargo test` runs do not build, so the existing harness
// SKIPs that leg with a notice (`retained_owner_contract_tests.rs:134-135`).
// A real DTOR marker would therefore skip instead of proving. Instead, ELF
// unload is subsumed by the Rust-Drop marker: the only `dlclose` path is
// `_lib: Library`'s `Drop` (`loading.rs`), and `exit_group` preempts all
// userspace drops (M1 proves none run), so no `dlclose` path can execute on
// the stop path. The guard below makes that structural claim concrete by
// owning a real `Library` handle across the stop.
struct M4ElfGuard {
    path: std::path::PathBuf,
    _lib: libloading::Library,
}

impl Drop for M4ElfGuard {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.path, M4_BYTES);
        // `_lib` drops (dlclose) right after this `drop` returns — on the
        // normal path only; the stop preempts both.
    }
}

/// M4 stop child: `Library`-owning guard live across a dirty-owner drop.
fn run_m4_elf_stop() -> ! {
    let dir = child_outcome_dir();
    let guard = M4ElfGuard {
        path: dir.join("elf_unload_subsumed.marker"),
        _lib: super::loading::test_library_handle(),
    };
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let _ = writeln!(std::io::stdout(), "READY m4-elf-stop");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::mem::forget(guard);
    std::process::exit(20);
}

/// M4 control child: never-initialized backend + explicit guard drop (marker
/// written, inner `Library` dropped), then a normal exit.
fn run_m4_elf_control() -> ! {
    let dir = child_outcome_dir();
    let guard = M4ElfGuard {
        path: dir.join("elf_unload_subsumed.marker"),
        _lib: super::loading::test_library_handle(),
    };
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    let _ = writeln!(std::io::stdout(), "READY m4-elf-control");
    let _ = std::io::stdout().flush();
    drop(guard);
    drop(backend);
    std::process::exit(0);
}

/// M4: ELF unload is subsumed by the Rust-Drop marker (design fallback): the
/// only `dlclose` path is `_lib: Library`'s `Drop`, and the stop preempts all
/// userspace drops — so no `dlclose` can execute. The guard below owns a real
/// `Library` handle across the stop; its marker must stay absent.
#[test]
fn native_stop_m4_elf_unload_absent_on_stop() {
    let dir = fresh_outcome_dir("m4-stop");
    let (child, _permit) = spawn_marker_child("m4-elf-stop", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_stop_status(&output, "m4-elf-stop");
    assert_marker_absent(&dir.join("elf_unload_subsumed.marker"), "m4-elf-stop");
    let _ = std::fs::remove_dir_all(&dir);
}

/// M4 positive control: normal exit runs the guard (and its inner `Library`
/// drop), so the marker is present.
#[test]
fn native_stop_m4_elf_unload_control_present() {
    let dir = fresh_outcome_dir("m4-control");
    let (child, _permit) = spawn_marker_child("m4-elf-control", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_control_status(&output, "m4-elf-control");
    assert_marker_bytes(
        &dir.join("elf_unload_subsumed.marker"),
        b"elf-unload-subsumed",
        "m4-elf-control",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Expected bytes of the M5 provider-Finalize marker.
const M5_BYTES: &[u8] = b"provider-finalized";

/// Outcome dir for the M5 Finalize stub (the C stub captures nothing).
static M5_OUTCOME: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Append `line` to the M5 order log (best-effort, never panics).
fn m5_append_order(dir: &std::path::Path, line: &[u8]) {
    if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(dir.join("capdrop.order")) {
        use std::io::Write as _;
        let _ = file.write_all(line);
    }
}

/// M5 provider Finalize stub: writes the marker, sets the counter to 1,
/// appends to the order log. Must never run on the stop path.
unsafe extern "C" fn m5_finalize_stub(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
    if let Some(dir) = M5_OUTCOME.get() {
        let _ = std::fs::write(dir.join("provider_finalize.marker"), M5_BYTES);
        let _ = std::fs::write(dir.join("finalize.count"), b"1");
        m5_append_order(dir, b"finalize\n");
    }
    cryptoki_sys::CKR_OK
}

/// M5 capability-drop guard: its `Drop` appends to the order log, standing in
/// for permit/field-drop cleanup that the stop must preempt.
struct M5CapGuard {
    dir: std::path::PathBuf,
}

impl Drop for M5CapGuard {
    fn drop(&mut self) {
        m5_append_order(&self.dir, b"guard\n");
    }
}

/// M5 stop child: cap guard live + Finalize stub armed across a dirty-owner
/// drop (the stop). Neither the stub nor any drop may run.
fn run_m5_finalize_stop() -> ! {
    let dir = child_outcome_dir();
    let _ = M5_OUTCOME.set(dir.clone());
    let guard = M5CapGuard { dir };
    let backend = child_backend_managed(Some(child_initialize_ok), Some(m5_finalize_stub));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let _ = writeln!(std::io::stdout(), "READY m5-finalize-stop");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::mem::forget(guard);
    std::process::exit(20);
}

/// M5 control child: explicit `finalize()` (stub runs: marker + counter +
/// order line), then the guard drop appends, then a normal backend drop
/// (Release: finalized) and exit 0.
fn run_m5_finalize_control() -> ! {
    let dir = child_outcome_dir();
    let _ = M5_OUTCOME.set(dir.clone());
    let guard = M5CapGuard { dir };
    let backend = child_backend_managed(Some(child_initialize_ok), Some(m5_finalize_stub));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    if backend.finalize().is_err() {
        std::process::exit(32);
    }
    let _ = writeln!(std::io::stdout(), "READY m5-finalize-control");
    let _ = std::io::stdout().flush();
    drop(guard);
    drop(backend);
    std::process::exit(0);
}

/// Seed the M5 fresh values: counter `0`, order log `fresh`.
fn seed_m5_fresh(dir: &std::path::Path) {
    std::fs::write(dir.join("finalize.count"), b"0").expect("seed count");
    std::fs::write(dir.join("capdrop.order"), b"fresh\n").expect("seed order");
}

/// M5: provider Finalize must NOT run on the stop path (counter stays 0,
/// marker absent), and no capability-drop cleanup may run either (the order
/// log stays byte-identical to its fresh seed — the stop preempts all drops,
/// first, per the design placement proof).
#[test]
fn native_stop_m5_provider_finalize_absent_on_stop() {
    let dir = fresh_outcome_dir("m5-stop");
    seed_m5_fresh(&dir);
    let (child, _permit) = spawn_marker_child("m5-finalize-stop", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_stop_status(&output, "m5-finalize-stop");
    assert_marker_absent(&dir.join("provider_finalize.marker"), "m5-finalize-stop");
    assert_marker_bytes(&dir.join("finalize.count"), b"0", "m5-finalize-stop");
    assert_marker_bytes(&dir.join("capdrop.order"), b"fresh\n", "m5-finalize-stop");
    let _ = std::fs::remove_dir_all(&dir);
}

/// M5 positive control: explicit `finalize()` runs the provider stub (marker
/// present, counter exactly 1), then the capability-drop guard appends —
/// proving the exact cleanup order `fresh, finalize, guard` on the normal path.
#[test]
fn native_stop_m5_provider_finalize_control_present() {
    let dir = fresh_outcome_dir("m5-control");
    seed_m5_fresh(&dir);
    let (child, _permit) = spawn_marker_child("m5-finalize-control", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_control_status(&output, "m5-finalize-control");
    assert_marker_bytes(
        &dir.join("provider_finalize.marker"),
        b"provider-finalized",
        "m5-finalize-control",
    );
    assert_marker_bytes(&dir.join("finalize.count"), b"1", "m5-finalize-control");
    assert_marker_bytes(
        &dir.join("capdrop.order"),
        b"fresh\nfinalize\nguard\n",
        "m5-finalize-control",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Expected bytes of the M6 SIGABRT-handler marker.
const M6_BYTES: &[u8] = b"sigabrt-handler-returned";

// Manual `signal(2)`/`raise(3)` decls: no `libc` dev-dep needed (same as the
// M3 `atexit` and N1 `prctl` decls).
unsafe extern "C" {
    fn signal(
        signum: std::ffi::c_int,
        handler: Option<unsafe extern "C" fn(std::ffi::c_int)>,
    ) -> Option<unsafe extern "C" fn(std::ffi::c_int)>;
    fn raise(sig: std::ffi::c_int) -> std::ffi::c_int;
}

/// SIGABRT number on Linux (both x86_64 and x86).
const M6_SIGABRT: std::ffi::c_int = 6;

/// Set by the M6 handler; its only side effect (async-signal-safe).
static M6_FIRED: AtomicBool = AtomicBool::new(false);

/// M6 SIGABRT handler: records firing, then returns (never panics/exits).
unsafe extern "C" fn m6_sigabrt_handler(_sig: std::ffi::c_int) {
    M6_FIRED.store(true, Ordering::Relaxed);
}

/// M6 control child: a returning SIGABRT handler (contract bullet "A
/// returning SIGABRT-handler control …" in
/// `doc/release/native-mechanism-ownership.md`). The marker proves the
/// handler ran and returned; the normal exit-0 wait record proves the
/// harness observes that as distinct from a real abort (signal death).
fn run_m6_sigabrt_control() -> ! {
    let dir = child_outcome_dir();
    // If `signal` failed, `raise` below kills the child with SIGABRT and the
    // parent's exit-0 assertion fails loudly; success needs no check here.
    let _ = unsafe { signal(M6_SIGABRT, Some(m6_sigabrt_handler)) };
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    let _ = writeln!(std::io::stdout(), "READY m6-sigabrt-control");
    // Read-only core-policy record (no sysctl changes, per the contract).
    if let Ok(pattern) = std::fs::read_to_string("/proc/sys/kernel/core_pattern") {
        let _ = writeln!(std::io::stdout(), "CORE_PATTERN {}", pattern.trim());
    }
    let _ = std::io::stdout().flush();
    if unsafe { raise(M6_SIGABRT) } != 0 {
        std::process::exit(33);
    }
    if !M6_FIRED.load(Ordering::Relaxed) {
        std::process::exit(34);
    }
    let _ = std::fs::write(dir.join("sigabrt_handler.marker"), M6_BYTES);
    drop(backend);
    std::process::exit(0);
}

/// M6 positive control: the returning handler fires (marker present) and the
/// child exits 0 with no signal/core — the wait-status channel distinguishes
/// "handler ran and returned" from abort-death.
#[test]
fn native_stop_m6_sigabrt_handler_control_present() {
    let dir = fresh_outcome_dir("m6-control");
    let (child, _permit) = spawn_marker_child("m6-sigabrt-control", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_control_status(&output, "m6-sigabrt-control");
    assert_marker_bytes(
        &dir.join("sigabrt_handler.marker"),
        b"sigabrt-handler-returned",
        "m6-sigabrt-control",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// M7 stop child: C3M-clean (initialized then finalized) backend whose
/// lifecycle DOMAIN is poisoned. The C3M retirement predicate says
/// Release, so only the TF01b Drop quiescence probe can stop the group:
/// the child must exit 70. Reaching past the drop means no stop fired —
/// fail loudly with exit 20 (never silently green).
fn run_m7_poisoned_domain_stop() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    if backend.finalize().is_err() {
        std::process::exit(32);
    }
    std::thread::scope(|scope| {
        let poisoned = scope.spawn(|| {
            backend
                .lifecycle_domain
                .hold_write_across_for_tests(|| panic!("intentional M7 domain poison"));
        });
        if poisoned.join().is_ok() {
            std::process::exit(24);
        }
    });
    let _ = writeln!(std::io::stdout(), "READY m7-poisoned-domain-stop");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// M7 control child: the same C3M-clean backend with a quiet domain — a
/// normal Release drop and exit 0.
fn run_m7_poisoned_domain_control() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    if backend.finalize().is_err() {
        std::process::exit(32);
    }
    let _ = writeln!(std::io::stdout(), "READY m7-poisoned-domain-control");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(0);
}

/// M7: dropping a backend whose lifecycle domain is poisoned stops the
/// group at 70 even though the C3M predicate says Release.
#[test]
fn native_stop_m7_poisoned_domain_drop_stops() {
    let dir = fresh_outcome_dir("m7-stop");
    let (child, _permit) = spawn_marker_child("m7-poisoned-domain-stop", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_stop_status(&output, "m7-poisoned-domain-stop");
    let _ = std::fs::remove_dir_all(&dir);
}

/// M7 positive control: the same C3M-clean backend with a quiet domain
/// drops normally (exit 0, no stop).
#[test]
fn native_stop_m7_poisoned_domain_drop_control_clean() {
    let dir = fresh_outcome_dir("m7-control");
    let (child, _permit) = spawn_marker_child("m7-poisoned-domain-control", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_control_status(&output, "m7-poisoned-domain-control");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Expected bytes of the M8 TLS-Drop marker.
const M8_BYTES: &[u8] = b"tls-drop-fired";

/// M8 TLS sentinel: its `Drop` would write the marker. Lives in
/// thread-local storage; the stop must preempt it with the thread.
struct M8TlsGuard {
    path: std::path::PathBuf,
}

impl Drop for M8TlsGuard {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.path, M8_BYTES);
    }
}

std::thread_local! {
    static M8_TLS: std::cell::RefCell<Option<M8TlsGuard>> =
        const { std::cell::RefCell::new(None) };
}

/// M8 stop child: TLS sentinel armed on the main thread across a
/// dirty-owner drop (the stop). Thread-local destructors never run.
fn run_m8_tls_stop() -> ! {
    let dir = child_outcome_dir();
    M8_TLS.with(|cell| {
        *cell.borrow_mut() = Some(M8TlsGuard { path: dir.join("tls_drop.marker") });
    });
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let _ = writeln!(std::io::stdout(), "READY m8-tls-stop");
    let _ = std::io::stdout().flush();
    drop(backend);
    // No stop fired: disarm without running the sentinel, then fail loudly.
    M8_TLS.with(|cell| std::mem::forget(cell.take()));
    std::process::exit(20);
}

/// M8 control child: a worker thread arms its own TLS sentinel and
/// returns — thread exit runs the destructor — proving the marker works;
/// the main backend drops normally (never initialized) and exits 0.
fn run_m8_tls_control() -> ! {
    let dir = child_outcome_dir();
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    std::thread::scope(|scope| {
        let path = dir.join("tls_drop.marker");
        let joined = scope
            .spawn(move || {
                M8_TLS.with(|cell| *cell.borrow_mut() = Some(M8TlsGuard { path }));
            })
            .join();
        if joined.is_err() {
            std::process::exit(17);
        }
    });
    let _ = writeln!(std::io::stdout(), "READY m8-tls-control");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(0);
}

/// M8: thread-local destructors must NOT run when the stop fires.
#[test]
fn native_stop_m8_tls_drop_absent_on_stop() {
    let dir = fresh_outcome_dir("m8-stop");
    let (child, _permit) = spawn_marker_child("m8-tls-stop", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_stop_status(&output, "m8-tls-stop");
    assert_marker_absent(&dir.join("tls_drop.marker"), "m8-tls-stop");
    let _ = std::fs::remove_dir_all(&dir);
}

/// M8 positive control: worker-thread exit runs the TLS sentinel.
#[test]
fn native_stop_m8_tls_drop_control_present() {
    let dir = fresh_outcome_dir("m8-control");
    let (child, _permit) = spawn_marker_child("m8-tls-control", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_control_status(&output, "m8-tls-control");
    assert_marker_bytes(&dir.join("tls_drop.marker"), b"tls-drop-fired", "m8-tls-control");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Expected bytes of the M9 `on_exit` marker.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const M9_BYTES: &[u8] = b"c-onexit-fired";

// Manual `on_exit(3)` declaration (glibc-only, hence the whole M9 family
// is `cfg(all(linux, gnu))` — "where available" per the battery): no
// `libc` dev-dep needed, same as the M3 `atexit` decl.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
unsafe extern "C" {
    fn on_exit(
        callback: Option<unsafe extern "C" fn(std::ffi::c_int, *mut std::ffi::c_void)>,
        arg: *mut std::ffi::c_void,
    ) -> std::ffi::c_int;
}

/// Outcome dir for the M9 `on_exit` callback (C callbacks capture nothing).
#[cfg(all(target_os = "linux", target_env = "gnu"))]
static M9_OUTCOME: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// M9 `on_exit` callback: writes the marker. Never panics.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
unsafe extern "C" fn m9_onexit_callback(_status: std::ffi::c_int, _arg: *mut std::ffi::c_void) {
    if let Some(dir) = M9_OUTCOME.get() {
        let _ = std::fs::write(dir.join("c_onexit.marker"), M9_BYTES);
    }
}

/// Register the M9 `on_exit` callback (exits 31 when libc refuses).
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn install_m9_onexit(dir: &std::path::Path) {
    let _ = M9_OUTCOME.set(dir.to_path_buf());
    let registered = unsafe { on_exit(Some(m9_onexit_callback), std::ptr::null_mut()) };
    if registered != 0 {
        std::process::exit(31);
    }
}

/// M9 stop child: `on_exit` registered, then a dirty-owner drop (the
/// stop). `exit_group` preempts the exit-handler chain.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn run_m9_onexit_stop() -> ! {
    let dir = child_outcome_dir();
    install_m9_onexit(&dir);
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let _ = writeln!(std::io::stdout(), "READY m9-onexit-stop");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// M9 control child: `on_exit` registered, then `process::exit(0)` —
/// which runs the exit chain — so the marker is present.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn run_m9_onexit_control() -> ! {
    let dir = child_outcome_dir();
    install_m9_onexit(&dir);
    let _ = writeln!(std::io::stdout(), "READY m9-onexit-control");
    let _ = std::io::stdout().flush();
    std::process::exit(0);
}

/// M9: the C `on_exit` handler must NOT run when the stop fires.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
fn native_stop_m9_c_onexit_absent_on_stop() {
    let dir = fresh_outcome_dir("m9-stop");
    let (child, _permit) = spawn_marker_child("m9-onexit-stop", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_stop_status(&output, "m9-onexit-stop");
    assert_marker_absent(&dir.join("c_onexit.marker"), "m9-onexit-stop");
    let _ = std::fs::remove_dir_all(&dir);
}

/// M9 positive control: `process::exit(0)` runs `on_exit`, so the marker
/// is present.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
fn native_stop_m9_c_onexit_control_present() {
    let dir = fresh_outcome_dir("m9-control");
    let (child, _permit) = spawn_marker_child("m9-onexit-control", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_control_status(&output, "m9-onexit-control");
    assert_marker_bytes(&dir.join("c_onexit.marker"), b"c-onexit-fired", "m9-onexit-control");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Expected bytes of the M10 provider-entry marker.
const M10_BYTES: &[u8] = b"provider-entry-ran";

/// Outcome dir for the M10 stubs (C stubs capture nothing).
static M10_OUTCOME: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// M10 Initialize stub: records the received callback enrollment — the
/// backend must pass no mutex callbacks (exit 35 if one is ever
/// enrolled) — and succeeds.
unsafe extern "C" fn m10_initialize_stub(args: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
    if !args.is_null() {
        let init = unsafe { &*(args as *const cryptoki_sys::CK_C_INITIALIZE_ARGS) };
        if init.CreateMutex.is_some()
            || init.DestroyMutex.is_some()
            || init.LockMutex.is_some()
            || init.UnlockMutex.is_some()
        {
            std::process::exit(35);
        }
    }
    cryptoki_sys::CKR_OK
}

/// M10 OpenSession stub: the backend must pass no Notify callback (exit
/// 35 if one is ever enrolled); opens session 41.
unsafe extern "C" fn m10_open_session_stub(
    _slot: cryptoki_sys::CK_SLOT_ID,
    _flags: cryptoki_sys::CK_FLAGS,
    _application: cryptoki_sys::CK_VOID_PTR,
    notify: cryptoki_sys::CK_NOTIFY,
    session: *mut cryptoki_sys::CK_SESSION_HANDLE,
) -> cryptoki_sys::CK_RV {
    if notify.is_some() {
        std::process::exit(35);
    }
    if !session.is_null() {
        unsafe { *session = 41 };
    }
    cryptoki_sys::CKR_OK
}

/// M10 CloseSession stub: writes the marker and sets the counter to 1.
/// Must never run on the stop path (no provider entry may run there).
unsafe extern "C" fn m10_close_session_stub(
    _session: cryptoki_sys::CK_SESSION_HANDLE,
) -> cryptoki_sys::CK_RV {
    if let Some(dir) = M10_OUTCOME.get() {
        let _ = std::fs::write(dir.join("provider_entry.marker"), M10_BYTES);
        let _ = std::fs::write(dir.join("close_session.count"), b"1");
    }
    cryptoki_sys::CKR_OK
}

/// Build a managed backend with the M10 callback-recording stubs.
fn child_backend_m10() -> FfiBackend {
    let backend = child_backend_managed(Some(m10_initialize_stub), Some(child_finalize_ok));
    unsafe { (*backend.func_list).C_OpenSession = Some(m10_open_session_stub) };
    unsafe { (*backend.func_list).C_CloseSession = Some(m10_close_session_stub) };
    backend
}

/// M10 stop child: init (no mutex callbacks enrolled) + open session (no
/// Notify enrolled, open count held high) across a dirty-owner drop (the
/// stop). No host callback exists to fire, and no provider entry
/// (CloseSession) may run on the stop path either.
fn run_m10_callback_stop() -> ! {
    let dir = child_outcome_dir();
    let _ = M10_OUTCOME.set(dir);
    let backend = child_backend_m10();
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let opened = backend.ffi_open_session(
        pkcs11_proxy_ng_types::CkSlotId(11),
        pkcs11_proxy_ng_types::CkSessionFlags(
            pkcs11_proxy_ng_types::CkSessionFlags::SERIAL_SESSION,
        ),
    );
    if opened.is_err() {
        std::process::exit(35);
    }
    let _ = writeln!(std::io::stdout(), "READY m10-callback-stop");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(20);
}

/// M10 control child: the same stubs, but the session is closed
/// explicitly (entry runs: marker + counter) before Finalize and the
/// normal backend drop — proving the marker mechanism works.
fn run_m10_callback_control() -> ! {
    let dir = child_outcome_dir();
    let _ = M10_OUTCOME.set(dir);
    let backend = child_backend_m10();
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let session = match backend.ffi_open_session(
        pkcs11_proxy_ng_types::CkSlotId(11),
        pkcs11_proxy_ng_types::CkSessionFlags(
            pkcs11_proxy_ng_types::CkSessionFlags::SERIAL_SESSION,
        ),
    ) {
        Ok(session) => session,
        Err(_) => std::process::exit(35),
    };
    if backend.ffi_close_session(session).is_err() {
        std::process::exit(35);
    }
    if backend.finalize().is_err() {
        std::process::exit(32);
    }
    let _ = writeln!(std::io::stdout(), "READY m10-callback-control");
    let _ = std::io::stdout().flush();
    drop(backend);
    std::process::exit(0);
}

/// Seed the M10 fresh value: close-session counter `0`.
fn seed_m10_fresh(dir: &std::path::Path) {
    std::fs::write(dir.join("close_session.count"), b"0").expect("seed count");
}

/// M10: no host callback is ever enrolled (the stubs exit 35 if one is),
/// and no provider entry (CloseSession) runs on the stop path (marker
/// absent, counter stays 0).
#[test]
fn native_stop_m10_callback_absent_on_stop() {
    let dir = fresh_outcome_dir("m10-stop");
    seed_m10_fresh(&dir);
    let (child, _permit) = spawn_marker_child("m10-callback-stop", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_stop_status(&output, "m10-callback-stop");
    assert_marker_absent(&dir.join("provider_entry.marker"), "m10-callback-stop");
    assert_marker_bytes(&dir.join("close_session.count"), b"0", "m10-callback-stop");
    let _ = std::fs::remove_dir_all(&dir);
}

/// M10 positive control: the explicit close runs the provider entry
/// (marker present, counter exactly 1), then Finalize + normal drop.
#[test]
fn native_stop_m10_callback_control_present() {
    let dir = fresh_outcome_dir("m10-control");
    seed_m10_fresh(&dir);
    let (child, _permit) = spawn_marker_child("m10-callback-control", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_control_status(&output, "m10-callback-control");
    assert_marker_bytes(
        &dir.join("provider_entry.marker"),
        b"provider-entry-ran",
        "m10-callback-control",
    );
    assert_marker_bytes(&dir.join("close_session.count"), b"1", "m10-callback-control");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Expected bytes of the M11 domain-holder marker.
const M11_BYTES: &[u8] = b"domain-drop-fired";

/// M11 guard: its `Drop` would write the marker. Held in the same
/// enclosing scope as the backend — domain-owned storage drops only on
/// the normal path; the stop preempts it with everything else.
struct M11Guard {
    path: std::path::PathBuf,
}

impl Drop for M11Guard {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.path, M11_BYTES);
    }
}

/// Enclosing domain holder: field order drops the backend first (the
/// stop fires there) and the domain guard second (preempted on stop,
/// runs on the normal path).
struct M11DomainHolder {
    backend: FfiBackend,
    guard: M11Guard,
}

/// M11 stop child: the holder owns an initialized backend; dropping the
/// holder stops at the backend before the domain guard can drop.
fn run_m11_domain_stop() -> ! {
    let dir = child_outcome_dir();
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    let holder =
        M11DomainHolder { backend, guard: M11Guard { path: dir.join("domain_drop.marker") } };
    assert!(
        matches!(
            holder.backend.lifecycle.retirement_decision(),
            super::native_domain::RetirementDecision::Poison
        ),
        "M11 stop child must drop for the Poison reason"
    );
    assert!(!holder.guard.path.exists(), "M11 marker starts absent");
    let _ = writeln!(std::io::stdout(), "READY m11-domain-stop");
    let _ = std::io::stdout().flush();
    drop(holder);
    std::process::exit(20);
}

/// M11 control child: the holder owns a never-initialized backend, so
/// both drops run normally and the marker is present.
fn run_m11_domain_control() -> ! {
    let dir = child_outcome_dir();
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    let holder =
        M11DomainHolder { backend, guard: M11Guard { path: dir.join("domain_drop.marker") } };
    assert!(
        matches!(
            holder.backend.lifecycle.retirement_decision(),
            super::native_domain::RetirementDecision::Release
        ),
        "M11 control child must drop for the Release reason"
    );
    assert!(!holder.guard.path.exists(), "M11 marker starts absent");
    let _ = writeln!(std::io::stdout(), "READY m11-domain-control");
    let _ = std::io::stdout().flush();
    drop(holder);
    std::process::exit(0);
}

/// M11: domain-enclosing drops must NOT run when the stop fires.
#[test]
fn native_stop_m11_domain_drop_absent_on_stop() {
    let dir = fresh_outcome_dir("m11-stop");
    let (child, _permit) = spawn_marker_child("m11-domain-stop", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_stop_status(&output, "m11-domain-stop");
    assert_marker_absent(&dir.join("domain_drop.marker"), "m11-domain-stop");
    let _ = std::fs::remove_dir_all(&dir);
}

/// M11 positive control: the normal path drops the domain guard.
#[test]
fn native_stop_m11_domain_drop_control_present() {
    let dir = fresh_outcome_dir("m11-control");
    let (child, _permit) = spawn_marker_child("m11-domain-control", &dir);
    let output = child.wait_with_output().expect("reap marker child");
    assert_control_status(&output, "m11-domain-control");
    assert_marker_bytes(
        &dir.join("domain_drop.marker"),
        b"domain-drop-fired",
        "m11-domain-control",
    );
    let _ = std::fs::remove_dir_all(&dir);
}
