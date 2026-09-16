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
/// worker completion, 22 mech failed, 23 controller did not fire, 99 fell
/// through the denied stop).
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
        "c1-never-init" => run_c1_never_init(),
        "c2-unmanaged" => run_c2_unmanaged(),
        "n1-seccomp" => run_n1_seccomp(),
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
        construction: permit,
        lifecycle: Default::default(),
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

/// S9 child: unknown entry (stale generation: failed Finalize, re-init).
fn run_s9_unknown() -> ! {
    let backend = child_backend_managed(Some(child_initialize_ok), Some(child_finalize_ok));
    if backend.initialize().is_err() {
        std::process::exit(14);
    }
    // Dead-incarnation turnover: the new cycle is still dirty (no finalize).
    backend.lifecycle.note_finalize_failed();
    backend.lifecycle.note_initialized();
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

/// Install `BPF_DENY` on `__NR_exit_group`; exits 15/16 when refused.
///
/// Uses the already-loaded libc `prctl` via the self handle (no new
/// dependency: `libloading` is already a backend dependency). Raw syscalls
/// would need ESI/EDI on i686, which LLVM reserves for inline asm.
#[cfg(target_os = "linux")]
fn install_exit_group_errno_deny() {
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    let nr_exit_group: u32 = 231;
    #[cfg(all(target_arch = "x86", target_pointer_width = "32"))]
    let nr_exit_group: u32 = 252;
    #[cfg(not(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "x86", target_pointer_width = "32")
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
    let lib = libloading::os::unix::Library::this().into();
    let lib: libloading::Library = lib;
    type PrctlFn = unsafe extern "C" fn(i32, ...) -> i32;
    let prctl = match unsafe { lib.get::<PrctlFn>(b"prctl") } {
        Ok(prctl) => prctl,
        Err(_) => std::process::exit(15),
    };
    // SAFETY: resolved libc `prctl` with C calling convention; the filter
    // program outlives the installing call (kernel copies it).
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

/// S9: unknown entry (stale generation after failed Finalize + re-init).
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

/// N1: seccomp errno-denial on `exit_group` — child must NOT fall through.
/// Unsupported-environment: with `exit_group` denied (`BPF_DENY`), the stop
/// retry loop spins forever (never 70, never fallthrough exit 99); the parent
/// observes 5 s of aliveness, then SIGKILLs and reaps. Linux-only (seccomp).
#[cfg(target_os = "linux")]
#[test]
fn native_stop_n1_seccomp_errno_denial_unsupported_environment() {
    let (mut child, _permit) = spawn_stop_child("n1-seccomp");
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
                panic!("n1-seccomp: child must NOT exit (fell through?), got {status:?}");
            }
        }
    }
    match child.try_wait().expect("confirm child alive") {
        None => {}
        Some(status) => {
            panic!("n1-seccomp: child exited during kill window, got {status:?}");
        }
    }
    child.kill().expect("SIGKILL denied child");
    let output = child.wait_with_output().expect("reap denied child");
    // 9 is SIGKILL: killed, never exited 70/0/99 (no fallthrough).
    assert_eq!(output.status.signal(), Some(9), "n1-seccomp: SIGKILL, got {:?}", output.status);
    assert_eq!(output.status.code(), None, "n1-seccomp: no exit code when killed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("READY"), "n1-seccomp: READY missing, stdout={stdout:?}");
}
