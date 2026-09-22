//! T10 parent-watched shutdown-lifetime child tests.
//!
//! Each scenario runs the REAL [`coordinate_shutdown`] in a CHILD process
//! (re-spawned test binary, selected by `SHUTDOWN_LIFETIME_SCENARIO`),
//! so wedged writers/workers and abnormal stops stay child-contained:
//! no immortal blocking task ever strands the test runner. The parent
//! asserts the EXACT exit status plus marker files/pipes, with a bounded
//! wait that kills a hung child.
//!
//! Scenarios `wedge_audit`, `wedge_native_call`, `wedge_native_finalize`
//! and `failed_finalize_ffi` need hook builds:
//! `cargo test -p pkcs11-proxy-ng --features native-owner-test-hooks
//! --test shutdown_lifetime_test`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pkcs11_proxy_ng::config::AuditConfig;
use pkcs11_proxy_ng::server::audit::{AuditShutdown, AuditSink, spawn_managed_audit_sink};
use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::handle_map::BackendHandle;
use pkcs11_proxy_ng::server::shutdown::{
    SHUTDOWN_RUNTIME_TIMEOUT, ServeFuture, ShutdownError, ShutdownReason, coordinate_shutdown,
    listener_shutdown, spawn_eviction_task,
};
use pkcs11_proxy_ng::server::slot_map::BackendSlotId;
use pkcs11_proxy_ng_audit::{AUDIT_SCHEMA_VERSION, AuditRecord, EventClass};
use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
use pkcs11_proxy_ng_types::{CkRv, CkSlotId};

const SCENARIO_ENV: &str = "SHUTDOWN_LIFETIME_SCENARIO";
const MARKER_ENV: &str = "SHUTDOWN_LIFETIME_MARKERS";

/// Parent-side bound per child (covers the 10s runtime tail with margin).
const PARENT_BACKSTOP: Duration = Duration::from_secs(60);

fn marker_dir() -> PathBuf {
    PathBuf::from(std::env::var(MARKER_ENV).expect("child needs marker dir"))
}

fn write_marker(dir: &Path, name: &str, body: &str) {
    std::fs::write(dir.join(name), body).expect("marker write");
}

#[cfg(feature = "native-owner-test-hooks")]
fn await_file(path: PathBuf, bound: Duration) {
    let start = Instant::now();
    while !path.exists() {
        assert!(start.elapsed() < bound, "timed out awaiting {}", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Fake listener: drains (Ok) once shutdown is published.
fn fake_listener(rx: tokio::sync::watch::Receiver<Option<ShutdownReason>>) -> ServeFuture {
    Box::pin(async move {
        listener_shutdown(rx).await;
        Ok(())
    })
}

fn build_child_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("child runtime")
}

fn exit_code_of(outcome: Result<(), ShutdownError>) -> i32 {
    match outcome {
        Ok(()) => 0,
        Err(ShutdownError::Startup(_)) => 1,
        Err(ShutdownError::Finalize(_)) => 1,
        Err(ShutdownError::Coordinator(_)) => 2,
    }
}

/// Child entry: re-spawned test binary with `SHUTDOWN_LIFETIME_SCENARIO`
/// set. Diverges (process exit or raw stop); returns immediately in the
/// parent run. Never panics on setup failure — distinct exit codes.
#[test]
fn shutdown_lifetime_child_entry() {
    let Ok(scenario) = std::env::var(SCENARIO_ENV) else {
        return;
    };
    run_child_scenario(&scenario)
}

#[allow(clippy::too_many_lines)]
fn run_child_scenario(scenario: &str) -> ! {
    match scenario {
        "normal" => run_normal(),
        "wedge_eviction" => run_wedge_eviction(),
        "wedge_mock_finalize" => run_wedge_mock_finalize(),
        "failed_finalize_mock" => run_failed_finalize_mock(),
        "stuck_trip" => run_stuck_trip(),
        #[cfg(feature = "native-owner-test-hooks")]
        "wedge_audit" => run_wedge_audit(),
        #[cfg(feature = "native-owner-test-hooks")]
        "wedge_native_call" => run_wedge_native_call(),
        #[cfg(feature = "native-owner-test-hooks")]
        "wedge_native_finalize" => run_wedge_native_finalize(),
        #[cfg(feature = "native-owner-test-hooks")]
        "failed_finalize_ffi" => run_failed_finalize_ffi(),
        #[cfg(feature = "native-owner-test-hooks")]
        "wedge_eviction_ffi" => run_wedge_eviction_ffi(),
        _ => {
            // Child-entry diagnostic before any tracing exists; the exit
            // code (not the text) is the parent-visible signal.
            #[allow(clippy::print_stderr)]
            {
                eprintln!("unknown shutdown-lifetime scenario: {scenario}");
            }
            std::process::exit(11);
        }
    }
}

// ---------------------------------------------------------------------------
// Shared child drivers
// ---------------------------------------------------------------------------

/// Drive the real coordinator with a mock backend, fake draining
/// listener, real eviction task and optional managed audit sink.
/// `signal_after` delays the shutdown reason; returns the coordinator
/// outcome (caller maps to an exit code).
#[allow(clippy::too_many_arguments)]
async fn drive_mock_shutdown(
    backend: Arc<MockBackend>,
    audit: Option<(AuditSink, AuditShutdown)>,
    ctx_mgr: Arc<ContextManager>,
    eviction_interval: Duration,
    max_stuck: Option<u64>,
    signal_after: Duration,
    grace: Duration,
) -> Result<(), ShutdownError> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(None::<ShutdownReason>);
    let serve = fake_listener(shutdown_rx.clone());
    let signal = listener_shutdown(shutdown_rx);
    let eviction = spawn_eviction_task(
        ctx_mgr,
        backend.clone(),
        eviction_interval,
        1024,
        64,
        max_stuck,
        shutdown_tx.clone(),
    );
    tokio::spawn(async move {
        tokio::time::sleep(signal_after).await;
        shutdown_tx.send_modify(|reason| {
            if reason.is_none() {
                *reason = Some(ShutdownReason::Signal);
            }
        });
    });
    let backend_dyn: Arc<dyn Pkcs11Backend> = backend;
    coordinate_shutdown(vec![serve], signal, (), eviction, audit, backend_dyn, None, grace).await
}

fn test_audit_config(dir: PathBuf, with_signer: bool) -> AuditConfig {
    let signing_key = if with_signer {
        let seed = [0x5Au8; 32];
        let key_path = dir.join("signing.key");
        std::fs::write(&key_path, seed).expect("seed write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .expect("seed perms");
        }
        Some(key_path)
    } else {
        None
    };
    AuditConfig {
        dir: Some(dir),
        signing_key,
        rotate_max_bytes: 64 * 1024,
        rotate_keep_files: 10,
        ..Default::default()
    }
}

fn test_record() -> AuditRecord {
    AuditRecord {
        schema_version: AUDIT_SCHEMA_VERSION,
        seq: 0,
        ts_unix_ms: 1,
        ts_monotonic_ns: 1,
        prev_hash: String::new(),
        request_id: "shutdown-test".into(),
        identity: None,
        method: "C_Sign".into(),
        class: EventClass::KeyMgmt,
        slot: None,
        session: None,
        object_ref: None,
        ck_rv: 0,
        latency_us: 0,
        dropped_count: None,
    }
}

fn count_checkpoint_lines(audit_dir: &Path) -> usize {
    let path = audit_dir.join("audit.checkpoints.jsonl");
    match std::fs::read_to_string(&path) {
        Ok(body) => body.lines().count(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => panic!("checkpoint read failed: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Mock scenarios (default builds)
// ---------------------------------------------------------------------------

/// `normal`: orderly shutdown flushes audit exactly once (one
/// checkpoint), finalizes the backend exactly once, and exits 0
/// promptly (proving the timer-abort + writer-join + runtime ordering).
fn run_normal() -> ! {
    let markers = marker_dir();
    let audit_dir = markers.join("audit");
    std::fs::create_dir_all(&audit_dir).expect("audit dir");
    let runtime = build_child_runtime();
    // The sink spawn needs a runtime context (spawns writer + timer).
    let managed = {
        let _guard = runtime.enter();
        spawn_managed_audit_sink(&test_audit_config(audit_dir.clone(), true))
            .expect("sink")
            .expect("sink some")
    };

    let backend = Arc::new(MockBackend::default_test());
    backend.initialize().expect("init");
    let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
    let code = runtime.block_on(async {
        // One record so the flush seals exactly one checkpoint.
        assert!(matches!(
            managed.sink.emit(test_record()),
            pkcs11_proxy_ng::server::audit::EmitOutcome::Queued
        ));
        let audit = Some((managed.sink, managed.shutdown));
        let outcome = drive_mock_shutdown(
            backend.clone(),
            audit,
            ctx_mgr,
            Duration::from_secs(3600),
            None,
            Duration::from_millis(100),
            Duration::from_secs(5),
        )
        .await;
        write_marker(&markers, "finalize_calls", &backend.finalize_call_count().to_string());
        write_marker(&markers, "checkpoints", &count_checkpoint_lines(&audit_dir).to_string());
        exit_code_of(outcome)
    });
    runtime.shutdown_timeout(SHUTDOWN_RUNTIME_TIMEOUT);
    std::process::exit(code)
}

/// `wedge_eviction`: a teardown call parked past the remaining budget.
/// The join expires and the coordinator proceeds; phase 4 then finds
/// an exhausted budget. The mock finalize is ALSO parked so the
/// phase-4 timeout wins deterministically (an instant finalize would
/// race the ~0 remaining budget) → exit 2. Exactly one close attempt
/// proves the wedged tick started with no runaway re-ticking. (The
/// natively-stuck eviction case is `wedge_eviction_ffi`: same join
/// expiry, then the qualified phase-4 wait ends 70 instead of 2.)
fn run_wedge_eviction() -> ! {
    let markers = marker_dir();
    let backend = Arc::new(MockBackend::default_test());
    backend.initialize().expect("init");
    backend.set_close_session_delay(Duration::from_secs(8));
    // Pin the phase-4 outcome: with the join expired, remaining is
    // scheduling jitter (~0ms), so only a parked finalize makes the
    // timeout (→ exit 2) deterministic.
    backend.inject_finalize_park(true);
    let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));

    let runtime = build_child_runtime();
    let code = runtime.block_on(async {
        // One long-expired context holding a backend session: the first
        // tick's teardown parks in the delayed close.
        let ctx_id = ctx_mgr.create_context(None).await.expect("ctx");
        ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(BackendHandle(7), BackendSlotId(CkSlotId(0)));
                ctx.last_active = Instant::now() - Duration::from_secs(3600);
            })
            .await
            .expect("setup");
        let outcome = drive_mock_shutdown(
            backend.clone(),
            None,
            ctx_mgr,
            Duration::from_millis(50),
            None,
            Duration::from_millis(100),
            Duration::from_secs(2),
        )
        .await;
        // No finalize_calls marker: the phase-4 worker is detached by
        // the exhausted-budget timeout and may or may not run before
        // exit (both are the designed timeout path).
        write_marker(&markers, "close_calls", &backend.close_session_call_count().to_string());
        exit_code_of(outcome)
    });
    runtime.shutdown_timeout(SHUTDOWN_RUNTIME_TIMEOUT);
    std::process::exit(code)
}

/// `wedge_mock_finalize`: parked mock finalize past the remaining
/// budget → phase-4 timeout → coordinator error → exit 2. The parked
/// worker is leaked at runtime shutdown (this scenario proves the
/// leak-then-exit path on the orderly side).
fn run_wedge_mock_finalize() -> ! {
    let markers = marker_dir();
    let backend = Arc::new(MockBackend::default_test());
    backend.initialize().expect("init");
    backend.inject_finalize_park(true);
    let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));

    let runtime = build_child_runtime();
    let code = runtime.block_on(async {
        let outcome = drive_mock_shutdown(
            backend.clone(),
            None,
            ctx_mgr,
            Duration::from_secs(3600),
            None,
            Duration::from_millis(100),
            Duration::from_secs(1),
        )
        .await;
        // finalize entered (then parked): exactly one attempt, no retry.
        write_marker(&markers, "finalize_calls", &backend.finalize_call_count().to_string());
        exit_code_of(outcome)
    });
    // The parked worker outlives this: shutdown_timeout expires, leaks
    // it, and the process exits 2.
    runtime.shutdown_timeout(SHUTDOWN_RUNTIME_TIMEOUT);
    std::process::exit(code)
}

/// `failed_finalize_mock`: scripted provider finalize error, no native
/// uncertainty → exit 1, promptly.
fn run_failed_finalize_mock() -> ! {
    let markers = marker_dir();
    let backend = Arc::new(MockBackend::default_test());
    backend.initialize().expect("init");
    backend.set_next_finalize_outcome(Err(CkRv::DEVICE_ERROR));
    let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));

    let runtime = build_child_runtime();
    let code = runtime.block_on(async {
        let outcome = drive_mock_shutdown(
            backend.clone(),
            None,
            ctx_mgr,
            Duration::from_secs(3600),
            None,
            Duration::from_millis(100),
            Duration::from_secs(5),
        )
        .await;
        write_marker(&markers, "finalize_calls", &backend.finalize_call_count().to_string());
        exit_code_of(outcome)
    });
    runtime.shutdown_timeout(SHUTDOWN_RUNTIME_TIMEOUT);
    std::process::exit(code)
}

/// `stuck_trip`: one expired context with a delayed close; the 5s
/// teardown timeout bumps the stuck gauge, `max_stuck = 0` trips, and
/// the coordinator shuts down through the lifecycle (no direct exit) →
/// exit 0 once settled.
fn run_stuck_trip() -> ! {
    let markers = marker_dir();
    let backend = Arc::new(MockBackend::default_test());
    backend.initialize().expect("init");
    backend.set_close_session_delay(Duration::from_secs(8));
    let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));

    let runtime = build_child_runtime();
    let code = runtime.block_on(async {
        let ctx_id = ctx_mgr.create_context(None).await.expect("ctx");
        ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(BackendHandle(9), BackendSlotId(CkSlotId(0)));
                ctx.last_active = Instant::now() - Duration::from_secs(3600);
            })
            .await
            .expect("setup");
        // No test signal: the trip itself must request shutdown, so the
        // signal future stays pending and the 20s grace only backstops.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(None::<ShutdownReason>);
        let serve = fake_listener(shutdown_rx.clone());
        let signal = listener_shutdown(shutdown_rx);
        let eviction = spawn_eviction_task(
            ctx_mgr,
            backend.clone(),
            Duration::from_millis(100),
            1024,
            64,
            Some(0),
            shutdown_tx,
        );
        let backend_dyn: Arc<dyn Pkcs11Backend> = backend.clone();
        let outcome = coordinate_shutdown(
            vec![serve],
            signal,
            (),
            eviction,
            None,
            backend_dyn,
            None,
            Duration::from_secs(20),
        )
        .await;
        write_marker(&markers, "finalize_calls", &backend.finalize_call_count().to_string());
        write_marker(&markers, "close_calls", &backend.close_session_call_count().to_string());
        exit_code_of(outcome)
    });
    runtime.shutdown_timeout(SHUTDOWN_RUNTIME_TIMEOUT);
    std::process::exit(code)
}

// ---------------------------------------------------------------------------
// Hook-build scenarios (audit wedge + FFI fixtures)
// ---------------------------------------------------------------------------

/// `wedge_audit`: writer parked on flush. The flush times out (logged),
/// finalize still runs exactly once, exit 0 — bounded, with no
/// checkpoint written by the parked flush.
#[cfg(feature = "native-owner-test-hooks")]
fn run_wedge_audit() -> ! {
    let markers = marker_dir();
    let audit_dir = markers.join("audit");
    std::fs::create_dir_all(&audit_dir).expect("audit dir");
    let runtime = build_child_runtime();
    // The sink spawn needs a runtime context (spawns writer + timer).
    let managed = {
        let _guard = runtime.enter();
        spawn_managed_audit_sink(&test_audit_config(audit_dir.clone(), true))
            .expect("sink")
            .expect("sink some")
    };

    let backend = Arc::new(MockBackend::default_test());
    backend.initialize().expect("init");
    let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
    let code = runtime.block_on(async {
        assert!(matches!(
            managed.sink.emit(test_record()),
            pkcs11_proxy_ng::server::audit::EmitOutcome::Queued
        ));
        // Arm the park AFTER the record is queued: the coordinator's
        // flush is the wedged one.
        managed.sink.arm_flush_park_for_test().await;
        let audit = Some((managed.sink, managed.shutdown));
        let outcome = drive_mock_shutdown(
            backend.clone(),
            audit,
            ctx_mgr,
            Duration::from_secs(3600),
            None,
            Duration::from_millis(100),
            Duration::from_secs(2),
        )
        .await;
        write_marker(&markers, "finalize_calls", &backend.finalize_call_count().to_string());
        write_marker(&markers, "checkpoints", &count_checkpoint_lines(&audit_dir).to_string());
        exit_code_of(outcome)
    });
    runtime.shutdown_timeout(SHUTDOWN_RUNTIME_TIMEOUT);
    std::process::exit(code)
}

#[cfg(feature = "native-owner-test-hooks")]
mod ffi_fixtures {
    //! Stub-backed FFI backends for the native child scenarios. The
    //! tables stay caller-owned (see `test_backend_with_tables`); native
    //! stubs write marker files and park on process-local gates.

    use std::path::PathBuf;
    use std::sync::{Condvar, Mutex, OnceLock};

    use pkcs11_proxy_ng_backend::FfiBackend;

    static MARKERS: OnceLock<PathBuf> = OnceLock::new();
    static PARK_GATE: (Mutex<bool>, Condvar) = (Mutex::new(true), Condvar::new());

    fn mark(name: &str) {
        let dir = MARKERS.get().expect("markers set");
        std::fs::write(dir.join(name), "1").expect("marker write");
    }

    pub(super) unsafe extern "C" fn init_ok(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    pub(super) unsafe extern "C" fn slot_list_one(
        _token_present: cryptoki_sys::CK_BBOOL,
        slots: *mut cryptoki_sys::CK_SLOT_ID,
        count: *mut cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        if count.is_null() {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }
        if slots.is_null() {
            unsafe {
                *count = 1;
            }
            return cryptoki_sys::CKR_OK;
        }
        unsafe {
            *slots = 7;
            *count = 1;
        }
        cryptoki_sys::CKR_OK
    }

    /// Stuck ordinary call: marks entry, then parks forever (spurious
    /// wakeups re-park via the latched gate).
    pub(super) unsafe extern "C" fn token_info_park(
        _slot: cryptoki_sys::CK_SLOT_ID,
        _info: cryptoki_sys::CK_TOKEN_INFO_PTR,
    ) -> cryptoki_sys::CK_RV {
        mark("token_info_entered");
        let guard = PARK_GATE.0.lock().expect("gate");
        let _guard = PARK_GATE.1.wait_while(guard, |parked| *parked).expect("gate");
        cryptoki_sys::CKR_OK
    }

    /// Finalize that marks entry, then parks forever.
    pub(super) unsafe extern "C" fn finalize_park(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
        mark("finalize_entered");
        let guard = PARK_GATE.0.lock().expect("gate");
        let _guard = PARK_GATE.1.wait_while(guard, |parked| *parked).expect("gate");
        cryptoki_sys::CKR_OK
    }

    /// Finalize that marks entry and fails (uncertain incarnation).
    pub(super) unsafe extern "C" fn finalize_fails(
        _: *mut std::ffi::c_void,
    ) -> cryptoki_sys::CK_RV {
        mark("finalize_entered");
        cryptoki_sys::CKR_DEVICE_ERROR
    }

    /// Session close that marks entry, then parks forever (a natively
    /// stuck eviction teardown call, holding its admission guard).
    pub(super) unsafe extern "C" fn close_park(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        mark("close_entered");
        let guard = PARK_GATE.0.lock().expect("gate");
        let _guard = PARK_GATE.1.wait_while(guard, |parked| *parked).expect("gate");
        cryptoki_sys::CKR_OK
    }

    pub(super) unsafe extern "C" fn finalize_ok(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    /// Build a stub-backed FFI backend. `markers` receives the stub
    /// marker files. The returned table `Box` MUST outlive the backend
    /// (declare it first so it drops last).
    pub(super) fn fixture_backend(
        markers: PathBuf,
        token_info: cryptoki_sys::CK_C_GetTokenInfo,
        finalize: cryptoki_sys::CK_C_Finalize,
    ) -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        fixture_backend_full(markers, token_info, finalize, None)
    }

    /// [`fixture_backend`] plus an optional session-close stub (for
    /// natively stuck eviction teardown).
    pub(super) fn fixture_backend_full(
        markers: PathBuf,
        token_info: cryptoki_sys::CK_C_GetTokenInfo,
        finalize: cryptoki_sys::CK_C_Finalize,
        close_session: cryptoki_sys::CK_C_CloseSession,
    ) -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        MARKERS.set(markers).expect("markers once");
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_Initialize = Some(init_ok);
        functions.C_Finalize = finalize;
        functions.C_GetSlotList = Some(slot_list_one);
        functions.C_GetTokenInfo = token_info;
        functions.C_CloseSession = close_session;
        // SAFETY: `functions` stays caller-owned for the backend's life.
        let backend = FfiBackend::test_backend_with_tables(functions.as_mut(), None, None);
        (backend, functions)
    }

    /// Managed variant: reserves the process construction slot so the
    /// instance takes the final-owner guard path on drop. The child
    /// must hold no other backend.
    pub(super) fn fixture_backend_managed(
        markers: PathBuf,
        finalize: cryptoki_sys::CK_C_Finalize,
    ) -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        MARKERS.set(markers).expect("markers once");
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_Initialize = Some(init_ok);
        functions.C_Finalize = finalize;
        functions.C_GetSlotList = Some(slot_list_one);
        // SAFETY: `functions` stays caller-owned for the backend's life.
        match FfiBackend::test_backend_managed_with_tables(functions.as_mut()) {
            Ok(backend) => (backend, functions),
            Err(e) => {
                // Child-entry diagnostic before any tracing exists; the
                // exit code (not the text) is the parent-visible signal.
                #[allow(clippy::print_stderr)]
                {
                    eprintln!("managed fixture reservation failed: {e}");
                }
                std::process::exit(12);
            }
        }
    }
}

/// `wedge_native_call`: a parked native ordinary call holds its guard;
/// the seal cannot drain → the controller fires → exit 70 (qualified),
/// with NO native Finalize entry over the outstanding call. On
/// unqualified targets the coordinator times out → exit 2.
///
/// The child also sets a huge `PKCS11_PROXY_NATIVE_STOP_GRACE_MS`
/// override to prove the coordinator-driven arm ignores it (the 70
/// lands at the 1s coordinator grace, not the 4min override).
#[cfg(feature = "native-owner-test-hooks")]
fn run_wedge_native_call() -> ! {
    use ffi_fixtures as fx;

    let markers = marker_dir();
    // SAFETY: the child is single-threaded here (no runtime or worker
    // threads exist yet), so no concurrent env access is possible.
    unsafe {
        std::env::set_var("PKCS11_PROXY_NATIVE_STOP_GRACE_MS", "240000");
    }
    let (backend, _functions) =
        fx::fixture_backend(markers.clone(), Some(fx::token_info_park), Some(fx::finalize_ok));
    let backend = Arc::new(backend);
    backend.initialize().expect("fixture init");
    // The stuck worker is a PLAIN thread (not runtime-managed): on the
    // unqualified exit-2 path `process::exit` kills it without joining.
    let stuck_backend = backend.clone();
    std::thread::spawn(move || {
        let _ = stuck_backend.get_token_info(CkSlotId(7));
    });
    await_file(markers.join("token_info_entered"), Duration::from_secs(10));

    let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
    let runtime = build_child_runtime();
    let code = runtime.block_on(async {
        drive_ffi_shutdown(&markers, backend.clone(), ctx_mgr, Duration::from_secs(1)).await
    });
    runtime.shutdown_timeout(SHUTDOWN_RUNTIME_TIMEOUT);
    std::process::exit(code)
}

/// `wedge_native_finalize`: seal completes (quiescent), then native
/// `C_Finalize` parks → controller fires → exit 70 (qualified) /
/// coordinator timeout → exit 2 (unqualified). The entry marker proves
/// the stop landed inside native Finalize, never before the seal.
#[cfg(feature = "native-owner-test-hooks")]
fn run_wedge_native_finalize() -> ! {
    use ffi_fixtures as fx;

    let markers = marker_dir();
    let (backend, _functions) = fx::fixture_backend(markers.clone(), None, Some(fx::finalize_park));
    let backend = Arc::new(backend);
    backend.initialize().expect("fixture init");

    let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
    let runtime = build_child_runtime();
    let code = runtime.block_on(async {
        drive_ffi_shutdown(&markers, backend.clone(), ctx_mgr, Duration::from_secs(1)).await
    });
    runtime.shutdown_timeout(SHUTDOWN_RUNTIME_TIMEOUT);
    std::process::exit(code)
}

/// `failed_finalize_ffi`: native `C_Finalize` returns an error → the
/// incarnation is uncertain → the final-owner guard stop-fires 70
/// during unwind on qualified targets (DESIGNED path); poison path →
/// exit 1 on unqualified targets.
#[cfg(feature = "native-owner-test-hooks")]
fn run_failed_finalize_ffi() -> ! {
    use ffi_fixtures as fx;

    let markers = marker_dir();
    let (backend, _functions) =
        fx::fixture_backend_managed(markers.clone(), Some(fx::finalize_fails));
    let backend = Arc::new(backend);
    backend.initialize().expect("fixture init");

    let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
    let runtime = build_child_runtime();
    // Move (never clone) the child-frame `Arc`: the final-owner guard
    // must observe the LAST owner drop during unwind inside `block_on`
    // — a surviving frame clone plus `process::exit` (which skips
    // destructors) would silence the guard and report exit 1.
    let code = runtime.block_on(async {
        drive_ffi_shutdown(&markers, backend, ctx_mgr, Duration::from_secs(5)).await
    });
    runtime.shutdown_timeout(SHUTDOWN_RUNTIME_TIMEOUT);
    std::process::exit(code)
}

/// `wedge_eviction_ffi`: an eviction teardown close parks NATIVELY
/// (holding its guard). The phase-2 join expires, the coordinator
/// proceeds, and the qualified phase-4 seal cannot drain → exit 70
/// with NO native Finalize entry; unqualified → exit 2.
#[cfg(feature = "native-owner-test-hooks")]
fn run_wedge_eviction_ffi() -> ! {
    use ffi_fixtures as fx;

    let markers = marker_dir();
    let (backend, _functions) = fx::fixture_backend_full(
        markers.clone(),
        None,
        Some(fx::finalize_ok),
        Some(fx::close_park),
    );
    let backend = Arc::new(backend);
    backend.initialize().expect("fixture init");

    let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
    let runtime = build_child_runtime();
    let code = runtime.block_on(async {
        let ctx_id = ctx_mgr.create_context(None).await.expect("ctx");
        ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(BackendHandle(11), BackendSlotId(CkSlotId(7)));
                ctx.last_active = Instant::now() - Duration::from_secs(3600);
            })
            .await
            .expect("setup");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(None::<ShutdownReason>);
        let serve = fake_listener(shutdown_rx.clone());
        let signal = listener_shutdown(shutdown_rx);
        let eviction = spawn_eviction_task(
            ctx_mgr,
            backend.clone(),
            Duration::from_millis(50),
            1024,
            64,
            None,
            shutdown_tx.clone(),
        );
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            shutdown_tx.send_modify(|reason| {
                if reason.is_none() {
                    *reason = Some(ShutdownReason::Signal);
                }
            });
        });
        // Rendezvous: the first tick must be inside the parked native
        // close before the coordinator can expire the join on it.
        // (Poll outside the runtime clock: the marker is a plain file.)
        let entered = markers.join("close_entered");
        let start = Instant::now();
        while !entered.exists() {
            assert!(start.elapsed() < Duration::from_secs(10), "tick must enter the parked close");
            tokio::task::yield_now().await;
        }
        let backend_dyn: Arc<dyn Pkcs11Backend> = backend.clone();
        drop(backend);
        let outcome = coordinate_shutdown(
            vec![serve],
            signal,
            (),
            eviction,
            None,
            backend_dyn,
            None,
            Duration::from_secs(2),
        )
        .await;
        exit_code_of(outcome)
    });
    runtime.shutdown_timeout(SHUTDOWN_RUNTIME_TIMEOUT);
    std::process::exit(code)
}

/// Shared FFI child driver: fake listener + eviction + coordinator,
/// no audit. NOTE: takes `backend` by value and drops the child-side
/// Arc right after the coordinator returns, so the final-owner guard
/// (if Poison) fires inside the child deterministically.
#[cfg(feature = "native-owner-test-hooks")]
async fn drive_ffi_shutdown(
    _markers: &Path,
    backend: Arc<pkcs11_proxy_ng_backend::FfiBackend>,
    ctx_mgr: Arc<ContextManager>,
    grace: Duration,
) -> i32 {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(None::<ShutdownReason>);
    let serve = fake_listener(shutdown_rx.clone());
    let signal = listener_shutdown(shutdown_rx);
    let eviction = spawn_eviction_task(
        ctx_mgr,
        backend.clone(),
        Duration::from_secs(3600),
        1024,
        64,
        None,
        shutdown_tx.clone(),
    );
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        shutdown_tx.send_modify(|reason| {
            if reason.is_none() {
                *reason = Some(ShutdownReason::Signal);
            }
        });
    });
    let backend_dyn: Arc<dyn Pkcs11Backend> = backend.clone();
    drop(backend);
    let outcome =
        coordinate_shutdown(vec![serve], signal, (), eviction, None, backend_dyn, None, grace)
            .await;
    exit_code_of(outcome)
}

// ---------------------------------------------------------------------------
// Parent side
// ---------------------------------------------------------------------------

struct ChildOutcome {
    status: Option<i32>,
    elapsed: Duration,
    stderr: String,
}

/// Spawn the re-entrant child for `scenario` with a fresh marker dir.
/// A watchdog kills a hung child past the backstop (no immortal test
/// runner); `wait_with_output` reaps pipes without deadlock.
fn run_child(scenario: &str) -> (tempfile::TempDir, ChildOutcome) {
    let markers = tempfile::tempdir().expect("marker dir");
    let mut child = Command::new(std::env::current_exe().expect("current exe"))
        .arg("--exact")
        .arg("shutdown_lifetime_child_entry")
        .arg("--nocapture")
        .env(SCENARIO_ENV, scenario)
        .env(MARKER_ENV, markers.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child");
    let start = Instant::now();
    // Bounded reap: children are quiet by construction (no tracing
    // init; the harness prints a few lines), so piped-output deadlock
    // is impossible and a `try_wait` loop with kill past the backstop
    // cannot pin the suite.
    let output = loop {
        match child.try_wait().expect("poll child") {
            Some(_) => break child.wait_with_output().expect("reap child"),
            None if start.elapsed() >= PARENT_BACKSTOP => {
                let _ = child.kill();
                panic!("child {scenario} hung past the parent backstop; killed");
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let elapsed = start.elapsed();
    assert!(
        elapsed < PARENT_BACKSTOP + Duration::from_secs(10),
        "child {scenario} exceeded the parent backstop ({elapsed:?})"
    );
    (
        markers,
        ChildOutcome {
            status: output.status.code(),
            elapsed,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
    )
}

fn read_marker(markers: &Path, name: &str) -> String {
    std::fs::read_to_string(markers.join(name)).expect("marker present").trim().to_owned()
}

/// Single-sourced stop qualification (T10 review must-fix): reads the
/// REAL backend predicate instead of a hand-maintained `cfg!` mirror
/// (the old mirror replicated only the linux-x86_64 leg and asserted
/// exit 2/1 on i686/aarch64/macOS/Windows where the backend produces
/// 70). The only targets whose phase-4 wait is natively bounded.
#[cfg(feature = "native-owner-test-hooks")]
use pkcs11_proxy_ng_backend::ffi::stop_qualified_target;

#[test]
fn shutdown_normal_flushes_and_finalizes_once() {
    let (markers, outcome) = run_child("normal");
    assert_eq!(outcome.status, Some(0), "stderr:\n{}", outcome.stderr);
    assert!(
        outcome.elapsed < Duration::from_secs(3),
        "orderly shutdown must be prompt (timer abort + writer join), took {:?}",
        outcome.elapsed
    );
    assert_eq!(read_marker(markers.path(), "finalize_calls"), "1");
    assert_eq!(
        read_marker(markers.path(), "checkpoints"),
        "1",
        "exactly one checkpoint: flushed exactly once, no duplicate final markers"
    );
}

#[test]
fn shutdown_wedge_eviction_proceeds_past_join_expiry() {
    let (markers, outcome) = run_child("wedge_eviction");
    // Join expiry consumed the budget: phase 4 has nothing left, so the
    // non-natively-bounded mock path reports coordinator error → 2.
    assert_eq!(outcome.status, Some(2), "stderr:\n{}", outcome.stderr);
    assert!(
        outcome.elapsed < Duration::from_secs(15),
        "join expiry must bound the wedged tick, took {:?}",
        outcome.elapsed
    );
    assert_eq!(
        read_marker(markers.path(), "close_calls"),
        "1",
        "one close attempt: the wedged tick started, no runaway re-ticking"
    );
}

#[test]
fn shutdown_wedge_mock_finalize_exits_2_bounded() {
    let (markers, outcome) = run_child("wedge_mock_finalize");
    assert_eq!(outcome.status, Some(2), "stderr:\n{}", outcome.stderr);
    assert!(
        outcome.elapsed < Duration::from_secs(30),
        "exit-2 path must stay bounded (1s grace + 10s runtime tail), took {:?}",
        outcome.elapsed
    );
    assert!(
        outcome.elapsed >= Duration::from_secs(1),
        "must actually wait out the phase-4 budget, took {:?}",
        outcome.elapsed
    );
    assert_eq!(read_marker(markers.path(), "finalize_calls"), "1", "single attempt, no retry");
}

#[test]
fn shutdown_failed_finalize_mock_exits_1() {
    let (markers, outcome) = run_child("failed_finalize_mock");
    assert_eq!(outcome.status, Some(1), "stderr:\n{}", outcome.stderr);
    assert!(
        outcome.elapsed < Duration::from_secs(5),
        "scripted failure must surface promptly, took {:?}",
        outcome.elapsed
    );
    assert_eq!(read_marker(markers.path(), "finalize_calls"), "1");
}

#[test]
fn shutdown_stuck_trip_shuts_down_through_lifecycle() {
    let (markers, outcome) = run_child("stuck_trip");
    // No direct exit: the trip requests coordinator shutdown, the 5s
    // teardown timeout resolves the stuck call, and the daemon retires
    // orderly.
    assert_eq!(outcome.status, Some(0), "stderr:\n{}", outcome.stderr);
    assert!(
        outcome.elapsed >= Duration::from_secs(4),
        "must actually trip on the 5s teardown timeout, took {:?}",
        outcome.elapsed
    );
    assert!(
        outcome.elapsed < Duration::from_secs(20),
        "lifecycle stop must stay bounded, took {:?}",
        outcome.elapsed
    );
    assert_eq!(read_marker(markers.path(), "finalize_calls"), "1");
    assert_eq!(read_marker(markers.path(), "close_calls"), "1");
}

#[test]
#[cfg(feature = "native-owner-test-hooks")]
fn shutdown_wedge_audit_flush_timeout_still_finalizes() {
    let (markers, outcome) = run_child("wedge_audit");
    assert_eq!(outcome.status, Some(0), "stderr:\n{}", outcome.stderr);
    assert!(
        outcome.elapsed >= Duration::from_secs(1),
        "must actually wait out the flush budget, took {:?}",
        outcome.elapsed
    );
    assert!(
        outcome.elapsed < Duration::from_secs(20),
        "flush timeout must bound the wedged writer, took {:?}",
        outcome.elapsed
    );
    assert_eq!(read_marker(markers.path(), "finalize_calls"), "1");
    assert_eq!(read_marker(markers.path(), "checkpoints"), "0", "the parked flush wrote nothing");
}

#[test]
#[cfg(feature = "native-owner-test-hooks")]
fn shutdown_wedge_native_call_stops_without_finalize_over_outstanding() {
    let (markers, outcome) = run_child("wedge_native_call");
    assert!(
        markers.path().join("token_info_entered").exists(),
        "the native call must be provably outstanding at the stop"
    );
    assert!(
        !markers.path().join("finalize_entered").exists(),
        "no native Finalize may run over outstanding native work"
    );
    if stop_qualified_target() {
        assert_eq!(outcome.status, Some(70), "stderr:\n{}", outcome.stderr);
        assert!(
            outcome.elapsed < Duration::from_secs(30),
            "the 1s coordinator arm (not the 4min env override) must fire, took {:?}",
            outcome.elapsed
        );
    } else {
        assert_eq!(outcome.status, Some(2), "stderr:\n{}", outcome.stderr);
    }
}

#[test]
#[cfg(feature = "native-owner-test-hooks")]
fn shutdown_wedge_native_finalize_stops_inside_finalize() {
    let (markers, outcome) = run_child("wedge_native_finalize");
    assert!(
        markers.path().join("finalize_entered").exists(),
        "the stop must land inside native Finalize (post-seal)"
    );
    if stop_qualified_target() {
        assert_eq!(outcome.status, Some(70), "stderr:\n{}", outcome.stderr);
    } else {
        assert_eq!(outcome.status, Some(2), "stderr:\n{}", outcome.stderr);
    }
}

#[test]
#[cfg(feature = "native-owner-test-hooks")]
fn shutdown_failed_finalize_ffi_guards_through_70() {
    let (markers, outcome) = run_child("failed_finalize_ffi");
    assert!(
        markers.path().join("finalize_entered").exists(),
        "native Finalize must have been attempted"
    );
    if stop_qualified_target() {
        // DESIGNED 70-via-guard path (uncertain incarnation), prompt:
        // the guard fires during unwind, not at any deadline.
        assert_eq!(outcome.status, Some(70), "stderr:\n{}", outcome.stderr);
        assert!(
            outcome.elapsed < Duration::from_secs(5),
            "guard backstop must fire promptly, took {:?}",
            outcome.elapsed
        );
    } else {
        assert_eq!(outcome.status, Some(1), "stderr:\n{}", outcome.stderr);
    }
}

#[test]
#[cfg(feature = "native-owner-test-hooks")]
fn shutdown_wedge_eviction_ffi_joins_expire_then_stops_natively() {
    let (markers, outcome) = run_child("wedge_eviction_ffi");
    assert!(
        markers.path().join("close_entered").exists(),
        "the eviction teardown close must be provably parked at the stop"
    );
    assert!(
        !markers.path().join("finalize_entered").exists(),
        "no native Finalize may run while the teardown call is outstanding"
    );
    if stop_qualified_target() {
        assert_eq!(outcome.status, Some(70), "stderr:\n{}", outcome.stderr);
        assert!(
            outcome.elapsed < Duration::from_secs(30),
            "the 2s coordinator arm must bound the seal, took {:?}",
            outcome.elapsed
        );
    } else {
        assert_eq!(outcome.status, Some(2), "stderr:\n{}", outcome.stderr);
    }
}
