// W1-L12-03: test diagnostics (skip notices, progress, summaries) go to
// stderr by design; the workspace lint table denies this sink elsewhere.
#![allow(clippy::print_stderr)]
#![cfg(all(test, unix))]
//! Subprocess-only constructor battery (TO26a group 1): permanent-denial
//! paths that cannot run in-process because they poison the process-global
//! registry for the rest of the test process.
//!
//! Re-spawn harness (same shape as STOP-C1 in `native_stop_tests.rs`):
//! each parent test re-runs this lib test binary via `current_exe` with
//! `--exact <child-entry> --nocapture` plus a scenario selector env var.
//!
//! - D1 discovery failure: `dlopen` succeeds but no PKCS#11 entry point
//!   is discovered (a loadable non-PKCS#11 library). `dlopen` already ran
//!   unknown module initializers, so constructor-created background
//!   activity is unprovable and the slot poisons until restart (fail-closed
//!   reading of ownership-doc step 4); the failed constructor still drops
//!   its `Library` (unload) while reuse stays denied. The child pins the
//!   denial: post-failure `reserve` reports `Poisoned` and a second `load`
//!   reports poison, never Vacant treatment.
//! - D2 registry-mutex poison: a panic under the registry lock denies
//!   every later constructor with `MutexPoisoned`, never Vacant.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Scenario selector env var.
const CHILD_ENV: &str = "PKCS11_PROXY_CONSTRUCTOR_CHILD";
/// Exact child entry test path within the lib test binary.
const CHILD_TEST_PATH: &str = "ffi::constructor_child_tests::constructor_child_entry";

/// Private test-only owner: no dependency on another package's tests or on
/// new dev dependencies when this package is tested standalone.
struct ConstructorChild {
    child: Child,
    stdout: File,
    stderr: File,
}

fn anonymous_log() -> File {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_LOG: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "pkcs11-constructor-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        NEXT_LOG.fetch_add(1, Ordering::Relaxed),
    ));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .expect("create constructor log");
    std::fs::remove_file(path).expect("unlink constructor log");
    file
}

/// Spawn the lib test binary as a constructor child for `scenario`.
fn spawn_constructor_child(scenario: &str) -> ConstructorChild {
    let stdout = anonymous_log();
    let stderr = anonymous_log();
    let child = Command::new(std::env::current_exe().expect("current test exe"))
        .args(["--exact", CHILD_TEST_PATH, "--nocapture"])
        .env(CHILD_ENV, scenario)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone().expect("stdout clone")))
        .stderr(Stdio::from(stderr.try_clone().expect("stderr clone")))
        .spawn()
        .expect("spawn constructor child");
    ConstructorChild { child, stdout, stderr }
}

impl ConstructorChild {
    fn wait(mut self, timeout: Duration) -> Result<Output, Output> {
        let start = Instant::now();
        let (status, timed_out) = loop {
            match self.child.try_wait().expect("poll constructor child") {
                Some(status) => break (status, false),
                None if start.elapsed() >= timeout => {
                    let _ = self.child.kill();
                    break (self.child.wait().expect("reap killed constructor child"), true);
                }
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        fn prefix(file: &mut File) -> Vec<u8> {
            file.seek(SeekFrom::Start(0)).expect("rewind constructor log");
            let mut bytes = Vec::new();
            file.take(8192).read_to_end(&mut bytes).expect("read constructor log");
            bytes
        }
        let output =
            Output { status, stdout: prefix(&mut self.stdout), stderr: prefix(&mut self.stderr) };
        if timed_out { Err(output) } else { Ok(output) }
    }
}

impl Drop for ConstructorChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_constructor_child(child: ConstructorChild) -> Output {
    child.wait(Duration::from_secs(30)).unwrap_or_else(|output| {
        panic!("constructor child exceeded deadline; killed and reaped: status={} stdout={:?} stderr={:?}",
            output.status, String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    })
}

/// Assert the constructor-child record: normal exit 0 with a READY line
/// after reaping, no signal/core.
fn assert_child_status(output: &Output, scenario: &str) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "scenario {scenario}: normal exit status 0, got {:?}",
        output.status
    );
    use std::os::unix::process::ExitStatusExt as _;
    assert_eq!(output.status.signal(), None, "scenario {scenario}: no terminating signal");
    assert!(!output.status.core_dumped(), "scenario {scenario}: no core");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("READY"),
        "scenario {scenario}: READY line missing after child exit, stdout={stdout:?}"
    );
}

/// Child entry: vacuously passes in-process; diverges in the re-spawned child.
#[test]
fn constructor_child_entry() {
    let Ok(scenario) = std::env::var(CHILD_ENV) else {
        return;
    };
    run_constructor_child(&scenario);
}

/// Child dispatch. Never panics: setup failures exit with distinct codes
/// (11 bad scenario, 40 environment skip — no loadable non-PKCS#11
/// library, 41 expected denial missing, 42 unexpected error kind).
fn run_constructor_child(scenario: &str) -> ! {
    match scenario {
        "d1-discovery-failure" => run_d1_discovery_failure(),
        "d2-mutex-poison" => run_d2_mutex_poison(),
        "harness-wedge" | "harness-verbose" => run_harness_control(scenario),
        _ => std::process::exit(11),
    }
}

/// Independent child-side backstop: a regression in the parent's watchdog
/// or output draining must fail these controls rather than hang the suite.
fn run_harness_control(scenario: &str) -> ! {
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(5));
        std::process::exit(99);
    });
    if scenario == "harness-verbose" {
        for _ in 0..128 {
            std::io::stdout().write_all(&[b'v'; 4096]).unwrap();
            std::io::stderr().write_all(&[b'v'; 4096]).unwrap();
        }
        std::process::exit(0);
    }
    loop {
        std::thread::park();
    }
}

/// Loadable non-PKCS#11 candidates per platform: `dlopen` succeeds, but
/// neither `C_GetInterface` nor `C_GetFunctionList` exists, so discovery
/// fails after native initializers already ran.
fn discovery_candidates() -> &'static [&'static str] {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    return &["libc.so.6", "libm.so.6"];
    #[cfg(all(target_os = "linux", target_env = "musl"))]
    return &["libc.musl-x86_64.so.1", "libc.musl-x86.so.1"];
    #[cfg(target_os = "macos")]
    return &["libc.dylib", "/usr/lib/libc.dylib"];
    #[cfg(not(any(
        all(target_os = "linux", target_env = "gnu"),
        all(target_os = "linux", target_env = "musl"),
        target_os = "macos"
    )))]
    return &[];
}

/// D1 child: discovery failure after successful `dlopen` poisons the slot.
/// The load error must be neither AlreadyReserved (nothing is held) nor a
/// loader failure (`dlopen` succeeded) — it is the discovery error — and
/// every later constructor observes poison, never Vacant treatment.
fn run_d1_discovery_failure() -> ! {
    let mut discovered_failure = None;
    for candidate in discovery_candidates() {
        match super::FfiBackend::load(std::path::Path::new(candidate)) {
            Ok(_) => std::process::exit(42),
            Err(err) if err.contains("already reserved") => std::process::exit(42),
            Err(err) if err.contains("native module load failed") => continue,
            Err(err) => {
                discovered_failure = Some(err);
                break;
            }
        }
    }
    let discovery_err = match discovered_failure {
        Some(err) => err,
        // No candidate `dlopen`ed (static-musl without `dlopen`, minimal
        // rootfs): nothing was proven or denied — environment skip.
        None => std::process::exit(40),
    };
    let _ = writeln!(std::io::stderr(), "D1 discovery error: {discovery_err}");
    match super::native_domain::reserve_for_construction() {
        Err(super::native_domain::DomainError::Poisoned) => {}
        Err(other) => {
            let _ = writeln!(std::io::stderr(), "D1 post-failure reserve: {other:?}");
            std::process::exit(41);
        }
        Ok(_) => std::process::exit(41),
    }
    let retry =
        super::FfiBackend::load(std::path::Path::new("/nonexistent-pkcs11-proxy-ng-test.so"));
    match retry {
        Err(err) if err.contains("poisoned") => {}
        _ => std::process::exit(41),
    }
    let _ = writeln!(std::io::stdout(), "READY d1-discovery-failure");
    let _ = std::io::stdout().flush();
    std::process::exit(0);
}

/// D2 child: a poisoned registry mutex denies every constructor with
/// `MutexPoisoned` (registry marked poisoned for every future caller),
/// never Vacant treatment. The panic hook is silenced so the intentional
/// poison panic stays out of the child's stderr.
fn run_d2_mutex_poison() -> ! {
    std::panic::set_hook(Box::new(|_| {}));
    super::native_domain::poison_registry_mutex_for_tests();
    for _ in 0..2 {
        match super::native_domain::reserve_for_construction() {
            Err(super::native_domain::DomainError::MutexPoisoned) => {}
            Err(other) => {
                let _ = writeln!(std::io::stderr(), "D2 post-poison reserve: {other:?}");
                std::process::exit(41);
            }
            Ok(_) => std::process::exit(41),
        }
    }
    match super::FfiBackend::load(std::path::Path::new("/nonexistent-pkcs11-proxy-ng-test.so")) {
        Err(err) if err.contains("poisoned") => {}
        _ => std::process::exit(41),
    }
    let _ = writeln!(std::io::stdout(), "READY d2-mutex-poison");
    let _ = std::io::stdout().flush();
    std::process::exit(0);
}

/// D1: discovery failure after successful `dlopen` poisons until restart
/// (no reuse), while the failed constructor still unloads its `Library`.
/// Exit 40 is an environment skip (no `dlopen`able candidate), reported
/// with a notice — never silent green.
#[test]
fn constructor_d1_discovery_failure_poisons_until_restart() {
    let child = spawn_constructor_child("d1-discovery-failure");
    let output = wait_constructor_child(child);
    if output.status.code() == Some(40) {
        eprintln!("notice: D1 skipped — no loadable non-PKCS#11 library on this host");
        return;
    }
    assert_child_status(&output, "d1-discovery-failure");
}

/// D2: registry-mutex poison denies every constructor, never Vacant.
#[test]
fn constructor_d2_registry_mutex_poison_denies() {
    let child = spawn_constructor_child("d2-mutex-poison");
    let output = wait_constructor_child(child);
    assert_child_status(&output, "d2-mutex-poison");
}

#[test]
fn constructor_harness_reaps_wedged_child() {
    let child = spawn_constructor_child("harness-wedge");
    let pid = child.child.id();
    assert!(child.wait(Duration::from_millis(150)).is_err(), "wedge must time out");
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) }, -1);
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
}

#[test]
fn constructor_harness_accepts_verbose_child_with_bounded_diagnostics() {
    let output = wait_constructor_child(spawn_constructor_child("harness-verbose"));
    assert!(output.status.success());
    assert!(output.stdout.len() <= 8192 && output.stderr.len() <= 8192);
    assert!(output.stdout.contains(&b'v') && output.stderr.contains(&b'v'));
}
