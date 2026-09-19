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

use std::io::Write as _;
use std::process::{Command, Output, Stdio};

/// Scenario selector env var.
const CHILD_ENV: &str = "PKCS11_PROXY_CONSTRUCTOR_CHILD";
/// Exact child entry test path within the lib test binary.
const CHILD_TEST_PATH: &str = "ffi::constructor_child_tests::constructor_child_entry";

/// Spawn the lib test binary as a constructor child for `scenario`.
fn spawn_constructor_child(scenario: &str) -> std::process::Child {
    let exe = std::env::current_exe().expect("current test exe");
    Command::new(exe)
        .arg("--exact")
        .arg(CHILD_TEST_PATH)
        .arg("--nocapture")
        .env(CHILD_ENV, scenario)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn constructor child")
}

/// Assert the constructor-child record: normal exit 0 with a READY line
/// (pipe EOF proof), no signal/core.
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
        "scenario {scenario}: READY line missing (pipe EOF proof), stdout={stdout:?}"
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
        _ => std::process::exit(11),
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
    let output = child.wait_with_output().expect("reap constructor child");
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
    let output = child.wait_with_output().expect("reap constructor child");
    assert_child_status(&output, "d2-mutex-poison");
}
