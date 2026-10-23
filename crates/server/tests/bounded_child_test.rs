//! Behavioral controls run the harness under an independent parent backstop.
#![cfg(target_os = "linux")]

#[path = "support/bounded_child.rs"]
mod bounded_child;

use bounded_child::BoundedChild;
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SCENARIO: &str = "BOUNDED_CHILD_SCENARIO";
const FIXTURE: &str = "BOUNDED_CHILD_FIXTURE";

fn fixture_command(scenario: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "fixture_entry", "--ignored", "--nocapture"]).env(FIXTURE, scenario);
    command
}

#[test]
#[ignore = "subprocess helper; selected only by its owning parent with a scenario sentinel"]
fn fixture_entry() {
    let scenario = std::env::var(FIXTURE).expect("fixture entry requires its parent's sentinel");
    std::io::stderr().write_all(b"child entered\n").unwrap();
    if let Some(marker) = std::env::var_os("BOUNDED_CHILD_ENTERED") {
        std::fs::write(marker, "entered").unwrap();
    }
    if scenario == "verbose" {
        let block = [b'v'; 4096];
        for _ in 0..128 {
            std::io::stdout().write_all(&block).unwrap();
            std::io::stderr().write_all(&block).unwrap();
        }
        return;
    }
    loop {
        std::thread::park();
    }
}

fn assert_reaped(pid: u32) {
    let mut status = 0;
    let result = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
    if result == 0 {
        // Independent cleanup on a broken owner, before failing the assertion.
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
            libc::waitpid(pid as i32, &mut status, 0);
        }
    }
    assert_eq!(result, -1, "owned child must already be reaped");
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
}

#[test]
#[ignore = "subprocess helper; selected only by its owning parent with a scenario sentinel"]
fn probe_entry() {
    let scenario = std::env::var(SCENARIO).expect("probe entry requires its parent's sentinel");
    let markers = tempfile::tempdir().unwrap();
    let marker = markers.path().join("entered");
    let mut command = fixture_command(&scenario);
    command.env("BOUNDED_CHILD_ENTERED", &marker);
    let mut child = BoundedChild::spawn(&mut command).unwrap();
    let pid = child.id();
    if scenario != "verbose" {
        // Start the short negative-control budget only after actual child entry.
        child.wait_for_ready(Duration::from_secs(5), || marker.exists()).unwrap();
    }
    match scenario.as_str() {
        "never-ready" => {
            let error = child.wait_for_ready(Duration::from_millis(150), || false).unwrap_err();
            assert!(error.contains("child entered"), "{error}");
            assert_reaped(pid);
        }
        "wedge" => {
            let error = child.wait(Duration::from_millis(150)).unwrap_err();
            assert!(error.contains("child entered"), "{error}");
            assert_reaped(pid);
        }
        "verbose" => {
            let output = child.wait(Duration::from_secs(5)).unwrap();
            assert!(output.status.success());
            assert!(output.stdout.len() <= 8192 && output.stderr.len() <= 8192);
            assert!(output.stdout.contains(&b'v') && output.stderr.contains(&b'v'));
            assert_reaped(pid);
        }
        "panic" => {
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _owned = child;
                panic!("intentional test panic");
            }));
            assert!(panic.is_err());
            assert_reaped(pid);
        }
        _ => panic!("bad scenario"),
    }
}

fn run_probe(scenario: &str) {
    // Adopt a fixture if a deliberately broken probe exits before reaping it.
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, 0);
    let mut log = tempfile::tempfile().unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "probe_entry", "--ignored", "--nocapture"])
        .env(SCENARIO, scenario)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log.try_clone().unwrap()));
    // Isolate the probe and its fixture so even a broken helper is cleaned up.
    use std::os::unix::process::CommandExt;
    command.process_group(0);
    let mut probe = command.spawn().unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(status) = probe.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > Duration::from_secs(8) {
            unsafe {
                libc::kill(-(probe.id() as i32), libc::SIGKILL);
            }
            let _ = probe.wait();
            let mut status = 0;
            while unsafe { libc::waitpid(-(probe.id() as i32), &mut status, 0) } > 0 {}
            panic!("{scenario}: independent backstop killed wedged probe");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let _ = probe.wait();
    // Settle adopted fixtures even if a deliberately broken probe panicked
    // before its own cleanup assertion. This group belongs only to this probe.
    unsafe {
        libc::kill(-(probe.id() as i32), libc::SIGKILL);
    }
    let mut child_status = 0;
    while unsafe { libc::waitpid(-(probe.id() as i32), &mut child_status, 0) } > 0 {}
    log.seek(SeekFrom::Start(0)).unwrap();
    let mut diagnostic = String::new();
    log.take(16384).read_to_string(&mut diagnostic).unwrap();
    assert!(status.success(), "{scenario}: {status}: {diagnostic}");
}

#[test]
fn never_ready_child_is_killed_reaped_and_reported() {
    run_probe("never-ready");
}
#[test]
fn wedged_child_has_bounded_exit() {
    run_probe("wedge");
}
#[test]
fn verbose_child_cannot_fill_output_pipes() {
    run_probe("verbose");
}
#[test]
fn panic_reaps_owned_child() {
    run_probe("panic");
}
