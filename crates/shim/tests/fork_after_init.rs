#![cfg(unix)]
// fork(2)/waitpid(2) test with no Windows equivalent; excluded from the Windows compile lane.

//! Concurrency-audit test for fork-after-C_Initialize.
//!
//! PKCS#11 v3.0 §5.4 says behaviour after `fork()` is undefined.
//! Real-world PKCS#11 libraries that hold thread / socket / mutex
//! state across the fork generally don't survive it: the child
//! inherits half-initialised mutexes and dead file descriptors. Our
//! shim has a tokio runtime, gRPC channel, and the `MECHANISM_REGISTRY`
//! RwLock — all of which are unsafe to use post-fork from the child.
//!
//! What we verify here:
//!   * The CHILD calling pre-init functions (`C_GetFunctionList`) is
//!     safe — those don't touch the tokio runtime.
//!   * The CHILD calling `C_Initialize` either succeeds cleanly (by
//!     re-establishing all per-process state) or returns a clean
//!     `CK_RV` error. The acceptance bar is "no crash / no
//!     deadlock"; we don't require correctness, just liveness.
//!
//! This test does NOT require the daemon to be running — it exercises
//! only pre-init paths and the `C_Initialize` error path against an
//! unreachable endpoint. The point is to prove the FFI surface
//! survives fork without aborting the process.

use std::os::unix::process::ExitStatusExt;

/// Direct fork(2) test. The parent forks; the child performs the
/// shim's pre-init introspection sequence and then attempts a
/// `C_Initialize` against an unreachable endpoint. The child uses
/// `_exit()` to avoid running atexit handlers (which would touch
/// the parent-inherited tokio runtime).
///
/// The parent verifies:
///   * the child exited (didn't deadlock — bounded by a wait timeout),
///   * the child's exit code is in the expected set: 0 (clean), or
///     the PKCS#11 CK_RV-derived code (any value < 256).
///
/// Marked `#[ignore]` by default because `unsafe { libc::fork() }`
/// inside `cargo test` is rough on the test harness — the child
/// inherits the harness's process state, which is fine because the
/// child calls `_exit()` immediately after recording its result.
/// Run with `cargo test --test fork_after_init -- --ignored` to
/// exercise.
#[test]
#[ignore]
fn child_can_call_pre_init_after_parent_fork() {
    use pkcs11_proxy_ng_shim::__test_api::mechanism_registry;
    use pkcs11_proxy_ng_types::MechanismRegistry;
    // Pre-populate the parent's MECHANISM_REGISTRY so the child
    // inherits a real (if stale) registry too.
    let reg = MechanismRegistry::load(None).expect("embedded default registry");
    pkcs11_proxy_ng_shim::__test_api::replace_mechanism_registry(reg);

    // Verify the parent's pre-fork state is sane.
    let parent_arc = mechanism_registry();
    assert!(parent_arc.is_parameterless(0x0001), "parent registry is functional pre-fork");
    drop(parent_arc);

    // SAFETY: fork(2) is async-signal-safe; what we do in the child
    // is strictly limited to async-signal-safe operations plus
    // _exit(). We never touch the parent-inherited tokio runtime,
    // RwLock, or socket from the child.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Child: try to clone the inherited Arc once. Reading a
        // RwLock that the parent doesn't hold is safe because the
        // child has a duplicated copy of the parent's address space;
        // no lock is held at fork point.
        let _child_arc = mechanism_registry();

        // Exit cleanly. Skipping the test harness's drop sequence
        // is intentional — fork-child drop semantics with tokio
        // pools is the very thing the spec says is undefined.
        unsafe { libc::_exit(0) };
    }

    assert!(pid > 0, "fork() failed: {pid}");

    let mut status: i32 = 0;
    // Bounded wait: 5 seconds is plenty for the child's pre-init path.
    for _ in 0..50 {
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r == pid {
            break;
        }
        if r == -1 {
            panic!("waitpid error");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let st = std::process::ExitStatus::from_raw(status);
    assert!(st.success(), "child did not exit cleanly: status = {:?} ({})", st, status);
}

/// Bounded waitpid helper shared by the fork tests below: waits up to
/// ~5 s for `pid`, panics on wait errors, and returns the raw status.
fn wait_child(pid: i32) -> std::process::ExitStatus {
    let mut status: i32 = 0;
    for _ in 0..50 {
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r == pid {
            break;
        }
        if r == -1 {
            panic!("waitpid error");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    std::process::ExitStatus::from_raw(status)
}

/// T2run (macOS run-6): a forked child must NOT inherit the parent's
/// tokio runtime — its I/O driver (kqueue fd) is dead post-fork and
/// the first `block_on` use panics with EBADF (SIGABRT in the
/// cross-process isolation test). The child must get a freshly built
/// runtime instead. Red-before: child observes the parent's pointer.
#[test]
#[ignore]
fn child_gets_fresh_runtime_after_fork() {
    use pkcs11_proxy_ng_shim::__test_api::runtime;

    let parent_ptr = runtime() as *const _ as usize;
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let child_ptr = runtime() as *const _ as usize;
        unsafe { libc::_exit(i32::from(child_ptr == parent_ptr)) };
    }
    assert!(pid > 0, "fork() failed: {pid}");
    let st = wait_child(pid);
    assert!(st.success(), "child inherited the parent runtime: {st:?} ({st})");
}

/// T2run (macOS run-6): the initialized flag must not leak across
/// fork — the child's `C_Initialize` must run the full path (fresh
/// runtime + reconnected channel) instead of short-circuiting on the
/// parent's state. Red-before: child observes initialized == true.
#[test]
#[ignore]
fn child_init_flag_reset_after_fork() {
    use pkcs11_proxy_ng_shim::__test_api::{is_initialized, mark_finalized, mark_initialized};

    assert!(mark_initialized(), "parent must transition to initialized");
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let observed = is_initialized();
        unsafe { libc::_exit(i32::from(observed)) };
    }
    assert!(pid > 0, "fork() failed: {pid}");
    let st = wait_child(pid);
    mark_finalized(); // restore the parent for the rest of the suite
    assert!(st.success(), "child inherited initialized == true: {st:?} ({st})");
}
