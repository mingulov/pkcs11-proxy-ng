//! Abnormal native-lifetime stop: raw `exit_group(70)` on stop-qualified
//! Linux, `TerminateProcess(70)` on stop-qualified Windows. macOS is
//! load-qualified but has no stop arm yet: there the guard compiles out
//! and the poison path applies.
//!
//! The final-owner guard (`Drop` in `ffi/loading.rs`) and the
//! shutdown-deadline controller below are the only production callers. Both
//! reach `abnormal_stop_native_lifetime`, which retries the raw stop
//! until the process is gone: a return means interception — retry, never
//! fall through to dependent destruction. (The Windows stub models
//! non-return and spins itself; the outer loop is unreachable there.)
//!
//! Contract rows live in `doc/release/native-mechanism-ownership.md`
//! (x86_64: `syscall` nr 231 with status 70 in RDI; i686: `int 0x80`
//! nr 252 with status 70 via ECX into EBX and balanced push/pop;
//! Windows MSVC x86_64/x86: `TerminateProcess` with status 70). Both Linux
//! stubs model a possible return; the outer loop retries on interception.

use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::SeqCst;
use std::time::{Duration, Instant};

/// Return carrier for one raw `exit_group(70)` attempt.
///
/// Transparent over `i32` so the modeled return stays visible in codegen
/// instead of folding into a diverging shape. The x86_64 stub truncates
/// the 64-bit RAX result; the i686 stub carries EAX directly.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ffi) struct RawStopAttempt(pub(in crate::ffi) i32);

/// Why the native lifetime must stop abnormally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ffi) enum StopReason {
    /// Final owner cannot prove quiescence.
    ///
    /// Constructed only by the `Drop` guard, which is cfg-gated to the
    /// Linux and Windows stop arms (macOS is load-qualified but has no
    /// stop arm yet).
    UnprovenFinalOwner,
    /// Shutdown deadline expired with native work still outstanding.
    ShutdownDeadlineExpired,
}

// x86_64 Linux GNU/musl: contract row 1.
#[cfg(all(
    target_os = "linux",
    any(target_env = "gnu", target_env = "musl"),
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
mod arch {
    use super::RawStopAttempt;

    /// One raw `exit_group(70)` attempt via `syscall`.
    ///
    /// Models a possible return: on interception the call returns and the
    /// caller retries. Never diverges by itself.
    ///
    /// # Safety
    ///
    /// Ends the process on success; on hypothetical return the value is the
    /// raw RAX result and the caller must retry, never fall through.
    #[inline(never)]
    pub(in crate::ffi) unsafe fn raw_exit_group_70() -> RawStopAttempt {
        let mut nr_ret: i64 = 231;
        // SAFETY: raw exit_group(70) with the documented register contract.
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") nr_ret,
                in("rdi") 70i64,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack)
            );
        }
        RawStopAttempt(nr_ret as i32)
    }
}

// i686 Linux GNU/musl: contract row 2.
#[cfg(all(
    target_os = "linux",
    any(target_env = "gnu", target_env = "musl"),
    target_arch = "x86",
    target_pointer_width = "32"
))]
mod arch {
    use super::RawStopAttempt;

    /// One raw `exit_group(70)` attempt via `int 0x80`.
    ///
    /// Models a possible return: on interception the call returns and the
    /// caller retries. Never diverges by itself. Balanced push/pop keeps
    /// the PIC base in EBX intact across the hypothetical return.
    ///
    /// # Safety
    ///
    /// Ends the process on success; on hypothetical return the value is the
    /// raw EAX result and the caller must retry, never fall through.
    #[inline(never)]
    pub(in crate::ffi) unsafe fn raw_exit_group_70() -> RawStopAttempt {
        let mut nr_ret: i32 = 252;
        // SAFETY: raw exit_group(70) with the documented register contract.
        unsafe {
            core::arch::asm!(
                "push ebx",
                "mov ebx, ecx",
                "int 0x80",
                "pop ebx",
                inlateout("eax") nr_ret,
                in("ecx") 70i32,
            );
        }
        RawStopAttempt(nr_ret)
    }
}

// Windows MSVC x86_64/x86: contract row 3 (reviewer Q3 ruling). One arm
// covers both widths: `extern "system"` is `__stdcall` on x86 (the
// kernel32 convention) and the x64 convention on x86_64, and `HANDLE`
// is pointer-sized on both, so the same two imports are correct for
// PE32 and PE32+.
#[cfg(all(
    target_os = "windows",
    target_env = "msvc",
    any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "x86", target_pointer_width = "32")
    )
))]
mod arch {
    use std::ffi::{c_int, c_uint, c_void};

    /// Win32 `HANDLE` (opaque pointer).
    type HANDLE = *mut c_void;
    /// Win32 `BOOL` (32-bit int).
    type BOOL = c_int;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> HANDLE;
        fn TerminateProcess(hProcess: HANDLE, uExitCode: c_uint) -> BOOL;
    }

    /// One abnormal-stop attempt via `TerminateProcess(70)`.
    ///
    /// Modeled non-return: `TerminateProcess` on the current-process
    /// pseudo-handle never returns on success, so the trailing `loop {}`
    /// is unreachable in practice; a hypothetical return spins instead of
    /// falling through to dependent destruction.
    ///
    /// # Safety
    ///
    /// Ends the process on success with status 70; no DLL detach
    /// routines, C exit handlers, or Rust destructors run.
    #[inline(never)]
    pub(in crate::ffi) unsafe fn raw_exit_group_70() -> super::RawStopAttempt {
        // SAFETY: whole-process immediate termination with status 70.
        unsafe {
            TerminateProcess(GetCurrentProcess(), 70);
        }
        loop {}
    }
}

// Fallback: every target without a qualified stop arm — everything
// outside the Linux/Windows stop boundary, including macOS (load-qualified
// but with no stop stub yet). Partition proof — each target lands on
// exactly one `arch` arm: (1) Linux x86_64 GNU/musl 64-bit, (2) Linux x86
// GNU/musl 32-bit, (3) Windows MSVC x86_64 64-bit / x86 32-bit, (4) this
// fallback. Arms 1-3 are pairwise disjoint (the linux-x86_64, linux-x86,
// and windows-msvc predicates differ on target_os/target_arch), and arm 4
// is the exact `not(any(1, 2, 3))` complement, hence exhaustive and disjoint
// by construction. Reachable only if a future guard arm calls it (today's
// guard is cfg-gated to the Linux and Windows stop arms, and the
// controller fires only past an armed deadline).
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "musl"),
        target_arch = "x86_64",
        target_pointer_width = "64"
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "musl"),
        target_arch = "x86",
        target_pointer_width = "32"
    ),
    all(
        target_os = "windows",
        target_env = "msvc",
        any(
            all(target_arch = "x86_64", target_pointer_width = "64"),
            all(target_arch = "x86", target_pointer_width = "32")
        )
    )
)))]
mod arch {
    use super::RawStopAttempt;

    /// Compiling fallback for targets without a qualified stop stub.
    ///
    /// # Safety
    ///
    /// Never reached on the stop-qualified Linux/Windows arms: the guard
    /// call site is cfg-gated there, and the controller fires only past an
    /// armed deadline.
    #[inline(never)]
    pub(in crate::ffi) unsafe fn raw_exit_group_70() -> RawStopAttempt {
        unimplemented!(
            "native stop: no qualified stop arm for this target \
             (Linux x86_64/x86 GNU/musl or Windows MSVC x86_64/x86 required)"
        )
    }
}

/// Abnormally stop the native lifetime; never returns to the caller.
///
/// Consumes `reason` for debugger/codegen-visible discrimination, then
/// retries the raw stop (Linux `exit_group(70)`, Windows
/// `TerminateProcess(70)`) until the process is gone. A return means
/// interception: retry, never fall through to dependent destruction.
pub(in crate::ffi) fn abnormal_stop_native_lifetime(reason: StopReason) -> ! {
    let _ = reason;
    loop {
        // SAFETY: raw exit_group(70); a return means interception — retry.
        let attempt = unsafe { arch::raw_exit_group_70() };
        // Keep the modeled return visible so codegen cannot fold the stub
        // into a noreturn shape; the value itself is never acted on.
        let _ = attempt.0;
    }
}

/// Default shutdown-deadline grace when no override is configured.
pub(in crate::ffi) const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

/// Env override (milliseconds) for the proactive deadline, read once at
/// first arm. It can only lengthen/shorten the proactive deadline, never
/// suppress the final-owner guard: a longer grace delays the controller,
/// never the `Drop`-time stop.
const GRACE_OVERRIDE_ENV: &str = "PKCS11_PROXY_NATIVE_STOP_GRACE_MS";

/// Seq of the latest armed deadline (0 = none yet).
static ARMED_SEQ: AtomicU64 = AtomicU64::new(0);
/// Seq of the latest completed/disarm.
static DONE_SEQ: AtomicU64 = AtomicU64::new(0);
/// Armed deadline as nanos since `BASE`.
static DEADLINE_NANOS: AtomicU64 = AtomicU64::new(0);
/// Controller thread handle, spawned lazily once at first arm.
static CONTROLLER_THREAD: OnceLock<std::thread::Thread> = OnceLock::new();
/// Monotonic base for `DEADLINE_NANOS`.
static BASE: OnceLock<Instant> = OnceLock::new();
/// Grace override, read once at first arm (never on the hot/stop path).
static GRACE_OVERRIDE: OnceLock<Duration> = OnceLock::new();

/// Effective shutdown-deadline grace: the env override when set and
/// parseable, else [`DEFAULT_SHUTDOWN_GRACE`]. Read once per process.
pub(in crate::ffi) fn shutdown_grace() -> Duration {
    *GRACE_OVERRIDE.get_or_init(|| {
        std::env::var(GRACE_OVERRIDE_ENV)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            // `from_millis` is total over `u64` (u64::MAX ms fits in a
            // `Duration`), so hostile input cannot panic here.
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_SHUTDOWN_GRACE)
    })
}

fn base_instant() -> Instant {
    *BASE.get_or_init(Instant::now)
}

fn nanos_since_base() -> u64 {
    base_instant().elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

fn nanos_limited(timeout: Duration) -> u64 {
    timeout.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// Arm the shutdown deadline: if no [`DeadlineGuard`] disarms within
/// `timeout`, the controller stops the group with
/// [`StopReason::ShutdownDeadlineExpired`]. Single-flight: arming while
/// armed replaces the deadline, and a stale guard's disarm is ignored by
/// seq comparison (fail-safe toward stopping, never toward suppressing).
pub(in crate::ffi) fn arm_shutdown_deadline(timeout: Duration) -> DeadlineGuard {
    ensure_controller();
    let deadline = nanos_since_base().saturating_add(nanos_limited(timeout));
    DEADLINE_NANOS.store(deadline, SeqCst);
    let seq = ARMED_SEQ.fetch_add(1, SeqCst).wrapping_add(1);
    if let Some(thread) = CONTROLLER_THREAD.get() {
        thread.unpark();
    }
    DeadlineGuard { seq }
}

/// Spawn the controller thread once. A plain OS thread — never a tokio
/// task, never a worker-pool thread. Detached: nothing ever joins it (it
/// parks forever after normal shutdown; `exit_group` kills it with the
/// group). Spawn failure leaves the deadline unenforced (best-effort).
fn ensure_controller() {
    if CONTROLLER_THREAD.get().is_none()
        && let Ok(handle) = std::thread::Builder::new()
            .name("pkcs11-stop-controller".to_owned())
            .spawn(controller_loop)
    {
        // A lost start race just leaks a second parking controller;
        // both enforce the same atomics, so the duplicate is benign.
        let _ = CONTROLLER_THREAD.set(handle.thread().clone());
    }
}

/// Controller hot path: park until armed, then until the deadline, then
/// stop. Only atomic loads/stores, `Instant::now` (via
/// `nanos_since_base`), park/unpark and the stop itself — no locks, no
/// allocation, no logging, no provider calls, no panic path.
fn controller_loop() {
    loop {
        let armed = ARMED_SEQ.load(SeqCst);
        if armed != DONE_SEQ.load(SeqCst) {
            let now = nanos_since_base();
            let deadline = DEADLINE_NANOS.load(SeqCst);
            if now >= deadline {
                abnormal_stop_native_lifetime(StopReason::ShutdownDeadlineExpired);
            }
            std::thread::park_timeout(Duration::from_nanos(deadline.saturating_sub(now)));
        } else {
            std::thread::park();
        }
    }
}

/// Armed-deadline guard: dropping disarms via one lock-free seq store.
/// Runs on the armed worker thread (normal path), never on the controller.
pub(in crate::ffi) struct DeadlineGuard {
    seq: u64,
}

impl Drop for DeadlineGuard {
    fn drop(&mut self) {
        // Monotonic max: a stale guard (superseded by a newer arm) cannot
        // disarm the newer deadline. Lock-free, panic-free, allocation-free.
        DONE_SEQ.fetch_max(self.seq, SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static SERIAL_STOP_TESTS: Mutex<()> = Mutex::new(());

    fn serial_stop_test_guard() -> std::sync::MutexGuard<'static, ()> {
        SERIAL_STOP_TESTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn default_shutdown_grace_is_thirty_seconds() {
        assert_eq!(DEFAULT_SHUTDOWN_GRACE, Duration::from_secs(30));
    }

    #[test]
    fn disarm_before_deadline_never_fires() {
        let _serial = serial_stop_test_guard();
        let guard = arm_shutdown_deadline(Duration::from_millis(100));
        let seq = guard.seq;
        drop(guard);
        assert!(DONE_SEQ.load(SeqCst) >= seq, "dropping the guard must disarm its seq");
        std::thread::sleep(Duration::from_millis(300));
        // Still alive past the deadline: the disarmed deadline never fired.
        assert!(DONE_SEQ.load(SeqCst) >= seq, "disarmed deadline must stay disarmed");
    }

    #[test]
    fn stale_guard_disarm_does_not_cancel_newer_deadline() {
        let _serial = serial_stop_test_guard();
        let older = arm_shutdown_deadline(Duration::from_secs(60));
        let newer = arm_shutdown_deadline(Duration::from_secs(60));
        assert!(newer.seq > older.seq, "arms must issue strictly increasing seqs");
        let newer_seq = newer.seq;
        drop(older);
        assert!(
            DONE_SEQ.load(SeqCst) < ARMED_SEQ.load(SeqCst),
            "stale guard must not disarm the newer deadline"
        );
        drop(newer);
        assert!(DONE_SEQ.load(SeqCst) >= newer_seq, "dropping the newest guard must disarm");
    }
}
