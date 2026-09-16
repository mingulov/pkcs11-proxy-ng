//! Abnormal native-lifetime stop via raw `exit_group(70)`.
//!
//! Fragment A (stubs only): two Linux raw-syscall stubs plus a compiling
//! fallback for all other targets. The guard (fragment B) owns the call
//! sites; tests (fragment C) qualify the linked bytes.
//!
//! Contract rows live in `doc/release/native-mechanism-ownership.md`
//! (x86_64: `syscall` nr 231 with status 70 in RDI; i686: `int 0x80`
//! nr 252 with status 70 via ECX into EBX and balanced push/pop). Both
//! stubs model a possible return; the outer loop retries on interception.

/// Return carrier for one raw `exit_group(70)` attempt.
///
/// Transparent over `i32` so the modeled return stays visible in codegen
/// instead of folding into a diverging shape. The x86_64 stub truncates
/// the 64-bit RAX result; the i686 stub carries EAX directly.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // STOP-B removes: wired by guard
pub(in crate::ffi) struct RawStopAttempt(pub(in crate::ffi) i32);

/// Why the native lifetime must stop abnormally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // STOP-B removes: wired by guard
pub(in crate::ffi) enum StopReason {
    /// Final owner cannot prove quiescence.
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
    #[allow(dead_code)] // STOP-B removes: wired by guard
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
    #[allow(dead_code)] // STOP-B removes: wired by guard
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

// Everything else (incl. Windows; T7 owns that arm): compiling fallback,
// unreachable because the guard call site is cfg-gated to the Linux arms.
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
    )
)))]
mod arch {
    use super::RawStopAttempt;

    /// Compiling fallback for targets without a qualified Linux stub.
    ///
    /// # Safety
    ///
    /// Never called: the guard call site is cfg-gated to the Linux arms.
    #[allow(dead_code)] // STOP-B removes: wired by guard
    #[inline(never)]
    pub(in crate::ffi) unsafe fn raw_exit_group_70() -> RawStopAttempt {
        unimplemented!("native stop: non-Linux arm not owned by STOP-IMPL (T7 owns Windows)")
    }
}

/// Abnormally stop the native lifetime; never returns to the caller.
///
/// Consumes `reason` for debugger/codegen-visible discrimination, then
/// retries raw `exit_group(70)` until the process is gone. A return means
/// interception: retry, never fall through to dependent destruction.
#[allow(dead_code)] // STOP-B removes: wired by guard
pub(in crate::ffi) fn abnormal_stop_native_lifetime(reason: StopReason) -> ! {
    let _ = reason;
    loop {
        // SAFETY: raw exit_group(70); a return means interception — retry.
        unsafe { arch::raw_exit_group_70() };
    }
}
