//! Guarded Flat backing (R12, S2 §6): `GuardedBytes`.
//!
//! S2 §6 memory promise (exact — quoted verbatim):
//!
//! > the declared extent sits at the END of a zeroed page mapping,
//! > immediately before a no-access guard page; reads within the
//! > declared extent see exact bytes; underreads remaining inside
//! > the zero-filled pre-buffer mapping see zeros, while farther
//! > underreads may fault and are NOT contained; reads past
//! > `declared_len` fault. Never claim every overread crashes —
//! > only contiguous reads past the extent do.
//!
//! And, same paragraph: `ulParameterLen` is exactly `declared_len`;
//! the pointer is non-NULL even at length zero; no client address
//! bits are used.
//!
//! Layout (this implementation): one OS mapping of `data_len + guard`
//! bytes, where `data_len` rounds the declared length UP to a whole
//! number of pages and then adds one more full page of zero-filled
//! pre-buffer, and `guard` is one trailing no-access page. The declared
//! bytes are copied to the END of the data region. Consequences, each
//! pinned by a test in this module:
//!
//! * in-extent reads see the exact input bytes (`as_slice`);
//! * underreads landing inside the pre-buffer mapping see zeros (the
//!   pre-buffer is at least one page, so small underreads never fault);
//! * farther underreads (before the mapping) may fault and are NOT
//!   contained — no second guard page is mapped below on purpose;
//! * reads past `declared_len` land in the no-access guard page and
//!   fault — but ONLY contiguous reads are so bounded (S2 §10: the
//!   guard page bounds only contiguous overreads past the declared
//!   extent; derived/indexed pointers and writes are NOT contained).
//!
//! Alignment note (T5 precedent): the backing allocation itself is page
//! mapped (maximum alignment — never an alignment-1 byte `Vec` for a
//! provider-typed read), but the EXTENT START has whatever alignment
//! `mapping_end - declared_len` has: the exact fault promise forces the
//! extent end to coincide with the mapping end, so unaligned declared
//! lengths yield unaligned extent starts. That is inherent to verbatim
//! forwarding (client Flat buffers are arbitrarily aligned too), not a
//! defect. This module itself only ever touches the mapping with byte
//! copies, which are alignment-safe.
//!
//! Per-platform (S2 §16): unix via `mmap` + `PROT_NONE`, Windows via
//! `VirtualAlloc` + `PAGE_NOACCESS`, using only the `libc` OS
//! primitives already in the dependency closure. Under Miri the OS
//! mapping is replaced by a zeroed `Vec` fallback (Miri cannot execute
//! `mmap`/`mprotect`): every unit test stays green there, while the
//! fault-on-past-extent-read pins are `#[cfg(not(miri))]` — fault
//! semantics need a real guard page.
//!
//! Drop zeroes the data region (volatile wipes via `zeroize`, never
//! elided) before releasing the mapping.

use pkcs11_proxy_ng_types::shape_descriptors::FLAT_MAX_BYTES;
use pkcs11_proxy_ng_types::{CkResult, CkRv};
use std::cell::Cell;
use std::marker::PhantomData;
use std::ptr::NonNull;
#[cfg(miri)]
use zeroize::Zeroizing;

/// Maximum Flat extent this module will map (S2 §6 64 KiB cap, enforced
/// before FFI allocation — validation guarantees it, this is the
/// fail-closed backstop).
const MAX_BYTES: usize = FLAT_MAX_BYTES as usize;

/// Data-region size for `declared_len` caller bytes on `page`-byte pages:
/// the extent's own whole pages plus one full zero-filled pre-buffer page,
/// so small underreads land inside the mapping (zeros) instead of faulting.
fn data_len_for(declared_len: usize, page: usize) -> usize {
    declared_len.next_multiple_of(page).saturating_add(page)
}

/// OS page size, queried once. Falls back to 4096 if the query fails;
/// every mapping call still validates its own result, so a wrong size
/// fails closed (`HOST_MEMORY`), never silently unguarded.
#[cfg(all(not(miri), unix))]
fn page_size() -> usize {
    static PAGE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *PAGE.get_or_init(|| {
        // SAFETY: `sysconf` with `_SC_PAGESIZE` takes no pointer arguments.
        let queried = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(queried).unwrap_or(4096).max(1)
    })
}

/// OS page size via `GetSystemInfo`, queried once (same 4096 fallback
/// discipline as the unix arm above).
#[cfg(all(not(miri), windows))]
fn page_size() -> usize {
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    static PAGE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *PAGE.get_or_init(|| {
        // SAFETY: `GetSystemInfo` fully initializes the struct it is given.
        let queried = unsafe {
            let mut info = std::mem::MaybeUninit::<SYSTEM_INFO>::uninit();
            GetSystemInfo(info.as_mut_ptr());
            info.assume_init().dwPageSize
        };
        usize::try_from(queried).unwrap_or(4096).max(1)
    })
}

/// Guarded Flat extent: `declared_len` exact bytes ending where the
/// zeroed data mapping ends, followed by a no-access guard page.
///
/// Variance mirrors [`NativeAllocation`](super::super::native_allocation):
/// `Send` (unique ownership moves across threads into the session
/// `mech_cache`) but `!Sync` (no shared-borrowing discipline is
/// asserted — provider access is exclusive across the native call).
#[cfg(not(miri))]
pub(in crate::ffi) struct GuardedBytes {
    /// Base of the whole mapping (data region + trailing guard page).
    base: NonNull<u8>,
    /// Data-region length in bytes (pre-buffer + extent).
    data_len: usize,
    /// Declared extent length (`ulParameterLen`).
    declared_len: usize,
    /// Trailing guard length (one page).
    guard_len: usize,
    owned_invariant: PhantomData<Cell<u8>>,
}

/// Miri fallback: same layout (zero pre-buffer + exact extent at the end)
/// in a plain allocation — no guard page, so the fault pins exclude Miri.
/// `UnsafeCell` gives the whole allocation provider-mutable provenance
/// (the real mapping is provider-writable behind a shared reference
/// too): a sub-slice reborrow would narrow Miri provenance to the extent
/// and falsely flag pre-extent reads and provider writes (caught by
/// Miri's borrow checker during R12 development).
#[cfg(miri)]
pub(in crate::ffi) struct GuardedBytes {
    storage: std::cell::UnsafeCell<Zeroizing<Vec<u8>>>,
    data_len: usize,
    declared_len: usize,
}

#[cfg(not(miri))]
impl GuardedBytes {
    /// Map guarded storage holding an exact copy of `bytes`.
    ///
    /// Over-cap input fails closed (`MECHANISM_PARAM_INVALID` — a
    /// validated Flat never exceeds the cap, so this indicates bypass);
    /// genuine mapping failures report `HOST_MEMORY` (S2 §6 RV table:
    /// genuine sub-cap allocation failure).
    pub(in crate::ffi) fn new(bytes: &[u8]) -> CkResult<Self> {
        let declared_len = bytes.len();
        if declared_len > MAX_BYTES {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        let page = page_size();
        let data_len = data_len_for(declared_len, page);
        let total_len = data_len.saturating_add(page);
        // SAFETY: anonymous private mapping, no file descriptor, no fixed
        // address; every error path releases what it acquired.
        #[cfg(unix)]
        let base = unsafe {
            let base = libc::mmap(
                std::ptr::null_mut(),
                total_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if base == libc::MAP_FAILED {
                return Err(CkRv::HOST_MEMORY);
            }
            let guard_start = base.byte_add(data_len);
            if libc::mprotect(guard_start, page, libc::PROT_NONE) != 0 {
                libc::munmap(base, total_len);
                return Err(CkRv::HOST_MEMORY);
            }
            base as *mut u8
        };
        // SAFETY: fresh committed mapping owned by this value; every error
        // path releases what it acquired.
        #[cfg(windows)]
        let base = unsafe {
            use windows_sys::Win32::System::Memory::{
                MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE, VirtualAlloc,
                VirtualFree, VirtualProtect,
            };
            let base =
                VirtualAlloc(std::ptr::null(), total_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
                    as *mut u8;
            if base.is_null() {
                return Err(CkRv::HOST_MEMORY);
            }
            let guard_start = base.add(data_len) as *const std::ffi::c_void;
            let mut previous = 0u32;
            if VirtualProtect(guard_start, page, PAGE_NOACCESS, &mut previous) == 0 {
                VirtualFree(base as *mut std::ffi::c_void, 0, MEM_RELEASE);
                return Err(CkRv::HOST_MEMORY);
            }
            base
        };
        // SAFETY: `base` owns `data_len` writable bytes; the extent range
        // `[data_len - declared_len, data_len)` is in-bounds by
        // construction (`data_len >= declared_len` always: the rounding
        // only grows, and the extra page only adds).
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                base.add(data_len - declared_len),
                declared_len,
            );
        }
        Ok(Self {
            base: NonNull::new(base).expect("mapping base is nonnull"),
            data_len,
            declared_len,
            guard_len: page,
            owned_invariant: PhantomData,
        })
    }

    /// Pointer handed to the provider (`pParameter`): start of the
    /// declared extent. Non-NULL even at length zero (then it addresses
    /// the end of the data mapping, where no read may legally occur).
    pub(in crate::ffi) fn as_ptr(&self) -> *mut std::ffi::c_void {
        // SAFETY: in-bounds by construction (see `new`).
        unsafe {
            self.base.as_ptr().add(self.data_len - self.declared_len) as *mut std::ffi::c_void
        }
    }

    /// Exact extent bytes (for verification — the provider reads the same
    /// bytes through [`Self::as_ptr`]).
    #[cfg(test)]
    pub(in crate::ffi) fn as_slice(&self) -> &[u8] {
        // SAFETY: extent range is mapped and initialized (see `new`); the
        // borrow ends before any provider call can mutate through the raw
        // pointer, matching the `NativeAllocation` no-live-reference rule.
        unsafe { std::slice::from_raw_parts(self.as_ptr() as *const u8, self.declared_len) }
    }

    /// Declared extent length (`ulParameterLen`).
    pub(in crate::ffi) fn declared_len(&self) -> usize {
        self.declared_len
    }

    /// Zero-filled pre-buffer length (mapping bytes before the extent).
    #[cfg(test)]
    pub(in crate::ffi) fn prebuffer_len(&self) -> usize {
        self.data_len - self.declared_len
    }
}

#[cfg(not(miri))]
impl Drop for GuardedBytes {
    fn drop(&mut self) {
        // SAFETY: the data region is fully owned and mapped; volatile
        // wipes first (never elided), then release. Errors are ignored:
        // `Drop` must not panic, and the mapping is process-local either
        // way (an unreleased mapping at worst leaks address space).
        unsafe {
            let region = std::slice::from_raw_parts_mut(self.base.as_ptr(), self.data_len);
            for byte in region.iter_mut() {
                use zeroize::Zeroize as _;
                byte.zeroize();
            }
            #[cfg(unix)]
            libc::munmap(self.base.as_ptr() as *mut libc::c_void, self.data_len + self.guard_len);
            #[cfg(windows)]
            {
                use windows_sys::Win32::System::Memory::{MEM_RELEASE, VirtualFree};
                VirtualFree(self.base.as_ptr() as *mut std::ffi::c_void, 0, MEM_RELEASE);
            }
        }
    }
}

#[cfg(miri)]
impl GuardedBytes {
    /// Miri fallback constructor: identical layout, no guard page (Miri
    /// cannot execute `mmap`/`mprotect`). Same cap discipline as real.
    pub(in crate::ffi) fn new(bytes: &[u8]) -> CkResult<Self> {
        let declared_len = bytes.len();
        if declared_len > MAX_BYTES {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        // Fixed 4 KiB layout unit under Miri (no OS page query either).
        let data_len = data_len_for(declared_len, 4096);
        let mut vec = vec![0u8; data_len];
        vec[data_len - declared_len..].copy_from_slice(bytes);
        Ok(Self {
            storage: std::cell::UnsafeCell::new(Zeroizing::new(vec)),
            data_len,
            declared_len,
        })
    }

    /// See the real implementation: extent start, non-NULL at zero length.
    pub(in crate::ffi) fn as_ptr(&self) -> *mut std::ffi::c_void {
        // SAFETY: `data_len >= 1` always (the construction adds a page),
        // so the offset is live; whole-allocation provenance via
        // `UnsafeCell` (see the struct docs).
        unsafe {
            (*self.storage.get()).as_mut_ptr().add(self.data_len - self.declared_len)
                as *mut std::ffi::c_void
        }
    }

    /// See the real implementation.
    #[cfg(test)]
    pub(in crate::ffi) fn as_slice(&self) -> &[u8] {
        // SAFETY: extent range initialized; the borrow ends before any
        // provider write (same no-live-reference rule as the real impl).
        unsafe {
            let storage = &*self.storage.get();
            &storage[self.data_len - self.declared_len..]
        }
    }

    /// See the real implementation.
    pub(in crate::ffi) fn declared_len(&self) -> usize {
        self.declared_len
    }

    /// See the real implementation.
    #[cfg(test)]
    pub(in crate::ffi) fn prebuffer_len(&self) -> usize {
        self.data_len - self.declared_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// In-extent reads see exact bytes, at every interesting length
    /// (zero, sub-page, page edges, cap).
    #[test]
    fn guarded_extent_sees_exact_bytes() {
        for len in [0usize, 1, 3, 16, 4095, 4096, 4097, 65536] {
            let input: Vec<u8> =
                (0..len).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
            let guarded = GuardedBytes::new(&input).expect("guarded allocation");
            assert_eq!(guarded.declared_len(), len, "declared_len at {len}");
            assert_eq!(guarded.as_slice(), input.as_slice(), "exact bytes at {len}");
        }
    }

    /// Underreads landing inside the zero-filled pre-buffer mapping see
    /// zeros (SAFE per the promise — this read stays inside the mapping).
    #[test]
    fn guarded_prebuffer_reads_zero() {
        let guarded = GuardedBytes::new(&[0xA5; 16]).expect("guarded allocation");
        let pre = guarded.prebuffer_len();
        assert!(pre >= 64, "pre-buffer must cover the probe: {pre}");
        // SAFETY: the 64 bytes before the extent are inside the zeroed
        // data mapping by the assertion above; the copy is bytewise.
        let before =
            unsafe { std::slice::from_raw_parts((guarded.as_ptr() as *const u8).sub(64), 64) };
        assert_eq!(before, &[0u8; 64]);
    }

    /// Pointer non-NULL even at length zero (S2 §6).
    #[test]
    fn guarded_zero_length_is_non_null() {
        let guarded = GuardedBytes::new(&[]).expect("empty guarded allocation");
        assert!(!guarded.as_ptr().is_null(), "zero-length extent must stay non-NULL");
        assert_eq!(guarded.declared_len(), 0);
        assert_eq!(guarded.as_slice(), &[] as &[u8]);
    }

    /// Over-cap input fails closed (validation guarantees the cap; this
    /// is the backstop against bypass).
    #[test]
    fn guarded_over_cap_rejected() {
        let too_big = vec![0u8; MAX_BYTES + 1];
        assert_eq!(GuardedBytes::new(&too_big).err(), Some(CkRv::MECHANISM_PARAM_INVALID));
        // The cap itself still maps.
        let at_cap = vec![0x5Au8; MAX_BYTES];
        let guarded = GuardedBytes::new(&at_cap).expect("cap-sized allocation");
        assert_eq!(guarded.as_slice(), at_cap.as_slice());
    }

    /// The mapping base is page-aligned (maximum alignment — never an
    /// alignment-1 byte backing). Real mappings only (Miri uses `Vec`).
    #[test]
    #[cfg(not(miri))]
    fn guarded_base_page_aligned() {
        let guarded = GuardedBytes::new(&[0xA5; 16]).expect("guarded allocation");
        assert_eq!(guarded.base.as_ptr() as usize % guarded.guard_len, 0);
        assert!(guarded.guard_len >= 4096, "guard is a full page: {}", guarded.guard_len);
    }

    // -- Guard-fault child battery (real guard pages only) ------------------
    //
    // Re-spawn harness (same shape as STOP-C1 in `native_stop_tests.rs`
    // and the constructor battery): each parent test re-runs this lib
    // test binary via `current_exe` with `--exact <child-entry>
    // --nocapture` plus a scenario selector env var. Miri excluded
    // (no `Command::spawn`, no guard page under the `Vec` fallback).

    /// Scenario selector env var.
    const CHILD_ENV: &str = "PKCS11_PROXY_NG_GUARDED_CHILD";
    /// Exact child entry test path within the lib test binary.
    #[cfg(not(miri))]
    const CHILD_TEST_PATH: &str = "ffi::ffi_conversion::guarded::tests::guarded_child_entry";
    /// Past-extent read offset shared by the fault and sensitivity
    /// scenarios: 8 bytes past a 16-byte declared extent.
    const FAULT_DECLARED: usize = 16;
    const FAULT_OFFSET: usize = FAULT_DECLARED + 8;

    /// Spawn the lib test binary as a guarded child for `scenario`.
    #[cfg(not(miri))]
    fn spawn_guarded_child(scenario: &str) -> std::process::Child {
        let exe = std::env::current_exe().expect("current test exe");
        std::process::Command::new(exe)
            .arg("--exact")
            .arg(CHILD_TEST_PATH)
            .arg("--nocapture")
            .env(CHILD_ENV, scenario)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn guarded child")
    }

    /// Assert the child died by fault (never a normal exit): unix signal
    /// death (SEGV or BUS — both are guard-page faults), Windows access
    /// violation. The `vec-survives` sensitivity scenario below proves
    /// this assertion is non-vacuous.
    #[cfg(not(miri))]
    fn assert_child_faulted(output: &std::process::Output, scenario: &str) {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;
            let signal = output.status.signal();
            assert!(
                signal == Some(libc::SIGSEGV) || signal == Some(libc::SIGBUS),
                "scenario {scenario}: expected fault death (SIGSEGV/SIGBUS), got {:?}",
                output.status
            );
            assert_eq!(output.status.code(), None, "scenario {scenario}: no exit code when killed");
        }
        #[cfg(windows)]
        {
            // Unhandled access violation surfaces as the process exit code.
            const STATUS_ACCESS_VIOLATION: i32 = 0xC000_0005u32 as i32;
            assert_eq!(
                output.status.code(),
                Some(STATUS_ACCESS_VIOLATION),
                "scenario {scenario}: expected access-violation death, got {:?}",
                output.status
            );
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (output, scenario);
            panic!("guarded fault battery needs unix-signal or windows-code attribution");
        }
    }

    /// Child entry: vacuously passes in-process; diverges in the
    /// re-spawned child.
    #[test]
    fn guarded_child_entry() {
        let Ok(scenario) = std::env::var(CHILD_ENV) else {
            return;
        };
        run_guarded_child(&scenario);
    }

    /// Child dispatch. Never panics: setup failures exit with distinct
    /// codes (11 bad scenario). Fault scenarios return only if the read
    /// did NOT fault (parent then fails the pin).
    fn run_guarded_child(scenario: &str) -> ! {
        // Keep the intentional fault quiet: no core dump on unix, no
        // crash dialog on Windows.
        #[cfg(unix)]
        {
            let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            // SAFETY: plain value argument; errors ignored (best effort).
            unsafe {
                libc::setrlimit(libc::RLIMIT_CORE, &no_core);
            }
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Diagnostics::Debug::{
                SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode,
            };
            // SAFETY: process-wide mode flags, no pointers involved.
            unsafe {
                SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
            }
        }
        match scenario {
            "guarded-fault" => {
                let guarded =
                    GuardedBytes::new(&[0xA5; FAULT_DECLARED]).expect("child guarded allocation");
                // SAFETY: deliberately past the declared extent — lands in
                // the guard page and faults (that is the assertion).
                let probe =
                    unsafe { (guarded.as_ptr() as *const u8).add(FAULT_OFFSET).read_volatile() };
                std::hint::black_box(probe);
                // Reached only if the guard page failed to fault.
                std::process::exit(42);
            }
            "guarded-fault-empty" => {
                let guarded = GuardedBytes::new(&[]).expect("child empty allocation");
                // SAFETY: any read at a zero-length extent is past the
                // extent — first guard byte, faults.
                let probe = unsafe { (guarded.as_ptr() as *const u8).read_volatile() };
                std::hint::black_box(probe);
                std::process::exit(42);
            }
            "vec-survives" => {
                // Plain-`Vec` backing WITHOUT a guard page, read at the
                // SAME relative offset: survives, proving the fault pins
                // above distinguish guarded from unguarded (this is the
                // committed RED-proof for the guard page itself). The
                // heap `Vec` (not a stack array) is deliberate: it is
                // the no-guard backing variant the plan names.
                #[allow(clippy::useless_vec)]
                let backing = vec![0u8; FAULT_OFFSET + 64];
                // SAFETY: in-bounds by construction (`FAULT_OFFSET + 64`
                // slack); volatile to match the fault scenarios.
                let probe = unsafe { backing.as_ptr().add(FAULT_OFFSET).read_volatile() };
                std::hint::black_box(probe);
                let _ = writeln!(std::io::stdout(), "READY vec-survives");
                let _ = std::io::stdout().flush();
                std::process::exit(0);
            }
            _ => std::process::exit(11),
        }
    }

    /// S2 §6/§10: a contiguous read past the declared extent faults.
    #[test]
    #[cfg(not(miri))]
    fn guarded_past_extent_read_faults() {
        let child = spawn_guarded_child("guarded-fault");
        let output = child.wait_with_output().expect("reap guarded child");
        assert_child_faulted(&output, "guarded-fault");
    }

    /// Same promise at zero length: any read at an empty extent faults.
    #[test]
    #[cfg(not(miri))]
    fn guarded_empty_extent_read_faults() {
        let child = spawn_guarded_child("guarded-fault-empty");
        let output = child.wait_with_output().expect("reap guarded child");
        assert_child_faulted(&output, "guarded-fault-empty");
    }

    /// Sensitivity pin (committed RED-proof): the SAME past-extent read
    /// against plain-`Vec` backing survives — so the fault pins above
    /// genuinely prove the guard page, not the harness.
    #[test]
    #[cfg(not(miri))]
    fn guarded_fault_test_sensitivity_vec_survives() {
        let child = spawn_guarded_child("vec-survives");
        let output = child.wait_with_output().expect("reap guarded child");
        assert_eq!(
            output.status.code(),
            Some(0),
            "vec-survives: plain backing must survive the read, got {:?}",
            output.status
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("READY"), "vec-survives: READY line missing: {stdout:?}");
    }
}
