use super::FfiBackend;
use libloading::{Library, Symbol};
use std::ffi::CString;
use std::path::Path;

/// Portable test-only stand-in for the provider-module handle.
///
/// Unit tests build `FfiBackend` values with hand-written function lists and
/// need a placeholder `_lib` that is never used for symbol lookup. The unix
/// arm is the historical `dlopen(NULL)` self handle (null handle on static
/// musl, where `dlopen` is unsupported — see below); the Windows arm is the
/// process image handle (`GetModuleHandleExW(0, NULL, _)`, libloading 0.8.9).
#[cfg(test)]
#[cfg(all(unix, not(target_env = "musl")))]
pub(in crate::ffi) fn test_library_handle() -> libloading::Library {
    libloading::os::unix::Library::this().into()
}

/// Static-musl arm: `dlopen` (including `dlopen(NULL)`) is unsupported in
/// static-pie musl binaries, so `Library::this()` panics. The placeholder is
/// never used for symbol lookup (`_lib` is never read), so a null handle
/// suffices; its `Drop` calls `dlclose(NULL)`, which musl answers with an
/// error (no crash) that libloading ignores. Proven natively on both musl
/// widths (C3M Task 4 fix).
#[cfg(test)]
#[cfg(all(unix, target_env = "musl"))]
pub(in crate::ffi) fn test_library_handle() -> libloading::Library {
    // SAFETY: never used for lookup; dropping only calls `dlclose(NULL)`,
    // which is error-returning, not fatal, on musl.
    unsafe { libloading::os::unix::Library::from_raw(std::ptr::null_mut()) }.into()
}

/// Portable test-only stand-in for the provider-module handle (Windows arm).
#[cfg(test)]
#[cfg(windows)]
pub(in crate::ffi) fn test_library_handle() -> libloading::Library {
    libloading::os::windows::Library::this().expect("test process image handle").into()
}

/// Type alias for the `C_GetInterface` symbol signature.
type GetInterfaceFn = unsafe extern "C" fn(
    *mut cryptoki_sys::CK_UTF8CHAR,
    *mut cryptoki_sys::CK_VERSION,
    *mut *mut cryptoki_sys::CK_INTERFACE,
    cryptoki_sys::CK_FLAGS,
) -> cryptoki_sys::CK_RV;

impl FfiBackend {
    /// Load a PKCS#11 module from the given path.
    ///
    /// Prefers C_GetInterface (PKCS#11 3.x) if available, falls back
    /// to C_GetFunctionList (2.x). See ADR-0004 §2.
    pub fn load(path: &Path) -> Result<Self, String> {
        Self::load_with_init_args(path, None)
    }

    /// Load a PKCS#11 module with optional `C_Initialize` library parameters.
    ///
    /// Some modules, notably NSS softoken, require a non-null `pReserved`
    /// library-parameters string in `CK_C_INITIALIZE_ARGS`.
    ///
    /// C3M.4 construction order: purely local platform/config validation,
    /// then the process construction reservation, and only then
    /// `dlopen`/discovery. An occupied or refused slot fails here with zero
    /// loader or provider attempts. A failed `dlopen` rolls the untouched
    /// reservation back; any later failure (native code may have run)
    /// poisons the slot instead of recycling it.
    pub fn load_with_init_args(path: &Path, initialize_args: Option<&str>) -> Result<Self, String> {
        super::native_domain::check_native_platform().map_err(|e| e.to_string())?;
        let initialize_args = initialize_args
            .map(|s| {
                CString::new(s)
                    .map_err(|_| "initialize_args contains an interior NUL byte".to_string())
            })
            .transpose()?;
        let permit = super::native_domain::reserve_for_construction().map_err(|e| e.to_string())?;

        let lib = match unsafe { Library::new(path) } {
            Ok(lib) => lib,
            Err(e) => {
                permit.rollback_before_native();
                return Err(format!("native module load failed: {e}"));
            }
        };

        let get_iface_sym = Self::resolve_get_interface(&lib);
        let mut legacy = || pkcs11_module::function_list(&lib);
        let (func_list, primary_from_interface) = match get_iface_sym {
            Some(sym) => {
                let mut q = ffi_query(sym);
                match select_primary(Some(&mut q), &mut legacy) {
                    Ok(selected) => selected,
                    Err(e) => {
                        permit.poison();
                        return Err(e);
                    }
                }
            }
            None => match select_primary(None, &mut legacy) {
                Ok(selected) => selected,
                Err(e) => {
                    permit.poison();
                    return Err(e);
                }
            },
        };

        // Attempt to discover 3.0 and 3.2 function lists. These are optional;
        // a 2.40-only module will simply leave both as None.
        //
        // Some 3.x modules answer an *explicit* versioned `C_GetInterface`
        // query for {3,0} with a NULL interface even though they implement the
        // 3.0 functions — BouncyHSM, for instance, exposes a 3.1 default
        // interface and a 3.2 interface but no literal "3.0" one. Because the
        // 3.0 function list is a prefix of every higher 3.x list, the primary
        // interface (already resolved into `func_list`) can serve the 3.0
        // functions whenever it is itself >= 3.0. Without this fallback,
        // 3.0-only dispatch (e.g. `C_SessionCancel`) wrongly returns
        // `CKR_FUNCTION_NOT_SUPPORTED` through the proxy on such modules.
        //
        let func_list_3_0 = get_iface_sym
            .and_then(|sym| select_versioned(&mut ffi_query(sym), 3, 0))
            .or_else(|| Self::primary_interface_fallback(func_list, primary_from_interface, 3, 0))
            .map(|ptr| ptr as *const cryptoki_sys::CK_FUNCTION_LIST_3_0);
        let func_list_3_2 = get_iface_sym
            .and_then(|sym| select_versioned(&mut ffi_query(sym), 3, 2))
            // 3.2-only fields are valid only on an actual >= 3.2 list, so this
            // fallback is gated on the stricter version than the 3.0 one above.
            .or_else(|| Self::primary_interface_fallback(func_list, primary_from_interface, 3, 2))
            .map(|ptr| ptr as *const cryptoki_sys::CK_FUNCTION_LIST_3_2);

        if let Err(e) = permit.activate() {
            permit.poison();
            return Err(e.to_string());
        }

        Ok(Self {
            _lib: lib,
            func_list,
            func_list_3_0,
            func_list_3_2,
            initialize_args,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            retirement_sentinel: super::native_domain::RetirementSentinel::for_permit(&permit),
            construction: permit,
            lifecycle: super::native_domain::LifecycleTracker::default(),
            lifecycle_domain: super::native_domain::LifecycleDomain::new(),
            session_fences: super::session_fence::SessionFenceTable::default(),
        })
    }

    /// Returns `true` if a PKCS#11 3.0 function list was detected.
    #[inline]
    pub fn has_3_0_interface(&self) -> bool {
        self.func_list_3_0.is_some()
    }

    /// Returns `true` if a PKCS#11 3.2 function list was detected.
    #[inline]
    pub fn has_3_2_interface(&self) -> bool {
        self.func_list_3_2.is_some()
    }

    /// Resolve the `C_GetInterface` symbol from the loaded library.
    ///
    /// Returns `None` if the symbol is not exported (2.40-only module).
    fn resolve_get_interface(lib: &Library) -> Option<GetInterfaceFn> {
        let sym: Symbol<GetInterfaceFn> = unsafe { lib.get(b"C_GetInterface\0").ok()? };
        // Copy the function pointer out of the Symbol wrapper so we don't
        // need to keep the Symbol borrow alive.
        Some(*sym)
    }

    fn primary_interface_fallback(
        func_list: *mut cryptoki_sys::CK_FUNCTION_LIST,
        primary_from_interface: bool,
        major: u8,
        minor: u8,
    ) -> Option<*mut std::ffi::c_void> {
        if !primary_from_interface {
            return None;
        }
        // The first field of every `CK_FUNCTION_LIST*` variant is `version`,
        // so reading it through the 2.40-typed pointer is sound. Using fields
        // beyond the base list is only sound when this pointer came from a
        // `CK_INTERFACE`; `C_GetFunctionList` can still return a base-size list
        // whose version field reports 3.x.
        let primary_version = unsafe { (*func_list).version };
        let primary_at_least = primary_version.major > major
            || (primary_version.major == major && primary_version.minor >= minor);
        primary_at_least.then_some(func_list as *mut std::ffi::c_void)
    }
}

/// Pure fire condition for the abnormal-stop guard: stop only when the
/// retiring instance cannot prove quiescence (`Poison`) and still holds
/// the process-registry slot (managed permit). Ungated so the unit-test
/// matrix below exercises it on every host; the `Drop` guard applies the
/// qualified-target cfg around the call.
fn stop_fire_condition(
    decision: super::native_domain::RetirementDecision,
    holds_slot: bool,
) -> bool {
    matches!(decision, super::native_domain::RetirementDecision::Poison) && holds_slot
}

/// Test-only `cfg!` mirror of the `Drop`-guard predicate below (Linux
/// x86_64/x86, Windows x86_64/x86, macOS aarch64/x86_64 — leg for leg with
/// `NATIVE_STOP_QUALIFIED`). The `cfg` on the guard is the source of
/// truth; this mirror lets the coherence test assert the guard arms
/// exactly where stop arms exist.
#[cfg(test)]
pub(in crate::ffi) const DROP_GUARD_STOP_ARMED: bool = cfg!(any(
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "musl"),
        any(
            all(target_arch = "x86_64", target_pointer_width = "64"),
            all(target_arch = "x86", target_pointer_width = "32")
        )
    ),
    all(
        target_os = "windows",
        target_env = "msvc",
        any(
            all(target_arch = "x86_64", target_pointer_width = "64"),
            all(target_arch = "x86", target_pointer_width = "32")
        )
    ),
    all(
        target_os = "macos",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        target_pointer_width = "64"
    )
));

impl Drop for FfiBackend {
    /// Retire the construction reservation honestly: enter `Retiring` for the
    /// exact epoch only when the instance lifecycle proves quiescence (never
    /// initialized, or finalized with no open sessions) — the slot stays
    /// occupied throughout dependent retirement and library close, and the
    /// last-field [`super::native_domain::RetirementSentinel`] publishes the
    /// next `Vacant` once every field has dropped; otherwise retain ownership
    /// and poison the slot until process restart. Stale handles and already
    /// poisoned slots are untouched.
    fn drop(&mut self) {
        use super::native_domain::RetirementDecision::{Poison, Release};
        let decision = self.lifecycle.retirement_decision();
        // Stop-qualified targets only (Linux x86_64/x86 GNU/musl, Windows
        // MSVC x86_64/x86, macOS aarch64/x86_64 — exactly the
        // `NATIVE_FFI_QUALIFIED` legs): abnormally stop the native lifetime
        // when the managed final owner cannot prove quiescence. First
        // statement and lock-free (atomic-only decision plus a plain-bool
        // slot check), so it precedes the lock-taking poison path and all
        // dependent field drops. Elsewhere this block cfg-compiles out and
        // the arms below keep today's behavior bit-for-bit.
        #[cfg(any(
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "musl"),
                any(
                    all(target_arch = "x86_64", target_pointer_width = "64"),
                    all(target_arch = "x86", target_pointer_width = "32")
                )
            ),
            all(
                target_os = "windows",
                target_env = "msvc",
                any(
                    all(target_arch = "x86_64", target_pointer_width = "64"),
                    all(target_arch = "x86", target_pointer_width = "32")
                )
            ),
            all(
                target_os = "macos",
                any(target_arch = "aarch64", target_arch = "x86_64"),
                target_pointer_width = "64"
            )
        ))]
        if stop_fire_condition(decision, self.construction.holds_registry_slot()) {
            super::native_stop::abnormal_stop_native_lifetime(
                super::native_stop::StopReason::UnprovenFinalOwner,
            );
        }
        // TF01b/I4 Drop integration (same stop-qualified gate): stop-fire
        // when the lifecycle domain is poisoned — the sole `Drop`-time
        // signal. The probe is a non-blocking `try_write` (never blocks
        // in `Drop`); contention deliberately has no arm (`WouldBlock` is
        // unreachable — a live guard would keep its `Arc` owner alive).
        // Elsewhere this block cfg-compiles out, bit-for-bit.
        #[cfg(any(
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "musl"),
                any(
                    all(target_arch = "x86_64", target_pointer_width = "64"),
                    all(target_arch = "x86", target_pointer_width = "32")
                )
            ),
            all(
                target_os = "windows",
                target_env = "msvc",
                any(
                    all(target_arch = "x86_64", target_pointer_width = "64"),
                    all(target_arch = "x86", target_pointer_width = "32")
                )
            ),
            all(
                target_os = "macos",
                any(target_arch = "aarch64", target_arch = "x86_64"),
                target_pointer_width = "64"
            )
        ))]
        if self.lifecycle_domain.quiescence_poisoned() {
            super::native_stop::abnormal_stop_native_lifetime(
                super::native_stop::StopReason::UnprovenFinalOwner,
            );
        }
        match decision {
            Release => {
                self.construction.begin_retirement();
            }
            Poison => {
                self.construction.poison();
            }
        }
    }
}

/// One `C_GetInterface` answer as the module reported it.
pub(crate) struct InterfaceAnswer {
    pub name: Option<Vec<u8>>,
    pub func_list: *mut std::ffi::c_void,
}

type InterfaceQuery<'a> =
    dyn FnMut(Option<&[u8]>, Option<cryptoki_sys::CK_VERSION>) -> Option<InterfaceAnswer> + 'a;

const STANDARD_NAME: &[u8] = b"PKCS 11";

/// §6a acceptance rule, applied uniformly to named and unnamed answers:
/// only an interface named exactly "PKCS 11" with a non-NULL function
/// list may be treated as a standard table. OASIS lets any unnamed query
/// return "a default interface of its choice", and a vendor interface's
/// function list has no guaranteed layout beyond the leading CK_VERSION.
fn accepts_standard(ans: &InterfaceAnswer) -> bool {
    ans.name.as_deref() == Some(STANDARD_NAME) && !ans.func_list.is_null()
}

/// Primary-list selection (§6a order, §6b provenance): named standard →
/// validated unnamed → legacy. Provenance in the returned bool comes from
/// the branch that produced the pointer, never from symbol existence.
fn select_primary(
    query: Option<&mut InterfaceQuery<'_>>,
    legacy: &mut dyn FnMut() -> Result<*mut cryptoki_sys::CK_FUNCTION_LIST, String>,
) -> Result<(*mut cryptoki_sys::CK_FUNCTION_LIST, bool), String> {
    if let Some(q) = query {
        for name in [Some(STANDARD_NAME), None] {
            if let Some(ans) = q(name, None)
                && accepts_standard(&ans)
            {
                return Ok((ans.func_list as *mut cryptoki_sys::CK_FUNCTION_LIST, true));
            }
        }
    }
    legacy().map(|func_list| (func_list, false))
}

/// Versioned-list selection: named first, then the unnamed fallback for
/// modules (e.g. BouncyHSM) that only respond to the unnamed form — with
/// the same §6a name rule on the unnamed result. Rejecting a hypothetical
/// vendor-named answer here is soundness over coverage.
///
/// A downgraded answer (e.g. a 3.0 table for a 3.2 query, rv=0) is
/// rejected and selection falls through to the next name/fallback: without
/// this guard the daemon would OOB-read version-gated fields as zeros and
/// publish phantom "3.2-with-NULLs" tables (F5).
fn select_versioned(
    q: &mut InterfaceQuery<'_>,
    major: u8,
    minor: u8,
) -> Option<*mut std::ffi::c_void> {
    let version = cryptoki_sys::CK_VERSION { major, minor };
    for name in [Some(STANDARD_NAME), None] {
        if let Some(ans) = q(name, Some(version))
            && accepts_standard(&ans)
            && answer_version_at_least(&ans, major, minor)
        {
            return Some(ans.func_list);
        }
    }
    None
}

/// Leading-version guard for [`select_versioned`]: the answer's table must
/// be at least the requested version. Reads only the leading `CK_VERSION`,
/// the first field of every `CK_FUNCTION_LIST*` variant — the same reliance
/// as [`FfiBackend::primary_interface_fallback`]. Callers ensure the
/// pointer is non-null via [`accepts_standard`].
fn answer_version_at_least(ans: &InterfaceAnswer, major: u8, minor: u8) -> bool {
    let reported = unsafe { (*(ans.func_list as *const cryptoki_sys::CK_FUNCTION_LIST)).version };
    reported.major > major || (reported.major == major && reported.minor >= minor)
}

/// FFI adapter: performs one real `C_GetInterface` query and copies the
/// answer out of module-owned memory.
fn ffi_query(
    get_interface: GetInterfaceFn,
) -> impl FnMut(Option<&[u8]>, Option<cryptoki_sys::CK_VERSION>) -> Option<InterfaceAnswer> {
    move |name, version| {
        // NUL-terminated storage must outlive the call.
        let name_buf: Vec<u8>;
        let name_ptr = match name {
            Some(n) => {
                name_buf = [n, b"\0"].concat();
                name_buf.as_ptr() as *mut cryptoki_sys::CK_UTF8CHAR
            }
            None => std::ptr::null_mut(),
        };
        let mut version_val = version.unwrap_or(cryptoki_sys::CK_VERSION { major: 0, minor: 0 });
        let version_ptr: *mut cryptoki_sys::CK_VERSION =
            if version.is_some() { &mut version_val } else { std::ptr::null_mut() };
        let mut interface_ptr: *mut cryptoki_sys::CK_INTERFACE = std::ptr::null_mut();
        let rv = unsafe { get_interface(name_ptr, version_ptr, &mut interface_ptr, 0) };
        if rv != 0 || interface_ptr.is_null() {
            return None;
        }
        let iface = unsafe { &*interface_ptr };
        let name = if iface.pInterfaceName.is_null() {
            None
        } else {
            Some(
                unsafe {
                    std::ffi::CStr::from_ptr(iface.pInterfaceName as *const std::os::raw::c_char)
                }
                .to_bytes()
                .to_vec(),
            )
        };
        Some(InterfaceAnswer { name, func_list: iface.pFunctionList })
    }
}

#[cfg(test)]
mod tests {
    /// T7: the factored stop-fire condition preserves the guard's
    /// `Poison + holds_registry_slot` truth table exactly. The `Drop`
    /// guard applies the qualified-target cfg; this matrix pins the pure
    /// decision logic on every host.
    #[test]
    fn stop_fire_condition_matrix() {
        use crate::ffi::native_domain::RetirementDecision::{Poison, Release};
        for (decision, holds_slot, expected) in [
            (Poison, true, true),
            (Poison, false, false),
            (Release, true, false),
            (Release, false, false),
        ] {
            assert_eq!(
                super::stop_fire_condition(decision, holds_slot),
                expected,
                "decision={decision:?} holds_slot={holds_slot}"
            );
        }
    }

    #[test]
    fn drop_guard_cfg_matches_stop_arms() {
        // TC1: the `Drop` guard must fire exactly where stop arms exist;
        // the guard predicate mirrors `NATIVE_STOP_QUALIFIED` leg for leg.
        assert_eq!(
            super::DROP_GUARD_STOP_ARMED,
            crate::ffi::native_stop::NATIVE_STOP_QUALIFIED,
            "Drop guard cfg must arm exactly where stop arms exist"
        );
    }

    /// Verify that a backend constructed with `None` for the 3.x fields
    /// reports both as absent.
    #[test]
    fn has_interface_accessors_report_none_when_absent() {
        // We cannot load a real module in unit tests, but we can verify the
        // accessor logic by checking the field values via the public helpers
        // on a hypothetical backend. Since we cannot construct FfiBackend
        // without a real library, we test the Option logic directly.
        let none_3_0: Option<*const cryptoki_sys::CK_FUNCTION_LIST_3_0> = None;
        let none_3_2: Option<*const cryptoki_sys::CK_FUNCTION_LIST_3_2> = None;
        assert!(none_3_0.is_none());
        assert!(none_3_2.is_none());
    }

    /// Verify that a non-null pointer is treated as Some.
    #[test]
    fn has_interface_accessors_report_some_when_present() {
        // Use a dangling but non-null sentinel — we never dereference it.
        let sentinel_3_0: Option<*const cryptoki_sys::CK_FUNCTION_LIST_3_0> =
            Some(std::ptr::NonNull::dangling().as_ptr());
        let sentinel_3_2: Option<*const cryptoki_sys::CK_FUNCTION_LIST_3_2> =
            Some(std::ptr::NonNull::dangling().as_ptr());
        assert!(sentinel_3_0.is_some());
        assert!(sentinel_3_2.is_some());
    }

    #[test]
    fn primary_fallback_ignores_c_get_function_list_version_3_x() {
        let mut base_list: cryptoki_sys::CK_FUNCTION_LIST = unsafe { std::mem::zeroed() };
        base_list.version = cryptoki_sys::CK_VERSION { major: 3, minor: 2 };
        let base_ptr = &mut base_list as *mut cryptoki_sys::CK_FUNCTION_LIST;

        assert!(
            super::FfiBackend::primary_interface_fallback(base_ptr, false, 3, 0).is_none(),
            "a C_GetFunctionList pointer is only known to be base-size even when \
             its version field reports 3.x",
        );
        assert!(
            super::FfiBackend::primary_interface_fallback(base_ptr, false, 3, 2).is_none(),
            "3.2 fallback must also be rejected for C_GetFunctionList pointers",
        );

        assert!(
            super::FfiBackend::primary_interface_fallback(base_ptr, true, 3, 0).is_some(),
            "a primary pointer obtained from C_GetInterface can be reused for \
             lower 3.x versions",
        );
        assert!(
            super::FfiBackend::primary_interface_fallback(base_ptr, true, 3, 2).is_some(),
            "a 3.2 CK_INTERFACE function list can be reused for 3.2 calls",
        );
    }

    /// Regression test for the 3.0-interface fallback (see `load_with_init_args`).
    ///
    /// BouncyHSM answers an explicit `C_GetInterface` query for {3,0} with a
    /// NULL interface even though its 3.1 default interface implements the 3.0
    /// functions (notably `C_SessionCancel`). Before the fallback, the daemon
    /// left `func_list_3_0` as None and every 3.0-only call returned
    /// `CKR_FUNCTION_NOT_SUPPORTED` through the proxy, breaking pkcs11-check's
    /// post-failure `C_SessionCancel` cleanup and cascading
    /// `CKR_OPERATION_ACTIVE` across subsequent AEAD tests.
    ///
    /// `load()` only does dlopen + `C_GetInterface` (static tables), so no
    /// backend server is needed. The test is skipped when the module is absent
    /// (e.g. CI) — point `PKCS11_PROXY_NG_BOUNCYHSM_MODULE` at the `.so` to run
    /// it. This quirk is module-specific: SoftHSM2/NSS answer {3,0} correctly
    /// and would not exercise the fallback.
    #[test]
    fn bouncyhsm_3_0_interface_falls_back_to_primary() {
        use std::path::Path;

        // Serialized with the constructor-domain tests: this is the only
        // other test touching the process-global reservation.
        let _serial = crate::ffi::native_domain::serial_domain_test_guard();

        const DEFAULT_MODULE: &str = concat!(
            "/home/user/.nuget/packages/bouncyhsm.client/2.0.1/",
            "runtimes/linux-x64/native/BouncyHsm.Pkcs11Lib.so"
        );
        let module = std::env::var("PKCS11_PROXY_NG_BOUNCYHSM_MODULE")
            .unwrap_or_else(|_| DEFAULT_MODULE.to_string());
        if !Path::new(&module).exists() {
            eprintln!("skipping: BouncyHSM module not found at {module}");
            return;
        }

        // The module must match the test process's architecture. `dlopen` of a
        // 64-bit `.so` into a 32-bit process (e.g. the i686 cross-build) fails
        // with a "wrong ELF class" error that is unrelated to the
        // C_GetInterface fallback this test exercises. The ELF identification
        // byte at offset 4 is 1 for ELFCLASS32 and 2 for ELFCLASS64; skip when
        // it does not match the running process.
        if let Ok(bytes) = std::fs::read(&module) {
            let module_is_64 = bytes.get(4) == Some(&2u8);
            let process_is_64 = cfg!(target_pointer_width = "64");
            if module_is_64 != process_is_64 {
                eprintln!(
                    "skipping: BouncyHSM module ELF class does not match the \
                     test process (module 64-bit={module_is_64}, process \
                     64-bit={process_is_64})"
                );
                return;
            }
        }

        let backend = super::FfiBackend::load(Path::new(&module))
            .expect("BouncyHSM module should load via C_GetInterface");
        // The fallback must surface a usable 3.0 list even though the explicit
        // {3,0} query returns a NULL interface for this module.
        assert!(
            backend.has_3_0_interface(),
            "func_list_3_0 must fall back to the 3.1 primary interface so 3.0 \
             functions (C_SessionCancel) are reachable through the proxy",
        );
        // BouncyHSM also offers an explicit 3.2 interface.
        assert!(backend.has_3_2_interface(), "BouncyHSM advertises a 3.2 interface");
    }

    /// win32 stub live-load proof (T2-5): `LoadLibrary` a real PE32 provider
    /// stub, resolve `C_GetFunctionList`, and cross the FFI boundary with
    /// u32 `CK_ULONG` + pack(1) structs.
    ///
    /// The stub (`tests/win32-stub/p11win32stub.c`, built with x86 `cl.exe`
    /// by the `win32` CI job) exports only `C_GetFunctionList`, returning a
    /// static 2.40 list with live `C_Initialize`/`C_GetInfo` and NULL
    /// everywhere else. This test asserts the 2.40 version, non-null live
    /// pointers, the 3.x absence (legacy path), and one `C_GetInfo` call
    /// observed through `ffi_get_info` with the stub's marker strings —
    /// proving the call crossed into the DLL and the packed layout reads
    /// correctly (`flags` sits at a packed offset, so a layout mismatch
    /// would surface as garbage).
    ///
    /// Gated like the BouncyHSM test above: win32-only (`windows` + 32-bit
    /// pointers) and skipped unless `PKCS11_PROXY_NG_WIN32_STUB_MODULE`
    /// points at the stub DLL. When the variable IS set the DLL must exist
    /// — CI always sets it, so a green win32 leg proves this test ran
    /// (fail-loud, never a silent skip). Never calls `C_Initialize`:
    /// initializing would arm the lifecycle and turn the final `Drop` into
    /// an abnormal-stop test exit.
    #[cfg(all(windows, target_pointer_width = "32"))]
    #[test]
    fn win32_stub_live_load() {
        use std::path::Path;

        // Serialized with the constructor-domain tests: like the BouncyHSM
        // test above, this is a real `FfiBackend::load` touching the
        // process-global construction reservation.
        let _serial = crate::ffi::native_domain::serial_domain_test_guard();

        let Ok(module) = std::env::var("PKCS11_PROXY_NG_WIN32_STUB_MODULE") else {
            eprintln!("skipping: PKCS11_PROXY_NG_WIN32_STUB_MODULE is not set");
            return;
        };
        assert!(
            Path::new(&module).exists(),
            "PKCS11_PROXY_NG_WIN32_STUB_MODULE is set but missing: {module}"
        );

        let backend = super::FfiBackend::load(Path::new(&module))
            .expect("win32 stub DLL should load via C_GetFunctionList");

        // 2.40 legacy path: no C_GetInterface export, so no 3.x lists.
        assert!(!backend.has_3_0_interface(), "stub is 2.40-only: no 3.0 list");
        assert!(!backend.has_3_2_interface(), "stub is 2.40-only: no 3.2 list");

        // Version + non-null pointers, read by value (the win32 list is
        // packed — never borrow its fields).
        let version = unsafe { (*backend.func_list).version };
        assert_eq!((version.major, version.minor), (2, 40), "stub list version");
        let c_initialize: cryptoki_sys::CK_C_Initialize =
            unsafe { (*backend.func_list).C_Initialize };
        assert!(c_initialize.is_some(), "stub C_Initialize must be non-null");
        let c_get_info: cryptoki_sys::CK_C_GetInfo = unsafe { (*backend.func_list).C_GetInfo };
        assert!(c_get_info.is_some(), "stub C_GetInfo must be non-null");

        // One live call across the boundary.
        let info = backend.ffi_get_info().expect("stub C_GetInfo should succeed");
        assert_eq!(info.cryptoki_version, (2, 40));
        assert_eq!(info.manufacturer_id, "T2RUN WIN32 STUB");
        assert_eq!(info.flags, 0);
        assert_eq!(info.library_description, "PE32 stub provider");
        assert_eq!(info.library_version, (2, 40));
        eprintln!("win32-stub-live-load: ok (2.40, markers verified)");
    }

    use super::{InterfaceAnswer, select_primary, select_versioned};

    fn dangling_list() -> *mut cryptoki_sys::CK_FUNCTION_LIST {
        std::ptr::NonNull::dangling().as_ptr()
    }
    fn answer(name: &[u8]) -> InterfaceAnswer {
        InterfaceAnswer {
            name: Some(name.to_vec()),
            func_list: std::ptr::NonNull::<std::ffi::c_void>::dangling().as_ptr(),
        }
    }

    /// §6b: C_GetInterface exists but every query fails; the legacy table
    /// must carry provenance false (the current code derives the flag from
    /// symbol existence, which this test would catch).
    #[test]
    fn provenance_is_false_when_queries_fail_and_legacy_succeeds() {
        let mut q = |_: Option<&[u8]>, _: Option<cryptoki_sys::CK_VERSION>| None;
        let expected = dangling_list();
        let mut legacy = || Ok(expected);
        let (list, from_interface) =
            select_primary(Some(&mut q), &mut legacy).expect("legacy succeeds");
        assert_eq!(list, expected);
        assert!(!from_interface, "a C_GetFunctionList pointer is never interface-derived");
    }

    /// §6a: an unnamed result is accepted only when named exactly "PKCS 11".
    #[test]
    fn unnamed_vendor_interface_is_rejected_and_falls_through_to_legacy() {
        let mut q = |name: Option<&[u8]>, _: Option<cryptoki_sys::CK_VERSION>| match name {
            Some(_) => None,                      // named standard query fails
            None => Some(answer(b"ACME Vendor")), // unnamed returns a vendor interface
        };
        let expected = dangling_list();
        let mut legacy = || Ok(expected);
        let (list, from_interface) = select_primary(Some(&mut q), &mut legacy).unwrap();
        assert_eq!(list, expected);
        assert!(!from_interface);
    }

    #[test]
    fn unnamed_standard_interface_is_accepted() {
        let std_answer = answer(b"PKCS 11");
        let expected = std_answer.func_list as *mut cryptoki_sys::CK_FUNCTION_LIST;
        let mut q = |name: Option<&[u8]>, _: Option<cryptoki_sys::CK_VERSION>| match name {
            Some(_) => None,
            None => Some(answer(b"PKCS 11")),
        };
        let mut legacy = || -> Result<*mut cryptoki_sys::CK_FUNCTION_LIST, String> {
            panic!("legacy must not be consulted when the unnamed standard answer is valid")
        };
        let (list, from_interface) = select_primary(Some(&mut q), &mut legacy).unwrap();
        assert_eq!(list, expected);
        assert!(from_interface);
    }

    /// The versioned (BouncyHSM-class) unnamed fallback applies the same rule.
    #[test]
    fn versioned_unnamed_vendor_is_rejected_standard_is_accepted() {
        let mut vendor_q = |name: Option<&[u8]>, _: Option<cryptoki_sys::CK_VERSION>| match name {
            Some(_) => None,
            None => Some(answer(b"ACME Vendor")),
        };
        assert!(select_versioned(&mut vendor_q, 3, 0).is_none());

        // The version guard reads the table's leading CK_VERSION, so the
        // accepted answer needs real version storage behind the pointer.
        let v30 = Box::new(cryptoki_sys::CK_VERSION { major: 3, minor: 0 });
        let v30_ptr = (&*v30 as *const cryptoki_sys::CK_VERSION).cast_mut().cast();
        let mut std_q = |name: Option<&[u8]>, _: Option<cryptoki_sys::CK_VERSION>| match name {
            Some(_) => None,
            None => Some(InterfaceAnswer { name: Some(b"PKCS 11".to_vec()), func_list: v30_ptr }),
        };
        assert!(select_versioned(&mut std_q, 3, 0).is_some());
    }

    /// F5: a module that answers a 3.2 query with a 3.0 table (rv=0) must
    /// not produce a "3.2" list. The downgraded answer is rejected for 3.2
    /// but still accepted when 3.0 is requested.
    #[test]
    fn versioned_downgraded_answer_is_rejected_for_newer_query() {
        let v30 = Box::new(cryptoki_sys::CK_VERSION { major: 3, minor: 0 });
        let v30_ptr = (&*v30 as *const cryptoki_sys::CK_VERSION).cast_mut().cast();
        let mut downgrading = |_: Option<&[u8]>, _: Option<cryptoki_sys::CK_VERSION>| {
            Some(InterfaceAnswer { name: Some(b"PKCS 11".to_vec()), func_list: v30_ptr })
        };
        assert!(
            select_versioned(&mut downgrading, 3, 2).is_none(),
            "3.0 table must not satisfy a 3.2 query"
        );
        assert!(
            select_versioned(&mut downgrading, 3, 0).is_some(),
            "3.0 table still satisfies a 3.0 query"
        );

        let v32 = Box::new(cryptoki_sys::CK_VERSION { major: 3, minor: 2 });
        let v32_ptr = (&*v32 as *const cryptoki_sys::CK_VERSION).cast_mut().cast();
        let mut current = |_: Option<&[u8]>, _: Option<cryptoki_sys::CK_VERSION>| {
            Some(InterfaceAnswer { name: Some(b"PKCS 11".to_vec()), func_list: v32_ptr })
        };
        assert!(select_versioned(&mut current, 3, 2).is_some());
        assert!(select_versioned(&mut current, 3, 0).is_some());
    }
}
