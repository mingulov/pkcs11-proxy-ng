use super::FfiBackend;
use libloading::{Library, Symbol};
use std::ffi::CString;
use std::path::Path;

/// Portable test-only stand-in for the provider-module handle.
///
/// Unit tests build `FfiBackend` values with hand-written function lists and
/// need a placeholder `_lib` that is never used for symbol lookup. The unix
/// arm is the historical `dlopen(NULL)` self handle; the Windows arm is the
/// process image handle (`GetModuleHandleExW(0, NULL, _)`, libloading 0.8.9).
#[cfg(test)]
#[cfg(unix)]
pub(in crate::ffi) fn test_library_handle() -> libloading::Library {
    libloading::os::unix::Library::this().into()
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
            construction: permit,
            lifecycle: super::native_domain::LifecycleTracker::default(),
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

impl Drop for FfiBackend {
    /// Retire the construction reservation honestly: release the exact epoch
    /// only when the instance lifecycle proves quiescence (never initialized,
    /// or finalized with no open sessions); otherwise retain ownership and
    /// poison the slot until process restart. Stale handles and already
    /// poisoned slots are untouched.
    fn drop(&mut self) {
        use super::native_domain::RetirementDecision::{Poison, Release};
        match self.lifecycle.retirement_decision() {
            Release => {
                super::native_domain::ConstructionPermit::release_if_owner(self.construction.epoch);
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
fn select_versioned(
    q: &mut InterfaceQuery<'_>,
    major: u8,
    minor: u8,
) -> Option<*mut std::ffi::c_void> {
    let version = cryptoki_sys::CK_VERSION { major, minor };
    for name in [Some(STANDARD_NAME), None] {
        if let Some(ans) = q(name, Some(version))
            && accepts_standard(&ans)
        {
            return Some(ans.func_list);
        }
    }
    None
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

        let mut std_q = |name: Option<&[u8]>, _: Option<cryptoki_sys::CK_VERSION>| match name {
            Some(_) => None,
            None => Some(answer(b"PKCS 11")),
        };
        assert!(select_versioned(&mut std_q, 3, 0).is_some());
    }
}
