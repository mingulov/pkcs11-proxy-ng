mod dispatch;
mod function_list;
mod function_list_3_0;
mod function_list_3_2;
mod function_registry;
pub(crate) mod interface_probe;
mod state;

/// Test-only surface used by `crates/shim/tests/stress_registry.rs`
/// and similar concurrency-audit fixtures. Not part
/// of the shim's public API; do NOT depend on it from consumers.
#[doc(hidden)]
pub mod __test_api {
    pub use crate::state::{
        is_initialized, mark_finalized, mark_initialized, mechanism_registry,
        replace_mechanism_registry, runtime,
    };
}

use crate::dispatch::general::catch_panics;
use cryptoki_sys::*;

// PKCS#11 requires C_GetFunctionList, C_GetInterfaceList, and C_GetInterface
// to be callable before C_Initialize (pre-init introspection).  All three are
// #[no_mangle] exports so they are always present in the shared-library symbol
// table.
//
// Each pre-init function calls `interface_probe::ensure_probed()` to
// attempt a best-effort probe of the backend's interface capabilities.
// If the daemon is reachable, the probe populates patched function lists
// that NULL-out any slots the backend does not support and only advertise
// the interfaces the backend actually has.  If the daemon is not yet
// running, the probe silently fails and the static all-non-null fallback
// lists are used.  After C_Initialize, `reprobe()` refreshes the cache.

/// PKCS#11 entry point — called by applications to get the 2.40 function list.
///
/// # Safety
/// `pp_function_list` must be a valid, non-null pointer to a `CK_FUNCTION_LIST` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    catch_panics(|| {
        if pp_function_list.is_null() {
            return CKR_ARGUMENTS_BAD as CK_RV;
        }
        // Best-effort probe — ignore errors (daemon may not be up yet).
        let _ = interface_probe::ensure_probed();
        unsafe {
            *pp_function_list = interface_probe::get_function_list();
        }
        CKR_OK as CK_RV
    })
}

// ---------------------------------------------------------------------------
// PKCS#11 3.0 Interface catalog
// ---------------------------------------------------------------------------

/// PKCS#11 3.0 — enumerate available interfaces.
///
/// A null `p_interfaces_list` is used to query the count only.
///
/// # Safety
/// If non-null, `p_interfaces_list` must point to at least `*pul_count`
/// writable `CK_INTERFACE` slots on entry; on success `*pul_count` is set
/// to the actual count written.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInterfaceList(
    p_interfaces_list: *mut CK_INTERFACE,
    pul_count: *mut CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        if pul_count.is_null() {
            return CKR_ARGUMENTS_BAD as CK_RV;
        }

        // Best-effort probe — ignore errors (daemon may not be up yet).
        let _ = interface_probe::ensure_probed();
        let n = interface_probe::interface_count();

        if p_interfaces_list.is_null() {
            // Caller is querying the count only.
            unsafe {
                *pul_count = n;
            }
            return CKR_OK as CK_RV;
        }

        if unsafe { *pul_count } < n {
            // Spec: "In either case, the value *pulCount is set to hold the number
            // of interfaces."
            unsafe {
                *pul_count = n;
            }
            return CKR_BUFFER_TOO_SMALL as CK_RV;
        }

        // SAFETY (W1-L1-02): `p_interfaces_list` is non-null here (the
        // null case returned via the count-only path above) and the
        // caller-declared `*pul_count >= n` entries were checked above;
        // `copy_catalog` re-checks the length and fails safe on short.
        let written = unsafe { interface_probe::copy_catalog(p_interfaces_list, *pul_count) };
        unsafe {
            *pul_count = written;
        }
        CKR_OK as CK_RV
    })
}

/// PKCS#11 3.0 — look up a named interface, optionally filtered by version and flags.
///
/// - A null `p_interface_name` returns the default (highest-version) interface.
/// - A null `p_version` matches any version; the highest-version match wins.
/// - If no match is found, sets `*pp_interface = NULL` and returns `CKR_OK`
///   (per PKCS#11 3.0 §5.4).
/// - Requested flags must be a subset of the returned interface's advertised flags.
/// - Names longer than 256 content bytes (no NUL in the bound) are rejected
///   with `CKR_ARGUMENTS_BAD` (W1-C6-06).
///
/// # Safety
/// `pp_interface` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInterface(
    p_interface_name: *mut CK_UTF8CHAR,
    p_version: *mut CK_VERSION,
    pp_interface: *mut *mut CK_INTERFACE,
    flags: CK_FLAGS,
) -> CK_RV {
    catch_panics(|| {
        if pp_interface.is_null() {
            return CKR_ARGUMENTS_BAD as CK_RV;
        }

        // Best-effort probe — ignore errors (daemon may not be up yet).
        let _ = interface_probe::ensure_probed();

        let name = if p_interface_name.is_null() {
            None
        } else {
            // W1-C6-06: bounded scan (256 content bytes) — an unterminated
            // or overlong caller name is a loud ARGUMENTS_BAD, never an
            // unbounded `CStr::from_ptr` read.
            match unsafe {
                crate::dispatch::general::helpers::read_bounded_cstr(
                    p_interface_name as *const std::ffi::c_char,
                )
            } {
                Ok(name) => Some(name),
                Err(_) => return CKR_ARGUMENTS_BAD as CK_RV,
            }
        };

        let version = if p_version.is_null() { None } else { Some(unsafe { &*p_version }) };

        let result = interface_probe::find_interface(name, version, flags);
        unsafe {
            *pp_interface = result;
        }
        CKR_OK as CK_RV
    })
}

// ---------------------------------------------------------------------------
// Tests — pre-C_Initialize introspection contract (Item 54)
//
// All three entry points (C_GetFunctionList, C_GetInterfaceList,
// C_GetInterface) must work before C_Initialize is called.  They are
// shim-local and must not touch any transport state.
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(not(miri))] // daemon-based integration tests need real sockets
mod tests;
