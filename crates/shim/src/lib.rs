mod dispatch;
mod function_list;
mod function_list_3_0;
mod function_list_3_2;
mod function_registry;
pub(crate) mod interface_probe;
mod state;

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

        let written = interface_probe::copy_catalog(p_interfaces_list, unsafe { *pul_count });
        unsafe {
            *pul_count = written;
        }
        CKR_OK as CK_RV
    })
}

/// PKCS#11 3.0 — look up a named interface, optionally filtered by version.
///
/// - A null `p_interface_name` returns the default (highest-version) interface.
/// - A null `p_version` matches any version; the highest-version match wins.
/// - If no match is found, sets `*pp_interface = NULL` and returns `CKR_OK`
///   (per PKCS#11 3.0 §5.4).
///
/// # Safety
/// `pp_interface` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInterface(
    p_interface_name: *mut CK_UTF8CHAR,
    p_version: *mut CK_VERSION,
    pp_interface: *mut *mut CK_INTERFACE,
    _flags: CK_FLAGS,
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
            Some(unsafe {
                std::ffi::CStr::from_ptr(p_interface_name as *const std::os::raw::c_char)
            })
        };

        let version = if p_version.is_null() { None } else { Some(unsafe { &*p_version }) };

        let result = interface_probe::find_interface(name, version);
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
mod tests;
