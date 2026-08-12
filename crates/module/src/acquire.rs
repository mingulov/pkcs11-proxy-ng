//! Raw table acquisition — the three pre-initialize entry points.

use cryptoki_sys::{CK_INTERFACE, CK_RV, CK_ULONG, CKR_BUFFER_TOO_SMALL, CKR_OK};
use libloading::{Library, Symbol};

/// Resolve `C_GetFunctionList` and return the module's legacy 2.40 table.
///
/// Never calls `C_Initialize`. The returned pointer aliases the module's
/// static data and is valid while `lib` stays loaded.
pub fn function_list(lib: &Library) -> Result<*mut cryptoki_sys::CK_FUNCTION_LIST, String> {
    let get_func_list: Symbol<
        unsafe extern "C" fn(*mut *mut cryptoki_sys::CK_FUNCTION_LIST) -> cryptoki_sys::CK_RV,
    > = unsafe {
        lib.get(b"C_GetFunctionList\0").map_err(|e| format!("C_GetFunctionList not found: {e}"))?
    };

    let mut func_list: *mut cryptoki_sys::CK_FUNCTION_LIST = std::ptr::null_mut();
    let rv = unsafe { get_func_list(&mut func_list) };
    if rv != 0 {
        return Err(format!("C_GetFunctionList returned 0x{rv:08x}"));
    }
    if func_list.is_null() {
        return Err("C_GetFunctionList returned null".into());
    }
    Ok(func_list)
}

/// One interface exactly as the module reported it. Nothing is resolved,
/// dereferenced, deduplicated, or reinterpreted; NULL fields are preserved.
#[derive(Debug)]
pub struct RawInterface {
    /// May be NULL or unreadable. Acquisition never follows it.
    pub name_ptr: *mut cryptoki_sys::CK_UTF8CHAR,
    /// May be NULL or unreadable. Acquisition never follows it.
    pub func_list: *mut std::ffi::c_void,
    pub flags: cryptoki_sys::CK_FLAGS,
}

/// Providers report a handful of interfaces; a garbage count must not
/// drive allocation.
const MAX_INTERFACES: usize = 256;
/// Whole two-call sequences attempted when the count keeps growing.
const MAX_ATTEMPTS: u32 = 3;

/// Raw `C_GetInterfaceList` enumeration (two-call pattern).
///
/// - `Ok(None)` — the module does not export `C_GetInterfaceList`. The
///   only proven fact is "symbol not exported"; callers must not infer
///   the module generation from it.
/// - `Ok(Some(vec![]))` — export present, zero interfaces reported.
pub fn interface_list(lib: &libloading::Library) -> Result<Option<Vec<RawInterface>>, String> {
    type GetInterfaceListFn = unsafe extern "C" fn(*mut CK_INTERFACE, *mut CK_ULONG) -> CK_RV;
    let sym: Option<libloading::Symbol<GetInterfaceListFn>> =
        unsafe { lib.get(b"C_GetInterfaceList\0").ok() };
    match sym {
        None => Ok(None),
        Some(f) => {
            interface_list_impl(Some(|ifaces: *mut CK_INTERFACE, count: *mut CK_ULONG| unsafe {
                f(ifaces, count)
            }))
        }
    }
}

/// Resolver-level seam: `None` models an absent export so `Ok(None)` is
/// reachable in deterministic tests; the driver below is pure Rust.
fn interface_list_impl<F>(mut get_list: Option<F>) -> Result<Option<Vec<RawInterface>>, String>
where
    F: FnMut(*mut CK_INTERFACE, *mut CK_ULONG) -> CK_RV,
{
    let Some(get_list) = get_list.as_mut() else {
        return Ok(None);
    };

    for _ in 0..MAX_ATTEMPTS {
        // Call 1: count only.
        let mut count: CK_ULONG = 0;
        let rv = get_list(std::ptr::null_mut(), &mut count);
        if rv != CKR_OK {
            return Err(format!("C_GetInterfaceList (count) returned 0x{rv:08x}"));
        }
        let capacity: usize =
            count.try_into().map_err(|_| format!("interface count {count} does not fit usize"))?;
        if capacity > MAX_INTERFACES {
            return Err(format!("provider reports {capacity} interfaces; cap is {MAX_INTERFACES}"));
        }
        if capacity == 0 {
            return Ok(Some(Vec::new()));
        }

        // Call 2: fill.
        let mut buf: Vec<CK_INTERFACE> = (0..capacity)
            .map(|_| CK_INTERFACE {
                pInterfaceName: std::ptr::null_mut(),
                pFunctionList: std::ptr::null_mut(),
                flags: 0,
            })
            .collect();
        let mut written: CK_ULONG = count;
        let rv = get_list(buf.as_mut_ptr(), &mut written);
        if rv == CKR_BUFFER_TOO_SMALL {
            continue; // the count grew between calls; retry the sequence
        }
        if rv != CKR_OK {
            return Err(format!("C_GetInterfaceList returned 0x{rv:08x}"));
        }
        let filled: usize = written
            .try_into()
            .map_err(|_| format!("written count {written} does not fit usize"))?;
        if filled > capacity {
            return Err(format!(
                "provider claims {filled} interfaces written into capacity {capacity}"
            ));
        }
        return Ok(Some(
            buf[..filled]
                .iter()
                .map(|i| RawInterface {
                    name_ptr: i.pInterfaceName,
                    func_list: i.pFunctionList,
                    flags: i.flags,
                })
                .collect(),
        ));
    }
    Err(format!("C_GetInterfaceList count kept growing after {MAX_ATTEMPTS} attempts"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki_sys::{CK_INTERFACE, CK_RV, CK_ULONG, CKR_BUFFER_TOO_SMALL, CKR_OK};

    type NoFn = fn(*mut CK_INTERFACE, *mut CK_ULONG) -> CK_RV;

    /// A fake standard interface backed by test-owned static data.
    fn fake_iface(name: &'static [u8], func_list: *mut std::ffi::c_void) -> CK_INTERFACE {
        CK_INTERFACE {
            pInterfaceName: name.as_ptr() as *mut cryptoki_sys::CK_UTF8CHAR,
            pFunctionList: func_list,
            flags: 0,
        }
    }

    // A static 2-byte CK_VERSION {3, 0} the fake pFunctionList can point at.
    static FAKE_LIST_HEADER: cryptoki_sys::CK_VERSION =
        cryptoki_sys::CK_VERSION { major: 3, minor: 0 };
    fn fake_list_ptr() -> *mut std::ffi::c_void {
        &FAKE_LIST_HEADER as *const _ as *mut std::ffi::c_void
    }

    #[test]
    fn absent_symbol_is_ok_none() {
        assert_eq!(interface_list_impl(None::<NoFn>).map(|o| o.is_none()), Ok(true),);
    }

    #[test]
    fn zero_interfaces_is_ok_some_empty() {
        let result =
            interface_list_impl(Some(|_ifaces: *mut CK_INTERFACE, count: *mut CK_ULONG| {
                unsafe { *count = 0 };
                CKR_OK
            }))
            .unwrap();
        assert_eq!(result.map(|v| v.len()), Some(0));
    }

    #[test]
    fn count_growth_converges_on_retry() {
        let mut calls = 0u32;
        let result =
            interface_list_impl(Some(|ifaces: *mut CK_INTERFACE, count: *mut CK_ULONG| {
                calls += 1;
                match calls {
                    1 => {
                        unsafe { *count = 1 };
                        CKR_OK
                    } // count query
                    2 => {
                        unsafe { *count = 2 };
                        CKR_BUFFER_TOO_SMALL
                    } // grew
                    3 => {
                        unsafe { *count = 2 };
                        CKR_OK
                    } // fresh count
                    _ => {
                        unsafe {
                            *ifaces = fake_iface(b"PKCS 11\0", fake_list_ptr());
                            *ifaces.add(1) = fake_iface(b"Vendor X\0", fake_list_ptr());
                            *count = 2;
                        }
                        CKR_OK
                    }
                }
            }))
            .unwrap()
            .unwrap();
        assert_eq!(result.len(), 2);
        assert!(!result[0].name_ptr.is_null());
        assert!(!result[1].name_ptr.is_null());
        assert_eq!(result[0].func_list, fake_list_ptr());
        assert_eq!(result[1].func_list, fake_list_ptr());
    }

    #[test]
    fn count_growth_never_converging_errors_after_three_attempts() {
        let mut fills = 0u32;
        let err = interface_list_impl(Some(|ifaces: *mut CK_INTERFACE, count: *mut CK_ULONG| {
            if ifaces.is_null() {
                unsafe { *count = 1 };
                CKR_OK
            } else {
                fills += 1;
                unsafe { *count = 2 };
                CKR_BUFFER_TOO_SMALL
            }
        }))
        .unwrap_err();
        assert_eq!(fills, 3, "exactly three whole attempts");
        assert!(err.contains("attempts"), "unexpected error: {err}");
    }

    #[test]
    fn absurd_count_is_rejected_by_the_cap() {
        let err = interface_list_impl(Some(|_: *mut CK_INTERFACE, count: *mut CK_ULONG| {
            unsafe { *count = 10_000 };
            CKR_OK
        }))
        .unwrap_err();
        assert!(err.contains("cap"), "unexpected error: {err}");
    }

    #[test]
    fn capacity_overrun_is_rejected() {
        let err = interface_list_impl(Some(|ifaces: *mut CK_INTERFACE, count: *mut CK_ULONG| {
            if ifaces.is_null() {
                unsafe { *count = 1 };
            } else {
                unsafe { *count = 2 }; // claims more than the capacity it was given
            }
            CKR_OK
        }))
        .unwrap_err();
        assert!(err.contains("capacity"), "unexpected error: {err}");
    }

    #[test]
    fn interface_targets_are_returned_verbatim_without_being_read() {
        let name_ptr = 1usize as *mut cryptoki_sys::CK_UTF8CHAR;
        let func_list = 2usize as *mut std::ffi::c_void;
        let result =
            interface_list_impl(Some(|ifaces: *mut CK_INTERFACE, count: *mut CK_ULONG| {
                if ifaces.is_null() {
                    unsafe { *count = 1 };
                } else {
                    unsafe {
                        *ifaces = CK_INTERFACE {
                            pInterfaceName: name_ptr,
                            pFunctionList: func_list,
                            flags: 7,
                        };
                        *count = 1;
                    }
                }
                CKR_OK
            }))
            .unwrap()
            .unwrap();

        assert_eq!(result[0].name_ptr, name_ptr);
        assert_eq!(result[0].func_list, func_list);
        assert_eq!(result[0].flags, 7);
    }

    #[test]
    fn null_name_and_null_func_list_are_preserved_not_dereferenced() {
        let result =
            interface_list_impl(Some(|ifaces: *mut CK_INTERFACE, count: *mut CK_ULONG| {
                if ifaces.is_null() {
                    unsafe { *count = 2 };
                } else {
                    unsafe {
                        *ifaces = CK_INTERFACE {
                            pInterfaceName: std::ptr::null_mut(),
                            pFunctionList: fake_list_ptr(),
                            flags: 0,
                        };
                        *ifaces.add(1) = fake_iface(b"PKCS 11\0", std::ptr::null_mut());
                        *count = 2;
                    }
                }
                CKR_OK
            }))
            .unwrap()
            .unwrap();
        assert!(result[0].name_ptr.is_null());
        assert_eq!(result[0].func_list, fake_list_ptr());
        assert!(!result[1].name_ptr.is_null());
        assert!(result[1].func_list.is_null());
    }

    /// Real 3.x provider check (SoftHSM2 2.6 is 2.40-only, so it cannot
    /// serve here). Point PKCS11_MODULE_TEST_3X_MODULE at a 3.x .so
    /// (kryoptic or BouncyHSM) to run; skipped otherwise.
    #[test]
    fn real_3x_module_reports_standard_interfaces() {
        let Ok(path) = std::env::var("PKCS11_MODULE_TEST_3X_MODULE") else {
            eprintln!("skipping: PKCS11_MODULE_TEST_3X_MODULE not set");
            return;
        };
        if !std::path::Path::new(&path).exists() {
            eprintln!("skipping: {path} not found");
            return;
        }
        let lib = unsafe { libloading::Library::new(&path) }.expect("dlopen");
        let listed = interface_list(&lib).expect("enumeration should succeed");
        let listed = listed.expect("a 3.x module exports C_GetInterfaceList");
        assert!(!listed.is_empty());
        assert!(
            listed.iter().any(|i| !i.name_ptr.is_null() && !i.func_list.is_null()),
            "a conforming 3.x module reports at least one usable raw interface record"
        );
        // The legacy surface must be independently collectable too.
        super::function_list(&lib).expect("legacy 2.40 table");
    }
}
