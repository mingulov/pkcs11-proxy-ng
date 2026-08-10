//! Raw table acquisition — the three pre-initialize entry points.

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
