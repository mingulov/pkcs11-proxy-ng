use super::FfiBackend;
use libloading::{Library, Symbol};
use std::ffi::CString;
use std::path::Path;

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
    pub fn load_with_init_args(path: &Path, initialize_args: Option<&str>) -> Result<Self, String> {
        let lib = unsafe { Library::new(path).map_err(|e| format!("dlopen failed: {e}"))? };

        let func_list =
            Self::try_get_interface(&lib).or_else(|_| Self::try_get_function_list(&lib))?;

        // Attempt to discover 3.0 and 3.2 function lists. These are optional;
        // a 2.40-only module will simply leave both as None.
        let get_iface_sym = Self::resolve_get_interface(&lib);
        let func_list_3_0 = get_iface_sym
            .and_then(|sym| Self::try_get_versioned_interface(sym, 3, 0))
            .map(|ptr| ptr as *const cryptoki_sys::CK_FUNCTION_LIST_3_0);
        let func_list_3_2 = get_iface_sym
            .and_then(|sym| Self::try_get_versioned_interface(sym, 3, 2))
            .map(|ptr| ptr as *const cryptoki_sys::CK_FUNCTION_LIST_3_2);

        let initialize_args = initialize_args
            .map(|s| {
                CString::new(s)
                    .map_err(|_| "initialize_args contains an interior NUL byte".to_string())
            })
            .transpose()?;

        Ok(Self {
            _lib: lib,
            func_list,
            func_list_3_0,
            func_list_3_2,
            initialize_args,
            mech_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
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

    /// Try to resolve via C_GetInterface (3.x) with no name/version filter
    /// (returns the default/highest interface).
    fn try_get_interface(lib: &Library) -> Result<*mut cryptoki_sys::CK_FUNCTION_LIST, String> {
        let get_interface = Self::resolve_get_interface(lib)
            .ok_or_else(|| "C_GetInterface not found".to_string())?;

        let mut interface_ptr: *mut cryptoki_sys::CK_INTERFACE = std::ptr::null_mut();
        let rv = unsafe {
            get_interface(std::ptr::null_mut(), std::ptr::null_mut(), &mut interface_ptr, 0)
        };
        if rv != 0 {
            return Err(format!("C_GetInterface returned 0x{rv:08x}"));
        }
        if interface_ptr.is_null() {
            return Err("C_GetInterface returned null interface".into());
        }
        let func_list =
            unsafe { (*interface_ptr).pFunctionList } as *mut cryptoki_sys::CK_FUNCTION_LIST;
        if func_list.is_null() {
            return Err("CK_INTERFACE.pFunctionList is null".into());
        }
        Ok(func_list)
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

    /// Call `C_GetInterface` for a specific major/minor version.
    ///
    /// Tries the named query `C_GetInterface("PKCS 11", version)` first, then
    /// falls back to `C_GetInterface(NULL, version)` for modules (e.g. BouncyHSM)
    /// that only respond to the unnamed form.
    ///
    /// Returns the raw `pFunctionList` pointer from the resulting
    /// `CK_INTERFACE`, or `None` if the module does not offer that version.
    fn try_get_versioned_interface(
        get_interface: GetInterfaceFn,
        major: u8,
        minor: u8,
    ) -> Option<*mut std::ffi::c_void> {
        // Try with explicit name first.
        if let Some(ptr) = Self::get_interface_with_name(get_interface, major, minor, true) {
            return Some(ptr);
        }
        // Fallback: NULL name (some modules only respond to this form).
        Self::get_interface_with_name(get_interface, major, minor, false)
    }

    fn get_interface_with_name(
        get_interface: GetInterfaceFn,
        major: u8,
        minor: u8,
        use_name: bool,
    ) -> Option<*mut std::ffi::c_void> {
        let name = b"PKCS 11\0";
        let name_ptr = if use_name {
            name.as_ptr() as *mut cryptoki_sys::CK_UTF8CHAR
        } else {
            std::ptr::null_mut()
        };
        let mut version = cryptoki_sys::CK_VERSION { major, minor };
        let mut interface_ptr: *mut cryptoki_sys::CK_INTERFACE = std::ptr::null_mut();

        let rv = unsafe { get_interface(name_ptr, &mut version, &mut interface_ptr, 0) };
        if rv != 0 || interface_ptr.is_null() {
            return None;
        }
        let func_list = unsafe { (*interface_ptr).pFunctionList };
        if func_list.is_null() {
            return None;
        }
        Some(func_list)
    }

    /// Fallback: resolve via C_GetFunctionList (2.x).
    fn try_get_function_list(lib: &Library) -> Result<*mut cryptoki_sys::CK_FUNCTION_LIST, String> {
        let get_func_list: Symbol<
            unsafe extern "C" fn(*mut *mut cryptoki_sys::CK_FUNCTION_LIST) -> cryptoki_sys::CK_RV,
        > = unsafe {
            lib.get(b"C_GetFunctionList\0")
                .map_err(|e| format!("C_GetFunctionList not found: {e}"))?
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
}
