//! BUG-001: Interface capability detection for FfiBackend.

use super::FfiBackend;
use super::function_field_tables::*;
use pkcs11_proxy_ng_types::{InterfaceCapabilities, InterfaceInfo};

impl FfiBackend {
    /// Detect which interfaces the loaded PKCS#11 module supports and
    /// which function pointers are NULL in each function list.
    pub fn detect_interface_capabilities(&self) -> InterfaceCapabilities {
        let mut interfaces = Vec::with_capacity(3);

        // v2.40 is always present (func_list is required).
        let null_2_40 =
            unsafe { detect_null_functions(self.func_list as *const u8, FUNCTION_LIST_FIELDS) };
        interfaces.push(InterfaceInfo {
            version_major: 2,
            version_minor: 40,
            null_functions: null_2_40,
        });

        // v3.0 if available.
        if let Some(fl3) = self.func_list_3_0 {
            // Check the v2.40 fields (they exist in the 3.0 struct too)
            // plus the 3.0-specific fields.
            let mut nulls =
                unsafe { detect_null_functions(fl3 as *const u8, FUNCTION_LIST_FIELDS) };
            nulls.extend(unsafe {
                detect_null_functions(fl3 as *const u8, FUNCTION_LIST_3_0_EXTRA_FIELDS)
            });
            interfaces.push(InterfaceInfo {
                version_major: 3,
                version_minor: 0,
                null_functions: nulls,
            });
        }

        // v3.2 if available.
        if let Some(fl3_2) = self.func_list_3_2 {
            let mut nulls =
                unsafe { detect_null_functions(fl3_2 as *const u8, FUNCTION_LIST_FIELDS) };
            nulls.extend(unsafe {
                detect_null_functions(fl3_2 as *const u8, FUNCTION_LIST_3_0_EXTRA_FIELDS)
            });
            nulls.extend(unsafe {
                detect_null_functions(fl3_2 as *const u8, FUNCTION_LIST_3_2_EXTRA_FIELDS)
            });
            interfaces.push(InterfaceInfo {
                version_major: 3,
                version_minor: 2,
                null_functions: nulls,
            });
        }

        InterfaceCapabilities { interfaces }
    }
}
