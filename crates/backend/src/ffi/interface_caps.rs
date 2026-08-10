//! BUG-001: Interface capability detection for FfiBackend.

use super::FfiBackend;
use pkcs11_module::tables::{Surface, TableSet, detect_null_functions, tables_for};
use pkcs11_proxy_ng_types::{InterfaceCapabilities, InterfaceInfo};

fn nulls_for(list: *const u8, surface: Surface) -> Vec<String> {
    match tables_for(surface) {
        TableSet::Walk(sets) | TableSet::WalkKnownPrefix(sets) => {
            sets.iter().flat_map(|fields| unsafe { detect_null_functions(list, fields) }).collect()
        }
        TableSet::Refuse => Vec::new(),
    }
}

impl FfiBackend {
    /// Detect which interfaces the loaded PKCS#11 module supports and
    /// which function pointers are NULL in each function list.
    pub fn detect_interface_capabilities(&self) -> InterfaceCapabilities {
        let mut interfaces = Vec::with_capacity(3);

        // v2.40 is always present. self.func_list may be legacy- or (validated)
        // interface-derived; both walk base-only, so LegacyFunctionList is the
        // conservative surface for it either way.
        let null_2_40 = nulls_for(self.func_list as *const u8, Surface::LegacyFunctionList);
        interfaces.push(InterfaceInfo {
            version_major: 2,
            version_minor: 40,
            null_functions: null_2_40,
        });

        // v3.0 if available (list came from a validated versioned {3,0} query):
        if let Some(fl3) = self.func_list_3_0 {
            let nulls = nulls_for(
                fl3 as *const u8,
                Surface::StandardInterface {
                    version: cryptoki_sys::CK_VERSION { major: 3, minor: 0 },
                },
            );
            interfaces.push(InterfaceInfo {
                version_major: 3,
                version_minor: 0,
                null_functions: nulls,
            });
        }

        // v3.2 if available:
        if let Some(fl3_2) = self.func_list_3_2 {
            let nulls = nulls_for(
                fl3_2 as *const u8,
                Surface::StandardInterface {
                    version: cryptoki_sys::CK_VERSION { major: 3, minor: 2 },
                },
            );
            interfaces.push(InterfaceInfo {
                version_major: 3,
                version_minor: 2,
                null_functions: nulls,
            });
        }

        InterfaceCapabilities { interfaces }
    }
}
