//! BUG-001: Interface capability detection for FfiBackend.

use super::FfiBackend;
use pkcs11_module::tables::{Surface, TableSet, detect_null_functions, tables_for};
use pkcs11_proxy_ng_types::{InterfaceCapabilities, InterfaceInfo};

fn nulls_for(list: *const u8, surface: Surface) -> Vec<String> {
    match tables_for(surface) {
        TableSet::Walk(sets) | TableSet::WalkKnownPrefix(sets) => sets
            .iter()
            .flat_map(|span| unsafe { detect_null_functions(list, span.fields()) })
            .collect(),
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
        let null_2_40 = nulls_for(
            self.func_list as *const u8,
            Surface::LegacyFunctionList {
                version: cryptoki_sys::CK_VERSION { major: 2, minor: 40 },
            },
        );
        interfaces.push(InterfaceInfo {
            version_major: 2,
            version_minor: 40,
            null_functions: null_2_40,
        });

        // v3.0 if available (list came from a validated versioned {3,0} query):
        if let Some(fl3) = self.func_list_3_0 {
            // W1-L5-01: the dispatch slot may hold a primary-fallback table
            // stamped with a different 3.x version (BouncyHSM answers an
            // explicit {3,0} with NULL, so its 3.1 default interface serves
            // dispatch). Advertise the version the backend stamped on the
            // table — 3.1≡3.0 layout, so the same 92-field surface walk
            // applies — instead of inventing a {3,0} alias. Any other stamp
            // keeps the slot default (3,0), i.e. today's behavior.
            // Soundness: leading-CK_VERSION read on a non-null
            // interface-derived table — the same reliance as
            // `answer_version_at_least`/`primary_interface_fallback`.
            let stamped = unsafe { (*fl3).version };
            let minor = if stamped.major == 3 && stamped.minor == 1 { 1 } else { 0 };
            let nulls = nulls_for(
                fl3 as *const u8,
                Surface::StandardInterface {
                    version: cryptoki_sys::CK_VERSION { major: 3, minor },
                },
            );
            interfaces.push(InterfaceInfo {
                version_major: 3,
                version_minor: minor,
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

#[cfg(test)]
mod tests {
    use pkcs11_module::tables::{
        FUNCTION_LIST_3_0_EXTRA_FIELDS, FUNCTION_LIST_3_2_EXTRA_FIELDS, FUNCTION_LIST_FIELDS,
        Surface, TableSet, tables_for,
    };

    use super::super::FfiBackend;

    /// Test backend whose 3.0-dispatch slot points at a table stamped with the
    /// given version — mimics BouncyHSM when stamped {3,1} (explicit {3,0}
    /// query NULL, primary fallback) and classic 3.0 modules when {3,0}.
    fn backend_with_3_slot(
        major: u8,
        minor: u8,
    ) -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>, Box<cryptoki_sys::CK_FUNCTION_LIST_3_0>)
    {
        let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        base.version = cryptoki_sys::CK_VERSION { major: 2, minor: 40 };
        let mut table_3 = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_0::default());
        table_3.version = cryptoki_sys::CK_VERSION { major, minor };
        let backend =
            FfiBackend::test_backend_with_tables(base.as_mut(), Some(table_3.as_ref()), None);
        (backend, base, table_3)
    }

    fn reported_versions(backend: &FfiBackend) -> Vec<(u8, u8)> {
        backend
            .detect_interface_capabilities()
            .interfaces
            .iter()
            .map(|info| (info.version_major, info.version_minor))
            .collect()
    }

    /// W1-L5-01: a 3.1-stamped table in the 3.0-dispatch slot (BouncyHSM:
    /// explicit {3,0} NULL, primary fallback) must be advertised as (3,1) —
    /// never as an invented (3,0) alias.
    #[test]
    fn capability_report_advertises_stamped_3_1_not_aliased_3_0() {
        let (backend, _base, _table_3) = backend_with_3_slot(3, 1);
        let versions = reported_versions(&backend);
        assert!(
            versions.contains(&(3, 1)),
            "backend offering 3.1 must advertise (3,1): {versions:?}"
        );
        assert!(
            !versions.contains(&(3, 0)),
            "no invented (3,0) alias for a 3.1-only table: {versions:?}"
        );
    }

    /// Control: a literally-answered 3.0 table keeps advertising (3,0) and
    /// must not gain a phantom (3,1).
    #[test]
    fn capability_report_keeps_literal_3_0() {
        let (backend, _base, _table_3) = backend_with_3_slot(3, 0);
        let versions = reported_versions(&backend);
        assert!(versions.contains(&(3, 0)), "literal 3.0 must be kept: {versions:?}");
        assert!(!versions.contains(&(3, 1)), "no phantom (3,1): {versions:?}");
    }

    fn walked_field_count(set: TableSet) -> Option<usize> {
        match set {
            TableSet::Walk(spans) | TableSet::WalkKnownPrefix(spans) => {
                Some(spans.iter().map(|span| span.fields().len()).sum())
            }
            TableSet::Refuse => None,
        }
    }

    #[test]
    fn upstream_function_tables_expose_104_standard_fields() {
        // Pinned contract with the pkcs11-components git dependency: the
        // capability scan and the OASIS inventory both assume the
        // 68 + 24 + 12 standard catalog.
        assert_eq!(FUNCTION_LIST_FIELDS.len(), 68);
        assert_eq!(FUNCTION_LIST_3_0_EXTRA_FIELDS.len(), 24);
        assert_eq!(FUNCTION_LIST_3_2_EXTRA_FIELDS.len(), 12);
    }

    #[test]
    fn capability_scan_surfaces_walk_known_prefixes() {
        let legacy = Surface::LegacyFunctionList {
            version: cryptoki_sys::CK_VERSION { major: 2, minor: 40 },
        };
        assert_eq!(walked_field_count(tables_for(legacy)), Some(68));
        for (major, minor, expected) in [(3u8, 0u8, 92), (3, 1, 92), (3, 2, 104)] {
            let surface =
                Surface::StandardInterface { version: cryptoki_sys::CK_VERSION { major, minor } };
            assert_eq!(walked_field_count(tables_for(surface)), Some(expected));
        }
        // Unknown 2.x standard interfaces are refused, never walked.
        let bogus = Surface::StandardInterface {
            version: cryptoki_sys::CK_VERSION { major: 2, minor: 30 },
        };
        assert_eq!(walked_field_count(tables_for(bogus)), None);
    }
}
