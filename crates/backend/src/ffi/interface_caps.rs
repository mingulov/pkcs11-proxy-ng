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
        let mut interfaces = Vec::with_capacity(4);

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
            // Issue #28: a 3.1-stamped primary fallback in this slot must
            // not duplicate the explicit {3,1} answer below — the
            // explicit answer's null walk wins.
            let shadowed = minor == 1 && self.func_list_3_1.is_some();
            if !shadowed {
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
        }

        // v3.1 if an explicit {3,1} answer was recorded (issue #28):
        // the answer proved the module serves {3,1}, so the queried
        // version is advertised unconditionally. 3.1 shares the 3.0
        // layout, so the same 92-field surface walk applies.
        if let Some(fl3_1) = self.func_list_3_1 {
            let nulls = nulls_for(
                fl3_1 as *const u8,
                Surface::StandardInterface {
                    version: cryptoki_sys::CK_VERSION { major: 3, minor: 1 },
                },
            );
            interfaces.push(InterfaceInfo {
                version_major: 3,
                version_minor: 1,
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

    /// Haskoki-shape stub (issue #28): literal {3,0} + literal {3,1}
    /// tables, mimicking a module that answers both versioned queries.
    fn backend_with_3_0_and_3_1() -> (
        FfiBackend,
        Box<cryptoki_sys::CK_FUNCTION_LIST>,
        Box<cryptoki_sys::CK_FUNCTION_LIST_3_0>,
        Box<cryptoki_sys::CK_FUNCTION_LIST_3_0>,
    ) {
        let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        base.version = cryptoki_sys::CK_VERSION { major: 2, minor: 40 };
        let mut table_3_0 = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_0::default());
        table_3_0.version = cryptoki_sys::CK_VERSION { major: 3, minor: 0 };
        let mut table_3_1 = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_0::default());
        table_3_1.version = cryptoki_sys::CK_VERSION { major: 3, minor: 1 };
        let backend =
            FfiBackend::test_backend_with_tables(base.as_mut(), Some(table_3_0.as_ref()), None)
                .with_3_1_table(Some(table_3_1.as_ref()));
        (backend, base, table_3_0, table_3_1)
    }

    /// Issue #28: a module answering literal {3,0} AND {3,1} must
    /// advertise both — the explicit {3,1} answer lands in the 3.1
    /// slot and must surface as (3,1) alongside the literal (3,0).
    #[test]
    fn capability_report_advertises_literal_3_0_and_3_1() {
        let (backend, _base, _table_3_0, _table_3_1) = backend_with_3_0_and_3_1();
        let versions = reported_versions(&backend);
        assert!(versions.contains(&(3, 0)), "literal 3.0 must be kept: {versions:?}");
        assert!(
            versions.contains(&(3, 1)),
            "explicit {{3,1}} answer must be advertised: {versions:?}"
        );
    }

    unsafe extern "C" fn stub_session_cancel(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _flags: cryptoki_sys::CK_FLAGS,
    ) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    /// The (3,1) entry's null list is walked from the 3.1 table, not
    /// copied from the 3.0 slot: a function present only in the 3.1
    /// table must be absent from the (3,1) nulls and present in the
    /// (3,0) nulls.
    #[test]
    fn capability_report_walks_3_1_nulls_from_3_1_table() {
        let (backend, _base, _table_3_0, mut table_3_1) = backend_with_3_0_and_3_1();
        table_3_1.C_SessionCancel = Some(stub_session_cancel);
        let caps = backend.detect_interface_capabilities();
        let nulls_of = |major: u8, minor: u8| {
            caps.interfaces
                .iter()
                .find(|info| info.version_major == major && info.version_minor == minor)
                .unwrap_or_else(|| panic!("missing ({major},{minor}) entry"))
                .null_functions
                .clone()
        };
        let nulls_3_0 = nulls_of(3, 0);
        let nulls_3_1 = nulls_of(3, 1);
        assert!(
            nulls_3_0.contains(&"C_SessionCancel".to_string()),
            "zeroed 3.0 table must report C_SessionCancel null"
        );
        assert!(
            !nulls_3_1.contains(&"C_SessionCancel".to_string()),
            "3.1 table with C_SessionCancel set must not report it null"
        );
    }

    /// BouncyHSM + explicit {3,1}: when the 3.0 slot holds the
    /// 3.1-stamped primary fallback AND the 3.1 slot holds the explicit
    /// answer, (3,1) is advertised exactly once and no (3,0) alias
    /// is invented.
    #[test]
    fn capability_report_dedupes_fallback_3_1_against_explicit_3_1() {
        let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        base.version = cryptoki_sys::CK_VERSION { major: 2, minor: 40 };
        let mut fallback = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_0::default());
        fallback.version = cryptoki_sys::CK_VERSION { major: 3, minor: 1 };
        let mut table_3_1 = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_0::default());
        table_3_1.version = cryptoki_sys::CK_VERSION { major: 3, minor: 1 };
        let backend =
            FfiBackend::test_backend_with_tables(base.as_mut(), Some(fallback.as_ref()), None)
                .with_3_1_table(Some(table_3_1.as_ref()));
        let versions = reported_versions(&backend);
        assert_eq!(
            versions.iter().filter(|v| **v == (3, 1)).count(),
            1,
            "exactly one (3,1): {versions:?}"
        );
        assert!(!versions.contains(&(3, 0)), "no invented (3,0) alias: {versions:?}");
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
        // Pinned contract with the published pkcs11-module dependency: the
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
