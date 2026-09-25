//! Compile-time tables mapping function field names to their byte offsets
//! within CK_FUNCTION_LIST, CK_FUNCTION_LIST_3_0, and CK_FUNCTION_LIST_3_2.
//!
//! Used by `get_interface_capabilities()` to detect NULL function pointers
//! without manual field-by-field code.

use cryptoki_sys::*;

/// A (field_name, byte_offset) pair for a function pointer field.
#[derive(Debug)]
pub struct FnField {
    pub name: &'static str,
    pub offset: usize,
}

macro_rules! fn_fields {
    ($struct_type:ty, [ $( $field:ident ),+ $(,)? ]) => {
        &[ $(
            FnField {
                name: stringify!($field),
                offset: std::mem::offset_of!($struct_type, $field),
            },
        )+ ]
    };
}

/// All 68 function pointer fields in CK_FUNCTION_LIST (v2.40).
/// Excludes `version` (CK_VERSION, not a function pointer).
pub static FUNCTION_LIST_FIELDS: &[FnField] = fn_fields!(
    CK_FUNCTION_LIST,
    [
        C_Initialize,
        C_Finalize,
        C_GetInfo,
        C_GetFunctionList,
        C_GetSlotList,
        C_GetSlotInfo,
        C_GetTokenInfo,
        C_GetMechanismList,
        C_GetMechanismInfo,
        C_InitToken,
        C_InitPIN,
        C_SetPIN,
        C_OpenSession,
        C_CloseSession,
        C_CloseAllSessions,
        C_GetSessionInfo,
        C_GetOperationState,
        C_SetOperationState,
        C_Login,
        C_Logout,
        C_CreateObject,
        C_CopyObject,
        C_DestroyObject,
        C_GetObjectSize,
        C_GetAttributeValue,
        C_SetAttributeValue,
        C_FindObjectsInit,
        C_FindObjects,
        C_FindObjectsFinal,
        C_EncryptInit,
        C_Encrypt,
        C_EncryptUpdate,
        C_EncryptFinal,
        C_DecryptInit,
        C_Decrypt,
        C_DecryptUpdate,
        C_DecryptFinal,
        C_DigestInit,
        C_Digest,
        C_DigestUpdate,
        C_DigestKey,
        C_DigestFinal,
        C_SignInit,
        C_Sign,
        C_SignUpdate,
        C_SignFinal,
        C_SignRecoverInit,
        C_SignRecover,
        C_VerifyInit,
        C_Verify,
        C_VerifyUpdate,
        C_VerifyFinal,
        C_VerifyRecoverInit,
        C_VerifyRecover,
        C_DigestEncryptUpdate,
        C_DecryptDigestUpdate,
        C_SignEncryptUpdate,
        C_DecryptVerifyUpdate,
        C_GenerateKey,
        C_GenerateKeyPair,
        C_WrapKey,
        C_UnwrapKey,
        C_DeriveKey,
        C_SeedRandom,
        C_GenerateRandom,
        C_GetFunctionStatus,
        C_CancelFunction,
        C_WaitForSlotEvent,
    ]
);

/// Additional 24 function pointer fields in CK_FUNCTION_LIST_3_0 (beyond v2.40).
pub static FUNCTION_LIST_3_0_EXTRA_FIELDS: &[FnField] = fn_fields!(
    CK_FUNCTION_LIST_3_0,
    [
        C_GetInterfaceList,
        C_GetInterface,
        C_LoginUser,
        C_SessionCancel,
        C_MessageEncryptInit,
        C_EncryptMessage,
        C_EncryptMessageBegin,
        C_EncryptMessageNext,
        C_MessageEncryptFinal,
        C_MessageDecryptInit,
        C_DecryptMessage,
        C_DecryptMessageBegin,
        C_DecryptMessageNext,
        C_MessageDecryptFinal,
        C_MessageSignInit,
        C_SignMessage,
        C_SignMessageBegin,
        C_SignMessageNext,
        C_MessageSignFinal,
        C_MessageVerifyInit,
        C_VerifyMessage,
        C_VerifyMessageBegin,
        C_VerifyMessageNext,
        C_MessageVerifyFinal,
    ]
);

/// Additional 12 function pointer fields in CK_FUNCTION_LIST_3_2 (beyond v3.0).
pub static FUNCTION_LIST_3_2_EXTRA_FIELDS: &[FnField] = fn_fields!(
    CK_FUNCTION_LIST_3_2,
    [
        C_EncapsulateKey,
        C_DecapsulateKey,
        C_VerifySignatureInit,
        C_VerifySignature,
        C_VerifySignatureUpdate,
        C_VerifySignatureFinal,
        C_GetSessionValidationFlags,
        C_AsyncComplete,
        C_AsyncGetID,
        C_AsyncJoin,
        C_WrapKeyAuthenticated,
        C_UnwrapKeyAuthenticated,
    ]
);

/// Check a function list struct for NULL function pointers.
///
/// # Safety
/// `base` must point to a valid, live struct of the type that `fields`
/// was generated from. The struct must remain valid for the duration
/// of this call.
pub unsafe fn detect_null_functions(base: *const u8, fields: &[FnField]) -> Vec<String> {
    let mut nulls = Vec::new();
    for field in fields {
        // Each function pointer field is `Option<unsafe extern "C" fn(...)>`,
        // which is pointer-sized. A None value is all-zero bytes. read_unaligned:
        // on the packed Windows-MSVC cryptoki-sys bindings these fields start at
        // offset 2 (after CK_VERSION), where an aligned read is UB.
        let ptr_val = unsafe { (base.add(field.offset) as *const usize).read_unaligned() };
        if ptr_val == 0 {
            nulls.push(field.name.to_string());
        }
    }
    nulls
}

/// Read every function-pointer field from an owned table snapshot.
pub fn read_fn_pointers(
    bytes: &[u8],
    fields: &[FnField],
) -> Result<Vec<(&'static str, usize)>, String> {
    let width = std::mem::size_of::<usize>();
    fields
        .iter()
        .map(|field| {
            let end = field
                .offset
                .checked_add(width)
                .ok_or_else(|| format!("{} offset overflows", field.name))?;
            let src = bytes.get(field.offset..end).ok_or_else(|| {
                format!(
                    "{} needs bytes {}..{end}, snapshot has {}",
                    field.name,
                    field.offset,
                    bytes.len()
                )
            })?;
            let mut raw = [0u8; std::mem::size_of::<usize>()];
            raw.copy_from_slice(src);
            Ok((field.name, usize::from_ne_bytes(raw)))
        })
        .collect()
}

/// Where a function table came from — the input that decides which field
/// tables may be walked over it (spec §7). Vendor interfaces and NULL
/// function lists are deliberately unrepresentable: only `is_standard()`
/// interfaces may be wrapped in `StandardInterface`, and callers never
/// construct a `Surface` for anything else.
#[derive(Debug, Clone, Copy)]
pub enum Surface {
    /// Obtained via `C_GetFunctionList`, with its bounded-read version.
    LegacyFunctionList { version: cryptoki_sys::CK_VERSION },
    /// A standard or independently corroborated standard-shaped interface,
    /// with its bounded-read reported version.
    StandardInterface { version: cryptoki_sys::CK_VERSION },
}

/// A prefix of one shared field table. The 2.00 ABI reuses the first 67
/// entries of the 68-entry base table instead of copying their names.
#[derive(Debug, Clone, Copy)]
pub struct TableSpan {
    fields: &'static [FnField],
    len: usize,
}

impl TableSpan {
    pub fn fields(&self) -> &'static [FnField] {
        &self.fields[..self.len]
    }
}

/// The tables that may be walked over a surface, in walk order.
#[derive(Debug, Clone, Copy)]
pub enum TableSet {
    Walk(&'static [TableSpan]),
    /// 3.x with minor > 2: the listed tables are a safe *prefix*; fields
    /// beyond the known 3.2 layout exist but must be recorded as excess,
    /// not walked.
    WalkKnownPrefix(&'static [TableSpan]),
    /// Unknown major/layout: record, walk nothing.
    Refuse,
}

static V2_00: &[TableSpan] = &[TableSpan { fields: FUNCTION_LIST_FIELDS, len: 67 }];
static BASE: &[TableSpan] =
    &[TableSpan { fields: FUNCTION_LIST_FIELDS, len: FUNCTION_LIST_FIELDS.len() }];
static V3_0: &[TableSpan] = &[
    TableSpan { fields: FUNCTION_LIST_FIELDS, len: FUNCTION_LIST_FIELDS.len() },
    TableSpan { fields: FUNCTION_LIST_3_0_EXTRA_FIELDS, len: FUNCTION_LIST_3_0_EXTRA_FIELDS.len() },
];
static V3_2: &[TableSpan] = &[
    TableSpan { fields: FUNCTION_LIST_FIELDS, len: FUNCTION_LIST_FIELDS.len() },
    TableSpan { fields: FUNCTION_LIST_3_0_EXTRA_FIELDS, len: FUNCTION_LIST_3_0_EXTRA_FIELDS.len() },
    TableSpan { fields: FUNCTION_LIST_3_2_EXTRA_FIELDS, len: FUNCTION_LIST_3_2_EXTRA_FIELDS.len() },
];

/// The single authority binding provenance + validated version to the
/// walkable field tables (spec §7). Both the proxy's capability scan and
/// the discovery helper go through this, so the invariant has one home.
pub fn tables_for(surface: Surface) -> TableSet {
    match surface {
        Surface::LegacyFunctionList { version } => match (version.major, version.minor) {
            (2, 0) => TableSet::Walk(V2_00),
            (2, 1 | 10 | 11 | 20 | 30 | 40) => TableSet::Walk(BASE),
            (2, _) | (3, _) => TableSet::WalkKnownPrefix(BASE),
            _ => TableSet::Refuse,
        },
        Surface::StandardInterface { version } => match (version.major, version.minor) {
            // OASIS mandates 0x02/0x28 ("a version 2.40 compatible
            // structure") — the only 2.x layout the base table describes.
            (2, 40) => TableSet::Walk(BASE),
            (2, _) => TableSet::Refuse,
            (3, 0) | (3, 1) => TableSet::Walk(V3_0),
            (3, 2) => TableSet::Walk(V3_2),
            (3, _) => TableSet::WalkKnownPrefix(V3_2),
            _ => TableSet::Refuse,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A byte buffer standing in for a CK_FUNCTION_LIST: one non-NULL slot
    /// written at the C_Initialize offset, everything else zero.
    fn fake_base_table() -> Vec<u8> {
        let mut buf = vec![0u8; std::mem::size_of::<cryptoki_sys::CK_FUNCTION_LIST>()];
        let off = FUNCTION_LIST_FIELDS[0].offset; // C_Initialize
        buf[off..off + std::mem::size_of::<usize>()]
            .copy_from_slice(&0xDEAD_BEEFusize.to_ne_bytes());
        buf
    }

    #[test]
    fn detect_null_functions_reports_all_but_the_set_slot() {
        let buf = fake_base_table();
        let nulls = unsafe { detect_null_functions(buf.as_ptr(), FUNCTION_LIST_FIELDS) };
        assert!(!nulls.contains(&"C_Initialize".to_string()));
        assert_eq!(nulls.len(), FUNCTION_LIST_FIELDS.len() - 1);
    }

    #[test]
    fn read_fn_pointers_returns_names_with_values() {
        let buf = fake_base_table();
        let ptrs = read_fn_pointers(&buf, FUNCTION_LIST_FIELDS).unwrap();
        assert_eq!(ptrs.len(), FUNCTION_LIST_FIELDS.len());
        assert_eq!(ptrs[0], ("C_Initialize", 0xDEAD_BEEF));
        assert!(ptrs[1..].iter().all(|(_, v)| *v == 0));
    }

    #[test]
    fn read_fn_pointers_rejects_a_short_snapshot() {
        let last = FUNCTION_LIST_FIELDS.last().unwrap();
        let short = vec![0u8; last.offset + std::mem::size_of::<usize>() - 1];
        let err = read_fn_pointers(&short, FUNCTION_LIST_FIELDS).unwrap_err();
        assert!(err.contains("C_WaitForSlotEvent"), "unexpected error: {err}");
    }

    #[test]
    fn table_sizes_match_the_documented_counts() {
        assert_eq!(FUNCTION_LIST_FIELDS.len(), 68);
        assert_eq!(FUNCTION_LIST_3_0_EXTRA_FIELDS.len(), 24);
        assert_eq!(FUNCTION_LIST_3_2_EXTRA_FIELDS.len(), 12);
    }

    fn std_iface(major: u8, minor: u8) -> Surface {
        Surface::StandardInterface { version: cryptoki_sys::CK_VERSION { major, minor } }
    }

    fn walked(set: TableSet) -> Vec<*const FnField> {
        match set {
            TableSet::Walk(s) | TableSet::WalkKnownPrefix(s) => {
                s.iter().map(|span| span.fields().as_ptr()).collect()
            }
            TableSet::Refuse => Vec::new(),
        }
    }

    fn field_count(set: TableSet) -> usize {
        match set {
            TableSet::Walk(spans) | TableSet::WalkKnownPrefix(spans) => {
                spans.iter().map(|span| span.fields().len()).sum()
            }
            TableSet::Refuse => 0,
        }
    }

    #[test]
    fn legacy_200_walks_67_fields_and_201_walks_68() {
        let legacy = |minor| Surface::LegacyFunctionList {
            version: cryptoki_sys::CK_VERSION { major: 2, minor },
        };
        assert_eq!(field_count(tables_for(legacy(0))), 67);
        assert_eq!(field_count(tables_for(legacy(1))), 68);
    }

    #[test]
    fn every_published_later_legacy_revision_walks_68_fields() {
        for minor in [10, 11, 20, 30, 40] {
            let set = tables_for(Surface::LegacyFunctionList {
                version: cryptoki_sys::CK_VERSION { major: 2, minor },
            });
            assert!(matches!(set, TableSet::Walk(_)), "2.{minor:02} must be exact");
            assert_eq!(field_count(set), 68, "2.{minor:02}");
        }
    }

    #[test]
    fn unpublished_later_legacy_versions_are_known_prefixes() {
        for version in [
            cryptoki_sys::CK_VERSION { major: 2, minor: 2 },
            cryptoki_sys::CK_VERSION { major: 2, minor: 41 },
            cryptoki_sys::CK_VERSION { major: 3, minor: 0 },
            cryptoki_sys::CK_VERSION { major: 3, minor: 2 },
        ] {
            let set = tables_for(Surface::LegacyFunctionList { version });
            assert!(matches!(set, TableSet::WalkKnownPrefix(_)), "{version:?}");
            assert_eq!(field_count(set), 68, "{version:?}");
        }
    }

    #[test]
    fn legacy_unknown_majors_are_refused() {
        for major in [0, 1, 4] {
            assert!(matches!(
                tables_for(Surface::LegacyFunctionList {
                    version: cryptoki_sys::CK_VERSION { major, minor: 0 },
                }),
                TableSet::Refuse
            ));
        }
    }

    #[test]
    fn legacy_misstamped_3x_walks_only_the_known_base_prefix() {
        let set = tables_for(Surface::LegacyFunctionList {
            version: cryptoki_sys::CK_VERSION { major: 3, minor: 2 },
        });
        assert!(matches!(set, TableSet::WalkKnownPrefix(_)));
        assert_eq!(walked(set), vec![FUNCTION_LIST_FIELDS.as_ptr()]);
        assert_eq!(field_count(set), 68);
    }

    #[test]
    fn standard_240_walks_base_and_other_2x_is_refused() {
        let set = tables_for(std_iface(2, 40));
        assert!(matches!(set, TableSet::Walk(_)));
        assert_eq!(walked(set), vec![FUNCTION_LIST_FIELDS.as_ptr()]);
        // OASIS defines the structure only as 0x02/0x28 "2.40 compatible";
        // an older 2.x table is not guaranteed to contain the full 2.40 tail.
        assert!(matches!(tables_for(std_iface(2, 30)), TableSet::Refuse));
        assert!(matches!(tables_for(std_iface(2, 20)), TableSet::Refuse));
    }

    #[test]
    fn standard_30_and_31_walk_base_plus_30() {
        for minor in [0, 1] {
            let set = tables_for(std_iface(3, minor));
            assert!(matches!(set, TableSet::Walk(_)));
            assert_eq!(
                walked(set),
                vec![FUNCTION_LIST_FIELDS.as_ptr(), FUNCTION_LIST_3_0_EXTRA_FIELDS.as_ptr()],
            );
        }
    }

    #[test]
    fn standard_32_walks_all_three() {
        let set = tables_for(std_iface(3, 2));
        assert!(matches!(set, TableSet::Walk(_)));
        assert_eq!(
            walked(set),
            vec![
                FUNCTION_LIST_FIELDS.as_ptr(),
                FUNCTION_LIST_3_0_EXTRA_FIELDS.as_ptr(),
                FUNCTION_LIST_3_2_EXTRA_FIELDS.as_ptr(),
            ],
        );
    }

    #[test]
    fn standard_3_minor_above_2_walks_known_prefix() {
        let set = tables_for(std_iface(3, 3));
        assert!(matches!(set, TableSet::WalkKnownPrefix(_)));
        assert_eq!(
            walked(set),
            vec![
                FUNCTION_LIST_FIELDS.as_ptr(),
                FUNCTION_LIST_3_0_EXTRA_FIELDS.as_ptr(),
                FUNCTION_LIST_3_2_EXTRA_FIELDS.as_ptr(),
            ],
        );
    }

    #[test]
    fn unknown_majors_are_refused() {
        assert!(matches!(tables_for(std_iface(4, 0)), TableSet::Refuse));
        assert!(matches!(tables_for(std_iface(1, 0)), TableSet::Refuse));
        assert!(matches!(tables_for(std_iface(0, 0)), TableSet::Refuse));
    }
}
