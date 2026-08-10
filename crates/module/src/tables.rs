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

/// Read every function-pointer field's raw value (for pointer→file-offset
/// mapping in discovery tooling).
///
/// # Safety
/// Same contract as [`detect_null_functions`]: `base` must point to a
/// valid, live struct of the type `fields` was generated from.
pub unsafe fn read_fn_pointers(base: *const u8, fields: &[FnField]) -> Vec<(&'static str, usize)> {
    fields
        .iter()
        .map(|field| {
            let value = unsafe { (base.add(field.offset) as *const usize).read_unaligned() };
            (field.name, value)
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
    /// Obtained via `C_GetFunctionList`. Only known to be base-size,
    /// regardless of what its own version field claims.
    LegacyFunctionList,
    /// A `C_GetInterfaceList`/`C_GetInterface` interface whose reported
    /// name is exactly "PKCS 11", with its validated reported version.
    StandardInterface { version: cryptoki_sys::CK_VERSION },
}

/// The tables that may be walked over a surface, in walk order.
#[derive(Debug, Clone, Copy)]
pub enum TableSet {
    Walk(&'static [&'static [FnField]]),
    /// 3.x with minor > 2: the listed tables are a safe *prefix*; fields
    /// beyond the known 3.2 layout exist but must be recorded as excess,
    /// not walked.
    WalkKnownPrefix(&'static [&'static [FnField]]),
    /// Unknown layout (non-2.40 2.x, unknown major): record, walk nothing.
    Refuse,
}

static BASE: &[&[FnField]] = &[FUNCTION_LIST_FIELDS];
static V3_0: &[&[FnField]] = &[FUNCTION_LIST_FIELDS, FUNCTION_LIST_3_0_EXTRA_FIELDS];
static V3_2: &[&[FnField]] =
    &[FUNCTION_LIST_FIELDS, FUNCTION_LIST_3_0_EXTRA_FIELDS, FUNCTION_LIST_3_2_EXTRA_FIELDS];

/// The single authority binding provenance + validated version to the
/// walkable field tables (spec §7). Both the proxy's capability scan and
/// the discovery helper go through this, so the invariant has one home.
pub fn tables_for(surface: Surface) -> TableSet {
    match surface {
        Surface::LegacyFunctionList => TableSet::Walk(BASE),
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
        let ptrs = unsafe { read_fn_pointers(buf.as_ptr(), FUNCTION_LIST_FIELDS) };
        assert_eq!(ptrs.len(), FUNCTION_LIST_FIELDS.len());
        assert_eq!(ptrs[0], ("C_Initialize", 0xDEAD_BEEF));
        assert!(ptrs[1..].iter().all(|(_, v)| *v == 0));
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
                s.iter().map(|f| f.as_ptr()).collect()
            }
            TableSet::Refuse => Vec::new(),
        }
    }

    #[test]
    fn legacy_walks_base_only_regardless_of_any_version_claim() {
        // Provenance, not the table's own bytes, decides: legacy is base-only.
        let set = tables_for(Surface::LegacyFunctionList);
        assert!(matches!(set, TableSet::Walk(_)));
        assert_eq!(walked(set), vec![FUNCTION_LIST_FIELDS.as_ptr()]);
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
