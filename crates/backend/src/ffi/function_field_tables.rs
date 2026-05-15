//! Compile-time tables mapping function field names to their byte offsets
//! within CK_FUNCTION_LIST, CK_FUNCTION_LIST_3_0, and CK_FUNCTION_LIST_3_2.
//!
//! Used by `get_interface_capabilities()` to detect NULL function pointers
//! without manual field-by-field code.

use cryptoki_sys::*;

/// A (field_name, byte_offset) pair for a function pointer field.
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
/// `base` must point to a valid, properly-aligned struct of the type
/// that `fields` was generated from. The struct must remain valid
/// for the duration of this call.
pub unsafe fn detect_null_functions(base: *const u8, fields: &[FnField]) -> Vec<String> {
    let mut nulls = Vec::new();
    for field in fields {
        // Each function pointer field is `Option<unsafe extern "C" fn(...)>`,
        // which is pointer-sized. A None value is all-zero bytes.
        let ptr_val = unsafe { (base.add(field.offset) as *const usize).read() };
        if ptr_val == 0 {
            nulls.push(field.name.to_string());
        }
    }
    nulls
}
