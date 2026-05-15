use std::sync::OnceLock;

use cryptoki_sys::*;

use crate::dispatch::general;
use crate::function_registry::build_function_list_3_x;

static FUNC_LIST_3_2: OnceLock<CK_FUNCTION_LIST_3_2> = OnceLock::new();

pub fn get_function_list_3_2() -> *mut CK_FUNCTION_LIST_3_2 {
    let fl = FUNC_LIST_3_2.get_or_init(build_function_list_3_2);
    fl as *const CK_FUNCTION_LIST_3_2 as *mut CK_FUNCTION_LIST_3_2
}

fn build_function_list_3_2() -> CK_FUNCTION_LIST_3_2 {
    // All 2.40 and 3.0 functions are wired the same way as the earlier
    // function lists. New 3.2 functions remain non-null stubs until modeled.
    build_function_list_3_x!(
        CK_FUNCTION_LIST_3_2,
        CK_VERSION { major: 3, minor: 2 },
        // 3.2-only: KEM operations
        C_EncapsulateKey: Some(general::c_encapsulate_key),
        C_DecapsulateKey: Some(general::c_decapsulate_key),
        // 3.2-only: VerifySignature operations
        C_VerifySignatureInit: Some(general::c_verify_signature_init),
        C_VerifySignature: Some(general::c_verify_signature),
        C_VerifySignatureUpdate: Some(general::c_verify_signature_update),
        C_VerifySignatureFinal: Some(general::c_verify_signature_final),
        // 3.2-only: session validation
        C_GetSessionValidationFlags: Some(general::c_get_session_validation_flags),
        // 3.2-only: async operations
        C_AsyncComplete: Some(general::c_async_complete),
        C_AsyncGetID: Some(general::c_async_get_id),
        C_AsyncJoin: Some(general::c_async_join),
        // 3.2-only: authenticated wrap/unwrap
        C_WrapKeyAuthenticated: Some(general::c_wrap_key_authenticated),
        C_UnwrapKeyAuthenticated: Some(general::c_unwrap_key_authenticated),
    )
}
