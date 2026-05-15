use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

#[allow(unused_imports)]
use super::*;

// ---------------------------------------------------------------------------
// Stubs for unsupported / out-of-scope functions
//
// Each stub has the exact signature required by its CK_FUNCTION_LIST slot so
// no transmute is needed. The architecture rule requires non-null pointers for
// every exported slot, so these return CKR_FUNCTION_NOT_SUPPORTED instead of
// wiring None into the function list.
// ---------------------------------------------------------------------------

/// Zero-argument fallback — kept only for completeness.
#[allow(dead_code)]
pub unsafe extern "C" fn c_not_supported() -> CK_RV {
    rv_err(CkRv::FUNCTION_NOT_SUPPORTED)
}

/// Session-scoped fallback — kept for completeness.
#[allow(dead_code)]
pub unsafe extern "C" fn c_not_supported_session(_h: CK_SESSION_HANDLE) -> CK_RV {
    rv_err(CkRv::FUNCTION_NOT_SUPPORTED)
}

#[allow(dead_code)]
pub unsafe extern "C" fn c_not_supported_msg_init(
    _h: CK_SESSION_HANDLE,
    _p_mechanism: *mut CK_MECHANISM,
    _h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    rv_err(CkRv::FUNCTION_NOT_SUPPORTED)
}

// 3.2-only stubs have been replaced by real implementations in Wave 5:
// - VerifySignature* in verify_signature.rs
// - WrapKeyAuthenticated/UnwrapKeyAuthenticated in authenticated_wrap.rs
// - Async* in async_ops.rs
