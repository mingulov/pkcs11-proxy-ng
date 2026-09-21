//! Characterization pins for the
//! classify→spec→`byte_output_exact`→write_exact dispatch shape (W1-L11-09).
//!
//! Every site listed here delegates to one shared helper after the
//! extraction. These pins capture the pre-client-gate RV contract —
//! oversize input is `CKR_ARGUMENTS_BAD`, valid-but-uninitialized calls
//! are `CKR_CRYPTOKI_NOT_INITIALIZED` — and must pass identically before
//! AND after the refactor.

use super::*;

/// Full-shape exports: `(session, input ptr/len, output ptr/len)`.
type FullShapeFn = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV;

/// Output-only exports: `(session, output ptr/len)`; the input sent is
/// always empty bytes (never a classified NULL).
type OutputOnlyFn = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;

fn full_shape_sites() -> [(&'static str, FullShapeFn); 12] {
    [
        ("c_digest_encrypt_update", dispatch::general::c_digest_encrypt_update),
        ("c_decrypt_digest_update", dispatch::general::c_decrypt_digest_update),
        ("c_sign_encrypt_update", dispatch::general::c_sign_encrypt_update),
        ("c_decrypt_verify_update", dispatch::general::c_decrypt_verify_update),
        ("c_sign", dispatch::general::c_sign),
        ("c_sign_recover", dispatch::general::c_sign_recover),
        ("c_verify_recover", dispatch::general::c_verify_recover),
        ("c_digest", dispatch::general::c_digest),
        ("c_encrypt", dispatch::general::c_encrypt),
        ("c_encrypt_update", dispatch::general::c_encrypt_update),
        ("c_decrypt", dispatch::general::c_decrypt),
        ("c_decrypt_update", dispatch::general::c_decrypt_update),
    ]
}

fn output_only_sites() -> [(&'static str, OutputOnlyFn); 5] {
    [
        ("c_sign_final", dispatch::general::c_sign_final),
        ("c_digest_final", dispatch::general::c_digest_final),
        ("c_encrypt_final", dispatch::general::c_encrypt_final),
        ("c_decrypt_final", dispatch::general::c_decrypt_final),
        ("c_get_operation_state", dispatch::general::c_get_operation_state),
    ]
}

#[test]
fn byte_output_shape_oversize_input_is_arguments_bad() {
    // W1-L11-09 pin: the TooLarge input class is rejected with the
    // documented stable RV before any client use, on every full-shape
    // site. A dangling (never dereferenced) pointer proves the length
    // is rejected before any memory access.
    let _guard = shim_state_test_guard();
    let mut out = [0u8; 8];
    let mut out_len = out.len() as CK_ULONG;
    for (name, site) in full_shape_sites() {
        let rv = unsafe {
            site(
                0,
                std::ptr::dangling_mut::<CK_BYTE>(),
                CK_ULONG::MAX,
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV, "{name}: oversize input");
    }
}

#[test]
fn byte_output_shape_uninitialized_is_not_initialized() {
    // W1-L11-09 pin: with valid arguments, every site reaches the
    // with_client! init gate (uninitialized → CRYPTOKI_NOT_INITIALIZED),
    // proving classification/spec succeed and the RPC path is entered.
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    assert!(!state::is_initialized(), "test requires pre-init state");
    let input = [0u8; 1];
    let mut out = [0u8; 8];
    let mut out_len = out.len() as CK_ULONG;
    for (name, site) in full_shape_sites() {
        let rv =
            unsafe { site(0, input.as_ptr() as CK_BYTE_PTR, 0, out.as_mut_ptr(), &mut out_len) };
        assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV, "{name}: uninitialized");
    }
    for (name, site) in output_only_sites() {
        let rv = unsafe { site(0, out.as_mut_ptr(), &mut out_len) };
        assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV, "{name}: uninitialized");
    }
}
