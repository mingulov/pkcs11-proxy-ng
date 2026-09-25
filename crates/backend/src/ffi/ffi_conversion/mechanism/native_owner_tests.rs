//! Row-1 retained-root ownership gates (C3M.6 order item 1).
//!
//! These tests pin the common-constructor requirement: the raw roots handed
//! to native code must survive ordinary Rust owner moves (Box/Vec/session
//! insertion) and remain readable through snapshots afterwards, under both
//! Miri borrow models. They use only unaligned raw reads, never typed
//! references into retained native storage.

use super::*;
use cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS;

fn pss_input() -> CkMechanism {
    CkMechanism {
        mechanism_type: CkMechanismType::RSA_PKCS_PSS,
        params: Some(CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
            hash_alg: CkMechanismType::SHA256,
            mgf: CkMgf(1),
            salt_len: 32,
        })),
    }
}

/// The common `from_box` RED: the retained PSS root must keep its address
/// and contents across a production-style owner move.
#[test]
fn native_owner_pss_retained_root_survives_moves_and_snapshots() {
    let ffi = mechanism_to_ffi(&pss_input()).expect("PSS parameters convert");
    let parameter_pointer = ffi.ck_mechanism().pParameter;
    assert!(!parameter_pointer.is_null(), "PSS keeps a live parameter root");
    // SAFETY: the owner is alive and unchanged; read once before the move.
    let before = unsafe { (parameter_pointer.cast::<CK_RSA_PKCS_PSS_PARAMS>()).read_unaligned() };
    // E0793: params structs are packed on Windows; assert on by-value copies.
    let (before_hash_alg, before_mgf, before_s_len) = (before.hashAlg, before.mgf, before.sLen);
    assert_eq!(before_hash_alg, CkMechanismType::SHA256.0 as cryptoki_sys::CK_MECHANISM_TYPE);
    assert_eq!(before_mgf, 1);
    assert_eq!(before_s_len, 32);

    // Move the owner the way session caches do: Box, then Vec growth.
    let boxed_owner = Box::new(ffi);
    let mut owners = Vec::with_capacity(1);
    owners.push(*boxed_owner);
    owners.reserve(8);
    let moved_owner = owners.pop().expect("moved owner remains present");

    let moved_p_parameter = moved_owner.ck_mechanism().pParameter;
    assert_eq!(
        moved_p_parameter, parameter_pointer,
        "owner move preserves the retained native root address"
    );
    // SAFETY: the moved owner is alive; the snapshot must read the same root.
    let after = unsafe {
        (moved_owner.ck_mechanism().pParameter.cast::<CK_RSA_PKCS_PSS_PARAMS>()).read_unaligned()
    };
    let (after_hash_alg, after_mgf, after_s_len) = (after.hashAlg, after.mgf, after.sLen);
    assert_eq!(after_hash_alg, before_hash_alg, "snapshot survives the owner move");
    assert_eq!(after_mgf, before_mgf, "snapshot survives the owner move");
    assert_eq!(after_s_len, before_s_len, "snapshot survives the owner move");
}
