// CK_ULONG is u32 on narrow targets (i686, armv7, Windows x64), so the
// `as u64` widens below are no-ops here but required there; scoped
// allow keeps the width conversions explicit (ADR-0011, W1-L12-07).
#![allow(clippy::unnecessary_cast)]
//! Consistency guard for the width-bridge attribute classifier (ADR-0011 D10).
//!
//! `CkAttributeType` (in the `types` crate, which does not depend on
//! `cryptoki-sys`) hard-codes the hex values of the `CK_ULONG`-typed attributes
//! the width bridge re-encodes. This test — in the `shim` crate, which depends on
//! both — pins every classified value to the authoritative `cryptoki_sys::CKA_*`
//! constant, so a hex typo or an upstream value change fails the build rather
//! than silently mis-encoding (or skipping) an attribute across a 32/64-bit ABI.
//!
//! The set itself is sourced from the OASIS attribute-type tables (see
//! `CkAttributeType::is_ulong`); adding/removing a classifier entry requires
//! updating the corresponding list here, which is the intended drift guard.

use cryptoki_sys::CK_ATTRIBUTE_TYPE;
use pkcs11_proxy_ng_types::CkAttributeType;

const SCALAR_ULONG: &[(CkAttributeType, CK_ATTRIBUTE_TYPE)] = &[
    (CkAttributeType::CLASS, cryptoki_sys::CKA_CLASS),
    (CkAttributeType::CERTIFICATE_TYPE, cryptoki_sys::CKA_CERTIFICATE_TYPE),
    (CkAttributeType::CERTIFICATE_CATEGORY, cryptoki_sys::CKA_CERTIFICATE_CATEGORY),
    (CkAttributeType::JAVA_MIDP_SECURITY_DOMAIN, cryptoki_sys::CKA_JAVA_MIDP_SECURITY_DOMAIN),
    (CkAttributeType::NAME_HASH_ALGORITHM, cryptoki_sys::CKA_NAME_HASH_ALGORITHM),
    (CkAttributeType::KEY_TYPE, cryptoki_sys::CKA_KEY_TYPE),
    (CkAttributeType::AUTH_PIN_FLAGS, cryptoki_sys::CKA_AUTH_PIN_FLAGS),
    (CkAttributeType::MODULUS_BITS, cryptoki_sys::CKA_MODULUS_BITS),
    (CkAttributeType::PRIME_BITS, cryptoki_sys::CKA_PRIME_BITS),
    (CkAttributeType::SUBPRIME_BITS, cryptoki_sys::CKA_SUBPRIME_BITS),
    (CkAttributeType::VALUE_BITS, cryptoki_sys::CKA_VALUE_BITS),
    (CkAttributeType::VALUE_LEN, cryptoki_sys::CKA_VALUE_LEN),
    (CkAttributeType::KEY_GEN_MECHANISM, cryptoki_sys::CKA_KEY_GEN_MECHANISM),
    (CkAttributeType::OTP_FORMAT, cryptoki_sys::CKA_OTP_FORMAT),
    (CkAttributeType::OTP_LENGTH, cryptoki_sys::CKA_OTP_LENGTH),
    (CkAttributeType::OTP_TIME_INTERVAL, cryptoki_sys::CKA_OTP_TIME_INTERVAL),
    (CkAttributeType::OTP_CHALLENGE_REQUIREMENT, cryptoki_sys::CKA_OTP_CHALLENGE_REQUIREMENT),
    (CkAttributeType::OTP_TIME_REQUIREMENT, cryptoki_sys::CKA_OTP_TIME_REQUIREMENT),
    (CkAttributeType::OTP_COUNTER_REQUIREMENT, cryptoki_sys::CKA_OTP_COUNTER_REQUIREMENT),
    (CkAttributeType::OTP_PIN_REQUIREMENT, cryptoki_sys::CKA_OTP_PIN_REQUIREMENT),
    (CkAttributeType::HW_FEATURE_TYPE, cryptoki_sys::CKA_HW_FEATURE_TYPE),
    (CkAttributeType::PIXEL_X, cryptoki_sys::CKA_PIXEL_X),
    (CkAttributeType::PIXEL_Y, cryptoki_sys::CKA_PIXEL_Y),
    (CkAttributeType::RESOLUTION, cryptoki_sys::CKA_RESOLUTION),
    (CkAttributeType::CHAR_ROWS, cryptoki_sys::CKA_CHAR_ROWS),
    (CkAttributeType::CHAR_COLUMNS, cryptoki_sys::CKA_CHAR_COLUMNS),
    (CkAttributeType::BITS_PER_PIXEL, cryptoki_sys::CKA_BITS_PER_PIXEL),
    (CkAttributeType::MECHANISM_TYPE, cryptoki_sys::CKA_MECHANISM_TYPE),
    (CkAttributeType::PROFILE_ID, cryptoki_sys::CKA_PROFILE_ID),
    (CkAttributeType::X2RATCHET_BAGSIZE, cryptoki_sys::CKA_X2RATCHET_BAGSIZE),
    (CkAttributeType::X2RATCHET_NR, cryptoki_sys::CKA_X2RATCHET_NR),
    (CkAttributeType::X2RATCHET_NS, cryptoki_sys::CKA_X2RATCHET_NS),
    (CkAttributeType::X2RATCHET_PNS, cryptoki_sys::CKA_X2RATCHET_PNS),
    (CkAttributeType::HSS_LEVELS, cryptoki_sys::CKA_HSS_LEVELS),
    (CkAttributeType::HSS_LMS_TYPE, cryptoki_sys::CKA_HSS_LMS_TYPE),
    (CkAttributeType::HSS_LMOTS_TYPE, cryptoki_sys::CKA_HSS_LMOTS_TYPE),
    (CkAttributeType::HSS_KEYS_REMAINING, cryptoki_sys::CKA_HSS_KEYS_REMAINING),
    (CkAttributeType::PARAMETER_SET, cryptoki_sys::CKA_PARAMETER_SET),
    (CkAttributeType::OBJECT_VALIDATION_FLAGS, cryptoki_sys::CKA_OBJECT_VALIDATION_FLAGS),
    (CkAttributeType::VALIDATION_TYPE, cryptoki_sys::CKA_VALIDATION_TYPE),
    (CkAttributeType::VALIDATION_LEVEL, cryptoki_sys::CKA_VALIDATION_LEVEL),
    (CkAttributeType::VALIDATION_FLAG, cryptoki_sys::CKA_VALIDATION_FLAG),
    (CkAttributeType::VALIDATION_AUTHORITY_TYPE, cryptoki_sys::CKA_VALIDATION_AUTHORITY_TYPE),
    (CkAttributeType::TRUST_SERVER_AUTH, cryptoki_sys::CKA_TRUST_SERVER_AUTH),
    (CkAttributeType::TRUST_CLIENT_AUTH, cryptoki_sys::CKA_TRUST_CLIENT_AUTH),
    (CkAttributeType::TRUST_CODE_SIGNING, cryptoki_sys::CKA_TRUST_CODE_SIGNING),
    (CkAttributeType::TRUST_EMAIL_PROTECTION, cryptoki_sys::CKA_TRUST_EMAIL_PROTECTION),
    (CkAttributeType::TRUST_IPSEC_IKE, cryptoki_sys::CKA_TRUST_IPSEC_IKE),
    (CkAttributeType::TRUST_TIME_STAMPING, cryptoki_sys::CKA_TRUST_TIME_STAMPING),
    (CkAttributeType::TRUST_OCSP_SIGNING, cryptoki_sys::CKA_TRUST_OCSP_SIGNING),
];
const ULONG_ARRAY: &[(CkAttributeType, CK_ATTRIBUTE_TYPE)] = &[
    (CkAttributeType::ALLOWED_MECHANISMS, cryptoki_sys::CKA_ALLOWED_MECHANISMS),
    (CkAttributeType::HSS_LMS_TYPES, cryptoki_sys::CKA_HSS_LMS_TYPES),
    (CkAttributeType::HSS_LMOTS_TYPES, cryptoki_sys::CKA_HSS_LMOTS_TYPES),
];

#[test]
fn scalar_ulong_values_match_cryptoki_sys() {
    for (ours, theirs) in SCALAR_ULONG {
        assert_eq!(
            ours.0, *theirs as u64,
            "{ours:?} hex diverges from cryptoki_sys (0x{:08x} vs 0x{:08x})",
            ours.0, theirs
        );
        assert!(ours.is_ulong(), "{ours:?} must classify as scalar ulong");
        assert!(!ours.is_ulong_array(), "{ours:?} must not classify as ulong array");
    }
}

#[test]
fn ulong_array_values_match_cryptoki_sys() {
    for (ours, theirs) in ULONG_ARRAY {
        assert_eq!(
            ours.0, *theirs as u64,
            "{ours:?} hex diverges from cryptoki_sys (0x{:08x} vs 0x{:08x})",
            ours.0, theirs
        );
        assert!(ours.is_ulong_array(), "{ours:?} must classify as ulong array");
        assert!(!ours.is_ulong(), "{ours:?} must not classify as scalar ulong");
    }
}

#[test]
fn classifications_are_mutually_exclusive() {
    // A given attribute is at most one of: scalar ulong, ulong array, bool,
    // nested attribute template. Overlap would route a value through two
    // incompatible bridge paths.
    for (ours, _) in SCALAR_ULONG.iter().chain(ULONG_ARRAY) {
        let n =
            [ours.is_ulong(), ours.is_ulong_array(), ours.is_bool(), ours.is_attribute_template()]
                .into_iter()
                .filter(|&b| b)
                .count();
        assert_eq!(n, 1, "{ours:?} must match exactly one value-shape classifier, matched {n}");
    }
}
