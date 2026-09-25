//! Mechanism-accurate output lengths for the mock (no crypto).
//!
//! Real tokens produce digests/MACs of mechanism-defined sizes (SHA-256
//! = 32, SHA3-384 = 48, …). The mock echoes bytes of the right *length*
//! so the two-call buffer protocol is exercised with realistic sizes.
//! Signature lengths that are key-dependent (RSA, ECDSA) have no fixed
//! answer here and fall back to the caller's default.
//!
//! Values come from `cryptoki_sys::CKM_*` (authoritative OASIS numeric
//! assignments) so the table cannot drift from the header set.

use pkcs11_proxy_ng_types::CkMechanismType;

fn ckm(v: cryptoki_sys::CK_MECHANISM_TYPE) -> u64 {
    v as u64
}

/// Standalone hash-function output length in bytes, by mechanism.
///
/// `None` for anything that is not a standalone digest (signatures,
/// HMACs — those resolve through [`mac_len`] or a key-size fallback).
pub fn digest_len(mech: CkMechanismType) -> Option<usize> {
    use cryptoki_sys::*;
    let v = mech.0;
    Some(match v {
        x if x == ckm(CKM_SHA_1) => 20,
        x if x == ckm(CKM_SHA224) => 28,
        x if x == ckm(CKM_SHA256) => 32,
        x if x == ckm(CKM_SHA384) => 48,
        x if x == ckm(CKM_SHA512) => 64,
        x if x == ckm(CKM_SHA512_224) => 28,
        x if x == ckm(CKM_SHA512_256) => 32,
        x if x == ckm(CKM_SHA3_224) => 28,
        x if x == ckm(CKM_SHA3_256) => 32,
        x if x == ckm(CKM_SHA3_384) => 48,
        x if x == ckm(CKM_SHA3_512) => 64,
        x if x == ckm(CKM_MD5) => 16,
        x if x == ckm(CKM_MD2) => 16,
        x if x == ckm(CKM_RIPEMD128) => 16,
        x if x == ckm(CKM_RIPEMD160) => 20,
        x if x == ckm(CKM_BLAKE2B_160) => 20,
        x if x == ckm(CKM_BLAKE2B_256) => 32,
        x if x == ckm(CKM_BLAKE2B_384) => 48,
        x if x == ckm(CKM_BLAKE2B_512) => 64,
        x if x == ckm(CKM_GOSTR3411) => 32,
        _ => return None,
    })
}

/// MAC output length in bytes for HMAC / block-cipher MAC mechanisms.
///
/// `general_param` (the `CK_MAC_GENERAL_PARAMS` ulong of a `*_GENERAL`
/// mechanism) overrides the full-length default when present; the plain
/// HMAC of a hash is that hash's digest length; CMAC/GMAC/XCBC are
/// block-sized.
pub fn mac_len(mech: CkMechanismType, general_param: Option<u64>) -> Option<usize> {
    use cryptoki_sys::*;
    if let Some(n) = general_param {
        return Some(n as usize);
    }
    let v = mech.0;
    Some(match v {
        x if x == ckm(CKM_SHA_1_HMAC) => 20,
        x if x == ckm(CKM_SHA224_HMAC) => 28,
        x if x == ckm(CKM_SHA256_HMAC) => 32,
        x if x == ckm(CKM_SHA384_HMAC) => 48,
        x if x == ckm(CKM_SHA512_HMAC) => 64,
        x if x == ckm(CKM_SHA3_224_HMAC) => 28,
        x if x == ckm(CKM_SHA3_256_HMAC) => 32,
        x if x == ckm(CKM_SHA3_384_HMAC) => 48,
        x if x == ckm(CKM_SHA3_512_HMAC) => 64,
        x if x == ckm(CKM_MD5_HMAC) => 16,
        x if x == ckm(CKM_AES_CMAC) => 16,
        x if x == ckm(CKM_AES_XCBC_MAC) => 16,
        x if x == ckm(CKM_AES_XCBC_MAC_96) => 12,
        x if x == ckm(CKM_AES_GMAC) => 16,
        x if x == ckm(CKM_DES3_CMAC) => 8,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki_sys::*;

    fn m(v: cryptoki_sys::CK_MECHANISM_TYPE) -> CkMechanismType {
        CkMechanismType(v as u64)
    }

    #[test]
    fn digest_lengths_match_the_hash_family() {
        assert_eq!(digest_len(m(CKM_SHA_1)), Some(20));
        assert_eq!(digest_len(m(CKM_SHA256)), Some(32));
        assert_eq!(digest_len(m(CKM_SHA384)), Some(48));
        assert_eq!(digest_len(m(CKM_SHA512)), Some(64));
        assert_eq!(digest_len(m(CKM_SHA3_384)), Some(48));
        assert_eq!(digest_len(m(CKM_BLAKE2B_160)), Some(20));
        assert_eq!(digest_len(m(CKM_MD5)), Some(16));
        // A signature mechanism is not a standalone digest.
        assert_eq!(digest_len(m(CKM_RSA_PKCS)), None);
    }

    #[test]
    fn hmac_lengths_follow_the_underlying_hash() {
        assert_eq!(mac_len(m(CKM_SHA256_HMAC), None), Some(32));
        assert_eq!(mac_len(m(CKM_SHA_1_HMAC), None), Some(20));
        assert_eq!(mac_len(m(CKM_AES_CMAC), None), Some(16));
    }

    #[test]
    fn general_mac_honors_its_requested_length() {
        // CK_MAC_GENERAL_PARAMS overrides the full-length default.
        assert_eq!(mac_len(m(CKM_SHA256_HMAC_GENERAL), Some(12)), Some(12));
        assert_eq!(mac_len(m(CKM_AES_CMAC_GENERAL), Some(8)), Some(8));
    }

    #[test]
    fn unknown_mechanism_has_no_defined_length() {
        assert_eq!(digest_len(CkMechanismType(0xDEAD_BEEF)), None);
        assert_eq!(mac_len(CkMechanismType(0xDEAD_BEEF), None), None);
    }
}
