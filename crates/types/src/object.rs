/// Virtual object handle — scoped to logical client instance (ADR-0002 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CkObjectHandle(pub u64);

/// Object class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CkObjectClass(pub u64);

impl CkObjectClass {
    pub const VENDOR_DEFINED: Self = Self(0x8000_0000);

    pub const DATA: Self = Self(0x00000000);
    pub const CERTIFICATE: Self = Self(0x00000001);
    pub const PUBLIC_KEY: Self = Self(0x00000002);
    pub const PRIVATE_KEY: Self = Self(0x00000003);
    pub const SECRET_KEY: Self = Self(0x00000004);
    // Extended classes: OASIS PKCS#11 v3.2 CKO_* object classes
    // (pkcs11t.h; values verified against cryptoki-sys 0.5.0). The proxy
    // already models attributes of HW_FEATURE/MECHANISM/OTP objects.
    pub const HW_FEATURE: Self = Self(0x00000005);
    pub const DOMAIN_PARAMETERS: Self = Self(0x00000006);
    pub const MECHANISM: Self = Self(0x00000007);
    pub const OTP_KEY: Self = Self(0x00000008);
    pub const PROFILE: Self = Self(0x00000009);
    pub const VALIDATION: Self = Self(0x0000000A);
    pub const TRUST: Self = Self(0x0000000B);

    pub const fn from_vendor(offset: u32) -> Self {
        Self(Self::VENDOR_DEFINED.0 | offset as u64)
    }

    pub const fn is_vendor_defined(self) -> bool {
        (self.0 & Self::VENDOR_DEFINED.0) == Self::VENDOR_DEFINED.0
    }
}

/// Key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CkKeyType(pub u64);

impl CkKeyType {
    pub const VENDOR_DEFINED: Self = Self(0x8000_0000);

    // Asymmetric keys
    pub const RSA: Self = Self(0x0000_0000);
    pub const DSA: Self = Self(0x0000_0001);
    pub const DH: Self = Self(0x0000_0002);
    pub const EC: Self = Self(0x0000_0003);
    pub const X9_42_DH: Self = Self(0x0000_0004);
    pub const KEA: Self = Self(0x0000_0005);

    // Symmetric / legacy / HMAC
    pub const GENERIC_SECRET: Self = Self(0x0000_0010);
    pub const RC2: Self = Self(0x0000_0011);
    pub const RC4: Self = Self(0x0000_0012);
    pub const DES: Self = Self(0x0000_0013);
    pub const DES2: Self = Self(0x0000_0014);
    pub const DES3: Self = Self(0x0000_0015);
    pub const CAST: Self = Self(0x0000_0016);
    pub const CAST3: Self = Self(0x0000_0017);
    pub const CAST128: Self = Self(0x0000_0018);
    pub const RC5: Self = Self(0x0000_0019);
    pub const IDEA: Self = Self(0x0000_001A);
    pub const SKIPJACK: Self = Self(0x0000_001B);
    pub const BATON: Self = Self(0x0000_001C);
    pub const JUNIPER: Self = Self(0x0000_001D);
    pub const CDMF: Self = Self(0x0000_001E);
    pub const AES: Self = Self(0x0000_001F);
    pub const BLOWFISH: Self = Self(0x0000_0020);
    pub const TWOFISH: Self = Self(0x0000_0021);
    pub const SECURID: Self = Self(0x0000_0022);
    pub const HOTP: Self = Self(0x0000_0023);
    pub const ACTI: Self = Self(0x0000_0024);
    pub const CAMELLIA: Self = Self(0x0000_0025);
    pub const ARIA: Self = Self(0x0000_0026);
    // HMAC and modern key types, 0x27-0x4B. Values verified against
    // cryptoki-sys 0.5.0 (generated from the OASIS pkcs11t.h); the
    // key_type_and_class_tables_match_published_headers test pins every
    // entry against its binding. Names are the canonical CKK_* spellings.
    pub const MD5_HMAC: Self = Self(0x0000_0027);
    pub const SHA_1_HMAC: Self = Self(0x0000_0028);
    pub const RIPEMD128_HMAC: Self = Self(0x0000_0029);
    pub const RIPEMD160_HMAC: Self = Self(0x0000_002A);
    pub const SHA256_HMAC: Self = Self(0x0000_002B);
    pub const SHA384_HMAC: Self = Self(0x0000_002C);
    pub const SHA512_HMAC: Self = Self(0x0000_002D);
    pub const SHA224_HMAC: Self = Self(0x0000_002E);
    pub const SEED: Self = Self(0x0000_002F);
    pub const GOSTR3410: Self = Self(0x0000_0030);
    pub const GOSTR3411: Self = Self(0x0000_0031);
    pub const GOST28147: Self = Self(0x0000_0032);
    pub const CHACHA20: Self = Self(0x0000_0033);
    pub const POLY1305: Self = Self(0x0000_0034);
    pub const AES_XTS: Self = Self(0x0000_0035);
    pub const SHA3_224_HMAC: Self = Self(0x0000_0036);
    pub const SHA3_256_HMAC: Self = Self(0x0000_0037);
    pub const SHA3_384_HMAC: Self = Self(0x0000_0038);
    pub const SHA3_512_HMAC: Self = Self(0x0000_0039);
    pub const BLAKE2B_160_HMAC: Self = Self(0x0000_003A);
    pub const BLAKE2B_256_HMAC: Self = Self(0x0000_003B);
    pub const BLAKE2B_384_HMAC: Self = Self(0x0000_003C);
    pub const BLAKE2B_512_HMAC: Self = Self(0x0000_003D);
    pub const SALSA20: Self = Self(0x0000_003E);
    pub const X2RATCHET: Self = Self(0x0000_003F);
    pub const EC_EDWARDS: Self = Self(0x0000_0040);
    pub const EC_MONTGOMERY: Self = Self(0x0000_0041);
    pub const HKDF: Self = Self(0x0000_0042);
    pub const SHA512_224_HMAC: Self = Self(0x0000_0043);
    pub const SHA512_256_HMAC: Self = Self(0x0000_0044);
    pub const SHA512_T_HMAC: Self = Self(0x0000_0045);
    pub const HSS: Self = Self(0x0000_0046);
    pub const XMSS: Self = Self(0x0000_0047);
    pub const XMSSMT: Self = Self(0x0000_0048);
    pub const ML_KEM: Self = Self(0x0000_0049);
    pub const ML_DSA: Self = Self(0x0000_004A);
    pub const SLH_DSA: Self = Self(0x0000_004B);

    // Pre-T02 bare names, kept as deprecated aliases to the corrected
    // values for external source compatibility. They previously denoted
    // wrong values (a shifted range starting at 0x27) and omit the HMAC
    // suffix the standard names carry. In-tree code must use the
    // canonical names above; these aliases must never appear as competing
    // match arms (same value => unreachable pattern).
    #[deprecated(note = "use CkKeyType::SHA512_224_HMAC (corrected value 0x43)")]
    pub const SHA512_224: Self = Self(0x0000_0043);
    #[deprecated(note = "use CkKeyType::SHA512_256_HMAC (corrected value 0x44)")]
    pub const SHA512_256: Self = Self(0x0000_0044);
    #[deprecated(note = "use CkKeyType::SHA3_224_HMAC (corrected value 0x36)")]
    pub const SHA3_224: Self = Self(0x0000_0036);
    #[deprecated(note = "use CkKeyType::SHA3_256_HMAC (corrected value 0x37)")]
    pub const SHA3_256: Self = Self(0x0000_0037);
    #[deprecated(note = "use CkKeyType::SHA3_384_HMAC (corrected value 0x38)")]
    pub const SHA3_384: Self = Self(0x0000_0038);
    #[deprecated(note = "use CkKeyType::SHA3_512_HMAC (corrected value 0x39)")]
    pub const SHA3_512: Self = Self(0x0000_0039);
    #[deprecated(note = "use CkKeyType::BLAKE2B_160_HMAC (corrected value 0x3A)")]
    pub const BLAKE2B_160: Self = Self(0x0000_003A);
    #[deprecated(note = "use CkKeyType::BLAKE2B_256_HMAC (corrected value 0x3B)")]
    pub const BLAKE2B_256: Self = Self(0x0000_003B);
    #[deprecated(note = "use CkKeyType::BLAKE2B_384_HMAC (corrected value 0x3C)")]
    pub const BLAKE2B_384: Self = Self(0x0000_003C);
    #[deprecated(note = "use CkKeyType::BLAKE2B_512_HMAC (corrected value 0x3D)")]
    pub const BLAKE2B_512: Self = Self(0x0000_003D);

    pub const fn from_vendor(offset: u32) -> Self {
        Self(Self::VENDOR_DEFINED.0 | offset as u64)
    }

    pub const fn is_vendor_defined(self) -> bool {
        (self.0 & Self::VENDOR_DEFINED.0) == Self::VENDOR_DEFINED.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // W1-C9-07: the class table extends past SECRET_KEY(4) for the
    // HW_FEATURE/DOMAIN_PARAMETERS/MECHANISM/OTP_KEY classes whose
    // attributes the proxy already models.
    #[test]
    fn object_class_table_covers_extended_classes() {
        assert_eq!(CkObjectClass::DATA.0, 0x00000000);
        assert_eq!(CkObjectClass::CERTIFICATE.0, 0x00000001);
        assert_eq!(CkObjectClass::PUBLIC_KEY.0, 0x00000002);
        assert_eq!(CkObjectClass::PRIVATE_KEY.0, 0x00000003);
        assert_eq!(CkObjectClass::SECRET_KEY.0, 0x00000004);
        assert_eq!(CkObjectClass::HW_FEATURE.0, 0x00000005);
        assert_eq!(CkObjectClass::DOMAIN_PARAMETERS.0, 0x00000006);
        assert_eq!(CkObjectClass::MECHANISM.0, 0x00000007);
        assert_eq!(CkObjectClass::OTP_KEY.0, 0x00000008);
        assert_eq!(CkObjectClass::PROFILE.0, 0x00000009);
        assert_eq!(CkObjectClass::VALIDATION.0, 0x0000000A);
        assert_eq!(CkObjectClass::TRUST.0, 0x0000000B);
    }

    // Pins each deprecated pre-T02 bare name to its canonical target so the
    // aliases cannot drift. The allow is scoped: production code must use
    // the canonical names (see the alias docs).
    #[allow(deprecated)]
    #[test]
    fn deprecated_bare_names_alias_corrected_values() {
        assert_eq!(CkKeyType::SHA512_224, CkKeyType::SHA512_224_HMAC);
        assert_eq!(CkKeyType::SHA512_256, CkKeyType::SHA512_256_HMAC);
        assert_eq!(CkKeyType::SHA3_224, CkKeyType::SHA3_224_HMAC);
        assert_eq!(CkKeyType::SHA3_256, CkKeyType::SHA3_256_HMAC);
        assert_eq!(CkKeyType::SHA3_384, CkKeyType::SHA3_384_HMAC);
        assert_eq!(CkKeyType::SHA3_512, CkKeyType::SHA3_512_HMAC);
        assert_eq!(CkKeyType::BLAKE2B_160, CkKeyType::BLAKE2B_160_HMAC);
        assert_eq!(CkKeyType::BLAKE2B_256, CkKeyType::BLAKE2B_256_HMAC);
        assert_eq!(CkKeyType::BLAKE2B_384, CkKeyType::BLAKE2B_384_HMAC);
        assert_eq!(CkKeyType::BLAKE2B_512, CkKeyType::BLAKE2B_512_HMAC);
    }

    #[test]
    fn object_class_vendor_helpers() {
        let vendor = CkObjectClass::from_vendor(0x7B);
        assert_eq!(vendor.0, 0x8000_007B);
        assert!(vendor.is_vendor_defined());
        assert!(!CkObjectClass::PUBLIC_KEY.is_vendor_defined());
    }

    #[test]
    fn key_type_vendor_helpers() {
        let vendor = CkKeyType::from_vendor(0x55);
        assert_eq!(vendor.0, 0x8000_0055);
        assert!(vendor.is_vendor_defined());
        assert!(!CkKeyType::AES.is_vendor_defined());
    }

    /// Every named key-type/object-class constant matches the pinned header
    /// binding (`cryptoki-sys` 0.5, generated from the OASIS `pkcs11t.h`).
    /// Comparisons go project-const vs binding only — never project vs
    /// project — so a shifted table cannot stay self-consistent.
    #[test]
    fn key_type_and_class_tables_match_published_headers() {
        use cryptoki_sys as ck;
        let keys: &[(CkKeyType, ck::CK_KEY_TYPE, &str)] = &[
            (CkKeyType::RSA, ck::CKK_RSA, "RSA"),
            (CkKeyType::DSA, ck::CKK_DSA, "DSA"),
            (CkKeyType::DH, ck::CKK_DH, "DH"),
            (CkKeyType::EC, ck::CKK_EC, "EC"),
            (CkKeyType::X9_42_DH, ck::CKK_X9_42_DH, "X9_42_DH"),
            (CkKeyType::KEA, ck::CKK_KEA, "KEA"),
            (CkKeyType::GENERIC_SECRET, ck::CKK_GENERIC_SECRET, "GENERIC_SECRET"),
            (CkKeyType::RC2, ck::CKK_RC2, "RC2"),
            (CkKeyType::RC4, ck::CKK_RC4, "RC4"),
            (CkKeyType::DES, ck::CKK_DES, "DES"),
            (CkKeyType::DES2, ck::CKK_DES2, "DES2"),
            (CkKeyType::DES3, ck::CKK_DES3, "DES3"),
            (CkKeyType::CAST, ck::CKK_CAST, "CAST"),
            (CkKeyType::CAST3, ck::CKK_CAST3, "CAST3"),
            (CkKeyType::CAST128, ck::CKK_CAST128, "CAST128"),
            (CkKeyType::RC5, ck::CKK_RC5, "RC5"),
            (CkKeyType::IDEA, ck::CKK_IDEA, "IDEA"),
            (CkKeyType::SKIPJACK, ck::CKK_SKIPJACK, "SKIPJACK"),
            (CkKeyType::BATON, ck::CKK_BATON, "BATON"),
            (CkKeyType::JUNIPER, ck::CKK_JUNIPER, "JUNIPER"),
            (CkKeyType::CDMF, ck::CKK_CDMF, "CDMF"),
            (CkKeyType::AES, ck::CKK_AES, "AES"),
            (CkKeyType::BLOWFISH, ck::CKK_BLOWFISH, "BLOWFISH"),
            (CkKeyType::TWOFISH, ck::CKK_TWOFISH, "TWOFISH"),
            (CkKeyType::SECURID, ck::CKK_SECURID, "SECURID"),
            (CkKeyType::HOTP, ck::CKK_HOTP, "HOTP"),
            (CkKeyType::ACTI, ck::CKK_ACTI, "ACTI"),
            (CkKeyType::CAMELLIA, ck::CKK_CAMELLIA, "CAMELLIA"),
            (CkKeyType::ARIA, ck::CKK_ARIA, "ARIA"),
            (CkKeyType::MD5_HMAC, ck::CKK_MD5_HMAC, "MD5_HMAC"),
            (CkKeyType::SHA_1_HMAC, ck::CKK_SHA_1_HMAC, "SHA_1_HMAC"),
            (CkKeyType::RIPEMD128_HMAC, ck::CKK_RIPEMD128_HMAC, "RIPEMD128_HMAC"),
            (CkKeyType::RIPEMD160_HMAC, ck::CKK_RIPEMD160_HMAC, "RIPEMD160_HMAC"),
            (CkKeyType::SHA256_HMAC, ck::CKK_SHA256_HMAC, "SHA256_HMAC"),
            (CkKeyType::SHA384_HMAC, ck::CKK_SHA384_HMAC, "SHA384_HMAC"),
            (CkKeyType::SHA512_HMAC, ck::CKK_SHA512_HMAC, "SHA512_HMAC"),
            (CkKeyType::SHA224_HMAC, ck::CKK_SHA224_HMAC, "SHA224_HMAC"),
            (CkKeyType::SEED, ck::CKK_SEED, "SEED"),
            (CkKeyType::GOSTR3410, ck::CKK_GOSTR3410, "GOSTR3410"),
            (CkKeyType::GOSTR3411, ck::CKK_GOSTR3411, "GOSTR3411"),
            (CkKeyType::GOST28147, ck::CKK_GOST28147, "GOST28147"),
            (CkKeyType::CHACHA20, ck::CKK_CHACHA20, "CHACHA20"),
            (CkKeyType::POLY1305, ck::CKK_POLY1305, "POLY1305"),
            (CkKeyType::AES_XTS, ck::CKK_AES_XTS, "AES_XTS"),
            (CkKeyType::SHA3_224_HMAC, ck::CKK_SHA3_224_HMAC, "SHA3_224_HMAC"),
            (CkKeyType::SHA3_256_HMAC, ck::CKK_SHA3_256_HMAC, "SHA3_256_HMAC"),
            (CkKeyType::SHA3_384_HMAC, ck::CKK_SHA3_384_HMAC, "SHA3_384_HMAC"),
            (CkKeyType::SHA3_512_HMAC, ck::CKK_SHA3_512_HMAC, "SHA3_512_HMAC"),
            (CkKeyType::BLAKE2B_160_HMAC, ck::CKK_BLAKE2B_160_HMAC, "BLAKE2B_160_HMAC"),
            (CkKeyType::BLAKE2B_256_HMAC, ck::CKK_BLAKE2B_256_HMAC, "BLAKE2B_256_HMAC"),
            (CkKeyType::BLAKE2B_384_HMAC, ck::CKK_BLAKE2B_384_HMAC, "BLAKE2B_384_HMAC"),
            (CkKeyType::BLAKE2B_512_HMAC, ck::CKK_BLAKE2B_512_HMAC, "BLAKE2B_512_HMAC"),
            (CkKeyType::SALSA20, ck::CKK_SALSA20, "SALSA20"),
            (CkKeyType::X2RATCHET, ck::CKK_X2RATCHET, "X2RATCHET"),
            (CkKeyType::EC_EDWARDS, ck::CKK_EC_EDWARDS, "EC_EDWARDS"),
            (CkKeyType::EC_MONTGOMERY, ck::CKK_EC_MONTGOMERY, "EC_MONTGOMERY"),
            (CkKeyType::HKDF, ck::CKK_HKDF, "HKDF"),
            (CkKeyType::SHA512_224_HMAC, ck::CKK_SHA512_224_HMAC, "SHA512_224_HMAC"),
            (CkKeyType::SHA512_256_HMAC, ck::CKK_SHA512_256_HMAC, "SHA512_256_HMAC"),
            (CkKeyType::SHA512_T_HMAC, ck::CKK_SHA512_T_HMAC, "SHA512_T_HMAC"),
            (CkKeyType::HSS, ck::CKK_HSS, "HSS"),
            (CkKeyType::XMSS, ck::CKK_XMSS, "XMSS"),
            (CkKeyType::XMSSMT, ck::CKK_XMSSMT, "XMSSMT"),
            (CkKeyType::ML_KEM, ck::CKK_ML_KEM, "ML_KEM"),
            (CkKeyType::ML_DSA, ck::CKK_ML_DSA, "ML_DSA"),
            (CkKeyType::SLH_DSA, ck::CKK_SLH_DSA, "SLH_DSA"),
        ];
        for (project, binding, name) in keys {
            assert_eq!(project.0, *binding as u64, "CkKeyType::{name}");
        }
        let classes: &[(CkObjectClass, ck::CK_OBJECT_CLASS, &str)] = &[
            (CkObjectClass::DATA, ck::CKO_DATA, "DATA"),
            (CkObjectClass::CERTIFICATE, ck::CKO_CERTIFICATE, "CERTIFICATE"),
            (CkObjectClass::PUBLIC_KEY, ck::CKO_PUBLIC_KEY, "PUBLIC_KEY"),
            (CkObjectClass::PRIVATE_KEY, ck::CKO_PRIVATE_KEY, "PRIVATE_KEY"),
            (CkObjectClass::SECRET_KEY, ck::CKO_SECRET_KEY, "SECRET_KEY"),
            (CkObjectClass::HW_FEATURE, ck::CKO_HW_FEATURE, "HW_FEATURE"),
            (CkObjectClass::DOMAIN_PARAMETERS, ck::CKO_DOMAIN_PARAMETERS, "DOMAIN_PARAMETERS"),
            (CkObjectClass::MECHANISM, ck::CKO_MECHANISM, "MECHANISM"),
            (CkObjectClass::OTP_KEY, ck::CKO_OTP_KEY, "OTP_KEY"),
            (CkObjectClass::PROFILE, ck::CKO_PROFILE, "PROFILE"),
            (CkObjectClass::VALIDATION, ck::CKO_VALIDATION, "VALIDATION"),
            (CkObjectClass::TRUST, ck::CKO_TRUST, "TRUST"),
        ];
        for (project, binding, name) in classes {
            assert_eq!(project.0, *binding as u64, "CkObjectClass::{name}");
        }
    }
}
