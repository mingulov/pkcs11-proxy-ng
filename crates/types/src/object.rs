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
    pub const SHA512_224: Self = Self(0x0000_0027);
    pub const SHA512_256: Self = Self(0x0000_0028);
    pub const SEED: Self = Self(0x0000_0029);
    pub const GOSTR3410: Self = Self(0x0000_002A);
    pub const GOSTR3411: Self = Self(0x0000_002B);
    pub const GOST28147: Self = Self(0x0000_002C);
    pub const CHACHA20: Self = Self(0x0000_002D);
    pub const POLY1305: Self = Self(0x0000_002E);
    pub const AES_XTS: Self = Self(0x0000_002F);
    pub const SHA3_224: Self = Self(0x0000_0030);
    pub const SHA3_256: Self = Self(0x0000_0031);
    pub const SHA3_384: Self = Self(0x0000_0032);
    pub const SHA3_512: Self = Self(0x0000_0033);
    pub const BLAKE2B_160: Self = Self(0x0000_0034);
    pub const BLAKE2B_256: Self = Self(0x0000_0035);
    pub const BLAKE2B_384: Self = Self(0x0000_0036);
    pub const BLAKE2B_512: Self = Self(0x0000_0037);
    pub const SALSA20: Self = Self(0x0000_0038);
    pub const X2RATCHET: Self = Self(0x0000_0039);
    pub const EC_EDWARDS: Self = Self(0x0000_003A);
    pub const EC_MONTGOMERY: Self = Self(0x0000_003B);
    pub const HKDF: Self = Self(0x0000_003C);

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
}
