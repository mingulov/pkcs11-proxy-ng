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

    pub const RSA: Self = Self(0x00000000);
    pub const EC: Self = Self(0x00000003);
    pub const AES: Self = Self(0x0000001F);

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
