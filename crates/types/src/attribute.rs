/// Attribute type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CkAttributeType(pub u64);

impl CkAttributeType {
    pub const VENDOR_DEFINED: Self = Self(0x8000_0000);

    pub const CLASS: Self = Self(0x00000000);
    pub const TOKEN: Self = Self(0x00000001);
    pub const PRIVATE: Self = Self(0x00000002);
    pub const LABEL: Self = Self(0x00000003);
    pub const VALUE: Self = Self(0x00000011);
    pub const CERTIFICATE_TYPE: Self = Self(0x00000080);
    pub const SUBJECT: Self = Self(0x00000101);
    pub const KEY_TYPE: Self = Self(0x00000100);
    pub const SENSITIVE: Self = Self(0x00000103);
    pub const ENCRYPT: Self = Self(0x00000104);
    pub const DECRYPT: Self = Self(0x00000105);
    pub const WRAP: Self = Self(0x00000106);
    pub const UNWRAP: Self = Self(0x00000107);
    pub const SIGN: Self = Self(0x00000108);
    pub const VERIFY: Self = Self(0x0000010A);
    pub const EXTRACTABLE: Self = Self(0x00000162);
    pub const MODULUS: Self = Self(0x00000120);
    pub const MODULUS_BITS: Self = Self(0x00000121);
    pub const PUBLIC_EXPONENT: Self = Self(0x00000122);
    pub const EC_PARAMS: Self = Self(0x00000180);
    pub const EC_POINT: Self = Self(0x00000181);
    pub const ID: Self = Self(0x00000102);
    pub const VALUE_LEN: Self = Self(0x00000161);

    /// `CKF_ARRAY_ATTRIBUTE` flag (0x40000000).
    const ARRAY_ATTRIBUTE_FLAG: u64 = 0x4000_0000;

    pub const WRAP_TEMPLATE: Self = Self(Self::ARRAY_ATTRIBUTE_FLAG | 0x00000211);
    pub const UNWRAP_TEMPLATE: Self = Self(Self::ARRAY_ATTRIBUTE_FLAG | 0x00000212);
    pub const DERIVE_TEMPLATE: Self = Self(Self::ARRAY_ATTRIBUTE_FLAG | 0x00000213);
    pub const ALLOWED_MECHANISMS: Self = Self(Self::ARRAY_ATTRIBUTE_FLAG | 0x00000600);

    pub const fn from_vendor(offset: u32) -> Self {
        Self(Self::VENDOR_DEFINED.0 | offset as u64)
    }

    pub const fn is_vendor_defined(self) -> bool {
        (self.0 & Self::VENDOR_DEFINED.0) == Self::VENDOR_DEFINED.0
    }

    /// Returns true if this attribute type has the `CKF_ARRAY_ATTRIBUTE` flag set,
    /// meaning its value is a nested `CK_ATTRIBUTE[]` template.
    pub const fn is_array_attribute(self) -> bool {
        (self.0 & Self::ARRAY_ATTRIBUTE_FLAG) == Self::ARRAY_ATTRIBUTE_FLAG
    }

    /// Returns true if this attribute type has a boolean value.
    pub fn is_bool(self) -> bool {
        matches!(
            self,
            Self::TOKEN
                | Self::PRIVATE
                | Self::SENSITIVE
                | Self::ENCRYPT
                | Self::DECRYPT
                | Self::WRAP
                | Self::UNWRAP
                | Self::SIGN
                | Self::VERIFY
                | Self::EXTRACTABLE
        )
    }

    /// Returns true if this attribute type has a CK_ULONG value.
    pub fn is_ulong(self) -> bool {
        matches!(
            self,
            Self::CLASS
                | Self::KEY_TYPE
                | Self::CERTIFICATE_TYPE
                | Self::MODULUS_BITS
                | Self::VALUE_LEN
        )
    }

    /// Returns true if this attribute's CK_ULONG value is used as an
    /// allocation size by backends.  Absurd values (e.g., ULONG_MAX)
    /// can cause capacity-overflow panics inside `extern "C"` backend
    /// functions, aborting the daemon process.
    pub fn is_allocation_size(self) -> bool {
        matches!(self, Self::VALUE_LEN | Self::MODULUS_BITS)
    }
}

/// A typed attribute value (ADR-0001: known attributes use typed serialization).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CkAttributeValue {
    Bool(bool),
    Ulong(u64),
    Bytes(Vec<u8>),
    String(String),
}

/// A single PKCS#11 attribute (type + optional value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkAttribute {
    pub attr_type: CkAttributeType,
    pub value: Option<CkAttributeValue>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_type_classification() {
        assert!(CkAttributeType::TOKEN.is_bool());
        assert!(CkAttributeType::CLASS.is_ulong());
        assert!(!CkAttributeType::LABEL.is_bool());
        assert!(!CkAttributeType::LABEL.is_ulong());
    }

    #[test]
    fn allocation_size_classification() {
        assert!(CkAttributeType::VALUE_LEN.is_allocation_size());
        assert!(CkAttributeType::MODULUS_BITS.is_allocation_size());
        // Constants, not sizes — should not be flagged
        assert!(!CkAttributeType::CLASS.is_allocation_size());
        assert!(!CkAttributeType::KEY_TYPE.is_allocation_size());
        assert!(!CkAttributeType::CERTIFICATE_TYPE.is_allocation_size());
    }

    #[test]
    fn subject_attribute_has_standard_id() {
        assert_eq!(CkAttributeType::SUBJECT.0, 0x0000_0101);
    }

    #[test]
    fn vendor_attribute_helpers() {
        let vendor = CkAttributeType::from_vendor(0x42);
        assert_eq!(vendor.0, 0x8000_0042);
        assert!(vendor.is_vendor_defined());
        assert!(!CkAttributeType::LABEL.is_vendor_defined());
    }
}
