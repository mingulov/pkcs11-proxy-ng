use pkcs11_proxy_ng_types::*;

/// The backend ABI the mock emulates on the wire (ADR-0011).
///
/// A backend's ABI shows up in two wire-visible numbers: the `CK_ULONG`
/// width (attribute values, returned lengths) and the `CK_ATTRIBUTE`
/// struct stride (nested `CKA_*_TEMPLATE` byte lengths). Real backends:
/// LP64 Linux x86_64 (8-byte ulong, 24-byte stride), ILP32 Linux i686
/// (4, 12), and LLP64 Windows x64 with `#pragma pack(1)` (4, 16 — the
/// stride is NOT 3x the width, which is exactly why it must be modeled
/// separately).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockAbi {
    /// 64-bit Unix: `CK_ULONG` = 8, `CK_ATTRIBUTE` = 8+8+8.
    Lp64,
    /// 32-bit Unix: `CK_ULONG` = 4, `CK_ATTRIBUTE` = 4+4+4.
    Ilp32,
    /// Windows x64, packed(1): `CK_ULONG` = 4, `CK_ATTRIBUTE` = 4+8+4.
    Llp64,
}

impl MockAbi {
    /// The profile matching the process this mock runs in — the default,
    /// so existing tests keep emulating a host-native backend.
    pub fn host() -> Self {
        match std::mem::size_of::<cryptoki_sys::CK_ULONG>() {
            8 => Self::Lp64,
            _ if cfg!(windows) => Self::Llp64,
            _ => Self::Ilp32,
        }
    }

    /// Native `CK_ULONG` width in bytes.
    pub fn ulong_width(self) -> usize {
        match self {
            Self::Lp64 => 8,
            Self::Ilp32 | Self::Llp64 => 4,
        }
    }

    /// Native `sizeof(CK_ATTRIBUTE)`.
    pub fn attribute_stride(self) -> usize {
        match self {
            Self::Lp64 => 24,
            Self::Ilp32 => 12,
            Self::Llp64 => 16,
        }
    }

    /// Encode a value as this ABI's native `CK_ULONG` bytes (LE).
    ///
    /// Mock fixture values are small by construction; a value that does
    /// not fit the emulated width is a fixture bug, not a runtime case.
    pub fn encode_ulong(self, v: u64) -> Vec<u8> {
        let width = self.ulong_width();
        assert!(
            width == 8 || v <= u32::MAX as u64,
            "mock fixture value {v:#x} does not fit a {width}-byte CK_ULONG"
        );
        v.to_le_bytes()[..width].to_vec()
    }
}

/// Per-attribute slot in the mock attribute store.
///
/// Used with `MockBackend::set_attribute` to configure `get_attribute_value` behavior.
#[derive(Clone)]
pub enum MockAttributeSlot {
    /// The attribute has this value.
    Value(CkAttributeValue),
    /// The attribute is sensitive: `C_GetAttributeValue` must set `ulValueLen =
    /// CK_UNAVAILABLE_INFORMATION` and return `CKR_ATTRIBUTE_SENSITIVE`.
    Sensitive,
    /// The attribute type is invalid for this object: set `ulValueLen =
    /// CK_UNAVAILABLE_INFORMATION` and return `CKR_ATTRIBUTE_TYPE_INVALID`.
    InvalidType,
    /// The attribute is a nested `CK_ATTRIBUTE[]` template (CKF_ARRAY_ATTRIBUTE).
    ///
    /// Each entry is `(attr_type, sub_slot)` where `sub_slot` must be a `Value`.
    NestedTemplate(Vec<(CkAttributeType, MockAttributeSlot)>),
}

#[cfg(test)]
mod mock_abi_tests {
    use super::MockAbi;

    #[test]
    fn mock_abi_widths_and_strides() {
        assert_eq!(MockAbi::Lp64.ulong_width(), 8);
        assert_eq!(MockAbi::Ilp32.ulong_width(), 4);
        assert_eq!(MockAbi::Llp64.ulong_width(), 4);
        // CK_ATTRIBUTE strides: LP64 8+8+8; ILP32 4+4+4; LLP64 pack(1) 4+8+4.
        assert_eq!(MockAbi::Lp64.attribute_stride(), 24);
        assert_eq!(MockAbi::Ilp32.attribute_stride(), 12);
        assert_eq!(MockAbi::Llp64.attribute_stride(), 16);
    }

    #[test]
    fn mock_abi_host_matches_this_process() {
        let host = MockAbi::host();
        assert_eq!(host.ulong_width(), std::mem::size_of::<cryptoki_sys::CK_ULONG>());
        assert_eq!(host.attribute_stride(), std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>());
    }

    #[test]
    fn mock_abi_encode_ulong_matches_width() {
        assert_eq!(MockAbi::Lp64.encode_ulong(3), vec![3, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(MockAbi::Ilp32.encode_ulong(3), vec![3, 0, 0, 0]);
        assert_eq!(MockAbi::Llp64.encode_ulong(0x0102_0304), vec![4, 3, 2, 1]);
    }
}

/// Per-session active multi-part operation type (PKCS#11 §5.14).
///
/// Only one multi-part operation may be active per session at a time.
/// Attempting to start a second operation returns `CKR_OPERATION_ACTIVE`.
/// Calling update/final without init returns `CKR_OPERATION_NOT_INITIALIZED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiPartOp {
    Sign,
    SignRecover,
    Verify,
    VerifyRecover,
    Digest,
    Encrypt,
    Decrypt,
    FindObjects,
}
