use pkcs11_proxy_ng_types::*;

/// The backend ABI the mock emulates on the wire (ADR-0011).
///
/// A backend's ABI shows up in two wire-visible numbers: the `CK_ULONG`
/// width (attribute values, returned lengths) and the `CK_ATTRIBUTE`
/// struct stride (nested `CKA_*_TEMPLATE` byte lengths). Real backends:
/// LP64 Linux x86_64 (8-byte ulong, 24-byte stride), ILP32 Linux i686
/// (4, 12), and LLP64 Windows x64 with `#pragma pack(1)` (4, 16 — the
/// stride is NOT 3x the width, which is exactly why it must be modeled
/// separately). 32-bit Windows (PE32) shares natural ILP32's two numbers
/// (`CK_ULONG` width 4 and `CK_ATTRIBUTE` stride 12, layout-identical),
/// so the width/stride modeling needs no fourth profile — but win32 is a
/// distinct packed v1 layout, so the mechanism-ABI identity does: that is
/// what `Ilp32Packed` is for. This is NOT a general pack(1)≡ILP32 theorem,
/// which is false: e.g. `CK_INFO` is 76 bytes naturally vs 72 packed, and
/// `CK_FUNCTION_LIST` fn fields shift by 2 (see task-t6b-review.md I1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockAbi {
    /// 64-bit Unix: `CK_ULONG` = 8, `CK_ATTRIBUTE` = 8+8+8.
    Lp64,
    /// 32-bit Unix: `CK_ULONG` = 4, `CK_ATTRIBUTE` = 4+4+4.
    Ilp32,
    /// Windows x64, packed(1): `CK_ULONG` = 4, `CK_ATTRIBUTE` = 4+8+4.
    Llp64,
    /// 32-bit Windows, packed(1): `CK_ULONG` = 4, `CK_ATTRIBUTE` =
    /// 4+4+4 — the same two numbers as [`MockAbi::Ilp32`] but the packed
    /// v1 layout (Q04: width/stride alone cannot name it).
    Ilp32Packed,
}

impl MockAbi {
    /// The profile matching the process this mock runs in — the default,
    /// so existing tests keep emulating a host-native backend.
    pub fn host() -> Self {
        match std::mem::size_of::<cryptoki_sys::CK_ULONG>() {
            8 => Self::Lp64,
            _ if cfg!(all(windows, target_pointer_width = "64")) => Self::Llp64,
            _ if cfg!(all(windows, target_pointer_width = "32")) => Self::Ilp32Packed,
            _ => Self::Ilp32,
        }
    }

    /// Native `CK_ULONG` width in bytes.
    pub fn ulong_width(self) -> usize {
        match self {
            Self::Lp64 => 8,
            Self::Ilp32 | Self::Llp64 | Self::Ilp32Packed => 4,
        }
    }

    /// Native `sizeof(CK_ATTRIBUTE)`.
    pub fn attribute_stride(self) -> usize {
        match self {
            Self::Lp64 => 24,
            Self::Ilp32 | Self::Ilp32Packed => 12,
            Self::Llp64 => 16,
        }
    }

    /// This profile's exact v1 native mechanism-parameter ABI (Q04): the
    /// packing is part of the profile's identity, never inferred from
    /// the width (which cannot separate [`MockAbi::Ilp32Packed`] from
    /// [`MockAbi::Ilp32`]).
    pub fn mechanism_param_abi(self) -> pkcs11_proxy_ng_types::shape_descriptors::ParamAbi {
        use pkcs11_proxy_ng_types::shape_descriptors::ParamAbi;
        match self {
            Self::Lp64 => ParamAbi::Lp64NativeLe,
            Self::Ilp32 => ParamAbi::Ilp32NativeLe,
            Self::Llp64 => ParamAbi::Llp64Packed1Le,
            Self::Ilp32Packed => ParamAbi::Ilp32Packed1Le,
        }
    }

    /// Encode a value as this ABI's native `CK_ULONG` bytes.
    ///
    /// The byte order follows the host: the mock emulates a same-endian
    /// backend (consistent with its default order advertisement), so a
    /// big-endian host gets big-endian bytes. Cross-endian peers stay
    /// covered by the D6-refusal advertisement knob, never by values.
    ///
    /// Mock fixture values are small by construction; a value that does
    /// not fit the emulated width is a fixture bug, not a runtime case.
    pub fn encode_ulong(self, v: u64) -> Vec<u8> {
        let width = self.ulong_width();
        assert!(
            width == 8 || v <= u32::MAX as u64,
            "mock fixture value {v:#x} does not fit a {width}-byte CK_ULONG"
        );
        encode_native_ulong(v, width)
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
    use pkcs11_proxy_ng_types::shape_descriptors::ParamAbi;

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
    fn mock_abi_packed32_profile_numbers() {
        // Q04: win32 shares natural ILP32's width/stride numbers (4, 12)
        // but is a distinct packed layout — the profile models both.
        assert_eq!(MockAbi::Ilp32Packed.ulong_width(), 4);
        assert_eq!(MockAbi::Ilp32Packed.attribute_stride(), 12);
        // Native-order pin (mirrors `mock_abi_encode_ulong_matches_width`).
        let narrow3: Vec<u8> =
            if cfg!(target_endian = "little") { vec![3, 0, 0, 0] } else { vec![0, 0, 0, 3] };
        assert_eq!(MockAbi::Ilp32Packed.encode_ulong(3), narrow3);
    }

    #[test]
    fn mock_abi_mechanism_param_abi_mapping() {
        // Q04: every profile maps to its exact v1 native ABI — packing
        // is part of the identity, never inferred from the width.
        assert_eq!(MockAbi::Lp64.mechanism_param_abi(), ParamAbi::Lp64NativeLe);
        assert_eq!(MockAbi::Ilp32.mechanism_param_abi(), ParamAbi::Ilp32NativeLe);
        assert_eq!(MockAbi::Llp64.mechanism_param_abi(), ParamAbi::Llp64Packed1Le);
        assert_eq!(MockAbi::Ilp32Packed.mechanism_param_abi(), ParamAbi::Ilp32Packed1Le);
    }

    #[test]
    fn mock_abi_host_matches_native_fact() {
        // Q04: on little-endian hosts the host profile IS the process's
        // own v1 ABI (including packed Windows builds); on big-endian
        // hosts there is no v1 ABI at all (server derivation stays
        // silent via the byte-order check).
        if cfg!(target_endian = "little") {
            assert_eq!(Some(MockAbi::host().mechanism_param_abi()), ParamAbi::native());
        } else {
            assert_eq!(ParamAbi::native(), None);
        }
    }

    #[test]
    fn mock_abi_host_matches_this_process() {
        let host = MockAbi::host();
        assert_eq!(host.ulong_width(), std::mem::size_of::<cryptoki_sys::CK_ULONG>());
        assert_eq!(host.attribute_stride(), std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>());
    }

    #[test]
    fn mock_abi_encode_ulong_matches_width() {
        // Native-order pins: identical bytes on little-endian hosts, the
        // byte-reversed form on big-endian ones.
        let le = cfg!(target_endian = "little");
        let wide3: Vec<u8> =
            if le { vec![3, 0, 0, 0, 0, 0, 0, 0] } else { vec![0, 0, 0, 0, 0, 0, 0, 3] };
        let narrow3: Vec<u8> = if le { vec![3, 0, 0, 0] } else { vec![0, 0, 0, 3] };
        let word: Vec<u8> = if le { vec![4, 3, 2, 1] } else { vec![1, 2, 3, 4] };
        assert_eq!(MockAbi::Lp64.encode_ulong(3), wide3);
        assert_eq!(MockAbi::Ilp32.encode_ulong(3), narrow3);
        assert_eq!(MockAbi::Llp64.encode_ulong(0x0102_0304), word);
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
