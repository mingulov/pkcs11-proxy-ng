//! SP800-108 `CK_PRF_DATA_PARAM` value models (F5).
//!
//! The domain carries each data-param value as opaque bytes
//! (`PrfDataParam::value_presence` — W1-C9-12 deliberately models no
//! counter/DKM structs at the domain/proto layer). But four of the five
//! OASIS data types embed `CK_ULONG` scalars the provider reads via
//! aligned native loads (`sp800-108_key_derivation.md`: COUNTER and
//! counter-mode ITERATION_VARIABLE are `CK_SP800_108_COUNTER_FORMAT`,
//! DKM_LENGTH is `CK_SP800_108_DKM_LENGTH_FORMAT`, KEY_HANDLE is
//! `CK_OBJECT_HANDLE`; only BYTE_ARRAY is opaque bytes). Rebuilding them
//! as byte copies into align-1 `Vec<u8>` hands the provider client-layout
//! bytes at an unaligned address, violating the R19 reconstruction rule
//! ("never alignment-1 byte backing for provider-typed reads").
//!
//! These parsers decode the client-layout bytes into scalars, inferring
//! the client `CK_ULONG` width from the payload length — the only width
//! signal on the wire, and the same length-inference the server
//! `read_sp800_108_key_handle_value` codec and the mock key-handle
//! decoder already apply. Lengths matching neither width are
//! `MECHANISM_PARAM_INVALID`: a short payload would hand the provider a
//! buffer smaller than its native read (overread), and an ambiguous
//! middle length has no sound client-width reading (strictness
//! precedented by the server key-handle codec and the F4 exact-size rule).
//!
//! Endianness is native (`from_ne_bytes`): cross-endian clients are out
//! of scope (no big-endian CI target; the same assumption as the
//! existing server/mock key-handle codecs).

use pkcs11_proxy_ng_types::{CkResult, CkRv};

/// OASIS `CK_PRF_DATA_TYPE` ids as wire `u64` (single backend source of
/// truth; the mock match arms, the mechanism-entry filter, and the FFI
/// value-leg router import these).
pub(crate) const CK_SP800_108_ITERATION_VARIABLE: u64 =
    cryptoki_sys::CK_SP800_108_ITERATION_VARIABLE as u64;
pub(crate) const CK_SP800_108_COUNTER: u64 = cryptoki_sys::CK_SP800_108_COUNTER as u64;
pub(crate) const CK_SP800_108_DKM_LENGTH: u64 = cryptoki_sys::CK_SP800_108_DKM_LENGTH as u64;
pub(crate) const CK_SP800_108_BYTE_ARRAY: u64 = cryptoki_sys::CK_SP800_108_BYTE_ARRAY as u64;
pub(crate) const CK_SP800_108_KEY_HANDLE: u64 = cryptoki_sys::CK_SP800_108_KEY_HANDLE as u64;

/// Parsed `CK_SP800_108_COUNTER_FORMAT`: `{ bLittleEndian: CK_BBOOL,
/// ulWidthInBits: CK_ULONG }` (also the counter-mode iteration-variable
/// shape per the OASIS `CK_PRF_DATA_PARAM` prose).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sp800108CounterFormat {
    /// Raw `CK_BBOOL` byte, preserved verbatim (no 0/1 normalization —
    /// a degenerate client byte must reach the provider unchanged, as
    /// under direct loading).
    pub(crate) little_endian: u8,
    /// Width in bits, widened losslessly to `u64` from either width.
    pub(crate) width_in_bits: u64,
}

/// Parsed `CK_SP800_108_DKM_LENGTH_FORMAT`: `{ dkmLengthMethod:
/// CK_ULONG, bLittleEndian: CK_BBOOL, ulWidthInBits: CK_ULONG }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sp800108DkmLengthFormat {
    /// DKM length method, widened losslessly to `u64` (method *policy*
    /// stays with the caller — the parser accepts any value).
    pub(crate) method: u64,
    /// Raw `CK_BBOOL` byte, preserved verbatim (see
    /// [`Sp800108CounterFormat::little_endian`]).
    pub(crate) little_endian: u8,
    /// Width in bits, widened losslessly to `u64` from either width.
    pub(crate) width_in_bits: u64,
}

/// Decode a COUNTER (or counter-shaped ITERATION_VARIABLE) payload,
/// inferring the client `CK_ULONG` width from the length: 16 bytes is
/// LP64 `{u8, pad[7], u64}` with the width at offset 8, 8 bytes is ILP32
/// `{u8, pad[3], u32}` with the width at offset 4 (cryptoki-sys bindgen
/// offsets on both widths — pinned by the layout tests below).
pub(crate) fn parse_counter_format(value: &[u8]) -> CkResult<Sp800108CounterFormat> {
    match value.len() {
        16 => {
            let mut width = [0u8; 8];
            width.copy_from_slice(&value[8..16]);
            Ok(Sp800108CounterFormat {
                little_endian: value[0],
                width_in_bits: u64::from_ne_bytes(width),
            })
        }
        8 => {
            let mut width = [0u8; 4];
            width.copy_from_slice(&value[4..8]);
            Ok(Sp800108CounterFormat {
                little_endian: value[0],
                width_in_bits: u32::from_ne_bytes(width) as u64,
            })
        }
        _ => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

/// Decode a DKM_LENGTH payload: 24 bytes is LP64 `{u64, u8, pad[7],
/// u64}` (method at 0, bool at 8, width at 16), 12 bytes is ILP32
/// `{u32, u8, pad[3], u32}` (method at 0, bool at 4, width at 8).
pub(crate) fn parse_dkm_length_format(value: &[u8]) -> CkResult<Sp800108DkmLengthFormat> {
    match value.len() {
        24 => {
            let mut method = [0u8; 8];
            method.copy_from_slice(&value[0..8]);
            let mut width = [0u8; 8];
            width.copy_from_slice(&value[16..24]);
            Ok(Sp800108DkmLengthFormat {
                method: u64::from_ne_bytes(method),
                little_endian: value[8],
                width_in_bits: u64::from_ne_bytes(width),
            })
        }
        12 => {
            let mut method = [0u8; 4];
            method.copy_from_slice(&value[0..4]);
            let mut width = [0u8; 4];
            width.copy_from_slice(&value[8..12]);
            Ok(Sp800108DkmLengthFormat {
                method: u32::from_ne_bytes(method) as u64,
                little_endian: value[4],
                width_in_bits: u32::from_ne_bytes(width) as u64,
            })
        }
        _ => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

/// Decode a KEY_HANDLE payload: 8 bytes is an LP64 `CK_OBJECT_HANDLE`,
/// 4 bytes is an ILP32 one (mirrors the server
/// `read_sp800_108_key_handle_value` codec exactly, minus the
/// width echo — the FFI rebuild is always backend-native width).
pub(crate) fn parse_key_handle_value(value: &[u8]) -> CkResult<u64> {
    match value.len() {
        8 => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(value);
            Ok(u64::from_ne_bytes(bytes))
        }
        4 => {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(value);
            Ok(u32::from_ne_bytes(bytes) as u64)
        }
        _ => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LP64 counter-format vector (literal 16 bytes — the client layout,
    /// not the host's — so the same vector pins both directions on both
    /// CI widths).
    fn counter_lp64(little_endian: u8, width_in_bits: u64) -> Vec<u8> {
        let mut value = vec![0u8; 16];
        value[0] = little_endian;
        value[8..16].copy_from_slice(&width_in_bits.to_ne_bytes());
        value
    }

    /// ILP32 counter-format vector (literal 8 bytes).
    fn counter_ilp32(little_endian: u8, width_in_bits: u32) -> Vec<u8> {
        let mut value = vec![0u8; 8];
        value[0] = little_endian;
        value[4..8].copy_from_slice(&width_in_bits.to_ne_bytes());
        value
    }

    /// LP64 DKM-length-format vector (literal 24 bytes).
    fn dkm_lp64(method: u64, little_endian: u8, width_in_bits: u64) -> Vec<u8> {
        let mut value = vec![0u8; 24];
        value[0..8].copy_from_slice(&method.to_ne_bytes());
        value[8] = little_endian;
        value[16..24].copy_from_slice(&width_in_bits.to_ne_bytes());
        value
    }

    /// ILP32 DKM-length-format vector (literal 12 bytes).
    fn dkm_ilp32(method: u32, little_endian: u8, width_in_bits: u32) -> Vec<u8> {
        let mut value = vec![0u8; 12];
        value[0..4].copy_from_slice(&method.to_ne_bytes());
        value[4] = little_endian;
        value[8..12].copy_from_slice(&width_in_bits.to_ne_bytes());
        value
    }

    #[test]
    fn counter_format_layout_matches_bindgen_on_host_width() {
        // The parser's byte map must match the bindgen record on every
        // target: LP64 `{u8, pad[7], u64}` (16 bytes, width at 8), ILP32
        // `{u8, pad[3], u32}` (8 bytes, width at 4).
        let ulong = std::mem::size_of::<cryptoki_sys::CK_ULONG>();
        assert_eq!(
            std::mem::size_of::<cryptoki_sys::CK_SP800_108_COUNTER_FORMAT>(),
            2 * ulong,
            "counter format is two CK_ULONG"
        );
        assert_eq!(
            std::mem::align_of::<cryptoki_sys::CK_SP800_108_COUNTER_FORMAT>(),
            std::mem::align_of::<cryptoki_sys::CK_ULONG>(),
            "counter format aligns as CK_ULONG"
        );
        assert_eq!(
            std::mem::offset_of!(cryptoki_sys::CK_SP800_108_COUNTER_FORMAT, bLittleEndian),
            0,
            "bool at offset 0"
        );
        assert_eq!(
            std::mem::offset_of!(cryptoki_sys::CK_SP800_108_COUNTER_FORMAT, ulWidthInBits),
            ulong,
            "width follows one CK_ULONG"
        );
    }

    #[test]
    fn dkm_length_format_layout_matches_bindgen_on_host_width() {
        // LP64 `{u64, u8, pad[7], u64}` (24 bytes: 0/8/16), ILP32 `{u32,
        // u8, pad[3], u32}` (12 bytes: 0/4/8).
        let ulong = std::mem::size_of::<cryptoki_sys::CK_ULONG>();
        assert_eq!(
            std::mem::size_of::<cryptoki_sys::CK_SP800_108_DKM_LENGTH_FORMAT>(),
            3 * ulong,
            "DKM format is three CK_ULONG"
        );
        assert_eq!(
            std::mem::align_of::<cryptoki_sys::CK_SP800_108_DKM_LENGTH_FORMAT>(),
            std::mem::align_of::<cryptoki_sys::CK_ULONG>(),
            "DKM format aligns as CK_ULONG"
        );
        assert_eq!(
            std::mem::offset_of!(cryptoki_sys::CK_SP800_108_DKM_LENGTH_FORMAT, dkmLengthMethod),
            0,
            "method at offset 0"
        );
        assert_eq!(
            std::mem::offset_of!(cryptoki_sys::CK_SP800_108_DKM_LENGTH_FORMAT, bLittleEndian),
            ulong,
            "bool follows the method"
        );
        assert_eq!(
            std::mem::offset_of!(cryptoki_sys::CK_SP800_108_DKM_LENGTH_FORMAT, ulWidthInBits),
            2 * ulong,
            "width follows method + bool slot"
        );
    }

    #[test]
    fn parse_counter_format_accepts_both_widths() {
        let lp64 = parse_counter_format(&counter_lp64(1, 0x1_0000_0001)).unwrap();
        assert_eq!(
            lp64,
            Sp800108CounterFormat { little_endian: 1, width_in_bits: 0x1_0000_0001 },
            "LP64 width above u32::MAX survives"
        );
        let ilp32 = parse_counter_format(&counter_ilp32(0, 0xAABB_CCDD)).unwrap();
        assert_eq!(
            ilp32,
            Sp800108CounterFormat { little_endian: 0, width_in_bits: 0xAABB_CCDD },
            "ILP32 width widens losslessly"
        );
    }

    #[test]
    fn parse_counter_format_rejects_unmodelable_lengths() {
        // 12 is the ILP32 *DKM* size: struct sizes must not cross-talk.
        for len in [0, 1, 4, 7, 12, 15, 17, 20, 24, 32] {
            assert_eq!(
                parse_counter_format(&vec![0u8; len]).unwrap_err(),
                CkRv::MECHANISM_PARAM_INVALID,
                "{len}-byte counter payload must fail closed"
            );
        }
    }

    #[test]
    fn parse_counter_format_preserves_bool_byte_verbatim() {
        // Degenerate non-0/1 bytes are not normalized: the provider must
        // see exactly what a direct-loaded client handed it.
        let parsed = parse_counter_format(&counter_lp64(0x02, 32)).unwrap();
        assert_eq!(parsed.little_endian, 0x02, "bool byte passes through");
    }

    #[test]
    fn parse_dkm_length_format_accepts_both_widths() {
        let lp64 = parse_dkm_length_format(&dkm_lp64(2, 1, 512)).unwrap();
        assert_eq!(
            lp64,
            Sp800108DkmLengthFormat { method: 2, little_endian: 1, width_in_bits: 512 },
            "LP64 triple decodes"
        );
        let ilp32 = parse_dkm_length_format(&dkm_ilp32(1, 0, 0x1234_5678)).unwrap();
        assert_eq!(
            ilp32,
            Sp800108DkmLengthFormat { method: 1, little_endian: 0, width_in_bits: 0x1234_5678 },
            "ILP32 triple decodes and widens"
        );
    }

    #[test]
    fn parse_dkm_length_format_rejects_unmodelable_lengths() {
        // 8/16 are the counter sizes: struct sizes must not cross-talk.
        for len in [0, 4, 8, 11, 13, 16, 20, 23, 25] {
            assert_eq!(
                parse_dkm_length_format(&vec![0u8; len]).unwrap_err(),
                CkRv::MECHANISM_PARAM_INVALID,
                "{len}-byte DKM payload must fail closed"
            );
        }
    }

    #[test]
    fn parse_dkm_length_format_passes_method_through() {
        // The parser models the layout; method *policy* stays with the
        // caller (the mock rejects unknown methods, the FFI rebuilds).
        let parsed = parse_dkm_length_format(&dkm_lp64(99, 1, 64)).unwrap();
        assert_eq!(parsed.method, 99, "unknown method still parses");
    }

    #[test]
    fn parse_key_handle_value_accepts_both_widths() {
        let wide = parse_key_handle_value(&0x1122_3344_5566_7788u64.to_ne_bytes()).unwrap();
        assert_eq!(wide, 0x1122_3344_5566_7788, "LP64 handle decodes");
        let narrow = parse_key_handle_value(&0xDEAD_BEEFu32.to_ne_bytes()).unwrap();
        assert_eq!(narrow, 0xDEAD_BEEF, "ILP32 handle widens");
    }

    #[test]
    fn parse_key_handle_value_rejects_unmodelable_lengths() {
        for len in [0, 1, 3, 5, 6, 7, 12, 16] {
            assert_eq!(
                parse_key_handle_value(&vec![0u8; len]).unwrap_err(),
                CkRv::MECHANISM_PARAM_INVALID,
                "{len}-byte key payload must fail closed"
            );
        }
    }
}
