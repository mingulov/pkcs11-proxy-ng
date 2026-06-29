//! Pure `CK_ULONG` width translation for cross-ABI bridging (ADR-0011).
//!
//! The gRPC wire carries `CK_ULONG`-typed attribute values as the *source*
//! edge's native-width bytes; each C-ABI edge re-encodes them to its own native
//! `CK_ULONG` width. These functions are parameterised by
//! `(src_width, dst_width, byte_order)` so the full cross-width matrix
//! (`32<->64`, `64<->32`, `32<->32`, `64<->64`) is exhaustively testable on any
//! host — the "Tier A" unit seam of the ADR-0011 testing strategy. They are the
//! single source of truth for the bridge's value/length translation in both
//! directions (client output edge and server input edge).

/// Byte order of an edge's `CK_ULONG` encoding.
///
/// All currently supported targets are little-endian; the variant exists so a
/// big-endian backend is *detected* (and refused at probe) rather than silently
/// mis-decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    Little,
    Big,
}

/// Why a width translation could not be performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WidthError {
    /// A value did not fit the destination `CK_ULONG` width (narrowing
    /// overflow; ADR-0011 D4/D5).
    Overflow,
    /// The source byte length was not a whole number of `src_width` elements.
    Misaligned,
    /// A width other than 4 or 8 bytes (the only valid `CK_ULONG` widths).
    UnsupportedWidth,
}

/// Valid `CK_ULONG` byte widths.
const fn is_valid_width(w: usize) -> bool {
    w == 4 || w == 8
}

/// The platform-sized `CK_UNAVAILABLE_INFORMATION` sentinel (`~0UL`) for a given
/// `CK_ULONG` byte width: `0xFFFF_FFFF` for 4, `0xFFFF_FFFF_FFFF_FFFF` for 8.
pub const fn all_ones(width: usize) -> u64 {
    if width >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * width as u32)) - 1
    }
}

fn read_uint(bytes: &[u8], order: ByteOrder) -> u64 {
    let mut buf = [0u8; 8];
    let n = bytes.len().min(8);
    match order {
        ByteOrder::Little => buf[..n].copy_from_slice(&bytes[..n]),
        ByteOrder::Big => buf[8 - n..].copy_from_slice(&bytes[..n]),
    }
    match order {
        ByteOrder::Little => u64::from_le_bytes(buf),
        ByteOrder::Big => u64::from_be_bytes(buf),
    }
}

fn write_uint(v: u64, width: usize, order: ByteOrder) -> Vec<u8> {
    match order {
        ByteOrder::Little => v.to_le_bytes()[..width].to_vec(),
        ByteOrder::Big => v.to_be_bytes()[8 - width..].to_vec(),
    }
}

/// Re-encode a (possibly multi-element) `CK_ULONG` value from `src_width` to
/// `dst_width`, interpreting each element in `order`.
///
/// Used for scalar ulong attributes (one element) and ulong arrays such as
/// `CKA_ALLOWED_MECHANISMS` (`src_bytes.len() / src_width` elements). Converts
/// the *integer value* of each element, so a real value of `1` is always `1`
/// regardless of widths. Returns the destination-width bytes, or:
/// - [`WidthError::Overflow`] if any element exceeds the destination width
///   (narrowing a value that does not fit — never silently truncated);
/// - [`WidthError::Misaligned`] if `src_bytes.len()` is not a multiple of
///   `src_width`;
/// - [`WidthError::UnsupportedWidth`] for widths other than 4 or 8.
///
/// Widening (`dst_width >= src_width`) never overflows.
pub fn reencode_ulong(
    src_bytes: &[u8],
    src_width: usize,
    dst_width: usize,
    order: ByteOrder,
) -> Result<Vec<u8>, WidthError> {
    if !is_valid_width(src_width) || !is_valid_width(dst_width) {
        return Err(WidthError::UnsupportedWidth);
    }
    if !src_bytes.len().is_multiple_of(src_width) {
        return Err(WidthError::Misaligned);
    }
    let dst_max = all_ones(dst_width);
    let mut out = Vec::with_capacity(src_bytes.len() / src_width * dst_width);
    for chunk in src_bytes.chunks_exact(src_width) {
        let v = read_uint(chunk, order);
        if v > dst_max {
            return Err(WidthError::Overflow);
        }
        out.extend_from_slice(&write_uint(v, dst_width, order));
    }
    Ok(out)
}

/// Translate a `CK_ULONG`-typed attribute's `ulValueLen` from the source edge's
/// width to the destination edge's width.
///
/// - The platform-sized `CK_UNAVAILABLE_INFORMATION` sentinel (all-ones of the
///   *source* width) maps to all-ones of the *destination* width — the
///   sentinel-widening asymmetry of ADR-0011 (free when narrowing by
///   truncation, explicit when widening).
/// - Otherwise the length is a byte count of `src_width`-wide elements and is
///   rescaled to `dst_width`-wide elements: `(len / src_width) * dst_width`.
pub fn translate_ulong_len(src_len: u64, src_width: usize, dst_width: usize) -> u64 {
    if src_len == all_ones(src_width) {
        return all_ones(dst_width);
    }
    let elements = src_len / src_width as u64;
    elements * dst_width as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const LE: ByteOrder = ByteOrder::Little;
    const BE: ByteOrder = ByteOrder::Big;

    #[test]
    fn all_ones_is_platform_sized() {
        assert_eq!(all_ones(4), 0xFFFF_FFFF);
        assert_eq!(all_ones(8), u64::MAX);
    }

    #[test]
    fn reencode_widens_value_one_4_to_8() {
        // value 1, 4-byte LE -> 8-byte LE
        let out = reencode_ulong(&[1, 0, 0, 0], 4, 8, LE).unwrap();
        assert_eq!(out, vec![1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn reencode_narrows_value_one_8_to_4() {
        // value 1, 8-byte LE -> 4-byte LE; "1 stays 1"
        let out = reencode_ulong(&[1, 0, 0, 0, 0, 0, 0, 0], 8, 4, LE).unwrap();
        assert_eq!(out, vec![1, 0, 0, 0]);
    }

    #[test]
    fn reencode_narrowing_rejects_overflow_not_truncate() {
        // value 0x1_0000_0001 (low word is also 1) must NOT become 1.
        let src = 0x1_0000_0001u64.to_le_bytes();
        assert_eq!(reencode_ulong(&src, 8, 4, LE), Err(WidthError::Overflow));
    }

    #[test]
    fn reencode_identity_same_width() {
        assert_eq!(
            reencode_ulong(&[3, 0, 0, 0, 0, 0, 0, 0], 8, 8, LE).unwrap(),
            vec![3, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(reencode_ulong(&[7, 0, 0, 0], 4, 4, LE).unwrap(), vec![7, 0, 0, 0]);
    }

    #[test]
    fn reencode_ulong_array_narrows_each_element() {
        // [1, 2] as 8-byte LE elements -> [1, 2] as 4-byte LE elements
        let mut src = Vec::new();
        src.extend_from_slice(&1u64.to_le_bytes());
        src.extend_from_slice(&2u64.to_le_bytes());
        let out = reencode_ulong(&src, 8, 4, LE).unwrap();
        assert_eq!(out, vec![1, 0, 0, 0, 2, 0, 0, 0]);
    }

    #[test]
    fn reencode_ulong_array_widens_each_element() {
        // [5, 6] as 4-byte LE -> 8-byte LE
        let out = reencode_ulong(&[5, 0, 0, 0, 6, 0, 0, 0], 4, 8, LE).unwrap();
        let mut want = Vec::new();
        want.extend_from_slice(&5u64.to_le_bytes());
        want.extend_from_slice(&6u64.to_le_bytes());
        assert_eq!(out, want);
    }

    #[test]
    fn reencode_rejects_misaligned() {
        assert_eq!(reencode_ulong(&[1, 0, 0], 4, 8, LE), Err(WidthError::Misaligned));
    }

    #[test]
    fn reencode_rejects_bad_width() {
        assert_eq!(reencode_ulong(&[1, 0], 2, 8, LE), Err(WidthError::UnsupportedWidth));
        assert_eq!(reencode_ulong(&[1; 8], 8, 3, LE), Err(WidthError::UnsupportedWidth));
    }

    #[test]
    fn reencode_big_endian_roundtrip() {
        // value 1, 8-byte BE -> 4-byte BE
        let out = reencode_ulong(&1u64.to_be_bytes(), 8, 4, BE).unwrap();
        assert_eq!(out, vec![0, 0, 0, 1]);
        // value 1, 4-byte BE -> 8-byte BE
        let out = reencode_ulong(&[0, 0, 0, 1], 4, 8, BE).unwrap();
        assert_eq!(out, 1u64.to_be_bytes().to_vec());
    }

    #[test]
    fn translate_len_scalar_both_directions() {
        assert_eq!(translate_ulong_len(8, 8, 4), 4); // 64-bit backend ulong -> 32-bit client
        assert_eq!(translate_ulong_len(4, 4, 8), 8); // 32-bit backend ulong -> 64-bit client
        assert_eq!(translate_ulong_len(8, 8, 8), 8); // identity
        assert_eq!(translate_ulong_len(4, 4, 4), 4);
    }

    #[test]
    fn translate_len_array_rescales_by_element_count() {
        assert_eq!(translate_ulong_len(24, 8, 4), 12); // 3 elems: 3*8 -> 3*4
        assert_eq!(translate_ulong_len(12, 4, 8), 24); // 3 elems: 3*4 -> 3*8
    }

    #[test]
    fn translate_len_preserves_unavailable_sentinel_both_directions() {
        // narrowing: 0xFFFF_FFFF_FFFF_FFFF -> 0xFFFF_FFFF
        assert_eq!(translate_ulong_len(u64::MAX, 8, 4), 0xFFFF_FFFF);
        // widening: 0xFFFF_FFFF -> 0xFFFF_FFFF_FFFF_FFFF (must NOT zero-extend)
        assert_eq!(translate_ulong_len(0xFFFF_FFFF, 4, 8), u64::MAX);
        // identity
        assert_eq!(translate_ulong_len(u64::MAX, 8, 8), u64::MAX);
        assert_eq!(translate_ulong_len(0xFFFF_FFFF, 4, 4), 0xFFFF_FFFF);
    }
}
