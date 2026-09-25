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
/// The variants exist so a big-endian edge is *detected* (and refused at
/// probe when it mismatches the peer — ADR-0011 D6) rather than silently
/// mis-decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    Little,
    Big,
}

impl ByteOrder {
    /// The byte order of `CK_ULONG` on this build target.
    ///
    /// D6 refuses mismatched peers at probe, so past the probe both edges
    /// share the client's native order — bridge code must use this, never a
    /// hardcoded order, when (re-)encoding ulong values.
    pub fn native() -> Self {
        if cfg!(target_endian = "little") { Self::Little } else { Self::Big }
    }
}

/// Encode `v` as native-order `CK_ULONG` bytes of `width` (4 or 8).
///
/// The single source of truth for "emulated/native ulong bytes" outside
/// the FFI edge itself (the mock backend, bridge tests). Panics on any
/// other width; callers must ensure `v` fits `width` (a truncated value
/// here is a fixture bug, not a runtime case).
pub fn encode_native_ulong(v: u64, width: usize) -> Vec<u8> {
    assert!(width == 4 || width == 8, "CK_ULONG width must be 4 or 8, got {width}");
    let full = v.to_ne_bytes();
    if cfg!(target_endian = "little") { full[..width].to_vec() } else { full[8 - width..].to_vec() }
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
    if width >= 8 { u64::MAX } else { (1u64 << (8 * width as u32)) - 1 }
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

/// The canonical, width-independent wire encoding of
/// `CK_UNAVAILABLE_INFORMATION` ("no information available").
///
/// Each C-ABI edge maps its own native all-ones sentinel to/from this single
/// value, so the sentinel survives every width combination with one `== ` check
/// and needs no backend-width knowledge (see [`canonicalize_ulong`] /
/// [`decanonicalize_ulong`] for value fields, and [`translate_ulong_len`] for
/// lengths). ADR-0011.
pub const CANONICAL_UNAVAILABLE: u64 = u64::MAX;

/// Backend edge: map a source-width `CK_ULONG` value to its canonical wire form.
///
/// The source-width all-ones sentinel (`CK_UNAVAILABLE_INFORMATION`) becomes the
/// canonical [`CANONICAL_UNAVAILABLE`]; every other value passes through. Use for
/// plain `CK_ULONG`-valued fields (e.g. `CK_TOKEN_INFO` counts/sizes) so the
/// sentinel is recognised by any-width client.
pub fn canonicalize_ulong(value: u64, src_width: usize) -> u64 {
    if value == all_ones(src_width) { CANONICAL_UNAVAILABLE } else { value }
}

/// Client edge: map a canonical wire `CK_ULONG` value to the destination-width
/// native value (returned as `u64`, to be cast to the native `CK_ULONG`).
///
/// The canonical sentinel becomes the destination-width all-ones
/// (`CK_UNAVAILABLE_INFORMATION`); other values pass through, rejecting one that
/// does not fit the destination width (D4/D5). Use for plain `CK_ULONG`-valued
/// fields; lengths use [`translate_ulong_len`] and byte values use
/// [`reencode_ulong`].
pub fn decanonicalize_ulong(wire: u64, dst_width: usize) -> Result<u64, WidthError> {
    if wire == CANONICAL_UNAVAILABLE {
        return Ok(all_ones(dst_width));
    }
    if wire > all_ones(dst_width) {
        return Err(WidthError::Overflow);
    }
    Ok(wire)
}

/// Client edge: narrow a canonical wire `CK_ULONG` info-struct field to the
/// destination-width native value (returned as `u64`, to be cast to the native
/// `CK_ULONG`).
///
/// Info-struct fields such as the `CK_TOKEN_INFO` session counts and memory
/// sizes use `CK_UNAVAILABLE_INFORMATION` (all-ones) as a "no information"
/// sentinel, and unlike attribute values there is no caller buffer to reject a
/// too-large value against — `C_GetTokenInfo` must still succeed. So, unlike
/// [`decanonicalize_ulong`], this never errors:
///
/// - The canonical [`CANONICAL_UNAVAILABLE`] sentinel becomes the
///   destination-width all-ones (`CK_UNAVAILABLE_INFORMATION` in the caller's
///   width).
/// - A genuine value that does not fit the destination width is reported as
///   `CK_UNAVAILABLE_INFORMATION` rather than silently truncated: the value
///   exists but cannot be represented for a narrower caller, which is precisely
///   what that sentinel means.
/// - Every representable value (including `CK_EFFECTIVELY_INFINITE`, i.e. `0`)
///   passes through unchanged.
pub fn narrow_info_field(wire: u64, dst_width: usize) -> u64 {
    let ones = all_ones(dst_width);
    if wire == CANONICAL_UNAVAILABLE || wire > ones { ones } else { wire }
}

/// Check a wire `CK_RV`/`CK_SLOT_ID` against a caller width (TO26b group 2:
/// ownership §"Slot-event scope"). Returns the value unchanged when it fits
/// `dst_width` bytes, else `None` — the caller maps that to local
/// `CKR_FUNCTION_FAILED` without writing output. Never truncates: a
/// nonzero wide error must not become `CKR_OK`, and a wide slot must not
/// become a wrong slot.
pub fn checked_narrow_to_width(wire: u64, dst_width: usize) -> Option<u64> {
    if wire > all_ones(dst_width) { None } else { Some(wire) }
}

/// Translate a `CK_ULONG`-typed attribute's `ulValueLen` from the source edge's
/// width to the destination edge's width.
///
/// - The canonical [`CANONICAL_UNAVAILABLE`] sentinel maps to all-ones of the
///   *destination* width (`CK_UNAVAILABLE_INFORMATION`). Because the sentinel is
///   canonicalised at the backend edge, this is width-independent and symmetric.
/// - Otherwise the length is a byte count of `src_width`-wide elements and is
///   rescaled to `dst_width`-wide elements: `(len / src_width) * dst_width`.
pub fn translate_ulong_len(src_len: u64, src_width: usize, dst_width: usize) -> u64 {
    if src_len == CANONICAL_UNAVAILABLE {
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
    fn native_order_matches_target_endianness() {
        let want = if cfg!(target_endian = "little") { LE } else { BE };
        assert_eq!(ByteOrder::native(), want);
    }

    #[test]
    fn native_encode_decodes_to_value_at_both_widths() {
        // Order-independent pin: whatever this host's order is, the native
        // encoding must decode back to the value in the native order.
        for width in [4usize, 8] {
            let bytes = encode_native_ulong(0x0102_0304, width);
            assert_eq!(bytes.len(), width);
            let back = reencode_ulong(&bytes, width, 8, ByteOrder::native()).unwrap();
            let int_bytes: [u8; 8] = back.try_into().unwrap();
            let v = if cfg!(target_endian = "little") {
                u64::from_le_bytes(int_bytes)
            } else {
                u64::from_be_bytes(int_bytes)
            };
            assert_eq!(v, 0x0102_0304, "round-trip at width {width}");
        }
    }

    #[test]
    #[should_panic(expected = "CK_ULONG width must be 4 or 8")]
    fn native_encode_rejects_bad_width() {
        let _ = encode_native_ulong(1, 2);
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
    fn translate_len_maps_canonical_sentinel_to_native_both_directions() {
        // The wire sentinel is canonical (u64::MAX) regardless of backend width;
        // it maps to the destination-width all-ones in every direction.
        assert_eq!(translate_ulong_len(CANONICAL_UNAVAILABLE, 8, 4), 0xFFFF_FFFF);
        assert_eq!(translate_ulong_len(CANONICAL_UNAVAILABLE, 4, 8), u64::MAX);
        assert_eq!(translate_ulong_len(CANONICAL_UNAVAILABLE, 8, 8), u64::MAX);
        assert_eq!(translate_ulong_len(CANONICAL_UNAVAILABLE, 4, 4), 0xFFFF_FFFF);
    }

    #[test]
    fn canonicalize_maps_native_sentinel_to_canonical() {
        assert_eq!(canonicalize_ulong(0xFFFF_FFFF, 4), CANONICAL_UNAVAILABLE); // 32-bit backend
        assert_eq!(canonicalize_ulong(u64::MAX, 8), CANONICAL_UNAVAILABLE); // 64-bit backend
        assert_eq!(canonicalize_ulong(5, 4), 5); // regular value untouched
        assert_eq!(canonicalize_ulong(0, 8), 0); // CK_EFFECTIVELY_INFINITE (0) untouched
    }

    #[test]
    fn decanonicalize_maps_canonical_sentinel_to_native() {
        assert_eq!(decanonicalize_ulong(CANONICAL_UNAVAILABLE, 4), Ok(0xFFFF_FFFF));
        assert_eq!(decanonicalize_ulong(CANONICAL_UNAVAILABLE, 8), Ok(u64::MAX));
        assert_eq!(decanonicalize_ulong(5, 4), Ok(5));
        assert_eq!(decanonicalize_ulong(0x1_0000_0000, 4), Err(WidthError::Overflow));
    }

    #[test]
    fn narrow_info_field_maps_sentinel_overflow_and_values() {
        // The canonical wire sentinel becomes the destination-width
        // CK_UNAVAILABLE_INFORMATION in either width.
        assert_eq!(narrow_info_field(CANONICAL_UNAVAILABLE, 4), 0xFFFF_FFFF);
        assert_eq!(narrow_info_field(CANONICAL_UNAVAILABLE, 8), u64::MAX);
        // Representable values pass through unchanged.
        assert_eq!(narrow_info_field(42, 4), 42);
        assert_eq!(narrow_info_field(42, 8), 42);
        // CK_EFFECTIVELY_INFINITE (0) is a real value, untouched.
        assert_eq!(narrow_info_field(0, 4), 0);
        // A genuine value that does not fit the destination width is reported
        // as CK_UNAVAILABLE_INFORMATION rather than silently truncated: the
        // value exists but cannot be represented for a narrower caller, which
        // is exactly what that sentinel means.
        assert_eq!(narrow_info_field(0x1_0000_0000, 4), 0xFFFF_FFFF);
        assert_eq!(narrow_info_field(5_000_000_000, 4), 0xFFFF_FFFF);
    }

    #[test]
    fn checked_narrow_to_width_matrix() {
        // TO26b group 2: representable values pass through unchanged in
        // either width; unrepresentable values fail instead of truncating.
        for width in [4, 8] {
            assert_eq!(checked_narrow_to_width(0, width), Some(0));
            assert_eq!(checked_narrow_to_width(1, width), Some(1));
            assert_eq!(checked_narrow_to_width(0xFFFF_FFFF, width), Some(0xFFFF_FFFF));
        }
        assert_eq!(checked_narrow_to_width(0x1_0000_0000, 8), Some(0x1_0000_0000));
        assert_eq!(checked_narrow_to_width(u64::MAX, 8), Some(u64::MAX));
        // A wide nonzero value that a narrow caller cannot represent —
        // including one whose truncation would be CKR_OK — fails loudly.
        assert_eq!(checked_narrow_to_width(0x1_0000_0000, 4), None);
        assert_eq!(checked_narrow_to_width(0xDEAD_BEEF_0000_0000, 4), None);
        assert_eq!(checked_narrow_to_width(u64::MAX, 4), None);
    }

    #[test]
    fn sentinel_roundtrips_across_widths() {
        // 32-bit backend sentinel -> canonical wire -> 64-bit client native sentinel
        let wire = canonicalize_ulong(0xFFFF_FFFF, 4);
        assert_eq!(decanonicalize_ulong(wire, 8), Ok(u64::MAX));
        // regular value survives any direction
        assert_eq!(decanonicalize_ulong(canonicalize_ulong(7, 4), 8), Ok(7));
        assert_eq!(decanonicalize_ulong(canonicalize_ulong(7, 8), 4), Ok(7));
    }
}

#[cfg(test)]
mod law_tests {
    //! Randomized law tests (dependency-free): a seeded xorshift PRNG
    //! sweeps a few thousand cases per law, complementing the pinned
    //! example matrix above. Failures print the seed value so a case is
    //! reproducible by pasting it into a pinned test.

    use super::*;

    /// Deterministic xorshift64* — good enough to sweep input space,
    /// no dependency, identical on every arch/run.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    // Miri interprets ~100x slower; a smaller sweep still exercises the
    // laws' unsafe-free arithmetic paths there.
    const CASES: usize = if cfg!(miri) { 48 } else { 4096 };

    #[test]
    fn law_reencode_round_trips_for_representable_values() {
        // widen(narrow(x)) == x for narrow-representable arrays, and
        // narrow(widen(x)) == x always — element counts preserved.
        let mut rng = Rng(0xC0FF_EE00_0000_0001);
        for _ in 0..CASES {
            let n = (rng.next() % 5) as usize; // 0..=4 elements
            let narrow_values: Vec<u64> = (0..n).map(|_| rng.next() & 0xFFFF_FFFF).collect();
            let narrow_bytes: Vec<u8> =
                narrow_values.iter().flat_map(|v| (*v as u32).to_le_bytes()).collect();

            let widened = reencode_ulong(&narrow_bytes, 4, 8, ByteOrder::Little).expect("widen");
            assert_eq!(widened.len(), n * 8, "element count preserved");
            let back = reencode_ulong(&widened, 8, 4, ByteOrder::Little).expect("narrow back");
            assert_eq!(back, narrow_bytes, "narrow∘widen == id (values {narrow_values:?})");
        }
    }

    #[test]
    fn law_reencode_preserves_every_element_value() {
        let mut rng = Rng(0xDEC0_DE00_0000_0002);
        for _ in 0..CASES {
            let v = rng.next() & 0xFFFF_FFFF;
            let widened =
                reencode_ulong(&(v as u32).to_le_bytes(), 4, 8, ByteOrder::Little).expect("widen");
            assert_eq!(u64::from_le_bytes(widened.try_into().expect("8 bytes")), v);
        }
    }

    #[test]
    fn law_reencode_rejects_any_unrepresentable_element() {
        // D4: one element above the destination range poisons the array —
        // never truncation, regardless of position.
        let mut rng = Rng(0xBAD0_0000_0000_0003);
        for _ in 0..CASES {
            let n = 1 + (rng.next() % 4) as usize;
            let poison_at = (rng.next() as usize) % n;
            let mut bytes = Vec::new();
            for i in 0..n {
                let v: u64 = if i == poison_at {
                    (rng.next() | 0x1_0000_0000).max(0x1_0000_0000)
                } else {
                    rng.next() & 0xFFFF_FFFF
                };
                bytes.extend_from_slice(&v.to_le_bytes());
            }
            assert_eq!(
                reencode_ulong(&bytes, 8, 4, ByteOrder::Little),
                Err(WidthError::Overflow),
                "poison at {poison_at}/{n}"
            );
        }
    }

    #[test]
    fn law_translate_len_scales_by_element_count() {
        let mut rng = Rng(0x1E11_0000_0000_0004);
        for _ in 0..CASES {
            let elements = rng.next() % 10_000;
            for (from, to) in [(4usize, 8usize), (8, 4), (4, 4), (8, 8)] {
                assert_eq!(
                    translate_ulong_len(elements * from as u64, from, to),
                    elements * to as u64
                );
            }
        }
    }

    #[test]
    fn law_sentinel_canonicalization_round_trips() {
        let mut rng = Rng(0x5E17_0000_0000_0005);
        for width in [4usize, 8] {
            // The native all-ones always maps to the canonical sentinel and back.
            assert_eq!(canonicalize_ulong(all_ones(width), width), CANONICAL_UNAVAILABLE);
            assert_eq!(decanonicalize_ulong(CANONICAL_UNAVAILABLE, width), Ok(all_ones(width)));
            for _ in 0..CASES {
                // Any non-sentinel representable value round-trips unchanged.
                let v = rng.next() & (all_ones(width) >> 1); // below all-ones
                let wire = canonicalize_ulong(v, width);
                assert_eq!(wire, v, "non-sentinel values are untouched");
                assert_eq!(decanonicalize_ulong(wire, width), Ok(v));
            }
        }
    }
}
