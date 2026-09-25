//! Pure attribute-value width bridging for the shim's `C_GetAttributeValue`
//! output path (ADR-0011).
//!
//! Only ulong-typed attribute values cross a 32/64-bit `CK_ULONG` boundary in a
//! width-dependent way; opaque byte/string attributes are width-independent and
//! pass through untouched (preserving the exact-output contract and ADR-0010
//! transparency). These helpers are pure compositions over
//! [`pkcs11_proxy_ng_types::width`] so the full cross-width matrix is unit
//! tested here without any FFI; the `extern "C"` entry point is a thin wrapper.
//!
//! The wire carries the backend's native-width ulong bytes in the backend's
//! native byte order (asserted compatible with this client at probe —
//! ADR-0011 D6), so both edges encode/decode in the shared native order.

use pkcs11_proxy_ng_types::{
    ByteOrder, CkAttributeType, WidthError, reencode_ulong, translate_ulong_len,
};

/// True when this attribute's value is one or more `CK_ULONG`s and therefore
/// must be re-encoded between differing edge widths.
fn is_ulong_typed(attr_type: CkAttributeType) -> bool {
    attr_type.is_ulong() || attr_type.is_ulong_array()
}

/// Inflate a caller's (client-width) `C_GetAttributeValue` buffer length to the
/// backend width for a ulong-typed attribute, so the backend's one exact FFI
/// call allocates a correctly sized buffer.
///
/// No-op when the widths match or the attribute is not ulong-typed (opaque
/// bytes need no translation). A size query (`client_len == 0`) stays `0`.
pub fn bridge_request_buffer_len(
    attr_type: CkAttributeType,
    client_len: u64,
    client_width: usize,
    backend_width: usize,
) -> u64 {
    if client_width == backend_width || !is_ulong_typed(attr_type) {
        return client_len;
    }
    translate_ulong_len(client_len, client_width, backend_width)
}

/// Outer `CKA_*_TEMPLATE` buffer length, client layout -> backend layout.
///
/// Template byte lengths count whole `CK_ATTRIBUTE` structs, whose size is
/// an ABI property of each edge (24 LP64 / 12 ILP32 / 16 LLP64-packed;
/// 32-bit Windows packs to 12, sharing the ILP32 stride).
/// Rescale by entry count; a zero stride (defensive) passes through.
#[cfg(test)]
pub fn bridge_template_request_len(
    client_len: u64,
    client_stride: usize,
    backend_stride: usize,
) -> u64 {
    if client_stride == 0 || backend_stride == 0 || client_stride == backend_stride {
        return client_len;
    }
    (client_len / client_stride as u64) * backend_stride as u64
}

/// Pure size query: backend-layout template byte length -> client layout.
#[cfg(test)]
pub fn bridge_template_output_len(
    backend_len: u64,
    backend_stride: usize,
    client_stride: usize,
) -> u64 {
    bridge_template_request_len(backend_len, backend_stride, client_stride)
}

/// Re-encode a ulong-typed attribute's backend-width output value to the client
/// width and translate its `returned_len`.
///
/// Returns `(value_for_caller, client_returned_len)`:
/// - Opaque (non-ulong) attributes and same-width edges pass through unchanged.
/// - For a ulong scalar/array, the value bytes are re-encoded element-by-element
///   and the length is rescaled by element count; the canonical
///   `CK_UNAVAILABLE_INFORMATION` sentinel maps to the client-width all-ones.
/// - [`WidthError::Overflow`] is returned if a genuine backend value exceeds the
///   client's `CK_ULONG` range (D4) — the caller surfaces that attribute as
///   `CK_UNAVAILABLE_INFORMATION` rather than truncating or failing the whole
///   call.
pub fn bridge_output_value(
    attr_type: CkAttributeType,
    value: Option<&[u8]>,
    returned_len: u64,
    backend_width: usize,
    client_width: usize,
) -> Result<(Option<Vec<u8>>, u64), WidthError> {
    if backend_width == client_width || !is_ulong_typed(attr_type) {
        return Ok((value.map(<[u8]>::to_vec), returned_len));
    }
    let client_len = translate_ulong_len(returned_len, backend_width, client_width);
    let client_value = match value {
        Some(bytes) => {
            // D6 guarantees both edges share this client's native order.
            Some(reencode_ulong(bytes, backend_width, client_width, ByteOrder::native())?)
        }
        None => None,
    };
    Ok((client_value, client_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs11_proxy_ng_types::{CANONICAL_UNAVAILABLE, encode_native_ulong};

    const SCALAR: CkAttributeType = CkAttributeType::CLASS;
    const ARRAY: CkAttributeType = CkAttributeType::ALLOWED_MECHANISMS;
    const OPAQUE: CkAttributeType = CkAttributeType::MODULUS; // byte array

    #[test]
    fn template_request_len_rescales_by_stride() {
        // 2 client CK_ATTRIBUTEs -> 2 backend CK_ATTRIBUTEs.
        assert_eq!(bridge_template_request_len(48, 24, 12), 24); // LP64 client -> ILP32 backend
        assert_eq!(bridge_template_request_len(48, 24, 16), 32); // LP64 client -> LLP64 backend
        assert_eq!(bridge_template_request_len(24, 12, 24), 48); // ILP32 client -> LP64 backend
        assert_eq!(bridge_template_request_len(32, 16, 24), 48); // LLP64 client -> LP64 backend
    }

    #[test]
    fn template_len_same_stride_is_identity() {
        assert_eq!(bridge_template_request_len(48, 24, 24), 48);
        assert_eq!(bridge_template_output_len(24, 12, 12), 24);
    }

    #[test]
    fn template_len_zero_stride_passes_through() {
        assert_eq!(bridge_template_request_len(48, 0, 24), 48);
        assert_eq!(bridge_template_output_len(48, 24, 0), 48);
    }

    #[test]
    fn template_output_len_rescales_backend_to_client() {
        // Pure size query: backend-layout template bytes -> client layout.
        assert_eq!(bridge_template_output_len(24, 12, 24), 48); // ILP32 backend -> LP64 client
        assert_eq!(bridge_template_output_len(32, 16, 24), 48); // LLP64 backend -> LP64 client
        assert_eq!(bridge_template_output_len(48, 24, 16), 32); // LP64 backend -> LLP64 client
    }

    #[test]
    fn request_len_same_width_is_identity() {
        assert_eq!(bridge_request_buffer_len(SCALAR, 8, 8, 8), 8);
        assert_eq!(bridge_request_buffer_len(SCALAR, 4, 4, 4), 4);
    }

    #[test]
    fn request_len_passes_opaque_through() {
        // A non-ulong attribute is byte-addressed; its length never rescales.
        assert_eq!(bridge_request_buffer_len(OPAQUE, 256, 4, 8), 256);
    }

    #[test]
    fn request_len_inflates_scalar_and_array_to_backend_width() {
        // 32-bit client -> 64-bit backend: one ulong 4 -> 8 bytes.
        assert_eq!(bridge_request_buffer_len(SCALAR, 4, 4, 8), 8);
        // Array of three: 3*4 -> 3*8.
        assert_eq!(bridge_request_buffer_len(ARRAY, 12, 4, 8), 24);
        // Size query stays zero.
        assert_eq!(bridge_request_buffer_len(SCALAR, 0, 4, 8), 0);
    }

    #[test]
    fn request_len_deflates_for_narrow_backend() {
        // 64-bit client -> 32-bit backend: 8 -> 4.
        assert_eq!(bridge_request_buffer_len(SCALAR, 8, 8, 4), 4);
        assert_eq!(bridge_request_buffer_len(ARRAY, 24, 8, 4), 12);
    }

    #[test]
    fn output_same_width_is_identity() {
        let v = vec![1u8, 0, 0, 0, 0, 0, 0, 0];
        let (out, len) = bridge_output_value(SCALAR, Some(&v), 8, 8, 8).unwrap();
        assert_eq!(out, Some(v));
        assert_eq!(len, 8);
    }

    #[test]
    fn output_passes_opaque_through_unchanged() {
        // A byte-array attribute is never re-encoded even across widths.
        let v = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01];
        let (out, len) = bridge_output_value(OPAQUE, Some(&v), 5, 8, 4).unwrap();
        assert_eq!(out, Some(v));
        assert_eq!(len, 5);
    }

    /// Backend-native ulong bytes for `v` at `width` on this host.
    fn native_bytes(v: u64, width: usize) -> Vec<u8> {
        encode_native_ulong(v, width)
    }

    #[test]
    fn output_narrows_scalar_value_and_len_64_to_32() {
        // Value 3 on the wire as an 8-byte native ulong -> 4-byte native on a 32-bit client.
        let backend = native_bytes(3, 8);
        let (out, len) = bridge_output_value(SCALAR, Some(&backend), 8, 8, 4).unwrap();
        assert_eq!(out, Some(native_bytes(3, 4)));
        assert_eq!(len, 4);
    }

    #[test]
    fn output_widens_scalar_value_and_len_32_to_64() {
        let backend = native_bytes(7, 4);
        let (out, len) = bridge_output_value(SCALAR, Some(&backend), 4, 4, 8).unwrap();
        assert_eq!(out, Some(native_bytes(7, 8)));
        assert_eq!(len, 8);
    }

    #[test]
    fn output_reencodes_array_each_element() {
        // [1,2] as 8-byte native elements -> 4-byte native elements, len 16 -> 8.
        let mut backend = native_bytes(1, 8);
        backend.extend_from_slice(&native_bytes(2, 8));
        let (out, len) = bridge_output_value(ARRAY, Some(&backend), 16, 8, 4).unwrap();
        let mut want = native_bytes(1, 4);
        want.extend_from_slice(&native_bytes(2, 4));
        assert_eq!(out, Some(want));
        assert_eq!(len, 8);
    }

    #[test]
    fn output_maps_canonical_sentinel_len_to_client_width() {
        // Sensitive/unavailable attribute: returned_len is the canonical sentinel,
        // value absent. The client must see its own all-ones sentinel.
        let (out, len) = bridge_output_value(SCALAR, None, CANONICAL_UNAVAILABLE, 8, 4).unwrap();
        assert_eq!(out, None);
        assert_eq!(len, 0xFFFF_FFFF);
        let (_, len64) = bridge_output_value(SCALAR, None, CANONICAL_UNAVAILABLE, 4, 8).unwrap();
        assert_eq!(len64, u64::MAX);
    }

    #[test]
    fn output_rejects_value_exceeding_client_width() {
        // A genuine 64-bit value that does not fit a 32-bit client's CK_ULONG.
        let backend = native_bytes(0x1_0000_0001, 8);
        assert_eq!(bridge_output_value(SCALAR, Some(&backend), 8, 8, 4), Err(WidthError::Overflow));
    }
}

#[cfg(test)]
mod law_tests {
    //! Randomized law tests (seeded xorshift, dependency-free) for the
    //! bridge's pure length/value functions across every width and stride
    //! pairing — complements the pinned example matrix in `tests`.

    use pkcs11_proxy_ng_types::{CkAttributeType, encode_native_ulong};

    use super::*;

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
    const STRIDES: [usize; 3] = [12, 16, 24];

    #[test]
    fn law_template_len_round_trips_across_all_stride_pairs() {
        let mut rng = Rng(0x57F1_0000_0000_0001);
        for _ in 0..CASES {
            let entries = rng.next() % 4096;
            for from in STRIDES {
                for to in STRIDES {
                    let there = bridge_template_request_len(entries * from as u64, from, to);
                    assert_eq!(there, entries * to as u64, "{from}->{to}");
                    let back = bridge_template_output_len(there, to, from);
                    assert_eq!(back, entries * from as u64, "{from}->{to}->{from}");
                }
            }
        }
    }

    #[test]
    fn law_ulong_output_bridge_preserves_value_and_element_count() {
        let mut rng = Rng(0x0B1D_0000_0000_0002);
        for _ in 0..CASES {
            let n = 1 + (rng.next() % 4) as usize;
            let values: Vec<u64> = (0..n).map(|_| rng.next() & 0xFFFF_FFFF).collect();
            // Backend width 4 -> client width 8 (the widening direction).
            let backend_bytes: Vec<u8> =
                values.iter().flat_map(|v| encode_native_ulong(*v, 4)).collect();
            let (out, len) = bridge_output_value(
                CkAttributeType::ALLOWED_MECHANISMS,
                Some(&backend_bytes),
                backend_bytes.len() as u64,
                4,
                8,
            )
            .expect("widening never overflows");
            assert_eq!(len, (n * 8) as u64);
            let out = out.expect("value present");
            for (i, v) in values.iter().enumerate() {
                let got = u64::from_ne_bytes(out[i * 8..(i + 1) * 8].try_into().expect("8"));
                assert_eq!(got, *v, "element {i}");
            }
        }
    }

    #[test]
    fn law_opaque_attributes_are_never_rescaled() {
        let mut rng = Rng(0x0AA0_0000_0000_0003);
        for _ in 0..CASES {
            let len = rng.next() % 100_000;
            assert_eq!(
                bridge_request_buffer_len(CkAttributeType::MODULUS, len, 8, 4),
                len,
                "opaque byte attributes are byte-addressed at every width"
            );
        }
    }
}
