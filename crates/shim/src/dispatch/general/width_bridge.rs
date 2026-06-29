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
//! The wire carries the backend's native-width ulong bytes in little-endian
//! (the byte order is asserted compatible at probe — ADR-0011 D6), so both
//! edges encode/decode as little-endian.

use pkcs11_proxy_ng_types::CkAttributeType;
use pkcs11_proxy_ng_types::width::{self, ByteOrder, WidthError};

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
    width::translate_ulong_len(client_len, client_width, backend_width)
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
    let client_len = width::translate_ulong_len(returned_len, backend_width, client_width);
    let client_value = match value {
        Some(bytes) => {
            Some(width::reencode_ulong(bytes, backend_width, client_width, ByteOrder::Little)?)
        }
        None => None,
    };
    Ok((client_value, client_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs11_proxy_ng_types::width::CANONICAL_UNAVAILABLE;

    const SCALAR: CkAttributeType = CkAttributeType::CLASS;
    const ARRAY: CkAttributeType = CkAttributeType::ALLOWED_MECHANISMS;
    const OPAQUE: CkAttributeType = CkAttributeType::MODULUS; // byte array

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

    #[test]
    fn output_narrows_scalar_value_and_len_64_to_32() {
        // CKK_RSA = 0 on the wire as an 8-byte LE ulong -> 4-byte LE on a 32-bit client.
        let backend = 3u64.to_le_bytes().to_vec(); // value 3
        let (out, len) = bridge_output_value(SCALAR, Some(&backend), 8, 8, 4).unwrap();
        assert_eq!(out, Some(vec![3, 0, 0, 0]));
        assert_eq!(len, 4);
    }

    #[test]
    fn output_widens_scalar_value_and_len_32_to_64() {
        let backend = 7u32.to_le_bytes().to_vec();
        let (out, len) = bridge_output_value(SCALAR, Some(&backend), 4, 4, 8).unwrap();
        assert_eq!(out, Some(7u64.to_le_bytes().to_vec()));
        assert_eq!(len, 8);
    }

    #[test]
    fn output_reencodes_array_each_element() {
        // [1,2] as 8-byte LE elements -> 4-byte LE elements, len 16 -> 8.
        let mut backend = Vec::new();
        backend.extend_from_slice(&1u64.to_le_bytes());
        backend.extend_from_slice(&2u64.to_le_bytes());
        let (out, len) = bridge_output_value(ARRAY, Some(&backend), 16, 8, 4).unwrap();
        assert_eq!(out, Some(vec![1, 0, 0, 0, 2, 0, 0, 0]));
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
        let backend = 0x1_0000_0001u64.to_le_bytes().to_vec();
        assert_eq!(bridge_output_value(SCALAR, Some(&backend), 8, 8, 4), Err(WidthError::Overflow));
    }
}
