//! ADR-0013 §5 prost-boundary helpers: every conversion from a wiping
//! owner into a plain allocation must be visible at its caller.
//!
//! prost generates `Vec<u8>`/`String` for protobuf `bytes`/`string` fields;
//! that codegen cannot emit `SecretBytes`. Each call below is therefore a
//! forced plain allocation at the protobuf boundary. The justification
//! ADR-0013 §5 requires lives here, once, instead of being repeated (or
//! omitted) at each of the ~100 call sites; the call sites stay visible
//! because they name these helpers explicitly:
//!
//! - The plain buffer's lifetime is minimal: response/request messages are
//!   encoded by tonic immediately after conversion and dropped at handler
//!   scope. No plain copy is cached, logged, or retained.
//! - The wiping owner on the other side of the conversion is unaffected:
//!   `secret_to_plain` borrows, so the source is still wiped on drop.
//! - Duplicate-field encodings — which would otherwise multiply the freed
//!   plain allocations prost drops during merge — are rejected before decode
//!   by [`crate::protected_decode`] (server requests, client responses).
//!
//! Every other direction (prost `Vec<u8>`/`String` into `SecretBytes`) must
//! wrap immediately via `SecretBytes::new` (adopting, zero-copy) or
//! `SecretBytes::copy_from_slice`, never retaining the plain buffer.

use pkcs11_proxy_ng_types::SecretBytes;

/// Copies secret bytes into a plain `Vec<u8>` for a prost message field.
///
/// See the [module](self) documentation for the standing ADR-0013 §5
/// justification. Callers must not retain the returned buffer beyond the
/// enclosing message encode.
pub fn secret_to_plain(secret: &SecretBytes) -> Vec<u8> {
    secret.expose(|bytes| bytes.to_vec())
}

/// Copies secret bytes into a plain `String` for a prost `string` field.
///
/// Decoding is lossy: values carried in `SecretBytes` string positions
/// originate from valid-UTF-8 prost strings, so a well-formed pipeline
/// round-trips exactly; malformed bytes degrade to U+FFFD instead of
/// panicking. See the [module](self) documentation for the standing
/// ADR-0013 §5 justification.
pub fn secret_to_plain_string(secret: &SecretBytes) -> String {
    secret.expose(|bytes| String::from_utf8_lossy(bytes).into_owned())
}
