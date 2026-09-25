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
//!   `secret_to_plain` borrows, so the source is still wiped on drop
//!   ([`secret_into_plain`] consumes, leaving an empty owner behind).
//! - Duplicate-field encodings — which would otherwise multiply the freed
//!   plain allocations prost drops during merge — are rejected before decode
//!   by [`crate::protected_decode`] for inbound server requests (untrusted
//!   clients); see the trust boundary below for the response direction.
//!
//! Every other direction (prost `Vec<u8>`/`String` into `SecretBytes`) must
//! wrap immediately via `SecretBytes::new` (adopting, zero-copy) or
//! `SecretBytes::copy_from_slice`, never retaining the plain buffer.
//!
//! # Trust boundary (W1-L2-13)
//!
//! The pre-decode scan is request-directional: the daemon scans inbound
//! request bytes because its peers (shims/clients over local IPC) are
//! untrusted, but the shim never scans daemon responses. That asymmetry is
//! deliberate:
//!
//! - The daemon is the shim's trusted computing base: it serves the
//!   mechanism registry, session state, and all key material. A daemon
//!   that emits malicious duplicate-field encodings already owns every
//!   secret the scan would protect, so response scanning would add no
//!   security boundary.
//! - Both directions share one schema and one tonic/prost codec: a
//!   conforming daemon never emits duplicates, and only the server owns
//!   the raw-bytes hook (its tower layer) needed to scan before decode —
//!   the tonic client decodes internally with no interception point.
//!
//! If the daemon is ever treated as untrusted (multi-tenant or remote
//! daemon), response scanning must be wired (a custom client decoder over
//! the response descriptors) BEFORE relying on this boundary. The
//! `scan_covers_requests_only` test pins the request-only shape, so that
//! change cannot land without updating this section.

use pkcs11_proxy_ng_types::SecretBytes;

/// Copies secret bytes into a plain `Vec<u8>` for a prost message field.
///
/// See the [module](self) documentation for the standing ADR-0013 §5
/// justification. Callers must not retain the returned buffer beyond the
/// enclosing message encode.
pub fn secret_to_plain(secret: &SecretBytes) -> Vec<u8> {
    secret.expose(|bytes| bytes.to_vec())
}

/// Moves secret bytes into a plain `Vec<u8>` for a prost message field,
/// transferring the allocation without copying.
///
/// Consuming counterpart to [`secret_to_plain`] for owned conversions
/// (W1-C8-09): the wiping owner is replaced with an empty buffer, so no
/// byte is copied and nothing extra needs wiping. The standing ADR-0013 §5
/// justification in the [module](self) documentation applies unchanged —
/// callers must not retain the returned buffer beyond the enclosing
/// message encode.
pub fn secret_into_plain(secret: SecretBytes) -> Vec<u8> {
    let mut wiping = secret.into_zeroizing();
    std::mem::take(&mut *wiping)
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::protected_decode::protected_request_paths;

    /// W1-L2-13 pin: the pre-decode scan covers every RPC's REQUEST and
    /// nothing else. Responses have no scan entry point by construction
    /// (see the module trust-boundary docs); this test fails if an RPC
    /// gains a second scanned path, loses its request path, or drifts out
    /// of the request/response naming that makes the direction visible.
    #[test]
    fn scan_covers_requests_only() {
        let service = include_str!("../../../proto/pkcs11-proxy-ng/v1/service.proto");
        let mut methods = BTreeSet::new();
        // One rpc spans two lines; join continuations before parsing.
        let mut current = String::new();
        for line in service.lines() {
            let line = line.trim();
            if line.strip_prefix("rpc ").is_some() {
                assert!(current.is_empty(), "unterminated rpc line: {current}");
                current.push_str(line);
            } else if !current.is_empty() {
                current.push(' ');
                current.push_str(line);
            } else {
                continue;
            }
            if !current.ends_with(';') {
                continue;
            }
            let rest = current.strip_prefix("rpc ").expect("malformed rpc line");
            // `Method(Request) returns (Response);`
            let (method, rest) = rest.split_once('(').expect("malformed rpc line");
            let (request, rest) = rest.split_once(')').expect("malformed rpc line");
            assert!(
                request.ends_with("Request"),
                "request type {request} must be request-directional"
            );
            let response = rest
                .strip_prefix(" returns (")
                .and_then(|rest| rest.strip_suffix(");"))
                .expect("malformed rpc line");
            assert!(
                response.ends_with("Response"),
                "response type {response} must be response-directional"
            );
            assert!(methods.insert(method.to_owned()), "duplicate rpc {method}");
            current.clear();
        }
        assert!(current.is_empty(), "unterminated rpc line: {current}");
        assert!(!methods.is_empty(), "no rpc methods parsed");
        let protected: BTreeSet<String> =
            protected_request_paths().into_iter().map(ToString::to_string).collect();
        let expected: BTreeSet<String> = methods
            .iter()
            .map(|method| format!("/pkcs11_proxy_ng.v1.Pkcs11Proxy/{method}"))
            .collect();
        assert_eq!(
            protected, expected,
            "scan must cover exactly the RPC request set (responses are trusted, not scanned)"
        );
    }
}
