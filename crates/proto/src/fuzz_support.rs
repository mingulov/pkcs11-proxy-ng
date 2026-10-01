//! Harness-decoding routines shared by the `cargo-fuzz` targets and the
//! seed-semantics regression gates (`crates/proto/tests/fuzz_seed_semantics.rs`).
//!
//! The fuzz targets in `fuzz/fuzz_targets/` build their typed inputs from raw
//! bytes with small scaffolding routines. Duplicating that scaffolding in
//! tests would let the two drift apart, so the single implementation lives
//! here: harnesses call it to fuzz, and the gate tests call it to pin what
//! each named seed decodes to. `#[doc(hidden)]`: public only for that sharing,
//! not part of the crate's supported API.

use crate::pkcs11_proxy_ng::v1 as proto;
use crate::protected_decode::protected_request_paths;

/// Builds a proto [`Attribute`](proto::Attribute) from raw fuzzer bytes.
///
/// `depth` counts nested levels already above this attribute; construction
/// caps total depth at 4 so hostile inputs cannot stack-overflow the harness
/// itself, while still probing the D8 depth refusal. Returns the attribute
/// plus the unconsumed tail. Short inputs (under 10 bytes) yield a default
/// `attr_type: 0` attribute and consume nothing.
pub fn fuzz_build_attribute(data: &[u8], depth: u8) -> (proto::Attribute, &[u8]) {
    if data.len() < 10 {
        return (proto::Attribute { attr_type: 0, value: None }, data);
    }
    let attr_type = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let kind = data[8];
    let rest = &data[9..];
    // `rest` is non-empty (guarded by the length check above).
    let payload_len = rest[0] as usize;
    let (payload, rest) = rest.split_at(payload_len.min(rest.len()));
    // Bias the top two levels toward nesting so depth>=2 trees (the
    // D8 refusal path) are built often; cap total depth at 4 so hostile
    // inputs cannot stack-overflow the harness itself.
    let nested_allowed = depth < 4;
    let selector = if depth < 2 { kind % 7 } else { kind % 5 };
    let value = match selector {
        0 if !nested_allowed || depth >= 2 => None,
        1 if !nested_allowed || depth >= 2 => {
            Some(proto::attribute::Value::BoolValue(kind & 1 == 1))
        }
        2 => {
            let mut buf = [0u8; 8];
            let n = payload.len().min(8);
            buf[..n].copy_from_slice(&payload[..n]);
            Some(proto::attribute::Value::UlongValue(u64::from_le_bytes(buf)))
        }
        3 => Some(proto::attribute::Value::BytesValue(payload.to_vec())),
        4 => Some(proto::attribute::Value::StringValue(
            String::from_utf8_lossy(payload).into_owned(),
        )),
        _ => {
            // Nested template (kinds 5, 6): up to 3 sub-attributes while
            // depth budget remains; deeper input still builds a nested
            // value so D8 refusal is exercised.
            let mut subs = Vec::new();
            let mut tail = payload;
            for _ in 0..3 {
                if tail.is_empty() {
                    break;
                }
                let (sub, next) = fuzz_build_attribute(tail, depth + 1);
                subs.push(sub);
                if next.len() >= tail.len() {
                    break;
                }
                tail = next;
            }
            Some(proto::attribute::Value::NestedTemplate(proto::NestedAttributes {
                attributes: subs,
            }))
        }
    };
    (proto::Attribute { attr_type, value }, rest)
}

/// Counts nested-template levels in a built proto attribute (0 = scalar).
pub fn fuzz_nested_depth(attr: &proto::Attribute) -> usize {
    match &attr.value {
        Some(proto::attribute::Value::NestedTemplate(n)) => {
            1 + n.attributes.iter().map(fuzz_nested_depth).max().unwrap_or(0)
        }
        _ => 0,
    }
}

/// Splits raw fuzzer bytes into the `(path, payload)` pair the
/// `fuzz_protected_decode` harness feeds the wire scanner.
///
/// The first byte selects the path class — a real protected path (by index),
/// a near-miss `prefix + raw` or `real-path + suffix` variant, or arbitrary
/// bytes — and also places the path/payload split boundary. Returns `None`
/// for inputs under 2 bytes, mirroring the harness's minimum-length guard.
pub fn fuzz_split_protected_input(data: &[u8]) -> Option<(String, &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let paths = protected_request_paths();
    let selector = data[0];
    let path_bytes = &data[1..];
    let split_at =
        if path_bytes.is_empty() { 0 } else { (data[0] as usize) % (path_bytes.len() + 1) };
    let (path_raw, payload) = path_bytes.split_at(split_at);
    let path = match selector % 4 {
        0 => paths[(selector as usize) % paths.len()].to_string(),
        1 => format!("/pkcs11_proxy_ng.v1.Pkcs11Proxy/{}", String::from_utf8_lossy(path_raw)),
        2 => {
            format!(
                "{}{}",
                paths[(selector as usize) % paths.len()],
                String::from_utf8_lossy(path_raw)
            )
        }
        _ => String::from_utf8_lossy(path_raw).into_owned(),
    };
    Some((path, payload))
}
