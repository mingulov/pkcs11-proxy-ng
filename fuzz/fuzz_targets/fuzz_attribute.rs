#![no_main]

//! Fuzz the attribute proto<->Rust edge plus the attribute-type predicates.
//!
//! Properties under test:
//! - `TryFrom<&proto::Attribute>` never panics on hostile input and refuses
//!   depth>=2 nested templates (D8) with a typed `CkRv`;
//! - accepted attributes round-trip back to an equal value;
//! - the `CkAttributeType` predicates are mutually consistent
//!   (template => array-flag; bool/ulong/ulong-array disjoint).

use libfuzzer_sys::fuzz_target;
use pkcs11_proxy_ng_proto::pkcs11_proxy_ng::v1 as proto;
use pkcs11_proxy_ng_types::{is_value_bearing_secret, CkAttribute, CkAttributeType};

/// Build a proto Attribute from raw bytes. `depth` counts nested levels
/// already above this attribute; construction caps total depth at 3 so the
/// harness itself stays small while still probing the D8 refusal.
fn build_attribute(data: &[u8], depth: u8) -> (proto::Attribute, &[u8]) {
    if data.len() < 10 {
        return (
            proto::Attribute { attr_type: 0, value: None },
            data,
        );
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
                let (sub, next) = build_attribute(tail, depth + 1);
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

fn nested_depth(attr: &proto::Attribute) -> usize {
    match &attr.value {
        Some(proto::attribute::Value::NestedTemplate(n)) => {
            1 + n.attributes.iter().map(nested_depth).max().unwrap_or(0)
        }
        _ => 0,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }
    let (attr, _) = build_attribute(data, 0);
    let depth = nested_depth(&attr);

    match CkAttribute::try_from(&attr) {
        Ok(back) => {
            // D8: accepted trees are at most one nested level.
            assert!(
                depth <= 1,
                "accepted a depth-{depth} nested template (D8 allows 1)"
            );
            // Round trip: Rust -> proto -> Rust preserves the value.
            let proto_again = proto::Attribute::from(&back);
            let back_again = CkAttribute::try_from(&proto_again)
                .expect("round-trip of an accepted attribute must succeed");
            assert_eq!(back, back_again, "attribute round-trip must be equal");
        }
        Err(_) => {
            // Typed refusal only; any panic above is a bug. Depth>=2 must
            // always refuse, but shallower trees may also refuse.
            if depth >= 2 {
                // Required refusal path; nothing more to check.
            }
        }
    }

    // Predicate consistency over the raw attr-type id.
    let t = CkAttributeType(attr.attr_type);
    if t.is_attribute_template() {
        assert!(t.is_array_attribute(), "template implies array flag");
    }
    let scalar_kinds = [t.is_bool(), t.is_ulong(), t.is_ulong_array()];
    assert!(
        scalar_kinds.iter().filter(|b| **b).count() <= 1,
        "bool/ulong/ulong-array must be disjoint"
    );
    let _ = is_value_bearing_secret(t);
});
