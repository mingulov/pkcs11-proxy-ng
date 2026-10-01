#![no_main]

//! Fuzz the attribute proto<->Rust edge plus the attribute-type predicates.
//!
//! Properties under test:
//! - `TryFrom<&proto::Attribute>` never panics on hostile input and refuses
//!   depth>=2 nested templates (D8) with a typed `CkRv`;
//! - accepted attributes round-trip back to an equal value;
//! - the `CkAttributeType` predicates are mutually consistent
//!   (template => array-flag; bool/ulong/ulong-array disjoint).
//!
//! Input construction lives in `pkcs11_proxy_ng_proto::fuzz_support`, shared
//! with the seed-semantics regression gates so the two cannot drift apart.

use libfuzzer_sys::fuzz_target;
use pkcs11_proxy_ng_proto::fuzz_support::{fuzz_build_attribute, fuzz_nested_depth};
use pkcs11_proxy_ng_proto::pkcs11_proxy_ng::v1 as proto;
use pkcs11_proxy_ng_types::{is_value_bearing_secret, CkAttribute, CkAttributeType};

fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }
    let (attr, _) = fuzz_build_attribute(data, 0);
    let depth = fuzz_nested_depth(&attr);

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
