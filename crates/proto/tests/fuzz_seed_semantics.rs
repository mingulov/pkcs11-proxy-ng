//! Permanent seed-semantics gates for `fuzz_attribute` and
//! `fuzz_protected_decode` (PR 22 assurance follow-up S3).
//!
//! A no-crash replay does not show that a named seed reaches its intended
//! branch, so each seed is decoded with the actual harness routines
//! ([`fuzz_support`](pkcs11_proxy_ng_proto::fuzz_support)) and its decoded
//! shape is asserted: accepted depth-one templates must be accepted and
//! nonempty, depth-two trees must reach refusal, and protected-request seeds
//! must split into the intended `(path, payload)` pair and reach the scanner
//! (or the intended passthrough). Rename-or-re-byte rule: a seed whose
//! decoded value contradicts its name gets corrected bytes when the name
//! states the intent (the harness format is never bent to fit a name).

use pkcs11_proxy_ng_proto::attribute::Value as AttributeValue;
use pkcs11_proxy_ng_proto::fuzz_support::{
    fuzz_build_attribute, fuzz_nested_depth, fuzz_split_protected_input,
};
use pkcs11_proxy_ng_proto::pkcs11_proxy_ng::v1::AsyncCompleteRequest;
use pkcs11_proxy_ng_proto::protected_decode::{
    ProtectedDecodeViolation, is_protected_path, validate_request_wire,
};
use pkcs11_proxy_ng_types::{CkAttribute, CkAttributeType, CkAttributeValue, CkRv};
use prost::Message;

const SERVICE_PREFIX: &str = "/pkcs11_proxy_ng.v1.Pkcs11Proxy/";
const ASYNC_COMPLETE_PATH: &str = "/pkcs11_proxy_ng.v1.Pkcs11Proxy/AsyncComplete";
const LOGIN_PATH: &str = "/pkcs11_proxy_ng.v1.Pkcs11Proxy/Login";

fn build_seed(seed: &[u8]) -> pkcs11_proxy_ng_proto::pkcs11_proxy_ng::v1::Attribute {
    assert!(seed.len() >= 10, "attribute seeds must clear the harness length guard");
    fuzz_build_attribute(seed, 0).0
}

// ── fuzz_attribute seeds ──────────────────────────────────────────────

#[test]
fn nested_depth1_seed_accepts_nonempty_depth_one_template() {
    let seed = include_bytes!("../../../fuzz/seeds/fuzz_attribute/nested-depth1");
    let attr = build_seed(seed);
    assert_eq!(attr.attr_type, CkAttributeType::WRAP_TEMPLATE.0);
    assert_eq!(fuzz_nested_depth(&attr), 1, "seed must build exactly one nested level");
    let back = CkAttribute::try_from(&attr).expect("depth-one template must be accepted");
    let subs = match &back.value {
        Some(CkAttributeValue::NestedTemplate(subs)) => subs,
        other => panic!("expected a nested template value, got {other:?}"),
    };
    assert!(!subs.is_empty(), "accepted template must be nonempty");
    assert_eq!(subs.len(), 1);
    // The sub-attribute carries the harness length byte as its first payload
    // byte (harness format, not seed intent): VALUE + 0x08-prefixed "seed123".
    assert_eq!(subs[0].attr_type, CkAttributeType::VALUE);
    assert_eq!(
        subs[0].value,
        Some(CkAttributeValue::Bytes(vec![0x08, b's', b'e', b'e', b'd', b'1', b'2', b'3'].into()))
    );
    // Round trip: Rust -> proto -> Rust preserves the accepted value.
    let proto_again = pkcs11_proxy_ng_proto::pkcs11_proxy_ng::v1::Attribute::from(&back);
    let back_again = CkAttribute::try_from(&proto_again).expect("round-trip must succeed");
    assert_eq!(back, back_again);
}

#[test]
fn nested_depth2_seed_reaches_d8_refusal() {
    let seed = include_bytes!("../../../fuzz/seeds/fuzz_attribute/nested-depth2-refuse");
    let attr = build_seed(seed);
    let depth = fuzz_nested_depth(&attr);
    assert!(depth >= 2, "refusal seed must build depth>=2, got {depth}");
    assert_eq!(
        CkAttribute::try_from(&attr).unwrap_err(),
        CkRv::ATTRIBUTE_VALUE_INVALID,
        "depth-{depth} template must reach the D8 typed refusal"
    );
}

#[test]
fn string_label_seed_decodes_clean_label() {
    let seed = include_bytes!("../../../fuzz/seeds/fuzz_attribute/string-label");
    let attr = build_seed(seed);
    assert_eq!(attr.attr_type, CkAttributeType::LABEL.0);
    match &attr.value {
        Some(AttributeValue::StringValue(text)) => {
            assert_eq!(text, "test-label", "label must not carry the harness length byte");
        }
        other => panic!("expected a string value, got {other:?}"),
    }
    let back = CkAttribute::try_from(&attr).expect("label string must be accepted");
    assert_eq!(
        back.value,
        Some(CkAttributeValue::String("test-label".to_string().into())),
        "decoded label bytes must round-trip exactly"
    );
}

#[test]
fn ulong_token_seed_decodes_clean_ulong() {
    let seed = include_bytes!("../../../fuzz/seeds/fuzz_attribute/ulong-token");
    let attr = build_seed(seed);
    assert_eq!(attr.attr_type, CkAttributeType::TOKEN.0);
    assert_eq!(
        attr.value,
        Some(AttributeValue::UlongValue(1)),
        "ulong payload must not include the harness length byte"
    );
    let back = CkAttribute::try_from(&attr).expect("ulong value must be accepted");
    assert_eq!(back.value, Some(CkAttributeValue::Ulong(1)));
}

// ── fuzz_protected_decode seeds ───────────────────────────────────────

fn split_seed(seed: &[u8]) -> (String, Vec<u8>) {
    let (path, payload) = fuzz_split_protected_input(seed)
        .expect("protected-decode seeds must clear the harness length guard");
    (path, payload.to_vec())
}

#[test]
fn real_path_empty_reaches_scanner_with_empty_payload() {
    let seed = include_bytes!("../../../fuzz/seeds/fuzz_protected_decode/real-path-empty");
    let (path, payload) = split_seed(seed);
    assert!(is_protected_path(&path), "seed must select a real protected path, got {path:?}");
    assert!(payload.is_empty(), "seed must split to an empty payload");
    validate_request_wire(&path, &payload).expect("empty payload must scan clean");
    // Prove the seed reaches the scanner rather than the unknown-path
    // passthrough: the same path rejects a duplicate-field encoding.
    let dup_field_one = [0x0au8, 0x01, b'a', 0x0a, 0x01, b'b'];
    assert!(
        matches!(
            validate_request_wire(&path, &dup_field_one),
            Err(ProtectedDecodeViolation::DuplicateField { .. })
                | Err(ProtectedDecodeViolation::OneofRepeated { .. })
        ),
        "path {path:?} must be scanner-enforced, not passthrough"
    );
}

#[test]
fn real_path_valid_pb_decodes_to_async_complete_request() {
    let seed = include_bytes!("../../../fuzz/seeds/fuzz_protected_decode/real-path-valid-pb");
    let (path, payload) = split_seed(seed);
    assert_eq!(path, ASYNC_COMPLETE_PATH, "selector 0 must select the first sorted path");
    // The payload must be a genuinely valid request for that method: every
    // field present with the wire type its descriptor declares.
    let request = AsyncCompleteRequest::decode(payload.as_slice())
        .expect("payload must prost-decode as AsyncCompleteRequest");
    assert_eq!(request.client_context_id, "hello");
    assert_eq!(request.session_handle, 1);
    assert_eq!(request.function_name, "bye");
    validate_request_wire(&path, &payload).expect("valid request must scan clean");
}

#[test]
fn nearmiss_dup_field_splits_loginx_with_dup_payload() {
    let seed = include_bytes!("../../../fuzz/seeds/fuzz_protected_decode/nearmiss-dup-field");
    let (path, payload) = split_seed(seed);
    assert_eq!(path, format!("{SERVICE_PREFIX}LoginX"), "seed must split at the LoginX boundary");
    assert!(!is_protected_path(&path), "near-miss path must not be a protected method");
    assert_eq!(
        payload,
        [0x0au8, 0x01, b'a', 0x0a, 0x01, b'b'],
        "payload must be the dup-field encoding"
    );
    validate_request_wire(&path, &payload).expect("near-miss path must pass through");
    // The dup-field half of the name is real: the same bytes are rejected on
    // a protected path whose field 1 is singular (LoginRequest.client_context_id).
    assert!(matches!(
        validate_request_wire(LOGIN_PATH, &payload),
        Err(ProtectedDecodeViolation::DuplicateField { number: 1, .. })
    ));
}

#[test]
fn garbage_path_passes_through_untouched() {
    let seed = include_bytes!("../../../fuzz/seeds/fuzz_protected_decode/garbage-path");
    let (path, payload) = split_seed(seed);
    assert!(!is_protected_path(&path), "garbage path must not be a protected method");
    assert!(!payload.is_empty(), "garbage seed must carry a payload");
    validate_request_wire(&path, &payload).expect("unknown path must pass through");
}

// ── fuzz dictionary spelling ──────────────────────────────────────────

#[test]
fn rpc_paths_dict_names_real_methods() {
    let dict = include_str!("../../../fuzz/dict/rpc_paths.dict");
    let paths = pkcs11_proxy_ng_proto::protected_decode::protected_request_paths();
    for line in dict.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let token = line
            .strip_prefix('"')
            .and_then(|t| t.strip_suffix('"'))
            .expect("dict entries are quoted");
        if token == SERVICE_PREFIX || token == "Request" || token == "Response" {
            continue;
        }
        assert!(
            paths.iter().any(|p| p.strip_prefix(SERVICE_PREFIX) == Some(token)),
            "dict method {token:?} must name a real method from service.proto"
        );
    }
}
