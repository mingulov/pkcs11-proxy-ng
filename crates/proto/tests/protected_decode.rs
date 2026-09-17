//! Behavioral tests for descriptor-aware pre-decode validation (ADR-0013
//! §5/§7, C3M Task 7.2). Payloads are prost-encoded real messages with
//! hand-spliced duplicate/truncated/malicious wire bytes.

use pkcs11_proxy_ng_proto::attribute::Value as AttributeValue;
use pkcs11_proxy_ng_proto::pkcs11_proxy_ng::v1::{Attribute, FindObjectsInitRequest, LoginRequest};
use pkcs11_proxy_ng_proto::protected_decode::{
    ProtectedDecodeViolation, protected_request_paths, validate_request_wire,
};
use prost::Message;

const LOGIN_PATH: &str = "/pkcs11_proxy_ng.v1.Pkcs11Proxy/Login";
const FIND_PATH: &str = "/pkcs11_proxy_ng.v1.Pkcs11Proxy/FindObjectsInit";

fn tag(number: u32, wire_type: u8) -> Vec<u8> {
    encode_varint(u64::from(number) << 3 | u64::from(wire_type))
}

fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return out;
        }
    }
}

fn len_delimited(number: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = tag(number, 2);
    out.extend(encode_varint(payload.len() as u64));
    out.extend(payload);
    out
}

fn login_bytes() -> Vec<u8> {
    LoginRequest {
        client_context_id: String::from("ctx"),
        session_handle: 7,
        user_type: 1,
        pin: Some(vec![9, 9, 9]),
    }
    .encode_to_vec()
}

#[test]
fn valid_requests_validate() {
    assert_eq!(validate_request_wire(LOGIN_PATH, &login_bytes()), Ok(()));
    let find = FindObjectsInitRequest {
        client_context_id: String::from("ctx"),
        session_handle: 7,
        template: vec![
            Attribute { attr_type: 0x100, value: Some(AttributeValue::UlongValue(3)) },
            Attribute { attr_type: 0x101, value: Some(AttributeValue::BytesValue(vec![1, 2, 3])) },
        ],
    };
    assert_eq!(validate_request_wire(FIND_PATH, &find.encode_to_vec()), Ok(()));
    assert_eq!(validate_request_wire(LOGIN_PATH, &[]), Ok(()));
}

#[test]
fn duplicate_singular_secret_field_rejected() {
    // A second `pin` (field 4) would make prost replace — and unwiped-free —
    // the first decoded PIN allocation.
    let mut payload = login_bytes();
    payload.extend(len_delimited(4, &[8, 8]));
    assert_eq!(
        validate_request_wire(LOGIN_PATH, &payload),
        Err(ProtectedDecodeViolation::DuplicateField { message: "LoginRequest", number: 4 })
    );
}

#[test]
fn duplicate_scalar_rejected() {
    let mut payload = login_bytes();
    // session_handle (field 2, varint) with value 8.
    payload.extend(tag(2, 0));
    payload.push(8);
    assert_eq!(
        validate_request_wire(LOGIN_PATH, &payload),
        Err(ProtectedDecodeViolation::DuplicateField { message: "LoginRequest", number: 2 })
    );
}

#[test]
fn nested_duplicate_rejected() {
    // A template element whose `attr_type` (Attribute field 1, a plain
    // singular scalar) occurs twice inside the nested element.
    let mut element =
        Attribute { attr_type: 0x101, value: Some(AttributeValue::BytesValue(vec![1])) }
            .encode_to_vec();
    element.extend(tag(1, 0));
    element.extend(encode_varint(0x102));
    let mut payload = FindObjectsInitRequest {
        client_context_id: String::from("ctx"),
        session_handle: 7,
        template: Vec::new(),
    }
    .encode_to_vec();
    payload.extend(len_delimited(3, &element));
    assert_eq!(
        validate_request_wire(FIND_PATH, &payload),
        Err(ProtectedDecodeViolation::DuplicateField { message: "Attribute", number: 1 })
    );
}

#[test]
fn oneof_second_member_rejected() {
    // bytes_value (field 4) followed by ulong_value (field 3): prost keeps
    // the last oneof member, dropping the decoded bytes without wiping.
    let mut payload = len_delimited(4, &[1, 2]);
    payload.extend(tag(3, 0));
    payload.push(9);
    let mut request = FindObjectsInitRequest {
        client_context_id: String::new(),
        session_handle: 0,
        template: Vec::new(),
    }
    .encode_to_vec();
    request.extend(len_delimited(3, &payload));
    assert_eq!(
        validate_request_wire(FIND_PATH, &request),
        Err(ProtectedDecodeViolation::OneofRepeated { message: "Attribute" })
    );
}

#[test]
fn oneof_same_member_twice_rejected() {
    let mut payload = len_delimited(4, &[1]);
    payload.extend(len_delimited(4, &[2]));
    let mut request = Vec::new();
    request.extend(len_delimited(3, &payload));
    assert_eq!(
        validate_request_wire(FIND_PATH, &request),
        Err(ProtectedDecodeViolation::OneofRepeated { message: "Attribute" })
    );
}

#[test]
fn repeated_fields_may_recur() {
    let find = FindObjectsInitRequest {
        client_context_id: String::new(),
        session_handle: 0,
        template: vec![
            Attribute { attr_type: 1, value: None },
            Attribute { attr_type: 2, value: None },
            Attribute { attr_type: 3, value: None },
        ],
    };
    assert_eq!(validate_request_wire(FIND_PATH, &find.encode_to_vec()), Ok(()));
}

#[test]
fn unknown_fields_skipped() {
    // Field 999 in every wire shape: prost discards unknown fields without
    // retaining an allocation, so they cannot smuggle a replacement.
    let mut payload = login_bytes();
    payload.extend(tag(999, 0));
    payload.extend(encode_varint(12345));
    payload.extend(tag(999, 1));
    payload.extend([0u8; 8]);
    payload.extend(tag(999, 5));
    payload.extend([0u8; 4]);
    payload.extend(len_delimited(999, &[7, 7, 7]));
    assert_eq!(validate_request_wire(LOGIN_PATH, &payload), Ok(()));
}

#[test]
fn groups_rejected() {
    // Field 3, wire type 3 (start group): proto3 never emits groups.
    assert_eq!(
        validate_request_wire(LOGIN_PATH, &[0x1b]),
        Err(ProtectedDecodeViolation::GroupsRejected { message: "LoginRequest" })
    );
    // Field 3, wire type 4 (end group) is likewise rejected.
    assert_eq!(
        validate_request_wire(LOGIN_PATH, &[0x1c]),
        Err(ProtectedDecodeViolation::GroupsRejected { message: "LoginRequest" })
    );
}

#[test]
fn truncated_rejected() {
    // Unterminated varint.
    assert_eq!(
        validate_request_wire(LOGIN_PATH, &[0xff]),
        Err(ProtectedDecodeViolation::Truncated { message: "LoginRequest" })
    );
    // Length prefix overrunning the buffer.
    assert_eq!(
        validate_request_wire(LOGIN_PATH, &[0x22, 0x10, 0x01]),
        Err(ProtectedDecodeViolation::Truncated { message: "LoginRequest" })
    );
    // Valid message cut mid-payload.
    let mut payload = login_bytes();
    payload.pop();
    assert_eq!(
        validate_request_wire(LOGIN_PATH, &payload),
        Err(ProtectedDecodeViolation::Truncated { message: "LoginRequest" })
    );
    // Non-canonical 10-byte varint with dropped payload bits.
    let mut evil = tag(2, 0);
    evil.pop();
    evil.extend([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);
    assert_eq!(
        validate_request_wire(LOGIN_PATH, &evil),
        Err(ProtectedDecodeViolation::Truncated { message: "LoginRequest" })
    );
    // Over-long varint (continuation past the 10th byte).
    assert_eq!(
        validate_request_wire(LOGIN_PATH, &[0xff; 12]),
        Err(ProtectedDecodeViolation::Truncated { message: "LoginRequest" })
    );
}

#[test]
fn unknown_paths_pass_through() {
    // Health checks and future services have no descriptor entry; garbage
    // bytes under an unknown path are not ours to judge.
    assert_eq!(validate_request_wire("/grpc.health.v1.Health/Check", &[0xff, 0x00, 0x1b]), Ok(()));
    assert_eq!(validate_request_wire("/other.Service/Method", &[0x1b]), Ok(()));
}

#[test]
fn depth_bomb_rejected() {
    // Attribute -> nested_template (field 6) -> NestedAttributes ->
    // attributes (field 1) -> Attribute ... nested past the depth cap.
    let mut element = vec![0x08, 0x01];
    for _ in 0..70 {
        let nested = len_delimited(1, &element);
        let mut outer = vec![0x08, 0x01];
        outer.extend(len_delimited(6, &nested));
        element = outer;
    }
    let payload = len_delimited(3, &element);
    assert_eq!(
        validate_request_wire(FIND_PATH, &payload),
        Err(ProtectedDecodeViolation::DepthExceeded)
    );
}

#[test]
fn shallow_nesting_accepted() {
    // One template level (the ADR-0011 D8 bound) validates cleanly.
    let inner =
        Attribute { attr_type: 0x101, value: Some(AttributeValue::UlongValue(5)) }.encode_to_vec();
    let nested = len_delimited(1, &inner);
    let mut element = vec![0x08, 0x01];
    element.extend(len_delimited(6, &nested));
    let payload = len_delimited(3, &element);
    assert_eq!(validate_request_wire(FIND_PATH, &payload), Ok(()));
}

#[test]
fn violation_messages_carry_no_payload_bytes() {
    let violation = ProtectedDecodeViolation::DuplicateField { message: "LoginRequest", number: 4 };
    let rendered = format!("{violation}");
    assert!(rendered.contains("LoginRequest"));
    assert!(!rendered.contains("9"));
}

#[test]
fn coverage_matches_service_proto() {
    let mut methods = std::collections::BTreeSet::new();
    for line in include_str!("../../../proto/pkcs11-proxy-ng/v1/service.proto").lines() {
        let line = line.split("//").next().unwrap_or_default();
        if let Some(rest) = line.trim().strip_prefix("rpc ") {
            let method: String =
                rest.chars().take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_').collect();
            assert!(!method.is_empty());
            assert!(methods.insert(method), "duplicate rpc method");
        }
    }
    assert!(!methods.is_empty());
    let covered: std::collections::BTreeSet<String> = protected_request_paths()
        .iter()
        .map(|path| {
            path.strip_prefix("/pkcs11_proxy_ng.v1.Pkcs11Proxy/")
                .expect("service path prefix")
                .to_owned()
        })
        .collect();
    assert_eq!(methods, covered, "every rpc method must be validation-covered");
}
