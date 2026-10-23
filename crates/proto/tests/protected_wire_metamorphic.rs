//! Hand-encoded transformations exercise the real descriptor-aware scanner.
//! No prost encoder or scanner descriptor builds the expected wire bytes.

use pkcs11_proxy_ng_proto::protected_decode::{
    ProtectedDecodeViolation as V, validate_request_wire,
};

const LOGIN: &str = "/pkcs11_proxy_ng.v1.Pkcs11Proxy/Login";
const CREATE: &str = "/pkcs11_proxy_ng.v1.Pkcs11Proxy/CreateObject";

// Attribute nested in CreateObject.template (field 3). Fixtures are bounded
// to one-byte lengths; this envelope is independent of product encoding.
fn template(attribute: &[u8]) -> Vec<u8> {
    assert!(attribute.len() < 128);
    let mut wire = vec![0x1a, attribute.len() as u8];
    wire.extend_from_slice(attribute);
    wire
}

#[test]
fn duplicate_singular_transformations_are_refused_in_either_order() {
    // Removing duplicate checking (or accepting everything) must fail here.
    for value in 0..16_u8 {
        let fields =
            [vec![0x0a, 1, b'c'], vec![0x10, value], vec![0x18, value], vec![0x22, 1, value]];
        for (index, field) in fields.iter().enumerate() {
            let valid: Vec<_> = fields.iter().flatten().copied().collect();
            assert_eq!(validate_request_wire(LOGIN, &valid), Ok(()));
            for duplicate in [
                [valid.as_slice(), field.as_slice()].concat(),
                [field.as_slice(), valid.as_slice()].concat(),
            ] {
                assert_eq!(
                    validate_request_wire(LOGIN, &duplicate),
                    Err(V::DuplicateField { message: "LoginRequest", number: index as u32 + 1 }),
                    "value={value} field={index} bytes={duplicate:?}"
                );
            }
        }
    }
}

#[test]
fn repeated_templates_keep_independent_oneof_scopes_but_replacements_fail() {
    for value in 0..16_u8 {
        // Attribute.attr_type=1, bytes_value=[value].
        let attribute = [0x08, 1, 0x22, 1, value];
        let valid = template(&attribute);
        assert_eq!(validate_request_wire(CREATE, &valid), Ok(()));
        for count in 2..=8 {
            assert_eq!(
                validate_request_wire(CREATE, &valid.repeat(count)),
                Ok(()),
                "repeated count={count} value={value}"
            );
        }
        // Same member twice, or a different member in the same oneof.
        for replacement in [&[0x22, 0][..], &[0x2a, 1, b'x'][..], &[0x10, 1][..]] {
            let replaced = template(&[attribute.as_slice(), replacement].concat());
            assert_eq!(
                validate_request_wire(CREATE, &replaced),
                Err(V::OneofRepeated { message: "Attribute" }),
                "value={value} replacement={replacement:?}"
            );
        }
        let duplicate_type = template(&[attribute.as_slice(), &[0x08, 2]].concat());
        assert_eq!(
            validate_request_wire(CREATE, &duplicate_type),
            Err(V::DuplicateField { message: "Attribute", number: 1 })
        );
        // A bad nested message cannot hide behind an earlier legal repeated item.
        let after_valid = [valid.as_slice(), duplicate_type.as_slice()].concat();
        assert_eq!(
            validate_request_wire(CREATE, &after_valid),
            Err(V::DuplicateField { message: "Attribute", number: 1 })
        );
    }
}

#[test]
fn unknown_fields_are_opaque_and_unknown_paths_pass_through() {
    // Unknown field 31, wire type 2, contains duplicate known-looking tags.
    let opaque = [0xfa, 0x01, 4, 0x10, 1, 0x10, 2];
    let valid = [0x10, 1];
    assert_eq!(
        validate_request_wire(LOGIN, &[valid.as_slice(), &opaque, &opaque].concat()),
        Ok(())
    );
    // Unknown fixed64, fixed32 and varint fields are also legal and repeatable.
    let unknown = [0xf9, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd, 0x01, 0, 0, 0, 0, 0xf8, 0x01, 1];
    assert_eq!(validate_request_wire(LOGIN, &unknown.repeat(2)), Ok(()));
    for path in ["/pkcs11_proxy_ng.v1.Pkcs11Proxy/LoginX", "/grpc.health.v1.Health/Check", ""] {
        for payload in [&[0x10, 1, 0x10, 2][..], &[0x22, 0x80][..]] {
            assert_eq!(validate_request_wire(path, payload), Ok(()), "path={path:?}");
        }
    }
}

#[test]
fn bounded_malformed_lengths_fail_at_the_enclosing_message() {
    // These tiny buffers describe truncated, overflowing and huge lengths;
    // the scanner must reject from the slice, without allocating that length.
    for malformed in [
        vec![0x22],
        vec![0x22, 0x80],
        vec![0x22, 1],
        vec![0x22, 2, 7],
        vec![0x22, 0x7f],
        vec![0x22, 0x80, 1],
        vec![0x22, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1],
        vec![0x22, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2],
        vec![0x22, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80],
    ] {
        assert_eq!(
            validate_request_wire(LOGIN, &malformed),
            Err(V::Truncated { message: "LoginRequest" }),
            "bytes={malformed:?}"
        );
        // The same invalid length inside a known nested Attribute is checked
        // there, even though the outer template envelope has a valid length.
        assert_eq!(
            validate_request_wire(CREATE, &template(&malformed)),
            Err(V::Truncated { message: "Attribute" }),
            "nested bytes={malformed:?}"
        );
    }
    // Opaque unknown fields still need a complete outer length-delimited body.
    assert_eq!(
        validate_request_wire(LOGIN, &[0xfa, 1, 2, 0]),
        Err(V::Truncated { message: "LoginRequest" })
    );
}
