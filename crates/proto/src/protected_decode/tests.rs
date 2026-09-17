//! White-box descriptor-table tests. Behavioral wire tests live in
//! `crates/proto/tests/protected_decode.rs`.

use super::{MESSAGE_DESCRIPTORS, NO_NESTED, NO_ONEOF, REQUEST_MESSAGES};

#[test]
fn request_table_covers_every_rpc_method() {
    assert_eq!(REQUEST_MESSAGES.len(), 106);
    let mut paths: Vec<&str> = REQUEST_MESSAGES.iter().map(|(path, _)| *path).collect();
    let sorted = {
        let mut sorted = paths.clone();
        sorted.sort();
        sorted
    };
    assert_eq!(paths, sorted, "REQUEST_MESSAGES must be sorted for binary search");
    paths.dedup();
    assert_eq!(paths.len(), 106, "duplicate request paths");
    assert!(
        REQUEST_MESSAGES
            .iter()
            .all(|(path, _)| path.starts_with("/pkcs11_proxy_ng.v1.Pkcs11Proxy/")),
        "unexpected service path prefix"
    );
    assert!(
        REQUEST_MESSAGES.contains(&("/pkcs11_proxy_ng.v1.Pkcs11Proxy/Login", 0))
            || REQUEST_MESSAGES.iter().any(|(path, _)| path.ends_with("/Login")),
        "Login must be covered"
    );
}

#[test]
fn message_descriptors_match_schema_spot_checks() {
    let login = MESSAGE_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.name == "LoginRequest")
        .expect("LoginRequest descriptor");
    assert_eq!(login.fields.len(), 4);
    assert!(login.fields.iter().all(|field| !field.repeated));
    assert!(login.fields.iter().all(|field| field.nested == NO_NESTED));
    assert!(login.fields.iter().all(|field| field.oneof == NO_ONEOF));

    let attribute = MESSAGE_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.name == "Attribute")
        .expect("Attribute descriptor");
    assert_eq!(attribute.fields.len(), 6);
    // attr_type is a plain singular scalar; the rest share one oneof.
    assert_eq!(attribute.fields[0].number, 1);
    assert_eq!(attribute.fields[0].oneof, NO_ONEOF);
    for field in &attribute.fields[1..] {
        assert_eq!(field.oneof, 0, "field {} must be in oneof 0", field.number);
        assert!(!field.repeated);
    }
    // nested_template links to the NestedAttributes descriptor.
    let nested = MESSAGE_DESCRIPTORS
        .iter()
        .position(|descriptor| descriptor.name == "NestedAttributes")
        .expect("NestedAttributes descriptor") as u32;
    assert_eq!(attribute.fields[5].nested, nested);

    let find = MESSAGE_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.name == "FindObjectsInitRequest")
        .expect("FindObjectsInitRequest descriptor");
    let template = find.fields.iter().find(|field| field.number == 3).expect("template");
    assert!(template.repeated);
    assert_ne!(template.nested, NO_NESTED);
}

#[test]
fn nested_links_resolve_inside_the_table() {
    for descriptor in MESSAGE_DESCRIPTORS {
        for field in descriptor.fields {
            if field.nested != NO_NESTED {
                assert!(
                    (field.nested as usize) < MESSAGE_DESCRIPTORS.len(),
                    "dangling nested link in {}",
                    descriptor.name
                );
            }
        }
    }
    for (_, index) in REQUEST_MESSAGES {
        assert!((*index as usize) < MESSAGE_DESCRIPTORS.len(), "dangling request link");
    }
}
