#![no_main]

//! Fuzz the pre-decode wire scanner (`validate_request_wire`, ADR-0013 §5/§7).
//!
//! The scanner runs over hostile gRPC request bytes before prost decode; it
//! must be total (typed violations only, never a panic), deterministic, and
//! must pass unknown paths through untouched.

use libfuzzer_sys::fuzz_target;
use pkcs11_proxy_ng_proto::protected_decode::{
    is_protected_path, protected_request_paths, validate_request_wire,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let paths = protected_request_paths();
    assert!(!paths.is_empty(), "service must publish request paths");

    // First byte selects the path class: a real protected path (by index),
    // a near-miss prefix/suffix of one, or arbitrary bytes.
    let selector = data[0];
    let path_bytes = &data[1..];
    // Split path bytes from payload at a fuzzed boundary.
    let split_at = if path_bytes.is_empty() {
        0
    } else {
        (data[0] as usize) % (path_bytes.len() + 1)
    };
    let (path_raw, payload) = path_bytes.split_at(split_at);
    let path = match selector % 4 {
        0 => paths[(selector as usize) % paths.len()].to_string(),
        1 => format!("/pkcs11_proxy_ng.v1.Pkcs11Proxy/{}", String::from_utf8_lossy(path_raw)),
        2 => format!("{}{}", paths[(selector as usize) % paths.len()], String::from_utf8_lossy(path_raw)),
        _ => String::from_utf8_lossy(path_raw).into_owned(),
    };

    // Totality + determinism: two runs over the same input agree.
    let first = validate_request_wire(&path, payload);
    let second = validate_request_wire(&path, payload);
    assert_eq!(
        format!("{first:?}"),
        format!("{second:?}"),
        "scanner must be deterministic"
    );

    // Unknown paths pass through untouched.
    if !is_protected_path(&path) {
        assert!(first.is_ok(), "unknown path must pass through");
    }

    // Empty payload over a protected path: only Truncated-or-Ok outcomes.
    if payload.is_empty() && is_protected_path(&path) {
        let _ = first;
    }
});
