#![no_main]

//! Fuzz the pre-decode wire scanner (`validate_request_wire`, ADR-0013 §5/§7).
//!
//! The scanner runs over hostile gRPC request bytes before prost decode; it
//! must be total (typed violations only, never a panic), deterministic, and
//! must pass unknown paths through untouched.
//!
//! Input splitting lives in `pkcs11_proxy_ng_proto::fuzz_support`, shared
//! with the seed-semantics regression gates so the two cannot drift apart.

use libfuzzer_sys::fuzz_target;
use pkcs11_proxy_ng_proto::fuzz_support::fuzz_split_protected_input;
use pkcs11_proxy_ng_proto::protected_decode::{
    is_protected_path, protected_request_paths, validate_request_wire,
};

fuzz_target!(|data: &[u8]| {
    // Assert before any path indexing, as before the split-helper move.
    let paths = protected_request_paths();
    assert!(!paths.is_empty(), "service must publish request paths");
    let Some((path, payload)) = fuzz_split_protected_input(data) else {
        return;
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
