#![no_main]

//! Fuzz the hostile-wire -> `CkMechanism` edge (AGENTS.md §12).
//!
//! Raw bytes are decoded as protobuf `Mechanism` wire encoding — the exact
//! shape an untrusted peer sends — then converted via
//! `TryFrom<&proto::Mechanism>`. This covers all 79 parameter shapes
//! uniformly through the real decode path (including prost merge
//! behavior), rather than hand-building each shape.
//!
//! Properties under test:
//! - wire decode + conversion never panic (typed errors only);
//! - accepted mechanisms round-trip Rust -> proto -> Rust to an equal value.

use libfuzzer_sys::fuzz_target;
use pkcs11_proxy_ng_proto::pkcs11_proxy_ng::v1 as proto;
use pkcs11_proxy_ng_types::CkMechanism;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let wire = match proto::Mechanism::decode(data) {
        Ok(m) => m,
        // Malformed wire: prost's typed refusal, nothing to convert.
        Err(_) => return,
    };
    match CkMechanism::try_from(&wire) {
        Ok(back) => {
            let proto_again = proto::Mechanism::try_from(&back)
                .expect("round-trip of an accepted mechanism must succeed");
            let back_again = CkMechanism::try_from(&proto_again)
                .expect("re-conversion of an emitted mechanism must succeed");
            assert_eq!(back, back_again, "mechanism round-trip must be equal");
        }
        Err(_) => {
            // Typed refusal only; any panic above is a bug.
        }
    }
});
