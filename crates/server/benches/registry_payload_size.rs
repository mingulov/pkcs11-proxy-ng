// W1-L12-03: test/bench report lines go to stdout by design; the
// workspace lint table denies this sink elsewhere.
#![allow(clippy::print_stdout)]
//! Registry payload size for the upper-bound vendor case.
//!
//! Synthesizes a MechanismRegistry with N vendor mechanism entries
//! distributed across common param shapes, converts it to the proto
//! payload the daemon serves over `GetBackendInterfacesResponse`,
//! and reports the encoded wire size.
//!
//! Target: < 16 KiB for 100 vendor entries.
//!
//! Run: `cargo bench --bench registry_payload_size`

use prost::Message as _;
use std::collections::{HashMap, HashSet};

use pkcs11_proxy_ng_types::mechanism_registry::{EMBEDDED_DEFAULT_REVISION, MechanismRegistry};

fn synth_registry(n_vendor: usize) -> MechanismRegistry {
    // Start from the embedded default.
    let mut reg = MechanismRegistry::load(None).expect("embedded default loads");

    // Distribute n_vendor across 10 representative shapes from the
    // embedded default. Vendor mechanism IDs occupy 0x80000000+.
    let shapes = [
        "gcm",
        "iv",
        "sp800_108_kdf",
        "hkdf_derive",
        "ecdh_derive",
        "oaep_encrypt",
        "pss_sign",
        "aes_ctr",
        "aes_ccm",
        "tls_key_derive",
    ];

    // We rebuild via from_parts since param_shapes_view is read-only.
    let mut param_shapes: HashMap<u64, String> = reg.param_shapes_view().clone();
    let parameterless: HashSet<u64> = reg.parameterless_view().clone();
    let disabled: HashSet<u64> = reg.excluded_view().clone();
    let discovery_mode = reg.discovery_mode();

    let vendor_base: u64 = 0x80001000;
    for i in 0..n_vendor {
        let mech_id = vendor_base + i as u64;
        let shape = shapes[i % shapes.len()].to_owned();
        param_shapes.insert(mech_id, shape);
    }

    reg = MechanismRegistry::from_parts(
        param_shapes,
        parameterless,
        disabled,
        discovery_mode,
        EMBEDDED_DEFAULT_REVISION.to_owned(),
    );
    reg
}

fn main() {
    println!("# n_vendor  total_mechs  encoded_bytes");
    let mut out_json = String::from("[");
    let mut first = true;
    for &n in &[0usize, 10, 50, 100, 500, 1000] {
        let reg = synth_registry(n);
        let payload: pkcs11_proxy_ng_proto::MechanismRegistryPayload = (&reg).into();
        let bytes = payload.encoded_len();
        let total_mechs = reg.parameterless_view().len() + reg.param_shapes_view().len();
        println!("{n:>4}        {total_mechs:>4}         {bytes}");
        if !first {
            out_json.push(',');
        }
        out_json.push_str(&format!(
            r#"{{"n_vendor":{n},"total_mechs":{total_mechs},"encoded_bytes":{bytes}}}"#
        ));
        first = false;
    }
    out_json.push(']');
    if let Ok(path) = std::env::var("REGISTRY_OUT") {
        std::fs::write(path, out_json).unwrap();
    }
    println!();
    println!("Target: < 16 KiB (16384 bytes) for 100 vendor mechanisms.");
}
