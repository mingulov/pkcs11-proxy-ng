#![no_main]

//! Fuzz the mechanism-registry TOML edge (`MechanismRegistry`).
//!
//! Registry content comes from operator files and daemon-published gRPC; the
//! loader must be total over arbitrary strings (typed `String` errors only,
//! never a panic), and every query entry must be total over arbitrary
//! mechanism ids once a registry is loaded.

use libfuzzer_sys::fuzz_target;
use pkcs11_proxy_ng_types::mechanism_registry::MechanismRegistry;
use std::path::Path;

fn mech_ids(data: &[u8]) -> Vec<u64> {
    data.chunks_exact(8)
        .take(16)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // Split: first half selects ids, whole input doubles as TOML content.
    let content = String::from_utf8_lossy(data);
    let ids = mech_ids(data);

    // Both load edges must be total.
    let base: &Path = Path::new("/nonexistent-fuzz-base");
    let loaded = MechanismRegistry::load_from_content(&content, base);
    let loaded_override = MechanismRegistry::load_with_override_str(Some(&content));

    for registry in [&loaded, &loaded_override].into_iter().flatten() {
        // Query surface must be total over arbitrary ids.
        for &id in &ids {
            let _ = registry.param_shape(id);
            let _ = registry.is_parameterless(id);
            let _ = registry.check_operation(id, true);
            let _ = registry.check_operation(id, false);
        }
        let _ = registry.filter_mechanisms(&ids);
        let _ = registry.registered_mechanisms();
        let _ = registry.param_shapes_view();
        let _ = registry.parameterless_view();
        let _ = registry.excluded_view();
        let _ = registry.discovery_mode();
        let _ = registry.revision();
    }
});
