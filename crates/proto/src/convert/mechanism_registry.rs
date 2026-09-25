//! Bidirectional conversion between
//! [`pkcs11_proxy_ng_types::MechanismRegistry`] and the wire-format
//! [`crate::MechanismRegistryPayload`].
//!
//! The conversion is intentionally lossless for the registry's data
//! (parameterless set, param-shape map, discovery mode, revision). The
//! payload is what the daemon publishes to shims over the
//! `GetBackendInterfaces` RPC.

use std::collections::{HashMap, HashSet};

use pkcs11_proxy_ng_types::{DiscoveryMode, EMBEDDED_DEFAULT_REVISION, MechanismRegistry};

use crate::{MechanismParamEntry, MechanismRegistryPayload};

/// Render an in-memory registry into its wire-format payload.
///
/// Server-side: the daemon loads `mechanism_params.toml` into a
/// `MechanismRegistry`, attaches a content-derived revision, and calls
/// this to produce the payload it serves over gRPC.
impl From<&MechanismRegistry> for MechanismRegistryPayload {
    fn from(registry: &MechanismRegistry) -> Self {
        // Group mechanisms by shape so the wire format mirrors the TOML
        // structure rather than emitting one entry per mechanism.
        let mut by_shape: HashMap<&str, Vec<u64>> = HashMap::new();
        for (mech, shape) in registry.param_shapes_view() {
            by_shape.entry(shape.as_str()).or_default().push(*mech);
        }

        // Sort mechanisms within each shape and shapes by name so the
        // serialised payload is deterministic across reloads with the
        // same content.
        let mut params: Vec<MechanismParamEntry> = by_shape
            .into_iter()
            .map(|(shape, mut mechanisms)| {
                mechanisms.sort_unstable();
                MechanismParamEntry { shape: shape.to_string(), mechanisms }
            })
            .collect();
        params.sort_by(|a, b| a.shape.cmp(&b.shape));

        let mut parameterless: Vec<u64> = registry.parameterless_view().iter().copied().collect();
        parameterless.sort_unstable();

        MechanismRegistryPayload {
            revision: registry.revision().to_string(),
            discovery_mode: discovery_mode_to_str(registry.discovery_mode()).to_string(),
            parameterless,
            params,
        }
    }
}

/// Reconstruct a registry from a wire-format payload.
///
/// Shim-side: `interface_probe` receives the payload during the
/// `GetBackendInterfaces` response and uses this to build the
/// `MechanismRegistry` that will replace the shim's previous registry.
///
/// Unknown `discovery_mode` strings fall back to [`DiscoveryMode::Transparent`]
/// — the conservative choice that preserves the spec-conformant default.
impl From<&MechanismRegistryPayload> for MechanismRegistry {
    fn from(payload: &MechanismRegistryPayload) -> Self {
        let mut param_shapes: HashMap<u64, String> = HashMap::new();
        for entry in &payload.params {
            for &mech in &entry.mechanisms {
                param_shapes.insert(mech, entry.shape.clone());
            }
        }
        let parameterless: HashSet<u64> = payload.parameterless.iter().copied().collect();
        let discovery_mode = parse_discovery_mode(&payload.discovery_mode);
        let revision = if payload.revision.is_empty() {
            EMBEDDED_DEFAULT_REVISION.to_string()
        } else {
            payload.revision.clone()
        };
        MechanismRegistry::from_parts(param_shapes, parameterless, discovery_mode, revision)
    }
}

fn discovery_mode_to_str(mode: DiscoveryMode) -> &'static str {
    match mode {
        DiscoveryMode::Transparent => "transparent",
        DiscoveryMode::Filtered => "filtered",
    }
}

fn parse_discovery_mode(s: &str) -> DiscoveryMode {
    match s {
        "filtered" => DiscoveryMode::Filtered,
        // "transparent", "", or any unknown value: default to Transparent.
        _ => DiscoveryMode::Transparent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs11_proxy_ng_types::MechanismRegistry;

    #[test]
    fn embedded_default_round_trips() {
        let original = MechanismRegistry::load_with_override_str(None).unwrap();
        let payload: MechanismRegistryPayload = (&original).into();

        // Embedded default uses the sentinel revision.
        assert_eq!(payload.revision, EMBEDDED_DEFAULT_REVISION);
        // Discovery mode is transparent by default.
        assert_eq!(payload.discovery_mode, "transparent");

        let recovered: MechanismRegistry = (&payload).into();

        // Spot-check well-known mechanism IDs survive the round trip.
        assert_eq!(recovered.param_shape(0x1087), Some("gcm")); // CKM_AES_GCM
        assert!(recovered.is_parameterless(0x0001)); // CKM_RSA_PKCS
        assert_eq!(recovered.revision(), EMBEDDED_DEFAULT_REVISION);
        assert_eq!(recovered.discovery_mode(), DiscoveryMode::Transparent);
    }

    #[test]
    fn override_round_trips() {
        let override_toml = r#"
            discovery_mode = "filtered"
            parameterless = [0x80000001]
            [[params]]
            shape = "gcm"
            mechanisms = [0x80000002]
        "#;
        let mut original = MechanismRegistry::load_with_override_str(Some(override_toml)).unwrap();
        original.set_revision("test-revision-abc".to_string());

        let payload: MechanismRegistryPayload = (&original).into();
        assert_eq!(payload.revision, "test-revision-abc");
        assert_eq!(payload.discovery_mode, "filtered");

        let recovered: MechanismRegistry = (&payload).into();
        assert_eq!(recovered.discovery_mode(), DiscoveryMode::Filtered);
        assert!(recovered.is_parameterless(0x80000001));
        assert_eq!(recovered.param_shape(0x80000002), Some("gcm"));
        assert_eq!(recovered.revision(), "test-revision-abc");
    }

    #[test]
    fn empty_revision_falls_back_to_embedded_default() {
        let payload = MechanismRegistryPayload {
            revision: String::new(),
            discovery_mode: "transparent".to_string(),
            parameterless: vec![],
            params: vec![],
        };
        let registry: MechanismRegistry = (&payload).into();
        assert_eq!(registry.revision(), EMBEDDED_DEFAULT_REVISION);
    }

    #[test]
    fn unknown_discovery_mode_defaults_to_transparent() {
        let payload = MechanismRegistryPayload {
            revision: "x".to_string(),
            discovery_mode: "garbage".to_string(),
            parameterless: vec![],
            params: vec![],
        };
        let registry: MechanismRegistry = (&payload).into();
        assert_eq!(registry.discovery_mode(), DiscoveryMode::Transparent);
    }

    #[test]
    fn payload_groups_mechanisms_by_shape() {
        let override_toml = r#"
            [[params]]
            shape = "gcm"
            mechanisms = [0x80000010, 0x80000011]
            [[params]]
            shape = "iv"
            mechanisms = [0x80000020]
        "#;
        let original = MechanismRegistry::load_with_override_str(Some(override_toml)).unwrap();
        let payload: MechanismRegistryPayload = (&original).into();

        // Embedded default also contributes; pick out the shapes we added.
        let gcm_entry =
            payload.params.iter().find(|e| e.shape == "gcm").expect("gcm shape present");
        assert!(gcm_entry.mechanisms.contains(&0x80000010));
        assert!(gcm_entry.mechanisms.contains(&0x80000011));

        let iv_entry = payload.params.iter().find(|e| e.shape == "iv").expect("iv shape present");
        assert!(iv_entry.mechanisms.contains(&0x80000020));

        // Mechanisms inside each entry are sorted for deterministic
        // wire output.
        let mut sorted = gcm_entry.mechanisms.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, gcm_entry.mechanisms);
    }
}
