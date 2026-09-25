//! Bidirectional conversion between
//! [`pkcs11_proxy_ng_types::MechanismRegistry`] and the wire-format
//! [`crate::MechanismRegistryPayload`].
//!
//! The conversion is intentionally lossless for the registry's data
//! (parameterless set, param-shape map, operator-excluded set, discovery
//! mode, revision). The payload is what the daemon publishes to shims over
//! the `GetBackendInterfaces` RPC.

use std::collections::{HashMap, HashSet};
use std::fmt;

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

        let mut excluded: Vec<u64> = registry.excluded_view().iter().copied().collect();
        excluded.sort_unstable();

        MechanismRegistryPayload {
            revision: registry.revision().to_string(),
            discovery_mode: discovery_mode_to_str(registry.discovery_mode()).to_string(),
            parameterless,
            params,
            excluded,
        }
    }
}

/// One mechanism ID listed twice in a registry payload's shape entries.
///
/// A registry maps each mechanism to exactly one parameter shape; a payload
/// repeating an ID is malformed (no conforming daemon emits one — the encode
/// path groups a `HashMap` by shape, so each ID occurs exactly once).
/// Decoding fails with this error instead of silently last-winning, so a
/// corrupt payload cannot smuggle an arbitrary shape mapping into the shim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateMechanismId {
    /// The repeated mechanism ID (CKM value).
    pub mechanism: u64,
    /// Shape of the entry that first listed the ID.
    pub first_shape: String,
    /// Shape of the entry that repeated the ID.
    pub second_shape: String,
}

impl fmt::Display for DuplicateMechanismId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "mechanism {:#X} listed under two shape entries: '{}' and '{}'",
            self.mechanism, self.first_shape, self.second_shape
        )
    }
}

impl std::error::Error for DuplicateMechanismId {}

/// Reconstruct a registry from a wire-format payload.
///
/// Shim-side: `interface_probe` receives the payload during the
/// `GetBackendInterfaces` response and uses this to build the
/// `MechanismRegistry` that will replace the shim's previous registry.
///
/// Unknown `discovery_mode` strings fall back to [`DiscoveryMode::Transparent`]
/// — the conservative choice that preserves the spec-conformant default.
///
/// A mechanism ID repeated across (or within) shape entries fails with
/// [`DuplicateMechanismId`] naming the ID (W1-C8-10); the caller keeps its
/// previous registry instead of installing a last-wins corruption.
impl TryFrom<&MechanismRegistryPayload> for MechanismRegistry {
    type Error = DuplicateMechanismId;

    fn try_from(payload: &MechanismRegistryPayload) -> Result<Self, Self::Error> {
        let mut param_shapes: HashMap<u64, String> = HashMap::new();
        for entry in &payload.params {
            for &mech in &entry.mechanisms {
                if let Some(first) = param_shapes.get(&mech) {
                    return Err(DuplicateMechanismId {
                        mechanism: mech,
                        first_shape: first.clone(),
                        second_shape: entry.shape.clone(),
                    });
                }
                param_shapes.insert(mech, entry.shape.clone());
            }
        }
        let parameterless: HashSet<u64> = payload.parameterless.iter().copied().collect();
        // Absent from older daemons; an empty list means "nothing excluded".
        let disabled: HashSet<u64> = payload.excluded.iter().copied().collect();
        let discovery_mode = parse_discovery_mode(&payload.discovery_mode);
        let revision = if payload.revision.is_empty() {
            EMBEDDED_DEFAULT_REVISION.to_string()
        } else {
            payload.revision.clone()
        };
        Ok(MechanismRegistry::from_parts(
            param_shapes,
            parameterless,
            disabled,
            discovery_mode,
            revision,
        ))
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
    use pkcs11_proxy_ng_types::{CkRv, MechanismRegistry};

    #[test]
    fn embedded_default_round_trips() {
        let original = MechanismRegistry::load_with_override_str(None).unwrap();
        let payload: MechanismRegistryPayload = (&original).into();

        // Embedded default uses the sentinel revision.
        assert_eq!(payload.revision, EMBEDDED_DEFAULT_REVISION);
        // Discovery mode is transparent by default.
        assert_eq!(payload.discovery_mode, "transparent");

        let recovered = MechanismRegistry::try_from(&payload).expect("test payload must decode");

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

        let recovered = MechanismRegistry::try_from(&payload).expect("test payload must decode");
        assert_eq!(recovered.discovery_mode(), DiscoveryMode::Filtered);
        assert!(recovered.is_parameterless(0x80000001));
        assert_eq!(recovered.param_shape(0x80000002), Some("gcm"));
        assert_eq!(recovered.revision(), "test-revision-abc");
    }

    #[test]
    fn excluded_round_trips() {
        let override_toml = r#"
            exclude = [0x80000001, 0x0001]
        "#;
        let original = MechanismRegistry::load_with_override_str(Some(override_toml)).unwrap();
        let payload: MechanismRegistryPayload = (&original).into();

        assert!(payload.excluded.contains(&0x80000001));
        assert!(payload.excluded.contains(&0x0001));

        let recovered = MechanismRegistry::try_from(&payload).expect("test payload must decode");
        assert_eq!(recovered.check_operation(0x80000001, false), Err(CkRv::MECHANISM_INVALID));
        assert_eq!(recovered.check_operation(0x0001, false), Err(CkRv::MECHANISM_INVALID));
        // Non-excluded mechanisms survive the round trip unaffected.
        assert!(recovered.check_operation(0x1087, true).is_ok());
    }

    #[test]
    fn empty_revision_falls_back_to_embedded_default() {
        let payload = MechanismRegistryPayload {
            revision: String::new(),
            discovery_mode: "transparent".to_string(),
            parameterless: vec![],
            params: vec![],
            excluded: vec![],
        };
        let registry = MechanismRegistry::try_from(&payload).expect("test payload must decode");
        assert_eq!(registry.revision(), EMBEDDED_DEFAULT_REVISION);
    }

    #[test]
    fn unknown_discovery_mode_defaults_to_transparent() {
        let payload = MechanismRegistryPayload {
            revision: "x".to_string(),
            discovery_mode: "garbage".to_string(),
            parameterless: vec![],
            params: vec![],
            excluded: vec![],
        };
        let registry = MechanismRegistry::try_from(&payload).expect("test payload must decode");
        assert_eq!(registry.discovery_mode(), DiscoveryMode::Transparent);
    }

    /// W1-C8-10 pin: one mechanism ID under two shape entries fails
    /// decode loudly instead of silently last-winning. The error names
    /// the offending ID plus both shapes for diagnosis.
    #[test]
    fn duplicate_mechanism_id_across_shapes_fails_decode_naming_the_id() {
        let payload = MechanismRegistryPayload {
            revision: "rev".to_string(),
            discovery_mode: "transparent".to_string(),
            parameterless: vec![],
            params: vec![
                MechanismParamEntry { shape: "gcm".to_string(), mechanisms: vec![0x1087] },
                MechanismParamEntry { shape: "iv".to_string(), mechanisms: vec![0x1087] },
            ],
            excluded: vec![],
        };
        let error =
            MechanismRegistry::try_from(&payload).expect_err("duplicate ID must fail decode");
        assert_eq!(error.mechanism, 0x1087);
        assert_eq!(error.first_shape, "gcm");
        assert_eq!(error.second_shape, "iv");
        let rendered = error.to_string();
        assert!(rendered.contains("0x1087"), "error must name the ID: {rendered}");
        assert!(
            rendered.contains("gcm") && rendered.contains("iv"),
            "error must name both shapes: {rendered}"
        );
    }

    #[test]
    fn duplicate_mechanism_id_within_one_entry_fails_decode() {
        let payload = MechanismRegistryPayload {
            revision: "rev".to_string(),
            discovery_mode: "transparent".to_string(),
            parameterless: vec![],
            params: vec![MechanismParamEntry {
                shape: "gcm".to_string(),
                mechanisms: vec![0x1087, 0x1087],
            }],
            excluded: vec![],
        };
        let error =
            MechanismRegistry::try_from(&payload).expect_err("duplicate ID must fail decode");
        assert_eq!(error.mechanism, 0x1087);
    }

    /// Negative control: distinct IDs across shapes still decode.
    #[test]
    fn distinct_ids_across_shapes_decode() {
        let payload = MechanismRegistryPayload {
            revision: "rev".to_string(),
            discovery_mode: "transparent".to_string(),
            parameterless: vec![],
            params: vec![
                MechanismParamEntry { shape: "gcm".to_string(), mechanisms: vec![0x1087] },
                MechanismParamEntry { shape: "iv".to_string(), mechanisms: vec![0x1081] },
            ],
            excluded: vec![],
        };
        let registry = MechanismRegistry::try_from(&payload).expect("distinct IDs must decode");
        assert_eq!(registry.param_shape(0x1087), Some("gcm"));
        assert_eq!(registry.param_shape(0x1081), Some("iv"));
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
