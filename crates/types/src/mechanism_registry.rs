//! Config-driven mechanism registry.
//!
//! Replaces the hardcoded `is_mechanism_params_modeled()` and
//! `KNOWN_PARAMETERLESS` with a TOML-driven registry that maps mechanism
//! types to parameter shapes or marks them parameterless.
//!
//! The embedded default is loaded from `mechanism_params_default.toml`
//! (compiled in via `include_str!`). An optional override file can add
//! vendor-specific mechanisms (e.g. CloudHSM extensions) or hard-disable
//! mechanisms via `exclude` (e.g. historical ciphers in FIPS deployments).
//!
//! Exclusion is an operation-time gate, not just a discovery hint: a
//! filtered discovery allowlist hides mechanisms from `C_GetMechanismList`
//! but still permits direct invocations, while `exclude` rejects them in
//! [`MechanismRegistry::check_operation`] and hides them in every
//! discovery mode.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::Deserialize;

use crate::CkRv;

// ─── Public types ──────────────────────────────────────────────────────────

/// How the proxy advertises mechanisms to clients via `C_GetMechanismList`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMode {
    /// Pass through every mechanism the backend reports.
    #[default]
    Transparent,
    /// Only advertise mechanisms the proxy can fully handle (parameterless
    /// or with a known parameter shape).
    Filtered,
}

/// Sentinel revision used when the registry is the embedded default or has
/// no content-derived revision otherwise.
pub const EMBEDDED_DEFAULT_REVISION: &str = "embedded-default";

/// Registry of mechanism parameter shapes, parameterless mechanisms,
/// operator-excluded mechanisms, and discovery mode. Built from an embedded
/// TOML default plus an optional operator override, or reconstructed from a
/// server-published payload.
#[derive(Debug)]
pub struct MechanismRegistry {
    param_shapes: HashMap<u64, String>,
    parameterless: HashSet<u64>,
    /// Operator-disabled mechanisms (`exclude` list). Checked first by
    /// [`MechanismRegistry::check_operation`] and hidden by
    /// [`MechanismRegistry::filter_mechanisms`] in every discovery mode.
    disabled: HashSet<u64>,
    discovery_mode: DiscoveryMode,
    /// Short content-derived identifier used for change detection
    /// between probes (`EMBEDDED_DEFAULT_REVISION` for the embedded
    /// default, or a hex-truncated SHA-256 of the source TOML).
    revision: String,
}

// ─── TOML schema ───────────────────────────────────────────────────────────

/// Top-level TOML document.
#[derive(Debug, Deserialize)]
struct TomlConfig {
    discovery_mode: Option<DiscoveryMode>,
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    parameterless: Vec<u64>,
    #[serde(default)]
    params: Vec<TomlParamsEntry>,
    /// CK_MECHANISM_TYPE values the operator hard-disables. Exclusion wins
    /// over every other entry: an excluded mechanism is rejected by
    /// `check_operation` (even parameterless) and hidden from discovery in
    /// every discovery mode. Excluding an unknown mechanism is not an error.
    #[serde(default)]
    exclude: Vec<u64>,
}

/// A `[[params]]` table: one shape name → list of mechanism type values.
#[derive(Debug, Deserialize)]
struct TomlParamsEntry {
    shape: String,
    mechanisms: Vec<u64>,
}

// ─── Embedded default ──────────────────────────────────────────────────────

const DEFAULT_TOML: &str = include_str!("mechanism_params_default.toml");

// ─── Implementation ────────────────────────────────────────────────────────

impl MechanismRegistry {
    /// Parse the embedded default and return the initial registry state.
    #[allow(clippy::type_complexity)]
    fn load_base()
    -> Result<(HashMap<u64, String>, HashSet<u64>, HashSet<u64>, DiscoveryMode), String> {
        let base: TomlConfig = toml::from_str(DEFAULT_TOML)
            .map_err(|e| format!("failed to parse embedded mechanism config: {e}"))?;

        let mut param_shapes = HashMap::new();
        let mut parameterless = HashSet::new();
        let mut disabled = HashSet::new();
        let mut discovery_mode = DiscoveryMode::default();
        Self::merge_config(
            &base,
            &mut param_shapes,
            &mut parameterless,
            &mut disabled,
            &mut discovery_mode,
        );

        Ok((param_shapes, parameterless, disabled, discovery_mode))
    }

    /// Load the registry from the embedded default, optionally merging an
    /// override file from disk.
    ///
    /// `override_path` is typically sourced from the
    /// `PKCS11_PROXY_MECHANISMS` environment variable.
    pub fn load(override_path: Option<&Path>) -> Result<Self, String> {
        let (mut param_shapes, mut parameterless, mut disabled, mut discovery_mode) =
            Self::load_base()?;

        if let Some(path) = override_path {
            let content = std::fs::read_to_string(path).map_err(|e| {
                format!("failed to read mechanism override {}: {e}", path.display())
            })?;
            let over: TomlConfig = toml::from_str(&content)
                .map_err(|e| format!("failed to parse mechanism override config: {e}"))?;

            // Process includes (single-level, no recursion).
            let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
            for include_path_str in &over.include {
                let include_path = Path::new(include_path_str);
                let resolved = if include_path.is_absolute() {
                    include_path.to_path_buf()
                } else {
                    base_dir.join(include_path)
                };
                let inc_content = std::fs::read_to_string(&resolved).map_err(|e| {
                    format!("failed to read included mechanism config {}: {e}", resolved.display())
                })?;
                let inc_config: TomlConfig = toml::from_str(&inc_content).map_err(|e| {
                    format!("failed to parse included mechanism config {}: {e}", resolved.display())
                })?;
                // Merge included config (ignore its `include` field — no recursion).
                Self::merge_config(
                    &inc_config,
                    &mut param_shapes,
                    &mut parameterless,
                    &mut disabled,
                    &mut discovery_mode,
                );
            }

            // Merge the override file's own entries last (highest priority).
            Self::merge_config(
                &over,
                &mut param_shapes,
                &mut parameterless,
                &mut disabled,
                &mut discovery_mode,
            );
        }

        Ok(Self {
            param_shapes,
            parameterless,
            disabled,
            discovery_mode,
            revision: EMBEDDED_DEFAULT_REVISION.to_string(),
        })
    }

    /// Merge a parsed `TomlConfig` into the running state.
    fn merge_config(
        config: &TomlConfig,
        param_shapes: &mut HashMap<u64, String>,
        parameterless: &mut HashSet<u64>,
        disabled: &mut HashSet<u64>,
        discovery_mode: &mut DiscoveryMode,
    ) {
        if let Some(mode) = config.discovery_mode {
            *discovery_mode = mode;
        }
        parameterless.extend(&config.parameterless);
        disabled.extend(&config.exclude);
        for entry in &config.params {
            for &mech in &entry.mechanisms {
                param_shapes.insert(mech, entry.shape.clone());
            }
        }
    }

    /// Load from embedded default, optionally merging an override TOML
    /// string. Useful for testing without touching the filesystem.
    pub fn load_with_override_str(override_toml: Option<&str>) -> Result<Self, String> {
        let (mut param_shapes, mut parameterless, mut disabled, mut discovery_mode) =
            Self::load_base()?;

        // Merge override if provided.
        // Note: includes are not processed here (no file path context).
        if let Some(toml_str) = override_toml {
            let over: TomlConfig = toml::from_str(toml_str)
                .map_err(|e| format!("failed to parse mechanism override config: {e}"))?;
            Self::merge_config(
                &over,
                &mut param_shapes,
                &mut parameterless,
                &mut disabled,
                &mut discovery_mode,
            );
        }

        Ok(Self {
            param_shapes,
            parameterless,
            disabled,
            discovery_mode,
            revision: EMBEDDED_DEFAULT_REVISION.to_string(),
        })
    }

    /// Construct a registry directly from its component parts. Used by
    /// the proto conversion layer when reconstructing a registry from a
    /// server-published payload.
    pub fn from_parts(
        param_shapes: HashMap<u64, String>,
        parameterless: HashSet<u64>,
        disabled: HashSet<u64>,
        discovery_mode: DiscoveryMode,
        revision: String,
    ) -> Self {
        Self { param_shapes, parameterless, disabled, discovery_mode, revision }
    }

    /// Replace the revision string. Used by the daemon after loading a
    /// registry file from disk to attach a content-derived identifier.
    pub fn set_revision(&mut self, revision: String) {
        self.revision = revision;
    }

    /// Return the registry's revision identifier. Callers must treat this
    /// as opaque; equality across two values means "same registry
    /// contents", inequality means "may differ" — nothing else.
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Borrow the parameter-shape map, for serialisation into the proto
    /// payload. Callers should not mutate; this is a read-only view.
    pub fn param_shapes_view(&self) -> &HashMap<u64, String> {
        &self.param_shapes
    }

    /// Borrow the parameterless set, for serialisation into the proto
    /// payload.
    pub fn parameterless_view(&self) -> &HashSet<u64> {
        &self.parameterless
    }

    /// Borrow the operator-excluded set, for serialisation into the proto
    /// payload.
    pub fn excluded_view(&self) -> &HashSet<u64> {
        &self.disabled
    }

    /// Return the parameter shape name for a mechanism, or `None` if the
    /// mechanism has no known parameterized shape.
    pub fn param_shape(&self, mech_type: u64) -> Option<&str> {
        self.param_shapes.get(&mech_type).map(|s| s.as_str())
    }

    /// Return `true` if the mechanism is registered as parameterless.
    pub fn is_parameterless(&self, mech_type: u64) -> bool {
        self.parameterless.contains(&mech_type)
    }

    /// Operation-time check: can the proxy forward this mechanism invocation?
    ///
    /// - Operator-excluded mechanisms are always rejected with
    ///   `CKR_MECHANISM_INVALID`, even without params. Exclusion wins over
    ///   every other registry entry.
    /// - Other parameterless invocations (no params) are always allowed.
    /// - Invocations with params must have a known parameter shape.
    /// - Unknown mechanisms with params are rejected with
    ///   `CKR_MECHANISM_PARAM_INVALID`.
    pub fn check_operation(&self, mech_type: u64, has_params: bool) -> Result<(), CkRv> {
        if self.disabled.contains(&mech_type) {
            tracing::warn!(
                mechanism = format_args!("0x{mech_type:08X}"),
                "rejecting operator-excluded mechanism"
            );
            return Err(CkRv::MECHANISM_INVALID);
        }
        if !has_params {
            return Ok(());
        }
        if self.param_shapes.contains_key(&mech_type) {
            Ok(())
        } else {
            tracing::warn!(
                mechanism = format_args!("0x{mech_type:08X}"),
                "rejecting mechanism with unmodeled parameters"
            );
            Err(CkRv::MECHANISM_PARAM_INVALID)
        }
    }

    /// Filter a mechanism list for `C_GetMechanismList`.
    ///
    /// Operator-excluded mechanisms are hidden in every discovery mode;
    /// exclusion is a security boundary, not a display hint.
    ///
    /// - `Transparent`: return all backend mechanisms except excluded ones.
    /// - `Filtered`: return only mechanisms the proxy fully handles
    ///   (parameterless or with a known parameter shape), minus excluded ones.
    pub fn filter_mechanisms(&self, backend_mechs: &[u64]) -> Vec<u64> {
        match self.discovery_mode {
            DiscoveryMode::Transparent => {
                backend_mechs.iter().copied().filter(|m| !self.disabled.contains(m)).collect()
            }
            DiscoveryMode::Filtered => backend_mechs
                .iter()
                .copied()
                .filter(|m| {
                    !self.disabled.contains(m)
                        && (self.parameterless.contains(m) || self.param_shapes.contains_key(m))
                })
                .collect(),
        }
    }

    /// The active discovery mode.
    pub fn discovery_mode(&self) -> DiscoveryMode {
        self.discovery_mode
    }

    /// Return every mechanism registered by the embedded/default registry plus
    /// any operator override, minus operator-excluded mechanisms, sorted and
    /// deduplicated.
    ///
    /// This is intended for deterministic test backends and audit tooling that
    /// need the complete proxy-understood mechanism surface, not for filtering
    /// real provider discovery.
    pub fn registered_mechanisms(&self) -> Vec<u64> {
        let mut registered = self.parameterless.clone();
        registered.extend(self.param_shapes.keys().copied());
        registered.retain(|m| !self.disabled.contains(m));
        let mut mechanisms: Vec<u64> = registered.into_iter().collect();
        mechanisms.sort_unstable();
        mechanisms
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Well-known mechanism constants (from OASIS PKCS#11 v3.02).
    const CKM_AES_GCM: u64 = 0x1087;
    const CKM_RSA_PKCS: u64 = 0x0001;
    const CKM_RSA_PKCS_PSS: u64 = 0x000D;
    const CKM_AES_ECB: u64 = 0x1081;
    const CKM_AES_KEY_GEN: u64 = 0x1080;
    const CKM_SHA256: u64 = 0x0250;
    const CKM_AES_CBC: u64 = 0x1082;
    const CKM_DES3_CBC_PAD: u64 = 0x0136;
    const CKM_ECDH1_DERIVE: u64 = 0x1050;
    const CKM_RSA_PKCS_OAEP: u64 = 0x0009;
    const CKM_AES_CBC_PAD: u64 = 0x1085;
    const CKM_DES3_CBC: u64 = 0x0133;
    const CKM_SP800_108_COUNTER_KDF: u64 = 0x03AC;
    const CKM_SP800_108_FEEDBACK_KDF: u64 = 0x03AD;
    const CKM_SP800_108_DOUBLE_PIPELINE_KDF: u64 = 0x03AE;
    const CKM_EXTRACT_KEY_FROM_KEY: u64 = 0x0365;
    const CKM_WTLS_MASTER_KEY_DERIVE: u64 = 0x03D1;
    const CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC: u64 = 0x03D2;
    const CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE: u64 = 0x03D4;
    const CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE: u64 = 0x03D5;
    const CKM_ECMQV_DERIVE: u64 = 0x1052;
    const CKM_DES_ECB_ENCRYPT_DATA: u64 = 0x1100;
    const CKM_DES3_ECB_ENCRYPT_DATA: u64 = 0x1102;
    const CKM_BLAKE2B_512_KEY_DERIVE: u64 = 0x401E;
    const CKM_BLAKE2B_512_KEY_GEN: u64 = 0x401F;
    const CKM_SALSA20: u64 = 0x4020;
    const CKM_X3DH_INITIALIZE: u64 = 0x4023;
    const CKM_IKE2_PRF_PLUS_DERIVE: u64 = 0x402E;
    const CKM_IKE_PRF_DERIVE: u64 = 0x402F;
    const CKM_IKE1_PRF_DERIVE: u64 = 0x4030;
    const CKM_IKE1_EXTENDED_DERIVE: u64 = 0x4031;
    const CKM_RC2_ECB: u64 = 0x0101;
    const CKM_RC2_MAC: u64 = 0x0103;
    const CKM_RC2_MAC_GENERAL: u64 = 0x0104;

    #[test]
    fn load_embedded_default() {
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();

        // AES-GCM should map to "gcm" shape.
        assert_eq!(reg.param_shape(CKM_AES_GCM), Some("gcm"));

        // RSA-PSS should map to "rsa_pss" shape.
        assert_eq!(reg.param_shape(CKM_RSA_PKCS_PSS), Some("rsa_pss"));

        // RSA-OAEP should map to "rsa_oaep" shape.
        assert_eq!(reg.param_shape(CKM_RSA_PKCS_OAEP), Some("rsa_oaep"));

        // ECDH1-DERIVE should map to "ecdh1_derive" shape.
        assert_eq!(reg.param_shape(CKM_ECDH1_DERIVE), Some("ecdh1_derive"));

        // IV-based mechanisms
        assert_eq!(reg.param_shape(CKM_AES_CBC), Some("iv"));
        assert_eq!(reg.param_shape(CKM_AES_CBC_PAD), Some("iv"));
        assert_eq!(reg.param_shape(CKM_DES3_CBC), Some("iv"));
        assert_eq!(reg.param_shape(CKM_DES3_CBC_PAD), Some("iv"));

        // RSA_PKCS is parameterless.
        assert!(reg.is_parameterless(CKM_RSA_PKCS));

        // SHA256 is parameterless.
        assert!(reg.is_parameterless(CKM_SHA256));

        // AES_ECB is parameterless.
        assert!(reg.is_parameterless(CKM_AES_ECB));

        // AES_KEY_GEN is parameterless.
        assert!(reg.is_parameterless(CKM_AES_KEY_GEN));

        // SP800-108 has two official parameter structs: feedback mode has
        // an IV field, while counter and double-pipeline do not.
        assert_eq!(reg.param_shape(CKM_SP800_108_COUNTER_KDF), Some("sp800_108_kdf"));
        assert_eq!(reg.param_shape(CKM_SP800_108_FEEDBACK_KDF), Some("sp800_108_feedback_kdf"));
        assert_eq!(reg.param_shape(CKM_SP800_108_DOUBLE_PIPELINE_KDF), Some("sp800_108_kdf"));

        // CK_EXTRACT_PARAMS is its own bit-position parameter shape, not a MAC length.
        assert_eq!(reg.param_shape(CKM_EXTRACT_KEY_FROM_KEY), Some("extract"));

        // WTLS master-key derivation has a mutable pVersion byte.
        assert_eq!(reg.param_shape(CKM_WTLS_MASTER_KEY_DERIVE), Some("wtls_master_key_derive"));
        assert_eq!(
            reg.param_shape(CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC),
            Some("wtls_master_key_derive")
        );
        assert_eq!(reg.param_shape(CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE), Some("wtls_key_mat"));
        assert_eq!(reg.param_shape(CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE), Some("wtls_key_mat"));

        // Default discovery mode is transparent.
        assert_eq!(reg.discovery_mode(), DiscoveryMode::Transparent);
    }

    #[test]
    fn embedded_default_uses_the_rc2_parameter_shapes() {
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();

        assert_eq!(
            [
                reg.param_shape(CKM_RC2_ECB),
                reg.param_shape(CKM_RC2_MAC),
                reg.param_shape(CKM_RC2_MAC_GENERAL),
            ],
            [Some("mac_general"), Some("mac_general"), Some("rc2_mac_general")]
        );
        for mechanism in [CKM_RC2_ECB, CKM_RC2_MAC, CKM_RC2_MAC_GENERAL] {
            assert!(!reg.is_parameterless(mechanism));
        }
    }

    #[test]
    fn embedded_default_registry_does_not_assign_project_local_placeholder_ids() {
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();

        assert_eq!(reg.param_shape(CKM_ECMQV_DERIVE), Some("ecmqv_derive"));
        assert_eq!(reg.param_shape(CKM_DES_ECB_ENCRYPT_DATA), Some("key_derivation_string"));
        assert_eq!(reg.param_shape(CKM_DES3_ECB_ENCRYPT_DATA), Some("key_derivation_string"));
        assert_eq!(reg.param_shape(CKM_SALSA20), Some("salsa20"));

        assert_eq!(reg.param_shape(CKM_IKE_PRF_DERIVE), Some("ike_prf_derive"));
        assert_eq!(reg.param_shape(CKM_IKE1_PRF_DERIVE), Some("ike1_prf_derive"));
        assert_eq!(reg.param_shape(CKM_IKE1_EXTENDED_DERIVE), Some("ike1_extended_derive"));
        assert_eq!(reg.param_shape(CKM_IKE2_PRF_PLUS_DERIVE), Some("ike2_prf_plus_derive"));

        assert_eq!(reg.param_shape(CKM_BLAKE2B_512_KEY_DERIVE), None);
        assert_eq!(reg.param_shape(CKM_BLAKE2B_512_KEY_GEN), None);
        assert_eq!(reg.param_shape(CKM_X3DH_INITIALIZE), None);
    }

    #[test]
    fn ml_dsa_and_slh_dsa_hash_variants_use_sign_additional_context() {
        // Regression guard: pure CKM_ML_DSA already mapped, but the hash-specific
        // ML-DSA / SLH-DSA mechanisms take the SAME plain CK_SIGN_ADDITIONAL_CONTEXT
        // (the hash is implied by the mechanism — OASIS PKCS#11 v3.2 ml_dsa.md
        // §"CKM_HASH_ML_DSA_*"). If they are NOT mapped here, the shim ships their
        // context parameter via the Raw path (which serialises a host pointer) and
        // a real backend rejects it with CKR_MECHANISM_PARAM_INVALID.
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();
        for mech in [
            0x001D, // CKM_ML_DSA (pure)
            0x002E, // CKM_SLH_DSA (pure)
            0x0024, // CKM_HASH_ML_DSA_SHA256
            0x0026, // CKM_HASH_ML_DSA_SHA512
            0x002C, // CKM_HASH_ML_DSA_SHAKE256
            0x0037, // CKM_HASH_SLH_DSA_SHA256
            0x003F, // CKM_HASH_SLH_DSA_SHAKE256
            0x001F, // CKM_HASH_ML_DSA  (generic — CK_HASH_SIGN_ADDITIONAL_CONTEXT)
            0x0034, // CKM_HASH_SLH_DSA (generic — CK_HASH_SIGN_ADDITIONAL_CONTEXT)
        ] {
            assert_eq!(
                reg.param_shape(mech),
                Some("sign_additional_context"),
                "mechanism {mech:#06x} should map to sign_additional_context"
            );
        }
    }

    #[test]
    fn check_operation_parameterless_always_ok() {
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();
        // Unknown mechanism with no params is always fine.
        let unknown = 0xDEAD_BEEF_u64;
        assert!(reg.check_operation(unknown, false).is_ok());
    }

    #[test]
    fn check_operation_unknown_with_params_rejected() {
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();
        let unknown = 0xDEAD_BEEF_u64;
        let result = reg.check_operation(unknown, true);
        assert_eq!(result, Err(CkRv::MECHANISM_PARAM_INVALID));
    }

    #[test]
    fn check_operation_known_with_params_ok() {
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();
        // AES-GCM with params should be accepted.
        assert!(reg.check_operation(CKM_AES_GCM, true).is_ok());
    }

    #[test]
    fn merge_override_adds_mechanisms() {
        let override_toml = r#"
            [[params]]
            shape = "gcm"
            mechanisms = [0x80001087]
        "#;
        let reg = MechanismRegistry::load_with_override_str(Some(override_toml)).unwrap();

        // Vendor mechanism should now map to "gcm".
        assert_eq!(reg.param_shape(0x80001087), Some("gcm"));

        // Original AES-GCM should still be present.
        assert_eq!(reg.param_shape(CKM_AES_GCM), Some("gcm"));
    }

    #[test]
    fn merge_override_appends_parameterless() {
        let override_toml = r#"
            parameterless = [0x80FF0001]
        "#;
        let reg = MechanismRegistry::load_with_override_str(Some(override_toml)).unwrap();

        // Vendor mechanism should be parameterless.
        assert!(reg.is_parameterless(0x80FF0001));

        // Original parameterless mechanisms should still be present.
        assert!(reg.is_parameterless(CKM_RSA_PKCS));
    }

    #[test]
    fn exclude_rejects_with_and_without_params() {
        let override_toml = r#"
            exclude = [0x0001, 0x1087]
        "#;
        let reg = MechanismRegistry::load_with_override_str(Some(override_toml)).unwrap();

        // Excluded parameterless mechanism is rejected even without params.
        assert_eq!(reg.check_operation(CKM_RSA_PKCS, false), Err(CkRv::MECHANISM_INVALID));
        // Excluded shaped mechanism is rejected with and without params.
        assert_eq!(reg.check_operation(CKM_AES_GCM, true), Err(CkRv::MECHANISM_INVALID));
        assert_eq!(reg.check_operation(CKM_AES_GCM, false), Err(CkRv::MECHANISM_INVALID));

        // Non-excluded mechanisms are unaffected.
        assert!(reg.check_operation(CKM_AES_ECB, false).is_ok());
        assert!(reg.check_operation(CKM_RSA_PKCS_PSS, true).is_ok());
    }

    #[test]
    fn exclude_filters_discovery_in_transparent_and_filtered_modes() {
        for mode_toml in ["", "discovery_mode = \"filtered\""] {
            let override_toml = format!("{mode_toml}\nexclude = [0x0001, 0x1087]\n");
            let reg = MechanismRegistry::load_with_override_str(Some(&override_toml)).unwrap();

            let output = reg.filter_mechanisms(&[CKM_RSA_PKCS, CKM_AES_GCM, CKM_AES_ECB]);
            assert!(
                !output.contains(&CKM_RSA_PKCS),
                "excluded mech advertised (mode: {mode_toml:?})"
            );
            assert!(
                !output.contains(&CKM_AES_GCM),
                "excluded mech advertised (mode: {mode_toml:?})"
            );
            assert!(
                output.contains(&CKM_AES_ECB),
                "non-excluded mech dropped (mode: {mode_toml:?})"
            );
        }
    }

    #[test]
    fn exclude_unknown_mechanism_loads_and_rejects() {
        // Excluding a mechanism the embedded default never modeled is not
        // an error (forward-compatibility for vendor IDs).
        let override_toml = "exclude = [0xDEADBEEF]";
        let reg = MechanismRegistry::load_with_override_str(Some(override_toml)).unwrap();

        assert_eq!(reg.check_operation(0xDEAD_BEEF, false), Err(CkRv::MECHANISM_INVALID));
        assert_eq!(reg.check_operation(0xDEAD_BEEF, true), Err(CkRv::MECHANISM_INVALID));
        // Everything else is unaffected.
        assert!(reg.check_operation(CKM_RSA_PKCS, false).is_ok());
    }

    #[test]
    fn registered_mechanisms_omits_excluded() {
        let override_toml = "exclude = [0x0001]";
        let reg = MechanismRegistry::load_with_override_str(Some(override_toml)).unwrap();

        let registered = reg.registered_mechanisms();
        assert!(!registered.contains(&CKM_RSA_PKCS));
        assert!(registered.contains(&CKM_AES_ECB));
    }

    #[test]
    fn filtered_discovery_without_exclude_does_not_gate_operations() {
        // Documents why `exclude` exists: filtered discovery only hides
        // unlisted mechanisms from C_GetMechanismList; the operation-time
        // gate still permits anything the embedded default models
        // (e.g. historical RC4, which stays parameterless-allowed).
        let override_toml = r#"discovery_mode = "filtered""#;
        let reg = MechanismRegistry::load_with_override_str(Some(override_toml)).unwrap();

        const CKM_RC4: u64 = 0x0111;
        const UNKNOWN: u64 = 0xDEAD_BEEF;
        // Unknown mechanisms are hidden from filtered discovery ...
        assert!(!reg.filter_mechanisms(&[UNKNOWN]).contains(&UNKNOWN));
        // ... but a parameterless invocation would still be forwarded.
        assert!(reg.check_operation(UNKNOWN, false).is_ok());
        // Likewise a default-modeled historical mechanism stays allowed.
        assert!(reg.check_operation(CKM_RC4, false).is_ok());

        // ...unless the operator excludes them.
        let override_toml = "discovery_mode = \"filtered\"\nexclude = [0x0111, 0xDEADBEEF]\n";
        let reg = MechanismRegistry::load_with_override_str(Some(override_toml)).unwrap();
        assert_eq!(reg.check_operation(CKM_RC4, false), Err(CkRv::MECHANISM_INVALID));
        assert_eq!(reg.check_operation(UNKNOWN, false), Err(CkRv::MECHANISM_INVALID));
    }

    #[test]
    fn filter_transparent_returns_all() {
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();
        assert_eq!(reg.discovery_mode(), DiscoveryMode::Transparent);

        let input = vec![CKM_AES_GCM, 0xDEAD_BEEF, CKM_RSA_PKCS];
        let output = reg.filter_mechanisms(&input);
        assert_eq!(output, input);
    }

    #[test]
    fn filter_filtered_returns_only_known() {
        let override_toml = r#"
            discovery_mode = "filtered"
        "#;
        let reg = MechanismRegistry::load_with_override_str(Some(override_toml)).unwrap();
        assert_eq!(reg.discovery_mode(), DiscoveryMode::Filtered);

        let unknown = 0xDEAD_BEEF_u64;
        let input = vec![CKM_AES_GCM, unknown, CKM_RSA_PKCS, CKM_AES_ECB];
        let output = reg.filter_mechanisms(&input);

        // Unknown should be filtered out; known should remain.
        assert!(output.contains(&CKM_AES_GCM));
        assert!(output.contains(&CKM_RSA_PKCS));
        assert!(output.contains(&CKM_AES_ECB));
        assert!(!output.contains(&unknown));
    }

    #[test]
    fn override_changes_discovery_mode() {
        // Default is transparent.
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();
        assert_eq!(reg.discovery_mode(), DiscoveryMode::Transparent);

        // Override to filtered.
        let override_toml = r#"discovery_mode = "filtered""#;
        let reg = MechanismRegistry::load_with_override_str(Some(override_toml)).unwrap();
        assert_eq!(reg.discovery_mode(), DiscoveryMode::Filtered);
    }

    #[test]
    fn all_eight_current_modeled_mechanisms_have_shapes() {
        // Verify the 8 mechanisms from is_mechanism_params_modeled() all have
        // shapes in the registry.
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();

        let modeled = [
            (CKM_RSA_PKCS_PSS, "rsa_pss"),
            (CKM_RSA_PKCS_OAEP, "rsa_oaep"),
            (CKM_AES_GCM, "gcm"),
            (CKM_ECDH1_DERIVE, "ecdh1_derive"),
            (CKM_AES_CBC, "iv"),
            (CKM_AES_CBC_PAD, "iv"),
            (CKM_DES3_CBC, "iv"),
            (CKM_DES3_CBC_PAD, "iv"),
        ];

        for (mech, expected_shape) in &modeled {
            assert_eq!(
                reg.param_shape(*mech),
                Some(*expected_shape),
                "mechanism 0x{mech:04X} should have shape \"{expected_shape}\""
            );
        }
    }

    #[test]
    fn all_current_known_parameterless_in_registry() {
        // Verify every mechanism from KNOWN_PARAMETERLESS in
        // mechanism_filter.rs is in the registry.
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();

        let known_parameterless = [
            0x0001_u64, // CKM_RSA_PKCS
            0x0000,     // CKM_RSA_PKCS_KEY_PAIR_GEN
            0x0040,     // CKM_SHA256_RSA_PKCS
            0x0041,     // CKM_SHA384_RSA_PKCS
            0x0042,     // CKM_SHA512_RSA_PKCS
            0x1041,     // CKM_ECDSA
            0x1044,     // CKM_ECDSA_SHA256
            0x1045,     // CKM_ECDSA_SHA384
            0x1046,     // CKM_ECDSA_SHA512
            0x1040,     // CKM_EC_KEY_PAIR_GEN
            0x0250,     // CKM_SHA256
            0x0260,     // CKM_SHA384
            0x0270,     // CKM_SHA512
        ];

        for mech in &known_parameterless {
            assert!(reg.is_parameterless(*mech), "mechanism 0x{mech:04X} should be parameterless");
        }
    }

    #[test]
    fn invalid_override_toml_returns_error() {
        let bad_toml = "this is not valid toml {{{";
        let result = MechanismRegistry::load_with_override_str(Some(bad_toml));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to parse mechanism override config"));
    }

    #[test]
    fn override_adds_new_shape() {
        let override_toml = r#"
            [[params]]
            shape = "vendor_special"
            mechanisms = [0x80AABBCC]
        "#;
        let reg = MechanismRegistry::load_with_override_str(Some(override_toml)).unwrap();
        assert_eq!(reg.param_shape(0x80AABBCC), Some("vendor_special"));
    }

    #[test]
    fn parameterless_not_in_param_shapes() {
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();
        // AES_ECB is parameterless and should not appear in param_shapes.
        assert!(reg.is_parameterless(CKM_AES_ECB));
        assert_eq!(reg.param_shape(CKM_AES_ECB), None);
    }

    #[test]
    fn cloudhsm_example_override_parses_and_merges() {
        // The CloudHSM example override file from examples/cloudhsm-mechanisms.toml.
        // Inline the content so the test does not depend on filesystem layout.
        let cloudhsm_toml = r#"
            # CKM_CLOUDHSM_AES_GCM — same params as standard AES-GCM
            [[params]]
            shape = "gcm"
            mechanisms = [0x80001087]

            # CloudHSM AES key wrap variants — IV-based
            [[params]]
            shape = "iv"
            mechanisms = [0x80002109, 0x8000210A, 0x8000216F]
        "#;

        let reg = MechanismRegistry::load_with_override_str(Some(cloudhsm_toml)).unwrap();

        // Vendor GCM mechanism should be present with gcm shape.
        assert_eq!(reg.param_shape(0x80001087), Some("gcm"));

        // Vendor IV-based mechanisms should all map to iv shape.
        assert_eq!(reg.param_shape(0x80002109), Some("iv"));
        assert_eq!(reg.param_shape(0x8000210A), Some("iv"));
        assert_eq!(reg.param_shape(0x8000216F), Some("iv"));

        // Standard mechanisms should still be present (merge is additive).
        assert_eq!(reg.param_shape(CKM_AES_GCM), Some("gcm"));
        assert_eq!(reg.param_shape(CKM_AES_CBC), Some("iv"));
        assert!(reg.is_parameterless(CKM_RSA_PKCS));
        assert!(reg.is_parameterless(CKM_SHA256));

        // Vendor mechanisms with params should pass check_operation.
        assert!(reg.check_operation(0x80001087, true).is_ok());
        assert!(reg.check_operation(0x80002109, true).is_ok());

        // Discovery mode should remain transparent (CloudHSM override
        // does not set it).
        assert_eq!(reg.discovery_mode(), DiscoveryMode::Transparent);
    }

    #[test]
    fn registered_mechanisms_returns_parameterless_and_parameterized_union() {
        let reg = MechanismRegistry::load_with_override_str(Some(
            r#"
            parameterless = [0x80FF0001]

            [[params]]
            shape = "gcm"
            mechanisms = [0x80001087]
            "#,
        ))
        .unwrap();

        let mechanisms = reg.registered_mechanisms();

        assert!(mechanisms.contains(&CKM_RSA_PKCS), "parameterless mechanism included");
        assert!(mechanisms.contains(&CKM_AES_GCM), "parameterized mechanism included");
        assert!(mechanisms.contains(&0x80FF0001), "vendor parameterless mechanism included");
        assert!(mechanisms.contains(&0x80001087), "vendor parameterized mechanism included");
        assert!(mechanisms.windows(2).all(|pair| pair[0] < pair[1]), "mechanisms sorted unique");
    }

    #[test]
    fn official_mechanisms_include_provider_gap_examples() {
        let mechanisms = crate::pkcs11_3_2_official_mechanisms();

        assert!(mechanisms.windows(2).all(|pair| pair[0].0 < pair[1].0), "sorted unique");
        assert!(mechanisms.contains(&crate::CkMechanismType(0x0000_001F))); // CKM_HASH_ML_DSA
        assert!(mechanisms.contains(&crate::CkMechanismType(0x0000_002E))); // CKM_SLH_DSA
        assert!(mechanisms.contains(&crate::CkMechanismType(0x0000_03D5))); // CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE
        assert!(mechanisms.contains(&crate::CkMechanismType(0x0000_108D))); // CKM_AES_XCBC_MAC_96
        assert!(mechanisms.contains(&crate::CkMechanismType(0x0000_4037))); // CKM_XMSSMT
        assert!(mechanisms.contains(&crate::CkMechanismType(0x0000_403A))); // CKM_PUB_KEY_FROM_PRIV_KEY
    }

    #[test]
    fn all_standard_parameterless_mechanisms_present_in_default_config() {
        // Verify that the embedded default TOML contains all 133 standard
        // parameterless mechanisms. This list is exhaustive against the
        // mechanism_params_default.toml file to catch accidental deletions.
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();

        // Every family of parameterless mechanisms from the default TOML.
        let expected_parameterless: &[u64] = &[
            // RSA
            0x0000, // CKM_RSA_PKCS_KEY_PAIR_GEN
            0x0001, // CKM_RSA_PKCS
            0x0002, // CKM_RSA_9796
            0x0003, // CKM_RSA_X_509
            0x0004, // CKM_MD2_RSA_PKCS
            0x0005, // CKM_MD5_RSA_PKCS
            0x0006, // CKM_SHA1_RSA_PKCS
            0x0007, // CKM_RIPEMD128_RSA_PKCS
            0x0008, // CKM_RIPEMD160_RSA_PKCS
            0x000A, // CKM_RSA_X9_31_KEY_PAIR_GEN
            0x000B, // CKM_RSA_X9_31
            0x000C, // CKM_SHA1_RSA_X9_31
            0x0040, // CKM_SHA256_RSA_PKCS
            0x0041, // CKM_SHA384_RSA_PKCS
            0x0042, // CKM_SHA512_RSA_PKCS
            0x0046, // CKM_SHA224_RSA_PKCS
            0x0060, // CKM_SHA3_256_RSA_PKCS
            0x0061, // CKM_SHA3_384_RSA_PKCS
            0x0062, // CKM_SHA3_512_RSA_PKCS
            0x0066, // CKM_SHA3_224_RSA_PKCS
            // DSA
            0x0010, // CKM_DSA_KEY_PAIR_GEN
            0x0011, // CKM_DSA
            0x0012, // CKM_DSA_SHA1
            0x0013, // CKM_DSA_SHA224
            0x0014, // CKM_DSA_SHA256
            0x0015, // CKM_DSA_SHA384
            0x0016, // CKM_DSA_SHA512
            0x0018, // CKM_DSA_SHA3_224
            0x0019, // CKM_DSA_SHA3_256
            0x001A, // CKM_DSA_SHA3_384
            0x001B, // CKM_DSA_SHA3_512
            0x2000, // CKM_DSA_PARAMETER_GEN
            0x2003, // CKM_DSA_PROBABILISTIC_PARAMETER_GEN
            0x2004, // CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN
            0x2005, // CKM_DSA_FIPS_G_GEN
            // DH
            0x0020, // CKM_DH_PKCS_KEY_PAIR_GEN
            0x2001, // CKM_DH_PKCS_PARAMETER_GEN
            // X9.42 DH
            0x0030, // CKM_X9_42_DH_KEY_PAIR_GEN
            0x2002, // CKM_X9_42_DH_PARAMETER_GEN
            // EC / ECDSA
            0x1040, // CKM_EC_KEY_PAIR_GEN
            0x1041, // CKM_ECDSA
            0x1042, // CKM_ECDSA_SHA1
            0x1043, // CKM_ECDSA_SHA224
            0x1044, // CKM_ECDSA_SHA256
            0x1045, // CKM_ECDSA_SHA384
            0x1046, // CKM_ECDSA_SHA512
            0x1047, // CKM_ECDSA_SHA3_224
            0x1048, // CKM_ECDSA_SHA3_256
            0x1049, // CKM_ECDSA_SHA3_384
            0x104A, // CKM_ECDSA_SHA3_512
            0x1055, // CKM_EC_EDWARDS_KEY_PAIR_GEN
            0x1056, // CKM_EC_MONTGOMERY_KEY_PAIR_GEN
            0x1057, // CKM_EDDSA
            // KEA
            0x1010, // CKM_KEA_KEY_PAIR_GEN
            // Generic secret
            0x0350, // CKM_GENERIC_SECRET_KEY_GEN
            // RC2
            0x0100, // CKM_RC2_KEY_GEN
            // RC4
            0x0110, // CKM_RC4_KEY_GEN
            0x0111, // CKM_RC4
            // RC5
            0x0330, // CKM_RC5_KEY_GEN
            0x0331, // CKM_RC5_ECB
            0x0333, // CKM_RC5_MAC
            // DES
            0x0120, // CKM_DES_KEY_GEN
            0x0121, // CKM_DES_ECB
            0x0123, // CKM_DES_MAC
            // DES2 / DES3
            0x0130, // CKM_DES2_KEY_GEN
            0x0131, // CKM_DES3_KEY_GEN
            0x0132, // CKM_DES3_ECB
            0x0134, // CKM_DES3_MAC
            0x0138, // CKM_DES3_CMAC
            // CDMF
            0x0140, // CKM_CDMF_KEY_GEN
            0x0141, // CKM_CDMF_ECB
            0x0143, // CKM_CDMF_MAC
            // CAST
            0x0300, // CKM_CAST_KEY_GEN
            0x0301, // CKM_CAST_ECB
            0x0303, // CKM_CAST_MAC
            // CAST3
            0x0310, // CKM_CAST3_KEY_GEN
            0x0311, // CKM_CAST3_ECB
            0x0313, // CKM_CAST3_MAC
            // CAST128
            0x0320, // CKM_CAST128_KEY_GEN
            0x0321, // CKM_CAST128_ECB
            0x0323, // CKM_CAST128_MAC
            // IDEA
            0x0340, // CKM_IDEA_KEY_GEN
            0x0341, // CKM_IDEA_ECB
            0x0343, // CKM_IDEA_MAC
            // AES
            0x1080, // CKM_AES_KEY_GEN
            0x1081, // CKM_AES_ECB
            0x1083, // CKM_AES_MAC
            0x108A, // CKM_AES_CMAC
            // SSL/TLS
            0x0370, // CKM_SSL3_PRE_MASTER_KEY_GEN
            0x0374, // CKM_TLS_PRE_MASTER_KEY_GEN
            0x0380, // CKM_SSL3_MD5_MAC
            0x0381, // CKM_SSL3_SHA1_MAC
            // Digests
            0x0200, // CKM_MD2
            0x0201, // CKM_MD2_HMAC
            0x0210, // CKM_MD5
            0x0211, // CKM_MD5_HMAC
            0x0220, // CKM_SHA_1
            0x0221, // CKM_SHA_1_HMAC
            0x0250, // CKM_SHA256
            0x0251, // CKM_SHA256_HMAC
            0x0255, // CKM_SHA224
            0x0256, // CKM_SHA224_HMAC
            0x0260, // CKM_SHA384
            0x0261, // CKM_SHA384_HMAC
            0x0270, // CKM_SHA512
            0x0271, // CKM_SHA512_HMAC
            0x02B0, // CKM_SHA3_256
            0x02B1, // CKM_SHA3_256_HMAC
            0x02B5, // CKM_SHA3_224
            0x02B6, // CKM_SHA3_224_HMAC
            0x02C0, // CKM_SHA3_384
            0x02C1, // CKM_SHA3_384_HMAC
            0x02D0, // CKM_SHA3_512
            0x02D1, // CKM_SHA3_512_HMAC
            // RIPEMD
            0x0230, // CKM_RIPEMD128
            0x0231, // CKM_RIPEMD128_HMAC
            0x0240, // CKM_RIPEMD160
            0x0241, // CKM_RIPEMD160_HMAC
            // Fasthash
            0x1070, // CKM_FASTHASH
            // Wrapping
            0x0400, // CKM_KEY_WRAP_LYNKS
            0x2109, // CKM_AES_KEY_WRAP
            0x210A, // CKM_AES_KEY_WRAP_PAD
            0x210B, // CKM_AES_KEY_WRAP_KWP
            0x210C, // CKM_AES_KEY_WRAP_PKCS7
            // Skipjack
            0x1000, // CKM_SKIPJACK_KEY_GEN
            0x1008, // CKM_SKIPJACK_WRAP
            // Baton
            0x1030, // CKM_BATON_KEY_GEN
            0x1036, // CKM_BATON_WRAP
            // Juniper
            0x1060, // CKM_JUNIPER_KEY_GEN
            0x1065, // CKM_JUNIPER_WRAP
            // Fortezza
            0x1020, // CKM_FORTEZZA_TIMESTAMP
            // Post-quantum
            0x001C, // CKM_ML_DSA_KEY_PAIR_GEN
            0x001D, // CKM_ML_DSA
        ];

        // Verify count matches the TOML (133 parameterless mechanisms).
        // Parameterized RC2 ECB/MAC mechanisms use registry shapes.
        assert_eq!(
            expected_parameterless.len(),
            133,
            "expected list should contain exactly 133 entries"
        );

        for &mech in expected_parameterless {
            assert!(
                reg.is_parameterless(mech),
                "mechanism 0x{mech:04X} should be registered as parameterless"
            );
        }
    }

    #[test]
    fn cloudhsm_override_in_filtered_mode_includes_vendor_mechanisms() {
        // CloudHSM override combined with filtered mode should include
        // vendor mechanisms in the filtered output.
        let cloudhsm_plus_filtered = r#"
            discovery_mode = "filtered"

            [[params]]
            shape = "gcm"
            mechanisms = [0x80001087]

            [[params]]
            shape = "iv"
            mechanisms = [0x80002109, 0x8000210A, 0x8000216F]
        "#;

        let reg = MechanismRegistry::load_with_override_str(Some(cloudhsm_plus_filtered)).unwrap();
        assert_eq!(reg.discovery_mode(), DiscoveryMode::Filtered);

        let backend = vec![
            CKM_AES_GCM,  // standard, known shape
            CKM_RSA_PKCS, // standard, parameterless
            0x80001087,   // vendor, gcm shape from override
            0x80002109,   // vendor, iv shape from override
            0xDEAD_BEEF,  // unknown, should be filtered out
        ];

        let filtered = reg.filter_mechanisms(&backend);

        assert!(filtered.contains(&CKM_AES_GCM));
        assert!(filtered.contains(&CKM_RSA_PKCS));
        assert!(filtered.contains(&0x80001087));
        assert!(filtered.contains(&0x80002109));
        assert!(!filtered.contains(&0xDEAD_BEEF));
        assert_eq!(filtered.len(), 4);
    }

    #[test]
    #[cfg_attr(miri, ignore = "exercises real filesystem I/O, unsupported under miri isolation")]
    fn include_relative_paths_resolves_and_merges() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendors");
        std::fs::create_dir(&vendor_dir).unwrap();

        let included_path = vendor_dir.join("test-vendor.toml");
        let mut f = std::fs::File::create(&included_path).unwrap();
        write!(
            f,
            r#"
            parameterless = [0x80FF0001]

            [[params]]
            shape = "gcm"
            mechanisms = [0x80001087]
        "#
        )
        .unwrap();

        let main_path = dir.path().join("mechanisms.toml");
        let mut f = std::fs::File::create(&main_path).unwrap();
        write!(
            f,
            r#"
            include = ["vendors/test-vendor.toml"]

            [[params]]
            shape = "iv"
            mechanisms = [0x80002109]
        "#
        )
        .unwrap();

        let reg = MechanismRegistry::load(Some(&main_path)).unwrap();

        // From included file:
        assert_eq!(reg.param_shape(0x80001087), Some("gcm"));
        assert!(reg.is_parameterless(0x80FF0001));

        // From main override:
        assert_eq!(reg.param_shape(0x80002109), Some("iv"));

        // From embedded default:
        assert_eq!(reg.param_shape(CKM_AES_GCM), Some("gcm"));
        assert!(reg.is_parameterless(CKM_RSA_PKCS));
    }

    #[test]
    #[cfg_attr(miri, ignore = "exercises real filesystem I/O, unsupported under miri isolation")]
    fn include_absolute_path_works() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();

        let included_path = dir.path().join("vendor-abs.toml");
        let mut f = std::fs::File::create(&included_path).unwrap();
        write!(
            f,
            r#"
            parameterless = [0x80EE0001]
        "#
        )
        .unwrap();

        let main_path = dir.path().join("mechanisms.toml");
        let mut f = std::fs::File::create(&main_path).unwrap();
        write!(f, r#"include = ["{}"]"#, included_path.display()).unwrap();

        let reg = MechanismRegistry::load(Some(&main_path)).unwrap();
        assert!(reg.is_parameterless(0x80EE0001));
    }

    #[test]
    #[cfg_attr(miri, ignore = "exercises real filesystem I/O, unsupported under miri isolation")]
    fn include_missing_file_returns_error() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let main_path = dir.path().join("mechanisms.toml");
        let mut f = std::fs::File::create(&main_path).unwrap();
        write!(f, r#"include = ["nonexistent/vendor.toml"]"#).unwrap();

        let result = MechanismRegistry::load(Some(&main_path));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("nonexistent/vendor.toml"),
            "error should mention the missing file: {err}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "exercises real filesystem I/O, unsupported under miri isolation")]
    fn include_merge_order_later_overrides_earlier() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();

        let first_path = dir.path().join("first.toml");
        let mut f = std::fs::File::create(&first_path).unwrap();
        write!(
            f,
            r#"
            [[params]]
            shape = "first"
            mechanisms = [0x800000AA]
        "#
        )
        .unwrap();

        let second_path = dir.path().join("second.toml");
        let mut f = std::fs::File::create(&second_path).unwrap();
        write!(
            f,
            r#"
            [[params]]
            shape = "second"
            mechanisms = [0x800000AA]
        "#
        )
        .unwrap();

        let main_path = dir.path().join("mechanisms.toml");
        let mut f = std::fs::File::create(&main_path).unwrap();
        write!(f, r#"include = ["first.toml", "second.toml"]"#).unwrap();

        let reg = MechanismRegistry::load(Some(&main_path)).unwrap();
        assert_eq!(reg.param_shape(0x800000AA), Some("second"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "exercises real filesystem I/O, unsupported under miri isolation")]
    fn local_entries_override_includes() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();

        let included_path = dir.path().join("vendor.toml");
        let mut f = std::fs::File::create(&included_path).unwrap();
        write!(
            f,
            r#"
            [[params]]
            shape = "from_include"
            mechanisms = [0x800000BB]
        "#
        )
        .unwrap();

        let main_path = dir.path().join("mechanisms.toml");
        let mut f = std::fs::File::create(&main_path).unwrap();
        write!(
            f,
            r#"
            include = ["vendor.toml"]

            [[params]]
            shape = "local_override"
            mechanisms = [0x800000BB]
        "#
        )
        .unwrap();

        let reg = MechanismRegistry::load(Some(&main_path)).unwrap();
        assert_eq!(reg.param_shape(0x800000BB), Some("local_override"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "exercises real filesystem I/O, unsupported under miri isolation")]
    fn empty_include_is_noop() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let main_path = dir.path().join("mechanisms.toml");
        let mut f = std::fs::File::create(&main_path).unwrap();
        write!(
            f,
            r#"
            include = []

            parameterless = [0x80DD0001]
        "#
        )
        .unwrap();

        let reg = MechanismRegistry::load(Some(&main_path)).unwrap();
        assert!(reg.is_parameterless(0x80DD0001));
        assert!(reg.is_parameterless(CKM_RSA_PKCS));
    }

    #[test]
    #[cfg_attr(miri, ignore = "exercises real filesystem I/O, unsupported under miri isolation")]
    fn include_in_included_file_is_ignored() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();

        let grandchild_path = dir.path().join("grandchild.toml");
        let mut f = std::fs::File::create(&grandchild_path).unwrap();
        write!(f, r#"parameterless = [0x80CC0099]"#).unwrap();

        let child_path = dir.path().join("child.toml");
        let mut f = std::fs::File::create(&child_path).unwrap();
        write!(
            f,
            r#"
            include = ["grandchild.toml"]
            parameterless = [0x80CC0001]
        "#
        )
        .unwrap();

        let main_path = dir.path().join("mechanisms.toml");
        let mut f = std::fs::File::create(&main_path).unwrap();
        write!(f, r#"include = ["child.toml"]"#).unwrap();

        let reg = MechanismRegistry::load(Some(&main_path)).unwrap();
        assert!(reg.is_parameterless(0x80CC0001));
        assert!(!reg.is_parameterless(0x80CC0099));
    }

    #[test]
    #[cfg_attr(miri, ignore = "exercises real filesystem I/O, unsupported under miri isolation")]
    fn multiple_includes_compose_parameterless_and_shapes() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();

        let v1_path = dir.path().join("vendor1.toml");
        let mut f = std::fs::File::create(&v1_path).unwrap();
        write!(
            f,
            r#"
            parameterless = [0x80A00001]

            [[params]]
            shape = "gcm"
            mechanisms = [0x80A00002]
        "#
        )
        .unwrap();

        let v2_path = dir.path().join("vendor2.toml");
        let mut f = std::fs::File::create(&v2_path).unwrap();
        write!(
            f,
            r#"
            parameterless = [0x80B00001]

            [[params]]
            shape = "iv"
            mechanisms = [0x80B00002]
        "#
        )
        .unwrap();

        let main_path = dir.path().join("mechanisms.toml");
        let mut f = std::fs::File::create(&main_path).unwrap();
        write!(f, r#"include = ["vendor1.toml", "vendor2.toml"]"#).unwrap();

        let reg = MechanismRegistry::load(Some(&main_path)).unwrap();

        assert!(reg.is_parameterless(0x80A00001));
        assert!(reg.is_parameterless(0x80B00001));

        assert_eq!(reg.param_shape(0x80A00002), Some("gcm"));
        assert_eq!(reg.param_shape(0x80B00002), Some("iv"));

        assert!(reg.is_parameterless(CKM_RSA_PKCS));
        assert_eq!(reg.param_shape(CKM_AES_GCM), Some("gcm"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "exercises real filesystem I/O, unsupported under miri isolation")]
    fn include_toml_parse_error_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "this is not valid {{{").unwrap();
        let main_path = dir.path().join("mechanisms.toml");
        std::fs::write(&main_path, r#"include = ["bad.toml"]"#).unwrap();
        let result = MechanismRegistry::load(Some(&main_path));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("bad.toml"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "exercises real filesystem I/O, unsupported under miri isolation")]
    fn cloudhsm_vendor_overlay_via_include() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();

        // Write the real CloudHSM overlay content.
        let vendor_path = dir.path().join("aws-cloudhsm.toml");
        let mut f = std::fs::File::create(&vendor_path).unwrap();
        write!(
            f,
            r#"
            # CKM_CLOUDHSM_AES_GCM
            [[params]]
            shape = "gcm"
            mechanisms = [0x80001087]

            # CloudHSM AES key wrap variants
            [[params]]
            shape = "iv"
            mechanisms = [0x80002109, 0x8000210A, 0x8000216F]

            # CKM_CLOUDHSM_SP800_108_COUNTER_KDF
            [[params]]
            shape = "sp800_108_kdf"
            mechanisms = [0x80000001]
        "#
        )
        .unwrap();

        // Main config includes the CloudHSM overlay.
        let main_path = dir.path().join("mechanisms.toml");
        let mut f = std::fs::File::create(&main_path).unwrap();
        write!(
            f,
            r#"
            include = ["aws-cloudhsm.toml"]
            discovery_mode = "filtered"
        "#
        )
        .unwrap();

        let reg = MechanismRegistry::load(Some(&main_path)).unwrap();

        // CloudHSM mechanisms should be present.
        assert_eq!(reg.param_shape(0x80001087), Some("gcm"));
        assert_eq!(reg.param_shape(0x80002109), Some("iv"));
        assert_eq!(reg.param_shape(0x8000210A), Some("iv"));
        assert_eq!(reg.param_shape(0x8000216F), Some("iv"));
        assert_eq!(reg.param_shape(0x80000001), Some("sp800_108_kdf"));

        // Filtered mode should include these vendor mechanisms.
        let backend = vec![CKM_AES_GCM, CKM_RSA_PKCS, 0x80001087, 0x80000001, 0xDEAD_BEEF];
        let filtered = reg.filter_mechanisms(&backend);
        assert!(filtered.contains(&0x80001087));
        assert!(filtered.contains(&0x80000001));
        assert!(!filtered.contains(&0xDEAD_BEEF));
    }

    /// Wave 3 F2/D1: previously unmapped mechanisms whose calls fail-closed
    /// with CKR_MECHANISM_PARAM_INVALID before reaching the backend.
    #[test]
    fn wave3_f2_coverage_gaps_are_mapped() {
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();

        // Single-DES OFB/CFB take a fixed 8-byte IV.
        for mech in [
            0x0150, // CKM_DES_OFB64
            0x0151, // CKM_DES_OFB8
            0x0152, // CKM_DES_CFB64
            0x0153, // CKM_DES_CFB8
        ] {
            assert_eq!(reg.param_shape(mech), Some("iv"), "mechanism {mech:#06x}");
            assert!(reg.check_operation(mech, true).is_ok());
        }

        // Pre-master keygen takes a 2-byte CK_VERSION (opaque bytes).
        for mech in [
            0x0370, // CKM_SSL3_PRE_MASTER_KEY_GEN
            0x0374, // CKM_TLS_PRE_MASTER_KEY_GEN
        ] {
            assert_eq!(reg.param_shape(mech), Some("iv"), "mechanism {mech:#06x}");
            assert!(reg.check_operation(mech, true).is_ok());
            // Dual-listed: the no-param call stays parameterless-legal.
            assert!(reg.is_parameterless(mech));
        }

        // SSL3 MACs take a CK_ULONG length; TLS master-key derive reuses
        // the SSL3 RandomInfo struct.
        for mech in [
            0x0380, // CKM_SSL3_MD5_MAC
            0x0381, // CKM_SSL3_SHA1_MAC
        ] {
            assert_eq!(reg.param_shape(mech), Some("mac_general"), "mechanism {mech:#06x}");
            assert!(reg.check_operation(mech, true).is_ok());
            assert!(reg.is_parameterless(mech));
        }
        assert_eq!(reg.param_shape(0x0375), Some("ssl3_master_key_derive")); // TLS_MASTER_KEY_DERIVE
        assert!(reg.check_operation(0x0375, true).is_ok());

        // ECB_ENCRYPT_DATA takes CK_KEY_DERIVATION_STRING_DATA.
        for mech in [
            0x0556, // CKM_CAMELLIA_ECB_ENCRYPT_DATA
            0x0566, // CKM_ARIA_ECB_ENCRYPT_DATA
            0x0656, // CKM_SEED_ECB_ENCRYPT_DATA
        ] {
            assert_eq!(reg.param_shape(mech), Some("key_derivation_string"));
            assert!(reg.check_operation(mech, true).is_ok());
        }
    }

    /// Wave 3 §7.3: AES-CCM and ChaCha20-Poly1305 resolve to
    /// message-capable shapes, so the message path binds the
    /// CK_CCM_MESSAGE_PARAMS / CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS
    /// structs for them.
    #[test]
    fn message_capable_aead_shapes_resolve() {
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();
        assert_eq!(reg.param_shape(0x1087), Some("gcm")); // CKM_AES_GCM
        assert_eq!(reg.param_shape(0x1088), Some("ccm")); // CKM_AES_CCM
        assert_eq!(reg.param_shape(0x4021), Some("salsa20_chacha20_poly1305")); // CHACHA20_POLY1305
        assert_eq!(reg.param_shape(0x4022), Some("salsa20_chacha20_poly1305")); // SALSA20_POLY1305
    }

    /// Wave 3 F2/D1: the shipped BouncyHSM/opencryptoki vendor overlays
    /// (examples/vendors/) merge onto the default registry. The shipped
    /// files are read via `include_str!` so overlay drift or breakage
    /// fails this test (Wave 3.5 smalls review Finding 4).
    #[test]
    fn wave3_f2_vendor_overlays_merge() {
        let blake2b_toml = include_str!("../../../examples/vendors/bouncyhsm-blake2b.toml");
        let ecdh_toml = include_str!("../../../examples/vendors/opencryptoki-ecdh-x-cof.toml");

        // Each overlay merges onto the defaults on its own...
        for (overlay, shape, mechs) in [
            (blake2b_toml, "mac_general", vec![0x400Eu64, 0x4013, 0x4018, 0x401D]),
            (ecdh_toml, "ecdh_aes_key_wrap", vec![0x4038u64, 0x4039]),
        ] {
            let reg = MechanismRegistry::load_with_override_str(Some(overlay)).unwrap();
            for mech in mechs {
                assert_eq!(reg.param_shape(mech), Some(shape), "mechanism {mech:#06x}");
                assert!(reg.check_operation(mech, true).is_ok());
            }
            // ...additively: defaults are untouched.
            assert_eq!(reg.param_shape(CKM_AES_GCM), Some("gcm"));
            assert!(reg.is_parameterless(CKM_RSA_PKCS));
        }

        // ...and neither overlay is in the defaults (operator opt-in).
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();
        for mech in [0x400Eu64, 0x4013, 0x4018, 0x401D, 0x4038, 0x4039] {
            assert_eq!(reg.param_shape(mech), None, "mechanism {mech:#06x} must stay opt-in");
            assert_eq!(reg.check_operation(mech, true), Err(CkRv::MECHANISM_PARAM_INVALID));
        }
    }
}
