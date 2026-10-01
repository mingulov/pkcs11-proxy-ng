//! Machine-checkable mechanism-parameter manifest (S2 §8) + Phase-2 gate (S2 §11).
//!
//! S2 §8 prose is NOT the compatibility contract — this manifest is. One entry
//! per compiled classic shape ([`SHAPE_DESCRIPTORS`](crate::shape_descriptors::SHAPE_DESCRIPTORS)):
//! shape ID, operation contexts, forms, per-ABI layouts (native size, first
//! unsafe offset, layout fingerprint), virtual-handle presence, output fields,
//! minimum transport version, wire-message binding, and completion status.
//!
//! Format choice (R8 implementer decision): a **checked-in generated TOML file**
//! ([`MANIFEST_TOML`], `mechanism_param_manifest.toml`) plus a generator
//! ([`render_manifest`]) and a byte-exact generator test — option (b) from the
//! R8 brief. Rationale: any descriptor change that alters the contract forces
//! a regeneration whose diff is reviewable item-by-item against S2 §8, while a
//! pure-Rust derived table would absorb the same change silently (no diff to
//! review). The TOML is a snapshot, not an independent authority: it is
//! generated from the compiled tables, verified byte-exact by test, and the
//! single human edit point is [`SHAPE_BINDINGS`] below (wire messages, output
//! fields, completion status). This keeps the "TOML binding alone never
//! authorizes" rule intact: the manifest TOML cannot add, remove, or alter a
//! shape — the byte-exact test fails unless it matches regeneration from the
//! compiled descriptors plus the reviewed bindings.
//!
//! The manifest is live, not decorative: [`manifest_complete`] — the machine
//! half of the S2 §11 Phase-2 gate — reads the embedded TOML. R21 flipped
//! the tail bindings to complete (plus regeneration) once the Phase-3 rows
//! landed; R23 asserts [`manifest_complete`] at advertisement time and
//! refuses to advertise v1 while it is false. The predicate is pinned true
//! (`r21_manifest_complete_after_phase3`) and the manifest bytes are pinned
//! by the freeze digest (`r21_manifest_digest_freeze`).
//!
//! The manifest ↔ proto cross-check lives in this crate (not in `proto`)
//! because the dependency runs `proto → types`: `types` cannot name the
//! generated wire types, so the tests match wire-message names against the
//! `.proto` sources via `include_str!` (same repository — standalone-safe).
//! Presence-field coverage is COMPLETE since R21: every manifest shape
//! carries its wire envelope + domain conversion + shim reader + backend
//! reconstruction (cross-crate Nelson checks in `manifest_tests`).
//!
//! No behavior change: this module is unwired tables + tests (R8 is Phase 1).

use std::sync::OnceLock;

use serde::Deserialize;

use self::ManifestStatus::Complete;
use crate::shape_descriptors::{Operation, OuterKind, ParamAbi, ResolvedShape, ShapeResolver};

// ─── Human-attested bindings (single edit point) ──────────────────────────────

/// Completion status of one manifest entry.
///
/// R21 flipped every [`ManifestStatus::PendingTail`] to
/// [`ManifestStatus::Complete`] (plus TOML regeneration) once the Phase-3
/// tail rows landed; only then could [`manifest_complete`] return true.
/// The `PendingTail` variant is retained for wire-format history (old
/// TOML snapshots still parse) — no live entry carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum ManifestStatus {
    /// Wire envelope + transport representation complete for v1.
    #[serde(rename = "complete")]
    Complete,
    /// Output/nested tail envelope pending (lands R16–R20, asserted in R21).
    #[serde(rename = "pending-tail")]
    PendingTail,
}

impl ManifestStatus {
    /// TOML rendering of the status.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::PendingTail => "pending-tail",
        }
    }
}

/// Reviewed per-shape facts the descriptors do not carry: wire-message
/// binding, output-field indices, completion status, minimum transport
/// version. Everything else in the manifest (operations, forms, layouts,
/// handles) is derived from [`SHAPE_DESCRIPTORS`](crate::shape_descriptors::SHAPE_DESCRIPTORS)
/// by [`render_manifest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShapeBinding {
    /// Shape name (the compiled descriptor key).
    pub shape: &'static str,
    /// Proto message names covering the shape's forms (empty only for the
    /// `parameterless` marker, which rides the unset `params` oneof).
    pub wire_messages: &'static [&'static str],
    /// Completion status (the R21 flip target).
    pub status: ManifestStatus,
    /// Top-level field indices the provider may write (tail only; every
    /// index is `Pointer`-class in every form — test-enforced).
    pub output_fields: &'static [u8],
    /// Minimum `parameter_encoding_version` carrying this shape (1 = v1 for
    /// every entry; tail gating is by status, not version).
    pub min_transport_version: u32,
}

/// Transport version 1 (R6 v1 envelopes): the minimum version every
/// manifest entry carries today; tail gating is by status, not version.
const V1: u32 = 1;

/// Row constructor: one line per shape (the 68 rows below).
const fn bind(
    shape: &'static str,
    wire_messages: &'static [&'static str],
    status: ManifestStatus,
    output_fields: &'static [u8],
    min_transport_version: u32,
) -> ShapeBinding {
    ShapeBinding { shape, wire_messages, status, output_fields, min_transport_version }
}

/// Reviewed bindings for all 68 compiled shapes, sorted by shape name (same
/// order as `SHAPE_DESCRIPTORS`). Group comments cite the S2 §8 family each
/// row belongs to; the family-coverage test pins this mapping exactly.
pub const SHAPE_BINDINGS: &[ShapeBinding] = &[
    // S2 §8 "AES/DES/ARIA/Camellia/SEED CBC-encrypt-data" (+ CTR cousins).
    bind("aes_cbc_encrypt_data", &["AesCbcEncryptDataParams"], Complete, &[], V1),
    bind("aes_ctr", &["AesCtrParams"], Complete, &[], V1),
    bind("aria_cbc_encrypt_data", &["AriaCbcEncryptDataParams"], Complete, &[], V1),
    bind("camellia_cbc_encrypt_data", &["CamelliaCbcEncryptDataParams"], Complete, &[], V1),
    bind("camellia_ctr", &["CamelliaCtrParams"], Complete, &[], V1),
    // S2 §8 "GCM/CCM/wrap".
    bind("ccm", &["CcmParams"], Complete, &[], V1),
    bind("ccm_wrap", &["CcmWrapParams"], Complete, &[], V1),
    // S2 §8 "ChaCha20".
    bind("chacha20", &["ChaCha20Params"], Complete, &[], V1),
    bind("des_cbc_encrypt_data", &["DesCbcEncryptDataParams"], Complete, &[], V1),
    // S2 §8 "ECDH1/2".
    bind("ecdh1_derive", &["Ecdh1DeriveParams"], Complete, &[], V1),
    bind("ecdh2_derive", &["Ecdh2DeriveParams"], Complete, &[], V1),
    // S2 §8 "RSA-AES-wrap nesting" (ECDH cousin rides the same family).
    bind("ecdh_aes_key_wrap", &["EcdhAesKeyWrapParams"], Complete, &[], V1),
    // S2 §8 "ECMQV".
    bind("ecmqv_derive", &["EcmqvDeriveParams"], Complete, &[], V1),
    // S2 §8 "EdDSA".
    bind("eddsa", &["EddsaParams"], Complete, &[], V1),
    bind("extract", &["ExtractParams"], Complete, &[], V1),
    // S2 §8 "GCM/CCM/wrap" (cont.): `gcm_compat` binds both typed messages.
    bind("gcm", &["GcmParams"], Complete, &[], V1),
    bind("gcm_compat", &["IvParams", "GcmParams"], Complete, &[], V1),
    bind("gcm_wrap", &["GcmWrapParams"], Complete, &[], V1),
    // S2 §8 "GOST derive/wrap".
    bind("gostr3410_derive", &["Gostr3410DeriveParams"], Complete, &[], V1),
    bind("gostr3410_key_wrap", &["Gostr3410KeyWrapParams"], Complete, &[], V1),
    // S2 §8 "HKDF".
    bind("hkdf", &["HkdfParams"], Complete, &[], V1),
    // S2 §8 "IKE v1/v2".
    bind("ike1_extended_derive", &["Ike1ExtendedDeriveParams"], Complete, &[], V1),
    bind("ike1_prf_derive", &["Ike1PrfDeriveParams"], Complete, &[], V1),
    bind("ike2_prf_plus_derive", &["Ike2PrfPlusDeriveParams"], Complete, &[], V1),
    bind("ike_prf_derive", &["IkePrfDeriveParams"], Complete, &[], V1),
    bind("iv", &["IvParams"], Complete, &[], V1),
    // S2 §8 "KEA" (tail: RandomA/RandomB role-dependent in/out).
    bind("kea_derive", &["KeaDeriveParams"], Complete, &[2, 3], V1),
    // S2 §8 "KDF string-data".
    bind("key_derivation_string", &["KeyDerivationStringData"], Complete, &[], V1),
    // S2 §8 "OAEP" (SET cousin rides the same family).
    bind("key_wrap_set_oaep", &["KeyWrapSetOaepParams"], Complete, &[], V1),
    // S2 §8 "KIP" (tail: nested mechanism; input-only fields).
    bind("kip", &["KipParams"], Complete, &[], V1),
    // S2 §8 "KMAC".
    bind("kmac", &["KmacParams"], Complete, &[], V1),
    bind("mac_general", &["MacGeneralParams"], Complete, &[], V1),
    bind("mu_gen", &["MuGenParams"], Complete, &[], V1),
    bind("object_handle", &["ObjectHandleParam"], Complete, &[], V1),
    // S2 §8 "OTP/SP800-108" (tail: counted struct array; input-only).
    bind("otp", &["OtpParams"], Complete, &[], V1),
    // The parameterless marker rides the unset oneof: no wire message.
    bind("parameterless", &[], Complete, &[], V1),
    // S2 §8 "PBE".
    bind("pbe", &["PbeParams"], Complete, &[], V1),
    // S2 §8 "PBKDF2".
    bind("pkcs5_pbkd2", &["Pkcs5Pbkd2Params"], Complete, &[], V1),
    bind("rc2_cbc", &["Rc2CbcParams"], Complete, &[], V1),
    bind("rc2_mac_general", &["Rc2MacGeneralParams"], Complete, &[], V1),
    // S2 §8 "RC5".
    bind("rc5", &["Rc5Params"], Complete, &[], V1),
    bind("rc5_cbc", &["Rc5CbcParams"], Complete, &[], V1),
    bind("rc5_mac_general", &["Rc5MacGeneralParams"], Complete, &[], V1),
    // S2 §8 "RSA-AES-wrap nesting" (nested OAEP past the safe prefix).
    bind("rsa_aes_key_wrap", &["RsaAesKeyWrapParams"], Complete, &[], V1),
    // S2 §8 "OAEP" (cont.) and "PSS-flat".
    bind("rsa_oaep", &["RsaPkcsOaepParams"], Complete, &[], V1),
    bind("rsa_pss", &["RsaPkcsPssParams"], Complete, &[], V1),
    // S2 §8 "Salsa20" and "AEAD".
    bind("salsa20", &["Salsa20Params"], Complete, &[], V1),
    bind("salsa20_chacha20_poly1305", &["Salsa20ChaCha20Poly1305Params"], Complete, &[], V1),
    bind("seed_cbc_encrypt_data", &["SeedCbcEncryptDataParams"], Complete, &[], V1),
    // One wire message covers both forms (`hash` selects the variant).
    bind("sign_additional_context", &["SignAdditionalContext"], Complete, &[], V1),
    // S2 §8 "Skipjack" (tail: counted/length-led inputs; input-only).
    bind("skipjack_private_wrap", &["SkipjackPrivateWrapParams"], Complete, &[], V1),
    bind("skipjack_relayx", &["SkipjackRelayxParams"], Complete, &[], V1),
    // S2 §8 "OTP/SP800-108" (tail: output = additional-derived-keys array).
    bind("sp800_108_feedback_kdf", &["Sp800108FeedbackKdfParams"], Complete, &[6], V1),
    bind("sp800_108_kdf", &["Sp800108KdfParams"], Complete, &[4], V1),
    // S2 §8 "key-mat" (tail: output = returned key material).
    bind("ssl3_key_mat", &["Ssl3KeyMatParams"], Complete, &[5], V1),
    // S2 §8 TLS-input shapes (Flat-covered: no output fields).
    bind("ssl3_master_key_derive", &["Ssl3MasterKeyDeriveParams"], Complete, &[], V1),
    bind(
        "tls12_extended_master_key_derive",
        &["Tls12ExtendedMasterKeyDeriveParams"],
        Complete,
        &[],
        V1,
    ),
    bind("tls12_master_key_derive", &["Tls12MasterKeyDeriveParams"], Complete, &[], V1),
    bind("tls_kdf", &["TlsKdfParams"], Complete, &[], V1),
    bind("tls_mac", &["TlsMacParams"], Complete, &[], V1),
    // S2 §8 "TLS/WTLS envelopes" (tail: output = pOutput + length pointer).
    bind("tls_prf", &["TlsPrfParams"], Complete, &[4, 5], V1),
    bind("wtls_key_mat", &["WtlsKeyMatParams"], Complete, &[7], V1),
    bind("wtls_master_key_derive", &["WtlsMasterKeyDeriveParams"], Complete, &[], V1),
    bind("wtls_prf", &["WtlsPrfParams"], Complete, &[5, 6], V1),
    // S2 §8 "X9.42 DH/MQV".
    bind("x942_dh1_derive", &["X942Dh1DeriveParams"], Complete, &[], V1),
    bind("x942_dh2_derive", &["X942Dh2DeriveParams"], Complete, &[], V1),
    bind("x942_mqv_derive", &["X942MqvDeriveParams"], Complete, &[], V1),
    // S2 §8 "EdDSA" (XEdDSA cousin rides the same family).
    bind("xeddsa", &["XeddsaParams"], Complete, &[], V1),
];

// ─── Checked-in artifact + schema ────────────────────────────────────────────

/// The checked-in generated manifest (S2 §8 contract snapshot). Lives under
/// `src/` so the crate's `include` packaging keeps standalone builds working,
/// mirroring `mechanism_params_default.toml`.
pub const MANIFEST_TOML: &str = include_str!("mechanism_param_manifest.toml");

/// Manifest schema version (bumped only by a manifest-format change, which
/// R21's freeze then treats as a contract change).
pub const MANIFEST_VERSION: u32 = 1;

/// Parsed manifest file: schema version + one entry per compiled shape.
#[derive(Debug, Clone, Deserialize)]
pub struct ManifestFile {
    /// [`MANIFEST_VERSION`] the file was generated with.
    pub manifest_version: u32,
    /// Shape entries (absent in the empty RED skeleton only).
    #[serde(default)]
    pub shape: Vec<ManifestShape>,
}

/// One checked-in manifest entry (S2 §8 row).
#[derive(Debug, Clone, Deserialize)]
pub struct ManifestShape {
    /// Shape ID (compiled descriptor key).
    pub name: String,
    /// Outer kind of the primary form (`PointerStruct`, …).
    pub outer_kind: String,
    /// Operation contexts (`General`, `WrapKey`).
    pub operations: Vec<String>,
    /// Whether the primary form embeds a virtual handle.
    pub virtual_handle: bool,
    /// Minimum `parameter_encoding_version` carrying this shape.
    pub min_transport_version: u32,
    /// Completion status (the R21 flip target).
    pub status: ManifestStatus,
    /// Proto message names covering the shape's forms.
    pub wire_messages: Vec<String>,
    /// Top-level field indices the provider may write (tail only).
    pub output_fields: Vec<u8>,
    /// Primary form first, then length-selected alternates.
    pub form: Vec<ManifestForm>,
}

/// One form's per-ABI layouts. Bare (parameterless/byte-buffer) forms carry
/// no size/offset and the ABI-exempt fingerprint.
#[derive(Debug, Clone, Deserialize)]
pub struct ManifestForm {
    /// Form name (empty for primary forms).
    pub name: String,
    /// Outer kind of this form.
    pub outer_kind: String,
    /// Native struct size on LP64 / ILP32 / LLP64-pack1 (`None` when bare).
    pub lp64_size: Option<usize>,
    /// First unsafe offset on LP64 (`None` when bare or fully scalar-safe).
    pub lp64_first_unsafe: Option<usize>,
    /// Expected wire fingerprint on LP64 (`0x…` hex).
    pub lp64_fingerprint: String,
    /// Native struct size on ILP32 (`None` when bare).
    pub ilp32_size: Option<usize>,
    /// First unsafe offset on ILP32.
    pub ilp32_first_unsafe: Option<usize>,
    /// Expected wire fingerprint on ILP32 (`0x…` hex).
    pub ilp32_fingerprint: String,
    /// Native struct size on LLP64-pack1 (`None` when bare).
    pub llp64_size: Option<usize>,
    /// First unsafe offset on LLP64-pack1.
    pub llp64_first_unsafe: Option<usize>,
    /// Expected wire fingerprint on LLP64-pack1 (`0x…` hex).
    pub llp64_fingerprint: String,
}

// ─── Loader + Phase-2 gate predicate ─────────────────────────────────────────

/// Parse-once access to the embedded checked-in manifest.
pub fn manifest() -> &'static ManifestFile {
    static CELL: OnceLock<ManifestFile> = OnceLock::new();
    CELL.get_or_init(|| {
        toml::from_str(MANIFEST_TOML).expect("checked-in manifest parses (pinned by tests)")
    })
}

/// Look up one checked-in manifest entry by shape name.
pub fn manifest_shape(name: &str) -> Option<&'static ManifestShape> {
    manifest().shape.iter().find(|entry| entry.name == name)
}

/// Machine half of the S2 §11 Phase-2 gate: true only when every manifest
/// entry is complete. R21 flipped this to true (tail rows complete); R23
/// asserts it at advertisement time and refuses v1 while it is false.
/// Pinned true (`r21_manifest_complete_after_phase3`).
pub fn manifest_complete() -> bool {
    // Fail closed on an empty manifest: `all()` is vacuously true.
    !manifest().shape.is_empty()
        && manifest().shape.iter().all(|entry| entry.status == ManifestStatus::Complete)
}

/// Shape IDs still pending (empty since R21 completed the tail), in
/// manifest order.
pub fn pending_shapes() -> Vec<&'static str> {
    manifest()
        .shape
        .iter()
        .filter(|entry| entry.status != ManifestStatus::Complete)
        .map(|entry| entry.name.as_str())
        .collect()
}

// ─── Generator ───────────────────────────────────────────────────────────────

/// v1 ABI set rendered per form, in fixed order.
const RENDER_ABIS: &[(&str, ParamAbi)] = &[
    ("lp64", ParamAbi::Lp64NativeLe),
    ("ilp32", ParamAbi::Ilp32NativeLe),
    ("llp64", ParamAbi::Llp64Packed1Le),
];

fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::General => "General",
        Operation::WrapKey => "WrapKey",
    }
}

fn outer_kind_name(kind: OuterKind) -> &'static str {
    match kind {
        OuterKind::Parameterless => "Parameterless",
        OuterKind::ByteBuffer => "ByteBuffer",
        OuterKind::ScalarStruct => "ScalarStruct",
        OuterKind::PointerStruct => "PointerStruct",
        OuterKind::NestedOrOutput => "NestedOrOutput",
    }
}

fn render_str_list(values: &[&str]) -> String {
    let mut rendered = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            rendered.push_str(", ");
        }
        rendered.push('"');
        rendered.push_str(value);
        rendered.push('"');
    }
    rendered.push(']');
    rendered
}

fn render_u8_list(values: &[u8]) -> String {
    let mut rendered = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            rendered.push_str(", ");
        }
        rendered.push_str(&value.to_string());
    }
    rendered.push(']');
    rendered
}

/// Regenerate the manifest TOML text from the compiled descriptors plus
/// [`SHAPE_BINDINGS`]. Deterministic: fixed binding order, fixed ABI order,
/// fixed key order. The generator test pins the checked-in file byte-exact
/// against this output.
pub fn render_manifest() -> String {
    let mut rendered = String::from(
        "# GENERATED — do not edit by hand.\n\
         # Contract: S2 §8 machine-checkable manifest; gates Phase 2 (S2 §11).\n\
         # Source: SHAPE_DESCRIPTORS (shape_descriptors.rs) + SHAPE_BINDINGS (this module).\n\
         # Regenerate with: UPDATE_MANIFEST=1 cargo test -p pkcs11-proxy-ng-types manifest\n\
         # Any diff to this file is a contract change: review it against S2 §8.\n",
    );
    rendered.push_str(&format!("manifest_version = {MANIFEST_VERSION}\n"));
    for binding in SHAPE_BINDINGS {
        let descriptor = ShapeResolver::descriptor(binding.shape).unwrap_or_else(|| {
            panic!("manifest binding references unknown shape `{}`", binding.shape)
        });
        let operations: Vec<&str> =
            descriptor.operations.iter().map(|op| operation_name(*op)).collect();
        rendered.push_str("\n[[shape]]\n");
        rendered.push_str(&format!("name = \"{}\"\n", binding.shape));
        rendered
            .push_str(&format!("outer_kind = \"{}\"\n", outer_kind_name(descriptor.outer_kind)));
        rendered.push_str(&format!("operations = {}\n", render_str_list(&operations)));
        rendered.push_str(&format!("virtual_handle = {}\n", descriptor.contains_virtual_handle));
        rendered.push_str(&format!("min_transport_version = {}\n", binding.min_transport_version));
        rendered.push_str(&format!("status = \"{}\"\n", binding.status.as_str()));
        rendered.push_str(&format!("wire_messages = {}\n", render_str_list(binding.wire_messages)));
        rendered.push_str(&format!("output_fields = {}\n", render_u8_list(binding.output_fields)));
        let mut forms = Vec::with_capacity(1 + descriptor.alternate_forms.len());
        forms.push(ResolvedShape::primary(descriptor));
        for alternate in descriptor.alternate_forms {
            forms.push(ResolvedShape { descriptor, alternate: Some(alternate) });
        }
        for resolved in forms {
            rendered.push_str("\n[[shape.form]]\n");
            rendered.push_str(&format!("name = \"{}\"\n", resolved.form_name()));
            rendered.push_str(&format!(
                "outer_kind = \"{}\"\n",
                outer_kind_name(resolved.outer_kind())
            ));
            for (key, abi) in RENDER_ABIS {
                if let Some(size) = resolved.native_size(*abi) {
                    rendered.push_str(&format!("{key}_size = {size}\n"));
                }
                if let Some(offset) = resolved.first_unsafe_offset(*abi) {
                    rendered.push_str(&format!("{key}_first_unsafe = {offset}\n"));
                }
                rendered.push_str(&format!(
                    "{key}_fingerprint = \"0x{:016x}\"\n",
                    resolved.fingerprint(*abi)
                ));
            }
        }
    }
    rendered
}

#[cfg(test)]
mod manifest_tests {
    use std::collections::BTreeSet;

    use super::{MANIFEST_VERSION, ManifestForm, ManifestStatus, outer_kind_name};
    use crate::shape_descriptors::{
        FieldClass, OuterKind, ResolvedShape, SHAPE_DESCRIPTORS, ShapeResolver,
        VENDOR_FLAT_ALLOWLIST,
    };

    // Sibling-crate `.proto` sources (`types` cannot depend on `proto`;
    // matching names against the sources keeps the check in-crate and
    // standalone-safe).
    const MECHANISM_PARAMS_PROTO: &str =
        include_str!("../../proto/proto/pkcs11-proxy-ng/v1/mechanism_params.proto");
    const TYPES_PROTO: &str = include_str!("../../proto/proto/pkcs11-proxy-ng/v1/types.proto");

    /// Whether `message {name} {` is defined in either `.proto` file.
    fn message_defined(name: &str) -> bool {
        [MECHANISM_PARAMS_PROTO, TYPES_PROTO].iter().any(|source| {
            source.lines().any(|line| {
                let line = line.trim_start();
                line.starts_with(&format!("message {name} "))
                    || line.starts_with(&format!("message {name}{{"))
            })
        })
    }

    /// Whether `{name}` appears as a `Mechanism.params` oneof member type.
    fn oneof_member(name: &str) -> bool {
        TYPES_PROTO.lines().any(|line| {
            let line = line.trim_start();
            line.starts_with(&format!("{name} ")) && line.contains('=')
        })
    }

    /// `(size, first_unsafe, fingerprint)` for one ABI key of a TOML form.
    fn toml_layout<'a>(
        form: &'a ManifestForm,
        key: &str,
    ) -> (Option<usize>, Option<usize>, &'a str) {
        match key {
            "lp64" => (form.lp64_size, form.lp64_first_unsafe, form.lp64_fingerprint.as_str()),
            "ilp32" => (form.ilp32_size, form.ilp32_first_unsafe, form.ilp32_fingerprint.as_str()),
            _ => (form.llp64_size, form.llp64_first_unsafe, form.llp64_fingerprint.as_str()),
        }
    }

    #[test]
    fn generated_manifest_matches_checked_in_file_byte_exact() {
        let rendered = super::render_manifest();
        if std::env::var_os("UPDATE_MANIFEST").is_some() {
            // Snapshot workflow: this run rewrites the file (and still
            // fails against the stale embedded copy); the next run is green.
            let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src/mechanism_param_manifest.toml");
            std::fs::write(&path, &rendered).expect("write regenerated manifest");
        }
        assert_eq!(
            rendered,
            super::MANIFEST_TOML,
            "checked-in manifest drifted from regeneration; run \
             UPDATE_MANIFEST=1 cargo test -p pkcs11-proxy-ng-types manifest \
             and review the diff against S2 §8"
        );
    }

    #[test]
    fn bindings_cover_every_descriptor_with_no_extras() {
        let bound: Vec<&str> = super::SHAPE_BINDINGS.iter().map(|binding| binding.shape).collect();
        let mut sorted = bound.clone();
        sorted.sort_unstable();
        assert_eq!(bound, sorted, "bindings must stay sorted (manifest order)");
        let compiled: Vec<&str> =
            SHAPE_DESCRIPTORS.iter().map(|descriptor| descriptor.name).collect();
        assert_eq!(bound, compiled, "every descriptor bound exactly once, no extras");
    }

    #[test]
    fn manifest_covers_every_descriptor_with_no_extras() {
        let in_manifest: Vec<&str> =
            super::manifest().shape.iter().map(|entry| entry.name.as_str()).collect();
        let compiled: Vec<&str> =
            SHAPE_DESCRIPTORS.iter().map(|descriptor| descriptor.name).collect();
        assert_eq!(
            in_manifest, compiled,
            "every descriptor in the manifest exactly once, no extras"
        );
    }

    #[test]
    fn manifest_entries_match_descriptors() {
        for entry in super::manifest().shape.iter() {
            let descriptor = ShapeResolver::descriptor(entry.name.as_str())
                .unwrap_or_else(|| panic!("manifest names unknown shape {}", entry.name));
            assert_eq!(
                entry.outer_kind,
                outer_kind_name(descriptor.outer_kind),
                "outer kind for {}",
                entry.name
            );
            let operations: Vec<String> =
                descriptor.operations.iter().map(|op| format!("{op:?}")).collect();
            assert_eq!(entry.operations, operations, "operations for {}", entry.name);
            assert_eq!(
                entry.virtual_handle, descriptor.contains_virtual_handle,
                "virtual handle for {}",
                entry.name
            );
            // Reviewed facts round-trip through the TOML unchanged.
            let binding = super::SHAPE_BINDINGS
                .iter()
                .find(|candidate| candidate.shape == entry.name)
                .unwrap_or_else(|| panic!("manifest entry {} has no binding", entry.name));
            assert_eq!(entry.status, binding.status, "status for {}", entry.name);
            assert_eq!(
                entry.min_transport_version, binding.min_transport_version,
                "min version for {}",
                entry.name
            );
            let wire: Vec<String> = binding.wire_messages.iter().map(ToString::to_string).collect();
            assert_eq!(entry.wire_messages, wire, "wire messages for {}", entry.name);
            assert_eq!(
                entry.output_fields, binding.output_fields,
                "output fields for {}",
                entry.name
            );
            // Every form re-derived per ABI: size, first unsafe offset,
            // fingerprint (numeric parse — independent of render formatting).
            let mut expected = vec![ResolvedShape::primary(descriptor)];
            expected.extend(
                descriptor
                    .alternate_forms
                    .iter()
                    .map(|alternate| ResolvedShape { descriptor, alternate: Some(alternate) }),
            );
            assert_eq!(entry.form.len(), expected.len(), "form count for {}", entry.name);
            for (toml_form, resolved) in entry.form.iter().zip(expected) {
                assert_eq!(toml_form.name, resolved.form_name(), "form name for {}", entry.name);
                assert_eq!(
                    toml_form.outer_kind,
                    outer_kind_name(resolved.outer_kind()),
                    "form kind for {}#{}",
                    entry.name,
                    toml_form.name
                );
                for (key, abi) in super::RENDER_ABIS {
                    let (size, first_unsafe, fingerprint) = toml_layout(toml_form, key);
                    assert_eq!(size, resolved.native_size(*abi), "{key} size for {}", entry.name);
                    assert_eq!(
                        first_unsafe,
                        resolved.first_unsafe_offset(*abi),
                        "{key} first unsafe for {}",
                        entry.name
                    );
                    let parsed = u64::from_str_radix(
                        fingerprint.strip_prefix("0x").unwrap_or(fingerprint),
                        16,
                    )
                    .unwrap_or_else(|_| panic!("bad {key} fingerprint hex for {}", entry.name));
                    assert_eq!(
                        parsed,
                        resolved.fingerprint(*abi),
                        "{key} fingerprint for {}",
                        entry.name
                    );
                }
            }
        }
    }

    #[test]
    fn manifest_wire_messages_exist_in_proto() {
        for entry in super::manifest().shape.iter() {
            for message in entry.wire_messages.iter() {
                assert!(
                    message_defined(message),
                    "shape {} names missing message {message}",
                    entry.name
                );
                assert!(
                    oneof_member(message),
                    "shape {} names {message} outside the Mechanism oneof",
                    entry.name
                );
            }
        }
        // The parameterless marker rides the unset oneof: no wire message.
        let marker = super::manifest_shape("parameterless").expect("parameterless entry");
        assert!(marker.wire_messages.is_empty(), "parameterless binds no wire message");
        // The dual-encoding GMAC shape binds both typed messages (short
        // buffers forward as `Iv`, struct-sized as `Gcm`).
        let compat = super::manifest_shape("gcm_compat").expect("gcm_compat entry");
        assert_eq!(
            compat.wire_messages,
            vec!["IvParams".to_string(), "GcmParams".to_string()],
            "gcm_compat binds both typed messages"
        );
    }

    #[test]
    fn v1_flat_null_envelopes_exist() {
        // The generic v1 envelopes every `min_transport_version = 1` entry
        // relies on (R6 wire): Flat caller bytes / NULL + declared length.
        for message in ["FlatMechanismParams", "NullMechanismParams"] {
            assert!(message_defined(message), "{message} must exist");
            assert!(oneof_member(message), "{message} must ride the Mechanism oneof");
        }
        assert!(
            TYPES_PROTO.contains("parameter_encoding_version = 83"),
            "per-message version field must exist at tag 83"
        );
    }

    /// S2 §8 family → compiled shapes. S2-named families first, then the
    /// compiled-but-S2-unnamed input shapes (still D1(a)-covered), then the
    /// tail. The reviewer checks this table item-by-item against S2 §8.
    const S2_SECTION_8_FAMILIES: &[(&str, &[&str])] = &[
        ("GCM/CCM/wrap", &["ccm", "ccm_wrap", "gcm", "gcm_compat", "gcm_wrap"]),
        ("EdDSA", &["eddsa", "xeddsa"]),
        ("OAEP", &["key_wrap_set_oaep", "rsa_oaep"]),
        ("ECDH1/2", &["ecdh1_derive", "ecdh2_derive"]),
        ("ECMQV", &["ecmqv_derive"]),
        ("X9.42 DH/MQV", &["x942_dh1_derive", "x942_dh2_derive", "x942_mqv_derive"]),
        ("HKDF", &["hkdf"]),
        ("GOST derive/wrap", &["gostr3410_derive", "gostr3410_key_wrap"]),
        (
            "AES/DES/ARIA/Camellia/SEED CBC-encrypt-data",
            &[
                "aes_cbc_encrypt_data",
                "aria_cbc_encrypt_data",
                "camellia_cbc_encrypt_data",
                "des_cbc_encrypt_data",
                "seed_cbc_encrypt_data",
            ],
        ),
        ("RC5", &["rc5", "rc5_cbc", "rc5_mac_general"]),
        ("ChaCha20", &["chacha20"]),
        ("Salsa20", &["salsa20"]),
        ("AEAD", &["salsa20_chacha20_poly1305"]),
        ("PBKDF2", &["pkcs5_pbkd2"]),
        (
            "IKE v1/v2",
            &["ike1_extended_derive", "ike1_prf_derive", "ike2_prf_plus_derive", "ike_prf_derive"],
        ),
        ("KDF string-data", &["key_derivation_string"]),
        ("KMAC", &["kmac"]),
        // No standalone MGF mechanism takes parameters: MGF selection rides
        // as the `mgf` field inside the OAEP/PSS envelopes (pinned below).
        ("MGF (field inside OAEP/PSS, no standalone shape)", &[]),
        ("PBE", &["pbe"]),
        ("RSA-AES-wrap nesting", &["ecdh_aes_key_wrap", "rsa_aes_key_wrap"]),
        ("PSS-flat", &["rsa_pss"]),
        // Compiled classic input shapes S2 §8 does not name individually.
        ("CTR", &["aes_ctr", "camellia_ctr"]),
        ("RC2", &["rc2_cbc", "rc2_mac_general"]),
        (
            "TLS-input",
            &[
                "ssl3_master_key_derive",
                "tls12_extended_master_key_derive",
                "tls12_master_key_derive",
                "tls_kdf",
                "tls_mac",
                "wtls_master_key_derive",
            ],
        ),
        ("scalar misc", &["extract", "mac_general", "object_handle"]),
        ("byte-buffer", &["iv"]),
        ("PQ/local", &["mu_gen", "sign_additional_context"]),
        ("parameterless marker", &["parameterless"]),
        // Output/nested tail (pending until R21).
        ("TLS/WTLS envelopes", &["tls_prf", "wtls_prf"]),
        ("key-mat", &["ssl3_key_mat", "wtls_key_mat"]),
        ("KEA", &["kea_derive"]),
        ("KIP", &["kip"]),
        ("OTP/SP800-108", &["otp", "sp800_108_feedback_kdf", "sp800_108_kdf"]),
        ("Skipjack", &["skipjack_private_wrap", "skipjack_relayx"]),
    ];

    #[test]
    fn s2_section_8_family_coverage_is_exact() {
        let mut seen = BTreeSet::new();
        for (family, shapes) in S2_SECTION_8_FAMILIES {
            if family.starts_with("MGF ") {
                assert!(shapes.is_empty(), "MGF keeps its no-standalone-shape pin");
                continue;
            }
            assert!(!shapes.is_empty(), "family {family} must be non-empty");
            for shape in *shapes {
                assert!(seen.insert(*shape), "shape {shape} listed in two families");
                assert!(
                    super::manifest_shape(shape).is_some(),
                    "family {family} names unknown shape {shape}"
                );
            }
        }
        let in_manifest: BTreeSet<&str> =
            super::manifest().shape.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(seen, in_manifest, "family union must equal the manifest exactly");
    }

    #[test]
    fn mgf_rides_inside_oaep_pss_envelopes() {
        assert!(
            super::SHAPE_BINDINGS.iter().all(|binding| binding.shape != "mgf"),
            "no standalone mgf shape exists"
        );
        let mgf_fields =
            MECHANISM_PARAMS_PROTO.lines().filter(|line| line.trim() == "uint64 mgf = 2;").count();
        assert_eq!(mgf_fields, 2, "mgf rides exactly in the OAEP + PSS envelopes");
    }

    #[test]
    fn kem_rides_general_mechanism_path_without_manifest_entry() {
        for message in ["KyberParams", "DilithiumParams"] {
            assert!(message_defined(message), "{message} must exist");
            assert!(oneof_member(message), "{message} must ride the general Mechanism oneof");
        }
        let referenced: BTreeSet<&str> = super::SHAPE_BINDINGS
            .iter()
            .flat_map(|binding| binding.wire_messages.iter().copied())
            .collect();
        assert!(
            !referenced.contains("KyberParams") && !referenced.contains("DilithiumParams"),
            "KEM needs no manifest entry (no new envelope)"
        );
    }

    #[test]
    fn vendor_requires_compiled_descriptor_plus_allowlist_never_toml_alone() {
        assert!(VENDOR_FLAT_ALLOWLIST.is_empty(), "v1 carries no vendor Flat");
        // Vendor-ish wire messages exist, but no manifest entry references
        // them: a vendor shape needs a compiled descriptor + allowlist entry
        // first, and this manifest snapshot cannot create either.
        let referenced: BTreeSet<&str> = super::SHAPE_BINDINGS
            .iter()
            .flat_map(|binding| binding.wire_messages.iter().copied())
            .collect();
        for message in [
            "AesCmacKeyDerivationParams",
            "CmsSigParams",
            "EciesParams",
            "HdKeyDeriveParams",
            "VendorObjectExtractParams",
            "VendorObjectInsertParams",
            "X2RatchetInitializeParams",
            "X2RatchetRespondParams",
            "X3dhInitiateParams",
            "X3dhRespondParams",
        ] {
            assert!(message_defined(message), "{message} must exist (else this pin is vacuous)");
            assert!(!referenced.contains(message), "{message} must stay outside the manifest");
        }
    }

    #[test]
    fn r21_manifest_complete_after_phase3() {
        assert!(
            super::manifest_complete(),
            "R21: every manifest entry is complete (Phase-3 rows landed)"
        );
        assert!(
            super::pending_shapes().is_empty(),
            "R21: no shape may remain pending, got {:?}",
            super::pending_shapes()
        );
    }

    #[test]
    fn r21_tail_complete_and_exactly_nested_or_output() {
        // The exact R8 pending tail (kept as the completed-tail pin): the
        // NestedOrOutput set, every member Complete since R21.
        let tail: BTreeSet<&str> = SHAPE_DESCRIPTORS
            .iter()
            .filter(|descriptor| descriptor.outer_kind == OuterKind::NestedOrOutput)
            .map(|descriptor| descriptor.name)
            .collect();
        assert_eq!(
            tail,
            BTreeSet::from([
                "kea_derive",
                "kip",
                "otp",
                "skipjack_private_wrap",
                "skipjack_relayx",
                "sp800_108_feedback_kdf",
                "sp800_108_kdf",
                "ssl3_key_mat",
                "tls_prf",
                "wtls_key_mat",
                "wtls_prf",
            ]),
            "completed tail must equal the NestedOrOutput set"
        );
        for shape in &tail {
            let entry = super::manifest_shape(shape).expect("tail entry in manifest");
            assert_eq!(
                entry.status,
                ManifestStatus::Complete,
                "R21 completed the tail: {shape} must be Complete"
            );
        }
    }

    #[test]
    fn output_fields_are_pointers_in_every_form() {
        for entry in super::manifest().shape.iter() {
            let descriptor = ShapeResolver::descriptor(entry.name.as_str())
                .unwrap_or_else(|| panic!("manifest names unknown shape {}", entry.name));
            let mut forms = vec![ResolvedShape::primary(descriptor)];
            forms.extend(
                descriptor
                    .alternate_forms
                    .iter()
                    .map(|alternate| ResolvedShape { descriptor, alternate: Some(alternate) }),
            );
            for index in entry.output_fields.iter() {
                for resolved in &forms {
                    let fields = resolved.fields();
                    let position = usize::from(*index);
                    assert!(
                        position < fields.len(),
                        "output index {index} out of range for {}",
                        entry.name
                    );
                    assert_eq!(
                        fields[position],
                        FieldClass::Pointer,
                        "output index {index} must be Pointer-class for {}",
                        entry.name
                    );
                }
            }
            if descriptor.outer_kind != OuterKind::NestedOrOutput {
                assert!(
                    entry.output_fields.is_empty(),
                    "only tail shapes carry output fields: {}",
                    entry.name
                );
            }
        }
        // Exact pins for the output-bearing tail rows.
        let outputs =
            |shape: &str| super::manifest_shape(shape).expect("tail entry").output_fields.clone();
        // KEA RandomA/RandomB are role-dependent: exactly one is written per
        // call, selected by isSender.
        assert_eq!(outputs("kea_derive"), vec![2, 3]);
        assert_eq!(outputs("tls_prf"), vec![4, 5]);
        assert_eq!(outputs("wtls_prf"), vec![5, 6]);
        assert_eq!(outputs("ssl3_key_mat"), vec![5]);
        assert_eq!(outputs("wtls_key_mat"), vec![7]);
        assert_eq!(outputs("sp800_108_kdf"), vec![4]);
        assert_eq!(outputs("sp800_108_feedback_kdf"), vec![6]);
        for shape in ["kip", "otp", "skipjack_private_wrap", "skipjack_relayx"] {
            assert!(outputs(shape).is_empty(), "{shape} is nested/count-only tail");
        }
    }

    #[test]
    fn min_transport_version_is_one_everywhere() {
        assert_eq!(super::manifest().manifest_version, MANIFEST_VERSION);
        assert_eq!(MANIFEST_VERSION, 1, "schema version pin");
        for entry in super::manifest().shape.iter() {
            assert_eq!(entry.min_transport_version, 1, "v1 carries every shape: {}", entry.name);
        }
    }

    /// R16 typed-presence table: (S2 §8 family, shape, wire message,
    /// pre-R16 max tag, [(bytes field, `*_null_len` field, tag)]), in S2 §8
    /// family order. The tags are the S2 §3-named tags (GCM 8/9, OAEP 6,
    /// EdDSA 3) plus the binding TAG RULE for the rest (lowest free tag per
    /// message, `optional uint64 <field>_null_len`, consecutive from the
    /// pre-R16 max — machine-checked below). The reviewer checks this table
    /// item-by-item against S2 §8; the union test below proves no
    /// input-pointer family is silently omitted.
    #[allow(clippy::type_complexity)]
    const R16_PRESENCE_TABLE: &[(&str, &str, &str, u32, &[(&str, &str, u32)])] = &[
        // S2 §8 "GCM/CCM/wrap" (`gcm_compat` rides `GcmParams` for its
        // struct form — covered by the `gcm` row).
        (
            "GCM/CCM/wrap",
            "ccm",
            "CcmParams",
            6,
            &[("nonce", "nonce_null_len", 7), ("aad", "aad_null_len", 8)],
        ),
        (
            "GCM/CCM/wrap",
            "ccm_wrap",
            "CcmWrapParams",
            6,
            &[("nonce", "nonce_null_len", 7), ("aad", "aad_null_len", 8)],
        ),
        (
            "GCM/CCM/wrap",
            "gcm",
            "GcmParams",
            7,
            &[("iv", "iv_null_len", 8), ("aad", "aad_null_len", 9)],
        ),
        (
            "GCM/CCM/wrap",
            "gcm_wrap",
            "GcmWrapParams",
            5,
            &[("iv", "iv_null_len", 6), ("aad", "aad_null_len", 7)],
        ),
        // S2 §8 "EdDSA" (`xeddsa` is scalar — no presence).
        ("EdDSA", "eddsa", "EddsaParams", 2, &[("context_data", "context_data_null_len", 3)]),
        // S2 §8 "OAEP".
        ("OAEP", "rsa_oaep", "RsaPkcsOaepParams", 5, &[("source_data", "source_data_null_len", 6)]),
        ("OAEP", "key_wrap_set_oaep", "KeyWrapSetOaepParams", 2, &[("x", "x_null_len", 3)]),
        // S2 §8 "ECDH1/2".
        (
            "ECDH1/2",
            "ecdh1_derive",
            "Ecdh1DeriveParams",
            3,
            &[
                ("shared_data", "shared_data_null_len", 4),
                ("public_data", "public_data_null_len", 5),
            ],
        ),
        (
            "ECDH1/2",
            "ecdh2_derive",
            "Ecdh2DeriveParams",
            6,
            &[
                ("shared_data", "shared_data_null_len", 7),
                ("public_data", "public_data_null_len", 8),
                ("public_data2", "public_data2_null_len", 9),
            ],
        ),
        // S2 §8 "ECMQV".
        (
            "ECMQV",
            "ecmqv_derive",
            "EcmqvDeriveParams",
            7,
            &[
                ("shared_data", "shared_data_null_len", 8),
                ("public_data", "public_data_null_len", 9),
                ("public_data2", "public_data2_null_len", 10),
            ],
        ),
        // S2 §8 "X9.42 DH/MQV".
        (
            "X9.42 DH/MQV",
            "x942_dh1_derive",
            "X942Dh1DeriveParams",
            3,
            &[("other_info", "other_info_null_len", 4), ("public_data", "public_data_null_len", 5)],
        ),
        (
            "X9.42 DH/MQV",
            "x942_dh2_derive",
            "X942Dh2DeriveParams",
            6,
            &[
                ("other_info", "other_info_null_len", 7),
                ("public_data", "public_data_null_len", 8),
                ("public_data2", "public_data2_null_len", 9),
            ],
        ),
        (
            "X9.42 DH/MQV",
            "x942_mqv_derive",
            "X942MqvDeriveParams",
            7,
            &[
                ("other_info", "other_info_null_len", 8),
                ("public_data", "public_data_null_len", 9),
                ("public_data2", "public_data2_null_len", 10),
            ],
        ),
        // S2 §8 "HKDF".
        (
            "HKDF",
            "hkdf",
            "HkdfParams",
            7,
            &[("salt", "salt_null_len", 8), ("info", "info_null_len", 9)],
        ),
        // S2 §8 "GOST derive/wrap".
        (
            "GOST derive/wrap",
            "gostr3410_derive",
            "Gostr3410DeriveParams",
            3,
            &[("public_data", "public_data_null_len", 4), ("ukm", "ukm_null_len", 5)],
        ),
        (
            "GOST derive/wrap",
            "gostr3410_key_wrap",
            "Gostr3410KeyWrapParams",
            3,
            &[("wrap_oid", "wrap_oid_null_len", 4), ("ukm", "ukm_null_len", 5)],
        ),
        // S2 §8 "AES/DES/ARIA/Camellia/SEED CBC-encrypt-data" (the `iv`
        // bytes are a fixed inline array, not a pointer — `data` only).
        (
            "CBC-encrypt-data",
            "aes_cbc_encrypt_data",
            "AesCbcEncryptDataParams",
            2,
            &[("data", "data_null_len", 3)],
        ),
        (
            "CBC-encrypt-data",
            "des_cbc_encrypt_data",
            "DesCbcEncryptDataParams",
            2,
            &[("data", "data_null_len", 3)],
        ),
        (
            "CBC-encrypt-data",
            "aria_cbc_encrypt_data",
            "AriaCbcEncryptDataParams",
            2,
            &[("data", "data_null_len", 3)],
        ),
        (
            "CBC-encrypt-data",
            "camellia_cbc_encrypt_data",
            "CamelliaCbcEncryptDataParams",
            2,
            &[("data", "data_null_len", 3)],
        ),
        (
            "CBC-encrypt-data",
            "seed_cbc_encrypt_data",
            "SeedCbcEncryptDataParams",
            2,
            &[("data", "data_null_len", 3)],
        ),
        // S2 §8 "RC5" (`rc5`/`rc5_mac_general` scalar; only `rc5_cbc`
        // carries a (variable-length) IV pointer).
        ("RC5", "rc5_cbc", "Rc5CbcParams", 3, &[("iv", "iv_null_len", 4)]),
        // S2 §8 "ChaCha20".
        (
            "ChaCha20",
            "chacha20",
            "ChaCha20Params",
            4,
            &[("block_counter", "block_counter_null_len", 5), ("nonce", "nonce_null_len", 6)],
        ),
        // S2 §8 "Salsa20".
        (
            "Salsa20",
            "salsa20",
            "Salsa20Params",
            3,
            &[("block_counter", "block_counter_null_len", 4), ("nonce", "nonce_null_len", 5)],
        ),
        // S2 §8 "AEAD".
        (
            "AEAD",
            "salsa20_chacha20_poly1305",
            "Salsa20ChaCha20Poly1305Params",
            2,
            &[("nonce", "nonce_null_len", 3), ("aad", "aad_null_len", 4)],
        ),
        // S2 §8 "PBKDF2".
        (
            "PBKDF2",
            "pkcs5_pbkd2",
            "Pkcs5Pbkd2Params",
            6,
            &[
                ("salt_source_data", "salt_source_data_null_len", 7),
                ("prf_data", "prf_data_null_len", 8),
                ("password", "password_null_len", 9),
            ],
        ),
        // S2 §8 "IKE v1/v2".
        (
            "IKE v1/v2",
            "ike_prf_derive",
            "IkePrfDeriveParams",
            6,
            &[("ni", "ni_null_len", 7), ("nr", "nr_null_len", 8)],
        ),
        (
            "IKE v1/v2",
            "ike1_prf_derive",
            "Ike1PrfDeriveParams",
            7,
            &[("ckyi", "ckyi_null_len", 8), ("ckyr", "ckyr_null_len", 9)],
        ),
        (
            "IKE v1/v2",
            "ike1_extended_derive",
            "Ike1ExtendedDeriveParams",
            4,
            &[("extra_data", "extra_data_null_len", 5)],
        ),
        (
            "IKE v1/v2",
            "ike2_prf_plus_derive",
            "Ike2PrfPlusDeriveParams",
            4,
            &[("seed_data", "seed_data_null_len", 5)],
        ),
        // S2 §8 "KDF string-data".
        (
            "KDF string-data",
            "key_derivation_string",
            "KeyDerivationStringData",
            1,
            &[("data", "data_null_len", 2)],
        ),
        // S2 §8 "KMAC".
        (
            "KMAC",
            "kmac",
            "KmacParams",
            3,
            &[("customization_string", "customization_string_null_len", 4)],
        ),
        // S2 §8 "MGF": no standalone shape (existing `mgf` pin) — no row.
        // S2 §8 "PBE".
        (
            "PBE",
            "pbe",
            "PbeParams",
            4,
            &[
                ("init_vector", "init_vector_null_len", 5),
                ("password", "password_null_len", 6),
                ("salt", "salt_null_len", 7),
            ],
        ),
        // S2 §8 "RSA-AES-wrap nesting".
        (
            "RSA-AES-wrap nesting",
            "ecdh_aes_key_wrap",
            "EcdhAesKeyWrapParams",
            3,
            &[("shared_data", "shared_data_null_len", 4)],
        ),
        // `rsa_aes_key_wrap` carries no direct byte buffer: its only
        // pointer past the safe prefix is the nested OAEP struct, whose
        // presence rides the shared `RsaPkcsOaepParams` envelope (nested
        // presence is otherwise an R18 tail concept). Empty list + the
        // no-direct-bytes pin below.
        ("RSA-AES-wrap nesting", "rsa_aes_key_wrap", "RsaAesKeyWrapParams", 2, &[]),
        // S2 §8 "PSS-flat": scalar — no row.
        // Compiled-but-S2-unnamed input-pointer shapes (D1(a) full
        // inventory; R18 claims none of these, so R16 covers them).
        (
            "PQ/local",
            "mu_gen",
            "MuGenParams",
            3,
            &[("tr", "tr_null_len", 4), ("context", "context_null_len", 5)],
        ),
        (
            "PQ/local",
            "sign_additional_context",
            "SignAdditionalContext",
            3,
            &[("context", "context_null_len", 4)],
        ),
    ];

    /// Complete+PointerStruct shapes R16 does NOT cover: R18 owns every
    /// TLS/WTLS envelope (R18 step 1 names them), so they are excluded
    /// here explicitly — never silently. The union test pins this set
    /// against the live manifest in both directions.
    const R16_R18_TLS_SET: &[&str] = &[
        "ssl3_master_key_derive",
        "tls12_extended_master_key_derive",
        "tls12_master_key_derive",
        "tls_kdf",
        "wtls_master_key_derive",
    ];

    /// Source lines of the top-level `message {name} {...}` block in
    /// `mechanism_params.proto` (brace-counted, so nested oneofs stay
    /// inside the block).
    fn message_block_lines(name: &str) -> Vec<&'static str> {
        let mut lines = Vec::new();
        let mut depth = 0u32;
        let mut inside = false;
        for line in MECHANISM_PARAMS_PROTO.lines() {
            if !inside {
                let trimmed = line.trim_start();
                if trimmed.starts_with(&format!("message {name} "))
                    || trimmed.starts_with(&format!("message {name}{{"))
                {
                    inside = true;
                } else {
                    continue;
                }
            }
            depth += line.chars().filter(|c| *c == '{').count() as u32;
            depth -= line.chars().filter(|c| *c == '}').count() as u32;
            lines.push(line);
            if depth == 0 {
                break;
            }
        }
        assert!(inside, "message {name} not found in mechanism_params.proto");
        lines
    }

    #[test]
    fn r16_input_pointer_presence_fields_exist() {
        for (family, shape, message, pre16_max, fields) in R16_PRESENCE_TABLE {
            let block = message_block_lines(message);
            // TAG RULE (binding): lowest free tag per message — the row's
            // tags are exactly pre16_max+1, +2, … in order. The S2-named
            // tags (GCM 8/9, OAEP 6, EdDSA 3) satisfy the same rule.
            for (index, (_, _, tag)) in fields.iter().enumerate() {
                assert_eq!(
                    *tag,
                    pre16_max + index as u32 + 1,
                    "tag rule for {family}/{shape}/{message}"
                );
            }
            for (bytes_field, null_len_field, tag) in *fields {
                assert!(
                    block.iter().any(|line| line
                        .trim_start()
                        .starts_with(&format!("bytes {bytes_field} ="))),
                    "{family}/{shape}: {message} must carry `bytes {bytes_field}` \
                     (else the presence pin is vacuous)"
                );
                let expected = format!("optional uint64 {null_len_field} = {tag};");
                assert!(
                    block.iter().any(|line| line.trim_start().starts_with(&expected)),
                    "{family}/{shape}: {message} must carry `{expected}`"
                );
            }
            // The table's only empty row: `rsa_aes_key_wrap` has no direct
            // byte buffer (nested OAEP envelope carries the presence).
            if fields.is_empty() {
                assert_eq!(
                    (*shape, *message),
                    ("rsa_aes_key_wrap", "RsaAesKeyWrapParams"),
                    "only rsa_aes_key_wrap may list no presence fields"
                );
                assert!(
                    !block.iter().any(|line| line.trim_start().starts_with("bytes ")),
                    "rsa_aes_key_wrap must have no direct bytes field"
                );
            }
        }
    }

    #[test]
    fn r16_presence_table_covers_every_input_pointer_shape() {
        let table_shapes: BTreeSet<&str> = R16_PRESENCE_TABLE.iter().map(|row| row.1).collect();
        assert_eq!(
            table_shapes.len(),
            R16_PRESENCE_TABLE.len(),
            "one row per shape (no duplicates)"
        );
        // Every row resolves to a live Complete PointerStruct whose wire
        // binding carries the row's message.
        for (family, shape, message, _, _) in R16_PRESENCE_TABLE {
            let entry = super::manifest_shape(shape)
                .unwrap_or_else(|| panic!("{family} names unknown shape {shape}"));
            assert_eq!(
                entry.status,
                ManifestStatus::Complete,
                "{family}/{shape} must be Complete (tail is R18)"
            );
            let descriptor = ShapeResolver::descriptor(shape)
                .unwrap_or_else(|| panic!("{family} names undescribed shape {shape}"));
            assert_eq!(
                descriptor.outer_kind,
                OuterKind::PointerStruct,
                "{family}/{shape} must be PointerStruct"
            );
            assert!(
                entry.wire_messages.iter().any(|bound| bound == message),
                "{family}/{shape} must bind {message}"
            );
        }
        // No silent omission in either direction: the table is exactly the
        // Complete PointerStruct set minus the explicit R18 TLS set.
        let complete_pointer: BTreeSet<&str> = SHAPE_DESCRIPTORS
            .iter()
            .filter(|descriptor| descriptor.outer_kind == OuterKind::PointerStruct)
            .filter(|descriptor| {
                super::manifest_shape(descriptor.name)
                    .is_some_and(|entry| entry.status == ManifestStatus::Complete)
            })
            .map(|descriptor| descriptor.name)
            .collect();
        let r18: BTreeSet<&str> = R16_R18_TLS_SET.iter().copied().collect();
        assert_eq!(r18.len(), R16_R18_TLS_SET.len(), "R18 set has no duplicates");
        for shape in &r18 {
            assert!(
                complete_pointer.contains(shape),
                "R18 exclusion {shape} must be a live Complete PointerStruct \
                 (else the exclusion is vacuous)"
            );
        }
        let mut expected = complete_pointer;
        for shape in &r18 {
            expected.remove(shape);
        }
        assert_eq!(
            table_shapes, expected,
            "presence table must equal Complete PointerStructs minus the R18 TLS set"
        );
    }

    /// R18 tail-envelope field kinds (S2 §8 tail, D1(a)): byte-pointer
    /// presence follows the R16 pattern; counted arrays and length-less
    /// scalar pointers get their own envelope shapes (no silent omission
    /// — every tail pointer must appear here with its kind).
    /// The shared `Null` prefix mirrors the `_null_len`/`_null_count`/
    /// `_null` proto suffixes it classifies.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[allow(clippy::enum_variant_names)]
    enum R18FieldKind {
        /// `optional uint64 {field} = {tag};` beside `bytes {companion}`
        /// (R16 semantics: present = NULL + exactly that length).
        NullLen { companion: &'static str },
        /// `optional uint64 {field} = {tag};` beside
        /// `repeated <T> {companion}` (present = NULL array + exactly
        /// that count; absent = non-NULL, count == len).
        NullCount { companion: &'static str },
        /// `optional bool {field} = {tag};` (length-less pointer:
        /// `Some(true)` = NULL; absent/`Some(false)` = non-NULL).
        NullBit,
    }

    /// R18 tail-envelope table: `(S2 family, shape, wire message,
    /// pre-R18 max tag, message lives in types.proto,
    /// [(envelope field, tag, kind)])`. TAG RULE (binding, R16 step 2):
    /// lowest free tag per message — the row's tags are exactly
    /// pre18_max+1, +2, … in C-struct field order. The union test pins
    /// this table against the live manifest in both directions.
    #[allow(clippy::type_complexity)]
    const R18_TAIL_TABLE: &[(&str, &str, &str, u32, bool, &[(&str, u32, R18FieldKind)])] = &[
        // S2 §8 "KEA" (A/B share ulRandomLen — companions).
        (
            "KEA",
            "kea_derive",
            "KeaDeriveParams",
            4,
            false,
            &[
                ("random_a_null_len", 5, R18FieldKind::NullLen { companion: "random_a" }),
                ("random_b_null_len", 6, R18FieldKind::NullLen { companion: "random_b" }),
                ("public_data_null_len", 7, R18FieldKind::NullLen { companion: "public_data" }),
            ],
        ),
        // S2 §8 "KIP" (nesting presence; message lives in types.proto).
        (
            "KIP",
            "kip",
            "KipParams",
            3,
            true,
            &[
                ("mechanism_null", 4, R18FieldKind::NullBit),
                ("seed_null_len", 5, R18FieldKind::NullLen { companion: "seed" }),
            ],
        ),
        // S2 §8 "OTP/SP800-108" (array presence).
        (
            "OTP/SP800-108",
            "otp",
            "OtpParams",
            1,
            false,
            &[("params_null_count", 2, R18FieldKind::NullCount { companion: "params" })],
        ),
        (
            "OTP/SP800-108",
            "sp800_108_kdf",
            "Sp800108KdfParams",
            3,
            false,
            &[
                ("data_params_null_count", 4, R18FieldKind::NullCount { companion: "data_params" }),
                (
                    "additional_derived_keys_null_count",
                    5,
                    R18FieldKind::NullCount { companion: "additional_derived_keys" },
                ),
            ],
        ),
        (
            "OTP/SP800-108",
            "sp800_108_feedback_kdf",
            "Sp800108FeedbackKdfParams",
            4,
            false,
            &[
                ("data_params_null_count", 5, R18FieldKind::NullCount { companion: "data_params" }),
                ("iv_null_len", 6, R18FieldKind::NullLen { companion: "iv" }),
                (
                    "additional_derived_keys_null_count",
                    7,
                    R18FieldKind::NullCount { companion: "additional_derived_keys" },
                ),
            ],
        ),
        // S2 §8 "Skipjack" (shared-length companions: P/G share ulPAndGLen).
        (
            "Skipjack",
            "skipjack_private_wrap",
            "SkipjackPrivateWrapParams",
            7,
            false,
            &[
                ("password_null_len", 8, R18FieldKind::NullLen { companion: "password" }),
                ("public_data_null_len", 9, R18FieldKind::NullLen { companion: "public_data" }),
                ("random_a_null_len", 10, R18FieldKind::NullLen { companion: "random_a" }),
                ("prime_p_null_len", 11, R18FieldKind::NullLen { companion: "prime_p" }),
                ("base_g_null_len", 12, R18FieldKind::NullLen { companion: "base_g" }),
                ("subprime_q_null_len", 13, R18FieldKind::NullLen { companion: "subprime_q" }),
            ],
        ),
        (
            "Skipjack",
            "skipjack_relayx",
            "SkipjackRelayxParams",
            7,
            false,
            &[
                ("old_wrapped_x_null_len", 8, R18FieldKind::NullLen { companion: "old_wrapped_x" }),
                ("old_password_null_len", 9, R18FieldKind::NullLen { companion: "old_password" }),
                (
                    "old_public_data_null_len",
                    10,
                    R18FieldKind::NullLen { companion: "old_public_data" },
                ),
                ("old_random_a_null_len", 11, R18FieldKind::NullLen { companion: "old_random_a" }),
                ("new_password_null_len", 12, R18FieldKind::NullLen { companion: "new_password" }),
                (
                    "new_public_data_null_len",
                    13,
                    R18FieldKind::NullLen { companion: "new_public_data" },
                ),
                ("new_random_a_null_len", 14, R18FieldKind::NullLen { companion: "new_random_a" }),
            ],
        ),
        // S2 §8 "TLS/WTLS envelopes": TlsMac is scalar (no pointers —
        // the table's only empty row, pinned below).
        ("TLS/WTLS envelopes", "tls_mac", "TlsMacParams", 3, false, &[]),
        (
            "TLS/WTLS envelopes",
            "tls_prf",
            "TlsPrfParams",
            4,
            false,
            &[
                ("seed_null_len", 5, R18FieldKind::NullLen { companion: "seed" }),
                ("label_null_len", 6, R18FieldKind::NullLen { companion: "label" }),
                ("output_null", 7, R18FieldKind::NullBit),
                ("output_len_null", 8, R18FieldKind::NullBit),
            ],
        ),
        (
            "TLS/WTLS envelopes",
            "tls_kdf",
            "TlsKdfParams",
            4,
            false,
            &[
                ("label_null_len", 5, R18FieldKind::NullLen { companion: "label" }),
                ("context_data_null_len", 6, R18FieldKind::NullLen { companion: "context_data" }),
            ],
        ),
        (
            "TLS/WTLS envelopes",
            "ssl3_master_key_derive",
            "Ssl3MasterKeyDeriveParams",
            3,
            false,
            &[("version_null", 4, R18FieldKind::NullBit)],
        ),
        (
            "TLS/WTLS envelopes",
            "tls12_master_key_derive",
            "Tls12MasterKeyDeriveParams",
            4,
            false,
            &[("version_null", 5, R18FieldKind::NullBit)],
        ),
        (
            "TLS/WTLS envelopes",
            "tls12_extended_master_key_derive",
            "Tls12ExtendedMasterKeyDeriveParams",
            4,
            false,
            &[
                ("session_hash_null_len", 5, R18FieldKind::NullLen { companion: "session_hash" }),
                ("version_null", 6, R18FieldKind::NullBit),
            ],
        ),
        (
            "TLS/WTLS envelopes",
            "ssl3_key_mat",
            "Ssl3KeyMatParams",
            12,
            false,
            &[
                ("returned_key_material_null", 13, R18FieldKind::NullBit),
                ("client_iv_null_len", 14, R18FieldKind::NullLen { companion: "client_iv" }),
                ("server_iv_null_len", 15, R18FieldKind::NullLen { companion: "server_iv" }),
            ],
        ),
        (
            "TLS/WTLS envelopes",
            "wtls_master_key_derive",
            "WtlsMasterKeyDeriveParams",
            3,
            false,
            &[("version_null", 4, R18FieldKind::NullBit)],
        ),
        (
            "TLS/WTLS envelopes",
            "wtls_prf",
            "WtlsPrfParams",
            5,
            false,
            &[
                ("seed_null_len", 6, R18FieldKind::NullLen { companion: "seed" }),
                ("label_null_len", 7, R18FieldKind::NullLen { companion: "label" }),
                ("output_null", 8, R18FieldKind::NullBit),
                ("output_len_null", 9, R18FieldKind::NullBit),
            ],
        ),
        (
            "TLS/WTLS envelopes",
            "wtls_key_mat",
            "WtlsKeyMatParams",
            10,
            false,
            &[
                ("returned_key_material_null", 11, R18FieldKind::NullBit),
                ("iv_null_len", 12, R18FieldKind::NullLen { companion: "iv" }),
            ],
        ),
    ];

    /// Source lines of the top-level `message {name} {...}` block in the
    /// given `.proto` source (brace-counted, so nested oneofs stay
    /// inside the block).
    fn message_block_lines_in(source: &'static str, name: &str) -> Vec<&'static str> {
        let mut lines = Vec::new();
        let mut depth = 0u32;
        let mut inside = false;
        for line in source.lines() {
            if !inside {
                let trimmed = line.trim_start();
                if trimmed.starts_with(&format!("message {name} "))
                    || trimmed.starts_with(&format!("message {name}{{"))
                {
                    inside = true;
                } else {
                    continue;
                }
            }
            depth += line.chars().filter(|c| *c == '{').count() as u32;
            depth -= line.chars().filter(|c| *c == '}').count() as u32;
            lines.push(line);
            if depth == 0 {
                break;
            }
        }
        assert!(inside, "message {name} not found in .proto source");
        lines
    }

    #[test]
    fn r18_tail_envelope_fields_exist() {
        for (family, shape, message, pre18_max, in_types_proto, fields) in R18_TAIL_TABLE {
            let source = if *in_types_proto { TYPES_PROTO } else { MECHANISM_PARAMS_PROTO };
            let block = message_block_lines_in(source, message);
            // TAG RULE (binding): lowest free tag per message — the row's
            // tags are exactly pre18_max+1, +2, … in C-struct order.
            for (index, (_, tag, _)) in fields.iter().enumerate() {
                assert_eq!(
                    *tag,
                    pre18_max + index as u32 + 1,
                    "tag rule for {family}/{shape}/{message}"
                );
            }
            for (field, tag, kind) in *fields {
                let expected = match kind {
                    R18FieldKind::NullLen { companion } => {
                        assert!(
                            block.iter().any(|line| line
                                .trim_start()
                                .starts_with(&format!("bytes {companion} ="))),
                            "{family}/{shape}: {message} must carry `bytes {companion}` \
                             (else the presence pin is vacuous)"
                        );
                        format!("optional uint64 {field} = {tag};")
                    }
                    R18FieldKind::NullCount { companion } => {
                        assert!(
                            block.iter().any(|line| {
                                let trimmed = line.trim_start();
                                trimmed.starts_with("repeated ")
                                    && trimmed.contains(&format!(" {companion} ="))
                            }),
                            "{family}/{shape}: {message} must carry `repeated <T> {companion}` \
                             (else the count pin is vacuous)"
                        );
                        format!("optional uint64 {field} = {tag};")
                    }
                    R18FieldKind::NullBit => format!("optional bool {field} = {tag};"),
                };
                assert!(
                    block.iter().any(|line| line.trim_start().starts_with(&expected)),
                    "{family}/{shape}: {message} must carry `{expected}`"
                );
            }
            // The table's only empty row: `tls_mac` is scalar (no
            // pointers, nothing to envelop).
            if fields.is_empty() {
                assert_eq!(
                    (*shape, *message),
                    ("tls_mac", "TlsMacParams"),
                    "only tls_mac may list no envelope fields"
                );
                assert!(
                    !block.iter().any(|line| {
                        let trimmed = line.trim_start();
                        trimmed.starts_with("bytes ")
                            || trimmed.starts_with("repeated ")
                            || trimmed.starts_with("optional ")
                    }),
                    "tls_mac must have no byte/array/envelope field"
                );
                let descriptor = ShapeResolver::descriptor(shape)
                    .unwrap_or_else(|| panic!("{family} names undescribed shape {shape}"));
                assert_eq!(
                    descriptor.outer_kind,
                    OuterKind::ScalarStruct,
                    "{family}/{shape} must be ScalarStruct"
                );
            }
        }
    }

    #[test]
    fn r18_tail_submessage_envelopes_exist() {
        // Shared/nested sub-messages carry the envelopes their parents
        // reuse (pinned here — they have no manifest shape row of their
        // own, so the table test cannot cover them).
        for (message, pre18_max, fields) in [
            (
                "SslRandomData",
                2u32,
                &[("client_random_null_len", 3u32), ("server_random_null_len", 4u32)]
                    as &[(&str, u32)],
            ),
            (
                "WtlsRandomData",
                2u32,
                &[("client_random_null_len", 3u32), ("server_random_null_len", 4u32)]
                    as &[(&str, u32)],
            ),
            ("PrfDataParam", 2u32, &[("value_null_len", 3u32)] as &[(&str, u32)]),
            ("OtpParam", 2u32, &[("value_null_len", 3u32)] as &[(&str, u32)]),
            ("Sp800108DerivedKey", 2u32, &[("template_null_count", 3u32)] as &[(&str, u32)]),
        ] {
            let block = message_block_lines_in(MECHANISM_PARAMS_PROTO, message);
            for (index, (field, tag)) in fields.iter().enumerate() {
                assert_eq!(*tag, pre18_max + index as u32 + 1, "tag rule for {message}");
                let expected = format!("optional uint64 {field} = {tag};");
                assert!(
                    block.iter().any(|line| line.trim_start().starts_with(&expected)),
                    "{message} must carry `{expected}`"
                );
            }
        }
        // The SP800-108 derived-key output-handle null bit (length-less
        // pointer — the bool envelope kind).
        let block = message_block_lines_in(MECHANISM_PARAMS_PROTO, "Sp800108DerivedKey");
        assert!(
            block
                .iter()
                .any(|line| line.trim_start().starts_with("optional bool ph_key_null = 4;")),
            "Sp800108DerivedKey must carry `optional bool ph_key_null = 4;`"
        );
    }

    #[test]
    fn r18_tail_table_covers_every_tail_shape() {
        let table_shapes: BTreeSet<&str> = R18_TAIL_TABLE.iter().map(|row| row.1).collect();
        assert_eq!(table_shapes.len(), R18_TAIL_TABLE.len(), "one row per shape (no duplicates)");
        // Every row resolves to a live shape whose wire binding carries
        // the row's message.
        for (family, shape, message, _, _, _) in R18_TAIL_TABLE {
            let entry = super::manifest_shape(shape)
                .unwrap_or_else(|| panic!("{family} names unknown shape {shape}"));
            assert!(
                entry.wire_messages.iter().any(|bound| bound == message),
                "{family}/{shape} must bind {message}"
            );
        }
        // No silent omission in either direction: the table is exactly
        // the completed tail (NestedOrOutput, R21) + the R16-deferred
        // TLS-input set + tls_mac.
        let mut expected: BTreeSet<&str> = SHAPE_DESCRIPTORS
            .iter()
            .filter(|descriptor| descriptor.outer_kind == OuterKind::NestedOrOutput)
            .map(|descriptor| descriptor.name)
            .collect();
        for shape in R16_R18_TLS_SET {
            expected.insert(shape);
        }
        expected.insert("tls_mac");
        assert_eq!(
            expected,
            BTreeSet::from([
                "kea_derive",
                "kip",
                "otp",
                "skipjack_private_wrap",
                "skipjack_relayx",
                "sp800_108_feedback_kdf",
                "sp800_108_kdf",
                "ssl3_key_mat",
                "ssl3_master_key_derive",
                "tls12_extended_master_key_derive",
                "tls12_master_key_derive",
                "tls_kdf",
                "tls_mac",
                "tls_prf",
                "wtls_key_mat",
                "wtls_master_key_derive",
                "wtls_prf",
            ]),
            "exact R18 tail scope (completed tail + TLS-input + tls_mac)"
        );
        assert_eq!(table_shapes, expected, "tail table must equal the exact R18 tail scope");
        // R21: the whole R18 scope is Complete (the tail half flipped here).
        for shape in &table_shapes {
            let entry = super::manifest_shape(shape).expect("tail entry in manifest");
            assert_eq!(
                entry.status,
                ManifestStatus::Complete,
                "R21 completed the tail scope: {shape} must be Complete"
            );
        }
    }

    #[test]
    fn r18_kem_needs_no_envelope() {
        // S2 §8: KEM rides the general `Mechanism` path — no KEM message
        // gains an envelope field. Each KEM request carries a `Mechanism`
        // member; each KEM response carries none. The only `optional`
        // lines are the pre-R18 ones (ADR-0010 Scope 2 / Wave 3.5 D2).
        for (message, optionals) in [
            ("EncapsulateKeyRequest", &[] as &[&str]),
            ("EncapsulateKeyExactRequest", &[] as &[&str]),
            ("DecapsulateKeyRequest", &["optional uint64 ciphertext_null_len = 7;"] as &[&str]),
        ] {
            let block = message_block_lines_in(TYPES_PROTO, message);
            assert!(
                block.iter().any(|line| line.trim_start().starts_with("Mechanism mechanism =")),
                "{message} must ride the general Mechanism path"
            );
            let got: Vec<&str> = block
                .iter()
                .map(|line| line.trim_start())
                .filter(|l| l.starts_with("optional "))
                .collect();
            assert_eq!(got, *optionals, "{message} gains no envelope field");
        }
        for message in
            ["EncapsulateKeyResponse", "DecapsulateKeyResponse", "EncapsulateKeyExactResponse"]
        {
            let block = message_block_lines_in(TYPES_PROTO, message);
            assert!(
                !block.iter().any(|line| line.trim_start().starts_with("Mechanism ")),
                "{message} carries no Mechanism"
            );
            assert!(
                !block.iter().any(|line| line.trim_start().starts_with("optional ")),
                "{message} gains no envelope field"
            );
        }
    }

    #[test]
    fn r18_vendor_tail_fail_closed() {
        use crate::mechanism_registry::MechanismRegistry;
        use crate::shape_descriptors::{
            FlatDecision, FlatDenyReason, FlatRequest, Operation, ParamAbi, decide_flat,
            is_vendor_mechanism,
        };
        // (a) No TOML-created tail descriptor: a vendor override naming
        // an uncompiled tail shape fails loudly at load.
        let override_toml = "[[params]]\nshape = \"vendor_tls_tail\"\nmechanisms = [0x80001087]\n";
        let err = MechanismRegistry::load_with_override_str(Some(override_toml)).unwrap_err();
        assert!(
            err.contains("vendor_tls_tail"),
            "TOML-created tail shape must fail load naming the shape, got: {err}"
        );
        // (b) A vendor mechanism bound to a COMPILED tail shape still
        // fails closed on the Flat path (vendor check precedes the
        // nested check, so the reason names the missing allowlist
        // entry — TOML binding alone never authorizes vendor Flat).
        let vendor_mech = 0x8000_0001u64;
        assert!(is_vendor_mechanism(vendor_mech));
        let decision = decide_flat(FlatRequest {
            mechanism: vendor_mech,
            operation: Operation::General,
            declared_len: 64,
            bound_shape: Some("tls_prf"),
            parameterless_listed: false,
            excluded: false,
            peer_fingerprint: 0,
            peer_abi: ParamAbi::Lp64NativeLe,
            local_abi: ParamAbi::Lp64NativeLe,
        });
        assert_eq!(
            decision,
            FlatDecision::Denied(FlatDenyReason::VendorWithoutAllowlist),
            "vendor + compiled tail shape must deny Flat for the missing allowlist entry"
        );
        // (c) Vendor wire messages carry no envelope fields (no
        // presence/count/null-bit line in any vendor block).
        for message in [
            "AesCmacKeyDerivationParams",
            "DilithiumParams",
            "KyberParams",
            "HdKeyDeriveParams",
            "VendorObjectExtractParams",
            "VendorObjectInsertParams",
        ] {
            let block = message_block_lines_in(MECHANISM_PARAMS_PROTO, message);
            assert!(
                !block.iter().any(|line| {
                    let trimmed = line.trim_start();
                    trimmed.contains("_null_len")
                        || trimmed.contains("_null_count")
                        || trimmed.starts_with("optional bool")
                }),
                "{message} carries no envelope field"
            );
        }
    }

    // ─── R21: Phase-3 completion + freeze (S2 §8/§11) ────────────────────────
    //
    // COMPLETE presence-field coverage: every manifest shape carries its
    // wire envelope + domain conversion + shim reader + backend
    // reconstruction. Each row below names the R-task that delivered it;
    // rows delivered pre-campaign say so (the R21 pin, not the code, is
    // new). Cross-crate by `include_str!` (the dependency runs
    // proto/shim/backend → types, so the tests match identifiers against
    // the sibling sources — same repository, standalone-safe).

    /// R21 no-envelope table: `(S2 §8 family, shape, wire message, why no
    /// envelope)`. Scalar shapes have no pointers to envelop; the
    /// byte-buffer form (`iv`) expresses NULL at the OUTER layer (D3
    /// `Null`), never per-field. The union test pins this table against
    /// the live manifest in both directions (no silent omission, no
    /// silent addition).
    const R21_NO_ENVELOPE_SHAPES: &[(&str, &str, &str, &str)] = &[
        ("CTR", "aes_ctr", "AesCtrParams", "scalar: fixed array + counter, no pointer"),
        ("CTR", "camellia_ctr", "CamelliaCtrParams", "scalar: fixed array + counter, no pointer"),
        ("RC2", "rc2_cbc", "Rc2CbcParams", "scalar: fixed IV array, no pointer"),
        ("RC2", "rc2_mac_general", "Rc2MacGeneralParams", "scalar: fixed IV array, no pointer"),
        ("RC5", "rc5", "Rc5Params", "scalar: wordsize/rounds only, no pointer"),
        (
            "RC5",
            "rc5_mac_general",
            "Rc5MacGeneralParams",
            "scalar: wordsize/rounds/mac-len, no pointer",
        ),
        ("PSS-flat", "rsa_pss", "RsaPkcsPssParams", "scalar: algs + salt len, no pointer"),
        ("EdDSA", "xeddsa", "XeddsaParams", "scalar: prehash flag only, no pointer"),
        ("scalar misc", "mac_general", "MacGeneralParams", "scalar: mac len only, no pointer"),
        ("scalar misc", "extract", "ExtractParams", "scalar: handle + bit flag, no pointer"),
        ("scalar misc", "object_handle", "ObjectHandleParam", "scalar: single handle, no pointer"),
        ("byte-buffer", "iv", "IvParams", "byte-buffer: NULL rides the outer Null layer (D3)"),
    ];

    /// Prost oneof-variant overrides: the variant derives from the
    /// snake_case FIELD name, which round-trips to the message name for
    /// every manifest message except these two (`ChaCha` → `chacha` →
    /// `Chacha`). The conversion test pins this map exact in both
    /// directions (each override necessary + sufficient, nothing else
    /// needs one).
    const R21_PROST_ONEOF_OVERRIDES: &[(&str, &str)] = &[
        ("ChaCha20Params", "Chacha20Params"),
        ("Salsa20ChaCha20Poly1305Params", "Salsa20Chacha20Poly1305Params"),
    ];

    /// Sibling-crate sources for the cross-crate Nelson checks (same
    /// repository — standalone-safe, like the `.proto` includes above).
    const PROTO_CONVERT_MOD: &str = include_str!("../../proto/src/convert/mechanism/mod.rs");
    const SHIM_MECHANISM_READ: &str =
        include_str!("../../shim/src/dispatch/general/helpers/mechanism_read.rs");
    const BACKEND_MECHANISM: &str =
        include_str!("../../backend/src/ffi/ffi_conversion/mechanism.rs");

    /// Lines of `source` before the line containing `end`, with full-line
    /// `//` comments stripped (doc comments quote identifiers — code
    /// mentions only). Panics unless `end` occurs exactly once.
    fn code_span_before(source: &'static str, end: &str) -> Vec<&'static str> {
        let lines: Vec<&str> = source.lines().collect();
        let positions: Vec<usize> =
            lines.iter().enumerate().filter(|(_, l)| l.contains(end)).map(|(i, _)| i).collect();
        assert_eq!(positions.len(), 1, "anchor `{end}` must occur exactly once");
        lines[..positions[0]]
            .iter()
            .filter(|l| !l.trim_start().starts_with("//"))
            .copied()
            .collect()
    }

    /// Lines of `source` from the line containing `start` (inclusive) to
    /// the line containing `end` (exclusive), with full-line `//`
    /// comments stripped. Panics unless both anchors occur exactly once,
    /// in order.
    fn code_span_between(source: &'static str, start: &str, end: &str) -> Vec<&'static str> {
        let lines: Vec<&str> = source.lines().collect();
        let at = |anchor: &str| {
            let positions: Vec<usize> = lines
                .iter()
                .enumerate()
                .filter(|(_, l)| l.contains(anchor))
                .map(|(i, _)| i)
                .collect();
            assert_eq!(positions.len(), 1, "anchor `{anchor}` must occur exactly once");
            positions[0]
        };
        let (lo, hi) = (at(start), at(end));
        assert!(lo < hi, "anchor `{start}` must precede anchor `{end}`");
        lines[lo..hi].iter().filter(|l| !l.trim_start().starts_with("//")).copied().collect()
    }

    /// Whether any line of `span` contains `needle`.
    fn span_contains(span: &[&str], needle: &str) -> bool {
        span.iter().any(|line| line.contains(needle))
    }

    /// Shape IDs referenced as `Some("shape")` in `span` (shim reader
    /// arms). Tokens are restricted to `[a-z0-9_]+` so error strings can
    /// never match.
    fn some_shape_tokens(span: &[&'static str]) -> BTreeSet<&'static str> {
        let mut shapes = BTreeSet::new();
        for line in span {
            for part in line.split("Some(\"").skip(1) {
                let token = part.split('"').next().unwrap_or("");
                if !token.is_empty()
                    && token
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
                {
                    shapes.insert(token);
                }
            }
        }
        shapes
    }

    /// Every `"snake"` token in `span` (shim dispatch predicates list
    /// shapes as `"a" | "b"` across lines, so the `Some("` prefix cannot
    /// anchor them). Tokens are restricted to `[a-z0-9_]+`.
    fn quoted_snake_tokens(span: &[&'static str]) -> BTreeSet<&'static str> {
        let mut tokens = BTreeSet::new();
        for line in span {
            let mut rest = *line;
            while let Some(open) = rest.find('"') {
                rest = &rest[open + 1..];
                let Some(close) = rest.find('"') else { break };
                let token = &rest[..close];
                if !token.is_empty()
                    && token
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
                {
                    tokens.insert(token);
                }
                rest = &rest[close + 1..];
            }
        }
        tokens
    }

    /// `CkMechanismParams` variant for a wire message: the message name
    /// minus its `Params`/`Param`/`Data` suffix (`IvParams` → `Iv`,
    /// `ObjectHandleParam` → `ObjectHandle`, `KeyDerivationStringData` →
    /// `KeyDerivationString`, `SignAdditionalContext` unchanged). The
    /// conversion/backend tests fail loudly on any message this rule
    /// mis-derives.
    fn domain_variant(message: &str) -> &str {
        for suffix in ["Params", "Param", "Data"] {
            if let Some(variant) = message.strip_suffix(suffix).filter(|v| !v.is_empty()) {
                return variant;
            }
        }
        message
    }

    /// `Mechanism.params` oneof variant for a wire message: the message
    /// name, except the [`R21_PROST_ONEOF_OVERRIDES`] prost renames.
    fn oneof_variant(message: &str) -> &str {
        R21_PROST_ONEOF_OVERRIDES
            .iter()
            .find(|(name, _)| *name == message)
            .map(|(_, variant)| *variant)
            .unwrap_or(message)
    }

    /// Source lines of the top-level `message {name} {...}` block,
    /// wherever it lives (`mechanism_params.proto` or `types.proto`).
    fn message_block_lines_either(name: &str) -> Vec<&'static str> {
        for source in [MECHANISM_PARAMS_PROTO, TYPES_PROTO] {
            let found = source.lines().any(|line| {
                let line = line.trim_start();
                line.starts_with(&format!("message {name} "))
                    || line.starts_with(&format!("message {name}{{"))
            });
            if found {
                return message_block_lines_in(source, name);
            }
        }
        panic!("message {name} not found in either .proto source");
    }

    #[test]
    fn r21_envelope_union_covers_every_manifest_shape() {
        let r16: BTreeSet<&str> = R16_PRESENCE_TABLE.iter().map(|row| row.1).collect();
        let r18: BTreeSet<&str> = R18_TAIL_TABLE.iter().map(|row| row.1).collect();
        let no_envelope: BTreeSet<&str> = R21_NO_ENVELOPE_SHAPES.iter().map(|row| row.1).collect();
        assert_eq!(r16.len(), R16_PRESENCE_TABLE.len(), "R16 table: one row per shape");
        assert_eq!(r18.len(), R18_TAIL_TABLE.len(), "R18 table: one row per shape");
        assert_eq!(
            no_envelope.len(),
            12,
            "R21 no-envelope table: exactly the 12 scalar/byte-buffer shapes"
        );
        // Pairwise disjoint: every shape has exactly one envelope story.
        assert!(r16.intersection(&r18).next().is_none(), "R16/R18 tables must be disjoint");
        assert!(
            r16.intersection(&no_envelope).next().is_none()
                && r18.intersection(&no_envelope).next().is_none(),
            "no-envelope shapes must sit outside both presence tables"
        );
        assert!(
            !r16.contains("gcm_compat")
                && !r18.contains("gcm_compat")
                && !no_envelope.contains("gcm_compat"),
            "gcm_compat rides the shared gcm row (asserted below), never its own"
        );
        // Union + the two special rows == the manifest exactly.
        let mut union = r16.clone();
        union.extend(r18.iter().copied());
        union.extend(no_envelope.iter().copied());
        union.insert("gcm_compat");
        union.insert("parameterless");
        let in_manifest: BTreeSet<&str> =
            super::manifest().shape.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(in_manifest.len(), 68, "manifest shape count pin");
        assert_eq!(union, in_manifest, "envelope union must equal the manifest exactly");
        // Every S2 §8 family is fully classified (MGF keeps its vacuous pin).
        for (family, shapes) in S2_SECTION_8_FAMILIES {
            if family.starts_with("MGF ") {
                assert!(shapes.is_empty(), "MGF keeps its no-standalone-shape pin");
                continue;
            }
            for shape in *shapes {
                assert!(
                    union.contains(shape),
                    "S2 §8 family {family} shape {shape} has no envelope row"
                );
            }
        }
        // No-envelope rows (owner R21): the wire block carries no
        // presence/count/null-bit line at all.
        for (family, shape, message, why) in R21_NO_ENVELOPE_SHAPES {
            let entry = super::manifest_shape(shape)
                .unwrap_or_else(|| panic!("R21 names unknown shape {shape}"));
            assert!(
                entry.wire_messages.iter().any(|bound| bound == message),
                "R21/{family}/{shape} must bind {message}"
            );
            assert!(
                why.len() > "scalar: ".len(),
                "R21/{shape} must record why no envelope is needed"
            );
            let block = message_block_lines_either(message);
            assert!(
                !block.iter().any(|line| {
                    line.contains("_null") || line.trim_start().starts_with("optional ")
                }),
                "R21/{family}/{shape}: {message} must carry no envelope field ({why})"
            );
        }
        // gcm_compat (owner R16 for the struct form via the shared gcm
        // row; the bare-IV byte form needs no envelope, like `iv`).
        let compat = super::manifest_shape("gcm_compat").expect("gcm_compat entry");
        assert_eq!(
            compat.wire_messages,
            vec!["IvParams".to_string(), "GcmParams".to_string()],
            "gcm_compat still binds both typed messages"
        );
        assert!(r16.contains("gcm"), "gcm_compat struct form rides the R16 gcm row");
        // parameterless (owner R8): rides the unset oneof, no message.
        let marker = super::manifest_shape("parameterless").expect("parameterless entry");
        assert!(marker.wire_messages.is_empty(), "parameterless binds no wire message");
    }

    #[test]
    fn r21_domain_conversion_dispatches_every_wire_message() {
        // Encode = everything above the legacy-bool scan (v0 `try_from`
        // + `to_wire_with_transport_version` + both v1 encoders); decode =
        // the wire `try_from` (the trailing `MechanismInfo` impls convert
        // no params).
        let encode = code_span_before(PROTO_CONVERT_MOD, "fn has_set_legacy_null_bool(");
        let decode = code_span_between(
            PROTO_CONVERT_MOD,
            "fn try_from(m: &v1_proto::Mechanism)",
            "fn from(m: &CkMechanismInfo)",
        );
        let r16: BTreeSet<&str> = R16_PRESENCE_TABLE.iter().map(|row| row.1).collect();
        let r18: BTreeSet<&str> = R18_TAIL_TABLE.iter().map(|row| row.1).collect();
        let conversion_owner = |shape: &str| {
            if r16.contains(shape) || shape == "gcm_compat" {
                "R16(decode)+R17(v1 encode)+R19(legacy removal)"
            } else if r18.contains(shape) {
                "R18(v1 encode+decode)"
            } else {
                "pre-campaign(R21 dispatch pin)"
            }
        };
        let mut messages = 0;
        for entry in super::manifest().shape.iter() {
            for message in entry.wire_messages.iter() {
                messages += 1;
                let owner = conversion_owner(entry.name.as_str());
                let oneof = format!("Params::{}", oneof_variant(message));
                let variant = format!("CkMechanismParams::{}", domain_variant(message));
                assert!(
                    span_contains(&encode, &oneof),
                    "{owner}: encode must dispatch {message} ({} row {})",
                    entry.name,
                    oneof
                );
                assert!(
                    span_contains(&decode, &oneof),
                    "{owner}: decode must dispatch {message} ({} row {})",
                    entry.name,
                    oneof
                );
                assert!(
                    span_contains(&encode, &variant),
                    "{owner}: encode must convert domain {} ({} row)",
                    variant,
                    entry.name
                );
                assert!(
                    span_contains(&decode, &variant),
                    "{owner}: decode must convert domain {} ({} row)",
                    variant,
                    entry.name
                );
            }
        }
        assert_eq!(messages, 68, "per-row wire-message count pin (66 distinct + gcm_compat dual)");
        // Override map exact in both directions: each override is
        // necessary (default name absent both halves) and sufficient
        // (override present both halves — already asserted above); every
        // other message round-trips under its own name (also above).
        for (message, variant) in R21_PROST_ONEOF_OVERRIDES {
            let default = format!("Params::{message}");
            assert!(
                !span_contains(&encode, &default) && !span_contains(&decode, &default),
                "override {message} → {variant} must be necessary (default absent)"
            );
        }
        assert_eq!(
            R21_PROST_ONEOF_OVERRIDES.len(),
            2,
            "exactly the two ChaCha prost renames (any third is a new finding)"
        );
    }

    #[test]
    fn r21_shim_v1_reader_covers_every_shape() {
        let pred17 =
            code_span_between(SHIM_MECHANISM_READ, "fn is_r17_v1_shape(", "fn is_r18_tail_shape(");
        let pred18 = code_span_between(
            SHIM_MECHANISM_READ,
            "fn is_r18_tail_shape(",
            "fn read_v1_typed_params(",
        );
        let typed = code_span_between(
            SHIM_MECHANISM_READ,
            "fn read_v1_typed_params(",
            "fn read_v1_tail_params(",
        );
        let tail = code_span_between(
            SHIM_MECHANISM_READ,
            "fn read_v1_tail_params(",
            "fn read_mechanism_with_shape_budgeted(",
        );
        let budgeted = code_span_between(
            SHIM_MECHANISM_READ,
            "fn read_mechanism_with_shape_budgeted(",
            "fn gcm_iv_buffer_len(",
        );
        let r16: BTreeSet<&str> = R16_PRESENCE_TABLE.iter().map(|row| row.1).collect();
        let r18: BTreeSet<&str> = R18_TAIL_TABLE.iter().map(|row| row.1).collect();
        let mut typed_shapes = r16.clone();
        typed_shapes.insert("gcm_compat");
        // Predicates route exactly the reader sets (R17 38 + R18 17),
        // disjoint from each other.
        assert_eq!(
            quoted_snake_tokens(&pred17),
            typed_shapes,
            "is_r17_v1_shape (R17) must list exactly the 38 typed shapes"
        );
        assert_eq!(
            quoted_snake_tokens(&pred18),
            r18,
            "is_r18_tail_shape (R18) must list exactly the 17 tail shapes"
        );
        assert_eq!(
            some_shape_tokens(&typed),
            typed_shapes,
            "read_v1_typed_params (R17) must arm exactly the 38 typed shapes"
        );
        assert_eq!(
            some_shape_tokens(&tail),
            r18,
            "read_v1_tail_params (R18) must arm exactly the 17 tail shapes"
        );
        assert!(
            typed_shapes.intersection(&r18).next().is_none(),
            "R17/R18 reader sets must be disjoint"
        );
        // The pre-existing typed reader arms every non-parameterless
        // shape; scalar/byte-buffer shapes reach it through the R17 v1
        // fallback (wired below), whose Raw fallbacks v1 rejects locally.
        let budgeted_shapes = some_shape_tokens(&budgeted);
        let mut all_but_marker: BTreeSet<&str> =
            super::manifest().shape.iter().map(|entry| entry.name.as_str()).collect();
        assert!(all_but_marker.remove("parameterless"), "parameterless entry exists");
        assert_eq!(
            budgeted_shapes, all_but_marker,
            "budgeted typed reader must arm every non-parameterless shape"
        );
        // parameterless (owner R11) rides the outer None/Flat path: no
        // reader arm anywhere.
        for (region, span) in [
            ("is_r17_v1_shape", &pred17),
            ("is_r18_tail_shape", &pred18),
            ("typed", &typed),
            ("tail", &tail),
            ("budgeted", &budgeted),
        ] {
            assert!(
                !span_contains(span, "\"parameterless\""),
                "R11: parameterless must have no {region} arm"
            );
        }
        // Fallback wiring (owner R17): the v1 typed branch tries the
        // step-1 readers first, then the existing reader with Raw
        // rejected locally (never emitted on v1).
        let fallback = code_span_between(
            SHIM_MECHANISM_READ,
            "fn read_typed_under_v1(",
            "fn read_flat_under_v1(",
        );
        for symbol in [
            "is_r17_v1_shape",
            "read_v1_typed_params",
            "is_r18_tail_shape",
            "read_v1_tail_params",
            "read_mechanism_with_shape_budgeted",
            "CkMechanismParams::Raw",
            "MECHANISM_PARAM_INVALID",
        ] {
            assert!(span_contains(&fallback, symbol), "R17 fallback must reference {symbol}");
        }
    }

    #[test]
    fn r21_backend_reconstruction_covers_every_variant() {
        let body = code_span_between(
            BACKEND_MECHANISM,
            "fn mechanism_to_ffi_at_depth(",
            "fn gcm_iv_capacity(",
        );
        let r16: BTreeSet<&str> = R16_PRESENCE_TABLE.iter().map(|row| row.1).collect();
        let r18: BTreeSet<&str> = R18_TAIL_TABLE.iter().map(|row| row.1).collect();
        let backend_owner = |shape: &str| {
            if r16.contains(shape) || r18.contains(shape) || shape == "gcm_compat" {
                "R19(mechanism_to_ffi_at_depth)"
            } else {
                "pre-campaign arm(R21 pin: scalar/byte-buffer, no presence)"
            }
        };
        let mut variants = 0;
        for entry in super::manifest().shape.iter() {
            for message in entry.wire_messages.iter() {
                variants += 1;
                let arm = format!("CkMechanismParams::{}", domain_variant(message));
                let armed = body.iter().any(|line| line.contains(&arm) && line.contains("=>"));
                assert!(
                    armed,
                    "{}: backend must reconstruct {} ({} row {arm})",
                    backend_owner(entry.name.as_str()),
                    entry.name,
                    message
                );
            }
        }
        assert_eq!(variants, 68, "per-row variant count pin (66 distinct + gcm_compat dual)");
        // parameterless rides None (current arm form via the R12
        // mechanism_to_ffi rework; origin pre-campaign).
        assert!(
            body.iter().any(|line| line.contains("None")
                && line.contains("=>")
                && line.contains("no_param")),
            "R12: backend must map params None (parameterless) via no_param"
        );
        // Generic envelopes need no per-shape arm (owner R12).
        for generic in ["CkMechanismParams::Flat", "CkMechanismParams::Null"] {
            assert!(
                body.iter().any(|line| line.contains(generic) && line.contains("=>")),
                "R12: backend must reconstruct generic {generic}"
            );
        }
    }

    /// FNV-1a 64 over bytes: std-only and deterministic across runs (the
    /// freeze digest must not depend on a random seed).
    fn fnv1a_64(bytes: &[u8]) -> u64 {
        let mut hash = 0xcbf29ce484222325u64;
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }

    /// Frozen manifest digest (R21): FNV-1a 64 of the checked-in
    /// [`MANIFEST_TOML`](super::MANIFEST_TOML). Manifest entries are
    /// immutable from here — any later layout change requires a new
    /// transport version (S2 §3 fingerprint freeze). A digest change
    /// without a version bump fails REVIEW, not the test: the test pins
    /// the value; the R-task review verdicts any change.
    const MANIFEST_DIGEST: u64 = 0x8f88efabb3d6cbab;

    #[test]
    fn r21_manifest_digest_freeze() {
        assert_eq!(
            fnv1a_64(super::MANIFEST_TOML.as_bytes()),
            MANIFEST_DIGEST,
            "frozen manifest digest changed: review any manifest edit against \
             S2 §8 + the S2 §3 version rule before updating MANIFEST_DIGEST"
        );
    }
}
