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
//! half of the S2 §11 Phase-2 gate — reads the embedded TOML. R21 flips the
//! tail bindings to complete (plus regeneration) once the Phase-3 rows land;
//! R23 asserts [`manifest_complete`] at advertisement time and refuses to
//! advertise v1 while it is false. Until R21 the predicate is pinned false
//! with the exact pending list
//! (`manifest_incomplete_by_construction_until_r21`).
//!
//! The manifest ↔ proto cross-check lives in this crate (not in `proto`)
//! because the dependency runs `proto → types`: `types` cannot name the
//! generated wire types, so the tests match wire-message names against the
//! `.proto` sources via `include_str!` (same repository — standalone-safe).
//! Presence-field coverage is asserted COMPLETE only in R21; here the tests
//! assert the input-pointer wire messages exist and the tail is explicitly
//! listed as pending.
//!
//! No behavior change: this module is unwired tables + tests (R8 is Phase 1).

use std::sync::OnceLock;

use serde::Deserialize;

use self::ManifestStatus::{Complete, PendingTail};
use crate::shape_descriptors::{Operation, OuterKind, ParamAbi, ResolvedShape, ShapeResolver};

// ─── Human-attested bindings (single edit point) ──────────────────────────────

/// Completion status of one manifest entry.
///
/// R21 flips every [`ManifestStatus::PendingTail`] to
/// [`ManifestStatus::Complete`] (plus TOML regeneration) once the Phase-3
/// tail rows land; only then may [`manifest_complete`] return true.
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
    bind("kea_derive", &["KeaDeriveParams"], PendingTail, &[2, 3], V1),
    // S2 §8 "KDF string-data".
    bind("key_derivation_string", &["KeyDerivationStringData"], Complete, &[], V1),
    // S2 §8 "OAEP" (SET cousin rides the same family).
    bind("key_wrap_set_oaep", &["KeyWrapSetOaepParams"], Complete, &[], V1),
    // S2 §8 "KIP" (tail: nested mechanism; input-only fields).
    bind("kip", &["KipParams"], PendingTail, &[], V1),
    // S2 §8 "KMAC".
    bind("kmac", &["KmacParams"], Complete, &[], V1),
    bind("mac_general", &["MacGeneralParams"], Complete, &[], V1),
    bind("mu_gen", &["MuGenParams"], Complete, &[], V1),
    bind("object_handle", &["ObjectHandleParam"], Complete, &[], V1),
    // S2 §8 "OTP/SP800-108" (tail: counted struct array; input-only).
    bind("otp", &["OtpParams"], PendingTail, &[], V1),
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
    bind("skipjack_private_wrap", &["SkipjackPrivateWrapParams"], PendingTail, &[], V1),
    bind("skipjack_relayx", &["SkipjackRelayxParams"], PendingTail, &[], V1),
    // S2 §8 "OTP/SP800-108" (tail: output = additional-derived-keys array).
    bind("sp800_108_feedback_kdf", &["Sp800108FeedbackKdfParams"], PendingTail, &[6], V1),
    bind("sp800_108_kdf", &["Sp800108KdfParams"], PendingTail, &[4], V1),
    // S2 §8 "key-mat" (tail: output = returned key material).
    bind("ssl3_key_mat", &["Ssl3KeyMatParams"], PendingTail, &[5], V1),
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
    bind("tls_prf", &["TlsPrfParams"], PendingTail, &[4, 5], V1),
    bind("wtls_key_mat", &["WtlsKeyMatParams"], PendingTail, &[7], V1),
    bind("wtls_master_key_derive", &["WtlsMasterKeyDeriveParams"], Complete, &[], V1),
    bind("wtls_prf", &["WtlsPrfParams"], PendingTail, &[5, 6], V1),
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
/// entry is complete. R21 flips this to true (tail rows complete); R23
/// asserts it at advertisement time and refuses v1 while it is false.
/// Pinned false with the exact pending list until R21.
pub fn manifest_complete() -> bool {
    // Fail closed on an empty manifest: `all()` is vacuously true.
    !manifest().shape.is_empty()
        && manifest().shape.iter().all(|entry| entry.status == ManifestStatus::Complete)
}

/// Shape IDs still pending (the tail until R21), in manifest order.
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

    use super::{MANIFEST_VERSION, ManifestForm, outer_kind_name};
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
    fn manifest_incomplete_by_construction_until_r21() {
        assert!(!super::manifest_complete(), "R21 flips this pin (tail pending until then)");
        assert_eq!(
            super::pending_shapes(),
            vec![
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
            ],
            "exact pending tail (R21 completes it)"
        );
    }

    #[test]
    fn pending_tail_is_exactly_nested_or_output() {
        let tail: BTreeSet<&str> = SHAPE_DESCRIPTORS
            .iter()
            .filter(|descriptor| descriptor.outer_kind == OuterKind::NestedOrOutput)
            .map(|descriptor| descriptor.name)
            .collect();
        let pending: BTreeSet<&str> = super::pending_shapes().into_iter().collect();
        assert_eq!(pending, tail, "pending set must equal the NestedOrOutput set");
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
}
