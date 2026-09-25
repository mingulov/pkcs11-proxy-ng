//! ADR-0013 redacted generated-message diagnostics (C3M Task 7.2).
//!
//! prost generates a `Debug` impl for every wire message and oneof enum that
//! prints every field. `crates/proto/build.rs` instead derives the redacted
//! set from `secret-fields.toml` on every build: every secret-bearing message
//! gets `skip_debug` plus a whole-message `TypeName([REDACTED])` impl, as do
//! the oneof enums under a redacted parent. These tests prove the behavior
//! and audit the generated set against the manifest, so a new secret field
//! cannot silently regain a payload-printing `Debug`.

use std::collections::BTreeSet;

use pkcs11_proxy_ng_proto::{
    REDACTED_WIRE_MESSAGES,
    attribute::Value as AttributeValue,
    attribute_result::Result as AttributeResultValue,
    authenticated_mechanism_output::Output as AuthenticatedOutput,
    message_parameter::Params as MessageParams,
    message_parameter_effects::Effect as MessageEffect,
    pkcs11_proxy_ng::v1::{
        Attribute, AttributeResult, AuthenticatedMechanismOutput, AuthenticatedParameters,
        CcmMessageEffects, DecryptResponse, EncryptResponse, GcmMessageEffects, GcmParams,
        LoginRequest, MessageParameter, MessageParameterEffects, SalsaMessageEffects,
        SeedRandomRequest, SignRequest, Sp800108Attribute,
    },
    sp800108_attribute::Value as Sp800108Value,
};

/// Authentication tag/parameter envelopes redacted at BASE although none of
/// their own bytes/string fields is secret-classified. Mirrors
/// `EXTRA_REDACTED_MESSAGES` in `crates/proto/build.rs` deliberately: adding
/// or removing an extra must update both sites with review.
const EXPECTED_EXTRAS: &[&str] = &[
    "AuthenticatedParameters",
    "CcmMessageEffects",
    "GcmMessageEffects",
    "MessageParameterEffects",
    "SalsaMessageEffects",
];

fn secret_bearing_messages() -> BTreeSet<String> {
    let manifest: toml::Value =
        include_str!("../secret-fields.toml").parse().expect("secret-fields.toml must parse");
    let secret =
        manifest.get("secret").and_then(toml::Value::as_table).expect("missing [secret] table");
    let mut messages = BTreeSet::new();
    for (category, value) in secret {
        let fields =
            value.as_array().unwrap_or_else(|| panic!("[secret].{category} must be an array"));
        for field in fields {
            let field = field.as_str().expect("manifest entries must be strings");
            let mut parts = field.split('.');
            match (parts.next(), parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some("pkcs11_proxy_ng"), Some("v1"), Some(message), Some(_), None) => {
                    messages.insert(message.to_owned());
                }
                _ => panic!("malformed manifest entry {field:?}"),
            }
        }
    }
    assert!(!messages.is_empty());
    messages
}

#[test]
fn redacted_set_covers_every_secret_bearing_message_exactly() {
    let mut expected = secret_bearing_messages();
    expected.extend(EXPECTED_EXTRAS.iter().map(ToString::to_string));
    let actual: BTreeSet<String> = REDACTED_WIRE_MESSAGES.iter().map(ToString::to_string).collect();

    let missing: Vec<_> = expected.difference(&actual).collect();
    assert!(missing.is_empty(), "secret-bearing messages without redacted Debug: {missing:?}");

    let extra: Vec<_> = actual.difference(&expected).collect();
    assert!(
        extra.is_empty(),
        "redacted messages that are neither secret-bearing nor reviewed extras: {extra:?}"
    );
}

#[test]
fn authentication_envelope_extras_stay_redacted() {
    for message in EXPECTED_EXTRAS {
        assert!(
            REDACTED_WIRE_MESSAGES.contains(message),
            "reviewed BASE redaction of {message} must not regress"
        );
    }
}

/// A PIN canary that would be unmistakable in a derived `Debug`
/// (`Some([222, 173, 190, 239])`).
const PIN_CANARY: [u8; 4] = [222, 173, 190, 239];

#[test]
fn pin_and_secret_request_debug_renders_no_payload() {
    let login = LoginRequest {
        client_context_id: String::new(),
        session_handle: 7,
        user_type: 1,
        pin: Some(PIN_CANARY.to_vec()),
    };
    assert_eq!(format!("{login:?}"), "LoginRequest([REDACTED])");

    let sign = SignRequest {
        client_context_id: String::from("ctx"),
        session_handle: 7,
        data: PIN_CANARY.to_vec(),
        data_null_len: None,
    };
    assert_eq!(format!("{sign:?}"), "SignRequest([REDACTED])");

    let seed = SeedRandomRequest {
        client_context_id: String::new(),
        session_handle: 7,
        seed: PIN_CANARY.to_vec(),
        seed_null_len: None,
    };
    assert_eq!(format!("{seed:?}"), "SeedRandomRequest([REDACTED])");
}

#[test]
fn secret_response_and_mechanism_debug_renders_no_payload() {
    let decrypt = DecryptResponse { ck_rv: 0, data: PIN_CANARY.to_vec(), mechanism_out: None };
    assert_eq!(format!("{decrypt:?}"), "DecryptResponse([REDACTED])");

    let gcm = GcmParams {
        iv: PIN_CANARY.to_vec(),
        iv_bits: 96,
        aad: PIN_CANARY.to_vec(),
        tag_bits: 128,
        iv_buffer_len: 0,

        iv_null: false,
        aad_null: false,
    };
    assert_eq!(format!("{gcm:?}"), "GcmParams([REDACTED])");
}

#[test]
fn attribute_and_message_parameter_oneofs_render_no_payload() {
    let attribute =
        Attribute { attr_type: 0x11, value: Some(AttributeValue::BytesValue(PIN_CANARY.to_vec())) };
    assert_eq!(format!("{attribute:?}"), "Attribute([REDACTED])");
    assert_eq!(
        format!("{:?}", AttributeValue::StringValue(String::from("canary-string"))),
        "attribute.Value([REDACTED])"
    );

    let result = AttributeResult {
        attr_type: 0x11,
        actual_length: 4,
        result: Some(AttributeResultValue::Value(PIN_CANARY.to_vec())),
    };
    assert_eq!(format!("{result:?}"), "AttributeResult([REDACTED])");
    assert_eq!(
        format!("{:?}", AttributeResultValue::Value(PIN_CANARY.to_vec())),
        "attribute_result.Result([REDACTED])"
    );

    let parameter = MessageParameter { params: Some(MessageParams::Raw(PIN_CANARY.to_vec())) };
    assert_eq!(format!("{parameter:?}"), "MessageParameter([REDACTED])");
    assert_eq!(
        format!("{:?}", MessageParams::Raw(PIN_CANARY.to_vec())),
        "message_parameter.Params([REDACTED])"
    );

    let sp800108 = Sp800108Attribute {
        attr_type: 1,
        value: Some(Sp800108Value::BytesValue(PIN_CANARY.to_vec())),
    };
    assert_eq!(format!("{sp800108:?}"), "Sp800108Attribute([REDACTED])");
    assert_eq!(
        format!("{:?}", Sp800108Value::BytesValue(PIN_CANARY.to_vec())),
        "sp800108_attribute.Value([REDACTED])"
    );
}

#[test]
fn authenticated_mechanism_output_oneof_renders_no_payload() {
    let parent =
        AuthenticatedMechanismOutput { output: Some(AuthenticatedOutput::Iv(PIN_CANARY.to_vec())) };
    assert_eq!(format!("{parent:?}"), "AuthenticatedMechanismOutput([REDACTED])");
    assert_eq!(
        format!("{:?}", AuthenticatedOutput::Unchanged(true)),
        "authenticated_mechanism_output.Output([REDACTED])"
    );
    // The secret member (`bytes iv = 2`, manifest `key_attributes_material`).
    assert_eq!(
        format!("{:?}", AuthenticatedOutput::Iv(PIN_CANARY.to_vec())),
        "authenticated_mechanism_output.Output([REDACTED])"
    );
    let parameter = MessageParameter { params: Some(MessageParams::Raw(PIN_CANARY.to_vec())) };
    assert_eq!(
        format!("{:?}", AuthenticatedOutput::MessageParameter(parameter)),
        "authenticated_mechanism_output.Output([REDACTED])"
    );
    let effects = MessageParameterEffects { effect: None };
    assert_eq!(
        format!("{:?}", AuthenticatedOutput::MessageEffects(effects)),
        "authenticated_mechanism_output.Output([REDACTED])"
    );
}

#[test]
fn message_parameter_effects_oneof_renders_no_payload() {
    let parent = MessageParameterEffects {
        effect: Some(MessageEffect::Gcm(GcmMessageEffects {
            iv: Some(PIN_CANARY.to_vec()),
            tag: Some(PIN_CANARY.to_vec()),
        })),
    };
    assert_eq!(format!("{parent:?}"), "MessageParameterEffects([REDACTED])");
    // Every member message is itself redacted; the enum level must not print them either.
    assert_eq!(
        format!(
            "{:?}",
            MessageEffect::Gcm(GcmMessageEffects {
                iv: Some(PIN_CANARY.to_vec()),
                tag: Some(PIN_CANARY.to_vec())
            })
        ),
        "message_parameter_effects.Effect([REDACTED])"
    );
    assert_eq!(
        format!(
            "{:?}",
            MessageEffect::Ccm(CcmMessageEffects {
                nonce: Some(PIN_CANARY.to_vec()),
                mac: Some(PIN_CANARY.to_vec())
            })
        ),
        "message_parameter_effects.Effect([REDACTED])"
    );
    assert_eq!(
        format!(
            "{:?}",
            MessageEffect::Salsa(SalsaMessageEffects { tag: Some(PIN_CANARY.to_vec()) })
        ),
        "message_parameter_effects.Effect([REDACTED])"
    );
}

/// The oneof enums under a redacted parent, each with a generated
/// `Path([REDACTED])` impl. Mirrors `build.rs` emission: every oneof whose
/// parent message is in the redacted set gets a manual `Debug` impl. A
/// dropped impl falls back to derived `Debug` (payload-printing), so this
/// audits the generated file directly — the failure names the missing impl.
/// (`mechanism::Params` is the deliberate exception: message-only variants,
/// each redacted-or-safe; see the 7.2 report.)
const EXPECTED_ONEOF_IMPLS: &[&str] = &[
    "attribute::Value",
    "attribute_result::Result",
    "authenticated_mechanism_output::Output",
    "message_parameter::Params",
    "message_parameter_effects::Effect",
    "sp800108_attribute::Value",
];

#[test]
fn emitted_oneof_debug_impls_match_expected_set_exactly() {
    let generated = std::fs::read_to_string(concat!(env!("OUT_DIR"), "/redacted_debug_gen.rs"))
        .expect("build.rs must emit redacted_debug_gen.rs");
    const PREFIX: &str = "impl ::std::fmt::Debug for crate::pkcs11_proxy_ng::v1::";
    let mut actual: Vec<&str> = generated
        .lines()
        .filter_map(|line| line.strip_prefix(PREFIX))
        .filter_map(|path| path.strip_suffix(" {"))
        .filter(|path| path.contains("::"))
        .collect();
    actual.sort();
    assert_eq!(actual, EXPECTED_ONEOF_IMPLS, "emitted oneof Debug impl set drifted");
}

#[test]
fn base_authentication_envelopes_keep_exact_redacted_format() {
    let effects =
        GcmMessageEffects { iv: Some(PIN_CANARY.to_vec()), tag: Some(PIN_CANARY.to_vec()) };
    assert_eq!(format!("{effects:?}"), "GcmMessageEffects([REDACTED])");

    let parameters = AuthenticatedParameters { message_parameter: None };
    assert_eq!(format!("{parameters:?}"), "AuthenticatedParameters([REDACTED])");

    let parameter_effects = MessageParameterEffects { effect: None };
    assert_eq!(format!("{parameter_effects:?}"), "MessageParameterEffects([REDACTED])");
}

#[test]
fn safe_metadata_messages_keep_derived_debug() {
    // `safe_metadata` (here: ciphertext) stays printable by design: the
    // classification decides wiping ownership, not loggability (ADR-0013 §3).
    // This test locks the other direction — redaction must not swallow types
    // the manifest classifies as safe metadata.
    let response = EncryptResponse { ck_rv: 0, encrypted_data: vec![1, 2, 3], mechanism_out: None };
    let rendered = format!("{response:?}");
    assert!(rendered.contains("encrypted_data"), "unexpected: {rendered}");
    assert!(rendered.contains("[1, 2, 3]"), "unexpected: {rendered}");
}
