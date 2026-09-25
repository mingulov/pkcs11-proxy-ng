//! W1-C8-11 (FOLLOWUP-zeroize-proto): PIN/password prost messages wipe on drop.
//!
//! `crates/proto/build.rs` derives `Zeroize` + `ZeroizeOnDrop` on the five
//! PIN-bearing request messages at codegen time, so the decoded buffers the
//! borrow-based conversions copy out of are overwritten when the prost
//! message drops instead of being freed plain. Mirrors the PBE/Skipjack
//! canary pattern in `convert::mechanism::tests`: `ZeroizeOnDrop` delegates
//! drop-wiping to `zeroize`, and post-drop memory is unobservable, so the
//! test pins the wipe behavior directly plus a compile-time `ZeroizeOnDrop`
//! bound per message.

use pkcs11_proxy_ng_proto::{
    Attribute, AuthenticatedMechanismOutput, CmsSigParams, DecryptResponse, EciesParams,
    EncryptRequest, GenerateRandomResponse, InitPinRequest, InitTokenRequest, KipParams,
    LoginRequest, LoginUserRequest, Mechanism, MessageParameter, OtpParam, ParameterRoundtripSpec,
    SeedRandomRequest, SetPinRequest, WrapKeyResponse, ZEROIZE_SKIPPED_BOXED_FIELDS,
    ZEROIZED_WIRE_MESSAGES, attribute::Value as AttributeValue,
    authenticated_mechanism_output::Output as AuthenticatedOutput,
    message_parameter::Params as MessageParams,
};
use zeroize::Zeroize;

fn assert_canary_nonempty(label: &str, bytes: &[u8]) {
    assert!(!bytes.is_empty(), "{label} canary must be non-empty before zeroize");
    assert!(bytes.iter().any(|&byte| byte != 0), "{label} canary must be nonzero before zeroize");
}

#[test]
fn pin_request_messages_zeroize_wipes_secrets() {
    // All fields spelled out: struct-update syntax cannot move fields out
    // of a `ZeroizeOnDrop` value.
    let mut login = LoginRequest {
        client_context_id: "ctx".to_string(),
        session_handle: 1,
        user_type: 1,
        pin: Some(vec![0xA5u8; 16]),
    };
    assert_canary_nonempty("LoginRequest.pin", login.pin.as_deref().unwrap_or_default());
    login.zeroize();
    // `Option::zeroize` wipes the inner buffer, then clears presence: no
    // secret bytes remain reachable in any form.
    assert!(login.pin.is_none(), "LoginRequest.pin must not survive zeroize");

    let mut login_user = LoginUserRequest {
        client_context_id: "ctx".to_string(),
        session_handle: 1,
        user_type: 1,
        pin: Some(vec![0x5Au8; 16]),
        username: Some(vec![0x55u8; 8]),
    };
    assert_canary_nonempty("LoginUserRequest.pin", login_user.pin.as_deref().unwrap_or_default());
    assert_canary_nonempty(
        "LoginUserRequest.username",
        login_user.username.as_deref().unwrap_or_default(),
    );
    login_user.zeroize();
    // `Option::zeroize` wipes the inner buffer, then clears presence: no
    // secret bytes remain reachable in any form (same as `LoginRequest`).
    assert!(login_user.pin.is_none(), "LoginUserRequest.pin must not survive zeroize");
    assert!(login_user.username.is_none(), "LoginUserRequest.username must not survive zeroize");

    let mut init_token = InitTokenRequest {
        client_context_id: "ctx".to_string(),
        slot_id: 7,
        so_pin: Some(vec![0x3Cu8; 16]),
        label: "token".to_string(),
    };
    assert_canary_nonempty(
        "InitTokenRequest.so_pin",
        init_token.so_pin.as_deref().unwrap_or_default(),
    );
    init_token.zeroize();
    assert!(init_token.so_pin.is_none(), "InitTokenRequest.so_pin must not survive zeroize");

    let mut init_pin = InitPinRequest {
        client_context_id: "ctx".to_string(),
        session_handle: 1,
        pin: Some(vec![0xC3u8; 16]),
    };
    assert_canary_nonempty("InitPinRequest.pin", init_pin.pin.as_deref().unwrap_or_default());
    init_pin.zeroize();
    assert!(init_pin.pin.is_none(), "InitPinRequest.pin must not survive zeroize");

    let mut set_pin = SetPinRequest {
        client_context_id: "ctx".to_string(),
        session_handle: 1,
        old_pin: Some(vec![0x0Fu8; 16]),
        new_pin: Some(vec![0xF0u8; 16]),
    };
    assert_canary_nonempty("SetPinRequest.old_pin", set_pin.old_pin.as_deref().unwrap_or_default());
    assert_canary_nonempty("SetPinRequest.new_pin", set_pin.new_pin.as_deref().unwrap_or_default());
    set_pin.zeroize();
    assert!(set_pin.old_pin.is_none(), "SetPinRequest.old_pin must not survive zeroize");
    assert!(set_pin.new_pin.is_none(), "SetPinRequest.new_pin must not survive zeroize");
}

#[test]
fn pin_request_messages_wipe_on_drop() {
    // Compile-time pin (PBE canary pattern): dropping any of these
    // owners from the build.rs wipe closure must fail compilation here.
    fn assert_wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_wiped_on_drop::<LoginRequest>();
    assert_wiped_on_drop::<LoginUserRequest>();
    assert_wiped_on_drop::<InitTokenRequest>();
    assert_wiped_on_drop::<InitPinRequest>();
    assert_wiped_on_drop::<SetPinRequest>();
}

/// W1-L2-09: `OtpParam.value` is `pin_auth`-classified and copied out by
/// the borrow-based OTP conversion, so the message gets the same
/// codegen treatment as the other PIN/password messages. Unlike the
/// request messages above, `value` is a bare (non-`optional`) `bytes`
/// field, so `zeroize` wipes the buffer in place rather than clearing
/// presence. The `OtpParams` wrapper needs no derive: dropping its
/// `Vec<OtpParam>` runs each element's `ZeroizeOnDrop`.
#[test]
fn otp_param_value_zeroizes_and_wipes_on_drop() {
    fn assert_wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_wiped_on_drop::<OtpParam>();

    let mut otp = OtpParam { r#type: 1, value: vec![0xA5u8; 8] };
    assert_canary_nonempty("OtpParam.value", &otp.value);
    otp.zeroize();
    assert!(otp.value.iter().all(|byte| *byte == 0), "OtpParam.value must not survive zeroize");
}

/// W1-L2-09: every `pin_auth` field's owner message must be a
/// `ZeroizeOnDrop` prost message (each pinned individually by the canary
/// bounds above). A new PIN/password field lands here automatically via
/// the manifest parse and fails until its owner gains the wipe closure
/// derive plus a canary bound. (`LoginUserRequest.username` is
/// secret-classified under `unknown_vendor` and covered by that
/// checkpoint; T12 wipes every `[secret]` category.)
const PIN_AUTH_ZEROIZED_MESSAGES: &[&str] = &[
    "InitPinRequest",
    "InitTokenRequest",
    "LoginRequest",
    "LoginUserRequest",
    "OtpParam",
    "PbeParams",
    "Pkcs5Pbkd2Params",
    "SetPinRequest",
    "SkipjackPrivateWrapParams",
    "SkipjackRelayxParams",
];

#[test]
fn pin_auth_manifest_owners_match_zeroized_set_exactly() {
    let manifest: toml::Value =
        include_str!("../secret-fields.toml").parse().expect("secret-fields.toml must parse");
    let pin_auth = manifest
        .get("secret")
        .and_then(|secret| secret.get("pin_auth"))
        .and_then(toml::Value::as_array)
        .expect("missing [secret].pin_auth array");
    let mut owners = std::collections::BTreeSet::new();
    for field in pin_auth {
        let field = field.as_str().expect("manifest entries must be strings");
        let mut parts = field.split('.');
        match (parts.next(), parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some("pkcs11_proxy_ng"), Some("v1"), Some(message), Some(_), None) => {
                owners.insert(message.to_owned());
            }
            _ => panic!("malformed manifest entry {field:?}"),
        }
    }
    let expected: std::collections::BTreeSet<String> =
        PIN_AUTH_ZEROIZED_MESSAGES.iter().map(ToString::to_string).collect();
    assert_eq!(owners, expected, "pin_auth owner set drifted");
}

/// T12: auto-boxed back-edges (`Option<Box<Mechanism>>`) carry
/// `#[zeroize(skip)]` because `zeroize` implements `Zeroize` for neither
/// `Box<T>` nor (transitively) the `Option`. Skipping is sound only because
/// the boxed target self-wipes: this test pins the wipe pair on the target
/// and on every current skipped parent (compile-time bounds — deleting a
/// derive in build.rs fails here), pins the runtime tradeoff explicitly
/// (`.zeroize()` wipes the parent's own buffers but does not propagate into
/// the box), and audits the emitted skip list (every entry must name a
/// closure member). Drop-time wipe of the box contents follows from
/// `Mechanism: ZeroizeOnDrop` running when the box drops with the parent;
/// post-drop memory is unobservable, so (as with the PIN canaries above) the
/// bound plus the codegen per-site assert are the proof, not a memory read.
#[test]
fn boxed_back_edge_skip_preserves_drop_wipe_chain() {
    fn assert_wipe_pair<T: Zeroize + zeroize::ZeroizeOnDrop>() {}
    assert_wipe_pair::<Mechanism>();
    assert_wipe_pair::<KipParams>();
    assert_wipe_pair::<EciesParams>();
    assert_wipe_pair::<CmsSigParams>();

    for site in ZEROIZE_SKIPPED_BOXED_FIELDS {
        let (message, field) = site.split_once('.').expect("skip site must be Message.field");
        assert!(
            ZEROIZED_WIRE_MESSAGES.contains(&message),
            "skipped {site} names a message outside the wipe closure",
        );
        assert!(!field.is_empty(), "skipped {site} names an empty field");
    }

    let mechanism = || Mechanism { mechanism_type: 1, params: None };
    let mut kip =
        KipParams { mechanism: Some(Box::new(mechanism())), key_handle: 9, seed: vec![0xA5u8; 8] };
    assert_canary_nonempty("KipParams.seed", &kip.seed);
    kip.zeroize();
    assert!(kip.seed.iter().all(|byte| *byte == 0), "KipParams.seed must not survive zeroize");
    // Pinned tradeoff: the skipped box survives explicit `.zeroize()` (its
    // target self-wipes on drop instead — bound asserted above).
    assert!(kip.mechanism.is_some(), "skipped box must survive explicit zeroize");

    let mut ecies = EciesParams {
        derivation_mechanism: Some(Box::new(mechanism())),
        encryption_mechanism: None,
        mac_mechanism: None,
        shared_data: vec![0x5Au8; 8],
    };
    ecies.zeroize();
    assert!(
        ecies.shared_data.iter().all(|byte| *byte == 0),
        "EciesParams.shared_data must not survive zeroize"
    );
    assert!(ecies.derivation_mechanism.is_some(), "skipped box must survive explicit zeroize");
}

/// T12 checkpoint helper: every manifest owner of a `[secret]` category
/// must be in the emitted wipe closure. Subset (not exact match):
/// the closure also carries transit vessels with no secret bytes of their
/// own.
fn assert_category_owners_zeroized(category: &str) {
    let manifest: toml::Value =
        include_str!("../secret-fields.toml").parse().expect("secret-fields.toml must parse");
    let entries = manifest
        .get("secret")
        .and_then(|secret| secret.get(category))
        .and_then(toml::Value::as_array)
        .unwrap_or_else(|| panic!("missing [secret].{category} array"));
    assert!(!entries.is_empty(), "[secret].{category} must not be empty");
    let zeroized: std::collections::BTreeSet<&str> =
        ZEROIZED_WIRE_MESSAGES.iter().copied().collect();
    for field in entries {
        let field = field.as_str().expect("manifest entries must be strings");
        let mut parts = field.split('.');
        match (parts.next(), parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some("pkcs11_proxy_ng"), Some("v1"), Some(message), Some(_), None) => {
                assert!(
                    zeroized.contains(message),
                    "[secret].{category} owner {message} is missing from the wipe closure",
                );
            }
            _ => panic!("malformed manifest entry {field:?}"),
        }
    }
}

/// T12 checkpoint `key_attributes_material`: key bytes, attribute values,
/// and wrapped-key blobs wipe. Covers the bare-bytes field
/// (`WrapKeyResponse.wrapped_key`), the oneof-carrying parent (`Attribute`),
/// and the oneof enum itself (`Attribute.Value`, `Authenticated.Output`),
/// each with a bound pin plus a runtime canary.
#[test]
fn key_attributes_material_checkpoint() {
    assert_category_owners_zeroized("pin_auth");
    assert_category_owners_zeroized("key_attributes_material");

    fn assert_wipe_pair<T: Zeroize + zeroize::ZeroizeOnDrop>() {}
    assert_wipe_pair::<WrapKeyResponse>();
    assert_wipe_pair::<Attribute>();
    assert_wipe_pair::<AttributeValue>();
    assert_wipe_pair::<AuthenticatedMechanismOutput>();
    assert_wipe_pair::<AuthenticatedOutput>();

    let mut wrap = WrapKeyResponse { ck_rv: 0, wrapped_key: vec![0xA5u8; 16] };
    assert_canary_nonempty("WrapKeyResponse.wrapped_key", &wrap.wrapped_key);
    wrap.zeroize();
    assert!(
        wrap.wrapped_key.iter().all(|byte| *byte == 0),
        "WrapKeyResponse.wrapped_key must not survive zeroize"
    );

    let mut attribute =
        Attribute { attr_type: 0x11, value: Some(AttributeValue::BytesValue(vec![0x5Au8; 8])) };
    attribute.zeroize();
    assert!(attribute.value.is_none(), "Attribute.value must not survive zeroize");

    let mut value = AttributeValue::BytesValue(vec![0x5Au8; 8]);
    value.zeroize();
    // By reference: the payload cannot move out of a `ZeroizeOnDrop` enum.
    match &value {
        AttributeValue::BytesValue(bytes) => {
            assert!(bytes.iter().all(|byte| *byte == 0), "oneof payload must wipe in place");
        }
        other => panic!("zeroize must not change the oneof variant, got {other:?}"),
    }

    let mut output =
        AuthenticatedMechanismOutput { output: Some(AuthenticatedOutput::Iv(vec![0x3Cu8; 12])) };
    output.zeroize();
    assert!(
        output.output.is_none(),
        "AuthenticatedMechanismOutput.output must not survive zeroize"
    );
}

/// T12 checkpoint `seed_state`: RNG seeds, operation-state blobs, and KDF
/// salt/info wipe. (`KipParams.seed` is already canaried by the boxed
/// back-edge test above.)
#[test]
fn seed_state_checkpoint() {
    assert_category_owners_zeroized("seed_state");

    fn assert_wipe_pair<T: Zeroize + zeroize::ZeroizeOnDrop>() {}
    assert_wipe_pair::<SeedRandomRequest>();
    assert_wipe_pair::<GenerateRandomResponse>();

    let mut seed = SeedRandomRequest {
        client_context_id: "ctx".to_string(),
        session_handle: 1,
        seed: vec![0xA5u8; 32],
        seed_null_len: None,
    };
    assert_canary_nonempty("SeedRandomRequest.seed", &seed.seed);
    seed.zeroize();
    assert!(
        seed.seed.iter().all(|byte| *byte == 0),
        "SeedRandomRequest.seed must not survive zeroize"
    );

    let mut random = GenerateRandomResponse { ck_rv: 0, random_data: vec![0x5Au8; 32] };
    assert_canary_nonempty("GenerateRandomResponse.random_data", &random.random_data);
    random.zeroize();
    assert!(
        random.random_data.iter().all(|byte| *byte == 0),
        "GenerateRandomResponse.random_data must not survive zeroize"
    );
}

/// T12 checkpoint `plaintext_decrypted`: operation input/output plaintext
/// wipes — the largest category (single/multi-part and message-crypto
/// requests plus decrypt/verify-recover responses).
#[test]
fn plaintext_decrypted_checkpoint() {
    assert_category_owners_zeroized("plaintext_decrypted");

    fn assert_wipe_pair<T: Zeroize + zeroize::ZeroizeOnDrop>() {}
    assert_wipe_pair::<EncryptRequest>();
    assert_wipe_pair::<DecryptResponse>();

    let mut encrypt = EncryptRequest {
        client_context_id: "ctx".to_string(),
        session_handle: 1,
        data: vec![0xA5u8; 16],
        data_null_len: None,
    };
    assert_canary_nonempty("EncryptRequest.data", &encrypt.data);
    encrypt.zeroize();
    assert!(
        encrypt.data.iter().all(|byte| *byte == 0),
        "EncryptRequest.data must not survive zeroize"
    );

    let mut decrypt = DecryptResponse { ck_rv: 0, data: vec![0x5Au8; 16], mechanism_out: None };
    assert_canary_nonempty("DecryptResponse.data", &decrypt.data);
    decrypt.zeroize();
    assert!(
        decrypt.data.iter().all(|byte| *byte == 0),
        "DecryptResponse.data must not survive zeroize"
    );
}

/// T12 checkpoint `unknown_vendor`: vendor/derived blobs, derivation
/// contexts, and exact-output carriers wipe.
#[test]
fn unknown_vendor_checkpoint() {
    assert_category_owners_zeroized("unknown_vendor");

    fn assert_wipe_pair<T: Zeroize + zeroize::ZeroizeOnDrop>() {}
    assert_wipe_pair::<ParameterRoundtripSpec>();
    assert_wipe_pair::<MessageParameter>();
    assert_wipe_pair::<MessageParams>();

    let mut spec = ParameterRoundtripSpec {
        buffer_present: true,
        buffer_len: 8,
        value: Some(vec![0xA5u8; 8]),
    };
    assert_canary_nonempty(
        "ParameterRoundtripSpec.value",
        spec.value.as_deref().unwrap_or_default(),
    );
    spec.zeroize();
    assert!(spec.value.is_none(), "ParameterRoundtripSpec.value must not survive zeroize");

    let mut parameter = MessageParameter { params: Some(MessageParams::Raw(vec![0x5Au8; 8])) };
    parameter.zeroize();
    assert!(parameter.params.is_none(), "MessageParameter.params must not survive zeroize");
}

/// T12 steady state: the wipe closure covers every `[secret]` category
/// dynamically, so a new category would silently gain wiping without a
/// reviewed checkpoint. Pin the reviewed set: adding a category must fail
/// here until it gains its own `*_checkpoint` test above.
#[test]
fn secret_category_set_matches_reviewed_checkpoints() {
    let manifest: toml::Value =
        include_str!("../secret-fields.toml").parse().expect("secret-fields.toml must parse");
    let secret = manifest.get("secret").and_then(toml::Value::as_table).expect("missing [secret]");
    let actual: std::collections::BTreeSet<&str> = secret.keys().map(String::as_str).collect();
    let expected: std::collections::BTreeSet<&str> = [
        "key_attributes_material",
        "pin_auth",
        "plaintext_decrypted",
        "seed_state",
        "unknown_vendor",
    ]
    .into_iter()
    .collect();
    assert_eq!(actual, expected, "secret category set drifted: add a checkpoint test");
}
