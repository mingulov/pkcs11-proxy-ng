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
    InitPinRequest, InitTokenRequest, LoginRequest, LoginUserRequest, OtpParam, SetPinRequest,
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
    // Compile-time pin (PBE canary pattern): deleting `ZeroizeOnDrop`
    // from any build.rs PIN `type_attribute` line must fail compilation here.
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
/// the manifest parse and fails until its owner gains the build.rs derive
/// plus a canary bound. (`LoginUserRequest.username` is secret-classified
/// under `unknown_vendor` but wipes with its whole-message derive; the
/// broader secret classes stay future work per the build.rs residual note.)
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
