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
    InitPinRequest, InitTokenRequest, LoginRequest, LoginUserRequest, SetPinRequest,
};
use zeroize::Zeroize;

fn assert_canary_nonempty(label: &str, bytes: &[u8]) {
    assert!(!bytes.is_empty(), "{label} canary must be non-empty before zeroize");
    assert!(bytes.iter().any(|&byte| byte != 0), "{label} canary must be nonzero before zeroize");
}

/// `Vec::zeroize` overwrites every element plus the spare capacity, then
/// clears: after the call nothing secret remains reachable in any form.
fn assert_wiped(label: &str, bytes: &[u8]) {
    assert!(bytes.is_empty(), "{label} must not retain secret bytes after zeroize");
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
        pin: vec![0x5Au8; 16],
        username: vec![0x55u8; 8],
    };
    assert_canary_nonempty("LoginUserRequest.pin", &login_user.pin);
    assert_canary_nonempty("LoginUserRequest.username", &login_user.username);
    login_user.zeroize();
    assert_wiped("LoginUserRequest.pin", &login_user.pin);
    assert_wiped("LoginUserRequest.username", &login_user.username);

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
