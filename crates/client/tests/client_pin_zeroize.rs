//! W1-L2-10: client PIN buffers wipe on drop.
//!
//! The client's session methods (`login`, `init_token`, `init_pin`,
//! `set_pin`, `login_user`) copy the caller-provided PIN/username bytes
//! exactly once, into the prost-generated request struct, which is then
//! moved into the tonic client for encoding. Those five request messages
//! derive `Zeroize` + `ZeroizeOnDrop` at codegen time (see
//! `crates/proto/build.rs`, W1-C8-11), so the client-owned PIN copy is
//! overwritten when the request drops after encoding instead of being
//! freed plain. Wrapping the field in a second wiping container here
//! would only add an extra copy, so the message-level wipe is the whole
//! mechanism — these tests pin the client's side of that contract:
//!
//! - `client_pin_requests_wipe_on_drop` (compile-time): deleting
//!   `ZeroizeOnDrop` from any of the five messages fails compilation.
//! - `client_pin_zeroize_clears_pin_fields` (canary): each request built
//!   exactly as the session methods build it wipes every PIN/username
//!   field on `zeroize()` (the same call `ZeroizeOnDrop` makes; post-drop
//!   memory is unobservable, so the wipe behavior is pinned directly).
//! - `client_pin_handling_note_matches_codegen_reality`: the `E3` module
//!   note in `src/client/session.rs` must describe this mechanism, not
//!   the pre-C8-11 "cannot wipe" claim.
//!
//! Residuals (unchanged, documented in the `E3` note): the caller's own
//! PIN buffer stays application-owned, and tonic's encoded wire buffers
//! (`bytes::Bytes` inside the gRPC stack) are unreachable for wiping —
//! the send-side mirror of the receive-side transport-buffer limitation.

use pkcs11_proxy_ng_proto::{
    InitPinRequest, InitTokenRequest, LoginRequest, LoginUserRequest, SetPinRequest,
};
use zeroize::Zeroize;

fn assert_canary_nonempty(label: &str, bytes: &[u8]) {
    assert!(!bytes.is_empty(), "{label} canary must be non-empty before zeroize");
    assert!(bytes.iter().any(|&byte| byte != 0), "{label} canary must be nonzero before zeroize");
}

#[test]
fn client_pin_requests_wipe_on_drop() {
    // Compile-time pin (proto `pin_zeroize.rs` pattern, from the
    // consumer side): the exact request types the client's session
    // methods construct must wipe on drop. Deleting `ZeroizeOnDrop` from
    // any build.rs PIN `type_attribute` line must fail compilation here.
    fn assert_wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_wiped_on_drop::<LoginRequest>();
    assert_wiped_on_drop::<LoginUserRequest>();
    assert_wiped_on_drop::<InitTokenRequest>();
    assert_wiped_on_drop::<InitPinRequest>();
    assert_wiped_on_drop::<SetPinRequest>();
}

#[test]
fn client_pin_zeroize_clears_pin_fields() {
    // Each request is built exactly as the corresponding
    // `Pkcs11Client::<>` method builds it (`pin.map(|p| p.to_vec())`
    // into the wiping struct — no other client-owned PIN copy exists).
    // All fields spelled out: struct-update syntax cannot move fields out
    // of a `ZeroizeOnDrop` value.
    let pin: Option<&[u8]> = Some(b"CLIENT-PIN-CANARY-7c3b9f4e2a1d");
    let mut login = LoginRequest {
        client_context_id: "ctx".to_string(),
        session_handle: 1,
        user_type: 1,
        pin: pin.map(|p| p.to_vec()),
    };
    assert_canary_nonempty("LoginRequest.pin", login.pin.as_deref().unwrap_or_default());
    login.zeroize();
    assert!(login.pin.is_none(), "LoginRequest.pin must not survive zeroize");

    let username: Option<&[u8]> = Some(b"CLIENT-USER-CANARY-aa55cc33");
    let mut login_user = LoginUserRequest {
        client_context_id: "ctx".to_string(),
        session_handle: 1,
        user_type: 1,
        pin: pin.map(|p| p.to_vec()),
        username: username.map(|u| u.to_vec()),
    };
    assert_canary_nonempty("LoginUserRequest.pin", login_user.pin.as_deref().unwrap_or_default());
    assert_canary_nonempty(
        "LoginUserRequest.username",
        login_user.username.as_deref().unwrap_or_default(),
    );
    login_user.zeroize();
    assert!(login_user.pin.is_none(), "LoginUserRequest.pin must not survive zeroize");
    assert!(login_user.username.is_none(), "LoginUserRequest.username must not survive zeroize");

    let mut init_token = InitTokenRequest {
        client_context_id: "ctx".to_string(),
        slot_id: 7,
        so_pin: pin.map(|p| p.to_vec()),
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
        pin: pin.map(|p| p.to_vec()),
    };
    assert_canary_nonempty("InitPinRequest.pin", init_pin.pin.as_deref().unwrap_or_default());
    init_pin.zeroize();
    assert!(init_pin.pin.is_none(), "InitPinRequest.pin must not survive zeroize");

    let new_pin: Option<&[u8]> = Some(b"CLIENT-NEW-PIN-bb44ee77cc11");
    let mut set_pin = SetPinRequest {
        client_context_id: "ctx".to_string(),
        session_handle: 1,
        old_pin: pin.map(|p| p.to_vec()),
        new_pin: new_pin.map(|p| p.to_vec()),
    };
    assert_canary_nonempty("SetPinRequest.old_pin", set_pin.old_pin.as_deref().unwrap_or_default());
    assert_canary_nonempty("SetPinRequest.new_pin", set_pin.new_pin.as_deref().unwrap_or_default());
    set_pin.zeroize();
    assert!(set_pin.old_pin.is_none(), "SetPinRequest.old_pin must not survive zeroize");
    assert!(set_pin.new_pin.is_none(), "SetPinRequest.new_pin must not survive zeroize");
}

#[test]
fn client_pin_handling_note_matches_codegen_reality() {
    // The E3 module note must describe the message-level wipe (W1-C8-11),
    // not the pre-codegen "cannot wipe / intentionally omitted" claim —
    // a stale note would misdirect the next audit of this path.
    let note =
        std::fs::read_to_string(format!("{}/src/client/session.rs", env!("CARGO_MANIFEST_DIR")))
            .expect("read client session.rs E3 note");
    assert!(
        note.contains("ZeroizeOnDrop"),
        "E3 note must name the ZeroizeOnDrop mechanism that wipes client PIN copies"
    );
    for stale in ["intentionally omitted", "cannot wipe"] {
        assert!(
            !note.contains(stale),
            "E3 note must not carry the stale pre-C8-11 claim {stale:?}"
        );
    }
}
