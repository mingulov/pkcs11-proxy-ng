//! Step-20 end-to-end traces: token ceremony and operation state.
//!
//! The audit traced `C_InitToken`/ceremony and
//! `C_GetOperationState`/`C_SetOperationState` through every layer but
//! found no happy-path test driving them across the full stack. These
//! tests close that gap against one backend (MockBackend, no matrix):
//! high-level `Pkcs11Client` → gRPC → daemon → `MockBackend`.
//!
//! Each test pins backend-observed effects (requested slots, login
//! count, exported blob bytes) plus negative cases, so a vacuous test
//! that never reached the backend cannot pass.

mod common_3x;

use std::sync::Arc;

use common_3x::{init_client, mock_daemon};
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_types::{
    CkInBuf, CkMechanism, CkMechanismType, CkObjectHandle, CkRv, CkSessionFlags, CkSlotId,
    CkUserType, InitTokenLabel,
};

fn rsa_pkcs_mechanism() -> CkMechanism {
    CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None }
}

fn rw_session_flags() -> CkSessionFlags {
    CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION
}

/// Full token ceremony across the stack: `InitToken` → SO login →
/// `InitPIN` → logout → user login → `SetPIN` → logout.
#[tokio::test]
async fn init_token_ceremony_end_to_end() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(7)], vec![CkMechanismType::RSA_PKCS]));
    let (endpoint, _shutdown) = mock_daemon(backend.clone()).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    assert_eq!(slots.len(), 1);
    let slot = slots[0];

    client
        .init_token(slot, Some(b"so-pin"), InitTokenLabel::text_only("ceremony-token"))
        .await
        .unwrap();
    // The backend observed exactly one init_token for its own slot id.
    assert_eq!(backend.init_token_requested_slots(), vec![CkSlotId(7)]);

    // The reinit relabel is visible through the daemon (cache invalidated).
    let info = client.get_token_info(slot).await.unwrap();
    assert!(
        info.label.contains("ceremony-token"),
        "relabel must be visible end to end, got {:?}",
        info.label
    );

    let session = client.open_session(slot, rw_session_flags()).await.unwrap();
    client.login(session, CkUserType::So, Some(b"so-pin")).await.unwrap();
    client.init_pin(session, Some(b"user-pin")).await.unwrap();
    client.logout(session).await.unwrap();

    client.login(session, CkUserType::User, Some(b"user-pin")).await.unwrap();
    client.set_pin(session, Some(b"user-pin"), Some(b"user-pin-2")).await.unwrap();
    client.logout(session).await.unwrap();
    client.close_session(session).await.unwrap();

    // Both logins reached the backend exactly once each.
    assert_eq!(backend.login_call_count(), 2);
    client.finalize().await.unwrap();
}

/// Operation-state export/import across the stack: begin a multipart
/// sign on one session, export the blob, restore it on a fresh
/// session, and continue the operation there.
#[tokio::test]
async fn operation_state_export_import_end_to_end() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
    let (endpoint, _shutdown) = mock_daemon(backend.clone()).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], rw_session_flags()).await.unwrap();

    // Negative: nothing to export before any operation begins.
    assert_eq!(
        client.get_operation_state(session).await.unwrap_err(),
        CkRv::OPERATION_NOT_INITIALIZED
    );

    // A bare created object suffices as the sign key (T3 precedent).
    let key = client.create_object(session, Some(&[])).await.unwrap();
    client.sign_init(session, &rsa_pkcs_mechanism(), key).await.unwrap();

    let blob = client.get_operation_state(session).await.unwrap();
    let bytes = blob.expose(|raw| raw.to_vec());
    // Mock encoding: 0xC9 0xEA prefix + op byte (Sign = 1).
    assert_eq!(bytes, vec![0xC9, 0xEA, 0x01]);

    // Restore onto a fresh session (the restore target must have no
    // active operation); no auxiliary keys needed (wire 0 = no key).
    let restored = client.open_session(slots[0], rw_session_flags()).await.unwrap();
    client
        .set_operation_state(restored, CkInBuf::Bytes(&bytes), CkObjectHandle(0), CkObjectHandle(0))
        .await
        .unwrap();

    // The continued operation works on the restore target.
    client.sign_update(restored, CkInBuf::Bytes(b"hello")).await.unwrap();
    let signature = client.sign_final(restored).await.unwrap();
    assert!(!signature.is_empty());

    // Negative: a garbage blob is refused loudly, on a session with no
    // active operation so the blob (not the session state) is blamed.
    let probe = client.open_session(slots[0], rw_session_flags()).await.unwrap();
    assert_eq!(
        client
            .set_operation_state(
                probe,
                CkInBuf::Bytes(&[0x00]),
                CkObjectHandle(0),
                CkObjectHandle(0),
            )
            .await
            .unwrap_err(),
        CkRv::SAVED_STATE_INVALID
    );
    client.finalize().await.unwrap();
}
