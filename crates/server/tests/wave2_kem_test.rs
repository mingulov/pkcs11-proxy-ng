//! Round-trip tests for PKCS#11 3.2 Wave 2 KEM functions.
//!
//! These tests exercise `EncapsulateKey` and `DecapsulateKey` through the full
//! client -> gRPC -> backend stack using `MockBackend`.
//!
//! `MockBackend` implements deterministic encapsulation and decapsulation so
//! these tests can verify both paths through the full client, proto, gRPC
//! handler, and backend stack without depending on provider KEM support.

use std::sync::Arc;

use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

mod common_3x;
use common_3x::{init_client, mock, mock_daemon};

/// Open a session and create an object to get a valid key handle for KEM tests.
async fn setup_session_with_key(client: &mut Pkcs11Client) -> (CkSessionHandle, CkObjectHandle) {
    let slots = client.get_slot_list(false).await.unwrap();
    let session = client
        .open_session(slots[0], CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
        .await
        .unwrap();
    // Create a minimal object; the mock backend assigns a handle.
    let template = [CkAttribute {
        attr_type: CkAttributeType::CLASS,
        value: Some(CkAttributeValue::Ulong(3)), // CKO_SECRET_KEY
    }];
    let key = client.create_object(session, &template).await.unwrap();
    (session, key)
}

const CKF_SERIAL: CkSessionFlags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION);

fn test_mechanism() -> CkMechanism {
    CkMechanism { mechanism_type: CkMechanismType(0x00000001), params: None }
}

// ────────────────────────────────────────────────────────────────────
// EncapsulateKey round-trip
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn encapsulate_key_returns_synthetic_result_through_full_stack() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let (session, key) = setup_session_with_key(&mut client).await;

    let (ciphertext, encapsulated_key) =
        client.encapsulate_key(session, &test_mechanism(), key, &[]).await.unwrap();

    assert_eq!(ciphertext, vec![0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF]);
    assert_ne!(encapsulated_key, CkObjectHandle(0));
}

#[tokio::test]
async fn encapsulate_key_with_template_returns_synthetic_result() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let (session, key) = setup_session_with_key(&mut client).await;

    // Non-empty template should propagate through without crashing.
    let template = [CkAttribute {
        attr_type: CkAttributeType::CLASS,
        value: Some(CkAttributeValue::Ulong(3)),
    }];
    let (ciphertext, encapsulated_key) =
        client.encapsulate_key(session, &test_mechanism(), key, &template).await.unwrap();

    assert_eq!(ciphertext, vec![0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF]);
    assert_ne!(encapsulated_key, CkObjectHandle(0));
}

// ────────────────────────────────────────────────────────────────────
// DecapsulateKey round-trip
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn decapsulate_key_returns_synthetic_handle_through_full_stack() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let (session, key) = setup_session_with_key(&mut client).await;

    let decapsulated_key =
        client.decapsulate_key(session, &test_mechanism(), key, &[], &[0xAA, 0xBB]).await.unwrap();

    assert_ne!(decapsulated_key, CkObjectHandle(0));
}

#[tokio::test]
async fn decapsulate_key_with_empty_ciphertext() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let (session, key) = setup_session_with_key(&mut client).await;

    // Empty ciphertext should still reach the backend.
    let decapsulated_key =
        client.decapsulate_key(session, &test_mechanism(), key, &[], &[]).await.unwrap();

    assert_ne!(decapsulated_key, CkObjectHandle(0));
}

// ────────────────────────────────────────────────────────────────────
// Session validity: KEM functions reject invalid sessions
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn encapsulate_key_rejects_invalid_session() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    // Use a session handle that was never opened.
    let bad_session = CkSessionHandle(999_999);
    let err = client
        .encapsulate_key(bad_session, &test_mechanism(), CkObjectHandle(1), &[])
        .await
        .unwrap_err();

    assert_eq!(
        err,
        CkRv::SESSION_HANDLE_INVALID,
        "encapsulate_key with invalid session handle should return CKR_SESSION_HANDLE_INVALID"
    );
}

#[tokio::test]
async fn decapsulate_key_rejects_invalid_session() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let bad_session = CkSessionHandle(999_999);
    let err = client
        .decapsulate_key(bad_session, &test_mechanism(), CkObjectHandle(1), &[], &[0xCC])
        .await
        .unwrap_err();

    assert_eq!(
        err,
        CkRv::SESSION_HANDLE_INVALID,
        "decapsulate_key with invalid session handle should return CKR_SESSION_HANDLE_INVALID"
    );
}

// ────────────────────────────────────────────────────────────────────
// Key handle forwarding: unknown proxy handles are forwarded to the backend
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn encapsulate_key_returns_backend_error_for_unknown_key_handle() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    // Key handle 999_999 was never created. The proxy forwards CK_INVALID_HANDLE
    // to the backend, and MockBackend now reports that as an invalid object.
    let err = client
        .encapsulate_key(session, &test_mechanism(), CkObjectHandle(999_999), &[])
        .await
        .unwrap_err();

    assert_eq!(err, CkRv::OBJECT_HANDLE_INVALID);
}

#[tokio::test]
async fn decapsulate_key_returns_backend_error_for_unknown_key_handle() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    let err = client
        .decapsulate_key(session, &test_mechanism(), CkObjectHandle(999_999), &[], &[0xAA])
        .await
        .unwrap_err();

    assert_eq!(err, CkRv::OBJECT_HANDLE_INVALID);
}
