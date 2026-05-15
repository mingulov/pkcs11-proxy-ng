//! Integration tests for PKCS#11 3.0/3.2 functions (Wave 6).
//!
//! These tests exercise the full client -> gRPC -> backend stack using
//! `TestBackend3x`, which provides simple deterministic implementations of
//! all 34 new trait methods.  Unlike the Wave 1–5 tests (which validated
//! `CKR_FUNCTION_NOT_SUPPORTED` propagation with `MockBackend`), these tests
//! verify that the full round-trip succeeds with a cooperating backend.

use std::sync::Arc;

use pkcs11_proxy_ng_backend::{MockBackend, TestBackend3x};
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

mod common_3x;
use common_3x::{init_client, mock_daemon};

const CKF_SERIAL: CkSessionFlags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION);

fn test_mechanism() -> CkMechanism {
    CkMechanism { mechanism_type: CkMechanismType(0x00000001), params: None }
}

/// Open a session and create an object to get a valid key handle.
async fn setup_session_with_key(client: &mut Pkcs11Client) -> (CkSessionHandle, CkObjectHandle) {
    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let template = [CkAttribute {
        attr_type: CkAttributeType::CLASS,
        value: Some(CkAttributeValue::Ulong(3)), // CKO_SECRET_KEY
    }];
    let key = client.create_object(session, &template).await.unwrap();
    (session, key)
}

/// Open a session and create two objects to get two valid key handles.
async fn setup_session_with_two_keys(
    client: &mut Pkcs11Client,
) -> (CkSessionHandle, CkObjectHandle, CkObjectHandle) {
    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let template = [CkAttribute {
        attr_type: CkAttributeType::CLASS,
        value: Some(CkAttributeValue::Ulong(3)),
    }];
    let key1 = client.create_object(session, &template).await.unwrap();
    let key2 = client.create_object(session, &template).await.unwrap();
    (session, key1, key2)
}

// ────────────────────────────────────────────────────────────────────
// 1. login_user_valid_pin
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn login_user_valid_pin() {
    let backend = Arc::new(TestBackend3x::default_test());
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    let result = client.login_user(session, CkUserType::User, b"testuser", b"1234").await;
    assert!(result.is_ok(), "login_user with PIN 1234 should succeed");
}

// ────────────────────────────────────────────────────────────────────
// 2. login_user_wrong_pin
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn login_user_wrong_pin() {
    let backend = Arc::new(TestBackend3x::default_test());
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    let err =
        client.login_user(session, CkUserType::User, b"testuser", b"wrong").await.unwrap_err();
    assert_eq!(
        err,
        CkRv::PIN_INCORRECT,
        "login_user with wrong PIN should return CKR_PIN_INCORRECT"
    );
}

// ────────────────────────────────────────────────────────────────────
// 3. session_cancel_succeeds
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn session_cancel_succeeds() {
    let backend = Arc::new(TestBackend3x::default_test());
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    let result = client.session_cancel(session, CkFlags(0)).await;
    assert!(result.is_ok(), "session_cancel should succeed on TestBackend3x");
}

// ────────────────────────────────────────────────────────────────────
// 4. encapsulate_decapsulate_round_trip
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn encapsulate_decapsulate_round_trip() {
    let backend = Arc::new(TestBackend3x::default_test());
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let (session, key) = setup_session_with_key(&mut client).await;

    // Encapsulate
    let (capsule, enc_key) =
        client.encapsulate_key(session, &test_mechanism(), key, &[]).await.unwrap();
    assert_eq!(capsule, vec![0xCA; 32], "capsule should be synthetic 0xCA bytes");
    // The key handle returned is a virtual handle (remapped by context manager),
    // just verify it's nonzero.
    assert_ne!(enc_key, CkObjectHandle(0), "encapsulated key handle should be nonzero");

    // Decapsulate
    let dec_key =
        client.decapsulate_key(session, &test_mechanism(), key, &[], &capsule).await.unwrap();
    assert_ne!(dec_key, CkObjectHandle(0), "decapsulated key handle should be nonzero");
}

// ────────────────────────────────────────────────────────────────────
// 5. message_encrypt_decrypt_round_trip
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn message_encrypt_decrypt_round_trip() {
    let backend = Arc::new(TestBackend3x::default_test());
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let (session, key) = setup_session_with_key(&mut client).await;
    let plaintext = b"hello world 3x";
    let parameter = b"nonce123";

    // Init encrypt
    client.message_encrypt_init(session, Some(&test_mechanism()), key).await.unwrap();

    // Encrypt one message
    let (param_out, ciphertext) =
        client.encrypt_message(session, parameter, &[], plaintext).await.unwrap();
    assert_ne!(ciphertext, plaintext.to_vec(), "ciphertext should differ from plaintext");

    // Finalize encrypt
    client.message_encrypt_final(session).await.unwrap();

    // Init decrypt
    client.message_decrypt_init(session, Some(&test_mechanism()), key).await.unwrap();

    // Decrypt
    let (_param_out2, recovered) =
        client.decrypt_message(session, &param_out, &[], &ciphertext).await.unwrap();
    assert_eq!(recovered, plaintext.to_vec(), "decrypted plaintext should match original");

    // Finalize decrypt
    client.message_decrypt_final(session).await.unwrap();
}

#[tokio::test]
async fn encrypt_init_returns_gcm_output_params_through_grpc() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_GCM]));
    let generated_iv = vec![0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB];
    backend.set_encrypt_init_output(Some(CkMechanismParams::Gcm(GcmParams {
        iv: generated_iv.clone(),
        iv_bits: 96,
        iv_buffer_len: generated_iv.len() as u64,
        aad: b"aad".to_vec(),
        tag_bits: 128,
    })));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;
    let (session, key) = setup_session_with_key(&mut client).await;

    let mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv: vec![],
            iv_bits: 96,
            iv_buffer_len: generated_iv.len() as u64,
            aad: b"aad".to_vec(),
            tag_bits: 128,
        })),
    };

    let output = client.encrypt_init(session, &mechanism, key).await.unwrap();

    assert_eq!(
        output,
        Some(CkMechanismParams::Gcm(GcmParams {
            iv: generated_iv.clone(),
            iv_bits: 96,
            iv_buffer_len: generated_iv.len() as u64,
            aad: b"aad".to_vec(),
            tag_bits: 128,
        }))
    );
}

// ────────────────────────────────────────────────────────────────────
// 6. message_sign_verify_round_trip
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn message_sign_verify_round_trip() {
    let backend = Arc::new(TestBackend3x::default_test());
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let (session, key) = setup_session_with_key(&mut client).await;
    let data = b"sign this data";
    let parameter = b"param01";

    // Init sign
    client.message_sign_init(session, Some(&test_mechanism()), key).await.unwrap();

    // Sign message
    let (param_out, signature) = client.sign_message(session, parameter, data).await.unwrap();
    assert!(!signature.is_empty(), "signature should not be empty");

    // Finalize sign
    client.message_sign_final(session).await.unwrap();

    // Init verify
    client.message_verify_init(session, Some(&test_mechanism()), key).await.unwrap();

    // Verify message
    let result = client.verify_message(session, &param_out, data, &signature).await;
    assert!(result.is_ok(), "verify_message should succeed for matching signature");

    // Finalize verify
    client.message_verify_final(session).await.unwrap();
}

// ────────────────────────────────────────────────────────────────────
// 7. verify_signature_round_trip
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn verify_signature_round_trip() {
    let backend = Arc::new(TestBackend3x::default_test());
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let (session, key) = setup_session_with_key(&mut client).await;

    // The TestBackend3x stores the signature at init time, and on
    // verify_signature checks that data == signature reversed.
    let data = b"abcdef";
    let signature: Vec<u8> = data.iter().rev().copied().collect(); // "fedcba"

    // Init with signature
    client.verify_signature_init(session, Some(&test_mechanism()), key, &signature).await.unwrap();

    // Single-part verify: data should match signature reversed
    let result = client.verify_signature(session, data).await;
    assert!(result.is_ok(), "verify_signature should succeed when data matches");
}

// ────────────────────────────────────────────────────────────────────
// 8. async_complete_returns_result
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn async_complete_returns_result() {
    let backend = Arc::new(TestBackend3x::default_test());
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    let (version, value, value_len, _h1, _h2) =
        client.async_complete(session, "C_Sign").await.unwrap();

    assert_eq!(version, 1, "async_complete should return version 1");
    assert_eq!(value, vec![0xA5; 8], "async_complete should return synthetic data");
    assert_eq!(value_len, 8, "async_complete should return correct value_len");
}

// ────────────────────────────────────────────────────────────────────
// 9. async_get_id_returns_state_unsaveable
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn async_get_id_returns_state_unsaveable() {
    let backend = Arc::new(TestBackend3x::default_test());
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    let err = client.async_get_id(session, "C_Sign").await.unwrap_err();
    assert_eq!(
        err,
        CkRv::STATE_UNSAVEABLE,
        "async_get_id should always return CKR_STATE_UNSAVEABLE (Option B)"
    );
}

// ────────────────────────────────────────────────────────────────────
// 10. async_join_returns_saved_state_invalid
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn async_join_returns_saved_state_invalid() {
    let backend = Arc::new(TestBackend3x::default_test());
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    let err = client.async_join(session, "C_Sign", 0, 256).await.unwrap_err();
    assert_eq!(
        err,
        CkRv::SAVED_STATE_INVALID,
        "async_join should always return CKR_SAVED_STATE_INVALID (Option B)"
    );
}

// ────────────────────────────────────────────────────────────────────
// Bonus: get_session_validation_flags returns 0
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_session_validation_flags_returns_zero() {
    let backend = Arc::new(TestBackend3x::default_test());
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    let flags = client.get_session_validation_flags(session, 0).await.unwrap();
    assert_eq!(flags, 0, "get_session_validation_flags should return 0 from TestBackend3x");
}

// ────────────────────────────────────────────────────────────────────
// Bonus: wrap/unwrap authenticated round-trip
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn wrap_unwrap_key_authenticated_round_trip() {
    let backend = Arc::new(TestBackend3x::default_test());
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let (session, wrapping_key, target_key) = setup_session_with_two_keys(&mut client).await;

    // Wrap
    let (wrapped_key, mech_param_out) = client
        .wrap_key_authenticated(session, &test_mechanism(), wrapping_key, target_key, &[])
        .await
        .unwrap();
    assert_eq!(wrapped_key, vec![0xBB; 16], "wrapped_key should be synthetic 0xBB bytes");
    assert_eq!(mech_param_out, vec![0xCC; 12], "mechanism_parameter_out should be 0xCC bytes");

    // Unwrap
    let (new_key, mech_param_out2) = client
        .unwrap_key_authenticated(session, &test_mechanism(), wrapping_key, &wrapped_key, &[], &[])
        .await
        .unwrap();
    assert_ne!(new_key, CkObjectHandle(0), "unwrapped key handle should be nonzero");
    assert_eq!(mech_param_out2, vec![0xCC; 12], "mechanism_parameter_out should be 0xCC bytes");
}
