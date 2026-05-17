//! Integration tests for PKCS#11 3.0/3.2 functions (Wave 6).
//!
//! These tests exercise the full client -> gRPC -> backend stack using
//! `TestBackend3x`, which provides simple deterministic implementations of
//! the 3.x trait methods. These tests verify that the full round-trip succeeds
//! with a cooperating backend and add MockBackend coverage for mechanism-output
//! paths that need its provider-behavior hooks.

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
async fn message_encrypt_decrypt_begin_next_round_trip() {
    let mechanism = test_mechanism();
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![mechanism.mechanism_type]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let (session, key) = setup_session_with_key(&mut client).await;
    let aad = b"begin-next-aad";
    let parameter = b"begin-next-param";
    let part1 = b"hello ";
    let part2 = b"message begin-next";

    client.message_encrypt_init(session, Some(&mechanism), key).await.unwrap();
    let encrypt_parameter = client.encrypt_message_begin(session, parameter, aad).await.unwrap();
    assert_eq!(encrypt_parameter, parameter);

    let (encrypt_parameter, ciphertext1) =
        client.encrypt_message_next(session, &encrypt_parameter, part1, CkFlags(0)).await.unwrap();
    let (encrypt_parameter, ciphertext2) =
        client.encrypt_message_next(session, &encrypt_parameter, part2, CkFlags(0)).await.unwrap();
    assert_eq!(encrypt_parameter, parameter);
    assert_ne!(ciphertext1, part1);
    assert_ne!(ciphertext2, part2);
    client.message_encrypt_final(session).await.unwrap();

    client.message_decrypt_init(session, Some(&mechanism), key).await.unwrap();
    let decrypt_parameter =
        client.decrypt_message_begin(session, &encrypt_parameter, aad).await.unwrap();
    assert_eq!(decrypt_parameter, parameter);

    let (decrypt_parameter, recovered1) = client
        .decrypt_message_next(session, &decrypt_parameter, &ciphertext1, CkFlags(0))
        .await
        .unwrap();
    let (decrypt_parameter, recovered2) = client
        .decrypt_message_next(session, &decrypt_parameter, &ciphertext2, CkFlags(0))
        .await
        .unwrap();
    assert_eq!(decrypt_parameter, parameter);
    assert_eq!(recovered1, part1);
    assert_eq!(recovered2, part2);
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

#[tokio::test]
async fn simple_encrypt_returns_cached_gcm_output_params_through_grpc() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_GCM]));
    let generated_iv = vec![0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB];
    backend.set_encrypt_init_output(Some(CkMechanismParams::Gcm(GcmParams {
        iv: generated_iv.clone(),
        iv_bits: 96,
        iv_buffer_len: generated_iv.len() as u64,
        aad: b"simple-aad".to_vec(),
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
            aad: b"simple-aad".to_vec(),
            tag_bits: 128,
        })),
    };
    let init_output = client.encrypt_init(session, &mechanism, key).await.unwrap();
    assert!(init_output.is_some(), "init response should expose generated IV");

    let plaintext = b"simple encrypt mechanism_out";
    let (ciphertext, mechanism_out) =
        client.encrypt_with_mechanism_out(session, plaintext).await.unwrap();
    let expected_ciphertext = plaintext.iter().map(|byte| byte ^ 0x42).collect::<Vec<_>>();

    assert_eq!(ciphertext, expected_ciphertext);
    assert_eq!(
        mechanism_out,
        Some(CkMechanismParams::Gcm(GcmParams {
            iv: generated_iv,
            iv_bits: 96,
            iv_buffer_len: 12,
            aad: b"simple-aad".to_vec(),
            tag_bits: 128,
        }))
    );
}

#[tokio::test]
async fn simple_encrypt_returns_late_gcm_output_params_through_grpc() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_GCM]));
    let generated_iv = vec![0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB];
    let expected_output = CkMechanismParams::Gcm(GcmParams {
        iv: generated_iv.clone(),
        iv_bits: 96,
        iv_buffer_len: generated_iv.len() as u64,
        aad: b"late-simple-aad".to_vec(),
        tag_bits: 128,
    });
    backend.set_encrypt_operation_output(Some(expected_output.clone()));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;
    let (session, key) = setup_session_with_key(&mut client).await;

    let mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv: vec![],
            iv_bits: 96,
            iv_buffer_len: generated_iv.len() as u64,
            aad: b"late-simple-aad".to_vec(),
            tag_bits: 128,
        })),
    };
    let init_output = client.encrypt_init(session, &mechanism, key).await.unwrap();
    assert_eq!(init_output, None, "late-output simulation must not surface output at init");

    let plaintext = b"late simple encrypt mechanism_out";
    let (ciphertext, mechanism_out) =
        client.encrypt_with_mechanism_out(session, plaintext).await.unwrap();
    let expected_ciphertext = plaintext.iter().map(|byte| byte ^ 0x42).collect::<Vec<_>>();
    assert_eq!(ciphertext, expected_ciphertext);
    assert_eq!(mechanism_out, Some(expected_output));
}

#[tokio::test]
async fn multipart_encrypt_returns_cached_gcm_output_params_through_grpc() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_GCM]));
    let generated_iv = vec![0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB];
    let expected_output = CkMechanismParams::Gcm(GcmParams {
        iv: generated_iv.clone(),
        iv_bits: 96,
        iv_buffer_len: generated_iv.len() as u64,
        aad: b"multipart-aad".to_vec(),
        tag_bits: 128,
    });
    backend.set_encrypt_init_output(Some(expected_output.clone()));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;
    let (session, key) = setup_session_with_key(&mut client).await;

    let mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv: vec![],
            iv_bits: 96,
            iv_buffer_len: generated_iv.len() as u64,
            aad: b"multipart-aad".to_vec(),
            tag_bits: 128,
        })),
    };
    let init_output = client.encrypt_init(session, &mechanism, key).await.unwrap();
    assert_eq!(init_output, Some(expected_output.clone()));

    let plaintext_part = b"multipart encrypt mechanism_out";
    let (encrypted_part, update_mechanism_out) =
        client.encrypt_update_with_mechanism_out(session, plaintext_part).await.unwrap();
    let expected_part = plaintext_part.iter().map(|byte| byte ^ 0x42).collect::<Vec<_>>();
    assert_eq!(encrypted_part, expected_part);
    assert_eq!(update_mechanism_out, Some(expected_output.clone()));

    let (last_encrypted_part, final_mechanism_out) =
        client.encrypt_final_with_mechanism_out(session).await.unwrap();
    assert!(last_encrypted_part.is_empty(), "MockBackend final encrypt emits no trailing bytes");
    assert_eq!(final_mechanism_out, Some(expected_output));
}

#[tokio::test]
async fn multipart_encrypt_returns_late_gcm_output_params_through_grpc() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_GCM]));
    let generated_iv = vec![0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB];
    let expected_output = CkMechanismParams::Gcm(GcmParams {
        iv: generated_iv.clone(),
        iv_bits: 96,
        iv_buffer_len: generated_iv.len() as u64,
        aad: b"late-multipart-aad".to_vec(),
        tag_bits: 128,
    });
    backend.set_encrypt_operation_output(Some(expected_output.clone()));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;
    let (session, key) = setup_session_with_key(&mut client).await;

    let mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv: vec![],
            iv_bits: 96,
            iv_buffer_len: generated_iv.len() as u64,
            aad: b"late-multipart-aad".to_vec(),
            tag_bits: 128,
        })),
    };
    let init_output = client.encrypt_init(session, &mechanism, key).await.unwrap();
    assert_eq!(init_output, None, "late-output simulation must not surface output at init");

    let plaintext_part = b"late multipart encrypt mechanism_out";
    let (encrypted_part, update_mechanism_out) =
        client.encrypt_update_with_mechanism_out(session, plaintext_part).await.unwrap();
    let expected_part = plaintext_part.iter().map(|byte| byte ^ 0x42).collect::<Vec<_>>();
    assert_eq!(encrypted_part, expected_part);
    assert_eq!(update_mechanism_out, Some(expected_output.clone()));

    let (last_encrypted_part, final_mechanism_out) =
        client.encrypt_final_with_mechanism_out(session).await.unwrap();
    assert!(last_encrypted_part.is_empty(), "MockBackend final encrypt emits no trailing bytes");
    assert_eq!(final_mechanism_out, Some(expected_output));
}

#[tokio::test]
async fn byte_output_exact_encrypt_returns_gcm_output_params_through_grpc() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_GCM]));
    let generated_iv = vec![0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB];
    backend.set_encrypt_exact_output(Some(CkMechanismParams::Gcm(GcmParams {
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
    client.encrypt_init(session, &mechanism, key).await.unwrap();

    let plaintext = b"exact-output mechanism_out";
    let size_spec = CkOutputBufferSpec { buffer_present: false, buffer_len: 0 };
    let (size_result, size_mechanism_out) = client
        .byte_output_exact_with_mechanism_out(
            session,
            ByteOutputFunction::Encrypt,
            &size_spec,
            plaintext,
            None,
            0,
            0,
        )
        .await
        .unwrap();
    assert_eq!(size_result.ck_rv, CkRv::OK);
    assert_eq!(size_result.returned_len, plaintext.len() as u64);
    assert!(size_result.value.is_none(), "size query must not return ciphertext bytes");
    assert!(size_mechanism_out.is_none(), "size query must not surface delayed mechanism_out");

    let data_spec = CkOutputBufferSpec { buffer_present: true, buffer_len: plaintext.len() as u64 };
    let (data_result, data_mechanism_out) = client
        .byte_output_exact_with_mechanism_out(
            session,
            ByteOutputFunction::Encrypt,
            &data_spec,
            plaintext,
            None,
            0,
            0,
        )
        .await
        .unwrap();

    assert_eq!(data_result.ck_rv, CkRv::OK);
    assert_eq!(data_result.returned_len, plaintext.len() as u64);
    let expected_ciphertext = plaintext.iter().map(|byte| byte ^ 0x42).collect::<Vec<_>>();
    assert_eq!(data_result.value.as_deref(), Some(expected_ciphertext.as_slice()));
    assert_eq!(
        data_mechanism_out,
        Some(CkMechanismParams::Gcm(GcmParams {
            iv: generated_iv.clone(),
            iv_bits: 96,
            iv_buffer_len: generated_iv.len() as u64,
            aad: b"aad".to_vec(),
            tag_bits: 128,
        }))
    );
}

#[tokio::test]
async fn byte_output_exact_wrap_key_returns_gcm_output_params_through_grpc() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_GCM]));
    let generated_iv = vec![0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB];
    backend.set_wrap_key_exact_output(Some(CkMechanismParams::Gcm(GcmParams {
        iv: generated_iv.clone(),
        iv_bits: 96,
        iv_buffer_len: generated_iv.len() as u64,
        aad: b"wrap-aad".to_vec(),
        tag_bits: 128,
    })));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;
    let (session, wrapping_key, key) = setup_session_with_two_keys(&mut client).await;

    let mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv: vec![],
            iv_bits: 96,
            iv_buffer_len: generated_iv.len() as u64,
            aad: b"wrap-aad".to_vec(),
            tag_bits: 128,
        })),
    };

    let size_spec = CkOutputBufferSpec { buffer_present: false, buffer_len: 0 };
    let (size_result, size_mechanism_out) = client
        .byte_output_exact_with_mechanism_out(
            session,
            ByteOutputFunction::WrapKey,
            &size_spec,
            &[],
            Some(&mechanism),
            wrapping_key.0,
            key.0,
        )
        .await
        .unwrap();
    assert_eq!(size_result.ck_rv, CkRv::OK);
    assert_eq!(size_result.returned_len, 4);
    assert!(size_result.value.is_none(), "size query must not return wrapped bytes");
    assert!(size_mechanism_out.is_none(), "size query must not surface delayed mechanism_out");

    let data_spec = CkOutputBufferSpec { buffer_present: true, buffer_len: 4 };
    let (wrap_result, mechanism_out) = client
        .byte_output_exact_with_mechanism_out(
            session,
            ByteOutputFunction::WrapKey,
            &data_spec,
            &[],
            Some(&mechanism),
            wrapping_key.0,
            key.0,
        )
        .await
        .unwrap();

    assert_eq!(wrap_result.ck_rv, CkRv::OK);
    assert_eq!(wrap_result.returned_len, 4);
    assert_eq!(wrap_result.value, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    assert_eq!(
        mechanism_out,
        Some(CkMechanismParams::Gcm(GcmParams {
            iv: generated_iv,
            iv_bits: 96,
            iv_buffer_len: 12,
            aad: b"wrap-aad".to_vec(),
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

#[tokio::test]
async fn message_sign_verify_begin_next_round_trip() {
    let mechanism = test_mechanism();
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![mechanism.mechanism_type]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let (session, key) = setup_session_with_key(&mut client).await;
    let parameter = b"sign-begin-next-param";
    let nonfinal_data = b"nonfinal";
    let final_data = b"final payload";

    client.message_sign_init(session, Some(&mechanism), key).await.unwrap();
    let sign_parameter = client.sign_message_begin(session, parameter).await.unwrap();
    assert_eq!(sign_parameter, parameter);

    let (sign_parameter, nonfinal_signature) =
        client.sign_message_next(session, &sign_parameter, nonfinal_data, false).await.unwrap();
    assert_eq!(sign_parameter, parameter);
    assert!(nonfinal_signature.is_empty());

    let (sign_parameter, signature) =
        client.sign_message_next(session, &sign_parameter, final_data, true).await.unwrap();
    let expected_signature: Vec<u8> = final_data.iter().rev().copied().collect();
    assert_eq!(sign_parameter, parameter);
    assert_eq!(signature, expected_signature);
    client.message_sign_final(session).await.unwrap();

    client.message_verify_init(session, Some(&mechanism), key).await.unwrap();
    client.verify_message_begin(session, &sign_parameter).await.unwrap();
    client.verify_message_next(session, &sign_parameter, nonfinal_data, false, &[]).await.unwrap();
    client
        .verify_message_next(session, &sign_parameter, final_data, true, &signature)
        .await
        .unwrap();
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
