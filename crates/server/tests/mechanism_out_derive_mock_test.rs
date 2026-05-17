//! MockBackend-backed integration coverage for `C_DeriveKey` mechanism_out.
//!
//! Provider matrices often do not expose TLS/WTLS/PBE mechanisms that mutate
//! their parameter structs. This test uses MockBackend as the deterministic
//! internal provider so the client -> gRPC -> backend path is covered without
//! depending on a host token.

use std::sync::Arc;

use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_types::*;

mod common_3x;
use common_3x::{init_client, mock_daemon};

const CKM_PBE_MD2_DES_CBC: CkMechanismType = CkMechanismType(0x0000_03A0);
const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);
const CKM_SP800_108_FEEDBACK_KDF: CkMechanismType = CkMechanismType(0x0000_03AD);
const CKM_SP800_108_DOUBLE_PIPELINE_KDF: CkMechanismType = CkMechanismType(0x0000_03AE);
const CKM_WTLS_MASTER_KEY_DERIVE: CkMechanismType = CkMechanismType(0x0000_03D1);
const CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE: CkMechanismType = CkMechanismType(0x0000_03D4);
const CKM_TLS12_KEY_AND_MAC_DERIVE: CkMechanismType = CkMechanismType(0x0000_03E1);
const CKM_SHA256_HMAC: u64 = 0x0000_0251;
const CK_SP800_108_ITERATION_VARIABLE: u64 = 0x0000_0001;
const CK_SP800_108_KEY_HANDLE: u64 = 0x0000_0005;
const CKF_SERIAL: CkSessionFlags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION);

fn sp800_108_counter_iteration_param() -> PrfDataParam {
    PrfDataParam { type_: CK_SP800_108_ITERATION_VARIABLE, value: vec![0; 16] }
}

#[tokio::test]
async fn derive_key_mechanism_out_surfaces_pbe_iv_through_mock_grpc_stack() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CKM_PBE_MD2_DES_CBC]));
    let expected_output = CkMechanismParams::Pbe(PbeParams {
        init_vector: vec![0xA5; 8],
        password: b"password".to_vec(),
        salt: b"salt".to_vec(),
        iteration: 4096,
    });
    backend.set_derive_key_output(Some(expected_output.clone()));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let base_key = client.create_object(session, &[]).await.unwrap();
    let mechanism = CkMechanism { mechanism_type: CKM_PBE_MD2_DES_CBC, params: None };

    let (derived_key, mechanism_out) =
        client.derive_key_with_mechanism_out(session, &mechanism, base_key, &[]).await.unwrap();

    assert_ne!(derived_key, CkObjectHandle(0));
    assert_eq!(mechanism_out, Some(expected_output));
}

#[tokio::test]
async fn derive_key_mechanism_out_surfaces_wtls_version_through_mock_grpc_stack() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CKM_WTLS_MASTER_KEY_DERIVE]));
    let expected_output = CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
        digest_mechanism: CkMechanismType::SHA256.0,
        random_info: WtlsRandomData {
            client_random: vec![0x11; 16],
            server_random: vec![0x22; 16],
        },
        version: 2,
    });
    backend.set_derive_key_output(Some(expected_output.clone()));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let base_key = client.create_object(session, &[]).await.unwrap();
    let mechanism = CkMechanism {
        mechanism_type: CKM_WTLS_MASTER_KEY_DERIVE,
        params: Some(CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
            digest_mechanism: CkMechanismType::SHA256.0,
            random_info: WtlsRandomData {
                client_random: vec![0x11; 16],
                server_random: vec![0x22; 16],
            },
            version: 1,
        })),
    };

    let (derived_key, mechanism_out) =
        client.derive_key_with_mechanism_out(session, &mechanism, base_key, &[]).await.unwrap();

    assert_ne!(derived_key, CkObjectHandle(0));
    assert_eq!(mechanism_out, Some(expected_output));
}

#[tokio::test]
async fn derive_key_mechanism_out_surfaces_wtls_key_material_through_mock_grpc_stack() {
    let backend =
        Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE]));
    let expected_output = CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
        digest_mechanism: CkMechanismType::SHA256.0,
        mac_size_bits: 160,
        key_size_bits: 128,
        iv_size_bits: 32,
        sequence_number: 7,
        is_export: true,
        random_info: WtlsRandomData {
            client_random: vec![0x33; 16],
            server_random: vec![0x44; 16],
        },
        mac_secret_handle: 101,
        key_handle: 202,
        iv: vec![0xA1, 0xA2, 0xA3, 0xA4],
    });
    backend.set_derive_key_output(Some(expected_output.clone()));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let base_key = client.create_object(session, &[]).await.unwrap();
    let mechanism = CkMechanism {
        mechanism_type: CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
        params: Some(CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
            digest_mechanism: CkMechanismType::SHA256.0,
            mac_size_bits: 160,
            key_size_bits: 128,
            iv_size_bits: 32,
            sequence_number: 7,
            is_export: true,
            random_info: WtlsRandomData {
                client_random: vec![0x33; 16],
                server_random: vec![0x44; 16],
            },
            mac_secret_handle: 0,
            key_handle: 0,
            iv: vec![0; 4],
        })),
    };

    let (derived_key, mechanism_out) =
        client.derive_key_with_mechanism_out(session, &mechanism, base_key, &[]).await.unwrap();

    assert_ne!(derived_key, CkObjectHandle(0));
    assert_eq!(mechanism_out, Some(expected_output));
}

#[tokio::test]
async fn derive_key_mechanism_out_surfaces_tls_key_material_through_mock_grpc_stack() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CKM_TLS12_KEY_AND_MAC_DERIVE]));
    let expected_output = CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
        mac_size_bits: 160,
        key_size_bits: 128,
        iv_size_bits: 32,
        is_export: false,
        random_info: SslRandomData { client_random: vec![0x55; 32], server_random: vec![0x66; 32] },
        prf_hash_mechanism: CkMechanismType::SHA256.0,
        client_mac_secret_handle: 101,
        server_mac_secret_handle: 102,
        client_key_handle: 201,
        server_key_handle: 202,
        client_iv: vec![0xA1, 0xA2, 0xA3, 0xA4],
        server_iv: vec![0xB1, 0xB2, 0xB3, 0xB4],
    });
    backend.set_derive_key_output(Some(expected_output.clone()));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let base_key = client.create_object(session, &[]).await.unwrap();
    let mechanism = CkMechanism {
        mechanism_type: CKM_TLS12_KEY_AND_MAC_DERIVE,
        params: Some(CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
            mac_size_bits: 160,
            key_size_bits: 128,
            iv_size_bits: 32,
            is_export: false,
            random_info: SslRandomData {
                client_random: vec![0x55; 32],
                server_random: vec![0x66; 32],
            },
            prf_hash_mechanism: CkMechanismType::SHA256.0,
            client_mac_secret_handle: 0,
            server_mac_secret_handle: 0,
            client_key_handle: 0,
            server_key_handle: 0,
            client_iv: vec![0; 4],
            server_iv: vec![0; 4],
        })),
    };

    let (derived_key, mechanism_out) =
        client.derive_key_with_mechanism_out(session, &mechanism, base_key, &[]).await.unwrap();

    assert_ne!(derived_key, CkObjectHandle(0));
    assert_eq!(mechanism_out, Some(expected_output));
}

#[tokio::test]
async fn derive_key_mechanism_out_virtualizes_sp800_108_additional_key_handles() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CKM_SP800_108_COUNTER_KDF]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let base_key = client.create_object(session, &[]).await.unwrap();
    let mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_COUNTER_KDF,
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CKM_SHA256_HMAC,
            data_params: vec![sp800_108_counter_iteration_param()],
            additional_derived_keys: vec![Sp800108DerivedKey {
                template: vec![CkAttribute {
                    attr_type: CkAttributeType::VALUE_LEN,
                    value: Some(CkAttributeValue::Ulong(32)),
                }],
                key_handle: 0,
            }],
        })),
    };

    let (primary_key, mechanism_out) =
        client.derive_key_with_mechanism_out(session, &mechanism, base_key, &[]).await.unwrap();
    let Some(CkMechanismParams::Sp800108Kdf(output)) = mechanism_out else {
        panic!("expected SP800-108 mechanism_out");
    };
    let additional_key = CkObjectHandle(output.additional_derived_keys[0].key_handle);

    assert_ne!(primary_key, CkObjectHandle(0));
    assert_ne!(additional_key, CkObjectHandle(0));
    let (rv, size_results) = client
        .get_attribute_value_exact(
            session,
            additional_key,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::VALUE_LEN,
                buffer_present: false,
                buffer_len: 0,
                nested: None,
            }],
        )
        .await
        .unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(size_results[0].returned_len, 8);

    let (rv, data_results) = client
        .get_attribute_value_exact(
            session,
            additional_key,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::VALUE_LEN,
                buffer_present: true,
                buffer_len: size_results[0].returned_len,
                nested: None,
            }],
        )
        .await
        .unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(data_results[0].value, Some(32_u64.to_le_bytes().to_vec()));
    client.destroy_object(session, additional_key).await.unwrap();
}

#[tokio::test]
async fn derive_key_mechanism_out_virtualizes_sp800_108_double_pipeline_additional_key_handles() {
    let backend =
        Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CKM_SP800_108_DOUBLE_PIPELINE_KDF]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let base_key = client.create_object(session, &[]).await.unwrap();
    let mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_DOUBLE_PIPELINE_KDF,
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CKM_SHA256_HMAC,
            data_params: vec![
                sp800_108_counter_iteration_param(),
                PrfDataParam {
                    type_: CK_SP800_108_KEY_HANDLE,
                    value: base_key.0.to_ne_bytes().to_vec(),
                },
            ],
            additional_derived_keys: vec![Sp800108DerivedKey {
                template: vec![CkAttribute {
                    attr_type: CkAttributeType::LABEL,
                    value: Some(CkAttributeValue::String("double-pipeline-extra".to_string())),
                }],
                key_handle: 0,
            }],
        })),
    };

    let (primary_key, mechanism_out) =
        client.derive_key_with_mechanism_out(session, &mechanism, base_key, &[]).await.unwrap();
    let Some(CkMechanismParams::Sp800108Kdf(output)) = mechanism_out else {
        panic!("expected SP800-108 double-pipeline mechanism_out");
    };
    let additional_key = CkObjectHandle(output.additional_derived_keys[0].key_handle);

    assert_ne!(primary_key, CkObjectHandle(0));
    assert_ne!(additional_key, CkObjectHandle(0));
    assert_ne!(primary_key, additional_key);
    let (rv, data_results) = client
        .get_attribute_value_exact(
            session,
            additional_key,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::LABEL,
                buffer_present: true,
                buffer_len: "double-pipeline-extra".len() as u64,
                nested: None,
            }],
        )
        .await
        .unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(data_results[0].value, Some(b"double-pipeline-extra".to_vec()));
    client.destroy_object(session, additional_key).await.unwrap();
}

#[tokio::test]
async fn derive_key_mechanism_out_surfaces_sp800_108_template_failure_handle() {
    const SENTINEL_HANDLE: u64 = 0xCAFE_BABE;

    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CKM_SP800_108_COUNTER_KDF]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let base_key = client.create_object(session, &[]).await.unwrap();
    let mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_COUNTER_KDF,
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CKM_SHA256_HMAC,
            data_params: vec![sp800_108_counter_iteration_param()],
            additional_derived_keys: vec![
                Sp800108DerivedKey {
                    template: vec![CkAttribute {
                        attr_type: CkAttributeType::VALUE_LEN,
                        value: Some(CkAttributeValue::Ulong(32)),
                    }],
                    key_handle: SENTINEL_HANDLE,
                },
                Sp800108DerivedKey {
                    template: vec![CkAttribute {
                        attr_type: CkAttributeType::VALUE_LEN,
                        value: Some(CkAttributeValue::Ulong(0)),
                    }],
                    key_handle: SENTINEL_HANDLE,
                },
            ],
        })),
    };

    let result = client
        .derive_key_with_mechanism_out_result(session, &mechanism, base_key, &[])
        .await
        .unwrap();

    assert_eq!(result.rv, CkRv::TEMPLATE_INCONSISTENT);
    assert_eq!(result.key_handle, None);
    let Some(CkMechanismParams::Sp800108Kdf(output)) = result.mechanism_out else {
        panic!("expected SP800-108 mechanism output on template failure");
    };
    assert_eq!(output.additional_derived_keys[0].key_handle, SENTINEL_HANDLE);
    assert_eq!(output.additional_derived_keys[1].key_handle, 0);
    assert_eq!(
        client.destroy_object(session, CkObjectHandle(base_key.0 + 1)).await.unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID,
        "failed SP800-108 derive must not leak the primary derived object"
    );
}

#[tokio::test]
async fn derive_key_mechanism_out_virtualizes_sp800_108_feedback_additional_key_handles() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CKM_SP800_108_FEEDBACK_KDF]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let base_key = client.create_object(session, &[]).await.unwrap();
    let mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_FEEDBACK_KDF,
        params: Some(CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
            prf_type: CKM_SHA256_HMAC,
            data_params: vec![sp800_108_counter_iteration_param()],
            iv: vec![0xA5; 16],
            additional_derived_keys: vec![Sp800108DerivedKey {
                template: vec![CkAttribute {
                    attr_type: CkAttributeType::VALUE_LEN,
                    value: Some(CkAttributeValue::Ulong(64)),
                }],
                key_handle: 0,
            }],
        })),
    };

    let (primary_key, mechanism_out) =
        client.derive_key_with_mechanism_out(session, &mechanism, base_key, &[]).await.unwrap();
    let Some(CkMechanismParams::Sp800108FeedbackKdf(output)) = mechanism_out else {
        panic!("expected SP800-108 feedback mechanism_out");
    };
    let additional_key = CkObjectHandle(output.additional_derived_keys[0].key_handle);

    assert_ne!(primary_key, CkObjectHandle(0));
    assert_eq!(output.iv, vec![0xA5; 16]);
    assert_ne!(additional_key, CkObjectHandle(0));
    let (rv, data_results) = client
        .get_attribute_value_exact(
            session,
            additional_key,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::VALUE_LEN,
                buffer_present: true,
                buffer_len: 8,
                nested: None,
            }],
        )
        .await
        .unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(data_results[0].value, Some(64_u64.to_le_bytes().to_vec()));
    client.destroy_object(session, additional_key).await.unwrap();
}

#[tokio::test]
async fn derive_key_rejects_invalid_sp800_108_key_handle_data_param() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CKM_SP800_108_COUNTER_KDF]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
    let base_key = client.create_object(session, &[]).await.unwrap();
    let invalid_nested_key = CkObjectHandle(0xDEAD_BEEF);
    let mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_COUNTER_KDF,
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CKM_SHA256_HMAC,
            data_params: vec![
                sp800_108_counter_iteration_param(),
                PrfDataParam {
                    type_: CK_SP800_108_KEY_HANDLE,
                    value: invalid_nested_key.0.to_ne_bytes().to_vec(),
                },
            ],
            additional_derived_keys: Vec::new(),
        })),
    };

    let err = client.derive_key_with_mechanism_out(session, &mechanism, base_key, &[]).await;

    assert_eq!(err.unwrap_err(), CkRv::OBJECT_HANDLE_INVALID);
}
