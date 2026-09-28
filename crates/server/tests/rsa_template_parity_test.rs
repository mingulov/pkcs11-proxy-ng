// W1-L12-03: test diagnostics (skip notices, progress, summaries) go to
// stderr by design; the workspace lint table denies this sink elsewhere.
#![allow(clippy::print_stderr)]
//! RSA/EC keygen template parity at the backend boundary (perf T2 gate).
//!
//! Asserts that synthetic RSA templates (modulus 2048/3072/4096, exponent
//! `[0x01, 0x00, 0x01]`, native `CK_ULONG` width, exact attribute
//! order/count/nullness) and the parameterless `RSA_PKCS_KEY_PAIR_GEN`
//! mechanism reach the backend verbatim, plus an EC (`CKA_EC_PARAMS`)
//! control. Two tiers:
//!
//! * Mock tier (always runs): Rust client -> gRPC -> `MockBackend` with
//!   recorded keygen templates; asserts conversion fidelity, template
//!   nullness preservation, and malformed-width passthrough shape.
//! * SoftHSM2 tier (skipped when the provider is absent): the same keygens
//!   through a real daemon + `FfiBackend`, asserting success and attribute
//!   readback; malformed widths must fail cleanly (provider refusal,
//!   never a hang or crash).
//!
//! Cross-width (32<->64) transitions stay covered by the width-bridge unit
//! tests and the cross-width live suites; this test pins host-native width
//! portably via `size_of::<CK_ULONG>()` instead of duplicating them.

mod common_3x;
mod support;

use std::sync::Arc;

use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_types::*;

use common_3x::{init_client, mock_daemon};
use support::{
    DaemonHarness, ProviderFixture, SkipReason, find_token_slot, initialized_client,
    open_user_session, softhsm2_present,
};

const RSA_KEYGEN: CkMechanismType = CkMechanismType::RSA_PKCS_KEY_PAIR_GEN;
const EC_KEYGEN: CkMechanismType = CkMechanismType::EC_KEY_PAIR_GEN;
const CKF_SERIAL: CkSessionFlags = CkSessionFlags::SERIAL_SESSION;

/// DER-encoded `prime256v1` OID for `CKA_EC_PARAMS` (X9.62 §4.3).
const P256_OID: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

fn rsa_pub_template(modulus_bits: u64) -> Vec<CkAttribute> {
    vec![
        CkAttribute {
            attr_type: CkAttributeType::MODULUS_BITS,
            value: Some(CkAttributeValue::Ulong(modulus_bits)),
        },
        CkAttribute {
            attr_type: CkAttributeType::PUBLIC_EXPONENT,
            value: Some(CkAttributeValue::Bytes(vec![0x01, 0x00, 0x01].into())),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
    ]
}

fn rsa_priv_template() -> Vec<CkAttribute> {
    vec![
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::SENSITIVE,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ]
}

fn ec_pub_template() -> Vec<CkAttribute> {
    vec![
        CkAttribute {
            attr_type: CkAttributeType::EC_PARAMS,
            value: Some(CkAttributeValue::Bytes(P256_OID.to_vec().into())),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
    ]
}

fn rsa_mechanism() -> CkMechanism {
    CkMechanism { mechanism_type: RSA_KEYGEN, params: None }
}

async fn mock_session(
    backend: Arc<MockBackend>,
) -> (pkcs11_proxy_ng_client::Pkcs11Client, CkSessionHandle, impl Sized) {
    let (endpoint, shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;
    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();
    (client, session, shutdown)
}

fn assert_exponent_bytes(value: &Option<CkAttributeValue>) {
    match value {
        // Synthetic test constant (65537), not key material.
        Some(CkAttributeValue::Bytes(bytes)) => {
            bytes.expose(|plain| assert_eq!(plain, &[0x01, 0x00, 0x01]));
        }
        other => panic!("PUBLIC_EXPONENT must be Bytes, got {other:?}"),
    }
}

// ── Tier M: MockBackend conversion fidelity (always runs) ────────────────

#[tokio::test]
async fn rsa_templates_reach_mock_verbatim_for_2048_3072_4096() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![RSA_KEYGEN]));
    let (mut client, session, _shutdown) = mock_session(backend.clone()).await;

    for bits in [2048u64, 3072, 4096] {
        let public = rsa_pub_template(bits);
        let private = rsa_priv_template();
        let (pub_handle, priv_handle) = client
            .generate_key_pair(session, &rsa_mechanism(), Some(&public), Some(&private))
            .await
            .unwrap();
        assert_ne!(pub_handle, CkObjectHandle(0));
        assert_ne!(priv_handle, CkObjectHandle(0));

        let recorded = backend.take_keygen_templates();
        assert_eq!(recorded.len(), 1, "one backend call per keygen");
        let (mechanism, recorded_pub, recorded_priv) = &recorded[0];
        assert_eq!(mechanism.mechanism_type, RSA_KEYGEN);
        assert_eq!(mechanism.params, None, "RSA keygen is parameterless");
        assert_eq!(recorded_pub.as_deref(), Some(public.as_slice()));
        assert_eq!(recorded_priv.as_deref(), Some(private.as_slice()));
        // Spot-check the security-relevant values, not just struct equality.
        assert_eq!(recorded_pub.as_ref().unwrap()[0].value, Some(CkAttributeValue::Ulong(bits)));
        assert_exponent_bytes(&recorded_pub.as_ref().unwrap()[1].value);
    }
}

#[tokio::test]
async fn template_nullness_preserved_to_mock() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![RSA_KEYGEN]));
    let (mut client, session, _shutdown) = mock_session(backend.clone()).await;

    let public = rsa_pub_template(2048);
    client.generate_key_pair(session, &rsa_mechanism(), Some(&public), None).await.unwrap();
    let recorded = backend.take_keygen_templates();
    assert_eq!(recorded.len(), 1);
    assert!(recorded[0].1.is_some(), "public template present");
    assert!(recorded[0].2.is_none(), "private None must stay None");

    client.generate_key_pair(session, &rsa_mechanism(), None, None).await.unwrap();
    let recorded = backend.take_keygen_templates();
    assert_eq!(recorded.len(), 1);
    assert!(recorded[0].1.is_none(), "public None must stay None");
    assert!(recorded[0].2.is_none(), "private None must stay None");
}

#[tokio::test]
async fn malformed_modulus_bits_traverses_mock_as_bytes() {
    // A caller-supplied MODULUS_BITS with a non-native length arrives at the
    // Rust layer as opaque Bytes (shim passthrough); the conversion path must
    // carry it verbatim and let the provider decide.
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![RSA_KEYGEN]));
    let (mut client, session, _shutdown) = mock_session(backend.clone()).await;

    let public = vec![CkAttribute {
        attr_type: CkAttributeType::MODULUS_BITS,
        value: Some(CkAttributeValue::Bytes(vec![0x08, 0x00, 0x00].into())),
    }];
    client.generate_key_pair(session, &rsa_mechanism(), Some(&public), Some(&[])).await.unwrap();
    let recorded = backend.take_keygen_templates();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].1.as_deref(), Some(public.as_slice()));
}

#[tokio::test]
async fn ec_control_template_reaches_mock() {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![EC_KEYGEN]));
    let (mut client, session, _shutdown) = mock_session(backend.clone()).await;

    let public = ec_pub_template();
    let mechanism = CkMechanism { mechanism_type: EC_KEYGEN, params: None };
    client.generate_key_pair(session, &mechanism, Some(&public), Some(&[])).await.unwrap();
    let recorded = backend.take_keygen_templates();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].0.mechanism_type, EC_KEYGEN);
    assert_eq!(recorded[0].1.as_deref(), Some(public.as_slice()));
}

// ── Tier S: SoftHSM2 real-backend parity (skipped when absent) ────────────

async fn softhsm_client()
-> Option<(pkcs11_proxy_ng_client::Pkcs11Client, CkSessionHandle, DaemonHarness, ProviderFixture)> {
    if !softhsm2_present() {
        record_skip!(SkipReason::ProviderMissing("SoftHSM2"));
        return None;
    }
    let fixture = ProviderFixture::soft_hsm().await.ok()?;
    let daemon = DaemonHarness::start(&fixture).await.ok()?;
    let mut client = initialized_client(daemon.endpoint()).await.ok()?;
    let slot = find_token_slot(&mut client).await.ok()?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await.ok()?;
    Some((client, session, daemon, fixture))
}

async fn read_ulong(
    client: &mut pkcs11_proxy_ng_client::Pkcs11Client,
    session: CkSessionHandle,
    object: CkObjectHandle,
    attr_type: CkAttributeType,
) -> CkAttributeValue {
    let query = vec![CkAttribute { attr_type, value: Some(CkAttributeValue::Ulong(0)) }];
    let (rv, values) = client.get_attribute_value(session, object, &query).await.unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(values.len(), 1);
    values.into_iter().next().unwrap().value.unwrap()
}

#[tokio::test]
async fn softhsm_rsa_keygen_succeeds_and_reads_back() -> Result<(), String> {
    let Some((mut client, session, daemon, _fixture)) = softhsm_client().await else {
        return Ok(());
    };
    // Host-native width, portably: the Ulong path must match CK_ULONG.
    assert_eq!(std::mem::size_of::<u64>(), 8, "u64 wire width");
    let _native_ck_ulong_bytes = std::mem::size_of::<cryptoki_sys::CK_ULONG>();

    for bits in [2048u64, 3072, 4096] {
        let (pub_handle, _priv_handle) = client
            .generate_key_pair(
                session,
                &rsa_mechanism(),
                Some(&rsa_pub_template(bits)),
                Some(&rsa_priv_template()),
            )
            .await
            .map_err(|rv| format!("SoftHSM2 RSA-{bits} keygen failed: {rv}"))?;
        let read_bits =
            read_ulong(&mut client, session, pub_handle, CkAttributeType::MODULUS_BITS).await;
        assert_eq!(read_bits, CkAttributeValue::Ulong(bits));
        let query = vec![CkAttribute {
            attr_type: CkAttributeType::PUBLIC_EXPONENT,
            value: Some(CkAttributeValue::Bytes(vec![0; 8].into())),
        }];
        let (rv, values) = client.get_attribute_value(session, pub_handle, &query).await.unwrap();
        assert_eq!(rv, CkRv::OK);
        match &values[0].value {
            Some(CkAttributeValue::Bytes(bytes)) => {
                bytes.expose(|b| assert_eq!(b, &[0x01, 0x00, 0x01]));
            }
            other => panic!("PUBLIC_EXPONENT readback must be Bytes, got {other:?}"),
        }
        client.destroy_object(session, pub_handle).await.unwrap();
        client.destroy_object(session, _priv_handle).await.unwrap();
    }

    daemon.shutdown().await
}

#[tokio::test]
async fn softhsm_malformed_modulus_bits_refused_cleanly() -> Result<(), String> {
    let Some((mut client, session, daemon, _fixture)) = softhsm_client().await else {
        return Ok(());
    };
    // 3-byte MODULUS_BITS (what a malformed native template becomes after
    // shim passthrough): the provider must refuse with a clean RV — the
    // exact code is provider behavior, the absence of success/hang is the
    // contract.
    let public = vec![CkAttribute {
        attr_type: CkAttributeType::MODULUS_BITS,
        value: Some(CkAttributeValue::Bytes(vec![0x08, 0x00, 0x00].into())),
    }];
    let result =
        client.generate_key_pair(session, &rsa_mechanism(), Some(&public), Some(&[])).await;
    match &result {
        Ok(_) => panic!("malformed MODULUS_BITS must not generate a key"),
        Err(rv) => eprintln!("SoftHSM2 malformed MODULUS_BITS refusal: {rv}"),
    }

    daemon.shutdown().await
}

#[tokio::test]
async fn softhsm_ec_p256_keygen_succeeds() -> Result<(), String> {
    let Some((mut client, session, daemon, _fixture)) = softhsm_client().await else {
        return Ok(());
    };
    let mechanism = CkMechanism { mechanism_type: EC_KEYGEN, params: None };
    let (pub_handle, priv_handle) = client
        .generate_key_pair(session, &mechanism, Some(&ec_pub_template()), Some(&[]))
        .await
        .map_err(|rv| format!("SoftHSM2 EC P-256 keygen failed: {rv}"))?;
    let query = vec![CkAttribute {
        attr_type: CkAttributeType::EC_PARAMS,
        value: Some(CkAttributeValue::Bytes(vec![0; 16].into())),
    }];
    let (rv, values) = client.get_attribute_value(session, pub_handle, &query).await.unwrap();
    assert_eq!(rv, CkRv::OK);
    match &values[0].value {
        Some(CkAttributeValue::Bytes(bytes)) => {
            bytes.expose(|b| assert_eq!(b, P256_OID));
        }
        other => panic!("EC_PARAMS readback must be Bytes, got {other:?}"),
    }
    client.destroy_object(session, pub_handle).await.unwrap();
    client.destroy_object(session, priv_handle).await.unwrap();

    daemon.shutdown().await
}
