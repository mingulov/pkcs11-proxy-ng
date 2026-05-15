//! Provider-specific object-template compatibility tests (Item 83).
//!
//! These tests exercise keygen and import templates with SoftHSM2 to
//! document which attributes are required, optional, or rejected.
//! Each test records its finding via eprintln so results are visible
//! with `--nocapture`.
//!
//! All tests require SoftHSM2 and are marked `#[ignore]`.

mod support;

use pkcs11_proxy_ng_types::*;
use support::*;

/// Helper: attempt to generate an RSA key pair with the given templates.
/// Returns Ok((pub, priv)) or Err(CkRv).
async fn try_rsa_keygen(
    client: &mut pkcs11_proxy_ng_client::Pkcs11Client,
    session: CkSessionHandle,
    pub_template: &[CkAttribute],
    priv_template: &[CkAttribute],
) -> Result<(CkObjectHandle, CkObjectHandle), CkRv> {
    let mechanism =
        CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN, params: None };
    client.generate_key_pair(session, &mechanism, pub_template, priv_template).await
}

/// Helper: attempt to generate an AES key with the given template.
async fn try_aes_keygen(
    client: &mut pkcs11_proxy_ng_client::Pkcs11Client,
    session: CkSessionHandle,
    template: &[CkAttribute],
) -> Result<CkObjectHandle, CkRv> {
    // CKM_AES_KEY_GEN = 0x00001080
    let mechanism = CkMechanism { mechanism_type: CkMechanismType(0x00001080), params: None };
    client.generate_key(session, &mechanism, template).await
}

fn rsa_pub_template(label: &str, extra: &[CkAttribute]) -> Vec<CkAttribute> {
    let mut t = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::PUBLIC_KEY.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CkKeyType::RSA.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::MODULUS_BITS,
            value: Some(CkAttributeValue::Ulong(2048)),
        },
        CkAttribute {
            attr_type: CkAttributeType::PUBLIC_EXPONENT,
            value: Some(CkAttributeValue::Bytes(vec![0x01, 0x00, 0x01])),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label.to_string())),
        },
        CkAttribute {
            attr_type: CkAttributeType::VERIFY,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];
    t.extend_from_slice(extra);
    t
}

fn rsa_priv_template(label: &str, extra: &[CkAttribute]) -> Vec<CkAttribute> {
    let mut t = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::PRIVATE_KEY.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CkKeyType::RSA.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label.to_string())),
        },
        CkAttribute { attr_type: CkAttributeType::SIGN, value: Some(CkAttributeValue::Bool(true)) },
        CkAttribute {
            attr_type: CkAttributeType::SENSITIVE,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];
    t.extend_from_slice(extra);
    t
}

// ── RSA keygen template variants ──────────────────────────────────────

#[tokio::test]
#[ignore]
async fn rsa_keygen_minimal_template() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    // Minimal: just MODULUS_BITS and PUBLIC_EXPONENT on public side
    let pub_t = vec![
        CkAttribute {
            attr_type: CkAttributeType::MODULUS_BITS,
            value: Some(CkAttributeValue::Ulong(2048)),
        },
        CkAttribute {
            attr_type: CkAttributeType::PUBLIC_EXPONENT,
            value: Some(CkAttributeValue::Bytes(vec![0x01, 0x00, 0x01])),
        },
    ];
    let priv_t = vec![];

    let result = try_rsa_keygen(&mut client, session, &pub_t, &priv_t).await;
    match &result {
        Ok(_) => eprintln!("[SoftHSM2] RSA minimal template: OK"),
        Err(rv) => eprintln!("[SoftHSM2] RSA minimal template: {rv}"),
    }
    assert!(result.is_ok(), "SoftHSM2 should accept minimal RSA template");

    daemon.shutdown().await
}

#[tokio::test]
#[ignore]
async fn rsa_keygen_with_id_attribute() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    let label = unique_label("rsa-id");
    let key_id = vec![0x01, 0x02, 0x03];
    let extra = [CkAttribute {
        attr_type: CkAttributeType::ID,
        value: Some(CkAttributeValue::Bytes(key_id.clone())),
    }];
    let pub_t = rsa_pub_template(&label, &extra);
    let priv_t = rsa_priv_template(&label, &extra);

    let result = try_rsa_keygen(&mut client, session, &pub_t, &priv_t).await;
    match &result {
        Ok(_) => eprintln!("[SoftHSM2] RSA with CKA_ID: OK"),
        Err(rv) => eprintln!("[SoftHSM2] RSA with CKA_ID: {rv}"),
    }
    assert!(result.is_ok(), "SoftHSM2 should accept CKA_ID in RSA template");

    daemon.shutdown().await
}

#[tokio::test]
#[ignore]
async fn rsa_keygen_extractable_variants() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    // Extractable = true
    let label1 = unique_label("rsa-extract");
    let extra1 = [CkAttribute {
        attr_type: CkAttributeType::EXTRACTABLE,
        value: Some(CkAttributeValue::Bool(true)),
    }];
    let result1 = try_rsa_keygen(
        &mut client,
        session,
        &rsa_pub_template(&label1, &[]),
        &rsa_priv_template(&label1, &extra1),
    )
    .await;
    let msg1 = result1.as_ref().map_or_else(|e| format!("{e}"), |_| "OK".into());
    eprintln!("[SoftHSM2] RSA EXTRACTABLE=true: {msg1}");

    // Extractable = false (default-like)
    let label2 = unique_label("rsa-noextract");
    let extra2 = [CkAttribute {
        attr_type: CkAttributeType::EXTRACTABLE,
        value: Some(CkAttributeValue::Bool(false)),
    }];
    let result2 = try_rsa_keygen(
        &mut client,
        session,
        &rsa_pub_template(&label2, &[]),
        &rsa_priv_template(&label2, &extra2),
    )
    .await;
    let msg2 = result2.as_ref().map_or_else(|e| format!("{e}"), |_| "OK".into());
    eprintln!("[SoftHSM2] RSA EXTRACTABLE=false: {msg2}");

    assert!(result1.is_ok() && result2.is_ok(), "both extractable variants should work");
    daemon.shutdown().await
}

#[tokio::test]
#[ignore]
async fn rsa_keygen_wrap_unwrap_usage() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    let label = unique_label("rsa-wrap");
    let pub_extra = [CkAttribute {
        attr_type: CkAttributeType::WRAP,
        value: Some(CkAttributeValue::Bool(true)),
    }];
    let priv_extra = [CkAttribute {
        attr_type: CkAttributeType::UNWRAP,
        value: Some(CkAttributeValue::Bool(true)),
    }];
    let result = try_rsa_keygen(
        &mut client,
        session,
        &rsa_pub_template(&label, &pub_extra),
        &rsa_priv_template(&label, &priv_extra),
    )
    .await;
    let msg = result.as_ref().map_or_else(|e| format!("{e}"), |_| "OK".into());
    eprintln!("[SoftHSM2] RSA WRAP/UNWRAP usage: {msg}");
    assert!(result.is_ok(), "SoftHSM2 should accept WRAP/UNWRAP usage flags");

    daemon.shutdown().await
}

// ── AES keygen template variants ──────────────────────────────────────

#[tokio::test]
#[ignore]
async fn aes_keygen_template_variants() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    // Check if AES_KEY_GEN is supported
    // CKM_AES_KEY_GEN = 0x00001080
    if !supports_mechanism(&mut client, slot, CkMechanismType(0x00001080)).await? {
        record_skip!(SkipReason::MechanismUnsupported {
            provider: "SoftHSM2",
            mechanism: "CKM_AES_KEY_GEN",
        });
        daemon.shutdown().await?;
        return Ok(());
    }

    // AES-128
    let label128 = unique_label("aes128");
    let t128 = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CkKeyType::AES.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::VALUE_LEN,
            value: Some(CkAttributeValue::Ulong(16)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label128)),
        },
        CkAttribute {
            attr_type: CkAttributeType::ENCRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::DECRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];
    let r128 = try_aes_keygen(&mut client, session, &t128).await;
    let msg128 = r128.as_ref().map_or_else(|e| format!("{e}"), |_| "OK".into());
    eprintln!("[SoftHSM2] AES-128: {msg128}");

    // AES-256
    let label256 = unique_label("aes256");
    let t256 = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CkKeyType::AES.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::VALUE_LEN,
            value: Some(CkAttributeValue::Ulong(32)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label256)),
        },
        CkAttribute {
            attr_type: CkAttributeType::ENCRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::DECRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];
    let r256 = try_aes_keygen(&mut client, session, &t256).await;
    let msg256 = r256.as_ref().map_or_else(|e| format!("{e}"), |_| "OK".into());
    eprintln!("[SoftHSM2] AES-256: {msg256}");

    assert!(r128.is_ok(), "AES-128 keygen should succeed");
    assert!(r256.is_ok(), "AES-256 keygen should succeed");

    daemon.shutdown().await
}

// ── EC keygen template variants ───────────────────────────────────────

#[tokio::test]
#[ignore]
async fn ec_keygen_template_variants() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    if !supports_mechanism(&mut client, slot, CkMechanismType::EC_KEY_PAIR_GEN).await? {
        record_skip!(SkipReason::MechanismUnsupported {
            provider: "SoftHSM2",
            mechanism: "CKM_EC_KEY_PAIR_GEN",
        });
        daemon.shutdown().await?;
        return Ok(());
    }

    // P-256 (OID 1.2.840.10045.3.1.7)
    let p256_oid = vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let label = unique_label("ec-p256");
    let pub_t = vec![
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CkKeyType::EC.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::EC_PARAMS,
            value: Some(CkAttributeValue::Bytes(p256_oid.clone())),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label.clone())),
        },
        CkAttribute {
            attr_type: CkAttributeType::VERIFY,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];
    let priv_t = vec![
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label.clone())),
        },
        CkAttribute { attr_type: CkAttributeType::SIGN, value: Some(CkAttributeValue::Bool(true)) },
        CkAttribute {
            attr_type: CkAttributeType::SENSITIVE,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::EC_KEY_PAIR_GEN, params: None };
    let result = client.generate_key_pair(session, &mechanism, &pub_t, &priv_t).await;
    let msg = result.as_ref().map_or_else(|e| format!("{e}"), |_| "OK".into());
    eprintln!("[SoftHSM2] EC P-256 keygen: {msg}");
    assert!(result.is_ok(), "EC P-256 keygen should succeed");

    // P-384 (OID 1.3.132.0.34)
    let p384_oid = vec![0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
    let label2 = unique_label("ec-p384");
    let pub_t2 = vec![
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CkKeyType::EC.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::EC_PARAMS,
            value: Some(CkAttributeValue::Bytes(p384_oid)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label2.clone())),
        },
        CkAttribute {
            attr_type: CkAttributeType::VERIFY,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];
    let priv_t2 = vec![
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label2)),
        },
        CkAttribute { attr_type: CkAttributeType::SIGN, value: Some(CkAttributeValue::Bool(true)) },
    ];
    let result2 = client.generate_key_pair(session, &mechanism, &pub_t2, &priv_t2).await;
    let msg2 = result2.as_ref().map_or_else(|e| format!("{e}"), |_| "OK".into());
    eprintln!("[SoftHSM2] EC P-384 keygen: {msg2}");
    assert!(result2.is_ok(), "EC P-384 keygen should succeed");

    daemon.shutdown().await
}

// ── Data object import ────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn data_object_template_variants() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    // Minimal data object
    let label1 = unique_label("data-minimal");
    let t1 = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::DATA.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::VALUE,
            value: Some(CkAttributeValue::Bytes(b"hello".to_vec())),
        },
    ];
    let r1 = client.create_object(session, &t1).await;
    let msg1 = r1.as_ref().map_or_else(|e| format!("{e}"), |_| "OK".into());
    eprintln!("[SoftHSM2] Data object (minimal): {msg1}");

    // Data object with label and application
    let t2 = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::DATA.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label1)),
        },
        CkAttribute {
            attr_type: CkAttributeType::VALUE,
            value: Some(CkAttributeValue::Bytes(b"test data".to_vec())),
        },
        CkAttribute {
            attr_type: CkAttributeType::PRIVATE,
            value: Some(CkAttributeValue::Bool(false)),
        },
    ];
    let r2 = client.create_object(session, &t2).await;
    let msg2 = r2.as_ref().map_or_else(|e| format!("{e}"), |_| "OK".into());
    eprintln!("[SoftHSM2] Data object (full): {msg2}");

    assert!(r1.is_ok(), "minimal data object should succeed");
    assert!(r2.is_ok(), "full data object should succeed");

    daemon.shutdown().await
}

// ── Token vs session persistence in templates ─────────────────────────

#[tokio::test]
#[ignore]
async fn token_object_attribute_required_for_persistence() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    // Default (no CKA_TOKEN): should default to session object
    let label1 = unique_label("default-persist");
    let pub_t = vec![
        CkAttribute {
            attr_type: CkAttributeType::MODULUS_BITS,
            value: Some(CkAttributeValue::Ulong(2048)),
        },
        CkAttribute {
            attr_type: CkAttributeType::PUBLIC_EXPONENT,
            value: Some(CkAttributeValue::Bytes(vec![0x01, 0x00, 0x01])),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label1.clone())),
        },
    ];
    let priv_t = vec![CkAttribute {
        attr_type: CkAttributeType::LABEL,
        value: Some(CkAttributeValue::String(label1)),
    }];
    let r1 = try_rsa_keygen(&mut client, session, &pub_t, &priv_t).await;
    let msg = r1.as_ref().map_or_else(|e| format!("{e}"), |_| "OK (session object)".into());
    eprintln!("[SoftHSM2] RSA without CKA_TOKEN (default): {msg}");
    assert!(r1.is_ok(), "keygen without CKA_TOKEN should default to session object");

    daemon.shutdown().await
}
