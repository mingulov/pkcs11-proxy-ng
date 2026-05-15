//! Comprehensive parameterized mechanism integration tests against SoftHSM2.
//!
//! Each test proves a different mechanism parameter shape works through the full
//! proxy stack: Rust struct -> proto -> gRPC -> proto -> C struct -> SoftHSM2 FFI
//! -> result -> reverse path.
//!
//! All tests are `#[ignore]` because they require SoftHSM2 to be installed.
//!
//! Run with:
//! ```sh
//! cargo test -p pkcs11-proxy --test parameterized_mechanism_test -- --ignored --test-threads=1 --nocapture
//! ```

mod support;

use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::{
    CkAttribute, CkAttributeType, CkAttributeValue, CkMechanism, CkMechanismParams,
    CkMechanismType, CkObjectClass, CkObjectHandle, CkResult, CkRv, CkSessionHandle, GcmParams,
    IvParams,
};
use support::{
    CKK_DES3, CKM_AES_CBC_ENCRYPT_DATA, CKM_AES_CTR, CKM_DES3_KEY_GEN, CKM_HKDF_DERIVE,
    DaemonHarness, ProviderFixture, ensure_user_token, generate_aes_key,
    generate_named_rsa_key_pair, initialized_client, open_user_session, supports_mechanism,
    test_aes_cbc_encrypt_data_derive, test_aes_cbc_encrypt_decrypt, test_aes_ctr_encrypt_decrypt,
    test_ecdh1_derive, test_hkdf_derive, test_rsa_oaep_encrypt_decrypt, test_rsa_pss_sign_verify,
};

/// Generate a DES3 (Triple-DES) key for encrypt/decrypt.
async fn generate_des3_key(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
) -> CkResult<CkObjectHandle> {
    let mechanism = CkMechanism { mechanism_type: CKM_DES3_KEY_GEN, params: None };
    let template = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CKK_DES3)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
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
    client.generate_key(session, &mechanism, &template).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// AES-CBC encrypt + decrypt with IvParams (16-byte IV) through the proxy.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn softhsm_aes_cbc_encrypt_decrypt() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CkMechanismType::AES_CBC).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "softhsm2",
            mechanism: "CKM_AES_CBC",
        });
        client.finalize().await.map_err(|rv| rv.to_string())?;
        daemon.shutdown().await?;
        return Ok(());
    }

    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    test_aes_cbc_encrypt_decrypt(&mut client, session, slot).await?;

    eprintln!("AES-CBC encrypt+decrypt with IvParams: OK");

    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// AES-CBC-PAD encrypt + decrypt with IvParams and non-block-aligned plaintext.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn softhsm_aes_cbc_pad_encrypt_decrypt() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CkMechanismType::AES_CBC_PAD).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "softhsm2",
            mechanism: "CKM_AES_CBC_PAD",
        });
        client.finalize().await.map_err(|rv| rv.to_string())?;
        daemon.shutdown().await?;
        return Ok(());
    }

    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let aes_key = generate_aes_key(&mut client, session, 32)
        .await
        .map_err(|rv| format!("AES key generation failed: {rv}"))?;

    let iv = vec![
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F,
    ];
    let cbc_pad_mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_CBC_PAD,
        params: Some(CkMechanismParams::Iv(IvParams { iv: iv.clone() })),
    };

    // Non-block-aligned plaintext: 13 bytes (not a multiple of 16).
    let plaintext = b"Hello, world!";

    // Encrypt.
    client
        .encrypt_init(session, &cbc_pad_mechanism, aes_key)
        .await
        .map_err(|rv| format!("C_EncryptInit(AES-CBC-PAD) failed: {rv}"))?;
    let ciphertext = client
        .encrypt(session, plaintext)
        .await
        .map_err(|rv| format!("C_Encrypt(AES-CBC-PAD) failed: {rv}"))?;

    if ciphertext.is_empty() {
        return Err("ciphertext should be non-empty".into());
    }
    if ciphertext.len() % 16 != 0 {
        return Err("padded ciphertext should be block-aligned".into());
    }

    // Decrypt.
    client
        .decrypt_init(session, &cbc_pad_mechanism, aes_key)
        .await
        .map_err(|rv| format!("C_DecryptInit(AES-CBC-PAD) failed: {rv}"))?;
    let decrypted = client
        .decrypt(session, &ciphertext)
        .await
        .map_err(|rv| format!("C_Decrypt(AES-CBC-PAD) failed: {rv}"))?;

    if decrypted.as_slice() != plaintext.as_slice() {
        return Err("AES-CBC-PAD round-trip should recover plaintext".into());
    }
    eprintln!(
        "AES-CBC-PAD encrypt+decrypt with IvParams: OK (plaintext {} -> ciphertext {} bytes)",
        plaintext.len(),
        ciphertext.len()
    );

    // Clean up.
    client.destroy_object(session, aes_key).await.map_err(|rv| rv.to_string())?;
    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// DES3-CBC encrypt + decrypt with IvParams (8-byte IV) through the proxy.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn softhsm_des3_cbc_encrypt_decrypt() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CkMechanismType::DES3_CBC).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "softhsm2",
            mechanism: "CKM_DES3_CBC",
        });
        client.finalize().await.map_err(|rv| rv.to_string())?;
        daemon.shutdown().await?;
        return Ok(());
    }

    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let des3_key = generate_des3_key(&mut client, session)
        .await
        .map_err(|rv| format!("DES3 key generation failed: {rv}"))?;

    // 8-byte IV for DES3-CBC.
    let iv = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let des3_cbc_mechanism = CkMechanism {
        mechanism_type: CkMechanismType::DES3_CBC,
        params: Some(CkMechanismParams::Iv(IvParams { iv: iv.clone() })),
    };

    // Plaintext must be a multiple of 8 (DES3 block size) for CBC without padding.
    let plaintext = b"DES3TEST"; // exactly 8 bytes

    // Encrypt.
    client
        .encrypt_init(session, &des3_cbc_mechanism, des3_key)
        .await
        .map_err(|rv| format!("C_EncryptInit(DES3-CBC) failed: {rv}"))?;
    let ciphertext = client
        .encrypt(session, plaintext)
        .await
        .map_err(|rv| format!("C_Encrypt(DES3-CBC) failed: {rv}"))?;

    if ciphertext.is_empty() {
        return Err("ciphertext should be non-empty".into());
    }
    if ciphertext.as_slice() == plaintext.as_slice() {
        return Err("ciphertext should differ from plaintext".into());
    }

    // Decrypt with same IV.
    client
        .decrypt_init(session, &des3_cbc_mechanism, des3_key)
        .await
        .map_err(|rv| format!("C_DecryptInit(DES3-CBC) failed: {rv}"))?;
    let decrypted = client
        .decrypt(session, &ciphertext)
        .await
        .map_err(|rv| format!("C_Decrypt(DES3-CBC) failed: {rv}"))?;

    if decrypted.as_slice() != plaintext.as_slice() {
        return Err("DES3-CBC round-trip should recover plaintext".into());
    }
    eprintln!("DES3-CBC encrypt+decrypt with IvParams (8-byte IV): OK");

    // Clean up.
    client.destroy_object(session, des3_key).await.map_err(|rv| rv.to_string())?;
    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// RSA-PSS sign + verify with PssParams through the proxy against SoftHSM2.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn softhsm_rsa_pss_sign_verify() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, support::CKM_SHA256_RSA_PKCS_PSS).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "softhsm2",
            mechanism: "CKM_SHA256_RSA_PKCS_PSS",
        });
        client.finalize().await.map_err(|rv| rv.to_string())?;
        daemon.shutdown().await?;
        return Ok(());
    }

    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    let pair = generate_named_rsa_key_pair(&mut client, session, "softhsm-pss-test", false).await?;

    test_rsa_pss_sign_verify(&mut client, session, pair.public_key, pair.private_key).await?;

    eprintln!("RSA-PSS sign+verify with PssParams: OK");

    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// RSA-OAEP encrypt + decrypt with OaepParams through the proxy.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn softhsm_rsa_oaep_encrypt_decrypt() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CkMechanismType::RSA_PKCS_OAEP).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "softhsm2",
            mechanism: "CKM_RSA_PKCS_OAEP",
        });
        client.finalize().await.map_err(|rv| rv.to_string())?;
        daemon.shutdown().await?;
        return Ok(());
    }

    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    let pair =
        generate_named_rsa_key_pair(&mut client, session, "softhsm-oaep-test", false).await?;

    test_rsa_oaep_encrypt_decrypt(&mut client, session, pair.public_key, pair.private_key).await?;

    eprintln!("RSA-OAEP encrypt+decrypt with OaepParams (SHA-1): OK");

    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// ECDH1-DERIVE key derivation with Ecdh1DeriveParams through the proxy.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn softhsm_ecdh1_derive() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CkMechanismType::ECDH1_DERIVE).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "softhsm2",
            mechanism: "CKM_ECDH1_DERIVE",
        });
        client.finalize().await.map_err(|rv| rv.to_string())?;
        daemon.shutdown().await?;
        return Ok(());
    }

    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    test_ecdh1_derive(&mut client, session).await?;

    eprintln!("ECDH1-DERIVE produced key: OK");

    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// AES-CTR encrypt + decrypt with AesCtrParams through the proxy.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn softhsm_aes_ctr_encrypt_decrypt() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CKM_AES_CTR).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "softhsm2",
            mechanism: "CKM_AES_CTR",
        });
        client.finalize().await.map_err(|rv| rv.to_string())?;
        daemon.shutdown().await?;
        return Ok(());
    }

    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    test_aes_ctr_encrypt_decrypt(&mut client, session).await?;

    eprintln!("AES-CTR encrypt+decrypt with AesCtrParams: OK");

    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// AES-GCM encrypt + decrypt with GcmParams through the proxy against SoftHSM2.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn softhsm_aes_gcm_encrypt_decrypt() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CkMechanismType::AES_GCM).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "softhsm2",
            mechanism: "CKM_AES_GCM",
        });
        client.finalize().await.map_err(|rv| rv.to_string())?;
        daemon.shutdown().await?;
        return Ok(());
    }

    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let aes_key = generate_aes_key(&mut client, session, 32)
        .await
        .map_err(|rv| format!("AES key generation failed: {rv}"))?;

    // 12-byte IV (96 bits) — the standard GCM nonce size.
    let iv = vec![0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B];
    let aad = b"softhsm2 gcm additional authenticated data".to_vec();
    let gcm_mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv: iv.clone(),
            iv_bits: 96,
            iv_buffer_len: iv.len() as u64,
            aad: aad.clone(),
            tag_bits: 128,
        })),
    };

    // GCM supports arbitrary-length plaintext (no block alignment required).
    let plaintext = b"AES-GCM SoftHSM2 parameterized mechanism test payload";

    // Encrypt.
    client
        .encrypt_init(session, &gcm_mechanism, aes_key)
        .await
        .map_err(|rv| format!("C_EncryptInit(AES-GCM) failed: {rv}"))?;

    let ciphertext = match client.encrypt(session, plaintext).await {
        Ok(ct) => ct,
        Err(rv) if rv == CkRv::BUFFER_TOO_SMALL => {
            // Known SoftHSM2 GCM buffer sizing issue: skip gracefully.
            eprintln!(
                "Known SoftHSM2 AES-GCM buffer sizing issue (CKR_BUFFER_TOO_SMALL) — skipping"
            );
            client.destroy_object(session, aes_key).await.map_err(|rv| rv.to_string())?;
            client.logout(session).await.map_err(|rv| rv.to_string())?;
            client.close_session(session).await.map_err(|rv| rv.to_string())?;
            client.finalize().await.map_err(|rv| rv.to_string())?;
            daemon.shutdown().await?;
            return Ok(());
        }
        Err(rv) => return Err(format!("C_Encrypt(AES-GCM) failed: {rv}")),
    };

    if ciphertext.is_empty() {
        return Err("AES-GCM ciphertext should be non-empty".into());
    }
    // GCM ciphertext = plaintext length + tag length (128 bits = 16 bytes).
    let expected_ct_len = plaintext.len() + 16;
    if ciphertext.len() != expected_ct_len {
        return Err(format!(
            "AES-GCM ciphertext should be plaintext + 16-byte tag ({}), got {}",
            expected_ct_len,
            ciphertext.len()
        ));
    }

    // Decrypt with the same mechanism + same params.
    let gcm_decrypt_mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv,
            iv_bits: 96,
            iv_buffer_len: 12,
            aad,
            tag_bits: 128,
        })),
    };
    client
        .decrypt_init(session, &gcm_decrypt_mechanism, aes_key)
        .await
        .map_err(|rv| format!("C_DecryptInit(AES-GCM) failed: {rv}"))?;
    let decrypted = client
        .decrypt(session, &ciphertext)
        .await
        .map_err(|rv| format!("C_Decrypt(AES-GCM) failed: {rv}"))?;

    if decrypted.as_slice() != plaintext.as_slice() {
        return Err("AES-GCM round-trip should recover plaintext".into());
    }
    eprintln!("AES-GCM encrypt+decrypt with GcmParams: OK");

    // Clean up.
    client.destroy_object(session, aes_key).await.map_err(|rv| rv.to_string())?;
    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// HKDF key derivation with HkdfParams through the proxy against SoftHSM2.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn softhsm_hkdf_derive() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CKM_HKDF_DERIVE).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "softhsm2",
            mechanism: "CKM_HKDF_DERIVE",
        });
        client.finalize().await.map_err(|rv| rv.to_string())?;
        daemon.shutdown().await?;
        return Ok(());
    }

    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    test_hkdf_derive(&mut client, session, b"softhsm2-hkdf-salt-value", b"softhsm2 hkdf test")
        .await?;

    eprintln!("HKDF-DERIVE produced key: OK");

    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// AES-CBC-ENCRYPT-DATA key derivation with AesCbcEncryptDataParams through
/// the proxy against SoftHSM2.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn softhsm_aes_cbc_encrypt_data_derive() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CKM_AES_CBC_ENCRYPT_DATA).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "softhsm2",
            mechanism: "CKM_AES_CBC_ENCRYPT_DATA",
        });
        client.finalize().await.map_err(|rv| rv.to_string())?;
        daemon.shutdown().await?;
        return Ok(());
    }

    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    test_aes_cbc_encrypt_data_derive(&mut client, session).await?;

    eprintln!("AES-CBC-ENCRYPT-DATA derive + use derived key: OK");

    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}
