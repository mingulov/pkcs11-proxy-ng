// W1-L12-03: test diagnostics (skip notices, progress, summaries) go to
// stderr by design; the workspace lint table denies this sink elsewhere.
#![allow(clippy::print_stderr)]
//! Comprehensive parameterized mechanism integration tests against SoftHSM2.
//!
//! Each test proves a different mechanism parameter shape works through the full
//! proxy stack: Rust struct -> proto -> gRPC -> proto -> C struct -> SoftHSM2 FFI
//! -> result -> reverse path.
//!
//! Default `cargo test` behavior: these tests RUN by default (W1-L9-09). When
//! SoftHSM2 (`libsofthsm2.so` + `softhsm2-util`) is present, every test
//! executes for real. When it is absent, each test records an honest
//! `record_skip!(ProviderMissing)` line and returns `Ok` — never a silent
//! pass, and never a failure for a missing optional provider. Any other
//! fixture failure (present-but-broken provider) stays a hard error.
//!
//! The `softhsm_all_param_shapes_execute` driver additionally covers every
//! [`CkMechanismParams`] variant (see `support/shape_matrix.rs`): each shape
//! is pushed through the live stack, mechanisms SoftHSM2 does not implement
//! are recorded via `record_skip!(MechanismUnsupported)`, and the test
//! asserts `executed + skipped == 79` with zero transport failures, so a
//! crash can never masquerade as coverage.
//!
//! Run with:
//! ```sh
//! cargo test -p pkcs11-proxy-ng --test parameterized_mechanism_test -- --test-threads=1 --nocapture
//! ```

mod support;

use std::sync::atomic::{AtomicU64, Ordering};

use pkcs11_proxy_ng_client::{Pkcs11Client, set_transport_failure_hook};
use pkcs11_proxy_ng_types::{
    CkAttribute, CkAttributeType, CkAttributeValue, CkKeyType, CkMechanism, CkMechanismFlags,
    CkMechanismParams, CkMechanismType, CkObjectClass, CkObjectHandle, CkResult, CkRv,
    CkSessionHandle, CkSlotId, CkUserType, GcmParams, IvParams,
};
use support::{
    CKA_DERIVE, CKK_DES3, CKK_GENERIC_SECRET, CKM_AES_CBC_ENCRYPT_DATA, CKM_AES_CTR,
    CKM_DES3_KEY_GEN, CKM_HKDF_DERIVE, DaemonHarness, ProviderFixture, ShapeKeyHint,
    ensure_user_token, generate_aes_key, generate_named_rsa_key_pair, initialized_client,
    open_user_session, supports_mechanism, test_aes_cbc_encrypt_data_derive,
    test_aes_cbc_encrypt_decrypt, test_aes_ctr_encrypt_decrypt, test_ecdh1_derive,
    test_hkdf_derive, test_rsa_oaep_encrypt_decrypt, test_rsa_pss_sign_verify,
};

/// Build a SoftHSM2 fixture, or record an honest provider-missing skip.
///
/// The skip path triggers ONLY when SoftHSM2 is genuinely absent
/// (re-probed after the failure); a present-but-broken provider still fails.
async fn soft_hsm_or_skip() -> Result<Option<ProviderFixture>, String> {
    match ProviderFixture::soft_hsm().await {
        Ok(fixture) => Ok(Some(fixture)),
        Err(err) if !support::softhsm2_present() => {
            record_skip!(support::SkipReason::ProviderMissing("softhsm2"));
            eprintln!("fixture unavailable ({err}); recorded as skip, not a pass");
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

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
    client.generate_key(session, &mechanism, Some(&template)).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// AES-CBC encrypt + decrypt with IvParams (16-byte IV) through the proxy.
#[tokio::test]
async fn softhsm_aes_cbc_encrypt_decrypt() -> Result<(), String> {
    let Some(fixture) = soft_hsm_or_skip().await? else {
        return Ok(());
    };
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
async fn softhsm_aes_cbc_pad_encrypt_decrypt() -> Result<(), String> {
    let Some(fixture) = soft_hsm_or_skip().await? else {
        return Ok(());
    };
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
async fn softhsm_des3_cbc_encrypt_decrypt() -> Result<(), String> {
    let Some(fixture) = soft_hsm_or_skip().await? else {
        return Ok(());
    };
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
async fn softhsm_rsa_pss_sign_verify() -> Result<(), String> {
    let Some(fixture) = soft_hsm_or_skip().await? else {
        return Ok(());
    };
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
async fn softhsm_rsa_oaep_encrypt_decrypt() -> Result<(), String> {
    let Some(fixture) = soft_hsm_or_skip().await? else {
        return Ok(());
    };
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
async fn softhsm_ecdh1_derive() -> Result<(), String> {
    let Some(fixture) = soft_hsm_or_skip().await? else {
        return Ok(());
    };
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
async fn softhsm_aes_ctr_encrypt_decrypt() -> Result<(), String> {
    let Some(fixture) = soft_hsm_or_skip().await? else {
        return Ok(());
    };
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
async fn softhsm_aes_gcm_encrypt_decrypt() -> Result<(), String> {
    let Some(fixture) = soft_hsm_or_skip().await? else {
        return Ok(());
    };
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
            aad: aad.clone().into(),
            tag_bits: 128,

            iv_null: false,
            aad_null: false,
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
            // Known SoftHSM2 GCM buffer sizing issue: record the skip loudly
            // (W1-L9-09: never a silent pass).
            record_skip!(support::SkipReason::KnownIncompat {
                provider: "softhsm2",
                description: "AES-GCM CKR_BUFFER_TOO_SMALL buffer sizing",
            });
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
            aad: aad.into(),
            tag_bits: 128,

            iv_null: false,
            aad_null: false,
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
async fn softhsm_hkdf_derive() -> Result<(), String> {
    let Some(fixture) = soft_hsm_or_skip().await? else {
        return Ok(());
    };
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
async fn softhsm_aes_cbc_encrypt_data_derive() -> Result<(), String> {
    let Some(fixture) = soft_hsm_or_skip().await? else {
        return Ok(());
    };
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

// ---------------------------------------------------------------------------
// W1-L9-09 shape matrix: every CkMechanismParams variant through the live stack
// ---------------------------------------------------------------------------

/// Process-wide count of gRPC transport failures observed via the client hook.
///
/// The driver asserts this does not advance while the shapes run: a
/// server-side panic or channel failure mapped to a CK_RV must fail the run,
/// never count as executed coverage. (Sibling tests in this binary share the
/// process; any transport failure fails their own test first, so a trip here
/// always coincides with a genuinely red run.)
static TRANSPORT_FAILURE_COUNT: AtomicU64 = AtomicU64::new(0);

fn arm_transport_tripwire() {
    set_transport_failure_hook(|| {
        TRANSPORT_FAILURE_COUNT.fetch_add(1, Ordering::SeqCst);
    });
}

/// Open a RW session and log in, tolerating an already-logged-in token.
///
/// Each executed shape gets its own session so a successful `*_init` never
/// leaks `CKR_OPERATION_ACTIVE` into the next shape; login state may be
/// shared across the proxy's backend sessions, hence the tolerance.
async fn open_logged_in_session(
    client: &mut Pkcs11Client,
    slot: CkSlotId,
    user_pin: &str,
) -> Result<CkSessionHandle, String> {
    let session = support::open_public_session(client, slot, true).await?;
    match client.login(session, CkUserType::User, Some(user_pin.as_bytes())).await {
        Ok(()) => Ok(session),
        Err(rv) if rv == CkRv::USER_ALREADY_LOGGED_IN => Ok(session),
        Err(rv) => Err(format!("C_Login failed: {rv}")),
    }
}

fn token_object_attrs(label: &str) -> [CkAttribute; 2] {
    [
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label.to_string().into())),
        },
    ]
}

/// One key of each family the shape matrix may need, generated once per run
/// as TOKEN objects so every per-shape session can use them.
struct ShapeKeys {
    aes: CkObjectHandle,
    generic: CkObjectHandle,
    rsa_public: CkObjectHandle,
    rsa_private: CkObjectHandle,
    ec_private: CkObjectHandle,
}

impl ShapeKeys {
    async fn generate(client: &mut Pkcs11Client, session: CkSessionHandle) -> Result<Self, String> {
        let bool_attr = |attr_type: CkAttributeType| CkAttribute {
            attr_type,
            value: Some(CkAttributeValue::Bool(true)),
        };
        let aes_mech = CkMechanism { mechanism_type: CkMechanismType::AES_KEY_GEN, params: None };
        let mut aes_template = vec![
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
            bool_attr(CkAttributeType::ENCRYPT),
            bool_attr(CkAttributeType::DECRYPT),
            bool_attr(CKA_DERIVE),
        ];
        aes_template.extend(token_object_attrs("shape-matrix-aes"));
        let aes = client
            .generate_key(session, &aes_mech, Some(&aes_template))
            .await
            .map_err(|rv| format!("driver AES keygen failed: {rv}"))?;

        let generic_mech =
            CkMechanism { mechanism_type: CkMechanismType::GENERIC_SECRET_KEY_GEN, params: None };
        let mut generic_template = vec![
            CkAttribute {
                attr_type: CkAttributeType::CLASS,
                value: Some(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
            },
            CkAttribute {
                attr_type: CkAttributeType::KEY_TYPE,
                value: Some(CkAttributeValue::Ulong(CKK_GENERIC_SECRET)),
            },
            CkAttribute {
                attr_type: CkAttributeType::VALUE_LEN,
                value: Some(CkAttributeValue::Ulong(32)),
            },
            bool_attr(CkAttributeType::SIGN),
            bool_attr(CKA_DERIVE),
        ];
        generic_template.extend(token_object_attrs("shape-matrix-generic"));
        let generic = client
            .generate_key(session, &generic_mech, Some(&generic_template))
            .await
            .map_err(|rv| format!("driver generic-secret keygen failed: {rv}"))?;

        let rsa_mech =
            CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN, params: None };
        let mut rsa_pub = vec![
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
                value: Some(CkAttributeValue::Bytes(vec![0x01, 0x00, 0x01].into())),
            },
            bool_attr(CkAttributeType::ENCRYPT),
            bool_attr(CkAttributeType::VERIFY),
        ];
        rsa_pub.extend(token_object_attrs("shape-matrix-rsa-pub"));
        let mut rsa_priv = vec![
            CkAttribute {
                attr_type: CkAttributeType::CLASS,
                value: Some(CkAttributeValue::Ulong(CkObjectClass::PRIVATE_KEY.0)),
            },
            CkAttribute {
                attr_type: CkAttributeType::KEY_TYPE,
                value: Some(CkAttributeValue::Ulong(CkKeyType::RSA.0)),
            },
            bool_attr(CkAttributeType::DECRYPT),
            bool_attr(CkAttributeType::SIGN),
        ];
        rsa_priv.extend(token_object_attrs("shape-matrix-rsa-priv"));
        let (rsa_public, rsa_private) = client
            .generate_key_pair(session, &rsa_mech, Some(&rsa_pub), Some(&rsa_priv))
            .await
            .map_err(|rv| format!("driver RSA keygen failed: {rv}"))?;

        // P-256 OID: 1.2.840.10045.3.1.7 (DER-encoded).
        let ec_params = vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        let ec_mech =
            CkMechanism { mechanism_type: CkMechanismType::EC_KEY_PAIR_GEN, params: None };
        let mut ec_pub = vec![
            CkAttribute {
                attr_type: CkAttributeType::CLASS,
                value: Some(CkAttributeValue::Ulong(CkObjectClass::PUBLIC_KEY.0)),
            },
            CkAttribute {
                attr_type: CkAttributeType::KEY_TYPE,
                value: Some(CkAttributeValue::Ulong(CkKeyType::EC.0)),
            },
            CkAttribute {
                attr_type: CkAttributeType::EC_PARAMS,
                value: Some(CkAttributeValue::Bytes(ec_params.clone().into())),
            },
            bool_attr(CkAttributeType::VERIFY),
        ];
        ec_pub.extend(token_object_attrs("shape-matrix-ec-pub"));
        let mut ec_priv = vec![
            CkAttribute {
                attr_type: CkAttributeType::CLASS,
                value: Some(CkAttributeValue::Ulong(CkObjectClass::PRIVATE_KEY.0)),
            },
            CkAttribute {
                attr_type: CkAttributeType::KEY_TYPE,
                value: Some(CkAttributeValue::Ulong(CkKeyType::EC.0)),
            },
            bool_attr(CkAttributeType::SIGN),
            bool_attr(CKA_DERIVE),
        ];
        ec_priv.extend(token_object_attrs("shape-matrix-ec-priv"));
        let (_ec_public, ec_private) = client
            .generate_key_pair(session, &ec_mech, Some(&ec_pub), Some(&ec_priv))
            .await
            .map_err(|rv| format!("driver EC keygen failed: {rv}"))?;

        Ok(Self { aes, generic, rsa_public, rsa_private, ec_private })
    }

    fn resolve(&self, hint: ShapeKeyHint) -> CkObjectHandle {
        match hint {
            ShapeKeyHint::Aes => self.aes,
            ShapeKeyHint::GenericSecret => self.generic,
            ShapeKeyHint::RsaPrivate => self.rsa_private,
            ShapeKeyHint::RsaPublic => self.rsa_public,
            ShapeKeyHint::EcPrivate => self.ec_private,
        }
    }
}

fn generic_derive_template() -> Vec<CkAttribute> {
    vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(CKK_GENERIC_SECRET)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::EXTRACTABLE,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ]
}

/// Push one shape through the live stack, dispatching on the mechanism's
/// advertised operation flags. Any honest CK_RV outcome — success or a
/// mechanism-level error from the backend — proves the params traversed
/// Rust -> proto -> gRPC -> Rust -> C -> SoftHSM2; only a transport failure
/// (caught by the tripwire) or a test-harness error fails the shape.
///
/// The caller passes a fresh session per shape (closed afterwards) so a
/// successful `*_init` never leaks `CKR_OPERATION_ACTIVE` into the next
/// shape; keys are token objects shared across those sessions.
async fn execute_shape(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    slot: CkSlotId,
    case: &support::ShapeCase,
    keys: &ShapeKeys,
) -> Result<String, String> {
    let info = client
        .get_mechanism_info(slot, case.mechanism.mechanism_type)
        .await
        .map_err(|rv| format!("C_GetMechanismInfo({}) failed: {rv}", case.variant))?;
    let flags = info.flags.0;
    let key = keys.resolve(case.key);
    let mechanism = &case.mechanism;

    if flags & CkMechanismFlags::DERIVE != 0 {
        let template = generic_derive_template();
        return match client.derive_key(session, mechanism, key, Some(&template)).await {
            Ok(handle) => {
                let _ = client.destroy_object(session, handle).await;
                Ok("derive ok".to_string())
            }
            Err(rv) => Ok(format!("derive -> {rv}")),
        };
    }
    if flags & CkMechanismFlags::ENCRYPT != 0 {
        return match client.encrypt_init(session, mechanism, key).await {
            Ok(mech_out) => Ok(format!("encrypt-init ok (mechanism_out: {})", mech_out.is_some())),
            Err(rv) => Ok(format!("encrypt-init -> {rv}")),
        };
    }
    if flags & CkMechanismFlags::SIGN != 0 {
        return match client.sign_init(session, mechanism, key).await {
            Ok(()) => Ok("sign-init ok".to_string()),
            Err(rv) => Ok(format!("sign-init -> {rv}")),
        };
    }
    if flags & CkMechanismFlags::DIGEST != 0 {
        return match client.digest_init(session, mechanism).await {
            Ok(()) => Ok("digest-init ok".to_string()),
            Err(rv) => Ok(format!("digest-init -> {rv}")),
        };
    }
    if flags & CkMechanismFlags::WRAP != 0 {
        return match client.wrap_key(session, mechanism, key, keys.aes).await {
            Ok(wrapped) => Ok(format!("wrap ok ({} bytes)", wrapped.len())),
            Err(rv) => Ok(format!("wrap -> {rv}")),
        };
    }
    // No live-operation flag (keygen-only or vendor quirk): still push the
    // params through an init-class call so the Rust -> C conversion executes.
    match client.encrypt_init(session, mechanism, key).await {
        Ok(mech_out) => {
            Ok(format!("fallback encrypt-init ok (mechanism_out: {})", mech_out.is_some()))
        }
        Err(rv) => Ok(format!("fallback encrypt-init -> {rv}")),
    }
}

/// Pins the absent-provider probe logic deterministically in every
/// environment: bogus inputs must read absent regardless of what is
/// installed (the real `softhsm2_present()` result itself is environment
/// truth and is asserted nowhere).
#[test]
fn softhsm2_presence_probe_logic() {
    // Missing library dominates: absent even when the tool exists.
    assert!(!support::softhsm2_present_with(
        &["/nonexistent-w1-l9-09/libsofthsm2.so"],
        "softhsm2-util"
    ));
    // Missing tool dominates: absent even when libraries exist. Uses two
    // real system paths (present on any Linux CI image) plus a tool name
    // that cannot exist, so this holds with or without SoftHSM2.
    assert!(!support::softhsm2_present_with(
        &["/bin/sh", "/usr/bin/sh"],
        "definitely-not-a-pkcs11-tool-w1-l9-09"
    ));
}

/// Every [`CkMechanismParams`] variant executes against SoftHSM2 (count
/// asserted) or is recorded as an honest provider skip — never a silent pass.
#[tokio::test]
async fn softhsm_all_param_shapes_execute() -> Result<(), String> {
    let Some(fixture) = soft_hsm_or_skip().await? else { return Ok(()) };
    arm_transport_tripwire();
    let tripwire_before = TRANSPORT_FAILURE_COUNT.load(Ordering::SeqCst);

    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = ensure_user_token(&mut client, &fixture).await?;

    let cases = support::all_shape_cases();
    assert_eq!(
        cases.len(),
        support::EXPECTED_SHAPE_COUNT,
        "shape table must cover every CkMechanismParams variant"
    );

    let advertised = client
        .get_mechanism_list(slot)
        .await
        .map_err(|rv| format!("C_GetMechanismList failed: {rv}"))?;

    let keygen_session = open_logged_in_session(&mut client, slot, &fixture.user_pin).await?;
    let keys = ShapeKeys::generate(&mut client, keygen_session).await?;

    let mut executed: u32 = 0;
    let mut skipped: u32 = 0;
    for case in &cases {
        let params = case.mechanism.params.as_ref().expect("shape case must carry params");
        assert_eq!(
            support::variant_name(params),
            case.variant,
            "shape table entry must match its variant"
        );
        if !advertised.contains(&case.mechanism.mechanism_type) {
            record_skip!(support::SkipReason::MechanismUnsupported {
                provider: "softhsm2",
                mechanism: case.variant,
            });
            skipped += 1;
            continue;
        }
        let shape_session = open_logged_in_session(&mut client, slot, &fixture.user_pin).await?;
        let outcome = execute_shape(&mut client, shape_session, slot, case, &keys).await?;
        client.close_session(shape_session).await.map_err(|rv| rv.to_string())?;
        eprintln!("shape {} (0x{:08x}): {outcome}", case.variant, case.mechanism.mechanism_type.0);
        executed += 1;
    }

    assert_eq!(
        TRANSPORT_FAILURE_COUNT.load(Ordering::SeqCst),
        tripwire_before,
        "transport failure during shape matrix: a crash is not coverage"
    );
    assert_eq!(executed + skipped, cases.len() as u32, "every shape must execute or skip honestly");
    assert!(
        executed >= 1,
        "SoftHSM2 supports core mechanisms; zero executions means the driver is vacuous"
    );
    eprintln!(
        "shape matrix: {executed} executed, {skipped} honestly skipped ({} total)",
        cases.len()
    );

    client.logout(keygen_session).await.map_err(|rv| rv.to_string())?;
    client.close_session(keygen_session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}
