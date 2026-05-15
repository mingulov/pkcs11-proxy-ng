//! Comprehensive parameterized mechanism integration tests against Kryoptic.
//!
//! Each test proves a different mechanism parameter shape works through the full
//! proxy stack: Rust struct -> proto -> gRPC -> proto -> C struct -> Kryoptic FFI
//! -> result -> reverse path.
//!
//! All tests are `#[ignore]` because they require the Kryoptic PKCS#11 module
//! and specific environment variables to be set.
//!
//! Run with:
//! ```sh
//! KRYOPTIC_TMPDIR="$(mktemp -d)"
//! trap 'rm -rf "$KRYOPTIC_TMPDIR"' EXIT
//! KRYOPTIC_RUN_ID="$(date +%s)$$"
//! export PKCS11_PROXY_KRYOPTIC_MODULE=/home/user/src/kryoptic/target/release/libkryoptic_pkcs11.so
//! export PKCS11_PROXY_KRYOPTIC_INIT_ARGS="$KRYOPTIC_TMPDIR/token.sql"
//! export PKCS11_PROXY_KRYOPTIC_INIT_TOKEN=1
//! export PKCS11_PROXY_KRYOPTIC_TOKEN_LABEL="kryoptic-token-$KRYOPTIC_RUN_ID"
//! export PKCS11_PROXY_KRYOPTIC_USER_PIN="1$KRYOPTIC_RUN_ID"
//! export PKCS11_PROXY_KRYOPTIC_SO_PIN="9$KRYOPTIC_RUN_ID"
//! cargo test -p pkcs11-proxy-ng --test kryoptic_mechanism_test -- --ignored --test-threads=1 --nocapture
//! ```

mod support;

use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::{
    CkAttribute, CkAttributeType, CkAttributeValue, CkKeyType, CkMechanism, CkMechanismType,
    CkObjectClass, CkObjectHandle, CkSessionHandle,
};
use support::{
    CKM_AES_CBC_ENCRYPT_DATA, CKM_AES_CTR, CKM_ECDSA_SHA3_256, CKM_HKDF_DERIVE,
    CKM_SHA256_RSA_PKCS_PSS, DaemonHarness, ProviderFixture, ensure_user_token,
    generate_ec_key_pair, initialized_client, open_user_session, supports_mechanism,
    test_aes_cbc_encrypt_data_derive, test_aes_cbc_encrypt_decrypt, test_aes_ctr_encrypt_decrypt,
    test_ecdh1_derive, test_hkdf_derive, test_rsa_oaep_encrypt_decrypt, test_rsa_pss_sign_verify,
};

// ---------------------------------------------------------------------------
// Local helpers (Kryoptic-specific)
// ---------------------------------------------------------------------------

/// Generate an RSA key pair for sign/verify and encrypt/decrypt tests.
async fn generate_rsa_key_pair(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    label_prefix: &str,
) -> Result<(CkObjectHandle, CkObjectHandle), String> {
    let public_template = vec![
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
            attr_type: CkAttributeType::PRIVATE,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(format!("{label_prefix}-pub"))),
        },
        CkAttribute {
            attr_type: CkAttributeType::ENCRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::VERIFY,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];
    let private_template = vec![
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
            attr_type: CkAttributeType::PRIVATE,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(format!("{label_prefix}-priv"))),
        },
        CkAttribute {
            attr_type: CkAttributeType::DECRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute { attr_type: CkAttributeType::SIGN, value: Some(CkAttributeValue::Bool(true)) },
        CkAttribute {
            attr_type: CkAttributeType::SENSITIVE,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::EXTRACTABLE,
            value: Some(CkAttributeValue::Bool(false)),
        },
    ];
    let mechanism =
        CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN, params: None };
    client
        .generate_key_pair(session, &mechanism, &public_template, &private_template)
        .await
        .map_err(|rv| format!("RSA key pair generation failed: {rv}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Enumerate all Kryoptic mechanisms and verify the count is substantial.
#[tokio::test]
#[ignore] // requires Kryoptic
async fn kryoptic_all_mechanisms_visible() -> Result<(), String> {
    let fixture = match ProviderFixture::kryoptic_from_env().await {
        Ok(f) => f,
        Err(_) => {
            record_skip!(support::SkipReason::ProviderMissing("kryoptic"));
            return Ok(());
        }
    };
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slot = ensure_user_token(&mut client, &fixture).await?;
    let mechanisms = client.get_mechanism_list(slot).await.map_err(|rv| rv.to_string())?;

    // Kryoptic supports 117+ mechanisms.
    if mechanisms.len() < 100 {
        return Err(format!("Expected 100+ mechanisms from Kryoptic, got {}", mechanisms.len()));
    }

    let standard_count = mechanisms.iter().filter(|m| m.0 < 0x8000_0000).count();
    let vendor_count = mechanisms.iter().filter(|m| m.0 >= 0x8000_0000).count();
    eprintln!(
        "Kryoptic mechanisms: {} total ({} standard, {} vendor/new)",
        mechanisms.len(),
        standard_count,
        vendor_count
    );

    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// AES-CBC encrypt + decrypt with IvParams (16-byte IV) through the proxy
/// against Kryoptic.
#[tokio::test]
#[ignore] // requires Kryoptic
async fn kryoptic_aes_cbc_encrypt_decrypt() -> Result<(), String> {
    let fixture = match ProviderFixture::kryoptic_from_env().await {
        Ok(f) => f,
        Err(_) => {
            record_skip!(support::SkipReason::ProviderMissing("kryoptic"));
            return Ok(());
        }
    };
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CkMechanismType::AES_CBC).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "kryoptic",
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

/// AES-CTR encrypt + decrypt with AesCtrParams through the proxy
/// against Kryoptic.
#[tokio::test]
#[ignore] // requires Kryoptic
async fn kryoptic_aes_ctr_encrypt_decrypt() -> Result<(), String> {
    let fixture = match ProviderFixture::kryoptic_from_env().await {
        Ok(f) => f,
        Err(_) => {
            record_skip!(support::SkipReason::ProviderMissing("kryoptic"));
            return Ok(());
        }
    };
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CKM_AES_CTR).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "kryoptic",
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

/// RSA-PSS sign + verify with PssParams through the proxy against Kryoptic.
#[tokio::test]
#[ignore] // requires Kryoptic
async fn kryoptic_rsa_pss_sign_verify() -> Result<(), String> {
    let fixture = match ProviderFixture::kryoptic_from_env().await {
        Ok(f) => f,
        Err(_) => {
            record_skip!(support::SkipReason::ProviderMissing("kryoptic"));
            return Ok(());
        }
    };
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CKM_SHA256_RSA_PKCS_PSS).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "kryoptic",
            mechanism: "CKM_SHA256_RSA_PKCS_PSS",
        });
        client.finalize().await.map_err(|rv| rv.to_string())?;
        daemon.shutdown().await?;
        return Ok(());
    }

    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let (public_key, private_key) =
        generate_rsa_key_pair(&mut client, session, "kryoptic-pss").await?;

    test_rsa_pss_sign_verify(&mut client, session, public_key, private_key).await?;

    eprintln!("RSA-PSS sign+verify with PssParams: OK");

    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// RSA-OAEP encrypt + decrypt with OaepParams through the proxy against
/// Kryoptic.
#[tokio::test]
#[ignore] // requires Kryoptic
async fn kryoptic_rsa_oaep_encrypt_decrypt() -> Result<(), String> {
    let fixture = match ProviderFixture::kryoptic_from_env().await {
        Ok(f) => f,
        Err(_) => {
            record_skip!(support::SkipReason::ProviderMissing("kryoptic"));
            return Ok(());
        }
    };
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CkMechanismType::RSA_PKCS_OAEP).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "kryoptic",
            mechanism: "CKM_RSA_PKCS_OAEP",
        });
        client.finalize().await.map_err(|rv| rv.to_string())?;
        daemon.shutdown().await?;
        return Ok(());
    }

    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let (public_key, private_key) =
        generate_rsa_key_pair(&mut client, session, "kryoptic-oaep").await?;

    test_rsa_oaep_encrypt_decrypt(&mut client, session, public_key, private_key).await?;

    eprintln!("RSA-OAEP encrypt+decrypt with OaepParams (SHA-1): OK");

    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// ECDH1-DERIVE key derivation with Ecdh1DeriveParams through the proxy
/// against Kryoptic.
#[tokio::test]
#[ignore] // requires Kryoptic
async fn kryoptic_ecdh1_derive() -> Result<(), String> {
    let fixture = match ProviderFixture::kryoptic_from_env().await {
        Ok(f) => f,
        Err(_) => {
            record_skip!(support::SkipReason::ProviderMissing("kryoptic"));
            return Ok(());
        }
    };
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CkMechanismType::ECDH1_DERIVE).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "kryoptic",
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

/// HKDF key derivation with HkdfParams through the proxy against Kryoptic.
#[tokio::test]
#[ignore] // requires Kryoptic
async fn kryoptic_hkdf_derive() -> Result<(), String> {
    let fixture = match ProviderFixture::kryoptic_from_env().await {
        Ok(f) => f,
        Err(_) => {
            record_skip!(support::SkipReason::ProviderMissing("kryoptic"));
            return Ok(());
        }
    };
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CKM_HKDF_DERIVE).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "kryoptic",
            mechanism: "CKM_HKDF_DERIVE",
        });
        client.finalize().await.map_err(|rv| rv.to_string())?;
        daemon.shutdown().await?;
        return Ok(());
    }

    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    test_hkdf_derive(&mut client, session, b"kryoptic-hkdf-salt-value", b"kryoptic hkdf test")
        .await?;

    eprintln!("HKDF-DERIVE produced key: OK");

    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// AES-CBC-ENCRYPT-DATA key derivation with AesCbcEncryptDataParams through
/// the proxy against Kryoptic.
#[tokio::test]
#[ignore] // requires Kryoptic
async fn kryoptic_aes_cbc_encrypt_data_derive() -> Result<(), String> {
    let fixture = match ProviderFixture::kryoptic_from_env().await {
        Ok(f) => f,
        Err(_) => {
            record_skip!(support::SkipReason::ProviderMissing("kryoptic"));
            return Ok(());
        }
    };
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CKM_AES_CBC_ENCRYPT_DATA).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "kryoptic",
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

/// ECDSA-SHA3-256 sign + verify (parameterless) through the proxy against
/// Kryoptic.
#[tokio::test]
#[ignore] // requires Kryoptic
async fn kryoptic_ecdsa_sha3_sign_verify() -> Result<(), String> {
    let fixture = match ProviderFixture::kryoptic_from_env().await {
        Ok(f) => f,
        Err(_) => {
            record_skip!(support::SkipReason::ProviderMissing("kryoptic"));
            return Ok(());
        }
    };
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = ensure_user_token(&mut client, &fixture).await?;

    if !supports_mechanism(&mut client, slot, CKM_ECDSA_SHA3_256).await? {
        record_skip!(support::SkipReason::MechanismUnsupported {
            provider: "kryoptic",
            mechanism: "CKM_ECDSA_SHA3_256",
        });
        client.finalize().await.map_err(|rv| rv.to_string())?;
        daemon.shutdown().await?;
        return Ok(());
    }

    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    let (public_key, private_key) =
        generate_ec_key_pair(&mut client, session, "kryoptic-ecdsa-sha3").await?;

    // ECDSA-SHA3-256 is parameterless: the backend hashes the data internally.
    let mechanism = CkMechanism { mechanism_type: CKM_ECDSA_SHA3_256, params: None };

    let data = b"Kryoptic ECDSA-SHA3-256 mechanism test payload for proxy verification";

    // Sign.
    client
        .sign_init(session, &mechanism, private_key)
        .await
        .map_err(|rv| format!("C_SignInit(ECDSA-SHA3-256) failed: {rv}"))?;
    let signature = client
        .sign(session, data)
        .await
        .map_err(|rv| format!("C_Sign(ECDSA-SHA3-256) failed: {rv}"))?;

    if signature.is_empty() {
        return Err("ECDSA-SHA3-256 signature should be non-empty".into());
    }
    eprintln!("ECDSA-SHA3-256 signature length: {} bytes", signature.len());

    // Verify.
    client
        .verify_init(session, &mechanism, public_key)
        .await
        .map_err(|rv| format!("C_VerifyInit(ECDSA-SHA3-256) failed: {rv}"))?;
    client
        .verify(session, data, &signature)
        .await
        .map_err(|rv| format!("C_Verify(ECDSA-SHA3-256) failed: {rv}"))?;

    eprintln!("ECDSA-SHA3-256 sign+verify: OK");

    // Clean up.
    client.destroy_object(session, public_key).await.map_err(|rv| rv.to_string())?;
    client.destroy_object(session, private_key).await.map_err(|rv| rv.to_string())?;
    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// Verify that C_GetMechanismInfo works for every mechanism Kryoptic reports.
#[tokio::test]
#[ignore] // requires Kryoptic
async fn kryoptic_mechanism_info_for_all() -> Result<(), String> {
    let fixture = match ProviderFixture::kryoptic_from_env().await {
        Ok(f) => f,
        Err(_) => {
            record_skip!(support::SkipReason::ProviderMissing("kryoptic"));
            return Ok(());
        }
    };
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = ensure_user_token(&mut client, &fixture).await?;

    let mechanisms = client.get_mechanism_list(slot).await.map_err(|rv| rv.to_string())?;

    let mut info_ok: usize = 0;
    let mut info_fail: usize = 0;
    for mech in &mechanisms {
        match client.get_mechanism_info(slot, *mech).await {
            Ok(_info) => info_ok += 1,
            Err(e) => {
                eprintln!("MechanismInfo failed for 0x{:08X}: {}", mech.0, e);
                info_fail += 1;
            }
        }
    }

    eprintln!("MechanismInfo: {}/{} succeeded", info_ok, mechanisms.len());
    if info_fail != 0 {
        return Err(format!("{} mechanism info queries failed", info_fail));
    }

    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}
