//! Real-module end-to-end smoke coverage.
//!
//! Tests here cover SoftHSM2 (the primary regression backend) and NSS
//! softokn for operations that SoftHSM2 does not support (e.g. sign-recover).
//! The broader provider and failure-path suites live in separate integration
//! test binaries so they can be run independently by the matrix scripts.

mod support;

use pkcs11_proxy_ng_types::CkMechanismType;
use support::{
    CKF_SIGN_RECOVER, CKF_VERIFY_RECOVER, DaemonHarness, ProviderFixture, SkipReason,
    create_data_object, ensure_user_token, find_objects_by_label, find_token_slot,
    generate_rsa_key_pair, initialized_client, mechanism_has_flags, open_user_session,
    rsa_encrypt_and_decrypt, rsa_oaep_encrypt, rsa_pss_sign, rsa_sign_and_verify,
    rsa_sign_recover_and_verify_recover, sha256_digest_matches, supports_mechanism,
};

#[tokio::test]
#[ignore] // requires SoftHSM2 tools and library
async fn softhsm_smoke_workflow() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let info = client.get_info().await.map_err(|rv| rv.to_string())?;
    assert!(!info.manufacturer_id.trim().is_empty());
    assert!(!info.library_description.trim().is_empty());

    let slot = find_token_slot(&mut client).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    let random = client.generate_random(session, 32).await.map_err(|rv| rv.to_string())?;
    assert_eq!(random.len(), 32);
    assert!(random.iter().any(|b| *b != 0));

    let (public_key, private_key) =
        generate_rsa_key_pair(&mut client, session, "smoke", false).await?;

    let payload = b"hello pkcs11 proxy";
    let signature =
        rsa_sign_and_verify(&mut client, session, private_key, public_key, payload).await?;
    assert!(!signature.is_empty());

    let decrypted =
        rsa_encrypt_and_decrypt(&mut client, session, public_key, private_key, payload).await?;
    assert_eq!(decrypted, payload);

    if supports_mechanism(&mut client, slot, CkMechanismType::SHA256).await? {
        sha256_digest_matches(&mut client, session, payload).await?;
    }

    if supports_mechanism(&mut client, slot, CkMechanismType::RSA_PKCS_PSS).await? {
        rsa_pss_sign(&mut client, session, private_key, payload).await?;
    }

    if supports_mechanism(&mut client, slot, CkMechanismType::RSA_PKCS_OAEP).await? {
        rsa_oaep_encrypt(&mut client, session, public_key, payload).await?;
    }

    let object_label = "smoke-data-object";
    let object = create_data_object(&mut client, session, object_label, b"payload").await?;
    let matches = find_objects_by_label(&mut client, session, object_label).await?;
    assert!(matches.contains(&object));

    client.destroy_object(session, object).await.map_err(|rv| rv.to_string())?;
    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// Validate C_SignRecover and C_VerifyRecover using NSS softokn, which
/// reports CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER for RSA-PKCS.
///
/// SoftHSM2 does not advertise these flags for any mechanism, so NSS is
/// the canonical real-backend validation target for items 19 and 20.
#[tokio::test]
#[ignore] // requires NSS softokn library (libsoftokn3.so) and certutil
async fn nss_sign_recover_and_verify_recover() -> Result<(), String> {
    let fixture = ProviderFixture::nss_softokn().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    // ensure_user_token handles InitToken + SO login + InitPIN for NSS.
    let slot = ensure_user_token(&mut client, &fixture).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    // Guard: only run if the backend actually advertises sign-recover support.
    // This prevents a hard failure if NSS is updated or configured differently.
    let sign_recover_ok =
        mechanism_has_flags(&mut client, slot, CkMechanismType::RSA_PKCS, CKF_SIGN_RECOVER).await?;
    let verify_recover_ok =
        mechanism_has_flags(&mut client, slot, CkMechanismType::RSA_PKCS, CKF_VERIFY_RECOVER)
            .await?;
    if !sign_recover_ok || !verify_recover_ok {
        record_skip!(SkipReason::MechanismUnsupported {
            provider: "NSS softokn",
            mechanism: "CKF_SIGN_RECOVER/CKF_VERIFY_RECOVER on RSA_PKCS",
        });
        return Ok(());
    }

    let (public_key, private_key) =
        generate_rsa_key_pair(&mut client, session, "sign-recover", false).await?;

    // Data must be short enough for PKCS#1 v1.5 padding (≤ key_size_bytes − 11).
    // Using a 32-byte payload well within the 2048-bit key limit.
    let payload = b"sign-recover test payload 12345!";

    let recovered =
        rsa_sign_recover_and_verify_recover(&mut client, session, private_key, public_key, payload)
            .await?;

    assert_eq!(recovered, payload, "C_VerifyRecover must return the original plaintext");

    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}
