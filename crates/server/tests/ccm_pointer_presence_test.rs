// Test diagnostics are intentionally printed for the local real-provider tier.
#![allow(clippy::print_stderr)]
//! Live CKM_AES_CCM parameter coverage with a provider that advertises CCM.
//!
//! The test is ignored by default because it needs an initialized Kryoptic
//! token and the `PKCS11_PROXY_KRYOPTIC_*` fixture environment.

mod support;

use pkcs11_proxy_ng_types::{CcmParams, CkMechanism, CkMechanismParams, CkMechanismType};
use support::{
    DaemonHarness, ProviderFixture, ensure_user_token, generate_aes_key, initialized_client,
    open_user_session, supports_mechanism,
};

#[tokio::test]
#[ignore] // requires an initialized CCM-capable Kryoptic token
async fn kryoptic_ccm_empty_aad_null_and_nonnull_round_trip() -> Result<(), String> {
    let fixture = ProviderFixture::kryoptic_from_env().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = match initialized_client(daemon.endpoint()).await {
        Ok(client) => client,
        Err(error) => {
            let _ = daemon.shutdown().await;
            return Err(error);
        }
    };
    let mut session_to_close = None;
    let mut key_to_destroy = None;

    let proof =
        async {
            let slot = ensure_user_token(&mut client, &fixture).await?;
            if !supports_mechanism(&mut client, slot, CkMechanismType::AES_CCM).await? {
                return Err("Kryoptic did not advertise CKM_AES_CCM; live proof unavailable".into());
            }
            let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
            session_to_close = Some(session);
            let key = generate_aes_key(&mut client, session, 16)
                .await
                .map_err(|rv| format!("C_GenerateKey(AES) failed: {rv}"))?;
            key_to_destroy = Some(key);
            let plaintext = b"CCM pointer-nullness full-stack proof";
            let nonce = vec![0x35; 12];

            for aad_null in [true, false] {
                let mechanism = CkMechanism {
                    mechanism_type: CkMechanismType::AES_CCM,
                    params: Some(CkMechanismParams::Ccm(CcmParams {
                        data_len: plaintext.len() as u64,
                        nonce: nonce.clone(),
                        aad: Vec::new().into(),
                        mac_len: 16,
                        nonce_null: false,
                        aad_null,
                    })),
                };
                client.encrypt_init(session, &mechanism, key).await.map_err(|rv| {
                    format!("C_EncryptInit(CCM, aad_null={aad_null}) failed: {rv}")
                })?;
                let ciphertext = client
                    .encrypt(session, plaintext)
                    .await
                    .map_err(|rv| format!("C_Encrypt(CCM, aad_null={aad_null}) failed: {rv}"))?;
                if ciphertext.len() != plaintext.len() + 16 {
                    return Err(format!(
                        "CCM aad_null={aad_null}: expected {} ciphertext bytes, got {}",
                        plaintext.len() + 16,
                        ciphertext.len()
                    ));
                }
                client.decrypt_init(session, &mechanism, key).await.map_err(|rv| {
                    format!("C_DecryptInit(CCM, aad_null={aad_null}) failed: {rv}")
                })?;
                let decrypted = client
                    .decrypt(session, &ciphertext)
                    .await
                    .map_err(|rv| format!("C_Decrypt(CCM, aad_null={aad_null}) failed: {rv}"))?;
                if !decrypted.expose(|bytes| bytes == plaintext) {
                    return Err(format!("CCM aad_null={aad_null}: decrypted plaintext mismatch"));
                }
                eprintln!(
                    "Kryoptic CCM empty-AAD round trip: aad_null={aad_null}, ciphertext_len={}",
                    ciphertext.len()
                );
            }
            Ok::<(), String>(())
        }
        .await;

    // Retire the live native owner even if the proof returned an error.
    if let Some(session) = session_to_close {
        if let Some(key) = key_to_destroy {
            let _ = client.destroy_object(session, key).await;
        }
        let _ = client.logout(session).await;
        let _ = client.close_session(session).await;
    }
    let client_finalize = client.finalize().await.map_err(|rv| format!("client finalize: {rv}"));
    let daemon_shutdown = daemon.shutdown().await;
    proof?;
    client_finalize?;
    daemon_shutdown?;
    Ok(())
}
