//! End-to-end validation of the AES-GCM HSM-generated IV round-trip
//! introduced in Wave 1 (commits `1c487c6`, `00fb886`) and Wave 2-A
//! (`9579dac`).
//!
//! Stock SoftHSM2 does not generate IVs server-side; it requires the
//! caller to supply the IV in `CK_GCM_PARAMS.pIv`.  This test uses a
//! locally-built patched SoftHSM2 that simulates init-time provider IV
//! writeback — see `pkcs11-check/docker/softhsm2/patches/
//! 0001-simulate-aes-gcm-generated-iv.patch`.
//!
//! The patch generates the IV during `C_EncryptInit`. It does not simulate
//! providers that defer generated-IV writeback until `C_Encrypt`.
//!
//! Run with:
//!
//! ```text
//! SOFTHSM2_GCM_IV_SIM_LIB=/path/to/patched/libsofthsm2.so \
//!     cargo test -p pkcs11-proxy-ng \
//!     --test mechanism_out_gcm_iv_test -- --ignored --nocapture
//! ```
//!
//! Without the env var the test is skipped (printing the reason) so
//! CI on hosts that don't have the patched library still passes.

mod support;

use std::path::PathBuf;

use pkcs11_proxy_ng_types::{
    CkAttribute, CkAttributeType, CkAttributeValue, CkKeyType, CkMechanism, CkMechanismParams,
    CkMechanismType, CkObjectClass, CkObjectHandle, GcmParams,
};
use support::{
    DaemonHarness, ProviderFixture, find_token_slot, initialized_client, open_user_session,
};

fn patched_softhsm_path() -> Option<PathBuf> {
    std::env::var_os("SOFTHSM2_GCM_IV_SIM_LIB").map(PathBuf::from)
}

fn skip_if_no_patched_lib() -> Option<PathBuf> {
    match patched_softhsm_path() {
        Some(p) => Some(p),
        None => {
            eprintln!(
                "[mechanism_out_gcm_iv_test] SOFTHSM2_GCM_IV_SIM_LIB not set — skipping. \
                 Build the patched SoftHSM2 from pkcs11-check/docker/softhsm2/patches/ \
                 and re-run with the env var pointing at the resulting libsofthsm2.so."
            );
            None
        }
    }
}

/// Caller passes a 12-byte zeroed `pIv` buffer with `ulIvLen=12,
/// ulIvBits=0` (AWS CloudHSM convention).  After `C_EncryptInit` the
/// patched SoftHSM populates `pIv` with a random 12-byte IV.  Verify
/// that the IV reaches the caller through both the EncryptInit
/// response and the post-Encrypt mechanism_out cached on the session,
/// then verify the returned IV can decrypt the ciphertext.
#[tokio::test]
#[ignore] // requires patched SoftHSM2
async fn aes_gcm_aws_convention_iv_round_trip() -> Result<(), String> {
    let lib = match skip_if_no_patched_lib() {
        Some(p) => p,
        None => return Ok(()),
    };
    let fixture = ProviderFixture::soft_hsm_with_module(Some(lib)).await?;
    let harness = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(harness.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    // Generate a session AES-128 key.
    let key_handle = generate_aes_session_key(&mut client, session, 16).await?;

    // AWS convention: ulIvLen = buffer capacity (12), ulIvBits = 0,
    // and a writable pIv buffer.  Through the proto layer the IV
    // payload is empty (the caller has nothing yet); the patched
    // SoftHSM2 generates it and writes it back.
    let mech = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv: vec![0u8; 12],
            iv_bits: 0,
            iv_buffer_len: 12,
            aad: Vec::new(),
            tag_bits: 128,
        })),
    };
    let init_out = client
        .encrypt_init(session, &mech, key_handle)
        .await
        .map_err(|rv| format!("C_EncryptInit failed: CKR 0x{:08X}", rv.0))?;

    // The patched simulator generates the IV during EncryptInit, so
    // mechanism_out from EncryptInit should already carry it.
    let init_iv = match init_out.as_ref() {
        Some(CkMechanismParams::Gcm(g)) => g.iv.clone(),
        _ => Vec::new(),
    };

    let plaintext = b"hello, AES-GCM with HSM-generated IV";
    let (ciphertext, encrypt_mech_out) = client
        .encrypt_with_mechanism_out(session, plaintext)
        .await
        .map_err(|rv| format!("C_Encrypt failed: CKR 0x{:08X}", rv.0))?;

    let encrypt_iv = match encrypt_mech_out.as_ref() {
        Some(CkMechanismParams::Gcm(g)) => g.iv.clone(),
        _ => Vec::new(),
    };

    assert_eq!(ciphertext.len(), plaintext.len() + 16, "GCM ciphertext = plaintext + tag");
    assert!(!init_iv.is_empty() || !encrypt_iv.is_empty(), "patched SoftHSM2 must surface IV");

    // The two IV reports (init-time and encrypt-time) must agree
    // when both are non-empty — they describe the same operation.
    if !init_iv.is_empty() && !encrypt_iv.is_empty() {
        assert_eq!(init_iv, encrypt_iv, "EncryptInit and Encrypt IVs must match");
    }

    let iv = if !encrypt_iv.is_empty() { encrypt_iv } else { init_iv };
    assert_eq!(iv.len(), 12, "GCM IV must be 12 bytes");
    assert_ne!(iv, vec![0u8; 12], "patched SoftHSM2 must generate a non-zero IV");

    let decrypt_mech = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv: iv.clone(),
            iv_bits: 96,
            iv_buffer_len: iv.len() as u64,
            aad: Vec::new(),
            tag_bits: 128,
        })),
    };
    client
        .decrypt_init(session, &decrypt_mech, key_handle)
        .await
        .map_err(|rv| format!("C_DecryptInit failed: CKR 0x{:08X}", rv.0))?;
    let recovered = client
        .decrypt(session, &ciphertext)
        .await
        .map_err(|rv| format!("C_Decrypt failed: CKR 0x{:08X}", rv.0))?;
    assert_eq!(recovered.as_slice(), plaintext, "returned IV must decrypt the ciphertext");

    Ok(())
}

/// Strict PKCS#11 convention: `ulIvLen = 0`, `ulIvBits = 96`, pIv
/// points at a 12-byte buffer.  The patched SoftHSM2 also supports
/// this shape and writes back through the same path.
#[tokio::test]
#[ignore] // requires patched SoftHSM2
async fn aes_gcm_strict_convention_iv_round_trip() -> Result<(), String> {
    let lib = match skip_if_no_patched_lib() {
        Some(p) => p,
        None => return Ok(()),
    };
    let fixture = ProviderFixture::soft_hsm_with_module(Some(lib)).await?;
    let harness = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(harness.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    let key_handle = generate_aes_session_key(&mut client, session, 16).await?;

    let mech = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv: Vec::new(),
            iv_bits: 96,
            iv_buffer_len: 12,
            aad: Vec::new(),
            tag_bits: 128,
        })),
    };
    let init_out = client
        .encrypt_init(session, &mech, key_handle)
        .await
        .map_err(|rv| format!("C_EncryptInit failed: CKR 0x{:08X}", rv.0))?;

    let iv = match init_out.as_ref() {
        Some(CkMechanismParams::Gcm(g)) => g.iv.clone(),
        _ => Vec::new(),
    };
    assert_eq!(iv.len(), 12, "strict-convention IV writeback must be 12 bytes");
    assert_ne!(iv, vec![0u8; 12]);

    Ok(())
}

async fn generate_aes_session_key(
    client: &mut pkcs11_proxy_ng_client::Pkcs11Client,
    session: pkcs11_proxy_ng_types::CkSessionHandle,
    key_len: u32,
) -> Result<CkObjectHandle, String> {
    let mech = CkMechanism { mechanism_type: CkMechanismType::AES_KEY_GEN, params: None };
    let template = vec![
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
            value: Some(CkAttributeValue::Ulong(u64::from(key_len))),
        },
        CkAttribute {
            attr_type: CkAttributeType::ENCRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::DECRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
    ];
    client
        .generate_key(session, &mech, &template)
        .await
        .map_err(|rv| format!("C_GenerateKey(AES-{}) failed: CKR 0x{:08X}", key_len * 8, rv.0))
}
