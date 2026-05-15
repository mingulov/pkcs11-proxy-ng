use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;
use sha2::{Digest, Sha256};

use super::{ProviderFixture, TokenSetupState};

static LABEL_COUNTER: AtomicU64 = AtomicU64::new(1);
const CKG_MGF1_SHA256: u64 = 0x00000002;
const CKZ_DATA_SPECIFIED: u64 = 0x00000001;
pub const CKF_SIGN_RECOVER: u64 = 0x00001000;
pub const CKF_VERIFY_RECOVER: u64 = 0x00004000;

fn now_millis() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()
}

pub fn unique_label(prefix: &str) -> String {
    let id = LABEL_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{}-{id}", now_millis())
}

pub struct GeneratedRsaKeyPair {
    pub public_key: CkObjectHandle,
    pub private_key: CkObjectHandle,
    pub public_label: String,
    pub private_label: String,
    pub key_id: Vec<u8>,
}

pub async fn initialized_client(endpoint: &str) -> Result<Pkcs11Client, String> {
    let mut client = Pkcs11Client::connect(endpoint).await?;
    client.initialize().await.map_err(|rv| format!("C_Initialize failed: {rv}"))?;
    Ok(client)
}

pub async fn find_token_slot(client: &mut Pkcs11Client) -> Result<CkSlotId, String> {
    let slots =
        client.get_slot_list(true).await.map_err(|rv| format!("C_GetSlotList failed: {rv}"))?;
    if slots.is_empty() {
        return Err("no slots available".into());
    }
    for &slot in &slots {
        if let Ok(info) = client.get_token_info(slot).await
            && !info.label.trim().is_empty()
        {
            return Ok(slot);
        }
    }
    Ok(slots[0])
}

pub async fn ensure_user_token(
    client: &mut Pkcs11Client,
    fixture: &ProviderFixture,
) -> Result<CkSlotId, String> {
    match fixture.token_setup_state() {
        TokenSetupState::Preinitialized => find_token_slot(client).await,
        token_setup @ TokenSetupState::InitTokenAndUserPin { .. } => {
            let slots = client
                .get_slot_list(false)
                .await
                .map_err(|rv| format!("C_GetSlotList(false) failed: {rv}"))?;
            if slots.is_empty() {
                return Err("no slots available for token initialization".into());
            }

            let mut initialized_slot = None;
            let mut init_errors = Vec::new();
            for slot in slots {
                match client
                    .init_token(slot, Some(fixture.so_pin.as_bytes()), &fixture.token_label)
                    .await
                {
                    Ok(()) => {
                        initialized_slot = Some(slot);
                        break;
                    }
                    Err(rv) => {
                        init_errors.push(format!("{slot:?}: {rv}"));
                        if rv == CkRv::TOKEN_WRITE_PROTECTED
                            || rv == CkRv::TOKEN_NOT_PRESENT
                            || rv == CkRv::GENERAL_ERROR
                        {
                            continue;
                        }
                    }
                }
            }

            let slot = initialized_slot.ok_or_else(|| {
                format!("C_InitToken failed for all candidate slots: {}", init_errors.join(", "))
            })?;

            let session = open_public_session(client, slot, true).await?;
            client
                .login(session, CkUserType::So, Some(token_setup.so_pin_bytes(fixture)))
                .await
                .map_err(|rv| format!("SO C_Login failed: {rv}"))?;
            client
                .init_pin(session, Some(fixture.user_pin.as_bytes()))
                .await
                .map_err(|rv| format!("C_InitPIN failed: {rv}"))?;
            client.logout(session).await.map_err(|rv| format!("SO C_Logout failed: {rv}"))?;
            client
                .close_session(session)
                .await
                .map_err(|rv| format!("C_CloseSession failed: {rv}"))?;
            Ok(slot)
        }
    }
}

pub async fn open_user_session(
    client: &mut Pkcs11Client,
    slot: CkSlotId,
    user_pin: &str,
    read_write: bool,
) -> Result<CkSessionHandle, String> {
    let mut flags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION);
    if read_write {
        flags = CkSessionFlags(flags.0 | CkSessionFlags::RW_SESSION);
    }
    let session = client
        .open_session(slot, flags)
        .await
        .map_err(|rv| format!("C_OpenSession failed: {rv}"))?;
    client
        .login(session, CkUserType::User, Some(user_pin.as_bytes()))
        .await
        .map_err(|rv| format!("C_Login failed: {rv}"))?;
    Ok(session)
}

pub async fn open_public_session(
    client: &mut Pkcs11Client,
    slot: CkSlotId,
    read_write: bool,
) -> Result<CkSessionHandle, String> {
    let mut flags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION);
    if read_write {
        flags = CkSessionFlags(flags.0 | CkSessionFlags::RW_SESSION);
    }
    client.open_session(slot, flags).await.map_err(|rv| format!("C_OpenSession failed: {rv}"))
}

pub async fn create_data_object(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    label: &str,
    value: &[u8],
) -> Result<CkObjectHandle, String> {
    let template = vec![
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
            value: Some(CkAttributeValue::String(label.to_string())),
        },
        CkAttribute {
            attr_type: CkAttributeType::VALUE,
            value: Some(CkAttributeValue::Bytes(value.to_vec())),
        },
    ];
    client
        .create_object(session, &template)
        .await
        .map_err(|rv| format!("C_CreateObject failed: {rv}"))
}

pub async fn find_objects_by_label(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    label: &str,
) -> Result<Vec<CkObjectHandle>, String> {
    let template = vec![CkAttribute {
        attr_type: CkAttributeType::LABEL,
        value: Some(CkAttributeValue::String(label.to_string())),
    }];
    client
        .find_objects_init(session, &template)
        .await
        .map_err(|rv| format!("C_FindObjectsInit failed: {rv}"))?;
    let objects = client
        .find_objects(session, 32)
        .await
        .map_err(|rv| format!("C_FindObjects failed: {rv}"))?;
    client
        .find_objects_final(session)
        .await
        .map_err(|rv| format!("C_FindObjectsFinal failed: {rv}"))?;
    Ok(objects)
}

pub async fn find_objects_by_id(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    key_id: &[u8],
) -> Result<Vec<CkObjectHandle>, String> {
    let template = vec![CkAttribute {
        attr_type: CkAttributeType::ID,
        value: Some(CkAttributeValue::Bytes(key_id.to_vec())),
    }];
    client
        .find_objects_init(session, &template)
        .await
        .map_err(|rv| format!("C_FindObjectsInit failed: {rv}"))?;
    let objects = client
        .find_objects(session, 32)
        .await
        .map_err(|rv| format!("C_FindObjects failed: {rv}"))?;
    client
        .find_objects_final(session)
        .await
        .map_err(|rv| format!("C_FindObjectsFinal failed: {rv}"))?;
    Ok(objects)
}

pub async fn get_attribute_bytes(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    object: CkObjectHandle,
    attr_type: CkAttributeType,
) -> Result<Option<Vec<u8>>, String> {
    let (rv, results) = client
        .get_attribute_value_exact(
            session,
            object,
            &[CkAttributeQuery { attr_type, buffer_present: false, buffer_len: 0, nested: None }],
        )
        .await
        .map_err(|rv| format!("C_GetAttributeValueExact(size) failed: {rv}"))?;
    if !rv.is_ok() {
        return Err(format!("C_GetAttributeValueExact(size) failed: 0x{:08X}", rv.0));
    }
    let Some(result) = results.into_iter().next() else {
        return Ok(None);
    };
    if result.returned_len == u64::MAX {
        return Ok(None);
    }

    let (rv, results) = client
        .get_attribute_value_exact(
            session,
            object,
            &[CkAttributeQuery {
                attr_type,
                buffer_present: true,
                buffer_len: result.returned_len,
                nested: None,
            }],
        )
        .await
        .map_err(|rv| format!("C_GetAttributeValueExact(data) failed: {rv}"))?;
    if !rv.is_ok() {
        return Err(format!("C_GetAttributeValueExact(data) failed: 0x{:08X}", rv.0));
    }
    Ok(results.into_iter().next().and_then(|result| result.value))
}

pub async fn generate_named_rsa_key_pair(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    label_prefix: &str,
    token_object: bool,
) -> Result<GeneratedRsaKeyPair, String> {
    let label_base = unique_label(label_prefix);
    let key_id = LABEL_COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes().to_vec();
    let public_label = format!("{label_base}-pub");
    let private_label = format!("{label_base}-priv");
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
            value: Some(CkAttributeValue::Bool(token_object)),
        },
        CkAttribute {
            attr_type: CkAttributeType::PRIVATE,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(public_label.clone())),
        },
        CkAttribute {
            attr_type: CkAttributeType::ID,
            value: Some(CkAttributeValue::Bytes(key_id.clone())),
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
            value: Some(CkAttributeValue::Bool(token_object)),
        },
        CkAttribute {
            attr_type: CkAttributeType::PRIVATE,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(private_label.clone())),
        },
        CkAttribute {
            attr_type: CkAttributeType::ID,
            value: Some(CkAttributeValue::Bytes(key_id.clone())),
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
    let (public_key, private_key) = client
        .generate_key_pair(session, &mechanism, &public_template, &private_template)
        .await
        .map_err(|rv| format!("C_GenerateKeyPair failed: {rv}"))?;
    Ok(GeneratedRsaKeyPair { public_key, private_key, public_label, private_label, key_id })
}

pub async fn generate_rsa_key_pair(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    label_prefix: &str,
    token_object: bool,
) -> Result<(CkObjectHandle, CkObjectHandle), String> {
    let pair = generate_named_rsa_key_pair(client, session, label_prefix, token_object).await?;
    Ok((pair.public_key, pair.private_key))
}

pub async fn rsa_sign_and_verify(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    private_key: CkObjectHandle,
    public_key: CkObjectHandle,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    client
        .sign_init(session, &mechanism, private_key)
        .await
        .map_err(|rv| format!("C_SignInit failed: {rv}"))?;
    let signature =
        client.sign(session, data).await.map_err(|rv| format!("C_Sign failed: {rv}"))?;
    client
        .verify_init(session, &mechanism, public_key)
        .await
        .map_err(|rv| format!("C_VerifyInit failed: {rv}"))?;
    client
        .verify(session, data, &signature)
        .await
        .map_err(|rv| format!("C_Verify failed: {rv}"))?;
    Ok(signature)
}

pub async fn rsa_encrypt_and_decrypt(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    public_key: CkObjectHandle,
    private_key: CkObjectHandle,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    client
        .encrypt_init(session, &mechanism, public_key)
        .await
        .map_err(|rv| format!("C_EncryptInit failed: {rv}"))?;
    let ciphertext =
        client.encrypt(session, plaintext).await.map_err(|rv| format!("C_Encrypt failed: {rv}"))?;
    client
        .decrypt_init(session, &mechanism, private_key)
        .await
        .map_err(|rv| format!("C_DecryptInit failed: {rv}"))?;
    let decrypted = client
        .decrypt(session, &ciphertext)
        .await
        .map_err(|rv| format!("C_Decrypt failed: {rv}"))?;
    Ok(decrypted)
}

pub async fn rsa_pss_sign(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    private_key: CkObjectHandle,
    data: &[u8],
) -> Result<(), String> {
    let mechanism = CkMechanism {
        mechanism_type: CkMechanismType::RSA_PKCS_PSS,
        params: Some(CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
            hash_alg: CkMechanismType::SHA256,
            mgf: CKG_MGF1_SHA256,
            salt_len: 32,
        })),
    };
    // CKM_RSA_PKCS_PSS expects pre-hashed data (SHA-256 digest = 32 bytes).
    let digest = Sha256::digest(data).to_vec();
    client
        .sign_init(session, &mechanism, private_key)
        .await
        .map_err(|rv| format!("C_SignInit(RSA-PSS) failed: {rv}"))?;
    let signature = client
        .sign(session, &digest)
        .await
        .map_err(|rv| format!("C_Sign(RSA-PSS) failed: {rv}"))?;
    assert!(!signature.is_empty(), "RSA-PSS signature should be non-empty");
    Ok(())
}

pub async fn rsa_oaep_encrypt(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    public_key: CkObjectHandle,
    plaintext: &[u8],
) -> Result<(), String> {
    let mechanism = CkMechanism {
        mechanism_type: CkMechanismType::RSA_PKCS_OAEP,
        // Use SHA-1/MGF1-SHA1 for maximum compatibility (SoftHSM2 rejects SHA-256 OAEP).
        params: Some(CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
            hash_alg: CkMechanismType(0x00000220), // CKM_SHA_1
            mgf: 0x00000001,                       // CKG_MGF1_SHA1
            source: CKZ_DATA_SPECIFIED,
            source_data: Vec::new(),
        })),
    };
    client
        .encrypt_init(session, &mechanism, public_key)
        .await
        .map_err(|rv| format!("C_EncryptInit(RSA-OAEP) failed: {rv}"))?;
    let ciphertext = client
        .encrypt(session, plaintext)
        .await
        .map_err(|rv| format!("C_Encrypt(RSA-OAEP) failed: {rv}"))?;
    assert!(!ciphertext.is_empty(), "RSA-OAEP ciphertext should be non-empty");
    Ok(())
}

pub async fn sha256_digest_matches(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    data: &[u8],
) -> Result<(), String> {
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    let expected = Sha256::digest(data).to_vec();

    client
        .digest_init(session, &mechanism)
        .await
        .map_err(|rv| format!("C_DigestInit failed: {rv}"))?;
    let one_shot =
        client.digest(session, data).await.map_err(|rv| format!("C_Digest failed: {rv}"))?;
    assert_eq!(one_shot, expected);

    client
        .digest_init(session, &mechanism)
        .await
        .map_err(|rv| format!("C_DigestInit(2) failed: {rv}"))?;
    let split_at = std::cmp::max(1, data.len() / 2);
    client
        .digest_update(session, &data[..split_at])
        .await
        .map_err(|rv| format!("C_DigestUpdate(1) failed: {rv}"))?;
    client
        .digest_update(session, &data[split_at..])
        .await
        .map_err(|rv| format!("C_DigestUpdate(2) failed: {rv}"))?;
    let incremental =
        client.digest_final(session).await.map_err(|rv| format!("C_DigestFinal failed: {rv}"))?;
    assert_eq!(incremental, expected);
    Ok(())
}

pub async fn supports_mechanism(
    client: &mut Pkcs11Client,
    slot: CkSlotId,
    mechanism: CkMechanismType,
) -> Result<bool, String> {
    let mechs = client
        .get_mechanism_list(slot)
        .await
        .map_err(|rv| format!("C_GetMechanismList failed: {rv}"))?;
    Ok(mechs.contains(&mechanism))
}

pub async fn mechanism_has_flags(
    client: &mut Pkcs11Client,
    slot: CkSlotId,
    mechanism: CkMechanismType,
    flags: u64,
) -> Result<bool, String> {
    let info = client
        .get_mechanism_info(slot, mechanism)
        .await
        .map_err(|rv| format!("C_GetMechanismInfo failed: {rv}"))?;
    Ok((info.flags.0 & flags) == flags)
}

pub async fn rsa_sign_recover_and_verify_recover(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    private_key: CkObjectHandle,
    public_key: CkObjectHandle,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };

    client
        .sign_recover_init(session, &mechanism, private_key)
        .await
        .map_err(|rv| format!("C_SignRecoverInit failed: {rv}"))?;
    let signature = client
        .sign_recover(session, data)
        .await
        .map_err(|rv| format!("C_SignRecover failed: {rv}"))?;

    client
        .verify_recover_init(session, &mechanism, public_key)
        .await
        .map_err(|rv| format!("C_VerifyRecoverInit failed: {rv}"))?;
    let recovered = client
        .verify_recover(session, &signature)
        .await
        .map_err(|rv| format!("C_VerifyRecover failed: {rv}"))?;

    Ok(recovered)
}
