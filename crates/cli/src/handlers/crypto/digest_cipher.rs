use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::super::{CliResult, close_session, find_key_by_label, login_user, open_session};
use crate::mechanisms::parse_mechanism;

fn parameterless_mechanism(name: &str) -> Result<CkMechanism, Box<dyn std::error::Error>> {
    let mechanism_type = parse_mechanism(name)?;
    Ok(CkMechanism { mechanism_type: CkMechanismType(mechanism_type), params: None })
}

pub(crate) async fn digest(
    client: &mut Pkcs11Client,
    slot_id: u64,
    mechanism: String,
    input: String,
) -> CliResult {
    let mechanism = parameterless_mechanism(&mechanism)?;
    let session =
        open_session(client, slot_id, CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await?;
    let data = hex::decode(&input).map_err(|e| format!("Invalid hex input: {e}"))?;

    client
        .digest_init(session, &mechanism)
        .await
        .map_err(|e| format!("C_DigestInit failed: CKR 0x{:08X}", e.0))?;
    let digest = client
        .digest(session, &data)
        .await
        .map_err(|e| format!("C_Digest failed: CKR 0x{:08X}", e.0))?;
    println!("{}", hex::encode(&digest));
    close_session(client, session, false).await;
    Ok(())
}

pub(crate) async fn encrypt(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: String,
    key_label: String,
    mechanism: String,
    input: String,
) -> CliResult {
    let mechanism = parameterless_mechanism(&mechanism)?;
    let session =
        open_session(client, slot_id, CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await?;
    login_user(client, session, &pin).await?;
    let key = find_key_by_label(client, session, &key_label, CkObjectClass::PUBLIC_KEY).await?;
    let data = hex::decode(&input).map_err(|e| format!("Invalid hex input: {e}"))?;

    client
        .encrypt_init(session, &mechanism, key)
        .await
        .map_err(|e| format!("C_EncryptInit failed: CKR 0x{:08X}", e.0))?;
    let ciphertext = client
        .encrypt(session, &data)
        .await
        .map_err(|e| format!("C_Encrypt failed: CKR 0x{:08X}", e.0))?;
    println!("{}", hex::encode(&ciphertext));
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn decrypt(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: String,
    key_label: String,
    mechanism: String,
    input: String,
) -> CliResult {
    let mechanism = parameterless_mechanism(&mechanism)?;
    let session =
        open_session(client, slot_id, CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await?;
    login_user(client, session, &pin).await?;
    let key = find_key_by_label(client, session, &key_label, CkObjectClass::PRIVATE_KEY).await?;
    let ciphertext = hex::decode(&input).map_err(|e| format!("Invalid hex input: {e}"))?;

    client
        .decrypt_init(session, &mechanism, key)
        .await
        .map_err(|e| format!("C_DecryptInit failed: CKR 0x{:08X}", e.0))?;
    let plaintext = client
        .decrypt(session, &ciphertext)
        .await
        .map_err(|e| format!("C_Decrypt failed: CKR 0x{:08X}", e.0))?;
    println!("{}", hex::encode(&plaintext));
    close_session(client, session, true).await;
    Ok(())
}
