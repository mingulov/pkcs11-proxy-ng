use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::super::{
    CliResult, cli_mechanism, close_session, find_key_by_label, login_user, open_session,
};

pub(crate) async fn digest(
    client: &mut Pkcs11Client,
    slot_id: u64,
    mechanism: String,
    params_file: Option<std::path::PathBuf>,
    input: String,
) -> CliResult {
    let mechanism = cli_mechanism(&mechanism, params_file.as_deref())?;
    let session =
        open_session(client, slot_id, CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await?;
    let data = hex::decode(&input).map_err(|e| format!("Invalid hex input: {e}"))?;

    client
        .digest_init(session, &mechanism)
        .await
        .map_err(crate::handlers::cli_err("C_DigestInit"))?;
    let digest =
        client.digest(session, &data).await.map_err(crate::handlers::cli_err("C_Digest"))?;
    println!("{}", hex::encode(&digest));
    close_session(client, session, false).await;
    Ok(())
}

pub(crate) async fn encrypt(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: SecretBytes,
    key_label: String,
    mechanism: String,
    params_file: Option<std::path::PathBuf>,
    input: String,
) -> CliResult {
    let mechanism = cli_mechanism(&mechanism, params_file.as_deref())?;
    let session =
        open_session(client, slot_id, CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await?;
    login_user(client, session, pin).await?;
    let key = find_key_by_label(client, session, &key_label, CkObjectClass::PUBLIC_KEY).await?;
    let data = hex::decode(&input).map_err(|e| format!("Invalid hex input: {e}"))?;

    client
        .encrypt_init(session, &mechanism, key)
        .await
        .map_err(crate::handlers::cli_err("C_EncryptInit"))?;
    let ciphertext =
        client.encrypt(session, &data).await.map_err(crate::handlers::cli_err("C_Encrypt"))?;
    println!("{}", hex::encode(&ciphertext));
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn decrypt(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: SecretBytes,
    key_label: String,
    mechanism: String,
    params_file: Option<std::path::PathBuf>,
    input: String,
) -> CliResult {
    let mechanism = cli_mechanism(&mechanism, params_file.as_deref())?;
    let session =
        open_session(client, slot_id, CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await?;
    login_user(client, session, pin).await?;
    let key = find_key_by_label(client, session, &key_label, CkObjectClass::PRIVATE_KEY).await?;
    let ciphertext = hex::decode(&input).map_err(|e| format!("Invalid hex input: {e}"))?;

    client
        .decrypt_init(session, &mechanism, key)
        .await
        .map_err(crate::handlers::cli_err("C_DecryptInit"))?;
    let plaintext = client
        .decrypt(session, &ciphertext)
        .await
        .map_err(crate::handlers::cli_err("C_Decrypt"))?;
    println!("{}", hex::encode(&plaintext));
    close_session(client, session, true).await;
    Ok(())
}
