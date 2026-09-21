use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::super::{
    CliResult, close_session, find_key_by_label, login_if_present, login_user, open_session,
};

// W1-C11-09 (Task 16): this thin wrapper is still triplicated across
// sign_verify.rs/digest_cipher.rs/key_ops.rs; dedupe there.
fn cli_mechanism(
    name: &str,
    params_file: Option<&std::path::Path>,
) -> Result<CkMechanism, Box<dyn core::error::Error>> {
    crate::mech_params::build_mechanism(name, params_file)
}

pub(crate) async fn sign(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: String,
    key_label: String,
    mechanism: String,
    params_file: Option<std::path::PathBuf>,
    input: String,
) -> CliResult {
    let mechanism = cli_mechanism(&mechanism, params_file.as_deref())?;
    let session =
        open_session(client, slot_id, CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await?;
    login_user(client, session, &pin).await?;
    let key = find_key_by_label(client, session, &key_label, CkObjectClass::PRIVATE_KEY).await?;
    let data = hex::decode(&input).map_err(|e| format!("Invalid hex input: {e}"))?;

    client
        .sign_init(session, &mechanism, key)
        .await
        .map_err(crate::handlers::cli_err("C_SignInit"))?;
    let signature =
        client.sign(session, &data).await.map_err(crate::handlers::cli_err("C_Sign"))?;
    println!("{}", hex::encode(&signature));
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn verify(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: Option<String>,
    key_label: String,
    mechanism: String,
    params_file: Option<std::path::PathBuf>,
    data: String,
    signature: String,
) -> CliResult {
    let mechanism = cli_mechanism(&mechanism, params_file.as_deref())?;
    let data = hex::decode(&data).map_err(|e| format!("Invalid hex data: {e}"))?;
    let signature = hex::decode(&signature).map_err(|e| format!("Invalid hex signature: {e}"))?;
    let session =
        open_session(client, slot_id, CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await?;
    login_if_present(client, session, pin.as_deref()).await?;
    let key = find_key_by_label(client, session, &key_label, CkObjectClass::PUBLIC_KEY).await?;

    client
        .verify_init(session, &mechanism, key)
        .await
        .map_err(crate::handlers::cli_err("C_VerifyInit"))?;
    match client.verify(session, CkInBuf::Bytes(&data), CkInBuf::Bytes(&signature)).await {
        Ok(()) => println!("Signature VALID"),
        Err(error) if error == CkRv::SIGNATURE_INVALID => {
            // W1-C11-12: release the session (logout + close) and
            // return a sentinel so main finalizes and exits 2 —
            // never exit(1) past cleanup like a generic error.
            eprintln!("Signature INVALID (CKR_SIGNATURE_INVALID)");
            close_session(client, session, pin.is_some()).await;
            return Err(Box::new(super::super::VerifyInvalid));
        }
        Err(error) => return Err(crate::handlers::cli_err("C_Verify")(error)),
    }
    close_session(client, session, pin.is_some()).await;
    Ok(())
}
