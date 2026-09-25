use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::super::{
    CliResult, cli_mechanism, close_session, find_key_by_label, login_if_present, login_user,
    open_session,
};

pub(crate) async fn sign(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: SecretBytes,
    key_label: String,
    mechanism: String,
    params_file: Option<std::path::PathBuf>,
    input: zeroize::Zeroizing<String>,
) -> CliResult {
    let mechanism = cli_mechanism(&mechanism, params_file.as_deref())?;
    let session = open_session(client, slot_id, CkSessionFlags::SERIAL_SESSION).await?;
    login_user(client, session, pin).await?;
    let key = find_key_by_label(client, session, &key_label, CkObjectClass::PRIVATE_KEY).await?;
    // T14: decode into a wiping owner, then lend the wiping allocation
    // across the RPC (no plain working copy).
    let data = crate::secrets::decode_hex_secret(&input, "Invalid hex input")?.into_zeroizing();

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
    pin: Option<SecretBytes>,
    key_label: String,
    mechanism: String,
    params_file: Option<std::path::PathBuf>,
    data: zeroize::Zeroizing<String>,
    signature: zeroize::Zeroizing<String>,
) -> CliResult {
    let mechanism = cli_mechanism(&mechanism, params_file.as_deref())?;
    // T14: decode into wiping owners, then lend the wiping allocations
    // across the RPC (no plain working copy).
    let data = crate::secrets::decode_hex_secret(&data, "Invalid hex data")?.into_zeroizing();
    let signature =
        crate::secrets::decode_hex_secret(&signature, "Invalid hex signature")?.into_zeroizing();
    let session = open_session(client, slot_id, CkSessionFlags::SERIAL_SESSION).await?;
    // By-value PIN (W1-L2-11): consume it into login, keep only the
    // logged-in flag for session teardown.
    let logged_in = pin.is_some();
    login_if_present(client, session, pin).await?;
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
            close_session(client, session, logged_in).await;
            return Err(Box::new(super::super::VerifyInvalid));
        }
        Err(error) => return Err(crate::handlers::cli_err("C_Verify")(error)),
    }
    close_session(client, session, logged_in).await;
    Ok(())
}
