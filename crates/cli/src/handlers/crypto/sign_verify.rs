use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::super::{
    CliResult, close_session, find_key_by_label, login_if_present, login_user, open_session,
};
use crate::mechanisms::parse_mechanism;

fn parameterless_mechanism(name: &str) -> Result<CkMechanism, Box<dyn std::error::Error>> {
    let mechanism_type = parse_mechanism(name)?;
    Ok(CkMechanism { mechanism_type: CkMechanismType(mechanism_type), params: None })
}

pub(crate) async fn sign(
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
    let data = hex::decode(&input).map_err(|e| format!("Invalid hex input: {e}"))?;

    client
        .sign_init(session, &mechanism, key)
        .await
        .map_err(|e| format!("C_SignInit failed: CKR 0x{:08X}", e.0))?;
    let signature = client
        .sign(session, &data)
        .await
        .map_err(|e| format!("C_Sign failed: CKR 0x{:08X}", e.0))?;
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
    data: String,
    signature: String,
) -> CliResult {
    let mechanism = parameterless_mechanism(&mechanism)?;
    let data = hex::decode(&data).map_err(|e| format!("Invalid hex data: {e}"))?;
    let signature = hex::decode(&signature).map_err(|e| format!("Invalid hex signature: {e}"))?;
    let session =
        open_session(client, slot_id, CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await?;
    login_if_present(client, session, pin.as_deref()).await?;
    let key = find_key_by_label(client, session, &key_label, CkObjectClass::PUBLIC_KEY).await?;

    client
        .verify_init(session, &mechanism, key)
        .await
        .map_err(|e| format!("C_VerifyInit failed: CKR 0x{:08X}", e.0))?;
    match client.verify(session, &data, &signature).await {
        Ok(()) => println!("Signature VALID"),
        Err(error) if error == CkRv::SIGNATURE_INVALID => {
            eprintln!("Signature INVALID (CKR_SIGNATURE_INVALID)");
            std::process::exit(1);
        }
        Err(error) => return Err(format!("C_Verify failed: CKR 0x{:08X}", error.0).into()),
    }
    close_session(client, session, pin.is_some()).await;
    Ok(())
}
