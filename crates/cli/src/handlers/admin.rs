use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::{CliResult, close_session, login_user, open_session};

pub(crate) async fn init_token(
    client: &mut Pkcs11Client,
    slot_id: u64,
    so_pin: SecretBytes,
    label: String,
) -> CliResult {
    // By-value PIN (W1-L2-11): transfer the wiping allocation into the
    // call; it is wiped on drop afterwards.
    let so = so_pin.into_zeroizing();
    client
        .init_token(CkSlotId(slot_id), Some(so.as_slice()), &label)
        .await
        .map_err(crate::handlers::cli_err("C_InitToken"))?;
    println!("Token initialized successfully.");
    Ok(())
}

pub(crate) async fn init_pin(
    client: &mut Pkcs11Client,
    slot_id: u64,
    so_pin: SecretBytes,
    new_pin: SecretBytes,
) -> CliResult {
    let session =
        open_session(client, slot_id, CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION)
            .await?;
    let so = so_pin.into_zeroizing();
    client
        .login(session, CkUserType::So, Some(so.as_slice()))
        .await
        .map_err(crate::handlers::cli_err("C_Login (SO)"))?;
    let new = new_pin.into_zeroizing();
    client
        .init_pin(session, Some(new.as_slice()))
        .await
        .map_err(crate::handlers::cli_err("C_InitPIN"))?;
    println!("User PIN initialized successfully.");
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn seed_random(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: SecretBytes,
    seed: String,
) -> CliResult {
    let seed = hex::decode(&seed).map_err(|e| format!("Invalid hex seed: {e}"))?;
    let session = open_session(client, slot_id, CkSessionFlags::SERIAL_SESSION).await?;
    login_user(client, session, pin).await?;
    client
        .seed_random(session, CkInBuf::Bytes(&seed))
        .await
        .map_err(crate::handlers::cli_err("C_SeedRandom"))?;
    println!("RNG seeded.");
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn set_pin(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: SecretBytes,
    new_pin: SecretBytes,
) -> CliResult {
    let session =
        open_session(client, slot_id, CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION)
            .await?;
    // The old PIN serves both C_Login and C_SetPIN: one wiping clone for
    // the login, then the original moves into the set-PIN call. Both
    // copies are wiped on drop.
    login_user(client, session, pin.clone()).await?;
    let old = pin.into_zeroizing();
    let new = new_pin.into_zeroizing();
    client
        .set_pin(session, Some(old.as_slice()), Some(new.as_slice()))
        .await
        .map_err(crate::handlers::cli_err("C_SetPIN"))?;
    println!("PIN changed successfully.");
    close_session(client, session, true).await;
    Ok(())
}
