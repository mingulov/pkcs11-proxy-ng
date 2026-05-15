use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::{CliResult, close_session, login_user, open_session};

pub(crate) async fn init_token(
    client: &mut Pkcs11Client,
    slot_id: u64,
    so_pin: String,
    label: String,
) -> CliResult {
    client
        .init_token(CkSlotId(slot_id), Some(so_pin.as_bytes()), &label)
        .await
        .map_err(|e| format!("C_InitToken failed: CKR 0x{:08X}", e.0))?;
    println!("Token initialized successfully.");
    Ok(())
}

pub(crate) async fn init_pin(
    client: &mut Pkcs11Client,
    slot_id: u64,
    so_pin: String,
    new_pin: String,
) -> CliResult {
    let session = open_session(
        client,
        slot_id,
        CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION),
    )
    .await?;
    client
        .login(session, CkUserType::So, Some(so_pin.as_bytes()))
        .await
        .map_err(|e| format!("C_Login (SO) failed: CKR 0x{:08X}", e.0))?;
    client
        .init_pin(session, Some(new_pin.as_bytes()))
        .await
        .map_err(|e| format!("C_InitPIN failed: CKR 0x{:08X}", e.0))?;
    println!("User PIN initialized successfully.");
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn seed_random(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: String,
    seed: String,
) -> CliResult {
    let seed = hex::decode(&seed).map_err(|e| format!("Invalid hex seed: {e}"))?;
    let session =
        open_session(client, slot_id, CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await?;
    login_user(client, session, &pin).await?;
    client
        .seed_random(session, &seed)
        .await
        .map_err(|e| format!("C_SeedRandom failed: CKR 0x{:08X}", e.0))?;
    println!("RNG seeded.");
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn set_pin(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: String,
    new_pin: String,
) -> CliResult {
    let session = open_session(
        client,
        slot_id,
        CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION),
    )
    .await?;
    login_user(client, session, &pin).await?;
    client
        .set_pin(session, Some(pin.as_bytes()), Some(new_pin.as_bytes()))
        .await
        .map_err(|e| format!("C_SetPIN failed: CKR 0x{:08X}", e.0))?;
    println!("PIN changed successfully.");
    close_session(client, session, true).await;
    Ok(())
}
