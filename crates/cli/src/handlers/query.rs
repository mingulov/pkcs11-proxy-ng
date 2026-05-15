use base64::prelude::*;
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::{CliResult, close_session, login_if_present, open_session};
use crate::mechanisms::mechanism_name;

pub(crate) async fn list_slots(client: &mut Pkcs11Client, token_present: bool) -> CliResult {
    let slots = client
        .get_slot_list(token_present)
        .await
        .map_err(|e| format!("C_GetSlotList failed: CKR 0x{:08X}", e.0))?;
    if slots.is_empty() {
        println!("No slots found.");
    } else {
        for slot in &slots {
            println!("Slot {}", slot.0);
        }
    }
    Ok(())
}

pub(crate) async fn slot_info(client: &mut Pkcs11Client, slot_id: u64) -> CliResult {
    let info = client
        .get_slot_info(CkSlotId(slot_id))
        .await
        .map_err(|e| format!("C_GetSlotInfo failed: CKR 0x{:08X}", e.0))?;
    println!("Slot {}:", slot_id);
    println!("  Description:  {}", info.slot_description);
    println!("  Manufacturer: {}", info.manufacturer_id);
    println!("  Flags:        0x{:08X}", info.flags.0);
    println!("  HW version:   {}.{}", info.hardware_version.0, info.hardware_version.1);
    println!("  FW version:   {}.{}", info.firmware_version.0, info.firmware_version.1);
    Ok(())
}

pub(crate) async fn token_info(client: &mut Pkcs11Client, slot_id: u64) -> CliResult {
    let info = client
        .get_token_info(CkSlotId(slot_id))
        .await
        .map_err(|e| format!("C_GetTokenInfo failed: CKR 0x{:08X}", e.0))?;
    println!("Token in slot {}:", slot_id);
    println!("  Label:            {}", info.label);
    println!("  Manufacturer:     {}", info.manufacturer_id);
    println!("  Model:            {}", info.model);
    println!("  Serial:           {}", info.serial_number);
    println!("  Flags:            0x{:08X}", info.flags.0);
    println!("  Max sessions:     {}", info.max_session_count);
    println!("  Current sessions: {}", info.session_count);
    println!("  Max PIN length:   {}", info.max_pin_len);
    println!("  Min PIN length:   {}", info.min_pin_len);
    Ok(())
}

pub(crate) async fn list_mechanisms(client: &mut Pkcs11Client, slot_id: u64) -> CliResult {
    let mechs = client
        .get_mechanism_list(CkSlotId(slot_id))
        .await
        .map_err(|e| format!("C_GetMechanismList failed: CKR 0x{:08X}", e.0))?;
    if mechs.is_empty() {
        println!("No mechanisms found for slot {}.", slot_id);
    } else {
        println!("Mechanisms for slot {}:", slot_id);
        for mechanism in &mechs {
            println!("  0x{:08X}  {}", mechanism.0, mechanism_name(mechanism.0));
        }
    }
    Ok(())
}

pub(crate) async fn get_info(client: &mut Pkcs11Client) -> CliResult {
    let info =
        client.get_info().await.map_err(|e| format!("C_GetInfo failed: CKR 0x{:08X}", e.0))?;
    println!("Cryptoki version: {}.{}", info.cryptoki_version.0, info.cryptoki_version.1);
    println!("Manufacturer:     {}", info.manufacturer_id);
    println!("Library:          {}", info.library_description);
    println!("Library version:  {}.{}", info.library_version.0, info.library_version.1);
    println!("Flags:            0x{:08X}", info.flags);
    Ok(())
}

pub(crate) async fn session_info(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: Option<String>,
) -> CliResult {
    let session =
        open_session(client, slot_id, CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await?;
    login_if_present(client, session, pin.as_deref()).await?;
    let info = client
        .get_session_info(session)
        .await
        .map_err(|e| format!("C_GetSessionInfo failed: CKR 0x{:08X}", e.0))?;
    let state_name = match info.state {
        CkSessionState::RoPublic => "RO public",
        CkSessionState::RoUser => "RO user",
        CkSessionState::RwPublic => "RW public",
        CkSessionState::RwUser => "RW user",
        CkSessionState::RwSo => "RW SO",
    };
    println!("Session info (slot {}):", slot_id);
    println!("  Slot:         {}", info.slot_id.0);
    println!("  State:        {state_name}");
    println!("  Flags:        0x{:08X}", info.flags.0);
    println!("  Device error: 0x{:08X}", info.device_error);
    close_session(client, session, pin.is_some()).await;
    Ok(())
}

pub(crate) async fn random(
    client: &mut Pkcs11Client,
    slot_id: u64,
    len: u32,
    format: String,
) -> CliResult {
    let session =
        open_session(client, slot_id, CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await?;
    let data = client
        .generate_random(session, len)
        .await
        .map_err(|e| format!("C_GenerateRandom failed: CKR 0x{:08X}", e.0))?;
    match format.to_lowercase().as_str() {
        "base64" => {
            use std::io::Write;
            let encoded = BASE64_STANDARD.encode(&data);
            std::io::stdout().write_all(encoded.as_bytes()).ok();
            println!();
        }
        _ => println!("{}", hex::encode(&data)),
    }
    close_session(client, session, false).await;
    Ok(())
}
