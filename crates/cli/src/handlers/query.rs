use base64::prelude::*;
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::{CliResult, close_session, login_if_present, open_session};
use crate::mechanisms::mechanism_name;

pub(crate) async fn list_slots(client: &mut Pkcs11Client, token_present: bool) -> CliResult {
    let slots = client
        .get_slot_list(token_present)
        .await
        .map_err(crate::handlers::cli_err("C_GetSlotList"))?;
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
        .map_err(crate::handlers::cli_err("C_GetSlotInfo"))?;
    println!("Slot {}:", slot_id);
    println!("  Description:  {}", info.slot_description);
    println!("  Manufacturer: {}", info.manufacturer_id);
    println!("  Flags:        0x{:08X}", info.flags.0);
    println!("  HW version:   {}.{}", info.hardware_version.0, info.hardware_version.1);
    println!("  FW version:   {}.{}", info.firmware_version.0, info.firmware_version.1);
    Ok(())
}

/// Render the full `CkTokenInfo` struct (W1-C11-23): all 18 fields —
/// the RW session counts, memory counters, versions and utc_time the
/// old 9-line printer dropped.
pub(super) fn format_token_info(slot_id: u64, info: &CkTokenInfo) -> String {
    use std::fmt::Write as _;
    let mut out = format!("Token in slot {slot_id}:");
    let mut line = |label: &str, value: String| {
        write!(out, "\n  {label:<20} {value}").expect("String write cannot fail");
    };
    line("Label:", info.label.clone());
    line("Manufacturer:", info.manufacturer_id.clone());
    line("Model:", info.model.clone());
    line("Serial:", info.serial_number.clone());
    line("Flags:", format!("0x{:08X}", info.flags.0));
    line("Max sessions:", info.max_session_count.to_string());
    line("Current sessions:", info.session_count.to_string());
    line("Max RW sessions:", info.max_rw_session_count.to_string());
    line("RW sessions:", info.rw_session_count.to_string());
    line("Max PIN length:", info.max_pin_len.to_string());
    line("Min PIN length:", info.min_pin_len.to_string());
    line("Total public memory:", format!("{} bytes", info.total_public_memory));
    line("Free public memory:", format!("{} bytes", info.free_public_memory));
    line("Total private memory:", format!("{} bytes", info.total_private_memory));
    line("Free private memory:", format!("{} bytes", info.free_private_memory));
    line("HW version:", format!("{}.{}", info.hardware_version.0, info.hardware_version.1));
    line("FW version:", format!("{}.{}", info.firmware_version.0, info.firmware_version.1));
    line("UTC time:", info.utc_time.clone());
    out
}

pub(crate) async fn token_info(client: &mut Pkcs11Client, slot_id: u64) -> CliResult {
    let info = client
        .get_token_info(CkSlotId(slot_id))
        .await
        .map_err(crate::handlers::cli_err("C_GetTokenInfo"))?;
    println!("{}", format_token_info(slot_id, &info));
    Ok(())
}

pub(crate) async fn list_mechanisms(client: &mut Pkcs11Client, slot_id: u64) -> CliResult {
    let mechs = client
        .get_mechanism_list(CkSlotId(slot_id))
        .await
        .map_err(crate::handlers::cli_err("C_GetMechanismList"))?;
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
    let info = client.get_info().await.map_err(crate::handlers::cli_err("C_GetInfo"))?;
    println!("Cryptoki version: {}.{}", info.cryptoki_version.0, info.cryptoki_version.1);
    println!("Manufacturer:     {}", info.manufacturer_id);
    println!("Library:          {}", info.library_description);
    println!("Library version:  {}.{}", info.library_version.0, info.library_version.1);
    println!("Flags:            0x{:08X}", info.flags.0);
    Ok(())
}

pub(crate) async fn session_info(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: Option<SecretBytes>,
) -> CliResult {
    let session = open_session(client, slot_id, CkSessionFlags::SERIAL_SESSION).await?;
    // By-value PIN (W1-L2-11): consume it into login, keep only the
    // logged-in flag for session teardown.
    let logged_in = pin.is_some();
    login_if_present(client, session, pin).await?;
    let info = client
        .get_session_info(session)
        .await
        .map_err(crate::handlers::cli_err("C_GetSessionInfo"))?;
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
    println!("  Device error: 0x{:08X}", info.device_error.0);
    close_session(client, session, logged_in).await;
    Ok(())
}

/// Output encodings for `random` (W1-C11-06).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RandomFormat {
    Hex,
    Base64,
}

/// Parse `--format`, rejecting unknown values loudly instead of
/// falling through to hex.
pub(super) fn parse_random_format(format: &str) -> Result<RandomFormat, String> {
    match format.to_lowercase().as_str() {
        "hex" => Ok(RandomFormat::Hex),
        "base64" => Ok(RandomFormat::Base64),
        other => Err(format!("unknown --format '{other}' (valid: hex, base64)")),
    }
}

pub(crate) async fn random(
    client: &mut Pkcs11Client,
    slot_id: u64,
    len: u32,
    format: String,
) -> CliResult {
    // W1-C11-06: validate before any session/RPC work so a typo'd
    // format fails fast with the valid list.
    let format =
        parse_random_format(&format).map_err(|e| -> Box<dyn core::error::Error> { e.into() })?;
    let session = open_session(client, slot_id, CkSessionFlags::SERIAL_SESSION).await?;
    let data = client
        .generate_random(session, len)
        .await
        .map_err(crate::handlers::cli_err("C_GenerateRandom"))?;
    match format {
        RandomFormat::Base64 => {
            use std::io::Write;
            let encoded = BASE64_STANDARD.encode(&data);
            std::io::stdout().write_all(encoded.as_bytes()).ok();
            println!();
        }
        RandomFormat::Hex => println!("{}", hex::encode(&data)),
    }
    close_session(client, session, false).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{format_token_info, parse_random_format};
    use pkcs11_proxy_ng_types::{CkTokenFlags, CkTokenInfo};

    // W1-C11-23: token-info prints all 18 CkTokenInfo fields (1 header +
    // 18 field lines); if the struct grows, extend the printer.
    #[test]
    fn token_info_format_prints_all_18_fields() {
        let info = CkTokenInfo {
            label: "LABEL-AAA".to_string(),
            manufacturer_id: "MFR-BBB".to_string(),
            model: "MODEL-CCC".to_string(),
            serial_number: "SER-DDD".to_string(),
            flags: CkTokenFlags(4),
            max_session_count: 101,
            session_count: 102,
            max_rw_session_count: 103,
            rw_session_count: 104,
            max_pin_len: 105,
            min_pin_len: 106,
            total_public_memory: 107,
            free_public_memory: 108,
            total_private_memory: 109,
            free_private_memory: 110,
            hardware_version: (9, 8),
            firmware_version: (7, 6),
            utc_time: "UTC-EEE".to_string(),
        };
        let out = format_token_info(7, &info);
        for needle in [
            "LABEL-AAA",
            "MFR-BBB",
            "MODEL-CCC",
            "SER-DDD",
            "0x00000004",
            "101",
            "102",
            "103",
            "104",
            "105",
            "106",
            "107",
            "108",
            "109",
            "110",
            "9.8",
            "7.6",
            "UTC-EEE",
        ] {
            assert!(out.contains(needle), "missing {needle}:\n{out}");
        }
        assert_eq!(out.lines().count(), 19, "header + 18 fields:\n{out}");
    }

    // W1-C11-06: valid formats (case-insensitive) parse; anything else
    // errors loudly listing the valid values instead of silent-hex.
    #[test]
    fn random_format_accepts_hex_and_base64() {
        assert!(parse_random_format("hex").is_ok());
        assert!(parse_random_format("HEX").is_ok());
        assert!(parse_random_format("base64").is_ok());
        assert!(parse_random_format("Base64").is_ok());
    }

    #[test]
    fn random_format_rejects_unknown_values_loudly() {
        let err = parse_random_format("b64").unwrap_err();
        assert!(err.contains("b64"), "must echo the bad value: {err}");
        assert!(err.contains("hex"), "must list valid formats: {err}");
        assert!(err.contains("base64"), "must list valid formats: {err}");
    }
}
