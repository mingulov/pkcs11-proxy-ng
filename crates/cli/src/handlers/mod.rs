mod admin;
mod crypto;
mod objects;
mod query;

use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use crate::cli::Commands;
use crate::pkcs11_names::object_class_name;

pub(crate) type CliResult = Result<(), Box<dyn std::error::Error>>;

pub(crate) async fn run_command(client: &mut Pkcs11Client, command: Commands) -> CliResult {
    match command {
        Commands::ListSlots { token_present } => query::list_slots(client, token_present).await,
        Commands::SlotInfo { slot_id } => query::slot_info(client, slot_id).await,
        Commands::TokenInfo { slot_id } => query::token_info(client, slot_id).await,
        Commands::ListMechanisms { slot_id } => query::list_mechanisms(client, slot_id).await,
        Commands::GetInfo => query::get_info(client).await,
        Commands::SessionInfo { slot_id, pin } => query::session_info(client, slot_id, pin).await,
        Commands::Random { slot_id, len, format } => {
            query::random(client, slot_id, len, format).await
        }
        Commands::ListMechanismNames => Ok(()),
        Commands::FindObjects { slot_id, pin, label, verbose } => {
            objects::find_objects(client, slot_id, pin, label, verbose).await
        }
        Commands::DestroyObject { slot_id, pin, object_handle } => {
            objects::destroy_object(client, slot_id, pin, object_handle).await
        }
        Commands::GetObjectSize { slot_id, pin, object_handle } => {
            objects::get_object_size(client, slot_id, pin, object_handle).await
        }
        Commands::CreateObject { slot_id, pin, label, value } => {
            objects::create_object(client, slot_id, pin, label, value).await
        }
        Commands::GetAttribute { slot_id, pin, object_handle, attr } => {
            objects::get_attribute(client, slot_id, pin, object_handle, attr).await
        }
        Commands::ImportCertificate { slot_id, pin, label, file } => {
            objects::import_certificate(client, slot_id, pin, label, file).await
        }
        Commands::WrapKey { slot_id, pin, mechanism, wrapping_key_handle, key_handle } => {
            objects::wrap_key(client, slot_id, pin, mechanism, wrapping_key_handle, key_handle)
                .await
        }
        Commands::UnwrapKey {
            slot_id,
            pin,
            mechanism,
            unwrapping_key_handle,
            wrapped_key,
            label,
        } => {
            objects::unwrap_key(
                client,
                slot_id,
                pin,
                mechanism,
                unwrapping_key_handle,
                wrapped_key,
                label,
            )
            .await
        }
        Commands::DeriveKey { slot_id, pin, mechanism, base_key_handle, label } => {
            objects::derive_key(client, slot_id, pin, mechanism, base_key_handle, label).await
        }
        Commands::GenerateKey { slot_id, pin, mechanism, label, key_size } => {
            objects::generate_key(client, slot_id, pin, mechanism, label, key_size).await
        }
        Commands::GenerateKeyPair { slot_id, pin, mechanism, label, key_size } => {
            objects::generate_key_pair(client, slot_id, pin, mechanism, label, key_size).await
        }
        Commands::Sign { slot_id, pin, key_label, mechanism, input } => {
            crypto::sign(client, slot_id, pin, key_label, mechanism, input).await
        }
        Commands::Digest { slot_id, mechanism, input } => {
            crypto::digest(client, slot_id, mechanism, input).await
        }
        Commands::Encrypt { slot_id, pin, key_label, mechanism, input } => {
            crypto::encrypt(client, slot_id, pin, key_label, mechanism, input).await
        }
        Commands::Decrypt { slot_id, pin, key_label, mechanism, input } => {
            crypto::decrypt(client, slot_id, pin, key_label, mechanism, input).await
        }
        Commands::Verify { slot_id, pin, key_label, mechanism, data, signature } => {
            crypto::verify(client, slot_id, pin, key_label, mechanism, data, signature).await
        }
        Commands::InitToken { slot_id, so_pin, label } => {
            admin::init_token(client, slot_id, so_pin, label).await
        }
        Commands::InitPin { slot_id, so_pin, new_pin } => {
            admin::init_pin(client, slot_id, so_pin, new_pin).await
        }
        Commands::SeedRandom { slot_id, pin, seed } => {
            admin::seed_random(client, slot_id, pin, seed).await
        }
        Commands::SetPin { slot_id, pin, new_pin } => {
            admin::set_pin(client, slot_id, pin, new_pin).await
        }
    }
}

pub(crate) async fn open_session(
    client: &mut Pkcs11Client,
    slot_id: u64,
    flags: CkSessionFlags,
) -> Result<CkSessionHandle, Box<dyn std::error::Error>> {
    client
        .open_session(CkSlotId(slot_id), flags)
        .await
        .map_err(|e| format!("C_OpenSession failed: CKR 0x{:08X}", e.0).into())
}

pub(crate) async fn login_user(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    pin: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    client
        .login(session, CkUserType::User, Some(pin.as_bytes()))
        .await
        .map_err(|e| format!("C_Login failed: CKR 0x{:08X}", e.0).into())
}

pub(crate) async fn login_if_present(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    pin: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(pin) = pin {
        login_user(client, session, pin).await?;
    }
    Ok(())
}

pub(crate) async fn close_session(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    logged_in: bool,
) {
    if logged_in {
        let _ = client.logout(session).await;
    }
    let _ = client.close_session(session).await;
}

pub(crate) async fn find_key_by_label(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    key_label: &str,
    class: CkObjectClass,
) -> Result<CkObjectHandle, Box<dyn std::error::Error>> {
    let template = vec![
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(key_label.to_string())),
        },
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(class.0)),
        },
    ];
    client
        .find_objects_init(session, &template)
        .await
        .map_err(|e| format!("C_FindObjectsInit failed: CKR 0x{:08X}", e.0))?;
    let objects = client
        .find_objects(session, 1)
        .await
        .map_err(|e| format!("C_FindObjects failed: CKR 0x{:08X}", e.0))?;
    client
        .find_objects_final(session)
        .await
        .map_err(|e| format!("C_FindObjectsFinal failed: CKR 0x{:08X}", e.0))?;

    objects.into_iter().next().ok_or_else(|| {
        format!("No {} found with label '{key_label}'", object_class_name(class.0)).into()
    })
}
