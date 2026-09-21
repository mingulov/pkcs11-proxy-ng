mod admin;
pub(crate) mod audit;
mod crypto;
mod objects;
mod query;

use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use crate::cli::Commands;
use crate::pkcs11_names::object_class_name;

pub(crate) type CliResult = Result<(), Box<dyn core::error::Error>>;

/// Sentinel for `verify` reporting `CKR_SIGNATURE_INVALID` (W1-C11-12):
/// the handler releases its session and returns this instead of
/// `process::exit`-ing, so `main` can finalize and exit with a code
/// distinct from generic failures.
#[derive(Debug)]
pub(crate) struct VerifyInvalid;

impl core::fmt::Display for VerifyInvalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "signature INVALID (CKR_SIGNATURE_INVALID)")
    }
}

impl core::error::Error for VerifyInvalid {}

/// Format a `CkRv` from a named PKCS#11 entry point as a CLI-facing error.
/// Use with `.map_err(cli_err("C_FooName"))?`. Centralises the
/// `"C_FooName failed: CKR 0x{...}"` shape that was copy-pasted at 37+ sites.
pub(crate) fn cli_err(fn_name: &'static str) -> impl FnOnce(CkRv) -> Box<dyn core::error::Error> {
    move |e| format!("{fn_name} failed: CKR 0x{:08X}", e.0).into()
}

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
        // Handled in main() before we initialize the PKCS#11 client.
        Commands::Health { .. } => Ok(()),
        // Audit subcommands are intercepted in main() before the PKCS#11 client
        // is initialized, so this arm is never reached.
        Commands::Audit { .. } => {
            unreachable!("audit subcommands are dispatched in main before client init")
        }
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
        Commands::WrapKey {
            slot_id,
            pin,
            mechanism,
            params_file,
            wrapping_key_handle,
            key_handle,
        } => {
            objects::wrap_key(
                client,
                slot_id,
                pin,
                mechanism,
                params_file,
                wrapping_key_handle,
                key_handle,
            )
            .await
        }
        Commands::UnwrapKey {
            slot_id,
            pin,
            mechanism,
            params_file,
            unwrapping_key_handle,
            wrapped_key,
            label,
        } => {
            objects::unwrap_key(
                client,
                slot_id,
                pin,
                mechanism,
                params_file,
                unwrapping_key_handle,
                wrapped_key,
                label,
            )
            .await
        }
        Commands::DeriveKey { slot_id, pin, mechanism, params_file, base_key_handle, label } => {
            objects::derive_key(
                client,
                slot_id,
                pin,
                mechanism,
                params_file,
                base_key_handle,
                label,
            )
            .await
        }
        Commands::GenerateKey { slot_id, pin, mechanism, params_file, label, key_size } => {
            objects::generate_key(client, slot_id, pin, mechanism, params_file, label, key_size)
                .await
        }
        Commands::GenerateKeyPair {
            slot_id,
            pin,
            mechanism,
            params_file,
            label,
            key_size,
            ec_params,
        } => {
            objects::generate_key_pair(
                client,
                slot_id,
                pin,
                mechanism,
                params_file,
                label,
                key_size,
                ec_params,
            )
            .await
        }
        Commands::Sign { slot_id, pin, key_label, mechanism, params_file, input } => {
            crypto::sign(client, slot_id, pin, key_label, mechanism, params_file, input).await
        }
        Commands::Digest { slot_id, mechanism, params_file, input } => {
            crypto::digest(client, slot_id, mechanism, params_file, input).await
        }
        Commands::Encrypt { slot_id, pin, key_label, mechanism, params_file, input } => {
            crypto::encrypt(client, slot_id, pin, key_label, mechanism, params_file, input).await
        }
        Commands::Decrypt { slot_id, pin, key_label, mechanism, params_file, input } => {
            crypto::decrypt(client, slot_id, pin, key_label, mechanism, params_file, input).await
        }
        Commands::Verify { slot_id, pin, key_label, mechanism, params_file, data, signature } => {
            crypto::verify(client, slot_id, pin, key_label, mechanism, params_file, data, signature)
                .await
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
) -> Result<CkSessionHandle, Box<dyn core::error::Error>> {
    client.open_session(CkSlotId(slot_id), flags).await.map_err(cli_err("C_OpenSession"))
}

pub(crate) async fn login_user(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    pin: &str,
) -> Result<(), Box<dyn core::error::Error>> {
    client.login(session, CkUserType::User, Some(pin.as_bytes())).await.map_err(cli_err("C_Login"))
}

pub(crate) async fn login_if_present(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    pin: Option<&str>,
) -> Result<(), Box<dyn core::error::Error>> {
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

/// Page size for `find_objects` listing loops (W1-C11-13).
pub(crate) const FIND_PAGE_SIZE: u32 = 100;

/// Fetch every handle of an active find operation (W1-C11-13): loop
/// `find_objects` to exhaustion (a short/empty batch ends the search)
/// instead of capping the listing at one page.
pub(crate) async fn find_all_paged(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
) -> Result<Vec<CkObjectHandle>, Box<dyn core::error::Error>> {
    let mut objects = Vec::new();
    loop {
        let batch =
            client.find_objects(session, FIND_PAGE_SIZE).await.map_err(cli_err("C_FindObjects"))?;
        let exhausted = batch.len() < FIND_PAGE_SIZE as usize;
        objects.extend(batch);
        if exhausted {
            break;
        }
    }
    Ok(objects)
}

pub(crate) async fn find_key_by_label(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    key_label: &str,
    class: CkObjectClass,
) -> Result<CkObjectHandle, Box<dyn core::error::Error>> {
    // W1-C11-04: symmetric crypto (AES encrypt/decrypt, HMAC sign/verify)
    // operates on SECRET_KEY objects, but each op historically searched only
    // its asymmetric class. Try the requested class first so existing
    // behavior is unchanged, then fall back to SECRET_KEY.
    let mut classes = vec![class];
    if class != CkObjectClass::SECRET_KEY {
        classes.push(CkObjectClass::SECRET_KEY);
    }
    for class in classes {
        if let Some(handle) =
            find_unique_by_label_and_class(client, session, key_label, class).await?
        {
            return Ok(handle);
        }
    }

    Err(format!("No {} found with label '{key_label}'", object_class_name(class.0)).into())
}

/// Resolve one key by label+class (W1-C11-14): `CKA_LABEL` is not
/// unique, so fetch every match and error loudly on ambiguity (listing
/// the handles) instead of taking whatever comes first.
async fn find_unique_by_label_and_class(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    key_label: &str,
    class: CkObjectClass,
) -> Result<Option<CkObjectHandle>, Box<dyn core::error::Error>> {
    let template = vec![
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(key_label.to_string().into())),
        },
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(class.0)),
        },
    ];
    client
        .find_objects_init(session, Some(&template))
        .await
        .map_err(crate::handlers::cli_err("C_FindObjectsInit"))?;
    let objects = find_all_paged(client, session).await?;
    client
        .find_objects_final(session)
        .await
        .map_err(crate::handlers::cli_err("C_FindObjectsFinal"))?;

    match objects.len() {
        0 => Ok(None),
        1 => Ok(objects.into_iter().next()),
        _ => {
            let handles = objects.iter().map(|h| h.0.to_string()).collect::<Vec<_>>().join(", ");
            Err(format!(
                "Multiple {} objects found with label '{key_label}' (handles: {handles}); \
                 CKA_LABEL is not unique — delete or relabel duplicates, or select by handle",
                object_class_name(class.0)
            )
            .into())
        }
    }
}
