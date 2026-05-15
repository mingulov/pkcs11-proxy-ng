use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::super::{CliResult, close_session, login_if_present, login_user, open_session};
use super::output::print_verbose_object;
use crate::pkcs11_names::{attr_type_name, parse_attr_type};

pub(crate) async fn find_objects(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: Option<String>,
    label: Option<String>,
    verbose: bool,
) -> CliResult {
    let session =
        open_session(client, slot_id, CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await?;
    login_if_present(client, session, pin.as_deref()).await?;

    let mut template = Vec::new();
    if let Some(label) = label {
        template.push(CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label)),
        });
    }

    client
        .find_objects_init(session, &template)
        .await
        .map_err(|e| format!("C_FindObjectsInit failed: CKR 0x{:08X}", e.0))?;
    let objects = client
        .find_objects(session, 100)
        .await
        .map_err(|e| format!("C_FindObjects failed: CKR 0x{:08X}", e.0))?;
    client
        .find_objects_final(session)
        .await
        .map_err(|e| format!("C_FindObjectsFinal failed: CKR 0x{:08X}", e.0))?;

    if objects.is_empty() {
        println!("No objects found.");
    } else {
        for object in &objects {
            if verbose {
                print_verbose_object(client, session, *object).await;
            } else {
                println!("Object handle: {}", object.0);
            }
        }
    }

    close_session(client, session, pin.is_some()).await;
    Ok(())
}

pub(crate) async fn destroy_object(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: Option<String>,
    object_handle: u64,
) -> CliResult {
    let session = open_session(
        client,
        slot_id,
        CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION),
    )
    .await?;
    login_if_present(client, session, pin.as_deref()).await?;
    client
        .destroy_object(session, CkObjectHandle(object_handle))
        .await
        .map_err(|e| format!("C_DestroyObject failed: CKR 0x{:08X}", e.0))?;
    println!("Object {} destroyed.", object_handle);
    close_session(client, session, pin.is_some()).await;
    Ok(())
}

pub(crate) async fn get_object_size(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: Option<String>,
    object_handle: u64,
) -> CliResult {
    let session =
        open_session(client, slot_id, CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await?;
    login_if_present(client, session, pin.as_deref()).await?;
    let size = client
        .get_object_size(session, CkObjectHandle(object_handle))
        .await
        .map_err(|e| format!("C_GetObjectSize failed: CKR 0x{:08X}", e.0))?;
    println!("Object {} size: {} bytes", object_handle, size);
    close_session(client, session, pin.is_some()).await;
    Ok(())
}

pub(crate) async fn create_object(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: String,
    label: String,
    value: Option<String>,
) -> CliResult {
    let session = open_session(
        client,
        slot_id,
        CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION),
    )
    .await?;
    login_user(client, session, &pin).await?;

    let mut template = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::DATA.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];
    if let Some(value) = value {
        let bytes = hex::decode(&value).map_err(|e| format!("Invalid hex value: {e}"))?;
        template.push(CkAttribute {
            attr_type: CkAttributeType::VALUE,
            value: Some(CkAttributeValue::Bytes(bytes)),
        });
    }

    let handle = client
        .create_object(session, &template)
        .await
        .map_err(|e| format!("C_CreateObject failed: CKR 0x{:08X}", e.0))?;
    println!("Created object with handle: {}", handle.0);
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn get_attribute(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: Option<String>,
    object_handle: u64,
    attr: Vec<String>,
) -> CliResult {
    let session =
        open_session(client, slot_id, CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await?;
    login_if_present(client, session, pin.as_deref()).await?;

    let attr_types: Vec<CkAttributeType> =
        attr.iter().map(|attr| parse_attr_type(attr)).collect::<Result<Vec<_>, _>>()?;
    let template: Vec<CkAttribute> = attr_types
        .iter()
        .map(|attr_type| CkAttribute { attr_type: *attr_type, value: None })
        .collect();

    let (get_rv, results) = client
        .get_attribute_value(session, CkObjectHandle(object_handle), &template)
        .await
        .map_err(|e| format!("C_GetAttributeValue failed: CKR 0x{:08X}", e.0))?;
    if !get_rv.is_ok() {
        eprintln!(
            "warning: C_GetAttributeValue returned CKR 0x{:08X} (partial results follow)",
            get_rv.0
        );
    }

    for attribute in &results {
        let name = attr_type_name(attribute.attr_type.0);
        match &attribute.value {
            Some(CkAttributeValue::Bytes(bytes)) => {
                if bytes.iter().all(|byte| byte.is_ascii_graphic() || *byte == b' ') {
                    println!("  {}: \"{}\"", name, String::from_utf8_lossy(bytes));
                } else {
                    println!("  {}: 0x{}", name, hex::encode(bytes));
                }
            }
            Some(CkAttributeValue::Ulong(value)) => println!("  {}: {}", name, value),
            Some(CkAttributeValue::Bool(value)) => println!("  {}: {}", name, value),
            Some(CkAttributeValue::String(value)) => println!("  {}: \"{}\"", name, value),
            None => println!("  {}: <unavailable>", name),
        }
    }

    close_session(client, session, pin.is_some()).await;
    Ok(())
}
