use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::super::{CliResult, close_session, login_user, open_session};
use crate::mechanisms::parse_mechanism;

fn parameterless_mechanism(name: &str) -> Result<CkMechanism, Box<dyn std::error::Error>> {
    let mechanism_type = parse_mechanism(name)?;
    Ok(CkMechanism { mechanism_type: CkMechanismType(mechanism_type), params: None })
}

pub(crate) async fn wrap_key(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: String,
    mechanism: String,
    wrapping_key_handle: u64,
    key_handle: u64,
) -> CliResult {
    let mechanism = parameterless_mechanism(&mechanism)?;
    let session =
        open_session(client, slot_id, CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).await?;
    login_user(client, session, &pin).await?;
    let wrapped = client
        .wrap_key(
            session,
            &mechanism,
            CkObjectHandle(wrapping_key_handle),
            CkObjectHandle(key_handle),
        )
        .await
        .map_err(|e| format!("C_WrapKey failed: CKR 0x{:08X}", e.0))?;
    println!("{}", hex::encode(&wrapped));
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn unwrap_key(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: String,
    mechanism: String,
    unwrapping_key_handle: u64,
    wrapped_key: String,
    label: Option<String>,
) -> CliResult {
    let mechanism = parameterless_mechanism(&mechanism)?;
    let session = open_session(
        client,
        slot_id,
        CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION),
    )
    .await?;
    login_user(client, session, &pin).await?;

    let wrapped_key = hex::decode(&wrapped_key).map_err(|e| format!("Invalid hex: {e}"))?;
    let mut template = vec![
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::DECRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];
    if let Some(label) = label {
        template.push(CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label)),
        });
    }

    let handle = client
        .unwrap_key(
            session,
            &mechanism,
            CkObjectHandle(unwrapping_key_handle),
            &wrapped_key,
            &template,
        )
        .await
        .map_err(|e| format!("C_UnwrapKey failed: CKR 0x{:08X}", e.0))?;
    println!("Unwrapped key handle: {}", handle.0);
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn derive_key(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: String,
    mechanism: String,
    base_key_handle: u64,
    label: Option<String>,
) -> CliResult {
    let mechanism = parameterless_mechanism(&mechanism)?;
    let session = open_session(
        client,
        slot_id,
        CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION),
    )
    .await?;
    login_user(client, session, &pin).await?;

    let mut template = vec![CkAttribute {
        attr_type: CkAttributeType::TOKEN,
        value: Some(CkAttributeValue::Bool(true)),
    }];
    if let Some(label) = label {
        template.push(CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label)),
        });
    }

    let handle = client
        .derive_key(session, &mechanism, CkObjectHandle(base_key_handle), &template)
        .await
        .map_err(|e| format!("C_DeriveKey failed: CKR 0x{:08X}", e.0))?;
    println!("Derived key handle: {}", handle.0);
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn generate_key(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: String,
    mechanism: String,
    label: String,
    key_size: Option<u64>,
) -> CliResult {
    let mechanism = parameterless_mechanism(&mechanism)?;
    let session = open_session(
        client,
        slot_id,
        CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION),
    )
    .await?;
    login_user(client, session, &pin).await?;

    let mut template = vec![
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::ENCRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::DECRYPT,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];
    if let Some(key_size) = key_size {
        template.push(CkAttribute {
            attr_type: CkAttributeType::VALUE_LEN,
            value: Some(CkAttributeValue::Ulong(key_size / 8)),
        });
    }

    let key_handle = client
        .generate_key(session, &mechanism, &template)
        .await
        .map_err(|e| format!("C_GenerateKey failed: CKR 0x{:08X}", e.0))?;
    println!("Generated key handle: {}", key_handle.0);
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn generate_key_pair(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: String,
    mechanism: String,
    label: String,
    key_size: Option<u64>,
) -> CliResult {
    let mechanism = parameterless_mechanism(&mechanism)?;
    let session = open_session(
        client,
        slot_id,
        CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION),
    )
    .await?;
    login_user(client, session, &pin).await?;

    let mut public_template = vec![
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label.clone())),
        },
        CkAttribute {
            attr_type: CkAttributeType::VERIFY,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];
    if let Some(key_size) = key_size {
        public_template.push(CkAttribute {
            attr_type: CkAttributeType::MODULUS_BITS,
            value: Some(CkAttributeValue::Ulong(key_size)),
        });
    }

    let private_template = vec![
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label)),
        },
        CkAttribute { attr_type: CkAttributeType::SIGN, value: Some(CkAttributeValue::Bool(true)) },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];

    let (public_key, private_key) = client
        .generate_key_pair(session, &mechanism, &public_template, &private_template)
        .await
        .map_err(|e| format!("C_GenerateKeyPair failed: CKR 0x{:08X}", e.0))?;
    println!("Public key handle:  {}", public_key.0);
    println!("Private key handle: {}", private_key.0);
    close_session(client, session, true).await;
    Ok(())
}
