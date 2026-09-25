use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::super::{CliResult, close_session, login_user, open_session};
use crate::mechanisms::parse_mechanism;

fn parameterless_mechanism(name: &str) -> Result<CkMechanism, Box<dyn core::error::Error>> {
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
        .map_err(crate::handlers::cli_err("C_WrapKey"))?;
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
            value: Some(CkAttributeValue::String(label.into())),
        });
    }

    let handle = client
        .unwrap_key(
            session,
            &mechanism,
            CkObjectHandle(unwrapping_key_handle),
            CkInBuf::Bytes(&wrapped_key),
            Some(&template),
        )
        .await
        .map_err(crate::handlers::cli_err("C_UnwrapKey"))?;
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
            value: Some(CkAttributeValue::String(label.into())),
        });
    }

    let handle = client
        .derive_key(session, &mechanism, CkObjectHandle(base_key_handle), Some(&template))
        .await
        .map_err(crate::handlers::cli_err("C_DeriveKey"))?;
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
            value: Some(CkAttributeValue::String(label.into())),
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
        .generate_key(session, &mechanism, Some(&template))
        .await
        .map_err(crate::handlers::cli_err("C_GenerateKey"))?;
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
            value: Some(CkAttributeValue::String(label.clone().into())),
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
            value: Some(CkAttributeValue::String(label.into())),
        },
        CkAttribute { attr_type: CkAttributeType::SIGN, value: Some(CkAttributeValue::Bool(true)) },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(true)),
        },
    ];

    let (public_key, private_key) = client
        .generate_key_pair(session, &mechanism, Some(&public_template), Some(&private_template))
        .await
        .map_err(crate::handlers::cli_err("C_GenerateKeyPair"))?;
    println!("Public key handle:  {}", public_key.0);
    println!("Private key handle: {}", private_key.0);
    close_session(client, session, true).await;
    Ok(())
}
