use base64::prelude::*;
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::super::{CliResult, close_session, login_user, open_session};

pub(crate) async fn import_certificate(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: String,
    label: String,
    file: std::path::PathBuf,
) -> CliResult {
    let raw =
        std::fs::read(&file).map_err(|e| format!("Cannot read file {}: {e}", file.display()))?;
    let der = if raw.first() == Some(&b'-') {
        let pem = std::str::from_utf8(&raw).map_err(|_| "Certificate file is not valid UTF-8")?;
        let base64: String =
            pem.lines().filter(|line| !line.starts_with("-----")).collect::<Vec<_>>().join("");
        BASE64_STANDARD.decode(base64.trim()).map_err(|e| format!("Invalid PEM base64: {e}"))?
    } else {
        raw
    };

    let session = open_session(
        client,
        slot_id,
        CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION),
    )
    .await?;
    login_user(client, session, &pin).await?;

    let (_, certificate) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| format!("Failed to parse X.509 certificate: {e}"))?;
    let subject_der = certificate.subject().as_raw().to_vec();

    let template = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::CERTIFICATE.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(true)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label)),
        },
        CkAttribute {
            attr_type: CkAttributeType::CERTIFICATE_TYPE,
            value: Some(CkAttributeValue::Ulong(0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::SUBJECT,
            value: Some(CkAttributeValue::Bytes(subject_der)),
        },
        CkAttribute {
            attr_type: CkAttributeType::VALUE,
            value: Some(CkAttributeValue::Bytes(der)),
        },
    ];
    let handle = client
        .create_object(session, &template)
        .await
        .map_err(|e| format!("C_CreateObject failed: CKR 0x{:08X}", e.0))?;
    println!("Certificate imported with handle: {}", handle.0);
    close_session(client, session, true).await;
    Ok(())
}
