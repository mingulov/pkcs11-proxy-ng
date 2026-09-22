use base64::prelude::*;
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::super::{CliResult, close_session, login_user, open_session};

/// CKC_X_509 (PKCS#11 §2.4: certificate-type values): X.509 public-key
/// certificates — the only certificate type `import-certificate`
/// handles (the parser rejects anything else before this is used).
const CKC_X_509: u64 = 0;

/// Build the create-object template for an imported X.509 certificate
/// (W1-C11-29): split out so tests pin the named `CKC_X_509`
/// certificate type instead of trusting inline construction.
fn build_certificate_template(
    label: String,
    subject_der: Vec<u8>,
    der: Vec<u8>,
) -> Vec<CkAttribute> {
    vec![
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
            value: Some(CkAttributeValue::String(label.into())),
        },
        CkAttribute {
            attr_type: CkAttributeType::CERTIFICATE_TYPE,
            value: Some(CkAttributeValue::Ulong(CKC_X_509)),
        },
        CkAttribute {
            attr_type: CkAttributeType::SUBJECT,
            value: Some(CkAttributeValue::Bytes(subject_der.into())),
        },
        CkAttribute {
            attr_type: CkAttributeType::VALUE,
            value: Some(CkAttributeValue::Bytes(der.into())),
        },
    ]
}

pub(crate) async fn import_certificate(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: SecretBytes,
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

    let session =
        open_session(client, slot_id, CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION)
            .await?;
    login_user(client, session, pin).await?;

    let (_, certificate) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| format!("Failed to parse X.509 certificate: {e}"))?;
    let subject_der = certificate.subject().as_raw().to_vec();

    let template = build_certificate_template(label, subject_der, der);
    let handle = client
        .create_object(session, Some(&template))
        .await
        .map_err(crate::handlers::cli_err("C_CreateObject"))?;
    println!("Certificate imported with handle: {}", handle.0);
    close_session(client, session, true).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CKC_X_509, build_certificate_template};
    use pkcs11_proxy_ng_types::{CkAttributeType, CkAttributeValue, CkObjectClass};

    // W1-C11-29: the X.509 certificate type is a named const, and the
    // import template carries it (not a magic Ulong(0)).
    #[test]
    fn certificate_template_uses_named_x509_type() {
        assert_eq!(CKC_X_509, 0);
        let template = build_certificate_template("label".to_string(), vec![1, 2], vec![3, 4]);
        let cert_type = template
            .iter()
            .find(|attr| attr.attr_type == CkAttributeType::CERTIFICATE_TYPE)
            .expect("CERTIFICATE_TYPE present");
        assert_eq!(cert_type.value, Some(CkAttributeValue::Ulong(CKC_X_509)));
        let class = template
            .iter()
            .find(|attr| attr.attr_type == CkAttributeType::CLASS)
            .expect("CLASS present");
        assert_eq!(class.value, Some(CkAttributeValue::Ulong(CkObjectClass::CERTIFICATE.0)));
    }
}
