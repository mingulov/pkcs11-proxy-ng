use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::super::{CliResult, close_session, login_if_present, login_user, open_session};
use super::output::print_verbose_object;
use crate::pkcs11_names::{attr_type_name, object_class_name, parse_attr_type};

/// Render a typed `Ulong` attribute value (W1-C11-07): CLASS prints
/// symbolically (matching the verbose decoder); every other ulong
/// attr prints its decoded number.
fn format_ulong_attribute(attr_type: CkAttributeType, value: u64) -> String {
    if attr_type == CkAttributeType::CLASS {
        format!("{} ({value})", object_class_name(value))
    } else {
        value.to_string()
    }
}

/// Attribute types whose values are key material (W1-L2-12): the
/// secret-key/private-key blobs `get-attribute --redact` replaces with
/// `[redacted]`. Public halves (MODULUS, PUBLIC_EXPONENT, EC_POINT,
/// ...) and metadata are never secret.
fn is_secret_attribute(attr_type: CkAttributeType) -> bool {
    use CkAttributeType as T;
    matches!(
        attr_type,
        T::VALUE
            | T::PRIVATE_EXPONENT
            | T::PRIME_1
            | T::PRIME_2
            | T::EXPONENT_1
            | T::EXPONENT_2
            | T::COEFFICIENT
    )
}

/// Render one `get-attribute` output line (W1-L2-12): with `redact`, a
/// present secret value prints as `[redacted]`; everything else keeps
/// its exact historical shape.
fn format_attribute_value(name: &str, attribute: &CkAttribute, redact: bool) -> String {
    if redact && attribute.value.is_some() && is_secret_attribute(attribute.attr_type) {
        return format!("  {name}: [redacted]");
    }
    match &attribute.value {
        Some(CkAttributeValue::Bytes(bytes)) => bytes.expose(|raw| {
            if raw.iter().all(|byte| byte.is_ascii_graphic() || *byte == b' ') {
                format!("  {name}: \"{}\"", String::from_utf8_lossy(raw))
            } else {
                format!("  {name}: 0x{}", hex::encode(raw))
            }
        }),
        Some(CkAttributeValue::Ulong(value)) => {
            format!("  {name}: {}", format_ulong_attribute(attribute.attr_type, *value))
        }
        Some(CkAttributeValue::Bool(value)) => format!("  {name}: {value}"),
        Some(CkAttributeValue::String(value)) => {
            value.expose(|raw| format!("  {name}: \"{}\"", String::from_utf8_lossy(raw)))
        }
        Some(CkAttributeValue::NestedTemplate(subs)) => {
            format!("  {name}: <nested template, {} attributes>", subs.len())
        }
        None => format!("  {name}: <unavailable>"),
    }
}

pub(crate) async fn find_objects(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: Option<SecretBytes>,
    label: Option<String>,
    verbose: bool,
) -> CliResult {
    let session = open_session(client, slot_id, CkSessionFlags::SERIAL_SESSION).await?;
    // By-value PIN (W1-L2-11): consume it into login, keep only the
    // logged-in flag for session teardown.
    let logged_in = pin.is_some();
    login_if_present(client, session, pin).await?;

    let mut template = Vec::new();
    if let Some(label) = label {
        template.push(CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label.into())),
        });
    }

    client
        .find_objects_init(session, Some(&template))
        .await
        .map_err(crate::handlers::cli_err("C_FindObjectsInit"))?;
    // W1-C11-13: page to exhaustion instead of capping at 100.
    let objects = crate::handlers::find_all_paged(client, session).await?;
    client
        .find_objects_final(session)
        .await
        .map_err(crate::handlers::cli_err("C_FindObjectsFinal"))?;

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

    close_session(client, session, logged_in).await;
    Ok(())
}

pub(crate) async fn destroy_object(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: Option<SecretBytes>,
    object_handle: u64,
) -> CliResult {
    let session =
        open_session(client, slot_id, CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION)
            .await?;
    let logged_in = pin.is_some();
    login_if_present(client, session, pin).await?;
    client
        .destroy_object(session, CkObjectHandle(object_handle))
        .await
        .map_err(crate::handlers::cli_err("C_DestroyObject"))?;
    println!("Object {} destroyed.", object_handle);
    close_session(client, session, logged_in).await;
    Ok(())
}

pub(crate) async fn get_object_size(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: Option<SecretBytes>,
    object_handle: u64,
) -> CliResult {
    let session = open_session(client, slot_id, CkSessionFlags::SERIAL_SESSION).await?;
    let logged_in = pin.is_some();
    login_if_present(client, session, pin).await?;
    let size = client
        .get_object_size(session, CkObjectHandle(object_handle))
        .await
        .map_err(crate::handlers::cli_err("C_GetObjectSize"))?;
    println!("Object {} size: {} bytes", object_handle, size);
    close_session(client, session, logged_in).await;
    Ok(())
}

pub(crate) async fn create_object(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: SecretBytes,
    label: String,
    value: Option<String>,
) -> CliResult {
    let session =
        open_session(client, slot_id, CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION)
            .await?;
    login_user(client, session, pin).await?;

    let mut template = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::DATA.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label.into())),
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
            value: Some(CkAttributeValue::Bytes(bytes.into())),
        });
    }

    let handle = client
        .create_object(session, Some(&template))
        .await
        .map_err(crate::handlers::cli_err("C_CreateObject"))?;
    println!("Created object with handle: {}", handle.0);
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn get_attribute(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: Option<SecretBytes>,
    object_handle: u64,
    attr: Vec<String>,
    redact: bool,
) -> CliResult {
    // W1-C11-31: an empty query prints nothing and would exit 0 — reject
    // it loudly before any session/RPC work (clap also requires --attr,
    // this guards programmatic callers).
    if attr.is_empty() {
        return Err("get-attribute requires at least one --attr (e.g. --attr LABEL)".into());
    }
    let session = open_session(client, slot_id, CkSessionFlags::SERIAL_SESSION).await?;
    let logged_in = pin.is_some();
    login_if_present(client, session, pin).await?;

    let attr_types: Vec<CkAttributeType> =
        attr.iter().map(|attr| parse_attr_type(attr)).collect::<Result<Vec<_>, _>>()?;
    let template: Vec<CkAttribute> = attr_types
        .iter()
        .map(|attr_type| CkAttribute { attr_type: *attr_type, value: None })
        .collect();

    let (get_rv, results) = client
        .get_attribute_value(session, CkObjectHandle(object_handle), &template)
        .await
        .map_err(crate::handlers::cli_err("C_GetAttributeValue"))?;
    if get_rv.is_err() {
        eprintln!("warning: C_GetAttributeValue returned {get_rv} (partial results follow)");
    }

    for attribute in &results {
        let name = attr_type_name(attribute.attr_type.0);
        println!("{}", format_attribute_value(&name, attribute, redact));
    }

    close_session(client, session, logged_in).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{format_attribute_value, format_ulong_attribute, is_secret_attribute};
    use pkcs11_proxy_ng_types::{CkAttribute, CkAttributeType, CkAttributeValue};

    // W1-C11-07: CLASS renders symbolically from the now-typed Ulong
    // value; other ulong attrs render decoded (no raw-LE-hex fallback).
    #[test]
    fn class_renders_symbolically() {
        assert_eq!(format_ulong_attribute(CkAttributeType::CLASS, 2), "public-key (2)".to_string());
    }

    #[test]
    fn non_class_ulong_renders_decoded_number() {
        assert_eq!(format_ulong_attribute(CkAttributeType::VALUE_LEN, 32), "32".to_string());
    }

    // W1-L2-12: exactly the key-material attributes count as secret
    // (public halves and metadata never redact).
    #[test]
    fn is_secret_attribute_pins_key_material() {
        use CkAttributeType as T;
        for secret in [
            T::VALUE,
            T::PRIVATE_EXPONENT,
            T::PRIME_1,
            T::PRIME_2,
            T::EXPONENT_1,
            T::EXPONENT_2,
            T::COEFFICIENT,
        ] {
            assert!(is_secret_attribute(secret), "{secret:?} must be secret");
        }
        for public in [
            T::LABEL,
            T::CLASS,
            T::KEY_TYPE,
            T::MODULUS,
            T::MODULUS_BITS,
            T::PUBLIC_EXPONENT,
            T::EC_PARAMS,
            T::EC_POINT,
            T::ID,
            T::SUBJECT,
            T::ISSUER,
            T::SERIAL_NUMBER,
            T::VALUE_LEN,
        ] {
            assert!(!is_secret_attribute(public), "{public:?} must not be secret");
        }
    }

    // W1-L2-12: --redact hides secret values only; public values still
    // print, and unredacted secrets still print (explicitly requested).
    #[test]
    fn format_attribute_redacts_secrets_only_when_asked() {
        let secret = CkAttribute {
            attr_type: CkAttributeType::VALUE,
            value: Some(CkAttributeValue::Bytes(vec![0xab, 0xcd].into())),
        };
        let redacted = format_attribute_value("VALUE", &secret, true);
        assert!(redacted.contains("[redacted]"), "must redact: {redacted}");
        assert!(!redacted.contains("abcd"), "must not leak hex: {redacted}");
        let shown = format_attribute_value("VALUE", &secret, false);
        assert!(shown.contains("abcd"), "explicit request prints: {shown}");

        let label = CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String("my-key".to_string().into())),
        };
        let line = format_attribute_value("LABEL", &label, true);
        assert!(line.contains("my-key"), "public values print under --redact: {line}");

        let missing = CkAttribute { attr_type: CkAttributeType::PRIVATE_EXPONENT, value: None };
        let line = format_attribute_value("PRIVATE_EXPONENT", &missing, true);
        assert!(line.contains("unavailable"), "missing stays missing: {line}");
    }
}
