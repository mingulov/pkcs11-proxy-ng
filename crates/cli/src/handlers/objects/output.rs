use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use crate::pkcs11_names::{bytes_to_u64, key_type_name, object_class_name};

/// Decode a label-ish value (W1-C10-08): `String` from typed reads,
/// `Bytes` from unhinted reads; anything else has no text.
pub(crate) fn label_text(value: &CkAttributeValue) -> Option<String> {
    match value {
        CkAttributeValue::String(text) => text.expose(|raw| String::from_utf8(raw.to_vec()).ok()),
        CkAttributeValue::Bytes(bytes) => bytes.expose(|raw| String::from_utf8(raw.to_vec()).ok()),
        _ => None,
    }
}

/// Decode a ulong-ish value (W1-C10-08): `Ulong` from typed reads,
/// `Bytes` via `bytes_to_u64` from unhinted reads.
pub(crate) fn ulong_value(value: &CkAttributeValue) -> Option<u64> {
    match value {
        CkAttributeValue::Ulong(v) => Some(*v),
        CkAttributeValue::Bytes(bytes) => bytes.expose(bytes_to_u64),
        _ => None,
    }
}

pub(super) async fn print_verbose_object(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    object: CkObjectHandle,
) {
    let attr_template = vec![
        CkAttribute { attr_type: CkAttributeType::LABEL, value: None },
        CkAttribute { attr_type: CkAttributeType::CLASS, value: None },
        CkAttribute { attr_type: CkAttributeType::KEY_TYPE, value: None },
    ];
    let attrs = client
        .get_attribute_value(session, object, &attr_template)
        .await
        .map(|(_, attrs)| attrs)
        .unwrap_or_default();

    let object_label = attrs
        .iter()
        .find(|attr| attr.attr_type == CkAttributeType::LABEL)
        .and_then(|attr| attr.value.as_ref())
        .and_then(label_text)
        .unwrap_or_else(|| "<no label>".to_string());
    let object_class = attrs
        .iter()
        .find(|attr| attr.attr_type == CkAttributeType::CLASS)
        .and_then(|attr| attr.value.as_ref())
        .and_then(ulong_value)
        .map(object_class_name)
        .unwrap_or_else(|| "unknown".to_string());
    let key_type = attrs
        .iter()
        .find(|attr| attr.attr_type == CkAttributeType::KEY_TYPE)
        .and_then(|attr| attr.value.as_ref())
        .and_then(ulong_value)
        .map(key_type_name)
        .unwrap_or_else(|| "n/a".to_string());

    println!(
        "  handle={:<6}  class={:<12}  key_type={:<10}  label={}",
        object.0, object_class, key_type, object_label
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // W1-C10-08: verbose-object arms decode typed values (Ulong/String)
    // as well as legacy Bytes; anything else stays unknown.
    #[test]
    fn label_text_accepts_string_and_bytes() {
        assert_eq!(
            label_text(&CkAttributeValue::String("my-key".to_string().into())),
            Some("my-key".to_string())
        );
        assert_eq!(
            label_text(&CkAttributeValue::Bytes(b"my-key".to_vec().into())),
            Some("my-key".to_string())
        );
        assert_eq!(label_text(&CkAttributeValue::Ulong(1)), None);
        assert_eq!(label_text(&CkAttributeValue::Bytes(vec![0xff].into())), None);
    }

    #[test]
    fn ulong_value_accepts_ulong_and_bytes() {
        assert_eq!(ulong_value(&CkAttributeValue::Ulong(4)), Some(4));
        assert_eq!(
            ulong_value(&CkAttributeValue::Bytes(4u64.to_ne_bytes().to_vec().into())),
            Some(4)
        );
        assert_eq!(ulong_value(&CkAttributeValue::Bool(true)), None);
    }
}
