use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use crate::pkcs11_names::{bytes_to_u64, key_type_name, object_class_name};

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
        .and_then(|value| match value {
            CkAttributeValue::Bytes(bytes) => String::from_utf8(bytes.clone()).ok(),
            _ => None,
        })
        .unwrap_or_else(|| "<no label>".to_string());
    let object_class = attrs
        .iter()
        .find(|attr| attr.attr_type == CkAttributeType::CLASS)
        .and_then(|attr| attr.value.as_ref())
        .and_then(|value| match value {
            CkAttributeValue::Bytes(bytes) => bytes_to_u64(bytes),
            _ => None,
        })
        .map(object_class_name)
        .unwrap_or_else(|| "unknown".to_string());
    let key_type = attrs
        .iter()
        .find(|attr| attr.attr_type == CkAttributeType::KEY_TYPE)
        .and_then(|attr| attr.value.as_ref())
        .and_then(|value| match value {
            CkAttributeValue::Bytes(bytes) => bytes_to_u64(bytes),
            _ => None,
        })
        .map(key_type_name)
        .unwrap_or_else(|| "n/a".to_string());

    println!(
        "  handle={:<6}  class={:<12}  key_type={:<10}  label={}",
        object.0, object_class, key_type, object_label
    );
}
