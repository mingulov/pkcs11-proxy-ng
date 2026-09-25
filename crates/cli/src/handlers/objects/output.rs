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

/// Render one verbose object line (W1-C11-32): `Ok` renders the
/// attribute line (missing values keep the unknown/n/a fallbacks);
/// `Err` renders the failure with its symbolic CKR cause instead of
/// swallowing it as placeholder values.
pub(crate) fn format_verbose_object(
    object: CkObjectHandle,
    result: &Result<(CkRv, Vec<CkAttribute>), CkRv>,
) -> String {
    match result {
        Err(rv) => {
            format!("  handle={:<6}  error: C_GetAttributeValue failed: {rv}", object.0)
        }
        Ok((_, attrs)) => {
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

            format!(
                "  handle={:<6}  class={:<12}  key_type={:<10}  label={}",
                object.0, object_class, key_type, object_label
            )
        }
    }
}

/// Warning for a non-OK per-object rv with partial results
/// (W1-C11-32): `None` when OK so successes stay silent.
pub(crate) fn verbose_rv_warning(rv: CkRv) -> Option<String> {
    if rv.is_err() {
        Some(format!("warning: C_GetAttributeValue returned {rv} (partial results follow)"))
    } else {
        None
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
    let result = client.get_attribute_value(session, object, &attr_template).await;
    if let Ok((rv, _)) = &result
        && let Some(warning) = verbose_rv_warning(*rv)
    {
        eprintln!("{warning}");
    }
    println!("{}", format_verbose_object(object, &result));
}

#[cfg(test)]
mod tests {
    use super::*;

    // W1-C11-32: successes keep their exact line shape (missing values
    // still fall back to unknown/n/a — only RPC failures change).
    #[test]
    fn verbose_success_line_keeps_shape() {
        let attrs = vec![
            CkAttribute {
                attr_type: CkAttributeType::LABEL,
                value: Some(CkAttributeValue::String("my-key".to_string().into())),
            },
            CkAttribute {
                attr_type: CkAttributeType::CLASS,
                value: Some(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
            },
            CkAttribute {
                attr_type: CkAttributeType::KEY_TYPE,
                value: Some(CkAttributeValue::Ulong(CkKeyType::AES.0)),
            },
        ];
        let line = format_verbose_object(CkObjectHandle(3), &Ok((CkRv::OK, attrs)));
        assert_eq!(line, "  handle=3       class=secret-key    key_type=AES         label=my-key");
    }

    // W1-C11-32: a failed get_attribute_value renders with its symbolic
    // CKR cause instead of unknown/n/a placeholders.
    #[test]
    fn verbose_error_line_surfaces_cause() {
        let line = format_verbose_object(CkObjectHandle(9), &Err(CkRv::ATTRIBUTE_SENSITIVE));
        assert!(line.contains("handle=9"), "must name the handle: {line}");
        assert!(line.contains("CKR_ATTRIBUTE_SENSITIVE"), "must name the cause: {line}");
        assert!(line.contains("0x"), "must keep hex alongside: {line}");
        assert!(!line.contains("unknown"), "must not swallow as unknown: {line}");
    }

    // W1-C11-32: a non-OK rv with partial results warns symbolically;
    // OK stays silent.
    #[test]
    fn verbose_partial_rv_warns_symbolically() {
        let warning = verbose_rv_warning(CkRv::ATTRIBUTE_TYPE_INVALID).expect("must warn");
        assert!(warning.contains("CKR_ATTRIBUTE_TYPE_INVALID"), "must name: {warning}");
        assert!(warning.contains("0x"), "must keep hex: {warning}");
        assert_eq!(verbose_rv_warning(CkRv::OK), None);
    }

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
