use crate::pkcs11_proxy_ng::v1 as v1_proto;
// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use crate::secret_boundary::{secret_to_plain, secret_to_plain_string};
use pkcs11_proxy_ng_types::{CkAttribute, CkAttributeType, CkAttributeValue, CkRv, SecretBytes};

impl From<&CkAttribute> for v1_proto::Attribute {
    fn from(a: &CkAttribute) -> Self {
        let value = match &a.value {
            None => None,
            Some(CkAttributeValue::Bool(b)) => Some(v1_proto::attribute::Value::BoolValue(*b)),
            Some(CkAttributeValue::Ulong(u)) => Some(v1_proto::attribute::Value::UlongValue(*u)),
            Some(CkAttributeValue::Bytes(b)) => {
                Some(v1_proto::attribute::Value::BytesValue(secret_to_plain(b)))
            }
            Some(CkAttributeValue::String(s)) => {
                Some(v1_proto::attribute::Value::StringValue(secret_to_plain_string(s)))
            }
            Some(CkAttributeValue::NestedTemplate(subs)) => {
                Some(v1_proto::attribute::Value::NestedTemplate(v1_proto::NestedAttributes {
                    attributes: subs.iter().map(v1_proto::Attribute::from).collect(),
                }))
            }
        };
        v1_proto::Attribute { attr_type: a.attr_type.0, value }
    }
}

impl TryFrom<&v1_proto::Attribute> for CkAttribute {
    type Error = CkRv;

    fn try_from(a: &v1_proto::Attribute) -> Result<Self, Self::Error> {
        let value = match &a.value {
            None => None,
            Some(v1_proto::attribute::Value::BoolValue(b)) => Some(CkAttributeValue::Bool(*b)),
            Some(v1_proto::attribute::Value::UlongValue(u)) => Some(CkAttributeValue::Ulong(*u)),
            Some(v1_proto::attribute::Value::BytesValue(b)) => {
                Some(CkAttributeValue::Bytes(SecretBytes::copy_from_slice(b)))
            }
            Some(v1_proto::attribute::Value::StringValue(s)) => {
                Some(CkAttributeValue::String(SecretBytes::copy_from_slice(s.as_bytes())))
            }
            Some(v1_proto::attribute::Value::NestedTemplate(nested)) => {
                // D8: one level of nesting. A sub-attribute carrying another
                // nested template is refused at the deserialization edge so
                // neither the daemon nor the backend ever sees deeper trees.
                let subs: Vec<CkAttribute> = nested
                    .attributes
                    .iter()
                    .map(CkAttribute::try_from)
                    .collect::<Result<_, _>>()?;
                if subs
                    .iter()
                    .any(|sub| matches!(sub.value, Some(CkAttributeValue::NestedTemplate(_))))
                {
                    return Err(CkRv::ATTRIBUTE_VALUE_INVALID);
                }
                Some(CkAttributeValue::NestedTemplate(subs))
            }
        };
        Ok(CkAttribute { attr_type: CkAttributeType(a.attr_type), value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_bool_round_trip() {
        let original = CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(true)),
        };
        let proto: v1_proto::Attribute = (&original).into();
        let back = CkAttribute::try_from(&proto).unwrap();
        assert_eq!(back.attr_type, original.attr_type);
        assert_eq!(back.value, original.value);
    }

    #[test]
    fn attribute_bool_false_round_trip() {
        let original = CkAttribute {
            attr_type: CkAttributeType::SENSITIVE,
            value: Some(CkAttributeValue::Bool(false)),
        };
        let proto: v1_proto::Attribute = (&original).into();
        let back = CkAttribute::try_from(&proto).unwrap();
        assert_eq!(back.value, Some(CkAttributeValue::Bool(false)));
    }

    #[test]
    fn attribute_ulong_round_trip() {
        let original = CkAttribute {
            attr_type: CkAttributeType::KEY_TYPE,
            value: Some(CkAttributeValue::Ulong(0x00000003)), // CKK_RSA
        };
        let proto: v1_proto::Attribute = (&original).into();
        let back = CkAttribute::try_from(&proto).unwrap();
        assert_eq!(back.attr_type, original.attr_type);
        assert_eq!(back.value, original.value);
    }

    #[test]
    fn attribute_ulong_max_value_round_trip() {
        // u64::MAX is used as CK_UNAVAILABLE_INFORMATION for sensitive attributes.
        let original = CkAttribute {
            attr_type: CkAttributeType::VALUE_LEN,
            value: Some(CkAttributeValue::Ulong(u64::MAX)),
        };
        let proto: v1_proto::Attribute = (&original).into();
        let back = CkAttribute::try_from(&proto).unwrap();
        assert_eq!(back.value, Some(CkAttributeValue::Ulong(u64::MAX)));
    }

    #[test]
    fn attribute_bytes_round_trip() {
        let original = CkAttribute {
            attr_type: CkAttributeType::MODULUS,
            value: Some(CkAttributeValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF].into())),
        };
        let proto: v1_proto::Attribute = (&original).into();
        let back = CkAttribute::try_from(&proto).unwrap();
        assert_eq!(back.value, original.value);
    }

    #[test]
    fn attribute_empty_bytes_round_trip() {
        // Empty bytes occur during C_GetAttributeValue size-query pass:
        // the client sends attributes with None/empty value, server fills them.
        let original = CkAttribute {
            attr_type: CkAttributeType::MODULUS,
            value: Some(CkAttributeValue::Bytes(vec![].into())),
        };
        let proto: v1_proto::Attribute = (&original).into();
        let back = CkAttribute::try_from(&proto).unwrap();
        assert_eq!(back.value, original.value);
    }

    #[test]
    fn attribute_string_round_trip() {
        let original = CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String("my-key".to_string().into())),
        };
        let proto: v1_proto::Attribute = (&original).into();
        let back = CkAttribute::try_from(&proto).unwrap();
        assert_eq!(back.value, Some(CkAttributeValue::String("my-key".to_string().into())));
    }

    #[test]
    fn attribute_no_value_round_trip() {
        let original = CkAttribute { attr_type: CkAttributeType::MODULUS, value: None };
        let proto: v1_proto::Attribute = (&original).into();
        let back = CkAttribute::try_from(&proto).unwrap();
        assert_eq!(back.attr_type, original.attr_type);
        assert!(back.value.is_none());
    }

    #[test]
    fn attribute_nested_template_round_trip() {
        let original = CkAttribute {
            attr_type: CkAttributeType::WRAP_TEMPLATE,
            value: Some(CkAttributeValue::NestedTemplate(vec![
                CkAttribute {
                    attr_type: CkAttributeType::CLASS,
                    value: Some(CkAttributeValue::Ulong(4)),
                },
                CkAttribute {
                    attr_type: CkAttributeType::EXTRACTABLE,
                    value: Some(CkAttributeValue::Bool(false)),
                },
            ])),
        };
        let proto: v1_proto::Attribute = (&original).into();
        let back = CkAttribute::try_from(&proto).unwrap();
        assert_eq!(back.value, original.value);
    }

    #[test]
    fn attribute_nested_template_depth_two_is_refused() {
        // D8: sub-attributes must not themselves be templates.
        let inner = CkAttribute {
            attr_type: CkAttributeType::WRAP_TEMPLATE,
            value: Some(CkAttributeValue::NestedTemplate(vec![])),
        };
        let outer = CkAttribute {
            attr_type: CkAttributeType::WRAP_TEMPLATE,
            value: Some(CkAttributeValue::NestedTemplate(vec![inner])),
        };
        let proto: v1_proto::Attribute = (&outer).into();
        assert_eq!(CkAttribute::try_from(&proto).unwrap_err(), CkRv::ATTRIBUTE_VALUE_INVALID);
    }

    #[test]
    fn attribute_type_high_value_preserved() {
        // Attribute types are open-ended; unknown/vendor types must pass through.
        let original = CkAttribute {
            attr_type: CkAttributeType(0x8000_0001), // hypothetical vendor attribute
            value: Some(CkAttributeValue::Bytes(vec![1, 2, 3].into())),
        };
        let proto: v1_proto::Attribute = (&original).into();
        let back = CkAttribute::try_from(&proto).unwrap();
        assert_eq!(back.attr_type, CkAttributeType(0x8000_0001));
    }

    #[test]
    fn attribute_large_bytes_payload_round_trip() {
        // Ensure large buffers (e.g. a 512-byte RSA modulus) pass through intact.
        let payload: Vec<u8> = (0u8..=255).chain(0u8..=255).collect(); // 512 bytes
        let original = CkAttribute {
            attr_type: CkAttributeType::MODULUS,
            value: Some(CkAttributeValue::Bytes(payload.clone().into())),
        };
        let proto: v1_proto::Attribute = (&original).into();
        let back = CkAttribute::try_from(&proto).unwrap();
        assert_eq!(back.value, Some(CkAttributeValue::Bytes(payload.into())));
    }
}
