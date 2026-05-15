use crate::pkcs11_proxy_ng::v1 as v1_proto;
use pkcs11_proxy_ng_types::{CkAttribute, CkAttributeType, CkAttributeValue, CkRv};

impl From<&CkAttribute> for v1_proto::Attribute {
    fn from(a: &CkAttribute) -> Self {
        let value = match &a.value {
            None => None,
            Some(CkAttributeValue::Bool(b)) => Some(v1_proto::attribute::Value::BoolValue(*b)),
            Some(CkAttributeValue::Ulong(u)) => Some(v1_proto::attribute::Value::UlongValue(*u)),
            Some(CkAttributeValue::Bytes(b)) => {
                Some(v1_proto::attribute::Value::BytesValue(b.clone()))
            }
            Some(CkAttributeValue::String(s)) => {
                Some(v1_proto::attribute::Value::StringValue(s.clone()))
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
                Some(CkAttributeValue::Bytes(b.clone()))
            }
            Some(v1_proto::attribute::Value::StringValue(s)) => {
                Some(CkAttributeValue::String(s.clone()))
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
            value: Some(CkAttributeValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF])),
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
            value: Some(CkAttributeValue::Bytes(vec![])),
        };
        let proto: v1_proto::Attribute = (&original).into();
        let back = CkAttribute::try_from(&proto).unwrap();
        assert_eq!(back.value, original.value);
    }

    #[test]
    fn attribute_string_round_trip() {
        let original = CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String("my-key".to_string())),
        };
        let proto: v1_proto::Attribute = (&original).into();
        let back = CkAttribute::try_from(&proto).unwrap();
        assert_eq!(back.value, Some(CkAttributeValue::String("my-key".to_string())));
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
    fn attribute_type_high_value_preserved() {
        // Attribute types are open-ended; unknown/vendor types must pass through.
        let original = CkAttribute {
            attr_type: CkAttributeType(0x8000_0001), // hypothetical vendor attribute
            value: Some(CkAttributeValue::Bytes(vec![1, 2, 3])),
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
            value: Some(CkAttributeValue::Bytes(payload.clone())),
        };
        let proto: v1_proto::Attribute = (&original).into();
        let back = CkAttribute::try_from(&proto).unwrap();
        assert_eq!(back.value, Some(CkAttributeValue::Bytes(payload)));
    }
}
