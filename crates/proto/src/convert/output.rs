use crate::pkcs11_proxy_ng::v1 as v1_proto;
use pkcs11_proxy_ng_types::{
    ByteOutputFunction, CkAttributeQuery, CkAttributeQueryResult, CkAttributeType, CkObjectHandle,
    CkOutputAndHandleResult, CkOutputBufferResult, CkOutputBufferSpec, CkParameterRoundtripResult,
    CkParameterRoundtripSpec, CkRv, ParameterOutputFunction,
};

fn attribute_queries_to_proto(queries: &[CkAttributeQuery]) -> v1_proto::AttributeQueryList {
    v1_proto::AttributeQueryList {
        queries: queries.iter().map(v1_proto::AttributeQuery::from).collect(),
    }
}

fn attribute_queries_from_proto(queries: &v1_proto::AttributeQueryList) -> Vec<CkAttributeQuery> {
    queries.queries.iter().map(CkAttributeQuery::from).collect()
}

fn attribute_query_results_to_proto(
    results: &[CkAttributeQueryResult],
) -> v1_proto::AttributeQueryResultList {
    v1_proto::AttributeQueryResultList {
        results: results.iter().map(v1_proto::AttributeQueryResult::from).collect(),
    }
}

fn attribute_query_results_from_proto(
    results: &v1_proto::AttributeQueryResultList,
) -> Vec<CkAttributeQueryResult> {
    results.results.iter().map(CkAttributeQueryResult::from).collect()
}

impl From<&CkOutputBufferSpec> for v1_proto::OutputBufferSpec {
    fn from(spec: &CkOutputBufferSpec) -> Self {
        Self { buffer_present: spec.buffer_present, buffer_len: spec.buffer_len }
    }
}

impl From<&v1_proto::OutputBufferSpec> for CkOutputBufferSpec {
    fn from(spec: &v1_proto::OutputBufferSpec) -> Self {
        Self { buffer_present: spec.buffer_present, buffer_len: spec.buffer_len }
    }
}

impl From<&CkOutputBufferResult> for v1_proto::OutputBufferResult {
    fn from(result: &CkOutputBufferResult) -> Self {
        Self {
            ck_rv: result.ck_rv.0,
            returned_len: result.returned_len,
            value: result.value.clone(),
        }
    }
}

impl From<&v1_proto::OutputBufferResult> for CkOutputBufferResult {
    fn from(result: &v1_proto::OutputBufferResult) -> Self {
        Self {
            ck_rv: CkRv(result.ck_rv),
            returned_len: result.returned_len,
            value: result.value.clone(),
        }
    }
}

impl From<&CkParameterRoundtripSpec> for v1_proto::ParameterRoundtripSpec {
    fn from(spec: &CkParameterRoundtripSpec) -> Self {
        Self {
            buffer_present: spec.buffer_present,
            buffer_len: spec.buffer_len,
            value: spec.value.clone(),
        }
    }
}

impl From<&v1_proto::ParameterRoundtripSpec> for CkParameterRoundtripSpec {
    fn from(spec: &v1_proto::ParameterRoundtripSpec) -> Self {
        Self {
            buffer_present: spec.buffer_present,
            buffer_len: spec.buffer_len,
            value: spec.value.clone(),
        }
    }
}

impl From<&CkParameterRoundtripResult> for v1_proto::ParameterRoundtripResult {
    fn from(result: &CkParameterRoundtripResult) -> Self {
        Self {
            ck_rv: result.ck_rv.0,
            returned_len: result.returned_len,
            value: result.value.clone(),
        }
    }
}

impl From<&v1_proto::ParameterRoundtripResult> for CkParameterRoundtripResult {
    fn from(result: &v1_proto::ParameterRoundtripResult) -> Self {
        Self {
            ck_rv: CkRv(result.ck_rv),
            returned_len: result.returned_len,
            value: result.value.clone(),
        }
    }
}

impl From<&CkOutputAndHandleResult> for v1_proto::OutputAndHandleResult {
    fn from(result: &CkOutputAndHandleResult) -> Self {
        Self {
            ck_rv: result.ck_rv.0,
            returned_len: result.returned_len,
            value: result.value.clone(),
            object_handle: result.object_handle.0,
        }
    }
}

impl From<&v1_proto::OutputAndHandleResult> for CkOutputAndHandleResult {
    fn from(result: &v1_proto::OutputAndHandleResult) -> Self {
        Self {
            ck_rv: CkRv(result.ck_rv),
            returned_len: result.returned_len,
            value: result.value.clone(),
            object_handle: CkObjectHandle(result.object_handle),
        }
    }
}

impl From<&CkAttributeQuery> for v1_proto::AttributeQuery {
    fn from(query: &CkAttributeQuery) -> Self {
        Self {
            attr_type: query.attr_type.0,
            buffer_present: query.buffer_present,
            buffer_len: query.buffer_len,
            nested: query.nested.as_deref().map(attribute_queries_to_proto),
        }
    }
}

impl From<&v1_proto::AttributeQuery> for CkAttributeQuery {
    fn from(query: &v1_proto::AttributeQuery) -> Self {
        Self {
            attr_type: CkAttributeType(query.attr_type),
            buffer_present: query.buffer_present,
            buffer_len: query.buffer_len,
            nested: query.nested.as_ref().map(attribute_queries_from_proto),
        }
    }
}

impl From<&CkAttributeQueryResult> for v1_proto::AttributeQueryResult {
    fn from(result: &CkAttributeQueryResult) -> Self {
        Self {
            attr_type: result.attr_type.0,
            returned_len: result.returned_len,
            value: result.value.clone(),
            ck_rv: result.ck_rv.map(|rv| rv.0),
            nested: result.nested.as_deref().map(attribute_query_results_to_proto),
        }
    }
}

impl From<&v1_proto::AttributeQueryResult> for CkAttributeQueryResult {
    fn from(result: &v1_proto::AttributeQueryResult) -> Self {
        Self {
            attr_type: CkAttributeType(result.attr_type),
            returned_len: result.returned_len,
            value: result.value.clone(),
            ck_rv: result.ck_rv.map(CkRv),
            nested: result.nested.as_ref().map(attribute_query_results_from_proto),
        }
    }
}

impl From<ByteOutputFunction> for v1_proto::ByteOutputFunction {
    fn from(f: ByteOutputFunction) -> Self {
        match f {
            ByteOutputFunction::Sign => Self::Sign,
            ByteOutputFunction::SignFinal => Self::SignFinal,
            ByteOutputFunction::SignRecover => Self::SignRecover,
            ByteOutputFunction::VerifyRecover => Self::VerifyRecover,
            ByteOutputFunction::Digest => Self::Digest,
            ByteOutputFunction::DigestFinal => Self::DigestFinal,
            ByteOutputFunction::Encrypt => Self::Encrypt,
            ByteOutputFunction::EncryptUpdate => Self::EncryptUpdate,
            ByteOutputFunction::EncryptFinal => Self::EncryptFinal,
            ByteOutputFunction::Decrypt => Self::Decrypt,
            ByteOutputFunction::DecryptUpdate => Self::DecryptUpdate,
            ByteOutputFunction::DecryptFinal => Self::DecryptFinal,
            ByteOutputFunction::DigestEncryptUpdate => Self::DigestEncryptUpdate,
            ByteOutputFunction::DecryptDigestUpdate => Self::DecryptDigestUpdate,
            ByteOutputFunction::SignEncryptUpdate => Self::SignEncryptUpdate,
            ByteOutputFunction::DecryptVerifyUpdate => Self::DecryptVerifyUpdate,
            ByteOutputFunction::WrapKey => Self::WrapKey,
            ByteOutputFunction::GetOperationState => Self::GetOperationState,
        }
    }
}

impl TryFrom<v1_proto::ByteOutputFunction> for ByteOutputFunction {
    type Error = ();

    fn try_from(f: v1_proto::ByteOutputFunction) -> Result<Self, Self::Error> {
        match f {
            v1_proto::ByteOutputFunction::Unspecified => Err(()),
            v1_proto::ByteOutputFunction::Sign => Ok(Self::Sign),
            v1_proto::ByteOutputFunction::SignFinal => Ok(Self::SignFinal),
            v1_proto::ByteOutputFunction::SignRecover => Ok(Self::SignRecover),
            v1_proto::ByteOutputFunction::VerifyRecover => Ok(Self::VerifyRecover),
            v1_proto::ByteOutputFunction::Digest => Ok(Self::Digest),
            v1_proto::ByteOutputFunction::DigestFinal => Ok(Self::DigestFinal),
            v1_proto::ByteOutputFunction::Encrypt => Ok(Self::Encrypt),
            v1_proto::ByteOutputFunction::EncryptUpdate => Ok(Self::EncryptUpdate),
            v1_proto::ByteOutputFunction::EncryptFinal => Ok(Self::EncryptFinal),
            v1_proto::ByteOutputFunction::Decrypt => Ok(Self::Decrypt),
            v1_proto::ByteOutputFunction::DecryptUpdate => Ok(Self::DecryptUpdate),
            v1_proto::ByteOutputFunction::DecryptFinal => Ok(Self::DecryptFinal),
            v1_proto::ByteOutputFunction::DigestEncryptUpdate => Ok(Self::DigestEncryptUpdate),
            v1_proto::ByteOutputFunction::DecryptDigestUpdate => Ok(Self::DecryptDigestUpdate),
            v1_proto::ByteOutputFunction::SignEncryptUpdate => Ok(Self::SignEncryptUpdate),
            v1_proto::ByteOutputFunction::DecryptVerifyUpdate => Ok(Self::DecryptVerifyUpdate),
            v1_proto::ByteOutputFunction::WrapKey => Ok(Self::WrapKey),
            v1_proto::ByteOutputFunction::GetOperationState => Ok(Self::GetOperationState),
        }
    }
}

// --- ParameterOutputFunction conversions ---

impl From<ParameterOutputFunction> for v1_proto::ParameterOutputFunction {
    fn from(f: ParameterOutputFunction) -> Self {
        match f {
            ParameterOutputFunction::EncryptMessage => Self::EncryptMessage,
            ParameterOutputFunction::DecryptMessage => Self::DecryptMessage,
            ParameterOutputFunction::SignMessage => Self::SignMessage,
            ParameterOutputFunction::EncryptMessageNext => Self::EncryptMessageNext,
            ParameterOutputFunction::DecryptMessageNext => Self::DecryptMessageNext,
            ParameterOutputFunction::SignMessageNext => Self::SignMessageNext,
            ParameterOutputFunction::WrapKeyAuthenticated => Self::WrapKeyAuthenticated,
        }
    }
}

impl TryFrom<v1_proto::ParameterOutputFunction> for ParameterOutputFunction {
    type Error = ();

    fn try_from(f: v1_proto::ParameterOutputFunction) -> Result<Self, Self::Error> {
        match f {
            v1_proto::ParameterOutputFunction::Unspecified => Err(()),
            v1_proto::ParameterOutputFunction::EncryptMessage => Ok(Self::EncryptMessage),
            v1_proto::ParameterOutputFunction::DecryptMessage => Ok(Self::DecryptMessage),
            v1_proto::ParameterOutputFunction::SignMessage => Ok(Self::SignMessage),
            v1_proto::ParameterOutputFunction::EncryptMessageNext => Ok(Self::EncryptMessageNext),
            v1_proto::ParameterOutputFunction::DecryptMessageNext => Ok(Self::DecryptMessageNext),
            v1_proto::ParameterOutputFunction::SignMessageNext => Ok(Self::SignMessageNext),
            v1_proto::ParameterOutputFunction::WrapKeyAuthenticated => {
                Ok(Self::WrapKeyAuthenticated)
            }
        }
    }
}

/// Convert a `ParameterOutputFunction` to the proto i32 representation.
pub fn parameter_output_function_to_i32(f: ParameterOutputFunction) -> i32 {
    v1_proto::ParameterOutputFunction::from(f) as i32
}

/// Convert a proto i32 to a `ParameterOutputFunction`.
///
/// Returns `None` if the value is unrecognized or `UNSPECIFIED`.
pub fn parameter_output_function_from_i32(value: i32) -> Option<ParameterOutputFunction> {
    let proto = v1_proto::ParameterOutputFunction::try_from(value).ok()?;
    ParameterOutputFunction::try_from(proto).ok()
}

/// Convert a `ByteOutputFunction` to the proto i32 representation.
pub fn byte_output_function_to_i32(f: ByteOutputFunction) -> i32 {
    v1_proto::ByteOutputFunction::from(f) as i32
}

/// Convert a proto i32 to a `ByteOutputFunction`.
///
/// Returns `None` if the value is unrecognized or `UNSPECIFIED`.
pub fn byte_output_function_from_i32(value: i32) -> Option<ByteOutputFunction> {
    let proto = v1_proto::ByteOutputFunction::try_from(value).ok()?;
    ByteOutputFunction::try_from(proto).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use std::fmt::Debug;

    fn wire_round_trip<M>(message: &M) -> M
    where
        M: Message + Default + PartialEq + Debug,
    {
        let mut encoded = Vec::new();
        message.encode(&mut encoded).expect("message should encode");
        M::decode(encoded.as_slice()).expect("message should decode")
    }

    fn append_unknown_length_delimited_field(encoded: &mut Vec<u8>) {
        // field 99, wire type 2, length 3, payload "new"
        encoded.extend_from_slice(&[0x9a, 0x06, 0x03, b'n', b'e', b'w']);
    }

    #[test]
    fn output_buffer_spec_round_trip() {
        let original = CkOutputBufferSpec { buffer_present: true, buffer_len: 4096 };
        let proto = v1_proto::OutputBufferSpec::from(&original);
        let back = CkOutputBufferSpec::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn exact_output_wire_round_trip_preserves_optional_empty_bytes() {
        let output = v1_proto::OutputBufferResult {
            ck_rv: CkRv::OK.0,
            returned_len: 0,
            value: Some(Vec::new()),
        };
        assert_eq!(wire_round_trip(&output).value, Some(Vec::new()));

        let parameter_spec = v1_proto::ParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: 0,
            value: Some(Vec::new()),
        };
        assert_eq!(wire_round_trip(&parameter_spec).value, Some(Vec::new()));

        let parameter_result = v1_proto::ParameterRoundtripResult {
            ck_rv: CkRv::OK.0,
            returned_len: 0,
            value: Some(Vec::new()),
        };
        assert_eq!(wire_round_trip(&parameter_result).value, Some(Vec::new()));

        let output_and_handle = v1_proto::OutputAndHandleResult {
            ck_rv: CkRv::OK.0,
            returned_len: 0,
            value: Some(Vec::new()),
            object_handle: 7,
        };
        assert_eq!(wire_round_trip(&output_and_handle).value, Some(Vec::new()));

        let attribute_result = v1_proto::AttributeQueryResult {
            attr_type: CkAttributeType::VALUE.0,
            returned_len: 0,
            value: Some(Vec::new()),
            ck_rv: Some(CkRv::OK.0),
            nested: Some(v1_proto::AttributeQueryResultList { results: Vec::new() }),
        };
        let decoded = wire_round_trip(&attribute_result);
        assert_eq!(decoded.value, Some(Vec::new()));
        assert_eq!(decoded.ck_rv, Some(CkRv::OK.0));
        assert_eq!(
            decoded.nested,
            Some(v1_proto::AttributeQueryResultList { results: Vec::new() })
        );
    }

    #[test]
    fn exact_request_decode_ignores_unknown_future_fields() {
        let request = v1_proto::ByteOutputExactRequest {
            client_context_id: "ctx".to_string(),
            session_handle: 11,
            function: byte_output_function_to_i32(ByteOutputFunction::Sign),
            output_spec: Some(v1_proto::OutputBufferSpec { buffer_present: true, buffer_len: 64 }),
            input_data: b"payload".to_vec(),
            mechanism: None,
            wrapping_key_handle: 0,
            key_handle: 0,
        };

        let mut encoded = Vec::new();
        request.encode(&mut encoded).expect("request should encode");
        append_unknown_length_delimited_field(&mut encoded);

        let decoded = v1_proto::ByteOutputExactRequest::decode(encoded.as_slice())
            .expect("unknown future fields should be ignored");
        assert_eq!(decoded, request);
    }

    #[test]
    fn output_buffer_result_round_trip_preserves_absent_value() {
        let original =
            CkOutputBufferResult { ck_rv: CkRv::BUFFER_TOO_SMALL, returned_len: 512, value: None };
        let proto = v1_proto::OutputBufferResult::from(&original);
        let back = CkOutputBufferResult::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn parameter_roundtrip_spec_round_trip_preserves_empty_value() {
        let original = CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: 0,
            value: Some(Vec::new()),
        };
        let proto = v1_proto::ParameterRoundtripSpec::from(&original);
        let back = CkParameterRoundtripSpec::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn parameter_roundtrip_result_round_trip() {
        let original = CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: 7,
            value: Some(vec![1, 2, 3, 4, 5, 6, 7]),
        };
        let proto = v1_proto::ParameterRoundtripResult::from(&original);
        let back = CkParameterRoundtripResult::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn output_and_handle_result_round_trip() {
        let original = CkOutputAndHandleResult {
            ck_rv: CkRv::OK,
            returned_len: 3,
            value: Some(vec![0xAA, 0xBB, 0xCC]),
            object_handle: CkObjectHandle(41),
        };
        let proto = v1_proto::OutputAndHandleResult::from(&original);
        let back = CkOutputAndHandleResult::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn attribute_query_round_trip_preserves_nested_shape() {
        let original = CkAttributeQuery {
            attr_type: CkAttributeType::VALUE,
            buffer_present: true,
            buffer_len: 64,
            nested: Some(vec![
                CkAttributeQuery {
                    attr_type: CkAttributeType::LABEL,
                    buffer_present: false,
                    buffer_len: 0,
                    nested: None,
                },
                CkAttributeQuery {
                    attr_type: CkAttributeType::MODULUS,
                    buffer_present: true,
                    buffer_len: 128,
                    nested: Some(vec![]),
                },
            ]),
        };
        let proto = v1_proto::AttributeQuery::from(&original);
        let back = CkAttributeQuery::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn attribute_query_result_round_trip_preserves_nested_per_attribute_status() {
        let original = CkAttributeQueryResult {
            attr_type: CkAttributeType::VALUE,
            returned_len: u64::MAX,
            value: None,
            ck_rv: Some(CkRv::ATTRIBUTE_SENSITIVE),
            nested: Some(vec![CkAttributeQueryResult {
                attr_type: CkAttributeType::LABEL,
                returned_len: 4,
                value: Some(b"test".to_vec()),
                ck_rv: None,
                nested: Some(vec![]),
            }]),
        };
        let proto = v1_proto::AttributeQueryResult::from(&original);
        let back = CkAttributeQueryResult::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn attribute_query_list_round_trip_preserves_empty_nested_list() {
        let original = vec![CkAttributeQuery {
            attr_type: CkAttributeType::VALUE,
            buffer_present: true,
            buffer_len: 1,
            nested: Some(vec![]),
        }];
        let proto = attribute_queries_to_proto(&original);
        let back = attribute_queries_from_proto(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn attribute_query_result_list_round_trip_preserves_absent_and_empty_values() {
        let original = vec![
            CkAttributeQueryResult {
                attr_type: CkAttributeType::VALUE,
                returned_len: 0,
                value: Some(Vec::new()),
                ck_rv: None,
                nested: None,
            },
            CkAttributeQueryResult {
                attr_type: CkAttributeType::SUBJECT,
                returned_len: 12,
                value: None,
                ck_rv: Some(CkRv::ATTRIBUTE_TYPE_INVALID),
                nested: Some(vec![]),
            },
        ];
        let proto = attribute_query_results_to_proto(&original);
        let back = attribute_query_results_from_proto(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn byte_output_function_round_trip_all_variants() {
        let variants = [
            ByteOutputFunction::Sign,
            ByteOutputFunction::SignFinal,
            ByteOutputFunction::SignRecover,
            ByteOutputFunction::VerifyRecover,
            ByteOutputFunction::Digest,
            ByteOutputFunction::DigestFinal,
            ByteOutputFunction::Encrypt,
            ByteOutputFunction::EncryptUpdate,
            ByteOutputFunction::EncryptFinal,
            ByteOutputFunction::Decrypt,
            ByteOutputFunction::DecryptUpdate,
            ByteOutputFunction::DecryptFinal,
            ByteOutputFunction::DigestEncryptUpdate,
            ByteOutputFunction::DecryptDigestUpdate,
            ByteOutputFunction::SignEncryptUpdate,
            ByteOutputFunction::DecryptVerifyUpdate,
            ByteOutputFunction::WrapKey,
            ByteOutputFunction::GetOperationState,
        ];

        for &variant in &variants {
            let proto = v1_proto::ByteOutputFunction::from(variant);
            let back = ByteOutputFunction::try_from(proto).expect("round-trip should succeed");
            assert_eq!(back, variant);

            // Also test the i32 path (used by prost for enum fields)
            let i32_val = byte_output_function_to_i32(variant);
            let back2 =
                byte_output_function_from_i32(i32_val).expect("i32 round-trip should succeed");
            assert_eq!(back2, variant);
        }
    }

    #[test]
    fn byte_output_function_rejects_unspecified() {
        assert!(ByteOutputFunction::try_from(v1_proto::ByteOutputFunction::Unspecified).is_err());
        assert!(byte_output_function_from_i32(0).is_none());
    }

    #[test]
    fn byte_output_function_rejects_out_of_range() {
        assert!(byte_output_function_from_i32(99).is_none());
    }

    #[test]
    fn parameter_output_function_round_trip_all_variants() {
        let variants = [
            ParameterOutputFunction::EncryptMessage,
            ParameterOutputFunction::DecryptMessage,
            ParameterOutputFunction::SignMessage,
            ParameterOutputFunction::EncryptMessageNext,
            ParameterOutputFunction::DecryptMessageNext,
            ParameterOutputFunction::SignMessageNext,
            ParameterOutputFunction::WrapKeyAuthenticated,
        ];

        for &variant in &variants {
            let proto = v1_proto::ParameterOutputFunction::from(variant);
            let back = ParameterOutputFunction::try_from(proto).expect("round-trip should succeed");
            assert_eq!(back, variant);

            // Also test the i32 path (used by prost for enum fields)
            let i32_val = parameter_output_function_to_i32(variant);
            let back2 =
                parameter_output_function_from_i32(i32_val).expect("i32 round-trip should succeed");
            assert_eq!(back2, variant);
        }
    }

    #[test]
    fn parameter_output_function_rejects_unspecified() {
        assert!(
            ParameterOutputFunction::try_from(v1_proto::ParameterOutputFunction::Unspecified)
                .is_err()
        );
        assert!(parameter_output_function_from_i32(0).is_none());
    }

    #[test]
    fn parameter_output_function_rejects_out_of_range() {
        assert!(parameter_output_function_from_i32(99).is_none());
    }
}
