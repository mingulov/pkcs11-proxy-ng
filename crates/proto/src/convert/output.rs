use crate::pkcs11_proxy_ng::v1 as v1_proto;
// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use crate::secret_boundary::{secret_into_plain, secret_to_plain};
use pkcs11_proxy_ng_types::{
    ByteOutputFunction, CkAttributeQuery, CkAttributeQueryResult, CkAttributeType, CkObjectHandle,
    CkOutputAndHandleResult, CkOutputBufferResult, CkOutputBufferSpec, CkParameterRoundtripResult,
    CkParameterRoundtripSpec, CkRv, ParameterOutputFunction, SecretBytes,
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

/// Owned-input variant of `attribute_query_results_to_proto`. Moves the
/// `Vec<u8>` of each result's `value` straight into the proto buffer
/// without cloning (the wiping owner's allocation is transferred via
/// `secret_into_plain`; the borrowed `From<&CkAttributeQueryResult>` still
/// copies via `secret_to_plain`). Mirrors the consume-by-value optimization
/// applied to `attribute_results` for `C_GetAttributeValue` so the exact
/// path (`C_GetAttributeValue_exact`) has the same allocation profile.
fn attribute_query_results_into_proto(
    results: Vec<CkAttributeQueryResult>,
) -> v1_proto::AttributeQueryResultList {
    v1_proto::AttributeQueryResultList {
        results: results.into_iter().map(v1_proto::AttributeQueryResult::from).collect(),
    }
}

#[cfg(test)]
fn attribute_query_results_from_proto(
    results: &v1_proto::AttributeQueryResultList,
) -> Result<Vec<CkAttributeQueryResult>, CkRv> {
    results.results.iter().map(CkAttributeQueryResult::try_from).collect()
}

impl From<&CkOutputBufferSpec> for v1_proto::OutputBufferSpec {
    fn from(spec: &CkOutputBufferSpec) -> Self {
        Self {
            buffer_present: spec.buffer_present,
            buffer_len: spec.buffer_len,
            length_pointer_null: spec.length_pointer_null,
        }
    }
}

impl From<&v1_proto::OutputBufferSpec> for CkOutputBufferSpec {
    fn from(spec: &v1_proto::OutputBufferSpec) -> Self {
        Self {
            buffer_present: spec.buffer_present,
            buffer_len: spec.buffer_len,
            length_pointer_null: spec.length_pointer_null,
        }
    }
}

impl From<&CkOutputBufferResult> for v1_proto::OutputBufferResult {
    fn from(result: &CkOutputBufferResult) -> Self {
        Self {
            ck_rv: result.ck_rv.0,
            returned_len: result.returned_len.unwrap_or(0),
            value: result.value.as_ref().map(secret_to_plain),
            apply_returned_len: Some(result.returned_len.is_some()),
        }
    }
}

impl TryFrom<&v1_proto::OutputBufferResult> for CkOutputBufferResult {
    type Error = CkRv;
    fn try_from(result: &v1_proto::OutputBufferResult) -> Result<Self, CkRv> {
        let apply = result.apply_returned_len.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        if !apply && (result.returned_len != 0 || result.value.is_some()) {
            return Err(CkRv::FUNCTION_NOT_SUPPORTED);
        }
        Ok(Self {
            ck_rv: CkRv(result.ck_rv),
            returned_len: apply.then_some(result.returned_len),
            value: result.value.clone().map(SecretBytes::new),
        })
    }
}

/// T13 owned entry point: identical validation to the borrowed `TryFrom`,
/// but adopts the value buffer with `mem::take` instead of cloning it — no
/// transient second copy. The caller must own the message (typically a
/// `mem::take`n response field). On validation failure the message drops
/// and wipes via T12. (Free function rather than an inherent method: the
/// `Ck` project types live in the `types` crate, which must not depend on
/// the wire schema.)
pub fn output_buffer_result_from_owned(
    mut result: v1_proto::OutputBufferResult,
) -> Result<CkOutputBufferResult, CkRv> {
    let apply = result.apply_returned_len.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
    if !apply && (result.returned_len != 0 || result.value.is_some()) {
        return Err(CkRv::FUNCTION_NOT_SUPPORTED);
    }
    Ok(CkOutputBufferResult {
        ck_rv: CkRv(result.ck_rv),
        returned_len: apply.then_some(result.returned_len),
        value: result.value.take().map(SecretBytes::new),
    })
}

impl From<&CkParameterRoundtripSpec> for v1_proto::ParameterRoundtripSpec {
    fn from(spec: &CkParameterRoundtripSpec) -> Self {
        Self {
            buffer_present: spec.buffer_present,
            buffer_len: spec.buffer_len,
            value: spec.value.as_ref().map(secret_to_plain),
        }
    }
}

impl From<&v1_proto::ParameterRoundtripSpec> for CkParameterRoundtripSpec {
    fn from(spec: &v1_proto::ParameterRoundtripSpec) -> Self {
        Self {
            buffer_present: spec.buffer_present,
            buffer_len: spec.buffer_len,
            value: spec.value.clone().map(SecretBytes::new),
        }
    }
}

/// T13 owned entry point: adopts the value buffer with `mem::take`
/// instead of cloning it. The caller must own the message.
pub fn parameter_roundtrip_spec_from_owned(
    mut spec: v1_proto::ParameterRoundtripSpec,
) -> CkParameterRoundtripSpec {
    CkParameterRoundtripSpec {
        buffer_present: spec.buffer_present,
        buffer_len: spec.buffer_len,
        value: spec.value.take().map(SecretBytes::new),
    }
}

impl From<&CkParameterRoundtripResult> for v1_proto::ParameterRoundtripResult {
    fn from(result: &CkParameterRoundtripResult) -> Self {
        Self {
            ck_rv: result.ck_rv.0,
            returned_len: result.returned_len,
            value: result.value.as_ref().map(secret_to_plain),
        }
    }
}

impl From<&v1_proto::ParameterRoundtripResult> for CkParameterRoundtripResult {
    fn from(result: &v1_proto::ParameterRoundtripResult) -> Self {
        Self {
            ck_rv: CkRv(result.ck_rv),
            returned_len: result.returned_len,
            value: result.value.clone().map(SecretBytes::new),
        }
    }
}

/// T13 owned entry point: adopts the value buffer with `mem::take`
/// instead of cloning it. The caller must own the message.
pub fn parameter_roundtrip_result_from_owned(
    mut result: v1_proto::ParameterRoundtripResult,
) -> CkParameterRoundtripResult {
    CkParameterRoundtripResult {
        ck_rv: CkRv(result.ck_rv),
        returned_len: result.returned_len,
        value: result.value.take().map(SecretBytes::new),
    }
}

impl From<&CkOutputAndHandleResult> for v1_proto::OutputAndHandleResult {
    fn from(result: &CkOutputAndHandleResult) -> Self {
        Self {
            ck_rv: result.ck_rv.0,
            returned_len: result.returned_len.unwrap_or(0),
            value: result.value.as_ref().map(secret_to_plain),
            object_handle: result.object_handle.map_or(0, |handle| handle.0),
            apply_returned_len: Some(result.returned_len.is_some()),
            apply_object_handle: Some(result.object_handle.is_some()),
        }
    }
}

impl TryFrom<&v1_proto::OutputAndHandleResult> for CkOutputAndHandleResult {
    type Error = CkRv;
    fn try_from(result: &v1_proto::OutputAndHandleResult) -> Result<Self, CkRv> {
        let apply = result.apply_returned_len.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let handle = result.apply_object_handle.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        if (!apply && (result.returned_len != 0 || result.value.is_some()))
            || (!handle && result.object_handle != 0)
            || (handle && result.ck_rv != CkRv::OK.0)
        {
            return Err(CkRv::FUNCTION_NOT_SUPPORTED);
        }
        Ok(Self {
            ck_rv: CkRv(result.ck_rv),
            returned_len: apply.then_some(result.returned_len),
            value: result.value.clone().map(SecretBytes::new),
            object_handle: handle.then_some(CkObjectHandle(result.object_handle)),
        })
    }
}

/// T13 owned entry point: identical validation to the borrowed
/// `TryFrom`, but adopts the value buffer with `mem::take` instead of
/// cloning it. The caller must own the message. On validation failure
/// the message drops and wipes via T12.
pub fn output_and_handle_result_from_owned(
    mut result: v1_proto::OutputAndHandleResult,
) -> Result<CkOutputAndHandleResult, CkRv> {
    let apply = result.apply_returned_len.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
    let handle = result.apply_object_handle.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
    if (!apply && (result.returned_len != 0 || result.value.is_some()))
        || (!handle && result.object_handle != 0)
        || (handle && result.ck_rv != CkRv::OK.0)
    {
        return Err(CkRv::FUNCTION_NOT_SUPPORTED);
    }
    Ok(CkOutputAndHandleResult {
        ck_rv: CkRv(result.ck_rv),
        returned_len: apply.then_some(result.returned_len),
        value: result.value.take().map(SecretBytes::new),
        object_handle: handle.then_some(CkObjectHandle(result.object_handle)),
    })
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
            apply_returned_len: Some(result.apply_returned_len),
            apply_type: Some(result.apply_type),
            attr_type: result.attr_type.0,
            returned_len: result.returned_len,
            value: result.value.as_ref().map(secret_to_plain),
            ck_rv: result.ck_rv.map(|rv| rv.0),
            nested: result.nested.as_deref().map(attribute_query_results_to_proto),
        }
    }
}

impl From<CkAttributeQueryResult> for v1_proto::AttributeQueryResult {
    fn from(mut result: CkAttributeQueryResult) -> Self {
        Self {
            apply_returned_len: Some(result.apply_returned_len),
            apply_type: Some(result.apply_type),
            attr_type: result.attr_type.0,
            returned_len: result.returned_len,
            value: result.value.take().map(secret_into_plain),
            ck_rv: result.ck_rv.map(|rv| rv.0),
            nested: result.nested.map(attribute_query_results_into_proto),
        }
    }
}

impl TryFrom<&v1_proto::AttributeQueryResult> for CkAttributeQueryResult {
    type Error = CkRv;
    fn try_from(result: &v1_proto::AttributeQueryResult) -> Result<Self, CkRv> {
        decode_attribute_result(result, 0)
    }
}

/// T13 owned entry point: identical validation to the borrowed `TryFrom`
/// (including the depth-1 nesting cap), but adopts every value buffer
/// with `mem::take` instead of cloning it. The caller must own the
/// message. On validation failure the message drops and wipes via T12.
pub fn attribute_query_result_from_owned(
    result: v1_proto::AttributeQueryResult,
) -> Result<CkAttributeQueryResult, CkRv> {
    decode_attribute_result_owned(result, 0)
}

fn decode_attribute_result_owned(
    mut result: v1_proto::AttributeQueryResult,
    depth: usize,
) -> Result<CkAttributeQueryResult, CkRv> {
    let apply_returned_len = result.apply_returned_len.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
    let apply_type = result.apply_type.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
    if !apply_returned_len
        && (result.returned_len != 0 || result.value.is_some() || result.nested.is_some())
    {
        return Err(CkRv::FUNCTION_NOT_SUPPORTED);
    }
    if depth > 1 {
        return Err(CkRv::FUNCTION_NOT_SUPPORTED);
    }
    Ok(CkAttributeQueryResult {
        apply_returned_len,
        apply_type,
        attr_type: CkAttributeType(result.attr_type),
        returned_len: result.returned_len,
        value: result.value.take().map(SecretBytes::new),
        ck_rv: result.ck_rv.map(CkRv),
        nested: result
            .nested
            .take()
            .map(|mut list| {
                std::mem::take(&mut list.results)
                    .into_iter()
                    .map(|sub| decode_attribute_result_owned(sub, depth + 1))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?,
    })
}

fn decode_attribute_result(
    result: &v1_proto::AttributeQueryResult,
    depth: usize,
) -> Result<CkAttributeQueryResult, CkRv> {
    let apply_returned_len = result.apply_returned_len.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
    let apply_type = result.apply_type.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
    if !apply_returned_len
        && (result.returned_len != 0 || result.value.is_some() || result.nested.is_some())
    {
        return Err(CkRv::FUNCTION_NOT_SUPPORTED);
    }
    if depth > 1 {
        return Err(CkRv::FUNCTION_NOT_SUPPORTED);
    }
    Ok(CkAttributeQueryResult {
        apply_returned_len,
        apply_type,
        attr_type: CkAttributeType(result.attr_type),
        returned_len: result.returned_len,
        value: result.value.clone().map(SecretBytes::new),
        ck_rv: result.ck_rv.map(CkRv),
        nested: result
            .nested
            .as_ref()
            .map(|list| {
                list.results
                    .iter()
                    .map(|sub| decode_attribute_result(sub, depth + 1))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?,
    })
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

    #[test]
    fn exact_effect_legacy_or_missing_ack_is_rejected_without_writeback() {
        let legacy = v1_proto::OutputBufferResult {
            ck_rv: CkRv::DEVICE_ERROR.0,
            returned_len: 0,
            value: None,
            apply_returned_len: None,
        };
        assert!(
            CkOutputBufferResult::try_from(&legacy).is_err(),
            "absence is not an effects acknowledgement"
        );
    }

    #[test]
    fn exact_effect_wire_round_trip_distinguishes_absent_zero_and_all_ones() {
        for length in [None, Some(0), Some(u64::MAX)] {
            let original = CkOutputBufferResult {
                ck_rv: CkRv::DEVICE_ERROR,
                returned_len: length,
                value: None,
            };
            let wire = wire_round_trip(&v1_proto::OutputBufferResult::from(&original));
            assert_eq!(wire.apply_returned_len, Some(length.is_some()));
            assert_eq!(CkOutputBufferResult::try_from(&wire).unwrap(), original);
        }
    }

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
        let original = CkOutputBufferSpec {
            buffer_present: true,
            buffer_len: 4096,
            length_pointer_null: true,
        };
        let proto = v1_proto::OutputBufferSpec::from(&original);
        let back = CkOutputBufferSpec::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn output_buffer_spec_absent_length_pointer_field_decodes_false() {
        // Legacy wire bytes: field 1 = true, field 2 = 4096, no field 3.
        let decoded =
            v1_proto::OutputBufferSpec::decode(&[0x08, 0x01, 0x10, 0x80, 0x20][..]).unwrap();
        assert!(decoded.buffer_present);
        assert_eq!(decoded.buffer_len, 4096);
        assert!(!decoded.length_pointer_null);
        assert!(!CkOutputBufferSpec::from(&decoded).length_pointer_null);
    }

    #[test]
    fn exact_output_wire_round_trip_preserves_optional_empty_bytes() {
        let output = v1_proto::OutputBufferResult {
            apply_returned_len: Some(true),
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
            apply_returned_len: Some(true),
            apply_object_handle: Some(true),
            ck_rv: CkRv::OK.0,
            returned_len: 0,
            value: Some(Vec::new()),
            object_handle: 7,
        };
        assert_eq!(wire_round_trip(&output_and_handle).value, Some(Vec::new()));

        let attribute_result = v1_proto::AttributeQueryResult {
            apply_returned_len: Some(true),
            apply_type: Some(false),
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
            exact_output_effects_version: 1,
            client_context_id: "ctx".to_string(),
            session_handle: 11,
            function: byte_output_function_to_i32(ByteOutputFunction::Sign),
            output_spec: Some(v1_proto::OutputBufferSpec {
                buffer_present: true,
                buffer_len: 64,
                length_pointer_null: false,
            }),
            input_data: b"payload".to_vec(),
            mechanism: None,
            wrapping_key_handle: 0,
            key_handle: 0,
            input_data_null_len: None,
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
        let original = CkOutputBufferResult {
            ck_rv: CkRv::BUFFER_TOO_SMALL,
            returned_len: Some(512),
            value: None,
        };
        let proto = v1_proto::OutputBufferResult::from(&original);
        let back = CkOutputBufferResult::try_from(&proto).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn parameter_roundtrip_spec_round_trip_preserves_empty_value() {
        let original = CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: 0,
            value: Some(Vec::new().into()),
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
            value: Some(vec![1, 2, 3, 4, 5, 6, 7].into()),
        };
        let proto = v1_proto::ParameterRoundtripResult::from(&original);
        let back = CkParameterRoundtripResult::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn output_and_handle_result_round_trip() {
        let original = CkOutputAndHandleResult {
            ck_rv: CkRv::OK,
            returned_len: Some(3),
            value: Some(vec![0xAA, 0xBB, 0xCC].into()),
            object_handle: Some(CkObjectHandle(41)),
        };
        let proto = v1_proto::OutputAndHandleResult::from(&original);
        let back = CkOutputAndHandleResult::try_from(&proto).unwrap();
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
            apply_returned_len: true,
            apply_type: false,
            attr_type: CkAttributeType::VALUE,
            returned_len: u64::MAX,
            value: None,
            ck_rv: Some(CkRv::ATTRIBUTE_SENSITIVE),
            nested: Some(vec![CkAttributeQueryResult {
                apply_returned_len: true,
                apply_type: false,
                attr_type: CkAttributeType::LABEL,
                returned_len: 4,
                value: Some(b"test".to_vec().into()),
                ck_rv: None,
                nested: Some(vec![]),
            }]),
        };
        let proto = v1_proto::AttributeQueryResult::from(&original);
        let back = CkAttributeQueryResult::try_from(&proto).unwrap();
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
                apply_returned_len: true,
                apply_type: false,
                attr_type: CkAttributeType::VALUE,
                returned_len: 0,
                value: Some(Vec::new().into()),
                ck_rv: None,
                nested: None,
            },
            CkAttributeQueryResult {
                apply_returned_len: true,
                apply_type: false,
                attr_type: CkAttributeType::SUBJECT,
                returned_len: 12,
                value: None,
                ck_rv: Some(CkRv::ATTRIBUTE_TYPE_INVALID),
                nested: Some(vec![]),
            },
        ];
        let proto = attribute_query_results_to_proto(&original);
        let back = attribute_query_results_from_proto(&proto).unwrap();
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

    // ADR-0010 Scope 2: *_null_len companion field round-trip tests.

    #[test]
    fn byte_output_exact_request_null_len_roundtrip() {
        // T12: `ByteOutputExactRequest` is `ZeroizeOnDrop`; struct-update
        // syntax is forbidden — all fields are spelled out.
        let req = v1_proto::ByteOutputExactRequest {
            client_context_id: String::new(),
            session_handle: 0,
            function: 0,
            output_spec: None,
            input_data: Vec::new(),
            mechanism: None,
            wrapping_key_handle: 0,
            key_handle: 0,
            input_data_null_len: Some(42),
            exact_output_effects_version: 1,
        };
        let bytes = prost::Message::encode_to_vec(&req);
        let back = v1_proto::ByteOutputExactRequest::decode(&bytes[..]).unwrap();
        assert_eq!(back.input_data_null_len, Some(42));
        assert!(back.input_data.is_empty());
    }

    /// Decoding bytes encoded WITHOUT input_data_null_len (old-shim wire format)
    /// must yield None — verifies additive backward compatibility.
    #[test]
    fn decrypt_request_null_len_absent_on_old_wire() {
        // Encode a DecryptRequest that never had the null_len field.
        let old = v1_proto::DecryptRequest {
            client_context_id: "ctx".to_string(),
            session_handle: 1,
            encrypted_data: b"ciphertext".to_vec(),
            encrypted_data_null_len: None,
        };
        let bytes = prost::Message::encode_to_vec(&old);
        let decoded = v1_proto::DecryptRequest::decode(&bytes[..]).unwrap();
        assert_eq!(decoded.encrypted_data_null_len, None);
        assert_eq!(decoded.encrypted_data, b"ciphertext");
    }

    /// W1-C8-09 pin: the owned conversion moves each result's value
    /// allocation into the proto message without cloning — the output
    /// buffer is the same allocation, so the pointers must match exactly
    /// (top-level and nested).
    #[test]
    fn owned_attribute_result_conversion_moves_value_buffer_without_copy() {
        fn canary_result(
            value: Vec<u8>,
            nested: Option<Vec<CkAttributeQueryResult>>,
        ) -> CkAttributeQueryResult {
            CkAttributeQueryResult {
                apply_returned_len: true,
                apply_type: false,
                attr_type: CkAttributeType::VALUE,
                returned_len: value.len() as u64,
                value: Some(value.into()),
                ck_rv: None,
                nested,
            }
        }

        let nested = canary_result(vec![0xBBu8; 32], None);
        let nested_ptr =
            nested.value.as_ref().expect("nested canary").expose(|bytes| bytes.as_ptr());
        let original = canary_result(vec![0xAAu8; 64], Some(vec![nested]));
        let top_ptr = original.value.as_ref().expect("top canary").expose(|bytes| bytes.as_ptr());

        let proto = v1_proto::AttributeQueryResult::from(original);
        assert_eq!(
            proto.value.as_ref().expect("proto value").as_ptr(),
            top_ptr,
            "owned conversion must move the value allocation, not clone it"
        );
        let nested_proto = proto
            .nested
            .as_ref()
            .expect("proto nested")
            .results
            .first()
            .expect("one nested result");
        assert_eq!(
            nested_proto.value.as_ref().expect("nested proto value").as_ptr(),
            nested_ptr,
            "owned conversion must move nested value allocations too"
        );
    }

    /// Contrast pin: the borrowed `From<&CkAttributeQueryResult>` cannot
    /// move out of a borrow, so it must copy — equal bytes, distinct
    /// allocation, source still usable afterwards.
    #[test]
    fn borrowed_attribute_result_conversion_copies_value_buffer() {
        let original = CkAttributeQueryResult {
            apply_returned_len: true,
            apply_type: false,
            attr_type: CkAttributeType::VALUE,
            returned_len: 64,
            value: Some(vec![0xAAu8; 64].into()),
            ck_rv: None,
            nested: None,
        };
        let before = original.value.as_ref().expect("canary").expose(|bytes| bytes.as_ptr());
        let proto = v1_proto::AttributeQueryResult::from(&original);
        let after = proto.value.as_ref().expect("proto value");
        assert_eq!(after.as_slice(), &[0xAAu8; 64]);
        assert_ne!(
            after.as_ptr(),
            before,
            "borrowed conversion must copy (it cannot move out of a borrow)"
        );
        assert!(original.value.is_some(), "borrowed conversion must not consume the source");
    }

    #[test]
    fn null_len_present_with_zero_is_distinct_from_absent() {
        // NULL pointer with claimed length 0 is a real client input class; the
        // wire must distinguish Some(0) (NULL, len 0) from None (valid pointer).
        // T12: `ByteOutputExactRequest` is `ZeroizeOnDrop`; struct-update
        // syntax is forbidden — all fields are spelled out.
        let req = v1_proto::ByteOutputExactRequest {
            client_context_id: String::new(),
            session_handle: 0,
            function: 0,
            output_spec: None,
            input_data: Vec::new(),
            mechanism: None,
            wrapping_key_handle: 0,
            key_handle: 0,
            input_data_null_len: Some(0),
            exact_output_effects_version: 1,
        };
        let bytes = prost::Message::encode_to_vec(&req);
        let back = v1_proto::ByteOutputExactRequest::decode(&bytes[..]).unwrap();
        assert_eq!(back.input_data_null_len, Some(0));
    }
}
