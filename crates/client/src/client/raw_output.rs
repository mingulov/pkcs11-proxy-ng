//! Shared raw-output helpers for exact PKCS#11 caller-buffer semantics.

use crate::error::{MessageCallError, grpc_status_to_ck_rv};

use pkcs11_proxy_ng_proto::convert::message_params::validate_structured_wire_parameter;
use pkcs11_proxy_ng_proto::pkcs11_proxy_ng::v1 as v1_proto;
use pkcs11_proxy_ng_types::{
    ByteOutputFunction, CkAttribute, CkAttributeQuery, CkAttributeQueryResult, CkInBuf,
    CkMechanism, CkMechanismParams, CkObjectHandle, CkOutputAndHandleResult, CkOutputBufferResult,
    CkOutputBufferSpec, CkParameterRoundtripResult, CkParameterRoundtripSpec, CkRv,
    CkSessionHandle, ParameterOutputFunction,
};

use super::Pkcs11Client;

pub type ParameterOutputExactDecoded = (
    CkOutputBufferResult,
    CkParameterRoundtripResult,
    Option<pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
);

fn decode_parameter_output_exact_response(
    response: pkcs11_proxy_ng_proto::ParameterOutputExactResponse,
    output_spec: &CkOutputBufferSpec,
    parameter_spec: &CkParameterRoundtripSpec,
    request_parameter: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
    function: ParameterOutputFunction,
) -> Result<ParameterOutputExactDecoded, CkRv> {
    let output = response
        .output_result
        .as_ref()
        .map(CkOutputBufferResult::from)
        .ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
    let parameter = response
        .parameter_result
        .as_ref()
        .map(CkParameterRoundtripResult::from)
        .ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

    if output_spec.length_pointer_null && (output.returned_len != 0 || output.value.is_some()) {
        return Err(CkRv::FUNCTION_NOT_SUPPORTED);
    }

    let validates_memory = output.ck_rv == CkRv::OK || output.ck_rv == CkRv::BUFFER_TOO_SMALL;
    if validates_memory {
        let output_valid = if output_spec.length_pointer_null {
            output.returned_len == 0 && output.value.is_none()
        } else {
            match output.ck_rv {
                CkRv::OK if !output_spec.buffer_present => output.value.is_none(),
                CkRv::OK => output.value.as_ref().is_some_and(|value| {
                    value.len() as u64 == output.returned_len
                        && output.returned_len <= output_spec.buffer_len
                }),
                CkRv::BUFFER_TOO_SMALL if output_spec.buffer_present => {
                    output.value.is_none() && output.returned_len > output_spec.buffer_len
                }
                _ => false,
            }
        };
        let message_function = matches!(
            function,
            ParameterOutputFunction::EncryptMessage
                | ParameterOutputFunction::DecryptMessage
                | ParameterOutputFunction::SignMessage
                | ParameterOutputFunction::EncryptMessageNext
                | ParameterOutputFunction::DecryptMessageNext
                | ParameterOutputFunction::SignMessageNext
        );
        let parameter_valid = parameter.ck_rv == output.ck_rv
            && if message_function {
                parameter.returned_len == parameter_spec.buffer_len
                    && match (parameter_spec.buffer_present, parameter.value.as_ref()) {
                        (true, Some(value)) => value.is_empty(),
                        (false, None) => true,
                        _ => false,
                    }
            } else if output_spec.length_pointer_null {
                match (parameter_spec.buffer_present, parameter.value.as_ref()) {
                    (false, None) => parameter.returned_len == parameter_spec.buffer_len,
                    (true, Some(value)) => {
                        value.len() as u64 == parameter.returned_len
                            && parameter.returned_len <= parameter_spec.buffer_len
                    }
                    _ => false,
                }
            } else {
                match (output.ck_rv, parameter_spec.buffer_present, parameter.value.as_ref()) {
                    (CkRv::OK, false, None) => true,
                    (CkRv::OK, true, Some(value)) => {
                        value.len() as u64 == parameter.returned_len
                            && parameter.returned_len <= parameter_spec.buffer_len
                    }
                    (CkRv::BUFFER_TOO_SMALL, true, None) => {
                        parameter.returned_len > parameter_spec.buffer_len
                    }
                    _ => false,
                }
            };
        if !output_valid || !parameter_valid {
            return Err(CkRv::FUNCTION_NOT_SUPPORTED);
        }
    }

    let response_parameter = if validates_memory {
        match (request_parameter, response.message_parameter_out.as_ref()) {
            (Some(request), Some(wire)) => {
                request.validate_structured().map_err(|_| CkRv::FUNCTION_NOT_SUPPORTED)?;
                validate_structured_wire_parameter(wire)
                    .map_err(|_| CkRv::FUNCTION_NOT_SUPPORTED)?;
                let decoded =
                    pkcs11_proxy_ng_proto::convert::message_params::MessageParameter::try_from(
                        wire,
                    )
                    .map_err(|_| CkRv::FUNCTION_NOT_SUPPORTED)?;
                decoded.validate_structured().map_err(|_| CkRv::FUNCTION_NOT_SUPPORTED)?;
                if !request.same_layout_and_scalars(&decoded)
                    || (matches!(
                        function,
                        ParameterOutputFunction::DecryptMessage
                            | ParameterOutputFunction::DecryptMessageNext
                    ) && request != &decoded)
                {
                    return Err(CkRv::FUNCTION_NOT_SUPPORTED);
                }
                Some(decoded)
            }
            (None, None) => None,
            _ => return Err(CkRv::FUNCTION_NOT_SUPPORTED),
        }
    } else {
        None
    };

    Ok((output, parameter, response_parameter))
}

fn decode_parameter_output_exact_contract_response(
    response: pkcs11_proxy_ng_proto::ParameterOutputExactResponse,
    output_spec: &CkOutputBufferSpec,
    parameter_spec: &CkParameterRoundtripSpec,
    request_parameter: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
    function: ParameterOutputFunction,
) -> Result<ParameterOutputExactDecoded, MessageCallError> {
    let decoded = decode_parameter_output_exact_response(
        response,
        output_spec,
        parameter_spec,
        request_parameter,
        function,
    )
    .map_err(|_| MessageCallError::protocol())?;
    if !matches!(decoded.0.ck_rv, CkRv::OK | CkRv::BUFFER_TOO_SMALL) {
        return Err(MessageCallError::backend(decoded.0.ck_rv));
    }
    Ok(decoded)
}

// Task 2 stops at shared scaffolding; Task 3 wires these helpers into concrete RPCs.
impl Pkcs11Client {
    #[allow(dead_code)]
    pub(crate) fn proto_output_buffer_spec(
        spec: &CkOutputBufferSpec,
    ) -> v1_proto::OutputBufferSpec {
        spec.into()
    }

    #[allow(dead_code)]
    pub(crate) fn proto_parameter_roundtrip_spec(
        spec: &CkParameterRoundtripSpec,
    ) -> v1_proto::ParameterRoundtripSpec {
        spec.into()
    }

    pub(crate) fn proto_attribute_queries(
        queries: &[CkAttributeQuery],
    ) -> Vec<v1_proto::AttributeQuery> {
        queries.iter().map(v1_proto::AttributeQuery::from).collect()
    }

    #[allow(dead_code)]
    pub(crate) fn output_buffer_result_from_proto(
        result: &v1_proto::OutputBufferResult,
    ) -> CkOutputBufferResult {
        result.into()
    }

    #[allow(dead_code)]
    pub(crate) fn parameter_roundtrip_result_from_proto(
        result: &v1_proto::ParameterRoundtripResult,
    ) -> CkParameterRoundtripResult {
        result.into()
    }

    #[allow(dead_code)]
    pub(crate) fn output_and_handle_result_from_proto(
        result: &v1_proto::OutputAndHandleResult,
    ) -> CkOutputAndHandleResult {
        result.into()
    }

    pub(crate) fn attribute_query_results_from_proto(
        results: &[v1_proto::AttributeQueryResult],
    ) -> Vec<CkAttributeQueryResult> {
        results.iter().map(CkAttributeQueryResult::from).collect()
    }

    pub async fn get_attribute_value_exact(
        &mut self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        queries: &[CkAttributeQuery],
    ) -> Result<(CkRv, Vec<CkAttributeQueryResult>), CkRv> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::GetAttributeValueExactRequest {
            client_context_id: ctx,
            session_handle: session.0,
            object_handle: object.0,
            queries: Self::proto_attribute_queries(queries),
        };
        let resp = self
            .grpc
            .get_attribute_value_exact(req)
            .await
            .map_err(|status| grpc_status_to_ck_rv(status.code(), true))?
            .into_inner();
        Ok((CkRv(resp.ck_rv), Self::attribute_query_results_from_proto(&resp.results)))
    }

    /// Send a `ParameterOutputExact` RPC for any of the 7 parameter-output functions.
    #[allow(clippy::too_many_arguments)]
    pub async fn parameter_output_exact_contract(
        &mut self,
        session: CkSessionHandle,
        function: ParameterOutputFunction,
        output_spec: &CkOutputBufferSpec,
        input_data: CkInBuf<'_>,
        associated_data: CkInBuf<'_>,
        parameter: &[u8],
        param_out_spec: &CkParameterRoundtripSpec,
        flags: u64,
        mechanism: Option<&CkMechanism>,
        wrapping_key_handle: u64,
        key_handle: u64,
        message_parameter: Option<
            &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        >,
    ) -> Result<
        (
            CkOutputBufferResult,
            CkParameterRoundtripResult,
            Option<pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        ),
        MessageCallError,
    > {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let mut req = pkcs11_proxy_ng_proto::ParameterOutputExactRequest {
            client_context_id: ctx,
            session_handle: session.0,
            function: pkcs11_proxy_ng_proto::convert::output::parameter_output_function_to_i32(
                function,
            ),
            output_spec: Some(Self::proto_output_buffer_spec(output_spec)),
            input_data: Vec::new(),
            associated_data: Vec::new(),
            parameter: parameter.to_vec(),
            parameter_out_spec: Some(Self::proto_parameter_roundtrip_spec(param_out_spec)),
            flags,
            mechanism: mechanism.map(pkcs11_proxy_ng_proto::Mechanism::from),
            wrapping_key_handle,
            key_handle,
            message_parameter: message_parameter.map(pkcs11_proxy_ng_proto::MessageParameter::from),
            input_data_null_len: None,
            associated_data_null_len: None,
        };
        Self::fill_input(input_data, &mut req.input_data, &mut req.input_data_null_len);
        Self::fill_input(
            associated_data,
            &mut req.associated_data,
            &mut req.associated_data_null_len,
        );
        let resp = self
            .grpc
            .parameter_output_exact(req)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_parameter_output_exact_contract_response(
            resp,
            output_spec,
            param_out_spec,
            message_parameter,
            function,
        )
    }

    /// Backward-compatible exact-output surface for non-stateful callers.
    /// Message-stateful C-ABI paths use `parameter_output_exact_contract` so
    /// transport/protocol ambiguity is not inferred from a flattened CK_RV.
    #[allow(clippy::too_many_arguments)]
    pub async fn parameter_output_exact(
        &mut self,
        session: CkSessionHandle,
        function: ParameterOutputFunction,
        output_spec: &CkOutputBufferSpec,
        input_data: CkInBuf<'_>,
        associated_data: CkInBuf<'_>,
        parameter: &[u8],
        param_out_spec: &CkParameterRoundtripSpec,
        flags: u64,
        mechanism: Option<&CkMechanism>,
        wrapping_key_handle: u64,
        key_handle: u64,
        message_parameter: Option<
            &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        >,
    ) -> Result<ParameterOutputExactDecoded, CkRv> {
        self.parameter_output_exact_contract(
            session,
            function,
            output_spec,
            input_data,
            associated_data,
            parameter,
            param_out_spec,
            flags,
            mechanism,
            wrapping_key_handle,
            key_handle,
            message_parameter,
        )
        .await
        .map_err(|error| error.ck_rv)
    }

    /// Send an `EncapsulateKeyExact` RPC for KEM encapsulation with exact output semantics.
    pub async fn encapsulate_key_exact(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        public_key: CkObjectHandle,
        template: &[CkAttribute],
        spec: &CkOutputBufferSpec,
    ) -> Result<CkOutputAndHandleResult, CkRv> {
        let ctx = self.context_id()?;
        let proto_template: Vec<pkcs11_proxy_ng_proto::Attribute> =
            template.iter().map(pkcs11_proxy_ng_proto::Attribute::from).collect();
        let req = pkcs11_proxy_ng_proto::EncapsulateKeyExactRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(pkcs11_proxy_ng_proto::Mechanism::from(mechanism)),
            public_key_handle: public_key.0,
            template: proto_template,
            output_spec: Some(Self::proto_output_buffer_spec(spec)),
        };
        let resp = self
            .grpc
            .encapsulate_key_exact(req)
            .await
            .map_err(|status| grpc_status_to_ck_rv(status.code(), true))?
            .into_inner();
        match resp.result {
            Some(ref result) => Ok(Self::output_and_handle_result_from_proto(result)),
            None => Err(CkRv::FUNCTION_NOT_SUPPORTED),
        }
    }

    /// Serialize a `CkInBuf` into the two wire fields of `ByteOutputExactRequest`.
    ///
    /// When the caller holds `Bytes(b)`, the bytes are placed in `input_data`
    /// and `input_data_null_len` is left `None`.  When the caller holds
    /// `Null { len }` (a NULL pointer with a claimed length), the bytes field
    /// is left empty and `input_data_null_len` is set to `Some(len)` so the
    /// server can reconstruct the original pointer class faithfully.
    pub(crate) fn fill_input(
        data: CkInBuf<'_>,
        bytes_field: &mut Vec<u8>,
        null_len_field: &mut Option<u64>,
    ) {
        match data {
            CkInBuf::Bytes(b) => {
                *bytes_field = b.to_vec();
                *null_len_field = None;
            }
            CkInBuf::Null { len } => {
                bytes_field.clear();
                *null_len_field = Some(len);
            }
        }
    }

    /// Send a `ByteOutputExact` RPC for any of the 18 byte-output functions.
    pub async fn byte_output_exact(
        &mut self,
        session: CkSessionHandle,
        function: ByteOutputFunction,
        spec: &CkOutputBufferSpec,
        input_data: CkInBuf<'_>,
        mechanism: Option<&CkMechanism>,
        wrapping_key_handle: u64,
        key_handle: u64,
    ) -> Result<CkOutputBufferResult, CkRv> {
        let (result, _) = self
            .byte_output_exact_with_mechanism_out(
                session,
                function,
                spec,
                input_data,
                mechanism,
                wrapping_key_handle,
                key_handle,
            )
            .await?;
        Ok(result)
    }

    pub async fn byte_output_exact_with_mechanism_out(
        &mut self,
        session: CkSessionHandle,
        function: ByteOutputFunction,
        spec: &CkOutputBufferSpec,
        input_data: CkInBuf<'_>,
        mechanism: Option<&CkMechanism>,
        wrapping_key_handle: u64,
        key_handle: u64,
    ) -> Result<(CkOutputBufferResult, Option<CkMechanismParams>), CkRv> {
        let ctx = self.context_id()?;
        let mut input_bytes = Vec::new();
        let mut input_null_len = None;
        Self::fill_input(input_data, &mut input_bytes, &mut input_null_len);
        let req = pkcs11_proxy_ng_proto::ByteOutputExactRequest {
            client_context_id: ctx,
            session_handle: session.0,
            function: pkcs11_proxy_ng_proto::convert::output::byte_output_function_to_i32(function),
            output_spec: Some(Self::proto_output_buffer_spec(spec)),
            input_data: input_bytes,
            mechanism: mechanism.map(pkcs11_proxy_ng_proto::Mechanism::from),
            wrapping_key_handle,
            key_handle,
            input_data_null_len: input_null_len,
        };
        let resp = self
            .grpc
            .byte_output_exact(req)
            .await
            .map_err(|status| grpc_status_to_ck_rv(status.code(), true))?
            .into_inner();
        let mechanism_out = match resp.mechanism_out {
            Some(proto_mech) => CkMechanism::try_from(&proto_mech)?.params,
            None => None,
        };
        match resp.result {
            Some(result) => Ok((Self::output_buffer_result_from_proto(&result), mechanism_out)),
            None => Err(CkRv::FUNCTION_NOT_SUPPORTED),
        }
    }
}

#[cfg(test)]
mod message_contract_tests {
    use super::*;
    use pkcs11_proxy_ng_proto::convert::message_params::{
        CcmMessageParams, GcmMessageParams, MessageParameter,
    };

    fn gcm_parameter() -> MessageParameter {
        MessageParameter::GcmMessage(GcmMessageParams {
            iv: vec![0x11; 12],
            iv_null_len: None,
            iv_fixed_bits: 96,
            iv_generator: 0,
            tag: vec![0; 16],
            tag_null_len: None,
            tag_bits: 128,
        })
    }

    fn ccm_parameter() -> MessageParameter {
        MessageParameter::CcmMessage(CcmMessageParams {
            data_len: 32,
            nonce: vec![0x22; 12],
            nonce_null_len: None,
            nonce_fixed_bits: 96,
            nonce_generator: 0,
            mac: vec![0; 16],
            mac_null_len: None,
            mac_len: 16,
        })
    }

    #[test]
    fn null_output_length_accepts_only_canonical_main_envelope_and_exact_rv() {
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true };
        let parameter_spec =
            CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None };
        let response = |returned_len, value| pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                ck_rv: CkRv::ARGUMENTS_BAD.0,
                returned_len,
                value,
            }),
            parameter_result: Some(pkcs11_proxy_ng_proto::ParameterRoundtripResult {
                ck_rv: CkRv::ARGUMENTS_BAD.0,
                returned_len: 0,
                value: None,
            }),
            message_parameter_out: None,
        };

        let (output, _, _) = decode_parameter_output_exact_response(
            response(0, None),
            &output_spec,
            &parameter_spec,
            None,
            ParameterOutputFunction::WrapKeyAuthenticated,
        )
        .expect("canonical missing-length envelope");
        assert_eq!(output.ck_rv, CkRv::ARGUMENTS_BAD);
        assert_eq!(
            decode_parameter_output_exact_response(
                response(1, None),
                &output_spec,
                &parameter_spec,
                None,
                ParameterOutputFunction::WrapKeyAuthenticated,
            ),
            Err(CkRv::FUNCTION_NOT_SUPPORTED),
        );
        assert_eq!(
            decode_parameter_output_exact_response(
                response(0, Some(Vec::new())),
                &output_spec,
                &parameter_spec,
                None,
                ParameterOutputFunction::WrapKeyAuthenticated,
            ),
            Err(CkRv::FUNCTION_NOT_SUPPORTED),
        );
    }

    #[test]
    fn null_output_length_ok_preserves_genuine_parameter_output() {
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true };
        let parameter_spec =
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 3, value: None };
        let response = pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                ck_rv: CkRv::OK.0,
                returned_len: 0,
                value: None,
            }),
            parameter_result: Some(pkcs11_proxy_ng_proto::ParameterRoundtripResult {
                ck_rv: CkRv::OK.0,
                returned_len: 3,
                value: Some(vec![1, 0xA5, 3]),
            }),
            message_parameter_out: None,
        };

        let (_, parameter, _) = decode_parameter_output_exact_response(
            response,
            &output_spec,
            &parameter_spec,
            None,
            ParameterOutputFunction::WrapKeyAuthenticated,
        )
        .expect("genuine parameter output");
        assert_eq!(parameter.value, Some(vec![1, 0xA5, 3]));
    }

    #[test]
    fn null_output_length_buffer_too_small_preserves_genuine_parameter_output() {
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true };
        let parameter_spec =
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 3, value: None };
        let response = pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                ck_rv: CkRv::BUFFER_TOO_SMALL.0,
                returned_len: 0,
                value: None,
            }),
            parameter_result: Some(pkcs11_proxy_ng_proto::ParameterRoundtripResult {
                ck_rv: CkRv::BUFFER_TOO_SMALL.0,
                returned_len: 3,
                value: Some(vec![1, 0xA5, 3]),
            }),
            message_parameter_out: None,
        };

        let (output, parameter, _) = decode_parameter_output_exact_response(
            response,
            &output_spec,
            &parameter_spec,
            None,
            ParameterOutputFunction::WrapKeyAuthenticated,
        )
        .expect("canonical buffer-too-small response");

        assert_eq!(output.ck_rv, CkRv::BUFFER_TOO_SMALL);
        assert_eq!(parameter.ck_rv, CkRv::BUFFER_TOO_SMALL);
        assert_eq!(parameter.value, Some(vec![1, 0xA5, 3]));
    }

    #[test]
    fn old_server_missing_parameter_ack_on_b2s_is_rejected() {
        let request = gcm_parameter();
        let response = pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                ck_rv: CkRv::BUFFER_TOO_SMALL.0,
                returned_len: 8,
                value: None,
            }),
            parameter_result: None,
            message_parameter_out: Some((&request).into()),
        };
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 4, length_pointer_null: false };
        let parameter_spec =
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 48, value: None };

        let error = decode_parameter_output_exact_response(
            response,
            &output_spec,
            &parameter_spec,
            Some(&request),
            ParameterOutputFunction::EncryptMessage,
        )
        .unwrap_err();

        assert_eq!(error, CkRv::FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn exact_contract_rejects_outer_pointer_class_or_length_mutation() {
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 1, length_pointer_null: false };
        for parameter_spec in [
            CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None },
            CkParameterRoundtripSpec { buffer_present: false, buffer_len: 7, value: None },
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 0, value: None },
        ] {
            let acknowledged = pkcs11_proxy_ng_proto::ParameterRoundtripResult {
                ck_rv: CkRv::OK.0,
                returned_len: parameter_spec.buffer_len,
                value: parameter_spec.buffer_present.then(Vec::new),
            };
            let mut wrong_class = acknowledged.clone();
            wrong_class.value = if parameter_spec.buffer_present { None } else { Some(Vec::new()) };
            let mut wrong_len = acknowledged.clone();
            wrong_len.returned_len += 1;

            for (label, parameter_result) in [("pointer class", wrong_class), ("length", wrong_len)]
            {
                let response = pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
                    output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                        ck_rv: CkRv::OK.0,
                        returned_len: 1,
                        value: Some(vec![0x31]),
                    }),
                    parameter_result: Some(parameter_result),
                    message_parameter_out: None,
                };
                let error = decode_parameter_output_exact_response(
                    response,
                    &output_spec,
                    &parameter_spec,
                    None,
                    ParameterOutputFunction::EncryptMessage,
                )
                .unwrap_err();
                assert_eq!(error, CkRv::FUNCTION_NOT_SUPPORTED, "{label} for {parameter_spec:?}",);
            }
        }
    }

    #[test]
    fn exact_contract_rejects_raw_malformed_or_wrong_variant_response() {
        let request = gcm_parameter();
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 4, length_pointer_null: false };
        let parameter_spec =
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 48, value: None };
        let responses = [
            ("malformed oneof", pkcs11_proxy_ng_proto::MessageParameter { params: None }),
            (
                "raw empty",
                pkcs11_proxy_ng_proto::MessageParameter {
                    params: Some(pkcs11_proxy_ng_proto::message_parameter::Params::Raw(Vec::new())),
                },
            ),
            (
                "raw nonempty",
                pkcs11_proxy_ng_proto::MessageParameter {
                    params: Some(pkcs11_proxy_ng_proto::message_parameter::Params::Raw(vec![0xA5])),
                },
            ),
            ("wrong structured variant", (&ccm_parameter()).into()),
        ];

        for (label, message_parameter_out) in responses {
            let response = pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
                output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                    ck_rv: CkRv::OK.0,
                    returned_len: 4,
                    value: Some(vec![1, 2, 3, 4]),
                }),
                parameter_result: Some(pkcs11_proxy_ng_proto::ParameterRoundtripResult {
                    ck_rv: CkRv::OK.0,
                    returned_len: parameter_spec.buffer_len,
                    value: Some(Vec::new()),
                }),
                message_parameter_out: Some(message_parameter_out),
            };
            let error = decode_parameter_output_exact_response(
                response,
                &output_spec,
                &parameter_spec,
                Some(&request),
                ParameterOutputFunction::EncryptMessage,
            )
            .unwrap_err();
            assert_eq!(error, CkRv::FUNCTION_NOT_SUPPORTED, "{label}");
        }
    }

    #[test]
    fn completed_parameter_output_error_retains_backend_origin() {
        let response = pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                ck_rv: CkRv::FUNCTION_FAILED.0,
                returned_len: 0,
                value: None,
            }),
            parameter_result: Some(pkcs11_proxy_ng_proto::ParameterRoundtripResult {
                ck_rv: CkRv::FUNCTION_FAILED.0,
                returned_len: 0,
                value: None,
            }),
            message_parameter_out: None,
        };
        let error = decode_parameter_output_exact_contract_response(
            response,
            &CkOutputBufferSpec {
                buffer_present: false,
                buffer_len: 0,
                length_pointer_null: false,
            },
            &CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None },
            None,
            ParameterOutputFunction::EncryptMessage,
        )
        .unwrap_err();

        assert_eq!(error.origin, crate::error::MessageCallErrorOrigin::Backend);
        assert_eq!(error.ck_rv, CkRv::FUNCTION_FAILED);
    }

    #[test]
    fn authenticated_wrap_accepts_actual_mechanism_parameter_length() {
        let response = pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                ck_rv: CkRv::OK.0,
                returned_len: 8,
                value: None,
            }),
            parameter_result: Some(pkcs11_proxy_ng_proto::ParameterRoundtripResult {
                ck_rv: CkRv::OK.0,
                returned_len: 0,
                value: Some(Vec::new()),
            }),
            message_parameter_out: None,
        };
        let output_spec =
            CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: false };
        let parameter_spec =
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 16, value: None };

        let (_, parameter, message) = decode_parameter_output_exact_response(
            response,
            &output_spec,
            &parameter_spec,
            None,
            ParameterOutputFunction::WrapKeyAuthenticated,
        )
        .expect("actual mechanism parameter size within caller capacity is valid");

        assert_eq!(parameter.returned_len, 0);
        assert_eq!(parameter.value, Some(Vec::new()));
        assert!(message.is_none());
    }
}
