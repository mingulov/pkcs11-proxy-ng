//! Shared raw-output helpers for exact PKCS#11 caller-buffer semantics.

use crate::error::grpc_status_to_ck_rv;

use pkcs11_proxy_ng_proto::pkcs11_proxy_ng::v1 as v1_proto;
use pkcs11_proxy_ng_types::{
    ByteOutputFunction, CkAttribute, CkAttributeQuery, CkAttributeQueryResult, CkMechanism,
    CkMechanismParams, CkObjectHandle, CkOutputAndHandleResult, CkOutputBufferResult,
    CkOutputBufferSpec, CkParameterRoundtripResult, CkParameterRoundtripSpec, CkRv,
    CkSessionHandle, ParameterOutputFunction,
};

use super::Pkcs11Client;

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
    pub async fn parameter_output_exact(
        &mut self,
        session: CkSessionHandle,
        function: ParameterOutputFunction,
        output_spec: &CkOutputBufferSpec,
        input_data: &[u8],
        associated_data: &[u8],
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
        CkRv,
    > {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::ParameterOutputExactRequest {
            client_context_id: ctx,
            session_handle: session.0,
            function: pkcs11_proxy_ng_proto::convert::output::parameter_output_function_to_i32(
                function,
            ),
            output_spec: Some(Self::proto_output_buffer_spec(output_spec)),
            input_data: input_data.to_vec(),
            associated_data: associated_data.to_vec(),
            parameter: parameter.to_vec(),
            parameter_out_spec: Some(Self::proto_parameter_roundtrip_spec(param_out_spec)),
            flags,
            mechanism: mechanism.map(pkcs11_proxy_ng_proto::Mechanism::from),
            wrapping_key_handle,
            key_handle,
            message_parameter: message_parameter.map(pkcs11_proxy_ng_proto::MessageParameter::from),
        };
        let resp = self
            .grpc
            .parameter_output_exact(req)
            .await
            .map_err(|status| grpc_status_to_ck_rv(status.code(), true))?
            .into_inner();
        let output_result = match resp.output_result {
            Some(ref result) => Self::output_buffer_result_from_proto(result),
            None => return Err(CkRv::FUNCTION_NOT_SUPPORTED),
        };
        let param_result = match resp.parameter_result {
            Some(ref result) => Self::parameter_roundtrip_result_from_proto(result),
            None => return Err(CkRv::FUNCTION_NOT_SUPPORTED),
        };
        let msg_param_out = resp.message_parameter_out.as_ref().and_then(|mp| {
            pkcs11_proxy_ng_proto::convert::message_params::MessageParameter::try_from(mp).ok()
        });
        Ok((output_result, param_result, msg_param_out))
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

    /// Send a `ByteOutputExact` RPC for any of the 18 byte-output functions.
    pub async fn byte_output_exact(
        &mut self,
        session: CkSessionHandle,
        function: ByteOutputFunction,
        spec: &CkOutputBufferSpec,
        input_data: &[u8],
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
        input_data: &[u8],
        mechanism: Option<&CkMechanism>,
        wrapping_key_handle: u64,
        key_handle: u64,
    ) -> Result<(CkOutputBufferResult, Option<CkMechanismParams>), CkRv> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::ByteOutputExactRequest {
            client_context_id: ctx,
            session_handle: session.0,
            function: pkcs11_proxy_ng_proto::convert::output::byte_output_function_to_i32(function),
            output_spec: Some(Self::proto_output_buffer_spec(spec)),
            input_data: input_data.to_vec(),
            mechanism: mechanism.map(pkcs11_proxy_ng_proto::Mechanism::from),
            wrapping_key_handle,
            key_handle,
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
