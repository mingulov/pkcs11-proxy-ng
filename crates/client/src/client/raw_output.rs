//! Shared raw-output helpers for exact PKCS#11 caller-buffer semantics.

use crate::error::{MessageCallError, grpc_status_to_ck_rv};
use pkcs11_proxy_ng_proto::convert::message_effects::ParameterEffectCallMode;

use pkcs11_proxy_ng_proto::pkcs11_proxy_ng::v1 as v1_proto;
use pkcs11_proxy_ng_proto::version::exact_output_effects_version_supported;
use pkcs11_proxy_ng_types::{
    ByteOutputFunction, CkAttribute, CkAttributeQuery, CkAttributeQueryResult, CkFlags, CkInBuf,
    CkMechanism, CkMechanismParams, CkObjectHandle, CkOutputAndHandleResult, CkOutputBufferResult,
    CkOutputBufferSpec, CkParameterRoundtripResult, CkParameterRoundtripSpec, CkRv,
    CkSessionHandle, ParameterOutputFunction, SecretBytes,
};

use super::Pkcs11Client;
use pkcs11_proxy_ng_proto::convert::message_effects::{MessageEffectContext, MessageEffects};
use pkcs11_proxy_ng_proto::convert::message_params::MessageParameter;

pub type ParameterOutputExactDecoded =
    (CkOutputBufferResult, CkParameterRoundtripResult, Option<MessageEffects>);

fn decode_parameter_output_exact_response(
    mut response: pkcs11_proxy_ng_proto::ParameterOutputExactResponse,
    output_spec: &CkOutputBufferSpec,
    parameter_spec: &CkParameterRoundtripSpec,
    request_parameter: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
    function: ParameterOutputFunction,
    flags: u64,
) -> Result<ParameterOutputExactDecoded, CkRv> {
    // T13: adopt the owned result buffers instead of cloning them. The
    // effects part stays borrowed (its project type is not a wiping
    // owner and is outside the T13 conversion scope).
    let output = response
        .output_result
        .take()
        .map(pkcs11_proxy_ng_proto::convert::output::output_buffer_result_from_owned)
        .transpose()?
        .ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
    let parameter = response
        .parameter_result
        .take()
        .map(pkcs11_proxy_ng_proto::convert::output::parameter_roundtrip_result_from_owned)
        .ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

    output.validate_for(output_spec, u64::MAX).map_err(|_| CkRv::FUNCTION_NOT_SUPPORTED)?;
    let validates_memory = output.ck_rv == CkRv::OK || output.ck_rv == CkRv::BUFFER_TOO_SMALL;
    if response.message_parameter_out.is_some() || response.authenticated_output.is_some() {
        return Err(CkRv::FUNCTION_NOT_SUPPORTED);
    }
    let no_effect_failure = !validates_memory
        && output.returned_len.is_none()
        && output.value.is_none()
        && response.message_effects.is_none()
        && parameter.returned_len == 0
        && parameter.value.is_none();
    if no_effect_failure {
        if parameter.ck_rv != output.ck_rv
            || parameter.returned_len != 0
            || parameter.value.is_some()
        {
            return Err(CkRv::FUNCTION_NOT_SUPPORTED);
        }
        return Ok((output, parameter, None));
    }
    let valid_parameter = if function == ParameterOutputFunction::WrapKeyAuthenticated {
        parameter.returned_len <= parameter_spec.buffer_len
            && parameter.value.as_ref().is_none_or(|bytes| {
                parameter_spec.buffer_present && bytes.len() as u64 == parameter.returned_len
            })
    } else {
        parameter.returned_len == parameter_spec.buffer_len
            && parameter.value == parameter_spec.buffer_present.then(SecretBytes::default)
    };
    if parameter.ck_rv != output.ck_rv || !valid_parameter {
        return Err(CkRv::FUNCTION_NOT_SUPPORTED);
    }
    let response_parameter = match (request_parameter, response.message_effects.as_ref()) {
        (Some(request), Some(wire)) => {
            // R5/F1 (controller ruling): the R3 None-effects wire signal
            // (`message_effects: Some(empty)`) decodes to
            // `MessageEffects::None` for a `Raw` request only — a
            // Raw request exists solely on the v1 path, so no legacy
            // exchange can present this pair. Every other
            // `(request, Some(empty))` combination keeps flowing through
            // the unchanged `TryFrom`, which rejects the empty oneof
            // with `ARGUMENTS_BAD`.
            let effects = match (request, wire.effect.as_ref()) {
                (MessageParameter::Raw(_), None) => MessageEffects::None,
                _ => MessageEffects::try_from(wire)?,
            };
            effects
                .validate_for(
                    request,
                    MessageEffectContext {
                        mode: ParameterEffectCallMode::from_output_spec(output_spec),
                        encrypt: matches!(
                            function,
                            ParameterOutputFunction::EncryptMessage
                                | ParameterOutputFunction::EncryptMessageNext
                        ),
                        generated_stage: matches!(
                            function,
                            ParameterOutputFunction::EncryptMessage
                                | ParameterOutputFunction::DecryptMessage
                        ),
                        auth_stage: matches!(
                            function,
                            ParameterOutputFunction::EncryptMessage
                                | ParameterOutputFunction::DecryptMessage
                        ) || flags & CkFlags::END_OF_MESSAGE.0 != 0,
                        rv: output.ck_rv,
                    },
                )
                .map_err(|_| CkRv::FUNCTION_NOT_SUPPORTED)?;
            Some(effects)
        }
        (None, None) => None,
        _ => return Err(CkRv::FUNCTION_NOT_SUPPORTED),
    };

    Ok((output, parameter, response_parameter))
}

fn decode_parameter_output_exact_contract_response(
    response: pkcs11_proxy_ng_proto::ParameterOutputExactResponse,
    output_spec: &CkOutputBufferSpec,
    parameter_spec: &CkParameterRoundtripSpec,
    request_parameter: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
    function: ParameterOutputFunction,
    flags: u64,
) -> Result<ParameterOutputExactDecoded, MessageCallError> {
    let decoded = decode_parameter_output_exact_response(
        response,
        output_spec,
        parameter_spec,
        request_parameter,
        function,
        flags,
    )
    .map_err(|_| MessageCallError::protocol())?;
    Ok(decoded)
}

impl Pkcs11Client {
    pub(crate) async fn require_exact_output_effects(&mut self) -> Result<(), CkRv> {
        // W1-L5-04: compatibility-range gates, never equality literals. An
        // absent probe version (legacy daemon) still fails closed here —
        // only the init negotiation (W1-L5-05) treats absence as v1.
        if !exact_output_effects_version_supported(
            self.exact_effects_version.load(std::sync::atomic::Ordering::Acquire),
        ) {
            let probe =
                self.get_backend_interfaces().await.map_err(|_| CkRv::FUNCTION_NOT_SUPPORTED)?;
            if !probe
                .exact_output_effects_version
                .is_some_and(exact_output_effects_version_supported)
            {
                return Err(CkRv::FUNCTION_NOT_SUPPORTED);
            }
        }
        Ok(())
    }
    pub(crate) fn proto_output_buffer_spec(
        spec: &CkOutputBufferSpec,
    ) -> v1_proto::OutputBufferSpec {
        spec.into()
    }

    pub(crate) fn proto_parameter_roundtrip_spec(
        spec: &CkParameterRoundtripSpec,
    ) -> v1_proto::ParameterRoundtripSpec {
        spec.into()
    }

    /// Encode an optional message parameter for the wire under this
    /// connection's cached transport capability (R5/F1): v1-opaque at
    /// ≥ 1, bit-identical legacy encoding otherwise. A value the v1
    /// encoding cannot represent (over the 64 KiB outer cap) fails HERE
    /// with a backend-origin `MECHANISM_PARAM_INVALID` — the caller's `?`
    /// emits no RPC.
    pub(crate) fn proto_message_parameter(
        &self,
        parameter: Option<&MessageParameter>,
    ) -> Result<Option<v1_proto::MessageParameter>, MessageCallError> {
        parameter
            .map(|value| {
                value.to_wire_with_transport_version(self.mechanism_parameter_transport_version())
            })
            .transpose()
            .map_err(MessageCallError::backend)
    }

    pub(crate) fn proto_attribute_queries(
        queries: &[CkAttributeQuery],
    ) -> Vec<v1_proto::AttributeQuery> {
        queries.iter().map(v1_proto::AttributeQuery::from).collect()
    }

    pub(crate) fn attribute_query_results_from_owned(
        results: Vec<v1_proto::AttributeQueryResult>,
    ) -> Result<Vec<CkAttributeQueryResult>, CkRv> {
        results
            .into_iter()
            .map(pkcs11_proxy_ng_proto::convert::output::attribute_query_result_from_owned)
            .collect()
    }

    pub async fn get_attribute_value_exact(
        &mut self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        queries: &[CkAttributeQuery],
    ) -> Result<(CkRv, Vec<CkAttributeQueryResult>), CkRv> {
        self.require_exact_output_effects().await?;
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::GetAttributeValueExactRequest {
            exact_output_effects_version: 1,
            client_context_id: ctx,
            session_handle: session.0,
            object_handle: object.0,
            queries: Self::proto_attribute_queries(queries),
        };
        // T13: adopt the owned results instead of cloning them.
        let mut resp = self
            .grpc
            .get_attribute_value_exact(req)
            .await
            .map_err(|status| grpc_status_to_ck_rv(status.code(), true))?
            .into_inner();
        if !exact_output_effects_version_supported(resp.exact_output_effects_version) {
            return Err(CkRv::FUNCTION_NOT_SUPPORTED);
        }
        let ck_rv = CkRv(resp.ck_rv);
        Ok((ck_rv, Self::attribute_query_results_from_owned(std::mem::take(&mut resp.results))?))
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
        (CkOutputBufferResult, CkParameterRoundtripResult, Option<MessageEffects>),
        MessageCallError,
    > {
        self.require_exact_output_effects().await.map_err(|_| MessageCallError::protocol())?;
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        if function == ParameterOutputFunction::WrapKeyAuthenticated
            && mechanism.is_some_and(|m| {
                !pkcs11_proxy_ng_proto::convert::authenticated::legacy_parameter_supported(m)
            })
        {
            return Err(MessageCallError::backend(CkRv::FUNCTION_NOT_SUPPORTED));
        }
        let mut req = pkcs11_proxy_ng_proto::ParameterOutputExactRequest {
            exact_output_effects_version: 1,
            authenticated_parameters: None,
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
            mechanism: mechanism
                .map(|m| self.proto_mechanism(m))
                .transpose()
                .map_err(MessageCallError::backend)?,
            wrapping_key_handle,
            key_handle,
            message_parameter: self.proto_message_parameter(message_parameter)?,
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
            flags,
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
        template: Option<&[CkAttribute]>,
        spec: &CkOutputBufferSpec,
    ) -> Result<CkOutputAndHandleResult, CkRv> {
        self.require_exact_output_effects().await?;
        let ctx = self.context_id()?;
        let proto_template: Vec<pkcs11_proxy_ng_proto::Attribute> =
            template.unwrap_or(&[]).iter().map(pkcs11_proxy_ng_proto::Attribute::from).collect();
        let req = pkcs11_proxy_ng_proto::EncapsulateKeyExactRequest {
            exact_output_effects_version: 1,
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(self.proto_mechanism(mechanism)?),
            public_key_handle: public_key.0,
            template: proto_template,
            template_null: template.is_none(),
            output_spec: Some(Self::proto_output_buffer_spec(spec)),
        };
        let resp = self
            .grpc
            .encapsulate_key_exact(req)
            .await
            .map_err(|status| grpc_status_to_ck_rv(status.code(), true))?
            .into_inner();
        match resp.result {
            // T13: adopt the owned result instead of cloning it.
            Some(result) => {
                pkcs11_proxy_ng_proto::convert::output::output_and_handle_result_from_owned(result)
            }
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
        self.require_exact_output_effects().await?;
        let ctx = self.context_id()?;
        let mut input_bytes = Vec::new();
        let mut input_null_len = None;
        Self::fill_input(input_data, &mut input_bytes, &mut input_null_len);
        let req = pkcs11_proxy_ng_proto::ByteOutputExactRequest {
            exact_output_effects_version: 1,
            client_context_id: ctx,
            session_handle: session.0,
            function: pkcs11_proxy_ng_proto::convert::output::byte_output_function_to_i32(function),
            output_spec: Some(Self::proto_output_buffer_spec(spec)),
            input_data: input_bytes,
            mechanism: mechanism.map(|m| self.proto_mechanism(m)).transpose()?,
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
            // T13: adopt the owned result instead of cloning it.
            Some(result) => Ok((
                pkcs11_proxy_ng_proto::convert::output::output_buffer_result_from_owned(result)?,
                mechanism_out,
            )),
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

    /// W1-L5-04: a supported cached version needs no re-probe. The channel
    /// is dead, so `Ok` proves no I/O happened (characterization: the range
    /// accepts v1 exactly like the old equality gate).
    #[tokio::test]
    async fn require_supported_cached_version_needs_no_probe() {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        let mut client = Pkcs11Client::from_channel(channel);
        client.note_backend_probe(1, true, 0);
        assert!(client.require_exact_output_effects().await.is_ok());
    }

    /// W1-L5-04: an out-of-range cached version fails closed (the re-probe
    /// hits the dead channel and maps to FUNCTION_NOT_SUPPORTED).
    #[tokio::test]
    async fn require_unsupported_cached_version_fails_closed() {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        let mut client = Pkcs11Client::from_channel(channel);
        client.note_backend_probe(99, true, 0);
        assert_eq!(client.require_exact_output_effects().await, Err(CkRv::FUNCTION_NOT_SUPPORTED));
    }

    /// W1-L5-04: no equality-gate literal may remain on any version line —
    /// every gate delegates to the compatibility-range helper.
    #[test]
    fn exact_effects_gates_use_the_compatibility_range() {
        let src = include_str!("raw_output.rs");
        // Concat-built so the patterns cannot match their own source text.
        let pats = [
            ["!= ", "1"].concat(),
            ["== ", "1"].concat(),
            ["!= ", "Some(1)"].concat(),
            ["== ", "Some(1)"].concat(),
        ];
        for (index, line) in src.lines().enumerate() {
            if line.contains("effects_version") && !line.trim_start().starts_with("//") {
                for pat in &pats {
                    assert!(
                        !line.contains(pat),
                        "line {}: gate must use the range helper, not `{pat}`: {line}",
                        index + 1
                    );
                }
            }
        }
        let helper = ["exact_output_effects_version_", "supported"].concat();
        assert_eq!(
            src.matches(&helper).count(),
            4,
            "one import + three gate calls (cached, probe, response) must name the range helper"
        );
    }

    /// W1-C10-09: no dead from-proto helper, no stale dead-code allows,
    /// and no stale Task scaffolding comment may remain in this module —
    /// every remaining helper is wired into an RPC.
    #[test]
    fn t32_no_dead_helpers_or_stale_allows_or_task_comment() {
        let src = include_str!("raw_output.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        // Concat-built so the patterns cannot match their own source text.
        let dead_fn = ["parameter_roundtrip_result", "_from_proto"].concat();
        assert!(!src.contains(&dead_fn), "dead helper `{dead_fn}` must be deleted, not kept");
        let allow = ["allow(dead", "_code)"].concat();
        assert!(!prod.contains(&allow), "stale allows must go — the helpers are all live");
        assert!(
            !prod.lines().any(|line| {
                let trimmed = line.trim_start();
                trimmed.starts_with("// Task ") || trimmed.starts_with("//Task ")
            }),
            "stale scaffolding comment must go — the wiring it promises long landed"
        );
    }

    /// W1-C10-11 (const half, landed by Task 6 W1-C9-09): the message
    /// auth-stage bit test must use the named constant — never a magic bit.
    #[test]
    fn t32_end_of_message_bit_uses_named_const() {
        fn has_magic_bit(line: &str) -> bool {
            line.contains("flags & 1")
        }
        // The detector itself, pinned both ways (negative control).
        assert!(has_magic_bit(") || flags & 1 != 0,"));
        assert!(!has_magic_bit(") || flags & CkFlags::END_OF_MESSAGE != 0,"));
        let src = include_str!("raw_output.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        for (index, line) in prod.lines().enumerate() {
            assert!(
                !has_magic_bit(line),
                "line {}: magic bit — use the named const: {line}",
                index + 1
            );
        }
        let named = ["CkFlags::END", "_OF_MESSAGE"].concat();
        assert!(prod.contains(&named), "the flags-bit test must name the const");
    }

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
            message_effects: None,
            authenticated_output: None,
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                apply_returned_len: Some(false),
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
            0,
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
                0,
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
                0,
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
            message_effects: None,
            authenticated_output: None,
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                apply_returned_len: Some(false),
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
            0,
        )
        .expect("genuine parameter output");
        assert_eq!(parameter.value, Some(SecretBytes::new(vec![1, 0xA5, 3])));
    }

    #[test]
    fn null_output_length_buffer_too_small_preserves_genuine_parameter_output() {
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true };
        let parameter_spec =
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 3, value: None };
        let response = pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
            message_effects: None,
            authenticated_output: None,
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                apply_returned_len: Some(false),
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
            0,
        )
        .expect("canonical buffer-too-small response");

        assert_eq!(output.ck_rv, CkRv::BUFFER_TOO_SMALL);
        assert_eq!(parameter.ck_rv, CkRv::BUFFER_TOO_SMALL);
        assert_eq!(parameter.value, Some(SecretBytes::new(vec![1, 0xA5, 3])));
    }

    #[test]
    fn old_server_missing_parameter_ack_on_b2s_is_rejected() {
        let request = gcm_parameter();
        let response = pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
            message_effects: None,
            authenticated_output: None,
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                apply_returned_len: Some(true),
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
            0,
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
                    message_effects: None,
                    authenticated_output: None,
                    output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                        apply_returned_len: Some(true),
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
                    0,
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
            (
                "malformed oneof",
                pkcs11_proxy_ng_proto::MessageParameter {
                    params: None,
                    parameter_encoding_version: 0,
                },
            ),
            (
                "raw empty",
                pkcs11_proxy_ng_proto::MessageParameter {
                    params: Some(pkcs11_proxy_ng_proto::message_parameter::Params::Raw(Vec::new())),
                    parameter_encoding_version: 0,
                },
            ),
            (
                "raw nonempty",
                pkcs11_proxy_ng_proto::MessageParameter {
                    params: Some(pkcs11_proxy_ng_proto::message_parameter::Params::Raw(vec![0xA5])),
                    parameter_encoding_version: 0,
                },
            ),
            ("wrong structured variant", (&ccm_parameter()).into()),
        ];

        for (label, message_parameter_out) in responses {
            let response = pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
                message_effects: None,
                authenticated_output: None,
                output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                    apply_returned_len: Some(true),
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
                0,
            )
            .unwrap_err();
            assert_eq!(error, CkRv::FUNCTION_NOT_SUPPORTED, "{label}");
        }
    }

    #[test]
    fn completed_parameter_output_error_retains_backend_origin() {
        let response = pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
            message_effects: None,
            authenticated_output: None,
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                apply_returned_len: Some(false),
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
        let (output, _, _) = decode_parameter_output_exact_contract_response(
            response,
            &CkOutputBufferSpec {
                buffer_present: false,
                buffer_len: 0,
                length_pointer_null: false,
            },
            &CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None },
            None,
            ParameterOutputFunction::EncryptMessage,
            0,
        )
        .unwrap();

        assert_eq!(output.ck_rv, CkRv::FUNCTION_FAILED);
        assert_eq!(output.returned_len, None);
    }

    #[test]
    fn authenticated_wrap_accepts_actual_mechanism_parameter_length() {
        let response = pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
            message_effects: None,
            authenticated_output: None,
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                apply_returned_len: Some(true),
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
            0,
        )
        .expect("actual mechanism parameter size within caller capacity is valid");

        assert_eq!(parameter.returned_len, 0);
        assert_eq!(parameter.value, Some(SecretBytes::new(Vec::new())));
        assert!(message.is_none());
    }

    fn r5_success_response_with_effects(
        message_effects: Option<v1_proto::MessageParameterEffects>,
    ) -> pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
        pkcs11_proxy_ng_proto::ParameterOutputExactResponse {
            message_effects,
            authenticated_output: None,
            output_result: Some(pkcs11_proxy_ng_proto::OutputBufferResult {
                apply_returned_len: Some(true),
                ck_rv: CkRv::OK.0,
                returned_len: 16,
                value: Some(vec![0x31; 16]),
            }),
            parameter_result: Some(pkcs11_proxy_ng_proto::ParameterRoundtripResult {
                ck_rv: CkRv::OK.0,
                returned_len: 16,
                value: Some(Vec::new()),
            }),
            message_parameter_out: None,
        }
    }

    /// R5/F1 (controller ruling): a Raw request paired with the R3
    /// None-effects wire signal (`message_effects: Some(empty)`) decodes to
    /// `MessageEffects::None` (the existing `validate_for` confirms the
    /// `(None, None)` pair). RED pre-R5: the empty wire oneof fails
    /// `TryFrom` with `ARGUMENTS_BAD`.
    #[test]
    fn r5_raw_request_with_empty_effects_wire_decodes_to_none() {
        let request = MessageParameter::Raw(vec![0xA5; 16].into());
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 16, length_pointer_null: false };
        let parameter_spec =
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 16, value: None };
        let response = r5_success_response_with_effects(Some(v1_proto::MessageParameterEffects {
            effect: None,
        }));
        let (_, _, effects) = decode_parameter_output_exact_response(
            response,
            &output_spec,
            &parameter_spec,
            Some(&request),
            ParameterOutputFunction::EncryptMessage,
            0,
        )
        .expect("Raw request + empty effects wire decodes to None");
        assert_eq!(effects, Some(MessageEffects::None));
    }

    /// R5/F1 ruling matrix pins (green before AND after): every other
    /// `(request, Some(empty))` combination keeps `ARGUMENTS_BAD`
    /// (`TryFrom` unchanged); `(None, None)` still decodes to no effects;
    /// a Raw request with a non-empty structured effects message keeps the
    /// `validate_for` rejection.
    #[test]
    fn r5_empty_effects_wire_matrix_pins() {
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 16, length_pointer_null: false };
        let parameter_spec =
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 16, value: None };
        let empty = || Some(v1_proto::MessageParameterEffects { effect: None });

        for (label, request) in [("gcm", gcm_parameter()), ("ccm", ccm_parameter())] {
            let error = decode_parameter_output_exact_response(
                r5_success_response_with_effects(empty()),
                &output_spec,
                &parameter_spec,
                Some(&request),
                ParameterOutputFunction::EncryptMessage,
                0,
            )
            .unwrap_err();
            assert_eq!(error, CkRv::ARGUMENTS_BAD, "{label} + empty effects wire");
        }

        let (_, _, effects) = decode_parameter_output_exact_response(
            r5_success_response_with_effects(None),
            &output_spec,
            &parameter_spec,
            None,
            ParameterOutputFunction::EncryptMessage,
            0,
        )
        .expect("(None, None) still decodes");
        assert!(effects.is_none());

        let request = MessageParameter::Raw(vec![0xA5; 16].into());
        let structured_wire = v1_proto::MessageParameterEffects {
            effect: Some(v1_proto::message_parameter_effects::Effect::Gcm(
                v1_proto::GcmMessageEffects { iv: Some(vec![0x42; 12]), tag: None },
            )),
        };
        let error = decode_parameter_output_exact_response(
            r5_success_response_with_effects(Some(structured_wire)),
            &output_spec,
            &parameter_spec,
            Some(&request),
            ParameterOutputFunction::EncryptMessage,
            0,
        )
        .unwrap_err();
        assert_eq!(error, CkRv::FUNCTION_NOT_SUPPORTED, "Raw + structured effects wire");
    }

    fn r5_client_with_transport_version(version: u32) -> Pkcs11Client {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        let client = Pkcs11Client::from_channel(channel);
        client.set_mechanism_parameter_transport_version_for_tests(version);
        assert_eq!(client.mechanism_parameter_transport_version(), version);
        client
    }

    /// R17 client threading: `proto_mechanism` reads the cached
    /// `mechanism_parameter_transport_version` (R5 precedent). At legacy
    /// capability the bytes are identical to the legacy `TryFrom`; at
    /// capability ≥ 1 the mixed IV+AAD-NULL-16 GCM emits v1
    /// (copied IV + `aad_null_len`, stamp 1, bools unset); a tail family
    /// (KEA) stays v0-shaped at every capability.
    #[tokio::test]
    async fn r17_proto_mechanism_threads_capability() {
        use pkcs11_proxy_ng_types::{CkMechanismType, GcmParams, KeaDeriveParams, PointerBytes};
        let mixed = CkMechanism {
            mechanism_type: CkMechanismType::AES_GCM,
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv: vec![0x11; 12],
                iv_bits: 96,
                iv_buffer_len: 12,
                aad: SecretBytes::copy_from_slice(&[]),
                tag_bits: 128,
                iv_null: false,
                aad_null: false,
                iv_presence: PointerBytes::present_copy(&[0x11; 12]),
                aad_presence: PointerBytes::null_len(16),
            })),
        };

        let legacy = r5_client_with_transport_version(0);
        let wire = legacy.proto_mechanism(&mixed).expect("legacy encodes");
        assert_eq!(wire, pkcs11_proxy_ng_proto::Mechanism::try_from(&mixed).unwrap());
        assert_eq!(wire.parameter_encoding_version, 0);

        for version in [1, 2] {
            let client = r5_client_with_transport_version(version);
            let wire = client.proto_mechanism(&mixed).expect("v1 encodes");
            assert_eq!(wire.parameter_encoding_version, 1, "capability {version}");
            match &wire.params {
                Some(pkcs11_proxy_ng_proto::mechanism::Params::GcmParams(p)) => {
                    assert_eq!(p.iv, vec![0x11; 12]);
                    assert_eq!(p.iv_null_len, None);
                    assert!(p.aad.is_empty());
                    assert_eq!(p.aad_null_len, Some(16));
                    assert!(!p.iv_null && !p.aad_null);
                }
                other => panic!("capability {version} must emit GcmParams, got {other:?}"),
            }
        }

        let kea = CkMechanism {
            mechanism_type: CkMechanismType(0xFFFF_FFFF),
            params: Some(CkMechanismParams::KeaDerive(KeaDeriveParams {
                is_sender: true,
                random_a: vec![1; 4],
                random_b: vec![2; 4],
                public_data: Vec::new(),
            })),
        };
        let client = r5_client_with_transport_version(1);
        let wire = client.proto_mechanism(&kea).expect("tail encodes");
        assert_eq!(wire, pkcs11_proxy_ng_proto::Mechanism::try_from(&kea).unwrap());
        assert_eq!(wire.parameter_encoding_version, 0);
    }

    /// R5/F1 client encode matrix: at legacy capability the helper emits
    /// bit-identical legacy bytes; at capability ≥ 1 a `Raw` IV emits
    /// v1-opaque (exact bytes, declared length, version 1); structured
    /// values keep the legacy encoding at every capability.
    #[tokio::test]
    async fn r5_proto_message_parameter_encode_matrix() {
        let raw16 = MessageParameter::Raw(vec![0xA5; 16].into());

        let legacy = r5_client_with_transport_version(0);
        let wire = legacy
            .proto_message_parameter(Some(&raw16))
            .expect("legacy encodes")
            .expect("Some in, Some out");
        assert_eq!(wire, pkcs11_proxy_ng_proto::MessageParameter::from(&raw16));
        assert!(legacy.proto_message_parameter(None).expect("None encodes").is_none());

        for version in [1, 2] {
            let client = r5_client_with_transport_version(version);
            let wire = client
                .proto_message_parameter(Some(&raw16))
                .expect("v1 encodes Raw")
                .expect("Some in, Some out");
            assert_eq!(wire.parameter_encoding_version, 1, "capability {version}");
            match &wire.params {
                Some(pkcs11_proxy_ng_proto::message_parameter::Params::OpaqueMessageParams(
                    opaque,
                )) => {
                    assert_eq!(opaque.data, vec![0xA5; 16]);
                    assert_eq!(opaque.declared_len, 16);
                }
                other => panic!("capability {version} must emit opaque, got {other:?}"),
            }
        }

        let client = r5_client_with_transport_version(1);
        let structured = gcm_parameter();
        let wire = client
            .proto_message_parameter(Some(&structured))
            .expect("structured encodes")
            .expect("Some in, Some out");
        assert_eq!(wire, pkcs11_proxy_ng_proto::MessageParameter::from(&structured));
    }

    /// R5/F1: an over-64 KiB `Raw` value fails LOCALLY with a
    /// backend-origin `MECHANISM_PARAM_INVALID` under v1 (no RPC is
    /// attempted — the channel is dead, so any emission would surface a
    /// transport error instead).
    #[tokio::test]
    async fn r5_over_cap_raw_fails_locally_without_wire_emission() {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        let mut client = Pkcs11Client::from_channel(channel);
        client.restore_context_id(Some("r5-no-emission".to_string()));
        client.set_mechanism_parameter_transport_version_for_tests(1);
        let big = MessageParameter::Raw(vec![0xA5; 64 * 1024 + 1].into());
        let mechanism = CkMechanism {
            mechanism_type: pkcs11_proxy_ng_types::CkMechanismType::AES_CBC,
            params: None,
        };
        let envelope =
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 16, value: None };
        let error = client
            .message_encrypt_init_contract(
                CkSessionHandle(7),
                &mechanism,
                Some(&big),
                CkObjectHandle(1),
                &envelope,
                pkcs11_proxy_ng_proto::convert::message_params::MessageParameterShape::Unmodeled,
            )
            .await
            .unwrap_err();
        assert_eq!(error.ck_rv, CkRv::MECHANISM_PARAM_INVALID);
        assert_eq!(error.origin, crate::MessageCallErrorOrigin::Backend);

        // Control: a representable value on the same dead channel proceeds
        // to the RPC (transport error), proving the helper only gates the
        // unrepresentable case.
        let small = MessageParameter::Raw(vec![0xA5; 16].into());
        let error = client
            .message_encrypt_init_contract(
                CkSessionHandle(7),
                &mechanism,
                Some(&small),
                CkObjectHandle(1),
                &envelope,
                pkcs11_proxy_ng_proto::convert::message_params::MessageParameterShape::Unmodeled,
            )
            .await
            .unwrap_err();
        assert_eq!(error.origin, crate::MessageCallErrorOrigin::Transport);
    }
}
