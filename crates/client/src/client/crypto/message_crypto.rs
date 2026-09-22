use pkcs11_proxy_ng_proto::convert::message_effects::ParameterEffectCallMode;
use pkcs11_proxy_ng_proto::convert::message_params::{
    MessageParameter, MessageParameterShape, validate_structured_wire_parameter,
};
use pkcs11_proxy_ng_types::*;

use crate::client::Pkcs11Client;
use crate::error::{MessageCallError, grpc_status_to_ck_rv};

use pkcs11_proxy_ng_proto::convert::message_effects::{MessageEffectContext, MessageEffects};
type MessageBeginContractDecoded = (CkParameterRoundtripResult, Option<MessageEffects>);

fn decode_message_init_contract_response(
    ck_rv: u64,
    parameter_result: Option<&pkcs11_proxy_ng_proto::ParameterRoundtripResult>,
    response_shape: Option<i32>,
    response_parameter: Option<&pkcs11_proxy_ng_proto::MessageParameter>,
    envelope: &CkParameterRoundtripSpec,
    requested: Option<&MessageParameter>,
    expected_shape: MessageParameterShape,
) -> Result<(), MessageCallError> {
    let rv = CkRv(ck_rv);
    if rv.is_err() {
        return Err(MessageCallError::backend(rv));
    }

    let parameter_result = parameter_result
        .map(CkParameterRoundtripResult::from)
        .ok_or_else(MessageCallError::protocol)?;
    if parameter_result.ck_rv != CkRv::OK
        || parameter_result.returned_len != envelope.buffer_len
        || parameter_result.value != envelope.buffer_present.then(SecretBytes::default)
    {
        return Err(MessageCallError::protocol());
    }

    let response_shape =
        response_shape.ok_or_else(MessageCallError::protocol).and_then(|value| {
            MessageParameterShape::try_from_proto_i32(value)
                .map_err(|_| MessageCallError::protocol())
        })?;
    if response_shape != expected_shape {
        return Err(MessageCallError::protocol());
    }

    match (requested, response_parameter) {
        (None, None) => Ok(()),
        (Some(requested), Some(response)) => {
            validate_structured_wire_parameter(response)
                .map_err(|_| MessageCallError::protocol())?;
            let response =
                MessageParameter::try_from(response).map_err(|_| MessageCallError::protocol())?;
            if !expected_shape.matches(&response) || requested != &response {
                return Err(MessageCallError::protocol());
            }
            Ok(())
        }
        _ => Err(MessageCallError::protocol()),
    }
}

#[allow(clippy::too_many_arguments)]
fn decode_message_begin_contract_response(
    ck_rv: u64,
    legacy_parameter: &[u8],
    parameter_result: Option<&pkcs11_proxy_ng_proto::ParameterRoundtripResult>,
    message_parameter_out: Option<&pkcs11_proxy_ng_proto::MessageParameter>,
    message_effects: Option<&pkcs11_proxy_ng_proto::pkcs11_proxy_ng::v1::MessageParameterEffects>,
    envelope: &CkParameterRoundtripSpec,
    requested: Option<&MessageParameter>,
    decrypt: bool,
) -> Result<MessageBeginContractDecoded, MessageCallError> {
    let rv = CkRv(ck_rv);
    if rv.is_err()
        && parameter_result.is_none()
        && message_effects.is_none()
        && message_parameter_out.is_none()
        && legacy_parameter.is_empty()
    {
        return Err(MessageCallError::backend(rv));
    }
    if !legacy_parameter.is_empty() || message_parameter_out.is_some() {
        return Err(MessageCallError::protocol());
    }
    let parameter_result = parameter_result
        .map(CkParameterRoundtripResult::from)
        .ok_or_else(MessageCallError::protocol)?;
    if parameter_result.ck_rv != rv
        || parameter_result.returned_len != envelope.buffer_len
        || parameter_result.value != envelope.buffer_present.then(SecretBytes::default)
    {
        return Err(MessageCallError::protocol());
    }
    let response_parameter = match (requested, message_effects) {
        (Some(request), Some(response)) => {
            let decoded =
                MessageEffects::try_from(response).map_err(|_| MessageCallError::protocol())?;
            decoded
                .validate_for(
                    request,
                    MessageEffectContext {
                        mode: ParameterEffectCallMode::Begin,
                        encrypt: !decrypt,
                        generated_stage: true,
                        auth_stage: false,
                        rv,
                    },
                )
                .map_err(|_| MessageCallError::protocol())?;
            Some(decoded)
        }
        (None, None) => None,
        _ => return Err(MessageCallError::protocol()),
    };
    Ok((parameter_result, response_parameter))
}

fn decode_empty_message_parameter_response(
    ck_rv: u64,
    legacy_parameter: &[u8],
    unexpected_output: &[u8],
    parameter_result: Option<&pkcs11_proxy_ng_proto::ParameterRoundtripResult>,
    envelope: &CkParameterRoundtripSpec,
) -> Result<CkParameterRoundtripResult, MessageCallError> {
    let rv = CkRv(ck_rv);
    if rv.is_err() {
        return Err(MessageCallError::backend(rv));
    }
    if !legacy_parameter.is_empty() || !unexpected_output.is_empty() {
        return Err(MessageCallError::protocol());
    }
    let result = parameter_result
        .map(CkParameterRoundtripResult::from)
        .ok_or_else(MessageCallError::protocol)?;
    if result.ck_rv != CkRv::OK
        || result.returned_len != envelope.buffer_len
        || result.value != envelope.buffer_present.then(SecretBytes::default)
    {
        return Err(MessageCallError::protocol());
    }
    Ok(result)
}

fn decode_stateful_unit_response(ck_rv: u64) -> Result<(), MessageCallError> {
    let rv = CkRv(ck_rv);
    if rv.is_err() { Err(MessageCallError::backend(rv)) } else { Ok(()) }
}

impl Pkcs11Client {
    // --- Message Encrypt Init (optional mechanism — None = cancel) ---

    pub async fn message_encrypt_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        init_param: Option<&MessageParameter>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.message_encrypt_init_stateful(session, mechanism, init_param, key)
            .await
            .map_err(|error| error.ck_rv)
    }

    pub async fn message_encrypt_init_stateful(
        &mut self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        init_param: Option<&MessageParameter>,
        key: CkObjectHandle,
    ) -> Result<(), MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let req = pkcs11_proxy_ng_proto::MessageEncryptInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: mechanism
                .map(Self::proto_mechanism)
                .transpose()
                .map_err(MessageCallError::backend)?,
            key_handle: key.0,
            init_message_parameter: init_param.map(Into::into),
            parameter_out_spec: None,
            parameter_shape: None,
        };
        let response = self
            .grpc
            .message_encrypt_init(req)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_stateful_unit_response(response.ck_rv)
    }

    /// Capability-gated message Init contract used by the C shim. Unlike the
    /// legacy method, this requires shape, outer-envelope and structured
    /// acknowledgements and preserves the origin of failures.
    pub async fn message_encrypt_init_contract(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        init_param: Option<&MessageParameter>,
        key: CkObjectHandle,
        envelope: &CkParameterRoundtripSpec,
        shape: MessageParameterShape,
    ) -> Result<(), MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let req = pkcs11_proxy_ng_proto::MessageEncryptInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism).map_err(MessageCallError::backend)?),
            key_handle: key.0,
            init_message_parameter: init_param.map(Into::into),
            parameter_out_spec: Some(Self::proto_parameter_roundtrip_spec(envelope)),
            parameter_shape: Some(shape.to_proto_i32()),
        };
        let response = self
            .grpc
            .message_encrypt_init(req)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_message_init_contract_response(
            response.ck_rv,
            response.parameter_result.as_ref(),
            response.parameter_shape,
            response.init_message_parameter.as_ref(),
            envelope,
            init_param,
            shape,
        )
    }

    // --- Message Encrypt Final ---

    pub async fn message_encrypt_final(&mut self, session: CkSessionHandle) -> CkResult<()> {
        self.message_encrypt_final_stateful(session).await.map_err(|error| error.ck_rv)
    }

    pub async fn message_encrypt_final_stateful(
        &mut self,
        session: CkSessionHandle,
    ) -> Result<(), MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let req = pkcs11_proxy_ng_proto::MessageEncryptFinalRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        let response = self
            .grpc
            .message_encrypt_final(req)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_stateful_unit_response(response.ck_rv)
    }

    // --- Message Decrypt Init (optional mechanism — None = cancel) ---

    pub async fn message_decrypt_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        init_param: Option<&MessageParameter>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.message_decrypt_init_stateful(session, mechanism, init_param, key)
            .await
            .map_err(|error| error.ck_rv)
    }

    pub async fn message_decrypt_init_stateful(
        &mut self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        init_param: Option<&MessageParameter>,
        key: CkObjectHandle,
    ) -> Result<(), MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let req = pkcs11_proxy_ng_proto::MessageDecryptInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: mechanism
                .map(Self::proto_mechanism)
                .transpose()
                .map_err(MessageCallError::backend)?,
            key_handle: key.0,
            init_message_parameter: init_param.map(Into::into),
            parameter_out_spec: None,
            parameter_shape: None,
        };
        let response = self
            .grpc
            .message_decrypt_init(req)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_stateful_unit_response(response.ck_rv)
    }

    pub async fn message_decrypt_init_contract(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        init_param: Option<&MessageParameter>,
        key: CkObjectHandle,
        envelope: &CkParameterRoundtripSpec,
        shape: MessageParameterShape,
    ) -> Result<(), MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let req = pkcs11_proxy_ng_proto::MessageDecryptInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism).map_err(MessageCallError::backend)?),
            key_handle: key.0,
            init_message_parameter: init_param.map(Into::into),
            parameter_out_spec: Some(Self::proto_parameter_roundtrip_spec(envelope)),
            parameter_shape: Some(shape.to_proto_i32()),
        };
        let response = self
            .grpc
            .message_decrypt_init(req)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_message_init_contract_response(
            response.ck_rv,
            response.parameter_result.as_ref(),
            response.parameter_shape,
            response.init_message_parameter.as_ref(),
            envelope,
            init_param,
            shape,
        )
    }

    // --- Message Decrypt Final ---

    pub async fn message_decrypt_final(&mut self, session: CkSessionHandle) -> CkResult<()> {
        self.message_decrypt_final_stateful(session).await.map_err(|error| error.ck_rv)
    }

    pub async fn message_decrypt_final_stateful(
        &mut self,
        session: CkSessionHandle,
    ) -> Result<(), MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let req = pkcs11_proxy_ng_proto::MessageDecryptFinalRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        let response = self
            .grpc
            .message_decrypt_final(req)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_stateful_unit_response(response.ck_rv)
    }

    // --- Message Sign Init (optional mechanism — None = cancel) ---

    pub async fn message_sign_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.message_sign_init_stateful(session, mechanism, key).await.map_err(|error| error.ck_rv)
    }

    pub async fn message_sign_init_stateful(
        &mut self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> Result<(), MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let req = pkcs11_proxy_ng_proto::MessageSignInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: mechanism
                .map(Self::proto_mechanism)
                .transpose()
                .map_err(MessageCallError::backend)?,
            key_handle: key.0,
        };
        let response = self
            .grpc
            .message_sign_init(req)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_stateful_unit_response(response.ck_rv)
    }

    // --- Message Sign Final ---

    pub async fn message_sign_final(&mut self, session: CkSessionHandle) -> CkResult<()> {
        self.message_sign_final_stateful(session).await.map_err(|error| error.ck_rv)
    }

    pub async fn message_sign_final_stateful(
        &mut self,
        session: CkSessionHandle,
    ) -> Result<(), MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let req = pkcs11_proxy_ng_proto::MessageSignFinalRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        let response = self
            .grpc
            .message_sign_final(req)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_stateful_unit_response(response.ck_rv)
    }

    // --- Message Verify Init (optional mechanism — None = cancel) ---

    pub async fn message_verify_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.message_verify_init_stateful(session, mechanism, key)
            .await
            .map_err(|error| error.ck_rv)
    }

    pub async fn message_verify_init_stateful(
        &mut self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> Result<(), MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let req = pkcs11_proxy_ng_proto::MessageVerifyInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: mechanism
                .map(Self::proto_mechanism)
                .transpose()
                .map_err(MessageCallError::backend)?,
            key_handle: key.0,
        };
        let response = self
            .grpc
            .message_verify_init(req)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_stateful_unit_response(response.ck_rv)
    }

    // --- Message Verify Final ---

    pub async fn message_verify_final(&mut self, session: CkSessionHandle) -> CkResult<()> {
        self.message_verify_final_stateful(session).await.map_err(|error| error.ck_rv)
    }

    pub async fn message_verify_final_stateful(
        &mut self,
        session: CkSessionHandle,
    ) -> Result<(), MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let req = pkcs11_proxy_ng_proto::MessageVerifyFinalRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        let response = self
            .grpc
            .message_verify_final(req)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_stateful_unit_response(response.ck_rv)
    }

    // =====================================================================
    // One-shot / Begin / Next methods
    // =====================================================================

    // --- C_EncryptMessage — returns (parameter_out, ciphertext) ---

    pub async fn encrypt_message(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: CkInBuf<'_>,
        plaintext: CkInBuf<'_>,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::EncryptMessageRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            associated_data: Vec::new(),
            plaintext: Vec::new(),
            associated_data_null_len: None,
            plaintext_null_len: None,
        };
        Self::fill_input(aad, &mut req.associated_data, &mut req.associated_data_null_len);
        Self::fill_input(plaintext, &mut req.plaintext, &mut req.plaintext_null_len);
        // T12: `EncryptMessageResponse` is `ZeroizeOnDrop`; take owned
        // fields out with `mem::take` instead of moving them.
        let mut resp = pkcs11_unary_call!(self.grpc.encrypt_message(req), true);
        let parameter_out = std::mem::take(&mut resp.parameter_out);
        Ok((parameter_out, std::mem::take(&mut resp.ciphertext)))
    }

    // --- C_EncryptMessageBegin — returns parameter_out ---

    pub async fn encrypt_message_begin(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: CkInBuf<'_>,
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::EncryptMessageBeginRequest {
            exact_output_effects_version: 1,
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            associated_data: Vec::new(),
            associated_data_null_len: None,
            parameter_out_spec: None,
            message_parameter: None,
        };
        Self::fill_input(aad, &mut req.associated_data, &mut req.associated_data_null_len);
        // T12: `EncryptMessageBeginResponse` is `ZeroizeOnDrop`; take the
        // owned field out with `mem::take` instead of moving it.
        let mut resp = pkcs11_unary_call!(self.grpc.encrypt_message_begin(req), true);
        Ok(std::mem::take(&mut resp.parameter_out))
    }

    /// Capability-gated Begin contract used by the C shim. The raw legacy
    /// parameter stays empty; the envelope and structured value are both
    /// acknowledged before the caller may commit generated IV/nonce bytes.
    pub async fn encrypt_message_begin_contract(
        &mut self,
        session: CkSessionHandle,
        envelope: &CkParameterRoundtripSpec,
        message_parameter: Option<&MessageParameter>,
        aad: CkInBuf<'_>,
    ) -> Result<MessageBeginContractDecoded, MessageCallError> {
        self.require_exact_output_effects().await.map_err(MessageCallError::backend)?;
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let mut req = pkcs11_proxy_ng_proto::EncryptMessageBeginRequest {
            exact_output_effects_version: 1,
            client_context_id: ctx,
            session_handle: session.0,
            parameter: Vec::new(),
            associated_data: Vec::new(),
            associated_data_null_len: None,
            parameter_out_spec: Some(Self::proto_parameter_roundtrip_spec(envelope)),
            message_parameter: message_parameter.map(Into::into),
        };
        Self::fill_input(aad, &mut req.associated_data, &mut req.associated_data_null_len);
        let response = self
            .grpc
            .encrypt_message_begin(req)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_message_begin_contract_response(
            response.ck_rv,
            &response.parameter_out,
            response.parameter_result.as_ref(),
            response.message_parameter_out.as_ref(),
            response.message_effects.as_ref(),
            envelope,
            message_parameter,
            false,
        )
    }

    // --- C_EncryptMessageNext — returns (parameter_out, ciphertext_part) ---

    pub async fn encrypt_message_next(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        plaintext_part: CkInBuf<'_>,
        flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::EncryptMessageNextRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            plaintext_part: Vec::new(),
            flags: flags.0,
            plaintext_part_null_len: None,
        };
        Self::fill_input(plaintext_part, &mut req.plaintext_part, &mut req.plaintext_part_null_len);
        // T12: `EncryptMessageNextResponse` is `ZeroizeOnDrop`; take owned
        // fields out with `mem::take` instead of moving them.
        let mut resp = pkcs11_unary_call!(self.grpc.encrypt_message_next(req), true);
        let parameter_out = std::mem::take(&mut resp.parameter_out);
        Ok((parameter_out, std::mem::take(&mut resp.ciphertext_part)))
    }

    // --- C_DecryptMessage — returns (parameter_out, plaintext) ---

    pub async fn decrypt_message(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: CkInBuf<'_>,
        ciphertext: CkInBuf<'_>,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::DecryptMessageRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            associated_data: Vec::new(),
            ciphertext: Vec::new(),
            associated_data_null_len: None,
            ciphertext_null_len: None,
        };
        Self::fill_input(aad, &mut req.associated_data, &mut req.associated_data_null_len);
        Self::fill_input(ciphertext, &mut req.ciphertext, &mut req.ciphertext_null_len);
        // T12: `DecryptMessageResponse` is `ZeroizeOnDrop`; take owned
        // fields out with `mem::take` instead of moving them.
        let mut resp = pkcs11_unary_call!(self.grpc.decrypt_message(req), true);
        let parameter_out = std::mem::take(&mut resp.parameter_out);
        Ok((parameter_out, std::mem::take(&mut resp.plaintext)))
    }

    // --- C_DecryptMessageBegin — returns parameter_out ---

    pub async fn decrypt_message_begin(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: CkInBuf<'_>,
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::DecryptMessageBeginRequest {
            exact_output_effects_version: 1,
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            associated_data: Vec::new(),
            associated_data_null_len: None,
            parameter_out_spec: None,
            message_parameter: None,
        };
        Self::fill_input(aad, &mut req.associated_data, &mut req.associated_data_null_len);
        // T12: `DecryptMessageBeginResponse` is `ZeroizeOnDrop`; take the
        // owned field out with `mem::take` instead of moving it.
        let mut resp = pkcs11_unary_call!(self.grpc.decrypt_message_begin(req), true);
        Ok(std::mem::take(&mut resp.parameter_out))
    }

    pub async fn decrypt_message_begin_contract(
        &mut self,
        session: CkSessionHandle,
        envelope: &CkParameterRoundtripSpec,
        message_parameter: Option<&MessageParameter>,
        aad: CkInBuf<'_>,
    ) -> Result<MessageBeginContractDecoded, MessageCallError> {
        self.require_exact_output_effects().await.map_err(MessageCallError::backend)?;
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let mut req = pkcs11_proxy_ng_proto::DecryptMessageBeginRequest {
            exact_output_effects_version: 1,
            client_context_id: ctx,
            session_handle: session.0,
            parameter: Vec::new(),
            associated_data: Vec::new(),
            associated_data_null_len: None,
            parameter_out_spec: Some(Self::proto_parameter_roundtrip_spec(envelope)),
            message_parameter: message_parameter.map(Into::into),
        };
        Self::fill_input(aad, &mut req.associated_data, &mut req.associated_data_null_len);
        let response = self
            .grpc
            .decrypt_message_begin(req)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_message_begin_contract_response(
            response.ck_rv,
            &response.parameter_out,
            response.parameter_result.as_ref(),
            response.message_parameter_out.as_ref(),
            response.message_effects.as_ref(),
            envelope,
            message_parameter,
            true,
        )
    }

    // --- C_DecryptMessageNext — returns (parameter_out, plaintext_part) ---

    pub async fn decrypt_message_next(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        ciphertext_part: CkInBuf<'_>,
        flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::DecryptMessageNextRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            ciphertext_part: Vec::new(),
            flags: flags.0,
            ciphertext_part_null_len: None,
        };
        Self::fill_input(
            ciphertext_part,
            &mut req.ciphertext_part,
            &mut req.ciphertext_part_null_len,
        );
        // T12: `DecryptMessageNextResponse` is `ZeroizeOnDrop`; take owned
        // fields out with `mem::take` instead of moving them.
        let mut resp = pkcs11_unary_call!(self.grpc.decrypt_message_next(req), true);
        let parameter_out = std::mem::take(&mut resp.parameter_out);
        Ok((parameter_out, std::mem::take(&mut resp.plaintext_part)))
    }

    // --- C_SignMessage — returns (parameter_out, signature) ---

    pub async fn sign_message(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        data: CkInBuf<'_>,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::SignMessageRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            data: Vec::new(),
            data_null_len: None,
        };
        Self::fill_input(data, &mut req.data, &mut req.data_null_len);
        // T12: `SignMessageResponse` is `ZeroizeOnDrop`; take owned fields
        // out with `mem::take` instead of moving them.
        let mut resp = pkcs11_unary_call!(self.grpc.sign_message(req), true);
        let parameter_out = std::mem::take(&mut resp.parameter_out);
        Ok((parameter_out, std::mem::take(&mut resp.signature)))
    }

    // --- C_SignMessageBegin — returns parameter_out ---

    pub async fn sign_message_begin(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::SignMessageBeginRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            parameter_out_spec: None,
        };
        // T12: `SignMessageBeginResponse` is `ZeroizeOnDrop`; take the
        // owned field out with `mem::take` instead of moving it.
        let mut resp = pkcs11_unary_call!(self.grpc.sign_message_begin(req), true);
        Ok(std::mem::take(&mut resp.parameter_out))
    }

    pub async fn sign_message_begin_contract(
        &mut self,
        session: CkSessionHandle,
        envelope: &CkParameterRoundtripSpec,
    ) -> Result<CkParameterRoundtripResult, MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let request = pkcs11_proxy_ng_proto::SignMessageBeginRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: Vec::new(),
            parameter_out_spec: Some(Self::proto_parameter_roundtrip_spec(envelope)),
        };
        let response = self
            .grpc
            .sign_message_begin(request)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_empty_message_parameter_response(
            response.ck_rv,
            &response.parameter_out,
            &[],
            response.parameter_result.as_ref(),
            envelope,
        )
    }

    // --- C_SignMessageNext — returns (parameter_out, signature) ---

    pub async fn sign_message_next(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        data_part: CkInBuf<'_>,
        request_signature: bool,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::SignMessageNextRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            data_part: Vec::new(),
            request_signature,
            data_part_null_len: None,
            parameter_out_spec: None,
        };
        Self::fill_input(data_part, &mut req.data_part, &mut req.data_part_null_len);
        // T12: `SignMessageNextResponse` is `ZeroizeOnDrop`; take owned
        // fields out with `mem::take` instead of moving them.
        let mut resp = pkcs11_unary_call!(self.grpc.sign_message_next(req), true);
        let parameter_out = std::mem::take(&mut resp.parameter_out);
        Ok((parameter_out, std::mem::take(&mut resp.signature)))
    }

    pub async fn sign_message_next_feed_contract(
        &mut self,
        session: CkSessionHandle,
        envelope: &CkParameterRoundtripSpec,
        data_part: CkInBuf<'_>,
    ) -> Result<CkParameterRoundtripResult, MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let mut request = pkcs11_proxy_ng_proto::SignMessageNextRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: Vec::new(),
            data_part: Vec::new(),
            request_signature: false,
            data_part_null_len: None,
            parameter_out_spec: Some(Self::proto_parameter_roundtrip_spec(envelope)),
        };
        Self::fill_input(data_part, &mut request.data_part, &mut request.data_part_null_len);
        let response = self
            .grpc
            .sign_message_next(request)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_empty_message_parameter_response(
            response.ck_rv,
            &response.parameter_out,
            &response.signature,
            response.parameter_result.as_ref(),
            envelope,
        )
    }

    // --- C_VerifyMessage — unit result, parameter is input-only ---

    pub async fn verify_message(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        data: CkInBuf<'_>,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::VerifyMessageRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            data: Vec::new(),
            signature: Vec::new(),
            data_null_len: None,
            signature_null_len: None,
            parameter_out_spec: None,
        };
        Self::fill_input(data, &mut req.data, &mut req.data_null_len);
        Self::fill_input(signature, &mut req.signature, &mut req.signature_null_len);
        pkcs11_unary_ok!(self.grpc.verify_message(req), true)
    }

    pub async fn verify_message_contract(
        &mut self,
        session: CkSessionHandle,
        envelope: &CkParameterRoundtripSpec,
        data: CkInBuf<'_>,
        signature: CkInBuf<'_>,
    ) -> Result<CkParameterRoundtripResult, MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let mut request = pkcs11_proxy_ng_proto::VerifyMessageRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: Vec::new(),
            data: Vec::new(),
            signature: Vec::new(),
            data_null_len: None,
            signature_null_len: None,
            parameter_out_spec: Some(Self::proto_parameter_roundtrip_spec(envelope)),
        };
        Self::fill_input(data, &mut request.data, &mut request.data_null_len);
        Self::fill_input(signature, &mut request.signature, &mut request.signature_null_len);
        let response = self
            .grpc
            .verify_message(request)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_empty_message_parameter_response(
            response.ck_rv,
            &[],
            &[],
            response.parameter_result.as_ref(),
            envelope,
        )
    }

    // --- C_VerifyMessageBegin — unit result ---

    pub async fn verify_message_begin(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::VerifyMessageBeginRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            parameter_out_spec: None,
        };
        pkcs11_unary_ok!(self.grpc.verify_message_begin(req), true)
    }

    pub async fn verify_message_begin_contract(
        &mut self,
        session: CkSessionHandle,
        envelope: &CkParameterRoundtripSpec,
    ) -> Result<CkParameterRoundtripResult, MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let request = pkcs11_proxy_ng_proto::VerifyMessageBeginRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: Vec::new(),
            parameter_out_spec: Some(Self::proto_parameter_roundtrip_spec(envelope)),
        };
        let response = self
            .grpc
            .verify_message_begin(request)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_empty_message_parameter_response(
            response.ck_rv,
            &response.parameter_out,
            &[],
            response.parameter_result.as_ref(),
            envelope,
        )
    }

    // --- C_VerifyMessageNext — unit result ---

    pub async fn verify_message_next(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        data_part: CkInBuf<'_>,
        is_final: bool,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::VerifyMessageNextRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            data_part: Vec::new(),
            is_final,
            signature: Vec::new(),
            data_part_null_len: None,
            signature_null_len: None,
            parameter_out_spec: None,
        };
        Self::fill_input(data_part, &mut req.data_part, &mut req.data_part_null_len);
        Self::fill_input(signature, &mut req.signature, &mut req.signature_null_len);
        pkcs11_unary_ok!(self.grpc.verify_message_next(req), true)
    }

    pub async fn verify_message_next_contract(
        &mut self,
        session: CkSessionHandle,
        envelope: &CkParameterRoundtripSpec,
        data_part: CkInBuf<'_>,
        is_final: bool,
        signature: CkInBuf<'_>,
    ) -> Result<CkParameterRoundtripResult, MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let mut request = pkcs11_proxy_ng_proto::VerifyMessageNextRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: Vec::new(),
            data_part: Vec::new(),
            is_final,
            signature: Vec::new(),
            data_part_null_len: None,
            signature_null_len: None,
            parameter_out_spec: Some(Self::proto_parameter_roundtrip_spec(envelope)),
        };
        Self::fill_input(data_part, &mut request.data_part, &mut request.data_part_null_len);
        Self::fill_input(signature, &mut request.signature, &mut request.signature_null_len);
        let response = self
            .grpc
            .verify_message_next(request)
            .await
            .map_err(|status| {
                MessageCallError::transport(grpc_status_to_ck_rv(status.code(), true))
            })?
            .into_inner();
        decode_empty_message_parameter_response(
            response.ck_rv,
            &[],
            &[],
            response.parameter_result.as_ref(),
            envelope,
        )
    }
}

#[cfg(test)]
mod begin_contract_tests {
    use super::*;
    use pkcs11_proxy_ng_proto::convert::message_params::{
        CcmMessageParams, GcmMessageParams, Salsa20ChaCha20Poly1305MessageParams,
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

    fn salsa_parameter() -> MessageParameter {
        MessageParameter::SalaChacha(Salsa20ChaCha20Poly1305MessageParams {
            nonce: vec![0x33; 12],
            nonce_bits: 96,
            nonce_null_len: None,
            tag: vec![0; 16],
            tag_null_len: None,
        })
    }

    #[test]
    fn init_contract_rejects_same_layout_with_mutated_bytes_for_every_shape() {
        let envelope =
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 48, value: None };
        let acknowledged = pkcs11_proxy_ng_proto::ParameterRoundtripResult {
            ck_rv: CkRv::OK.0,
            returned_len: envelope.buffer_len,
            value: Some(Vec::new()),
        };
        for (shape, requested) in [
            (MessageParameterShape::Gcm, gcm_parameter()),
            (MessageParameterShape::Ccm, ccm_parameter()),
            (MessageParameterShape::SalsaChacha, salsa_parameter()),
        ] {
            let mut mutated = requested.clone();
            match &mut mutated {
                MessageParameter::GcmMessage(parameter) => parameter.iv[0] ^= 0xFF,
                MessageParameter::CcmMessage(parameter) => parameter.nonce[0] ^= 0xFF,
                MessageParameter::SalaChacha(parameter) => parameter.nonce[0] ^= 0xFF,
                MessageParameter::Raw(_) => unreachable!(),
            }
            let wire_mutated = (&mutated).into();
            let error = decode_message_init_contract_response(
                CkRv::OK.0,
                Some(&acknowledged),
                Some(shape.to_proto_i32()),
                Some(&wire_mutated),
                &envelope,
                Some(&requested),
                shape,
            )
            .unwrap_err();
            assert_eq!(error.origin, crate::MessageCallErrorOrigin::Protocol, "{shape:?}");
        }
    }

    #[test]
    fn init_contract_rejects_missing_or_mutated_acknowledgements() {
        let requested = gcm_parameter();
        let wire_requested = (&requested).into();
        let envelope =
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 48, value: None };
        let acknowledged = pkcs11_proxy_ng_proto::ParameterRoundtripResult {
            ck_rv: CkRv::OK.0,
            returned_len: envelope.buffer_len,
            value: Some(Vec::new()),
        };
        let mut mutated_envelope = acknowledged.clone();
        mutated_envelope.returned_len += 1;
        let mut mutated_parameter = requested.clone();
        let MessageParameter::GcmMessage(parameter) = &mut mutated_parameter else {
            unreachable!();
        };
        parameter.iv[0] ^= 0xFF;
        let wire_mutated = (&mutated_parameter).into();
        let malformed_parameter = pkcs11_proxy_ng_proto::MessageParameter { params: None };
        let raw_parameter = pkcs11_proxy_ng_proto::MessageParameter {
            params: Some(pkcs11_proxy_ng_proto::message_parameter::Params::Raw(Vec::new())),
        };
        let raw_nonempty_parameter = pkcs11_proxy_ng_proto::MessageParameter {
            params: Some(pkcs11_proxy_ng_proto::message_parameter::Params::Raw(vec![0xA5])),
        };
        let wrong_variant = (&ccm_parameter()).into();

        decode_message_init_contract_response(
            CkRv::OK.0,
            Some(&acknowledged),
            Some(MessageParameterShape::Gcm.to_proto_i32()),
            Some(&wire_requested),
            &envelope,
            Some(&requested),
            MessageParameterShape::Gcm,
        )
        .expect("complete exact acknowledgement");

        for (label, parameter_result, response_shape, response_parameter) in [
            (
                "missing outer acknowledgement",
                None,
                Some(MessageParameterShape::Gcm.to_proto_i32()),
                Some(&wire_requested),
            ),
            (
                "mutated outer acknowledgement",
                Some(&mutated_envelope),
                Some(MessageParameterShape::Gcm.to_proto_i32()),
                Some(&wire_requested),
            ),
            ("missing shape acknowledgement", Some(&acknowledged), None, Some(&wire_requested)),
            (
                "mutated shape acknowledgement",
                Some(&acknowledged),
                Some(MessageParameterShape::Ccm.to_proto_i32()),
                Some(&wire_requested),
            ),
            (
                "unknown shape acknowledgement",
                Some(&acknowledged),
                Some(i32::MAX),
                Some(&wire_requested),
            ),
            (
                "missing structured acknowledgement",
                Some(&acknowledged),
                Some(MessageParameterShape::Gcm.to_proto_i32()),
                None,
            ),
            (
                "mutated structured acknowledgement",
                Some(&acknowledged),
                Some(MessageParameterShape::Gcm.to_proto_i32()),
                Some(&wire_mutated),
            ),
            (
                "malformed structured acknowledgement",
                Some(&acknowledged),
                Some(MessageParameterShape::Gcm.to_proto_i32()),
                Some(&malformed_parameter),
            ),
            (
                "raw structured acknowledgement",
                Some(&acknowledged),
                Some(MessageParameterShape::Gcm.to_proto_i32()),
                Some(&raw_parameter),
            ),
            (
                "nonempty raw structured acknowledgement",
                Some(&acknowledged),
                Some(MessageParameterShape::Gcm.to_proto_i32()),
                Some(&raw_nonempty_parameter),
            ),
            (
                "wrong structured variant acknowledgement",
                Some(&acknowledged),
                Some(MessageParameterShape::Gcm.to_proto_i32()),
                Some(&wrong_variant),
            ),
        ] {
            let error = decode_message_init_contract_response(
                CkRv::OK.0,
                parameter_result,
                response_shape,
                response_parameter,
                &envelope,
                Some(&requested),
                MessageParameterShape::Gcm,
            )
            .unwrap_err();
            assert_eq!(error.origin, crate::MessageCallErrorOrigin::Protocol, "{label}");
        }

        let error = decode_message_init_contract_response(
            CkRv::OK.0,
            Some(&acknowledged),
            Some(MessageParameterShape::Gcm.to_proto_i32()),
            Some(&wire_requested),
            &envelope,
            None,
            MessageParameterShape::Gcm,
        )
        .unwrap_err();
        assert_eq!(error.origin, crate::MessageCallErrorOrigin::Protocol);
    }

    #[test]
    fn begin_contract_rejects_missing_outer_ack() {
        let requested = gcm_parameter();
        let envelope =
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 32, value: None };
        let response = pkcs11_proxy_ng_proto::EncryptMessageBeginResponse {
            message_effects: None,
            ck_rv: CkRv::OK.0,
            parameter_out: Vec::new(),
            parameter_result: None,
            message_parameter_out: Some((&requested).into()),
        };

        let error = decode_message_begin_contract_response(
            response.ck_rv,
            &response.parameter_out,
            response.parameter_result.as_ref(),
            response.message_parameter_out.as_ref(),
            response.message_effects.as_ref(),
            &envelope,
            Some(&requested),
            false,
        )
        .unwrap_err();

        assert_eq!(error.origin, crate::MessageCallErrorOrigin::Protocol);
    }

    #[test]
    fn begin_contract_rejects_outer_pointer_class_or_length_mutation() {
        for envelope in [
            CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None },
            CkParameterRoundtripSpec { buffer_present: false, buffer_len: 7, value: None },
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 0, value: None },
        ] {
            let acknowledged = pkcs11_proxy_ng_proto::ParameterRoundtripResult {
                ck_rv: CkRv::OK.0,
                returned_len: envelope.buffer_len,
                value: envelope.buffer_present.then(Vec::new),
            };
            let mut wrong_class = acknowledged.clone();
            wrong_class.value = if envelope.buffer_present { None } else { Some(Vec::new()) };
            let mut wrong_len = acknowledged.clone();
            wrong_len.returned_len += 1;

            for (label, response) in [("pointer class", wrong_class), ("length", wrong_len)] {
                let error = decode_message_begin_contract_response(
                    CkRv::OK.0,
                    &[],
                    Some(&response),
                    None,
                    None,
                    &envelope,
                    None,
                    false,
                )
                .unwrap_err();
                assert_eq!(
                    error.origin,
                    crate::MessageCallErrorOrigin::Protocol,
                    "{label} for {envelope:?}",
                );
            }
        }
    }

    #[test]
    fn begin_contract_rejects_raw_malformed_or_wrong_variant_response() {
        let requested = gcm_parameter();
        let envelope =
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 48, value: None };
        let acknowledged = pkcs11_proxy_ng_proto::ParameterRoundtripResult {
            ck_rv: CkRv::OK.0,
            returned_len: envelope.buffer_len,
            value: Some(Vec::new()),
        };
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

        for (label, response) in responses {
            let error = decode_message_begin_contract_response(
                CkRv::OK.0,
                &[],
                Some(&acknowledged),
                Some(&response),
                None,
                &envelope,
                Some(&requested),
                false,
            )
            .unwrap_err();
            assert_eq!(error.origin, crate::MessageCallErrorOrigin::Protocol, "{label}",);
        }
    }

    #[test]
    fn empty_parameter_contract_rejects_missing_or_mutated_ack() {
        let envelope =
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 0, value: None };

        let missing =
            decode_empty_message_parameter_response(CkRv::OK.0, &[], &[], None, &envelope)
                .unwrap_err();
        assert_eq!(missing.origin, crate::MessageCallErrorOrigin::Protocol);

        let mutated = pkcs11_proxy_ng_proto::ParameterRoundtripResult {
            ck_rv: CkRv::OK.0,
            returned_len: 1,
            value: Some(Vec::new()),
        };
        let error = decode_empty_message_parameter_response(
            CkRv::OK.0,
            &[],
            &[],
            Some(&mutated),
            &envelope,
        )
        .unwrap_err();
        assert_eq!(error.origin, crate::MessageCallErrorOrigin::Protocol);
    }
}
