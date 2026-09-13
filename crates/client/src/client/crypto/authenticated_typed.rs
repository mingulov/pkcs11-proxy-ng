use crate::client::Pkcs11Client;
use crate::error::grpc_status_to_ck_rv;
use pkcs11_proxy_ng_proto as wire;
use pkcs11_proxy_ng_proto::convert::message_effects::ParameterEffectCallMode;
use pkcs11_proxy_ng_types::*;
use wire::convert::authenticated::{AuthenticatedOutput, validate_input};
use wire::convert::message_params::MessageParameter;

fn decode_output(
    mechanism: &CkMechanism,
    parameter: Option<&MessageParameter>,
    output: Option<&wire::AuthenticatedMechanismOutput>,
    raw: &[u8],
) -> CkResult<AuthenticatedOutput> {
    if !raw.is_empty() {
        return Err(CkRv::FUNCTION_NOT_SUPPORTED);
    }
    let output = AuthenticatedOutput::try_from(output.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?)
        .map_err(|_| CkRv::FUNCTION_NOT_SUPPORTED)?;
    output.validate_for(mechanism, parameter).map_err(|_| CkRv::FUNCTION_NOT_SUPPORTED)?;
    Ok(output)
}

impl Pkcs11Client {
    pub async fn require_typed_authenticated_parameters(&mut self) -> CkResult<()> {
        let probe =
            self.get_backend_interfaces().await.map_err(|_| CkRv::FUNCTION_NOT_SUPPORTED)?;
        if probe.pointer_safe_authenticated_parameters {
            Ok(())
        } else {
            Err(CkRv::FUNCTION_NOT_SUPPORTED)
        }
    }

    pub async fn wrap_key_authenticated_typed(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        parameter: Option<&MessageParameter>,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
    ) -> CkResult<(Vec<u8>, AuthenticatedOutput)> {
        validate_input(mechanism, parameter)?;
        self.require_typed_authenticated_parameters().await?;
        let mut request = wire::WrapKeyAuthenticatedRequest {
            client_context_id: self.context_id()?,
            session_handle: session.0,
            mechanism: Some(mechanism.into()),
            wrapping_key_handle: wrapping_key.0,
            key_handle: key.0,
            authenticated_parameters: Some(wire::AuthenticatedParameters {
                message_parameter: parameter.map(Into::into),
            }),
            ..Default::default()
        };
        Self::fill_input(aad, &mut request.associated_data, &mut request.associated_data_null_len);
        let response = pkcs11_unary_call!(self.grpc.wrap_key_authenticated(request), true);
        let output = decode_output(
            mechanism,
            parameter,
            response.authenticated_output.as_ref(),
            &response.mechanism_parameter_out,
        )?;
        Ok((response.wrapped_key, output))
    }

    pub async fn wrap_key_authenticated_exact_typed(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        parameter: Option<&MessageParameter>,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, AuthenticatedOutput)> {
        validate_input(mechanism, parameter)?;
        self.require_typed_authenticated_parameters().await?;
        self.require_exact_output_effects().await?;
        let mut request = wire::ParameterOutputExactRequest {
            exact_output_effects_version: 1,
            client_context_id: self.context_id()?,
            session_handle: session.0,
            function: wire::ParameterOutputFunction::WrapKeyAuthenticated as i32,
            mechanism: Some(mechanism.into()),
            wrapping_key_handle: wrapping_key.0,
            key_handle: key.0,
            output_spec: Some(spec.into()),
            authenticated_parameters: Some(wire::AuthenticatedParameters {
                message_parameter: parameter.map(Into::into),
            }),
            ..Default::default()
        };
        Self::fill_input(aad, &mut request.associated_data, &mut request.associated_data_null_len);
        let response = self
            .grpc
            .parameter_output_exact(request)
            .await
            .map_err(|status| grpc_status_to_ck_rv(status.code(), true))?
            .into_inner();
        let main = response
            .output_result
            .as_ref()
            .map(CkOutputBufferResult::try_from)
            .transpose()?
            .ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        if !matches!(main.ck_rv, CkRv::OK | CkRv::BUFFER_TOO_SMALL)
            && main.returned_len.is_none()
            && main.value.is_none()
            && response.authenticated_output.is_none()
        {
            return Err(main.ck_rv);
        }
        let ack = response.parameter_result.as_ref().ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        if ack.ck_rv != main.ck_rv.0
            || ack.returned_len != 0
            || ack.value.is_some()
            || response.message_parameter_out.is_some()
        {
            return Err(CkRv::FUNCTION_NOT_SUPPORTED);
        }
        main.validate_for(spec, u64::MAX).map_err(|_| CkRv::FUNCTION_NOT_SUPPORTED)?;
        let output =
            decode_output(mechanism, parameter, response.authenticated_output.as_ref(), &[])?;
        output
            .validate_exact_for(
                mechanism,
                parameter,
                main.ck_rv,
                ParameterEffectCallMode::from_output_spec(spec),
            )
            .map_err(|_| CkRv::FUNCTION_NOT_SUPPORTED)?;
        Ok((main, output))
    }

    pub async fn unwrap_key_authenticated_typed(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        parameter: Option<&MessageParameter>,
        unwrapping_key: CkObjectHandle,
        wrapped: CkInBuf<'_>,
        template: &[CkAttribute],
        aad: CkInBuf<'_>,
    ) -> CkResult<(CkObjectHandle, AuthenticatedOutput)> {
        validate_input(mechanism, parameter)?;
        self.require_typed_authenticated_parameters().await?;
        let mut request = wire::UnwrapKeyAuthenticatedRequest {
            client_context_id: self.context_id()?,
            session_handle: session.0,
            mechanism: Some(mechanism.into()),
            unwrapping_key_handle: unwrapping_key.0,
            template: Self::proto_template(template),
            authenticated_parameters: Some(wire::AuthenticatedParameters {
                message_parameter: parameter.map(Into::into),
            }),
            ..Default::default()
        };
        Self::fill_input(wrapped, &mut request.wrapped_key, &mut request.wrapped_key_null_len);
        Self::fill_input(aad, &mut request.associated_data, &mut request.associated_data_null_len);
        let response = pkcs11_unary_call!(self.grpc.unwrap_key_authenticated(request), true);
        let output = decode_output(
            mechanism,
            parameter,
            response.authenticated_output.as_ref(),
            &response.mechanism_parameter_out,
        )?;
        Ok((CkObjectHandle(response.key_handle), output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn authenticated_legacy_exact_client_rejects_structures_before_transport() {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        let mut client = Pkcs11Client::from_channel(channel);
        client.context_id = Some("isolated-test-context".into());
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType::GOSTR3410_KEY_WRAP,
            params: Some(CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
                wrap_oid: vec![0; 3],
                ukm: vec![0; 8],
                key_handle: 17,
            })),
        };
        let result = client
            .parameter_output_exact(
                CkSessionHandle(1),
                ParameterOutputFunction::WrapKeyAuthenticated,
                &CkOutputBufferSpec {
                    buffer_present: false,
                    buffer_len: 0,
                    length_pointer_null: false,
                },
                CkInBuf::Bytes(&[]),
                CkInBuf::Bytes(&[]),
                &[],
                &CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None },
                0,
                Some(&mechanism),
                2,
                3,
                None,
            )
            .await;
        assert!(
            matches!(result, Err(CkRv::FUNCTION_NOT_SUPPORTED)),
            "legacy structure calls must stop before transport"
        );
    }

    #[test]
    fn authenticated_client_rejects_absent_dual_or_wrong_shape_output_before_writeback() {
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType::AES_CBC,
            params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0; 16] })),
        };
        let valid =
            wire::AuthenticatedMechanismOutput::try_from(&AuthenticatedOutput::Iv(vec![0; 16]))
                .unwrap();
        assert!(decode_output(&mechanism, None, Some(&valid), &[]).is_ok());
        for output in [
            None,
            Some(wire::AuthenticatedMechanismOutput::default()),
            Some(
                wire::AuthenticatedMechanismOutput::try_from(&AuthenticatedOutput::Unchanged)
                    .unwrap(),
            ),
        ] {
            assert!(decode_output(&mechanism, None, output.as_ref(), &[]).is_err());
        }
        assert!(decode_output(&mechanism, None, Some(&valid), &[0]).is_err());
    }
}
