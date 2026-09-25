use crate::client::Pkcs11Client;
use crate::error::grpc_status_to_ck_rv;
use pkcs11_proxy_ng_proto as wire;
use pkcs11_proxy_ng_proto::convert::message_effects::ParameterEffectCallMode;
use pkcs11_proxy_ng_types::*;
use wire::convert::authenticated::{AuthenticatedOutput, validate_input};
use wire::convert::message_params::MessageParameter;
use wire::convert::output::output_buffer_result_from_owned;

/// T13 owned decoder: the caller takes both fields out of its owned
/// response. `raw` arrives as `SecretBytes` (adopted, never copied) so the
/// non-empty rejection path wipes instead of freeing plain.
fn decode_output_owned(
    mechanism: &CkMechanism,
    parameter: Option<&MessageParameter>,
    output: Option<wire::AuthenticatedMechanismOutput>,
    raw: SecretBytes,
) -> CkResult<AuthenticatedOutput> {
    if !raw.is_empty() {
        return Err(CkRv::FUNCTION_NOT_SUPPORTED);
    }
    let output = AuthenticatedOutput::try_from_owned(output.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?)
        .map_err(|_| CkRv::FUNCTION_NOT_SUPPORTED)?;
    output.validate_for(mechanism, parameter).map_err(|_| CkRv::FUNCTION_NOT_SUPPORTED)?;
    Ok(output)
}

/// Tri-state `typed_auth_capability` encoding (W1-C10-03).
const AUTH_CAP_UNKNOWN: u8 = 0;
const AUTH_CAP_NO: u8 = 1;
const AUTH_CAP_YES: u8 = 2;

impl Pkcs11Client {
    /// The cached `pointer_safe_authenticated_parameters` capability, if a
    /// probe already established it on this connection.
    pub(crate) fn cached_typed_auth_capability(&self) -> Option<bool> {
        match self.typed_auth_capability.load(std::sync::atomic::Ordering::Acquire) {
            AUTH_CAP_YES => Some(true),
            AUTH_CAP_NO => Some(false),
            _ => None,
        }
    }

    /// Record the capability carried by a fresh probe. Every probe
    /// overwrites — the value always matches the latest effects version
    /// the client has seen, so a version change can never leave a stale
    /// capability behind.
    pub(crate) fn note_typed_auth_capability(&self, capable: bool) {
        self.typed_auth_capability.store(
            if capable { AUTH_CAP_YES } else { AUTH_CAP_NO },
            std::sync::atomic::Ordering::Release,
        );
    }

    /// Drop the cached capability (reconnect re-probes on next use).
    /// Store-based so all clones sharing the connection observe it.
    pub(crate) fn invalidate_typed_auth_capability(&self) {
        self.typed_auth_capability.store(AUTH_CAP_UNKNOWN, std::sync::atomic::Ordering::Release);
    }

    pub async fn require_typed_authenticated_parameters(&mut self) -> CkResult<()> {
        if let Some(capable) = self.cached_typed_auth_capability() {
            return if capable { Ok(()) } else { Err(CkRv::FUNCTION_NOT_SUPPORTED) };
        }
        let probe =
            self.get_backend_interfaces().await.map_err(|_| CkRv::FUNCTION_NOT_SUPPORTED)?;
        // `get_backend_interfaces` already cached the fresh probe value.
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
    ) -> CkResult<(SecretBytes, AuthenticatedOutput)> {
        validate_input(mechanism, parameter)?;
        self.require_typed_authenticated_parameters().await?;
        // T12: `WrapKeyAuthenticatedRequest` is `ZeroizeOnDrop`, so
        // struct-update syntax is forbidden — all fields are spelled out
        // (the input buffer is filled by `fill_input` below).
        let mut request = wire::WrapKeyAuthenticatedRequest {
            client_context_id: self.context_id()?,
            session_handle: session.0,
            mechanism: Some(mechanism.try_into()?),
            wrapping_key_handle: wrapping_key.0,
            key_handle: key.0,
            associated_data: Vec::new(),
            associated_data_null_len: None,
            authenticated_parameters: Some(wire::AuthenticatedParameters {
                message_parameter: parameter.map(Into::into),
            }),
        };
        Self::fill_input(aad, &mut request.associated_data, &mut request.associated_data_null_len);
        // T12: `WrapKeyAuthenticatedResponse` is `ZeroizeOnDrop`; take
        // owned fields out with `mem::take` instead of moving them. T13:
        // the wrapped blob is adopted into `SecretBytes` (no copy).
        let mut response = pkcs11_unary_call!(self.grpc.wrap_key_authenticated(request), true);
        let raw = SecretBytes::new(std::mem::take(&mut response.mechanism_parameter_out));
        let output = decode_output_owned(
            mechanism,
            parameter,
            std::mem::take(&mut response.authenticated_output),
            raw,
        )?;
        Ok((SecretBytes::new(std::mem::take(&mut response.wrapped_key)), output))
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
        // T12: `ParameterOutputExactRequest` is `ZeroizeOnDrop`, so
        // struct-update syntax is forbidden — all fields are spelled out
        // (the input buffer is filled by `fill_input` below).
        let mut request = wire::ParameterOutputExactRequest {
            exact_output_effects_version: 1,
            client_context_id: self.context_id()?,
            session_handle: session.0,
            function: wire::ParameterOutputFunction::WrapKeyAuthenticated as i32,
            mechanism: Some(mechanism.try_into()?),
            wrapping_key_handle: wrapping_key.0,
            key_handle: key.0,
            output_spec: Some(spec.into()),
            input_data: Vec::new(),
            associated_data: Vec::new(),
            parameter: Vec::new(),
            parameter_out_spec: None,
            flags: 0,
            message_parameter: None,
            input_data_null_len: None,
            associated_data_null_len: None,
            authenticated_parameters: Some(wire::AuthenticatedParameters {
                message_parameter: parameter.map(Into::into),
            }),
        };
        Self::fill_input(aad, &mut request.associated_data, &mut request.associated_data_null_len);
        // T13: adopt the owned result buffer instead of cloning it.
        let mut response = self
            .grpc
            .parameter_output_exact(request)
            .await
            .map_err(|status| grpc_status_to_ck_rv(status.code(), true))?
            .into_inner();
        let main = response
            .output_result
            .take()
            .map(output_buffer_result_from_owned)
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
        // Exact responses carry no legacy raw channel; the empty default
        // documents that (rather than borrowing a field that isn't there).
        let output = decode_output_owned(
            mechanism,
            parameter,
            std::mem::take(&mut response.authenticated_output),
            SecretBytes::default(),
        )?;
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
        template: Option<&[CkAttribute]>,
        aad: CkInBuf<'_>,
    ) -> CkResult<(CkObjectHandle, AuthenticatedOutput)> {
        validate_input(mechanism, parameter)?;
        self.require_typed_authenticated_parameters().await?;
        // T12: `UnwrapKeyAuthenticatedRequest` is `ZeroizeOnDrop`, so
        // struct-update syntax is forbidden — all fields are spelled out
        // (the input buffers are filled by `fill_input` below).
        let mut request = wire::UnwrapKeyAuthenticatedRequest {
            client_context_id: self.context_id()?,
            session_handle: session.0,
            mechanism: Some(mechanism.try_into()?),
            unwrapping_key_handle: unwrapping_key.0,
            wrapped_key: Vec::new(),
            template: Self::proto_template(template.unwrap_or(&[])),
            associated_data: Vec::new(),
            wrapped_key_null_len: None,
            associated_data_null_len: None,
            authenticated_parameters: Some(wire::AuthenticatedParameters {
                message_parameter: parameter.map(Into::into),
            }),
            template_null: template.is_none(),
        };
        Self::fill_input(wrapped, &mut request.wrapped_key, &mut request.wrapped_key_null_len);
        Self::fill_input(aad, &mut request.associated_data, &mut request.associated_data_null_len);
        // T12: `UnwrapKeyAuthenticatedResponse` is `ZeroizeOnDrop`; take
        // owned fields out with `mem::take` instead of moving them.
        let mut response = pkcs11_unary_call!(self.grpc.unwrap_key_authenticated(request), true);
        let raw = SecretBytes::new(std::mem::take(&mut response.mechanism_parameter_out));
        let output = decode_output_owned(
            mechanism,
            parameter,
            std::mem::take(&mut response.authenticated_output),
            raw,
        )?;
        Ok((CkObjectHandle(response.key_handle), output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // W1-C10-03: the capability tri-state starts unknown, records both
    // outcomes, and invalidates back to unknown.
    #[tokio::test]
    async fn typed_auth_capability_tristate_round_trip() {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        let client = Pkcs11Client::from_channel(channel);
        assert_eq!(client.cached_typed_auth_capability(), None);
        client.note_typed_auth_capability(true);
        assert_eq!(client.cached_typed_auth_capability(), Some(true));
        client.note_typed_auth_capability(false);
        assert_eq!(client.cached_typed_auth_capability(), Some(false));
        client.invalidate_typed_auth_capability();
        assert_eq!(client.cached_typed_auth_capability(), None);
    }

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
                key_handle: CkObjectHandle(17),
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
        let valid = wire::AuthenticatedMechanismOutput::try_from(&AuthenticatedOutput::Iv(
            vec![0; 16].into(),
        ))
        .unwrap();
        assert!(
            decode_output_owned(&mechanism, None, Some(valid.clone()), SecretBytes::default())
                .is_ok()
        );
        for output in [
            None,
            Some(wire::AuthenticatedMechanismOutput::default()),
            Some(
                wire::AuthenticatedMechanismOutput::try_from(&AuthenticatedOutput::Unchanged)
                    .unwrap(),
            ),
        ] {
            assert!(decode_output_owned(&mechanism, None, output, SecretBytes::default()).is_err());
        }
        assert!(
            decode_output_owned(&mechanism, None, Some(valid), SecretBytes::copy_from_slice(&[0]))
                .is_err()
        );
    }
}
