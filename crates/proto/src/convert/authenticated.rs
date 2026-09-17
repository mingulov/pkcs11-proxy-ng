//! Authenticated parameter transport has a separate output allowlist. In
//! particular, mechanism inputs must never be reused as output messages: they
//! may contain backend object handles after authorization/remapping.
use super::message_effects::{MessageEffectContext, MessageEffects};
use super::message_params::{
    MessageParameter, MessageParameterShape, validate_structured_wire_parameter,
};
use crate::pkcs11_proxy_ng::v1 as wire;
use crate::secret_boundary::secret_to_plain;
use pkcs11_proxy_ng_types::*;

impl std::fmt::Debug for wire::AuthenticatedMechanismOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthenticatedMechanismOutput([REDACTED])")
    }
}
impl std::fmt::Debug for wire::authenticated_mechanism_output::Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthenticatedMechanismOutput::Output([REDACTED])")
    }
}
impl std::fmt::Debug for wire::AuthenticatedParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthenticatedParameters([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum AuthenticatedOutput {
    Unchanged,
    /// `AuthenticatedMechanismOutput.iv` is classified secret (ADR-0013
    /// key-attributes material): wiping owner, redacted `Debug` below.
    Iv(SecretBytes),
    Message(MessageParameter),
    Effects(MessageEffects),
    Invalid(OutputContractViolation),
}

impl std::fmt::Debug for AuthenticatedOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unchanged => "AuthenticatedOutput::Unchanged",
            Self::Iv(_) => "AuthenticatedOutput::Iv([REDACTED])",
            Self::Message(_) => "AuthenticatedOutput::Message([REDACTED])",
            Self::Effects(_) => "AuthenticatedOutput::Effects([REDACTED])",
            Self::Invalid(_) => "AuthenticatedOutput::Invalid",
        })
    }
}

pub fn legacy_parameter_supported(mechanism: &CkMechanism) -> bool {
    mechanism.params.is_none()
        || (matches!(mechanism.params, Some(CkMechanismParams::Iv(_)))
            && pointer_free_iv_shape(mechanism.mechanism_type))
}

fn pointer_free_iv_shape(mechanism: CkMechanismType) -> bool {
    // The embedded inventory proves these are byte-array parameters. A wire
    // client cannot relabel an arbitrary pointer-bearing native layout as IV.
    // Runtime vendor extensions require a separate reviewed output contract.
    static REGISTRY: std::sync::OnceLock<Result<MechanismRegistry, String>> =
        std::sync::OnceLock::new();
    REGISTRY
        .get_or_init(|| MechanismRegistry::load_with_override_str(None))
        .as_ref()
        .is_ok_and(|registry| registry.param_shape(mechanism.0) == Some("iv"))
}

pub fn authenticated_shape(mechanism: CkMechanismType) -> MessageParameterShape {
    match mechanism {
        CkMechanismType::AES_GCM => MessageParameterShape::Gcm,
        CkMechanismType::AES_CCM => MessageParameterShape::Ccm,
        CkMechanismType::CHACHA20_POLY1305 | CkMechanismType::SALSA20_POLY1305 => {
            MessageParameterShape::SalsaChacha
        }
        _ => MessageParameterShape::Unmodeled,
    }
}

pub fn validate_input(
    mechanism: &CkMechanism,
    parameter: Option<&MessageParameter>,
) -> CkResult<()> {
    if let Some(parameter) = parameter {
        parameter.validate_structured()?;
        if mechanism.params.is_some()
            || !authenticated_shape(mechanism.mechanism_type).matches(parameter)
        {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        return Ok(());
    }
    match mechanism.params {
        None => Ok(()),
        Some(CkMechanismParams::Iv(_)) if pointer_free_iv_shape(mechanism.mechanism_type) => Ok(()),
        Some(CkMechanismParams::Gostr3410KeyWrap(_))
            if mechanism.mechanism_type == CkMechanismType::GOSTR3410_KEY_WRAP =>
        {
            Ok(())
        }
        _ => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

pub fn decode_parameters(
    mechanism: &CkMechanism,
    wire: &wire::AuthenticatedParameters,
) -> CkResult<Option<MessageParameter>> {
    let parameter = wire
        .message_parameter
        .as_ref()
        .map(|message| {
            validate_structured_wire_parameter(message)?;
            MessageParameter::try_from(message)
        })
        .transpose()?;
    validate_input(mechanism, parameter.as_ref())?;
    Ok(parameter)
}

impl AuthenticatedOutput {
    pub fn validate_exact_for(
        &self,
        mechanism: &CkMechanism,
        parameter: Option<&MessageParameter>,
        rv: CkRv,
        mode: super::message_effects::ParameterEffectCallMode,
    ) -> CkResult<()> {
        match (self, parameter) {
            (Self::Effects(effects), Some(input)) => {
                validate_input(mechanism, parameter)?;
                effects.validate_for(
                    input,
                    MessageEffectContext {
                        mode,
                        encrypt: true,
                        generated_stage: true,
                        auth_stage: true,
                        rv,
                    },
                )
            }
            (Self::Message(_), _) | (Self::Invalid(_), _) => Err(CkRv::DEVICE_ERROR),
            _ => self.validate_for(mechanism, parameter),
        }
    }
    pub fn validate_for(
        &self,
        mechanism: &CkMechanism,
        parameter: Option<&MessageParameter>,
    ) -> CkResult<()> {
        validate_input(mechanism, parameter)?;
        match (self, parameter, mechanism.params.as_ref()) {
            (Self::Effects(effects), Some(input), None) => effects.validate_for(
                input,
                MessageEffectContext {
                    mode: super::message_effects::ParameterEffectCallMode::Data,
                    encrypt: true,
                    generated_stage: true,
                    auth_stage: true,
                    rv: CkRv::OK,
                },
            ),
            (Self::Message(output), Some(input), None) if input.same_layout_and_scalars(output) => {
                output.validate_structured()
            }
            (Self::Iv(output), None, Some(CkMechanismParams::Iv(input)))
                if output.len() == input.iv.len() =>
            {
                Ok(())
            }
            (Self::Unchanged, None, None | Some(CkMechanismParams::Gostr3410KeyWrap(_))) => Ok(()),
            _ => Err(CkRv::MECHANISM_PARAM_INVALID),
        }
    }
}

impl TryFrom<&AuthenticatedOutput> for wire::AuthenticatedMechanismOutput {
    type Error = CkRv;
    fn try_from(output: &AuthenticatedOutput) -> CkResult<Self> {
        use wire::authenticated_mechanism_output::Output;
        Ok(Self {
            output: match output {
                AuthenticatedOutput::Unchanged => Some(Output::Unchanged(true)),
                AuthenticatedOutput::Iv(iv) => Some(Output::Iv(secret_to_plain(iv))),
                AuthenticatedOutput::Message(message) => {
                    Some(Output::MessageParameter(message.into()))
                }
                AuthenticatedOutput::Effects(effects) => {
                    Some(Output::MessageEffects(wire::MessageParameterEffects::try_from(effects)?))
                }
                AuthenticatedOutput::Invalid(_) => return Err(CkRv::DEVICE_ERROR),
            },
        })
    }
}

impl TryFrom<&wire::AuthenticatedMechanismOutput> for AuthenticatedOutput {
    type Error = CkRv;
    fn try_from(output: &wire::AuthenticatedMechanismOutput) -> CkResult<Self> {
        use wire::authenticated_mechanism_output::Output;
        match output.output.as_ref() {
            Some(Output::Unchanged(true)) => Ok(Self::Unchanged),
            Some(Output::Iv(iv)) => Ok(Self::Iv(SecretBytes::copy_from_slice(iv))),
            Some(Output::MessageParameter(message)) => {
                validate_structured_wire_parameter(message)?;
                Ok(Self::Message(MessageParameter::try_from(message)?))
            }
            Some(Output::MessageEffects(effects)) => Ok(Self::Effects(effects.try_into()?)),
            _ => Err(CkRv::MECHANISM_PARAM_INVALID),
        }
    }
}

#[cfg(test)]
#[test]
fn invalid_authenticated_native_completion_cannot_serialize_as_empty_wire_output() {
    for invalid in [
        AuthenticatedOutput::Invalid(OutputContractViolation::ParameterIntegrity),
        AuthenticatedOutput::Effects(MessageEffects::Invalid(
            OutputContractViolation::ParameterIntegrity,
        )),
    ] {
        assert!(
            wire::AuthenticatedMechanismOutput::try_from(&invalid).is_err(),
            "invalid native completion must fail conversion, not become an empty wire output"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn authenticated_wire_debug_never_formats_payload_buffers() {
        let output = wire::AuthenticatedMechanismOutput::try_from(&AuthenticatedOutput::Iv(
            vec![77, 78].into(),
        ))
        .unwrap();
        assert!(
            !format!("{output:?}").contains("77"),
            "authenticated wire output Debug must redact buffers"
        );
    }

    #[test]
    fn authenticated_output_roundtrips_an_explicit_empty_ack_without_native_fields() {
        let output =
            wire::AuthenticatedMechanismOutput::try_from(&AuthenticatedOutput::Unchanged).unwrap();
        assert_eq!(output.encode_to_vec(), [8, 1]);
        assert!(matches!(
            AuthenticatedOutput::try_from(&output),
            Ok(AuthenticatedOutput::Unchanged)
        ));
        assert!(
            AuthenticatedOutput::try_from(&wire::AuthenticatedMechanismOutput::default()).is_err()
        );
    }

    #[test]
    fn authenticated_conversion_rejects_raw_message_and_wrong_output_shape() {
        let mechanism = CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: None };
        let raw = wire::AuthenticatedParameters {
            message_parameter: Some(wire::MessageParameter::from(&MessageParameter::Raw(
                vec![0; 16].into(),
            ))),
        };
        assert!(matches!(decode_parameters(&mechanism, &raw), Err(CkRv::MECHANISM_PARAM_INVALID)));
        assert!(
            AuthenticatedOutput::Iv(vec![0; 16].into()).validate_for(&mechanism, None).is_err()
        );
    }

    #[test]
    fn authenticated_conversion_binds_parameter_layout_to_mechanism() {
        for mechanism in [
            CkMechanism {
                mechanism_type: CkMechanismType::AES_GCM,
                params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0; 48] })),
            },
            CkMechanism {
                mechanism_type: CkMechanismType::RSA_PKCS_OAEP,
                params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0; 40] })),
            },
            CkMechanism {
                mechanism_type: CkMechanismType::AES_CCM,
                params: Some(CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
                    wrap_oid: vec![0; 3],
                    ukm: vec![0; 8],
                    key_handle: 17,
                })),
            },
        ] {
            assert!(
                matches!(validate_input(&mechanism, None), Err(CkRv::MECHANISM_PARAM_INVALID)),
                "typed authenticated input must bind the native layout to the mechanism"
            );
        }
    }
}
