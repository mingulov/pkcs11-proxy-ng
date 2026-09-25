//! Typed direction/stage effects; only owned output bytes can cross this boundary.
use super::message_params::MessageParameter;
use crate::pkcs11_proxy_ng::v1 as wire;
use pkcs11_proxy_ng_types::{
    CkGeneratorFunction, CkOutputBufferSpec, CkResult, CkRv, OutputContractViolation,
};

#[derive(Clone, PartialEq, Eq)]
pub enum MessageEffects {
    Gcm {
        iv: Option<Vec<u8>>,
        tag: Option<Vec<u8>>,
    },
    Ccm {
        nonce: Option<Vec<u8>>,
        mac: Option<Vec<u8>>,
    },
    Salsa {
        tag: Option<Vec<u8>>,
    },
    /// Internal completion metadata; the service suppresses every output channel.
    Invalid(OutputContractViolation),
}

impl std::fmt::Debug for MessageEffects {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MessageEffects([REDACTED])")
    }
}

/// Independent of direction and message stage. A present zero-capacity buffer
/// is Data; Begin has no main output, but is not a size query. Missing length
/// storage cannot establish successful data output even if a provider says OK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterEffectCallMode {
    Begin,
    SizeQuery,
    Data,
    MissingLength,
}

impl ParameterEffectCallMode {
    pub fn from_output_spec(spec: &CkOutputBufferSpec) -> Self {
        if spec.length_pointer_null {
            Self::MissingLength
        } else if spec.buffer_present {
            Self::Data
        } else {
            Self::SizeQuery
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MessageEffectContext {
    pub mode: ParameterEffectCallMode,
    pub encrypt: bool,
    pub generated_stage: bool,
    pub auth_stage: bool,
    pub rv: CkRv,
}

impl MessageEffects {
    pub fn capture(
        input: &MessageParameter,
        output: &MessageParameter,
        context: MessageEffectContext,
    ) -> Self {
        if !input.same_layout_and_scalars(output) {
            return Self::Invalid(OutputContractViolation::ParameterIntegrity);
        }
        let generated = |generator: u64| {
            context.encrypt
                && context.generated_stage
                && generator != CkGeneratorFunction::NO_GENERATE.0
                && (generator == CkGeneratorFunction::GENERATE_COUNTER_XOR.0
                    || (context.rv == CkRv::OK
                        && matches!(
                            context.mode,
                            ParameterEffectCallMode::Data | ParameterEffectCallMode::Begin
                        )))
        };
        let auth = context.encrypt
            && context.auth_stage
            && context.rv == CkRv::OK
            && context.mode == ParameterEffectCallMode::Data;
        match (input, output) {
            (MessageParameter::GcmMessage(a), MessageParameter::GcmMessage(b)) => Self::Gcm {
                iv: (generated(a.iv_generator) && a.iv_null_len.is_none()).then(|| b.iv.clone()),
                tag: (auth && a.tag_null_len.is_none()).then(|| b.tag.clone()),
            },
            (MessageParameter::CcmMessage(a), MessageParameter::CcmMessage(b)) => Self::Ccm {
                nonce: (generated(a.nonce_generator) && a.nonce_null_len.is_none())
                    .then(|| b.nonce.clone()),
                mac: (auth && a.mac_null_len.is_none()).then(|| b.mac.clone()),
            },
            (MessageParameter::SalaChacha(a), MessageParameter::SalaChacha(b)) => {
                Self::Salsa { tag: (auth && a.tag_null_len.is_none()).then(|| b.tag.clone()) }
            }
            _ => Self::Invalid(OutputContractViolation::ParameterIntegrity),
        }
    }

    pub fn validate_for(
        &self,
        input: &MessageParameter,
        context: MessageEffectContext,
    ) -> CkResult<()> {
        input.validate_structured()?;
        let allowed = Self::capture(input, input, context);
        let valid =
            |effect: &Option<Vec<u8>>, permitted: &Option<Vec<u8>>| match (effect, permitted) {
                (None, _) => true,
                (Some(value), Some(original)) => value.len() == original.len(),
                _ => false,
            };
        let matches = match (self, &allowed) {
            (Self::Gcm { iv, tag }, Self::Gcm { iv: a, tag: b }) => valid(iv, a) && valid(tag, b),
            (Self::Ccm { nonce, mac }, Self::Ccm { nonce: a, mac: b }) => {
                valid(nonce, a) && valid(mac, b)
            }
            (Self::Salsa { tag }, Self::Salsa { tag: a }) => valid(tag, a),
            _ => false,
        };
        let fixed_prefix_matches = |output: &Option<Vec<u8>>, original: &[u8], bits: u64| {
            let Some(output) = output else {
                return true;
            };
            let Ok(bytes) = usize::try_from(bits / 8) else {
                return false;
            };
            let remainder = (bits % 8) as u32;
            output.get(..bytes) == original.get(..bytes)
                && (remainder == 0
                    || output
                        .get(bytes)
                        .zip(original.get(bytes))
                        .is_some_and(|(out, old)| (out ^ old) & (0xff << (8 - remainder)) == 0))
        };
        let prefix = match (self, input) {
            (Self::Gcm { iv, .. }, MessageParameter::GcmMessage(p)) => {
                fixed_prefix_matches(iv, &p.iv, p.iv_fixed_bits)
            }
            (Self::Ccm { nonce, .. }, MessageParameter::CcmMessage(p)) => {
                fixed_prefix_matches(nonce, &p.nonce, p.nonce_fixed_bits)
            }
            _ => true,
        };
        if matches && prefix { Ok(()) } else { Err(CkRv::DEVICE_ERROR) }
    }
}

// Wire `Debug` redaction for `MessageParameterEffects`, its `Effect` oneof,
// and the `Gcm`/`Ccm`/`SalsaMessageEffects` envelopes is generated by
// build.rs (`redacted_debug_gen.rs`, from secret-fields.toml).

impl TryFrom<&MessageEffects> for wire::MessageParameterEffects {
    type Error = CkRv;
    fn try_from(effects: &MessageEffects) -> CkResult<Self> {
        use wire::message_parameter_effects::Effect;
        let effect = match effects {
            MessageEffects::Gcm { iv, tag } => {
                Effect::Gcm(wire::GcmMessageEffects { iv: iv.clone(), tag: tag.clone() })
            }
            MessageEffects::Ccm { nonce, mac } => {
                Effect::Ccm(wire::CcmMessageEffects { nonce: nonce.clone(), mac: mac.clone() })
            }
            MessageEffects::Salsa { tag } => {
                Effect::Salsa(wire::SalsaMessageEffects { tag: tag.clone() })
            }
            MessageEffects::Invalid(_) => return Err(CkRv::DEVICE_ERROR),
        };
        Ok(Self { effect: Some(effect) })
    }
}
impl TryFrom<&wire::MessageParameterEffects> for MessageEffects {
    type Error = CkRv;
    fn try_from(effects: &wire::MessageParameterEffects) -> CkResult<Self> {
        use wire::message_parameter_effects::Effect;
        match effects.effect.as_ref() {
            Some(Effect::Gcm(value)) => {
                Ok(Self::Gcm { iv: value.iv.clone(), tag: value.tag.clone() })
            }
            Some(Effect::Ccm(value)) => {
                Ok(Self::Ccm { nonce: value.nonce.clone(), mac: value.mac.clone() })
            }
            Some(Effect::Salsa(value)) => Ok(Self::Salsa { tag: value.tag.clone() }),
            None => Err(super::ABSENT_MESSAGE_ONEOF_RV),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::message_params::GcmMessageParams;

    #[test]
    fn exact_parameter_effect_mode_direction_stage_rv_matrix() {
        use crate::convert::message_params::{
            CcmMessageParams, Salsa20ChaCha20Poly1305MessageParams,
        };
        for mode in [
            ParameterEffectCallMode::Begin,
            ParameterEffectCallMode::SizeQuery,
            ParameterEffectCallMode::Data,
            ParameterEffectCallMode::MissingLength,
        ] {
            for encrypt in [false, true] {
                for generated_stage in [false, true] {
                    for auth_stage in [false, true] {
                        for rv in [CkRv::OK, CkRv::BUFFER_TOO_SMALL, CkRv::FUNCTION_FAILED] {
                            for generator in 0..=4 {
                                let context = MessageEffectContext {
                                    mode,
                                    encrypt,
                                    generated_stage,
                                    auth_stage,
                                    rv,
                                };
                                let generated = encrypt
                                    && generated_stage
                                    && generator != 0
                                    && (generator == 4
                                        || (rv == CkRv::OK
                                            && matches!(
                                                mode,
                                                ParameterEffectCallMode::Data
                                                    | ParameterEffectCallMode::Begin
                                            )));
                                let authenticated = encrypt
                                    && auth_stage
                                    && rv == CkRv::OK
                                    && mode == ParameterEffectCallMode::Data;
                                let inputs = [
                                    MessageParameter::GcmMessage(GcmMessageParams {
                                        iv: vec![0x11; 12],
                                        iv_null_len: None,
                                        iv_fixed_bits: 0,
                                        iv_generator: generator,
                                        tag: vec![0; 16],
                                        tag_null_len: None,
                                        tag_bits: 128,
                                    }),
                                    MessageParameter::CcmMessage(CcmMessageParams {
                                        data_len: 0,
                                        nonce: vec![0x11; 12],
                                        nonce_null_len: None,
                                        nonce_fixed_bits: 0,
                                        nonce_generator: generator,
                                        mac: vec![0; 16],
                                        mac_null_len: None,
                                        mac_len: 16,
                                    }),
                                    MessageParameter::SalaChacha(
                                        Salsa20ChaCha20Poly1305MessageParams {
                                            nonce: vec![0x11; 12],
                                            nonce_bits: 96,
                                            nonce_null_len: None,
                                            tag: vec![0; 16],
                                            tag_null_len: None,
                                        },
                                    ),
                                ];
                                for input in inputs {
                                    let mut output = input.clone();
                                    match &mut output {
                                        MessageParameter::GcmMessage(p) => {
                                            p.iv.fill(0x42);
                                            p.tag.fill(0x5a);
                                        }
                                        MessageParameter::CcmMessage(p) => {
                                            p.nonce.fill(0x42);
                                            p.mac.fill(0x5a);
                                        }
                                        MessageParameter::SalaChacha(p) => p.tag.fill(0x5a),
                                        _ => unreachable!(),
                                    }
                                    let expected = match &input {
                                        MessageParameter::GcmMessage(_) => MessageEffects::Gcm {
                                            iv: generated.then(|| vec![0x42; 12]),
                                            tag: authenticated.then(|| vec![0x5a; 16]),
                                        },
                                        MessageParameter::CcmMessage(_) => MessageEffects::Ccm {
                                            nonce: generated.then(|| vec![0x42; 12]),
                                            mac: authenticated.then(|| vec![0x5a; 16]),
                                        },
                                        MessageParameter::SalaChacha(_) => MessageEffects::Salsa {
                                            tag: authenticated.then(|| vec![0x5a; 16]),
                                        },
                                        _ => unreachable!(),
                                    };
                                    assert_eq!(
                                        MessageEffects::capture(&input, &output, context),
                                        expected,
                                        "context={context:?} generator={generator}"
                                    );
                                    expected.validate_for(&input, context).unwrap();
                                    if !authenticated {
                                        let forbidden = match &input {
                                            MessageParameter::GcmMessage(_) => {
                                                MessageEffects::Gcm {
                                                    iv: None,
                                                    tag: Some(vec![0; 16]),
                                                }
                                            }
                                            MessageParameter::CcmMessage(_) => {
                                                MessageEffects::Ccm {
                                                    nonce: None,
                                                    mac: Some(vec![0; 16]),
                                                }
                                            }
                                            _ => MessageEffects::Salsa { tag: Some(vec![0; 16]) },
                                        };
                                        assert!(forbidden.validate_for(&input, context).is_err());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn exact_parameter_call_mode_preserves_zero_capacity_and_null_length_classes() {
        for present in [false, true] {
            for null_length in [false, true] {
                for capacity in [0, 8, u64::MAX] {
                    let spec = CkOutputBufferSpec {
                        buffer_present: present,
                        buffer_len: capacity,
                        length_pointer_null: null_length,
                    };
                    assert_eq!(
                        ParameterEffectCallMode::from_output_spec(&spec),
                        if null_length {
                            ParameterEffectCallMode::MissingLength
                        } else if present {
                            ParameterEffectCallMode::Data
                        } else {
                            ParameterEffectCallMode::SizeQuery
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn exact_message_effect_rejects_changed_partial_fixed_prefix() {
        let input = MessageParameter::GcmMessage(GcmMessageParams {
            iv: vec![0xa5; 12],
            iv_null_len: None,
            iv_fixed_bits: 9,
            iv_generator: CkGeneratorFunction::GENERATE_COUNTER_XOR.0,
            tag: vec![0; 16],
            tag_null_len: None,
            tag_bits: 128,
        });
        let mut output = vec![0xa5; 12];
        output[1] ^= 0x80;
        let effect = MessageEffects::Gcm { iv: Some(output), tag: None };
        assert!(
            effect
                .validate_for(
                    &input,
                    MessageEffectContext {
                        mode: ParameterEffectCallMode::Data,
                        encrypt: true,
                        generated_stage: true,
                        auth_stage: true,
                        rv: CkRv::DEVICE_ERROR
                    }
                )
                .is_err()
        );
    }

    #[test]
    fn absent_effect_oneof_decodes_to_unified_rv() {
        // W1-C8-03: absent oneof must report the documented sibling-wide RV.
        assert_eq!(
            MessageEffects::try_from(&wire::MessageParameterEffects { effect: None }),
            Err(crate::convert::ABSENT_MESSAGE_ONEOF_RV),
        );
        assert_eq!(
            MessageEffects::try_from(&wire::MessageParameterEffects { effect: None }),
            Err(CkRv::ARGUMENTS_BAD),
        );
    }

    #[test]
    fn exact_message_effect_wire_debug_is_redacted() {
        let effect = wire::MessageParameterEffects::try_from(&MessageEffects::Gcm {
            iv: Some(b"secret-iv-canary".to_vec()),
            tag: Some(vec![201; 16]),
        })
        .unwrap();
        let rendered = format!("{effect:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("201"));
    }
}
