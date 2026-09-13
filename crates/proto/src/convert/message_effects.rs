//! Typed direction/stage effects; only owned output bytes can cross this boundary.
use super::message_params::MessageParameter;
use crate::pkcs11_proxy_ng::v1 as wire;
use pkcs11_proxy_ng_types::{CkResult, CkRv, OutputContractViolation};
// Published CK_GENERATOR_FUNCTION values, independent of native integer width.
const CKG_NO_GENERATE: u64 = 0;
const CKG_GENERATE_COUNTER_XOR: u64 = 4;

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

#[derive(Debug, Clone, Copy)]
pub struct MessageEffectContext {
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
                && generator != CKG_NO_GENERATE
                && (context.rv == CkRv::OK || generator == CKG_GENERATE_COUNTER_XOR)
        };
        let auth = context.encrypt && context.auth_stage && context.rv == CkRv::OK;
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

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {$ (
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("MessageEffects([REDACTED])") }
        }
    )+};
}
redacted_debug!(
    wire::MessageParameterEffects,
    wire::message_parameter_effects::Effect,
    wire::GcmMessageEffects,
    wire::CcmMessageEffects,
    wire::SalsaMessageEffects
);

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
            None => Err(CkRv::FUNCTION_NOT_SUPPORTED),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::message_params::GcmMessageParams;

    #[test]
    fn exact_message_effect_rejects_changed_partial_fixed_prefix() {
        let input = MessageParameter::GcmMessage(GcmMessageParams {
            iv: vec![0xa5; 12],
            iv_null_len: None,
            iv_fixed_bits: 9,
            iv_generator: CKG_GENERATE_COUNTER_XOR,
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
