//! Capture authenticated caller memory once; write only allowed owned outputs.
use super::*;
use pkcs11_proxy_ng_proto::convert::authenticated::{
    AuthenticatedOutput, authenticated_shape, validate_input,
};
use pkcs11_proxy_ng_proto::convert::message_params::{MessageParameter, MessageParameterShape};

pub(crate) struct AuthenticatedCall {
    pub(crate) mechanism: CkMechanism,
    message: Option<MessageParameterCall>,
    parameter_spec: CkParameterRoundtripSpec,
    iv_target: *mut u8,
}

impl AuthenticatedCall {
    pub(crate) fn parameter(&self) -> Option<&MessageParameter> {
        self.message.as_ref().and_then(MessageParameterCall::parameter)
    }

    /// # Safety
    /// Every supplied non-null pointer must satisfy the PKCS#11 caller's
    /// readable/writable extent contract for this call.
    pub(crate) unsafe fn read(
        mechanism: CK_MECHANISM_PTR,
        direction: MessageParameterDirection,
        memory: MessageCallMemory,
    ) -> CkResult<Self> {
        if mechanism.is_null() {
            return Err(CkRv::ARGUMENTS_BAD);
        }
        validate_message_mechanism_outer(mechanism)?;
        let outer = unsafe { std::ptr::read_unaligned(mechanism) };
        let shape = authenticated_shape(CkMechanismType(outer.mechanism as u64));
        let memory = memory.with_mechanism(mechanism);
        let parameter_spec = CkParameterRoundtripSpec {
            buffer_present: !outer.pParameter.is_null(),
            buffer_len: outer.ulParameterLen as u64,
            value: None,
        };
        if shape != MessageParameterShape::Unmodeled {
            // No generic mechanism reader: the authenticated entrypoint uses
            // message layouts, including distinct IV/tag and nonce/MAC buffers.
            let message = unsafe {
                read_message_parameter_call_for_shape_with_memory(
                    outer.pParameter,
                    outer.ulParameterLen,
                    shape,
                    direction,
                    MessageParameterStage::OneShot,
                    memory,
                )
            }?;
            if message.parameter().is_none()
                && (parameter_spec.buffer_present || parameter_spec.buffer_len != 0)
            {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            return Ok(Self {
                mechanism: CkMechanism {
                    mechanism_type: CkMechanismType(outer.mechanism as u64),
                    params: None,
                },
                message: Some(message),
                parameter_spec,
                iv_target: std::ptr::null_mut(),
            });
        }
        validate_message_caller_ranges(memory, outer.pParameter, outer.ulParameterLen as u64, &[])?;
        let rv = unsafe { validate_mechanism(mechanism) };
        if rv != CKR_OK {
            return Err(CkRv(rv as u64));
        }
        let mechanism = unsafe { read_mechanism(mechanism) };
        validate_input(&mechanism, None)?;
        let iv_target = if matches!(mechanism.params, Some(CkMechanismParams::Iv(_))) {
            outer.pParameter.cast()
        } else {
            std::ptr::null_mut()
        };
        Ok(Self { mechanism, message: None, parameter_spec, iv_target })
    }

    /// Validate all channels before writing any caller bytes or lengths.
    pub(crate) unsafe fn write_output(
        &self,
        spec: &CkOutputBufferSpec,
        main: &CkOutputBufferResult,
        output: &AuthenticatedOutput,
        buffer: CK_BYTE_PTR,
        length: CK_ULONG_PTR,
    ) -> CK_RV {
        if output.validate_for(&self.mechanism, self.parameter()).is_err()
            || validate_exact_output_result(main, spec).is_err()
            || buffer.is_null() == spec.buffer_present
            || length.is_null() != spec.length_pointer_null
        {
            return rv_err(CkRv::GENERAL_ERROR);
        }
        if let Some(message) = &self.message {
            let legacy_effects;
            let parameter = match output {
                AuthenticatedOutput::Message(p) => {
                    legacy_effects =
                        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects::capture(
                            self.parameter().expect("captured message input"),
                            p,
                            super::message_params::effect_context(message, main.ck_rv, spec),
                        );
                    Some(&legacy_effects)
                }
                AuthenticatedOutput::Effects(effects) => Some(effects),
                _ => None,
            };
            let ack = CkParameterRoundtripResult {
                ck_rv: main.ck_rv,
                returned_len: self.parameter_spec.buffer_len,
                value: self.parameter_spec.buffer_present.then(Vec::new),
            };
            return unsafe {
                write_exact_message_output(
                    spec,
                    &self.parameter_spec,
                    message,
                    main,
                    &ack,
                    parameter,
                    buffer,
                    length,
                )
            };
        }
        if main.returned_len.is_some_and(|n| CK_ULONG::try_from(n).is_err()) {
            return rv_err(CkRv::GENERAL_ERROR);
        }
        if let AuthenticatedOutput::Iv(iv) = output
            && !iv.is_empty()
        {
            if self.iv_target.is_null() {
                return rv_err(CkRv::GENERAL_ERROR);
            }
            unsafe { std::ptr::copy_nonoverlapping(iv.as_ptr(), self.iv_target, iv.len()) };
        }
        unsafe { write_exact_output(spec, main, buffer, length) }
    }

    pub(crate) unsafe fn write_parameter(&self, output: &AuthenticatedOutput) -> CK_RV {
        let mut length = 0;
        unsafe {
            self.write_output(
                &CkOutputBufferSpec {
                    buffer_present: false,
                    buffer_len: 0,
                    length_pointer_null: false,
                },
                &CkOutputBufferResult { ck_rv: CkRv::OK, returned_len: Some(0), value: None },
                output,
                std::ptr::null_mut(),
                &mut length,
            )
        }
    }
}
