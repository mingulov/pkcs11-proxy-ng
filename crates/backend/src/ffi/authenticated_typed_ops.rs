//! Authenticated native calls and pointer-free, output-only readback.
use super::FfiBackend;
use super::ffi_conversion::{FfiAttrs, FfiMechanism, mechanism_to_ffi, narrow_wire_ulong};
use pkcs11_proxy_ng_proto::convert::authenticated::{AuthenticatedOutput, validate_input};
use pkcs11_proxy_ng_proto::convert::message_effects::ParameterEffectCallMode;
use pkcs11_proxy_ng_proto::convert::message_params::MessageParameter;
use pkcs11_proxy_ng_types::*;

enum NativeStorage<'a> {
    Mechanism(FfiMechanism),
    Message(super::message_ops::MessageInitMechanism, &'a MessageParameter),
}

struct NativeParameter<'a> {
    storage: NativeStorage<'a>,
    // Fieldwise snapshot, never serialized or compared as a native image.
    original: cryptoki_sys::CK_MECHANISM,
    input: &'a CkMechanism,
}

impl<'a> NativeParameter<'a> {
    fn new(mechanism: &'a CkMechanism, parameter: Option<&'a MessageParameter>) -> CkResult<Self> {
        validate_input(mechanism, parameter)?;
        let storage = if let Some(parameter) = parameter {
            NativeStorage::Message(
                super::message_ops::build_message_init_mechanism(
                    narrow_wire_ulong(mechanism.mechanism_type.0)?,
                    parameter,
                )?,
                parameter,
            )
        } else {
            NativeStorage::Mechanism(mechanism_to_ffi(mechanism)?)
        };
        let original = match &storage {
            NativeStorage::Mechanism(ffi) => ffi.ck_mechanism,
            NativeStorage::Message(ffi, _) => ffi.ck_mechanism,
        };
        Ok(Self { storage, original, input: mechanism })
    }

    fn pointer(&mut self) -> cryptoki_sys::CK_MECHANISM_PTR {
        match &mut self.storage {
            NativeStorage::Mechanism(ffi) => &mut ffi.ck_mechanism,
            NativeStorage::Message(ffi, _) => &mut ffi.ck_mechanism,
        }
    }
    fn validate_inputs(&self) -> CkResult<()> {
        let outer = match &self.storage {
            NativeStorage::Mechanism(ffi) => &ffi.ck_mechanism,
            NativeStorage::Message(ffi, _) => &ffi.ck_mechanism,
        };
        if outer.mechanism != self.original.mechanism
            || outer.pParameter != self.original.pParameter
            || outer.ulParameterLen != self.original.ulParameterLen
        {
            return Err(CkRv::DEVICE_ERROR);
        }
        match &self.storage {
            NativeStorage::Mechanism(ffi) => ffi.validate_authenticated_inputs(self.input),
            NativeStorage::Message(ffi, input) => ffi.validate_authenticated_inputs(input),
        }
    }
    fn read_output(&self) -> CkResult<AuthenticatedOutput> {
        match &self.storage {
            NativeStorage::Mechanism(ffi) => ffi.authenticated_output(),
            NativeStorage::Message(ffi, input) => {
                Ok(AuthenticatedOutput::Message(ffi.authenticated_output(input)))
            }
        }
    }
}

fn with_parameter<T>(
    mechanism: &CkMechanism,
    parameter: Option<&MessageParameter>,
    call: impl FnOnce(&mut NativeParameter<'_>) -> CkResult<T>,
) -> CkResult<(T, AuthenticatedOutput)> {
    let mut native = NativeParameter::new(mechanism, parameter)?;
    let result = call(&mut native)?;
    native.validate_inputs()?;
    Ok((result, native.read_output()?))
}

impl FfiBackend {
    pub(super) fn ffi_wrap_authenticated_typed(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        parameter: Option<&MessageParameter>,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
    ) -> CkResult<(Vec<u8>, AuthenticatedOutput)> {
        let fl = self.func_list_3_2.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_WrapKeyAuthenticated }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let (aad_ptr, aad_len) = aad.as_ptr_len();
        let aad_len = narrow_wire_ulong(aad_len)?;
        with_parameter(mechanism, parameter, |native| {
            let mut len = 0;
            Self::ck_result(unsafe {
                f(
                    Self::session_handle(session),
                    native.pointer(),
                    Self::object_handle(wrapping_key),
                    Self::object_handle(key),
                    aad_ptr.cast_mut(),
                    aad_len,
                    std::ptr::null_mut(),
                    &mut len,
                )
            })?;
            // Validate the first provider call before allowing a second call
            // to observe any changed native pointer or scalar field.
            native.validate_inputs()?;
            let size = super::call_helpers::capped_output_len(len as u64);
            let mut bytes = vec![0; size];
            len = size as cryptoki_sys::CK_ULONG;
            Self::ck_result(unsafe {
                f(
                    Self::session_handle(session),
                    native.pointer(),
                    Self::object_handle(wrapping_key),
                    Self::object_handle(key),
                    aad_ptr.cast_mut(),
                    aad_len,
                    bytes.as_mut_ptr(),
                    &mut len,
                )
            })?;
            bytes.truncate(len as usize);
            Ok(bytes)
        })
    }

    pub(super) fn ffi_wrap_authenticated_exact_typed(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        parameter: Option<&MessageParameter>,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, AuthenticatedOutput)> {
        let fl = self.func_list_3_2.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_WrapKeyAuthenticated }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let (aad_ptr, aad_len) = aad.as_ptr_len();
        let aad_len = narrow_wire_ulong(aad_len)?;
        let mut native = NativeParameter::new(mechanism, parameter)?;
        let output = Self::single_call_bytes_exact(spec, |output, length| unsafe {
            f(
                Self::session_handle(session),
                native.pointer(),
                Self::object_handle(wrapping_key),
                Self::object_handle(key),
                aad_ptr.cast_mut(),
                aad_len,
                output,
                length,
            )
        })?;
        let effects = if native.validate_inputs().is_err() {
            AuthenticatedOutput::Invalid(OutputContractViolation::ParameterIntegrity)
        } else {
            match native.read_output() {
                Ok(AuthenticatedOutput::Message(post)) => {
                    let effects =
                        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects::capture(
                            parameter.expect("message storage has immutable typed input"),
                            &post,
                            pkcs11_proxy_ng_proto::convert::message_effects::MessageEffectContext {
                                mode: ParameterEffectCallMode::from_output_spec(spec),
                                encrypt: true,
                                generated_stage: true,
                                auth_stage: true,
                                rv: output.ck_rv,
                            },
                        );
                    AuthenticatedOutput::Effects(effects)
                }
                Ok(other) => other,
                Err(_) => AuthenticatedOutput::Invalid(OutputContractViolation::ParameterIntegrity),
            }
        };
        Ok((output, effects))
    }

    pub(super) fn ffi_unwrap_authenticated_typed(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        parameter: Option<&MessageParameter>,
        unwrapping_key: CkObjectHandle,
        wrapped_key: CkInBuf<'_>,
        template: &[CkAttribute],
        aad: CkInBuf<'_>,
    ) -> CkResult<(CkObjectHandle, AuthenticatedOutput)> {
        self.object_cleanup.ensure_clear()?;
        let fl = self.func_list_3_2.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_UnwrapKeyAuthenticated }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let attrs = FfiAttrs::from_slice(template)?;
        let (aad_ptr, aad_len) = aad.as_ptr_len();
        let aad_len = narrow_wire_ulong(aad_len)?;
        let (wrapped_ptr, wrapped_len) = wrapped_key.as_ptr_len();
        let wrapped_len = narrow_wire_ulong(wrapped_len)?;
        let mut native = NativeParameter::new(mechanism, parameter)?;
        let mut handle = 0;
        Self::ck_result(unsafe {
            f(
                Self::session_handle(session),
                native.pointer(),
                Self::object_handle(unwrapping_key),
                wrapped_ptr.cast_mut(),
                wrapped_len,
                Self::ffi_attr_ptr(&attrs),
                Self::ffi_attr_len(&attrs),
                aad_ptr.cast_mut(),
                aad_len,
                &mut handle,
            )
        })?;
        let created = crate::object_cleanup::PendingNativeObject::new(
            self,
            &self.object_cleanup,
            session,
            CkObjectHandle(handle as u64),
        );
        native.validate_inputs()?;
        let output = native.read_output()?;
        // AEAD unwrap consumes the IV and authentication value; those buffers
        // are input-only. Keep the validated acknowledgment, but no provider
        // mutation is authorized to modify these caller inputs.
        let output = parameter.map_or(output, |p| AuthenticatedOutput::Message(p.clone()));
        Ok((created.transfer(), output))
    }
}
