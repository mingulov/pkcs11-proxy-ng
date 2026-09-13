//! Authenticated native calls and pointer-free, output-only readback.
use super::FfiBackend;
use super::ffi_conversion::{FfiAttrs, FfiMechanism, mechanism_to_ffi, narrow_wire_ulong};
use pkcs11_proxy_ng_proto::convert::authenticated::{AuthenticatedOutput, validate_input};
use pkcs11_proxy_ng_proto::convert::message_params::MessageParameter;
use pkcs11_proxy_ng_types::*;

enum NativeParameter<'a> {
    Mechanism(FfiMechanism),
    Message(super::message_ops::MessageInitMechanism, &'a MessageParameter),
}

impl NativeParameter<'_> {
    fn pointer(&mut self) -> cryptoki_sys::CK_MECHANISM_PTR {
        match self {
            Self::Mechanism(ffi) => &mut ffi.ck_mechanism,
            Self::Message(ffi, _) => &mut ffi.ck_mechanism,
        }
    }
    fn output(&self) -> CkResult<AuthenticatedOutput> {
        match self {
            Self::Mechanism(ffi) => ffi.authenticated_output(),
            Self::Message(ffi, input) => {
                Ok(AuthenticatedOutput::Message(ffi.authenticated_output(input)?))
            }
        }
    }
}

fn with_parameter<T>(
    mechanism: &CkMechanism,
    parameter: Option<&MessageParameter>,
    call: impl FnOnce(&mut NativeParameter<'_>) -> CkResult<T>,
) -> CkResult<(T, AuthenticatedOutput)> {
    validate_input(mechanism, parameter)?;
    let mut native = if let Some(parameter) = parameter {
        NativeParameter::Message(
            super::message_ops::build_message_init_mechanism(
                narrow_wire_ulong(mechanism.mechanism_type.0)?,
                parameter,
            )?,
            parameter,
        )
    } else {
        NativeParameter::Mechanism(mechanism_to_ffi(mechanism)?)
    };
    let result = call(&mut native)?;
    Ok((result, native.output()?))
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
            native.output()?;
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
        with_parameter(mechanism, parameter, |native| {
            Self::single_call_bytes_exact(spec, |output, length| unsafe {
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
            })
        })
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
        let fl = self.func_list_3_2.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_UnwrapKeyAuthenticated }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let attrs = FfiAttrs::from_slice(template)?;
        let (aad_ptr, aad_len) = aad.as_ptr_len();
        let aad_len = narrow_wire_ulong(aad_len)?;
        let (wrapped_ptr, wrapped_len) = wrapped_key.as_ptr_len();
        let wrapped_len = narrow_wire_ulong(wrapped_len)?;
        let (handle, output) = with_parameter(mechanism, parameter, |native| {
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
            Ok(CkObjectHandle(handle as u64))
        })?;
        // AEAD unwrap consumes the IV and authentication value; those buffers
        // are input-only. Keep the validated acknowledgment, but no provider
        // mutation is authorized to modify these caller inputs.
        let output = parameter.map_or(output, |p| AuthenticatedOutput::Message(p.clone()));
        Ok((handle, output))
    }
}
