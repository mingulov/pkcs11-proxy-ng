use super::FfiBackend;
use super::ffi_conversion::{FfiAttrs, mechanism_to_ffi};
use pkcs11_proxy_ng_types::*;

impl FfiBackend {
    /// `C_WrapKeyAuthenticated` — two-call pattern for wrapped_key output.
    /// Returns `(wrapped_key, mechanism_parameter_out)`.
    pub(super) fn ffi_wrap_key_authenticated(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let fl = self.func_list_3_2.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_WrapKeyAuthenticated }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let mut ffi_mech = mechanism_to_ffi(mechanism)?;

        // Save the original parameter pointer and length for read-back after the call.
        let param_ptr = ffi_mech.ck_mechanism.pParameter as *mut u8;
        let param_len = ffi_mech.ck_mechanism.ulParameterLen as usize;

        // Two-call pattern: first call with pWrappedKey = null to get size.
        let mut wrapped_key_len: cryptoki_sys::CK_ULONG = 0;
        Self::ck_result(unsafe {
            f(
                Self::session_handle(session),
                &mut ffi_mech.ck_mechanism,
                Self::object_handle(wrapping_key),
                Self::object_handle(key),
                aad.as_ptr() as *mut cryptoki_sys::CK_BYTE,
                Self::ulong_len(aad.len()),
                std::ptr::null_mut(),
                &mut wrapped_key_len,
            )
        })?;

        // Second call: allocate buffer and get wrapped key (capped to prevent OOM).
        let capped_len = (wrapped_key_len as u64).min(super::call_helpers::MAX_OUTPUT_BUFFER_BYTES);
        wrapped_key_len = capped_len as cryptoki_sys::CK_ULONG;
        let mut wrapped_key = vec![0u8; capped_len as usize];
        Self::ck_result(unsafe {
            f(
                Self::session_handle(session),
                &mut ffi_mech.ck_mechanism,
                Self::object_handle(wrapping_key),
                Self::object_handle(key),
                aad.as_ptr() as *mut cryptoki_sys::CK_BYTE,
                Self::ulong_len(aad.len()),
                wrapped_key.as_mut_ptr(),
                &mut wrapped_key_len,
            )
        })?;
        wrapped_key.truncate(wrapped_key_len as usize);

        // Read back mechanism parameter (tag/IV write-back).
        let mechanism_parameter_out = if !param_ptr.is_null() && param_len > 0 {
            unsafe { std::slice::from_raw_parts(param_ptr, param_len) }.to_vec()
        } else {
            Vec::new()
        };

        Ok((wrapped_key, mechanism_parameter_out))
    }

    /// `C_UnwrapKeyAuthenticated` — returns `(key_handle, mechanism_parameter_out)`.
    pub(super) fn ffi_unwrap_key_authenticated(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        unwrapping_key: CkObjectHandle,
        wrapped_key: &[u8],
        template: &[CkAttribute],
        aad: &[u8],
    ) -> CkResult<(CkObjectHandle, Vec<u8>)> {
        let fl = self.func_list_3_2.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_UnwrapKeyAuthenticated }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let ffi_attrs = FfiAttrs::from_slice(template);
        let mut ffi_mech = mechanism_to_ffi(mechanism)?;

        // Save the original parameter pointer and length for read-back after the call.
        let param_ptr = ffi_mech.ck_mechanism.pParameter as *mut u8;
        let param_len = ffi_mech.ck_mechanism.ulParameterLen as usize;

        let mut key_handle: cryptoki_sys::CK_OBJECT_HANDLE = 0;

        Self::ck_result(unsafe {
            f(
                Self::session_handle(session),
                &mut ffi_mech.ck_mechanism,
                Self::object_handle(unwrapping_key),
                wrapped_key.as_ptr() as *mut cryptoki_sys::CK_BYTE,
                Self::ulong_len(wrapped_key.len()),
                Self::ffi_attr_ptr(&ffi_attrs),
                Self::ffi_attr_len(&ffi_attrs),
                aad.as_ptr() as *mut cryptoki_sys::CK_BYTE,
                Self::ulong_len(aad.len()),
                &mut key_handle,
            )
        })?;

        // Read back mechanism parameter (tag/IV write-back).
        let mechanism_parameter_out = if !param_ptr.is_null() && param_len > 0 {
            unsafe { std::slice::from_raw_parts(param_ptr, param_len) }.to_vec()
        } else {
            Vec::new()
        };

        Ok((CkObjectHandle(key_handle as u64), mechanism_parameter_out))
    }

    /// `C_WrapKeyAuthenticated` — exact buffer semantics for wrapped_key output
    /// AND mechanism parameter write-back.
    pub(super) fn ffi_wrap_key_authenticated_exact(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let fl = self.func_list_3_2.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_WrapKeyAuthenticated }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let mut ffi_mech = mechanism_to_ffi(mechanism)?;

        // The mechanism parameter acts as the "parameter" input/output channel.
        // Extract pointer/len from the mechanism for use as the parameter buffer.
        let mech_param_ptr = ffi_mech.ck_mechanism.pParameter as *mut u8;
        let mech_param_len = ffi_mech.ck_mechanism.ulParameterLen as usize;
        // C_WrapKeyAuthenticated passes pParameter via the mechanism struct,
        // not as separate args. We use a direct single-call approach.
        let mut out_len: cryptoki_sys::CK_ULONG = 0;

        if !output_spec.buffer_present {
            // Size query: pass NULL for pWrappedKey.
            let rv = unsafe {
                f(
                    Self::session_handle(session),
                    &mut ffi_mech.ck_mechanism,
                    Self::object_handle(wrapping_key),
                    Self::object_handle(key),
                    aad.as_ptr() as *mut cryptoki_sys::CK_BYTE,
                    Self::ulong_len(aad.len()),
                    std::ptr::null_mut(),
                    &mut out_len,
                )
            };
            if rv == CkRv::OK.0 {
                // Read back mechanism parameter.
                let param_value = if param_out_spec.buffer_present
                    && !mech_param_ptr.is_null()
                    && mech_param_len > 0
                {
                    Some(
                        unsafe { std::slice::from_raw_parts(mech_param_ptr, mech_param_len) }
                            .to_vec(),
                    )
                } else {
                    None
                };
                let output_result = CkOutputBufferResult {
                    ck_rv: CkRv::OK,
                    returned_len: out_len as u64,
                    value: None,
                };
                let param_result = CkParameterRoundtripResult {
                    ck_rv: CkRv::OK,
                    returned_len: mech_param_len as u64,
                    value: param_value,
                };
                Ok((output_result, param_result))
            } else {
                Err(CkRv(rv))
            }
        } else {
            // Data query: allocate caller-specified buffer.
            out_len = output_spec.buffer_len as cryptoki_sys::CK_ULONG;
            let mut buf = vec![0u8; output_spec.buffer_len as usize];
            let rv = unsafe {
                f(
                    Self::session_handle(session),
                    &mut ffi_mech.ck_mechanism,
                    Self::object_handle(wrapping_key),
                    Self::object_handle(key),
                    aad.as_ptr() as *mut cryptoki_sys::CK_BYTE,
                    Self::ulong_len(aad.len()),
                    buf.as_mut_ptr(),
                    &mut out_len,
                )
            };

            if rv == CkRv::OK.0 {
                buf.truncate(out_len as usize);
                // Read back mechanism parameter.
                let param_value = if param_out_spec.buffer_present
                    && !mech_param_ptr.is_null()
                    && mech_param_len > 0
                {
                    Some(
                        unsafe { std::slice::from_raw_parts(mech_param_ptr, mech_param_len) }
                            .to_vec(),
                    )
                } else {
                    None
                };
                let output_result = CkOutputBufferResult {
                    ck_rv: CkRv::OK,
                    returned_len: out_len as u64,
                    value: Some(buf),
                };
                let param_result = CkParameterRoundtripResult {
                    ck_rv: CkRv::OK,
                    returned_len: mech_param_len as u64,
                    value: param_value,
                };
                Ok((output_result, param_result))
            } else if rv == CkRv::BUFFER_TOO_SMALL.0 {
                let output_result = CkOutputBufferResult {
                    ck_rv: CkRv::BUFFER_TOO_SMALL,
                    returned_len: out_len as u64,
                    value: None,
                };
                let param_result = CkParameterRoundtripResult {
                    ck_rv: CkRv::BUFFER_TOO_SMALL,
                    returned_len: mech_param_len as u64,
                    value: None,
                };
                Ok((output_result, param_result))
            } else {
                Err(CkRv(rv))
            }
        }
    }
}
