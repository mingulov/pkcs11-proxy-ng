use super::FfiBackend;
use super::ffi_conversion::{FfiAttrs, mechanism_to_ffi};
use pkcs11_proxy_ng_types::*;

impl FfiBackend {
    /// Legacy convenience `C_WrapKeyAuthenticated` path using two provider calls.
    /// Exact caller-buffer forwarding uses `ffi_wrap_key_authenticated_exact`.
    /// Returns `(wrapped_key, mechanism_parameter_out)`.
    pub(super) fn ffi_wrap_key_authenticated(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let fl = self.func_list_3_2.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_WrapKeyAuthenticated }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let mut ffi_mech = mechanism_to_ffi(mechanism)?;

        // Save the original parameter pointer and length for read-back after the call.
        let param_ptr = ffi_mech.ck_mechanism.pParameter as *mut u8;
        let param_len = ffi_mech.ck_mechanism.ulParameterLen as usize;

        let (aad_ptr, aad_len) = aad.as_ptr_len();

        // Two-call pattern: first call with pWrappedKey = null to get size.
        let mut wrapped_key_len: cryptoki_sys::CK_ULONG = 0;
        Self::ck_result(unsafe {
            f(
                Self::session_handle(session),
                &mut ffi_mech.ck_mechanism,
                Self::object_handle(wrapping_key),
                Self::object_handle(key),
                aad_ptr as *mut cryptoki_sys::CK_BYTE,
                Self::ulong_len_u64(aad_len),
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
                aad_ptr as *mut cryptoki_sys::CK_BYTE,
                Self::ulong_len_u64(aad_len),
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
        wrapped_key: CkInBuf<'_>,
        template: &[CkAttribute],
        aad: CkInBuf<'_>,
    ) -> CkResult<(CkObjectHandle, Vec<u8>)> {
        let fl = self.func_list_3_2.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_UnwrapKeyAuthenticated }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let ffi_attrs = FfiAttrs::from_slice(template)?;
        let mut ffi_mech = mechanism_to_ffi(mechanism)?;

        // Save the original parameter pointer and length for read-back after the call.
        let param_ptr = ffi_mech.ck_mechanism.pParameter as *mut u8;
        let param_len = ffi_mech.ck_mechanism.ulParameterLen as usize;

        let (wk_ptr, wk_len) = wrapped_key.as_ptr_len();
        let (aad_ptr, aad_len) = aad.as_ptr_len();

        let mut key_handle: cryptoki_sys::CK_OBJECT_HANDLE = 0;

        Self::ck_result(unsafe {
            f(
                Self::session_handle(session),
                &mut ffi_mech.ck_mechanism,
                Self::object_handle(unwrapping_key),
                wk_ptr as *mut cryptoki_sys::CK_BYTE,
                Self::ulong_len_u64(wk_len),
                Self::ffi_attr_ptr(&ffi_attrs),
                Self::ffi_attr_len(&ffi_attrs),
                aad_ptr as *mut cryptoki_sys::CK_BYTE,
                Self::ulong_len_u64(aad_len),
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
        aad: CkInBuf<'_>,
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
        let (aad_ptr, aad_len) = aad.as_ptr_len();
        let mut out_len: cryptoki_sys::CK_ULONG = 0;

        if output_spec.length_pointer_null {
            let output = if output_spec.buffer_present {
                std::ptr::NonNull::<cryptoki_sys::CK_BYTE>::dangling().as_ptr()
            } else {
                std::ptr::null_mut()
            };
            let rv = CkRv(unsafe {
                f(
                    Self::session_handle(session),
                    &mut ffi_mech.ck_mechanism,
                    Self::object_handle(wrapping_key),
                    Self::object_handle(key),
                    aad_ptr as *mut cryptoki_sys::CK_BYTE,
                    Self::ulong_len_u64(aad_len),
                    output,
                    std::ptr::null_mut(),
                )
            } as u64);
            if rv != CkRv::OK && rv != CkRv::BUFFER_TOO_SMALL {
                return Err(rv);
            }
            let param_value = if param_out_spec.buffer_present
                && !mech_param_ptr.is_null()
                && mech_param_len > 0
            {
                Some(unsafe { std::slice::from_raw_parts(mech_param_ptr, mech_param_len) }.to_vec())
            } else {
                None
            };
            return Ok((
                CkOutputBufferResult { ck_rv: rv, returned_len: 0, value: None },
                CkParameterRoundtripResult {
                    ck_rv: rv,
                    returned_len: mech_param_len as u64,
                    value: param_value,
                },
            ));
        }

        if !output_spec.buffer_present {
            // Size query: pass NULL for pWrappedKey.
            let rv = unsafe {
                f(
                    Self::session_handle(session),
                    &mut ffi_mech.ck_mechanism,
                    Self::object_handle(wrapping_key),
                    Self::object_handle(key),
                    aad_ptr as *mut cryptoki_sys::CK_BYTE,
                    Self::ulong_len_u64(aad_len),
                    std::ptr::null_mut(),
                    &mut out_len,
                )
            };
            if rv == CkRv::OK.0 as cryptoki_sys::CK_RV {
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
                Err(CkRv(rv as u64))
            }
        } else {
            // Data query: allocate caller-specified buffer.
            let capped = super::call_helpers::capped_output_len(output_spec.buffer_len);
            out_len = capped as cryptoki_sys::CK_ULONG;
            let mut buf = vec![0u8; capped];
            let rv = unsafe {
                f(
                    Self::session_handle(session),
                    &mut ffi_mech.ck_mechanism,
                    Self::object_handle(wrapping_key),
                    Self::object_handle(key),
                    aad_ptr as *mut cryptoki_sys::CK_BYTE,
                    Self::ulong_len_u64(aad_len),
                    buf.as_mut_ptr(),
                    &mut out_len,
                )
            };

            if rv == CkRv::OK.0 as cryptoki_sys::CK_RV {
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
            } else if rv == CkRv::BUFFER_TOO_SMALL.0 as cryptoki_sys::CK_RV {
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
                Err(CkRv(rv as u64))
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static OUTPUT_PRESENT: AtomicUsize = AtomicUsize::new(0);
    static LENGTH_NULL: AtomicUsize = AtomicUsize::new(0);
    static RETURN_RV: AtomicUsize = AtomicUsize::new(cryptoki_sys::CKR_OK as usize);
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe extern "C" fn missing_length_wrap(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        mechanism: cryptoki_sys::CK_MECHANISM_PTR,
        _wrapping_key: cryptoki_sys::CK_OBJECT_HANDLE,
        _key: cryptoki_sys::CK_OBJECT_HANDLE,
        _aad: cryptoki_sys::CK_BYTE_PTR,
        _aad_len: cryptoki_sys::CK_ULONG,
        output: cryptoki_sys::CK_BYTE_PTR,
        output_len: cryptoki_sys::CK_ULONG_PTR,
    ) -> cryptoki_sys::CK_RV {
        CALLS.fetch_add(1, Ordering::SeqCst);
        OUTPUT_PRESENT.store(usize::from(!output.is_null()), Ordering::SeqCst);
        LENGTH_NULL.store(usize::from(output_len.is_null()), Ordering::SeqCst);
        if !mechanism.is_null() {
            let mechanism = unsafe { &mut *mechanism };
            if !mechanism.pParameter.is_null() && mechanism.ulParameterLen > 0 {
                unsafe { *mechanism.pParameter.cast::<u8>() = 0xA5 };
            }
        }
        RETURN_RV.load(Ordering::SeqCst) as cryptoki_sys::CK_RV
    }

    fn backend_with_missing_length_wrap()
    -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>, Box<cryptoki_sys::CK_FUNCTION_LIST_3_2>)
    {
        let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_2::default());
        functions.C_WrapKeyAuthenticated = Some(missing_length_wrap);
        let backend = FfiBackend {
            _lib: libloading::os::unix::Library::this().into(),
            func_list: base.as_mut(),
            func_list_3_0: None,
            func_list_3_2: Some(functions.as_ref()),
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
        };
        (backend, base, functions)
    }

    #[test]
    fn null_output_length_authenticated_wrap_forwards_once_and_keeps_parameter_output() {
        let _guard = TEST_LOCK.lock().unwrap();
        CALLS.store(0, Ordering::SeqCst);
        OUTPUT_PRESENT.store(0, Ordering::SeqCst);
        LENGTH_NULL.store(0, Ordering::SeqCst);
        RETURN_RV.store(cryptoki_sys::CKR_OK as usize, Ordering::SeqCst);
        let (backend, _base, _functions) = backend_with_missing_length_wrap();
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType::AES_CBC,
            params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0x11; 16] })),
        };
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true };
        let parameter_spec = CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: 16,
            value: Some(vec![0x11; 16]),
        };

        let (output, parameter) = backend
            .ffi_wrap_key_authenticated_exact(
                CkSessionHandle(1),
                &mechanism,
                CkObjectHandle(2),
                CkObjectHandle(3),
                CkInBuf::Bytes(b"aad"),
                &output_spec,
                &parameter_spec,
            )
            .expect("provider result envelope");

        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(OUTPUT_PRESENT.load(Ordering::SeqCst), 1);
        assert_eq!(LENGTH_NULL.load(Ordering::SeqCst), 1);
        assert_eq!(output.ck_rv, CkRv::OK);
        assert_eq!(output.returned_len, 0);
        assert_eq!(output.value, None);
        assert_eq!(parameter.ck_rv, CkRv::OK);
        assert_eq!(parameter.returned_len, 16);
        assert_eq!(parameter.value.as_ref().map(|value| value[0]), Some(0xA5));
    }

    #[test]
    fn null_output_length_authenticated_wrap_preserves_buffer_too_small_and_parameter_output() {
        let _guard = TEST_LOCK.lock().unwrap();
        CALLS.store(0, Ordering::SeqCst);
        RETURN_RV.store(cryptoki_sys::CKR_BUFFER_TOO_SMALL as usize, Ordering::SeqCst);
        let (backend, _base, _functions) = backend_with_missing_length_wrap();
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType::AES_CBC,
            params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0x11; 16] })),
        };
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true };
        let parameter_spec = CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: 16,
            value: Some(vec![0x11; 16]),
        };

        let (output, parameter) = backend
            .ffi_wrap_key_authenticated_exact(
                CkSessionHandle(1),
                &mechanism,
                CkObjectHandle(2),
                CkObjectHandle(3),
                CkInBuf::Bytes(b"aad"),
                &output_spec,
                &parameter_spec,
            )
            .expect("provider result envelope");

        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(output.ck_rv, CkRv::BUFFER_TOO_SMALL);
        assert_eq!(output.returned_len, 0);
        assert_eq!(output.value, None);
        assert_eq!(parameter.ck_rv, CkRv::BUFFER_TOO_SMALL);
        assert_eq!(parameter.returned_len, 16);
        assert_eq!(parameter.value.as_ref().map(|value| value[0]), Some(0xA5));
    }
}
