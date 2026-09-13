use super::{FfiBackend, call_3x_fn, ffi_conversion::mechanism_to_ffi};
use pkcs11_proxy_ng_types::*;

impl FfiBackend {
    /// Exact-output variant of `C_EncapsulateKey`.
    ///
    /// Unlike the convenience `ffi_encapsulate_key`, this performs a single FFI
    /// call matching the caller's buffer spec:
    /// - Size query (`!spec.buffer_present`): passes NULL pCiphertext to get size.
    ///   The backend should NOT create a key in this case — returns handle 0.
    /// - Data query (`spec.buffer_present`): allocates the caller-specified buffer,
    ///   captures both ciphertext and the created key handle.
    pub(super) fn ffi_encapsulate_key_exact(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        public_key: CkObjectHandle,
        template: &[CkAttribute],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputAndHandleResult> {
        use super::ffi_conversion::FfiAttrs;

        let fl = self.func_list_3_2.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let function = unsafe { (*fl).C_EncapsulateKey }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let mut ffi_mech = mechanism_to_ffi(mechanism)?;
        let ffi_attrs = FfiAttrs::from_slice(template)?;

        let mut out_len: cryptoki_sys::CK_ULONG = 0;
        let mut key_handle: cryptoki_sys::CK_OBJECT_HANDLE = 0;

        if spec.length_pointer_null {
            let output = if spec.buffer_present {
                std::ptr::NonNull::<cryptoki_sys::CK_BYTE>::dangling().as_ptr()
            } else {
                std::ptr::null_mut()
            };
            let rv = CkRv(unsafe {
                function(
                    Self::session_handle(session),
                    &mut ffi_mech.ck_mechanism,
                    Self::object_handle(public_key),
                    Self::ffi_attr_ptr(&ffi_attrs),
                    Self::ffi_attr_len(&ffi_attrs),
                    output,
                    std::ptr::null_mut(),
                    &mut key_handle,
                )
            } as u64);
            if !rv.is_ok() {
                return Err(rv);
            }
            return Ok(CkOutputAndHandleResult {
                ck_rv: rv,
                returned_len: 0,
                value: None,
                object_handle: CkObjectHandle(key_handle as u64),
            });
        }

        if !spec.buffer_present {
            // Size query: pass NULL pCiphertext
            let rv = unsafe {
                function(
                    Self::session_handle(session),
                    &mut ffi_mech.ck_mechanism,
                    Self::object_handle(public_key),
                    Self::ffi_attr_ptr(&ffi_attrs),
                    Self::ffi_attr_len(&ffi_attrs),
                    std::ptr::null_mut(),
                    &mut out_len,
                    &mut key_handle,
                )
            };
            if rv == CkRv::OK.0 as cryptoki_sys::CK_RV
                || rv == CkRv::BUFFER_TOO_SMALL.0 as cryptoki_sys::CK_RV
            {
                // Both CKR_OK and CKR_BUFFER_TOO_SMALL are valid size-query
                // responses (NSS returns BUFFER_TOO_SMALL). Propagate the
                // returned length so the caller can allocate correctly.
                Ok(CkOutputAndHandleResult {
                    ck_rv: CkRv(rv as u64),
                    returned_len: out_len as u64,
                    value: None,
                    object_handle: CkObjectHandle(if rv == CkRv::OK.0 as cryptoki_sys::CK_RV {
                        key_handle as u64
                    } else {
                        0
                    }),
                })
            } else {
                Err(CkRv(rv as u64))
            }
        } else {
            // Data query: allocate caller-specified buffer
            let capped = super::call_helpers::capped_output_len(spec.buffer_len);
            out_len = capped as cryptoki_sys::CK_ULONG;
            let mut buf = vec![0u8; capped];
            let rv = unsafe {
                function(
                    Self::session_handle(session),
                    &mut ffi_mech.ck_mechanism,
                    Self::object_handle(public_key),
                    Self::ffi_attr_ptr(&ffi_attrs),
                    Self::ffi_attr_len(&ffi_attrs),
                    buf.as_mut_ptr(),
                    &mut out_len,
                    &mut key_handle,
                )
            };
            if rv == CkRv::OK.0 as cryptoki_sys::CK_RV {
                buf.truncate(out_len as usize);
                Ok(CkOutputAndHandleResult {
                    ck_rv: CkRv::OK,
                    returned_len: out_len as u64,
                    value: Some(buf),
                    object_handle: CkObjectHandle(key_handle as u64),
                })
            } else if rv == CkRv::BUFFER_TOO_SMALL.0 as cryptoki_sys::CK_RV {
                Ok(CkOutputAndHandleResult {
                    ck_rv: CkRv::BUFFER_TOO_SMALL,
                    returned_len: out_len as u64,
                    value: None,
                    object_handle: CkObjectHandle(0),
                })
            } else {
                Err(CkRv(rv as u64))
            }
        }
    }

    pub(super) fn ffi_encapsulate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        public_key: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<(Vec<u8>, CkObjectHandle)> {
        use super::ffi_conversion::FfiAttrs;

        let fl = self.func_list_3_2.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let function = unsafe { (*fl).C_EncapsulateKey }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let mut ffi_mech = mechanism_to_ffi(mechanism)?;
        let ffi_attrs = FfiAttrs::from_slice(template)?;

        // Two-call pattern: first call with pCiphertext=null to get size.
        let mut ciphertext_len: cryptoki_sys::CK_ULONG = 0;
        let mut key_handle: cryptoki_sys::CK_OBJECT_HANDLE = 0;
        Self::ck_result(unsafe {
            function(
                Self::session_handle(session),
                &mut ffi_mech.ck_mechanism,
                Self::object_handle(public_key),
                Self::ffi_attr_ptr(&ffi_attrs),
                Self::ffi_attr_len(&ffi_attrs),
                std::ptr::null_mut(),
                &mut ciphertext_len,
                &mut key_handle,
            )
        })?;

        // Second call: allocate buffer and get ciphertext + key handle (capped to prevent OOM).
        let capped_len = (ciphertext_len as u64).min(super::call_helpers::MAX_OUTPUT_BUFFER_BYTES);
        ciphertext_len = capped_len as cryptoki_sys::CK_ULONG;
        let mut ciphertext = vec![0u8; capped_len as usize];
        Self::ck_result(unsafe {
            function(
                Self::session_handle(session),
                &mut ffi_mech.ck_mechanism,
                Self::object_handle(public_key),
                Self::ffi_attr_ptr(&ffi_attrs),
                Self::ffi_attr_len(&ffi_attrs),
                ciphertext.as_mut_ptr(),
                &mut ciphertext_len,
                &mut key_handle,
            )
        })?;
        ciphertext.truncate(ciphertext_len as usize);

        Ok((ciphertext, CkObjectHandle(key_handle as u64)))
    }

    pub(super) fn ffi_decapsulate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        private_key: CkObjectHandle,
        template: &[CkAttribute],
        ciphertext: CkInBuf<'_>,
    ) -> CkResult<CkObjectHandle> {
        use super::ffi_conversion::FfiAttrs;

        let ffi_attrs = FfiAttrs::from_slice(template)?;
        let mut ffi_mech = mechanism_to_ffi(mechanism)?;
        let (ct_ptr, ct_len) = ciphertext.as_ptr_len();
        let mut key_handle: cryptoki_sys::CK_OBJECT_HANDLE = 0;

        call_3x_fn!(
            self,
            func_list_3_2,
            C_DecapsulateKey,
            Self::session_handle(session),
            &mut ffi_mech.ck_mechanism,
            Self::object_handle(private_key),
            Self::ffi_attr_ptr(&ffi_attrs),
            Self::ffi_attr_len(&ffi_attrs),
            ct_ptr as *mut cryptoki_sys::CK_BYTE,
            Self::ulong_len_u64(ct_len),
            &mut key_handle
        )?;

        Ok(CkObjectHandle(key_handle as u64))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static OUTPUT_PRESENT: AtomicUsize = AtomicUsize::new(0);
    static LENGTH_NULL: AtomicUsize = AtomicUsize::new(0);
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe extern "C" fn missing_length_encapsulate(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _mechanism: cryptoki_sys::CK_MECHANISM_PTR,
        _public_key: cryptoki_sys::CK_OBJECT_HANDLE,
        _template: cryptoki_sys::CK_ATTRIBUTE_PTR,
        _attribute_count: cryptoki_sys::CK_ULONG,
        output: cryptoki_sys::CK_BYTE_PTR,
        output_len: cryptoki_sys::CK_ULONG_PTR,
        key: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
    ) -> cryptoki_sys::CK_RV {
        CALLS.fetch_add(1, Ordering::SeqCst);
        OUTPUT_PRESENT.store(usize::from(!output.is_null()), Ordering::SeqCst);
        LENGTH_NULL.store(usize::from(output_len.is_null()), Ordering::SeqCst);
        if !key.is_null() {
            unsafe { *key = 0x44 };
        }
        cryptoki_sys::CKR_OK
    }

    fn backend_with_missing_length_encapsulate()
    -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>, Box<cryptoki_sys::CK_FUNCTION_LIST_3_2>)
    {
        let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_2::default());
        functions.C_EncapsulateKey = Some(missing_length_encapsulate);
        let backend = FfiBackend {
            _lib: libloading::os::unix::Library::this().into(),
            func_list: base.as_mut(),
            func_list_3_0: None,
            func_list_3_2: Some(functions.as_ref()),
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
        };
        (backend, base, functions)
    }

    #[test]
    fn null_output_length_kem_forwards_once_and_preserves_provider_handle() {
        let _guard = TEST_LOCK.lock().unwrap();
        CALLS.store(0, Ordering::SeqCst);
        OUTPUT_PRESENT.store(0, Ordering::SeqCst);
        LENGTH_NULL.store(0, Ordering::SeqCst);
        let (backend, _base, _functions) = backend_with_missing_length_encapsulate();
        let mechanism = CkMechanism { mechanism_type: CkMechanismType(0x0000_0017), params: None };
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true };

        let result = backend
            .ffi_encapsulate_key_exact(
                CkSessionHandle(1),
                &mechanism,
                CkObjectHandle(2),
                &[],
                &output_spec,
            )
            .expect("provider result envelope");

        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(OUTPUT_PRESENT.load(Ordering::SeqCst), 1);
        assert_eq!(LENGTH_NULL.load(Ordering::SeqCst), 1);
        assert_eq!(result.ck_rv, CkRv::OK);
        assert_eq!(result.returned_len, 0);
        assert_eq!(result.value, None);
        assert_eq!(result.object_handle, CkObjectHandle(0x44));
    }
}
