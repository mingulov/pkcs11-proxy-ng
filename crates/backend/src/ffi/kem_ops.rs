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
        let ffi_attrs = FfiAttrs::from_slice(template);

        let mut out_len: cryptoki_sys::CK_ULONG = 0;
        let mut key_handle: cryptoki_sys::CK_OBJECT_HANDLE = 0;

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
            if rv == CkRv::OK.0 || rv == CkRv::BUFFER_TOO_SMALL.0 {
                // Both CKR_OK and CKR_BUFFER_TOO_SMALL are valid size-query
                // responses (NSS returns BUFFER_TOO_SMALL). Propagate the
                // returned length so the caller can allocate correctly.
                Ok(CkOutputAndHandleResult {
                    ck_rv: CkRv(rv),
                    returned_len: out_len as u64,
                    value: None,
                    object_handle: CkObjectHandle(if rv == CkRv::OK.0 {
                        key_handle as u64
                    } else {
                        0
                    }),
                })
            } else {
                Err(CkRv(rv))
            }
        } else {
            // Data query: allocate caller-specified buffer
            out_len = spec.buffer_len as cryptoki_sys::CK_ULONG;
            let mut buf = vec![0u8; spec.buffer_len as usize];
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
            if rv == CkRv::OK.0 {
                buf.truncate(out_len as usize);
                Ok(CkOutputAndHandleResult {
                    ck_rv: CkRv::OK,
                    returned_len: out_len as u64,
                    value: Some(buf),
                    object_handle: CkObjectHandle(key_handle as u64),
                })
            } else if rv == CkRv::BUFFER_TOO_SMALL.0 {
                Ok(CkOutputAndHandleResult {
                    ck_rv: CkRv::BUFFER_TOO_SMALL,
                    returned_len: out_len as u64,
                    value: None,
                    object_handle: CkObjectHandle(0),
                })
            } else {
                Err(CkRv(rv))
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
        let ffi_attrs = FfiAttrs::from_slice(template);

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
        ciphertext: &[u8],
    ) -> CkResult<CkObjectHandle> {
        use super::ffi_conversion::FfiAttrs;

        let ffi_attrs = FfiAttrs::from_slice(template);
        let mut ffi_mech = mechanism_to_ffi(mechanism)?;
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
            ciphertext.as_ptr() as *mut cryptoki_sys::CK_BYTE,
            Self::ulong_len(ciphertext.len()),
            &mut key_handle
        )?;

        Ok(CkObjectHandle(key_handle as u64))
    }
}
