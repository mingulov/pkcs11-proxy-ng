use super::{
    mechanism_key_init, session_bytes_final, session_bytes_input, session_object_unit,
    session_unit_input, *,
};

impl FfiBackend {
    pub(super) fn ffi_sign_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        let h_key = Self::object_handle(key)?;
        self.call_init_with_mechanism(
            &admission,
            session,
            OperationFamily::Sign,
            unsafe { (*self.func_list).C_SignInit },
            mechanism,
            |function, mech| unsafe { function(h_session, mech, h_key) },
        )
    }

    pub(super) fn ffi_sign_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        Self::call_unit(&admission, unsafe { (*self.func_list).C_SignInit }, |function| unsafe {
            function(h_session, std::ptr::null_mut(), 0)
        })?;
        self.drop_mech_cache_family(session, OperationFamily::Sign);
        Ok(())
    }

    pub(super) fn ffi_sign(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_Sign },
            |function, signature, signature_len| {
                session_bytes_input!(session, data, function, signature, signature_len)
            },
        )
    }

    pub(super) fn ffi_sign_update(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_unit(&admission, unsafe { (*self.func_list).C_SignUpdate }, |function| {
            session_unit_input!(session, part, function)
        })
    }

    pub(super) fn ffi_sign_final(&self, session: CkSessionHandle) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_SignFinal },
            |function, signature, signature_len| {
                session_bytes_final!(session, function, signature, signature_len)
            },
        )
    }

    pub(super) fn ffi_sign_recover_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_unit_with_mechanism(
            &admission,
            unsafe { (*self.func_list).C_SignRecoverInit },
            mechanism,
            |function, mech| mechanism_key_init!(session, mechanism, key, function, mech),
        )
    }

    pub(super) fn ffi_sign_recover_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_SignRecoverInit },
            |function| unsafe { function(h_session, std::ptr::null_mut(), 0) },
        )?;
        self.drop_mech_cache_family(session, OperationFamily::SignRecover);
        Ok(())
    }

    pub(super) fn ffi_sign_recover(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_SignRecover },
            |function, signature, signature_len| {
                session_bytes_input!(session, data, function, signature, signature_len)
            },
        )
    }

    pub(super) fn ffi_sign_exact(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_Sign },
            spec,
            |function, signature, signature_len| {
                session_bytes_input!(session, data, function, signature, signature_len)
            },
        )
    }

    pub(super) fn ffi_sign_final_exact(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_SignFinal },
            spec,
            |function, signature, signature_len| {
                session_bytes_final!(session, function, signature, signature_len)
            },
        )
    }

    pub(super) fn ffi_sign_recover_exact(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_SignRecover },
            spec,
            |function, signature, signature_len| {
                session_bytes_input!(session, data, function, signature, signature_len)
            },
        )
    }

    pub(super) fn ffi_verify_recover_exact(
        &self,
        session: CkSessionHandle,
        signature: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_VerifyRecover },
            spec,
            |function, data, data_len| {
                session_bytes_input!(session, signature, function, data, data_len)
            },
        )
    }

    pub(super) fn ffi_verify_recover_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_unit_with_mechanism(
            &admission,
            unsafe { (*self.func_list).C_VerifyRecoverInit },
            mechanism,
            |function, mech| mechanism_key_init!(session, mechanism, key, function, mech),
        )
    }

    pub(super) fn ffi_verify_recover_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_VerifyRecoverInit },
            |function| unsafe { function(h_session, std::ptr::null_mut(), 0) },
        )?;
        self.drop_mech_cache_family(session, OperationFamily::VerifyRecover);
        Ok(())
    }

    pub(super) fn ffi_verify_recover(
        &self,
        session: CkSessionHandle,
        signature: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_VerifyRecover },
            |function, data, data_len| {
                session_bytes_input!(session, signature, function, data, data_len)
            },
        )
    }

    pub(super) fn ffi_verify_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        self.call_init_with_mechanism(
            &admission,
            session,
            OperationFamily::Verify,
            unsafe { (*self.func_list).C_VerifyInit },
            mechanism,
            |function, mech| mechanism_key_init!(session, mechanism, key, function, mech),
        )
    }

    pub(super) fn ffi_verify_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        // Forward C_VerifyInit(NULL mechanism) verbatim, like the five sibling
        // init-cancel paths, so the module's native RV reaches the client
        // (ADR-0010 transparent forwarding). A module that SEGVs on it crashes
        // the daemon — its direct-load behavior, accepted by ADR-0010.
        let h_session = Self::session_handle(session)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_VerifyInit },
            |function| unsafe { function(h_session, std::ptr::null_mut(), 0) },
        )?;
        self.drop_mech_cache_family(session, OperationFamily::Verify);
        Ok(())
    }

    pub(super) fn ffi_verify(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (data_ptr, data_len) = data.as_ptr_len();
        let (sig_ptr, sig_len) = signature.as_ptr_len();
        let h_session = Self::session_handle(session)?;
        Self::call_unit(&admission, unsafe { (*self.func_list).C_Verify }, |function| unsafe {
            function(
                h_session,
                data_ptr as *mut _,
                Self::ulong_len_u64(data_len),
                sig_ptr as *mut _,
                Self::ulong_len_u64(sig_len),
            )
        })
    }

    pub(super) fn ffi_verify_update(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_unit(&admission, unsafe { (*self.func_list).C_VerifyUpdate }, |function| {
            session_unit_input!(session, part, function)
        })
    }

    pub(super) fn ffi_verify_final(
        &self,
        session: CkSessionHandle,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_unit(&admission, unsafe { (*self.func_list).C_VerifyFinal }, |function| {
            session_unit_input!(session, signature, function)
        })
    }

    pub(super) fn ffi_digest_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        self.call_init_with_mechanism(
            &admission,
            session,
            OperationFamily::Digest,
            unsafe { (*self.func_list).C_DigestInit },
            mechanism,
            |function, mech| unsafe { function(h_session, mech) },
        )
    }

    pub(super) fn ffi_digest_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        // Forward C_DigestInit(NULL mechanism) verbatim (ADR-0010): the module
        // decides — softhsm2/kryoptic cancel the active digest, others reject.
        // NSS softokn SEGVs on it; that is its direct-load behavior and an
        // accepted shared-daemon trade-off per ADR-0010.
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_DigestInit },
            |function| unsafe { function(h_session, std::ptr::null_mut()) },
        )?;
        self.drop_mech_cache_family(session, OperationFamily::Digest);
        Ok(())
    }

    pub(super) fn ffi_digest(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_Digest },
            |function, digest, digest_len| {
                session_bytes_input!(session, data, function, digest, digest_len)
            },
        )
    }

    pub(super) fn ffi_digest_exact(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_Digest },
            spec,
            |function, digest, digest_len| {
                session_bytes_input!(session, data, function, digest, digest_len)
            },
        )
    }

    pub(super) fn ffi_digest_update(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_unit(&admission, unsafe { (*self.func_list).C_DigestUpdate }, |function| {
            session_unit_input!(session, part, function)
        })
    }

    pub(super) fn ffi_digest_key(
        &self,
        session: CkSessionHandle,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_unit(&admission, unsafe { (*self.func_list).C_DigestKey }, |function| {
            session_object_unit!(session, key, function)
        })
    }

    pub(super) fn ffi_digest_final(&self, session: CkSessionHandle) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_DigestFinal },
            |function, digest, digest_len| {
                session_bytes_final!(session, function, digest, digest_len)
            },
        )
    }

    pub(super) fn ffi_digest_final_exact(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_DigestFinal },
            spec,
            |function, digest, digest_len| {
                session_bytes_final!(session, function, digest, digest_len)
            },
        )
    }

    pub(super) fn ffi_encrypt_init_with_output(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        self.call_init_with_mechanism_output(
            &admission,
            session,
            OperationFamily::Encrypt,
            unsafe { (*self.func_list).C_EncryptInit },
            mechanism,
            |function, mech| mechanism_key_init!(session, mechanism, key, function, mech),
        )
    }

    pub(super) fn ffi_encrypt_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_EncryptInit },
            |function| unsafe { function(h_session, std::ptr::null_mut(), 0) },
        )?;
        self.drop_mech_cache_family(session, OperationFamily::Encrypt);
        Ok(())
    }

    pub(super) fn ffi_encrypt(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_Encrypt },
            |function, output, output_len| {
                session_bytes_input!(session, data, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_encrypt_update(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_EncryptUpdate },
            |function, output, output_len| {
                session_bytes_input!(session, part, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_encrypt_final(&self, session: CkSessionHandle) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_EncryptFinal },
            |function, output, output_len| {
                session_bytes_final!(session, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_decrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        self.call_init_with_mechanism_output(
            &admission,
            session,
            OperationFamily::Decrypt,
            unsafe { (*self.func_list).C_DecryptInit },
            mechanism,
            |function, mech| mechanism_key_init!(session, mechanism, key, function, mech),
        )
    }

    pub(super) fn ffi_decrypt_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_DecryptInit },
            |function| unsafe { function(h_session, std::ptr::null_mut(), 0) },
        )?;
        self.drop_mech_cache_family(session, OperationFamily::Decrypt);
        Ok(())
    }

    pub(super) fn ffi_decrypt(
        &self,
        session: CkSessionHandle,
        encrypted_data: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_Decrypt },
            |function, output, output_len| {
                session_bytes_input!(session, encrypted_data, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_decrypt_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_DecryptUpdate },
            |function, output, output_len| {
                session_bytes_input!(session, encrypted_part, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_decrypt_final(&self, session: CkSessionHandle) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_DecryptFinal },
            |function, output, output_len| {
                session_bytes_final!(session, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_encrypt_exact(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_Encrypt },
            spec,
            |function, output, output_len| {
                session_bytes_input!(session, data, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_encrypt_exact_with_output(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, Option<CkMechanismParams>)> {
        let before = self.cached_mechanism_output_params_for(session, OperationFamily::Encrypt);
        let result = Self::call_bytes_exact(
            unsafe { (*self.func_list).C_Encrypt },
            spec,
            |function, output, output_len| {
                session_bytes_input!(session, data, function, output, output_len)
            },
        )?;
        // Cached mirror of the one-shot rule (B-E2): data/missing-length
        // calls surface the retained params on OK, and on error only when
        // the provider actually changed them. Size queries suppress always.
        let after = self.cached_mechanism_output_params_for(session, OperationFamily::Encrypt);
        let mechanism_out = if !(spec.buffer_present || spec.length_pointer_null) {
            None
        } else if result.ck_rv == CkRv::OK || after != before {
            after
        } else {
            None
        };
        Ok((result, mechanism_out))
    }

    pub(super) fn ffi_encrypt_update_exact(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_EncryptUpdate },
            spec,
            |function, output, output_len| {
                session_bytes_input!(session, part, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_encrypt_final_exact(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_EncryptFinal },
            spec,
            |function, output, output_len| {
                session_bytes_final!(session, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_decrypt_exact(
        &self,
        session: CkSessionHandle,
        encrypted_data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_Decrypt },
            spec,
            |function, output, output_len| {
                session_bytes_input!(session, encrypted_data, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_decrypt_update_exact(
        &self,
        session: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_DecryptUpdate },
            spec,
            |function, output, output_len| {
                session_bytes_input!(session, encrypted_part, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_decrypt_final_exact(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_DecryptFinal },
            spec,
            |function, output, output_len| {
                session_bytes_final!(session, function, output, output_len)
            },
        )
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicPtr, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    static LOCK: Mutex<()> = Mutex::new(());
    static ENCRYPT_ERROR_IV_TARGET: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());

    unsafe extern "C" fn encrypt_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _data: cryptoki_sys::CK_BYTE_PTR,
        _data_len: cryptoki_sys::CK_ULONG,
        _output: cryptoki_sys::CK_BYTE_PTR,
        output_len: cryptoki_sys::CK_ULONG_PTR,
    ) -> cryptoki_sys::CK_RV {
        if !output_len.is_null() {
            unsafe { *output_len = 4 };
        }
        cryptoki_sys::CKR_OK
    }

    #[test]
    fn encrypt_missing_length_surfaces_cached_mechanism_output_but_size_query_does_not() {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_Encrypt = Some(encrypt_ok);
        let backend = FfiBackend {
            _lib: crate::ffi::loading::test_library_handle(),
            func_list: functions.as_mut(),
            func_list_3_0: None,
            func_list_3_2: None,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            // Test-local backend: bypasses the process reservation without
            // consuming it; never backs production dispatch (C3M.4).
            construction: crate::ffi::native_domain::ConstructionPermit::unmanaged_test_only(),
            lifecycle: Default::default(),
            lifecycle_domain: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
        let session = CkSessionHandle(7);
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType::AES_GCM,
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv: vec![0xA5; 12],
                iv_bits: 96,
                iv_buffer_len: 12,
                aad: Vec::new().into(),
                tag_bits: 128,

                iv_null: false,
                aad_null: false,
            })),
        };
        backend.mech_cache.insert(
            (session.0, OperationFamily::Encrypt),
            super::super::ffi_conversion::mechanism_to_ffi(&mechanism).unwrap(),
        );

        let (_, missing_output) = backend
            .ffi_encrypt_exact_with_output(
                session,
                CkInBuf::Bytes(b"data"),
                &CkOutputBufferSpec {
                    buffer_present: false,
                    buffer_len: 0,
                    length_pointer_null: true,
                },
            )
            .unwrap();
        assert_eq!(missing_output, mechanism.params);

        let (_, size_output) = backend
            .ffi_encrypt_exact_with_output(
                session,
                CkInBuf::Bytes(b"data"),
                &CkOutputBufferSpec {
                    buffer_present: false,
                    buffer_len: 0,
                    length_pointer_null: false,
                },
            )
            .unwrap();
        assert_eq!(size_output, None);
    }

    unsafe extern "C" fn encrypt_fails_after_mutating_cached_iv(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _data: cryptoki_sys::CK_BYTE_PTR,
        _data_len: cryptoki_sys::CK_ULONG,
        _output: cryptoki_sys::CK_BYTE_PTR,
        output_len: cryptoki_sys::CK_ULONG_PTR,
    ) -> cryptoki_sys::CK_RV {
        // Benign native-provider effect: write within the initialized
        // retained IV published by the test (C_Encrypt carries no mechanism
        // pointer, so the stub reaches retained storage through the static).
        let target = ENCRYPT_ERROR_IV_TARGET.load(Ordering::SeqCst);
        if !target.is_null() {
            unsafe { target.write(0x42) };
        }
        if !output_len.is_null() {
            unsafe { *output_len = 7 };
        }
        cryptoki_sys::CKR_FUNCTION_FAILED
    }

    unsafe extern "C" fn encrypt_fails_without_mutation(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _data: cryptoki_sys::CK_BYTE_PTR,
        _data_len: cryptoki_sys::CK_ULONG,
        _output: cryptoki_sys::CK_BYTE_PTR,
        output_len: cryptoki_sys::CK_ULONG_PTR,
    ) -> cryptoki_sys::CK_RV {
        if !output_len.is_null() {
            unsafe { *output_len = 7 };
        }
        cryptoki_sys::CKR_FUNCTION_FAILED
    }

    fn encrypt_backend_with(
        encrypt: unsafe extern "C" fn(
            cryptoki_sys::CK_SESSION_HANDLE,
            cryptoki_sys::CK_BYTE_PTR,
            cryptoki_sys::CK_ULONG,
            cryptoki_sys::CK_BYTE_PTR,
            cryptoki_sys::CK_ULONG_PTR,
        ) -> cryptoki_sys::CK_RV,
    ) -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_Encrypt = Some(encrypt);
        let backend = FfiBackend {
            _lib: crate::ffi::loading::test_library_handle(),
            func_list: functions.as_mut(),
            func_list_3_0: None,
            func_list_3_2: None,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            // Test-local backend: bypasses the process reservation without
            // consuming it; never backs production dispatch (C3M.4).
            construction: crate::ffi::native_domain::ConstructionPermit::unmanaged_test_only(),
            lifecycle: Default::default(),
            lifecycle_domain: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
        (backend, functions)
    }

    fn seed_encrypt_gcm_cache(backend: &FfiBackend, session: CkSessionHandle) {
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType::AES_GCM,
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv: vec![0x11; 12],
                iv_bits: 96,
                iv_buffer_len: 12,
                aad: Vec::new().into(),
                tag_bits: 128,

                iv_null: false,
                aad_null: false,
            })),
        };
        let ffi_mech = super::super::ffi_conversion::mechanism_to_ffi(&mechanism).unwrap();
        // Publish the retained IV root for the stub before inserting: the
        // owned IV buffer address is stable across the move into the slot.
        let outer = ffi_mech.ck_mechanism();
        let iv_root = unsafe { (*outer.pParameter.cast::<cryptoki_sys::CK_GCM_PARAMS>()).pIv };
        ENCRYPT_ERROR_IV_TARGET.store(iv_root, Ordering::SeqCst);
        backend.mech_cache.insert((session.0, OperationFamily::Encrypt), ffi_mech);
    }

    #[cfg_attr(miri, ignore)] // Miri: backend instance needs dlopen + DashMap; helper-level matrix covers the rule under Miri
    #[test]
    fn encrypt_error_effect_requires_changed_cached_iv() {
        let _guard = LOCK.lock().unwrap();
        let data_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 4, length_pointer_null: false };
        let (backend, _functions) = encrypt_backend_with(encrypt_fails_after_mutating_cached_iv);
        let session = CkSessionHandle(21);
        seed_encrypt_gcm_cache(&backend, session);
        let (output, effects) = backend
            .ffi_encrypt_exact_with_output(session, CkInBuf::Bytes(b"data"), &data_spec)
            .unwrap();
        assert_eq!(output.ck_rv, CkRv::FUNCTION_FAILED);
        let Some(CkMechanismParams::Gcm(gcm)) = effects else {
            panic!("failed encrypt must surface the mutated cached GCM IV");
        };
        assert_eq!(gcm.iv[0], 0x42);

        let (plain_backend, _plain_functions) =
            encrypt_backend_with(encrypt_fails_without_mutation);
        let plain_session = CkSessionHandle(22);
        seed_encrypt_gcm_cache(&plain_backend, plain_session);
        let (output, effects) = plain_backend
            .ffi_encrypt_exact_with_output(plain_session, CkInBuf::Bytes(b"data"), &data_spec)
            .unwrap();
        assert_eq!(output.ck_rv, CkRv::FUNCTION_FAILED);
        assert_eq!(effects, None);
    }

    #[cfg_attr(miri, ignore)] // Miri: backend instance needs dlopen + DashMap; helper-level matrix covers the rule under Miri
    #[test]
    fn encrypt_error_size_query_suppresses_cached_output() {
        let _guard = LOCK.lock().unwrap();
        let (backend, _functions) = encrypt_backend_with(encrypt_fails_after_mutating_cached_iv);
        let session = CkSessionHandle(23);
        seed_encrypt_gcm_cache(&backend, session);
        let (output, effects) = backend
            .ffi_encrypt_exact_with_output(
                session,
                CkInBuf::Bytes(b"data"),
                &CkOutputBufferSpec {
                    buffer_present: false,
                    buffer_len: 0,
                    length_pointer_null: false,
                },
            )
            .unwrap();
        assert_eq!(output.ck_rv, CkRv::FUNCTION_FAILED);
        assert_eq!(effects, None);
    }

    #[cfg_attr(miri, ignore)] // Miri: backend instance needs dlopen + DashMap; helper-level matrix covers the rule under Miri
    #[test]
    fn encrypt_error_missing_length_surfaces_changed_cached_iv() {
        let _guard = LOCK.lock().unwrap();
        let missing_spec =
            CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: true };
        let (backend, _functions) = encrypt_backend_with(encrypt_fails_after_mutating_cached_iv);
        let session = CkSessionHandle(24);
        seed_encrypt_gcm_cache(&backend, session);
        let (output, effects) = backend
            .ffi_encrypt_exact_with_output(session, CkInBuf::Bytes(b"data"), &missing_spec)
            .unwrap();
        assert_eq!(output.ck_rv, CkRv::FUNCTION_FAILED);
        let Some(CkMechanismParams::Gcm(gcm)) = effects else {
            panic!("failed missing-length encrypt must surface the mutated cached GCM IV");
        };
        assert_eq!(gcm.iv[0], 0x42);

        let (plain_backend, _plain_functions) =
            encrypt_backend_with(encrypt_fails_without_mutation);
        let plain_session = CkSessionHandle(25);
        seed_encrypt_gcm_cache(&plain_backend, plain_session);
        let (output, effects) = plain_backend
            .ffi_encrypt_exact_with_output(plain_session, CkInBuf::Bytes(b"data"), &missing_spec)
            .unwrap();
        assert_eq!(output.ck_rv, CkRv::FUNCTION_FAILED);
        assert_eq!(effects, None);
    }

    unsafe extern "C" fn encrypt_init_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _mechanism: *mut cryptoki_sys::CK_MECHANISM,
        _key: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn digest_init_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _mechanism: *mut cryptoki_sys::CK_MECHANISM,
    ) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn encrypt_init_fails(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _mechanism: *mut cryptoki_sys::CK_MECHANISM,
        _key: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_FUNCTION_FAILED
    }

    #[cfg_attr(miri, ignore = "Miri cannot dlopen; covered natively")]
    #[test]
    fn native_owner_dual_families_and_cancel_are_independent() {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_EncryptInit = Some(encrypt_init_ok);
        functions.C_DigestInit = Some(digest_init_ok);
        let backend = FfiBackend {
            _lib: crate::ffi::loading::test_library_handle(),
            func_list: functions.as_mut(),
            func_list_3_0: None,
            func_list_3_2: None,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            // Test-local backend: bypasses the process reservation without
            // consuming it; never backs production dispatch (C3M.4).
            construction: crate::ffi::native_domain::ConstructionPermit::unmanaged_test_only(),
            lifecycle: Default::default(),
            lifecycle_domain: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
        // Cancel paths are ordinary: establish post-Initialize state.
        backend.lifecycle_domain.open_for_tests();
        let session = CkSessionHandle(11);
        let gcm = CkMechanism {
            mechanism_type: CkMechanismType::AES_GCM,
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv: vec![0xA5; 12],
                iv_bits: 96,
                iv_buffer_len: 12,
                aad: Vec::new().into(),
                tag_bits: 128,

                iv_null: false,
                aad_null: false,
            })),
        };
        let encrypt_out =
            backend.ffi_encrypt_init_with_output(session, &gcm, CkObjectHandle(1)).unwrap();
        assert_eq!(encrypt_out, gcm.params);
        backend
            .ffi_digest_init(
                session,
                &CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None },
            )
            .unwrap();
        // The later DigestInit must not evict the Encrypt family graph.
        assert!(backend.mech_cache.contains_key(&(session.0, OperationFamily::Encrypt)));
        assert!(backend.mech_cache.contains_key(&(session.0, OperationFamily::Digest)));
        assert_eq!(
            backend.cached_mechanism_output_params_for(session, OperationFamily::Encrypt),
            gcm.params
        );
        // Cancelling Digest retires only the Digest slot: the Encrypt graph
        // stays live and still yields its retained IV output.
        backend.ffi_digest_init_cancel(session).unwrap();
        assert!(!backend.mech_cache.contains_key(&(session.0, OperationFamily::Digest)));
        assert!(backend.mech_cache.contains_key(&(session.0, OperationFamily::Encrypt)));
        assert_eq!(
            backend.cached_mechanism_output_params_for(session, OperationFamily::Encrypt),
            gcm.params
        );
    }

    #[cfg_attr(miri, ignore = "Miri cannot dlopen; covered natively")]
    #[test]
    fn native_owner_init_failure_preserves_active() {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_EncryptInit = Some(encrypt_init_ok);
        let backend = FfiBackend {
            _lib: crate::ffi::loading::test_library_handle(),
            func_list: functions.as_mut(),
            func_list_3_0: None,
            func_list_3_2: None,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            // Test-local backend: bypasses the process reservation without
            // consuming it; never backs production dispatch (C3M.4).
            construction: crate::ffi::native_domain::ConstructionPermit::unmanaged_test_only(),
            lifecycle: Default::default(),
            lifecycle_domain: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
        // Init paths are ordinary: establish post-Initialize state.
        backend.lifecycle_domain.open_for_tests();
        let session = CkSessionHandle(12);
        let gcm = CkMechanism {
            mechanism_type: CkMechanismType::AES_GCM,
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv: vec![0xA5; 12],
                iv_bits: 96,
                iv_buffer_len: 12,
                aad: Vec::new().into(),
                tag_bits: 128,

                iv_null: false,
                aad_null: false,
            })),
        };
        backend.ffi_encrypt_init_with_output(session, &gcm, CkObjectHandle(1)).unwrap();
        // A failed re-Init must not disturb the live owner: same slot,
        // same output, same last-Init marker.
        functions.C_EncryptInit = Some(encrypt_init_fails);
        assert_eq!(
            backend.ffi_encrypt_init_with_output(session, &gcm, CkObjectHandle(1)).unwrap_err(),
            CkRv::FUNCTION_FAILED
        );
        assert!(backend.mech_cache.contains_key(&(session.0, OperationFamily::Encrypt)));
        assert_eq!(
            backend.cached_mechanism_output_params_for(session, OperationFamily::Encrypt),
            gcm.params
        );
        assert_eq!(
            backend.last_init_family.get(&session.0).as_deref(),
            Some(&OperationFamily::Encrypt)
        );
    }

    #[cfg_attr(miri, ignore)] // Miri: backend instance needs dlopen + DashMap; helper-level matrix covers the rule under Miri
    #[test]
    fn native_owner_first_init_failure_publishes_nothing() {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_EncryptInit = Some(encrypt_init_fails);
        let backend = FfiBackend {
            _lib: crate::ffi::loading::test_library_handle(),
            func_list: functions.as_mut(),
            func_list_3_0: None,
            func_list_3_2: None,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            // Test-local backend: bypasses the process reservation without
            // consuming it; never backs production dispatch (C3M.4).
            construction: crate::ffi::native_domain::ConstructionPermit::unmanaged_test_only(),
            lifecycle: Default::default(),
            lifecycle_domain: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
        // Init paths are ordinary: establish post-Initialize state.
        backend.lifecycle_domain.open_for_tests();
        let session = CkSessionHandle(25);
        let gcm = CkMechanism {
            mechanism_type: CkMechanismType::AES_GCM,
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv: vec![0xA5; 12],
                iv_bits: 96,
                iv_buffer_len: 12,
                aad: Vec::new().into(),
                tag_bits: 128,

                iv_null: false,
                aad_null: false,
            })),
        };
        // A failed FIRST Init on an empty slot publishes nothing: no cache
        // entry, no last-Init marker.
        assert_eq!(
            backend.ffi_encrypt_init_with_output(session, &gcm, CkObjectHandle(1)).unwrap_err(),
            CkRv::FUNCTION_FAILED
        );
        assert!(
            !backend.mech_cache.iter().any(|entry| entry.key().0 == session.0),
            "failed first Init must not publish any mech_cache entry"
        );
        assert!(backend.last_init_family.get(&session.0).is_none());
    }

    #[cfg_attr(miri, ignore)] // Miri: backend instance needs dlopen + DashMap; helper-level matrix covers the rule under Miri
    #[test]
    fn native_owner_failed_reinit_keeps_marker_and_graph() {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_EncryptInit = Some(encrypt_init_ok);
        let backend = FfiBackend {
            _lib: crate::ffi::loading::test_library_handle(),
            func_list: functions.as_mut(),
            func_list_3_0: None,
            func_list_3_2: None,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            // Test-local backend: bypasses the process reservation without
            // consuming it; never backs production dispatch (C3M.4).
            construction: crate::ffi::native_domain::ConstructionPermit::unmanaged_test_only(),
            lifecycle: Default::default(),
            lifecycle_domain: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
        // Init paths are ordinary: establish post-Initialize state.
        backend.lifecycle_domain.open_for_tests();
        let session = CkSessionHandle(26);
        let gcm = CkMechanism {
            mechanism_type: CkMechanismType::AES_GCM,
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv: vec![0xA5; 12],
                iv_bits: 96,
                iv_buffer_len: 12,
                aad: Vec::new().into(),
                tag_bits: 128,

                iv_null: false,
                aad_null: false,
            })),
        };
        let first = backend.ffi_encrypt_init_with_output(session, &gcm, CkObjectHandle(1)).unwrap();
        assert_eq!(first, gcm.params);
        // Two consecutive failed re-Inits must still preserve the original
        // graph bytes and the last-Init marker.
        functions.C_EncryptInit = Some(encrypt_init_fails);
        assert_eq!(
            backend.ffi_encrypt_init_with_output(session, &gcm, CkObjectHandle(1)).unwrap_err(),
            CkRv::FUNCTION_FAILED
        );
        assert_eq!(
            backend.ffi_encrypt_init_with_output(session, &gcm, CkObjectHandle(1)).unwrap_err(),
            CkRv::FUNCTION_FAILED
        );
        assert_eq!(
            backend.cached_mechanism_output_params_for(session, OperationFamily::Encrypt),
            first
        );
        assert_eq!(
            backend.last_init_family.get(&session.0).as_deref(),
            Some(&OperationFamily::Encrypt)
        );
    }

    unsafe extern "C" fn sign_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _data: cryptoki_sys::CK_BYTE_PTR,
        _data_len: cryptoki_sys::CK_ULONG,
        _signature: cryptoki_sys::CK_BYTE_PTR,
        signature_len: cryptoki_sys::CK_ULONG_PTR,
    ) -> cryptoki_sys::CK_RV {
        if !signature_len.is_null() {
            unsafe { *signature_len = 4 };
        }
        cryptoki_sys::CKR_OK
    }

    fn backend_with_sign_stub() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_Sign = Some(sign_ok);
        let backend = FfiBackend {
            _lib: crate::ffi::loading::test_library_handle(),
            func_list: functions.as_mut(),
            func_list_3_0: None,
            func_list_3_2: None,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            // Test-local backend: bypasses the process reservation without
            // consuming it; never backs production dispatch (C3M.4).
            construction: crate::ffi::native_domain::ConstructionPermit::unmanaged_test_only(),
            lifecycle: Default::default(),
            lifecycle_domain: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
        (backend, functions)
    }

    #[test]
    fn sign_denied_before_lifecycle_open() {
        // TF01a read-path proof (`call_bytes` family): no admission before
        // Initialize — the stub provider is never reached.
        let (backend, _functions) = backend_with_sign_stub();
        assert_eq!(
            backend.ffi_sign(CkSessionHandle(7), CkInBuf::Bytes(b"data")).unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn sign_admitted_after_lifecycle_open() {
        // Control: the same call reaches the stub once the domain is open.
        let (backend, _functions) = backend_with_sign_stub();
        backend.lifecycle_domain.open_for_tests();
        let signature = backend.ffi_sign(CkSessionHandle(7), CkInBuf::Bytes(b"data")).unwrap();
        assert_eq!(signature.len(), 4);
    }

    unsafe extern "C" fn sign_init_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _mechanism: *mut cryptoki_sys::CK_MECHANISM,
        _key: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn sign_recover_init_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _mechanism: *mut cryptoki_sys::CK_MECHANISM,
        _key: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    fn backend_with_init_stubs() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_SignInit = Some(sign_init_ok);
        functions.C_SignRecoverInit = Some(sign_recover_init_ok);
        functions.C_EncryptInit = Some(encrypt_init_ok);
        let backend = FfiBackend {
            _lib: crate::ffi::loading::test_library_handle(),
            func_list: functions.as_mut(),
            func_list_3_0: None,
            func_list_3_2: None,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            // Test-local backend: bypasses the process reservation without
            // consuming it; never backs production dispatch (C3M.4).
            construction: crate::ffi::native_domain::ConstructionPermit::unmanaged_test_only(),
            lifecycle: Default::default(),
            lifecycle_domain: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
        (backend, functions)
    }

    fn rsa_pkcs_mechanism() -> CkMechanism {
        CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None }
    }

    #[test]
    fn sign_init_denied_before_lifecycle_open() {
        // TF01b `call_init_with_mechanism` ordinary proof (Init publish
        // path): no admission pre-Init.
        let (backend, _functions) = backend_with_init_stubs();
        assert_eq!(
            backend
                .ffi_sign_init(CkSessionHandle(7), &rsa_pkcs_mechanism(), CkObjectHandle(9))
                .unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn sign_init_admitted_after_lifecycle_open() {
        // Control: the same call reaches the stub once the domain is open.
        let (backend, _functions) = backend_with_init_stubs();
        backend.lifecycle_domain.open_for_tests();
        backend
            .ffi_sign_init(CkSessionHandle(7), &rsa_pkcs_mechanism(), CkObjectHandle(9))
            .unwrap();
        assert!(backend.mech_cache.contains_key(&(7, OperationFamily::Sign)));
    }

    #[test]
    fn sign_recover_init_denied_before_lifecycle_open() {
        // TF01b `call_unit_with_mechanism` ordinary proof: no admission
        // pre-Init.
        let (backend, _functions) = backend_with_init_stubs();
        assert_eq!(
            backend
                .ffi_sign_recover_init(CkSessionHandle(7), &rsa_pkcs_mechanism(), CkObjectHandle(9))
                .unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn sign_recover_init_admitted_after_lifecycle_open() {
        // Control: the same call reaches the stub once the domain is open.
        let (backend, _functions) = backend_with_init_stubs();
        backend.lifecycle_domain.open_for_tests();
        backend
            .ffi_sign_recover_init(CkSessionHandle(7), &rsa_pkcs_mechanism(), CkObjectHandle(9))
            .unwrap();
    }

    #[test]
    fn encrypt_init_with_output_denied_before_lifecycle_open() {
        // TF01b `call_init_with_mechanism_output` ordinary proof (Init
        // publish path with output): no admission pre-Init.
        let (backend, _functions) = backend_with_init_stubs();
        let gcm = CkMechanism {
            mechanism_type: CkMechanismType::AES_GCM,
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv: vec![0xA5; 12],
                iv_bits: 96,
                iv_buffer_len: 12,
                aad: Vec::new().into(),
                tag_bits: 128,
                iv_null: false,
                aad_null: false,
            })),
        };
        assert_eq!(
            backend
                .ffi_encrypt_init_with_output(CkSessionHandle(7), &gcm, CkObjectHandle(1))
                .unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn encrypt_init_with_output_admitted_after_lifecycle_open() {
        // Control: the same call reaches the stub once the domain is open.
        let (backend, _functions) = backend_with_init_stubs();
        backend.lifecycle_domain.open_for_tests();
        let gcm = CkMechanism {
            mechanism_type: CkMechanismType::AES_GCM,
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv: vec![0xA5; 12],
                iv_bits: 96,
                iv_buffer_len: 12,
                aad: Vec::new().into(),
                tag_bits: 128,
                iv_null: false,
                aad_null: false,
            })),
        };
        backend.ffi_encrypt_init_with_output(CkSessionHandle(7), &gcm, CkObjectHandle(1)).unwrap();
        assert!(backend.mech_cache.contains_key(&(7, OperationFamily::Encrypt)));
    }

    // Blocked-stub exclusion shape (Init publish family): a parked Init
    // holds its guard across native entry AND the cache publication, so
    // control settlement cannot complete until release.
    static SIGN_INIT_PARK_GATE: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>> =
        Mutex::new(None);

    unsafe extern "C" fn sign_init_parkable(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _mechanism: *mut cryptoki_sys::CK_MECHANISM,
        _key: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        let gate = SIGN_INIT_PARK_GATE.lock().unwrap().take();
        match gate {
            Some((entered, release)) => {
                let _ = entered.send(());
                match release.recv_timeout(Duration::from_secs(10)) {
                    Ok(()) => cryptoki_sys::CKR_OK,
                    // Test bug (release never came): fail loudly, never hang.
                    Err(_) => cryptoki_sys::CKR_FUNCTION_FAILED,
                }
            }
            None => cryptoki_sys::CKR_FUNCTION_FAILED,
        }
    }

    #[test]
    fn parked_sign_init_blocks_control_until_release() {
        let (backend, _functions) = backend_with_init_stubs();
        backend.lifecycle_domain.open_for_tests();
        unsafe { (*backend.func_list).C_SignInit = Some(sign_init_parkable) };
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *SIGN_INIT_PARK_GATE.lock().unwrap() = Some((entered_tx, release_rx));
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                backend.ffi_sign_init(CkSessionHandle(7), &rsa_pkcs_mechanism(), CkObjectHandle(9))
            });
            entered_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("worker parks inside the stub holding its guard");
            scope.spawn(|| {
                let ticket = backend.lifecycle_domain.begin_initialize().expect("control proceeds");
                done_tx.send(()).expect("report control settlement");
                backend.lifecycle_domain.abandon_initialize(ticket);
            });
            assert!(
                done_rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "control must not settle while an ordinary call is parked"
            );
            release_tx.send(()).expect("release the parked stub");
            done_rx.recv_timeout(Duration::from_secs(5)).expect("control proceeds after release");
            worker.join().expect("worker joins").expect("parked call succeeds");
        });
    }

    // Blocked-stub exclusion shape (`call_bytes` family): a provider parked
    // mid-call holds its ordinary guard, so control settlement cannot
    // complete until release; it proceeds after. Bounded waits throughout.
    static SIGN_PARK_GATE: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>> = Mutex::new(None);

    unsafe extern "C" fn sign_parkable(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _data: cryptoki_sys::CK_BYTE_PTR,
        _data_len: cryptoki_sys::CK_ULONG,
        signature: cryptoki_sys::CK_BYTE_PTR,
        signature_len: cryptoki_sys::CK_ULONG_PTR,
    ) -> cryptoki_sys::CK_RV {
        // Two-call helper queries with NULL output first: park only there;
        // the fill call completes immediately (the guard spans both).
        if !signature.is_null() {
            if !signature_len.is_null() {
                unsafe { *signature_len = 4 };
            }
            return cryptoki_sys::CKR_OK;
        }
        let gate = SIGN_PARK_GATE.lock().unwrap().take();
        match gate {
            Some((entered, release)) => {
                let _ = entered.send(());
                match release.recv_timeout(Duration::from_secs(10)) {
                    Ok(()) => {
                        if !signature_len.is_null() {
                            unsafe { *signature_len = 4 };
                        }
                        cryptoki_sys::CKR_OK
                    }
                    // Test bug (release never came): fail loudly, never hang.
                    Err(_) => cryptoki_sys::CKR_FUNCTION_FAILED,
                }
            }
            None => cryptoki_sys::CKR_FUNCTION_FAILED,
        }
    }

    unsafe extern "C" fn initialize_ok(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    #[test]
    fn initialize_blocks_on_parked_ordinary_then_proceeds_after_release() {
        // I1 contention pin (blocking chosen; see `begin_initialize` docs):
        // a full `initialize()` cycle waits behind a provider-parked
        // ordinary call — it must neither fail fast under contention nor
        // wedge past release. Bounded waits throughout: 200ms of provable
        // block, then prompt completion after release.
        let (backend, _functions) = backend_with_sign_stub();
        unsafe { (*backend.func_list).C_Initialize = Some(initialize_ok) };
        backend.initialize().expect("setup initialize opens the incarnation");
        // Swap in the parking stub for this test only.
        unsafe { (*backend.func_list).C_Sign = Some(sign_parkable) };
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *SIGN_PARK_GATE.lock().unwrap() = Some((entered_tx, release_rx));
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let worker =
                scope.spawn(|| backend.ffi_sign(CkSessionHandle(7), CkInBuf::Bytes(b"data")));
            entered_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("worker parks inside the stub holding its guard");
            scope.spawn(|| {
                let outcome = backend.initialize();
                done_tx.send(outcome.is_ok()).expect("report initialize completion");
            });
            assert!(
                done_rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "initialize must wait while an ordinary call is parked, not fail fast"
            );
            release_tx.send(()).expect("release the parked stub");
            assert!(
                done_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("initialize proceeds after release"),
                "initialize succeeds after release"
            );
            let signature = worker.join().expect("worker joins").expect("parked call succeeds");
            assert_eq!(signature.len(), 4);
        });
    }

    #[test]
    fn parked_sign_blocks_control_until_release() {
        let (backend, _functions) = backend_with_sign_stub();
        backend.lifecycle_domain.open_for_tests();
        // Swap in the parking stub for this test only.
        unsafe { (*backend.func_list).C_Sign = Some(sign_parkable) };
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *SIGN_PARK_GATE.lock().unwrap() = Some((entered_tx, release_rx));
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let worker =
                scope.spawn(|| backend.ffi_sign(CkSessionHandle(7), CkInBuf::Bytes(b"data")));
            entered_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("worker parks inside the stub holding its guard");
            scope.spawn(|| {
                let ticket = backend.lifecycle_domain.begin_initialize().expect("control proceeds");
                done_tx.send(()).expect("report control settlement");
                backend.lifecycle_domain.abandon_initialize(ticket);
            });
            assert!(
                done_rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "control must not settle while an ordinary call is parked"
            );
            release_tx.send(()).expect("release the parked stub");
            done_rx.recv_timeout(Duration::from_secs(5)).expect("control proceeds after release");
            let signature = worker.join().expect("worker joins").expect("parked call succeeds");
            assert_eq!(signature.len(), 4);
        });
    }
}
