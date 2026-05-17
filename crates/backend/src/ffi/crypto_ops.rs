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
        self.call_init_with_mechanism(
            session,
            unsafe { (*self.func_list).C_SignInit },
            mechanism,
            |function, mech| unsafe {
                function(Self::session_handle(session), mech, Self::object_handle(key))
            },
        )
    }

    pub(super) fn ffi_sign_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_SignInit }, |function| unsafe {
            function(Self::session_handle(session), std::ptr::null_mut(), 0)
        })?;
        self.drop_mech_cache(session);
        Ok(())
    }

    pub(super) fn ffi_sign(&self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        Self::call_bytes(
            unsafe { (*self.func_list).C_Sign },
            |function, signature, signature_len| {
                session_bytes_input!(session, data, function, signature, signature_len)
            },
        )
    }

    pub(super) fn ffi_sign_update(&self, session: CkSessionHandle, part: &[u8]) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_SignUpdate }, |function| {
            session_unit_input!(session, part, function)
        })
    }

    pub(super) fn ffi_sign_final(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        Self::call_bytes(
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
        Self::call_unit_with_mechanism(
            unsafe { (*self.func_list).C_SignRecoverInit },
            mechanism,
            |function, mech| mechanism_key_init!(session, mechanism, key, function, mech),
        )
    }

    pub(super) fn ffi_sign_recover_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_SignRecoverInit }, |function| unsafe {
            function(Self::session_handle(session), std::ptr::null_mut(), 0)
        })?;
        self.drop_mech_cache(session);
        Ok(())
    }

    pub(super) fn ffi_sign_recover(
        &self,
        session: CkSessionHandle,
        data: &[u8],
    ) -> CkResult<Vec<u8>> {
        Self::call_bytes(
            unsafe { (*self.func_list).C_SignRecover },
            |function, signature, signature_len| {
                session_bytes_input!(session, data, function, signature, signature_len)
            },
        )
    }

    pub(super) fn ffi_sign_exact(
        &self,
        session: CkSessionHandle,
        data: &[u8],
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
        data: &[u8],
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
        signature: &[u8],
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
        Self::call_unit_with_mechanism(
            unsafe { (*self.func_list).C_VerifyRecoverInit },
            mechanism,
            |function, mech| mechanism_key_init!(session, mechanism, key, function, mech),
        )
    }

    pub(super) fn ffi_verify_recover_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_VerifyRecoverInit }, |function| unsafe {
            function(Self::session_handle(session), std::ptr::null_mut(), 0)
        })?;
        self.drop_mech_cache(session);
        Ok(())
    }

    pub(super) fn ffi_verify_recover(
        &self,
        session: CkSessionHandle,
        signature: &[u8],
    ) -> CkResult<Vec<u8>> {
        Self::call_bytes(
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
        self.call_init_with_mechanism(
            session,
            unsafe { (*self.func_list).C_VerifyInit },
            mechanism,
            |function, mech| mechanism_key_init!(session, mechanism, key, function, mech),
        )
    }

    pub(super) fn ffi_verify_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_VerifyInit }, |function| unsafe {
            function(Self::session_handle(session), std::ptr::null_mut(), 0)
        })?;
        self.drop_mech_cache(session);
        Ok(())
    }

    pub(super) fn ffi_verify(
        &self,
        session: CkSessionHandle,
        data: &[u8],
        signature: &[u8],
    ) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_Verify }, |function| unsafe {
            function(
                Self::session_handle(session),
                data.as_ptr() as *mut _,
                Self::ulong_len(data.len()),
                signature.as_ptr() as *mut _,
                Self::ulong_len(signature.len()),
            )
        })
    }

    pub(super) fn ffi_verify_update(&self, session: CkSessionHandle, part: &[u8]) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_VerifyUpdate }, |function| {
            session_unit_input!(session, part, function)
        })
    }

    pub(super) fn ffi_verify_final(
        &self,
        session: CkSessionHandle,
        signature: &[u8],
    ) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_VerifyFinal }, |function| {
            session_unit_input!(session, signature, function)
        })
    }

    pub(super) fn ffi_digest_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
    ) -> CkResult<()> {
        self.call_init_with_mechanism(
            session,
            unsafe { (*self.func_list).C_DigestInit },
            mechanism,
            |function, mech| unsafe { function(Self::session_handle(session), mech) },
        )
    }

    pub(super) fn ffi_digest_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_DigestInit }, |function| unsafe {
            function(Self::session_handle(session), std::ptr::null_mut())
        })?;
        self.drop_mech_cache(session);
        Ok(())
    }

    pub(super) fn ffi_digest(&self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        Self::call_bytes(unsafe { (*self.func_list).C_Digest }, |function, digest, digest_len| {
            session_bytes_input!(session, data, function, digest, digest_len)
        })
    }

    pub(super) fn ffi_digest_exact(
        &self,
        session: CkSessionHandle,
        data: &[u8],
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

    pub(super) fn ffi_digest_update(&self, session: CkSessionHandle, part: &[u8]) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_DigestUpdate }, |function| {
            session_unit_input!(session, part, function)
        })
    }

    pub(super) fn ffi_digest_key(
        &self,
        session: CkSessionHandle,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_DigestKey }, |function| {
            session_object_unit!(session, key, function)
        })
    }

    pub(super) fn ffi_digest_final(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        Self::call_bytes(
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
        self.call_init_with_mechanism_output(
            session,
            unsafe { (*self.func_list).C_EncryptInit },
            mechanism,
            |function, mech| mechanism_key_init!(session, mechanism, key, function, mech),
        )
    }

    pub(super) fn ffi_encrypt_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_EncryptInit }, |function| unsafe {
            function(Self::session_handle(session), std::ptr::null_mut(), 0)
        })?;
        self.drop_mech_cache(session);
        Ok(())
    }

    pub(super) fn ffi_encrypt(&self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        Self::call_bytes(unsafe { (*self.func_list).C_Encrypt }, |function, output, output_len| {
            session_bytes_input!(session, data, function, output, output_len)
        })
    }

    pub(super) fn ffi_encrypt_update(
        &self,
        session: CkSessionHandle,
        part: &[u8],
    ) -> CkResult<Vec<u8>> {
        Self::call_bytes(
            unsafe { (*self.func_list).C_EncryptUpdate },
            |function, output, output_len| {
                session_bytes_input!(session, part, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_encrypt_final(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        Self::call_bytes(
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
        self.call_init_with_mechanism_output(
            session,
            unsafe { (*self.func_list).C_DecryptInit },
            mechanism,
            |function, mech| mechanism_key_init!(session, mechanism, key, function, mech),
        )
    }

    pub(super) fn ffi_decrypt_init_cancel(&self, session: CkSessionHandle) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_DecryptInit }, |function| unsafe {
            function(Self::session_handle(session), std::ptr::null_mut(), 0)
        })?;
        self.drop_mech_cache(session);
        Ok(())
    }

    pub(super) fn ffi_decrypt(
        &self,
        session: CkSessionHandle,
        encrypted_data: &[u8],
    ) -> CkResult<Vec<u8>> {
        Self::call_bytes(unsafe { (*self.func_list).C_Decrypt }, |function, output, output_len| {
            session_bytes_input!(session, encrypted_data, function, output, output_len)
        })
    }

    pub(super) fn ffi_decrypt_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>> {
        Self::call_bytes(
            unsafe { (*self.func_list).C_DecryptUpdate },
            |function, output, output_len| {
                session_bytes_input!(session, encrypted_part, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_decrypt_final(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        Self::call_bytes(
            unsafe { (*self.func_list).C_DecryptFinal },
            |function, output, output_len| {
                session_bytes_final!(session, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_encrypt_exact(
        &self,
        session: CkSessionHandle,
        data: &[u8],
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
        data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, Option<CkMechanismParams>)> {
        let result = Self::call_bytes_exact(
            unsafe { (*self.func_list).C_Encrypt },
            spec,
            |function, output, output_len| {
                session_bytes_input!(session, data, function, output, output_len)
            },
        )?;
        let mechanism_out = if spec.buffer_present && result.ck_rv == CkRv::OK {
            self.cached_mechanism_output_params(session)
        } else {
            None
        };
        Ok((result, mechanism_out))
    }

    pub(super) fn ffi_encrypt_update_exact(
        &self,
        session: CkSessionHandle,
        part: &[u8],
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
        encrypted_data: &[u8],
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
        encrypted_part: &[u8],
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
