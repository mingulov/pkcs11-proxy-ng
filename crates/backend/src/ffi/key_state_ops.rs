use super::{session_bytes_input, *};

impl FfiBackend {
    pub(super) fn ffi_derive_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let ffi_attrs = FfiAttrs::from_slice(template);
        Self::call_object_with_mechanism(
            unsafe { (*self.func_list).C_DeriveKey },
            mechanism,
            |function, mech, handle| unsafe {
                function(
                    Self::session_handle(session),
                    mech,
                    Self::object_handle(base_key),
                    Self::ffi_attr_ptr(&ffi_attrs),
                    Self::ffi_attr_len(&ffi_attrs),
                    handle,
                )
            },
        )
    }

    /// `C_DeriveKey` returning the derived key handle plus
    /// HSM-mutated mechanism params (e.g. the negotiated `CK_VERSION`
    /// from `CKM_TLS12_MASTER_KEY_DERIVE.pVersion`).  See AGENTS.md
    /// §2 — behavioural parity with a native PKCS#11 module.
    pub(super) fn ffi_derive_key_with_output(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<(CkObjectHandle, Option<CkMechanismParams>)> {
        let ffi_attrs = FfiAttrs::from_slice(template);
        Self::call_object_with_mechanism_output(
            unsafe { (*self.func_list).C_DeriveKey },
            mechanism,
            |function, mech, handle| unsafe {
                function(
                    Self::session_handle(session),
                    mech,
                    Self::object_handle(base_key),
                    Self::ffi_attr_ptr(&ffi_attrs),
                    Self::ffi_attr_len(&ffi_attrs),
                    handle,
                )
            },
        )
    }

    pub(super) fn ffi_derive_key_with_output_result(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<crate::traits::CkDeriveKeyOutputResult> {
        let ffi_attrs = FfiAttrs::from_slice(template);
        Self::call_object_with_mechanism_output_result(
            unsafe { (*self.func_list).C_DeriveKey },
            mechanism,
            |function, mech, handle| unsafe {
                function(
                    Self::session_handle(session),
                    mech,
                    Self::object_handle(base_key),
                    Self::ffi_attr_ptr(&ffi_attrs),
                    Self::ffi_attr_len(&ffi_attrs),
                    handle,
                )
            },
        )
    }

    pub(super) fn ffi_wrap_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
    ) -> CkResult<Vec<u8>> {
        Self::call_bytes_with_mechanism(
            unsafe { (*self.func_list).C_WrapKey },
            mechanism,
            |function, mech, output, output_len| unsafe {
                function(
                    Self::session_handle(session),
                    mech,
                    Self::object_handle(wrapping_key),
                    Self::object_handle(key),
                    output,
                    output_len,
                )
            },
        )
    }

    pub(super) fn ffi_wrap_key_exact(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact_with_mechanism(
            unsafe { (*self.func_list).C_WrapKey },
            mechanism,
            spec,
            |function, mech, output, output_len| unsafe {
                function(
                    Self::session_handle(session),
                    mech,
                    Self::object_handle(wrapping_key),
                    Self::object_handle(key),
                    output,
                    output_len,
                )
            },
        )
    }

    /// `C_WrapKey` with mechanism-param write-back so HSM-generated values
    /// (most importantly the AES-GCM IV when wrapping with `CKM_AES_GCM`)
    /// round-trip back to the caller's `CK_MECHANISM`.  See AGENTS.md
    /// §2/§3 — the proxy must behave like a native PKCS#11 module.
    pub(super) fn ffi_wrap_key_exact_with_output(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, Option<CkMechanismParams>)> {
        Self::call_bytes_exact_with_mechanism_output(
            unsafe { (*self.func_list).C_WrapKey },
            mechanism,
            spec,
            |function, mech, output, output_len| unsafe {
                function(
                    Self::session_handle(session),
                    mech,
                    Self::object_handle(wrapping_key),
                    Self::object_handle(key),
                    output,
                    output_len,
                )
            },
        )
    }

    pub(super) fn ffi_unwrap_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        unwrapping_key: CkObjectHandle,
        wrapped_key: &[u8],
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let ffi_attrs = FfiAttrs::from_slice(template);
        Self::call_object_with_mechanism(
            unsafe { (*self.func_list).C_UnwrapKey },
            mechanism,
            |function, mech, handle| unsafe {
                function(
                    Self::session_handle(session),
                    mech,
                    Self::object_handle(unwrapping_key),
                    wrapped_key.as_ptr() as *mut _,
                    Self::ulong_len(wrapped_key.len()),
                    Self::ffi_attr_ptr(&ffi_attrs),
                    Self::ffi_attr_len(&ffi_attrs),
                    handle,
                )
            },
        )
    }

    pub(super) fn ffi_generate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let ffi_attrs = FfiAttrs::from_slice(template);
        Self::call_object_with_mechanism(
            unsafe { (*self.func_list).C_GenerateKey },
            mechanism,
            |function, mech, handle| unsafe {
                function(
                    Self::session_handle(session),
                    mech,
                    Self::ffi_attr_ptr(&ffi_attrs),
                    Self::ffi_attr_len(&ffi_attrs),
                    handle,
                )
            },
        )
    }

    pub(super) fn ffi_generate_key_pair(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        pub_template: &[CkAttribute],
        priv_template: &[CkAttribute],
    ) -> CkResult<(CkObjectHandle, CkObjectHandle)> {
        let pub_ffi = FfiAttrs::from_slice(pub_template);
        let priv_ffi = FfiAttrs::from_slice(priv_template);
        Self::call_object_pair_with_mechanism(
            unsafe { (*self.func_list).C_GenerateKeyPair },
            mechanism,
            |function, mech, public_handle, private_handle| unsafe {
                function(
                    Self::session_handle(session),
                    mech,
                    Self::ffi_attr_ptr(&pub_ffi),
                    Self::ffi_attr_len(&pub_ffi),
                    Self::ffi_attr_ptr(&priv_ffi),
                    Self::ffi_attr_len(&priv_ffi),
                    public_handle,
                    private_handle,
                )
            },
        )
    }

    pub(super) fn ffi_wait_for_slot_event(&self, flags: u64) -> CkResult<CkSlotId> {
        Self::call_slot_output(
            unsafe { (*self.func_list).C_WaitForSlotEvent },
            |function, slot| unsafe {
                function(flags as cryptoki_sys::CK_FLAGS, slot, std::ptr::null_mut())
            },
        )
    }

    pub(super) fn ffi_get_operation_state(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        Self::call_bytes(
            unsafe { (*self.func_list).C_GetOperationState },
            |function, state, state_len| unsafe {
                function(Self::session_handle(session), state, state_len)
            },
        )
    }

    pub(super) fn ffi_get_operation_state_exact(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_GetOperationState },
            spec,
            |function, state, state_len| unsafe {
                function(Self::session_handle(session), state, state_len)
            },
        )
    }

    pub(super) fn ffi_set_operation_state(
        &self,
        session: CkSessionHandle,
        state: &[u8],
        enc_key: CkObjectHandle,
        auth_key: CkObjectHandle,
    ) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_SetOperationState }, |function| unsafe {
            function(
                Self::session_handle(session),
                state.as_ptr() as *mut _,
                Self::ulong_len(state.len()),
                Self::object_handle(enc_key),
                Self::object_handle(auth_key),
            )
        })
    }

    pub(super) fn ffi_seed_random(&self, session: CkSessionHandle, seed: &[u8]) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_SeedRandom }, |function| unsafe {
            function(
                Self::session_handle(session),
                seed.as_ptr() as *mut _,
                Self::ulong_len(seed.len()),
            )
        })
    }

    pub(super) fn ffi_generate_random(
        &self,
        session: CkSessionHandle,
        len: u32,
    ) -> CkResult<Vec<u8>> {
        Self::fill_bytes(
            unsafe { (*self.func_list).C_GenerateRandom },
            len as usize,
            |function, output, output_len| unsafe {
                function(Self::session_handle(session), output, output_len)
            },
        )
    }

    pub(super) fn ffi_digest_encrypt_update(
        &self,
        session: CkSessionHandle,
        part: &[u8],
    ) -> CkResult<Vec<u8>> {
        Self::call_bytes(
            unsafe { (*self.func_list).C_DigestEncryptUpdate },
            |function, output, output_len| unsafe {
                function(
                    Self::session_handle(session),
                    part.as_ptr() as *mut _,
                    Self::ulong_len(part.len()),
                    output,
                    output_len,
                )
            },
        )
    }

    pub(super) fn ffi_digest_encrypt_update_exact(
        &self,
        session: CkSessionHandle,
        part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_DigestEncryptUpdate },
            spec,
            |function, output, output_len| {
                session_bytes_input!(session, part, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_decrypt_digest_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>> {
        Self::call_bytes(
            unsafe { (*self.func_list).C_DecryptDigestUpdate },
            |function, output, output_len| unsafe {
                function(
                    Self::session_handle(session),
                    encrypted_part.as_ptr() as *mut _,
                    Self::ulong_len(encrypted_part.len()),
                    output,
                    output_len,
                )
            },
        )
    }

    pub(super) fn ffi_decrypt_digest_update_exact(
        &self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_DecryptDigestUpdate },
            spec,
            |function, output, output_len| {
                session_bytes_input!(session, encrypted_part, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_sign_encrypt_update(
        &self,
        session: CkSessionHandle,
        part: &[u8],
    ) -> CkResult<Vec<u8>> {
        Self::call_bytes(
            unsafe { (*self.func_list).C_SignEncryptUpdate },
            |function, output, output_len| unsafe {
                function(
                    Self::session_handle(session),
                    part.as_ptr() as *mut _,
                    Self::ulong_len(part.len()),
                    output,
                    output_len,
                )
            },
        )
    }

    pub(super) fn ffi_sign_encrypt_update_exact(
        &self,
        session: CkSessionHandle,
        part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_SignEncryptUpdate },
            spec,
            |function, output, output_len| {
                session_bytes_input!(session, part, function, output, output_len)
            },
        )
    }

    pub(super) fn ffi_decrypt_verify_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>> {
        Self::call_bytes(
            unsafe { (*self.func_list).C_DecryptVerifyUpdate },
            |function, output, output_len| unsafe {
                function(
                    Self::session_handle(session),
                    encrypted_part.as_ptr() as *mut _,
                    Self::ulong_len(encrypted_part.len()),
                    output,
                    output_len,
                )
            },
        )
    }

    pub(super) fn ffi_decrypt_verify_update_exact(
        &self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Self::call_bytes_exact(
            unsafe { (*self.func_list).C_DecryptVerifyUpdate },
            spec,
            |function, output, output_len| {
                session_bytes_input!(session, encrypted_part, function, output, output_len)
            },
        )
    }
}
