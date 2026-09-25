use super::{ffi_conversion::narrow_wire_ulong, session_bytes_input, *};

/// Maximum bytes a single `C_GenerateRandom` may request. Random output cannot
/// be returned short, so an over-large request is rejected (CKR_DATA_LEN_RANGE)
/// rather than clamped — preventing a multi-GB allocation in the shared daemon
/// from one client-supplied uint32.
pub(super) const MAX_RANDOM_BYTES: usize = super::call_helpers::MAX_OUTPUT_BUFFER_BYTES as usize;

/// Validate a client-supplied random length against the allocation bound.
pub(super) fn checked_random_len(len: u32) -> CkResult<usize> {
    if len as usize > MAX_RANDOM_BYTES { Err(CkRv::DATA_LEN_RANGE) } else { Ok(len as usize) }
}

/// Maximum bytes a single `C_GenerateRandom` may request. Random output cannot
/// be returned short, so an over-large request is rejected (CKR_DATA_LEN_RANGE)
/// rather than clamped — preventing a multi-GB allocation in the shared daemon
/// from one client-supplied uint32.
pub(super) const MAX_RANDOM_BYTES: usize = super::call_helpers::MAX_OUTPUT_BUFFER_BYTES as usize;

/// Validate a client-supplied random length against the allocation bound.
pub(super) fn checked_random_len(len: u32) -> CkResult<usize> {
    if len as usize > MAX_RANDOM_BYTES { Err(CkRv::DATA_LEN_RANGE) } else { Ok(len as usize) }
}

impl FfiBackend {
    pub(super) fn ffi_derive_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let ffi_attrs = FfiAttrs::from_opt_slice(template)?;
        let h_session = Self::session_handle(session)?;
        let h_base_key = Self::object_handle(base_key)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_object_with_mechanism(
            &admission,
            unsafe { (*self.func_list).C_DeriveKey },
            mechanism,
            |function, mech, handle| unsafe {
                function(
                    h_session,
                    mech,
                    h_base_key,
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
        template: Option<&[CkAttribute]>,
    ) -> CkResult<(CkObjectHandle, Option<CkMechanismParams>)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let ffi_attrs = FfiAttrs::from_opt_slice(template)?;
        let h_session = Self::session_handle(session)?;
        let h_base_key = Self::object_handle(base_key)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_object_with_mechanism_output(
            &admission,
            unsafe { (*self.func_list).C_DeriveKey },
            mechanism,
            |function, mech, handle| unsafe {
                function(
                    h_session,
                    mech,
                    h_base_key,
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
        template: Option<&[CkAttribute]>,
    ) -> CkResult<crate::traits::CkDeriveKeyOutputResult> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let ffi_attrs = FfiAttrs::from_opt_slice(template)?;
        let h_session = Self::session_handle(session)?;
        let h_base_key = Self::object_handle(base_key)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_object_with_mechanism_output_result(
            &admission,
            unsafe { (*self.func_list).C_DeriveKey },
            mechanism,
            |function, mech, handle| unsafe {
                function(
                    h_session,
                    mech,
                    h_base_key,
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
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        let h_wrapping_key = Self::object_handle(wrapping_key)?;
        let h_key = Self::object_handle(key)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_bytes_with_mechanism(
            &admission,
            unsafe { (*self.func_list).C_WrapKey },
            mechanism,
            |function, mech, output, output_len| unsafe {
                function(h_session, mech, h_wrapping_key, h_key, output, output_len)
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        let h_wrapping_key = Self::object_handle(wrapping_key)?;
        let h_key = Self::object_handle(key)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_bytes_exact_with_mechanism(
            &admission,
            unsafe { (*self.func_list).C_WrapKey },
            mechanism,
            spec,
            |function, mech, output, output_len| unsafe {
                function(h_session, mech, h_wrapping_key, h_key, output, output_len)
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        let h_wrapping_key = Self::object_handle(wrapping_key)?;
        let h_key = Self::object_handle(key)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_bytes_exact_with_mechanism_output(
            &admission,
            unsafe { (*self.func_list).C_WrapKey },
            mechanism,
            spec,
            |function, mech, output, output_len| unsafe {
                function(h_session, mech, h_wrapping_key, h_key, output, output_len)
            },
        )
    }

    pub(super) fn ffi_unwrap_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        unwrapping_key: CkObjectHandle,
        wrapped_key: CkInBuf<'_>,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let ffi_attrs = FfiAttrs::from_slice(template);
        let (wk_ptr, wk_len) = wrapped_key.as_ptr_len();
        Self::call_object_with_mechanism(
            &admission,
            unsafe { (*self.func_list).C_UnwrapKey },
            mechanism,
            |function, mech, handle| unsafe {
                function(
                    h_session,
                    mech,
                    Self::object_handle(unwrapping_key),
                    wk_ptr as *mut _,
                    Self::ulong_len_u64(wk_len),
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
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let ffi_attrs = FfiAttrs::from_opt_slice(template)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_object_with_mechanism(
            &admission,
            unsafe { (*self.func_list).C_GenerateKey },
            mechanism,
            |function, mech, handle| unsafe {
                function(
                    h_session,
                    mech,
                    Self::ffi_attr_ptr(&ffi_attrs),
                    Self::ffi_attr_len(&ffi_attrs),
                    handle,
                )
            },
        )
    }

    /// `C_GenerateKey` capturing HSM-written mechanism params (e.g. the
    /// generated `CK_PBE_PARAMS.pInitVector`). Mirrors `ffi_derive_key_with_output`.
    pub(super) fn ffi_generate_key_with_output(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<(CkObjectHandle, Option<CkMechanismParams>)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let ffi_attrs = FfiAttrs::from_opt_slice(template)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_object_with_mechanism_output(
            &admission,
            unsafe { (*self.func_list).C_GenerateKey },
            mechanism,
            |function, mech, handle| unsafe {
                function(
                    h_session,
                    mech,
                    Self::ffi_attr_ptr(&ffi_attrs),
                    Self::ffi_attr_len(&ffi_attrs),
                    handle,
                )
            },
        )
    }

    /// `C_GenerateKey` capturing HSM-written mechanism params (e.g. the
    /// generated `CK_PBE_PARAMS.pInitVector`). Mirrors `ffi_derive_key_with_output`.
    pub(super) fn ffi_generate_key_with_output(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        template: &[CkAttribute],
    ) -> CkResult<(CkObjectHandle, Option<CkMechanismParams>)> {
        let ffi_attrs = FfiAttrs::from_slice(template);
        Self::call_object_with_mechanism_output(
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
        pub_template: Option<&[CkAttribute]>,
        priv_template: Option<&[CkAttribute]>,
    ) -> CkResult<(CkObjectHandle, CkObjectHandle)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let pub_ffi = FfiAttrs::from_opt_slice(pub_template)?;
        let priv_ffi = FfiAttrs::from_opt_slice(priv_template)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_object_pair_with_mechanism(
            &admission,
            unsafe { (*self.func_list).C_GenerateKeyPair },
            mechanism,
            |function, mech, public_handle, private_handle| unsafe {
                function(
                    h_session,
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
        // Ownership ordered boundary: lifecycle first, then checked width,
        // then mode, then waiter contention ("lifecycle precedes width,
        // width precedes mode, and mode precedes contention"). Flags the
        // native CK_FLAGS cannot represent fail loudly (FUNCTION_FAILED) —
        // a native module could not have been handed that value either —
        // and blocking mode is refused locally (FUNCTION_NOT_SUPPORTED) so
        // no native wait can block the daemon worker. Every refusal is
        // local with zero native attempts; the sole supported DONT_BLOCK
        // reservation preserves every original bit, including
        // representable unknown ones.
        let admission = match self.lifecycle_domain.admit_ordinary() {
            Ok(guard) => guard,
            Err(error) => {
                // Wait-table row: an Uncertain domain refuses DEVICE_ERROR.
                // Admission itself reports GENERAL_ERROR for every ordinary
                // path, so the wait boundary maps it here; the peek races
                // benignly (both outcomes are local zero-native refusals).
                if self.lifecycle_domain.is_uncertain() {
                    return Err(CkRv::DEVICE_ERROR);
                }
                return Err(error);
            }
        };
        let native_flags = narrow_wire_ulong(flags)?;
        if native_flags & cryptoki_sys::CKF_DONT_BLOCK == 0 {
            return Err(CkRv::FUNCTION_NOT_SUPPORTED);
        }
        let mut waiter = self.lifecycle_domain.reserve_waiter(&admission, flags)?;
        let function = Self::require_fn(unsafe { (*self.func_list).C_WaitForSlotEvent })?;
        waiter.commit_native()?;
        let result = Self::call_slot_output(&admission, Some(function), |function, slot| unsafe {
            function(native_flags, slot, std::ptr::null_mut())
        });
        match &result {
            Ok(_) => waiter.note_returned(0, true),
            Err(error) => waiter.note_returned(error.0, false),
        }
        result
    }

    pub(super) fn ffi_get_operation_state(
        &self,
        session: CkSessionHandle,
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_GetOperationState },
            |function, state, state_len| unsafe { function(h_session, state, state_len) },
        )
    }

    pub(super) fn ffi_get_operation_state_exact(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_bytes_exact(
            &admission,
            unsafe { (*self.func_list).C_GetOperationState },
            spec,
            |function, state, state_len| unsafe { function(h_session, state, state_len) },
        )
    }

    pub(super) fn ffi_set_operation_state(
        &self,
        session: CkSessionHandle,
        state: CkInBuf<'_>,
        enc_key: CkObjectHandle,
        auth_key: CkObjectHandle,
    ) -> CkResult<()> {
        let (state_ptr, state_len) = state.as_ptr_len();
        Self::call_unit(unsafe { (*self.func_list).C_SetOperationState }, |function| unsafe {
            function(
                Self::session_handle(session),
                state_ptr as *mut _,
                Self::ulong_len_u64(state_len),
                Self::object_handle(enc_key),
                Self::object_handle(auth_key),
            )
        })
    }

    pub(super) fn ffi_seed_random(
        &self,
        session: CkSessionHandle,
        seed: CkInBuf<'_>,
    ) -> CkResult<()> {
        let (seed_ptr, seed_len) = seed.as_ptr_len();
        Self::call_unit(unsafe { (*self.func_list).C_SeedRandom }, |function| unsafe {
            function(
                Self::session_handle(session),
                seed_ptr as *mut _,
                Self::ulong_len_u64(seed_len),
            )
        })
    }

    pub(super) fn ffi_generate_random(
        &self,
        session: CkSessionHandle,
        len: u32,
    ) -> CkResult<Vec<u8>> {
        let len = checked_random_len(len)?;
        Self::fill_bytes(
            &admission,
            unsafe { (*self.func_list).C_GenerateRandom },
            len,
            |function, output, output_len| unsafe {
                function(Self::session_handle(session), output, output_len)
            },
        )
    }

    pub(super) fn ffi_digest_encrypt_update(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
    ) -> CkResult<Vec<u8>> {
        let (part_ptr, part_len) = part.as_ptr_len();
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_DigestEncryptUpdate },
            |function, output, output_len| unsafe {
                function(
                    Self::session_handle(session),
                    part_ptr as *mut _,
                    Self::ulong_len_u64(part_len),
                    output,
                    output_len,
                )
            },
        )
    }

    pub(super) fn ffi_digest_encrypt_update_exact(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_bytes_exact(
            &admission,
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
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<Vec<u8>> {
        let (ep_ptr, ep_len) = encrypted_part.as_ptr_len();
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_DecryptDigestUpdate },
            |function, output, output_len| unsafe {
                function(
                    Self::session_handle(session),
                    ep_ptr as *mut _,
                    Self::ulong_len_u64(ep_len),
                    output,
                    output_len,
                )
            },
        )
    }

    pub(super) fn ffi_decrypt_digest_update_exact(
        &self,
        session: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_bytes_exact(
            &admission,
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
        part: CkInBuf<'_>,
    ) -> CkResult<Vec<u8>> {
        let (part_ptr, part_len) = part.as_ptr_len();
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_SignEncryptUpdate },
            |function, output, output_len| unsafe {
                function(
                    Self::session_handle(session),
                    part_ptr as *mut _,
                    Self::ulong_len_u64(part_len),
                    output,
                    output_len,
                )
            },
        )
    }

    pub(super) fn ffi_sign_encrypt_update_exact(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_bytes_exact(
            &admission,
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
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<Vec<u8>> {
        let (ep_ptr, ep_len) = encrypted_part.as_ptr_len();
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_DecryptVerifyUpdate },
            |function, output, output_len| unsafe {
                function(
                    Self::session_handle(session),
                    ep_ptr as *mut _,
                    Self::ulong_len_u64(ep_len),
                    output,
                    output_len,
                )
            },
        )
    }

    pub(super) fn ffi_decrypt_verify_update_exact(
        &self,
        session: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_bytes_exact(
            &admission,
            unsafe { (*self.func_list).C_DecryptVerifyUpdate },
            spec,
            |function, output, output_len| {
                session_bytes_input!(session, encrypted_part, function, output, output_len)
            },
        )
    }
}

#[cfg(test)]
mod generate_random_bound_tests {
    use super::{MAX_RANDOM_BYTES, checked_random_len};
    use pkcs11_proxy_ng_types::CkRv;

    #[test]
    fn rejects_absurd_length() {
        // ~4 GB from one uint32 must be rejected, not allocated.
        assert_eq!(checked_random_len(u32::MAX), Err(CkRv::DATA_LEN_RANGE));
    }

    #[test]
    fn accepts_reasonable_length() {
        assert_eq!(checked_random_len(1024), Ok(1024));
        assert_eq!(checked_random_len(0), Ok(0));
    }

    #[test]
    fn bound_is_512_mib() {
        assert_eq!(MAX_RANDOM_BYTES, 512 * 1024 * 1024);
    }
}
