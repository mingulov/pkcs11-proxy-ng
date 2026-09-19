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
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let ffi_attrs = FfiAttrs::from_opt_slice(template)?;
        let (wk_ptr, wk_len) = wrapped_key.as_ptr_len();
        let h_session = Self::session_handle(session)?;
        let h_unwrapping_key = Self::object_handle(unwrapping_key)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_object_with_mechanism(
            &admission,
            unsafe { (*self.func_list).C_UnwrapKey },
            mechanism,
            |function, mech, handle| unsafe {
                function(
                    h_session,
                    mech,
                    h_unwrapping_key,
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (state_ptr, state_len) = state.as_ptr_len();
        let h_session = Self::session_handle(session)?;
        let h_enc_key = Self::object_handle(enc_key)?;
        let h_auth_key = Self::object_handle(auth_key)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(
            &admission,
            unsafe { (*self.func_list).C_SetOperationState },
            |function| unsafe {
                function(
                    h_session,
                    state_ptr as *mut _,
                    Self::ulong_len_u64(state_len),
                    h_enc_key,
                    h_auth_key,
                )
            },
        )
    }

    pub(super) fn ffi_seed_random(
        &self,
        session: CkSessionHandle,
        seed: CkInBuf<'_>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (seed_ptr, seed_len) = seed.as_ptr_len();
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(&admission, unsafe { (*self.func_list).C_SeedRandom }, |function| unsafe {
            function(h_session, seed_ptr as *mut _, Self::ulong_len_u64(seed_len))
        })
    }

    pub(super) fn ffi_generate_random(
        &self,
        session: CkSessionHandle,
        len: u32,
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let len = checked_random_len(len)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::fill_bytes(
            &admission,
            unsafe { (*self.func_list).C_GenerateRandom },
            len,
            |function, output, output_len| unsafe { function(h_session, output, output_len) },
        )
    }

    pub(super) fn ffi_digest_encrypt_update(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (part_ptr, part_len) = part.as_ptr_len();
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_DigestEncryptUpdate },
            |function, output, output_len| unsafe {
                function(
                    h_session,
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
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (ep_ptr, ep_len) = encrypted_part.as_ptr_len();
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_DecryptDigestUpdate },
            |function, output, output_len| unsafe {
                function(
                    h_session,
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
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (part_ptr, part_len) = part.as_ptr_len();
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_SignEncryptUpdate },
            |function, output, output_len| unsafe {
                function(
                    h_session,
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
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (ep_ptr, ep_len) = encrypted_part.as_ptr_len();
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_bytes(
            &admission,
            unsafe { (*self.func_list).C_DecryptVerifyUpdate },
            |function, output, output_len| unsafe {
                function(
                    h_session,
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

#[cfg(all(test, unix))]
mod lifecycle_mech_tests {
    use super::*;
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;

    unsafe extern "C" fn derive_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _mechanism: *mut cryptoki_sys::CK_MECHANISM,
        _base_key: cryptoki_sys::CK_OBJECT_HANDLE,
        _template: cryptoki_sys::CK_ATTRIBUTE_PTR,
        _count: cryptoki_sys::CK_ULONG,
        handle: *mut cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        if !handle.is_null() {
            unsafe { *handle = 51 };
        }
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn wrap_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _mechanism: *mut cryptoki_sys::CK_MECHANISM,
        _wrapping_key: cryptoki_sys::CK_OBJECT_HANDLE,
        _key: cryptoki_sys::CK_OBJECT_HANDLE,
        output: *mut cryptoki_sys::CK_BYTE,
        output_len: *mut cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        if output_len.is_null() {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }
        if output.is_null() {
            unsafe { *output_len = 8 };
            return cryptoki_sys::CKR_OK;
        }
        let n = unsafe { *output_len }.min(8) as usize;
        unsafe { std::ptr::write_bytes(output, 0xC3, n) };
        unsafe { *output_len = n as cryptoki_sys::CK_ULONG };
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn keypair_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _mechanism: *mut cryptoki_sys::CK_MECHANISM,
        _pub_template: cryptoki_sys::CK_ATTRIBUTE_PTR,
        _pub_count: cryptoki_sys::CK_ULONG,
        _priv_template: cryptoki_sys::CK_ATTRIBUTE_PTR,
        _priv_count: cryptoki_sys::CK_ULONG,
        pub_handle: *mut cryptoki_sys::CK_OBJECT_HANDLE,
        priv_handle: *mut cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        if !pub_handle.is_null() {
            unsafe { *pub_handle = 61 };
        }
        if !priv_handle.is_null() {
            unsafe { *priv_handle = 62 };
        }
        cryptoki_sys::CKR_OK
    }

    fn backend_with_mech_stubs() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_DeriveKey = Some(derive_ok);
        functions.C_WrapKey = Some(wrap_ok);
        functions.C_GenerateKeyPair = Some(keypair_ok);
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
            session_fences: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
        (backend, functions)
    }

    fn cbc_mechanism() -> CkMechanism {
        CkMechanism {
            mechanism_type: CkMechanismType::AES_CBC,
            params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0x11; 16] })),
        }
    }

    fn data_spec() -> CkOutputBufferSpec {
        CkOutputBufferSpec { buffer_present: true, buffer_len: 8, length_pointer_null: false }
    }

    #[test]
    fn derive_key_denied_before_lifecycle_open() {
        // TF01b `call_object_with_mechanism` ordinary proof: no admission
        // pre-Init.
        let (backend, _functions) = backend_with_mech_stubs();
        assert_eq!(
            backend
                .ffi_derive_key(CkSessionHandle(7), &cbc_mechanism(), CkObjectHandle(9), None)
                .unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn derive_key_admitted_after_lifecycle_open() {
        let (backend, _functions) = backend_with_mech_stubs();
        backend.lifecycle_domain.open_for_tests();
        assert_eq!(
            backend
                .ffi_derive_key(CkSessionHandle(7), &cbc_mechanism(), CkObjectHandle(9), None)
                .unwrap(),
            CkObjectHandle(51)
        );
    }

    #[test]
    fn derive_key_with_output_denied_before_lifecycle_open() {
        // TF01b `call_object_with_mechanism_output` ordinary proof.
        let (backend, _functions) = backend_with_mech_stubs();
        assert_eq!(
            backend
                .ffi_derive_key_with_output(
                    CkSessionHandle(7),
                    &cbc_mechanism(),
                    CkObjectHandle(9),
                    None
                )
                .unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn derive_key_with_output_admitted_after_lifecycle_open() {
        let (backend, _functions) = backend_with_mech_stubs();
        backend.lifecycle_domain.open_for_tests();
        let (handle, _) = backend
            .ffi_derive_key_with_output(
                CkSessionHandle(7),
                &cbc_mechanism(),
                CkObjectHandle(9),
                None,
            )
            .unwrap();
        assert_eq!(handle, CkObjectHandle(51));
    }

    #[test]
    fn derive_key_with_output_result_denied_before_lifecycle_open() {
        // TF01b `call_object_with_mechanism_output_result` ordinary proof.
        let (backend, _functions) = backend_with_mech_stubs();
        assert_eq!(
            backend
                .ffi_derive_key_with_output_result(
                    CkSessionHandle(7),
                    &cbc_mechanism(),
                    CkObjectHandle(9),
                    None
                )
                .unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn derive_key_with_output_result_admitted_after_lifecycle_open() {
        let (backend, _functions) = backend_with_mech_stubs();
        backend.lifecycle_domain.open_for_tests();
        let result = backend
            .ffi_derive_key_with_output_result(
                CkSessionHandle(7),
                &cbc_mechanism(),
                CkObjectHandle(9),
                None,
            )
            .unwrap();
        assert_eq!(result.rv, CkRv::OK);
        assert_eq!(result.key_handle, Some(CkObjectHandle(51)));
    }

    #[test]
    fn wrap_key_denied_before_lifecycle_open() {
        // TF01b `call_bytes_with_mechanism` ordinary proof.
        let (backend, _functions) = backend_with_mech_stubs();
        assert_eq!(
            backend
                .ffi_wrap_key(
                    CkSessionHandle(7),
                    &cbc_mechanism(),
                    CkObjectHandle(8),
                    CkObjectHandle(9)
                )
                .unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn wrap_key_admitted_after_lifecycle_open() {
        let (backend, _functions) = backend_with_mech_stubs();
        backend.lifecycle_domain.open_for_tests();
        let bytes = backend
            .ffi_wrap_key(
                CkSessionHandle(7),
                &cbc_mechanism(),
                CkObjectHandle(8),
                CkObjectHandle(9),
            )
            .unwrap();
        assert_eq!(bytes.expose(|raw| raw.to_vec()), vec![0xC3; 8]);
    }

    #[test]
    fn wrap_key_exact_denied_before_lifecycle_open() {
        // TF01b `call_bytes_exact_with_mechanism` ordinary proof.
        let (backend, _functions) = backend_with_mech_stubs();
        assert_eq!(
            backend
                .ffi_wrap_key_exact(
                    CkSessionHandle(7),
                    &cbc_mechanism(),
                    CkObjectHandle(8),
                    CkObjectHandle(9),
                    &data_spec(),
                )
                .unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn wrap_key_exact_admitted_after_lifecycle_open() {
        let (backend, _functions) = backend_with_mech_stubs();
        backend.lifecycle_domain.open_for_tests();
        let result = backend
            .ffi_wrap_key_exact(
                CkSessionHandle(7),
                &cbc_mechanism(),
                CkObjectHandle(8),
                CkObjectHandle(9),
                &data_spec(),
            )
            .unwrap();
        assert_eq!(result.ck_rv, CkRv::OK);
    }

    #[test]
    fn wrap_key_exact_with_output_denied_before_lifecycle_open() {
        // TF01b `call_bytes_exact_with_mechanism_output` ordinary proof.
        let (backend, _functions) = backend_with_mech_stubs();
        assert_eq!(
            backend
                .ffi_wrap_key_exact_with_output(
                    CkSessionHandle(7),
                    &cbc_mechanism(),
                    CkObjectHandle(8),
                    CkObjectHandle(9),
                    &data_spec(),
                )
                .unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn wrap_key_exact_with_output_admitted_after_lifecycle_open() {
        let (backend, _functions) = backend_with_mech_stubs();
        backend.lifecycle_domain.open_for_tests();
        let (result, _) = backend
            .ffi_wrap_key_exact_with_output(
                CkSessionHandle(7),
                &cbc_mechanism(),
                CkObjectHandle(8),
                CkObjectHandle(9),
                &data_spec(),
            )
            .unwrap();
        assert_eq!(result.ck_rv, CkRv::OK);
    }

    #[test]
    fn generate_key_pair_denied_before_lifecycle_open() {
        // TF01b `call_object_pair_with_mechanism` ordinary proof.
        let (backend, _functions) = backend_with_mech_stubs();
        assert_eq!(
            backend
                .ffi_generate_key_pair(CkSessionHandle(7), &cbc_mechanism(), None, None)
                .unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn generate_key_pair_admitted_after_lifecycle_open() {
        let (backend, _functions) = backend_with_mech_stubs();
        backend.lifecycle_domain.open_for_tests();
        assert_eq!(
            backend
                .ffi_generate_key_pair(CkSessionHandle(7), &cbc_mechanism(), None, None)
                .unwrap(),
            (CkObjectHandle(61), CkObjectHandle(62))
        );
    }

    // Blocked-stub exclusion shape (object-with-mechanism family): a parked
    // ordinary call blocks control settlement until release.
    static DERIVE_PARK_GATE: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>> =
        Mutex::new(None);

    unsafe extern "C" fn derive_parkable(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        _mechanism: *mut cryptoki_sys::CK_MECHANISM,
        _base_key: cryptoki_sys::CK_OBJECT_HANDLE,
        _template: cryptoki_sys::CK_ATTRIBUTE_PTR,
        _count: cryptoki_sys::CK_ULONG,
        handle: *mut cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        let gate = DERIVE_PARK_GATE.lock().unwrap().take();
        match gate {
            Some((entered, release)) => {
                let _ = entered.send(());
                match release.recv_timeout(Duration::from_secs(10)) {
                    Ok(()) => {
                        if !handle.is_null() {
                            unsafe { *handle = 51 };
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

    #[test]
    fn parked_derive_key_blocks_control_until_release() {
        let (backend, _functions) = backend_with_mech_stubs();
        backend.lifecycle_domain.open_for_tests();
        unsafe { (*backend.func_list).C_DeriveKey = Some(derive_parkable) };
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *DERIVE_PARK_GATE.lock().unwrap() = Some((entered_tx, release_rx));
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                backend.ffi_derive_key(
                    CkSessionHandle(7),
                    &cbc_mechanism(),
                    CkObjectHandle(9),
                    None,
                )
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
}

#[cfg(all(test, unix))]
mod lifecycle_op_state_tests {
    use super::*;

    unsafe extern "C" fn op_state_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        output: *mut cryptoki_sys::CK_BYTE,
        output_len: *mut cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        if output_len.is_null() {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }
        if output.is_null() {
            unsafe { *output_len = 6 };
            return cryptoki_sys::CKR_OK;
        }
        let n = unsafe { *output_len }.min(6) as usize;
        unsafe { std::ptr::write_bytes(output, 0x5A, n) };
        unsafe { *output_len = n as cryptoki_sys::CK_ULONG };
        cryptoki_sys::CKR_OK
    }

    fn backend_with_op_state() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_GetOperationState = Some(op_state_ok);
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
            session_fences: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
        (backend, functions)
    }

    #[test]
    fn get_operation_state_exact_denied_before_lifecycle_open() {
        // TF01b `call_bytes_exact` ordinary proof (second site): no admission
        // pre-Init.
        let (backend, _functions) = backend_with_op_state();
        let spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 8, length_pointer_null: false };
        assert_eq!(
            backend.ffi_get_operation_state_exact(CkSessionHandle(7), &spec).unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn get_operation_state_exact_admitted_after_lifecycle_open() {
        let (backend, _functions) = backend_with_op_state();
        backend.lifecycle_domain.open_for_tests();
        let spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 8, length_pointer_null: false };
        let result = backend.ffi_get_operation_state_exact(CkSessionHandle(7), &spec).unwrap();
        assert_eq!(result.ck_rv, CkRv::OK);
        assert_eq!(result.returned_len, Some(6));
    }
}

#[cfg(all(test, unix))]
mod lifecycle_random_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RANDOM_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RANDOM_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe extern "C" fn random_ok(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        output: *mut cryptoki_sys::CK_BYTE,
        len: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        RANDOM_CALLS.fetch_add(1, Ordering::SeqCst);
        if !output.is_null() {
            unsafe { std::ptr::write_bytes(output, 0xAB, len as usize) };
        }
        cryptoki_sys::CKR_OK
    }

    fn backend_with_random() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_GenerateRandom = Some(random_ok);
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
            session_fences: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
        (backend, functions)
    }

    #[test]
    fn generate_random_denied_before_lifecycle_open() {
        // TF01b `fill_bytes` ordinary proof: no admission pre-Init.
        let _guard = RANDOM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        RANDOM_CALLS.store(0, Ordering::SeqCst);
        let (backend, _functions) = backend_with_random();
        assert_eq!(
            backend.ffi_generate_random(CkSessionHandle(7), 16).unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
        assert_eq!(RANDOM_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn generate_random_admitted_after_lifecycle_open() {
        // Control: the same call reaches the stub once the domain is open.
        let _guard = RANDOM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        RANDOM_CALLS.store(0, Ordering::SeqCst);
        let (backend, _functions) = backend_with_random();
        backend.lifecycle_domain.open_for_tests();
        let bytes = backend.ffi_generate_random(CkSessionHandle(7), 16).unwrap();
        assert_eq!(RANDOM_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(bytes.expose(|raw| raw.to_vec()), vec![0xAB; 16]);
    }
}

#[cfg(all(test, unix))]
mod slot_wait_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    static SLOT_WAIT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SLOT_WAIT_FLAGS: AtomicU64 = AtomicU64::new(0);
    /// Scripted native RV (default `CKR_OK`).
    static SLOT_WAIT_RV: AtomicU64 = AtomicU64::new(0);
    /// Scripted native slot cell (default 7).
    static SLOT_WAIT_SLOT: AtomicU64 = AtomicU64::new(7);
    static SLOT_WAIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    /// Gate controls for the blocking stub (TO26b group 2): the stub
    /// records entry, parks until the gate opens, then answers with the
    /// scripted RV/slot. The park is bounded — a stuck test fails its RV
    /// loudly instead of hanging the suite.
    static GATED_WAIT_ENTERED: AtomicBool = AtomicBool::new(false);
    static GATED_WAIT_OPEN: AtomicBool = AtomicBool::new(false);
    /// Ordering flags for the no-Finalize-overlap test.
    static WAIT_RETURNED: AtomicBool = AtomicBool::new(false);
    static FINALIZE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FINALIZE_ENTERED_AFTER_WAIT_RETURN: AtomicBool = AtomicBool::new(false);

    fn reset_wait_fixture() {
        SLOT_WAIT_CALLS.store(0, Ordering::SeqCst);
        SLOT_WAIT_FLAGS.store(0, Ordering::SeqCst);
        SLOT_WAIT_RV.store(0, Ordering::SeqCst);
        SLOT_WAIT_SLOT.store(7, Ordering::SeqCst);
        GATED_WAIT_ENTERED.store(false, Ordering::SeqCst);
        GATED_WAIT_OPEN.store(false, Ordering::SeqCst);
        WAIT_RETURNED.store(false, Ordering::SeqCst);
        FINALIZE_CALLS.store(0, Ordering::SeqCst);
        FINALIZE_ENTERED_AFTER_WAIT_RETURN.store(false, Ordering::SeqCst);
    }

    unsafe extern "C" fn recording_wait(
        flags: cryptoki_sys::CK_FLAGS,
        slot: *mut cryptoki_sys::CK_SLOT_ID,
        _reserved: *mut std::ffi::c_void,
    ) -> cryptoki_sys::CK_RV {
        SLOT_WAIT_CALLS.fetch_add(1, Ordering::SeqCst);
        SLOT_WAIT_FLAGS.store(flags as u64, Ordering::SeqCst);
        if !slot.is_null() {
            unsafe { *slot = SLOT_WAIT_SLOT.load(Ordering::SeqCst) as cryptoki_sys::CK_SLOT_ID };
        }
        SLOT_WAIT_RV.load(Ordering::SeqCst) as cryptoki_sys::CK_RV
    }

    unsafe extern "C" fn gated_wait(
        flags: cryptoki_sys::CK_FLAGS,
        slot: *mut cryptoki_sys::CK_SLOT_ID,
        _reserved: *mut std::ffi::c_void,
    ) -> cryptoki_sys::CK_RV {
        SLOT_WAIT_CALLS.fetch_add(1, Ordering::SeqCst);
        SLOT_WAIT_FLAGS.store(flags as u64, Ordering::SeqCst);
        GATED_WAIT_ENTERED.store(true, Ordering::SeqCst);
        let start = std::time::Instant::now();
        while !GATED_WAIT_OPEN.load(Ordering::SeqCst) {
            if start.elapsed() > std::time::Duration::from_secs(10) {
                return cryptoki_sys::CKR_DEVICE_ERROR;
            }
            std::thread::yield_now();
        }
        if !slot.is_null() {
            unsafe { *slot = SLOT_WAIT_SLOT.load(Ordering::SeqCst) as cryptoki_sys::CK_SLOT_ID };
        }
        WAIT_RETURNED.store(true, Ordering::SeqCst);
        SLOT_WAIT_RV.load(Ordering::SeqCst) as cryptoki_sys::CK_RV
    }

    unsafe extern "C" fn wait_fixture_initialize_ok(
        _: *mut std::ffi::c_void,
    ) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn wait_fixture_finalize_ok(_: *mut std::ffi::c_void) -> cryptoki_sys::CK_RV {
        FINALIZE_CALLS.fetch_add(1, Ordering::SeqCst);
        FINALIZE_ENTERED_AFTER_WAIT_RETURN
            .store(WAIT_RETURNED.load(Ordering::SeqCst), Ordering::SeqCst);
        cryptoki_sys::CKR_OK
    }

    fn backend_with_wait() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        backend_with_wait_fn(Some(recording_wait))
    }

    fn backend_with_wait_fn(
        wait: cryptoki_sys::CK_C_WaitForSlotEvent,
    ) -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_Initialize = Some(wait_fixture_initialize_ok);
        functions.C_Finalize = Some(wait_fixture_finalize_ok);
        functions.C_WaitForSlotEvent = wait;
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
            session_fences: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
        (backend, functions)
    }

    #[test]
    fn wait_for_slot_denied_before_lifecycle_open() {
        // TF01b `call_slot_output` ordinary proof: no admission pre-Init.
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        let (backend, _functions) = backend_with_wait();
        let flags = cryptoki_sys::CKF_DONT_BLOCK as u64;
        assert_eq!(
            backend.ffi_wait_for_slot_event(flags).unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
        assert_eq!(SLOT_WAIT_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn slot_wait_blocking_rejected_without_native_entry() {
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        let (backend, _functions) = backend_with_wait();
        // Ordinary path: establish post-Initialize state (admission precedes
        // the local mode refusal at the boundary).
        backend.lifecycle_domain.open_for_tests();

        // C3M.4: blocking mode is refused locally; the provider is never
        // entered, so no native wait can block the daemon worker.
        assert_eq!(backend.ffi_wait_for_slot_event(0).unwrap_err(), CkRv::FUNCTION_NOT_SUPPORTED);
        assert_eq!(SLOT_WAIT_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn slot_wait_nonblocking_preserves_native_result_and_flags() {
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        let (backend, _functions) = backend_with_wait();
        // Ordinary path: establish post-Initialize state.
        backend.lifecycle_domain.open_for_tests();

        // Representable unknown bits ride along untouched (C3M.4): the sole
        // supported waiter makes one native call with every original bit.
        let flags = cryptoki_sys::CKF_DONT_BLOCK as u64 | 0x8000_0000;
        assert_eq!(backend.ffi_wait_for_slot_event(flags).unwrap(), CkSlotId(7));
        assert_eq!(SLOT_WAIT_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(SLOT_WAIT_FLAGS.load(Ordering::SeqCst), flags);
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn slot_wait_checked_width_and_precedence() {
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        let (backend, _functions) = backend_with_wait();
        // Ordinary path: establish post-Initialize state (admission precedes
        // checked narrowing at the boundary).
        backend.lifecycle_domain.open_for_tests();

        // C3M.4: flags the native CK_FLAGS cannot represent fail checked
        // narrowing (FUNCTION_FAILED) before any mode check or native entry.
        let flags = 1u64 << 32 | cryptoki_sys::CKF_DONT_BLOCK as u64;
        assert_eq!(backend.ffi_wait_for_slot_event(flags).unwrap_err(), CkRv::FUNCTION_FAILED);
        assert_eq!(SLOT_WAIT_CALLS.load(Ordering::SeqCst), 0);
    }

    /// TO26b group 2: every sealed state refuses every flag shape before
    /// width, mode, contention and native entry (lifecycle precedes all).
    #[test]
    fn slot_wait_sealed_states_refuse_before_everything() {
        use crate::ffi::native_domain::ModuleState::*;
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        let (backend, _functions) = backend_with_wait();
        let dont_block = cryptoki_sys::CKF_DONT_BLOCK as u64;
        let flag_shapes =
            [0, dont_block, dont_block | 0x8000_0000, 1u64 << 32, 1u64 << 32 | dont_block];
        for state in [LoadedUninitialized, Initializing, Draining, Finalizing, Finalized] {
            backend.lifecycle_domain.set_state_for_tests(state, 3);
            for flags in flag_shapes {
                assert_eq!(
                    backend.ffi_wait_for_slot_event(flags).unwrap_err(),
                    CkRv::CRYPTOKI_NOT_INITIALIZED,
                    "sealed {state:?} must refuse flags {flags:#x} first"
                );
            }
            assert_eq!(
                SLOT_WAIT_CALLS.load(Ordering::SeqCst),
                0,
                "sealed {state:?} must make zero native attempts"
            );
        }
    }

    /// TO26b group 2: an Uncertain domain refuses DEVICE_ERROR (wait-table
    /// row) for every flag shape, with zero native attempts.
    #[test]
    fn slot_wait_uncertain_refuses_device_error() {
        use crate::ffi::native_domain::ModuleState;
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        let (backend, _functions) = backend_with_wait();
        backend.lifecycle_domain.set_state_for_tests(ModuleState::Uncertain, 3);
        let dont_block = cryptoki_sys::CKF_DONT_BLOCK as u64;
        for flags in [0, dont_block, dont_block | 0x8000_0000, 1u64 << 32, 1u64 << 32 | dont_block]
        {
            assert_eq!(
                backend.ffi_wait_for_slot_event(flags).unwrap_err(),
                CkRv::DEVICE_ERROR,
                "Uncertain must refuse flags {flags:#x} with DEVICE_ERROR"
            );
        }
        assert_eq!(SLOT_WAIT_CALLS.load(Ordering::SeqCst), 0);
    }

    /// TO26b group 2: mode precedes contention — blocking flags refuse
    /// NOT_SUPPORTED even while a genuine waiter holds the reservation.
    #[test]
    fn slot_wait_blocking_refused_despite_busy_waiter() {
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        let (backend, _functions) = backend_with_wait_fn(Some(gated_wait));
        backend.lifecycle_domain.open_for_tests();
        std::thread::scope(|scope| {
            // The gate stays closed until both rivals are checked, so the
            // spawned waiter deterministically holds the reservation
            // through native entry while they race it.
            let holder = scope
                .spawn(|| backend.ffi_wait_for_slot_event(cryptoki_sys::CKF_DONT_BLOCK as u64));
            let start = std::time::Instant::now();
            while !GATED_WAIT_ENTERED.load(Ordering::SeqCst) {
                assert!(start.elapsed() < std::time::Duration::from_secs(10), "waiter must enter");
                std::thread::yield_now();
            }
            assert_eq!(
                backend.ffi_wait_for_slot_event(0).unwrap_err(),
                CkRv::FUNCTION_NOT_SUPPORTED,
                "mode precedes contention"
            );
            assert_eq!(
                backend.ffi_wait_for_slot_event(cryptoki_sys::CKF_DONT_BLOCK as u64).unwrap_err(),
                CkRv::FUNCTION_FAILED,
                "concurrent waiter refused while one is in native"
            );
            GATED_WAIT_OPEN.store(true, Ordering::SeqCst);
            assert_eq!(holder.join().expect("holder joins").unwrap(), CkSlotId(7));
        });
        assert_eq!(SLOT_WAIT_CALLS.load(Ordering::SeqCst), 1, "rivals make no native attempt");
    }

    /// TO26b group 2: the second concurrent waiter is refused (contention)
    /// and the slot frees on settlement — a later waiter succeeds.
    #[test]
    fn slot_wait_contention_refused_then_slot_reusable() {
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        let (backend, _functions) = backend_with_wait_fn(Some(gated_wait));
        backend.lifecycle_domain.open_for_tests();
        let dont_block = cryptoki_sys::CKF_DONT_BLOCK as u64;
        std::thread::scope(|scope| {
            let holder = scope.spawn(|| backend.ffi_wait_for_slot_event(dont_block));
            let start = std::time::Instant::now();
            while !GATED_WAIT_ENTERED.load(Ordering::SeqCst) {
                assert!(start.elapsed() < std::time::Duration::from_secs(10), "waiter must enter");
                std::thread::yield_now();
            }
            assert_eq!(
                backend.ffi_wait_for_slot_event(dont_block).unwrap_err(),
                CkRv::FUNCTION_FAILED,
                "concurrent waiter must refuse while one is in native"
            );
            assert_eq!(SLOT_WAIT_CALLS.load(Ordering::SeqCst), 1);
            GATED_WAIT_OPEN.store(true, Ordering::SeqCst);
            assert_eq!(holder.join().expect("holder joins").unwrap(), CkSlotId(7));
        });
        // Settlement freed the slot: the next waiter succeeds with a fresh ID.
        assert_eq!(backend.ffi_wait_for_slot_event(dont_block).unwrap(), CkSlotId(7));
        assert_eq!(SLOT_WAIT_CALLS.load(Ordering::SeqCst), 2);
        let observed = backend
            .lifecycle_domain
            .last_waiter_observation_for_tests()
            .expect("settlement publishes the observation");
        assert_eq!(observed.id, 1, "second settlement advances the wait ID");
        assert_eq!(observed.native_rv, Some(0));
        assert!(observed.slot_written);
    }

    /// TO26b group 2: plain DONT_BLOCK succeeds with exact flags, one
    /// native call, and a published completion observation.
    #[test]
    fn slot_wait_plain_dont_block_ok_with_observation() {
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        let (backend, _functions) = backend_with_wait();
        backend.lifecycle_domain.open_for_tests();
        let flags = cryptoki_sys::CKF_DONT_BLOCK as u64;
        assert_eq!(backend.ffi_wait_for_slot_event(flags).unwrap(), CkSlotId(7));
        assert_eq!(SLOT_WAIT_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(SLOT_WAIT_FLAGS.load(Ordering::SeqCst), flags);
        let observed = backend
            .lifecycle_domain
            .last_waiter_observation_for_tests()
            .expect("settlement publishes the observation");
        assert_eq!(observed.id, 0);
        assert_eq!(observed.flags, flags);
        assert_eq!(observed.native_rv, Some(0));
        assert!(observed.slot_written);
    }

    /// TO26b group 2: slot zero is a valid successful result, not an error.
    #[test]
    fn slot_wait_slot_zero_delivered() {
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        SLOT_WAIT_SLOT.store(0, Ordering::SeqCst);
        let (backend, _functions) = backend_with_wait();
        backend.lifecycle_domain.open_for_tests();
        assert_eq!(
            backend.ffi_wait_for_slot_event(cryptoki_sys::CKF_DONT_BLOCK as u64).unwrap(),
            CkSlotId(0)
        );
        assert_eq!(SLOT_WAIT_CALLS.load(Ordering::SeqCst), 1);
    }

    /// TO26b group 2: NO_EVENT with a dirtied native output cell surfaces
    /// exactly NO_EVENT; the observation records no slot write (the cell
    /// is never read on error — the shim canary test pins the caller side).
    #[test]
    fn slot_wait_no_event_with_modified_native_output() {
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        SLOT_WAIT_RV.store(cryptoki_sys::CKR_NO_EVENT as u64, Ordering::SeqCst);
        SLOT_WAIT_SLOT.store(0xDEAD, Ordering::SeqCst);
        let (backend, _functions) = backend_with_wait();
        backend.lifecycle_domain.open_for_tests();
        assert_eq!(
            backend.ffi_wait_for_slot_event(cryptoki_sys::CKF_DONT_BLOCK as u64).unwrap_err(),
            CkRv::NO_EVENT
        );
        assert_eq!(SLOT_WAIT_CALLS.load(Ordering::SeqCst), 1);
        let observed = backend
            .lifecycle_domain
            .last_waiter_observation_for_tests()
            .expect("settlement publishes the observation");
        assert_eq!(observed.native_rv, Some(cryptoki_sys::CKR_NO_EVENT as u64));
        assert!(!observed.slot_written, "error return writes no slot");
    }

    /// TO26b group 2: a sentinel provider error passes through unchanged
    /// and verbatim into the completion observation.
    #[test]
    fn slot_wait_sentinel_provider_error_passes_through() {
        const SENTINEL: u64 = 0xDEAD_BEEF;
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        SLOT_WAIT_RV.store(SENTINEL, Ordering::SeqCst);
        SLOT_WAIT_SLOT.store(0xBEEF, Ordering::SeqCst);
        let (backend, _functions) = backend_with_wait();
        backend.lifecycle_domain.open_for_tests();
        assert_eq!(
            backend.ffi_wait_for_slot_event(cryptoki_sys::CKF_DONT_BLOCK as u64).unwrap_err(),
            CkRv(SENTINEL)
        );
        let observed = backend
            .lifecycle_domain
            .last_waiter_observation_for_tests()
            .expect("settlement publishes the observation");
        assert_eq!(observed.native_rv, Some(SENTINEL), "original RV preserved verbatim");
        assert!(!observed.slot_written);
    }

    /// TO26b group 2: a missing provider entry refuses locally with no
    /// native attempt and no completed observation; the slot stays usable.
    #[test]
    fn slot_wait_missing_function_refused_without_native_entry() {
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        let (backend, _functions) = backend_with_wait_fn(None);
        backend.lifecycle_domain.open_for_tests();
        let flags = cryptoki_sys::CKF_DONT_BLOCK as u64;
        assert_eq!(
            backend.ffi_wait_for_slot_event(flags).unwrap_err(),
            CkRv::FUNCTION_NOT_SUPPORTED
        );
        assert_eq!(SLOT_WAIT_CALLS.load(Ordering::SeqCst), 0);
        let observed = backend
            .lifecycle_domain
            .last_waiter_observation_for_tests()
            .expect("refusal still publishes an observation");
        assert_eq!(observed.native_rv, None, "no native return was reached");
        assert!(!observed.slot_written);
        // The dropped reservation freed the slot: a repeat behaves identically.
        assert_eq!(
            backend.ffi_wait_for_slot_event(flags).unwrap_err(),
            CkRv::FUNCTION_NOT_SUPPORTED
        );
        assert_eq!(SLOT_WAIT_CALLS.load(Ordering::SeqCst), 0);
    }

    /// TO26b group 2: local refusals (lifecycle/width/mode/contention)
    /// never reserve, so they publish no observation at all.
    #[test]
    fn slot_wait_local_refusals_publish_no_observation() {
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        let (backend, _functions) = backend_with_wait();
        let dont_block = cryptoki_sys::CKF_DONT_BLOCK as u64;
        // Lifecycle refusal (fresh backend is LoadedUninitialized).
        let _ = backend.ffi_wait_for_slot_event(dont_block).unwrap_err();
        backend.lifecycle_domain.open_for_tests();
        // Mode refusal.
        let _ = backend.ffi_wait_for_slot_event(0).unwrap_err();
        // Width refusal (infallible on 64-bit for this value — the mode
        // arm takes it; the assertion below holds regardless).
        let _ = backend.ffi_wait_for_slot_event(1u64 << 32).unwrap_err();
        assert_eq!(
            backend.lifecycle_domain.last_waiter_observation_for_tests(),
            None,
            "refusals never reserve, so nothing is observed"
        );
    }

    /// TO26b group 2, width matrix: `2^32` and `2^32 | DONT_BLOCK` fail
    /// checked narrowing on a 32-bit backend; on a 64-bit backend both are
    /// representable, so mode/contention decide instead.
    #[test]
    fn slot_wait_wide_flags_width_matrix() {
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        let (backend, _functions) = backend_with_wait();
        backend.lifecycle_domain.open_for_tests();
        let dont_block = cryptoki_sys::CKF_DONT_BLOCK as u64;
        #[cfg(target_pointer_width = "32")]
        {
            assert_eq!(
                backend.ffi_wait_for_slot_event(1u64 << 32).unwrap_err(),
                CkRv::FUNCTION_FAILED,
                "width precedes mode on narrow backends"
            );
            assert_eq!(
                backend.ffi_wait_for_slot_event(1u64 << 32 | dont_block).unwrap_err(),
                CkRv::FUNCTION_FAILED,
                "width precedes contention on narrow backends"
            );
            assert_eq!(SLOT_WAIT_CALLS.load(Ordering::SeqCst), 0);
        }
        #[cfg(target_pointer_width = "64")]
        {
            // Representable on wide backends: `2^32` (DONT_BLOCK clear) is
            // a mode refusal, and `2^32 | DONT_BLOCK` rides to native with
            // every original bit preserved.
            assert_eq!(
                backend.ffi_wait_for_slot_event(1u64 << 32).unwrap_err(),
                CkRv::FUNCTION_NOT_SUPPORTED
            );
            assert_eq!(
                backend.ffi_wait_for_slot_event(1u64 << 32 | dont_block).unwrap(),
                CkSlotId(7)
            );
            assert_eq!(SLOT_WAIT_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(SLOT_WAIT_FLAGS.load(Ordering::SeqCst), 1u64 << 32 | dont_block);
        }
    }

    /// TO26b group 2: the gRPC policy follow-up (`get_token_info`) on a
    /// sealed domain is refused at admission with zero native attempts —
    /// no policy query crosses the seal. The fixture installs no
    /// `C_GetTokenInfo` stub, so any post-admission path would answer
    /// NOT_SUPPORTED; observing NOT_INIT proves admission refused first.
    /// (The handler maps this refusal to local NOT_INITIALIZED.)
    #[test]
    fn slot_wait_policy_query_after_seal_makes_no_native_attempt() {
        use crate::ffi::native_domain::ModuleState::*;
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        let (backend, _functions) = backend_with_wait();
        for state in [Draining, Finalizing, Finalized, Initializing, LoadedUninitialized] {
            backend.lifecycle_domain.set_state_for_tests(state, 3);
            assert_eq!(
                backend.ffi_get_token_info(CkSlotId(0)).unwrap_err(),
                CkRv::CRYPTOKI_NOT_INITIALIZED,
                "sealed {state:?} must refuse the policy query at admission"
            );
        }
    }

    /// TO26b group 2: no native wait overlaps native Finalize — a Finalize
    /// racing an in-flight gated wait drains (it cannot overtake), the
    /// waiter settles first, and exactly one native call of each ran.
    #[test]
    fn slot_wait_finalize_cannot_overlap_native_wait() {
        use std::sync::mpsc::channel;
        let _guard = SLOT_WAIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_wait_fixture();
        let (backend, _functions) = backend_with_wait_fn(Some(gated_wait));
        backend.initialize().expect("honest control cycle publishes Open");
        let dont_block = cryptoki_sys::CKF_DONT_BLOCK as u64;
        std::thread::scope(|scope| {
            let waiter_done = scope.spawn(|| backend.ffi_wait_for_slot_event(dont_block));
            let start = std::time::Instant::now();
            while !GATED_WAIT_ENTERED.load(Ordering::SeqCst) {
                assert!(start.elapsed() < std::time::Duration::from_secs(10), "waiter must enter");
                std::thread::yield_now();
            }
            // Finalize seals admission immediately (a rival wait now
            // refuses) but its native call must wait for the waiter.
            let (final_tx, final_rx) = channel();
            let backend_ref = &backend;
            scope.spawn(move || final_tx.send(backend_ref.finalize()).expect("report finalize"));
            std::thread::sleep(std::time::Duration::from_millis(200));
            assert_eq!(
                FINALIZE_CALLS.load(Ordering::SeqCst),
                0,
                "native Finalize must not enter while the wait is in flight"
            );
            assert!(final_rx.try_recv().is_err(), "Finalize must still be draining, not completed");
            GATED_WAIT_OPEN.store(true, Ordering::SeqCst);
            assert_eq!(waiter_done.join().expect("waiter joins").unwrap(), CkSlotId(7));
            final_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("Finalize completes after the waiter settles")
                .expect("Finalize succeeds");
        });
        assert_eq!(SLOT_WAIT_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FINALIZE_CALLS.load(Ordering::SeqCst), 1);
        assert!(
            FINALIZE_ENTERED_AFTER_WAIT_RETURN.load(Ordering::SeqCst),
            "native wait returned before native Finalize entered"
        );
    }
}
