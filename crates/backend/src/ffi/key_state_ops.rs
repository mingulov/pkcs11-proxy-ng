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
        // C3M.4 ordered boundary: checked width first, then mode. Flags the
        // native CK_FLAGS cannot represent fail loudly (FUNCTION_FAILED) —
        // a native module could not have been handed that value either —
        // and blocking mode is refused locally (FUNCTION_NOT_SUPPORTED) so
        // no native wait can block the daemon worker. Neither refusal makes
        // a native attempt; the sole supported DONT_BLOCK call preserves
        // every original bit, including representable unknown ones.
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let native_flags = narrow_wire_ulong(flags)?;
        if native_flags & cryptoki_sys::CKF_DONT_BLOCK == 0 {
            return Err(CkRv::FUNCTION_NOT_SUPPORTED);
        }
        Self::call_slot_output(
            &admission,
            unsafe { (*self.func_list).C_WaitForSlotEvent },
            |function, slot| unsafe { function(native_flags, slot, std::ptr::null_mut()) },
        )
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
        let h_session = Self::session_handle(session)?;
        Self::call_bytes_exact(
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
        Self::call_bytes_exact(
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
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    static SLOT_WAIT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SLOT_WAIT_FLAGS: AtomicU64 = AtomicU64::new(0);
    static SLOT_WAIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe extern "C" fn recording_wait(
        flags: cryptoki_sys::CK_FLAGS,
        slot: *mut cryptoki_sys::CK_SLOT_ID,
        _reserved: *mut std::ffi::c_void,
    ) -> cryptoki_sys::CK_RV {
        SLOT_WAIT_CALLS.fetch_add(1, Ordering::SeqCst);
        SLOT_WAIT_FLAGS.store(flags as u64, Ordering::SeqCst);
        if !slot.is_null() {
            unsafe { *slot = 7 };
        }
        cryptoki_sys::CKR_OK
    }

    fn backend_with_wait() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        functions.C_WaitForSlotEvent = Some(recording_wait);
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
        SLOT_WAIT_CALLS.store(0, Ordering::SeqCst);
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
        SLOT_WAIT_CALLS.store(0, Ordering::SeqCst);
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
        SLOT_WAIT_CALLS.store(0, Ordering::SeqCst);
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
        SLOT_WAIT_CALLS.store(0, Ordering::SeqCst);
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
}
