use pkcs11_proxy_ng_types::{CkInBuf, *};

/// Structured `C_DeriveKey` result for mechanisms that can mutate caller-owned
/// mechanism parameters even when the PKCS#11 return value is not `CKR_OK`.
#[derive(Debug, Clone, PartialEq)]
pub struct CkDeriveKeyOutputResult {
    pub rv: CkRv,
    pub key_handle: Option<CkObjectHandle>,
    pub mechanism_out: Option<CkMechanismParams>,
}

impl CkDeriveKeyOutputResult {
    pub fn ok(key_handle: CkObjectHandle, mechanism_out: Option<CkMechanismParams>) -> Self {
        Self { rv: CkRv::OK, key_handle: Some(key_handle), mechanism_out }
    }

    pub fn error(rv: CkRv, mechanism_out: Option<CkMechanismParams>) -> Self {
        Self { rv, key_handle: None, mechanism_out }
    }
}

/// Shared slot-wait width→mode admission (T10a).
///
/// Checked native-width narrowing first (`CKR_FUNCTION_FAILED` on overflow —
/// a native module could not have been handed that value either), then
/// `DONT_BLOCK`-only mode (`CKR_FUNCTION_NOT_SUPPORTED` when the bit is
/// clear). Pure and provider-free. Backends with module-lifecycle state call
/// this AFTER their own lifecycle refusal; see
/// [`Pkcs11Backend::admit_slot_wait`].
pub fn admit_slot_wait_width_mode(flags: u64) -> CkResult<()> {
    let native_flags =
        cryptoki_sys::CK_ULONG::try_from(flags).map_err(|_| CkRv::FUNCTION_FAILED)?;
    if native_flags & cryptoki_sys::CKF_DONT_BLOCK == 0 {
        return Err(CkRv::FUNCTION_NOT_SUPPORTED);
    }
    Ok(())
}

/// A PKCS#11 backend that the daemon can dispatch operations to (ADR-0004 §1).
/// Each method corresponds to a supported PKCS#11 function.
/// All methods are synchronous — the daemon bridges to async at the gRPC layer
/// via tokio::task::spawn_blocking.
pub trait Pkcs11Backend: Send + Sync {
    /// The backend's native `sizeof(CK_ULONG)` for the D2 advertisement
    /// (ADR-0011). The FFI backend runs in this process, so the host
    /// values are correct defaults; emulating backends override.
    fn abi_ulong_size(&self) -> u32 {
        crate::host_abi::host_ulong_size()
    }

    /// The backend's `CK_ULONG` byte order for the wire: 1 = little-endian,
    /// 2 = big-endian (D6).
    fn abi_byte_order(&self) -> u32 {
        crate::host_abi::host_byte_order()
    }

    /// The backend's native `sizeof(CK_ATTRIBUTE)` — the stride of nested
    /// `CKA_*_TEMPLATE` byte lengths on the wire (D2 extension; on LLP64
    /// the packed stride is not derivable from the ulong width).
    fn abi_attribute_stride(&self) -> u32 {
        std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>() as u32
    }

    fn initialize(&self) -> CkResult<()>;
    fn finalize(&self) -> CkResult<()>;
    /// T10 coordinator-path finalize: retire native state with the
    /// shutdown controller armed for exactly `grace` (the coordinator's
    /// remaining overall budget). The FFI override arms with `grace`
    /// and seals against the same absolute deadline; backends without
    /// native work use the default (`finalize()`), which the
    /// coordinator bounds with its own timeout. Attempted once; no
    /// retry (a failed attempt proves nothing about provider state).
    fn finalize_with_grace(&self, _grace: std::time::Duration) -> CkResult<()> {
        self.finalize()
    }
    /// Whether `finalize_with_grace` is bounded by the native
    /// shutdown-deadline controller (process-stopping on overrun) as
    /// opposed to needing the coordinator's own timeout. Trait default
    /// `false` (mock/test/custom backends: no native work, the
    /// coordinator's timeout applies); the FFI override returns
    /// `NATIVE_STOP_QUALIFIED`. Pure predicate — no provider contact,
    /// no arming, no state change.
    fn finalize_is_natively_bounded(&self) -> bool {
        false
    }
    fn get_info(&self) -> CkResult<CkInfo>;

    fn get_slot_list(&self, token_present: bool) -> CkResult<Vec<CkSlotId>>;
    fn get_slot_info(&self, slot_id: CkSlotId) -> CkResult<CkSlotInfo>;
    fn get_token_info(&self, slot_id: CkSlotId) -> CkResult<CkTokenInfo>;
    fn get_mechanism_list(&self, slot_id: CkSlotId) -> CkResult<Vec<CkMechanismType>>;
    fn get_mechanism_info(
        &self,
        slot_id: CkSlotId,
        mech: CkMechanismType,
    ) -> CkResult<CkMechanismInfo>;

    fn init_token(&self, slot_id: CkSlotId, so_pin: Option<&[u8]>, label: &str) -> CkResult<()>;
    fn init_pin(&self, session: CkSessionHandle, pin: Option<&[u8]>) -> CkResult<()>;
    fn set_pin(
        &self,
        session: CkSessionHandle,
        old_pin: Option<&[u8]>,
        new_pin: Option<&[u8]>,
    ) -> CkResult<()>;

    fn open_session(&self, slot_id: CkSlotId, flags: CkSessionFlags) -> CkResult<CkSessionHandle>;
    fn close_session(&self, session: CkSessionHandle) -> CkResult<()>;
    fn close_all_sessions(&self, slot_id: CkSlotId) -> CkResult<()>;

    /// Close multiple sessions individually. Returns the last error if any
    /// close_session call failed, or Ok(()) if all succeeded.
    fn close_sessions(&self, sessions: &[CkSessionHandle]) -> CkResult<()> {
        let mut last_error = None;
        for &session in sessions {
            if let Err(rv) = self.close_session(session) {
                last_error = Some(rv);
            }
        }
        match last_error {
            Some(rv) => Err(rv),
            None => Ok(()),
        }
    }
    fn get_session_info(&self, session: CkSessionHandle) -> CkResult<CkSessionInfo>;
    fn login(
        &self,
        session: CkSessionHandle,
        user_type: CkUserType,
        pin: Option<&[u8]>,
    ) -> CkResult<()>;
    fn logout(&self, session: CkSessionHandle) -> CkResult<()>;

    fn find_objects_init(
        &self,
        session: CkSessionHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<()>;
    fn find_objects(
        &self,
        session: CkSessionHandle,
        max_count: u32,
    ) -> CkResult<Vec<CkObjectHandle>>;
    fn find_objects_final(&self, session: CkSessionHandle) -> CkResult<()>;
    /// Map attribute values from the object into `template` (PKCS#11 §5.7).
    ///
    /// Implementations **must** write back into the template even when returning
    /// `Err(CkRv::ATTRIBUTE_SENSITIVE)`, `Err(CkRv::ATTRIBUTE_TYPE_INVALID)`, or
    /// `Err(CkRv::BUFFER_TOO_SMALL)` — the spec requires partial results in these
    /// cases. Callers must inspect the template on those errors, not just discard it.
    fn get_attribute_value(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &mut [CkAttribute],
    ) -> CkResult<()>;
    fn get_attribute_value_exact(
        &self,
        _session: CkSessionHandle,
        _object: CkObjectHandle,
        _queries: &[CkAttributeQuery],
    ) -> CkResult<(CkRv, Vec<CkAttributeQueryResult>)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()>;
    fn sign_init_cancel(&self, _session: CkSessionHandle) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }
    fn sign(&self, session: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<SecretBytes>;
    fn sign_update(&self, session: CkSessionHandle, part: CkInBuf<'_>) -> CkResult<()>;
    fn sign_final(&self, session: CkSessionHandle) -> CkResult<SecretBytes>;

    fn digest_encrypt_update(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes>;
    fn decrypt_digest_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes>;
    fn sign_encrypt_update(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes>;
    fn decrypt_verify_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes>;

    fn sign_recover_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()>;
    fn sign_recover_init_cancel(&self, _session: CkSessionHandle) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }
    fn sign_recover(&self, session: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<SecretBytes>;

    fn verify_recover_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()>;
    fn verify_recover_init_cancel(&self, _session: CkSessionHandle) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }
    fn verify_recover(
        &self,
        session: CkSessionHandle,
        signature: CkInBuf<'_>,
    ) -> CkResult<SecretBytes>;

    fn verify_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()>;
    fn verify_init_cancel(&self, _session: CkSessionHandle) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }
    fn verify(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        signature: CkInBuf<'_>,
    ) -> CkResult<()>;
    fn verify_update(&self, session: CkSessionHandle, part: CkInBuf<'_>) -> CkResult<()>;
    fn verify_final(&self, session: CkSessionHandle, signature: CkInBuf<'_>) -> CkResult<()>;

    /// Returns `(public_handle, private_handle)` — in that order, matching
    /// the pub_template / priv_template argument ordering.
    fn create_object(
        &self,
        session: CkSessionHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle>;
    fn copy_object(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle>;
    fn destroy_object(&self, session: CkSessionHandle, object: CkObjectHandle) -> CkResult<()>;
    /// Destroy a quarantined native object from `Drop` (`PendingNativeObject`
    /// cleanup) WITHOUT ordinary admission. The `FfiBackend` override rides
    /// the enclosing op's exclusion via the control choke (admitting would
    /// nest under the live guard and deadlock behind a queued writer —
    /// Drop-may-never-admit, pinned by the nesting tripwire). Backends
    /// without a lifecycle domain (mocks) destroy normally.
    fn destroy_quarantined_object(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> CkResult<()> {
        self.destroy_object(session, object)
    }
    fn get_object_size(&self, session: CkSessionHandle, object: CkObjectHandle) -> CkResult<u64>;
    fn set_attribute_value(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<()>;

    fn digest_init(&self, session: CkSessionHandle, mechanism: &CkMechanism) -> CkResult<()>;
    fn digest_init_cancel(&self, _session: CkSessionHandle) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }
    fn digest(&self, session: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<SecretBytes>;
    fn digest_update(&self, session: CkSessionHandle, part: CkInBuf<'_>) -> CkResult<()>;
    fn digest_key(&self, session: CkSessionHandle, key: CkObjectHandle) -> CkResult<()>;
    fn digest_final(&self, session: CkSessionHandle) -> CkResult<SecretBytes>;

    fn encrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>>;
    fn encrypt_init_cancel(&self, _session: CkSessionHandle) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }
    fn encrypt(&self, session: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<SecretBytes>;
    fn encrypt_update(&self, session: CkSessionHandle, part: CkInBuf<'_>) -> CkResult<SecretBytes>;
    fn encrypt_final(&self, session: CkSessionHandle) -> CkResult<SecretBytes>;

    fn decrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>>;
    fn decrypt_init_cancel(&self, _session: CkSessionHandle) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }
    fn decrypt(
        &self,
        session: CkSessionHandle,
        encrypted_data: CkInBuf<'_>,
    ) -> CkResult<SecretBytes>;
    fn decrypt_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes>;
    fn decrypt_final(&self, session: CkSessionHandle) -> CkResult<SecretBytes>;

    fn derive_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle>;

    /// `C_DeriveKey` returning both the derived key handle AND any
    /// mechanism-param mutations the HSM performed during the call —
    /// most importantly the negotiated `CK_VERSION` written back to
    /// `CK_TLS12_MASTER_KEY_DERIVE_PARAMS.pVersion`. Default delegates
    /// to `derive_key` and reports no mutation, preserving the
    /// pre-existing behaviour for backends that don't implement it.
    fn derive_key_with_output(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<(CkObjectHandle, Option<CkMechanismParams>)> {
        self.derive_key(session, mechanism, base_key, template).map(|h| (h, None))
    }

    /// Non-throwing PKCS#11 result shape for `C_DeriveKey` mechanism-output
    /// writeback. The outer `CkResult` is reserved for failures that prevent a
    /// structured call result from being formed; PKCS#11 return values from the
    /// backend call itself live in [`CkDeriveKeyOutputResult::rv`].
    fn derive_key_with_output_result(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkDeriveKeyOutputResult> {
        Ok(match self.derive_key_with_output(session, mechanism, base_key, template) {
            Ok((handle, mechanism_out)) => CkDeriveKeyOutputResult::ok(handle, mechanism_out),
            Err(rv) => CkDeriveKeyOutputResult::error(rv, None),
        })
    }
    fn wrap_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
    ) -> CkResult<SecretBytes>;
    fn unwrap_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        unwrapping_key: CkObjectHandle,
        wrapped_key: CkInBuf<'_>,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle>;
    fn generate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle>;

    /// `C_GenerateKey` returning both the key handle AND any mechanism-param
    /// mutations the HSM performed during the call — notably the generated
    /// `CK_PBE_PARAMS.pInitVector` for PBE key generation. Default delegates to
    /// `generate_key` and reports no mutation, preserving prior behaviour for
    /// backends that don't implement it. Mirrors `derive_key_with_output`.
    fn generate_key_with_output(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<(CkObjectHandle, Option<CkMechanismParams>)> {
        self.generate_key(session, mechanism, template).map(|h| (h, None))
    }
    fn generate_key_pair(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        pub_template: Option<&[CkAttribute]>,
        priv_template: Option<&[CkAttribute]>,
    ) -> CkResult<(CkObjectHandle, CkObjectHandle)>;
    /// Wait for a slot event. `flags == CkFlags::DONT_BLOCK` means non-blocking.
    /// Returns the slot ID where the event occurred.
    ///
    /// The service admits every wait through [`Pkcs11Backend::admit_slot_wait`]
    /// before dispatching here, so a refused wait never reaches this method
    /// from the service path. Direct callers (tests, embedded users) must
    /// admit first themselves to preserve the ownership ordering.
    /// [`MockBackend`](crate::mock::MockBackend) deliberately models
    /// faulty/legacy providers underneath admission (blocking calls park
    /// once admitted; hangs are injectable) for abort/timeout coverage —
    /// it is test-only and never the deployed backend.
    fn wait_for_slot_event(&self, flags: u64) -> CkResult<CkSlotId>;
    /// Admit a slot wait without a provider attempt (T10a service seam).
    ///
    /// Ownership order (`doc/release/native-mechanism-ownership.md`
    /// §"Slot-event scope"): lifecycle → native width → mode →
    /// contention. The service calls this after its own context check and
    /// before dispatching [`Pkcs11Backend::wait_for_slot_event`]; an `Err`
    /// return value is answered to the caller with zero provider attempts
    /// and no slot output. Contention stays with the wait itself (only a
    /// held reservation can serialize waiters); this seam covers
    /// lifecycle/width/mode, and mode-before-contention holds because a
    /// mode refusal here precedes any dispatch.
    ///
    /// Custom-backend responsibilities: the default implementation performs
    /// the shared width→mode checks ([`admit_slot_wait_width_mode`]) for
    /// backends without module-lifecycle state. A backend WITH lifecycle
    /// state must override this method, refuse its non-admissible states
    /// first, and then delegate to [`admit_slot_wait_width_mode`] — never
    /// refuse mode before lifecycle/width, and never touch the provider.
    fn admit_slot_wait(&self, flags: u64) -> CkResult<()> {
        admit_slot_wait_width_mode(flags)
    }
    fn get_operation_state(&self, session: CkSessionHandle) -> CkResult<SecretBytes>;
    fn set_operation_state(
        &self,
        session: CkSessionHandle,
        state: CkInBuf<'_>,
        enc_key: CkObjectHandle,
        auth_key: CkObjectHandle,
    ) -> CkResult<()>;
    fn seed_random(&self, session: CkSessionHandle, seed: CkInBuf<'_>) -> CkResult<()>;
    fn generate_random(&self, session: CkSessionHandle, len: u32) -> CkResult<SecretBytes>;

    // --- Exact byte-output methods (Track B) ---
    // Default: FUNCTION_NOT_SUPPORTED. Tasks 2-5 wire real backends.

    // Shape: (session, data, spec) -> CkOutputBufferResult

    fn sign_exact(
        &self,
        _session: CkSessionHandle,
        _data: CkInBuf<'_>,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_recover_exact(
        &self,
        _session: CkSessionHandle,
        _data: CkInBuf<'_>,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn verify_recover_exact(
        &self,
        _session: CkSessionHandle,
        _signature: CkInBuf<'_>,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn digest_exact(
        &self,
        _session: CkSessionHandle,
        _data: CkInBuf<'_>,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encrypt_exact(
        &self,
        _session: CkSessionHandle,
        _data: CkInBuf<'_>,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encrypt_exact_with_output(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, Option<CkMechanismParams>)> {
        self.encrypt_exact(session, data, spec).map(|result| (result, None))
    }

    fn encrypt_update_exact(
        &self,
        _session: CkSessionHandle,
        _part: CkInBuf<'_>,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_exact(
        &self,
        _session: CkSessionHandle,
        _encrypted_data: CkInBuf<'_>,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_update_exact(
        &self,
        _session: CkSessionHandle,
        _encrypted_part: CkInBuf<'_>,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn digest_encrypt_update_exact(
        &self,
        _session: CkSessionHandle,
        _part: CkInBuf<'_>,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_digest_update_exact(
        &self,
        _session: CkSessionHandle,
        _encrypted_part: CkInBuf<'_>,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_encrypt_update_exact(
        &self,
        _session: CkSessionHandle,
        _part: CkInBuf<'_>,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_verify_update_exact(
        &self,
        _session: CkSessionHandle,
        _encrypted_part: CkInBuf<'_>,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    // Shape: (session, spec) -> CkOutputBufferResult

    fn sign_final_exact(
        &self,
        _session: CkSessionHandle,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn digest_final_exact(
        &self,
        _session: CkSessionHandle,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encrypt_final_exact(
        &self,
        _session: CkSessionHandle,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_final_exact(
        &self,
        _session: CkSessionHandle,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn get_operation_state_exact(
        &self,
        _session: CkSessionHandle,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    // Shape: (session, mechanism, wrapping_key, key, spec) -> CkOutputBufferResult

    fn wrap_key_exact(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _wrapping_key: CkObjectHandle,
        _key: CkObjectHandle,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    /// `C_WrapKey` with mechanism-param write-back. Returns the wrapped key
    /// bytes plus any `Option<CkMechanismParams>` the HSM mutated during
    /// the call — most importantly the AES-GCM IV when wrapping with
    /// `CKM_AES_GCM` and the HSM generated it. Default delegates to
    /// `wrap_key_exact` and reports no mechanism mutation, preserving the
    /// pre-existing behaviour for backends that don't implement it.
    fn wrap_key_exact_with_output(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, Option<CkMechanismParams>)> {
        self.wrap_key_exact(session, mechanism, wrapping_key, key, spec)
            .map(|result| (result, None))
    }

    // --- Track C: Exact parameter-output methods ---
    // Default: FUNCTION_NOT_SUPPORTED.

    fn encrypt_message_exact(
        &self,
        _session: CkSessionHandle,
        _parameter: &[u8],
        _aad: CkInBuf<'_>,
        _plaintext: CkInBuf<'_>,
        _output_spec: &CkOutputBufferSpec,
        _param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_message_exact(
        &self,
        _session: CkSessionHandle,
        _parameter: &[u8],
        _aad: CkInBuf<'_>,
        _ciphertext: CkInBuf<'_>,
        _output_spec: &CkOutputBufferSpec,
        _param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_message_exact(
        &self,
        _session: CkSessionHandle,
        _parameter: &[u8],
        _data: CkInBuf<'_>,
        _output_spec: &CkOutputBufferSpec,
        _param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encrypt_message_next_exact(
        &self,
        _session: CkSessionHandle,
        _parameter: &[u8],
        _plaintext_part: CkInBuf<'_>,
        _flags: CkFlags,
        _output_spec: &CkOutputBufferSpec,
        _param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_message_next_exact(
        &self,
        _session: CkSessionHandle,
        _parameter: &[u8],
        _ciphertext_part: CkInBuf<'_>,
        _flags: CkFlags,
        _output_spec: &CkOutputBufferSpec,
        _param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_message_next_exact(
        &self,
        _session: CkSessionHandle,
        _parameter: &[u8],
        _data_part: CkInBuf<'_>,
        _output_spec: &CkOutputBufferSpec,
        _param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    // --- Track C: Structured message parameter variants ---
    // These take a `MessageParameter` with actual data instead of raw
    // C struct bytes with embedded pointers.  Default: FUNCTION_NOT_SUPPORTED.

    fn encrypt_message_exact_msg(
        &self,
        _session: CkSessionHandle,
        _msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        _aad: CkInBuf<'_>,
        _plaintext: CkInBuf<'_>,
        _output_spec: &CkOutputBufferSpec,
        _provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_message_exact_msg(
        &self,
        _session: CkSessionHandle,
        _msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        _aad: CkInBuf<'_>,
        _ciphertext: CkInBuf<'_>,
        _output_spec: &CkOutputBufferSpec,
        _provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encrypt_message_begin_msg(
        &self,
        _session: CkSessionHandle,
        _msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        _aad: CkInBuf<'_>,
        _provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_message_begin_msg(
        &self,
        _session: CkSessionHandle,
        _msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        _aad: CkInBuf<'_>,
        _provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_message_exact_msg(
        &self,
        _session: CkSessionHandle,
        _msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        _data: CkInBuf<'_>,
        _output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    )> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encrypt_message_next_exact_msg(
        &self,
        _session: CkSessionHandle,
        _msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        _plaintext_part: CkInBuf<'_>,
        _flags: CkFlags,
        _output_spec: &CkOutputBufferSpec,
        _provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_message_next_exact_msg(
        &self,
        _session: CkSessionHandle,
        _msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        _ciphertext_part: CkInBuf<'_>,
        _flags: CkFlags,
        _output_spec: &CkOutputBufferSpec,
        _provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_message_next_exact_msg(
        &self,
        _session: CkSessionHandle,
        _msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        _data_part: CkInBuf<'_>,
        _output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    )> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn wrap_key_authenticated_exact(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _wrapping_key: CkObjectHandle,
        _key: CkObjectHandle,
        _aad: CkInBuf<'_>,
        _output_spec: &CkOutputBufferSpec,
        _param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    // --- Legacy parallel function status (PKCS#11 2.40) ---

    fn get_function_status(&self, _session: CkSessionHandle) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_PARALLEL)
    }

    fn cancel_function(&self, _session: CkSessionHandle) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_PARALLEL)
    }

    // --- PKCS#11 3.0/3.2 functions (defaults: unsupported) ---

    // Wave 1: Session extensions

    fn login_user(
        &self,
        _session: CkSessionHandle,
        _user_type: CkUserType,
        _username: Option<&[u8]>,
        _pin: Option<&[u8]>,
    ) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn session_cancel(&self, _session: CkSessionHandle, _flags: CkFlags) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn get_session_validation_flags(
        &self,
        _session: CkSessionHandle,
        _flags_type: u64,
    ) -> CkResult<u64> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    // Wave 2: KEM

    fn encapsulate_key_exact(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _public_key: CkObjectHandle,
        _template: Option<&[CkAttribute]>,
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputAndHandleResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encapsulate_key(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _public_key: CkObjectHandle,
        _template: Option<&[CkAttribute]>,
    ) -> CkResult<(SecretBytes, CkObjectHandle)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decapsulate_key(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _private_key: CkObjectHandle,
        _template: Option<&[CkAttribute]>,
        _ciphertext: CkInBuf<'_>,
    ) -> CkResult<CkObjectHandle> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    // Wave 3: Message encrypt — mechanism is Option (None means cancel)

    fn message_encrypt_init(
        &self,
        _session: CkSessionHandle,
        _mechanism: Option<&CkMechanism>,
        _init_param: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        _key: CkObjectHandle,
    ) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn message_encrypt_init_contract(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        init_param: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        key: CkObjectHandle,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.message_encrypt_init(session, Some(mechanism), init_param, key)?;
        Ok(CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        })
    }

    fn encrypt_message(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
        _aad: CkInBuf<'_>,
        _plaintext: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encrypt_message_begin(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
        _aad: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encrypt_message_begin_exact(
        &self,
        _session: CkSessionHandle,
        _aad: CkInBuf<'_>,
        _provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encrypt_message_next(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
        _plaintext_part: CkInBuf<'_>,
        _flags: CkFlags,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn message_encrypt_final(&self, _session: CkSessionHandle) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    // Wave 3: Message decrypt — mechanism is Option (None means cancel)

    fn message_decrypt_init(
        &self,
        _session: CkSessionHandle,
        _mechanism: Option<&CkMechanism>,
        _init_param: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        _key: CkObjectHandle,
    ) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn message_decrypt_init_contract(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        init_param: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        key: CkObjectHandle,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.message_decrypt_init(session, Some(mechanism), init_param, key)?;
        Ok(CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        })
    }

    fn decrypt_message(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
        _aad: CkInBuf<'_>,
        _ciphertext: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_message_begin(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
        _aad: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_message_begin_exact(
        &self,
        _session: CkSessionHandle,
        _aad: CkInBuf<'_>,
        _provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_message_next(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
        _ciphertext_part: CkInBuf<'_>,
        _flags: CkFlags,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn message_decrypt_final(&self, _session: CkSessionHandle) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    // Wave 4: Message sign — mechanism is Option (None means cancel)

    fn message_sign_init(
        &self,
        _session: CkSessionHandle,
        _mechanism: Option<&CkMechanism>,
        _key: CkObjectHandle,
    ) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_message(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
        _data: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_message_begin(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
    ) -> CkResult<SecretBytes> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_message_begin_exact(
        &self,
        _session: CkSessionHandle,
        _provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_message_next(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
        _data_part: CkInBuf<'_>,
        _request_signature: bool,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_message_next_feed_exact(
        &self,
        _session: CkSessionHandle,
        _data_part: CkInBuf<'_>,
        _provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn message_sign_final(&self, _session: CkSessionHandle) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    // Wave 4: Message verify — mechanism is Option (None means cancel)

    fn message_verify_init(
        &self,
        _session: CkSessionHandle,
        _mechanism: Option<&CkMechanism>,
        _key: CkObjectHandle,
    ) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn verify_message(
        &self,
        _session: CkSessionHandle,
        _parameter: &[u8],
        _data: CkInBuf<'_>,
        _signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn verify_message_exact(
        &self,
        _session: CkSessionHandle,
        _data: CkInBuf<'_>,
        _signature: CkInBuf<'_>,
        _provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn verify_message_begin(&self, _session: CkSessionHandle, _parameter: &[u8]) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn verify_message_begin_exact(
        &self,
        _session: CkSessionHandle,
        _provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn verify_message_next(
        &self,
        _session: CkSessionHandle,
        _parameter: &[u8],
        _data_part: CkInBuf<'_>,
        _is_final: bool,
        _signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn verify_message_next_exact(
        &self,
        _session: CkSessionHandle,
        _data_part: CkInBuf<'_>,
        _is_final: bool,
        _signature: CkInBuf<'_>,
        _provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn message_verify_final(&self, _session: CkSessionHandle) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    // Wave 5: VerifySignature — signature provided at init, Option mechanism for cancel

    fn verify_signature_init(
        &self,
        _session: CkSessionHandle,
        _mechanism: Option<&CkMechanism>,
        _key: CkObjectHandle,
        _signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn verify_signature(&self, _session: CkSessionHandle, _data: CkInBuf<'_>) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn verify_signature_update(
        &self,
        _session: CkSessionHandle,
        _data_part: CkInBuf<'_>,
    ) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn verify_signature_final(&self, _session: CkSessionHandle) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    // Pointer-safe authenticated output. Defaults fail before native dispatch;
    // implementations must not adapt arbitrary legacy structure bytes.
    fn wrap_key_authenticated_typed(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _parameter: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        _wrapping_key: CkObjectHandle,
        _key: CkObjectHandle,
        _aad: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput)>
    {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn wrap_key_authenticated_exact_typed(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _parameter: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        _wrapping_key: CkObjectHandle,
        _key: CkObjectHandle,
        _aad: CkInBuf<'_>,
        _output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput,
    )> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn unwrap_key_authenticated_typed(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _parameter: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        _unwrapping_key: CkObjectHandle,
        _wrapped_key: CkInBuf<'_>,
        _template: Option<&[CkAttribute]>,
        _aad: CkInBuf<'_>,
    ) -> CkResult<(
        CkObjectHandle,
        pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput,
    )> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    // Wave 5: Authenticated wrap — legacy pointer-free outputs only.

    fn wrap_key_authenticated(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _wrapping_key: CkObjectHandle,
        _key: CkObjectHandle,
        _aad: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn unwrap_key_authenticated(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _unwrapping_key: CkObjectHandle,
        _wrapped_key: CkInBuf<'_>,
        _template: Option<&[CkAttribute]>,
        _aad: CkInBuf<'_>,
    ) -> CkResult<(CkObjectHandle, SecretBytes)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    // Wave 5: Async (Option B: polling only)

    fn async_complete(
        &self,
        _session: CkSessionHandle,
        _function_name: &str,
    ) -> CkResult<(u64, SecretBytes, u64, CkObjectHandle, CkObjectHandle)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    /// Option B async: always returns `CKR_STATE_UNSAVEABLE`.
    fn async_get_id(&self, _session: CkSessionHandle, _function_name: &str) -> CkResult<u64> {
        Err(CkRv::STATE_UNSAVEABLE)
    }

    /// Option B async: always returns `CKR_SAVED_STATE_INVALID`.
    fn async_join(
        &self,
        _session: CkSessionHandle,
        _function_name: &str,
        _operation_id: u64,
        _buffer_size: u64,
    ) -> CkResult<SecretBytes> {
        Err(CkRv::SAVED_STATE_INVALID)
    }

    // --- BUG-001: Interface version transparency ---

    /// Report which PKCS#11 interface versions this backend supports and
    /// which function pointers are NULL in each function list.
    ///
    /// Default: returns v2.40 only with no NULL functions.
    fn get_interface_capabilities(&self) -> InterfaceCapabilities {
        InterfaceCapabilities {
            interfaces: vec![InterfaceInfo {
                version_major: 2,
                version_minor: 40,
                null_functions: vec![],
            }],
        }
    }

    /// Return the current `output_params()` of the mechanism cached for
    /// `session` (set by the last `*_init` call). Used by the server to
    /// surface HSM-mutated mechanism fields (e.g. AES-GCM IV after
    /// `C_Encrypt`) on the simple `Encrypt`/`Decrypt` RPCs that pre-date
    /// the `ByteOutputExact` exact-output path.  Returns `None` for
    /// backends that don't cache mechanism state across RPCs.
    fn session_output_mechanism_params(
        &self,
        _session: CkSessionHandle,
    ) -> Option<CkMechanismParams> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T10a: the shared width→mode helper admits DONT_BLOCK, refuses
    /// blocking mode, and fails unrepresentable widths before mode (on
    /// narrow hosts; wide hosts narrow infallibly).
    #[test]
    fn admit_width_mode_boundary() {
        assert_eq!(admit_slot_wait_width_mode(CkFlags::DONT_BLOCK.0), Ok(()));
        assert_eq!(
            admit_slot_wait_width_mode(CkFlags::DONT_BLOCK.0 | 0x8000_0000),
            Ok(()),
            "representable unknown bits ride along with DONT_BLOCK"
        );
        assert_eq!(admit_slot_wait_width_mode(0).unwrap_err(), CkRv::FUNCTION_NOT_SUPPORTED);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(
            admit_slot_wait_width_mode(1u64 << 32).unwrap_err(),
            CkRv::FUNCTION_FAILED,
            "width precedes mode"
        );
    }
}
