use pkcs11_proxy_ng_types::*;

/// A PKCS#11 backend that the daemon can dispatch operations to (ADR-0004 §1).
/// Each method corresponds to a supported PKCS#11 function.
/// All methods are synchronous — the daemon bridges to async at the gRPC layer
/// via tokio::task::spawn_blocking.
pub trait Pkcs11Backend: Send + Sync {
    fn initialize(&self) -> CkResult<()>;
    fn finalize(&self) -> CkResult<()>;
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

    fn find_objects_init(&self, session: CkSessionHandle, template: &[CkAttribute])
    -> CkResult<()>;
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
    fn sign(&self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>>;
    fn sign_update(&self, session: CkSessionHandle, part: &[u8]) -> CkResult<()>;
    fn sign_final(&self, session: CkSessionHandle) -> CkResult<Vec<u8>>;

    fn digest_encrypt_update(&self, session: CkSessionHandle, part: &[u8]) -> CkResult<Vec<u8>>;
    fn decrypt_digest_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>>;
    fn sign_encrypt_update(&self, session: CkSessionHandle, part: &[u8]) -> CkResult<Vec<u8>>;
    fn decrypt_verify_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>>;

    fn sign_recover_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()>;
    fn sign_recover(&self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>>;

    fn verify_recover_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()>;
    fn verify_recover(&self, session: CkSessionHandle, signature: &[u8]) -> CkResult<Vec<u8>>;

    fn verify_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()>;
    fn verify(&self, session: CkSessionHandle, data: &[u8], signature: &[u8]) -> CkResult<()>;
    fn verify_update(&self, session: CkSessionHandle, part: &[u8]) -> CkResult<()>;
    fn verify_final(&self, session: CkSessionHandle, signature: &[u8]) -> CkResult<()>;

    /// Returns `(public_handle, private_handle)` — in that order, matching
    /// the pub_template / priv_template argument ordering.
    fn create_object(
        &self,
        session: CkSessionHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle>;
    fn copy_object(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle>;
    fn destroy_object(&self, session: CkSessionHandle, object: CkObjectHandle) -> CkResult<()>;
    fn get_object_size(&self, session: CkSessionHandle, object: CkObjectHandle) -> CkResult<u64>;
    fn set_attribute_value(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<()>;

    fn digest_init(&self, session: CkSessionHandle, mechanism: &CkMechanism) -> CkResult<()>;
    fn digest(&self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>>;
    fn digest_update(&self, session: CkSessionHandle, part: &[u8]) -> CkResult<()>;
    fn digest_key(&self, session: CkSessionHandle, key: CkObjectHandle) -> CkResult<()>;
    fn digest_final(&self, session: CkSessionHandle) -> CkResult<Vec<u8>>;

    fn encrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>>;
    fn encrypt(&self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>>;
    fn encrypt_update(&self, session: CkSessionHandle, part: &[u8]) -> CkResult<Vec<u8>>;
    fn encrypt_final(&self, session: CkSessionHandle) -> CkResult<Vec<u8>>;

    fn decrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()>;
    fn decrypt(&self, session: CkSessionHandle, encrypted_data: &[u8]) -> CkResult<Vec<u8>>;
    fn decrypt_update(&self, session: CkSessionHandle, encrypted_part: &[u8]) -> CkResult<Vec<u8>>;
    fn decrypt_final(&self, session: CkSessionHandle) -> CkResult<Vec<u8>>;

    fn derive_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle>;
    fn wrap_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
    ) -> CkResult<Vec<u8>>;
    fn unwrap_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        unwrapping_key: CkObjectHandle,
        wrapped_key: &[u8],
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle>;
    fn generate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle>;
    fn generate_key_pair(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        pub_template: &[CkAttribute],
        priv_template: &[CkAttribute],
    ) -> CkResult<(CkObjectHandle, CkObjectHandle)>;
    /// Wait for a slot event. `flags == 1` means non-blocking (CKF_DONT_BLOCK).
    /// Returns the slot ID where the event occurred.
    fn wait_for_slot_event(&self, flags: u64) -> CkResult<CkSlotId>;
    fn get_operation_state(&self, session: CkSessionHandle) -> CkResult<Vec<u8>>;
    fn set_operation_state(
        &self,
        session: CkSessionHandle,
        state: &[u8],
        enc_key: CkObjectHandle,
        auth_key: CkObjectHandle,
    ) -> CkResult<()>;
    fn seed_random(&self, session: CkSessionHandle, seed: &[u8]) -> CkResult<()>;
    fn generate_random(&self, session: CkSessionHandle, len: u32) -> CkResult<Vec<u8>>;

    // --- Exact byte-output methods (Track B) ---
    // Default: FUNCTION_NOT_SUPPORTED. Tasks 2-5 wire real backends.

    // Shape: (session, data, spec) -> CkOutputBufferResult

    fn sign_exact(
        &self,
        _session: CkSessionHandle,
        _data: &[u8],
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_recover_exact(
        &self,
        _session: CkSessionHandle,
        _data: &[u8],
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn verify_recover_exact(
        &self,
        _session: CkSessionHandle,
        _signature: &[u8],
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn digest_exact(
        &self,
        _session: CkSessionHandle,
        _data: &[u8],
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encrypt_exact(
        &self,
        _session: CkSessionHandle,
        _data: &[u8],
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encrypt_exact_with_output(
        &self,
        session: CkSessionHandle,
        data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, Option<CkMechanismParams>)> {
        self.encrypt_exact(session, data, spec).map(|result| (result, None))
    }

    fn encrypt_update_exact(
        &self,
        _session: CkSessionHandle,
        _part: &[u8],
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_exact(
        &self,
        _session: CkSessionHandle,
        _encrypted_data: &[u8],
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_update_exact(
        &self,
        _session: CkSessionHandle,
        _encrypted_part: &[u8],
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn digest_encrypt_update_exact(
        &self,
        _session: CkSessionHandle,
        _part: &[u8],
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_digest_update_exact(
        &self,
        _session: CkSessionHandle,
        _encrypted_part: &[u8],
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_encrypt_update_exact(
        &self,
        _session: CkSessionHandle,
        _part: &[u8],
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_verify_update_exact(
        &self,
        _session: CkSessionHandle,
        _encrypted_part: &[u8],
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

    // --- Track C: Exact parameter-output methods ---
    // Default: FUNCTION_NOT_SUPPORTED.

    fn encrypt_message_exact(
        &self,
        _session: CkSessionHandle,
        _parameter: &[u8],
        _aad: &[u8],
        _plaintext: &[u8],
        _output_spec: &CkOutputBufferSpec,
        _param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_message_exact(
        &self,
        _session: CkSessionHandle,
        _parameter: &[u8],
        _aad: &[u8],
        _ciphertext: &[u8],
        _output_spec: &CkOutputBufferSpec,
        _param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_message_exact(
        &self,
        _session: CkSessionHandle,
        _parameter: &[u8],
        _data: &[u8],
        _output_spec: &CkOutputBufferSpec,
        _param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encrypt_message_next_exact(
        &self,
        _session: CkSessionHandle,
        _parameter: &[u8],
        _plaintext_part: &[u8],
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
        _ciphertext_part: &[u8],
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
        _data_part: &[u8],
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
        _aad: &[u8],
        _plaintext: &[u8],
        _output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    )> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_message_exact_msg(
        &self,
        _session: CkSessionHandle,
        _msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        _aad: &[u8],
        _ciphertext: &[u8],
        _output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    )> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_message_exact_msg(
        &self,
        _session: CkSessionHandle,
        _msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        _data: &[u8],
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
        _plaintext_part: &[u8],
        _flags: CkFlags,
        _output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    )> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_message_next_exact_msg(
        &self,
        _session: CkSessionHandle,
        _msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        _ciphertext_part: &[u8],
        _flags: CkFlags,
        _output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    )> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_message_next_exact_msg(
        &self,
        _session: CkSessionHandle,
        _msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        _data_part: &[u8],
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
        _aad: &[u8],
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
        _username: &[u8],
        _pin: &[u8],
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
        _template: &[CkAttribute],
        _spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputAndHandleResult> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encapsulate_key(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _public_key: CkObjectHandle,
        _template: &[CkAttribute],
    ) -> CkResult<(Vec<u8>, CkObjectHandle)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decapsulate_key(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _private_key: CkObjectHandle,
        _template: &[CkAttribute],
        _ciphertext: &[u8],
    ) -> CkResult<CkObjectHandle> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    // Wave 3: Message encrypt — mechanism is Option (None means cancel)

    fn message_encrypt_init(
        &self,
        _session: CkSessionHandle,
        _mechanism: Option<&CkMechanism>,
        _key: CkObjectHandle,
    ) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encrypt_message(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
        _aad: &[u8],
        _plaintext: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encrypt_message_begin(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
        _aad: &[u8],
    ) -> CkResult<Vec<u8>> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn encrypt_message_next(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
        _plaintext_part: &[u8],
        _flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
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
        _key: CkObjectHandle,
    ) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_message(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
        _aad: &[u8],
        _ciphertext: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_message_begin(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
        _aad: &[u8],
    ) -> CkResult<Vec<u8>> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn decrypt_message_next(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
        _ciphertext_part: &[u8],
        _flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
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
        _data: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_message_begin(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
    ) -> CkResult<Vec<u8>> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn sign_message_next(
        &self,
        _session: CkSessionHandle,
        _parameter: &mut [u8],
        _data_part: &[u8],
        _request_signature: bool,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
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
        _data: &[u8],
        _signature: &[u8],
    ) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn verify_message_begin(&self, _session: CkSessionHandle, _parameter: &[u8]) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn verify_message_next(
        &self,
        _session: CkSessionHandle,
        _parameter: &[u8],
        _data_part: &[u8],
        _is_final: bool,
        _signature: &[u8],
    ) -> CkResult<()> {
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
        _signature: &[u8],
    ) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn verify_signature(&self, _session: CkSessionHandle, _data: &[u8]) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn verify_signature_update(
        &self,
        _session: CkSessionHandle,
        _data_part: &[u8],
    ) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn verify_signature_final(&self, _session: CkSessionHandle) -> CkResult<()> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    // Wave 5: Authenticated wrap — returns (wrapped_key, mechanism_parameter_out)

    fn wrap_key_authenticated(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _wrapping_key: CkObjectHandle,
        _key: CkObjectHandle,
        _aad: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    fn unwrap_key_authenticated(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _unwrapping_key: CkObjectHandle,
        _wrapped_key: &[u8],
        _template: &[CkAttribute],
        _aad: &[u8],
    ) -> CkResult<(CkObjectHandle, Vec<u8>)> {
        Err(CkRv::FUNCTION_NOT_SUPPORTED)
    }

    // Wave 5: Async (Option B: polling only)

    fn async_complete(
        &self,
        _session: CkSessionHandle,
        _function_name: &str,
    ) -> CkResult<(u64, Vec<u8>, u64, CkObjectHandle, CkObjectHandle)> {
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
    ) -> CkResult<Vec<u8>> {
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
}
