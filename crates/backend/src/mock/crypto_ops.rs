use pkcs11_proxy_ng_proto::convert::message_params::{
    CcmMessageParams, GcmMessageParams, MessageParameter, Salsa20ChaCha20Poly1305MessageParams,
};
use pkcs11_proxy_ng_types::*;

use super::{MockBackend, MultiPartOp};
use pkcs11_proxy_ng_types::{CkOutputBufferResult, CkParameterRoundtripResult};

const MOCK_STATE_PREFIX: [u8; 2] = [0xC9, 0xEA];
const MOCK_SIGN_OUTPUT: [u8; 2] = [0xDE, 0xAD];
pub(super) const MOCK_VERIFY_RECOVER_OUTPUT: [u8; 2] = [0xBE, 0xEF];
pub(super) const MOCK_WRAP_OUTPUT: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
pub(super) const MOCK_ENCAPSULATE_OUTPUT: [u8; 8] =
    [0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF];
const MOCK_GCM_TAG_BYTE: u8 = 0xA5;
const MOCK_CCM_MAC_BYTE: u8 = 0xC3;
const MOCK_SALSA_CHACHA_TAG_BYTE: u8 = 0x5A;
const MOCK_DIGEST_FINAL_LEN: usize = 4;
const MOCK_RANDOM_BYTE: u8 = 0x42;

impl MockBackend {
    pub(super) fn require_live_key(
        &self,
        state: &super::MockState,
        session: CkSessionHandle,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        self.require_live_object(state, key)
    }

    pub(super) fn require_live_keys(
        &self,
        state: &super::MockState,
        session: CkSessionHandle,
        keys: &[CkObjectHandle],
    ) -> CkResult<()> {
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        for key in keys {
            self.require_live_object(state, *key)?;
        }
        Ok(())
    }

    pub(super) fn require_live_key_for_optional_mechanism_workflow(
        &self,
        state: &super::MockState,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
        required_flag: u64,
    ) -> CkResult<()> {
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        if let Some(mechanism) = mechanism {
            self.require_mechanism_workflow_for_state(state, session, mechanism, required_flag)?;
            self.require_live_object(state, key)?;
        }
        Ok(())
    }

    fn begin_keyed_op(
        &self,
        session: CkSessionHandle,
        key: CkObjectHandle,
        op: MultiPartOp,
    ) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        self.require_live_key(&state, session, key)?;
        state.begin_op(session, op)
    }

    pub(super) fn begin_keyed_op_with_mechanism(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
        op: MultiPartOp,
    ) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        self.require_live_key(&state, session, key)?;
        self.validate_source_grounded_param_handles(&state, mechanism)?;
        state.begin_op(session, op)
    }

    pub(super) fn init_cancel_impl(
        &self,
        session: CkSessionHandle,
        op: MultiPartOp,
    ) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        state.cancel_op_if_active(session, op);
        Ok(())
    }

    pub(super) fn sign_init_impl(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.check_injected()?;
        self.begin_keyed_op_with_mechanism(session, mechanism, key, MultiPartOp::Sign)
    }

    pub(super) fn sign_impl(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.state.lock().unwrap().end_op(session, MultiPartOp::Sign)?;
        Ok(MOCK_SIGN_OUTPUT.to_vec())
    }

    pub(super) fn sign_update_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        self.state.lock().unwrap().require_op(session, MultiPartOp::Sign)
    }

    pub(super) fn sign_final_impl(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.state.lock().unwrap().end_op(session, MultiPartOp::Sign)?;
        Ok(MOCK_SIGN_OUTPUT.to_vec())
    }

    pub(super) fn verify_init_impl(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.check_injected()?;
        self.begin_keyed_op_with_mechanism(session, mechanism, key, MultiPartOp::Verify)
    }

    pub(super) fn verify_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        self.state.lock().unwrap().end_op(session, MultiPartOp::Verify)
    }

    pub(super) fn verify_update_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        self.state.lock().unwrap().require_op(session, MultiPartOp::Verify)
    }

    pub(super) fn verify_final_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        self.state.lock().unwrap().end_op(session, MultiPartOp::Verify)
    }

    pub(super) fn digest_init_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        self.state.lock().unwrap().begin_op(session, MultiPartOp::Digest)
    }

    pub(super) fn digest_impl(&self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        self.state.lock().unwrap().end_op(session, MultiPartOp::Digest)?;
        Ok(Self::digest_bytes(data))
    }

    pub(super) fn digest_update_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        self.state.lock().unwrap().require_op(session, MultiPartOp::Digest)
    }

    pub(super) fn digest_key_impl(
        &self,
        session: CkSessionHandle,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        state.require_op(session, MultiPartOp::Digest)?;
        self.require_live_object(&state, key)
    }

    pub(super) fn digest_final_impl(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.state.lock().unwrap().end_op(session, MultiPartOp::Digest)?;
        Ok(vec![0; MOCK_DIGEST_FINAL_LEN])
    }

    pub(super) fn encrypt_init_impl(
        &self,
        session: CkSessionHandle,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.check_injected()?;
        self.begin_keyed_op(session, key, MultiPartOp::Encrypt)
    }

    pub(super) fn encrypt_impl(&self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        self.state.lock().unwrap().end_op(session, MultiPartOp::Encrypt)?;
        self.record_encrypt_operation_output(session);
        Ok(Self::xor_bytes(data))
    }

    pub(super) fn encrypt_update_impl(
        &self,
        session: CkSessionHandle,
        part: &[u8],
    ) -> CkResult<Vec<u8>> {
        self.state.lock().unwrap().require_op(session, MultiPartOp::Encrypt)?;
        self.record_encrypt_operation_output(session);
        Ok(Self::xor_bytes(part))
    }

    pub(super) fn encrypt_final_impl(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.state.lock().unwrap().end_op(session, MultiPartOp::Encrypt)?;
        self.record_encrypt_operation_output(session);
        Ok(vec![])
    }

    fn record_encrypt_operation_output(&self, session: CkSessionHandle) {
        if let Some(params) = self.encrypt_operation_output.lock().unwrap().clone() {
            self.session_mechanism_output.lock().unwrap().insert(session.0, params);
        }
    }

    pub(super) fn decrypt_init_impl(
        &self,
        session: CkSessionHandle,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.check_injected()?;
        self.begin_keyed_op(session, key, MultiPartOp::Decrypt)
    }

    pub(super) fn decrypt_impl(
        &self,
        session: CkSessionHandle,
        encrypted_data: &[u8],
    ) -> CkResult<Vec<u8>> {
        self.state.lock().unwrap().end_op(session, MultiPartOp::Decrypt)?;
        Ok(Self::xor_bytes(encrypted_data))
    }

    pub(super) fn decrypt_update_impl(
        &self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>> {
        self.state.lock().unwrap().require_op(session, MultiPartOp::Decrypt)?;
        Ok(Self::xor_bytes(encrypted_part))
    }

    pub(super) fn decrypt_final_impl(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.state.lock().unwrap().end_op(session, MultiPartOp::Decrypt)?;
        Ok(vec![])
    }

    pub(super) fn operation_state(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        let state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        match state.active_ops.get(&session.0) {
            None => Err(CkRv::OPERATION_NOT_INITIALIZED),
            Some(op) => match self.encode_op(*op) {
                Some(op_byte) => Ok([MOCK_STATE_PREFIX.as_slice(), &[op_byte]].concat()),
                None => Err(CkRv::OPERATION_NOT_INITIALIZED),
            },
        }
    }

    pub(super) fn restore_operation_state(
        &self,
        session: CkSessionHandle,
        state_blob: &[u8],
    ) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        if state.active_ops.contains_key(&session.0) {
            return Err(CkRv::OPERATION_ACTIVE);
        }
        let op = self.decode_state_blob(state_blob)?;
        state.active_ops.insert(session.0, op);
        Ok(())
    }

    pub(super) fn seed_random_impl(&self) -> CkResult<()> {
        Ok(())
    }

    pub(super) fn generate_random_impl(&self, len: u32) -> CkResult<Vec<u8>> {
        self.check_injected()?;
        if len > Self::MAX_RANDOM_BYTES {
            return Err(CkRv::DATA_LEN_RANGE);
        }
        Ok(vec![MOCK_RANDOM_BYTE; len as usize])
    }

    pub(super) fn combined_update(&self, part: &[u8]) -> CkResult<Vec<u8>> {
        Ok(Self::xor_bytes(part))
    }

    pub(super) fn verify_recover_impl(&self) -> CkResult<Vec<u8>> {
        Ok(MOCK_VERIFY_RECOVER_OUTPUT.to_vec())
    }

    pub(super) fn encapsulate_key_impl(
        &self,
        session: CkSessionHandle,
        _mechanism: &CkMechanism,
        public_key: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<(Vec<u8>, CkObjectHandle)> {
        self.check_injected()?;
        let mut state = self.state.lock().unwrap();
        self.require_live_key(&state, session, public_key)?;
        let ciphertext = MOCK_ENCAPSULATE_OUTPUT.to_vec();
        let key_handle =
            self.allocate_session_object_with_template(&mut state, session, template)?;
        Ok((ciphertext, key_handle))
    }

    pub(super) fn encapsulate_key_exact_impl(
        &self,
        session: CkSessionHandle,
        _mechanism: &CkMechanism,
        public_key: CkObjectHandle,
        template: &[CkAttribute],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputAndHandleResult> {
        self.check_injected()?;
        let output = CkOutputBufferResult::from_convenience_bytes(&MOCK_ENCAPSULATE_OUTPUT, spec);

        let mut state = self.state.lock().unwrap();
        self.require_live_key(&state, session, public_key)?;

        let object_handle = if output.value.is_some() {
            self.allocate_session_object_with_template(&mut state, session, template)?
        } else {
            CkObjectHandle(0)
        };

        Ok(CkOutputAndHandleResult {
            ck_rv: output.ck_rv,
            returned_len: output.returned_len,
            value: output.value,
            object_handle,
        })
    }

    fn encode_op(&self, op: MultiPartOp) -> Option<u8> {
        match op {
            MultiPartOp::Sign => Some(1),
            MultiPartOp::Verify => Some(2),
            MultiPartOp::Digest => Some(3),
            MultiPartOp::Encrypt => Some(4),
            MultiPartOp::Decrypt => Some(5),
            MultiPartOp::SignRecover => Some(6),
            MultiPartOp::VerifyRecover => Some(7),
            MultiPartOp::FindObjects => None,
        }
    }

    fn decode_state_blob(&self, state_blob: &[u8]) -> CkResult<MultiPartOp> {
        if state_blob.len() != 3 || state_blob[..2] != MOCK_STATE_PREFIX {
            return Err(CkRv::SAVED_STATE_INVALID);
        }
        match state_blob[2] {
            1 => Ok(MultiPartOp::Sign),
            2 => Ok(MultiPartOp::Verify),
            3 => Ok(MultiPartOp::Digest),
            4 => Ok(MultiPartOp::Encrypt),
            5 => Ok(MultiPartOp::Decrypt),
            6 => Ok(MultiPartOp::SignRecover),
            7 => Ok(MultiPartOp::VerifyRecover),
            _ => Err(CkRv::SAVED_STATE_INVALID),
        }
    }

    // --- Exact byte-output mock implementations ---
    //
    // Each delegates to the existing convenience method and wraps the result
    // with `CkOutputBufferResult::from_convenience_bytes`.

    fn exact_terminal_output(
        &self,
        session: CkSessionHandle,
        op: MultiPartOp,
        bytes: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let result = CkOutputBufferResult::from_convenience_bytes(bytes, spec);
        if result.ck_rv == CkRv::OK && result.value.is_some() {
            self.state.lock().unwrap().end_op(session, op)?;
        } else {
            self.state.lock().unwrap().require_op(session, op)?;
        }
        Ok(result)
    }

    pub(super) fn sign_exact_impl(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.exact_terminal_output(session, MultiPartOp::Sign, &MOCK_SIGN_OUTPUT, spec)
    }

    pub(super) fn sign_final_exact_impl(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.exact_terminal_output(session, MultiPartOp::Sign, &MOCK_SIGN_OUTPUT, spec)
    }

    pub(super) fn sign_recover_exact_impl(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.exact_terminal_output(session, MultiPartOp::SignRecover, &MOCK_SIGN_OUTPUT, spec)
    }

    pub(super) fn verify_recover_exact_impl(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = self.verify_recover_impl()?;
        self.exact_terminal_output(session, MultiPartOp::VerifyRecover, &bytes, spec)
    }

    pub(super) fn digest_exact_impl(
        &self,
        session: CkSessionHandle,
        data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = Self::digest_bytes(data);
        self.exact_terminal_output(session, MultiPartOp::Digest, &bytes, spec)
    }

    pub(super) fn digest_final_exact_impl(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = vec![0; MOCK_DIGEST_FINAL_LEN];
        self.exact_terminal_output(session, MultiPartOp::Digest, &bytes, spec)
    }

    pub(super) fn encrypt_exact_impl(
        &self,
        session: CkSessionHandle,
        data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = Self::xor_bytes(data);
        let result = self.exact_terminal_output(session, MultiPartOp::Encrypt, &bytes, spec)?;
        if result.ck_rv == CkRv::OK && result.value.is_some() {
            self.record_encrypt_operation_output(session);
        }
        Ok(result)
    }

    pub(super) fn encrypt_update_exact_impl(
        &self,
        session: CkSessionHandle,
        part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = self.encrypt_update_impl(session, part)?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
    }

    pub(super) fn encrypt_final_exact_impl(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = Vec::new();
        let result = self.exact_terminal_output(session, MultiPartOp::Encrypt, &bytes, spec)?;
        if result.ck_rv == CkRv::OK && result.value.is_some() {
            self.record_encrypt_operation_output(session);
        }
        Ok(result)
    }

    pub(super) fn decrypt_exact_impl(
        &self,
        session: CkSessionHandle,
        encrypted_data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = Self::xor_bytes(encrypted_data);
        self.exact_terminal_output(session, MultiPartOp::Decrypt, &bytes, spec)
    }

    pub(super) fn decrypt_update_exact_impl(
        &self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = self.decrypt_update_impl(session, encrypted_part)?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
    }

    pub(super) fn decrypt_final_exact_impl(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = Vec::new();
        self.exact_terminal_output(session, MultiPartOp::Decrypt, &bytes, spec)
    }

    pub(super) fn digest_encrypt_update_exact_impl(
        &self,
        part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = self.combined_update(part)?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
    }

    pub(super) fn decrypt_digest_update_exact_impl(
        &self,
        encrypted_part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = self.combined_update(encrypted_part)?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
    }

    pub(super) fn sign_encrypt_update_exact_impl(
        &self,
        part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = self.combined_update(part)?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
    }

    pub(super) fn decrypt_verify_update_exact_impl(
        &self,
        encrypted_part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = self.combined_update(encrypted_part)?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
    }

    pub(super) fn wrap_key_exact_impl(
        &self,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = self.wrap_key_impl()?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
    }

    pub(super) fn get_operation_state_exact_impl(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = self.operation_state(session)?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
    }

    // --- Track C: Exact parameter-output mock implementations ---
    //
    // Each calls the existing convenience method, wraps the main output with
    // `CkOutputBufferResult::from_convenience_bytes`, and returns the input
    // parameter bytes as the parameter write-back (identity).

    fn mock_param_roundtrip(
        parameter: &[u8],
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkParameterRoundtripResult {
        CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: parameter.len() as u64,
            value: if param_out_spec.buffer_present { Some(parameter.to_vec()) } else { None },
        }
    }

    fn mock_message_parameter_out(message_parameter: &MessageParameter) -> MessageParameter {
        match message_parameter {
            MessageParameter::Raw(raw) => MessageParameter::Raw(raw.clone()),
            MessageParameter::GcmMessage(params) => {
                let tag_len = if params.tag_bits == 0 {
                    params.tag.len()
                } else {
                    params.tag_bits.div_ceil(8) as usize
                };
                MessageParameter::GcmMessage(GcmMessageParams {
                    iv: params.iv.clone(),
                    iv_fixed_bits: params.iv_fixed_bits,
                    iv_generator: params.iv_generator,
                    tag: vec![MOCK_GCM_TAG_BYTE; tag_len],
                    tag_bits: params.tag_bits,
                })
            }
            MessageParameter::CcmMessage(params) => {
                let mac_len =
                    if params.mac_len == 0 { params.mac.len() } else { params.mac_len as usize };
                MessageParameter::CcmMessage(CcmMessageParams {
                    data_len: params.data_len,
                    nonce: params.nonce.clone(),
                    nonce_fixed_bits: params.nonce_fixed_bits,
                    nonce_generator: params.nonce_generator,
                    mac: vec![MOCK_CCM_MAC_BYTE; mac_len],
                    mac_len: params.mac_len,
                })
            }
            MessageParameter::SalaChacha(params) => {
                let tag_len = if params.tag.is_empty() { 16 } else { params.tag.len() };
                MessageParameter::SalaChacha(Salsa20ChaCha20Poly1305MessageParams {
                    nonce: params.nonce.clone(),
                    tag: vec![MOCK_SALSA_CHACHA_TAG_BYTE; tag_len],
                })
            }
        }
    }

    pub(super) fn encrypt_message_exact_msg_impl(
        &self,
        session: CkSessionHandle,
        message_parameter: &MessageParameter,
        _aad: &[u8],
        plaintext: &[u8],
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        self.require_open_session(session)?;
        let bytes = Self::xor_bytes(plaintext);
        let output_result = CkOutputBufferResult::from_convenience_bytes(&bytes, output_spec);
        Ok((output_result, Self::mock_message_parameter_out(message_parameter)))
    }

    pub(super) fn decrypt_message_exact_msg_impl(
        &self,
        session: CkSessionHandle,
        message_parameter: &MessageParameter,
        _aad: &[u8],
        ciphertext: &[u8],
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        self.require_open_session(session)?;
        let bytes = Self::xor_bytes(ciphertext);
        let output_result = CkOutputBufferResult::from_convenience_bytes(&bytes, output_spec);
        Ok((output_result, Self::mock_message_parameter_out(message_parameter)))
    }

    pub(super) fn sign_message_exact_msg_impl(
        &self,
        session: CkSessionHandle,
        message_parameter: &MessageParameter,
        data: &[u8],
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        self.require_open_session(session)?;
        let bytes = Self::reverse_bytes(data);
        let output_result = CkOutputBufferResult::from_convenience_bytes(&bytes, output_spec);
        Ok((output_result, Self::mock_message_parameter_out(message_parameter)))
    }

    pub(super) fn encrypt_message_next_exact_msg_impl(
        &self,
        session: CkSessionHandle,
        message_parameter: &MessageParameter,
        plaintext_part: &[u8],
        _flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        self.encrypt_message_exact_msg_impl(
            session,
            message_parameter,
            &[],
            plaintext_part,
            output_spec,
        )
    }

    pub(super) fn decrypt_message_next_exact_msg_impl(
        &self,
        session: CkSessionHandle,
        message_parameter: &MessageParameter,
        ciphertext_part: &[u8],
        _flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        self.decrypt_message_exact_msg_impl(
            session,
            message_parameter,
            &[],
            ciphertext_part,
            output_spec,
        )
    }

    pub(super) fn sign_message_next_exact_msg_impl(
        &self,
        session: CkSessionHandle,
        message_parameter: &MessageParameter,
        data_part: &[u8],
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        self.sign_message_exact_msg_impl(session, message_parameter, data_part, output_spec)
    }

    pub(super) fn encrypt_message_exact_impl(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        _aad: &[u8],
        plaintext: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let bytes = self.encrypt_impl(session, plaintext)?;
        let output_result = CkOutputBufferResult::from_convenience_bytes(&bytes, output_spec);
        let param_result = Self::mock_param_roundtrip(parameter, param_out_spec);
        Ok((output_result, param_result))
    }

    pub(super) fn decrypt_message_exact_impl(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        _aad: &[u8],
        ciphertext: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let bytes = self.decrypt_impl(session, ciphertext)?;
        let output_result = CkOutputBufferResult::from_convenience_bytes(&bytes, output_spec);
        let param_result = Self::mock_param_roundtrip(parameter, param_out_spec);
        Ok((output_result, param_result))
    }

    pub(super) fn sign_message_exact_impl(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        _data: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let bytes = self.sign_impl(session)?;
        let output_result = CkOutputBufferResult::from_convenience_bytes(&bytes, output_spec);
        let param_result = Self::mock_param_roundtrip(parameter, param_out_spec);
        Ok((output_result, param_result))
    }

    pub(super) fn encrypt_message_next_exact_impl(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        plaintext_part: &[u8],
        _flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let bytes = self.encrypt_update_impl(session, plaintext_part)?;
        let output_result = CkOutputBufferResult::from_convenience_bytes(&bytes, output_spec);
        let param_result = Self::mock_param_roundtrip(parameter, param_out_spec);
        Ok((output_result, param_result))
    }

    pub(super) fn decrypt_message_next_exact_impl(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        ciphertext_part: &[u8],
        _flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let bytes = self.decrypt_update_impl(session, ciphertext_part)?;
        let output_result = CkOutputBufferResult::from_convenience_bytes(&bytes, output_spec);
        let param_result = Self::mock_param_roundtrip(parameter, param_out_spec);
        Ok((output_result, param_result))
    }

    pub(super) fn sign_message_next_exact_impl(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        _data_part: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let bytes = self.sign_impl(session)?;
        let output_result = CkOutputBufferResult::from_convenience_bytes(&bytes, output_spec);
        let param_result = Self::mock_param_roundtrip(parameter, param_out_spec);
        Ok((output_result, param_result))
    }

    pub(super) fn wrap_key_authenticated_exact_impl(
        &self,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let bytes = self.wrap_key_impl()?;
        let output_result = CkOutputBufferResult::from_convenience_bytes(&bytes, output_spec);
        // Authenticated wrap has no input parameter in the mock — return empty.
        let param_result = CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: 0,
            value: if param_out_spec.buffer_present { Some(Vec::new()) } else { None },
        };
        Ok((output_result, param_result))
    }
}
