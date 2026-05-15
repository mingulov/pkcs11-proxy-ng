use pkcs11_proxy_ng_types::*;

use super::{MockBackend, MultiPartOp};
use pkcs11_proxy_ng_types::{CkOutputBufferResult, CkParameterRoundtripResult};

const MOCK_STATE_PREFIX: [u8; 2] = [0xC9, 0xEA];
const MOCK_SIGN_OUTPUT: [u8; 2] = [0xDE, 0xAD];
pub(super) const MOCK_VERIFY_RECOVER_OUTPUT: [u8; 2] = [0xBE, 0xEF];
pub(super) const MOCK_WRAP_OUTPUT: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
pub(super) const MOCK_ENCAPSULATE_OUTPUT: [u8; 8] =
    [0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF];
const MOCK_ENCAPSULATE_KEY_HANDLE: u64 = 42;
const MOCK_DIGEST_FINAL_LEN: usize = 4;
const MOCK_RANDOM_BYTE: u8 = 0x42;

impl MockBackend {
    pub(super) fn sign_init_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        self.check_injected()?;
        self.state.lock().unwrap().begin_op(session, MultiPartOp::Sign)
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

    pub(super) fn verify_init_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        self.check_injected()?;
        self.state.lock().unwrap().begin_op(session, MultiPartOp::Verify)
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
        let sum: u32 = data.iter().map(|&byte| byte as u32).sum();
        Ok(sum.to_be_bytes().to_vec())
    }

    pub(super) fn digest_update_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        self.state.lock().unwrap().require_op(session, MultiPartOp::Digest)
    }

    pub(super) fn digest_key_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        self.state.lock().unwrap().require_op(session, MultiPartOp::Digest)
    }

    pub(super) fn digest_final_impl(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.state.lock().unwrap().end_op(session, MultiPartOp::Digest)?;
        Ok(vec![0; MOCK_DIGEST_FINAL_LEN])
    }

    pub(super) fn encrypt_init_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        self.check_injected()?;
        self.state.lock().unwrap().begin_op(session, MultiPartOp::Encrypt)
    }

    pub(super) fn encrypt_impl(&self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        self.state.lock().unwrap().end_op(session, MultiPartOp::Encrypt)?;
        Ok(Self::xor_bytes(data))
    }

    pub(super) fn encrypt_update_impl(
        &self,
        session: CkSessionHandle,
        part: &[u8],
    ) -> CkResult<Vec<u8>> {
        self.state.lock().unwrap().require_op(session, MultiPartOp::Encrypt)?;
        Ok(Self::xor_bytes(part))
    }

    pub(super) fn encrypt_final_impl(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.state.lock().unwrap().end_op(session, MultiPartOp::Encrypt)?;
        Ok(vec![])
    }

    pub(super) fn decrypt_init_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        self.check_injected()?;
        self.state.lock().unwrap().begin_op(session, MultiPartOp::Decrypt)
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
            Some(op) => Ok([MOCK_STATE_PREFIX.as_slice(), &[self.encode_op(*op)]].concat()),
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
        _public_key: CkObjectHandle,
        _template: &[CkAttribute],
    ) -> CkResult<(Vec<u8>, CkObjectHandle)> {
        self.check_injected()?;
        // Verify session exists
        let state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        drop(state);
        // Return synthetic ciphertext + a fixed mock key handle
        let ciphertext = MOCK_ENCAPSULATE_OUTPUT.to_vec();
        let key_handle = CkObjectHandle(MOCK_ENCAPSULATE_KEY_HANDLE);
        Ok((ciphertext, key_handle))
    }

    fn encode_op(&self, op: MultiPartOp) -> u8 {
        match op {
            MultiPartOp::Sign => 1,
            MultiPartOp::Verify => 2,
            MultiPartOp::Digest => 3,
            MultiPartOp::Encrypt => 4,
            MultiPartOp::Decrypt => 5,
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
            _ => Err(CkRv::SAVED_STATE_INVALID),
        }
    }

    // --- Exact byte-output mock implementations ---
    //
    // Each delegates to the existing convenience method and wraps the result
    // with `CkOutputBufferResult::from_convenience_bytes`.

    pub(super) fn sign_exact_impl(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = self.sign_impl(session)?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
    }

    pub(super) fn sign_final_exact_impl(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = self.sign_final_impl(session)?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
    }

    pub(super) fn sign_recover_exact_impl(
        &self,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = MOCK_SIGN_OUTPUT.to_vec();
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
    }

    pub(super) fn verify_recover_exact_impl(
        &self,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = self.verify_recover_impl()?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
    }

    pub(super) fn digest_exact_impl(
        &self,
        session: CkSessionHandle,
        data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = self.digest_impl(session, data)?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
    }

    pub(super) fn digest_final_exact_impl(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = self.digest_final_impl(session)?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
    }

    pub(super) fn encrypt_exact_impl(
        &self,
        session: CkSessionHandle,
        data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        if !spec.buffer_present {
            self.state.lock().unwrap().require_op(session, MultiPartOp::Encrypt)?;
            return Ok(CkOutputBufferResult::from_convenience_bytes(&Self::xor_bytes(data), spec));
        }
        let bytes = self.encrypt_impl(session, data)?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
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
        let bytes = self.encrypt_final_impl(session)?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
    }

    pub(super) fn decrypt_exact_impl(
        &self,
        session: CkSessionHandle,
        encrypted_data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let bytes = self.decrypt_impl(session, encrypted_data)?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
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
        let bytes = self.decrypt_final_impl(session)?;
        Ok(CkOutputBufferResult::from_convenience_bytes(&bytes, spec))
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
