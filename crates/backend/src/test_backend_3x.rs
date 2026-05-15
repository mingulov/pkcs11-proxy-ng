//! A test-only backend implementing PKCS#11 3.0/3.2 trait methods for
//! integration testing.  Wraps `MockBackend` for the base v2.40 interface and
//! provides simple, deterministic implementations of all 34 new trait methods.
//!
//! **Not cryptographically correct** — the goal is protocol correctness so that
//! full-stack integration tests can verify the gRPC ↔ backend wiring.

use crate::mock::MockBackend;
use crate::traits::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;
use std::sync::Mutex;

/// Test-only 3.x backend state.
struct State3x {
    /// Stored signature for VerifySignatureInit → VerifySignature flow.
    stored_signature: Vec<u8>,
    /// Accumulated data for VerifySignatureUpdate → VerifySignatureFinal flow.
    accumulated_data: Vec<u8>,
}

/// A test backend that delegates the PKCS#11 2.40 surface to `MockBackend` and
/// overrides all 3.0/3.2 trait methods with simple deterministic logic.
pub struct TestBackend3x {
    inner: MockBackend,
    state_3x: Mutex<State3x>,
}

impl TestBackend3x {
    /// Create a `TestBackend3x` wrapping a fresh `MockBackend` with the given
    /// slots and mechanisms.
    pub fn new(slots: Vec<CkSlotId>, mechanisms: Vec<CkMechanismType>) -> Self {
        Self {
            inner: MockBackend::new(slots, mechanisms),
            state_3x: Mutex::new(State3x {
                stored_signature: Vec::new(),
                accumulated_data: Vec::new(),
            }),
        }
    }

    /// Simple default test backend: one slot, one mechanism.
    pub fn default_test() -> Self {
        Self::new(vec![CkSlotId(0)], vec![CkMechanismType(0x00000001)])
    }

    /// XOR every byte with 0xAA — used for message encrypt/decrypt.
    fn xor_aa(data: &[u8]) -> Vec<u8> {
        data.iter().map(|b| b ^ 0xAA).collect()
    }

    /// "Sign" by reversing data bytes.
    fn reverse_sign(data: &[u8]) -> Vec<u8> {
        data.iter().rev().copied().collect()
    }
}

// ---- Delegate the entire v2.40 surface to `MockBackend` ----

impl Pkcs11Backend for TestBackend3x {
    fn initialize(&self) -> CkResult<()> {
        self.inner.initialize()
    }
    fn finalize(&self) -> CkResult<()> {
        self.inner.finalize()
    }
    fn get_info(&self) -> CkResult<CkInfo> {
        self.inner.get_info()
    }
    fn get_slot_list(&self, token_present: bool) -> CkResult<Vec<CkSlotId>> {
        self.inner.get_slot_list(token_present)
    }
    fn get_slot_info(&self, slot_id: CkSlotId) -> CkResult<CkSlotInfo> {
        self.inner.get_slot_info(slot_id)
    }
    fn get_token_info(&self, slot_id: CkSlotId) -> CkResult<CkTokenInfo> {
        self.inner.get_token_info(slot_id)
    }
    fn get_mechanism_list(&self, slot_id: CkSlotId) -> CkResult<Vec<CkMechanismType>> {
        self.inner.get_mechanism_list(slot_id)
    }
    fn get_mechanism_info(
        &self,
        slot_id: CkSlotId,
        mech: CkMechanismType,
    ) -> CkResult<CkMechanismInfo> {
        self.inner.get_mechanism_info(slot_id, mech)
    }
    fn init_token(&self, slot_id: CkSlotId, so_pin: Option<&[u8]>, label: &str) -> CkResult<()> {
        self.inner.init_token(slot_id, so_pin, label)
    }
    fn init_pin(&self, session: CkSessionHandle, pin: Option<&[u8]>) -> CkResult<()> {
        self.inner.init_pin(session, pin)
    }
    fn set_pin(
        &self,
        session: CkSessionHandle,
        old_pin: Option<&[u8]>,
        new_pin: Option<&[u8]>,
    ) -> CkResult<()> {
        self.inner.set_pin(session, old_pin, new_pin)
    }
    fn open_session(&self, slot_id: CkSlotId, flags: CkSessionFlags) -> CkResult<CkSessionHandle> {
        self.inner.open_session(slot_id, flags)
    }
    fn close_session(&self, session: CkSessionHandle) -> CkResult<()> {
        self.inner.close_session(session)
    }
    fn close_all_sessions(&self, slot_id: CkSlotId) -> CkResult<()> {
        self.inner.close_all_sessions(slot_id)
    }
    fn get_session_info(&self, session: CkSessionHandle) -> CkResult<CkSessionInfo> {
        self.inner.get_session_info(session)
    }
    fn login(
        &self,
        session: CkSessionHandle,
        user_type: CkUserType,
        pin: Option<&[u8]>,
    ) -> CkResult<()> {
        self.inner.login(session, user_type, pin)
    }
    fn logout(&self, session: CkSessionHandle) -> CkResult<()> {
        self.inner.logout(session)
    }
    fn find_objects_init(&self, s: CkSessionHandle, t: &[CkAttribute]) -> CkResult<()> {
        self.inner.find_objects_init(s, t)
    }
    fn find_objects(&self, s: CkSessionHandle, m: u32) -> CkResult<Vec<CkObjectHandle>> {
        self.inner.find_objects(s, m)
    }
    fn find_objects_final(&self, s: CkSessionHandle) -> CkResult<()> {
        self.inner.find_objects_final(s)
    }
    fn get_attribute_value(
        &self,
        s: CkSessionHandle,
        object: CkObjectHandle,
        template: &mut [CkAttribute],
    ) -> CkResult<()> {
        self.inner.get_attribute_value(s, object, template)
    }
    fn get_attribute_value_exact(
        &self,
        s: CkSessionHandle,
        object: CkObjectHandle,
        queries: &[CkAttributeQuery],
    ) -> CkResult<(CkRv, Vec<CkAttributeQueryResult>)> {
        self.inner.get_attribute_value_exact(s, object, queries)
    }
    fn sign_init(&self, s: CkSessionHandle, m: &CkMechanism, k: CkObjectHandle) -> CkResult<()> {
        self.inner.sign_init(s, m, k)
    }
    fn sign(&self, s: CkSessionHandle, d: &[u8]) -> CkResult<Vec<u8>> {
        self.inner.sign(s, d)
    }
    fn sign_update(&self, s: CkSessionHandle, p: &[u8]) -> CkResult<()> {
        self.inner.sign_update(s, p)
    }
    fn sign_final(&self, s: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.inner.sign_final(s)
    }
    fn sign_recover_init(
        &self,
        s: CkSessionHandle,
        m: &CkMechanism,
        k: CkObjectHandle,
    ) -> CkResult<()> {
        self.inner.sign_recover_init(s, m, k)
    }
    fn sign_recover(&self, s: CkSessionHandle, d: &[u8]) -> CkResult<Vec<u8>> {
        self.inner.sign_recover(s, d)
    }
    fn verify_recover_init(
        &self,
        s: CkSessionHandle,
        m: &CkMechanism,
        k: CkObjectHandle,
    ) -> CkResult<()> {
        self.inner.verify_recover_init(s, m, k)
    }
    fn verify_recover(&self, s: CkSessionHandle, sig: &[u8]) -> CkResult<Vec<u8>> {
        self.inner.verify_recover(s, sig)
    }
    fn verify_init(&self, s: CkSessionHandle, m: &CkMechanism, k: CkObjectHandle) -> CkResult<()> {
        self.inner.verify_init(s, m, k)
    }
    fn verify(&self, s: CkSessionHandle, d: &[u8], sig: &[u8]) -> CkResult<()> {
        self.inner.verify(s, d, sig)
    }
    fn verify_update(&self, s: CkSessionHandle, p: &[u8]) -> CkResult<()> {
        self.inner.verify_update(s, p)
    }
    fn verify_final(&self, s: CkSessionHandle, sig: &[u8]) -> CkResult<()> {
        self.inner.verify_final(s, sig)
    }
    fn digest_init(&self, s: CkSessionHandle, m: &CkMechanism) -> CkResult<()> {
        self.inner.digest_init(s, m)
    }
    fn digest(&self, s: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        self.inner.digest(s, data)
    }
    fn digest_update(&self, s: CkSessionHandle, p: &[u8]) -> CkResult<()> {
        self.inner.digest_update(s, p)
    }
    fn digest_key(&self, s: CkSessionHandle, k: CkObjectHandle) -> CkResult<()> {
        self.inner.digest_key(s, k)
    }
    fn digest_final(&self, s: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.inner.digest_final(s)
    }
    fn encrypt_init(
        &self,
        s: CkSessionHandle,
        m: &CkMechanism,
        k: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>> {
        self.inner.encrypt_init(s, m, k)
    }
    fn encrypt(&self, s: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        self.inner.encrypt(s, data)
    }
    fn encrypt_update(&self, s: CkSessionHandle, part: &[u8]) -> CkResult<Vec<u8>> {
        self.inner.encrypt_update(s, part)
    }
    fn encrypt_final(&self, s: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.inner.encrypt_final(s)
    }
    fn decrypt_init(&self, s: CkSessionHandle, m: &CkMechanism, k: CkObjectHandle) -> CkResult<()> {
        self.inner.decrypt_init(s, m, k)
    }
    fn decrypt(&self, s: CkSessionHandle, encrypted_data: &[u8]) -> CkResult<Vec<u8>> {
        self.inner.decrypt(s, encrypted_data)
    }
    fn decrypt_update(&self, s: CkSessionHandle, encrypted_part: &[u8]) -> CkResult<Vec<u8>> {
        self.inner.decrypt_update(s, encrypted_part)
    }
    fn decrypt_final(&self, s: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.inner.decrypt_final(s)
    }
    fn derive_key(
        &self,
        s: CkSessionHandle,
        m: &CkMechanism,
        base_key: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.inner.derive_key(s, m, base_key, template)
    }
    fn wrap_key(
        &self,
        s: CkSessionHandle,
        m: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
    ) -> CkResult<Vec<u8>> {
        self.inner.wrap_key(s, m, wrapping_key, key)
    }
    fn unwrap_key(
        &self,
        s: CkSessionHandle,
        m: &CkMechanism,
        unwrapping_key: CkObjectHandle,
        wrapped_key: &[u8],
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.inner.unwrap_key(s, m, unwrapping_key, wrapped_key, template)
    }
    fn generate_key(
        &self,
        s: CkSessionHandle,
        m: &CkMechanism,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.inner.generate_key(s, m, template)
    }
    fn create_object(
        &self,
        s: CkSessionHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.inner.create_object(s, template)
    }
    fn copy_object(
        &self,
        s: CkSessionHandle,
        object: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.inner.copy_object(s, object, template)
    }
    fn destroy_object(&self, s: CkSessionHandle, object: CkObjectHandle) -> CkResult<()> {
        self.inner.destroy_object(s, object)
    }
    fn get_object_size(&self, s: CkSessionHandle, object: CkObjectHandle) -> CkResult<u64> {
        self.inner.get_object_size(s, object)
    }
    fn set_attribute_value(
        &self,
        s: CkSessionHandle,
        object: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<()> {
        self.inner.set_attribute_value(s, object, template)
    }
    fn generate_key_pair(
        &self,
        s: CkSessionHandle,
        m: &CkMechanism,
        pub_t: &[CkAttribute],
        priv_t: &[CkAttribute],
    ) -> CkResult<(CkObjectHandle, CkObjectHandle)> {
        self.inner.generate_key_pair(s, m, pub_t, priv_t)
    }
    fn wait_for_slot_event(&self, flags: u64) -> CkResult<CkSlotId> {
        self.inner.wait_for_slot_event(flags)
    }
    fn get_operation_state(&self, s: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.inner.get_operation_state(s)
    }
    fn set_operation_state(
        &self,
        s: CkSessionHandle,
        state: &[u8],
        enc_key: CkObjectHandle,
        auth_key: CkObjectHandle,
    ) -> CkResult<()> {
        self.inner.set_operation_state(s, state, enc_key, auth_key)
    }
    fn seed_random(&self, s: CkSessionHandle, seed: &[u8]) -> CkResult<()> {
        self.inner.seed_random(s, seed)
    }
    fn generate_random(&self, s: CkSessionHandle, len: u32) -> CkResult<Vec<u8>> {
        self.inner.generate_random(s, len)
    }
    fn digest_encrypt_update(&self, s: CkSessionHandle, part: &[u8]) -> CkResult<Vec<u8>> {
        self.inner.digest_encrypt_update(s, part)
    }
    fn decrypt_digest_update(
        &self,
        s: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>> {
        self.inner.decrypt_digest_update(s, encrypted_part)
    }
    fn sign_encrypt_update(&self, s: CkSessionHandle, part: &[u8]) -> CkResult<Vec<u8>> {
        self.inner.sign_encrypt_update(s, part)
    }
    fn decrypt_verify_update(
        &self,
        s: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>> {
        self.inner.decrypt_verify_update(s, encrypted_part)
    }

    // =====================================================================
    // PKCS#11 3.0/3.2 overrides — deterministic test implementations
    // =====================================================================

    // ---- Wave 1: Session extensions ----

    fn login_user(
        &self,
        _session: CkSessionHandle,
        _user_type: CkUserType,
        _username: &[u8],
        pin: &[u8],
    ) -> CkResult<()> {
        if pin == b"1234" { Ok(()) } else { Err(CkRv::PIN_INCORRECT) }
    }

    fn session_cancel(&self, _session: CkSessionHandle, _flags: CkFlags) -> CkResult<()> {
        Ok(())
    }

    fn get_session_validation_flags(
        &self,
        _session: CkSessionHandle,
        _flags_type: u64,
    ) -> CkResult<u64> {
        Ok(0)
    }

    // ---- Wave 2: KEM ----

    fn encapsulate_key(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _public_key: CkObjectHandle,
        _template: &[CkAttribute],
    ) -> CkResult<(Vec<u8>, CkObjectHandle)> {
        Ok((vec![0xCA; 32], CkObjectHandle(9001)))
    }

    fn decapsulate_key(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _private_key: CkObjectHandle,
        _template: &[CkAttribute],
        _ciphertext: &[u8],
    ) -> CkResult<CkObjectHandle> {
        Ok(CkObjectHandle(9002))
    }

    // ---- Wave 3: Message encrypt ----

    fn message_encrypt_init(
        &self,
        _session: CkSessionHandle,
        _mechanism: Option<&CkMechanism>,
        _key: CkObjectHandle,
    ) -> CkResult<()> {
        Ok(())
    }

    fn encrypt_message(
        &self,
        _session: CkSessionHandle,
        parameter: &mut [u8],
        _aad: &[u8],
        plaintext: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ciphertext = Self::xor_aa(plaintext);
        // Return order: (parameter_out, ciphertext)
        Ok((parameter.to_vec(), ciphertext))
    }

    fn encrypt_message_begin(
        &self,
        _session: CkSessionHandle,
        parameter: &mut [u8],
        _aad: &[u8],
    ) -> CkResult<Vec<u8>> {
        Ok(parameter.to_vec())
    }

    fn encrypt_message_next(
        &self,
        _session: CkSessionHandle,
        parameter: &mut [u8],
        plaintext_part: &[u8],
        _flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ciphertext_part = Self::xor_aa(plaintext_part);
        // Return order: (parameter_out, ciphertext_part)
        Ok((parameter.to_vec(), ciphertext_part))
    }

    fn message_encrypt_final(&self, _session: CkSessionHandle) -> CkResult<()> {
        Ok(())
    }

    // ---- Wave 3: Message decrypt ----

    fn message_decrypt_init(
        &self,
        _session: CkSessionHandle,
        _mechanism: Option<&CkMechanism>,
        _key: CkObjectHandle,
    ) -> CkResult<()> {
        Ok(())
    }

    fn decrypt_message(
        &self,
        _session: CkSessionHandle,
        parameter: &mut [u8],
        _aad: &[u8],
        ciphertext: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        // XOR with 0xAA is self-inverse
        let plaintext = Self::xor_aa(ciphertext);
        // Return order: (parameter_out, plaintext)
        Ok((parameter.to_vec(), plaintext))
    }

    fn decrypt_message_begin(
        &self,
        _session: CkSessionHandle,
        parameter: &mut [u8],
        _aad: &[u8],
    ) -> CkResult<Vec<u8>> {
        Ok(parameter.to_vec())
    }

    fn decrypt_message_next(
        &self,
        _session: CkSessionHandle,
        parameter: &mut [u8],
        ciphertext_part: &[u8],
        _flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let plaintext_part = Self::xor_aa(ciphertext_part);
        // Return order: (parameter_out, plaintext_part)
        Ok((parameter.to_vec(), plaintext_part))
    }

    fn message_decrypt_final(&self, _session: CkSessionHandle) -> CkResult<()> {
        Ok(())
    }

    // ---- Wave 4: Message sign ----

    fn message_sign_init(
        &self,
        _session: CkSessionHandle,
        _mechanism: Option<&CkMechanism>,
        _key: CkObjectHandle,
    ) -> CkResult<()> {
        Ok(())
    }

    fn sign_message(
        &self,
        _session: CkSessionHandle,
        parameter: &mut [u8],
        data: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let signature = Self::reverse_sign(data);
        // Return order: (parameter_out, signature)
        Ok((parameter.to_vec(), signature))
    }

    fn sign_message_begin(
        &self,
        _session: CkSessionHandle,
        parameter: &mut [u8],
    ) -> CkResult<Vec<u8>> {
        Ok(parameter.to_vec())
    }

    fn sign_message_next(
        &self,
        _session: CkSessionHandle,
        parameter: &mut [u8],
        data_part: &[u8],
        request_signature: bool,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let signature = if request_signature { Self::reverse_sign(data_part) } else { Vec::new() };
        // Return order: (parameter_out, signature)
        Ok((parameter.to_vec(), signature))
    }

    fn message_sign_final(&self, _session: CkSessionHandle) -> CkResult<()> {
        Ok(())
    }

    // ---- Wave 4: Message verify ----

    fn message_verify_init(
        &self,
        _session: CkSessionHandle,
        _mechanism: Option<&CkMechanism>,
        _key: CkObjectHandle,
    ) -> CkResult<()> {
        Ok(())
    }

    fn verify_message(
        &self,
        _session: CkSessionHandle,
        _parameter: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> CkResult<()> {
        let expected = Self::reverse_sign(data);
        if signature == expected { Ok(()) } else { Err(CkRv::SIGNATURE_INVALID) }
    }

    fn verify_message_begin(&self, _session: CkSessionHandle, _parameter: &[u8]) -> CkResult<()> {
        Ok(())
    }

    fn verify_message_next(
        &self,
        _session: CkSessionHandle,
        _parameter: &[u8],
        data_part: &[u8],
        is_final: bool,
        signature: &[u8],
    ) -> CkResult<()> {
        if is_final {
            let expected = Self::reverse_sign(data_part);
            if signature == expected { Ok(()) } else { Err(CkRv::SIGNATURE_INVALID) }
        } else {
            Ok(())
        }
    }

    fn message_verify_final(&self, _session: CkSessionHandle) -> CkResult<()> {
        Ok(())
    }

    // ---- Wave 5: VerifySignature ----

    fn verify_signature_init(
        &self,
        _session: CkSessionHandle,
        _mechanism: Option<&CkMechanism>,
        _key: CkObjectHandle,
        signature: &[u8],
    ) -> CkResult<()> {
        let mut state = self.state_3x.lock().unwrap();
        state.stored_signature = signature.to_vec();
        state.accumulated_data.clear();
        Ok(())
    }

    fn verify_signature(&self, _session: CkSessionHandle, data: &[u8]) -> CkResult<()> {
        let state = self.state_3x.lock().unwrap();
        let expected: Vec<u8> = state.stored_signature.iter().rev().copied().collect();
        if data == expected.as_slice() { Ok(()) } else { Err(CkRv::SIGNATURE_INVALID) }
    }

    fn verify_signature_update(&self, _session: CkSessionHandle, data_part: &[u8]) -> CkResult<()> {
        let mut state = self.state_3x.lock().unwrap();
        state.accumulated_data.extend_from_slice(data_part);
        Ok(())
    }

    fn verify_signature_final(&self, _session: CkSessionHandle) -> CkResult<()> {
        let state = self.state_3x.lock().unwrap();
        let expected: Vec<u8> = state.stored_signature.iter().rev().copied().collect();
        if state.accumulated_data == expected { Ok(()) } else { Err(CkRv::SIGNATURE_INVALID) }
    }

    // ---- Wave 5: Authenticated wrap/unwrap ----

    fn wrap_key_authenticated(
        &self,
        _session: CkSessionHandle,
        _mechanism: &CkMechanism,
        _wrapping_key: CkObjectHandle,
        _key: CkObjectHandle,
        _aad: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        Ok((vec![0xBB; 16], vec![0xCC; 12]))
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
        Ok((CkObjectHandle(9003), vec![0xCC; 12]))
    }

    // ---- Wave 5: Async (Option B) ----

    fn async_complete(
        &self,
        _session: CkSessionHandle,
        _function_name: &str,
    ) -> CkResult<(u64, Vec<u8>, u64, CkObjectHandle, CkObjectHandle)> {
        Ok((1, vec![0xA5; 8], 8, CkObjectHandle(0), CkObjectHandle(0)))
    }

    // async_get_id and async_join use the trait defaults:
    // - async_get_id → Err(CKR_STATE_UNSAVEABLE)
    // - async_join   → Err(CKR_SAVED_STATE_INVALID)

    // ---- BUG-001: Interface version transparency ----

    fn get_interface_capabilities(&self) -> InterfaceCapabilities {
        InterfaceCapabilities {
            interfaces: vec![
                InterfaceInfo { version_major: 2, version_minor: 40, null_functions: vec![] },
                InterfaceInfo { version_major: 3, version_minor: 0, null_functions: vec![] },
                InterfaceInfo { version_major: 3, version_minor: 2, null_functions: vec![] },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_user_correct_pin() {
        let backend = TestBackend3x::default_test();
        backend.initialize().unwrap();
        let result = backend.login_user(CkSessionHandle(1), CkUserType::User, b"alice", b"1234");
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn login_user_wrong_pin() {
        let backend = TestBackend3x::default_test();
        backend.initialize().unwrap();
        let result = backend.login_user(CkSessionHandle(1), CkUserType::User, b"alice", b"wrong");
        assert_eq!(result, Err(CkRv::PIN_INCORRECT));
    }

    #[test]
    fn session_cancel_always_ok() {
        let backend = TestBackend3x::default_test();
        let result = backend.session_cancel(CkSessionHandle(1), CkFlags(0));
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn get_session_validation_flags_returns_zero() {
        let backend = TestBackend3x::default_test();
        let result = backend.get_session_validation_flags(CkSessionHandle(1), 0);
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn encapsulate_key_returns_synthetic() {
        let backend = TestBackend3x::default_test();
        let mech = CkMechanism { mechanism_type: CkMechanismType(1), params: None };
        let (capsule, key) =
            backend.encapsulate_key(CkSessionHandle(1), &mech, CkObjectHandle(1), &[]).unwrap();
        assert_eq!(capsule, vec![0xCA; 32]);
        assert_eq!(key, CkObjectHandle(9001));
    }

    #[test]
    fn decapsulate_key_returns_synthetic() {
        let backend = TestBackend3x::default_test();
        let mech = CkMechanism { mechanism_type: CkMechanismType(1), params: None };
        let key = backend
            .decapsulate_key(CkSessionHandle(1), &mech, CkObjectHandle(1), &[], &[0xCA; 32])
            .unwrap();
        assert_eq!(key, CkObjectHandle(9002));
    }

    #[test]
    fn message_encrypt_decrypt_round_trip() {
        let backend = TestBackend3x::default_test();
        let plaintext = b"hello world";
        let mut param = vec![0u8; 4];

        let (_param_out, ciphertext) =
            backend.encrypt_message(CkSessionHandle(1), &mut param, &[], plaintext).unwrap();
        assert_ne!(ciphertext, plaintext.to_vec());

        let mut param2 = vec![0u8; 4];
        let (_param_out, recovered) =
            backend.decrypt_message(CkSessionHandle(1), &mut param2, &[], &ciphertext).unwrap();
        assert_eq!(recovered, plaintext.to_vec());
    }

    #[test]
    fn message_sign_verify_round_trip() {
        let backend = TestBackend3x::default_test();
        let data = b"test data";
        let mut param = vec![0u8; 4];

        let (_param_out, signature) =
            backend.sign_message(CkSessionHandle(1), &mut param, data).unwrap();

        let result = backend.verify_message(CkSessionHandle(1), &param, data, &signature);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn verify_signature_single_part() {
        let backend = TestBackend3x::default_test();
        let data = b"abcdef";
        let signature: Vec<u8> = data.iter().rev().copied().collect(); // reverse

        backend
            .verify_signature_init(CkSessionHandle(1), None, CkObjectHandle(1), &signature)
            .unwrap();

        // data should match signature reversed
        let result = backend.verify_signature(CkSessionHandle(1), data);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn verify_signature_multi_part() {
        let backend = TestBackend3x::default_test();
        let data = b"abcdef";
        let signature: Vec<u8> = data.iter().rev().copied().collect();

        backend
            .verify_signature_init(CkSessionHandle(1), None, CkObjectHandle(1), &signature)
            .unwrap();

        backend.verify_signature_update(CkSessionHandle(1), b"abc").unwrap();
        backend.verify_signature_update(CkSessionHandle(1), b"def").unwrap();

        let result = backend.verify_signature_final(CkSessionHandle(1));
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn async_complete_returns_data() {
        let backend = TestBackend3x::default_test();
        let (version, value, value_len, h1, h2) =
            backend.async_complete(CkSessionHandle(1), "C_Sign").unwrap();
        assert_eq!(version, 1);
        assert_eq!(value, vec![0xA5; 8]);
        assert_eq!(value_len, 8);
        assert_eq!(h1, CkObjectHandle(0));
        assert_eq!(h2, CkObjectHandle(0));
    }

    #[test]
    fn async_get_id_returns_state_unsaveable() {
        let backend = TestBackend3x::default_test();
        let result = backend.async_get_id(CkSessionHandle(1), "C_Sign");
        assert_eq!(result, Err(CkRv::STATE_UNSAVEABLE));
    }

    #[test]
    fn async_join_returns_saved_state_invalid() {
        let backend = TestBackend3x::default_test();
        let result = backend.async_join(CkSessionHandle(1), "C_Sign", 0, 256);
        assert_eq!(result, Err(CkRv::SAVED_STATE_INVALID));
    }
}
