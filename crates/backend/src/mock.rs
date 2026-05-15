// crates/backend/src/mock.rs
use crate::traits::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;
use std::collections::HashMap;
use std::sync::Mutex;

mod crypto_ops;
mod mock_types;
mod object_ops;
mod session_ops;
mod state;

pub use self::mock_types::{MockAttributeSlot, MultiPartOp};
use self::state::{MockState, compute_session_state};

/// A mock PKCS#11 backend for unit testing the daemon without loading any real module.
///
/// **Known limitations (by design — expand as test coverage requires):**
/// - `find_objects_*` have no state machine; out-of-order calls are not detected.
/// - `sign`/`verify` return fixed stub bytes; cannot test signature-length-sensitive paths.
/// - `wait_for_slot_event` with flags=0 (blocking) behaves as non-blocking.
///   Real blocking semantics would require a thread/condvar and are out of scope for the mock.
///
/// **Attribute simulation** (`get_attribute_value`):
/// By default returns `Ok(())` without modifying the template.  Call `set_attribute` to
/// register attribute values or error slots for a specific object handle; `get_attribute_value`
/// will then respond according to the registry.
///
/// **Slot event simulation** (`wait_for_slot_event`):
/// By default, no events are pending. Call `enqueue_slot_event(slot)` to enqueue a slot
/// event; the next call to `wait_for_slot_event` will dequeue and return it.
///
/// **Operation-state export/import** (`get_operation_state` / `set_operation_state`):
/// `get_operation_state` returns a 3-byte blob [0xC9, 0xEA, op_type] when an operation is
/// active, or `CKR_OPERATION_NOT_INITIALIZED` when none is active.
/// `set_operation_state` accepts a previously exported blob and restores the operation into
/// the target session (which must have no active operation).  Invalid or empty blobs return
/// `CKR_SAVED_STATE_INVALID`.
///
/// **Quota enforcement** (`max_sessions`, `max_objects`):
/// When non-zero, these fields cap the number of concurrent open sessions and live objects.
/// Exceeding the session cap returns `CKR_SESSION_COUNT`; exceeding the object cap returns
/// `CKR_DEVICE_MEMORY`.  Both quotas default to 0 (unlimited).  Use `with_quotas()` to
/// configure limits in tests that validate exhaustion behavior.
///
/// **Large-request cap** (`generate_random`):
/// Requests for more than `MAX_RANDOM_BYTES` (65 536) bytes return `CKR_DATA_LEN_RANGE`.
pub struct MockBackend {
    pub slots: Vec<CkSlotId>,
    pub mechanisms: Vec<CkMechanismType>,
    /// Session count cap (0 = unlimited).  `open_session` returns `CKR_SESSION_COUNT` when
    /// the number of open sessions would exceed this value.
    pub max_sessions: u64,
    /// Object count cap (0 = unlimited).  `create_object` / `copy_object` return
    /// `CKR_DEVICE_MEMORY` when the number of live objects would exceed this value.
    pub max_objects: u64,
    state: Mutex<MockState>,
    /// object_handle → (attr_type → slot)
    attribute_store: Mutex<HashMap<u64, HashMap<u64, MockAttributeSlot>>>,
    /// Pending slot events (FIFO queue). Drained by wait_for_slot_event.
    slot_event_queue: Mutex<std::collections::VecDeque<CkSlotId>>,
    /// Per-slot token presence override. Slots not present in this map default
    /// to token-present to preserve the historical mock behavior.
    token_presence: Mutex<HashMap<CkSlotId, bool>>,
    /// Per-slot mechanism list override. Slots without an override use the
    /// global `mechanisms` list to preserve the historical mock behavior.
    slot_mechanisms: Mutex<HashMap<CkSlotId, Vec<CkMechanismType>>>,
    /// Injected error: if set, most backend operations return this error instead of
    /// proceeding normally.  Used to simulate backend failures such as device removal,
    /// token-not-present, or device errors.  Set via `inject_error()`, clear via
    /// `clear_error()`.
    injected_error: Mutex<Option<CkRv>>,
    /// Optional mechanism parameters to return from `C_EncryptInit`.
    ///
    /// Real providers may mutate selected init parameters, for example by
    /// generating an AES-GCM IV into a caller-supplied buffer. Tests can set
    /// this hook to exercise the proxy's output-parameter path without loading
    /// a real PKCS#11 module.
    encrypt_init_output: Mutex<Option<CkMechanismParams>>,
    /// Optional mechanism parameters to return from exact `C_Encrypt` data calls.
    ///
    /// This simulates providers that retain `CK_GCM_PARAMS` from
    /// `C_EncryptInit` and only populate its output IV during `C_Encrypt`.
    encrypt_exact_output: Mutex<Option<CkMechanismParams>>,
    /// Interface capabilities to report. If `None`, uses the default
    /// (v2.40 only, no NULL functions).
    interface_capabilities: Mutex<Option<InterfaceCapabilities>>,
}

impl MockBackend {
    /// Maximum bytes that `generate_random` will return in a single call.
    /// Larger requests return `CKR_DATA_LEN_RANGE`.
    pub const MAX_RANDOM_BYTES: u32 = 65_536;

    pub fn new(slots: Vec<CkSlotId>, mechanisms: Vec<CkMechanismType>) -> Self {
        Self {
            slots,
            mechanisms,
            max_sessions: 0,
            max_objects: 0,
            state: Mutex::new(MockState {
                initialized: false,
                next_session: 1,
                next_object: 1,
                open_sessions: Vec::new(),
                login_state: HashMap::new(),
                live_objects: std::collections::HashSet::new(),
                active_ops: HashMap::new(),
            }),
            slot_event_queue: Mutex::new(std::collections::VecDeque::new()),
            token_presence: Mutex::new(HashMap::new()),
            slot_mechanisms: Mutex::new(HashMap::new()),
            attribute_store: Mutex::new(HashMap::new()),
            injected_error: Mutex::new(None),
            encrypt_init_output: Mutex::new(None),
            encrypt_exact_output: Mutex::new(None),
            interface_capabilities: Mutex::new(None),
        }
    }

    /// Register an attribute slot for a specific object handle.
    ///
    /// When `get_attribute_value` is called for `object` and `attr_type` is in the template,
    /// the response will follow `slot`:
    /// - `Value(v)` → fills the template entry with `v`.
    /// - `Sensitive` → leaves value as `None`, contributes `CKR_ATTRIBUTE_SENSITIVE`.
    /// - `InvalidType` → leaves value as `None`, contributes `CKR_ATTRIBUTE_TYPE_INVALID`.
    ///
    /// Attribute types NOT in the store (for a registered object) return `InvalidType`.
    /// Objects NOT in the store at all use the default no-op behavior (Ok, no template change).
    pub fn set_attribute(
        &self,
        object: CkObjectHandle,
        attr_type: CkAttributeType,
        slot: MockAttributeSlot,
    ) {
        let mut store = self.attribute_store.lock().unwrap();
        store.entry(object.0).or_default().insert(attr_type.0, slot);
    }

    /// Enqueue a slot event to be returned by the next `wait_for_slot_event` call.
    ///
    /// Events are returned FIFO. If multiple events are queued, each call to
    /// `wait_for_slot_event` returns one.
    pub fn enqueue_slot_event(&self, slot: CkSlotId) {
        self.slot_event_queue.lock().unwrap().push_back(slot);
    }

    /// Configure whether a token is present in a known slot.
    ///
    /// This lets tests model insertion/removal without changing the default
    /// mock behavior where all configured slots have a token present.
    pub fn set_token_present(&self, slot_id: CkSlotId, present: bool) {
        self.token_presence.lock().unwrap().insert(slot_id, present);
    }

    /// Configure a slot-specific mechanism list.
    ///
    /// Slots without an override continue to use the mock's global mechanism
    /// list, preserving existing tests that do not care about per-slot policy.
    pub fn set_slot_mechanisms(&self, slot_id: CkSlotId, mechanisms: Vec<CkMechanismType>) {
        self.slot_mechanisms.lock().unwrap().insert(slot_id, mechanisms);
    }

    /// Simple default mock with one slot and common mechanisms.
    pub fn default_test() -> Self {
        Self::new(
            vec![CkSlotId(0)],
            vec![
                CkMechanismType::RSA_PKCS,
                CkMechanismType::SHA256_RSA_PKCS,
                CkMechanismType::ECDSA,
                CkMechanismType::RSA_PKCS_KEY_PAIR_GEN,
                CkMechanismType::EC_KEY_PAIR_GEN,
            ],
        )
    }

    /// Inject an error that most backend operations will return instead of
    /// proceeding normally.  Simulates device removal, token-not-present, etc.
    pub fn inject_error(&self, rv: CkRv) {
        *self.injected_error.lock().unwrap() = Some(rv);
    }

    /// Clear any previously injected error.
    pub fn clear_error(&self) {
        *self.injected_error.lock().unwrap() = None;
    }

    /// Configure optional mechanism parameters returned by `encrypt_init`.
    pub fn set_encrypt_init_output(&self, output: Option<CkMechanismParams>) {
        *self.encrypt_init_output.lock().unwrap() = output;
    }

    /// Configure optional mechanism parameters returned by exact `C_Encrypt` data calls.
    pub fn set_encrypt_exact_output(&self, output: Option<CkMechanismParams>) {
        *self.encrypt_exact_output.lock().unwrap() = output;
    }

    /// Configure the interface capabilities reported by this mock backend.
    ///
    /// Used to test shim behavior with backends of different versions.
    pub fn set_interface_capabilities(&self, caps: InterfaceCapabilities) {
        *self.interface_capabilities.lock().unwrap() = Some(caps);
    }

    /// If an error is injected, return Err(rv); otherwise Ok(()).
    fn check_injected(&self) -> CkResult<()> {
        match *self.injected_error.lock().unwrap() {
            Some(rv) => Err(rv),
            None => Ok(()),
        }
    }

    /// Builder: set session and object quotas.
    ///
    /// `max_sessions`: maximum number of concurrently open sessions (0 = unlimited).
    /// `max_objects`:  maximum number of live objects (0 = unlimited).
    pub fn with_quotas(mut self, max_sessions: u64, max_objects: u64) -> Self {
        self.max_sessions = max_sessions;
        self.max_objects = max_objects;
        self
    }

    fn allocate_object(&self, state: &mut MockState) -> CkResult<CkObjectHandle> {
        if self.max_objects > 0 && state.live_objects.len() as u64 >= self.max_objects {
            return Err(CkRv::DEVICE_MEMORY);
        }
        let handle = CkObjectHandle(state.next_object);
        state.next_object += 1;
        state.live_objects.insert(handle.0);
        Ok(handle)
    }

    fn require_live_object(&self, state: &MockState, object: CkObjectHandle) -> CkResult<()> {
        if state.live_objects.contains(&object.0) {
            Ok(())
        } else {
            Err(CkRv::OBJECT_HANDLE_INVALID)
        }
    }

    fn xor_bytes(data: &[u8]) -> Vec<u8> {
        data.iter().map(|byte| byte ^ 0x42).collect()
    }

    fn require_known_slot(&self, slot_id: CkSlotId) -> CkResult<()> {
        if self.slots.contains(&slot_id) { Ok(()) } else { Err(CkRv::SLOT_ID_INVALID) }
    }

    fn token_present_for_slot(&self, slot_id: CkSlotId) -> bool {
        self.token_presence.lock().unwrap().get(&slot_id).copied().unwrap_or(true)
    }

    fn require_token_present(&self, slot_id: CkSlotId) -> CkResult<()> {
        if self.token_present_for_slot(slot_id) { Ok(()) } else { Err(CkRv::TOKEN_NOT_PRESENT) }
    }

    fn mechanisms_for_slot(&self, slot_id: CkSlotId) -> Vec<CkMechanismType> {
        self.slot_mechanisms
            .lock()
            .unwrap()
            .get(&slot_id)
            .cloned()
            .unwrap_or_else(|| self.mechanisms.clone())
    }

    fn allocate_object_locked(&self) -> CkResult<CkObjectHandle> {
        let mut state = self.state.lock().unwrap();
        self.allocate_object(&mut state)
    }
}

impl Pkcs11Backend for MockBackend {
    fn initialize(&self) -> CkResult<()> {
        self.initialize_backend()
    }

    fn finalize(&self) -> CkResult<()> {
        self.finalize_backend()
    }

    fn get_info(&self) -> CkResult<CkInfo> {
        self.backend_info()
    }

    fn get_slot_list(&self, token_present: bool) -> CkResult<Vec<CkSlotId>> {
        self.slot_list_for_presence(token_present)
    }

    fn get_slot_info(&self, slot_id: CkSlotId) -> CkResult<CkSlotInfo> {
        self.slot_info(slot_id)
    }

    fn get_token_info(&self, slot_id: CkSlotId) -> CkResult<CkTokenInfo> {
        self.token_info(slot_id)
    }

    fn get_mechanism_list(&self, slot_id: CkSlotId) -> CkResult<Vec<CkMechanismType>> {
        self.mechanism_list(slot_id)
    }

    fn get_mechanism_info(
        &self,
        slot_id: CkSlotId,
        mech: CkMechanismType,
    ) -> CkResult<CkMechanismInfo> {
        self.mechanism_info(slot_id, mech)
    }

    fn init_token(&self, _slot_id: CkSlotId, _so_pin: Option<&[u8]>, _label: &str) -> CkResult<()> {
        self.noop_ok()
    }

    fn init_pin(&self, _session: CkSessionHandle, _pin: Option<&[u8]>) -> CkResult<()> {
        self.noop_ok()
    }

    fn set_pin(
        &self,
        _session: CkSessionHandle,
        _old_pin: Option<&[u8]>,
        _new_pin: Option<&[u8]>,
    ) -> CkResult<()> {
        self.noop_ok()
    }

    fn open_session(&self, slot_id: CkSlotId, flags: CkSessionFlags) -> CkResult<CkSessionHandle> {
        self.open_session_impl(slot_id, flags)
    }

    fn close_session(&self, session: CkSessionHandle) -> CkResult<()> {
        self.close_session_impl(session)
    }

    fn close_all_sessions(&self, slot_id: CkSlotId) -> CkResult<()> {
        self.close_all_sessions_impl(slot_id)
    }

    fn get_session_info(&self, session: CkSessionHandle) -> CkResult<CkSessionInfo> {
        self.session_info(session)
    }

    fn login(
        &self,
        session: CkSessionHandle,
        user_type: CkUserType,
        _pin: Option<&[u8]>,
    ) -> CkResult<()> {
        self.login_impl(session, user_type)
    }

    fn logout(&self, session: CkSessionHandle) -> CkResult<()> {
        self.logout_impl(session)
    }
    fn find_objects_init(&self, _s: CkSessionHandle, _t: &[CkAttribute]) -> CkResult<()> {
        self.find_objects_init_impl()
    }
    fn find_objects(&self, _s: CkSessionHandle, _m: u32) -> CkResult<Vec<CkObjectHandle>> {
        self.find_objects_impl()
    }
    fn find_objects_final(&self, _s: CkSessionHandle) -> CkResult<()> {
        self.find_objects_final_impl()
    }
    fn get_attribute_value(
        &self,
        _s: CkSessionHandle,
        object: CkObjectHandle,
        template: &mut [CkAttribute],
    ) -> CkResult<()> {
        self.get_attribute_value_impl(object, template)
    }
    fn get_attribute_value_exact(
        &self,
        _s: CkSessionHandle,
        object: CkObjectHandle,
        queries: &[CkAttributeQuery],
    ) -> CkResult<(CkRv, Vec<CkAttributeQueryResult>)> {
        self.get_attribute_value_exact_impl(object, queries)
    }
    fn sign_init(&self, s: CkSessionHandle, _m: &CkMechanism, _k: CkObjectHandle) -> CkResult<()> {
        self.sign_init_impl(s)
    }
    fn sign(&self, s: CkSessionHandle, _d: &[u8]) -> CkResult<Vec<u8>> {
        self.sign_impl(s)
    }
    fn sign_update(&self, s: CkSessionHandle, _p: &[u8]) -> CkResult<()> {
        self.sign_update_impl(s)
    }
    fn sign_final(&self, s: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.sign_final_impl(s)
    }
    fn sign_recover_init(
        &self,
        _s: CkSessionHandle,
        _m: &CkMechanism,
        _k: CkObjectHandle,
    ) -> CkResult<()> {
        Ok(())
    }
    fn sign_recover(&self, _s: CkSessionHandle, _d: &[u8]) -> CkResult<Vec<u8>> {
        Ok(vec![0xDE, 0xAD])
    }
    fn verify_recover_init(
        &self,
        _s: CkSessionHandle,
        _m: &CkMechanism,
        _k: CkObjectHandle,
    ) -> CkResult<()> {
        Ok(())
    }
    fn verify_recover(&self, _s: CkSessionHandle, _sig: &[u8]) -> CkResult<Vec<u8>> {
        self.verify_recover_impl()
    }

    fn verify_init(
        &self,
        s: CkSessionHandle,
        _m: &CkMechanism,
        _k: CkObjectHandle,
    ) -> CkResult<()> {
        self.verify_init_impl(s)
    }
    fn verify(&self, s: CkSessionHandle, _d: &[u8], _sig: &[u8]) -> CkResult<()> {
        self.verify_impl(s)
    }
    fn verify_update(&self, s: CkSessionHandle, _p: &[u8]) -> CkResult<()> {
        self.verify_update_impl(s)
    }
    fn verify_final(&self, s: CkSessionHandle, _sig: &[u8]) -> CkResult<()> {
        self.verify_final_impl(s)
    }
    fn digest_init(&self, s: CkSessionHandle, _m: &CkMechanism) -> CkResult<()> {
        self.digest_init_impl(s)
    }
    fn digest(&self, s: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        self.digest_impl(s, data)
    }
    fn digest_update(&self, s: CkSessionHandle, _p: &[u8]) -> CkResult<()> {
        self.digest_update_impl(s)
    }
    fn digest_key(&self, s: CkSessionHandle, _k: CkObjectHandle) -> CkResult<()> {
        self.digest_key_impl(s)
    }
    fn digest_final(&self, s: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.digest_final_impl(s)
    }
    fn encrypt_init(
        &self,
        s: CkSessionHandle,
        _m: &CkMechanism,
        _k: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>> {
        self.encrypt_init_impl(s)?;
        Ok(self.encrypt_init_output.lock().unwrap().clone())
    }
    fn encrypt(&self, s: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        self.encrypt_impl(s, data)
    }
    fn encrypt_update(&self, s: CkSessionHandle, part: &[u8]) -> CkResult<Vec<u8>> {
        self.encrypt_update_impl(s, part)
    }
    fn encrypt_final(&self, s: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.encrypt_final_impl(s)
    }
    fn decrypt_init(
        &self,
        s: CkSessionHandle,
        _m: &CkMechanism,
        _k: CkObjectHandle,
    ) -> CkResult<()> {
        self.decrypt_init_impl(s)
    }
    fn decrypt(&self, s: CkSessionHandle, encrypted_data: &[u8]) -> CkResult<Vec<u8>> {
        self.decrypt_impl(s, encrypted_data)
    }
    fn decrypt_update(&self, s: CkSessionHandle, encrypted_part: &[u8]) -> CkResult<Vec<u8>> {
        self.decrypt_update_impl(s, encrypted_part)
    }
    fn decrypt_final(&self, s: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.decrypt_final_impl(s)
    }
    fn derive_key(
        &self,
        _s: CkSessionHandle,
        _m: &CkMechanism,
        _base_key: CkObjectHandle,
        _template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.derive_key_impl()
    }
    fn wrap_key(
        &self,
        _s: CkSessionHandle,
        _m: &CkMechanism,
        _wrapping_key: CkObjectHandle,
        _key: CkObjectHandle,
    ) -> CkResult<Vec<u8>> {
        self.wrap_key_impl()
    }
    fn unwrap_key(
        &self,
        _s: CkSessionHandle,
        _m: &CkMechanism,
        _unwrapping_key: CkObjectHandle,
        _wrapped_key: &[u8],
        _template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.unwrap_key_impl()
    }
    fn generate_key(
        &self,
        _s: CkSessionHandle,
        _m: &CkMechanism,
        _template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.generate_key_impl()
    }
    fn create_object(
        &self,
        _s: CkSessionHandle,
        _template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.create_object_impl()
    }
    fn copy_object(
        &self,
        _s: CkSessionHandle,
        _object: CkObjectHandle,
        _template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.copy_object_impl()
    }
    fn destroy_object(&self, _s: CkSessionHandle, object: CkObjectHandle) -> CkResult<()> {
        self.destroy_object_impl(object)
    }
    fn get_object_size(&self, _s: CkSessionHandle, object: CkObjectHandle) -> CkResult<u64> {
        self.object_size(object)
    }
    fn set_attribute_value(
        &self,
        _s: CkSessionHandle,
        object: CkObjectHandle,
        _template: &[CkAttribute],
    ) -> CkResult<()> {
        self.set_attribute_value_impl(object)
    }
    fn generate_key_pair(
        &self,
        _s: CkSessionHandle,
        _m: &CkMechanism,
        _pub: &[CkAttribute],
        _priv: &[CkAttribute],
    ) -> CkResult<(CkObjectHandle, CkObjectHandle)> {
        self.generate_key_pair_impl()
    }
    fn wait_for_slot_event(&self, _flags: u64) -> CkResult<CkSlotId> {
        self.wait_for_slot_event_impl()
    }

    fn get_operation_state(&self, s: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.operation_state(s)
    }

    fn set_operation_state(
        &self,
        s: CkSessionHandle,
        state: &[u8],
        _enc_key: CkObjectHandle,
        _auth_key: CkObjectHandle,
    ) -> CkResult<()> {
        self.restore_operation_state(s, state)
    }

    fn seed_random(&self, _s: CkSessionHandle, _seed: &[u8]) -> CkResult<()> {
        self.seed_random_impl()
    }

    fn generate_random(&self, _s: CkSessionHandle, len: u32) -> CkResult<Vec<u8>> {
        self.generate_random_impl(len)
    }

    // --- Exact byte-output trait methods (Track B) ---

    fn sign_exact(
        &self,
        s: CkSessionHandle,
        _data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.sign_exact_impl(s, spec)
    }

    fn sign_final_exact(
        &self,
        s: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.sign_final_exact_impl(s, spec)
    }

    fn sign_recover_exact(
        &self,
        _s: CkSessionHandle,
        _data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.sign_recover_exact_impl(spec)
    }

    fn verify_recover_exact(
        &self,
        _s: CkSessionHandle,
        _signature: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.verify_recover_exact_impl(spec)
    }

    fn digest_exact(
        &self,
        s: CkSessionHandle,
        data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.digest_exact_impl(s, data, spec)
    }

    fn digest_final_exact(
        &self,
        s: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.digest_final_exact_impl(s, spec)
    }

    fn encrypt_exact(
        &self,
        s: CkSessionHandle,
        data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.encrypt_exact_impl(s, data, spec)
    }

    fn encrypt_exact_with_output(
        &self,
        s: CkSessionHandle,
        data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, Option<CkMechanismParams>)> {
        let result = self.encrypt_exact_impl(s, data, spec)?;
        let output = if spec.buffer_present && result.ck_rv == CkRv::OK {
            self.encrypt_exact_output.lock().unwrap().clone()
        } else {
            None
        };
        Ok((result, output))
    }

    fn encrypt_update_exact(
        &self,
        s: CkSessionHandle,
        part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.encrypt_update_exact_impl(s, part, spec)
    }

    fn encrypt_final_exact(
        &self,
        s: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.encrypt_final_exact_impl(s, spec)
    }

    fn decrypt_exact(
        &self,
        s: CkSessionHandle,
        encrypted_data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.decrypt_exact_impl(s, encrypted_data, spec)
    }

    fn decrypt_update_exact(
        &self,
        s: CkSessionHandle,
        encrypted_part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.decrypt_update_exact_impl(s, encrypted_part, spec)
    }

    fn decrypt_final_exact(
        &self,
        s: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.decrypt_final_exact_impl(s, spec)
    }

    fn digest_encrypt_update_exact(
        &self,
        _s: CkSessionHandle,
        part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.digest_encrypt_update_exact_impl(part, spec)
    }

    fn decrypt_digest_update_exact(
        &self,
        _s: CkSessionHandle,
        encrypted_part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.decrypt_digest_update_exact_impl(encrypted_part, spec)
    }

    fn sign_encrypt_update_exact(
        &self,
        _s: CkSessionHandle,
        part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.sign_encrypt_update_exact_impl(part, spec)
    }

    fn decrypt_verify_update_exact(
        &self,
        _s: CkSessionHandle,
        encrypted_part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.decrypt_verify_update_exact_impl(encrypted_part, spec)
    }

    fn wrap_key_exact(
        &self,
        _s: CkSessionHandle,
        _mechanism: &CkMechanism,
        _wrapping_key: CkObjectHandle,
        _key: CkObjectHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.wrap_key_exact_impl(spec)
    }

    fn get_operation_state_exact(
        &self,
        s: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.get_operation_state_exact_impl(s, spec)
    }

    // --- KEM convenience method ---

    fn encapsulate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        public_key: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<(Vec<u8>, CkObjectHandle)> {
        self.encapsulate_key_impl(session, mechanism, public_key, template)
    }

    // --- Track C Task 2: Exact KEM trait method ---

    fn encapsulate_key_exact(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        public_key: CkObjectHandle,
        template: &[CkAttribute],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputAndHandleResult> {
        let (ciphertext, key_handle) =
            self.encapsulate_key(session, mechanism, public_key, template)?;
        let output = CkOutputBufferResult::from_convenience_bytes(&ciphertext, spec);
        // Per PKCS#11 spec: the key is only created when the ciphertext buffer
        // is present and large enough (data query succeeds).  On a size query
        // (NULL buffer) or buffer-too-small, no key is created.
        let data_written = output.value.is_some();
        Ok(CkOutputAndHandleResult {
            ck_rv: output.ck_rv,
            returned_len: output.returned_len,
            value: output.value,
            object_handle: if data_written { key_handle } else { CkObjectHandle(0) },
        })
    }

    // --- Track C: Exact parameter-output trait methods ---

    fn encrypt_message_exact(
        &self,
        s: CkSessionHandle,
        parameter: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.encrypt_message_exact_impl(s, parameter, aad, plaintext, output_spec, param_out_spec)
    }

    fn decrypt_message_exact(
        &self,
        s: CkSessionHandle,
        parameter: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.decrypt_message_exact_impl(s, parameter, aad, ciphertext, output_spec, param_out_spec)
    }

    fn sign_message_exact(
        &self,
        s: CkSessionHandle,
        parameter: &[u8],
        data: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.sign_message_exact_impl(s, parameter, data, output_spec, param_out_spec)
    }

    fn encrypt_message_next_exact(
        &self,
        s: CkSessionHandle,
        parameter: &[u8],
        plaintext_part: &[u8],
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.encrypt_message_next_exact_impl(
            s,
            parameter,
            plaintext_part,
            flags,
            output_spec,
            param_out_spec,
        )
    }

    fn decrypt_message_next_exact(
        &self,
        s: CkSessionHandle,
        parameter: &[u8],
        ciphertext_part: &[u8],
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.decrypt_message_next_exact_impl(
            s,
            parameter,
            ciphertext_part,
            flags,
            output_spec,
            param_out_spec,
        )
    }

    fn sign_message_next_exact(
        &self,
        s: CkSessionHandle,
        parameter: &[u8],
        data_part: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.sign_message_next_exact_impl(s, parameter, data_part, output_spec, param_out_spec)
    }

    fn wrap_key_authenticated_exact(
        &self,
        _s: CkSessionHandle,
        _mechanism: &CkMechanism,
        _wrapping_key: CkObjectHandle,
        _key: CkObjectHandle,
        _aad: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.wrap_key_authenticated_exact_impl(output_spec, param_out_spec)
    }

    fn digest_encrypt_update(&self, _s: CkSessionHandle, part: &[u8]) -> CkResult<Vec<u8>> {
        self.combined_update(part)
    }

    fn decrypt_digest_update(
        &self,
        _s: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>> {
        self.combined_update(encrypted_part)
    }

    fn sign_encrypt_update(&self, _s: CkSessionHandle, part: &[u8]) -> CkResult<Vec<u8>> {
        self.combined_update(part)
    }

    fn decrypt_verify_update(
        &self,
        _s: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>> {
        self.combined_update(encrypted_part)
    }

    fn get_interface_capabilities(&self) -> InterfaceCapabilities {
        if let Some(caps) = self.interface_capabilities.lock().unwrap().as_ref() {
            return caps.clone();
        }
        // Default: v2.40 only, no NULL functions
        InterfaceCapabilities {
            interfaces: vec![InterfaceInfo {
                version_major: 2,
                version_minor: 40,
                null_functions: vec![],
            }],
        }
    }
}

#[cfg(test)]
mod tests;
