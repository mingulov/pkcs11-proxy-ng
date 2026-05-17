// crates/backend/src/mock.rs
use crate::traits::{CkDeriveKeyOutputResult, Pkcs11Backend};
use pkcs11_proxy_ng_proto::convert::message_params::MessageParameter;
use pkcs11_proxy_ng_types::*;
use std::collections::HashMap;
use std::sync::{Condvar, Mutex};

mod crypto_ops;
mod mock_types;
mod object_ops;
mod session_ops;
mod state;

pub use self::mock_types::{MockAttributeSlot, MultiPartOp};
use self::state::{MockState, compute_session_state};

const CK_SP800_108_KEY_HANDLE: u64 = 0x0000_0005;
const CK_SP800_108_ITERATION_VARIABLE: u64 = 0x0000_0001;
const CK_SP800_108_COUNTER: u64 = 0x0000_0002;
const CK_SP800_108_DKM_LENGTH: u64 = 0x0000_0003;
const CK_SP800_108_BYTE_ARRAY: u64 = 0x0000_0004;
const CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS: u64 = 0x0000_0001;
const CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS: u64 = 0x0000_0002;
const CKM_SP800_108_COUNTER_KDF: u64 = 0x0000_03AC;
// OASIS SP800-108 lists PRF mechanisms explicitly; plain digest mechanisms are not PRFs.
const CKM_DES3_CMAC: u64 = 0x0000_0138;
const CKM_SHA_1_HMAC: u64 = 0x0000_0221;
const CKM_SHA224_HMAC: u64 = 0x0000_0256;
const CKM_SHA256_HMAC: u64 = 0x0000_0251;
const CKM_SHA384_HMAC: u64 = 0x0000_0261;
const CKM_SHA512_HMAC: u64 = 0x0000_0271;
const CKM_SHA3_224_HMAC: u64 = 0x0000_02B6;
const CKM_SHA3_256_HMAC: u64 = 0x0000_02B1;
const CKM_SHA3_384_HMAC: u64 = 0x0000_02C1;
const CKM_SHA3_512_HMAC: u64 = 0x0000_02D1;
const CKM_AES_CMAC: u64 = 0x0000_108A;
const CK_SP800_108_COUNTER_FORMAT_LEN: usize =
    std::mem::size_of::<cryptoki_sys::CK_SP800_108_COUNTER_FORMAT>();
const CK_SP800_108_DKM_LENGTH_FORMAT_LEN: usize =
    std::mem::size_of::<cryptoki_sys::CK_SP800_108_DKM_LENGTH_FORMAT>();

/// A mock PKCS#11 backend for unit testing the daemon without loading any real module.
///
/// **Known limitations (by design — expand as test coverage requires):**
/// - `sign`/`verify` return fixed stub bytes; cannot test signature-length-sensitive paths.
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
    slot_event_condvar: Condvar,
    /// Per-slot token presence override. Slots not present in this map default
    /// to token-present to preserve the historical mock behavior.
    token_presence: Mutex<HashMap<CkSlotId, bool>>,
    /// Per-slot mechanism list override. Slots without an override use the
    /// global `mechanisms` list to preserve the historical mock behavior.
    slot_mechanisms: Mutex<HashMap<CkSlotId, Vec<CkMechanismType>>>,
    /// When set, advertised mechanisms are also checked against source-grounded
    /// `CK_MECHANISM_INFO` workflow flags before mechanism-bearing operations
    /// are accepted.
    enforce_source_grounded_workflows: bool,
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
    /// Optional mechanism parameters to cache after simple/multipart encrypt calls.
    ///
    /// This exercises the gRPC `mechanism_out` fields on `C_Encrypt`,
    /// `C_EncryptUpdate`, and `C_EncryptFinal` without routing through the
    /// exact-output shim path.
    encrypt_operation_output: Mutex<Option<CkMechanismParams>>,
    /// Optional mechanism parameters to return from exact `C_Encrypt` data calls.
    ///
    /// This simulates providers that retain `CK_GCM_PARAMS` from
    /// `C_EncryptInit` and only populate its output IV during `C_Encrypt`.
    encrypt_exact_output: Mutex<Option<CkMechanismParams>>,
    /// Optional mechanism parameters to return from exact `C_WrapKey` data calls.
    ///
    /// This simulates providers that populate caller-supplied wrapping
    /// mechanism parameters, such as the AES-GCM IV, only when the key wrap
    /// operation produces wrapped bytes.
    wrap_key_exact_output: Mutex<Option<CkMechanismParams>>,
    /// Optional mechanism parameters to return from `C_DeriveKey`.
    ///
    /// This simulates providers that write back mutable derivation parameters,
    /// such as TLS/WTLS negotiated versions or PBE generated IV bytes.
    derive_key_output: Mutex<Option<CkMechanismParams>>,
    /// Session-scoped mechanism output returned by `session_output_mechanism_params`.
    ///
    /// This mirrors the FFI backend's session mechanism cache closely enough
    /// for gRPC tests that exercise the simple Encrypt/Decrypt response
    /// `mechanism_out` fields.
    session_mechanism_output: Mutex<HashMap<u64, CkMechanismParams>>,
    /// Per-session signature captured by `C_VerifySignatureInit`.
    verify_signature_state: Mutex<HashMap<u64, Vec<u8>>>,
    /// Per-session accumulated data for `C_VerifySignatureUpdate`/`Final`.
    verify_signature_accumulator: Mutex<HashMap<u64, Vec<u8>>>,
    /// Interface capabilities to report. If `None`, uses the MockBackend
    /// default 2.40/3.0/3.2 catalog with no NULL functions.
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
                session_objects: HashMap::new(),
                active_ops: HashMap::new(),
            }),
            slot_event_queue: Mutex::new(std::collections::VecDeque::new()),
            slot_event_condvar: Condvar::new(),
            token_presence: Mutex::new(HashMap::new()),
            slot_mechanisms: Mutex::new(HashMap::new()),
            enforce_source_grounded_workflows: false,
            attribute_store: Mutex::new(HashMap::new()),
            injected_error: Mutex::new(None),
            encrypt_init_output: Mutex::new(None),
            encrypt_operation_output: Mutex::new(None),
            encrypt_exact_output: Mutex::new(None),
            wrap_key_exact_output: Mutex::new(None),
            derive_key_output: Mutex::new(None),
            session_mechanism_output: Mutex::new(HashMap::new()),
            verify_signature_state: Mutex::new(HashMap::new()),
            verify_signature_accumulator: Mutex::new(HashMap::new()),
            interface_capabilities: Mutex::new(None),
        }
    }

    /// Build a mock backend that advertises every mechanism registered by
    /// the supplied mechanism registry.
    ///
    /// This is useful for protocol/workflow tests that need the complete
    /// proxy-understood mechanism surface, including vendor override entries.
    pub fn with_mechanism_registry(slots: Vec<CkSlotId>, registry: &MechanismRegistry) -> Self {
        let mechanisms =
            registry.registered_mechanisms().into_iter().map(CkMechanismType).collect();
        Self::new(slots, mechanisms)
    }

    /// Convenience constructor using the embedded default mechanism registry.
    pub fn with_default_mechanism_registry(slots: Vec<CkSlotId>) -> Result<Self, String> {
        let registry = MechanismRegistry::load(None)?;
        Ok(Self::with_mechanism_registry(slots, &registry))
    }

    /// Build a catalog-smoke mock backend that advertises every official
    /// PKCS#11 v3.2 mechanism ID known to the bundled inventory.
    ///
    /// This deliberately differs from `with_default_mechanism_registry`,
    /// which advertises the proxy-understood parameter-shape registry. The
    /// official inventory catalog-smoke mode is for protocol coverage of
    /// mechanisms that may not be available on any local provider.
    pub fn with_official_mechanism_catalog_smoke(slots: Vec<CkSlotId>) -> Self {
        Self::new(slots, pkcs11_3_2_official_mechanisms().to_vec())
    }

    /// Build a mock backend that advertises every official PKCS#11 v3.2
    /// mechanism ID known to the bundled inventory and rejects operations that
    /// are not backed by the mechanism's source-grounded workflow flags.
    pub fn with_official_mechanisms(slots: Vec<CkSlotId>) -> Self {
        Self {
            enforce_source_grounded_workflows: true,
            ..Self::with_official_mechanism_catalog_smoke(slots)
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
        self.slot_event_condvar.notify_one();
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
                CkMechanismType::SHA256,
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

    /// Configure optional mechanism parameters cached after simple/multipart encrypt calls.
    pub fn set_encrypt_operation_output(&self, output: Option<CkMechanismParams>) {
        *self.encrypt_operation_output.lock().unwrap() = output;
    }

    /// Configure optional mechanism parameters returned by exact `C_WrapKey` data calls.
    pub fn set_wrap_key_exact_output(&self, output: Option<CkMechanismParams>) {
        *self.wrap_key_exact_output.lock().unwrap() = output;
    }

    /// Configure optional mechanism parameters returned by `C_DeriveKey`.
    pub fn set_derive_key_output(&self, output: Option<CkMechanismParams>) {
        *self.derive_key_output.lock().unwrap() = output;
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

    fn allocate_object_with_template(
        &self,
        state: &mut MockState,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let handle = self.allocate_object(state)?;
        self.store_object_template(handle, template);
        Ok(handle)
    }

    fn allocate_session_object_with_template(
        &self,
        state: &mut MockState,
        session: CkSessionHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let handle = self.allocate_object_with_template(state, template)?;
        if !Self::template_requests_token_object(template) {
            state.session_objects.insert(handle.0, session.0);
        }
        Ok(handle)
    }

    fn template_requests_token_object(template: &[CkAttribute]) -> bool {
        template.iter().any(|attr| {
            attr.attr_type == CkAttributeType::TOKEN
                && matches!(attr.value.as_ref(), Some(CkAttributeValue::Bool(true)))
        })
    }

    fn store_object_template(&self, handle: CkObjectHandle, template: &[CkAttribute]) {
        if template.is_empty() {
            return;
        }

        let attrs = template
            .iter()
            .filter_map(|attr| {
                attr.value.clone().map(|value| (attr.attr_type.0, MockAttributeSlot::Value(value)))
            })
            .collect::<HashMap<_, _>>();
        self.attribute_store.lock().unwrap().insert(handle.0, attrs);
    }

    fn remove_objects(&self, state: &mut MockState, objects: &[u64]) {
        for object in objects {
            state.live_objects.remove(object);
            state.session_objects.remove(object);
        }
        if !objects.is_empty() {
            let mut store = self.attribute_store.lock().unwrap();
            for object in objects {
                store.remove(object);
            }
        }
    }

    fn remove_session_owned_objects(&self, state: &mut MockState, sessions: &[u64]) {
        let objects: Vec<u64> = state
            .session_objects
            .iter()
            .filter_map(|(object, owner)| sessions.contains(owner).then_some(*object))
            .collect();
        self.remove_objects(state, &objects);
    }

    fn require_live_object(&self, state: &MockState, object: CkObjectHandle) -> CkResult<()> {
        if state.live_objects.contains(&object.0) {
            Ok(())
        } else {
            Err(CkRv::OBJECT_HANDLE_INVALID)
        }
    }

    fn require_live_object_if_nonzero(&self, state: &MockState, object: u64) -> CkResult<()> {
        if object == 0 { Ok(()) } else { self.require_live_object(state, CkObjectHandle(object)) }
    }

    fn validate_source_grounded_param_handles(
        &self,
        state: &MockState,
        mechanism: &CkMechanism,
    ) -> CkResult<()> {
        let Some(params) = mechanism.params.as_ref() else {
            return Ok(());
        };

        match params {
            CkMechanismParams::ObjectHandle(params) => {
                self.require_live_object(state, CkObjectHandle(params.handle))?;
            }
            CkMechanismParams::Kip(params)
                if matches!(
                    mechanism.mechanism_type,
                    CkMechanismType::KIP_DERIVE | CkMechanismType::KIP_MAC
                ) =>
            {
                self.require_live_object_if_nonzero(state, params.key_handle)?;
            }
            CkMechanismParams::Ecdh2Derive(params) => {
                self.require_live_object(state, CkObjectHandle(params.private_data_handle))?;
            }
            CkMechanismParams::EcmqvDerive(params) => {
                for handle in [params.private_data_handle, params.public_key_handle] {
                    self.require_live_object(state, CkObjectHandle(handle))?;
                }
            }
            CkMechanismParams::X942Dh2Derive(params) => {
                self.require_live_object(state, CkObjectHandle(params.private_data_handle))?;
            }
            CkMechanismParams::X942MqvDerive(params) => {
                for handle in [params.private_data_handle, params.public_key_handle] {
                    self.require_live_object(state, CkObjectHandle(handle))?;
                }
            }
            CkMechanismParams::X3dhInitiate(params) => {
                // OASIS defines these fields as CK_OBJECT_HANDLE. The remaining
                // local fields are lengthless byte pointers in the spec.
                for handle in [
                    params.peer_identity_handle,
                    params.peer_prekey_handle,
                    params.own_identity_handle,
                    params.own_ephemeral_handle,
                ] {
                    self.require_live_object(state, CkObjectHandle(handle))?;
                }
            }
            CkMechanismParams::X3dhRespond(params) => {
                self.require_live_object(state, CkObjectHandle(params.initiator_identity_handle))?;
            }
            CkMechanismParams::X2RatchetInitialize(params) => {
                for handle in [
                    params.peer_public_prekey_handle,
                    params.peer_public_identity_handle,
                    params.own_public_identity_handle,
                ] {
                    self.require_live_object(state, CkObjectHandle(handle))?;
                }
            }
            CkMechanismParams::X2RatchetRespond(params) => {
                for handle in [
                    params.own_prekey_handle,
                    params.initiator_identity_handle,
                    params.own_identity_handle,
                ] {
                    self.require_live_object(state, CkObjectHandle(handle))?;
                }
            }
            CkMechanismParams::CmsSig(params) => {
                // The spec permits an absent certificate; this transport uses
                // CK_OBJECT_HANDLE(0) for that absent value.
                self.require_live_object_if_nonzero(state, params.certificate_handle)?;
            }
            _ => {}
        }

        Ok(())
    }

    fn require_open_session(&self, session: CkSessionHandle) -> CkResult<()> {
        if self.state.lock().unwrap().has_session(session) {
            Ok(())
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    fn require_supported_mechanism_for_state(
        &self,
        state: &MockState,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
    ) -> CkResult<()> {
        let Some((slot_id, _)) = state.session_record(session) else {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        };
        if self.mechanisms_for_slot(slot_id).contains(&mechanism.mechanism_type) {
            Ok(())
        } else {
            Err(CkRv::MECHANISM_INVALID)
        }
    }

    fn require_mechanism_workflow_for_state(
        &self,
        state: &MockState,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        required_flag: u64,
    ) -> CkResult<()> {
        self.require_supported_mechanism_for_state(state, session, mechanism)?;
        if self.enforce_source_grounded_workflows
            && session_ops::mock_mechanism_workflow_flags(mechanism.mechanism_type) & required_flag
                == 0
        {
            return Err(CkRv::MECHANISM_INVALID);
        }
        Ok(())
    }

    fn require_mechanism_workflow_for_session(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        required_flag: u64,
    ) -> CkResult<()> {
        let state = self.state.lock().unwrap();
        self.require_mechanism_workflow_for_state(&state, session, mechanism, required_flag)
    }

    fn xor_bytes(data: &[u8]) -> Vec<u8> {
        data.iter().map(|byte| byte ^ 0x42).collect()
    }

    fn digest_bytes(data: &[u8]) -> Vec<u8> {
        let sum: u32 = data.iter().map(|&byte| byte as u32).sum();
        sum.to_be_bytes().to_vec()
    }

    fn reverse_bytes(data: &[u8]) -> Vec<u8> {
        data.iter().rev().copied().collect()
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

    fn derive_key_with_sp800_108_output_result(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        template: &[CkAttribute],
    ) -> CkResult<CkDeriveKeyOutputResult> {
        let mut state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Ok(CkDeriveKeyOutputResult::error(CkRv::SESSION_HANDLE_INVALID, None));
        }
        if let Err(rv) = self.validate_sp800_108_data_params(&state, mechanism) {
            return Ok(CkDeriveKeyOutputResult::error(rv, None));
        }
        if let Some(output) = sp800_108_template_failure_output(mechanism) {
            return Ok(CkDeriveKeyOutputResult::error(CkRv::TEMPLATE_INCONSISTENT, Some(output)));
        }
        if let Err(rv) = self.require_sp800_108_derive_capacity(&state, mechanism) {
            return Ok(CkDeriveKeyOutputResult::error(rv, None));
        }

        let primary = self.allocate_session_object_with_template(&mut state, session, template)?;
        let output = match mechanism.params.as_ref() {
            Some(CkMechanismParams::Sp800108Kdf(params))
                if !params.additional_derived_keys.is_empty() =>
            {
                let mut params = params.clone();
                for derived_key in &mut params.additional_derived_keys {
                    derived_key.key_handle = self
                        .allocate_session_object_with_template(
                            &mut state,
                            session,
                            &derived_key.template,
                        )?
                        .0;
                }
                Some(CkMechanismParams::Sp800108Kdf(params))
            }
            Some(CkMechanismParams::Sp800108FeedbackKdf(params))
                if !params.additional_derived_keys.is_empty() =>
            {
                let mut params = params.clone();
                for derived_key in &mut params.additional_derived_keys {
                    derived_key.key_handle = self
                        .allocate_session_object_with_template(
                            &mut state,
                            session,
                            &derived_key.template,
                        )?
                        .0;
                }
                Some(CkMechanismParams::Sp800108FeedbackKdf(params))
            }
            _ => None,
        };
        Ok(CkDeriveKeyOutputResult::ok(primary, output))
    }

    fn validate_sp800_108_data_params(
        &self,
        state: &MockState,
        mechanism: &CkMechanism,
    ) -> CkResult<()> {
        let (prf_type, data_params, is_counter_mode) = match mechanism.params.as_ref() {
            Some(CkMechanismParams::Sp800108Kdf(params)) => (
                params.prf_type,
                &params.data_params,
                mechanism.mechanism_type.0 == CKM_SP800_108_COUNTER_KDF,
            ),
            Some(CkMechanismParams::Sp800108FeedbackKdf(params)) => {
                (params.prf_type, &params.data_params, false)
            }
            _ => return Ok(()),
        };

        if !sp800_108_prf_type_valid(prf_type) {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }

        if !data_params.iter().any(|data_param| data_param.type_ == CK_SP800_108_ITERATION_VARIABLE)
        {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        let mut counter_param_count = 0;
        let mut dkm_length_param_count = 0;

        for data_param in data_params {
            match data_param.type_ {
                CK_SP800_108_ITERATION_VARIABLE
                    if !sp800_108_iteration_variable_payload_valid(is_counter_mode, data_param) =>
                {
                    return Err(CkRv::MECHANISM_PARAM_INVALID);
                }
                CK_SP800_108_ITERATION_VARIABLE => {}
                CK_SP800_108_COUNTER => {
                    if is_counter_mode {
                        return Err(CkRv::MECHANISM_PARAM_INVALID);
                    }
                    counter_param_count += 1;
                    if counter_param_count > 1
                        || data_param.value.len() != CK_SP800_108_COUNTER_FORMAT_LEN
                    {
                        return Err(CkRv::MECHANISM_PARAM_INVALID);
                    }
                }
                CK_SP800_108_DKM_LENGTH => {
                    dkm_length_param_count += 1;
                    if dkm_length_param_count > 1
                        || data_param.value.len() != CK_SP800_108_DKM_LENGTH_FORMAT_LEN
                        || !sp800_108_dkm_length_format_valid(&data_param.value)
                    {
                        return Err(CkRv::MECHANISM_PARAM_INVALID);
                    }
                }
                CK_SP800_108_BYTE_ARRAY if data_param.value.is_empty() => {
                    return Err(CkRv::MECHANISM_PARAM_INVALID);
                }
                CK_SP800_108_KEY_HANDLE => {
                    let handle = read_sp800_108_key_handle_value(&data_param.value)?;
                    self.require_live_object(state, CkObjectHandle(handle))?;
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn require_sp800_108_derive_capacity(
        &self,
        state: &MockState,
        mechanism: &CkMechanism,
    ) -> CkResult<()> {
        if self.max_objects == 0 {
            return Ok(());
        }

        let additional_count = match mechanism.params.as_ref() {
            Some(CkMechanismParams::Sp800108Kdf(params)) => params.additional_derived_keys.len(),
            Some(CkMechanismParams::Sp800108FeedbackKdf(params)) => {
                params.additional_derived_keys.len()
            }
            _ => 0,
        };
        let required_objects = 1_u64.saturating_add(additional_count as u64);
        if state.live_objects.len() as u64 + required_objects > self.max_objects {
            return Err(CkRv::DEVICE_MEMORY);
        }

        Ok(())
    }

    fn clear_session_scoped_side_state(&self, session_id: u64) {
        self.session_mechanism_output.lock().unwrap().remove(&session_id);
        self.verify_signature_state.lock().unwrap().remove(&session_id);
        self.verify_signature_accumulator.lock().unwrap().remove(&session_id);
    }

    fn clear_all_session_scoped_side_state(&self) {
        self.session_mechanism_output.lock().unwrap().clear();
        self.verify_signature_state.lock().unwrap().clear();
        self.verify_signature_accumulator.lock().unwrap().clear();
    }
}

fn sp800_108_prf_type_valid(prf_type: u64) -> bool {
    matches!(
        prf_type,
        CKM_SHA_1_HMAC
            | CKM_SHA224_HMAC
            | CKM_SHA256_HMAC
            | CKM_SHA384_HMAC
            | CKM_SHA512_HMAC
            | CKM_SHA3_224_HMAC
            | CKM_SHA3_256_HMAC
            | CKM_SHA3_384_HMAC
            | CKM_SHA3_512_HMAC
            | CKM_DES3_CMAC
            | CKM_AES_CMAC
    )
}

fn sp800_108_dkm_length_format_valid(value: &[u8]) -> bool {
    let Some(method) = read_ck_ulong_prefix(value) else {
        return false;
    };
    matches!(method, CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS | CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS)
}

fn sp800_108_template_failure_output(mechanism: &CkMechanism) -> Option<CkMechanismParams> {
    match mechanism.params.as_ref()? {
        CkMechanismParams::Sp800108Kdf(params) => {
            let failure_index =
                sp800_108_additional_template_failure_index(&params.additional_derived_keys)?;
            let mut output = params.clone();
            output.additional_derived_keys[failure_index].key_handle = 0;
            Some(CkMechanismParams::Sp800108Kdf(output))
        }
        CkMechanismParams::Sp800108FeedbackKdf(params) => {
            let failure_index =
                sp800_108_additional_template_failure_index(&params.additional_derived_keys)?;
            let mut output = params.clone();
            output.additional_derived_keys[failure_index].key_handle = 0;
            Some(CkMechanismParams::Sp800108FeedbackKdf(output))
        }
        _ => None,
    }
}

fn sp800_108_additional_template_failure_index(
    additional_derived_keys: &[Sp800108DerivedKey],
) -> Option<usize> {
    additional_derived_keys.iter().position(|derived_key| {
        derived_key.template.iter().any(|attr| {
            attr.attr_type == CkAttributeType::VALUE_LEN
                && matches!(attr.value, Some(CkAttributeValue::Ulong(0)))
        })
    })
}

fn read_ck_ulong_prefix(value: &[u8]) -> Option<u64> {
    let ulong_len = std::mem::size_of::<cryptoki_sys::CK_ULONG>();
    if value.len() < ulong_len {
        return None;
    }
    match ulong_len {
        8 => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&value[..8]);
            Some(u64::from_ne_bytes(bytes))
        }
        4 => {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&value[..4]);
            Some(u32::from_ne_bytes(bytes) as u64)
        }
        _ => None,
    }
}

fn sp800_108_iteration_variable_payload_valid(
    is_counter_mode: bool,
    data_param: &PrfDataParam,
) -> bool {
    if is_counter_mode {
        return data_param.value.len() == CK_SP800_108_COUNTER_FORMAT_LEN;
    }

    // OASIS SP800-108 text is inconsistent for Feedback and Double Pipeline:
    // the CK_PRF_DATA_PARAM field prose says NULL/0, while mode tables and
    // examples also show CK_SP800_108_COUNTER_FORMAT. Accept both shaped forms
    // but reject arbitrary payload lengths.
    data_param.value.is_empty() || data_param.value.len() == CK_SP800_108_COUNTER_FORMAT_LEN
}

fn read_sp800_108_key_handle_value(value: &[u8]) -> CkResult<u64> {
    match value.len() {
        8 => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(value);
            Ok(u64::from_ne_bytes(bytes))
        }
        4 => {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(value);
            Ok(u32::from_ne_bytes(bytes) as u64)
        }
        _ => Err(CkRv::MECHANISM_PARAM_INVALID),
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

    fn init_token(&self, slot_id: CkSlotId, _so_pin: Option<&[u8]>, _label: &str) -> CkResult<()> {
        self.require_known_slot(slot_id)?;
        self.noop_ok()
    }

    fn init_pin(&self, session: CkSessionHandle, _pin: Option<&[u8]>) -> CkResult<()> {
        self.require_open_session(session)?;
        self.noop_ok()
    }

    fn set_pin(
        &self,
        session: CkSessionHandle,
        _old_pin: Option<&[u8]>,
        _new_pin: Option<&[u8]>,
    ) -> CkResult<()> {
        self.require_open_session(session)?;
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
    fn find_objects_init(&self, session: CkSessionHandle, _t: &[CkAttribute]) -> CkResult<()> {
        self.find_objects_init_impl(session)
    }
    fn find_objects(&self, session: CkSessionHandle, _m: u32) -> CkResult<Vec<CkObjectHandle>> {
        self.find_objects_impl(session)
    }
    fn find_objects_final(&self, session: CkSessionHandle) -> CkResult<()> {
        self.find_objects_final_impl(session)
    }
    fn get_attribute_value(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &mut [CkAttribute],
    ) -> CkResult<()> {
        self.get_attribute_value_impl(session, object, template)
    }
    fn get_attribute_value_exact(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        queries: &[CkAttributeQuery],
    ) -> CkResult<(CkRv, Vec<CkAttributeQueryResult>)> {
        self.get_attribute_value_exact_impl(session, object, queries)
    }
    fn sign_init(&self, s: CkSessionHandle, m: &CkMechanism, k: CkObjectHandle) -> CkResult<()> {
        self.require_mechanism_workflow_for_session(s, m, CkMechanismFlags::SIGN)?;
        self.sign_init_impl(s, m, k)
    }
    fn sign_init_cancel(&self, s: CkSessionHandle) -> CkResult<()> {
        self.init_cancel_impl(s, MultiPartOp::Sign)
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
        s: CkSessionHandle,
        m: &CkMechanism,
        k: CkObjectHandle,
    ) -> CkResult<()> {
        self.require_mechanism_workflow_for_session(s, m, CkMechanismFlags::SIGN_RECOVER)?;
        self.begin_keyed_op_with_mechanism(s, m, k, MultiPartOp::SignRecover)
    }
    fn sign_recover_init_cancel(&self, s: CkSessionHandle) -> CkResult<()> {
        self.init_cancel_impl(s, MultiPartOp::SignRecover)
    }
    fn sign_recover(&self, s: CkSessionHandle, _d: &[u8]) -> CkResult<Vec<u8>> {
        self.state.lock().unwrap().end_op(s, MultiPartOp::SignRecover)?;
        Ok(vec![0xDE, 0xAD])
    }
    fn verify_recover_init(
        &self,
        s: CkSessionHandle,
        m: &CkMechanism,
        k: CkObjectHandle,
    ) -> CkResult<()> {
        self.require_mechanism_workflow_for_session(s, m, CkMechanismFlags::VERIFY_RECOVER)?;
        self.begin_keyed_op_with_mechanism(s, m, k, MultiPartOp::VerifyRecover)
    }
    fn verify_recover_init_cancel(&self, s: CkSessionHandle) -> CkResult<()> {
        self.init_cancel_impl(s, MultiPartOp::VerifyRecover)
    }
    fn verify_recover(&self, s: CkSessionHandle, _sig: &[u8]) -> CkResult<Vec<u8>> {
        self.state.lock().unwrap().end_op(s, MultiPartOp::VerifyRecover)?;
        self.verify_recover_impl()
    }

    fn verify_init(&self, s: CkSessionHandle, m: &CkMechanism, k: CkObjectHandle) -> CkResult<()> {
        self.require_mechanism_workflow_for_session(s, m, CkMechanismFlags::VERIFY)?;
        self.verify_init_impl(s, m, k)
    }
    fn verify_init_cancel(&self, s: CkSessionHandle) -> CkResult<()> {
        self.init_cancel_impl(s, MultiPartOp::Verify)
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
    fn digest_init(&self, s: CkSessionHandle, m: &CkMechanism) -> CkResult<()> {
        self.require_mechanism_workflow_for_session(s, m, CkMechanismFlags::DIGEST)?;
        self.digest_init_impl(s)
    }
    fn digest_init_cancel(&self, s: CkSessionHandle) -> CkResult<()> {
        self.init_cancel_impl(s, MultiPartOp::Digest)
    }
    fn digest(&self, s: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        self.digest_impl(s, data)
    }
    fn digest_update(&self, s: CkSessionHandle, _p: &[u8]) -> CkResult<()> {
        self.digest_update_impl(s)
    }
    fn digest_key(&self, s: CkSessionHandle, k: CkObjectHandle) -> CkResult<()> {
        self.digest_key_impl(s, k)
    }
    fn digest_final(&self, s: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.digest_final_impl(s)
    }
    fn encrypt_init(
        &self,
        s: CkSessionHandle,
        m: &CkMechanism,
        k: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>> {
        self.require_mechanism_workflow_for_session(s, m, CkMechanismFlags::ENCRYPT)?;
        self.encrypt_init_impl(s, k)?;
        let output = self.encrypt_init_output.lock().unwrap().clone();
        match &output {
            Some(params) => {
                self.session_mechanism_output.lock().unwrap().insert(s.0, params.clone());
            }
            None => {
                self.session_mechanism_output.lock().unwrap().remove(&s.0);
            }
        }
        Ok(output)
    }
    fn encrypt_init_cancel(&self, s: CkSessionHandle) -> CkResult<()> {
        self.session_mechanism_output.lock().unwrap().remove(&s.0);
        self.init_cancel_impl(s, MultiPartOp::Encrypt)
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
        m: &CkMechanism,
        k: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>> {
        self.require_mechanism_workflow_for_session(s, m, CkMechanismFlags::DECRYPT)?;
        self.decrypt_init_impl(s, k).map(|_| None)
    }
    fn decrypt_init_cancel(&self, s: CkSessionHandle) -> CkResult<()> {
        self.init_cancel_impl(s, MultiPartOp::Decrypt)
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
        session: CkSessionHandle,
        m: &CkMechanism,
        base_key: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.require_mechanism_workflow_for_session(session, m, CkMechanismFlags::DERIVE)?;
        let state = self.state.lock().unwrap();
        self.require_live_key(&state, session, base_key)?;
        self.validate_source_grounded_param_handles(&state, m)?;
        drop(state);
        self.derive_key_impl(session, template)
    }

    fn derive_key_with_output(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<(CkObjectHandle, Option<CkMechanismParams>)> {
        let result = self.derive_key_with_output_result(session, mechanism, base_key, template)?;
        if result.rv.is_ok() {
            Ok((result.key_handle.unwrap_or(CkObjectHandle(0)), result.mechanism_out))
        } else {
            Err(result.rv)
        }
    }

    fn derive_key_with_output_result(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkDeriveKeyOutputResult> {
        if let Err(rv) = self.require_mechanism_workflow_for_session(
            session,
            mechanism,
            CkMechanismFlags::DERIVE,
        ) {
            return Ok(CkDeriveKeyOutputResult::error(rv, None));
        }
        let state = self.state.lock().unwrap();
        if let Err(rv) = self.require_live_key(&state, session, base_key) {
            return Ok(CkDeriveKeyOutputResult::error(rv, None));
        }
        if let Err(rv) = self.validate_source_grounded_param_handles(&state, mechanism) {
            return Ok(CkDeriveKeyOutputResult::error(rv, None));
        }
        drop(state);
        if let Some(output) = self.derive_key_output.lock().unwrap().clone() {
            let handle = self.derive_key_impl(session, template)?;
            return Ok(CkDeriveKeyOutputResult::ok(handle, Some(output)));
        }
        self.derive_key_with_sp800_108_output_result(session, mechanism, template)
    }

    fn wrap_key(
        &self,
        s: CkSessionHandle,
        m: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
    ) -> CkResult<Vec<u8>> {
        self.require_mechanism_workflow_for_session(s, m, CkMechanismFlags::WRAP)?;
        let state = self.state.lock().unwrap();
        self.require_live_keys(&state, s, &[wrapping_key, key])?;
        self.wrap_key_impl()
    }
    fn unwrap_key(
        &self,
        session: CkSessionHandle,
        m: &CkMechanism,
        unwrapping_key: CkObjectHandle,
        _wrapped_key: &[u8],
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.require_mechanism_workflow_for_session(session, m, CkMechanismFlags::UNWRAP)?;
        let state = self.state.lock().unwrap();
        self.require_live_key(&state, session, unwrapping_key)?;
        drop(state);
        self.unwrap_key_impl(session, template)
    }
    fn generate_key(
        &self,
        session: CkSessionHandle,
        m: &CkMechanism,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.require_mechanism_workflow_for_session(session, m, CkMechanismFlags::GENERATE)?;
        self.generate_key_impl(session, template)
    }
    fn create_object(
        &self,
        session: CkSessionHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.create_object_impl(session, template)
    }
    fn copy_object(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.copy_object_impl(session, object, template)
    }
    fn destroy_object(&self, session: CkSessionHandle, object: CkObjectHandle) -> CkResult<()> {
        self.destroy_object_impl(session, object)
    }
    fn get_object_size(&self, session: CkSessionHandle, object: CkObjectHandle) -> CkResult<u64> {
        self.object_size(session, object)
    }
    fn set_attribute_value(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        _template: &[CkAttribute],
    ) -> CkResult<()> {
        self.set_attribute_value_impl(session, object)
    }
    fn generate_key_pair(
        &self,
        session: CkSessionHandle,
        m: &CkMechanism,
        public_template: &[CkAttribute],
        private_template: &[CkAttribute],
    ) -> CkResult<(CkObjectHandle, CkObjectHandle)> {
        self.require_mechanism_workflow_for_session(
            session,
            m,
            CkMechanismFlags::GENERATE_KEY_PAIR,
        )?;
        self.generate_key_pair_impl(session, public_template, private_template)
    }
    fn wait_for_slot_event(&self, flags: u64) -> CkResult<CkSlotId> {
        self.wait_for_slot_event_impl(flags)
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

    fn seed_random(&self, s: CkSessionHandle, _seed: &[u8]) -> CkResult<()> {
        self.require_open_session(s)?;
        self.seed_random_impl()
    }

    fn generate_random(&self, s: CkSessionHandle, len: u32) -> CkResult<Vec<u8>> {
        self.require_open_session(s)?;
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
        s: CkSessionHandle,
        _data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.sign_recover_exact_impl(s, spec)
    }

    fn verify_recover_exact(
        &self,
        s: CkSessionHandle,
        _signature: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.verify_recover_exact_impl(s, spec)
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
        s: CkSessionHandle,
        part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.require_open_session(s)?;
        self.digest_encrypt_update_exact_impl(part, spec)
    }

    fn decrypt_digest_update_exact(
        &self,
        s: CkSessionHandle,
        encrypted_part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.require_open_session(s)?;
        self.decrypt_digest_update_exact_impl(encrypted_part, spec)
    }

    fn sign_encrypt_update_exact(
        &self,
        s: CkSessionHandle,
        part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.require_open_session(s)?;
        self.sign_encrypt_update_exact_impl(part, spec)
    }

    fn decrypt_verify_update_exact(
        &self,
        s: CkSessionHandle,
        encrypted_part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.require_open_session(s)?;
        self.decrypt_verify_update_exact_impl(encrypted_part, spec)
    }

    fn wrap_key_exact(
        &self,
        s: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.require_mechanism_workflow_for_session(s, mechanism, CkMechanismFlags::WRAP)?;
        let state = self.state.lock().unwrap();
        self.require_live_keys(&state, s, &[wrapping_key, key])?;
        self.wrap_key_exact_impl(spec)
    }

    fn wrap_key_exact_with_output(
        &self,
        s: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, Option<CkMechanismParams>)> {
        let result = self.wrap_key_exact(s, mechanism, wrapping_key, key, spec)?;
        let output = if spec.buffer_present && result.ck_rv == CkRv::OK {
            self.wrap_key_exact_output.lock().unwrap().clone()
        } else {
            None
        };
        Ok((result, output))
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
        self.require_mechanism_workflow_for_session(
            session,
            mechanism,
            CkMechanismFlags::ENCAPSULATE,
        )?;
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
        self.require_mechanism_workflow_for_session(
            session,
            mechanism,
            CkMechanismFlags::ENCAPSULATE,
        )?;
        self.encapsulate_key_exact_impl(session, mechanism, public_key, template, spec)
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

    fn encrypt_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        aad: &[u8],
        plaintext: &[u8],
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        self.encrypt_message_exact_msg_impl(session, msg_param, aad, plaintext, output_spec)
    }

    fn decrypt_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        aad: &[u8],
        ciphertext: &[u8],
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        self.decrypt_message_exact_msg_impl(session, msg_param, aad, ciphertext, output_spec)
    }

    fn sign_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        data: &[u8],
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        self.sign_message_exact_msg_impl(session, msg_param, data, output_spec)
    }

    fn encrypt_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        plaintext_part: &[u8],
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        self.encrypt_message_next_exact_msg_impl(
            session,
            msg_param,
            plaintext_part,
            flags,
            output_spec,
        )
    }

    fn decrypt_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        ciphertext_part: &[u8],
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        self.decrypt_message_next_exact_msg_impl(
            session,
            msg_param,
            ciphertext_part,
            flags,
            output_spec,
        )
    }

    fn sign_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        data_part: &[u8],
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        self.sign_message_next_exact_msg_impl(session, msg_param, data_part, output_spec)
    }

    fn wrap_key_authenticated_exact(
        &self,
        s: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        _aad: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.require_mechanism_workflow_for_session(s, mechanism, CkMechanismFlags::WRAP)?;
        let state = self.state.lock().unwrap();
        self.require_live_keys(&state, s, &[wrapping_key, key])?;
        self.wrap_key_authenticated_exact_impl(output_spec, param_out_spec)
    }

    fn digest_encrypt_update(&self, s: CkSessionHandle, part: &[u8]) -> CkResult<Vec<u8>> {
        self.require_open_session(s)?;
        self.combined_update(part)
    }

    fn decrypt_digest_update(
        &self,
        s: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>> {
        self.require_open_session(s)?;
        self.combined_update(encrypted_part)
    }

    fn sign_encrypt_update(&self, s: CkSessionHandle, part: &[u8]) -> CkResult<Vec<u8>> {
        self.require_open_session(s)?;
        self.combined_update(part)
    }

    fn decrypt_verify_update(
        &self,
        s: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>> {
        self.require_open_session(s)?;
        self.combined_update(encrypted_part)
    }

    fn login_user(
        &self,
        session: CkSessionHandle,
        _user_type: CkUserType,
        _username: &[u8],
        pin: &[u8],
    ) -> CkResult<()> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        if pin == b"1234" { Ok(()) } else { Err(CkRv::PIN_INCORRECT) }
    }

    fn session_cancel(&self, session: CkSessionHandle, _flags: CkFlags) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        state.active_ops.remove(&session.0);
        drop(state);
        self.clear_session_scoped_side_state(session.0);
        Ok(())
    }

    fn get_session_validation_flags(
        &self,
        session: CkSessionHandle,
        _flags_type: u64,
    ) -> CkResult<u64> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok(0)
    }

    fn decapsulate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        private_key: CkObjectHandle,
        template: &[CkAttribute],
        _ciphertext: &[u8],
    ) -> CkResult<CkObjectHandle> {
        self.require_mechanism_workflow_for_session(
            session,
            mechanism,
            CkMechanismFlags::DECAPSULATE,
        )?;
        let mut state = self.state.lock().unwrap();
        self.require_live_key(&state, session, private_key)?;
        self.allocate_session_object_with_template(&mut state, session, template)
    }

    fn message_encrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let state = self.state.lock().unwrap();
        self.require_live_key_for_optional_mechanism_workflow(
            &state,
            session,
            mechanism,
            key,
            CkMechanismFlags::MESSAGE_ENCRYPT,
        )
    }

    fn encrypt_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        _aad: &[u8],
        plaintext: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok((parameter.to_vec(), Self::xor_bytes(plaintext)))
    }

    fn encrypt_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        _aad: &[u8],
    ) -> CkResult<Vec<u8>> {
        if self.state.lock().unwrap().has_session(session) {
            Ok(parameter.to_vec())
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    fn encrypt_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        plaintext_part: &[u8],
        _flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok((parameter.to_vec(), Self::xor_bytes(plaintext_part)))
    }

    fn message_encrypt_final(&self, session: CkSessionHandle) -> CkResult<()> {
        if self.state.lock().unwrap().has_session(session) {
            Ok(())
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    fn message_decrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let state = self.state.lock().unwrap();
        self.require_live_key_for_optional_mechanism_workflow(
            &state,
            session,
            mechanism,
            key,
            CkMechanismFlags::MESSAGE_DECRYPT,
        )
    }

    fn decrypt_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        _aad: &[u8],
        ciphertext: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok((parameter.to_vec(), Self::xor_bytes(ciphertext)))
    }

    fn decrypt_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        _aad: &[u8],
    ) -> CkResult<Vec<u8>> {
        if self.state.lock().unwrap().has_session(session) {
            Ok(parameter.to_vec())
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    fn decrypt_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        ciphertext_part: &[u8],
        _flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok((parameter.to_vec(), Self::xor_bytes(ciphertext_part)))
    }

    fn message_decrypt_final(&self, session: CkSessionHandle) -> CkResult<()> {
        if self.state.lock().unwrap().has_session(session) {
            Ok(())
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    fn message_sign_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let state = self.state.lock().unwrap();
        self.require_live_key_for_optional_mechanism_workflow(
            &state,
            session,
            mechanism,
            key,
            CkMechanismFlags::MESSAGE_SIGN,
        )
    }

    fn sign_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        data: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok((parameter.to_vec(), Self::reverse_bytes(data)))
    }

    fn sign_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
    ) -> CkResult<Vec<u8>> {
        if self.state.lock().unwrap().has_session(session) {
            Ok(parameter.to_vec())
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    fn sign_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        data_part: &[u8],
        request_signature: bool,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        let signature = if request_signature { Self::reverse_bytes(data_part) } else { Vec::new() };
        Ok((parameter.to_vec(), signature))
    }

    fn message_sign_final(&self, session: CkSessionHandle) -> CkResult<()> {
        if self.state.lock().unwrap().has_session(session) {
            Ok(())
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    fn message_verify_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let state = self.state.lock().unwrap();
        self.require_live_key_for_optional_mechanism_workflow(
            &state,
            session,
            mechanism,
            key,
            CkMechanismFlags::MESSAGE_VERIFY,
        )
    }

    fn verify_message(
        &self,
        session: CkSessionHandle,
        _parameter: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> CkResult<()> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        if signature == Self::reverse_bytes(data) { Ok(()) } else { Err(CkRv::SIGNATURE_INVALID) }
    }

    fn verify_message_begin(&self, session: CkSessionHandle, _parameter: &[u8]) -> CkResult<()> {
        if self.state.lock().unwrap().has_session(session) {
            Ok(())
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    fn verify_message_next(
        &self,
        session: CkSessionHandle,
        _parameter: &[u8],
        data_part: &[u8],
        is_final: bool,
        signature: &[u8],
    ) -> CkResult<()> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        if !is_final || signature == Self::reverse_bytes(data_part) {
            Ok(())
        } else {
            Err(CkRv::SIGNATURE_INVALID)
        }
    }

    fn message_verify_final(&self, session: CkSessionHandle) -> CkResult<()> {
        if self.state.lock().unwrap().has_session(session) {
            Ok(())
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    fn verify_signature_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
        signature: &[u8],
    ) -> CkResult<()> {
        let state = self.state.lock().unwrap();
        self.require_live_key_for_optional_mechanism_workflow(
            &state,
            session,
            mechanism,
            key,
            CkMechanismFlags::VERIFY,
        )?;
        drop(state);
        self.verify_signature_state.lock().unwrap().insert(session.0, signature.to_vec());
        self.verify_signature_accumulator.lock().unwrap().remove(&session.0);
        Ok(())
    }

    fn verify_signature(&self, session: CkSessionHandle, data: &[u8]) -> CkResult<()> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        let signatures = self.verify_signature_state.lock().unwrap();
        let Some(signature) = signatures.get(&session.0) else {
            return Err(CkRv::OPERATION_NOT_INITIALIZED);
        };
        if data == Self::reverse_bytes(signature) { Ok(()) } else { Err(CkRv::SIGNATURE_INVALID) }
    }

    fn verify_signature_update(&self, session: CkSessionHandle, data_part: &[u8]) -> CkResult<()> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        if !self.verify_signature_state.lock().unwrap().contains_key(&session.0) {
            return Err(CkRv::OPERATION_NOT_INITIALIZED);
        }
        self.verify_signature_accumulator
            .lock()
            .unwrap()
            .entry(session.0)
            .or_default()
            .extend_from_slice(data_part);
        Ok(())
    }

    fn verify_signature_final(&self, session: CkSessionHandle) -> CkResult<()> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        let signatures = self.verify_signature_state.lock().unwrap();
        let Some(signature) = signatures.get(&session.0) else {
            return Err(CkRv::OPERATION_NOT_INITIALIZED);
        };
        let accumulated = self.verify_signature_accumulator.lock().unwrap();
        let data = accumulated.get(&session.0).map(Vec::as_slice).unwrap_or(&[]);
        if data == Self::reverse_bytes(signature) { Ok(()) } else { Err(CkRv::SIGNATURE_INVALID) }
    }

    fn wrap_key_authenticated(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        _aad: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        self.require_mechanism_workflow_for_session(session, mechanism, CkMechanismFlags::WRAP)?;
        let state = self.state.lock().unwrap();
        self.require_live_keys(&state, session, &[wrapping_key, key])?;
        Ok((self.wrap_key_impl()?, vec![0xCC; 12]))
    }

    fn unwrap_key_authenticated(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        unwrapping_key: CkObjectHandle,
        _wrapped_key: &[u8],
        template: &[CkAttribute],
        _aad: &[u8],
    ) -> CkResult<(CkObjectHandle, Vec<u8>)> {
        self.require_mechanism_workflow_for_session(session, mechanism, CkMechanismFlags::UNWRAP)?;
        let mut state = self.state.lock().unwrap();
        self.require_live_key(&state, session, unwrapping_key)?;
        Ok((
            self.allocate_session_object_with_template(&mut state, session, template)?,
            vec![0xCC; 12],
        ))
    }

    fn async_complete(
        &self,
        session: CkSessionHandle,
        _function_name: &str,
    ) -> CkResult<(u64, Vec<u8>, u64, CkObjectHandle, CkObjectHandle)> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok((1, vec![0xA5; 8], 8, CkObjectHandle(0), CkObjectHandle(0)))
    }

    fn async_get_id(&self, session: CkSessionHandle, _function_name: &str) -> CkResult<u64> {
        if self.state.lock().unwrap().has_session(session) {
            Ok(1)
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    fn async_join(
        &self,
        session: CkSessionHandle,
        _function_name: &str,
        _operation_id: u64,
        _buffer_size: u64,
    ) -> CkResult<Vec<u8>> {
        if self.state.lock().unwrap().has_session(session) {
            Ok(vec![0xA5; 8])
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    fn get_interface_capabilities(&self) -> InterfaceCapabilities {
        if let Some(caps) = self.interface_capabilities.lock().unwrap().as_ref() {
            return caps.clone();
        }
        InterfaceCapabilities {
            interfaces: vec![
                InterfaceInfo { version_major: 2, version_minor: 40, null_functions: vec![] },
                InterfaceInfo { version_major: 3, version_minor: 0, null_functions: vec![] },
                InterfaceInfo { version_major: 3, version_minor: 2, null_functions: vec![] },
            ],
        }
    }

    fn session_output_mechanism_params(
        &self,
        session: CkSessionHandle,
    ) -> Option<CkMechanismParams> {
        self.session_mechanism_output.lock().unwrap().get(&session.0).cloned()
    }
}

#[cfg(test)]
mod tests;
