// crates/backend/src/mock.rs
use crate::traits::{CkDeriveKeyOutputResult, Pkcs11Backend};
use pkcs11_proxy_ng_proto::convert::message_effects::ParameterEffectCallMode;
use pkcs11_proxy_ng_proto::convert::message_params::MessageParameter;
use pkcs11_proxy_ng_types::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

/// One-shot behavior for the next stateful lifecycle call covered by the
/// message/session transition tests. This deterministic seam replaces a slow
/// or crashing native provider.
#[derive(Debug, Clone, Copy)]
pub enum MockMessageLifecycleAction {
    Return(CkRv),
    Delay(std::time::Duration, CkRv),
    Panic,
}

/// Test gate for deterministically forcing the M5 cross-context first-login
/// race: when installed, each real backend `login` signals on `entered` and
/// then blocks until `proceed`'s flag is set and the condvar is notified.
struct LoginGate {
    entered: std::sync::mpsc::Sender<()>,
    proceed: Arc<(Mutex<bool>, Condvar)>,
}

/// One-shot rendezvous gate for slow-provider simulation (T09): the next
/// matching call signals on `entered`, blocks on `release`, then proceeds.
/// Taken (not cloned) so only the first call parks — later calls run
/// normally, which keeps multi-RPC tests deadlock-free.
struct TokenRendezvous {
    entered: std::sync::mpsc::Sender<CkSlotId>,
    release: std::sync::mpsc::Receiver<()>,
}

/// Predicate over a `find_objects_init` template: installed with
/// [`MockBackend::set_find_template_gate`] so `find_objects` can simulate
/// class-sensitive search.
type FindTemplateGate = Arc<dyn Fn(&[CkAttribute]) -> bool + Send + Sync>;

mod crypto_ops;
pub mod echo;
mod historical_flags;
mod mechanism_entry;
mod mock_types;
mod object_ops;
pub mod output_lengths;
mod session_ops;
mod state;
mod wrap_entry;

pub use self::mechanism_entry::{MockEmbeddedHandles, MockMechanismEntry};
pub use self::mock_types::{MockAbi, MockAttributeSlot, MultiPartOp};
use self::state::{MockState, compute_session_state};
pub use self::wrap_entry::{MockWrapAction, MockWrapEntry, MockWrapObservation};

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
    wrap_entries: Mutex<Vec<MockWrapObservation>>,
    wrap_action: Mutex<Option<MockWrapAction>>,
    authenticated_unwrap_fault: Mutex<Option<CkRv>>,
    destroy_error: Mutex<Option<CkRv>>,
    destroy_calls: AtomicUsize,
    mechanism_entries: Mutex<mechanism_entry::MechanismEntries>,
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
    /// When set, even DONT_BLOCK `wait_for_slot_event` calls park on the
    /// condvar, simulating a faulty provider that hangs a nonblocking
    /// waiter. Set via `inject_slot_event_hang()`; releasing works through
    /// the normal `enqueue_slot_event` wakeup (or by clearing the flag,
    /// which also wakes parked waiters to re-check).
    hang_slot_event: Mutex<bool>,
    /// One-shot `wait_for_slot_event` outcome override for ownership-matrix
    /// tests (TO26b group 2). The next wait consumes it, letting tests
    /// script backend errors (contention, sentinel RVs) the queue cannot
    /// express. Set via `set_next_wait_outcome()`.
    next_wait_outcome: Mutex<Option<CkResult<CkSlotId>>>,
    /// Count of `wait_for_slot_event` trait calls reaching the backend.
    /// Wait-matrix tests use it to prove zero-backend-entry refusals.
    wait_calls: AtomicUsize,
    /// Per-slot token presence override. Slots not present in this map default
    /// to token-present to preserve the historical mock behavior.
    token_presence: Mutex<HashMap<CkSlotId, bool>>,
    token_identities: Mutex<HashMap<CkSlotId, (String, String)>>,
    token_info_requested_slots: Mutex<Vec<CkSlotId>>,
    init_token_requested_slots: Mutex<Vec<CkSlotId>>,
    session_info_slot_overrides: Mutex<HashMap<CkSessionHandle, CkSlotId>>,
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
    /// Error that `close_session` specifically returns. The general
    /// `injected_error` deliberately does NOT block close, so close-failure
    /// paths are exercised through this separate hook. Set via
    /// `inject_close_error()`.
    injected_close_error: Mutex<Option<CkRv>>,
    /// Optional blocking delay before `close_session` settles, used to prove
    /// timeout-safe lifecycle completion without a real slow provider.
    close_session_delay: Mutex<Option<std::time::Duration>>,
    /// Optional blocking delay before `logout` settles. The `close_session`
    /// analogue for teardown tests (W1-C2-03): wedges the last-holder
    /// logout so eviction boundedness is provable without a real stuck HSM.
    logout_delay: Mutex<Option<std::time::Duration>>,
    /// One-shot gate for the next `init_token` (T09): signals entry, waits
    /// release, then proceeds — models a slow provider reinit.
    init_token_gate: Mutex<Option<TokenRendezvous>>,
    /// One-shot error for the next `init_token` (T09), e.g. SESSION_EXISTS
    /// with open sessions. Consumed by the call; `None` (default) succeeds.
    init_token_error: Mutex<Option<CkRv>>,
    /// One-shot gate for the next `get_token_info` (T09): snapshots the
    /// CURRENT identity at entry, signals, waits release, then returns the
    /// snapshot — modeling a slow provider read whose data may be stale by
    /// return time.
    token_info_gate: Mutex<Option<TokenRendezvous>>,
    /// Error that `login` specifically returns (before `login_impl`). Used to
    /// simulate PIN failures (e.g. CKR_PIN_INCORRECT) so tests can exercise
    /// the per-slot failed-login budget without a real PKCS#11 module.
    /// `login_calls` is still incremented so the caller can assert backend reach.
    injected_login_rv: Mutex<Option<CkRv>>,
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
    /// Active digest mechanism per session, captured at C_DigestInit so
    /// digest output length can match the mechanism (mock::output_lengths).
    session_digest_mechanism: Mutex<HashMap<u64, CkMechanismType>>,
    /// Per-session signature captured by `C_VerifySignatureInit`.
    verify_signature_state: Mutex<HashMap<u64, Vec<u8>>>,
    /// Per-session accumulated data for `C_VerifySignatureUpdate`/`Final`.
    verify_signature_accumulator: Mutex<HashMap<u64, Vec<u8>>>,
    /// Interface capabilities to report. If `None`, uses the MockBackend
    /// default 2.40/3.0/3.2 catalog with no NULL functions.
    interface_capabilities: Mutex<Option<InterfaceCapabilities>>,
    login_calls: AtomicUsize,
    login_user_calls: AtomicUsize,
    /// Presence-only observations of backend `login_user` (`C_LoginUser`)
    /// calls: `(username_is_none, pin_is_none)` per call, in arrival order.
    /// Records pointer-presence only — never secret bytes — so NULL-vs-empty
    /// proxying (W1-C6-07) is observable without retaining credentials.
    login_user_presence: Mutex<Vec<(bool, bool)>>,
    token_info_calls: AtomicUsize,
    /// Count of backend `find_objects` (`C_FindObjects`) calls. Used by the
    /// W1-C1-07 scan-bound test to prove bounded backend round-trips.
    find_objects_calls: AtomicUsize,
    /// Count of backend data-operation calls (sign, verify, digest, encrypt,
    /// decrypt and their variants). Incremented inside `resolve_input` so
    /// every migrated data op that calls it contributes. Used by
    /// sanitize_inputs tests to confirm whether the backend was reached.
    data_op_calls: AtomicUsize,
    /// Count of message Encrypt/Decrypt Begin trait calls. The loaded C-ABI
    /// contract test uses this independent counter to prove one native call is
    /// dispatched to exactly one backend method.
    message_begin_calls: AtomicUsize,
    /// Last structured MessageEncrypt/MessageDecrypt Init contract observed
    /// at the backend trait boundary. Tests use this to distinguish the
    /// caller-native envelope length from the daemon-native provider struct.
    message_init_contract: Mutex<Option<(MessageParameter, CkParameterRoundtripSpec)>>,
    /// Count of structured MessageEncrypt/MessageDecrypt Init trait calls.
    message_init_contract_calls: AtomicUsize,
    /// One-shot outcome for the next covered lifecycle call, plus a
    /// reachability counter for endpoint tests.
    next_message_lifecycle_action: Mutex<Option<MockMessageLifecycleAction>>,
    message_lifecycle_calls: AtomicUsize,
    /// Most recent structured one-shot/Next parameter received by the mock.
    /// Loaded C-ABI tests use it to prove Begin-generated bytes are supplied
    /// again on both following Next calls.
    last_message_parameter_call: Mutex<Option<MessageParameter>>,
    /// Count of empty-only Sign/Verify message calls reaching the backend.
    message_parameter_calls: AtomicUsize,
    /// One-shot provider acknowledgement override for message-parameter
    /// contract tests. The next structured exact message call consumes it.
    next_message_parameter_ack: Mutex<Option<CkParameterRoundtripResult>>,
    /// One-shot structured response override for server contract tests. The
    /// next structured Begin/one-shot/Next call consumes it.
    next_message_parameter_response: Mutex<Option<MessageParameter>>,
    /// One-shot random-bytes override for wrong-length contract tests
    /// (W1-L3-08). The next `generate_random` call consumes it verbatim,
    /// even when the length differs from the requested one.
    next_random_bytes: Mutex<Option<Vec<u8>>>,
    close_session_calls: AtomicUsize,
    /// Count of `C_GetAttributeValue` calls reaching the backend (regular path).
    /// Used by R2 coalescer tests to assert whether the backend was bypassed on
    /// a cache hit.
    attr_get_calls: AtomicUsize,
    /// Count of `C_GetAttributeValue` calls reaching the backend (exact path).
    /// Parallels `attr_get_calls` for the exact-output RPC path.
    attr_get_exact_calls: AtomicUsize,
    /// Test-only gate (M5 harness): when `Some`, each real backend `login`
    /// signals + blocks on it. `None` (default) makes `login` a no-op gate.
    login_gate: Mutex<Option<LoginGate>>,
    /// Test-only gate (W1-C1-02 harness): the `C_LoginUser` analogue of
    /// `login_gate`. `None` (default) makes `login_user` a no-op gate.
    login_user_gate: Mutex<Option<LoginGate>>,
    /// The backend ABI this mock emulates on the wire (ADR-0011): ulong
    /// width for values/lengths, CK_ATTRIBUTE stride for nested templates.
    abi: MockAbi,
    /// Override for the D2 byte-order advertisement (`1` = little-endian,
    /// `2` = big-endian) so the client's D6 refusal path can be exercised.
    /// `None` (default) advertises the host's own byte order, consistent
    /// with the same-endian values [`MockAbi::encode_ulong`] emits.
    advertised_byte_order: Option<u32>,
    /// Mechanism-parameter presence rules captured from a registry at
    /// construction (`with_mechanism_registry`); `None` (plain `new`)
    /// keeps the mock permissive for existing suites.
    param_presence: Option<ParamPresence>,
    /// PKCS#11 version reported by `get_info`. Default `(3, 0)`.
    /// Set via `with_cryptoki_version` to test the v3.0+ startup guard.
    cryptoki_version: (u8, u8),
    /// When `Some`, `find_objects` returns successive slices of this list,
    /// advancing the cursor on each call. After all objects have been returned,
    /// subsequent calls return an empty vec — simulating genuine backend exhaustion.
    /// `find_objects_init` resets the cursor to 0. Default `None` preserves the
    /// historical "always empty" find behavior for tests that do not need search.
    find_objects_override: Mutex<Option<Vec<CkObjectHandle>>>,
    /// Cursor into `find_objects_override`: the index of the next object to return.
    /// Each `find_objects` call advances it by the number of objects returned.
    /// `find_objects_init` resets it to 0. Enables multi-batch test scenarios where
    /// successive calls return successive slices (batch1 → batch2 → [] exhausted).
    find_objects_cursor: Mutex<usize>,
    /// Log of every `find_objects_init` template, in call order. Tests drain it
    /// with [`MockBackend::take_find_init_templates`] to assert which searches
    /// a client issued (e.g. primary-class search followed by a SECRET_KEY
    /// fallback). Unbounded by design — test-only, tiny templates.
    find_init_templates: Mutex<Vec<Vec<CkAttribute>>>,
    /// Optional gate (W1-C11-04 harness): when `Some`, `find_objects` serves
    /// the override list only if the gate accepts the most recent init
    /// template, and returns `[]` otherwise. `None` (default) keeps the
    /// historical template-blind behavior. Lets tests simulate a backend
    /// where only a specific class (e.g. SECRET_KEY) matches the search.
    find_template_gate: Mutex<Option<FindTemplateGate>>,
}

/// Which mechanisms require parameters and which forbid them, snapshot
/// from a `MechanismRegistry`. Mechanisms in neither set (vendor,
/// unregistered) are not validated.
struct ParamPresence {
    parameterless: std::collections::HashSet<u64>,
    shaped: std::collections::HashSet<u64>,
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
            hang_slot_event: Mutex::new(false),
            next_wait_outcome: Mutex::new(None),
            wait_calls: AtomicUsize::new(0),
            mechanism_entries: Mutex::new(mechanism_entry::MechanismEntries::default()),
            wrap_entries: Mutex::new(Vec::new()),
            wrap_action: Mutex::new(None),
            authenticated_unwrap_fault: Mutex::new(None),
            destroy_error: Mutex::new(None),
            destroy_calls: AtomicUsize::new(0),
            slot_event_condvar: Condvar::new(),
            token_presence: Mutex::new(HashMap::new()),
            token_identities: Mutex::new(HashMap::new()),
            token_info_requested_slots: Mutex::new(Vec::new()),
            init_token_requested_slots: Mutex::new(Vec::new()),
            session_info_slot_overrides: Mutex::new(HashMap::new()),
            slot_mechanisms: Mutex::new(HashMap::new()),
            enforce_source_grounded_workflows: false,
            attribute_store: Mutex::new(HashMap::new()),
            injected_error: Mutex::new(None),
            injected_close_error: Mutex::new(None),
            close_session_delay: Mutex::new(None),
            logout_delay: Mutex::new(None),
            init_token_gate: Mutex::new(None),
            init_token_error: Mutex::new(None),
            token_info_gate: Mutex::new(None),
            injected_login_rv: Mutex::new(None),
            encrypt_init_output: Mutex::new(None),
            encrypt_operation_output: Mutex::new(None),
            encrypt_exact_output: Mutex::new(None),
            wrap_key_exact_output: Mutex::new(None),
            derive_key_output: Mutex::new(None),
            session_mechanism_output: Mutex::new(HashMap::new()),
            session_digest_mechanism: Mutex::new(HashMap::new()),
            verify_signature_state: Mutex::new(HashMap::new()),
            verify_signature_accumulator: Mutex::new(HashMap::new()),
            interface_capabilities: Mutex::new(None),
            login_calls: AtomicUsize::new(0),
            login_user_calls: AtomicUsize::new(0),
            login_user_presence: Mutex::new(Vec::new()),
            token_info_calls: AtomicUsize::new(0),
            find_objects_calls: AtomicUsize::new(0),
            data_op_calls: AtomicUsize::new(0),
            message_begin_calls: AtomicUsize::new(0),
            message_init_contract: Mutex::new(None),
            message_init_contract_calls: AtomicUsize::new(0),
            next_message_lifecycle_action: Mutex::new(None),
            message_lifecycle_calls: AtomicUsize::new(0),
            last_message_parameter_call: Mutex::new(None),
            message_parameter_calls: AtomicUsize::new(0),
            next_message_parameter_ack: Mutex::new(None),
            next_message_parameter_response: Mutex::new(None),
            next_random_bytes: Mutex::new(None),
            close_session_calls: AtomicUsize::new(0),
            attr_get_calls: AtomicUsize::new(0),
            attr_get_exact_calls: AtomicUsize::new(0),
            login_gate: Mutex::new(None),
            login_user_gate: Mutex::new(None),
            abi: MockAbi::host(),
            advertised_byte_order: None,
            param_presence: None,
            cryptoki_version: (3, 0),
            find_objects_override: Mutex::new(None),
            find_objects_cursor: Mutex::new(0),
            find_init_templates: Mutex::new(Vec::new()),
            find_template_gate: Mutex::new(None),
        }
    }

    /// Install a login gate (M5 test harness). Each subsequent real backend
    /// `login` signals on `entered`, then blocks until `proceed`'s flag is set
    /// and the condvar notified. Lets a test deterministically hold the first
    /// client inside `C_Login` while it starts a second, forcing the race.
    pub fn set_login_gate(
        &self,
        entered: std::sync::mpsc::Sender<()>,
        proceed: Arc<(Mutex<bool>, Condvar)>,
    ) {
        *self.login_gate.lock().unwrap() = Some(LoginGate { entered, proceed });
    }

    /// Install a gate so the next `login_user` call(s) signal `entered` and
    /// block until `proceed`'s flag is set and the condvar notified. The
    /// `C_LoginUser` analogue of [`MockBackend::set_login_gate`]: lets a test
    /// deterministically hold the first client inside `C_LoginUser` while it
    /// starts a second, forcing the race.
    pub fn set_login_user_gate(
        &self,
        entered: std::sync::mpsc::Sender<()>,
        proceed: Arc<(Mutex<bool>, Condvar)>,
    ) {
        *self.login_user_gate.lock().unwrap() = Some(LoginGate { entered, proceed });
    }

    /// Build a mock backend that advertises every mechanism registered by
    /// the supplied mechanism registry.
    ///
    /// This is useful for protocol/workflow tests that need the complete
    /// proxy-understood mechanism surface, including vendor override entries.
    pub fn with_mechanism_registry(slots: Vec<CkSlotId>, registry: &MechanismRegistry) -> Self {
        let mechanisms = registry
            .registered_mechanisms()
            .into_iter()
            .map(|x| CkMechanismType(x as u64))
            .collect();
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

    /// Configure the objects to be served by successive `find_objects` calls.
    ///
    /// `find_objects` returns a cursor-based slice of up to `max_count` handles on each
    /// call, advancing the cursor. Once all handles have been returned, subsequent calls
    /// yield an empty vec — simulating genuine backend exhaustion. `find_objects_init`
    /// resets the cursor to 0, so a new search starts from the beginning.
    ///
    /// This enables multi-batch test scenarios (e.g. batch1=[denied], batch2=[allowed])
    /// by configuring a list larger than `max_count` and using a small `max_object_count`.
    ///
    /// W1-C5-03: installing a new list resets the cursor, so a mid-search
    /// swap serves from the new list's start with defined behavior instead
    /// of slicing at a stale offset. The override and cursor locks are
    /// never held simultaneously here or in `find_objects_impl`, so there
    /// is no lock-ordering hazard.
    pub fn set_find_objects_result(&self, objects: Vec<CkObjectHandle>) {
        *self.find_objects_override.lock().unwrap() = Some(objects);
        *self.find_objects_cursor.lock().unwrap() = 0;
    }

    /// Install a gate so `find_objects` serves the override list only when
    /// the gate accepts the most recent `find_objects_init` template, and
    /// returns `[]` otherwise. Simulate class-sensitive search by matching
    /// on the template's `CKA_CLASS` entry.
    pub fn set_find_template_gate(
        &self,
        gate: impl Fn(&[CkAttribute]) -> bool + Send + Sync + 'static,
    ) {
        *self.find_template_gate.lock().unwrap() = Some(Arc::new(gate));
    }

    /// Drain the log of `find_objects_init` templates, in call order.
    pub fn take_find_init_templates(&self) -> Vec<Vec<CkAttribute>> {
        std::mem::take(&mut self.find_init_templates.lock().unwrap())
    }

    /// Whether the installed find gate (if any) accepts the most recent
    /// init template. No gate installed means "serve the override".
    fn find_template_gate_passes(&self) -> bool {
        let gate = self.find_template_gate.lock().unwrap().clone();
        match gate {
            None => true,
            Some(gate) => {
                let templates = self.find_init_templates.lock().unwrap();
                templates.last().is_some_and(|t| gate(t))
            }
        }
    }

    /// Enqueue a slot event to be returned by the next `wait_for_slot_event` call.
    ///
    /// Events are returned FIFO. If multiple events are queued, each call to
    /// `wait_for_slot_event` returns one.
    pub fn enqueue_slot_event(&self, slot: CkSlotId) {
        self.slot_event_queue.lock().unwrap().push_back(slot);
        self.slot_event_condvar.notify_one();
    }

    /// Make `wait_for_slot_event` park even for DONT_BLOCK calls until the
    /// flag is cleared (which wakes parked waiters to re-check) or an event
    /// is enqueued. Simulates a faulty hanging provider for abnormal-stop
    /// coverage; clearing performs no cleanup or unload by itself.
    pub fn inject_slot_event_hang(&self, hang: bool) {
        *self.hang_slot_event.lock().unwrap() = hang;
        self.slot_event_condvar.notify_all();
    }

    /// Script the next `wait_for_slot_event` outcome (consumed one-shot).
    /// Lets ownership-matrix tests drive backend errors — contention
    /// refusals, sentinel RVs — the event queue cannot express.
    pub fn set_next_wait_outcome(&self, outcome: CkResult<CkSlotId>) {
        *self.next_wait_outcome.lock().unwrap() = Some(outcome);
    }

    /// Number of `wait_for_slot_event` trait calls that reached the backend.
    pub fn wait_call_count(&self) -> usize {
        self.wait_calls.load(Ordering::SeqCst)
    }

    /// Configure whether a token is present in a known slot.
    ///
    /// This lets tests model insertion/removal without changing the default
    /// mock behavior where all configured slots have a token present.
    pub fn set_token_present(&self, slot_id: CkSlotId, present: bool) {
        self.token_presence.lock().unwrap().insert(slot_id, present);
    }

    pub fn login_call_count(&self) -> usize {
        self.login_calls.load(Ordering::SeqCst)
    }

    /// Number of backend `login_user` (`C_LoginUser`) calls. The `C_LoginUser`
    /// analogue of [`MockBackend::login_call_count`].
    pub fn login_user_call_count(&self) -> usize {
        self.login_user_calls.load(Ordering::SeqCst)
    }

    /// Snapshot of the presence-only `login_user` observations recorded so
    /// far: `(username_is_none, pin_is_none)` per call, in arrival order.
    /// Presence only — no secret bytes are ever retained.
    pub fn login_user_presence_observations(&self) -> Vec<(bool, bool)> {
        self.login_user_presence.lock().unwrap().clone()
    }

    /// Number of backend `find_objects` (`C_FindObjects`) calls.
    pub fn find_objects_call_count(&self) -> usize {
        self.find_objects_calls.load(Ordering::SeqCst)
    }

    /// Number of backend data-operation calls (sign, verify, digest, encrypt,
    /// decrypt, etc.). Used by sanitize_inputs tests to check whether the
    /// backend was reached without relying solely on the returned CK_RV.
    pub fn data_op_call_count(&self) -> usize {
        self.data_op_calls.load(Ordering::SeqCst)
    }

    pub fn message_begin_call_count(&self) -> usize {
        self.message_begin_calls.load(Ordering::SeqCst)
    }

    pub fn last_message_init_contract(
        &self,
    ) -> Option<(MessageParameter, CkParameterRoundtripSpec)> {
        self.message_init_contract.lock().unwrap().clone()
    }

    pub fn message_init_contract_call_count(&self) -> usize {
        self.message_init_contract_calls.load(Ordering::SeqCst)
    }

    pub fn set_next_message_lifecycle_action(&self, action: MockMessageLifecycleAction) {
        *self.next_message_lifecycle_action.lock().unwrap() = Some(action);
    }

    pub fn message_lifecycle_call_count(&self) -> usize {
        self.message_lifecycle_calls.load(Ordering::SeqCst)
    }

    pub fn last_message_parameter_call(&self) -> Option<MessageParameter> {
        self.last_message_parameter_call.lock().unwrap().clone()
    }

    pub fn message_parameter_call_count(&self) -> usize {
        self.message_parameter_calls.load(Ordering::SeqCst)
    }

    pub fn set_next_message_parameter_ack(&self, result: CkParameterRoundtripResult) {
        *self.next_message_parameter_ack.lock().unwrap() = Some(result);
    }

    fn next_message_parameter_ack_or(
        &self,
        default: CkParameterRoundtripResult,
    ) -> CkParameterRoundtripResult {
        self.next_message_parameter_ack.lock().unwrap().take().unwrap_or(default)
    }

    pub fn set_next_message_parameter_response(&self, parameter: MessageParameter) {
        *self.next_message_parameter_response.lock().unwrap() = Some(parameter);
    }

    pub fn set_next_random_bytes(&self, bytes: Vec<u8>) {
        *self.next_random_bytes.lock().unwrap() = Some(bytes);
    }

    fn next_message_parameter_response_or(&self, default: MessageParameter) -> MessageParameter {
        self.next_message_parameter_response.lock().unwrap().take().unwrap_or(default)
    }

    /// Number of `C_GetTokenInfo` calls — used to assert the token-info cache
    /// (M9) deduplicates repeated authorization checks.
    pub fn token_info_call_count(&self) -> usize {
        self.token_info_calls.load(Ordering::SeqCst)
    }

    /// Override only the token's identity; presence and injected errors still apply.
    pub fn set_slot_token_identity(&self, slot: CkSlotId, label: String, serial: String) {
        self.token_identities.lock().unwrap().insert(slot, (label, serial));
    }

    /// Native token-metadata request arguments, including calls that returned errors.
    pub fn token_info_requested_slots(&self) -> Vec<CkSlotId> {
        self.token_info_requested_slots.lock().unwrap().clone()
    }

    /// Native InitToken slot arguments; PIN and label payloads are not retained.
    pub fn init_token_requested_slots(&self) -> Vec<CkSlotId> {
        self.init_token_requested_slots.lock().unwrap().clone()
    }

    /// Simulate a provider reporting an inconsistent session owner.
    pub fn set_session_info_slot_override(&self, session: CkSessionHandle, slot: Option<CkSlotId>) {
        let mut overrides = self.session_info_slot_overrides.lock().unwrap();
        if let Some(slot) = slot {
            overrides.insert(session, slot);
        } else {
            overrides.remove(&session);
        }
    }

    /// Number of `C_GetAttributeValue` calls reaching the backend (regular path).
    ///
    /// Used by R2 coalescer tests to assert that a cache hit does NOT increment
    /// the backend call count, confirming the backend was bypassed.
    pub fn attr_get_call_count(&self) -> usize {
        self.attr_get_calls.load(Ordering::SeqCst)
    }

    /// Number of `C_GetAttributeValue` calls reaching the backend (exact path).
    pub fn attr_get_exact_call_count(&self) -> usize {
        self.attr_get_exact_calls.load(Ordering::SeqCst)
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

    /// Make the next (and subsequent) `close_session` calls return `rv` until
    /// cleared, so close-failure handling can be tested.
    pub fn inject_close_error(&self, rv: CkRv) {
        *self.injected_close_error.lock().unwrap() = Some(rv);
    }

    /// Clear a previously injected `close_session` error.
    pub fn clear_close_error(&self) {
        *self.injected_close_error.lock().unwrap() = None;
    }

    pub fn set_close_session_delay(&self, delay: std::time::Duration) {
        *self.close_session_delay.lock().unwrap() = Some(delay);
    }

    pub fn clear_close_session_delay(&self) {
        *self.close_session_delay.lock().unwrap() = None;
    }

    pub fn close_session_call_count(&self) -> usize {
        self.close_session_calls.load(Ordering::SeqCst)
    }

    /// Block `logout` for `delay` before settling. The `close_session`
    /// analogue for teardown tests (W1-C2-03).
    pub fn set_logout_delay(&self, delay: std::time::Duration) {
        *self.logout_delay.lock().unwrap() = Some(delay);
    }

    pub fn clear_logout_delay(&self) {
        *self.logout_delay.lock().unwrap() = None;
    }

    /// Install a one-shot gate for the next `init_token` (T09): it signals
    /// `entered` with the slot, blocks until `release` fires, then proceeds
    /// (updating the slot identity to the requested label on success).
    pub fn set_init_token_gate(
        &self,
        entered: std::sync::mpsc::Sender<CkSlotId>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        *self.init_token_gate.lock().unwrap() = Some(TokenRendezvous { entered, release });
    }

    /// Fail the next `init_token` with `rv` (T09), e.g. SESSION_EXISTS with
    /// open sessions. Consumed by the call; the slot identity is untouched.
    pub fn set_init_token_error(&self, rv: CkRv) {
        *self.init_token_error.lock().unwrap() = Some(rv);
    }

    /// Install a one-shot gate for the next `get_token_info` (T09): it
    /// snapshots the current identity at entry, signals `entered`, blocks
    /// until `release` fires, then returns the snapshot (possibly stale).
    pub fn set_token_info_gate(
        &self,
        entered: std::sync::mpsc::Sender<CkSlotId>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        *self.token_info_gate.lock().unwrap() = Some(TokenRendezvous { entered, release });
    }

    /// Number of currently open backend sessions. Leak accounting for
    /// stress/eviction tests (W1-C2-03, W1-C2-07).
    pub fn open_session_count(&self) -> usize {
        self.state.lock().unwrap().open_sessions.len()
    }

    /// Number of live backend objects. Leak accounting for stress tests
    /// (W1-C2-07).
    pub fn live_object_count(&self) -> usize {
        self.state.lock().unwrap().live_objects.len()
    }

    /// Make subsequent `login` calls return `rv` instead of the normal
    /// login logic. `login_calls` is still incremented so tests can assert
    /// whether the backend was reached. Use to simulate PIN failures without
    /// a real PKCS#11 module (e.g. `CKR_PIN_INCORRECT`).
    pub fn inject_login_rv(&self, rv: CkRv) {
        *self.injected_login_rv.lock().unwrap() = Some(rv);
    }

    /// Clear a previously injected login error, restoring normal login behavior.
    pub fn clear_login_rv(&self) {
        *self.injected_login_rv.lock().unwrap() = None;
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

    fn run_message_lifecycle_action(&self) -> Option<CkResult<()>> {
        self.message_lifecycle_calls.fetch_add(1, Ordering::SeqCst);
        let action = self.next_message_lifecycle_action.lock().unwrap().take()?;
        let rv = match action {
            MockMessageLifecycleAction::Return(rv) => rv,
            MockMessageLifecycleAction::Delay(delay, rv) => {
                std::thread::sleep(delay);
                rv
            }
            MockMessageLifecycleAction::Panic => panic!("injected message lifecycle panic"),
        };
        Some(if rv == CkRv::OK { Ok(()) } else { Err(rv) })
    }

    /// Convert a `CkInBuf` to a `&[u8]` reference for mock operations.
    ///
    /// `Bytes(b)` → `Ok(b)` (zero-copy borrow).
    /// `Null { len: 0 }` → `Ok(&[])` (NULL with zero length is treated as empty).
    /// `Null { len > 0 }` → `Err(ARGUMENTS_BAD)` (NULL with non-zero length is rejected).
    ///
    /// The mock plays a strict softhsm2-like token so that proxy-level tests can
    /// assert NULL pass-through end-to-end: any method that accepts data must call
    /// this helper, making `Null { len > 0 }` uniformly rejected on every migrated
    /// method.
    ///
    /// Increments `data_op_calls` on every call so sanitize_inputs tests can
    /// distinguish "backend not reached" (count unchanged) from "backend called
    /// but returned ARGUMENTS_BAD" (count incremented).
    pub(crate) fn resolve_input<'a>(&self, input: CkInBuf<'a>) -> CkResult<&'a [u8]> {
        self.data_op_calls.fetch_add(1, Ordering::SeqCst);
        match input {
            CkInBuf::Bytes(b) => Ok(b),
            CkInBuf::Null { len: 0 } => Ok(&[]),
            CkInBuf::Null { .. } => Err(CkRv::ARGUMENTS_BAD),
        }
    }

    /// Builder: set session and object quotas.
    ///
    /// `max_sessions`: maximum number of concurrently open sessions (0 = unlimited).
    /// `max_objects`:  maximum number of live objects (0 = unlimited).
    /// Opt in to registry-backed mechanism-parameter presence validation:
    /// a shaped mechanism without params — or a parameterless one WITH
    /// params — is rejected with `CKR_MECHANISM_PARAM_INVALID`, matching
    /// real-token behavior. Off by default: protocol-coverage suites
    /// deliberately drive every mechanism with `params: None`.
    pub fn with_param_presence_validation(mut self, registry: &MechanismRegistry) -> Self {
        let parameterless = registry
            .registered_mechanisms()
            .into_iter()
            .map(|x| x as u64)
            .filter(|m| registry.is_parameterless(*m))
            .collect();
        let shaped = registry.param_shapes_view().keys().copied().collect();
        self.param_presence = Some(ParamPresence { parameterless, shaped });
        self
    }

    /// Emulate a specific backend ABI (default: the host's own profile).
    pub fn with_abi(mut self, abi: MockAbi) -> Self {
        self.abi = abi;
        self
    }

    /// Advertise big-endian byte order (D2) so tests can pin the client's
    /// D6 refusal path. Values are still emitted in host order: a correct
    /// client must refuse before ever parsing one.
    pub fn with_big_endian_advertisement(mut self) -> Self {
        self.advertised_byte_order = Some(2);
        self
    }

    /// Advertise little-endian byte order (D2): the mirror knob for
    /// big-endian hosts, where the big-endian advertisement matches the
    /// client and it is the little-endian one the client must refuse.
    pub fn with_little_endian_advertisement(mut self) -> Self {
        self.advertised_byte_order = Some(1);
        self
    }

    /// Override the PKCS#11 cryptoki version reported by `get_info`.
    /// Used by startup-guard tests to simulate a pre-3.0 backend.
    pub fn with_cryptoki_version(mut self, major: u8, minor: u8) -> Self {
        self.cryptoki_version = (major, minor);
        self
    }

    /// The ABI profile this mock emulates.
    pub fn abi(&self) -> MockAbi {
        self.abi
    }

    pub fn with_quotas(mut self, max_sessions: u64, max_objects: u64) -> Self {
        self.max_sessions = max_sessions;
        self.max_objects = max_objects;
        self
    }

    fn allocate_object(&self, state: &mut MockState) -> CkResult<CkObjectHandle> {
        if self.max_objects > 0 && state.live_objects.len() as u64 >= self.max_objects {
            return Err(CkRv::DEVICE_MEMORY);
        }
        let handle = CkObjectHandle(state.next_object as u64);
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

    /// Map one input attribute to its stored slot. A nested-template
    /// VALUE round-trips through the structural nested slot so the exact
    /// output path serves it with real two-call semantics.
    fn template_entry_to_slot(attr: &CkAttribute) -> Option<(u64, MockAttributeSlot)> {
        let slot = match attr.value.clone()? {
            CkAttributeValue::NestedTemplate(subs) => MockAttributeSlot::NestedTemplate(
                subs.into_iter()
                    .filter_map(|sub| {
                        sub.value.map(|v| (sub.attr_type, MockAttributeSlot::Value(v)))
                    })
                    .collect(),
            ),
            value => MockAttributeSlot::Value(value),
        };
        Some((attr.attr_type.0, slot))
    }

    fn store_object_template(&self, handle: CkObjectHandle, template: &[CkAttribute]) {
        if template.is_empty() {
            return;
        }
        let mut attrs =
            template.iter().filter_map(Self::template_entry_to_slot).collect::<HashMap<_, _>>();
        Self::synthesize_value_from_value_len(handle, &mut attrs);
        self.attribute_store.lock().unwrap().insert(handle.0, attrs);
    }

    /// A key created with CKA_VALUE_LEN but no explicit CKA_VALUE gets a
    /// deterministic CKA_VALUE of exactly that many bytes — matching a
    /// real token, where generate/derive produce key material of the
    /// requested length and it reads back at that size.
    fn synthesize_value_from_value_len(
        handle: CkObjectHandle,
        attrs: &mut HashMap<u64, MockAttributeSlot>,
    ) {
        if attrs.contains_key(&CkAttributeType::VALUE.0) {
            return;
        }
        let Some(MockAttributeSlot::Value(CkAttributeValue::Ulong(len))) =
            attrs.get(&CkAttributeType::VALUE_LEN.0)
        else {
            return;
        };
        let len = *len as usize;
        let value = echo::echo_bytes("key-value", &[&handle.0.to_le_bytes()], len);
        attrs.insert(
            CkAttributeType::VALUE.0,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(value.into())),
        );
    }

    /// Set CKA_CLASS/CKA_KEY_TYPE (+CKA_LOCAL = true) on a freshly
    /// generated key from the mechanism, unless the template already
    /// provided them — matching a real token, so read-after-generate
    /// shows an authentic object. Creates the store entry if the object
    /// was generated with an empty template.
    fn synthesize_default_key_attributes(
        &self,
        handle: CkObjectHandle,
        class: u64,
        key_type: Option<u64>,
    ) {
        let mut store = self.attribute_store.lock().unwrap();
        let attrs = store.entry(handle.0).or_default();
        attrs
            .entry(CkAttributeType::CLASS.0)
            .or_insert_with(|| MockAttributeSlot::Value(CkAttributeValue::Ulong(class)));
        if let Some(kt) = key_type {
            attrs
                .entry(CkAttributeType::KEY_TYPE.0)
                .or_insert_with(|| MockAttributeSlot::Value(CkAttributeValue::Ulong(kt)));
        }
        attrs
            .entry(CkAttributeType::LOCAL.0)
            .or_insert_with(|| MockAttributeSlot::Value(CkAttributeValue::Bool(true)));
    }

    /// C_SetAttributeValue semantics: merge the template into the object's
    /// existing attributes (unlike allocation, which starts fresh).
    fn merge_object_template(&self, handle: CkObjectHandle, template: &[CkAttribute]) {
        if template.is_empty() {
            return;
        }
        let mut store = self.attribute_store.lock().unwrap();
        let attrs = store.entry(handle.0).or_default();
        attrs.extend(template.iter().filter_map(Self::template_entry_to_slot));
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
        if object == 0 {
            Ok(())
        } else {
            self.require_live_object(state, CkObjectHandle(object as u64))
        }
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
                self.require_live_object(state, params.handle)?;
            }
            CkMechanismParams::Kip(params)
                if matches!(
                    mechanism.mechanism_type,
                    CkMechanismType::KIP_DERIVE | CkMechanismType::KIP_MAC
                ) =>
            {
                self.require_live_object_if_nonzero(state, params.key_handle.0)?;
            }
            CkMechanismParams::Ecdh2Derive(params) => {
                self.require_live_object(state, params.private_data_handle)?;
            }
            CkMechanismParams::EcmqvDerive(params) => {
                for handle in [params.private_data_handle, params.public_key_handle] {
                    self.require_live_object(state, handle)?;
                }
            }
            CkMechanismParams::X942Dh2Derive(params) => {
                self.require_live_object(state, params.private_data_handle)?;
            }
            CkMechanismParams::X942MqvDerive(params) => {
                for handle in [params.private_data_handle, params.public_key_handle] {
                    self.require_live_object(state, handle)?;
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
                    self.require_live_object(state, handle)?;
                }
            }
            CkMechanismParams::X3dhRespond(params) => {
                self.require_live_object(state, params.initiator_identity_handle)?;
            }
            CkMechanismParams::X2RatchetInitialize(params) => {
                for handle in [
                    params.peer_public_prekey_handle,
                    params.peer_public_identity_handle,
                    params.own_public_identity_handle,
                ] {
                    self.require_live_object(state, handle)?;
                }
            }
            CkMechanismParams::X2RatchetRespond(params) => {
                for handle in [
                    params.own_prekey_handle,
                    params.initiator_identity_handle,
                    params.own_identity_handle,
                ] {
                    self.require_live_object(state, handle)?;
                }
            }
            CkMechanismParams::CmsSig(params) => {
                // The spec permits an absent certificate; this transport uses
                // CK_OBJECT_HANDLE(0) for that absent value.
                self.require_live_object_if_nonzero(state, params.certificate_handle.0)?;
            }
            _ => {}
        }

        Ok(())
    }

    pub(crate) fn require_open_session(&self, session: CkSessionHandle) -> CkResult<()> {
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

    /// Registry-backed parameter-presence validation: a shaped mechanism
    /// without params — or a parameterless one WITH params — is rejected
    /// the way a real token rejects it. Permissive without a registry and
    /// for mechanisms the registry does not classify (vendor).
    fn validate_mechanism_param_presence(&self, mechanism: &CkMechanism) -> CkResult<()> {
        let Some(presence) = &self.param_presence else {
            return Ok(());
        };
        let mech = mechanism.mechanism_type.0;
        if presence.shaped.contains(&mech) && mechanism.params.is_none() {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        if presence.parameterless.contains(&mech) && mechanism.params.is_some() {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        Ok(())
    }

    fn require_mechanism_workflow_for_state(
        &self,
        state: &MockState,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        required_flag: CkMechanismFlags,
    ) -> CkResult<()> {
        self.require_supported_mechanism_for_state(state, session, mechanism)?;
        self.validate_mechanism_param_presence(mechanism)?;
        if self.enforce_source_grounded_workflows
            && session_ops::mock_mechanism_workflow_flags(mechanism.mechanism_type)
                & required_flag.0
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
        required_flag: CkMechanismFlags,
    ) -> CkResult<()> {
        let state = self.state.lock().unwrap();
        self.require_mechanism_workflow_for_state(&state, session, mechanism, required_flag)
    }

    /// Deterministic IV writeback for `CK_GCM_WRAP_PARAMS` whose generator
    /// asks the token to produce the IV (anything but CKG_NO_GENERATE = 1):
    /// the caller's `iv_fixed_bits` prefix is preserved and the tail is a
    /// stable echo of (session, fixed prefix) — assertable byte-exact,
    /// distinct per session.
    fn generated_iv_writeback(
        session: CkSessionHandle,
        mechanism: &CkMechanism,
    ) -> Option<CkMechanismParams> {
        let Some(CkMechanismParams::GcmWrap(p)) = &mechanism.params else {
            return None;
        };
        if p.iv_generator.0 <= 1 || p.iv.is_empty() {
            return None;
        }
        let fixed_bytes = ((p.iv_fixed_bits as usize) / 8).min(p.iv.len());
        let mut iv = p.iv[..fixed_bytes].to_vec();
        iv.extend(echo::echo_bytes(
            "gcm-iv",
            &[&session.0.to_le_bytes(), &p.iv[..fixed_bytes]],
            p.iv.len() - fixed_bytes,
        ));
        let mut generated = p.clone();
        generated.iv = iv;
        Some(CkMechanismParams::GcmWrap(generated))
    }

    fn xor_bytes(data: &[u8]) -> Vec<u8> {
        data.iter().map(|byte| byte ^ 0x42).collect()
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
                    derived_key.key_handle = self.allocate_session_object_with_template(
                        &mut state,
                        session,
                        &derived_key.template,
                    )?;
                }
                Some(CkMechanismParams::Sp800108Kdf(params))
            }
            Some(CkMechanismParams::Sp800108FeedbackKdf(params))
                if !params.additional_derived_keys.is_empty() =>
            {
                let mut params = params.clone();
                for derived_key in &mut params.additional_derived_keys {
                    derived_key.key_handle = self.allocate_session_object_with_template(
                        &mut state,
                        session,
                        &derived_key.template,
                    )?;
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

        if !sp800_108_prf_type_valid(prf_type.0) {
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
                        || !data_param.value.expose(sp800_108_dkm_length_format_valid)
                    {
                        return Err(CkRv::MECHANISM_PARAM_INVALID);
                    }
                }
                CK_SP800_108_BYTE_ARRAY if data_param.value.is_empty() => {
                    return Err(CkRv::MECHANISM_PARAM_INVALID);
                }
                CK_SP800_108_KEY_HANDLE => {
                    let handle = data_param.value.expose(read_sp800_108_key_handle_value)?;
                    self.require_live_object(state, CkObjectHandle(handle as u64))?;
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
            output.additional_derived_keys[failure_index].key_handle = CkObjectHandle(0);
            Some(CkMechanismParams::Sp800108Kdf(output))
        }
        CkMechanismParams::Sp800108FeedbackKdf(params) => {
            let failure_index =
                sp800_108_additional_template_failure_index(&params.additional_derived_keys)?;
            let mut output = params.clone();
            output.additional_derived_keys[failure_index].key_handle = CkObjectHandle(0);
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
    fn abi_ulong_size(&self) -> u32 {
        self.abi.ulong_width() as u32
    }

    fn abi_byte_order(&self) -> u32 {
        self.advertised_byte_order.unwrap_or_else(crate::host_abi::host_byte_order)
    }

    fn abi_attribute_stride(&self) -> u32 {
        self.abi.attribute_stride() as u32
    }

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
        self.token_info_calls.fetch_add(1, Ordering::SeqCst);
        self.token_info_requested_slots.lock().unwrap().push(slot_id);
        // T09 one-shot gate: snapshot at entry, signal, park until release,
        // then return the snapshot (stale if the token changed meanwhile).
        // NOTE: the take is bound BEFORE the branch — a
        // `if let Some(..) = lock().take()` scrutinee would hold the guard
        // across the park (temporary lifetime) and wedge later calls.
        let gate = self.token_info_gate.lock().unwrap().take();
        if let Some(gate) = gate {
            let snapshot = self.token_info(slot_id)?;
            let _ = gate.entered.send(slot_id);
            let _ = gate.release.recv();
            return Ok(snapshot);
        }
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

    fn init_token(&self, slot_id: CkSlotId, _so_pin: Option<&[u8]>, label: &str) -> CkResult<()> {
        self.init_token_requested_slots.lock().unwrap().push(slot_id);
        self.require_known_slot(slot_id)?;
        // T09 one-shot gate: signal entry, park until release, then proceed.
        // Bound before the branch: an if-let scrutinee take would hold the
        // guard across the park (temporary lifetime) and wedge later calls.
        let gate = self.init_token_gate.lock().unwrap().take();
        if let Some(gate) = gate {
            let _ = gate.entered.send(slot_id);
            let _ = gate.release.recv();
        }
        // T09 one-shot error injection (e.g. SESSION_EXISTS with open
        // sessions): consumed here; the slot identity is untouched.
        let injected = self.init_token_error.lock().unwrap().take();
        if let Some(rv) = injected {
            return Err(rv);
        }
        // A real reinit relabels the token: adopt the requested label (keep
        // the serial) so daemon cache invalidation is observable.
        let serial = self
            .token_identities
            .lock()
            .unwrap()
            .get(&slot_id)
            .map(|(_, serial)| serial.clone())
            .unwrap_or_else(|| "0001".into());
        self.set_slot_token_identity(slot_id, label.to_string(), serial);
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
        self.login_calls.fetch_add(1, Ordering::SeqCst);
        // M5 test gate: clone the handles out from under the gate lock, then
        // signal + block WITHOUT holding that lock, so a concurrent login can
        // also reach the gate (otherwise the second login would serialize on the
        // gate's own mutex instead of exercising the real race).
        let gate = self
            .login_gate
            .lock()
            .unwrap()
            .as_ref()
            .map(|g| (g.entered.clone(), Arc::clone(&g.proceed)));
        if let Some((entered, proceed)) = gate {
            let _ = entered.send(());
            let (lock, cv) = &*proceed;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = cv.wait(released).unwrap();
            }
        }
        // G2-PR3: injected login error for PIN-failure tests. Checked after the
        // gate and counter so tests can assert backend reach via login_call_count.
        if let Some(rv) = *self.injected_login_rv.lock().unwrap() {
            return Err(rv);
        }
        self.login_impl(session, user_type)
    }

    fn logout(&self, session: CkSessionHandle) -> CkResult<()> {
        self.logout_impl(session)
    }
    fn find_objects_init(
        &self,
        session: CkSessionHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<()> {
        self.find_init_templates.lock().unwrap().push(template.unwrap_or(&[]).to_vec());
        self.find_objects_init_impl(session)
    }
    fn find_objects(
        &self,
        session: CkSessionHandle,
        max_count: u32,
    ) -> CkResult<Vec<CkObjectHandle>> {
        self.find_objects_impl(session, max_count)
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
        self.record_mechanism_entry(MockMechanismEntry::SignInit, Some(m));
        self.require_mechanism_workflow_for_session(s, m, CkMechanismFlags::SIGN)?;
        self.sign_init_impl(s, m, k)
    }
    fn sign_init_cancel(&self, s: CkSessionHandle) -> CkResult<()> {
        self.init_cancel_impl(s, MultiPartOp::Sign)
    }
    fn sign(&self, s: CkSessionHandle, d: CkInBuf<'_>) -> CkResult<SecretBytes> {
        let data = self.resolve_input(d)?;
        self.sign_impl(s, data)
    }
    fn sign_update(&self, s: CkSessionHandle, p: CkInBuf<'_>) -> CkResult<()> {
        let _ = self.resolve_input(p)?;
        self.sign_update_impl(s)
    }
    fn sign_final(&self, s: CkSessionHandle) -> CkResult<SecretBytes> {
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
    fn sign_recover(&self, s: CkSessionHandle, d: CkInBuf<'_>) -> CkResult<SecretBytes> {
        let data = self.resolve_input(d)?;
        self.state.lock().unwrap().end_op(s, MultiPartOp::SignRecover)?;
        Ok(echo::echo_bytes("sign-recover", &[data], 2).into())
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
    fn verify_recover(&self, s: CkSessionHandle, sig: CkInBuf<'_>) -> CkResult<SecretBytes> {
        let _ = self.resolve_input(sig)?;
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
    fn verify(&self, s: CkSessionHandle, d: CkInBuf<'_>, sig: CkInBuf<'_>) -> CkResult<()> {
        let data = self.resolve_input(d)?;
        let signature = self.resolve_input(sig)?;
        // A real integrity check: the one-shot sign echo is a function of
        // the signed data (see sign_impl), so a signature that does not
        // reproduce echo("sign", data) means data or signature bytes were
        // lost/corrupted between sign and verify.
        let expected = echo::echo_bytes("sign", &[data], crypto_ops::MOCK_SIGN_LEN);
        // Terminate the operation first (like a real token: C_Verify ends
        // the op whether it returns OK or CKR_SIGNATURE_INVALID), then
        // report the signature outcome.
        self.verify_impl(s)?;
        if signature != expected {
            return Err(CkRv::SIGNATURE_INVALID);
        }
        Ok(())
    }
    fn verify_update(&self, s: CkSessionHandle, p: CkInBuf<'_>) -> CkResult<()> {
        let _ = self.resolve_input(p)?;
        self.verify_update_impl(s)
    }
    fn verify_final(&self, s: CkSessionHandle, sig: CkInBuf<'_>) -> CkResult<()> {
        let signature = self.resolve_input(sig)?;
        // Multi-part verify accumulates no data (sign_final's echo is
        // input-independent), so this stays a shape check against the
        // sign-final echo rather than a data-integrity check.
        let expected = echo::echo_bytes("sign-final", &[], crypto_ops::MOCK_SIGN_LEN);
        self.verify_final_impl(s)?;
        if signature != expected {
            return Err(CkRv::SIGNATURE_INVALID);
        }
        Ok(())
    }
    fn digest_init(&self, s: CkSessionHandle, m: &CkMechanism) -> CkResult<()> {
        self.record_mechanism_entry(MockMechanismEntry::DigestInit, Some(m));
        self.require_mechanism_workflow_for_session(s, m, CkMechanismFlags::DIGEST)?;
        self.digest_init_impl(s)?;
        self.session_digest_mechanism.lock().unwrap().insert(s.0, m.mechanism_type);
        Ok(())
    }
    fn digest_init_cancel(&self, s: CkSessionHandle) -> CkResult<()> {
        self.record_mechanism_entry(MockMechanismEntry::DigestInitCancel, None);
        self.session_digest_mechanism.lock().unwrap().remove(&s.0);
        self.init_cancel_impl(s, MultiPartOp::Digest)
    }
    fn digest(&self, s: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<SecretBytes> {
        let data = self.resolve_input(data)?;
        // Length follows the active mechanism (mock::output_lengths);
        // unknown mechanisms keep the legacy compact length.
        let len = self
            .session_digest_mechanism
            .lock()
            .unwrap()
            .get(&s.0)
            .and_then(|m| output_lengths::digest_len(*m))
            .unwrap_or(crypto_ops::MOCK_DEFAULT_DIGEST_LEN);
        self.digest_impl(s, data, len)
    }
    fn digest_update(&self, s: CkSessionHandle, p: CkInBuf<'_>) -> CkResult<()> {
        let _ = self.resolve_input(p)?;
        self.digest_update_impl(s)
    }
    fn digest_key(&self, s: CkSessionHandle, k: CkObjectHandle) -> CkResult<()> {
        self.digest_key_impl(s, k)
    }
    fn digest_final(&self, s: CkSessionHandle) -> CkResult<SecretBytes> {
        let len = self
            .session_digest_mechanism
            .lock()
            .unwrap()
            .get(&s.0)
            .and_then(|m| output_lengths::digest_len(*m))
            .unwrap_or(crypto_ops::MOCK_DEFAULT_DIGEST_LEN);
        self.digest_final_impl(s, len)
    }
    fn encrypt_init(
        &self,
        s: CkSessionHandle,
        m: &CkMechanism,
        k: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>> {
        self.require_mechanism_workflow_for_session(s, m, CkMechanismFlags::ENCRYPT)?;
        self.encrypt_init_impl(s, k)?;
        // Injected test output wins; otherwise IV-generating GCM-wrap
        // params produce a deterministic writeback.
        let output = self
            .encrypt_init_output
            .lock()
            .unwrap()
            .clone()
            .or_else(|| Self::generated_iv_writeback(s, m));
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
    fn encrypt(&self, s: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.encrypt_impl(s, self.resolve_input(data)?)
    }
    fn encrypt_update(&self, s: CkSessionHandle, part: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.encrypt_update_impl(s, self.resolve_input(part)?)
    }
    fn encrypt_final(&self, s: CkSessionHandle) -> CkResult<SecretBytes> {
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
    fn decrypt(&self, s: CkSessionHandle, encrypted_data: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.decrypt_impl(s, self.resolve_input(encrypted_data)?)
    }
    fn decrypt_update(
        &self,
        s: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.decrypt_update_impl(s, self.resolve_input(encrypted_part)?)
    }
    fn decrypt_final(&self, s: CkSessionHandle) -> CkResult<SecretBytes> {
        self.decrypt_final_impl(s)
    }
    fn derive_key(
        &self,
        session: CkSessionHandle,
        m: &CkMechanism,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.record_mechanism_entry(MockMechanismEntry::DeriveKey, Some(m));
        self.require_mechanism_workflow_for_session(session, m, CkMechanismFlags::DERIVE)?;
        let state = self.state.lock().unwrap();
        self.require_live_key(&state, session, base_key)?;
        self.validate_source_grounded_param_handles(&state, m)?;
        drop(state);
        self.derive_key_impl(session, template.unwrap_or(&[]))
    }

    fn derive_key_with_output(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
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
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkDeriveKeyOutputResult> {
        self.record_mechanism_entry(MockMechanismEntry::DeriveKey, Some(mechanism));
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
            let handle = self.derive_key_impl(session, template.unwrap_or(&[]))?;
            return Ok(CkDeriveKeyOutputResult::ok(handle, Some(output)));
        }
        self.derive_key_with_sp800_108_output_result(session, mechanism, template.unwrap_or(&[]))
    }

    fn wrap_key(
        &self,
        s: CkSessionHandle,
        m: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
    ) -> CkResult<SecretBytes> {
        self.record_wrap_entry(MockWrapEntry::Wrap, s, m, wrapping_key, key, None, None)?;
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
        wrapped_key: CkInBuf<'_>,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        let _ = self.resolve_input(wrapped_key)?;
        self.require_mechanism_workflow_for_session(session, m, CkMechanismFlags::UNWRAP)?;
        let state = self.state.lock().unwrap();
        self.require_live_key(&state, session, unwrapping_key)?;
        drop(state);
        self.unwrap_key_impl(session, template.unwrap_or(&[]))
    }
    fn generate_key(
        &self,
        session: CkSessionHandle,
        m: &CkMechanism,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.record_mechanism_entry(MockMechanismEntry::GenerateKey, Some(m));
        self.require_mechanism_workflow_for_session(session, m, CkMechanismFlags::GENERATE)?;
        let handle = self.generate_key_impl(session, template.unwrap_or(&[]))?;
        // CKO_SECRET_KEY, with the key type derived from the mechanism.
        self.synthesize_default_key_attributes(
            handle,
            0x0000_0004,
            session_ops::mock_secret_key_type(m.mechanism_type),
        );
        Ok(handle)
    }
    fn create_object(
        &self,
        session: CkSessionHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.create_object_impl(session, template.unwrap_or(&[]))
    }
    fn copy_object(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.copy_object_impl(session, object, template.unwrap_or(&[]))
    }
    fn destroy_object(&self, session: CkSessionHandle, object: CkObjectHandle) -> CkResult<()> {
        self.destroy_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(rv) = *self.destroy_error.lock().unwrap() {
            return Err(rv);
        }
        self.destroy_object_impl(session, object)
    }
    fn get_object_size(&self, session: CkSessionHandle, object: CkObjectHandle) -> CkResult<u64> {
        self.object_size(session, object)
    }
    fn set_attribute_value(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<()> {
        self.set_attribute_value_impl(session, object)?;
        // The template was previously discarded: C_SetAttributeValue merges
        // into the stored attributes so set-then-read round-trips.
        self.merge_object_template(object, template.unwrap_or(&[]));
        Ok(())
    }
    fn generate_key_pair(
        &self,
        session: CkSessionHandle,
        m: &CkMechanism,
        public_template: Option<&[CkAttribute]>,
        private_template: Option<&[CkAttribute]>,
    ) -> CkResult<(CkObjectHandle, CkObjectHandle)> {
        self.record_mechanism_entry(MockMechanismEntry::GenerateKeyPair, Some(m));
        self.require_mechanism_workflow_for_session(
            session,
            m,
            CkMechanismFlags::GENERATE_KEY_PAIR,
        )?;
        let (public, private) = self.generate_key_pair_impl(
            session,
            public_template.unwrap_or(&[]),
            private_template.unwrap_or(&[]),
        )?;
        let key_type = session_ops::mock_pair_key_type(m.mechanism_type);
        self.synthesize_default_key_attributes(public, 0x0000_0002, key_type); // CKO_PUBLIC_KEY
        self.synthesize_default_key_attributes(private, 0x0000_0003, key_type); // CKO_PRIVATE_KEY
        Ok((public, private))
    }
    fn wait_for_slot_event(&self, flags: u64) -> CkResult<CkSlotId> {
        self.wait_for_slot_event_impl(flags)
    }

    fn get_operation_state(&self, s: CkSessionHandle) -> CkResult<SecretBytes> {
        self.operation_state(s)
    }

    fn set_operation_state(
        &self,
        s: CkSessionHandle,
        state: CkInBuf<'_>,
        _enc_key: CkObjectHandle,
        _auth_key: CkObjectHandle,
    ) -> CkResult<()> {
        if let Some(result) = self.run_message_lifecycle_action() {
            return result;
        }
        self.restore_operation_state(s, self.resolve_input(state)?)
    }

    fn seed_random(&self, s: CkSessionHandle, seed: CkInBuf<'_>) -> CkResult<()> {
        let _ = self.resolve_input(seed)?;
        self.require_open_session(s)?;
        self.seed_random_impl()
    }

    fn generate_random(&self, s: CkSessionHandle, len: u32) -> CkResult<SecretBytes> {
        self.require_open_session(s)?;
        self.generate_random_impl(len)
    }

    // --- Exact byte-output trait methods (Track B) ---

    fn sign_exact(
        &self,
        s: CkSessionHandle,
        data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.sign_exact_impl(s, self.resolve_input(data)?, spec)
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
        data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.sign_recover_exact_impl(s, self.resolve_input(data)?, spec)
    }

    fn verify_recover_exact(
        &self,
        s: CkSessionHandle,
        signature: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        let _ = self.resolve_input(signature)?;
        self.verify_recover_exact_impl(s, spec)
    }

    fn digest_exact(
        &self,
        s: CkSessionHandle,
        data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.digest_exact_impl(s, self.resolve_input(data)?, spec)
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
        data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.encrypt_exact_impl(s, self.resolve_input(data)?, spec)
    }

    fn encrypt_exact_with_output(
        &self,
        s: CkSessionHandle,
        data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, Option<CkMechanismParams>)> {
        let result = self.encrypt_exact_impl(s, self.resolve_input(data)?, spec)?;
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
        part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.encrypt_update_exact_impl(s, self.resolve_input(part)?, spec)
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
        encrypted_data: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.decrypt_exact_impl(s, self.resolve_input(encrypted_data)?, spec)
    }

    fn decrypt_update_exact(
        &self,
        s: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.decrypt_update_exact_impl(s, self.resolve_input(encrypted_part)?, spec)
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
        part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.require_open_session(s)?;
        self.digest_encrypt_update_exact_impl(self.resolve_input(part)?, spec)
    }

    fn decrypt_digest_update_exact(
        &self,
        s: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.require_open_session(s)?;
        self.decrypt_digest_update_exact_impl(self.resolve_input(encrypted_part)?, spec)
    }

    fn sign_encrypt_update_exact(
        &self,
        s: CkSessionHandle,
        part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.require_open_session(s)?;
        self.sign_encrypt_update_exact_impl(self.resolve_input(part)?, spec)
    }

    fn decrypt_verify_update_exact(
        &self,
        s: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.require_open_session(s)?;
        self.decrypt_verify_update_exact_impl(self.resolve_input(encrypted_part)?, spec)
    }

    fn wrap_key_exact(
        &self,
        s: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.record_wrap_entry(
            MockWrapEntry::Exact,
            s,
            mechanism,
            wrapping_key,
            key,
            Some(spec),
            None,
        )?;
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
        template: Option<&[CkAttribute]>,
    ) -> CkResult<(SecretBytes, CkObjectHandle)> {
        self.record_mechanism_entry(MockMechanismEntry::EncapsulateKey, Some(mechanism));
        self.require_mechanism_workflow_for_session(
            session,
            mechanism,
            CkMechanismFlags::ENCAPSULATE,
        )?;
        self.encapsulate_key_impl(session, mechanism, public_key, template.unwrap_or(&[]))
    }

    // --- Track C Task 2: Exact KEM trait method ---

    fn encapsulate_key_exact(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        public_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputAndHandleResult> {
        self.record_mechanism_entry(MockMechanismEntry::EncapsulateKeyExact, Some(mechanism));
        self.require_mechanism_workflow_for_session(
            session,
            mechanism,
            CkMechanismFlags::ENCAPSULATE,
        )?;
        self.encapsulate_key_exact_impl(
            session,
            mechanism,
            public_key,
            template.unwrap_or(&[]),
            spec,
        )
    }

    // --- Track C: Exact parameter-output trait methods ---

    fn encrypt_message_exact(
        &self,
        s: CkSessionHandle,
        parameter: &[u8],
        aad: CkInBuf<'_>,
        plaintext: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.message_parameter_calls.fetch_add(1, Ordering::SeqCst);
        self.encrypt_message_exact_impl(
            s,
            parameter,
            self.resolve_input(aad)?,
            self.resolve_input(plaintext)?,
            output_spec,
            param_out_spec,
        )
    }

    fn decrypt_message_exact(
        &self,
        s: CkSessionHandle,
        parameter: &[u8],
        aad: CkInBuf<'_>,
        ciphertext: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.message_parameter_calls.fetch_add(1, Ordering::SeqCst);
        self.decrypt_message_exact_impl(
            s,
            parameter,
            self.resolve_input(aad)?,
            self.resolve_input(ciphertext)?,
            output_spec,
            param_out_spec,
        )
    }

    fn sign_message_exact(
        &self,
        s: CkSessionHandle,
        parameter: &[u8],
        data: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.message_parameter_calls.fetch_add(1, Ordering::SeqCst);
        self.sign_message_exact_impl(
            s,
            parameter,
            self.resolve_input(data)?,
            output_spec,
            param_out_spec,
        )
    }

    fn encrypt_message_next_exact(
        &self,
        s: CkSessionHandle,
        parameter: &[u8],
        plaintext_part: CkInBuf<'_>,
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.message_parameter_calls.fetch_add(1, Ordering::SeqCst);
        self.encrypt_message_next_exact_impl(
            s,
            parameter,
            self.resolve_input(plaintext_part)?,
            flags,
            output_spec,
            param_out_spec,
        )
    }

    fn decrypt_message_next_exact(
        &self,
        s: CkSessionHandle,
        parameter: &[u8],
        ciphertext_part: CkInBuf<'_>,
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.message_parameter_calls.fetch_add(1, Ordering::SeqCst);
        self.decrypt_message_next_exact_impl(
            s,
            parameter,
            self.resolve_input(ciphertext_part)?,
            flags,
            output_spec,
            param_out_spec,
        )
    }

    fn sign_message_next_exact(
        &self,
        s: CkSessionHandle,
        parameter: &[u8],
        data_part: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.message_parameter_calls.fetch_add(1, Ordering::SeqCst);
        self.sign_message_next_exact_impl(
            s,
            parameter,
            self.resolve_input(data_part)?,
            output_spec,
            param_out_spec,
        )
    }

    fn encrypt_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        aad: CkInBuf<'_>,
        plaintext: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        self.message_parameter_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_message_parameter_call.lock().unwrap() = Some(msg_param.clone());
        let (output, message) = self.encrypt_message_exact_msg_impl(
            session,
            msg_param,
            self.resolve_input(aad)?,
            self.resolve_input(plaintext)?,
            output_spec,
        )?;
        let parameter = self.next_message_parameter_ack_or(CkParameterRoundtripResult {
            ck_rv: output.ck_rv,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        });
        let message = self.next_message_parameter_response_or(message);
        let effects = pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects::capture(
            msg_param,
            &message,
            pkcs11_proxy_ng_proto::convert::message_effects::MessageEffectContext {
                mode: ParameterEffectCallMode::from_output_spec(output_spec),
                encrypt: true,
                generated_stage: true,
                auth_stage: true,
                rv: output.ck_rv,
            },
        );
        Ok((output, parameter, effects))
    }

    fn decrypt_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        aad: CkInBuf<'_>,
        ciphertext: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        self.message_parameter_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_message_parameter_call.lock().unwrap() = Some(msg_param.clone());
        let (output, message) = self.decrypt_message_exact_msg_impl(
            session,
            msg_param,
            self.resolve_input(aad)?,
            self.resolve_input(ciphertext)?,
            output_spec,
        )?;
        let parameter = self.next_message_parameter_ack_or(CkParameterRoundtripResult {
            ck_rv: output.ck_rv,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        });
        let message = self.next_message_parameter_response_or(message);
        let effects = pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects::capture(
            msg_param,
            &message,
            pkcs11_proxy_ng_proto::convert::message_effects::MessageEffectContext {
                mode: ParameterEffectCallMode::from_output_spec(output_spec),
                encrypt: false,
                generated_stage: true,
                auth_stage: true,
                rv: output.ck_rv,
            },
        );
        Ok((output, parameter, effects))
    }

    fn encrypt_message_begin_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        aad: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        self.message_begin_calls.fetch_add(1, Ordering::SeqCst);
        let _ = self.resolve_input(aad)?;
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        msg_param.validate_structured()?;
        *self.last_message_parameter_call.lock().unwrap() = Some(msg_param.clone());
        let ack = self.next_message_parameter_ack_or(CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        });
        let returned = self
            .next_message_parameter_response_or(Self::mock_message_begin_parameter_out(msg_param));
        let effects = pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects::capture(
            msg_param,
            &returned,
            pkcs11_proxy_ng_proto::convert::message_effects::MessageEffectContext {
                mode: ParameterEffectCallMode::Begin,
                encrypt: true,
                generated_stage: true,
                auth_stage: false,
                rv: ack.ck_rv,
            },
        );
        Ok((ack, effects))
    }

    fn decrypt_message_begin_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        aad: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        self.message_begin_calls.fetch_add(1, Ordering::SeqCst);
        let _ = self.resolve_input(aad)?;
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        msg_param.validate_structured()?;
        *self.last_message_parameter_call.lock().unwrap() = Some(msg_param.clone());
        let ack = self.next_message_parameter_ack_or(CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        });
        let returned = self.next_message_parameter_response_or(msg_param.clone());
        let effects = pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects::capture(
            msg_param,
            &returned,
            pkcs11_proxy_ng_proto::convert::message_effects::MessageEffectContext {
                mode: ParameterEffectCallMode::Begin,
                encrypt: false,
                generated_stage: true,
                auth_stage: false,
                rv: ack.ck_rv,
            },
        );
        Ok((ack, effects))
    }

    fn sign_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        data: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        self.sign_message_exact_msg_impl(session, msg_param, self.resolve_input(data)?, output_spec)
    }

    fn encrypt_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        plaintext_part: CkInBuf<'_>,
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        self.message_parameter_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_message_parameter_call.lock().unwrap() = Some(msg_param.clone());
        let (output, message) = self.encrypt_message_next_exact_msg_impl(
            session,
            msg_param,
            self.resolve_input(plaintext_part)?,
            flags,
            output_spec,
        )?;
        let parameter = self.next_message_parameter_ack_or(CkParameterRoundtripResult {
            ck_rv: output.ck_rv,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        });
        let message = self.next_message_parameter_response_or(message);
        let effects = pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects::capture(
            msg_param,
            &message,
            pkcs11_proxy_ng_proto::convert::message_effects::MessageEffectContext {
                mode: ParameterEffectCallMode::from_output_spec(output_spec),
                encrypt: true,
                generated_stage: false,
                auth_stage: flags.0 & CkFlags::END_OF_MESSAGE.0 != 0,
                rv: output.ck_rv,
            },
        );
        Ok((output, parameter, effects))
    }

    fn decrypt_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        ciphertext_part: CkInBuf<'_>,
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        CkParameterRoundtripResult,
        pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects,
    )> {
        self.message_parameter_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_message_parameter_call.lock().unwrap() = Some(msg_param.clone());
        let (output, message) = self.decrypt_message_next_exact_msg_impl(
            session,
            msg_param,
            self.resolve_input(ciphertext_part)?,
            flags,
            output_spec,
        )?;
        let parameter = self.next_message_parameter_ack_or(CkParameterRoundtripResult {
            ck_rv: output.ck_rv,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        });
        let message = self.next_message_parameter_response_or(message);
        let effects = pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects::capture(
            msg_param,
            &message,
            pkcs11_proxy_ng_proto::convert::message_effects::MessageEffectContext {
                mode: ParameterEffectCallMode::from_output_spec(output_spec),
                encrypt: false,
                generated_stage: false,
                auth_stage: flags.0 & CkFlags::END_OF_MESSAGE.0 != 0,
                rv: output.ck_rv,
            },
        );
        Ok((output, parameter, effects))
    }

    fn sign_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        data_part: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        self.sign_message_next_exact_msg_impl(
            session,
            msg_param,
            self.resolve_input(data_part)?,
            output_spec,
        )
    }

    fn wrap_key_authenticated_exact(
        &self,
        s: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.record_wrap_entry(
            MockWrapEntry::AuthenticatedExact,
            s,
            mechanism,
            wrapping_key,
            key,
            Some(output_spec),
            Some(aad),
        )?;
        let _ = self.resolve_input(aad)?;
        self.require_mechanism_workflow_for_session(s, mechanism, CkMechanismFlags::WRAP)?;
        let state = self.state.lock().unwrap();
        self.require_live_keys(&state, s, &[wrapping_key, key])?;
        self.wrap_key_authenticated_exact_impl(output_spec, param_out_spec)
    }

    fn digest_encrypt_update(
        &self,
        s: CkSessionHandle,
        part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.require_open_session(s)?;
        self.combined_update(self.resolve_input(part)?)
    }

    fn decrypt_digest_update(
        &self,
        s: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.require_open_session(s)?;
        self.combined_update(self.resolve_input(encrypted_part)?)
    }

    fn sign_encrypt_update(&self, s: CkSessionHandle, part: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.require_open_session(s)?;
        self.combined_update(self.resolve_input(part)?)
    }

    fn decrypt_verify_update(
        &self,
        s: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.require_open_session(s)?;
        self.combined_update(self.resolve_input(encrypted_part)?)
    }

    fn login_user(
        &self,
        session: CkSessionHandle,
        _user_type: CkUserType,
        username: Option<&[u8]>,
        pin: Option<&[u8]>,
    ) -> CkResult<()> {
        self.login_user_calls.fetch_add(1, Ordering::SeqCst);
        self.login_user_presence.lock().unwrap().push((username.is_none(), pin.is_none()));
        // W1-C1-02 test gate: same enter/block contract as the `login` gate —
        // clone the handles out from under the gate lock, then signal + block
        // WITHOUT holding that lock.
        let gate = self
            .login_user_gate
            .lock()
            .unwrap()
            .as_ref()
            .map(|g| (g.entered.clone(), Arc::clone(&g.proceed)));
        if let Some((entered, proceed)) = gate {
            let _ = entered.send(());
            let (lock, cv) = &*proceed;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = cv.wait(released).unwrap();
            }
        }
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        // A NULL (protected-path) PIN carries no verifiable bytes, so the
        // mock cannot accept it; only the exact test PIN succeeds.
        if pin.is_some_and(|p| p == b"1234") { Ok(()) } else { Err(CkRv::PIN_INCORRECT) }
    }

    fn session_cancel(&self, session: CkSessionHandle, _flags: CkFlags) -> CkResult<()> {
        if let Some(result) = self.run_message_lifecycle_action() {
            return result;
        }
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
        template: Option<&[CkAttribute]>,
        ciphertext: CkInBuf<'_>,
    ) -> CkResult<CkObjectHandle> {
        self.record_mechanism_entry(MockMechanismEntry::DecapsulateKey, Some(mechanism));
        let _ = self.resolve_input(ciphertext)?;
        self.require_mechanism_workflow_for_session(
            session,
            mechanism,
            CkMechanismFlags::DECAPSULATE,
        )?;
        let mut state = self.state.lock().unwrap();
        self.require_live_key(&state, session, private_key)?;
        self.allocate_session_object_with_template(&mut state, session, template.unwrap_or(&[]))
    }

    fn message_encrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        _init_param: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        if let Some(result) = self.run_message_lifecycle_action() {
            return result;
        }
        let state = self.state.lock().unwrap();
        self.require_live_key_for_optional_mechanism_workflow(
            &state,
            session,
            mechanism,
            key,
            CkMechanismFlags::MESSAGE_ENCRYPT,
        )
    }

    fn message_encrypt_init_contract(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        init_param: Option<&MessageParameter>,
        key: CkObjectHandle,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.message_init_contract_calls.fetch_add(1, Ordering::SeqCst);
        self.message_encrypt_init(session, Some(mechanism), init_param, key)?;
        if let Some(parameter) = init_param {
            parameter.validate_structured()?;
            *self.message_init_contract.lock().unwrap() =
                Some((parameter.clone(), provider_spec.clone()));
        } else {
            *self.message_init_contract.lock().unwrap() = None;
        }
        Ok(CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        })
    }

    fn encrypt_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: CkInBuf<'_>,
        plaintext: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        let _ = self.resolve_input(aad)?;
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok((parameter.to_vec().into(), Self::xor_bytes(self.resolve_input(plaintext)?).into()))
    }

    fn encrypt_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.message_begin_calls.fetch_add(1, Ordering::SeqCst);
        let _ = self.resolve_input(aad)?;
        if self.state.lock().unwrap().has_session(session) {
            Ok(parameter.to_vec().into())
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    fn encrypt_message_begin_exact(
        &self,
        session: CkSessionHandle,
        aad: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.message_begin_calls.fetch_add(1, Ordering::SeqCst);
        let _ = self.resolve_input(aad)?;
        if provider_spec.value.is_some()
            || (provider_spec.buffer_present && provider_spec.buffer_len > 0)
        {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok(CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        })
    }

    fn encrypt_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        plaintext_part: CkInBuf<'_>,
        _flags: CkFlags,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok((parameter.to_vec().into(), Self::xor_bytes(self.resolve_input(plaintext_part)?).into()))
    }

    fn message_encrypt_final(&self, session: CkSessionHandle) -> CkResult<()> {
        if let Some(result) = self.run_message_lifecycle_action() {
            return result;
        }
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
        _init_param: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        if let Some(result) = self.run_message_lifecycle_action() {
            return result;
        }
        let state = self.state.lock().unwrap();
        self.require_live_key_for_optional_mechanism_workflow(
            &state,
            session,
            mechanism,
            key,
            CkMechanismFlags::MESSAGE_DECRYPT,
        )
    }

    fn message_decrypt_init_contract(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        init_param: Option<&MessageParameter>,
        key: CkObjectHandle,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.message_init_contract_calls.fetch_add(1, Ordering::SeqCst);
        self.message_decrypt_init(session, Some(mechanism), init_param, key)?;
        if let Some(parameter) = init_param {
            parameter.validate_structured()?;
            *self.message_init_contract.lock().unwrap() =
                Some((parameter.clone(), provider_spec.clone()));
        } else {
            *self.message_init_contract.lock().unwrap() = None;
        }
        Ok(CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        })
    }

    fn decrypt_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: CkInBuf<'_>,
        ciphertext: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        let _ = self.resolve_input(aad)?;
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok((parameter.to_vec().into(), Self::xor_bytes(self.resolve_input(ciphertext)?).into()))
    }

    fn decrypt_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.message_begin_calls.fetch_add(1, Ordering::SeqCst);
        let _ = self.resolve_input(aad)?;
        if self.state.lock().unwrap().has_session(session) {
            Ok(parameter.to_vec().into())
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    fn decrypt_message_begin_exact(
        &self,
        session: CkSessionHandle,
        aad: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.encrypt_message_begin_exact(session, aad, provider_spec)
    }

    fn decrypt_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        ciphertext_part: CkInBuf<'_>,
        _flags: CkFlags,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok((
            parameter.to_vec().into(),
            Self::xor_bytes(self.resolve_input(ciphertext_part)?).into(),
        ))
    }

    fn message_decrypt_final(&self, session: CkSessionHandle) -> CkResult<()> {
        if let Some(result) = self.run_message_lifecycle_action() {
            return result;
        }
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
        data: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok((parameter.to_vec().into(), Self::reverse_bytes(self.resolve_input(data)?).into()))
    }

    fn sign_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
    ) -> CkResult<SecretBytes> {
        if self.state.lock().unwrap().has_session(session) {
            Ok(parameter.to_vec().into())
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    fn sign_message_begin_exact(
        &self,
        session: CkSessionHandle,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.message_parameter_calls.fetch_add(1, Ordering::SeqCst);
        if provider_spec.value.is_some()
            || (provider_spec.buffer_present && provider_spec.buffer_len > 0)
        {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok(CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        })
    }

    fn sign_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        data_part: CkInBuf<'_>,
        request_signature: bool,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        let data_part = self.resolve_input(data_part)?;
        let signature = if request_signature { Self::reverse_bytes(data_part) } else { Vec::new() };
        Ok((parameter.to_vec().into(), signature.into()))
    }

    fn sign_message_next_feed_exact(
        &self,
        session: CkSessionHandle,
        data_part: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.message_parameter_calls.fetch_add(1, Ordering::SeqCst);
        let _ = self.resolve_input(data_part)?;
        if provider_spec.value.is_some()
            || (provider_spec.buffer_present && provider_spec.buffer_len > 0)
        {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok(CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        })
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
        data: CkInBuf<'_>,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        let data = self.resolve_input(data)?;
        let signature = self.resolve_input(signature)?;
        if signature == Self::reverse_bytes(data) { Ok(()) } else { Err(CkRv::SIGNATURE_INVALID) }
    }

    fn verify_message_exact(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        signature: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.message_parameter_calls.fetch_add(1, Ordering::SeqCst);
        let data = self.resolve_input(data)?;
        let signature = self.resolve_input(signature)?;
        if provider_spec.value.is_some()
            || (provider_spec.buffer_present && provider_spec.buffer_len > 0)
        {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        if signature != Self::reverse_bytes(data) {
            return Err(CkRv::SIGNATURE_INVALID);
        }
        Ok(CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        })
    }

    fn verify_message_begin(&self, session: CkSessionHandle, _parameter: &[u8]) -> CkResult<()> {
        if self.state.lock().unwrap().has_session(session) {
            Ok(())
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    fn verify_message_begin_exact(
        &self,
        session: CkSessionHandle,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.message_parameter_calls.fetch_add(1, Ordering::SeqCst);
        if provider_spec.value.is_some()
            || (provider_spec.buffer_present && provider_spec.buffer_len > 0)
        {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok(CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        })
    }

    fn verify_message_next(
        &self,
        session: CkSessionHandle,
        _parameter: &[u8],
        data_part: CkInBuf<'_>,
        is_final: bool,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        let data_part = self.resolve_input(data_part)?;
        let signature = self.resolve_input(signature)?;
        if !is_final || signature == Self::reverse_bytes(data_part) {
            Ok(())
        } else {
            Err(CkRv::SIGNATURE_INVALID)
        }
    }

    fn verify_message_next_exact(
        &self,
        session: CkSessionHandle,
        data_part: CkInBuf<'_>,
        is_final: bool,
        signature: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        self.message_parameter_calls.fetch_add(1, Ordering::SeqCst);
        let data = self.resolve_input(data_part)?;
        let signature = self.resolve_input(signature)?;
        if provider_spec.value.is_some()
            || (provider_spec.buffer_present && provider_spec.buffer_len > 0)
        {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        if is_final && signature != Self::reverse_bytes(data) {
            return Err(CkRv::SIGNATURE_INVALID);
        }
        Ok(CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        })
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
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        self.record_mechanism_entry(
            if mechanism.is_some() {
                MockMechanismEntry::VerifySignatureInit
            } else {
                MockMechanismEntry::VerifySignatureCancel
            },
            mechanism,
        );
        let state = self.state.lock().unwrap();
        self.require_live_key_for_optional_mechanism_workflow(
            &state,
            session,
            mechanism,
            key,
            CkMechanismFlags::VERIFY,
        )?;
        drop(state);
        let signature = self.resolve_input(signature)?;
        self.verify_signature_state.lock().unwrap().insert(session.0, signature.to_vec());
        self.verify_signature_accumulator.lock().unwrap().remove(&session.0);
        Ok(())
    }

    fn verify_signature(&self, session: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<()> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        let data = self.resolve_input(data)?;
        let signatures = self.verify_signature_state.lock().unwrap();
        let Some(signature) = signatures.get(&session.0) else {
            return Err(CkRv::OPERATION_NOT_INITIALIZED);
        };
        if data == Self::reverse_bytes(signature) { Ok(()) } else { Err(CkRv::SIGNATURE_INVALID) }
    }

    fn verify_signature_update(
        &self,
        session: CkSessionHandle,
        data_part: CkInBuf<'_>,
    ) -> CkResult<()> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        if !self.verify_signature_state.lock().unwrap().contains_key(&session.0) {
            return Err(CkRv::OPERATION_NOT_INITIALIZED);
        }
        let data_part = self.resolve_input(data_part)?;
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

    fn wrap_key_authenticated_typed(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        parameter: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput)>
    {
        let output = self.authenticated_output(mechanism, parameter)?;
        let (bytes, _) = self.wrap_key_authenticated(session, mechanism, wrapping_key, key, aad)?;
        Ok((bytes, output))
    }

    fn wrap_key_authenticated_exact_typed(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        parameter: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput,
    )> {
        let output = self.authenticated_output(mechanism, parameter)?;
        let (bytes, _) = self.wrap_key_authenticated_exact(
            session,
            mechanism,
            wrapping_key,
            key,
            aad,
            spec,
            &CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None },
        )?;
        use pkcs11_proxy_ng_proto::convert::{
            authenticated::AuthenticatedOutput,
            message_effects::{MessageEffectContext, MessageEffects},
        };
        let output = match (parameter, output) {
            (Some(input), AuthenticatedOutput::Message(returned)) => {
                AuthenticatedOutput::Effects(MessageEffects::capture(
                    input,
                    &returned,
                    MessageEffectContext {
                        mode: ParameterEffectCallMode::from_output_spec(spec),
                        encrypt: true,
                        generated_stage: true,
                        auth_stage: true,
                        rv: bytes.ck_rv,
                    },
                ))
            }
            (_, output) => output,
        };
        Ok((bytes, output))
    }

    fn unwrap_key_authenticated_typed(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        parameter: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
        unwrapping_key: CkObjectHandle,
        wrapped_key: CkInBuf<'_>,
        template: Option<&[CkAttribute]>,
        aad: CkInBuf<'_>,
    ) -> CkResult<(
        CkObjectHandle,
        pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput,
    )> {
        let output = self.authenticated_output(mechanism, parameter)?;
        let (key, _) = self.unwrap_key_authenticated(
            session,
            mechanism,
            unwrapping_key,
            wrapped_key,
            template,
            aad,
        )?;
        if let Some(rv) = self.authenticated_unwrap_fault.lock().unwrap().take() {
            *self.destroy_error.lock().unwrap() = (rv != CkRv::OK).then_some(rv);
            return Ok((
                key,
                pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput::Iv(
                    Vec::new().into(),
                ),
            ));
        }
        Ok((key, output))
    }

    fn wrap_key_authenticated(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        self.record_wrap_entry(
            MockWrapEntry::Authenticated,
            session,
            mechanism,
            wrapping_key,
            key,
            None,
            Some(aad),
        )?;
        let _ = self.resolve_input(aad)?;
        self.require_mechanism_workflow_for_session(session, mechanism, CkMechanismFlags::WRAP)?;
        let state = self.state.lock().unwrap();
        self.require_live_keys(&state, session, &[wrapping_key, key])?;
        Ok((self.wrap_key_impl()?.into(), vec![0xCC; 12].into()))
    }

    fn unwrap_key_authenticated(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        unwrapping_key: CkObjectHandle,
        wrapped_key: CkInBuf<'_>,
        template: Option<&[CkAttribute]>,
        aad: CkInBuf<'_>,
    ) -> CkResult<(CkObjectHandle, SecretBytes)> {
        self.record_wrap_entry(
            MockWrapEntry::UnwrapAuthenticated,
            session,
            mechanism,
            unwrapping_key,
            CkObjectHandle(0),
            None,
            Some(aad),
        )?;
        let _ = self.resolve_input(wrapped_key)?;
        let _ = self.resolve_input(aad)?;
        self.require_mechanism_workflow_for_session(session, mechanism, CkMechanismFlags::UNWRAP)?;
        let mut state = self.state.lock().unwrap();
        self.require_live_key(&state, session, unwrapping_key)?;
        Ok((
            self.allocate_session_object_with_template(
                &mut state,
                session,
                template.unwrap_or(&[]),
            )?,
            vec![0xCC; 12].into(),
        ))
    }

    fn async_complete(
        &self,
        session: CkSessionHandle,
        _function_name: &str,
    ) -> CkResult<(u64, SecretBytes, u64, CkObjectHandle, CkObjectHandle)> {
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok((1, vec![0xA5; 8].into(), 8, CkObjectHandle(0), CkObjectHandle(0)))
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
    ) -> CkResult<SecretBytes> {
        if self.state.lock().unwrap().has_session(session) {
            Ok(vec![0xA5; 8].into())
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
