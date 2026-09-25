use super::handle_map::{BackendHandle, HandleMap, VirtualHandle};
use super::slot_map::{BackendSlotId, SlotMap, VirtualSlotId};
use dashmap::DashMap;
use pkcs11_proxy_ng_proto::convert::message_params::MessageParameterShape;
use pkcs11_proxy_ng_types::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};
use uuid::Uuid;

/// Opaque context identifier (ADR-0002 §3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientContextId(pub String);

impl ClientContextId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

/// Per-context login state for a single token (ADR-0002 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoginState {
    Public,
    User,
    So,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum MessageOperation {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
}

#[derive(Debug, Default)]
pub(crate) struct MessageOperationState {
    pub(crate) shape: Option<MessageParameterShape>,
}

/// Owns one message-operation state transition across the actual blocking
/// provider call.  The state is hidden while the transition is in flight.
/// Dropping before invocation restores it; dropping after invocation without
/// an explicit outcome (for example, provider panic) clears it fail-closed.
pub(crate) struct MessageOperationTransition {
    state: OwnedMutexGuard<MessageOperationState>,
    saved_shape: Option<MessageParameterShape>,
    started: bool,
    settled: bool,
}

impl MessageOperationTransition {
    pub(crate) fn begin(mut state: OwnedMutexGuard<MessageOperationState>) -> Self {
        let saved_shape = state.shape.take();
        Self { state, saved_shape, started: false, settled: false }
    }

    pub(crate) fn mark_started(&mut self) {
        self.started = true;
    }

    pub(crate) fn settle<T>(
        &mut self,
        result: &CkResult<T>,
        successful_shape: Option<MessageParameterShape>,
    ) {
        self.state.shape = match result {
            Ok(_) => successful_shape,
            Err(error) if *error == CkRv::DEVICE_ERROR => None,
            Err(_) => self.saved_shape,
        };
        self.settled = true;
    }

    pub(crate) fn settle_ambiguous(&mut self) {
        self.state.shape = None;
        self.settled = true;
    }
}

impl Drop for MessageOperationTransition {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        self.state.shape = if self.started { None } else { self.saved_shape };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseSessionBeginError {
    ContextMissing,
    SessionMissing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseSessionCompletion {
    Terminal,
    Transient,
    Ambiguous,
}

/// Completion token for a suspended session close.  It is moved into the
/// blocking provider closure so timeout/cancellation of the async handler
/// cannot strand or prematurely reactivate the virtual handle.
pub(crate) struct CloseSessionTransition {
    manager: Arc<ContextManager>,
    context_id: ClientContextId,
    virtual_session: VirtualHandle,
    backend_handle: BackendHandle,
    _operation_guard: OperationGuard,
    started: bool,
    settled: bool,
}

impl CloseSessionTransition {
    pub(crate) fn backend_handle(&self) -> BackendHandle {
        self.backend_handle
    }

    pub(crate) fn mark_started(&mut self) {
        self.started = true;
    }

    pub(crate) fn settle(&mut self, result: &CkResult<()>) {
        let completion = match result {
            Ok(()) => CloseSessionCompletion::Terminal,
            Err(error)
                if *error == CkRv::SESSION_CLOSED || *error == CkRv::SESSION_HANDLE_INVALID =>
            {
                CloseSessionCompletion::Terminal
            }
            Err(error) if *error == CkRv::DEVICE_ERROR => CloseSessionCompletion::Ambiguous,
            Err(_) => CloseSessionCompletion::Transient,
        };
        self.manager.complete_close_session(
            &self.context_id,
            self.virtual_session,
            self.backend_handle,
            completion,
        );
        self.settled = true;
    }
}

impl Drop for CloseSessionTransition {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let completion = if self.started {
            CloseSessionCompletion::Ambiguous
        } else {
            CloseSessionCompletion::Transient
        };
        self.manager.complete_close_session(
            &self.context_id,
            self.virtual_session,
            self.backend_handle,
            completion,
        );
    }
}

/// Cached object metadata for the per-object / per-class authorization gate (G3).
///
/// Fetched in a single `C_GetAttributeValue` round-trip covering
/// `CKA_UNIQUE_ID`, `CKA_CLASS`, and `CKA_TOKEN`. Session objects
/// (`is_token = false`) are cached for the virtual handle's lifetime; token
/// objects are cached gated by the authz generation (W1-L13-18) so gated
/// reuse avoids a backend round-trip without stale-authz risk (the I2
/// never-cache rule it replaces; ADR-0012 §G3).
#[derive(Debug, Clone)]
pub struct ObjectMetadata {
    /// `CKA_UNIQUE_ID` bytes (ADR-0013: attribute values are secret-classified
    /// and fail closed). Wiping owner; cached copies wipe on eviction, and
    /// the derived `Debug` redacts via `SecretBytes`.
    pub unique_id: SecretBytes,
    /// `None` when `CKA_CLASS` is absent or unparseable (M2: uid-only deployments must not
    /// fail on a missing class attribute). Class-confined gates treat `None` as fail-closed
    /// (deny); uid-only deployments ignore this field entirely.
    pub class: Option<CkObjectClass>,
    pub is_token: bool,
}

/// Raw per-attribute backend result stored by the session-scoped coalescer (R2).
///
/// Captures both the value bytes and the `CK_RV` so the coalescer can faithfully
/// replay the exact backend response — including attribute-level errors — without
/// a second backend round-trip.
#[derive(Debug, Clone)]
pub struct CachedAttr {
    /// Raw attribute value bytes as returned by the backend (may be empty on error).
    ///
    /// A wiping owner (ADR-0013 §2): attribute fields are polymorphic and
    /// vendor-defined types fail closed to secret, so even though the
    /// coalescer declines to cache known-secret types, whatever IS cached
    /// (including vendor-unknown values) wipes on eviction/session drop.
    pub value: SecretBytes,
    /// The raw `CK_RV` returned by the backend for this attribute.
    pub ck_rv: u64,
}

/// Token-object metadata tagged with the authz generation that fetched it
/// (W1-L13-18). Reusable only while `generation` equals the manager's
/// current generation; older entries are stale and must be re-fetched.
#[derive(Debug, Clone)]
pub struct GatedObjectMetadata {
    /// Daemon-wide authz generation at fetch time.
    pub generation: u64,
    /// The fetched metadata.
    pub meta: ObjectMetadata,
}

/// A logical client instance — the server-side PKCS#11 "application" (ADR-0002).
pub struct LogicalClientInstance {
    pub id: ClientContextId,
    pub created_at: Instant,
    pub last_active: Instant,
    pub session_handles: HandleMap, // virtual session → backend session
    pub session_slots: HashMap<VirtualHandle, BackendSlotId>, // session → slot ownership (ADR-0002 §7)
    pub object_handles: HandleMap,                            // virtual object → backend object
    /// Per-virtual-object cached `ObjectMetadata` (G3). **Only session objects
    /// (`CKA_TOKEN=false`) are cached here** — their lifetime is tied to the
    /// owning session, so per-handle eviction suffices. Token objects live in
    /// [`LogicalClientInstance::token_object_metadata`], gated by the
    /// daemon-wide authz generation (W1-L13-18).
    ///
    /// Entries are evicted wherever `object_handles` entries are removed —
    /// on explicit `C_DestroyObject`, on session close (for session objects),
    /// and on context teardown — so a recycled virtual handle can never return
    /// stale metadata within one context.
    pub object_metadata: HashMap<VirtualHandle, ObjectMetadata>,
    /// Per-virtual-object cached token-object `ObjectMetadata` (W1-L13-18),
    /// each tagged with the authz generation that fetched it. An entry is
    /// reusable only while its generation is current; any daemon-wide object
    /// mutation (`C_DestroyObject`, `C_InitToken`) revokes the generation, so
    /// a cross-client backend handle recycling event cannot cause a stale
    /// authorization decision (the I2 never-cache rule, made generational).
    ///
    /// Evicted in the SAME removal hooks as `object_metadata` (per-handle
    /// removal on session close and on `C_DestroyObject`, plus full teardown).
    pub token_object_metadata: HashMap<VirtualHandle, GatedObjectMetadata>,
    /// Virtual object handles created as SESSION objects (CKA_TOKEN=false) in
    /// each virtual session. Evicted when that session closes so a recycled
    /// backend object number can never alias a stale handle (B2). Token objects
    /// are intentionally absent — their handles persist across the application's
    /// sessions.
    pub session_objects: HashMap<VirtualHandle, Vec<VirtualHandle>>,
    pub login_state: HashMap<BackendSlotId, LoginState>, // per-token login
    pub authenticated_identity: Option<String>,          // bound at creation (ADR-0005 §4)
    /// Virtual object handles minted by this context (via generate/wrap/create,
    /// NOT via find). Used by `gate_object_handle` to allow a principal to use
    /// keys it generated, even when its `objects` grant does not list the new
    /// object's `CKA_UNIQUE_ID` (which is backend-assigned and therefore
    /// unknown at configuration time).
    ///
    /// Entries are evicted in the SAME removal hooks that evict `object_metadata`
    /// (per-handle removal on session close and on `C_DestroyObject`, plus full
    /// teardown) so a recycled virtual handle cannot inherit created-status from
    /// a prior object.
    ///
    /// FIND results (`register_object_handles`) are intentionally NOT inserted
    /// here — only minting operations insert.
    pub created_objects: HashSet<VirtualHandle>,
    /// Template-declared `CKA_PRIVATE` bit per virtual object handle, recorded
    /// at mint time (create/copy/generate/derive/unwrap/encapsulate/decapsulate)
    /// for the D6(1) logical-login enforcement. `true` = known-private (refuse
    /// USE while logged out without a backend probe); `false` = known-public
    /// (proceed without a probe). ABSENT = unknown (find results and
    /// backend-minted mechanism-out handles, which carry no client template):
    /// logged-out USE probes `CKA_PRIVATE` from the backend once per operation.
    /// `CKA_PRIVATE` is immutable after creation, so a recorded bit never goes
    /// stale within the handle's lifetime.
    ///
    /// Entries are evicted in the SAME removal hooks as `object_metadata` and
    /// `created_objects` (per-handle removal on session close and on
    /// `C_DestroyObject`, plus full teardown) so a recycled virtual handle
    /// cannot inherit a stale privacy bit.
    pub object_private: HashMap<VirtualHandle, bool>,
    /// Session-scoped attribute result cache (R2 coalescer).
    ///
    /// Keys are `(virtual object handle, attribute type)`. Entries are evicted
    /// in the SAME hooks that evict `object_metadata` and `created_objects`
    /// (per-handle removal on session close and `C_DestroyObject`, plus full
    /// teardown) so a recycled virtual handle can never return stale cached
    /// attributes within one context. The map is always allocated; it is only
    /// populated when `resilience::coalesce_enabled()` is `true` (Task 2 wires
    /// the serving path).
    pub attr_cache: HashMap<(VirtualHandle, CkAttributeType), CachedAttr>,
    /// Count of backend operations currently in flight for this context.
    /// Eviction never reaps a context with `in_flight > 0`, so a single
    /// long backend call (DH/RSA keygen, slow-HSM op) is not evicted MID-CALL
    /// even when it outlasts the lease. `Arc` so an `OperationGuard` can hold
    /// and decrement it after the DashMap shard lock is released.
    pub in_flight: Arc<AtomicI64>,
    /// Per-virtual-session message-operation serialization/state. The owned
    /// Tokio guard can travel into a blocking backend closure, so timeout of
    /// the gRPC future cannot release this state while the provider still runs.
    pub(crate) message_operations:
        HashMap<(VirtualHandle, MessageOperation), Arc<Mutex<MessageOperationState>>>,
}

impl LogicalClientInstance {
    pub fn new(identity: Option<String>) -> Self {
        let now = Instant::now();
        Self {
            id: ClientContextId::generate(),
            created_at: now,
            last_active: now,
            session_handles: HandleMap::new(),
            session_slots: HashMap::new(),
            object_handles: HandleMap::new(),
            object_metadata: HashMap::new(),
            token_object_metadata: HashMap::new(),
            session_objects: HashMap::new(),
            created_objects: HashSet::new(),
            object_private: HashMap::new(),
            attr_cache: HashMap::new(),
            login_state: HashMap::new(),
            authenticated_identity: identity,
            in_flight: Arc::new(AtomicI64::new(0)),
            message_operations: HashMap::new(),
        }
    }

    pub fn touch(&mut self) {
        self.last_active = Instant::now();
    }

    /// Register a session with its owning slot (ADR-0002 §7).
    pub fn register_session(
        &mut self,
        backend: BackendHandle,
        slot: BackendSlotId,
    ) -> VirtualHandle {
        let virt = self.session_handles.insert(backend);
        self.session_slots.insert(virt, slot);
        virt
    }

    /// Remove sessions for a specific slot. Returns backend handles to close.
    pub fn remove_sessions_for_slot(&mut self, slot: BackendSlotId) -> Vec<BackendHandle> {
        let to_remove: Vec<VirtualHandle> =
            self.session_slots.iter().filter(|(_, s)| **s == slot).map(|(vh, _)| *vh).collect();

        let mut backend_handles = Vec::with_capacity(to_remove.len());
        for vh in to_remove {
            self.session_slots.remove(&vh);
            self.message_operations.retain(|(session, _), _| *session != vh);
            // Evict each closed session's session objects (B2) together with
            // their cached unique IDs so recycled virtual handles cannot return
            // stale ids. Also evict the created-set entries so a recycled
            // virtual handle cannot inherit created-status.
            if let Some(objects) = self.session_objects.remove(&vh) {
                for object in objects {
                    self.object_handles.remove(object);
                    self.object_metadata.remove(&object);
                    self.token_object_metadata.remove(&object);
                    self.created_objects.remove(&object);
                    self.object_private.remove(&object);
                    // Evict all cached attribute entries for this object (R2). Mirrors
                    // the object_metadata + created_objects eviction so a recycled
                    // virtual handle cannot return stale cached attributes.
                    self.attr_cache.retain(|(attr_vh, _), _| *attr_vh != object);
                }
            }
            if let Some(bh) = self.session_handles.remove(vh) {
                backend_handles.push(bh);
            }
        }
        self.login_state.remove(&slot);
        backend_handles
    }

    /// Record `object` as a session object (CKA_TOKEN=false) created in
    /// `session`, so its virtual handle is evicted when that session closes (B2).
    pub fn record_session_object(&mut self, session: VirtualHandle, object: VirtualHandle) {
        self.session_objects.entry(session).or_default().push(object);
    }

    /// Remove one session. If it was the final session this logical client
    /// held for the slot, clear the corresponding logical login state.
    pub fn remove_session(&mut self, session: VirtualHandle) -> Option<BackendHandle> {
        let slot = self.session_slots.remove(&session);
        let backend_handle = self.session_handles.remove(session);
        self.message_operations.retain(|(owned_session, _), _| *owned_session != session);
        // Evict the session's session objects: the backend destroys them on
        // close, so the virtual handles must not linger and alias a recycled
        // backend object number (B2).  Cached unique IDs and created-set
        // entries are evicted alongside object handles so a recycled virtual
        // handle cannot return stale metadata or inherit created-status.
        if let Some(objects) = self.session_objects.remove(&session) {
            for object in objects {
                self.object_handles.remove(object);
                self.object_metadata.remove(&object);
                self.token_object_metadata.remove(&object);
                self.created_objects.remove(&object);
                self.object_private.remove(&object);
                // Evict all cached attribute entries for this object (R2). Mirrors
                // the object_metadata + created_objects eviction so a recycled
                // virtual handle cannot return stale cached attributes.
                self.attr_cache.retain(|(attr_vh, _), _| *attr_vh != object);
            }
        }
        if let Some(slot) = slot {
            let has_remaining_session_for_slot = self.session_slots.values().any(|s| *s == slot);
            if !has_remaining_session_for_slot {
                self.login_state.remove(&slot);
            }
        }
        backend_handle
    }

    /// Prepare teardown: collect backend session handles, then clear maps.
    /// Returns the backend session handles that must be closed via the
    /// backend trait. The CALLER is responsible for calling
    /// backend.close_session() for each.
    pub fn teardown(&mut self) -> Vec<u64> {
        let backend_sessions: Vec<u64> =
            self.session_handles.backend_handles().map(|backend| backend.0).collect();
        self.session_handles.clear();
        self.session_slots.clear();
        self.object_handles.clear();
        self.object_metadata.clear();
        self.token_object_metadata.clear();
        self.session_objects.clear();
        self.created_objects.clear();
        self.object_private.clear();
        self.attr_cache.clear();
        self.login_state.clear();
        self.message_operations.clear();
        backend_sessions
    }
}

/// One slot needing a last-holder backend logout at teardown (D6(2)/D9).
#[derive(Debug, Clone, Copy)]
pub struct SlotLogout {
    /// Slot whose shared backend login must be released.
    pub slot: BackendSlotId,
    /// A backend session on that slot, open at plan time, to carry the
    /// `C_Logout` call. Best-effort: the executor substitutes a live session
    /// when this one raced shut.
    pub via_session: u64,
}

/// Backend actions required to tear down one departed context (D6(2)/D9
/// shared tenancy model). Computed by
/// [`ContextManager::plan_removed_context_teardown`] after the context leaves
/// the live map, so every liveness probe inside observes only live tenants.
#[derive(Debug, Default)]
pub struct ContextTeardownPlan {
    /// Departing context's backend sessions that are safe to close: each is
    /// unreferenced by every live context (refcount check — sessions are
    /// per-context owned, so this is normally all of them).
    pub sessions_to_close: Vec<u64>,
    /// Slots where the departing context held the last logical login: each
    /// needs one real backend `C_Logout`, executed BEFORE the sessions close.
    pub slot_logouts: Vec<SlotLogout>,
}

/// Manages all active logical client instances (ADR-0002 §3, §9, §10).
///
/// The `contexts` map is a `DashMap` (sharded concurrent hashmap) rather
/// than `RwLock<HashMap>` so that concurrent RPC handlers touching
/// *different* `ClientContextId` shards don't serialize on a global
/// write lock. The single-key critical section (insert / remove / a
/// `get_mut` callback) is still atomic via per-shard locking.
pub struct ContextManager {
    contexts: Arc<DashMap<ClientContextId, LogicalClientInstance>>,
    slot_map: Arc<RwLock<SlotMap>>,
    lease_duration: std::time::Duration,
    max_contexts: usize,
    /// Cache of `(label, serial)` per backend slot, captured when the daemon
    /// last read `C_GetTokenInfo` for an authorization check (M9). Authorization
    /// is otherwise a blocking backend call on every discovery/open. Entries are
    /// invalidated explicitly on slot re-registration AND expire after
    /// `TOKEN_INFO_CACHE_TTL`, so a token swapped without a re-registration is
    /// re-read within at most the TTL — the cache never authorizes against a
    /// token-identity older than that.
    token_info_cache: Arc<DashMap<BackendSlotId, (Instant, String, String)>>,
    /// Per-slot serialization lock for login/logout (M5). The cross-context
    /// login-state scan, the backend `C_Login`, and the `login_state` insert
    /// must be atomic per slot. Without it, two clients racing the FIRST login
    /// on a shared token both observe "no other login", both take the real
    /// `C_Login` path, and the second is answered `USER_ALREADY_LOGGED_IN` by
    /// the already-logged-in token instead of the synthesized logical OK. One
    /// lock per slot id; different slots log in concurrently.
    login_locks: Arc<DashMap<BackendSlotId, Arc<Mutex<()>>>>,
    /// Daemon-wide authz generation (W1-L13-18). Cached token-object metadata
    /// is tagged with the generation at fetch time and reusable only while
    /// current. Revoked (bumped) by every daemon-wide object mutation —
    /// `C_DestroyObject` and `C_InitToken` — so a cross-client backend handle
    /// recycling event can never validate a stale cached entry.
    authz_generation: AtomicU64,
    /// Outstanding per-principal session-quota reservations (W1-L6-04):
    /// opens that passed the quota check but have not registered yet.
    /// The quota check-and-reserve is atomic under this mutex, so
    /// concurrent opens cannot exceed the cap. Entries are removed when
    /// their count reaches zero, keeping the map bounded by the number of
    /// principals with in-flight opens.
    ///
    /// Lock order: quota mutex OUTER, contexts-DashMap shard guards INNER
    /// (transient, inside `session_count_for_principal`). Never acquire
    /// this mutex while holding a contexts guard.
    session_quota_reservations: Arc<std::sync::Mutex<HashMap<String, usize>>>,
}

/// Maximum age of a cached `(label, serial)` before an authorization check
/// re-reads `C_GetTokenInfo`. Bounds the staleness of token-policy decisions
/// after an undetected runtime token change (M9).
const TOKEN_INFO_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// RAII guard marking a backend operation in flight for one context. While it
/// lives, eviction skips that context (see `ContextManager::begin_operation`).
#[derive(Clone)]
pub struct OperationGuard {
    inner: Arc<OperationGuardInner>,
}

struct OperationGuardInner {
    manager: Arc<ContextManager>,
    id: ClientContextId,
    counter: Arc<AtomicI64>,
}

impl OperationGuard {
    fn new(manager: Arc<ContextManager>, id: ClientContextId, counter: Arc<AtomicI64>) -> Self {
        Self { inner: Arc::new(OperationGuardInner { manager, id, counter }) }
    }

    pub(crate) fn belongs_to(&self, manager: &Arc<ContextManager>, id: &ClientContextId) -> bool {
        Arc::ptr_eq(&self.inner.manager, manager) && self.inner.id == *id
    }
}

impl Drop for OperationGuardInner {
    fn drop(&mut self) {
        // Refresh last_active before publishing in_flight=0 and hold the DashMap
        // shard lock through the decrement.  Otherwise the reaper can remove the
        // context in the decrement-to-touch window after a long backend call.
        if let Some(mut ctx) = self.manager.contexts.get_mut(&self.id) {
            ctx.touch();
            self.counter.fetch_sub(1, Ordering::Relaxed);
        } else {
            self.counter.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// One outstanding per-principal session-quota slot (W1-L6-04), minted by
/// [`ContextManager::try_reserve_session_for_principal`]. Dropping it
/// releases the slot (the entry is removed at zero, bounding the map).
pub(crate) struct SessionQuotaReservation {
    reservations: Arc<std::sync::Mutex<HashMap<String, usize>>>,
    principal: String,
}

impl Drop for SessionQuotaReservation {
    fn drop(&mut self) {
        let mut reservations = self.reservations.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = reservations.get_mut(&self.principal) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                reservations.remove(&self.principal);
            }
        }
    }
}

/// Outcome of [`ContextManager::remove_context_if_idle`].
pub enum RemoveIfIdleOutcome {
    /// The context was removed; the caller owns teardown. Boxed: the
    /// instance is large and the other variants are fieldless.
    Removed(Box<LogicalClientInstance>),
    /// The context exists but has foreign operations in flight; it was
    /// left in place and the caller should refuse busy (retryable).
    Busy,
    /// No such context.
    Missing,
}

impl ContextManager {
    pub fn new(lease_duration: std::time::Duration, max_contexts: usize) -> Self {
        Self {
            contexts: Arc::new(DashMap::new()),
            slot_map: Arc::new(RwLock::new(SlotMap::new())),
            lease_duration,
            max_contexts,
            token_info_cache: Arc::new(DashMap::new()),
            login_locks: Arc::new(DashMap::new()),
            authz_generation: AtomicU64::new(0),
            session_quota_reservations: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Current daemon-wide authz generation (W1-L13-18). Token-object
    /// metadata cached under an older generation is stale.
    pub fn authz_generation(&self) -> u64 {
        self.authz_generation.load(Ordering::SeqCst)
    }

    /// Revoke the daemon-wide authz generation (W1-L13-18), invalidating all
    /// cached token-object metadata. Called after every daemon-wide object
    /// mutation (`C_DestroyObject`, `C_InitToken`); session-object entries are
    /// unaffected (their lifetime is per-handle, not generational).
    pub fn revoke_authz_generation(&self) {
        self.authz_generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Per-slot login/logout serialization lock (M5). Acquire it (`.lock().await`)
    /// after resolving the slot and hold it across the cross-context login-state
    /// scan, the backend `C_Login`/`C_Logout`, and the `login_state` mutation, so
    /// concurrent logins on the same shared token cannot both take the real-login
    /// path. The lock is keyed by slot, so different slots are unaffected.
    pub fn slot_login_lock(&self, slot: BackendSlotId) -> Arc<Mutex<()>> {
        self.login_locks.entry(slot).or_insert_with(|| Arc::new(Mutex::new(()))).clone()
    }

    pub(crate) async fn message_operation_lock(
        &self,
        ctx_id: &ClientContextId,
        virtual_session: VirtualHandle,
        operation: MessageOperation,
    ) -> CkResult<Arc<Mutex<MessageOperationState>>> {
        match self
            .get_context(ctx_id, |ctx| {
                if ctx.session_handles.resolve(virtual_session).is_none() {
                    return Err(CkRv::SESSION_HANDLE_INVALID);
                }
                Ok(ctx
                    .message_operations
                    .entry((virtual_session, operation))
                    .or_insert_with(|| Arc::new(Mutex::new(MessageOperationState::default())))
                    .clone())
            })
            .await
        {
            Some(result) => result,
            None => Err(CkRv::CRYPTOKI_NOT_INITIALIZED),
        }
    }

    /// Begin several message-operation transitions in caller-supplied fixed
    /// order.  The returned guards can move into the blocking provider closure
    /// so timeout/cancellation of the async handler cannot release them early.
    pub(crate) async fn begin_message_operation_transitions(
        &self,
        ctx_id: &ClientContextId,
        virtual_session: VirtualHandle,
        operations: &[MessageOperation],
    ) -> CkResult<Vec<MessageOperationTransition>> {
        let mut transitions = Vec::with_capacity(operations.len());
        for operation in operations {
            let state = self.message_operation_lock(ctx_id, virtual_session, *operation).await?;
            transitions.push(MessageOperationTransition::begin(state.lock_owned().await));
        }
        Ok(transitions)
    }

    /// Atomically suspend an active virtual session and return a completion
    /// token.  Suspended handles cannot be resolved by later RPCs.
    #[cfg(test)]
    pub(crate) fn begin_close_session(
        self: &Arc<Self>,
        ctx_id: &ClientContextId,
        virtual_session: VirtualHandle,
    ) -> Result<CloseSessionTransition, CloseSessionBeginError> {
        self.begin_close_session_with_guard(ctx_id, virtual_session, None)
    }

    pub(crate) fn begin_close_session_with_guard(
        self: &Arc<Self>,
        ctx_id: &ClientContextId,
        virtual_session: VirtualHandle,
        inherited_guard: Option<OperationGuard>,
    ) -> Result<CloseSessionTransition, CloseSessionBeginError> {
        let operation_guard = match inherited_guard {
            Some(guard) if guard.belongs_to(self, ctx_id) => guard,
            _ => self.begin_operation(ctx_id).ok_or(CloseSessionBeginError::ContextMissing)?,
        };
        let backend_handle = {
            let mut context =
                self.contexts.get_mut(ctx_id).ok_or(CloseSessionBeginError::ContextMissing)?;
            context
                .session_handles
                .suspend(virtual_session)
                .ok_or(CloseSessionBeginError::SessionMissing)?
        };
        Ok(CloseSessionTransition {
            manager: Arc::clone(self),
            context_id: ctx_id.clone(),
            virtual_session,
            backend_handle,
            _operation_guard: operation_guard,
            started: false,
            settled: false,
        })
    }

    /// Synchronous completion path used from a blocking provider thread.
    /// Mutate only the expected suspended tuple; stale completions are no-ops.
    fn complete_close_session(
        &self,
        ctx_id: &ClientContextId,
        virtual_session: VirtualHandle,
        expected_backend: BackendHandle,
        completion: CloseSessionCompletion,
    ) {
        let Some(mut context) = self.contexts.get_mut(ctx_id) else {
            return;
        };
        if context.session_handles.suspended_backend(virtual_session) != Some(expected_backend) {
            return;
        }

        match completion {
            CloseSessionCompletion::Terminal => {
                context.remove_session(virtual_session);
            }
            CloseSessionCompletion::Transient => {
                if !context.session_handles.reactivate_suspended(virtual_session, expected_backend)
                {
                    // The raw handle has been rebound to a newer virtual id.
                    // Keep the old mapping quarantined and discard stale shape.
                    context
                        .message_operations
                        .retain(|(session, _), _| *session != virtual_session);
                }
            }
            CloseSessionCompletion::Ambiguous => {
                context.message_operations.retain(|(session, _), _| *session != virtual_session);
            }
        }
    }

    /// Cached `(label, serial)` for `backend_slot` if it was read within
    /// `TOKEN_INFO_CACHE_TTL`; otherwise `None` (the caller must re-read it).
    pub fn cached_token_info(&self, backend_slot: BackendSlotId) -> Option<(String, String)> {
        self.cached_token_info_within(backend_slot, TOKEN_INFO_CACHE_TTL)
    }

    /// Look up the backend slot that owns `virtual_session` within context
    /// `ctx_id`. Returns `None` when the context does not exist or the session
    /// is not registered in `session_slots`.
    pub async fn slot_for_session(
        &self,
        ctx_id: &ClientContextId,
        virtual_session: VirtualHandle,
    ) -> Option<BackendSlotId> {
        self.get_context(ctx_id, |ctx| ctx.session_slots.get(&virtual_session).copied())
            .await
            .flatten()
    }

    /// Return the cached [`ObjectMetadata`] for `virtual_object` within context
    /// `ctx_id`, or `None` on a cache miss.
    ///
    /// Session objects hit the per-handle cache. Token objects hit only while
    /// their entry's authz generation is current (W1-L13-18); a revoked entry
    /// is dropped eagerly and reads as a miss. The caller must fetch from the
    /// backend via `fetch_object_metadata` when this returns `None`.
    pub async fn object_metadata(
        &self,
        ctx_id: &ClientContextId,
        virtual_object: u64,
    ) -> Option<ObjectMetadata> {
        let generation = self.authz_generation.load(Ordering::SeqCst);
        self.get_context(ctx_id, |ctx| {
            let vh = VirtualHandle(virtual_object);
            if let Some(meta) = ctx.object_metadata.get(&vh) {
                return Some(meta.clone());
            }
            match ctx.token_object_metadata.get(&vh) {
                Some(gated) if gated.generation == generation => Some(gated.meta.clone()),
                // Stale generation: drop eagerly so the entry can never
                // validate a later gate call.
                Some(_) => {
                    ctx.token_object_metadata.remove(&vh);
                    None
                }
                None => None,
            }
        })
        .await
        .flatten()
    }

    /// Cache [`ObjectMetadata`] for `virtual_object` within context `ctx_id`.
    ///
    /// Session objects (`!meta.is_token`) are cached and evicted together with
    /// the virtual object handle (on `C_DestroyObject`, session close, or
    /// context teardown) so a recycled virtual handle can never return stale
    /// metadata within one context.
    ///
    /// Token objects (`meta.is_token == true`) are cached tagged with the
    /// current authz generation (W1-L13-18): gated reuse within the generation
    /// avoids a backend round-trip, and any daemon-wide object mutation
    /// revokes the generation so a cross-client backend handle recycling event
    /// cannot cause a stale authorization decision (the I2 never-cache rule,
    /// made generational).
    ///
    /// No-ops silently when the context no longer exists.
    pub async fn cache_object_metadata(
        &self,
        ctx_id: &ClientContextId,
        virtual_object: u64,
        meta: ObjectMetadata,
    ) {
        if meta.is_token {
            let generation = self.authz_generation.load(Ordering::SeqCst);
            let _ = self
                .get_context(ctx_id, |ctx| {
                    ctx.token_object_metadata.insert(
                        VirtualHandle(virtual_object),
                        GatedObjectMetadata { generation, meta },
                    );
                })
                .await;
            return;
        }
        let _ = self
            .get_context(ctx_id, |ctx| {
                ctx.object_metadata.insert(VirtualHandle(virtual_object), meta);
            })
            .await;
    }

    // --- R2 attribute coalescer accessors ---

    /// Return the cached [`CachedAttr`] for `(object, attr)` within context `ctx_id`,
    /// or `None` on a cache miss.
    ///
    /// A `None` result means either the attribute has never been cached for this object,
    /// or the object's cache entries were evicted (session close / context teardown).
    /// The caller should forward the request to the backend and then call
    /// [`attr_cache_put`](Self::attr_cache_put) when the coalescer is enabled.
    pub async fn attr_cache_get(
        &self,
        ctx_id: &ClientContextId,
        object: u64,
        attr: CkAttributeType,
    ) -> Option<CachedAttr> {
        self.get_context(ctx_id, |ctx| ctx.attr_cache.get(&(VirtualHandle(object), attr)).cloned())
            .await
            .flatten()
    }

    /// Borrow a cached attribute to build a response without cloning the
    /// entry out of the map (W1-L13-15: single copy on the coalescer hit
    /// path — only the wire encoding allocates). Returns `None` on a cache
    /// miss or when the context is gone.
    pub async fn attr_cache_get_with<R>(
        &self,
        ctx_id: &ClientContextId,
        object: u64,
        attr: CkAttributeType,
        f: impl FnOnce(&CachedAttr) -> R,
    ) -> Option<R> {
        self.get_context(ctx_id, |ctx| ctx.attr_cache.get(&(VirtualHandle(object), attr)).map(f))
            .await
            .flatten()
    }

    /// Store a [`CachedAttr`] for `(object, attr)` within context `ctx_id`.
    ///
    /// No-ops silently when the context no longer exists (the backend result is
    /// still forwarded to the caller; only the caching step is skipped).
    pub async fn attr_cache_put(
        &self,
        ctx_id: &ClientContextId,
        object: u64,
        attr: CkAttributeType,
        entry: CachedAttr,
    ) {
        let _ = self
            .get_context(ctx_id, |ctx| {
                ctx.attr_cache.insert((VirtualHandle(object), attr), entry);
            })
            .await;
    }

    /// Drop ALL cached attribute entries for `object` within context `ctx_id`.
    ///
    /// Called when a virtual object handle is invalidated (e.g. `C_DestroyObject`)
    /// so a reused virtual handle cannot serve stale cached attributes from a prior
    /// object. No-ops silently when the context is gone.
    pub async fn attr_cache_invalidate_object(&self, ctx_id: &ClientContextId, object: u64) {
        let _ = self
            .get_context(ctx_id, |ctx| {
                ctx.attr_cache.retain(|(vh, _), _| *vh != VirtualHandle(object));
            })
            .await;
    }

    /// Clear ALL cached attribute entries for context `ctx_id` (e.g. after `C_Logout`).
    ///
    /// Per PKCS#11, `C_Logout` invalidates an application's handles to private objects
    /// on the token; the coalescer must not serve cached attributes of those handles
    /// after logout. Evicting the entire cache is conservative and correct: it also
    /// clears public-object entries, which is only a performance miss, not a correctness
    /// issue. Distinguishing private vs. public would require `CKA_PRIVATE` to be
    /// tracked per handle — which the cache does not do. No-ops silently when the
    /// context is gone.
    pub async fn attr_cache_clear(&self, ctx_id: &ClientContextId) {
        let _ = self
            .get_context(ctx_id, |ctx| {
                ctx.attr_cache.clear();
            })
            .await;
    }

    /// Return `true` when `virtual_object` was minted (generated, created,
    /// unwrapped) by context `ctx_id` in this session — i.e. it is present in
    /// the context's `created_objects` set.
    ///
    /// Used by `gate_object_handle` to allow a confined principal to use keys
    /// it just generated even when the backend-assigned `CKA_UNIQUE_ID` is not
    /// in its pre-configured `objects` grant.
    ///
    /// Returns `false` when the context is gone (fail-safe: treat absence as
    /// not-created so the gate does not skip its normal policy check).
    pub async fn object_was_created_here(
        &self,
        ctx_id: &ClientContextId,
        virtual_object: u64,
    ) -> bool {
        self.get_context(ctx_id, |ctx| ctx.created_objects.contains(&VirtualHandle(virtual_object)))
            .await
            .unwrap_or(false)
    }

    fn cached_token_info_within(
        &self,
        backend_slot: BackendSlotId,
        ttl: std::time::Duration,
    ) -> Option<(String, String)> {
        self.token_info_cache.get(&backend_slot).and_then(|entry| {
            let (cached_at, label, serial) = entry.value();
            (cached_at.elapsed() < ttl).then(|| (label.clone(), serial.clone()))
        })
    }

    /// Record the `(label, serial)` read for `backend_slot`.
    pub fn cache_token_info(&self, backend_slot: BackendSlotId, label: String, serial: String) {
        self.token_info_cache.insert(backend_slot, (Instant::now(), label, serial));
    }

    /// Drop any cached token info for `backend_slot` (the token may have changed).
    pub fn invalidate_token_info(&self, backend_slot: BackendSlotId) {
        self.token_info_cache.remove(&backend_slot);
    }

    /// Populate slot map from backend's C_GetSlotList.
    pub async fn populate_slots(
        &self,
        backend: &Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend>,
    ) -> CkResult<()> {
        let backend = backend.clone();
        let slots = tokio::task::spawn_blocking(move || backend.get_slot_list(true))
            .await
            .map_err(|_| CkRv::GENERAL_ERROR)??;
        let mut map = self.slot_map.write().await;
        for backend_slot in slots {
            map.register(BackendSlotId(backend_slot));
        }
        Ok(())
    }

    /// Register a single backend slot discovered at runtime.
    pub async fn register_slot(&self, backend_slot: BackendSlotId) {
        // A (re-)registration may reflect a changed token in the slot, so drop
        // any cached token info for it (M9).
        self.invalidate_token_info(backend_slot);
        self.slot_map.write().await.register(backend_slot);
    }

    /// Resolve virtual → backend slot ID.
    pub async fn resolve_slot(&self, virtual_slot: VirtualSlotId) -> Option<BackendSlotId> {
        self.slot_map.read().await.resolve(virtual_slot)
    }

    /// Get all virtual slot IDs.
    pub async fn virtual_slots(&self) -> Vec<VirtualSlotId> {
        self.slot_map.read().await.virtual_slots()
    }

    /// Map backend → virtual slot ID.
    pub async fn to_virtual_slot(&self, backend_slot: BackendSlotId) -> Option<VirtualSlotId> {
        self.slot_map.read().await.to_virtual(backend_slot)
    }

    pub async fn create_context(&self, identity: Option<String>) -> CkResult<ClientContextId> {
        // Enforce max context limit. The check + insert is not strictly
        // atomic across shards (DashMap has no global lock), so under
        // concurrent context creation the limit may be exceeded
        // transiently by the number of racing creators — acceptable
        // because the limit is a soft cap, not a correctness gate.
        if self.max_contexts > 0 && self.contexts.len() >= self.max_contexts {
            // Try evicting expired contexts first — but ONLY those holding no
            // open backend sessions. This path has no backend handle and so
            // cannot close backend sessions; dropping a context that holds them
            // would leak them. Contexts with open sessions are reclaimed by the
            // background reaper (`evict_expired`), which closes them properly
            // (M4).
            let now = std::time::Instant::now();
            let expired: Vec<_> = self
                .contexts
                .iter()
                .filter(|entry| {
                    self.is_reapable(entry.value(), now)
                        && entry.value().session_handles.backend_handles().next().is_none()
                })
                .map(|entry| entry.key().clone())
                .collect();
            for id in &expired {
                self.contexts.remove(id);
            }
            // Still at capacity? Reject.
            if self.contexts.len() >= self.max_contexts {
                tracing::error!(
                    count = self.contexts.len(),
                    max = self.max_contexts,
                    "context limit reached"
                );
                return Err(CkRv::HOST_MEMORY);
            }
        }

        let ctx = LogicalClientInstance::new(identity);
        let id = ctx.id.clone();
        self.contexts.insert(id.clone(), ctx);
        Ok(id)
    }

    /// Returns the current number of active contexts.
    // Not `async`: a DashMap read needs no `.await` (L5).
    pub fn context_count(&self) -> usize {
        self.contexts.len()
    }

    /// Returns the currently active context IDs.
    // Not `async`: a DashMap read needs no `.await` (L5).
    pub fn context_ids(&self) -> Vec<ClientContextId> {
        self.contexts.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Run `f` against the mutable context for `id`, touching its lease.
    ///
    /// Intentionally `async` even though it only touches the `DashMap`: this is
    /// the per-RPC accessor with 60+ call sites, and keeping it `async` keeps a
    /// uniform awaited-accessor shape across the manager (alongside the RwLock-
    /// backed slot accessors) and preserves room to await inside later without a
    /// call-site-wide churn. The empty future is zero-cost (L5).
    pub async fn get_context<F, R>(&self, id: &ClientContextId, f: F) -> Option<R>
    where
        F: FnOnce(&mut LogicalClientInstance) -> R,
    {
        // DashMap::get_mut returns a per-shard guard, so concurrent
        // RPCs touching different contexts don't serialize.
        self.contexts.get_mut(id).map(|mut ctx| {
            ctx.touch();
            f(ctx.value_mut())
        })
    }

    pub fn first_login_state_for_slot_excluding(
        &self,
        slot: BackendSlotId,
        excluded_id: &ClientContextId,
    ) -> Option<LoginState> {
        self.contexts.iter().find_map(|ctx| {
            if ctx.key() == excluded_id { None } else { ctx.login_state.get(&slot).copied() }
        })
    }

    /// Begin a backend operation for `id`: bump its in-flight counter and return
    /// a guard. While the guard lives the context is NOT evicted even past the
    /// lease, so a single long backend call (DH/RSA keygen, slow-HSM op) is never
    /// reaped MID-CALL. On drop the guard decrements the counter and refreshes
    /// `last_active` so a long op that just finished isn't evicted before the
    /// client's next call. Returns `None` when the context doesn't exist — the
    /// caller then errors out normally and no guard is needed.
    /// Like [`begin_operation`](Self::begin_operation) but enforces a
    /// per-context in-flight cap (M2): `Ok(Some(guard))` when the context exists
    /// and is under `max_in_flight`, `Ok(None)` when the context is gone (the
    /// handler then returns the right CK_RV), and `Err(())` when the context is
    /// at its cap (the caller should reject the request so one client cannot
    /// monopolise the shared backend-call budget).
    ///
    /// `pub(crate)`: a crate-internal helper, so the `Err(())` at-capacity signal
    /// needs no richer error type (it would otherwise trip `result_unit_err`).
    pub(crate) fn begin_operation_capped(
        self: &Arc<Self>,
        id: &ClientContextId,
        max_in_flight: i64,
    ) -> Result<Option<OperationGuard>, ()> {
        let counter = {
            let Some(entry) = self.contexts.get(id) else { return Ok(None) };
            // Reserve a slot with a CAS so the cap is exact even under concurrent
            // reservations on the same context (all under this shard read lock).
            loop {
                let current = entry.in_flight.load(Ordering::Relaxed);
                if max_in_flight > 0 && current >= max_in_flight {
                    return Err(());
                }
                if entry
                    .in_flight
                    .compare_exchange_weak(
                        current,
                        current + 1,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    break;
                }
            }
            entry.in_flight.clone()
        };
        Ok(Some(OperationGuard::new(Arc::clone(self), id.clone(), counter)))
    }

    pub fn begin_operation(self: &Arc<Self>, id: &ClientContextId) -> Option<OperationGuard> {
        // Increment in_flight WHILE holding the shard lock (the `get` guard), so
        // the eviction path's `remove_if` — which takes the shard write lock and
        // is therefore mutually exclusive with this read lock — cannot observe
        // in_flight==0 and reap this context between the read and the increment
        // (L10). The Arc is cloned for the guard before the lock is released.
        let counter = {
            let entry = self.contexts.get(id)?;
            entry.in_flight.fetch_add(1, Ordering::Relaxed);
            entry.in_flight.clone()
        };
        Some(OperationGuard::new(Arc::clone(self), id.clone(), counter))
    }

    // Not `async`: a DashMap read needs no `.await` (L5).
    pub fn context_identity(&self, id: &ClientContextId) -> Option<String> {
        self.contexts.get(id).and_then(|ctx| ctx.authenticated_identity.clone())
    }

    /// Atomically check the per-principal session quota and reserve one
    /// slot when under `max` (W1-L6-04). Returns `None` (at cap) or
    /// `Some(reservation)`; the reservation counts toward the cap until
    /// dropped. `open_session` drops it once the session registers (the
    /// live count then covers it) or when the open fails — every return
    /// path releases, so the cap cannot leak.
    ///
    /// Lock order: quota mutex OUTER, contexts-DashMap shard guards INNER
    /// (transient). Never call while holding a contexts guard.
    ///
    /// Not `async`: mutex + DashMap reads need no `.await` (L5).
    pub(crate) fn try_reserve_session_for_principal(
        &self,
        principal_key: &str,
        max: usize,
    ) -> Option<SessionQuotaReservation> {
        let mut reservations =
            self.session_quota_reservations.lock().unwrap_or_else(|e| e.into_inner());
        let live = self.session_count_for_principal(principal_key);
        let outstanding = reservations.get(principal_key).copied().unwrap_or(0);
        if live + outstanding >= max {
            return None;
        }
        *reservations.entry(principal_key.to_owned()).or_insert(0) += 1;
        Some(SessionQuotaReservation {
            reservations: Arc::clone(&self.session_quota_reservations),
            principal: principal_key.to_owned(),
        })
    }

    /// Sum of open sessions across ALL contexts whose principal key equals
    /// `principal_key`. A context's principal key is its `authenticated_identity`
    /// when set; otherwise the context-id string itself (mirrors the derivation
    /// used at the dispatch seam so authenticated principals aggregate across
    /// their contexts and unauthenticated contexts are counted individually).
    ///
    /// Counts LIVE sessions only; in-flight opens hold
    /// [`SessionQuotaReservation`]s which count toward the same cap (W1-L6-04).
    /// Quota callers must use [`Self::try_reserve_session_for_principal`],
    /// not a bare read of this count (check-then-act races the cap).
    ///
    /// Not `async`: iterates the DashMap with shared shard guards, no await
    /// needed (L5).
    pub fn session_count_for_principal(&self, principal_key: &str) -> usize {
        self.contexts
            .iter()
            .map(|entry| {
                let ctx = entry.value();
                let key =
                    ctx.authenticated_identity.as_deref().unwrap_or_else(|| entry.key().0.as_str());
                if key == principal_key { ctx.session_slots.len() } else { 0 }
            })
            .sum()
    }

    // Not `async`: a DashMap remove needs no `.await` (L5).
    pub fn remove_context(&self, id: &ClientContextId) -> Option<LogicalClientInstance> {
        self.contexts.remove(id).map(|(_k, v)| v)
    }

    /// Remove `id` only when no FOREIGN backend operation is in flight
    /// (W1-L6-02): the check + remove are atomic under the DashMap shard
    /// write lock (same TOCTOU discipline as eviction's `remove_if`), so a
    /// concurrent op that began before the removal is never cut off
    /// mid-backend-call — `begin_operation` increments under the shard read
    /// lock, which is mutually exclusive with this write lock.
    ///
    /// `own_guards` is the number of in-flight guards held by the caller
    /// itself (finalize holds exactly one via dispatch scoping): removal
    /// proceeds when `in_flight <= own_guards`.
    ///
    /// Lock order: contexts-DashMap shard lock only, held transiently;
    /// never acquire any other lock (quota mutex, slot login locks) while
    /// holding it, and never call this while holding one.
    ///
    /// Not `async`: a DashMap predicate-remove needs no `.await` (L5).
    pub fn remove_context_if_idle(
        &self,
        id: &ClientContextId,
        own_guards: i64,
    ) -> RemoveIfIdleOutcome {
        if let Some((_, ctx)) = self
            .contexts
            .remove_if(id, |_, ctx| ctx.in_flight.load(Ordering::Relaxed) <= own_guards)
        {
            return RemoveIfIdleOutcome::Removed(Box::new(ctx));
        }
        if self.contexts.contains_key(id) {
            // Still present: the predicate refused it, so a foreign op is
            // in flight. (A concurrent remover winning the race reports
            // Missing instead — equally correct for the caller.)
            RemoveIfIdleOutcome::Busy
        } else {
            RemoveIfIdleOutcome::Missing
        }
    }

    /// True when any live context holds logical login for `slot`.
    pub fn any_login_state_for_slot(&self, slot: BackendSlotId) -> bool {
        self.contexts.iter().any(|entry| entry.value().login_state.contains_key(&slot))
    }

    /// True when any live context's session map still references `handle`
    /// (active or mid-close). The D9 refcount check: a departing context's
    /// backend session is closed only when this returns false.
    pub fn backend_session_referenced_by_live_context(&self, handle: BackendHandle) -> bool {
        self.contexts.iter().any(|entry| entry.value().session_handles.references_backend(handle))
    }

    /// Any currently resolvable (non-suspended) backend session on `slot`
    /// across all live contexts — a carrier for last-holder logout (D6(2)/D9).
    pub fn any_active_backend_session_for_slot(&self, slot: BackendSlotId) -> Option<u64> {
        self.contexts.iter().find_map(|entry| {
            let ctx = entry.value();
            ctx.session_slots
                .iter()
                .find(|(_, s)| **s == slot)
                .and_then(|(vh, _)| ctx.session_handles.resolve(*vh).map(|b| b.0))
        })
    }

    /// Compute the teardown plan for an already-removed context and clear its
    /// maps. Every removal site (finalize, lease eviction) MUST route teardown
    /// through here so backend sessions are reaped only when unreferenced by
    /// live contexts and the backend login is released exactly on
    /// last-context-out (D6(2)/D9 shared tenancy model).
    pub fn plan_removed_context_teardown(
        &self,
        departed: &mut LogicalClientInstance,
    ) -> ContextTeardownPlan {
        let sessions_to_close: Vec<u64> = departed
            .session_handles
            .backend_handles()
            .map(|b| b.0)
            .filter(|h| !self.backend_session_referenced_by_live_context(BackendHandle(*h)))
            .collect();
        let mut slot_logouts = Vec::new();
        for slot in departed.login_state.keys().copied().collect::<Vec<_>>() {
            if self.first_login_state_for_slot_excluding(slot, &departed.id).is_some() {
                continue;
            }
            // Last holder out: prefer one of the departed context's own still-
            // open sessions on this slot as the logout carrier, else any live
            // session. None at all means the token already auto-logged-out
            // with its last session close — nothing to do.
            let carrier = departed
                .session_slots
                .iter()
                .filter(|(_, s)| **s == slot)
                .filter_map(|(vh, _)| departed.session_handles.resolve(*vh))
                .map(|b| b.0)
                .next()
                .or_else(|| self.any_active_backend_session_for_slot(slot));
            if let Some(via_session) = carrier {
                slot_logouts.push(SlotLogout { slot, via_session });
            }
        }
        let _ = departed.teardown();
        ContextTeardownPlan { sessions_to_close, slot_logouts }
    }

    /// Attempt one last-holder backend logout on `slot` (D6(2)/D9): when no
    /// live context holds logical login — rechecked under the per-slot login
    /// lock — release the shared backend login via a still-open session, so
    /// the next login PIN-verifies against a logged-out token.
    ///
    /// Best-effort, never blocks: when the slot lock is contended its holder
    /// is actively establishing login consistency (a login inserting a holder,
    /// a logout releasing one, or another teardown). Every skip/failure warns
    /// (F-01 observability): a skipped logout leaves the backend logged in
    /// with no holder, which the next login reconciles (one backend logout +
    /// a single retry — see `login`). `None` carrier falls back to any live
    /// session; with no open session at all the token may already have
    /// auto-logged-out. A carrier that raced shut is retried once via a live
    /// session; every other outcome ends the attempt.
    ///
    /// Returns `true` only when this call released the backend login, so a
    /// caller that already logged out pre-close can skip a post-close retry
    /// (which would answer `USER_NOT_LOGGED_IN` and warn).
    pub async fn backend_logout_if_last_holder_out(
        &self,
        backend: &Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend>,
        slot: BackendSlotId,
        preferred_session: Option<u64>,
    ) -> bool {
        self.backend_logout_if_last_holder_out_inner(
            backend,
            slot,
            preferred_session,
            None,
            TEARDOWN_BACKEND_TIMEOUT,
        )
        .await
    }

    /// Same as [`Self::backend_logout_if_last_holder_out`], but the
    /// last-holder check excludes `exclude`'s own logical login (T5F). Used
    /// by the singular `close_session` pre-close attempt, where the closing
    /// context still holds its login: it is dropped only when the close
    /// settles terminal, so transient close failures retain it.
    pub async fn backend_logout_if_last_holder_out_excluding(
        &self,
        backend: &Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend>,
        slot: BackendSlotId,
        preferred_session: Option<u64>,
        exclude: &ClientContextId,
    ) -> bool {
        self.backend_logout_if_last_holder_out_inner(
            backend,
            slot,
            preferred_session,
            Some(exclude),
            TEARDOWN_BACKEND_TIMEOUT,
        )
        .await
    }

    async fn backend_logout_if_last_holder_out_inner(
        &self,
        backend: &Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend>,
        slot: BackendSlotId,
        preferred_session: Option<u64>,
        exclude: Option<&ClientContextId>,
        timeout: Duration,
    ) -> bool {
        // Fast path without the lock: observing any live holder means no logout.
        if self.slot_login_held(slot, exclude) {
            return false;
        }
        let lock = self.slot_login_lock(slot);
        let Ok(_guard) = lock.try_lock() else {
            tracing::warn!(
                slot = slot.0.0,
                "last-holder backend logout skipped: slot login lock contended"
            );
            return false;
        };
        // Recheck under the lock: a fresh login may have landed since the fast
        // path. The lock serializes this recheck+logout against every login's
        // scan+insert, so a concurrent login is never stolen.
        if self.slot_login_held(slot, exclude) {
            return false;
        }
        let live = self.any_active_backend_session_for_slot(slot);
        let mut carriers = Vec::with_capacity(2);
        if let Some(via) = preferred_session {
            carriers.push(via);
        }
        if let Some(via) = live
            && Some(via) != preferred_session
        {
            carriers.push(via);
        }
        if carriers.is_empty() {
            tracing::warn!(
                slot = slot.0.0,
                "last-holder backend logout skipped: no open session to carry the call"
            );
            return false;
        }
        for via in carriers {
            let backend = backend.clone();
            // W1-C2-03: route through spawn_backend so a wedged backend
            // times out (breaker slot + stuck accounting included) instead
            // of stalling the caller — eviction or session close — forever.
            let result = crate::server::grpc_service::service_utils::spawn_backend_with_timeout(
                timeout,
                move || backend.logout(CkSessionHandle(via)),
            )
            .await;
            match result {
                Ok(Ok(())) => {
                    tracing::debug!("last-holder backend logout succeeded");
                    return true;
                }
                Ok(Err(rv)) if rv == CkRv::SESSION_HANDLE_INVALID || rv == CkRv::SESSION_CLOSED => {
                    continue; // carrier raced shut; try the next candidate
                }
                Ok(Err(rv)) => {
                    tracing::warn!(
                        slot = slot.0.0,
                        rv = rv.0,
                        "last-holder backend logout failed; backend may stay logged in with no holder"
                    );
                    return false;
                }
                Err(status) => {
                    tracing::warn!(
                        slot = slot.0.0,
                        error = %status,
                        "last-holder backend logout spawn failed; backend may stay logged in with no holder"
                    );
                    return false;
                }
            }
        }
        // Every carrier raced shut: same holderless-but-logged-in risk as a
        // failed logout (some tokens do not auto-logout on last close).
        tracing::warn!(
            slot = slot.0.0,
            "last-holder backend logout skipped: all carriers raced shut"
        );
        false
    }

    /// Whether any live context holds logical login for `slot`, optionally
    /// excluding one departing context's own login (T5F pre-close check).
    fn slot_login_held(&self, slot: BackendSlotId, exclude: Option<&ClientContextId>) -> bool {
        match exclude {
            Some(id) => self.first_login_state_for_slot_excluding(slot, id).is_some(),
            None => self.any_login_state_for_slot(slot),
        }
    }

    /// Execute teardown plans: all last-holder logouts first (each rechecked
    /// under its slot lock, so no live tenant is disturbed), then all session
    /// closes. Logouts are deduplicated by slot across plans.
    pub async fn execute_teardown_plans(
        &self,
        backend: &Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend>,
        plans: Vec<ContextTeardownPlan>,
    ) {
        self.execute_teardown_plans_with_timeout(backend, plans, TEARDOWN_BACKEND_TIMEOUT).await;
    }

    /// [`Self::execute_teardown_plans`] with an explicit per-call backend
    /// timeout. Tests drive wedged-backend boundedness through this; all
    /// production callers use the default via [`Self::execute_teardown_plans`].
    pub(crate) async fn execute_teardown_plans_with_timeout(
        &self,
        backend: &Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend>,
        plans: Vec<ContextTeardownPlan>,
        timeout: Duration,
    ) {
        let mut logouts: HashMap<BackendSlotId, u64> = HashMap::new();
        let mut closes: Vec<u64> = Vec::new();
        for plan in plans {
            for logout in plan.slot_logouts {
                logouts.entry(logout.slot).or_insert(logout.via_session);
            }
            closes.extend(plan.sessions_to_close);
        }
        for (slot, via_session) in logouts {
            self.backend_logout_if_last_holder_out_inner(
                backend,
                slot,
                Some(via_session),
                None,
                timeout,
            )
            .await;
        }
        Self::close_backend_sessions(backend, closes, timeout).await;
    }

    /// Evict expired contexts (called periodically). Returns the contexts
    /// actually removed (a candidate touched concurrently survives and is not
    /// returned). Each removal is planned and executed through the shared
    /// D6(2)/D9 teardown path: refcount-checked session reaping plus
    /// last-holder backend logout.
    pub async fn evict_expired(
        &self,
        backend: &Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend>,
    ) -> Vec<ClientContextId> {
        self.evict_expired_with_timeout(backend, TEARDOWN_BACKEND_TIMEOUT).await
    }

    /// [`Self::evict_expired`] with an explicit per-call backend timeout for
    /// the teardown phase. Tests drive wedged-backend boundedness through
    /// this; the background reaper uses the default via [`Self::evict_expired`].
    pub(crate) async fn evict_expired_with_timeout(
        &self,
        backend: &Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend>,
        timeout: Duration,
    ) -> Vec<ClientContextId> {
        let now = Instant::now();
        let expired = self.collect_expired_context_ids(now);
        let mut evicted = Vec::with_capacity(expired.len());
        let mut plans = Vec::with_capacity(expired.len());
        for id in &expired {
            // Re-check expiry and remove ATOMICALLY under the per-shard write
            // lock: `remove_if` evaluates the predicate while holding the lock,
            // so a context touched (last_active bumped) or that started an
            // operation (in_flight incremented under the read lock) since the
            // best-effort first scan is not evicted on stale data — closing the
            // get-then-remove TOCTOU (L10). The first scan is just a cheap
            // candidate filter. Sequential remove-then-plan keeps multi-expire
            // login accounting exact: an earlier plan still sees a later
            // candidate as a live holder.
            if let Some((_, mut ctx)) =
                self.contexts.remove_if(id, |_, ctx| self.is_reapable(ctx, now))
            {
                evicted.push(id.clone());
                plans.push(self.plan_removed_context_teardown(&mut ctx));
            }
        }
        self.execute_teardown_plans_with_timeout(backend, plans, timeout).await;
        evicted
    }

    /// A context is reapable only when its lease has expired AND it has no
    /// backend operation in flight (a long in-flight op must never be evicted
    /// mid-call — that is the whole point of the in-flight counter).
    fn is_reapable(&self, ctx: &LogicalClientInstance, now: Instant) -> bool {
        ctx.in_flight.load(Ordering::Relaxed) == 0
            && now.duration_since(ctx.last_active) > self.lease_duration
    }

    fn collect_expired_context_ids(&self, now: Instant) -> Vec<ClientContextId> {
        self.contexts
            .iter()
            .filter(|entry| self.is_reapable(entry.value(), now))
            .map(|entry| entry.key().clone())
            .collect()
    }

    async fn close_backend_sessions(
        backend: &Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend>,
        backend_sessions: Vec<u64>,
        timeout: Duration,
    ) {
        // W1-C2-03: one bounded spawn_backend call per session (not one
        // unbounded batch) so a wedged backend stalls reaping by at most
        // `timeout` per session while a slow-but-live backend still drains.
        // Best-effort: every outcome is ignored — teardown must not fail.
        for handle in backend_sessions {
            let backend = backend.clone();
            let _ = crate::server::grpc_service::service_utils::spawn_backend_with_timeout(
                timeout,
                move || {
                    let _ = backend.close_session(CkSessionHandle(handle));
                    Ok(())
                },
            )
            .await;
        }
    }
}

/// Per-call backend timeout for context-teardown work (W1-C2-03): session
/// closes and last-holder logouts during eviction/finalize. Teardown is
/// best-effort background reaping, so it gets a shorter bound than the
/// data-plane `proxy.request_timeout_secs` default — a wedged backend must
/// not stall lease reaping (or session close) beyond this per call.
const TEARDOWN_BACKEND_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests;
