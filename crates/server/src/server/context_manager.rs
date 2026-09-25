use super::handle_map::{BackendHandle, HandleMap, VirtualHandle};
use super::slot_map::SlotMap;
use dashmap::DashMap;
use pkcs11_proxy_ng_types::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};
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
/// `CKA_UNIQUE_ID`, `CKA_CLASS`, and `CKA_TOKEN`. Only session objects
/// (`is_token = false`) are stored in the cache; token objects are always
/// re-fetched to prevent stale authorization against recycled backend handles
/// (I2 fix, ADR-0012 §G3).
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

/// A logical client instance — the server-side PKCS#11 "application" (ADR-0002).
pub struct LogicalClientInstance {
    pub id: ClientContextId,
    pub created_at: Instant,
    pub last_active: Instant,
    pub session_handles: HandleMap, // virtual session → backend session
    pub session_slots: HashMap<VirtualHandle, CkSlotId>, // session → slot ownership (ADR-0002 §7)
    pub object_handles: HandleMap,  // virtual object → backend object
    /// Virtual object handles created as SESSION objects (CKA_TOKEN=false) in
    /// each virtual session. Evicted when that session closes so a recycled
    /// backend object number can never alias a stale handle (B2). Token objects
    /// are intentionally absent — their handles persist across the application's
    /// sessions.
    pub session_objects: HashMap<VirtualHandle, Vec<VirtualHandle>>,
    pub login_state: HashMap<CkSlotId, LoginState>, // per-token login
    pub authenticated_identity: Option<String>,     // bound at creation (ADR-0005 §4)
    /// Count of backend operations currently in flight for this context.
    /// Eviction never reaps a context with `in_flight > 0`, so a single
    /// long backend call (DH/RSA keygen, slow-HSM op) is not evicted MID-CALL
    /// even when it outlasts the lease. `Arc` so an `OperationGuard` can hold
    /// and decrement it after the DashMap shard lock is released.
    pub in_flight: Arc<AtomicI64>,
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
            session_objects: HashMap::new(),
            login_state: HashMap::new(),
            authenticated_identity: identity,
            in_flight: Arc::new(AtomicI64::new(0)),
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
            // Evict each closed session's session objects (B2).
            if let Some(objects) = self.session_objects.remove(&vh) {
                for object in objects {
                    self.object_handles.remove(object);
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
        // Evict the session's session objects: the backend destroys them on
        // close, so the virtual handles must not linger and alias a recycled
        // backend object number (B2).
        if let Some(objects) = self.session_objects.remove(&session) {
            for object in objects {
                self.object_handles.remove(object);
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
        self.session_objects.clear();
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
    /// Per-(slot, login state) PIN verifiers (salted SHA-256), captured at the
    /// first successful backend login so a co-located logical client can be
    /// PIN-validated without a second backend `C_Login` (which the shared,
    /// already-logged-in token answers `USER_ALREADY_LOGGED_IN` without
    /// checking the PIN). Stores a salted hash, never the raw PIN. See ADR-0008.
    pin_verifiers: Arc<DashMap<(CkSlotId, LoginState), [u8; 32]>>,
    /// Random per-process salt for the PIN-verifier hashes.
    pin_salt: [u8; 16],
    /// Cache of `(label, serial)` per backend slot, captured when the daemon
    /// last read `C_GetTokenInfo` for an authorization check (M9). Authorization
    /// is otherwise a blocking backend call on every discovery/open. Entries are
    /// invalidated explicitly on slot re-registration AND expire after
    /// `TOKEN_INFO_CACHE_TTL`, so a token swapped without a re-registration is
    /// re-read within at most the TTL — the cache never authorizes against a
    /// token-identity older than that.
    token_info_cache: Arc<DashMap<CkSlotId, (Instant, String, String)>>,
    /// Per-slot serialization lock for login/logout (M5). The cross-context
    /// login-state scan, the backend `C_Login`, and the `login_state` insert
    /// must be atomic per slot. Without it, two clients racing the FIRST login
    /// on a shared token both observe "no other login", both take the real
    /// `C_Login` path, and the second is answered `USER_ALREADY_LOGGED_IN` by
    /// the already-logged-in token instead of the synthesized logical OK. One
    /// lock per slot id; different slots log in concurrently.
    login_locks: Arc<DashMap<CkSlotId, Arc<Mutex<()>>>>,
}

/// Maximum age of a cached `(label, serial)` before an authorization check
/// re-reads `C_GetTokenInfo`. Bounds the staleness of token-policy decisions
/// after an undetected runtime token change (M9).
const TOKEN_INFO_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// RAII guard marking a backend operation in flight for one context. While it
/// lives, eviction skips that context (see `ContextManager::begin_operation`).
pub struct OperationGuard {
    manager: Arc<ContextManager>,
    id: ClientContextId,
    counter: Arc<AtomicI64>,
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
        // Refresh last_active (sync DashMap access) so a long op that just
        // finished isn't evicted before the client's next call.
        if let Some(mut ctx) = self.manager.contexts.get_mut(&self.id) {
            ctx.touch();
        }
    }
}

impl ContextManager {
    pub fn new(lease_duration: std::time::Duration, max_contexts: usize) -> Self {
        Self {
            contexts: Arc::new(DashMap::new()),
            slot_map: Arc::new(RwLock::new(SlotMap::new())),
            lease_duration,
            max_contexts,
            pin_verifiers: Arc::new(DashMap::new()),
            pin_salt: *Uuid::new_v4().as_bytes(),
            token_info_cache: Arc::new(DashMap::new()),
            login_locks: Arc::new(DashMap::new()),
        }
    }

    /// Per-slot login/logout serialization lock (M5). Acquire it (`.lock().await`)
    /// after resolving the slot and hold it across the cross-context login-state
    /// scan, the backend `C_Login`/`C_Logout`, and the `login_state` mutation, so
    /// concurrent logins on the same shared token cannot both take the real-login
    /// path. The lock is keyed by slot, so different slots are unaffected.
    pub fn slot_login_lock(&self, slot: CkSlotId) -> Arc<Mutex<()>> {
        self.login_locks.entry(slot).or_insert_with(|| Arc::new(Mutex::new(()))).clone()
    }

    /// Cached `(label, serial)` for `backend_slot` if it was read within
    /// `TOKEN_INFO_CACHE_TTL`; otherwise `None` (the caller must re-read it).
    pub fn cached_token_info(&self, backend_slot: CkSlotId) -> Option<(String, String)> {
        self.cached_token_info_within(backend_slot, TOKEN_INFO_CACHE_TTL)
    }

    fn cached_token_info_within(
        &self,
        backend_slot: CkSlotId,
        ttl: std::time::Duration,
    ) -> Option<(String, String)> {
        self.token_info_cache.get(&backend_slot).and_then(|entry| {
            let (cached_at, label, serial) = entry.value();
            (cached_at.elapsed() < ttl).then(|| (label.clone(), serial.clone()))
        })
    }

    /// Record the `(label, serial)` read for `backend_slot`.
    pub fn cache_token_info(&self, backend_slot: CkSlotId, label: String, serial: String) {
        self.token_info_cache.insert(backend_slot, (Instant::now(), label, serial));
    }

    /// Drop any cached token info for `backend_slot` (the token may have changed).
    pub fn invalidate_token_info(&self, backend_slot: CkSlotId) {
        self.token_info_cache.remove(&backend_slot);
    }

    /// Salted hash of a PIN for verifier storage/comparison. A `None` PIN
    /// (protected-auth path) hashes to a value distinct from an empty PIN.
    pub fn hash_pin(&self, pin: Option<&[u8]>) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.pin_salt);
        match pin {
            Some(p) => {
                hasher.update([1u8]);
                hasher.update(p);
            }
            None => hasher.update([0u8]),
        }
        hasher.finalize().into()
    }

    /// Capture the PIN verifier for `(slot, state)` after a successful backend
    /// login so later co-located logical logins can be PIN-validated.
    pub fn store_pin_verifier_hash(&self, slot: CkSlotId, state: LoginState, hash: [u8; 32]) {
        self.pin_verifiers.insert((slot, state), hash);
    }

    /// Validate a presented PIN's hash against the stored verifier for
    /// `(slot, state)`. `None` means no verifier is recorded — the caller must
    /// not synthesize a login (it cannot validate the PIN).
    pub fn verify_pin_hash(
        &self,
        slot: CkSlotId,
        state: LoginState,
        hash: &[u8; 32],
    ) -> Option<bool> {
        self.pin_verifiers.get(&(slot, state)).map(|stored| *stored == *hash)
    }

    /// Drop the PIN verifier for `(slot, state)` (on the last real logout).
    pub fn clear_pin_verifier(&self, slot: CkSlotId, state: LoginState) {
        self.pin_verifiers.remove(&(slot, state));
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
    pub async fn register_slot(&self, backend_slot: CkSlotId) {
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
                        && entry.value().session_handles.virtual_handles().next().is_none()
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
        slot: CkSlotId,
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
        Ok(Some(OperationGuard { manager: Arc::clone(self), id: id.clone(), counter }))
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
        Some(OperationGuard { manager: Arc::clone(self), id: id.clone(), counter })
    }

    // Not `async`: a DashMap read needs no `.await` (L5).
    pub fn context_identity(&self, id: &ClientContextId) -> Option<String> {
        self.contexts.get(id).and_then(|ctx| ctx.authenticated_identity.clone())
    }

    // Not `async`: a DashMap remove needs no `.await` (L5).
    pub fn remove_context(&self, id: &ClientContextId) -> Option<LogicalClientInstance> {
        self.contexts.remove(id).map(|(_k, v)| v)
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

    /// Sum of open sessions across ALL contexts whose principal key equals
    /// `principal_key`. A context's principal key is its `authenticated_identity`
    /// when set; otherwise the context-id string itself (mirrors the derivation
    /// used at the dispatch seam so authenticated principals aggregate across
    /// their contexts and unauthenticated contexts are counted individually).
    ///
    /// Not `async`: iterates the DashMap with shared shard guards, no await
    /// needed (L5). Called from `open_session` BEFORE opening the backend
    /// session — leak-proof because it reads live bookkeeping rather than
    /// maintaining a separate reserve/release counter.
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
        self.backend_logout_if_last_holder_out_inner(backend, slot, preferred_session, None).await
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
        )
        .await
    }

    async fn backend_logout_if_last_holder_out_inner(
        &self,
        backend: &Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend>,
        slot: BackendSlotId,
        preferred_session: Option<u64>,
        exclude: Option<&ClientContextId>,
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
            let result =
                tokio::task::spawn_blocking(move || backend.logout(CkSessionHandle(via))).await;
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
                Err(join_error) => {
                    tracing::warn!(
                        slot = slot.0.0,
                        error = %join_error,
                        "last-holder backend logout join failed; backend may stay logged in with no holder"
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
        let mut logouts: HashMap<BackendSlotId, u64> = HashMap::new();
        let mut closes: Vec<u64> = Vec::new();
        for plan in plans {
            for logout in plan.slot_logouts {
                logouts.entry(logout.slot).or_insert(logout.via_session);
            }
            closes.extend(plan.sessions_to_close);
        }
        for (slot, via_session) in logouts {
            self.backend_logout_if_last_holder_out(backend, slot, Some(via_session)).await;
        }
        Self::close_backend_sessions(backend, closes).await;
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
        let now = Instant::now();
        let expired = self.collect_expired_context_ids(now);
        let all_backend_sessions = self.drain_expired_contexts(&expired);
        Self::close_backend_sessions(backend, all_backend_sessions).await;
        expired
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

    fn drain_expired_contexts(&self, expired: &[ClientContextId]) -> Vec<u64> {
        // Re-check expiry and remove ATOMICALLY under the per-shard write lock:
        // `remove_if` evaluates the predicate while holding the lock, so a
        // context touched (last_active bumped) or that started an operation
        // (in_flight incremented under the read lock) since the best-effort first
        // scan is not evicted on stale data — closing the get-then-remove TOCTOU
        // (L10). The first scan is just a cheap candidate filter.
        let now = Instant::now();
        let mut backend_sessions = Vec::new();
        for id in expired {
            if let Some((_, mut ctx)) =
                self.contexts.remove_if(id, |_, ctx| self.is_reapable(ctx, now))
            {
                backend_sessions.extend(ctx.teardown());
            }
        }
        self.execute_teardown_plans(backend, plans).await;
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
    ) {
        if backend_sessions.is_empty() {
            return;
        }
        let backend = backend.clone();
        let _ = tokio::task::spawn_blocking(move || {
            for handle in backend_sessions {
                let _ = backend.close_session(CkSessionHandle(handle as u64));
            }
        })
        .await;
    }
}

#[cfg(test)]
mod tests;
