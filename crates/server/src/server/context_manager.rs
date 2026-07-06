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

/// Cached object metadata for the per-object / per-class authorization gate (G3).
///
/// Fetched in a single `C_GetAttributeValue` round-trip covering
/// `CKA_UNIQUE_ID`, `CKA_CLASS`, and `CKA_TOKEN`. Only session objects
/// (`is_token = false`) are stored in the cache; token objects are always
/// re-fetched to prevent stale authorization against recycled backend handles
/// (I2 fix, ADR-0012 §G3).
#[derive(Debug, Clone)]
pub struct ObjectMetadata {
    pub unique_id: Vec<u8>,
    /// `None` when `CKA_CLASS` is absent or unparseable (M2: uid-only deployments must not
    /// fail on a missing class attribute). Class-confined gates treat `None` as fail-closed
    /// (deny); uid-only deployments ignore this field entirely.
    pub class: Option<CkObjectClass>,
    pub is_token: bool,
}

/// A logical client instance — the server-side PKCS#11 "application" (ADR-0002).
pub struct LogicalClientInstance {
    pub id: ClientContextId,
    pub created_at: Instant,
    pub last_active: Instant,
    pub session_handles: HandleMap, // virtual session → backend session
    pub session_slots: HashMap<VirtualHandle, CkSlotId>, // session → slot ownership (ADR-0002 §7)
    pub object_handles: HandleMap,  // virtual object → backend object
    /// Per-virtual-object cached `ObjectMetadata` (G3). **Only session objects
    /// (`CKA_TOKEN=false`) are cached.** Token objects are never stored here —
    /// they are re-fetched on every gate call so a cross-client backend handle
    /// recycling event cannot cause a stale authorization decision (I2 fix).
    ///
    /// Entries are evicted wherever `object_handles` entries are removed —
    /// on explicit `C_DestroyObject`, on session close (for session objects),
    /// and on context teardown — so a recycled virtual handle can never return
    /// stale metadata within one context.
    pub object_metadata: HashMap<VirtualHandle, ObjectMetadata>,
    /// Virtual object handles created as SESSION objects (CKA_TOKEN=false) in
    /// each virtual session. Evicted when that session closes so a recycled
    /// backend object number can never alias a stale handle (B2). Token objects
    /// are intentionally absent — their handles persist across the application's
    /// sessions.
    pub session_objects: HashMap<VirtualHandle, Vec<VirtualHandle>>,
    pub login_state: HashMap<CkSlotId, LoginState>, // per-token login
    pub authenticated_identity: Option<String>,     // bound at creation (ADR-0005 §4)
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
            object_metadata: HashMap::new(),
            session_objects: HashMap::new(),
            created_objects: HashSet::new(),
            login_state: HashMap::new(),
            authenticated_identity: identity,
            in_flight: Arc::new(AtomicI64::new(0)),
        }
    }

    pub fn touch(&mut self) {
        self.last_active = Instant::now();
    }

    /// Register a session with its owning slot (ADR-0002 §7).
    pub fn register_session(&mut self, backend: BackendHandle, slot: CkSlotId) -> VirtualHandle {
        let virt = self.session_handles.insert(backend);
        self.session_slots.insert(virt, slot);
        virt
    }

    /// Remove sessions for a specific slot. Returns backend handles to close.
    pub fn remove_sessions_for_slot(&mut self, slot: CkSlotId) -> Vec<BackendHandle> {
        let to_remove: Vec<VirtualHandle> =
            self.session_slots.iter().filter(|(_, s)| **s == slot).map(|(vh, _)| *vh).collect();

        let mut backend_handles = Vec::with_capacity(to_remove.len());
        for vh in to_remove {
            self.session_slots.remove(&vh);
            // Evict each closed session's session objects (B2) together with
            // their cached unique IDs so recycled virtual handles cannot return
            // stale ids. Also evict the created-set entries so a recycled
            // virtual handle cannot inherit created-status.
            if let Some(objects) = self.session_objects.remove(&vh) {
                for object in objects {
                    self.object_handles.remove(object);
                    self.object_metadata.remove(&object);
                    self.created_objects.remove(&object);
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
        // backend object number (B2).  Cached unique IDs and created-set
        // entries are evicted alongside object handles so a recycled virtual
        // handle cannot return stale metadata or inherit created-status.
        if let Some(objects) = self.session_objects.remove(&session) {
            for object in objects {
                self.object_handles.remove(object);
                self.object_metadata.remove(&object);
                self.created_objects.remove(&object);
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
        let backend_sessions: Vec<u64> = self
            .session_handles
            .virtual_handles()
            .filter_map(|vh| self.session_handles.resolve(vh).map(|bh| bh.0))
            .collect();
        self.session_handles.clear();
        self.session_slots.clear();
        self.object_handles.clear();
        self.object_metadata.clear();
        self.session_objects.clear();
        self.created_objects.clear();
        self.login_state.clear();
        backend_sessions
    }
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

    /// Look up the backend slot that owns `virtual_session` within context
    /// `ctx_id`. Returns `None` when the context does not exist or the session
    /// is not registered in `session_slots`.
    pub async fn slot_for_session(
        &self,
        ctx_id: &ClientContextId,
        virtual_session: VirtualHandle,
    ) -> Option<CkSlotId> {
        self.get_context(ctx_id, |ctx| ctx.session_slots.get(&virtual_session).copied())
            .await
            .flatten()
    }

    /// Return the cached [`ObjectMetadata`] for `virtual_object` within context
    /// `ctx_id`, or `None` on a cache miss.
    ///
    /// A `None` result means either the object has never been fetched, OR it is
    /// a token object (token objects are never cached — see `cache_object_metadata`).
    /// The caller must fetch from the backend via `fetch_object_metadata` when
    /// this returns `None`.
    pub async fn object_metadata(
        &self,
        ctx_id: &ClientContextId,
        virtual_object: u64,
    ) -> Option<ObjectMetadata> {
        self.get_context(ctx_id, |ctx| {
            ctx.object_metadata.get(&VirtualHandle(virtual_object)).cloned()
        })
        .await
        .flatten()
    }

    /// Cache [`ObjectMetadata`] for `virtual_object` within context `ctx_id`.
    ///
    /// **I2 fix:** token objects (`meta.is_token == true`) are NEVER cached.
    /// They are re-fetched on every gate call so a cross-client backend handle
    /// recycling event cannot cause a stale authorization decision.
    ///
    /// Session objects (`!meta.is_token`) are cached and evicted together with
    /// the virtual object handle (on `C_DestroyObject`, session close, or
    /// context teardown) so a recycled virtual handle can never return stale
    /// metadata within one context.
    ///
    /// No-ops silently when the context no longer exists.
    pub async fn cache_object_metadata(
        &self,
        ctx_id: &ClientContextId,
        virtual_object: u64,
        meta: ObjectMetadata,
    ) {
        if meta.is_token {
            return; // Never cache token objects (I2 fix).
        }
        let _ = self
            .get_context(ctx_id, |ctx| {
                ctx.object_metadata.insert(VirtualHandle(virtual_object), meta);
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
            map.register(backend_slot);
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
    pub async fn resolve_slot(&self, virtual_slot: CkSlotId) -> Option<CkSlotId> {
        self.slot_map.read().await.resolve(virtual_slot)
    }

    /// Get all virtual slot IDs.
    pub async fn virtual_slots(&self) -> Vec<CkSlotId> {
        self.slot_map.read().await.virtual_slots()
    }

    /// Map backend → virtual slot ID.
    pub async fn to_virtual_slot(&self, backend_slot: CkSlotId) -> Option<CkSlotId> {
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

    /// Evict expired contexts (called periodically).
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
        backend_sessions
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
