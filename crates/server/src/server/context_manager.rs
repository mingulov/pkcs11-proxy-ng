use super::handle_map::{BackendHandle, HandleMap, VirtualHandle};
use super::slot_map::SlotMap;
use dashmap::DashMap;
use pkcs11_proxy_ng_types::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Instant;
use tokio::sync::RwLock;
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
        let backend_sessions: Vec<u64> = self
            .session_handles
            .virtual_handles()
            .filter_map(|vh| self.session_handles.resolve(vh).map(|bh| bh.0))
            .collect();
        self.session_handles.clear();
        self.session_slots.clear();
        self.object_handles.clear();
        self.session_objects.clear();
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
}

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
        }
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
    pub async fn context_count(&self) -> usize {
        self.contexts.len()
    }

    /// Returns the currently active context IDs.
    pub async fn context_ids(&self) -> Vec<ClientContextId> {
        self.contexts.iter().map(|entry| entry.key().clone()).collect()
    }

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
    pub fn begin_operation(self: &Arc<Self>, id: &ClientContextId) -> Option<OperationGuard> {
        let counter = self.contexts.get(id)?.in_flight.clone();
        counter.fetch_add(1, Ordering::Relaxed);
        Some(OperationGuard { manager: Arc::clone(self), id: id.clone(), counter })
    }

    pub async fn context_identity(&self, id: &ClientContextId) -> Option<String> {
        self.contexts.get(id).and_then(|ctx| ctx.authenticated_identity.clone())
    }

    pub async fn remove_context(&self, id: &ClientContextId) -> Option<LogicalClientInstance> {
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
        // Re-check expiry under the per-shard lock so a context that
        // got touched between `collect_expired_context_ids` and here
        // is not evicted on stale data. The first scan is best-effort
        // (no lock held across shards); this scan is authoritative.
        let now = Instant::now();
        let mut backend_sessions = Vec::new();
        for id in expired {
            let still_expired =
                self.contexts.get(id).is_some_and(|entry| self.is_reapable(&entry, now));
            if !still_expired {
                continue;
            }
            if let Some((_, mut ctx)) = self.contexts.remove(id) {
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
                let _ = backend.close_session(CkSessionHandle(handle));
            }
        })
        .await;
    }
}

#[cfg(test)]
mod tests;
