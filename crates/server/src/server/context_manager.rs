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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub login_state: HashMap<CkSlotId, LoginState>, // per-token login
    pub authenticated_identity: Option<String>, // bound at creation (ADR-0005 §4)
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
            if let Some(bh) = self.session_handles.remove(vh) {
                backend_handles.push(bh);
            }
        }
        self.login_state.remove(&slot);
        backend_handles
    }

    /// Remove one session. If it was the final session this logical client
    /// held for the slot, clear the corresponding logical login state.
    pub fn remove_session(&mut self, session: VirtualHandle) -> Option<BackendHandle> {
        let slot = self.session_slots.remove(&session);
        let backend_handle = self.session_handles.remove(session);
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
        }
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
            // Try evicting expired contexts first.
            let now = std::time::Instant::now();
            let expired: Vec<_> = self
                .contexts
                .iter()
                .filter(|entry| self.is_reapable(entry.value(), now))
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
