use super::handle_map::{BackendHandle, HandleMap, VirtualHandle};
use super::slot_map::SlotMap;
use pkcs11_proxy_ng_types::*;
use std::collections::HashMap;
use std::sync::Arc;
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
        backend_handles
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
pub struct ContextManager {
    contexts: Arc<RwLock<HashMap<ClientContextId, LogicalClientInstance>>>,
    slot_map: Arc<RwLock<SlotMap>>,
    lease_duration: std::time::Duration,
    max_contexts: usize,
}

impl ContextManager {
    pub fn new(lease_duration: std::time::Duration, max_contexts: usize) -> Self {
        Self {
            contexts: Arc::new(RwLock::new(HashMap::new())),
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
        let mut contexts = self.contexts.write().await;

        // Enforce max context limit
        if self.max_contexts > 0 && contexts.len() >= self.max_contexts {
            // Try evicting expired contexts first
            let now = std::time::Instant::now();
            let expired: Vec<_> = contexts
                .iter()
                .filter(|(_, ctx)| now.duration_since(ctx.last_active) > self.lease_duration)
                .map(|(id, _)| id.clone())
                .collect();
            for id in &expired {
                contexts.remove(id);
            }
            // Still at capacity? Reject.
            if contexts.len() >= self.max_contexts {
                tracing::error!(
                    count = contexts.len(),
                    max = self.max_contexts,
                    "context limit reached"
                );
                return Err(CkRv::HOST_MEMORY);
            }
        }

        let ctx = LogicalClientInstance::new(identity);
        let id = ctx.id.clone();
        contexts.insert(id.clone(), ctx);
        Ok(id)
    }

    /// Returns the current number of active contexts.
    pub async fn context_count(&self) -> usize {
        self.contexts.read().await.len()
    }

    /// Returns the currently active context IDs.
    pub async fn context_ids(&self) -> Vec<ClientContextId> {
        self.contexts.read().await.keys().cloned().collect()
    }

    pub async fn get_context<F, R>(&self, id: &ClientContextId, f: F) -> Option<R>
    where
        F: FnOnce(&mut LogicalClientInstance) -> R,
    {
        let mut contexts = self.contexts.write().await;
        contexts.get_mut(id).map(|ctx| {
            ctx.touch();
            f(ctx)
        })
    }

    pub async fn context_identity(&self, id: &ClientContextId) -> Option<String> {
        self.contexts.read().await.get(id).and_then(|ctx| ctx.authenticated_identity.clone())
    }

    pub async fn remove_context(&self, id: &ClientContextId) -> Option<LogicalClientInstance> {
        self.contexts.write().await.remove(id)
    }

    /// Evict expired contexts (called periodically).
    pub async fn evict_expired(
        &self,
        backend: &Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend>,
    ) -> Vec<ClientContextId> {
        let mut contexts = self.contexts.write().await;
        let now = Instant::now();
        let expired = self.collect_expired_context_ids(&contexts, now);
        let all_backend_sessions = Self::drain_expired_contexts(&mut contexts, &expired);
        drop(contexts); // release the lock before blocking FFI calls
        Self::close_backend_sessions(backend, all_backend_sessions).await;
        expired
    }

    fn collect_expired_context_ids(
        &self,
        contexts: &HashMap<ClientContextId, LogicalClientInstance>,
        now: Instant,
    ) -> Vec<ClientContextId> {
        contexts
            .iter()
            .filter(|(_, ctx)| now.duration_since(ctx.last_active) > self.lease_duration)
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn drain_expired_contexts(
        contexts: &mut HashMap<ClientContextId, LogicalClientInstance>,
        expired: &[ClientContextId],
    ) -> Vec<u64> {
        let mut backend_sessions = Vec::new();
        for id in expired {
            if let Some(mut ctx) = contexts.remove(id) {
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
