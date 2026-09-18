use std::collections::{HashMap, HashSet};

/// Opaque backend handle (never exposed to clients).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackendHandle(pub u64);

/// Virtual handle visible to the client (ADR-0002 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VirtualHandle(pub u64);

/// Bidirectional mapping between virtual handles (client-facing) and
/// backend handles (real PKCS#11 module). Scoped per logical client instance.
pub struct HandleMap {
    next_id: u64,
    virtual_to_backend: HashMap<VirtualHandle, BackendHandle>,
    backend_to_virtual: HashMap<BackendHandle, VirtualHandle>,
    suspended_virtual_to_backend: HashMap<VirtualHandle, BackendHandle>,
}

impl Default for HandleMap {
    fn default() -> Self {
        Self::new()
    }
}

impl HandleMap {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            virtual_to_backend: HashMap::new(),
            backend_to_virtual: HashMap::new(),
            suspended_virtual_to_backend: HashMap::new(),
        }
    }

    pub fn insert(&mut self, backend: BackendHandle) -> VirtualHandle {
        // Return existing virtual handle if this backend handle is already mapped
        // (idempotent, like SlotMap::register).
        if let Some(&existing) = self.backend_to_virtual.get(&backend) {
            return existing;
        }
        let virt = VirtualHandle(self.next_id);
        self.next_id += 1;
        self.virtual_to_backend.insert(virt, backend);
        self.backend_to_virtual.insert(backend, virt);
        virt
    }

    pub fn resolve(&self, virt: VirtualHandle) -> Option<BackendHandle> {
        self.virtual_to_backend.get(&virt).copied()
    }

    pub fn resolve_backend(&self, backend: BackendHandle) -> Option<VirtualHandle> {
        self.backend_to_virtual.get(&backend).copied()
    }

    pub fn remove(&mut self, virt: VirtualHandle) -> Option<BackendHandle> {
        let backend = self
            .virtual_to_backend
            .remove(&virt)
            .or_else(|| self.suspended_virtual_to_backend.remove(&virt));
        if let Some(backend) = backend {
            // A suspended raw handle may already have been recycled and bound
            // to a newer virtual handle.  Never delete that newer reverse map.
            if self.backend_to_virtual.get(&backend) == Some(&virt) {
                self.backend_to_virtual.remove(&backend);
            }
            Some(backend)
        } else {
            None
        }
    }

    /// Make `virt` temporarily unresolvable while retaining the expected raw
    /// handle for close completion and teardown.  Detaching the reverse entry
    /// allows a provider-recycled raw handle to receive a fresh virtual id.
    pub fn suspend(&mut self, virt: VirtualHandle) -> Option<BackendHandle> {
        let backend = self.virtual_to_backend.remove(&virt)?;
        if self.backend_to_virtual.get(&backend) == Some(&virt) {
            self.backend_to_virtual.remove(&backend);
        }
        self.suspended_virtual_to_backend.insert(virt, backend);
        Some(backend)
    }

    pub fn suspended_backend(&self, virt: VirtualHandle) -> Option<BackendHandle> {
        self.suspended_virtual_to_backend.get(&virt).copied()
    }

    /// Reactivate exactly the suspended mapping when the raw handle has not
    /// meanwhile been rebound.  A stale close completion cannot steal an ABA
    /// binding from a newer virtual handle.
    pub fn reactivate_suspended(
        &mut self,
        virt: VirtualHandle,
        expected_backend: BackendHandle,
    ) -> bool {
        if self.suspended_backend(virt) != Some(expected_backend) {
            return false;
        }
        if self.backend_to_virtual.get(&expected_backend).is_some_and(|bound| *bound != virt) {
            return false;
        }
        self.suspended_virtual_to_backend.remove(&virt);
        self.virtual_to_backend.insert(virt, expected_backend);
        self.backend_to_virtual.insert(expected_backend, virt);
        true
    }

    pub fn clear(&mut self) {
        self.virtual_to_backend.clear();
        self.backend_to_virtual.clear();
        self.suspended_virtual_to_backend.clear();
    }

    pub fn virtual_handles(&self) -> impl Iterator<Item = VirtualHandle> + '_ {
        self.virtual_to_backend.keys().copied()
    }

    /// All raw handles retained by active or suspended entries, deduplicated
    /// for context teardown when an ABA-recycled value appears in both maps.
    pub fn backend_handles(&self) -> impl Iterator<Item = BackendHandle> + '_ {
        let handles: HashSet<BackendHandle> = self
            .virtual_to_backend
            .values()
            .chain(self.suspended_virtual_to_backend.values())
            .copied()
            .collect();
        handles.into_iter()
    }

    /// True when `backend` is retained by this map in any state (active or
    /// suspended). Used for the teardown refcount check (D9): a departing
    /// context's backend session is closed only when no live context still
    /// references it.
    pub fn references_backend(&self, backend: BackendHandle) -> bool {
        self.backend_to_virtual.contains_key(&backend)
            || self.suspended_virtual_to_backend.values().any(|b| *b == backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_and_resolve() {
        let mut map = HandleMap::new();
        let virtual_h = map.insert(BackendHandle(100));
        assert_eq!(map.resolve(virtual_h), Some(BackendHandle(100)));
    }

    #[test]
    fn remove_invalidates() {
        let mut map = HandleMap::new();
        let virtual_h = map.insert(BackendHandle(100));
        map.remove(virtual_h);
        assert_eq!(map.resolve(virtual_h), None);
    }

    #[test]
    fn handles_are_unique() {
        let mut map = HandleMap::new();
        let h1 = map.insert(BackendHandle(100));
        let h2 = map.insert(BackendHandle(200));
        assert_ne!(h1, h2);
    }

    #[test]
    fn insert_same_backend_is_idempotent() {
        let mut map = HandleMap::new();
        let h1 = map.insert(BackendHandle(100));
        let h2 = map.insert(BackendHandle(100));
        assert_eq!(h1, h2);
        assert_eq!(map.resolve(h1), Some(BackendHandle(100)));
        assert_eq!(map.resolve_backend(BackendHandle(100)), Some(h1));
    }

    #[test]
    fn remove_also_clears_reverse_mapping() {
        // After remove(virt), the backend→virtual reverse mapping must also be gone.
        let mut map = HandleMap::new();
        let virt = map.insert(BackendHandle(77));
        map.remove(virt);
        assert_eq!(map.resolve(virt), None);
        assert_eq!(map.resolve_backend(BackendHandle(77)), None);
    }

    #[test]
    fn clear_empties_both_directions() {
        let mut map = HandleMap::new();
        let h1 = map.insert(BackendHandle(10));
        let h2 = map.insert(BackendHandle(20));
        map.clear();
        assert_eq!(map.resolve(h1), None);
        assert_eq!(map.resolve(h2), None);
        assert_eq!(map.resolve_backend(BackendHandle(10)), None);
        assert_eq!(map.resolve_backend(BackendHandle(20)), None);
    }

    #[test]
    fn virtual_handles_iterator_returns_all() {
        let mut map = HandleMap::new();
        let h1 = map.insert(BackendHandle(10));
        let h2 = map.insert(BackendHandle(20));
        let h3 = map.insert(BackendHandle(30));
        let mut virts: Vec<VirtualHandle> = map.virtual_handles().collect();
        virts.sort_by_key(|v| v.0);
        assert_eq!(virts, vec![h1, h2, h3]);
    }

    #[test]
    fn resolve_unknown_virtual_returns_none() {
        let map = HandleMap::new();
        assert_eq!(map.resolve(VirtualHandle(999)), None);
    }

    #[test]
    fn resolve_unknown_backend_returns_none() {
        let map = HandleMap::new();
        assert_eq!(map.resolve_backend(BackendHandle(999)), None);
    }

    #[test]
    fn remove_unknown_handle_returns_none() {
        let mut map = HandleMap::new();
        assert_eq!(map.remove(VirtualHandle(999)), None);
    }

    #[test]
    fn handles_start_at_one() {
        // PKCS#11 handle 0 is CK_INVALID_HANDLE; virtual handles must start at 1.
        let mut map = HandleMap::new();
        let h = map.insert(BackendHandle(1));
        assert_ne!(h.0, 0, "virtual handle 0 is CK_INVALID_HANDLE — must not be allocated");
    }

    #[test]
    fn handles_increase_after_remove_and_reinsert() {
        // After removing a backend handle and reinserting a different one,
        // the new virtual handle must be distinct from the old one.
        let mut map = HandleMap::new();
        let h1 = map.insert(BackendHandle(100));
        map.remove(h1);
        let h2 = map.insert(BackendHandle(200));
        assert_ne!(h1, h2);
    }

    #[test]
    fn suspended_handle_is_unresolvable_and_recycled_backend_gets_a_new_virtual() {
        let mut map = HandleMap::new();
        let backend = BackendHandle(77);
        let old = map.insert(backend);

        assert_eq!(map.suspend(old), Some(backend));
        assert_eq!(map.resolve(old), None);
        assert_eq!(map.resolve_backend(backend), None);
        assert_eq!(map.suspended_backend(old), Some(backend));

        let new = map.insert(backend);
        assert_ne!(new, old);
        assert_eq!(map.resolve(new), Some(backend));
        assert_eq!(map.resolve_backend(backend), Some(new));

        assert_eq!(map.remove(old), Some(backend));
        assert_eq!(map.resolve(new), Some(backend));
        assert_eq!(map.resolve_backend(backend), Some(new));
    }

    #[test]
    fn transient_old_completion_cannot_steal_recycled_backend_binding() {
        let mut map = HandleMap::new();
        let backend = BackendHandle(77);
        let old = map.insert(backend);
        assert_eq!(map.suspend(old), Some(backend));
        let new = map.insert(backend);

        assert!(!map.reactivate_suspended(old, backend));
        assert_eq!(map.resolve(old), None);
        assert_eq!(map.suspended_backend(old), Some(backend));
        assert_eq!(map.resolve(new), Some(backend));
        assert_eq!(map.resolve_backend(backend), Some(new));
    }

    #[test]
    fn transient_completion_reactivates_suspended_mapping_when_backend_is_unbound() {
        let mut map = HandleMap::new();
        let backend = BackendHandle(77);
        let old = map.insert(backend);
        assert_eq!(map.suspend(old), Some(backend));

        assert!(map.reactivate_suspended(old, backend));
        assert_eq!(map.resolve(old), Some(backend));
        assert_eq!(map.resolve_backend(backend), Some(old));
        assert_eq!(map.suspended_backend(old), None);
    }

    #[test]
    fn backend_handles_include_suspended_entries_without_duplicates() {
        let mut map = HandleMap::new();
        let backend = BackendHandle(77);
        let old = map.insert(backend);
        assert_eq!(map.suspend(old), Some(backend));
        let _new = map.insert(backend);

        assert_eq!(map.backend_handles().collect::<Vec<_>>(), vec![backend]);
    }
}
