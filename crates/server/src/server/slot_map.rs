use pkcs11_proxy_ng_types::CkSlotId;
use std::collections::HashMap;

/// Slot identifier exposed on the proxy wire; never a native provider identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VirtualSlotId(pub u64);

/// Native provider slot; owns sessions and keys token policy/login state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackendSlotId(pub CkSlotId);

/// Bidirectional slot ID mapping: virtual ↔ backend (ADR-0002 §4).
pub struct SlotMap {
    virtual_to_backend: HashMap<VirtualSlotId, BackendSlotId>,
    backend_to_virtual: HashMap<BackendSlotId, VirtualSlotId>,
    next_virtual: u64,
}

impl Default for SlotMap {
    fn default() -> Self {
        Self::new()
    }
}

impl SlotMap {
    pub fn new() -> Self {
        Self {
            virtual_to_backend: HashMap::new(),
            backend_to_virtual: HashMap::new(),
            next_virtual: 1,
        }
    }

    /// Register a backend slot, returns its virtual ID.
    pub fn register(&mut self, backend_slot: BackendSlotId) -> VirtualSlotId {
        if let Some(&existing) = self.backend_to_virtual.get(&backend_slot) {
            return existing;
        }
        let virtual_id = CkSlotId(self.next_virtual as u64);
        self.next_virtual += 1;
        self.virtual_to_backend.insert(virtual_id, backend_slot);
        self.backend_to_virtual.insert(backend_slot, virtual_id);
        virtual_id
    }

    /// Resolve virtual → backend slot ID.
    pub fn resolve(&self, virtual_slot: VirtualSlotId) -> Option<BackendSlotId> {
        self.virtual_to_backend.get(&virtual_slot).copied()
    }

    /// Map backend → virtual slot ID.
    pub fn to_virtual(&self, backend_slot: BackendSlotId) -> Option<VirtualSlotId> {
        self.backend_to_virtual.get(&backend_slot).copied()
    }

    /// All virtual slot IDs.
    pub fn virtual_slots(&self) -> Vec<VirtualSlotId> {
        self.virtual_to_backend.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_resolve() {
        let mut map = SlotMap::new();
        let virtual_slot = map.register(BackendSlotId(CkSlotId(42)));
        assert_eq!(map.resolve(virtual_slot), Some(BackendSlotId(CkSlotId(42))));
        assert_eq!(map.to_virtual(BackendSlotId(CkSlotId(42))), Some(virtual_slot));
    }

    #[test]
    fn registering_existing_backend_slot_preserves_virtual_identity() {
        let mut map = SlotMap::new();
        let first = map.register(BackendSlotId(CkSlotId(42)));
        let second = map.register(BackendSlotId(CkSlotId(42)));
        assert_eq!(first, second);
    }

    #[test]
    fn numeric_collision_preserves_both_slot_directions() {
        let mut map = SlotMap::new();
        assert_eq!(map.register(BackendSlotId(CkSlotId(42))), VirtualSlotId(1));
        assert_eq!(map.register(BackendSlotId(CkSlotId(1))), VirtualSlotId(2));
        assert_eq!(map.resolve(VirtualSlotId(1)), Some(BackendSlotId(CkSlotId(42))));
        assert_eq!(map.resolve(VirtualSlotId(2)), Some(BackendSlotId(CkSlotId(1))));
        assert_eq!(map.to_virtual(BackendSlotId(CkSlotId(42))), Some(VirtualSlotId(1)));
        assert_eq!(map.to_virtual(BackendSlotId(CkSlotId(1))), Some(VirtualSlotId(2)));
    }

    #[test]
    fn multiple_slots_get_distinct_virtual_ids() {
        let mut map = SlotMap::new();
        let first = map.register(BackendSlotId(CkSlotId(10)));
        let second = map.register(BackendSlotId(CkSlotId(20)));
        let third = map.register(BackendSlotId(CkSlotId(30)));
        assert_ne!(first, second);
        assert_ne!(second, third);
        assert_eq!(map.resolve(first), Some(BackendSlotId(CkSlotId(10))));
        assert_eq!(map.resolve(second), Some(BackendSlotId(CkSlotId(20))));
        assert_eq!(map.resolve(third), Some(BackendSlotId(CkSlotId(30))));
    }

    #[test]
    fn unknown_virtual_slot_returns_none() {
        let map = SlotMap::new();
        assert_eq!(map.resolve(VirtualSlotId(999)), None);
    }

    #[test]
    fn unknown_backend_slot_returns_none() {
        let map = SlotMap::new();
        assert_eq!(map.to_virtual(BackendSlotId(CkSlotId(999))), None);
    }

    #[test]
    fn virtual_slots_lists_all_registered_slots() {
        let mut map = SlotMap::new();
        let first = map.register(BackendSlotId(CkSlotId(1)));
        let second = map.register(BackendSlotId(CkSlotId(2)));
        let third = map.register(BackendSlotId(CkSlotId(3)));
        let mut slots = map.virtual_slots();
        slots.sort_by_key(|slot| slot.0);
        assert_eq!(slots, vec![first, second, third]);
    }

    #[test]
    fn virtual_ids_start_at_one() {
        let mut map = SlotMap::new();
        let virtual_slot = map.register(BackendSlotId(CkSlotId(999)));
        assert_ne!(virtual_slot.0, 0);
    }
}
