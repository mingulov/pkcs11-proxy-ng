//! Catches lost/stealing reverse bindings and dropped suspended teardown references.
//! The oracle stores only a vector of logical leases, never the product's maps.

use super::{BackendHandle, HandleMap, VirtualHandle};

#[derive(Clone, Copy, Debug)]
enum Action {
    Insert(u64),
    Remove(u64),
    Suspend(u64),
    Reactivate(u64, u64),
    Clear,
}

#[derive(Clone, Copy)]
struct Lease {
    virtual_id: u64,
    raw: u64,
    active: bool,
}

struct Model {
    leases: Vec<Lease>,
    next_id: u64,
}

impl Model {
    fn active_for(&self, raw: u64) -> Option<u64> {
        self.leases.iter().find(|lease| lease.raw == raw && lease.active).map(|l| l.virtual_id)
    }

    fn apply(&mut self, map: &mut HandleMap, action: Action, context: &str) {
        match action {
            Action::Insert(raw) => {
                let expected = match self.active_for(raw) {
                    Some(id) => id,
                    None => {
                        let id = self.next_id;
                        self.next_id += 1;
                        self.leases.push(Lease { virtual_id: id, raw, active: true });
                        id
                    }
                };
                assert_eq!(map.insert(BackendHandle(raw)), VirtualHandle(expected), "{context}");
            }
            Action::Remove(id) => {
                let expected = self
                    .leases
                    .iter()
                    .position(|l| l.virtual_id == id)
                    .map(|pos| self.leases.remove(pos).raw);
                assert_eq!(map.remove(VirtualHandle(id)).map(|b| b.0), expected, "{context}");
            }
            Action::Suspend(id) => {
                let expected =
                    self.leases.iter_mut().find(|l| l.virtual_id == id && l.active).map(|lease| {
                        lease.active = false;
                        lease.raw
                    });
                assert_eq!(map.suspend(VirtualHandle(id)).map(|b| b.0), expected, "{context}");
            }
            Action::Reactivate(id, raw) => {
                let expected = self.active_for(raw).is_none()
                    && self.leases.iter().any(|l| l.virtual_id == id && l.raw == raw && !l.active);
                if expected {
                    self.leases.iter_mut().find(|l| l.virtual_id == id).unwrap().active = true;
                }
                assert_eq!(
                    map.reactivate_suspended(VirtualHandle(id), BackendHandle(raw)),
                    expected,
                    "{context}"
                );
            }
            Action::Clear => {
                self.leases.clear();
                map.clear();
            }
        }
    }

    fn assert_observables(&self, map: &HandleMap, context: &str) {
        // Include invalid zero and the next unallocated id; old ids remain
        // checked after clear, which must not revive stale client handles.
        for id in 0..=self.next_id {
            let lease = self.leases.iter().find(|l| l.virtual_id == id);
            let live = lease.filter(|l| l.active).map(|l| BackendHandle(l.raw));
            let suspended = lease.filter(|l| !l.active).map(|l| BackendHandle(l.raw));
            assert_eq!(map.resolve(VirtualHandle(id)), live, "forward id={id}: {context}");
            assert_eq!(
                map.suspended_backend(VirtualHandle(id)),
                suspended,
                "suspended id={id}: {context}"
            );
            assert_eq!(
                map.is_proven_gone(VirtualHandle(id)),
                lease.is_none(),
                "gone id={id}: {context}"
            );
        }
        for raw in 0..=8 {
            assert_eq!(
                map.resolve_backend(BackendHandle(raw)).map(|v| v.0),
                self.active_for(raw),
                "reverse raw={raw}: {context}"
            );
            assert_eq!(
                map.references_backend(BackendHandle(raw)),
                self.leases.iter().any(|l| l.raw == raw),
                "reference raw={raw}: {context}"
            );
        }
        let mut live: Vec<_> = map.virtual_handles().map(|v| v.0).collect();
        live.sort_unstable();
        let mut expected_live: Vec<_> =
            self.leases.iter().filter(|l| l.active).map(|l| l.virtual_id).collect();
        expected_live.sort_unstable();
        assert_eq!(live, expected_live, "active set: {context}");
        let mut retained: Vec<_> = map.backend_handles().map(|b| b.0).collect();
        retained.sort_unstable();
        let mut expected_retained: Vec<_> = self.leases.iter().map(|l| l.raw).collect();
        expected_retained.sort_unstable();
        expected_retained.dedup();
        assert_eq!(retained, expected_retained, "retained set (including dedup): {context}");
    }
}

#[test]
fn seeded_handle_lifecycle_matches_vector_model() {
    // Catches unconditional reverse-map removal when a suspended raw value
    // has already been reused by another live virtual handle.
    let prefix = [
        Action::Insert(3),
        Action::Insert(3),
        Action::Suspend(1),
        Action::Reactivate(1, 4),
        Action::Reactivate(1, 3),
        Action::Suspend(1),
        Action::Insert(3),
        Action::Reactivate(1, 3),
        Action::Remove(1),
        Action::Suspend(2),
        Action::Reactivate(2, 4),
        Action::Reactivate(2, 3),
        Action::Suspend(2),
        Action::Clear,
        Action::Reactivate(2, 3),
        Action::Remove(2),
        Action::Insert(3),
        Action::Suspend(3),
        Action::Insert(3),
        Action::Remove(4),
        Action::Reactivate(3, 3),
        Action::Clear,
    ];
    for seed in [1_u64, 0x5eed, 0x0a89_7d83, 0xdead_beef, u64::MAX] {
        let mut rng = seed;
        let mut map = HandleMap::new();
        let mut model = Model { leases: Vec::new(), next_id: 1 };
        let mut trace = Vec::new();
        for step in 0..(prefix.len() + 512) {
            let action = if step < prefix.len() {
                prefix[step]
            } else {
                // Fixed xorshift recurrence: each failure is replayable from
                // the printed seed and trace prefix, without an RNG crate.
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                let raw = (rng >> 8) % 8;
                let id = (rng >> 16) % (model.next_id + 2);
                match rng % 16 {
                    0 => Action::Clear,
                    1..=5 => Action::Insert(raw),
                    6..=8 => Action::Remove(id),
                    9..=11 => Action::Suspend(id),
                    _ => Action::Reactivate(id, raw),
                }
            };
            trace.push(action);
            let context = format!("seed={seed:#x} step={step} trace={trace:?}");
            model.apply(&mut map, action, &context);
            model.assert_observables(&map, &context);
        }
    }
}
