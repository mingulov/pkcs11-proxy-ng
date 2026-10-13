//! F4 round-2: suspect marking vs membership removal interleave.
//!
//! `mark_slot_sessions_suspect` collects members under `SESSION_SLOTS`
//! and extends `SUSPECT_AFTER_BATCH_FAILURE` after releasing it, while
//! the removal paths (`evict_slot_session_caches`,
//! `evict_session_authoritative_state`) remove under `SESSION_SLOTS`
//! and clear the suspect mark after. When a mark's collect/extend
//! straddles a removal, the dead session's mark is recreated after its
//! clear — an orphan mark for a session with no membership, violating
//! the map's live-bounded doc invariant. The hammer collides both
//! shapes until the interleave lands (pre-fix); the fix serializes
//! both sides under one lock order so no orphan can exist.

use super::*;
use cryptoki_sys::{CK_SESSION_HANDLE, CK_SLOT_ID};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Slot/handle range reserved for this hammer: far from any production
/// or fixture id, and fully drained at the end so no residue leaks into
/// other tests sharing the process-global maps.
const INTERLEAVE_SLOT: u64 = 0xF4F4_F4F4;
const INTERLEAVE_HANDLES: [u64; 8] = [
    0xF4F4_0000,
    0xF4F4_0001,
    0xF4F4_0002,
    0xF4F4_0003,
    0xF4F4_0004,
    0xF4F4_0005,
    0xF4F4_0006,
    0xF4F4_0007,
];

#[test]
fn suspect_marking_never_orphans_against_concurrent_removal() {
    let _guard = shim_state_test_guard();
    for handle in INTERLEAVE_HANDLES {
        crate::state::remember_session_slot(
            handle as CK_SESSION_HANDLE,
            INTERLEAVE_SLOT as CK_SLOT_ID,
        );
    }
    const ITERS: usize = 3000;
    let marker = std::thread::spawn(|| {
        for _ in 0..ITERS {
            for handle in INTERLEAVE_HANDLES {
                crate::state::remember_session_slot(
                    handle as CK_SESSION_HANDLE,
                    INTERLEAVE_SLOT as CK_SLOT_ID,
                );
            }
            crate::state::mark_slot_sessions_suspect(INTERLEAVE_SLOT as CK_SLOT_ID);
        }
    });
    let evictor = std::thread::spawn(|| {
        for i in 0..ITERS {
            if i % 2 == 0 {
                crate::state::evict_slot_session_caches(INTERLEAVE_SLOT as CK_SLOT_ID);
            } else {
                for handle in INTERLEAVE_HANDLES {
                    crate::state::evict_session_authoritative_state(handle as CK_SESSION_HANDLE);
                }
            }
        }
    });
    // Orphans are transient (later iterations re-member and clear
    // them), so end-state asserts alone cannot see them — sample the
    // atomic orphan probe while the race runs.
    let orphan_seen = Arc::new(AtomicBool::new(false));
    let sampler_seen = Arc::clone(&orphan_seen);
    let sampler = std::thread::spawn(move || {
        for _ in 0..ITERS {
            for handle in INTERLEAVE_HANDLES {
                if crate::state::session_suspect_without_membership(handle as CK_SESSION_HANDLE) {
                    sampler_seen.store(true, Ordering::Relaxed);
                    return;
                }
            }
        }
    });
    marker.join().unwrap();
    evictor.join().unwrap();
    sampler.join().unwrap();
    assert!(
        !orphan_seen.load(Ordering::Relaxed),
        "no suspect mark may exist without membership at any instant"
    );

    // Drain everything: no mark may survive without membership.
    crate::state::evict_slot_session_caches(INTERLEAVE_SLOT as CK_SLOT_ID);
    for handle in INTERLEAVE_HANDLES {
        let handle = handle as CK_SESSION_HANDLE;
        crate::state::evict_session_authoritative_state(handle);
        assert!(
            !crate::state::is_session_known(handle),
            "hammer handle {handle} must leave no membership residue"
        );
        assert!(
            !crate::state::is_session_suspect(handle),
            "hammer handle {handle} must leave no orphan suspect mark"
        );
    }
}
