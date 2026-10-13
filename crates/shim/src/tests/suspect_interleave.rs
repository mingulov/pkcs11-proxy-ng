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
//!
//! Round-4 hardening (m2): independent fixed-length loops let the
//! sampler finish before the conflicting work starts, so a green run
//! proves no concurrent coverage. A start barrier now launches all
//! three threads together, each worker rendezvouses with the sampler
//! mid-flight (proving overlap structurally, not by timing luck), and
//! the sampler runs completion-controlled until both workers finish.

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
    const RENDEZVOUS_AT: usize = ITERS / 2;
    // Start barrier: all three threads enter the race together, so the
    // sampler cannot finish before the conflicting work starts.
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let marker_barrier = Arc::clone(&barrier);
    let evictor_barrier = Arc::clone(&barrier);
    // Mid-flight rendezvous: each worker parks at half its loop until
    // the sampler observes it there, proving the sampler ran while the
    // worker was mid-flight (structural overlap, not timing luck).
    let marker_half = Arc::new(AtomicBool::new(false));
    let marker_ack = Arc::new(AtomicBool::new(false));
    let marker_done = Arc::new(AtomicBool::new(false));
    let evictor_half = Arc::new(AtomicBool::new(false));
    let evictor_ack = Arc::new(AtomicBool::new(false));
    let evictor_done = Arc::new(AtomicBool::new(false));
    let sampler_marker_half = Arc::clone(&marker_half);
    let sampler_marker_ack = Arc::clone(&marker_ack);
    let sampler_marker_done = Arc::clone(&marker_done);
    let sampler_evictor_half = Arc::clone(&evictor_half);
    let sampler_evictor_ack = Arc::clone(&evictor_ack);
    let sampler_evictor_done = Arc::clone(&evictor_done);
    let worker_marker_half = Arc::clone(&marker_half);
    let worker_marker_ack = Arc::clone(&marker_ack);
    let worker_marker_done = Arc::clone(&marker_done);
    let worker_evictor_half = Arc::clone(&evictor_half);
    let worker_evictor_ack = Arc::clone(&evictor_ack);
    let worker_evictor_done = Arc::clone(&evictor_done);
    let marker = std::thread::spawn(move || {
        marker_barrier.wait();
        for i in 0..ITERS {
            for handle in INTERLEAVE_HANDLES {
                crate::state::remember_session_slot(
                    handle as CK_SESSION_HANDLE,
                    INTERLEAVE_SLOT as CK_SLOT_ID,
                );
            }
            crate::state::mark_slot_sessions_suspect(INTERLEAVE_SLOT as CK_SLOT_ID);
            if i == RENDEZVOUS_AT {
                worker_marker_half.store(true, Ordering::SeqCst);
                while !worker_marker_ack.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
            }
        }
        worker_marker_done.store(true, Ordering::SeqCst);
    });
    let evictor = std::thread::spawn(move || {
        evictor_barrier.wait();
        for i in 0..ITERS {
            if i % 2 == 0 {
                crate::state::evict_slot_session_caches(INTERLEAVE_SLOT as CK_SLOT_ID);
            } else {
                for handle in INTERLEAVE_HANDLES {
                    crate::state::evict_session_authoritative_state(handle as CK_SESSION_HANDLE);
                }
            }
            if i == RENDEZVOUS_AT {
                worker_evictor_half.store(true, Ordering::SeqCst);
                while !worker_evictor_ack.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
            }
        }
        worker_evictor_done.store(true, Ordering::SeqCst);
    });
    // Orphans are transient (later iterations re-member and clear
    // them), so end-state asserts alone cannot see them — sample the
    // atomic orphan probe completion-controlled, until both workers
    // finish. No early return on an orphan: the workers park at the
    // rendezvous until acked, so the sampler must run to completion.
    let orphan_seen = Arc::new(AtomicBool::new(false));
    let sampler_seen = Arc::clone(&orphan_seen);
    let sampler = std::thread::spawn(move || {
        barrier.wait();
        let mut rounds: usize = 0;
        while !sampler_marker_done.load(Ordering::SeqCst)
            || !sampler_evictor_done.load(Ordering::SeqCst)
        {
            for handle in INTERLEAVE_HANDLES {
                if crate::state::session_suspect_without_membership(handle as CK_SESSION_HANDLE) {
                    sampler_seen.store(true, Ordering::SeqCst);
                }
            }
            if sampler_marker_half.load(Ordering::SeqCst) {
                sampler_marker_ack.store(true, Ordering::SeqCst);
            }
            if sampler_evictor_half.load(Ordering::SeqCst) {
                sampler_evictor_ack.store(true, Ordering::SeqCst);
            }
            rounds += 1;
        }
        rounds
    });
    marker.join().unwrap();
    evictor.join().unwrap();
    let rounds = sampler.join().unwrap();
    assert!(
        !orphan_seen.load(Ordering::SeqCst),
        "no suspect mark may exist without membership at any instant"
    );
    assert!(
        marker_ack.load(Ordering::SeqCst) && evictor_ack.load(Ordering::SeqCst),
        "the sampler must observe both workers mid-flight (structural overlap, {rounds} rounds)"
    );
    assert!(rounds > 0, "the sampler must run while the workers run");

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
