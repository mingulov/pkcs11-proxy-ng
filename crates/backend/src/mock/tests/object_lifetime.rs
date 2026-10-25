use super::*;

/// Object-lifetime binding: a bound destroy captured against a minted
/// object refuses (OBJECT_HANDLE_INVALID, no destroy issued) once the
/// numeric handle has been destroyed and reused within the SAME live
/// session, and still destroys while the lifetime matches.
#[test]
fn bound_destroy_refuses_stale_object_lifetime_in_same_session() {
    let backend = MockBackend::default_test();
    backend.set_handle_recycling(true);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let incarnation = backend.session_incarnation(session);

    let minted = backend.create_object(session, Some(&[])).unwrap();
    let lifetime =
        backend.object_lifetime(session, minted).expect("minted object must carry a lifetime");

    // The client destroys the original and a new mint reuses the
    // numeric handle in the same live session.
    backend.destroy_object(session, minted).unwrap();
    assert_eq!(backend.object_lifetime(session, minted), None);
    let replacement = backend.create_object(session, Some(&[])).unwrap();
    assert_eq!(replacement, minted, "recycling mock must reuse the object handle");
    let replacement_lifetime =
        backend.object_lifetime(session, replacement).expect("replacement must carry a lifetime");
    assert_ne!(lifetime, replacement_lifetime);

    let destroys_before = backend.destroy_call_count();
    assert_eq!(
        backend.destroy_object_if_bound(session, replacement, incarnation, Some(lifetime)),
        Err(CkRv::OBJECT_HANDLE_INVALID),
        "stale lifetime must refuse the bound destroy"
    );
    assert_eq!(
        backend.destroy_call_count(),
        destroys_before,
        "stale-lifetime refusal must issue no destroy"
    );
    assert_eq!(backend.live_object_count(), 1, "replacement must survive");

    // Positive control: the current lifetime still destroys.
    backend
        .destroy_object_if_bound(session, replacement, incarnation, Some(replacement_lifetime))
        .unwrap();
    assert_eq!(backend.live_object_count(), 0);
    assert_eq!(backend.object_lifetime(session, replacement), None);
}

/// Legacy fallback preserved: with NO captured lifetime against an
/// object the backend does not track (current `None` — the state an
/// untracked backend reports for every object), the bound destroy is
/// the legacy raw destroy. An uncaptured incarnation likewise keeps
/// the legacy path. (No capture against a TRACKED object refuses
/// instead; see `bound_destroy_no_capture_against_tracking_backend_refuses`.)
#[test]
fn bound_destroy_legacy_fallbacks_still_destroy() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();

    let first = backend.create_object(session, Some(&[])).unwrap();
    // Simulate an untracked object (what a backend without lifetime
    // tracking reports): no live entry for the handle.
    backend.state.lock().unwrap().object_lifetimes.remove(&(session.0, first.0));
    assert_eq!(backend.object_lifetime(session, first), None);
    backend.destroy_object_if_bound(session, first, None, None).unwrap();
    assert_eq!(backend.live_object_count(), 0);

    let second = backend.create_object(session, Some(&[])).unwrap();
    let lifetime = backend.object_lifetime(session, second);
    backend.destroy_object_if_bound(session, second, None, lifetime).unwrap();
    assert_eq!(backend.live_object_count(), 0);
}

/// Atomic mint capture: pairs reported at the fresh-record site are
/// collected for the capture's session only, exactly as minted —
/// a later destroy+recreate cannot rewrite them.
#[test]
fn mint_capture_collects_mint_pairs_atomically() {
    let backend = MockBackend::default_test();
    backend.set_handle_recycling(true);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let other = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();

    let capture = crate::mint_capture::begin(session);
    let minted = backend.create_object(session, Some(&[])).unwrap();
    // A mint on a different session inside the window is not ours.
    let foreign = backend.create_object(other, Some(&[])).unwrap();
    let captured = capture.captured();
    drop(capture);

    let minted_lifetime = backend.object_lifetime(session, minted).unwrap();
    assert_eq!(captured, vec![(minted, minted_lifetime)]);
    assert_eq!(capture_lifetime_for(&captured, minted), Some(minted_lifetime));
    assert_eq!(capture_lifetime_for(&captured, foreign), None);

    // Destroy+recreate after the mint: the captured pair still names
    // the ORIGINAL lifetime, so settlement refuses and the valid
    // replacement survives (the pre-fix query-at-payload-build bound
    // would have captured the replacement's lifetime and destroyed it).
    backend.destroy_object(session, minted).unwrap();
    let replacement = backend.create_object(session, Some(&[])).unwrap();
    assert_eq!(replacement, minted);
    assert_ne!(backend.object_lifetime(session, replacement), Some(minted_lifetime));
    let destroys_before = backend.destroy_call_count();
    assert_eq!(
        backend.destroy_object_if_bound(
            session,
            replacement,
            backend.session_incarnation(session),
            capture_lifetime_for(&captured, minted),
        ),
        Err(CkRv::OBJECT_HANDLE_INVALID),
    );
    assert_eq!(backend.destroy_call_count(), destroys_before);
    assert_eq!(backend.live_object_count(), 2, "replacement and foreign object survive");
    backend.get_object_size(session, replacement).expect("replacement remains usable");
}

/// Contention poison (Defect A, mock mirror): a fresh record that
/// finds an existing lifetime entry for the same numeric handle
/// under ANY session is racing another object's record. The table
/// still updates to the newest id, but the mint capture reports
/// nothing, so settlement (None against Some) refuses and the
/// tracked object survives. The competitor entry is seeded
/// directly because the mock allocator cannot reissue a live
/// handle — seeding is the deterministic equivalent of the
/// competitor's fresh record landing inside the allocation funnel
/// between handle allocation and lifetime recording.
#[test]
fn contended_mint_capture_is_poisoned_and_replacement_survives() {
    let backend = MockBackend::default_test();
    backend.set_handle_recycling(true);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let other = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let incarnation = backend.session_incarnation(session);

    // Competitor tracks handle 1 (the next handle this mint will
    // allocate) under a different session.
    backend.state.lock().unwrap().object_lifetimes.insert((other.0, 1), 9999);

    let capture = crate::mint_capture::begin(session);
    let minted = backend.create_object(session, Some(&[])).unwrap();
    assert_eq!(minted, CkObjectHandle(1), "setup: mint must allocate the contended handle");
    let captured = capture.captured();
    let captured_lifetime = capture_lifetime_for(&captured, minted);
    drop(capture);

    assert_eq!(
        captured,
        Vec::<(CkObjectHandle, u64)>::new(),
        "contended mint capture must be poisoned (report nothing)"
    );
    assert_eq!(captured_lifetime, None, "poisoned capture carries None for the handle");
    assert!(
        backend.object_lifetime(session, minted).is_some(),
        "table must still update its entry to the newest fresh id"
    );
    assert_ne!(
        backend.object_lifetime(session, minted),
        Some(9999),
        "table entry must be the newest fresh id, not the competitor's"
    );

    let destroys_before = backend.destroy_call_count();
    assert_eq!(
        backend.destroy_object_if_bound(session, minted, incarnation, captured_lifetime),
        Err(CkRv::OBJECT_HANDLE_INVALID),
        "poisoned settlement (None against a tracking backend) must refuse"
    );
    assert_eq!(backend.destroy_call_count(), destroys_before, "refusal must issue no destroy");
    assert_eq!(backend.live_object_count(), 1, "tracked object must survive");
    backend.get_object_size(session, minted).expect("object remains usable");

    // Positive control: an undisturbed mint still captures and
    // settles exactly once.
    let capture2 = crate::mint_capture::begin(session);
    let second = backend.create_object(session, Some(&[])).unwrap();
    let captured2 = capture2.captured();
    let captured2_lifetime = capture_lifetime_for(&captured2, second);
    drop(capture2);
    let second_lifetime = backend.object_lifetime(session, second).expect("tracked mint");
    assert_eq!(captured2, vec![(second, second_lifetime)]);
    backend.destroy_object_if_bound(session, second, incarnation, captured2_lifetime).unwrap();
    assert_eq!(backend.object_lifetime(session, second), None);
}

fn capture_lifetime_for(captured: &[(CkObjectHandle, u64)], handle: CkObjectHandle) -> Option<u64> {
    captured.iter().find(|(h, _)| *h == handle).map(|(_, l)| *l)
}

/// Mint-capture isolation: a dropped capture leaks nothing into the
/// next capture on the same thread (pooled blocking threads mint
/// sequentially), and dropping a nested capture restores the outer
/// one, which keeps collecting.
#[test]
fn mint_capture_sequential_and_nested_captures_are_isolated() {
    let session = CkSessionHandle(71);

    // Sequential: the first capture collects and drops; the second
    // capture on the same thread starts empty.
    let first = crate::mint_capture::begin(session);
    crate::mint_capture::report(session, CkObjectHandle(101), 1001);
    assert_eq!(first.captured(), vec![(CkObjectHandle(101), 1001)]);
    drop(first);

    let second = crate::mint_capture::begin(session);
    assert!(second.captured().is_empty(), "second capture must start empty");
    crate::mint_capture::report(session, CkObjectHandle(102), 1002);
    assert_eq!(second.captured(), vec![(CkObjectHandle(102), 1002)]);
    drop(second);

    // Nested: the inner capture starts empty and collects only its
    // own report; dropping it restores the outer capture, which
    // still holds its earlier pair and keeps collecting.
    let outer = crate::mint_capture::begin(session);
    crate::mint_capture::report(session, CkObjectHandle(201), 2001);
    {
        let inner = crate::mint_capture::begin(session);
        assert!(inner.captured().is_empty(), "inner capture must start empty");
        crate::mint_capture::report(session, CkObjectHandle(202), 2002);
        assert_eq!(inner.captured(), vec![(CkObjectHandle(202), 2002)]);
        drop(inner);
    }
    assert_eq!(outer.captured(), vec![(CkObjectHandle(201), 2001)]);
    crate::mint_capture::report(session, CkObjectHandle(203), 2003);
    assert_eq!(
        outer.captured(),
        vec![(CkObjectHandle(201), 2001), (CkObjectHandle(203), 2003)],
        "outer capture must still collect after the inner capture drops"
    );
    drop(outer);

    // After the outer capture drops, no capture remains on this
    // thread: a stray report is a no-op and the next capture is empty.
    crate::mint_capture::report(session, CkObjectHandle(999), 9999);
    let third = crate::mint_capture::begin(session);
    assert!(third.captured().is_empty(), "capture after outer drop must start empty");
    drop(third);
}

/// Fail-safe settlement (captured Some, current None): the object is
/// gone or untracked under the settling session now — a raw destroy
/// could hit a replacement recorded under another session — so the
/// bound destroy must refuse without issuing any destroy.
#[test]
fn bound_destroy_captured_some_current_none_refuses_without_destroy() {
    let backend = MockBackend::default_test();
    backend.set_handle_recycling(true);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let incarnation = backend.session_incarnation(session);

    let minted = backend.create_object(session, Some(&[])).unwrap();
    let lifetime =
        backend.object_lifetime(session, minted).expect("minted object must carry a lifetime");
    backend.destroy_object(session, minted).unwrap();
    assert_eq!(backend.object_lifetime(session, minted), None);

    let destroys_before = backend.destroy_call_count();
    assert_eq!(
        backend.destroy_object_if_bound(session, minted, incarnation, Some(lifetime)),
        Err(CkRv::OBJECT_HANDLE_INVALID),
        "captured lifetime with no current entry must refuse"
    );
    assert_eq!(backend.destroy_call_count(), destroys_before, "refusal must issue no destroy");
}

/// Fail-safe settlement (captured None, current Some): a payload that
/// missed capture must not destroy against a backend that does track
/// lifetimes — the live entry proves tracking, so the uncaptured
/// destroy would be a blind raw-handle destroy.
#[test]
fn bound_destroy_no_capture_against_tracking_backend_refuses() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();

    let minted = backend.create_object(session, Some(&[])).unwrap();
    assert!(backend.object_lifetime(session, minted).is_some(), "mock tracks mints");

    let destroys_before = backend.destroy_call_count();
    assert_eq!(
        backend.destroy_object_if_bound(session, minted, None, None),
        Err(CkRv::OBJECT_HANDLE_INVALID),
        "missed capture against a tracking backend must refuse"
    );
    assert_eq!(backend.destroy_call_count(), destroys_before, "refusal must issue no destroy");
    assert_eq!(backend.live_object_count(), 1, "tracked object must survive an uncaptured settle");
    backend.get_object_size(session, minted).expect("object remains usable");
}

/// Destroy invalidation: a token object destroyed through a DIFFERENT
/// session must drop the lifetime entry under ALL sessions. Otherwise
/// the origin session's stale entry still matches its captured
/// lifetime and settlement destroys a replacement minted under the
/// destroying session.
#[test]
fn cross_session_destroy_invalidates_origin_entry_and_replacement_survives() {
    let backend = MockBackend::default_test();
    backend.set_handle_recycling(true);
    backend.initialize().unwrap();
    let origin = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let other = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let incarnation = backend.session_incarnation(origin);
    let token_template = [CkAttribute {
        attr_type: CkAttributeType::TOKEN,
        value: Some(CkAttributeValue::Bool(true)),
    }];

    let minted = backend.create_object(origin, Some(&token_template)).unwrap();
    let lifetime =
        backend.object_lifetime(origin, minted).expect("minted object must carry a lifetime");

    // The token object surfaces in the other session (find records it
    // there too), then is destroyed through that session.
    backend.set_find_objects_result(vec![minted]);
    backend.find_objects_init(other, Some(&[])).unwrap();
    assert_eq!(backend.find_objects(other, 10).unwrap(), vec![minted]);
    backend.find_objects_final(other).unwrap();
    assert!(backend.object_lifetime(other, minted).is_some());
    backend.destroy_object(other, minted).unwrap();
    assert_eq!(
        backend.object_lifetime(origin, minted),
        None,
        "destroy through another session must invalidate the origin entry"
    );
    assert_eq!(backend.object_lifetime(other, minted), None);

    // A replacement reuses the numeric handle, minted under the other
    // session. Settlement from the ORIGIN session with the captured
    // lifetime must not destroy it.
    let replacement = backend.create_object(other, Some(&token_template)).unwrap();
    assert_eq!(replacement, minted, "recycling mock must reuse the object handle");
    let destroys_before = backend.destroy_call_count();
    assert_eq!(
        backend.destroy_object_if_bound(origin, replacement, incarnation, Some(lifetime)),
        Err(CkRv::OBJECT_HANDLE_INVALID),
        "stale origin settlement must refuse after cross-session destroy"
    );
    assert_eq!(backend.destroy_call_count(), destroys_before, "refusal must issue no destroy");
    assert_eq!(backend.live_object_count(), 1, "replacement must survive");
    backend.get_object_size(other, replacement).expect("replacement remains usable");
}

/// Lifetime entries die with their object and with their session.
#[test]
fn object_lifetime_removed_on_destroy_close_and_finalize() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();

    let minted = backend.create_object(session, Some(&[])).unwrap();
    assert!(backend.object_lifetime(session, minted).is_some());
    backend.destroy_object(session, minted).unwrap();
    assert_eq!(backend.object_lifetime(session, minted), None);

    let second = backend.create_object(session, Some(&[])).unwrap();
    assert!(backend.object_lifetime(session, second).is_some());
    backend.close_session(session).unwrap();
    assert_eq!(backend.object_lifetime(session, second), None);

    let session2 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let third = backend.create_object(session2, Some(&[])).unwrap();
    assert!(backend.object_lifetime(session2, third).is_some());
    backend.finalize().unwrap();
    assert_eq!(backend.object_lifetime(session2, third), None);
}
