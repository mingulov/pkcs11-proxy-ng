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

/// Tracking backend, no legacy fallback: with NO captured lifetime
/// the bound destroy refuses even when no live entry exists for the
/// handle (the emptied-table state). The `(None, None)` legacy raw
/// destroy remains only for non-tracking backends (see
/// `untracked_backend_legacy_destroy_still_works`). An uncaptured
/// incarnation with a captured lifetime still destroys.
#[test]
fn bound_destroy_legacy_fallbacks_still_destroy() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();

    let first = backend.create_object(session, Some(&[])).unwrap();
    backend.state.lock().unwrap().object_lifetimes.remove(&first.0);
    assert_eq!(backend.object_lifetime(session, first), None);
    assert!(backend.tracks_object_lifetimes(), "mock is a tracking backend");
    let destroys_before = backend.destroy_call_count();
    assert_eq!(
        backend.destroy_object_if_bound(session, first, None, None),
        Err(CkRv::OBJECT_HANDLE_INVALID),
        "tracking backend must refuse a None capture even with an empty table"
    );
    assert_eq!(backend.destroy_call_count(), destroys_before);
    assert_eq!(backend.live_object_count(), 1, "object must survive the refused settle");
    backend.destroy_object(session, first).unwrap();
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
    backend
        .state
        .lock()
        .unwrap()
        .object_lifetimes
        .insert(1, super::super::state::ObjectLifetimeEntry { lifetime: 9999, owner: other.0 });

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

/// I-1 cross-session residual (mock mirror): the original mint's
/// delayed fresh record lands between a competitor's cross-session
/// destroy and its recreate. The table then holds
/// `(origin,H)=idA` and `(competitor,H)=idB` for the replacement.
/// Settlement from the origin with `idA` must refuse with no counted
/// destroy, leaving the replacement usable. The delayed record is
/// seeded directly because the mock allocation funnel records
/// atomically with allocation and cannot split native return from
/// record; the competitor find/destroy/recreate run through real
/// mock APIs and the seeded entry is exactly the delayed record.
#[test]
fn cross_session_delayed_record_then_recreate_refuses_origin_settlement() {
    let backend = MockBackend::default_test();
    backend.set_handle_recycling(true);
    backend.initialize().unwrap();
    let origin = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let other = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let origin_incarnation = backend.session_incarnation(origin);
    let token_template = [CkAttribute {
        attr_type: CkAttributeType::TOKEN,
        value: Some(CkAttributeValue::Bool(true)),
    }];

    // Original mint in the origin session; capture its lifetime.
    let capture = crate::mint_capture::begin(origin);
    let minted = backend.create_object(origin, Some(&token_template)).unwrap();
    let captured = capture.captured();
    let captured_lifetime = capture_lifetime_for(&captured, minted);
    drop(capture);
    let id_a = backend.object_lifetime(origin, minted).expect("tracked mint");
    assert_eq!(captured_lifetime, Some(id_a));

    // Competitor FindObjects-records and destroys through the other
    // session, clearing every entry for the handle.
    backend.set_find_objects_result(vec![minted]);
    backend.find_objects_init(other, Some(&[])).unwrap();
    assert_eq!(backend.find_objects(other, 10).unwrap(), vec![minted]);
    backend.find_objects_final(other).unwrap();
    backend.destroy_object(other, minted).unwrap();
    assert_eq!(backend.object_lifetime(origin, minted), None);
    assert_eq!(backend.object_lifetime(other, minted), None);
    assert_eq!(backend.live_object_count(), 0);

    // Original thread's delayed fresh record lands now ( seeded:
    // the funnel cannot delay its record past the destroy above).
    backend.state.lock().unwrap().object_lifetimes.insert(
        minted.0,
        super::super::state::ObjectLifetimeEntry { lifetime: id_a, owner: origin.0 },
    );
    assert_eq!(backend.object_lifetime(origin, minted), Some(id_a));

    // Competitor recreates the same numeric handle; its capture is
    // poisoned by the origin entry and it inserts a newer id.
    let competitor_capture = crate::mint_capture::begin(other);
    let replacement = backend.create_object(other, Some(&token_template)).unwrap();
    assert_eq!(replacement, minted, "recycling mock must reuse the object handle");
    assert_eq!(
        competitor_capture.captured(),
        Vec::<(CkObjectHandle, u64)>::new(),
        "competitor recreate capture must be poisoned by the origin entry"
    );
    drop(competitor_capture);
    let id_b = backend.object_lifetime(other, replacement).expect("tracked replacement");
    assert_ne!(id_a, id_b);
    assert_eq!(
        backend.object_lifetime(origin, replacement),
        Some(id_b),
        "single handle-global entry must name the newest replacement, not the origin's stale id"
    );

    let destroys_before = backend.destroy_call_count();
    assert_eq!(
        backend.destroy_object_if_bound(origin, replacement, origin_incarnation, Some(id_a)),
        Err(CkRv::OBJECT_HANDLE_INVALID),
        "origin settlement must refuse when another session tracks a newer lifetime"
    );
    assert_eq!(
        backend.destroy_call_count(),
        destroys_before,
        "refused origin settlement must issue no destroy"
    );
    assert_eq!(backend.live_object_count(), 1, "replacement must survive");
    backend.get_object_size(other, replacement).expect("replacement remains usable");
    assert_eq!(backend.object_lifetime(other, replacement), Some(id_b));
}

/// Control: the same cross-session interleaving WITHOUT the
/// competitor recreate still settles the original exactly once.
/// The competitor destroy clears the prior object; the origin then
/// mints and records the only entry for the handle, so settlement
/// with its captured id destroys once and a second settle refuses.
#[test]
fn cross_session_delayed_record_without_recreate_settles_once() {
    let backend = MockBackend::default_test();
    backend.set_handle_recycling(true);
    backend.initialize().unwrap();
    let origin = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let other = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let origin_incarnation = backend.session_incarnation(origin);
    let token_template = [CkAttribute {
        attr_type: CkAttributeType::TOKEN,
        value: Some(CkAttributeValue::Bool(true)),
    }];

    // Prior object under the competitor session, found and destroyed
    // there so every entry for the handle is cleared.
    let prior = backend.create_object(other, Some(&token_template)).unwrap();
    backend.destroy_object(other, prior).unwrap();
    assert_eq!(backend.object_lifetime(origin, prior), None);
    assert_eq!(backend.object_lifetime(other, prior), None);

    // Origin mints the handle with no competitor recreate afterwards.
    let capture = crate::mint_capture::begin(origin);
    let minted = backend.create_object(origin, Some(&token_template)).unwrap();
    assert_eq!(minted, prior, "recycling mock must reuse the object handle");
    let captured = capture.captured();
    let captured_lifetime = capture_lifetime_for(&captured, minted);
    drop(capture);
    let id_a = backend.object_lifetime(origin, minted).expect("tracked mint");
    assert_eq!(captured_lifetime, Some(id_a));
    assert_eq!(
        backend.object_lifetime(other, minted),
        Some(id_a),
        "handle-global entry is the same record whichever session asks"
    );

    let destroys_before = backend.destroy_call_count();
    backend.destroy_object_if_bound(origin, minted, origin_incarnation, Some(id_a)).unwrap();
    assert_eq!(
        backend.destroy_call_count(),
        destroys_before + 1,
        "uncontended origin record must settle exactly once"
    );
    assert_eq!(backend.live_object_count(), 0);
    assert_eq!(backend.object_lifetime(origin, minted), None);
    assert_eq!(
        backend.destroy_object_if_bound(origin, minted, origin_incarnation, Some(id_a)),
        Err(CkRv::OBJECT_HANDLE_INVALID),
    );
    assert_eq!(backend.destroy_call_count(), destroys_before + 1);
}

/// Ordering (i) v2: competitor close must not leave origin's stale
/// entry sole-matching a still-live token replacement.
#[test]
fn v2_competitor_close_then_origin_settle_refuses() {
    let backend = MockBackend::default_test();
    backend.set_handle_recycling(true);
    backend.initialize().unwrap();
    let origin = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let other = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let origin_incarnation = backend.session_incarnation(origin);
    let token_template = [CkAttribute {
        attr_type: CkAttributeType::TOKEN,
        value: Some(CkAttributeValue::Bool(true)),
    }];
    let capture = crate::mint_capture::begin(origin);
    let minted = backend.create_object(origin, Some(&token_template)).unwrap();
    let id_a = capture.lifetime_for(minted).expect("mint capture");
    drop(capture);
    backend.set_find_objects_result(vec![minted]);
    backend.find_objects_init(other, Some(&[])).unwrap();
    assert_eq!(backend.find_objects(other, 10).unwrap(), vec![minted]);
    backend.find_objects_final(other).unwrap();
    backend.destroy_object(other, minted).unwrap();
    // Delayed origin record (seeded; mock funnel records atomically).
    backend.state.lock().unwrap().object_lifetimes.insert(
        minted.0,
        super::super::state::ObjectLifetimeEntry { lifetime: id_a, owner: origin.0 },
    );
    let comp_capture = crate::mint_capture::begin(other);
    let replacement = backend.create_object(other, Some(&token_template)).unwrap();
    assert_eq!(replacement, minted);
    assert_eq!(comp_capture.captured(), Vec::<(CkObjectHandle, u64)>::new());
    drop(comp_capture);
    let id_b = backend.object_lifetime(other, replacement).expect("replacement tracked");
    assert_ne!(id_a, id_b);
    backend.close_session(other).unwrap();
    let destroys_before = backend.destroy_call_count();
    assert_eq!(
        backend.destroy_object_if_bound(origin, replacement, origin_incarnation, Some(id_a)),
        Err(CkRv::OBJECT_HANDLE_INVALID),
        "competitor-close must not make origin settlement destroy replacement"
    );
    assert_eq!(backend.destroy_call_count(), destroys_before);
    assert_eq!(backend.live_object_count(), 1);
    backend.get_object_size(origin, replacement).expect("replacement usable via origin");
}

/// Ordering (ii) v2: poisoned capture must not reach legacy destroy
/// after destroy+recreate+owner-close empties the table.
#[test]
fn v2_poisoned_capture_after_emptying_cycle_refuses() {
    let backend = MockBackend::default_test();
    backend.set_handle_recycling(true);
    backend.initialize().unwrap();
    let origin = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let other = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let token_template = [CkAttribute {
        attr_type: CkAttributeType::TOKEN,
        value: Some(CkAttributeValue::Bool(true)),
    }];
    backend
        .state
        .lock()
        .unwrap()
        .object_lifetimes
        .insert(1, super::super::state::ObjectLifetimeEntry { lifetime: 9999, owner: other.0 });
    let capture = crate::mint_capture::begin(origin);
    let minted = backend.create_object(origin, Some(&token_template)).unwrap();
    assert_eq!(minted, CkObjectHandle(1));
    let captured = capture.lifetime_for(minted);
    drop(capture);
    assert_eq!(captured, None, "contended mint must be poisoned");
    backend.destroy_object(origin, minted).unwrap();
    let replacement = backend.create_object(other, Some(&token_template)).unwrap();
    assert_eq!(replacement, minted);
    backend.close_session(other).unwrap();
    assert_eq!(backend.object_lifetime(origin, replacement), None);
    let destroys_before = backend.destroy_call_count();
    assert_eq!(
        backend.destroy_object_if_bound(
            origin,
            replacement,
            backend.session_incarnation(origin),
            captured
        ),
        Err(CkRv::OBJECT_HANDLE_INVALID),
        "poisoned capture on tracking backend must refuse even with empty table"
    );
    assert_eq!(backend.destroy_call_count(), destroys_before);
    assert_eq!(backend.live_object_count(), 1);
    backend.get_object_size(origin, replacement).expect("replacement usable via origin");
}

/// Ordering (iii) v2: settlement racing a competitor
/// destroy+recreate must never destroy the replacement.
#[test]
fn v2_settlement_racing_recreate_never_destroys_replacement() {
    let backend = MockBackend::default_test();
    backend.set_handle_recycling(true);
    backend.initialize().unwrap();
    let origin = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let other = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let origin_incarnation = backend.session_incarnation(origin);
    let token_template = [CkAttribute {
        attr_type: CkAttributeType::TOKEN,
        value: Some(CkAttributeValue::Bool(true)),
    }];
    let minted = backend.create_object(origin, Some(&token_template)).unwrap();
    let id_a = backend.object_lifetime(origin, minted).expect("tracked mint");
    let backend_ref = &backend;
    let replacement = std::thread::scope(|scope| {
        let competitor = scope.spawn(move || {
            let _ = backend_ref.destroy_object(other, minted);
            backend_ref.create_object(other, Some(&token_template)).expect("recreate succeeds")
        });
        let settle = scope.spawn(move || {
            backend_ref.destroy_object_if_bound(origin, minted, origin_incarnation, Some(id_a))
        });
        let repl = competitor.join().expect("competitor joins");
        let _ = settle.join().expect("settle joins");
        repl
    });
    assert_eq!(backend.live_object_count(), 1, "replacement must survive the race");
    backend.get_object_size(other, replacement).expect("replacement usable");
    // A second settle with the stale id must also refuse.
    assert_eq!(
        backend.destroy_object_if_bound(origin, replacement, origin_incarnation, Some(id_a)),
        Err(CkRv::OBJECT_HANDLE_INVALID)
    );
    assert_eq!(backend.live_object_count(), 1);
}

/// Repeated race regression: settlement racing a competitor
/// destroy+recreate of the same numeric handle must never destroy
/// the replacement. The bound destroy historically composed
/// `session_incarnation()` + `object_lifetime()` (each locking
/// briefly) and then `destroy_object()` (locking again), so a
/// destroy+recreate could slip between the check and the destroy
/// and the bound destroy killed a valid replacement. Loop with a
/// barrier start to force interleavings; the replacement must
/// survive EVERY iteration.
#[test]
fn bound_destroy_racing_destroy_recreate_never_destroys_replacement_repeated() {
    let backend = MockBackend::default_test();
    backend.set_handle_recycling(true);
    backend.initialize().unwrap();
    let origin = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let other = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let origin_incarnation = backend.session_incarnation(origin);
    let token_template = [CkAttribute {
        attr_type: CkAttributeType::TOKEN,
        value: Some(CkAttributeValue::Bool(true)),
    }];
    let backend_ref = &backend;
    let token_template_ref = &token_template;
    for iteration in 0..200u32 {
        let minted = backend.create_object(origin, Some(&token_template)).unwrap();
        let id_a = backend.object_lifetime(origin, minted).expect("tracked mint");
        let destroys_before = backend.destroy_call_count();
        let barrier = std::sync::Barrier::new(3);
        let barrier_ref = &barrier;
        let (replacement, competitor_result, settle_result) = std::thread::scope(|scope| {
            let competitor = scope.spawn(move || {
                barrier_ref.wait();
                let result = backend_ref.destroy_object(other, minted);
                let repl = backend_ref
                    .create_object(other, Some(token_template_ref.as_slice()))
                    .expect("recreate succeeds");
                (repl, result)
            });
            let settle = scope.spawn(move || {
                barrier_ref.wait();
                backend_ref.destroy_object_if_bound(origin, minted, origin_incarnation, Some(id_a))
            });
            barrier_ref.wait();
            let (repl, comp) = competitor.join().expect("competitor joins");
            let settle_res = settle.join().expect("settle joins");
            (repl, comp, settle_res)
        });
        assert_eq!(
            replacement, minted,
            "iteration {iteration}: recycling mock must reuse the object handle"
        );
        assert!(
            !(competitor_result.is_ok() && settle_result.is_ok()),
            "iteration {iteration}: both destroys succeeded — settlement destroyed the replacement"
        );
        assert_eq!(
            backend.live_object_count(),
            1,
            "iteration {iteration}: replacement must survive the race"
        );
        backend.get_object_size(other, replacement).unwrap_or_else(|rv| {
            panic!("iteration {iteration}: replacement remains usable: {rv:?}")
        });
        // Only legitimate destroys count: the competitor's plain
        // destroy always counts one call; a bound destroy counts
        // only when it actually destroys (Ok), never on refusal.
        let expected_destroys = destroys_before + 1 + usize::from(settle_result.is_ok());
        assert_eq!(
            backend.destroy_call_count(),
            expected_destroys,
            "iteration {iteration}: destroy_call_count reflects only legitimate destroys"
        );
        // A second settle with the stale id must also refuse with
        // no counted destroy.
        let destroys_before_second = backend.destroy_call_count();
        assert_eq!(
            backend.destroy_object_if_bound(origin, replacement, origin_incarnation, Some(id_a)),
            Err(CkRv::OBJECT_HANDLE_INVALID),
            "iteration {iteration}: stale settle after race must refuse"
        );
        assert_eq!(
            backend.destroy_call_count(),
            destroys_before_second,
            "iteration {iteration}: stale refusal must issue no destroy"
        );
        assert_eq!(backend.live_object_count(), 1, "iteration {iteration}: replacement still live");
        backend.destroy_object(other, replacement).unwrap();
        assert_eq!(
            backend.live_object_count(),
            0,
            "iteration {iteration}: cleanup destroys replacement"
        );
    }
}

/// Found-object sharing control: an object minted in session A and
/// then found in session B must share one lifetime id, so settlement
/// from A with the captured id destroys exactly once with no false
/// refusal from B's found entry.
#[test]
fn found_object_shared_across_sessions_settles_from_origin() {
    let backend = MockBackend::default_test();
    backend.set_handle_recycling(true);
    backend.initialize().unwrap();
    let origin = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let other = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let origin_incarnation = backend.session_incarnation(origin);
    let token_template = [CkAttribute {
        attr_type: CkAttributeType::TOKEN,
        value: Some(CkAttributeValue::Bool(true)),
    }];

    let capture = crate::mint_capture::begin(origin);
    let minted = backend.create_object(origin, Some(&token_template)).unwrap();
    let captured = capture.captured();
    let captured_lifetime = capture_lifetime_for(&captured, minted);
    drop(capture);
    let id_a = backend.object_lifetime(origin, minted).expect("tracked mint");
    assert_eq!(captured_lifetime, Some(id_a));

    backend.set_find_objects_result(vec![minted]);
    backend.find_objects_init(other, Some(&[])).unwrap();
    assert_eq!(backend.find_objects(other, 10).unwrap(), vec![minted]);
    backend.find_objects_final(other).unwrap();
    assert_eq!(
        backend.object_lifetime(other, minted),
        Some(id_a),
        "found object must reuse the existing lifetime id across sessions"
    );

    let destroys_before = backend.destroy_call_count();
    backend.destroy_object_if_bound(origin, minted, origin_incarnation, Some(id_a)).unwrap();
    assert_eq!(backend.destroy_call_count(), destroys_before + 1);
    assert_eq!(backend.live_object_count(), 0);
    assert_eq!(backend.object_lifetime(origin, minted), None);
    assert_eq!(backend.object_lifetime(other, minted), None);
    assert_eq!(
        backend.destroy_object_if_bound(origin, minted, origin_incarnation, Some(id_a)),
        Err(CkRv::OBJECT_HANDLE_INVALID),
    );
    assert_eq!(backend.destroy_call_count(), destroys_before + 1);
}

/// Non-tracking test backend: wraps the mock for object storage but
/// exposes no lifetime tracking at the trait surface (default
/// `object_lifetime`/`tracks_object_lifetimes`/`destroy_object_if_bound`),
/// so settlement keeps the `(None, None)` legacy raw destroy.
struct UntrackedBackend {
    inner: MockBackend,
}

impl UntrackedBackend {
    fn new() -> Self {
        Self { inner: MockBackend::default_test() }
    }
}

impl Pkcs11Backend for UntrackedBackend {
    fn initialize(&self) -> CkResult<()> {
        self.inner.initialize()
    }
    fn finalize(&self) -> CkResult<()> {
        self.inner.finalize()
    }
    fn get_info(&self) -> CkResult<CkInfo> {
        self.inner.get_info()
    }
    fn get_slot_list(&self, token_present: bool) -> CkResult<Vec<CkSlotId>> {
        self.inner.get_slot_list(token_present)
    }
    fn get_slot_info(&self, slot_id: CkSlotId) -> CkResult<CkSlotInfo> {
        self.inner.get_slot_info(slot_id)
    }
    fn get_token_info(&self, slot_id: CkSlotId) -> CkResult<CkTokenInfo> {
        self.inner.get_token_info(slot_id)
    }
    fn get_mechanism_list(&self, slot_id: CkSlotId) -> CkResult<Vec<CkMechanismType>> {
        self.inner.get_mechanism_list(slot_id)
    }
    fn get_mechanism_info(
        &self,
        slot_id: CkSlotId,
        mech: CkMechanismType,
    ) -> CkResult<CkMechanismInfo> {
        self.inner.get_mechanism_info(slot_id, mech)
    }
    fn init_token(
        &self,
        slot_id: CkSlotId,
        so_pin: Option<&[u8]>,
        label: InitTokenLabel<'_>,
    ) -> CkResult<()> {
        self.inner.init_token(slot_id, so_pin, label)
    }
    fn init_pin(&self, session: CkSessionHandle, pin: Option<&[u8]>) -> CkResult<()> {
        self.inner.init_pin(session, pin)
    }
    fn set_pin(
        &self,
        session: CkSessionHandle,
        old_pin: Option<&[u8]>,
        new_pin: Option<&[u8]>,
    ) -> CkResult<()> {
        self.inner.set_pin(session, old_pin, new_pin)
    }
    fn open_session(&self, slot_id: CkSlotId, flags: CkSessionFlags) -> CkResult<CkSessionHandle> {
        self.inner.open_session(slot_id, flags)
    }
    fn close_session(&self, session: CkSessionHandle) -> CkResult<()> {
        self.inner.close_session(session)
    }
    fn close_all_sessions(&self, slot_id: CkSlotId) -> CkResult<()> {
        // W1-C5-04: entries are keyed by handle, and handles are never
        // reused, so a slot close-all leaves other slots' live entries
        // untouched; closed sessions' entries become unreachable but stay
        // bounded by the test's session count.
        self.inner.close_all_sessions(slot_id)
    }
    fn get_session_info(&self, session: CkSessionHandle) -> CkResult<CkSessionInfo> {
        self.inner.get_session_info(session)
    }
    fn login(
        &self,
        session: CkSessionHandle,
        user_type: CkUserType,
        pin: Option<&[u8]>,
    ) -> CkResult<()> {
        self.inner.login(session, user_type, pin)
    }
    fn logout(&self, session: CkSessionHandle) -> CkResult<()> {
        self.inner.logout(session)
    }
    fn find_objects_init(&self, s: CkSessionHandle, t: Option<&[CkAttribute]>) -> CkResult<()> {
        self.inner.find_objects_init(s, t)
    }
    fn find_objects(&self, s: CkSessionHandle, m: u32) -> CkResult<Vec<CkObjectHandle>> {
        self.inner.find_objects(s, m)
    }
    fn find_objects_final(&self, s: CkSessionHandle) -> CkResult<()> {
        self.inner.find_objects_final(s)
    }
    fn get_attribute_value(
        &self,
        s: CkSessionHandle,
        object: CkObjectHandle,
        template: &mut [CkAttribute],
    ) -> CkResult<()> {
        self.inner.get_attribute_value(s, object, template)
    }
    fn get_attribute_value_exact(
        &self,
        s: CkSessionHandle,
        object: CkObjectHandle,
        queries: Option<&[CkAttributeQuery]>,
    ) -> CkResult<(CkRv, Vec<CkAttributeQueryResult>)> {
        self.inner.get_attribute_value_exact(s, object, queries)
    }
    fn sign_init(
        &self,
        s: CkSessionHandle,
        m: &ValidatedMechanismParams,
        k: CkObjectHandle,
    ) -> CkResult<()> {
        self.inner.sign_init(s, m, k)
    }
    fn sign(&self, s: CkSessionHandle, d: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.inner.sign(s, d)
    }
    fn sign_update(&self, s: CkSessionHandle, p: CkInBuf<'_>) -> CkResult<()> {
        self.inner.sign_update(s, p)
    }
    fn sign_final(&self, s: CkSessionHandle) -> CkResult<SecretBytes> {
        self.inner.sign_final(s)
    }
    fn sign_recover_init(
        &self,
        s: CkSessionHandle,
        m: &ValidatedMechanismParams,
        k: CkObjectHandle,
    ) -> CkResult<()> {
        self.inner.sign_recover_init(s, m, k)
    }
    fn sign_recover(&self, s: CkSessionHandle, d: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.inner.sign_recover(s, d)
    }
    fn verify_recover_init(
        &self,
        s: CkSessionHandle,
        m: &ValidatedMechanismParams,
        k: CkObjectHandle,
    ) -> CkResult<()> {
        self.inner.verify_recover_init(s, m, k)
    }
    fn verify_recover(&self, s: CkSessionHandle, sig: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.inner.verify_recover(s, sig)
    }
    fn verify_init(
        &self,
        s: CkSessionHandle,
        m: &ValidatedMechanismParams,
        k: CkObjectHandle,
    ) -> CkResult<()> {
        self.inner.verify_init(s, m, k)
    }
    fn verify(&self, s: CkSessionHandle, d: CkInBuf<'_>, sig: CkInBuf<'_>) -> CkResult<()> {
        self.inner.verify(s, d, sig)
    }
    fn verify_update(&self, s: CkSessionHandle, p: CkInBuf<'_>) -> CkResult<()> {
        self.inner.verify_update(s, p)
    }
    fn verify_final(&self, s: CkSessionHandle, sig: CkInBuf<'_>) -> CkResult<()> {
        self.inner.verify_final(s, sig)
    }
    fn digest_init(&self, s: CkSessionHandle, m: &ValidatedMechanismParams) -> CkResult<()> {
        self.inner.digest_init(s, m)
    }
    fn digest(&self, s: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.inner.digest(s, data)
    }
    fn digest_update(&self, s: CkSessionHandle, p: CkInBuf<'_>) -> CkResult<()> {
        self.inner.digest_update(s, p)
    }
    fn digest_key(&self, s: CkSessionHandle, k: CkObjectHandle) -> CkResult<()> {
        self.inner.digest_key(s, k)
    }
    fn digest_final(&self, s: CkSessionHandle) -> CkResult<SecretBytes> {
        self.inner.digest_final(s)
    }
    fn encrypt_init(
        &self,
        s: CkSessionHandle,
        m: &ValidatedMechanismParams,
        k: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>> {
        self.inner.encrypt_init(s, m, k)
    }
    fn encrypt(&self, s: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.inner.encrypt(s, data)
    }
    fn encrypt_update(&self, s: CkSessionHandle, part: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.inner.encrypt_update(s, part)
    }
    fn encrypt_final(&self, s: CkSessionHandle) -> CkResult<SecretBytes> {
        self.inner.encrypt_final(s)
    }
    fn decrypt_init(
        &self,
        s: CkSessionHandle,
        m: &ValidatedMechanismParams,
        k: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>> {
        self.inner.decrypt_init(s, m, k)
    }
    fn decrypt(&self, s: CkSessionHandle, encrypted_data: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.inner.decrypt(s, encrypted_data)
    }
    fn decrypt_update(
        &self,
        s: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.inner.decrypt_update(s, encrypted_part)
    }
    fn decrypt_final(&self, s: CkSessionHandle) -> CkResult<SecretBytes> {
        self.inner.decrypt_final(s)
    }
    fn derive_key(
        &self,
        s: CkSessionHandle,
        m: &ValidatedMechanismParams,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.inner.derive_key(s, m, base_key, template)
    }
    fn wrap_key(
        &self,
        s: CkSessionHandle,
        m: &ValidatedMechanismParams,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
    ) -> CkResult<SecretBytes> {
        self.inner.wrap_key(s, m, wrapping_key, key)
    }
    fn unwrap_key(
        &self,
        s: CkSessionHandle,
        m: &ValidatedMechanismParams,
        unwrapping_key: CkObjectHandle,
        wrapped_key: CkInBuf<'_>,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.inner.unwrap_key(s, m, unwrapping_key, wrapped_key, template)
    }
    fn generate_key(
        &self,
        s: CkSessionHandle,
        m: &ValidatedMechanismParams,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.inner.generate_key(s, m, template)
    }
    fn create_object(
        &self,
        s: CkSessionHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.inner.create_object(s, template)
    }
    fn copy_object(
        &self,
        s: CkSessionHandle,
        object: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.inner.copy_object(s, object, template)
    }
    fn destroy_object(&self, s: CkSessionHandle, object: CkObjectHandle) -> CkResult<()> {
        self.inner.destroy_object(s, object)
    }
    fn session_incarnation(&self, s: CkSessionHandle) -> Option<u64> {
        self.inner.session_incarnation(s)
    }
    fn destroy_object_if_incarnation(
        &self,
        s: CkSessionHandle,
        object: CkObjectHandle,
        incarnation: Option<u64>,
    ) -> CkResult<()> {
        self.inner.destroy_object_if_incarnation(s, object, incarnation)
    }
    fn get_object_size(&self, s: CkSessionHandle, object: CkObjectHandle) -> CkResult<u64> {
        self.inner.get_object_size(s, object)
    }
    fn set_attribute_value(
        &self,
        s: CkSessionHandle,
        object: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<()> {
        self.inner.set_attribute_value(s, object, template)
    }
    fn generate_key_pair(
        &self,
        s: CkSessionHandle,
        m: &ValidatedMechanismParams,
        pub_t: Option<&[CkAttribute]>,
        priv_t: Option<&[CkAttribute]>,
    ) -> CkResult<(CkObjectHandle, CkObjectHandle)> {
        self.inner.generate_key_pair(s, m, pub_t, priv_t)
    }
    fn wait_for_slot_event(&self, flags: u64) -> CkResult<CkSlotId> {
        self.inner.wait_for_slot_event(flags)
    }
    fn admit_slot_wait(&self, flags: u64) -> CkResult<()> {
        self.inner.admit_slot_wait(flags)
    }
    fn get_operation_state(&self, s: CkSessionHandle) -> CkResult<SecretBytes> {
        self.inner.get_operation_state(s)
    }
    fn set_operation_state(
        &self,
        s: CkSessionHandle,
        state: CkInBuf<'_>,
        enc_key: CkObjectHandle,
        auth_key: CkObjectHandle,
    ) -> CkResult<()> {
        self.inner.set_operation_state(s, state, enc_key, auth_key)
    }
    fn seed_random(&self, s: CkSessionHandle, seed: CkInBuf<'_>) -> CkResult<()> {
        self.inner.seed_random(s, seed)
    }
    fn generate_random(&self, s: CkSessionHandle, len: u32) -> CkResult<SecretBytes> {
        self.inner.generate_random(s, len)
    }
    fn digest_encrypt_update(
        &self,
        s: CkSessionHandle,
        part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.inner.digest_encrypt_update(s, part)
    }
    fn decrypt_digest_update(
        &self,
        s: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.inner.decrypt_digest_update(s, encrypted_part)
    }
    fn sign_encrypt_update(&self, s: CkSessionHandle, part: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.inner.sign_encrypt_update(s, part)
    }
    fn decrypt_verify_update(
        &self,
        s: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.inner.decrypt_verify_update(s, encrypted_part)
    }
}

#[test]
fn untracked_backend_legacy_destroy_still_works() {
    let backend = UntrackedBackend::new();
    assert!(!backend.tracks_object_lifetimes(), "wrapper must not track");
    backend.inner.initialize().unwrap();
    let session = backend.inner.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let object = backend.create_object(session, Some(&[])).unwrap();
    assert_eq!(backend.object_lifetime(session, object), None);
    assert_eq!(backend.inner.live_object_count(), 1);
    backend.destroy_object_if_bound(session, object, None, None).unwrap();
    assert_eq!(
        backend.inner.live_object_count(),
        0,
        "legacy (None,None) destroy must still work for non-tracking backends"
    );
}
