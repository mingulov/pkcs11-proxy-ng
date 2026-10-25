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

/// Legacy fallbacks preserved: an uncaptured lifetime (directly
/// constructed payloads) and an uncaptured incarnation both destroy
/// exactly as the pre-binding path did.
#[test]
fn bound_destroy_legacy_fallbacks_still_destroy() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();

    let first = backend.create_object(session, Some(&[])).unwrap();
    backend.destroy_object_if_bound(session, first, None, None).unwrap();
    assert_eq!(backend.live_object_count(), 0);

    let second = backend.create_object(session, Some(&[])).unwrap();
    let lifetime = backend.object_lifetime(session, second);
    backend.destroy_object_if_bound(session, second, None, lifetime).unwrap();
    assert_eq!(backend.live_object_count(), 0);
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
