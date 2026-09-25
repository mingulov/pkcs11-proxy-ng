use super::*;

#[test]
fn find_objects_swap_mid_search_restarts_from_new_list() {
    // W1-C5-03: swapping the override list mid-search resets the cursor,
    // so the next batch starts from the beginning of the new list instead
    // of slicing at a stale offset (or panicking past the new end).
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let old: Vec<CkObjectHandle> = (1..=5u64).map(CkObjectHandle).collect();
    backend.set_find_objects_result(old);
    backend.find_objects_init(session, Some(&[])).unwrap();
    let first = backend.find_objects(session, 2).unwrap();
    assert_eq!(first, vec![CkObjectHandle(1), CkObjectHandle(2)]);
    let new: Vec<CkObjectHandle> = vec![CkObjectHandle(11), CkObjectHandle(12)];
    backend.set_find_objects_result(new.clone());
    let batch = backend.find_objects(session, 10).unwrap();
    assert_eq!(batch, new, "swapped list must serve from its start");
    assert!(backend.find_objects(session, 10).unwrap().is_empty());
    backend.find_objects_final(session).unwrap();
}

#[test]
fn find_objects_cursor_past_end_yields_empty_not_panic() {
    // W1-C5-03: the slice start is clamped to the override-list length,
    // so even a cursor racing ahead of a concurrent swap yields an
    // empty batch instead of panicking on an out-of-bounds slice.
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    backend.set_find_objects_result(vec![CkObjectHandle(1)]);
    backend.find_objects_init(session, Some(&[])).unwrap();
    *backend.find_objects_cursor.lock().unwrap() = 99;
    let batch = backend.find_objects(session, 10).unwrap();
    assert!(batch.is_empty());
    backend.find_objects_final(session).unwrap();
}
