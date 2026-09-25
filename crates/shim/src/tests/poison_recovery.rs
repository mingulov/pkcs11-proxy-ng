//! Local lock-poison fixtures (T07, C-B2).
//!
//! The shim's process-global locks are shared with every other unit test
//! in this binary, so these fixtures poison LOCAL locks and drive the
//! exact recovery helpers production uses (`lock_recovering`,
//! `read/write_registry_recovering`). The global accessors are thin
//! wrappers over those helpers; poisoning the real globals here would
//! leak the poison flag into unrelated parallel tests.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

/// Poison `m` the way production poisoning happens: a thread panics
/// while holding the guard. Returns after the panic is reaped.
fn poison_mutex<T: Send + 'static>(m: &Mutex<T>) {
    std::thread::scope(|s| {
        let handle = s.spawn(|| {
            let _guard = m.lock().unwrap();
            panic!("T07 fixture: poison the mutex");
        });
        assert!(handle.join().is_err(), "fixture thread must panic");
    });
    assert!(m.is_poisoned(), "fixture must leave the mutex poisoned");
}

fn poison_rwlock_write<T: Send + Sync + 'static>(m: &RwLock<T>) {
    std::thread::scope(|s| {
        let handle = s.spawn(|| {
            let _guard = m.write().unwrap();
            panic!("T07 fixture: poison the rwlock");
        });
        assert!(handle.join().is_err(), "fixture thread must panic");
    });
    assert!(m.is_poisoned(), "fixture must leave the rwlock poisoned");
}

/// Reads through `lock_recovering` see committed entries after poison.
#[test]
fn recovering_reads_see_committed_map_entries() {
    let map = Mutex::new(HashMap::from([(7u64, 70u64), (8u64, 80u64)]));
    poison_mutex(&map);
    let guard = crate::state::lock_recovering(&map);
    assert_eq!(guard.get(&7), Some(&70));
    assert_eq!(guard.get(&8), Some(&80));
    assert_eq!(guard.len(), 2);
}

/// Writes through `lock_recovering` take effect after poison.
#[test]
fn recovering_writes_land_on_poisoned_map() {
    let map = Mutex::new(HashMap::from([(7u64, 70u64)]));
    poison_mutex(&map);
    crate::state::lock_recovering(&map).insert(9u64, 90u64);
    let guard = crate::state::lock_recovering(&map);
    assert_eq!(guard.get(&9), Some(&90));
    assert_eq!(guard.len(), 2);
}

/// Eviction (`remove`/`retain`) and `clear` through the recovering
/// helper actually remove entries after poison: retaining orphans
/// behind a skipped op is a failure (T07).
#[test]
fn recovering_eviction_and_clear_leave_no_orphans() {
    let map = Mutex::new(HashMap::from([(1u64, 10u64), (2u64, 20u64), (3u64, 30u64)]));
    poison_mutex(&map);
    crate::state::lock_recovering(&map).remove(&2u64);
    crate::state::lock_recovering(&map).retain(|k, _| *k != 3u64);
    assert_eq!(*crate::state::lock_recovering(&map), HashMap::from([(1u64, 10u64)]));
    crate::state::lock_recovering(&map).clear();
    assert!(crate::state::lock_recovering(&map).is_empty(), "clear must not retain orphans");
}

/// Recovery is not a blind `clear_poison`: the flag stays set and every
/// later accessor re-recovers deliberately through the helper.
#[test]
fn recovery_keeps_poison_flag_set_for_later_accessors() {
    let map = Mutex::new(HashMap::from([(1u64, 1u64)]));
    poison_mutex(&map);
    drop(crate::state::lock_recovering(&map));
    assert!(map.is_poisoned(), "recovery must not clear the poison flag");
    // A later accessor still recovers (and still observes the flag).
    assert!(map.lock().is_err());
    assert_eq!(crate::state::lock_recovering(&map).get(&1), Some(&1));
}

/// A poisoned registry lock still yields a usable `Arc` snapshot: the
/// recovered clone is either the pre- or post-swap registry, whole.
#[test]
fn recovering_registry_read_yields_usable_snapshot() {
    let registry =
        pkcs11_proxy_ng_types::MechanismRegistry::load(None).expect("embedded default registry");
    let lock = RwLock::new(Arc::new(registry));
    poison_rwlock_write(&lock);
    let snapshot = crate::state::read_registry_recovering(&lock).clone();
    // 0x0001 is parameterless in the embedded default: the
    // snapshot answers registry queries instead of panicking.
    assert!(snapshot.is_parameterless(0x0001));
}

/// A poisoned registry write lock recovers and the replacement swap
/// overwrites whatever the panicked writer left behind.
#[test]
fn recovering_registry_write_replaces_snapshot() {
    let registry =
        pkcs11_proxy_ng_types::MechanismRegistry::load(None).expect("embedded default registry");
    let lock = RwLock::new(Arc::new(registry));
    poison_rwlock_write(&lock);
    let replacement =
        pkcs11_proxy_ng_types::MechanismRegistry::load(None).expect("embedded default registry");
    *crate::state::write_registry_recovering(&lock) = Arc::new(replacement);
    let snapshot = crate::state::read_registry_recovering(&lock).clone();
    assert!(snapshot.is_parameterless(0x0001));
    assert!(lock.is_poisoned(), "recovery must not clear the poison flag");
}
