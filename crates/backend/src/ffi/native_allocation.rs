//! Private persistent native allocation owner (C3M.2).
//!
//! Every outer `CK_MECHANISM`, scalar/native record and boxed nested pointee
//! handed to native code is owned by exactly one [`NativeAllocation`]. Raw
//! roots always derive from the persistent [`NonNull`] root established by a
//! single `Box::into_raw`, never from a reborrow (`&mut *boxed`) of a `Box`
//! that is subsequently moved: that reborrow pattern invalidates pointer
//! provenance under Miri's borrow models (defect I1) as soon as the box moves
//! into backing storage or the owner moves through session caches.
//!
//! Ownership discipline (see the C3M.2 unsafe invariants):
//!
//! * one allocation, one `into_raw`, one owner, one matching `from_raw`;
//! * no `Clone`/`Copy`/`Deref`/`DerefMut` on the owner, no `mem::forget`;
//! * raw access derives from the persistent root; no live `&T`/`&mut T` into
//!   retained storage crosses a provider call (snapshots return owned copies);
//! * retention ends before wiping or freeing; native-record `Drop` never
//!   follows native nested pointers.

use std::{cell::Cell, marker::PhantomData, ptr::NonNull};

pub(in crate::ffi) struct NativeAllocation<T> {
    root: NonNull<T>,
    owned_invariant: PhantomData<Cell<T>>,
}

impl<T> NativeAllocation<T> {
    /// Allocate and take unique ownership of `value`.
    ///
    /// This is an allocation primitive, not C9 admission: callers reserve the
    /// checked layout before calling it, and no allocation may occur inside a
    /// successful Init activation step. Production consumers land with the P2
    /// graph migration; unit tests exercise it now.
    #[allow(dead_code)]
    pub(in crate::ffi) fn new(value: T) -> Self {
        let root = NonNull::new(Box::into_raw(Box::new(value))).expect("Box root is nonnull");
        Self { root, owned_invariant: PhantomData }
    }

    /// Take unique ownership of an existing boxed native record without
    /// copying it. The raw root is the `into_raw` allocation itself, so no
    /// reborrow is created and later owner moves cannot invalidate it.
    pub(in crate::ffi) fn from_box(boxed: Box<T>) -> Self {
        let root = NonNull::new(Box::into_raw(boxed)).expect("Box root is nonnull");
        Self { root, owned_invariant: PhantomData }
    }

    /// Project the persistent raw root. Callers must hold the
    /// native-operation guard; no native writer or live reference may alias
    /// this storage during the use.
    pub(in crate::ffi) fn root(&self) -> *mut T {
        self.root.as_ptr()
    }

    // SAFETY: valid initialized T; caller holds the native-operation guard;
    // no native writer or live reference aliases this storage during the read.
    // Production readback lands with the P2 guard API; unit tests cover it now.
    #[allow(dead_code)]
    pub(in crate::ffi) unsafe fn snapshot(&self) -> T
    where
        T: Copy,
    {
        unsafe { self.root.as_ptr().read() }
    }
}

impl<T> Drop for NativeAllocation<T> {
    fn drop(&mut self) {
        // SAFETY: the containing lifecycle owner has proved native retention ended;
        // this is the unique reconstruction of the original allocation and layout.
        unsafe {
            drop(Box::from_raw(self.root.as_ptr()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Drop-counted sentinel. Each test owns its counter so parallel test
    /// threads cannot observe each other's destructions. The sentinel is
    /// never bitwise-copied: field reads use `addr_of!` projection, so no
    /// value is ever double-dropped by a test.
    struct Counted<'a> {
        value: u64,
        drops: &'a AtomicUsize,
    }

    impl Drop for Counted<'_> {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Fieldwise raw projection: read one `Copy` field of a Drop-guarded
    /// record without copying (and later double-dropping) the record itself.
    unsafe fn field_value(root: *mut Counted<'_>) -> u64 {
        // SAFETY: caller proves the owner is alive and unchanged; the
        // projection copies only the `u64` field, never the Drop guard.
        unsafe { std::ptr::addr_of!((*root).value).read_unaligned() }
    }

    #[test]
    fn native_allocation_drops_exactly_once() {
        let drops = AtomicUsize::new(0);
        {
            let _owner = NativeAllocation::new(Counted { value: 7, drops: &drops });
        }
        assert_eq!(drops.load(Ordering::SeqCst), 1, "exactly one destruction");
    }

    #[test]
    fn native_allocation_root_survives_owner_moves() {
        let owner = NativeAllocation::new(0x1234_5678u64);
        let root = owner.root();
        // SAFETY: owner is alive and no writer aliases the storage.
        let before = unsafe { owner.snapshot() };
        let boxed = Box::new(owner);
        let mut owners = Vec::with_capacity(1);
        owners.push(*boxed);
        owners.reserve(8);
        let moved_owner = owners.pop().expect("moved owner remains present");
        assert_eq!(moved_owner.root(), root, "move preserves the raw root address");
        // SAFETY: the moved owner is alive and unchanged.
        let after = unsafe { moved_owner.snapshot() };
        assert_eq!(before, after, "snapshot survives the owner move");
        assert_eq!(after, 0x1234_5678u64, "snapshot carries the stored value");
    }

    #[test]
    fn native_allocation_from_box_keeps_root_and_drops_once() {
        let drops = AtomicUsize::new(0);
        let boxed = Box::new(Counted { value: 11, drops: &drops });
        let owner = NativeAllocation::from_box(boxed);
        let root = owner.root();
        let mut owners = Vec::with_capacity(1);
        owners.push(owner);
        owners.reserve(8);
        let moved_owner = owners.pop().expect("moved owner remains present");
        assert_eq!(moved_owner.root(), root, "move preserves the boxed root address");
        // SAFETY: the moved owner is alive and unchanged.
        assert_eq!(unsafe { field_value(moved_owner.root()) }, 11, "value survives move");
        drop(moved_owner);
        assert_eq!(drops.load(Ordering::SeqCst), 1, "exactly one destruction");
    }

    #[test]
    fn native_allocation_zst_drops_once() {
        let drops = AtomicUsize::new(0);
        struct Zst<'a>(Counted<'a>);
        impl Drop for Zst<'_> {
            fn drop(&mut self) {
                self.drops_count();
            }
        }
        impl Zst<'_> {
            fn drops_count(&self) {
                self.0.drops.fetch_add(1, Ordering::SeqCst);
            }
        }
        {
            let _owner = NativeAllocation::new(Zst(Counted { value: 0, drops: &drops }));
            assert_eq!(drops.load(Ordering::SeqCst), 0, "no premature destruction");
        }
        // Owner Drop runs the ZST destructor (+1), which observes the drop,
        // then the inner counted value drops (+1).
        assert_eq!(drops.load(Ordering::SeqCst), 2, "owner and inner value drop once each");
    }
}
