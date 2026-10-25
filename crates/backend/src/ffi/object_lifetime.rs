//! Per-object lifetime ids for detached late-mint settlement.
//!
//! The session fence binds a late destroy to a session incarnation,
//! but within one live session a provider can recycle an object
//! handle: a cancelled mint's token object can be found and destroyed
//! by the client, and a later mint can reuse the numeric handle. This
//! table assigns every minted (or found) object a fresh monotonic
//! lifetime id, so a bound destroy can tell the originally minted
//! object apart from a later replacement carrying the same numeric
//! handle.
//!
//! Ownership is handle-global: a single entry per numeric handle
//! names the current lifetime id and the session that owns the
//! entry (the minting session, or the finding session when the find
//! first tracked the handle). Session close removes only entries
//! the closing session owns — a competitor's close therefore cannot
//! leave an origin session's stale entry as the sole record for a
//! still-live token replacement — and every successful destroy
//! removes the handle's entry outright.
//!
//! Lock order: the lifetime lock is a leaf below lifecycle-domain
//! admission and session-fence entry (both are taken before it on
//! every path, including the bound destroy, whose fence-checked
//! entry precedes this lock). While holding it, callers only run a
//! native call and thread-local mint-capture maintenance; they never
//! admit, enter a fence, or begin a lifecycle transition. Object-
//! creating calls, destroys, `FindObjects`, and session closes hold
//! it across the native call plus record maintenance, so an object
//! is never provider-visible while unrecorded. Finalize/re-Initialize
//! likewise hold it across the native call and the publish purge
//! (their lifecycle seals already drained ordinary work, so holding
//! the leaf there cannot cycle with admitted mints).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use pkcs11_proxy_ng_types::{CkObjectHandle, CkSessionHandle};

/// One handle-global lifetime record: the current lifetime id for a
/// numeric handle and the session that owns the entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ffi) struct ObjectLifetimeEntry {
    pub(in crate::ffi) lifetime: u64,
    pub(in crate::ffi) owner: u64,
}

pub(in crate::ffi) type ObjectLifetimeEntries = HashMap<u64, ObjectLifetimeEntry>;
pub(in crate::ffi) type ObjectLifetimeGuard<'a> = std::sync::MutexGuard<'a, ObjectLifetimeEntries>;

/// Object-lifetime table owned by [`super::FfiBackend`]. Starts ids
/// at 1 so `0` can never be a live lifetime.
#[derive(Debug)]
pub(in crate::ffi) struct ObjectLifetimeTable {
    entries: Mutex<ObjectLifetimeEntries>,
    next: AtomicU64,
}

impl Default for ObjectLifetimeTable {
    fn default() -> Self {
        Self { entries: Mutex::new(HashMap::new()), next: AtomicU64::new(1) }
    }
}

impl ObjectLifetimeTable {
    pub(in crate::ffi) fn lock_entries(&self) -> ObjectLifetimeGuard<'_> {
        self.entries.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    /// Record a FRESH lifetime in a locked table. Returns the new id
    /// and whether the record was *contended*: an existing entry for
    /// this numeric handle means the object is currently tracked as
    /// alive, so this fresh record is racing another object's record.
    /// The entry still updates to the newest id/owner, but the caller
    /// must poison its mint capture for the handle (report nothing).
    pub(in crate::ffi) fn record_fresh_in(
        &self,
        entries: &mut ObjectLifetimeEntries,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> (u64, bool) {
        // Fetch inside the caller's lock so concurrent fresh records
        // store ids in lock order: the last writer holds the newest
        // id (M-3).
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let contended = entries.contains_key(&object.0);
        entries.insert(object.0, ObjectLifetimeEntry { lifetime: id, owner: session.0 });
        (id, contended)
    }

    /// Record in a locked table only when the handle is untracked
    /// (handles surfaced by `C_FindObjects`). Found-object sharing:
    /// when the handle is already tracked, its existing id is reused
    /// and nothing updates (ownership stays with the minting
    /// session), so a legitimate bound destroy from the origin still
    /// matches after another session finds the same physical object.
    /// A fresh id is minted only when no entry for the handle exists.
    pub(in crate::ffi) fn record_if_absent_in(
        &self,
        entries: &mut ObjectLifetimeEntries,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> u64 {
        if let Some(entry) = entries.get(&object.0) {
            return entry.lifetime;
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        entries.insert(object.0, ObjectLifetimeEntry { lifetime: id, owner: session.0 });
        id
    }

    // Kept as the self-locking record site modelled directly by tests.
    #[allow(dead_code)]
    pub(in crate::ffi) fn record_if_absent(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> u64 {
        let mut entries = self.lock_entries();
        self.record_if_absent_in(&mut entries, session, object)
    }

    /// The current lifetime id for a numeric handle, regardless of
    /// which session asks: lifetime identity is handle-global (token
    /// objects are visible across sessions, and a finding session
    /// reuses the minting session's id without taking ownership).
    pub(in crate::ffi) fn lifetime(
        &self,
        _session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> Option<u64> {
        self.lock_entries().get(&object.0).map(|entry| entry.lifetime)
    }

    /// Drop only entries owned by `session` in a locked table
    /// (session close).
    pub(in crate::ffi) fn drop_session_in(
        entries: &mut ObjectLifetimeEntries,
        session: CkSessionHandle,
    ) {
        entries.retain(|_, entry| entry.owner != session.0);
    }

    // Kept as the self-locking record site modelled directly by tests.
    #[allow(dead_code)]
    pub(in crate::ffi) fn drop_session(&self, session: CkSessionHandle) {
        Self::drop_session_in(&mut self.lock_entries(), session);
    }

    /// Lock the entries for an atomic check + native destroy +
    /// removal sequence (bound destroy path). Holding this lock
    /// across the native destroy prevents a destroy/recreate pair
    /// from slipping a fresh lifetime in between the check and the
    /// native call; the plain destroy path takes the same lock across
    /// its native destroy + removal.
    pub(in crate::ffi) fn lock_for_destroy(&self) -> ObjectLifetimeGuard<'_> {
        self.lock_entries()
    }
}

impl super::FfiBackend {
    pub(in crate::ffi) fn record_object_lifetime_fresh_in(
        &self,
        entries: &mut ObjectLifetimeEntries,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) {
        if object.0 != 0 {
            let (id, contended) = self.object_lifetimes.record_fresh_in(entries, session, object);
            if contended {
                // Fail-safe contention poison: this mint's record
                // raced another object's live record for the same
                // numeric handle, so its capture must carry nothing
                // for the handle. Settlement then presents `None`
                // against a tracking backend and refuses instead of
                // destroying the valid replacement now tracked under
                // the newest id.
                crate::mint_capture::poison(session, object);
            } else {
                // Atomic mint capture: report the pair while the mint
                // call is still on this thread, so a caller's payload
                // binds exactly this mint's lifetime even if the handle
                // is destroyed and reused before the call returns.
                crate::mint_capture::report(session, object, id);
            }
        }
    }

    // Self-locking record site modelled directly by tests; mint paths
    // use the `_in` variant under a lock held across the native call.
    #[allow(dead_code)]
    pub(in crate::ffi) fn record_object_lifetime_fresh(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) {
        if object.0 != 0 {
            self.record_object_lifetime_fresh_in(
                &mut self.object_lifetimes.lock_entries(),
                session,
                object,
            );
        }
    }

    pub(in crate::ffi) fn record_object_lifetime_if_absent_in(
        &self,
        entries: &mut ObjectLifetimeEntries,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) {
        if object.0 != 0 {
            self.object_lifetimes.record_if_absent_in(entries, session, object);
        }
    }

    #[allow(dead_code)]
    pub(in crate::ffi) fn record_object_lifetime_if_absent(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) {
        if object.0 != 0 {
            self.object_lifetimes.record_if_absent(session, object);
        }
    }

    /// Record fresh lifetimes for object handles minted into a
    /// derive output mechanism (SP800-108 additional keys, SSL3/WTLS
    /// key-material OUT handles), mirroring the server's settlement
    /// extraction set.
    pub(in crate::ffi) fn record_mechanism_output_lifetimes_in(
        &self,
        entries: &mut ObjectLifetimeEntries,
        session: CkSessionHandle,
        params: &Option<pkcs11_proxy_ng_types::CkMechanismParams>,
    ) {
        use pkcs11_proxy_ng_types::CkMechanismParams;
        let Some(params) = params else { return };
        match params {
            CkMechanismParams::Sp800108Kdf(params) => {
                if let Some(keys) = params.additional_derived_keys_presence.as_present() {
                    for key in keys {
                        self.record_object_lifetime_fresh_in(entries, session, key.key_handle);
                    }
                }
            }
            CkMechanismParams::Sp800108FeedbackKdf(params) => {
                if let Some(keys) = params.additional_derived_keys_presence.as_present() {
                    for key in keys {
                        self.record_object_lifetime_fresh_in(entries, session, key.key_handle);
                    }
                }
            }
            CkMechanismParams::Ssl3KeyMat(params) => {
                for handle in [
                    params.client_mac_secret_handle,
                    params.server_mac_secret_handle,
                    params.client_key_handle,
                    params.server_key_handle,
                ] {
                    self.record_object_lifetime_fresh_in(entries, session, handle);
                }
            }
            CkMechanismParams::WtlsKeyMat(params) => {
                for handle in [params.mac_secret_handle, params.key_handle] {
                    self.record_object_lifetime_fresh_in(entries, session, handle);
                }
            }
            _ => {}
        }
    }
}
