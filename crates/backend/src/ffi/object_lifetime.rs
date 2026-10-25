//! Per-object lifetime ids for detached late-mint settlement.
//!
//! The session fence binds a late destroy to a session incarnation,
//! but within one live session a provider can recycle an object
//! handle: a cancelled mint's token object can be found and destroyed
//! by the client, and a later mint can reuse the numeric handle. This
//! table assigns every minted (or found) object a fresh monotonic
//! lifetime id keyed by `(session, object)`, so a bound destroy can
//! tell the originally minted object apart from a later replacement
//! carrying the same numeric handle.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use pkcs11_proxy_ng_types::{CkObjectHandle, CkSessionHandle};

/// Object-lifetime table owned by [`super::FfiBackend`]. Starts ids
/// at 1 so `0` can never be a live lifetime.
#[derive(Debug)]
pub(in crate::ffi) struct ObjectLifetimeTable {
    entries: Mutex<HashMap<(u64, u64), u64>>,
    next: AtomicU64,
}

impl Default for ObjectLifetimeTable {
    fn default() -> Self {
        Self { entries: Mutex::new(HashMap::new()), next: AtomicU64::new(1) }
    }
}

impl ObjectLifetimeTable {
    fn lock_entries(&self) -> std::sync::MutexGuard<'_, HashMap<(u64, u64), u64>> {
        self.entries.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    /// Record a FRESH lifetime for a newly minted object, replacing
    /// any stale entry for the recycled numeric handle.
    pub(in crate::ffi) fn record_fresh(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> u64 {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        self.lock_entries().insert((session.0, object.0), id);
        id
    }

    /// Record a lifetime only when the object is not yet tracked
    /// (handles surfaced by `C_FindObjects`).
    pub(in crate::ffi) fn record_if_absent(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> u64 {
        let mut entries = self.lock_entries();
        match entries.get(&(session.0, object.0)) {
            Some(&id) => id,
            None => {
                let id = self.next.fetch_add(1, Ordering::SeqCst);
                entries.insert((session.0, object.0), id);
                id
            }
        }
    }

    pub(in crate::ffi) fn lifetime(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> Option<u64> {
        self.lock_entries().get(&(session.0, object.0)).copied()
    }

    /// Drop every entry owned by `session` (session close).
    pub(in crate::ffi) fn drop_session(&self, session: CkSessionHandle) {
        self.lock_entries().retain(|&(owner, _), _| owner != session.0);
    }

    /// Drop every entry (Finalize / re-Initialize purge).
    pub(in crate::ffi) fn clear(&self) {
        self.lock_entries().clear();
    }

    /// Lock the entries for an atomic check + native destroy +
    /// removal sequence (bound destroy path). Holding this lock
    /// across the native destroy prevents a destroy/recreate pair
    /// from slipping a fresh lifetime in between the check and the
    /// native call; the plain destroy path takes the same lock across
    /// its native destroy + removal.
    pub(in crate::ffi) fn lock_for_destroy(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<(u64, u64), u64>> {
        self.lock_entries()
    }
}

impl super::FfiBackend {
    pub(in crate::ffi) fn record_object_lifetime_fresh(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) {
        if object.0 != 0 {
            self.object_lifetimes.record_fresh(session, object);
        }
    }

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
    pub(in crate::ffi) fn record_mechanism_output_lifetimes(
        &self,
        session: CkSessionHandle,
        params: &Option<pkcs11_proxy_ng_types::CkMechanismParams>,
    ) {
        use pkcs11_proxy_ng_types::CkMechanismParams;
        let Some(params) = params else { return };
        match params {
            CkMechanismParams::Sp800108Kdf(params) => {
                if let Some(keys) = params.additional_derived_keys_presence.as_present() {
                    for key in keys {
                        self.record_object_lifetime_fresh(session, key.key_handle);
                    }
                }
            }
            CkMechanismParams::Sp800108FeedbackKdf(params) => {
                if let Some(keys) = params.additional_derived_keys_presence.as_present() {
                    for key in keys {
                        self.record_object_lifetime_fresh(session, key.key_handle);
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
                    self.record_object_lifetime_fresh(session, handle);
                }
            }
            CkMechanismParams::WtlsKeyMat(params) => {
                for handle in [params.mac_secret_handle, params.key_handle] {
                    self.record_object_lifetime_fresh(session, handle);
                }
            }
            _ => {}
        }
    }
}
