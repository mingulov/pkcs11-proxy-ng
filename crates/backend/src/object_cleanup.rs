//! Ownership of newly created objects during fallible ancillary validation.
//! Quarantine is backend/service-lifetime state, never wire data or logging.
use crate::Pkcs11Backend;
use pkcs11_proxy_ng_types::{CkObjectHandle, CkResult, CkRv, CkSessionHandle};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

struct QuarantinedObject {
    session: CkSessionHandle,
    object: CkObjectHandle,
    cleanup_rv: AtomicU64,
}

/// Each instance belongs to exactly one backend/service. Failed destruction
/// retains the native identity and outcome here and stops further authenticated
/// creation. No automatic retry: session/object handles may subsequently become
/// stale. Provider/operator recovery is required; this is not a durable journal.
#[derive(Default)]
pub struct ObjectCleanupQuarantine {
    objects: Mutex<Vec<Arc<QuarantinedObject>>>,
}

impl ObjectCleanupQuarantine {
    pub fn ensure_clear(&self) -> CkResult<()> {
        if self.objects.lock().unwrap_or_else(|e| e.into_inner()).is_empty() {
            Ok(())
        } else {
            Err(CkRv::DEVICE_ERROR)
        }
    }
}

/// Construct immediately after successful native creation, before any output
/// validation/conversion. Drop attempts destruction exactly once unless the
/// validated success explicitly transfers ownership to the caller.
pub struct PendingNativeObject<'a> {
    backend: &'a dyn Pkcs11Backend,
    quarantine: &'a ObjectCleanupQuarantine,
    session: CkSessionHandle,
    object: Option<CkObjectHandle>,
}

impl<'a> PendingNativeObject<'a> {
    pub fn new(
        backend: &'a dyn Pkcs11Backend,
        quarantine: &'a ObjectCleanupQuarantine,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> Self {
        Self { backend, quarantine, session, object: Some(object) }
    }

    pub fn transfer(mut self) -> CkObjectHandle {
        self.object.take().expect("pending object transfers only once")
    }
}

impl Drop for PendingNativeObject<'_> {
    fn drop(&mut self) {
        let Some(object) = self.object.take() else {
            return;
        };
        let pending = Arc::new(QuarantinedObject {
            session: self.session,
            object,
            cleanup_rv: AtomicU64::new(CkRv::DEVICE_ERROR.0),
        });
        // Establish retained responsibility BEFORE calling a possibly failing
        // or panicking backend. Never hold the queue lock during provider work.
        self.quarantine
            .objects
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Arc::clone(&pending));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.backend.destroy_quarantined_object(pending.session, pending.object)
        }))
        .unwrap_or(Err(CkRv::DEVICE_ERROR));
        match outcome {
            Ok(()) => self
                .quarantine
                .objects
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|entry| !Arc::ptr_eq(entry, &pending)),
            Err(rv) => pending.cleanup_rv.store(rv.0, Ordering::Release),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockBackend;
    use pkcs11_proxy_ng_types::*;

    #[test]
    fn authenticated_cleanup_quarantine_retains_native_identity_and_failure_responsibility() {
        let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]);
        let quarantine = ObjectCleanupQuarantine::default();
        // This session deliberately does not exist, so destruction fails.
        drop(PendingNativeObject::new(
            &backend,
            &quarantine,
            CkSessionHandle(7),
            CkObjectHandle(9),
        ));
        assert_eq!(backend.destroy_call_count(), 1);
        assert_eq!(quarantine.ensure_clear(), Err(CkRv::DEVICE_ERROR));
        let records = quarantine.objects.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].session == CkSessionHandle(7) && records[0].object == CkObjectHandle(9));
        assert_eq!(records[0].cleanup_rv.load(Ordering::Acquire), CkRv::SESSION_HANDLE_INVALID.0);
    }
}
