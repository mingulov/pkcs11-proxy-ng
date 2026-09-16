//! One-chain constructor domain (P0/I1, C3M.4).
//!
//! Every project-managed [`super::FfiBackend`] constructor shares one private
//! short-held process registry holding metadata only (never an owning `Arc`).
//! The reservation is taken after purely local platform/config validation and
//! before `dlopen`/discovery; the registry mutex is never held across loading,
//! native calls, waits, callbacks, retirement or unload. A second independent
//! load fails locally with zero loader or provider attempts, regardless of
//! path: separate processes are required for independent chains.
//!
//! Interim scope: [`ConstructionPermit`] release on backend `Drop` retires an
//! exact-epoch `Active`/`Retiring` reservation after normal unload so the slot
//! is reusable. Proof of session quiescence and successful native `Finalize`
//! before retirement lands with the lifecycle slice (`native_session`); until
//! then, post-`dlopen` load failures poison the slot instead of recycling it.

use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::Ordering::SeqCst;

/// Build-time native-FFI qualifier for v0.2: Linux GNU/musl on x86_64 with
/// 64-bit pointers or x86 with 32-bit pointers, or Windows MSVC on x86_64
/// with 64-bit pointers. x32, other architectures/environments and other
/// operating systems are excluded.
pub(in crate::ffi) const NATIVE_FFI_QUALIFIED: bool = (cfg!(target_os = "linux")
    && cfg!(any(target_env = "gnu", target_env = "musl"))
    && ((cfg!(target_arch = "x86_64") && cfg!(target_pointer_width = "64"))
        || (cfg!(target_arch = "x86") && cfg!(target_pointer_width = "32"))))
    || (cfg!(target_os = "windows")
        && cfg!(target_env = "msvc")
        && cfg!(target_arch = "x86_64")
        && cfg!(target_pointer_width = "64"));

/// Local constructor-domain failure. These are never fabricated provider
/// `CK_RV` values; [`super::FfiBackend::load`] surfaces them as `Err(String)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::ffi) enum DomainError {
    /// The host cannot run project-managed native FFI in v0.2.
    UnsupportedPlatform { detail: &'static str },
    /// Another chain holds the process reservation.
    AlreadyReserved { epoch: u64 },
    /// The registry is unusable until process restart.
    Poisoned,
    /// The registry mutex itself is poisoned; treated as [`DomainError::Poisoned`].
    MutexPoisoned,
    /// No fresh epoch remains; construction is rejected, never wrapped.
    EpochExhausted,
    /// No live reservation matches this epoch (stale or already settled).
    NotReserved { epoch: u64 },
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainError::UnsupportedPlatform { detail } => write!(
                f,
                "native FFI unavailable on this platform ({detail}); v0.2 requires \
                 Linux GNU/musl on x86_64 (64-bit) or x86 (32-bit), or \
                 Windows MSVC x86_64 (64-bit); refusing to load provider"
            ),
            DomainError::AlreadyReserved { epoch } => write!(
                f,
                "a project-managed provider chain is already reserved (epoch {epoch}) \
                 in this process; independent chains require separate processes"
            ),
            DomainError::Poisoned => {
                write!(f, "constructor registry poisoned; restart the process")
            }
            DomainError::MutexPoisoned => {
                write!(f, "constructor registry lock poisoned; restart the process")
            }
            DomainError::EpochExhausted => {
                write!(f, "constructor epoch exhausted; refusing to wrap identity")
            }
            DomainError::NotReserved { epoch } => {
                write!(f, "no live construction reservation matches epoch {epoch}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryState {
    Vacant { next_epoch: u64 },
    Reserved { epoch: u64, next_epoch: u64 },
    Active { epoch: u64, next_epoch: u64 },
    // Entered by the backend `Drop` body on the Release path (C3M step
    // 7): the slot stays occupied throughout dependent retirement and
    // library close, and only the last-field [`RetirementSentinel`]
    // publishes the next `Vacant` once every field has dropped.
    Retiring { epoch: u64, next_epoch: u64 },
    Poisoned { epoch: u64 },
}

impl RegistryState {
    fn epoch(&self) -> u64 {
        match *self {
            RegistryState::Vacant { next_epoch } => next_epoch,
            RegistryState::Reserved { epoch, .. }
            | RegistryState::Active { epoch, .. }
            | RegistryState::Retiring { epoch, .. }
            | RegistryState::Poisoned { epoch } => epoch,
        }
    }
}

pub(in crate::ffi) struct DomainRegistry {
    state: RegistryState,
}

impl DomainRegistry {
    /// Fresh vacant registry for deterministic unit tests. Production uses
    /// the process-global registry below, never this constructor.
    #[cfg(test)]
    pub(in crate::ffi) fn fresh_for_tests() -> Self {
        Self { state: RegistryState::Vacant { next_epoch: 0 } }
    }

    /// Vacant registry resuming at `next` for boundary tests. Production uses
    /// the process-global registry below, never this constructor.
    #[cfg(test)]
    pub(in crate::ffi) fn at_epoch_for_tests(next: u64) -> Self {
        Self { state: RegistryState::Vacant { next_epoch: next } }
    }

    pub(in crate::ffi) fn reserve(&mut self) -> Result<ConstructionPermit, DomainError> {
        match self.state {
            RegistryState::Vacant { next_epoch } => {
                if next_epoch == u64::MAX {
                    return Err(DomainError::EpochExhausted);
                }
                self.state =
                    RegistryState::Reserved { epoch: next_epoch, next_epoch: next_epoch + 1 };
                Ok(ConstructionPermit { epoch: next_epoch, managed: true })
            }
            RegistryState::Reserved { epoch, .. }
            | RegistryState::Active { epoch, .. }
            | RegistryState::Retiring { epoch, .. } => Err(DomainError::AlreadyReserved { epoch }),
            RegistryState::Poisoned { .. } => Err(DomainError::Poisoned),
        }
    }

    pub(in crate::ffi) fn activate(&mut self, epoch: u64) -> Result<(), DomainError> {
        match self.state {
            RegistryState::Reserved { epoch: live, next_epoch } if live == epoch => {
                self.state = RegistryState::Active { epoch, next_epoch };
                Ok(())
            }
            _ => Err(DomainError::NotReserved { epoch }),
        }
    }

    pub(in crate::ffi) fn rollback(&mut self, epoch: u64) {
        if let RegistryState::Reserved { epoch: live, next_epoch } = self.state
            && live == epoch
        {
            self.state = RegistryState::Vacant { next_epoch };
        }
    }

    pub(in crate::ffi) fn poison(&mut self, epoch: u64) {
        match self.state {
            RegistryState::Reserved { epoch: live, .. }
            | RegistryState::Active { epoch: live, .. }
            | RegistryState::Retiring { epoch: live, .. }
                if live == epoch =>
            {
                self.state = RegistryState::Poisoned { epoch };
            }
            _ => {}
        }
    }

    /// Enter `Retiring` for the exact epoch after a normal-unload
    /// decision (C3M step 7). Returns `true` only when this call published
    /// `Retiring`; anything but the live `Active` epoch is stale and
    /// changes nothing.
    pub(in crate::ffi) fn begin_retirement(&mut self, epoch: u64) -> bool {
        match self.state {
            RegistryState::Active { epoch: live, next_epoch } if live == epoch => {
                self.state = RegistryState::Retiring { epoch, next_epoch };
                true
            }
            _ => false,
        }
    }

    pub(in crate::ffi) fn release_if_owner(&mut self, epoch: u64) -> bool {
        match self.state {
            RegistryState::Active { next_epoch, .. }
            | RegistryState::Retiring { next_epoch, .. }
                if self.state.epoch() == epoch =>
            {
                self.state = RegistryState::Vacant { next_epoch };
                true
            }
            _ => false,
        }
    }
}

static CONSTRUCTOR_REGISTRY: Mutex<DomainRegistry> =
    Mutex::new(DomainRegistry { state: RegistryState::Vacant { next_epoch: 0 } });

/// Run `op` under the short-held registry lock. A poisoned mutex marks the
/// registry poisoned for every future caller and denies this one: no `unwrap`,
/// no treating it as vacant.
fn with_registry<R>(op: impl FnOnce(&mut DomainRegistry) -> R) -> Result<R, DomainError> {
    match CONSTRUCTOR_REGISTRY.lock() {
        Ok(mut guard) => Ok(op(&mut guard)),
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            let epoch = guard.state.epoch();
            guard.state = RegistryState::Poisoned { epoch };
            Err(DomainError::MutexPoisoned)
        }
    }
}

#[cfg(test)]
pub(in crate::ffi) fn serial_domain_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL_DOMAIN_TESTS: Mutex<()> = Mutex::new(());
    SERIAL_DOMAIN_TESTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Refuse native construction on hosts outside the v0.2 qualification
/// boundary before any reservation, loading or discovery attempt.
pub(in crate::ffi) fn check_native_platform() -> Result<(), DomainError> {
    if NATIVE_FFI_QUALIFIED {
        return Ok(());
    }
    let detail = if cfg!(target_os = "windows") {
        "non-MSVC/non-x86_64 Windows target"
    } else if !cfg!(target_os = "linux") {
        "non-Linux target_os"
    } else if !cfg!(any(target_env = "gnu", target_env = "musl")) {
        "non-GNU/musl target_env"
    } else {
        "unsupported architecture/pointer width"
    };
    Err(DomainError::UnsupportedPlatform { detail })
}

/// Reserve the process construction slot. The caller must either activate the
/// returned permit (successful construction), roll it back (pre-native
/// failure only) or poison it (any post-`dlopen` failure) — see
/// [`ConstructionPermit`]. Occupied or poisoned states fail with zero loader
/// or provider attempts.
pub(in crate::ffi) fn reserve_for_construction() -> Result<ConstructionPermit, DomainError> {
    with_registry(|registry| registry.reserve())?
}

/// Proof that this backend instance owns the process construction slot for
/// `epoch`. Created only by [`reserve_for_construction`] (or the test-only
/// unmanaged sentinel, which never matches a live registry epoch).
pub(in crate::ffi) struct ConstructionPermit {
    pub(in crate::ffi) epoch: u64,
    /// True when the permit came from the process registry (`reserve`);
    /// false only for the `cfg(test)` unmanaged sentinel. Structural flag —
    /// no lock, no registry read — so the final-owner guard can scope itself
    /// to managed permits on the lock-free stop path.
    //
    // The guard (cfg-gated to the qualified Linux and Windows arms) is
    // the only non-test reader.
    managed: bool,
}

impl ConstructionPermit {
    /// Publish a successfully constructed backend: `Reserved` becomes `Active`
    /// for the exact epoch. Any other state is a stale handle.
    pub(in crate::ffi) fn activate(&self) -> Result<(), DomainError> {
        with_registry(|registry| registry.activate(self.epoch))?
    }

    /// Give back a reservation before any native exposure (`dlopen`,
    /// discovery, callbacks, initialization). Must never be used once loading
    /// or discovery has started; that path requires [`ConstructionPermit::poison`].
    pub(in crate::ffi) fn rollback_before_native(self) {
        let _ = with_registry(|registry| registry.rollback(self.epoch));
    }

    /// Retire the slot after any post-`dlopen` failure or unprovable state:
    /// the exact epoch becomes `Poisoned` and no new chain loads until process
    /// restart. Stale permits change nothing. Takes `&self` so backend `Drop`
    /// can poison without moving the owned permit.
    pub(in crate::ffi) fn poison(&self) {
        let _ = with_registry(|registry| registry.poison(self.epoch));
    }

    /// Enter `Retiring` for the exact epoch after a normal-unload
    /// decision (C3M step 7): the slot remains occupied throughout
    /// dependent retirement and library close. Returns `true` only when
    /// this call published `Retiring`. Stale permits change nothing.
    /// Called by the backend `Drop` body; the [`RetirementSentinel`]
    /// publishes the next `Vacant` once every field has dropped.
    pub(in crate::ffi) fn begin_retirement(&self) -> bool {
        with_registry(|registry| registry.begin_retirement(self.epoch)).unwrap_or(false)
    }

    /// Retire an exact-epoch `Active`/`Retiring` reservation after normal
    /// unload so the slot is reusable. Returns `true` only when this call
    /// published the next `Vacant`. Stale releases, late workers and old
    /// destructors can never free another epoch's slot. Used by the
    /// [`RetirementSentinel`] and by tests probing stale handles.
    pub(in crate::ffi) fn release_if_owner(epoch: u64) -> bool {
        with_registry(|registry| registry.release_if_owner(epoch)).unwrap_or(false)
    }

    /// Whether this permit holds a process-registry slot. Plain-bool read:
    /// lock-free, so the final-owner guard may call it on the stop path.
    /// False only for the `cfg(test)` unmanaged sentinel.
    //
    // The guard (cfg-gated to the qualified Linux and Windows arms) is
    // the only non-test caller.
    pub(in crate::ffi) fn holds_registry_slot(&self) -> bool {
        self.managed
    }

    /// Test-only permit that matches no live registry epoch: in-crate test
    /// backends built from `Library::this()` bypass the process reservation
    /// without consuming or freeing it. Must never back production dispatch.
    #[cfg(test)]
    pub(in crate::ffi) fn unmanaged_test_only() -> Self {
        // `u64::MAX` is never issued (`Vacant { u64::MAX }` rejects with
        // `EpochExhausted`), so this sentinel matches no live epoch and every
        // registry transition ignores it.
        Self { epoch: u64::MAX, managed: false }
    }
}

/// Last-field retirement sentinel (C3M step 7): publishes the next `Vacant`
/// for the exact epoch once every other backend field — dependent graphs,
/// the `Library` (`dlclose`), the permit and the lifecycle — has dropped.
///
/// Must stay the LAST field of [`super::FfiBackend`]: field drops run in
/// declaration order, so this `Drop` runs after all of them, while the
/// backend `Drop` body (which runs before every field drop) publishes only
/// `Retiring` on the Release path. Stale epochs and poisoned slots are
/// untouched, so the Poison path and unmanaged test backends drop through
/// here with no effect.
pub(in crate::ffi) struct RetirementSentinel {
    epoch: u64,
}

impl RetirementSentinel {
    /// Sentinel retiring the same epoch the permit owns. Borrow the permit
    /// before moving it into the backend literal.
    pub(in crate::ffi) fn for_permit(permit: &ConstructionPermit) -> Self {
        Self { epoch: permit.epoch }
    }

    /// Test-only sentinel matching no live registry epoch, pairing with
    /// [`ConstructionPermit::unmanaged_test_only`].
    #[cfg(test)]
    pub(in crate::ffi) fn unmanaged_test_only() -> Self {
        Self { epoch: u64::MAX }
    }
}

impl Drop for RetirementSentinel {
    fn drop(&mut self) {
        ConstructionPermit::release_if_owner(self.epoch);
    }
}

/// Backend-instance lifecycle for an honest retirement decision (C3M.4).
///
/// Tracks only locally observed facts: successful native `C_Initialize`,
/// successful native `C_Finalize`, and native sessions opened/closed through
/// this instance. Counters move fail-closed: provider failures never reduce
/// the open-session count, so an uncertain state poisons the slot instead of
/// recycling it. Lock-free atomics; no mutex joins the native call path.
#[derive(Debug, Default)]
pub(in crate::ffi) struct LifecycleTracker {
    initialized: std::sync::atomic::AtomicBool,
    finalized_ok: std::sync::atomic::AtomicBool,
    open_sessions: std::sync::atomic::AtomicUsize,
    /// Initialization-cycle generation (C3M.4/row 10): advances once per
    /// successful initialization cycle inside this reservation, so session
    /// identities can be qualified against the incarnation that created
    /// them and stale work cannot publish into a reinitialized domain.
    generation: std::sync::atomic::AtomicU64,
    /// A `C_Finalize` failed since the current incarnation opened. The old
    /// incarnation is then uncertain (not cleanly closed): a later
    /// successful `C_Initialize` starts a new cycle rather than re-affirming
    /// the stale one. Used only for the new-cycle predicate, never to
    /// soften the retirement decision.
    finalize_failed: std::sync::atomic::AtomicBool,
}

/// Retirement outcome for backend `Drop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ffi) enum RetirementDecision {
    /// Proven quiescent (never initialized, or finalized with no open
    /// sessions): the exact epoch may publish the next `Vacant`.
    Release,
    /// Anything else: retain ownership and poison the slot until restart.
    Poison,
}

impl LifecycleTracker {
    /// Record a successful native `C_Initialize`. A new initialization cycle
    /// always clears a previously observed finalization.
    ///
    /// Only the first initialization of an incarnation advances the
    /// generation and resets the open-session count: re-affirming an
    /// already-open incarnation keeps its generation, bindings and count,
    /// while a cycle after `C_Finalize` starts clean so a reused numeric
    /// handle cannot alias the dead incarnation's owners.
    pub(in crate::ffi) fn note_initialized(&self) {
        let new_cycle = !self.initialized.load(SeqCst)
            || self.finalized_ok.load(SeqCst)
            || self.finalize_failed.load(SeqCst);
        self.initialized.store(true, SeqCst);
        self.finalized_ok.store(false, SeqCst);
        self.finalize_failed.store(false, SeqCst);
        if new_cycle {
            self.generation.fetch_add(1, SeqCst);
            self.open_sessions.store(0, SeqCst);
        }
    }

    /// Current initialization-cycle generation. Session identities created
    /// under an older generation are stale after re-initialization.
    pub(in crate::ffi) fn current_generation(&self) -> u64 {
        self.generation.load(SeqCst)
    }

    /// Test-only read of the provider-confirmed open-session count.
    #[cfg(test)]
    pub(in crate::ffi) fn open_session_count_for_tests(&self) -> usize {
        self.open_sessions.load(SeqCst)
    }

    /// Record a successful native `C_Finalize`. The provider has destroyed
    /// every session, matching `drop_all_mech_cache`, so the open count
    /// returns to zero together with the cleared session maps.
    pub(in crate::ffi) fn note_finalized(&self) {
        self.finalized_ok.store(true, SeqCst);
        self.finalize_failed.store(false, SeqCst);
        self.open_sessions.store(0, SeqCst);
    }

    /// Record a failed native `C_Finalize`. The incarnation is uncertain —
    /// not cleanly closed — so a later successful `C_Initialize` opens a new
    /// cycle instead of re-affirming the stale one. Session bindings and the
    /// open count are deliberately retained here (the failure proves
    /// nothing about provider state); they reset when the new cycle starts.
    pub(in crate::ffi) fn note_finalize_failed(&self) {
        self.finalize_failed.store(true, SeqCst);
    }

    /// Record one provider-confirmed session open.
    pub(in crate::ffi) fn note_session_opened(&self) {
        self.open_sessions.fetch_add(1, SeqCst);
    }

    /// Record provider-confirmed session closes. A single compare-exchange
    /// attempt applies the exact decrement; an underflow surprise or a lost
    /// race keeps the count high (fail-closed toward
    /// [`RetirementDecision::Poison`]) instead of hiding live sessions.
    pub(in crate::ffi) fn note_sessions_closed(&self, count: usize) {
        let open = self.open_sessions.load(SeqCst);
        if let Some(next) = open.checked_sub(count) {
            let _ = self.open_sessions.compare_exchange(open, next, SeqCst, SeqCst);
        }
    }

    /// Decide backend `Drop`: release only when quiescent with no open
    /// sessions; poison on every uncertain state.
    pub(in crate::ffi) fn retirement_decision(&self) -> RetirementDecision {
        use RetirementDecision::{Poison, Release};
        let quiescent = !self.initialized.load(SeqCst) || self.finalized_ok.load(SeqCst);
        if quiescent && self.open_sessions.load(SeqCst) == 0 { Release } else { Poison }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t3_qualified_host_platform_check_is_ok() {
        // This test runs on a qualified native-FFI host (Linux GNU/musl
        // x86_64/x86); the const itself is covered by
        // `native_domain_current_host_reports_qualified_or_refuses`.
        assert!(check_native_platform().is_ok());
    }

    #[test]
    fn t3_unsupported_platform_display_names_qualified_hosts() {
        let msg = DomainError::UnsupportedPlatform { detail: "test-detail" }.to_string();
        assert!(msg.contains("Linux GNU/musl"), "Display must name Linux hosts, got: {msg}");
        assert!(
            msg.contains("Windows MSVC x86_64"),
            "Display must name Windows MSVC x86_64 hosts, got: {msg}"
        );
    }
}
