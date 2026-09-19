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
//!
//! TF01a slice note (partial enforcement — the F-01 clause is NOT satisfied):
//! `LifecycleDomain` admission is compile-time-enforced (B2) on exactly two
//! choke families — `call_bytes` (read path: 17 dependent-op entries) and
//! `call_unit` (32 ordinary entries) plus the `call_control_unit` split for
//! `Initialize`/`Finalize` and the stateless probe info queries (forwarded
//! regardless of domain state; providers may still return
//! `CKR_CRYPTOKI_NOT_INITIALIZED`). Every
//! other native entry (`call_bytes_exact*`, `call_*_with_mechanism*`,
//! `call_raw`, `call_array`, `call_*_output`, `fill_bytes`, 3.x paths) is
//! NOT yet admission-gated, `Finalize` performs no seal/drain (the domain
//! stays `Open` across it, exactly as before this slice), and there are no
//! session fences or `Drop` integration yet — all TF01b. The ownership-doc
//! clause stays as-is and the CHANGELOG F-01 entry stays open until TF01b.

use std::cell::Cell;
use std::fmt;
use std::marker::PhantomData;
use std::sync::TryLockError;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Instant;

use pkcs11_proxy_ng_types::{CkResult, CkRv};

use super::native_stop::{StopReason, abnormal_stop_native_lifetime, shutdown_grace};

/// Build-time native-FFI qualifier for v0.2: Linux GNU/musl on x86_64 with
/// 64-bit pointers or x86 with 32-bit pointers, macOS on aarch64 or x86_64
/// with 64-bit pointers (LP64; libloading loads .dylib), or Windows MSVC on
/// x86_64 with 64-bit pointers or x86 with 32-bit pointers (PE32 LLP32:
/// 32-bit `CK_ULONG`, 32-bit pointers, `#pragma pack(1)` structs). x32,
/// other architectures/environments and other operating systems are excluded.
pub(in crate::ffi) const NATIVE_FFI_QUALIFIED: bool = (cfg!(target_os = "linux")
    && cfg!(any(target_env = "gnu", target_env = "musl"))
    && ((cfg!(target_arch = "x86_64") && cfg!(target_pointer_width = "64"))
        || (cfg!(target_arch = "x86") && cfg!(target_pointer_width = "32"))))
    || (cfg!(target_os = "macos")
        && cfg!(any(target_arch = "aarch64", target_arch = "x86_64"))
        && cfg!(target_pointer_width = "64"))
    || (cfg!(target_os = "windows")
        && cfg!(target_env = "msvc")
        && ((cfg!(target_arch = "x86_64") && cfg!(target_pointer_width = "64"))
            || (cfg!(target_arch = "x86") && cfg!(target_pointer_width = "32"))));

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
                 Linux GNU/musl on x86_64 (64-bit) or x86 (32-bit), \
                 macOS on aarch64 or x86_64 (64-bit), or \
                 Windows MSVC on x86_64 (64-bit) or x86 (32-bit); refusing to load provider"
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
        "non-MSVC or non-x86-family Windows target"
    } else if cfg!(target_os = "macos") {
        "non-aarch64/x86_64 macOS target"
    } else if !cfg!(target_os = "linux") {
        "non-Linux/macOS target_os"
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
    // The guard (cfg-gated to the stop arms) is the only non-test
    // reader.
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
    // The guard (cfg-gated to the stop arms) is the only non-test
    // caller.
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
    /// A `C_Initialize` attempt reached native entry (set BEFORE the call,
    /// fail-closed). Once native code may have run, only a later successful
    /// `C_Finalize` re-earns release; a failed attempt without success
    /// poisons instead of recycling (C3M steps 4-5). Monotonic: never
    /// cleared, so failed/unknown initialization retains ownership.
    init_attempted: std::sync::atomic::AtomicBool,
    initialized: std::sync::atomic::AtomicBool,
    finalized_ok: std::sync::atomic::AtomicBool,
    open_sessions: std::sync::atomic::AtomicUsize,
    /// Initialization-cycle generation (C3M.4/row 10): advances once per
    /// successful initialization cycle inside this reservation, so session
    /// identities can be qualified against the incarnation that created
    /// them and stale work cannot publish into a reinitialized domain.
    generation: std::sync::atomic::AtomicU64,
    /// A `C_Finalize` failed since the current incarnation opened. The old
    /// incarnation is then uncertain (not cleanly closed): re-initialization
    /// is refused until a later successful `C_Finalize` (F-08). Used only to
    /// refuse new cycles, never to soften the retirement decision; cleared
    /// only by [`LifecycleTracker::note_finalized`].
    finalize_failed: std::sync::atomic::AtomicBool,
}

/// Retirement outcome for backend `Drop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ffi) enum RetirementDecision {
    /// Proven quiescent (no Initialize attempt and never initialized,
    /// or finalized with no open sessions): the exact epoch may publish
    /// the next `Vacant` after completed normal unload.
    Release,
    /// Anything else: retain ownership and poison the slot until restart.
    Poison,
}

/// Why a (re-)initialization was refused without opening a cycle (F-08).
///
/// Denial idiom follows [`DomainError`]: explicit refusal variants, never a
/// wrapped or reused identity. The dispatch boundary
/// (`super::FfiBackend::initialize`) maps these to caller-visible `CK_RV`s;
/// this module fabricates no provider return values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ffi) enum LifecycleRefusal {
    /// A `C_Finalize` failed since the current incarnation opened, so the
    /// provider state is unknown: the old incarnation may still be live, and
    /// only a later successful `C_Finalize` can satisfy a new cycle.
    FailedFinalizeUnresolved,
    /// No fresh lifecycle generation remains: the counter stands at
    /// `u64::MAX`, so the cycle is rejected rather than wrapping back to the
    /// pre-initial identity. Precedent: [`DomainError::EpochExhausted`].
    GenerationExhausted,
}

impl LifecycleTracker {
    /// Record a `C_Initialize` attempt BEFORE native entry. Callers must
    /// set this before invoking the provider so a failed attempt (native
    /// code ran, error RV) poisons instead of recycling the reservation.
    pub(in crate::ffi) fn note_init_attempted(&self) {
        self.init_attempted.store(true, SeqCst);
    }

    /// Pre-native gate for (re-)initialization: refuse cycles the contract
    /// forbids BEFORE any provider contact, with zero lifecycle side effects
    /// — not even the init-attempt marker — so a refused cycle keeps the
    /// retained-session evidence intact (F-08).
    pub(in crate::ffi) fn check_reinitialize(&self) -> Result<(), LifecycleRefusal> {
        if self.finalize_failed.load(SeqCst) {
            return Err(LifecycleRefusal::FailedFinalizeUnresolved);
        }
        let new_cycle = !self.initialized.load(SeqCst) || self.finalized_ok.load(SeqCst);
        if new_cycle && self.generation.load(SeqCst) == u64::MAX {
            return Err(LifecycleRefusal::GenerationExhausted);
        }
        Ok(())
    }

    /// Record a successful native `C_Initialize`. A new initialization cycle
    /// always clears a previously observed finalization.
    ///
    /// Only the first initialization of an incarnation advances the
    /// generation and resets the open-session count: re-affirming an
    /// already-open incarnation keeps its generation, bindings and count,
    /// while a cycle after `C_Finalize` starts clean so a reused numeric
    /// handle cannot alias the dead incarnation's owners.
    ///
    /// Fails closed (F-08): a set `finalize_failed` flag refuses the cycle
    /// instead of opening a new one, and the generation bump is checked — at
    /// `u64::MAX` there is no next identity, so the cycle is refused WITHOUT
    /// consuming the finalized evidence, purging bindings or resetting the
    /// count. The flag itself is never cleared here — only
    /// [`LifecycleTracker::note_finalized`] clears it — so a Finalize that
    /// fails concurrently with this call still denies every later cycle.
    pub(in crate::ffi) fn note_initialized(&self) -> Result<(), LifecycleRefusal> {
        if self.finalize_failed.load(SeqCst) {
            return Err(LifecycleRefusal::FailedFinalizeUnresolved);
        }
        let new_cycle = !self.initialized.load(SeqCst) || self.finalized_ok.load(SeqCst);
        if new_cycle {
            // Checked claim: `fetch_update` keeps the bump atomic under
            // concurrent initializers, and `checked_add` refuses at
            // `u64::MAX` rather than wrapping to the pre-initial identity.
            if self
                .generation
                .fetch_update(SeqCst, SeqCst, |generation| generation.checked_add(1))
                .is_err()
            {
                return Err(LifecycleRefusal::GenerationExhausted);
            }
            self.initialized.store(true, SeqCst);
            self.finalized_ok.store(false, SeqCst);
            self.open_sessions.store(0, SeqCst);
        }
        Ok(())
    }

    /// Current initialization-cycle generation. Session identities created
    /// under an older generation are stale after re-initialization.
    pub(in crate::ffi) fn current_generation(&self) -> u64 {
        self.generation.load(SeqCst)
    }

    /// Seed the lifecycle generation for boundary tests. Production cycles
    /// advance only through [`LifecycleTracker::note_initialized`].
    #[cfg(test)]
    pub(in crate::ffi) fn set_generation_for_tests(&self, generation: u64) {
        self.generation.store(generation, SeqCst);
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
    /// not cleanly closed — so re-initialization is refused until a later
    /// successful `C_Finalize` (F-08). Session bindings and the open count
    /// are deliberately retained here (the failure proves nothing about
    /// provider state); they reset only when a legitimate new cycle starts.
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
    /// sessions; poison on every uncertain state. A recorded Initialize
    /// attempt without a later successful Finalize is uncertain (native
    /// code may have run), even when initialization never succeeded.
    pub(in crate::ffi) fn retirement_decision(&self) -> RetirementDecision {
        use RetirementDecision::{Poison, Release};
        let never_exposed = !self.init_attempted.load(SeqCst) && !self.initialized.load(SeqCst);
        let quiescent = never_exposed || self.finalized_ok.load(SeqCst);
        if quiescent && self.open_sessions.load(SeqCst) == 0 { Release } else { Poison }
    }
}

// ---------------------------------------------------------------------------
// LifecycleDomain: F-01 lifecycle read exclusion (TF01a core).
//
// Every admitted ordinary invocation holds lifecycle read exclusion through
// actual native return, validation and settlement. Admission is checked
// under the read acquisition that seals it, and the proof is threaded
// through the `Self::call_*` choke family as `&OrdinaryGuard` (B2 shape),
// so every threaded native entry proves admission at COMPILE TIME — never
// advisory (TF01a: two families; see partial scope below).
//
// Whole-subsystem lock order (TF01a + TF01b; reviewed design TF01b follows):
//   lifecycle-domain RwLock (outer) -> session fence(s) (TF01b, middle)
//   -> DashMap shard locks (inner, leaf).
// Ordinary guards are held across unbounded provider calls — the first
// lock ever held there — so everything taken under a guard must be a
// short leaf or a TF01b session fence held under the order below: DashMap
// shard ops qualify (per-op, never held across native calls themselves).
// The order is never inverted: eviction helpers take no lifecycle lock in
// TF01a, and the constructor-registry mutex is never acquired under
// lifecycle.
//
// I1 contention decision (blocking is INTENDED — decided, not assumed):
// the detached ticket only avoids HOLDING write across the native call;
// ACQUIRING write in begin/publish/abandon blocks until in-flight readers
// drain, and `std::sync::RwLock` is writer-preferring, so a queued control
// op additionally stalls NEW ordinary admissions until the drain completes
// (pinned by `queued_writer_stalls_new_admissions`). Blocking is chosen
// over try_write-plus-fail-fast because (a) the daemon calls `initialize()`
// once at startup before serving (`crates/server/src/main.rs:88`) and
// per-client Initialize never touches the backend
// (`grpc_service/general/lifecycle.rs`), so no production traffic can wedge
// it — this mitigation is LOAD-BEARING; (b) blocking preserves
// initialize-eventually-succeeds for direct embedders, while fail-fast
// would invent spurious `GENERAL_ERROR` under load; (c) a truly stuck
// provider wedges every design equally (the in-flight call never returns),
// so fail-fast buys nothing there. Pinned by
// `initialize_blocks_on_parked_ordinary_then_proceeds_after_release`
// (Initialize waits behind parked ordinary work, then proceeds promptly
// after release — it never fails fast under contention).
//
// TF01b Finalize seal (I3 — mechanism specified exactly, because a literal
// "hold write across a bounded drain" is unimplementable with
// `std::sync::RwLock`): acquisition IS the drain, and seal-before-drain is
// impossible — the `Draining` flip needs write, which needs the drain
// first (actual order is drain-then-seal). TF01b MUST therefore seal in two
// arms: (1) a `try_write` loop against the shutdown deadline for the fast
// path — each miss re-checks the deadline instead of blocking unboundedly,
// and on expiry the sealer itself calls `abnormal_stop_native_lifetime`
// (suicide — it never returns failure, never proceeds unsealed); (2) past
// N misses, ONE blocking write acquisition under the already-armed
// shutdown deadline — the queued writer stalls new admissions
// (writer-preferring: probed and pinned, so the drain terminates modulo a
// truly stuck provider), and the external deadline arm owns the bound.
// Overrun on either arm is `abnormal_stop_native_lifetime` — PROCESS DEATH
// (`exit_group(70)`; `native_stop.rs`) — acceptable ONLY because
// `backend.finalize()` runs at post-traffic shutdown
// (`crates/server/src/main.rs:658`), after the last ordinary call has
// drained. TF01b test (for the TF01b brief): Finalize under continuous
// ordinary load completes without hitting the death deadline (pins
// writer-preferring drain termination).
//
// TF01b session fences (I4 — normative; TF01b builds from this text). For
// close(S) to exclude in-flight ordinary ops on S, ORDINARY PATHS MUST
// acquire S's fence — a second lock held across unbounded native calls.
// Order: lifecycle-domain (outer) -> session fence (middle) -> DashMap
// shard (inner, leaf); fences are per-session siblings, never nested
// except by close-all, which acquires the affected fences in ascending
// numeric session-handle order (a total order — no close-all-vs-close-all
// deadlock). A fence is acquired ONLY under a live `OrdinaryGuard`
// (admission is the gate: no guard ⇒ no fence), so the Finalize seal needs
// no fence of its own — draining lifecycle readers drains fence holders
// with them. Drop-may-never-admit: destructors MUST NOT call
// `admit_ordinary` or any domain method that acquires the lock — a Drop
// firing under a live guard would nest read behind a waiting writer and
// deadlock (today's `PendingNativeObject::drop` → `destroy_object` edge is
// safe only because no admitted path reaches it yet). Destroy-via-Drop MUST
// therefore ride a control path that takes no lifecycle lock, or carry a
// pre-admitted token threaded from the admitting scope; auditing every
// `Drop` that can reach a native call is a TF01b exit gate.
//
// TF01b `Drop` integration: the backend `Drop` quiescence check over the
// lifecycle domain MUST use non-blocking `try_write` (never block in
// `Drop`). At backend `Drop` no guard can be alive anywhere — the backend
// is `Arc`-owned with `&self` methods, so a live guard would keep its
// owner alive — hence only poison is observable: any `try_write` failure
// is fail-closed (poison ⇒ stop-fire via `abnormal_stop_native_lifetime`).
//
// Re-entrancy (load-bearing with `std` locks): a thread holding read that
// takes write deadlocks, as does nested read behind a waiting writer. So:
// ordinary paths admit EXACTLY ONCE at the `ffi_*` boundary and thread
// `&OrdinaryGuard` down — helpers take the guard as a parameter and never
// re-admit; control paths (Initialize/Finalize) NEVER admit (audited — the
// `call_control_*` chokes take no guard, and no control path calls
// `admit_ordinary`). While an `OrdinaryGuard` is alive on a thread, that
// thread must not call any domain method that acquires the lock.
// Destructors are in scope for this rule (see Drop-may-never-admit above):
// no `Drop` may admit or acquire.
//
// conc-M2 nesting tripwire (debug only): a thread-local "admitted" flag,
// set on admission and cleared by `OrdinaryGuard::drop`. `admit_ordinary`
// `debug_assert`s the flag is clear FIRST (before the read acquisition,
// so a violation panics instead of deadlocking behind a queued writer),
// and the self-test pins it — any nesting a future edit introduces fails
// the suite loudly instead of wedging under load.
//
// Poison policy: `std::sync::RwLock` poison is sticky and maps to
// fail-closed denial everywhere (precedent: `DomainError::MutexPoisoned`
// denies new loads until restart). Only a WRITER panic poisons (`std`
// semantics: panicking readers never poison — a settlement bug unwinds
// through the guard and releases read WITHOUT wedging the domain).
// Short control sections contain no user code, so write-side poison
// needs a panic inside the section itself (practically unreachable);
// the mapping is defense-in-depth. `Drop` paths ignore poison instead
// of panicking.
//
// Epoch: monotonic under the write lock, stamped into every guard and
// control ticket at the acquisition that seals it. `abandon_initialize`
// verifies the ticket epoch: a mismatch means a later control op already
// moved the domain, so the stale ticket is a no-op (the later op owns the
// outcome). TF01b session fences correlate on guard epochs.
//
// TF01a partial scope (clause NOT satisfied): the domain, admission and
// the Initialize-side control transitions are live; B2 threading covers
// `call_bytes` (read path) and `call_unit` + `call_control_unit` (control
// split) only. TF01b remainder: remaining choke families, Finalize
// seal/drain (`Draining`/`Finalizing`/`Finalized` production transitions),
// session fences, `Drop` integration, ownership-doc flip, CHANGELOG.
// ---------------------------------------------------------------------------

/// Private module states (§"Module lifecycle and native storage").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(in crate::ffi) enum ModuleState {
    /// Freshly loaded, no `C_Initialize` cycle published yet.
    #[default]
    LoadedUninitialized,
    /// A control thread is inside the Initialize transition; ordinary
    /// admission is denied until it publishes or abandons.
    Initializing,
    /// The only state that admits ordinary work.
    Open,
    /// TF01b: Finalize sealed admission and is draining in-flight guards.
    Draining,
    /// TF01b: drained; the exclusive Finalize native call is in flight.
    Finalizing,
    /// TF01b: cleanly finalized; ordinary work denied until re-Initialize.
    Finalized,
    /// Provider state unknown (concurrent-control collision at abandon, or
    /// epoch exhaustion); fail-closed until a later control cycle heals it.
    Uncertain,
}

#[derive(Debug, Default)]
struct LifecycleInner {
    state: ModuleState,
    epoch: u64,
}

/// F-01 lifecycle domain: module state machine + admission control.
#[derive(Debug, Default)]
pub(in crate::ffi) struct LifecycleDomain {
    inner: RwLock<LifecycleInner>,
}

/// Proof of ordinary admission: holds lifecycle read exclusion. Dropping
/// the guard ends settlement. `!Send + !Sync` via the raw-pointer marker:
/// the guarded native call, validation and settlement all stay on the
/// admitting thread (FIX-D §5 item 1: explicitly mapped confinement).
#[derive(Debug)]
pub(in crate::ffi) struct OrdinaryGuard<'a> {
    _read: RwLockReadGuard<'a, LifecycleInner>,
    // Read by the session-fence correlation (TF01b): closes record the
    // closing epoch as the fence's terminal state.
    epoch: u64,
    _confine: PhantomData<*const ()>,
}

/// Outstanding Initialize control attempt: detached ticket (no lock held)
/// stamped with the prior state and the epoch observed under the write
/// acquisition that sealed `begin_initialize`. Exactly one of
/// `publish_open` / `abandon_initialize` settles it; `Drop` abandons an
/// unsettled ticket, so early returns and panics restore instead of
/// wedging the domain in `Initializing`.
#[derive(Debug)]
pub(in crate::ffi) struct InitTicket<'a> {
    domain: &'a LifecycleDomain,
    prior: ModuleState,
    epoch: u64,
    settled: bool,
}

/// Detached seal for the Finalize control transition (I3 mirror of
/// [`InitTicket`]): stamped with the prior state and the epoch observed
/// under the sealing write acquisition. `enter_finalizing` marks the
/// exclusive native call in flight; exactly one of
/// `publish_finalized_with_purge` / `abandon_finalize` settles it; `Drop`
/// abandons an unsettled ticket, so early returns and panics restore
/// instead of wedging the domain in a sealed state.
#[derive(Debug)]
pub(in crate::ffi) struct FinalizeTicket<'a> {
    domain: &'a LifecycleDomain,
    prior: ModuleState,
    epoch: u64,
    settled: bool,
}

/// Arm-1 optimism budget: `try_write` misses before the sealer falls
/// through to the single blocking acquisition. Each miss is nanoseconds
/// plus a yield, so this covers only transient contention — the quiet
/// fast path seals on the first attempt, and sustained contention moves
/// to arm 2 (queued writer stalls new admissions; the armed shutdown
/// deadline owns the bound) within about a millisecond instead of
/// spinning against live traffic the seal has not yet fenced.
const FINALIZE_SEAL_SPIN_MISSES: u32 = 1_000;

thread_local! {
    /// conc-M2 nesting tripwire: true while an `OrdinaryGuard` is alive on
    /// this thread. Guards are `!Send`, so a plain thread-local (never read
    /// cross-thread) is the whole mechanism.
    static ADMITTED_ON_THREAD: Cell<bool> = const { Cell::new(false) };
}

/// Debug-only: asserts the calling thread holds a live [`OrdinaryGuard`].
/// Destructor paths that ride enclosing exclusion instead of admitting
/// (Drop-may-never-admit) call this to pin the contract: in a debug build
/// a `Drop` that reaches native without an enclosing guard fails loudly
/// instead of running unexcluded. Compiles to nothing in release.
pub(in crate::ffi) fn debug_assert_admitted() {
    debug_assert!(
        ADMITTED_ON_THREAD.get(),
        "native call from Drop without an enclosing OrdinaryGuard: destructors must ride \
         enclosing exclusion or quarantine, never admit, never run bare"
    );
}

impl LifecycleDomain {
    /// Fresh domain: `LoadedUninitialized` at epoch 0. Ordinary work is
    /// denied until the first `C_Initialize` publishes `Open`.
    pub(in crate::ffi) fn new() -> Self {
        Self {
            inner: RwLock::new(LifecycleInner {
                state: ModuleState::LoadedUninitialized,
                epoch: 0,
            }),
        }
    }

    /// Admit one ordinary invocation, checking state+epoch under the read
    /// acquisition that seals them. The returned guard holds read
    /// exclusion across native return, validation and settlement; it must
    /// stay alive until the `ffi_*` boundary returns.
    ///
    /// Denial map (local refusals, no provider contact):
    /// - poisoned lock ⇒ `GENERAL_ERROR` (fail-closed);
    /// - `Open` ⇒ admitted;
    /// - `Uncertain` ⇒ `GENERAL_ERROR` (unknown provider state);
    /// - any other state ⇒ `CRYPTOKI_NOT_INITIALIZED` (matches what a
    ///   compliant provider reports for ordinary calls outside a live
    ///   incarnation, so pre-Initialize callers observe no new RV).
    pub(in crate::ffi) fn admit_ordinary(&self) -> CkResult<OrdinaryGuard<'_>> {
        // Tripwire FIRST: a nested admission must panic, never hang behind
        // a queued writer (and never silently nest in debug).
        debug_assert!(
            !ADMITTED_ON_THREAD.get(),
            "nested ordinary admission: a second admit under a live OrdinaryGuard \
             deadlocks behind a queued writer; thread the guard down instead"
        );
        let read = self.inner.read().map_err(|_| CkRv::GENERAL_ERROR)?;
        let (state, epoch) = (read.state, read.epoch);
        match state {
            ModuleState::Open => {
                // Denial arms return WITHOUT setting the flag: only a live
                // guard trips, and its Drop clears.
                ADMITTED_ON_THREAD.set(true);
                Ok(OrdinaryGuard { _read: read, epoch, _confine: PhantomData })
            }
            ModuleState::Uncertain => Err(CkRv::GENERAL_ERROR),
            _ => Err(CkRv::CRYPTOKI_NOT_INITIALIZED),
        }
    }

    /// Start the Initialize control transition under one short write: deny
    /// from sealed states (`Draining`/`Finalizing`: a TF01b Finalize owns
    /// the domain), consume an epoch, record the prior state in the
    /// ticket, enter `Initializing`. The write is NOT held across the
    /// native call — the ticket is detached — but ACQUIRING it blocks until
    /// in-flight readers drain (intended per the I1 contention decision in
    /// the design block above; a queued writer also stalls new admissions).
    /// Settlement re-acquires short.
    pub(in crate::ffi) fn begin_initialize(&self) -> CkResult<InitTicket<'_>> {
        let mut write = self.lock_write()?;
        match write.state {
            ModuleState::Draining | ModuleState::Finalizing => Err(CkRv::CRYPTOKI_NOT_INITIALIZED),
            _ => {
                let epoch = write.epoch.checked_add(1).ok_or(CkRv::GENERAL_ERROR)?;
                let prior = write.state;
                write.epoch = epoch;
                write.state = ModuleState::Initializing;
                Ok(InitTicket { domain: self, prior, epoch, settled: false })
            }
        }
    }

    /// Test-only plain publish: production publishes through
    /// `publish_open_with_purge` so the incarnation purge is atomic with
    /// the generation it retires.
    #[cfg(test)]
    pub(in crate::ffi) fn publish_open(&self, ticket: InitTicket<'_>) -> CkResult<()> {
        ticket.settle_publish(|| {})
    }

    /// Publish exactly like [`publish_open`](Self::publish_open), running
    /// `purge` INSIDE the same write section after the state flips to `Open`
    /// (I2: the re-Initialize incarnation purge must be invisible to both
    /// the pre-publish in-flight readers the write acquisition drains and
    /// the post-publish admissions that wait for the section to end). The
    /// closure runs under lifecycle write, so it may only take inner-leaf
    /// locks (DashMap shards — legal under lifecycle→shard order); it must
    /// never admit, begin control, or touch native entry points. On
    /// exhaustion the purge does NOT run: fail closed to `Uncertain`, like
    /// a refused cycle.
    pub(in crate::ffi) fn publish_open_with_purge(
        &self,
        ticket: InitTicket<'_>,
        purge: impl FnOnce(),
    ) -> CkResult<()> {
        ticket.settle_publish(purge)
    }

    /// Abandon a failed/refused Initialize cycle (best-effort cleanup, no
    /// failure mode of its own): if the ticket epoch still matches, restore
    /// the prior stable state — or `Uncertain` when the prior was the
    /// transient `Initializing` (a concurrent control op began first). On
    /// epoch mismatch a later control op already moved the domain, so the
    /// stale ticket is a silent no-op. Poison ⇒ no-op (already fail-closed).
    pub(in crate::ffi) fn abandon_initialize(&self, ticket: InitTicket<'_>) {
        ticket.settle_abandon();
    }

    /// Start the Finalize control transition (I3 drain-then-seal): the
    /// sealing write acquisition IS the drain — no in-flight reader
    /// survives it — and the `Draining` flip under that write is the
    /// seal. Two arms, exactly per the design block: (1) a `try_write`
    /// loop for the quiet fast path, each miss re-checking the local
    /// view of the shutdown deadline (suicide on expiry — the sealer
    /// never returns failure, never proceeds unsealed; the local check
    /// also covers a failed controller spawn, which leaves the external
    /// deadline unenforced); (2) past [`FINALIZE_SEAL_SPIN_MISSES`]
    /// misses, ONE blocking acquisition under the already-armed
    /// shutdown deadline (queued writer stalls new admissions, so the
    /// drain terminates modulo a truly stuck provider; the external arm
    /// owns the bound). The ticket is detached — write is NOT held
    /// across the native call; settlement re-acquires short.
    ///
    /// Proceeds only from `Open` (an `Initialize` owns the domain from
    /// `Initializing`; a concurrent Finalize from `Draining`/`Finalizing`;
    /// there is no live incarnation to seal from `LoadedUninitialized`/
    /// `Finalized` — the denial RV matches what a compliant provider
    /// reports there, so out-of-incarnation callers observe no new RV).
    /// Poison or epoch exhaustion denies fail-closed WITHOUT native
    /// entry (the provider stays initialized; shutdown still exits).
    pub(in crate::ffi) fn begin_finalize(&self) -> CkResult<FinalizeTicket<'_>> {
        let deadline = Instant::now() + shutdown_grace();
        let mut misses = 0u32;
        let mut write = loop {
            match self.inner.try_write() {
                Ok(write) => break write,
                Err(TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        // Overrun: process death, never an unsealed return.
                        abnormal_stop_native_lifetime(StopReason::ShutdownDeadlineExpired);
                    }
                    misses += 1;
                    if misses > FINALIZE_SEAL_SPIN_MISSES {
                        // Arm 2: one blocking acquisition; the armed
                        // shutdown deadline bounds it externally.
                        break self.lock_write()?;
                    }
                    std::thread::yield_now();
                }
                // Poisoned before the seal: fail closed without sealing
                // and without native entry (mirrors every poison mapping;
                // post-poison no reader can exist, so denying the cycle
                // cannot strand in-flight work).
                Err(TryLockError::Poisoned(_)) => return Err(CkRv::GENERAL_ERROR),
            }
        };
        match write.state {
            ModuleState::Open => {
                let epoch = write.epoch.checked_add(1).ok_or(CkRv::GENERAL_ERROR)?;
                let prior = write.state;
                write.epoch = epoch;
                write.state = ModuleState::Draining;
                Ok(FinalizeTicket { domain: self, prior, epoch, settled: false })
            }
            ModuleState::Uncertain => Err(CkRv::GENERAL_ERROR),
            _ => Err(CkRv::CRYPTOKI_NOT_INITIALIZED),
        }
    }

    /// Publish a successful native Finalize, running `purge` INSIDE the
    /// same write section after the state flips to `Finalized` (purge/
    /// publish ordering: the I2 mirror — `Finalized` implies purged, so
    /// no racing re-Initialize cycle can observe the dead incarnation's
    /// bindings). Same closure contract as
    /// [`publish_open_with_purge`](Self::publish_open_with_purge): inner
    /// leaves only, never admit/begin/native. On exhaustion the purge
    /// does NOT run: fail closed to `Uncertain`, like a refused cycle.
    pub(in crate::ffi) fn publish_finalized_with_purge(
        &self,
        ticket: FinalizeTicket<'_>,
        purge: impl FnOnce(),
    ) -> CkResult<()> {
        ticket.settle_publish(purge)
    }

    /// Abandon a failed Finalize cycle (best-effort cleanup, no failure
    /// mode of its own): if the ticket epoch still matches, restore the
    /// prior stable state (`Open` — begin proceeds only from there) or
    /// `Uncertain` when the prior was transient. On epoch mismatch a
    /// later control op already moved the domain, so the stale ticket is
    /// a silent no-op. Poison ⇒ no-op (already fail-closed).
    pub(in crate::ffi) fn abandon_finalize(&self, ticket: FinalizeTicket<'_>) {
        ticket.settle_abandon();
    }

    fn lock_write(&self) -> CkResult<RwLockWriteGuard<'_, LifecycleInner>> {
        self.inner.write().map_err(|_| CkRv::GENERAL_ERROR)
    }

    /// Test-only state injection for TF01b-state denial coverage.
    /// Production reaches these states only through control transitions.
    #[cfg(test)]
    pub(in crate::ffi) fn set_state_for_tests(&self, state: ModuleState, epoch: u64) {
        let mut write = self.inner.write().expect("test setup on unpoisoned domain");
        write.state = state;
        write.epoch = epoch;
    }

    #[cfg(test)]
    pub(in crate::ffi) fn state_for_tests(&self) -> ModuleState {
        self.inner.read().expect("test setup on unpoisoned domain").state
    }

    #[cfg(test)]
    pub(in crate::ffi) fn epoch_for_tests(&self) -> u64 {
        self.inner.read().expect("test setup on unpoisoned domain").epoch
    }

    /// Test-only: drive the honest begin/publish cycle so tests exercise
    /// ordinary paths in the post-Initialize state production guarantees.
    #[cfg(test)]
    pub(in crate::ffi) fn open_for_tests(&self) {
        let init = self.begin_initialize().expect("test setup: begin on unsealed domain");
        self.publish_open(init).expect("test setup: publish on unsealed domain");
    }

    /// Test-only: hold the write lock across `f`, so a panicking `f`
    /// poisons the domain the way a panic inside a control section would.
    /// Production control sections run no caller code, so this shape is
    /// reachable only here; the poison mapping itself is defense-in-depth.
    #[cfg(test)]
    pub(in crate::ffi) fn hold_write_across_for_tests(&self, f: impl FnOnce()) {
        let _write = self.inner.write().expect("test setup on unpoisoned domain");
        f();
    }
}

impl OrdinaryGuard<'_> {
    /// The domain epoch stamped at the admission that sealed it. Session
    /// fences correlate on it (close-ownership records the closing epoch);
    /// valid only while the guard is alive (it pins the epoch).
    pub(in crate::ffi) fn epoch(&self) -> u64 {
        self.epoch
    }

    #[cfg(test)]
    pub(in crate::ffi) fn epoch_for_tests(&self) -> u64 {
        self.epoch
    }
}

impl Drop for OrdinaryGuard<'_> {
    /// Settlement end: releasing read exclusion also clears the thread's
    /// tripwire flag. Runs on unwind too, so a settlement panic never leaves
    /// the flag tripped for later admissions on this thread.
    fn drop(&mut self) {
        ADMITTED_ON_THREAD.set(false);
    }
}

impl InitTicket<'_> {
    fn settle_publish(mut self, purge: impl FnOnce()) -> CkResult<()> {
        self.settled = true;
        let mut write = self.domain.lock_write()?;
        match write.epoch.checked_add(1) {
            Some(epoch) => {
                write.epoch = epoch;
                write.state = ModuleState::Open;
                // Still under write: post-publish admissions wait, so the
                // purge is atomic with the generation it retires. The
                // explicit `drop` keeps the guard alive across `purge`
                // (NLL would otherwise end it at the last field store).
                purge();
                drop(write);
                Ok(())
            }
            None => {
                // No next identity: fail closed without consuming an epoch
                // and without purging (a refused cycle purges nothing).
                write.state = ModuleState::Uncertain;
                Err(CkRv::GENERAL_ERROR)
            }
        }
    }

    fn settle_abandon(mut self) {
        self.settled = true;
        Self::abandon_raw(self.domain, self.prior, self.epoch);
    }

    fn abandon_raw(domain: &LifecycleDomain, prior: ModuleState, epoch: u64) {
        let Ok(mut write) = domain.inner.write() else {
            return;
        };
        if write.epoch != epoch {
            // Stale ticket: a later control op owns the outcome.
            return;
        }
        // The only live ticket at u64::MAX is this one (begin is denied
        // there), so restoring without a bump is confusion-free; control
        // frozen from here on, incarnation pinned (a restored `Open` keeps
        // admitting — only new control cycles are denied).
        if let Some(next) = write.epoch.checked_add(1) {
            write.epoch = next;
        }
        write.state = match prior {
            // Transient prior: nothing stable to restore — fail closed.
            ModuleState::Initializing | ModuleState::Draining | ModuleState::Finalizing => {
                ModuleState::Uncertain
            }
            stable => stable,
        };
    }

    #[cfg(test)]
    pub(in crate::ffi) fn epoch_for_tests(&self) -> u64 {
        self.epoch
    }
}

impl Drop for InitTicket<'_> {
    /// Backstop: an unsettled ticket (early return, panic) abandons so the
    /// domain never wedges in `Initializing`. Never panics: poison ⇒ no-op.
    fn drop(&mut self) {
        if !self.settled {
            Self::abandon_raw(self.domain, self.prior, self.epoch);
        }
    }
}

impl FinalizeTicket<'_> {
    /// Mark the exclusive native call in flight: `Draining` → `Finalizing`
    /// under one short write, immediately before native entry. Consumes no
    /// epoch — the flip belongs to the begin cycle, so the ticket epoch
    /// stays authoritative for abandon. The acquisition is uncontended in
    /// practice (`Draining` denies every new admission; only microsecond
    /// denying reads can interleave), so plain blocking matches every
    /// other control section. Fails closed on poison or an unexpected
    /// state (unreachable without a concurrent control op, which the
    /// sealed domain denies — defense in depth).
    pub(in crate::ffi) fn enter_finalizing(&self) -> CkResult<()> {
        let mut write = self.domain.lock_write()?;
        if write.state != ModuleState::Draining {
            return Err(CkRv::GENERAL_ERROR);
        }
        write.state = ModuleState::Finalizing;
        Ok(())
    }

    fn settle_publish(mut self, purge: impl FnOnce()) -> CkResult<()> {
        self.settled = true;
        let mut write = self.domain.lock_write()?;
        match write.epoch.checked_add(1) {
            Some(epoch) => {
                write.epoch = epoch;
                write.state = ModuleState::Finalized;
                // Still under write: the purge is atomic with the
                // `Finalized` it retires (I2 mirror — see
                // `InitTicket::settle_publish` for the NLL note).
                purge();
                drop(write);
                Ok(())
            }
            None => {
                // No next identity: fail closed without consuming an epoch
                // and without purging (a refused cycle purges nothing).
                write.state = ModuleState::Uncertain;
                Err(CkRv::GENERAL_ERROR)
            }
        }
    }

    fn settle_abandon(mut self) {
        self.settled = true;
        Self::abandon_raw(self.domain, self.prior, self.epoch);
    }

    fn abandon_raw(domain: &LifecycleDomain, prior: ModuleState, epoch: u64) {
        let Ok(mut write) = domain.inner.write() else {
            return;
        };
        if write.epoch != epoch {
            // Stale ticket: a later control op owns the outcome.
            return;
        }
        // The only live ticket at u64::MAX is this one (begin is denied
        // there), so restoring without a bump is confusion-free; control
        // frozen from here on, incarnation pinned (a restored `Open` keeps
        // admitting — only new control cycles are denied).
        if let Some(next) = write.epoch.checked_add(1) {
            write.epoch = next;
        }
        write.state = match prior {
            // Transient prior: nothing stable to restore — fail closed.
            ModuleState::Initializing | ModuleState::Draining | ModuleState::Finalizing => {
                ModuleState::Uncertain
            }
            stable => stable,
        };
    }

    #[cfg(test)]
    pub(in crate::ffi) fn epoch_for_tests(&self) -> u64 {
        self.epoch
    }
}

impl Drop for FinalizeTicket<'_> {
    /// Backstop: an unsettled ticket (early return, panic) abandons so the
    /// domain never wedges in a sealed state. Never panics: poison ⇒ no-op.
    fn drop(&mut self) {
        if !self.settled {
            Self::abandon_raw(self.domain, self.prior, self.epoch);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t3_qualified_host_platform_check_is_ok() {
        // This test runs on a qualified native-FFI host (Linux GNU/musl
        // x86_64/x86, macOS aarch64/x86_64, Windows MSVC x86_64/x86); the
        // const itself is covered by
        // `native_domain_current_host_reports_qualified_or_refuses`.
        assert!(check_native_platform().is_ok());
    }

    #[test]
    fn t3_unsupported_platform_display_names_qualified_hosts() {
        let msg = DomainError::UnsupportedPlatform { detail: "test-detail" }.to_string();
        assert!(msg.contains("Linux GNU/musl"), "Display must name Linux hosts, got: {msg}");
        assert!(
            msg.contains("Windows MSVC on x86_64 (64-bit) or x86 (32-bit)"),
            "Display must name Windows MSVC x86_64/x86 hosts, got: {msg}"
        );
    }
}
