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
//! `Initialize`/`Finalize` and the pre-Initialize-legal info queries. Every
//! other native entry (`call_bytes_exact*`, `call_*_with_mechanism*`,
//! `call_raw`, `call_array`, `call_*_output`, `fill_bytes`, 3.x paths) is
//! NOT yet admission-gated, `Finalize` performs no seal/drain (the domain
//! stays `Open` across it, exactly as before this slice), and there are no
//! session fences or `Drop` integration yet — all TF01b. The ownership-doc
//! clause stays as-is and the CHANGELOG F-01 entry stays open until TF01b.

use std::fmt;
use std::marker::PhantomData;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use pkcs11_proxy_ng_types::{CkResult, CkRv};

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
// so every native entry proves admission at COMPILE TIME — never advisory.
//
// Whole-subsystem lock order (TF01a + TF01b; reviewed design TF01b follows):
//   lifecycle-domain RwLock (outer) -> DashMap shard locks (inner, leaf).
// Ordinary guards are held across unbounded provider calls — the first
// lock ever held there — so everything taken under a guard must be a
// short leaf: DashMap shard ops qualify (per-op, never held across native
// calls themselves). The order is never inverted: eviction helpers take
// no lifecycle lock in TF01a (TF01b session fences stay leaf-scoped), and
// the constructor-registry mutex is never acquired under lifecycle.
// TF01a control sections (begin/publish/abandon) are SHORT write holds
// that never span a native call, so ordinary traffic cannot wedge
// Initialize. TF01b's Finalize seal is the one deliberate exception: it
// holds write across a BOUNDED drain (existing `native_stop` overrun path),
// and the drain terminates because in-flight readers only ever take short
// shard leaves — modulo a truly stuck provider, which the bound covers.
//
// Re-entrancy (load-bearing with `std` locks): a thread holding read that
// takes write deadlocks, as does nested read behind a waiting writer. So:
// ordinary paths admit EXACTLY ONCE at the `ffi_*` boundary and thread
// `&OrdinaryGuard` down — helpers take the guard as a parameter and never
// re-admit; control paths (Initialize/Finalize) NEVER admit (audited — the
// `call_control_*` chokes take no guard, and no control path calls
// `admit_ordinary`). While an `OrdinaryGuard` is alive on a thread, that
// thread must not call any domain method that acquires the lock.
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
#[allow(dead_code)]
// TF01b-removes: Draining/Finalizing/Finalized gain
// production constructors with the Finalize seal/drain; until then only
// test injection builds them, so the non-test build would warn.
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
    // TF01b-removes: TF01b session fences correlate on guard epochs; until
    // then only tests read the stamp, so the non-test build would warn.
    #[allow(dead_code)]
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
        let read = self.inner.read().map_err(|_| CkRv::GENERAL_ERROR)?;
        let (state, epoch) = (read.state, read.epoch);
        match state {
            ModuleState::Open => Ok(OrdinaryGuard { _read: read, epoch, _confine: PhantomData }),
            ModuleState::Uncertain => Err(CkRv::GENERAL_ERROR),
            _ => Err(CkRv::CRYPTOKI_NOT_INITIALIZED),
        }
    }

    /// Start the Initialize control transition under one short write: deny
    /// from sealed states (`Draining`/`Finalizing`: a TF01b Finalize owns
    /// the domain), consume an epoch, record the prior state in the
    /// ticket, enter `Initializing`. The write is NOT held across the
    /// native call — the ticket is detached — so in-flight ordinary work
    /// cannot wedge Initialize; settlement re-acquires short.
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

    /// Publish a successful native `C_Initialize`: last-writer-wins `Open`
    /// (concurrent successes are idempotent-safe), consuming an epoch. At
    /// epoch exhaustion there is no next identity: fail closed to
    /// `Uncertain` (precedent: `GenerationExhausted` ⇒ `GENERAL_ERROR`).
    pub(in crate::ffi) fn publish_open(&self, ticket: InitTicket<'_>) -> CkResult<()> {
        ticket.settle_publish()
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
    #[cfg(test)]
    pub(in crate::ffi) fn epoch_for_tests(&self) -> u64 {
        self.epoch
    }
}

impl InitTicket<'_> {
    fn settle_publish(mut self) -> CkResult<()> {
        self.settled = true;
        let mut write = self.domain.lock_write()?;
        match write.epoch.checked_add(1) {
            Some(epoch) => {
                write.epoch = epoch;
                write.state = ModuleState::Open;
                Ok(())
            }
            None => {
                // No next identity: fail closed without consuming an epoch.
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
        // there), so restoring without a bump is confusion-free; every
        // later begin is denied, fail-closed going forward.
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
