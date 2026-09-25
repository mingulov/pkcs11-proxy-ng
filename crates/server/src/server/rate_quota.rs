//! Per-principal in-flight / session-quota limiter and per-slot failed-login budget.
//!
//! All limits are opt-in: an absent or all-`None` `[rate_limit]` config section
//! is byte-identical to having no rate limiting. Configure once at daemon startup
//! via `configure`; all public functions are safe to call before `configure`
//! (they act as if every limit is unset, i.e. always allow).
//!
//! Mirrors the `OnceLock<State>` + `DashMap` pattern of [`super::rate_limit`].
//! Uses `Arc<DashMap>` for `in_flight` so `PrincipalOpGuard` can hold the map
//! reference without lifetime parameters (enabling test isolation via local state).
//!
//! ## Concurrency safety for in-flight GC
//!
//! The guard holds the principal `String` key and **re-looks-up** the DashMap entry
//! on drop (`map.get(key)`).  `DashMap::get()` holds a shard **read-lock** for the
//! lifetime of the returned `Ref`, and `DashMap::retain()` acquires a shard
//! **write-lock** — the two are mutually exclusive at the shard level.  Therefore:
//!
//! - A GC pass (`retain`) cannot remove an entry while its guard is being dropped
//!   (the drop holds the shard read-lock via the `Ref`, blocking GC's write-lock).
//! - The admit path (`entry().or_insert_with()` + `fetch_add`) holds a shard
//!   write-lock for the entire insert+increment sequence, preventing GC from
//!   removing a newly-inserted zero-count entry before the increment completes.
//! - GC only drops entries whose count is `<= 0`; a just-admitted entry has count
//!   `>= 1` when the shard lock is released, so it is never a GC target.
//!
//! The alternative (guard holds `Arc<AtomicI64>` so the decrement hits the same
//! counter even after map removal) was not chosen because the re-lookup design is
//! already correct under DashMap shard-locking and requires no extra allocation.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Minimum interval between opportunistic GC sweeps of the in-flight map.
/// There is no per-op window here (unlike `rate_limit.rs`), so a fixed constant is used.
const INFLIGHT_GC_INTERVAL: Duration = Duration::from_secs(60);

use super::slot_map::BackendSlotId;
use dashmap::DashMap;

/// Default failed-login cooldown when a budget is configured but
/// `per_slot_failed_login_cooldown_secs` is absent.
const DEFAULT_COOLDOWN_SECS: u64 = 60;

// ── Internal state ────────────────────────────────────────────────────────────

struct FailedLoginState {
    count: u32,
    cooldown_until: Option<Instant>,
}

struct RateQuota {
    max_in_flight: Option<usize>,
    max_sessions: Option<usize>,
    login_budget: Option<u32>,
    login_cooldown: Duration,
    /// Arc so `PrincipalOpGuard` can hold a reference without a lifetime.
    in_flight: Arc<DashMap<String, AtomicI64>>,
    /// Timestamp of the last opportunistic GC sweep of `in_flight`.
    /// `try_lock` is used; a missed sweep is not a correctness issue, only
    /// a bounded delay in reclaiming idle entries.
    last_inflight_gc: Mutex<Instant>,
    login_state: DashMap<BackendSlotId, FailedLoginState>,
}

static STATE: OnceLock<RateQuota> = OnceLock::new();

// ── Guard ─────────────────────────────────────────────────────────────────────

/// RAII guard returned by [`try_begin_principal_op`].
///
/// Decrements the principal's in-flight counter on `Drop`, freeing one slot.
/// The `NoOp` variant (limit unset) holds no slot and is zero-cost on drop.
pub struct PrincipalOpGuard(GuardKind);

enum GuardKind {
    /// Limit disabled or state unconfigured — no counter to decrement.
    NoOp,
    /// Active slot reserved in `map` under `key`; decrement on drop.
    Active { map: Arc<DashMap<String, AtomicI64>>, key: String },
}

impl Drop for PrincipalOpGuard {
    fn drop(&mut self) {
        if let GuardKind::Active { map, key } = &self.0
            && let Some(cell) = map.get(key.as_str())
        {
            // Saturating: never below 0 (defensive against double-drop bugs).
            let prev = cell.fetch_sub(1, Ordering::Relaxed);
            if prev <= 0 {
                cell.store(0, Ordering::Relaxed);
            }
        }
    }
}

// ── Core logic (also exercised by tests via local RateQuota instances) ────────

/// Attempt to begin an operation for `principal` against the given in-flight map
/// and limit. Returns `Some(guard)` on success or `None` when at the cap.
fn begin_op_on(
    max_in_flight: Option<usize>,
    in_flight: &Arc<DashMap<String, AtomicI64>>,
    principal: &str,
) -> Option<PrincipalOpGuard> {
    let max = match max_in_flight {
        None => {
            return Some(PrincipalOpGuard(GuardKind::NoOp));
        }
        Some(m) => m,
    };
    // Speculative increment; roll back if over the cap.
    let cell = in_flight.entry(principal.to_owned()).or_insert_with(|| AtomicI64::new(0));
    let prev = cell.fetch_add(1, Ordering::Relaxed);
    if prev >= max as i64 {
        cell.fetch_sub(1, Ordering::Relaxed);
        crate::server::resilience::record_rate_limit_rejected();
        return None;
    }
    drop(cell); // Release DashMap shard lock before cloning Arc.
    Some(PrincipalOpGuard(GuardKind::Active {
        map: Arc::clone(in_flight),
        key: principal.to_owned(),
    }))
}

/// Record a failed login for `slot` against the given state. Returns `true` when
/// the budget is reached (slot enters cooldown). Records the metric once on the
/// first trip; subsequent calls while in cooldown return `true` without re-recording.
fn record_failure_on(
    login_budget: Option<u32>,
    login_cooldown: Duration,
    login_state: &DashMap<BackendSlotId, FailedLoginState>,
    slot: BackendSlotId,
) -> bool {
    let budget = match login_budget {
        None => return false,
        Some(b) => b,
    };
    let mut entry = login_state
        .entry(slot)
        .or_insert_with(|| FailedLoginState { count: 0, cooldown_until: None });
    // Don't increment past the budget (guards against u32 saturation).
    if entry.count < budget {
        entry.count = entry.count.saturating_add(1);
    }
    if entry.count >= budget {
        if entry.cooldown_until.is_none() {
            // First trip: arm the cooldown and record the metric.
            entry.cooldown_until = Some(Instant::now() + login_cooldown);
            crate::server::resilience::record_login_budget_tripped();
        }
        true
    } else {
        false
    }
}

/// Reset the failure count and clear any active cooldown for `slot`.
fn record_success_on(login_state: &DashMap<BackendSlotId, FailedLoginState>, slot: BackendSlotId) {
    if let Some(mut entry) = login_state.get_mut(&slot) {
        entry.count = 0;
        entry.cooldown_until = None;
    }
}

/// Returns `true` if `slot` is within an active cooldown window.
fn in_cooldown_on(
    login_state: &DashMap<BackendSlotId, FailedLoginState>,
    slot: BackendSlotId,
) -> bool {
    login_state.get(&slot).is_some_and(|e| e.cooldown_until.is_some_and(|t| t > Instant::now()))
}

/// Opportunistically reclaim idle (count == 0) entries from the in-flight map.
///
/// Gated by two conditions (matching the sibling `rate_limit.rs` GC pattern):
/// - map size > 1 024 (avoids a full scan when the map is small — the common case).
/// - `INFLIGHT_GC_INTERVAL` has elapsed since the last sweep (rate-limits scan cost).
///
/// `try_lock` is used so a contended GC lock is skipped silently; the next
/// successful admit on any principal will retry.
///
/// # Safety
///
/// See the module-level concurrency note.  Entries with `count <= 0` are safe to
/// remove because the guard's `Drop` impl holds a DashMap shard **read-lock** for
/// the entire decrement (via `map.get()`), which is mutually exclusive with
/// `retain`'s shard **write-lock**.  A dropped guard therefore cannot observe a
/// missing entry mid-decrement, and a just-admitted entry (count >= 1) is never
/// a GC target.
fn maybe_gc_inflight(
    in_flight: &Arc<DashMap<String, AtomicI64>>,
    last_gc: &Mutex<Instant>,
    now: Instant,
) {
    if in_flight.len() > 1024
        && let Ok(mut last) = last_gc.try_lock()
        && now.duration_since(*last) >= INFLIGHT_GC_INTERVAL
    {
        in_flight.retain(|_, c| c.load(Ordering::Relaxed) > 0);
        *last = now;
    }
}

/// Force a GC pass unconditionally, bypassing the size and interval gates.
///
/// Available only in tests so each test can control when GC runs without
/// waiting for the 1 024-entry trigger or the 60-second interval.
#[cfg(test)]
fn force_gc_on(in_flight: &Arc<DashMap<String, AtomicI64>>) {
    in_flight.retain(|_, c| c.load(Ordering::Relaxed) > 0);
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Install the rate-quota configuration. Called once at daemon startup.
/// Only the first call wins; subsequent calls are silently ignored (OnceLock
/// semantics, matching [`super::rate_limit::configure`]).
pub fn configure(cfg: &crate::config::RateLimitConfig) {
    let cooldown_secs = cfg.per_slot_failed_login_cooldown_secs.unwrap_or(DEFAULT_COOLDOWN_SECS);
    let _ = STATE.set(RateQuota {
        max_in_flight: cfg.per_principal_max_in_flight,
        max_sessions: cfg.per_principal_max_sessions,
        login_budget: cfg.per_slot_failed_login_budget,
        login_cooldown: Duration::from_secs(cooldown_secs),
        in_flight: Arc::new(DashMap::new()),
        last_inflight_gc: Mutex::new(Instant::now()),
        login_state: DashMap::new(),
    });
}

/// Attempt to begin an operation for `principal`, subject to the in-flight cap.
///
/// Returns `Some(guard)` if the principal is below the configured cap; the guard
/// decrements the counter on drop, freeing the slot. Returns `None` when the cap
/// is reached; callers should respond with `CKR_SESSION_COUNT` or similar.
///
/// When `per_principal_max_in_flight` is unset, always returns `Some` (a no-op
/// guard that holds no slot).
pub fn try_begin_principal_op(principal: &str) -> Option<PrincipalOpGuard> {
    let Some(state) = STATE.get() else {
        return Some(PrincipalOpGuard(GuardKind::NoOp));
    };
    let guard = begin_op_on(state.max_in_flight, &state.in_flight, principal)?;
    // Opportunistic GC: reclaim idle (count == 0) principal entries from the
    // in_flight map.  Only runs when the map is large AND the interval has
    // elapsed; otherwise it is a single atomic size-load + a failed try_lock.
    // Runs only on successful admission so GC never delays a rejected caller.
    maybe_gc_inflight(&state.in_flight, &state.last_inflight_gc, Instant::now());
    Some(guard)
}

/// Returns the configured per-principal session limit, or `None` when
/// `per_principal_max_sessions` is unset or the rate-quota state has not been
/// configured yet. Used by `open_session` to check the derived session count
/// against the live bookkeeping (leak-proof — no reserve/release needed).
pub fn per_principal_max_sessions() -> Option<usize> {
    STATE.get()?.max_sessions
}

/// Record a failed login attempt for `slot`.
///
/// Returns `true` if the failure count has now reached the configured budget
/// (the slot has entered its cooldown window). Returns `false` otherwise.
/// When `per_slot_failed_login_budget` is unset always returns `false`.
pub fn record_login_failure(slot: BackendSlotId) -> bool {
    let Some(state) = STATE.get() else { return false };
    record_failure_on(state.login_budget, state.login_cooldown, &state.login_state, slot)
}

/// Record a successful login for `slot`, resetting the failure count and clearing
/// any active cooldown. No-op when `per_slot_failed_login_budget` is unset.
pub fn record_login_success(slot: BackendSlotId) {
    let Some(state) = STATE.get() else { return };
    if state.login_budget.is_none() {
        return;
    }
    record_success_on(&state.login_state, slot);
}

/// Returns `true` if `slot` is currently within a failed-login cooldown window.
/// Always returns `false` when `per_slot_failed_login_budget` is unset.
pub fn login_slot_in_cooldown(slot: BackendSlotId) -> bool {
    let Some(state) = STATE.get() else { return false };
    if state.login_budget.is_none() {
        return false;
    }
    in_cooldown_on(&state.login_state, slot)
}

/// Returns the configured per-slot failed-login budget, or `None` when
/// `per_slot_failed_login_budget` is unset or the state has not been
/// configured. Used by tests to detect which OnceLock branch is active.
pub fn configured_login_budget() -> Option<u32> {
    STATE.get()?.login_budget
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a local RateQuota for test isolation (avoids the global OnceLock).
    fn make_quota(
        max_in_flight: Option<usize>,
        max_sessions: Option<usize>,
        login_budget: Option<u32>,
        cooldown_secs: u64,
    ) -> RateQuota {
        RateQuota {
            max_in_flight,
            max_sessions,
            login_budget,
            login_cooldown: Duration::from_secs(cooldown_secs),
            in_flight: Arc::new(DashMap::new()),
            last_inflight_gc: Mutex::new(Instant::now()),
            login_state: DashMap::new(),
        }
    }

    // ── In-flight cap ─────────────────────────────────────────────────────────

    #[test]
    fn inflight_admits_n_rejects_n_plus_1() {
        let q = make_quota(Some(2), None, None, 60);
        let g1 = begin_op_on(q.max_in_flight, &q.in_flight, "alice").expect("1st guard");
        let g2 = begin_op_on(q.max_in_flight, &q.in_flight, "alice").expect("2nd guard");
        assert!(
            begin_op_on(q.max_in_flight, &q.in_flight, "alice").is_none(),
            "3rd must be rejected at cap=2"
        );
        // Drop one → a new guard must succeed.
        drop(g1);
        let _g3 = begin_op_on(q.max_in_flight, &q.in_flight, "alice").expect("admitted after drop");
        drop(g2);
    }

    #[test]
    fn inflight_principals_are_independent() {
        let q = make_quota(Some(1), None, None, 60);
        let _ga = begin_op_on(q.max_in_flight, &q.in_flight, "alice").expect("alice ok");
        let _gb = begin_op_on(q.max_in_flight, &q.in_flight, "bob").expect("bob ok (independent)");
        assert!(begin_op_on(q.max_in_flight, &q.in_flight, "alice").is_none(), "alice at cap");
        assert!(begin_op_on(q.max_in_flight, &q.in_flight, "bob").is_none(), "bob at cap");
    }

    #[test]
    fn inflight_none_limit_always_admits() {
        let q = make_quota(None, None, None, 60);
        let guards: Vec<_> = (0..1000)
            .map(|_| begin_op_on(q.max_in_flight, &q.in_flight, "carol").expect("all admitted"))
            .collect();
        drop(guards);
    }

    // ── Login budget ──────────────────────────────────────────────────────────

    #[test]
    fn failed_login_budget_is_isolated_by_backend_slot() {
        let q = make_quota(None, None, Some(1), 60);
        let a = BackendSlotId(pkcs11_proxy_ng_types::CkSlotId(42));
        let b = BackendSlotId(pkcs11_proxy_ng_types::CkSlotId(1));
        assert!(record_failure_on(q.login_budget, q.login_cooldown, &q.login_state, a));
        assert!(in_cooldown_on(&q.login_state, a));
        assert!(!in_cooldown_on(&q.login_state, b));
        record_success_on(&q.login_state, b);
        assert!(in_cooldown_on(&q.login_state, a));
        assert!(record_failure_on(q.login_budget, q.login_cooldown, &q.login_state, b));
        record_success_on(&q.login_state, a);
        assert!(!in_cooldown_on(&q.login_state, a));
        assert!(in_cooldown_on(&q.login_state, b));
    }

    #[test]
    fn login_budget_trips_at_k() {
        let q = make_quota(None, None, Some(3), 60);
        let slot = BackendSlotId(pkcs11_proxy_ng_types::CkSlotId(100));
        assert!(
            !record_failure_on(q.login_budget, q.login_cooldown, &q.login_state, slot),
            "1st failure: not tripped"
        );
        assert!(
            !record_failure_on(q.login_budget, q.login_cooldown, &q.login_state, slot),
            "2nd failure: not tripped"
        );
        assert!(
            record_failure_on(q.login_budget, q.login_cooldown, &q.login_state, slot),
            "3rd failure: trip at budget=3"
        );
        assert!(in_cooldown_on(&q.login_state, slot), "slot must be in cooldown after trip");
    }

    #[test]
    fn login_success_clears_cooldown() {
        let q = make_quota(None, None, Some(3), 60);
        let slot = BackendSlotId(pkcs11_proxy_ng_types::CkSlotId(101));
        record_failure_on(q.login_budget, q.login_cooldown, &q.login_state, slot);
        record_failure_on(q.login_budget, q.login_cooldown, &q.login_state, slot);
        record_failure_on(q.login_budget, q.login_cooldown, &q.login_state, slot); // trips
        assert!(in_cooldown_on(&q.login_state, slot));
        record_success_on(&q.login_state, slot);
        assert!(!in_cooldown_on(&q.login_state, slot), "cooldown cleared on success");
        // Budget resets: can fail again from scratch.
        assert!(
            !record_failure_on(q.login_budget, q.login_cooldown, &q.login_state, slot),
            "first failure after reset is not a trip"
        );
    }

    #[test]
    fn login_cooldown_expires_with_zero_duration() {
        // 0-second cooldown: the window instant is set to now+0, so it is in
        // the past by the time in_cooldown_on checks `t > Instant::now()`.
        let q = make_quota(None, None, Some(1), 0);
        let slot = BackendSlotId(pkcs11_proxy_ng_types::CkSlotId(102));
        assert!(
            record_failure_on(q.login_budget, q.login_cooldown, &q.login_state, slot),
            "budget=1 trips on first failure"
        );
        // Zero-duration cooldown is already expired.
        assert!(!in_cooldown_on(&q.login_state, slot), "0-second cooldown immediately expired");
    }

    #[test]
    fn login_none_budget_always_inert() {
        let q = make_quota(None, None, None, 60);
        let slot = BackendSlotId(pkcs11_proxy_ng_types::CkSlotId(103));
        for _ in 0..10 {
            assert!(
                !record_failure_on(q.login_budget, q.login_cooldown, &q.login_state, slot),
                "None budget: never trip"
            );
            assert!(!in_cooldown_on(&q.login_state, slot), "None budget: never in cooldown");
        }
    }

    // ── In-flight GC ──────────────────────────────────────────────────────────

    #[test]
    fn gc_reclaims_idle_entries() {
        // After all guards are dropped (count → 0), force_gc_on must remove them.
        let q = make_quota(Some(10), None, None, 60);
        let g1 = begin_op_on(q.max_in_flight, &q.in_flight, "alice").expect("g1");
        let g2 = begin_op_on(q.max_in_flight, &q.in_flight, "bob").expect("g2");
        assert_eq!(q.in_flight.len(), 2, "two principals registered before drop");
        drop(g1);
        drop(g2);
        // Both counts are now 0; GC must remove them.
        force_gc_on(&q.in_flight);
        assert_eq!(q.in_flight.len(), 0, "GC reclaimed both idle entries");
    }

    #[test]
    fn gc_retains_entries_with_live_guards() {
        // A principal whose guard is still live (count > 0) must NOT be GC'd.
        let q = make_quota(Some(10), None, None, 60);
        let _ga = begin_op_on(q.max_in_flight, &q.in_flight, "alice").expect("g_alice");
        let gb = begin_op_on(q.max_in_flight, &q.in_flight, "bob").expect("g_bob");
        drop(gb); // bob's guard dropped; count → 0

        force_gc_on(&q.in_flight);

        assert!(q.in_flight.contains_key("alice"), "alice must be retained (live guard)");
        assert!(!q.in_flight.contains_key("bob"), "bob must be reclaimed (idle)");
        let alice_count = q.in_flight.get("alice").map(|c| c.load(Ordering::Relaxed)).unwrap_or(-1);
        assert_eq!(alice_count, 1, "alice's in-flight count stays 1 after GC");
    }

    #[test]
    fn gc_then_readmit_accounting_correct() {
        // Admit, drop, GC removes entry, admit again: new entry has correct count.
        let q = make_quota(Some(5), None, None, 60);
        let g1 = begin_op_on(q.max_in_flight, &q.in_flight, "carol").expect("first admit");
        drop(g1); // count → 0
        force_gc_on(&q.in_flight); // entry removed
        assert!(!q.in_flight.contains_key("carol"), "entry was reclaimed by GC");

        // Fresh admit must create a new entry with count == 1.
        let g2 = begin_op_on(q.max_in_flight, &q.in_flight, "carol").expect("re-admit");
        let count = q.in_flight.get("carol").map(|c| c.load(Ordering::Relaxed)).unwrap_or(-1);
        assert_eq!(count, 1, "fresh entry starts at 1 after re-admit");
        drop(g2);
    }
}
