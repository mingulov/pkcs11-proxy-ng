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

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use pkcs11_proxy_ng_types::CkSlotId;

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
    login_state: DashMap<CkSlotId, FailedLoginState>,
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
    login_state: &DashMap<CkSlotId, FailedLoginState>,
    slot: CkSlotId,
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
fn record_success_on(login_state: &DashMap<CkSlotId, FailedLoginState>, slot: CkSlotId) {
    if let Some(mut entry) = login_state.get_mut(&slot) {
        entry.count = 0;
        entry.cooldown_until = None;
    }
}

/// Returns `true` if `slot` is within an active cooldown window.
fn in_cooldown_on(login_state: &DashMap<CkSlotId, FailedLoginState>, slot: CkSlotId) -> bool {
    login_state.get(&slot).is_some_and(|e| e.cooldown_until.is_some_and(|t| t > Instant::now()))
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
    begin_op_on(state.max_in_flight, &state.in_flight, principal)
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
pub fn record_login_failure(slot: CkSlotId) -> bool {
    let Some(state) = STATE.get() else { return false };
    record_failure_on(state.login_budget, state.login_cooldown, &state.login_state, slot)
}

/// Record a successful login for `slot`, resetting the failure count and clearing
/// any active cooldown. No-op when `per_slot_failed_login_budget` is unset.
pub fn record_login_success(slot: CkSlotId) {
    let Some(state) = STATE.get() else { return };
    if state.login_budget.is_none() {
        return;
    }
    record_success_on(&state.login_state, slot);
}

/// Returns `true` if `slot` is currently within a failed-login cooldown window.
/// Always returns `false` when `per_slot_failed_login_budget` is unset.
pub fn login_slot_in_cooldown(slot: CkSlotId) -> bool {
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
    fn login_budget_trips_at_k() {
        let q = make_quota(None, None, Some(3), 60);
        let slot = CkSlotId(100);
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
        let slot = CkSlotId(101);
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
        let slot = CkSlotId(102);
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
        let slot = CkSlotId(103);
        for _ in 0..10 {
            assert!(
                !record_failure_on(q.login_budget, q.login_cooldown, &q.login_state, slot),
                "None budget: never trip"
            );
            assert!(!in_cooldown_on(&q.login_state, slot), "None budget: never in cooldown");
        }
    }
}
