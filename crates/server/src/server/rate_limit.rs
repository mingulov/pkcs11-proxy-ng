//! Per-peer rate limiters for the unauthenticated surface:
//! `GetBackendInterfaces` (discovery) and `Initialize` (context creation).
//!
//! The discovery limiter closes `FOLLOWUP-rate-limit`. The threat is
//! unauthenticated TCP peers fanning out registry probes at high QPS;
//! though the trust model already requires intra-VPC network isolation,
//! defence in depth caps the per-peer rate to a configurable budget.
//!
//! The initialize limiter (W1-L7-03) is a SEPARATE, always-on budget:
//! a default-config flood must not reach the `max_contexts` cap, so the
//! throttle cannot share the discovery limiter's opt-in (default-off)
//! state. The budget is a fixed generous constant — legitimate clients
//! initialize once per process, while a flood trips it loudly.
//!
//! Implementation: a simple fixed-window counter per peer IP. Memory
//! is bounded — entries idle for > 5× the window are GC'd lazily by
//! the next caller. Not for high-throughput general traffic; these are
//! knobs to throttle a single noisy peer's discovery/initialize RPCs.
//!
//! ## Limiter scope (W1-C2-B08)
//!
//! This module covers per-peer fixed-window budgets for the two
//! unauthenticated RPCs only (`check` for discovery, `check_init` for
//! context creation, with independent budgets). Every other layer is
//! owned elsewhere — deliberately distinct, never overlapping:
//!
//! - Authenticated/general RPC load: the global `IN_FLIGHT` breaker plus
//!   the per-context cap in `grpc_service/service_utils.rs`.
//! - One noisy connection hogging the breaker: the per-connection
//!   `PEER_IN_FLIGHT` admission in `service_utils.rs` (W1-L7-28).
//! - Transport floods: the tonic `concurrency_limit_per_connection` /
//!   `max_concurrent_streams` / `load_shed` knobs in `main.rs`
//!   (W1-L6-20), which bound buffering above the breaker.
//! - Per-principal quotas and login budgets: `rate_quota.rs` (opt-in).
//!
//! A general per-connection token bucket is DEFERRED by adjudication
//! (group-36: per-peer + breaker coverage is sufficient); this module
//! must not grow one without revisiting that decision. Adjacent future
//! work (W1-L7-02 peer-keyed unauthenticated quota, Task 30) extends the
//! quota layer, not this module.

use std::net::IpAddr;
use std::sync::{LazyLock, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Rate-limiter state. Lazy-initialised on first call.
struct State {
    /// Window length.
    window: Duration,
    /// Max calls per window per peer IP.
    max_per_window: u32,
    /// Per-peer counter (count, window_start).
    peers: DashMap<IpAddr, PeerCell>,
    /// When the last opportunistic GC walked `peers`. Initial value
    /// is the daemon start time. Gated to at most one GC sweep per
    /// `window` to keep the per-check cost flat even if `peers.len()`
    /// hovers above the GC trigger threshold.
    last_gc: std::sync::Mutex<Instant>,
}

#[derive(Clone, Copy)]
struct PeerCell {
    count: u32,
    window_start: Instant,
}

static STATE: OnceLock<State> = OnceLock::new();

/// Configure the rate limiter. Called once at daemon startup from
/// `main`. Safe to call multiple times; only the first wins.
///
/// `max_per_window == 0` disables rate limiting (the default — we ship
/// permissive so existing deployments don't suddenly see
/// RESOURCE_EXHAUSTED).
pub fn configure(window: Duration, max_per_window: u32) {
    let _ = STATE.set(State {
        window,
        max_per_window,
        peers: DashMap::new(),
        last_gc: std::sync::Mutex::new(Instant::now()),
    });
}

/// Check whether a peer may issue another call. Returns `Ok(())`
/// if allowed (and consumes one budget unit); `Err(retry_after)` if
/// the peer is over budget.
pub fn check(peer: IpAddr) -> Result<(), Duration> {
    check_against(STATE.get(), peer, Instant::now())
}

/// Fixed-window length for the always-on initialize budget (W1-L7-03).
pub(crate) const INIT_THROTTLE_WINDOW: Duration = Duration::from_secs(60);
/// Max unauthenticated `Initialize` calls per peer IP per
/// [`INIT_THROTTLE_WINDOW`] (W1-L7-03). Generous on purpose: legitimate
/// clients initialize once per process, so 10/s sustained from one IP
/// still passes deploy herds while a context-creation flood trips the
/// throttle loudly long before the `max_contexts` cap.
pub(crate) const INIT_THROTTLE_MAX_PER_WINDOW: u32 = 600;

/// Always-on per-IP state for the initialize throttle (W1-L7-03).
/// Separate from the opt-in discovery `STATE` above: initialize
/// throttling engages under default configuration with no operator
/// setup and never shares budget with discovery probes.
static INIT_STATE: LazyLock<State> = LazyLock::new(|| State {
    window: INIT_THROTTLE_WINDOW,
    max_per_window: INIT_THROTTLE_MAX_PER_WINDOW,
    peers: DashMap::new(),
    last_gc: std::sync::Mutex::new(Instant::now()),
});

/// Check whether a peer may issue another unauthenticated `Initialize`.
/// Always on (no `configure` needed); returns `Ok(())` if allowed (and
/// consumes one budget unit), `Err(retry_after)` if the peer is over
/// budget.
pub fn check_init(peer: IpAddr) -> Result<(), Duration> {
    check_against(Some(&INIT_STATE), peer, Instant::now())
}

/// Pure check against an explicit `State` reference at a given `now`.
/// Exposed to tests so each test owns its `State` instead of racing on
/// the global `STATE` OnceLock (which is set-once for the daemon's
/// lifetime).
fn check_against(state: Option<&State>, peer: IpAddr, now: Instant) -> Result<(), Duration> {
    let state = match state {
        Some(s) if s.max_per_window > 0 => s,
        _ => return Ok(()),
    };
    {
        let mut entry = state.peers.entry(peer).or_insert(PeerCell { count: 0, window_start: now });
        if now.duration_since(entry.window_start) >= state.window {
            entry.window_start = now;
            entry.count = 0;
        }
        if entry.count >= state.max_per_window {
            let elapsed = now.duration_since(entry.window_start);
            let retry_after = state.window.saturating_sub(elapsed);
            return Err(retry_after);
        }
        entry.count += 1;
        // `entry` (the per-shard write guard) drops here before the
        // GC below — `DashMap::retain` walks every shard and would
        // deadlock-or-stall if we held this shard's guard across it.
    }

    // Opportunistic GC: when the map has more than 1k entries AND
    // we haven't GC'd within the last window, walk it and drop
    // entries idle > 5 windows. The window-gate keeps the
    // per-check cost flat (O(1) load) even if `peers.len()` stays
    // above 1024 — without it, every check would trigger an O(N)
    // retain scan.
    if state.peers.len() > 1024
        && let Ok(mut last) = state.last_gc.try_lock()
        && now.duration_since(*last) >= state.window
    {
        let stale_after = state.window * 5;
        state.peers.retain(|_, cell| now.duration_since(cell.window_start) < stale_after);
        *last = now;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn peer(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
    }

    fn fresh_state(window: Duration, max_per_window: u32) -> State {
        State {
            window,
            max_per_window,
            peers: DashMap::new(),
            last_gc: std::sync::Mutex::new(Instant::now()),
        }
    }

    #[test]
    fn disabled_when_state_unset() {
        // The disabled path is the one we hit when `configure()` has
        // never been called (the default for daemons that don't opt
        // in). Test it with an explicit `None` so we don't race on the
        // global `STATE` OnceLock with sibling tests.
        let now = Instant::now();
        for _ in 0..10_000 {
            check_against(None, peer(1), now).unwrap();
        }
    }

    #[test]
    fn disabled_when_max_is_zero() {
        // Explicit `max_per_window = 0` is the documented "disabled"
        // setting. Verify it short-circuits even when state IS set.
        let state = fresh_state(Duration::from_millis(100), 0);
        let now = Instant::now();
        for _ in 0..10_000 {
            check_against(Some(&state), peer(1), now).unwrap();
        }
    }

    #[test]
    fn allows_within_budget_rejects_over() {
        let state = fresh_state(Duration::from_millis(100), 3);
        let now = Instant::now();
        let p = peer(2);
        assert!(check_against(Some(&state), p, now).is_ok());
        assert!(check_against(Some(&state), p, now).is_ok());
        assert!(check_against(Some(&state), p, now).is_ok());
        let rejection = check_against(Some(&state), p, now)
            .expect_err("4th call within budget should be rejected");
        assert!(rejection > Duration::ZERO);
    }

    #[test]
    fn window_rollover_resets_count() {
        // Verify the count resets when `now` advances past the window.
        // Previously untested — now trivial with explicit `now`.
        let state = fresh_state(Duration::from_millis(100), 2);
        let t0 = Instant::now();
        let p = peer(3);
        assert!(check_against(Some(&state), p, t0).is_ok());
        assert!(check_against(Some(&state), p, t0).is_ok());
        assert!(check_against(Some(&state), p, t0).is_err());
        let t1 = t0 + Duration::from_millis(150);
        assert!(check_against(Some(&state), p, t1).is_ok());
    }

    #[test]
    fn limiter_scope_discovery_and_initialize_budgets_are_independent() {
        // W1-C2-B08 scope pin: each unauthenticated RPC family has its own
        // per-peer budget — exhausting discovery for a peer never throttles
        // its initialize calls, and vice versa.
        let discovery = fresh_state(Duration::from_secs(60), 1);
        let init = fresh_state(Duration::from_secs(60), 1);
        let now = Instant::now();
        let p = peer(6);
        assert!(check_against(Some(&discovery), p, now).is_ok());
        assert!(
            check_against(Some(&discovery), p, now).is_err(),
            "second discovery call must exhaust the budget of 1"
        );
        assert!(
            check_against(Some(&init), p, now).is_ok(),
            "exhausted discovery budget must not throttle initialize"
        );
        assert!(check_against(Some(&init), p, now).is_err());
        assert!(
            check_against(Some(&discovery), p, now).is_err(),
            "budgets stay independent in both directions"
        );
    }

    #[test]
    fn per_peer_isolation() {
        // Distinct peers don't share a budget.
        let state = fresh_state(Duration::from_millis(100), 1);
        let now = Instant::now();
        assert!(check_against(Some(&state), peer(4), now).is_ok());
        assert!(check_against(Some(&state), peer(5), now).is_ok());
        assert!(check_against(Some(&state), peer(4), now).is_err());
        assert!(check_against(Some(&state), peer(5), now).is_err());
    }

    #[test]
    fn init_throttle_is_always_on_under_default_config() {
        // W1-L7-03 fix round: the initialize budget engages with no
        // `configure` call (decoupled from the opt-in discovery
        // limiter). Uses a dedicated TEST-NET IP so the shared global
        // cannot interact with other tests touching INIT_STATE.
        let p = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 47));
        for _ in 0..INIT_THROTTLE_MAX_PER_WINDOW {
            assert!(check_init(p).is_ok(), "in-budget initialize checks must pass");
        }
        let retry_after =
            check_init(p).expect_err("over-budget initialize check must be throttled");
        assert!(retry_after > Duration::ZERO);
        assert!(retry_after <= INIT_THROTTLE_WINDOW);
    }
}
