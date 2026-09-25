//! Per-peer rate limiter for `GetBackendInterfaces`.
//!
//! Closes `FOLLOWUP-rate-limit`. The threat is unauthenticated TCP
//! peers fanning out registry probes at high QPS; though the trust
//! model already requires intra-VPC network isolation, defence in
//! depth caps the per-peer rate to a configurable budget.
//!
//! Implementation: a simple fixed-window counter per peer IP. Memory
//! is bounded — entries idle for > 5× the window are GC'd lazily by
//! the next caller. Not for high-throughput general traffic; this is
//! a knob to throttle a single noisy peer's discovery RPC.

use std::net::IpAddr;
use std::sync::OnceLock;
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
    fn per_peer_isolation() {
        // Distinct peers don't share a budget.
        let state = fresh_state(Duration::from_millis(100), 1);
        let now = Instant::now();
        assert!(check_against(Some(&state), peer(4), now).is_ok());
        assert!(check_against(Some(&state), peer(5), now).is_ok());
        assert!(check_against(Some(&state), peer(4), now).is_err());
        assert!(check_against(Some(&state), peer(5), now).is_err());
    }
}
