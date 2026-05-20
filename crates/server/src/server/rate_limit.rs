//! Per-peer rate limiter for `GetBackendInterfaces`.
//!
//! Closes `R3-FOLLOWUP-rate-limit`. The threat is unauthenticated TCP
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
    let _ = STATE.set(State { window, max_per_window, peers: DashMap::new() });
}

/// Check whether a peer may issue another call. Returns `Ok(())`
/// if allowed (and consumes one budget unit); `Err(retry_after)` if
/// the peer is over budget.
pub fn check(peer: IpAddr) -> Result<(), Duration> {
    let state = match STATE.get() {
        Some(s) if s.max_per_window > 0 => s,
        _ => return Ok(()),
    };
    let now = Instant::now();
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

    // Opportunistic GC: when the map has more than 1k entries, walk it
    // and drop ones that have been idle > 5 windows. Cheaper than a
    // dedicated GC task for the expected steady-state of a single-
    // digit peer set.
    if state.peers.len() > 1024 {
        let stale_after = state.window * 5;
        state.peers.retain(|_, cell| now.duration_since(cell.window_start) < stale_after);
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

    #[test]
    fn disabled_by_default() {
        // We rely on configure() not having been called by this point
        // in this test module's lifecycle. Multiple tests in this
        // module share state; we use distinct peer IPs to keep things
        // independent.
        for _ in 0..10_000 {
            check(peer(1)).unwrap();
        }
    }

    #[test]
    fn allows_within_budget_rejects_over() {
        configure(Duration::from_millis(100), 3);
        let p = peer(2);
        assert!(check(p).is_ok());
        assert!(check(p).is_ok());
        assert!(check(p).is_ok());
        let rejection = check(p).expect_err("4th call within budget should be rejected");
        assert!(rejection > Duration::ZERO);
    }
}
