//! T10 bounded daemon shutdown coordinator.
//!
//! One absolute deadline (`D = shutdown start + overall grace`) bounds the
//! whole post-signal shutdown. Phases run in order, each awaiting at most
//! `D - now`; the native domain (not this module) owns native retirement
//! and is the sole authority that may end the process over outstanding
//! native work. See `doc/release/native-mechanism-ownership.md` §"Daemon
//! shutdown coordination" for the accepted integration design.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use tokio::sync::watch;

use super::audit::{AuditShutdown, AuditSink};
use super::context_manager::ContextManager;

/// Bounded tail AFTER the overall deadline for tokio runtime teardown
/// (accepted design §"Runtime-shutdown ownership"). `main` passes this
/// to `Runtime::shutdown_timeout`: healthy shutdown leaves no running
/// workers, so expiry implies a stuck thread, which tokio leaks while
/// the process exits. Pinned at 10s — orders above healthy
/// worker-shutdown + writer close-flush latency (child tests assert
/// prompt exit far below it).
pub const SHUTDOWN_RUNTIME_TIMEOUT: Duration = Duration::from_secs(10);

/// Why shutdown was requested: an OS signal or a stuck-call trip.
/// First-wins on the shared channel; the reason is log context only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownReason {
    /// SIGINT/SIGTERM (or the test signal future).
    Signal,
    /// `max_stuck_backend_calls` tripped by the eviction loop.
    StuckCalls {
        /// Observed stuck calls at the trip.
        stuck: u64,
        /// Configured limit that was exceeded.
        limit: u64,
    },
}

/// Daemon exit failure (accepted design §"Exit-status table").
#[derive(Debug)]
pub enum ShutdownError {
    /// Config/load/bind/serve failure → exit 1.
    Startup(String),
    /// Provider `C_Finalize` error return on a backend without native
    /// uncertainty (mock/test) → exit 1. (On qualified FFI the same
    /// return makes the incarnation uncertain and the final-owner
    /// guard stop-fires 70 during unwind — the `Startup`/`Finalize`
    /// mapping never executes there.)
    Finalize(pkcs11_proxy_ng_types::CkRv),
    /// Phase-4 timeout/`JoinError` on a non-natively-bounded backend,
    /// or an unrecoverable coordinator failure → exit 2.
    Coordinator(String),
}

impl ShutdownError {
    /// Map to the process exit code (never via `std::process::exit`).
    pub fn exit_code(&self) -> std::process::ExitCode {
        match self {
            Self::Startup(_) | Self::Finalize(_) => std::process::ExitCode::from(1),
            Self::Coordinator(_) => std::process::ExitCode::from(2),
        }
    }
}

impl std::fmt::Display for ShutdownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Startup(e) => write!(f, "{e}"),
            Self::Finalize(rv) => write!(f, "C_Finalize failed: {rv}"),
            Self::Coordinator(e) => write!(f, "shutdown coordinator failed: {e}"),
        }
    }
}

impl std::error::Error for ShutdownError {}

/// Stringified failures are startup failures (config/load/bind/serve
/// surface their context as strings at the failure site).
impl From<String> for ShutdownError {
    fn from(e: String) -> Self {
        Self::Startup(e)
    }
}

impl From<std::io::Error> for ShutdownError {
    fn from(e: std::io::Error) -> Self {
        Self::Startup(e.to_string())
    }
}

/// A boxed listener serve future (tonic `serve_with_incoming_shutdown`).
pub type ServeFuture =
    Pin<Box<dyn std::future::Future<Output = Result<(), tonic::transport::Error>> + Send>>;

/// A per-listener graceful-shutdown future driven by the shared reason
/// channel. Resolves when a shutdown reason is published (or the sender
/// drops).
pub async fn listener_shutdown(mut rx: watch::Receiver<Option<ShutdownReason>>) {
    let _ = rx.wait_for(|reason| reason.is_some()).await;
}

/// Serve until the shutdown signal, then drain bounded by `grace`
/// (W1-L6-07, T10 phase 1).
///
/// The grace clock starts at **shutdown start**, not at entry: the join
/// over the serve futures races the `signal` future, and only the
/// post-signal drain runs under `timeout(grace, …)`. Pre-signal serve
/// time is unbounded (a listener that never exits and no signal means
/// the daemon keeps serving); a join that completes on its own
/// (listener error exit) propagates immediately without waiting for
/// the signal.
///
/// Returns the serve outcome (`Some` when the join finishes — either
/// before the signal or inside the post-signal grace, errors propagate
/// unchanged; `None` when the post-signal grace expires first and the
/// serve futures are dropped, aborting in-flight connections) plus the
/// shutdown-start `Instant` (signal receipt, or pre-signal completion)
/// from which the coordinator measures the overall deadline.
pub async fn serve_with_grace(
    serve_futures: Vec<ServeFuture>,
    signal: impl std::future::Future<Output = ()>,
    grace: Duration,
) -> (Option<Result<Vec<()>, tonic::transport::Error>>, Instant) {
    let mut drain = Box::pin(futures::future::try_join_all(serve_futures));
    tokio::pin!(signal);
    // Phase 1 (unbounded): serve until the listeners exit on their own
    // or the shutdown signal arrives, whichever comes first. Biased
    // toward the listener outcome so a concurrent listener error still
    // propagates as the exit cause.
    let pre_signal_outcome = tokio::select! {
        biased;
        outcome = &mut drain => Some(outcome),
        () = &mut signal => None,
    };
    // The overall-deadline clock starts here in both arms: signal
    // receipt, or pre-signal completion (shutdown starts immediately).
    let shutdown_start = Instant::now();
    // Phase 2 (bounded): only after the signal, drain under the grace.
    // (A separate step rather than a third select branch so `drain`
    // moves into the timeout cleanly once the phase-1 borrows end.)
    let outcome = match pre_signal_outcome {
        Some(outcome) => Some(outcome),
        None => match tokio::time::timeout(grace, drain).await {
            Ok(outcome) => Some(outcome),
            Err(_elapsed) => {
                tracing::error!(
                    grace_secs = grace.as_secs(),
                    "shutdown grace expired with listeners still draining; \
                     forcing shutdown (in-flight connections aborted)"
                );
                None
            }
        },
    };
    (outcome, shutdown_start)
}

/// A spawned eviction task with its cancellation channel (T10 phase 2).
pub struct EvictionTask {
    /// The ticker task; join within the remaining budget.
    pub handle: tokio::task::JoinHandle<()>,
    /// Send `true` (or drop) to stop new ticks. A tick already running
    /// finishes under its own per-call teardown timeouts; cancellation
    /// never cancels a running native call.
    pub cancel: watch::Sender<bool>,
}

/// Spawn the context-eviction ticker.
///
/// The task evicts expired contexts, logs resource pressure, and trips
/// coordinator shutdown (first-wins on `shutdown_tx`, then returns)
/// when stuck backend calls exceed `max_stuck_backend_calls` — the T10
/// lifecycle-routed replacement for the old direct `exit(70)`.
pub fn spawn_eviction_task(
    context_manager: Arc<ContextManager>,
    backend: Arc<dyn Pkcs11Backend>,
    eviction_interval: Duration,
    max_contexts: usize,
    max_concurrent_backend_calls: usize,
    max_stuck_backend_calls: Option<u64>,
    shutdown_tx: watch::Sender<Option<ShutdownReason>>,
) -> EvictionTask {
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(eviction_interval);
        loop {
            tokio::select! {
                _ = cancel_rx.changed() => break,
                _ = interval.tick() => {}
            }
            let expired = context_manager.evict_expired(&backend).await;
            if !expired.is_empty() {
                tracing::info!(count = expired.len(), "Evicted expired contexts");
            }

            // Resource-aware logging
            let ctx_count = context_manager.context_count();
            if max_contexts > 0 && ctx_count > max_contexts * 80 / 100 {
                tracing::warn!(contexts = ctx_count, max = max_contexts, "context usage above 80%");
            }
            let in_flight = super::grpc_service::service_utils::backend_in_flight();
            if in_flight > max_concurrent_backend_calls * 80 / 100 {
                tracing::warn!(
                    in_flight,
                    max = max_concurrent_backend_calls,
                    "backend call usage above 80%"
                );
            }

            // Opt-in fail-fast: a token wedged past the configured stuck-call
            // limit is a permanent condition the daemon can only escape via a
            // supervisor restart. Request coordinator shutdown (T10: no direct
            // exit — the coordinator runs seal/drain/deadline and the native
            // controller owns the stop) and end this task; the coordinator
            // joins it already complete.
            let stuck = super::grpc_service::service_utils::stuck_backend_calls();
            if stuck > 0 {
                tracing::warn!(stuck_calls = stuck, "backend calls wedged past their timeout");
            }
            if crate::config::should_exit_on_stuck_calls(stuck as u64, max_stuck_backend_calls) {
                let limit = max_stuck_backend_calls.unwrap_or(u64::MAX);
                tracing::error!(
                    stuck_calls = stuck,
                    limit = max_stuck_backend_calls,
                    "stuck backend calls exceeded proxy.max_stuck_backend_calls; \
                     requesting shutdown for supervisor restart"
                );
                // `send_modify` returns `()` (no receivers is not an error
                // for a `watch` broadcast), so no `let _` binding.
                shutdown_tx.send_modify(|reason| {
                    if reason.is_none() {
                        *reason = Some(ShutdownReason::StuckCalls { stuck: stuck as u64, limit });
                    }
                });
                break;
            }
        }
    });
    EvictionTask { handle, cancel: cancel_tx }
}

/// Remaining overall budget from the absolute deadline (saturating).
fn remaining_until(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// T10 bounded shutdown coordinator.
///
/// Runs phases 1–4 against the single overall deadline `D =
/// shutdown start + overall_grace` (each phase awaits at most `D -
/// now`): listener drain → eviction stop/join → audit completion →
/// native retirement. `svc` (the service stack holding an audit sender)
/// is dropped before the audit join; `unix_socket_path` (if any) is
/// removed right after the drain so a restart can rebind. Phase 4
/// always runs, exactly once.
///
/// Returns `Ok` on orderly shutdown or [`ShutdownError`] per the
/// exit-status table. On qualified FFI with unresolved native work the
/// function never returns — the native controller ends the process.
pub async fn coordinate_shutdown<S>(
    serve_futures: Vec<ServeFuture>,
    signal: impl std::future::Future<Output = ()>,
    svc: S,
    eviction: EvictionTask,
    audit: Option<(AuditSink, AuditShutdown)>,
    backend: Arc<dyn Pkcs11Backend>,
    unix_socket_path: Option<PathBuf>,
    overall_grace: Duration,
) -> Result<(), ShutdownError> {
    // Phase 1: drain under the full grace (its clock starts at shutdown
    // start, which IS the overall deadline's origin).
    let (serve_result, shutdown_start) =
        serve_with_grace(serve_futures, signal, overall_grace).await;
    let deadline = shutdown_start + overall_grace;

    // Post-drain: free the Unix path for a restart (the fd stays valid).
    if let Some(path) = unix_socket_path {
        let _ = std::fs::remove_file(&path);
    }

    // A serve error is carried through the remaining phases (the backend
    // must still retire) and reported if nothing worse happened.
    let mut serve_error: Option<String> = None;
    if let Some(Err(e)) = serve_result {
        serve_error = Some(format!("serve failed: {e}"));
    }

    // Phase 2: stop new ticks, join the ticker within the remainder.
    // The send is sync (always performed); a joining tick is itself
    // bounded by per-call teardown timeouts. On join expiry the
    // coordinator proceeds; the tick's workers hold their guards into
    // the phase-4 seal/drain.
    let _ = eviction.cancel.send(true);
    match tokio::time::timeout(remaining_until(deadline), eviction.handle).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) if e.is_panic() => {
            tracing::error!("eviction task panicked during shutdown: {e}");
        }
        Ok(Err(e)) => {
            tracing::error!("eviction task failed during shutdown: {e}");
        }
        Err(_) => {
            tracing::error!("eviction join expired; proceeding to audit/finalize");
        }
    }

    // Phase 3: drop the service (releases its audit sender: no handler
    // can emit past this point — phase 1 drained or aborted them all),
    // then bounded audit completion. Every failure logs and proceeds.
    drop(svc);
    if let Some((sink, shutdown)) = audit
        && let Err(e) = shutdown.shutdown(sink, remaining_until(deadline)).await
    {
        tracing::error!(error = %e, "audit shutdown on daemon stop failed");
    }

    // Phase 4: native retirement. ALWAYS runs, exactly once, on a
    // blocking worker. No coordinator logging on the qualified wait
    // itself: past `D` with native outstanding the only correct action
    // is silent awaiting (the controller owns the stop).
    let remaining = remaining_until(deadline);
    let worker_backend = backend.clone();
    let worker = tokio::task::spawn_blocking(move || worker_backend.finalize_with_grace(remaining));
    if backend.finalize_is_natively_bounded() {
        match worker.await {
            Ok(Ok(())) => {}
            Ok(Err(rv)) => {
                // Provider error return: the incarnation is now uncertain
                // (`abandon_finalize`) and `retirement_decision` is Poison,
                // so the final-owner guard stop-fires 70 when the last
                // backend Arc drops during unwind — the DESIGNED path. The
                // mapping below never executes there.
                tracing::error!(error = %rv, "C_Finalize failed; backend drop follows");
                return Err(ShutdownError::Finalize(rv));
            }
            Err(e) => {
                // Worker panic: poison or initialized-without-fresh-
                // finalize both read Poison → guard backstop fires 70.
                tracing::error!("finalize worker failed during shutdown: {e}");
                return Err(ShutdownError::Coordinator(format!("finalize worker failed: {e}")));
            }
        }
    } else {
        match tokio::time::timeout(remaining, worker).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(rv))) => {
                tracing::error!(error = %rv, "C_Finalize failed; backend drop follows");
                return Err(ShutdownError::Finalize(rv));
            }
            Ok(Err(e)) => {
                return Err(ShutdownError::Coordinator(format!("finalize worker failed: {e}")));
            }
            Err(_) => {
                // The parked worker is detached; runtime shutdown leaks it
                // (child-contained in tests) and the process exits 2.
                return Err(ShutdownError::Coordinator(format!(
                    "finalize timed out after {remaining:?}"
                )));
            }
        }
    }

    // Orderly retirement; a carried serve error still fails the exit.
    if let Some(e) = serve_error {
        return Err(ShutdownError::Startup(e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// W1-L6-07: listeners that exit on their own (pre-signal) return
    /// their `try_join_all` outcome unchanged, without waiting for the
    /// signal.
    #[tokio::test]
    async fn serve_with_grace_returns_outcome_when_drained_in_time() {
        let futures: Vec<ServeFuture> =
            vec![Box::pin(async { Ok(()) }), Box::pin(async { Ok(()) })];
        let (outcome, _start) =
            serve_with_grace(futures, std::future::pending(), Duration::from_secs(30)).await;
        assert!(matches!(outcome, Some(Ok(_))), "drained listeners must propagate Ok");
    }

    /// W1-L6-07: after the signal, a wedged listener (never resolves)
    /// must not pin SIGTERM forever — the grace bounds the post-signal
    /// drain, then the serve futures are dropped (aborting in-flight
    /// connections) and shutdown proceeds.
    #[tokio::test]
    async fn serve_with_grace_bounds_a_wedged_listener() {
        let futures: Vec<ServeFuture> =
            vec![Box::pin(async { Ok(()) }), Box::pin(std::future::pending())];
        let start = Instant::now();
        let (outcome, _shutdown_start) =
            serve_with_grace(futures, std::future::ready(()), Duration::from_millis(50)).await;
        assert!(outcome.is_none(), "wedged listeners must time out to forced shutdown");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "grace wait must be bounded, took {:?}",
            start.elapsed()
        );
    }

    /// W1-L6-07: a pre-signal serve error propagates immediately (the
    /// daemon must exit on listener failure without waiting for a
    /// signal that may never come).
    #[tokio::test]
    async fn serve_with_grace_propagates_serve_errors() {
        // try_join_all short-circuits on the first error; a ready error
        // must surface even with ample grace left. (A malformed endpoint
        // URI is the cheapest way to fabricate a transport::Error.)
        let err = tonic::transport::Endpoint::from_shared("http://exa mple.com").unwrap_err();
        let futures: Vec<ServeFuture> = vec![Box::pin(async move { Err(err) })];
        let (outcome, _start) =
            serve_with_grace(futures, std::future::pending(), Duration::from_secs(30)).await;
        assert!(matches!(outcome, Some(Err(_))), "serve errors must propagate");
    }

    /// W1-L6-07 fix round: the grace clock must start at signal receipt,
    /// not at startup. With no signal and no listener exit, the helper
    /// stays pending far past the grace (pre-signal serve time is
    /// unbounded) — the daemon must not force-exit `grace` after boot.
    #[tokio::test]
    async fn serve_with_grace_does_not_bound_pre_signal_uptime() {
        let futures: Vec<ServeFuture> = vec![Box::pin(std::future::pending())];
        let outcome = tokio::time::timeout(
            Duration::from_millis(500),
            serve_with_grace(futures, std::future::pending(), Duration::from_millis(50)),
        )
        .await;
        assert!(
            outcome.is_err(),
            "pre-signal serve must stay pending past the grace (10x overrun)"
        );
    }

    /// W1-L6-07 fix round: post-signal drain obeys the grace the other
    /// way — a drain that finishes inside the grace returns its outcome
    /// (the wedged-listener test above pins the expiry way).
    #[tokio::test]
    async fn serve_with_grace_returns_post_signal_drain_outcome() {
        let (tx, mut signal_rx) = watch::channel(false);
        let mut serve_rx = tx.subscribe();
        // Signal future: resolves when the "SIGTERM" flips the channel.
        let signal = async move {
            let _ = signal_rx.changed().await;
        };
        // Serve future: drains only after the signal, then succeeds
        // inside the grace.
        let serve: ServeFuture = Box::pin(async move {
            let _ = serve_rx.changed().await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(())
        });
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = tx.send(true);
        });
        let (outcome, _start) = serve_with_grace(vec![serve], signal, Duration::from_secs(5)).await;
        assert!(
            matches!(outcome, Some(Ok(_))),
            "post-signal drain inside the grace must propagate Ok"
        );
    }

    /// T10: eviction cancellation is responsive — no new ticks after
    /// cancel, and the retained handle joins promptly (the phase-2
    /// contract; the child `wedge_eviction` covers the join-expiry
    /// half).
    #[tokio::test]
    async fn eviction_cancel_stops_ticks_and_joins_promptly() {
        use pkcs11_proxy_ng_backend::MockBackend;

        let backend = Arc::new(MockBackend::default_test());
        backend.initialize().unwrap();
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        let (shutdown_tx, _rx) = watch::channel(None::<ShutdownReason>);
        let task = spawn_eviction_task(
            ctx_mgr,
            backend,
            Duration::from_millis(10),
            1024,
            64,
            None,
            shutdown_tx,
        );
        // Let several fast no-op ticks fire, then cancel: the task must
        // end (not tick again), and the join must complete promptly.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = task.cancel.send(true);
        tokio::time::timeout(Duration::from_secs(5), task.handle)
            .await
            .expect("cancelled eviction task must join promptly")
            .expect("eviction task must not panic");
    }

    /// T10: the reported shutdown-start instant is the signal receipt
    /// (not entry, not drain end), so the coordinator's overall
    /// deadline shares the drain's clock origin exactly.
    #[tokio::test]
    async fn serve_with_grace_reports_signal_receipt_as_origin() {
        // Listeners already drained; the signal resolves after 100ms; the
        // reported origin must be ≈100ms after entry, not ≈entry.
        let entered = Instant::now();
        let (_tx, rx) = watch::channel(None::<ShutdownReason>);
        let signal = async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(rx);
        };
        let futures: Vec<ServeFuture> = vec![Box::pin(std::future::pending())];
        let (_outcome, origin) =
            serve_with_grace(futures, signal, Duration::from_millis(300)).await;
        let skew = origin.saturating_duration_since(entered);
        assert!(
            skew >= Duration::from_millis(100),
            "origin must be signal receipt, not entry (skew {skew:?})"
        );
        assert!(
            skew < Duration::from_secs(2),
            "origin must not drift past the signal (skew {skew:?})"
        );
    }
}
