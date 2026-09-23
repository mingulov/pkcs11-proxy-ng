use crate::server::slot_map::{BackendSlotId, VirtualSlotId};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::mpsc;
use tonic::Status;

use pkcs11_proxy_ng_types::*;

use super::super::auth::identity::AuthenticatedIdentity;
use super::super::context_manager::{
    ClientContextId, ContextManager, LoginState, ObjectMetadata, OperationGuard,
};
use super::super::handle_map::{BackendHandle, VirtualHandle};
use super::HandlerContext;

mod exact_completion;
pub(super) use exact_completion::{ExactCompletion, spawn_backend_exact};

/// Global backend-call budget shared by all tenants (W1-L15-30): one noisy
/// tenant can fill the budget and trip `CKR_HOST_MEMORY` for co-tenants.
/// Accepted blast radius (ADR-0012): per-context (M2) and per-connection
/// (W1-L7-28) quarter-budget caps bound a single tenant, and stuck slots free
/// when the backend returns; per-tenant backend partitioning is out of scope.
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static BACKEND_TIMEOUT: OnceLock<Duration> = OnceLock::new();
static MAX_BACKEND_CALLS: OnceLock<usize> = OnceLock::new();
static LOGIN_LOCK_TIMEOUT: OnceLock<Duration> = OnceLock::new();
static HEALTH_EVENT_TX: OnceLock<mpsc::Sender<BackendHealthEvent>> = OnceLock::new();
/// In-flight backend calls per TCP peer address (W1-L7-28): the
/// per-connection admission budget under the global `IN_FLIGHT`
/// breaker. Entries are removed when their count drains to zero, so
/// the table stays bounded by the number of connections with
/// in-flight backend calls.
static PEER_IN_FLIGHT: LazyLock<DashMap<SocketAddr, Arc<AtomicUsize>>> =
    LazyLock::new(DashMap::new);

tokio::task_local! {
    static CONTEXT_OPERATION_GUARD: Option<OperationGuard>;
}

tokio::task_local! {
    /// This request's TCP peer address (W1-L7-28), published by
    /// `run_context_scoped` from `request.remote_addr()`. `None` on UDS
    /// (no peer address) and wherever dispatch did not publish one —
    /// those calls run unadmitted under the global breaker only.
    static CURRENT_PEER: Option<SocketAddr>;
}

/// Scope one already-admitted context operation around a service handler.
/// Backend tasks clone the same guard, so a timeout cannot make the context
/// reapable while its blocking provider call is still running.
pub(super) async fn scope_context_operation<T, F>(guard: Option<OperationGuard>, future: F) -> T
where
    F: Future<Output = T>,
{
    CONTEXT_OPERATION_GUARD.scope(guard, future).await
}

pub(super) fn current_context_operation_guard() -> Option<OperationGuard> {
    CONTEXT_OPERATION_GUARD.try_with(|guard| guard.clone()).ok().flatten()
}

/// Publish this request's peer address around a service handler (W1-L7-28).
pub(super) async fn scope_peer_admission<T, F>(peer: Option<SocketAddr>, future: F) -> T
where
    F: Future<Output = T>,
{
    CURRENT_PEER.scope(peer, future).await
}

pub(super) fn current_peer() -> Option<SocketAddr> {
    CURRENT_PEER.try_with(|peer| *peer).ok().flatten()
}

/// Derive the per-principal quota key (W1-L7-02), shared by the
/// in-flight guard and the session quota so both caps key identically:
/// the bound transport identity when one is recorded; otherwise the
/// TCP peer IP from [`current_peer`] (published by
/// `run_context_scoped` for every RPC) so N contexts from one peer
/// cannot multiply the opt-in caps; otherwise (UDS / unpublished
/// transport — no IP exists) the context id, as before.
pub(super) fn principal_quota_key(ctx_mgr: &ContextManager, ctx_id: &ClientContextId) -> String {
    if let Some(identity) = ctx_mgr.context_identity(ctx_id) {
        return identity;
    }
    if let Some(peer) = current_peer() {
        return peer.ip().to_string();
    }
    ctx_id.0.clone()
}
/// Tracks whether the LAST sent health event was `Success`. Initialized
/// to `true` because the health-gate task assumes the daemon starts in
/// `SERVING`. Used by [`report_backend_outcome`] to suppress
/// successive `Success` events — the gate only needs the first
/// `Success` after a `Failure` streak to reset its counter, so a
/// per-RPC `Success` push at the data-plane rate is pure noise.
static LAST_SENT_HEALTHY: AtomicBool = AtomicBool::new(true);

/// Outcome reported by [`spawn_backend`] for the health-gating task
/// in `main.rs` to consume. `Success` = backend produced any
/// completed application-level outcome; `Failure` = transport failure
/// (timeout, blocking-pool panic, circuit-breaker trip) or an established
/// provider-down RV (DEVICE_REMOVED/HOST_MEMORY). Exact pre-native rejection
/// emits neither event, so it cannot degrade readiness or signal recovery.
#[derive(Debug, Clone, Copy)]
pub enum BackendHealthEvent {
    Success,
    Failure,
}

/// Called once at server startup to configure the backend guard.
pub fn configure_backend_guard(timeout_secs: u64, max_calls: usize) {
    BACKEND_TIMEOUT.set(Duration::from_secs(timeout_secs)).ok();
    MAX_BACKEND_CALLS.set(max_calls).ok();
}

/// Called once at server startup to configure the per-slot login-lock
/// acquisition timeout (cross-tenant DoS bound).
pub fn configure_login_lock_timeout(secs: u64) {
    LOGIN_LOCK_TIMEOUT.set(Duration::from_secs(secs)).ok();
}

/// Returns the configured login-lock acquisition timeout.
/// Falls back to 10 seconds if `configure_login_lock_timeout` was never called.
pub fn login_lock_timeout() -> Duration {
    *LOGIN_LOCK_TIMEOUT.get().unwrap_or(&Duration::from_secs(10))
}

/// Bounded per-slot login-lock acquisition (W1-L11-07, G2/V11): serialize
/// login/logout on a slot, refusing with `CKR_GENERAL_ERROR` (W1-L3-01:
/// proxy serialization refusal, backend untouched) rather than queueing
/// unboundedly when a slow/wedged backend pins the lock. One acquisition
/// site shared by login and logout; the caller must hold the returned
/// guard across its critical section. `OwnedMutexGuard` (not the borrowed
/// guard) so the lock can be acquired inside this helper.
pub(super) async fn acquire_slot_login_lock(
    ctx_mgr: &Arc<ContextManager>,
    slot: BackendSlotId,
) -> Result<tokio::sync::OwnedMutexGuard<()>, CkRv> {
    let login_guard = ctx_mgr.slot_login_lock(slot);
    match tokio::time::timeout(login_lock_timeout(), login_guard.lock_owned()).await {
        Ok(guard) => Ok(guard),
        Err(_elapsed) => {
            // Another tenant holds the per-slot login lock past the configured
            // bound (slow/wedged backend login on the shared token). Refuse
            // rather than queue unboundedly; CKR_GENERAL_ERROR is a transient
            // proxy-serialization failure the client can retry (W1-L3-01:
            // distinct from the backend DEVICE_ERROR catch-all).
            Err(CkRv::GENERAL_ERROR)
        }
    }
}

/// Wire up the channel that `spawn_backend` uses to report outcomes
/// to the health-gating task. Called once at startup. If never called,
/// backend outcomes are silently dropped — health gating is disabled
/// and `tonic-health` stays at whatever startup last set it to.
pub fn configure_backend_health_events(tx: mpsc::Sender<BackendHealthEvent>) {
    HEALTH_EVENT_TX.set(tx).ok();
}

fn report_backend_outcome(success: bool) {
    let Some(tx) = HEALTH_EVENT_TX.get() else { return };
    // The channel is BOUNDED (L11): use non-blocking try_send from this sync
    // data-plane path. Dropping on a full buffer is safe — Success events are
    // already coalesced to unhealthy->healthy transitions (rare; the buffer is
    // draining by then), and a dropped Failure is harmless because a full buffer
    // already holds far more consecutive failures than the gate's flip threshold.
    if success {
        // Only signal Success on a transition from a previously-unhealthy state:
        // the gate uses it solely to reset its consecutive-failure counter, so
        // repeated successes are noise on every data-plane RPC.
        if !LAST_SENT_HEALTHY.swap(true, Ordering::Relaxed) {
            let _ = tx.try_send(BackendHealthEvent::Success);
        }
    } else {
        LAST_SENT_HEALTHY.store(false, Ordering::Relaxed);
        let _ = tx.try_send(BackendHealthEvent::Failure);
    }
}

fn backend_timeout() -> Duration {
    *BACKEND_TIMEOUT.get().unwrap_or(&Duration::from_secs(30))
}

fn max_concurrent_backend_calls() -> usize {
    *MAX_BACKEND_CALLS.get().unwrap_or(&200)
}

/// Per-context in-flight cap: a quarter of the global backend-call budget (at
/// least 1). Under the global circuit breaker, this stops a single noisy logical
/// client from draining the whole budget and tipping every other tenant into
/// HOST_MEMORY (M2). Scales with the configured global limit.
pub(super) fn per_context_max_in_flight() -> usize {
    (max_concurrent_backend_calls() / 4).max(1)
}

/// Per-connection in-flight cap (W1-L7-28): a quarter of the global
/// backend-call budget (at least 1), mirroring the per-context M2
/// fraction. Under the global circuit breaker, this stops a single
/// connection from draining the whole budget and tipping every other
/// tenant into HOST_MEMORY. Scales with the configured global limit.
pub(super) fn per_connection_max_in_flight() -> usize {
    (max_concurrent_backend_calls() / 4).max(1)
}

/// Number of live per-peer admission entries (W1-L7-28 tests only).
#[cfg(test)]
pub(super) fn peer_admission_table_size_for_test() -> usize {
    PEER_IN_FLIGHT.len()
}

/// Current number of in-flight backend calls (for health checks / metrics).
pub fn backend_in_flight() -> usize {
    IN_FLIGHT.load(Ordering::Relaxed)
}

/// Calls that outlived their timeout and have not yet returned from the
/// backend — the "token wedged" signal, as opposed to plain overload
/// (see `backend_in_flight`). Incremented when a call's timeout fires;
/// decremented if/when the stuck FFI call finally returns.
static STUCK_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Current number of timed-out-but-still-running backend calls.
pub fn stuck_backend_calls() -> usize {
    STUCK_CALLS.load(Ordering::Relaxed)
}

pub(super) async fn spawn_task<T, F>(operation: F) -> Result<T, Status>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| Status::internal(format!("spawn_blocking panic: {error}")))
}

/// RAII guard that decrements an in-flight backend-call counter on drop.
///
/// This ensures the counter is decremented even if the gRPC handler's Future
/// is cancelled by tonic's server-level timeout. Without this guard, a race
/// between tonic's timeout and `spawn_backend`'s internal timeout can leak
/// IN_FLIGHT counts, eventually latching the circuit breaker.
struct InFlightGuard {
    counter: &'static AtomicUsize,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Exactly-once stuck-call accounting (T08, R-H1).
///
/// A backend call counts as stuck from the timeout branch's publication
/// until the blocking task actually finishes. The old
/// `fetch_add`-then-`store` handshake leaked +1 whenever the FFI
/// returned in between; the timeout and completion sides now rendezvous
/// on one mutex over three states, so every interleaving balances:
///
/// * `Running → TimedOut` (timeout branch): increments the gauge.
/// * `TimedOut → Completed` (task completion guard): decrements it.
/// * `Running → Completed` (fast completion): no gauge movement.
/// * `Completed → Completed` (redundant completion): no-op.
///
/// No backend operation runs under the lock — only the state flip and
/// the gauge update — so this cannot wedge a call. A poisoned mutex
/// (unreachable in practice: the critical section cannot panic)
/// recovers via `into_inner` like the shim's lock helpers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StuckCallState {
    Running,
    TimedOut,
    Completed,
}

struct StuckCallAccounting<'a> {
    gauge: &'a AtomicUsize,
    state: Mutex<StuckCallState>,
}

impl<'a> StuckCallAccounting<'a> {
    fn new(gauge: &'a AtomicUsize) -> Self {
        Self { gauge, state: Mutex::new(StuckCallState::Running) }
    }

    /// Publish the timeout. Returns the gauge value after publication
    /// (the live stuck count for the timeout log line). If the task
    /// already completed (`Running → Completed` won the race), the call
    /// is already accounted and nothing is published.
    fn timeout(&self) -> usize {
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        if *state == StuckCallState::Running {
            *state = StuckCallState::TimedOut;
            self.gauge.fetch_add(1, Ordering::Relaxed) + 1
        } else {
            self.gauge.load(Ordering::Relaxed)
        }
    }

    /// Mark the backend call finished. Returns the remaining stuck count
    /// when this call releases a published stuck slot, `None` otherwise.
    /// Idempotent: only the `TimedOut → Completed` transition decrements,
    /// so the gauge can neither leak +1 nor underflow.
    fn complete(&self) -> Option<usize> {
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        match *state {
            StuckCallState::TimedOut => {
                *state = StuckCallState::Completed;
                Some(self.gauge.fetch_sub(1, Ordering::Relaxed) - 1)
            }
            StuckCallState::Running => {
                *state = StuckCallState::Completed;
                None
            }
            StuckCallState::Completed => None,
        }
    }
}

/// Drops when the blocking task ends — normal return, panic unwind, or
/// post-cancellation completion — releasing exactly one stuck slot iff
/// the timeout branch published one. Caller cancellation alone never
/// touches the gauge: it drops the timeout future (no `timeout()` call)
/// while the task still runs, and the later `complete()` observes
/// `Running → Completed`.
struct StuckCallCompletionGuard<'a> {
    accounting: Arc<StuckCallAccounting<'a>>,
}

impl Drop for StuckCallCompletionGuard<'_> {
    fn drop(&mut self) {
        if let Some(remaining) = self.accounting.complete() {
            tracing::info!(
                stuck_calls = remaining,
                "a previously stuck backend call returned; slot released"
            );
        }
    }
}

fn try_acquire_backend_call(
    counter: &'static AtomicUsize,
    max_calls: usize,
) -> Option<InFlightGuard> {
    let mut current = counter.load(Ordering::Relaxed);

    loop {
        if current >= max_calls {
            return None;
        }

        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Some(InFlightGuard { counter }),
            Err(actual) => current = actual,
        }
    }
}

/// RAII slot for one peer's admission budget (W1-L7-28). Moved into the
/// blocking task alongside the global [`InFlightGuard`] so the peer slot
/// is held for the TRUE backend-call lifetime; on drop the count
/// decrements and a drained entry is removed (bounded table).
struct PeerAdmissionGuard {
    peer: SocketAddr,
    counter: Arc<AtomicUsize>,
}

impl Drop for PeerAdmissionGuard {
    fn drop(&mut self) {
        let previous = self.counter.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(previous >= 1, "peer admission count must not underflow");
        if previous == 1 {
            // Last slot released: remove the entry so the table cannot
            // grow with stale peers. The predicate re-checks under the
            // shard lock — a racing admission (count back above zero, or
            // a recycled Arc) keeps the entry.
            let mine = Arc::clone(&self.counter);
            PEER_IN_FLIGHT.remove_if(&self.peer, |_, count| {
                Arc::ptr_eq(count, &mine) && count.load(Ordering::Relaxed) == 0
            });
        }
    }
}

/// Admit one backend call for `peer` under `max_in_flight` (W1-L7-28).
/// CAS-exact like the global acquire; `None` when the peer is at cap.
fn try_admit_peer(peer: SocketAddr, max_in_flight: usize) -> Option<PeerAdmissionGuard> {
    let counter =
        PEER_IN_FLIGHT.entry(peer).or_insert_with(|| Arc::new(AtomicUsize::new(0))).clone();
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current >= max_in_flight {
            return None;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Some(PeerAdmissionGuard { peer, counter }),
            Err(actual) => current = actual,
        }
    }
}

pub(super) async fn spawn_backend<T, F>(operation: F) -> Result<CkResult<T>, Status>
where
    T: Send + 'static,
    F: FnOnce() -> CkResult<T> + Send + 'static,
{
    spawn_backend_core(
        &IN_FLIGHT,
        &STUCK_CALLS,
        backend_timeout(),
        max_concurrent_backend_calls(),
        operation,
    )
    .await
}

/// Testable variant of [`spawn_backend`] with an explicit timeout.  It uses
/// the same breaker/completion machinery; production callers use the
/// configured timeout through `spawn_backend`. Also used by
/// `context_manager` eviction teardown (W1-C2-03) so a wedged backend
/// cannot stall lease reaping.
pub(crate) async fn spawn_backend_with_timeout<T, F>(
    timeout: Duration,
    operation: F,
) -> Result<CkResult<T>, Status>
where
    T: Send + 'static,
    F: FnOnce() -> CkResult<T> + Send + 'static,
{
    spawn_backend_core(&IN_FLIGHT, &STUCK_CALLS, timeout, max_concurrent_backend_calls(), operation)
        .await
}

/// Testable variant of [`spawn_backend_with_timeout`] with explicit
/// breaker/stuck counters. Tests asserting exact stuck deltas must not
/// use the global gauges: concurrent suite tests move them, which makes
/// exact-delta asserts racy (and a failure there can strand a parked
/// backend thread — see the session hang-guard tests).
#[cfg(test)]
pub(super) async fn spawn_backend_with_counters<T, F>(
    counter: &'static AtomicUsize,
    stuck_gauge: &'static AtomicUsize,
    timeout: Duration,
    max_calls: usize,
    operation: F,
) -> Result<CkResult<T>, Status>
where
    T: Send + 'static,
    F: FnOnce() -> CkResult<T> + Send + 'static,
{
    spawn_backend_core(counter, stuck_gauge, timeout, max_calls, operation).await
}

pub(super) async fn spawn_backend_with_optional_timeout<T, F>(
    timeout: Option<Duration>,
    operation: F,
) -> Result<CkResult<T>, Status>
where
    T: Send + 'static,
    F: FnOnce() -> CkResult<T> + Send + 'static,
{
    match timeout {
        Some(timeout) => spawn_backend_with_timeout(timeout, operation).await,
        None => spawn_backend(operation).await,
    }
}

/// Timeout/breaker core of [`spawn_backend`], parameterized for tests.
///
/// The in-flight guard travels INTO the blocking task and drops when the
/// FFI call actually returns — not when the caller's timeout fires. A
/// wedged token therefore keeps its breaker slot: accumulated stuck calls
/// trip the breaker (bounding leaked blocking threads at `max_calls`
/// instead of the runtime's thread cap), and if the token later unsticks,
/// the slots free and the daemon self-recovers without a restart.
async fn spawn_backend_core<T, F>(
    counter: &'static AtomicUsize,
    stuck_gauge: &'static AtomicUsize,
    timeout: Duration,
    max_calls: usize,
    operation: F,
) -> Result<CkResult<T>, Status>
where
    T: Send + 'static,
    F: FnOnce() -> CkResult<T> + Send + 'static,
{
    spawn_backend_core_classified(counter, stuck_gauge, timeout, max_calls, operation, |result| {
        Some(classify_backend_outcome(result))
    })
    .await
}

async fn spawn_backend_core_classified<T, F, C>(
    counter: &'static AtomicUsize,
    stuck_gauge: &'static AtomicUsize,
    timeout: Duration,
    max_calls: usize,
    operation: F,
    classify: C,
) -> Result<CkResult<T>, Status>
where
    T: Send + 'static,
    F: FnOnce() -> CkResult<T> + Send + 'static,
    C: FnOnce(&Result<CkResult<T>, Status>) -> Option<bool>,
{
    // Circuit breaker
    let Some(guard) = try_acquire_backend_call(counter, max_calls) else {
        let current = counter.load(Ordering::Relaxed);
        tracing::error!(
            in_flight = current,
            max = max_calls,
            "Backend circuit breaker tripped — too many in-flight calls"
        );
        // A flood of breaker trips means the daemon is overloaded (or the
        // backend is wedged and every slot is held by a stuck call) and
        // downstream traffic should be diverted — count as a failure
        // for the health gate. Caller-visible CKR_HOST_MEMORY (W1-L3-01):
        // the daemon cannot accept more work; the backend was untouched.
        report_backend_outcome(false);
        return Ok(Err(CkRv::HOST_MEMORY));
    };
    // W1-L7-28: per-connection admission UNDER the global breaker, after
    // the global slot is held (a peer rejection below drops it again).
    // One connection cannot exhaust the shared budget. Distinct layer
    // from the L6-20 transport knobs (which bound buffering) and the
    // per-context M2 cap (which binds earlier for single-context
    // connections). No health event on rejection: a per-peer trip
    // reflects one noisy client and must not flip daemon readiness (M1).
    let peer_guard = match current_peer() {
        Some(peer) => match try_admit_peer(peer, per_connection_max_in_flight()) {
            Some(guard) => Some(guard),
            None => {
                tracing::warn!(
                    peer = %peer,
                    max = per_connection_max_in_flight(),
                    "per-connection backend-call budget exhausted — rejecting"
                );
                // Same breaker class as the global trip above (W1-L3-01).
                return Ok(Err(CkRv::HOST_MEMORY));
            }
        },
        // UDS / unpublished transport: global breaker only.
        None => None,
    };
    let context_operation_guard = current_context_operation_guard();

    // Exactly-once stuck accounting (T08): the mutex inside serializes
    // the timeout branch below against the task's completion guard, so a
    // return racing the timeout can neither leak +1 nor decrement a gauge
    // that was never incremented.
    let accounting = Arc::new(StuckCallAccounting::new(stuck_gauge));
    let accounting_task = Arc::clone(&accounting);
    let task = spawn_task(move || {
        // Hold the slot for the TRUE lifetime of the backend call: a
        // blocking task always runs to completion, so the guard drops
        // exactly when the FFI returns (even if the caller timed out or
        // the gRPC future was cancelled long before).
        let _guard = guard;
        let _peer_guard = peer_guard;
        let _context_operation_guard = context_operation_guard;
        // Completion ownership lives INSIDE the blocking closure: the
        // guard drops exactly when the FFI returns — including on panic
        // unwind and after caller cancellation — balancing any timeout
        // publication. Breaker/peer/context guards keep their true
        // lifetimes: caller cancellation releases none of them.
        let _completion = StuckCallCompletionGuard { accounting: accounting_task };
        operation()
    });

    let result = match tokio::time::timeout(timeout, task).await {
        Ok(result) => result,
        Err(_elapsed) => {
            let stuck = accounting.timeout();
            tracing::warn!(
                timeout_secs = timeout.as_secs(),
                in_flight = counter.load(Ordering::Relaxed),
                stuck_calls = stuck,
                "Backend call timed out; its breaker slot stays held until the \
                 backend returns. Consider increasing proxy.request_timeout_secs \
                 or investigating HSM responsiveness."
            );
            // A timeout is a transport-level failure of the daemon's own making.
            // Report it to the readiness gauge HERE, then return early, so the
            // ck_rv classifier never sees this proxy-generated FUNCTION_FAILED
            // and can treat a backend-RETURNED DEVICE_ERROR as a per-request
            // response rather than a daemon-health signal (M1). The timeout RV
            // is FUNCTION_FAILED (W1-L3-01): outcome-ambiguous, the backend
            // call may still complete — matching the client-side mapping of a
            // gRPC DeadlineExceeded (ADR-0003 §3).
            report_backend_outcome(false);
            return Ok(Err(CkRv::FUNCTION_FAILED));
        }
    };

    if let Some(healthy) = classify(&result) {
        tracing::debug!(healthy, "backend outcome classified");
        report_backend_outcome(healthy);
    }

    result
}

/// Classify a `spawn_backend` result as healthy (true) or unhealthy
/// (false) from the daemon-level readiness gauge's perspective.
///
/// Transport failures are classified separately from provider responses:
///   * timeouts (reported before returning proxy-generated FUNCTION_FAILED),
///   * `spawn_blocking` panics (`Err(Status)`),
///   * circuit-breaker trips (also `Ok(Err(..))` — `CKR_HOST_MEMORY`,
///     reported separately by `spawn_backend` before this function is
///     called).
///
/// Native DEVICE_REMOVED/HOST_MEMORY also retain their provider-down meaning.
/// Other PKCS#11 application errors (CKR_PIN_INCORRECT, CKR_DATA_INVALID,
/// CKR_MECHANISM_INVALID, …) are normal client-side outcomes; they
/// must NOT trip the readiness gauge, or a noisy authentication user
/// could take the daemon out of the load-balancer rotation.
///
/// Extracted as a pure function so the contract is testable without
/// the global `HEALTH_EVENT_TX` channel state.
fn provider_rv_is_healthy(rv: CkRv) -> bool {
    rv != CkRv::DEVICE_REMOVED && rv != CkRv::HOST_MEMORY
}

fn classify_backend_outcome<T>(result: &Result<CkResult<T>, Status>) -> bool {
    match result {
        Ok(Ok(_)) => true,
        // Genuine backend/HSM-down signals: the device reports that it is gone
        // or out of memory. A single client's request shape cannot induce these,
        // so repeated occurrences remain a daemon-readiness signal.
        Ok(Err(rv)) if !provider_rv_is_healthy(*rv) => {
            tracing::debug!(?rv, "backend outcome: unhealthy");
            false
        }
        // Any OTHER backend-RETURNED CK_RV is a per-request response, NOT daemon
        // health — including the `CKR_DEVICE_ERROR` catch-all (kryoptic & other
        // backends return it for many request-specific conditions) and
        // `CKR_TOKEN_NOT_PRESENT`. Letting these flip readiness would let one
        // noisy client evict the pod for every tenant (M1). The daemon's own
        // transport failures — timeout, circuit-breaker trip, blocking-pool
        // panic — are reported separately and are the only request-path inputs
        // that flip readiness.
        Ok(Err(_)) => true,
        Err(_) => false, // blocking-pool panic / transport break
    }
}

pub(super) fn ck_rv_only(result: CkResult<()>) -> u64 {
    match result {
        Ok(()) => CkRv::OK.0,
        Err(error) => error.0,
    }
}

/// Convert a `CkMechanismParams` returned by the backend into a proto
/// `Mechanism`, deriving the mechanism type from the variant tag.
///
/// Used by all RPCs whose response carries a `mechanism_out` field
/// (Encrypt/Decrypt simple paths + ByteOutputExact + WrapKey). New
/// mechanism variants that surface output parameters must extend the
/// match below; the catch-all is enumerated exhaustively (no bare `_`)
/// so adding a new `CkMechanismParams` variant fails to compile here,
/// forcing the maintainer to triage whether the new variant surfaces
/// `mechanism_out` and add the appropriate arm.
pub(super) fn mechanism_output_to_proto(
    params: CkMechanismParams,
) -> Option<pkcs11_proxy_ng_proto::Mechanism> {
    let mechanism_type = match &params {
        // Variants that surface mechanism output to the caller.
        CkMechanismParams::Gcm(_) => CkMechanismType::AES_GCM,
        CkMechanismParams::Tls12MasterKeyDerive(_) => CkMechanismType::TLS12_MASTER_KEY_DERIVE,
        // Variants that do NOT surface mechanism output (today). The
        // exhaustive enumeration forces a compile error when a new
        // variant is added.
        CkMechanismParams::RsaPkcsPss(_)
        | CkMechanismParams::RsaPkcsOaep(_)
        | CkMechanismParams::Ecdh1Derive(_)
        | CkMechanismParams::Iv(_)
        | CkMechanismParams::Rc5(_)
        | CkMechanismParams::Rc5MacGeneral(_)
        | CkMechanismParams::Rc2MacGeneral(_)
        | CkMechanismParams::Xeddsa(_)
        | CkMechanismParams::TlsMac(_)
        | CkMechanismParams::AesCtr(_)
        | CkMechanismParams::CamelliaCtr(_)
        | CkMechanismParams::Rc2Cbc(_)
        | CkMechanismParams::Rc5Cbc(_)
        | CkMechanismParams::AesCbcEncryptData(_)
        | CkMechanismParams::DesCbcEncryptData(_)
        | CkMechanismParams::AriaCbcEncryptData(_)
        | CkMechanismParams::CamelliaCbcEncryptData(_)
        | CkMechanismParams::SeedCbcEncryptData(_)
        | CkMechanismParams::Ccm(_)
        | CkMechanismParams::ChaCha20(_)
        | CkMechanismParams::Salsa20(_)
        | CkMechanismParams::Salsa20ChaCha20Poly1305(_)
        | CkMechanismParams::GcmWrap(_)
        | CkMechanismParams::CcmWrap(_)
        | CkMechanismParams::Ecdh2Derive(_)
        | CkMechanismParams::EcmqvDerive(_)
        | CkMechanismParams::X942Dh1Derive(_)
        | CkMechanismParams::X942Dh2Derive(_)
        | CkMechanismParams::X942MqvDerive(_)
        | CkMechanismParams::Hkdf(_)
        | CkMechanismParams::Eddsa(_)
        | CkMechanismParams::Gostr3410Derive(_)
        | CkMechanismParams::KeaDerive(_)
        | CkMechanismParams::EcdhAesKeyWrap(_)
        | CkMechanismParams::RsaAesKeyWrap(_)
        | CkMechanismParams::Gostr3410KeyWrap(_)
        | CkMechanismParams::KeyWrapSetOaep(_)
        | CkMechanismParams::Pbe(_)
        | CkMechanismParams::Pkcs5Pbkd2(_)
        | CkMechanismParams::TlsPrf(_)
        | CkMechanismParams::TlsKdf(_)
        | CkMechanismParams::Ssl3MasterKeyDerive(_)
        | CkMechanismParams::Tls12ExtendedMasterKeyDerive(_)
        | CkMechanismParams::Ssl3KeyMat(_)
        | CkMechanismParams::WtlsMasterKeyDerive(_)
        | CkMechanismParams::WtlsPrf(_)
        | CkMechanismParams::WtlsKeyMat(_)
        | CkMechanismParams::IkePrfDerive(_)
        | CkMechanismParams::Ike1PrfDerive(_)
        | CkMechanismParams::Ike1ExtendedDerive(_)
        | CkMechanismParams::Ike2PrfPlusDerive(_)
        | CkMechanismParams::Sp800108Kdf(_)
        | CkMechanismParams::Sp800108FeedbackKdf(_)
        | CkMechanismParams::X3dhInitiate(_)
        | CkMechanismParams::X3dhRespond(_)
        | CkMechanismParams::X2RatchetInitialize(_)
        | CkMechanismParams::X2RatchetRespond(_)
        | CkMechanismParams::Otp(_)
        | CkMechanismParams::Kip(_)
        | CkMechanismParams::CmsSig(_)
        | CkMechanismParams::SkipjackPrivateWrap(_)
        | CkMechanismParams::SkipjackRelayx(_)
        | CkMechanismParams::MacGeneral(_)
        | CkMechanismParams::ObjectHandle(_)
        | CkMechanismParams::Extract(_)
        | CkMechanismParams::SignAdditionalContext(_)
        | CkMechanismParams::Kmac(_)
        | CkMechanismParams::MuGen(_)
        | CkMechanismParams::KeyDerivationString(_)
        | CkMechanismParams::Raw(_)
        | CkMechanismParams::Ecies(_)
        | CkMechanismParams::AesCmacKeyDerivation(_)
        | CkMechanismParams::Dilithium(_)
        | CkMechanismParams::Kyber(_)
        | CkMechanismParams::HdKeyDerive(_)
        | CkMechanismParams::VendorObjectExtract(_)
        | CkMechanismParams::VendorObjectInsert(_) => return None,
    };
    // Only Gcm and Tls12MasterKeyDerive reach this conversion, and
    // neither shape carries templates or nested mechanisms, so the
    // fallible conversion cannot fail here (the nested-template
    // refusal, W1-C8-01, is its only Err source). `.ok()` preserves
    // the existing "variant does not surface output" contract; a
    // future surfaced variant carrying templates must propagate the
    // error loudly at its call sites instead.
    pkcs11_proxy_ng_proto::Mechanism::try_from(&CkMechanism {
        mechanism_type,
        params: Some(params),
    })
    .ok()
}

pub(super) async fn context_exists(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
) -> bool {
    ctx_mgr.get_context(ctx_id, |_| ()).await.is_some()
}

pub(super) async fn resolve_slot(
    ctx_mgr: &Arc<ContextManager>,
    slot_id: u64,
) -> Result<BackendSlotId, CkRv> {
    ctx_mgr.resolve_slot(VirtualSlotId(slot_id)).await.ok_or(CkRv::SLOT_ID_INVALID)
}

pub(super) fn parse_mechanism(
    mechanism: Option<pkcs11_proxy_ng_proto::Mechanism>,
) -> Result<CkMechanism, CkRv> {
    let proto_mechanism = mechanism.ok_or(CkRv::ARGUMENTS_BAD)?;
    CkMechanism::try_from(&proto_mechanism)
}

pub(super) async fn resolve_session(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    session_handle: u64,
) -> Result<CkSessionHandle, CkRv> {
    let Some(session) = ctx_mgr
        .get_context(ctx_id, |ctx| ctx.session_handles.resolve(VirtualHandle(session_handle)))
        .await
    else {
        return Err(CkRv::CRYPTOKI_NOT_INITIALIZED);
    };

    let backend_session = session.ok_or(CkRv::SESSION_HANDLE_INVALID)?;
    Ok(CkSessionHandle(backend_session.0 as u64))
}

/// Resolve a virtual session to its backend session, owning slot, and current
/// login state in a single context-locked read (shared by login/logout — M7).
/// Returns the CK_RV the caller should surface when the context is gone
/// (`CRYPTOKI_NOT_INITIALIZED`) or the session handle is unknown
/// (`SESSION_HANDLE_INVALID`).
///
/// W1-L11-16: the shared home for this triple read (moved out of auth.rs so
/// auth routes through the service_utils resolve_* helpers); the
/// single-locked-read semantics are unchanged.
pub(super) async fn resolve_session_slot_login(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    session_handle: u64,
) -> Result<(CkSessionHandle, BackendSlotId, Option<LoginState>), CkRv> {
    let resolved = ctx_mgr
        .get_context(ctx_id, |ctx| {
            let virtual_session = VirtualHandle(session_handle);
            let backend_session = ctx.session_handles.resolve(virtual_session);
            let slot = ctx.session_slots.get(&virtual_session).copied();
            let current_login_state = slot.and_then(|slot| ctx.login_state.get(&slot).copied());
            (backend_session, slot, current_login_state)
        })
        .await;

    match resolved {
        None => Err(CkRv::CRYPTOKI_NOT_INITIALIZED),
        Some((Some(backend_session), Some(slot), current_login_state)) => {
            Ok((CkSessionHandle(backend_session.0 as u64), slot, current_login_state))
        }
        Some(_) => Err(CkRv::SESSION_HANDLE_INVALID),
    }
}

/// Resolve the caller's identity and the token `(label, serial)` for the
/// session that owns `virtual_session`.
///
/// This is the shared identity + slot-info prologue for the per-object
/// authorization gate (`gate_object_handle`, USE-time) and the
/// `find_objects` enumeration filter (G3-PR2). Extracting it here keeps
/// the two call sites DRY — neither duplicates the identity lookup, slot
/// lookup, or token-info cache logic.
///
/// Returns `None` (fail-closed) when:
/// - the context is gone,
/// - the session is not registered in `session_slots`,
/// - the slot's token info is unavailable (`TOKEN_NOT_PRESENT`, backend
///   error, or transport failure).
pub(super) async fn resolve_object_authz_context(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    virtual_session: u64,
) -> Option<(AuthenticatedIdentity, String, String)> {
    // Step 1: Resolve the caller's identity from the context.
    let identity =
        super::authorization::context_identity(&ctx.context_manager, ctx_id).await.ok()?;

    // Step 2: Resolve the slot that owns this session → (label, serial).
    let backend_slot =
        ctx.context_manager.slot_for_session(ctx_id, VirtualHandle(virtual_session)).await?;

    let (label, serial) = match ctx.context_manager.cached_token_info(backend_slot) {
        Some(cached) => cached,
        None => {
            // Generation-guarded publication (T09): a fetch started before
            // a reinit must not reinsert stale label/serial after its
            // invalidation.
            let generation = ctx.context_manager.authz_generation();
            let backend_ref = ctx.backend.clone();
            match spawn_backend(move || backend_ref.get_token_info(backend_slot.0)).await {
                Ok(Ok(info)) => {
                    ctx.context_manager.cache_token_info_if_generation(
                        backend_slot,
                        info.label.clone(),
                        info.serial_number.clone(),
                        generation,
                    );
                    (info.label, info.serial_number)
                }
                // TOKEN_NOT_PRESENT, backend CkRv error, or transport failure.
                _ => return None, // fail-closed
            }
        }
    };

    Some((identity, label, serial))
}

/// Per-object authorization gate (G3-PR1, ADR-0012).
///
/// Called when `ctx.token_policy.per_object_active()` is `true` AND
/// the object resolved to a real backend handle (non-zero).  Returns the
/// original `backend_object` when the identity is allowed to use it;
/// returns `CkObjectHandle(0)` (the NOT-FOUND sentinel) otherwise.
///
/// **Invisible-denial contract (ADR-0012 §G3):** a denied object must
/// appear byte-for-byte identical to a non-existent one on the **RV**,
/// **audit**, and **metric** axes.  The caller substitutes the denied handle
/// with 0, exactly as the not-found path does.  No early return with a
/// different RV; no distinct audit record; no metric.  The backend returns
/// the operation's own handle-invalid code (`CKR_OBJECT_HANDLE_INVALID` for
/// object ops, `CKR_KEY_HANDLE_INVALID` for key ops); since both paths use
/// handle 0, the deny and not-found codes converge automatically.
///
/// **Timing note (I1):** the denial is NOT constant-latency.  A not-found
/// virtual handle (never registered) skips the backend entirely; a denied
/// handle (registered but policy-blocked) incurs a `get_token_info` +
/// `C_GetAttributeValue` (`CKA_UNIQUE_ID`) round-trip on first use (the
/// cache eliminates these on subsequent uses of the same handle).  This
/// first-use timing side-channel is accepted; a constant-latency denial
/// path (padding the not-found path with phantom backend calls) is tracked
/// as a future refinement.
///
/// **Fail-closed semantics:**
/// - Identity unavailable → deny (handle 0).
/// - Session's slot unknown → deny.
/// - Token info fetch fails → deny.
/// - `CKA_UNIQUE_ID` absent or empty → deny.
/// - `allows_object_use` returns false → deny.
///
/// NOTE: enumeration-time filtering of `find_objects` results is implemented
/// by G3-PR2 (`find_objects` in `object/search.rs`).  This gate covers
/// USE-time only; objects that pass the enumeration filter have their
/// `CKA_UNIQUE_ID` pre-cached so this gate avoids a re-fetch.
pub(super) async fn gate_object_handle(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    virtual_session: u64,
    virtual_object: u64,
    backend_session: BackendHandle,
    backend_object: CkObjectHandle,
) -> CkObjectHandle {
    let backend_session = CkSessionHandle(backend_session.0 as u64);

    // --- 1+2: Resolve identity and (label, serial) via shared helper ---
    let Some((identity, label, serial)) =
        resolve_object_authz_context(ctx, ctx_id, virtual_session).await
    else {
        return CkObjectHandle(0); // fail-closed
    };

    // --- 2. Early creator bypass (I3/M1 fix) ---
    // A principal can always use an object it minted this session (generate /
    // create / unwrap), even when its backend-assigned CKA_UNIQUE_ID is not in
    // the pre-configured `objects` grant. This is the minimal, correct ACL
    // inheritance: creator-owns-what-it-mints.
    //
    // The check is EARLY (before the metadata fetch) so that uid-only deployments
    // avoid the entire C_GetAttributeValue round-trip for created objects (M1).
    //
    // The check is per-context: context B's created_objects set is independent
    // of A's, so B is still gated by its own policy for any object it did NOT
    // mint. A recycled virtual handle cannot inherit created-status because the
    // removal hooks that evict object_metadata also evict created_objects.
    if ctx.context_manager.object_was_created_here(ctx_id, virtual_object).await {
        if !ctx.token_policy.per_class_active() {
            // No class gate: creator bypass is unconditional. No metadata fetch
            // needed for uid-only deployments (M1 — no overhead for creators).
            return backend_object;
        }
        // Class gate is active (I3 fix): fetch metadata for the class check only;
        // the uid check is still skipped (creator-owns-what-it-mints for uid).
        let fetched =
            super::authorization::fetch_object_metadata(ctx, backend_session, backend_object).await;
        if let Some(ref m) = fetched {
            ctx.context_manager.cache_object_metadata(ctx_id, virtual_object, m.clone()).await;
        }
        return match fetched {
            Some(meta)
                if meta.class.is_some_and(|c| {
                    ctx.token_policy.allows_class(&identity, &label, &serial, c)
                }) =>
            {
                backend_object
            }
            // fail-closed: class denied, class unknown (None), or metadata fetch failed
            _ => CkObjectHandle(0),
        };
    }

    // --- 3. Resolve ObjectMetadata from cache or backend (non-created objects) ---
    // Session objects are cached for the lifetime of the virtual handle;
    // token objects are cached gated by the authz generation (W1-L13-18:
    // cross-client backend handle recycling immunity via revocation).
    let meta: Option<ObjectMetadata> =
        ctx.context_manager.object_metadata(ctx_id, virtual_object).await;
    let meta = match meta {
        Some(cached) => cached,
        None => {
            // Cache miss: fetch uid + class + token in one C_GetAttributeValue call.
            let fetched =
                super::authorization::fetch_object_metadata(ctx, backend_session, backend_object)
                    .await;
            // cache_object_metadata tags token objects with the current
            // authz generation (W1-L13-18).
            if let Some(ref m) = fetched {
                ctx.context_manager.cache_object_metadata(ctx_id, virtual_object, m.clone()).await;
            }
            match fetched {
                Some(m) => m,
                None => return CkObjectHandle(0), // fail-closed
            }
        }
    };

    // Fail-closed: absent or empty CKA_UNIQUE_ID on a real object → deny.
    if meta.unique_id.is_empty() {
        return CkObjectHandle(0);
    }

    // --- 4. Policy checks ---
    // Per-object uid check (opt-in; pass-through when no objects grant configured).
    if !meta
        .unique_id
        .expose(|raw| ctx.token_policy.allows_object_use(&identity, &label, &serial, raw))
    {
        // Constant-work deny: substitute the NOT-FOUND sentinel. The handler
        // forwards handle 0 to the backend which returns CKR_OBJECT_HANDLE_INVALID,
        // IDENTICAL to a genuinely-nonexistent object. No log, no audit, no metric.
        return CkObjectHandle(0);
    }
    // Per-class check (opt-in; skipped when no classes grant is configured).
    // M2: class is Option — None is fail-closed when per_class_active() (deny).
    if ctx.token_policy.per_class_active()
        && !meta.class.is_some_and(|c| ctx.token_policy.allows_class(&identity, &label, &serial, c))
    {
        return CkObjectHandle(0);
    }

    backend_object
}

pub(super) async fn resolve_session_and_key(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    session_handle: u64,
    key_handle: u64,
) -> Result<(CkSessionHandle, CkObjectHandle), CkRv> {
    resolve_session_and_handle(ctx, ctx_id, session_handle, key_handle, CkRv::KEY_HANDLE_INVALID)
        .await
}

async fn resolve_session_and_handle(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    session_handle: u64,
    object_handle: u64,
    stale_rv: CkRv,
) -> Result<(CkSessionHandle, CkObjectHandle), CkRv> {
    let Some((session, key, destroyed)) = ctx
        .context_manager
        .get_context(ctx_id, |c| {
            (
                c.session_handles.resolve(VirtualHandle(session_handle)),
                c.object_handles.resolve(VirtualHandle(object_handle)),
                c.destroyed_objects.contains(&VirtualHandle(object_handle)),
            )
        })
        .await
    else {
        return Err(CkRv::CRYPTOKI_NOT_INITIALIZED);
    };

    let backend_session = session.ok_or(CkRv::SESSION_HANDLE_INVALID)?;
    // T20 tombstone: a virtual handle removed by an explicit C_DestroyObject
    // names a definitively-gone object — answer the handle-invalid family
    // locally instead of forwarding 0 (whose backend verdict is
    // backend-specific: bouncyhsm answers DEVICE_ERROR on copy-of-0 but
    // OBJECT_HANDLE_INVALID on copy-of-destroyed). Never-existed handles
    // still forward 0 so the backend decides error priority.
    if key.is_none() && destroyed {
        return Err(stale_rv);
    }
    // When the key handle is unknown to the proxy (not in the mapping),
    // forward CK_INVALID_HANDLE (0) to the backend rather than returning
    // CKR_KEY_HANDLE_INVALID locally.  This preserves transparency: the
    // backend decides the error priority (e.g., CKR_FUNCTION_NOT_SUPPORTED
    // vs CKR_KEY_HANDLE_INVALID).
    let backend_key = key.map_or(CkObjectHandle(0), |h| CkObjectHandle(h.0 as u64));
    // D6(1): a logically-logged-out caller must not USE a private object even
    // when the shared backend token is logged in by other tenants. Unknown
    // handles (0) skip the check — the backend decides their error. Authn
    // runs before the authz gate below.
    if backend_key.0 != 0 {
        ensure_private_use_allowed(
            ctx,
            ctx_id,
            session_handle,
            object_handle,
            CkSessionHandle(backend_session.0),
            backend_key,
        )
        .await?;
    }
    // Per-object / per-class gate: enter when any object or class grant is
    // active AND the key resolved to a real handle. When both flags are false
    // (no policy configured) this is a zero-overhead transparent pass-through.
    let backend_key = if (ctx.token_policy.per_object_active()
        || ctx.token_policy.per_class_active())
        && backend_key.0 != 0
    {
        gate_object_handle(ctx, ctx_id, session_handle, object_handle, backend_session, backend_key)
            .await
    } else {
        backend_key
    };
    Ok((CkSessionHandle(backend_session.0 as u64), backend_key))
}

pub(super) async fn resolve_session_and_object(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    session_handle: u64,
    object_handle: u64,
) -> Result<(CkSessionHandle, CkObjectHandle), CkRv> {
    // W1-L11-05: one shared implementation behind both names (same
    // forward-0, tombstone, D6(1) authn, and per-object/class gate); the
    // names differ only in the tombstone RV flavor (key vs object) for
    // call-site clarity.
    resolve_session_and_handle(
        ctx,
        ctx_id,
        session_handle,
        object_handle,
        CkRv::OBJECT_HANDLE_INVALID,
    )
    .await
}

pub(super) async fn resolve_session_and_two_objects(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    session_handle: u64,
    first_object_handle: u64,
    second_object_handle: u64,
) -> Result<(CkSessionHandle, CkObjectHandle, CkObjectHandle), CkRv> {
    let Some((session, first_object, second_object, first_destroyed, second_destroyed)) = ctx
        .context_manager
        .get_context(ctx_id, |c| {
            (
                c.session_handles.resolve(VirtualHandle(session_handle)),
                c.object_handles.resolve(VirtualHandle(first_object_handle)),
                c.object_handles.resolve(VirtualHandle(second_object_handle)),
                c.destroyed_objects.contains(&VirtualHandle(first_object_handle)),
                c.destroyed_objects.contains(&VirtualHandle(second_object_handle)),
            )
        })
        .await
    else {
        return Err(CkRv::CRYPTOKI_NOT_INITIALIZED);
    };

    let backend_session = session.ok_or(CkRv::SESSION_HANDLE_INVALID)?;
    // T20 tombstones (both handles are keys on the wrap/unwrap path): a
    // destroyed handle answers KEY_HANDLE_INVALID locally instead of
    // forwarding 0; never-existed handles still forward 0.
    if first_object.is_none() && first_destroyed {
        return Err(CkRv::KEY_HANDLE_INVALID);
    }
    if second_object.is_none() && second_destroyed {
        return Err(CkRv::KEY_HANDLE_INVALID);
    }
    // Forward CK_INVALID_HANDLE to backend when either object is unknown; see
    // resolve_session_and_key for rationale. Local context/session validation
    // remains explicit; backend-visible object handle priority stays backend-owned.
    let first_backend_object =
        first_object.map_or(CkObjectHandle(0), |h| CkObjectHandle(h.0 as u64));
    let second_backend_object =
        second_object.map_or(CkObjectHandle(0), |h| CkObjectHandle(h.0 as u64));
    // D6(1): refuse private-object USE while logically logged out (each
    // handle independently; unknown handles skip — the backend decides).
    for (virtual_object, backend_object) in
        [(first_object_handle, first_backend_object), (second_object_handle, second_backend_object)]
    {
        if backend_object.0 != 0 {
            ensure_private_use_allowed(
                ctx,
                ctx_id,
                session_handle,
                virtual_object,
                CkSessionHandle(backend_session.0),
                backend_object,
            )
            .await?;
        }
    }
    // Per-object / per-class gate: gate each object independently (the two-object
    // operations are wrapping/unwrapping where BOTH handles must be authorized).
    // Zero-overhead when both per_object_active() and per_class_active() are false.
    let (first_backend_object, second_backend_object) =
        if ctx.token_policy.per_object_active() || ctx.token_policy.per_class_active() {
            let first = if first_backend_object.0 != 0 {
                gate_object_handle(
                    ctx,
                    ctx_id,
                    session_handle,
                    first_object_handle,
                    backend_session,
                    first_backend_object,
                )
                .await
            } else {
                first_backend_object
            };
            let second = if second_backend_object.0 != 0 {
                gate_object_handle(
                    ctx,
                    ctx_id,
                    session_handle,
                    second_object_handle,
                    backend_session,
                    second_backend_object,
                )
                .await
            } else {
                second_backend_object
            };
            (first, second)
        } else {
            (first_backend_object, second_backend_object)
        };

    Ok((CkSessionHandle(backend_session.0 as u64), first_backend_object, second_backend_object))
}

/// True when `template` declares `CKA_TOKEN` as a true value — i.e. a token
/// object, whose handle persists across the application's sessions and must NOT
/// be evicted on session close. The bool may arrive as a typed `Bool`, a raw
/// `CK_BBOOL` byte, or a ulong, so all encodings are accepted (B2).
/// The `CKA_CLASS` declared by `template`, if any (W1-L7-05).
/// Server-side templates arrive through proto conversion, which decodes
/// `CKA_CLASS` to `Ulong`; any other encoding is treated as undeclared
/// (the mint gate falls through to the backend verdict for it).
pub(super) fn template_declared_class(template: &[CkAttribute]) -> Option<CkObjectClass> {
    template.iter().find_map(|attr| {
        if attr.attr_type != CkAttributeType::CLASS {
            return None;
        }
        match &attr.value {
            Some(CkAttributeValue::Ulong(class)) => Some(CkObjectClass(*class)),
            _ => None,
        }
    })
}

pub(super) fn template_declares_token_object(template: &[CkAttribute]) -> bool {
    template.iter().any(|attr| {
        attr.attr_type == CkAttributeType::TOKEN
            && match &attr.value {
                Some(CkAttributeValue::Bool(b)) => *b,
                Some(CkAttributeValue::Bytes(bytes)) => {
                    bytes.expose(|raw| raw.first().is_some_and(|&b| b != 0))
                }
                Some(CkAttributeValue::Ulong(u)) => *u != 0,
                _ => false,
            }
    })
}

/// True when `template` declares `CKA_PRIVATE` as a true value — i.e. a private
/// object, which natively requires the calling application to be logged in.
/// Accepts every bool encoding (`Bool`, raw `CK_BBOOL` byte, ulong) exactly
/// like [`template_declares_token_object`] (D6(1)).
pub(super) fn template_declares_private_object(template: &[CkAttribute]) -> bool {
    template.iter().any(|attr| {
        attr.attr_type == CkAttributeType::PRIVATE
            && match &attr.value {
                Some(CkAttributeValue::Bool(b)) => *b,
                Some(CkAttributeValue::Bytes(bytes)) => {
                    bytes.expose(|raw| raw.first().is_some_and(|&b| b != 0))
                }
                Some(CkAttributeValue::Ulong(u)) => *u != 0,
                _ => false,
            }
    })
}

/// True when `template` carries any `CKA_PRIVATE` attribute, whatever its value
/// (presence check for copy-inheritance: an explicit `False` makes a public
/// copy even of a private source).
pub(super) fn template_has_private_attr(template: &[CkAttribute]) -> bool {
    template.iter().any(|attr| attr.attr_type == CkAttributeType::PRIVATE)
}

/// Logical login state of `ctx_id` for the slot owning `virtual_session`
/// (`None` = logically logged out, or the session is unknown to the context).
pub(super) async fn session_slot_login_state(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    virtual_session: u64,
) -> Option<LoginState> {
    ctx_mgr
        .get_context(ctx_id, |ctx| {
            ctx.session_slots
                .get(&VirtualHandle(virtual_session))
                .copied()
                .and_then(|slot| ctx.login_state.get(&slot).copied())
        })
        .await
        .flatten()
}

/// D6(1) enforcement for object-MINTING operations (create/copy/generate/
/// derive/unwrap), as refined in T20: when the calling context is logically
/// logged out on the session's slot and `template` declares the new object
/// private, refuse with `CKR_USER_NOT_LOGGED_IN` — but ONLY while another
/// live tenant holds the slot login (forwarding would ride their backend
/// login). With no other holder the backend is truly logged out, so its
/// verdict is unpolluted and authoritative: forward and return whatever it
/// says (lenient backends such as NSS allow logged-out private session
/// mints; strict backends refuse — both match direct exactly). The old
/// unconditional refusal diverged from every lenient backend (21 lanes).
/// Unknown sessions fail closed (refuse), preserving error precedence for
/// the downstream handle resolve.
pub(super) async fn ensure_private_mint_allowed(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    virtual_session: u64,
    template: &[CkAttribute],
) -> Result<(), CkRv> {
    if !template_declares_private_object(template) {
        return Ok(());
    }
    let (_, slot, login_state) =
        match resolve_session_slot_login(ctx_mgr, ctx_id, virtual_session).await {
            Ok(triple) => triple,
            Err(_) => return Err(CkRv::USER_NOT_LOGGED_IN),
        };
    if login_state.is_none() && ctx_mgr.other_login_state_for_slot(slot, ctx_id) {
        return Err(CkRv::USER_NOT_LOGGED_IN);
    }
    Ok(())
}

/// Outcome of a single boolean-attribute probe (T20 visibility refinement).
/// `Present(b)` is a decoded value; `AttrAbsent` is attribute-absence — the
/// call failed with `ATTRIBUTE_TYPE_INVALID`, or succeeded with a
/// per-attribute `CK_UNAVAILABLE_INFORMATION` marker (value `None`);
/// `Failed` is any other backend/transport error or an undecodable value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoolAttrProbe {
    Present(bool),
    AttrAbsent,
    Failed,
}

/// Shared single-attribute boolean probe behind the read-only find filters
/// (`CKA_PRIVATE` / `CKA_TOKEN`). Read-only; never disturbs other tenants.
async fn probe_bool_attr(
    ctx: &HandlerContext,
    backend_session: CkSessionHandle,
    backend_object: CkObjectHandle,
    attr_type: CkAttributeType,
) -> BoolAttrProbe {
    let backend = ctx.backend.clone();
    let fetched = spawn_backend(move || {
        let mut template = [CkAttribute { attr_type, value: Some(CkAttributeValue::Bool(false)) }];
        let outcome =
            match backend.get_attribute_value(backend_session, backend_object, &mut template) {
                Ok(()) => match template.first().and_then(|attr| attr.value.as_ref()) {
                    None => BoolAttrProbe::AttrAbsent,
                    Some(CkAttributeValue::Bool(b)) => BoolAttrProbe::Present(*b),
                    Some(CkAttributeValue::Bytes(bytes)) => BoolAttrProbe::Present(
                        bytes.expose(|raw| raw.first().is_some_and(|&b| b != 0)),
                    ),
                    Some(CkAttributeValue::Ulong(u)) => BoolAttrProbe::Present(*u != 0),
                    Some(_) => BoolAttrProbe::Failed,
                },
                Err(e) if e == CkRv::ATTRIBUTE_TYPE_INVALID => BoolAttrProbe::AttrAbsent,
                Err(_) => BoolAttrProbe::Failed,
            };
        Ok(outcome)
    })
    .await;
    match fetched {
        Ok(Ok(outcome)) => outcome,
        _ => BoolAttrProbe::Failed,
    }
}

/// Read `CKA_PRIVATE` for one backend object. Returns `true` only on a
/// positive True; any backend error, transport failure, or absent/unparseable
/// value returns `false` so the caller falls through to the real operation
/// and the backend's own faithful verdict (fail-open to the backend — the
/// D6(1) refusal only fires for known-private objects).
async fn backend_object_is_private(
    ctx: &HandlerContext,
    backend_session: CkSessionHandle,
    backend_object: CkObjectHandle,
) -> bool {
    matches!(
        probe_bool_attr(ctx, backend_session, backend_object, CkAttributeType::PRIVATE).await,
        BoolAttrProbe::Present(true)
    )
}

/// F-04: known-public probe for find-enumeration filtering. Returns `true`
/// when the probe positively reports public, or when the attribute is absent
/// on a spec "other"-class object (see [`is_other_object_class`]); unknown
/// privacy otherwise hides the object (fail-closed — unlike USE there is no
/// backend verdict to fall back to, and a logged-out context must not
/// observe private objects).
pub(super) async fn backend_object_known_public(
    ctx: &HandlerContext,
    backend_session: CkSessionHandle,
    backend_object: CkObjectHandle,
) -> bool {
    match probe_bool_attr(ctx, backend_session, backend_object, CkAttributeType::PRIVATE).await {
        BoolAttrProbe::Present(public) => !public,
        // Absent PRIVATE on an "other"-class object is spec-compliant (no
        // storage attributes); such objects are token-global metadata —
        // fail open. Anything else stays fail-closed.
        BoolAttrProbe::AttrAbsent => {
            backend_object_has_other_class(ctx, backend_session, backend_object).await
        }
        BoolAttrProbe::Failed => false,
    }
}

/// CROSS-PROC-001: known-token probe for find-enumeration filtering.
/// Returns `true` when the probe positively reports a token object, or when
/// the attribute is absent on a spec "other"-class object (see
/// [`is_other_object_class`]); session-scoped or otherwise-unknown objects
/// return `false` (fail-closed — an unknown session object belongs to
/// another context and must hide).
pub(super) async fn backend_object_known_token(
    ctx: &HandlerContext,
    backend_session: CkSessionHandle,
    backend_object: CkObjectHandle,
) -> bool {
    match probe_bool_attr(ctx, backend_session, backend_object, CkAttributeType::TOKEN).await {
        BoolAttrProbe::Present(token) => token,
        // Absent TOKEN on an "other"-class object is spec-compliant (no
        // storage attributes); such objects are token-global metadata —
        // fail open. Anything else stays fail-closed.
        BoolAttrProbe::AttrAbsent => {
            backend_object_has_other_class(ctx, backend_session, backend_object).await
        }
        BoolAttrProbe::Failed => false,
    }
}

/// T20 visibility: PKCS#11 "other" object classes (OASIS
/// `object_classification`: HW_FEATURE, MECHANISM, PROFILE, VALIDATION)
/// possess no storage attributes, so spec-compliant backends answer
/// `CKA_TOKEN` / `CKA_PRIVATE` with `ATTRIBUTE_TYPE_INVALID` (observed
/// natively on kryoptic mechanism objects). They are token-global
/// metadata by design — never secrets — so attribute-absence fails open
/// for them, matching direct (where no proxy filter hides them).
/// Storage classes and unknown/vendor classes stay fail-closed.
fn is_other_object_class(class: CkObjectClass) -> bool {
    matches!(
        class,
        CkObjectClass::HW_FEATURE
            | CkObjectClass::MECHANISM
            | CkObjectClass::PROFILE
            | CkObjectClass::VALIDATION
    )
}

/// `CKA_CLASS` probe for one backend object: the class value, or `None` on
/// any failure or undecodable value (fail-closed — callers treat unknown
/// class as storage).
async fn probe_object_class(
    ctx: &HandlerContext,
    backend_session: CkSessionHandle,
    backend_object: CkObjectHandle,
) -> Option<CkObjectClass> {
    let backend = ctx.backend.clone();
    let fetched = spawn_backend(move || {
        let mut template = [CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(0)),
        }];
        let class =
            match backend.get_attribute_value(backend_session, backend_object, &mut template) {
                Ok(()) => match template.first().and_then(|attr| attr.value.as_ref()) {
                    Some(CkAttributeValue::Ulong(u)) => Some(CkObjectClass(*u)),
                    Some(CkAttributeValue::Bytes(bytes)) => bytes.expose(|raw| {
                        if raw.len() == size_of::<u64>() {
                            let mut buf = [0u8; 8];
                            buf.copy_from_slice(raw);
                            Some(CkObjectClass(u64::from_ne_bytes(buf)))
                        } else if raw.len() == size_of::<u32>() {
                            let mut buf = [0u8; 4];
                            buf.copy_from_slice(raw);
                            Some(CkObjectClass(u64::from(u32::from_ne_bytes(buf))))
                        } else {
                            None
                        }
                    }),
                    _ => None,
                },
                Err(_) => None,
            };
        Ok(class)
    })
    .await;
    match fetched {
        Ok(Ok(class)) => class,
        _ => None,
    }
}

/// True when the object's probed class is a spec "other" class (see
/// [`is_other_object_class`]); any probe failure reads as storage
/// (fail-closed).
async fn backend_object_has_other_class(
    ctx: &HandlerContext,
    backend_session: CkSessionHandle,
    backend_object: CkObjectHandle,
) -> bool {
    probe_object_class(ctx, backend_session, backend_object)
        .await
        .is_some_and(is_other_object_class)
}

/// CROSS-PROC-001: true when `backend_object` already maps in the calling
/// context — minted here, or admitted by an earlier vetted find. Such
/// handles skip the token probe (their visibility was already decided).
///
/// Residual (T2run-fix1 prod M3, flagged 2026-09-19): handle-recycling ABA —
/// if the provider deletes an object out-of-band and recycles its handle for
/// a foreign session object, a stale mapping shows it without re-probing.
/// Narrow (destroy paths remove mappings, so staleness needs provider-side
/// deletion + handle reuse) and fail-closed everywhere else — accepted.
pub(super) async fn context_maps_backend_object(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    backend_object: CkObjectHandle,
) -> bool {
    ctx_mgr
        .get_context(ctx_id, |c| {
            c.object_handles.resolve_backend(BackendHandle(backend_object.0)).is_some()
        })
        .await
        .unwrap_or(false)
}

/// CROSS-PROC-001: cross-context session-object isolation for find.
/// Session objects are visible to every backend session of the daemon's
/// single backend application — including other tenants' contexts — so a
/// find result is shown only when this context already maps it (minted
/// here or vetted by an earlier find) or it probes as a token object
/// (app-global by design). Fail-closed throughout: probe failure hides.
pub(super) async fn find_result_visible_to_context(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    backend_session: CkSessionHandle,
    backend_object: CkObjectHandle,
) -> bool {
    if context_maps_backend_object(&ctx.context_manager, ctx_id, backend_object).await {
        return true;
    }
    backend_object_known_token(ctx, backend_session, backend_object).await
}

/// D6(1) enforcement for object/key USE (sign/verify/encrypt/decrypt/digest
/// init, get/set attributes, wrap/unwrap/derive keys, ...), as refined in
/// T20: when the calling context is logically logged out on the session's
/// slot and the object is private, refuse with `CKR_USER_NOT_LOGGED_IN` —
/// but ONLY while another live tenant holds the slot login (forwarding
/// would ride their backend login). With no other holder the backend is
/// truly logged out, so its verdict is unpolluted and authoritative:
/// forward and return whatever it says (lenient backends such as NSS
/// allow logged-out use of own private session objects; strict backends
/// refuse — both match direct exactly). The old unconditional refusal
/// diverged from every lenient backend (21 lanes).
///
/// Cost: the logged-in path costs one in-memory map read. The logged-out path
/// decides from the mint-recorded privacy bit when known (still no backend
/// call, so cache-hit and coalescer semantics are unchanged) and probes
/// `CKA_PRIVATE` from the backend — a read-only probe that never disturbs
/// other tenants — only for unknown (find-registered / backend-minted)
/// objects.
/// Privacy bit for one object: the mint-recorded bit when known, else a
/// single backend `CKA_PRIVATE` probe (fail-open `false` — the caller falls
/// through to the backend's own faithful verdict).
pub(super) async fn object_is_private(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    virtual_object: u64,
    backend_session: CkSessionHandle,
    backend_object: CkObjectHandle,
) -> bool {
    let known = ctx
        .context_manager
        .get_context(ctx_id, |c| c.object_private.get(&VirtualHandle(virtual_object)).copied())
        .await
        .flatten();
    match known {
        Some(private) => private,
        None => backend_object_is_private(ctx, backend_session, backend_object).await,
    }
}

pub(super) async fn ensure_private_use_allowed(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    virtual_session: u64,
    virtual_object: u64,
    backend_session: CkSessionHandle,
    backend_object: CkObjectHandle,
) -> Result<(), CkRv> {
    let (_, slot, login_state) =
        match resolve_session_slot_login(&ctx.context_manager, ctx_id, virtual_session).await {
            Ok(triple) => triple,
            Err(_) => {
                // Unknown session: fail closed exactly like the old gate
                // (refuse when private), preserving error precedence for
                // the downstream handle resolve.
                if object_is_private(ctx, ctx_id, virtual_object, backend_session, backend_object)
                    .await
                {
                    return Err(CkRv::USER_NOT_LOGGED_IN);
                }
                return Ok(());
            }
        };
    if login_state.is_some() {
        return Ok(());
    }
    if object_is_private(ctx, ctx_id, virtual_object, backend_session, backend_object).await
        && ctx.context_manager.other_login_state_for_slot(slot, ctx_id)
    {
        return Err(CkRv::USER_NOT_LOGGED_IN);
    }
    Ok(())
}

/// Register a backend object handle and, when it is a session object, record it
/// under `session` so it is evicted when that session closes (B2). Returns the
/// virtual object handle (0 if the context is gone).
///
/// This is a MINTING registration (generate/create/unwrap/derive path,
/// including SP800-108 additional derived keys and SSL3/TLS/WTLS key-mat
/// OUT handles virtualized out of a successful derive's `mechanism_out`).
/// The new virtual handle is inserted into `created_objects` so the
/// per-object gate (`gate_object_handle`) allows the creating context to
/// use this key even when its backend-assigned `CKA_UNIQUE_ID` is not in
/// the pre-configured `objects` grant (G3-PR3 Task 2).
///
/// `is_private` records the template-declared `CKA_PRIVATE` bit for the D6(1)
/// logical-login enforcement. Production mint sites always pass
/// `Some(declared)`; `None` leaves the bit unknown so logged-out USE probes
/// the backend once per operation (used by test fixtures that bypass real
/// minting).
pub(super) async fn register_session_object_handle(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    session: VirtualHandle,
    backend_handle: CkObjectHandle,
    is_token_object: bool,
    is_private: Option<bool>,
) -> u64 {
    ctx_mgr
        .get_context(ctx_id, |ctx| {
            let virtual_object = ctx.object_handles.insert(BackendHandle(backend_handle.0));
            if !is_token_object {
                ctx.record_session_object(session, virtual_object);
            }
            // Minting: the creating context can always use what it generated.
            ctx.created_objects.insert(virtual_object);
            if let Some(private) = is_private {
                ctx.object_private.insert(virtual_object, private);
            }
            virtual_object.0
        })
        .await
        .unwrap_or(0)
}

/// Register a generated key pair, recording each key as a session object under
/// `session` unless its own template marks it a token object (B2).
///
/// This is a MINTING registration (C_GenerateKeyPair / C_DeriveKey path). Both
/// virtual handles are inserted into `created_objects` so the creating context
/// can use them immediately even when their backend-assigned `CKA_UNIQUE_ID`s
/// are not in the pre-configured `objects` grant (G3-PR3 Task 2).
///
/// `first_is_private` / `second_is_private` record each key's
/// template-declared `CKA_PRIVATE` bit for the D6(1) enforcement (see
/// [`register_session_object_handle`]).
pub(super) async fn register_session_object_pair(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    session: VirtualHandle,
    first_backend_handle: CkObjectHandle,
    first_is_token: bool,
    first_is_private: bool,
    second_backend_handle: CkObjectHandle,
    second_is_token: bool,
    second_is_private: bool,
) -> Option<(u64, u64)> {
    ctx_mgr
        .get_context(ctx_id, |ctx| {
            let first = ctx.object_handles.insert(BackendHandle(first_backend_handle.0));
            let second = ctx.object_handles.insert(BackendHandle(second_backend_handle.0));
            if !first_is_token {
                ctx.record_session_object(session, first);
            }
            if !second_is_token {
                ctx.record_session_object(session, second);
            }
            // Minting: the creating context can always use both generated keys.
            ctx.created_objects.insert(first);
            ctx.created_objects.insert(second);
            ctx.object_private.insert(first, first_is_private);
            ctx.object_private.insert(second, second_is_private);
            (first.0, second.0)
        })
        .await
}

pub(super) async fn register_session_handle(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    backend_handle: CkSessionHandle,
    slot_id: BackendSlotId,
) -> Option<u64> {
    ctx_mgr
        .get_context(ctx_id, |ctx| ctx.register_session(BackendHandle(backend_handle.0), slot_id).0)
        .await
}

pub(super) async fn register_object_handles(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    backend_handles: &[CkObjectHandle],
) -> Option<Vec<u64>> {
    ctx_mgr
        .get_context(ctx_id, |ctx| {
            backend_handles
                .iter()
                .map(|handle| ctx.object_handles.insert(BackendHandle(handle.0)).0)
                .collect()
        })
        .await
}

/// Reconstruct a `CkInBuf` from its two wire fields.
///
/// When `null_len` is `Some(len)`, the original pointer was NULL with the
/// caller's claimed length, so we reconstruct `CkInBuf::Null { len }`.
/// Otherwise the bytes field holds the actual input data.
pub(super) fn input_from_wire(bytes: &[u8], null_len: Option<u64>) -> CkInBuf<'_> {
    match null_len {
        Some(len) => CkInBuf::Null { len },
        None => CkInBuf::Bytes(bytes),
    }
}

/// ADR-0010 sanitize_inputs gate: reject a NULL data pointer with non-zero
/// claimed length before the backend is touched. Call sites construct the
/// actual CkInBuf via input_from_wire inside the spawn_backend closure.
pub(super) fn check_sanitize(sanitize: bool, null_len: Option<u64>) -> Result<(), CkRv> {
    if sanitize && null_len.is_some_and(|len| len > 0) {
        return Err(CkRv::ARGUMENTS_BAD);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs11_proxy_ng_backend::Pkcs11Backend;
    use pkcs11_proxy_ng_types::{GcmParams, SslRandomData, Tls12MasterKeyDeriveParams};

    #[test]
    fn template_declares_private_object_accepts_every_bool_encoding() {
        // D6(1): the mint refusal must fire however the client encoded
        // CKA_PRIVATE=true (typed Bool, raw CK_BBOOL byte, ulong) and must
        // stay silent for false/absent/other attributes.
        let cases: Vec<(Vec<CkAttribute>, bool)> = vec![
            (
                vec![CkAttribute {
                    attr_type: CkAttributeType::PRIVATE,
                    value: Some(CkAttributeValue::Bool(true)),
                }],
                true,
            ),
            (
                vec![CkAttribute {
                    attr_type: CkAttributeType::PRIVATE,
                    value: Some(CkAttributeValue::Bytes(vec![1u8].into())),
                }],
                true,
            ),
            (
                vec![CkAttribute {
                    attr_type: CkAttributeType::PRIVATE,
                    value: Some(CkAttributeValue::Ulong(1)),
                }],
                true,
            ),
            (
                vec![CkAttribute {
                    attr_type: CkAttributeType::PRIVATE,
                    value: Some(CkAttributeValue::Bool(false)),
                }],
                false,
            ),
            (
                vec![CkAttribute {
                    attr_type: CkAttributeType::PRIVATE,
                    value: Some(CkAttributeValue::Bytes(vec![0u8].into())),
                }],
                false,
            ),
            (vec![], false),
            (
                vec![CkAttribute {
                    attr_type: CkAttributeType::TOKEN,
                    value: Some(CkAttributeValue::Bool(true)),
                }],
                false,
            ),
        ];
        for (template, expected) in cases {
            assert_eq!(
                template_declares_private_object(&template),
                expected,
                "template {template:?}"
            );
        }
    }

    #[test]
    fn mechanism_output_to_proto_handles_gcm() {
        let params = CkMechanismParams::Gcm(GcmParams {
            iv: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            iv_bits: 96,
            iv_buffer_len: 12,
            aad: Vec::new().into(),
            tag_bits: 128,

            iv_null: false,
            aad_null: false,
        });
        let proto_mech = mechanism_output_to_proto(params).expect("gcm should convert");
        // The proto Mechanism's type field should match AES_GCM.
        assert_eq!(proto_mech.mechanism_type, CkMechanismType::AES_GCM.0);
    }

    #[test]
    fn mechanism_output_to_proto_handles_tls12_master_key_derive() {
        let params = CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
            random_info: SslRandomData {
                client_random: vec![0xaa; 32],
                server_random: vec![0xbb; 32],
            },
            version_major: 3,
            version_minor: 3, // TLS 1.2
            prf_hash_mechanism: CkMechanismType::SHA256,
        });
        let proto_mech = mechanism_output_to_proto(params).expect("tls12 should convert");
        assert_eq!(proto_mech.mechanism_type, CkMechanismType::TLS12_MASTER_KEY_DERIVE.0);
    }

    #[test]
    fn mechanism_output_to_proto_returns_none_for_unmodeled_variant() {
        // A mechanism variant we haven't added to the match (e.g. Raw)
        // should return None so the response carries no mech_out rather
        // than panicking or sending wrong type info.
        let params = CkMechanismParams::Raw(pkcs11_proxy_ng_types::RawMechanismParams {
            data: vec![1, 2, 3].into(),
        });
        assert!(mechanism_output_to_proto(params).is_none());
    }

    #[test]
    fn configure_backend_guard_sets_values() {
        // OnceLock: first call wins. Subsequent calls in other tests are no-ops.
        configure_backend_guard(45, 128);
        // After configuration, the accessors should return *some* valid value.
        // (If another test ran first, those values win, but they are still valid.)
        assert!(backend_timeout().as_secs() > 0);
        assert!(max_concurrent_backend_calls() > 0);
    }

    #[test]
    fn backend_in_flight_initially_zero() {
        // IN_FLIGHT is a global AtomicUsize; in a fresh process it starts at 0.
        // Other tests may have modified it, so just verify the accessor works.
        let _count = backend_in_flight();
    }

    #[tokio::test]
    async fn stuck_backend_call_holds_breaker_slot_until_completion() {
        // A call that outlives its timeout must KEEP its in-flight slot
        // until the FFI actually returns: the breaker has to see wedged
        // calls (a stuck token otherwise leaks unbounded blocking threads
        // and the daemon cannot self-recover). Dedicated counter + short
        // timeout keep this hermetic from the global IN_FLIGHT.
        static STUCK_TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);
        static STUCK_TEST_GAUGE: AtomicUsize = AtomicUsize::new(0);
        let (unstick_tx, unstick_rx) = std::sync::mpsc::channel::<()>();

        let result = spawn_backend_core(
            &STUCK_TEST_COUNTER,
            &STUCK_TEST_GAUGE,
            Duration::from_millis(50),
            8,
            move || {
                let _ = unstick_rx.recv();
                Ok(0u8)
            },
        )
        .await;
        assert_eq!(
            result.expect("no transport error").unwrap_err(),
            CkRv::FUNCTION_FAILED,
            "W1-L3-01: caller sees the timeout as FUNCTION_FAILED (was DEVICE_ERROR)"
        );
        assert_eq!(
            STUCK_TEST_COUNTER.load(Ordering::Relaxed),
            1,
            "the wedged call must still hold its breaker slot after timeout"
        );

        // The token unsticks: the slot frees WITHOUT a daemon restart.
        unstick_tx.send(()).expect("receiver alive");
        for _ in 0..200 {
            if STUCK_TEST_COUNTER.load(Ordering::Relaxed) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            STUCK_TEST_COUNTER.load(Ordering::Relaxed),
            0,
            "slot must free once the stuck call finally returns"
        );
    }

    #[tokio::test]
    async fn timed_out_call_is_counted_stuck_until_it_returns() {
        // Operators must be able to distinguish "overloaded" from "token
        // wedged": a call that outlived its timeout counts as stuck until
        // the backend actually returns.
        static GAUGE_TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);
        static GAUGE_TEST_GAUGE: AtomicUsize = AtomicUsize::new(0);
        let (unstick_tx, unstick_rx) = std::sync::mpsc::channel::<()>();

        let result = spawn_backend_core(
            &GAUGE_TEST_COUNTER,
            &GAUGE_TEST_GAUGE,
            Duration::from_millis(50),
            8,
            move || {
                let _ = unstick_rx.recv();
                Ok(0u8)
            },
        )
        .await;
        assert!(result.expect("no transport error").is_err());
        assert_eq!(
            GAUGE_TEST_GAUGE.load(Ordering::Relaxed),
            1,
            "a timed-out-but-running call counts as stuck"
        );

        unstick_tx.send(()).expect("receiver alive");
        for _ in 0..200 {
            if GAUGE_TEST_GAUGE.load(Ordering::Relaxed) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            GAUGE_TEST_GAUGE.load(Ordering::Relaxed),
            0,
            "gauge drops when the call returns"
        );
    }

    #[test]
    fn stuck_accounting_state_level_contract() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let gauge = AtomicUsize::new(0);
        let accounting = StuckCallAccounting::new(&gauge);
        accounting.complete();
        accounting.timeout();
        assert_eq!(gauge.load(Ordering::SeqCst), 0);

        let gauge = AtomicUsize::new(0);
        let accounting = StuckCallAccounting::new(&gauge);
        accounting.timeout();
        assert_eq!(gauge.load(Ordering::SeqCst), 1);
        accounting.complete();
        accounting.complete();
        assert_eq!(gauge.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn stuck_accounting_timeout_complete_collision_balances() {
        // Forced collisions, not sleeps: both sides enter past a barrier
        // simultaneously 500 times, so the mutex sees both orders across
        // iterations. Every pair must net to zero — any non-atomicity in
        // the handshake would leak +1 or underflow.
        use std::sync::Barrier;
        static COLLISION_GAUGE: AtomicUsize = AtomicUsize::new(0);
        for _ in 0..500 {
            let accounting = StuckCallAccounting::new(&COLLISION_GAUGE);
            let barrier = Barrier::new(2);
            std::thread::scope(|s| {
                s.spawn(|| {
                    barrier.wait();
                    accounting.timeout();
                });
                barrier.wait();
                accounting.complete();
            });
            assert_eq!(
                COLLISION_GAUGE.load(Ordering::SeqCst),
                0,
                "every timeout/complete collision must balance"
            );
        }
    }

    #[tokio::test]
    async fn stuck_accounting_completion_after_timeout_balances_gauge() {
        // Rendezvous-forced order: the timeout observably fires first
        // (FUNCTION_FAILED + gauge 1), then the release lets the FFI
        // return. The late completion must free both the stuck slot and
        // the breaker slot — no leaked +1 either side.
        static LATE_TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);
        static LATE_TEST_GAUGE: AtomicUsize = AtomicUsize::new(0);
        let (unstick_tx, unstick_rx) = std::sync::mpsc::channel::<()>();

        let result = spawn_backend_core(
            &LATE_TEST_COUNTER,
            &LATE_TEST_GAUGE,
            Duration::from_millis(50),
            8,
            move || {
                let _ = unstick_rx.recv();
                Ok(0u8)
            },
        )
        .await;
        assert_eq!(result.expect("no transport error").unwrap_err(), CkRv::FUNCTION_FAILED);
        assert_eq!(LATE_TEST_GAUGE.load(Ordering::Relaxed), 1);

        unstick_tx.send(()).expect("receiver alive");
        for _ in 0..400 {
            if LATE_TEST_GAUGE.load(Ordering::Relaxed) == 0
                && LATE_TEST_COUNTER.load(Ordering::Relaxed) == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            LATE_TEST_GAUGE.load(Ordering::Relaxed),
            0,
            "late completion releases the stuck slot"
        );
        assert_eq!(
            LATE_TEST_COUNTER.load(Ordering::Relaxed),
            0,
            "late completion releases the breaker slot"
        );
    }

    #[tokio::test]
    async fn stuck_accounting_task_panic_after_timeout_balances_gauge() {
        // The completion guard drops on task unwind: a panic after the
        // timeout published must still release the stuck slot.
        static PANIC_LATE_COUNTER: AtomicUsize = AtomicUsize::new(0);
        static PANIC_LATE_GAUGE: AtomicUsize = AtomicUsize::new(0);
        let (unstick_tx, unstick_rx) = std::sync::mpsc::channel::<()>();

        let result = spawn_backend_core(
            &PANIC_LATE_COUNTER,
            &PANIC_LATE_GAUGE,
            Duration::from_millis(50),
            8,
            move || -> CkResult<u8> {
                let _ = unstick_rx.recv();
                panic!("T08 fixture: panic after timeout");
            },
        )
        .await;
        assert_eq!(result.expect("no transport error").unwrap_err(), CkRv::FUNCTION_FAILED);
        assert_eq!(PANIC_LATE_GAUGE.load(Ordering::Relaxed), 1);

        unstick_tx.send(()).expect("receiver alive");
        for _ in 0..400 {
            if PANIC_LATE_GAUGE.load(Ordering::Relaxed) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            PANIC_LATE_GAUGE.load(Ordering::Relaxed),
            0,
            "unwind completion releases the stuck slot"
        );
    }

    #[tokio::test]
    async fn stuck_accounting_task_panic_before_timeout_never_increments() {
        // A panic before any timeout: the guard observes Running →
        // Completed, so the gauge never moves. Deterministic — the spawn
        // returns only after the task (and its guard) finished.
        static PANIC_FAST_COUNTER: AtomicUsize = AtomicUsize::new(0);
        static PANIC_FAST_GAUGE: AtomicUsize = AtomicUsize::new(0);
        let result = spawn_backend_core(
            &PANIC_FAST_COUNTER,
            &PANIC_FAST_GAUGE,
            Duration::from_secs(30),
            8,
            || -> CkResult<u8> {
                panic!("T08 fixture: panic before timeout");
            },
        )
        .await;
        assert!(result.is_err(), "blocking-task panic surfaces as Status");
        assert_eq!(PANIC_FAST_GAUGE.load(Ordering::SeqCst), 0);
        assert_eq!(PANIC_FAST_COUNTER.load(Ordering::SeqCst), 0, "breaker slot frees on panic");
    }

    #[tokio::test]
    async fn stuck_accounting_caller_cancellation_leaves_no_stuck_count() {
        // Caller cancellation drops the timeout future (no timeout() call)
        // while the task still runs: the later completion observes Running
        // → Completed, and no guard is released early.
        static CANCEL_TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);
        static CANCEL_TEST_GAUGE: AtomicUsize = AtomicUsize::new(0);
        let (unstick_tx, unstick_rx) = std::sync::mpsc::channel::<()>();

        let rpc = tokio::spawn(spawn_backend_core(
            &CANCEL_TEST_COUNTER,
            &CANCEL_TEST_GAUGE,
            Duration::from_secs(30),
            8,
            move || {
                let _ = unstick_rx.recv();
                Ok(0u8)
            },
        ));
        for _ in 0..400 {
            if CANCEL_TEST_COUNTER.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            CANCEL_TEST_COUNTER.load(Ordering::Relaxed),
            1,
            "slot acquired before cancellation"
        );

        rpc.abort();
        let aborted = rpc.await.expect_err("aborted join must err");
        assert!(aborted.is_cancelled());
        assert_eq!(
            CANCEL_TEST_COUNTER.load(Ordering::Relaxed),
            1,
            "cancellation must not release the breaker slot"
        );

        unstick_tx.send(()).expect("receiver alive");
        for _ in 0..400 {
            if CANCEL_TEST_GAUGE.load(Ordering::Relaxed) == 0
                && CANCEL_TEST_COUNTER.load(Ordering::Relaxed) == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(CANCEL_TEST_GAUGE.load(Ordering::Relaxed), 0);
        assert_eq!(CANCEL_TEST_COUNTER.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn fast_call_never_counts_as_stuck() {
        let baseline = stuck_backend_calls();
        let result = spawn_backend(|| Ok(7u8)).await;
        assert_eq!(result.expect("ok").unwrap(), 7);
        assert_eq!(stuck_backend_calls(), baseline);
    }

    #[tokio::test]
    async fn spawn_backend_returns_ok_for_fast_operation() {
        let result = spawn_backend(|| Ok(42u64)).await;
        let inner = result.expect("spawn_backend should not return Status error");
        assert_eq!(inner.unwrap(), 42);
    }

    #[tokio::test]
    async fn spawn_backend_propagates_ck_rv_error() {
        let result = spawn_backend(|| Err::<(), _>(CkRv::TOKEN_NOT_PRESENT)).await;
        let inner = result.expect("spawn_backend should not return Status error");
        assert_eq!(inner.unwrap_err(), CkRv::TOKEN_NOT_PRESENT);
    }

    #[test]
    fn backend_call_acquire_enforces_limit_without_overshoot() {
        // The guard is 'static so it can travel into blocking tasks.
        static LIMIT_TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);
        let counter = &LIMIT_TEST_COUNTER;
        let max = 3;

        let first = try_acquire_backend_call(counter, max).expect("first slot");
        let second = try_acquire_backend_call(counter, max).expect("second slot");
        let third = try_acquire_backend_call(counter, max).expect("third slot");

        assert_eq!(counter.load(Ordering::Relaxed), max);
        assert!(try_acquire_backend_call(counter, max).is_none());
        assert_eq!(
            counter.load(Ordering::Relaxed),
            max,
            "failed acquisition must not overshoot the configured bound"
        );

        drop(second);
        assert_eq!(counter.load(Ordering::Relaxed), max - 1);

        let replacement =
            try_acquire_backend_call(counter, max).expect("slot released by dropped guard");
        assert_eq!(counter.load(Ordering::Relaxed), max);

        drop(first);
        drop(third);
        drop(replacement);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    /// Health-event classification tests use the pure
    /// `classify_backend_outcome` helper rather than driving
    /// `spawn_backend` end-to-end. The end-to-end path is exercised
    /// at runtime by `spawn_backend_health_gate` in `main.rs`; in
    /// unit tests it races on the global `HEALTH_EVENT_TX` OnceLock
    /// when other tests run in parallel.

    #[test]
    fn classify_ok_is_healthy() {
        let result: Result<CkResult<u64>, Status> = Ok(Ok(42));
        assert!(classify_backend_outcome(&result));
    }

    #[test]
    fn classify_pkcs11_application_error_is_healthy() {
        // CKR_PIN_INCORRECT, CKR_DATA_INVALID, etc. are normal
        // application-level outcomes — they must NOT trip the
        // readiness gauge, or a noisy auth user would take the
        // daemon out of rotation.
        for rv in [
            CkRv::PIN_INCORRECT,
            CkRv::DATA_INVALID,
            CkRv::MECHANISM_INVALID,
            CkRv::SESSION_HANDLE_INVALID,
            CkRv::USER_NOT_LOGGED_IN,
        ] {
            let result: Result<CkResult<()>, Status> = Ok(Err(rv));
            assert!(
                classify_backend_outcome(&result),
                "CkRv {:?} must be classified as healthy",
                rv
            );
        }
    }

    #[test]
    fn classify_backend_returned_device_error_and_token_not_present_are_healthy() {
        // M1: a backend-RETURNED CKR_DEVICE_ERROR (kryoptic's request-specific
        // catch-all) or CKR_TOKEN_NOT_PRESENT is a per-request response, not a
        // daemon-health signal — they must NOT flip readiness, or one noisy
        // client could evict the pod. The daemon's own timeout/breaker RVs
        // (FUNCTION_FAILED / HOST_MEMORY) are reported separately in
        // spawn_backend before classification.
        for rv in [CkRv::DEVICE_ERROR, CkRv::TOKEN_NOT_PRESENT] {
            let result: Result<CkResult<()>, Status> = Ok(Err(rv));
            assert!(
                classify_backend_outcome(&result),
                "backend-returned CkRv {:?} must be classified as healthy",
                rv
            );
        }
    }

    #[test]
    fn classify_genuine_hsm_down_signals_are_unhealthy() {
        // CKR_HOST_MEMORY (HSM out of memory) and CKR_DEVICE_REMOVED (HSM
        // disconnected) report that the device itself is down — not inducible
        // by one client's request shape — so they remain readiness signals.
        for rv in [CkRv::HOST_MEMORY, CkRv::DEVICE_REMOVED] {
            let result: Result<CkResult<()>, Status> = Ok(Err(rv));
            assert!(
                !classify_backend_outcome(&result),
                "CkRv {:?} must be classified as unhealthy",
                rv
            );
        }
    }

    #[test]
    fn classify_transport_status_is_unhealthy() {
        // `Err(Status)` from spawn_task means a blocking-pool panic
        // or otherwise unrecoverable backend interaction — always
        // unhealthy.
        let result: Result<CkResult<()>, Status> = Err(Status::internal("backend panicked"));
        assert!(!classify_backend_outcome(&result));
    }

    #[tokio::test]
    async fn circuit_breaker_trips_at_limit() {
        // Temporarily set IN_FLIGHT to a value at/above max to trigger the breaker.
        let max = max_concurrent_backend_calls();
        let previous = IN_FLIGHT.load(Ordering::Relaxed);
        IN_FLIGHT.store(max, Ordering::Relaxed);

        let result = spawn_backend(|| Ok(())).await;
        let inner = result.expect("spawn_backend should not return Status error");
        assert_eq!(
            inner.unwrap_err(),
            CkRv::HOST_MEMORY,
            "W1-L3-01: breaker trip surfaces HOST_MEMORY (was DEVICE_ERROR)"
        );

        // Restore previous value so other tests are not affected.
        IN_FLIGHT.store(previous, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn resolve_two_objects_forwards_unknown_first_object_to_backend() {
        use pkcs11_proxy_ng_backend::MockBackend;
        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> =
            Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let (session, known_object) = ctx_mgr
            .get_context(&ctx_id, |c| {
                let session = c.register_session(
                    BackendHandle(123),
                    crate::server::slot_map::BackendSlotId(CkSlotId(7)),
                );
                let object = c.object_handles.insert(BackendHandle(456));
                (session, object)
            })
            .await
            .unwrap();

        let result = resolve_session_and_two_objects(&ctx, &ctx_id, session.0, 999, known_object.0)
            .await
            .unwrap();

        assert_eq!(result, (CkSessionHandle(123), CkObjectHandle(0), CkObjectHandle(456)));
    }

    #[tokio::test]
    async fn resolve_two_objects_forwards_unknown_second_object_to_backend() {
        use pkcs11_proxy_ng_backend::MockBackend;
        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> =
            Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let (session, known_object) = ctx_mgr
            .get_context(&ctx_id, |c| {
                let session = c.register_session(
                    BackendHandle(123),
                    crate::server::slot_map::BackendSlotId(CkSlotId(7)),
                );
                let object = c.object_handles.insert(BackendHandle(456));
                (session, object)
            })
            .await
            .unwrap();

        let result = resolve_session_and_two_objects(&ctx, &ctx_id, session.0, known_object.0, 999)
            .await
            .unwrap();

        assert_eq!(result, (CkSessionHandle(123), CkObjectHandle(456), CkObjectHandle(0)));
    }

    // --- per-object gate tests (G3-PR1 Task 3) ---

    /// Build a [`TokenPolicy`] with a per-object `objects` grant allowing only
    /// the hex-encoded `allowed_uid`.
    fn per_object_policy(
        identity: &str,
        token_label: &str,
        allowed_uid_hex: &str,
    ) -> Arc<crate::server::auth::policy::TokenPolicy> {
        use crate::config::{
            AuthConfig, ExtractPolicyConfig, GrantSpec, PolicyEntry, RichGrantConfig,
            TokenAccessSpec,
        };
        Arc::new(
            crate::server::auth::policy::TokenPolicy::from_config(&AuthConfig {
                allow_all_authenticated: false,
                anonymous_principal: None,
                policy: vec![PolicyEntry {
                    identity: identity.into(),
                    tokens: TokenAccessSpec::Specific(vec![GrantSpec::Rich(RichGrantConfig {
                        token: format!("label:{token_label}"),
                        classes: None,
                        mechanisms: None,
                        extract: ExtractPolicyConfig::Allow,
                        objects: Some(vec![crate::config::ObjectAclSpec::Bare(
                            allowed_uid_hex.into(),
                        )]),
                    })]),
                }],
            })
            .expect("per-object policy must parse"),
        )
    }

    /// Build a [`TokenPolicy`] with a per-class `classes` grant (no object restriction).
    fn per_class_policy(
        identity: &str,
        token_label: &str,
        allowed_classes: Vec<&str>,
    ) -> Arc<crate::server::auth::policy::TokenPolicy> {
        use crate::config::{
            AuthConfig, ExtractPolicyConfig, GrantSpec, PolicyEntry, RichGrantConfig,
            TokenAccessSpec,
        };
        Arc::new(
            crate::server::auth::policy::TokenPolicy::from_config(&AuthConfig {
                allow_all_authenticated: false,
                anonymous_principal: None,
                policy: vec![PolicyEntry {
                    identity: identity.into(),
                    tokens: TokenAccessSpec::Specific(vec![GrantSpec::Rich(RichGrantConfig {
                        token: format!("label:{token_label}"),
                        classes: Some(allowed_classes.into_iter().map(Into::into).collect()),
                        mechanisms: None,
                        extract: ExtractPolicyConfig::Allow,
                        objects: None,
                    })]),
                }],
            })
            .expect("per-class policy must parse"),
        )
    }

    /// Set up a MockBackend with an initialized session and one object on slot 0.
    /// The object has CLASS and TOKEN set (required by `fetch_object_metadata`'s
    /// 3-element template). Returns `(ctx, ctx_id, virtual_session, virtual_object)`.
    async fn setup_per_object_test(
        policy: Arc<crate::server::auth::policy::TokenPolicy>,
        identity: Option<String>,
        uid_bytes: Option<Vec<u8>>,
    ) -> (HandlerContext, crate::server::context_manager::ClientContextId, u64, u64) {
        setup_per_object_test_with_class(
            policy,
            identity,
            uid_bytes,
            CkObjectClass::SECRET_KEY,
            false,
        )
        .await
    }

    /// Extended setup: also configures CKA_CLASS and CKA_TOKEN on the test object.
    async fn setup_per_object_test_with_class(
        policy: Arc<crate::server::auth::policy::TokenPolicy>,
        identity: Option<String>,
        uid_bytes: Option<Vec<u8>>,
        class: CkObjectClass,
        is_token: bool,
    ) -> (HandlerContext, crate::server::context_manager::ClientContextId, u64, u64) {
        use pkcs11_proxy_ng_backend::{MockBackend, mock::MockAttributeSlot};
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION;
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        let backend_object = mock.create_object(backend_session, Some(&[])).unwrap();

        // Always set CLASS and TOKEN (required by fetch_object_metadata's 3-element
        // template — all conformant PKCS#11 backends expose these on every object).
        mock.set_attribute(
            backend_object,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(class.0)),
        );
        mock.set_attribute(
            backend_object,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(is_token)),
        );
        if let Some(uid) = uid_bytes {
            mock.set_attribute(
                backend_object,
                CkAttributeType::UNIQUE_ID,
                MockAttributeSlot::Value(CkAttributeValue::Bytes(uid.into())),
            );
        }

        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx_id = ctx_mgr.create_context(identity).await.unwrap();

        let (virtual_session, virtual_object) = ctx_mgr
            .get_context(&ctx_id, |c| {
                let vs = c.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                );
                let vo = c.object_handles.insert(BackendHandle(backend_object.0));
                (vs, vo)
            })
            .await
            .unwrap();

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;
        (ctx, ctx_id, virtual_session.0, virtual_object.0)
    }

    /// The uid "aabbcc" → hex-encoded bytes [0xaa, 0xbb, 0xcc].
    const ALLOWED_UID_HEX: &str = "aabbcc";
    const ALLOWED_UID_BYTES: [u8; 3] = [0xaa, 0xbb, 0xcc];
    const OTHER_UID_BYTES: [u8; 3] = [0x11, 0x22, 0x33];
    const IDENTITY: &str = "uid=1000";

    #[tokio::test]
    async fn per_object_gate_inactive_is_transparent() {
        // When no grant has `objects`, per_object_active()==false and the gate
        // must be a zero-overhead pass-through for all objects.
        use pkcs11_proxy_ng_backend::MockBackend;
        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> =
            Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend); // default policy: no objects
        assert!(
            !ctx.token_policy.per_object_active(),
            "default policy must have per_object_active()==false"
        );

        let ctx_id = ctx_mgr.create_context(Some(IDENTITY.into())).await.unwrap();
        let (vs, vo) = ctx_mgr
            .get_context(&ctx_id, |c| {
                let vs = c.register_session(
                    BackendHandle(77),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                );
                let vo = c.object_handles.insert(BackendHandle(42));
                (vs, vo)
            })
            .await
            .unwrap();

        let (_, backend_obj) = resolve_session_and_object(&ctx, &ctx_id, vs.0, vo.0).await.unwrap();
        // Gate is inactive → real backend handle returned unchanged.
        assert_eq!(backend_obj, CkObjectHandle(42), "inactive gate must return real handle");
    }

    #[tokio::test]
    async fn t7_session_key_and_object_resolvers_agree() {
        // W1-L11-05 characterization: resolve_session_and_key and
        // resolve_session_and_object must return identical results for
        // identical inputs (ok, forward-0, unknown session, unknown
        // context). Must pass before AND after the delegation DRY.
        use pkcs11_proxy_ng_backend::MockBackend;
        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> =
            Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend); // default policy: no grants
        let ctx_id = ctx_mgr.create_context(Some(IDENTITY.into())).await.unwrap();
        let (vs, vo) = ctx_mgr
            .get_context(&ctx_id, |c| {
                let vs = c.register_session(
                    BackendHandle(77),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                );
                let vo = c.object_handles.insert(BackendHandle(42));
                (vs, vo)
            })
            .await
            .unwrap();

        // Known session + known handle: identical (session, object).
        let via_key = resolve_session_and_key(&ctx, &ctx_id, vs.0, vo.0).await;
        let via_object = resolve_session_and_object(&ctx, &ctx_id, vs.0, vo.0).await;
        assert_eq!(via_key, via_object, "ok-case results must match");
        assert_eq!(via_object.unwrap(), (CkSessionHandle(77), CkObjectHandle(42)));

        // Unknown handle: both forward CK_INVALID_HANDLE (0) to the backend.
        let via_key = resolve_session_and_key(&ctx, &ctx_id, vs.0, 9_999_999).await;
        let via_object = resolve_session_and_object(&ctx, &ctx_id, vs.0, 9_999_999).await;
        assert_eq!(via_key, via_object, "forward-0 results must match");
        assert_eq!(via_object.unwrap().1, CkObjectHandle(0));

        // Unknown session: both SESSION_HANDLE_INVALID.
        let via_key = resolve_session_and_key(&ctx, &ctx_id, 9_999_999, vo.0).await;
        let via_object = resolve_session_and_object(&ctx, &ctx_id, 9_999_999, vo.0).await;
        assert_eq!(via_key, via_object, "unknown-session errors must match");
        assert_eq!(via_object.unwrap_err(), CkRv::SESSION_HANDLE_INVALID);

        // Unknown context: both CRYPTOKI_NOT_INITIALIZED.
        let gone = ClientContextId("t7-gone".into());
        let via_key = resolve_session_and_key(&ctx, &gone, vs.0, vo.0).await;
        let via_object = resolve_session_and_object(&ctx, &gone, vs.0, vo.0).await;
        assert_eq!(via_key, via_object, "unknown-context errors must match");
        assert_eq!(via_object.unwrap_err(), CkRv::CRYPTOKI_NOT_INITIALIZED);
    }

    #[tokio::test]
    async fn t7_resolve_session_slot_login_pins_triple_read() {
        // W1-L11-16 characterization: pin the (session, slot, login-state)
        // triple read and its RV mapping. Moved here with the helper from
        // auth.rs; assertions unchanged — the single-locked-read semantics
        // must survive the shared-helper routing.
        use pkcs11_proxy_ng_backend::MockBackend;
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        let backend_session = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();

        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let backend_slot = crate::server::slot_map::BackendSlotId(CkSlotId(0));
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(BackendHandle(backend_session.0), backend_slot)
            })
            .await
            .unwrap();

        // Unknown context → CRYPTOKI_NOT_INITIALIZED.
        let gone = ClientContextId("t7-gone".into());
        assert_eq!(
            resolve_session_slot_login(&ctx_mgr, &gone, session_vh.0).await.unwrap_err(),
            CkRv::CRYPTOKI_NOT_INITIALIZED
        );
        // Unknown session → SESSION_HANDLE_INVALID.
        assert_eq!(
            resolve_session_slot_login(&ctx_mgr, &ctx_id, 9_999_999).await.unwrap_err(),
            CkRv::SESSION_HANDLE_INVALID
        );
        // Known session, nobody logged in → (backend session, slot, None).
        assert_eq!(
            resolve_session_slot_login(&ctx_mgr, &ctx_id, session_vh.0).await.unwrap(),
            (CkSessionHandle(backend_session.0), backend_slot, None)
        );
        // Logged-in slot → current login state is reported.
        ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.login_state.insert(backend_slot, LoginState::User);
            })
            .await;
        assert_eq!(
            resolve_session_slot_login(&ctx_mgr, &ctx_id, session_vh.0).await.unwrap(),
            (CkSessionHandle(backend_session.0), backend_slot, Some(LoginState::User))
        );
    }

    #[tokio::test]
    async fn per_object_gate_allows_permitted_object() {
        // Principal P is allowed only objects with unique_id ALLOWED_UID.
        // Using an object with that uid must return the real backend handle.
        let policy = per_object_policy(IDENTITY, "MockToken", ALLOWED_UID_HEX);
        let (ctx, ctx_id, vs, vo) =
            setup_per_object_test(policy, Some(IDENTITY.into()), Some(ALLOWED_UID_BYTES.to_vec()))
                .await;

        let (_, backend_obj) = resolve_session_and_object(&ctx, &ctx_id, vs, vo).await.unwrap();
        assert_ne!(
            backend_obj,
            CkObjectHandle(0),
            "permitted object must return the real backend handle"
        );
    }

    #[tokio::test]
    async fn per_object_gate_denied_object_identical_to_nonexistent() {
        // The invisible-denial contract (ADR-0012 §G3): using an object whose
        // unique_id is NOT in the allowed list must produce CkObjectHandle(0),
        // byte-for-byte identical to what a genuinely-nonexistent handle produces.
        // The test also verifies that no audit sink fires (ctx.audit is None).
        let policy = per_object_policy(IDENTITY, "MockToken", ALLOWED_UID_HEX);
        // Object exists in the backend but has a DIFFERENT unique_id.
        let (ctx, ctx_id, vs, vo) =
            setup_per_object_test(policy, Some(IDENTITY.into()), Some(OTHER_UID_BYTES.to_vec()))
                .await;

        // Denied object: unique_id ∉ allowed list → CkObjectHandle(0).
        let (_, denied_backend_obj) =
            resolve_session_and_object(&ctx, &ctx_id, vs, vo).await.unwrap();

        // Nonexistent-handle path: resolve a virtual handle that is not in the map.
        let (_, nonexistent_backend_obj) =
            resolve_session_and_object(&ctx, &ctx_id, vs, 9_999_999).await.unwrap();

        assert_eq!(
            denied_backend_obj, nonexistent_backend_obj,
            "denied object and nonexistent object must produce the SAME backend handle (invisible denial)"
        );
        assert_eq!(
            denied_backend_obj,
            CkObjectHandle(0),
            "both paths must produce the not-found sentinel CkObjectHandle(0)"
        );
        // No audit sink is wired in for_test, guaranteeing no distinct audit record.
        assert!(
            ctx.audit.is_none(),
            "test context must have no audit sink (invisible-denial: no audit on deny)"
        );
    }

    #[tokio::test]
    async fn per_object_gate_fail_closed_on_empty_unique_id() {
        // Fail-closed: a real object with an absent/empty CKA_UNIQUE_ID must be
        // denied (handle 0), even though the backend handle is non-zero.
        let policy = per_object_policy(IDENTITY, "MockToken", ALLOWED_UID_HEX);
        // uid_bytes=None → no CKA_UNIQUE_ID set on the object.
        let (ctx, ctx_id, vs, vo) =
            setup_per_object_test(policy, Some(IDENTITY.into()), None).await;

        let (_, backend_obj) = resolve_session_and_object(&ctx, &ctx_id, vs, vo).await.unwrap();
        assert_eq!(
            backend_obj,
            CkObjectHandle(0),
            "object with no CKA_UNIQUE_ID must be denied (handle 0)"
        );
    }

    // --- per-class gate tests (G3-PR3 Task 1) ---

    #[tokio::test]
    async fn per_class_gate_denies_wrong_class() {
        // A principal confined to SECRET_KEY objects must not use a PUBLIC_KEY object.
        // The denial must be byte-identical to a non-existent object (invisible denial).
        let policy = per_class_policy(IDENTITY, "MockToken", vec!["secret_key"]);
        let uid = ALLOWED_UID_BYTES.to_vec(); // uid is valid; only class is wrong
        let (ctx, ctx_id, vs, vo) = setup_per_object_test_with_class(
            policy,
            Some(IDENTITY.into()),
            Some(uid),
            CkObjectClass::PUBLIC_KEY, // wrong class — principal is restricted to SECRET_KEY
            false,
        )
        .await;

        let (_, backend_obj) = resolve_session_and_object(&ctx, &ctx_id, vs, vo).await.unwrap();
        assert_eq!(
            backend_obj,
            CkObjectHandle(0),
            "PUBLIC_KEY object must be denied for a principal confined to secret_key"
        );
    }

    #[tokio::test]
    async fn per_class_gate_allows_correct_class() {
        // A principal confined to SECRET_KEY objects CAN use a SECRET_KEY object.
        let policy = per_class_policy(IDENTITY, "MockToken", vec!["secret_key"]);
        let uid = ALLOWED_UID_BYTES.to_vec();
        let (ctx, ctx_id, vs, vo) = setup_per_object_test_with_class(
            policy,
            Some(IDENTITY.into()),
            Some(uid),
            CkObjectClass::SECRET_KEY, // correct class
            false,
        )
        .await;

        let (_, backend_obj) = resolve_session_and_object(&ctx, &ctx_id, vs, vo).await.unwrap();
        assert_ne!(
            backend_obj,
            CkObjectHandle(0),
            "SECRET_KEY object must be allowed for a principal confined to secret_key"
        );
    }

    #[tokio::test]
    async fn per_class_gate_inactive_is_transparent() {
        // When no grant has `classes`, per_class_active()==false and the gate must
        // not perform any class check. Use per_object_inactive policy (no objects,
        // no classes) to verify the gate is skipped entirely.
        use pkcs11_proxy_ng_backend::MockBackend;
        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> =
            Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        assert!(
            !ctx.token_policy.per_class_active(),
            "default policy must have per_class_active()==false"
        );

        let ctx_id = ctx_mgr.create_context(Some(IDENTITY.into())).await.unwrap();
        let (vs, vo) = ctx_mgr
            .get_context(&ctx_id, |c| {
                let vs = c.register_session(
                    BackendHandle(77),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                );
                let vo = c.object_handles.insert(BackendHandle(42));
                (vs, vo)
            })
            .await
            .unwrap();

        let (_, backend_obj) = resolve_session_and_object(&ctx, &ctx_id, vs.0, vo.0).await.unwrap();
        // Gate is inactive → real backend handle returned unchanged.
        assert_eq!(backend_obj, CkObjectHandle(42), "inactive class gate must return real handle");
    }

    #[tokio::test]
    async fn per_object_gate_token_object_cached_until_revoked() {
        // W1-L13-18: a token object (is_token=true) IS cached, gated by the
        // authz generation. Two consecutive gated uses issue one backend
        // fetch; revoking the generation forces a re-fetch.
        use pkcs11_proxy_ng_backend::{MockBackend, mock::MockAttributeSlot};
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION;
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        let backend_object = mock.create_object(backend_session, Some(&[])).unwrap();

        // Mark as TOKEN object.
        mock.set_attribute(
            backend_object,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        );
        mock.set_attribute(
            backend_object,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(true)), // token object
        );
        let uid = ALLOWED_UID_BYTES.to_vec();
        mock.set_attribute(
            backend_object,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(uid.clone().into())),
        );
        // Public object (native default): the D6(1) logged-out USE check then
        // needs no per-operation backend probe, so the mock counter below
        // observes metadata fetches only.
        mock.set_attribute(
            backend_object,
            CkAttributeType::PRIVATE,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );

        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> = mock.clone();
        let policy = per_object_policy(IDENTITY, "MockToken", ALLOWED_UID_HEX);
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx_id = ctx_mgr.create_context(Some(IDENTITY.into())).await.unwrap();
        let (virtual_session, virtual_object) = ctx_mgr
            .get_context(&ctx_id, |c| {
                let vs = c.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                );
                let vo = c.object_handles.insert(BackendHandle(backend_object.0));
                // Record the known-public bit (as mint registration would) so
                // logged-out USE skips the backend privacy probe.
                c.object_private.insert(vo, false);
                (vs, vo)
            })
            .await
            .unwrap();
        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;

        let calls_before = mock.attr_get_call_count();
        // First gated use — must fetch from the backend.
        let first = resolve_session_and_object(&ctx, &ctx_id, virtual_session.0, virtual_object.0)
            .await
            .unwrap();
        let calls_after_first = mock.attr_get_call_count();
        assert!(
            calls_after_first > calls_before,
            "first gated use must fetch token metadata from the backend"
        );

        // Second gated use — generation still current, no re-fetch.
        let second = resolve_session_and_object(&ctx, &ctx_id, virtual_session.0, virtual_object.0)
            .await
            .unwrap();
        assert_eq!(
            mock.attr_get_call_count(),
            calls_after_first,
            "repeated gated use of a token object must not re-fetch"
        );
        assert_eq!(first, second, "gated reuse must resolve identically");

        // The entry is cached under the virtual handle.
        let cached = ctx_mgr.object_metadata(&ctx_id, virtual_object.0).await;
        assert!(
            cached.is_some_and(|meta| meta.is_token),
            "token object metadata must be cached within the generation"
        );

        // Revocation invalidates: the entry reads as a miss and the next
        // gated use re-fetches from the backend.
        ctx_mgr.revoke_authz_generation();
        assert!(
            ctx_mgr.object_metadata(&ctx_id, virtual_object.0).await.is_none(),
            "revoking the authz generation must invalidate cached token metadata"
        );
        let _ = resolve_session_and_object(&ctx, &ctx_id, virtual_session.0, virtual_object.0)
            .await
            .unwrap();
        assert!(
            mock.attr_get_call_count() > calls_after_first,
            "gated use after revocation must re-fetch from the backend"
        );
    }

    // --- minted-object ACL inheritance tests (G3-PR3 Task 2) ---

    /// A confined principal can use a key it just GENERATED, even when the
    /// backend-assigned CKA_UNIQUE_ID is not in its pre-configured objects list.
    /// This is the core usability regression described in G3-PR3 Task 2.
    #[tokio::test]
    async fn minted_object_usable_by_creator_despite_uid_not_in_list() {
        use pkcs11_proxy_ng_backend::{MockBackend, mock::MockAttributeSlot};
        // Policy: principal may only use ALLOWED_UID objects.
        let policy = per_object_policy(IDENTITY, "MockToken", ALLOWED_UID_HEX);

        // Create a backend object whose UID is OTHER_UID (NOT in the allowed list).
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION;
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        let backend_object = mock.create_object(backend_session, Some(&[])).unwrap();
        mock.set_attribute(
            backend_object,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        );
        mock.set_attribute(
            backend_object,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        // UID is NOT in the allowed list.
        mock.set_attribute(
            backend_object,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(OTHER_UID_BYTES.to_vec().into())),
        );

        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx_id = ctx_mgr.create_context(Some(IDENTITY.into())).await.unwrap();

        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();

        // Register via the MINTING path (register_session_object_handle), which
        // inserts the virtual handle into created_objects.
        let virtual_object_raw = register_session_object_handle(
            &ctx_mgr,
            &ctx_id,
            virtual_session,
            backend_object,
            false, // session object
            None,  // privacy unknown (fixture bypasses real minting)
        )
        .await;
        assert_ne!(virtual_object_raw, 0, "minting registration must return a non-zero handle");

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;

        // Despite uid NOT being in the allowed list, the creator must be allowed.
        let (_, backend_obj) =
            resolve_session_and_object(&ctx, &ctx_id, virtual_session.0, virtual_object_raw)
                .await
                .unwrap();
        assert_ne!(
            backend_obj,
            CkObjectHandle(0),
            "confined creator must be able to use a key it minted, even if uid ∉ allowed list"
        );
        assert_eq!(
            backend_obj.0, backend_object.0,
            "creator must receive the REAL backend handle, not a substitute"
        );
    }

    /// A found (non-minted) object whose uid is NOT in the principal's objects
    /// list must STILL be denied — the creator bypass does not affect find results.
    #[tokio::test]
    async fn found_object_not_in_list_still_denied() {
        // Reuse the existing setup helper: it uses object_handles.insert directly
        // (not the minting path), so the object is NOT in created_objects.
        let policy = per_object_policy(IDENTITY, "MockToken", ALLOWED_UID_HEX);
        let (ctx, ctx_id, vs, vo) =
            setup_per_object_test(policy, Some(IDENTITY.into()), Some(OTHER_UID_BYTES.to_vec()))
                .await;

        let (_, backend_obj) = resolve_session_and_object(&ctx, &ctx_id, vs, vo).await.unwrap();
        assert_eq!(
            backend_obj,
            CkObjectHandle(0),
            "found object with uid ∉ allowed list must still be denied (gate unchanged for non-minted)"
        );
    }

    /// Cross-context: context A mints an object; the same backend object
    /// surfaced to context B (B did NOT mint it) must be gated by B's own
    /// policy — B's created_objects set is empty for this object.
    #[tokio::test]
    async fn minted_object_cross_context_still_gated() {
        use pkcs11_proxy_ng_backend::{MockBackend, mock::MockAttributeSlot};
        let policy_a = per_object_policy(IDENTITY, "MockToken", ALLOWED_UID_HEX);
        let policy_b = per_object_policy("uid=9999", "MockToken", ALLOWED_UID_HEX);

        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION;
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        let backend_object = mock.create_object(backend_session, Some(&[])).unwrap();
        mock.set_attribute(
            backend_object,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        );
        mock.set_attribute(
            backend_object,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            backend_object,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(OTHER_UID_BYTES.to_vec().into())),
        );

        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );

        // Context A: IDENTITY mints the object.
        let ctx_id_a = ctx_mgr.create_context(Some(IDENTITY.into())).await.unwrap();
        let vs_a = ctx_mgr
            .get_context(&ctx_id_a, |c| {
                c.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();
        let vo_a_raw =
            register_session_object_handle(&ctx_mgr, &ctx_id_a, vs_a, backend_object, false, None)
                .await;

        // Context B: uid=9999 sees the SAME backend object (e.g. via an out-of-band
        // find) but did NOT mint it — registered via direct insert, not minting.
        let ctx_id_b = ctx_mgr.create_context(Some("uid=9999".into())).await.unwrap();
        let vo_b_raw = ctx_mgr
            .get_context(&ctx_id_b, |c| {
                let vs_b = c.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                );
                // B registers the handle as a find result (NOT via register_session_object_handle).
                let vo_b = c.object_handles.insert(BackendHandle(backend_object.0));
                (vs_b.0, vo_b.0)
            })
            .await
            .unwrap();

        // Context A's gate: creator → allow.
        let mut ctx_a = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx_a.token_policy = policy_a;
        let (_, result_a) =
            resolve_session_and_object(&ctx_a, &ctx_id_a, vs_a.0, vo_a_raw).await.unwrap();
        assert_ne!(
            result_a,
            CkObjectHandle(0),
            "context A (creator) must be allowed to use the minted object"
        );

        // Context B's gate: did not mint → uid NOT in list → deny.
        let mut ctx_b = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx_b.token_policy = policy_b;
        let (_, result_b) =
            resolve_session_and_object(&ctx_b, &ctx_id_b, vo_b_raw.0, vo_b_raw.1).await.unwrap();
        assert_eq!(
            result_b,
            CkObjectHandle(0),
            "context B (non-creator) must be denied for an object it did not mint"
        );
    }

    /// After the minting session closes, the created-set entry must be gone
    /// (no stale created-status on handle reuse).
    #[tokio::test]
    async fn minted_object_created_status_gone_after_session_close() {
        use pkcs11_proxy_ng_backend::{MockBackend, mock::MockAttributeSlot};
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION;
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        let backend_object = mock.create_object(backend_session, Some(&[])).unwrap();
        mock.set_attribute(
            backend_object,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        );
        mock.set_attribute(
            backend_object,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)), // session object
        );

        let _backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        let vs = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();

        let vo_raw =
            register_session_object_handle(&ctx_mgr, &ctx_id, vs, backend_object, false, None)
                .await;

        // Verify the object is in the created set before session close.
        let created_before = ctx_mgr.object_was_created_here(&ctx_id, vo_raw).await;
        assert!(created_before, "object must be in created_objects immediately after minting");

        // Close the session — this removes session objects and their created-set entries.
        ctx_mgr
            .get_context(&ctx_id, |c| {
                c.remove_session(vs);
            })
            .await;

        // After session close the virtual handle and its created-status must be gone.
        let created_after = ctx_mgr.object_was_created_here(&ctx_id, vo_raw).await;
        assert!(
            !created_after,
            "created_objects entry must be evicted on session close (no stale created-status)"
        );
    }

    // --- I3/M1: created-object class-gate + no-metadata-fetch for uid-only ---

    /// I3 fix: a principal confined to SECRET_KEY objects cannot use a
    /// PRIVATE_KEY it just minted — the class gate still applies for created objects
    /// when `per_class_active()` is true.
    #[tokio::test]
    async fn i3_minted_private_key_denied_when_class_confined_to_secret_key() {
        use pkcs11_proxy_ng_backend::{MockBackend, mock::MockAttributeSlot};
        let policy = per_class_policy(IDENTITY, "MockToken", vec!["secret_key"]);
        assert!(policy.per_class_active(), "per_class_active must be true");

        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION;
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        let backend_object = mock.create_object(backend_session, Some(&[])).unwrap();
        // PRIVATE_KEY — denied class.
        mock.set_attribute(
            backend_object,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(CkObjectClass::PRIVATE_KEY.0)),
        );
        mock.set_attribute(
            backend_object,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            backend_object,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(OTHER_UID_BYTES.to_vec().into())),
        );

        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx_id = ctx_mgr.create_context(Some(IDENTITY.into())).await.unwrap();

        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();

        // Register via the MINTING path so object is in created_objects.
        let vo_raw = register_session_object_handle(
            &ctx_mgr,
            &ctx_id,
            virtual_session,
            backend_object,
            false,
            None,
        )
        .await;

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;

        let (_, backend_obj) =
            resolve_session_and_object(&ctx, &ctx_id, virtual_session.0, vo_raw).await.unwrap();
        assert_eq!(
            backend_obj,
            CkObjectHandle(0),
            "I3: creator of a PRIVATE_KEY must be denied by class gate (confined to secret_key)"
        );
    }

    /// I3 fix: a principal confined to SECRET_KEY CAN use a SECRET_KEY it minted.
    #[tokio::test]
    async fn i3_minted_secret_key_allowed_when_class_confined_to_secret_key() {
        use pkcs11_proxy_ng_backend::{MockBackend, mock::MockAttributeSlot};
        let policy = per_class_policy(IDENTITY, "MockToken", vec!["secret_key"]);

        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION;
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        let backend_object = mock.create_object(backend_session, Some(&[])).unwrap();
        // SECRET_KEY — allowed class.
        mock.set_attribute(
            backend_object,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        );
        mock.set_attribute(
            backend_object,
            CkAttributeType::TOKEN,
            MockAttributeSlot::Value(CkAttributeValue::Bool(false)),
        );
        mock.set_attribute(
            backend_object,
            CkAttributeType::UNIQUE_ID,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(OTHER_UID_BYTES.to_vec().into())),
        );

        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx_id = ctx_mgr.create_context(Some(IDENTITY.into())).await.unwrap();

        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();

        let vo_raw = register_session_object_handle(
            &ctx_mgr,
            &ctx_id,
            virtual_session,
            backend_object,
            false,
            None,
        )
        .await;

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;

        let (_, backend_obj) =
            resolve_session_and_object(&ctx, &ctx_id, virtual_session.0, vo_raw).await.unwrap();
        assert_ne!(
            backend_obj,
            CkObjectHandle(0),
            "I3: creator of a SECRET_KEY must be allowed by class gate (confined to secret_key)"
        );
        assert_eq!(backend_obj.0, backend_object.0, "I3: must receive the real backend handle");
    }

    /// M1 fix: a uid-only-confined principal (no class grant) that mints an object
    /// must be allowed WITHOUT a metadata fetch. We prove this by creating an object
    /// with NO attributes registered (CLASS/TOKEN/UNIQUE_ID all absent). If the gate
    /// were to fetch metadata, it would get ATTRIBUTE_TYPE_INVALID for all three
    /// attributes → fetch_object_metadata returns None → gate returns CkObjectHandle(0)
    /// (fail-closed). If M1 works correctly: no fetch, real handle returned.
    #[tokio::test]
    async fn m1_uid_only_creator_bypass_requires_no_metadata_fetch() {
        use pkcs11_proxy_ng_backend::MockBackend;
        // uid-only policy: objects restricted, no classes list → per_class_active==false.
        let policy = per_object_policy(IDENTITY, "MockToken", ALLOWED_UID_HEX);
        assert!(!policy.per_class_active(), "uid-only policy must have per_class_active==false");

        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION;
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        let backend_object = mock.create_object(backend_session, Some(&[])).unwrap();
        // Intentionally NO attributes (CLASS, TOKEN, UNIQUE_ID). If the gate fetches
        // metadata, the MockBackend returns ATTRIBUTE_TYPE_INVALID for all three →
        // fetch_object_metadata returns None → gate returns 0 (fail-closed).
        // If M1 works, no fetch occurs and the real handle passes through.

        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx_id = ctx_mgr.create_context(Some(IDENTITY.into())).await.unwrap();

        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();

        // Register via MINTING path (created_objects entry).
        let vo_raw = register_session_object_handle(
            &ctx_mgr,
            &ctx_id,
            virtual_session,
            backend_object,
            false,
            None,
        )
        .await;

        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;

        let (_, backend_obj) =
            resolve_session_and_object(&ctx, &ctx_id, virtual_session.0, vo_raw).await.unwrap();
        assert_ne!(
            backend_obj,
            CkObjectHandle(0),
            "M1: uid-only creator must be allowed without metadata fetch \
             (if fetch occurred the attribute-less object would be fail-closed)"
        );
        assert_eq!(
            backend_obj.0, backend_object.0,
            "M1: must receive the real backend handle, not a substitute"
        );
    }

    // --- Login-lock timeout tests ---

    /// Verify that a timed acquisition fires when the lock is held by another
    /// holder. This is the core DoS-bound property: a slow/wedged backend
    /// login on one session must not queue other tenants indefinitely.
    #[tokio::test]
    async fn login_lock_timeout_fires_when_lock_is_held() {
        let mutex = Arc::new(tokio::sync::Mutex::new(()));
        // Simulate a tenant that holds the login lock (e.g. wedged backend call).
        let _held = mutex.lock().await;
        // A very short timeout must fire because the lock is held.
        let result = tokio::time::timeout(Duration::from_millis(10), mutex.lock()).await;
        assert!(
            result.is_err(),
            "timed lock acquisition must time out when the lock is already held"
        );
    }

    /// Verify that a timed acquisition succeeds when the lock is free. This
    /// ensures the 10-second default does not trip normal (uncontended) login.
    #[tokio::test]
    async fn login_lock_timeout_succeeds_when_lock_is_free() {
        let mutex = Arc::new(tokio::sync::Mutex::new(()));
        // Lock is uncontended — acquisition must succeed before any timeout.
        let result = tokio::time::timeout(Duration::from_millis(10), mutex.lock()).await;
        assert!(result.is_ok(), "timed lock acquisition must succeed when the lock is uncontended");
    }

    #[test]
    fn configure_login_lock_timeout_and_getter_round_trip() {
        // OnceLock: the first call in this process wins; subsequent calls are
        // no-ops. We verify only that the getter returns a positive duration
        // regardless of which test ran first.
        configure_login_lock_timeout(7);
        assert!(
            login_lock_timeout().as_millis() > 0,
            "login_lock_timeout() must return a positive duration"
        );
    }

    // --- W1-L7-28: per-connection admission under the global breaker ---

    // Final-review F6: the peer admission table is process-global, so the
    // tests that park table entries serialize on this test-only mutex;
    // otherwise a sibling's live entry breaks the size-0 drain assertion
    // in `per_connection_admission_rejects_over_cap`. No production
    // change: the table behavior itself is pinned and green.
    static PEER_ADMISSION_TEST_LOCK: LazyLock<tokio::sync::Mutex<()>> =
        LazyLock::new(|| tokio::sync::Mutex::new(()));

    fn test_peer(octet: u8, port: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, octet)),
            port,
        )
    }

    /// Park `n` backend calls holding `peer`'s admission slots. Returns the
    /// join handles plus one releaser per call; each parked call signals
    /// `entered_tx` once its slot is held. All releasers must be fired (or
    /// dropped) or the test binary hangs on teardown.
    async fn park_peer_calls(
        peer: std::net::SocketAddr,
        n: usize,
        entered_tx: tokio::sync::mpsc::Sender<()>,
    ) -> (
        Vec<tokio::task::JoinHandle<Result<CkResult<u8>, Status>>>,
        Vec<std::sync::mpsc::Sender<()>>,
    ) {
        let mut parked = Vec::with_capacity(n);
        let mut releasers = Vec::with_capacity(n);
        for _ in 0..n {
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            releasers.push(release_tx);
            let entered_tx = entered_tx.clone();
            parked.push(tokio::spawn(async move {
                scope_peer_admission(Some(peer), async move {
                    spawn_backend(move || {
                        entered_tx.blocking_send(()).expect("entered signal");
                        release_rx.recv().expect("released");
                        Ok::<u8, CkRv>(7)
                    })
                    .await
                })
                .await
            }));
        }
        (parked, releasers)
    }

    /// W1-L7-28: a peer at its cap is rejected (breaker class) without
    /// running the backend call; released slots admit again and the empty
    /// entry is removed (bounded table).
    #[tokio::test(flavor = "multi_thread")]
    async fn per_connection_admission_rejects_over_cap() {
        let _table_guard = PEER_ADMISSION_TEST_LOCK.lock().await;
        let peer = test_peer(51, 40051);
        let cap = per_connection_max_in_flight();
        assert!(cap >= 1, "per-connection cap must be at least 1");

        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::channel::<()>(cap + 1);
        let (parked, releasers) = park_peer_calls(peer, cap, entered_tx).await;
        for _ in 0..cap {
            entered_rx.recv().await.expect("each parked call holds a slot");
        }

        // Over cap: rejected as HOST_MEMORY (breaker class), backend never runs.
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran_clone = Arc::clone(&ran);
        let rejected = scope_peer_admission(Some(peer), async move {
            spawn_backend(move || {
                ran_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok::<u8, CkRv>(9)
            })
            .await
        })
        .await;
        assert_eq!(
            rejected.expect("admission rejection is a ck_rv, not a transport error"),
            Err(CkRv::HOST_MEMORY),
            "W1-L3-01: per-peer breaker trip surfaces HOST_MEMORY (was DEVICE_ERROR)"
        );
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst), "rejected call must not run");

        // Release everything: slots free and the table entry is removed.
        for tx in releasers {
            tx.send(()).expect("release parked call");
        }
        for handle in parked {
            let result = handle.await.expect("parked task joins").expect("no transport error");
            assert_eq!(result, Ok(7u8));
        }
        assert_eq!(
            peer_admission_table_size_for_test(),
            0,
            "drained peer entries must be removed (bounded table)"
        );

        // The freed cap admits again.
        let again =
            scope_peer_admission(Some(peer), async { spawn_backend(|| Ok::<u8, CkRv>(1)).await })
                .await;
        assert_eq!(again.expect("no transport error"), Ok(1u8));
    }

    /// W1-L7-28: the cap is per peer — an unrelated connection is unaffected
    /// by another peer's exhausted budget.
    #[tokio::test(flavor = "multi_thread")]
    async fn per_connection_admission_is_per_peer() {
        let _table_guard = PEER_ADMISSION_TEST_LOCK.lock().await;
        let busy = test_peer(52, 40052);
        let idle = test_peer(53, 40053);
        let cap = per_connection_max_in_flight();

        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::channel::<()>(cap + 1);
        let (parked, releasers) = park_peer_calls(busy, cap, entered_tx).await;
        for _ in 0..cap {
            entered_rx.recv().await.expect("each parked call holds a slot");
        }

        let other =
            scope_peer_admission(Some(idle), async { spawn_backend(|| Ok::<u8, CkRv>(3)).await })
                .await;
        assert_eq!(other.expect("no transport error"), Ok(3u8), "idle peer must be admitted");

        for tx in releasers {
            tx.send(()).expect("release parked call");
        }
        for handle in parked {
            handle.await.expect("parked task joins").expect("no transport error").unwrap();
        }
    }

    /// W1-L7-28 characterization: without a scoped peer (UDS / unknown
    /// transport) backend calls run unadmitted, as before.
    #[tokio::test]
    async fn per_connection_admission_skipped_without_peer() {
        let result = spawn_backend(|| Ok::<u8, CkRv>(5)).await;
        assert_eq!(result.expect("no transport error"), Ok(5u8));
    }

    /// W1-L7-02: a context with a bound transport identity keeps that
    /// identity as its quota key even when a peer is published —
    /// authenticated quotas are unchanged.
    #[tokio::test]
    async fn principal_quota_key_prefers_bound_identity_over_peer() {
        let ctx_mgr = ContextManager::new(Duration::from_secs(300), 0);
        let ctx_id = ctx_mgr.create_context(Some("alice".to_string())).await.unwrap();
        let peer = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7)),
            4321,
        );
        let key =
            scope_peer_admission(Some(peer), async { principal_quota_key(&ctx_mgr, &ctx_id) })
                .await;
        assert_eq!(key, "alice", "bound identity must win over the peer key");
    }

    /// W1-L7-02: unauthenticated contexts (no bound identity) share one
    /// quota key per peer IP, so N contexts cannot multiply the caps.
    /// The key is IP-only: ports never split a peer's quota.
    #[tokio::test]
    async fn principal_quota_key_uses_peer_ip_for_unauthenticated() {
        let ctx_mgr = ContextManager::new(Duration::from_secs(300), 0);
        let ctx_a = ctx_mgr.create_context(None).await.unwrap();
        let ctx_b = ctx_mgr.create_context(None).await.unwrap();
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7));
        let key_a = scope_peer_admission(Some(std::net::SocketAddr::new(ip, 1111)), async {
            principal_quota_key(&ctx_mgr, &ctx_a)
        })
        .await;
        let key_b = scope_peer_admission(Some(std::net::SocketAddr::new(ip, 2222)), async {
            principal_quota_key(&ctx_mgr, &ctx_b)
        })
        .await;
        assert_eq!(key_a, "192.0.2.7", "unauthenticated key must be the peer IP");
        assert_eq!(key_b, key_a, "same-IP contexts must share one quota key");
        let other_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 8));
        let key_c = scope_peer_admission(Some(std::net::SocketAddr::new(other_ip, 1111)), async {
            principal_quota_key(&ctx_mgr, &ctx_b)
        })
        .await;
        assert_ne!(key_c, key_a, "different peer IPs must not share a quota key");
    }

    /// W1-L7-02 characterization: without a published peer (UDS /
    /// unknown transport) the unauthenticated key stays the context id,
    /// as before — there is no IP to key on.
    #[tokio::test]
    async fn principal_quota_key_falls_back_to_ctx_id_without_peer() {
        let ctx_mgr = ContextManager::new(Duration::from_secs(300), 0);
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        assert!(current_peer().is_none(), "setup: no peer must be published");
        assert_eq!(
            principal_quota_key(&ctx_mgr, &ctx_id),
            ctx_id.0,
            "peerless contexts keep the context-id key"
        );
    }
}
