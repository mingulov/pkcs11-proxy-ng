use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, RwLock};
use std::time::Duration;

use cryptoki_sys::{CK_SESSION_HANDLE, CK_SLOT_ID};
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_proto::convert::message_params::MessageParameterShape;
use pkcs11_proxy_ng_types::{CkRv, MechanismRegistry};
use tokio::runtime::Runtime;

/// Fork-aware tokio runtime cell (T2run: macOS run-6). A `OnceLock`
/// runtime is inherited across `fork()` with a dead I/O driver (the
/// kqueue fd does not survive; the first post-fork `block_on` panics
/// with EBADF and aborts the child). The pid tag detects the fork: a
/// process whose pid differs from the tag leaks a fresh runtime and
/// claims the cell. Leaked runtimes are never dropped, so no
/// destructor ever touches a dead driver.
///
/// Lock-free by design: a mutex here could be inherited
/// locked-by-a-dead-thread after a fork inside a build. Races are
/// benign — every racer builds a valid runtime for the current pid
/// and uses its own; the losers' runtimes leak but stay valid.
static RUNTIME_PTR: AtomicPtr<Runtime> = AtomicPtr::new(std::ptr::null_mut());
/// Pid the current `RUNTIME_PTR` was built for (0 = unbuilt).
static RUNTIME_PID: AtomicU32 = AtomicU32::new(0);
/// Pid whose lifecycle flags (`INITIALIZED`, `CLIENT_RECONNECT_REQUIRED`)
/// are live (0 = unclaimed). Claimed by [`reclaim_after_fork`].
static SHIM_PID: AtomicU32 = AtomicU32::new(0);
static CLIENT: OnceLock<tokio::sync::Mutex<Pkcs11Client>> = OnceLock::new();
/// Guards the one-time CLIENT initialization so that concurrent callers
/// wait rather than racing to connect, and so that a failed init is
/// retried on the next `C_Initialize` rather than being cached forever.
static CLIENT_INIT: Mutex<()> = Mutex::new(());
/// `C_Finalize` ends the PKCS#11 application context.  A later
/// `C_Initialize` must re-read connection configuration instead of reusing a
/// channel that may point at an old daemon.
static CLIENT_RECONNECT_REQUIRED: AtomicBool = AtomicBool::new(false);

/// Cached pre-init failed-dial outcome (W1-C7-01). A pre-init probe against
/// an unreachable daemon burns one full dial series (~21 s at the default
/// 10 attempts + backoff); without a cache, every `C_GetFunctionList` /
/// `C_GetInterfaceList` / `C_GetInterface` call re-pays it. The key folds
/// the pid and endpoint together so a forked child and an endpoint change
/// both miss the cache and dial fresh — lock-free on purpose, so no
/// fork-inherited mutex is ever touched on this path.
static PRE_INIT_CONNECT_FAILED: AtomicBool = AtomicBool::new(false);
static PRE_INIT_CONNECT_FAILED_KEY: AtomicU64 = AtomicU64::new(0);

/// Dial-series counter, test-only: each `connect_with_retry` invocation is
/// one series of up to `MAX_ATTEMPTS` attempts.
#[cfg(test)]
static CONNECT_SERIES: AtomicU32 = AtomicU32::new(0);

#[cfg(test)]
pub(crate) fn connect_series_count() -> u32 {
    CONNECT_SERIES.load(Ordering::Relaxed)
}

fn pre_init_failure_key(endpoint: &str) -> u64 {
    // FNV-1a over the pid + endpoint; compared only within this process.
    let mut h: u64 = 0xcbf29ce484222325;
    for b in std::process::id().to_le_bytes().iter().chain(endpoint.as_bytes()) {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Whether the pre-init dial to the current endpoint already failed.
/// Consulted only while `!is_initialized()`; `C_Initialize` sets the
/// initialized flag before connecting, so it always dials fresh.
pub(crate) fn pre_init_connect_failed() -> bool {
    if !PRE_INIT_CONNECT_FAILED.load(Ordering::Acquire) {
        return false;
    }
    // W1-L8-02: an unresolvable endpoint (e.g. tls:// socket) has no
    // cache key; report "no cached failure" so the probe reaches the
    // connect path, which surfaces the loud parse error.
    let Ok(endpoint) = resolve_endpoint_from_env() else {
        return false;
    };
    PRE_INIT_CONNECT_FAILED_KEY.load(Ordering::Relaxed) == pre_init_failure_key(&endpoint)
}

fn record_pre_init_connect_failure(endpoint: &str) {
    PRE_INIT_CONNECT_FAILED_KEY.store(pre_init_failure_key(endpoint), Ordering::Relaxed);
    PRE_INIT_CONNECT_FAILED.store(true, Ordering::Release);
}

/// Drop any cached pre-init dial failure. Called on successful connect,
/// reconnect-required, re-probe/cache-clear, and by tests for isolation.
pub(crate) fn clear_pre_init_connect_failure() {
    PRE_INIT_CONNECT_FAILED.store(false, Ordering::Release);
}

/// The mechanism registry uses a two-level wrapper:
///
/// * `OnceLock<...>` so the very first registry can be installed exactly
///   once during `C_Initialize`, matching the historical contract.
/// * `RwLock<Arc<MechanismRegistry>>` so subsequent probes
///   (`reprobe()`-driven) can atomically swap the registry without
///   blocking concurrent readers — readers clone the `Arc` while holding
///   the read lock for only a couple of nanoseconds, then drop the lock
///   before doing any work.
///
/// Readers MUST NOT hold the read guard across FFI or RPC calls; that
/// invariant is enforced by the fact that the public accessor returns
/// an owned `Arc<MechanismRegistry>` rather than a borrow tied to the
/// guard.
static MECHANISM_REGISTRY: OnceLock<RwLock<Arc<MechanismRegistry>>> = OnceLock::new();

/// Returns a cheap clone of the current mechanism registry.
///
/// Panics if called before [`replace_mechanism_registry`] has installed
/// the first registry. Callers do not have to worry about locking — the
/// `Arc<MechanismRegistry>` is captured and the underlying lock is
/// released before this function returns.
pub fn mechanism_registry() -> Arc<MechanismRegistry> {
    MECHANISM_REGISTRY
        .get()
        .expect("MechanismRegistry not initialized")
        .read()
        .expect("MechanismRegistry RwLock poisoned")
        .clone()
}

/// Install or atomically replace the global mechanism registry.
///
/// First invocation (from `C_Initialize`) creates the `RwLock` inside
/// the `OnceLock`; later invocations (from `reprobe()`) acquire the
/// write lock and swap the `Arc` in-place. Existing readers that already
/// cloned the `Arc` keep using the old registry until they drop it,
/// which preserves consistency for in-flight operations.
pub fn replace_mechanism_registry(reg: MechanismRegistry) {
    let arc = Arc::new(reg);
    match MECHANISM_REGISTRY.get() {
        Some(lock) => {
            *lock.write().expect("MechanismRegistry RwLock poisoned") = arc;
        }
        None => {
            // Ignore the race outcome: if another thread already
            // installed the OnceLock between our `get()` and `set()`,
            // we fall through to a swap on the next call.
            let _ = MECHANISM_REGISTRY.set(RwLock::new(arc));
        }
    }
}

/// Whether `C_Initialize` has been called and returned `CKR_OK`.
///
/// The shim checks this flag locally before forwarding to the server so
/// that `CKR_CRYPTOKI_ALREADY_INITIALIZED` (double init) and
/// `CKR_CRYPTOKI_NOT_INITIALIZED` (finalize before init) are returned
/// without a network round-trip.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Claim `slot` for `pid`, retrying `compare_exchange_weak` until the claim
/// lands or another claimant's pid is observed.
///
/// Returns `true` exactly when this call performed the claim (i.e. the
/// caller owns the reset). A single weak CAS can fail spuriously (W1-C6-05),
/// which previously skipped the child's lifecycle reset for that call; the
/// loop retries on any observed value other than `pid`, so a spurious
/// failure can no longer drop the reset.
fn claim_pid_slot(slot: &AtomicU32, pid: u32) -> bool {
    let mut current = slot.load(Ordering::Relaxed);
    loop {
        if current == pid {
            return false;
        }
        match slot.compare_exchange_weak(current, pid, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

/// Reset fork-unsafe lifecycle flags when the process forked since the
/// shim state was claimed. After this, the child's `C_Initialize` runs
/// the full path (fresh runtime via [`runtime`], reconnected channel
/// via the reconnect flag) instead of inheriting the parent's dead
/// I/O driver and sockets. No-op fast path: one atomic load when the
/// pid already matches.
///
/// Residual (T2run-fix1 prod M2, flagged 2026-09-19): the child keeps the
/// parent's SESSION_SLOTS/message-state entries (`c_initialize` never
/// clears them; only `c_finalize` does), so a recycled server-side handle
/// could collide with a stale entry. Narrow (needs open parent sessions
/// at fork + handle collision + slot mismatch), pre-existing class, within
/// this file's documented liveness bar — accepted, not fixed.
fn reclaim_after_fork() {
    let pid = std::process::id();
    if claim_pid_slot(&SHIM_PID, pid) {
        INITIALIZED.store(false, Ordering::Release);
        CLIENT_RECONNECT_REQUIRED.store(true, Ordering::Release);
    }
}

/// Returns `true` if `C_Initialize` has completed successfully.
pub fn is_initialized() -> bool {
    reclaim_after_fork();
    INITIALIZED.load(Ordering::Acquire)
}

/// Transition from uninitialized → initialized.
/// Returns `true` if the transition succeeded (i.e., was not already set).
pub fn mark_initialized() -> bool {
    reclaim_after_fork();
    INITIALIZED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok()
}

/// Transition from initialized → uninitialized.
pub fn mark_finalized() {
    INITIALIZED.store(false, Ordering::Release);
}

/// Require the next client access to connect from the current environment.
pub fn mark_client_reconnect_required() {
    CLIENT_RECONNECT_REQUIRED.store(true, Ordering::Release);
    // A forced reconnect must dial fresh — never reuse a cached failure.
    clear_pre_init_connect_failure();
}

pub type SessionSlotMap = Mutex<HashMap<CK_SESSION_HANDLE, CK_SLOT_ID>>;

static SESSION_SLOTS: LazyLock<SessionSlotMap> = LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum MessageOperation {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
}

#[derive(Debug, Default)]
pub(crate) struct MessageOperationState {
    pub(crate) shape: Option<MessageParameterShape>,
}

type MessageOperationStateMap =
    Mutex<HashMap<(CK_SESSION_HANDLE, MessageOperation), Arc<Mutex<MessageOperationState>>>>;
static MESSAGE_OPERATION_STATES: LazyLock<MessageOperationStateMap> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Return the stable per-session/per-operation guard object without retaining
/// the global map lock. Callers lock this object across parsing, RPC and
/// writeback so a concurrent Init cannot change shape mid-call.
pub(crate) fn message_operation_state(
    h_session: CK_SESSION_HANDLE,
    operation: MessageOperation,
) -> Arc<Mutex<MessageOperationState>> {
    MESSAGE_OPERATION_STATES
        .lock()
        .expect("message-operation state map poisoned")
        .entry((h_session, operation))
        .or_insert_with(|| Arc::new(Mutex::new(MessageOperationState::default())))
        .clone()
}

fn evict_message_operations(h_session: CK_SESSION_HANDLE) {
    if let Ok(mut map) = MESSAGE_OPERATION_STATES.lock() {
        map.retain(|(session, _), _| *session != h_session);
    }
}

pub(crate) fn remember_session_slot(h_session: CK_SESSION_HANDLE, slot_id: CK_SLOT_ID) {
    if let Ok(mut map) = SESSION_SLOTS.lock() {
        map.insert(h_session, slot_id);
    }
}

/// Whether `h_session` was opened through this shim and not since closed
/// (W1-L3-11: native error precedence needs session resolution before
/// mechanism validation). Every live session in this process passed through
/// `c_open_session` (which remembers it) and every close/evict path forgets
/// it, so "unknown" means the server would answer `SESSION_HANDLE_INVALID`
/// (or the handle never existed). Fail-open on a poisoned map: proceeding
/// preserves correctness (the server still resolves the session), degrading
/// only the precedence nicety.
pub(crate) fn is_session_known(h_session: CK_SESSION_HANDLE) -> bool {
    match SESSION_SLOTS.lock() {
        Ok(map) => map.contains_key(&h_session),
        Err(_) => true,
    }
}

fn forget_session_slot(h_session: CK_SESSION_HANDLE) {
    if let Ok(mut map) = SESSION_SLOTS.lock() {
        map.remove(&h_session);
    }
}

/// Clear every per-session cache across all sessions.
///
/// W1-C6-04: the 16 two-call byte caches plus the encapsulate cache were
/// dead state (production only evicted them, never inserted or read), so
/// they are gone; only session ownership and message-operation
/// discriminators remain.
pub(crate) fn clear_all_caches() {
    if let Ok(mut map) = SESSION_SLOTS.lock() {
        map.clear();
    }
    if let Ok(mut map) = MESSAGE_OPERATION_STATES.lock() {
        map.clear();
    }
}

/// Forget session ownership and all message-operation discriminators without
/// touching the disposable output caches.  Close uses this only for terminal
/// or outcome-ambiguous results; decoded transient failures keep it intact.
pub(crate) fn evict_session_authoritative_state(h_session: CK_SESSION_HANDLE) {
    forget_session_slot(h_session);
    evict_message_operations(h_session);
}

/// Forget session ownership and message-operation discriminators for sessions
/// opened on one slot.
///
/// Called from `c_close_all_sessions` on the close attempt, unconditionally
/// (dropped regardless of the server's `CK_RV`).
pub(crate) fn evict_slot_session_caches(slot_id: CK_SLOT_ID) {
    let sessions = if let Ok(mut map) = SESSION_SLOTS.lock() {
        let sessions: Vec<_> =
            map.iter().filter(|(_, slot)| **slot == slot_id).map(|(session, _)| *session).collect();
        for session in &sessions {
            map.remove(session);
        }
        sessions
    } else {
        Vec::new()
    };

    for session in sessions {
        evict_message_operations(session);
    }
}

pub fn runtime() -> &'static Runtime {
    // F3: a CURRENT-THREAD runtime, not the multi-thread default of
    // `Runtime::new()`. This shim is loaded into arbitrary host applications as
    // a `cdylib`, and PKCS#11 applications commonly `fork()`. A multi-thread
    // runtime keeps worker threads and an internal blocking pool whose mutexes,
    // if held at the moment of `fork()`, are inherited locked-by-a-dead-thread in
    // the child and deadlock the next runtime call. A current-thread runtime owns
    // no background worker threads, so it cannot deadlock that way; the shim only
    // ever drives it via `block_on` (one request at a time), so it needs no
    // multi-thread executor. (Per PKCS#11, a forked child must still call
    // C_Initialize again before reusing the module; the daemon connection is
    // re-established by the shim's reconnect path.)
    //
    // Fork generation: a child whose pid differs from RUNTIME_PID leaks a
    // fresh runtime instead of inheriting the parent's dead I/O driver
    // (see RUNTIME_PTR). No lock: races are benign (each builder's
    // runtime is valid for its user), and a lock could wedge a child
    // forked mid-build.
    reclaim_after_fork();
    let pid = std::process::id();
    let ptr = RUNTIME_PTR.load(Ordering::Acquire);
    if !ptr.is_null() && RUNTIME_PID.load(Ordering::Acquire) == pid {
        // SAFETY: the pointer is either null or a leaked `Box<Runtime>`
        // that is never mutated or freed; sharing it is sound, and the
        // pid tag proves it was built for this process.
        return unsafe { &*ptr };
    }
    let fresh = Box::leak(Box::new(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime"),
    ));
    RUNTIME_PTR.store(fresh as *mut Runtime, Ordering::Release);
    RUNTIME_PID.store(pid, Ordering::Release);
    fresh
}

/// Loud warning when `PKCS11_PROXY_CONNECT_TIMEOUT` is set but not a
/// valid second count (W1-L8-15). Returns `None` when the var is unset
/// or parses — the call site logs `Some` via `tracing::warn!` and the
/// value still falls back to the 5 s default, but never silently.
pub(crate) fn connect_timeout_warning(raw: Option<&str>) -> Option<String> {
    match raw {
        None => None,
        Some(value) => match value.parse::<u64>() {
            Ok(_) => None,
            Err(_) => Some(format!(
                "PKCS11_PROXY_CONNECT_TIMEOUT={value:?} is not a valid number of seconds; \
                 using default 5"
            )),
        },
    }
}

fn connect_client_from_env() -> Result<Pkcs11Client, CkRv> {
    // W1-L8-02: a malformed endpoint (e.g. tls:// socket) fails the
    // connect outright — never dial a fallback on the caller's behalf.
    // The parse error is already logged loudly by the resolver.
    let endpoint = resolve_endpoint_from_env().map_err(|_| CkRv::DEVICE_ERROR)?;
    let timeout_raw = std::env::var("PKCS11_PROXY_CONNECT_TIMEOUT").ok();
    if let Some(warning) = connect_timeout_warning(timeout_raw.as_deref()) {
        tracing::warn!("{warning}");
    }
    let timeout_secs: u64 = timeout_raw.as_deref().and_then(|s| s.parse().ok()).unwrap_or(5);
    let tls_files =
        pkcs11_proxy_ng_client::tls::ClientTlsFiles::from_env().map_err(|_| CkRv::DEVICE_ERROR)?;
    let rt = runtime();
    let result = rt
        .block_on(async { connect_with_retry(&endpoint, tls_files, timeout_secs).await })
        .map_err(|_| CkRv::DEVICE_ERROR);
    // W1-C7-01: cache only the failure; any success invalidates.
    match &result {
        Ok(_) => clear_pre_init_connect_failure(),
        Err(_) => record_pre_init_connect_failure(&endpoint),
    }
    result
}

/// Resolve the daemon endpoint from environment variables.
///
/// Precedence:
///   1. `PKCS11_PROXY_ENDPOINT` (canonical, accepts `http://...` and
///      `https://...`).
///   2. `PKCS11_PROXY_SOCKET` (back-compat with the old C pkcs11-proxy,
///      `tcp://host:port` → `http://host:port`). The legacy `tls://`
///      prefix is intentionally NOT supported here: the new shim uses
///      mTLS configured via `PKCS11_PROXY_TLS_*` env vars rather than
///      TLS-PSK. A `tls://` URL is a loud error (W1-L8-02): it must
///      never fall through to the default endpoint, which would
///      silently connect to the wrong daemon with no TLS.
///   3. Default `http://127.0.0.1:7512`.
///
/// Returns `Err` (naming the variable and the offending value class) for
/// a `tls://` socket instead of producing any connection string.
pub(crate) fn resolve_endpoint_from_env() -> Result<String, String> {
    if let Ok(endpoint) = std::env::var("PKCS11_PROXY_ENDPOINT") {
        if std::env::var_os("PKCS11_PROXY_SOCKET").is_some() {
            tracing::debug!(
                "PKCS11_PROXY_ENDPOINT and PKCS11_PROXY_SOCKET both set; \
                 PKCS11_PROXY_ENDPOINT wins"
            );
        }
        return Ok(endpoint);
    }
    if let Ok(socket) = std::env::var("PKCS11_PROXY_SOCKET") {
        if let Some(rest) = socket.strip_prefix("tcp://") {
            let translated = format!("http://{rest}");
            tracing::info!(
                socket = %socket,
                endpoint = %translated,
                "translating legacy PKCS11_PROXY_SOCKET to PKCS11_PROXY_ENDPOINT"
            );
            return Ok(translated);
        }
        if socket.starts_with("tls://") {
            let msg = format!(
                "PKCS11_PROXY_SOCKET has unsupported tls:// endpoint {socket:?}; \
                 use PKCS11_PROXY_ENDPOINT=https://... and PKCS11_PROXY_TLS_* env vars for mTLS"
            );
            tracing::error!(socket = %socket, "{msg}");
            return Err(msg);
        }
        tracing::warn!(
            socket = %socket,
            "PKCS11_PROXY_SOCKET must use tcp:// prefix; ignoring"
        );
    }
    Ok("http://127.0.0.1:7512".to_string())
}

/// Establish the gRPC client connection with retry.
///
/// Must be called **outside** any `runtime().block_on()` context to avoid
/// a nested-`block_on` panic.  `c_initialize` calls this before entering
/// its own `block_on` block; every subsequent `client()` call returns the
/// cached value until `C_Finalize` marks it stale.
///
/// Returns `Err(CkRv::DEVICE_ERROR)` if all connect attempts fail
/// (instead of panicking).
///
/// Uses `CLIENT_INIT` mutex so that concurrent callers serialize, and a
/// failed init is retried on the next call (not cached).
pub fn ensure_client_connected() -> Result<(), CkRv> {
    // Reclaim first so a forked child takes the reconnect path below
    // (fresh channel) instead of the fast path (dead sockets).
    reclaim_after_fork();
    // Fast path: already connected.
    if CLIENT.get().is_some() && !CLIENT_RECONNECT_REQUIRED.load(Ordering::Acquire) {
        // Connected means reachable: no failure stays cached (W1-C7-01).
        clear_pre_init_connect_failure();
        return Ok(());
    }
    // Slow path: serialize init attempts.
    let _guard = CLIENT_INIT.lock().unwrap_or_else(|e| e.into_inner());
    // Re-check after acquiring the lock (another thread may have succeeded).
    if let Some(existing) = CLIENT.get() {
        if !CLIENT_RECONNECT_REQUIRED.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut client = connect_client_from_env()?;
        runtime().block_on(async {
            let mut guard = existing.lock().await;
            // W1-L6-29: preserve the logical session across the swap. The
            // reconnect may run mid-session (steady-state data plane), and
            // a fresh client carries no context id — dropping it would
            // orphan the server context (later calls, including finalize,
            // short-circuit locally and never reach the daemon).
            let context_id = guard.context_id_opt();
            client.restore_context_id(context_id);
            *guard = client;
        });
        CLIENT_RECONNECT_REQUIRED.store(false, Ordering::Release);
        return Ok(());
    }
    let client = connect_client_from_env()?;
    // Store the connected client; ignore the error (another winner is fine).
    let _ = CLIENT.set(tokio::sync::Mutex::new(client));
    CLIENT_RECONNECT_REQUIRED.store(false, Ordering::Release);
    Ok(())
}

/// Returns the lazily-connected gRPC client.
///
/// Panics if called before `ensure_client_connected()`.
pub fn client() -> &'static tokio::sync::Mutex<Pkcs11Client> {
    CLIENT.get().expect("BUG: client() called before ensure_client_connected()")
}

/// Bounded exponential backoff with jitter, matching the resilience
/// contract:
///
/// * Attempt 1: no delay (immediate connect).
/// * Attempt N≥2: delay = min(`INITIAL_BACKOFF` × 2^(N−2), `MAX_BACKOFF`)
///   with ±`JITTER_PCT`% multiplicative jitter applied on each attempt.
///   The jitter prevents many shims that all dropped connection at the
///   same time (e.g. after a daemon pod restart) from re-dialing in
///   lock-step.
///
/// Iterations are capped at `MAX_ATTEMPTS` so a permanently-unreachable
/// endpoint can't block the C_Initialize call forever.
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(5);
const JITTER_PCT: u32 = 20;
const MAX_ATTEMPTS: u32 = 10;

/// Return the backoff delay for attempt `n` (0-indexed). Attempt 0 is
/// immediate. The deterministic part (`base`) is exposed so unit tests
/// can verify the doubling+cap without depending on jitter randomness.
fn backoff_for_attempt(n: u32) -> Duration {
    if n == 0 {
        return Duration::ZERO;
    }
    let base = backoff_base(n);
    apply_jitter(base, JITTER_PCT)
}

fn backoff_base(n: u32) -> Duration {
    // Doubling pattern, capped at MAX_BACKOFF. checked_pow guards against
    // overflow at very high attempt numbers.
    let exp = n.saturating_sub(1);
    let factor = 1u64.checked_shl(exp.min(63)).unwrap_or(u64::MAX);
    let millis =
        INITIAL_BACKOFF.as_millis().saturating_mul(factor as u128).min(MAX_BACKOFF.as_millis())
            as u64;
    Duration::from_millis(millis)
}

fn apply_jitter(base: Duration, jitter_pct: u32) -> Duration {
    if jitter_pct == 0 || base.is_zero() {
        return base;
    }
    // Lightweight LCG-style jitter seeded by the wall clock nanosecond
    // count. We intentionally avoid adding a `rand` dependency for this
    // single use; the jitter doesn't need cryptographic randomness — it
    // just needs to decorrelate concurrent shims.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let mixed = nanos.wrapping_add(pid);
    let pct_range = (jitter_pct as u64) * 2; // ±jitter_pct
    let offset_pct = (mixed as u64) % pct_range; // 0..pct_range
    let signed_pct = offset_pct as i64 - jitter_pct as i64; // -jitter_pct..jitter_pct
    let base_millis = base.as_millis() as i64;
    let delta = base_millis * signed_pct / 100;
    let total = (base_millis + delta).max(0) as u64;
    Duration::from_millis(total)
}

/// Connect to the daemon with bounded exponential backoff + jitter.
///
/// Returns `Ok` on the first successful attempt, `Err` after
/// `MAX_ATTEMPTS` failures. Each attempt's connect call is itself
/// bounded by `timeout_secs` so a hung TCP handshake cannot block the
/// retry loop indefinitely.
///
/// `PKCS11_PROXY_CONNECT_ATTEMPTS` lowers the attempt cap (clamped to
/// `1..=MAX_ATTEMPTS`) for deployments — and the test suite — that
/// must fail fast on an unreachable daemon. It cannot raise the cap:
/// the resilience contract's bound on how long `C_Initialize` can
/// block stays intact.
pub(crate) fn connect_attempts_from_value(raw: Option<&str>) -> u32 {
    raw.and_then(|s| s.trim().parse::<u32>().ok())
        .map(|n| n.clamp(1, MAX_ATTEMPTS))
        .unwrap_or(MAX_ATTEMPTS)
}

/// Loud warning when `PKCS11_PROXY_CONNECT_ATTEMPTS` is set but not a
/// valid attempt count (W1-L8-15). The parse predicate matches
/// [`connect_attempts_from_value`] exactly (trimmed `u32`), so the
/// warning fires exactly when the default engages. Clamping is
/// documented behavior and stays silent.
pub(crate) fn connect_attempts_warning(raw: Option<&str>) -> Option<String> {
    match raw {
        None => None,
        Some(value) => match value.trim().parse::<u32>() {
            Ok(_) => None,
            Err(_) => Some(format!(
                "PKCS11_PROXY_CONNECT_ATTEMPTS={value:?} is not a valid attempt count; \
                 using default {MAX_ATTEMPTS}"
            )),
        },
    }
}

async fn connect_with_retry(
    endpoint: &str,
    tls_files: Option<pkcs11_proxy_ng_client::tls::ClientTlsFiles>,
    timeout_secs: u64,
) -> Result<Pkcs11Client, String> {
    #[cfg(test)]
    CONNECT_SERIES.fetch_add(1, Ordering::Relaxed);
    let connect_timeout = Duration::from_secs(timeout_secs);
    let attempts_raw = std::env::var("PKCS11_PROXY_CONNECT_ATTEMPTS").ok();
    if let Some(warning) = connect_attempts_warning(attempts_raw.as_deref()) {
        tracing::warn!("{warning}");
    }
    let max_attempts = connect_attempts_from_value(attempts_raw.as_deref());

    for attempt in 0..max_attempts {
        let delay = backoff_for_attempt(attempt);
        if !delay.is_zero() {
            tracing::debug!(
                attempt = attempt + 1,
                backoff_ms = delay.as_millis() as u64,
                "gRPC reconnect: sleeping before next attempt"
            );
            tokio::time::sleep(delay).await;
        }

        let connect = async {
            match tls_files.clone() {
                Some(tls_files) => Pkcs11Client::connect_with_tls_files(endpoint, tls_files).await,
                None => Pkcs11Client::connect(endpoint).await,
            }
        };
        match tokio::time::timeout(connect_timeout, connect).await {
            Ok(Ok(client)) => return Ok(client),
            Ok(Err(e)) => {
                tracing::warn!(
                    attempt = attempt + 1,
                    max_attempts,
                    error = %e,
                    "gRPC connect failed, retrying"
                );
            }
            Err(_) => {
                tracing::warn!(
                    attempt = attempt + 1,
                    max_attempts,
                    timeout_secs,
                    "gRPC connect timed out, retrying"
                );
            }
        }
    }
    Err(format!("all {max_attempts} connect attempts failed"))
}

#[cfg(test)]
mod backoff_tests {
    use super::*;

    #[test]
    fn first_attempt_is_immediate() {
        // `backoff_for_attempt(0)` is the public contract — attempt 0
        // (the very first connect) takes no delay. `backoff_base`'s
        // own n=0 value is unused; the wrapper short-circuits.
        assert_eq!(backoff_for_attempt(0), Duration::ZERO);
    }

    #[test]
    fn second_attempt_starts_at_initial_backoff() {
        assert_eq!(backoff_base(1), INITIAL_BACKOFF);
    }

    #[test]
    fn base_doubles_until_cap() {
        assert_eq!(backoff_base(1), Duration::from_millis(100));
        assert_eq!(backoff_base(2), Duration::from_millis(200));
        assert_eq!(backoff_base(3), Duration::from_millis(400));
        assert_eq!(backoff_base(4), Duration::from_millis(800));
        assert_eq!(backoff_base(5), Duration::from_millis(1600));
        assert_eq!(backoff_base(6), Duration::from_millis(3200));
        // Attempt 7's doubled value (6400 ms) exceeds MAX_BACKOFF.
        assert_eq!(backoff_base(7), MAX_BACKOFF);
        assert_eq!(backoff_base(20), MAX_BACKOFF);
    }

    #[test]
    #[cfg_attr(miri, ignore = "apply_jitter uses SystemTime::now which miri isolates")]
    fn jitter_stays_within_band() {
        let base = Duration::from_millis(1000);
        // Sample many times so any randomness in the jitter source
        // would surface as an outlier.
        for _ in 0..1000 {
            let d = apply_jitter(base, JITTER_PCT);
            let millis = d.as_millis() as u64;
            assert!(
                (800..=1200).contains(&millis),
                "{millis}ms is outside the ±{JITTER_PCT}% band around {}ms",
                base.as_millis()
            );
        }
    }

    #[test]
    fn jitter_at_zero_disables_offset() {
        let base = Duration::from_millis(1000);
        assert_eq!(apply_jitter(base, 0), base);
    }

    #[test]
    fn jitter_on_zero_delay_stays_zero() {
        assert_eq!(apply_jitter(Duration::ZERO, JITTER_PCT), Duration::ZERO);
    }

    #[test]
    fn connect_attempts_defaults_to_max() {
        assert_eq!(connect_attempts_from_value(None), MAX_ATTEMPTS);
    }

    #[test]
    fn connect_attempts_accepts_lower_values() {
        assert_eq!(connect_attempts_from_value(Some("1")), 1);
        assert_eq!(connect_attempts_from_value(Some("3")), 3);
    }

    #[test]
    fn connect_attempts_clamps_zero_to_one() {
        assert_eq!(connect_attempts_from_value(Some("0")), 1);
    }

    #[test]
    fn connect_attempts_cannot_exceed_contract_cap() {
        assert_eq!(connect_attempts_from_value(Some("50")), MAX_ATTEMPTS);
    }

    #[test]
    fn connect_attempts_ignores_unparseable_values() {
        assert_eq!(connect_attempts_from_value(Some("junk")), MAX_ATTEMPTS);
        assert_eq!(connect_attempts_from_value(Some("")), MAX_ATTEMPTS);
        assert_eq!(connect_attempts_from_value(Some("-2")), MAX_ATTEMPTS);
    }

    #[test]
    #[cfg_attr(miri, ignore = "backoff_for_attempt calls apply_jitter (uses SystemTime::now)")]
    fn backoff_for_attempt_is_within_jittered_band() {
        // Attempts 1..MAX_ATTEMPTS — every value should be within ±JITTER_PCT
        // of the base for that attempt (and base is bounded by MAX_BACKOFF).
        for n in 1..MAX_ATTEMPTS {
            let base = backoff_base(n).as_millis() as i128;
            let actual = backoff_for_attempt(n).as_millis() as i128;
            let band = base * JITTER_PCT as i128 / 100;
            assert!(
                actual >= base - band && actual <= base + band,
                "attempt {n}: actual {actual}ms outside [{}..={}]",
                base - band,
                base + band,
            );
        }
    }
}

#[cfg(test)]
mod env_warning_tests {
    use super::*;

    // W1-L8-15: an invalid PKCS11_PROXY_CONNECT_TIMEOUT must produce a
    // loud naming warning (the value still falls back to the default,
    // but never silently).
    #[test]
    fn connect_timeout_warning_names_invalid_value() {
        let warning =
            connect_timeout_warning(Some("junk")).expect("invalid timeout must warn loudly");
        assert!(
            warning.contains("PKCS11_PROXY_CONNECT_TIMEOUT") && warning.contains("junk"),
            "warning must name the var and the value, got: {warning}"
        );
    }

    #[test]
    fn connect_timeout_warning_silent_when_valid_or_unset() {
        assert_eq!(connect_timeout_warning(None), None);
        assert_eq!(connect_timeout_warning(Some("10")), None);
    }

    // W1-L8-15: same loud-warning contract for
    // PKCS11_PROXY_CONNECT_ATTEMPTS. Clamping (0 → 1, >max → max) is
    // documented behavior and stays silent; only unparseable values warn.
    #[test]
    fn connect_attempts_warning_names_invalid_value() {
        let warning =
            connect_attempts_warning(Some("junk")).expect("invalid attempts must warn loudly");
        assert!(
            warning.contains("PKCS11_PROXY_CONNECT_ATTEMPTS") && warning.contains("junk"),
            "warning must name the var and the value, got: {warning}"
        );
    }

    #[test]
    fn connect_attempts_warning_silent_when_valid_unset_or_clamped() {
        assert_eq!(connect_attempts_warning(None), None);
        assert_eq!(connect_attempts_warning(Some("3")), None);
        assert_eq!(connect_attempts_warning(Some("0")), None);
        assert_eq!(connect_attempts_warning(Some("50")), None);
    }

    // W1-C6-05: the pid-claim loop retries a spuriously-failing weak CAS
    // instead of skipping the fork reset for that call.
    #[test]
    fn claim_pid_slot_claims_once_then_observes() {
        use std::sync::atomic::AtomicU32;
        let slot = AtomicU32::new(0);
        assert!(super::claim_pid_slot(&slot, 123), "first claim must win");
        assert_eq!(slot.load(std::sync::atomic::Ordering::Relaxed), 123);
        assert!(
            !super::claim_pid_slot(&slot, 123),
            "re-claim for the same pid observes, not resets"
        );
    }

    #[test]
    fn claim_pid_slot_concurrent_claims_terminate() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        let slot = Arc::new(AtomicU32::new(0));
        let wins = Arc::new(AtomicU32::new(0));
        std::thread::scope(|scope| {
            for thread in 0..8 {
                let slot = Arc::clone(&slot);
                let wins = Arc::clone(&wins);
                scope.spawn(move || {
                    // Distinct pids per thread; every call must either win
                    // the claim or observe a winner — never spin forever and
                    // never report a win it did not perform.
                    for round in 0..50 {
                        let pid = 1000 + thread * 100 + round;
                        if super::claim_pid_slot(&slot, pid) {
                            wins.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        });
        let final_pid = slot.load(Ordering::Relaxed);
        assert!(
            (1000..1800).contains(&final_pid),
            "slot must hold exactly one claimant's pid, got {final_pid}"
        );
        assert!(wins.load(Ordering::Relaxed) > 0, "some claim must have won");
    }
}
