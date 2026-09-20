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
    PRE_INIT_CONNECT_FAILED_KEY.load(Ordering::Relaxed)
        == pre_init_failure_key(&resolve_endpoint_from_env())
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
    if SHIM_PID.load(Ordering::Relaxed) == pid {
        return;
    }
    if SHIM_PID
        .compare_exchange_weak(
            SHIM_PID.load(Ordering::Relaxed),
            pid,
            Ordering::AcqRel,
            Ordering::Relaxed,
        )
        .is_ok()
    {
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

pub type SessionByteCacheMap = Mutex<HashMap<CK_SESSION_HANDLE, Vec<u8>>>;
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

fn forget_session_slot(h_session: CK_SESSION_HANDLE) {
    if let Ok(mut map) = SESSION_SLOTS.lock() {
        map.remove(&h_session);
    }
}

/// Lazily-initialised holder for a per-session byte-output cache, used
/// by the two-call `C_*` patterns (`C_Sign`, `C_SignFinal`, `C_Digest`,
/// etc.). The macro `byte_cache!` below declares one static per
/// PKCS#11 op so each op gets its own cache.
pub struct ByteResultCache(LazyLock<SessionByteCacheMap>);

impl ByteResultCache {
    pub const fn new() -> Self {
        Self(LazyLock::new(|| Mutex::new(HashMap::new())))
    }

    pub fn get(&self) -> &SessionByteCacheMap {
        &self.0
    }
}

macro_rules! byte_cache {
    ($(#[$meta:meta])* $name:ident, $static_name:ident) => {
        $(#[$meta])*
        static $static_name: ByteResultCache = ByteResultCache::new();

        pub fn $name() -> &'static SessionByteCacheMap {
            $static_name.get()
        }
    };
}

byte_cache!(
    /// Two-call pattern cache for one-shot `C_Sign`.
    sig_cache,
    SIG_CACHE
);
byte_cache!(
    /// Two-call pattern cache for `C_SignFinal`.
    sig_final_cache,
    SIG_FINAL_CACHE
);
byte_cache!(
    /// Two-call pattern cache for one-shot `C_Digest`.
    dig_cache,
    DIG_CACHE
);
byte_cache!(
    /// Two-call pattern cache for `C_DigestFinal`.
    dig_final_cache,
    DIG_FINAL_CACHE
);
byte_cache!(
    /// Two-call pattern cache for one-shot `C_Encrypt`.
    enc_cache,
    ENC_CACHE
);
byte_cache!(
    /// Two-call pattern cache for `C_EncryptFinal`.
    enc_final_cache,
    ENC_FINAL_CACHE
);
byte_cache!(
    /// Two-call pattern cache for one-shot `C_Decrypt`.
    dec_cache,
    DEC_CACHE
);
byte_cache!(
    /// Two-call pattern cache for `C_DecryptFinal`.
    dec_final_cache,
    DEC_FINAL_CACHE
);
byte_cache!(
    /// Two-call pattern cache for `C_WrapKey`.
    wrap_cache,
    WRAP_CACHE
);
byte_cache!(
    /// Two-call pattern cache for `C_GetOperationState`.
    op_state_cache,
    OP_STATE_CACHE
);
byte_cache!(
    /// Two-call pattern cache for `C_SignRecover`.
    sign_recover_cache,
    SIGN_RECOVER_CACHE
);
byte_cache!(
    /// Two-call pattern cache for `C_VerifyRecover`.
    verify_recover_cache,
    VERIFY_RECOVER_CACHE
);
byte_cache!(
    /// Two-call pattern cache for message encrypt output:
    /// `C_EncryptMessage` and `C_EncryptMessageNext`.
    msg_enc_cache,
    MSG_ENC_CACHE
);
byte_cache!(
    /// Two-call pattern cache for message decrypt output:
    /// `C_DecryptMessage` and `C_DecryptMessageNext`.
    msg_dec_cache,
    MSG_DEC_CACHE
);
byte_cache!(
    /// Two-call pattern cache for message sign output:
    /// `C_SignMessage` and `C_SignMessageNext`.
    msg_sign_cache,
    MSG_SIGN_CACHE
);
byte_cache!(
    /// Two-call pattern cache for `C_WrapKeyAuthenticated`.
    wrap_auth_cache,
    WRAP_AUTH_CACHE
);

/// Cache type for `C_EncapsulateKey`: stores `(ciphertext, key_handle)` atomically.
///
/// Unlike the byte-only `SessionByteCacheMap`, this caches the full result tuple
/// so that the second call of the two-call pattern returns both the ciphertext
/// and the key handle without creating a duplicate key on the backend.
pub type SessionEncapsulateCacheMap =
    Mutex<HashMap<CK_SESSION_HANDLE, (Vec<u8>, cryptoki_sys::CK_OBJECT_HANDLE)>>;

pub struct EncapsulateResultCache(OnceLock<SessionEncapsulateCacheMap>);

impl EncapsulateResultCache {
    pub const fn new() -> Self {
        Self(OnceLock::new())
    }

    pub fn get(&self) -> &SessionEncapsulateCacheMap {
        self.0.get_or_init(|| Mutex::new(HashMap::new()))
    }
}

static ENCAPSULATE_CACHE: EncapsulateResultCache = EncapsulateResultCache::new();

/// Two-call pattern cache for `C_EncapsulateKey`: stores `(ciphertext, key_handle)`.
pub fn encapsulate_cache() -> &'static SessionEncapsulateCacheMap {
    ENCAPSULATE_CACHE.get()
}

/// Run `f` against each per-session byte cache (input and output) so callers
/// can query or evict entries across all of them.
fn with_all_byte_caches(mut f: impl FnMut(&SessionByteCacheMap)) {
    let byte_caches: &[&SessionByteCacheMap] = &[
        sig_cache(),
        sig_final_cache(),
        dig_cache(),
        dig_final_cache(),
        enc_cache(),
        enc_final_cache(),
        dec_cache(),
        dec_final_cache(),
        wrap_cache(),
        op_state_cache(),
        sign_recover_cache(),
        verify_recover_cache(),
        msg_enc_cache(),
        msg_dec_cache(),
        msg_sign_cache(),
        wrap_auth_cache(),
    ];
    for cache in byte_caches {
        f(cache);
    }
}

fn clear_session_byte_caches(h_session: CK_SESSION_HANDLE, caches: &[&SessionByteCacheMap]) {
    for cache in caches {
        if let Ok(mut map) = cache.lock() {
            map.remove(&h_session);
        }
    }
}

pub(crate) fn clear_sign_output_caches(h_session: CK_SESSION_HANDLE) {
    clear_session_byte_caches(h_session, &[sig_cache(), sig_final_cache()]);
}

pub(crate) fn clear_digest_output_caches(h_session: CK_SESSION_HANDLE) {
    clear_session_byte_caches(h_session, &[dig_cache(), dig_final_cache()]);
}

pub(crate) fn clear_encrypt_output_caches(h_session: CK_SESSION_HANDLE) {
    clear_session_byte_caches(h_session, &[enc_cache(), enc_final_cache()]);
}

pub(crate) fn clear_decrypt_output_caches(h_session: CK_SESSION_HANDLE) {
    clear_session_byte_caches(h_session, &[dec_cache(), dec_final_cache()]);
}

pub(crate) fn clear_sign_recover_output_cache(h_session: CK_SESSION_HANDLE) {
    clear_session_byte_caches(h_session, &[sign_recover_cache()]);
}

pub(crate) fn clear_verify_recover_output_cache(h_session: CK_SESSION_HANDLE) {
    clear_session_byte_caches(h_session, &[verify_recover_cache()]);
}

pub(crate) fn clear_message_encrypt_output_cache(h_session: CK_SESSION_HANDLE) {
    clear_session_byte_caches(h_session, &[msg_enc_cache()]);
}

pub(crate) fn clear_message_decrypt_output_cache(h_session: CK_SESSION_HANDLE) {
    clear_session_byte_caches(h_session, &[msg_dec_cache()]);
}

pub(crate) fn clear_message_sign_output_cache(h_session: CK_SESSION_HANDLE) {
    clear_session_byte_caches(h_session, &[msg_sign_cache()]);
}

pub(crate) fn clear_operation_state_cache(h_session: CK_SESSION_HANDLE) {
    clear_session_byte_caches(h_session, &[op_state_cache()]);
}

/// Clear every output cache across all sessions.
pub(crate) fn clear_all_caches() {
    with_all_byte_caches(|cache| {
        if let Ok(mut map) = cache.lock() {
            map.clear();
        }
    });
    if let Ok(mut map) = encapsulate_cache().lock() {
        map.clear();
    }
    if let Ok(mut map) = SESSION_SLOTS.lock() {
        map.clear();
    }
    if let Ok(mut map) = MESSAGE_OPERATION_STATES.lock() {
        map.clear();
    }
}

fn evict_disposable_output_caches_for_session(h_session: CK_SESSION_HANDLE) {
    with_all_byte_caches(|cache| {
        if let Ok(mut map) = cache.lock() {
            map.remove(&h_session);
        }
    });
    if let Ok(mut map) = encapsulate_cache().lock() {
        map.remove(&h_session);
    }
}

/// Drop only retryable/two-call output material, without changing session
/// ownership or authoritative message-operation discriminators.
pub(crate) fn evict_session_output_caches(h_session: CK_SESSION_HANDLE) {
    evict_disposable_output_caches_for_session(h_session);
}

/// Forget session ownership and all message-operation discriminators without
/// touching the disposable output caches.  Close uses this only for terminal
/// or outcome-ambiguous results; decoded transient failures keep it intact.
pub(crate) fn evict_session_authoritative_state(h_session: CK_SESSION_HANDLE) {
    forget_session_slot(h_session);
    evict_message_operations(h_session);
}

/// Remove all cached two-call-pattern data for sessions opened on one slot.
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
        evict_disposable_output_caches_for_session(session);
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

fn connect_client_from_env() -> Result<Pkcs11Client, CkRv> {
    let endpoint = resolve_endpoint_from_env();
    let timeout_secs: u64 = std::env::var("PKCS11_PROXY_CONNECT_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
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
///      TLS-PSK. A `tls://` URL logs an explicit error and falls
///      through to the default endpoint so the daemon refuses the
///      connection visibly rather than silently misrouting.
///   3. Default `http://127.0.0.1:7512`.
fn resolve_endpoint_from_env() -> String {
    if let Ok(endpoint) = std::env::var("PKCS11_PROXY_ENDPOINT") {
        if std::env::var_os("PKCS11_PROXY_SOCKET").is_some() {
            tracing::debug!(
                "PKCS11_PROXY_ENDPOINT and PKCS11_PROXY_SOCKET both set; \
                 PKCS11_PROXY_ENDPOINT wins"
            );
        }
        return endpoint;
    }
    if let Ok(socket) = std::env::var("PKCS11_PROXY_SOCKET") {
        if let Some(rest) = socket.strip_prefix("tcp://") {
            let translated = format!("http://{rest}");
            tracing::info!(
                socket = %socket,
                endpoint = %translated,
                "translating legacy PKCS11_PROXY_SOCKET to PKCS11_PROXY_ENDPOINT"
            );
            return translated;
        }
        if socket.starts_with("tls://") {
            tracing::error!(
                socket = %socket,
                "PKCS11_PROXY_SOCKET tls:// is not supported by this shim; \
                 use PKCS11_PROXY_ENDPOINT=https://... and PKCS11_PROXY_TLS_* env vars for mTLS"
            );
            // Fall through to the default endpoint so the connection
            // attempt fails visibly rather than silently misrouting.
        } else {
            tracing::warn!(
                socket = %socket,
                "PKCS11_PROXY_SOCKET must use tcp:// prefix; ignoring"
            );
        }
    }
    "http://127.0.0.1:7512".to_string()
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
        let client = connect_client_from_env()?;
        runtime().block_on(async {
            *existing.lock().await = client;
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

async fn connect_with_retry(
    endpoint: &str,
    tls_files: Option<pkcs11_proxy_ng_client::tls::ClientTlsFiles>,
    timeout_secs: u64,
) -> Result<Pkcs11Client, String> {
    #[cfg(test)]
    CONNECT_SERIES.fetch_add(1, Ordering::Relaxed);
    let connect_timeout = Duration::from_secs(timeout_secs);
    let max_attempts =
        connect_attempts_from_value(std::env::var("PKCS11_PROXY_CONNECT_ATTEMPTS").ok().as_deref());

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
