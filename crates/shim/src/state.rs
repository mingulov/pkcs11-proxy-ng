use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use cryptoki_sys::{CK_SESSION_HANDLE, CK_SLOT_ID};
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::{CkRv, MechanismRegistry};
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static CLIENT: OnceLock<tokio::sync::Mutex<Pkcs11Client>> = OnceLock::new();
/// Guards the one-time CLIENT initialization so that concurrent callers
/// wait rather than racing to connect, and so that a failed init is
/// retried on the next `C_Initialize` rather than being cached forever.
static CLIENT_INIT: Mutex<()> = Mutex::new(());
/// `C_Finalize` ends the PKCS#11 application context.  A later
/// `C_Initialize` must re-read connection configuration instead of reusing a
/// channel that may point at an old daemon.
static CLIENT_RECONNECT_REQUIRED: AtomicBool = AtomicBool::new(false);
static MECHANISM_REGISTRY: OnceLock<MechanismRegistry> = OnceLock::new();

/// Returns the global mechanism registry.
///
/// Panics if called before `init_mechanism_registry()`.
pub fn mechanism_registry() -> &'static MechanismRegistry {
    MECHANISM_REGISTRY.get().expect("MechanismRegistry not initialized")
}

/// Initialize the global mechanism registry (called from `C_Initialize`).
///
/// Returns `Ok(())` on first call; `Err` if already set (OnceLock semantics).
pub fn init_mechanism_registry(reg: MechanismRegistry) -> Result<(), MechanismRegistry> {
    MECHANISM_REGISTRY.set(reg)
}

/// Whether `C_Initialize` has been called and returned `CKR_OK`.
///
/// The shim checks this flag locally before forwarding to the server so
/// that `CKR_CRYPTOKI_ALREADY_INITIALIZED` (double init) and
/// `CKR_CRYPTOKI_NOT_INITIALIZED` (finalize before init) are returned
/// without a network round-trip.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Returns `true` if `C_Initialize` has completed successfully.
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

/// Transition from uninitialized → initialized.
/// Returns `true` if the transition succeeded (i.e., was not already set).
pub fn mark_initialized() -> bool {
    INITIALIZED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok()
}

/// Transition from initialized → uninitialized.
pub fn mark_finalized() {
    INITIALIZED.store(false, Ordering::Release);
}

/// Require the next client access to connect from the current environment.
pub fn mark_client_reconnect_required() {
    CLIENT_RECONNECT_REQUIRED.store(true, Ordering::Release);
}

pub type SessionByteCacheMap = Mutex<HashMap<CK_SESSION_HANDLE, Vec<u8>>>;
pub type SessionSlotMap = Mutex<HashMap<CK_SESSION_HANDLE, CK_SLOT_ID>>;
type SessionMechanismParamMap = Mutex<HashMap<CK_SESSION_HANDLE, usize>>;

static SESSION_SLOTS: OnceLock<SessionSlotMap> = OnceLock::new();
static DELAYED_GCM_WRITEBACK: OnceLock<SessionMechanismParamMap> = OnceLock::new();

fn session_slots() -> &'static SessionSlotMap {
    SESSION_SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn delayed_gcm_writebacks() -> &'static SessionMechanismParamMap {
    DELAYED_GCM_WRITEBACK.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn remember_session_slot(h_session: CK_SESSION_HANDLE, slot_id: CK_SLOT_ID) {
    if let Ok(mut map) = session_slots().lock() {
        map.insert(h_session, slot_id);
    }
}

fn forget_session_slot(h_session: CK_SESSION_HANDLE) {
    if let Ok(mut map) = session_slots().lock() {
        map.remove(&h_session);
    }
}

pub(crate) fn remember_delayed_gcm_writeback(
    h_session: CK_SESSION_HANDLE,
    mechanism_param_addr: usize,
) {
    if let Ok(mut map) = delayed_gcm_writebacks().lock() {
        map.insert(h_session, mechanism_param_addr);
    }
}

pub(crate) fn take_delayed_gcm_writeback(h_session: CK_SESSION_HANDLE) -> Option<usize> {
    delayed_gcm_writebacks().lock().ok().and_then(|mut map| map.remove(&h_session))
}

pub(crate) fn clear_delayed_gcm_writeback(h_session: CK_SESSION_HANDLE) {
    if let Ok(mut map) = delayed_gcm_writebacks().lock() {
        map.remove(&h_session);
    }
}

pub struct ByteResultCache(OnceLock<SessionByteCacheMap>);

impl ByteResultCache {
    pub const fn new() -> Self {
        Self(OnceLock::new())
    }

    pub fn get(&self) -> &SessionByteCacheMap {
        self.0.get_or_init(|| Mutex::new(HashMap::new()))
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

/// Remove all cached two-call-pattern data for the given session handle.
///
/// Called from `c_close_session` after the server confirms the close,
/// so that stale entries do not accumulate and leak memory.
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
    if let Ok(mut map) = session_slots().lock() {
        map.clear();
    }
    if let Ok(mut map) = delayed_gcm_writebacks().lock() {
        map.clear();
    }
}

fn evict_output_caches_for_session(h_session: CK_SESSION_HANDLE) {
    with_all_byte_caches(|cache| {
        if let Ok(mut map) = cache.lock() {
            map.remove(&h_session);
        }
    });
    if let Ok(mut map) = encapsulate_cache().lock() {
        map.remove(&h_session);
    }
    clear_delayed_gcm_writeback(h_session);
}

/// Remove all cached two-call-pattern data for the given session handle.
///
/// Called from `c_close_session` after the server confirms the close,
/// so that stale entries do not accumulate and leak memory.
pub(crate) fn evict_session_caches(h_session: CK_SESSION_HANDLE) {
    forget_session_slot(h_session);
    evict_output_caches_for_session(h_session);
}

/// Remove all cached two-call-pattern data for sessions opened on one slot.
///
/// Called from `c_close_all_sessions` after the server confirms the close.
pub(crate) fn evict_slot_session_caches(slot_id: CK_SLOT_ID) {
    let sessions = if let Ok(mut map) = session_slots().lock() {
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
        evict_output_caches_for_session(session);
    }
}

pub fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| Runtime::new().expect("Failed to create tokio runtime"))
}

fn connect_client_from_env() -> Result<Pkcs11Client, CkRv> {
    let endpoint =
        std::env::var("PKCS11_PROXY_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:7512".into());
    let timeout_secs: u64 = std::env::var("PKCS11_PROXY_CONNECT_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let tls_files =
        pkcs11_proxy_ng_client::tls::ClientTlsFiles::from_env().map_err(|_| CkRv::DEVICE_ERROR)?;
    let rt = runtime();
    rt.block_on(async { connect_with_retry(&endpoint, tls_files, timeout_secs).await })
        .map_err(|_| CkRv::DEVICE_ERROR)
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
    // Fast path: already connected.
    if CLIENT.get().is_some() && !CLIENT_RECONNECT_REQUIRED.load(Ordering::Acquire) {
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

/// Connect to the daemon with up to 3 attempts and exponential backoff.
async fn connect_with_retry(
    endpoint: &str,
    tls_files: Option<pkcs11_proxy_ng_client::tls::ClientTlsFiles>,
    timeout_secs: u64,
) -> Result<Pkcs11Client, String> {
    let delays = [
        Duration::from_millis(0),   // attempt 1: immediate
        Duration::from_millis(100), // attempt 2: 100ms backoff
        Duration::from_millis(500), // attempt 3: 500ms backoff
    ];
    let connect_timeout = Duration::from_secs(timeout_secs);

    for (i, delay) in delays.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(*delay).await;
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
                tracing::warn!(attempt = i + 1, error = %e, "gRPC connect failed, retrying");
            }
            Err(_) => {
                tracing::warn!(attempt = i + 1, timeout_secs, "gRPC connect timed out, retrying");
            }
        }
    }
    Err("all connect attempts failed".into())
}
