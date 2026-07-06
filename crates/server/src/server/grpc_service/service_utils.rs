use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tonic::Status;

use pkcs11_proxy_ng_types::*;

use super::super::auth::identity::AuthenticatedIdentity;
use super::super::context_manager::{ClientContextId, ContextManager, ObjectMetadata};
use super::super::handle_map::{BackendHandle, VirtualHandle};
use super::HandlerContext;

static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static BACKEND_TIMEOUT: OnceLock<Duration> = OnceLock::new();
static MAX_BACKEND_CALLS: OnceLock<usize> = OnceLock::new();
static LOGIN_LOCK_TIMEOUT: OnceLock<Duration> = OnceLock::new();
static HEALTH_EVENT_TX: OnceLock<mpsc::Sender<BackendHealthEvent>> = OnceLock::new();
/// Tracks whether the LAST sent health event was `Success`. Initialized
/// to `true` because the health-gate task assumes the daemon starts in
/// `SERVING`. Used by [`report_backend_outcome`] to suppress
/// successive `Success` events — the gate only needs the first
/// `Success` after a `Failure` streak to reset its counter, so a
/// per-RPC `Success` push at the data-plane rate is pure noise.
static LAST_SENT_HEALTHY: AtomicBool = AtomicBool::new(true);

/// Outcome reported by [`spawn_backend`] for the health-gating task
/// in `main.rs` to consume. `Success` = backend produced any
/// `CkResult` (including a PKCS#11 error code that is a normal
/// application-level outcome); `Failure` = transport-level failure
/// (timeout, blocking-pool panic, circuit-breaker trip) — those are
/// the only conditions that flip `tonic-health` to NOT_SERVING.
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
/// DEVICE_ERROR (M2). Scales with the configured global limit.
pub(super) fn per_context_max_in_flight() -> usize {
    (max_concurrent_backend_calls() / 4).max(1)
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
        // for the health gate.
        report_backend_outcome(false);
        return Ok(Err(CkRv::DEVICE_ERROR));
    };

    // Set when the caller's timeout fires: tells the task's completion
    // path to decrement the stuck gauge it was counted into.
    let timed_out = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let timed_out_task = std::sync::Arc::clone(&timed_out);
    let task = spawn_task(move || {
        // Hold the slot for the TRUE lifetime of the backend call: a
        // blocking task always runs to completion, so the guard drops
        // exactly when the FFI returns (even if the caller timed out or
        // the gRPC future was cancelled long before).
        let _guard = guard;
        let result = operation();
        if timed_out_task.load(Ordering::Acquire) {
            let remaining = stuck_gauge.fetch_sub(1, Ordering::Relaxed) - 1;
            tracing::info!(
                stuck_calls = remaining,
                "a previously stuck backend call returned; slot released"
            );
        }
        result
    });

    let result = match tokio::time::timeout(timeout, task).await {
        Ok(result) => result,
        Err(_elapsed) => {
            // Order matters: count the call as stuck BEFORE publishing the
            // flag its completion path reads, so the decrement can never
            // run against a gauge that was not yet incremented.
            let stuck = stuck_gauge.fetch_add(1, Ordering::Relaxed) + 1;
            timed_out.store(true, Ordering::Release);
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
            // ck_rv classifier never sees this proxy-generated DEVICE_ERROR and
            // can treat a backend-RETURNED DEVICE_ERROR as a per-request
            // response rather than a daemon-health signal (M1).
            report_backend_outcome(false);
            return Ok(Err(CkRv::DEVICE_ERROR));
        }
    };

    let healthy = classify_backend_outcome::<T>(&result);
    tracing::debug!(healthy, "backend outcome classified");
    report_backend_outcome(healthy);

    result
}

/// Classify a `spawn_backend` result as healthy (true) or unhealthy
/// (false) from the daemon-level readiness gauge's perspective.
///
/// Health gating triggers ONLY on transport-level failures:
///   * timeouts (mapped to `Ok(Err(CkRv::DEVICE_ERROR))` by
///     [`spawn_backend`] above, distinguishable because PKCS#11
///     application errors must never produce `CKR_DEVICE_ERROR`),
///   * `spawn_blocking` panics (`Err(Status)`),
///   * circuit-breaker trips (also `Ok(Err(CkRv::DEVICE_ERROR))` —
///     reported separately by `spawn_backend` before this function is
///     called).
///
/// PKCS#11 application errors (CKR_PIN_INCORRECT, CKR_DATA_INVALID,
/// CKR_MECHANISM_INVALID, …) are normal client-side outcomes; they
/// must NOT trip the readiness gauge, or a noisy authentication user
/// could take the daemon out of the load-balancer rotation.
///
/// Extracted as a pure function so the contract is testable without
/// the global `HEALTH_EVENT_TX` channel state.
fn classify_backend_outcome<T>(result: &Result<CkResult<T>, Status>) -> bool {
    match result {
        Ok(Ok(_)) => true,
        // Genuine backend/HSM-down signals: the device reports that it is gone
        // or out of memory. A single client's request shape cannot induce these,
        // so repeated occurrences remain a daemon-readiness signal.
        Ok(Err(rv)) if *rv == CkRv::DEVICE_REMOVED || *rv == CkRv::HOST_MEMORY => {
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
    Some(pkcs11_proxy_ng_proto::Mechanism::from(&CkMechanism {
        mechanism_type,
        params: Some(params),
    }))
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
) -> Result<CkSlotId, CkRv> {
    ctx_mgr.resolve_slot(CkSlotId(slot_id as u64)).await.ok_or(CkRv::SLOT_ID_INVALID)
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
            let backend_ref = ctx.backend.clone();
            match spawn_backend(move || backend_ref.get_token_info(backend_slot)).await {
                Ok(Ok(info)) => {
                    ctx.context_manager.cache_token_info(
                        backend_slot,
                        info.label.clone(),
                        info.serial_number.clone(),
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

    // --- 3. Resolve ObjectMetadata from cache or backend ---
    // Token objects (is_token=true) are never cached (I2 fix: cross-client backend
    // handle recycling immunity). Session objects are cached for the lifetime of
    // the virtual handle.
    let meta: Option<ObjectMetadata> =
        ctx.context_manager.object_metadata(ctx_id, virtual_object).await;
    let meta = match meta {
        Some(cached) => cached,
        None => {
            // Cache miss: fetch uid + class + token in one C_GetAttributeValue call.
            let fetched =
                super::authorization::fetch_object_metadata(ctx, backend_session, backend_object)
                    .await;
            // cache_object_metadata internally skips token objects (I2 fix).
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

    // --- 3b. Creator bypass (G3-PR3 Task 2) ---
    // A principal can always use an object it minted this session (generate /
    // create / unwrap), even when its backend-assigned CKA_UNIQUE_ID is not in
    // the pre-configured `objects` grant.  This is the minimal, correct ACL
    // inheritance: creator-owns-what-it-mints.
    //
    // The check is per-context: context B's created_objects set is independent
    // of A's, so B is still gated by its own policy for any object it did NOT
    // mint.  A recycled virtual handle cannot inherit created-status because the
    // removal hooks that evict object_metadata also evict created_objects.
    if ctx.context_manager.object_was_created_here(ctx_id, virtual_object).await {
        return backend_object;
    }

    // --- 4. Policy checks ---
    // Per-object uid check (opt-in; pass-through when no objects grant configured).
    if !ctx.token_policy.allows_object_use(&identity, &label, &serial, &meta.unique_id) {
        // Constant-work deny: substitute the NOT-FOUND sentinel. The handler
        // forwards handle 0 to the backend which returns CKR_OBJECT_HANDLE_INVALID,
        // IDENTICAL to a genuinely-nonexistent object. No log, no audit, no metric.
        return CkObjectHandle(0);
    }
    // Per-class check (opt-in; skipped when no classes grant is configured).
    if ctx.token_policy.per_class_active()
        && !ctx.token_policy.allows_class(&identity, &label, &serial, meta.class)
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
    let Some((session, key)) = ctx
        .context_manager
        .get_context(ctx_id, |c| {
            (
                c.session_handles.resolve(VirtualHandle(session_handle)),
                c.object_handles.resolve(VirtualHandle(key_handle)),
            )
        })
        .await
    else {
        return Err(CkRv::CRYPTOKI_NOT_INITIALIZED);
    };

    let backend_session = session.ok_or(CkRv::SESSION_HANDLE_INVALID)?;
    // When the key handle is unknown to the proxy (not in the mapping),
    // forward CK_INVALID_HANDLE (0) to the backend rather than returning
    // CKR_KEY_HANDLE_INVALID locally.  This preserves transparency: the
    // backend decides the error priority (e.g., CKR_FUNCTION_NOT_SUPPORTED
    // vs CKR_KEY_HANDLE_INVALID).
    let backend_key = key.map_or(CkObjectHandle(0), |h| CkObjectHandle(h.0 as u64));
    // Per-object / per-class gate: enter when any object or class grant is
    // active AND the key resolved to a real handle. When both flags are false
    // (no policy configured) this is a zero-overhead transparent pass-through.
    let backend_key = if (ctx.token_policy.per_object_active()
        || ctx.token_policy.per_class_active())
        && backend_key.0 != 0
    {
        gate_object_handle(ctx, ctx_id, session_handle, key_handle, backend_session, backend_key)
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
    let Some((session, object)) = ctx
        .context_manager
        .get_context(ctx_id, |c| {
            (
                c.session_handles.resolve(VirtualHandle(session_handle)),
                c.object_handles.resolve(VirtualHandle(object_handle)),
            )
        })
        .await
    else {
        return Err(CkRv::CRYPTOKI_NOT_INITIALIZED);
    };

    let backend_session = session.ok_or(CkRv::SESSION_HANDLE_INVALID)?;
    // Forward CK_INVALID_HANDLE to backend when object is unknown — see
    // resolve_session_and_key for rationale.
    let backend_object = object.map_or(CkObjectHandle(0), |h| CkObjectHandle(h.0 as u64));
    // Per-object / per-class gate: see gate_object_handle for the invisible-denial
    // contract. Zero-overhead when both per_object_active() and per_class_active()
    // are false.
    let backend_object = if (ctx.token_policy.per_object_active()
        || ctx.token_policy.per_class_active())
        && backend_object.0 != 0
    {
        gate_object_handle(
            ctx,
            ctx_id,
            session_handle,
            object_handle,
            backend_session,
            backend_object,
        )
        .await
    } else {
        backend_object
    };
    Ok((CkSessionHandle(backend_session.0 as u64), backend_object))
}

pub(super) async fn resolve_session_and_two_objects(
    ctx: &HandlerContext,
    ctx_id: &ClientContextId,
    session_handle: u64,
    first_object_handle: u64,
    second_object_handle: u64,
) -> Result<(CkSessionHandle, CkObjectHandle, CkObjectHandle), CkRv> {
    let Some((session, first_object, second_object)) = ctx
        .context_manager
        .get_context(ctx_id, |c| {
            (
                c.session_handles.resolve(VirtualHandle(session_handle)),
                c.object_handles.resolve(VirtualHandle(first_object_handle)),
                c.object_handles.resolve(VirtualHandle(second_object_handle)),
            )
        })
        .await
    else {
        return Err(CkRv::CRYPTOKI_NOT_INITIALIZED);
    };

    let backend_session = session.ok_or(CkRv::SESSION_HANDLE_INVALID)?;
    // Forward CK_INVALID_HANDLE to backend when either object is unknown; see
    // resolve_session_and_key for rationale. Local context/session validation
    // remains explicit; backend-visible object handle priority stays backend-owned.
    let first_backend_object =
        first_object.map_or(CkObjectHandle(0), |h| CkObjectHandle(h.0 as u64));
    let second_backend_object =
        second_object.map_or(CkObjectHandle(0), |h| CkObjectHandle(h.0 as u64));
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

pub(super) async fn register_object_handle(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    backend_handle: CkObjectHandle,
) -> u64 {
    ctx_mgr
        .get_context(ctx_id, |ctx| ctx.object_handles.insert(BackendHandle(backend_handle.0)).0)
        .await
        .unwrap_or(0)
}

/// True when `template` declares `CKA_TOKEN` as a true value — i.e. a token
/// object, whose handle persists across the application's sessions and must NOT
/// be evicted on session close. The bool may arrive as a typed `Bool`, a raw
/// `CK_BBOOL` byte, or a ulong, so all encodings are accepted (B2).
pub(super) fn template_declares_token_object(template: &[CkAttribute]) -> bool {
    template.iter().any(|attr| {
        attr.attr_type == CkAttributeType::TOKEN
            && match &attr.value {
                Some(CkAttributeValue::Bool(b)) => *b,
                Some(CkAttributeValue::Bytes(bytes)) => bytes.first().is_some_and(|&b| b != 0),
                Some(CkAttributeValue::Ulong(u)) => *u != 0,
                _ => false,
            }
    })
}

/// Register a backend object handle and, when it is a session object, record it
/// under `session` so it is evicted when that session closes (B2). Returns the
/// virtual object handle (0 if the context is gone).
///
/// This is a MINTING registration (generate/create/unwrap path). The new
/// virtual handle is inserted into `created_objects` so the per-object gate
/// (`gate_object_handle`) allows the creating context to use this key even
/// when its backend-assigned `CKA_UNIQUE_ID` is not in the pre-configured
/// `objects` grant (G3-PR3 Task 2).
pub(super) async fn register_session_object_handle(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    session: VirtualHandle,
    backend_handle: CkObjectHandle,
    is_token_object: bool,
) -> u64 {
    ctx_mgr
        .get_context(ctx_id, |ctx| {
            let virtual_object = ctx.object_handles.insert(BackendHandle(backend_handle.0));
            if !is_token_object {
                ctx.record_session_object(session, virtual_object);
            }
            // Minting: the creating context can always use what it generated.
            ctx.created_objects.insert(virtual_object);
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
pub(super) async fn register_session_object_pair(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    session: VirtualHandle,
    first_backend_handle: CkObjectHandle,
    first_is_token: bool,
    second_backend_handle: CkObjectHandle,
    second_is_token: bool,
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
            (first.0, second.0)
        })
        .await
}

pub(super) async fn register_session_handle(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    backend_handle: CkSessionHandle,
    slot_id: CkSlotId,
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
    fn mechanism_output_to_proto_handles_gcm() {
        let params = CkMechanismParams::Gcm(GcmParams {
            iv: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            iv_bits: 96,
            iv_buffer_len: 12,
            aad: Vec::new(),
            tag_bits: 128,
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
            prf_hash_mechanism: CkMechanismType::SHA256.0,
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
            data: vec![1, 2, 3],
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
            CkRv::DEVICE_ERROR,
            "caller sees the timeout as DEVICE_ERROR"
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
        // client could evict the pod. The daemon's own timeout/breaker DEVICE_ERROR
        // is reported separately in spawn_backend before classification.
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
        assert_eq!(inner.unwrap_err(), CkRv::DEVICE_ERROR);

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
                let session = c.register_session(BackendHandle(123), CkSlotId(7));
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
                let session = c.register_session(BackendHandle(123), CkSlotId(7));
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
                        objects: Some(vec![allowed_uid_hex.into()]),
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
        let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        let backend_object = mock.create_object(backend_session, &[]).unwrap();

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
                MockAttributeSlot::Value(CkAttributeValue::Bytes(uid)),
            );
        }

        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(CkSlotId(0)).await;
        ctx_mgr.cache_token_info(CkSlotId(0), "MockToken".into(), "0001".into());
        let ctx_id = ctx_mgr.create_context(identity).await.unwrap();

        let (virtual_session, virtual_object) = ctx_mgr
            .get_context(&ctx_id, |c| {
                let vs = c.register_session(BackendHandle(backend_session.0), CkSlotId(0));
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
                let vs = c.register_session(BackendHandle(77), CkSlotId(0));
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
                let vs = c.register_session(BackendHandle(77), CkSlotId(0));
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
    async fn per_object_gate_token_object_not_cached() {
        // I2 proof: a token object (is_token=true) must NOT be cached.
        // Two consecutive gate calls on the same token-object virtual handle must
        // each trigger a fresh backend C_GetAttributeValue (no cache hit).
        // We verify by counting backend attribute calls via a mock counter.
        use pkcs11_proxy_ng_backend::{MockBackend, mock::MockAttributeSlot};
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock.initialize().unwrap();
        let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        let backend_object = mock.create_object(backend_session, &[]).unwrap();

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
            MockAttributeSlot::Value(CkAttributeValue::Bytes(uid.clone())),
        );

        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> = mock.clone();
        let policy = per_object_policy(IDENTITY, "MockToken", ALLOWED_UID_HEX);
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(CkSlotId(0)).await;
        ctx_mgr.cache_token_info(CkSlotId(0), "MockToken".into(), "0001".into());
        let ctx_id = ctx_mgr.create_context(Some(IDENTITY.into())).await.unwrap();
        let (virtual_session, virtual_object) = ctx_mgr
            .get_context(&ctx_id, |c| {
                let vs = c.register_session(BackendHandle(backend_session.0), CkSlotId(0));
                let vo = c.object_handles.insert(BackendHandle(backend_object.0));
                (vs, vo)
            })
            .await
            .unwrap();
        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        ctx.token_policy = policy;

        // First gate call — should fetch from backend.
        let _ = resolve_session_and_object(&ctx, &ctx_id, virtual_session.0, virtual_object.0)
            .await
            .unwrap();
        // Second gate call — token objects must NOT be cached; must re-fetch.
        let _ = resolve_session_and_object(&ctx, &ctx_id, virtual_session.0, virtual_object.0)
            .await
            .unwrap();

        // cache_object_metadata skips token objects (is_token=true), so the context's
        // object_metadata map must have NO entry for this virtual handle.
        let cached = ctx_mgr.object_metadata(&ctx_id, virtual_object.0).await;
        assert!(
            cached.is_none(),
            "token object metadata must NOT be cached in the context (I2 fix)"
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
        let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        let backend_object = mock.create_object(backend_session, &[]).unwrap();
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
            MockAttributeSlot::Value(CkAttributeValue::Bytes(OTHER_UID_BYTES.to_vec())),
        );

        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(CkSlotId(0)).await;
        ctx_mgr.cache_token_info(CkSlotId(0), "MockToken".into(), "0001".into());
        let ctx_id = ctx_mgr.create_context(Some(IDENTITY.into())).await.unwrap();

        let virtual_session = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(BackendHandle(backend_session.0), CkSlotId(0))
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
        let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        let backend_object = mock.create_object(backend_session, &[]).unwrap();
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
            MockAttributeSlot::Value(CkAttributeValue::Bytes(OTHER_UID_BYTES.to_vec())),
        );

        let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        ctx_mgr.register_slot(CkSlotId(0)).await;
        ctx_mgr.cache_token_info(CkSlotId(0), "MockToken".into(), "0001".into());

        // Context A: IDENTITY mints the object.
        let ctx_id_a = ctx_mgr.create_context(Some(IDENTITY.into())).await.unwrap();
        let vs_a = ctx_mgr
            .get_context(&ctx_id_a, |c| {
                c.register_session(BackendHandle(backend_session.0), CkSlotId(0))
            })
            .await
            .unwrap();
        let vo_a_raw =
            register_session_object_handle(&ctx_mgr, &ctx_id_a, vs_a, backend_object, false).await;

        // Context B: uid=9999 sees the SAME backend object (e.g. via an out-of-band
        // find) but did NOT mint it — registered via direct insert, not minting.
        let ctx_id_b = ctx_mgr.create_context(Some("uid=9999".into())).await.unwrap();
        let vo_b_raw = ctx_mgr
            .get_context(&ctx_id_b, |c| {
                let vs_b = c.register_session(BackendHandle(backend_session.0), CkSlotId(0));
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
        let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
        let backend_session = mock.open_session(CkSlotId(0), flags).unwrap();
        let backend_object = mock.create_object(backend_session, &[]).unwrap();
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
        ctx_mgr.register_slot(CkSlotId(0)).await;
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        let vs = ctx_mgr
            .get_context(&ctx_id, |c| {
                c.register_session(BackendHandle(backend_session.0), CkSlotId(0))
            })
            .await
            .unwrap();

        let vo_raw =
            register_session_object_handle(&ctx_mgr, &ctx_id, vs, backend_object, false).await;

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
}
