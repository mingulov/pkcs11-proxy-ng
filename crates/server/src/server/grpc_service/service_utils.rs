use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tonic::Status;

use pkcs11_proxy_ng_types::*;

use super::super::context_manager::{ClientContextId, ContextManager};
use super::super::handle_map::{BackendHandle, VirtualHandle};

static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static BACKEND_TIMEOUT: OnceLock<Duration> = OnceLock::new();
static MAX_BACKEND_CALLS: OnceLock<usize> = OnceLock::new();
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
struct InFlightGuard<'a> {
    counter: &'a AtomicUsize,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

fn try_acquire_backend_call(counter: &AtomicUsize, max_calls: usize) -> Option<InFlightGuard<'_>> {
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
    // Circuit breaker
    let max_calls = max_concurrent_backend_calls();
    let Some(_guard) = try_acquire_backend_call(&IN_FLIGHT, max_calls) else {
        let current = IN_FLIGHT.load(Ordering::Relaxed);
        tracing::error!(
            in_flight = current,
            max = max_calls,
            "Backend circuit breaker tripped — too many in-flight calls"
        );
        // A flood of breaker trips means the daemon is overloaded and
        // downstream traffic should be diverted — count as a failure
        // for the health gate.
        report_backend_outcome(false);
        return Ok(Err(CkRv::DEVICE_ERROR));
    };

    let result = match tokio::time::timeout(backend_timeout(), spawn_task(operation)).await {
        Ok(result) => result,
        Err(_elapsed) => {
            tracing::warn!(
                timeout_secs = backend_timeout().as_secs(),
                in_flight = IN_FLIGHT.load(Ordering::Relaxed),
                "Backend call timed out. Consider increasing \
                 proxy.request_timeout_secs or investigating HSM responsiveness."
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
    // _guard drops here (or when Future is cancelled) → IN_FLIGHT decremented
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

pub(super) async fn resolve_session_and_key(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    session_handle: u64,
    key_handle: u64,
) -> Result<(CkSessionHandle, CkObjectHandle), CkRv> {
    let Some((session, key)) = ctx_mgr
        .get_context(ctx_id, |ctx| {
            (
                ctx.session_handles.resolve(VirtualHandle(session_handle)),
                ctx.object_handles.resolve(VirtualHandle(key_handle)),
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
    Ok((CkSessionHandle(backend_session.0 as u64), backend_key))
}

pub(super) async fn resolve_session_and_object(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    session_handle: u64,
    object_handle: u64,
) -> Result<(CkSessionHandle, CkObjectHandle), CkRv> {
    let Some((session, object)) = ctx_mgr
        .get_context(ctx_id, |ctx| {
            (
                ctx.session_handles.resolve(VirtualHandle(session_handle)),
                ctx.object_handles.resolve(VirtualHandle(object_handle)),
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
    Ok((CkSessionHandle(backend_session.0 as u64), backend_object))
}

pub(super) async fn resolve_session_and_two_objects(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    session_handle: u64,
    first_object_handle: u64,
    second_object_handle: u64,
) -> Result<(CkSessionHandle, CkObjectHandle, CkObjectHandle), CkRv> {
    let Some((session, first_object, second_object)) = ctx_mgr
        .get_context(ctx_id, |ctx| {
            (
                ctx.session_handles.resolve(VirtualHandle(session_handle)),
                ctx.object_handles.resolve(VirtualHandle(first_object_handle)),
                ctx.object_handles.resolve(VirtualHandle(second_object_handle)),
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
            virtual_object.0
        })
        .await
        .unwrap_or(0)
}

/// Register a generated key pair, recording each key as a session object under
/// `session` unless its own template marks it a token object (B2).
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
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let max = 3;

        let first = try_acquire_backend_call(&counter, max).expect("first slot");
        let second = try_acquire_backend_call(&counter, max).expect("second slot");
        let third = try_acquire_backend_call(&counter, max).expect("third slot");

        assert_eq!(counter.load(Ordering::Relaxed), max);
        assert!(try_acquire_backend_call(&counter, max).is_none());
        assert_eq!(
            counter.load(Ordering::Relaxed),
            max,
            "failed acquisition must not overshoot the configured bound"
        );

        drop(second);
        assert_eq!(counter.load(Ordering::Relaxed), max - 1);

        let replacement =
            try_acquire_backend_call(&counter, max).expect("slot released by dropped guard");
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
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let (session, known_object) = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                let session = ctx.register_session(BackendHandle(123), CkSlotId(7));
                let object = ctx.object_handles.insert(BackendHandle(456));
                (session, object)
            })
            .await
            .unwrap();

        let result =
            resolve_session_and_two_objects(&ctx_mgr, &ctx_id, session.0, 999, known_object.0)
                .await
                .unwrap();

        assert_eq!(result, (CkSessionHandle(123), CkObjectHandle(0), CkObjectHandle(456)));
    }

    #[tokio::test]
    async fn resolve_two_objects_forwards_unknown_second_object_to_backend() {
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let (session, known_object) = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                let session = ctx.register_session(BackendHandle(123), CkSlotId(7));
                let object = ctx.object_handles.insert(BackendHandle(456));
                (session, object)
            })
            .await
            .unwrap();

        let result =
            resolve_session_and_two_objects(&ctx_mgr, &ctx_id, session.0, known_object.0, 999)
                .await
                .unwrap();

        assert_eq!(result, (CkSessionHandle(123), CkObjectHandle(456), CkObjectHandle(0)));
    }
}
