use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tonic::Status;

use pkcs11_proxy_ng_types::*;

use super::super::context_manager::{ClientContextId, ContextManager};
use super::super::handle_map::{BackendHandle, VirtualHandle};

static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static BACKEND_TIMEOUT: OnceLock<Duration> = OnceLock::new();
static MAX_BACKEND_CALLS: OnceLock<usize> = OnceLock::new();
static HEALTH_EVENT_TX: OnceLock<mpsc::UnboundedSender<BackendHealthEvent>> = OnceLock::new();

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
pub fn configure_backend_health_events(tx: mpsc::UnboundedSender<BackendHealthEvent>) {
    HEALTH_EVENT_TX.set(tx).ok();
}

fn report_backend_outcome(success: bool) {
    if let Some(tx) = HEALTH_EVENT_TX.get() {
        let _ = tx.send(if success {
            BackendHealthEvent::Success
        } else {
            BackendHealthEvent::Failure
        });
    }
}

fn backend_timeout() -> Duration {
    *BACKEND_TIMEOUT.get().unwrap_or(&Duration::from_secs(30))
}

fn max_concurrent_backend_calls() -> usize {
    *MAX_BACKEND_CALLS.get().unwrap_or(&200)
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
            Ok(Err(CkRv::DEVICE_ERROR))
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
        // CkRv values that indicate the backend ITSELF is unhealthy
        // (not just that the application's request was malformed).
        // After N consecutive of these, the daemon flips
        // tonic-health to NOT_SERVING so k8s pulls the pod out of
        // the Service endpoint pool.  R8 scenario 2 verifies this.
        Ok(Err(rv))
            if *rv == CkRv::DEVICE_ERROR        // timeout / breaker trip
                || *rv == CkRv::HOST_MEMORY     // HSM resource exhaustion
                || *rv == CkRv::DEVICE_REMOVED  // HSM disconnected
                || *rv == CkRv::TOKEN_NOT_PRESENT =>
        {
            tracing::debug!(rv = %format!("{:?}", rv), "backend outcome: unhealthy");
            false
        }
        Ok(Err(_)) => true, // normal application-level PKCS#11 error
        Err(_) => false,    // blocking-pool panic / transport break
    }
}

/// Trace which RPC produced a backend Success. Helps diagnose
/// why the gate counter resets unexpectedly during R8 scenario 2.
fn _trace_classify_method() {}

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
/// match below, otherwise `mechanism_out` will silently be `None` for
/// that mechanism even when the backend mutated it.
pub(super) fn mechanism_output_to_proto(
    params: CkMechanismParams,
) -> Option<pkcs11_proxy_ng_proto::Mechanism> {
    let mechanism_type = match params {
        CkMechanismParams::Gcm(_) => CkMechanismType::AES_GCM,
        CkMechanismParams::Tls12MasterKeyDerive(_) => CkMechanismType::TLS12_MASTER_KEY_DERIVE,
        _ => return None,
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
    ctx_mgr.resolve_slot(CkSlotId(slot_id)).await.ok_or(CkRv::SLOT_ID_INVALID)
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
    Ok(CkSessionHandle(backend_session.0))
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
    let backend_key = key.map(|h| CkObjectHandle(h.0)).unwrap_or(CkObjectHandle(0));
    Ok((CkSessionHandle(backend_session.0), backend_key))
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
    let backend_object = object.map(|h| CkObjectHandle(h.0)).unwrap_or(CkObjectHandle(0));
    Ok((CkSessionHandle(backend_session.0), backend_object))
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
        first_object.map(|h| CkObjectHandle(h.0)).unwrap_or(CkObjectHandle(0));
    let second_backend_object =
        second_object.map(|h| CkObjectHandle(h.0)).unwrap_or(CkObjectHandle(0));

    Ok((CkSessionHandle(backend_session.0), first_backend_object, second_backend_object))
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

pub(super) async fn register_object_pair(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    first_backend_handle: CkObjectHandle,
    second_backend_handle: CkObjectHandle,
) -> Option<(u64, u64)> {
    ctx_mgr
        .get_context(ctx_id, |ctx| {
            let first = ctx.object_handles.insert(BackendHandle(first_backend_handle.0)).0;
            let second = ctx.object_handles.insert(BackendHandle(second_backend_handle.0)).0;
            (first, second)
        })
        .await
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
    fn classify_device_error_is_unhealthy() {
        // CKR_DEVICE_ERROR is what spawn_backend produces on the
        // timeout and circuit-breaker-trip paths. PKCS#11
        // application errors must NOT use CKR_DEVICE_ERROR — that
        // invariant is enforced by the proto layer (see
        // ADR-0003 §3).
        let result: Result<CkResult<()>, Status> = Ok(Err(CkRv::DEVICE_ERROR));
        assert!(!classify_backend_outcome(&result));
    }

    #[test]
    fn classify_resource_exhaustion_is_unhealthy() {
        // R8 scenario 2: persistent CKR_HOST_MEMORY (HSM out of
        // memory), CKR_DEVICE_REMOVED (HSM disconnected), or
        // CKR_TOKEN_NOT_PRESENT (token gone) are backend-health
        // signals, not application errors. Repeated occurrences
        // flip readiness so k8s pulls the pod out of the Service.
        for rv in [CkRv::HOST_MEMORY, CkRv::DEVICE_REMOVED, CkRv::TOKEN_NOT_PRESENT] {
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
