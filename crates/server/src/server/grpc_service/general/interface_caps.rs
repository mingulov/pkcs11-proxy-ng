use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_proto::MechanismRegistryPayload;

use crate::mechanism_registry_source::MechanismRegistrySource;
use crate::server::rate_limit;

use super::super::super::context_manager::ContextManager;

/// Maximum age of a cached discovery rendering (W1-L13-22). A rotated
/// registry revision misses immediately regardless of age (the cache
/// keys on the payload `Arc`), so this bounds caps staleness only.
const DISCOVERY_CACHE_TTL: Duration = Duration::from_secs(5);

/// Single-entry cache for rendered discovery responses (W1-L13-22).
/// Keyed on (backend identity, payload revision `Arc`): repeated
/// context-free discovery calls skip the per-call function-table walk
/// and payload re-read. The per-response owned clone is inherent to
/// tonic; the rate limiter remains the flood backstop.
#[derive(Default)]
struct DiscoveryCache {
    entry: Option<DiscoveryCacheEntry>,
}

struct DiscoveryCacheEntry {
    backend_id: usize,
    payload: Arc<MechanismRegistryPayload>,
    response: pkcs11_proxy_ng_proto::GetBackendInterfacesResponse,
    stored_at: Instant,
}

impl DiscoveryCache {
    fn get(
        &self,
        now: Instant,
        backend_id: usize,
        payload: &Arc<MechanismRegistryPayload>,
    ) -> Option<pkcs11_proxy_ng_proto::GetBackendInterfacesResponse> {
        let entry = self.entry.as_ref()?;
        if entry.backend_id != backend_id {
            return None;
        }
        if !Arc::ptr_eq(&entry.payload, payload) {
            return None; // rotated revision → re-render immediately
        }
        if now.saturating_duration_since(entry.stored_at) >= DISCOVERY_CACHE_TTL {
            return None;
        }
        Some(entry.response.clone())
    }

    fn put(
        &mut self,
        now: Instant,
        backend_id: usize,
        payload: &Arc<MechanismRegistryPayload>,
        response: pkcs11_proxy_ng_proto::GetBackendInterfacesResponse,
    ) {
        self.entry = Some(DiscoveryCacheEntry {
            backend_id,
            payload: Arc::clone(payload),
            response,
            stored_at: now,
        });
    }
}

static DISCOVERY_CACHE: LazyLock<Mutex<DiscoveryCache>> =
    LazyLock::new(|| Mutex::new(DiscoveryCache::default()));

/// Handler for GetBackendInterfaces RPC.
///
/// Context-free: no client_context_id required.
/// Returns the backend's interface capabilities (which versions are
/// supported and which function pointers are NULL) plus the daemon's
/// current mechanism registry payload so shims can refresh their
/// param-shape / parameterless data without restarting.
///
/// Rate-limited per peer IP (FOLLOWUP-rate-limit). Disabled by
/// default — see `proxy.rate_limit_get_backend_interfaces` in
/// proxy.toml.
pub(super) async fn get_backend_interfaces(
    _ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    registry_source: &MechanismRegistrySource,
    request: Request<pkcs11_proxy_ng_proto::GetBackendInterfacesRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetBackendInterfacesResponse>, Status> {
    // W1-L13-22: honor the limiter default explicitly. The default is OFF
    // (`max_per_window == 0` = disabled; wired in `main.rs` from
    // `proxy.rate_limit_get_backend_interfaces`, whose default is 0), so
    // default-config discovery always passes this check — and this check
    // is the only throttle on the path (a cache hit below never bypasses
    // it: budget is consumed before the cache is consulted).
    if let Some(peer) = request.remote_addr()
        && let Err(retry_after) = rate_limit::check(peer.ip())
    {
        return Err(Status::resource_exhausted(format!(
            "rate limit exceeded; retry after {} ms",
            retry_after.as_millis()
        )));
    }
    let _request = request;
    // NOTE: get_interface_capabilities is pure metadata (reads the .so's
    // function-list NULL pointers — no PKCS#11 call into the backend).
    // We deliberately do NOT route it through spawn_backend, because
    // that path emits Success events to the backend-health gate. The
    // chaos scenario 2 needs the gate to see only real backend-call outcomes;
    // routing this metadata read through spawn_backend would emit
    // spurious Successes interleaved with the actual failing C_Sign
    // events and reset the consecutive-failure counter.
    let backend = backend_ref.clone();
    let backend_id = Arc::as_ptr(backend_ref) as *const () as usize;
    // Take a snapshot of the registry payload up-front so the cache key
    // and the response below need no extra RwLock acquisition.
    // W1-C3-26: a poisoned registry lock fails closed with Internal,
    // never an expect-panic on the request path.
    let registry_payload = registry_source.current().map_err(Status::internal)?;
    let now = Instant::now();

    // W1-L13-22: serve a fresh cached rendering when the backend and the
    // payload revision both match. A poisoned cache lock degrades to
    // uncached behavior (render fresh, store nothing) — never an error.
    if let Ok(cache) = DISCOVERY_CACHE.lock()
        && let Some(cached) = cache.get(now, backend_id, &registry_payload)
    {
        return Ok(Response::new(cached));
    }

    // W1-C1-14: `get_interface_capabilities()` is infallible — build the
    // caps directly with no dead `Err` arm remaining.
    let caps = backend.get_interface_capabilities();

    let interfaces = caps
        .interfaces
        .into_iter()
        .map(|info| pkcs11_proxy_ng_proto::InterfaceInfo {
            version_major: info.version_major as u32,
            version_minor: info.version_minor as u32,
            null_functions: info.null_functions,
        })
        .collect();

    let response = pkcs11_proxy_ng_proto::GetBackendInterfacesResponse {
        exact_output_effects_version: Some(1),
        pointer_safe_authenticated_parameters: Some(true),
        interfaces,
        mechanism_registry: Some((*registry_payload).clone()),
        backend_ulong_size: Some(backend.abi_ulong_size()),
        backend_byte_order: Some(backend.abi_byte_order()),
        backend_attribute_stride: Some(backend.abi_attribute_stride()),
        pointer_safe_message_parameters: Some(true),
    };
    if let Ok(mut cache) = DISCOVERY_CACHE.lock() {
        cache.put(now, backend_id, &registry_payload, response.clone());
    }
    Ok(Response::new(response))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use pkcs11_proxy_ng_backend::MockBackend;

    use super::*;

    #[tokio::test]
    async fn pointer_safe_message_backend_interfaces_advertises_true() {
        let context_manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        let backend = Arc::new(MockBackend::default_test());
        backend.initialize().expect("initialize mock backend");
        let backend: Arc<dyn Pkcs11Backend> = backend;
        let registry = MechanismRegistrySource::load(None).expect("load embedded registry");

        let response = get_backend_interfaces(
            &context_manager,
            &backend,
            &registry,
            Request::new(pkcs11_proxy_ng_proto::GetBackendInterfacesRequest {}),
        )
        .await
        .expect("GetBackendInterfaces should succeed")
        .into_inner();

        assert_eq!(response.pointer_safe_message_parameters, Some(true));
    }

    /// W1-C1-14 pin: caps are built infallibly straight from the backend —
    /// the response always carries the backend's real interface list
    /// (never an empty fallback shape).
    #[tokio::test]
    async fn c1_14_caps_passthrough_matches_backend_exactly() {
        let context_manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        let backend = Arc::new(MockBackend::default_test());
        backend.initialize().expect("initialize mock backend");
        let backend: Arc<dyn Pkcs11Backend> = backend;
        let registry = MechanismRegistrySource::load(None).expect("load embedded registry");

        let expected = backend.get_interface_capabilities();
        assert!(!expected.interfaces.is_empty(), "test backend must report at least one interface");

        let response = get_backend_interfaces(
            &context_manager,
            &backend,
            &registry,
            Request::new(pkcs11_proxy_ng_proto::GetBackendInterfacesRequest {}),
        )
        .await
        .expect("GetBackendInterfaces should succeed")
        .into_inner();

        assert_eq!(
            response.interfaces.len(),
            expected.interfaces.len(),
            "response must carry the backend's real interface list"
        );
        for (got, want) in response.interfaces.iter().zip(expected.interfaces.iter()) {
            assert_eq!(got.version_major, u32::from(want.version_major));
            assert_eq!(got.version_minor, u32::from(want.version_minor));
            assert_eq!(got.null_functions, want.null_functions);
        }
        assert!(response.mechanism_registry.is_some(), "response must carry the registry payload");
    }

    /// W1-L13-22 guard: a registry rotation (SIGHUP reload) must be
    /// picked up by subsequent discovery calls (no stale cache pin).
    #[tokio::test]
    async fn l13_22_rotation_picked_up_after_reload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("registry.toml");
        std::fs::write(&path, "[[params]]\nshape = \"gcm\"\nmechanisms = [0x8000C3A1]\n")
            .expect("write registry A");
        let registry =
            MechanismRegistrySource::load(Some(path.as_path())).expect("load registry A");

        let context_manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        let backend = Arc::new(MockBackend::default_test());
        backend.initialize().expect("initialize mock backend");
        let backend: Arc<dyn Pkcs11Backend> = backend;

        async fn call(
            context_manager: &Arc<ContextManager>,
            backend: &Arc<dyn Pkcs11Backend>,
            registry: &MechanismRegistrySource,
        ) -> pkcs11_proxy_ng_proto::GetBackendInterfacesResponse {
            get_backend_interfaces(
                context_manager,
                backend,
                registry,
                Request::new(pkcs11_proxy_ng_proto::GetBackendInterfacesRequest {}),
            )
            .await
            .expect("GetBackendInterfaces should succeed")
            .into_inner()
        }

        let first = call(&context_manager, &backend, &registry).await;
        let rev_a = first.mechanism_registry.clone().expect("payload").revision;

        std::fs::write(&path, "[[params]]\nshape = \"iv\"\nmechanisms = [0x8000C3A2]\n")
            .expect("write registry B");
        registry.reload().expect("reload must succeed");

        let second = call(&context_manager, &backend, &registry).await;
        let payload_b = second.mechanism_registry.clone().expect("payload");
        assert_ne!(payload_b.revision, rev_a, "rotation must be picked up");
        assert!(
            payload_b.params.iter().any(|e| e.shape == "iv"),
            "rotated payload content must be served"
        );
    }

    /// W1-L13-22 cache mechanics: miss on empty, hit within TTL for the
    /// same backend + payload revision.
    #[test]
    fn l13_22_cache_hits_within_ttl_for_same_revision() {
        use std::time::{Duration, Instant};

        use pkcs11_proxy_ng_proto::MechanismRegistryPayload;

        let payload =
            Arc::new(MechanismRegistryPayload { revision: "rev-A".into(), ..Default::default() });
        let response = pkcs11_proxy_ng_proto::GetBackendInterfacesResponse {
            mechanism_registry: Some((*payload).clone()),
            ..Default::default()
        };
        let mut cache = super::DiscoveryCache::default();
        let t0 = Instant::now();
        assert!(cache.get(t0, 7, &payload).is_none(), "empty cache must miss");
        cache.put(t0, 7, &payload, response);
        let hit = cache
            .get(t0 + Duration::from_secs(1), 7, &payload)
            .expect("same backend + revision within TTL must hit");
        assert_eq!(hit.mechanism_registry.expect("payload").revision, "rev-A");
    }

    /// W1-L13-22 cache mechanics: a rotated payload (new Arc), a
    /// different backend, and TTL expiry all miss (rotation is picked
    /// up, never pinned stale).
    #[test]
    fn l13_22_cache_misses_on_rotation_backend_change_and_expiry() {
        use std::time::{Duration, Instant};

        use pkcs11_proxy_ng_proto::MechanismRegistryPayload;

        let payload_a =
            Arc::new(MechanismRegistryPayload { revision: "rev-A".into(), ..Default::default() });
        let payload_b =
            Arc::new(MechanismRegistryPayload { revision: "rev-B".into(), ..Default::default() });
        let response = pkcs11_proxy_ng_proto::GetBackendInterfacesResponse {
            mechanism_registry: Some((*payload_a).clone()),
            ..Default::default()
        };
        let mut cache = super::DiscoveryCache::default();
        let t0 = Instant::now();
        cache.put(t0, 7, &payload_a, response);
        assert!(cache.get(t0, 7, &payload_b).is_none(), "rotated payload revision must miss");
        assert!(cache.get(t0, 8, &payload_a).is_none(), "different backend must miss");
        assert!(
            cache
                .get(t0 + super::DISCOVERY_CACHE_TTL + Duration::from_secs(1), 7, &payload_a)
                .is_none(),
            "expired entry must miss"
        );
        // A fresh put re-arms the cache.
        let response_b = pkcs11_proxy_ng_proto::GetBackendInterfacesResponse {
            mechanism_registry: Some((*payload_b).clone()),
            ..Default::default()
        };
        let t1 = t0 + super::DISCOVERY_CACHE_TTL + Duration::from_secs(1);
        cache.put(t1, 7, &payload_b, response_b);
        let hit = cache.get(t1, 7, &payload_b).expect("fresh put must hit");
        assert_eq!(hit.mechanism_registry.expect("payload").revision, "rev-B");
    }

    /// W1-L13-22: the discovery limiter default is OFF (max 0 = disabled)
    /// and the handler honors it explicitly — default-config discovery
    /// is never throttled. No test in this package configures the global
    /// limiter, so this pins the default path.
    #[tokio::test]
    async fn l13_22_limiter_default_allows_unlimited_discovery() {
        let context_manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        let backend = Arc::new(MockBackend::default_test());
        backend.initialize().expect("initialize mock backend");
        let backend: Arc<dyn Pkcs11Backend> = backend;
        let registry = MechanismRegistrySource::load(None).expect("load embedded registry");

        for _ in 0..50 {
            get_backend_interfaces(
                &context_manager,
                &backend,
                &registry,
                Request::new(pkcs11_proxy_ng_proto::GetBackendInterfacesRequest {}),
            )
            .await
            .expect("default-config discovery must never be throttled");
        }
    }
}
