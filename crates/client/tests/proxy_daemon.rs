//! Client reliability integration tests (W1-C10-01/02/03/08).
//!
//! Spins an in-process mock daemon (real server service + `MockBackend`,
//! mirroring the CLI crypto tests) so the client's deadline, reconnect,
//! capability-cache, and typed-attribute paths run against real gRPC I/O.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_client::Pkcs11Client;
// W1-C10-06: downstream crates name these types from the crate root.
use pkcs11_proxy_ng_client::{BackendInterface, BackendProbe, DeriveKeyMechanismOutResult};
use pkcs11_proxy_ng_types::*;

#[test]
fn root_reexports_name_downstream_types() {
    let probe = BackendProbe {
        exact_output_effects_version: Some(1),
        interfaces: vec![BackendInterface {
            version_major: 3,
            version_minor: 0,
            null_functions: vec![],
        }],
        mechanism_registry: None,
        backend_ulong_size: Some(8),
        backend_byte_order: Some(1),
        backend_attribute_stride: None,
        pointer_safe_message_parameters: true,
        pointer_safe_authenticated_parameters: false,
    };
    assert_eq!(probe.exact_output_effects_version, Some(1));
    // W1-C10-10: downstream names the interface fields (no positional tuple).
    assert_eq!(probe.interfaces[0].version_major, 3);
    assert_eq!(probe.interfaces[0].version_minor, 0);
    assert!(probe.interfaces[0].null_functions.is_empty());
    let out = DeriveKeyMechanismOutResult { rv: CkRv::OK, key_handle: None, mechanism_out: None };
    assert_eq!(out.rv, CkRv::OK);
}

/// Counts every gRPC request reaching the mock service. Generic over the
/// request type so the test needs no `http` import; forwards
/// `NamedService` for `add_service` routing.
#[derive(Clone)]
struct Counting<S> {
    inner: S,
    count: Arc<AtomicUsize>,
}

impl<S, R> tower::Service<R> for Counting<S>
where
    S: tower::Service<R>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: R) -> Self::Future {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.inner.call(req)
    }
}

impl<S: tonic::server::NamedService> tonic::server::NamedService for Counting<S> {
    const NAME: &'static str = S::NAME;
}

struct MockDaemon {
    endpoint: String,
    port: u16,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

/// Serve `backend` on 127.0.0.1, optionally counting requests. When `port`
/// is `Some`, bind that exact port (daemon restart on the client's stored
/// endpoint); otherwise pick an ephemeral port.
async fn mock_daemon_on(
    backend: Arc<MockBackend>,
    port: Option<u16>,
    counter: Option<Arc<AtomicUsize>>,
) -> MockDaemon {
    use pkcs11_proxy_ng::server::context_manager::ContextManager;
    use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;

    backend.initialize().expect("initialize mock backend before serving");
    let ctx = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
    let backend: Arc<dyn Pkcs11Backend> = backend;
    ctx.populate_slots(&backend).await.expect("populate_slots");
    let svc = Pkcs11ProxyService::insecure_for_tests(ctx, backend);

    let bind = match port {
        Some(p) => format!("127.0.0.1:{p}"),
        None => "127.0.0.1:0".to_string(),
    };
    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://127.0.0.1:{}", addr.port());

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_shutdown = shutdown_rx.clone();
    let task = tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let counter = counter.clone();
        let _ = match counter {
            Some(count) => {
                tonic::transport::Server::builder()
                    .add_service(Counting {
                        inner: pkcs11_proxy_ng_proto::Pkcs11ProxyServer::new(svc),
                        count,
                    })
                    .serve_with_incoming_shutdown(incoming, async move {
                        let mut rx = server_shutdown;
                        let _ = rx.changed().await;
                    })
                    .await
            }
            None => {
                tonic::transport::Server::builder()
                    .add_service(pkcs11_proxy_ng_proto::Pkcs11ProxyServer::new(svc))
                    .serve_with_incoming_shutdown(incoming, async move {
                        let mut rx = server_shutdown;
                        let _ = rx.changed().await;
                    })
                    .await
            }
        };
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    MockDaemon { endpoint, port: addr.port(), shutdown_tx: Some(shutdown_tx), task: Some(task) }
}

async fn mock_daemon(backend: Arc<MockBackend>) -> MockDaemon {
    mock_daemon_on(backend, None, None).await
}

impl MockDaemon {
    /// Stop the daemon and wait for its listener to drop so the port can
    /// be rebound by a fresh daemon (simulated daemon restart).
    async fn stop(mut self) {
        drop(self.shutdown_tx.take());
        if let Some(task) = self.task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
        }
    }
}

fn mock_backend() -> Arc<MockBackend> {
    Arc::new(MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType::AES_ECB, CkMechanismType(0x0000_0251)],
    ))
}

// W1-C10-01: every RPC carries a deadline (configurable, sane default) so
// a wedged daemon cannot hang callers forever. The blackhole below accepts
// TCP but never speaks HTTP/2, so without a client-side deadline the RPC
// would pend until the test guard below fires (FAIL); with it, the call
// fails fast with the DeadlineExceeded mapping (FUNCTION_FAILED).
#[tokio::test]
async fn rpc_deadline_bounds_hung_call() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        // Hold each accepted socket open without a single byte: the
        // client's HTTP/2 handshake pends indefinitely.
        while let Ok((_stream, _)) = listener.accept().await {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });

    let channel = tonic::transport::Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
        .unwrap()
        .connect_lazy();
    let mut client =
        Pkcs11Client::from_channel(channel).with_rpc_timeout(Duration::from_millis(100));
    let start = std::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(15), client.initialize()).await;
    let elapsed = start.elapsed();
    let result = result.expect("client must bound a hung RPC itself (W1-C10-01)");
    assert_eq!(result.unwrap_err(), CkRv::FUNCTION_FAILED);
    assert!(
        elapsed < Duration::from_secs(10),
        "hung RPC must fail within the deadline, took {elapsed:?}"
    );
}

// W1-C10-02: reconnect re-initializes (fresh context) instead of reusing
// the pre-reconnect context_id. After a daemon restart the old context is
// unknown server-side, so the stale-context probe is rejected and
// reconnect must mint a fresh context rather than fail.
#[tokio::test]
async fn reconnect_reinitializes_after_daemon_restart() {
    let daemon = mock_daemon(mock_backend()).await;
    let endpoint = daemon.endpoint.clone();
    let port = daemon.port;
    let mut client = Pkcs11Client::connect(&endpoint).await.unwrap();
    client.initialize().await.unwrap();
    let old_ctx = client.context_id_opt().expect("initialize stores a context");
    assert!(!client.get_slot_list(false).await.unwrap().is_empty());

    // Simulate a daemon restart: same endpoint, fresh server-side state.
    daemon.stop().await;
    let daemon = mock_daemon_on(mock_backend(), Some(port), None).await;
    assert_eq!(daemon.endpoint, endpoint);

    client.reconnect().await.expect("reconnect must re-init after stale-context rejection");
    let new_ctx = client.context_id_opt().expect("reconnect keeps a context");
    assert_ne!(new_ctx, old_ctx, "reconnect must mint a fresh context id");
    assert!(!client.get_slot_list(false).await.unwrap().is_empty());
    daemon.stop().await;
}

// W1-C10-03: the GetBackendInterfaces capability gate is cached — repeated
// gate calls (one per wrap/unwrap today) issue a single capability RPC per
// connection; reconnect refreshes the cache (next gate call re-probes once).
#[tokio::test]
async fn typed_auth_capability_cached_per_connection() {
    let counter = Arc::new(AtomicUsize::new(0));
    let daemon = mock_daemon_on(mock_backend(), None, Some(counter.clone())).await;
    let mut client = Pkcs11Client::connect(&daemon.endpoint).await.unwrap();
    client.initialize().await.unwrap();

    let baseline = counter.load(Ordering::SeqCst);
    let first = client.require_typed_authenticated_parameters().await;
    let second = client.require_typed_authenticated_parameters().await;
    assert_eq!(first, second, "cached gate must agree with the probed gate");
    assert_eq!(
        counter.load(Ordering::SeqCst) - baseline,
        1,
        "two gate calls must issue a single capability RPC (W1-C10-03)"
    );

    // A direct probe also refreshes the cache: the gate that follows it
    // must not issue another RPC (covers the version-change refresh path —
    // every probe overwrites the cache with its own fresh capability).
    client.get_backend_interfaces().await.unwrap();
    let baseline = counter.load(Ordering::SeqCst);
    let third = client.require_typed_authenticated_parameters().await;
    assert_eq!(third, first);
    assert_eq!(
        counter.load(Ordering::SeqCst) - baseline,
        0,
        "gate after a fresh probe must not re-probe"
    );

    // Reconnect invalidates: the next gate call re-probes exactly once.
    client.reconnect().await.unwrap();
    let baseline = counter.load(Ordering::SeqCst);
    let fourth = client.require_typed_authenticated_parameters().await;
    assert_eq!(fourth, first);
    assert_eq!(
        counter.load(Ordering::SeqCst) - baseline,
        1,
        "reconnect must refresh the capability cache"
    );
    daemon.stop().await;
}

// W1-C10-08: get_attribute_value preserves Bool/Ulong/String types from
// the exact path instead of forcing every value to Bytes. Buffer-hint
// reads (the value-bearing path; size queries carry no values by
// PKCS#11 semantics) must come back in the hinted shape.
#[tokio::test]
async fn get_attribute_value_preserves_scalar_types() {
    let daemon = mock_daemon(mock_backend()).await;
    let mut client = Pkcs11Client::connect(&daemon.endpoint).await.unwrap();
    client.initialize().await.unwrap();
    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CkSessionFlags::SERIAL_SESSION).await.unwrap();
    let object = client
        .create_object(
            session,
            Some(&[
                CkAttribute {
                    attr_type: CkAttributeType::CLASS,
                    value: Some(CkAttributeValue::Ulong(CkObjectClass::DATA.0)),
                },
                CkAttribute {
                    attr_type: CkAttributeType::LABEL,
                    value: Some(CkAttributeValue::String("c10-08".to_string().into())),
                },
                CkAttribute {
                    attr_type: CkAttributeType::TOKEN,
                    value: Some(CkAttributeValue::Bool(true)),
                },
            ]),
        )
        .await
        .unwrap();

    let template = vec![
        CkAttribute { attr_type: CkAttributeType::CLASS, value: Some(CkAttributeValue::Ulong(0)) },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String("................".to_string().into())),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
    ];
    let (rv, attrs) = client.get_attribute_value(session, object, &template).await.unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(attrs.len(), 3);
    assert_eq!(
        attrs[0].value,
        Some(CkAttributeValue::Ulong(CkObjectClass::DATA.0)),
        "CLASS must decode as Ulong"
    );
    assert!(
        matches!(attrs[1].value, Some(CkAttributeValue::String(_))),
        "LABEL must decode as String, got {:?}",
        attrs[1].value
    );
    assert_eq!(attrs[2].value, Some(CkAttributeValue::Bool(true)), "TOKEN must decode as Bool");
    daemon.stop().await;
}

// W1-C10-02: reconnect without a context only redials (no probe, no init).
#[tokio::test]
async fn reconnect_without_context_skips_probe() {
    let daemon = mock_daemon(mock_backend()).await;
    let mut client = Pkcs11Client::connect(&daemon.endpoint).await.unwrap();
    client.reconnect().await.unwrap();
    assert!(client.context_id_opt().is_none());
    daemon.stop().await;
}

// W1-C10-02: a channel-sharing client cannot reconnect (no endpoint).
#[tokio::test]
async fn reconnect_shared_channel_is_general_error() {
    let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
    let mut client = Pkcs11Client::from_channel(channel);
    assert_eq!(client.reconnect().await.unwrap_err(), CkRv::GENERAL_ERROR);
}

// W1-C10-01: healthy RPCs are unaffected by the default deadline.
#[tokio::test]
async fn healthy_rpcs_unaffected_by_default_deadline() {
    let daemon = mock_daemon(mock_backend()).await;
    let mut client = Pkcs11Client::connect(&daemon.endpoint).await.unwrap();
    client.initialize().await.unwrap();
    let slots = client.get_slot_list(false).await.unwrap();
    assert!(!slots.is_empty());
    client.finalize().await.unwrap();
    daemon.stop().await;
}
