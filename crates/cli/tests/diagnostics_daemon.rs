// Diagnostics against an in-process mock daemon (real server service
// + `MockBackend`, plus a grpc.health.v1 reporter): the probe must
// exit 0 with a discovery report on SERVING, exit 1 on NOT_SERVING,
// and never initialize a PKCS#11 context (the daemon's context
// count stays zero — the `max_contexts = 1` pin).
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_types::{CkMechanismType, CkSlotId};

const SERVICE_NAME: &str = "pkcs11_proxy_ng.v1.Pkcs11Proxy";

// NOTE: multi_thread is load-bearing below — the blocking child wait
// must not starve the in-process server task (a current_thread
// runtime deadlocks: the probe connects to a server that never runs).
struct MockDaemon {
    endpoint: String,
    ctx: Arc<ContextManager>,
    reporter: tonic_health::server::HealthReporter,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

/// Stall every request reaching the wrapped service (applied to the
/// proxy service only; health stays fast). Models a hung discovery
/// RPC so the probe's deadline arms are testable.
#[derive(Clone)]
struct StallAll<S> {
    inner: S,
}

impl<S, R> tower::Service<R> for StallAll<S>
where
    S: tower::Service<R> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
    S::Error: Send + 'static,
    R: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: R) -> Self::Future {
        let mut inner = self.inner.clone();
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            inner.call(req).await
        })
    }
}

impl<S: tonic::server::NamedService> tonic::server::NamedService for StallAll<S> {
    const NAME: &'static str = S::NAME;
}

async fn mock_daemon_with(stall_proxy: bool) -> MockDaemon {
    let backend = Arc::new(MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType::AES_ECB, CkMechanismType(0x0000_0251)],
    ));
    backend.initialize().expect("initialize mock backend before serving");
    // max_contexts = 1: the production admission guardrail. The
    // occupied-slot test below proves diagnostics works without
    // consuming it.
    let ctx = Arc::new(ContextManager::new(Duration::from_secs(300), 1));
    let backend: Arc<dyn Pkcs11Backend> = backend;
    ctx.populate_slots(&backend).await.expect("populate_slots");
    let svc = Pkcs11ProxyService::insecure_for_tests(ctx.clone(), backend);

    let (reporter, health_service) = tonic_health::server::health_reporter();
    reporter.set_service_status(SERVICE_NAME, tonic_health::ServingStatus::Serving).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("http://127.0.0.1:{port}");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_shutdown = shutdown_rx.clone();
    let task = tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let shutdown = async move {
            let mut rx = server_shutdown;
            let _ = rx.changed().await;
        };
        if stall_proxy {
            let _ = tonic::transport::Server::builder()
                .add_service(health_service)
                .add_service(StallAll { inner: pkcs11_proxy_ng_proto::Pkcs11ProxyServer::new(svc) })
                .serve_with_incoming_shutdown(incoming, shutdown)
                .await;
        } else {
            let _ = tonic::transport::Server::builder()
                .add_service(health_service)
                .add_service(pkcs11_proxy_ng_proto::Pkcs11ProxyServer::new(svc))
                .serve_with_incoming_shutdown(incoming, shutdown)
                .await;
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    MockDaemon { endpoint, ctx, reporter, shutdown_tx: Some(shutdown_tx), task: Some(task) }
}

async fn mock_daemon() -> MockDaemon {
    mock_daemon_with(false).await
}

impl MockDaemon {
    async fn stop(mut self) {
        drop(self.shutdown_tx.take());
        if let Some(task) = self.task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
        }
    }
}

fn run_diagnostics(endpoint: &str, extra: &[&str]) -> std::process::Output {
    let mut args = vec!["--endpoint", endpoint, "diagnostics"];
    args.extend(extra.iter());
    Command::new(env!("CARGO_BIN_EXE_pkcs11-proxy-ng-cli"))
        .args(&args)
        .output()
        .expect("run diagnostics binary")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn diagnostics_reports_serving_daemon_without_a_context() {
    let daemon = mock_daemon().await;
    // Occupy the sole admitted context first: diagnostics must work
    // without initializing (any initialize attempt would be refused
    // and break the run — an init/finalize cycle cannot hide here).
    let mut occupant = pkcs11_proxy_ng_client::Pkcs11Client::connect(&daemon.endpoint)
        .await
        .expect("occupant connects");
    occupant.initialize().await.expect("occupant initializes");
    assert_eq!(daemon.ctx.context_count(), 1);
    let out = run_diagnostics(&daemon.endpoint, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "SERVING must exit 0, stderr: {stderr}");
    for needle in
        ["service pkcs11_proxy_ng.v1.Pkcs11Proxy: SERVING", "interfaces:", "backend ulong:"]
    {
        assert!(stdout.contains(needle), "missing {needle:?} in:\n{stdout}");
    }
    assert_eq!(
        daemon.ctx.context_count(),
        1,
        "diagnostics must neither initialize nor finalize a context"
    );
    let _ = occupant.finalize().await;
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn diagnostics_json_reports_serving_daemon() {
    let daemon = mock_daemon().await;
    let out = run_diagnostics(&daemon.endpoint, &["--format", "json"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout.contains("\"health\":\"SERVING\""), "not a SERVING report:\n{stdout}");
    assert!(stdout.contains("\"discovery_ok\":true"), "discovery must succeed:\n{stdout}");
    assert_eq!(daemon.ctx.context_count(), 0, "diagnostics must not initialize a context");
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn diagnostics_reports_not_serving_with_exit_1() {
    let daemon = mock_daemon().await;
    daemon.reporter.set_service_status(SERVICE_NAME, tonic_health::ServingStatus::NotServing).await;
    let out = run_diagnostics(&daemon.endpoint, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "NOT_SERVING must exit 1, stdout:\n{stdout}");
    assert!(stdout.contains("NOT_SERVING"), "report must carry the verdict:\n{stdout}");
    assert_eq!(daemon.ctx.context_count(), 0, "diagnostics must not initialize a context");
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn diagnostics_serving_with_stalled_discovery_exits_2() {
    // SERVING gates on discovery: a hung discovery RPC must fail the
    // probe (exit 2) once the deadline passes, not hang forever.
    let daemon = mock_daemon_with(true).await;
    let out = run_diagnostics(&daemon.endpoint, &["--timeout-secs", "2"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stalled discovery must exit 2, stderr: {stderr}");
    assert!(stderr.contains("timed out"), "must name the timeout: {stderr}");
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn diagnostics_not_serving_survives_stalled_discovery() {
    // A confirmed NOT_SERVING verdict survives discovery trouble:
    // the report prints with discovery unavailable and the exit
    // stays 1 — the stall must not erase the verdict into a 2.
    let daemon = mock_daemon_with(true).await;
    daemon.reporter.set_service_status(SERVICE_NAME, tonic_health::ServingStatus::NotServing).await;
    let out = run_diagnostics(&daemon.endpoint, &["--timeout-secs", "2"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "verdict must survive the stall, stdout:\n{stdout}");
    assert!(stdout.contains("NOT_SERVING"), "report must carry the verdict:\n{stdout}");
    assert!(
        stdout.contains("unavailable (discovery failed)"),
        "report must mark discovery:\n{stdout}"
    );
    daemon.stop().await;
}
