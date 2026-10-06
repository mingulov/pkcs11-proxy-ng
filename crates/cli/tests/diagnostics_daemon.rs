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

async fn mock_daemon() -> MockDaemon {
    let backend = Arc::new(MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType::AES_ECB, CkMechanismType(0x0000_0251)],
    ));
    backend.initialize().expect("initialize mock backend before serving");
    let ctx = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
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
        let _ = tonic::transport::Server::builder()
            .add_service(health_service)
            .add_service(pkcs11_proxy_ng_proto::Pkcs11ProxyServer::new(svc))
            .serve_with_incoming_shutdown(incoming, async move {
                let mut rx = server_shutdown;
                let _ = rx.changed().await;
            })
            .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    MockDaemon { endpoint, ctx, reporter, shutdown_tx: Some(shutdown_tx), task: Some(task) }
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
    let out = run_diagnostics(&daemon.endpoint, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "SERVING must exit 0, stderr: {stderr}");
    for needle in
        ["service pkcs11_proxy_ng.v1.Pkcs11Proxy: SERVING", "interfaces:", "backend ulong:"]
    {
        assert!(stdout.contains(needle), "missing {needle:?} in:\n{stdout}");
    }
    assert_eq!(daemon.ctx.context_count(), 0, "diagnostics must not initialize a context");
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
