// Readiness against a real mTLS listener (RO-05): the SERVING probe
// runs the recipe shipped in `examples/configs/prod/proxy.toml` (with
// test-double endpoint/cert/domain substitutions), NOT_SERVING exits
// 1, missing/untrusted TLS material exits 2, and the old plaintext
// recipe stays a negative control. Probes never consume the sole
// admitted client context.
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_client::tls::ClientTlsFiles;
use pkcs11_proxy_ng_types::{CkMechanismType, CkSlotId};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tempfile::TempDir;

const SERVICE_NAME: &str = "pkcs11_proxy_ng.v1.Pkcs11Proxy";

// NOTE: multi_thread is load-bearing below — the blocking child wait
// must not starve the in-process server task.
struct MockMtlsDaemon {
    endpoint: String,
    ctx: Arc<ContextManager>,
    reporter: tonic_health::server::HealthReporter,
    tls: ClientTlsFiles,
    other_ca: PathBuf,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    task: Option<tokio::task::JoinHandle<()>>,
    _temp: TempDir,
}

fn new_ca() -> (String, Issuer<'static, KeyPair>) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, "Readiness Test CA");
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), Issuer::new(params, key))
}

fn new_leaf(
    issuer: &Issuer<'static, KeyPair>,
    common_name: &str,
    sans: Vec<String>,
    usage: ExtendedKeyUsagePurpose,
) -> (String, String) {
    let mut params = CertificateParams::new(sans).unwrap();
    params.distinguished_name.push(DnType::CommonName, common_name);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.extended_key_usages.push(usage);
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, issuer).unwrap();
    (cert.pem(), key.serialize_pem())
}

fn write_cred(dir: &TempDir, name: &str, contents: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

async fn mock_mtls_daemon() -> MockMtlsDaemon {
    let temp = tempfile::tempdir().unwrap();
    let (ca_pem, ca_issuer) = new_ca();
    let (other_ca_pem, _) = new_ca();
    let (server_cert, server_key) = new_leaf(
        &ca_issuer,
        "localhost",
        vec!["localhost".into()],
        ExtendedKeyUsagePurpose::ServerAuth,
    );
    let (client_cert, client_key) =
        new_leaf(&ca_issuer, "health-probe", Vec::new(), ExtendedKeyUsagePurpose::ClientAuth);
    let ca_path = write_cred(&temp, "ca.pem", &ca_pem);
    let other_ca = write_cred(&temp, "other-ca.pem", &other_ca_pem);
    let server_cert_path = write_cred(&temp, "server.pem", &server_cert);
    let server_key_path = write_cred(&temp, "server-key.pem", &server_key);
    let client_cert_path = write_cred(&temp, "client.pem", &client_cert);
    let client_key_path = write_cred(&temp, "client-key.pem", &client_key);

    let backend = Arc::new(MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType::AES_ECB, CkMechanismType(0x0000_0251)],
    ));
    backend.initialize().expect("initialize mock backend before serving");
    // max_contexts = 1: the production admission guardrail. The
    // occupied-slot test below proves health works without consuming it.
    let ctx = Arc::new(ContextManager::new(Duration::from_secs(300), 1));
    let backend: Arc<dyn Pkcs11Backend> = backend;
    ctx.populate_slots(&backend).await.expect("populate_slots");
    let svc = Pkcs11ProxyService::insecure_for_tests(ctx.clone(), backend);

    let (reporter, health_service) = tonic_health::server::health_reporter();
    reporter.set_service_status(SERVICE_NAME, tonic_health::ServingStatus::Serving).await;

    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(
            std::fs::read(&server_cert_path).unwrap(),
            std::fs::read(&server_key_path).unwrap(),
        ))
        .client_ca_root(tonic::transport::Certificate::from_pem(std::fs::read(&ca_path).unwrap()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("https://127.0.0.1:{port}");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let shutdown = async move {
            let mut rx = shutdown_rx;
            let _ = rx.changed().await;
        };
        let _ = tonic::transport::Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(health_service)
            .add_service(pkcs11_proxy_ng_proto::Pkcs11ProxyServer::new(svc))
            .serve_with_incoming_shutdown(incoming, shutdown)
            .await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    MockMtlsDaemon {
        endpoint,
        ctx,
        reporter,
        tls: ClientTlsFiles {
            ca_cert: ca_path,
            client_cert: client_cert_path,
            client_key: client_key_path,
            domain_name: Some("localhost".into()),
        },
        other_ca,
        shutdown_tx: Some(shutdown_tx),
        task: Some(task),
        _temp: temp,
    }
}

impl MockMtlsDaemon {
    async fn stop(mut self) {
        drop(self.shutdown_tx.take());
        if let Some(task) = self.task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
        }
    }
}

/// The `exec: [...]` health recipe quoted in the prod sample config.
/// The live SERVING test runs exactly this argv (with endpoint/cert/
/// domain substitutions), so the documented recipe cannot drift from
/// a working probe.
fn shipped_recipe_argv() -> Vec<String> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/configs/prod/proxy.toml");
    let text = std::fs::read_to_string(&path).expect("read prod recipe");
    let mut collecting = false;
    let mut depth = 0;
    let mut current = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('#') {
            continue;
        }
        let body = &trimmed[1..];
        if !collecting {
            if body.contains("exec:") && body.contains('[') {
                collecting = true;
                depth = 1;
                current.push_str(body.split_once('[').map_or("", |part| part.1));
            }
            continue;
        }
        current.push(' ');
        current.push_str(body);
        for char in body.chars() {
            if char == '[' {
                depth += 1;
            } else if char == ']' {
                depth -= 1;
            }
        }
        if depth <= 0 {
            break;
        }
    }
    assert!(depth <= 0 && collecting, "prod must carry an exec: [...] recipe");
    let mut argv = Vec::new();
    let mut rest = current.as_str();
    while let Some(open) = rest.find('"') {
        let after = &rest[open + 1..];
        let close = after.find('"').expect("balanced quotes in recipe");
        argv.push(after[..close].to_string());
        rest = &after[close + 1..];
    }
    assert!(argv.iter().any(|arg| arg == "health"), "recipe must probe health: {argv:?}");
    argv
}

/// Render the shipped recipe against the mock daemon: the binary path,
/// endpoint, certificate files, and SNI domain become test doubles.
fn render_recipe(argv: &[String], daemon: &MockMtlsDaemon) -> Vec<String> {
    let mut rendered: Vec<String> =
        argv.iter().skip(1).map(std::string::ToString::to_string).collect();
    let mut index = 0;
    while index < rendered.len() {
        let key = rendered[index].clone();
        let value = match key.as_str() {
            "--endpoint" => Some(daemon.endpoint.clone()),
            "--tls-ca-cert" => Some(daemon.tls.ca_cert.display().to_string()),
            "--tls-client-cert" => Some(daemon.tls.client_cert.display().to_string()),
            "--tls-client-key" => Some(daemon.tls.client_key.display().to_string()),
            "--tls-domain" => Some("localhost".to_string()),
            _ => None,
        };
        if let Some(value) = value {
            assert!(index + 1 < rendered.len(), "recipe flag {key} lacks a value");
            rendered[index + 1] = value;
            index += 2;
        } else {
            index += 1;
        }
    }
    rendered
}

fn run_cli(args: &[String]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pkcs11-proxy-ng-cli"))
        .args(args)
        .output()
        .expect("run health probe binary")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serving_with_shipped_recipe_exits_0() {
    let daemon = mock_mtls_daemon().await;
    let recipe = shipped_recipe_argv();
    let args = render_recipe(&recipe, &daemon);
    let out = run_cli(&args);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "shipped recipe must exit 0, stderr: {stderr}");
    assert!(stdout.contains("SERVING"), "must print SERVING, got: {stdout}");
    assert_eq!(daemon.ctx.context_count(), 0, "health must not initialize a context");
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serving_with_occupied_sole_context_exits_0() {
    let daemon = mock_mtls_daemon().await;
    // Occupy the sole admitted context first: the probe must work
    // without initializing (any initialize attempt would be refused).
    let mut occupant = pkcs11_proxy_ng_client::Pkcs11Client::connect_with_tls_files(
        &daemon.endpoint,
        daemon.tls.clone(),
    )
    .await
    .expect("occupant connects");
    occupant.initialize().await.expect("occupant initializes");
    assert_eq!(daemon.ctx.context_count(), 1);
    let recipe = shipped_recipe_argv();
    let args = render_recipe(&recipe, &daemon);
    let out = run_cli(&args);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "occupied SERVING must exit 0, stderr: {stderr}");
    assert_eq!(
        daemon.ctx.context_count(),
        1,
        "health must neither initialize nor finalize a context"
    );
    let _ = occupant.finalize().await;
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_serving_with_shipped_recipe_exits_1() {
    let daemon = mock_mtls_daemon().await;
    daemon.reporter.set_service_status(SERVICE_NAME, tonic_health::ServingStatus::NotServing).await;
    let recipe = shipped_recipe_argv();
    let args = render_recipe(&recipe, &daemon);
    let out = run_cli(&args);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "NOT_SERVING must exit 1, stderr: {stderr}");
    assert!(stderr.contains("NOT_SERVING"), "must report NOT_SERVING: {stderr}");
    assert_eq!(daemon.ctx.context_count(), 0, "health must not initialize a context");
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrusted_ca_exits_2() {
    let daemon = mock_mtls_daemon().await;
    let recipe = shipped_recipe_argv();
    let mut args = render_recipe(&recipe, &daemon);
    let position = args.iter().position(|arg| arg == "--tls-ca-cert").expect("ca flag");
    args[position + 1] = daemon.other_ca.display().to_string();
    let out = run_cli(&args);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "untrusted CA must exit 2, stderr: {stderr}");
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_sni_domain_exits_2() {
    let daemon = mock_mtls_daemon().await;
    let recipe = shipped_recipe_argv();
    let mut args = render_recipe(&recipe, &daemon);
    let position = args.iter().position(|arg| arg == "--tls-domain").expect("domain flag");
    args[position + 1] = "wrong.example.invalid".to_string();
    let out = run_cli(&args);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "wrong SNI domain must exit 2, stderr: {stderr}");
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plaintext_recipe_is_a_negative_control() {
    // The pre-Q13 recommendation (plaintext endpoint, no client
    // material) against the mTLS listener: must fail the probe (exit
    // 2), proving no unauthenticated health port exists to rescue it.
    let daemon = mock_mtls_daemon().await;
    let plaintext = daemon.endpoint.replacen("https://", "http://", 1);
    let out = run_cli(&["--endpoint".to_string(), plaintext, "health".to_string()]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "plaintext probe must fail, stderr: {stderr}");
    assert!(stderr.contains("health probe"), "must report a probe failure, got: {stderr}");
    daemon.stop().await;
}
