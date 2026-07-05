use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pkcs11_proxy_ng::config::{
    AuthConfig, PolicyEntry, TcpAuthMode, TcpListenerConfig, TokenAccessSpec,
};
use pkcs11_proxy_ng::server::auth::mtls;
use pkcs11_proxy_ng::server::auth::policy::TokenPolicy;
use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_client::{Pkcs11Client, tls::ClientTlsFiles};
use pkcs11_proxy_ng_proto::{InitializeRequest, Pkcs11ProxyClient, Pkcs11ProxyServer};
use pkcs11_proxy_ng_types::*;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Code;
use tonic::transport::{Certificate as TonicCertificate, ClientTlsConfig, Endpoint, Server};

struct LeafCert {
    cert_pem: String,
    key_pem: String,
    der: Vec<u8>,
}

struct MtlsFixture {
    endpoint: String,
    ca_cert: PathBuf,
    client_a: ClientTlsFiles,
    client_b: ClientTlsFiles,
    _temp: TempDir,
    _shutdown: tokio::sync::watch::Sender<bool>,
}

fn new_ca() -> (Certificate, Issuer<'static, KeyPair>) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, "Root CA");
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert, Issuer::new(params, key))
}

fn new_leaf(
    issuer: &Issuer<'static, KeyPair>,
    common_name: &str,
    subject_alt_names: Vec<String>,
    usage: ExtendedKeyUsagePurpose,
) -> LeafCert {
    let mut params = CertificateParams::new(subject_alt_names).unwrap();
    params.distinguished_name.push(DnType::CommonName, common_name);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.extended_key_usages.push(usage);

    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, issuer).unwrap();
    LeafCert { cert_pem: cert.pem(), key_pem: key.serialize_pem(), der: cert.der().to_vec() }
}

fn write_file(dir: &TempDir, name: &str, contents: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, contents).unwrap();
    // The daemon rejects mTLS private keys with group/other access (mode must
    // be 0600 or stricter). The test host's umask can leave freshly written
    // files at 0664, so tighten every credential file we emit to owner-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

async fn start_mtls_daemon() -> MtlsFixture {
    let temp = tempfile::tempdir().unwrap();
    let (ca_cert, ca_issuer) = new_ca();
    let server = new_leaf(
        &ca_issuer,
        "localhost",
        vec!["localhost".into()],
        ExtendedKeyUsagePurpose::ServerAuth,
    );
    let client_a =
        new_leaf(&ca_issuer, "client-a", Vec::new(), ExtendedKeyUsagePurpose::ClientAuth);
    let client_b =
        new_leaf(&ca_issuer, "client-b", Vec::new(), ExtendedKeyUsagePurpose::ClientAuth);

    let ca_path = write_file(&temp, "ca.pem", &ca_cert.pem());
    let server_cert = write_file(&temp, "server.pem", &server.cert_pem);
    let server_key = write_file(&temp, "server-key.pem", &server.key_pem);
    let client_a_cert = write_file(&temp, "client-a.pem", &client_a.cert_pem);
    let client_a_key = write_file(&temp, "client-a-key.pem", &client_a.key_pem);
    let client_b_cert = write_file(&temp, "client-b.pem", &client_b.cert_pem);
    let client_b_key = write_file(&temp, "client-b-key.pem", &client_b.key_pem);

    let (issuer, subject) = mtls::extract_identity(&client_a.der).unwrap();
    let client_a_identity = format!("x509:issuer={issuer};subject={subject}");
    let token_policy = TokenPolicy::from_config(&AuthConfig {
        allow_all_authenticated: false,
        policy: vec![PolicyEntry {
            identity: client_a_identity,
            tokens: TokenAccessSpec::Specific(vec!["label:MockToken".into()]),
        }],
    })
    .unwrap();

    let backend: Arc<dyn Pkcs11Backend> =
        Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
    let context_manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
    context_manager.populate_slots(&backend).await.unwrap();
    let service = Pkcs11ProxyService::new(
        context_manager,
        backend,
        TcpAuthMode::Mtls,
        pkcs11_proxy_ng::config::UnixAuthMode::None,
        Arc::new(token_policy),
        pkcs11_proxy_ng::mechanism_registry_source::MechanismRegistrySource::load(None).unwrap(),
        None, // audit: not needed for transport tests
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tcp = TcpListenerConfig {
        bind: addr.to_string(),
        auth: TcpAuthMode::Mtls,
        ca_cert: Some(ca_path.clone()),
        server_cert: Some(server_cert),
        server_key: Some(server_key),
        allow_insecure_tcp: false,
    };
    let tls_config = pkcs11_proxy_ng::server::transport::server_tls_config(&tcp).unwrap().unwrap();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let incoming = TcpListenerStream::new(listener);
        let _ = Server::builder()
            .tls_config(tls_config)
            .unwrap()
            .add_service(Pkcs11ProxyServer::new(service))
            .serve_with_incoming_shutdown(incoming, async move {
                let mut shutdown_rx = shutdown_rx;
                let _ = shutdown_rx.changed().await;
            })
            .await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    MtlsFixture {
        endpoint: format!("https://127.0.0.1:{}", addr.port()),
        ca_cert: ca_path.clone(),
        client_a: ClientTlsFiles {
            ca_cert: ca_path.clone(),
            client_cert: client_a_cert,
            client_key: client_a_key,
            domain_name: Some("localhost".into()),
        },
        client_b: ClientTlsFiles {
            ca_cert: ca_path,
            client_cert: client_b_cert,
            client_key: client_b_key,
            domain_name: Some("localhost".into()),
        },
        _temp: temp,
        _shutdown: shutdown_tx,
    }
}

#[tokio::test]
async fn mtls_context_identity_filters_tokens_by_client_certificate() {
    let fixture = start_mtls_daemon().await;

    let mut client_a =
        Pkcs11Client::connect_with_tls_files(&fixture.endpoint, fixture.client_a.clone())
            .await
            .unwrap();
    client_a.initialize().await.unwrap();
    let client_a_slots = client_a.get_slot_list(true).await.unwrap();
    assert_eq!(client_a_slots.len(), 1);

    let mut client_b =
        Pkcs11Client::connect_with_tls_files(&fixture.endpoint, fixture.client_b.clone())
            .await
            .unwrap();
    client_b.initialize().await.unwrap();
    let client_b_slots = client_b.get_slot_list(true).await.unwrap();
    assert!(client_b_slots.is_empty());
}

#[tokio::test]
async fn mtls_authorized_identity_can_open_session() {
    // Faithful, A2-consistent replacement for the former authz_policy_test
    // open-session case. The policy grants client-a's certificate identity, so
    // it can discover the token's slot and open a session on it. Because the
    // context identity is derived from the very certificate that authenticates
    // each request, the per-request ownership gate (A2) is satisfied by
    // construction — the impossible "mTLS identity over a no-auth transport"
    // state the old test relied on no longer compiles past the gate.
    let fixture = start_mtls_daemon().await;

    let mut client_a =
        Pkcs11Client::connect_with_tls_files(&fixture.endpoint, fixture.client_a.clone())
            .await
            .unwrap();
    client_a.initialize().await.unwrap();

    let slots = client_a.get_slot_list(true).await.unwrap();
    assert_eq!(slots.len(), 1);

    let session = client_a
        .open_session(slots[0], CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
        .await
        .unwrap();
    assert_ne!(session.0, 0);
}

#[tokio::test]
async fn mtls_listener_rejects_client_without_certificate() {
    let fixture = start_mtls_daemon().await;
    let ca = std::fs::read(&fixture.ca_cert).unwrap();
    let tls = ClientTlsConfig::new()
        .ca_certificate(TonicCertificate::from_pem(ca))
        .domain_name("localhost");

    let channel = Endpoint::from_shared(fixture.endpoint.clone())
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await;

    // A certless client MUST NOT reach an authenticated RPC. Depending on
    // whether tonic handshakes eagerly, that shows up either as a failed
    // connect (Err) or as a failed RPC (Ok + error). Both branches must assert
    // — the old `if let Ok` form passed vacuously when connect() returned Err,
    // so a regression that opened the listener would not be caught.
    match channel {
        Ok(channel) => {
            let status = Pkcs11ProxyClient::new(channel)
                .initialize(InitializeRequest { client_context_id: String::new() })
                .await
                .unwrap_err();
            assert!(
                matches!(
                    status.code(),
                    Code::Unauthenticated | Code::Unavailable | Code::Internal | Code::Unknown
                ),
                "unexpected status for missing client cert: {status}"
            );
            let status_text = format!("{status:?}");
            assert!(
                status_text.contains("CertificateRequired")
                    || status.message().contains("transport"),
                "missing client cert should fail at TLS transport: {status_text}"
            );
        }
        Err(err) => {
            // The daemon is up (start_mtls_daemon), so a failed connect is the
            // server actively rejecting the certless TLS handshake. Confirm it
            // is a transport/TLS failure, not an unrelated/unreachable error.
            let text = format!("{err:?}").to_lowercase();
            assert!(
                text.contains("transport")
                    || text.contains("tls")
                    || text.contains("certificate")
                    || text.contains("handshake")
                    || text.contains("connect"),
                "certless connect should fail at TLS transport, got: {text}"
            );
        }
    }
}
