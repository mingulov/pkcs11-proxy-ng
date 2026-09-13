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
use pkcs11_proxy_ng_client::tls::ClientTlsFiles;
use pkcs11_proxy_ng_proto::{Pkcs11ProxyClient, Pkcs11ProxyServer};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{
    Certificate as TonicCertificate, ClientTlsConfig, Endpoint, Identity, Server,
};

struct LeafCert {
    cert_pem: String,
    key_pem: String,
    der: Vec<u8>,
}

// Each integration binary uses the fixture fields relevant to its boundary.
#[allow(dead_code)]
pub struct MtlsFixture {
    pub endpoint: String,
    pub ca_cert: PathBuf,
    pub client_a: ClientTlsFiles,
    pub client_b: ClientTlsFiles,
    pub context_manager: Arc<ContextManager>,
    pub backend: Arc<MockBackend>,
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

pub async fn start_mtls_daemon(
    backend: Arc<MockBackend>,
    grants: [TokenAccessSpec; 2],
) -> MtlsFixture {
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

    let (_, _, spki_sha256) = mtls::extract_identity(&client_a.der).unwrap();
    let client_a_identity = format!("x509:spki={spki_sha256}");
    let (_, _, b_spki) = mtls::extract_identity(&client_b.der).unwrap();
    let [grants_a, grants_b] = grants;
    let token_policy = TokenPolicy::from_config(&AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![
            PolicyEntry { identity: client_a_identity, tokens: grants_a },
            PolicyEntry { identity: format!("x509:spki={b_spki}"), tokens: grants_b },
        ],
    })
    .unwrap();

    backend.initialize().unwrap();
    let backend_ref: Arc<dyn Pkcs11Backend> = backend.clone();
    let context_manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
    context_manager.populate_slots(&backend_ref).await.unwrap();
    let service = Pkcs11ProxyService::new(
        context_manager.clone(),
        backend_ref,
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

    let fixture = MtlsFixture {
        context_manager,
        backend,
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
    };
    fixture.raw_client(false).await;
    fixture
}

impl MtlsFixture {
    pub async fn raw_client(&self, second: bool) -> Pkcs11ProxyClient<tonic::transport::Channel> {
        let files = if second { &self.client_b } else { &self.client_a };
        let tls = ClientTlsConfig::new()
            .ca_certificate(TonicCertificate::from_pem(std::fs::read(&files.ca_cert).unwrap()))
            .identity(Identity::from_pem(
                std::fs::read(&files.client_cert).unwrap(),
                std::fs::read(&files.client_key).unwrap(),
            ))
            .domain_name("localhost");
        let channel = Endpoint::from_shared(self.endpoint.clone())
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
            .unwrap();
        Pkcs11ProxyClient::new(channel)
    }
}
