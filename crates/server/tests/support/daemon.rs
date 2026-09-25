use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pkcs11_proxy_ng::config::{
    AuthConfig, PolicyEntry, TcpAuthMode, TcpListenerConfig, TokenAccessSpec, UnixAuthMode,
};
use pkcs11_proxy_ng::mechanism_registry_source::MechanismRegistrySource;
use pkcs11_proxy_ng::server::auth::mtls;
use pkcs11_proxy_ng::server::auth::policy::TokenPolicy;
use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
#[cfg(unix)]
use pkcs11_proxy_ng::server::transport::bind_unix_listener;
use pkcs11_proxy_ng::server::transport::server_tls_config;
use pkcs11_proxy_ng_backend::{FfiBackend, Pkcs11Backend};
use pkcs11_proxy_ng_client::tls::ClientTlsFiles;
use pkcs11_proxy_ng_proto::Pkcs11ProxyServer;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

use super::ProviderFixture;
use super::mtls_fixture;

/// Client identities for an mTLS [`DaemonHarness`] (W1-L9-10 combo (a)).
///
/// * `authorized` — granted `All` tokens; the happy path.
/// * `unauthorized` — a valid CA-signed cert with no grants; must see zero
///   tokens (default deny).
/// * `rogue` — signed by a different CA the server does not trust; the TLS
///   handshake must reject it loudly.
#[derive(Debug, Clone)]
pub struct MtlsClientCredentials {
    pub authorized: ClientTlsFiles,
    pub unauthorized: ClientTlsFiles,
    pub rogue: ClientTlsFiles,
}

pub struct DaemonHarness {
    endpoint: String,
    addr: SocketAddr,
    backend: Arc<FfiBackend>,
    mtls_credentials: Option<MtlsClientCredentials>,
    shutdown: watch::Sender<bool>,
    server_task: Option<JoinHandle<()>>,
    eviction_task: Option<JoinHandle<()>>,
    _certs: Option<TempDir>,
}

/// Real-FFI Unix-domain-socket daemon with peer-credential auth
/// (W1-L9-10 combo (b)). UDS has no TCP address, so this is a separate type
/// rather than a [`DaemonHarness`] variant; the insecure TCP path is untouched.
#[cfg(unix)]
pub struct UdsDaemonHarness {
    endpoint: String,
    backend: Arc<FfiBackend>,
    shutdown: watch::Sender<bool>,
    server_task: Option<JoinHandle<()>>,
    eviction_task: Option<JoinHandle<()>>,
    _socket_dir: TempDir,
}

/// Load a real FFI backend for `fixture`: dlopen, C_Initialize, and slot
/// discovery. Shared by every auth combo so all of them serve real PKCS#11.
async fn load_ffi_backend(
    fixture: &ProviderFixture,
    lease_duration: Duration,
) -> Result<(Arc<FfiBackend>, Arc<dyn Pkcs11Backend>, Arc<ContextManager>), String> {
    let backend = Arc::new(FfiBackend::load_with_init_args(
        &fixture.module_path,
        fixture.initialize_args.as_deref(),
    )?);
    backend.initialize().map_err(|rv| format!("C_Initialize failed: {rv}"))?;

    let backend_obj: Arc<dyn Pkcs11Backend> = backend.clone();
    let context_manager = Arc::new(ContextManager::new(lease_duration, 0));
    context_manager
        .populate_slots(&backend_obj)
        .await
        .map_err(|rv| format!("populate_slots failed: {rv}"))?;
    Ok((backend, backend_obj, context_manager))
}

/// Spawn the lease-eviction loop shared by every auth combo.
fn spawn_eviction_task(
    backend: Arc<dyn Pkcs11Backend>,
    context_manager: Arc<ContextManager>,
    mut shutdown_rx: watch::Receiver<bool>,
    eviction_interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(eviction_interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let _ = context_manager.evict_expired(&backend).await;
                }
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() && *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    })
}

fn token_policy_all(identity: String) -> Result<TokenPolicy, String> {
    TokenPolicy::from_config(&AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![PolicyEntry { identity, tokens: TokenAccessSpec::All("all".into()) }],
    })
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: getuid() is always-successful and has no preconditions.
    unsafe { libc::getuid() }
}

impl DaemonHarness {
    pub async fn start(fixture: &ProviderFixture) -> Result<Self, String> {
        Self::start_with(fixture, None, Duration::from_secs(300), Duration::from_millis(100)).await
    }

    pub async fn start_with(
        fixture: &ProviderFixture,
        addr: Option<SocketAddr>,
        lease_duration: Duration,
        eviction_interval: Duration,
    ) -> Result<Self, String> {
        let (backend, backend_obj, context_manager) =
            load_ffi_backend(fixture, lease_duration).await?;

        let service =
            Pkcs11ProxyService::insecure_for_tests(context_manager.clone(), backend_obj.clone());

        let listener = match addr {
            Some(addr) => {
                TcpListener::bind(addr).await.map_err(|e| format!("bind {addr} failed: {e}"))?
            }
            None => {
                TcpListener::bind("127.0.0.1:0").await.map_err(|e| format!("bind failed: {e}"))?
            }
        };
        let addr = listener.local_addr().map_err(|e| format!("local_addr failed: {e}"))?;
        let endpoint = format!("http://127.0.0.1:{}", addr.port());

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server_shutdown = shutdown_rx.clone();
        let server_task = tokio::spawn(async move {
            let incoming = TcpListenerStream::new(listener);
            let _ = Server::builder()
                .add_service(Pkcs11ProxyServer::new(service))
                .serve_with_incoming_shutdown(incoming, async move {
                    let mut shutdown_rx = server_shutdown;
                    let _ = shutdown_rx.changed().await;
                })
                .await;
        });

        let eviction_task = spawn_eviction_task(
            backend_obj.clone(),
            context_manager.clone(),
            shutdown_rx.clone(),
            eviction_interval,
        );

        tokio::time::sleep(Duration::from_millis(50)).await;

        Ok(Self {
            endpoint,
            addr,
            backend,
            mtls_credentials: None,
            shutdown: shutdown_tx,
            server_task: Some(server_task),
            eviction_task: Some(eviction_task),
            _certs: None,
        })
    }

    /// Start a real-FFI daemon over mTLS TCP (W1-L9-10 combo (a)).
    ///
    /// Issues a fresh CA plus server/client certificates, serves the real FFI
    /// backend behind `TcpAuthMode::Mtls`, and grants only the authorized
    /// client SPKI. Authz stays default-deny; there is no bypass.
    pub async fn start_mtls(fixture: &ProviderFixture) -> Result<Self, String> {
        use rcgen::ExtendedKeyUsagePurpose;

        let certs = tempfile::tempdir().map_err(|e| format!("cert tempdir failed: {e}"))?;
        let (ca_cert, ca_issuer) = mtls_fixture::new_ca();
        let server = mtls_fixture::new_leaf(
            &ca_issuer,
            "localhost",
            vec!["localhost".into()],
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let client_a = mtls_fixture::new_leaf(
            &ca_issuer,
            "client-a",
            Vec::new(),
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let client_b = mtls_fixture::new_leaf(
            &ca_issuer,
            "client-b",
            Vec::new(),
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        // Rogue CA: signs a client cert the server must reject at the TLS
        // handshake (negative path; the rogue CA is never trusted).
        let (_rogue_ca, rogue_issuer) = mtls_fixture::new_ca();
        let rogue = mtls_fixture::new_leaf(
            &rogue_issuer,
            "rogue",
            Vec::new(),
            ExtendedKeyUsagePurpose::ClientAuth,
        );

        let ca_path = mtls_fixture::write_file(&certs, "ca.pem", &ca_cert.pem());
        let server_cert = mtls_fixture::write_file(&certs, "server.pem", &server.cert_pem);
        let server_key = mtls_fixture::write_file(&certs, "server-key.pem", &server.key_pem);
        let client_a_cert = mtls_fixture::write_file(&certs, "client-a.pem", &client_a.cert_pem);
        let client_a_key = mtls_fixture::write_file(&certs, "client-a-key.pem", &client_a.key_pem);
        let client_b_cert = mtls_fixture::write_file(&certs, "client-b.pem", &client_b.cert_pem);
        let client_b_key = mtls_fixture::write_file(&certs, "client-b-key.pem", &client_b.key_pem);
        let rogue_cert = mtls_fixture::write_file(&certs, "rogue.pem", &rogue.cert_pem);
        let rogue_key = mtls_fixture::write_file(&certs, "rogue-key.pem", &rogue.key_pem);

        let (_, _, spki_a) = mtls::extract_identity(&client_a.der)?;
        let (_, _, spki_b) = mtls::extract_identity(&client_b.der)?;
        let token_policy = TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: false,
            anonymous_principal: None,
            policy: vec![
                PolicyEntry {
                    identity: format!("x509:spki={spki_a}"),
                    tokens: TokenAccessSpec::All("all".into()),
                },
                // Valid cert, explicitly zero grants: default-deny filtering.
                PolicyEntry {
                    identity: format!("x509:spki={spki_b}"),
                    tokens: TokenAccessSpec::Specific(vec![]),
                },
            ],
        })?;

        let (backend, backend_obj, context_manager) =
            load_ffi_backend(fixture, Duration::from_secs(300)).await?;
        let service = Pkcs11ProxyService::new(
            context_manager.clone(),
            backend_obj.clone(),
            TcpAuthMode::Mtls,
            UnixAuthMode::None,
            Arc::new(token_policy),
            MechanismRegistrySource::load(None)?,
            None,
        );

        let listener =
            TcpListener::bind("127.0.0.1:0").await.map_err(|e| format!("bind failed: {e}"))?;
        let addr = listener.local_addr().map_err(|e| format!("local_addr failed: {e}"))?;
        let tcp = TcpListenerConfig {
            bind: addr.to_string(),
            auth: TcpAuthMode::Mtls,
            ca_cert: Some(ca_path.clone()),
            server_cert: Some(server_cert),
            server_key: Some(server_key),
            allow_insecure_tcp: false,
        };
        let tls_config =
            server_tls_config(&tcp)?.ok_or_else(|| "mTLS requires a TLS config".to_string())?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_shutdown = shutdown_rx.clone();
        let server_task = tokio::spawn(async move {
            let incoming = TcpListenerStream::new(listener);
            let _ = Server::builder()
                .tls_config(tls_config)
                .unwrap()
                .add_service(Pkcs11ProxyServer::new(service))
                .serve_with_incoming_shutdown(incoming, async move {
                    let mut shutdown_rx = server_shutdown;
                    let _ = shutdown_rx.changed().await;
                })
                .await;
        });
        let eviction_task = spawn_eviction_task(
            backend_obj.clone(),
            context_manager.clone(),
            shutdown_rx.clone(),
            Duration::from_millis(100),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;

        Ok(Self {
            endpoint: format!("https://127.0.0.1:{}", addr.port()),
            addr,
            backend,
            mtls_credentials: Some(MtlsClientCredentials {
                authorized: ClientTlsFiles {
                    ca_cert: ca_path.clone(),
                    client_cert: client_a_cert,
                    client_key: client_a_key,
                    domain_name: Some("localhost".into()),
                },
                unauthorized: ClientTlsFiles {
                    ca_cert: ca_path.clone(),
                    client_cert: client_b_cert,
                    client_key: client_b_key,
                    domain_name: Some("localhost".into()),
                },
                rogue: ClientTlsFiles {
                    ca_cert: ca_path,
                    client_cert: rogue_cert,
                    client_key: rogue_key,
                    domain_name: Some("localhost".into()),
                },
            }),
            shutdown: shutdown_tx,
            server_task: Some(server_task),
            eviction_task: Some(eviction_task),
            _certs: Some(certs),
        })
    }

    /// Start a real-FFI daemon over UDS with peer-credential auth
    /// (W1-L9-10 combo (b)), authorizing the current uid.
    #[cfg(unix)]
    pub async fn start_uds_peer_cred(
        fixture: &ProviderFixture,
    ) -> Result<UdsDaemonHarness, String> {
        Self::start_uds_peer_cred_for_uid(fixture, current_uid()).await
    }

    /// Start a real-FFI UDS peer-cred daemon authorizing `uid`. The happy path
    /// passes the connecting uid; passing any other uid exercises the
    /// default-deny rejection (existing policy, no bypass).
    #[cfg(unix)]
    pub async fn start_uds_peer_cred_for_uid(
        fixture: &ProviderFixture,
        uid: u32,
    ) -> Result<UdsDaemonHarness, String> {
        let (backend, backend_obj, context_manager) =
            load_ffi_backend(fixture, Duration::from_secs(300)).await?;
        let service = Pkcs11ProxyService::new(
            context_manager.clone(),
            backend_obj.clone(),
            TcpAuthMode::None,
            UnixAuthMode::PeerCred,
            Arc::new(token_policy_all(format!("uid={uid}"))?),
            MechanismRegistrySource::load(None)?,
            None,
        );

        let socket_dir = tempfile::tempdir().map_err(|e| format!("socket tempdir failed: {e}"))?;
        let sock = socket_dir.path().join("proxy.sock");
        let listener = bind_unix_listener(&sock)?;
        let endpoint = format!("unix:{}", sock.display());

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_shutdown = shutdown_rx.clone();
        let server_task = tokio::spawn(async move {
            let incoming = UnixListenerStream::new(listener);
            let _ = Server::builder()
                .add_service(Pkcs11ProxyServer::new(service))
                .serve_with_incoming_shutdown(incoming, async move {
                    let mut shutdown_rx = server_shutdown;
                    let _ = shutdown_rx.changed().await;
                })
                .await;
        });
        let eviction_task = spawn_eviction_task(
            backend_obj.clone(),
            context_manager.clone(),
            shutdown_rx.clone(),
            Duration::from_millis(100),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;

        Ok(UdsDaemonHarness {
            endpoint,
            backend,
            shutdown: shutdown_tx,
            server_task: Some(server_task),
            eviction_task: Some(eviction_task),
            _socket_dir: socket_dir,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Client identities for an mTLS harness (`None` on insecure harnesses).
    pub fn mtls_credentials(&self) -> Option<&MtlsClientCredentials> {
        self.mtls_credentials.as_ref()
    }

    pub async fn shutdown(mut self) -> Result<(), String> {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.server_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.eviction_task.take() {
            let _ = task.await;
        }
        self.backend.finalize().map_err(|rv| format!("C_Finalize failed: {rv}"))?;
        Ok(())
    }
}

#[cfg(unix)]
impl UdsDaemonHarness {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub async fn shutdown(mut self) -> Result<(), String> {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.server_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.eviction_task.take() {
            let _ = task.await;
        }
        self.backend.finalize().map_err(|rv| format!("C_Finalize failed: {rv}"))?;
        Ok(())
    }
}
