use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng_backend::{FfiBackend, Pkcs11Backend};
use pkcs11_proxy_ng_proto::Pkcs11ProxyServer;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use super::ProviderFixture;

pub struct DaemonHarness {
    endpoint: String,
    addr: SocketAddr,
    backend: Arc<FfiBackend>,
    shutdown: watch::Sender<bool>,
    server_task: Option<JoinHandle<()>>,
    eviction_task: Option<JoinHandle<()>>,
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

        let eviction_backend = backend_obj.clone();
        let eviction_context = context_manager.clone();
        let eviction_shutdown = shutdown_rx.clone();
        let eviction_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(eviction_interval);
            let mut shutdown_rx = eviction_shutdown;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let _ = eviction_context.evict_expired(&eviction_backend).await;
                    }
                    changed = shutdown_rx.changed() => {
                        if changed.is_ok() && *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        Ok(Self {
            endpoint,
            addr,
            backend,
            shutdown: shutdown_tx,
            server_task: Some(server_task),
            eviction_task: Some(eviction_task),
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
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
