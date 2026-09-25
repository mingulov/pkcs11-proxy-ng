//! End-to-end Unix-domain-socket transport tests (C1).
//!
//! Verifies the full local-IPC path: the client's `unix:` connector dials the
//! daemon's `UnixListener`, tonic surfaces `SO_PEERCRED` as `UdsConnectInfo`,
//! and the server derives an `AuthenticatedIdentity::PeerCred { uid }` that
//! feeds the token policy — the local-IPC equivalent of mutual auth (no TLS).

use std::sync::Arc;
use std::time::Duration;

use pkcs11_proxy_ng::config::{
    AuthConfig, PolicyEntry, TcpAuthMode, TokenAccessSpec, UnixAuthMode,
};
use pkcs11_proxy_ng::mechanism_registry_source::MechanismRegistrySource;
use pkcs11_proxy_ng::server::auth::policy::TokenPolicy;
use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_proto::Pkcs11ProxyServer;
use pkcs11_proxy_ng_types::*;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

/// Spawn a peer-cred Unix-socket daemon serving a single MockBackend slot under
/// `policy`. Returns the `unix:` endpoint plus guards that keep the server and
/// its socket directory alive for the test's duration.
async fn spawn_uds_server(
    policy: TokenPolicy,
) -> (String, tokio::sync::watch::Sender<bool>, tempfile::TempDir) {
    let backend: Arc<dyn Pkcs11Backend> =
        Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
    let ctx = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
    ctx.populate_slots(&backend).await.unwrap();
    let service = Pkcs11ProxyService::new(
        ctx,
        backend,
        TcpAuthMode::None,
        UnixAuthMode::PeerCred,
        Arc::new(policy),
        MechanismRegistrySource::load(None).unwrap(),
    );

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("proxy.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let incoming = UnixListenerStream::new(listener);
        let _ = Server::builder()
            .add_service(Pkcs11ProxyServer::new(service))
            .serve_with_incoming_shutdown(incoming, async move {
                let mut rx = rx;
                let _ = rx.changed().await;
            })
            .await;
    });
    // Give the accept loop a moment to come up before the client dials.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let endpoint = format!("unix:{}", sock.display());
    (endpoint, tx, dir)
}

fn current_uid() -> u32 {
    // SAFETY: getuid() is always-successful and has no preconditions.
    unsafe { libc::getuid() }
}

fn all_tokens(identity: String) -> TokenPolicy {
    TokenPolicy::from_config(&AuthConfig {
        allow_all_authenticated: false,
        policy: vec![PolicyEntry { identity, tokens: TokenAccessSpec::All("all".into()) }],
    })
    .unwrap()
}

/// The client connects over the Unix socket and the server authorizes it by the
/// kernel-reported peer uid: a policy keyed to the real uid makes the token
/// visible end-to-end (connect -> Initialize -> GetSlotList).
#[tokio::test]
async fn uds_peer_cred_identity_authorizes_matching_uid() {
    let policy = all_tokens(format!("uid={}", current_uid()));
    let (endpoint, _shutdown, _dir) = spawn_uds_server(policy).await;

    let mut client = Pkcs11Client::connect(&endpoint).await.expect("connect over unix socket");
    client.initialize().await.expect("Initialize over unix socket");
    let slots = client.get_slot_list(true).await.expect("GetSlotList over unix socket");
    // One backend slot is authorized for this uid, so it is visible (the proxy
    // returns a virtual slot id, so assert on the count rather than the value).
    assert_eq!(slots.len(), 1, "peer-cred uid matched policy -> slot visible");
}

/// Proves the derived identity is the *real* peer uid (not a bypass): a policy
/// authorizing a different uid must filter the token out during discovery.
#[tokio::test]
async fn uds_peer_cred_identity_filters_non_matching_uid() {
    let other = current_uid().wrapping_add(1);
    let policy = all_tokens(format!("uid={other}"));
    let (endpoint, _shutdown, _dir) = spawn_uds_server(policy).await;

    let mut client = Pkcs11Client::connect(&endpoint).await.unwrap();
    client.initialize().await.unwrap();
    let slots = client.get_slot_list(true).await.unwrap();

    assert!(slots.is_empty(), "peer-cred uid != policy uid -> token filtered (default deny)");
}
