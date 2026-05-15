use std::sync::Arc;
use std::time::Duration;

use pkcs11_proxy_ng::config::{AuthConfig, PolicyEntry, TcpAuthMode, TokenAccessSpec};
use pkcs11_proxy_ng::server::auth::policy::TokenPolicy;
use pkcs11_proxy_ng::server::context_manager::{ClientContextId, ContextManager};
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_proto::{
    GetSlotListRequest, OpenSessionRequest, Pkcs11ProxyClient, Pkcs11ProxyServer,
};
use pkcs11_proxy_ng_types::*;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

const MTLS_IDENTITY: &str = "x509:issuer=CN=Root CA;subject=CN=client";

fn matching_policy() -> TokenPolicy {
    TokenPolicy::from_config(&AuthConfig {
        allow_all_authenticated: false,
        policy: vec![PolicyEntry {
            identity: MTLS_IDENTITY.into(),
            tokens: TokenAccessSpec::Specific(vec!["label:MockToken".into()]),
        }],
    })
    .unwrap()
}

async fn start_daemon(
    token_policy: TokenPolicy,
) -> (String, ClientContextId, tokio::sync::watch::Sender<bool>) {
    let backend: Arc<dyn Pkcs11Backend> =
        Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
    let context_manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
    context_manager.populate_slots(&backend).await.unwrap();
    let context_id = context_manager.create_context(Some(MTLS_IDENTITY.into())).await.unwrap();

    let service = Pkcs11ProxyService::new(
        context_manager,
        backend,
        TcpAuthMode::None,
        Arc::new(token_policy),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://127.0.0.1:{}", addr.port());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    tokio::spawn(async move {
        let incoming = TcpListenerStream::new(listener);
        let _ = Server::builder()
            .add_service(Pkcs11ProxyServer::new(service))
            .serve_with_incoming_shutdown(incoming, async move {
                let mut shutdown_rx = shutdown_rx;
                let _ = shutdown_rx.changed().await;
            })
            .await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (endpoint, context_id, shutdown_tx)
}

#[tokio::test]
async fn service_filters_slot_list_for_unauthorized_identity() {
    let (endpoint, context_id, _shutdown) =
        start_daemon(TokenPolicy::from_config(&AuthConfig::default()).unwrap()).await;
    let mut client = Pkcs11ProxyClient::connect(endpoint).await.unwrap();

    let response = client
        .get_slot_list(GetSlotListRequest { client_context_id: context_id.0, token_present: true })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.ck_rv, CkRv::OK.0);
    assert!(response.slot_ids.is_empty());
}

#[tokio::test]
async fn service_allows_matching_policy_to_open_session() {
    let (endpoint, context_id, _shutdown) = start_daemon(matching_policy()).await;
    let mut client = Pkcs11ProxyClient::connect(endpoint).await.unwrap();

    let slot_response = client
        .get_slot_list(GetSlotListRequest {
            client_context_id: context_id.0.clone(),
            token_present: true,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(slot_response.ck_rv, CkRv::OK.0);
    assert_eq!(slot_response.slot_ids.len(), 1);

    let open_response = client
        .open_session(OpenSessionRequest {
            client_context_id: context_id.0,
            slot_id: slot_response.slot_ids[0],
            flags: CkSessionFlags::SERIAL_SESSION,
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(open_response.ck_rv, CkRv::OK.0);
    assert_ne!(open_response.session_handle, 0);
}
