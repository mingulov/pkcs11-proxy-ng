//! Live pre-decode validation proof (ADR-0013 §5/§7, C3M Task 7.2).
//!
//! Spins a real daemon router — the exact layer stack from `main.rs`
//! (`TraceIdLayer` outside `ProtectedDecodeLayer` outside the routes) over a
//! `MockBackend` — and speaks raw HTTP/2 to it with hand-framed gRPC bodies
//! that a prost client could never emit. A duplicate-PIN `Login` must be
//! rejected with `InvalidArgument` before any handler runs, while a valid
//! `GetInfo` passes through to a data response.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use pkcs11_proxy_ng::server::context_manager::ContextManager;
use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
use pkcs11_proxy_ng_proto::Pkcs11ProxyServer;
use pkcs11_proxy_ng_proto::pkcs11_proxy_ng::v1::{GetInfoRequest, LoginRequest};
use pkcs11_proxy_ng_types::{CkMechanismType, CkSlotId, InterfaceCapabilities};
use prost::Message as _;
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use hyper_util::rt::{TokioExecutor, TokioIo};

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut raw = vec![0];
    raw.extend(u32::try_from(payload.len()).expect("test payload fits").to_be_bytes());
    raw.extend(payload);
    raw
}

async fn serve_once() -> (String, tokio::task::JoinHandle<()>) {
    let mock = MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType::SHA256, CkMechanismType::AES_GCM],
    );
    mock.set_interface_capabilities(InterfaceCapabilities { interfaces: Vec::new() });
    let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
    let context_manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
    context_manager.populate_slots(&backend).await.expect("populate_slots");
    let service = Pkcs11ProxyService::insecure_for_tests(context_manager, backend);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let incoming = TcpListenerStream::new(listener);
    let router = Server::builder()
        .layer(pkcs11_proxy_ng::server::trace_id::TraceIdLayer)
        .layer(pkcs11_proxy_ng::server::protected_decode::ProtectedDecodeLayer::new(
            4 * 1024 * 1024,
        ))
        .add_service(Pkcs11ProxyServer::new(service));
    let handle = tokio::spawn(async move {
        let _ = router.serve_with_incoming(incoming).await;
    });
    // Let `accept()` start before the client connects.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (format!("127.0.0.1:{}", addr.port()), handle)
}

async fn post_grpc(addr: &str, path: &str, raw: Vec<u8>) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let stream = TcpStream::connect(addr).await.expect("connect");
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("handshake");
    tokio::spawn(connection);
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}{path}"))
        .header("content-type", "application/grpc")
        .body(Full::new(Bytes::from(raw)))
        .expect("request builds");
    let response = sender.send_request(request).await.expect("send");
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or_default().to_owned()))
        .collect();
    let body = response.into_body().collect().await.expect("collect").to_bytes().to_vec();
    (status, headers, body)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(candidate, _)| candidate == name).map(|(_, value)| value.as_str())
}

#[tokio::test]
async fn live_duplicate_pin_rejected_with_invalid_argument() {
    let (addr, daemon) = serve_once().await;
    let mut payload = LoginRequest {
        client_context_id: String::from("ctx"),
        session_handle: 0,
        user_type: 1,
        pin: Some(vec![9, 9, 9]),
    }
    .encode_to_vec();
    // A second `pin` (field 4): prost would replace the first PIN allocation.
    payload.extend([0x22, 0x01, 0x08]);

    let (status, headers, body) =
        post_grpc(&addr, "/pkcs11_proxy_ng.v1.Pkcs11Proxy/Login", frame(&payload)).await;
    daemon.abort();

    assert_eq!(status, 200);
    assert_eq!(header(&headers, "grpc-status"), Some("3"), "headers: {headers:?}");
    let message = header(&headers, "grpc-message").unwrap_or_default();
    assert!(message.contains("duplicate"), "grpc-message: {message}");
    assert!(body.is_empty(), "trailers-only rejection carries no data frame");
}

#[tokio::test]
async fn live_valid_request_passes_through_to_handler() {
    let (addr, daemon) = serve_once().await;
    let payload = GetInfoRequest { client_context_id: String::from("ctx") }.encode_to_vec();

    let (status, headers, body) =
        post_grpc(&addr, "/pkcs11_proxy_ng.v1.Pkcs11Proxy/GetInfo", frame(&payload)).await;
    daemon.abort();

    assert_eq!(status, 200);
    assert_eq!(header(&headers, "grpc-status"), None, "headers: {headers:?}");
    // A data frame (compression flag 0 + length + message) proves a handler
    // ran and answered; a rejection would be trailers-only with no body.
    assert!(body.len() > 5, "expected a data frame, got {body:?}");
    assert_eq!(body[0], 0);
}
