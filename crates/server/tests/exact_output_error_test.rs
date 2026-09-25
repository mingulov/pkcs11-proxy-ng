//! Exact native effect integration gates; external fixture/shim paths are explicit.
use pkcs11_proxy_ng::server::{context_manager::ContextManager, grpc_service::Pkcs11ProxyService};
use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
use pkcs11_proxy_ng_proto as wire;
use std::{sync::Arc, time::Duration};
#[cfg(unix)]
#[path = "exact_output_error/loaded.rs"]
mod loaded;

async fn service(
    backend: Arc<dyn Pkcs11Backend>,
) -> (String, tokio::sync::oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    backend.initialize().unwrap();
    let context = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
    context.populate_slots(&backend).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let (ready, readiness) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let service = Pkcs11ProxyService::insecure_for_tests(context, backend.clone());
        ready.send(()).unwrap();
        tonic::transport::Server::builder()
            .add_service(wire::Pkcs11ProxyServer::new(service))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = stopped.await;
                },
            )
            .await
            .unwrap();
        // Graceful-serve completion path (defense in depth; normally the
        // caller aborts below after finalizing — the shim keeps its idle
        // connection open across C_Finalize, so graceful shutdown alone
        // never completes). The explicit drops run the final backend
        // drop here when this path wins the race.
        let _ = backend.finalize();
        drop(backend);
    });
    readiness.await.unwrap();
    (endpoint, stop, server)
}

#[tokio::test]
async fn exact_preprovider_rejections_leave_all_caller_outputs_untouched() {
    let backend = Arc::new(MockBackend::default_test());
    // Mock backend: no final-owner guard, so the completion join is
    // unneeded (runtime cancel of the server task is clean here).
    let (endpoint, _stop, _server) = service(backend.clone()).await;
    let mut client =
        tokio::time::timeout(Duration::from_secs(5), wire::Pkcs11ProxyClient::connect(endpoint))
            .await
            .unwrap()
            .unwrap();
    let error = client
        .byte_output_exact(wire::ByteOutputExactRequest::default())
        .await
        .expect_err("legacy exact request must fail before dispatch");
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    let error = client
        .parameter_output_exact(wire::ParameterOutputExactRequest::default())
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    let error = client
        .encapsulate_key_exact(wire::EncapsulateKeyExactRequest::default())
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    let error = client
        .get_attribute_value_exact(wire::GetAttributeValueExactRequest::default())
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert_eq!(backend.data_op_call_count(), 0);
    let error = client
        .encrypt_message_begin(wire::EncryptMessageBeginRequest {
            parameter_out_spec: Some(Default::default()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    let error = client
        .decrypt_message_begin(wire::DecryptMessageBeginRequest {
            parameter_out_spec: Some(Default::default()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert_eq!(backend.message_begin_call_count(), 0);
}
