use pkcs11_proxy_ng::config::{GrantSpec, TokenAccessSpec};
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_proto::{InitializeRequest, Pkcs11ProxyClient};
use pkcs11_proxy_ng_types::*;
use std::sync::Arc;
use tonic::Code;
use tonic::transport::{Certificate as TonicCertificate, ClientTlsConfig, Endpoint};
#[path = "support/mtls_fixture.rs"]
mod mtls_fixture;
use mtls_fixture::MtlsFixture;

async fn start_mtls_daemon() -> MtlsFixture {
    mtls_fixture::start_mtls_daemon(
        Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS])),
        [
            TokenAccessSpec::Specific(vec![GrantSpec::Bare("label:MockToken".into())]),
            TokenAccessSpec::Specific(vec![]),
        ],
    )
    .await
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
                .initialize(InitializeRequest {
                    client_context_id: String::new(),
                    client_effects_version_min: None,
                    client_effects_version_max: None,
                })
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
