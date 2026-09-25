//! Real-FFI auth-combo harness smoke coverage (W1-L9-10).
//!
//! The daemon harness serves real FFI backends over three auth combos:
//! insecure-for-tests (TCP, pre-existing), mTLS (TCP), and UDS peer-cred.
//! Each combo test drives one real FFI call through SoftHSM2 and asserts the
//! discovered token label, proving the bytes came from the real module rather
//! than a mock. Auth failures (bad cert, wrong uid) are rejected loudly per
//! the existing policy (default deny / TLS handshake failure) — no bypass.
//!
//! Tests skip honestly when SoftHSM2 is absent.

mod support;

use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_proto::{InitializeRequest, Pkcs11ProxyClient};
use support::{DaemonHarness, ProviderFixture, SkipReason, find_token_slot, initialized_client};
use tonic::Code;
use tonic::transport::{Certificate as TonicCertificate, ClientTlsConfig, Endpoint, Identity};

async fn softhsm_or_skip() -> Result<Option<ProviderFixture>, String> {
    match ProviderFixture::soft_hsm().await {
        Ok(fixture) => Ok(Some(fixture)),
        Err(_reason) if !support::softhsm2_present() => {
            record_skip!(SkipReason::ProviderMissing("SoftHSM2"));
            Ok(None)
        }
        Err(reason) => Err(reason),
    }
}

/// One real FFI call chain (C_GetInfo + C_GetSlotList + C_GetTokenInfo) with a
/// real-backend fingerprint: the discovered token label must equal the label
/// `softhsm2-util --init-token` wrote, which no mock can produce.
async fn assert_real_softhsm_token(
    client: &mut Pkcs11Client,
    fixture: &ProviderFixture,
) -> Result<(), String> {
    let info = client.get_info().await.map_err(|rv| rv.to_string())?;
    assert!(!info.manufacturer_id.trim().is_empty(), "real C_GetInfo must report a manufacturer");
    let slot = find_token_slot(client).await?;
    let token = client.get_token_info(slot).await.map_err(|rv| rv.to_string())?;
    assert_eq!(
        token.label.trim(),
        fixture.token_label,
        "token label must come from the real SoftHSM2 module"
    );
    Ok(())
}

#[tokio::test]
async fn insecure_combo_real_ffi_smoke() -> Result<(), String> {
    let Some(fixture) = softhsm_or_skip().await? else { return Ok(()) };
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    assert_real_softhsm_token(&mut client, &fixture).await?;
    daemon.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn mtls_combo_real_ffi_smoke() -> Result<(), String> {
    let Some(fixture) = softhsm_or_skip().await? else { return Ok(()) };
    let daemon = DaemonHarness::start_mtls(&fixture).await?;
    let creds = daemon.mtls_credentials().expect("mTLS harness must carry client credentials");
    let mut client =
        Pkcs11Client::connect_with_tls_files(daemon.endpoint(), creds.authorized.clone()).await?;
    client.initialize().await.map_err(|rv| rv.to_string())?;
    assert_real_softhsm_token(&mut client, &fixture).await?;
    daemon.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[cfg(unix)]
async fn uds_peer_cred_combo_real_ffi_smoke() -> Result<(), String> {
    let Some(fixture) = softhsm_or_skip().await? else { return Ok(()) };
    let daemon = DaemonHarness::start_uds_peer_cred(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    assert_real_softhsm_token(&mut client, &fixture).await?;
    daemon.shutdown().await?;
    Ok(())
}

/// A TLS identity the harness server cannot authenticate must fail loudly —
/// either the connect fails at the TLS handshake or the first RPC fails with
/// a transport/auth gRPC status. Mirrors the existing certless-client policy
/// test, exercised here against the real-FFI mTLS harness.
async fn assert_tls_identity_rejected(endpoint: &str, tls: ClientTlsConfig, what: &str) {
    let channel = Endpoint::from_shared(endpoint.to_string())
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await;
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
                "unexpected status for {what}: {status}"
            );
        }
        Err(err) => {
            let text = format!("{err:?}").to_lowercase();
            assert!(
                text.contains("transport")
                    || text.contains("tls")
                    || text.contains("certificate")
                    || text.contains("handshake")
                    || text.contains("connect"),
                "{what} should fail at the TLS transport, got: {text}"
            );
        }
    }
}

#[tokio::test]
async fn mtls_bad_certs_rejected_loudly() -> Result<(), String> {
    let Some(fixture) = softhsm_or_skip().await? else { return Ok(()) };
    let daemon = DaemonHarness::start_mtls(&fixture).await?;
    let creds = daemon.mtls_credentials().expect("mTLS harness must carry client credentials");

    // (a) Valid TLS cert with no grants: default-deny filtering, no tokens visible.
    let mut unauthorized =
        Pkcs11Client::connect_with_tls_files(daemon.endpoint(), creds.unauthorized.clone()).await?;
    unauthorized.initialize().await.map_err(|rv| rv.to_string())?;
    let slots = unauthorized.get_slot_list(true).await.map_err(|rv| rv.to_string())?;
    assert!(slots.is_empty(), "unauthorized client cert must see no tokens (default deny)");

    // (b) Rogue-CA cert: the TLS handshake must reject it loudly.
    let rogue_tls = ClientTlsConfig::new()
        .ca_certificate(TonicCertificate::from_pem(
            std::fs::read(&creds.rogue.ca_cert).map_err(|e| e.to_string())?,
        ))
        .identity(Identity::from_pem(
            std::fs::read(&creds.rogue.client_cert).map_err(|e| e.to_string())?,
            std::fs::read(&creds.rogue.client_key).map_err(|e| e.to_string())?,
        ))
        .domain_name("localhost");
    assert_tls_identity_rejected(daemon.endpoint(), rogue_tls, "rogue-CA client cert").await;

    // (c) No client cert at all: the mTLS listener must reject the handshake.
    let certless_tls = ClientTlsConfig::new()
        .ca_certificate(TonicCertificate::from_pem(
            std::fs::read(&creds.authorized.ca_cert).map_err(|e| e.to_string())?,
        ))
        .domain_name("localhost");
    assert_tls_identity_rejected(daemon.endpoint(), certless_tls, "certless client").await;

    daemon.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[cfg(unix)]
async fn uds_wrong_uid_rejected_loudly() -> Result<(), String> {
    let Some(fixture) = softhsm_or_skip().await? else { return Ok(()) };
    // Policy authorizes a different uid than the connecting peer: the real
    // peer-cred identity must filter every token out (default deny), proving
    // the gate reads the kernel-reported uid rather than bypassing it.
    // SAFETY: getuid() is always-successful and has no preconditions.
    let other = unsafe { libc::getuid() }.wrapping_add(1);
    let daemon = DaemonHarness::start_uds_peer_cred_for_uid(&fixture, other).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slots = client.get_slot_list(true).await.map_err(|rv| rv.to_string())?;
    assert!(slots.is_empty(), "wrong-uid peer must see no tokens (default deny)");
    daemon.shutdown().await?;
    Ok(())
}
