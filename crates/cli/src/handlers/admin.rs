use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use super::{CliResult, close_session, login_if_present, login_user, open_session};

pub(crate) async fn init_token(
    client: &mut Pkcs11Client,
    slot_id: u64,
    so_pin: SecretBytes,
    label: String,
) -> CliResult {
    // By-value PIN (W1-L2-11): transfer the wiping allocation into the
    // call; it is wiped on drop afterwards.
    let so = so_pin.into_zeroizing();
    client
        .init_token(CkSlotId(slot_id), Some(so.as_slice()), &label)
        .await
        .map_err(crate::handlers::cli_err("C_InitToken"))?;
    println!("Token initialized successfully.");
    Ok(())
}

pub(crate) async fn init_pin(
    client: &mut Pkcs11Client,
    slot_id: u64,
    so_pin: SecretBytes,
    new_pin: SecretBytes,
) -> CliResult {
    let session =
        open_session(client, slot_id, CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION)
            .await?;
    let so = so_pin.into_zeroizing();
    client
        .login(session, CkUserType::So, Some(so.as_slice()))
        .await
        .map_err(crate::handlers::cli_err("C_Login (SO)"))?;
    let new = new_pin.into_zeroizing();
    client
        .init_pin(session, Some(new.as_slice()))
        .await
        .map_err(crate::handlers::cli_err("C_InitPIN"))?;
    println!("User PIN initialized successfully.");
    close_session(client, session, true).await;
    Ok(())
}

pub(crate) async fn seed_random(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: Option<SecretBytes>,
    seed: String,
) -> CliResult {
    let seed = hex::decode(&seed).map_err(|e| format!("Invalid hex seed: {e}"))?;
    let session = open_session(client, slot_id, CkSessionFlags::SERIAL_SESSION).await?;
    // W1-C11-33: the PIN is optional like digest/session-info/verify —
    // log in only when one was given, so PIN-less seeding works where
    // the backend allows.
    let logged_in = pin.is_some();
    login_if_present(client, session, pin).await?;
    client
        .seed_random(session, CkInBuf::Bytes(&seed))
        .await
        .map_err(crate::handlers::cli_err("C_SeedRandom"))?;
    println!("RNG seeded.");
    close_session(client, session, logged_in).await;
    Ok(())
}

pub(crate) async fn set_pin(
    client: &mut Pkcs11Client,
    slot_id: u64,
    pin: SecretBytes,
    new_pin: SecretBytes,
) -> CliResult {
    let session =
        open_session(client, slot_id, CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION)
            .await?;
    // The old PIN serves both C_Login and C_SetPIN: one wiping clone for
    // the login, then the original moves into the set-PIN call. Both
    // copies are wiped on drop.
    login_user(client, session, pin.clone()).await?;
    let old = pin.into_zeroizing();
    let new = new_pin.into_zeroizing();
    client
        .set_pin(session, Some(old.as_slice()), Some(new.as_slice()))
        .await
        .map_err(crate::handlers::cli_err("C_SetPIN"))?;
    println!("PIN changed successfully.");
    close_session(client, session, true).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! W1-C11-33: `seed-random` takes an optional PIN like
    //! digest/session-info/verify — PIN-less seeding works where the
    //! backend allows, and a provided PIN still logs in.
    //!
    //! Each test spins an in-process mock daemon (client -> gRPC ->
    //! backend) and runs the real CLI handler.

    use std::sync::Arc;
    use std::time::Duration;

    use pkcs11_proxy_ng_backend::mock::MockBackend;
    use pkcs11_proxy_ng_client::Pkcs11Client;
    use pkcs11_proxy_ng_types::*;

    use super::seed_random;

    /// Spin up an in-process gRPC daemon backed by `backend`.
    /// Mirrors `handlers::objects::tests::mock_daemon`.
    async fn mock_daemon(backend: Arc<MockBackend>) -> (String, tokio::sync::watch::Sender<bool>) {
        use pkcs11_proxy_ng::server::context_manager::ContextManager;
        use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
        use pkcs11_proxy_ng_backend::Pkcs11Backend;

        backend.initialize().expect("initialize mock backend before serving");
        let ctx = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        let backend: Arc<dyn Pkcs11Backend> = backend;
        ctx.populate_slots(&backend).await.expect("populate_slots");
        let svc = Pkcs11ProxyService::insecure_for_tests(ctx, backend);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = format!("http://127.0.0.1:{}", addr.port());

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
            let _ = tonic::transport::Server::builder()
                .add_service(pkcs11_proxy_ng_proto::Pkcs11ProxyServer::new(svc))
                .serve_with_incoming_shutdown(incoming, async move {
                    let mut rx = server_shutdown;
                    let _ = rx.changed().await;
                })
                .await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        (endpoint, shutdown_tx)
    }

    struct Fixture {
        backend: Arc<MockBackend>,
        client: Pkcs11Client,
        slot: u64,
        _shutdown: tokio::sync::watch::Sender<bool>,
    }

    async fn fixture() -> Fixture {
        let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        let (endpoint, shutdown) = mock_daemon(backend.clone()).await;
        let mut client = Pkcs11Client::connect(&endpoint).await.unwrap();
        client.initialize().await.unwrap();
        let slots = client.get_slot_list(false).await.unwrap();
        Fixture { backend, client, slot: slots[0].0, _shutdown: shutdown }
    }

    #[tokio::test]
    async fn seed_random_without_pin_succeeds() {
        let mut fx = fixture().await;
        seed_random(&mut fx.client, fx.slot, None, "aabb".to_string())
            .await
            .expect("PIN-less seed must succeed");
        assert_eq!(fx.backend.login_call_count(), 0, "no login without a PIN");
    }

    #[tokio::test]
    async fn seed_random_with_pin_logs_in() {
        let mut fx = fixture().await;
        seed_random(&mut fx.client, fx.slot, Some(SecretBytes::from("1234")), "aabb".to_string())
            .await
            .expect("seed with PIN must succeed");
        assert_eq!(fx.backend.login_call_count(), 1, "a provided PIN must log in");
    }
}
