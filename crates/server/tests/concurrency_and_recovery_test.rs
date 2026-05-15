//! Concurrency, isolation, lease-expiry, and restart coverage.

mod support;

use std::time::Duration;

use pkcs11_proxy_ng_types::{CkAttribute, CkAttributeType, CkRv};
use support::{
    DaemonHarness, ProviderFixture, create_data_object, find_objects_by_label, find_token_slot,
    initialized_client, open_public_session, open_user_session, unique_label,
};

#[tokio::test]
#[ignore] // requires SoftHSM2 tools and library
async fn multi_client_random_workload() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let endpoint = daemon.endpoint().to_string();

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let endpoint = endpoint.clone();
        tasks.push(tokio::spawn(async move {
            let mut client = initialized_client(&endpoint).await?;
            let slot = find_token_slot(&mut client).await?;
            let session = open_public_session(&mut client, slot, false).await?;
            let random = client
                .generate_random(session, 32)
                .await
                .map_err(|rv| format!("C_GenerateRandom failed: {rv}"))?;
            client.close_session(session).await.map_err(|rv| rv.to_string())?;
            client.finalize().await.map_err(|rv| rv.to_string())?;
            Ok::<usize, String>(random.len())
        }));
    }

    for task in tasks {
        let len = task.await.map_err(|e| format!("task join failed: {e}"))??;
        assert_eq!(len, 32);
    }

    daemon.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore] // requires SoftHSM2 tools and library
async fn virtual_object_handles_are_isolated_per_context() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let endpoint = daemon.endpoint().to_string();

    let mut client_a = initialized_client(&endpoint).await?;
    let mut client_b = initialized_client(&endpoint).await?;

    let slot_a = find_token_slot(&mut client_a).await?;
    let slot_b = find_token_slot(&mut client_b).await?;
    let session_a = open_user_session(&mut client_a, slot_a, &fixture.user_pin, true).await?;
    let session_b = open_public_session(&mut client_b, slot_b, true).await?;

    let label = unique_label("isolated-object");
    let object_a = create_data_object(&mut client_a, session_a, &label, b"context-a").await?;
    let visible_a = find_objects_by_label(&mut client_a, session_a, &label).await?;
    assert!(visible_a.contains(&object_a));

    let attrs = [CkAttribute { attr_type: CkAttributeType::LABEL, value: None }];
    // Cross-context object handle access must fail with OBJECT_HANDLE_INVALID.
    let (get_rv, _) = client_b.get_attribute_value(session_b, object_a, &attrs).await.unwrap();
    assert_eq!(get_rv, CkRv::OBJECT_HANDLE_INVALID);

    let still_visible = find_objects_by_label(&mut client_a, session_a, &label).await?;
    assert!(still_visible.contains(&object_a));

    client_a.destroy_object(session_a, object_a).await.map_err(|rv| rv.to_string())?;
    client_a.logout(session_a).await.map_err(|rv| rv.to_string())?;
    client_a.close_session(session_a).await.map_err(|rv| rv.to_string())?;
    client_b.close_session(session_b).await.map_err(|rv| rv.to_string())?;
    client_a.finalize().await.map_err(|rv| rv.to_string())?;
    client_b.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore] // requires SoftHSM2 tools and library
async fn lease_expiry_invalidates_context() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start_with(
        &fixture,
        None,
        Duration::from_millis(75),
        Duration::from_millis(10),
    )
    .await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    tokio::time::sleep(Duration::from_millis(200)).await;
    let rv = client.get_info().await.unwrap_err();
    assert_eq!(rv, CkRv::CRYPTOKI_NOT_INITIALIZED);

    daemon.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore] // requires SoftHSM2 tools and library
async fn restart_requires_reinitialize_after_reconnect() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let addr = daemon.addr();
    let endpoint = daemon.endpoint().to_string();

    let mut client = initialized_client(&endpoint).await?;
    let slot = find_token_slot(&mut client).await?;
    assert!(client.get_slot_info(slot).await.is_ok());

    daemon.shutdown().await?;

    let transport_rv = client.get_info().await.unwrap_err();
    assert_ne!(transport_rv, CkRv::OK);

    let restarted = DaemonHarness::start_with(
        &fixture,
        Some(addr),
        Duration::from_secs(300),
        Duration::from_millis(100),
    )
    .await?;

    let reconnect_rv = client.reconnect().await.unwrap_err();
    assert_eq!(reconnect_rv, CkRv::CRYPTOKI_NOT_INITIALIZED);

    client.initialize().await.map_err(|rv| rv.to_string())?;
    let slot = find_token_slot(&mut client).await?;
    assert!(client.get_token_info(slot).await.is_ok());

    client.finalize().await.map_err(|rv| rv.to_string())?;
    restarted.shutdown().await?;
    Ok(())
}
