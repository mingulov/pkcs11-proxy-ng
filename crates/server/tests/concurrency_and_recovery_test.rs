// W1-L12-03: test diagnostics (skip notices, progress, summaries) go to
// stderr by design; the workspace lint table denies this sink elsewhere.
#![allow(clippy::print_stderr)]
//! Concurrency, isolation, lease-expiry, and restart coverage.
//!
//! The cross-context handle-isolation test runs by default (W1-L10-23): when
//! SoftHSM2 is present it executes the multi-client invariant for real; when
//! SoftHSM2 is absent it records an honest `ProviderMissing` skip — never a
//! silent pass. The remaining tests stay `#[ignore]` (heavy workload,
//! timing-sensitive lease/restart legs).

mod common_3x;
mod support;

use std::sync::Arc;
use std::time::Duration;

use common_3x::{init_client, mock_daemon};
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_types::{
    CkAttribute, CkAttributeType, CkMechanism, CkMechanismType, CkRv, CkSessionHandle, CkSlotId,
};
use support::{
    DaemonHarness, ProviderFixture, create_data_object, find_objects_by_label, find_token_slot,
    initialized_client, open_public_session, open_user_session, unique_label,
};

/// Build a SoftHSM2 fixture, or record an honest provider-missing skip.
///
/// The skip path triggers ONLY when SoftHSM2 is genuinely absent
/// (re-probed after the failure); a present-but-broken provider still fails.
async fn soft_hsm_or_skip() -> Result<Option<ProviderFixture>, String> {
    match ProviderFixture::soft_hsm().await {
        Ok(fixture) => Ok(Some(fixture)),
        Err(err) if !support::softhsm2_present() => {
            record_skip!(support::SkipReason::ProviderMissing("softhsm2"));
            eprintln!("fixture unavailable ({err}); recorded as skip, not a pass");
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

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
async fn virtual_object_handles_are_isolated_per_context() -> Result<(), String> {
    // W1-L10-23: default CI exercises the cross-context invariant whenever
    // SoftHSM2 is present; absence records an explicit skip (never silent).
    let Some(fixture) = soft_hsm_or_skip().await? else {
        return Ok(());
    };
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

// ── T3: caller-visible degraded operation (mock-backed, deterministic) ────
// These qualify the existing controls: (a) local refusal before native
// entry, (b) caller timeout with unknown native outcome and exactly one
// native attempt, (c) completion. Entry is observed via the mock's
// data-op counter, never inferred from sleeps alone.

fn rsa_pkcs_mechanism() -> CkMechanism {
    CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None }
}

async fn t3_client() -> (
    pkcs11_proxy_ng_client::Pkcs11Client,
    CkSessionHandle,
    Arc<MockBackend>,
    tokio::sync::watch::Sender<bool>,
) {
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
    let (endpoint, shutdown) = mock_daemon(backend.clone()).await;
    let mut client = init_client(&endpoint).await;
    let slots = client.get_slot_list(false).await.unwrap();
    let session = client
        .open_session(slots[0], pkcs11_proxy_ng_types::CkSessionFlags::SERIAL_SESSION)
        .await
        .unwrap();
    // The shutdown sender MUST stay alive for the whole test: dropping it
    // races server shutdown against subsequent RPCs (flaky DEVICE_ERROR).
    (client, session, backend, shutdown)
}

async fn t3_sign_key(
    client: &mut pkcs11_proxy_ng_client::Pkcs11Client,
    session: CkSessionHandle,
) -> pkcs11_proxy_ng_types::CkObjectHandle {
    // T3 tests timeout/cancellation mechanics, not key semantics: a bare
    // created object suffices as the sign key (stress_test precedent).
    client.create_object(session, Some(&[])).await.unwrap()
}

/// Poll a counter until it reaches `expected` (bounded; tests must observe
/// native entry, not assume it from elapsed time).
async fn await_count(backend: &MockBackend, expected: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while backend.data_op_call_count() < expected {
        assert!(tokio::time::Instant::now() < deadline, "native entry never observed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn t3_slow_success_within_budget_completes() {
    let (mut client, session, backend, _shutdown) = t3_client().await;
    let key = t3_sign_key(&mut client, session).await;
    backend.set_data_op_delay(Duration::from_millis(100));

    let before = backend.data_op_call_count();
    client.sign_init(session, &rsa_pkcs_mechanism(), key).await.unwrap();
    let sig = client.sign(session, &[0xABu8; 32]).await.unwrap();
    assert!(!sig.is_empty());
    assert_eq!(backend.data_op_call_count(), before + 1);
}

#[tokio::test]
async fn t3_caller_timeout_reports_function_failed_with_single_native_attempt() {
    let (mut client, session, backend, _shutdown) = t3_client().await;
    let key = t3_sign_key(&mut client, session).await;
    // Server budget stays at the 30 s default; the caller trips first.
    client.set_rpc_timeout(Duration::from_millis(300));
    backend.set_data_op_delay(Duration::from_secs(2));

    let before = backend.data_op_call_count();
    client.sign_init(session, &rsa_pkcs_mechanism(), key).await.unwrap();
    let outcome = client.sign(session, &[0xABu8; 32]).await;
    assert_eq!(outcome.unwrap_err(), CkRv::FUNCTION_FAILED);
    // Exactly one native entry: the timeout neither replays nor invents work.
    await_count(&backend, before + 1).await;
    // Let the parked op finish, then prove no second attempt was issued.
    backend.clear_data_op_delay();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(backend.data_op_call_count(), before + 1);
}

#[tokio::test]
async fn t3_healthy_call_completes_alongside_stalled_call() {
    // Both legs share one daemon (separate clients/sessions) so the test
    // proves no head-of-line blocking behind a parked backend call.
    let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
    let (endpoint, _shutdown) = mock_daemon(backend.clone()).await;
    let mut stalled_client = init_client(&endpoint).await;
    let mut healthy_client = init_client(&endpoint).await;
    let slots = stalled_client.get_slot_list(false).await.unwrap();
    let flags = pkcs11_proxy_ng_types::CkSessionFlags::SERIAL_SESSION;
    let stalled_session = stalled_client.open_session(slots[0], flags).await.unwrap();
    let healthy_session = healthy_client.open_session(slots[0], flags).await.unwrap();

    let key = t3_sign_key(&mut stalled_client, stalled_session).await;
    // Park the stalled leg inside the backend; the healthy leg must not wait.
    // 8 s park: far beyond the healthy-leg bound, short enough to settle.
    backend.set_data_op_delay(Duration::from_secs(8));
    stalled_client.sign_init(stalled_session, &rsa_pkcs_mechanism(), key).await.unwrap();
    let before = backend.data_op_call_count();
    let mut stalled_sign = Box::pin(stalled_client.sign(stalled_session, &[0xCDu8; 32]));
    // Drive the stalled future until native entry is observed, then poll the
    // healthy leg to completion while the stall is still parked.
    let entered = tokio::spawn({
        let backend = backend.clone();
        async move { await_count(&backend, before + 1).await }
    });
    tokio::select! {
        _ = &mut stalled_sign => panic!("stalled leg finished while parked"),
        _ = entered => {}
    }
    let fast_start = tokio::time::Instant::now();
    let random = healthy_client.generate_random(healthy_session, 16).await.unwrap();
    assert_eq!(random.len(), 16);
    assert!(
        fast_start.elapsed() < Duration::from_secs(5),
        "healthy call must not queue behind the stall"
    );
    // Await the parked leg to completion (clear only affects subsequently
    // entered ops; the in-flight sleep runs its 8 s course, inside the
    // 12 s bound). Late completion is fine — its caller already moved on.
    backend.clear_data_op_delay();
    let _ = tokio::time::timeout(Duration::from_secs(12), stalled_sign).await;
}

#[tokio::test]
async fn t3_invalid_session_refused_before_native_entry() {
    let (mut client, session, backend, _shutdown) = t3_client().await;
    let key = t3_sign_key(&mut client, session).await;
    // Valid session first: proves the test discriminates (backend reached).
    let before = backend.data_op_call_count();
    client.sign_init(session, &rsa_pkcs_mechanism(), key).await.unwrap();
    client.sign(session, &[0xABu8; 8]).await.unwrap();
    assert_eq!(backend.data_op_call_count(), before + 1);

    // Bogus session: local refusal, backend untouched.
    let bogus = CkSessionHandle(u64::MAX - 7);
    let before = backend.data_op_call_count();
    let outcome = client.sign(bogus, &[0xABu8; 8]).await;
    assert_eq!(outcome.unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
    assert_eq!(backend.data_op_call_count(), before);
}
