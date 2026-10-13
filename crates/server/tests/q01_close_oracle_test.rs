//! Q01 counted loaded-provider oracle, plus the disposable real-provider
//! sign → failed-close/close → subsequent-use workflow.
//!
//! Drives SoftHSM2 through the real daemon stack (client → gRPC → server
//! → FFI backend → provider) and asserts on hook-recorded NATIVE
//! entries: which native calls the proxy issued, in which order, and
//! what the provider-side login/session state is afterwards.
//!
//! Requires SoftHSM2 (`#[ignore]` by repo convention) AND the
//! `native-owner-test-hooks` feature (native-entry event log,
//! close-failure injector, close-entry wedge). Run single-threaded —
//! the hook event log is process-global:
//!
//! ```sh
//! cargo test -p pkcs11-proxy-ng --features native-owner-test-hooks \
//!   --test q01_close_oracle_test -- --ignored --test-threads=1
//! ```

#![cfg(feature = "native-owner-test-hooks")]

mod support;

use std::time::{Duration, Instant};

use pkcs11_proxy_ng_backend::test_hooks::{
    NativeSessionEvent, set_fail_next_close, set_native_close_delay_once,
    take_native_session_events,
};
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;
use support::{
    DaemonHarness, ProviderFixture, ensure_user_token, generate_rsa_key_pair, initialized_client,
    open_public_session, open_user_session, rsa_sign_and_verify,
};

/// Wait for one native `C_CloseSession` ENTRY (recorded before the
/// wedge sleep / native call) and return its native handle. Drains the
/// event log while polling.
async fn wait_for_close_entry(deadline: Duration) -> Result<u64, String> {
    let start = Instant::now();
    loop {
        for (_, event) in take_native_session_events() {
            if let NativeSessionEvent::CloseSession { session } = event {
                return Ok(session);
            }
        }
        if start.elapsed() > deadline {
            return Err("timed out waiting for a native C_CloseSession entry".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Wait for the native `C_CloseSession` COMPLETION for `session`
/// (the provider call returned). Drains the event log while polling and
/// returns whatever was drained after the completion in its batch —
/// the detached completion (F1) starts the carrier immediately, so its
/// `OpenSession` entry may land in the same drain and must not be lost.
async fn wait_for_close_completion(
    session: u64,
    deadline: Duration,
) -> Result<Vec<NativeSessionEvent>, String> {
    let start = Instant::now();
    loop {
        let drained: Vec<NativeSessionEvent> =
            take_native_session_events().into_iter().map(|(_, event)| event).collect();
        for (index, event) in drained.iter().enumerate() {
            if let NativeSessionEvent::CloseSessionCompleted { session: done } = event {
                if *done != session {
                    return Err(format!(
                        "unexpected completion for native {done} while waiting for {session}"
                    ));
                }
                return Ok(drained[index + 1..].to_vec());
            }
        }
        if start.elapsed() > deadline {
            return Err("timed out waiting for native C_CloseSession completion".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Poll `C_GetSessionInfo` until the daemon reports the handle invalid
/// (mapping terminally removed) or the deadline passes.
async fn wait_for_handle_invalid(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    deadline: Duration,
) -> Result<(), String> {
    let start = Instant::now();
    loop {
        match client.get_session_info(session).await {
            Err(rv) if rv == CkRv::SESSION_HANDLE_INVALID => return Ok(()),
            // F2: FUNCTION_FAILED while the mapping is suspended under an
            // in-flight close — owned elsewhere, not settled yet. Poll on.
            Err(rv) if rv == CkRv::FUNCTION_FAILED => {}
            Err(rv) => {
                return Err(format!("expected SESSION_HANDLE_INVALID, got daemon {rv}"));
            }
            Ok(_) => {}
        }
        if start.elapsed() > deadline {
            return Err("timed out waiting for the mapping to settle terminal".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Poll the native-entry log until exactly the owned transient-carrier
/// sequence lands (open + logout + close entry/completion on one fresh
/// handle) or the deadline passes. Returns the carrier's native handle.
/// Fails on any unexpected native call (e.g. a duplicate member close).
/// `seed` carries events already drained alongside the member completion.
async fn wait_for_carrier_sequence(
    member: u64,
    seed: Vec<NativeSessionEvent>,
    deadline: Duration,
) -> Result<u64, String> {
    let start = Instant::now();
    let mut events: Vec<NativeSessionEvent> = seed;
    loop {
        events.extend(take_native_session_events().into_iter().map(|(_, event)| event));
        if events.len() >= 4 {
            break;
        }
        if start.elapsed() > deadline {
            return Err(format!("timed out waiting for the carrier sequence, got {events:?}"));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        events.len(),
        4,
        "the detached completion runs exactly one carrier sequence, got {events:?}"
    );
    let carrier = match (&events[0], &events[1], &events[2], &events[3]) {
        (
            NativeSessionEvent::OpenSession { .. },
            NativeSessionEvent::Logout { session: logged },
            NativeSessionEvent::CloseSession { session: closing },
            NativeSessionEvent::CloseSessionCompleted { session: closed },
        ) if logged == closing && closing == closed => *logged,
        _ => panic!("unexpected carrier shape: {events:?}"),
    };
    assert_ne!(carrier, member, "the carrier is a fresh session, not the member: {events:?}");
    Ok(carrier)
}

/// Loaded close-all shape: the server closes each member with its own
/// native `C_CloseSession` (never the native close-all — ADR-0002
/// per-client scope), settles every member, and releases the native
/// login through the owned transient carrier afterwards.
#[tokio::test]
#[ignore] // requires SoftHSM2 + native-owner-test-hooks
async fn loaded_close_all_uses_per_session_native_closes() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = ensure_user_token(&mut client, &fixture).await?;
    let s1 = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let s2 = open_public_session(&mut client, slot, true).await?;

    let _ = take_native_session_events();
    client.close_all_sessions(slot).await.map_err(|rv| format!("close-all failed: {rv}"))?;
    let sequenced = take_native_session_events();
    let events: Vec<NativeSessionEvent> =
        sequenced.iter().map(|(_, event)| event.clone()).collect();

    assert!(
        !events.iter().any(|event| matches!(event, NativeSessionEvent::CloseAllSessions { .. })),
        "the server must never call native C_CloseAllSessions, got {events:?}"
    );
    assert_eq!(
        events.len(),
        8,
        "two member entry/completion pairs + carrier open/logout/entry/completion, got {events:?}"
    );
    // Entry order: both member closes complete before the carrier opens,
    // and the carrier logout+close share one fresh handle after it.
    let open_idx =
        events.iter().position(|event| matches!(event, NativeSessionEvent::OpenSession { .. }));
    assert_eq!(open_idx, Some(4), "carrier opens only after both members complete: {events:?}");
    let member_handles: Vec<u64> = events[..4]
        .iter()
        .map(|event| match event {
            NativeSessionEvent::CloseSession { session }
            | NativeSessionEvent::CloseSessionCompleted { session } => *session,
            other => panic!("expected a member close entry/completion, got {other:?}"),
        })
        .collect();
    assert_eq!(
        member_handles[0], member_handles[1],
        "each member close completes before the next starts: {events:?}"
    );
    assert_eq!(
        member_handles[2], member_handles[3],
        "each member close completes before the next starts: {events:?}"
    );
    assert_ne!(member_handles[0], member_handles[2], "each member closes exactly once: {events:?}");
    assert!(
        matches!(events[0], NativeSessionEvent::CloseSession { .. })
            && matches!(events[1], NativeSessionEvent::CloseSessionCompleted { .. })
            && matches!(events[2], NativeSessionEvent::CloseSession { .. })
            && matches!(events[3], NativeSessionEvent::CloseSessionCompleted { .. }),
        "member closes pair entry then completion: {events:?}"
    );
    let carrier = match (&events[5], &events[6], &events[7]) {
        (
            NativeSessionEvent::Logout { session: logged },
            NativeSessionEvent::CloseSession { session: closing },
            NativeSessionEvent::CloseSessionCompleted { session: closed },
        ) if logged == closing && closing == closed => *logged,
        other => panic!("expected carrier logout+close on one handle, got {other:?}"),
    };
    assert!(
        !member_handles.contains(&carrier),
        "the carrier is a fresh session, not a member: {events:?}"
    );
    let seqs: Vec<u64> = sequenced.iter().map(|(seq, _)| *seq).collect();
    assert!(
        seqs.windows(2).all(|pair| pair[0] < pair[1]),
        "sequence numbers must order entries: {seqs:?}"
    );

    // Per-member completion: both virtual handles are invalid now.
    for (name, handle) in [("s1", s1), ("s2", s2)] {
        match client.get_session_info(handle).await {
            Err(rv) if rv == CkRv::SESSION_HANDLE_INVALID => {}
            other => {
                return Err(format!("{name} must be invalid after close-all, got {other:?}"));
            }
        }
    }
    // Actual login state: the native login was released — a fresh
    // session is public and a fresh login PIN-verifies.
    let fresh = open_public_session(&mut client, slot, true).await?;
    let info =
        client.get_session_info(fresh).await.map_err(|rv| format!("fresh info failed: {rv}"))?;
    assert_eq!(
        info.state,
        CkSessionState::RwPublic,
        "the token must be natively logged out after close-all"
    );
    client
        .login(fresh, CkUserType::User, Some(fixture.user_pin.as_bytes()))
        .await
        .map_err(|rv| format!("fresh login must PIN-verify: {rv}"))?;
    // Established teardown: release the context's sessions server-side,
    // then join tasks and finalize the provider (avoids the abnormal
    // native-lifetime stop on backend drop).
    client.finalize().await.map_err(|rv| format!("client finalize: {rv}"))?;
    daemon.shutdown().await?;
    Ok(())
}

/// Disposable real-provider workflow: sign → failed close (no native
/// entry, session stays usable) → retry close (one native member close
/// + owned carrier) → subsequent use on a fresh session.
#[tokio::test]
#[ignore] // requires SoftHSM2 + native-owner-test-hooks
async fn loaded_failed_close_keeps_signing_usable_and_retry_closes() -> Result<(), String> {
    failed_close_workflow(ProviderFixture::soft_hsm().await?).await
}

/// Same disposable workflow against NSS softokn as the second
/// provider: the native call shapes asserted here are the proxy's own
/// pattern, so any PKCS#11 provider must observe them.
#[tokio::test]
#[ignore] // requires NSS softokn + native-owner-test-hooks
async fn loaded_failed_close_workflow_on_nss() -> Result<(), String> {
    failed_close_workflow(ProviderFixture::nss_softokn().await?).await
}

async fn failed_close_workflow(fixture: ProviderFixture) -> Result<(), String> {
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = ensure_user_token(&mut client, &fixture).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let (public_key, private_key) =
        generate_rsa_key_pair(&mut client, session, "q01-oracle", false).await?;
    let data = b"q01 disposable workflow bytes";
    rsa_sign_and_verify(&mut client, session, private_key, public_key, data).await?;

    // Failed close: injected transient failure WITHOUT native entry.
    let _ = take_native_session_events();
    set_fail_next_close(true);
    match client.close_session(session).await {
        Err(rv) if rv == CkRv::FUNCTION_FAILED => {}
        other => return Err(format!("injected close must fail transiently, got {other:?}")),
    }
    assert!(
        take_native_session_events().is_empty(),
        "an injected close failure must not enter the provider"
    );
    // The retained session (mapping + native login) signs on.
    rsa_sign_and_verify(&mut client, session, private_key, public_key, data)
        .await
        .map_err(|err| format!("signing after a failed close must work: {err}"))?;

    // Retry close: one native member close (entry + completion),
    // then the owned carrier releases the last-holder login (no live
    // session remains).
    let _ = take_native_session_events();
    client.close_session(session).await.map_err(|rv| format!("retry close failed: {rv}"))?;
    let events: Vec<NativeSessionEvent> =
        take_native_session_events().into_iter().map(|(_, event)| event).collect();
    assert_eq!(
        events.len(),
        6,
        "member entry/completion + carrier open/logout/entry/completion, got {events:?}"
    );
    let member = match (&events[0], &events[1]) {
        (
            NativeSessionEvent::CloseSession { session: entered },
            NativeSessionEvent::CloseSessionCompleted { session: completed },
        ) if entered == completed => *entered,
        _ => panic!("unexpected member close shape: {events:?}"),
    };
    let carrier = match (&events[2], &events[3], &events[4], &events[5]) {
        (
            NativeSessionEvent::OpenSession { .. },
            NativeSessionEvent::Logout { session: logged },
            NativeSessionEvent::CloseSession { session: closing },
            NativeSessionEvent::CloseSessionCompleted { session: closed },
        ) if logged == closing && closing == closed => *logged,
        _ => panic!("unexpected retry-close carrier shape: {events:?}"),
    };
    assert_ne!(member, carrier, "the carrier is a fresh session: {events:?}");

    // Subsequent use: the old handle is invalid, a fresh session works.
    match client.get_session_info(session).await {
        Err(rv) if rv == CkRv::SESSION_HANDLE_INVALID => {}
        other => return Err(format!("closed handle must stay invalid, got {other:?}")),
    }
    let fresh = open_public_session(&mut client, slot, true).await?;
    client.get_session_info(fresh).await.map_err(|rv| format!("fresh info failed: {rv}"))?;
    client.finalize().await.map_err(|rv| format!("client finalize: {rv}"))?;
    daemon.shutdown().await?;
    Ok(())
}

/// Loaded cancellation: aborting a close provably in flight still
/// settles it late with exactly one native entry/completion pair and
/// no leak — and the detached completion (F1) still runs the owned
/// transient-carrier logout afterwards. While the close is wedged, an op
/// on the suspended member answers outcome-ambiguous FUNCTION_FAILED
/// (F2), never SESSION_HANDLE_INVALID.
#[tokio::test]
#[ignore] // requires SoftHSM2 + native-owner-test-hooks
async fn loaded_cancelled_close_settles_late_without_native_leak() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = ensure_user_token(&mut client, &fixture).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    let _ = take_native_session_events();
    set_native_close_delay_once(Duration::from_millis(1000));
    let mut closer = client.clone();
    let close_task = tokio::spawn(async move { closer.close_session(session).await });
    // Provably in flight: the native entry lands before the wedge sleep.
    let native = wait_for_close_entry(Duration::from_secs(10)).await?;
    // F2: the suspended member's fate is owned by the wedged close —
    // the daemon must answer ambiguous, not handle-invalid.
    match client.get_session_info(session).await {
        Err(rv) if rv == CkRv::FUNCTION_FAILED => {}
        other => return Err(format!("suspended member must read ambiguous, got {other:?}")),
    }
    close_task.abort();
    let _ = close_task.await;

    // Late completion settles terminally: exactly one entry/completion
    // pair for that handle, no duplicate close, no leaked session. The
    // completion wait (not a sleep) also guarantees quiescence of the
    // member close before the carrier wait below.
    let drained_with_completion =
        wait_for_close_completion(native, Duration::from_secs(10)).await?;
    wait_for_handle_invalid(&mut client, session, Duration::from_secs(10)).await?;
    // F1: the detached completion runs the owned carrier logout even
    // though the handler was dropped — exactly one carrier sequence on
    // a fresh handle, then silence.
    wait_for_carrier_sequence(native, drained_with_completion, Duration::from_secs(10)).await?;
    assert!(
        take_native_session_events().is_empty(),
        "nothing native may run past the member close + carrier sequence (native {native})"
    );
    // Provider truth (SoftHSM 2.6.1): closing the last session
    // auto-releases the token login — and the carrier above released it
    // again (best-effort; its logout reports USER_NOT_LOGGED_IN into the
    // daemon log). A fresh session therefore observes the public state
    // and a fresh login PIN-verifies directly with nothing to reconcile.
    // Whether a holderless login can exist at all is provider-dependent;
    // the server never relies on auto-logout (the owned carrier runs
    // after every last-holder-out, observed or detached), and the
    // server-side mechanism — no orphan, no late steal, serialization
    // through completion — is pinned by the mock-carrier tests.
    let probe = open_public_session(&mut client, slot, true).await?;
    let info =
        client.get_session_info(probe).await.map_err(|rv| format!("probe info failed: {rv}"))?;
    assert_eq!(
        info.state,
        CkSessionState::RwPublic,
        "SoftHSM releases the login with its last session"
    );
    client
        .login(probe, CkUserType::User, Some(fixture.user_pin.as_bytes()))
        .await
        .map_err(|rv| format!("fresh login must PIN-verify: {rv}"))?;
    client.finalize().await.map_err(|rv| format!("client finalize: {rv}"))?;
    daemon.shutdown().await?;
    Ok(())
}

/// Loaded response-timeout: a close wedged past the daemon timeout
/// answers FUNCTION_FAILED promptly (the timeout shapes only the RV),
/// then settles late with exactly one native entry/completion pair —
/// and the deferred post-settle logout (F1 round-2) still runs the
/// owned transient-carrier logout afterwards. Mirror of the
/// cancelled-close oracle on the timeout path.
#[tokio::test]
#[ignore] // requires SoftHSM2 + native-owner-test-hooks
async fn loaded_timed_out_close_releases_login_late() -> Result<(), String> {
    // Daemon-side 2s timeout: every other test in this binary uses fast
    // native calls (the cancel oracle's wedge is 1s), so 2s keeps them
    // far from the timeout however the tests order. OnceLock: first
    // call in this process wins; only this test configures it.
    ::pkcs11_proxy_ng::server::grpc_service::service_utils::configure_backend_guard(2, 200);
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = ensure_user_token(&mut client, &fixture).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    let _ = take_native_session_events();
    set_native_close_delay_once(Duration::from_secs(6));
    let started = Instant::now();
    match client.close_session(session).await {
        Err(rv) if rv == CkRv::FUNCTION_FAILED => {}
        other => return Err(format!("timed-out close must answer ambiguous, got {other:?}")),
    }
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "the response timeout must answer before the wedged native call returns"
    );

    // The native entry landed before the wedge sleep; late completion
    // settles terminally with exactly one entry/completion pair.
    let native = wait_for_close_entry(Duration::from_secs(10)).await?;
    let drained_with_completion =
        wait_for_close_completion(native, Duration::from_secs(10)).await?;
    wait_for_handle_invalid(&mut client, session, Duration::from_secs(10)).await?;
    // F1 round-2: the deferred completion runs the owned carrier logout
    // even though the response timed out — exactly one carrier sequence
    // on a fresh handle, then silence.
    wait_for_carrier_sequence(native, drained_with_completion, Duration::from_secs(10)).await?;
    assert!(
        take_native_session_events().is_empty(),
        "nothing native may run past the member close + carrier sequence (native {native})"
    );
    // Same provider truth as the cancel oracle: SoftHSM releases the
    // login with its last session and the carrier released it again
    // (best-effort); a fresh session observes the public state and a
    // fresh login PIN-verifies.
    let probe = open_public_session(&mut client, slot, true).await?;
    let info =
        client.get_session_info(probe).await.map_err(|rv| format!("probe info failed: {rv}"))?;
    assert_eq!(
        info.state,
        CkSessionState::RwPublic,
        "SoftHSM releases the login with its last session"
    );
    client
        .login(probe, CkUserType::User, Some(fixture.user_pin.as_bytes()))
        .await
        .map_err(|rv| format!("fresh login must PIN-verify: {rv}"))?;
    client.finalize().await.map_err(|rv| format!("client finalize: {rv}"))?;
    daemon.shutdown().await?;
    Ok(())
}
