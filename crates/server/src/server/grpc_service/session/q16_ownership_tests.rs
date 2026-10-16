#![allow(clippy::print_stderr)]
//! Q16 bounded native-result ownership investigation.
//!
//! Test-diagnostic transcript lines (`Q16:`-prefixed, slot ids / flags /
//! counts only — never secrets) read with `-- --nocapture`.
//!
//! Box 1 (late-OpenSession result ownership) drives the real
//! `open_session` dispatch path against an entry/completion-gated
//! [`MockBackend`]: cancel the caller after observed native entry,
//! then release completion and compare native session count, mapped
//! handles, issued closes, and post-teardown survival. Box 3
//! (PENDING/unsupported-async retention) pins the executed negative
//! controls — flag pass-through and plain PENDING mapping — that the
//! disposition trace rests on.

use super::{close_all_sessions, open_session};
use crate::server::context_manager::{ClientContextId, ContextManager};
use crate::server::slot_map::BackendSlotId;
use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
use pkcs11_proxy_ng_types::*;
use std::sync::Arc;
use std::time::Duration;
use tonic::Request;

/// PKCS#11 v3.2 `CKF_ASYNC_SESSION` (`general_data_types.md`): an
/// application requests an asynchronous session by setting this bit
/// in `C_OpenSession` flags. Stated here (not imported) because no
/// proxy layer names it — the box-3 trace proves that below.
const CKF_ASYNC_SESSION: u64 = 0x0000_0008;

/// Fresh backend + context with zero sessions, so native/mapped
/// counts are exact. Returns the mock (for gates/counters), the
/// trait backend, the manager, the context id, and the virtual slot.
async fn setup_clean()
-> (Arc<MockBackend>, Arc<dyn Pkcs11Backend>, Arc<ContextManager>, ClientContextId, u64) {
    let mock = Arc::new(MockBackend::default_test());
    mock.initialize().unwrap();
    let backend: Arc<dyn Pkcs11Backend> = mock.clone();
    let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
    ctx_mgr.register_slot(BackendSlotId(CkSlotId(0))).await;
    let ctx_id = ctx_mgr.create_context(None).await.unwrap();
    let virtual_slot = ctx_mgr.virtual_slots().await[0];
    assert_eq!(mock.open_session_count(), 0, "fresh backend must hold no sessions");
    (mock, backend, ctx_mgr, ctx_id, virtual_slot.0)
}

fn open_request(
    ctx_id: &ClientContextId,
    slot: u64,
    flags: u64,
) -> Request<pkcs11_proxy_ng_proto::OpenSessionRequest> {
    Request::new(pkcs11_proxy_ng_proto::OpenSessionRequest {
        client_context_id: ctx_id.0.clone(),
        slot_id: slot,
        flags,
    })
}

async fn mapped_session_count(ctx_mgr: &Arc<ContextManager>, ctx_id: &ClientContextId) -> usize {
    ctx_mgr.get_context(ctx_id, |ctx| ctx.session_slots.len()).await.unwrap_or(0)
}

/// Poll a backend-count predicate until it holds or fail loudly
/// instead of hanging. Used to await async settlement deterministically.
async fn await_backend_state(
    mock: &Arc<MockBackend>,
    what: &str,
    mut done: impl FnMut(usize, usize) -> bool,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let native = mock.open_session_count();
        let closes = mock.close_session_call_count();
        if done(native, closes) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for backend state ({what}): native={native} closes={closes}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Box 1, cancel-after-entry case: the caller is cancelled while the
/// worker is parked inside the real backend `open_session`; the
/// native open then completes. The completed native session must be
/// owned — registered or closed — never orphaned.
///
/// Pre-box-2 this fails with one surviving native session and zero
/// mapped handles / issued closes (box-1 confirmation + box-2 RED);
/// post-box-2 the completion owner closes the late result (GREEN).
#[tokio::test]
async fn q16_box1_cancel_after_entry_leaves_no_orphan() {
    let (mock, backend, ctx_mgr, ctx_id, slot) = setup_clean().await;
    let flags = (CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION).0;

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    mock.set_open_session_gate(entered_tx, release_rx);

    // Drive the real dispatch path (audit-wrapped test shim).
    let rpc = {
        let (ctx_mgr, backend, req) =
            (ctx_mgr.clone(), backend.clone(), open_request(&ctx_id, slot, flags));
        tokio::spawn(async move { open_session(&ctx_mgr, &backend, req).await })
    };
    // Native entry observed: the worker is inside backend open_session.
    let (seen_slot, seen_flags) = tokio::task::spawn_blocking(move || {
        entered_rx.recv_timeout(Duration::from_secs(10)).expect("native entry observed")
    })
    .await
    .unwrap();
    eprintln!("Q16: native entry observed slot={} flags={:#x}", seen_slot.0, seen_flags.0);
    assert_eq!(seen_slot, CkSlotId(0));
    assert_eq!(seen_flags.0, flags);
    assert_eq!(mock.open_session_count(), 0, "gated open must not allocate before release");

    // Cancel the caller while native completion is still pending.
    rpc.abort();
    let aborted = rpc.await.expect_err("aborted join must err");
    assert!(aborted.is_cancelled(), "handler future must cancel");
    eprintln!("Q16: caller cancelled while native open parked");

    // Complete the native open; the result now has no consumer.
    // Observe completion (native==1) or fast settlement (a close
    // already issued), whichever lands first — the settlement task
    // races this poll by design.
    release_tx.send(()).expect("parked worker alive");
    await_backend_state(&mock, "late native completion", |native, closes| {
        native == 1 || closes == 1
    })
    .await;
    eprintln!(
        "Q16: native open completed native={} mapped={} closes={}",
        mock.open_session_count(),
        mapped_session_count(&ctx_mgr, &ctx_id).await,
        mock.close_session_call_count()
    );
    assert_eq!(
        mapped_session_count(&ctx_mgr, &ctx_id).await,
        0,
        "cancelled open must never publish a mapping"
    );

    // Devil's-advocate cleanup 1: service close-all closes only mapped
    // sessions of this context — the orphan (if any) must survive it.
    let close_all = close_all_sessions(
        &ctx_mgr,
        &backend,
        Request::new(pkcs11_proxy_ng_proto::CloseAllSessionsRequest {
            client_context_id: ctx_id.0.clone(),
            slot_id: slot,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(close_all.ck_rv, CkRv::OK.0);
    eprintln!("Q16: after service close-all native={}", mock.open_session_count());

    // Devil's-advocate cleanup 2: full context teardown reaps only
    // mapped sessions — the orphan (if any) must survive it too.
    let mut departed = ctx_mgr.remove_context(&ctx_id).expect("context present");
    let plan = ctx_mgr.plan_removed_context_teardown(&mut departed);
    eprintln!("Q16: teardown plan closes {} mapped sessions", plan.sessions_to_close.len());
    ctx_mgr.execute_teardown_plans(&backend, vec![plan]).await;
    eprintln!(
        "Q16: after context teardown native={} closes={}",
        mock.open_session_count(),
        mock.close_session_call_count()
    );

    // Owned-handle verdict: the settlement (one close, exactly
    // once) must retire the late result — no native session may
    // survive teardown. Pre-fix this times out with native==1 and
    // closes==0 (the confirmed orphan).
    await_backend_state(&mock, "late-result settlement", |native, closes| {
        native == 0 && closes == 1
    })
    .await;
    eprintln!(
        "Q16: terminal native={} closes={}",
        mock.open_session_count(),
        mock.close_session_call_count()
    );
    assert_eq!(
        mock.open_session_count(),
        0,
        "late OpenSession result must be owned (registered or closed), never orphaned"
    );
    assert_eq!(mock.close_session_call_count(), 1, "the late result must be closed exactly once");
}

/// Box 1, allocation-failure case: the native open succeeds but
/// handle registration fails (context gone before the result is
/// consumed). The existing fallback close must own the handle.
#[tokio::test]
async fn q16_box1_registration_failure_fallback_close_owns_handle() {
    let (mock, backend, ctx_mgr, ctx_id, slot) = setup_clean().await;
    let flags = (CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION).0;

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    mock.set_open_session_gate(entered_tx, release_rx);

    let rpc = {
        let (ctx_mgr, backend, req) =
            (ctx_mgr.clone(), backend.clone(), open_request(&ctx_id, slot, flags));
        tokio::spawn(async move { open_session(&ctx_mgr, &backend, req).await })
    };
    tokio::task::spawn_blocking(move || {
        entered_rx.recv_timeout(Duration::from_secs(10)).expect("native entry observed")
    })
    .await
    .unwrap();
    eprintln!("Q16: native entry observed; removing context before completion");

    // Registration can no longer succeed: the context is gone.
    ctx_mgr.remove_context(&ctx_id).expect("context present");
    release_tx.send(()).expect("parked worker alive");
    let response = rpc.await.expect("handler joinable").expect("handler status ok").into_inner();
    eprintln!(
        "Q16: response ck_rv={:#x} handle={} native={} closes={}",
        response.ck_rv,
        response.session_handle,
        mock.open_session_count(),
        mock.close_session_call_count()
    );

    assert_eq!(response.session_handle, 0, "failed registration must not publish a handle");
    assert_eq!(
        mock.open_session_count(),
        0,
        "fallback close must retire the successfully opened native session"
    );
    assert_eq!(
        mock.close_session_call_count(),
        1,
        "exactly one fallback close must run for the unregistered handle"
    );
}

/// Box 3, refusal-gate control: an application `CKF_ASYNC_SESSION`
/// open request must either be refused before native entry or reach
/// the backend observably. This pins the executed fact the
/// disposition rests on: the flag reaches the backend verbatim —
/// no proxy layer refuses or masks async-session requests.
#[tokio::test]
async fn q16_box3_async_session_flag_reaches_backend_ungated() {
    let (mock, backend, ctx_mgr, ctx_id, slot) = setup_clean().await;
    let flags = (CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION).0 | CKF_ASYNC_SESSION;

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    mock.set_open_session_gate(entered_tx, release_rx);

    let rpc = {
        let (ctx_mgr, backend, req) =
            (ctx_mgr.clone(), backend.clone(), open_request(&ctx_id, slot, flags));
        tokio::spawn(async move { open_session(&ctx_mgr, &backend, req).await })
    };
    let (seen_slot, seen_flags) = tokio::task::spawn_blocking(move || {
        entered_rx.recv_timeout(Duration::from_secs(10)).expect("native entry observed")
    })
    .await
    .unwrap();
    eprintln!(
        "Q16: async-flag open reached backend slot={} flags={:#x}",
        seen_slot.0, seen_flags.0
    );
    release_tx.send(()).expect("parked worker alive");
    let response = rpc.await.expect("handler joinable").expect("handler status ok").into_inner();
    assert_eq!(response.ck_rv, CkRv::OK.0);

    assert_eq!(seen_slot, CkSlotId(0));
    assert_eq!(
        seen_flags.0 & CKF_ASYNC_SESSION,
        CKF_ASYNC_SESSION,
        "CKF_ASYNC_SESSION must reach the backend verbatim (no proxy refusal gate)"
    );
}

/// Box 3, PENDING-mapping control: a backend `CKR_PENDING` return is
/// passed through as a plain error RV with no PENDING branch. This
/// pins the executed half of the retention trace: nothing retains or
/// completes the frame on PENDING.
#[tokio::test]
async fn q16_box3_pending_returned_as_plain_error() {
    let (mock, backend, ctx_mgr, ctx_id, slot) = setup_clean().await;
    let flags = (CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION).0;

    mock.inject_error(CkRv::PENDING);
    let response = open_session(&ctx_mgr, &backend, open_request(&ctx_id, slot, flags))
        .await
        .expect("handler status ok")
        .into_inner();
    mock.clear_error();
    eprintln!(
        "Q16: injected PENDING answered ck_rv={:#x} handle={}",
        response.ck_rv, response.session_handle
    );

    assert_eq!(response.ck_rv, CkRv::PENDING.0, "PENDING must pass through verbatim");
    assert_eq!(response.session_handle, 0);
    assert_eq!(mock.open_session_count(), 0, "failed open must allocate nothing");
}
