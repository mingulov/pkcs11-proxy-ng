//! Replayable synthetic native session contracts; no real-provider qualification.
#![cfg(unix)]
#![allow(clippy::print_stderr)]

#[path = "session_sequence/harness.rs"]
mod harness;
#[path = "session_sequence/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../../../tests/ffi_oracles/session_lifecycle/src/types.rs"]
mod oracle_types;
#[path = "session_sequence/replay.rs"]
mod replay;

use pkcs11_proxy_ng_types::CkRv;
use replay::{Action::*, Replay};

async fn run_case(id: &str, prefixes: &[Vec<replay::Action>]) -> Result<(), String> {
    let selection = Replay::read()?;
    let mut traces = 0;
    let mut actions = 0;
    let mut max_live = 0;
    let mut native_events = 0;
    for seed in &selection.seeds {
        for prefix in prefixes {
            let stats = replay::run_trace(prefix, *seed, selection.prefix).await?;
            traces += 1;
            actions += stats.actions;
            max_live = max_live.max(stats.max_live);
            native_events += stats.native_events;
        }
    }
    eprintln!(
        "session-sequence:{id} traces={traces} actions={actions} max_live={max_live} native_events={native_events}"
    );
    // A selected/prefix replay is useful triage, never canonical completion evidence.
    if selection.selected {
        eprintln!(
            "session-sequence-replay-complete:{id} seeds={:?} prefix={:?}",
            selection.seeds, selection.prefix
        );
    } else {
        eprintln!("native-contract-complete:{id}");
    }
    Ok(())
}

/// Catches premature mapping retirement, pre-close logout, login short-circuits,
/// and failure to reopen the FFI fence after an actual native close error.
#[tokio::test]
#[ignore = "requires explicitly built session lifecycle native oracle"]
async fn sequence_login_retry_failed_close_preserves_native_state() -> Result<(), String> {
    run_case(
        "sequence_login_retry_failed_close_preserves_native_state",
        &[vec![
            Open(0),
            Login(0, false),
            Login(0, true),
            Login(0, false),
            Close(0, CkRv::FUNCTION_FAILED),
            Random(0, CkRv::OK),
            Login(0, true),
            Close(0, CkRv::OK),
            Info(0),
            Open(1),
            Login(1, true),
            CloseAll(None),
        ]],
    )
    .await
}

/// Catches settling an entire failed batch as terminal or retaining closed members.
#[tokio::test]
#[ignore = "requires explicitly built session lifecycle native oracle"]
async fn sequence_partial_close_all_keeps_only_survivor() -> Result<(), String> {
    run_case(
        "sequence_partial_close_all_keeps_only_survivor",
        &[vec![
            Open(0),
            Open(1),
            Login(0, true),
            CloseAll(Some(0)),
            Info(1),
            Random(0, CkRv::OK),
            Login(0, true),
            CloseAll(None),
            Info(0),
            Info(1),
        ]],
    )
    .await
}

/// Catches normalized operation errors, missing native entries and accidental lease eviction.
#[tokio::test]
#[ignore = "requires explicitly built session lifecycle native oracle"]
async fn sequence_operation_errors_do_not_retire_live_session() -> Result<(), String> {
    run_case(
        "sequence_operation_errors_do_not_retire_live_session",
        &[vec![
            Open(0),
            Login(0, true),
            Random(0, CkRv::ARGUMENTS_BAD),
            Random(0, CkRv::OK),
            Random(0, CkRv::OPERATION_NOT_INITIALIZED),
            Random(0, CkRv::OK),
            Random(0, CkRv::FUNCTION_FAILED),
            Info(0),
            Random(0, CkRv::OK),
            Close(0, CkRv::OK),
        ]],
    )
    .await
}

/// Catches a stale reverse binding or an old virtual id reaching a recycled raw session.
#[tokio::test]
#[ignore = "requires explicitly built session lifecycle native oracle"]
async fn sequence_raw_handle_reuse_never_revives_old_virtual_handle() -> Result<(), String> {
    run_case(
        "sequence_raw_handle_reuse_never_revives_old_virtual_handle",
        &[vec![
            Open(0),
            Login(0, true),
            Close(0, CkRv::OK),
            Reuse(0, 1),
            Info(0),
            Random(0, CkRv::OK),
            Close(0, CkRv::OK),
            Info(1),
            Login(1, true),
            Random(1, CkRv::OK),
            Close(1, CkRv::OK),
        ]],
    )
    .await
}

/// Catches lost detached completion/carrier ownership and a false terminal pending verdict.
#[tokio::test]
#[ignore = "requires explicitly built session lifecycle native oracle"]
async fn sequence_cancelled_close_replays_late_terminal_and_transient_outcomes()
-> Result<(), String> {
    run_case(
        "sequence_cancelled_close_replays_late_terminal_and_transient_outcomes",
        &[
            vec![
                Open(0),
                Login(0, true),
                CancelClose(0, CkRv::OK),
                Info(0),
                Open(1),
                Login(1, true),
                CloseAll(None),
            ],
            vec![
                Open(0),
                Login(0, true),
                CancelClose(0, CkRv::FUNCTION_FAILED),
                Random(0, CkRv::OK),
                Login(0, true),
                Close(0, CkRv::OK),
            ],
        ],
    )
    .await
}
