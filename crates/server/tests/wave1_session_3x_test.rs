//! Round-trip tests for PKCS#11 3.0/3.2 Wave 1 session extension functions.
//!
//! These tests exercise `LoginUser`, `SessionCancel`, and
//! `GetSessionValidationFlags` through the full client -> gRPC -> backend
//! stack using `MockBackend`.
//!
//! The `MockBackend` implements deterministic support for these functions so
//! tests can exercise the full client, proto, gRPC handler, and backend stack
//! without requiring a real provider that supports the 3.x calls.

use std::sync::Arc;

use pkcs11_proxy_ng_types::*;

mod common_3x;
use common_3x::{init_client, mock, mock_daemon};

const CKF_SERIAL: CkSessionFlags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION);

// ────────────────────────────────────────────────────────────────────
// LoginUser round-trip
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn login_user_succeeds_through_full_stack() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    client.login_user(session, CkUserType::User, b"testuser", b"1234").await.unwrap();
}

#[tokio::test]
async fn login_user_with_empty_credentials_reaches_backend() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    // Empty username and pin should still reach the backend and fail as a
    // backend PIN decision, not as unsupported wiring.
    let err = client.login_user(session, CkUserType::So, b"", b"").await.unwrap_err();

    assert_eq!(err, CkRv::PIN_INCORRECT);
}

#[tokio::test]
async fn login_user_all_user_types() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    // All valid CkUserType variants should reach the backend.
    for user_type in [CkUserType::So, CkUserType::User, CkUserType::ContextSpecific] {
        client.login_user(session, user_type, b"user", b"1234").await.unwrap();
    }
}

// ────────────────────────────────────────────────────────────────────
// SessionCancel round-trip
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn session_cancel_succeeds_through_full_stack() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    client.session_cancel(session, CkFlags(0)).await.unwrap();
}

#[tokio::test]
async fn session_cancel_with_flags() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    // Non-zero flags should propagate correctly.
    client.session_cancel(session, CkFlags(0x0000_0001)).await.unwrap();
}

// ────────────────────────────────────────────────────────────────────
// GetSessionValidationFlags round-trip
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_session_validation_flags_returns_zero() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    let flags = client.get_session_validation_flags(session, 0).await.unwrap();

    assert_eq!(flags, 0);
}

#[tokio::test]
async fn get_session_validation_flags_with_nonzero_type() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    // Non-zero flags_type should propagate through.
    let flags = client.get_session_validation_flags(session, 42).await.unwrap();

    assert_eq!(flags, 0);
}

// ────────────────────────────────────────────────────────────────────
// Session validity: Wave 1 functions reject invalid sessions
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn login_user_rejects_invalid_session() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    // Use a session handle that was never opened
    let bad_session = CkSessionHandle(999_999);
    let err = client.login_user(bad_session, CkUserType::User, b"user", b"pin").await.unwrap_err();

    assert_eq!(
        err,
        CkRv::SESSION_HANDLE_INVALID,
        "login_user with invalid session handle should return CKR_SESSION_HANDLE_INVALID"
    );
}

#[tokio::test]
async fn session_cancel_rejects_invalid_session() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let bad_session = CkSessionHandle(999_999);
    let err = client.session_cancel(bad_session, CkFlags(0)).await.unwrap_err();

    assert_eq!(
        err,
        CkRv::SESSION_HANDLE_INVALID,
        "session_cancel with invalid session handle should return CKR_SESSION_HANDLE_INVALID"
    );
}

#[tokio::test]
async fn get_session_validation_flags_rejects_invalid_session() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let bad_session = CkSessionHandle(999_999);
    let err = client.get_session_validation_flags(bad_session, 0).await.unwrap_err();

    assert_eq!(
        err,
        CkRv::SESSION_HANDLE_INVALID,
        "get_session_validation_flags with invalid session should return CKR_SESSION_HANDLE_INVALID"
    );
}
