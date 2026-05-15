//! Round-trip tests for PKCS#11 3.0/3.2 Wave 1 session extension functions.
//!
//! These tests exercise `LoginUser`, `SessionCancel`, and
//! `GetSessionValidationFlags` through the full client -> gRPC -> backend
//! stack using `MockBackend`.
//!
//! The `MockBackend` does not override the default trait implementations for
//! these functions, so they return `CKR_FUNCTION_NOT_SUPPORTED`. The tests
//! verify that this error propagates correctly through the full stack,
//! confirming all layers (client, proto, gRPC handler, backend) are wired.

use std::sync::Arc;

use pkcs11_proxy_ng_types::*;

mod common_3x;
use common_3x::{init_client, mock, mock_daemon};

const CKF_SERIAL: CkSessionFlags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION);

// ────────────────────────────────────────────────────────────────────
// LoginUser round-trip
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn login_user_returns_function_not_supported_through_full_stack() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    let err = client.login_user(session, CkUserType::User, b"testuser", b"1234").await.unwrap_err();

    assert_eq!(
        err,
        CkRv::FUNCTION_NOT_SUPPORTED,
        "MockBackend default login_user should return CKR_FUNCTION_NOT_SUPPORTED"
    );
}

#[tokio::test]
async fn login_user_with_empty_credentials() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    // Empty username and pin should still reach the backend
    let err = client.login_user(session, CkUserType::So, b"", b"").await.unwrap_err();

    assert_eq!(err, CkRv::FUNCTION_NOT_SUPPORTED);
}

#[tokio::test]
async fn login_user_all_user_types() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    // All valid CkUserType variants should reach the backend
    for user_type in [CkUserType::So, CkUserType::User, CkUserType::ContextSpecific] {
        let err = client.login_user(session, user_type, b"user", b"pin").await.unwrap_err();
        assert_eq!(
            err,
            CkRv::FUNCTION_NOT_SUPPORTED,
            "login_user({user_type:?}) should return CKR_FUNCTION_NOT_SUPPORTED"
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// SessionCancel round-trip
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn session_cancel_returns_function_not_supported_through_full_stack() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    let err = client.session_cancel(session, CkFlags(0)).await.unwrap_err();

    assert_eq!(
        err,
        CkRv::FUNCTION_NOT_SUPPORTED,
        "MockBackend default session_cancel should return CKR_FUNCTION_NOT_SUPPORTED"
    );
}

#[tokio::test]
async fn session_cancel_with_flags() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    // Non-zero flags should propagate correctly
    let err = client.session_cancel(session, CkFlags(0x0000_0001)).await.unwrap_err();

    assert_eq!(err, CkRv::FUNCTION_NOT_SUPPORTED);
}

// ────────────────────────────────────────────────────────────────────
// GetSessionValidationFlags round-trip
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_session_validation_flags_returns_function_not_supported() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    let err = client.get_session_validation_flags(session, 0).await.unwrap_err();

    assert_eq!(
        err,
        CkRv::FUNCTION_NOT_SUPPORTED,
        "MockBackend default get_session_validation_flags should return CKR_FUNCTION_NOT_SUPPORTED"
    );
}

#[tokio::test]
async fn get_session_validation_flags_with_nonzero_type() {
    let backend = Arc::new(mock(&[0], &[0x00000001]));
    let (endpoint, _shutdown) = mock_daemon(backend).await;
    let mut client = init_client(&endpoint).await;

    let slots = client.get_slot_list(false).await.unwrap();
    let session = client.open_session(slots[0], CKF_SERIAL).await.unwrap();

    // Non-zero flags_type should propagate through
    let err = client.get_session_validation_flags(session, 42).await.unwrap_err();

    assert_eq!(err, CkRv::FUNCTION_NOT_SUPPORTED);
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
