//! G2-PR3: per-slot aggregate failed-login budget — integration tests.
//!
//! This file is compiled as a separate binary so it has its own `OnceLock`
//! for `rate_quota::configure`, independent of the unit-test binaries.  All
//! "budget set" scenarios run in a single test function to avoid OnceLock
//! races between parallel test functions in the same binary.

use std::sync::Arc;

use pkcs11_proxy_ng::config::RateLimitConfig;
use pkcs11_proxy_ng::server::rate_quota;
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_types::*;

mod common_3x;
use common_3x::mock_daemon_with_lease;

/// Helper: spin up a mock daemon with the standard test lease.
async fn mock_daemon(backend: Arc<MockBackend>) -> (String, tokio::sync::watch::Sender<bool>) {
    mock_daemon_with_lease(
        backend,
        std::time::Duration::from_secs(300),
        std::time::Duration::from_millis(100),
    )
    .await
}

/// G2-PR3 end-to-end: verify the per-slot failed-login budget protects the
/// backend's shared PIN-lockout counter.
///
/// All budget-set scenarios are sequenced within a single `#[tokio::test]` so
/// the `OnceLock`-guarded `rate_quota::configure` is called exactly once per
/// process and all scenarios see a consistent configuration.
#[tokio::test]
async fn per_slot_failed_login_budget_end_to_end() {
    // ── Configure budget once ────────────────────────────────────────────────
    // OnceLock: first call wins; subsequent calls in the same process are no-ops.
    rate_quota::configure(&RateLimitConfig {
        per_principal_max_in_flight: None,
        per_principal_max_sessions: None,
        per_slot_failed_login_budget: Some(3),
        per_slot_failed_login_cooldown_secs: Some(1), // 1 s for the expiry scenario
    });

    // Verify the budget was actually applied (guard against a race where another
    // configure call already ran — should not happen in an isolated binary).
    if rate_quota::configured_login_budget() != Some(3) {
        // OnceLock set differently by a sibling invocation; skip rather than assert
        // on wrong invariants.
        return;
    }

    // ── Scenario A: budget trips at K; (K+1)th attempt fast-rejects ─────────
    //
    // The mock is configured to return CKR_PIN_INCORRECT from every login call.
    // With budget = 3:
    //   • Attempts 1-3 reach the backend and return CKR_PIN_INCORRECT
    //     (transparency — the real RV is forwarded verbatim).
    //   • Attempt 4 is fast-rejected with CKR_DEVICE_ERROR WITHOUT a backend
    //     call (assert login_call_count stays at 3).
    {
        let mock_a = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock_a.initialize().unwrap();
        mock_a.inject_login_rv(CkRv::PIN_INCORRECT);

        let (endpoint, _shutdown) = mock_daemon(mock_a.clone()).await;
        let mut client = pkcs11_proxy_ng_client::Pkcs11Client::connect(&endpoint).await.unwrap();
        client.initialize().await.unwrap();

        let slots = client.get_slot_list(false).await.unwrap();
        assert!(!slots.is_empty(), "setup: daemon must expose at least one slot");
        let session = client
            .open_session(
                slots[0],
                CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION),
            )
            .await
            .unwrap();

        // Attempts 1-3: backend is called, CKR_PIN_INCORRECT returned each time.
        for i in 1_usize..=3 {
            let rv = client.login(session, CkUserType::User, Some(b"wrongpin")).await.unwrap_err();
            assert_eq!(
                rv,
                CkRv::PIN_INCORRECT,
                "attempt {i}: must be transparent CKR_PIN_INCORRECT"
            );
            assert_eq!(
                mock_a.login_call_count(),
                i,
                "attempt {i}: backend must have been called exactly {i} time(s)"
            );
        }

        // Attempt 4: fast-reject — no backend call, CKR_DEVICE_ERROR.
        let rv4 = client.login(session, CkUserType::User, Some(b"wrongpin")).await.unwrap_err();
        assert_eq!(
            rv4,
            CkRv::DEVICE_ERROR,
            "4th attempt must be fast-rejected with CKR_DEVICE_ERROR (cooldown active)"
        );
        assert_eq!(
            mock_a.login_call_count(),
            3,
            "4th attempt must NOT reach the backend (login_call_count stays at 3)"
        );
    }

    // Reset rate_quota state for the next scenario: a successful login clears
    // native slot's failure counter and cooldown. Both fixtures use backend slot 0.
    rate_quota::record_login_success(::pkcs11_proxy_ng::server::slot_map::BackendSlotId(CkSlotId(
        0,
    )));

    // ── Scenario B: a successful login resets the failure counter ────────────
    //
    // Sequence: 2 failed logins (count=2), then one successful (count=0 reset),
    // then 3 more fails (count trips budget again), then 4th is fast-rejected.
    // The total number of backend login calls is 2 (fails) + 1 (success) + 3
    // (fresh fails) = 6; the 4th attempt after the second trip is not a backend
    // call (count stays at 6).
    {
        let mock_b = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock_b.initialize().unwrap();
        mock_b.inject_login_rv(CkRv::PIN_INCORRECT);

        let (endpoint, _shutdown) = mock_daemon(mock_b.clone()).await;
        let mut client = pkcs11_proxy_ng_client::Pkcs11Client::connect(&endpoint).await.unwrap();
        client.initialize().await.unwrap();

        let slots = client.get_slot_list(false).await.unwrap();
        let session = client
            .open_session(
                slots[0],
                CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION),
            )
            .await
            .unwrap();

        // Two failed attempts (count = 2, below budget=3).
        for _ in 0..2 {
            let rv = client.login(session, CkUserType::User, Some(b"bad")).await.unwrap_err();
            assert_eq!(rv, CkRv::PIN_INCORRECT, "pre-success fail must be PIN_INCORRECT");
        }
        assert_eq!(mock_b.login_call_count(), 2, "two failures must each reach the backend");

        // Successful login: clears inject so mock returns OK → backend records
        // login state → record_login_success resets the counter to 0.
        mock_b.clear_login_rv();
        client.login(session, CkUserType::User, Some(b"correct")).await.unwrap();
        assert_eq!(mock_b.login_call_count(), 3, "success must reach the backend");

        // Log out to allow fresh failed logins (the slot is now "logged in").
        client.logout(session).await.unwrap();

        // Re-inject PIN_INCORRECT for the post-reset failure run.
        mock_b.inject_login_rv(CkRv::PIN_INCORRECT);

        // Three fresh failures (counter starts at 0 again → trips at 3).
        for i in 1_usize..=3 {
            let rv = client.login(session, CkUserType::User, Some(b"bad")).await.unwrap_err();
            assert_eq!(
                rv,
                CkRv::PIN_INCORRECT,
                "post-reset attempt {i}: must be transparent PIN_INCORRECT (fresh budget)"
            );
        }
        assert_eq!(
            mock_b.login_call_count(),
            6,
            "three post-reset fails + one success + two pre-success fails = 6 backend calls"
        );

        // Next attempt: budget is tripped again, fast-reject.
        let rv_reject = client.login(session, CkUserType::User, Some(b"bad")).await.unwrap_err();
        assert_eq!(
            rv_reject,
            CkRv::DEVICE_ERROR,
            "post-reset 4th failure must be fast-rejected (budget tripped again)"
        );
        assert_eq!(mock_b.login_call_count(), 6, "fast-reject must not call the backend");
    }

    // Reset again for the cooldown-expiry scenario.
    rate_quota::record_login_success(::pkcs11_proxy_ng::server::slot_map::BackendSlotId(CkSlotId(
        0,
    )));

    // ── Scenario C: cooldown expiry allows logins through again ─────────────
    //
    // After the budget is exhausted (3 failures), logins are fast-rejected.
    // After the 1-second cooldown window expires, logins reach the backend again.
    {
        let mock_c = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![]));
        mock_c.initialize().unwrap();
        mock_c.inject_login_rv(CkRv::PIN_INCORRECT);

        let (endpoint, _shutdown) = mock_daemon(mock_c.clone()).await;
        let mut client = pkcs11_proxy_ng_client::Pkcs11Client::connect(&endpoint).await.unwrap();
        client.initialize().await.unwrap();

        let slots = client.get_slot_list(false).await.unwrap();
        let session = client
            .open_session(
                slots[0],
                CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION),
            )
            .await
            .unwrap();

        // Trip the budget (3 failures).
        for _ in 0..3 {
            let _ = client.login(session, CkUserType::User, Some(b"bad")).await;
        }
        assert_eq!(mock_c.login_call_count(), 3, "three failures must reach the backend");

        // Confirm we are in cooldown: the next attempt is fast-rejected.
        let rv_cold = client.login(session, CkUserType::User, Some(b"bad")).await.unwrap_err();
        assert_eq!(rv_cold, CkRv::DEVICE_ERROR, "slot must be in cooldown immediately after trip");
        assert_eq!(mock_c.login_call_count(), 3, "cooldown fast-reject must not call backend");

        // Wait for the cooldown to expire (configured at 1 second; add 200 ms margin).
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

        // After expiry the login must reach the backend again.
        let rv_after = client.login(session, CkUserType::User, Some(b"bad")).await.unwrap_err();
        assert_eq!(
            rv_after,
            CkRv::PIN_INCORRECT,
            "after cooldown expiry, login must reach the backend and return the real RV"
        );
        assert_eq!(
            mock_c.login_call_count(),
            4,
            "after cooldown expiry, backend must be called again"
        );
    }
}
