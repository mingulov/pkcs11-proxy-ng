//! SoftHSM fixture variants (Items 78, 82).
//!
//! Tests exercising multiple-slot, token reinit, object persistence,
//! virtual slot mapping, and multi-token topology scenarios.

mod support;

use std::{ffi::OsString, path::PathBuf};

use pkcs11_proxy_ng_types::*;
use support::{
    DaemonHarness, ProviderFixture, create_data_object, find_objects_by_label, find_token_slot,
    generate_rsa_key_pair, initialized_client, open_user_session, rsa_sign_and_verify,
};

struct EnvVarRestore {
    key: &'static str,
    original: Option<OsString>,
}

impl EnvVarRestore {
    fn capture(key: &'static str) -> Self {
        Self { key, original: std::env::var_os(key) }
    }
}

impl Drop for EnvVarRestore {
    fn drop(&mut self) {
        unsafe {
            match &self.original {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

/// Dropping a SoftHSM fixture should restore the caller's SOFTHSM2_CONF.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn soft_hsm_fixture_restores_softhsm2_conf_on_drop() -> Result<(), String> {
    let _restore = EnvVarRestore::capture("SOFTHSM2_CONF");
    let previous_conf =
        std::env::temp_dir().join(format!("pkcs11-proxy-ng-prev-{}", std::process::id()));
    unsafe {
        std::env::set_var("SOFTHSM2_CONF", &previous_conf);
    }

    let fixture = ProviderFixture::soft_hsm().await?;
    let active_conf = std::env::var_os("SOFTHSM2_CONF")
        .map(PathBuf::from)
        .ok_or_else(|| "fixture should set SOFTHSM2_CONF".to_string())?;
    assert_ne!(
        active_conf, previous_conf,
        "fixture should point SoftHSM at its isolated temp config while active"
    );

    drop(fixture);

    let restored_conf = std::env::var_os("SOFTHSM2_CONF")
        .map(PathBuf::from)
        .ok_or_else(|| "SOFTHSM2_CONF should be restored after fixture drop".to_string())?;
    assert_eq!(restored_conf, previous_conf);
    Ok(())
}

// ── Multi-slot tests ────────────────────────────────────────────────

/// Verify the daemon exposes multiple SoftHSM tokens as separate virtual slots.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn multi_slot_all_tokens_visible() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm_multi_slot(3).await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slots = client.get_slot_list(true).await.map_err(|rv| rv.to_string())?;
    assert!(slots.len() >= 3, "expected at least 3 slots, got {}", slots.len());

    // Verify each slot has a distinct token label.
    let mut labels = Vec::new();
    for &slot in &slots {
        let info = client.get_token_info(slot).await.map_err(|rv| rv.to_string())?;
        let label = info.label.trim().to_string();
        if !label.is_empty() {
            labels.push(label);
        }
    }
    // At least 3 initialized tokens should have labels.
    assert!(
        labels.len() >= 3,
        "expected at least 3 labeled tokens, got {}: {:?}",
        labels.len(),
        labels
    );
    // Labels should be unique.
    let unique: std::collections::HashSet<_> = labels.iter().collect();
    assert_eq!(unique.len(), labels.len(), "token labels must be unique: {:?}", labels);

    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// Create objects on different slots and verify they're isolated.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn multi_slot_object_isolation() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm_multi_slot(2).await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slots = client.get_slot_list(true).await.map_err(|rv| rv.to_string())?;
    assert!(slots.len() >= 2, "need at least 2 slots");

    let slot_a = slots[0];
    let slot_b = slots[1];

    // Open sessions on both slots.
    let session_a = open_user_session(&mut client, slot_a, "1234", true).await?;
    let session_b = open_user_session(&mut client, slot_b, "1234", true).await?;

    // Create a data object on slot A only.
    let label = "multi-slot-isolation-test";
    create_data_object(&mut client, session_a, label, b"slot-a-data").await?;

    // Object should be findable on slot A.
    let found_a = find_objects_by_label(&mut client, session_a, label).await?;
    assert!(!found_a.is_empty(), "object should exist on slot A");

    // Object should NOT be findable on slot B.
    let found_b = find_objects_by_label(&mut client, session_b, label).await?;
    assert!(found_b.is_empty(), "object should NOT exist on slot B");

    client.close_session(session_a).await.map_err(|rv| rv.to_string())?;
    client.close_session(session_b).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// Sign with a key on slot A, verify on slot A — slot B keys can't interfere.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn multi_slot_independent_crypto() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm_multi_slot(2).await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slots = client.get_slot_list(true).await.map_err(|rv| rv.to_string())?;
    assert!(slots.len() >= 2);

    let session_a = open_user_session(&mut client, slots[0], "1234", true).await?;

    let (pub_key, priv_key) =
        generate_rsa_key_pair(&mut client, session_a, "multi-slot-crypto", false).await?;

    let payload = b"multi-slot test data";
    let signature = rsa_sign_and_verify(&mut client, session_a, priv_key, pub_key, payload).await?;
    assert!(!signature.is_empty());

    client.close_session(session_a).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

// ── Token reinit tests ──────────────────────────────────────────────

/// Reinit token after creating objects — all objects should be gone.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn token_reinit_clears_objects() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;

    // Create a token object.
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let label = "reinit-test-obj";
    create_data_object(&mut client, session, label, b"will be destroyed").await?;
    let found = find_objects_by_label(&mut client, session, label).await?;
    assert!(!found.is_empty(), "object should exist before reinit");

    // Close all sessions (required before InitToken).
    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_all_sessions(slot).await.map_err(|rv| rv.to_string())?;

    // Reinitialize the token with a new label.
    client
        .init_token(slot, Some(fixture.so_pin.as_bytes()), "reinited-token")
        .await
        .map_err(|rv| format!("C_InitToken failed: {rv}"))?;

    // Set user PIN again (required after reinit).
    let flags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION | CkSessionFlags::RW_SESSION);
    let session2 = client.open_session(slot, flags).await.map_err(|rv| rv.to_string())?;
    client
        .login(session2, CkUserType::So, Some(fixture.so_pin.as_bytes()))
        .await
        .map_err(|rv| format!("SO login failed: {rv}"))?;
    client
        .init_pin(session2, Some(fixture.user_pin.as_bytes()))
        .await
        .map_err(|rv| format!("C_InitPIN failed: {rv}"))?;
    client.logout(session2).await.map_err(|rv| rv.to_string())?;
    client.close_session(session2).await.map_err(|rv| rv.to_string())?;

    // Verify token label changed.
    let info = client.get_token_info(slot).await.map_err(|rv| rv.to_string())?;
    assert_eq!(info.label.trim(), "reinited-token");

    // Verify objects are gone.
    let session3 = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let found_after = find_objects_by_label(&mut client, session3, label).await?;
    assert!(found_after.is_empty(), "objects should be gone after reinit");

    client.close_session(session3).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

// ── Object persistence tests ────────────────────────────────────────

/// Token objects persist across session close/reopen.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn token_object_persists_across_sessions() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;

    // Session 1: create a token (persistent) data object.
    let session1 = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let label = "persist-test-obj";
    let template = vec![
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(CkObjectClass::DATA.0)),
        },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(true)), // persistent
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(label.to_string())),
        },
        CkAttribute {
            attr_type: CkAttributeType::VALUE,
            value: Some(CkAttributeValue::Bytes(b"persistent payload".to_vec())),
        },
    ];
    client
        .create_object(session1, &template)
        .await
        .map_err(|rv| format!("C_CreateObject failed: {rv}"))?;

    // Close session 1 (logout first).
    client.logout(session1).await.map_err(|rv| rv.to_string())?;
    client.close_session(session1).await.map_err(|rv| rv.to_string())?;

    // Session 2: reopen and search for the object.
    let session2 = open_user_session(&mut client, slot, &fixture.user_pin, false).await?;
    let found = find_objects_by_label(&mut client, session2, label).await?;
    assert!(!found.is_empty(), "token object should persist across sessions");

    // Clean up: re-find the object in a RW session to get a valid handle.
    client.logout(session2).await.map_err(|rv| rv.to_string())?;
    client.close_session(session2).await.map_err(|rv| rv.to_string())?;
    let session_rw = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let to_delete = find_objects_by_label(&mut client, session_rw, label).await?;
    for obj in &to_delete {
        client
            .destroy_object(session_rw, *obj)
            .await
            .map_err(|rv| format!("C_DestroyObject failed: {rv}"))?;
    }
    client.logout(session_rw).await.map_err(|rv| rv.to_string())?;
    client.close_session(session_rw).await.map_err(|rv| rv.to_string())?;

    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// Session objects do NOT persist after session close.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn session_object_does_not_persist() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;

    // Session 1: create a session (non-persistent) data object.
    let session1 = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let label = "session-only-obj";
    create_data_object(&mut client, session1, label, b"ephemeral").await?;
    let found = find_objects_by_label(&mut client, session1, label).await?;
    assert!(!found.is_empty(), "session object should exist during session");

    // Close session 1.
    client.logout(session1).await.map_err(|rv| rv.to_string())?;
    client.close_session(session1).await.map_err(|rv| rv.to_string())?;

    // Session 2: reopen and verify the object is gone.
    let session2 = open_user_session(&mut client, slot, &fixture.user_pin, false).await?;
    let found_after = find_objects_by_label(&mut client, session2, label).await?;
    assert!(found_after.is_empty(), "session object should NOT persist after session close");

    client.close_session(session2).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// Generate a token-persistent RSA key pair, close session, reopen and use it.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn persistent_key_survives_session_close() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = find_token_slot(&mut client).await?;

    // Session 1: generate persistent key pair.
    let session1 = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let label_prefix = "persist-key";
    let (_, _) = generate_rsa_key_pair(&mut client, session1, label_prefix, true).await?;

    // Close session 1.
    client.logout(session1).await.map_err(|rv| rv.to_string())?;
    client.close_session(session1).await.map_err(|rv| rv.to_string())?;

    // Session 2: find the key by searching for private key class with our label prefix.
    let session2 = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    // Find private keys — our generated one should be there.
    let template = vec![CkAttribute {
        attr_type: CkAttributeType::CLASS,
        value: Some(CkAttributeValue::Ulong(CkObjectClass::PRIVATE_KEY.0)),
    }];
    client
        .find_objects_init(session2, &template)
        .await
        .map_err(|rv| format!("FindObjectsInit failed: {rv}"))?;
    let keys = client
        .find_objects(session2, 32)
        .await
        .map_err(|rv| format!("FindObjects failed: {rv}"))?;
    client
        .find_objects_final(session2)
        .await
        .map_err(|rv| format!("FindObjectsFinal failed: {rv}"))?;

    assert!(!keys.is_empty(), "persistent private key should survive session close");

    // Clean up: destroy the keys.
    for key in &keys {
        let _ = client.destroy_object(session2, *key).await;
    }
    // Also clean public keys.
    let pub_template = vec![CkAttribute {
        attr_type: CkAttributeType::CLASS,
        value: Some(CkAttributeValue::Ulong(CkObjectClass::PUBLIC_KEY.0)),
    }];
    client
        .find_objects_init(session2, &pub_template)
        .await
        .map_err(|rv| format!("FindObjectsInit failed: {rv}"))?;
    let pub_keys = client
        .find_objects(session2, 32)
        .await
        .map_err(|rv| format!("FindObjects failed: {rv}"))?;
    client
        .find_objects_final(session2)
        .await
        .map_err(|rv| format!("FindObjectsFinal failed: {rv}"))?;
    for key in &pub_keys {
        let _ = client.destroy_object(session2, *key).await;
    }

    client.close_session(session2).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

// ── Item 82: Multi-token topology matrix ────────────────────────────

/// Verify that virtual slot IDs are stable sequential values (not backend raw IDs).
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn virtual_slot_ids_are_sequential() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm_multi_slot(4).await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slots = client.get_slot_list(true).await.map_err(|rv| rv.to_string())?;
    assert!(slots.len() >= 4, "expected >=4 slots, got {}", slots.len());

    // Virtual slot IDs should be small sequential values (daemon-assigned),
    // not necessarily matching the backend's raw slot numbers.
    let mut ids: Vec<u64> = slots.iter().map(|s| s.0).collect();
    ids.sort();
    // Check they start from a reasonable base and are densely packed.
    let range = ids.last().unwrap() - ids.first().unwrap();
    assert!(range < 100, "virtual slot IDs should be densely packed, got range {range}: {:?}", ids);

    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// Query token info for every slot — none should error.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn all_slots_return_valid_token_info() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm_multi_slot(3).await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slots = client.get_slot_list(true).await.map_err(|rv| rv.to_string())?;
    let mut initialized_count = 0;
    for &slot in &slots {
        let slot_info = client.get_slot_info(slot).await.map_err(|rv| rv.to_string())?;
        assert!(slot_info.flags.token_present(), "slot {:?} should have token present", slot);

        let token_info = client.get_token_info(slot).await.map_err(|rv| rv.to_string())?;
        // SoftHSM2 may include extra uninitialized slots.
        if !token_info.flags.token_initialized() {
            continue;
        }
        initialized_count += 1;

        assert!(
            !token_info.label.trim().is_empty(),
            "initialized slot {:?} token label should not be empty",
            slot
        );

        // Mechanism list should be available for every initialized slot.
        let mechs = client.get_mechanism_list(slot).await.map_err(|rv| rv.to_string())?;
        assert!(!mechs.is_empty(), "slot {:?} should have mechanisms", slot);
    }
    assert!(
        initialized_count >= 3,
        "expected at least 3 initialized tokens, got {initialized_count}"
    );

    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// Concurrent sessions on different slots with independent crypto.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn concurrent_sessions_on_different_slots() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm_multi_slot(3).await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slots = client.get_slot_list(true).await.map_err(|rv| rv.to_string())?;
    assert!(slots.len() >= 3);

    // Open sessions on all 3 slots simultaneously.
    let session_a = open_user_session(&mut client, slots[0], "1234", true).await?;
    let session_b = open_user_session(&mut client, slots[1], "1234", true).await?;
    let session_c = open_user_session(&mut client, slots[2], "1234", true).await?;

    // Generate keys on each slot.
    let (pub_a, priv_a) = generate_rsa_key_pair(&mut client, session_a, "topo-a", false).await?;
    let (pub_b, priv_b) = generate_rsa_key_pair(&mut client, session_b, "topo-b", false).await?;
    let (pub_c, priv_c) = generate_rsa_key_pair(&mut client, session_c, "topo-c", false).await?;

    // Sign and verify on each slot independently.
    let payload = b"multi-slot concurrent crypto test";
    let sig_a = rsa_sign_and_verify(&mut client, session_a, priv_a, pub_a, payload).await?;
    let sig_b = rsa_sign_and_verify(&mut client, session_b, priv_b, pub_b, payload).await?;
    let sig_c = rsa_sign_and_verify(&mut client, session_c, priv_c, pub_c, payload).await?;

    // Signatures from different keys should be different.
    assert_ne!(sig_a, sig_b, "signatures from different keys must differ");
    assert_ne!(sig_b, sig_c, "signatures from different keys must differ");
    assert_ne!(sig_a, sig_c, "signatures from different keys must differ");

    // Close all sessions.
    for session in [session_a, session_b, session_c] {
        client.logout(session).await.map_err(|rv| rv.to_string())?;
        client.close_session(session).await.map_err(|rv| rv.to_string())?;
    }

    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// CloseAllSessions clears all session handles in the client context.
///
/// Note: The current proxy implementation clears ALL session handles
/// per-context (not just the targeted slot), because per-slot filtering
/// of virtual handles is not yet implemented. This test verifies the
/// current behavior: after CloseAllSessions(slot_a), sessions on
/// slot_b must be reopened. A new session on the other slot works fine
/// because the backend sessions for that slot are still alive.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn close_all_sessions_clears_context_handles() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm_multi_slot(2).await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slots = client.get_slot_list(true).await.map_err(|rv| rv.to_string())?;
    assert!(slots.len() >= 2);

    let session_a = open_user_session(&mut client, slots[0], "1234", true).await?;
    let _session_b = open_user_session(&mut client, slots[1], "1234", true).await?;

    // Create objects to prove sessions work.
    create_data_object(&mut client, session_a, "slot-a-obj", b"a").await?;

    // Close all sessions on slot A.
    client.close_all_sessions(slots[0]).await.map_err(|rv| rv.to_string())?;

    // Session A handle should be invalid.
    let result = client.get_session_info(session_a).await;
    assert!(result.is_err(), "session on slot A should be invalid after CloseAllSessions");

    // Can reopen a session on slot B — the backend sessions there are fine.
    // Note: Don't use open_user_session because the user may still be logged in
    // at the backend level after CloseAllSessions cleared virtual handles.
    let flags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION | CkSessionFlags::RW_SESSION);
    let session_b2 = client
        .open_session(slots[1], flags)
        .await
        .map_err(|rv| format!("reopen slot B session failed: {rv}"))?;
    // Try login; ignore USER_ALREADY_LOGGED_IN since backend login state persists.
    match client.login(session_b2, CkUserType::User, Some(b"1234".as_ref())).await {
        Ok(()) => {}
        Err(rv) if rv == CkRv::USER_ALREADY_LOGGED_IN => {} // expected
        Err(rv) => return Err(format!("login on reopened slot B failed: {rv}")),
    }
    create_data_object(&mut client, session_b2, "slot-b-after", b"b").await?;
    let found = find_objects_by_label(&mut client, session_b2, "slot-b-after").await?;
    assert!(!found.is_empty(), "new session on slot B should work after CloseAllSessions(slot A)");

    client.close_session(session_b2).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

/// GetSlotList(false) returns all slots including empty ones.
/// GetSlotList(true) returns only slots with tokens present.
#[tokio::test]
#[ignore] // requires SoftHSM2
async fn get_slot_list_token_present_filter() -> Result<(), String> {
    let fixture = ProviderFixture::soft_hsm_multi_slot(2).await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let all_slots = client.get_slot_list(false).await.map_err(|rv| rv.to_string())?;
    let present_slots = client.get_slot_list(true).await.map_err(|rv| rv.to_string())?;

    // SoftHSM typically has all slots with tokens, so present >= all or equal.
    // The key assertion is that both calls succeed and return non-empty results.
    assert!(!all_slots.is_empty(), "all_slots should not be empty");
    assert!(!present_slots.is_empty(), "present_slots should not be empty");
    assert!(
        present_slots.len() <= all_slots.len(),
        "present slots ({}) should be <= all slots ({})",
        present_slots.len(),
        all_slots.len()
    );
    // Every present slot should also appear in the all list.
    for slot in &present_slots {
        assert!(all_slots.contains(slot), "present slot {:?} should be in all_slots", slot);
    }

    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}
