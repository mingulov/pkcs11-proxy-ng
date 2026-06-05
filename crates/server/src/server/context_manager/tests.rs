use super::*;
use crate::server::handle_map::BackendHandle;

#[tokio::test]
async fn begin_operation_capped_enforces_the_per_context_limit() {
    // M2: a context can hold at most `max_in_flight` concurrent operations; the
    // next is rejected (Err) so one client cannot drain the shared budget. A
    // freed slot allows a new op, and a missing context yields Ok(None).
    let mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let ctx = mgr.create_context(None).await.unwrap();
    let cap = 3;
    let mut guards = Vec::new();
    for _ in 0..cap {
        guards.push(
            mgr.begin_operation_capped(&ctx, cap).expect("under cap").expect("context exists"),
        );
    }
    assert!(mgr.begin_operation_capped(&ctx, cap).is_err(), "must reject at the per-context cap");

    guards.pop(); // free one in-flight slot
    assert!(mgr.begin_operation_capped(&ctx, cap).is_ok(), "a freed slot must allow a new op");

    let gone = ClientContextId("nonexistent".into());
    assert!(
        matches!(mgr.begin_operation_capped(&gone, cap), Ok(None)),
        "a missing context yields Ok(None), not a cap rejection"
    );
}

#[test]
fn token_info_cache_serves_within_ttl_and_expires_after() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    mgr.cache_token_info(CkSlotId(0), "MockToken".into(), "SN1".into());
    assert_eq!(
        mgr.cached_token_info_within(CkSlotId(0), std::time::Duration::from_secs(60)),
        Some(("MockToken".to_string(), "SN1".to_string())),
        "a fresh entry must be served"
    );
    std::thread::sleep(std::time::Duration::from_millis(3));
    assert_eq!(
        mgr.cached_token_info_within(CkSlotId(0), std::time::Duration::from_millis(1)),
        None,
        "an entry older than the TTL must not be served"
    );
}

#[test]
fn invalidate_token_info_drops_the_entry() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    mgr.cache_token_info(CkSlotId(0), "MockToken".into(), "SN1".into());
    mgr.invalidate_token_info(CkSlotId(0));
    assert_eq!(mgr.cached_token_info(CkSlotId(0)), None);
}

#[tokio::test]
async fn capacity_eviction_skips_contexts_with_open_backend_sessions() {
    // M4: the inline capacity-eviction path must NOT drop an expired context
    // that still holds open backend sessions — it cannot close them (no backend
    // ref here), so doing so would leak them. Those are left to the background
    // reaper (evict_expired), which closes them properly. At capacity with only
    // such a context present, creation is rejected rather than leaking.
    let mgr = ContextManager::new(std::time::Duration::from_millis(1), 1);
    let ctx_a = mgr.create_context(None).await.unwrap();
    mgr.get_context(&ctx_a, |c| {
        c.register_session(BackendHandle(100), CkSlotId(0));
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await; // expire ctx_a

    let result = mgr.create_context(None).await;
    assert!(result.is_err(), "must not inline-evict a context with open backend sessions");
    assert!(
        mgr.get_context(&ctx_a, |_| ()).await.is_some(),
        "ctx_a with an open backend session must survive inline capacity-eviction"
    );
}

#[tokio::test]
async fn capacity_eviction_reclaims_sessionless_expired_contexts() {
    // A sessionless expired context leaks nothing, so it IS reclaimed inline to
    // make room (M4).
    let mgr = ContextManager::new(std::time::Duration::from_millis(1), 1);
    let ctx_a = mgr.create_context(None).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await; // expire ctx_a

    let ctx_b = mgr.create_context(None).await;
    assert!(ctx_b.is_ok(), "a sessionless expired context must be inline-reclaimed");
    assert!(
        mgr.get_context(&ctx_a, |_| ()).await.is_none(),
        "the sessionless expired context should be evicted"
    );
}

#[tokio::test]
async fn create_and_get_context() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let id = mgr.create_context(None).await.unwrap();
    let result = mgr.get_context(&id, |ctx| ctx.id.clone()).await;
    assert_eq!(result, Some(id));
}

#[tokio::test]
async fn unknown_context_returns_none() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let fake = ClientContextId("nonexistent".into());
    assert!(mgr.get_context(&fake, |_| ()).await.is_none());
}

#[tokio::test]
async fn remove_context() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let id = mgr.create_context(None).await.unwrap();
    assert!(mgr.remove_context(&id).is_some());
    assert!(mgr.get_context(&id, |_| ()).await.is_none());
}

#[test]
fn teardown_collects_backend_sessions() {
    let mut ctx = LogicalClientInstance::new(None);
    ctx.session_handles.insert(BackendHandle(100));
    ctx.session_handles.insert(BackendHandle(200));
    let sessions = ctx.teardown();
    assert_eq!(sessions.len(), 2);
    assert!(sessions.contains(&100));
    assert!(sessions.contains(&200));
}

#[test]
fn teardown_with_no_sessions_returns_empty() {
    let mut ctx = LogicalClientInstance::new(None);
    let sessions = ctx.teardown();
    assert!(sessions.is_empty());
}

#[test]
fn teardown_clears_session_handles() {
    let mut ctx = LogicalClientInstance::new(None);
    let virt = ctx.session_handles.insert(BackendHandle(50));
    let _ = ctx.teardown();
    assert_eq!(ctx.session_handles.resolve(virt), None);
}

#[test]
fn teardown_clears_object_handles() {
    let mut ctx = LogicalClientInstance::new(None);
    let virt = ctx.object_handles.insert(BackendHandle(77));
    let _ = ctx.teardown();
    assert_eq!(ctx.object_handles.resolve(virt), None);
}

#[test]
fn teardown_clears_login_state() {
    let mut ctx = LogicalClientInstance::new(None);
    ctx.login_state.insert(CkSlotId(1), LoginState::User);
    ctx.login_state.insert(CkSlotId(2), LoginState::So);
    let _ = ctx.teardown();
    assert!(ctx.login_state.is_empty());
}

#[test]
fn remove_session_evicts_only_its_recorded_session_objects() {
    // B2: closing a session evicts the session objects recorded under it, but
    // leaves other sessions' objects (and unrecorded token objects) intact.
    let mut ctx = LogicalClientInstance::new(None);
    let session_a = ctx.session_handles.insert(BackendHandle(10));
    let session_b = ctx.session_handles.insert(BackendHandle(20));

    let sess_obj_a = ctx.object_handles.insert(BackendHandle(100));
    let sess_obj_b = ctx.object_handles.insert(BackendHandle(200));
    let token_obj = ctx.object_handles.insert(BackendHandle(300)); // not recorded
    ctx.record_session_object(session_a, sess_obj_a);
    ctx.record_session_object(session_b, sess_obj_b);

    ctx.remove_session(session_a);

    assert_eq!(ctx.object_handles.resolve(sess_obj_a), None, "A's session object evicted");
    assert_eq!(
        ctx.object_handles.resolve(sess_obj_b),
        Some(BackendHandle(200)),
        "B's session object untouched"
    );
    assert_eq!(
        ctx.object_handles.resolve(token_obj),
        Some(BackendHandle(300)),
        "unrecorded (token) object persists"
    );
}

#[test]
fn remove_sessions_for_slot_evicts_their_session_objects() {
    let mut ctx = LogicalClientInstance::new(None);
    let session = ctx.session_handles.insert(BackendHandle(11));
    ctx.session_slots.insert(session, CkSlotId(7));
    let obj = ctx.object_handles.insert(BackendHandle(111));
    ctx.record_session_object(session, obj);

    ctx.remove_sessions_for_slot(CkSlotId(7));

    assert_eq!(ctx.object_handles.resolve(obj), None, "slot-close evicts session objects");
}

#[test]
fn session_and_object_handle_spaces_are_independent() {
    let mut ctx = LogicalClientInstance::new(None);
    let svirt = ctx.session_handles.insert(BackendHandle(1));
    let ovirt = ctx.object_handles.insert(BackendHandle(1));
    assert_eq!(ctx.session_handles.resolve(svirt), Some(BackendHandle(1)));
    assert_eq!(ctx.object_handles.resolve(ovirt), Some(BackendHandle(1)));
    assert_eq!(ctx.session_handles.resolve(ovirt), ctx.object_handles.resolve(svirt));
}

#[test]
fn identity_is_stored_on_context() {
    let ctx = LogicalClientInstance::new(Some("alice".into()));
    assert_eq!(ctx.authenticated_identity, Some("alice".to_string()));
}

#[test]
fn context_without_identity_has_none() {
    let ctx = LogicalClientInstance::new(None);
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn multiple_contexts_are_isolated() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let id1 = mgr.create_context(None).await.unwrap();
    let id2 = mgr.create_context(None).await.unwrap();
    let virt =
        mgr.get_context(&id1, |ctx| ctx.session_handles.insert(BackendHandle(42))).await.unwrap();
    let resolved_in_ctx2 =
        mgr.get_context(&id2, |ctx| ctx.session_handles.resolve(virt)).await.unwrap();
    assert_eq!(resolved_in_ctx2, None);
}

#[tokio::test]
async fn remove_context_removes_exactly_one() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let id1 = mgr.create_context(None).await.unwrap();
    let id2 = mgr.create_context(None).await.unwrap();
    mgr.remove_context(&id1);
    assert!(mgr.get_context(&id1, |_| ()).await.is_none());
    assert!(mgr.get_context(&id2, |_| ()).await.is_some());
}

#[tokio::test]
async fn evict_expired_removes_stale_context() {
    use pkcs11_proxy_ng_backend::MockBackend;
    use pkcs11_proxy_ng_types::CkMechanismType;

    let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> =
        Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
    let mgr = ContextManager::new(std::time::Duration::from_secs(0), 0);
    let id = mgr.create_context(None).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    let evicted = mgr.evict_expired(&backend).await;
    assert!(evicted.contains(&id));
    assert!(mgr.get_context(&id, |_| ()).await.is_none());
}

#[tokio::test]
async fn evict_expired_keeps_recently_active_context() {
    use pkcs11_proxy_ng_backend::MockBackend;
    use pkcs11_proxy_ng_types::CkMechanismType;

    let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> =
        Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let id = mgr.create_context(None).await.unwrap();
    let evicted = mgr.evict_expired(&backend).await;
    assert!(!evicted.contains(&id));
    assert!(mgr.get_context(&id, |_| ()).await.is_some());
}

#[tokio::test]
async fn evict_expired_skips_context_with_in_flight_operation() {
    use pkcs11_proxy_ng_backend::MockBackend;
    use pkcs11_proxy_ng_types::CkMechanismType;

    let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> =
        Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
    // Zero lease: the context is "expired" the instant any time elapses, so this
    // isolates the in-flight guard as the only thing keeping it alive.
    let mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(0), 0));
    let id = mgr.create_context(None).await.unwrap();

    // Long backend op in flight → must NOT be reaped mid-call (the bug this fixes:
    // DH/RSA keygen longer than the lease was evicted out from under itself).
    let guard = mgr.begin_operation(&id).expect("context exists");
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let evicted = mgr.evict_expired(&backend).await;
    assert!(!evicted.contains(&id), "in-flight context must not be evicted mid-call");
    assert!(mgr.get_context(&id, |_| ()).await.is_some());

    // Once the op finishes, the context is reapable again.
    drop(guard);
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let evicted = mgr.evict_expired(&backend).await;
    assert!(evicted.contains(&id), "context reapable after the in-flight op ends");
}

#[tokio::test]
async fn slot_registration_and_resolution() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    mgr.register_slot(CkSlotId(7)).await;
    let virtual_slot = mgr.to_virtual_slot(CkSlotId(7)).await;
    assert!(virtual_slot.is_some());
    let resolved_back = mgr.resolve_slot(virtual_slot.unwrap()).await;
    assert_eq!(resolved_back, Some(CkSlotId(7)));
}

#[tokio::test]
async fn virtual_slots_returns_all_registered() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    mgr.register_slot(CkSlotId(1)).await;
    mgr.register_slot(CkSlotId(2)).await;
    mgr.register_slot(CkSlotId(3)).await;
    let slots = mgr.virtual_slots().await;
    assert_eq!(slots.len(), 3);
}

#[tokio::test]
async fn identity_stored_in_context() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let id = mgr.create_context(Some("carol".into())).await.unwrap();
    let identity = mgr.get_context(&id, |ctx| ctx.authenticated_identity.clone()).await.unwrap();
    assert_eq!(identity, Some("carol".into()));
}

#[test]
fn login_state_defaults_to_empty() {
    let ctx = LogicalClientInstance::new(None);
    assert!(ctx.login_state.is_empty(), "new context starts with no login state");
}

#[test]
fn login_state_can_be_set_and_read_per_slot() {
    let mut ctx = LogicalClientInstance::new(None);
    ctx.login_state.insert(CkSlotId(1), LoginState::User);
    ctx.login_state.insert(CkSlotId(2), LoginState::So);
    assert_eq!(ctx.login_state.get(&CkSlotId(1)), Some(&LoginState::User));
    assert_eq!(ctx.login_state.get(&CkSlotId(2)), Some(&LoginState::So));
    assert_eq!(ctx.login_state.get(&CkSlotId(3)), None);
}

#[tokio::test]
async fn login_state_is_isolated_per_context() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let id1 = mgr.create_context(None).await.unwrap();
    let id2 = mgr.create_context(None).await.unwrap();
    mgr.get_context(&id1, |ctx| {
        ctx.login_state.insert(CkSlotId(0), LoginState::User);
    })
    .await
    .unwrap();
    let state_in_ctx2 =
        mgr.get_context(&id2, |ctx| ctx.login_state.get(&CkSlotId(0)).copied()).await.unwrap();
    assert_eq!(state_in_ctx2, None, "ctx2 must not see ctx1 login state");
}

#[test]
fn login_state_variants_are_distinct() {
    assert_ne!(LoginState::Public, LoginState::User);
    assert_ne!(LoginState::Public, LoginState::So);
    assert_ne!(LoginState::User, LoginState::So);
}

#[test]
fn teardown_clears_login_state_for_all_slots() {
    let mut ctx = LogicalClientInstance::new(None);
    for i in 0..5 {
        ctx.login_state.insert(CkSlotId(i), LoginState::User);
    }
    let _ = ctx.teardown();
    assert!(ctx.login_state.is_empty(), "teardown must clear all per-slot login state");
}

#[test]
fn virtual_session_handle_not_visible_after_teardown() {
    let mut ctx = LogicalClientInstance::new(None);
    let virt = ctx.session_handles.insert(BackendHandle(10));
    let _ = ctx.teardown();
    assert_eq!(
        ctx.session_handles.resolve(virt),
        None,
        "teardown must invalidate virtual session handles"
    );
}

#[test]
fn virtual_object_handle_not_visible_after_teardown() {
    let mut ctx = LogicalClientInstance::new(None);
    let virt = ctx.object_handles.insert(BackendHandle(20));
    let _ = ctx.teardown();
    assert_eq!(
        ctx.object_handles.resolve(virt),
        None,
        "teardown must invalidate virtual object handles"
    );
}

#[tokio::test]
async fn virtual_handles_from_removed_context_invisible_in_other_context() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let id1 = mgr.create_context(None).await.unwrap();
    let id2 = mgr.create_context(None).await.unwrap();
    let virt =
        mgr.get_context(&id1, |ctx| ctx.session_handles.insert(BackendHandle(99))).await.unwrap();
    mgr.remove_context(&id1);
    let resolved = mgr.get_context(&id2, |ctx| ctx.session_handles.resolve(virt)).await.unwrap();
    assert_eq!(resolved, None, "removed context handles must not bleed into other contexts");
}

#[tokio::test]
async fn concurrent_context_creation_all_unique() {
    let mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let m = mgr.clone();
        tasks.push(tokio::spawn(async move { m.create_context(None).await.unwrap() }));
    }
    let mut ids = Vec::new();
    for t in tasks {
        ids.push(t.await.unwrap());
    }
    let mut deduped = ids.clone();
    deduped.sort_by(|a, b| a.0.cmp(&b.0));
    deduped.dedup_by(|a, b| a.0 == b.0);
    assert_eq!(deduped.len(), 20, "all context IDs must be unique");
}

#[tokio::test]
async fn concurrent_get_context_from_multiple_readers() {
    let mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let id = mgr.create_context(Some("shared".into())).await.unwrap();
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let m = mgr.clone();
        let id_clone = ClientContextId(id.0.clone());
        tasks.push(tokio::spawn(async move {
            m.get_context(&id_clone, |ctx| ctx.authenticated_identity.clone()).await
        }));
    }
    for t in tasks {
        let result = t.await.unwrap();
        assert_eq!(result, Some(Some("shared".to_string())));
    }
}

#[tokio::test]
async fn evict_expired_concurrent_with_new_context_creation() {
    use pkcs11_proxy_ng_backend::MockBackend;

    let backend: Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend> =
        Arc::new(MockBackend::default_test());
    let mgr = Arc::new(ContextManager::new(std::time::Duration::from_millis(1), 0));
    let mgr_clone = mgr.clone();
    let backend_clone = backend.clone();
    let evict_task = tokio::spawn(async move {
        for _ in 0..50 {
            mgr_clone.evict_expired(&backend_clone).await;
            tokio::task::yield_now().await;
        }
    });
    for _ in 0..50 {
        let _ = mgr.create_context(None).await;
        tokio::task::yield_now().await;
    }
    evict_task.await.unwrap();
}

#[test]
fn teardown_returns_correct_backend_session_handles() {
    let mut ctx = LogicalClientInstance::new(None);
    ctx.session_handles.insert(BackendHandle(5));
    ctx.session_handles.insert(BackendHandle(7));
    ctx.session_handles.insert(BackendHandle(9));
    let backend_handles = ctx.teardown();
    let mut sorted = backend_handles.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        vec![5, 7, 9],
        "teardown must return backend session handles for caller to close"
    );
}
