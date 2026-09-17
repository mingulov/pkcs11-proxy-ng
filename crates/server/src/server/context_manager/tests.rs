use super::*;
use crate::server::handle_map::BackendHandle;

#[tokio::test]
async fn backend_slot_metadata_invalidation_does_not_touch_colliding_virtual_number() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let a = BackendSlotId(CkSlotId(42));
    let b = BackendSlotId(CkSlotId(1));
    mgr.register_slot(a).await;
    mgr.register_slot(b).await;
    assert_eq!(mgr.to_virtual_slot(a).await, Some(VirtualSlotId(1)));
    mgr.cache_token_info(a, "Token42".into(), "serial42".into());
    mgr.cache_token_info(b, "Token1".into(), "serial1".into());
    mgr.invalidate_token_info(a);
    assert_eq!(mgr.cached_token_info(a), None);
    assert_eq!(mgr.cached_token_info(b), Some(("Token1".into(), "serial1".into())));
}

#[test]
fn backend_slot_login_locks_share_only_the_same_backend_slot() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let a = mgr.slot_login_lock(BackendSlotId(CkSlotId(42)));
    let same = mgr.slot_login_lock(BackendSlotId(CkSlotId(42)));
    let other = mgr.slot_login_lock(BackendSlotId(CkSlotId(1)));
    assert!(Arc::ptr_eq(&a, &same));
    assert!(!Arc::ptr_eq(&a, &other));
}

#[test]
fn remove_sessions_for_backend_slot_preserves_other_slot_state() {
    let mut ctx = LogicalClientInstance::new(None);
    let a = BackendSlotId(CkSlotId(42));
    let b = BackendSlotId(CkSlotId(1));
    let sa = ctx.register_session(BackendHandle(101), a);
    let sb = ctx.register_session(BackendHandle(202), b);
    ctx.login_state.insert(a, LoginState::User);
    ctx.login_state.insert(b, LoginState::So);
    assert_eq!(ctx.remove_sessions_for_slot(a), vec![BackendHandle(101)]);
    assert_eq!(ctx.session_handles.resolve(sa), None);
    assert_eq!(ctx.session_handles.resolve(sb), Some(BackendHandle(202)));
    assert_eq!(ctx.session_slots.get(&sb), Some(&b));
    assert!(!ctx.login_state.contains_key(&a));
    assert_eq!(ctx.login_state.get(&b), Some(&LoginState::So));
}

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

#[tokio::test]
async fn operation_guard_identity_includes_its_manager() {
    let owner = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let other = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let context_id = owner.create_context(None).await.unwrap();
    let guard = owner.begin_operation(&context_id).expect("context exists");

    assert!(guard.belongs_to(&owner, &context_id));
    assert!(
        !guard.belongs_to(&other, &context_id),
        "the same context-id text in another manager must not reuse this guard",
    );
}

#[test]
fn token_info_cache_serves_within_ttl_and_expires_after() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    mgr.cache_token_info(
        crate::server::slot_map::BackendSlotId(CkSlotId(0)),
        "MockToken".into(),
        "SN1".into(),
    );
    assert_eq!(
        mgr.cached_token_info_within(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            std::time::Duration::from_secs(60)
        ),
        Some(("MockToken".to_string(), "SN1".to_string())),
        "a fresh entry must be served"
    );
    std::thread::sleep(std::time::Duration::from_millis(3));
    assert_eq!(
        mgr.cached_token_info_within(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            std::time::Duration::from_millis(1)
        ),
        None,
        "an entry older than the TTL must not be served"
    );
}

#[test]
fn invalidate_token_info_drops_the_entry() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    mgr.cache_token_info(
        crate::server::slot_map::BackendSlotId(CkSlotId(0)),
        "MockToken".into(),
        "SN1".into(),
    );
    mgr.invalidate_token_info(crate::server::slot_map::BackendSlotId(CkSlotId(0)));
    assert_eq!(mgr.cached_token_info(crate::server::slot_map::BackendSlotId(CkSlotId(0))), None);
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
        c.register_session(BackendHandle(100), crate::server::slot_map::BackendSlotId(CkSlotId(0)));
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
    ctx.login_state.insert(crate::server::slot_map::BackendSlotId(CkSlotId(1)), LoginState::User);
    ctx.login_state.insert(crate::server::slot_map::BackendSlotId(CkSlotId(2)), LoginState::So);
    let _ = ctx.teardown();
    assert!(ctx.login_state.is_empty());
}

#[test]
fn teardown_clears_message_operation_shapes() {
    let mut ctx = LogicalClientInstance::new(None);
    let session = ctx.session_handles.insert(BackendHandle(50));
    ctx.message_operations.insert(
        (session, MessageOperation::Encrypt),
        Arc::new(Mutex::new(MessageOperationState { shape: Some(MessageParameterShape::Gcm) })),
    );

    let _ = ctx.teardown();

    assert!(ctx.message_operations.is_empty());
}

#[test]
fn remove_session_evicts_only_its_message_operation_shapes() {
    let mut ctx = LogicalClientInstance::new(None);
    let session_a = ctx.session_handles.insert(BackendHandle(10));
    let session_b = ctx.session_handles.insert(BackendHandle(20));
    for session in [session_a, session_b] {
        ctx.message_operations.insert(
            (session, MessageOperation::Encrypt),
            Arc::new(Mutex::new(MessageOperationState { shape: Some(MessageParameterShape::Gcm) })),
        );
    }

    ctx.remove_session(session_a);

    assert!(!ctx.message_operations.contains_key(&(session_a, MessageOperation::Encrypt)));
    assert!(ctx.message_operations.contains_key(&(session_b, MessageOperation::Encrypt)));
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
    ctx.session_slots.insert(session, crate::server::slot_map::BackendSlotId(CkSlotId(7)));
    let obj = ctx.object_handles.insert(BackendHandle(111));
    ctx.record_session_object(session, obj);

    ctx.remove_sessions_for_slot(crate::server::slot_map::BackendSlotId(CkSlotId(7)));

    assert_eq!(ctx.object_handles.resolve(obj), None, "slot-close evicts session objects");
}

#[test]
fn remove_sessions_for_slot_evicts_only_target_message_operation_shapes() {
    let mut ctx = LogicalClientInstance::new(None);
    let target = ctx.session_handles.insert(BackendHandle(11));
    let other = ctx.session_handles.insert(BackendHandle(12));
    ctx.session_slots.insert(target, crate::server::slot_map::BackendSlotId(CkSlotId(7)));
    ctx.session_slots.insert(other, crate::server::slot_map::BackendSlotId(CkSlotId(8)));
    for session in [target, other] {
        ctx.message_operations.insert(
            (session, MessageOperation::Encrypt),
            Arc::new(Mutex::new(MessageOperationState { shape: Some(MessageParameterShape::Gcm) })),
        );
    }

    ctx.remove_sessions_for_slot(crate::server::slot_map::BackendSlotId(CkSlotId(7)));

    assert!(!ctx.message_operations.contains_key(&(target, MessageOperation::Encrypt)));
    assert!(ctx.message_operations.contains_key(&(other, MessageOperation::Encrypt)));
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
    mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(7))).await;
    let virtual_slot =
        mgr.to_virtual_slot(crate::server::slot_map::BackendSlotId(CkSlotId(7))).await;
    assert!(virtual_slot.is_some());
    let resolved_back = mgr.resolve_slot(virtual_slot.unwrap()).await;
    assert_eq!(resolved_back, Some(crate::server::slot_map::BackendSlotId(CkSlotId(7))));
}

#[tokio::test]
async fn virtual_slots_returns_all_registered() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(1))).await;
    mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(2))).await;
    mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(3))).await;
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
    ctx.login_state.insert(crate::server::slot_map::BackendSlotId(CkSlotId(1)), LoginState::User);
    ctx.login_state.insert(crate::server::slot_map::BackendSlotId(CkSlotId(2)), LoginState::So);
    assert_eq!(
        ctx.login_state.get(&crate::server::slot_map::BackendSlotId(CkSlotId(1))),
        Some(&LoginState::User)
    );
    assert_eq!(
        ctx.login_state.get(&crate::server::slot_map::BackendSlotId(CkSlotId(2))),
        Some(&LoginState::So)
    );
    assert_eq!(ctx.login_state.get(&crate::server::slot_map::BackendSlotId(CkSlotId(3))), None);
}

#[tokio::test]
async fn login_state_is_isolated_per_context() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let id1 = mgr.create_context(None).await.unwrap();
    let id2 = mgr.create_context(None).await.unwrap();
    mgr.get_context(&id1, |ctx| {
        ctx.login_state
            .insert(crate::server::slot_map::BackendSlotId(CkSlotId(0)), LoginState::User);
    })
    .await
    .unwrap();
    let state_in_ctx2 = mgr
        .get_context(&id2, |ctx| {
            ctx.login_state.get(&crate::server::slot_map::BackendSlotId(CkSlotId(0))).copied()
        })
        .await
        .unwrap();
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
        ctx.login_state
            .insert(crate::server::slot_map::BackendSlotId(CkSlotId(i as u64)), LoginState::User);
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

// --- per-object ObjectMetadata cache (G3, I2) ---

fn make_session_meta(uid: Vec<u8>) -> super::ObjectMetadata {
    super::ObjectMetadata {
        unique_id: uid.into(),
        class: Some(pkcs11_proxy_ng_types::CkObjectClass::SECRET_KEY),
        is_token: false,
    }
}

fn make_token_meta(uid: Vec<u8>) -> super::ObjectMetadata {
    super::ObjectMetadata {
        unique_id: uid.into(),
        class: Some(pkcs11_proxy_ng_types::CkObjectClass::SECRET_KEY),
        is_token: true,
    }
}

#[tokio::test]
async fn object_metadata_miss_returns_none() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let ctx_id = mgr.create_context(None).await.unwrap();
    assert_eq!(
        mgr.object_metadata(&ctx_id, 42).await.map(|m| m.unique_id),
        None,
        "a virtual object that was never cached must return None"
    );
}

#[tokio::test]
async fn object_metadata_session_object_round_trip() {
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let ctx_id = mgr.create_context(None).await.unwrap();
    let uid = vec![0xde, 0xad, 0xbe, 0xef];
    mgr.cache_object_metadata(&ctx_id, 7, make_session_meta(uid.clone())).await;
    assert_eq!(
        mgr.object_metadata(&ctx_id, 7).await.map(|m| m.unique_id),
        Some(SecretBytes::new(uid)),
        "a cached session-object metadata must be returned by object_metadata"
    );
}

#[tokio::test]
async fn object_metadata_token_object_not_cached() {
    // I2 fix: token objects (is_token=true) must never be stored in the cache.
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let ctx_id = mgr.create_context(None).await.unwrap();
    let uid = vec![0xde, 0xad, 0xbe, 0xef];
    mgr.cache_object_metadata(&ctx_id, 9, make_token_meta(uid)).await;
    assert_eq!(
        mgr.object_metadata(&ctx_id, 9).await.map(|m| m.unique_id),
        None,
        "token object metadata must not be cached (I2 fix: re-fetched every gate call)"
    );
}

#[tokio::test]
async fn object_metadata_evicted_on_session_close() {
    // When a virtual session closes, its session objects (and their cached
    // metadata) must be evicted so a recycled virtual handle cannot return
    // stale metadata (G3, B2).
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let ctx_id = mgr.create_context(None).await.unwrap();

    // Register a virtual session and a session object within it.
    let (session_vh, obj_vh) = mgr
        .get_context(&ctx_id, |ctx| {
            let s = ctx.session_handles.insert(BackendHandle(1));
            let o = ctx.object_handles.insert(BackendHandle(100));
            ctx.record_session_object(s, o);
            (s, o)
        })
        .await
        .unwrap();

    // Cache the metadata for the session object.
    mgr.cache_object_metadata(&ctx_id, obj_vh.0, make_session_meta(vec![1, 2, 3])).await;
    assert!(
        mgr.object_metadata(&ctx_id, obj_vh.0).await.is_some(),
        "metadata should be cached before session close"
    );

    // Close the session — its session objects are evicted.
    mgr.get_context(&ctx_id, |ctx| ctx.remove_session(session_vh)).await;

    assert_eq!(
        mgr.object_metadata(&ctx_id, obj_vh.0).await.map(|m| m.unique_id),
        None,
        "metadata must be evicted when the owning session closes"
    );
}

#[tokio::test]
async fn cache_object_metadata_noop_for_missing_context() {
    // Caching metadata for a non-existent context must not panic.
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let gone = ClientContextId("nonexistent".into());
    mgr.cache_object_metadata(&gone, 1, make_session_meta(vec![0xff])).await; // must not panic
    assert_eq!(mgr.object_metadata(&gone, 1).await.map(|m| m.unique_id), None);
}

// --- per-object attribute cache (R2 coalescer, Task 1) ---

fn make_cached_attr(value: Vec<u8>, rv: u64) -> super::CachedAttr {
    super::CachedAttr { value, ck_rv: rv }
}

#[tokio::test]
async fn attr_cache_put_then_get_round_trips() {
    // attr_cache_put followed by attr_cache_get must return an entry with the
    // exact same value bytes and ck_rv (R2, Task 1).
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let ctx_id = mgr.create_context(None).await.unwrap();
    let object: u64 = 42;
    let attr = CkAttributeType::CLASS;
    let entry = make_cached_attr(vec![0x03, 0x00, 0x00, 0x00], 0);

    mgr.attr_cache_put(&ctx_id, object, attr, entry.clone()).await;
    let result = mgr.attr_cache_get(&ctx_id, object, attr).await;

    let result = result.expect("a cached entry must be returned on a hit");
    assert_eq!(result.value, entry.value, "round-tripped value bytes must match");
    assert_eq!(result.ck_rv, entry.ck_rv, "round-tripped ck_rv must match");
}

#[tokio::test]
async fn attr_cache_miss_returns_none() {
    // A get for an object/attr pair that was never put must return None.
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let ctx_id = mgr.create_context(None).await.unwrap();
    let result = mgr.attr_cache_get(&ctx_id, 99, CkAttributeType::TOKEN).await;
    assert!(result.is_none(), "a cache miss must return None");
}

#[tokio::test]
async fn attr_cache_invalidate_object_drops_only_that_object() {
    // attr_cache_invalidate_object(O) must drop only entries whose key is O;
    // a different object's entries must remain (R2, Task 1).
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let ctx_id = mgr.create_context(None).await.unwrap();

    let obj_a: u64 = 10;
    let obj_b: u64 = 20;
    let attr = CkAttributeType::CLASS;

    mgr.attr_cache_put(&ctx_id, obj_a, attr, make_cached_attr(vec![1], 0)).await;
    mgr.attr_cache_put(&ctx_id, obj_b, attr, make_cached_attr(vec![2], 0)).await;

    mgr.attr_cache_invalidate_object(&ctx_id, obj_a).await;

    assert!(
        mgr.attr_cache_get(&ctx_id, obj_a, attr).await.is_none(),
        "invalidated object's entries must be gone"
    );
    assert!(
        mgr.attr_cache_get(&ctx_id, obj_b, attr).await.is_some(),
        "other object's entries must survive invalidate_object"
    );
}

#[test]
fn attr_cache_cleared_on_teardown() {
    // teardown() must clear attr_cache so no stale entries survive context
    // destruction (R2, Task 1).
    let mut ctx = LogicalClientInstance::new(None);
    let obj = VirtualHandle(55);
    let attr = CkAttributeType::CLASS;
    ctx.attr_cache.insert((obj, attr), super::CachedAttr { value: vec![0xff], ck_rv: 0 });
    let _ = ctx.teardown();
    assert!(ctx.attr_cache.is_empty(), "teardown must clear the attribute cache");
}

#[test]
fn attr_cache_evicted_on_session_close_via_remove_session() {
    // When remove_session() evicts a session object, that object's attr_cache
    // entries must also be evicted so a recycled virtual handle cannot serve
    // stale cached attributes (R2, Task 1, mirrors object_metadata eviction).
    let mut ctx = LogicalClientInstance::new(None);
    let session = ctx.session_handles.insert(BackendHandle(10));
    let obj = ctx.object_handles.insert(BackendHandle(100));
    ctx.record_session_object(session, obj);

    let attr = CkAttributeType::CLASS;
    ctx.attr_cache.insert((obj, attr), super::CachedAttr { value: vec![1, 2, 3], ck_rv: 0 });

    ctx.remove_session(session);

    assert!(
        !ctx.attr_cache.contains_key(&(obj, attr)),
        "attr_cache entries for a closed session's objects must be evicted"
    );
}

#[test]
fn attr_cache_evicted_on_session_close_via_remove_sessions_for_slot() {
    // When remove_sessions_for_slot() evicts session objects, their attr_cache
    // entries must also be evicted (R2, Task 1).
    let mut ctx = LogicalClientInstance::new(None);
    let session = ctx.session_handles.insert(BackendHandle(11));
    ctx.session_slots.insert(session, crate::server::slot_map::BackendSlotId(CkSlotId(7)));
    let obj = ctx.object_handles.insert(BackendHandle(111));
    ctx.record_session_object(session, obj);

    let attr = CkAttributeType::TOKEN;
    ctx.attr_cache.insert((obj, attr), super::CachedAttr { value: vec![0x01], ck_rv: 0 });

    ctx.remove_sessions_for_slot(crate::server::slot_map::BackendSlotId(CkSlotId(7)));

    assert!(
        !ctx.attr_cache.contains_key(&(obj, attr)),
        "attr_cache entries evicted by remove_sessions_for_slot"
    );
}

#[tokio::test]
async fn attr_cache_put_noop_for_missing_context() {
    // attr_cache_put on a gone context must not panic.
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let gone = ClientContextId("nonexistent".into());
    mgr.attr_cache_put(&gone, 1, CkAttributeType::CLASS, make_cached_attr(vec![0xff], 0)).await; // must not panic
    assert!(mgr.attr_cache_get(&gone, 1, CkAttributeType::CLASS).await.is_none());
}

#[tokio::test]
async fn attr_cache_clear_empties_all_entries_for_context() {
    // C1: attr_cache_clear must drop ALL entries for the target context, leaving
    // other contexts' entries untouched (used by the C_Logout handler).
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let ctx_a = mgr.create_context(None).await.unwrap();
    let ctx_b = mgr.create_context(None).await.unwrap();

    // Populate ctx_a with two attrs across two different objects.
    mgr.attr_cache_put(&ctx_a, 10, CkAttributeType::CLASS, make_cached_attr(vec![1], 0)).await;
    mgr.attr_cache_put(&ctx_a, 20, CkAttributeType::TOKEN, make_cached_attr(vec![1], 0)).await;
    // Populate ctx_b with one attr (must survive ctx_a's clear).
    mgr.attr_cache_put(&ctx_b, 10, CkAttributeType::CLASS, make_cached_attr(vec![2], 0)).await;

    // Clear ctx_a's entire cache.
    mgr.attr_cache_clear(&ctx_a).await;

    // ctx_a's entries must be gone.
    assert!(
        mgr.attr_cache_get(&ctx_a, 10, CkAttributeType::CLASS).await.is_none(),
        "attr_cache_clear must remove all entries for ctx_a (object 10)"
    );
    assert!(
        mgr.attr_cache_get(&ctx_a, 20, CkAttributeType::TOKEN).await.is_none(),
        "attr_cache_clear must remove all entries for ctx_a (object 20)"
    );

    // ctx_b's entry must be untouched.
    assert!(
        mgr.attr_cache_get(&ctx_b, 10, CkAttributeType::CLASS).await.is_some(),
        "attr_cache_clear for ctx_a must not affect ctx_b's entries"
    );
}

#[tokio::test]
async fn attr_cache_clear_noop_for_missing_context() {
    // attr_cache_clear on a non-existent context must not panic (no-op).
    let mgr = ContextManager::new(std::time::Duration::from_secs(300), 0);
    let gone = ClientContextId("nonexistent".into());
    mgr.attr_cache_clear(&gone).await; // must not panic
}

#[tokio::test]
async fn message_transition_restores_shape_when_dropped_before_provider_invocation() {
    let state =
        Arc::new(Mutex::new(MessageOperationState { shape: Some(MessageParameterShape::Gcm) }));

    let guard = Arc::clone(&state).lock_owned().await;
    drop(MessageOperationTransition::begin(guard));

    assert_eq!(state.lock().await.shape, Some(MessageParameterShape::Gcm));
}

#[tokio::test]
async fn message_transition_commits_success_and_restores_explicit_failure() {
    let state =
        Arc::new(Mutex::new(MessageOperationState { shape: Some(MessageParameterShape::Gcm) }));

    {
        let guard = Arc::clone(&state).lock_owned().await;
        let mut transition = MessageOperationTransition::begin(guard);
        transition.mark_started();
        transition.settle(&Ok(()), Some(MessageParameterShape::Ccm));
    }
    assert_eq!(state.lock().await.shape, Some(MessageParameterShape::Ccm));

    {
        let guard = Arc::clone(&state).lock_owned().await;
        let mut transition = MessageOperationTransition::begin(guard);
        transition.mark_started();
        transition.settle::<()>(&Err(CkRv::FUNCTION_FAILED), None);
    }
    assert_eq!(state.lock().await.shape, Some(MessageParameterShape::Ccm));
}

#[tokio::test]
async fn message_transition_clears_shape_when_provider_panics_after_invocation() {
    let state =
        Arc::new(Mutex::new(MessageOperationState { shape: Some(MessageParameterShape::Gcm) }));

    let guard = Arc::clone(&state).lock_owned().await;
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut transition = MessageOperationTransition::begin(guard);
        transition.mark_started();
        panic!("simulated provider panic");
    }));

    assert!(unwind.is_err());
    assert_eq!(state.lock().await.shape, None);
}

#[tokio::test]
async fn message_transition_clears_shape_for_ambiguous_provider_result() {
    let state =
        Arc::new(Mutex::new(MessageOperationState { shape: Some(MessageParameterShape::Gcm) }));

    {
        let guard = Arc::clone(&state).lock_owned().await;
        let mut transition = MessageOperationTransition::begin(guard);
        transition.mark_started();
        transition.settle_ambiguous();
    }

    assert_eq!(state.lock().await.shape, None);
}

#[tokio::test]
async fn close_transition_drop_before_invocation_reactivates_session() {
    let mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let ctx_id = mgr.create_context(None).await.unwrap();
    let backend = BackendHandle(77);
    let session = mgr
        .get_context(&ctx_id, |ctx| {
            ctx.register_session(backend, crate::server::slot_map::BackendSlotId(CkSlotId(1)))
        })
        .await
        .unwrap();

    let transition = mgr.begin_close_session(&ctx_id, session).unwrap();
    assert_eq!(transition.backend_handle(), backend);
    assert_eq!(
        mgr.get_context(&ctx_id, |ctx| ctx.session_handles.resolve(session)).await,
        Some(None)
    );
    drop(transition);

    assert_eq!(
        mgr.get_context(&ctx_id, |ctx| ctx.session_handles.resolve(session)).await,
        Some(Some(backend))
    );
}

#[tokio::test]
async fn close_transition_terminal_result_removes_session_and_shapes() {
    let mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let ctx_id = mgr.create_context(None).await.unwrap();
    let backend = BackendHandle(77);
    let session = mgr
        .get_context(&ctx_id, |ctx| {
            ctx.register_session(backend, crate::server::slot_map::BackendSlotId(CkSlotId(1)))
        })
        .await
        .unwrap();
    let operation =
        mgr.message_operation_lock(&ctx_id, session, MessageOperation::Encrypt).await.unwrap();
    operation.lock().await.shape = Some(MessageParameterShape::Gcm);

    let mut transition = mgr.begin_close_session(&ctx_id, session).unwrap();
    transition.mark_started();
    transition.settle(&Ok(()));

    let state = mgr
        .get_context(&ctx_id, |ctx| {
            (
                ctx.session_handles.resolve(session),
                ctx.session_handles.suspended_backend(session),
                ctx.message_operations.keys().any(|(owned_session, _)| *owned_session == session),
            )
        })
        .await
        .unwrap();
    assert_eq!(state, (None, None, false));
}

#[tokio::test]
async fn close_transition_panic_after_invocation_quarantines_session_and_clears_shapes() {
    let mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let ctx_id = mgr.create_context(None).await.unwrap();
    let backend = BackendHandle(77);
    let session = mgr
        .get_context(&ctx_id, |ctx| {
            ctx.register_session(backend, crate::server::slot_map::BackendSlotId(CkSlotId(1)))
        })
        .await
        .unwrap();
    let operation =
        mgr.message_operation_lock(&ctx_id, session, MessageOperation::Encrypt).await.unwrap();
    operation.lock().await.shape = Some(MessageParameterShape::Gcm);

    let mut transition = mgr.begin_close_session(&ctx_id, session).unwrap();
    transition.mark_started();
    drop(transition);

    let state = mgr
        .get_context(&ctx_id, |ctx| {
            (
                ctx.session_handles.resolve(session),
                ctx.session_handles.suspended_backend(session),
                ctx.message_operations.keys().any(|(owned_session, _)| *owned_session == session),
            )
        })
        .await
        .unwrap();
    assert_eq!(state, (None, Some(backend), false));
}

#[tokio::test]
async fn transient_old_close_completion_cannot_steal_recycled_session_binding() {
    let mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let ctx_id = mgr.create_context(None).await.unwrap();
    let backend = BackendHandle(77);
    let old = mgr
        .get_context(&ctx_id, |ctx| {
            ctx.register_session(backend, crate::server::slot_map::BackendSlotId(CkSlotId(1)))
        })
        .await
        .unwrap();
    let mut transition = mgr.begin_close_session(&ctx_id, old).unwrap();
    transition.mark_started();

    let new = mgr
        .get_context(&ctx_id, |ctx| {
            ctx.register_session(backend, crate::server::slot_map::BackendSlotId(CkSlotId(1)))
        })
        .await
        .unwrap();
    assert_ne!(new, old);
    transition.settle(&Err(CkRv::FUNCTION_FAILED));

    let state = mgr
        .get_context(&ctx_id, |ctx| {
            (
                ctx.session_handles.resolve(old),
                ctx.session_handles.suspended_backend(old),
                ctx.session_handles.resolve(new),
                ctx.session_handles.resolve_backend(backend),
            )
        })
        .await
        .unwrap();
    assert_eq!(state, (None, Some(backend), Some(backend), Some(new)));
}

#[tokio::test]
async fn terminal_old_close_completion_cannot_remove_recycled_session_binding() {
    let mgr = Arc::new(ContextManager::new(std::time::Duration::from_secs(300), 0));
    let ctx_id = mgr.create_context(None).await.unwrap();
    let backend = BackendHandle(77);
    let old = mgr
        .get_context(&ctx_id, |ctx| {
            ctx.register_session(backend, crate::server::slot_map::BackendSlotId(CkSlotId(1)))
        })
        .await
        .unwrap();
    let mut transition = mgr.begin_close_session(&ctx_id, old).unwrap();
    transition.mark_started();

    let new = mgr
        .get_context(&ctx_id, |ctx| {
            ctx.register_session(backend, crate::server::slot_map::BackendSlotId(CkSlotId(1)))
        })
        .await
        .unwrap();
    assert_ne!(new, old);
    transition.settle(&Ok(()));

    let state = mgr
        .get_context(&ctx_id, |ctx| {
            (
                ctx.session_handles.resolve(old),
                ctx.session_handles.suspended_backend(old),
                ctx.session_handles.resolve(new),
                ctx.session_handles.resolve_backend(backend),
            )
        })
        .await
        .unwrap();
    assert_eq!(state, (None, None, Some(backend), Some(new)));
}
