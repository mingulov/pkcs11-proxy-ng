use super::*;
use crate::server::handle_map::BackendHandle;

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
    assert!(mgr.remove_context(&id).await.is_some());
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
    mgr.remove_context(&id1).await;
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
    mgr.remove_context(&id1).await;
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
