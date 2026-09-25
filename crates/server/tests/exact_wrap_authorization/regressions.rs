use super::*;

#[tokio::test]
async fn class_denied_direct_objects_forward_zero_on_every_wrap_route() {
    let mut g = grant();
    g.classes = Some(vec!["CKO_SECRET_KEY".into()]);
    let f = fixture(g).await;
    let mut c = open(&f, false).await;
    let (denied, _) = mapped_object(&f, &c, CkObjectClass::PRIVATE_KEY, 0xd1).await;
    for route in ROUTES {
        for index in [0, 1] {
            let original = c.keys[index];
            c.keys[index] = denied;
            let before = f.backend.wrap_observations().len();
            f.backend.set_wrap_action(MockWrapAction::Return(CkRv::DEVICE_ERROR));
            assert_eq!(
                invoke(&mut c, route, mechanism(0), output_spec()).await.unwrap().rv,
                CkRv::DEVICE_ERROR.0
            );
            assert_eq!(f.backend.wrap_observations().len(), before + 1);
            let o = f.backend.wrap_observations().pop().unwrap();
            assert_eq!([o.wrapping_key, o.key][index], 0);
            c.keys[index] = original;
        }
    }
}

#[tokio::test]
async fn independent_extract_denial_precedes_zero_handle_provider_forwarding() {
    let mut g = grant();
    g.objects = Some(vec![
        ObjectAclSpec::Bare("b1".into()),
        ObjectAclSpec::Rich(ObjectAclRichConfig {
            id: "a1".into(),
            extract: Some(ExtractPolicyConfig::Deny),
        }),
    ]);
    let f = fixture(g).await;
    let mut c = open(&f, false).await;
    let (visibility_denied, _) = mapped_object(&f, &c, CkObjectClass::SECRET_KEY, 0xd1).await;
    let extraction_denied = c.keys[1];
    for route in ROUTES {
        for handle in [u64::MAX, extraction_denied] {
            c.keys[1] = handle;
            let before = f.backend.wrap_observations().len();
            assert_eq!(
                invoke(&mut c, route, mechanism(0), output_spec()).await.unwrap().rv,
                CkRv::KEY_FUNCTION_NOT_PERMITTED.0
            );
            assert_eq!(f.backend.wrap_observations().len(), before);
        }
        // Visibility denial alone still resolves a UID and inherits Allow;
        // the unknown UID above could conceal an explicit extraction override.
        c.keys[1] = visibility_denied;
        let before = f.backend.wrap_observations().len();
        f.backend.set_wrap_action(MockWrapAction::Return(CkRv::DEVICE_ERROR));
        assert_eq!(
            invoke(&mut c, route, mechanism(0), output_spec()).await.unwrap().rv,
            CkRv::DEVICE_ERROR.0
        );
        assert_eq!(f.backend.wrap_observations().len(), before + 1);
        assert_eq!(f.backend.wrap_observations().pop().unwrap().key, 0);
    }
}

#[tokio::test]
async fn foreign_authenticated_context_is_rejected_before_wrap_preparation() {
    let f = fixture(grant()).await;
    let mut c = open(&f, false).await;
    let other = open(&f, true).await;
    c.context = other.context;
    for route in ROUTES.into_iter().chain([Route::UnwrapAuthenticated]) {
        let result = invoke(&mut c, route, mechanism(0), output_spec()).await;
        assert!(matches!(result,Err(ref s) if s.code()==tonic::Code::PermissionDenied));
    }
    assert!(f.backend.wrap_observations().is_empty());
}

#[tokio::test]
async fn authenticated_wrap_aad_sanitation_is_local_after_shared_policy() {
    for sanitize in [false, true] {
        let backend = Arc::new(MockBackend::with_official_mechanisms(vec![CkSlotId(42)]));
        let f = mtls_fixture::start_mtls_daemon_with_audit(
            backend,
            [tokens(grant()), TokenAccessSpec::All("*".into())],
            None,
            sanitize,
        )
        .await;
        let mut c = open(&f, false).await;
        c.aad_null_len = Some(7);
        for route in [Route::Authenticated, Route::AuthenticatedExact, Route::UnwrapAuthenticated] {
            let before = f.backend.wrap_observations().len();
            assert_eq!(
                invoke(&mut c, route, mechanism(0), output_spec()).await.unwrap().rv,
                CkRv::ARGUMENTS_BAD.0
            );
            assert_eq!(f.backend.wrap_observations().len() - before, usize::from(!sanitize));
            if !sanitize {
                assert_eq!(f.backend.wrap_observations().pop().unwrap().aad, Some((false, 7)));
            }
        }
    }
    let mut g = grant();
    g.extract = ExtractPolicyConfig::Deny;
    let backend = Arc::new(MockBackend::with_official_mechanisms(vec![CkSlotId(42)]));
    let f = mtls_fixture::start_mtls_daemon_with_audit(
        backend,
        [tokens(g), TokenAccessSpec::All("*".into())],
        None,
        true,
    )
    .await;
    let mut c = open(&f, false).await;
    c.aad_null_len = Some(7);
    for route in [Route::Authenticated, Route::AuthenticatedExact] {
        assert_eq!(
            invoke(&mut c, route, mechanism(0), output_spec()).await.unwrap().rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0
        );
    }
    assert!(f.backend.wrap_observations().is_empty());
}

#[tokio::test]
async fn authenticated_unwrap_rejects_foreign_and_class_denied_embedded_handles() {
    let mut g = grant();
    g.classes = Some(vec!["CKO_SECRET_KEY".into()]);
    let f = fixture(g).await;
    let mut c = open(&f, false).await;
    let other = open(&f, true).await;
    mapped_object(&f, &other, CkObjectClass::SECRET_KEY, 0xe1).await;
    // The same integer cannot be used for the denied mapping in A or it would
    // accidentally turn the intended foreign case into an owned mapping.
    let (denied, _) = mapped_object(&f, &c, CkObjectClass::PRIVATE_KEY, 0xd1).await;
    let (foreign, _) = mapped_object(&f, &other, CkObjectClass::SECRET_KEY, 0xe2).await;
    assert_ne!(foreign, denied);
    for embedded in [foreign, denied, u64::MAX] {
        assert_eq!(
            invoke(&mut c, Route::UnwrapAuthenticated, mechanism(embedded), output_spec())
                .await
                .unwrap()
                .rv,
            CkRv::OBJECT_HANDLE_INVALID.0
        );
    }
    assert!(f.backend.wrap_observations().is_empty());
}
