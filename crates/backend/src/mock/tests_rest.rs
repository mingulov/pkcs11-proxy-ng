#[test]
fn finalize_with_open_sessions_clears_all() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let s1 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let s2 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert!(backend.get_session_info(s1).is_ok());
    assert!(backend.get_session_info(s2).is_ok());
    backend.finalize().unwrap();
    backend.initialize().unwrap();
    assert_eq!(backend.get_session_info(s1).unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
    assert_eq!(backend.get_session_info(s2).unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
}

#[test]
fn reinitialize_produces_fresh_handle_space() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let s_old = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    backend.finalize().unwrap();
    backend.initialize().unwrap();
    let s_new = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert!(backend.get_session_info(s_new).is_ok());
    assert_eq!(backend.get_session_info(s_old).unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
}

#[test]
fn close_all_sessions_clears_login_state_for_slot() {
    let backend = MockBackend::new(vec![CkSlotId(0), CkSlotId(1)], vec![CkMechanismType::RSA_PKCS]);
    backend.initialize().unwrap();
    let rw = CkSessionFlags(CkSessionFlags::RW_SESSION);
    let s0a = backend.open_session(CkSlotId(0), rw).unwrap();
    let s0b = backend.open_session(CkSlotId(0), rw).unwrap();
    let s1 = backend.open_session(CkSlotId(1), rw).unwrap();
    backend.login(s0a, CkUserType::User, Some(b"pin".as_ref())).unwrap();
    backend.close_all_sessions(CkSlotId(0)).unwrap();
    assert_eq!(backend.get_session_info(s0a).unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
    assert_eq!(backend.get_session_info(s0b).unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
    assert!(backend.get_session_info(s1).is_ok());
    let s0c = backend.open_session(CkSlotId(0), rw).unwrap();
    assert_eq!(backend.get_session_info(s0c).unwrap().state, CkSessionState::RwPublic);
    assert_eq!(backend.get_session_info(s1).unwrap().state, CkSessionState::RwPublic);
}

#[test]
fn create_object_returns_live_handle() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let obj = backend.create_object(session, &[]).unwrap();
    assert!(backend.get_object_size(session, obj).is_ok());
}

#[test]
fn destroy_object_invalidates_handle() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let obj = backend.create_object(session, &[]).unwrap();
    backend.destroy_object(session, obj).unwrap();
    assert_eq!(backend.destroy_object(session, obj).unwrap_err(), CkRv::OBJECT_HANDLE_INVALID);
    assert_eq!(backend.get_object_size(session, obj).unwrap_err(), CkRv::OBJECT_HANDLE_INVALID);
}

#[test]
fn destroy_object_with_unknown_handle_returns_error() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(
        backend.destroy_object(session, CkObjectHandle(9999)).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
}

#[test]
fn get_object_size_unknown_handle_returns_error() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(
        backend.get_object_size(session, CkObjectHandle(42)).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
}

#[test]
fn get_attribute_value_exact_unknown_handle_returns_error() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let query = CkAttributeQuery {
        attr_type: CkAttributeType::LABEL,
        buffer_present: false,
        buffer_len: 0,
        nested: None,
    };
    assert_eq!(
        backend
            .get_attribute_value_exact(session, CkObjectHandle(42), &[query])
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
}

#[test]
fn set_attribute_value_unknown_handle_returns_error() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(
        backend.set_attribute_value(session, CkObjectHandle(42), &[]).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
}

#[test]
fn set_attribute_value_on_live_handle_succeeds() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let obj = backend.create_object(session, &[]).unwrap();
    assert!(backend.set_attribute_value(session, obj, &[]).is_ok());
}

#[test]
fn generate_key_pair_handles_are_live() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN, params: None };
    let (pub_h, priv_h) = backend.generate_key_pair(session, &mech, &[], &[]).unwrap();
    assert!(backend.get_object_size(session, pub_h).is_ok());
    assert!(backend.get_object_size(session, priv_h).is_ok());
}

#[test]
fn finalize_invalidates_all_object_handles() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let obj = backend.create_object(session, &[]).unwrap();
    backend.finalize().unwrap();
    backend.initialize().unwrap();
    let session2 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(backend.get_object_size(session2, obj).unwrap_err(), CkRv::OBJECT_HANDLE_INVALID);
}

#[test]
fn session_handle_invalid_after_close() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    backend.close_session(session).unwrap();
    assert_eq!(backend.get_session_info(session).unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
}

#[test]
fn session_handles_are_unique_across_open_calls() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let s1 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let s2 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_ne!(s1, s2);
}

#[test]
fn object_handles_are_unique_and_non_overlapping() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let o1 = backend.create_object(session, &[]).unwrap();
    let o2 = backend.create_object(session, &[]).unwrap();
    let o3 = backend
        .generate_key(
            session,
            &CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None },
            &[],
        )
        .unwrap();
    assert_ne!(o1, o2);
    assert_ne!(o1, o3);
    assert_ne!(o2, o3);
}

#[test]
fn rw_session_flag_reflected_in_session_info() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let rw_flags = CkSessionFlags(CkSessionFlags::RW_SESSION);
    let session = backend.open_session(CkSlotId(0), rw_flags).unwrap();
    let info = backend.get_session_info(session).unwrap();
    assert!(info.flags.is_rw());
    assert_eq!(info.state, CkSessionState::RwPublic);
}

#[test]
fn ro_session_flag_reflected_in_session_info() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let ro_flags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION);
    let session = backend.open_session(CkSlotId(0), ro_flags).unwrap();
    let info = backend.get_session_info(session).unwrap();
    assert!(!info.flags.is_rw());
    assert_eq!(info.state, CkSessionState::RoPublic);
}

#[test]
fn user_login_transitions_rw_session_to_rw_user() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let rw_flags = CkSessionFlags(CkSessionFlags::RW_SESSION);
    let session = backend.open_session(CkSlotId(0), rw_flags).unwrap();
    backend.login(session, CkUserType::User, Some(b"1234".as_ref())).unwrap();
    let info = backend.get_session_info(session).unwrap();
    assert_eq!(info.state, CkSessionState::RwUser);
}

#[test]
fn user_login_transitions_ro_session_to_ro_user() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let ro_flags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION);
    let session = backend.open_session(CkSlotId(0), ro_flags).unwrap();
    backend.login(session, CkUserType::User, Some(b"1234".as_ref())).unwrap();
    let info = backend.get_session_info(session).unwrap();
    assert_eq!(info.state, CkSessionState::RoUser);
}

#[test]
fn so_login_transitions_rw_session_to_rw_so() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let rw_flags = CkSessionFlags(CkSessionFlags::RW_SESSION);
    let session = backend.open_session(CkSlotId(0), rw_flags).unwrap();
    backend.login(session, CkUserType::So, Some(b"so-pin".as_ref())).unwrap();
    let info = backend.get_session_info(session).unwrap();
    assert_eq!(info.state, CkSessionState::RwSo);
}

#[test]
fn login_returns_user_already_logged_in_on_double_login() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags(CkSessionFlags::RW_SESSION)).unwrap();
    backend.login(session, CkUserType::User, Some(b"1234".as_ref())).unwrap();
    let err = backend.login(session, CkUserType::User, Some(b"1234".as_ref())).unwrap_err();
    assert_eq!(err, CkRv::USER_ALREADY_LOGGED_IN);
}

#[test]
fn logout_after_login_transitions_back_to_public() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let rw_flags = CkSessionFlags(CkSessionFlags::RW_SESSION);
    let session = backend.open_session(CkSlotId(0), rw_flags).unwrap();
    backend.login(session, CkUserType::User, Some(b"1234".as_ref())).unwrap();
    backend.logout(session).unwrap();
    let info = backend.get_session_info(session).unwrap();
    assert_eq!(info.state, CkSessionState::RwPublic);
}

#[test]
fn close_last_session_clears_login_state_for_slot() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let rw_flags = CkSessionFlags(CkSessionFlags::RW_SESSION);
    let session = backend.open_session(CkSlotId(0), rw_flags).unwrap();
    backend.login(session, CkUserType::User, Some(b"1234".as_ref())).unwrap();
    backend.close_session(session).unwrap();

    let new_session = backend.open_session(CkSlotId(0), rw_flags).unwrap();
    let info = backend.get_session_info(new_session).unwrap();
    assert_eq!(info.state, CkSessionState::RwPublic);
}

#[test]
fn logout_when_not_logged_in_returns_user_not_logged_in() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let err = backend.logout(session).unwrap_err();
    assert_eq!(err, CkRv::USER_NOT_LOGGED_IN);
}

#[test]
fn login_state_is_token_wide_all_sessions_on_slot_see_login() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let rw_flags = CkSessionFlags(CkSessionFlags::RW_SESSION);
    let s1 = backend.open_session(CkSlotId(0), rw_flags).unwrap();
    let s2 = backend.open_session(CkSlotId(0), rw_flags).unwrap();
    backend.login(s1, CkUserType::User, Some(b"1234".as_ref())).unwrap();
    let info = backend.get_session_info(s2).unwrap();
    assert_eq!(info.state, CkSessionState::RwUser);
}

#[test]
fn login_state_is_per_slot_independent() {
    let backend = MockBackend::new(vec![CkSlotId(0), CkSlotId(1)], vec![CkMechanismType::RSA_PKCS]);
    backend.initialize().unwrap();
    let rw = CkSessionFlags(CkSessionFlags::RW_SESSION);
    let s0 = backend.open_session(CkSlotId(0), rw).unwrap();
    let s1 = backend.open_session(CkSlotId(1), rw).unwrap();
    backend.login(s0, CkUserType::User, Some(b"1234".as_ref())).unwrap();
    let info = backend.get_session_info(s1).unwrap();
    assert_eq!(info.state, CkSessionState::RwPublic);
}

#[test]
fn login_with_invalid_session_returns_session_handle_invalid() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let err = backend.login(CkSessionHandle(9999), CkUserType::User, Some(b"1234".as_ref())).unwrap_err();
    assert_eq!(err, CkRv::SESSION_HANDLE_INVALID);
}

#[test]
fn logout_with_invalid_session_returns_session_handle_invalid() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let err = backend.logout(CkSessionHandle(9999)).unwrap_err();
    assert_eq!(err, CkRv::SESSION_HANDLE_INVALID);
}

#[test]
fn so_login_can_be_followed_by_user_login_on_different_slot() {
    let backend = MockBackend::new(vec![CkSlotId(0), CkSlotId(1)], vec![CkMechanismType::RSA_PKCS]);
    backend.initialize().unwrap();
    let rw = CkSessionFlags(CkSessionFlags::RW_SESSION);
    let s0 = backend.open_session(CkSlotId(0), rw).unwrap();
    let s1 = backend.open_session(CkSlotId(1), rw).unwrap();
    backend.login(s0, CkUserType::So, Some(b"so-pin".as_ref())).unwrap();
    backend.login(s1, CkUserType::User, Some(b"user-pin".as_ref())).unwrap();
    assert_eq!(backend.get_session_info(s0).unwrap().state, CkSessionState::RwSo);
    assert_eq!(backend.get_session_info(s1).unwrap().state, CkSessionState::RwUser);
}

#[test]
fn finalize_clears_login_state() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags(CkSessionFlags::RW_SESSION)).unwrap();
    backend.login(session, CkUserType::User, Some(b"1234".as_ref())).unwrap();
    backend.finalize().unwrap();
    backend.initialize().unwrap();
    let session2 = backend.open_session(CkSlotId(0), CkSessionFlags(CkSessionFlags::RW_SESSION)).unwrap();
    let err = backend.logout(session2).unwrap_err();
    assert_eq!(err, CkRv::USER_NOT_LOGGED_IN);
}

#[test]
fn attribute_store_value_returned() {
    let backend = MockBackend::default_test();
    let obj = CkObjectHandle(1);
    backend.set_attribute(
        obj,
        CkAttributeType::LABEL,
        MockAttributeSlot::Value(CkAttributeValue::String("mykey".into())),
    );
    let mut template = vec![CkAttribute { attr_type: CkAttributeType::LABEL, value: None }];
    backend.get_attribute_value(CkSessionHandle(1), obj, &mut template).unwrap();
    assert_eq!(template[0].value, Some(CkAttributeValue::String("mykey".into())));
}

#[test]
fn attribute_store_sensitive_returns_none_and_error() {
    let backend = MockBackend::default_test();
    let obj = CkObjectHandle(2);
    backend.set_attribute(obj, CkAttributeType::VALUE, MockAttributeSlot::Sensitive);
    let mut template = vec![CkAttribute { attr_type: CkAttributeType::VALUE, value: None }];
    let rv = backend.get_attribute_value(CkSessionHandle(1), obj, &mut template).unwrap_err();
    assert_eq!(rv, CkRv::ATTRIBUTE_SENSITIVE);
    assert!(template[0].value.is_none());
}

#[test]
fn attribute_store_invalid_type_returns_none_and_error() {
    let backend = MockBackend::default_test();
    let obj = CkObjectHandle(3);
    backend.set_attribute(obj, CkAttributeType::LABEL, MockAttributeSlot::InvalidType);
    let mut template = vec![CkAttribute { attr_type: CkAttributeType::LABEL, value: None }];
    let rv = backend.get_attribute_value(CkSessionHandle(1), obj, &mut template).unwrap_err();
    assert_eq!(rv, CkRv::ATTRIBUTE_TYPE_INVALID);
    assert!(template[0].value.is_none());
}

#[test]
fn attribute_store_mixed_template_partial_results() {
    let backend = MockBackend::default_test();
    let obj = CkObjectHandle(4);
    backend.set_attribute(
        obj,
        CkAttributeType::LABEL,
        MockAttributeSlot::Value(CkAttributeValue::String("key".into())),
    );
    backend.set_attribute(obj, CkAttributeType::VALUE, MockAttributeSlot::Sensitive);
    backend.set_attribute(obj, CkAttributeType::MODULUS, MockAttributeSlot::InvalidType);
    let mut template = vec![
        CkAttribute { attr_type: CkAttributeType::LABEL, value: None },
        CkAttribute { attr_type: CkAttributeType::VALUE, value: None },
        CkAttribute { attr_type: CkAttributeType::MODULUS, value: None },
    ];
    let rv = backend.get_attribute_value(CkSessionHandle(1), obj, &mut template).unwrap_err();
    assert_eq!(rv, CkRv::ATTRIBUTE_SENSITIVE);
    assert!(template[0].value.is_some());
    assert!(template[1].value.is_none());
    assert!(template[2].value.is_none());
}

#[test]
fn attribute_store_absent_object_is_noop() {
    let backend = MockBackend::default_test();
    let mut template = vec![CkAttribute { attr_type: CkAttributeType::LABEL, value: None }];
    let result = backend.get_attribute_value(CkSessionHandle(1), CkObjectHandle(99), &mut template);
    assert!(result.is_ok());
    assert!(template[0].value.is_none());
}

#[test]
fn attribute_store_only_invalid_type() {
    let backend = MockBackend::default_test();
    let obj = CkObjectHandle(5);
    backend.set_attribute(
        obj,
        CkAttributeType::LABEL,
        MockAttributeSlot::Value(CkAttributeValue::String("k".into())),
    );
    backend.set_attribute(obj, CkAttributeType::MODULUS, MockAttributeSlot::InvalidType);
    let mut template = vec![
        CkAttribute { attr_type: CkAttributeType::LABEL, value: None },
        CkAttribute { attr_type: CkAttributeType::MODULUS, value: None },
    ];
    let rv = backend.get_attribute_value(CkSessionHandle(1), obj, &mut template).unwrap_err();
    assert_eq!(rv, CkRv::ATTRIBUTE_TYPE_INVALID);
    assert!(template[0].value.is_some());
    assert!(template[1].value.is_none());
}

#[test]
fn get_attribute_value_exact_size_query_returns_length_without_bytes() {
    let backend = MockBackend::default_test();
    let obj = CkObjectHandle(6);
    backend.set_attribute(
        obj,
        CkAttributeType::LABEL,
        MockAttributeSlot::Value(CkAttributeValue::String("key".into())),
    );

    let (rv, results) = backend
        .get_attribute_value_exact(
            CkSessionHandle(1),
            obj,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::LABEL,
                buffer_present: false,
                buffer_len: 7,
                nested: None,
            }],
        )
        .unwrap();

    assert_eq!(rv, CkRv::OK);
    assert_eq!(
        results,
        vec![CkAttributeQueryResult {
            attr_type: CkAttributeType::LABEL,
            returned_len: 3,
            value: None,
            ck_rv: None,
            nested: None,
        }]
    );
}

#[test]
fn get_attribute_value_exact_too_small_returns_backend_length() {
    let backend = MockBackend::default_test();
    let obj = CkObjectHandle(7);
    backend.set_attribute(
        obj,
        CkAttributeType::LABEL,
        MockAttributeSlot::Value(CkAttributeValue::String("key".into())),
    );

    let (rv, results) = backend
        .get_attribute_value_exact(
            CkSessionHandle(1),
            obj,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::LABEL,
                buffer_present: true,
                buffer_len: 2,
                nested: None,
            }],
        )
        .unwrap();

    assert_eq!(rv, CkRv::BUFFER_TOO_SMALL);
    assert_eq!(
        results,
        vec![CkAttributeQueryResult {
            attr_type: CkAttributeType::LABEL,
            returned_len: u64::MAX,
            value: None,
            ck_rv: Some(CkRv::BUFFER_TOO_SMALL),
            nested: None,
        }]
    );
}

#[test]
fn get_attribute_value_exact_mixed_sensitive_and_invalid_preserves_statuses() {
    let backend = MockBackend::default_test();
    let obj = CkObjectHandle(8);
    backend.set_attribute(
        obj,
        CkAttributeType::LABEL,
        MockAttributeSlot::Value(CkAttributeValue::String("key".into())),
    );
    backend.set_attribute(obj, CkAttributeType::VALUE, MockAttributeSlot::Sensitive);
    backend.set_attribute(obj, CkAttributeType::MODULUS, MockAttributeSlot::InvalidType);

    let (rv, results) = backend
        .get_attribute_value_exact(
            CkSessionHandle(1),
            obj,
            &[
                CkAttributeQuery {
                    attr_type: CkAttributeType::LABEL,
                    buffer_present: false,
                    buffer_len: 0,
                    nested: None,
                },
                CkAttributeQuery {
                    attr_type: CkAttributeType::VALUE,
                    buffer_present: false,
                    buffer_len: 0,
                    nested: None,
                },
                CkAttributeQuery {
                    attr_type: CkAttributeType::MODULUS,
                    buffer_present: false,
                    buffer_len: 0,
                    nested: None,
                },
            ],
        )
        .unwrap();

    assert_eq!(rv, CkRv::ATTRIBUTE_SENSITIVE);
    assert_eq!(
        results,
        vec![
            CkAttributeQueryResult {
                attr_type: CkAttributeType::LABEL,
                returned_len: 3,
                value: None,
                ck_rv: None,
                nested: None,
            },
            CkAttributeQueryResult {
                attr_type: CkAttributeType::VALUE,
                returned_len: u64::MAX,
                value: None,
                ck_rv: Some(CkRv::ATTRIBUTE_SENSITIVE),
                nested: None,
            },
            CkAttributeQueryResult {
                attr_type: CkAttributeType::MODULUS,
                returned_len: u64::MAX,
                value: None,
                ck_rv: Some(CkRv::ATTRIBUTE_TYPE_INVALID),
                nested: None,
            },
        ]
    );
}

fn setup_with_session() -> (MockBackend, CkSessionHandle) {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    (backend, session)
}

#[test]
fn get_op_state_no_op_returns_operation_not_initialized() {
    let (backend, session) = setup_with_session();
    let rv = backend.get_operation_state(session).unwrap_err();
    assert_eq!(rv, CkRv::OPERATION_NOT_INITIALIZED);
}

#[test]
fn get_op_state_sign_active_returns_blob() {
    let (backend, session) = setup_with_session();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    backend.sign_init(session, &mech, CkObjectHandle(1)).unwrap();
    let blob = backend.get_operation_state(session).unwrap();
    assert_eq!(blob, vec![0xC9u8, 0xEA, 1]);
}

#[test]
fn get_op_state_does_not_clear_active_operation() {
    let (backend, session) = setup_with_session();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    backend.sign_init(session, &mech, CkObjectHandle(1)).unwrap();
    let _blob = backend.get_operation_state(session).unwrap();
    backend.sign_update(session, &[0x01, 0x02]).unwrap();
}

#[test]
fn set_op_state_restores_sign_on_same_session() {
    let (backend, session) = setup_with_session();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    backend.sign_init(session, &mech, CkObjectHandle(1)).unwrap();
    let blob = backend.get_operation_state(session).unwrap();
    backend.sign_final(session).unwrap();
    backend.set_operation_state(session, &blob, CkObjectHandle(0), CkObjectHandle(0)).unwrap();
    backend.sign_final(session).unwrap();
}

#[test]
fn set_op_state_transfers_to_different_session() {
    let (backend, session_a) = setup_with_session();
    let session_b = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    backend.sign_init(session_a, &mech, CkObjectHandle(1)).unwrap();
    let blob = backend.get_operation_state(session_a).unwrap();
    backend.set_operation_state(session_b, &blob, CkObjectHandle(0), CkObjectHandle(0)).unwrap();
    backend.sign_final(session_b).unwrap();
}

#[test]
fn set_op_state_empty_blob_returns_saved_state_invalid() {
    let (backend, session) = setup_with_session();
    let rv = backend.set_operation_state(session, &[], CkObjectHandle(0), CkObjectHandle(0)).unwrap_err();
    assert_eq!(rv, CkRv::SAVED_STATE_INVALID);
}

#[test]
fn set_op_state_wrong_magic_returns_saved_state_invalid() {
    let (backend, session) = setup_with_session();
    let rv = backend
        .set_operation_state(session, &[0xFF, 0xFF, 0x01], CkObjectHandle(0), CkObjectHandle(0))
        .unwrap_err();
    assert_eq!(rv, CkRv::SAVED_STATE_INVALID);
}

#[test]
fn set_op_state_unknown_op_byte_returns_saved_state_invalid() {
    let (backend, session) = setup_with_session();
    let rv = backend
        .set_operation_state(session, &[0xC9, 0xEA, 0xFF], CkObjectHandle(0), CkObjectHandle(0))
        .unwrap_err();
    assert_eq!(rv, CkRv::SAVED_STATE_INVALID);
}

#[test]
fn set_op_state_when_active_returns_operation_active() {
    let (backend, session) = setup_with_session();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    backend.sign_init(session, &mech, CkObjectHandle(1)).unwrap();
    let blob = vec![0xC9u8, 0xEA, 2];
    let rv = backend
        .set_operation_state(session, &blob, CkObjectHandle(0), CkObjectHandle(0))
        .unwrap_err();
    assert_eq!(rv, CkRv::OPERATION_ACTIVE);
}

#[test]
fn get_set_op_state_all_op_types_roundtrip() {
    use MultiPartOp::*;
    let ops: &[(MultiPartOp, u8)] = &[(Sign, 1), (Verify, 2), (Digest, 3), (Encrypt, 4), (Decrypt, 5)];
    for (op, expected_byte) in ops {
        let (backend, session) = setup_with_session();
        let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
        match op {
            Sign => backend.sign_init(session, &mech, CkObjectHandle(1)).unwrap(),
            Verify => backend.verify_init(session, &mech, CkObjectHandle(1)).unwrap(),
            Digest => backend.digest_init(session, &mech).unwrap(),
            Encrypt => {
                backend.encrypt_init(session, &mech, CkObjectHandle(1)).unwrap();
            }
            Decrypt => backend.decrypt_init(session, &mech, CkObjectHandle(1)).unwrap(),
        }
        let blob = backend.get_operation_state(session).unwrap();
        assert_eq!(blob, vec![0xC9u8, 0xEA, *expected_byte]);
        match op {
            Sign => {
                backend.sign_final(session).unwrap();
            }
            Verify => {
                let _ = backend.verify(session, &[0xDE, 0xAD], &[0xDE, 0xAD]);
            }
            Digest => {
                backend.digest_final(session).unwrap();
            }
            Encrypt => {
                backend.encrypt_final(session).unwrap();
            }
            Decrypt => {
                backend.decrypt_final(session).unwrap();
            }
        }
        backend.set_operation_state(session, &blob, CkObjectHandle(0), CkObjectHandle(0)).unwrap();
        let blob2 = backend.get_operation_state(session).unwrap();
        assert_eq!(blob, blob2);
    }
}

#[test]
fn open_session_enforces_max_sessions_quota() {
    let backend = MockBackend::default_test().with_quotas(2, 0);
    backend.initialize().unwrap();
    backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let rv = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap_err();
    assert_eq!(rv, CkRv::SESSION_COUNT);
}

#[test]
fn open_session_quota_freed_after_close() {
    let backend = MockBackend::default_test().with_quotas(1, 0);
    backend.initialize().unwrap();
    let s1 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap_err(), CkRv::SESSION_COUNT);
    backend.close_session(s1).unwrap();
    backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
}

#[test]
fn create_object_enforces_max_objects_quota() {
    let backend = MockBackend::default_test().with_quotas(0, 2);
    backend.initialize().unwrap();
    let s = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    backend.create_object(s, &[]).unwrap();
    backend.create_object(s, &[]).unwrap();
    let rv = backend.create_object(s, &[]).unwrap_err();
    assert_eq!(rv, CkRv::DEVICE_MEMORY);
}

#[test]
fn create_object_quota_freed_after_destroy() {
    let backend = MockBackend::default_test().with_quotas(0, 1);
    backend.initialize().unwrap();
    let s = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let obj = backend.create_object(s, &[]).unwrap();
    assert_eq!(backend.create_object(s, &[]).unwrap_err(), CkRv::DEVICE_MEMORY);
    backend.destroy_object(s, obj).unwrap();
    backend.create_object(s, &[]).unwrap();
}

#[test]
fn copy_object_also_enforces_max_objects_quota() {
    let backend = MockBackend::default_test().with_quotas(0, 1);
    backend.initialize().unwrap();
    let s = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let obj = backend.create_object(s, &[]).unwrap();
    let rv = backend.copy_object(s, obj, &[]).unwrap_err();
    assert_eq!(rv, CkRv::DEVICE_MEMORY);
}

#[test]
fn generate_random_at_limit_succeeds() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let s = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let buf = backend.generate_random(s, MockBackend::MAX_RANDOM_BYTES).unwrap();
    assert_eq!(buf.len(), MockBackend::MAX_RANDOM_BYTES as usize);
}

#[test]
fn generate_random_over_limit_returns_data_len_range() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let s = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let rv = backend.generate_random(s, MockBackend::MAX_RANDOM_BYTES + 1).unwrap_err();
    assert_eq!(rv, CkRv::DATA_LEN_RANGE);
}

#[test]
fn unlimited_quotas_do_not_restrict_sessions_or_objects() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let s = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    for _ in 0..50 {
        backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    }
    for _ in 0..50 {
        backend.create_object(s, &[]).unwrap();
    }
}

#[test]
fn injected_device_removed_blocks_open_session() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let _s = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    backend.inject_error(CkRv::DEVICE_REMOVED);
    let err = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap_err();
    assert_eq!(err, CkRv::DEVICE_REMOVED);
}

#[test]
fn injected_error_blocks_get_slot_info() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    backend.inject_error(CkRv::TOKEN_NOT_PRESENT);
    let err = backend.get_slot_info(CkSlotId(0)).unwrap_err();
    assert_eq!(err, CkRv::TOKEN_NOT_PRESENT);
}

#[test]
fn injected_error_blocks_get_token_info() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    backend.inject_error(CkRv::DEVICE_ERROR);
    let err = backend.get_token_info(CkSlotId(0)).unwrap_err();
    assert_eq!(err, CkRv::DEVICE_ERROR);
}

#[test]
fn injected_error_blocks_get_mechanism_list() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    backend.inject_error(CkRv::TOKEN_NOT_PRESENT);
    let err = backend.get_mechanism_list(CkSlotId(0)).unwrap_err();
    assert_eq!(err, CkRv::TOKEN_NOT_PRESENT);
}

#[test]
fn injected_error_blocks_sign_init() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let s = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    backend.inject_error(CkRv::DEVICE_REMOVED);
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let err = backend.sign_init(s, &mech, CkObjectHandle(1)).unwrap_err();
    assert_eq!(err, CkRv::DEVICE_REMOVED);
}

#[test]
fn injected_error_blocks_encrypt_init() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let s = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    backend.inject_error(CkRv::DEVICE_ERROR);
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let err = backend.encrypt_init(s, &mech, CkObjectHandle(1)).unwrap_err();
    assert_eq!(err, CkRv::DEVICE_ERROR);
}

#[test]
fn injected_error_blocks_generate_key_pair() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let s = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    backend.inject_error(CkRv::DEVICE_REMOVED);
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN, params: None };
    let err = backend.generate_key_pair(s, &mech, &[], &[]).unwrap_err();
    assert_eq!(err, CkRv::DEVICE_REMOVED);
}

#[test]
fn injected_error_blocks_generate_random() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let s = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    backend.inject_error(CkRv::DEVICE_ERROR);
    let err = backend.generate_random(s, 16).unwrap_err();
    assert_eq!(err, CkRv::DEVICE_ERROR);
}

#[test]
fn clear_error_restores_normal_operation() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    backend.inject_error(CkRv::DEVICE_REMOVED);
    assert!(backend.open_session(CkSlotId(0), CkSessionFlags::default()).is_err());
    backend.clear_error();
    let _s = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
}

#[test]
fn close_session_works_even_with_injected_error() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let s = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    backend.inject_error(CkRv::DEVICE_REMOVED);
    assert!(backend.close_session(s).is_ok());
}

#[test]
fn get_slot_list_works_even_with_injected_error() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    backend.inject_error(CkRv::DEVICE_REMOVED);
    let slots = backend.get_slot_list(true).unwrap();
    assert!(!slots.is_empty());
}

#[test]
fn reinitialize_after_device_removal() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let _s = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    backend.inject_error(CkRv::DEVICE_REMOVED);
    assert!(backend.open_session(CkSlotId(0), CkSessionFlags::default()).is_err());
    backend.clear_error();
    backend.finalize().unwrap();
    backend.initialize().unwrap();
    let _s2 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
}
