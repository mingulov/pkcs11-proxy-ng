use super::*;

#[test]
fn mock_lifecycle() {
    let backend = MockBackend::default_test();
    assert!(backend.initialize().is_ok());
    assert_eq!(backend.initialize().unwrap_err(), CkRv::CRYPTOKI_ALREADY_INITIALIZED);
    assert!(backend.finalize().is_ok());
}

#[test]
fn mock_session_lifecycle() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let h = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert!(backend.get_session_info(h).is_ok());
    assert!(backend.close_session(h).is_ok());
    assert_eq!(backend.close_session(h).unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
}

#[test]
fn mock_invalid_slot() {
    let backend = MockBackend::default_test();
    assert_eq!(backend.get_slot_info(CkSlotId(99)).unwrap_err(), CkRv::SLOT_ID_INVALID);
    assert_eq!(
        backend.open_session(CkSlotId(99), CkSessionFlags::default()).unwrap_err(),
        CkRv::SLOT_ID_INVALID
    );
}

#[test]
fn slot_scoped_workflows_reject_invalid_slot() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();

    assert_eq!(
        backend.init_token(CkSlotId(99), Some(b"so-pin"), "MockToken").unwrap_err(),
        CkRv::SLOT_ID_INVALID
    );
    assert_eq!(backend.close_all_sessions(CkSlotId(99)).unwrap_err(), CkRv::SLOT_ID_INVALID);
    assert!(backend.get_session_info(session).is_ok());
}

#[test]
fn mock_generate_key_pair_returns_unique_handles() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN, params: None };
    let (pub_h, priv_h) = backend.generate_key_pair(session, &mech, &[], &[]).unwrap();
    assert_ne!(pub_h, priv_h);
}

#[test]
fn object_and_key_creation_workflows_reject_invalid_session_without_allocating() {
    assert_invalid_session_does_not_allocate_object(|backend, session, _mechanism| {
        backend.create_object(session, &[label_attr("created")])
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, _mechanism| {
        backend.copy_object(session, CkObjectHandle(1), &[label_attr("copied")])
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.generate_key(session, mechanism, &[label_attr("generated")])
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.derive_key(session, mechanism, CkObjectHandle(1), &[label_attr("derived")])
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.derive_key_with_output(
            session,
            mechanism,
            CkObjectHandle(1),
            &[label_attr("derived-output")],
        )
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.unwrap_key(
            session,
            mechanism,
            CkObjectHandle(1),
            CkInBuf::Bytes(b"wrapped"),
            &[label_attr("unwrapped")],
        )
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.generate_key_pair(
            session,
            mechanism,
            &[label_attr("public")],
            &[label_attr("private")],
        )
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.encapsulate_key(
            session,
            mechanism,
            CkObjectHandle(1),
            &[label_attr("encapsulated")],
        )
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.encapsulate_key_exact(
            session,
            mechanism,
            CkObjectHandle(1),
            &[label_attr("encapsulated-exact")],
            &CkOutputBufferSpec { buffer_present: true, buffer_len: 8, length_pointer_null: false },
        )
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.decapsulate_key(
            session,
            mechanism,
            CkObjectHandle(1),
            &[label_attr("decapsulated")],
            CkInBuf::Bytes(b"capsule"),
        )
    });
    assert_invalid_session_does_not_allocate_object(|backend, session, mechanism| {
        backend.unwrap_key_authenticated(
            session,
            mechanism,
            CkObjectHandle(1),
            CkInBuf::Bytes(b"wrapped"),
            &[label_attr("authenticated-unwrapped")],
            CkInBuf::Bytes(b"aad"),
        )
    });
}

#[test]
fn object_management_workflows_reject_invalid_session_without_mutating_objects() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let object = backend.create_object(session, &[label_attr("live")]).unwrap();
    let invalid_session = CkSessionHandle(999);

    assert_eq!(
        backend.find_objects_init(invalid_session, &[]).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(backend.find_objects(invalid_session, 1).unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
    assert_eq!(
        backend.find_objects_final(invalid_session).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );

    let mut template = [label_attr("ignored")];
    assert_eq!(
        backend.get_attribute_value(invalid_session, object, &mut template).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .get_attribute_value_exact(
                invalid_session,
                object,
                &[CkAttributeQuery {
                    attr_type: CkAttributeType::LABEL,
                    buffer_present: true,
                    buffer_len: 4,
                    nested: None,
                }],
            )
            .unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.get_object_size(invalid_session, object).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.set_attribute_value(invalid_session, object, &[label_attr("new")]).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.destroy_object(invalid_session, object).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );

    assert_eq!(backend.get_object_size(session, object).unwrap(), 0);
    assert_mock_label(&backend, session, object, "live");
}

#[test]
fn find_objects_tracks_active_search_operation() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let key = live_key(&backend, session);
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };

    assert_eq!(backend.find_objects(session, 1).unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);
    assert_eq!(backend.find_objects_final(session).unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);

    backend.find_objects_init(session, &[]).unwrap();
    assert_eq!(backend.find_objects_init(session, &[]).unwrap_err(), CkRv::OPERATION_ACTIVE);
    assert_eq!(backend.sign_init(session, &mechanism, key).unwrap_err(), CkRv::OPERATION_ACTIVE);
    assert_eq!(backend.find_objects(session, 0).unwrap(), Vec::<CkObjectHandle>::new());
    backend.find_objects_final(session).unwrap();
    assert_eq!(backend.find_objects_final(session).unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);

    backend.sign_init(session, &mechanism, key).unwrap();
    assert_eq!(backend.find_objects_init(session, &[]).unwrap_err(), CkRv::OPERATION_ACTIVE);
}

#[test]
fn stateless_session_workflows_reject_invalid_session() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let invalid_session = CkSessionHandle(999);
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let output_spec =
        CkOutputBufferSpec { buffer_present: true, buffer_len: 64, length_pointer_null: false };
    let param_spec = CkParameterRoundtripSpec {
        buffer_present: true,
        buffer_len: 16,
        value: Some(vec![0xAA; 4]),
    };

    assert_eq!(
        backend.init_pin(invalid_session, Some(b"pin")).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.set_pin(invalid_session, Some(b"old"), Some(b"new")).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.sign_recover_init(invalid_session, &mechanism, CkObjectHandle(1)).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.sign_recover(invalid_session, CkInBuf::Bytes(b"data")).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .sign_recover_exact(invalid_session, CkInBuf::Bytes(b"data"), &output_spec)
            .unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.verify_recover_init(invalid_session, &mechanism, CkObjectHandle(1)).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.verify_recover(invalid_session, CkInBuf::Bytes(b"signature")).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .verify_recover_exact(invalid_session, CkInBuf::Bytes(b"signature"), &output_spec)
            .unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .wrap_key(invalid_session, &mechanism, CkObjectHandle(1), CkObjectHandle(2))
            .unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .wrap_key_exact(
                invalid_session,
                &mechanism,
                CkObjectHandle(1),
                CkObjectHandle(2),
                &output_spec,
            )
            .unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .wrap_key_authenticated_exact(
                invalid_session,
                &mechanism,
                CkObjectHandle(1),
                CkObjectHandle(2),
                CkInBuf::Bytes(b"aad"),
                &output_spec,
                &param_spec,
            )
            .unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.seed_random(invalid_session, CkInBuf::Bytes(b"seed")).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.generate_random(invalid_session, 8).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.digest_encrypt_update(invalid_session, CkInBuf::Bytes(b"part")).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.decrypt_digest_update(invalid_session, CkInBuf::Bytes(b"part")).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.sign_encrypt_update(invalid_session, CkInBuf::Bytes(b"part")).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend.decrypt_verify_update(invalid_session, CkInBuf::Bytes(b"part")).unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .digest_encrypt_update_exact(invalid_session, CkInBuf::Bytes(b"part"), &output_spec)
            .unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .decrypt_digest_update_exact(invalid_session, CkInBuf::Bytes(b"part"), &output_spec)
            .unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .sign_encrypt_update_exact(invalid_session, CkInBuf::Bytes(b"part"), &output_spec)
            .unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .decrypt_verify_update_exact(invalid_session, CkInBuf::Bytes(b"part"), &output_spec)
            .unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
}

#[test]
fn generate_key_pair_does_not_partially_allocate_on_quota_failure() {
    let backend = MockBackend::default_test().with_quotas(0, 1);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mechanism =
        CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN, params: None };

    let err = backend
        .generate_key_pair(session, &mechanism, &[label_attr("public")], &[label_attr("private")])
        .unwrap_err();

    assert_eq!(err, CkRv::DEVICE_MEMORY);
    assert_eq!(
        backend.destroy_object(session, CkObjectHandle(1)).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID,
        "failed key-pair generation must not leak a partial public key"
    );
}

#[test]
fn mock_generate_random_returns_correct_length() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let random = backend.generate_random(session, 32).unwrap();
    assert_eq!(random.len(), 32);
}

#[test]
fn close_session_clears_session_mechanism_output() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_GCM]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let output = gcm_mechanism_output();
    backend.set_encrypt_init_output(Some(output.clone()));
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: None };
    let key = live_key(&backend, session);

    backend.encrypt_init(session, &mechanism, key).unwrap();
    assert_eq!(backend.session_output_mechanism_params(session), Some(output));

    backend.close_session(session).unwrap();
    assert_eq!(backend.session_output_mechanism_params(session), None);
}

#[test]
fn close_all_sessions_clears_only_matching_session_mechanism_outputs() {
    let backend = MockBackend::new(vec![CkSlotId(0), CkSlotId(1)], vec![CkMechanismType::AES_GCM]);
    backend.initialize().unwrap();
    let s0 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let s1 = backend.open_session(CkSlotId(1), CkSessionFlags::default()).unwrap();
    let output = gcm_mechanism_output();
    backend.set_encrypt_init_output(Some(output.clone()));
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: None };
    let key0 = live_key(&backend, s0);
    let key1 = live_key(&backend, s1);
    backend.encrypt_init(s0, &mechanism, key0).unwrap();
    backend.encrypt_init(s1, &mechanism, key1).unwrap();

    backend.close_all_sessions(CkSlotId(0)).unwrap();

    assert_eq!(backend.session_output_mechanism_params(s0), None);
    assert_eq!(backend.session_output_mechanism_params(s1), Some(output));
}

#[test]
fn finalize_clears_all_session_mechanism_outputs() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_GCM]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    backend.set_encrypt_init_output(Some(gcm_mechanism_output()));
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: None };
    let key = live_key(&backend, session);
    backend.encrypt_init(session, &mechanism, key).unwrap();
    assert!(backend.session_output_mechanism_params(session).is_some());

    backend.finalize().unwrap();
    assert_eq!(backend.session_output_mechanism_params(session), None);
}

#[test]
fn session_cancel_clears_all_session_scoped_mock_state() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_GCM]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: None };
    let key = live_key(&backend, session);
    let signature = b"payload".iter().rev().copied().collect::<Vec<_>>();

    backend.set_encrypt_init_output(Some(gcm_mechanism_output()));
    backend.encrypt_init(session, &mechanism, key).unwrap();
    assert!(backend.session_output_mechanism_params(session).is_some());
    backend
        .verify_signature_init(session, Some(&mechanism), key, CkInBuf::Bytes(&signature))
        .unwrap();
    backend.verify_signature_update(session, CkInBuf::Bytes(b"pay")).unwrap();
    backend.verify_signature_update(session, CkInBuf::Bytes(b"load")).unwrap();
    assert_eq!(backend.verify_signature_final(session), Ok(()));

    backend.session_cancel(session, CkFlags(0)).unwrap();

    assert_eq!(backend.session_output_mechanism_params(session), None);
    assert_eq!(
        backend.verify_signature(session, CkInBuf::Bytes(b"payload")).unwrap_err(),
        CkRv::OPERATION_NOT_INITIALIZED
    );
    assert_eq!(
        backend.verify_signature_update(session, CkInBuf::Bytes(b"payload")).unwrap_err(),
        CkRv::OPERATION_NOT_INITIALIZED
    );
}

#[test]
fn close_all_sessions_is_slot_scoped() {
    let backend = MockBackend::new(vec![CkSlotId(0), CkSlotId(1)], vec![CkMechanismType::RSA_PKCS]);
    backend.initialize().unwrap();
    let s0 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let s1 = backend.open_session(CkSlotId(1), CkSessionFlags::default()).unwrap();
    backend.close_all_sessions(CkSlotId(0)).unwrap();
    assert_eq!(backend.close_session(s0).unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
    assert!(backend.close_session(s1).is_ok());
}

#[test]
fn get_session_info_returns_correct_slot() {
    let backend = MockBackend::new(vec![CkSlotId(0), CkSlotId(5)], vec![CkMechanismType::RSA_PKCS]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(5), CkSessionFlags::default()).unwrap();
    let info = backend.get_session_info(session).unwrap();
    assert_eq!(info.slot_id, CkSlotId(5));
}

#[test]
fn wait_for_slot_event_blocking_returns_not_initialized_after_finalize() {
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    let backend = Arc::new(MockBackend::default_test());
    backend.initialize().unwrap();
    let waiter_backend = Arc::clone(&backend);
    let (started_tx, started_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();

    let waiter = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        result_tx.send(waiter_backend.wait_for_slot_event(0)).unwrap();
    });

    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(result_rx.recv_timeout(Duration::from_millis(50)).is_err());

    backend.finalize().unwrap();
    let result = match result_rx.recv_timeout(Duration::from_secs(1)) {
        Ok(result) => result,
        Err(err) => {
            backend.enqueue_slot_event(CkSlotId(7));
            let _ = waiter.join();
            panic!("blocking slot-event wait did not return after finalize: {err}");
        }
    };
    assert_eq!(result.unwrap_err(), CkRv::CRYPTOKI_NOT_INITIALIZED);
    waiter.join().unwrap();
}

#[test]
fn finalize_clears_pending_slot_events() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    backend.enqueue_slot_event(CkSlotId(3));
    backend.finalize().unwrap();
    backend.initialize().unwrap();

    assert_eq!(backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap_err(), CkRv::NO_EVENT);
}

#[test]
fn sign_operations_are_per_session_independent() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let s1 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let s2 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let sha_mech = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    let key = live_key(&backend, s1);
    backend.sign_init(s1, &mech, key).unwrap();
    backend.digest_init(s2, &sha_mech).unwrap();
    backend.sign_update(s1, CkInBuf::Bytes(b"data")).unwrap();
    backend.digest_update(s2, CkInBuf::Bytes(b"data")).unwrap();
    backend.sign_final(s1).unwrap();
    backend.digest_final(s2).unwrap();
}

#[test]
fn close_session_clears_active_op_state() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let key = live_key(&backend, session);
    backend.sign_init(session, &mech, key).unwrap();
    backend.close_session(session).unwrap();
    let session2 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(
        backend.sign(session2, CkInBuf::Bytes(b"data")).unwrap_err(),
        CkRv::OPERATION_NOT_INITIALIZED
    );
}

// --- Uniform NULL rejection contract tests ---
