use super::*;

#[test]
fn typed_message_exact_paths_return_structured_mock_outputs() {
    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![
            CkMechanismType::AES_GCM,
            CkMechanismType::AES_CCM,
            CkMechanismType::CHACHA20_POLY1305,
        ],
    );
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let key = live_key(&backend, session);
    let output_spec = CkOutputBufferSpec { buffer_present: true, buffer_len: 64 };

    let gcm = MessageParameter::GcmMessage(GcmMessageParams {
        iv: vec![0x10; 12],
        iv_null_len: None,
        iv_fixed_bits: 32,
        iv_generator: 1,
        tag: vec![0; 16],
        tag_null_len: None,
        tag_bits: 128,
    });
    let gcm_spec = CkParameterRoundtripSpec {
        buffer_present: true,
        buffer_len: std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>() as u64,
        value: None,
    };
    let ccm = MessageParameter::CcmMessage(CcmMessageParams {
        data_len: 5,
        nonce: vec![0x20; 13],
        nonce_null_len: None,
        nonce_fixed_bits: 16,
        nonce_generator: 2,
        mac: vec![0; 12],
        mac_null_len: None,
        mac_len: 12,
    });
    let ccm_spec = CkParameterRoundtripSpec {
        buffer_present: true,
        buffer_len: std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>() as u64,
        value: None,
    };
    let chacha = MessageParameter::SalaChacha(Salsa20ChaCha20Poly1305MessageParams {
        nonce: vec![0x30; 12],
        nonce_bits: 96,
        nonce_null_len: None,
        tag: vec![0; 16],
        tag_null_len: None,
    });
    let chacha_spec = CkParameterRoundtripSpec {
        buffer_present: true,
        buffer_len: std::mem::size_of::<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>()
            as u64,
        value: None,
    };
    let cases = [
        ("GCM", CkMechanismType::AES_GCM, &gcm, &gcm_spec),
        ("CCM", CkMechanismType::AES_CCM, &ccm, &ccm_spec),
        ("Salsa/ChaCha", CkMechanismType::CHACHA20_POLY1305, &chacha, &chacha_spec),
    ];
    let mut exercised_cells = 0;
    for (shape, mechanism_type, parameter, provider_spec) in cases {
        let mechanism = CkMechanism { mechanism_type, params: None };
        for encrypt in [true, false] {
            let direction = if encrypt { "Encrypt" } else { "Decrypt" };

            let init_ack = if encrypt {
                backend.message_encrypt_init_contract(
                    session,
                    &mechanism,
                    Some(parameter),
                    key,
                    provider_spec,
                )
            } else {
                backend.message_decrypt_init_contract(
                    session,
                    &mechanism,
                    Some(parameter),
                    key,
                    provider_spec,
                )
            }
            .unwrap_or_else(|rv| panic!("{shape} {direction} Init failed: {rv:?}"));
            assert_eq!(init_ack.ck_rv, CkRv::OK, "{shape} {direction} Init rv");
            assert_eq!(
                init_ack.returned_len, provider_spec.buffer_len,
                "{shape} {direction} Init native length",
            );
            assert_eq!(init_ack.value, Some(Vec::new()), "{shape} {direction} Init presence");
            assert_eq!(
                backend.last_message_init_contract(),
                Some((parameter.clone(), provider_spec.clone())),
                "{shape} {direction} Init reaches the structured backend contract",
            );
            exercised_cells += 1;

            let before = backend.message_parameter_call_count();
            let (one_shot, one_shot_ack, one_shot_parameter) = if encrypt {
                backend.encrypt_message_exact_msg(
                    session,
                    parameter,
                    CkInBuf::Bytes(b"aad"),
                    CkInBuf::Bytes(b"input"),
                    &output_spec,
                    provider_spec,
                )
            } else {
                backend.decrypt_message_exact_msg(
                    session,
                    parameter,
                    CkInBuf::Bytes(b"aad"),
                    CkInBuf::Bytes(b"input"),
                    &output_spec,
                    provider_spec,
                )
            }
            .unwrap_or_else(|rv| panic!("{shape} {direction} one-shot failed: {rv:?}"));
            assert_eq!(
                backend.message_parameter_call_count(),
                before + 1,
                "{shape} {direction} one-shot trait call",
            );
            assert_eq!(one_shot.ck_rv, CkRv::OK, "{shape} {direction} one-shot rv");
            assert_eq!(one_shot.returned_len, 5, "{shape} {direction} one-shot length");
            assert!(one_shot.value.is_some(), "{shape} {direction} one-shot output");
            assert_eq!(
                one_shot_ack.returned_len, provider_spec.buffer_len,
                "{shape} {direction} one-shot native length",
            );
            assert!(
                parameter.same_layout_and_scalars(&one_shot_parameter),
                "{shape} {direction} one-shot layout/scalars",
            );
            exercised_cells += 1;

            let before = backend.message_begin_call_count();
            let (begin_ack, begin_parameter) = if encrypt {
                backend.encrypt_message_begin_msg(
                    session,
                    parameter,
                    CkInBuf::Bytes(b"aad"),
                    provider_spec,
                )
            } else {
                backend.decrypt_message_begin_msg(
                    session,
                    parameter,
                    CkInBuf::Bytes(b"aad"),
                    provider_spec,
                )
            }
            .unwrap_or_else(|rv| panic!("{shape} {direction} Begin failed: {rv:?}"));
            assert_eq!(
                backend.message_begin_call_count(),
                before + 1,
                "{shape} {direction} Begin trait call",
            );
            assert_eq!(
                begin_ack.returned_len, provider_spec.buffer_len,
                "{shape} {direction} Begin native length",
            );
            assert!(
                parameter.same_layout_and_scalars(&begin_parameter),
                "{shape} {direction} Begin layout/scalars",
            );
            exercised_cells += 1;

            let before = backend.message_parameter_call_count();
            let (next, next_ack, next_parameter) = if encrypt {
                backend.encrypt_message_next_exact_msg(
                    session,
                    parameter,
                    CkInBuf::Bytes(b"input"),
                    CkFlags(0),
                    &output_spec,
                    provider_spec,
                )
            } else {
                backend.decrypt_message_next_exact_msg(
                    session,
                    parameter,
                    CkInBuf::Bytes(b"input"),
                    CkFlags(0),
                    &output_spec,
                    provider_spec,
                )
            }
            .unwrap_or_else(|rv| panic!("{shape} {direction} Next failed: {rv:?}"));
            assert_eq!(
                backend.message_parameter_call_count(),
                before + 1,
                "{shape} {direction} Next trait call",
            );
            assert_eq!(next.ck_rv, CkRv::OK, "{shape} {direction} Next rv");
            assert_eq!(next.returned_len, 5, "{shape} {direction} Next length");
            assert!(next.value.is_some(), "{shape} {direction} Next output");
            assert_eq!(
                next_ack.returned_len, provider_spec.buffer_len,
                "{shape} {direction} Next native length",
            );
            assert!(
                parameter.same_layout_and_scalars(&next_parameter),
                "{shape} {direction} Next layout/scalars",
            );
            exercised_cells += 1;
        }
    }
    assert_eq!(exercised_cells, 24, "three shapes x two directions x Init/one-shot/Begin/Next",);

    let too_small = CkOutputBufferSpec { buffer_present: true, buffer_len: 1 };
    let (small, _, _) = backend
        .encrypt_message_exact_msg(
            session,
            &gcm,
            CkInBuf::Bytes(b"aad"),
            CkInBuf::Bytes(b"hello"),
            &too_small,
            &gcm_spec,
        )
        .unwrap();
    assert_eq!(small.ck_rv, CkRv::BUFFER_TOO_SMALL);
    assert_eq!(small.returned_len, 5);
    assert_eq!(small.value, None);

    assert_eq!(
        backend
            .encrypt_message_exact_msg(
                CkSessionHandle(999),
                &gcm,
                CkInBuf::Bytes(b"aad"),
                CkInBuf::Bytes(b"hello"),
                &output_spec,
                &gcm_spec,
            )
            .unwrap_err(),
        CkRv::SESSION_HANDLE_INVALID
    );
}

#[test]
fn encapsulate_key_returns_live_key_with_template_attributes() {
    let backend = MockBackend::with_official_mechanisms(vec![CkSlotId(0)]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let public_key = live_key(&backend, session);
    let mechanism = CkMechanism { mechanism_type: CkMechanismType(0x0000_0017), params: None };

    let (ciphertext, encapsulated_key) = backend
        .encapsulate_key(
            session,
            &mechanism,
            public_key,
            &[CkAttribute {
                attr_type: CkAttributeType::LABEL,
                value: Some(CkAttributeValue::String("kem-output".to_string())),
            }],
        )
        .unwrap();

    assert!(!ciphertext.is_empty());
    let (rv, results) = backend
        .get_attribute_value_exact(
            session,
            encapsulated_key,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::LABEL,
                buffer_present: true,
                buffer_len: "kem-output".len() as u64,
                nested: None,
            }],
        )
        .unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(results[0].value, Some(b"kem-output".to_vec()));
}

#[test]
fn encapsulate_key_exact_data_query_returns_live_key_with_template_attributes() {
    let backend = MockBackend::with_official_mechanisms(vec![CkSlotId(0)]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let public_key = live_key(&backend, session);
    let mechanism = CkMechanism { mechanism_type: CkMechanismType(0x0000_0017), params: None };

    let result = backend
        .encapsulate_key_exact(
            session,
            &mechanism,
            public_key,
            &[CkAttribute {
                attr_type: CkAttributeType::LABEL,
                value: Some(CkAttributeValue::String("kem-exact".to_string())),
            }],
            &CkOutputBufferSpec { buffer_present: true, buffer_len: 8 },
        )
        .unwrap();

    assert_eq!(result.ck_rv, CkRv::OK);
    assert_eq!(result.returned_len, 8);
    assert_ne!(result.object_handle, CkObjectHandle(0));
    let (rv, results) = backend
        .get_attribute_value_exact(
            session,
            result.object_handle,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::LABEL,
                buffer_present: true,
                buffer_len: "kem-exact".len() as u64,
                nested: None,
            }],
        )
        .unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(results[0].value, Some(b"kem-exact".to_vec()));
}

#[test]
fn encapsulate_key_exact_non_data_queries_do_not_allocate_key() {
    let backend = MockBackend::with_official_mechanisms(vec![CkSlotId(0)]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let public_key = live_key(&backend, session);
    let mechanism = CkMechanism { mechanism_type: CkMechanismType(0x0000_0017), params: None };

    let size_query = backend
        .encapsulate_key_exact(
            session,
            &mechanism,
            public_key,
            &[],
            &CkOutputBufferSpec { buffer_present: false, buffer_len: 0 },
        )
        .unwrap();
    assert_eq!(size_query.ck_rv, CkRv::OK);
    assert_eq!(size_query.object_handle, CkObjectHandle(0));

    let too_small = backend
        .encapsulate_key_exact(
            session,
            &mechanism,
            public_key,
            &[],
            &CkOutputBufferSpec { buffer_present: true, buffer_len: 1 },
        )
        .unwrap();
    assert_eq!(too_small.ck_rv, CkRv::BUFFER_TOO_SMALL);
    assert_eq!(too_small.object_handle, CkObjectHandle(0));

    assert_eq!(
        backend.destroy_object(session, CkObjectHandle(public_key.0 + 1)).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
}

#[test]
fn full_registry_mock_accepts_every_registered_mechanism_for_exact_wrap_workflow() {
    let registry = MechanismRegistry::load_with_override_str(None).unwrap();
    let mechanisms = registry
        .registered_mechanisms()
        .into_iter()
        .map(|x| CkMechanismType(x as u64))
        .collect::<Vec<_>>();
    let backend = MockBackend::with_mechanism_registry(vec![CkSlotId(0)], &registry);
    backend.initialize().unwrap();

    for mechanism_type in mechanisms {
        let mechanism = CkMechanism { mechanism_type, params: None };
        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let wrapping_key = backend.create_object(session, &[]).unwrap();
        let key = backend.create_object(session, &[]).unwrap();

        let size_spec = CkOutputBufferSpec { buffer_present: false, buffer_len: 0 };
        let size_result =
            backend.wrap_key_exact(session, &mechanism, wrapping_key, key, &size_spec).unwrap();
        assert_eq!(size_result.ck_rv, CkRv::OK);
        assert_eq!(size_result.returned_len, 4);
        assert!(size_result.value.is_none());

        let data_spec = CkOutputBufferSpec { buffer_present: true, buffer_len: 4 };
        let data_result =
            backend.wrap_key_exact(session, &mechanism, wrapping_key, key, &data_spec).unwrap();
        assert_eq!(data_result.ck_rv, CkRv::OK);
        assert_eq!(data_result.value, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));

        backend.close_session(session).unwrap();
    }
}

#[test]
fn official_mechanism_mock_accepts_every_official_mechanism_across_exact_output_workflows() {
    let backend = MockBackend::with_official_mechanism_catalog_smoke(vec![CkSlotId(0)]);
    backend.initialize().unwrap();

    for mechanism_type in pkcs11_3_2_official_mechanisms() {
        let mechanism = CkMechanism { mechanism_type: *mechanism_type, params: None };
        let data = b"exact-output official workflow";
        let parameter = b"param";

        assert_exact_byte_size_and_data("sign_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.sign_init(session, &mechanism, key).unwrap();
            let result = backend.sign_exact(session, CkInBuf::Bytes(data), spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("sign_final_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.sign_init(session, &mechanism, key).unwrap();
            backend.sign_update(session, CkInBuf::Bytes(data)).unwrap();
            let result = backend.sign_final_exact(session, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("sign_recover_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.sign_recover_init(session, &mechanism, key).unwrap();
            let result = backend.sign_recover_exact(session, CkInBuf::Bytes(data), spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("verify_recover_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.verify_recover_init(session, &mechanism, key).unwrap();
            let result = backend.verify_recover_exact(session, CkInBuf::Bytes(data), spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("digest_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            backend.digest_init(session, &mechanism).unwrap();
            let result = backend.digest_exact(session, CkInBuf::Bytes(data), spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("digest_final_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            backend.digest_init(session, &mechanism).unwrap();
            backend.digest_update(session, CkInBuf::Bytes(data)).unwrap();
            let result = backend.digest_final_exact(session, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("encrypt_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.encrypt_init(session, &mechanism, key).unwrap();
            let result = backend.encrypt_exact(session, CkInBuf::Bytes(data), spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("encrypt_update_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.encrypt_init(session, &mechanism, key).unwrap();
            let result = backend.encrypt_update_exact(session, CkInBuf::Bytes(data), spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("encrypt_final_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.encrypt_init(session, &mechanism, key).unwrap();
            let result = backend.encrypt_final_exact(session, spec);
            backend.close_session(session).unwrap();
            result
        });

        let ciphertext = data.iter().map(|byte| byte ^ 0x42).collect::<Vec<_>>();
        assert_exact_byte_size_and_data("decrypt_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.decrypt_init(session, &mechanism, key).unwrap();
            let result = backend.decrypt_exact(session, CkInBuf::Bytes(&ciphertext), spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("decrypt_update_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.decrypt_init(session, &mechanism, key).unwrap();
            let result = backend.decrypt_update_exact(session, CkInBuf::Bytes(&ciphertext), spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("decrypt_final_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.decrypt_init(session, &mechanism, key).unwrap();
            let result = backend.decrypt_final_exact(session, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("digest_encrypt_update_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let result = backend.digest_encrypt_update_exact(session, CkInBuf::Bytes(data), spec);
            backend.close_session(session).unwrap();
            result
        });
        assert_exact_byte_size_and_data("decrypt_digest_update_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let result = backend.decrypt_digest_update_exact(session, CkInBuf::Bytes(data), spec);
            backend.close_session(session).unwrap();
            result
        });
        assert_exact_byte_size_and_data("sign_encrypt_update_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let result = backend.sign_encrypt_update_exact(session, CkInBuf::Bytes(data), spec);
            backend.close_session(session).unwrap();
            result
        });
        assert_exact_byte_size_and_data("decrypt_verify_update_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let result = backend.decrypt_verify_update_exact(session, CkInBuf::Bytes(data), spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("wrap_key_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let wrapping_key = live_key(&backend, session);
            let key = live_key(&backend, session);
            let result = backend.wrap_key_exact(session, &mechanism, wrapping_key, key, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_byte_size_and_data("get_operation_state_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            backend.sign_init(session, &mechanism, key).unwrap();
            let result = backend.get_operation_state_exact(session, spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_handle_size_and_data("encapsulate_key_exact", *mechanism_type, |spec| {
            let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
            let key = live_key(&backend, session);
            let result =
                backend.encapsulate_key_exact(session, &mechanism, key, &[label_attr("kem")], spec);
            backend.close_session(session).unwrap();
            result
        });

        assert_exact_parameter_size_and_data(
            "encrypt_message_exact",
            *mechanism_type,
            |output_spec, param_spec| {
                let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
                let key = live_key(&backend, session);
                backend.encrypt_init(session, &mechanism, key).unwrap();
                let result = backend.encrypt_message_exact(
                    session,
                    parameter,
                    CkInBuf::Bytes(b"aad"),
                    CkInBuf::Bytes(data),
                    output_spec,
                    param_spec,
                );
                backend.close_session(session).unwrap();
                result
            },
        );

        assert_exact_parameter_size_and_data(
            "decrypt_message_exact",
            *mechanism_type,
            |output_spec, param_spec| {
                let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
                let key = live_key(&backend, session);
                backend.decrypt_init(session, &mechanism, key).unwrap();
                let result = backend.decrypt_message_exact(
                    session,
                    parameter,
                    CkInBuf::Bytes(b"aad"),
                    CkInBuf::Bytes(&ciphertext),
                    output_spec,
                    param_spec,
                );
                backend.close_session(session).unwrap();
                result
            },
        );

        assert_exact_parameter_size_and_data(
            "sign_message_exact",
            *mechanism_type,
            |output_spec, param_spec| {
                let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
                let key = live_key(&backend, session);
                backend.sign_init(session, &mechanism, key).unwrap();
                let result = backend.sign_message_exact(
                    session,
                    parameter,
                    CkInBuf::Bytes(data),
                    output_spec,
                    param_spec,
                );
                backend.close_session(session).unwrap();
                result
            },
        );

        assert_exact_parameter_size_and_data(
            "encrypt_message_next_exact",
            *mechanism_type,
            |output_spec, param_spec| {
                let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
                let key = live_key(&backend, session);
                backend.encrypt_init(session, &mechanism, key).unwrap();
                let result = backend.encrypt_message_next_exact(
                    session,
                    parameter,
                    CkInBuf::Bytes(data),
                    CkFlags(0),
                    output_spec,
                    param_spec,
                );
                backend.close_session(session).unwrap();
                result
            },
        );

        assert_exact_parameter_size_and_data(
            "decrypt_message_next_exact",
            *mechanism_type,
            |output_spec, param_spec| {
                let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
                let key = live_key(&backend, session);
                backend.decrypt_init(session, &mechanism, key).unwrap();
                let result = backend.decrypt_message_next_exact(
                    session,
                    parameter,
                    CkInBuf::Bytes(&ciphertext),
                    CkFlags(0),
                    output_spec,
                    param_spec,
                );
                backend.close_session(session).unwrap();
                result
            },
        );

        assert_exact_parameter_size_and_data(
            "sign_message_next_exact",
            *mechanism_type,
            |output_spec, param_spec| {
                let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
                let key = live_key(&backend, session);
                backend.sign_init(session, &mechanism, key).unwrap();
                let result = backend.sign_message_next_exact(
                    session,
                    parameter,
                    CkInBuf::Bytes(data),
                    output_spec,
                    param_spec,
                );
                backend.close_session(session).unwrap();
                result
            },
        );

        assert_exact_parameter_size_and_data(
            "wrap_key_authenticated_exact",
            *mechanism_type,
            |output_spec, param_spec| {
                let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
                let wrapping_key = live_key(&backend, session);
                let key = live_key(&backend, session);
                let result = backend.wrap_key_authenticated_exact(
                    session,
                    &mechanism,
                    wrapping_key,
                    key,
                    CkInBuf::Bytes(b"aad"),
                    output_spec,
                    param_spec,
                );
                backend.close_session(session).unwrap();
                result
            },
        );
    }
}

#[test]
fn verify_rejects_signature_that_does_not_match_sign_echo() {
    // C_Verify must actually verify: since sign outputs a deterministic
    // echo of the signed data, a signature that does not match that echo
    // (any byte lost or corrupted by a proxy in between) is rejected.
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let key = backend.create_object(session, &[]).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };

    backend.sign_init(session, &mech, key).unwrap();
    let signature = backend.sign(session, CkInBuf::Bytes(b"the data")).unwrap();

    // Correct signature over the same data verifies.
    backend.verify_init(session, &mech, key).unwrap();
    backend.verify(session, CkInBuf::Bytes(b"the data"), CkInBuf::Bytes(&signature)).unwrap();

    // One flipped signature byte is rejected.
    let mut tampered = signature.clone();
    tampered[0] ^= 0x01;
    backend.verify_init(session, &mech, key).unwrap();
    assert_eq!(
        backend
            .verify(session, CkInBuf::Bytes(b"the data"), CkInBuf::Bytes(&tampered))
            .unwrap_err(),
        CkRv::SIGNATURE_INVALID,
    );

    // A signature over DIFFERENT data is rejected (the data reached the
    // backend intact only if the echo matches).
    backend.verify_init(session, &mech, key).unwrap();
    assert_eq!(
        backend
            .verify(session, CkInBuf::Bytes(b"other data"), CkInBuf::Bytes(&signature))
            .unwrap_err(),
        CkRv::SIGNATURE_INVALID,
    );
}
