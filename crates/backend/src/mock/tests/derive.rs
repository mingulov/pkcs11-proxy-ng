use super::*;

#[test]
fn derive_key_with_sp800_108_rejects_unsupported_prf_type() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);

    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CKM_SP800_108_COUNTER_KDF]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let base_key = live_key(&backend, session);
    let mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_COUNTER_KDF,
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CkMechanismType::SHA256.0,
            data_params: vec![sp800_108_counter_iteration_param()],
            additional_derived_keys: Vec::new(),
        })),
    };

    let err = backend.derive_key_with_output(session, &mechanism, base_key, Some(&[])).unwrap_err();

    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
}

#[test]
fn derive_key_validates_source_grounded_signal_parameter_handles() {
    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![
            CkMechanismType::X3DH_INITIALIZE,
            CkMechanismType::X3DH_RESPOND,
            CkMechanismType::X2RATCHET_INITIALIZE,
            CkMechanismType::X2RATCHET_RESPOND,
        ],
    );
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let handles = signal_live_handles(&backend, session, 16);
    let invalid = 0xFFFF_FFFF;

    let x3dh_initiate =
        |peer_identity_handle, peer_prekey_handle, own_identity_handle, own_ephemeral_handle| {
            CkMechanismParams::X3dhInitiate(X3dhInitiateParams {
                kdf: 1,
                peer_identity_handle,
                peer_prekey_handle,
                prekey_signature: vec![0xA5; 64],
                onetime_key_handle: invalid,
                own_identity_handle,
                own_ephemeral_handle,
            })
        };
    for (label, params) in [
        (
            "CK_X3DH_INITIATE_PARAMS.pPeer_identity",
            x3dh_initiate(invalid, handles[1].0, handles[2].0, handles[3].0),
        ),
        (
            "CK_X3DH_INITIATE_PARAMS.pPeer_prekey",
            x3dh_initiate(handles[0].0, invalid, handles[2].0, handles[3].0),
        ),
        (
            "CK_X3DH_INITIATE_PARAMS.pOwn_identity",
            x3dh_initiate(handles[0].0, handles[1].0, invalid, handles[3].0),
        ),
        (
            "CK_X3DH_INITIATE_PARAMS.pOwn_ephemeral",
            x3dh_initiate(handles[0].0, handles[1].0, handles[2].0, invalid),
        ),
    ] {
        expect_signal_derive_param_invalid(
            &backend,
            session,
            CkMechanismType::X3DH_INITIALIZE,
            params,
            label,
        );
    }

    expect_signal_derive_param_invalid(
        &backend,
        session,
        CkMechanismType::X3DH_RESPOND,
        CkMechanismParams::X3dhRespond(X3dhRespondParams {
            kdf: 1,
            identity_handle: invalid,
            prekey_handle: invalid,
            onetime_key_handle: invalid,
            initiator_identity_handle: invalid,
            initiator_ephemeral_handle: invalid,
        }),
        "CK_X3DH_RESPOND_PARAMS.pInitiator_identity",
    );

    let x2_initialize =
        |peer_public_prekey_handle, peer_public_identity_handle, own_public_identity_handle| {
            CkMechanismParams::X2RatchetInitialize(X2RatchetInitializeParams {
                sk: vec![0x42; 32].into(),
                peer_public_prekey_handle,
                peer_public_identity_handle,
                own_public_identity_handle,
                encrypted_header: true,
                curve: 255,
                aead_mechanism: CkMechanismType::AES_GCM.0,
                kdf_mechanism: 1,
            })
        };
    for (label, params) in [
        (
            "CK_X2RATCHET_INITIALIZE_PARAMS.peer_public_prekey",
            x2_initialize(invalid, handles[5].0, handles[6].0),
        ),
        (
            "CK_X2RATCHET_INITIALIZE_PARAMS.peer_public_identity",
            x2_initialize(handles[4].0, invalid, handles[6].0),
        ),
        (
            "CK_X2RATCHET_INITIALIZE_PARAMS.own_public_identity",
            x2_initialize(handles[4].0, handles[5].0, invalid),
        ),
    ] {
        expect_signal_derive_param_invalid(
            &backend,
            session,
            CkMechanismType::X2RATCHET_INITIALIZE,
            params,
            label,
        );
    }

    let x2_respond = |own_prekey_handle, initiator_identity_handle, own_identity_handle| {
        CkMechanismParams::X2RatchetRespond(X2RatchetRespondParams {
            sk: vec![0x24; 32].into(),
            own_prekey_handle,
            initiator_identity_handle,
            own_identity_handle,
            encrypted_header: false,
            curve: 255,
            aead_mechanism: CkMechanismType::AES_GCM.0,
            kdf_mechanism: 1,
        })
    };
    for (label, params) in [
        ("CK_X2RATCHET_RESPOND_PARAMS.own_prekey", x2_respond(invalid, handles[8].0, handles[9].0)),
        (
            "CK_X2RATCHET_RESPOND_PARAMS.initiator_identity",
            x2_respond(handles[7].0, invalid, handles[9].0),
        ),
        (
            "CK_X2RATCHET_RESPOND_PARAMS.own_public_identity",
            x2_respond(handles[7].0, handles[8].0, invalid),
        ),
    ] {
        expect_signal_derive_param_invalid(
            &backend,
            session,
            CkMechanismType::X2RATCHET_RESPOND,
            params,
            label,
        );
    }
}

#[test]
fn derive_key_leaves_lengthless_signal_byte_fields_unvalidated() {
    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType::X3DH_INITIALIZE, CkMechanismType::X3DH_RESPOND],
    );
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let handles = signal_live_handles(&backend, session, 5);
    let base_key = live_key(&backend, session);
    let invalid = 0xFFFF_FFFF;

    let initiate = CkMechanism {
        mechanism_type: CkMechanismType::X3DH_INITIALIZE,
        params: Some(CkMechanismParams::X3dhInitiate(X3dhInitiateParams {
            kdf: 1,
            peer_identity_handle: handles[0].0,
            peer_prekey_handle: handles[1].0,
            prekey_signature: Vec::new(),
            onetime_key_handle: invalid,
            own_identity_handle: handles[2].0,
            own_ephemeral_handle: handles[3].0,
        })),
    };
    let respond = CkMechanism {
        mechanism_type: CkMechanismType::X3DH_RESPOND,
        params: Some(CkMechanismParams::X3dhRespond(X3dhRespondParams {
            kdf: 1,
            identity_handle: invalid,
            prekey_handle: invalid,
            onetime_key_handle: invalid,
            initiator_identity_handle: handles[4].0,
            initiator_ephemeral_handle: invalid,
        })),
    };

    assert_ne!(
        backend.derive_key(session, &initiate, base_key, Some(&[label_attr("initiate")])).unwrap(),
        CkObjectHandle(0)
    );
    assert_ne!(
        backend.derive_key(session, &respond, base_key, Some(&[label_attr("respond")])).unwrap(),
        CkObjectHandle(0)
    );
}

#[test]
fn cms_sig_workflows_validate_optional_certificate_handle() {
    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType::CMS_SIG, CkMechanismType::RSA_PKCS, CkMechanismType::SHA256],
    );
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let signing_key = live_key(&backend, session);
    let certificate = live_key(&backend, session);
    let invalid_certificate = CkObjectHandle(0xFFFF_FFFE);
    let invalid_cert_mechanism = cms_sig_mechanism(invalid_certificate);

    assert_eq!(
        backend.sign_init(session, &invalid_cert_mechanism, signing_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.verify_init(session, &invalid_cert_mechanism, signing_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.sign_recover_init(session, &invalid_cert_mechanism, signing_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.verify_recover_init(session, &invalid_cert_mechanism, signing_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );

    let live_cert_mechanism = cms_sig_mechanism(certificate);
    backend.sign_init(session, &live_cert_mechanism, signing_key).unwrap();
    let signature = backend.sign_final(session).unwrap();
    let signature_bytes = signature.expose(|raw| raw.to_vec());
    backend.verify_init(session, &live_cert_mechanism, signing_key).unwrap();
    backend.verify_final(session, CkInBuf::Bytes(&signature_bytes)).unwrap();
    backend.sign_recover_init(session, &live_cert_mechanism, signing_key).unwrap();
    backend.sign_recover(session, CkInBuf::Bytes(b"data")).unwrap();
    backend.verify_recover_init(session, &live_cert_mechanism, signing_key).unwrap();
    backend.verify_recover(session, CkInBuf::Bytes(b"sig")).unwrap();

    let absent_cert_mechanism = cms_sig_mechanism(CkObjectHandle(0));
    backend.sign_init(session, &absent_cert_mechanism, signing_key).unwrap();
    backend.sign_final(session).unwrap();
}

#[test]
fn derive_key_validates_concatenate_base_and_key_parameter_handle() {
    let backend =
        MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::CONCATENATE_BASE_AND_KEY]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let base_key = live_key(&backend, session);
    let other_key = live_key(&backend, session);
    let invalid = 0xFFFF_FFFD;

    let invalid_mechanism = CkMechanism {
        mechanism_type: CkMechanismType::CONCATENATE_BASE_AND_KEY,
        params: Some(CkMechanismParams::ObjectHandle(ObjectHandleParam { handle: invalid })),
    };
    assert_eq!(
        backend
            .derive_key(session, &invalid_mechanism, base_key, Some(&[label_attr("derived")]))
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .derive_key_with_output(
                session,
                &invalid_mechanism,
                base_key,
                Some(&[label_attr("derived")])
            )
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );

    let valid_mechanism = CkMechanism {
        mechanism_type: CkMechanismType::CONCATENATE_BASE_AND_KEY,
        params: Some(CkMechanismParams::ObjectHandle(ObjectHandleParam { handle: other_key.0 })),
    };
    assert_ne!(
        backend
            .derive_key(session, &valid_mechanism, base_key, Some(&[label_attr("valid")]))
            .unwrap(),
        CkObjectHandle(0)
    );
}

#[test]
fn kip_derive_and_mac_validate_hkey_but_wrap_does_not_use_it() {
    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![CkMechanismType::KIP_DERIVE, CkMechanismType::KIP_MAC, CkMechanismType::KIP_WRAP],
    );
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let base_key = live_key(&backend, session);
    let entropy_key = live_key(&backend, session);
    let wrapping_key = live_key(&backend, session);
    let wrapped_key = live_key(&backend, session);
    let invalid = CkObjectHandle(0xFFFF_FFFC);

    let invalid_derive = kip_mechanism(CkMechanismType::KIP_DERIVE, invalid);
    assert_eq!(
        backend
            .derive_key(session, &invalid_derive, base_key, Some(&[label_attr("kip-derived")]))
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend
            .derive_key_with_output(
                session,
                &invalid_derive,
                base_key,
                Some(&[label_attr("kip-derived")])
            )
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );

    let valid_derive = kip_mechanism(CkMechanismType::KIP_DERIVE, entropy_key);
    assert_ne!(
        backend
            .derive_key(session, &valid_derive, base_key, Some(&[label_attr("kip-valid")]))
            .unwrap(),
        CkObjectHandle(0)
    );

    let invalid_mac = kip_mechanism(CkMechanismType::KIP_MAC, invalid);
    assert_eq!(
        backend.sign_init(session, &invalid_mac, base_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );
    assert_eq!(
        backend.verify_init(session, &invalid_mac, base_key).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID
    );

    let valid_mac = kip_mechanism(CkMechanismType::KIP_MAC, entropy_key);
    backend.sign_init(session, &valid_mac, base_key).unwrap();
    let signature = backend.sign_final(session).unwrap();
    let signature_bytes = signature.expose(|raw| raw.to_vec());
    backend.verify_init(session, &valid_mac, base_key).unwrap();
    backend.verify_final(session, CkInBuf::Bytes(&signature_bytes)).unwrap();

    let wrap_mechanism = kip_mechanism(CkMechanismType::KIP_WRAP, invalid);
    assert_eq!(
        backend.wrap_key(session, &wrap_mechanism, wrapping_key, wrapped_key).unwrap(),
        vec![0xDE, 0xAD, 0xBE, 0xEF].into()
    );
    assert_ne!(
        backend
            .unwrap_key(
                session,
                &wrap_mechanism,
                wrapping_key,
                CkInBuf::Bytes(b"wrapped"),
                Some(&[label_attr("kip-unwrapped")])
            )
            .unwrap(),
        CkObjectHandle(0)
    );
}

#[test]
fn derive_key_validates_dual_ec_and_x942_parameter_handles() {
    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![
            CkMechanismType::ECMQV_DERIVE,
            CkMechanismType::X9_42_DH_HYBRID_DERIVE,
            CkMechanismType::X9_42_MQV_DERIVE,
        ],
    );
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let handles = signal_live_handles(&backend, session, 8);
    let invalid = 0xFFFF_FFFB;

    let ecdh2 = |private_data_handle| {
        CkMechanismParams::Ecdh2Derive(Ecdh2DeriveParams {
            kdf: 1,
            shared_data: b"shared".to_vec().into(),
            public_data: b"peer-public-1".to_vec(),
            private_data_len: 32,
            private_data_handle,
            public_data2: b"peer-public-2".to_vec(),
        })
    };
    expect_derive_param_handle_invalid(
        &backend,
        session,
        CkMechanismType::ECMQV_DERIVE,
        ecdh2(invalid),
        "CK_ECDH2_DERIVE_PARAMS.hPrivateData",
    );

    let ecmqv = |private_data_handle, public_key_handle| {
        CkMechanismParams::EcmqvDerive(EcmqvDeriveParams {
            kdf: 1,
            shared_data: b"shared".to_vec().into(),
            public_data: b"peer-public-1".to_vec(),
            private_data_len: 32,
            private_data_handle,
            public_data2: b"peer-public-2".to_vec(),
            public_key_handle,
        })
    };
    expect_derive_param_handle_invalid(
        &backend,
        session,
        CkMechanismType::ECMQV_DERIVE,
        ecmqv(invalid, handles[1].0),
        "CK_ECMQV_DERIVE_PARAMS.hPrivateData",
    );
    expect_derive_param_handle_invalid(
        &backend,
        session,
        CkMechanismType::ECMQV_DERIVE,
        ecmqv(handles[0].0, invalid),
        "CK_ECMQV_DERIVE_PARAMS.publicKey",
    );

    let x942_dh2 = |private_data_handle| {
        CkMechanismParams::X942Dh2Derive(X942Dh2DeriveParams {
            kdf: 1,
            other_info: b"other".to_vec().into(),
            public_data: b"dh-public-1".to_vec(),
            private_data_len: 32,
            private_data_handle,
            public_data2: b"dh-public-2".to_vec(),
        })
    };
    expect_derive_param_handle_invalid(
        &backend,
        session,
        CkMechanismType::X9_42_DH_HYBRID_DERIVE,
        x942_dh2(invalid),
        "CK_X9_42_DH2_DERIVE_PARAMS.hPrivateData",
    );

    let x942_mqv = |private_data_handle, public_key_handle| {
        CkMechanismParams::X942MqvDerive(X942MqvDeriveParams {
            kdf: 1,
            other_info: b"other".to_vec().into(),
            public_data: b"dh-public-1".to_vec(),
            private_data_len: 32,
            private_data_handle,
            public_data2: b"dh-public-2".to_vec(),
            public_key_handle,
        })
    };
    expect_derive_param_handle_invalid(
        &backend,
        session,
        CkMechanismType::X9_42_MQV_DERIVE,
        x942_mqv(invalid, handles[3].0),
        "CK_X9_42_MQV_DERIVE_PARAMS.hPrivateData",
    );
    expect_derive_param_handle_invalid(
        &backend,
        session,
        CkMechanismType::X9_42_MQV_DERIVE,
        x942_mqv(handles[2].0, invalid),
        "CK_X9_42_MQV_DERIVE_PARAMS.publicKey",
    );

    for (mechanism_type, params) in [
        (CkMechanismType::ECMQV_DERIVE, ecdh2(handles[4].0)),
        (CkMechanismType::ECMQV_DERIVE, ecmqv(handles[4].0, handles[5].0)),
        (CkMechanismType::X9_42_DH_HYBRID_DERIVE, x942_dh2(handles[6].0)),
        (CkMechanismType::X9_42_MQV_DERIVE, x942_mqv(handles[6].0, handles[7].0)),
    ] {
        let base_key = live_key(&backend, session);
        let mechanism = CkMechanism { mechanism_type, params: Some(params) };
        assert_ne!(
            backend
                .derive_key(session, &mechanism, base_key, Some(&[label_attr("valid")]))
                .unwrap(),
            CkObjectHandle(0)
        );
    }
}

#[test]
fn derive_key_with_output_returns_configured_tls_output_params() {
    let backend =
        MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::TLS12_MASTER_KEY_DERIVE]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mechanism =
        CkMechanism { mechanism_type: CkMechanismType::TLS12_MASTER_KEY_DERIVE, params: None };
    let output = CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
        random_info: SslRandomData { client_random: vec![0x11; 32], server_random: vec![0x22; 32] },
        version_major: 3,
        version_minor: 3,
        prf_hash_mechanism: CkMechanismType::SHA256.0,
    });
    backend.set_derive_key_output(Some(output.clone()));
    let base_key = live_key(&backend, session);

    let (handle, mechanism_out) =
        backend.derive_key_with_output(session, &mechanism, base_key, Some(&[])).unwrap();

    assert_ne!(handle, CkObjectHandle(0));
    assert_eq!(mechanism_out, Some(output));
}

#[test]
fn derive_key_with_output_returns_configured_pbe_iv_output_params() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType(0x0000_03A0)]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mechanism = CkMechanism { mechanism_type: CkMechanismType(0x0000_03A0), params: None };
    let output = CkMechanismParams::Pbe(PbeParams {
        init_vector: vec![0x5A; 8].into(),
        password: b"password".to_vec().into(),
        salt: b"salt".to_vec().into(),
        iteration: 4096,
    });
    backend.set_derive_key_output(Some(output.clone()));
    let base_key = live_key(&backend, session);

    let (handle, mechanism_out) =
        backend.derive_key_with_output(session, &mechanism, base_key, Some(&[])).unwrap();

    assert_ne!(handle, CkObjectHandle(0));
    assert_eq!(mechanism_out, Some(output));
}

#[test]
fn derive_key_with_sp800_108_additional_keys_allocates_output_handles() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);

    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CKM_SP800_108_COUNTER_KDF]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_COUNTER_KDF,
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CKM_SHA256_HMAC,
            data_params: vec![sp800_108_counter_iteration_param()],
            additional_derived_keys: vec![
                Sp800108DerivedKey {
                    template: vec![CkAttribute {
                        attr_type: CkAttributeType::VALUE_LEN,
                        value: Some(CkAttributeValue::Ulong(32)),
                    }],
                    key_handle: 0,
                },
                Sp800108DerivedKey {
                    template: vec![CkAttribute {
                        attr_type: CkAttributeType::LABEL,
                        value: Some(CkAttributeValue::String("extra".to_string().into())),
                    }],
                    key_handle: 0,
                },
            ],
        })),
    };
    let base_key = live_key(&backend, session);

    let (primary, mechanism_out) =
        backend.derive_key_with_output(session, &mechanism, base_key, Some(&[])).unwrap();

    let Some(CkMechanismParams::Sp800108Kdf(output)) = mechanism_out else {
        panic!("expected SP800-108 output params");
    };
    assert_ne!(primary, CkObjectHandle(0));
    assert_eq!(output.additional_derived_keys.len(), 2);
    assert_ne!(output.additional_derived_keys[0].key_handle, 0);
    assert_ne!(output.additional_derived_keys[1].key_handle, 0);
    assert_ne!(
        output.additional_derived_keys[0].key_handle,
        output.additional_derived_keys[1].key_handle
    );
    assert_eq!(output.additional_derived_keys[0].template.len(), 1);
}

#[test]
fn derive_key_with_sp800_108_additional_key_handles_preserves_templates() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);
    const CKM_SP800_108_FEEDBACK_KDF: CkMechanismType = CkMechanismType(0x0000_03AD);

    for (mechanism_type, params) in [
        (
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![sp800_108_counter_iteration_param()],
                additional_derived_keys: vec![Sp800108DerivedKey {
                    template: vec![
                        CkAttribute {
                            attr_type: CkAttributeType::VALUE_LEN,
                            value: Some(CkAttributeValue::Ulong(48)),
                        },
                        CkAttribute {
                            attr_type: CkAttributeType::LABEL,
                            value: Some(CkAttributeValue::String("sp800 extra".to_string().into())),
                        },
                    ],
                    key_handle: 0,
                }],
            }),
        ),
        (
            CKM_SP800_108_FEEDBACK_KDF,
            CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![sp800_108_null_iteration_param()],
                iv: vec![0xA5; 16],
                additional_derived_keys: vec![Sp800108DerivedKey {
                    template: vec![
                        CkAttribute {
                            attr_type: CkAttributeType::VALUE_LEN,
                            value: Some(CkAttributeValue::Ulong(48)),
                        },
                        CkAttribute {
                            attr_type: CkAttributeType::LABEL,
                            value: Some(CkAttributeValue::String("sp800 extra".to_string().into())),
                        },
                    ],
                    key_handle: 0,
                }],
            }),
        ),
    ] {
        let backend = MockBackend::new(vec![CkSlotId(0)], vec![mechanism_type]);
        backend.initialize().unwrap();
        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let base_key = live_key(&backend, session);
        let mechanism = CkMechanism { mechanism_type, params: Some(params) };

        let (_, mechanism_out) =
            backend.derive_key_with_output(session, &mechanism, base_key, Some(&[])).unwrap();
        let additional_key = match mechanism_out {
            Some(CkMechanismParams::Sp800108Kdf(output)) => {
                CkObjectHandle(output.additional_derived_keys[0].key_handle)
            }
            Some(CkMechanismParams::Sp800108FeedbackKdf(output)) => {
                CkObjectHandle(output.additional_derived_keys[0].key_handle)
            }
            other => panic!("expected SP800-108 output params, got {other:?}"),
        };

        let (rv, size_results) = backend
            .get_attribute_value_exact(
                session,
                additional_key,
                &[
                    CkAttributeQuery {
                        attr_type: CkAttributeType::VALUE_LEN,
                        buffer_present: false,
                        buffer_len: 0,
                        nested: None,
                    },
                    CkAttributeQuery {
                        attr_type: CkAttributeType::LABEL,
                        buffer_present: false,
                        buffer_len: 0,
                        nested: None,
                    },
                ],
            )
            .unwrap();
        assert_eq!(rv, CkRv::OK);
        assert_eq!(
            size_results[0].returned_len,
            std::mem::size_of::<cryptoki_sys::CK_ULONG>() as u64
        );
        assert_eq!(size_results[1].returned_len, "sp800 extra".len() as u64);

        let (rv, data_results) = backend
            .get_attribute_value_exact(
                session,
                additional_key,
                &[
                    CkAttributeQuery {
                        attr_type: CkAttributeType::VALUE_LEN,
                        buffer_present: true,
                        buffer_len: size_results[0].returned_len,
                        nested: None,
                    },
                    CkAttributeQuery {
                        attr_type: CkAttributeType::LABEL,
                        buffer_present: true,
                        buffer_len: size_results[1].returned_len,
                        nested: None,
                    },
                ],
            )
            .unwrap();
        assert_eq!(rv, CkRv::OK);
        assert_eq!(
            data_results[0].value,
            Some(SecretBytes::new((48 as cryptoki_sys::CK_ULONG).to_le_bytes().to_vec()))
        );
        assert_eq!(data_results[1].value, Some(SecretBytes::new(b"sp800 extra".to_vec())));
    }
}

#[test]
fn derive_key_with_sp800_108_enforces_mode_data_param_rules() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);
    const CKM_SP800_108_FEEDBACK_KDF: CkMechanismType = CkMechanismType(0x0000_03AD);
    const CKM_SP800_108_DOUBLE_PIPELINE_KDF: CkMechanismType = CkMechanismType(0x0000_03AE);
    const CK_SP800_108_COUNTER: u64 = 0x0000_0002;

    let counter_field = PrfDataParam { type_: CK_SP800_108_COUNTER, value: vec![0; 16].into() };
    for (name, mechanism_type, params) in [
        (
            "counter mode missing iteration variable",
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: Vec::new(),
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "feedback mode missing iteration variable",
            CKM_SP800_108_FEEDBACK_KDF,
            CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: Vec::new(),
                iv: vec![0xA5; 16],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "double-pipeline mode missing iteration variable",
            CKM_SP800_108_DOUBLE_PIPELINE_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: Vec::new(),
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "counter mode rejects CK_SP800_108_COUNTER",
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![sp800_108_counter_iteration_param(), counter_field.clone()],
                additional_derived_keys: Vec::new(),
            }),
        ),
    ] {
        let backend = MockBackend::new(vec![CkSlotId(0)], vec![mechanism_type]);
        backend.initialize().unwrap();
        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let base_key = live_key(&backend, session);
        let mechanism = CkMechanism { mechanism_type, params: Some(params) };

        let err =
            backend.derive_key_with_output(session, &mechanism, base_key, Some(&[])).unwrap_err();

        assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID, "{name}");
        assert_eq!(
            backend.destroy_object(session, CkObjectHandle(base_key.0 + 1)).unwrap_err(),
            CkRv::OBJECT_HANDLE_INVALID,
            "{name} must not allocate a primary derived object"
        );
    }
}

#[test]
fn derive_key_with_sp800_108_validates_data_param_payload_shapes_and_singletons() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);
    const CKM_SP800_108_FEEDBACK_KDF: CkMechanismType = CkMechanismType(0x0000_03AD);
    const CKM_SP800_108_DOUBLE_PIPELINE_KDF: CkMechanismType = CkMechanismType(0x0000_03AE);
    const CK_SP800_108_ITERATION_VARIABLE: u64 = 0x0000_0001;
    const CK_SP800_108_COUNTER: u64 = 0x0000_0002;
    const CK_SP800_108_DKM_LENGTH: u64 = 0x0000_0003;
    const CK_SP800_108_BYTE_ARRAY: u64 = 0x0000_0004;

    let counter_format = sp800_108_counter_format_bytes();
    let dkm_length_format = sp800_108_dkm_length_format_bytes();
    let short_counter_format = vec![0; counter_format.len() - 1];
    let short_dkm_length_format = vec![0; dkm_length_format.len() - 1];

    let cases = vec![
        (
            "counter mode iteration variable requires counter-format payload",
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![PrfDataParam {
                    type_: CK_SP800_108_ITERATION_VARIABLE,
                    value: Vec::new().into(),
                }],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "feedback counter data field requires counter-format payload",
            CKM_SP800_108_FEEDBACK_KDF,
            CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_null_iteration_param(),
                    PrfDataParam {
                        type_: CK_SP800_108_COUNTER,
                        value: short_counter_format.clone().into(),
                    },
                ],
                iv: vec![0xA5; 16],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "double-pipeline DKM length data field requires DKM-format payload",
            CKM_SP800_108_DOUBLE_PIPELINE_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_null_iteration_param(),
                    PrfDataParam {
                        type_: CK_SP800_108_DKM_LENGTH,
                        value: short_dkm_length_format.into(),
                    },
                ],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "BYTE_ARRAY data field requires non-empty payload",
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_counter_iteration_param(),
                    PrfDataParam { type_: CK_SP800_108_BYTE_ARRAY, value: Vec::new().into() },
                ],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "feedback counter data field is single-instance",
            CKM_SP800_108_FEEDBACK_KDF,
            CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_null_iteration_param(),
                    PrfDataParam {
                        type_: CK_SP800_108_COUNTER,
                        value: counter_format.clone().into(),
                    },
                    PrfDataParam { type_: CK_SP800_108_COUNTER, value: counter_format.into() },
                ],
                iv: vec![0xA5; 16],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "DKM length data field is single-instance",
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_counter_iteration_param(),
                    PrfDataParam {
                        type_: CK_SP800_108_DKM_LENGTH,
                        value: dkm_length_format.clone().into(),
                    },
                    PrfDataParam {
                        type_: CK_SP800_108_DKM_LENGTH,
                        value: dkm_length_format.into(),
                    },
                ],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            "DKM length data field rejects unknown method",
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_counter_iteration_param(),
                    PrfDataParam {
                        type_: CK_SP800_108_DKM_LENGTH,
                        value: sp800_108_dkm_length_format_bytes_with_method(0xDEAD_BEEF).into(),
                    },
                ],
                additional_derived_keys: Vec::new(),
            }),
        ),
    ];

    for (name, mechanism_type, params) in cases {
        let backend = MockBackend::new(vec![CkSlotId(0)], vec![mechanism_type]);
        backend.initialize().unwrap();
        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let base_key = live_key(&backend, session);
        let mechanism = CkMechanism { mechanism_type, params: Some(params) };

        let err =
            backend.derive_key_with_output(session, &mechanism, base_key, Some(&[])).unwrap_err();

        assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID, "{name}");
        assert_eq!(
            backend.destroy_object(session, CkObjectHandle(base_key.0 + 1)).unwrap_err(),
            CkRv::OBJECT_HANDLE_INVALID,
            "{name} must not allocate a primary derived object"
        );
    }
}

#[test]
fn derive_key_with_sp800_108_key_handle_data_param_requires_live_input_key() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);
    const CKM_SP800_108_FEEDBACK_KDF: CkMechanismType = CkMechanismType(0x0000_03AD);
    const CK_SP800_108_KEY_HANDLE: u64 = 0x0000_0005;

    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![CKM_SP800_108_COUNTER_KDF, CKM_SP800_108_FEEDBACK_KDF],
    );
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let base_key = live_key(&backend, session);

    for (mechanism_type, params) in [
        (
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_counter_iteration_param(),
                    PrfDataParam {
                        type_: CK_SP800_108_KEY_HANDLE,
                        value: 0xBAD_u64.to_ne_bytes().to_vec().into(),
                    },
                ],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            CKM_SP800_108_FEEDBACK_KDF,
            CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_null_iteration_param(),
                    PrfDataParam {
                        type_: CK_SP800_108_KEY_HANDLE,
                        value: 0xBAD_u64.to_ne_bytes().to_vec().into(),
                    },
                ],
                iv: Vec::new(),
                additional_derived_keys: Vec::new(),
            }),
        ),
    ] {
        let mechanism = CkMechanism { mechanism_type, params: Some(params) };
        let err =
            backend.derive_key_with_output(session, &mechanism, base_key, Some(&[])).unwrap_err();

        assert_eq!(err, CkRv::OBJECT_HANDLE_INVALID);
    }
}

#[test]
fn derive_key_with_sp800_108_key_handle_data_param_accepts_live_input_key() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);
    const CKM_SP800_108_FEEDBACK_KDF: CkMechanismType = CkMechanismType(0x0000_03AD);
    const CK_SP800_108_KEY_HANDLE: u64 = 0x0000_0005;

    let backend = MockBackend::new(
        vec![CkSlotId(0)],
        vec![CKM_SP800_108_COUNTER_KDF, CKM_SP800_108_FEEDBACK_KDF],
    );
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let input_key = backend.create_object(session, Some(&[])).unwrap();

    for (mechanism_type, params) in [
        (
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_counter_iteration_param(),
                    PrfDataParam {
                        type_: CK_SP800_108_KEY_HANDLE,
                        value: input_key.0.to_ne_bytes().to_vec().into(),
                    },
                ],
                additional_derived_keys: Vec::new(),
            }),
        ),
        (
            CKM_SP800_108_FEEDBACK_KDF,
            CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![
                    sp800_108_null_iteration_param(),
                    PrfDataParam {
                        type_: CK_SP800_108_KEY_HANDLE,
                        value: input_key.0.to_ne_bytes().to_vec().into(),
                    },
                ],
                iv: Vec::new(),
                additional_derived_keys: Vec::new(),
            }),
        ),
    ] {
        let mechanism = CkMechanism { mechanism_type, params: Some(params) };
        let (derived, mechanism_out) =
            backend.derive_key_with_output(session, &mechanism, input_key, Some(&[])).unwrap();

        assert_ne!(derived, CkObjectHandle(0));
        assert_eq!(mechanism_out, None);
    }
}

#[test]
fn derive_key_preserves_primary_key_template() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::SHA256]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let base_key = live_key(&backend, session);
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };

    let derived_key = backend
        .derive_key(
            session,
            &mechanism,
            base_key,
            Some(&[
                CkAttribute {
                    attr_type: CkAttributeType::VALUE_LEN,
                    value: Some(CkAttributeValue::Ulong(24)),
                },
                CkAttribute {
                    attr_type: CkAttributeType::LABEL,
                    value: Some(CkAttributeValue::String("primary derive".to_string().into())),
                },
            ]),
        )
        .unwrap();

    let mut template = vec![
        CkAttribute { attr_type: CkAttributeType::VALUE_LEN, value: None },
        CkAttribute { attr_type: CkAttributeType::LABEL, value: None },
    ];
    backend.get_attribute_value(session, derived_key, &mut template).unwrap();

    assert_eq!(template[0].value, Some(CkAttributeValue::Ulong(24)));
    assert_eq!(
        template[1].value,
        Some(CkAttributeValue::String("primary derive".to_string().into()))
    );
}

#[test]
fn derive_key_with_sp800_108_additional_key_handles_rejects_small_attribute_buffers() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);

    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CKM_SP800_108_COUNTER_KDF]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_COUNTER_KDF,
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CKM_SHA256_HMAC,
            data_params: vec![sp800_108_counter_iteration_param()],
            additional_derived_keys: vec![Sp800108DerivedKey {
                template: vec![CkAttribute {
                    attr_type: CkAttributeType::LABEL,
                    value: Some(CkAttributeValue::String("sp800 extra".to_string().into())),
                }],
                key_handle: 0,
            }],
        })),
    };
    let base_key = live_key(&backend, session);

    let (_, mechanism_out) =
        backend.derive_key_with_output(session, &mechanism, base_key, Some(&[])).unwrap();
    let Some(CkMechanismParams::Sp800108Kdf(output)) = mechanism_out else {
        panic!("expected SP800-108 output params");
    };
    let additional_key = CkObjectHandle(output.additional_derived_keys[0].key_handle);

    let (rv, results) = backend
        .get_attribute_value_exact(
            session,
            additional_key,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::LABEL,
                buffer_present: true,
                buffer_len: 4,
                nested: None,
            }],
        )
        .unwrap();
    assert_eq!(rv, CkRv::BUFFER_TOO_SMALL);
    assert_eq!(results[0].returned_len, u64::MAX);
    assert_eq!(results[0].ck_rv, Some(CkRv::BUFFER_TOO_SMALL));
    assert_eq!(results[0].value, None);
}

#[test]
fn close_session_clears_sp800_108_session_keys_but_preserves_token_keys() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);

    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CKM_SP800_108_COUNTER_KDF]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let base_key = live_key(&backend, session);
    let session_mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_COUNTER_KDF,
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CKM_SHA256_HMAC,
            data_params: vec![sp800_108_counter_iteration_param()],
            additional_derived_keys: vec![Sp800108DerivedKey {
                template: vec![label_attr("session-extra")],
                key_handle: 0,
            }],
        })),
    };
    let token_mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_COUNTER_KDF,
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CKM_SHA256_HMAC,
            data_params: vec![sp800_108_counter_iteration_param()],
            additional_derived_keys: vec![Sp800108DerivedKey {
                template: vec![
                    CkAttribute {
                        attr_type: CkAttributeType::TOKEN,
                        value: Some(CkAttributeValue::Bool(true)),
                    },
                    label_attr("token-extra"),
                ],
                key_handle: 0,
            }],
        })),
    };

    let (session_primary, session_output) = backend
        .derive_key_with_output(
            session,
            &session_mechanism,
            base_key,
            Some(&[label_attr("session-primary")]),
        )
        .unwrap();
    let session_extra = match session_output {
        Some(CkMechanismParams::Sp800108Kdf(output)) => {
            CkObjectHandle(output.additional_derived_keys[0].key_handle)
        }
        other => panic!("expected SP800-108 output params, got {other:?}"),
    };
    let (token_primary, token_output) = backend
        .derive_key_with_output(
            session,
            &token_mechanism,
            base_key,
            Some(&[
                CkAttribute {
                    attr_type: CkAttributeType::TOKEN,
                    value: Some(CkAttributeValue::Bool(true)),
                },
                label_attr("token-primary"),
            ]),
        )
        .unwrap();
    let token_extra = match token_output {
        Some(CkMechanismParams::Sp800108Kdf(output)) => {
            CkObjectHandle(output.additional_derived_keys[0].key_handle)
        }
        other => panic!("expected SP800-108 output params, got {other:?}"),
    };

    assert_mock_label(&backend, session, session_primary, "session-primary");
    assert_mock_label(&backend, session, session_extra, "session-extra");
    assert_mock_label(&backend, session, token_primary, "token-primary");
    assert_mock_label(&backend, session, token_extra, "token-extra");

    backend.close_session(session).unwrap();
    let fresh_session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();

    for object in [session_primary, session_extra] {
        assert_eq!(
            backend.get_object_size(fresh_session, object).unwrap_err(),
            CkRv::OBJECT_HANDLE_INVALID
        );
        assert_eq!(
            backend
                .get_attribute_value_exact(
                    fresh_session,
                    object,
                    &[CkAttributeQuery {
                        attr_type: CkAttributeType::LABEL,
                        buffer_present: false,
                        buffer_len: 0,
                        nested: None,
                    }],
                )
                .unwrap_err(),
            CkRv::OBJECT_HANDLE_INVALID
        );
    }
    assert_mock_label(&backend, fresh_session, token_primary, "token-primary");
    assert_mock_label(&backend, fresh_session, token_extra, "token-extra");
}

#[test]
fn derive_key_with_sp800_108_additional_keys_does_not_partially_allocate_on_quota_failure() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);
    const CKM_SP800_108_FEEDBACK_KDF: CkMechanismType = CkMechanismType(0x0000_03AD);

    for (mechanism_type, params) in [
        (
            CKM_SP800_108_COUNTER_KDF,
            CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![sp800_108_counter_iteration_param()],
                additional_derived_keys: vec![
                    Sp800108DerivedKey { template: Vec::new(), key_handle: 0 },
                    Sp800108DerivedKey { template: Vec::new(), key_handle: 0 },
                ],
            }),
        ),
        (
            CKM_SP800_108_FEEDBACK_KDF,
            CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CKM_SHA256_HMAC,
                data_params: vec![sp800_108_null_iteration_param()],
                iv: vec![0xA5; 16],
                additional_derived_keys: vec![
                    Sp800108DerivedKey { template: Vec::new(), key_handle: 0 },
                    Sp800108DerivedKey { template: Vec::new(), key_handle: 0 },
                ],
            }),
        ),
    ] {
        let backend = MockBackend::new(vec![CkSlotId(0)], vec![mechanism_type]).with_quotas(0, 3);
        backend.initialize().unwrap();
        let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let base_key = live_key(&backend, session);
        let mechanism = CkMechanism { mechanism_type, params: Some(params) };

        let err =
            backend.derive_key_with_output(session, &mechanism, base_key, Some(&[])).unwrap_err();

        assert_eq!(err, CkRv::DEVICE_MEMORY);
        assert_eq!(
            backend.destroy_object(session, CkObjectHandle(base_key.0 + 1)).unwrap_err(),
            CkRv::OBJECT_HANDLE_INVALID,
            "failed SP800-108 derive must not leak the primary derived object"
        );
        assert_eq!(
            backend.destroy_object(session, CkObjectHandle(base_key.0 + 2)).unwrap_err(),
            CkRv::OBJECT_HANDLE_INVALID,
            "failed SP800-108 derive must not leak a partially allocated additional object"
        );
    }
}

#[test]
fn derive_key_with_sp800_108_template_failure_reports_invalid_additional_handle() {
    const CKM_SP800_108_COUNTER_KDF: CkMechanismType = CkMechanismType(0x0000_03AC);
    const SENTINEL_HANDLE: u64 = 0xCAFE_BABE;

    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CKM_SP800_108_COUNTER_KDF]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let base_key = live_key(&backend, session);
    let mechanism = CkMechanism {
        mechanism_type: CKM_SP800_108_COUNTER_KDF,
        params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CKM_SHA256_HMAC,
            data_params: vec![sp800_108_counter_iteration_param()],
            additional_derived_keys: vec![
                Sp800108DerivedKey {
                    template: vec![CkAttribute {
                        attr_type: CkAttributeType::VALUE_LEN,
                        value: Some(CkAttributeValue::Ulong(32)),
                    }],
                    key_handle: SENTINEL_HANDLE,
                },
                Sp800108DerivedKey {
                    template: vec![CkAttribute {
                        attr_type: CkAttributeType::VALUE_LEN,
                        value: Some(CkAttributeValue::Ulong(0)),
                    }],
                    key_handle: SENTINEL_HANDLE,
                },
            ],
        })),
    };

    let result = backend
        .derive_key_with_output_result(session, &mechanism, base_key, Some(&[]))
        .expect("mock backend call should return a structured PKCS#11 result");

    assert_eq!(result.rv, CkRv::TEMPLATE_INCONSISTENT);
    assert_eq!(result.key_handle, None);
    let Some(CkMechanismParams::Sp800108Kdf(output)) = result.mechanism_out else {
        panic!("expected SP800-108 mechanism output on template failure");
    };
    assert_eq!(output.additional_derived_keys[0].key_handle, SENTINEL_HANDLE);
    assert_eq!(output.additional_derived_keys[1].key_handle, 0);
    assert_eq!(
        backend.destroy_object(session, CkObjectHandle(base_key.0 + 1)).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID,
        "failed SP800-108 derive must not leak the primary derived object"
    );
}

#[test]
fn derived_object_stores_its_template_attributes() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let template = [CkAttribute {
        attr_type: CkAttributeType::VALUE_LEN,
        value: Some(CkAttributeValue::Ulong(32)),
    }];
    let base_key = backend.create_object(session, Some(&[])).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    let derived = backend.derive_key(session, &mech, base_key, Some(&template)).unwrap();
    let (rv, results) = backend
        .get_attribute_value_exact(
            session,
            derived,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::VALUE_LEN,
                buffer_present: false,
                buffer_len: 0,
                nested: None,
            }],
        )
        .unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(
        results[0].returned_len as usize,
        std::mem::size_of::<cryptoki_sys::CK_ULONG>(),
        "derived object's template ulong is readable"
    );
}
