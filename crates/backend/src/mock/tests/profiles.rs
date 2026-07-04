use super::*;

#[test]
fn full_registry_mock_advertises_every_default_registered_mechanism() {
    let registry = MechanismRegistry::load_with_override_str(None).unwrap();
    let expected = registry
        .registered_mechanisms()
        .into_iter()
        .map(|x| CkMechanismType(x as u64))
        .collect::<Vec<_>>();
    let backend = MockBackend::with_mechanism_registry(vec![CkSlotId(0)], &registry);

    let advertised = backend.get_mechanism_list(CkSlotId(0)).unwrap();

    assert_eq!(advertised, expected);
    for mechanism in advertised {
        assert!(
            backend.get_mechanism_info(CkSlotId(0), mechanism).is_ok(),
            "mechanism 0x{:08X} should have mock mechanism info",
            mechanism.0
        );
    }
}

#[test]
fn official_mechanism_mock_advertises_provider_gap_mechanisms() {
    let backend = MockBackend::with_official_mechanisms(vec![CkSlotId(0)]);
    let advertised = backend.get_mechanism_list(CkSlotId(0)).unwrap();

    assert_eq!(advertised, pkcs11_3_2_official_mechanisms());
    assert!(advertised.contains(&CkMechanismType(0x0000_001F))); // CKM_HASH_ML_DSA
    assert!(advertised.contains(&CkMechanismType(0x0000_002E))); // CKM_SLH_DSA
    assert!(advertised.contains(&CkMechanismType(0x0000_03D5))); // CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE
    assert!(advertised.contains(&CkMechanismType(0x0000_4037))); // CKM_XMSSMT
}

#[test]
fn mechanism_bearing_workflows_reject_unadvertised_mechanisms() {
    let output_spec = CkOutputBufferSpec { buffer_present: true, buffer_len: 64 };
    let param_spec = CkParameterRoundtripSpec { buffer_present: true, buffer_len: 16, value: None };

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(backend.sign_init(session, &mechanism, key).unwrap_err(), CkRv::MECHANISM_INVALID);

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(backend.verify_init(session, &mechanism, key).unwrap_err(), CkRv::MECHANISM_INVALID);

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.sign_recover_init(session, &mechanism, key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.verify_recover_init(session, &mechanism, key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, _, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(backend.digest_init(session, &mechanism).unwrap_err(), CkRv::MECHANISM_INVALID);

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.encrypt_init(session, &mechanism, key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.decrypt_init(session, &mechanism, key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.derive_key(session, &mechanism, key, &[]).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.derive_key_with_output(session, &mechanism, key, &[]).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, other_key, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.wrap_key(session, &mechanism, key, other_key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.unwrap_key(session, &mechanism, key, CkInBuf::Bytes(b"wrapped"), &[]).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, _, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.generate_key(session, &mechanism, &[]).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, _, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.generate_key_pair(session, &mechanism, &[], &[]).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, other_key, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.wrap_key_exact(session, &mechanism, key, other_key, &output_spec).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, other_key, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend
            .wrap_key_exact_with_output(session, &mechanism, key, other_key, &output_spec)
            .unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.encapsulate_key(session, &mechanism, key, &[]).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.encapsulate_key_exact(session, &mechanism, key, &[], &output_spec).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend
            .decapsulate_key(session, &mechanism, key, &[], CkInBuf::Bytes(b"ciphertext"))
            .unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.message_encrypt_init(session, Some(&mechanism), None, key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.message_decrypt_init(session, Some(&mechanism), None, key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.message_sign_init(session, Some(&mechanism), key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend.message_verify_init(session, Some(&mechanism), key).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend
            .verify_signature_init(session, Some(&mechanism), key, CkInBuf::Bytes(b"sig"))
            .unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, other_key, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend
            .wrap_key_authenticated(session, &mechanism, key, other_key, CkInBuf::Bytes(b"aad"))
            .unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, _, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend
            .unwrap_key_authenticated(
                session,
                &mechanism,
                key,
                CkInBuf::Bytes(b"wrapped"),
                &[],
                CkInBuf::Bytes(b"aad")
            )
            .unwrap_err(),
        CkRv::MECHANISM_INVALID
    );

    let (backend, session, key, other_key, mechanism) = unsupported_mechanism_fixture();
    assert_eq!(
        backend
            .wrap_key_authenticated_exact(
                session,
                &mechanism,
                key,
                other_key,
                CkInBuf::Bytes(b"aad"),
                &output_spec,
                &param_spec,
            )
            .unwrap_err(),
        CkRv::MECHANISM_INVALID
    );
}

#[test]
fn ilp32_profile_emits_4_byte_ulongs() {
    let backend = MockBackend::default_test().with_abi(MockAbi::Ilp32);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let object = backend.create_object(session, &[]).unwrap();
    backend.set_attribute(
        object,
        CkAttributeType::CLASS,
        MockAttributeSlot::Value(CkAttributeValue::Ulong(3)),
    );

    let size_query = [CkAttributeQuery {
        attr_type: CkAttributeType::CLASS,
        buffer_present: false,
        buffer_len: 0,
        nested: None,
    }];
    let (rv, results) = backend.get_attribute_value_exact(session, object, &size_query).unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(results[0].returned_len, 4, "ILP32 backend reports 4-byte ulong lengths");

    let data_query = [CkAttributeQuery {
        attr_type: CkAttributeType::CLASS,
        buffer_present: true,
        buffer_len: 4,
        nested: None,
    }];
    let (rv, results) = backend.get_attribute_value_exact(session, object, &data_query).unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(results[0].value, Some(vec![3, 0, 0, 0]), "value bytes at emulated width");
}

#[test]
fn llp64_profile_reports_16_byte_attribute_stride() {
    let backend = MockBackend::default_test().with_abi(MockAbi::Llp64);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let object = backend.create_object(session, &[]).unwrap();
    backend.set_attribute(
        object,
        CkAttributeType::WRAP_TEMPLATE,
        MockAttributeSlot::NestedTemplate(vec![
            (CkAttributeType::CLASS, MockAttributeSlot::Value(CkAttributeValue::Ulong(3))),
            (CkAttributeType::KEY_TYPE, MockAttributeSlot::Value(CkAttributeValue::Ulong(31))),
        ]),
    );

    // Pure size query: the wire length is the BACKEND-layout template size.
    let size_query = [CkAttributeQuery {
        attr_type: CkAttributeType::WRAP_TEMPLATE,
        buffer_present: false,
        buffer_len: 0,
        nested: None,
    }];
    let (rv, results) = backend.get_attribute_value_exact(session, object, &size_query).unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(results[0].returned_len, 2 * 16, "LLP64 packed CK_ATTRIBUTE stride is 16");

    // Data query: ulong sub-values are 4 bytes wide on this profile.
    let data_query = [CkAttributeQuery {
        attr_type: CkAttributeType::WRAP_TEMPLATE,
        buffer_present: true,
        buffer_len: 2 * 16,
        nested: Some(vec![
            CkAttributeQuery {
                attr_type: CkAttributeType::CLASS,
                buffer_present: true,
                buffer_len: 4,
                nested: None,
            },
            CkAttributeQuery {
                attr_type: CkAttributeType::KEY_TYPE,
                buffer_present: true,
                buffer_len: 4,
                nested: None,
            },
        ]),
    }];
    let (rv, results) = backend.get_attribute_value_exact(session, object, &data_query).unwrap();
    assert_eq!(rv, CkRv::OK);
    let nested = results[0].nested.as_ref().expect("nested results");
    assert_eq!(nested[0].value, Some(vec![3, 0, 0, 0]));
    assert_eq!(nested[1].value, Some(vec![31, 0, 0, 0]));
}

#[test]
fn mock_advertises_its_profile_not_the_host() {
    let narrow = MockBackend::default_test().with_abi(MockAbi::Ilp32);
    assert_eq!(narrow.abi_ulong_size(), 4);
    assert_eq!(narrow.abi_attribute_stride(), 12);
    assert_eq!(narrow.abi_byte_order(), 1, "advertises little-endian by default");

    let llp64 = MockBackend::default_test().with_abi(MockAbi::Llp64);
    assert_eq!(llp64.abi_ulong_size(), 4);
    assert_eq!(llp64.abi_attribute_stride(), 16);

    let be = MockBackend::default_test().with_big_endian_advertisement();
    assert_eq!(be.abi_byte_order(), 2, "the D6-refusal knob claims big-endian");
}

#[test]
fn registry_backed_mock_validates_mechanism_param_presence() {
    let registry = MechanismRegistry::load(None).expect("embedded default registry");
    let backend = MockBackend::with_mechanism_registry(vec![CkSlotId(0)], &registry)
        .with_param_presence_validation(&registry);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let key = backend.create_object(session, &[]).unwrap();

    // A shaped mechanism without its parameters must be rejected like a
    // real token would reject it.
    let gcm_no_params = CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: None };
    assert_eq!(
        backend.encrypt_init(session, &gcm_no_params, key).unwrap_err(),
        CkRv::MECHANISM_PARAM_INVALID,
        "AES-GCM without params"
    );

    // A parameterless mechanism with stray parameters is equally invalid.
    let sha_with_params = CkMechanism {
        mechanism_type: CkMechanismType::SHA256,
        params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0; 16] })),
    };
    assert_eq!(
        backend.digest_init(session, &sha_with_params).unwrap_err(),
        CkRv::MECHANISM_PARAM_INVALID,
        "SHA-256 with stray params"
    );

    // The valid pairings still initialize.
    let sha = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    backend.digest_init(session, &sha).expect("parameterless SHA-256");
    backend.digest_init_cancel(session).unwrap();

    let gcm = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv: vec![0; 12],
            iv_bits: 96,
            iv_buffer_len: 12,
            aad: vec![],
            tag_bits: 128,
        })),
    };
    backend.encrypt_init(session, &gcm, key).expect("GCM with params");
}

#[test]
fn registryless_mock_stays_permissive_about_params() {
    // MockBackend::new has no registry: presence validation must not
    // engage (existing suites rely on plain mechanisms with params: None).
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_GCM]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let gcm_no_params = CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: None };
    let key = backend.create_object(session, &[]).unwrap();
    backend.encrypt_init(session, &gcm_no_params, key).expect("no registry, no validation");
}

#[test]
fn gcm_wrap_iv_generation_is_deterministic_and_preserves_fixed_prefix() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_GCM]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let key = backend.create_object(session, &[]).unwrap();

    let mech = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::GcmWrap(GcmWrapParams {
            iv: vec![0xA1, 0xA2, 0xA3, 0xA4, 0, 0, 0, 0, 0, 0, 0, 0],
            iv_fixed_bits: 32,
            iv_generator: 4, // CKG_GENERATE_RANDOM
            aad: vec![],
            tag_bits: 128,
        })),
    };

    let output = backend.encrypt_init(session, &mech, key).unwrap();
    let Some(CkMechanismParams::GcmWrap(generated)) = output else {
        panic!("generator != NO_GENERATE must yield writeback params, got {output:?}");
    };
    assert_eq!(generated.iv.len(), 12, "IV length preserved");
    assert_eq!(&generated.iv[..4], &[0xA1, 0xA2, 0xA3, 0xA4], "fixed prefix preserved");
    assert_ne!(&generated.iv[4..], &[0u8; 8][..], "generated tail is non-zero");

    // Determinism: the same session re-initializing gets the same IV.
    backend.encrypt_init_cancel(session).unwrap();
    let again = backend.encrypt_init(session, &mech, key).unwrap();
    assert_eq!(again, Some(CkMechanismParams::GcmWrap(generated)));

    // NO_GENERATE yields no writeback.
    backend.encrypt_init_cancel(session).unwrap();
    let mech_no_gen = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::GcmWrap(GcmWrapParams {
            iv: vec![0; 12],
            iv_fixed_bits: 0,
            iv_generator: 1, // CKG_NO_GENERATE
            aad: vec![],
            tag_bits: 128,
        })),
    };
    assert_eq!(backend.encrypt_init(session, &mech_no_gen, key).unwrap(), None);
}

#[test]
fn create_object_stores_template_attributes_for_read_back() {
    let backend = MockBackend::default_test().with_abi(MockAbi::Ilp32);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();

    const VENDOR_ATTR: u64 = 0x8000_0042;
    let template = [
        CkAttribute { attr_type: CkAttributeType::CLASS, value: Some(CkAttributeValue::Ulong(4)) },
        CkAttribute {
            attr_type: CkAttributeType::TOKEN,
            value: Some(CkAttributeValue::Bool(false)),
        },
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String("probe".into())),
        },
        // Vendor attribute: opaque bytes, D7 passthrough at ANY width.
        CkAttribute {
            attr_type: CkAttributeType(VENDOR_ATTR),
            value: Some(CkAttributeValue::Bytes(vec![9, 8, 7])),
        },
    ];
    let object = backend.create_object(session, &template).unwrap();

    let query = |attr_type: CkAttributeType, buffer_len: u64| CkAttributeQuery {
        attr_type,
        buffer_present: true,
        buffer_len,
        nested: None,
    };
    let (rv, results) = backend
        .get_attribute_value_exact(
            session,
            object,
            &[
                query(CkAttributeType::CLASS, 4),
                query(CkAttributeType::TOKEN, 1),
                query(CkAttributeType::LABEL, 5),
                query(CkAttributeType(VENDOR_ATTR), 3),
            ],
        )
        .unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(results[0].value, Some(vec![4, 0, 0, 0]), "ulong at the emulated width");
    assert_eq!(results[1].value, Some(vec![0]), "bool as one byte");
    assert_eq!(results[2].value, Some(b"probe".to_vec()), "string bytes");
    assert_eq!(results[3].value, Some(vec![9, 8, 7]), "vendor bytes pass through opaquely");
}

#[test]
fn generated_secret_key_value_has_requested_value_len() {
    // A real token generating an n-byte secret key sets CKA_VALUE to n
    // bytes; the mock synthesizes deterministic echo bytes of exactly
    // CKA_VALUE_LEN so read-after-generate looks authentic.
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_KEY_GEN]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::AES_KEY_GEN, params: None };
    let template = [CkAttribute {
        attr_type: CkAttributeType::VALUE_LEN,
        value: Some(CkAttributeValue::Ulong(32)),
    }];
    let key = backend.generate_key(session, &mech, &template).unwrap();

    let (rv, results) = backend
        .get_attribute_value_exact(
            session,
            key,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::VALUE,
                buffer_present: false,
                buffer_len: 0,
                nested: None,
            }],
        )
        .unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(results[0].returned_len, 32, "CKA_VALUE length matches CKA_VALUE_LEN");
}

#[test]
fn explicit_value_wins_over_value_len_synthesis() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_KEY_GEN]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::AES_KEY_GEN, params: None };
    let template = [
        CkAttribute {
            attr_type: CkAttributeType::VALUE_LEN,
            value: Some(CkAttributeValue::Ulong(16)),
        },
        CkAttribute {
            attr_type: CkAttributeType::VALUE,
            value: Some(CkAttributeValue::Bytes(vec![0xAB; 4])),
        },
    ];
    let key = backend.generate_key(session, &mech, &template).unwrap();
    let (_rv, results) = backend
        .get_attribute_value_exact(
            session,
            key,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::VALUE,
                buffer_present: false,
                buffer_len: 0,
                nested: None,
            }],
        )
        .unwrap();
    assert_eq!(results[0].returned_len, 4, "an explicit CKA_VALUE is not overridden");
}

#[test]
fn generate_key_synthesizes_class_and_key_type() {
    // A real token sets CKA_CLASS/CKA_KEY_TYPE (and CKA_LOCAL) on a
    // generated key from the mechanism, unless the template overrides.
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_KEY_GEN]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::AES_KEY_GEN, params: None };
    let key = backend.generate_key(session, &mech, &[]).unwrap();

    let query = |t: CkAttributeType| CkAttributeQuery {
        attr_type: t,
        buffer_present: true,
        buffer_len: 8,
        nested: None,
    };
    let (rv, results) = backend
        .get_attribute_value_exact(
            session,
            key,
            &[query(CkAttributeType::CLASS), query(CkAttributeType::KEY_TYPE)],
        )
        .unwrap();
    assert_eq!(rv, CkRv::OK);
    // CKO_SECRET_KEY = 4, CKK_AES = 0x1F, at the mock's emulated width.
    assert_eq!(results[0].value, Some(MockAbi::host().encode_ulong(4)), "CKA_CLASS");
    assert_eq!(results[1].value, Some(MockAbi::host().encode_ulong(0x1F)), "CKA_KEY_TYPE");
}

#[test]
fn generate_key_template_overrides_synthesized_class() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::AES_KEY_GEN]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::AES_KEY_GEN, params: None };
    let template = [CkAttribute {
        attr_type: CkAttributeType::CLASS,
        value: Some(CkAttributeValue::Ulong(0x99)),
    }];
    let key = backend.generate_key(session, &mech, &template).unwrap();
    let (_rv, results) = backend
        .get_attribute_value_exact(
            session,
            key,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::CLASS,
                buffer_present: true,
                buffer_len: 8,
                nested: None,
            }],
        )
        .unwrap();
    assert_eq!(
        results[0].value,
        Some(MockAbi::host().encode_ulong(0x99)),
        "template CKA_CLASS wins"
    );
}
