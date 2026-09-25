use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit production shim and exact native oracle library paths"]
async fn fix_round_one_attribute_ordinary_error_zero_ambiguity_is_absent() {
    let _guard = LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let harness = Harness::start().await;
    for nested in [false, true] {
        for (store, returned) in
            [(false, 0), (true, 0), (true, 7), (true, CK_UNAVAILABLE_INFORMATION)]
        {
            let mut sub =
                CK_ATTRIBUTE { type_: 0xdead, pValue: ptr::null_mut(), ulValueLen: 0xbeef };
            let mut attr = CK_ATTRIBUTE {
                type_: if nested { CKA_WRAP_TEMPLATE } else { CKA_LABEL },
                pValue: if nested {
                    (&mut sub as *mut CK_ATTRIBUTE).cast()
                } else {
                    ptr::null_mut()
                },
                ulValueLen: if nested { std::mem::size_of_val(&sub) as CK_ULONG } else { 0xbeef },
            };
            harness.scenario(ExactOracleScenario {
                rv: CKR_FUNCTION_FAILED as u64,
                length_action: u32::from(store),
                returned_length: returned as u64,
                ..Default::default()
            });
            assert_eq!(
                unsafe {
                    harness.functions.C_GetAttributeValue.unwrap()(
                        harness.session,
                        harness.key,
                        &mut attr,
                        1,
                    )
                },
                CKR_FUNCTION_FAILED
            );
            assert_eq!(harness.observation().calls, 1);
            assert_eq!(harness.observation().length_stores, u64::from(store));
            assert_eq!(
                if nested { sub.ulValueLen } else { attr.ulValueLen },
                if store && returned != 0 { returned } else { 0xbeef }
            );
            if nested {
                assert_eq!(sub.type_, 0xdead);
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit production shim and exact native oracle library paths"]
async fn fix_round_one_generated_outputs_respect_query_vs_begin() {
    let _guard = LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let harness = Harness::start().await;
    for ccm in [false, true] {
        for begin in [false, true] {
            for generator in [CKG_GENERATE_RANDOM, CKG_GENERATE_COUNTER_XOR] {
                for native_rv in [CKR_OK, CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED] {
                    let run = |functions: &CK_FUNCTION_LIST_3_2, session, key| {
                        let mut iv = [0x11u8; 12];
                        let mut tag = [0xa5u8; 16];
                        let mut gcm = CK_GCM_MESSAGE_PARAMS {
                            pIv: iv.as_mut_ptr(),
                            ulIvLen: 12,
                            ulIvFixedBits: 0,
                            ivGenerator: generator,
                            pTag: tag.as_mut_ptr(),
                            ulTagBits: 128,
                        };
                        let mut ccm_param = CK_CCM_MESSAGE_PARAMS {
                            ulDataLen: 0,
                            pNonce: iv.as_mut_ptr(),
                            ulNonceLen: 12,
                            ulNonceFixedBits: 0,
                            nonceGenerator: generator,
                            pMAC: tag.as_mut_ptr(),
                            ulMACLen: 16,
                        };
                        let (pp, pn) = if ccm {
                            (
                                (&mut ccm_param as *mut CK_CCM_MESSAGE_PARAMS).cast(),
                                std::mem::size_of_val(&ccm_param) as CK_ULONG,
                            )
                        } else {
                            (
                                (&mut gcm as *mut CK_GCM_MESSAGE_PARAMS).cast(),
                                std::mem::size_of_val(&gcm) as CK_ULONG,
                            )
                        };
                        let mut mechanism = CK_MECHANISM {
                            mechanism: if ccm { CKM_AES_CCM } else { CKM_AES_GCM },
                            pParameter: ptr::null_mut(),
                            ulParameterLen: 0,
                        };
                        assert_eq!(
                            unsafe {
                                functions.C_MessageEncryptInit.unwrap()(
                                    session,
                                    &mut mechanism,
                                    key,
                                )
                            },
                            CKR_OK
                        );
                        let action = if generator == CKG_GENERATE_COUNTER_XOR {
                            6
                        } else if begin {
                            5
                        } else {
                            0
                        };
                        harness.scenario(ExactOracleScenario {
                            rv: native_rv as u64,
                            parameter_action: action,
                            length_action: 1,
                            returned_length: 4,
                            ..Default::default()
                        });
                        let mut length = 77;
                        let rv = unsafe {
                            if begin {
                                functions.C_EncryptMessageBegin.unwrap()(
                                    session,
                                    pp,
                                    pn,
                                    ptr::null_mut(),
                                    0,
                                )
                            } else {
                                functions.C_EncryptMessage.unwrap()(
                                    session,
                                    pp,
                                    pn,
                                    ptr::null_mut(),
                                    0,
                                    ptr::null_mut(),
                                    0,
                                    ptr::null_mut(),
                                    &mut length,
                                )
                            }
                        };
                        assert_eq!(harness.observation().calls, 1);
                        assert_eq!(tag, [0xa5; 16]);
                        (rv, length, iv)
                    };
                    let direct = run(&harness.native, 1, 41);
                    let proxy = run(&harness.functions, harness.session, harness.key);
                    assert_eq!(
                        proxy, direct,
                        "ccm={ccm} begin={begin} generator={generator} rv={native_rv:#x}"
                    );
                    let mut expected = [0x11; 12];
                    if generator == CKG_GENERATE_COUNTER_XOR {
                        expected[0] = 0x42;
                    } else if begin && native_rv == CKR_OK {
                        expected.fill(0x42);
                    }
                    assert_eq!(direct.2, expected);
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit production shim and exact native oracle library paths"]
async fn fix_round_one_typed_parameter_query_data_mode_matrix() {
    let _guard = LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let harness = Harness::start().await;
    let mut failures = Vec::new();
    let mut cases = 0;
    for mechanism_type in [CKM_AES_GCM, CKM_AES_CCM, CKM_CHACHA20_POLY1305, CKM_SALSA20_POLY1305] {
        for operation in ["one-shot", "final-next", "authenticated-wrap"] {
            for shape in ["query", "null-length", "zero-capacity", "data"] {
                for native_rv in [CKR_OK, CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED] {
                    let run = |functions: &CK_FUNCTION_LIST_3_2, session, key| {
                        let mut iv = [0x11u8; 12];
                        let mut tag = [0xa5u8; 16];
                        let mut gcm = CK_GCM_MESSAGE_PARAMS {
                            pIv: iv.as_mut_ptr(),
                            ulIvLen: 12,
                            ulIvFixedBits: 0,
                            ivGenerator: CKG_NO_GENERATE,
                            pTag: tag.as_mut_ptr(),
                            ulTagBits: 128,
                        };
                        let mut ccm = CK_CCM_MESSAGE_PARAMS {
                            ulDataLen: 0,
                            pNonce: iv.as_mut_ptr(),
                            ulNonceLen: 12,
                            ulNonceFixedBits: 0,
                            nonceGenerator: CKG_NO_GENERATE,
                            pMAC: tag.as_mut_ptr(),
                            ulMACLen: 16,
                        };
                        let mut salsa = CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS {
                            pNonce: iv.as_mut_ptr(),
                            ulNonceLen: 96,
                            pTag: tag.as_mut_ptr(),
                        };
                        let (pp, pn) = match mechanism_type {
                            CKM_AES_GCM => (
                                (&mut gcm as *mut CK_GCM_MESSAGE_PARAMS).cast(),
                                std::mem::size_of_val(&gcm) as CK_ULONG,
                            ),
                            CKM_AES_CCM => (
                                (&mut ccm as *mut CK_CCM_MESSAGE_PARAMS).cast(),
                                std::mem::size_of_val(&ccm) as CK_ULONG,
                            ),
                            _ => (
                                (&mut salsa as *mut CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS).cast(),
                                std::mem::size_of_val(&salsa) as CK_ULONG,
                            ),
                        };
                        let mut mechanism = CK_MECHANISM {
                            mechanism: mechanism_type,
                            pParameter: ptr::null_mut(),
                            ulParameterLen: 0,
                        };
                        if operation != "authenticated-wrap" {
                            assert_eq!(
                                unsafe {
                                    functions.C_MessageEncryptInit.unwrap()(
                                        session,
                                        &mut mechanism,
                                        key,
                                    )
                                },
                                CKR_OK
                            );
                            if operation == "final-next" {
                                harness.scenario(ExactOracleScenario::default());
                                assert_eq!(
                                    unsafe {
                                        functions.C_EncryptMessageBegin.unwrap()(
                                            session,
                                            pp,
                                            pn,
                                            ptr::null_mut(),
                                            0,
                                        )
                                    },
                                    CKR_OK
                                );
                            }
                        }
                        let mut bytes = [0xb6u8; 8];
                        let mut length = if shape == "zero-capacity" { 0 } else { 8 };
                        let output =
                            if shape == "query" { ptr::null_mut() } else { bytes.as_mut_ptr() };
                        let length_pointer =
                            if shape == "null-length" { ptr::null_mut() } else { &mut length };
                        // For a zero-byte successful data operation, a present zero-capacity
                        // destination is still Data and the authentication tag is defined.
                        let returned_length = if shape == "zero-capacity" { 0 } else { 4 };
                        harness.scenario(ExactOracleScenario {
                            rv: native_rv as u64,
                            length_action: 1,
                            returned_length,
                            parameter_action: u32::from(matches!(shape, "data" | "zero-capacity")),
                            output_action: u32::from(shape == "data" && native_rv == CKR_OK),
                            ..Default::default()
                        });
                        let rv = unsafe {
                            match operation {
                                "one-shot" => functions.C_EncryptMessage.unwrap()(
                                    session,
                                    pp,
                                    pn,
                                    ptr::null_mut(),
                                    0,
                                    ptr::null_mut(),
                                    0,
                                    output,
                                    length_pointer,
                                ),
                                "final-next" => functions.C_EncryptMessageNext.unwrap()(
                                    session,
                                    pp,
                                    pn,
                                    ptr::null_mut(),
                                    0,
                                    output,
                                    length_pointer,
                                    CKF_END_OF_MESSAGE,
                                ),
                                _ => {
                                    mechanism.pParameter = pp;
                                    mechanism.ulParameterLen = pn;
                                    functions.C_WrapKeyAuthenticated.unwrap()(
                                        session,
                                        &mut mechanism,
                                        key,
                                        key,
                                        ptr::null_mut(),
                                        0,
                                        output,
                                        length_pointer,
                                    )
                                }
                            }
                        };
                        assert_eq!(
                            harness.observation().calls,
                            1,
                            "mechanism={mechanism_type:#x} operation={operation} shape={shape} native_rv={native_rv:#x} caller_rv={rv:#x} session={session}"
                        );
                        (rv, length, iv, tag, bytes)
                    };
                    let direct = run(&harness.native, 1, 41);
                    let proxy = run(&harness.functions, harness.session, harness.key);
                    cases += 1;
                    if direct != proxy {
                        failures.push((mechanism_type, operation, shape, native_rv, direct, proxy));
                    }
                }
            }
        }
    }
    println!("typed query/data matrix: {cases} direct/proxy cases, {} mismatches", failures.len());
    assert!(failures.is_empty(), "typed call-mode mismatches: {failures:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit production shim and exact native oracle library paths"]
async fn fix_round_one_legal_mixed_empty_attribute_queries() {
    let _guard = LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let harness = Harness::start().await;
    let mut failures = Vec::new();
    for rv in [CKR_OK, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL] {
        for nested in [false, true] {
            let run = |functions: &CK_FUNCTION_LIST_3_2, session, key| {
                let mut sub =
                    CK_ATTRIBUTE { type_: 0xdead, pValue: ptr::null_mut(), ulValueLen: 0xdead };
                let mut canary = [0xa5u8; 1];
                let mut attrs = [
                    CK_ATTRIBUTE {
                        type_: if nested { CKA_WRAP_TEMPLATE } else { CKA_LABEL },
                        pValue: if nested {
                            (&mut sub as *mut CK_ATTRIBUTE).cast()
                        } else {
                            ptr::null_mut()
                        },
                        ulValueLen: if nested {
                            std::mem::size_of::<CK_ATTRIBUTE>() as CK_ULONG
                        } else {
                            0xdead
                        },
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_VALUE,
                        pValue: if rv == CKR_BUFFER_TOO_SMALL {
                            canary.as_mut_ptr().cast()
                        } else {
                            ptr::null_mut()
                        },
                        ulValueLen: if rv == CKR_BUFFER_TOO_SMALL { 1 } else { 0xdead },
                    },
                ];
                harness.scenario(ExactOracleScenario {
                    rv: rv as u64,
                    parameter_action: 4,
                    ..Default::default()
                });
                let returned = unsafe {
                    functions.C_GetAttributeValue.unwrap()(session, key, attrs.as_mut_ptr(), 2)
                };
                assert_eq!(harness.observation().calls, 1);
                assert_eq!(harness.observation().length_stores, 2);
                assert_eq!(canary, [0xa5]);
                (
                    returned,
                    if nested { sub.ulValueLen } else { attrs[0].ulValueLen },
                    attrs[1].ulValueLen,
                    if nested { sub.type_ } else { attrs[0].type_ },
                )
            };
            let direct = run(&harness.native, 1, 41);
            let proxy = run(&harness.functions, harness.session, harness.key);
            println!("legal mixed rv={rv:#x} nested={nested} direct={direct:?} proxy={proxy:?}");
            assert_eq!(
                direct,
                (rv, 0, if rv == CKR_OK { 4 } else { CK_UNAVAILABLE_INFORMATION }, CKA_LABEL)
            );
            if direct != proxy {
                failures.push((rv, nested, direct, proxy));
            }
        }
    }
    assert!(failures.is_empty(), "legal empty-query effect mismatches: {failures:?}");
}

#[ignore = "requires explicit production shim and exact native oracle library paths"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fix_round_one_partial_attribute_zero_query_effects() {
    let _guard = LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let harness = Harness::start().await;
    let mut failures = Vec::new();
    for rv in [CKR_OK, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL] {
        for nested in [false, true] {
            let scenario = ExactOracleScenario {
                rv: rv as u64,
                length_action: 1,
                returned_length: 0,
                ..Default::default()
            };
            let run = |functions: &CK_FUNCTION_LIST_3_2, session, key| {
                let mut sub =
                    CK_ATTRIBUTE { type_: CKA_LABEL, pValue: ptr::null_mut(), ulValueLen: 0xdead };
                let mut outer = CK_ATTRIBUTE {
                    type_: if nested { CKA_WRAP_TEMPLATE } else { CKA_LABEL },
                    pValue: if nested {
                        (&mut sub as *mut CK_ATTRIBUTE).cast()
                    } else {
                        ptr::null_mut()
                    },
                    ulValueLen: if nested {
                        std::mem::size_of::<CK_ATTRIBUTE>() as CK_ULONG
                    } else {
                        0xdead
                    },
                };
                let returned =
                    unsafe { functions.C_GetAttributeValue.unwrap()(session, key, &mut outer, 1) };
                (returned, if nested { sub.ulValueLen } else { outer.ulValueLen })
            };
            harness.scenario(scenario);
            let direct = run(&harness.native, 1, 1);
            let direct_observed = harness.observation();
            harness.scenario(scenario);
            let proxy = run(&harness.functions, harness.session, harness.key);
            let proxy_observed = harness.observation();
            println!(
                "partial rv={rv:#x} nested={nested} direct={direct:?} proxy={proxy:?} direct_calls={} direct_stores={} proxy_calls={} proxy_stores={}",
                direct_observed.calls,
                direct_observed.length_stores,
                proxy_observed.calls,
                proxy_observed.length_stores
            );
            assert_eq!(proxy_observed.calls, 1);
            if direct != proxy {
                failures.push((rv, nested, direct, proxy));
            }
        }
    }
    assert!(failures.is_empty(), "defined zero query effects lost: {failures:?}");
}

#[ignore = "requires explicit production shim and exact native oracle library paths"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fix_round_one_exact_completion_health_classification() {
    use pkcs11_proxy_ng::server::grpc_service::service_utils::{
        BackendHealthEvent, configure_backend_health_events,
    };
    let _guard = LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let harness = Harness::start().await;
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    configure_backend_health_events(tx);
    let mut results = Vec::new();
    for (name, native_rv, capacity) in [
        ("native device removed", CKR_DEVICE_REMOVED, 8),
        ("pre-native capacity limit", CKR_OK, 512 * 1024 * 1024 + 1),
        ("native host memory", CKR_HOST_MEMORY, 8),
    ] {
        harness.scenario(ExactOracleScenario { rv: native_rv as u64, ..Default::default() });
        let mut output = [0xa5u8; 8];
        let mut length = capacity;
        let rv = unsafe {
            harness.functions.C_GetOperationState.unwrap()(
                harness.session,
                output.as_mut_ptr(),
                &mut length,
            )
        };
        let observation = harness.observation();
        let health = rx.try_recv().ok();
        println!(
            "{name}: rv={rv:#x}, native_calls={}, health={health:?}, length={length}",
            observation.calls
        );
        results.push((name, observation.calls, health));
    }
    let mut family_failures = Vec::new();
    for family in
        ["encrypt", "wrap", "attribute", "kem", "message", "next", "begin", "authenticated-wrap"]
    {
        for (provider_rv, reject_before_native) in
            [(CKR_DEVICE_REMOVED, false), (CKR_HOST_MEMORY, false), (CKR_OK, true)]
        {
            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_RSA_PKCS,
                pParameter: ptr::null_mut(),
                ulParameterLen: 0,
            };
            let mut iv = [0x11u8; 12];
            let mut tag = [0xa5u8; 16];
            let mut parameter = CK_GCM_MESSAGE_PARAMS {
                pIv: iv.as_mut_ptr(),
                ulIvLen: 12,
                ulIvFixedBits: 0,
                ivGenerator: CKG_NO_GENERATE,
                pTag: tag.as_mut_ptr(),
                ulTagBits: 128,
            };
            let pp = (&mut parameter as *mut CK_GCM_MESSAGE_PARAMS).cast();
            let pn = std::mem::size_of_val(&parameter) as CK_ULONG;
            harness.scenario(ExactOracleScenario::default());
            unsafe {
                if family == "encrypt" {
                    assert_eq!(
                        harness.functions.C_EncryptInit.unwrap()(
                            harness.session,
                            &mut mechanism,
                            harness.key
                        ),
                        CKR_OK
                    );
                }
                if matches!(family, "message" | "next" | "begin") {
                    mechanism.mechanism = CKM_AES_GCM;
                    assert_eq!(
                        harness.functions.C_MessageEncryptInit.unwrap()(
                            harness.session,
                            &mut mechanism,
                            harness.key
                        ),
                        CKR_OK
                    );
                    if family == "next" {
                        assert_eq!(
                            harness.functions.C_EncryptMessageBegin.unwrap()(
                                harness.session,
                                pp,
                                pn,
                                ptr::null_mut(),
                                0
                            ),
                            CKR_OK
                        );
                    }
                }
            }
            while rx.try_recv().is_ok() {}
            harness.scenario(ExactOracleScenario { rv: provider_rv as u64, ..Default::default() });
            let mut bytes = [0xa5u8; 8];
            let mut length = if reject_before_native { 512 * 1024 * 1024 + 1 } else { 8 };
            let mut handle = 0x1234;
            let rv = unsafe {
                match family {
                    "encrypt" => harness.functions.C_Encrypt.unwrap()(
                        harness.session,
                        ptr::null_mut(),
                        0,
                        bytes.as_mut_ptr(),
                        &mut length,
                    ),
                    "wrap" => harness.functions.C_WrapKey.unwrap()(
                        harness.session,
                        &mut mechanism,
                        harness.key,
                        harness.key,
                        bytes.as_mut_ptr(),
                        &mut length,
                    ),
                    "attribute" => {
                        let mut attr = CK_ATTRIBUTE {
                            type_: CKA_LABEL,
                            pValue: bytes.as_mut_ptr().cast(),
                            ulValueLen: length,
                        };
                        harness.functions.C_GetAttributeValue.unwrap()(
                            harness.session,
                            harness.key,
                            &mut attr,
                            1,
                        )
                    }
                    "kem" => harness.functions.C_EncapsulateKey.unwrap()(
                        harness.session,
                        &mut mechanism,
                        harness.key,
                        ptr::null_mut(),
                        0,
                        bytes.as_mut_ptr(),
                        &mut length,
                        &mut handle,
                    ),
                    "message" => harness.functions.C_EncryptMessage.unwrap()(
                        harness.session,
                        pp,
                        pn,
                        ptr::null_mut(),
                        0,
                        ptr::null_mut(),
                        0,
                        bytes.as_mut_ptr(),
                        &mut length,
                    ),
                    "next" => harness.functions.C_EncryptMessageNext.unwrap()(
                        harness.session,
                        pp,
                        pn,
                        ptr::null_mut(),
                        0,
                        bytes.as_mut_ptr(),
                        &mut length,
                        CKF_END_OF_MESSAGE,
                    ),
                    "begin" => harness.functions.C_EncryptMessageBegin.unwrap()(
                        harness.session,
                        pp,
                        if reject_before_native { pn + 1 } else { pn },
                        ptr::null_mut(),
                        0,
                    ),
                    "authenticated-wrap" => {
                        mechanism.mechanism = CKM_AES_GCM;
                        mechanism.pParameter = pp;
                        mechanism.ulParameterLen = pn;
                        harness.functions.C_WrapKeyAuthenticated.unwrap()(
                            harness.session,
                            &mut mechanism,
                            harness.key,
                            harness.key,
                            ptr::null_mut(),
                            0,
                            bytes.as_mut_ptr(),
                            &mut length,
                        )
                    }
                    _ => unreachable!(),
                }
            };
            let health = rx.try_recv().ok();
            println!(
                "{family}: provider={provider_rv:#x} caller={rv:#x} calls={} health={health:?}",
                harness.observation().calls
            );
            let valid = if reject_before_native {
                assert_eq!(bytes, [0xa5; 8]);
                assert_eq!(length, 512 * 1024 * 1024 + 1);
                assert_eq!(handle, 0x1234);
                rv != CKR_OK && harness.observation().calls == 0 && health.is_none()
            } else {
                rv == provider_rv
                    && harness.observation().calls == 1
                    && matches!(health, Some(BackendHealthEvent::Failure))
            };
            if !valid {
                family_failures.push((family, provider_rv, rv, health));
            }
        }
    }
    for provider_rv in [CKR_DEVICE_REMOVED, CKR_HOST_MEMORY] {
        let mut mechanism =
            CK_MECHANISM { mechanism: CKM_AES_GCM, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        assert_eq!(
            unsafe {
                harness.functions.C_MessageEncryptInit.unwrap()(
                    harness.session,
                    &mut mechanism,
                    harness.key,
                )
            },
            CKR_OK
        );
        while rx.try_recv().is_ok() {}
        let mut iv = [0x11u8; 12];
        let mut tag = [0xa5u8; 16];
        let mut bytes = [0xb6u8; 8];
        let mut length = 8;
        let mut parameter = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: 12,
            ulIvFixedBits: 0,
            ivGenerator: CKG_GENERATE_COUNTER_XOR,
            pTag: tag.as_mut_ptr(),
            ulTagBits: 128,
        };
        harness.scenario(ExactOracleScenario {
            rv: provider_rv as u64,
            parameter_action: 2,
            length_action: 1,
            returned_length: 4,
            ..Default::default()
        });
        let mut call = || unsafe {
            harness.functions.C_EncryptMessage.unwrap()(
                harness.session,
                (&mut parameter as *mut CK_GCM_MESSAGE_PARAMS).cast(),
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                bytes.as_mut_ptr(),
                &mut length,
            )
        };
        assert_eq!(call(), CKR_DEVICE_ERROR);
        assert!(
            matches!(rx.try_recv(), Ok(BackendHealthEvent::Failure)),
            "invalid effects must retain provider RV health evidence"
        );
        assert_eq!(call(), CKR_OPERATION_NOT_INITIALIZED);
        assert!(rx.try_recv().is_err());
        assert_eq!(harness.observation().calls, 1);
        assert_eq!((length, iv, tag, bytes), (8, [0x11; 12], [0xa5; 16], [0xb6; 8]));
    }
    assert!(family_failures.is_empty(), "exact adapter health mismatches: {family_failures:?}");
    assert!(
        matches!(results[0].2, Some(BackendHealthEvent::Failure)),
        "native DEVICE_REMOVED must preserve unhealthy classification"
    );
    assert!(
        results[1].2.is_none(),
        "caller-controlled pre-native capacity rejection must not degrade backend health"
    );
    assert!(
        !matches!(results[2].2, Some(BackendHealthEvent::Success)),
        "native HOST_MEMORY must not signal recovery (repeated failures may be coalesced)"
    );
}

#[ignore = "requires explicit production shim and exact native oracle library paths"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fix_round_one_successful_size_query_does_not_fabricate_parameter_outputs() {
    let _guard = LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let harness = Harness::start().await;
    let mut failures = Vec::new();
    for operation in ["one-shot", "final-next", "authenticated-wrap"] {
        let run = |functions: &CK_FUNCTION_LIST_3_2, session, key| {
            let mut init = CK_MECHANISM {
                mechanism: CKM_AES_GCM,
                pParameter: ptr::null_mut(),
                ulParameterLen: 0,
            };
            let mut iv = [0x11u8; 12];
            let mut tag = [0xa5u8; 16];
            let mut parameter = CK_GCM_MESSAGE_PARAMS {
                pIv: iv.as_mut_ptr(),
                ulIvLen: 12,
                ulIvFixedBits: 0,
                ivGenerator: CKG_NO_GENERATE,
                pTag: tag.as_mut_ptr(),
                ulTagBits: 128,
            };
            let param_ptr = (&mut parameter as *mut CK_GCM_MESSAGE_PARAMS).cast();
            let param_len = std::mem::size_of_val(&parameter) as CK_ULONG;
            let mut length = 77;
            unsafe {
                if operation != "authenticated-wrap" {
                    assert_eq!(
                        functions.C_MessageEncryptInit.unwrap()(session, &mut init, key),
                        CKR_OK
                    );
                    if operation == "final-next" {
                        harness.scenario(ExactOracleScenario {
                            rv: CKR_OK as u64,
                            ..Default::default()
                        });
                        assert_eq!(
                            functions.C_EncryptMessageBegin.unwrap()(
                                session,
                                param_ptr,
                                param_len,
                                ptr::null_mut(),
                                0
                            ),
                            CKR_OK
                        );
                    }
                }
                harness.scenario(ExactOracleScenario {
                    rv: CKR_OK as u64,
                    length_action: 1,
                    returned_length: 4,
                    ..Default::default()
                });
                let rv = if operation == "one-shot" {
                    functions.C_EncryptMessage.unwrap()(
                        session,
                        param_ptr,
                        param_len,
                        ptr::null_mut(),
                        0,
                        ptr::null_mut(),
                        0,
                        ptr::null_mut(),
                        &mut length,
                    )
                } else if operation == "final-next" {
                    functions.C_EncryptMessageNext.unwrap()(
                        session,
                        param_ptr,
                        param_len,
                        ptr::null_mut(),
                        0,
                        ptr::null_mut(),
                        &mut length,
                        CKF_END_OF_MESSAGE,
                    )
                } else {
                    let mut mechanism = CK_MECHANISM {
                        mechanism: CKM_AES_GCM,
                        pParameter: param_ptr,
                        ulParameterLen: param_len,
                    };
                    functions.C_WrapKeyAuthenticated.unwrap()(
                        session,
                        &mut mechanism,
                        key,
                        key,
                        ptr::null_mut(),
                        0,
                        ptr::null_mut(),
                        &mut length,
                    )
                };
                (rv, length, iv, tag)
            }
        };
        let direct = run(&harness.native, 1, 41);
        let direct_observation = harness.observation();
        let proxy = run(&harness.functions, harness.session, harness.key);
        let proxy_observation = harness.observation();
        println!(
            "{operation} query: direct_rv={} proxy_rv={} direct_len={} proxy_len={} direct_tag={:?} proxy_tag={:?} direct_calls={} proxy_calls={} direct_parameter_stores={} proxy_parameter_stores={}",
            direct.0,
            proxy.0,
            direct.1,
            proxy.1,
            direct.3,
            proxy.3,
            direct_observation.calls,
            proxy_observation.calls,
            direct_observation.parameter_stores,
            proxy_observation.parameter_stores
        );
        assert_eq!(proxy_observation.calls, 1);
        if direct != proxy {
            failures.push(operation);
        }
    }
    assert!(failures.is_empty(), "size query invented parameter output writes: {failures:?}");
}
