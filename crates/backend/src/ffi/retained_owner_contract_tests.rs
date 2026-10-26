// W1-L12-03: test diagnostics (skip notices, progress, summaries) go to
// stderr by design; the workspace lint table denies this sink elsewhere.
#![allow(clippy::print_stderr)]
//! Retention observations through a deliberately retaining native provider.
//!
//! The oracle crate (`tests/ffi_oracles/retained_mechanisms`) is a dual
//! fixture (C3M.6): its `provider` module compiles in-process here for the
//! default suite, and the same sources build as an unpublished cdylib for
//! dlopen/subprocess/topology rows. Neither fixture substitutes for the
//! other; Miri cannot establish real dlopen provider behavior.
//!
//! The ignored dlopen test needs the built oracle:
//! `cargo build --locked --manifest-path tests/ffi_oracles/retained_mechanisms/Cargo.toml`
//! then run with `PKCS11_PROXY_RETAINED_ORACLE_LIB` pointing at the built
//! `.so`, serially (`--test-threads=1`): it consumes the process
//! construction reservation via `FfiBackend::load`.
use super::*;
use pkcs11_proxy_ng_types::PointerBytes;

#[path = "../../../../tests/ffi_oracles/retained_mechanisms/src/lib.rs"]
mod oracle;
use oracle::*;

fn backend_with_oracle_provider() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
    let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
    functions.C_Initialize = Some(oracle::provider::initialize);
    functions.C_Finalize = Some(oracle::provider::finalize);
    functions.C_OpenSession = Some(oracle::provider::open_session);
    functions.C_CloseSession = Some(oracle::provider::close_session);
    functions.C_EncryptInit = Some(oracle::provider::encrypt_init);
    functions.C_Encrypt = Some(oracle::provider::encrypt);
    let backend = FfiBackend::test_backend_with_tables(functions.as_mut(), None, None);
    (backend, functions)
}

fn gcm_mechanism() -> CkMechanism {
    CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv_bits: 96,
            iv_buffer_len: 12,
            tag_bits: 128,
            iv_presence: PointerBytes::from_legacy(&[0xA5; 12], false),
            aad_presence: PointerBytes::from_legacy(&[], false),
        })),
    }
}

/// Control entry points of whichever oracle instance backs the test: the
/// in-process provider module, or the dlopen-loaded cdylib resolved below.
/// A dlopen'd `.so` has its own state, unreachable through the in-process
/// copies, so each test must drive the instance its native calls reach.
#[derive(Clone, Copy)]
struct OracleControls {
    set_scenario: unsafe extern "C" fn(*const RetainedOracleScenario) -> u32,
    reset_observation: extern "C" fn() -> u32,
    get_observation: unsafe extern "C" fn(*mut RetainedOracleObservation) -> u32,
}

fn init_and_encrypt(
    backend: &FfiBackend,
    session: CkSessionHandle,
    controls: OracleControls,
) -> SecretBytes {
    reset_oracle(controls, 16);
    {
        let gcm = gcm_mechanism();
        backend
            .ffi_encrypt_init_with_output(
                session,
                &validated_mechanism_for_tests(&gcm),
                CkObjectHandle(1),
            )
            .unwrap();
    }
    backend.ffi_encrypt(session, CkInBuf::Bytes(b"data")).unwrap()
}

fn read_observation(controls: OracleControls) -> RetainedOracleObservation {
    let mut observation = RetainedOracleObservation::default();
    unsafe {
        (controls.get_observation)(&mut observation);
    }
    observation
}

fn assert_retention(observation: &RetainedOracleObservation) {
    assert_eq!(observation.init_calls, 1);
    // The backend's ordinary two-call helper issues sizing + fill entries;
    // both must observe the one retained Init root.
    assert_eq!(observation.encrypt_calls, 2);
    // One stable nonzero root across both native entries.
    assert_ne!(observation.init_mech_ptr, 0);
    assert_eq!(observation.init_mech_ptr, observation.encrypt_mech_ptr);
    assert_eq!(observation.ptr_equal, 1);
    // Content re-read through the retained root at Encrypt time: the same
    // parameter extent and the GCM mechanism type the backend installed.
    assert_ne!(observation.init_param_len, 0);
    assert_eq!(observation.init_param_len, observation.encrypt_param_len);
    assert_eq!(observation.encrypt_mech_type, cryptoki_sys::CKM_AES_GCM as u64);
}

#[test]
fn oracle_retains_init_root_across_native_calls() {
    let _guard = oracle::acquire_test_serial();
    let (backend, _functions) = backend_with_oracle_provider();
    // Mirror production: Initialize (opens the lifecycle domain) before
    // ordinary work.
    backend.initialize().expect("oracle initialize");
    let session = CkSessionHandle(31);
    let controls = OracleControls {
        set_scenario: RetainedOracle_SetScenario,
        reset_observation: RetainedOracle_ResetObservation,
        get_observation: RetainedOracle_GetObservation,
    };

    // The provider deliberately retains the Init mechanism root (like
    // OpenCryptoki) instead of copying it; both native entries must
    // observe the same root address, checked test-side from recorded
    // addresses the oracle never dereferences.
    let out = init_and_encrypt(&backend, session, controls);
    assert_eq!(out.len(), 16);

    assert_retention(&read_observation(controls));
    // The backend's retained family slot keeps the same graph alive that
    // the provider still references.
    assert!(backend.mech_cache.contains_key(&(session.0, OperationFamily::Encrypt)));
}

#[test]
#[ignore = "C3M.6: requires the built retained-mechanism oracle cdylib, run serially"]
fn native_owner_oracle_retains_init_root_across_calls() {
    let _guard = oracle::acquire_test_serial();
    // W1-L10-11: this test is `#[ignore]`, so reaching this code means an
    // explicit opt-in run. A missing oracle library is then a real error,
    // not a silent skip — fail loudly rather than returning a misleading
    // green pass (same L14 rule as the GCM-IV `require_patched_lib` gate).
    let Some(lib) = std::env::var_os("PKCS11_PROXY_RETAINED_ORACLE_LIB") else {
        panic!(
            "PKCS11_PROXY_RETAINED_ORACLE_LIB is not set — this #[ignore] test requires the \
             built retained-mechanism oracle cdylib. Build it with `cargo build --locked \
             --manifest-path tests/ffi_oracles/retained_mechanisms/Cargo.toml` and point the \
             env var at the resulting .so, then re-run serially (--test-threads=1). \
             (Refusing to pass silently — W1-L10-11.)"
        );
    };
    // Same assertions as the in-process test, through a real dlopen-loaded
    // provider: proves the cdylib artifact serves the retention contract.
    // Controls resolve from the loaded library: the `.so` owns state the
    // in-process copies cannot reach.
    let backend = FfiBackend::load(std::path::Path::new(&lib)).expect("load retained oracle");
    let controls_lib =
        unsafe { libloading::Library::new(&lib) }.expect("reopen oracle control symbols");
    let controls = OracleControls {
        set_scenario: *unsafe {
            controls_lib
                .get::<unsafe extern "C" fn(*const RetainedOracleScenario) -> u32>(
                    b"RetainedOracle_SetScenario",
                )
                .expect("oracle SetScenario symbol")
        },
        reset_observation: *unsafe {
            controls_lib
                .get::<extern "C" fn() -> u32>(b"RetainedOracle_ResetObservation")
                .expect("oracle ResetObservation symbol")
        },
        get_observation: *unsafe {
            controls_lib
                .get::<unsafe extern "C" fn(*mut RetainedOracleObservation) -> u32>(
                    b"RetainedOracle_GetObservation",
                )
                .expect("oracle GetObservation symbol")
        },
    };
    backend.initialize().expect("oracle initialize");
    let session = backend
        .ffi_open_session(CkSlotId(7), CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION)
        .expect("oracle open session");

    let out = init_and_encrypt(&backend, session, controls);
    assert_eq!(out.len(), 16);

    assert_retention(&read_observation(controls));
    assert!(backend.mech_cache.contains_key(&(session.0, OperationFamily::Encrypt)));

    // Resolve the distinct V1 observation from the same loaded instance;
    // the in-process fixture state cannot establish dlopen ownership.
    let get_deep = unsafe {
        controls_lib
            .get::<unsafe extern "C" fn(*mut RetainedOracleDeepObservationV1) -> u32>(
                b"RetainedOracle_GetDeepObservationV1",
            )
            .expect("oracle GetDeepObservationV1 symbol")
    };
    let mut deep = RetainedOracleDeepObservationV1::default();
    assert_eq!(unsafe { get_deep(&mut deep) }, 0);
    assert_eq!((deep.version, deep.graph_equal, deep.encrypt.valid), (1, 1, 1));
    assert_eq!(deep.encrypt.node_count, 1);
    let node = deep.encrypt.nodes[0];
    assert_eq!((node.scalar_a, node.scalar_b, node.first_len, node.second_len), (96, 128, 12, 0));
    assert_ne!(node.first_ptr, 0);
    assert_ne!(node.second_ptr, 0); // present-empty AAD
    assert_eq!(&node.first_bytes[..12], &[0xA5; 12]);

    backend.ffi_close_session(session).expect("oracle close session");
    backend.finalize().expect("oracle finalize");
    eprintln!(
        "native-contract-complete:ffi::retained_owner_contract_tests::native_owner_oracle_retains_init_root_across_calls"
    );
}

/// Bring the shared in-process oracle to a known state: gate open (so no
/// worker stranded by an earlier failure stays blocked), then the caller's
/// scenario and a zeroed observation. Every test starts this way because
/// the oracle instance is process-global.
fn reset_oracle(controls: OracleControls, output_len: u64) {
    unsafe {
        RetainedOracle_ReleaseGate();
        (controls.set_scenario)(&RetainedOracleScenario {
            encrypt_rv: 0,
            output_len,
            // Hermetic tests assert observations directly, including
            // mismatched roots: keep the fail-closed E2E gate off here.
            fail_unless_ptr_equal: 0,
        });
    }
    (controls.reset_observation)();
}

fn wait_for_condition(timeout: std::time::Duration, mut ready: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while !ready() {
        if start.elapsed() > timeout {
            panic!("condition not met within {timeout:?}");
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

#[test]
fn oracle_gate_holds_native_entry_until_released() {
    let _guard = oracle::acquire_test_serial();
    let controls = OracleControls {
        set_scenario: RetainedOracle_SetScenario,
        reset_observation: RetainedOracle_ResetObservation,
        get_observation: RetainedOracle_GetObservation,
    };
    reset_oracle(controls, 0);
    unsafe {
        RetainedOracle_ArmGate(RETAINED_OP_ENCRYPT);
    }

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut length: cryptoki_sys::CK_ULONG = 0;
            let rv = unsafe {
                oracle::provider::encrypt(
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut length,
                )
            };
            done_tx.send((rv, length)).unwrap();
        });
        // The native entry is held at the gate: entered but not returned.
        wait_for_condition(std::time::Duration::from_secs(5), || {
            read_observation(controls).gate_holds_current > 0
        });
        assert!(done_rx.recv_timeout(std::time::Duration::from_millis(100)).is_err());
        unsafe {
            RetainedOracle_ReleaseGate();
        }
        let (rv, length) = done_rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(rv, cryptoki_sys::CKR_OK);
        assert_eq!(length, 0);
    });

    let observation = read_observation(controls);
    assert_eq!(observation.encrypt_calls, 1);
    assert_eq!(observation.gate_holds_current, 0);
    assert_eq!(observation.gate_holds_total, 1);
    unsafe {
        RetainedOracle_ReleaseGate();
    }
}

#[cfg_attr(miri, ignore = "Miri cannot dlopen; covered natively")]
#[test]
fn native_owner_call_readback_is_one_transaction() {
    let _guard = oracle::acquire_test_serial();
    let (backend, _functions) = backend_with_oracle_provider();
    // Mirror production: Initialize (opens the lifecycle domain) before
    // ordinary work.
    backend.initialize().expect("oracle initialize");
    let controls = OracleControls {
        set_scenario: RetainedOracle_SetScenario,
        reset_observation: RetainedOracle_ResetObservation,
        get_observation: RetainedOracle_GetObservation,
    };
    reset_oracle(controls, 16);
    let session = CkSessionHandle(32);

    // The Init write lands ungated; the readback (Encrypt) is held at the
    // gate, proving the two native entries form one ordered transaction:
    // no second Init can interleave, and the backend-side retained graph
    // is already in its family slot before the native readback completes.
    let gcm = gcm_mechanism();
    backend
        .ffi_encrypt_init_with_output(
            session,
            &validated_mechanism_for_tests(&gcm),
            CkObjectHandle(1),
        )
        .unwrap();
    assert!(backend.mech_cache.contains_key(&(session.0, OperationFamily::Encrypt)));
    unsafe {
        RetainedOracle_ArmGate(RETAINED_OP_ENCRYPT);
    }

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let out = backend.ffi_encrypt(session, CkInBuf::Bytes(b"data")).unwrap();
            done_tx.send(out).unwrap();
        });
        wait_for_condition(std::time::Duration::from_secs(5), || {
            read_observation(controls).gate_holds_current > 0
        });
        // Still held: exactly one Init write, one Encrypt entry, no return.
        let observation = read_observation(controls);
        assert_eq!(observation.init_calls, 1);
        assert_eq!(observation.encrypt_calls, 1);
        assert!(done_rx.recv_timeout(std::time::Duration::from_millis(100)).is_err());
        unsafe {
            RetainedOracle_ReleaseGate();
        }
        let out = done_rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(out.len(), 16);
    });

    // Released once: sizing + fill both passed the open gate as one
    // transaction against the single retained root.
    assert_retention(&read_observation(controls));
    unsafe {
        RetainedOracle_ReleaseGate();
    }
}

fn deep_observation() -> RetainedOracleDeepObservationV1 {
    let mut observation = RetainedOracleDeepObservationV1::default();
    assert_eq!(unsafe { RetainedOracle_GetDeepObservationV1(&mut observation) }, 0);
    observation
}

#[cfg_attr(miri, ignore = "Miri cannot dlopen; covered natively")]
#[test]
fn delayed_native_gcm_observes_owned_bytes_after_domain_drop() {
    let _guard = oracle::acquire_test_serial();
    let (backend, _functions) = backend_with_oracle_provider();
    backend.initialize().unwrap();
    let controls = OracleControls {
        set_scenario: RetainedOracle_SetScenario,
        reset_observation: RetainedOracle_ResetObservation,
        get_observation: RetainedOracle_GetObservation,
    };
    reset_oracle(controls, 16);
    let session = CkSessionHandle(81);
    {
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType::AES_GCM,
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv_bits: 96,
                iv_buffer_len: 12,
                tag_bits: 128,
                iv_presence: PointerBytes::from_legacy(&[0xA5; 12], false),
                aad_presence: PointerBytes::from_legacy(&[0x37, 0x49, 0x8C], false),
            })),
        };
        backend
            .ffi_encrypt_init_with_output(
                session,
                &validated_mechanism_for_tests(&mechanism),
                CkObjectHandle(1),
            )
            .unwrap();
    }
    backend
        .ffi_encrypt(session, CkInBuf::Bytes(b"data"))
        .unwrap()
        .expose(|bytes| assert_eq!(bytes, &[0xC3; 16]));
    let deep = deep_observation();
    assert_eq!(deep.session, 81);
    assert_eq!(deep.graph_equal, 1);
    assert_eq!(deep.encrypt.valid, 1);
    assert_eq!(deep.encrypt.node_count, 1);
    let node = deep.encrypt.nodes[0];
    assert_eq!(node.mechanism, cryptoki_sys::CKM_AES_GCM as u64);
    assert_eq!((node.scalar_a, node.scalar_b), (96, 128));
    assert_eq!((node.first_len, node.second_len), (12, 3));
    assert_eq!(&node.first_bytes[..12], &[0xA5; 12]);
    assert_eq!(&node.second_bytes[..3], &[0x37, 0x49, 0x8C]);
    backend.ffi_close_session(session).unwrap();
    backend.finalize().unwrap();
}

fn graph_validated(mechanism: &CkMechanism) -> ValidatedMechanismParams {
    use pkcs11_proxy_ng_types::shape_descriptors::{Operation, ParamAbi};
    let registry = MechanismRegistry::from_parts(
        [
            (CkMechanismType::KIP_DERIVE.0, "kip".to_string()),
            (CkMechanismType::AES_GCM.0, "gcm".to_string()),
            (CkMechanismType::AES_CBC.0, "iv".to_string()),
        ]
        .into_iter()
        .collect(),
        Default::default(),
        Default::default(),
        DiscoveryMode::Transparent,
        "retained-graph-test".to_string(),
    );
    let abi = if std::mem::size_of::<cryptoki_sys::CK_ULONG>() == 8 {
        ParamAbi::Lp64NativeLe
    } else {
        ParamAbi::Ilp32NativeLe
    };
    ValidatedMechanismParams::validate(mechanism, &registry, Operation::General, abi, abi).unwrap()
}

#[cfg_attr(miri, ignore = "Miri cannot dlopen; covered natively")]
#[test]
fn delayed_native_generated_presence_and_nested_graph_families() {
    let _guard = oracle::acquire_test_serial();
    let (backend, _functions) = backend_with_oracle_provider();
    backend.initialize().unwrap();
    let controls = OracleControls {
        set_scenario: RetainedOracle_SetScenario,
        reset_observation: RetainedOracle_ResetObservation,
        get_observation: RetainedOracle_GetObservation,
    };
    reset_oracle(controls, 4);
    let legs = [
        PointerBytes::from_legacy(&[], true),
        PointerBytes::from_legacy(&[], false),
        PointerBytes::from_legacy(&[0x21, 0x43], false),
    ];
    let mut cases = 0;
    for depth in 0..=2 {
        for (iv_case, iv) in legs.iter().enumerate() {
            for (aad_case, aad) in legs.iter().enumerate() {
                let session = CkSessionHandle(100 + cases);
                {
                    let mut mechanism = CkMechanism {
                        mechanism_type: CkMechanismType::AES_GCM,
                        params: Some(CkMechanismParams::Gcm(GcmParams {
                            iv_bits: 96,
                            iv_buffer_len: 2,
                            tag_bits: 128,
                            iv_presence: iv.clone(),
                            aad_presence: aad.clone(),
                        })),
                    };
                    for level in 0..depth {
                        let seed_case = (iv_case + aad_case) % 3;
                        let seed_presence = if seed_case == 2 {
                            let bytes = if level == 0 { [0x51, 0x72] } else { [0x94, 0xB6] };
                            PointerBytes::from_legacy(&bytes, false)
                        } else {
                            legs[seed_case].clone()
                        };
                        mechanism = CkMechanism {
                            mechanism_type: CkMechanismType::KIP_DERIVE,
                            params: Some(CkMechanismParams::Kip(
                                pkcs11_proxy_ng_types::KipParams {
                                    mechanism: Some(Box::new(mechanism)),
                                    key_handle: CkObjectHandle(19 + u64::from(level)),
                                    seed_presence,
                                },
                            )),
                        };
                    }
                    backend
                        .ffi_encrypt_init_with_output(
                            session,
                            &graph_validated(&mechanism),
                            CkObjectHandle(1),
                        )
                        .unwrap();
                }
                let before = read_observation(controls).encrypt_calls;
                let result = backend
                    .ffi_encrypt_exact(
                        session,
                        CkInBuf::Bytes(b"x"),
                        &CkOutputBufferSpec {
                            buffer_present: true,
                            buffer_len: 4,
                            length_pointer_null: false,
                        },
                    )
                    .unwrap();
                assert_eq!(result.ck_rv, CkRv::OK);
                assert_eq!(result.returned_len, Some(4));
                result.value.unwrap().expose(|bytes| assert_eq!(bytes, &[0xC3; 4]));
                assert_eq!(read_observation(controls).encrypt_calls, before + 1);
                let deep = deep_observation();
                assert_eq!(
                    (deep.graph_equal, deep.encrypt.valid, deep.encrypt.node_count),
                    (1, 1, depth + 1)
                );
                // Wrapping makes the last constructed KIP the outermost node.
                // These literal expectations are independent of the construction loop.
                let expected_levels: &[(u64, [u8; 2])] = match depth {
                    0 => &[],
                    1 => &[(19, [0x51, 0x72])],
                    2 => &[(20, [0x94, 0xB6]), (19, [0x51, 0x72])],
                    _ => unreachable!(),
                };
                for (index, (key, seed)) in expected_levels.iter().enumerate() {
                    let node = deep.encrypt.nodes[index];
                    assert_eq!(node.mechanism, cryptoki_sys::CKM_KIP_DERIVE as u64);
                    assert_eq!(
                        node.scalar_a, *key,
                        "KIP key at retained outer-to-inner level {index}"
                    );
                    assert_ne!(deep.encrypt.nodes[index + 1].mechanism_ptr, 0);
                    let seed_case = (iv_case + aad_case) % 3;
                    assert_eq!(node.first_ptr == 0, seed_case == 0);
                    assert_eq!(node.first_len, if seed_case == 2 { 2 } else { 0 });
                    if seed_case == 2 {
                        assert_eq!(
                            &node.first_bytes[..2],
                            seed,
                            "KIP seed at retained outer-to-inner level {index}"
                        );
                    }
                }
                let node = deep.encrypt.nodes[depth as usize];
                assert_eq!(node.mechanism, cryptoki_sys::CKM_AES_GCM as u64);
                assert_eq!((node.scalar_a, node.scalar_b), (96, 128));
                for (case, ptr, len, bytes) in [
                    (iv_case, node.first_ptr, node.first_len, node.first_bytes),
                    (aad_case, node.second_ptr, node.second_len, node.second_bytes),
                ] {
                    assert_eq!(ptr == 0, case == 0);
                    assert_eq!(len, if case == 2 { 2 } else { 0 });
                    if case == 2 {
                        assert_eq!(&bytes[..2], &[0x21, 0x43]);
                    }
                }
                backend.ffi_close_session(session).unwrap();
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 27);
    // Exercise the independent NULL nested-mechanism leg as well as all
    // three seed presence forms. No substitute inner mechanism is invented.
    for (seed_case, seed) in legs.iter().enumerate() {
        let session = CkSessionHandle(100 + cases);
        {
            let mechanism = CkMechanism {
                mechanism_type: CkMechanismType::KIP_DERIVE,
                params: Some(CkMechanismParams::Kip(pkcs11_proxy_ng_types::KipParams {
                    mechanism: None,
                    key_handle: CkObjectHandle(19),
                    seed_presence: seed.clone(),
                })),
            };
            backend
                .ffi_encrypt_init_with_output(
                    session,
                    &graph_validated(&mechanism),
                    CkObjectHandle(1),
                )
                .unwrap();
        }
        backend.ffi_encrypt(session, CkInBuf::Bytes(b"x")).unwrap();
        let deep = deep_observation();
        assert_eq!((deep.graph_equal, deep.encrypt.valid, deep.encrypt.node_count), (1, 1, 1));
        assert_eq!(deep.encrypt.nodes[0].mechanism, cryptoki_sys::CKM_KIP_DERIVE as u64);
        assert_eq!(deep.encrypt.nodes[0].first_ptr == 0, seed_case == 0);
        assert_eq!(deep.encrypt.nodes[0].first_len, if seed_case == 2 { 2 } else { 0 });
        if seed_case == 2 {
            assert_eq!(&deep.encrypt.nodes[0].first_bytes[..2], &[0x21, 0x43]);
        }
        backend.ffi_close_session(session).unwrap();
        cases += 1;
    }
    assert_eq!(cases, 30);
    assert_eq!(read_observation(controls).init_calls, 30);
    backend.finalize().unwrap();
}

#[cfg_attr(miri, ignore = "Miri cannot dlopen; covered natively")]
#[test]
fn delayed_native_interleaved_sessions_keep_distinct_cbc_graphs() {
    let _guard = oracle::acquire_test_serial();
    let (backend, _functions) = backend_with_oracle_provider();
    backend.initialize().unwrap();
    let controls = OracleControls {
        set_scenario: RetainedOracle_SetScenario,
        reset_observation: RetainedOracle_ResetObservation,
        get_observation: RetainedOracle_GetObservation,
    };
    reset_oracle(controls, 4);
    for (session, byte) in [(201, 0x13), (202, 0x9B)] {
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType::AES_CBC,
            params: Some(CkMechanismParams::Iv(pkcs11_proxy_ng_types::IvParams {
                iv: vec![byte; 16],
            })),
        };
        backend
            .ffi_encrypt_init_with_output(
                CkSessionHandle(session),
                &graph_validated(&mechanism),
                CkObjectHandle(1),
            )
            .unwrap();
    }
    let mut roots = [0; 2];
    for (index, (session, byte)) in [(201, 0x13), (202, 0x9B), (201, 0x13)].into_iter().enumerate()
    {
        backend.ffi_encrypt(CkSessionHandle(session), CkInBuf::Bytes(b"x")).unwrap();
        let deep = deep_observation();
        assert_eq!((deep.session, deep.graph_equal), (session, 1));
        assert_eq!(&deep.encrypt.nodes[0].first_bytes[..16], &[byte; 16]);
        if index < 2 {
            roots[index] = deep.encrypt.nodes[0].mechanism_ptr;
        } else {
            assert_eq!(deep.encrypt.nodes[0].mechanism_ptr, roots[0]);
        }
    }
    assert_ne!(roots[0], roots[1]);
    assert_eq!(read_observation(controls).encrypt_calls, 6);
    for session in [201, 202] {
        backend.ffi_close_session(CkSessionHandle(session)).unwrap();
    }
    backend.finalize().unwrap();
}

#[cfg_attr(
    miri,
    ignore = "live-corruption model retains caller pointers across &mut writes (C-realistic; both borrow models reject); covered natively"
)]
#[test]
fn delayed_native_live_corruption_and_wrong_session_controls_fail_closed() {
    use cryptoki_sys::*;
    let _guard = oracle::acquire_test_serial();
    let controls = OracleControls {
        set_scenario: RetainedOracle_SetScenario,
        reset_observation: RetainedOracle_ResetObservation,
        get_observation: RetainedOracle_GetObservation,
    };
    reset_oracle(controls, 4);
    assert_eq!(RetainedOracle_RequireDeepEqualV1(1), 0);
    let mut iv = [0xA5; 12];
    let mut aad = [0x37, 0x49, 0x8C];
    let mut seed = [0x51, 0x72];
    let mut gcm = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: 12,
        ulIvBits: 96,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: 3,
        ulTagBits: 128,
    };
    let mut inner = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: (&mut gcm as *mut CK_GCM_PARAMS).cast(),
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    let mut kip =
        CK_KIP_PARAMS { pMechanism: &mut inner, hKey: 19, pSeed: seed.as_mut_ptr(), ulSeedLen: 2 };
    let mut root = CK_MECHANISM {
        mechanism: CKM_KIP_DERIVE,
        pParameter: (&mut kip as *mut CK_KIP_PARAMS).cast(),
        ulParameterLen: std::mem::size_of::<CK_KIP_PARAMS>() as CK_ULONG,
    };
    assert_eq!(unsafe { oracle::provider::encrypt_init(301, &mut root, 1) }, CKR_OK);
    let call = |session| {
        let mut length = 0;
        let rv = unsafe {
            oracle::provider::encrypt(
                session,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut length,
            )
        };
        (rv, length)
    };
    assert_eq!(call(301), (CKR_OK, 4));
    // All allocations stay live throughout. Each mutation targets a different
    // leg; a root-only oracle would miss every one of these failures.
    for leg in 0..3 {
        match leg {
            0 => iv[0] ^= 1,
            1 => aad[0] ^= 1,
            _ => seed[0] ^= 1,
        }
        assert_eq!(call(301), (CKR_DEVICE_ERROR, 0), "leg {leg}");
        let deep = deep_observation();
        assert_eq!((deep.init.valid, deep.encrypt.valid, deep.graph_equal), (1, 1, 0));
        assert_eq!(read_observation(controls).ptr_equal, 1);
        match leg {
            0 => assert_eq!(deep.encrypt.nodes[1].first_bytes[0], 0xA4),
            1 => assert_eq!(deep.encrypt.nodes[1].second_bytes[0], 0x36),
            _ => assert_eq!(deep.encrypt.nodes[0].first_bytes[0], 0x50),
        }
        match leg {
            0 => iv[0] ^= 1,
            1 => aad[0] ^= 1,
            _ => seed[0] ^= 1,
        }
        assert_eq!(call(301), (CKR_OK, 4));
        assert_eq!(deep_observation().graph_equal, 1);
    }
    assert_eq!(call(302), (CKR_DEVICE_ERROR, 0));
    let deep = deep_observation();
    assert_eq!((deep.session, deep.graph_equal, deep.encrypt.node_count), (302, 0, 0));
    assert_eq!(read_observation(controls).ptr_equal, 0);
    assert_eq!(unsafe { oracle::provider::close_session(301) }, CKR_OK);
    assert_eq!(call(301), (CKR_DEVICE_ERROR, 0));
    assert_eq!(read_observation(controls).encrypt_calls, 9);
    reset_oracle(controls, 0);
}

#[cfg_attr(miri, ignore = "Miri cannot dlopen; covered natively")]
#[test]
fn delayed_native_exact_output_family_preserves_one_call_and_raw_effects() {
    let _guard = oracle::acquire_test_serial();
    let (backend, _functions) = backend_with_oracle_provider();
    backend.initialize().unwrap();
    let controls = OracleControls {
        set_scenario: RetainedOracle_SetScenario,
        reset_observation: RetainedOracle_ResetObservation,
        get_observation: RetainedOracle_GetObservation,
    };
    reset_oracle(controls, 0);
    let mechanism = gcm_mechanism();
    let session = CkSessionHandle(401);
    backend
        .ffi_encrypt_init_with_output(
            session,
            &validated_mechanism_for_tests(&mechanism),
            CkObjectHandle(1),
        )
        .unwrap();
    let mut cases = 0;
    for rv in
        [cryptoki_sys::CKR_OK, cryptoki_sys::CKR_BUFFER_TOO_SMALL, cryptoki_sys::CKR_DEVICE_ERROR]
    {
        assert_eq!(
            unsafe {
                RetainedOracle_SetScenario(&RetainedOracleScenario {
                    encrypt_rv: rv as u64,
                    output_len: 24,
                    fail_unless_ptr_equal: 1,
                })
            },
            0
        );
        for (present, capacity, null_length) in [
            (false, 0, false),
            (true, 0, false),
            (true, 1, false),
            (true, 7, false),
            (true, 24, false),
            (true, 7, true),
        ] {
            let result = backend
                .ffi_encrypt_exact(
                    session,
                    CkInBuf::Bytes(b"x"),
                    &CkOutputBufferSpec {
                        buffer_present: present,
                        buffer_len: capacity,
                        length_pointer_null: null_length,
                    },
                )
                .unwrap();
            let expected_rv = if null_length { cryptoki_sys::CKR_ARGUMENTS_BAD } else { rv };
            assert_eq!(result.ck_rv.0, expected_rv as u64);
            let expected_len = if null_length {
                None
            } else if !present {
                Some(24)
            } else {
                Some(capacity.min(16))
            };
            assert_eq!(result.returned_len, expected_len);
            if let Some(bytes) = result.value {
                bytes.expose(|bytes| {
                    // The backend exposes successful payloads; raw RV and scalar effects
                    // remain observable for the error cases above.
                    assert!(bytes.iter().all(|byte| *byte == 0xC3));
                    assert_eq!(
                        bytes.len(),
                        if null_length { 0 } else { capacity.min(16) as usize }
                    );
                });
            } else {
                assert!(!present || null_length || rv != cryptoki_sys::CKR_OK);
            }
            cases += 1;
            // Every request, including bad arguments, enters the native fixture once.
            assert_eq!(read_observation(controls).encrypt_calls, cases);
        }
    }
    assert_eq!(cases, 18);
    backend.ffi_close_session(session).unwrap();
    backend.finalize().unwrap();
}

#[cfg_attr(
    miri,
    ignore = "ABI probe mutates caller structs the oracle retains pointers to (C-realistic; borrow models reject); covered natively"
)]
#[test]
fn delayed_native_observation_abi_and_bounds_are_explicit() {
    use cryptoki_sys::*;
    let _guard = oracle::acquire_test_serial();
    // Old exported fixed-size getters remain safe for existing consumers.
    assert_eq!(std::mem::size_of::<RetainedOracleScenario>(), 24);
    assert_eq!(std::mem::size_of::<RetainedOracleObservation>(), 80);
    assert_eq!(unsafe { RetainedOracle_GetDeepObservationV1(std::ptr::null_mut()) }, 1);
    assert_eq!(RetainedOracle_RequireDeepEqualV1(2), 1);
    RetainedOracle_ResetObservation();
    assert_eq!(RetainedOracle_RequireDeepEqualV1(1), 0);
    let mut canary = [0x21; 33];
    let mut root = CK_MECHANISM {
        mechanism: CKM_AES_CBC,
        pParameter: canary.as_mut_ptr().cast(),
        ulParameterLen: 33,
    };
    assert_eq!(unsafe { oracle::provider::encrypt_init(501, &mut root, 1) }, CKR_OK);
    let mut length = 0;
    assert_eq!(
        unsafe {
            oracle::provider::encrypt(
                501,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut length,
            )
        },
        CKR_DEVICE_ERROR
    );
    assert_eq!(deep_observation().encrypt.valid, 0);
    // A live self-cycle reaches the fixed depth bound and stops before node 6.
    let mut kip =
        CK_KIP_PARAMS { pMechanism: &mut root, hKey: 1, pSeed: std::ptr::null_mut(), ulSeedLen: 0 };
    root.mechanism = CKM_KIP_DERIVE;
    root.pParameter = (&mut kip as *mut CK_KIP_PARAMS).cast();
    root.ulParameterLen = std::mem::size_of::<CK_KIP_PARAMS>() as CK_ULONG;
    assert_eq!(unsafe { oracle::provider::encrypt_init(502, &mut root, 1) }, CKR_OK);
    assert_eq!(
        unsafe {
            oracle::provider::encrypt(
                502,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut length,
            )
        },
        CKR_DEVICE_ERROR
    );
    assert_eq!((deep_observation().encrypt.valid, deep_observation().encrypt.node_count), (0, 5));
    RetainedOracle_ResetObservation();
    root.mechanism = CKM_AES_CBC;
    root.pParameter = canary.as_mut_ptr().cast();
    root.ulParameterLen = 16;
    for session in 1..=64 {
        assert_eq!(unsafe { oracle::provider::encrypt_init(session, &mut root, 1) }, CKR_OK);
    }
    assert_eq!(unsafe { oracle::provider::encrypt_init(65, &mut root, 1) }, CKR_SESSION_COUNT);
    assert_eq!(unsafe { oracle::provider::close_session(1) }, CKR_OK);
    assert_eq!(unsafe { oracle::provider::encrypt_init(65, &mut root, 1) }, CKR_OK);
    RetainedOracle_ResetObservation();
}
