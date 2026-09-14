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

#[path = "../../../../tests/ffi_oracles/retained_mechanisms/src/lib.rs"]
mod oracle;
use oracle::*;

static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn backend_with_oracle_provider() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
    let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
    functions.C_Initialize = Some(oracle::provider::initialize);
    functions.C_Finalize = Some(oracle::provider::finalize);
    functions.C_OpenSession = Some(oracle::provider::open_session);
    functions.C_CloseSession = Some(oracle::provider::close_session);
    functions.C_EncryptInit = Some(oracle::provider::encrypt_init);
    functions.C_Encrypt = Some(oracle::provider::encrypt);
    let backend = FfiBackend {
        _lib: libloading::os::unix::Library::this().into(),
        func_list: functions.as_mut(),
        func_list_3_0: None,
        func_list_3_2: None,
        initialize_args: None,
        mech_cache: dashmap::DashMap::new(),
        last_init_family: dashmap::DashMap::new(),
        session_slot_map: dashmap::DashMap::new(),
        slot_sessions: dashmap::DashMap::new(),
        object_cleanup: Default::default(),
        // Test-local backend: bypasses the process reservation without
        // consuming it; never backs production dispatch (C3M.4).
        construction: crate::ffi::native_domain::ConstructionPermit::unmanaged_test_only(),
        lifecycle: Default::default(),
    };
    (backend, functions)
}

fn gcm_mechanism() -> CkMechanism {
    CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv: vec![0xA5; 12],
            iv_bits: 96,
            iv_buffer_len: 12,
            aad: Vec::new(),
            tag_bits: 128,
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
) -> Vec<u8> {
    unsafe {
        (controls.set_scenario)(&RetainedOracleScenario { encrypt_rv: 0, output_len: 16 });
    }
    (controls.reset_observation)();
    let gcm = gcm_mechanism();
    backend.ffi_encrypt_init_with_output(session, &gcm, CkObjectHandle(1)).unwrap();
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
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (backend, _functions) = backend_with_oracle_provider();
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
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(lib) = std::env::var_os("PKCS11_PROXY_RETAINED_ORACLE_LIB") else {
        eprintln!("SKIP: PKCS11_PROXY_RETAINED_ORACLE_LIB is not set");
        return;
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
        .ffi_open_session(
            CkSlotId(7),
            CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION),
        )
        .expect("oracle open session");

    let out = init_and_encrypt(&backend, session, controls);
    assert_eq!(out.len(), 16);

    assert_retention(&read_observation(controls));
    assert!(backend.mech_cache.contains_key(&(session.0, OperationFamily::Encrypt)));

    backend.ffi_close_session(session).expect("oracle close session");
    backend.finalize().expect("oracle finalize");
}
