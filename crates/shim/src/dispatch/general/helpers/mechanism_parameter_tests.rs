// `as CK_ULONG` / `as u64` casts below are identity on 64-bit targets but
// load-bearing on 32-bit targets (CK_ULONG=u32); the allow keeps them portable.
#![allow(clippy::unnecessary_cast)]
use super::{
    MAX_MECHANISM_PARAM_STRUCT_LEN, MAX_NESTED_MECHANISMS, MAX_SERIALIZABLE_BYTES,
    MAX_TEMPLATE_COUNT, NestingBudget, Operation, is_r18_tail_shape,
    prepare_mechanism_output_params, read_mechanism_for_transport,
    read_mechanism_for_transport_with_snapshots, read_mechanism_with_shape,
    read_mechanism_with_shape_budgeted, read_raw_bytes,
};
use cryptoki_sys::*;
use pkcs11_proxy_ng_types::mechanism_registry::DiscoveryMode;
use pkcs11_proxy_ng_types::shape_descriptors::{
    ABI_EXEMPT_FINGERPRINT, OperationContext, ParamAbi, ShapeResolver,
};
use pkcs11_proxy_ng_types::{
    CcmParams, CcmWrapParams, ChaCha20Params, CkAttributeType, CkAttributeValue,
    CkGeneratorFunction, CkKdf, CkMechanism, CkMechanismParams, CkMechanismType, CkMgf,
    CkOaepSource, CkObjectHandle, CkPbkdf2Prf, CkPbkdf2SaltSource, CkRv, ExtractParams, FlatParams,
    GcmParams, GcmWrapParams, IvParams, KeyWrapSetOaepParams, KipParams, KmacParams,
    MECHANISM_PARAMETER_TRANSPORT_VERSION, MacGeneralParams, MechanismRegistry, MuGenParams,
    PointerArray, PointerBytes, RsaAesKeyWrapParams, RsaPkcsOaepParams, RsaPkcsPssParams,
    Salsa20ChaCha20Poly1305Params, SecretBytes, SignAdditionalContext, Sp800108DerivedKey,
    Sp800108FeedbackKdfParams, Sp800108KdfParams, TlsMacParams, TlsPrfParams,
};

fn cached_default_registry() -> MechanismRegistry {
    // Load-once: the embedded default never changes within a test binary,
    // so parsing TOML on every call only burns time (minutes per call
    // under Miri across ~50 read_ck_mechanism tests).
    static DEFAULT: std::sync::OnceLock<MechanismRegistry> = std::sync::OnceLock::new();
    DEFAULT
        .get_or_init(|| MechanismRegistry::load(None).expect("default mechanism registry"))
        .clone()
}

fn ensure_registry() {
    // Each caller still gets a fresh clone installed globally, exactly as
    // before (needed by the production entry + nested reads, which gather
    // the registry from global state).
    crate::state::replace_mechanism_registry(cached_default_registry());
}

/// Clone of the embedded default registry WITHOUT installing it globally:
/// the snapshot core takes `&MechanismRegistry`, so injected-snapshot
/// tests run hermetically (no global state).
fn default_registry() -> MechanismRegistry {
    cached_default_registry()
}

/// Test read of a mechanism's typed params via the legacy branch of
/// `read_mechanism_for_transport` (capability 0, default registry).
///
/// # Safety
///
/// The reader contract: `mechanism.pParameter`, when non-null with nonzero
/// length, must designate `ulParameterLen` readable bytes containing the
/// appropriate C struct (the `&` borrow already upholds the
/// struct-validity half).
unsafe fn read_ck_mechanism(mechanism: &CK_MECHANISM) -> CkMechanismParams {
    // Hermetic: the snapshot core takes `&MechanismRegistry`, so no global
    // install is needed (KIP is unbound in the default registry, so no
    // nested read can reach the global gatherers from here).
    let registry = default_registry();
    unsafe {
        read_mechanism_for_transport_with_snapshots(
            mechanism,
            &registry,
            0,
            ParamAbi::native(),
            ParamAbi::native(),
            Operation::General,
            false,
            &mut NestingBudget::new(),
        )
    }
    .expect("read mechanism")
    .params
    .expect("mechanism params")
}

// ---------------------------------------------------------------------------
// R11 helpers: snapshot-core reads with injected capability/ABI/operation.
// ---------------------------------------------------------------------------

const R11_LP64: ParamAbi = ParamAbi::Lp64NativeLe;
const R11_ILP32: ParamAbi = ParamAbi::Ilp32NativeLe;

/// v1 read (capability 1, LP64 pair) for R11 emission tests. ABIs are
/// injected explicitly (never `native()`) so the tests are deterministic
/// on every host; lengths are chosen ABI-unambiguous (noncanonical under
/// every v1 ABI) and expected fingerprints are computed via R7 (R7 owns
/// the golden values).
///
/// # Safety
///
/// Same contract as the snapshot core.
unsafe fn read_r11_v1(
    mechanism: &CK_MECHANISM,
    registry: &MechanismRegistry,
    operation: Operation,
) -> Result<CkMechanism, CkRv> {
    unsafe {
        read_mechanism_for_transport_with_snapshots(
            mechanism,
            registry,
            1,
            Some(R11_LP64),
            Some(R11_LP64),
            operation,
            false,
            &mut NestingBudget::new(),
        )
    }
}

/// Legacy read (capability 0) for R11 identity tests. Snapshots are
/// deliberately `None`: the legacy branch must ignore them (it consults
/// neither ABI), so `None` proves ignorance as well as identity.
///
/// # Safety
///
/// Same contract as the snapshot core.
unsafe fn read_r11_legacy(
    mechanism: &CK_MECHANISM,
    registry: &MechanismRegistry,
    operation: Operation,
) -> Result<CkMechanism, CkRv> {
    unsafe {
        read_mechanism_for_transport_with_snapshots(
            mechanism,
            registry,
            0,
            None,
            None,
            operation,
            false,
            &mut NestingBudget::new(),
        )
    }
}

/// Custom registry for exclusion/unbound/vendor R11 tests.
fn r11_registry(
    bindings: &[(&str, u64)],
    parameterless: &[u64],
    excluded: &[u64],
) -> MechanismRegistry {
    MechanismRegistry::from_parts(
        bindings.iter().map(|(shape, mech)| (*mech, shape.to_string())).collect(),
        parameterless.iter().copied().collect(),
        excluded.iter().copied().collect(),
        DiscoveryMode::Transparent,
        "r11-test".to_string(),
    )
}

fn r11_mechanism(mech: u64, p_parameter: CK_VOID_PTR, ul_parameter_len: CK_ULONG) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: mech as CK_MECHANISM_TYPE,
        pParameter: p_parameter,
        ulParameterLen: ul_parameter_len,
    }
}

/// Expected R7 wire fingerprint for `shape` at `length` under `abi` (the
/// resolver selects the same form the reader routes on).
fn r11_expected_fingerprint_for_abi(
    shape: &str,
    mechanism: u64,
    length: u64,
    abi: ParamAbi,
) -> u64 {
    ShapeResolver::resolve(
        Some(shape),
        OperationContext { mechanism, operation: Operation::General, length },
        abi,
    )
    .expect("R11 fixture shape must resolve")
    .fingerprint(abi)
}

/// Expected R7 wire fingerprint for `shape` at `length` under LP64.
fn r11_expected_fingerprint(shape: &str, mechanism: u64, length: u64) -> u64 {
    r11_expected_fingerprint_for_abi(shape, mechanism, length, R11_LP64)
}

/// v1 read with the HOST-native local ABI (for struct-canonical fixtures,
/// which are host-native): backend = local (same-ABI pair). Portable: on
/// big-endian hosts `native()` is `None` and the reader takes the
/// typed-fallback path with identical typed assertions.
unsafe fn read_r11_v1_native_abi(
    mechanism: &CK_MECHANISM,
    registry: &MechanismRegistry,
    operation: Operation,
) -> Result<CkMechanism, CkRv> {
    let abi = ParamAbi::native();
    unsafe {
        read_mechanism_for_transport_with_snapshots(
            mechanism,
            registry,
            1,
            abi,
            abi,
            operation,
            false,
            &mut NestingBudget::new(),
        )
    }
}

/// v1 read with explicit local/backend ABIs (width-matrix tests).
unsafe fn read_r11_v1_abis(
    mechanism: &CK_MECHANISM,
    registry: &MechanismRegistry,
    operation: Operation,
    local_abi: Option<ParamAbi>,
    backend_abi: Option<ParamAbi>,
) -> Result<CkMechanism, CkRv> {
    unsafe {
        read_mechanism_for_transport_with_snapshots(
            mechanism,
            registry,
            1,
            local_abi,
            backend_abi,
            operation,
            false,
            &mut NestingBudget::new(),
        )
    }
}

/// Host-native `CK_GCM_PARAMS` over caller-owned buffers (the struct copies
/// the pointers; the caller keeps the buffers alive through the read).
fn r11_gcm_params(iv: *mut u8, iv_len: CK_ULONG, aad: *mut u8, aad_len: CK_ULONG) -> CK_GCM_PARAMS {
    CK_GCM_PARAMS {
        pIv: iv,
        ulIvLen: iv_len,
        ulIvBits: 96,
        pAAD: aad,
        ulAADLen: aad_len,
        ulTagBits: 128,
    }
}

/// Assert the v1 Flat envelope (declared length, threaded version, source
/// ABI, wire fingerprint) plus verbatim bytes.
fn r11_assert_flat(p: &FlatParams, expected: &[u8], fingerprint: u64) {
    assert_eq!(p.declared_len, expected.len() as u64);
    assert_eq!(p.version, MECHANISM_PARAMETER_TRANSPORT_VERSION);
    assert_eq!(p.source_abi, Some(R11_LP64));
    assert_eq!(p.fingerprint, fingerprint);
    p.bytes.expose(|bytes| assert_eq!(bytes, expected));
}

/// Assert a v1 Null member (declared length + threaded version, no bytes).
fn r11_assert_null(params: &Option<CkMechanismParams>, declared_len: u64) {
    match params {
        Some(CkMechanismParams::Null { declared_len: n, version }) => {
            assert_eq!(*n, declared_len);
            assert_eq!(*version, MECHANISM_PARAMETER_TRANSPORT_VERSION);
        }
        other => panic!("expected v1 Null({declared_len}), got {other:?}"),
    }
}

#[test]
fn read_raw_bytes_overlong_errors_while_empty_stays_empty() {
    // W1-L12-06: the raw-bytes reader must not conflate "overlong" with
    // "empty" — overlong is an explicit MECHANISM_PARAM_INVALID error
    // (matching the `read_mechanism_for_transport` legacy entry gate),
    // empty stays empty.
    let overlong = MAX_MECHANISM_PARAM_STRUCT_LEN + 1;
    // No memory is touched on the overlong path, so a null pointer is
    // a valid probe for the length check itself.
    let err = unsafe { read_raw_bytes(std::ptr::null_mut(), overlong) }
        .expect_err("overlong raw params must error, not read");
    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);

    // Empty stays empty: len 0 reads nothing.
    let mut sentinel = 0xA5u8;
    let empty =
        unsafe { read_raw_bytes(std::ptr::addr_of_mut!(sentinel).cast(), 0) }.expect("empty read");
    assert!(empty.is_empty());

    // Ordinary lengths still read through.
    let data = [0x5Au8; 16];
    let out = unsafe { read_raw_bytes(data.as_ptr() as *mut std::ffi::c_void, data.len()) }
        .expect("bounded read");
    assert_eq!(out, data);
}

#[test]
fn unsafe_official_lengthless_parameter_shapes_are_rejected_before_shim_read() {
    let registry = default_registry();
    let mut opaque = [0xA5u8];

    for mechanism_type in [
        CKM_CMS_SIG,
        CKM_X3DH_INITIALIZE,
        CKM_X3DH_RESPOND,
        CKM_X2RATCHET_INITIALIZE,
        CKM_X2RATCHET_RESPOND,
    ] {
        let mechanism = CK_MECHANISM {
            mechanism: mechanism_type,
            pParameter: opaque.as_mut_ptr() as CK_VOID_PTR,
            ulParameterLen: opaque.len() as CK_ULONG,
        };

        // Unbound + unlisted under both capabilities: legacy rejects via
        // the fused `check_operation`, v1 via UnknownShape. Same RV.
        for (name, result) in [
            ("legacy", unsafe { read_r11_legacy(&mechanism, &registry, Operation::General) }),
            ("v1", unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }),
        ] {
            assert!(
                matches!(result, Err(CkRv::MECHANISM_PARAM_INVALID)),
                "0x{mechanism_type:08X} should reject unmodeled caller-owned pointer shapes ({name})"
            );
        }
    }
}

#[test]
fn reads_common_mechanism_parameter_structs() {
    let mut source_data = [0xA0u8, 0xA1, 0xA2];
    let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        source: 1,
        pSourceData: source_data.as_mut_ptr() as CK_VOID_PTR,
        ulSourceDataLen: source_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::RSA_PKCS_OAEP.0 as CK_MECHANISM_TYPE,
        pParameter: &mut oaep as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams { source_data, .. }) => {
            assert_eq!(source_data, SecretBytes::copy_from_slice(&[0xA0, 0xA1, 0xA2]));
        }
        other => panic!("unexpected OAEP params: {other:?}"),
    }

    let mut pss = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        sLen: 32,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::RSA_PKCS_PSS.0 as CK_MECHANISM_TYPE,
        pParameter: &mut pss as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams { hash_alg, salt_len, .. }) => {
            assert_eq!(hash_alg, CkMechanismType::SHA256);
            assert_eq!(salt_len, 32);
        }
        other => panic!("unexpected PSS params: {other:?}"),
    }

    let mut iv = [0x10; 12];
    let mut aad = [0xAA, 0xBB, 0xCC];
    let mut gcm = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvBits: 96,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
        pParameter: &mut gcm as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Gcm(GcmParams { iv, iv_bits, iv_buffer_len, aad, tag_bits, .. }) => {
            assert_eq!(iv, [0x10; 12]);
            assert_eq!(iv_bits, 96);
            assert_eq!(iv_buffer_len, 12);
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xAA, 0xBB, 0xCC]));
            assert_eq!(tag_bits, 128);
        }
        other => panic!("unexpected GCM params: {other:?}"),
    }

    let mut cbc_iv = [0x55u8; 16];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_CBC.0 as CK_MECHANISM_TYPE,
        pParameter: cbc_iv.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: cbc_iv.len() as CK_ULONG,
    };
    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Iv(params) => assert_eq!(params.iv, [0x55; 16]),
        other => panic!("unexpected CBC IV params: {other:?}"),
    }

    const CKM_AES_CTR: CK_MECHANISM_TYPE = 0x0000_1086;
    let mut ctr = CK_AES_CTR_PARAMS { ulCounterBits: 128, cb: [0x33; 16] };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CTR,
        pParameter: &mut ctr as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_AES_CTR_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::AesCtr(params) => {
            assert_eq!(params.counter_bits, 128);
            assert_eq!(params.cb, [0x33; 16]);
        }
        other => panic!("unexpected CTR params: {other:?}"),
    }
}

#[test]
fn gmac_bare_iv_forwards_verbatim_as_iv() {
    // T20: 2.40-style callers (BouncyHSM) pass bare IV bytes for GMAC —
    // shorter than CK_GCM_PARAMS, flat and pointer-free, forwarded
    // verbatim exactly as the old "iv" mapping did. Registry-driven so
    // the TOML mapping itself is pinned.
    let mut iv = [0x11u8; 12];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GMAC.0 as CK_MECHANISM_TYPE,
        pParameter: iv.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: iv.len() as CK_ULONG,
    };
    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Iv(IvParams { iv }) => assert_eq!(iv, [0x11; 12]),
        other => panic!("unexpected GMAC bare-IV params: {other:?}"),
    }
}

#[test]
fn gmac_struct_params_parse_as_gcm_without_forwarding_pointers() {
    // T20: 3.x-style callers (freehsm-c) pass a CK_GCM_PARAMS struct for
    // GMAC. The struct half must be parsed — IV/AAD bytes copied
    // client-side — and never forwarded verbatim: the embedded pIv/pAAD
    // are client-process pointers that segfaulted the daemon (freehsm-c
    // AES-GMAC SIGSEGV). Uses the freehsm shape: NULL AAD with zero
    // length alongside a real IV.
    let mut iv = [0x11u8; 12];
    let mut gcm = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvBits: 96,
        pAAD: std::ptr::null_mut(),
        ulAADLen: 0,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GMAC.0 as CK_MECHANISM_TYPE,
        pParameter: &mut gcm as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Gcm(GcmParams {
            iv, iv_bits, aad, tag_bits, iv_null, aad_null, ..
        }) => {
            assert_eq!(iv, [0x11; 12]);
            assert_eq!(iv_bits, 96);
            assert_eq!(aad, SecretBytes::copy_from_slice(&[]));
            assert_eq!(tag_bits, 128);
            assert!(!iv_null);
            assert!(aad_null);
        }
        other => panic!("unexpected GMAC struct params: {other:?}"),
    }
}

#[test]
fn reads_handle_string_and_sign_context_parameter_structs() {
    let mut object_handle: CK_OBJECT_HANDLE = 0xCAFE;
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType(0x0000_0500).0 as CK_MECHANISM_TYPE,
        pParameter: &mut object_handle as *mut CK_OBJECT_HANDLE as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_OBJECT_HANDLE>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("object_handle")) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::ObjectHandle(params)) => {
            assert_eq!(params.handle.0, 0xCAFE);
        }
        other => panic!("unexpected object handle params: {other:?}"),
    }

    let mut derivation_data = [0xDE, 0xAD, 0xBE, 0xEF];
    let mut key_derivation = CK_KEY_DERIVATION_STRING_DATA {
        pData: derivation_data.as_mut_ptr(),
        ulLen: derivation_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType(0x0000_0501).0 as CK_MECHANISM_TYPE,
        pParameter: &mut key_derivation as *mut CK_KEY_DERIVATION_STRING_DATA as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KEY_DERIVATION_STRING_DATA>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("key_derivation_string")) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::KeyDerivationString(params)) => {
            assert_eq!(params.data, SecretBytes::copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]));
        }
        other => panic!("unexpected key derivation string params: {other:?}"),
    }

    #[repr(C)]
    struct TestSignAdditionalContext {
        hedge_variant: CK_ULONG,
        p_context: *mut CK_BYTE,
        ul_context_len: CK_ULONG,
    }

    let mut sign_context = [0xA1, 0xA2, 0xA3];
    let mut additional_context = TestSignAdditionalContext {
        hedge_variant: 1,
        p_context: sign_context.as_mut_ptr(),
        ul_context_len: sign_context.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType(0x0000_0502).0 as CK_MECHANISM_TYPE,
        pParameter: &mut additional_context as *mut TestSignAdditionalContext as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<TestSignAdditionalContext>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("sign_additional_context")) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::SignAdditionalContext(params)) => {
            assert_eq!(params.hedge_variant, 1);
            assert_eq!(params.context, SecretBytes::copy_from_slice(&[0xA1, 0xA2, 0xA3]));
        }
        other => panic!("unexpected sign additional context params: {other:?}"),
    }
}

#[test]
fn reads_signature_parameter_structs() {
    const CKM_TEST_EDDSA: CK_MECHANISM_TYPE = 0x8000_1040;
    const CKM_TEST_XEDDSA: CK_MECHANISM_TYPE = 0x8000_1041;

    let mut context = [0xA1u8, 0xA2, 0xA3];
    let mut eddsa = CK_EDDSA_PARAMS {
        phFlag: CK_TRUE,
        ulContextDataLen: context.len() as CK_ULONG,
        pContextData: context.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_EDDSA,
        pParameter: &mut eddsa as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_EDDSA_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("eddsa")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Eddsa(params) => {
            assert!(params.ph_flag);
            assert_eq!(params.context_data, vec![0xA1, 0xA2, 0xA3].into());
        }
        other => panic!("unexpected EdDSA params: {other:?}"),
    }

    let mut xeddsa = CK_XEDDSA_PARAMS { hash: CkMechanismType::SHA256.0 as CK_ULONG };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_XEDDSA,
        pParameter: &mut xeddsa as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_XEDDSA_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("xeddsa")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Xeddsa(params) => {
            assert_eq!(params.hash, CkMechanismType::SHA256);
        }
        other => panic!("unexpected XEdDSA params: {other:?}"),
    }
}

#[test]
fn reads_rsa_wrap_parameter_structs() {
    let mut source_data = [0xA0u8, 0xA1, 0xA2];
    let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        source: 1,
        pSourceData: source_data.as_mut_ptr() as CK_VOID_PTR,
        ulSourceDataLen: source_data.len() as CK_ULONG,
    };
    let mut rsa_aes_wrap = CK_RSA_AES_KEY_WRAP_PARAMS { ulAESKeyBits: 256, pOAEPParams: &mut oaep };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType(0x0000_1054).0 as CK_MECHANISM_TYPE,
        pParameter: &mut rsa_aes_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams { aes_key_bits, oaep_params }) => {
            assert_eq!(aes_key_bits, 256);
            assert_eq!(oaep_params.hash_alg, CkMechanismType::SHA256);
            assert_eq!(oaep_params.mgf, CkMgf(1));
            assert_eq!(oaep_params.source, CkOaepSource(1));
            assert_eq!(oaep_params.source_data, SecretBytes::copy_from_slice(&[0xA0, 0xA1, 0xA2]));
        }
        other => panic!("unexpected RSA-AES key wrap params: {other:?}"),
    }

    let mut x = [0x51u8, 0x52, 0x53, 0x54];
    let mut key_wrap_set =
        CK_KEY_WRAP_SET_OAEP_PARAMS { bBC: 7, pX: x.as_mut_ptr(), ulXLen: x.len() as CK_ULONG };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType(0x0000_0401).0 as CK_MECHANISM_TYPE,
        pParameter: &mut key_wrap_set as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KEY_WRAP_SET_OAEP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::KeyWrapSetOaep(KeyWrapSetOaepParams { bc, x, x_presence }) => {
            assert_eq!(bc, 7);
            assert_eq!(x, SecretBytes::copy_from_slice(&[0x51, 0x52, 0x53, 0x54]));
            assert_eq!(x_presence, PointerBytes::present_copy(&[0x51, 0x52, 0x53, 0x54]));
        }
        other => panic!("unexpected SET OAEP key wrap params: {other:?}"),
    }
}

#[test]
fn reads_authenticated_wrap_parameter_structs() {
    const CKM_TEST_GCM_WRAP: CK_MECHANISM_TYPE = 0x8000_1030;
    const CKM_TEST_CCM_WRAP: CK_MECHANISM_TYPE = 0x8000_1031;

    let mut iv = [0x11u8; 12];
    let mut gcm_aad = [0xA1u8, 0xA2];
    let mut gcm_wrap = CK_GCM_WRAP_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 32,
        ivGenerator: 1,
        pAAD: gcm_aad.as_mut_ptr(),
        ulAADLen: gcm_aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_GCM_WRAP,
        pParameter: &mut gcm_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("gcm_wrap")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::GcmWrap(GcmWrapParams {
            iv,
            iv_fixed_bits,
            iv_generator,
            aad,
            tag_bits,
            iv_presence,
            aad_presence,
        }) => {
            assert_eq!(iv, [0x11; 12]);
            assert_eq!(iv_fixed_bits, 32);
            assert_eq!(iv_generator, CkGeneratorFunction(1));
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xA1, 0xA2]));
            assert_eq!(tag_bits, 128);
            assert_eq!(iv_presence, PointerBytes::present_copy(&[0x11; 12]));
            assert_eq!(aad_presence, PointerBytes::present_copy(&[0xA1, 0xA2]));
        }
        other => panic!("unexpected GCM wrap params: {other:?}"),
    }

    let mut nonce = [0x22u8; 7];
    let mut ccm_aad = [0xB1u8, 0xB2, 0xB3];
    let mut ccm_wrap = CK_CCM_WRAP_PARAMS {
        ulDataLen: 1024,
        pNonce: nonce.as_mut_ptr(),
        ulNonceLen: nonce.len() as CK_ULONG,
        ulNonceFixedBits: 24,
        nonceGenerator: 2,
        pAAD: ccm_aad.as_mut_ptr(),
        ulAADLen: ccm_aad.len() as CK_ULONG,
        ulMACLen: 16,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_CCM_WRAP,
        pParameter: &mut ccm_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_CCM_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ccm_wrap")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::CcmWrap(CcmWrapParams {
            data_len,
            nonce,
            nonce_fixed_bits,
            nonce_generator,
            aad,
            mac_len,
            nonce_presence,
            aad_presence,
        }) => {
            assert_eq!(data_len, 1024);
            assert_eq!(nonce, [0x22; 7]);
            assert_eq!(nonce_fixed_bits, 24);
            assert_eq!(nonce_generator, CkGeneratorFunction(2));
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xB1, 0xB2, 0xB3]));
            assert_eq!(mac_len, 16);
            assert_eq!(nonce_presence, PointerBytes::present_copy(&[0x22; 7]));
            assert_eq!(aad_presence, PointerBytes::present_copy(&[0xB1, 0xB2, 0xB3]));
        }
        other => panic!("unexpected CCM wrap params: {other:?}"),
    }
}

#[test]
fn wrap_key_reader_uses_v32_aead_wrap_shapes() {
    let registry = default_registry();

    let mut iv = [0x11u8; 12];
    let mut gcm_aad = [0xA1u8, 0xA2];
    let mut gcm_wrap = CK_GCM_WRAP_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 32,
        ivGenerator: CKG_GENERATE as _,
        pAAD: gcm_aad.as_mut_ptr(),
        ulAADLen: gcm_aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: &mut gcm_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_r11_legacy(&mechanism, &registry, Operation::WrapKey) }
        .expect("read mechanism")
        .params
        .expect("params")
    {
        CkMechanismParams::GcmWrap(GcmWrapParams { iv, iv_generator, aad, .. }) => {
            assert_eq!(iv, [0x11; 12]);
            assert_eq!(iv_generator, CkGeneratorFunction(CKG_GENERATE as u64));
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xA1, 0xA2]));
        }
        other => panic!("unexpected GCM wrap-key params: {other:?}"),
    }
    // R11 v1 leg: exact wrap size under WrapKey is canonical for the wrap
    // layout → same typed output via the v1 path.
    match unsafe { read_r11_v1(&mechanism, &registry, Operation::WrapKey) }
        .expect("read mechanism")
        .params
        .expect("params")
    {
        CkMechanismParams::GcmWrap(GcmWrapParams { iv, aad, .. }) => {
            assert_eq!(iv, [0x11; 12]);
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xA1, 0xA2]));
        }
        other => panic!("v1 WrapKey must stay typed GcmWrap, got {other:?}"),
    }

    let mut nonce = [0x22u8; 12];
    let mut ccm_aad = [0xB1u8, 0xB2, 0xB3];
    let mut ccm_wrap = CK_CCM_WRAP_PARAMS {
        ulDataLen: 16,
        pNonce: nonce.as_mut_ptr(),
        ulNonceLen: nonce.len() as CK_ULONG,
        ulNonceFixedBits: 0,
        nonceGenerator: CKG_GENERATE as _,
        pAAD: ccm_aad.as_mut_ptr(),
        ulAADLen: ccm_aad.len() as CK_ULONG,
        ulMACLen: 16,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CCM,
        pParameter: &mut ccm_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_CCM_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_r11_legacy(&mechanism, &registry, Operation::WrapKey) }
        .expect("read mechanism")
        .params
        .expect("params")
    {
        CkMechanismParams::CcmWrap(CcmWrapParams {
            data_len,
            nonce,
            nonce_generator,
            aad,
            mac_len,
            ..
        }) => {
            assert_eq!(data_len, 16);
            assert_eq!(nonce, [0x22; 12]);
            assert_eq!(nonce_generator, CkGeneratorFunction(CKG_GENERATE as u64));
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xB1, 0xB2, 0xB3]));
            assert_eq!(mac_len, 16);
        }
        other => panic!("unexpected CCM wrap-key params: {other:?}"),
    }
    // R11 v1 leg: exact wrap size under WrapKey is canonical for the wrap
    // layout → same typed output via the v1 path.
    match unsafe { read_r11_v1(&mechanism, &registry, Operation::WrapKey) }
        .expect("read mechanism")
        .params
        .expect("params")
    {
        CkMechanismParams::CcmWrap(CcmWrapParams { data_len, nonce, mac_len, .. }) => {
            assert_eq!(data_len, 16);
            assert_eq!(nonce, [0x22; 12]);
            assert_eq!(mac_len, 16);
        }
        other => panic!("v1 WrapKey must stay typed CcmWrap, got {other:?}"),
    }
}

#[test]
fn wrap_key_reader_uses_wrap_shapes_only_on_exact_v32_size() {
    let registry = default_registry();

    #[repr(C)]
    struct GcmWithPadding {
        params: CK_GCM_PARAMS,
        padding: [CK_ULONG; 4],
    }

    #[repr(C)]
    struct CcmWithPadding {
        params: CK_CCM_PARAMS,
        padding: [CK_ULONG; 4],
    }

    assert!(std::mem::size_of::<GcmWithPadding>() > std::mem::size_of::<CK_GCM_WRAP_PARAMS>());
    assert!(std::mem::size_of::<CcmWithPadding>() > std::mem::size_of::<CK_CCM_WRAP_PARAMS>());

    let mut iv = [0x33u8; 12];
    let mut gcm_aad = [0xC1u8, 0xC2];
    let mut gcm_padded = GcmWithPadding {
        params: CK_GCM_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: 96,
            pAAD: gcm_aad.as_mut_ptr(),
            ulAADLen: gcm_aad.len() as CK_ULONG,
            ulTagBits: 128,
        },
        padding: [0; 4],
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: &mut gcm_padded as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<GcmWithPadding>() as CK_ULONG,
    };
    match unsafe { read_r11_legacy(&mechanism, &registry, Operation::WrapKey) }
        .expect("read mechanism")
        .params
        .expect("params")
    {
        CkMechanismParams::Gcm(GcmParams { iv, aad, tag_bits, .. }) => {
            assert_eq!(iv, [0x33; 12]);
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xC1, 0xC2]));
            assert_eq!(tag_bits, 128);
        }
        other => panic!("larger non-wrap GCM params must not be parsed as wrap: {other:?}"),
    }
    // R11 v1 leg: the same oversized input is noncanonical for a pointer
    // struct — Flat cannot reach past the safe prefix (S2 §5 residual
    // limit; typed-plus-tail only on provider evidence) → MPI.
    assert!(
        matches!(
            unsafe { read_r11_v1(&mechanism, &registry, Operation::WrapKey) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "v1 must reject pointer-bearing oversized GCM (residual limit)"
    );

    let mut nonce = [0x44u8; 12];
    let mut ccm_aad = [0xD1u8, 0xD2];
    let mut ccm_padded = CcmWithPadding {
        params: CK_CCM_PARAMS {
            ulDataLen: 16,
            pNonce: nonce.as_mut_ptr(),
            ulNonceLen: nonce.len() as CK_ULONG,
            pAAD: ccm_aad.as_mut_ptr(),
            ulAADLen: ccm_aad.len() as CK_ULONG,
            ulMACLen: 16,
        },
        padding: [0; 4],
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CCM,
        pParameter: &mut ccm_padded as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CcmWithPadding>() as CK_ULONG,
    };
    match unsafe { read_r11_legacy(&mechanism, &registry, Operation::WrapKey) }
        .expect("read mechanism")
        .params
        .expect("params")
    {
        CkMechanismParams::Ccm(CcmParams { data_len, nonce, aad, mac_len, .. }) => {
            assert_eq!(data_len, 16);
            assert_eq!(nonce, [0x44; 12]);
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xD1, 0xD2]));
            assert_eq!(mac_len, 16);
        }
        other => panic!("larger non-wrap CCM params must not be parsed as wrap: {other:?}"),
    }
    // R11 v1 leg: residual limit, CCM half (see the GCM leg above).
    assert!(
        matches!(
            unsafe { read_r11_v1(&mechanism, &registry, Operation::WrapKey) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "v1 must reject pointer-bearing oversized CCM (residual limit)"
    );
}

#[test]
fn write_mechanism_output_params_writes_aead_wrap_generated_fields() {
    let mut iv = [0u8; 12];
    let mut gcm_wrap = CK_GCM_WRAP_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 0,
        ivGenerator: CKG_GENERATE as _,
        pAAD: std::ptr::null_mut(),
        ulAADLen: 0,
        ulTagBits: 128,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: &mut gcm_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_WRAP_PARAMS>() as CK_ULONG,
    };
    let output = CkMechanismParams::GcmWrap(GcmWrapParams {
        iv: vec![1, 2, 3, 4],
        iv_fixed_bits: 0,
        iv_generator: CkGeneratorFunction(CKG_GENERATE as u64),
        aad: Vec::new().into(),
        tag_bits: 96,
        iv_presence: PointerBytes::present_copy(&[1, 2, 3, 4]),
        aad_presence: PointerBytes::present_copy(&[]),
    });
    let plan = unsafe { prepare_mechanism_output_params(&mut mechanism, &output) }
        .expect("valid output prepares");
    unsafe { plan.commit() };
    assert_eq!(&iv[..4], &[1, 2, 3, 4]);
    // E0793: params structs are packed on Windows; assert on by-value copies.
    let (gcm_iv_len, gcm_tag_bits) = (gcm_wrap.ulIvLen, gcm_wrap.ulTagBits);
    assert_eq!(gcm_iv_len, 4);
    assert_eq!(gcm_tag_bits, 96);

    let mut nonce = [0u8; 12];
    let mut ccm_wrap = CK_CCM_WRAP_PARAMS {
        ulDataLen: 16,
        pNonce: nonce.as_mut_ptr(),
        ulNonceLen: nonce.len() as CK_ULONG,
        ulNonceFixedBits: 0,
        nonceGenerator: CKG_GENERATE as _,
        pAAD: std::ptr::null_mut(),
        ulAADLen: 0,
        ulMACLen: 16,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CCM,
        pParameter: &mut ccm_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_CCM_WRAP_PARAMS>() as CK_ULONG,
    };
    let output = CkMechanismParams::CcmWrap(CcmWrapParams {
        data_len: 16,
        nonce: vec![9, 8, 7, 6],
        nonce_fixed_bits: 0,
        nonce_generator: CkGeneratorFunction(CKG_GENERATE as u64),
        aad: Vec::new().into(),
        mac_len: 12,
        nonce_presence: PointerBytes::present_copy(&[9, 8, 7, 6]),
        aad_presence: PointerBytes::present_copy(&[]),
    });
    let plan = unsafe { prepare_mechanism_output_params(&mut mechanism, &output) }
        .expect("valid output prepares");
    unsafe { plan.commit() };
    assert_eq!(&nonce[..4], &[9, 8, 7, 6]);
    let (ccm_nonce_len, ccm_mac_len) = (ccm_wrap.ulNonceLen, ccm_wrap.ulMACLen);
    assert_eq!(ccm_nonce_len, 4);
    assert_eq!(ccm_mac_len, 12);
}

#[test]
fn reads_aead_and_chacha_parameter_structs() {
    const CKM_TEST_CCM: CK_MECHANISM_TYPE = 0x8000_1040;
    const CKM_TEST_CHACHA20: CK_MECHANISM_TYPE = 0x8000_1041;
    const CKM_TEST_SALSA_CHACHA_POLY1305: CK_MECHANISM_TYPE = 0x8000_1042;

    let mut nonce = [0x31u8; 11];
    let mut ccm_aad = [0xC1u8, 0xC2];
    let mut ccm = CK_CCM_PARAMS {
        ulDataLen: 2048,
        pNonce: nonce.as_mut_ptr(),
        ulNonceLen: nonce.len() as CK_ULONG,
        pAAD: ccm_aad.as_mut_ptr(),
        ulAADLen: ccm_aad.len() as CK_ULONG,
        ulMACLen: 12,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_CCM,
        pParameter: &mut ccm as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_CCM_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ccm")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Ccm(CcmParams {
            data_len,
            nonce,
            aad,
            mac_len,
            nonce_null,
            aad_null,
            nonce_presence,
            aad_presence,
        }) => {
            assert_eq!(data_len, 2048);
            assert_eq!(nonce, [0x31; 11]);
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0xC1, 0xC2]));
            assert_eq!(mac_len, 12);
            assert!(!nonce_null);
            assert!(!aad_null);
            assert_eq!(nonce_presence, PointerBytes::from_legacy(&[0x31; 11], false));
            assert_eq!(aad_presence, PointerBytes::from_legacy(&[0xC1, 0xC2], false));
        }
        other => panic!("unexpected CCM params: {other:?}"),
    }

    let mut block_counter = [0x41u8; 4];
    let mut chacha_nonce = [0x42u8; 12];
    let mut chacha = CK_CHACHA20_PARAMS {
        pBlockCounter: block_counter.as_mut_ptr(),
        blockCounterBits: 32,
        pNonce: chacha_nonce.as_mut_ptr(),
        ulNonceBits: 96,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_CHACHA20,
        pParameter: &mut chacha as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_CHACHA20_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("chacha20")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::ChaCha20(ChaCha20Params {
            block_counter,
            block_counter_bits,
            nonce,
            nonce_bits,
            block_counter_presence,
            nonce_presence,
        }) => {
            assert_eq!(block_counter, [0x41; 4]);
            assert_eq!(block_counter_bits, 32);
            assert_eq!(nonce, [0x42; 12]);
            assert_eq!(nonce_bits, 96);
            assert_eq!(block_counter_presence, PointerBytes::present_copy(&[0x41; 4]));
            assert_eq!(nonce_presence, PointerBytes::present_copy(&[0x42; 12]));
        }
        other => panic!("unexpected ChaCha20 params: {other:?}"),
    }

    let mut poly_nonce = [0x51u8; 12];
    let mut poly_aad = [0x52u8, 0x53, 0x54];
    let mut salsa_chacha_poly = CK_SALSA20_CHACHA20_POLY1305_PARAMS {
        pNonce: poly_nonce.as_mut_ptr(),
        ulNonceLen: poly_nonce.len() as CK_ULONG,
        pAAD: poly_aad.as_mut_ptr(),
        ulAADLen: poly_aad.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_SALSA_CHACHA_POLY1305,
        pParameter: &mut salsa_chacha_poly as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SALSA20_CHACHA20_POLY1305_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("salsa20_chacha20_poly1305")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Salsa20ChaCha20Poly1305(Salsa20ChaCha20Poly1305Params {
            nonce,
            aad,
            nonce_presence,
            aad_presence,
        }) => {
            assert_eq!(nonce, [0x51; 12]);
            assert_eq!(aad, SecretBytes::copy_from_slice(&[0x52, 0x53, 0x54]));
            assert_eq!(nonce_presence, PointerBytes::present_copy(&[0x51; 12]));
            assert_eq!(aad_presence, PointerBytes::present_copy(&[0x52, 0x53, 0x54]));
        }
        other => panic!("unexpected Salsa20/ChaCha20-Poly1305 params: {other:?}"),
    }
}

#[test]
fn reads_counter_and_encrypt_data_parameter_structs() {
    const CKM_TEST_AES_CTR: CK_MECHANISM_TYPE = 0x8000_1050;
    const CKM_TEST_CAMELLIA_CTR: CK_MECHANISM_TYPE = 0x8000_1051;
    const CKM_TEST_AES_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x8000_1052;
    const CKM_TEST_DES_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x8000_1053;
    const CKM_TEST_ARIA_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x8000_1054;
    const CKM_TEST_CAMELLIA_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x8000_1055;
    const CKM_TEST_SEED_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x8000_1056;

    let mut aes_ctr = CK_AES_CTR_PARAMS { ulCounterBits: 128, cb: [0xA1; 16] };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_AES_CTR,
        pParameter: &mut aes_ctr as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_AES_CTR_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("aes_ctr")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::AesCtr(params) => {
            assert_eq!(params.counter_bits, 128);
            assert_eq!(params.cb, [0xA1; 16]);
        }
        other => panic!("unexpected AES CTR params: {other:?}"),
    }

    let mut camellia_ctr = CK_CAMELLIA_CTR_PARAMS { ulCounterBits: 64, cb: [0xC1; 16] };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_CAMELLIA_CTR,
        pParameter: &mut camellia_ctr as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_CAMELLIA_CTR_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("camellia_ctr")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::CamelliaCtr(params) => {
            assert_eq!(params.counter_bits, 64);
            assert_eq!(params.cb, [0xC1; 16]);
        }
        other => panic!("unexpected Camellia CTR params: {other:?}"),
    }

    let mut aes_data = [0xA2u8, 0xA3, 0xA4];
    let mut aes = CK_AES_CBC_ENCRYPT_DATA_PARAMS {
        iv: [0xA5; 16],
        pData: aes_data.as_mut_ptr(),
        length: aes_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_AES_CBC_ENCRYPT_DATA,
        pParameter: &mut aes as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_AES_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("aes_cbc_encrypt_data")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::AesCbcEncryptData(params) => {
            assert_eq!(params.iv, [0xA5; 16]);
            assert_eq!(params.data, SecretBytes::copy_from_slice(&[0xA2, 0xA3, 0xA4]));
        }
        other => panic!("unexpected AES CBC encrypt-data params: {other:?}"),
    }

    let mut des_data = [0xD2u8, 0xD3];
    let mut des = CK_DES_CBC_ENCRYPT_DATA_PARAMS {
        iv: [0xD5; 8],
        pData: des_data.as_mut_ptr(),
        length: des_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_DES_CBC_ENCRYPT_DATA,
        pParameter: &mut des as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_DES_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("des_cbc_encrypt_data")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::DesCbcEncryptData(params) => {
            assert_eq!(params.iv, [0xD5; 8]);
            assert_eq!(params.data, SecretBytes::copy_from_slice(&[0xD2, 0xD3]));
        }
        other => panic!("unexpected DES CBC encrypt-data params: {other:?}"),
    }

    let mut aria_data = [0x12u8, 0x13, 0x14, 0x15];
    let mut aria = CK_ARIA_CBC_ENCRYPT_DATA_PARAMS {
        iv: [0x15; 16],
        pData: aria_data.as_mut_ptr(),
        length: aria_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_ARIA_CBC_ENCRYPT_DATA,
        pParameter: &mut aria as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("aria_cbc_encrypt_data")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::AriaCbcEncryptData(params) => {
            assert_eq!(params.iv, [0x15; 16]);
            assert_eq!(params.data, SecretBytes::copy_from_slice(&[0x12, 0x13, 0x14, 0x15]));
        }
        other => panic!("unexpected ARIA CBC encrypt-data params: {other:?}"),
    }

    let mut camellia_data = [0x22u8, 0x23, 0x24];
    let mut camellia = CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS {
        iv: [0x25; 16],
        pData: camellia_data.as_mut_ptr(),
        length: camellia_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_CAMELLIA_CBC_ENCRYPT_DATA,
        pParameter: &mut camellia as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("camellia_cbc_encrypt_data")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::CamelliaCbcEncryptData(params) => {
            assert_eq!(params.iv, [0x25; 16]);
            assert_eq!(params.data, SecretBytes::copy_from_slice(&[0x22, 0x23, 0x24]));
        }
        other => panic!("unexpected Camellia CBC encrypt-data params: {other:?}"),
    }

    let mut seed_data = [0x32u8, 0x33];
    let mut seed = CK_SEED_CBC_ENCRYPT_DATA_PARAMS {
        iv: [0x35; 16],
        pData: seed_data.as_mut_ptr(),
        length: seed_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_SEED_CBC_ENCRYPT_DATA,
        pParameter: &mut seed as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SEED_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("seed_cbc_encrypt_data")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::SeedCbcEncryptData(params) => {
            assert_eq!(params.iv, [0x35; 16]);
            assert_eq!(params.data, SecretBytes::copy_from_slice(&[0x32, 0x33]));
        }
        other => panic!("unexpected SEED CBC encrypt-data params: {other:?}"),
    }
}

#[test]
fn reads_legacy_rc2_rc5_and_salsa20_parameter_structs() {
    const CKM_TEST_RC5: CK_MECHANISM_TYPE = 0x8000_1000;
    const CKM_TEST_RC2_MAC_GENERAL: CK_MECHANISM_TYPE = 0x8000_1001;
    const CKM_TEST_RC5_MAC_GENERAL: CK_MECHANISM_TYPE = 0x8000_1002;
    const CKM_TEST_RC5_CBC: CK_MECHANISM_TYPE = 0x8000_1003;
    const CKM_TEST_SALSA20: CK_MECHANISM_TYPE = 0x8000_1004;
    const CKM_TEST_RC2_CBC: CK_MECHANISM_TYPE = 0x8000_1005;
    const CKM_TEST_MAC_GENERAL: CK_MECHANISM_TYPE = 0x8000_1006;

    let mut rc5 = CK_RC5_PARAMS { ulWordsize: 32, ulRounds: 12 };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_RC5,
        pParameter: &mut rc5 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RC5_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("rc5")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Rc5(params) => {
            assert_eq!(params.word_size, 32);
            assert_eq!(params.rounds, 12);
        }
        other => panic!("unexpected RC5 params: {other:?}"),
    }

    let mut rc2_mac = CK_RC2_MAC_GENERAL_PARAMS { ulEffectiveBits: 128, ulMacLength: 12 };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_RC2_MAC_GENERAL,
        pParameter: &mut rc2_mac as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RC2_MAC_GENERAL_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("rc2_mac_general")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Rc2MacGeneral(params) => {
            assert_eq!(params.effective_bits, 128);
            assert_eq!(params.mac_length, 12);
        }
        other => panic!("unexpected RC2 MAC-GENERAL params: {other:?}"),
    }

    let mut rc5_mac = CK_RC5_MAC_GENERAL_PARAMS { ulWordsize: 32, ulRounds: 16, ulMacLength: 20 };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_RC5_MAC_GENERAL,
        pParameter: &mut rc5_mac as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RC5_MAC_GENERAL_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("rc5_mac_general")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Rc5MacGeneral(params) => {
            assert_eq!(params.word_size, 32);
            assert_eq!(params.rounds, 16);
            assert_eq!(params.mac_length, 20);
        }
        other => panic!("unexpected RC5 MAC-GENERAL params: {other:?}"),
    }

    let mut iv = [0xA5u8; 8];
    let mut rc5_cbc = CK_RC5_CBC_PARAMS {
        ulWordsize: 32,
        ulRounds: 18,
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_RC5_CBC,
        pParameter: &mut rc5_cbc as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RC5_CBC_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("rc5_cbc")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Rc5Cbc(params) => {
            assert_eq!(params.word_size, 32);
            assert_eq!(params.rounds, 18);
            assert_eq!(params.iv, vec![0xA5; 8]);
        }
        other => panic!("unexpected RC5-CBC params: {other:?}"),
    }

    let mut rc2_cbc = CK_RC2_CBC_PARAMS { ulEffectiveBits: 128, iv: [0xC2; 8] };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_RC2_CBC,
        pParameter: &mut rc2_cbc as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RC2_CBC_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("rc2_cbc")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Rc2Cbc(params) => {
            assert_eq!(params.effective_bits, 128);
            assert_eq!(params.iv, vec![0xC2; 8]);
        }
        other => panic!("unexpected RC2-CBC params: {other:?}"),
    }

    let mut mac_length: CK_MAC_GENERAL_PARAMS = 16;
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_MAC_GENERAL,
        pParameter: &mut mac_length as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_MAC_GENERAL_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("mac_general")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::MacGeneral(params) => {
            assert_eq!(params.mac_length, 16);
        }
        other => panic!("unexpected MAC-GENERAL params: {other:?}"),
    }

    let mut block_counter = [0x11u8; 8];
    let mut nonce = [0x22u8; 8];
    let mut salsa20 = CK_SALSA20_PARAMS {
        pBlockCounter: block_counter.as_mut_ptr(),
        pNonce: nonce.as_mut_ptr(),
        ulNonceBits: 64,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_SALSA20,
        pParameter: &mut salsa20 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SALSA20_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("salsa20")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Salsa20(params) => {
            assert_eq!(params.block_counter, vec![0x11; 8]);
            assert_eq!(params.nonce, vec![0x22; 8]);
            assert_eq!(params.nonce_bits, 64);
        }
        other => panic!("unexpected Salsa20 params: {other:?}"),
    }
}

#[test]
fn reads_tls_ssl_parameter_structs() {
    const CKM_TEST_TLS_MAC: CK_MECHANISM_TYPE = 0x8000_1008;
    const CKM_TEST_TLS_PRF: CK_MECHANISM_TYPE = 0x8000_1009;
    const CKM_TEST_TLS_KDF: CK_MECHANISM_TYPE = 0x8000_100A;
    const CKM_TEST_SSL3_MASTER_KEY_DERIVE: CK_MECHANISM_TYPE = 0x8000_100B;
    const CKM_TEST_TLS12_EXTENDED_MASTER_KEY_DERIVE: CK_MECHANISM_TYPE = 0x8000_100C;

    let mut tls_mac = CK_TLS_MAC_PARAMS {
        prfHashMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        ulMacLength: 32,
        ulServerOrClient: 1,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_TLS_MAC,
        pParameter: &mut tls_mac as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS_MAC_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("tls_mac")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::TlsMac(params) => {
            assert_eq!(params.prf_hash_mechanism.0, CkMechanismType::SHA256.0 as u64);
            assert_eq!(params.mac_length, 32);
            assert_eq!(params.server_or_client, 1);
        }
        other => panic!("unexpected TLS MAC params: {other:?}"),
    }

    let mut seed = [0xA1u8, 0xA2, 0xA3];
    let mut label = [0xB1u8, 0xB2];
    let mut output = [0u8; 12];
    let mut output_len = output.len() as CK_ULONG;
    let mut tls_prf = CK_TLS_PRF_PARAMS {
        pSeed: seed.as_mut_ptr(),
        ulSeedLen: seed.len() as CK_ULONG,
        pLabel: label.as_mut_ptr(),
        ulLabelLen: label.len() as CK_ULONG,
        pOutput: output.as_mut_ptr(),
        pulOutputLen: &mut output_len,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_TLS_PRF,
        pParameter: &mut tls_prf as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS_PRF_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("tls_prf")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::TlsPrf(params) => {
            assert_eq!(params.seed, vec![0xA1, 0xA2, 0xA3].into());
            assert_eq!(params.label, vec![0xB1, 0xB2].into());
            assert_eq!(params.output_len, 12);
        }
        other => panic!("unexpected TLS PRF params: {other:?}"),
    }

    let mut client_random = [0x11u8; 4];
    let mut server_random = [0x22u8; 4];
    let mut kdf_label = [0x33u8, 0x34];
    let mut context_data = [0x44u8, 0x45, 0x46];
    let mut tls_kdf = CK_TLS_KDF_PARAMS {
        prfMechanism: CkMechanismType::SHA384.0 as CK_MECHANISM_TYPE,
        pLabel: kdf_label.as_mut_ptr(),
        ulLabelLength: kdf_label.len() as CK_ULONG,
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: client_random.as_mut_ptr(),
            ulClientRandomLen: client_random.len() as CK_ULONG,
            pServerRandom: server_random.as_mut_ptr(),
            ulServerRandomLen: server_random.len() as CK_ULONG,
        },
        pContextData: context_data.as_mut_ptr(),
        ulContextDataLength: context_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_TLS_KDF,
        pParameter: &mut tls_kdf as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS_KDF_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("tls_kdf")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::TlsKdf(params) => {
            assert_eq!(params.prf_mechanism.0, CkMechanismType::SHA384.0 as u64);
            assert_eq!(params.label, vec![0x33, 0x34].into());
            assert_eq!(params.random_info.client_random, vec![0x11; 4]);
            assert_eq!(params.random_info.server_random, vec![0x22; 4]);
            assert_eq!(params.context_data, vec![0x44, 0x45, 0x46].into());
        }
        other => panic!("unexpected TLS KDF params: {other:?}"),
    }

    let mut ssl3_client_random = [0x51u8; 4];
    let mut ssl3_server_random = [0x52u8; 4];
    let mut ssl3_version = CK_VERSION { major: 3, minor: 0 };
    let mut ssl3_master = CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: ssl3_client_random.as_mut_ptr(),
            ulClientRandomLen: ssl3_client_random.len() as CK_ULONG,
            pServerRandom: ssl3_server_random.as_mut_ptr(),
            ulServerRandomLen: ssl3_server_random.len() as CK_ULONG,
        },
        pVersion: &mut ssl3_version,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_SSL3_MASTER_KEY_DERIVE,
        pParameter: &mut ssl3_master as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ssl3_master_key_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Ssl3MasterKeyDerive(params) => {
            assert_eq!(params.random_info.client_random, vec![0x51; 4]);
            assert_eq!(params.random_info.server_random, vec![0x52; 4]);
            assert_eq!(params.version_major, 3);
            assert_eq!(params.version_minor, 0);
        }
        other => panic!("unexpected SSL3 master-key params: {other:?}"),
    }

    let mut session_hash = [0x61u8; 8];
    let mut tls12_version = CK_VERSION { major: 3, minor: 3 };
    let mut tls12_extended = CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS {
        prfHashMechanism: CkMechanismType::SHA512.0 as CK_MECHANISM_TYPE,
        pSessionHash: session_hash.as_mut_ptr(),
        ulSessionHashLen: session_hash.len() as CK_ULONG,
        pVersion: &mut tls12_version,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_TLS12_EXTENDED_MASTER_KEY_DERIVE,
        pParameter: &mut tls12_extended as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>()
            as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("tls12_extended_master_key_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Tls12ExtendedMasterKeyDerive(params) => {
            assert_eq!(params.prf_hash_mechanism.0, CkMechanismType::SHA512.0 as u64);
            assert_eq!(params.session_hash, vec![0x61; 8]);
            assert_eq!(params.version_major, 3);
            assert_eq!(params.version_minor, 3);
        }
        other => panic!("unexpected TLS 1.2 extended master-key params: {other:?}"),
    }
}

#[test]
fn reads_kdf_and_legacy_agreement_parameter_structs() {
    const CKM_TEST_HKDF: CK_MECHANISM_TYPE = 0x8000_100D;
    const CKM_TEST_GOSTR3410_DERIVE: CK_MECHANISM_TYPE = 0x8000_100E;
    const CKM_TEST_GOSTR3410_KEY_WRAP: CK_MECHANISM_TYPE = 0x8000_100F;
    const CKM_TEST_KEA_DERIVE: CK_MECHANISM_TYPE = 0x8000_1012;
    const CKM_TEST_PKCS5_PBKD2: CK_MECHANISM_TYPE = 0x8000_1013;

    let mut salt = [0xA1u8, 0xA2, 0xA3];
    let mut info = [0xB1u8, 0xB2];
    let mut hkdf = CK_HKDF_PARAMS {
        bExtract: CK_TRUE,
        bExpand: CK_TRUE,
        prfHashMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        ulSaltType: 1,
        pSalt: salt.as_mut_ptr(),
        ulSaltLen: salt.len() as CK_ULONG,
        hSaltKey: 0x1234,
        pInfo: info.as_mut_ptr(),
        ulInfoLen: info.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_HKDF,
        pParameter: &mut hkdf as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_HKDF_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("hkdf")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Hkdf(params) => {
            assert!(params.extract);
            assert!(params.expand);
            assert_eq!(params.prf_hash_mechanism.0, CkMechanismType::SHA256.0 as u64);
            assert_eq!(params.salt_type, 1);
            assert_eq!(params.salt, vec![0xA1, 0xA2, 0xA3].into());
            assert_eq!(params.salt_key_handle.0, 0x1234);
            assert_eq!(params.info, vec![0xB1, 0xB2].into());
        }
        other => panic!("unexpected HKDF params: {other:?}"),
    }

    let mut public_data = [0xC1u8, 0xC2, 0xC3];
    let mut ukm = [0xD1u8, 0xD2];
    let mut gostr_derive = CK_GOSTR3410_DERIVE_PARAMS {
        kdf: 1,
        pPublicData: public_data.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        pUKM: ukm.as_mut_ptr(),
        ulUKMLen: ukm.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_GOSTR3410_DERIVE,
        pParameter: &mut gostr_derive as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GOSTR3410_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("gostr3410_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Gostr3410Derive(params) => {
            assert_eq!(params.kdf, CkKdf(1));
            assert_eq!(params.public_data, vec![0xC1, 0xC2, 0xC3]);
            assert_eq!(params.ukm, vec![0xD1, 0xD2]);
        }
        other => panic!("unexpected GOSTR3410 derive params: {other:?}"),
    }

    let mut wrap_oid = [0x06u8, 0x07, 0x2A];
    let mut wrap_ukm = [0xE1u8, 0xE2, 0xE3, 0xE4];
    let mut gostr_wrap = CK_GOSTR3410_KEY_WRAP_PARAMS {
        pWrapOID: wrap_oid.as_mut_ptr(),
        ulWrapOIDLen: wrap_oid.len() as CK_ULONG,
        pUKM: wrap_ukm.as_mut_ptr(),
        ulUKMLen: wrap_ukm.len() as CK_ULONG,
        hKey: 0xBEEF,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_GOSTR3410_KEY_WRAP,
        pParameter: &mut gostr_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GOSTR3410_KEY_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("gostr3410_key_wrap")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Gostr3410KeyWrap(params) => {
            assert_eq!(params.wrap_oid, vec![0x06, 0x07, 0x2A]);
            assert_eq!(params.ukm, vec![0xE1, 0xE2, 0xE3, 0xE4]);
            assert_eq!(params.key_handle.0, 0xBEEF);
        }
        other => panic!("unexpected GOSTR3410 key-wrap params: {other:?}"),
    }

    let mut random_a = [0x11u8, 0x12];
    let mut random_b = [0x21u8, 0x22];
    let mut kea_public = [0x31u8, 0x32, 0x33];
    let mut kea = CK_KEA_DERIVE_PARAMS {
        isSender: CK_TRUE,
        ulRandomLen: random_a.len() as CK_ULONG,
        RandomA: random_a.as_mut_ptr(),
        RandomB: random_b.as_mut_ptr(),
        ulPublicDataLen: kea_public.len() as CK_ULONG,
        PublicData: kea_public.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_KEA_DERIVE,
        pParameter: &mut kea as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KEA_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("kea_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::KeaDerive(params) => {
            assert!(params.is_sender);
            assert_eq!(params.random_a, vec![0x11, 0x12]);
            assert_eq!(params.random_b, vec![0x21, 0x22]);
            assert_eq!(params.public_data, vec![0x31, 0x32, 0x33]);
        }
        other => panic!("unexpected KEA derive params: {other:?}"),
    }

    let mut salt_source_data = [0x41u8, 0x42];
    let mut prf_data = [0x51u8];
    let mut password = [0x73u8, 0x65, 0x63, 0x72, 0x65, 0x74];
    let mut pbkd2 = CK_PKCS5_PBKD2_PARAMS2 {
        saltSource: 1,
        pSaltSourceData: salt_source_data.as_mut_ptr() as CK_VOID_PTR,
        ulSaltSourceDataLen: salt_source_data.len() as CK_ULONG,
        iterations: 600_000,
        prf: 2,
        pPrfData: prf_data.as_mut_ptr() as CK_VOID_PTR,
        ulPrfDataLen: prf_data.len() as CK_ULONG,
        pPassword: password.as_mut_ptr(),
        ulPasswordLen: password.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_PKCS5_PBKD2,
        pParameter: &mut pbkd2 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_PKCS5_PBKD2_PARAMS2>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("pkcs5_pbkd2")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Pkcs5Pbkd2(params) => {
            assert_eq!(params.salt_source, CkPbkdf2SaltSource(1));
            assert_eq!(params.salt_source_data, vec![0x41, 0x42].into());
            assert_eq!(params.iterations, 600_000);
            assert_eq!(params.prf, CkPbkdf2Prf(2));
            assert_eq!(params.prf_data, vec![0x51].into());
            assert_eq!(params.password, SecretBytes::copy_from_slice(b"secret"));
        }
        other => panic!("unexpected PKCS#5 PBKD2 params: {other:?}"),
    }
}

#[test]
fn reads_ecdh_and_x942_parameter_structs() {
    const CKM_TEST_ECDH1_DERIVE: CK_MECHANISM_TYPE = 0x8000_1014;
    const CKM_TEST_ECDH2_DERIVE: CK_MECHANISM_TYPE = 0x8000_1015;
    const CKM_TEST_ECMQV_DERIVE: CK_MECHANISM_TYPE = 0x8000_1016;
    const CKM_TEST_ECDH_AES_KEY_WRAP: CK_MECHANISM_TYPE = 0x8000_1017;
    const CKM_TEST_X942_DH1_DERIVE: CK_MECHANISM_TYPE = 0x8000_1018;
    const CKM_TEST_X942_DH2_DERIVE: CK_MECHANISM_TYPE = 0x8000_1019;

    let mut shared_data = [0xA1u8, 0xA2];
    let mut public_data = [0xB1u8, 0xB2, 0xB3];
    let mut ecdh1 = CK_ECDH1_DERIVE_PARAMS {
        kdf: 7,
        ulSharedDataLen: shared_data.len() as CK_ULONG,
        pSharedData: shared_data.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        pPublicData: public_data.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_ECDH1_DERIVE,
        pParameter: &mut ecdh1 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ecdh1_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Ecdh1Derive(params) => {
            assert_eq!(params.kdf, CkKdf(7));
            assert_eq!(params.shared_data, vec![0xA1, 0xA2].into());
            assert_eq!(params.public_data, vec![0xB1, 0xB2, 0xB3]);
        }
        other => panic!("unexpected ECDH1 derive params: {other:?}"),
    }

    let mut shared_data = [0xC1u8, 0xC2, 0xC3];
    let mut public_data = [0xD1u8, 0xD2];
    let mut public_data2 = [0xE1u8, 0xE2, 0xE3, 0xE4];
    let mut ecdh2 = CK_ECDH2_DERIVE_PARAMS {
        kdf: 8,
        ulSharedDataLen: shared_data.len() as CK_ULONG,
        pSharedData: shared_data.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        pPublicData: public_data.as_mut_ptr(),
        ulPrivateDataLen: 32,
        hPrivateData: 0x1234,
        ulPublicDataLen2: public_data2.len() as CK_ULONG,
        pPublicData2: public_data2.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_ECDH2_DERIVE,
        pParameter: &mut ecdh2 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_ECDH2_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ecdh2_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Ecdh2Derive(params) => {
            assert_eq!(params.kdf, CkKdf(8));
            assert_eq!(params.shared_data, vec![0xC1, 0xC2, 0xC3].into());
            assert_eq!(params.public_data, vec![0xD1, 0xD2]);
            assert_eq!(params.private_data_len, 32);
            assert_eq!(params.private_data_handle.0, 0x1234);
            assert_eq!(params.public_data2, vec![0xE1, 0xE2, 0xE3, 0xE4]);
        }
        other => panic!("unexpected ECDH2 derive params: {other:?}"),
    }

    let mut shared_data = [0x11u8, 0x12];
    let mut public_data = [0x21u8, 0x22, 0x23];
    let mut public_data2 = [0x31u8, 0x32];
    let mut ecmqv = CK_ECMQV_DERIVE_PARAMS {
        kdf: 9,
        ulSharedDataLen: shared_data.len() as CK_ULONG,
        pSharedData: shared_data.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        pPublicData: public_data.as_mut_ptr(),
        ulPrivateDataLen: 48,
        hPrivateData: 0x2345,
        ulPublicDataLen2: public_data2.len() as CK_ULONG,
        pPublicData2: public_data2.as_mut_ptr(),
        publicKey: 0x3456,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_ECMQV_DERIVE,
        pParameter: &mut ecmqv as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_ECMQV_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ecmqv_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::EcmqvDerive(params) => {
            assert_eq!(params.kdf, CkKdf(9));
            assert_eq!(params.shared_data, vec![0x11, 0x12].into());
            assert_eq!(params.public_data, vec![0x21, 0x22, 0x23]);
            assert_eq!(params.private_data_len, 48);
            assert_eq!(params.private_data_handle.0, 0x2345);
            assert_eq!(params.public_data2, vec![0x31, 0x32]);
            assert_eq!(params.public_key_handle.0, 0x3456);
        }
        other => panic!("unexpected ECMQV derive params: {other:?}"),
    }

    let mut shared_data = [0x41u8, 0x42, 0x43];
    let mut ecdh_wrap = CK_ECDH_AES_KEY_WRAP_PARAMS {
        ulAESKeyBits: 256,
        kdf: 10,
        ulSharedDataLen: shared_data.len() as CK_ULONG,
        pSharedData: shared_data.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_ECDH_AES_KEY_WRAP,
        pParameter: &mut ecdh_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_ECDH_AES_KEY_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ecdh_aes_key_wrap")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::EcdhAesKeyWrap(params) => {
            assert_eq!(params.aes_key_bits, 256);
            assert_eq!(params.kdf, CkKdf(10));
            assert_eq!(params.shared_data, vec![0x41, 0x42, 0x43].into());
        }
        other => panic!("unexpected ECDH AES key-wrap params: {other:?}"),
    }

    let mut other_info = [0x51u8, 0x52];
    let mut public_data = [0x61u8, 0x62, 0x63];
    let mut x942_dh1 = CK_X9_42_DH1_DERIVE_PARAMS {
        kdf: 11,
        ulOtherInfoLen: other_info.len() as CK_ULONG,
        pOtherInfo: other_info.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        pPublicData: public_data.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_X942_DH1_DERIVE,
        pParameter: &mut x942_dh1 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_X9_42_DH1_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("x942_dh1_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::X942Dh1Derive(params) => {
            assert_eq!(params.kdf, CkKdf(11));
            assert_eq!(params.other_info, vec![0x51, 0x52].into());
            assert_eq!(params.public_data, vec![0x61, 0x62, 0x63]);
        }
        other => panic!("unexpected X9.42 DH1 derive params: {other:?}"),
    }

    let mut other_info = [0x71u8, 0x72, 0x73];
    let mut public_data = [0x81u8, 0x82];
    let mut public_data2 = [0x91u8, 0x92, 0x93, 0x94];
    let mut x942_dh2 = CK_X9_42_DH2_DERIVE_PARAMS {
        kdf: 12,
        ulOtherInfoLen: other_info.len() as CK_ULONG,
        pOtherInfo: other_info.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        pPublicData: public_data.as_mut_ptr(),
        ulPrivateDataLen: 64,
        hPrivateData: 0x4567,
        ulPublicDataLen2: public_data2.len() as CK_ULONG,
        pPublicData2: public_data2.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_X942_DH2_DERIVE,
        pParameter: &mut x942_dh2 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_X9_42_DH2_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("x942_dh2_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::X942Dh2Derive(params) => {
            assert_eq!(params.kdf, CkKdf(12));
            assert_eq!(params.other_info, vec![0x71, 0x72, 0x73].into());
            assert_eq!(params.public_data, vec![0x81, 0x82]);
            assert_eq!(params.private_data_len, 64);
            assert_eq!(params.private_data_handle.0, 0x4567);
            assert_eq!(params.public_data2, vec![0x91, 0x92, 0x93, 0x94]);
        }
        other => panic!("unexpected X9.42 DH2 derive params: {other:?}"),
    }
}

#[test]
fn reads_ike_parameter_structs() {
    const CKM_TEST_IKE_PRF_DERIVE: CK_MECHANISM_TYPE = 0x8000_101A;
    const CKM_TEST_IKE1_PRF_DERIVE: CK_MECHANISM_TYPE = 0x8000_101B;
    const CKM_TEST_IKE1_EXTENDED_DERIVE: CK_MECHANISM_TYPE = 0x8000_101C;
    const CKM_TEST_IKE2_PRF_PLUS_DERIVE: CK_MECHANISM_TYPE = 0x8000_101D;

    let mut ni = [0xA1u8, 0xA2, 0xA3];
    let mut nr = [0xB1u8, 0xB2];
    let mut ike_prf = CK_IKE_PRF_DERIVE_PARAMS {
        prfMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        bDataAsKey: CK_TRUE,
        bRekey: CK_FALSE,
        pNi: ni.as_mut_ptr(),
        ulNiLen: ni.len() as CK_ULONG,
        pNr: nr.as_mut_ptr(),
        ulNrLen: nr.len() as CK_ULONG,
        hNewKey: 0x1234,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_IKE_PRF_DERIVE,
        pParameter: &mut ike_prf as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_IKE_PRF_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ike_prf_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::IkePrfDerive(params) => {
            assert_eq!(params.prf_mechanism.0, CkMechanismType::SHA256.0 as u64);
            assert!(params.data_as_key);
            assert!(!params.rekey);
            assert_eq!(params.ni, vec![0xA1, 0xA2, 0xA3].into());
            assert_eq!(params.nr, vec![0xB1, 0xB2].into());
            assert_eq!(params.new_key_handle.0, 0x1234);
        }
        other => panic!("unexpected IKE PRF derive params: {other:?}"),
    }

    let mut ckyi = [0xC1u8, 0xC2];
    let mut ckyr = [0xD1u8, 0xD2, 0xD3];
    let mut ike1_prf = CK_IKE1_PRF_DERIVE_PARAMS {
        prfMechanism: CkMechanismType::SHA384.0 as CK_MECHANISM_TYPE,
        bHasPrevKey: CK_TRUE,
        hKeygxy: 0x2345,
        hPrevKey: 0x3456,
        pCKYi: ckyi.as_mut_ptr(),
        ulCKYiLen: ckyi.len() as CK_ULONG,
        pCKYr: ckyr.as_mut_ptr(),
        ulCKYrLen: ckyr.len() as CK_ULONG,
        keyNumber: 3,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_IKE1_PRF_DERIVE,
        pParameter: &mut ike1_prf as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_IKE1_PRF_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ike1_prf_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Ike1PrfDerive(params) => {
            assert_eq!(params.prf_mechanism.0, CkMechanismType::SHA384.0 as u64);
            assert!(params.has_prev_key);
            assert_eq!(params.keygxy_handle.0, 0x2345);
            assert_eq!(params.prev_key_handle.0, 0x3456);
            assert_eq!(params.ckyi, vec![0xC1, 0xC2].into());
            assert_eq!(params.ckyr, vec![0xD1, 0xD2, 0xD3].into());
            assert_eq!(params.key_number, 3);
        }
        other => panic!("unexpected IKE1 PRF derive params: {other:?}"),
    }

    let mut extra_data = [0xE1u8, 0xE2, 0xE3, 0xE4];
    let mut ike1_extended = CK_IKE1_EXTENDED_DERIVE_PARAMS {
        prfMechanism: CkMechanismType::SHA512.0 as CK_MECHANISM_TYPE,
        bHasKeygxy: CK_TRUE,
        hKeygxy: 0x4567,
        pExtraData: extra_data.as_mut_ptr(),
        ulExtraDataLen: extra_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_IKE1_EXTENDED_DERIVE,
        pParameter: &mut ike1_extended as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_IKE1_EXTENDED_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ike1_extended_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Ike1ExtendedDerive(params) => {
            assert_eq!(params.prf_mechanism.0, CkMechanismType::SHA512.0 as u64);
            assert!(params.has_keygxy);
            assert_eq!(params.keygxy_handle.0, 0x4567);
            assert_eq!(params.extra_data, vec![0xE1, 0xE2, 0xE3, 0xE4].into());
        }
        other => panic!("unexpected IKE1 extended derive params: {other:?}"),
    }

    let mut seed_data = [0xF1u8, 0xF2, 0xF3];
    let mut ike2 = CK_IKE2_PRF_PLUS_DERIVE_PARAMS {
        prfMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        bHasSeedKey: CK_TRUE,
        hSeedKey: 0x5678,
        pSeedData: seed_data.as_mut_ptr(),
        ulSeedDataLen: seed_data.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_IKE2_PRF_PLUS_DERIVE,
        pParameter: &mut ike2 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("ike2_prf_plus_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Ike2PrfPlusDerive(params) => {
            assert_eq!(params.prf_mechanism.0, CkMechanismType::SHA256.0 as u64);
            assert!(params.has_seed_key);
            assert_eq!(params.seed_key_handle.0, 0x5678);
            assert_eq!(params.seed_data, vec![0xF1, 0xF2, 0xF3].into());
        }
        other => panic!("unexpected IKE2 PRF-plus derive params: {other:?}"),
    }
}

#[test]
fn reads_wtls_prf_and_x942_mqv_parameter_structs() {
    const CKM_TEST_WTLS_PRF: CK_MECHANISM_TYPE = 0x8000_1010;
    const CKM_TEST_X942_MQV: CK_MECHANISM_TYPE = 0x8000_1011;

    let mut seed = [0xA1u8, 0xA2, 0xA3];
    let mut label = [0xB1u8, 0xB2];
    let mut output = [0u8; 12];
    let mut output_len = output.len() as CK_ULONG;
    let mut wtls = CK_WTLS_PRF_PARAMS {
        DigestMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        pSeed: seed.as_mut_ptr(),
        ulSeedLen: seed.len() as CK_ULONG,
        pLabel: label.as_mut_ptr(),
        ulLabelLen: label.len() as CK_ULONG,
        pOutput: output.as_mut_ptr(),
        pulOutputLen: &mut output_len,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_WTLS_PRF,
        pParameter: &mut wtls as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_WTLS_PRF_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("wtls_prf")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::WtlsPrf(params) => {
            assert_eq!(params.digest_mechanism.0, CkMechanismType::SHA256.0 as u64);
            assert_eq!(params.seed, vec![0xA1, 0xA2, 0xA3].into());
            assert_eq!(params.label, vec![0xB1, 0xB2].into());
            assert_eq!(params.output_len, 12);
        }
        other => panic!("unexpected WTLS PRF params: {other:?}"),
    }

    let mut other_info = [0xC1u8, 0xC2];
    let mut public_data = [0xD1u8, 0xD2, 0xD3];
    let mut public_data2 = [0xE1u8, 0xE2, 0xE3, 0xE4];
    let mut x942 = CK_X9_42_MQV_DERIVE_PARAMS {
        kdf: 7,
        ulOtherInfoLen: other_info.len() as CK_ULONG,
        OtherInfo: other_info.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        PublicData: public_data.as_mut_ptr(),
        ulPrivateDataLen: 32,
        hPrivateData: 77,
        ulPublicDataLen2: public_data2.len() as CK_ULONG,
        PublicData2: public_data2.as_mut_ptr(),
        publicKey: 88,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_X942_MQV,
        pParameter: &mut x942 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_X9_42_MQV_DERIVE_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("x942_mqv_derive")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::X942MqvDerive(params) => {
            assert_eq!(params.kdf, CkKdf(7));
            assert_eq!(params.other_info, vec![0xC1, 0xC2].into());
            assert_eq!(params.public_data, vec![0xD1, 0xD2, 0xD3]);
            assert_eq!(params.private_data_len, 32);
            assert_eq!(params.private_data_handle.0, 77);
            assert_eq!(params.public_data2, vec![0xE1, 0xE2, 0xE3, 0xE4]);
            assert_eq!(params.public_key_handle.0, 88);
        }
        other => panic!("unexpected X9.42 MQV params: {other:?}"),
    }
}

#[test]
fn reads_otp_and_skipjack_parameter_structs() {
    const CKM_TEST_OTP: CK_MECHANISM_TYPE = 0x8000_1020;
    const CKM_TEST_SKIPJACK_PRIVATE_WRAP: CK_MECHANISM_TYPE = 0x8000_1021;
    const CKM_TEST_SKIPJACK_RELAYX: CK_MECHANISM_TYPE = 0x8000_1022;

    let mut otp_value = [0x11u8, 0x12, 0x13];
    let mut otp_pin = [0x21u8, 0x22];
    let mut otp_params = [
        CK_OTP_PARAM {
            type_: 0,
            pValue: otp_value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: otp_value.len() as CK_ULONG,
        },
        CK_OTP_PARAM {
            type_: 1,
            pValue: otp_pin.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: otp_pin.len() as CK_ULONG,
        },
    ];
    let mut otp =
        CK_OTP_PARAMS { pParams: otp_params.as_mut_ptr(), ulCount: otp_params.len() as CK_ULONG };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_OTP,
        pParameter: &mut otp as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_OTP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("otp")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Otp(params) => {
            assert_eq!(params.params.len(), 2);
            assert_eq!(params.params[0].type_, 0);
            assert_eq!(params.params[0].value, vec![0x11, 0x12, 0x13].into());
            assert_eq!(params.params[1].type_, 1);
            assert_eq!(params.params[1].value, vec![0x21, 0x22].into());
        }
        other => panic!("unexpected OTP params: {other:?}"),
    }

    let mut password = [0x31u8, 0x32];
    let mut public_data = [0x41u8, 0x42, 0x43];
    let mut random_a = [0x51u8, 0x52, 0x53, 0x54];
    let mut prime_p = [0x61u8, 0x62];
    let mut base_g = [0x71u8, 0x72];
    let mut subprime_q = [0x81u8, 0x82, 0x83];
    let mut private_wrap = CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
        ulPasswordLen: password.len() as CK_ULONG,
        pPassword: password.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        pPublicData: public_data.as_mut_ptr(),
        ulPAndGLen: prime_p.len() as CK_ULONG,
        ulQLen: subprime_q.len() as CK_ULONG,
        ulRandomLen: random_a.len() as CK_ULONG,
        pRandomA: random_a.as_mut_ptr(),
        pPrimeP: prime_p.as_mut_ptr(),
        pBaseG: base_g.as_mut_ptr(),
        pSubprimeQ: subprime_q.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_SKIPJACK_PRIVATE_WRAP,
        pParameter: &mut private_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SKIPJACK_PRIVATE_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("skipjack_private_wrap")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::SkipjackPrivateWrap(params) => {
            assert_eq!(params.password, vec![0x31, 0x32].into());
            assert_eq!(params.password_length, 2);
            assert_eq!(params.public_data, vec![0x41, 0x42, 0x43]);
            assert_eq!(params.random_a, vec![0x51, 0x52, 0x53, 0x54]);
            assert_eq!(params.prime_p, vec![0x61, 0x62]);
            assert_eq!(params.base_g, vec![0x71, 0x72]);
            assert_eq!(params.subprime_q, vec![0x81, 0x82, 0x83]);
        }
        other => panic!("unexpected Skipjack private-wrap params: {other:?}"),
    }

    let mut old_wrapped_x = [0x91u8, 0x92];
    let mut old_password = [0xA1u8, 0xA2, 0xA3];
    let mut old_public_data = [0xB1u8];
    let mut old_random_a = [0xC1u8, 0xC2];
    let mut new_password = [0xD1u8, 0xD2, 0xD3, 0xD4];
    let mut new_public_data = [0xE1u8, 0xE2];
    let mut new_random_a = [0xF1u8, 0xF2, 0xF3];
    let mut relayx = CK_SKIPJACK_RELAYX_PARAMS {
        ulOldWrappedXLen: old_wrapped_x.len() as CK_ULONG,
        pOldWrappedX: old_wrapped_x.as_mut_ptr(),
        ulOldPasswordLen: old_password.len() as CK_ULONG,
        pOldPassword: old_password.as_mut_ptr(),
        ulOldPublicDataLen: old_public_data.len() as CK_ULONG,
        pOldPublicData: old_public_data.as_mut_ptr(),
        ulOldRandomLen: old_random_a.len() as CK_ULONG,
        pOldRandomA: old_random_a.as_mut_ptr(),
        ulNewPasswordLen: new_password.len() as CK_ULONG,
        pNewPassword: new_password.as_mut_ptr(),
        ulNewPublicDataLen: new_public_data.len() as CK_ULONG,
        pNewPublicData: new_public_data.as_mut_ptr(),
        ulNewRandomLen: new_random_a.len() as CK_ULONG,
        pNewRandomA: new_random_a.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_SKIPJACK_RELAYX,
        pParameter: &mut relayx as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SKIPJACK_RELAYX_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("skipjack_relayx")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::SkipjackRelayx(params) => {
            assert_eq!(params.old_wrapped_x, vec![0x91, 0x92].into());
            assert_eq!(params.old_password, vec![0xA1, 0xA2, 0xA3].into());
            assert_eq!(params.old_public_data, vec![0xB1].into());
            assert_eq!(params.old_random_a, vec![0xC1, 0xC2].into());
            assert_eq!(params.new_password, vec![0xD1, 0xD2, 0xD3, 0xD4].into());
            assert_eq!(params.new_public_data, vec![0xE1, 0xE2].into());
            assert_eq!(params.new_random_a, vec![0xF1, 0xF2, 0xF3].into());
        }
        other => panic!("unexpected Skipjack relayx params: {other:?}"),
    }
}

#[test]
fn reads_kip_parameter_struct_with_nested_mechanism() {
    const CKM_TEST_KIP: CK_MECHANISM_TYPE = 0x8000_1030;

    // Guarded + pinned to legacy: the nested KIP read gathers the
    // global registry/capability snapshots.
    let _guard = crate::tests::shim_state_test_guard();
    crate::interface_probe::set_mechanism_parameter_transport_version_for_tests(0);
    ensure_registry();

    let mut nested = CK_MECHANISM {
        mechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut seed = [0x44u8, 0x45, 0x46];
    let mut kip = CK_KIP_PARAMS {
        pMechanism: &mut nested,
        hKey: 99,
        pSeed: seed.as_mut_ptr(),
        ulSeedLen: seed.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_KIP,
        pParameter: &mut kip as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KIP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("kip")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Kip(params) => {
            assert_eq!(params.mechanism.mechanism_type, CkMechanismType::SHA256);
            assert!(params.mechanism.params.is_none());
            assert_eq!(params.key_handle.0, 99);
            assert_eq!(params.seed, vec![0x44, 0x45, 0x46].into());
        }
        other => panic!("unexpected KIP params: {other:?}"),
    }
}

#[test]
fn oaep_null_source_pointer_with_nonzero_len_stays_raw() {
    let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        source: 1,
        pSourceData: std::ptr::null_mut(),
        ulSourceDataLen: 3,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::RSA_PKCS_OAEP.0 as CK_MECHANISM_TYPE,
        pParameter: &mut oaep as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>());
        }
        other => panic!("expected raw params for invalid OAEP pointer, got {other:?}"),
    }
}

#[test]
fn gcm_null_embedded_pointer_with_nonzero_len_stays_raw() {
    let mut aad = [0xAB, 0xCD];
    let mut gcm = CK_GCM_PARAMS {
        pIv: std::ptr::null_mut(),
        ulIvLen: 12,
        ulIvBits: 96,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
        pParameter: &mut gcm as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_GCM_PARAMS>());
        }
        other => panic!("expected raw params for invalid GCM pointer, got {other:?}"),
    }
}

#[test]
fn gcm_generated_iv_buffer_is_preserved_and_written_back() {
    let mut iv = [0u8; 12];
    let mut gcm = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: 0,
        ulIvBits: 96,
        pAAD: std::ptr::null_mut(),
        ulAADLen: 0,
        ulTagBits: 128,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
        pParameter: &mut gcm as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Gcm(GcmParams { iv, iv_bits, iv_buffer_len, aad, tag_bits, .. }) => {
            assert!(iv.is_empty());
            assert_eq!(iv_bits, 96);
            assert_eq!(iv_buffer_len, 12);
            assert!(aad.is_empty());
            assert_eq!(tag_bits, 128);
        }
        other => panic!("unexpected generated-IV GCM params: {other:?}"),
    }

    let generated = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let plan = unsafe {
        prepare_mechanism_output_params(
            &mut mechanism,
            &CkMechanismParams::Gcm(GcmParams {
                iv: generated.clone(),
                iv_bits: 96,
                iv_buffer_len: 12,
                aad: Vec::new().into(),
                tag_bits: 128,
                iv_presence: PointerBytes::from_legacy(&generated, false),
                aad_presence: PointerBytes::from_legacy(&[], false),

                iv_null: false,
                aad_null: false,
            }),
        )
    }
    .expect("valid output prepares");
    unsafe { plan.commit() };

    assert_eq!(iv, generated.as_slice());
    let (gcm_iv_len, gcm_iv_bits) = (gcm.ulIvLen, gcm.ulIvBits);
    assert_eq!(gcm_iv_len, 12);
    assert_eq!(gcm_iv_bits, 96);
}

#[test]
fn extract_params_reads_ck_ulong_bit_position() {
    const CKM_EXTRACT_KEY_FROM_KEY: CK_MECHANISM_TYPE = 0x0000_0365;

    let mut bit_position = 21 as CK_EXTRACT_PARAMS;
    let mechanism = CK_MECHANISM {
        mechanism: CKM_EXTRACT_KEY_FROM_KEY,
        pParameter: &mut bit_position as *mut CK_EXTRACT_PARAMS as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_EXTRACT_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Extract(ExtractParams { bit_position }) => {
            assert_eq!(bit_position, 21);
        }
        other => panic!("unexpected extract params: {other:?}"),
    }
}

#[test]
fn kmac_params_reads_key_length_and_customization_string() {
    const CKM_TEST_KMAC: CK_MECHANISM_TYPE = 0x8000_0001;

    let mut customization = *b"custom";
    let mut params = super::CkKmacParams {
        h_key: 0xCAFE,
        ul_mac_length: 64,
        p_customization_string: customization.as_mut_ptr() as CK_VOID_PTR,
        ul_customization_string_len: customization.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_KMAC,
        pParameter: &mut params as *mut super::CkKmacParams as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<super::CkKmacParams>() as CK_ULONG,
    };

    match unsafe { read_mechanism_with_shape(&mechanism, Some("kmac")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::Kmac(KmacParams {
            key_handle,
            mac_length,
            customization_string,
            customization_string_presence,
        }) => {
            assert_eq!(key_handle.0, 0xCAFE);
            assert_eq!(mac_length, 64);
            assert_eq!(customization_string, SecretBytes::copy_from_slice(b"custom"));
            assert_eq!(customization_string_presence, PointerBytes::present_copy(b"custom"));
        }
        other => panic!("unexpected KMAC params: {other:?}"),
    }
}

#[test]
fn mu_gen_params_reads_key_tr_and_context() {
    const CKM_TEST_MU_GEN: CK_MECHANISM_TYPE = 0x8000_0002;

    let mut tr = *b"precomputed-tr";
    let mut context = *b"context";
    let mut params = super::CkMuGenParams {
        h_key: 0xA11CE,
        p_tr: tr.as_mut_ptr(),
        ul_tr_len: tr.len() as CK_ULONG,
        p_ctx: context.as_mut_ptr(),
        ul_ctx_len: context.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TEST_MU_GEN,
        pParameter: &mut params as *mut super::CkMuGenParams as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<super::CkMuGenParams>() as CK_ULONG,
    };

    match unsafe { read_mechanism_with_shape(&mechanism, Some("mu_gen")) }
        .expect("read mechanism")
        .params
        .expect("mechanism params")
    {
        CkMechanismParams::MuGen(MuGenParams {
            key_handle,
            tr,
            context,
            tr_presence,
            context_presence,
        }) => {
            assert_eq!(key_handle.0, 0xA11CE);
            assert_eq!(tr, SecretBytes::copy_from_slice(b"precomputed-tr"));
            assert_eq!(context, SecretBytes::copy_from_slice(b"context"));
            assert_eq!(tr_presence, PointerBytes::present_copy(b"precomputed-tr"));
            assert_eq!(context_presence, PointerBytes::present_copy(b"context"));
        }
        other => panic!("unexpected mu-gen params: {other:?}"),
    }
}

#[test]
fn sp800_108_kdf_null_data_params_with_nonzero_count_stays_raw() {
    const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
    const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

    let mut params = CK_SP800_108_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC as _,
        ulNumberOfDataParams: 1,
        pDataParams: std::ptr::null_mut(),
        ulAdditionalDerivedKeys: 0,
        pAdditionalDerivedKeys: std::ptr::null_mut(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_KDF_PARAMS>());
        }
        other => panic!("unexpected SP800-108 params: {other:?}"),
    }
}

#[test]
fn sp800_108_kdf_null_additional_keys_with_nonzero_count_stays_raw() {
    const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
    const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

    let mut params = CK_SP800_108_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC as _,
        ulNumberOfDataParams: 0,
        pDataParams: std::ptr::null_mut(),
        ulAdditionalDerivedKeys: 1,
        pAdditionalDerivedKeys: std::ptr::null_mut(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_KDF_PARAMS>());
        }
        other => panic!("unexpected SP800-108 params: {other:?}"),
    }
}

#[test]
fn sp800_108_kdf_null_data_value_with_nonzero_len_stays_raw() {
    const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
    const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;
    const CK_SP800_108_BYTE_ARRAY: CK_PRF_DATA_TYPE = 4;

    let mut data_params = [CK_PRF_DATA_PARAM {
        type_: CK_SP800_108_BYTE_ARRAY,
        pValue: std::ptr::null_mut(),
        ulValueLen: 4,
    }];
    let mut params = CK_SP800_108_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC as _,
        ulNumberOfDataParams: data_params.len() as CK_ULONG,
        pDataParams: data_params.as_mut_ptr(),
        ulAdditionalDerivedKeys: 0,
        pAdditionalDerivedKeys: std::ptr::null_mut(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_KDF_PARAMS>());
        }
        other => panic!("unexpected SP800-108 params: {other:?}"),
    }
}

#[test]
fn sp800_108_kdf_null_template_with_nonzero_attr_count_stays_raw() {
    const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
    const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

    let mut output_handle = 0 as CK_OBJECT_HANDLE;
    let mut additional_keys = [CK_DERIVED_KEY {
        pTemplate: std::ptr::null_mut(),
        ulAttributeCount: 1,
        phKey: &mut output_handle,
    }];
    let mut params = CK_SP800_108_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC as _,
        ulNumberOfDataParams: 0,
        pDataParams: std::ptr::null_mut(),
        ulAdditionalDerivedKeys: additional_keys.len() as CK_ULONG,
        pAdditionalDerivedKeys: additional_keys.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_KDF_PARAMS>());
        }
        other => panic!("unexpected SP800-108 params: {other:?}"),
    }
}

#[test]
fn sp800_108_kdf_null_output_handle_stays_raw() {
    const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
    const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

    let mut additional_keys = [CK_DERIVED_KEY {
        pTemplate: std::ptr::null_mut(),
        ulAttributeCount: 0,
        phKey: std::ptr::null_mut(),
    }];
    let mut params = CK_SP800_108_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC as _,
        ulNumberOfDataParams: 0,
        pDataParams: std::ptr::null_mut(),
        ulAdditionalDerivedKeys: additional_keys.len() as CK_ULONG,
        pAdditionalDerivedKeys: additional_keys.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_KDF_PARAMS>());
        }
        other => panic!("unexpected SP800-108 params: {other:?}"),
    }
}

#[test]
fn sp800_108_kdf_malformed_derived_key_template_stays_raw() {
    // W1-L12-10: a derived-key template whose CONTENT the checked reader
    // rejects (NULL value with nonzero length) must surface as Raw via
    // the completed pre-validator — never a structured KDF with a silently
    // emptied template (`unwrap_or_default`).
    const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x0000_03AC;
    const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

    let mut template =
        [CK_ATTRIBUTE { type_: CKA_LABEL, pValue: std::ptr::null_mut(), ulValueLen: 4 }];
    let mut output_handle = 0 as CK_OBJECT_HANDLE;
    let mut additional_keys = [CK_DERIVED_KEY {
        pTemplate: template.as_mut_ptr(),
        ulAttributeCount: template.len() as CK_ULONG,
        phKey: &mut output_handle,
    }];
    let mut params = CK_SP800_108_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC as _,
        ulNumberOfDataParams: 0,
        pDataParams: std::ptr::null_mut(),
        ulAdditionalDerivedKeys: additional_keys.len() as CK_ULONG,
        pAdditionalDerivedKeys: additional_keys.as_mut_ptr(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_KDF_PARAMS>());
        }
        other => panic!("malformed derived-key template must stay Raw, got: {other:?}"),
    }
}

#[test]
fn sp800_108_feedback_null_iv_with_nonzero_len_stays_raw() {
    const CKM_SP800_108_FEEDBACK_KDF: CK_MECHANISM_TYPE = 0x0000_03AD;
    const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

    let mut params = CK_SP800_108_FEEDBACK_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC as _,
        ulNumberOfDataParams: 0,
        pDataParams: std::ptr::null_mut(),
        ulIVLen: 16,
        pIV: std::ptr::null_mut(),
        ulAdditionalDerivedKeys: 0,
        pAdditionalDerivedKeys: std::ptr::null_mut(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_FEEDBACK_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Raw(raw) => {
            assert_eq!(raw.data.len(), std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>());
        }
        other => panic!("unexpected SP800-108 feedback params: {other:?}"),
    }
}

#[test]
fn sp800_108_feedback_reads_additional_keys_and_writes_handles_back() {
    const CKM_SP800_108_FEEDBACK_KDF: CK_MECHANISM_TYPE = 0x0000_03AD;
    const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x0000_0251;

    let mut label = *b"extra";
    let mut value_len = 32 as CK_ULONG;
    let mut template = [
        CK_ATTRIBUTE {
            type_: CkAttributeType::LABEL.0 as _,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CkAttributeType::VALUE_LEN.0 as _,
            pValue: &mut value_len as *mut _ as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
    ];
    let mut additional_key_handle = 0 as CK_OBJECT_HANDLE;
    let mut additional_keys = [CK_DERIVED_KEY {
        pTemplate: template.as_mut_ptr(),
        ulAttributeCount: template.len() as CK_ULONG,
        phKey: &mut additional_key_handle,
    }];
    let mut iv = [0xA5u8; 16];
    let mut params = CK_SP800_108_FEEDBACK_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC as _,
        ulNumberOfDataParams: 0,
        pDataParams: std::ptr::null_mut(),
        ulIVLen: iv.len() as CK_ULONG,
        pIV: iv.as_mut_ptr(),
        ulAdditionalDerivedKeys: additional_keys.len() as CK_ULONG,
        pAdditionalDerivedKeys: additional_keys.as_mut_ptr(),
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_FEEDBACK_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>() as CK_ULONG,
    };

    match unsafe { read_ck_mechanism(&mechanism) } {
        CkMechanismParams::Sp800108FeedbackKdf(params) => {
            assert_eq!(params.prf_type.0, CKM_SHA256_HMAC as u64);
            assert_eq!(params.iv, vec![0xA5; 16]);
            assert_eq!(params.additional_derived_keys.len(), 1);
            let derived = &params.additional_derived_keys[0];
            assert_eq!(derived.key_handle.0, 0);
            assert_eq!(derived.template.len(), 2);
            assert_eq!(
                derived.template[0].value,
                Some(CkAttributeValue::Bytes(b"extra".to_vec().into()))
            );
            assert_eq!(derived.template[1].value, Some(CkAttributeValue::Ulong(32)));
        }
        other => panic!("unexpected SP800-108 feedback params: {other:?}"),
    }

    let plan = unsafe {
        prepare_mechanism_output_params(
            &mut mechanism,
            &CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                prf_type: CkMechanismType(CKM_SHA256_HMAC as u64),
                data_params_presence: PointerArray::present(Vec::new()),
                iv_presence: PointerBytes::present_copy(&[0xA5; 16]),
                additional_derived_keys_presence: PointerArray::present(vec![Sp800108DerivedKey {
                    template_presence: PointerArray::present(Vec::new()),
                    ph_key_is_null: false,
                    template: Vec::new(),
                    key_handle: CkObjectHandle(0xCAFE),
                }]),
                data_params: Vec::new(),
                iv: vec![0xA5; 16],
                additional_derived_keys: vec![Sp800108DerivedKey {
                    template_presence: PointerArray::present(Vec::new()),
                    ph_key_is_null: false,
                    template: Vec::new(),
                    key_handle: CkObjectHandle(0xCAFE),
                }],
            }),
        )
    }
    .expect("valid output prepares");
    unsafe { plan.commit() };

    assert_eq!(additional_key_handle, 0xCAFE);
}

/// ADR-0010 Scope 2: an unmaterializable AAD length (CK_ULONG::MAX) on a GCM
/// parameter must NOT cause a wild read / process abort.  The shim must fall
/// back to the raw-bytes path (or return a length-error) rather than
/// constructing a slice via `slice::from_raw_parts` with an absurd length.
///
/// The test is intentionally written as a "survives without aborting" check:
/// the observable contract is (a) no crash, and (b) the result is the safe
/// `Raw` fallback rather than a typed `Gcm` variant. (W1-L12-06: the read
/// itself is fallible at the type level, but this input is in-bounds, so
/// the read succeeds and the assertion targets the fallback shape.)
#[test]
fn gcm_aad_unmaterializable_len_rejected_not_wild_read() {
    let mut gcm = CK_GCM_PARAMS {
        pIv: std::ptr::null_mut(),
        ulIvLen: 0,
        ulIvBits: 0,
        // Non-null pointer, but an absurd claimed length — must never be
        // dereferenced as a slice of this size.
        pAAD: std::ptr::dangling_mut::<u8>(),
        ulAADLen: CK_ULONG::MAX,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: &mut gcm as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    // Must not crash.  With the guard in place the shim falls back to the raw
    // path; without the guard it would construct a slice of size usize::MAX
    // (UB) and typically kill the process.
    let result =
        unsafe { read_mechanism_with_shape(&mechanism, Some("gcm")) }.expect("read mechanism");
    match result.params.expect("params") {
        CkMechanismParams::Raw(_) => {} // expected: safe fallback
        other => panic!("expected Raw fallback for unmaterializable AAD len, got {other:?}"),
    }
}

/// ADR-0010 Scope 2: RSA OAEP params with a dangling (non-null) pSourceData
/// and ulSourceDataLen = CK_ULONG::MAX must NOT cause a wild read.  The shim
/// falls back to the raw-bytes path rather than calling
/// `slice::from_raw_parts` with an absurd length.
#[test]
fn rsa_oaep_unmaterializable_source_data_len_falls_back_to_raw() {
    let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        source: 1,
        pSourceData: std::ptr::dangling_mut::<u8>() as CK_VOID_PTR,
        ulSourceDataLen: CK_ULONG::MAX,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::RSA_PKCS_OAEP.0 as CK_MECHANISM_TYPE,
        pParameter: &mut oaep as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
    };
    // Must not crash or do a wild read.  With the guard the shim falls back to
    // the raw path; without it `slice::from_raw_parts` would be called with
    // size usize::MAX (UB).
    let result = unsafe { read_ck_mechanism(&mechanism) };
    match result {
        CkMechanismParams::Raw(_) => {} // expected: safe Raw fallback
        other => {
            panic!("expected Raw fallback for unmaterializable source data len, got {other:?}")
        }
    }
}

/// ADR-0010 Scope 2: an unmaterializable password length (CK_ULONG::MAX) on a
/// PBE parameter must NOT cause a wild read.  The shim falls back to the
/// raw-bytes path rather than calling `slice::from_raw_parts` with an absurd
/// length.
#[test]
fn pbe_password_unmaterializable_len_rejected_not_wild_read() {
    let mut pbe = CK_PBE_PARAMS {
        pInitVector: std::ptr::null_mut(),
        pPassword: std::ptr::dangling_mut::<u8>(),
        ulPasswordLen: CK_ULONG::MAX,
        pSalt: std::ptr::null_mut(),
        ulSaltLen: 0,
        ulIteration: 1,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_PBE_SHA1_DES3_EDE_CBC,
        pParameter: &mut pbe as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_PBE_PARAMS>() as CK_ULONG,
    };
    // Must not crash or do a wild read.  With the guard the shim falls back to
    // the raw path; without it `slice::from_raw_parts` would be called with
    // size usize::MAX (UB).
    let result =
        unsafe { read_mechanism_with_shape(&mechanism, Some("pbe")) }.expect("read mechanism");
    match result.params.expect("params") {
        CkMechanismParams::Raw(_) => {} // expected: safe Raw fallback
        other => panic!("expected Raw fallback for unmaterializable password len, got {other:?}"),
    }
}

/// ADR-0010 Scope 2: an unmaterializable nonce bit-length (CK_ULONG::MAX) on a
/// Salsa20 parameter must NOT cause a wild read.  The shim falls back to the
/// raw-bytes path rather than calling `slice::from_raw_parts` with the absurd
/// derived byte count.
#[test]
fn salsa20_nonce_unmaterializable_bits_rejected_not_wild_read() {
    let mut salsa20 = CK_SALSA20_PARAMS {
        pBlockCounter: std::ptr::dangling_mut::<u8>(),
        pNonce: std::ptr::dangling_mut::<u8>(),
        ulNonceBits: CK_ULONG::MAX,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SALSA20,
        pParameter: &mut salsa20 as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SALSA20_PARAMS>() as CK_ULONG,
    };
    // Must not crash or do a wild read.  With the guard the shim falls back to
    // the raw path; without it `slice::from_raw_parts` would be called with
    // size usize::MAX (UB).
    let result =
        unsafe { read_mechanism_with_shape(&mechanism, Some("salsa20")) }.expect("read mechanism");
    match result.params.expect("params") {
        CkMechanismParams::Raw(_) => {} // expected: safe Raw fallback
        other => panic!("expected Raw fallback for unmaterializable nonce bits, got {other:?}"),
    }
}

#[test]
fn gcm_null_vs_empty_iv_aad_survive_the_read() {
    // F3/D2: (NULL, 0) vs (ptr, 0) for pIv/pAAD must remain distinguishable
    // after the shim read so the daemon can materialize the caller's shape.
    for (p_iv, iv_null, p_aad, aad_null) in [
        (std::ptr::null_mut(), true, std::ptr::null_mut(), true),
        (std::ptr::null_mut(), true, std::ptr::dangling_mut(), false),
        (std::ptr::dangling_mut(), false, std::ptr::null_mut(), true),
        (std::ptr::dangling_mut(), false, std::ptr::dangling_mut(), false),
    ] {
        let mut gcm = CK_GCM_PARAMS {
            pIv: p_iv,
            ulIvLen: 0,
            ulIvBits: 0,
            pAAD: p_aad,
            ulAADLen: 0,
            ulTagBits: 128,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
            pParameter: &mut gcm as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::Gcm(gcm) => {
                assert!(gcm.iv.is_empty());
                assert!(gcm.aad.expose(|b| b.is_empty()));
                assert_eq!(gcm.iv_null, iv_null, "pIv nullness must survive");
                assert_eq!(gcm.aad_null, aad_null, "pAAD nullness must survive");
            }
            other => panic!("unexpected GCM params: {other:?}"),
        }
    }
}

#[test]
fn ccm_null_vs_empty_nonce_aad_survive_the_read() {
    // (NULL, 0) vs (ptr, 0) for pNonce/pAAD must remain distinguishable
    // after the shim read so the daemon can materialize the caller's shape.
    // wolfpkcs11 rejects (ptr, 0) at DecryptInit but accepts (NULL, 0).
    const CKM_TEST_CCM_NULL: CK_MECHANISM_TYPE = 0x8000_1043;
    for (p_nonce, nonce_null, p_aad, aad_null) in [
        (std::ptr::null_mut(), true, std::ptr::null_mut(), true),
        (std::ptr::null_mut(), true, std::ptr::dangling_mut(), false),
        (std::ptr::dangling_mut(), false, std::ptr::null_mut(), true),
        (std::ptr::dangling_mut(), false, std::ptr::dangling_mut(), false),
    ] {
        let mut ccm = CK_CCM_PARAMS {
            ulDataLen: 16,
            pNonce: p_nonce,
            ulNonceLen: 0,
            pAAD: p_aad,
            ulAADLen: 0,
            ulMACLen: 12,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_TEST_CCM_NULL,
            pParameter: &mut ccm as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_CCM_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("ccm")) }
            .expect("read mechanism")
            .params
            .expect("mechanism params")
        {
            CkMechanismParams::Ccm(ccm) => {
                assert!(ccm.nonce.is_empty());
                assert!(ccm.aad.expose(|b| b.is_empty()));
                assert_eq!(ccm.nonce_null, nonce_null, "pNonce nullness must survive");
                assert_eq!(ccm.aad_null, aad_null, "pAAD nullness must survive");
            }
            other => panic!("unexpected CCM params: {other:?}"),
        }
    }
}

#[test]
fn misaligned_rsa_aes_key_wrap_reads_byte_identical_values() {
    // W1-C6-03 / W1-L1-01 residual: the manual field reads for
    // rsa_aes_key_wrap must not dereference 8-byte fields at
    // potentially-misaligned pack(1) offsets. Place the outer struct at a
    // misaligned address (built with write_unaligned, so the test setup
    // itself is Miri-clean); the nested OAEP struct stays aligned per the
    // caller contract. Run under Miri: misaligned derefs are UB errors.
    let mut source_data = [0xA0u8, 0xA1, 0xA2];
    let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        source: 1,
        pSourceData: source_data.as_mut_ptr() as CK_VOID_PTR,
        ulSourceDataLen: source_data.len() as CK_ULONG,
    };
    let ulong_size = std::mem::size_of::<CK_ULONG>();
    let ptr_size = std::mem::size_of::<*mut std::ffi::c_void>();
    let wrap_size = ulong_size + ptr_size;
    let mut buf = [0u8; 64];
    let buf_addr = buf.as_mut_ptr() as usize;
    // Deterministic misalignment: some offset in 0..8 always misses 8-byte
    // alignment, regardless of the stack address.
    let offset = (0..8usize)
        .find(|o| !(buf_addr + o).is_multiple_of(ulong_size))
        .expect("a misaligned offset always exists");
    let base = buf.as_mut_ptr().wrapping_add(offset);
    assert_ne!(base as usize % ulong_size, 0, "test setup must be misaligned");
    unsafe {
        std::ptr::write_unaligned(base as *mut CK_ULONG, 256);
        std::ptr::write_unaligned(
            base.add(ulong_size) as *mut *mut CK_RSA_PKCS_OAEP_PARAMS,
            &mut oaep,
        );
    }
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType(0x0000_1054).0 as CK_MECHANISM_TYPE,
        pParameter: base as CK_VOID_PTR,
        ulParameterLen: wrap_size as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("rsa_aes_key_wrap")) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams {
            aes_key_bits,
            oaep_params,
        })) => {
            assert_eq!(aes_key_bits, 256);
            assert_eq!(oaep_params.hash_alg, CkMechanismType::SHA256);
            assert_eq!(oaep_params.mgf, CkMgf(1));
            assert_eq!(oaep_params.source, CkOaepSource(1));
            assert_eq!(oaep_params.source_data, SecretBytes::copy_from_slice(&[0xA0, 0xA1, 0xA2]));
        }
        other => panic!("unexpected RSA-AES key wrap params: {other:?}"),
    }
}

#[test]
fn misaligned_sign_additional_context_reads_byte_identical_values() {
    // W1-C6-03 / W1-L1-01 residual: same misalignment class for the
    // sign_additional_context manual reads, covering both the base
    // CK_SIGN_ADDITIONAL_CONTEXT and the hash-extended
    // CK_HASH_SIGN_ADDITIONAL_CONTEXT variant (trailing hash word).
    for with_hash in [false, true] {
        let mut sign_context = [0xB1u8, 0xB2];
        let ulong_size = std::mem::size_of::<CK_ULONG>();
        let ptr_size = std::mem::size_of::<*mut u8>();
        let base_size = ulong_size + ptr_size + ulong_size;
        let hash_size = base_size + ulong_size;
        let total = if with_hash { hash_size } else { base_size };
        let mut buf = [0u8; 64];
        let buf_addr = buf.as_mut_ptr() as usize;
        let offset = (0..8usize)
            .find(|o| !(buf_addr + o).is_multiple_of(ulong_size))
            .expect("a misaligned offset always exists");
        let base = buf.as_mut_ptr().wrapping_add(offset);
        assert_ne!(base as usize % ulong_size, 0, "test setup must be misaligned");
        unsafe {
            std::ptr::write_unaligned(base as *mut CK_ULONG, 7);
            std::ptr::write_unaligned(
                base.add(ulong_size) as *mut *mut u8,
                sign_context.as_mut_ptr(),
            );
            std::ptr::write_unaligned(
                base.add(ulong_size + ptr_size) as *mut CK_ULONG,
                sign_context.len() as CK_ULONG,
            );
            if with_hash {
                std::ptr::write_unaligned(base.add(base_size) as *mut CK_ULONG, 0xA5A5);
            }
        }
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType(0x0000_0502).0 as CK_MECHANISM_TYPE,
            pParameter: base as CK_VOID_PTR,
            ulParameterLen: total as CK_ULONG,
        };
        match unsafe { read_mechanism_with_shape(&mechanism, Some("sign_additional_context")) }
            .expect("read mechanism")
            .params
        {
            Some(CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
                hedge_variant,
                context,
                hash,
                context_presence,
            })) => {
                assert_eq!(hedge_variant, 7, "with_hash={with_hash}");
                assert_eq!(
                    context,
                    SecretBytes::copy_from_slice(&[0xB1, 0xB2]),
                    "with_hash={with_hash}"
                );
                assert_eq!(
                    context_presence,
                    PointerBytes::present_copy(&[0xB1, 0xB2]),
                    "with_hash={with_hash}"
                );
                assert_eq!(hash.0, if with_hash { 0xA5A5 } else { 0 }, "with_hash={with_hash}");
            }
            other => panic!("unexpected sign additional context params: {other:?}"),
        }
    }
}

#[test]
fn oaep_null_vs_empty_source_survives_the_read() {
    // F3/D2: (NULL, 0) vs (ptr, 0) for pSourceData must remain
    // distinguishable after the shim read.
    for (p_source, source_null) in [(std::ptr::null_mut(), true), (std::ptr::dangling_mut(), false)]
    {
        let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            mgf: 1,
            source: 1,
            pSourceData: p_source,
            ulSourceDataLen: 0,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CkMechanismType::RSA_PKCS_OAEP.0 as CK_MECHANISM_TYPE,
            pParameter: &mut oaep as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        };
        match unsafe { read_ck_mechanism(&mechanism) } {
            CkMechanismParams::RsaPkcsOaep(oaep) => {
                assert!(oaep.source_data.expose(|b| b.is_empty()));
                assert_eq!(oaep.source_null, source_null, "pSourceData nullness must survive");
            }
            other => panic!("unexpected OAEP params: {other:?}"),
        }
    }
}

// ─── T03: misalignment tolerance + KIP nesting budget ───────────────────────

/// Copy a `Copy` value into heap backing at a *guaranteed misaligned*
/// address for its type. Returns the backing (the caller must keep it
/// alive past the read) and the pointer. Every misaligned test below
/// offsets each nested record independently through this helper; byte
/// payloads need no misalignment (`u8` aligns anywhere) but their
/// backing must likewise outlive the read.
fn misaligned_copy<T: Copy>(value: T) -> (Vec<u8>, *const T) {
    let size = std::mem::size_of::<T>();
    let align = std::mem::align_of::<T>().max(2);
    let mut backing = vec![0u8; size + align + 1];
    let base = backing.as_ptr() as usize;
    let offset =
        (1..=align).find(|o| !(base + o).is_multiple_of(align)).expect("misaligned offset exists");
    let ptr = unsafe { backing.as_mut_ptr().add(offset) as *mut T };
    unsafe { ptr.write_unaligned(value) };
    assert_ne!((ptr as usize) % align, 0, "fixture must actually be misaligned");
    (backing, ptr as *const T)
}

fn live_bytes(data: &[u8]) -> (Vec<u8>, *mut u8) {
    let mut backing = data.to_vec();
    let ptr = backing.as_mut_ptr();
    (backing, ptr)
}

#[test]
fn misaligned_outer_mechanism_and_oaep_params_read() {
    // Production entry (the only misaligned-safe entry: it reads the outer
    // struct unaligned exactly once). Guarded + pinned to legacy: the entry
    // gathers the global capability snapshot.
    let _guard = crate::tests::shim_state_test_guard();
    crate::interface_probe::set_mechanism_parameter_transport_version_for_tests(0);
    ensure_registry();
    let (_src_backing, src) = live_bytes(&[0xA0, 0xA1, 0xA2]);
    let oaep = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        source: 1,
        pSourceData: src as CK_VOID_PTR,
        ulSourceDataLen: 3,
    };
    let (_oaep_backing, oaep_ptr) = misaligned_copy(oaep);
    let mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_OAEP,
        pParameter: oaep_ptr as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
    };
    let (_mech_backing, mech_ptr) = misaligned_copy(mechanism);
    match unsafe { read_mechanism_for_transport(mech_ptr, Operation::General) } {
        Ok(CkMechanism { params: Some(CkMechanismParams::RsaPkcsOaep(parsed)), .. }) => {
            assert_eq!(parsed.source_data, SecretBytes::copy_from_slice(&[0xA0, 0xA1, 0xA2]));
        }
        other => panic!("misaligned outer + OAEP must parse, got {other:?}"),
    }
}

#[test]
fn misaligned_scalar_mechanism_value_reads() {
    let (backing, val_ptr) = misaligned_copy(64 as CK_MAC_GENERAL_PARAMS);
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SHA_1_HMAC_GENERAL,
        pParameter: val_ptr as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_MAC_GENERAL_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("mac_general")) } {
        Ok(CkMechanism {
            params: Some(CkMechanismParams::MacGeneral(MacGeneralParams { mac_length })),
            ..
        }) => {
            assert_eq!(mac_length, 64);
        }
        other => panic!("misaligned scalar must parse, got {other:?}"),
    }
    let _ = backing;
}

#[test]
fn misaligned_nested_oaep_reads() {
    let (_src_backing, src) = live_bytes(&[0xB0, 0xB1]);
    let oaep = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        source: 1,
        pSourceData: src as CK_VOID_PTR,
        ulSourceDataLen: 2,
    };
    let (_oaep_backing, oaep_ptr) = misaligned_copy(oaep);
    // Real struct (not usize cells) so the OAEP pointer keeps its
    // provenance under Miri; int-to-pointer casts carry no provenance.
    let record = CK_RSA_AES_KEY_WRAP_PARAMS {
        ulAESKeyBits: 256,
        pOAEPParams: oaep_ptr as *mut CK_RSA_PKCS_OAEP_PARAMS,
    };
    let (_rec_backing, rec_ptr) = misaligned_copy(record);
    let mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_AES_KEY_WRAP,
        pParameter: rec_ptr as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("rsa_aes_key_wrap")) } {
        Ok(CkMechanism {
            params:
                Some(CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams {
                    aes_key_bits,
                    oaep_params,
                })),
            ..
        }) => {
            assert_eq!(aes_key_bits, 256);
            assert_eq!(oaep_params.source_data, SecretBytes::copy_from_slice(&[0xB0, 0xB1]));
        }
        other => panic!("misaligned nested OAEP must parse, got {other:?}"),
    }
}

#[test]
fn misaligned_tls_prf_lengths_read() {
    let (_seed_backing, seed) = live_bytes(&[0xC0, 0xC1]);
    let (_label_backing, label) = live_bytes(&[0xD0]);
    let (_len_backing, len_ptr) = misaligned_copy(48 as CK_ULONG);
    let prf = CK_TLS_PRF_PARAMS {
        pSeed: seed as *mut CK_BYTE,
        ulSeedLen: 2,
        pLabel: label as *mut CK_BYTE,
        ulLabelLen: 1,
        pOutput: std::ptr::null_mut(),
        pulOutputLen: len_ptr as *mut CK_ULONG,
    };
    let (_prf_backing, prf_ptr) = misaligned_copy(prf);
    let mechanism = CK_MECHANISM {
        mechanism: CKM_TLS_PRF,
        pParameter: prf_ptr as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS_PRF_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("tls_prf")) } {
        Ok(CkMechanism {
            params: Some(CkMechanismParams::TlsPrf(TlsPrfParams { seed, label, output_len, .. })),
            ..
        }) => {
            assert_eq!(seed, SecretBytes::copy_from_slice(&[0xC0, 0xC1]));
            assert_eq!(label, SecretBytes::copy_from_slice(&[0xD0]));
            assert_eq!(output_len, 48);
        }
        other => panic!("misaligned TLS PRF must parse, got {other:?}"),
    }
}

#[test]
fn misaligned_sp800_prf_array_reads() {
    let (_v0_backing, v0) = live_bytes(&[0xE0]);
    let (_v1_backing, v1) = live_bytes(&[0xE1, 0xE2]);
    let elems = [
        CK_PRF_DATA_PARAM { type_: 1 as CK_PRF_DATA_TYPE, pValue: v0 as *mut _, ulValueLen: 1 },
        CK_PRF_DATA_PARAM { type_: 2 as CK_PRF_DATA_TYPE, pValue: v1 as *mut _, ulValueLen: 2 },
    ];
    let (_arr_backing, arr_ptr) = misaligned_copy(elems);
    let kdf = CK_SP800_108_KDF_PARAMS {
        prfType: 1 as CK_SP800_108_PRF_TYPE,
        ulNumberOfDataParams: 2,
        pDataParams: arr_ptr as *mut CK_PRF_DATA_PARAM,
        ulAdditionalDerivedKeys: 0,
        pAdditionalDerivedKeys: std::ptr::null_mut(),
    };
    let (_kdf_backing, kdf_ptr) = misaligned_copy(kdf);
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: kdf_ptr as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("sp800_108_kdf")) } {
        Ok(CkMechanism {
            params: Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams { data_params, .. })),
            ..
        }) => {
            assert_eq!(data_params.len(), 2);
            assert_eq!(data_params[0].value, SecretBytes::copy_from_slice(&[0xE0]));
            assert_eq!(data_params[1].value, SecretBytes::copy_from_slice(&[0xE1, 0xE2]));
        }
        other => panic!("misaligned SP800 array must parse, got {other:?}"),
    }
}

#[test]
fn misaligned_sp800_phkey_reads() {
    let (_h_backing, h_ptr) = misaligned_copy(0xDEAD_BEEFu64 as CK_OBJECT_HANDLE);
    let keys = [CK_DERIVED_KEY {
        pTemplate: std::ptr::null_mut(),
        ulAttributeCount: 0,
        phKey: h_ptr as *mut CK_OBJECT_HANDLE,
    }];
    let (_arr_backing, arr_ptr) = misaligned_copy(keys);
    let kdf = CK_SP800_108_KDF_PARAMS {
        prfType: 1 as CK_SP800_108_PRF_TYPE,
        ulNumberOfDataParams: 0,
        pDataParams: std::ptr::null_mut(),
        ulAdditionalDerivedKeys: 1,
        pAdditionalDerivedKeys: arr_ptr as *mut CK_DERIVED_KEY,
    };
    let (_kdf_backing, kdf_ptr) = misaligned_copy(kdf);
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: kdf_ptr as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("sp800_108_kdf")) } {
        Ok(CkMechanism {
            params:
                Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                    additional_derived_keys, ..
                })),
            ..
        }) => {
            assert_eq!(additional_derived_keys.len(), 1);
            assert_eq!(additional_derived_keys[0].key_handle.0, 0xDEAD_BEEF);
        }
        other => panic!("misaligned SP800 phKey must parse, got {other:?}"),
    }
}

fn kip_nested_rsa_mechanism() -> CK_MECHANISM {
    CK_MECHANISM { mechanism: CKM_RSA_PKCS, pParameter: std::ptr::null_mut(), ulParameterLen: 0 }
}

#[test]
fn misaligned_kip_nested_records_read() {
    // Guarded + pinned to legacy: the nested KIP read gathers the
    // global registry/capability snapshots.
    let _guard = crate::tests::shim_state_test_guard();
    crate::interface_probe::set_mechanism_parameter_transport_version_for_tests(0);
    ensure_registry();
    let (_nested_backing, nested_ptr) = misaligned_copy(kip_nested_rsa_mechanism());
    let (_seed_backing, seed) = live_bytes(&[0xF0, 0xF1]);
    let kip = CK_KIP_PARAMS {
        pMechanism: nested_ptr as *mut CK_MECHANISM,
        hKey: 0x42,
        pSeed: seed as *mut CK_BYTE,
        ulSeedLen: 2,
    };
    let (_kip_backing, kip_ptr) = misaligned_copy(kip);
    let mechanism = CK_MECHANISM {
        mechanism: CKM_KIP_DERIVE,
        pParameter: kip_ptr as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KIP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("kip")) } {
        Ok(CkMechanism {
            params: Some(CkMechanismParams::Kip(KipParams { mechanism, key_handle, seed, .. })),
            ..
        }) => {
            assert_eq!(mechanism.mechanism_type.0, CKM_RSA_PKCS as u64);
            assert_eq!(key_handle.0, 0x42);
            assert_eq!(seed, SecretBytes::copy_from_slice(&[0xF0, 0xF1]));
        }
        other => panic!("misaligned KIP nesting must parse, got {other:?}"),
    }
}

#[test]
fn kip_valid_nested_mechanism_roundtrips() {
    // Guarded + pinned to legacy: the nested KIP read gathers the
    // global registry/capability snapshots.
    let _guard = crate::tests::shim_state_test_guard();
    crate::interface_probe::set_mechanism_parameter_transport_version_for_tests(0);
    ensure_registry();
    let mut nested = kip_nested_rsa_mechanism();
    let mut seed = [0xF2u8, 0xF3, 0xF4];
    let kip = CK_KIP_PARAMS {
        pMechanism: &mut nested,
        hKey: 0x43,
        pSeed: seed.as_mut_ptr() as *mut CK_BYTE,
        ulSeedLen: seed.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_KIP_DERIVE,
        pParameter: &kip as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KIP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("kip")) } {
        Ok(CkMechanism {
            params: Some(CkMechanismParams::Kip(KipParams { mechanism, key_handle, seed, .. })),
            ..
        }) => {
            assert_eq!(mechanism.mechanism_type.0, CKM_RSA_PKCS as u64);
            assert_eq!(key_handle.0, 0x43);
            assert_eq!(seed, SecretBytes::copy_from_slice(&[0xF2, 0xF3, 0xF4]));
        }
        other => panic!("valid KIP nesting must roundtrip, got {other:?}"),
    }
}

#[test]
fn kip_self_cycle_is_rejected() {
    // Guarded + pinned to legacy: the nested KIP read gathers the
    // global registry/capability snapshots.
    let _guard = crate::tests::shim_state_test_guard();
    crate::interface_probe::set_mechanism_parameter_transport_version_for_tests(0);
    ensure_registry();
    let mut nested = kip_nested_rsa_mechanism();
    let nested_addr = &mut nested as *mut CK_MECHANISM as usize;
    let mut seed = [0xF5u8];
    let kip = CK_KIP_PARAMS {
        pMechanism: &mut nested,
        hKey: 0,
        pSeed: seed.as_mut_ptr() as *mut CK_BYTE,
        ulSeedLen: seed.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_KIP_DERIVE,
        pParameter: &kip as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KIP_PARAMS>() as CK_ULONG,
    };
    // Positive control: the same fixture parses with a fresh budget.
    assert!(unsafe { read_mechanism_with_shape(&mechanism, Some("kip")) }.is_ok());
    // A repeated active address is a reference cycle: reject before recursion.
    let mut budget = NestingBudget::new();
    budget.enter(nested_addr).expect("first entry fits");
    assert!(
        matches!(
            unsafe { read_mechanism_with_shape_budgeted(&mechanism, Some("kip"), &mut budget) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "self-cycle must be rejected before recursion"
    );
}

#[test]
fn kip_depth_limit_is_enforced() {
    // Guarded + pinned to legacy: the nested KIP read gathers the
    // global registry/capability snapshots.
    let _guard = crate::tests::shim_state_test_guard();
    crate::interface_probe::set_mechanism_parameter_transport_version_for_tests(0);
    ensure_registry();
    assert_eq!(MAX_NESTED_MECHANISMS, 16, "shim/backend depth bound must match");
    let mut nested = kip_nested_rsa_mechanism();
    let mut seed = [0xF6u8];
    let kip = CK_KIP_PARAMS {
        pMechanism: &mut nested,
        hKey: 0,
        pSeed: seed.as_mut_ptr() as *mut CK_BYTE,
        ulSeedLen: seed.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_KIP_DERIVE,
        pParameter: &kip as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KIP_PARAMS>() as CK_ULONG,
    };
    // Fifteen active ancestors: the 16th nested node is still allowed.
    let mut budget = NestingBudget::new();
    for i in 0..15usize {
        budget.enter(0x1000 + i).expect("budget entry fits");
    }
    assert!(
        unsafe { read_mechanism_with_shape_budgeted(&mechanism, Some("kip"), &mut budget) }.is_ok(),
        "16 nested nodes must be allowed"
    );
    // Sixteen active ancestors: the 17th nested node is rejected.
    let mut budget = NestingBudget::new();
    for i in 0..16usize {
        budget.enter(0x1000 + i).expect("budget entry fits");
    }
    assert!(
        matches!(
            unsafe { read_mechanism_with_shape_budgeted(&mechanism, Some("kip"), &mut budget) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "17th nested node must be rejected before recursion"
    );
}

#[test]
fn nesting_budget_pins_sixteen_node_limit() {
    assert_eq!(MAX_NESTED_MECHANISMS, 16);
    let mut budget = NestingBudget::new();
    for i in 0..16usize {
        budget.enter(0x1000 + i).expect("first sixteen entries fit");
    }
    assert!(matches!(budget.enter(0x2000), Err(CkRv::MECHANISM_PARAM_INVALID)));
    let mut budget = NestingBudget::new();
    budget.enter(0x3000).expect("first entry fits");
    assert!(matches!(budget.enter(0x3000), Err(CkRv::MECHANISM_PARAM_INVALID)));
}

// ---------------------------------------------------------------------------
// R11 (S2 §5): shim Flat/Null emission probes (S2 §12 Flat subset)
// ---------------------------------------------------------------------------
//
// Each probe below is a named test. TDD RED: all six failed pre-change
// (legacy Raw/None where v1 Flat/Null is expected); GREEN after.

#[test]
fn r11_flat_sha256_with_16_bytes() {
    let registry = default_registry();
    let mut data = [0x5Au8; 16];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        pParameter: data.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: data.len() as CK_ULONG,
    };
    let params = unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params;
    match &params {
        Some(CkMechanismParams::Flat(p)) => {
            r11_assert_flat(p, &data, ABI_EXEMPT_FINGERPRINT);
        }
        other => panic!("SHA-256+16B must emit v1 Flat, got {other:?}"),
    }
}

#[test]
fn r11_flat_3_byte_pss() {
    let registry = default_registry();
    let mut data = [0x01u8, 0x02, 0x03];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::RSA_PKCS_PSS.0 as CK_MECHANISM_TYPE,
        pParameter: data.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: data.len() as CK_ULONG,
    };
    let params = unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params;
    match &params {
        Some(CkMechanismParams::Flat(p)) => {
            r11_assert_flat(
                p,
                &data,
                r11_expected_fingerprint("rsa_pss", CkMechanismType::RSA_PKCS_PSS.0, 3),
            );
        }
        other => panic!("3-byte PSS must emit v1 Flat, got {other:?}"),
    }
}

#[test]
fn r11_flat_1_byte_eddsa() {
    let registry = default_registry();
    let mut data = [0x07u8];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::EDDSA.0 as CK_MECHANISM_TYPE,
        pParameter: data.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: data.len() as CK_ULONG,
    };
    let params = unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params;
    match &params {
        Some(CkMechanismParams::Flat(p)) => {
            r11_assert_flat(
                p,
                &data,
                r11_expected_fingerprint("eddsa", CkMechanismType::EDDSA.0, 1),
            );
        }
        other => panic!("1-byte EdDSA must emit v1 Flat, got {other:?}"),
    }
}

#[test]
fn r11_outer_null_nonzero_is_null_not_none() {
    let registry = default_registry();
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 5,
    };
    let params = unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params;
    r11_assert_null(&params, 5);
}

#[test]
fn r11_outer_nonnull_empty_is_empty_flat_not_none() {
    let registry = default_registry();
    let mut data = [0x5Au8; 1];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_CBC.0 as CK_MECHANISM_TYPE,
        pParameter: data.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: 0,
    };
    let params = unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params;
    match &params {
        Some(CkMechanismParams::Flat(p)) => {
            r11_assert_flat(p, &[], ABI_EXEMPT_FINGERPRINT);
        }
        other => panic!("(non-NULL,0) must emit empty v1 Flat, got {other:?}"),
    }
}

#[test]
fn r11_null_huge_forwards_without_deref() {
    let registry = default_registry();
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 1024 * 1024 * 1024,
    };
    let params = unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params;
    r11_assert_null(&params, 1024 * 1024 * 1024);
}

#[test]
fn r11_outer_null_empty_distinctness() {
    // S2 §12 probe: the 4-cell outer matrix under v1. NULL and empty are
    // never conflated, in either direction.
    const UNKNOWN: u64 = 0x0000_9999;
    let registry = default_registry();
    let mut data = [0x5Au8; 16];
    let live = data.as_mut_ptr() as CK_VOID_PTR;

    // (NULL,0) -> None, descriptor-independent (bound, parameterless-only,
    // and unknown mechanisms alike).
    for mech in [CkMechanismType::RSA_PKCS_PSS.0, CkMechanismType::SHA256.0, UNKNOWN] {
        let mechanism = r11_mechanism(mech, std::ptr::null_mut(), 0);
        let params = unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }
            .expect("read mechanism")
            .params;
        assert_eq!(params, None, "(NULL,0) must stay None for 0x{mech:08X}");
    }
    // (NULL,5) -> Null (unknown mechanisms forward Null with no descriptor).
    for mech in [CkMechanismType::RSA_PKCS_PSS.0, CkMechanismType::SHA256.0, UNKNOWN] {
        let mechanism = r11_mechanism(mech, std::ptr::null_mut(), 5);
        let params = unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }
            .expect("read mechanism")
            .params;
        r11_assert_null(&params, 5);
    }
    // (non-NULL,0) -> empty Flat (parameterless-only and struct-bound);
    // unknown mechanisms cannot form one -> MPI.
    for (mech, shape) in
        [(CkMechanismType::SHA256.0, None), (CkMechanismType::RSA_PKCS_PSS.0, Some("rsa_pss"))]
    {
        let mechanism = r11_mechanism(mech, live, 0);
        let params = unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }
            .expect("read mechanism")
            .params;
        match &params {
            Some(CkMechanismParams::Flat(p)) => {
                let fingerprint = shape
                    .map(|s| r11_expected_fingerprint(s, mech, 0))
                    .unwrap_or(ABI_EXEMPT_FINGERPRINT);
                r11_assert_flat(p, &[], fingerprint);
            }
            other => panic!("(non-NULL,0) must emit empty Flat for 0x{mech:08X}, got {other:?}"),
        }
    }
    let mechanism = r11_mechanism(UNKNOWN, live, 0);
    assert!(
        matches!(
            unsafe { read_r11_v1(&mechanism, &registry, Operation::General) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "(non-NULL,0) with an unknown mechanism must be MPI (UnknownShape)"
    );
    // (non-NULL,16) -> Flat for representable shapes, MPI for unknown.
    let mechanism = r11_mechanism(CkMechanismType::SHA256.0, live, 16);
    let params = unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params;
    match &params {
        Some(CkMechanismParams::Flat(p)) => r11_assert_flat(p, &data, ABI_EXEMPT_FINGERPRINT),
        other => panic!("SHA-256+16B must emit v1 Flat, got {other:?}"),
    }
    let mechanism = r11_mechanism(UNKNOWN, live, 16);
    assert!(
        matches!(
            unsafe { read_r11_v1(&mechanism, &registry, Operation::General) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "unknown mechanism with params must be MPI (UnknownShape)"
    );
}

#[test]
fn r11_over_limit_no_deref() {
    // S2 §12 probe: over-cap Flat extents are denied BEFORE any dereference
    // (the pointer below is dangling — a dereference would fault / be Miri
    // UB). NULL lengths ignore the cap entirely (D3: no bytes materialize).
    let registry = default_registry();
    let dangling = std::ptr::dangling_mut::<u8>().cast::<std::ffi::c_void>();
    let mechanism = r11_mechanism(CkMechanismType::SHA256.0, dangling, 100 * 1024);
    assert!(
        matches!(
            unsafe { read_r11_v1(&mechanism, &registry, Operation::General) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "100 KiB Flat extent must be MPI without dereference (OverCap)"
    );
    let mechanism = r11_mechanism(CkMechanismType::SHA256.0, std::ptr::null_mut(), 100 * 1024);
    let params = unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params;
    r11_assert_null(&params, 100 * 1024);
}

#[test]
fn r11_legacy_capability_preservation() {
    // S2 §12 probe: under legacy capability the new call preserves the old
    // behavior EXACTLY — including legacy `Raw` emission for old daemons
    // and the NULL/empty collapse.
    let registry = default_registry();

    // Short structs ride legacy Raw (verbatim bytes) for old daemons.
    let mut data = [0x01u8, 0x02, 0x03];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::RSA_PKCS_PSS.0 as CK_MECHANISM_TYPE,
        pParameter: data.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: data.len() as CK_ULONG,
    };
    match unsafe { read_r11_legacy(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::Raw(p)) => {
            p.data.expose(|bytes| assert_eq!(bytes, &data));
        }
        other => panic!("legacy short PSS must emit Raw, got {other:?}"),
    }

    // NULL/empty collapse preserved (v1 distinguishes; legacy does not).
    let mechanism = r11_mechanism(CkMechanismType::SHA256.0, std::ptr::null_mut(), 5);
    let params = unsafe { read_r11_legacy(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params;
    assert_eq!(params, None, "legacy (NULL,5) must collapse to None");
    let mechanism = r11_mechanism(CkMechanismType::AES_CBC.0, data.as_mut_ptr().cast(), 0);
    let params = unsafe { read_r11_legacy(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params;
    assert_eq!(params, None, "legacy (non-NULL,0) must collapse to None");

    // Overlong outer lengths trip the entry gate without dereference.
    let dangling = std::ptr::dangling_mut::<u8>().cast::<std::ffi::c_void>();
    let mechanism = r11_mechanism(CkMechanismType::AES_CBC.0, dangling, 100 * 1024);
    assert!(
        matches!(
            unsafe { read_r11_legacy(&mechanism, &registry, Operation::General) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "legacy overlong extent must be MPI without dereference"
    );

    // Canonical typed reads are unchanged under legacy.
    let mut iv = [0x11u8; 12];
    let mut aad = [0xA1u8, 0xA2];
    let gcm = r11_gcm_params(iv.as_mut_ptr(), 12, aad.as_mut_ptr(), 2);
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
        pParameter: &gcm as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_r11_legacy(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::Gcm(_)) => {}
        other => panic!("legacy canonical GCM must stay typed, got {other:?}"),
    }

    // Wrap-sized GCM under General ignores the wrap layouts in legacy too
    // (registry shape "gcm", noncanonical length -> Raw).
    // `ivGenerator: 0` (not `CKG_GENERATE`): reinterpreted as CK_GCM_PARAMS,
    // that field becomes pAAD=NULL while ulAADLen becomes the (always
    // nonzero) `pAAD` address bits, so the missing-embedded-pointer guard
    // yields Raw deterministically on every platform. Any nonzero generator
    // makes the outcome address-magnitude-dependent instead (native stack
    // addresses trip the length cap; Miri's small addresses pass it and the
    // copy faults) — see the Miri UB this leg caught pre-commit.
    let mut wrap = CK_GCM_WRAP_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 32,
        ivGenerator: 0,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
        pParameter: &mut wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_r11_legacy(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::Raw(_)) => {}
        other => panic!("legacy General + wrap-sized GCM must emit Raw, got {other:?}"),
    }
}

#[test]
fn r11_gcm_compat_union_routing() {
    // `gcm_compat` is a byte-buffer/struct union selected by length (S2 §4):
    // short buffers stay typed Iv bytes, struct-sized buffers parse as the
    // GCM struct, longer-than-struct buffers are noncanonical for a pointer
    // struct -> MPI (residual limit).
    let registry = default_registry();
    let mut short = [0x5Au8; 16];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GMAC.0 as CK_MECHANISM_TYPE,
        pParameter: short.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: short.len() as CK_ULONG,
    };
    match unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::Iv(IvParams { iv })) => assert_eq!(iv, short),
        other => panic!("short GMAC must stay typed Iv bytes, got {other:?}"),
    }

    let mut iv = [0x11u8; 12];
    let mut aad = [0xA1u8, 0xA2];
    let gcm = r11_gcm_params(iv.as_mut_ptr(), 12, aad.as_mut_ptr(), 2);
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GMAC.0 as CK_MECHANISM_TYPE,
        pParameter: &gcm as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::Gcm(_)) => {}
        other => panic!("struct-sized GMAC must parse as the GCM struct, got {other:?}"),
    }

    let mut long = [0x5Au8; 64];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GMAC.0 as CK_MECHANISM_TYPE,
        pParameter: long.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: long.len() as CK_ULONG,
    };
    assert!(
        matches!(
            unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::General) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "oversized GMAC must be MPI (struct noncanonical, prefix too long)"
    );
}

#[test]
fn r11_wrap_key_operation_context() {
    // Operation context is load-bearing (S2 §4, R7
    // `general_operation_ignores_wrap_layouts`): the SAME (mechanism,
    // length) selects the wrap layout under WrapKey and rejects under
    // General; non-wrap sizes under WrapKey fall back to the registry.
    let registry = default_registry();
    let mut iv = [0x11u8; 12];
    let mut aad = [0xA1u8, 0xA2];
    let mut wrap = CK_GCM_WRAP_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 32,
        ivGenerator: CKG_GENERATE as _,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
        pParameter: &mut wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_WRAP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::WrapKey) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::GcmWrap(_)) => {}
        other => panic!("WrapKey + wrap-sized GCM must select GcmWrap, got {other:?}"),
    }
    assert!(
        matches!(
            unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::General) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "General + wrap-sized GCM must be MPI (wrap layouts ignored)"
    );

    // CCM half: General ignores the wrap layout too.
    let mut nonce = [0x22u8; 12];
    let mut ccm_aad = [0xB1u8, 0xB2, 0xB3];
    let mut ccm_wrap = CK_CCM_WRAP_PARAMS {
        ulDataLen: 16,
        pNonce: nonce.as_mut_ptr(),
        ulNonceLen: nonce.len() as CK_ULONG,
        ulNonceFixedBits: 0,
        nonceGenerator: CKG_GENERATE as _,
        pAAD: ccm_aad.as_mut_ptr(),
        ulAADLen: ccm_aad.len() as CK_ULONG,
        ulMACLen: 16,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_CCM.0 as CK_MECHANISM_TYPE,
        pParameter: &mut ccm_wrap as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_CCM_WRAP_PARAMS>() as CK_ULONG,
    };
    assert!(
        matches!(
            unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::General) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "General + wrap-sized CCM must be MPI (wrap layouts ignored)"
    );

    // WrapKey with a non-wrap size falls back to the registry binding.
    let gcm = r11_gcm_params(iv.as_mut_ptr(), 12, aad.as_mut_ptr(), 2);
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
        pParameter: &gcm as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::WrapKey) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::Gcm(_)) => {}
        other => panic!("WrapKey + struct-sized GCM must fall back to Gcm, got {other:?}"),
    }
}

#[test]
fn r11_null_pointer_never_dereferenced() {
    // Unreadable-pointer rule (S2 §5): only NULL (never dereferenced) is
    // unconditionally safe. Every length — including CK_ULONG::MAX, whose
    // narrowing is the daemon's job — forwards as Null with no descriptor
    // lookup and no memory access. The Miri run proves the no-deref half
    // (a NULL dereference is instant UB).
    const UNKNOWN: u64 = 0x0000_9999;
    let registry = default_registry();
    // A companion-set shape binding (R7 `kea_derive` carries one): outer
    // NULL still forwards — no struct is read, so no companion exists.
    let kea_registry = r11_registry(&[("kea_derive", 0x0000_9998)], &[], &[]);
    for length in [1u64, 5, 1024 * 1024 * 1024, CK_ULONG::MAX as u64] {
        let length = length as CK_ULONG;
        for (mech, registry) in [
            (CkMechanismType::SHA256.0, &registry),
            (CkMechanismType::RSA_PKCS_PSS.0, &registry),
            (UNKNOWN, &registry),
            (0x0000_9998, &kea_registry),
        ] {
            let mechanism = r11_mechanism(mech, std::ptr::null_mut(), length);
            let params = unsafe { read_r11_v1(&mechanism, registry, Operation::General) }
                .expect("read mechanism")
                .params;
            r11_assert_null(&params, length as u64);
        }
    }
}

#[test]
fn r11_width_same_abi_struct_prefix_ok() {
    // S2 §5 width rule, same-ABI leg on a non-LP64 pair: struct-prefix Flat
    // carries the local fingerprint and source ABI.
    let registry = default_registry();
    let mut data = [0x01u8, 0x02, 0x03];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::RSA_PKCS_PSS.0 as CK_MECHANISM_TYPE,
        pParameter: data.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: data.len() as CK_ULONG,
    };
    let params = unsafe {
        read_r11_v1_abis(
            &mechanism,
            &registry,
            Operation::General,
            Some(R11_ILP32),
            Some(R11_ILP32),
        )
    }
    .expect("read mechanism")
    .params;
    match &params {
        Some(CkMechanismParams::Flat(p)) => {
            assert_eq!(p.declared_len, 3);
            assert_eq!(p.version, MECHANISM_PARAMETER_TRANSPORT_VERSION);
            assert_eq!(p.source_abi, Some(R11_ILP32));
            assert_eq!(
                p.fingerprint,
                r11_expected_fingerprint_for_abi(
                    "rsa_pss",
                    CkMechanismType::RSA_PKCS_PSS.0,
                    3,
                    R11_ILP32
                )
            );
            p.bytes.expose(|bytes| assert_eq!(bytes, &data));
        }
        other => panic!("same-ABI struct prefix must emit Flat, got {other:?}"),
    }
}

#[test]
fn r11_width_cross_abi_struct_prefix_rejected() {
    // S2 §5 width rule: struct prefixes require identical layouts, else
    // explicit PARAM_INVALID — in both directions.
    let registry = default_registry();
    let mut data = [0x01u8, 0x02, 0x03];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::RSA_PKCS_PSS.0 as CK_MECHANISM_TYPE,
        pParameter: data.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: data.len() as CK_ULONG,
    };
    for (local, backend) in [(Some(R11_LP64), Some(R11_ILP32)), (Some(R11_ILP32), Some(R11_LP64))] {
        assert!(
            matches!(
                unsafe {
                    read_r11_v1_abis(&mechanism, &registry, Operation::General, local, backend)
                },
                Err(CkRv::MECHANISM_PARAM_INVALID)
            ),
            "cross-ABI struct prefix ({local:?} -> {backend:?}) must be MPI"
        );
    }
}

#[test]
fn r11_width_unknown_backend_abi_rejects_struct_prefix() {
    // An unknown backend ABI fails closed for struct prefixes (layouts
    // cannot be proven identical).
    let registry = default_registry();
    let mut data = [0x01u8, 0x02, 0x03];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::RSA_PKCS_PSS.0 as CK_MECHANISM_TYPE,
        pParameter: data.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: data.len() as CK_ULONG,
    };
    assert!(
        matches!(
            unsafe {
                read_r11_v1_abis(&mechanism, &registry, Operation::General, Some(R11_LP64), None)
            },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "struct prefix with unknown backend ABI must be MPI"
    );
}

#[test]
fn r11_width_bare_flat_crosses_abis() {
    // S2 §5 width rule: parameterless and byte-buffer Flat cross ABIs
    // (backend ignored — `None` proves it); NULL carries no ABI at all.
    let registry = default_registry();
    let mut data = [0x5Au8; 16];
    let live = data.as_mut_ptr() as CK_VOID_PTR;

    let mechanism = r11_mechanism(CkMechanismType::SHA256.0, live, 16);
    let params = unsafe {
        read_r11_v1_abis(&mechanism, &registry, Operation::General, Some(R11_LP64), Some(R11_ILP32))
    }
    .expect("read mechanism")
    .params;
    match &params {
        Some(CkMechanismParams::Flat(p)) => r11_assert_flat(p, &data, ABI_EXEMPT_FINGERPRINT),
        other => panic!("cross-ABI parameterless Flat must emit, got {other:?}"),
    }

    let mechanism = r11_mechanism(CkMechanismType::SHA256.0, live, 0);
    let params = unsafe {
        read_r11_v1_abis(&mechanism, &registry, Operation::General, Some(R11_LP64), None)
    }
    .expect("read mechanism")
    .params;
    match &params {
        Some(CkMechanismParams::Flat(p)) => r11_assert_flat(p, &[], ABI_EXEMPT_FINGERPRINT),
        other => panic!("empty Flat must emit with unknown backend ABI, got {other:?}"),
    }

    // Byte-buffer shapes keep their (ABI-independent) typed encoding across
    // ABIs.
    let mechanism = r11_mechanism(CkMechanismType::AES_CBC.0, live, 16);
    let params = unsafe {
        read_r11_v1_abis(&mechanism, &registry, Operation::General, Some(R11_LP64), Some(R11_ILP32))
    }
    .expect("read mechanism")
    .params;
    match &params {
        Some(CkMechanismParams::Iv(IvParams { iv })) => assert_eq!(iv.as_slice(), data),
        other => panic!("cross-ABI byte-buffer input must stay typed Iv, got {other:?}"),
    }

    let mechanism = r11_mechanism(CkMechanismType::RSA_PKCS_PSS.0, std::ptr::null_mut(), 7);
    let params = unsafe {
        read_r11_v1_abis(&mechanism, &registry, Operation::General, Some(R11_LP64), None)
    }
    .expect("read mechanism")
    .params;
    r11_assert_null(&params, 7);
}

#[test]
fn r11_d3_null_huge_forwards_freely() {
    // D3: NULL lengths above 512 MiB forward freely (no bytes materialize)
    // — for unknown mechanisms (no descriptor needed) and even for
    // companion-set shapes, where the shared-length exception is vacuous
    // at the outer level (no struct is read, so no companion can share
    // the length; R17 enforces the exception per field on the typed path).
    const HUGE: CK_ULONG = 1024 * 1024 * 1024;
    let registry = default_registry();
    let kea_registry = r11_registry(&[("kea_derive", 0x0000_9998)], &[], &[]);
    for (mech, registry) in [(0x0000_9999u64, &registry), (0x0000_9998, &kea_registry)] {
        let mechanism = r11_mechanism(mech, std::ptr::null_mut(), HUGE);
        let params = unsafe { read_r11_v1(&mechanism, registry, Operation::General) }
            .expect("read mechanism")
            .params;
        r11_assert_null(&params, HUGE as u64);
    }
}

#[test]
fn r11_d3_governed_companion_stays_capped() {
    // D3 exception half: a governed (materialized) companion stays capped
    // at 512 MiB. Canonical GCM with a 600 MiB AAD declaration cannot ride
    // the typed path (the embedded copy is unmaterializable) and cannot
    // ride Flat (full native image) -> local MPI, with no 600 MB copy
    // attempted (the length guard short-circuits before any materialization;
    // R17 will type this input once presence fields exist).
    let registry = default_registry();
    let mut aad = [0xA1u8];
    let gcm = CK_GCM_PARAMS {
        pIv: std::ptr::null_mut(),
        ulIvLen: 12,
        ulIvBits: 96,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: 600 * 1024 * 1024,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
        pParameter: &gcm as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    assert!(
        matches!(
            unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::General) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "canonical GCM with an over-cap companion must be MPI (cap preserved)"
    );
}

#[test]
fn r11_v1_never_emits_legacy_raw() {
    // Under v1 the shim NEVER emits legacy Raw (S2 §5): every input the
    // legacy reader would forward as Raw becomes Flat, local MPI, or —
    // since R17 — representable typed v1 (S2 §5 step-1 presence reads).
    let registry = default_registry();
    let kip_registry = r11_registry(&[("kip", CkMechanismType::KIP_DERIVE.0)], &[], &[]);

    // Short structs -> Flat.
    for (name, mech, shape, bytes) in [
        ("short-pss", CkMechanismType::RSA_PKCS_PSS.0, "rsa_pss", vec![0x01u8, 0x02, 0x03]),
        ("short-eddsa", CkMechanismType::EDDSA.0, "eddsa", vec![0x07u8]),
    ] {
        let mut bytes = bytes;
        let mechanism = CK_MECHANISM {
            mechanism: mech as CK_MECHANISM_TYPE,
            pParameter: bytes.as_mut_ptr() as CK_VOID_PTR,
            ulParameterLen: bytes.len() as CK_ULONG,
        };
        let params = unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }
            .expect("read mechanism")
            .params;
        match &params {
            Some(CkMechanismParams::Flat(p)) => {
                r11_assert_flat(
                    p,
                    &bytes,
                    r11_expected_fingerprint(shape, mech, bytes.len() as u64),
                );
            }
            other => panic!("{name} must emit Flat under v1, got {other:?}"),
        }
    }

    // Degenerate canonical structs, R17 update: NULL-IV-12 + valid AAD is
    // representable typed v1 (S2 §5 step-1 discipline — the R17 mixed-field
    // fix), no longer local MPI. (Pre-R17 this pinned MPI with
    // "(typed-v1 presence is R17)".)
    let mut aad = [0xA1u8, 0xA2];
    let gcm = CK_GCM_PARAMS {
        pIv: std::ptr::null_mut(),
        ulIvLen: 12,
        ulIvBits: 96,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
        pParameter: &gcm as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::General) } {
        Ok(read) => match &read.params {
            Some(CkMechanismParams::Gcm(p)) => {
                // No Debug-format of the peer (secret-capable type — the
                // ABI audit forbids `{:?}` sinks in this file).
                assert!(p.iv_presence.is_null(), "NULL IV stays the NULL arm");
                assert_eq!(p.iv_presence.declared_len(), 12);
                assert_eq!(p.aad_presence.declared_len(), 2);
                assert!(p.aad_presence.as_present().is_some(), "valid AAD stays Present");
            }
            other => panic!("degenerate canonical GCM must be typed v1, got {other:?}"),
        },
        Err(e) => panic!("degenerate canonical GCM must be typed v1 under R17, got {e:?}"),
    }

    // Short nested/output shapes -> MPI (typed envelopes only, R18).
    let mut short = [0x5Au8; 4];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::KIP_DERIVE.0 as CK_MECHANISM_TYPE,
        pParameter: short.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: short.len() as CK_ULONG,
    };
    assert!(
        matches!(
            unsafe { read_r11_v1_native_abi(&mechanism, &kip_registry, Operation::General) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "short KIP must be MPI under v1 (never Raw)"
    );

    // Unknown mechanisms with params -> MPI.
    let mechanism = CK_MECHANISM {
        mechanism: 0x0000_9999,
        pParameter: short.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: short.len() as CK_ULONG,
    };
    assert!(
        matches!(
            unsafe { read_r11_v1(&mechanism, &registry, Operation::General) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "unknown mechanism with params must be MPI under v1 (never Raw)"
    );
}

#[test]
fn r11_excluded_mechanism_rejected() {
    // S2 §4 rule 1: operator exclusion wins — under BOTH capabilities and
    // for every outer class, including parameterless invocations.
    let excluded = CkMechanismType::RSA_PKCS_PSS.0;
    let registry = r11_registry(&[("rsa_pss", excluded)], &[], &[excluded]);
    let mut data = [0x01u8, 0x02, 0x03];
    let live = data.as_mut_ptr() as CK_VOID_PTR;
    let pss = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        sLen: 32,
    };

    let cases: Vec<(&str, CK_MECHANISM)> = vec![
        ("null-empty", r11_mechanism(excluded, std::ptr::null_mut(), 0)),
        ("null-nonzero", r11_mechanism(excluded, std::ptr::null_mut(), 5)),
        ("nonnull-empty", r11_mechanism(excluded, live, 0)),
        ("short", r11_mechanism(excluded, live, 3)),
        (
            "canonical",
            CK_MECHANISM {
                mechanism: excluded as CK_MECHANISM_TYPE,
                pParameter: &pss as *const _ as CK_VOID_PTR,
                ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
            },
        ),
    ];
    for (name, mechanism) in &cases {
        for (cap, result) in [
            ("legacy", unsafe { read_r11_legacy(mechanism, &registry, Operation::General) }),
            ("v1-lp64", unsafe {
                read_r11_v1_native_abi(mechanism, &registry, Operation::General)
            }),
        ] {
            assert!(
                matches!(result, Err(CkRv::MECHANISM_INVALID)),
                "excluded mechanism must be MI ({name}, {cap})"
            );
        }
    }
}

#[test]
fn r11_unknown_mechanism_matrix() {
    // Unknown mechanisms: v1 forwards NULL (no descriptor needed, S2 §6 RV
    // table) and rejects non-NULL with MPI; legacy collapses NULL/empty to
    // None and rejects non-NULL/nonzero with MPI.
    const UNKNOWN: u64 = 0x0000_9999;
    let registry = default_registry();
    let mut data = [0x5Au8; 7];
    let live = data.as_mut_ptr() as CK_VOID_PTR;

    let mechanism = r11_mechanism(UNKNOWN, std::ptr::null_mut(), 0);
    for (cap, result) in [
        ("legacy", unsafe { read_r11_legacy(&mechanism, &registry, Operation::General) }),
        ("v1", unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }),
    ] {
        let params = result.expect("read mechanism").params;
        assert_eq!(params, None, "(NULL,0) must stay None ({cap})");
    }

    let mechanism = r11_mechanism(UNKNOWN, std::ptr::null_mut(), 7);
    let params = unsafe { read_r11_legacy(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params;
    assert_eq!(params, None, "legacy (NULL,7) must collapse to None");
    let params = unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params;
    r11_assert_null(&params, 7);

    let mechanism = r11_mechanism(UNKNOWN, live, 0);
    let params = unsafe { read_r11_legacy(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params;
    assert_eq!(params, None, "legacy (non-NULL,0) must collapse to None");
    assert!(
        matches!(
            unsafe { read_r11_v1(&mechanism, &registry, Operation::General) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "v1 (non-NULL,0) with unknown mechanism must be MPI"
    );

    let mechanism = r11_mechanism(UNKNOWN, live, 7);
    for (cap, result) in [
        ("legacy", unsafe { read_r11_legacy(&mechanism, &registry, Operation::General) }),
        ("v1", unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }),
    ] {
        assert!(
            matches!(result, Err(CkRv::MECHANISM_PARAM_INVALID)),
            "unknown mechanism with params must be MPI ({cap})"
        );
    }
}

#[test]
fn r11_vendor_flat_requires_allowlist() {
    // S2 §4 TOML rule: TOML may bind a mechanism to a compiled descriptor
    // but can never authorize vendor Flat (the v1 allowlist is empty) — a
    // TOML-bound vendor mechanism with a noncanonical length is MPI under
    // v1 (legacy still emits Raw for old daemons). Canonical lengths stay
    // typed under both.
    const VENDOR: u64 = 0x8000_0001;
    let registry = r11_registry(&[("rsa_pss", VENDOR)], &[], &[]);
    let mut data = [0x01u8, 0x02, 0x03];
    let mechanism = CK_MECHANISM {
        mechanism: VENDOR as CK_MECHANISM_TYPE,
        pParameter: data.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: data.len() as CK_ULONG,
    };
    assert!(
        matches!(
            unsafe { read_r11_v1(&mechanism, &registry, Operation::General) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "vendor noncanonical length must be MPI under v1 (no allowlist entry)"
    );
    match unsafe { read_r11_legacy(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::Raw(_)) => {}
        other => panic!("legacy vendor short input must emit Raw, got {other:?}"),
    }

    let pss = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        sLen: 32,
    };
    let mechanism = CK_MECHANISM {
        mechanism: VENDOR as CK_MECHANISM_TYPE,
        pParameter: &pss as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::RsaPkcsPss(_)) => {}
        other => panic!("canonical vendor input must stay typed under v1, got {other:?}"),
    }
}

#[test]
fn r11_v1_canonical_stays_typed() {
    // Canonical lengths route to the EXISTING typed reader unchanged (R17
    // owns the typed rework): struct params parse, byte-buffer shapes keep
    // their legacy typed encoding (still valid under v1, S2 §3).
    let registry = default_registry();

    let mut iv = [0x11u8; 12];
    let mut aad = [0xA1u8, 0xA2];
    let gcm = r11_gcm_params(iv.as_mut_ptr(), 12, aad.as_mut_ptr(), 2);
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_GCM.0 as CK_MECHANISM_TYPE,
        pParameter: &gcm as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::Gcm(_)) => {}
        other => panic!("canonical GCM must stay typed under v1, got {other:?}"),
    }

    let pss = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        sLen: 32,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::RSA_PKCS_PSS.0 as CK_MECHANISM_TYPE,
        pParameter: &pss as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::RsaPkcsPss(_)) => {}
        other => panic!("canonical PSS must stay typed under v1, got {other:?}"),
    }

    let mut bytes = [0x5Au8; 16];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::AES_CBC.0 as CK_MECHANISM_TYPE,
        pParameter: bytes.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: bytes.len() as CK_ULONG,
    };
    match unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::Iv(IvParams { iv })) => assert_eq!(iv, bytes),
        other => panic!("byte-buffer input must stay typed Iv under v1, got {other:?}"),
    }
}

#[test]
fn r11_nested_legacy_skips_validate_fusion() {
    // Nested KIP nodes under legacy reproduce the old nested read EXACTLY:
    // no validate-fusion (excluded nested mechanisms forward, unknown
    // nested mechanisms with params ride nested Raw) — validation was
    // top-level-only. Guarded: the nested helper gathers global snapshots;
    // the custom registry + legacy pin are restored before return.
    const EXCLUDED_NESTED: u64 = 0x0000_9997;
    let _guard = crate::tests::shim_state_test_guard();
    crate::interface_probe::set_mechanism_parameter_transport_version_for_tests(0);
    crate::state::replace_mechanism_registry(r11_registry(&[], &[], &[EXCLUDED_NESTED]));

    // Excluded nested (NULL,0) forwards (top-level would be MI).
    let mut nested = r11_mechanism(EXCLUDED_NESTED, std::ptr::null_mut(), 0);
    let mut seed = [0xF2u8, 0xF3];
    let kip = CK_KIP_PARAMS {
        pMechanism: &mut nested,
        hKey: 0x43,
        pSeed: seed.as_mut_ptr(),
        ulSeedLen: seed.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_KIP_DERIVE,
        pParameter: &kip as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KIP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("kip")) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::Kip(KipParams { mechanism, .. })) => {
            assert_eq!(mechanism.mechanism_type.0, EXCLUDED_NESTED);
            assert_eq!(mechanism.params, None);
        }
        other => panic!("excluded nested (NULL,0) must forward in legacy, got {other:?}"),
    }

    // Unknown nested with params rides nested Raw (top-level would be MPI).
    let mut bytes = [0xE0u8, 0xE1, 0xE2, 0xE3];
    let mut nested = r11_mechanism(0x0000_9999, bytes.as_mut_ptr().cast(), 4);
    let kip = CK_KIP_PARAMS {
        pMechanism: &mut nested,
        hKey: 0x44,
        pSeed: seed.as_mut_ptr(),
        ulSeedLen: seed.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_KIP_DERIVE,
        pParameter: &kip as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KIP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("kip")) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::Kip(KipParams { mechanism, .. })) => match &mechanism.params {
            Some(CkMechanismParams::Raw(p)) => {
                p.data.expose(|b| assert_eq!(b, &bytes));
            }
            other => panic!("unknown nested params must ride nested Raw, got {other:?}"),
        },
        other => panic!("KIP with unknown nested params must parse in legacy, got {other:?}"),
    }

    ensure_registry();
}

#[test]
fn r11_nested_v1_outer_classification() {
    // Nested KIP nodes under v1 get full v1 semantics through the nested
    // helper (one snapshot per node): a nested (NULL,n) becomes Null, never
    // collapsed. Guarded: global snapshots; restored before return.
    let _guard = crate::tests::shim_state_test_guard();
    crate::state::replace_mechanism_registry(r11_registry(
        &[("kip", CkMechanismType::KIP_DERIVE.0)],
        &[],
        &[],
    ));
    crate::interface_probe::set_mechanism_parameter_transport_version_for_tests(1);

    let mut nested = r11_mechanism(CkMechanismType::SHA256.0, std::ptr::null_mut(), 5);
    let mut seed = [0xF2u8, 0xF3];
    let kip = CK_KIP_PARAMS {
        pMechanism: &mut nested,
        hKey: 0x43,
        pSeed: seed.as_mut_ptr(),
        ulSeedLen: seed.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_KIP_DERIVE,
        pParameter: &kip as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KIP_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_mechanism_with_shape(&mechanism, Some("kip")) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::Kip(KipParams { mechanism, .. })) => {
            r11_assert_null(&mechanism.params, 5);
        }
        other => panic!("nested (NULL,5) must be Null under v1, got {other:?}"),
    }

    crate::interface_probe::set_mechanism_parameter_transport_version_for_tests(0);
    ensure_registry();
}

#[test]
fn r11_nested_core_skips_exclusion() {
    // The nested contract, hermetically: nested nodes skip exclusion under
    // BOTH capabilities (legacy parity: validation was top-level-only;
    // daemon R9 does not recurse into nested params).
    let excluded = CkMechanismType::RSA_PKCS_PSS.0;
    let registry = r11_registry(&[("rsa_pss", excluded)], &[], &[excluded]);
    let mechanism = r11_mechanism(excluded, std::ptr::null_mut(), 0);
    for capability in [0u32, 1] {
        let params = unsafe {
            read_mechanism_for_transport_with_snapshots(
                &mechanism,
                &registry,
                capability,
                Some(R11_LP64),
                Some(R11_LP64),
                Operation::General,
                true,
                &mut NestingBudget::new(),
            )
        }
        .expect("read mechanism")
        .params;
        assert_eq!(params, None, "nested (NULL,0) must forward (capability {capability})");
    }
    // Nested legacy also skips the shape gate: unknown nested params ride
    // nested Raw.
    let mut bytes = [0xE0u8, 0xE1];
    let mechanism = r11_mechanism(0x0000_9999, bytes.as_mut_ptr().cast(), 2);
    let params = unsafe {
        read_mechanism_for_transport_with_snapshots(
            &mechanism,
            &registry,
            0,
            Some(R11_LP64),
            Some(R11_LP64),
            Operation::General,
            true,
            &mut NestingBudget::new(),
        )
    }
    .expect("read mechanism")
    .params;
    match &params {
        Some(CkMechanismParams::Raw(p)) => {
            p.data.expose(|b| assert_eq!(b, &bytes));
        }
        other => panic!("nested legacy unknown params must ride Raw, got {other:?}"),
    }
}

#[test]
fn r11_production_entry_gathers_global_snapshots() {
    // The pointer-level production entry consumes the R5/R10 snapshot API
    // unchanged (global capability; registry + ABI from global state):
    // legacy globals reproduce legacy behavior, v1 globals switch the same
    // call to v1 emission. Guarded + restored (capability-mutating).
    let _guard = crate::tests::shim_state_test_guard();
    ensure_registry();
    crate::interface_probe::set_mechanism_parameter_transport_version_for_tests(0);

    let mut data = [0x01u8, 0x02, 0x03];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::RSA_PKCS_PSS.0 as CK_MECHANISM_TYPE,
        pParameter: data.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: data.len() as CK_ULONG,
    };
    match unsafe { read_mechanism_for_transport(&mechanism, Operation::General) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::Raw(_)) => {}
        other => panic!("production entry with legacy globals must emit Raw, got {other:?}"),
    }

    crate::interface_probe::set_mechanism_parameter_transport_version_for_tests(1);
    let mut bytes = [0x5Au8; 16];
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        pParameter: bytes.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: bytes.len() as CK_ULONG,
    };
    // Bare Flat crosses ABIs on every host (no struct layout involved).
    match unsafe { read_mechanism_for_transport(&mechanism, Operation::General) }
        .expect("read mechanism")
        .params
    {
        Some(CkMechanismParams::Flat(p)) => {
            assert_eq!(p.declared_len, 16);
            assert_eq!(p.version, MECHANISM_PARAMETER_TRANSPORT_VERSION);
            assert_eq!(p.fingerprint, ABI_EXEMPT_FINGERPRINT);
            p.bytes.expose(|b| assert_eq!(b, &bytes));
        }
        other => panic!("production entry with v1 globals must emit Flat, got {other:?}"),
    }
    let mechanism = r11_mechanism(CkMechanismType::SHA256.0, std::ptr::null_mut(), 5);
    let params = unsafe { read_mechanism_for_transport(&mechanism, Operation::General) }
        .expect("read mechanism")
        .params;
    r11_assert_null(&params, 5);

    crate::interface_probe::set_mechanism_parameter_transport_version_for_tests(0);
}

#[test]
fn r11_no_native_abi_typed_only_no_flat() {
    // Without a v1 ABI for this target (`local_abi == None`, i.e.
    // big-endian) the shim can never emit well-formed Flat (no source ABI
    // to name): the typed path still works via native mirrors, legacy Raw
    // stays banned, and (non-NULL,0) cannot collapse to None.
    let registry = default_registry();
    let mut data = [0x01u8, 0x02, 0x03];
    let live = data.as_mut_ptr() as CK_VOID_PTR;

    let mechanism = r11_mechanism(CkMechanismType::SHA256.0, live, 0);
    assert!(
        matches!(
            unsafe {
                read_mechanism_for_transport_with_snapshots(
                    &mechanism,
                    &registry,
                    1,
                    None,
                    None,
                    Operation::General,
                    false,
                    &mut NestingBudget::new(),
                )
            },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "(non-NULL,0) without a native ABI must be MPI (no Flat, no collapse)"
    );

    let mechanism = r11_mechanism(CkMechanismType::RSA_PKCS_PSS.0, live, 3);
    assert!(
        matches!(
            unsafe {
                read_mechanism_for_transport_with_snapshots(
                    &mechanism,
                    &registry,
                    1,
                    None,
                    None,
                    Operation::General,
                    false,
                    &mut NestingBudget::new(),
                )
            },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "short struct without a native ABI must be MPI (typed reader Raw banned)"
    );

    let pss = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        mgf: 1,
        sLen: 32,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::RSA_PKCS_PSS.0 as CK_MECHANISM_TYPE,
        pParameter: &pss as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };
    match unsafe {
        read_mechanism_for_transport_with_snapshots(
            &mechanism,
            &registry,
            1,
            None,
            None,
            Operation::General,
            false,
            &mut NestingBudget::new(),
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::RsaPkcsPss(_)) => {}
        other => panic!("canonical struct without a native ABI must stay typed, got {other:?}"),
    }
}

#[test]
fn r11_synthetic_parameterless_binding_rides_flat() {
    // A mechanism bound to the synthetic `parameterless` marker shape rides
    // Flat under v1 (S2 §4: parameterless-shaped bytes may carry arbitrary
    // flat bytes to the cap) — daemon-consistent (`decide_flat` grants the
    // bare form on both edges).
    let registry = r11_registry(&[("parameterless", 0x0000_9998)], &[], &[]);
    let mut data = [0x5Au8; 16];
    let mechanism = CK_MECHANISM {
        mechanism: 0x0000_9998,
        pParameter: data.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: data.len() as CK_ULONG,
    };
    let params = unsafe { read_r11_v1(&mechanism, &registry, Operation::General) }
        .expect("read mechanism")
        .params;
    match &params {
        Some(CkMechanismParams::Flat(p)) => r11_assert_flat(p, &data, ABI_EXEMPT_FINGERPRINT),
        other => panic!("parameterless-bound bytes must ride Flat, got {other:?}"),
    }
}

#[test]
fn r11_v1_canonical_kip_stays_typed() {
    // Nested/output forms ride the typed path under v1 (R18 owns their
    // envelopes): canonical KIP parses through the v1 router with v1
    // semantics at the nested node. Guarded: the nested helper gathers
    // global snapshots; restored before return.
    let _guard = crate::tests::shim_state_test_guard();
    let kip_registry = r11_registry(&[("kip", CkMechanismType::KIP_DERIVE.0)], &[], &[]);
    crate::state::replace_mechanism_registry(kip_registry.clone());
    crate::interface_probe::set_mechanism_parameter_transport_version_for_tests(1);

    let mut nested = r11_mechanism(CkMechanismType::SHA256.0, std::ptr::null_mut(), 5);
    let mut seed = [0xF2u8, 0xF3, 0xF4];
    let kip = CK_KIP_PARAMS {
        pMechanism: &mut nested,
        hKey: 0x43,
        pSeed: seed.as_mut_ptr(),
        ulSeedLen: seed.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::KIP_DERIVE.0 as CK_MECHANISM_TYPE,
        pParameter: &kip as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KIP_PARAMS>() as CK_ULONG,
    };
    let params = unsafe { read_r11_v1_native_abi(&mechanism, &kip_registry, Operation::General) }
        .expect("read mechanism")
        .params;
    match &params {
        Some(CkMechanismParams::Kip(KipParams { mechanism, key_handle, seed, .. })) => {
            assert_eq!(mechanism.mechanism_type.0, CkMechanismType::SHA256.0);
            assert_eq!(key_handle.0, 0x43);
            assert_eq!(seed, &SecretBytes::copy_from_slice(&[0xF2, 0xF3, 0xF4]));
            r11_assert_null(&mechanism.params, 5);
        }
        other => panic!("canonical KIP must stay typed under v1, got {other:?}"),
    }

    crate::interface_probe::set_mechanism_parameter_transport_version_for_tests(0);
    ensure_registry();
}

#[test]
fn r11_wrapping_extent_rejected_without_deref() {
    // Arithmetic-invalid extents are rejected without dereference even when
    // the Flat grant would allow the length: the capped raw reader
    // re-checks the extent rather than trust the grant. (The pointer below
    // is bogus — a dereference would fault / be Miri UB.)
    let registry = default_registry();
    let bogus = usize::MAX as *mut u8 as CK_VOID_PTR;
    let mechanism = r11_mechanism(CkMechanismType::SHA256.0, bogus, 100);
    assert!(
        matches!(
            unsafe { read_r11_v1(&mechanism, &registry, Operation::General) },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "wrapping extent must be MPI without dereference"
    );
}

// ---------------------------------------------------------------------------
// R17: shim typed readers, input-pointer families (S2 §5 step-1 discipline).
// Every embedded field is read INDEPENDENTLY: NULL records its declared
// length without dereference (D3: no cap); non-NULL/zero records
// Present(empty); non-NULL/positive copies under the 512 MiB ceiling.
// Legacy capability preserves existing behavior exactly (the R11 suites
// below pin it); these tests cover the v1 typed branch only.
// ---------------------------------------------------------------------------

/// Synthetic mechanism numbers for the R17 matrix (unbound range; the
/// wrap layouts key on the real AES_GCM/AES_CCM numbers, so the `gcm`
/// and `ccm` shapes bind those and every other shape binds synthetic).
const R17_SYN_BASE: u64 = 0x0000_A000;

/// R17 shapes bound to synthetic mechanisms (single source for the
/// registry builder + the mech lookup; reviewer-checked against the
/// R16 presence table — 33 R16 rows + `gcm_compat` here, `gcm`/`ccm`
/// on the real mechanisms, `gcm_wrap`/`ccm_wrap` unbound (wrap
/// selection bypasses the binding) = all 37 R16 input-pointer shapes).
const R17_SYN_SHAPES: &[&str] = &[
    "gcm_compat",
    "rsa_oaep",
    "ecdh1_derive",
    "hkdf",
    "eddsa",
    "chacha20",
    "salsa20",
    "salsa20_chacha20_poly1305",
    "aes_cbc_encrypt_data",
    "des_cbc_encrypt_data",
    "camellia_cbc_encrypt_data",
    "aria_cbc_encrypt_data",
    "seed_cbc_encrypt_data",
    "key_derivation_string",
    "rc5_cbc",
    "rsa_aes_key_wrap",
    "sign_additional_context",
    "kmac",
    "mu_gen",
    "pkcs5_pbkd2",
    "pbe",
    "ecdh_aes_key_wrap",
    "ecdh2_derive",
    "ecmqv_derive",
    "x942_dh1_derive",
    "x942_dh2_derive",
    "x942_mqv_derive",
    "gostr3410_derive",
    "gostr3410_key_wrap",
    "key_wrap_set_oaep",
    "ike_prf_derive",
    "ike1_prf_derive",
    "ike1_extended_derive",
    "ike2_prf_plus_derive",
];

/// Custom registry for the R17 matrix: no TOML parse (Miri-friendly),
/// one binding per input-pointer shape.
fn r17_registry() -> MechanismRegistry {
    let mut bindings: Vec<(&str, u64)> =
        vec![("gcm", CkMechanismType::AES_GCM.0), ("ccm", CkMechanismType::AES_CCM.0)];
    bindings.extend(
        R17_SYN_SHAPES.iter().enumerate().map(|(i, shape)| (*shape, R17_SYN_BASE + i as u64)),
    );
    assert_eq!(R17_SYN_SHAPES.len(), 34, "r17 registry binds 33 R16 rows + gcm_compat");
    r11_registry(&bindings, &[], &[])
}

/// Mechanism number bound to `shape` in [`r17_registry`] (`gcm_wrap` /
/// `ccm_wrap` ride the real AES numbers — wrap selection keys on the
/// number, and the R7 resolver bypasses the binding for wrap sizes).
fn r17_mech(shape: &str) -> u64 {
    match shape {
        "gcm" | "gcm_wrap" => CkMechanismType::AES_GCM.0,
        "ccm" | "ccm_wrap" => CkMechanismType::AES_CCM.0,
        _ => R17_SYN_SHAPES
            .iter()
            .position(|s| *s == shape)
            .map(|i| R17_SYN_BASE + i as u64)
            .expect("r17 shape"),
    }
}

/// Assert one v1 typed plain-bytes field: legacy bytes mirror the
/// present pointee, peer is `Present` of the same bytes.
fn r17_assert_present(legacy: &[u8], peer: &PointerBytes, expected: &[u8]) {
    assert_eq!(legacy, expected, "legacy bytes mirror the present pointee");
    assert_eq!(peer, &PointerBytes::present_copy(expected), "peer is Present(bytes)");
}

/// Secret-bytes variant of [`r17_assert_present`].
fn r17_assert_present_secret(legacy: &SecretBytes, peer: &PointerBytes, expected: &[u8]) {
    legacy.expose(|b| assert_eq!(b, expected, "legacy secret mirrors the present pointee"));
    assert_eq!(peer, &PointerBytes::present_copy(expected), "peer is Present(bytes)");
}

/// Assert one v1 typed plain-bytes field is NULL with `declared_len`:
/// legacy bytes stay empty, peer is `Null(n)`.
fn r17_assert_null(legacy: &[u8], peer: &PointerBytes, declared_len: u64) {
    assert!(legacy.is_empty(), "NULL legacy bytes stay empty");
    assert_eq!(peer, &PointerBytes::null_len(declared_len), "peer is Null(n)");
}

/// Secret-bytes variant of [`r17_assert_null`].
fn r17_assert_null_secret(legacy: &SecretBytes, peer: &PointerBytes, declared_len: u64) {
    legacy.expose(|b| assert!(b.is_empty(), "NULL legacy secret stays empty"));
    assert_eq!(peer, &PointerBytes::null_len(declared_len), "peer is Null(n)");
}

/// S2 §12 typed probe: GCM NULL-IV-12 — a NULL IV with declared length
/// 12 stays typed (`Null{12}`), beside a valid copied AAD.
#[test]
fn r17_probe_gcm_null_iv_12() {
    let registry = r17_registry();
    let mut aad = [0xA1u8, 0xA2];
    let gcm = CK_GCM_PARAMS {
        pIv: std::ptr::null_mut(),
        ulIvLen: 12,
        ulIvBits: 96,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: r17_mech("gcm") as CK_MECHANISM_TYPE,
        pParameter: &gcm as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::General) }
        .expect("NULL-IV-12 stays typed under v1")
        .params
    {
        Some(CkMechanismParams::Gcm(p)) => {
            r17_assert_null(&p.iv, &p.iv_presence, 12);
            assert_eq!(p.iv_buffer_len, 0, "NULL IV has no buffer");
            assert!(!p.iv_null && !p.aad_null, "v1 is presence-only: legacy bools stay clear");
            r17_assert_present_secret(&p.aad, &p.aad_presence, &aad);
            assert_eq!(p.tag_bits, 128);
        }
        other => panic!("GCM NULL-IV-12 must stay typed under v1, got {other:?}"),
    }
}

/// S2 §12 typed probe (THE mixed-field fix): valid-IV + NULL-AAD-16
/// GCM becomes ONE typed message (copied IV + `aad Null{16}`) — the IV
/// is never discarded into `Raw` again.
#[test]
fn r17_probe_gcm_mixed_iv_aad_null_16() {
    let registry = r17_registry();
    let mut iv = [0x11u8; 12];
    let gcm = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvBits: 96,
        pAAD: std::ptr::null_mut(),
        ulAADLen: 16,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: r17_mech("gcm") as CK_MECHANISM_TYPE,
        pParameter: &gcm as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::General) }
        .expect("mixed IV+AAD-NULL-16 stays typed under v1")
        .params
    {
        Some(CkMechanismParams::Gcm(p)) => {
            r17_assert_present(&p.iv, &p.iv_presence, &iv);
            assert_eq!(p.iv_buffer_len, 12);
            assert!(!p.iv_null && !p.aad_null, "v1 is presence-only: legacy bools stay clear");
            r17_assert_null_secret(&p.aad, &p.aad_presence, 16);
        }
        other => panic!("mixed IV+AAD-NULL-16 must stay typed under v1, got {other:?}"),
    }
}

/// S2 §12 typed probe: EdDSA NULL-ctx — a NULL context with declared
/// length stays typed (`Null{n}`), never `Raw`.
#[test]
fn r17_probe_eddsa_null_ctx() {
    let registry = r17_registry();
    let eddsa = CK_EDDSA_PARAMS {
        phFlag: CK_FALSE,
        ulContextDataLen: 7,
        pContextData: std::ptr::null_mut(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: r17_mech("eddsa") as CK_MECHANISM_TYPE,
        pParameter: &eddsa as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_EDDSA_PARAMS>() as CK_ULONG,
    };
    match unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::General) }
        .expect("EdDSA NULL-ctx stays typed under v1")
        .params
    {
        Some(CkMechanismParams::Eddsa(p)) => {
            assert!(!p.ph_flag);
            r17_assert_null_secret(&p.context_data, &p.context_data_presence, 7);
        }
        other => panic!("EdDSA NULL-ctx must stay typed under v1, got {other:?}"),
    }
}

/// S2 §12 typed probe: pointee-copy-before-decision — the typed value
/// owns its bytes (mutating caller memory after the read cannot change
/// it): the copy precedes the returned decision. Uses a mixed shape so
/// the probe also exercises the NULL arm beside the copied pointee.
#[test]
fn r17_probe_pointee_copy_before_decision() {
    let registry = r17_registry();
    let mut iv = [0x11u8; 12];
    let gcm = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvBits: 96,
        pAAD: std::ptr::null_mut(),
        ulAADLen: 16,
        ulTagBits: 128,
    };
    let mechanism = CK_MECHANISM {
        mechanism: r17_mech("gcm") as CK_MECHANISM_TYPE,
        pParameter: &gcm as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    let params = unsafe { read_r11_v1_native_abi(&mechanism, &registry, Operation::General) }
        .expect("mixed GCM stays typed under v1")
        .params;
    // Mutate the caller buffer after the read returns.
    iv.fill(0xEE);
    match params {
        Some(CkMechanismParams::Gcm(p)) => {
            r17_assert_present(&p.iv, &p.iv_presence, &[0x11; 12]);
            r17_assert_null_secret(&p.aad, &p.aad_presence, 16);
        }
        other => panic!("mixed GCM must stay typed under v1, got {other:?}"),
    }
}

/// Read one host-native param struct as `shape` under v1 with an
/// explicit operation (matrix shorthand).
///
/// # Safety
///
/// `p_parameter` must designate `ul_parameter_len` readable bytes
/// containing the shape's C struct.
unsafe fn r17_read_v1_op(
    registry: &MechanismRegistry,
    shape: &str,
    p_parameter: CK_VOID_PTR,
    ul_parameter_len: CK_ULONG,
    operation: Operation,
) -> Result<CkMechanism, CkRv> {
    let mechanism = r11_mechanism(r17_mech(shape), p_parameter, ul_parameter_len);
    unsafe { read_r11_v1_native_abi(&mechanism, registry, operation) }
}

/// Read one host-native param struct as `shape` under v1/`General`
/// (matrix shorthand; wrap tests pass [`Operation::WrapKey`] via
/// [`r17_read_v1_op`]).
///
/// # Safety
///
/// `p_parameter` must designate `ul_parameter_len` readable bytes
/// containing the shape's C struct.
unsafe fn r17_read_v1(
    registry: &MechanismRegistry,
    shape: &str,
    p_parameter: CK_VOID_PTR,
    ul_parameter_len: CK_ULONG,
) -> Result<CkMechanism, CkRv> {
    unsafe { r17_read_v1_op(registry, shape, p_parameter, ul_parameter_len, Operation::General) }
}

/// R17 embedded-field matrix for `rsa_oaep` (single field: NULL/0,
/// NULL/n, ptr/0, ptr/n; no mixed case).
#[test]
fn r17_matrix_rsa_oaep() {
    let registry = r17_registry();
    let read = |p: CK_VOID_PTR, len: CK_ULONG| {
        let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            mgf: 1,
            source: 1,
            pSourceData: p,
            ulSourceDataLen: len,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "rsa_oaep",
                &mut oaep as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
            )
        }
        .expect("OAEP stays typed under v1")
        .params
        {
            Some(CkMechanismParams::RsaPkcsOaep(p)) => p,
            other => panic!("OAEP must stay typed under v1, got {other:?}"),
        }
    };
    let mut data = [0xA0u8, 0xA1, 0xA2];
    // ptr/n: copied, Present.
    let p = read(data.as_mut_ptr() as CK_VOID_PTR, data.len() as CK_ULONG);
    assert!(!p.source_null, "v1 is presence-only");
    r17_assert_present_secret(&p.source_data, &p.source_data_presence, &data);
    // ptr/0: empty, Present.
    let p = read(data.as_mut_ptr() as CK_VOID_PTR, 0);
    assert!(!p.source_null, "v1 is presence-only");
    r17_assert_present_secret(&p.source_data, &p.source_data_presence, &[]);
    // NULL/0: Null{0}.
    let p = read(std::ptr::null_mut(), 0);
    assert!(!p.source_null, "v1 is presence-only");
    r17_assert_null_secret(&p.source_data, &p.source_data_presence, 0);
    // NULL/n: Null{n}, no dereference.
    let p = read(std::ptr::null_mut(), 9);
    assert!(!p.source_null, "v1 is presence-only");
    r17_assert_null_secret(&p.source_data, &p.source_data_presence, 9);
}

/// R17 embedded-field matrix for `eddsa` (single field).
#[test]
fn r17_matrix_eddsa() {
    let registry = r17_registry();
    let read = |p: CK_BYTE_PTR, len: CK_ULONG| {
        let mut eddsa = CK_EDDSA_PARAMS { phFlag: CK_TRUE, ulContextDataLen: len, pContextData: p };
        match unsafe {
            r17_read_v1(
                &registry,
                "eddsa",
                &mut eddsa as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_EDDSA_PARAMS>() as CK_ULONG,
            )
        }
        .expect("EdDSA stays typed under v1")
        .params
        {
            Some(CkMechanismParams::Eddsa(p)) => p,
            other => panic!("EdDSA must stay typed under v1, got {other:?}"),
        }
    };
    let mut ctx = [0xB1u8, 0xB2];
    let p = read(ctx.as_mut_ptr(), ctx.len() as CK_ULONG);
    assert!(p.ph_flag);
    r17_assert_present_secret(&p.context_data, &p.context_data_presence, &ctx);
    let p = read(ctx.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.context_data, &p.context_data_presence, &[]);
    let p = read(std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.context_data, &p.context_data_presence, 0);
    let p = read(std::ptr::null_mut(), 11);
    r17_assert_null_secret(&p.context_data, &p.context_data_presence, 11);
}

/// R17 embedded-field matrix for `rc5_cbc` (single IV field).
#[test]
fn r17_matrix_rc5_cbc() {
    let registry = r17_registry();
    let read = |p: CK_BYTE_PTR, len: CK_ULONG| {
        let mut rc5 = CK_RC5_CBC_PARAMS { ulWordsize: 4, ulRounds: 12, pIv: p, ulIvLen: len };
        match unsafe {
            r17_read_v1(
                &registry,
                "rc5_cbc",
                &mut rc5 as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_RC5_CBC_PARAMS>() as CK_ULONG,
            )
        }
        .expect("RC5-CBC stays typed under v1")
        .params
        {
            Some(CkMechanismParams::Rc5Cbc(p)) => p,
            other => panic!("RC5-CBC must stay typed under v1, got {other:?}"),
        }
    };
    let mut iv = [0xC1u8; 8];
    let p = read(iv.as_mut_ptr(), iv.len() as CK_ULONG);
    assert_eq!((p.word_size, p.rounds), (4, 12));
    r17_assert_present(&p.iv, &p.iv_presence, &iv);
    let p = read(iv.as_mut_ptr(), 0);
    r17_assert_present(&p.iv, &p.iv_presence, &[]);
    let p = read(std::ptr::null_mut(), 0);
    r17_assert_null(&p.iv, &p.iv_presence, 0);
    let p = read(std::ptr::null_mut(), 8);
    r17_assert_null(&p.iv, &p.iv_presence, 8);
}

/// R17 embedded-field matrix for `key_derivation_string` (single field).
#[test]
fn r17_matrix_key_derivation_string() {
    let registry = r17_registry();
    let read = |p: CK_BYTE_PTR, len: CK_ULONG| {
        let mut kds = CK_KEY_DERIVATION_STRING_DATA { pData: p, ulLen: len };
        match unsafe {
            r17_read_v1(
                &registry,
                "key_derivation_string",
                &mut kds as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_KEY_DERIVATION_STRING_DATA>() as CK_ULONG,
            )
        }
        .expect("KDF string stays typed under v1")
        .params
        {
            Some(CkMechanismParams::KeyDerivationString(p)) => p,
            other => panic!("KDF string must stay typed under v1, got {other:?}"),
        }
    };
    let mut data = [0xDEu8, 0xAD, 0xBE, 0xEF];
    let p = read(data.as_mut_ptr(), data.len() as CK_ULONG);
    r17_assert_present_secret(&p.data, &p.data_presence, &data);
    let p = read(data.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.data, &p.data_presence, &[]);
    let p = read(std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.data, &p.data_presence, 0);
    let p = read(std::ptr::null_mut(), 4);
    r17_assert_null_secret(&p.data, &p.data_presence, 4);
}

/// R17 embedded-field matrix for `kmac` (single customization field).
#[test]
fn r17_matrix_kmac() {
    let registry = r17_registry();
    let read = |p: CK_VOID_PTR, len: CK_ULONG| {
        let mut kmac = super::CkKmacParams {
            h_key: 7,
            ul_mac_length: 32,
            p_customization_string: p,
            ul_customization_string_len: len,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "kmac",
                &mut kmac as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<super::CkKmacParams>() as CK_ULONG,
            )
        }
        .expect("KMAC stays typed under v1")
        .params
        {
            Some(CkMechanismParams::Kmac(p)) => p,
            other => panic!("KMAC must stay typed under v1, got {other:?}"),
        }
    };
    let mut custom = [0xD1u8, 0xD2, 0xD3];
    let p = read(custom.as_mut_ptr() as CK_VOID_PTR, custom.len() as CK_ULONG);
    assert_eq!((p.key_handle.0, p.mac_length), (7, 32));
    r17_assert_present_secret(&p.customization_string, &p.customization_string_presence, &custom);
    let p = read(custom.as_mut_ptr() as CK_VOID_PTR, 0);
    r17_assert_present_secret(&p.customization_string, &p.customization_string_presence, &[]);
    let p = read(std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.customization_string, &p.customization_string_presence, 0);
    let p = read(std::ptr::null_mut(), 3);
    r17_assert_null_secret(&p.customization_string, &p.customization_string_presence, 3);
}

/// R17 embedded-field matrix for `key_wrap_set_oaep` (single field).
#[test]
fn r17_matrix_key_wrap_set_oaep() {
    let registry = r17_registry();
    let read = |p: CK_BYTE_PTR, len: CK_ULONG| {
        let mut kw = CK_KEY_WRAP_SET_OAEP_PARAMS { bBC: 7, pX: p, ulXLen: len };
        match unsafe {
            r17_read_v1(
                &registry,
                "key_wrap_set_oaep",
                &mut kw as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_KEY_WRAP_SET_OAEP_PARAMS>() as CK_ULONG,
            )
        }
        .expect("wrap-set-OAEP stays typed under v1")
        .params
        {
            Some(CkMechanismParams::KeyWrapSetOaep(p)) => p,
            other => panic!("wrap-set-OAEP must stay typed under v1, got {other:?}"),
        }
    };
    let mut x = [0xE1u8, 0xE2];
    let p = read(x.as_mut_ptr(), x.len() as CK_ULONG);
    assert_eq!(p.bc, 7);
    r17_assert_present_secret(&p.x, &p.x_presence, &x);
    let p = read(x.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.x, &p.x_presence, &[]);
    let p = read(std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.x, &p.x_presence, 0);
    let p = read(std::ptr::null_mut(), 2);
    r17_assert_null_secret(&p.x, &p.x_presence, 2);
}

/// R17 embedded-field matrix for `ike1_extended_derive` (single field).
#[test]
fn r17_matrix_ike1_extended_derive() {
    let registry = r17_registry();
    let read = |p: CK_BYTE_PTR, len: CK_ULONG| {
        let mut ike = CK_IKE1_EXTENDED_DERIVE_PARAMS {
            prfMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            bHasKeygxy: CK_FALSE,
            hKeygxy: 0,
            ulExtraDataLen: len,
            pExtraData: p,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "ike1_extended_derive",
                &mut ike as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_IKE1_EXTENDED_DERIVE_PARAMS>() as CK_ULONG,
            )
        }
        .expect("IKE1-extended stays typed under v1")
        .params
        {
            Some(CkMechanismParams::Ike1ExtendedDerive(p)) => p,
            other => panic!("IKE1-extended must stay typed under v1, got {other:?}"),
        }
    };
    let mut extra = [0xF1u8, 0xF2, 0xF3];
    let p = read(extra.as_mut_ptr(), extra.len() as CK_ULONG);
    assert!(!p.has_keygxy);
    r17_assert_present_secret(&p.extra_data, &p.extra_data_presence, &extra);
    let p = read(extra.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.extra_data, &p.extra_data_presence, &[]);
    let p = read(std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.extra_data, &p.extra_data_presence, 0);
    let p = read(std::ptr::null_mut(), 3);
    r17_assert_null_secret(&p.extra_data, &p.extra_data_presence, 3);
}

/// R17 embedded-field matrix for `ike2_prf_plus_derive` (single field).
#[test]
fn r17_matrix_ike2_prf_plus_derive() {
    let registry = r17_registry();
    let read = |p: CK_BYTE_PTR, len: CK_ULONG| {
        let mut ike = CK_IKE2_PRF_PLUS_DERIVE_PARAMS {
            prfMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            bHasSeedKey: CK_FALSE,
            hSeedKey: 0,
            ulSeedDataLen: len,
            pSeedData: p,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "ike2_prf_plus_derive",
                &mut ike as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>() as CK_ULONG,
            )
        }
        .expect("IKE2-prf-plus stays typed under v1")
        .params
        {
            Some(CkMechanismParams::Ike2PrfPlusDerive(p)) => p,
            other => panic!("IKE2-prf-plus must stay typed under v1, got {other:?}"),
        }
    };
    let mut seed = [0x01u8, 0x02];
    let p = read(seed.as_mut_ptr(), seed.len() as CK_ULONG);
    assert!(!p.has_seed_key);
    r17_assert_present_secret(&p.seed_data, &p.seed_data_presence, &seed);
    let p = read(seed.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.seed_data, &p.seed_data_presence, &[]);
    let p = read(std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.seed_data, &p.seed_data_presence, 0);
    let p = read(std::ptr::null_mut(), 2);
    r17_assert_null_secret(&p.seed_data, &p.seed_data_presence, 2);
}

/// R17 embedded-field matrix for `ecdh_aes_key_wrap` (single field).
#[test]
fn r17_matrix_ecdh_aes_key_wrap() {
    let registry = r17_registry();
    let read = |p: CK_BYTE_PTR, len: CK_ULONG| {
        let mut wrap = CK_ECDH_AES_KEY_WRAP_PARAMS {
            ulAESKeyBits: 256,
            kdf: 1,
            ulSharedDataLen: len,
            pSharedData: p,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "ecdh_aes_key_wrap",
                &mut wrap as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_ECDH_AES_KEY_WRAP_PARAMS>() as CK_ULONG,
            )
        }
        .expect("ECDH-AES-wrap stays typed under v1")
        .params
        {
            Some(CkMechanismParams::EcdhAesKeyWrap(p)) => p,
            other => panic!("ECDH-AES-wrap must stay typed under v1, got {other:?}"),
        }
    };
    let mut shared = [0x03u8, 0x04, 0x05];
    let p = read(shared.as_mut_ptr(), shared.len() as CK_ULONG);
    assert_eq!(p.aes_key_bits, 256);
    r17_assert_present_secret(&p.shared_data, &p.shared_data_presence, &shared);
    let p = read(shared.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.shared_data, &p.shared_data_presence, &[]);
    let p = read(std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.shared_data, &p.shared_data_presence, 0);
    let p = read(std::ptr::null_mut(), 3);
    r17_assert_null_secret(&p.shared_data, &p.shared_data_presence, 3);
}

#[repr(C)]
struct R17SignAdditionalContext {
    hedge_variant: CK_ULONG,
    p_context: *mut CK_BYTE,
    ul_context_len: CK_ULONG,
}

#[repr(C)]
struct R17HashSignAdditionalContext {
    hedge_variant: CK_ULONG,
    p_context: *mut CK_BYTE,
    ul_context_len: CK_ULONG,
    hash: CK_ULONG,
}

/// R17 embedded-field matrix for `sign_additional_context` (single
/// field; both the base and the trailing-hash layouts).
#[test]
fn r17_matrix_sign_additional_context() {
    let registry = r17_registry();
    let read = |ctx: &mut R17SignAdditionalContext| match unsafe {
        r17_read_v1(
            &registry,
            "sign_additional_context",
            ctx as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<R17SignAdditionalContext>() as CK_ULONG,
        )
    }
    .expect("sign-ctx stays typed under v1")
    .params
    {
        Some(CkMechanismParams::SignAdditionalContext(p)) => p,
        other => panic!("sign-ctx must stay typed under v1, got {other:?}"),
    };
    let mut context = [0xA1u8, 0xA2, 0xA3];
    let mut base = R17SignAdditionalContext {
        hedge_variant: 1,
        p_context: context.as_mut_ptr(),
        ul_context_len: 3,
    };
    let p = read(&mut base);
    assert_eq!((p.hedge_variant, p.hash.0), (1, 0));
    r17_assert_present_secret(&p.context, &p.context_presence, &context);
    base.ul_context_len = 0;
    let p = read(&mut base);
    r17_assert_present_secret(&p.context, &p.context_presence, &[]);
    base.p_context = std::ptr::null_mut();
    let p = read(&mut base);
    r17_assert_null_secret(&p.context, &p.context_presence, 0);
    base.ul_context_len = 3;
    let p = read(&mut base);
    r17_assert_null_secret(&p.context, &p.context_presence, 3);
    // Trailing-hash layout parses the hash alongside the matrix case.
    let mut hashed = R17HashSignAdditionalContext {
        hedge_variant: 2,
        p_context: std::ptr::null_mut(),
        ul_context_len: 5,
        hash: CkMechanismType::SHA256.0 as CK_ULONG,
    };
    match unsafe {
        r17_read_v1(
            &registry,
            "sign_additional_context",
            &mut hashed as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<R17HashSignAdditionalContext>() as CK_ULONG,
        )
    }
    .expect("hash sign-ctx stays typed under v1")
    .params
    {
        Some(CkMechanismParams::SignAdditionalContext(p)) => {
            assert_eq!((p.hedge_variant, p.hash), (2, CkMechanismType::SHA256));
            r17_assert_null_secret(&p.context, &p.context_presence, 5);
        }
        other => panic!("hash sign-ctx must stay typed under v1, got {other:?}"),
    }
}

/// R17 embedded-field matrix for `aes_cbc_encrypt_data` (single `data`
/// field; the IV is a fixed inline array, not a pointer).
#[test]
fn r17_matrix_aes_cbc_encrypt_data() {
    let registry = r17_registry();
    let read = |p: CK_BYTE_PTR, len: CK_ULONG| {
        let mut aes = CK_AES_CBC_ENCRYPT_DATA_PARAMS { iv: [0xA5; 16], pData: p, length: len };
        match unsafe {
            r17_read_v1(
                &registry,
                "aes_cbc_encrypt_data",
                &mut aes as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_AES_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
            )
        }
        .expect("AES-CBC-data stays typed under v1")
        .params
        {
            Some(CkMechanismParams::AesCbcEncryptData(p)) => p,
            other => panic!("AES-CBC-data must stay typed under v1, got {other:?}"),
        }
    };
    let mut data = [0xA2u8, 0xA3, 0xA4];
    let p = read(data.as_mut_ptr(), data.len() as CK_ULONG);
    assert_eq!(p.iv, [0xA5; 16]);
    r17_assert_present_secret(&p.data, &p.data_presence, &data);
    let p = read(data.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.data, &p.data_presence, &[]);
    let p = read(std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.data, &p.data_presence, 0);
    let p = read(std::ptr::null_mut(), 3);
    r17_assert_null_secret(&p.data, &p.data_presence, 3);
}

/// R17 embedded-field matrix for `des_cbc_encrypt_data`.
#[test]
fn r17_matrix_des_cbc_encrypt_data() {
    let registry = r17_registry();
    let read = |p: CK_BYTE_PTR, len: CK_ULONG| {
        let mut des = CK_DES_CBC_ENCRYPT_DATA_PARAMS { iv: [0xD5; 8], pData: p, length: len };
        match unsafe {
            r17_read_v1(
                &registry,
                "des_cbc_encrypt_data",
                &mut des as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_DES_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
            )
        }
        .expect("DES-CBC-data stays typed under v1")
        .params
        {
            Some(CkMechanismParams::DesCbcEncryptData(p)) => p,
            other => panic!("DES-CBC-data must stay typed under v1, got {other:?}"),
        }
    };
    let mut data = [0xD2u8, 0xD3];
    let p = read(data.as_mut_ptr(), data.len() as CK_ULONG);
    assert_eq!(p.iv, [0xD5; 8]);
    r17_assert_present_secret(&p.data, &p.data_presence, &data);
    let p = read(data.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.data, &p.data_presence, &[]);
    let p = read(std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.data, &p.data_presence, 0);
    let p = read(std::ptr::null_mut(), 2);
    r17_assert_null_secret(&p.data, &p.data_presence, 2);
}

/// R17 embedded-field matrix for `camellia_cbc_encrypt_data`.
#[test]
fn r17_matrix_camellia_cbc_encrypt_data() {
    let registry = r17_registry();
    let read = |p: CK_BYTE_PTR, len: CK_ULONG| {
        let mut camellia =
            CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS { iv: [0x25; 16], pData: p, length: len };
        match unsafe {
            r17_read_v1(
                &registry,
                "camellia_cbc_encrypt_data",
                &mut camellia as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
            )
        }
        .expect("Camellia-CBC-data stays typed under v1")
        .params
        {
            Some(CkMechanismParams::CamelliaCbcEncryptData(p)) => p,
            other => panic!("Camellia-CBC-data must stay typed under v1, got {other:?}"),
        }
    };
    let mut data = [0x22u8, 0x23, 0x24];
    let p = read(data.as_mut_ptr(), data.len() as CK_ULONG);
    assert_eq!(p.iv, [0x25; 16]);
    r17_assert_present_secret(&p.data, &p.data_presence, &data);
    let p = read(data.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.data, &p.data_presence, &[]);
    let p = read(std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.data, &p.data_presence, 0);
    let p = read(std::ptr::null_mut(), 3);
    r17_assert_null_secret(&p.data, &p.data_presence, 3);
}

/// R17 embedded-field matrix for `aria_cbc_encrypt_data`.
#[test]
fn r17_matrix_aria_cbc_encrypt_data() {
    let registry = r17_registry();
    let read = |p: CK_BYTE_PTR, len: CK_ULONG| {
        let mut aria = CK_ARIA_CBC_ENCRYPT_DATA_PARAMS { iv: [0x15; 16], pData: p, length: len };
        match unsafe {
            r17_read_v1(
                &registry,
                "aria_cbc_encrypt_data",
                &mut aria as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
            )
        }
        .expect("ARIA-CBC-data stays typed under v1")
        .params
        {
            Some(CkMechanismParams::AriaCbcEncryptData(p)) => p,
            other => panic!("ARIA-CBC-data must stay typed under v1, got {other:?}"),
        }
    };
    let mut data = [0x12u8, 0x13, 0x14, 0x15];
    let p = read(data.as_mut_ptr(), data.len() as CK_ULONG);
    assert_eq!(p.iv, [0x15; 16]);
    r17_assert_present_secret(&p.data, &p.data_presence, &data);
    let p = read(data.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.data, &p.data_presence, &[]);
    let p = read(std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.data, &p.data_presence, 0);
    let p = read(std::ptr::null_mut(), 4);
    r17_assert_null_secret(&p.data, &p.data_presence, 4);
}

/// R17 embedded-field matrix for `seed_cbc_encrypt_data`.
#[test]
fn r17_matrix_seed_cbc_encrypt_data() {
    let registry = r17_registry();
    let read = |p: CK_BYTE_PTR, len: CK_ULONG| {
        let mut seed = CK_SEED_CBC_ENCRYPT_DATA_PARAMS { iv: [0x35; 16], pData: p, length: len };
        match unsafe {
            r17_read_v1(
                &registry,
                "seed_cbc_encrypt_data",
                &mut seed as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_SEED_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
            )
        }
        .expect("SEED-CBC-data stays typed under v1")
        .params
        {
            Some(CkMechanismParams::SeedCbcEncryptData(p)) => p,
            other => panic!("SEED-CBC-data must stay typed under v1, got {other:?}"),
        }
    };
    let mut data = [0x32u8, 0x33];
    let p = read(data.as_mut_ptr(), data.len() as CK_ULONG);
    assert_eq!(p.iv, [0x35; 16]);
    r17_assert_present_secret(&p.data, &p.data_presence, &data);
    let p = read(data.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.data, &p.data_presence, &[]);
    let p = read(std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.data, &p.data_presence, 0);
    let p = read(std::ptr::null_mut(), 2);
    r17_assert_null_secret(&p.data, &p.data_presence, 2);
}

/// R17 embedded-field matrix for `gcm` (both fields × NULL/0, NULL/n,
/// ptr/0, ptr/n, plus both mixed directions).
#[test]
fn r17_matrix_gcm() {
    let registry = r17_registry();
    let read = |iv_p: CK_BYTE_PTR, iv_len: CK_ULONG, aad_p: CK_BYTE_PTR, aad_len: CK_ULONG| {
        let mut gcm = CK_GCM_PARAMS {
            pIv: iv_p,
            ulIvLen: iv_len,
            ulIvBits: 96,
            pAAD: aad_p,
            ulAADLen: aad_len,
            ulTagBits: 128,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "gcm",
                &mut gcm as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
            )
        }
        .expect("GCM stays typed under v1")
        .params
        {
            Some(CkMechanismParams::Gcm(p)) => p,
            other => panic!("GCM must stay typed under v1, got {other:?}"),
        }
    };
    let mut iv = [0x11u8; 12];
    let mut aad = [0xA1u8, 0xA2];
    // ptr/n × ptr/n.
    let p = read(iv.as_mut_ptr(), 12, aad.as_mut_ptr(), 2);
    assert!(!p.iv_null && !p.aad_null, "v1 is presence-only");
    r17_assert_present(&p.iv, &p.iv_presence, &iv);
    r17_assert_present_secret(&p.aad, &p.aad_presence, &aad);
    // ptr/0 × ptr/0.
    let p = read(iv.as_mut_ptr(), 0, aad.as_mut_ptr(), 0);
    r17_assert_present(&p.iv, &p.iv_presence, &[]);
    r17_assert_present_secret(&p.aad, &p.aad_presence, &[]);
    // NULL/0 × NULL/0.
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    assert!(!p.iv_null && !p.aad_null, "v1 is presence-only");
    r17_assert_null(&p.iv, &p.iv_presence, 0);
    r17_assert_null_secret(&p.aad, &p.aad_presence, 0);
    // NULL/n × NULL/m.
    let p = read(std::ptr::null_mut(), 12, std::ptr::null_mut(), 16);
    r17_assert_null(&p.iv, &p.iv_presence, 12);
    r17_assert_null_secret(&p.aad, &p.aad_presence, 16);
    // Mixed: valid IV + NULL AAD.
    let p = read(iv.as_mut_ptr(), 12, std::ptr::null_mut(), 16);
    r17_assert_present(&p.iv, &p.iv_presence, &iv);
    r17_assert_null_secret(&p.aad, &p.aad_presence, 16);
    // Mixed: NULL IV + valid AAD.
    let p = read(std::ptr::null_mut(), 12, aad.as_mut_ptr(), 2);
    r17_assert_null(&p.iv, &p.iv_presence, 12);
    r17_assert_present_secret(&p.aad, &p.aad_presence, &aad);
}

/// R17 embedded-field matrix for `ccm`.
#[test]
fn r17_matrix_ccm() {
    let registry = r17_registry();
    let read =
        |nonce_p: CK_BYTE_PTR, nonce_len: CK_ULONG, aad_p: CK_BYTE_PTR, aad_len: CK_ULONG| {
            let mut ccm = CK_CCM_PARAMS {
                ulDataLen: 32,
                pNonce: nonce_p,
                ulNonceLen: nonce_len,
                pAAD: aad_p,
                ulAADLen: aad_len,
                ulMACLen: 16,
            };
            match unsafe {
                r17_read_v1(
                    &registry,
                    "ccm",
                    &mut ccm as *mut _ as CK_VOID_PTR,
                    std::mem::size_of::<CK_CCM_PARAMS>() as CK_ULONG,
                )
            }
            .expect("CCM stays typed under v1")
            .params
            {
                Some(CkMechanismParams::Ccm(p)) => p,
                other => panic!("CCM must stay typed under v1, got {other:?}"),
            }
        };
    let mut nonce = [0x21u8; 12];
    let mut aad = [0xA3u8, 0xA4, 0xA5];
    let p = read(nonce.as_mut_ptr(), 12, aad.as_mut_ptr(), 3);
    assert!(!p.nonce_null && !p.aad_null, "v1 is presence-only");
    assert_eq!((p.data_len, p.mac_len), (32, 16));
    r17_assert_present(&p.nonce, &p.nonce_presence, &nonce);
    r17_assert_present_secret(&p.aad, &p.aad_presence, &aad);
    let p = read(nonce.as_mut_ptr(), 0, aad.as_mut_ptr(), 0);
    r17_assert_present(&p.nonce, &p.nonce_presence, &[]);
    r17_assert_present_secret(&p.aad, &p.aad_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    assert!(!p.nonce_null && !p.aad_null, "v1 is presence-only");
    r17_assert_null(&p.nonce, &p.nonce_presence, 0);
    r17_assert_null_secret(&p.aad, &p.aad_presence, 0);
    let p = read(std::ptr::null_mut(), 12, std::ptr::null_mut(), 3);
    r17_assert_null(&p.nonce, &p.nonce_presence, 12);
    r17_assert_null_secret(&p.aad, &p.aad_presence, 3);
    let p = read(nonce.as_mut_ptr(), 12, std::ptr::null_mut(), 3);
    r17_assert_present(&p.nonce, &p.nonce_presence, &nonce);
    r17_assert_null_secret(&p.aad, &p.aad_presence, 3);
    let p = read(std::ptr::null_mut(), 12, aad.as_mut_ptr(), 3);
    r17_assert_null(&p.nonce, &p.nonce_presence, 12);
    r17_assert_present_secret(&p.aad, &p.aad_presence, &aad);
}

/// R17 embedded-field matrix for `ecdh1_derive`.
#[test]
fn r17_matrix_ecdh1_derive() {
    let registry = r17_registry();
    let read =
        |shared_p: CK_BYTE_PTR, shared_len: CK_ULONG, pub_p: CK_BYTE_PTR, pub_len: CK_ULONG| {
            let mut ecdh = CK_ECDH1_DERIVE_PARAMS {
                kdf: 1,
                ulSharedDataLen: shared_len,
                pSharedData: shared_p,
                ulPublicDataLen: pub_len,
                pPublicData: pub_p,
            };
            match unsafe {
                r17_read_v1(
                    &registry,
                    "ecdh1_derive",
                    &mut ecdh as *mut _ as CK_VOID_PTR,
                    std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG,
                )
            }
            .expect("ECDH1 stays typed under v1")
            .params
            {
                Some(CkMechanismParams::Ecdh1Derive(p)) => p,
                other => panic!("ECDH1 must stay typed under v1, got {other:?}"),
            }
        };
    let mut shared = [0x31u8, 0x32];
    let mut public = [0x33u8; 65];
    let p = read(shared.as_mut_ptr(), 2, public.as_mut_ptr(), 65);
    r17_assert_present_secret(&p.shared_data, &p.shared_data_presence, &shared);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
    let p = read(shared.as_mut_ptr(), 0, public.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.shared_data, &p.shared_data_presence, &[]);
    r17_assert_present(&p.public_data, &p.public_data_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.shared_data, &p.shared_data_presence, 0);
    r17_assert_null(&p.public_data, &p.public_data_presence, 0);
    let p = read(std::ptr::null_mut(), 2, std::ptr::null_mut(), 65);
    r17_assert_null_secret(&p.shared_data, &p.shared_data_presence, 2);
    r17_assert_null(&p.public_data, &p.public_data_presence, 65);
    let p = read(shared.as_mut_ptr(), 2, std::ptr::null_mut(), 65);
    r17_assert_present_secret(&p.shared_data, &p.shared_data_presence, &shared);
    r17_assert_null(&p.public_data, &p.public_data_presence, 65);
    let p = read(std::ptr::null_mut(), 2, public.as_mut_ptr(), 65);
    r17_assert_null_secret(&p.shared_data, &p.shared_data_presence, 2);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
}

/// R17 embedded-field matrix for `hkdf`.
#[test]
fn r17_matrix_hkdf() {
    let registry = r17_registry();
    let read =
        |salt_p: CK_BYTE_PTR, salt_len: CK_ULONG, info_p: CK_BYTE_PTR, info_len: CK_ULONG| {
            let mut hkdf = CK_HKDF_PARAMS {
                bExtract: CK_TRUE,
                bExpand: CK_TRUE,
                prfHashMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
                ulSaltType: 0,
                pSalt: salt_p,
                ulSaltLen: salt_len,
                hSaltKey: 0,
                pInfo: info_p,
                ulInfoLen: info_len,
            };
            match unsafe {
                r17_read_v1(
                    &registry,
                    "hkdf",
                    &mut hkdf as *mut _ as CK_VOID_PTR,
                    std::mem::size_of::<CK_HKDF_PARAMS>() as CK_ULONG,
                )
            }
            .expect("HKDF stays typed under v1")
            .params
            {
                Some(CkMechanismParams::Hkdf(p)) => p,
                other => panic!("HKDF must stay typed under v1, got {other:?}"),
            }
        };
    let mut salt = [0x41u8; 32];
    let mut info = [0x42u8, 0x43];
    let p = read(salt.as_mut_ptr(), 32, info.as_mut_ptr(), 2);
    assert!(p.extract && p.expand);
    r17_assert_present_secret(&p.salt, &p.salt_presence, &salt);
    r17_assert_present_secret(&p.info, &p.info_presence, &info);
    let p = read(salt.as_mut_ptr(), 0, info.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.salt, &p.salt_presence, &[]);
    r17_assert_present_secret(&p.info, &p.info_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.salt, &p.salt_presence, 0);
    r17_assert_null_secret(&p.info, &p.info_presence, 0);
    let p = read(std::ptr::null_mut(), 32, std::ptr::null_mut(), 2);
    r17_assert_null_secret(&p.salt, &p.salt_presence, 32);
    r17_assert_null_secret(&p.info, &p.info_presence, 2);
    let p = read(salt.as_mut_ptr(), 32, std::ptr::null_mut(), 2);
    r17_assert_present_secret(&p.salt, &p.salt_presence, &salt);
    r17_assert_null_secret(&p.info, &p.info_presence, 2);
    let p = read(std::ptr::null_mut(), 32, info.as_mut_ptr(), 2);
    r17_assert_null_secret(&p.salt, &p.salt_presence, 32);
    r17_assert_present_secret(&p.info, &p.info_presence, &info);
}

/// R17 embedded-field matrix for `chacha20` (bits-governed lengths: a
/// NULL field records the derived byte length `div_ceil(bits, 8)`).
#[test]
fn r17_matrix_chacha20() {
    let registry = r17_registry();
    let read = |bc_p: CK_BYTE_PTR, bc_bits: CK_ULONG, n_p: CK_BYTE_PTR, n_bits: CK_ULONG| {
        let mut chacha = CK_CHACHA20_PARAMS {
            pBlockCounter: bc_p,
            blockCounterBits: bc_bits,
            pNonce: n_p,
            ulNonceBits: n_bits,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "chacha20",
                &mut chacha as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_CHACHA20_PARAMS>() as CK_ULONG,
            )
        }
        .expect("ChaCha20 stays typed under v1")
        .params
        {
            Some(CkMechanismParams::ChaCha20(p)) => p,
            other => panic!("ChaCha20 must stay typed under v1, got {other:?}"),
        }
    };
    let mut bc = [0x41u8; 4];
    let mut nonce = [0x42u8; 12];
    // ptr/n × ptr/n (32 bits = 4 bytes, 96 bits = 12 bytes).
    let p = read(bc.as_mut_ptr(), 32, nonce.as_mut_ptr(), 96);
    assert_eq!((p.block_counter_bits, p.nonce_bits), (32, 96));
    r17_assert_present(&p.block_counter, &p.block_counter_presence, &bc);
    r17_assert_present(&p.nonce, &p.nonce_presence, &nonce);
    // ptr/0-bits × ptr/0-bits: empty, Present.
    let p = read(bc.as_mut_ptr(), 0, nonce.as_mut_ptr(), 0);
    r17_assert_present(&p.block_counter, &p.block_counter_presence, &[]);
    r17_assert_present(&p.nonce, &p.nonce_presence, &[]);
    // NULL/0-bits × NULL/0-bits: Null{0}.
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null(&p.block_counter, &p.block_counter_presence, 0);
    r17_assert_null(&p.nonce, &p.nonce_presence, 0);
    // NULL/32-bits × NULL/96-bits: Null{derived bytes}.
    let p = read(std::ptr::null_mut(), 32, std::ptr::null_mut(), 96);
    r17_assert_null(&p.block_counter, &p.block_counter_presence, 4);
    r17_assert_null(&p.nonce, &p.nonce_presence, 12);
    // Mixed: valid counter + NULL nonce.
    let p = read(bc.as_mut_ptr(), 32, std::ptr::null_mut(), 96);
    r17_assert_present(&p.block_counter, &p.block_counter_presence, &bc);
    r17_assert_null(&p.nonce, &p.nonce_presence, 12);
    // Mixed: NULL counter + valid nonce.
    let p = read(std::ptr::null_mut(), 32, nonce.as_mut_ptr(), 96);
    r17_assert_null(&p.block_counter, &p.block_counter_presence, 4);
    r17_assert_present(&p.nonce, &p.nonce_presence, &nonce);
    // Non-multiple-of-8 bits round up (legacy `div_ceil` rule preserved).
    let mut bc9 = [0x43u8; 2];
    let p = read(bc9.as_mut_ptr(), 9, nonce.as_mut_ptr(), 96);
    r17_assert_present(&p.block_counter, &p.block_counter_presence, &bc9);
    let p = read(std::ptr::null_mut(), 9, std::ptr::null_mut(), 0);
    r17_assert_null(&p.block_counter, &p.block_counter_presence, 2);
    r17_assert_null(&p.nonce, &p.nonce_presence, 0);
}

/// R17 embedded-field matrix for `salsa20` (fixed 8-byte block counter
/// + bits-governed nonce: NULL records the fixed/derived extent).
#[test]
fn r17_matrix_salsa20() {
    let registry = r17_registry();
    let read = |bc_p: CK_BYTE_PTR, n_p: CK_BYTE_PTR, n_bits: CK_ULONG| {
        let mut salsa = CK_SALSA20_PARAMS { pBlockCounter: bc_p, pNonce: n_p, ulNonceBits: n_bits };
        match unsafe {
            r17_read_v1(
                &registry,
                "salsa20",
                &mut salsa as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_SALSA20_PARAMS>() as CK_ULONG,
            )
        }
        .expect("Salsa20 stays typed under v1")
        .params
        {
            Some(CkMechanismParams::Salsa20(p)) => p,
            other => panic!("Salsa20 must stay typed under v1, got {other:?}"),
        }
    };
    let mut bc = [0x11u8; 8];
    let mut nonce = [0x22u8; 8];
    let p = read(bc.as_mut_ptr(), nonce.as_mut_ptr(), 64);
    assert_eq!(p.nonce_bits, 64);
    r17_assert_present(&p.block_counter, &p.block_counter_presence, &bc);
    r17_assert_present(&p.nonce, &p.nonce_presence, &nonce);
    let p = read(bc.as_mut_ptr(), nonce.as_mut_ptr(), 0);
    r17_assert_present(&p.block_counter, &p.block_counter_presence, &bc);
    r17_assert_present(&p.nonce, &p.nonce_presence, &[]);
    let p = read(std::ptr::null_mut(), std::ptr::null_mut(), 0);
    r17_assert_null(&p.block_counter, &p.block_counter_presence, 8);
    r17_assert_null(&p.nonce, &p.nonce_presence, 0);
    let p = read(std::ptr::null_mut(), std::ptr::null_mut(), 64);
    r17_assert_null(&p.block_counter, &p.block_counter_presence, 8);
    r17_assert_null(&p.nonce, &p.nonce_presence, 8);
    let p = read(bc.as_mut_ptr(), std::ptr::null_mut(), 64);
    r17_assert_present(&p.block_counter, &p.block_counter_presence, &bc);
    r17_assert_null(&p.nonce, &p.nonce_presence, 8);
    let p = read(std::ptr::null_mut(), nonce.as_mut_ptr(), 64);
    r17_assert_null(&p.block_counter, &p.block_counter_presence, 8);
    r17_assert_present(&p.nonce, &p.nonce_presence, &nonce);
}

/// R17 embedded-field matrix for `salsa20_chacha20_poly1305`.
#[test]
fn r17_matrix_salsa20_chacha20_poly1305() {
    let registry = r17_registry();
    let read =
        |nonce_p: CK_BYTE_PTR, nonce_len: CK_ULONG, aad_p: CK_BYTE_PTR, aad_len: CK_ULONG| {
            let mut sp = CK_SALSA20_CHACHA20_POLY1305_PARAMS {
                pNonce: nonce_p,
                ulNonceLen: nonce_len,
                pAAD: aad_p,
                ulAADLen: aad_len,
            };
            match unsafe {
                r17_read_v1(
                    &registry,
                    "salsa20_chacha20_poly1305",
                    &mut sp as *mut _ as CK_VOID_PTR,
                    std::mem::size_of::<CK_SALSA20_CHACHA20_POLY1305_PARAMS>() as CK_ULONG,
                )
            }
            .expect("AEAD stays typed under v1")
            .params
            {
                Some(CkMechanismParams::Salsa20ChaCha20Poly1305(p)) => p,
                other => panic!("AEAD must stay typed under v1, got {other:?}"),
            }
        };
    let mut nonce = [0x51u8; 12];
    let mut aad = [0x52u8, 0x53];
    let p = read(nonce.as_mut_ptr(), 12, aad.as_mut_ptr(), 2);
    r17_assert_present(&p.nonce, &p.nonce_presence, &nonce);
    r17_assert_present_secret(&p.aad, &p.aad_presence, &aad);
    let p = read(nonce.as_mut_ptr(), 0, aad.as_mut_ptr(), 0);
    r17_assert_present(&p.nonce, &p.nonce_presence, &[]);
    r17_assert_present_secret(&p.aad, &p.aad_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null(&p.nonce, &p.nonce_presence, 0);
    r17_assert_null_secret(&p.aad, &p.aad_presence, 0);
    let p = read(std::ptr::null_mut(), 12, std::ptr::null_mut(), 2);
    r17_assert_null(&p.nonce, &p.nonce_presence, 12);
    r17_assert_null_secret(&p.aad, &p.aad_presence, 2);
    let p = read(nonce.as_mut_ptr(), 12, std::ptr::null_mut(), 2);
    r17_assert_present(&p.nonce, &p.nonce_presence, &nonce);
    r17_assert_null_secret(&p.aad, &p.aad_presence, 2);
    let p = read(std::ptr::null_mut(), 12, aad.as_mut_ptr(), 2);
    r17_assert_null(&p.nonce, &p.nonce_presence, 12);
    r17_assert_present_secret(&p.aad, &p.aad_presence, &aad);
}

/// R17 embedded-field matrix for `mu_gen`.
#[test]
fn r17_matrix_mu_gen() {
    let registry = r17_registry();
    let read = |tr_p: CK_BYTE_PTR, tr_len: CK_ULONG, ctx_p: CK_BYTE_PTR, ctx_len: CK_ULONG| {
        let mut mu = super::CkMuGenParams {
            h_key: 9,
            p_tr: tr_p,
            ul_tr_len: tr_len,
            p_ctx: ctx_p,
            ul_ctx_len: ctx_len,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "mu_gen",
                &mut mu as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<super::CkMuGenParams>() as CK_ULONG,
            )
        }
        .expect("mu-gen stays typed under v1")
        .params
        {
            Some(CkMechanismParams::MuGen(p)) => p,
            other => panic!("mu-gen must stay typed under v1, got {other:?}"),
        }
    };
    let mut tr = [0x61u8; 64];
    let mut ctx = [0x62u8, 0x63];
    let p = read(tr.as_mut_ptr(), 64, ctx.as_mut_ptr(), 2);
    assert_eq!(p.key_handle.0, 9);
    r17_assert_present_secret(&p.tr, &p.tr_presence, &tr);
    r17_assert_present_secret(&p.context, &p.context_presence, &ctx);
    let p = read(tr.as_mut_ptr(), 0, ctx.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.tr, &p.tr_presence, &[]);
    r17_assert_present_secret(&p.context, &p.context_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.tr, &p.tr_presence, 0);
    r17_assert_null_secret(&p.context, &p.context_presence, 0);
    let p = read(std::ptr::null_mut(), 64, std::ptr::null_mut(), 2);
    r17_assert_null_secret(&p.tr, &p.tr_presence, 64);
    r17_assert_null_secret(&p.context, &p.context_presence, 2);
    let p = read(tr.as_mut_ptr(), 64, std::ptr::null_mut(), 2);
    r17_assert_present_secret(&p.tr, &p.tr_presence, &tr);
    r17_assert_null_secret(&p.context, &p.context_presence, 2);
    let p = read(std::ptr::null_mut(), 64, ctx.as_mut_ptr(), 2);
    r17_assert_null_secret(&p.tr, &p.tr_presence, 64);
    r17_assert_present_secret(&p.context, &p.context_presence, &ctx);
}

/// R17 embedded-field matrix for `x942_dh1_derive`.
#[test]
fn r17_matrix_x942_dh1_derive() {
    let registry = r17_registry();
    let read = |oi_p: CK_BYTE_PTR, oi_len: CK_ULONG, pub_p: CK_BYTE_PTR, pub_len: CK_ULONG| {
        let mut dh = CK_X9_42_DH1_DERIVE_PARAMS {
            kdf: 11,
            ulOtherInfoLen: oi_len,
            pOtherInfo: oi_p,
            ulPublicDataLen: pub_len,
            pPublicData: pub_p,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "x942_dh1_derive",
                &mut dh as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_X9_42_DH1_DERIVE_PARAMS>() as CK_ULONG,
            )
        }
        .expect("X9.42-DH1 stays typed under v1")
        .params
        {
            Some(CkMechanismParams::X942Dh1Derive(p)) => p,
            other => panic!("X9.42-DH1 must stay typed under v1, got {other:?}"),
        }
    };
    let mut oi = [0x71u8, 0x72];
    let mut public = [0x73u8; 65];
    let p = read(oi.as_mut_ptr(), 2, public.as_mut_ptr(), 65);
    r17_assert_present_secret(&p.other_info, &p.other_info_presence, &oi);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
    let p = read(oi.as_mut_ptr(), 0, public.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.other_info, &p.other_info_presence, &[]);
    r17_assert_present(&p.public_data, &p.public_data_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.other_info, &p.other_info_presence, 0);
    r17_assert_null(&p.public_data, &p.public_data_presence, 0);
    let p = read(std::ptr::null_mut(), 2, std::ptr::null_mut(), 65);
    r17_assert_null_secret(&p.other_info, &p.other_info_presence, 2);
    r17_assert_null(&p.public_data, &p.public_data_presence, 65);
    let p = read(oi.as_mut_ptr(), 2, std::ptr::null_mut(), 65);
    r17_assert_present_secret(&p.other_info, &p.other_info_presence, &oi);
    r17_assert_null(&p.public_data, &p.public_data_presence, 65);
    let p = read(std::ptr::null_mut(), 2, public.as_mut_ptr(), 65);
    r17_assert_null_secret(&p.other_info, &p.other_info_presence, 2);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
}

/// R17 embedded-field matrix for `gostr3410_derive`.
#[test]
fn r17_matrix_gostr3410_derive() {
    let registry = r17_registry();
    let read = |pub_p: CK_BYTE_PTR, pub_len: CK_ULONG, ukm_p: CK_BYTE_PTR, ukm_len: CK_ULONG| {
        let mut gost = CK_GOSTR3410_DERIVE_PARAMS {
            kdf: 1,
            pPublicData: pub_p,
            ulPublicDataLen: pub_len,
            pUKM: ukm_p,
            ulUKMLen: ukm_len,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "gostr3410_derive",
                &mut gost as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GOSTR3410_DERIVE_PARAMS>() as CK_ULONG,
            )
        }
        .expect("GOST-derive stays typed under v1")
        .params
        {
            Some(CkMechanismParams::Gostr3410Derive(p)) => p,
            other => panic!("GOST-derive must stay typed under v1, got {other:?}"),
        }
    };
    let mut public = [0x74u8; 64];
    let mut ukm = [0x75u8, 0x76];
    let p = read(public.as_mut_ptr(), 64, ukm.as_mut_ptr(), 2);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
    r17_assert_present(&p.ukm, &p.ukm_presence, &ukm);
    let p = read(public.as_mut_ptr(), 0, ukm.as_mut_ptr(), 0);
    r17_assert_present(&p.public_data, &p.public_data_presence, &[]);
    r17_assert_present(&p.ukm, &p.ukm_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null(&p.public_data, &p.public_data_presence, 0);
    r17_assert_null(&p.ukm, &p.ukm_presence, 0);
    let p = read(std::ptr::null_mut(), 64, std::ptr::null_mut(), 2);
    r17_assert_null(&p.public_data, &p.public_data_presence, 64);
    r17_assert_null(&p.ukm, &p.ukm_presence, 2);
    let p = read(public.as_mut_ptr(), 64, std::ptr::null_mut(), 2);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
    r17_assert_null(&p.ukm, &p.ukm_presence, 2);
    let p = read(std::ptr::null_mut(), 64, ukm.as_mut_ptr(), 2);
    r17_assert_null(&p.public_data, &p.public_data_presence, 64);
    r17_assert_present(&p.ukm, &p.ukm_presence, &ukm);
}

/// R17 embedded-field matrix for `gostr3410_key_wrap`.
#[test]
fn r17_matrix_gostr3410_key_wrap() {
    let registry = r17_registry();
    let read = |oid_p: CK_BYTE_PTR, oid_len: CK_ULONG, ukm_p: CK_BYTE_PTR, ukm_len: CK_ULONG| {
        let mut wrap = CK_GOSTR3410_KEY_WRAP_PARAMS {
            pWrapOID: oid_p,
            ulWrapOIDLen: oid_len,
            pUKM: ukm_p,
            ulUKMLen: ukm_len,
            hKey: 0xBEEF,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "gostr3410_key_wrap",
                &mut wrap as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GOSTR3410_KEY_WRAP_PARAMS>() as CK_ULONG,
            )
        }
        .expect("GOST-wrap stays typed under v1")
        .params
        {
            Some(CkMechanismParams::Gostr3410KeyWrap(p)) => p,
            other => panic!("GOST-wrap must stay typed under v1, got {other:?}"),
        }
    };
    let mut oid = [0x77u8, 0x78, 0x79];
    let mut ukm = [0x7Au8, 0x7B];
    let p = read(oid.as_mut_ptr(), 3, ukm.as_mut_ptr(), 2);
    assert_eq!(p.key_handle.0, 0xBEEF);
    r17_assert_present(&p.wrap_oid, &p.wrap_oid_presence, &oid);
    r17_assert_present(&p.ukm, &p.ukm_presence, &ukm);
    let p = read(oid.as_mut_ptr(), 0, ukm.as_mut_ptr(), 0);
    r17_assert_present(&p.wrap_oid, &p.wrap_oid_presence, &[]);
    r17_assert_present(&p.ukm, &p.ukm_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null(&p.wrap_oid, &p.wrap_oid_presence, 0);
    r17_assert_null(&p.ukm, &p.ukm_presence, 0);
    let p = read(std::ptr::null_mut(), 3, std::ptr::null_mut(), 2);
    r17_assert_null(&p.wrap_oid, &p.wrap_oid_presence, 3);
    r17_assert_null(&p.ukm, &p.ukm_presence, 2);
    let p = read(oid.as_mut_ptr(), 3, std::ptr::null_mut(), 2);
    r17_assert_present(&p.wrap_oid, &p.wrap_oid_presence, &oid);
    r17_assert_null(&p.ukm, &p.ukm_presence, 2);
    let p = read(std::ptr::null_mut(), 3, ukm.as_mut_ptr(), 2);
    r17_assert_null(&p.wrap_oid, &p.wrap_oid_presence, 3);
    r17_assert_present(&p.ukm, &p.ukm_presence, &ukm);
}

/// R17 embedded-field matrix for `ike_prf_derive`.
#[test]
fn r17_matrix_ike_prf_derive() {
    let registry = r17_registry();
    let read = |ni_p: CK_BYTE_PTR, ni_len: CK_ULONG, nr_p: CK_BYTE_PTR, nr_len: CK_ULONG| {
        let mut ike = CK_IKE_PRF_DERIVE_PARAMS {
            prfMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            bDataAsKey: CK_FALSE,
            bRekey: CK_FALSE,
            ulNiLen: ni_len,
            pNi: ni_p,
            ulNrLen: nr_len,
            pNr: nr_p,
            hNewKey: 0,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "ike_prf_derive",
                &mut ike as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_IKE_PRF_DERIVE_PARAMS>() as CK_ULONG,
            )
        }
        .expect("IKE-PRF stays typed under v1")
        .params
        {
            Some(CkMechanismParams::IkePrfDerive(p)) => p,
            other => panic!("IKE-PRF must stay typed under v1, got {other:?}"),
        }
    };
    let mut ni = [0x81u8, 0x82];
    let mut nr = [0x83u8, 0x84];
    let p = read(ni.as_mut_ptr(), 2, nr.as_mut_ptr(), 2);
    r17_assert_present_secret(&p.ni, &p.ni_presence, &ni);
    r17_assert_present_secret(&p.nr, &p.nr_presence, &nr);
    let p = read(ni.as_mut_ptr(), 0, nr.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.ni, &p.ni_presence, &[]);
    r17_assert_present_secret(&p.nr, &p.nr_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.ni, &p.ni_presence, 0);
    r17_assert_null_secret(&p.nr, &p.nr_presence, 0);
    let p = read(std::ptr::null_mut(), 2, std::ptr::null_mut(), 2);
    r17_assert_null_secret(&p.ni, &p.ni_presence, 2);
    r17_assert_null_secret(&p.nr, &p.nr_presence, 2);
    let p = read(ni.as_mut_ptr(), 2, std::ptr::null_mut(), 2);
    r17_assert_present_secret(&p.ni, &p.ni_presence, &ni);
    r17_assert_null_secret(&p.nr, &p.nr_presence, 2);
    let p = read(std::ptr::null_mut(), 2, nr.as_mut_ptr(), 2);
    r17_assert_null_secret(&p.ni, &p.ni_presence, 2);
    r17_assert_present_secret(&p.nr, &p.nr_presence, &nr);
}

/// R17 embedded-field matrix for `ike1_prf_derive`.
#[test]
fn r17_matrix_ike1_prf_derive() {
    let registry = r17_registry();
    let read = |yi_p: CK_BYTE_PTR, yi_len: CK_ULONG, yr_p: CK_BYTE_PTR, yr_len: CK_ULONG| {
        let mut ike = CK_IKE1_PRF_DERIVE_PARAMS {
            prfMechanism: CkMechanismType::SHA384.0 as CK_MECHANISM_TYPE,
            bHasPrevKey: CK_TRUE,
            hKeygxy: 0x2345,
            hPrevKey: 0x3456,
            pCKYi: yi_p,
            ulCKYiLen: yi_len,
            pCKYr: yr_p,
            ulCKYrLen: yr_len,
            keyNumber: 3,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "ike1_prf_derive",
                &mut ike as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_IKE1_PRF_DERIVE_PARAMS>() as CK_ULONG,
            )
        }
        .expect("IKE1-PRF stays typed under v1")
        .params
        {
            Some(CkMechanismParams::Ike1PrfDerive(p)) => p,
            other => panic!("IKE1-PRF must stay typed under v1, got {other:?}"),
        }
    };
    let mut ckyi = [0x85u8; 8];
    let mut ckyr = [0x86u8; 8];
    let p = read(ckyi.as_mut_ptr(), 8, ckyr.as_mut_ptr(), 8);
    assert_eq!(p.key_number, 3);
    r17_assert_present_secret(&p.ckyi, &p.ckyi_presence, &ckyi);
    r17_assert_present_secret(&p.ckyr, &p.ckyr_presence, &ckyr);
    let p = read(ckyi.as_mut_ptr(), 0, ckyr.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.ckyi, &p.ckyi_presence, &[]);
    r17_assert_present_secret(&p.ckyr, &p.ckyr_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.ckyi, &p.ckyi_presence, 0);
    r17_assert_null_secret(&p.ckyr, &p.ckyr_presence, 0);
    let p = read(std::ptr::null_mut(), 8, std::ptr::null_mut(), 8);
    r17_assert_null_secret(&p.ckyi, &p.ckyi_presence, 8);
    r17_assert_null_secret(&p.ckyr, &p.ckyr_presence, 8);
    let p = read(ckyi.as_mut_ptr(), 8, std::ptr::null_mut(), 8);
    r17_assert_present_secret(&p.ckyi, &p.ckyi_presence, &ckyi);
    r17_assert_null_secret(&p.ckyr, &p.ckyr_presence, 8);
    let p = read(std::ptr::null_mut(), 8, ckyr.as_mut_ptr(), 8);
    r17_assert_null_secret(&p.ckyi, &p.ckyi_presence, 8);
    r17_assert_present_secret(&p.ckyr, &p.ckyr_presence, &ckyr);
}

/// R17 embedded-field matrix for `ecdh2_derive` (three fields; the two
/// mixed cases pin each direction plus a double-NULL mix).
#[test]
fn r17_matrix_ecdh2_derive() {
    let registry = r17_registry();
    let read = |s_p: CK_BYTE_PTR,
                s_len: CK_ULONG,
                p_p: CK_BYTE_PTR,
                p_len: CK_ULONG,
                p2_p: CK_BYTE_PTR,
                p2_len: CK_ULONG| {
        let mut ecdh = CK_ECDH2_DERIVE_PARAMS {
            kdf: 1,
            ulSharedDataLen: s_len,
            pSharedData: s_p,
            ulPublicDataLen: p_len,
            pPublicData: p_p,
            ulPrivateDataLen: 0,
            hPrivateData: 0,
            ulPublicDataLen2: p2_len,
            pPublicData2: p2_p,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "ecdh2_derive",
                &mut ecdh as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_ECDH2_DERIVE_PARAMS>() as CK_ULONG,
            )
        }
        .expect("ECDH2 stays typed under v1")
        .params
        {
            Some(CkMechanismParams::Ecdh2Derive(p)) => p,
            other => panic!("ECDH2 must stay typed under v1, got {other:?}"),
        }
    };
    let mut shared = [0x91u8, 0x92];
    let mut public = [0x93u8; 65];
    let mut public2 = [0x94u8; 65];
    let p = read(shared.as_mut_ptr(), 2, public.as_mut_ptr(), 65, public2.as_mut_ptr(), 65);
    r17_assert_present_secret(&p.shared_data, &p.shared_data_presence, &shared);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
    r17_assert_present(&p.public_data2, &p.public_data2_presence, &public2);
    let p = read(shared.as_mut_ptr(), 0, public.as_mut_ptr(), 0, public2.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.shared_data, &p.shared_data_presence, &[]);
    r17_assert_present(&p.public_data, &p.public_data_presence, &[]);
    r17_assert_present(&p.public_data2, &p.public_data2_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.shared_data, &p.shared_data_presence, 0);
    r17_assert_null(&p.public_data, &p.public_data_presence, 0);
    r17_assert_null(&p.public_data2, &p.public_data2_presence, 0);
    let p = read(std::ptr::null_mut(), 2, std::ptr::null_mut(), 65, std::ptr::null_mut(), 65);
    r17_assert_null_secret(&p.shared_data, &p.shared_data_presence, 2);
    r17_assert_null(&p.public_data, &p.public_data_presence, 65);
    r17_assert_null(&p.public_data2, &p.public_data2_presence, 65);
    // Mixed: valid shared/public + NULL public2.
    let p = read(shared.as_mut_ptr(), 2, public.as_mut_ptr(), 65, std::ptr::null_mut(), 65);
    r17_assert_present_secret(&p.shared_data, &p.shared_data_presence, &shared);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
    r17_assert_null(&p.public_data2, &p.public_data2_presence, 65);
    // Mixed: NULL shared + valid public/public2.
    let p = read(std::ptr::null_mut(), 2, public.as_mut_ptr(), 65, public2.as_mut_ptr(), 65);
    r17_assert_null_secret(&p.shared_data, &p.shared_data_presence, 2);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
    r17_assert_present(&p.public_data2, &p.public_data2_presence, &public2);
    // Mixed: NULL shared/public + valid public2.
    let p = read(std::ptr::null_mut(), 2, std::ptr::null_mut(), 65, public2.as_mut_ptr(), 65);
    r17_assert_null_secret(&p.shared_data, &p.shared_data_presence, 2);
    r17_assert_null(&p.public_data, &p.public_data_presence, 65);
    r17_assert_present(&p.public_data2, &p.public_data2_presence, &public2);
}

/// R17 embedded-field matrix for `ecmqv_derive`.
#[test]
fn r17_matrix_ecmqv_derive() {
    let registry = r17_registry();
    let read = |s_p: CK_BYTE_PTR,
                s_len: CK_ULONG,
                p_p: CK_BYTE_PTR,
                p_len: CK_ULONG,
                p2_p: CK_BYTE_PTR,
                p2_len: CK_ULONG| {
        let mut ecmqv = CK_ECMQV_DERIVE_PARAMS {
            kdf: 1,
            ulSharedDataLen: s_len,
            pSharedData: s_p,
            ulPublicDataLen: p_len,
            pPublicData: p_p,
            ulPrivateDataLen: 0,
            hPrivateData: 0,
            ulPublicDataLen2: p2_len,
            pPublicData2: p2_p,
            publicKey: 0x51,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "ecmqv_derive",
                &mut ecmqv as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_ECMQV_DERIVE_PARAMS>() as CK_ULONG,
            )
        }
        .expect("ECMQV stays typed under v1")
        .params
        {
            Some(CkMechanismParams::EcmqvDerive(p)) => p,
            other => panic!("ECMQV must stay typed under v1, got {other:?}"),
        }
    };
    let mut shared = [0xA1u8, 0xA2];
    let mut public = [0xA3u8; 65];
    let mut public2 = [0xA4u8; 65];
    let p = read(shared.as_mut_ptr(), 2, public.as_mut_ptr(), 65, public2.as_mut_ptr(), 65);
    assert_eq!(p.public_key_handle.0, 0x51);
    r17_assert_present_secret(&p.shared_data, &p.shared_data_presence, &shared);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
    r17_assert_present(&p.public_data2, &p.public_data2_presence, &public2);
    let p = read(shared.as_mut_ptr(), 0, public.as_mut_ptr(), 0, public2.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.shared_data, &p.shared_data_presence, &[]);
    r17_assert_present(&p.public_data, &p.public_data_presence, &[]);
    r17_assert_present(&p.public_data2, &p.public_data2_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.shared_data, &p.shared_data_presence, 0);
    r17_assert_null(&p.public_data, &p.public_data_presence, 0);
    r17_assert_null(&p.public_data2, &p.public_data2_presence, 0);
    let p = read(std::ptr::null_mut(), 2, std::ptr::null_mut(), 65, std::ptr::null_mut(), 65);
    r17_assert_null_secret(&p.shared_data, &p.shared_data_presence, 2);
    r17_assert_null(&p.public_data, &p.public_data_presence, 65);
    r17_assert_null(&p.public_data2, &p.public_data2_presence, 65);
    let p = read(shared.as_mut_ptr(), 2, public.as_mut_ptr(), 65, std::ptr::null_mut(), 65);
    r17_assert_present_secret(&p.shared_data, &p.shared_data_presence, &shared);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
    r17_assert_null(&p.public_data2, &p.public_data2_presence, 65);
    let p = read(std::ptr::null_mut(), 2, public.as_mut_ptr(), 65, public2.as_mut_ptr(), 65);
    r17_assert_null_secret(&p.shared_data, &p.shared_data_presence, 2);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
    r17_assert_present(&p.public_data2, &p.public_data2_presence, &public2);
}

/// R17 embedded-field matrix for `x942_dh2_derive`.
#[test]
fn r17_matrix_x942_dh2_derive() {
    let registry = r17_registry();
    let read = |o_p: CK_BYTE_PTR,
                o_len: CK_ULONG,
                p_p: CK_BYTE_PTR,
                p_len: CK_ULONG,
                p2_p: CK_BYTE_PTR,
                p2_len: CK_ULONG| {
        let mut dh = CK_X9_42_DH2_DERIVE_PARAMS {
            kdf: 11,
            ulOtherInfoLen: o_len,
            pOtherInfo: o_p,
            ulPublicDataLen: p_len,
            pPublicData: p_p,
            ulPrivateDataLen: 0,
            hPrivateData: 0,
            ulPublicDataLen2: p2_len,
            pPublicData2: p2_p,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "x942_dh2_derive",
                &mut dh as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_X9_42_DH2_DERIVE_PARAMS>() as CK_ULONG,
            )
        }
        .expect("X9.42-DH2 stays typed under v1")
        .params
        {
            Some(CkMechanismParams::X942Dh2Derive(p)) => p,
            other => panic!("X9.42-DH2 must stay typed under v1, got {other:?}"),
        }
    };
    let mut oi = [0xB1u8, 0xB2];
    let mut public = [0xB3u8; 65];
    let mut public2 = [0xB4u8; 65];
    let p = read(oi.as_mut_ptr(), 2, public.as_mut_ptr(), 65, public2.as_mut_ptr(), 65);
    r17_assert_present_secret(&p.other_info, &p.other_info_presence, &oi);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
    r17_assert_present(&p.public_data2, &p.public_data2_presence, &public2);
    let p = read(oi.as_mut_ptr(), 0, public.as_mut_ptr(), 0, public2.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.other_info, &p.other_info_presence, &[]);
    r17_assert_present(&p.public_data, &p.public_data_presence, &[]);
    r17_assert_present(&p.public_data2, &p.public_data2_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.other_info, &p.other_info_presence, 0);
    r17_assert_null(&p.public_data, &p.public_data_presence, 0);
    r17_assert_null(&p.public_data2, &p.public_data2_presence, 0);
    let p = read(std::ptr::null_mut(), 2, std::ptr::null_mut(), 65, std::ptr::null_mut(), 65);
    r17_assert_null_secret(&p.other_info, &p.other_info_presence, 2);
    r17_assert_null(&p.public_data, &p.public_data_presence, 65);
    r17_assert_null(&p.public_data2, &p.public_data2_presence, 65);
    let p = read(oi.as_mut_ptr(), 2, public.as_mut_ptr(), 65, std::ptr::null_mut(), 65);
    r17_assert_present_secret(&p.other_info, &p.other_info_presence, &oi);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
    r17_assert_null(&p.public_data2, &p.public_data2_presence, 65);
    let p = read(std::ptr::null_mut(), 2, public.as_mut_ptr(), 65, public2.as_mut_ptr(), 65);
    r17_assert_null_secret(&p.other_info, &p.other_info_presence, 2);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
    r17_assert_present(&p.public_data2, &p.public_data2_presence, &public2);
}

/// R17 embedded-field matrix for `x942_mqv_derive` (note the
/// non-`p`-prefixed MQV field names).
#[test]
fn r17_matrix_x942_mqv_derive() {
    let registry = r17_registry();
    let read = |o_p: CK_BYTE_PTR,
                o_len: CK_ULONG,
                p_p: CK_BYTE_PTR,
                p_len: CK_ULONG,
                p2_p: CK_BYTE_PTR,
                p2_len: CK_ULONG| {
        let mut mqv = CK_X9_42_MQV_DERIVE_PARAMS {
            kdf: 11,
            ulOtherInfoLen: o_len,
            OtherInfo: o_p,
            ulPublicDataLen: p_len,
            PublicData: p_p,
            ulPrivateDataLen: 0,
            hPrivateData: 0,
            ulPublicDataLen2: p2_len,
            PublicData2: p2_p,
            publicKey: 0x61,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "x942_mqv_derive",
                &mut mqv as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_X9_42_MQV_DERIVE_PARAMS>() as CK_ULONG,
            )
        }
        .expect("X9.42-MQV stays typed under v1")
        .params
        {
            Some(CkMechanismParams::X942MqvDerive(p)) => p,
            other => panic!("X9.42-MQV must stay typed under v1, got {other:?}"),
        }
    };
    let mut oi = [0xC1u8, 0xC2];
    let mut public = [0xC3u8; 65];
    let mut public2 = [0xC4u8; 65];
    let p = read(oi.as_mut_ptr(), 2, public.as_mut_ptr(), 65, public2.as_mut_ptr(), 65);
    assert_eq!(p.public_key_handle.0, 0x61);
    r17_assert_present_secret(&p.other_info, &p.other_info_presence, &oi);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
    r17_assert_present(&p.public_data2, &p.public_data2_presence, &public2);
    let p = read(oi.as_mut_ptr(), 0, public.as_mut_ptr(), 0, public2.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.other_info, &p.other_info_presence, &[]);
    r17_assert_present(&p.public_data, &p.public_data_presence, &[]);
    r17_assert_present(&p.public_data2, &p.public_data2_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.other_info, &p.other_info_presence, 0);
    r17_assert_null(&p.public_data, &p.public_data_presence, 0);
    r17_assert_null(&p.public_data2, &p.public_data2_presence, 0);
    let p = read(std::ptr::null_mut(), 2, std::ptr::null_mut(), 65, std::ptr::null_mut(), 65);
    r17_assert_null_secret(&p.other_info, &p.other_info_presence, 2);
    r17_assert_null(&p.public_data, &p.public_data_presence, 65);
    r17_assert_null(&p.public_data2, &p.public_data2_presence, 65);
    let p = read(oi.as_mut_ptr(), 2, public.as_mut_ptr(), 65, std::ptr::null_mut(), 65);
    r17_assert_present_secret(&p.other_info, &p.other_info_presence, &oi);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
    r17_assert_null(&p.public_data2, &p.public_data2_presence, 65);
    let p = read(std::ptr::null_mut(), 2, public.as_mut_ptr(), 65, public2.as_mut_ptr(), 65);
    r17_assert_null_secret(&p.other_info, &p.other_info_presence, 2);
    r17_assert_present(&p.public_data, &p.public_data_presence, &public);
    r17_assert_present(&p.public_data2, &p.public_data2_presence, &public2);
}

/// R17 embedded-field matrix for `pkcs5_pbkd2` (three fields).
#[test]
fn r17_matrix_pkcs5_pbkd2() {
    let registry = r17_registry();
    let read = |s_p: CK_VOID_PTR,
                s_len: CK_ULONG,
                d_p: CK_VOID_PTR,
                d_len: CK_ULONG,
                w_p: CK_BYTE_PTR,
                w_len: CK_ULONG| {
        let mut pbkd2 = CK_PKCS5_PBKD2_PARAMS2 {
            saltSource: 1,
            pSaltSourceData: s_p,
            ulSaltSourceDataLen: s_len,
            iterations: 600_000,
            prf: 2,
            pPrfData: d_p,
            ulPrfDataLen: d_len,
            pPassword: w_p,
            ulPasswordLen: w_len,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "pkcs5_pbkd2",
                &mut pbkd2 as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_PKCS5_PBKD2_PARAMS2>() as CK_ULONG,
            )
        }
        .expect("PBKD2 stays typed under v1")
        .params
        {
            Some(CkMechanismParams::Pkcs5Pbkd2(p)) => p,
            other => panic!("PBKD2 must stay typed under v1, got {other:?}"),
        }
    };
    let mut salt = [0x41u8, 0x42];
    let mut prf = [0x51u8];
    let mut password = [0x73u8, 0x65, 0x63, 0x72, 0x65, 0x74];
    let void = |p: *mut u8| p as CK_VOID_PTR;
    let p = read(void(salt.as_mut_ptr()), 2, void(prf.as_mut_ptr()), 1, password.as_mut_ptr(), 6);
    assert_eq!(p.iterations, 600_000);
    r17_assert_present_secret(&p.salt_source_data, &p.salt_source_data_presence, &salt);
    r17_assert_present_secret(&p.prf_data, &p.prf_data_presence, &prf);
    r17_assert_present_secret(&p.password, &p.password_presence, &password);
    let p = read(void(salt.as_mut_ptr()), 0, void(prf.as_mut_ptr()), 0, password.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.salt_source_data, &p.salt_source_data_presence, &[]);
    r17_assert_present_secret(&p.prf_data, &p.prf_data_presence, &[]);
    r17_assert_present_secret(&p.password, &p.password_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.salt_source_data, &p.salt_source_data_presence, 0);
    r17_assert_null_secret(&p.prf_data, &p.prf_data_presence, 0);
    r17_assert_null_secret(&p.password, &p.password_presence, 0);
    let p = read(std::ptr::null_mut(), 2, std::ptr::null_mut(), 1, std::ptr::null_mut(), 6);
    r17_assert_null_secret(&p.salt_source_data, &p.salt_source_data_presence, 2);
    r17_assert_null_secret(&p.prf_data, &p.prf_data_presence, 1);
    r17_assert_null_secret(&p.password, &p.password_presence, 6);
    // Mixed: valid salt/prf + NULL password.
    let p = read(void(salt.as_mut_ptr()), 2, void(prf.as_mut_ptr()), 1, std::ptr::null_mut(), 6);
    r17_assert_present_secret(&p.salt_source_data, &p.salt_source_data_presence, &salt);
    r17_assert_present_secret(&p.prf_data, &p.prf_data_presence, &prf);
    r17_assert_null_secret(&p.password, &p.password_presence, 6);
    // Mixed: NULL salt + valid prf/password.
    let p = read(std::ptr::null_mut(), 2, void(prf.as_mut_ptr()), 1, password.as_mut_ptr(), 6);
    r17_assert_null_secret(&p.salt_source_data, &p.salt_source_data_presence, 2);
    r17_assert_present_secret(&p.prf_data, &p.prf_data_presence, &prf);
    r17_assert_present_secret(&p.password, &p.password_presence, &password);
}

/// R17 embedded-field matrix for `pbe` (fixed 8-byte IV + two
/// length-governed fields: NULL IV records the fixed extent 8).
#[test]
fn r17_matrix_pbe() {
    let registry = r17_registry();
    let read = |iv_p: CK_BYTE_PTR,
                w_p: CK_BYTE_PTR,
                w_len: CK_ULONG,
                s_p: CK_BYTE_PTR,
                s_len: CK_ULONG| {
        let mut pbe = CK_PBE_PARAMS {
            pInitVector: iv_p,
            pPassword: w_p,
            ulPasswordLen: w_len,
            pSalt: s_p,
            ulSaltLen: s_len,
            ulIteration: 1,
        };
        match unsafe {
            r17_read_v1(
                &registry,
                "pbe",
                &mut pbe as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_PBE_PARAMS>() as CK_ULONG,
            )
        }
        .expect("PBE stays typed under v1")
        .params
        {
            Some(CkMechanismParams::Pbe(p)) => p,
            other => panic!("PBE must stay typed under v1, got {other:?}"),
        }
    };
    let mut iv = [0xD1u8; 8];
    let mut password = [0xD2u8, 0xD3];
    let mut salt = [0xD4u8; 8];
    let p = read(iv.as_mut_ptr(), password.as_mut_ptr(), 2, salt.as_mut_ptr(), 8);
    assert_eq!(p.iteration, 1);
    r17_assert_present_secret(&p.init_vector, &p.init_vector_presence, &iv);
    r17_assert_present_secret(&p.password, &p.password_presence, &password);
    r17_assert_present_secret(&p.salt, &p.salt_presence, &salt);
    let p = read(iv.as_mut_ptr(), password.as_mut_ptr(), 0, salt.as_mut_ptr(), 0);
    r17_assert_present_secret(&p.init_vector, &p.init_vector_presence, &iv);
    r17_assert_present_secret(&p.password, &p.password_presence, &[]);
    r17_assert_present_secret(&p.salt, &p.salt_presence, &[]);
    let p = read(std::ptr::null_mut(), std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null_secret(&p.init_vector, &p.init_vector_presence, 8);
    r17_assert_null_secret(&p.password, &p.password_presence, 0);
    r17_assert_null_secret(&p.salt, &p.salt_presence, 0);
    let p = read(std::ptr::null_mut(), std::ptr::null_mut(), 2, std::ptr::null_mut(), 8);
    r17_assert_null_secret(&p.init_vector, &p.init_vector_presence, 8);
    r17_assert_null_secret(&p.password, &p.password_presence, 2);
    r17_assert_null_secret(&p.salt, &p.salt_presence, 8);
    // Mixed: valid IV/password + NULL salt.
    let p = read(iv.as_mut_ptr(), password.as_mut_ptr(), 2, std::ptr::null_mut(), 8);
    r17_assert_present_secret(&p.init_vector, &p.init_vector_presence, &iv);
    r17_assert_present_secret(&p.password, &p.password_presence, &password);
    r17_assert_null_secret(&p.salt, &p.salt_presence, 8);
    // Mixed: NULL IV + valid password/salt.
    let p = read(std::ptr::null_mut(), password.as_mut_ptr(), 2, salt.as_mut_ptr(), 8);
    r17_assert_null_secret(&p.init_vector, &p.init_vector_presence, 8);
    r17_assert_present_secret(&p.password, &p.password_presence, &password);
    r17_assert_present_secret(&p.salt, &p.salt_presence, &salt);
}

/// R17 embedded-field matrix for `gcm_wrap` (wrap operation context).
#[test]
fn r17_matrix_gcm_wrap() {
    let registry = r17_registry();
    let read = |iv_p: CK_BYTE_PTR, iv_len: CK_ULONG, aad_p: CK_BYTE_PTR, aad_len: CK_ULONG| {
        let mut wrap = CK_GCM_WRAP_PARAMS {
            pIv: iv_p,
            ulIvLen: iv_len,
            ulIvFixedBits: 32,
            ivGenerator: CKG_GENERATE as _,
            pAAD: aad_p,
            ulAADLen: aad_len,
            ulTagBits: 128,
        };
        match unsafe {
            r17_read_v1_op(
                &registry,
                "gcm_wrap",
                &mut wrap as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_GCM_WRAP_PARAMS>() as CK_ULONG,
                Operation::WrapKey,
            )
        }
        .expect("GCM-wrap stays typed under v1")
        .params
        {
            Some(CkMechanismParams::GcmWrap(p)) => p,
            other => panic!("GCM-wrap must stay typed under v1, got {other:?}"),
        }
    };
    let mut iv = [0x11u8; 12];
    let mut aad = [0xA1u8, 0xA2];
    let p = read(iv.as_mut_ptr(), 12, aad.as_mut_ptr(), 2);
    assert_eq!(p.iv_fixed_bits, 32);
    r17_assert_present(&p.iv, &p.iv_presence, &iv);
    r17_assert_present_secret(&p.aad, &p.aad_presence, &aad);
    let p = read(iv.as_mut_ptr(), 0, aad.as_mut_ptr(), 0);
    r17_assert_present(&p.iv, &p.iv_presence, &[]);
    r17_assert_present_secret(&p.aad, &p.aad_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null(&p.iv, &p.iv_presence, 0);
    r17_assert_null_secret(&p.aad, &p.aad_presence, 0);
    let p = read(std::ptr::null_mut(), 12, std::ptr::null_mut(), 2);
    r17_assert_null(&p.iv, &p.iv_presence, 12);
    r17_assert_null_secret(&p.aad, &p.aad_presence, 2);
    let p = read(iv.as_mut_ptr(), 12, std::ptr::null_mut(), 2);
    r17_assert_present(&p.iv, &p.iv_presence, &iv);
    r17_assert_null_secret(&p.aad, &p.aad_presence, 2);
    let p = read(std::ptr::null_mut(), 12, aad.as_mut_ptr(), 2);
    r17_assert_null(&p.iv, &p.iv_presence, 12);
    r17_assert_present_secret(&p.aad, &p.aad_presence, &aad);
}

/// R17 embedded-field matrix for `ccm_wrap` (wrap operation context).
#[test]
fn r17_matrix_ccm_wrap() {
    let registry = r17_registry();
    let read =
        |nonce_p: CK_BYTE_PTR, nonce_len: CK_ULONG, aad_p: CK_BYTE_PTR, aad_len: CK_ULONG| {
            let mut wrap = CK_CCM_WRAP_PARAMS {
                ulDataLen: 16,
                pNonce: nonce_p,
                ulNonceLen: nonce_len,
                ulNonceFixedBits: 0,
                nonceGenerator: CKG_GENERATE as _,
                pAAD: aad_p,
                ulAADLen: aad_len,
                ulMACLen: 16,
            };
            match unsafe {
                r17_read_v1_op(
                    &registry,
                    "ccm_wrap",
                    &mut wrap as *mut _ as CK_VOID_PTR,
                    std::mem::size_of::<CK_CCM_WRAP_PARAMS>() as CK_ULONG,
                    Operation::WrapKey,
                )
            }
            .expect("CCM-wrap stays typed under v1")
            .params
            {
                Some(CkMechanismParams::CcmWrap(p)) => p,
                other => panic!("CCM-wrap must stay typed under v1, got {other:?}"),
            }
        };
    let mut nonce = [0x22u8; 12];
    let mut aad = [0xB1u8, 0xB2, 0xB3];
    let p = read(nonce.as_mut_ptr(), 12, aad.as_mut_ptr(), 3);
    assert_eq!((p.data_len, p.mac_len), (16, 16));
    r17_assert_present(&p.nonce, &p.nonce_presence, &nonce);
    r17_assert_present_secret(&p.aad, &p.aad_presence, &aad);
    let p = read(nonce.as_mut_ptr(), 0, aad.as_mut_ptr(), 0);
    r17_assert_present(&p.nonce, &p.nonce_presence, &[]);
    r17_assert_present_secret(&p.aad, &p.aad_presence, &[]);
    let p = read(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    r17_assert_null(&p.nonce, &p.nonce_presence, 0);
    r17_assert_null_secret(&p.aad, &p.aad_presence, 0);
    let p = read(std::ptr::null_mut(), 12, std::ptr::null_mut(), 3);
    r17_assert_null(&p.nonce, &p.nonce_presence, 12);
    r17_assert_null_secret(&p.aad, &p.aad_presence, 3);
    let p = read(nonce.as_mut_ptr(), 12, std::ptr::null_mut(), 3);
    r17_assert_present(&p.nonce, &p.nonce_presence, &nonce);
    r17_assert_null_secret(&p.aad, &p.aad_presence, 3);
    let p = read(std::ptr::null_mut(), 12, aad.as_mut_ptr(), 3);
    r17_assert_null(&p.nonce, &p.nonce_presence, 12);
    r17_assert_present_secret(&p.aad, &p.aad_presence, &aad);
}

/// R17 `gcm_compat` dual encoding under v1: short buffers stay `Iv`
/// bytes; struct-sized buffers take the v1 GCM struct reader (mixed
/// valid+NULL stays typed).
#[test]
fn r17_matrix_gcm_compat() {
    let registry = r17_registry();
    // Short half: bare IV bytes ride `Iv` (legacy dual encoding kept).
    let mut iv_bytes = [0x11u8; 12];
    match unsafe {
        r17_read_v1(
            &registry,
            "gcm_compat",
            iv_bytes.as_mut_ptr() as CK_VOID_PTR,
            iv_bytes.len() as CK_ULONG,
        )
    }
    .expect("short gcm_compat stays Iv under v1")
    .params
    {
        Some(CkMechanismParams::Iv(IvParams { iv })) => assert_eq!(iv, iv_bytes),
        other => panic!("short gcm_compat must stay Iv under v1, got {other:?}"),
    }
    // Struct half: the v1 GCM reader (mixed valid+NULL stays typed).
    let mut iv = [0x11u8; 12];
    let mut gcm = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvBits: 96,
        pAAD: std::ptr::null_mut(),
        ulAADLen: 16,
        ulTagBits: 128,
    };
    match unsafe {
        r17_read_v1(
            &registry,
            "gcm_compat",
            &mut gcm as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        )
    }
    .expect("struct gcm_compat stays typed under v1")
    .params
    {
        Some(CkMechanismParams::Gcm(p)) => {
            r17_assert_present(&p.iv, &p.iv_presence, &iv);
            r17_assert_null_secret(&p.aad, &p.aad_presence, 16);
        }
        other => panic!("struct gcm_compat must stay typed GCM under v1, got {other:?}"),
    }
    // Struct half, NULL-IV direction.
    let mut aad = [0xA1u8, 0xA2];
    gcm.pIv = std::ptr::null_mut();
    gcm.ulIvLen = 12;
    gcm.pAAD = aad.as_mut_ptr();
    gcm.ulAADLen = aad.len() as CK_ULONG;
    match unsafe {
        r17_read_v1(
            &registry,
            "gcm_compat",
            &mut gcm as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        )
    }
    .expect("struct gcm_compat stays typed under v1")
    .params
    {
        Some(CkMechanismParams::Gcm(p)) => {
            r17_assert_null(&p.iv, &p.iv_presence, 12);
            r17_assert_present_secret(&p.aad, &p.aad_presence, &aad);
        }
        other => panic!("struct gcm_compat must stay typed GCM under v1, got {other:?}"),
    }
}

/// R17 matrix for `rsa_aes_key_wrap`: a NULL nested OAEP pointer stays
/// fail-closed (`PARAM_INVALID` — nested-struct presence is an R18 tail
/// concept, and v1 never emits `Raw`); the nested OAEP *fields* take
/// the step-1 discipline through the shared OAEP envelope.
#[test]
fn r17_matrix_rsa_aes_key_wrap() {
    let registry = r17_registry();
    let read = |oaep: *mut CK_RSA_PKCS_OAEP_PARAMS| {
        let mut wrap = CK_RSA_AES_KEY_WRAP_PARAMS { ulAESKeyBits: 256, pOAEPParams: oaep };
        unsafe {
            r17_read_v1(
                &registry,
                "rsa_aes_key_wrap",
                &mut wrap as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>() as CK_ULONG,
            )
        }
    };
    // NULL nested struct: unrepresentable in v1 → local MPI (never Raw).
    assert!(
        matches!(read(std::ptr::null_mut()), Err(CkRv::MECHANISM_PARAM_INVALID)),
        "NULL nested OAEP must fail closed locally under v1"
    );
    // Nested-field matrix through the shared OAEP envelope.
    let mut data = [0xA0u8, 0xA1, 0xA2];
    // One raw pointer shared by every row: pre-materializing two would
    // invalidate the first under Stacked Borrows (Miri).
    let data_ptr = data.as_mut_ptr() as CK_VOID_PTR;
    for (p, len, expect_null) in [
        (data_ptr, 3 as CK_ULONG, None),
        (data_ptr, 0, None),
        (std::ptr::null_mut(), 0, Some(0u64)),
        (std::ptr::null_mut(), 9, Some(9u64)),
    ] {
        let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
            mgf: 1,
            source: 1,
            pSourceData: p,
            ulSourceDataLen: len,
        };
        match read(&mut oaep).expect("nested OAEP stays typed under v1").params {
            Some(CkMechanismParams::RsaAesKeyWrap(p)) => {
                assert_eq!(p.aes_key_bits, 256);
                assert!(!p.oaep_params.source_null, "v1 is presence-only");
                match expect_null {
                    Some(n) => r17_assert_null_secret(
                        &p.oaep_params.source_data,
                        &p.oaep_params.source_data_presence,
                        n,
                    ),
                    None if len == 0 => r17_assert_present_secret(
                        &p.oaep_params.source_data,
                        &p.oaep_params.source_data_presence,
                        &[],
                    ),
                    None => r17_assert_present_secret(
                        &p.oaep_params.source_data,
                        &p.oaep_params.source_data_presence,
                        &data,
                    ),
                }
            }
            other => panic!("nested OAEP must stay typed under v1, got {other:?}"),
        }
    }
}

/// R17 D3 per field: NULL lengths above 512 MiB forward freely (no
/// bytes materialize, no dereference — the tiny buffers below prove
/// the length is never touched); a non-NULL companion over the ceiling
/// stays capped (`PARAM_INVALID` without dereference).
#[test]
fn r17_d3_null_huge_forwards_per_field() {
    let registry = r17_registry();
    const HUGE: CK_ULONG = (512 * 1024 * 1024 + 1) as CK_ULONG;
    assert!(HUGE as usize > MAX_SERIALIZABLE_BYTES, "huge exceeds the ceiling");
    let mut tiny = [0x11u8; 4];
    // One raw pointer shared by every field below: a second `as_mut_ptr`
    // would invalidate the first under Stacked Borrows (Miri).
    let tiny_ptr = tiny.as_mut_ptr();
    // NULL IV + NULL AAD, both huge: forwards as typed Null pair.
    let mut gcm = CK_GCM_PARAMS {
        pIv: std::ptr::null_mut(),
        ulIvLen: HUGE,
        ulIvBits: 96,
        pAAD: std::ptr::null_mut(),
        ulAADLen: CK_ULONG::MAX,
        ulTagBits: 128,
    };
    match unsafe {
        r17_read_v1(
            &registry,
            "gcm",
            &mut gcm as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        )
    }
    .expect("NULL-huge pair forwards under v1")
    .params
    {
        Some(CkMechanismParams::Gcm(p)) => {
            r17_assert_null(&p.iv, &p.iv_presence, HUGE as u64);
            r17_assert_null_secret(&p.aad, &p.aad_presence, CK_ULONG::MAX as u64);
        }
        other => panic!("NULL-huge GCM must stay typed under v1, got {other:?}"),
    }
    // Mixed huge: valid tiny IV + NULL-huge AAD forwards (the fix holds
    // at D3 scale — the IV is copied, the AAD length only recorded).
    gcm.pIv = tiny_ptr;
    gcm.ulIvLen = tiny.len() as CK_ULONG;
    match unsafe {
        r17_read_v1(
            &registry,
            "gcm",
            &mut gcm as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        )
    }
    .expect("mixed tiny-NULL-huge forwards under v1")
    .params
    {
        Some(CkMechanismParams::Gcm(p)) => {
            r17_assert_present(&p.iv, &p.iv_presence, &tiny);
            r17_assert_null_secret(&p.aad, &p.aad_presence, CK_ULONG::MAX as u64);
        }
        other => panic!("mixed tiny-NULL-huge GCM must stay typed under v1, got {other:?}"),
    }
    // Non-NULL over the ceiling stays capped — per field, without
    // dereference (the 4-byte buffer cannot back a 512 MiB+ read).
    gcm.pAAD = tiny_ptr;
    gcm.ulAADLen = HUGE;
    assert!(
        matches!(
            unsafe {
                r17_read_v1(
                    &registry,
                    "gcm",
                    &mut gcm as *mut _ as CK_VOID_PTR,
                    std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
                )
            },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "non-NULL AAD over the ceiling must be MPI without dereference"
    );
    // Same per-field rule on a second family (EdDSA NULL-ctx huge).
    let mut eddsa = CK_EDDSA_PARAMS {
        phFlag: CK_FALSE,
        ulContextDataLen: CK_ULONG::MAX,
        pContextData: std::ptr::null_mut(),
    };
    match unsafe {
        r17_read_v1(
            &registry,
            "eddsa",
            &mut eddsa as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_EDDSA_PARAMS>() as CK_ULONG,
        )
    }
    .expect("EdDSA NULL-huge forwards under v1")
    .params
    {
        Some(CkMechanismParams::Eddsa(p)) => {
            r17_assert_null_secret(&p.context_data, &p.context_data_presence, CK_ULONG::MAX as u64);
        }
        other => panic!("EdDSA NULL-huge must stay typed under v1, got {other:?}"),
    }
    eddsa.pContextData = tiny_ptr;
    eddsa.ulContextDataLen = HUGE;
    assert!(
        matches!(
            unsafe {
                r17_read_v1(
                    &registry,
                    "eddsa",
                    &mut eddsa as *mut _ as CK_VOID_PTR,
                    std::mem::size_of::<CK_EDDSA_PARAMS>() as CK_ULONG,
                )
            },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "non-NULL ctx over the ceiling must be MPI without dereference"
    );
}

/// R17 512 MiB ceiling boundary: exactly 512 MiB is representable (the
/// pure length gate admits it), 512 MiB + 1 is not (per-field MPI
/// without dereference — no 512 MiB allocation in this test).
#[test]
fn r17_ceiling_512mib_boundary_per_field() {
    assert_eq!(MAX_SERIALIZABLE_BYTES, 512 * 1024 * 1024, "S2 §5 ceiling");
    assert!(super::embedded_payload_len_ok((MAX_SERIALIZABLE_BYTES) as CK_ULONG));
    assert!(!super::embedded_payload_len_ok((MAX_SERIALIZABLE_BYTES + 1) as CK_ULONG));
    // Reader level: non-NULL + ceiling+1 with a 1-byte buffer → MPI.
    let registry = r17_registry();
    let mut one = [0xAAu8];
    let mut kds = CK_KEY_DERIVATION_STRING_DATA {
        pData: one.as_mut_ptr(),
        ulLen: (MAX_SERIALIZABLE_BYTES + 1) as CK_ULONG,
    };
    assert!(
        matches!(
            unsafe {
                r17_read_v1(
                    &registry,
                    "key_derivation_string",
                    &mut kds as *mut _ as CK_VOID_PTR,
                    std::mem::size_of::<CK_KEY_DERIVATION_STRING_DATA>() as CK_ULONG,
                )
            },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "ceiling+1 non-NULL must be MPI without dereference"
    );
    // NULL + ceiling+1 forwards (D3, no bytes materialize).
    kds.pData = std::ptr::null_mut();
    match unsafe {
        r17_read_v1(
            &registry,
            "key_derivation_string",
            &mut kds as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_KEY_DERIVATION_STRING_DATA>() as CK_ULONG,
        )
    }
    .expect("NULL ceiling+1 forwards under v1")
    .params
    {
        Some(CkMechanismParams::KeyDerivationString(p)) => {
            r17_assert_null_secret(&p.data, &p.data_presence, (MAX_SERIALIZABLE_BYTES + 1) as u64);
        }
        other => panic!("NULL ceiling+1 must stay typed under v1, got {other:?}"),
    }
}

/// R17 shared-length exception (S2 §10/D3): the ONLY shapes whose R7
/// descriptor carries a shared-length group are the two R18-tail shapes
/// (`kea_derive` RandomA/B, `skipjack_private_wrap` P/G) — so the
/// exception is vacuous for every R17 v1 shape, and the step-1 rule
/// needs no companion check. Drift-proof: a future third sharer, or a
/// v1 shape gaining a group, fails this test by name.
#[test]
fn r17_shared_length_exception_vacuous_for_v1_input_shapes() {
    use pkcs11_proxy_ng_types::shape_descriptors::SHAPE_DESCRIPTORS;
    let mut sharers: Vec<&str> = SHAPE_DESCRIPTORS
        .iter()
        .filter(|d| {
            !d.shared_length_groups.is_empty()
                || d.alternate_forms.iter().any(|a| !a.shared_length_groups.is_empty())
        })
        .map(|d| d.name)
        .collect();
    sharers.sort_unstable();
    assert_eq!(
        sharers,
        ["kea_derive", "skipjack_private_wrap"],
        "only R18-tail shapes share lengths"
    );
    // Both sharers are NestedOrOutput tail (never v1 input shapes).
    for tail in sharers {
        let d = pkcs11_proxy_ng_types::shape_descriptors::ShapeResolver::descriptor(tail)
            .expect("tail descriptor");
        assert_eq!(
            d.outer_kind,
            pkcs11_proxy_ng_types::shape_descriptors::OuterKind::NestedOrOutput,
            "{tail} is R18 tail"
        );
    }
    // Every R17 v1 shape (R16 rows + gcm_compat) is group-free.
    let mut v1_shapes: Vec<&str> = R17_SYN_SHAPES.to_vec();
    v1_shapes.extend(["gcm", "ccm", "gcm_wrap", "ccm_wrap", "gcm_compat"]);
    v1_shapes.sort_unstable();
    v1_shapes.dedup();
    assert_eq!(v1_shapes.len(), 38, "37 R16 rows + gcm_compat");
    for shape in v1_shapes {
        let d = pkcs11_proxy_ng_types::shape_descriptors::ShapeResolver::descriptor(shape)
            .unwrap_or_else(|| panic!("v1 shape resolves: {shape}"));
        assert!(d.shared_length_groups.is_empty(), "{shape} shares no length");
        for alt in d.alternate_forms {
            assert!(alt.shared_length_groups.is_empty(), "{shape} alternate shares no length");
        }
    }
}

/// R17 short-struct gate: buffers shorter than the struct fail closed
/// locally with `PARAM_INVALID` under v1 — never `Raw` (v1 never emits
/// legacy `Raw`, S2 §5).
#[test]
fn r17_short_struct_fails_closed_without_raw() {
    let registry = r17_registry();
    // GCM 3 bytes short.
    let mut short = [0x11u8; 8];
    assert!(
        matches!(
            unsafe {
                r17_read_v1(
                    &registry,
                    "gcm",
                    short.as_mut_ptr() as CK_VOID_PTR,
                    short.len() as CK_ULONG,
                )
            },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "short GCM must be MPI under v1, never Raw"
    );
    // HKDF 1 byte short.
    let mut short_hkdf = [0x22u8; std::mem::size_of::<CK_HKDF_PARAMS>() - 1];
    assert!(
        matches!(
            unsafe {
                r17_read_v1(
                    &registry,
                    "hkdf",
                    short_hkdf.as_mut_ptr() as CK_VOID_PTR,
                    short_hkdf.len() as CK_ULONG,
                )
            },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "short HKDF must be MPI under v1, never Raw"
    );
    // Nested-OAEP wrapper 1 byte short.
    let mut short_rsa = [0x33u8; std::mem::size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>() - 1];
    assert!(
        matches!(
            unsafe {
                r17_read_v1(
                    &registry,
                    "rsa_aes_key_wrap",
                    short_rsa.as_mut_ptr() as CK_VOID_PTR,
                    short_rsa.len() as CK_ULONG,
                )
            },
            Err(CkRv::MECHANISM_PARAM_INVALID)
        ),
        "short RSA-AES-wrap must be MPI under v1, never Raw"
    );
}

/// R17 cross-path check (S2 §16): mechanisms participate in init, wrap,
/// derive, generate, KEM, and authenticated paths — each path reaches
/// the v1 typed reader (one representative family per path; wrap via
/// the `WrapKey` operation, the rest via `General`).
#[test]
fn r17_cross_path_each_operation_entry_hits_typed_v1() {
    let registry = r17_registry();
    // Init path rep: GCM mixed valid-IV + NULL-AAD (C_EncryptInit etc.).
    let mut iv = [0x11u8; 12];
    let mut gcm = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvBits: 96,
        pAAD: std::ptr::null_mut(),
        ulAADLen: 16,
        ulTagBits: 128,
    };
    match unsafe {
        r17_read_v1(
            &registry,
            "gcm",
            &mut gcm as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        )
    }
    .expect("init-path GCM stays typed under v1")
    .params
    {
        Some(CkMechanismParams::Gcm(p)) => {
            r17_assert_present(&p.iv, &p.iv_presence, &iv);
            r17_assert_null_secret(&p.aad, &p.aad_presence, 16);
        }
        other => panic!("init-path GCM must stay typed under v1, got {other:?}"),
    }
    // Wrap path rep: GCM-wrap mixed NULL-IV + valid AAD (C_WrapKey).
    let mut wrap_aad = [0xA1u8, 0xA2];
    let mut wrap = CK_GCM_WRAP_PARAMS {
        pIv: std::ptr::null_mut(),
        ulIvLen: 12,
        ulIvFixedBits: 32,
        ivGenerator: CKG_GENERATE as _,
        pAAD: wrap_aad.as_mut_ptr(),
        ulAADLen: wrap_aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    match unsafe {
        r17_read_v1_op(
            &registry,
            "gcm_wrap",
            &mut wrap as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_GCM_WRAP_PARAMS>() as CK_ULONG,
            Operation::WrapKey,
        )
    }
    .expect("wrap-path GCM-wrap stays typed under v1")
    .params
    {
        Some(CkMechanismParams::GcmWrap(p)) => {
            r17_assert_null(&p.iv, &p.iv_presence, 12);
            r17_assert_present_secret(&p.aad, &p.aad_presence, &wrap_aad);
        }
        other => panic!("wrap-path GCM-wrap must stay typed under v1, got {other:?}"),
    }
    // Derive path rep: ECDH1 mixed valid-shared + NULL-public (C_DeriveKey).
    let mut shared = [0x31u8, 0x32];
    let mut ecdh = CK_ECDH1_DERIVE_PARAMS {
        kdf: 1,
        ulSharedDataLen: shared.len() as CK_ULONG,
        pSharedData: shared.as_mut_ptr(),
        ulPublicDataLen: 65,
        pPublicData: std::ptr::null_mut(),
    };
    match unsafe {
        r17_read_v1(
            &registry,
            "ecdh1_derive",
            &mut ecdh as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG,
        )
    }
    .expect("derive-path ECDH1 stays typed under v1")
    .params
    {
        Some(CkMechanismParams::Ecdh1Derive(p)) => {
            r17_assert_present_secret(&p.shared_data, &p.shared_data_presence, &shared);
            r17_assert_null(&p.public_data, &p.public_data_presence, 65);
        }
        other => panic!("derive-path ECDH1 must stay typed under v1, got {other:?}"),
    }
    // Generate path rep: HKDF mixed NULL-salt + valid info (C_GenerateKey).
    let mut info = [0x42u8, 0x43];
    let mut hkdf = CK_HKDF_PARAMS {
        bExtract: CK_TRUE,
        bExpand: CK_TRUE,
        prfHashMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        ulSaltType: 0,
        pSalt: std::ptr::null_mut(),
        ulSaltLen: 32,
        hSaltKey: 0,
        pInfo: info.as_mut_ptr(),
        ulInfoLen: info.len() as CK_ULONG,
    };
    match unsafe {
        r17_read_v1(
            &registry,
            "hkdf",
            &mut hkdf as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_HKDF_PARAMS>() as CK_ULONG,
        )
    }
    .expect("generate-path HKDF stays typed under v1")
    .params
    {
        Some(CkMechanismParams::Hkdf(p)) => {
            r17_assert_null_secret(&p.salt, &p.salt_presence, 32);
            r17_assert_present_secret(&p.info, &p.info_presence, &info);
        }
        other => panic!("generate-path HKDF must stay typed under v1, got {other:?}"),
    }
    // KEM path rep: ECDH-AES-wrap NULL-shared (C_EncapsulateKey etc.).
    let mut kem = CK_ECDH_AES_KEY_WRAP_PARAMS {
        ulAESKeyBits: 256,
        kdf: 1,
        ulSharedDataLen: 9,
        pSharedData: std::ptr::null_mut(),
    };
    match unsafe {
        r17_read_v1(
            &registry,
            "ecdh_aes_key_wrap",
            &mut kem as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_ECDH_AES_KEY_WRAP_PARAMS>() as CK_ULONG,
        )
    }
    .expect("KEM-path ECDH-AES-wrap stays typed under v1")
    .params
    {
        Some(CkMechanismParams::EcdhAesKeyWrap(p)) => {
            r17_assert_null_secret(&p.shared_data, &p.shared_data_presence, 9);
        }
        other => panic!("KEM-path ECDH-AES-wrap must stay typed under v1, got {other:?}"),
    }
    // Authenticated path rep: CCM-wrap mixed valid-nonce + NULL-AAD.
    let mut nonce = [0x22u8; 12];
    let mut ccm_wrap = CK_CCM_WRAP_PARAMS {
        ulDataLen: 16,
        pNonce: nonce.as_mut_ptr(),
        ulNonceLen: nonce.len() as CK_ULONG,
        ulNonceFixedBits: 0,
        nonceGenerator: CKG_GENERATE as _,
        pAAD: std::ptr::null_mut(),
        ulAADLen: 5,
        ulMACLen: 16,
    };
    match unsafe {
        r17_read_v1_op(
            &registry,
            "ccm_wrap",
            &mut ccm_wrap as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_CCM_WRAP_PARAMS>() as CK_ULONG,
            Operation::WrapKey,
        )
    }
    .expect("authenticated-path CCM-wrap stays typed under v1")
    .params
    {
        Some(CkMechanismParams::CcmWrap(p)) => {
            r17_assert_present(&p.nonce, &p.nonce_presence, &nonce);
            r17_assert_null_secret(&p.aad, &p.aad_presence, 5);
        }
        other => panic!("authenticated-path CCM-wrap must stay typed under v1, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// R18: v1 tail-reader matrix (S2 §8 tail, D1(a)) — presence/count/output
// envelopes per tail family incl. NULL/count-0/empty edges. Byte-field
// assertions reuse the R17 helpers; only array + null-bit assertions are
// R18-local. These tests cover the v1 tail branch only; legacy identity
// for the same inputs stays pinned by the pre-R18 suites (append-only).
// ---------------------------------------------------------------------------

/// Synthetic mechanism numbers for the R18 matrix (unbound range above
/// the R17 block).
const R18_SYN_BASE: u64 = 0x0000_B000;

/// R18 tail shapes bound to synthetic mechanisms (single source for the
/// registry builder + the mech lookup; reviewer-checked against
/// `R18_TAIL_TABLE` — the 17-shape R18 scope).
const R18_SYN_SHAPES: &[&str] = &[
    "tls_mac",
    "tls_prf",
    "tls_kdf",
    "ssl3_master_key_derive",
    "tls12_master_key_derive",
    "tls12_extended_master_key_derive",
    "ssl3_key_mat",
    "wtls_master_key_derive",
    "wtls_prf",
    "wtls_key_mat",
    "kea_derive",
    "kip",
    "otp",
    "skipjack_private_wrap",
    "skipjack_relayx",
    "sp800_108_kdf",
    "sp800_108_feedback_kdf",
];

/// Custom registry for the R18 matrix: no TOML parse (Miri-friendly),
/// one binding per tail shape.
fn r18_registry() -> MechanismRegistry {
    let bindings: Vec<(&str, u64)> = R18_SYN_SHAPES
        .iter()
        .enumerate()
        .map(|(i, shape)| (*shape, R18_SYN_BASE + i as u64))
        .collect();
    assert_eq!(R18_SYN_SHAPES.len(), 17, "r18 registry binds the 17-shape R18 scope");
    r11_registry(&bindings, &[], &[])
}

/// Mechanism number bound to `shape` in [`r18_registry`].
fn r18_mech(shape: &str) -> u64 {
    R18_SYN_SHAPES
        .iter()
        .position(|s| *s == shape)
        .map(|i| R18_SYN_BASE + i as u64)
        .expect("r18 shape")
}

/// Read one host-native param struct as `shape` under v1/`General`
/// (matrix shorthand).
///
/// # Safety
///
/// `p_parameter` must designate `ul_parameter_len` readable bytes
/// containing the shape's C struct.
unsafe fn r18_read_v1(
    registry: &MechanismRegistry,
    shape: &str,
    p_parameter: CK_VOID_PTR,
    ul_parameter_len: CK_ULONG,
) -> Result<CkMechanism, CkRv> {
    let mechanism = r11_mechanism(r18_mech(shape), p_parameter, ul_parameter_len);
    unsafe { read_r11_v1_native_abi(&mechanism, registry, Operation::General) }
}

/// Assert one v1 counted array is NULL with `declared_count`: legacy
/// vec stays empty, peer is `Null(n)`.
fn r18_assert_null_array<T: PartialEq + std::fmt::Debug>(
    legacy: &[T],
    peer: &PointerArray<T>,
    declared_count: u64,
) {
    assert!(legacy.is_empty(), "NULL legacy array stays empty");
    assert_eq!(peer, &PointerArray::null_count(declared_count), "peer is Null(n)");
}

/// Assert one v1 counted array is present-but-empty: legacy vec stays
/// empty, peer is `Present(empty)`.
fn r18_assert_present_empty_array<T: PartialEq + std::fmt::Debug>(
    legacy: &[T],
    peer: &PointerArray<T>,
) {
    assert!(legacy.is_empty(), "empty legacy array stays empty");
    assert_eq!(peer, &PointerArray::present(Vec::new()), "peer is Present(empty)");
}

/// R18 dispatch: the predicate covers exactly the 17-shape tail scope
/// and stays disjoint from the R17 input-pointer shapes.
#[test]
fn r18_dispatch_predicate_covers_tail_scope() {
    for shape in R18_SYN_SHAPES {
        assert!(is_r18_tail_shape(Some(shape)), "{shape} must route to the tail readers");
    }
    for shape in R17_SYN_SHAPES {
        assert!(!is_r18_tail_shape(Some(shape)), "{shape} must NOT route to the tail readers");
    }
    for shape in ["gcm", "ccm", "rsa_pss", "iv", "mac_general", "no_such_shape"] {
        assert!(!is_r18_tail_shape(Some(shape)), "{shape} must NOT route to the tail readers");
    }
    assert!(!is_r18_tail_shape(None));
}

/// S2 §8 TLS/WTLS envelopes: TlsMac stays scalar under v1 (no envelope
/// fields — pinned by the R18 proto `tls_mac_stays_v0` test).
#[test]
fn r18_tls_mac_v1_scalar() {
    let registry = r18_registry();
    let mut tls_mac = CK_TLS_MAC_PARAMS {
        prfHashMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        ulMacLength: 32,
        ulServerOrClient: 1,
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "tls_mac",
            &mut tls_mac as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_TLS_MAC_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::TlsMac(TlsMacParams {
            prf_hash_mechanism,
            mac_length,
            server_or_client,
        })) => {
            assert_eq!(prf_hash_mechanism.0, CkMechanismType::SHA256.0 as u64);
            assert_eq!(mac_length, 32);
            assert_eq!(server_or_client, 1);
        }
        other => panic!("TLS MAC must stay scalar under v1, got {other:?}"),
    }
}

/// S2 §8 TLS/WTLS envelopes: TLS PRF with a NULL seed stays ONE typed
/// message (the mixed-field fix); NULL output pointers set the
/// length-less null bits with zeroed mirrors.
#[test]
fn r18_tls_prf_v1_null_seed_stays_typed() {
    let registry = r18_registry();
    let mut label = [0xD0u8, 0xD1];
    let mut prf = CK_TLS_PRF_PARAMS {
        pSeed: std::ptr::null_mut(),
        ulSeedLen: 7,
        pLabel: label.as_mut_ptr(),
        ulLabelLen: label.len() as CK_ULONG,
        pOutput: std::ptr::null_mut(),
        pulOutputLen: std::ptr::null_mut(),
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "tls_prf",
            &mut prf as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_TLS_PRF_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::TlsPrf(p)) => {
            r17_assert_null_secret(&p.seed, &p.seed_presence, 7);
            r17_assert_present_secret(&p.label, &p.label_presence, &label);
            assert!(p.output_is_null);
            assert!(p.output_len_is_null);
            assert_eq!(p.output_len, 0);
            p.output.expose(|b| assert!(b.is_empty()));
        }
        other => panic!("NULL-seed TLS PRF must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 TLS/WTLS envelopes: present PRF output pointers clear the null
/// bits and mirror the length — but the OUT bytes are never read
/// (W1-C5-01: the sentinel-filled caller buffer must not leak in).
#[test]
fn r18_tls_prf_v1_output_bits() {
    let registry = r18_registry();
    let mut seed = [0xC0u8, 0xC1];
    let mut label = [0xD0u8];
    let mut output = [0xEEu8; 48];
    let mut output_len = output.len() as CK_ULONG;
    let mut prf = CK_TLS_PRF_PARAMS {
        pSeed: seed.as_mut_ptr(),
        ulSeedLen: seed.len() as CK_ULONG,
        pLabel: label.as_mut_ptr(),
        ulLabelLen: label.len() as CK_ULONG,
        pOutput: output.as_mut_ptr(),
        pulOutputLen: &mut output_len,
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "tls_prf",
            &mut prf as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_TLS_PRF_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::TlsPrf(p)) => {
            r17_assert_present_secret(&p.seed, &p.seed_presence, &seed);
            r17_assert_present_secret(&p.label, &p.label_presence, &label);
            assert!(!p.output_is_null);
            assert!(!p.output_len_is_null);
            assert_eq!(p.output_len, 48);
            p.output.expose(|b| assert!(b.is_empty(), "OUT bytes never read"));
        }
        other => panic!("present-output TLS PRF must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 TLS/WTLS envelopes: TLS KDF mixed NULLs (label NULL+3, client
/// NULL+5, server present, context NULL+0 — the count-0 edge records
/// `Null{0}`, never conflated with present-empty).
#[test]
fn r18_tls_kdf_v1_mixed_nulls() {
    let registry = r18_registry();
    let mut server_random = [0x22u8; 4];
    let mut tls_kdf = CK_TLS_KDF_PARAMS {
        prfMechanism: CkMechanismType::SHA384.0 as CK_MECHANISM_TYPE,
        pLabel: std::ptr::null_mut(),
        ulLabelLength: 3,
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: std::ptr::null_mut(),
            ulClientRandomLen: 5,
            pServerRandom: server_random.as_mut_ptr(),
            ulServerRandomLen: server_random.len() as CK_ULONG,
        },
        pContextData: std::ptr::null_mut(),
        ulContextDataLength: 0,
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "tls_kdf",
            &mut tls_kdf as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_TLS_KDF_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::TlsKdf(p)) => {
            assert_eq!(p.prf_mechanism.0, CkMechanismType::SHA384.0 as u64);
            r17_assert_null_secret(&p.label, &p.label_presence, 3);
            r17_assert_null(&p.random_info.client_random, &p.random_info.client_random_presence, 5);
            r17_assert_present(
                &p.random_info.server_random,
                &p.random_info.server_random_presence,
                &server_random,
            );
            r17_assert_null_secret(&p.context_data, &p.context_data_presence, 0);
        }
        other => panic!("mixed-NULL TLS KDF must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 TLS/WTLS envelopes: SSL3 master with NULL version (bit set,
/// zeroed mirrors) and a NULL+0 client random beside present server
/// random.
#[test]
fn r18_ssl3_master_v1_null_version() {
    let registry = r18_registry();
    let mut server_random = [0x52u8; 4];
    let mut ssl3_master = CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: std::ptr::null_mut(),
            ulClientRandomLen: 0,
            pServerRandom: server_random.as_mut_ptr(),
            ulServerRandomLen: server_random.len() as CK_ULONG,
        },
        pVersion: std::ptr::null_mut(),
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "ssl3_master_key_derive",
            &mut ssl3_master as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::Ssl3MasterKeyDerive(p)) => {
            r17_assert_null(&p.random_info.client_random, &p.random_info.client_random_presence, 0);
            r17_assert_present(
                &p.random_info.server_random,
                &p.random_info.server_random_presence,
                &server_random,
            );
            assert!(p.version_is_null);
            assert_eq!((p.version_major, p.version_minor), (0, 0));
        }
        other => panic!("NULL-version SSL3 master must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 TLS/WTLS envelopes: TLS12 master with a present version
/// (values mirrored, bit clear) and present randoms.
#[test]
fn r18_tls12_master_v1_present_version() {
    let registry = r18_registry();
    let mut client_random = [0x11u8; 4];
    let mut server_random = [0x22u8; 4];
    let mut version = CK_VERSION { major: 3, minor: 3 };
    let mut tls12_master = CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: client_random.as_mut_ptr(),
            ulClientRandomLen: client_random.len() as CK_ULONG,
            pServerRandom: server_random.as_mut_ptr(),
            ulServerRandomLen: server_random.len() as CK_ULONG,
        },
        pVersion: &mut version,
        prfHashMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "tls12_master_key_derive",
            &mut tls12_master as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::Tls12MasterKeyDerive(p)) => {
            r17_assert_present(
                &p.random_info.client_random,
                &p.random_info.client_random_presence,
                &client_random,
            );
            r17_assert_present(
                &p.random_info.server_random,
                &p.random_info.server_random_presence,
                &server_random,
            );
            assert!(!p.version_is_null);
            assert_eq!((p.version_major, p.version_minor), (3, 3));
            assert_eq!(p.prf_hash_mechanism.0, CkMechanismType::SHA256.0 as u64);
        }
        other => panic!("present-version TLS12 master must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 TLS/WTLS envelopes: TLS12 extended master with NULL
/// session-hash + NULL version.
#[test]
fn r18_tls12_extended_v1_null_session_hash() {
    let registry = r18_registry();
    let mut tls12_extended = CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS {
        prfHashMechanism: CkMechanismType::SHA512.0 as CK_MECHANISM_TYPE,
        pSessionHash: std::ptr::null_mut(),
        ulSessionHashLen: 9,
        pVersion: std::ptr::null_mut(),
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "tls12_extended_master_key_derive",
            &mut tls12_extended as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::Tls12ExtendedMasterKeyDerive(p)) => {
            assert_eq!(p.prf_hash_mechanism.0, CkMechanismType::SHA512.0 as u64);
            r17_assert_null(&p.session_hash, &p.session_hash_presence, 9);
            assert!(p.version_is_null);
            assert_eq!((p.version_major, p.version_minor), (0, 0));
        }
        other => panic!("NULL-hash TLS12 extended master must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 key-mat: SSL3 key-mat with NULL returned material (bit
/// set, handles zero, IV peers record the bits-derived length without
/// dereference) beside present randoms.
#[test]
fn r18_ssl3_key_mat_v1_null_returned() {
    let registry = r18_registry();
    let mut client_random = [0x11u8, 0x12, 0x13];
    let mut server_random = [0x21u8, 0x22];
    let mut key_mat = CK_SSL3_KEY_MAT_PARAMS {
        ulMacSizeInBits: 160,
        ulKeySizeInBits: 128,
        ulIVSizeInBits: 32,
        bIsExport: CK_FALSE,
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: client_random.as_mut_ptr(),
            ulClientRandomLen: client_random.len() as CK_ULONG,
            pServerRandom: server_random.as_mut_ptr(),
            ulServerRandomLen: server_random.len() as CK_ULONG,
        },
        pReturnedKeyMaterial: std::ptr::null_mut(),
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "ssl3_key_mat",
            &mut key_mat as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_SSL3_KEY_MAT_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::Ssl3KeyMat(p)) => {
            r17_assert_present(
                &p.random_info.client_random,
                &p.random_info.client_random_presence,
                &client_random,
            );
            r17_assert_present(
                &p.random_info.server_random,
                &p.random_info.server_random_presence,
                &server_random,
            );
            assert!(p.returned_key_material_is_null);
            assert_eq!(p.client_mac_secret_handle.0, 0);
            assert_eq!(p.server_mac_secret_handle.0, 0);
            assert_eq!(p.client_key_handle.0, 0);
            assert_eq!(p.server_key_handle.0, 0);
            r17_assert_null_secret(&p.client_iv, &p.client_iv_presence, 4);
            r17_assert_null_secret(&p.server_iv, &p.server_iv_presence, 4);
            assert_eq!(p.prf_hash_mechanism.0, 0, "ssl3 form carries no prf");
        }
        other => panic!("NULL-returned SSL3 key-mat must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 key-mat: TLS12 key-mat superset with present returned
/// material (handles + IVs mirrored, bit clear, prf decoded).
#[test]
fn r18_ssl3_key_mat_v1_tls12_superset_present() {
    let registry = r18_registry();
    let mut client_random = [0x11u8, 0x12, 0x13];
    let mut server_random = [0x21u8, 0x22];
    let mut client_iv = [0xA1u8, 0xA2, 0xA3, 0xA4];
    let mut server_iv = [0xB1u8, 0xB2, 0xB3, 0xB4];
    let mut key_mat_out = CK_SSL3_KEY_MAT_OUT {
        hClientMacSecret: 101,
        hServerMacSecret: 102,
        hClientKey: 201,
        hServerKey: 202,
        pIVClient: client_iv.as_mut_ptr(),
        pIVServer: server_iv.as_mut_ptr(),
    };
    let mut key_mat = CK_TLS12_KEY_MAT_PARAMS {
        ulMacSizeInBits: 160,
        ulKeySizeInBits: 128,
        ulIVSizeInBits: 32,
        bIsExport: CK_FALSE,
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: client_random.as_mut_ptr(),
            ulClientRandomLen: client_random.len() as CK_ULONG,
            pServerRandom: server_random.as_mut_ptr(),
            ulServerRandomLen: server_random.len() as CK_ULONG,
        },
        pReturnedKeyMaterial: &mut key_mat_out,
        prfHashMechanism: CkMechanismType::SHA256.0 as CK_ULONG,
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "ssl3_key_mat",
            &mut key_mat as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_TLS12_KEY_MAT_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::Ssl3KeyMat(p)) => {
            assert!(!p.returned_key_material_is_null);
            assert_eq!(p.client_mac_secret_handle.0, 101);
            assert_eq!(p.server_mac_secret_handle.0, 102);
            assert_eq!(p.client_key_handle.0, 201);
            assert_eq!(p.server_key_handle.0, 202);
            r17_assert_present_secret(&p.client_iv, &p.client_iv_presence, &client_iv);
            r17_assert_present_secret(&p.server_iv, &p.server_iv_presence, &server_iv);
            assert_eq!(p.prf_hash_mechanism.0, CkMechanismType::SHA256.0 as u64);
        }
        other => panic!("present TLS12 key-mat must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 TLS/WTLS envelopes: WTLS master with NULL version (bit set,
/// zeroed mirror) beside a NULL client random + present server random.
#[test]
fn r18_wtls_master_v1_null_version() {
    let registry = r18_registry();
    let mut server_random = [0x22u8; 4];
    let mut wtls_master = CK_WTLS_MASTER_KEY_DERIVE_PARAMS {
        DigestMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        RandomInfo: CK_WTLS_RANDOM_DATA {
            pClientRandom: std::ptr::null_mut(),
            ulClientRandomLen: 6,
            pServerRandom: server_random.as_mut_ptr(),
            ulServerRandomLen: server_random.len() as CK_ULONG,
        },
        pVersion: std::ptr::null_mut(),
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "wtls_master_key_derive",
            &mut wtls_master as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_WTLS_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::WtlsMasterKeyDerive(p)) => {
            assert_eq!(p.digest_mechanism.0, CkMechanismType::SHA256.0 as u64);
            r17_assert_null(&p.random_info.client_random, &p.random_info.client_random_presence, 6);
            r17_assert_present(
                &p.random_info.server_random,
                &p.random_info.server_random_presence,
                &server_random,
            );
            assert!(p.version_is_null);
            assert_eq!(p.version, 0);
        }
        other => panic!("NULL-version WTLS master must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 TLS/WTLS envelopes: WTLS PRF output bits mirror the TLS PRF
/// contract (present pointers clear the bits; OUT bytes never read).
#[test]
fn r18_wtls_prf_v1_output_bits() {
    let registry = r18_registry();
    let mut seed = [0xA1u8, 0xA2, 0xA3];
    let mut label = [0xB1u8, 0xB2];
    let mut output = [0xEEu8; 20];
    let mut output_len = output.len() as CK_ULONG;
    let mut wtls = CK_WTLS_PRF_PARAMS {
        DigestMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        pSeed: seed.as_mut_ptr(),
        ulSeedLen: seed.len() as CK_ULONG,
        pLabel: label.as_mut_ptr(),
        ulLabelLen: label.len() as CK_ULONG,
        pOutput: output.as_mut_ptr(),
        pulOutputLen: &mut output_len,
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "wtls_prf",
            &mut wtls as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_WTLS_PRF_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::WtlsPrf(p)) => {
            r17_assert_present_secret(&p.seed, &p.seed_presence, &seed);
            r17_assert_present_secret(&p.label, &p.label_presence, &label);
            assert!(!p.output_is_null);
            assert!(!p.output_len_is_null);
            assert_eq!(p.output_len, 20);
            p.output.expose(|b| assert!(b.is_empty(), "OUT bytes never read"));
        }
        other => panic!("present-output WTLS PRF must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 key-mat: WTLS key-mat with NULL returned material (bit set,
/// handles zero, IV peer records the bits-derived length).
#[test]
fn r18_wtls_key_mat_v1_null_returned() {
    let registry = r18_registry();
    let mut client_random = [0x11u8; 4];
    let mut server_random = [0x22u8; 4];
    let mut key_mat = CK_WTLS_KEY_MAT_PARAMS {
        DigestMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        ulMacSizeInBits: 160,
        ulKeySizeInBits: 128,
        ulIVSizeInBits: 32,
        ulSequenceNumber: 7,
        bIsExport: CK_TRUE,
        RandomInfo: CK_WTLS_RANDOM_DATA {
            pClientRandom: client_random.as_mut_ptr(),
            ulClientRandomLen: client_random.len() as CK_ULONG,
            pServerRandom: server_random.as_mut_ptr(),
            ulServerRandomLen: server_random.len() as CK_ULONG,
        },
        pReturnedKeyMaterial: std::ptr::null_mut(),
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "wtls_key_mat",
            &mut key_mat as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_WTLS_KEY_MAT_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::WtlsKeyMat(p)) => {
            assert_eq!(p.sequence_number, 7);
            assert!(p.is_export);
            assert!(p.returned_key_material_is_null);
            assert_eq!(p.mac_secret_handle.0, 0);
            assert_eq!(p.key_handle.0, 0);
            r17_assert_null_secret(&p.iv, &p.iv_presence, 4);
        }
        other => panic!("NULL-returned WTLS key-mat must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 KEA: shared-length companions read independently — a NULL
/// B beside a valid A stays ONE typed message (agreement is the proto
/// decoder's job, pinned by the R18 `shared_len` tests).
#[test]
fn r18_kea_v1_null_b_stays_typed() {
    let registry = r18_registry();
    let mut random_a = [0xAAu8; 16];
    let mut kea = CK_KEA_DERIVE_PARAMS {
        isSender: CK_TRUE,
        ulRandomLen: 16,
        RandomA: random_a.as_mut_ptr(),
        RandomB: std::ptr::null_mut(),
        ulPublicDataLen: 0,
        PublicData: std::ptr::null_mut(),
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "kea_derive",
            &mut kea as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_KEA_DERIVE_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::KeaDerive(p)) => {
            assert!(p.is_sender);
            r17_assert_present(&p.random_a, &p.random_a_presence, &random_a);
            r17_assert_null(&p.random_b, &p.random_b_presence, 16);
            r17_assert_null(&p.public_data, &p.public_data_presence, 0);
        }
        other => panic!("NULL-B KEA must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 KIP: NULL nesting records the canonical placeholder + the set
/// nesting bit (the v1 decoder's `(None, true)` arm).
#[test]
fn r18_kip_v1_null_nesting() {
    let registry = r18_registry();
    let mut seed = [0xF2u8, 0xF3, 0xF4];
    let mut kip = CK_KIP_PARAMS {
        pMechanism: std::ptr::null_mut(),
        hKey: 0x43,
        pSeed: seed.as_mut_ptr() as *mut CK_BYTE,
        ulSeedLen: seed.len() as CK_ULONG,
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "kip",
            &mut kip as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_KIP_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::Kip(p)) => {
            assert!(p.mechanism_is_null);
            assert_eq!(*p.mechanism, KipParams::NULL_NESTED_MECHANISM);
            assert_eq!(p.key_handle.0, 0x43);
            r17_assert_present_secret(&p.seed, &p.seed_presence, &seed);
        }
        other => panic!("NULL-nested KIP must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 KIP: present nesting recurses through the v1 router (bit
/// clear) — guarded + pinned to v1: the nested read gathers the global
/// registry/capability snapshots.
#[test]
fn r18_kip_v1_nested_present() {
    let _guard = crate::tests::shim_state_test_guard();
    crate::interface_probe::set_mechanism_parameter_transport_version_for_tests(1);
    ensure_registry();
    let registry = r18_registry();
    let mut nested = kip_nested_rsa_mechanism();
    let mut seed = [0xF5u8];
    let mut kip = CK_KIP_PARAMS {
        pMechanism: &mut nested,
        hKey: 0x44,
        pSeed: seed.as_mut_ptr() as *mut CK_BYTE,
        ulSeedLen: seed.len() as CK_ULONG,
    };
    let params = unsafe {
        r18_read_v1(
            &registry,
            "kip",
            &mut kip as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_KIP_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params;
    crate::interface_probe::set_mechanism_parameter_transport_version_for_tests(0);
    match params {
        Some(CkMechanismParams::Kip(p)) => {
            assert!(!p.mechanism_is_null);
            assert_eq!(p.mechanism.mechanism_type.0, CKM_RSA_PKCS as u64);
            assert_eq!(p.mechanism.params, None, "nested (NULL,0) forwards paramless");
            assert_eq!(p.key_handle.0, 0x44);
            r17_assert_present_secret(&p.seed, &p.seed_presence, &seed);
        }
        other => panic!("nested-present KIP must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 OTP/SP800-108: NULL OTP array records its declared count
/// (counted-array envelope — the legacy conflation to empty is gone).
#[test]
fn r18_otp_v1_null_array() {
    let registry = r18_registry();
    let mut otp = CK_OTP_PARAMS { pParams: std::ptr::null_mut(), ulCount: 5 };
    match unsafe {
        r18_read_v1(
            &registry,
            "otp",
            &mut otp as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_OTP_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::Otp(p)) => {
            r18_assert_null_array(&p.params, &p.params_presence, 5);
        }
        other => panic!("NULL OTP array must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 OTP/SP800-108: count-0 records `Present(empty)` (never
/// conflated with `Null{0}`); over-cap counts fail closed.
#[test]
fn r18_otp_v1_count_zero_and_over_cap() {
    let registry = r18_registry();
    let mut probe =
        CK_OTP_PARAM { type_: 1 as CK_OTP_PARAM_TYPE, pValue: std::ptr::null_mut(), ulValueLen: 0 };
    let mut otp = CK_OTP_PARAMS { pParams: &mut probe, ulCount: 0 };
    match unsafe {
        r18_read_v1(
            &registry,
            "otp",
            &mut otp as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_OTP_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::Otp(p)) => {
            r18_assert_present_empty_array(&p.params, &p.params_presence);
        }
        other => panic!("count-0 OTP array must read Present(empty) under v1, got {other:?}"),
    }

    let mut otp =
        CK_OTP_PARAMS { pParams: &mut probe, ulCount: (MAX_TEMPLATE_COUNT + 1) as CK_ULONG };
    assert_eq!(
        unsafe {
            r18_read_v1(
                &registry,
                "otp",
                &mut otp as *mut _ as CK_VOID_PTR,
                std::mem::size_of::<CK_OTP_PARAMS>() as CK_ULONG,
            )
        },
        Err(CkRv::MECHANISM_PARAM_INVALID),
        "over-cap OTP count must fail closed"
    );
}

/// S2 §8 OTP/SP800-108: element payloads are independent — a NULL
/// element value records that element's `Null` peer instead of
/// rejecting the whole array.
#[test]
fn r18_otp_v1_mixed_element_null() {
    let registry = r18_registry();
    let mut v0 = [0x01u8, 0x02];
    let mut elems = [
        CK_OTP_PARAM {
            type_: 1 as CK_OTP_PARAM_TYPE,
            pValue: v0.as_mut_ptr() as *mut _,
            ulValueLen: v0.len() as CK_ULONG,
        },
        CK_OTP_PARAM { type_: 2 as CK_OTP_PARAM_TYPE, pValue: std::ptr::null_mut(), ulValueLen: 4 },
    ];
    let mut otp = CK_OTP_PARAMS { pParams: elems.as_mut_ptr(), ulCount: elems.len() as CK_ULONG };
    match unsafe {
        r18_read_v1(
            &registry,
            "otp",
            &mut otp as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_OTP_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::Otp(p)) => {
            assert_eq!(p.params.len(), 2);
            assert_eq!(p.params[0].type_, 1);
            r17_assert_present_secret(&p.params[0].value, &p.params[0].value_presence, &v0);
            assert_eq!(p.params[1].type_, 2);
            r17_assert_null_secret(&p.params[1].value, &p.params[1].value_presence, 4);
            assert_eq!(
                p.params_presence,
                PointerArray::present(p.params.clone()),
                "array peer mirrors the elements"
            );
        }
        other => panic!("mixed-NULL OTP array must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 Skipjack: shared-length companions read independently — a
/// NULL PrimeP beside a valid BaseG stays ONE typed message.
#[test]
fn r18_skipjack_private_wrap_v1_null_prime() {
    let registry = r18_registry();
    let mut password = [0x31u8, 0x32];
    let mut public_data = [0x41u8, 0x42, 0x43];
    let mut random_a = [0x51u8, 0x52, 0x53, 0x54];
    let mut base_g = [0x71u8, 0x72];
    let mut subprime_q = [0x81u8, 0x82, 0x83];
    let mut private_wrap = CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
        ulPasswordLen: password.len() as CK_ULONG,
        pPassword: password.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
        pPublicData: public_data.as_mut_ptr(),
        ulPAndGLen: base_g.len() as CK_ULONG,
        ulQLen: subprime_q.len() as CK_ULONG,
        ulRandomLen: random_a.len() as CK_ULONG,
        pRandomA: random_a.as_mut_ptr(),
        pPrimeP: std::ptr::null_mut(),
        pBaseG: base_g.as_mut_ptr(),
        pSubprimeQ: subprime_q.as_mut_ptr(),
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "skipjack_private_wrap",
            &mut private_wrap as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_SKIPJACK_PRIVATE_WRAP_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::SkipjackPrivateWrap(p)) => {
            r17_assert_present_secret(&p.password, &p.password_presence, &password);
            assert_eq!(p.password_length, password.len() as u64);
            r17_assert_present(&p.public_data, &p.public_data_presence, &public_data);
            r17_assert_present(&p.random_a, &p.random_a_presence, &random_a);
            r17_assert_null(&p.prime_p, &p.prime_p_presence, base_g.len() as u64);
            r17_assert_present(&p.base_g, &p.base_g_presence, &base_g);
            r17_assert_present(&p.subprime_q, &p.subprime_q_presence, &subprime_q);
        }
        other => panic!("NULL-prime Skipjack wrap must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 Skipjack: RelayX mixed NULLs (old password NULL+6) stay ONE
/// typed message.
#[test]
fn r18_skipjack_relayx_v1_mixed_nulls() {
    let registry = r18_registry();
    let mut old_wrapped_x = [0x01u8; 8];
    let mut old_public_data = [0x02u8; 4];
    let mut old_random_a = [0x03u8; 4];
    let mut new_password = [0x04u8; 2];
    let mut new_public_data = [0x05u8; 4];
    let mut new_random_a = [0x06u8; 4];
    let mut relayx = CK_SKIPJACK_RELAYX_PARAMS {
        ulOldWrappedXLen: old_wrapped_x.len() as CK_ULONG,
        pOldWrappedX: old_wrapped_x.as_mut_ptr(),
        ulOldPasswordLen: 6,
        pOldPassword: std::ptr::null_mut(),
        ulOldPublicDataLen: old_public_data.len() as CK_ULONG,
        pOldPublicData: old_public_data.as_mut_ptr(),
        ulOldRandomLen: old_random_a.len() as CK_ULONG,
        pOldRandomA: old_random_a.as_mut_ptr(),
        ulNewPasswordLen: new_password.len() as CK_ULONG,
        pNewPassword: new_password.as_mut_ptr(),
        ulNewPublicDataLen: new_public_data.len() as CK_ULONG,
        pNewPublicData: new_public_data.as_mut_ptr(),
        ulNewRandomLen: new_random_a.len() as CK_ULONG,
        pNewRandomA: new_random_a.as_mut_ptr(),
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "skipjack_relayx",
            &mut relayx as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_SKIPJACK_RELAYX_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::SkipjackRelayx(p)) => {
            r17_assert_present_secret(&p.old_wrapped_x, &p.old_wrapped_x_presence, &old_wrapped_x);
            r17_assert_null_secret(&p.old_password, &p.old_password_presence, 6);
            r17_assert_present_secret(
                &p.old_public_data,
                &p.old_public_data_presence,
                &old_public_data,
            );
            r17_assert_present_secret(&p.old_random_a, &p.old_random_a_presence, &old_random_a);
            r17_assert_present_secret(&p.new_password, &p.new_password_presence, &new_password);
            r17_assert_present_secret(
                &p.new_public_data,
                &p.new_public_data_presence,
                &new_public_data,
            );
            r17_assert_present_secret(&p.new_random_a, &p.new_random_a_presence, &new_random_a);
        }
        other => panic!("mixed-NULL Skipjack RelayX must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 OTP/SP800-108: NULL data-params + NULL derived-keys arrays
/// record their declared counts.
#[test]
fn r18_sp800_108_kdf_v1_null_arrays() {
    let registry = r18_registry();
    let mut params = CK_SP800_108_KDF_PARAMS {
        prfType: 1 as CK_SP800_108_PRF_TYPE,
        ulNumberOfDataParams: 2,
        pDataParams: std::ptr::null_mut(),
        ulAdditionalDerivedKeys: 3,
        pAdditionalDerivedKeys: std::ptr::null_mut(),
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "sp800_108_kdf",
            &mut params as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::Sp800108Kdf(p)) => {
            assert_eq!(p.prf_type.0, 1);
            r18_assert_null_array(&p.data_params, &p.data_params_presence, 2);
            r18_assert_null_array(
                &p.additional_derived_keys,
                &p.additional_derived_keys_presence,
                3,
            );
        }
        other => panic!("NULL-array SP800-108 KDF must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 OTP/SP800-108: a NULL `pTemplate` with a declared attribute
/// count records the `Null{count}` template peer with an empty mirror
/// (this test CLOSES the ADR-0010 Scope-2 class-4 `pTemplate` null-bit
/// residual — the legacy arm could only conflate it to empty or flee
/// to `Raw`); a NULL `phKey` sets the output-handle null bit.
#[test]
fn r18_sp800_108_null_template_closes_adr0010_residual() {
    let registry = r18_registry();
    let mut value = [0x09u8, 0x08];
    let mut data_params = [CK_PRF_DATA_PARAM {
        type_: 1 as CK_PRF_DATA_TYPE,
        pValue: value.as_mut_ptr() as *mut _,
        ulValueLen: value.len() as CK_ULONG,
    }];
    let mut derived_keys = [CK_DERIVED_KEY {
        pTemplate: std::ptr::null_mut(),
        ulAttributeCount: 3,
        phKey: std::ptr::null_mut(),
    }];
    let mut params = CK_SP800_108_KDF_PARAMS {
        prfType: 1 as CK_SP800_108_PRF_TYPE,
        ulNumberOfDataParams: data_params.len() as CK_ULONG,
        pDataParams: data_params.as_mut_ptr(),
        ulAdditionalDerivedKeys: derived_keys.len() as CK_ULONG,
        pAdditionalDerivedKeys: derived_keys.as_mut_ptr(),
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "sp800_108_kdf",
            &mut params as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::Sp800108Kdf(p)) => {
            assert_eq!(p.data_params.len(), 1);
            r17_assert_present_secret(
                &p.data_params[0].value,
                &p.data_params[0].value_presence,
                &value,
            );
            assert_eq!(p.additional_derived_keys.len(), 1);
            let dk = &p.additional_derived_keys[0];
            assert!(dk.template.is_empty(), "NULL template mirror stays empty");
            assert_eq!(
                dk.template_presence,
                PointerArray::null_count(3),
                "NULL template peer records the declared attribute count"
            );
            assert!(dk.ph_key_is_null);
            assert_eq!(dk.key_handle.0, 0);
        }
        other => panic!("NULL-template SP800-108 KDF must stay typed under v1, got {other:?}"),
    }
}

/// S2 §8 OTP/SP800-108: feedback KDF with NULL IV + NULL+0 data-params
/// (the count-0 edge records `Null{0}`) + NULL derived keys.
#[test]
fn r18_sp800_108_feedback_v1_iv_null() {
    let registry = r18_registry();
    let mut params = CK_SP800_108_FEEDBACK_KDF_PARAMS {
        prfType: 2 as CK_SP800_108_PRF_TYPE,
        ulNumberOfDataParams: 0,
        pDataParams: std::ptr::null_mut(),
        ulIVLen: 11,
        pIV: std::ptr::null_mut(),
        ulAdditionalDerivedKeys: 1,
        pAdditionalDerivedKeys: std::ptr::null_mut(),
    };
    match unsafe {
        r18_read_v1(
            &registry,
            "sp800_108_feedback_kdf",
            &mut params as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>() as CK_ULONG,
        )
    }
    .expect("read mechanism")
    .params
    {
        Some(CkMechanismParams::Sp800108FeedbackKdf(p)) => {
            assert_eq!(p.prf_type.0, 2);
            r18_assert_null_array(&p.data_params, &p.data_params_presence, 0);
            r17_assert_null(&p.iv, &p.iv_presence, 11);
            r18_assert_null_array(
                &p.additional_derived_keys,
                &p.additional_derived_keys_presence,
                1,
            );
        }
        other => panic!("NULL-IV feedback KDF must stay typed under v1, got {other:?}"),
    }
}

/// R18 closeout: every nested/output tail shape fails closed with
/// `PARAM_INVALID` (never `Raw`) on a short buffer. `tls_mac` is
/// scalar (not nested/output): a short image rides struct-prefix Flat
/// under same-ABI pairs by design (S2 §5 width rule), pinned below.
#[test]
fn r18_tail_short_buffers_fail_closed() {
    let registry = r18_registry();
    // Full-size buffers presented one byte short: the failure is the
    // shape gate, not unreadable memory.
    let cases: &[(&str, usize)] = &[
        ("tls_prf", std::mem::size_of::<CK_TLS_PRF_PARAMS>()),
        ("tls_kdf", std::mem::size_of::<CK_TLS_KDF_PARAMS>()),
        ("ssl3_master_key_derive", std::mem::size_of::<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>()),
        ("tls12_master_key_derive", std::mem::size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>()),
        (
            "tls12_extended_master_key_derive",
            std::mem::size_of::<CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>(),
        ),
        ("ssl3_key_mat", std::mem::size_of::<CK_SSL3_KEY_MAT_PARAMS>()),
        ("wtls_master_key_derive", std::mem::size_of::<CK_WTLS_MASTER_KEY_DERIVE_PARAMS>()),
        ("wtls_prf", std::mem::size_of::<CK_WTLS_PRF_PARAMS>()),
        ("wtls_key_mat", std::mem::size_of::<CK_WTLS_KEY_MAT_PARAMS>()),
        ("kea_derive", std::mem::size_of::<CK_KEA_DERIVE_PARAMS>()),
        ("kip", std::mem::size_of::<CK_KIP_PARAMS>()),
        ("otp", std::mem::size_of::<CK_OTP_PARAMS>()),
        ("skipjack_private_wrap", std::mem::size_of::<CK_SKIPJACK_PRIVATE_WRAP_PARAMS>()),
        ("skipjack_relayx", std::mem::size_of::<CK_SKIPJACK_RELAYX_PARAMS>()),
        ("sp800_108_kdf", std::mem::size_of::<CK_SP800_108_KDF_PARAMS>()),
        ("sp800_108_feedback_kdf", std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>()),
    ];
    assert_eq!(cases.len(), 16, "one short case per nested/output tail shape");
    let mut backing = [0u8; 512];
    for (shape, size) in cases {
        assert!(*size <= backing.len() && *size > 1, "{shape} fixture fits");
        let err = unsafe {
            r18_read_v1(
                &registry,
                shape,
                backing.as_mut_ptr() as CK_VOID_PTR,
                (*size - 1) as CK_ULONG,
            )
        }
        .expect_err("short tail buffer must fail");
        assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID, "{shape} short must fail closed");
    }

    // Scalar `tls_mac`, one byte short: struct-prefix Flat (same-ABI
    // pair), never `Raw`, never the typed reader.
    let short = std::mem::size_of::<CK_TLS_MAC_PARAMS>() - 1;
    match unsafe {
        r18_read_v1(&registry, "tls_mac", backing.as_mut_ptr() as CK_VOID_PTR, short as CK_ULONG)
    }
    .expect("short scalar reads")
    .params
    {
        Some(CkMechanismParams::Flat(p)) => {
            assert_eq!(p.declared_len, short as u64);
        }
        other => panic!("short tls_mac must ride struct-prefix Flat, got {other:?}"),
    }
}

/// R18 legacy pin: the same NULL-seed TLS PRF input rides legacy `Raw`
/// under capability 0 (behavior EXACTLY preserved) and stays typed
/// under v1.
#[test]
fn r18_legacy_capability_tail_behavior_exact() {
    let registry = r18_registry();
    let mut label = [0xD0u8, 0xD1];
    let mut prf = CK_TLS_PRF_PARAMS {
        pSeed: std::ptr::null_mut(),
        ulSeedLen: 7,
        pLabel: label.as_mut_ptr(),
        ulLabelLen: label.len() as CK_ULONG,
        pOutput: std::ptr::null_mut(),
        pulOutputLen: std::ptr::null_mut(),
    };
    let mechanism = r11_mechanism(
        r18_mech("tls_prf"),
        &mut prf as *mut _ as CK_VOID_PTR,
        std::mem::size_of::<CK_TLS_PRF_PARAMS>() as CK_ULONG,
    );
    match unsafe { read_r11_legacy(&mechanism, &registry, Operation::General) }
        .expect("legacy read")
        .params
    {
        Some(CkMechanismParams::Raw(_)) => {}
        other => panic!("NULL-seed TLS PRF must stay legacy Raw, got {other:?}"),
    }
    match unsafe {
        r18_read_v1(
            &registry,
            "tls_prf",
            &mut prf as *mut _ as CK_VOID_PTR,
            std::mem::size_of::<CK_TLS_PRF_PARAMS>() as CK_ULONG,
        )
    }
    .expect("v1 read")
    .params
    {
        Some(CkMechanismParams::TlsPrf(p)) => {
            r17_assert_null_secret(&p.seed, &p.seed_presence, 7);
            assert!(p.output_is_null && p.output_len_is_null);
        }
        other => panic!("NULL-seed TLS PRF must stay typed under v1, got {other:?}"),
    }
}
