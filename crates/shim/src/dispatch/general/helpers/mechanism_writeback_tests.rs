//! Transactional mechanism-output tests (T06): every writeback is
//! prepared (validated, no stores) before commit (infallible stores), so
//! malformed daemon output preserves all caller state.
use super::{
    PreparedMechanismOutput, derive_key_post_rpc, generate_key_post_rpc,
    prepare_mechanism_output_params, rv_err, rv_ok, wrap_key_post_rpc,
};
use cryptoki_sys::*;
use pkcs11_proxy_ng_types::{
    CkAttribute, CkMechanismParams, CkMechanismType, CkObjectHandle, CkOutputBufferResult,
    CkOutputBufferSpec, CkRv, GcmParams, SecretBytes, Sp800108DerivedKey, Sp800108KdfParams,
    Tls12MasterKeyDeriveParams, TlsPrfParams, WtlsKeyMatParams, WtlsRandomData,
};

/// Fixtures are built in two steps so nothing moves after its address
/// is taken: first the params struct (as a test-body local), then the
/// `CK_MECHANISM` borrowing it. Returning `(mechanism, params)` by value
/// would leave `pParameter` dangling at the pre-move slot.
fn tls12_params(p_version: *mut CK_VERSION) -> CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
    CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: std::ptr::null_mut(),
            ulClientRandomLen: 0,
            pServerRandom: std::ptr::null_mut(),
            ulServerRandomLen: 0,
        },
        pVersion: p_version,
        prfHashMechanism: 0,
    }
}

fn tls12_mechanism(params: &mut CK_TLS12_MASTER_KEY_DERIVE_PARAMS) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: CKM_TLS12_MASTER_KEY_DERIVE,
        pParameter: params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
    }
}

fn tls12_out(major: u32, minor: u32) -> CkMechanismParams {
    CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
        random_info: pkcs11_proxy_ng_types::SslRandomData {
            client_random: vec![],
            server_random: vec![],
        },
        version_major: major,
        version_minor: minor,
        prf_hash_mechanism: CkMechanismType::SHA256,
    })
}

#[test]
fn transactional_version_second_byte_invalid_preserves_both() {
    // Invalid second version byte: prepare fails and NEITHER caller
    // byte is stored (today's void helper would store major first).
    let mut version = CK_VERSION { major: 0xAA, minor: 0xBB };
    let mut params = tls12_params(&mut version);
    let mut mechanism = tls12_mechanism(&mut params);
    let prepared = unsafe { prepare_mechanism_output_params(&mut mechanism, &tls12_out(3, 256)) };
    assert!(matches!(prepared, Err(CkRv::GENERAL_ERROR)));
    assert_eq!((version.major, version.minor), (0xAA, 0xBB));
}

#[test]
fn transactional_version_valid_writes_both_bytes() {
    // Control: valid output still writes through prepare + commit.
    let mut version = CK_VERSION { major: 0xAA, minor: 0xBB };
    let mut params = tls12_params(&mut version);
    let mut mechanism = tls12_mechanism(&mut params);
    let plan: PreparedMechanismOutput =
        unsafe { prepare_mechanism_output_params(&mut mechanism, &tls12_out(3, 3)) }
            .expect("valid version prepares");
    unsafe { plan.commit() };
    assert_eq!((version.major, version.minor), (3, 3));
}

const SENTINEL_A: CK_OBJECT_HANDLE = 0xA5A5_5A5A;
const SENTINEL_B: CK_OBJECT_HANDLE = 0x5A5A_A5A5;
const SENTINEL_CELL: CK_OBJECT_HANDLE = 0xF0F0_0F0F;

fn sp800_params(entries: &mut [CK_DERIVED_KEY]) -> CK_SP800_108_KDF_PARAMS {
    CK_SP800_108_KDF_PARAMS {
        prfType: 0,
        ulNumberOfDataParams: 0,
        pDataParams: std::ptr::null_mut(),
        ulAdditionalDerivedKeys: entries.len() as CK_ULONG,
        pAdditionalDerivedKeys: entries.as_mut_ptr(),
    }
}

fn sp800_mechanism(params: &mut CK_SP800_108_KDF_PARAMS) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
    }
}

fn sp800_out(handles: &[u64]) -> CkMechanismParams {
    CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
        prf_type: CkMechanismType::SHA256,
        data_params: vec![],
        additional_derived_keys: handles
            .iter()
            .map(|h| Sp800108DerivedKey {
                template: Vec::<CkAttribute>::new(),
                key_handle: CkObjectHandle(*h),
            })
            .collect(),
    })
}

#[test]
fn transactional_sp800_last_handle_checked_before_any_write() {
    // Entries [_,_] with daemon keys [ok, u64::MAX]: on narrow hosts the
    // last handle is unrepresentable, so prepare fails and BOTH caller
    // cells keep their sentinels. On 64-bit hosts u64::MAX fits and both
    // write (the validate-before-commit ordering is host-independent;
    // only the narrowing outcome differs).
    let mut cells = [SENTINEL_A, SENTINEL_B];
    let mut entries = [
        CK_DERIVED_KEY {
            pTemplate: std::ptr::null_mut(),
            ulAttributeCount: 0,
            phKey: &mut cells[0],
        },
        CK_DERIVED_KEY {
            pTemplate: std::ptr::null_mut(),
            ulAttributeCount: 0,
            phKey: &mut cells[1],
        },
    ];
    let mut params = sp800_params(&mut entries);
    let mut mechanism = sp800_mechanism(&mut params);
    let prepared =
        unsafe { prepare_mechanism_output_params(&mut mechanism, &sp800_out(&[11, u64::MAX])) };
    if cfg!(target_pointer_width = "64") {
        let plan = prepared.expect("u64::MAX fits a 64-bit handle");
        unsafe { plan.commit() };
        assert_eq!(cells, [11, CK_OBJECT_HANDLE::MAX]);
    } else {
        assert!(matches!(prepared, Err(CkRv::GENERAL_ERROR)));
        assert_eq!(cells, [SENTINEL_A, SENTINEL_B]);
    }
}

#[test]
fn transactional_sp800_extra_daemon_keys_rejected_without_writes() {
    // Caller offered 1 slot but the daemon returned 2 keys: prepare
    // fails before the first store on every host width.
    let mut cell = SENTINEL_A;
    let mut entry =
        CK_DERIVED_KEY { pTemplate: std::ptr::null_mut(), ulAttributeCount: 0, phKey: &mut cell };
    let params = CK_SP800_108_KDF_PARAMS {
        prfType: 0,
        ulNumberOfDataParams: 0,
        pDataParams: std::ptr::null_mut(),
        ulAdditionalDerivedKeys: 1,
        pAdditionalDerivedKeys: &mut entry,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: &params as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
    };
    let prepared =
        unsafe { prepare_mechanism_output_params(&mut mechanism, &sp800_out(&[11, 12])) };
    assert!(matches!(prepared, Err(CkRv::GENERAL_ERROR)));
    assert_eq!(cell, SENTINEL_A);
}

fn gcm_params(iv_buf: &mut [u8; 12]) -> CK_GCM_PARAMS {
    CK_GCM_PARAMS {
        pIv: iv_buf.as_mut_ptr(),
        ulIvLen: iv_buf.len() as CK_ULONG,
        ulIvBits: 96,
        pAAD: std::ptr::null_mut(),
        ulAADLen: 0,
        ulTagBits: 128,
    }
}

fn gcm_mechanism(params: &mut CK_GCM_PARAMS) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    }
}

#[test]
fn transactional_gcm_overlong_daemon_iv_rejected() {
    // A daemon IV longer than the caller capacity is malformed output,
    // not something to truncate: the buffer, length, and tag bits are
    // all preserved (silent IV truncation would corrupt crypto).
    let mut iv_buf = [0xCCu8; 12];
    let mut params = gcm_params(&mut iv_buf);
    let mut mechanism = gcm_mechanism(&mut params);
    let out = CkMechanismParams::Gcm(GcmParams {
        iv: vec![0xD0; 16],
        iv_bits: 128,
        iv_buffer_len: 16,
        aad: Vec::new().into(),
        tag_bits: 96,
        iv_null: false,
        aad_null: false,
    });
    let prepared = unsafe { prepare_mechanism_output_params(&mut mechanism, &out) };
    assert!(matches!(prepared, Err(CkRv::GENERAL_ERROR)));
    assert_eq!(iv_buf, [0xCC; 12]);
}

#[test]
fn transactional_null_and_unshaped_mechanism_are_noop() {
    let out = tls12_out(3, 3);
    let plan = unsafe { prepare_mechanism_output_params(std::ptr::null_mut(), &out) }
        .expect("null mechanism prepares as no-op");
    unsafe { plan.commit() };
    // A variant without output params prepares empty against any shape.
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let noop =
        CkMechanismParams::MacGeneral(pkcs11_proxy_ng_types::MacGeneralParams { mac_length: 16 });
    let plan = unsafe { prepare_mechanism_output_params(&mut mechanism, &noop) }
        .expect("unshaped variant prepares as no-op");
    unsafe { plan.commit() };
}

fn wrap_byte_fixtures() -> (CkOutputBufferSpec, CkOutputBufferResult, [u8; 4], CK_ULONG) {
    let spec =
        CkOutputBufferSpec { buffer_present: true, buffer_len: 4, length_pointer_null: false };
    let result = CkOutputBufferResult {
        ck_rv: CkRv::OK,
        returned_len: Some(4),
        value: Some(SecretBytes::copy_from_slice(b"test")),
    };
    (spec, result, [0xE0; 4], 4)
}

#[test]
fn transactional_wrap_malformed_mechanism_preserves_bytes_and_length() {
    // Malformed mechanism output fails the call BEFORE the byte plan
    // writes: wrap bytes, wrap length, and mechanism fields untouched.
    let (spec, result, mut wrap_buf, mut wrap_len) = wrap_byte_fixtures();
    let mut version = CK_VERSION { major: 0xAA, minor: 0xBB };
    let mut params = tls12_params(&mut version);
    let mut mechanism = tls12_mechanism(&mut params);
    let bad_mech = tls12_out(3, 256);
    let rv = unsafe {
        wrap_key_post_rpc(
            &spec,
            &result,
            Some(&bad_mech),
            &mut mechanism,
            wrap_buf.as_mut_ptr(),
            &mut wrap_len,
        )
    };
    assert_eq!(rv, rv_err(CkRv::GENERAL_ERROR));
    assert_eq!(wrap_buf, [0xE0; 4]);
    assert_eq!(wrap_len, 4);
    assert_eq!((version.major, version.minor), (0xAA, 0xBB));
}

#[test]
fn transactional_wrap_malformed_bytes_preserve_mechanism_fields() {
    // Malformed byte output (length/value mismatch) fails before EITHER
    // channel writes, even with valid mechanism output waiting.
    let (spec, _result, mut wrap_buf, mut wrap_len) = wrap_byte_fixtures();
    let bad_result = CkOutputBufferResult {
        ck_rv: CkRv::OK,
        returned_len: Some(4),
        value: Some(SecretBytes::copy_from_slice(b"hello")),
    };
    let mut version = CK_VERSION { major: 0xAA, minor: 0xBB };
    let mut params = tls12_params(&mut version);
    let mut mechanism = tls12_mechanism(&mut params);
    let good_mech = tls12_out(3, 3);
    let rv = unsafe {
        wrap_key_post_rpc(
            &spec,
            &bad_result,
            Some(&good_mech),
            &mut mechanism,
            wrap_buf.as_mut_ptr(),
            &mut wrap_len,
        )
    };
    assert_eq!(rv, rv_err(CkRv::DEVICE_ERROR));
    assert_eq!(wrap_buf, [0xE0; 4]);
    assert_eq!(wrap_len, 4);
    assert_eq!((version.major, version.minor), (0xAA, 0xBB));
}

#[test]
fn transactional_wrap_valid_writes_both_channels() {
    // Control: valid byte + mechanism outputs both land.
    let (spec, result, mut wrap_buf, mut wrap_len) = wrap_byte_fixtures();
    let mut version = CK_VERSION { major: 0xAA, minor: 0xBB };
    let mut params = tls12_params(&mut version);
    let mut mechanism = tls12_mechanism(&mut params);
    let good_mech = tls12_out(3, 3);
    let rv = unsafe {
        wrap_key_post_rpc(
            &spec,
            &result,
            Some(&good_mech),
            &mut mechanism,
            wrap_buf.as_mut_ptr(),
            &mut wrap_len,
        )
    };
    assert_eq!(rv, rv_ok());
    assert_eq!(wrap_buf, *b"test");
    assert_eq!(wrap_len, 4);
    assert_eq!((version.major, version.minor), (3, 3));
}

#[test]
fn transactional_derive_missing_handle_publishes_nothing() {
    // Success RV but no required handle: GENERAL_ERROR with the
    // mechanism fields AND the handle cell untouched.
    let mut version = CK_VERSION { major: 0xAA, minor: 0xBB };
    let mut params = tls12_params(&mut version);
    let mut mechanism = tls12_mechanism(&mut params);
    let good_mech = tls12_out(3, 3);
    let mut cell = SENTINEL_CELL;
    let rv =
        unsafe { derive_key_post_rpc(CkRv::OK, None, Some(&good_mech), &mut mechanism, &mut cell) };
    assert_eq!(rv, rv_err(CkRv::GENERAL_ERROR));
    assert_eq!((version.major, version.minor), (0xAA, 0xBB));
    assert_eq!(cell, SENTINEL_CELL);
}

#[test]
fn transactional_derive_valid_writes_mechanism_and_handle() {
    // Control: valid derive output writes mechanism fields + handle.
    let mut version = CK_VERSION { major: 0xAA, minor: 0xBB };
    let mut params = tls12_params(&mut version);
    let mut mechanism = tls12_mechanism(&mut params);
    let good_mech = tls12_out(3, 3);
    let mut cell = 0;
    let rv = unsafe {
        derive_key_post_rpc(
            CkRv::OK,
            Some(CkObjectHandle(77)),
            Some(&good_mech),
            &mut mechanism,
            &mut cell,
        )
    };
    assert_eq!(rv, rv_ok());
    assert_eq!((version.major, version.minor), (3, 3));
    assert_eq!(cell, 77);
}

#[test]
fn transactional_derive_provider_error_preserves_rv_without_writes() {
    // Provider error with malformed mechanism output: the provider RV
    // wins (never masked), and nothing is written.
    let mut version = CK_VERSION { major: 0xAA, minor: 0xBB };
    let mut params = tls12_params(&mut version);
    let mut mechanism = tls12_mechanism(&mut params);
    let bad_mech = tls12_out(3, 256);
    let mut cell = SENTINEL_CELL;
    let rv = unsafe {
        derive_key_post_rpc(CkRv::DEVICE_ERROR, None, Some(&bad_mech), &mut mechanism, &mut cell)
    };
    assert_eq!(rv, rv_err(CkRv::DEVICE_ERROR));
    assert_eq!((version.major, version.minor), (0xAA, 0xBB));
    assert_eq!(cell, SENTINEL_CELL);
}

#[test]
fn transactional_generate_malformed_mechanism_writes_nothing() {
    // PBE IV longer than 8 bytes is malformed: no IV bytes and no
    // handle write.
    let mut iv_buf = [0xC1u8; 8];
    let params = CK_PBE_PARAMS {
        pInitVector: iv_buf.as_mut_ptr(),
        pPassword: std::ptr::null_mut(),
        ulPasswordLen: 0,
        pSalt: std::ptr::null_mut(),
        ulSaltLen: 0,
        ulIteration: 1,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_PBE_SHA1_DES3_EDE_CBC,
        pParameter: &params as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_PBE_PARAMS>() as CK_ULONG,
    };
    let bad_mech = CkMechanismParams::Pbe(pkcs11_proxy_ng_types::PbeParams {
        init_vector: SecretBytes::copy_from_slice(&[0xD2; 12]),
        password: SecretBytes::copy_from_slice(&[]),
        salt: SecretBytes::copy_from_slice(&[]),
        iteration: 1,
    });
    let mut cell = 0;
    let rv = unsafe {
        generate_key_post_rpc(CkObjectHandle(78), Some(&bad_mech), &mut mechanism, &mut cell)
    };
    assert_eq!(rv, rv_err(CkRv::GENERAL_ERROR));
    assert_eq!(iv_buf, [0xC1; 8]);
    assert_eq!(cell, 0);
}

#[test]
fn transactional_wtls_keymat_overlong_iv_preserves_handles_and_iv() {
    // ulIVSizeInBits = 64 gives an 8-byte IV capacity; a 12-byte daemon
    // IV is malformed, so prepare fails and the handle cells plus the
    // IV buffer keep their sentinels (no partial handle writes).
    let mut iv_buf = [0xE1u8; 8];
    let mut keymat_out =
        CK_WTLS_KEY_MAT_OUT { hMacSecret: SENTINEL_A, hKey: SENTINEL_B, pIV: iv_buf.as_mut_ptr() };
    let mut params = CK_WTLS_KEY_MAT_PARAMS {
        DigestMechanism: CKM_SHA256,
        ulMacSizeInBits: 128,
        ulKeySizeInBits: 128,
        ulIVSizeInBits: 64,
        ulSequenceNumber: 0,
        bIsExport: CK_FALSE,
        RandomInfo: CK_WTLS_RANDOM_DATA {
            pClientRandom: std::ptr::null_mut(),
            ulClientRandomLen: 0,
            pServerRandom: std::ptr::null_mut(),
            ulServerRandomLen: 0,
        },
        pReturnedKeyMaterial: &mut keymat_out,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_WTLS_KEY_MAT_PARAMS>() as CK_ULONG,
    };
    let bad_mech = CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
        digest_mechanism: CkMechanismType::SHA256,
        mac_size_bits: 128,
        key_size_bits: 128,
        iv_size_bits: 64,
        sequence_number: 0,
        is_export: false,
        random_info: WtlsRandomData { client_random: vec![], server_random: vec![] },
        mac_secret_handle: CkObjectHandle(11),
        key_handle: CkObjectHandle(12),
        iv: SecretBytes::copy_from_slice(&[0xE2; 12]),
    });
    let prepared = unsafe { prepare_mechanism_output_params(&mut mechanism, &bad_mech) };
    assert!(matches!(prepared, Err(CkRv::GENERAL_ERROR)));
    assert_eq!((keymat_out.hMacSecret, keymat_out.hKey), (SENTINEL_A, SENTINEL_B));
    assert_eq!(iv_buf, [0xE1; 8]);
}

#[test]
fn transactional_tls_prf_overlong_output_preserves_buffer_and_len() {
    // Caller offers a 16-byte PRF buffer; 20 daemon bytes are malformed,
    // so neither the buffer nor the length cell is touched.
    let mut out_buf = [0xF1u8; 16];
    let mut out_len: CK_ULONG = 16;
    let mut params = CK_TLS_PRF_PARAMS {
        pSeed: std::ptr::null_mut(),
        ulSeedLen: 0,
        pLabel: std::ptr::null_mut(),
        ulLabelLen: 0,
        pOutput: out_buf.as_mut_ptr(),
        pulOutputLen: &mut out_len,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_TLS_PRF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS_PRF_PARAMS>() as CK_ULONG,
    };
    let bad_mech = CkMechanismParams::TlsPrf(TlsPrfParams {
        seed: SecretBytes::copy_from_slice(&[]),
        label: SecretBytes::copy_from_slice(&[]),
        output_len: 16,
        output: SecretBytes::copy_from_slice(&[0xF2; 20]),
    });
    let prepared = unsafe { prepare_mechanism_output_params(&mut mechanism, &bad_mech) };
    assert!(matches!(prepared, Err(CkRv::GENERAL_ERROR)));
    assert_eq!(out_buf, [0xF1; 16]);
    assert_eq!(out_len, 16);
}
