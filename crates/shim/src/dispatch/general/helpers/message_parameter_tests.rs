use super::{message_parameter_roundtrip_spec, try_read_message_parameter};
use cryptoki_sys::*;
use pkcs11_proxy_ng_proto::convert::message_params::MessageParameter;
use pkcs11_proxy_ng_types::CkRv;

#[test]
fn null_zero_len_message_parameter_is_absent() {
    let param =
        unsafe { try_read_message_parameter(std::ptr::null(), 0) }.expect("valid null/zero");

    assert!(param.is_none());
}

#[test]
fn null_nonzero_len_message_parameter_is_rejected() {
    let err = unsafe { try_read_message_parameter(std::ptr::null(), 1) }.unwrap_err();

    assert_eq!(err, CkRv::ARGUMENTS_BAD);
}

#[test]
fn oversized_message_parameter_is_rejected_before_reading() {
    let mut byte = 0u8;
    let err = unsafe {
        try_read_message_parameter(
            &mut byte as *mut _ as *const _,
            (super::MAX_MECHANISM_PARAM_STRUCT_LEN + 1) as CK_ULONG,
        )
    }
    .unwrap_err();

    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
}

#[test]
fn raw_message_parameter_preserves_small_unknown_shape() {
    let bytes = [0xA5, 0x5A, 0x01];
    let param =
        unsafe { try_read_message_parameter(bytes.as_ptr() as *const _, bytes.len() as CK_ULONG) }
            .expect("small raw parameter")
            .expect("message parameter should be present");

    assert_eq!(param, MessageParameter::Raw(bytes.to_vec()));
}

#[test]
fn message_roundtrip_spec_rejects_null_nonzero_len() {
    let err = unsafe { message_parameter_roundtrip_spec(std::ptr::null_mut(), 1) }.unwrap_err();

    assert_eq!(err, CkRv::ARGUMENTS_BAD);
}

#[test]
fn message_roundtrip_spec_rejects_oversized_len_before_reading() {
    let mut byte = 0u8;
    let err = unsafe {
        message_parameter_roundtrip_spec(
            &mut byte as *mut _ as *mut _,
            (super::MAX_MECHANISM_PARAM_STRUCT_LEN + 1) as CK_ULONG,
        )
    }
    .unwrap_err();

    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
}

#[test]
fn write_mechanism_output_params_writes_tls12_pversion() {
    // Verify that the shim's writeback function fills in the
    // CK_VERSION buffer pointed at by
    // CK_TLS12_MASTER_KEY_DERIVE_PARAMS.pVersion when the backend
    // returns a Tls12MasterKeyDerive params variant. Without this,
    // applications calling C_DeriveKey on a remote HSM would never
    // learn the negotiated TLS version.
    use pkcs11_proxy_ng_types::{
        CkMechanismParams, CkMechanismType, SslRandomData, Tls12MasterKeyDeriveParams,
    };

    let mut version = CK_VERSION { major: 0, minor: 0 };
    let mut params = CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: std::ptr::null_mut(),
            ulClientRandomLen: 0,
            pServerRandom: std::ptr::null_mut(),
            ulServerRandomLen: 0,
        },
        pVersion: &mut version,
        prfHashMechanism: CkMechanismType::SHA256.0 as _,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::TLS12_MASTER_KEY_DERIVE.0 as _,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
    };

    let mech_out = CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
        random_info: SslRandomData { client_random: vec![], server_random: vec![] },
        version_major: 3,
        version_minor: 3, // TLS 1.2
        prf_hash_mechanism: CkMechanismType::SHA256.0 as _,
    });

    unsafe {
        super::write_mechanism_output_params(&mut mechanism, &mech_out);
    }

    assert_eq!(version.major, 3);
    assert_eq!(version.minor, 3);
}

#[test]
fn write_mechanism_output_params_writes_pbe_init_vector() {
    // C2: the HSM-generated CK_PBE_PARAMS.pInitVector must be written back
    // into the caller's buffer after PBE key generation. Only the IV is
    // written; pPassword/pSalt are left untouched.
    use pkcs11_proxy_ng_types::{CkMechanismParams, CkMechanismType, PbeParams};

    let mut iv_buf = [0u8; 8];
    let password = *b"secret";
    let salt = *b"saltsalt";
    let mut params = CK_PBE_PARAMS {
        pInitVector: iv_buf.as_mut_ptr(),
        pPassword: password.as_ptr() as *mut _,
        ulPasswordLen: password.len() as CK_ULONG,
        pSalt: salt.as_ptr() as *mut _,
        ulSaltLen: salt.len() as CK_ULONG,
        ulIteration: 1000,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::PBE_SHA1_DES3_EDE_CBC.0 as _,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_PBE_PARAMS>() as CK_ULONG,
    };

    let generated_iv = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    let mech_out = CkMechanismParams::Pbe(PbeParams {
        init_vector: generated_iv.clone(),
        password: Vec::new(),
        salt: Vec::new(),
        iteration: 1000,
    });

    unsafe {
        super::write_mechanism_output_params(&mut mechanism, &mech_out);
    }

    // The generated IV landed in the caller's buffer; password/salt intact.
    assert_eq!(&iv_buf[..], generated_iv.as_slice());
    assert_eq!(&password[..], b"secret");
    assert_eq!(&salt[..], b"saltsalt");
}

#[test]
fn write_mechanism_output_params_pbe_safe_when_init_vector_null() {
    // PBA (HMAC key gen) passes pInitVector = NULL — the writeback must be a
    // no-op rather than dereferencing NULL.
    use pkcs11_proxy_ng_types::{CkMechanismParams, CkMechanismType, PbeParams};

    let mut params = CK_PBE_PARAMS {
        pInitVector: std::ptr::null_mut(),
        pPassword: std::ptr::null_mut(),
        ulPasswordLen: 0,
        pSalt: std::ptr::null_mut(),
        ulSaltLen: 0,
        ulIteration: 1,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::PBA_SHA1_WITH_SHA1_HMAC.0 as _,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_PBE_PARAMS>() as CK_ULONG,
    };
    let mech_out = CkMechanismParams::Pbe(PbeParams {
        init_vector: vec![9u8; 8],
        password: Vec::new(),
        salt: Vec::new(),
        iteration: 1,
    });
    // Must not panic / deref NULL.
    unsafe {
        super::write_mechanism_output_params(&mut mechanism, &mech_out);
    }
}

#[test]
fn write_mechanism_output_params_tls12_safe_when_pversion_null() {
    // The TLS12 writeback path is a no-op when pVersion is NULL —
    // matching the spec which says the caller may pass NULL to
    // suppress version output.  Guard against UB.
    use pkcs11_proxy_ng_types::{
        CkMechanismParams, CkMechanismType, SslRandomData, Tls12MasterKeyDeriveParams,
    };

    let mut params = CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: std::ptr::null_mut(),
            ulClientRandomLen: 0,
            pServerRandom: std::ptr::null_mut(),
            ulServerRandomLen: 0,
        },
        pVersion: std::ptr::null_mut(),
        prfHashMechanism: CkMechanismType::SHA256.0 as _,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::TLS12_MASTER_KEY_DERIVE.0 as _,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
    };

    let mech_out = CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
        random_info: SslRandomData { client_random: vec![], server_random: vec![] },
        version_major: 3,
        version_minor: 3,
        prf_hash_mechanism: CkMechanismType::SHA256.0 as _,
    });

    unsafe {
        super::write_mechanism_output_params(&mut mechanism, &mech_out);
    }
    // Did not crash, did not write through NULL.
}

#[test]
fn wtls_master_key_derive_reads_version_byte_and_writes_it_back() {
    use pkcs11_proxy_ng_types::{
        CkMechanismParams, CkMechanismType, WtlsMasterKeyDeriveParams, WtlsRandomData,
    };

    const CKM_WTLS_MASTER_KEY_DERIVE: CK_MECHANISM_TYPE = 0x0000_03D1;

    let mut client_random = [0xA1u8, 0xA2, 0xA3];
    let mut server_random = [0xB1u8, 0xB2];
    let mut version = 1u8;
    let mut params = CK_WTLS_MASTER_KEY_DERIVE_PARAMS {
        DigestMechanism: CkMechanismType::SHA256.0 as _,
        RandomInfo: CK_WTLS_RANDOM_DATA {
            pClientRandom: client_random.as_mut_ptr(),
            ulClientRandomLen: client_random.len() as CK_ULONG,
            pServerRandom: server_random.as_mut_ptr(),
            ulServerRandomLen: server_random.len() as CK_ULONG,
        },
        pVersion: &mut version,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_WTLS_MASTER_KEY_DERIVE,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_WTLS_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
    };

    match unsafe { super::read_mechanism_with_shape(&mechanism, Some("wtls_master_key_derive")) }
        .params
        .expect("wtls params")
    {
        CkMechanismParams::WtlsMasterKeyDerive(params) => {
            assert_eq!(params.digest_mechanism, CkMechanismType::SHA256.0 as _);
            assert_eq!(params.random_info.client_random, client_random);
            assert_eq!(params.random_info.server_random, server_random);
            assert_eq!(params.version, 1);
        }
        other => panic!("unexpected WTLS params: {other:?}"),
    }

    let mech_out = CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
        digest_mechanism: CkMechanismType::SHA256.0 as _,
        random_info: WtlsRandomData {
            client_random: client_random.to_vec(),
            server_random: server_random.to_vec(),
        },
        version: 2,
    });
    unsafe {
        super::write_mechanism_output_params(&mut mechanism, &mech_out);
    }

    assert_eq!(version, 2);
}

#[test]
fn wtls_key_mat_reads_caller_stack_params_and_writes_outputs_back() {
    use pkcs11_proxy_ng_types::{
        CkMechanismParams, CkMechanismType, WtlsKeyMatParams, WtlsRandomData,
    };

    const CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE: CK_MECHANISM_TYPE = 0x0000_03D4;

    let mut client_random = [0xC1u8, 0xC2, 0xC3];
    let mut server_random = [0xD1u8, 0xD2];
    let mut iv = [0u8; 4];
    let mut key_mat_out = CK_WTLS_KEY_MAT_OUT { hMacSecret: 0, hKey: 0, pIV: iv.as_mut_ptr() };
    let mut params = CK_WTLS_KEY_MAT_PARAMS {
        DigestMechanism: CkMechanismType::SHA256.0 as _,
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
        pReturnedKeyMaterial: &mut key_mat_out,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_WTLS_KEY_MAT_PARAMS>() as CK_ULONG,
    };

    match unsafe { super::read_mechanism_with_shape(&mechanism, Some("wtls_key_mat")) }
        .params
        .expect("wtls key material params")
    {
        CkMechanismParams::WtlsKeyMat(params) => {
            assert_eq!(params.digest_mechanism, CkMechanismType::SHA256.0 as _);
            assert_eq!(params.mac_size_bits, 160);
            assert_eq!(params.key_size_bits, 128);
            assert_eq!(params.iv_size_bits, 32);
            assert_eq!(params.sequence_number, 7);
            assert!(params.is_export);
            assert_eq!(params.random_info.client_random, client_random);
            assert_eq!(params.random_info.server_random, server_random);
            assert_eq!(params.mac_secret_handle, 0);
            assert_eq!(params.key_handle, 0);
            assert_eq!(params.iv, [0u8; 4]);
        }
        other => panic!("unexpected WTLS key material params: {other:?}"),
    }

    let mech_out = CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
        digest_mechanism: CkMechanismType::SHA256.0 as _,
        mac_size_bits: 160,
        key_size_bits: 128,
        iv_size_bits: 32,
        sequence_number: 7,
        is_export: true,
        random_info: WtlsRandomData {
            client_random: client_random.to_vec(),
            server_random: server_random.to_vec(),
        },
        mac_secret_handle: 101,
        key_handle: 202,
        iv: vec![0xA1, 0xA2, 0xA3, 0xA4],
    });
    unsafe {
        super::write_mechanism_output_params(&mut mechanism, &mech_out);
    }

    assert_eq!(key_mat_out.hMacSecret, 101);
    assert_eq!(key_mat_out.hKey, 202);
    assert_eq!(iv, [0xA1, 0xA2, 0xA3, 0xA4]);
}

#[test]
fn ssl3_key_mat_reads_caller_stack_params_and_writes_outputs_back() {
    use pkcs11_proxy_ng_types::{
        CkMechanismParams, CkMechanismType, Ssl3KeyMatParams, SslRandomData,
    };

    const CKM_TLS12_KEY_AND_MAC_DERIVE: CK_MECHANISM_TYPE = 0x0000_03E1;

    let mut client_random = [0x11u8, 0x12, 0x13];
    let mut server_random = [0x21u8, 0x22];
    let mut client_iv = [0u8; 4];
    let mut server_iv = [0u8; 4];
    let mut key_mat_out = CK_SSL3_KEY_MAT_OUT {
        hClientMacSecret: 0,
        hServerMacSecret: 0,
        hClientKey: 0,
        hServerKey: 0,
        pIVClient: client_iv.as_mut_ptr(),
        pIVServer: server_iv.as_mut_ptr(),
    };
    let mut params = CK_TLS12_KEY_MAT_PARAMS {
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
        prfHashMechanism: CkMechanismType::SHA256.0 as _,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_TLS12_KEY_AND_MAC_DERIVE,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS12_KEY_MAT_PARAMS>() as CK_ULONG,
    };

    match unsafe { super::read_mechanism_with_shape(&mechanism, Some("ssl3_key_mat")) }
        .params
        .expect("ssl3/tls key material params")
    {
        CkMechanismParams::Ssl3KeyMat(params) => {
            assert_eq!(params.mac_size_bits, 160);
            assert_eq!(params.key_size_bits, 128);
            assert_eq!(params.iv_size_bits, 32);
            assert!(!params.is_export);
            assert_eq!(params.random_info.client_random, client_random);
            assert_eq!(params.random_info.server_random, server_random);
            assert_eq!(params.prf_hash_mechanism, CkMechanismType::SHA256.0 as _);
            assert_eq!(params.client_mac_secret_handle, 0);
            assert_eq!(params.server_mac_secret_handle, 0);
            assert_eq!(params.client_key_handle, 0);
            assert_eq!(params.server_key_handle, 0);
            assert_eq!(params.client_iv, [0u8; 4]);
            assert_eq!(params.server_iv, [0u8; 4]);
        }
        other => panic!("unexpected SSL3/TLS key material params: {other:?}"),
    }

    let mech_out = CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
        mac_size_bits: 160,
        key_size_bits: 128,
        iv_size_bits: 32,
        is_export: false,
        random_info: SslRandomData {
            client_random: client_random.to_vec(),
            server_random: server_random.to_vec(),
        },
        prf_hash_mechanism: CkMechanismType::SHA256.0 as _,
        client_mac_secret_handle: 101,
        server_mac_secret_handle: 102,
        client_key_handle: 201,
        server_key_handle: 202,
        client_iv: vec![0xA1, 0xA2, 0xA3, 0xA4],
        server_iv: vec![0xB1, 0xB2, 0xB3, 0xB4],
    });
    unsafe {
        super::write_mechanism_output_params(&mut mechanism, &mech_out);
    }

    assert_eq!(key_mat_out.hClientMacSecret, 101);
    assert_eq!(key_mat_out.hServerMacSecret, 102);
    assert_eq!(key_mat_out.hClientKey, 201);
    assert_eq!(key_mat_out.hServerKey, 202);
    assert_eq!(client_iv, [0xA1, 0xA2, 0xA3, 0xA4]);
    assert_eq!(server_iv, [0xB1, 0xB2, 0xB3, 0xB4]);
}

/// ADR-0010 Scope 2: a GCM message parameter with ulIvLen = CK_ULONG::MAX must
/// not cause a wild read.  The reader clamps to an empty IV (same behavior as
/// a null pIv) rather than constructing a slice of size usize::MAX.
///
/// Empty-Vec outcome is the deliberate class-5 status quo: embedded-pointer
/// handling in message params is deferred to its own follow-up plan; mechanism
/// arms use the Raw fallback instead.  See ADR-0010 Scope 2 input classes.
#[test]
fn gcm_message_params_unmaterializable_iv_len_yields_empty_not_crash() {
    let tag = [0xAAu8; 16];
    let params = CK_GCM_MESSAGE_PARAMS {
        pIv: std::ptr::dangling_mut::<u8>(),
        ulIvLen: CK_ULONG::MAX,
        ulIvFixedBits: 0,
        ivGenerator: 0,
        pTag: tag.as_ptr() as *mut u8,
        ulTagBits: 128,
    };
    let result =
        unsafe { super::read_gcm_message_params(&params as *const _ as *const std::ffi::c_void) };
    assert!(result.iv.is_empty(), "unmaterializable ulIvLen must yield empty IV, not a wild read");
    // pTag with sane tag_bytes (128/8=16 <= MAX_SERIALIZABLE_BYTES) must still be read.
    assert_eq!(result.tag, vec![0xAAu8; 16]);
}

/// ADR-0010 Scope 2: a GCM message parameter with ulTagBits = CK_ULONG::MAX
/// produces a tag_bytes of ~2^61, which exceeds MAX_SERIALIZABLE_BYTES.  The
/// reader must return an empty tag rather than calling `slice::from_raw_parts`
/// with an absurd length.
///
/// Empty-Vec outcome is the deliberate class-5 status quo: embedded-pointer
/// handling in message params is deferred to its own follow-up plan; mechanism
/// arms use the Raw fallback instead.  See ADR-0010 Scope 2 input classes.
#[test]
fn gcm_message_params_absurd_tag_bits_yields_empty_not_crash() {
    let params = CK_GCM_MESSAGE_PARAMS {
        pIv: std::ptr::null_mut(),
        ulIvLen: 0,
        ulIvFixedBits: 0,
        ivGenerator: 0,
        pTag: std::ptr::dangling_mut::<u8>(),
        ulTagBits: CK_ULONG::MAX,
    };
    let result =
        unsafe { super::read_gcm_message_params(&params as *const _ as *const std::ffi::c_void) };
    assert!(result.tag.is_empty(), "absurd ulTagBits must yield empty tag, not a wild read");
}

/// ADR-0010 Scope 2: CCM message reader — unmaterializable `ulNonceLen` must
/// yield an empty nonce, and unmaterializable `ulMACLen` must yield an empty
/// mac.  Neither should cause a wild read.
#[test]
fn ccm_message_params_unmaterializable_lens_yield_empty_not_crash() {
    // ulNonceLen = CK_ULONG::MAX: dangling pNonce must not be dereferenced.
    let params = CK_CCM_MESSAGE_PARAMS {
        ulDataLen: 16,
        pNonce: std::ptr::dangling_mut::<u8>(),
        ulNonceLen: CK_ULONG::MAX,
        ulNonceFixedBits: 0,
        nonceGenerator: 0,
        pMAC: std::ptr::dangling_mut::<u8>(),
        ulMACLen: CK_ULONG::MAX,
    };
    let result =
        unsafe { super::read_ccm_message_params(&params as *const _ as *const std::ffi::c_void) };
    assert!(
        result.nonce.is_empty(),
        "unmaterializable ulNonceLen must yield empty nonce, not a wild read"
    );
    assert!(
        result.mac.is_empty(),
        "unmaterializable ulMACLen must yield empty mac, not a wild read"
    );
}

/// ADR-0010 Scope 2: Salsa/ChaCha message reader — unmaterializable `ulNonceLen`
/// must yield an empty nonce.  The dangling pNonce must not be dereferenced.
#[test]
fn salsa_chacha_message_params_unmaterializable_nonce_len_yields_empty_not_crash() {
    let tag = [0xBBu8; 16];
    let params = CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS {
        pNonce: std::ptr::dangling_mut::<u8>(),
        ulNonceLen: CK_ULONG::MAX,
        pTag: tag.as_ptr() as *mut u8,
    };
    let result = unsafe {
        super::read_salsa_chacha_message_params(&params as *const _ as *const std::ffi::c_void)
    };
    assert!(
        result.nonce.is_empty(),
        "unmaterializable ulNonceLen must yield empty nonce, not a wild read"
    );
    // pTag with fixed 16-byte length must still be read correctly.
    assert_eq!(result.tag, vec![0xBBu8; 16]);
}
