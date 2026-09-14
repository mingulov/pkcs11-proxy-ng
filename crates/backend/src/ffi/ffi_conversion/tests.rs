//! Unit tests for the conversion edge (all modules cfg(test)-gated).

// The inner test modules reference conversion items as `super::X`,
// resolving through this glob; the lint cannot see that indirection.
#[allow(unused_imports)]
use super::*;

#[cfg(test)]
mod mechanism_to_ffi_tests {
    use super::mechanism_to_ffi;
    use pkcs11_proxy_ng_types::{
        AesCmacKeyDerivationParams, AesCtrParams, CkMechanism, CkMechanismParams, CkMechanismType,
        CkRv, DilithiumParams, EciesParams, ExtractParams, GcmParams, HdKeyDeriveParams, IvParams,
        KeyDerivationStringData, KmacParams, KyberParams, MuGenParams, ObjectHandleParam,
        PbeParams, Pkcs5Pbkd2Params, RawMechanismParams, RsaPkcsOaepParams, RsaPkcsPssParams,
        SignAdditionalContext, Ssl3KeyMatParams, SslRandomData, VendorObjectExtractParams,
        VendorObjectInsertParams, WtlsKeyMatParams, WtlsMasterKeyDeriveParams, WtlsRandomData,
    };

    fn convert(mechanism_type: CkMechanismType, params: CkMechanismParams) -> super::FfiMechanism {
        mechanism_to_ffi(&CkMechanism { mechanism_type, params: Some(params) })
            .expect("mechanism converts to ffi")
    }

    #[test]
    fn mechanism_type_wider_than_native_is_rejected_not_truncated() {
        // 0x1_0000_0000 | CKM_AES_ECB would truncate to CKM_AES_ECB on
        // a narrow host - the backend would EXECUTE a different
        // mechanism than the client requested. Reject instead (D4).
        let mech =
            CkMechanism { mechanism_type: CkMechanismType(0x1_0000_0000 + 0x1081), params: None };
        let result = mechanism_to_ffi(&mech);
        if std::mem::size_of::<cryptoki_sys::CK_ULONG>() == 4 {
            assert_eq!(result.err(), Some(CkRv::FUNCTION_FAILED));
        } else {
            assert!(result.is_ok(), "wide host passes the value through unchanged");
        }
    }

    #[test]
    fn ulong_mechanism_scalar_wider_than_native_is_rejected_not_truncated() {
        // D4 (ADR-0011): a wire u64 scalar that does not fit the host's
        // native CK_ULONG must reject loudly, never truncate (the low
        // word here is 1 — truncation would fabricate salt_len = 1).
        let mech = CkMechanism {
            mechanism_type: CkMechanismType::RSA_PKCS,
            params: Some(CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
                hash_alg: CkMechanismType::SHA256,
                mgf: 2,
                salt_len: 0x1_0000_0001,
            })),
        };
        let result = mechanism_to_ffi(&mech);
        if std::mem::size_of::<cryptoki_sys::CK_ULONG>() == 4 {
            assert_eq!(result.err(), Some(CkRv::FUNCTION_FAILED));
        } else {
            assert!(result.is_ok(), "wide host passes the value through unchanged");
        }
    }

    #[test]
    fn unsupported_mechanism_params_are_rejected_by_backend_ffi() {
        let parameterless = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
        let cases = [
            ("Raw", CkMechanismParams::Raw(RawMechanismParams { data: vec![0x01, 0x02] })),
            (
                "Ecies",
                CkMechanismParams::Ecies(EciesParams {
                    derivation_mechanism: Box::new(parameterless.clone()),
                    encryption_mechanism: Box::new(parameterless.clone()),
                    mac_mechanism: Box::new(parameterless.clone()),
                    shared_data: vec![0x03],
                }),
            ),
            (
                "AesCmacKeyDerivation",
                CkMechanismParams::AesCmacKeyDerivation(AesCmacKeyDerivationParams {
                    context: vec![0x04],
                    label: vec![0x05],
                }),
            ),
            ("Dilithium", CkMechanismParams::Dilithium(DilithiumParams { version: 1, mode: 2 })),
            (
                "Kyber",
                CkMechanismParams::Kyber(KyberParams {
                    version: 3,
                    mode: 4,
                    secret_handle: 5,
                    shared_data: vec![0x06],
                    blob: vec![0x07],
                }),
            ),
            (
                "HdKeyDerive",
                CkMechanismParams::HdKeyDerive(HdKeyDeriveParams {
                    derive_type: 8,
                    child_key_index: 9,
                    chain_code: vec![0x0A],
                    version: 10,
                }),
            ),
            (
                "VendorObjectExtract",
                CkMechanismParams::VendorObjectExtract(VendorObjectExtractParams {
                    format: 11,
                    context: vec![0x0C],
                }),
            ),
            (
                "VendorObjectInsert",
                CkMechanismParams::VendorObjectInsert(VendorObjectInsertParams {
                    format: 12,
                    context: vec![0x0D],
                    object_data: vec![0x0E],
                }),
            ),
        ];

        for (name, params) in cases {
            let mechanism =
                CkMechanism { mechanism_type: CkMechanismType(0x8000_0000), params: Some(params) };
            match mechanism_to_ffi(&mechanism) {
                Err(err) => assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID, "{name}"),
                Ok(_) => panic!("{name} should be rejected before backend FFI reconstruction"),
            }
        }
    }

    #[test]
    fn pss_params_reconstruct_c_struct() {
        let ffi = convert(
            CkMechanismType::RSA_PKCS_PSS,
            CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
                hash_alg: CkMechanismType::SHA256,
                mgf: 1,
                salt_len: 32,
            }),
        );

        assert_eq!(
            ffi.ck_mechanism().ulParameterLen,
            std::mem::size_of::<cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS>() as cryptoki_sys::CK_ULONG
        );
        let pss = unsafe {
            &*(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS)
        };
        assert_eq!(pss.hashAlg, CkMechanismType::SHA256.0 as cryptoki_sys::CK_MECHANISM_TYPE);
        assert_eq!(pss.mgf, 1);
        assert_eq!(pss.sLen, 32);
    }

    #[test]
    fn oaep_params_reconstruct_c_struct_and_source_data() {
        let ffi = convert(
            CkMechanismType::RSA_PKCS_OAEP,
            CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
                hash_alg: CkMechanismType::SHA256,
                mgf: 1,
                source: 1,
                source_data: vec![0xA0, 0xA1, 0xA2],
            }),
        );

        assert_eq!(
            ffi.ck_mechanism().ulParameterLen,
            std::mem::size_of::<cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS>() as cryptoki_sys::CK_ULONG
        );
        let oaep = unsafe {
            &*(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS)
        };
        assert_eq!(oaep.hashAlg, CkMechanismType::SHA256.0 as cryptoki_sys::CK_MECHANISM_TYPE);
        assert_eq!(oaep.mgf, 1);
        assert_eq!(oaep.source, 1);
        assert_eq!(oaep.ulSourceDataLen, 3);
        let source = unsafe {
            std::slice::from_raw_parts(oaep.pSourceData as *const u8, oaep.ulSourceDataLen as usize)
        };
        assert_eq!(source, [0xA0, 0xA1, 0xA2]);
    }

    #[test]
    fn gcm_params_reconstruct_c_struct_and_buffers() {
        let ffi = convert(
            CkMechanismType::AES_GCM,
            CkMechanismParams::Gcm(GcmParams {
                iv: vec![0x10; 12],
                iv_bits: 96,
                iv_buffer_len: 12,
                aad: vec![0xAA, 0xBB, 0xCC],
                tag_bits: 128,
            }),
        );

        assert_eq!(
            ffi.ck_mechanism().ulParameterLen,
            std::mem::size_of::<cryptoki_sys::CK_GCM_PARAMS>() as cryptoki_sys::CK_ULONG
        );
        let gcm =
            unsafe { &*(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_GCM_PARAMS) };
        assert_eq!(gcm.ulIvLen, 12);
        assert_eq!(gcm.ulIvBits, 96);
        assert_eq!(gcm.ulAADLen, 3);
        assert_eq!(gcm.ulTagBits, 128);
        let iv = unsafe { std::slice::from_raw_parts(gcm.pIv, gcm.ulIvLen as usize) };
        let aad = unsafe { std::slice::from_raw_parts(gcm.pAAD, gcm.ulAADLen as usize) };
        assert_eq!(iv, [0x10; 12]);
        assert_eq!(aad, [0xAA, 0xBB, 0xCC]);
    }

    // Row 7 (C3M.6 order item 7): classic-GCM IV lengths must round-trip
    // exactly — the provider-visible ulIvLen always names the caller input
    // length (zero selects provider-generated IVs) while the retained buffer
    // keeps max(input, iv_buffer_len) writable bytes. Lengths here span
    // sub-block, block, and multi-block IVs on every topology.
    #[test]
    fn gcm_iv_length_sweep_preserves_lengths_and_buffer_capacity() {
        for (iv_len, buffer_len) in
            [(0usize, 12), (1, 1), (7, 8), (8, 8), (12, 12), (16, 16), (24, 32)]
        {
            let ffi = convert(
                CkMechanismType::AES_GCM,
                CkMechanismParams::Gcm(GcmParams {
                    iv: vec![0x5A; iv_len],
                    iv_bits: 96,
                    iv_buffer_len: buffer_len as u64,
                    aad: Vec::new(),
                    tag_bits: 128,
                }),
            );
            let gcm =
                unsafe { &*(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_GCM_PARAMS) };
            assert_eq!(gcm.ulIvLen as usize, iv_len, "provider-visible IV length");
            let retained = match ffi.output_params() {
                Some(CkMechanismParams::Gcm(params)) => params,
                other => panic!("unexpected output params: {other:?}"),
            };
            assert_eq!(retained.iv.len(), iv_len, "output IV names the input bytes");
            assert_eq!(
                retained.iv_buffer_len as usize,
                iv_len.max(buffer_len),
                "retained buffer keeps generated-IV capacity"
            );
            if iv_len == 0 {
                assert!(gcm.pIv.is_null() == (buffer_len == 0));
            } else {
                assert!(!gcm.pIv.is_null());
            }
        }
    }

    // Row 7: an absurd iv_buffer_len must reject before any backing buffer is
    // allocated, on every width topology.
    #[test]
    fn gcm_absurd_iv_buffer_len_rejects_without_allocating() {
        let result = mechanism_to_ffi(&CkMechanism {
            mechanism_type: CkMechanismType::AES_GCM,
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv: Vec::new(),
                iv_bits: 96,
                iv_buffer_len: u64::MAX,
                aad: Vec::new(),
                tag_bits: 128,
            })),
        });
        assert_eq!(result.err(), Some(CkRv::MECHANISM_PARAM_INVALID));
    }

    // E1: the PBE/PBKDF2 password is held in the FFI backing via `Zeroizing`
    // (wiped on drop). These guard that wrapping the password in `Zeroizing`
    // did not break the C-struct contract — the pointer must still address the
    // correct password bytes while the `FfiMechanism` is alive.
    #[test]
    fn pbe_params_password_reaches_c_struct_through_zeroizing_backing() {
        let password = vec![0xAB, 0xCD, 0xEF, 0x12, 0x34];
        let ffi = convert(
            CkMechanismType(0x0000_03A1), // CKM_PBE_MD5_DES_CBC
            CkMechanismParams::Pbe(PbeParams {
                init_vector: vec![0x01; 8],
                password: password.clone(),
                salt: vec![0x02; 4],
                iteration: 1000,
            }),
        );
        let pbe =
            unsafe { &*(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_PBE_PARAMS) };
        assert_eq!(pbe.ulPasswordLen, password.len() as cryptoki_sys::CK_ULONG);
        assert_eq!(pbe.ulIteration, 1000);
        let pass = unsafe { std::slice::from_raw_parts(pbe.pPassword, pbe.ulPasswordLen as usize) };
        assert_eq!(pass, password.as_slice());
    }

    #[test]
    fn pkcs5_pbkd2_password_reaches_c_struct_through_zeroizing_backing() {
        let password = vec![0x55, 0x66, 0x77];
        let ffi = convert(
            CkMechanismType(0x0000_03B0), // CKM_PKCS5_PBKD2
            CkMechanismParams::Pkcs5Pbkd2(Pkcs5Pbkd2Params {
                salt_source: 1,
                salt_source_data: vec![0x09; 8],
                iterations: 2048,
                prf: 2,
                prf_data: vec![],
                password: password.clone(),
            }),
        );
        let p = unsafe {
            &*(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_PKCS5_PBKD2_PARAMS2)
        };
        assert_eq!(p.ulPasswordLen, password.len() as cryptoki_sys::CK_ULONG);
        let pass = unsafe { std::slice::from_raw_parts(p.pPassword, p.ulPasswordLen as usize) };
        assert_eq!(pass, password.as_slice());
    }

    #[test]
    fn gcm_generated_iv_keeps_writable_buffer_with_zero_input_len() {
        let ffi = convert(
            CkMechanismType::AES_GCM,
            CkMechanismParams::Gcm(GcmParams {
                iv: Vec::new(),
                iv_bits: 96,
                iv_buffer_len: 12,
                aad: Vec::new(),
                tag_bits: 128,
            }),
        );

        let gcm =
            unsafe { &mut *(ffi.ck_mechanism().pParameter as *mut cryptoki_sys::CK_GCM_PARAMS) };
        assert!(!gcm.pIv.is_null());
        assert_eq!(gcm.ulIvLen, 0);
        assert_eq!(gcm.ulIvBits, 96);

        let generated = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        unsafe {
            std::ptr::copy_nonoverlapping(generated.as_ptr(), gcm.pIv, generated.len());
        }
        gcm.ulIvLen = generated.len() as cryptoki_sys::CK_ULONG;

        match ffi.output_params() {
            Some(CkMechanismParams::Gcm(params)) => {
                assert_eq!(params.iv, generated);
                assert_eq!(params.iv_buffer_len, 12);
                assert_eq!(params.iv_bits, 96);
                assert_eq!(params.tag_bits, 128);
            }
            other => panic!("unexpected output params: {other:?}"),
        }
    }

    #[test]
    fn wtls_master_key_derive_output_params_surface_mutated_version_byte() {
        const CKM_WTLS_MASTER_KEY_DERIVE: CkMechanismType = CkMechanismType(0x0000_03D1);

        let ffi = convert(
            CKM_WTLS_MASTER_KEY_DERIVE,
            CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
                digest_mechanism: CkMechanismType::SHA256.0,
                random_info: WtlsRandomData {
                    client_random: vec![0xA1, 0xA2],
                    server_random: vec![0xB1, 0xB2],
                },
                version: 1,
            }),
        );

        let wtls = unsafe {
            &mut *(ffi.ck_mechanism().pParameter
                as *mut cryptoki_sys::CK_WTLS_MASTER_KEY_DERIVE_PARAMS)
        };
        assert!(!wtls.pVersion.is_null());
        unsafe {
            *wtls.pVersion = 2;
        }

        match ffi.output_params() {
            Some(CkMechanismParams::WtlsMasterKeyDerive(params)) => {
                assert_eq!(params.digest_mechanism, CkMechanismType::SHA256.0);
                assert_eq!(params.random_info.client_random, [0xA1, 0xA2]);
                assert_eq!(params.random_info.server_random, [0xB1, 0xB2]);
                assert_eq!(params.version, 2);
            }
            other => panic!("unexpected output params: {other:?}"),
        }
    }

    #[test]
    fn wtls_key_mat_output_params_surface_mutated_handles_and_iv() {
        const CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE: CkMechanismType = CkMechanismType(0x0000_03D4);

        let ffi = convert(
            CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
            CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
                digest_mechanism: CkMechanismType::SHA256.0,
                mac_size_bits: 160,
                key_size_bits: 128,
                iv_size_bits: 32,
                sequence_number: 7,
                is_export: true,
                random_info: WtlsRandomData {
                    client_random: vec![0xC1, 0xC2],
                    server_random: vec![0xD1, 0xD2],
                },
                mac_secret_handle: 0,
                key_handle: 0,
                iv: Vec::new(),
            }),
        );

        let wtls = unsafe {
            &mut *(ffi.ck_mechanism().pParameter as *mut cryptoki_sys::CK_WTLS_KEY_MAT_PARAMS)
        };
        let key_mat_out = unsafe { &mut *wtls.pReturnedKeyMaterial };
        assert!(!key_mat_out.pIV.is_null());
        key_mat_out.hMacSecret = 101;
        key_mat_out.hKey = 202;
        unsafe {
            std::ptr::copy_nonoverlapping([0xA1, 0xA2, 0xA3, 0xA4].as_ptr(), key_mat_out.pIV, 4);
        }

        match ffi.output_params() {
            Some(CkMechanismParams::WtlsKeyMat(params)) => {
                assert_eq!(params.digest_mechanism, CkMechanismType::SHA256.0);
                assert_eq!(params.mac_size_bits, 160);
                assert_eq!(params.key_size_bits, 128);
                assert_eq!(params.iv_size_bits, 32);
                assert_eq!(params.sequence_number, 7);
                assert!(params.is_export);
                assert_eq!(params.random_info.client_random, [0xC1, 0xC2]);
                assert_eq!(params.random_info.server_random, [0xD1, 0xD2]);
                assert_eq!(params.mac_secret_handle, 101);
                assert_eq!(params.key_handle, 202);
                assert_eq!(params.iv, [0xA1, 0xA2, 0xA3, 0xA4]);
            }
            other => panic!("unexpected output params: {other:?}"),
        }
    }

    #[test]
    fn ssl3_key_mat_output_params_surface_mutated_handles_and_ivs() {
        const CKM_SSL3_KEY_AND_MAC_DERIVE: CkMechanismType = CkMechanismType(0x0000_0372);

        let ffi = convert(
            CKM_SSL3_KEY_AND_MAC_DERIVE,
            CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
                mac_size_bits: 160,
                key_size_bits: 128,
                iv_size_bits: 32,
                is_export: false,
                random_info: SslRandomData {
                    client_random: vec![0x11, 0x12],
                    server_random: vec![0x21, 0x22],
                },
                prf_hash_mechanism: 0,
                client_mac_secret_handle: 0,
                server_mac_secret_handle: 0,
                client_key_handle: 0,
                server_key_handle: 0,
                client_iv: Vec::new(),
                server_iv: Vec::new(),
            }),
        );

        let ssl3 = unsafe {
            &mut *(ffi.ck_mechanism().pParameter as *mut cryptoki_sys::CK_SSL3_KEY_MAT_PARAMS)
        };
        let key_mat_out = unsafe { &mut *ssl3.pReturnedKeyMaterial };
        key_mat_out.hClientMacSecret = 101;
        key_mat_out.hServerMacSecret = 102;
        key_mat_out.hClientKey = 201;
        key_mat_out.hServerKey = 202;
        unsafe {
            std::ptr::copy_nonoverlapping(
                [0xA1, 0xA2, 0xA3, 0xA4].as_ptr(),
                key_mat_out.pIVClient,
                4,
            );
            std::ptr::copy_nonoverlapping(
                [0xB1, 0xB2, 0xB3, 0xB4].as_ptr(),
                key_mat_out.pIVServer,
                4,
            );
        }

        match ffi.output_params() {
            Some(CkMechanismParams::Ssl3KeyMat(params)) => {
                assert_eq!(params.mac_size_bits, 160);
                assert_eq!(params.key_size_bits, 128);
                assert_eq!(params.iv_size_bits, 32);
                assert!(!params.is_export);
                assert_eq!(params.random_info.client_random, [0x11, 0x12]);
                assert_eq!(params.random_info.server_random, [0x21, 0x22]);
                assert_eq!(params.prf_hash_mechanism, 0);
                assert_eq!(params.client_mac_secret_handle, 101);
                assert_eq!(params.server_mac_secret_handle, 102);
                assert_eq!(params.client_key_handle, 201);
                assert_eq!(params.server_key_handle, 202);
                assert_eq!(params.client_iv, [0xA1, 0xA2, 0xA3, 0xA4]);
                assert_eq!(params.server_iv, [0xB1, 0xB2, 0xB3, 0xB4]);
            }
            other => panic!("unexpected output params: {other:?}"),
        }
    }

    #[test]
    fn tls12_key_mat_output_params_surface_mutated_handles_and_ivs() {
        const CKM_TLS12_KEY_AND_MAC_DERIVE: CkMechanismType = CkMechanismType(0x0000_03E1);

        let ffi = convert(
            CKM_TLS12_KEY_AND_MAC_DERIVE,
            CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
                mac_size_bits: 160,
                key_size_bits: 128,
                iv_size_bits: 32,
                is_export: false,
                random_info: SslRandomData {
                    client_random: vec![0x31, 0x32],
                    server_random: vec![0x41, 0x42],
                },
                prf_hash_mechanism: CkMechanismType::SHA256.0,
                client_mac_secret_handle: 0,
                server_mac_secret_handle: 0,
                client_key_handle: 0,
                server_key_handle: 0,
                client_iv: Vec::new(),
                server_iv: Vec::new(),
            }),
        );

        let tls12 = unsafe {
            &mut *(ffi.ck_mechanism().pParameter as *mut cryptoki_sys::CK_TLS12_KEY_MAT_PARAMS)
        };
        let key_mat_out = unsafe { &mut *tls12.pReturnedKeyMaterial };
        key_mat_out.hClientMacSecret = 111;
        key_mat_out.hServerMacSecret = 112;
        key_mat_out.hClientKey = 211;
        key_mat_out.hServerKey = 212;
        unsafe {
            std::ptr::copy_nonoverlapping(
                [0xC1, 0xC2, 0xC3, 0xC4].as_ptr(),
                key_mat_out.pIVClient,
                4,
            );
            std::ptr::copy_nonoverlapping(
                [0xD1, 0xD2, 0xD3, 0xD4].as_ptr(),
                key_mat_out.pIVServer,
                4,
            );
        }

        match ffi.output_params() {
            Some(CkMechanismParams::Ssl3KeyMat(params)) => {
                assert_eq!(params.random_info.client_random, [0x31, 0x32]);
                assert_eq!(params.random_info.server_random, [0x41, 0x42]);
                assert_eq!(params.prf_hash_mechanism, CkMechanismType::SHA256.0);
                assert_eq!(params.client_mac_secret_handle, 111);
                assert_eq!(params.server_mac_secret_handle, 112);
                assert_eq!(params.client_key_handle, 211);
                assert_eq!(params.server_key_handle, 212);
                assert_eq!(params.client_iv, [0xC1, 0xC2, 0xC3, 0xC4]);
                assert_eq!(params.server_iv, [0xD1, 0xD2, 0xD3, 0xD4]);
            }
            other => panic!("unexpected output params: {other:?}"),
        }
    }

    #[test]
    fn cbc_iv_params_reconstruct_raw_iv_buffer() {
        let ffi = convert(
            CkMechanismType::AES_CBC,
            CkMechanismParams::Iv(IvParams { iv: vec![0x55; 16] }),
        );

        assert_eq!(ffi.ck_mechanism().ulParameterLen, 16);
        let iv = unsafe {
            std::slice::from_raw_parts(
                ffi.ck_mechanism().pParameter as *const u8,
                ffi.ck_mechanism().ulParameterLen as usize,
            )
        };
        assert_eq!(iv, [0x55; 16]);
    }

    #[test]
    fn ctr_params_reconstruct_c_struct() {
        let ffi = convert(
            CkMechanismType(0x0000_1086),
            CkMechanismParams::AesCtr(AesCtrParams { counter_bits: 128, cb: vec![0x33; 16] }),
        );

        assert_eq!(
            ffi.ck_mechanism().ulParameterLen,
            std::mem::size_of::<cryptoki_sys::CK_AES_CTR_PARAMS>() as cryptoki_sys::CK_ULONG
        );
        let ctr =
            unsafe { &*(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_AES_CTR_PARAMS) };
        assert_eq!(ctr.ulCounterBits, 128);
        assert_eq!(ctr.cb, [0x33; 16]);
    }

    #[test]
    fn extract_params_reconstruct_ck_ulong_bit_position() {
        let ffi = convert(
            CkMechanismType(0x0000_0365),
            CkMechanismParams::Extract(ExtractParams { bit_position: 21 }),
        );

        assert_eq!(
            ffi.ck_mechanism().ulParameterLen,
            std::mem::size_of::<cryptoki_sys::CK_EXTRACT_PARAMS>() as cryptoki_sys::CK_ULONG
        );
        let bit_position =
            unsafe { *(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_EXTRACT_PARAMS) };
        assert_eq!(bit_position, 21);
    }

    #[test]
    fn object_handle_param_reconstructs_ck_object_handle() {
        let ffi = convert(
            CkMechanismType(0x0000_0500),
            CkMechanismParams::ObjectHandle(ObjectHandleParam { handle: 0xCAFE }),
        );

        assert_eq!(
            ffi.ck_mechanism().ulParameterLen,
            std::mem::size_of::<cryptoki_sys::CK_OBJECT_HANDLE>() as cryptoki_sys::CK_ULONG
        );
        let handle =
            unsafe { *(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_OBJECT_HANDLE) };
        assert_eq!(handle, 0xCAFE);
    }

    #[test]
    fn key_derivation_string_data_reconstructs_c_struct() {
        let ffi = convert(
            CkMechanismType(0x0000_0501),
            CkMechanismParams::KeyDerivationString(KeyDerivationStringData {
                data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            }),
        );

        assert_eq!(
            ffi.ck_mechanism().ulParameterLen,
            std::mem::size_of::<cryptoki_sys::CK_KEY_DERIVATION_STRING_DATA>()
                as cryptoki_sys::CK_ULONG
        );
        let params = unsafe {
            &*(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_KEY_DERIVATION_STRING_DATA)
        };
        assert_eq!(params.ulLen, 4);
        let data = unsafe { std::slice::from_raw_parts(params.pData, params.ulLen as usize) };
        assert_eq!(data, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn sign_additional_context_reconstructs_c_struct() {
        let ffi = convert(
            CkMechanismType(0x0000_0502),
            CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
                hedge_variant: 1,
                context: vec![0xA1, 0xA2, 0xA3],
                hash: 0,
            }),
        );

        assert_eq!(
            ffi.ck_mechanism().ulParameterLen,
            std::mem::size_of::<super::FfiSignAdditionalContext>() as cryptoki_sys::CK_ULONG
        );
        let params =
            unsafe { &*(ffi.ck_mechanism().pParameter as *const super::FfiSignAdditionalContext) };
        assert_eq!(params.hedge_variant, 1);
        assert_eq!(params.ul_context_len, 3);
        let context =
            unsafe { std::slice::from_raw_parts(params.p_context, params.ul_context_len as usize) };
        assert_eq!(context, [0xA1, 0xA2, 0xA3]);
    }

    #[test]
    fn hash_sign_additional_context_reconstructs_c_struct() {
        // hash != 0 → the larger CK_HASH_SIGN_ADDITIONAL_CONTEXT (generic
        // CKM_HASH_ML_DSA / CKM_HASH_SLH_DSA), with the trailing hash mechanism.
        let ffi = convert(
            CkMechanismType(0x0000_001F), // CKM_HASH_ML_DSA
            CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
                hedge_variant: 1,
                context: vec![0xB1, 0xB2],
                hash: 0x0000_0250, // CKM_SHA256
            }),
        );

        assert_eq!(
            ffi.ck_mechanism().ulParameterLen,
            std::mem::size_of::<super::FfiHashSignAdditionalContext>() as cryptoki_sys::CK_ULONG
        );
        let params = unsafe {
            &*(ffi.ck_mechanism().pParameter as *const super::FfiHashSignAdditionalContext)
        };
        assert_eq!(params.hedge_variant, 1);
        assert_eq!(params.ul_context_len, 2);
        assert_eq!(params.hash, 0x0000_0250);
        let context =
            unsafe { std::slice::from_raw_parts(params.p_context, params.ul_context_len as usize) };
        assert_eq!(context, [0xB1, 0xB2]);
    }

    #[test]
    fn kmac_params_reconstruct_c_struct_and_customization_string() {
        let ffi = convert(
            CkMechanismType(0x8000_0001),
            CkMechanismParams::Kmac(KmacParams {
                key_handle: 0xCAFE,
                mac_length: 64,
                customization_string: b"custom".to_vec(),
            }),
        );

        assert_eq!(
            ffi.ck_mechanism().ulParameterLen,
            std::mem::size_of::<super::FfiKmacParams>() as cryptoki_sys::CK_ULONG
        );
        let kmac = unsafe { &*(ffi.ck_mechanism().pParameter as *const super::FfiKmacParams) };
        assert_eq!(kmac.h_key, 0xCAFE);
        assert_eq!(kmac.ul_mac_length, 64);
        assert_eq!(kmac.ul_customization_string_len, 6);
        let customization = unsafe {
            std::slice::from_raw_parts(
                kmac.p_customization_string as *const u8,
                kmac.ul_customization_string_len as usize,
            )
        };
        assert_eq!(customization, b"custom");
    }

    #[test]
    fn mu_gen_params_reconstruct_c_struct_tr_and_context() {
        let ffi = convert(
            CkMechanismType(0x8000_0002),
            CkMechanismParams::MuGen(MuGenParams {
                key_handle: 0xA11CE,
                tr: b"precomputed-tr".to_vec(),
                context: b"context".to_vec(),
            }),
        );

        assert_eq!(
            ffi.ck_mechanism().ulParameterLen,
            std::mem::size_of::<super::FfiMuGenParams>() as cryptoki_sys::CK_ULONG
        );
        let mu_gen = unsafe { &*(ffi.ck_mechanism().pParameter as *const super::FfiMuGenParams) };
        assert_eq!(mu_gen.h_key, 0xA11CE);
        assert_eq!(mu_gen.ul_tr_len, 14);
        assert_eq!(mu_gen.ul_ctx_len, 7);
        let tr = unsafe { std::slice::from_raw_parts(mu_gen.p_tr, mu_gen.ul_tr_len as usize) };
        let context =
            unsafe { std::slice::from_raw_parts(mu_gen.p_ctx, mu_gen.ul_ctx_len as usize) };
        assert_eq!(tr, b"precomputed-tr");
        assert_eq!(context, b"context");
    }
}

#[cfg(test)]
mod utf8_trim_tests {
    use super::{session_state_from_ck, space_pad, utf8_trim};
    use pkcs11_proxy_ng_types::CkSessionState;

    #[test]
    fn space_padded_field() {
        let bytes = b"SoftHSM2                        ";
        assert_eq!(utf8_trim(bytes), "SoftHSM2");
    }

    #[test]
    fn null_padded_field() {
        let bytes = b"Token\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        assert_eq!(utf8_trim(bytes), "Token");
    }

    #[test]
    fn mixed_null_and_space_padding() {
        let bytes = b"HSM   \0\0";
        assert_eq!(utf8_trim(bytes), "HSM");
    }

    #[test]
    fn exact_full_length_no_padding() {
        let bytes = b"ABCDEFGHIJKLMNOP";
        assert_eq!(utf8_trim(bytes), "ABCDEFGHIJKLMNOP");
    }

    #[test]
    fn all_spaces() {
        let bytes = b"                ";
        assert_eq!(utf8_trim(bytes), "");
    }

    #[test]
    fn all_nulls() {
        let bytes = b"\0\0\0\0\0\0\0\0";
        assert_eq!(utf8_trim(bytes), "");
    }

    #[test]
    fn empty_input() {
        let bytes: &[u8] = b"";
        assert_eq!(utf8_trim(bytes), "");
    }

    #[test]
    fn interior_spaces_preserved() {
        let bytes = b"My HSM Token    ";
        assert_eq!(utf8_trim(bytes), "My HSM Token");
    }

    #[test]
    fn interior_nulls_preserved() {
        let bytes = b"A\0B        ";
        assert_eq!(utf8_trim(bytes), "A\0B");
    }

    #[test]
    fn non_ascii_latin1_bytes() {
        let mut buf = [b' '; 16];
        buf[0] = 0xC4;
        buf[1] = b'B';
        buf[2] = b'C';
        let result = utf8_trim(&buf);
        assert!(result.ends_with("BC"), "got: {result:?}");
        assert!(!result.ends_with(' '));
    }

    #[test]
    fn valid_utf8_multibyte() {
        let src = "Tëst";
        let mut buf = [b' '; 32];
        buf[..src.len()].copy_from_slice(src.as_bytes());
        assert_eq!(utf8_trim(&buf), "Tëst");
    }

    #[test]
    fn sixteen_byte_serial_number_field() {
        let mut serial = [b' '; 16];
        serial[..4].copy_from_slice(b"0001");
        assert_eq!(utf8_trim(&serial), "0001");
    }

    #[test]
    fn utc_time_field_14_chars() {
        let mut utc = [b' '; 16];
        utc[..14].copy_from_slice(b"20260313120000");
        assert_eq!(utf8_trim(&utc), "20260313120000");
    }

    #[test]
    fn utc_time_field_with_null_terminator() {
        let mut utc = [0u8; 16];
        utc[..14].copy_from_slice(b"20260313120000");
        assert_eq!(utf8_trim(&utc), "20260313120000");
    }

    #[test]
    fn round_trip_trim_then_pad() {
        let original = b"My Token        ";
        let trimmed = utf8_trim(original);
        assert_eq!(trimmed, "My Token");

        let mut restored = [0u8; 16];
        let bytes = trimmed.as_bytes();
        let copy_len = bytes.len().min(restored.len());
        restored[..copy_len].copy_from_slice(&bytes[..copy_len]);
        for byte in &mut restored[copy_len..] {
            *byte = b' ';
        }
        assert_eq!(&restored, original);
    }

    #[test]
    fn space_pad_fills_fixed_width_field() {
        assert_eq!(&space_pad::<8>("HSM"), b"HSM     ");
    }

    #[test]
    fn space_pad_truncates_overlong_value() {
        assert_eq!(&space_pad::<4>("ABCDEFG"), b"ABCD");
    }

    #[test]
    fn session_state_mapping_matches_pkcs11_values() {
        assert_eq!(session_state_from_ck(0), CkSessionState::RoPublic);
        assert_eq!(session_state_from_ck(1), CkSessionState::RoUser);
        assert_eq!(session_state_from_ck(2), CkSessionState::RwPublic);
        assert_eq!(session_state_from_ck(3), CkSessionState::RwUser);
        assert_eq!(session_state_from_ck(4), CkSessionState::RwSo);
    }

    #[test]
    fn unknown_session_state_falls_back_to_ro_public() {
        assert_eq!(session_state_from_ck(99), CkSessionState::RoPublic);
    }
}

#[cfg(test)]
mod attribute_query_tests {
    use super::FfiAttributeQueries;
    use pkcs11_proxy_ng_types::{CkAttributeQuery, CkAttributeType, CkRv};

    #[test]
    fn raw_attribute_queries_zero_output_only_null_buffer_len_without_reading_caller() {
        let ffi = FfiAttributeQueries::from_queries(&[CkAttributeQuery {
            attr_type: CkAttributeType::LABEL,
            buffer_present: false,
            buffer_len: 17,
            nested: None,
        }])
        .expect("ffi queries");

        assert_eq!(ffi.attrs.len(), 1);
        assert!(ffi.attrs[0].pValue.is_null());
        assert_eq!(ffi.attrs[0].ulValueLen, 0);
    }

    #[test]
    fn raw_attribute_queries_reject_unallocatable_buffer_len() {
        let err = match FfiAttributeQueries::from_queries(&[CkAttributeQuery {
            attr_type: CkAttributeType::LABEL,
            buffer_present: true,
            buffer_len: u64::MAX,
            nested: None,
        }]) {
            Ok(_) => panic!("buffer_len should fail"),
            Err(err) => err,
        };

        assert_eq!(err, CkRv::HOST_MEMORY);
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn raw_attribute_queries_reject_null_buffer_len_that_exceeds_ck_ulong() {
        let err = match FfiAttributeQueries::from_queries(&[CkAttributeQuery {
            attr_type: CkAttributeType::LABEL,
            buffer_present: false,
            buffer_len: (u32::MAX as u64) + 1,
            nested: None,
        }]) {
            Ok(_) => panic!("buffer_len should fail"),
            Err(err) => err,
        };

        assert_eq!(err, CkRv::HOST_MEMORY);
    }
}
