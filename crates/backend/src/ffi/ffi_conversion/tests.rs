//! Unit tests for the conversion edge (all modules cfg(test)-gated).

// The inner test modules reference conversion items as `super::X`,
// resolving through this glob; the lint cannot see that indirection.
#[allow(unused_imports)]
use super::*;

#[cfg(test)]
mod mechanism_to_ffi_tests {
    use super::mechanism_to_ffi;
    use pkcs11_proxy_ng_types::{
        AesCmacKeyDerivationParams, AesCtrParams, CcmParams, CkMechanism, CkMechanismParams,
        CkMechanismType, CkMgf, CkOaepSource, CkObjectHandle, CkPbkdf2Prf, CkPbkdf2SaltSource,
        CkRv, DilithiumParams, EciesParams, ExtractParams, GcmParams, HdKeyDeriveParams,
        Ike1PrfDeriveParams, IvParams, KeyDerivationStringData, KeyWrapSetOaepParams, KipParams,
        KmacParams, KyberParams, MuGenParams, ObjectHandleParam, PbeParams, Pkcs5Pbkd2Params,
        RawMechanismParams, RsaAesKeyWrapParams, RsaPkcsOaepParams, RsaPkcsPssParams, SecretBytes,
        SignAdditionalContext, Ssl3KeyMatParams, Ssl3MasterKeyDeriveParams, SslRandomData,
        Tls12ExtendedMasterKeyDeriveParams, Tls12MasterKeyDeriveParams, TlsPrfParams,
        VendorObjectExtractParams, VendorObjectInsertParams, WtlsKeyMatParams,
        WtlsMasterKeyDeriveParams, WtlsPrfParams, WtlsRandomData,
    };

    fn convert(mechanism_type: CkMechanismType, params: CkMechanismParams) -> super::FfiMechanism {
        mechanism_to_ffi(&CkMechanism { mechanism_type, params: Some(params) })
            .expect("mechanism converts to ffi")
    }

    #[test]
    fn kip_nesting_depth_limit_is_enforced() {
        // T03/RV-N2 backend half: mirror of the shim reader bound (16
        // nested nodes allowed, 17th rejected). The typed tree is owned
        // (acyclic), so a depth counter suffices; no cycle check needed.
        fn nest(inner: CkMechanism) -> CkMechanism {
            CkMechanism {
                mechanism_type: CkMechanismType::RSA_PKCS,
                params: Some(CkMechanismParams::Kip(KipParams {
                    mechanism: Box::new(inner),
                    key_handle: CkObjectHandle(0),
                    seed: SecretBytes::copy_from_slice(&[]),
                })),
            }
        }
        fn leaf() -> CkMechanism {
            CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None }
        }
        let mut mech = leaf();
        for _ in 0..16 {
            mech = nest(mech);
        }
        assert!(mechanism_to_ffi(&mech).is_ok(), "16 nested nodes must convert");
        let deep = nest(mech);
        assert_eq!(
            mechanism_to_ffi(&deep).err(),
            Some(CkRv::MECHANISM_PARAM_INVALID),
            "17th nested node must be rejected before recursion"
        );
    }

    fn ssl_random() -> SslRandomData {
        SslRandomData { client_random: vec![0x11; 32], server_random: vec![0x22; 32] }
    }

    fn tls12_mech(major: u32, minor: u32) -> CkMechanism {
        CkMechanism {
            mechanism_type: CkMechanismType::TLS12_MASTER_KEY_DERIVE,
            params: Some(CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
                random_info: ssl_random(),
                version_major: major,
                version_minor: minor,
                prf_hash_mechanism: CkMechanismType::SHA256,
            })),
        }
    }

    #[test]
    fn tls12_version_bytes_are_checked_before_native_conversion() {
        // T05: valid versions convert; any out-of-byte version is
        // MECHANISM_PARAM_INVALID, including valid-first/invalid-second;
        // the 0.0 DH sentinel still converts (NULL version preserved).
        assert!(mechanism_to_ffi(&tls12_mech(3, 3)).is_ok());
        assert!(mechanism_to_ffi(&tls12_mech(0, 0)).is_ok());
        assert!(mechanism_to_ffi(&tls12_mech(255, 255)).is_ok());
        for (major, minor) in [(3, 256), (256, 3), (256, 256), (u32::MAX, 0), (0, u32::MAX)] {
            assert_eq!(
                mechanism_to_ffi(&tls12_mech(major, minor)).err(),
                Some(CkRv::MECHANISM_PARAM_INVALID),
                "TLS12 version {major}.{minor} must be rejected"
            );
        }
    }

    #[test]
    fn ssl3_and_tls12_extended_version_bytes_are_checked() {
        // T05: same byte discipline for the sibling version arms.
        let ssl3 = |major: u32, minor: u32| CkMechanism {
            mechanism_type: CkMechanismType::SSL3_MASTER_KEY_DERIVE,
            params: Some(CkMechanismParams::Ssl3MasterKeyDerive(Ssl3MasterKeyDeriveParams {
                random_info: ssl_random(),
                version_major: major,
                version_minor: minor,
            })),
        };
        let ext = |major: u32, minor: u32| CkMechanism {
            mechanism_type: CkMechanismType::TLS12_EXTENDED_MASTER_KEY_DERIVE,
            params: Some(CkMechanismParams::Tls12ExtendedMasterKeyDerive(
                Tls12ExtendedMasterKeyDeriveParams {
                    prf_hash_mechanism: CkMechanismType::SHA256,
                    session_hash: vec![0x33; 48],
                    version_major: major,
                    version_minor: minor,
                },
            )),
        };
        assert!(mechanism_to_ffi(&ssl3(3, 0)).is_ok());
        assert!(mechanism_to_ffi(&ssl3(0, 0)).is_ok());
        assert!(mechanism_to_ffi(&ext(3, 3)).is_ok());
        assert!(mechanism_to_ffi(&ext(0, 0)).is_ok());
        for (major, minor) in [(3, 256), (256, 3), (u32::MAX, u32::MAX)] {
            assert_eq!(
                mechanism_to_ffi(&ssl3(major, minor)).err(),
                Some(CkRv::MECHANISM_PARAM_INVALID),
                "SSL3 version {major}.{minor} must be rejected"
            );
            assert_eq!(
                mechanism_to_ffi(&ext(major, minor)).err(),
                Some(CkRv::MECHANISM_PARAM_INVALID),
                "TLS12-extended version {major}.{minor} must be rejected"
            );
        }
    }

    #[test]
    fn oaep_bc_ike1_key_number_and_wtls_version_bytes_are_checked() {
        // T05: single-byte wire fields reject >255 with
        // MECHANISM_PARAM_INVALID instead of truncating.
        let kwso = |bc: u32| CkMechanism {
            mechanism_type: CkMechanismType(0x0000_0401),
            params: Some(CkMechanismParams::KeyWrapSetOaep(KeyWrapSetOaepParams {
                bc,
                x: SecretBytes::copy_from_slice(&[0x44; 8]),
            })),
        };
        let ike1 = |key_number: u32| CkMechanism {
            mechanism_type: CkMechanismType::IKE1_PRF_DERIVE,
            params: Some(CkMechanismParams::Ike1PrfDerive(Ike1PrfDeriveParams {
                prf_mechanism: CkMechanismType::SHA256,
                has_prev_key: false,
                keygxy_handle: CkObjectHandle(1),
                prev_key_handle: CkObjectHandle(0),
                ckyi: SecretBytes::copy_from_slice(&[0x55; 8]),
                ckyr: SecretBytes::copy_from_slice(&[0x66; 8]),
                key_number,
            })),
        };
        let wtls = |version: u32| CkMechanism {
            mechanism_type: CkMechanismType::WTLS_MASTER_KEY_DERIVE,
            params: Some(CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
                digest_mechanism: CkMechanismType::SHA256,
                random_info: WtlsRandomData {
                    client_random: vec![0xA1, 0xA2],
                    server_random: vec![0xB1, 0xB2],
                },
                version,
            })),
        };
        assert!(mechanism_to_ffi(&kwso(1)).is_ok());
        assert!(mechanism_to_ffi(&ike1(1)).is_ok());
        assert!(mechanism_to_ffi(&wtls(1)).is_ok());
        // Upper boundary is inclusive at every arm (an over-strict arm
        // rejecting 255 must fail here, not just at the helper).
        assert!(mechanism_to_ffi(&kwso(255)).is_ok());
        assert!(mechanism_to_ffi(&ike1(255)).is_ok());
        assert!(mechanism_to_ffi(&wtls(255)).is_ok());
        for bad in [256, u32::MAX] {
            assert_eq!(
                mechanism_to_ffi(&kwso(bad)).err(),
                Some(CkRv::MECHANISM_PARAM_INVALID),
                "OAEP bc {bad} must be rejected"
            );
            assert_eq!(
                mechanism_to_ffi(&ike1(bad)).err(),
                Some(CkRv::MECHANISM_PARAM_INVALID),
                "IKE1 key_number {bad} must be rejected"
            );
            assert_eq!(
                mechanism_to_ffi(&wtls(bad)).err(),
                Some(CkRv::MECHANISM_PARAM_INVALID),
                "WTLS version {bad} must be rejected"
            );
        }
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
                mgf: CkMgf(2),
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
            ("Raw", CkMechanismParams::Raw(RawMechanismParams { data: vec![0x01, 0x02].into() })),
            (
                "Ecies",
                CkMechanismParams::Ecies(EciesParams {
                    derivation_mechanism: Box::new(parameterless.clone()),
                    encryption_mechanism: Box::new(parameterless.clone()),
                    mac_mechanism: Box::new(parameterless.clone()),
                    shared_data: vec![0x03].into(),
                }),
            ),
            (
                "AesCmacKeyDerivation",
                CkMechanismParams::AesCmacKeyDerivation(AesCmacKeyDerivationParams {
                    context: vec![0x04].into(),
                    label: vec![0x05].into(),
                }),
            ),
            ("Dilithium", CkMechanismParams::Dilithium(DilithiumParams { version: 1, mode: 2 })),
            (
                "Kyber",
                CkMechanismParams::Kyber(KyberParams {
                    version: 3,
                    mode: 4,
                    secret_handle: CkObjectHandle(5),
                    shared_data: vec![0x06].into(),
                    blob: vec![0x07].into(),
                }),
            ),
            (
                "HdKeyDerive",
                CkMechanismParams::HdKeyDerive(HdKeyDeriveParams {
                    derive_type: 8,
                    child_key_index: 9,
                    chain_code: vec![0x0A].into(),
                    version: 10,
                }),
            ),
            (
                "VendorObjectExtract",
                CkMechanismParams::VendorObjectExtract(VendorObjectExtractParams {
                    format: 11,
                    context: vec![0x0C].into(),
                }),
            ),
            (
                "VendorObjectInsert",
                CkMechanismParams::VendorObjectInsert(VendorObjectInsertParams {
                    format: 12,
                    context: vec![0x0D].into(),
                    object_data: vec![0x0E].into(),
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

    // W1-C9-06: the new DES/RC2/RC4/SHA-1/SP800-108/BLAKE2B/PQC named
    // constants must match the published cryptoki-sys headers exactly.
    #[test]
    fn new_mechanism_constants_match_cryptoki_sys_headers() {
        let eq = |named: CkMechanismType, header: cryptoki_sys::CK_MECHANISM_TYPE| {
            assert_eq!(named.0, header as u64);
        };
        eq(CkMechanismType::DES_CBC, cryptoki_sys::CKM_DES_CBC);
        eq(CkMechanismType::DES_MAC_GENERAL, cryptoki_sys::CKM_DES_MAC_GENERAL);
        eq(CkMechanismType::RC2_KEY_GEN, cryptoki_sys::CKM_RC2_KEY_GEN);
        eq(CkMechanismType::RC2_ECB, cryptoki_sys::CKM_RC2_ECB);
        eq(CkMechanismType::RC2_CBC, cryptoki_sys::CKM_RC2_CBC);
        eq(CkMechanismType::RC2_MAC, cryptoki_sys::CKM_RC2_MAC);
        eq(CkMechanismType::RC2_MAC_GENERAL, cryptoki_sys::CKM_RC2_MAC_GENERAL);
        eq(CkMechanismType::RC2_CBC_PAD, cryptoki_sys::CKM_RC2_CBC_PAD);
        eq(CkMechanismType::RC4_KEY_GEN, cryptoki_sys::CKM_RC4_KEY_GEN);
        eq(CkMechanismType::RC4, cryptoki_sys::CKM_RC4);
        eq(CkMechanismType::SHA_1, cryptoki_sys::CKM_SHA_1);
        eq(CkMechanismType::SHA_1_HMAC, cryptoki_sys::CKM_SHA_1_HMAC);
        eq(CkMechanismType::SHA_1_HMAC_GENERAL, cryptoki_sys::CKM_SHA_1_HMAC_GENERAL);
        eq(CkMechanismType::SP800_108_COUNTER_KDF, cryptoki_sys::CKM_SP800_108_COUNTER_KDF);
        eq(CkMechanismType::SP800_108_FEEDBACK_KDF, cryptoki_sys::CKM_SP800_108_FEEDBACK_KDF);
        eq(
            CkMechanismType::SP800_108_DOUBLE_PIPELINE_KDF,
            cryptoki_sys::CKM_SP800_108_DOUBLE_PIPELINE_KDF,
        );
        eq(CkMechanismType::BLAKE2B_160, cryptoki_sys::CKM_BLAKE2B_160);
        eq(CkMechanismType::BLAKE2B_160_HMAC, cryptoki_sys::CKM_BLAKE2B_160_HMAC);
        eq(CkMechanismType::BLAKE2B_160_HMAC_GENERAL, cryptoki_sys::CKM_BLAKE2B_160_HMAC_GENERAL);
        eq(CkMechanismType::BLAKE2B_160_KEY_DERIVE, cryptoki_sys::CKM_BLAKE2B_160_KEY_DERIVE);
        eq(CkMechanismType::BLAKE2B_160_KEY_GEN, cryptoki_sys::CKM_BLAKE2B_160_KEY_GEN);
        eq(CkMechanismType::BLAKE2B_256, cryptoki_sys::CKM_BLAKE2B_256);
        eq(CkMechanismType::BLAKE2B_256_HMAC, cryptoki_sys::CKM_BLAKE2B_256_HMAC);
        eq(CkMechanismType::BLAKE2B_256_HMAC_GENERAL, cryptoki_sys::CKM_BLAKE2B_256_HMAC_GENERAL);
        eq(CkMechanismType::BLAKE2B_256_KEY_DERIVE, cryptoki_sys::CKM_BLAKE2B_256_KEY_DERIVE);
        eq(CkMechanismType::BLAKE2B_256_KEY_GEN, cryptoki_sys::CKM_BLAKE2B_256_KEY_GEN);
        eq(CkMechanismType::BLAKE2B_384, cryptoki_sys::CKM_BLAKE2B_384);
        eq(CkMechanismType::BLAKE2B_384_HMAC, cryptoki_sys::CKM_BLAKE2B_384_HMAC);
        eq(CkMechanismType::BLAKE2B_384_HMAC_GENERAL, cryptoki_sys::CKM_BLAKE2B_384_HMAC_GENERAL);
        eq(CkMechanismType::BLAKE2B_384_KEY_DERIVE, cryptoki_sys::CKM_BLAKE2B_384_KEY_DERIVE);
        eq(CkMechanismType::BLAKE2B_384_KEY_GEN, cryptoki_sys::CKM_BLAKE2B_384_KEY_GEN);
        eq(CkMechanismType::BLAKE2B_512, cryptoki_sys::CKM_BLAKE2B_512);
        eq(CkMechanismType::BLAKE2B_512_HMAC, cryptoki_sys::CKM_BLAKE2B_512_HMAC);
        eq(CkMechanismType::BLAKE2B_512_HMAC_GENERAL, cryptoki_sys::CKM_BLAKE2B_512_HMAC_GENERAL);
        eq(CkMechanismType::BLAKE2B_512_KEY_DERIVE, cryptoki_sys::CKM_BLAKE2B_512_KEY_DERIVE);
        eq(CkMechanismType::BLAKE2B_512_KEY_GEN, cryptoki_sys::CKM_BLAKE2B_512_KEY_GEN);
        eq(CkMechanismType::ML_KEM_KEY_PAIR_GEN, cryptoki_sys::CKM_ML_KEM_KEY_PAIR_GEN);
        eq(CkMechanismType::ML_KEM, cryptoki_sys::CKM_ML_KEM);
        eq(CkMechanismType::ML_DSA_KEY_PAIR_GEN, cryptoki_sys::CKM_ML_DSA_KEY_PAIR_GEN);
        eq(CkMechanismType::ML_DSA, cryptoki_sys::CKM_ML_DSA);
        eq(CkMechanismType::HASH_ML_DSA, cryptoki_sys::CKM_HASH_ML_DSA);
        eq(CkMechanismType::HASH_ML_DSA_SHA224, cryptoki_sys::CKM_HASH_ML_DSA_SHA224);
        eq(CkMechanismType::HASH_ML_DSA_SHA256, cryptoki_sys::CKM_HASH_ML_DSA_SHA256);
        eq(CkMechanismType::HASH_ML_DSA_SHA384, cryptoki_sys::CKM_HASH_ML_DSA_SHA384);
        eq(CkMechanismType::HASH_ML_DSA_SHA512, cryptoki_sys::CKM_HASH_ML_DSA_SHA512);
        eq(CkMechanismType::HASH_ML_DSA_SHA3_224, cryptoki_sys::CKM_HASH_ML_DSA_SHA3_224);
        eq(CkMechanismType::HASH_ML_DSA_SHA3_256, cryptoki_sys::CKM_HASH_ML_DSA_SHA3_256);
        eq(CkMechanismType::HASH_ML_DSA_SHA3_384, cryptoki_sys::CKM_HASH_ML_DSA_SHA3_384);
        eq(CkMechanismType::HASH_ML_DSA_SHA3_512, cryptoki_sys::CKM_HASH_ML_DSA_SHA3_512);
        eq(CkMechanismType::HASH_ML_DSA_SHAKE128, cryptoki_sys::CKM_HASH_ML_DSA_SHAKE128);
        eq(CkMechanismType::HASH_ML_DSA_SHAKE256, cryptoki_sys::CKM_HASH_ML_DSA_SHAKE256);
        eq(CkMechanismType::SLH_DSA_KEY_PAIR_GEN, cryptoki_sys::CKM_SLH_DSA_KEY_PAIR_GEN);
        eq(CkMechanismType::SLH_DSA, cryptoki_sys::CKM_SLH_DSA);
        eq(CkMechanismType::HASH_SLH_DSA, cryptoki_sys::CKM_HASH_SLH_DSA);
        eq(CkMechanismType::HASH_SLH_DSA_SHA224, cryptoki_sys::CKM_HASH_SLH_DSA_SHA224);
        eq(CkMechanismType::HASH_SLH_DSA_SHA256, cryptoki_sys::CKM_HASH_SLH_DSA_SHA256);
        eq(CkMechanismType::HASH_SLH_DSA_SHA384, cryptoki_sys::CKM_HASH_SLH_DSA_SHA384);
        eq(CkMechanismType::HASH_SLH_DSA_SHA512, cryptoki_sys::CKM_HASH_SLH_DSA_SHA512);
        eq(CkMechanismType::HASH_SLH_DSA_SHA3_224, cryptoki_sys::CKM_HASH_SLH_DSA_SHA3_224);
        eq(CkMechanismType::HASH_SLH_DSA_SHA3_256, cryptoki_sys::CKM_HASH_SLH_DSA_SHA3_256);
        eq(CkMechanismType::HASH_SLH_DSA_SHA3_384, cryptoki_sys::CKM_HASH_SLH_DSA_SHA3_384);
        eq(CkMechanismType::HASH_SLH_DSA_SHA3_512, cryptoki_sys::CKM_HASH_SLH_DSA_SHA3_512);
        eq(CkMechanismType::HASH_SLH_DSA_SHAKE128, cryptoki_sys::CKM_HASH_SLH_DSA_SHAKE128);
        eq(CkMechanismType::HASH_SLH_DSA_SHAKE256, cryptoki_sys::CKM_HASH_SLH_DSA_SHAKE256);
    }

    #[test]
    fn official_pqc_mechanisms_flow_parameterless_to_null_ffi() {
        // OASIS v3.2 (ml-kem.md): CKM_ML_KEM keygen/encaps/decaps take no
        // parameters; ML-DSA/SLH-DSA likewise (hash variants take only an
        // optional additional context). The transparent path must deliver
        // them with NULL params — this is what CloudHSM PQC rides on, and
        // it must keep working while vendor shapes are gated.
        let pqc_ids = [
            (CkMechanismType::ML_KEM_KEY_PAIR_GEN, "CKM_ML_KEM_KEY_PAIR_GEN"),
            (CkMechanismType::ML_KEM, "CKM_ML_KEM"),
            (CkMechanismType::ML_DSA_KEY_PAIR_GEN, "CKM_ML_DSA_KEY_PAIR_GEN"),
            (CkMechanismType::ML_DSA, "CKM_ML_DSA"),
            (CkMechanismType::SLH_DSA_KEY_PAIR_GEN, "CKM_SLH_DSA_KEY_PAIR_GEN"),
            (CkMechanismType::SLH_DSA, "CKM_SLH_DSA"),
        ];
        for (id, name) in pqc_ids {
            let mech = CkMechanism { mechanism_type: id, params: None };
            let ffi = mechanism_to_ffi(&mech).expect("official PQC flows parameterless");
            let native = ffi.ck_mechanism();
            assert!(native.pParameter.is_null(), "{name}: NULL params on the wire");
            // E0793: CK_MECHANISM is packed on Windows; assert on a by-value copy.
            let ul_parameter_len = native.ulParameterLen;
            assert_eq!(ul_parameter_len, 0, "{name}: zero param length");
        }
    }

    #[test]
    fn pss_params_reconstruct_c_struct() {
        let ffi = convert(
            CkMechanismType::RSA_PKCS_PSS,
            CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
                hash_alg: CkMechanismType::SHA256,
                mgf: CkMgf(1),
                salt_len: 32,
            }),
        );

        // E0793: CK structs are packed on Windows; assert on by-value copies.
        let ul_parameter_len = ffi.ck_mechanism().ulParameterLen;
        assert_eq!(
            ul_parameter_len,
            std::mem::size_of::<cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS>() as cryptoki_sys::CK_ULONG
        );
        let pss = unsafe {
            &*(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS)
        };
        let (hash_alg, mgf, s_len) = (pss.hashAlg, pss.mgf, pss.sLen);
        assert_eq!(hash_alg, CkMechanismType::SHA256.0 as cryptoki_sys::CK_MECHANISM_TYPE);
        assert_eq!(mgf, 1);
        assert_eq!(s_len, 32);
    }

    #[test]
    fn oaep_params_reconstruct_c_struct_and_source_data() {
        let ffi = convert(
            CkMechanismType::RSA_PKCS_OAEP,
            CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
                hash_alg: CkMechanismType::SHA256,
                mgf: CkMgf(1),
                source: CkOaepSource(1),
                source_data: vec![0xA0, 0xA1, 0xA2].into(),

                source_null: false,
            }),
        );

        // E0793: CK structs are packed on Windows; assert on by-value copies.
        let ul_parameter_len = ffi.ck_mechanism().ulParameterLen;
        assert_eq!(
            ul_parameter_len,
            std::mem::size_of::<cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS>() as cryptoki_sys::CK_ULONG
        );
        let oaep = unsafe {
            &*(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS)
        };
        let (hash_alg, mgf, source, ul_source_data_len) =
            (oaep.hashAlg, oaep.mgf, oaep.source, oaep.ulSourceDataLen);
        assert_eq!(hash_alg, CkMechanismType::SHA256.0 as cryptoki_sys::CK_MECHANISM_TYPE);
        assert_eq!(mgf, 1);
        assert_eq!(source, 1);
        assert_eq!(ul_source_data_len, 3);
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
                aad: vec![0xAA, 0xBB, 0xCC].into(),
                tag_bits: 128,

                iv_null: false,
                aad_null: false,
            }),
        );

        // E0793: CK structs are packed on Windows; assert on by-value copies.
        let ul_parameter_len = ffi.ck_mechanism().ulParameterLen;
        assert_eq!(
            ul_parameter_len,
            std::mem::size_of::<cryptoki_sys::CK_GCM_PARAMS>() as cryptoki_sys::CK_ULONG
        );
        let gcm =
            unsafe { &*(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_GCM_PARAMS) };
        let (ul_iv_len, ul_iv_bits, ul_aad_len, ul_tag_bits) =
            (gcm.ulIvLen, gcm.ulIvBits, gcm.ulAADLen, gcm.ulTagBits);
        assert_eq!(ul_iv_len, 12);
        assert_eq!(ul_iv_bits, 96);
        assert_eq!(ul_aad_len, 3);
        assert_eq!(ul_tag_bits, 128);
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
                    aad: Vec::new().into(),
                    tag_bits: 128,

                    iv_null: false,
                    aad_null: false,
                }),
            );
            // SAFETY: the owner is alive and unchanged; snapshot once per
            // length. Only unaligned raw reads, never typed references into
            // retained native storage (row-1 discipline).
            // E0793: CK structs are packed on Windows; assert on by-value copies.
            let gcm = unsafe {
                ffi.ck_mechanism().pParameter.cast::<cryptoki_sys::CK_GCM_PARAMS>().read_unaligned()
            };
            let (ul_iv_len, p_iv) = (gcm.ulIvLen, gcm.pIv);
            assert_eq!(ul_iv_len as usize, iv_len, "provider-visible IV length");
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
                assert!(p_iv.is_null() == (buffer_len == 0));
            } else {
                assert!(!p_iv.is_null());
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
                aad: Vec::new().into(),
                tag_bits: 128,

                iv_null: false,
                aad_null: false,
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
                init_vector: vec![0x01; 8].into(),
                password: password.clone().into(),
                salt: vec![0x02; 4].into(),
                iteration: 1000,
            }),
        );
        let pbe =
            unsafe { &*(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_PBE_PARAMS) };
        // E0793: CK structs are packed on Windows; assert on by-value copies.
        let (ul_password_len, ul_iteration) = (pbe.ulPasswordLen, pbe.ulIteration);
        assert_eq!(ul_password_len, password.len() as cryptoki_sys::CK_ULONG);
        assert_eq!(ul_iteration, 1000);
        let pass = unsafe { std::slice::from_raw_parts(pbe.pPassword, pbe.ulPasswordLen as usize) };
        assert_eq!(pass, password.as_slice());
    }

    #[test]
    fn pkcs5_pbkd2_password_reaches_c_struct_through_zeroizing_backing() {
        let password = vec![0x55, 0x66, 0x77];
        let ffi = convert(
            CkMechanismType(0x0000_03B0), // CKM_PKCS5_PBKD2
            CkMechanismParams::Pkcs5Pbkd2(Pkcs5Pbkd2Params {
                salt_source: CkPbkdf2SaltSource(1),
                salt_source_data: vec![0x09; 8].into(),
                iterations: 2048,
                prf: CkPbkdf2Prf(2),
                prf_data: vec![].into(),
                password: password.clone().into(),
            }),
        );
        let p = unsafe {
            &*(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_PKCS5_PBKD2_PARAMS2)
        };
        // E0793: CK structs are packed on Windows; assert on a by-value copy.
        let ul_password_len = p.ulPasswordLen;
        assert_eq!(ul_password_len, password.len() as cryptoki_sys::CK_ULONG);
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
                aad: Vec::new().into(),
                tag_bits: 128,

                iv_null: false,
                aad_null: false,
            }),
        );

        let gcm =
            unsafe { &mut *(ffi.ck_mechanism().pParameter as *mut cryptoki_sys::CK_GCM_PARAMS) };
        assert!(!gcm.pIv.is_null());
        // E0793: CK structs are packed on Windows; assert on by-value copies.
        let (ul_iv_len, ul_iv_bits) = (gcm.ulIvLen, gcm.ulIvBits);
        assert_eq!(ul_iv_len, 0);
        assert_eq!(ul_iv_bits, 96);

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
                digest_mechanism: CkMechanismType::SHA256,
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
                assert_eq!(params.digest_mechanism.0, CkMechanismType::SHA256.0);
                assert_eq!(params.random_info.client_random, [0xA1, 0xA2]);
                assert_eq!(params.random_info.server_random, [0xB1, 0xB2]);
                assert_eq!(params.version, 2);
            }
            other => panic!("unexpected output params: {other:?}"),
        }
    }

    #[test]
    fn tls_prf_output_params_surface_provider_written_output() {
        // W1-C5-01: the provider writes the PRF output bytes into
        // `pOutput` and the written length into `*pulOutputLen`;
        // `output_params()` must surface both, not drop via `_ => None`.
        let ffi = convert(
            CkMechanismType::TLS_PRF,
            CkMechanismParams::TlsPrf(TlsPrfParams {
                seed: vec![0xA1, 0xA2, 0xA3].into(),
                label: vec![0xB1, 0xB2].into(),
                output_len: 48,
                output: Vec::new().into(),
            }),
        );

        let tls = unsafe {
            &mut *(ffi.ck_mechanism().pParameter as *mut cryptoki_sys::CK_TLS_PRF_PARAMS)
        };
        assert!(!tls.pOutput.is_null());
        assert!(!tls.pulOutputLen.is_null());
        // Provider-style write: 32 of the 48 requested bytes.
        let written = [0x5Au8; 32];
        unsafe {
            std::ptr::copy_nonoverlapping(written.as_ptr(), tls.pOutput, written.len());
            *tls.pulOutputLen = written.len() as cryptoki_sys::CK_ULONG;
        }

        match ffi.output_params() {
            Some(CkMechanismParams::TlsPrf(params)) => {
                assert_eq!(params.seed, vec![0xA1, 0xA2, 0xA3].into());
                assert_eq!(params.label, vec![0xB1, 0xB2].into());
                assert_eq!(params.output_len, 32, "provider-written length");
                assert_eq!(params.output, vec![0x5A; 32].into(), "provider-written bytes");
            }
            other => panic!("unexpected output params: {other:?}"),
        }
    }

    #[test]
    fn wtls_prf_output_params_surface_provider_written_output() {
        // W1-C5-01: same provider-write contract as TLS PRF, plus the
        // echoed digest mechanism.
        let ffi = convert(
            CkMechanismType::WTLS_PRF,
            CkMechanismParams::WtlsPrf(WtlsPrfParams {
                digest_mechanism: CkMechanismType::SHA256,
                seed: vec![0xC1, 0xC2].into(),
                label: vec![0xD1].into(),
                output_len: 20,
                output: Vec::new().into(),
            }),
        );

        let wtls = unsafe {
            &mut *(ffi.ck_mechanism().pParameter as *mut cryptoki_sys::CK_WTLS_PRF_PARAMS)
        };
        assert!(!wtls.pOutput.is_null());
        assert!(!wtls.pulOutputLen.is_null());
        let written = [0xA5u8; 20];
        unsafe {
            std::ptr::copy_nonoverlapping(written.as_ptr(), wtls.pOutput, written.len());
            *wtls.pulOutputLen = written.len() as cryptoki_sys::CK_ULONG;
        }

        match ffi.output_params() {
            Some(CkMechanismParams::WtlsPrf(params)) => {
                assert_eq!(params.digest_mechanism.0, CkMechanismType::SHA256.0);
                assert_eq!(params.seed, vec![0xC1, 0xC2].into());
                assert_eq!(params.label, vec![0xD1].into());
                assert_eq!(params.output_len, 20, "provider-written length");
                assert_eq!(params.output, vec![0xA5; 20].into(), "provider-written bytes");
            }
            other => panic!("unexpected output params: {other:?}"),
        }
    }

    #[test]
    fn ssl3_master_key_derive_output_params_surface_negotiated_version() {
        // W1-C5-01: `pVersion` is OUT — the provider writes the
        // negotiated version (mirrors the Tls12MasterKeyDerive arm).
        let ffi = convert(
            CkMechanismType::SSL3_MASTER_KEY_DERIVE,
            CkMechanismParams::Ssl3MasterKeyDerive(Ssl3MasterKeyDeriveParams {
                random_info: SslRandomData {
                    client_random: vec![0x11; 32],
                    server_random: vec![0x22; 32],
                },
                version_major: 3,
                version_minor: 0,
            }),
        );

        let ssl3 = unsafe {
            &mut *(ffi.ck_mechanism().pParameter
                as *mut cryptoki_sys::CK_SSL3_MASTER_KEY_DERIVE_PARAMS)
        };
        assert!(!ssl3.pVersion.is_null());
        unsafe {
            (*ssl3.pVersion).major = 3;
            (*ssl3.pVersion).minor = 3;
        }

        match ffi.output_params() {
            Some(CkMechanismParams::Ssl3MasterKeyDerive(params)) => {
                assert_eq!(params.random_info.client_random, [0x11; 32]);
                assert_eq!(params.random_info.server_random, [0x22; 32]);
                assert_eq!(params.version_major, 3);
                assert_eq!(params.version_minor, 3, "provider-negotiated version");
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
                digest_mechanism: CkMechanismType::SHA256,
                mac_size_bits: 160,
                key_size_bits: 128,
                iv_size_bits: 32,
                sequence_number: 7,
                is_export: true,
                random_info: WtlsRandomData {
                    client_random: vec![0xC1, 0xC2],
                    server_random: vec![0xD1, 0xD2],
                },
                mac_secret_handle: CkObjectHandle(0),
                key_handle: CkObjectHandle(0),
                iv: Vec::new().into(),
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
                assert_eq!(params.digest_mechanism.0, CkMechanismType::SHA256.0);
                assert_eq!(params.mac_size_bits, 160);
                assert_eq!(params.key_size_bits, 128);
                assert_eq!(params.iv_size_bits, 32);
                assert_eq!(params.sequence_number, 7);
                assert!(params.is_export);
                assert_eq!(params.random_info.client_random, [0xC1, 0xC2]);
                assert_eq!(params.random_info.server_random, [0xD1, 0xD2]);
                assert_eq!(params.mac_secret_handle.0, 101);
                assert_eq!(params.key_handle.0, 202);
                assert_eq!(params.iv, SecretBytes::copy_from_slice(&[0xA1, 0xA2, 0xA3, 0xA4]));
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
                prf_hash_mechanism: CkMechanismType(0),
                client_mac_secret_handle: CkObjectHandle(0),
                server_mac_secret_handle: CkObjectHandle(0),
                client_key_handle: CkObjectHandle(0),
                server_key_handle: CkObjectHandle(0),
                client_iv: Vec::new().into(),
                server_iv: Vec::new().into(),
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
                assert_eq!(params.prf_hash_mechanism.0, 0);
                assert_eq!(params.client_mac_secret_handle.0, 101);
                assert_eq!(params.server_mac_secret_handle.0, 102);
                assert_eq!(params.client_key_handle.0, 201);
                assert_eq!(params.server_key_handle.0, 202);
                assert_eq!(
                    params.client_iv,
                    SecretBytes::copy_from_slice(&[0xA1, 0xA2, 0xA3, 0xA4])
                );
                assert_eq!(
                    params.server_iv,
                    SecretBytes::copy_from_slice(&[0xB1, 0xB2, 0xB3, 0xB4])
                );
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
                prf_hash_mechanism: CkMechanismType::SHA256,
                client_mac_secret_handle: CkObjectHandle(0),
                server_mac_secret_handle: CkObjectHandle(0),
                client_key_handle: CkObjectHandle(0),
                server_key_handle: CkObjectHandle(0),
                client_iv: Vec::new().into(),
                server_iv: Vec::new().into(),
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
                assert_eq!(params.prf_hash_mechanism.0, CkMechanismType::SHA256.0);
                assert_eq!(params.client_mac_secret_handle.0, 111);
                assert_eq!(params.server_mac_secret_handle.0, 112);
                assert_eq!(params.client_key_handle.0, 211);
                assert_eq!(params.server_key_handle.0, 212);
                assert_eq!(
                    params.client_iv,
                    SecretBytes::copy_from_slice(&[0xC1, 0xC2, 0xC3, 0xC4])
                );
                assert_eq!(
                    params.server_iv,
                    SecretBytes::copy_from_slice(&[0xD1, 0xD2, 0xD3, 0xD4])
                );
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

        // E0793: CK_MECHANISM is packed on Windows; assert on a by-value copy.
        let ul_parameter_len = ffi.ck_mechanism().ulParameterLen;
        assert_eq!(ul_parameter_len, 16);
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

        // E0793: CK structs are packed on Windows; assert on by-value copies.
        let ul_parameter_len = ffi.ck_mechanism().ulParameterLen;
        assert_eq!(
            ul_parameter_len,
            std::mem::size_of::<cryptoki_sys::CK_AES_CTR_PARAMS>() as cryptoki_sys::CK_ULONG
        );
        let ctr =
            unsafe { &*(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_AES_CTR_PARAMS) };
        let ul_counter_bits = ctr.ulCounterBits;
        assert_eq!(ul_counter_bits, 128);
        assert_eq!(ctr.cb, [0x33; 16]);
    }

    #[test]
    fn extract_params_reconstruct_ck_ulong_bit_position() {
        let ffi = convert(
            CkMechanismType(0x0000_0365),
            CkMechanismParams::Extract(ExtractParams { bit_position: 21 }),
        );

        // E0793: CK_MECHANISM is packed on Windows; assert on a by-value copy.
        let ul_parameter_len = ffi.ck_mechanism().ulParameterLen;
        assert_eq!(
            ul_parameter_len,
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
            CkMechanismParams::ObjectHandle(ObjectHandleParam { handle: CkObjectHandle(0xCAFE) }),
        );

        // E0793: CK_MECHANISM is packed on Windows; assert on a by-value copy.
        let ul_parameter_len = ffi.ck_mechanism().ulParameterLen;
        assert_eq!(
            ul_parameter_len,
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
                data: vec![0xDE, 0xAD, 0xBE, 0xEF].into(),
            }),
        );

        // E0793: CK structs are packed on Windows; assert on by-value copies.
        let ul_parameter_len = ffi.ck_mechanism().ulParameterLen;
        assert_eq!(
            ul_parameter_len,
            std::mem::size_of::<cryptoki_sys::CK_KEY_DERIVATION_STRING_DATA>()
                as cryptoki_sys::CK_ULONG
        );
        let params = unsafe {
            &*(ffi.ck_mechanism().pParameter as *const cryptoki_sys::CK_KEY_DERIVATION_STRING_DATA)
        };
        let ul_len = params.ulLen;
        assert_eq!(ul_len, 4);
        let data = unsafe { std::slice::from_raw_parts(params.pData, params.ulLen as usize) };
        assert_eq!(data, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn sign_additional_context_reconstructs_c_struct() {
        let ffi = convert(
            CkMechanismType(0x0000_0502),
            CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
                hedge_variant: 1,
                context: vec![0xA1, 0xA2, 0xA3].into(),
                hash: CkMechanismType(0),
            }),
        );

        // E0793: CK structs are packed on Windows; assert on by-value copies.
        let ul_parameter_len = ffi.ck_mechanism().ulParameterLen;
        assert_eq!(
            ul_parameter_len,
            std::mem::size_of::<super::FfiSignAdditionalContext>() as cryptoki_sys::CK_ULONG
        );
        let params =
            unsafe { &*(ffi.ck_mechanism().pParameter as *const super::FfiSignAdditionalContext) };
        let (hedge_variant, ul_context_len) = (params.hedge_variant, params.ul_context_len);
        assert_eq!(hedge_variant, 1);
        assert_eq!(ul_context_len, 3);
        let context =
            unsafe { std::slice::from_raw_parts(params.p_context, params.ul_context_len as usize) };
        assert_eq!(context, [0xA1, 0xA2, 0xA3]);
    }

    #[test]
    fn hash_sign_additional_context_reconstructs_c_struct() {
        // hash != 0 → the larger CK_HASH_SIGN_ADDITIONAL_CONTEXT (generic
        // CKM_HASH_ML_DSA / CKM_HASH_SLH_DSA), with the trailing hash mechanism.
        let ffi = convert(
            CkMechanismType::HASH_ML_DSA,
            CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
                hedge_variant: 1,
                context: vec![0xB1, 0xB2].into(),
                hash: CkMechanismType::SHA256,
            }),
        );

        // E0793: CK structs are packed on Windows; assert on by-value copies.
        let ul_parameter_len = ffi.ck_mechanism().ulParameterLen;
        assert_eq!(
            ul_parameter_len,
            std::mem::size_of::<super::FfiHashSignAdditionalContext>() as cryptoki_sys::CK_ULONG
        );
        let params = unsafe {
            &*(ffi.ck_mechanism().pParameter as *const super::FfiHashSignAdditionalContext)
        };
        let (hedge_variant, ul_context_len, hash) =
            (params.hedge_variant, params.ul_context_len, params.hash);
        assert_eq!(hedge_variant, 1);
        assert_eq!(ul_context_len, 2);
        assert_eq!(hash, 0x0000_0250);
        let context =
            unsafe { std::slice::from_raw_parts(params.p_context, params.ul_context_len as usize) };
        assert_eq!(context, [0xB1, 0xB2]);
    }

    #[test]
    fn kmac_params_reconstruct_c_struct_and_customization_string() {
        let ffi = convert(
            CkMechanismType(0x8000_0001),
            CkMechanismParams::Kmac(KmacParams {
                key_handle: CkObjectHandle(0xCAFE),
                mac_length: 64,
                customization_string: b"custom".to_vec().into(),
            }),
        );

        // E0793: CK structs are packed on Windows; assert on by-value copies.
        let ul_parameter_len = ffi.ck_mechanism().ulParameterLen;
        assert_eq!(
            ul_parameter_len,
            std::mem::size_of::<super::FfiKmacParams>() as cryptoki_sys::CK_ULONG
        );
        let kmac = unsafe { &*(ffi.ck_mechanism().pParameter as *const super::FfiKmacParams) };
        let (h_key, ul_mac_length, ul_customization_string_len) =
            (kmac.h_key, kmac.ul_mac_length, kmac.ul_customization_string_len);
        assert_eq!(h_key, 0xCAFE);
        assert_eq!(ul_mac_length, 64);
        assert_eq!(ul_customization_string_len, 6);
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
                key_handle: CkObjectHandle(0xA11CE),
                tr: b"precomputed-tr".to_vec().into(),
                context: b"context".to_vec().into(),
            }),
        );

        // E0793: CK structs are packed on Windows; assert on by-value copies.
        let ul_parameter_len = ffi.ck_mechanism().ulParameterLen;
        assert_eq!(
            ul_parameter_len,
            std::mem::size_of::<super::FfiMuGenParams>() as cryptoki_sys::CK_ULONG
        );
        let mu_gen = unsafe { &*(ffi.ck_mechanism().pParameter as *const super::FfiMuGenParams) };
        let (h_key, ul_tr_len, ul_ctx_len) = (mu_gen.h_key, mu_gen.ul_tr_len, mu_gen.ul_ctx_len);
        assert_eq!(h_key, 0xA11CE);
        assert_eq!(ul_tr_len, 14);
        assert_eq!(ul_ctx_len, 7);
        let tr = unsafe { std::slice::from_raw_parts(mu_gen.p_tr, mu_gen.ul_tr_len as usize) };
        let context =
            unsafe { std::slice::from_raw_parts(mu_gen.p_ctx, mu_gen.ul_ctx_len as usize) };
        assert_eq!(tr, b"precomputed-tr");
        assert_eq!(context, b"context");
    }

    #[test]
    fn gcm_null_flags_materialize_null_pointers() {
        // F3/D2: only caller-NULL fields materialize NULL; empty non-NULL
        // fields keep a non-NULL pointer with len 0.
        for (iv_null, aad_null) in [(true, true), (true, false), (false, true), (false, false)] {
            let ffi = convert(
                CkMechanismType::AES_GCM,
                CkMechanismParams::Gcm(GcmParams {
                    iv: Vec::new(),
                    iv_bits: 0,
                    iv_buffer_len: 0,
                    aad: Vec::new().into(),
                    tag_bits: 128,
                    iv_null,
                    aad_null,
                }),
            );
            // E0793: CK structs are packed on Windows; assert on by-value copies.
            let gcm = unsafe {
                ffi.ck_mechanism().pParameter.cast::<cryptoki_sys::CK_GCM_PARAMS>().read_unaligned()
            };
            let (p_iv, ul_iv_len, p_aad, ul_aad_len) =
                (gcm.pIv, gcm.ulIvLen, gcm.pAAD, gcm.ulAADLen);
            assert_eq!(p_iv.is_null(), iv_null, "pIv nullness");
            assert_eq!(ul_iv_len, 0);
            assert_eq!(p_aad.is_null(), aad_null, "pAAD nullness");
            assert_eq!(ul_aad_len, 0);
        }
    }

    #[test]
    fn ccm_null_flags_materialize_null_pointers() {
        // Only caller-NULL fields materialize NULL; empty non-NULL
        // fields keep a non-NULL pointer with len 0.
        for (nonce_null, aad_null) in [(true, true), (true, false), (false, true), (false, false)] {
            let ffi = convert(
                CkMechanismType::AES_CCM,
                CkMechanismParams::Ccm(CcmParams {
                    data_len: 16,
                    nonce: Vec::new(),
                    aad: Vec::new().into(),
                    mac_len: 12,
                    nonce_null,
                    aad_null,
                }),
            );
            // E0793: CK structs are packed on Windows; assert on by-value copies.
            let ccm = unsafe {
                ffi.ck_mechanism().pParameter.cast::<cryptoki_sys::CK_CCM_PARAMS>().read_unaligned()
            };
            let (p_nonce, ul_nonce_len, p_aad, ul_aad_len) =
                (ccm.pNonce, ccm.ulNonceLen, ccm.pAAD, ccm.ulAADLen);
            assert_eq!(p_nonce.is_null(), nonce_null, "pNonce nullness");
            assert_eq!(ul_nonce_len, 0);
            assert_eq!(p_aad.is_null(), aad_null, "pAAD nullness");
            assert_eq!(ul_aad_len, 0);
        }
    }

    #[test]
    fn oaep_source_null_materializes_null_pointer() {
        // F3/D2: only a caller-NULL source materializes NULL; an empty
        // non-NULL source keeps a non-NULL pointer with len 0.
        for source_null in [true, false] {
            let ffi = convert(
                CkMechanismType::RSA_PKCS_OAEP,
                CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
                    hash_alg: CkMechanismType::SHA256,
                    mgf: CkMgf(1),
                    source: CkOaepSource(1),
                    source_data: Vec::new().into(),
                    source_null,
                }),
            );
            // E0793: CK structs are packed on Windows; assert on by-value copies.
            let oaep = unsafe {
                ffi.ck_mechanism()
                    .pParameter
                    .cast::<cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS>()
                    .read_unaligned()
            };
            let (p_source_data, ul_source_data_len) = (oaep.pSourceData, oaep.ulSourceDataLen);
            assert_eq!(p_source_data.is_null(), source_null, "pSourceData nullness");
            assert_eq!(ul_source_data_len, 0);
        }
    }

    #[test]
    fn nested_oaep_empty_key_honors_source_null_like_top_level() {
        // W1-L4-10: nested OAEP (inside RSA_AES_KEY_WRAP) with an empty key must
        // convert byte-identically to the top-level OAEP conversion of the same
        // input. Empty-input pointers are deterministic (NULL or dangling), so
        // comparing every field including the pointer value is byte equality of
        // all initialized struct bytes (padding excluded).
        for source_null in [true, false] {
            let oaep_params = RsaPkcsOaepParams {
                hash_alg: CkMechanismType::SHA256,
                mgf: CkMgf(1),
                source: CkOaepSource(1),
                source_data: Vec::new().into(),
                source_null,
            };
            let top = convert(
                CkMechanismType::RSA_PKCS_OAEP,
                CkMechanismParams::RsaPkcsOaep(oaep_params.clone()),
            );
            let nested = convert(
                CkMechanismType::RSA_AES_KEY_WRAP,
                CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams {
                    aes_key_bits: 256,
                    oaep_params,
                }),
            );
            // E0793: CK structs are packed on Windows; assert on by-value copies.
            let top_oaep = unsafe {
                top.ck_mechanism()
                    .pParameter
                    .cast::<cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS>()
                    .read_unaligned()
            };
            let wrap = unsafe {
                nested
                    .ck_mechanism()
                    .pParameter
                    .cast::<super::FfiRsaAesKeyWrapParams>()
                    .read_unaligned()
            };
            assert!(!wrap.p_oaep_params.is_null(), "nested OAEP pointer is set");
            let nested_oaep = unsafe { wrap.p_oaep_params.read_unaligned() };
            let (top_hash, top_mgf, top_source, top_ptr, top_len) = (
                top_oaep.hashAlg,
                top_oaep.mgf,
                top_oaep.source,
                top_oaep.pSourceData,
                top_oaep.ulSourceDataLen,
            );
            let (nested_hash, nested_mgf, nested_source, nested_ptr, nested_len) = (
                nested_oaep.hashAlg,
                nested_oaep.mgf,
                nested_oaep.source,
                nested_oaep.pSourceData,
                nested_oaep.ulSourceDataLen,
            );
            assert_eq!(
                (nested_hash, nested_mgf, nested_source),
                (top_hash, top_mgf, top_source),
                "source_null={source_null}: nested OAEP scalars must match top-level"
            );
            assert_eq!(
                nested_ptr, top_ptr,
                "source_null={source_null}: nested pSourceData must equal top-level"
            );
            assert_eq!(
                nested_len, top_len,
                "source_null={source_null}: nested ulSourceDataLen must equal top-level"
            );
            assert_eq!(nested_len, 0);
            assert_eq!(nested_ptr.is_null(), source_null, "pSourceData nullness");
        }

        // Non-empty nested keys are unchanged: valid pointer, correct bytes.
        let oaep_params = RsaPkcsOaepParams {
            hash_alg: CkMechanismType::SHA256,
            mgf: CkMgf(1),
            source: CkOaepSource(1),
            source_data: vec![0xA0, 0xA1, 0xA2].into(),
            source_null: false,
        };
        let nested = convert(
            CkMechanismType::RSA_AES_KEY_WRAP,
            CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams {
                aes_key_bits: 256,
                oaep_params,
            }),
        );
        let wrap = unsafe {
            nested
                .ck_mechanism()
                .pParameter
                .cast::<super::FfiRsaAesKeyWrapParams>()
                .read_unaligned()
        };
        let nested_oaep = unsafe { wrap.p_oaep_params.read_unaligned() };
        let (p_source_data, ul_source_data_len) =
            (nested_oaep.pSourceData, nested_oaep.ulSourceDataLen);
        assert!(!p_source_data.is_null());
        assert_eq!(ul_source_data_len, 3);
        let source = unsafe {
            std::slice::from_raw_parts(p_source_data as *const u8, ul_source_data_len as usize)
        };
        assert_eq!(source, [0xA0, 0xA1, 0xA2]);
    }
}

#[cfg(test)]
mod utf8_trim_tests {
    use super::{session_state_from_ck, utf8_trim};
    use pkcs11_proxy_ng_types::{CkSessionState, PKCS11_TOKEN_LABEL_LEN, space_pad_into};

    // W1-L11-12: local pad helper over the shared implementation.
    fn space_pad<const N: usize>(value: &str) -> [u8; N] {
        let mut padded = [0u8; N];
        space_pad_into(&mut padded, value);
        padded
    }

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
        let mut buf = [b' '; PKCS11_TOKEN_LABEL_LEN];
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

    // W1-L11-12 pin: vectors mirrored from the shim's `pad_string`
    // tests — both implementations must produce byte-identical
    // outputs before unification, and the shared helper after.
    #[test]
    fn space_pad_matches_shim_pad_string_vectors() {
        assert_eq!(&space_pad::<8>("hi"), b"hi      ");
        assert_eq!(&space_pad::<4>("ABCD"), b"ABCD");
        assert_eq!(&space_pad::<6>(""), b"      ");
        assert_eq!(&space_pad::<4>("ABCDEFGH"), b"ABCD");
        // Byte-wise copy: a multibyte char may split at the edge.
        assert_eq!(&space_pad::<4>("héllo"), &[0x68, 0xC3, 0xA9, 0x6C]);
        let label = space_pad::<PKCS11_TOKEN_LABEL_LEN>("My Test Token");
        assert_eq!(&label[..13], b"My Test Token");
        assert!(label[13..].iter().all(|&b| b == b' '));
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
        // E0793: CK_ATTRIBUTE is packed on Windows; assert on a by-value copy.
        let ul_value_len = ffi.attrs[0].ulValueLen;
        assert_eq!(ul_value_len, 0);
    }

    #[test]
    fn raw_attribute_queries_zero_length_exact_query_yields_null_pvalue() {
        // T4-FIX: a 0-length exact query (buffer_present=true, buffer_len=0 —
        // e.g. a sub-element cross-width buffer mapped to 0) must pass NULL
        // pValue, not the dangling Vec::new() pointer (0x1): backends that
        // null-check pValue and then write (NSS softokn) segfault the daemon.
        let ffi = FfiAttributeQueries::from_queries(&[CkAttributeQuery {
            attr_type: CkAttributeType::CLASS,
            buffer_present: true,
            buffer_len: 0,
            nested: None,
        }])
        .expect("ffi queries");

        assert_eq!(ffi.attrs.len(), 1);
        assert!(ffi.attrs[0].pValue.is_null());
        // E0793: CK_ATTRIBUTE is packed on Windows; assert on a by-value copy.
        let ul_value_len = ffi.attrs[0].ulValueLen;
        assert_eq!(ul_value_len, 0);
    }

    #[test]
    fn nested_zero_length_sub_query_yields_null_sub_pvalue() {
        // T4-AUDIT site 2: a nested exact sub-query with a 0-length buffer
        // (shim: sub CK_ATTRIBUTE with non-null pValue + ulValueLen 0 — the
        // nested capture path has no zero-length reject) must pass NULL for
        // the sub pValue, not the dangling empty-Vec pointer.
        let stride = std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>() as u64;
        let ffi = FfiAttributeQueries::from_queries(&[CkAttributeQuery {
            attr_type: CkAttributeType::WRAP_TEMPLATE,
            buffer_present: true,
            buffer_len: stride,
            nested: Some(vec![CkAttributeQuery {
                attr_type: CkAttributeType(0),
                buffer_present: true,
                buffer_len: 0,
                nested: None,
            }]),
        }])
        .expect("ffi queries");

        assert_eq!(ffi.attrs.len(), 1);
        assert!(!ffi.attrs[0].pValue.is_null(), "one-entry template box stays materialized");
        let sub_pvalue = unsafe {
            std::slice::from_raw_parts(ffi.attrs[0].pValue as *const cryptoki_sys::CK_ATTRIBUTE, 1)
        }[0]
        .pValue;
        // E0793: CK_ATTRIBUTE is packed on Windows; sub length by-value copy.
        let sub_len = unsafe {
            std::slice::from_raw_parts(ffi.attrs[0].pValue as *const cryptoki_sys::CK_ATTRIBUTE, 1)
        }[0]
        .ulValueLen;
        assert!(sub_pvalue.is_null());
        assert_eq!(sub_len, 0);
    }

    #[test]
    fn nested_preset_sub_query_type_is_reconstructed_verbatim() {
        // F7/D5: a caller-preset nested query type (shim: sub CK_ATTRIBUTE
        // with type_ set, e.g. CKA_SENSITIVE inside CKA_UNWRAP_TEMPLATE)
        // must reach the backend verbatim — forcing type 0 rewrites the
        // caller's query and SoftHSM answers CKR_GENERAL_ERROR.
        let stride = std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>() as u64;
        let ffi = FfiAttributeQueries::from_queries(&[CkAttributeQuery {
            attr_type: CkAttributeType::UNWRAP_TEMPLATE,
            buffer_present: true,
            buffer_len: stride,
            nested: Some(vec![CkAttributeQuery {
                attr_type: CkAttributeType::SENSITIVE,
                buffer_present: true,
                buffer_len: 1,
                nested: None,
            }]),
        }])
        .expect("ffi queries");

        assert_eq!(ffi.attrs.len(), 1);
        // E0793: CK_ATTRIBUTE is packed on Windows; sub type by-value copy.
        let sub_type = unsafe {
            std::slice::from_raw_parts(ffi.attrs[0].pValue as *const cryptoki_sys::CK_ATTRIBUTE, 1)
        }[0]
        .type_;
        assert_eq!(sub_type, CkAttributeType::SENSITIVE.0 as cryptoki_sys::CK_ATTRIBUTE_TYPE);
    }

    #[test]
    fn empty_nested_template_query_yields_null_parent_pvalue() {
        // T4-AUDIT site 5: a degenerate nested template query (shim: template
        // attr with non-null pValue + ulValueLen 0 → nested `Some(vec![])`,
        // buffer_len 0) must pass NULL for the parent pValue, not the dangling
        // empty-box-slice pointer.
        let ffi = FfiAttributeQueries::from_queries(&[CkAttributeQuery {
            attr_type: CkAttributeType::WRAP_TEMPLATE,
            buffer_present: true,
            buffer_len: 0,
            nested: Some(vec![]),
        }])
        .expect("ffi queries");

        assert_eq!(ffi.attrs.len(), 1);
        assert!(ffi.attrs[0].pValue.is_null());
        // E0793: CK_ATTRIBUTE is packed on Windows; assert on a by-value copy.
        let ul_value_len = ffi.attrs[0].ulValueLen;
        assert_eq!(ul_value_len, 0);
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

#[cfg(test)]
mod null_template_tests {
    use super::FfiAttrs;

    #[test]
    fn opt_slice_none_flags_null_template() {
        // F3/D2: a caller-NULL template is flagged so the FFI call
        // receives NULL, not the empty array's address.
        let none = FfiAttrs::from_opt_slice(None).expect("none template converts");
        assert!(none.null_template);
        assert!(none.attrs.is_empty());
        let empty = FfiAttrs::from_opt_slice(Some(&[])).expect("empty template converts");
        assert!(!empty.null_template);
        assert!(empty.attrs.is_empty());
    }
}

#[cfg(test)]
mod output_params_equal_tests {
    //! W1-C4-04: `output_params_equal` must agree with `output_params` on
    //! every mechanism-out arm, so `call_bytes_exact_with_mechanism_output`
    //! can reuse the pre-call snapshot when the provider wrote nothing and
    //! snapshot once per call instead of twice.
    use super::mechanism_to_ffi;
    use pkcs11_proxy_ng_types::{
        CkAttribute, CkAttributeType, CkAttributeValue, CkMechanism, CkMechanismParams,
        CkMechanismType, CkObjectHandle, GcmParams, PbeParams, PrfDataParam, SecretBytes,
        Sp800108DerivedKey, Sp800108FeedbackKdfParams, Sp800108KdfParams, Ssl3KeyMatParams,
        Ssl3MasterKeyDeriveParams, SslRandomData, Tls12MasterKeyDeriveParams, TlsPrfParams,
        WtlsKeyMatParams, WtlsMasterKeyDeriveParams, WtlsPrfParams, WtlsRandomData,
    };

    fn convert(mechanism_type: CkMechanismType, params: CkMechanismParams) -> super::FfiMechanism {
        mechanism_to_ffi(&CkMechanism { mechanism_type, params: Some(params) })
            .expect("mechanism converts to ffi")
    }

    fn gcm_fixture() -> CkMechanismParams {
        CkMechanismParams::Gcm(GcmParams {
            iv: vec![0x11; 12],
            iv_bits: 96,
            iv_buffer_len: 12,
            aad: b"aad-bytes".to_vec().into(),
            tag_bits: 128,
            iv_null: false,
            aad_null: false,
        })
    }

    fn all_output_fixtures() -> Vec<(CkMechanismType, CkMechanismParams, &'static str)> {
        // Arm selection keys off the params variant, not the mechanism
        // type (which is only narrowed); nearby consts stand in where no
        // exact official const exists in this checkout.
        vec![
            (CkMechanismType::AES_GCM, gcm_fixture(), "Gcm"),
            (
                CkMechanismType::TLS12_MASTER_KEY_DERIVE,
                CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
                    random_info: SslRandomData {
                        client_random: vec![0x01; 32],
                        server_random: vec![0x02; 32],
                    },
                    version_major: 3,
                    version_minor: 3,
                    prf_hash_mechanism: CkMechanismType::SHA256,
                }),
                "Tls12MasterKeyDerive",
            ),
            (
                CkMechanismType::WTLS_MASTER_KEY_DERIVE,
                CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
                    digest_mechanism: CkMechanismType::SHA256,
                    random_info: WtlsRandomData {
                        client_random: vec![0x03; 20],
                        server_random: vec![0x04; 20],
                    },
                    version: 1,
                }),
                "WtlsMasterKeyDerive",
            ),
            (
                CkMechanismType::WTLS_MASTER_KEY_DERIVE,
                CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
                    digest_mechanism: CkMechanismType::SHA256,
                    mac_size_bits: 128,
                    key_size_bits: 128,
                    iv_size_bits: 128,
                    sequence_number: 7,
                    is_export: false,
                    random_info: WtlsRandomData {
                        client_random: vec![0x05; 20],
                        server_random: vec![0x06; 20],
                    },
                    mac_secret_handle: CkObjectHandle(11),
                    key_handle: CkObjectHandle(12),
                    iv: vec![0x07; 16].into(),
                }),
                "WtlsKeyMat",
            ),
            (
                CkMechanismType::SSL3_KEY_AND_MAC_DERIVE,
                CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
                    mac_size_bits: 128,
                    key_size_bits: 128,
                    iv_size_bits: 64,
                    is_export: false,
                    random_info: SslRandomData {
                        client_random: vec![0x08; 32],
                        server_random: vec![0x09; 32],
                    },
                    prf_hash_mechanism: CkMechanismType(0),
                    client_mac_secret_handle: CkObjectHandle(21),
                    server_mac_secret_handle: CkObjectHandle(22),
                    client_key_handle: CkObjectHandle(23),
                    server_key_handle: CkObjectHandle(24),
                    client_iv: vec![0x0A; 8].into(),
                    server_iv: vec![0x0B; 8].into(),
                }),
                "Ssl3KeyMat",
            ),
            (
                CkMechanismType::TLS12_KEY_AND_MAC_DERIVE,
                CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
                    mac_size_bits: 128,
                    key_size_bits: 128,
                    iv_size_bits: 64,
                    is_export: false,
                    random_info: SslRandomData {
                        client_random: vec![0x0C; 32],
                        server_random: vec![0x0D; 32],
                    },
                    prf_hash_mechanism: CkMechanismType::SHA256,
                    client_mac_secret_handle: CkObjectHandle(31),
                    server_mac_secret_handle: CkObjectHandle(32),
                    client_key_handle: CkObjectHandle(33),
                    server_key_handle: CkObjectHandle(34),
                    client_iv: vec![0x0E; 8].into(),
                    server_iv: vec![0x0F; 8].into(),
                }),
                "Tls12KeyMat",
            ),
            (
                CkMechanismType::SP800_108_COUNTER_KDF,
                CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                    prf_type: CkMechanismType(0x0000_0251), // CKM_SHA256_HMAC
                    data_params: vec![PrfDataParam { type_: 1, value: b"counter".to_vec().into() }],
                    additional_derived_keys: vec![Sp800108DerivedKey {
                        template: vec![CkAttribute {
                            attr_type: CkAttributeType::LABEL,
                            value: Some(CkAttributeValue::String("kdf".to_string().into())),
                        }],
                        key_handle: CkObjectHandle(41),
                    }],
                }),
                "Sp800108Kdf",
            ),
            (
                CkMechanismType::SP800_108_FEEDBACK_KDF,
                CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                    prf_type: CkMechanismType(0x0000_0251), // CKM_SHA256_HMAC
                    data_params: vec![PrfDataParam {
                        type_: 2,
                        value: b"feedback".to_vec().into(),
                    }],
                    iv: vec![0x10; 16],
                    additional_derived_keys: vec![Sp800108DerivedKey {
                        template: vec![CkAttribute {
                            attr_type: CkAttributeType::LABEL,
                            value: Some(CkAttributeValue::String("fb".to_string().into())),
                        }],
                        key_handle: CkObjectHandle(42),
                    }],
                }),
                "Sp800108FeedbackKdf",
            ),
            (
                CkMechanismType::TLS_PRF,
                CkMechanismParams::TlsPrf(TlsPrfParams {
                    seed: vec![0xA1, 0xA2].into(),
                    label: vec![0xB1].into(),
                    output_len: 48,
                    output: Vec::new().into(),
                }),
                "TlsPrf",
            ),
            (
                CkMechanismType::WTLS_PRF,
                CkMechanismParams::WtlsPrf(WtlsPrfParams {
                    digest_mechanism: CkMechanismType::SHA256,
                    seed: vec![0xC1].into(),
                    label: vec![0xD1].into(),
                    output_len: 20,
                    output: Vec::new().into(),
                }),
                "WtlsPrf",
            ),
            (
                CkMechanismType::SSL3_MASTER_KEY_DERIVE,
                CkMechanismParams::Ssl3MasterKeyDerive(Ssl3MasterKeyDeriveParams {
                    random_info: SslRandomData {
                        client_random: vec![0x11; 32],
                        server_random: vec![0x12; 32],
                    },
                    version_major: 3,
                    version_minor: 0,
                }),
                "Ssl3MasterKeyDerive",
            ),
            (
                CkMechanismType::PBE_SHA1_DES3_EDE_CBC,
                CkMechanismParams::Pbe(PbeParams {
                    init_vector: vec![0x13; 8].into(),
                    password: b"pw".to_vec().into(),
                    salt: b"salt".to_vec().into(),
                    iteration: 1000,
                }),
                "Pbe",
            ),
        ]
    }

    #[test]
    fn equal_agrees_with_output_params_on_every_arm() {
        for (mech_type, params, name) in all_output_fixtures() {
            let ffi = convert(mech_type, params);
            let snapshot = ffi.output_params();
            assert!(snapshot.is_some(), "{name} fixture must produce output params");
            assert!(
                ffi.output_params_equal(&snapshot),
                "{name}: equal() must agree with output_params() on unchanged backing"
            );
        }
        // Parameterless mechanisms produce no output params on either side.
        let no_param = mechanism_to_ffi(&CkMechanism {
            mechanism_type: CkMechanismType::SHA256,
            params: None,
        })
        .expect("parameterless converts");
        assert_eq!(no_param.output_params(), None);
        assert!(no_param.output_params_equal(&None));
        // PBE with an empty IV reports no output on either side.
        let pbe_null = convert(
            CkMechanismType::PBE_SHA1_DES3_EDE_CBC,
            CkMechanismParams::Pbe(PbeParams {
                init_vector: Vec::new().into(),
                password: b"pw".to_vec().into(),
                salt: b"salt".to_vec().into(),
                iteration: 1,
            }),
        );
        assert_eq!(pbe_null.output_params(), None);
        assert!(pbe_null.output_params_equal(&None));
    }

    #[test]
    fn equal_rejects_cross_arm_tampered_and_none_mismatch() {
        let fixtures = all_output_fixtures();
        let snapshots: Vec<_> = fixtures
            .iter()
            .map(|(mech_type, params, _)| convert(*mech_type, params.clone()).output_params())
            .collect();
        for (i, (mech_type, params, name)) in fixtures.iter().enumerate() {
            let ffi = convert(*mech_type, params.clone());
            // Cross-arm: another arm's snapshot never matches this backing.
            let other = &snapshots[(i + 1) % snapshots.len()];
            assert!(
                !ffi.output_params_equal(other),
                "{name}: cross-arm snapshot must not compare equal"
            );
            // None never matches an output-producing backing.
            assert!(!ffi.output_params_equal(&None), "{name}: None must not match");
        }
        // Tampered scalar: flipping one GCM scalar breaks equality.
        let gcm = convert(CkMechanismType::AES_GCM, gcm_fixture());
        let mut tampered = gcm.output_params().expect("gcm snapshot");
        let CkMechanismParams::Gcm(ref mut p) = tampered else {
            panic!("gcm snapshot shape");
        };
        p.tag_bits ^= 0xFF;
        assert!(!gcm.output_params_equal(&Some(tampered)));
        // Tampered bytes: flipping one IV byte breaks equality.
        let mut tampered = gcm.output_params().expect("gcm snapshot");
        let CkMechanismParams::Gcm(ref mut p) = tampered else {
            panic!("gcm snapshot shape");
        };
        p.iv[0] ^= 0xFF;
        assert!(!gcm.output_params_equal(&Some(tampered)));
        // Tampered AAD: flipping one AAD byte breaks equality.
        let mut tampered = gcm.output_params().expect("gcm snapshot");
        let CkMechanismParams::Gcm(ref mut p) = tampered else {
            panic!("gcm snapshot shape");
        };
        let mut aad = p.aad.expose(|b| b.to_vec());
        aad[0] ^= 0xFF;
        p.aad = SecretBytes::new(aad);
        assert!(!gcm.output_params_equal(&Some(tampered)));
        // Tampered TLS version breaks equality on the TLS arm.
        let tls = convert(
            CkMechanismType::TLS12_MASTER_KEY_DERIVE,
            CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
                random_info: SslRandomData {
                    client_random: vec![0x01; 32],
                    server_random: vec![0x02; 32],
                },
                version_major: 3,
                version_minor: 3,
                prf_hash_mechanism: CkMechanismType::SHA256,
            }),
        );
        let mut tampered = tls.output_params().expect("tls snapshot");
        let CkMechanismParams::Tls12MasterKeyDerive(ref mut p) = tampered else {
            panic!("tls snapshot shape");
        };
        p.version_minor = 4;
        assert!(!tls.output_params_equal(&Some(tampered)));
    }

    #[test]
    fn equal_detects_provider_write_without_resnapshot() {
        // HSM-generated-IV pattern: the provider mutates the IV in place;
        // equal() must flip from true to false with no second snapshot.
        let ffi = convert(CkMechanismType::AES_GCM, gcm_fixture());
        let before = ffi.output_params();
        assert!(ffi.output_params_equal(&before));
        let gcm =
            unsafe { &mut *(ffi.ck_mechanism().pParameter as *mut cryptoki_sys::CK_GCM_PARAMS) };
        unsafe {
            gcm.pIv.write(0x42);
        }
        assert!(
            !ffi.output_params_equal(&before),
            "provider IV write must break equality with the pre-call snapshot"
        );
        assert!(ffi.output_params_equal(&ffi.output_params()));
    }

    #[test]
    fn output_params_has_no_double_copy() {
        // W1-C5-B07/W1-L13-06/W1-L4-19: random-info readback must copy
        // once (`x.to_vec()`), never twice (`x.clone().to_vec()`).
        let src = include_str!("mechanism.rs");
        assert!(
            !src.contains(".clone().to_vec()"),
            "output_params must not re-copy an already-owned clone"
        );
    }

    // W1-L12-03: the ns/iter printout IS this measurement test's
    // output (read with `-- --nocapture`); production code stays under
    // the workspace print/dbg deny.
    #[allow(clippy::print_stderr)]
    #[test]
    fn mechanism_clone_hotspot_measured() {
        // W1-C5-B06/W1-L13-05/W1-L13-06: measured note for the
        // per-Init backing clones. Prints ns/iter with `-- --nocapture`;
        // the bound below is ~1000x headroom over the measured ~1us and
        // exists only to catch pathological regression, not to gate flops.
        let mechanism =
            CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: Some(gcm_fixture()) };
        // Warm up once so first-touch allocation is out of the window.
        let ffi = mechanism_to_ffi(&mechanism).expect("gcm converts");
        let snapshot = ffi.output_params();
        assert!(ffi.output_params_equal(&snapshot));
        const ITERS: u32 = 2000;
        let start = std::time::Instant::now();
        for _ in 0..ITERS {
            let ffi = mechanism_to_ffi(&mechanism).expect("gcm converts");
            let snapshot = ffi.output_params();
            assert!(ffi.output_params_equal(&snapshot));
        }
        let elapsed = start.elapsed();
        let ns_per_iter = elapsed.as_nanos() / u128::from(ITERS);
        eprintln!(
            "task33-hotspot: mechanism_to_ffi(GCM-12B-iv)+output_params+equal = {ns_per_iter} ns/iter over {ITERS} iters"
        );
        assert!(ns_per_iter < 1_000_000, "hotspot blew past 1ms/iter: {ns_per_iter} ns");
    }
}
