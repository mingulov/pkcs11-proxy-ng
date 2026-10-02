//! R19 (S2 §6 + S2 §12 backend FFI tests, typed subset): typed + tail
//! reconstruction pins.
//!
//! Pure-conversion half (Miri-clean: no `FfiBackend`, no `dlopen` — the
//! `FfiBackend`-level typed/tail retention + failed-Init pins live in
//! `r19_init_retention_tests`, mirroring the R12 pure/retention split).
//!
//! Per-family matrix for EVERY R16 input-pointer family (the S2 §8 list)
//! and EVERY R18 tail envelope shape: `Null{0}` → NULL + 0; `Null{n}` →
//! NULL + narrowed `n`; `Present([])` → stable non-NULL + 0;
//! `Present(data)` → owned backing with exact bytes (aligned + zeroized —
//! never alignment-1 byte backing for provider-typed reads; the
//! `CK_ULONG` dereferences below are Miri-checked live alignment probes,
//! and every other typed read sits on `NativeAllocation<T>`/`Vec<T>` by
//! construction). Tail vectors additionally pin presence/count/output
//! envelopes (output pointers, counts, null bits, KIP nesting).
//!
//! Out of scope (no pointer-bearing shape to reconstruct): scalar-only
//! families (PSS, RC5, TlsMac, Xeddsa, CTR/CBC-fixed, MacGeneral,
//! Extract, ObjectHandle), the Signal/CMS/ECIES/vendor shapes (no S2 §8
//! presence — arms untouched), S2 §8 "MGF" (a scalar enum, not a params
//! shape) and "PSS-flat" (router-level Flat carriage, R11-pinned).

use super::super::{mechanism_to_ffi, validate_for_ffi};
use pkcs11_proxy_ng_types::{
    AesCbcEncryptDataParams, AriaCbcEncryptDataParams, CamelliaCbcEncryptDataParams, CcmParams,
    CcmWrapParams, ChaCha20Params, CkAttribute, CkAttributeType, CkGeneratorFunction, CkKdf,
    CkMechanism, CkMechanismParams, CkMechanismType, CkMgf, CkOaepSource, CkObjectHandle,
    CkPbkdf2Prf, CkPbkdf2SaltSource, DesCbcEncryptDataParams, Ecdh1DeriveParams, Ecdh2DeriveParams,
    EcdhAesKeyWrapParams, EcmqvDeriveParams, EddsaParams, GcmParams, GcmWrapParams,
    Gostr3410DeriveParams, Gostr3410KeyWrapParams, HkdfParams, Ike1ExtendedDeriveParams,
    Ike1PrfDeriveParams, Ike2PrfPlusDeriveParams, IkePrfDeriveParams, KeaDeriveParams,
    KeyDerivationStringData, KeyWrapSetOaepParams, KipParams, KmacParams, MuGenParams, OtpParam,
    OtpParams, PbeParams, Pkcs5Pbkd2Params, PointerArray, PointerBytes, PrfDataParam, Rc5CbcParams,
    RsaAesKeyWrapParams, RsaPkcsOaepParams, Salsa20ChaCha20Poly1305Params, Salsa20Params,
    SecretBytes, SeedCbcEncryptDataParams, SignAdditionalContext, SkipjackPrivateWrapParams,
    SkipjackRelayxParams, Sp800108DerivedKey, Sp800108FeedbackKdfParams, Sp800108KdfParams,
    Ssl3KeyMatParams, Ssl3MasterKeyDeriveParams, SslRandomData, Tls12ExtendedMasterKeyDeriveParams,
    Tls12MasterKeyDeriveParams, TlsKdfParams, TlsPrfParams, WtlsKeyMatParams,
    WtlsMasterKeyDeriveParams, WtlsPrfParams, WtlsRandomData, X942Dh1DeriveParams,
    X942Dh2DeriveParams, X942MqvDeriveParams,
};

// Vendor-range mechanism ids for families without a named
// `CkMechanismType` constant (test-only; reconstruction keys off the
// params variant, never the id). Precedent: the shim's `CKM_TEST_*`.
const CKM_TEST_RSA_AES_KEY_WRAP: u64 = 0x8000_1901;
const CKM_TEST_RC5_CBC: u64 = 0x8000_1902;
const CKM_TEST_ARIA_CBC_ENCRYPT_DATA: u64 = 0x8000_1903;
const CKM_TEST_CAMELLIA_CBC_ENCRYPT_DATA: u64 = 0x8000_1904;
const CKM_TEST_SEED_CBC_ENCRYPT_DATA: u64 = 0x8000_1905;
const CKM_TEST_SALSA20_CHACHA20_POLY1305: u64 = 0x8000_1906;
const CKM_TEST_GCM_WRAP: u64 = 0x8000_1907;
const CKM_TEST_CCM_WRAP: u64 = 0x8000_1908;
const CKM_TEST_ECDH2_DERIVE: u64 = 0x8000_1909;
const CKM_TEST_KEY_WRAP_SET_OAEP: u64 = 0x8000_190A;
const CKM_TEST_TLS12_EXTENDED_MASTER_KEY_DERIVE: u64 = 0x8000_190B;
const CKM_TEST_WTLS_KEY_MAT: u64 = 0x8000_190C;
const CKM_TEST_KEA_DERIVE: u64 = 0x8000_190D;
const CKM_TEST_OTP: u64 = 0x8000_190E;
const CKM_TEST_SKIPJACK_PRIVATE_WRAP: u64 = 0x8000_190F;
const CKM_TEST_SKIPJACK_RELAYX: u64 = 0x8000_1910;
const CKM_TEST_KMAC: u64 = 0x8000_1911;
const CKM_TEST_MU_GEN: u64 = 0x8000_1912;
const CKM_TEST_ECDH1_COFACTOR_DERIVE: u64 = 0x8000_1913;

/// Validate (backend-local funnel: typed params pass through) + convert.
/// Every typed/tail reconstruction test funnels through here.
fn convert(params: CkMechanismParams, mechanism_type: CkMechanismType) -> super::FfiMechanism {
    let mechanism = CkMechanism { mechanism_type, params: Some(params) };
    let validated = validate_for_ffi(&mechanism).expect("test mechanism validates for FFI");
    mechanism_to_ffi(&validated).expect("test mechanism reconstructs")
}

// Test-only retention arena: probe closures return raw provider-view
// pointers into `FfiMechanism` backings, and without a surviving owner
// the pointee reads would be use-after-free (the `FfiMechanism` would
// drop at closure end). [`param_struct`] takes its `FfiMechanism` by
// value and retains it here, so every backing outlives the test
// thread. Dropped at thread exit — no leak, Miri-clean. (Direct
// `let ffi = ...` vectors don't need it — their owner outlives the
// reads — but share the same funnel.)
thread_local! {
    static RETAINED_FFI: std::cell::RefCell<Vec<super::FfiMechanism>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Read the C param struct behind `pParameter` (by value: on packed-struct
/// targets — Windows LLP64 — field references are rejected, so every
/// assertion below goes through by-value copies; see `native_owner_tests`
/// E0793). Panics on NULL (callers assert presence first). Takes `ffi`
/// by value and retains it in [`RETAINED_FFI`] (see above).
fn param_struct<T>(ffi: super::FfiMechanism) -> T {
    let outer = ffi.ck_mechanism();
    assert!(!outer.pParameter.is_null(), "param struct needs a non-NULL pParameter");
    // SAFETY: `pParameter` points into live FFI backing holding a `T`;
    // the copy carries no provenance.
    let value = unsafe { (outer.pParameter.cast::<T>()).read_unaligned() };
    RETAINED_FFI.with(|retained| retained.borrow_mut().push(ffi));
    value
}

/// Provider-view copy of one pointee extent: `len` bytes at `ptr`, or
/// empty when NULL (a NULL extent carries no readable bytes at any
/// declared length).
fn pointee_bytes(ptr: *const u8, len: u64) -> Vec<u8> {
    if ptr.is_null() {
        return Vec::new();
    }
    // SAFETY: non-NULL `ptr` designates `len` live backing bytes; the
    // copy carries no provenance.
    unsafe { std::slice::from_raw_parts(ptr, len as usize).to_vec() }
}

/// Assert one reconstructed pointer field: NULL-ness + exact length.
/// `what` names the field (every vector funnels through here, so the
/// panic location alone cannot identify the failing field).
fn assert_field<T>(
    what: &str,
    ptr: *mut T,
    len: cryptoki_sys::CK_ULONG,
    expect_null: bool,
    expect_len: u64,
) {
    assert_eq!(ptr.is_null(), expect_null, "{what}: pointer NULL-ness");
    assert_eq!(len as u64, expect_len, "{what}: declared length");
}

#[test]
fn r19_empty_non_null_deref_probe() {
    // R19(2): EMPTY_NON_NULL designates a real static byte, never NULL
    // nor dangling — providers may probe readability of the
    // `Present([])` leg, so the shared address must dereference.
    let ptr = super::EMPTY_NON_NULL;
    assert!(!ptr.is_null(), "empty-present legs share one non-NULL address");
    // SAFETY: EMPTY_NON_NULL designates the `EMPTY_BYTE` static.
    assert_eq!(unsafe { *ptr }, 0);
}

// ---------------------------------------------------------------------------
// RSA-OAEP (S2 §8 "OAEP")
// ---------------------------------------------------------------------------

fn oaep(source: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
        hash_alg: CkMechanismType::SHA256,
        mgf: CkMgf(1),
        source: CkOaepSource(1),
        source_data_presence: source,
    })
}

#[test]
fn r19_reconstruct_rsa_oaep() {
    // Null{n} → NULL + narrow(n) (the peer governs, not the legacy bool).
    let ffi = convert(oaep(PointerBytes::null_len(9)), CkMechanismType::RSA_PKCS_OAEP);
    let p: cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS = param_struct(ffi);
    let (src_ptr, src_len) = (p.pSourceData, p.ulSourceDataLen);
    assert_field("oaep/null-9", src_ptr, src_len, true, 9);

    // Null{0} → NULL + 0.
    let ffi = convert(oaep(PointerBytes::null_len(0)), CkMechanismType::RSA_PKCS_OAEP);
    let p: cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS = param_struct(ffi);
    assert_field("oaep/null-0", p.pSourceData, p.ulSourceDataLen, true, 0);

    // Present([]) → stable non-NULL + 0.
    let ffi = convert(oaep(PointerBytes::present_copy(&[])), CkMechanismType::RSA_PKCS_OAEP);
    let p: cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS = param_struct(ffi);
    assert_field("oaep/present-empty", p.pSourceData, p.ulSourceDataLen, false, 0);

    // Present(data) → owned backing with exact bytes.
    let input = vec![0xA5; 7];
    let ffi = convert(oaep(PointerBytes::present_copy(&input)), CkMechanismType::RSA_PKCS_OAEP);
    let p: cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS = param_struct(ffi);
    let (src_ptr, src_len) = (p.pSourceData, p.ulSourceDataLen);
    assert_field("oaep/present-data", src_ptr, src_len, false, 7);
    assert_eq!(pointee_bytes(src_ptr as *const u8, src_len as u64), input);
}

// ---------------------------------------------------------------------------
// GCM (S2 §8 "GCM") — incl. generated-IV capacity + huge-NULL forwarding
// ---------------------------------------------------------------------------

fn gcm(iv: PointerBytes, aad: PointerBytes, iv_buffer_len: u64) -> CkMechanismParams {
    CkMechanismParams::Gcm(GcmParams {
        iv_bits: 96,
        iv_buffer_len,
        tag_bits: 128,
        iv_presence: iv,
        aad_presence: aad,
    })
}

fn gcm_fields(
    ffi: super::FfiMechanism,
) -> (*mut u8, cryptoki_sys::CK_ULONG, *mut u8, cryptoki_sys::CK_ULONG) {
    let p: cryptoki_sys::CK_GCM_PARAMS = param_struct(ffi);
    (p.pIv, p.ulIvLen, p.pAAD, p.ulAADLen)
}

#[test]
fn r19_reconstruct_gcm() {
    // Null/n → NULL + n on both legs (distinct lengths catch leg swaps).
    let ffi = convert(
        gcm(PointerBytes::null_len(12), PointerBytes::null_len(16), 0),
        CkMechanismType::AES_GCM,
    );
    let (iv_ptr, iv_len, aad_ptr, aad_len) = gcm_fields(ffi);
    assert_field("gcm/null-iv-12", iv_ptr, iv_len, true, 12);
    assert_field("gcm/null-aad-16", aad_ptr, aad_len, true, 16);

    // Null{0} → NULL + 0 on both legs.
    let ffi = convert(
        gcm(PointerBytes::null_len(0), PointerBytes::null_len(0), 0),
        CkMechanismType::AES_GCM,
    );
    let (iv_ptr, iv_len, aad_ptr, aad_len) = gcm_fields(ffi);
    assert_field("gcm/null-iv-0", iv_ptr, iv_len, true, 0);
    assert_field("gcm/null-aad-0", aad_ptr, aad_len, true, 0);

    // Present([]) → stable non-NULL + 0 on both legs.
    let ffi = convert(
        gcm(PointerBytes::present_copy(&[]), PointerBytes::present_copy(&[]), 0),
        CkMechanismType::AES_GCM,
    );
    let (iv_ptr, iv_len, aad_ptr, aad_len) = gcm_fields(ffi);
    assert_field("gcm/empty-iv", iv_ptr, iv_len, false, 0);
    assert_field("gcm/empty-aad", aad_ptr, aad_len, false, 0);

    // Present(data) → exact bytes in owned backing (no client address bits).
    let iv_input = vec![0x11; 12];
    let aad_input = vec![0x22; 8];
    let (iv_addr, aad_addr) = (iv_input.as_ptr(), aad_input.as_ptr());
    let ffi = convert(
        gcm(PointerBytes::present_copy(&iv_input), PointerBytes::present_copy(&aad_input), 0),
        CkMechanismType::AES_GCM,
    );
    let (iv_ptr, iv_len, aad_ptr, aad_len) = gcm_fields(ffi);
    assert_field("gcm/iv-data", iv_ptr, iv_len, false, 12);
    assert_field("gcm/aad-data", aad_ptr, aad_len, false, 8);
    assert_eq!(pointee_bytes(iv_ptr as *const u8, iv_len as u64), iv_input);
    assert_eq!(pointee_bytes(aad_ptr as *const u8, aad_len as u64), aad_input);
    assert_ne!(iv_ptr as *const u8, iv_addr, "gcm/iv: owned backing, not the client slice");
    assert_ne!(aad_ptr as *const u8, aad_addr, "gcm/aad: owned backing, not the client slice");

    // Mixed: NULL IV + present AAD (leg independence).
    let ffi = convert(
        gcm(PointerBytes::null_len(12), PointerBytes::present_copy(&aad_input), 0),
        CkMechanismType::AES_GCM,
    );
    let (iv_ptr, iv_len, aad_ptr, aad_len) = gcm_fields(ffi);
    assert_field("gcm/mixed-iv", iv_ptr, iv_len, true, 12);
    assert_field("gcm/mixed-aad", aad_ptr, aad_len, false, 8);
}

#[test]
fn r19_reconstruct_gcm_iv_capacity_zeroed() {
    // Generated-IV capacity: a Present IV shorter than iv_buffer_len →
    // ulIvLen names the input while the retained buffer keeps the full
    // capacity, zero-padded past the input.
    let iv_input = vec![0x33; 4];
    let ffi = convert(
        gcm(PointerBytes::present_copy(&iv_input), PointerBytes::present_copy(&[]), 12),
        CkMechanismType::AES_GCM,
    );
    let (iv_ptr, iv_len, _, _) = gcm_fields(ffi);
    assert_field("gcm-cap/iv", iv_ptr, iv_len, false, 4);
    // The full 12-byte capacity is readable behind the pointer: input
    // bytes followed by zero padding.
    let mut expected = iv_input.clone();
    expected.resize(12, 0);
    assert_eq!(pointee_bytes(iv_ptr as *const u8, 12), expected);
}

#[test]
fn r19_reconstruct_gcm_null_huge_forwards() {
    // D3: a huge NULL declared length forwards as NULL + narrowed length
    // without allocating (an allocation attempt would abort/OOM the test).
    let ffi = convert(
        gcm(PointerBytes::null_len(u64::MAX), PointerBytes::null_len(0), 0),
        CkMechanismType::AES_GCM,
    );
    let (iv_ptr, iv_len, aad_ptr, aad_len) = gcm_fields(ffi);
    assert_field("gcm-huge/null-iv-max", iv_ptr, iv_len, true, u64::MAX);
    assert_field("gcm-huge/null-aad-0", aad_ptr, aad_len, true, 0);
}

// ---------------------------------------------------------------------------
// CCM (S2 §8 "CCM")
// ---------------------------------------------------------------------------

fn ccm(nonce: PointerBytes, aad: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Ccm(CcmParams {
        data_len: 64,
        mac_len: 16,
        nonce_presence: nonce,
        aad_presence: aad,
    })
}

#[test]
fn r19_reconstruct_ccm() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::AES_CCM);
        let p: cryptoki_sys::CK_CCM_PARAMS = param_struct(ffi);
        (p.pNonce, p.ulNonceLen, p.pAAD, p.ulAADLen)
    };
    let (n_ptr, n_len, a_ptr, a_len) =
        probe(ccm(PointerBytes::null_len(7), PointerBytes::null_len(5)));
    assert_field("ccm/null-nonce-7", n_ptr, n_len, true, 7);
    assert_field("ccm/null-aad-5", a_ptr, a_len, true, 5);

    let (n_ptr, n_len, a_ptr, a_len) =
        probe(ccm(PointerBytes::null_len(0), PointerBytes::null_len(0)));
    assert_field("ccm/null-nonce-0", n_ptr, n_len, true, 0);
    assert_field("ccm/null-aad-0", a_ptr, a_len, true, 0);

    let (n_ptr, n_len, a_ptr, a_len) =
        probe(ccm(PointerBytes::present_copy(&[]), PointerBytes::present_copy(&[])));
    assert_field("ccm/empty-nonce", n_ptr, n_len, false, 0);
    assert_field("ccm/empty-aad", a_ptr, a_len, false, 0);

    let nonce_input = vec![0x44; 7];
    let aad_input = vec![0x55; 5];
    let (n_ptr, n_len, a_ptr, a_len) = probe(ccm(
        PointerBytes::present_copy(&nonce_input),
        PointerBytes::present_copy(&aad_input),
    ));
    assert_field("ccm/nonce-data", n_ptr, n_len, false, 7);
    assert_field("ccm/aad-data", a_ptr, a_len, false, 5);
    assert_eq!(pointee_bytes(n_ptr as *const u8, n_len as u64), nonce_input);
    assert_eq!(pointee_bytes(a_ptr as *const u8, a_len as u64), aad_input);

    // Mixed: valid nonce + NULL AAD.
    let (n_ptr, n_len, a_ptr, a_len) =
        probe(ccm(PointerBytes::present_copy(&nonce_input), PointerBytes::null_len(5)));
    assert_field("ccm/mixed-nonce", n_ptr, n_len, false, 7);
    assert_field("ccm/mixed-aad", a_ptr, a_len, true, 5);
}

// ---------------------------------------------------------------------------
// ECDH1 derive (S2 §8 "ECDH1/2")
// ---------------------------------------------------------------------------

fn ecdh1(shared: PointerBytes, public: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Ecdh1Derive(Ecdh1DeriveParams {
        kdf: CkKdf::SHA1_KDF,
        shared_data_presence: shared,
        public_data_presence: public,
    })
}

#[test]
fn r19_reconstruct_ecdh1_derive() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::ECDH1_DERIVE);
        let p: cryptoki_sys::CK_ECDH1_DERIVE_PARAMS = param_struct(ffi);
        (p.pSharedData, p.ulSharedDataLen, p.pPublicData, p.ulPublicDataLen)
    };
    let (s_ptr, s_len, p_ptr, p_len) =
        probe(ecdh1(PointerBytes::null_len(6), PointerBytes::null_len(65)));
    assert_field("ecdh1/null-shared-6", s_ptr, s_len, true, 6);
    assert_field("ecdh1/null-public-65", p_ptr, p_len, true, 65);

    let (s_ptr, s_len, p_ptr, p_len) =
        probe(ecdh1(PointerBytes::present_copy(&[]), PointerBytes::present_copy(&[])));
    assert_field("ecdh1/empty-shared", s_ptr, s_len, false, 0);
    assert_field("ecdh1/empty-public", p_ptr, p_len, false, 0);

    let shared_input = vec![0x66; 6];
    let public_input = vec![0x77; 65];
    let (s_ptr, s_len, p_ptr, p_len) = probe(ecdh1(
        PointerBytes::present_copy(&shared_input),
        PointerBytes::present_copy(&public_input),
    ));
    assert_field("ecdh1/shared-data", s_ptr, s_len, false, 6);
    assert_field("ecdh1/public-data", p_ptr, p_len, false, 65);
    assert_eq!(pointee_bytes(s_ptr as *const u8, s_len as u64), shared_input);
    assert_eq!(pointee_bytes(p_ptr as *const u8, p_len as u64), public_input);

    // Cofactor id rides the same params shape (id-independence: the
    // reconstruction keys off the variant, never the mechanism id).
    let ffi = convert(
        ecdh1(PointerBytes::null_len(6), PointerBytes::null_len(65)),
        CkMechanismType(CKM_TEST_ECDH1_COFACTOR_DERIVE),
    );
    let p: cryptoki_sys::CK_ECDH1_DERIVE_PARAMS = param_struct(ffi);
    assert_field("ecdh1-cofactor/null-shared-6", p.pSharedData, p.ulSharedDataLen, true, 6);
    assert_field("ecdh1-cofactor/null-public-65", p.pPublicData, p.ulPublicDataLen, true, 65);
}

// ---------------------------------------------------------------------------
// ECDH2 derive (S2 §8 "ECDH1/2")
// ---------------------------------------------------------------------------

fn ecdh2(shared: PointerBytes, public: PointerBytes, public2: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Ecdh2Derive(Ecdh2DeriveParams {
        kdf: CkKdf::SHA1_KDF,
        private_data_len: 0,
        private_data_handle: CkObjectHandle(0),
        shared_data_presence: shared,
        public_data_presence: public,
        public_data2_presence: public2,
    })
}

#[test]
fn r19_reconstruct_ecdh2_derive() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_ECDH2_DERIVE));
        let p: cryptoki_sys::CK_ECDH2_DERIVE_PARAMS = param_struct(ffi);
        (
            p.pSharedData,
            p.ulSharedDataLen,
            p.pPublicData,
            p.ulPublicDataLen,
            p.pPublicData2,
            p.ulPublicDataLen2,
        )
    };
    let (s_ptr, s_len, p_ptr, p_len, p2_ptr, p2_len) = probe(ecdh2(
        PointerBytes::null_len(6),
        PointerBytes::null_len(65),
        PointerBytes::null_len(33),
    ));
    assert_field("ecdh2/null-shared-6", s_ptr, s_len, true, 6);
    assert_field("ecdh2/null-public-65", p_ptr, p_len, true, 65);
    assert_field("ecdh2/null-public2-33", p2_ptr, p2_len, true, 33);

    let (s_ptr, s_len, p_ptr, p_len, p2_ptr, p2_len) = probe(ecdh2(
        PointerBytes::present_copy(&[]),
        PointerBytes::present_copy(&[]),
        PointerBytes::present_copy(&[]),
    ));
    assert_field("ecdh2/empty-shared", s_ptr, s_len, false, 0);
    assert_field("ecdh2/empty-public", p_ptr, p_len, false, 0);
    assert_field("ecdh2/empty-public2", p2_ptr, p2_len, false, 0);

    let shared_input = vec![0x68; 6];
    let public_input = vec![0x69; 65];
    let public2_input = vec![0x6A; 33];
    let (s_ptr, s_len, p_ptr, p_len, p2_ptr, p2_len) = probe(ecdh2(
        PointerBytes::present_copy(&shared_input),
        PointerBytes::present_copy(&public_input),
        PointerBytes::present_copy(&public2_input),
    ));
    assert_field("ecdh2/shared-data", s_ptr, s_len, false, 6);
    assert_field("ecdh2/public-data", p_ptr, p_len, false, 65);
    assert_field("ecdh2/public2-data", p2_ptr, p2_len, false, 33);
    assert_eq!(pointee_bytes(s_ptr as *const u8, s_len as u64), shared_input);
    assert_eq!(pointee_bytes(p_ptr as *const u8, p_len as u64), public_input);
    assert_eq!(pointee_bytes(p2_ptr as *const u8, p2_len as u64), public2_input);
}

// ---------------------------------------------------------------------------
// ECMQV derive (S2 §8 "ECMQV")
// ---------------------------------------------------------------------------

fn ecmqv(shared: PointerBytes, public: PointerBytes, public2: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::EcmqvDerive(EcmqvDeriveParams {
        kdf: CkKdf::SHA1_KDF,
        private_data_len: 0,
        private_data_handle: CkObjectHandle(0),
        public_key_handle: CkObjectHandle(0),
        shared_data_presence: shared,
        public_data_presence: public,
        public_data2_presence: public2,
    })
}

#[test]
fn r19_reconstruct_ecmqv_derive() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::ECMQV_DERIVE);
        let p: cryptoki_sys::CK_ECMQV_DERIVE_PARAMS = param_struct(ffi);
        (
            p.pSharedData,
            p.ulSharedDataLen,
            p.pPublicData,
            p.ulPublicDataLen,
            p.pPublicData2,
            p.ulPublicDataLen2,
        )
    };
    let (s_ptr, s_len, p_ptr, p_len, p2_ptr, p2_len) = probe(ecmqv(
        PointerBytes::null_len(6),
        PointerBytes::null_len(65),
        PointerBytes::null_len(33),
    ));
    assert_field("ecmqv/null-shared-6", s_ptr, s_len, true, 6);
    assert_field("ecmqv/null-public-65", p_ptr, p_len, true, 65);
    assert_field("ecmqv/null-public2-33", p2_ptr, p2_len, true, 33);

    let data_input = vec![0x6B; 6];
    let (s_ptr, s_len, p_ptr, p_len, p2_ptr, p2_len) = probe(ecmqv(
        PointerBytes::present_copy(&data_input),
        PointerBytes::present_copy(&[]),
        PointerBytes::null_len(33),
    ));
    assert_field("ecmqv/mixed-shared", s_ptr, s_len, false, 6);
    assert_eq!(pointee_bytes(s_ptr as *const u8, s_len as u64), data_input);
    assert_field("ecmqv/mixed-public-empty", p_ptr, p_len, false, 0);
    assert_field("ecmqv/mixed-public2-null", p2_ptr, p2_len, true, 33);
}

// ---------------------------------------------------------------------------
// X9.42 DH1 derive (S2 §8 "X9.42 DH1/2")
// ---------------------------------------------------------------------------

fn x942_dh1(other: PointerBytes, public: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::X942Dh1Derive(X942Dh1DeriveParams {
        kdf: CkKdf::SHA1_KDF,
        other_info_presence: other,
        public_data_presence: public,
    })
}

#[test]
fn r19_reconstruct_x942_dh1_derive() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::X9_42_DH_DERIVE);
        let p: cryptoki_sys::CK_X9_42_DH1_DERIVE_PARAMS = param_struct(ffi);
        (p.pOtherInfo, p.ulOtherInfoLen, p.pPublicData, p.ulPublicDataLen)
    };
    let (o_ptr, o_len, p_ptr, p_len) =
        probe(x942_dh1(PointerBytes::null_len(9), PointerBytes::null_len(64)));
    assert_field("x942-dh1/null-other-9", o_ptr, o_len, true, 9);
    assert_field("x942-dh1/null-public-64", p_ptr, p_len, true, 64);

    let (o_ptr, o_len, p_ptr, p_len) =
        probe(x942_dh1(PointerBytes::present_copy(&[]), PointerBytes::present_copy(&[])));
    assert_field("x942-dh1/empty-other", o_ptr, o_len, false, 0);
    assert_field("x942-dh1/empty-public", p_ptr, p_len, false, 0);

    let other_input = vec![0x6C; 9];
    let public_input = vec![0x6D; 64];
    let (o_ptr, o_len, p_ptr, p_len) = probe(x942_dh1(
        PointerBytes::present_copy(&other_input),
        PointerBytes::present_copy(&public_input),
    ));
    assert_field("x942-dh1/other-data", o_ptr, o_len, false, 9);
    assert_field("x942-dh1/public-data", p_ptr, p_len, false, 64);
    assert_eq!(pointee_bytes(o_ptr as *const u8, o_len as u64), other_input);
    assert_eq!(pointee_bytes(p_ptr as *const u8, p_len as u64), public_input);
}

// ---------------------------------------------------------------------------
// X9.42 DH2 derive (S2 §8 "X9.42 DH1/2")
// ---------------------------------------------------------------------------

fn x942_dh2(other: PointerBytes, public: PointerBytes, public2: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::X942Dh2Derive(X942Dh2DeriveParams {
        kdf: CkKdf::SHA1_KDF,
        private_data_len: 0,
        private_data_handle: CkObjectHandle(0),
        other_info_presence: other,
        public_data_presence: public,
        public_data2_presence: public2,
    })
}

#[test]
fn r19_reconstruct_x942_dh2_derive() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::X9_42_DH_HYBRID_DERIVE);
        let p: cryptoki_sys::CK_X9_42_DH2_DERIVE_PARAMS = param_struct(ffi);
        (
            p.pOtherInfo,
            p.ulOtherInfoLen,
            p.pPublicData,
            p.ulPublicDataLen,
            p.pPublicData2,
            p.ulPublicDataLen2,
        )
    };
    let (o_ptr, o_len, p_ptr, p_len, p2_ptr, p2_len) = probe(x942_dh2(
        PointerBytes::null_len(9),
        PointerBytes::null_len(64),
        PointerBytes::null_len(32),
    ));
    assert_field("x942-dh2/null-other-9", o_ptr, o_len, true, 9);
    assert_field("x942-dh2/null-public-64", p_ptr, p_len, true, 64);
    assert_field("x942-dh2/null-public2-32", p2_ptr, p2_len, true, 32);

    let other_input = vec![0x6E; 9];
    let (o_ptr, o_len, p_ptr, p_len, p2_ptr, p2_len) = probe(x942_dh2(
        PointerBytes::present_copy(&other_input),
        PointerBytes::present_copy(&[]),
        PointerBytes::null_len(32),
    ));
    assert_field("x942-dh2/mixed-other", o_ptr, o_len, false, 9);
    assert_eq!(pointee_bytes(o_ptr as *const u8, o_len as u64), other_input);
    assert_field("x942-dh2/mixed-public-empty", p_ptr, p_len, false, 0);
    assert_field("x942-dh2/mixed-public2-null", p2_ptr, p2_len, true, 32);
}

// ---------------------------------------------------------------------------
// X9.42 MQV derive (S2 §8 "X9.42 MQV")
// ---------------------------------------------------------------------------

fn x942_mqv(other: PointerBytes, public: PointerBytes, public2: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::X942MqvDerive(X942MqvDeriveParams {
        kdf: CkKdf::SHA1_KDF,
        private_data_len: 0,
        private_data_handle: CkObjectHandle(0),
        public_key_handle: CkObjectHandle(0),
        other_info_presence: other,
        public_data_presence: public,
        public_data2_presence: public2,
    })
}

#[test]
fn r19_reconstruct_x942_mqv_derive() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::X9_42_DH_HYBRID_DERIVE);
        let p: cryptoki_sys::CK_X9_42_MQV_DERIVE_PARAMS = param_struct(ffi);
        // NOTE: bindgen preserves the spec's odd member names here
        // (`OtherInfo`, not `pOtherInfo`).
        (
            p.OtherInfo,
            p.ulOtherInfoLen,
            p.PublicData,
            p.ulPublicDataLen,
            p.PublicData2,
            p.ulPublicDataLen2,
        )
    };
    let (o_ptr, o_len, p_ptr, p_len, p2_ptr, p2_len) = probe(x942_mqv(
        PointerBytes::null_len(9),
        PointerBytes::null_len(64),
        PointerBytes::null_len(32),
    ));
    assert_field("x942-mqv/null-other-9", o_ptr, o_len, true, 9);
    assert_field("x942-mqv/null-public-64", p_ptr, p_len, true, 64);
    assert_field("x942-mqv/null-public2-32", p2_ptr, p2_len, true, 32);

    let public_input = vec![0x6F; 64];
    let (o_ptr, o_len, p_ptr, p_len, p2_ptr, p2_len) = probe(x942_mqv(
        PointerBytes::null_len(9),
        PointerBytes::present_copy(&public_input),
        PointerBytes::present_copy(&[]),
    ));
    assert_field("x942-mqv/mixed-other-null", o_ptr, o_len, true, 9);
    assert_field("x942-mqv/mixed-public", p_ptr, p_len, false, 64);
    assert_eq!(pointee_bytes(p_ptr as *const u8, p_len as u64), public_input);
    assert_field("x942-mqv/mixed-public2-empty", p2_ptr, p2_len, false, 0);
}

// ---------------------------------------------------------------------------
// HKDF (S2 §8 "HKDF")
// ---------------------------------------------------------------------------

fn hkdf(salt: PointerBytes, info: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Hkdf(HkdfParams {
        extract: true,
        expand: true,
        prf_hash_mechanism: CkMechanismType::SHA256,
        salt_type: 0,
        salt_key_handle: CkObjectHandle(0),
        salt_presence: salt,
        info_presence: info,
    })
}

#[test]
fn r19_reconstruct_hkdf() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::HKDF_DERIVE);
        let p: cryptoki_sys::CK_HKDF_PARAMS = param_struct(ffi);
        (p.pSalt, p.ulSaltLen, p.pInfo, p.ulInfoLen)
    };
    let (s_ptr, s_len, i_ptr, i_len) =
        probe(hkdf(PointerBytes::null_len(16), PointerBytes::null_len(11)));
    assert_field("hkdf/null-salt-16", s_ptr, s_len, true, 16);
    assert_field("hkdf/null-info-11", i_ptr, i_len, true, 11);

    let (s_ptr, s_len, i_ptr, i_len) =
        probe(hkdf(PointerBytes::present_copy(&[]), PointerBytes::present_copy(&[])));
    assert_field("hkdf/empty-salt", s_ptr, s_len, false, 0);
    assert_field("hkdf/empty-info", i_ptr, i_len, false, 0);

    let salt_input = vec![0x70; 16];
    let info_input = vec![0x71; 11];
    let (s_ptr, s_len, i_ptr, i_len) = probe(hkdf(
        PointerBytes::present_copy(&salt_input),
        PointerBytes::present_copy(&info_input),
    ));
    assert_field("hkdf/salt-data", s_ptr, s_len, false, 16);
    assert_field("hkdf/info-data", i_ptr, i_len, false, 11);
    assert_eq!(pointee_bytes(s_ptr as *const u8, s_len as u64), salt_input);
    assert_eq!(pointee_bytes(i_ptr as *const u8, i_len as u64), info_input);
}

// ---------------------------------------------------------------------------
// EdDSA (S2 §8 "EdDSA")
// ---------------------------------------------------------------------------

fn eddsa(context: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Eddsa(EddsaParams { ph_flag: false, context_data_presence: context })
}

#[test]
fn r19_reconstruct_eddsa() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::EDDSA);
        let p: cryptoki_sys::CK_EDDSA_PARAMS = param_struct(ffi);
        (p.pContextData, p.ulContextDataLen)
    };
    let (c_ptr, c_len) = probe(eddsa(PointerBytes::null_len(13)));
    assert_field("eddsa/null-context-13", c_ptr, c_len, true, 13);

    let (c_ptr, c_len) = probe(eddsa(PointerBytes::present_copy(&[])));
    assert_field("eddsa/empty-context", c_ptr, c_len, false, 0);

    let context_input = vec![0x72; 13];
    let (c_ptr, c_len) = probe(eddsa(PointerBytes::present_copy(&context_input)));
    assert_field("eddsa/context-data", c_ptr, c_len, false, 13);
    assert_eq!(pointee_bytes(c_ptr as *const u8, c_len as u64), context_input);
}

// ---------------------------------------------------------------------------
// GOST R 34.10 derive (S2 §8 "GOST")
// ---------------------------------------------------------------------------

fn gost_derive(public: PointerBytes, ukm: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Gostr3410Derive(Gostr3410DeriveParams {
        kdf: CkKdf::SHA1_KDF,
        public_data_presence: public,
        ukm_presence: ukm,
    })
}

#[test]
fn r19_reconstruct_gostr3410_derive() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::GOSTR3410_DERIVE);
        let p: cryptoki_sys::CK_GOSTR3410_DERIVE_PARAMS = param_struct(ffi);
        (p.pPublicData, p.ulPublicDataLen, p.pUKM, p.ulUKMLen)
    };
    let (p_ptr, p_len, u_ptr, u_len) =
        probe(gost_derive(PointerBytes::null_len(64), PointerBytes::null_len(8)));
    assert_field("gost-derive/null-public-64", p_ptr, p_len, true, 64);
    assert_field("gost-derive/null-ukm-8", u_ptr, u_len, true, 8);

    let public_input = vec![0x73; 64];
    let ukm_input = vec![0x74; 8];
    let (p_ptr, p_len, u_ptr, u_len) = probe(gost_derive(
        PointerBytes::present_copy(&public_input),
        PointerBytes::present_copy(&ukm_input),
    ));
    assert_field("gost-derive/public-data", p_ptr, p_len, false, 64);
    assert_field("gost-derive/ukm-data", u_ptr, u_len, false, 8);
    assert_eq!(pointee_bytes(p_ptr as *const u8, p_len as u64), public_input);
    assert_eq!(pointee_bytes(u_ptr as *const u8, u_len as u64), ukm_input);
}

// ---------------------------------------------------------------------------
// GOST R 34.10 key wrap (S2 §8 "GOST")
// ---------------------------------------------------------------------------

fn gost_wrap(oid: PointerBytes, ukm: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
        key_handle: CkObjectHandle(0),
        wrap_oid_presence: oid,
        ukm_presence: ukm,
    })
}

#[test]
fn r19_reconstruct_gostr3410_key_wrap() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::GOSTR3410_KEY_WRAP);
        let p: cryptoki_sys::CK_GOSTR3410_KEY_WRAP_PARAMS = param_struct(ffi);
        (p.pWrapOID, p.ulWrapOIDLen, p.pUKM, p.ulUKMLen)
    };
    let (o_ptr, o_len, u_ptr, u_len) =
        probe(gost_wrap(PointerBytes::null_len(7), PointerBytes::null_len(8)));
    assert_field("gost-wrap/null-oid-7", o_ptr, o_len, true, 7);
    assert_field("gost-wrap/null-ukm-8", u_ptr, u_len, true, 8);

    let (o_ptr, o_len, u_ptr, u_len) =
        probe(gost_wrap(PointerBytes::present_copy(&[]), PointerBytes::present_copy(&[])));
    assert_field("gost-wrap/empty-oid", o_ptr, o_len, false, 0);
    assert_field("gost-wrap/empty-ukm", u_ptr, u_len, false, 0);

    let oid_input = vec![0x75; 7];
    let ukm_input = vec![0x76; 8];
    let (o_ptr, o_len, u_ptr, u_len) = probe(gost_wrap(
        PointerBytes::present_copy(&oid_input),
        PointerBytes::present_copy(&ukm_input),
    ));
    assert_field("gost-wrap/oid-data", o_ptr, o_len, false, 7);
    assert_field("gost-wrap/ukm-data", u_ptr, u_len, false, 8);
    assert_eq!(pointee_bytes(o_ptr as *const u8, o_len as u64), oid_input);
    assert_eq!(pointee_bytes(u_ptr as *const u8, u_len as u64), ukm_input);
}

// ---------------------------------------------------------------------------
// RC5-CBC (S2 §8 "RC5-CBC")
// ---------------------------------------------------------------------------

fn rc5_cbc(iv: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Rc5Cbc(Rc5CbcParams { word_size: 4, rounds: 12, iv_presence: iv })
}

#[test]
fn r19_reconstruct_rc5_cbc() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_RC5_CBC));
        let p: cryptoki_sys::CK_RC5_CBC_PARAMS = param_struct(ffi);
        (p.pIv, p.ulIvLen)
    };
    let (iv_ptr, iv_len) = probe(rc5_cbc(PointerBytes::null_len(8)));
    assert_field("rc5-cbc/null-iv-8", iv_ptr, iv_len, true, 8);

    let (iv_ptr, iv_len) = probe(rc5_cbc(PointerBytes::present_copy(&[])));
    assert_field("rc5-cbc/empty-iv", iv_ptr, iv_len, false, 0);

    let iv_input = vec![0x77; 8];
    let (iv_ptr, iv_len) = probe(rc5_cbc(PointerBytes::present_copy(&iv_input)));
    assert_field("rc5-cbc/iv-data", iv_ptr, iv_len, false, 8);
    assert_eq!(pointee_bytes(iv_ptr as *const u8, iv_len as u64), iv_input);
}

// ---------------------------------------------------------------------------
// ChaCha20 (S2 §8 "ChaCha20/Salsa20")
// ---------------------------------------------------------------------------

fn chacha20(counter: PointerBytes, nonce: PointerBytes) -> CkMechanismParams {
    let counter_bits = counter.declared_len() * 8;
    let nonce_bits = nonce.declared_len() * 8;
    CkMechanismParams::ChaCha20(ChaCha20Params {
        block_counter_bits: counter_bits,
        nonce_bits,
        block_counter_presence: counter,
        nonce_presence: nonce,
    })
}

#[test]
fn r19_reconstruct_chacha20() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::CHACHA20);
        let p: cryptoki_sys::CK_CHACHA20_PARAMS = param_struct(ffi);
        (p.pBlockCounter, p.blockCounterBits, p.pNonce, p.ulNonceBits)
    };
    // The C struct has no byte-length fields for these legs — only
    // NULL-ness crosses; the bits scalars ride independently.
    let (bc_ptr, bc_bits, n_ptr, n_bits) =
        probe(chacha20(PointerBytes::null_len(4), PointerBytes::null_len(12)));
    assert!(bc_ptr.is_null(), "chacha20/null-counter: must be NULL");
    assert_eq!(bc_bits as u64, 32, "chacha20/null-counter: bits scalar rides");
    assert!(n_ptr.is_null(), "chacha20/null-nonce: must be NULL");
    assert_eq!(n_bits as u64, 96, "chacha20/null-nonce: bits scalar rides");

    let (bc_ptr, bc_bits, n_ptr, n_bits) =
        probe(chacha20(PointerBytes::present_copy(&[]), PointerBytes::present_copy(&[])));
    assert!(!bc_ptr.is_null(), "chacha20/empty-counter: must be non-NULL");
    assert_eq!(bc_bits as u64, 0);
    assert!(!n_ptr.is_null(), "chacha20/empty-nonce: must be non-NULL");
    assert_eq!(n_bits as u64, 0);

    let counter_input = vec![0x78; 4];
    let nonce_input = vec![0x79; 12];
    let (bc_ptr, bc_bits, n_ptr, n_bits) = probe(chacha20(
        PointerBytes::present_copy(&counter_input),
        PointerBytes::present_copy(&nonce_input),
    ));
    assert!(!bc_ptr.is_null(), "chacha20/counter: must be non-NULL");
    assert_eq!(bc_bits as u64, 32);
    assert_eq!(pointee_bytes(bc_ptr as *const u8, 4), counter_input);
    assert!(!n_ptr.is_null(), "chacha20/nonce: must be non-NULL");
    assert_eq!(n_bits as u64, 96);
    assert_eq!(pointee_bytes(n_ptr as *const u8, 12), nonce_input);

    // Bits-governed fixed reads normalize to the governed size: a
    // short counter pads with zeros (no provider over-read), a long
    // nonce truncates (the provider reads 12 either way).
    let short = PointerBytes::present_copy(&[0x7C; 2]);
    let long = PointerBytes::present_copy(&[0x7D; 16]);
    let (bc_ptr, _, n_ptr, _) = probe(CkMechanismParams::ChaCha20(ChaCha20Params {
        block_counter_bits: 32,
        nonce_bits: 96,
        block_counter_presence: short,
        nonce_presence: long,
    }));
    assert!(!bc_ptr.is_null(), "chacha20/short-counter: must be non-NULL");
    assert_eq!(
        pointee_bytes(bc_ptr as *const u8, 4),
        vec![0x7C, 0x7C, 0, 0],
        "chacha20/short-counter: zero-padded to the governed size"
    );
    assert!(!n_ptr.is_null(), "chacha20/long-nonce: must be non-NULL");
    assert_eq!(
        pointee_bytes(n_ptr as *const u8, 12),
        vec![0x7D; 12],
        "chacha20/long-nonce: truncated to the governed size"
    );
}

// ---------------------------------------------------------------------------
// Salsa20 (S2 §8 "ChaCha20/Salsa20")
// ---------------------------------------------------------------------------

fn salsa20(counter: PointerBytes, nonce: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Salsa20(Salsa20Params {
        nonce_bits: nonce.declared_len() * 8,
        block_counter_presence: counter,
        nonce_presence: nonce,
    })
}

#[test]
fn r19_reconstruct_salsa20() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::SALSA20);
        let p: cryptoki_sys::CK_SALSA20_PARAMS = param_struct(ffi);
        (p.pBlockCounter, p.pNonce, p.ulNonceBits)
    };
    // As with ChaCha20: no byte-length fields — only NULL-ness crosses.
    // (The counter leg has no bits scalar either; the provider reads a
    // fixed 8-byte counter.)
    let (bc_ptr, n_ptr, n_bits) =
        probe(salsa20(PointerBytes::null_len(8), PointerBytes::null_len(8)));
    assert!(bc_ptr.is_null(), "salsa20/null-counter: must be NULL");
    assert!(n_ptr.is_null(), "salsa20/null-nonce: must be NULL");
    assert_eq!(n_bits as u64, 64, "salsa20/null-nonce: bits scalar rides");

    let (bc_ptr, n_ptr, n_bits) =
        probe(salsa20(PointerBytes::present_copy(&[]), PointerBytes::present_copy(&[])));
    assert!(!bc_ptr.is_null(), "salsa20/empty-counter: must be non-NULL");
    assert!(!n_ptr.is_null(), "salsa20/empty-nonce: must be non-NULL");
    assert_eq!(n_bits as u64, 0);

    let counter_input = vec![0x7A; 8];
    let nonce_input = vec![0x7B; 8];
    let (bc_ptr, n_ptr, n_bits) = probe(salsa20(
        PointerBytes::present_copy(&counter_input),
        PointerBytes::present_copy(&nonce_input),
    ));
    assert!(!bc_ptr.is_null(), "salsa20/counter: must be non-NULL");
    assert_eq!(pointee_bytes(bc_ptr as *const u8, 8), counter_input);
    assert!(!n_ptr.is_null(), "salsa20/nonce: must be non-NULL");
    assert_eq!(n_bits as u64, 64);
    assert_eq!(pointee_bytes(n_ptr as *const u8, 8), nonce_input);

    // Fixed/governed reads normalize: a short counter pads to the
    // fixed 8 (no provider over-read), a long nonce truncates to the
    // governed 8.
    let short = PointerBytes::present_copy(&[0x7E; 2]);
    let long = PointerBytes::present_copy(&[0x7F; 12]);
    let (bc_ptr, n_ptr, _) = probe(CkMechanismParams::Salsa20(Salsa20Params {
        nonce_bits: 64,
        block_counter_presence: short,
        nonce_presence: long,
    }));
    assert!(!bc_ptr.is_null(), "salsa20/short-counter: must be non-NULL");
    assert_eq!(
        pointee_bytes(bc_ptr as *const u8, 8),
        vec![0x7E, 0x7E, 0, 0, 0, 0, 0, 0],
        "salsa20/short-counter: zero-padded to the fixed 8"
    );
    assert!(!n_ptr.is_null(), "salsa20/long-nonce: must be non-NULL");
    assert_eq!(
        pointee_bytes(n_ptr as *const u8, 8),
        vec![0x7F; 8],
        "salsa20/long-nonce: truncated to the governed size"
    );
}

// ---------------------------------------------------------------------------
// Salsa20/ChaCha20-Poly1305 AEAD (S2 §8 "AEAD")
// ---------------------------------------------------------------------------

fn aead_poly1305(nonce: PointerBytes, aad: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Salsa20ChaCha20Poly1305(Salsa20ChaCha20Poly1305Params {
        nonce_presence: nonce,
        aad_presence: aad,
    })
}

#[test]
fn r19_reconstruct_salsa20_chacha20_poly1305() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_SALSA20_CHACHA20_POLY1305));
        let p: cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_PARAMS = param_struct(ffi);
        (p.pNonce, p.ulNonceLen, p.pAAD, p.ulAADLen)
    };
    let (n_ptr, n_len, a_ptr, a_len) =
        probe(aead_poly1305(PointerBytes::null_len(8), PointerBytes::null_len(16)));
    assert_field("aead/null-nonce-8", n_ptr, n_len, true, 8);
    assert_field("aead/null-aad-16", a_ptr, a_len, true, 16);

    let (n_ptr, n_len, a_ptr, a_len) =
        probe(aead_poly1305(PointerBytes::present_copy(&[]), PointerBytes::present_copy(&[])));
    assert_field("aead/empty-nonce", n_ptr, n_len, false, 0);
    assert_field("aead/empty-aad", a_ptr, a_len, false, 0);

    let nonce_input = vec![0x7C; 8];
    let aad_input = vec![0x7D; 16];
    let (n_ptr, n_len, a_ptr, a_len) = probe(aead_poly1305(
        PointerBytes::present_copy(&nonce_input),
        PointerBytes::present_copy(&aad_input),
    ));
    assert_field("aead/nonce-data", n_ptr, n_len, false, 8);
    assert_field("aead/aad-data", a_ptr, a_len, false, 16);
    assert_eq!(pointee_bytes(n_ptr as *const u8, n_len as u64), nonce_input);
    assert_eq!(pointee_bytes(a_ptr as *const u8, a_len as u64), aad_input);
}

// ---------------------------------------------------------------------------
// AES-CBC-encrypt-data (S2 §8 "CBC-encrypt-data")
// ---------------------------------------------------------------------------

fn aes_cbc_encrypt_data(iv: &[u8], data: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::AesCbcEncryptData(AesCbcEncryptDataParams {
        iv: iv.to_vec(),
        data_presence: data,
    })
}

#[test]
fn r19_reconstruct_aes_cbc_encrypt_data() {
    let iv = vec![0x7E; 16];
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::AES_CBC_ENCRYPT_DATA);
        let p: cryptoki_sys::CK_AES_CBC_ENCRYPT_DATA_PARAMS = param_struct(ffi);
        (p.iv, p.pData, p.length)
    };
    let (got_iv, d_ptr, d_len) = probe(aes_cbc_encrypt_data(&iv, PointerBytes::null_len(24)));
    assert_field("aes-cbc-data/null-data-24", d_ptr, d_len, true, 24);
    assert_eq!(&got_iv[..], iv.as_slice(), "aes-cbc-data/iv: inline array echoes");

    let (_, d_ptr, d_len) = probe(aes_cbc_encrypt_data(&iv, PointerBytes::present_copy(&[])));
    assert_field("aes-cbc-data/empty-data", d_ptr, d_len, false, 0);

    let data_input = vec![0x7F; 24];
    let (_, d_ptr, d_len) =
        probe(aes_cbc_encrypt_data(&iv, PointerBytes::present_copy(&data_input)));
    assert_field("aes-cbc-data/data", d_ptr, d_len, false, 24);
    assert_eq!(pointee_bytes(d_ptr as *const u8, d_len as u64), data_input);
}

// ---------------------------------------------------------------------------
// DES-CBC-encrypt-data (S2 §8 "CBC-encrypt-data")
// ---------------------------------------------------------------------------

fn des_cbc_encrypt_data(iv: &[u8], data: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::DesCbcEncryptData(DesCbcEncryptDataParams {
        iv: iv.to_vec(),
        data_presence: data,
    })
}

#[test]
fn r19_reconstruct_des_cbc_encrypt_data() {
    let iv = vec![0x80; 8];
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::DES_CBC_ENCRYPT_DATA);
        let p: cryptoki_sys::CK_DES_CBC_ENCRYPT_DATA_PARAMS = param_struct(ffi);
        (p.pData, p.length)
    };
    let (d_ptr, d_len) = probe(des_cbc_encrypt_data(&iv, PointerBytes::null_len(16)));
    assert_field("des-cbc-data/null-data-16", d_ptr, d_len, true, 16);

    let data_input = vec![0x81; 16];
    let (d_ptr, d_len) = probe(des_cbc_encrypt_data(&iv, PointerBytes::present_copy(&data_input)));
    assert_field("des-cbc-data/data", d_ptr, d_len, false, 16);
    assert_eq!(pointee_bytes(d_ptr as *const u8, d_len as u64), data_input);
}

// ---------------------------------------------------------------------------
// ARIA-CBC-encrypt-data (S2 §8 "CBC-encrypt-data")
// ---------------------------------------------------------------------------

fn aria_cbc_encrypt_data(iv: &[u8], data: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::AriaCbcEncryptData(AriaCbcEncryptDataParams {
        iv: iv.to_vec(),
        data_presence: data,
    })
}

#[test]
fn r19_reconstruct_aria_cbc_encrypt_data() {
    let iv = vec![0x82; 16];
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_ARIA_CBC_ENCRYPT_DATA));
        let p: cryptoki_sys::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS = param_struct(ffi);
        (p.pData, p.length)
    };
    let (d_ptr, d_len) = probe(aria_cbc_encrypt_data(&iv, PointerBytes::null_len(24)));
    assert_field("aria-cbc-data/null-data-24", d_ptr, d_len, true, 24);

    let (d_ptr, d_len) = probe(aria_cbc_encrypt_data(&iv, PointerBytes::present_copy(&[])));
    assert_field("aria-cbc-data/empty-data", d_ptr, d_len, false, 0);

    let data_input = vec![0x83; 24];
    let (d_ptr, d_len) = probe(aria_cbc_encrypt_data(&iv, PointerBytes::present_copy(&data_input)));
    assert_field("aria-cbc-data/data", d_ptr, d_len, false, 24);
    assert_eq!(pointee_bytes(d_ptr as *const u8, d_len as u64), data_input);
}

// ---------------------------------------------------------------------------
// Camellia-CBC-encrypt-data (S2 §8 "CBC-encrypt-data")
// ---------------------------------------------------------------------------

fn camellia_cbc_encrypt_data(iv: &[u8], data: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::CamelliaCbcEncryptData(CamelliaCbcEncryptDataParams {
        iv: iv.to_vec(),
        data_presence: data,
    })
}

#[test]
fn r19_reconstruct_camellia_cbc_encrypt_data() {
    let iv = vec![0x84; 16];
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_CAMELLIA_CBC_ENCRYPT_DATA));
        let p: cryptoki_sys::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS = param_struct(ffi);
        (p.pData, p.length)
    };
    let (d_ptr, d_len) = probe(camellia_cbc_encrypt_data(&iv, PointerBytes::null_len(24)));
    assert_field("camellia-cbc-data/null-data-24", d_ptr, d_len, true, 24);

    let data_input = vec![0x85; 24];
    let (d_ptr, d_len) =
        probe(camellia_cbc_encrypt_data(&iv, PointerBytes::present_copy(&data_input)));
    assert_field("camellia-cbc-data/data", d_ptr, d_len, false, 24);
    assert_eq!(pointee_bytes(d_ptr as *const u8, d_len as u64), data_input);
}

// ---------------------------------------------------------------------------
// SEED-CBC-encrypt-data (S2 §8 "CBC-encrypt-data")
// ---------------------------------------------------------------------------

fn seed_cbc_encrypt_data(iv: &[u8], data: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::SeedCbcEncryptData(SeedCbcEncryptDataParams {
        iv: iv.to_vec(),
        data_presence: data,
    })
}

#[test]
fn r19_reconstruct_seed_cbc_encrypt_data() {
    let iv = vec![0x86; 16];
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_SEED_CBC_ENCRYPT_DATA));
        let p: cryptoki_sys::CK_SEED_CBC_ENCRYPT_DATA_PARAMS = param_struct(ffi);
        (p.pData, p.length)
    };
    let (d_ptr, d_len) = probe(seed_cbc_encrypt_data(&iv, PointerBytes::null_len(24)));
    assert_field("seed-cbc-data/null-data-24", d_ptr, d_len, true, 24);

    let data_input = vec![0x87; 24];
    let (d_ptr, d_len) = probe(seed_cbc_encrypt_data(&iv, PointerBytes::present_copy(&data_input)));
    assert_field("seed-cbc-data/data", d_ptr, d_len, false, 24);
    assert_eq!(pointee_bytes(d_ptr as *const u8, d_len as u64), data_input);
}

// ---------------------------------------------------------------------------
// GCM key wrap (S2 §8 "GCM-wrap")
// ---------------------------------------------------------------------------

fn gcm_wrap(iv: PointerBytes, aad: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::GcmWrap(GcmWrapParams {
        iv_fixed_bits: 0,
        iv_generator: CkGeneratorFunction::NO_GENERATE,
        tag_bits: 128,
        iv_presence: iv,
        aad_presence: aad,
    })
}

#[test]
fn r19_reconstruct_gcm_wrap() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_GCM_WRAP));
        let p: cryptoki_sys::CK_GCM_WRAP_PARAMS = param_struct(ffi);
        (p.pIv, p.ulIvLen, p.pAAD, p.ulAADLen)
    };
    let (iv_ptr, iv_len, a_ptr, a_len) =
        probe(gcm_wrap(PointerBytes::null_len(12), PointerBytes::null_len(8)));
    assert_field("gcm-wrap/null-iv-12", iv_ptr, iv_len, true, 12);
    assert_field("gcm-wrap/null-aad-8", a_ptr, a_len, true, 8);

    let (iv_ptr, iv_len, a_ptr, a_len) =
        probe(gcm_wrap(PointerBytes::present_copy(&[]), PointerBytes::present_copy(&[])));
    assert_field("gcm-wrap/empty-iv", iv_ptr, iv_len, false, 0);
    assert_field("gcm-wrap/empty-aad", a_ptr, a_len, false, 0);

    let iv_input = vec![0x88; 12];
    let aad_input = vec![0x89; 8];
    let (iv_ptr, iv_len, a_ptr, a_len) = probe(gcm_wrap(
        PointerBytes::present_copy(&iv_input),
        PointerBytes::present_copy(&aad_input),
    ));
    assert_field("gcm-wrap/iv-data", iv_ptr, iv_len, false, 12);
    assert_field("gcm-wrap/aad-data", a_ptr, a_len, false, 8);
    assert_eq!(pointee_bytes(iv_ptr as *const u8, iv_len as u64), iv_input);
    assert_eq!(pointee_bytes(a_ptr as *const u8, a_len as u64), aad_input);
}

// ---------------------------------------------------------------------------
// CCM key wrap (S2 §8 "CCM-wrap")
// ---------------------------------------------------------------------------

fn ccm_wrap(nonce: PointerBytes, aad: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::CcmWrap(CcmWrapParams {
        data_len: 64,
        nonce_fixed_bits: 0,
        nonce_generator: CkGeneratorFunction::NO_GENERATE,
        mac_len: 16,
        nonce_presence: nonce,
        aad_presence: aad,
    })
}

#[test]
fn r19_reconstruct_ccm_wrap() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_CCM_WRAP));
        let p: cryptoki_sys::CK_CCM_WRAP_PARAMS = param_struct(ffi);
        (p.pNonce, p.ulNonceLen, p.pAAD, p.ulAADLen)
    };
    let (n_ptr, n_len, a_ptr, a_len) =
        probe(ccm_wrap(PointerBytes::null_len(7), PointerBytes::null_len(5)));
    assert_field("ccm-wrap/null-nonce-7", n_ptr, n_len, true, 7);
    assert_field("ccm-wrap/null-aad-5", a_ptr, a_len, true, 5);

    let nonce_input = vec![0x8A; 7];
    let aad_input = vec![0x8B; 5];
    let (n_ptr, n_len, a_ptr, a_len) = probe(ccm_wrap(
        PointerBytes::present_copy(&nonce_input),
        PointerBytes::present_copy(&aad_input),
    ));
    assert_field("ccm-wrap/nonce-data", n_ptr, n_len, false, 7);
    assert_field("ccm-wrap/aad-data", a_ptr, a_len, false, 5);
    assert_eq!(pointee_bytes(n_ptr as *const u8, n_len as u64), nonce_input);
    assert_eq!(pointee_bytes(a_ptr as *const u8, a_len as u64), aad_input);
}

// ---------------------------------------------------------------------------
// RSA-AES key wrap (S2 §8 "RSA-AES-wrap") — nested OAEP reconstruction
// ---------------------------------------------------------------------------

fn rsa_aes_wrap(source: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams {
        aes_key_bits: 256,
        oaep_params: RsaPkcsOaepParams {
            hash_alg: CkMechanismType::SHA256,
            mgf: CkMgf(1),
            source: CkOaepSource(1),
            source_data_presence: source,
        },
    })
}

#[test]
fn r19_reconstruct_rsa_aes_key_wrap() {
    // The nesting pointer is always live; the nested OAEP source leg
    // reconstructs per §6 exactly like the top level (byte-identity with
    // the top-level OAEP conversion is pinned by
    // `nested_oaep_empty_key_honors_source_null_like_top_level`).
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_RSA_AES_KEY_WRAP));
        let p: super::FfiRsaAesKeyWrapParams = param_struct(ffi);
        assert!(!p.p_oaep_params.is_null(), "rsa-aes-wrap/nested: must be non-NULL");
        // SAFETY: `p_oaep_params` designates the live nested OAEP struct;
        // the copy carries no provenance.
        let nested = unsafe { p.p_oaep_params.read_unaligned() };
        (nested.pSourceData, nested.ulSourceDataLen)
    };
    let (s_ptr, s_len) = probe(rsa_aes_wrap(PointerBytes::null_len(9)));
    assert_field("rsa-aes-wrap/null-source-9", s_ptr, s_len, true, 9);

    let (s_ptr, s_len) = probe(rsa_aes_wrap(PointerBytes::present_copy(&[])));
    assert_field("rsa-aes-wrap/empty-source", s_ptr, s_len, false, 0);

    let source_input = vec![0x8C; 9];
    let (s_ptr, s_len) = probe(rsa_aes_wrap(PointerBytes::present_copy(&source_input)));
    assert_field("rsa-aes-wrap/source-data", s_ptr, s_len, false, 9);
    assert_eq!(pointee_bytes(s_ptr as *const u8, s_len as u64), source_input);
}

// ---------------------------------------------------------------------------
// PKCS#5 PBKDF2 (S2 §8 "PBKDF2")
// ---------------------------------------------------------------------------

fn pbkdf2(salt: PointerBytes, prf_data: PointerBytes, password: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Pkcs5Pbkd2(Pkcs5Pbkd2Params {
        salt_source: CkPbkdf2SaltSource::SALT_SPECIFIED,
        iterations: 1000,
        prf: CkPbkdf2Prf::HMAC_SHA256,
        salt_source_data_presence: salt,
        prf_data_presence: prf_data,
        password_presence: password,
    })
}

#[test]
fn r19_reconstruct_pkcs5_pbkd2() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::PKCS5_PBKD2);
        let p: cryptoki_sys::CK_PKCS5_PBKD2_PARAMS2 = param_struct(ffi);
        (
            p.pSaltSourceData,
            p.ulSaltSourceDataLen,
            p.pPrfData,
            p.ulPrfDataLen,
            p.pPassword,
            p.ulPasswordLen,
        )
    };
    let (s_ptr, s_len, r_ptr, r_len, w_ptr, w_len) = probe(pbkdf2(
        PointerBytes::null_len(8),
        PointerBytes::null_len(0),
        PointerBytes::null_len(10),
    ));
    assert_field("pbkdf2/null-salt-8", s_ptr, s_len, true, 8);
    assert_field("pbkdf2/null-prf-0", r_ptr, r_len, true, 0);
    assert_field("pbkdf2/null-password-10", w_ptr, w_len, true, 10);

    let salt_input = vec![0x8D; 8];
    let password_input = vec![0x8E; 10];
    let (s_ptr, s_len, r_ptr, r_len, w_ptr, w_len) = probe(pbkdf2(
        PointerBytes::present_copy(&salt_input),
        PointerBytes::present_copy(&[]),
        PointerBytes::present_copy(&password_input),
    ));
    assert_field("pbkdf2/salt-data", s_ptr, s_len, false, 8);
    assert_eq!(pointee_bytes(s_ptr as *const u8, s_len as u64), salt_input);
    assert_field("pbkdf2/empty-prf", r_ptr, r_len, false, 0);
    assert_field("pbkdf2/password-data", w_ptr, w_len, false, 10);
    assert_eq!(pointee_bytes(w_ptr as *const u8, w_len as u64), password_input);
}

// ---------------------------------------------------------------------------
// PBE (S2 §8 "PBE")
// ---------------------------------------------------------------------------

fn pbe(iv: PointerBytes, password: PointerBytes, salt: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Pbe(PbeParams {
        iteration: 1000,
        init_vector_presence: iv,
        password_presence: password,
        salt_presence: salt,
    })
}

#[test]
fn r19_reconstruct_pbe() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::PBA_SHA1_WITH_SHA1_HMAC);
        let p: cryptoki_sys::CK_PBE_PARAMS = param_struct(ffi);
        (p.pInitVector, p.pPassword, p.ulPasswordLen, p.pSalt, p.ulSaltLen)
    };
    // The C struct has no IV length field — only NULL-ness crosses for
    // the IV leg (the provider reads a fixed 8-byte IV).
    let (iv_ptr, w_ptr, w_len, s_ptr, s_len) = probe(pbe(
        PointerBytes::null_len(8),
        PointerBytes::null_len(10),
        PointerBytes::null_len(8),
    ));
    assert!(iv_ptr.is_null(), "pbe/null-iv: must be NULL");
    assert_field("pbe/null-password-10", w_ptr, w_len, true, 10);
    assert_field("pbe/null-salt-8", s_ptr, s_len, true, 8);

    let iv_input = vec![0x8F; 8];
    let password_input = vec![0x90; 10];
    let salt_input = vec![0x91; 8];
    let (iv_ptr, w_ptr, w_len, s_ptr, s_len) = probe(pbe(
        PointerBytes::present_copy(&iv_input),
        PointerBytes::present_copy(&password_input),
        PointerBytes::present_copy(&salt_input),
    ));
    assert!(!iv_ptr.is_null(), "pbe/iv: must be non-NULL");
    assert_eq!(pointee_bytes(iv_ptr as *const u8, 8), iv_input);
    assert_field("pbe/password-data", w_ptr, w_len, false, 10);
    assert_eq!(pointee_bytes(w_ptr as *const u8, w_len as u64), password_input);
    assert_field("pbe/salt-data", s_ptr, s_len, false, 8);
    assert_eq!(pointee_bytes(s_ptr as *const u8, s_len as u64), salt_input);

    // The fixed 8-byte IV normalizes: empty → 8 zeros (live — the
    // provider writes 8 on the keygen path), short → zero-padded (no
    // provider over-read on the encrypt path).
    let (iv_ptr, _, _, _, _) = probe(pbe(
        PointerBytes::present_copy(&[]),
        PointerBytes::null_len(10),
        PointerBytes::null_len(8),
    ));
    assert!(!iv_ptr.is_null(), "pbe/empty-iv: must be non-NULL");
    assert_eq!(pointee_bytes(iv_ptr as *const u8, 8), vec![0u8; 8]);
    let (iv_ptr, _, _, _, _) = probe(pbe(
        PointerBytes::present_copy(&[0x92; 3]),
        PointerBytes::null_len(10),
        PointerBytes::null_len(8),
    ));
    assert!(!iv_ptr.is_null(), "pbe/short-iv: must be non-NULL");
    assert_eq!(
        pointee_bytes(iv_ptr as *const u8, 8),
        vec![0x92, 0x92, 0x92, 0, 0, 0, 0, 0],
        "pbe/short-iv: zero-padded to the fixed 8"
    );
}

// ---------------------------------------------------------------------------
// ECDH-AES key wrap (S2 §8 "ECDH-AES-wrap")
// ---------------------------------------------------------------------------

fn ecdh_aes_wrap(shared: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::EcdhAesKeyWrap(EcdhAesKeyWrapParams {
        aes_key_bits: 256,
        kdf: CkKdf::SHA1_KDF,
        shared_data_presence: shared,
    })
}

#[test]
fn r19_reconstruct_ecdh_aes_key_wrap() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::ECDH_AES_KEY_WRAP);
        let p: cryptoki_sys::CK_ECDH_AES_KEY_WRAP_PARAMS = param_struct(ffi);
        (p.pSharedData, p.ulSharedDataLen)
    };
    let (s_ptr, s_len) = probe(ecdh_aes_wrap(PointerBytes::null_len(6)));
    assert_field("ecdh-aes-wrap/null-shared-6", s_ptr, s_len, true, 6);

    let (s_ptr, s_len) = probe(ecdh_aes_wrap(PointerBytes::present_copy(&[])));
    assert_field("ecdh-aes-wrap/empty-shared", s_ptr, s_len, false, 0);

    let shared_input = vec![0x92; 6];
    let (s_ptr, s_len) = probe(ecdh_aes_wrap(PointerBytes::present_copy(&shared_input)));
    assert_field("ecdh-aes-wrap/shared-data", s_ptr, s_len, false, 6);
    assert_eq!(pointee_bytes(s_ptr as *const u8, s_len as u64), shared_input);
}

// ---------------------------------------------------------------------------
// Key-wrap SET-OAEP (S2 §8 "SET-OAEP")
// ---------------------------------------------------------------------------

fn set_oaep(bc: u32, x: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::KeyWrapSetOaep(KeyWrapSetOaepParams { bc, x_presence: x })
}

#[test]
fn r19_reconstruct_key_wrap_set_oaep() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_KEY_WRAP_SET_OAEP));
        let p: cryptoki_sys::CK_KEY_WRAP_SET_OAEP_PARAMS = param_struct(ffi);
        (p.bBC, p.pX, p.ulXLen)
    };
    let (bc, x_ptr, x_len) = probe(set_oaep(1, PointerBytes::null_len(9)));
    assert_eq!(bc, 1, "set-oaep/bc rides");
    assert_field("set-oaep/null-x-9", x_ptr, x_len, true, 9);

    let x_input = vec![0x93; 9];
    let (bc, x_ptr, x_len) = probe(set_oaep(1, PointerBytes::present_copy(&x_input)));
    assert_eq!(bc, 1, "set-oaep/bc rides");
    assert_field("set-oaep/x-data", x_ptr, x_len, false, 9);
    assert_eq!(pointee_bytes(x_ptr as *const u8, x_len as u64), x_input);
}

// ---------------------------------------------------------------------------
// ML-DSA sign context, plain + hash forms (S2 §8 "sign-context")
// ---------------------------------------------------------------------------

fn sign_ctx(context: PointerBytes, hash: CkMechanismType) -> CkMechanismParams {
    CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
        hedge_variant: 0,
        hash,
        context_presence: context,
    })
}

#[test]
fn r19_reconstruct_sign_additional_context() {
    // Plain form (`hash == 0`): CK_SIGN_ADDITIONAL_CONTEXT.
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::ML_DSA);
        let p: super::FfiSignAdditionalContext = param_struct(ffi);
        (p.p_context, p.ul_context_len)
    };
    let (c_ptr, c_len) = probe(sign_ctx(PointerBytes::null_len(5), CkMechanismType(0)));
    assert_field("sign-ctx/null-context-5", c_ptr, c_len, true, 5);

    let (c_ptr, c_len) = probe(sign_ctx(PointerBytes::present_copy(&[]), CkMechanismType(0)));
    assert_field("sign-ctx/empty-context", c_ptr, c_len, false, 0);

    let context_input = vec![0x94; 5];
    let (c_ptr, c_len) =
        probe(sign_ctx(PointerBytes::present_copy(&context_input), CkMechanismType(0)));
    assert_field("sign-ctx/context-data", c_ptr, c_len, false, 5);
    assert_eq!(pointee_bytes(c_ptr as *const u8, c_len as u64), context_input);
}

#[test]
fn r19_reconstruct_hash_sign_additional_context() {
    // Hash form (`hash != 0`): CK_HASH_SIGN_ADDITIONAL_CONTEXT carries
    // the same context leg plus the explicit hash mechanism.
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::HASH_ML_DSA);
        let p: super::FfiHashSignAdditionalContext = param_struct(ffi);
        (p.p_context, p.ul_context_len, p.hash)
    };
    let (c_ptr, c_len, hash) = probe(sign_ctx(PointerBytes::null_len(5), CkMechanismType::SHA256));
    assert_field("hash-sign-ctx/null-context-5", c_ptr, c_len, true, 5);
    assert_eq!(hash as u64, CkMechanismType::SHA256.0, "hash-sign-ctx/hash rides");

    let context_input = vec![0x95; 5];
    let (c_ptr, c_len, hash) =
        probe(sign_ctx(PointerBytes::present_copy(&context_input), CkMechanismType::SHA256));
    assert_field("hash-sign-ctx/context-data", c_ptr, c_len, false, 5);
    assert_eq!(pointee_bytes(c_ptr as *const u8, c_len as u64), context_input);
    assert_eq!(hash as u64, CkMechanismType::SHA256.0, "hash-sign-ctx/hash rides");
}

// ---------------------------------------------------------------------------
// KMAC (S2 §8 "KMAC")
// ---------------------------------------------------------------------------

fn kmac(customization: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Kmac(KmacParams {
        key_handle: CkObjectHandle(0),
        mac_length: 32,
        customization_string_presence: customization,
    })
}

#[test]
fn r19_reconstruct_kmac() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_KMAC));
        let p: super::FfiKmacParams = param_struct(ffi);
        (p.p_customization_string, p.ul_customization_string_len)
    };
    let (c_ptr, c_len) = probe(kmac(PointerBytes::null_len(7)));
    assert_field("kmac/null-custom-7", c_ptr, c_len, true, 7);

    let (c_ptr, c_len) = probe(kmac(PointerBytes::present_copy(&[])));
    assert_field("kmac/empty-custom", c_ptr, c_len, false, 0);

    let custom_input = vec![0x96; 7];
    let (c_ptr, c_len) = probe(kmac(PointerBytes::present_copy(&custom_input)));
    assert_field("kmac/custom-data", c_ptr, c_len, false, 7);
    assert_eq!(pointee_bytes(c_ptr as *const u8, c_len as u64), custom_input);
}

// ---------------------------------------------------------------------------
// ML-DSA external mu generation (S2 §8 "MuGen")
// ---------------------------------------------------------------------------

fn mugen(tr: PointerBytes, context: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::MuGen(MuGenParams {
        key_handle: CkObjectHandle(0),
        tr_presence: tr,
        context_presence: context,
    })
}

#[test]
fn r19_reconstruct_mu_gen() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_MU_GEN));
        let p: super::FfiMuGenParams = param_struct(ffi);
        (p.p_tr, p.ul_tr_len, p.p_ctx, p.ul_ctx_len)
    };
    let (t_ptr, t_len, c_ptr, c_len) =
        probe(mugen(PointerBytes::null_len(64), PointerBytes::null_len(5)));
    assert_field("mugen/null-tr-64", t_ptr, t_len, true, 64);
    assert_field("mugen/null-context-5", c_ptr, c_len, true, 5);

    let tr_input = vec![0x97; 64];
    let context_input = vec![0x98; 5];
    let (t_ptr, t_len, c_ptr, c_len) = probe(mugen(
        PointerBytes::present_copy(&tr_input),
        PointerBytes::present_copy(&context_input),
    ));
    assert_field("mugen/tr-data", t_ptr, t_len, false, 64);
    assert_field("mugen/context-data", c_ptr, c_len, false, 5);
    assert_eq!(pointee_bytes(t_ptr as *const u8, t_len as u64), tr_input);
    assert_eq!(pointee_bytes(c_ptr as *const u8, c_len as u64), context_input);
}

// ---------------------------------------------------------------------------
// Key-derivation string data (S2 §8 "KDF-string")
// ---------------------------------------------------------------------------

fn kdf_string(data: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::KeyDerivationString(KeyDerivationStringData { data_presence: data })
}

#[test]
fn r19_reconstruct_key_derivation_string_data() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::SHAKE_256_KEY_DERIVATION);
        let p: cryptoki_sys::CK_KEY_DERIVATION_STRING_DATA = param_struct(ffi);
        (p.pData, p.ulLen)
    };
    let (d_ptr, d_len) = probe(kdf_string(PointerBytes::null_len(18)));
    assert_field("kdf-string/null-data-18", d_ptr, d_len, true, 18);

    let (d_ptr, d_len) = probe(kdf_string(PointerBytes::present_copy(&[])));
    assert_field("kdf-string/empty-data", d_ptr, d_len, false, 0);

    let data_input = vec![0x99; 18];
    let (d_ptr, d_len) = probe(kdf_string(PointerBytes::present_copy(&data_input)));
    assert_field("kdf-string/data", d_ptr, d_len, false, 18);
    assert_eq!(pointee_bytes(d_ptr as *const u8, d_len as u64), data_input);
}

// ---------------------------------------------------------------------------
// IKE PRF derive (S2 §8 "IKE")
// ---------------------------------------------------------------------------

fn ike_prf(ni: PointerBytes, nr: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::IkePrfDerive(IkePrfDeriveParams {
        prf_mechanism: CkMechanismType::SHA_1_HMAC,
        data_as_key: false,
        rekey: false,
        new_key_handle: CkObjectHandle(0),
        ni_presence: ni,
        nr_presence: nr,
    })
}

#[test]
fn r19_reconstruct_ike_prf_derive() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::IKE_PRF_DERIVE);
        let p: cryptoki_sys::CK_IKE_PRF_DERIVE_PARAMS = param_struct(ffi);
        (p.pNi, p.ulNiLen, p.pNr, p.ulNrLen)
    };
    let (ni_ptr, ni_len, nr_ptr, nr_len) =
        probe(ike_prf(PointerBytes::null_len(16), PointerBytes::null_len(16)));
    assert_field("ike-prf/null-ni-16", ni_ptr, ni_len, true, 16);
    assert_field("ike-prf/null-nr-16", nr_ptr, nr_len, true, 16);

    let ni_input = vec![0x9A; 16];
    let nr_input = vec![0x9B; 16];
    let (ni_ptr, ni_len, nr_ptr, nr_len) = probe(ike_prf(
        PointerBytes::present_copy(&ni_input),
        PointerBytes::present_copy(&nr_input),
    ));
    assert_field("ike-prf/ni-data", ni_ptr, ni_len, false, 16);
    assert_field("ike-prf/nr-data", nr_ptr, nr_len, false, 16);
    assert_eq!(pointee_bytes(ni_ptr as *const u8, ni_len as u64), ni_input);
    assert_eq!(pointee_bytes(nr_ptr as *const u8, nr_len as u64), nr_input);
}

// ---------------------------------------------------------------------------
// IKE1 PRF derive (S2 §8 "IKE")
// ---------------------------------------------------------------------------

fn ike1_prf(ckyi: PointerBytes, ckyr: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Ike1PrfDerive(Ike1PrfDeriveParams {
        prf_mechanism: CkMechanismType::SHA_1_HMAC,
        has_prev_key: false,
        keygxy_handle: CkObjectHandle(0),
        prev_key_handle: CkObjectHandle(0),
        key_number: 1,
        ckyi_presence: ckyi,
        ckyr_presence: ckyr,
    })
}

#[test]
fn r19_reconstruct_ike1_prf_derive() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::IKE1_PRF_DERIVE);
        let p: cryptoki_sys::CK_IKE1_PRF_DERIVE_PARAMS = param_struct(ffi);
        (p.pCKYi, p.ulCKYiLen, p.pCKYr, p.ulCKYrLen)
    };
    let (i_ptr, i_len, r_ptr, r_len) =
        probe(ike1_prf(PointerBytes::null_len(8), PointerBytes::null_len(8)));
    assert_field("ike1-prf/null-ckyi-8", i_ptr, i_len, true, 8);
    assert_field("ike1-prf/null-ckyr-8", r_ptr, r_len, true, 8);

    let (i_ptr, i_len, r_ptr, r_len) =
        probe(ike1_prf(PointerBytes::present_copy(&[]), PointerBytes::present_copy(&[])));
    assert_field("ike1-prf/empty-ckyi", i_ptr, i_len, false, 0);
    assert_field("ike1-prf/empty-ckyr", r_ptr, r_len, false, 0);

    let ckyi_input = vec![0x9C; 8];
    let ckyr_input = vec![0x9D; 8];
    let (i_ptr, i_len, r_ptr, r_len) = probe(ike1_prf(
        PointerBytes::present_copy(&ckyi_input),
        PointerBytes::present_copy(&ckyr_input),
    ));
    assert_field("ike1-prf/ckyi-data", i_ptr, i_len, false, 8);
    assert_field("ike1-prf/ckyr-data", r_ptr, r_len, false, 8);
    assert_eq!(pointee_bytes(i_ptr as *const u8, i_len as u64), ckyi_input);
    assert_eq!(pointee_bytes(r_ptr as *const u8, r_len as u64), ckyr_input);
}

// ---------------------------------------------------------------------------
// IKE1 extended derive (S2 §8 "IKE")
// ---------------------------------------------------------------------------

fn ike1_extended(extra: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Ike1ExtendedDerive(Ike1ExtendedDeriveParams {
        prf_mechanism: CkMechanismType::SHA_1_HMAC,
        has_keygxy: false,
        keygxy_handle: CkObjectHandle(0),
        extra_data_presence: extra,
    })
}

#[test]
fn r19_reconstruct_ike1_extended_derive() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::IKE1_EXTENDED_DERIVE);
        let p: cryptoki_sys::CK_IKE1_EXTENDED_DERIVE_PARAMS = param_struct(ffi);
        (p.pExtraData, p.ulExtraDataLen)
    };
    let (e_ptr, e_len) = probe(ike1_extended(PointerBytes::null_len(12)));
    assert_field("ike1-ext/null-extra-12", e_ptr, e_len, true, 12);

    let extra_input = vec![0x9E; 12];
    let (e_ptr, e_len) = probe(ike1_extended(PointerBytes::present_copy(&extra_input)));
    assert_field("ike1-ext/extra-data", e_ptr, e_len, false, 12);
    assert_eq!(pointee_bytes(e_ptr as *const u8, e_len as u64), extra_input);
}

// ---------------------------------------------------------------------------
// IKE2 PRF+ derive (S2 §8 "IKE")
// ---------------------------------------------------------------------------

fn ike2_prf_plus(seed: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Ike2PrfPlusDerive(Ike2PrfPlusDeriveParams {
        prf_mechanism: CkMechanismType::SHA_1_HMAC,
        has_seed_key: false,
        seed_key_handle: CkObjectHandle(0),
        seed_data_presence: seed,
    })
}

#[test]
fn r19_reconstruct_ike2_prf_plus_derive() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::IKE2_PRF_PLUS_DERIVE);
        let p: cryptoki_sys::CK_IKE2_PRF_PLUS_DERIVE_PARAMS = param_struct(ffi);
        (p.pSeedData, p.ulSeedDataLen)
    };
    let (s_ptr, s_len) = probe(ike2_prf_plus(PointerBytes::null_len(20)));
    assert_field("ike2-prf+/null-seed-20", s_ptr, s_len, true, 20);

    let (s_ptr, s_len) = probe(ike2_prf_plus(PointerBytes::present_copy(&[])));
    assert_field("ike2-prf+/empty-seed", s_ptr, s_len, false, 0);

    let seed_input = vec![0x9F; 20];
    let (s_ptr, s_len) = probe(ike2_prf_plus(PointerBytes::present_copy(&seed_input)));
    assert_field("ike2-prf+/seed-data", s_ptr, s_len, false, 20);
    assert_eq!(pointee_bytes(s_ptr as *const u8, s_len as u64), seed_input);
}

// ---------------------------------------------------------------------------
// KEA derive (S2 §8 tail "KEA") — RandomA/B share `ulRandomLen`
// ---------------------------------------------------------------------------

fn kea(
    is_sender: bool,
    a: PointerBytes,
    b: PointerBytes,
    public: PointerBytes,
) -> CkMechanismParams {
    CkMechanismParams::KeaDerive(KeaDeriveParams {
        is_sender,
        random_a_presence: a,
        random_b_presence: b,
        public_data_presence: public,
    })
}

#[test]
fn r19_reconstruct_kea_derive() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_KEA_DERIVE));
        let p: cryptoki_sys::CK_KEA_DERIVE_PARAMS = param_struct(ffi);
        (p.ulRandomLen, p.RandomA, p.RandomB, p.ulPublicDataLen, p.PublicData)
    };
    // Agreeing NULL randoms: shared length rides, both legs NULL.
    let (rand_len, a_ptr, b_ptr, p_len, p_ptr) = probe(kea(
        true,
        PointerBytes::null_len(16),
        PointerBytes::null_len(16),
        PointerBytes::null_len(64),
    ));
    assert_eq!(rand_len as u64, 16, "kea/null-random-len");
    assert!(a_ptr.is_null(), "kea/null-a: must be NULL");
    assert!(b_ptr.is_null(), "kea/null-b: must be NULL");
    assert_field("kea/null-public-64", p_ptr, p_len, true, 64);

    // Agreeing present randoms: shared length + exact bytes on all legs.
    let a_input = vec![0xA0; 16];
    let b_input = vec![0xA1; 16];
    let public_input = vec![0xA2; 64];
    let (rand_len, a_ptr, b_ptr, p_len, p_ptr) = probe(kea(
        true,
        PointerBytes::present_copy(&a_input),
        PointerBytes::present_copy(&b_input),
        PointerBytes::present_copy(&public_input),
    ));
    assert_eq!(rand_len as u64, 16, "kea/random-len");
    assert!(!a_ptr.is_null() && !b_ptr.is_null(), "kea/randoms: must be non-NULL");
    assert_eq!(pointee_bytes(a_ptr as *const u8, 16), a_input);
    assert_eq!(pointee_bytes(b_ptr as *const u8, 16), b_input);
    assert_field("kea/public-data", p_ptr, p_len, false, 64);
    assert_eq!(pointee_bytes(p_ptr as *const u8, p_len as u64), public_input);

    // Present-empty randoms: shared length 0, both legs non-NULL.
    let (rand_len, a_ptr, b_ptr, _, _) = probe(kea(
        false,
        PointerBytes::present_copy(&[]),
        PointerBytes::present_copy(&[]),
        PointerBytes::present_copy(&[]),
    ));
    assert_eq!(rand_len as u64, 0, "kea/empty-random-len");
    assert!(!a_ptr.is_null() && !b_ptr.is_null(), "kea/empty-randoms: must be non-NULL");
}

#[test]
fn r19_reconstruct_kea_derive_legacy_mismatch_uses_a() {
    // v0-legacy mismatch pin (pre-existing behavior, NOT new §6 shape):
    // v1 decode rejects disagreeing RandomA/B lengths via
    // `check_shared_len_agreement`, but a directly-constructed legacy
    // value with mismatched legs still converts, with `ulRandomLen`
    // following leg A. This pins the follow-A rule so the R19 rework
    // cannot silently flip it to follow-B.
    let a_input = vec![0xA3; 8];
    let b_input = vec![0xA4; 10];
    let ffi = convert(
        kea(
            true,
            PointerBytes::present_copy(&a_input),
            PointerBytes::present_copy(&b_input),
            PointerBytes::present_copy(&[]),
        ),
        CkMechanismType(CKM_TEST_KEA_DERIVE),
    );
    let p: cryptoki_sys::CK_KEA_DERIVE_PARAMS = param_struct(ffi);
    let (rand_len, a_ptr, b_ptr) = (p.ulRandomLen, p.RandomA, p.RandomB);
    assert_eq!(rand_len as u64, 8, "kea-mismatch/random-len follows leg A");
    assert!(!a_ptr.is_null() && !b_ptr.is_null(), "kea-mismatch/legs stay non-NULL");
    assert_eq!(pointee_bytes(a_ptr as *const u8, 8), a_input);
    assert_eq!(pointee_bytes(b_ptr as *const u8, 10), b_input);
}

// ---------------------------------------------------------------------------
// Skipjack private wrap (S2 §8 tail "Skipjack") — PrimeP/BaseG share
// `ulPAndGLen`; `ulPasswordLen` stays scalar-authoritative
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn skipjack_private(
    password: PointerBytes,
    password_length: u64,
    public: PointerBytes,
    random_a: PointerBytes,
    prime_p: PointerBytes,
    base_g: PointerBytes,
    subprime_q: PointerBytes,
) -> CkMechanismParams {
    CkMechanismParams::SkipjackPrivateWrap(SkipjackPrivateWrapParams {
        password_length,
        password_presence: password,
        public_data_presence: public,
        random_a_presence: random_a,
        prime_p_presence: prime_p,
        base_g_presence: base_g,
        subprime_q_presence: subprime_q,
    })
}

#[test]
fn r19_reconstruct_skipjack_private_wrap() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_SKIPJACK_PRIVATE_WRAP));
        let p: cryptoki_sys::CK_SKIPJACK_PRIVATE_WRAP_PARAMS = param_struct(ffi);
        (
            p.ulPasswordLen,
            p.pPassword,
            p.pPublicData,
            p.ulPublicDataLen,
            p.ulPAndGLen,
            p.ulQLen,
            p.ulRandomLen,
            p.pRandomA,
            p.pPrimeP,
            p.pBaseG,
            p.pSubprimeQ,
        )
    };
    // Agreeing NULL legs: shared lengths ride, every leg NULL.
    let (w_len, w_ptr, pub_ptr, pub_len, pg_len, q_len, r_len, ra_ptr, pp_ptr, bg_ptr, sq_ptr) =
        probe(skipjack_private(
            PointerBytes::null_len(10),
            10,
            PointerBytes::null_len(64),
            PointerBytes::null_len(16),
            PointerBytes::null_len(64),
            PointerBytes::null_len(64),
            PointerBytes::null_len(20),
        ));
    assert_eq!(w_len as u64, 10, "sj-priv/null-password-len");
    assert!(w_ptr.is_null(), "sj-priv/null-password: must be NULL");
    assert_field("sj-priv/null-public-64", pub_ptr, pub_len, true, 64);
    assert_eq!(pg_len as u64, 64, "sj-priv/null-p-and-g-len");
    assert_eq!(q_len as u64, 20, "sj-priv/null-q-len");
    assert_eq!(r_len as u64, 16, "sj-priv/null-random-len");
    assert!(
        ra_ptr.is_null() && pp_ptr.is_null() && bg_ptr.is_null() && sq_ptr.is_null(),
        "sj-priv/null-legs: must be NULL"
    );

    // Agreeing present legs: shared lengths + exact bytes everywhere.
    let password_input = vec![0xA5; 10];
    let public_input = vec![0xA6; 64];
    let random_input = vec![0xA7; 16];
    let prime_input = vec![0xA8; 64];
    let base_input = vec![0xA9; 64];
    let subprime_input = vec![0xAA; 20];
    let (w_len, w_ptr, pub_ptr, pub_len, pg_len, q_len, r_len, ra_ptr, pp_ptr, bg_ptr, sq_ptr) =
        probe(skipjack_private(
            PointerBytes::present_copy(&password_input),
            10,
            PointerBytes::present_copy(&public_input),
            PointerBytes::present_copy(&random_input),
            PointerBytes::present_copy(&prime_input),
            PointerBytes::present_copy(&base_input),
            PointerBytes::present_copy(&subprime_input),
        ));
    assert_eq!(w_len as u64, 10, "sj-priv/password-len");
    assert!(!w_ptr.is_null(), "sj-priv/password: must be non-NULL");
    assert_eq!(pointee_bytes(w_ptr as *const u8, 10), password_input);
    assert_field("sj-priv/public-data", pub_ptr, pub_len, false, 64);
    assert_eq!(pointee_bytes(pub_ptr as *const u8, pub_len as u64), public_input);
    assert_eq!(pg_len as u64, 64, "sj-priv/p-and-g-len");
    assert_eq!(q_len as u64, 20, "sj-priv/q-len");
    assert_eq!(r_len as u64, 16, "sj-priv/random-len");
    assert_eq!(pointee_bytes(ra_ptr as *const u8, 16), random_input);
    assert_eq!(pointee_bytes(pp_ptr as *const u8, 64), prime_input);
    assert_eq!(pointee_bytes(bg_ptr as *const u8, 64), base_input);
    assert_eq!(pointee_bytes(sq_ptr as *const u8, 20), subprime_input);

    // Scalar authority: `ulPasswordLen` follows the scalar, not the
    // presence length (pre-existing semantic, pinned against the rework).
    // The test reads only the 10 backing bytes — no overread.
    let (w_len, w_ptr, _, _, _, _, _, _, _, _, _) = probe(skipjack_private(
        PointerBytes::present_copy(&password_input),
        12,
        PointerBytes::present_copy(&[]),
        PointerBytes::present_copy(&[]),
        PointerBytes::present_copy(&[]),
        PointerBytes::present_copy(&[]),
        PointerBytes::present_copy(&[]),
    ));
    assert_eq!(w_len as u64, 12, "sj-priv/scalar-password-len wins over presence");
    assert_eq!(pointee_bytes(w_ptr as *const u8, 10), password_input);
}

#[test]
fn r19_reconstruct_skipjack_private_wrap_legacy_mismatch_uses_prime_p() {
    // v0-legacy mismatch pin (pre-existing behavior, NOT new §6 shape):
    // v1 decode rejects disagreeing PrimeP/BaseG lengths via
    // `check_shared_len_agreement`, but a directly-constructed legacy
    // value with mismatched legs still converts, with `ulPAndGLen`
    // following PrimeP. This pins the follow-PrimeP rule so the R19
    // rework cannot silently flip it to follow-BaseG.
    let prime_input = vec![0xAB; 64];
    let base_input = vec![0xAC; 48];
    let ffi = convert(
        skipjack_private(
            PointerBytes::present_copy(&[]),
            0,
            PointerBytes::present_copy(&[]),
            PointerBytes::present_copy(&[]),
            PointerBytes::present_copy(&prime_input),
            PointerBytes::present_copy(&base_input),
            PointerBytes::present_copy(&[]),
        ),
        CkMechanismType(CKM_TEST_SKIPJACK_PRIVATE_WRAP),
    );
    let p: cryptoki_sys::CK_SKIPJACK_PRIVATE_WRAP_PARAMS = param_struct(ffi);
    assert_eq!(p.ulPAndGLen as u64, 64, "sj-priv-mismatch/p-and-g-len follows PrimeP");
    assert!(!p.pPrimeP.is_null() && !p.pBaseG.is_null(), "sj-priv-mismatch/legs stay non-NULL");
    assert_eq!(pointee_bytes(p.pPrimeP as *const u8, 64), prime_input);
    assert_eq!(pointee_bytes(p.pBaseG as *const u8, 48), base_input);
}

// ---------------------------------------------------------------------------
// Skipjack RelayX (S2 §8 tail "Skipjack") — seven byte legs
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn skipjack_relayx(
    old_x: PointerBytes,
    old_password: PointerBytes,
    old_public: PointerBytes,
    old_random: PointerBytes,
    new_password: PointerBytes,
    new_public: PointerBytes,
    new_random: PointerBytes,
) -> CkMechanismParams {
    CkMechanismParams::SkipjackRelayx(SkipjackRelayxParams {
        old_wrapped_x_presence: old_x,
        old_password_presence: old_password,
        old_public_data_presence: old_public,
        old_random_a_presence: old_random,
        new_password_presence: new_password,
        new_public_data_presence: new_public,
        new_random_a_presence: new_random,
    })
}

#[test]
fn r19_reconstruct_skipjack_relayx() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_SKIPJACK_RELAYX));
        let p: cryptoki_sys::CK_SKIPJACK_RELAYX_PARAMS = param_struct(ffi);
        [
            (p.pOldWrappedX, p.ulOldWrappedXLen),
            (p.pOldPassword, p.ulOldPasswordLen),
            (p.pOldPublicData, p.ulOldPublicDataLen),
            (p.pOldRandomA, p.ulOldRandomLen),
            (p.pNewPassword, p.ulNewPasswordLen),
            (p.pNewPublicData, p.ulNewPublicDataLen),
            (p.pNewRandomA, p.ulNewRandomLen),
        ]
    };
    // All-NULL with distinct lengths (each leg independently pinned).
    let legs = probe(skipjack_relayx(
        PointerBytes::null_len(24),
        PointerBytes::null_len(10),
        PointerBytes::null_len(64),
        PointerBytes::null_len(16),
        PointerBytes::null_len(11),
        PointerBytes::null_len(65),
        PointerBytes::null_len(17),
    ));
    for (i, ((ptr, len), expect)) in legs.iter().zip([24, 10, 64, 16, 11, 65, 17]).enumerate() {
        assert!(ptr.is_null(), "sj-relayx/null-leg-{i}: must be NULL");
        assert_eq!(*len as u64, expect, "sj-relayx/null-leg-{i}: declared length");
    }

    // All-present with distinct bytes per leg.
    let inputs: Vec<Vec<u8>> = (0..7).map(|i| vec![0xB0 + i as u8; 4 + i]).collect();
    let legs = probe(skipjack_relayx(
        PointerBytes::present_copy(&inputs[0]),
        PointerBytes::present_copy(&inputs[1]),
        PointerBytes::present_copy(&inputs[2]),
        PointerBytes::present_copy(&inputs[3]),
        PointerBytes::present_copy(&inputs[4]),
        PointerBytes::present_copy(&inputs[5]),
        PointerBytes::present_copy(&inputs[6]),
    ));
    for (i, ((ptr, len), input)) in legs.iter().zip(&inputs).enumerate() {
        assert!(!ptr.is_null(), "sj-relayx/leg-{i}: must be non-NULL");
        assert_eq!(*len as u64, input.len() as u64, "sj-relayx/leg-{i}: length");
        assert_eq!(pointee_bytes(*ptr as *const u8, *len as u64), *input);
    }
}

// ---------------------------------------------------------------------------
// TLS PRF (S2 §8 tail "TLS/WTLS envelopes") — incl. output envelopes
// ---------------------------------------------------------------------------

fn tls_prf(
    seed: PointerBytes,
    label: PointerBytes,
    output_len: u64,
    output_is_null: bool,
    output_len_is_null: bool,
) -> CkMechanismParams {
    CkMechanismParams::TlsPrf(TlsPrfParams {
        output_len,
        output: SecretBytes::copy_from_slice(&[]),
        seed_presence: seed,
        label_presence: label,
        output_is_null,
        output_len_is_null,
    })
}

#[test]
fn r19_reconstruct_tls_prf() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::TLS_PRF);
        let p: cryptoki_sys::CK_TLS_PRF_PARAMS = param_struct(ffi);
        (p.pSeed, p.ulSeedLen, p.pLabel, p.ulLabelLen, p.pOutput, p.pulOutputLen)
    };
    // NULL seed + live output envelope: input NULL + len, output live
    // zeroed buffer + live length cell primed with the capacity.
    let (s_ptr, s_len, l_ptr, l_len, o_ptr, ol_ptr) = probe(tls_prf(
        PointerBytes::null_len(5),
        PointerBytes::present_copy(&[0xAD; 3]),
        16,
        false,
        false,
    ));
    assert_field("tls-prf/null-seed-5", s_ptr, s_len, true, 5);
    assert_field("tls-prf/label-data", l_ptr, l_len, false, 3);
    assert_eq!(pointee_bytes(l_ptr as *const u8, l_len as u64), vec![0xAD; 3]);
    assert!(!o_ptr.is_null(), "tls-prf/output: must be non-NULL");
    assert!(!ol_ptr.is_null(), "tls-prf/output-len: must be non-NULL");
    // SAFETY: `pulOutputLen` designates a live aligned `CK_ULONG` cell.
    assert_eq!(unsafe { *ol_ptr }, 16, "tls-prf/output-len: initial length");
    assert_eq!(pointee_bytes(o_ptr as *const u8, 16), vec![0u8; 16], "tls-prf/output: zeroed");

    // NULL output envelopes: both pointers NULL.
    let (_, _, _, _, o_ptr, ol_ptr) = probe(tls_prf(
        PointerBytes::present_copy(&[0xAE; 5]),
        PointerBytes::present_copy(&[]),
        0,
        true,
        true,
    ));
    assert!(o_ptr.is_null(), "tls-prf/null-output: must be NULL");
    assert!(ol_ptr.is_null(), "tls-prf/null-output-len: must be NULL");

    // Present-empty seed → non-NULL + 0.
    let (s_ptr, s_len, _, _, _, _) = probe(tls_prf(
        PointerBytes::present_copy(&[]),
        PointerBytes::present_copy(&[]),
        16,
        false,
        false,
    ));
    assert_field("tls-prf/empty-seed", s_ptr, s_len, false, 0);
}

// ---------------------------------------------------------------------------
// TLS KDF (S2 §8 tail "TLS/WTLS envelopes") — label + random + context
// ---------------------------------------------------------------------------

fn ssl_random(client: PointerBytes, server: PointerBytes) -> SslRandomData {
    SslRandomData { client_random_presence: client, server_random_presence: server }
}

fn tls_kdf(label: PointerBytes, random: SslRandomData, context: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::TlsKdf(TlsKdfParams {
        prf_mechanism: CkMechanismType::SHA_1_HMAC,
        random_info: random,
        label_presence: label,
        context_data_presence: context,
    })
}

#[test]
fn r19_reconstruct_tls_kdf() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::TLS_KDF);
        let p: cryptoki_sys::CK_TLS_KDF_PARAMS = param_struct(ffi);
        (
            p.pLabel,
            p.ulLabelLength,
            p.RandomInfo.pClientRandom,
            p.RandomInfo.ulClientRandomLen,
            p.RandomInfo.pServerRandom,
            p.RandomInfo.ulServerRandomLen,
            p.pContextData,
            p.ulContextDataLength,
        )
    };
    let (l_ptr, l_len, c_ptr, c_len, s_ptr, s_len, x_ptr, x_len) = probe(tls_kdf(
        PointerBytes::null_len(9),
        ssl_random(PointerBytes::null_len(32), PointerBytes::null_len(32)),
        PointerBytes::null_len(7),
    ));
    assert_field("tls-kdf/null-label-9", l_ptr, l_len, true, 9);
    assert_field("tls-kdf/null-client-32", c_ptr, c_len, true, 32);
    assert_field("tls-kdf/null-server-32", s_ptr, s_len, true, 32);
    assert_field("tls-kdf/null-context-7", x_ptr, x_len, true, 7);

    let label_input = vec![0xAF; 9];
    let context_input = vec![0xB0; 7];
    let (l_ptr, l_len, c_ptr, c_len, s_ptr, s_len, x_ptr, x_len) = probe(tls_kdf(
        PointerBytes::present_copy(&label_input),
        ssl_random(PointerBytes::present_copy(&[0xB1; 32]), PointerBytes::present_copy(&[])),
        PointerBytes::present_copy(&context_input),
    ));
    assert_field("tls-kdf/label-data", l_ptr, l_len, false, 9);
    assert_eq!(pointee_bytes(l_ptr as *const u8, l_len as u64), label_input);
    assert_field("tls-kdf/client-data", c_ptr, c_len, false, 32);
    assert_eq!(pointee_bytes(c_ptr as *const u8, c_len as u64), vec![0xB1; 32]);
    assert_field("tls-kdf/empty-server", s_ptr, s_len, false, 0);
    assert_field("tls-kdf/context-data", x_ptr, x_len, false, 7);
    assert_eq!(pointee_bytes(x_ptr as *const u8, x_len as u64), context_input);
}

// ---------------------------------------------------------------------------
// SSL3 master-key derive (S2 §8 tail "TLS/WTLS envelopes") — version is an
// OUT cell governed by its null bit, not by a 0.0 sentinel
// ---------------------------------------------------------------------------

fn ssl3_master(
    random: SslRandomData,
    major: u32,
    minor: u32,
    version_is_null: bool,
) -> CkMechanismParams {
    CkMechanismParams::Ssl3MasterKeyDerive(Ssl3MasterKeyDeriveParams {
        random_info: random,
        version_major: major,
        version_minor: minor,
        version_is_null,
    })
}

#[test]
fn r19_reconstruct_ssl3_master_key_derive() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::SSL3_MASTER_KEY_DERIVE);
        let p: cryptoki_sys::CK_SSL3_MASTER_KEY_DERIVE_PARAMS = param_struct(ffi);
        (
            p.RandomInfo.pClientRandom,
            p.RandomInfo.ulClientRandomLen,
            p.RandomInfo.pServerRandom,
            p.RandomInfo.ulServerRandomLen,
            p.pVersion,
        )
    };
    let (c_ptr, c_len, s_ptr, s_len, v_ptr) = probe(ssl3_master(
        ssl_random(PointerBytes::null_len(32), PointerBytes::null_len(32)),
        3,
        3,
        false,
    ));
    assert_field("ssl3-master/null-client-32", c_ptr, c_len, true, 32);
    assert_field("ssl3-master/null-server-32", s_ptr, s_len, true, 32);
    assert!(!v_ptr.is_null(), "ssl3-master/version: must be non-NULL");
    // SAFETY: `pVersion` designates a live CK_VERSION cell.
    let v = unsafe { v_ptr.read_unaligned() };
    assert_eq!((v.major, v.minor), (3, 3), "ssl3-master/version: pre-call echo");

    // NULL version bit (with the zeroed scalars `check_null_bit_pair`
    // requires) → NULL.
    let (_, _, _, _, v_ptr) = probe(ssl3_master(
        ssl_random(
            PointerBytes::present_copy(&[0xB2; 32]),
            PointerBytes::present_copy(&[0xB3; 32]),
        ),
        0,
        0,
        true,
    ));
    assert!(v_ptr.is_null(), "ssl3-master/null-version: must be NULL");

    // The bit — not a 0.0 sentinel — governs presence (R18 finding):
    // zeroed scalars with an UNSET bit stay LIVE.
    let (_, _, _, _, v_ptr) = probe(ssl3_master(
        ssl_random(
            PointerBytes::present_copy(&[0xB2; 32]),
            PointerBytes::present_copy(&[0xB3; 32]),
        ),
        0,
        0,
        false,
    ));
    assert!(!v_ptr.is_null(), "ssl3-master/zero-version-live: must be non-NULL");

    // Present-empty randoms → non-NULL + 0.
    let (c_ptr, c_len, s_ptr, s_len, _) = probe(ssl3_master(
        ssl_random(PointerBytes::present_copy(&[]), PointerBytes::present_copy(&[])),
        3,
        3,
        false,
    ));
    assert_field("ssl3-master/empty-client", c_ptr, c_len, false, 0);
    assert_field("ssl3-master/empty-server", s_ptr, s_len, false, 0);
}

// ---------------------------------------------------------------------------
// TLS12 master-key derive (S2 §8 tail "TLS/WTLS envelopes")
// ---------------------------------------------------------------------------

fn tls12_master(
    random: SslRandomData,
    major: u32,
    minor: u32,
    version_is_null: bool,
) -> CkMechanismParams {
    CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
        random_info: random,
        version_major: major,
        version_minor: minor,
        prf_hash_mechanism: CkMechanismType::SHA256,
        version_is_null,
    })
}

#[test]
fn r19_reconstruct_tls12_master_key_derive() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::TLS12_MASTER_KEY_DERIVE);
        let p: cryptoki_sys::CK_TLS12_MASTER_KEY_DERIVE_PARAMS = param_struct(ffi);
        (
            p.RandomInfo.pClientRandom,
            p.RandomInfo.ulClientRandomLen,
            p.RandomInfo.pServerRandom,
            p.RandomInfo.ulServerRandomLen,
            p.pVersion,
            p.prfHashMechanism,
        )
    };
    let (c_ptr, c_len, s_ptr, s_len, v_ptr, prf) = probe(tls12_master(
        ssl_random(PointerBytes::null_len(32), PointerBytes::null_len(32)),
        3,
        3,
        false,
    ));
    assert_field("tls12-master/null-client-32", c_ptr, c_len, true, 32);
    assert_field("tls12-master/null-server-32", s_ptr, s_len, true, 32);
    assert!(!v_ptr.is_null(), "tls12-master/version: must be non-NULL");
    assert_eq!(prf as u64, CkMechanismType::SHA256.0, "tls12-master/prf rides");

    let (_, _, _, _, v_ptr, _) = probe(tls12_master(
        ssl_random(
            PointerBytes::present_copy(&[0xB4; 32]),
            PointerBytes::present_copy(&[0xB5; 32]),
        ),
        0,
        0,
        true,
    ));
    assert!(v_ptr.is_null(), "tls12-master/null-version: must be NULL");

    // The bit — not a 0.0 sentinel — governs presence (R18 finding):
    // zeroed scalars with an UNSET bit stay LIVE.
    let (_, _, _, _, v_ptr, _) = probe(tls12_master(
        ssl_random(
            PointerBytes::present_copy(&[0xB4; 32]),
            PointerBytes::present_copy(&[0xB5; 32]),
        ),
        0,
        0,
        false,
    ));
    assert!(!v_ptr.is_null(), "tls12-master/zero-version-live: must be non-NULL");

    let (c_ptr, c_len, s_ptr, s_len, _, _) = probe(tls12_master(
        ssl_random(PointerBytes::present_copy(&[]), PointerBytes::present_copy(&[])),
        3,
        3,
        false,
    ));
    assert_field("tls12-master/empty-client", c_ptr, c_len, false, 0);
    assert_field("tls12-master/empty-server", s_ptr, s_len, false, 0);
}

// ---------------------------------------------------------------------------
// TLS12 extended master-key derive (S2 §8 tail "TLS/WTLS envelopes")
// ---------------------------------------------------------------------------

fn tls12_extended(
    session_hash: PointerBytes,
    major: u32,
    minor: u32,
    version_is_null: bool,
) -> CkMechanismParams {
    CkMechanismParams::Tls12ExtendedMasterKeyDerive(Tls12ExtendedMasterKeyDeriveParams {
        prf_hash_mechanism: CkMechanismType::SHA256,
        version_major: major,
        version_minor: minor,
        session_hash_presence: session_hash,
        version_is_null,
    })
}

#[test]
fn r19_reconstruct_tls12_extended_master_key_derive() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_TLS12_EXTENDED_MASTER_KEY_DERIVE));
        let p: cryptoki_sys::CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS = param_struct(ffi);
        (p.pSessionHash, p.ulSessionHashLen, p.pVersion)
    };
    let (h_ptr, h_len, v_ptr) = probe(tls12_extended(PointerBytes::null_len(48), 3, 3, false));
    assert_field("tls12-ext/null-hash-48", h_ptr, h_len, true, 48);
    assert!(!v_ptr.is_null(), "tls12-ext/version: must be non-NULL");

    let (_, _, v_ptr) = probe(tls12_extended(PointerBytes::present_copy(&[]), 0, 0, true));
    assert!(v_ptr.is_null(), "tls12-ext/null-version: must be NULL");

    // The bit — not a 0.0 sentinel — governs presence (R18 finding):
    // zeroed scalars with an UNSET bit stay LIVE.
    let (_, _, v_ptr) = probe(tls12_extended(PointerBytes::present_copy(&[]), 0, 0, false));
    assert!(!v_ptr.is_null(), "tls12-ext/zero-version-live: must be non-NULL");

    let hash_input = vec![0xAB; 48];
    let (h_ptr, h_len, _) =
        probe(tls12_extended(PointerBytes::present_copy(&hash_input), 3, 3, false));
    assert_field("tls12-ext/hash-data", h_ptr, h_len, false, 48);
    assert_eq!(pointee_bytes(h_ptr as *const u8, h_len as u64), hash_input);
}

// ---------------------------------------------------------------------------
// SSL3/TLS12 key-mat (S2 §8 tail "key-mat") — incl. returned-material envelope
// ---------------------------------------------------------------------------

#[test]
fn r19_reconstruct_ssl3_key_mat() {
    let params = |random: SslRandomData,
                  client_iv: PointerBytes,
                  server_iv: PointerBytes,
                  prf: CkMechanismType,
                  returned_null: bool| {
        CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
            mac_size_bits: 128,
            key_size_bits: 128,
            iv_size_bits: 128,
            is_export: false,
            random_info: random,
            prf_hash_mechanism: prf,
            client_mac_secret_handle: CkObjectHandle(0),
            server_mac_secret_handle: CkObjectHandle(0),
            client_key_handle: CkObjectHandle(0),
            server_key_handle: CkObjectHandle(0),
            client_iv_presence: client_iv,
            server_iv_presence: server_iv,
            returned_key_material_is_null: returned_null,
        })
    };
    // SSL3 form (`prf == 0`): follow `pReturnedKeyMaterial` into the OUT
    // struct for the IV legs (16 bytes each at 128 IV bits).
    let probe_ssl3 = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::SSL3_KEY_AND_MAC_DERIVE);
        let p: cryptoki_sys::CK_SSL3_KEY_MAT_PARAMS = param_struct(ffi);
        let (c_ptr, c_len, s_ptr, s_len, out_ptr) = (
            p.RandomInfo.pClientRandom,
            p.RandomInfo.ulClientRandomLen,
            p.RandomInfo.pServerRandom,
            p.RandomInfo.ulServerRandomLen,
            p.pReturnedKeyMaterial,
        );
        // SAFETY: by-value copies of the OUT struct (when non-NULL); the
        // copies carry no provenance.
        let out = if out_ptr.is_null() { None } else { Some(unsafe { out_ptr.read_unaligned() }) };
        (c_ptr, c_len, s_ptr, s_len, out_ptr, out)
    };
    // NULL randoms + NULL IVs + live OUT struct: inputs NULL + lens, OUT
    // live with NULL IV legs (the IV length is bits-derived: 16 bytes).
    let (c_ptr, c_len, s_ptr, s_len, out_ptr, out) = probe_ssl3(params(
        ssl_random(PointerBytes::null_len(32), PointerBytes::null_len(32)),
        PointerBytes::null_len(16),
        PointerBytes::null_len(16),
        CkMechanismType(0),
        false,
    ));
    assert_field("ssl3-km/null-client-32", c_ptr, c_len, true, 32);
    assert_field("ssl3-km/null-server-32", s_ptr, s_len, true, 32);
    assert!(!out_ptr.is_null(), "ssl3-km/out: must be non-NULL");
    let out: cryptoki_sys::CK_SSL3_KEY_MAT_OUT = out.expect("OUT struct must read");
    assert!(out.pIVClient.is_null(), "ssl3-km/null-client-iv: must be NULL");
    assert!(out.pIVServer.is_null(), "ssl3-km/null-server-iv: must be NULL");

    // NULL returned material (output envelope): the OUT pointer is NULL.
    let (_, _, _, _, out_ptr, _) = probe_ssl3(params(
        ssl_random(
            PointerBytes::present_copy(&[0xAC; 32]),
            PointerBytes::present_copy(&[0xAD; 32]),
        ),
        PointerBytes::null_len(16),
        PointerBytes::null_len(16),
        CkMechanismType(0),
        true,
    ));
    assert!(out_ptr.is_null(), "ssl3-km/null-out: must be NULL");

    // Present IVs → exact bytes behind the OUT struct.
    let (client_in, server_in) = (vec![0xAE; 16], vec![0xAF; 16]);
    let (_, _, _, _, _, out) = probe_ssl3(params(
        ssl_random(
            PointerBytes::present_copy(&[0xAC; 32]),
            PointerBytes::present_copy(&[0xAD; 32]),
        ),
        PointerBytes::present_copy(&client_in),
        PointerBytes::present_copy(&server_in),
        CkMechanismType(0),
        false,
    ));
    let out: cryptoki_sys::CK_SSL3_KEY_MAT_OUT = out.expect("OUT struct must read");
    assert!(!out.pIVClient.is_null() && !out.pIVServer.is_null(), "ssl3-km/ivs: non-NULL");
    assert_eq!(pointee_bytes(out.pIVClient as *const u8, 16), client_in);
    assert_eq!(pointee_bytes(out.pIVServer as *const u8, 16), server_in);

    // TLS12 form (`prf != 0`): same legs plus the PRF mechanism scalar.
    let ffi = convert(
        params(
            ssl_random(PointerBytes::null_len(32), PointerBytes::null_len(32)),
            PointerBytes::null_len(16),
            PointerBytes::null_len(16),
            CkMechanismType::SHA256,
            false,
        ),
        CkMechanismType::SSL3_KEY_AND_MAC_DERIVE,
    );
    let p: cryptoki_sys::CK_TLS12_KEY_MAT_PARAMS = param_struct(ffi);
    let (c_ptr, c_len, out_ptr, prf) = (
        p.RandomInfo.pClientRandom,
        p.RandomInfo.ulClientRandomLen,
        p.pReturnedKeyMaterial,
        p.prfHashMechanism,
    );
    assert_field("tls12-km/null-client-32", c_ptr, c_len, true, 32);
    assert!(!out_ptr.is_null(), "tls12-km/out: must be non-NULL");
    assert_eq!(prf as u64, CkMechanismType::SHA256.0, "tls12-km/prf rides through");
    // SAFETY: the OUT struct sits in live FFI backing; by-value copy.
    let out: cryptoki_sys::CK_SSL3_KEY_MAT_OUT = unsafe { out_ptr.read_unaligned() };
    assert!(out.pIVClient.is_null() && out.pIVServer.is_null(), "tls12-km/null-ivs: NULL");
}

// ---------------------------------------------------------------------------
// WTLS master-key derive (S2 §8 tail "TLS/WTLS envelopes")
// ---------------------------------------------------------------------------

fn wtls_random(client: PointerBytes, server: PointerBytes) -> WtlsRandomData {
    WtlsRandomData { client_random_presence: client, server_random_presence: server }
}

#[test]
fn r19_reconstruct_wtls_master_key_derive() {
    let params = |random: WtlsRandomData, version: u32, version_is_null: bool| {
        CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
            digest_mechanism: CkMechanismType::SHA256,
            random_info: random,
            version,
            version_is_null,
        })
    };
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::WTLS_MASTER_KEY_DERIVE);
        let p: cryptoki_sys::CK_WTLS_MASTER_KEY_DERIVE_PARAMS = param_struct(ffi);
        (
            p.RandomInfo.pClientRandom,
            p.RandomInfo.ulClientRandomLen,
            p.RandomInfo.pServerRandom,
            p.RandomInfo.ulServerRandomLen,
            p.pVersion,
        )
    };
    let (c_ptr, c_len, s_ptr, s_len, v_ptr) = probe(params(
        wtls_random(PointerBytes::null_len(20), PointerBytes::null_len(20)),
        1,
        false,
    ));
    assert_field("wtls-master/null-client-20", c_ptr, c_len, true, 20);
    assert_field("wtls-master/null-server-20", s_ptr, s_len, true, 20);
    assert!(!v_ptr.is_null(), "wtls-master/version: must be non-NULL");
    // SAFETY: `pVersion` designates a live version byte cell.
    assert_eq!(unsafe { *v_ptr }, 1, "wtls-master/version: pre-call echo");

    let (_, _, _, _, v_ptr) = probe(params(
        wtls_random(
            PointerBytes::present_copy(&[0xB0; 20]),
            PointerBytes::present_copy(&[0xB1; 20]),
        ),
        0,
        true,
    ));
    assert!(v_ptr.is_null(), "wtls-master/null-version: must be NULL");

    let (c_ptr, c_len, s_ptr, s_len, _) = probe(params(
        wtls_random(PointerBytes::present_copy(&[]), PointerBytes::present_copy(&[])),
        1,
        false,
    ));
    assert_field("wtls-master/empty-client", c_ptr, c_len, false, 0);
    assert_field("wtls-master/empty-server", s_ptr, s_len, false, 0);
}

// ---------------------------------------------------------------------------
// WTLS PRF (S2 §8 tail "TLS/WTLS envelopes") — incl. output envelopes
// ---------------------------------------------------------------------------

#[test]
fn r19_reconstruct_wtls_prf() {
    let params = |seed: PointerBytes,
                  label: PointerBytes,
                  output_len: u64,
                  output_is_null: bool,
                  output_len_is_null: bool| {
        CkMechanismParams::WtlsPrf(WtlsPrfParams {
            digest_mechanism: CkMechanismType::SHA256,
            output_len,
            output: SecretBytes::copy_from_slice(&[]),
            seed_presence: seed,
            label_presence: label,
            output_is_null,
            output_len_is_null,
        })
    };
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::WTLS_PRF);
        let p: cryptoki_sys::CK_WTLS_PRF_PARAMS = param_struct(ffi);
        (p.pSeed, p.ulSeedLen, p.pLabel, p.ulLabelLen, p.pOutput, p.pulOutputLen)
    };
    let (s_ptr, s_len, l_ptr, l_len, o_ptr, ol_ptr) =
        probe(params(PointerBytes::null_len(5), PointerBytes::null_len(3), 16, false, false));
    assert_field("wtls-prf/null-seed-5", s_ptr, s_len, true, 5);
    assert_field("wtls-prf/null-label-3", l_ptr, l_len, true, 3);
    assert!(!o_ptr.is_null(), "wtls-prf/output: must be non-NULL");
    assert!(!ol_ptr.is_null(), "wtls-prf/output-len: must be non-NULL");
    // SAFETY: `pulOutputLen` designates a live aligned `CK_ULONG` cell.
    assert_eq!(unsafe { *ol_ptr }, 16, "wtls-prf/output-len: initial length");
    assert_eq!(pointee_bytes(o_ptr as *const u8, 16), vec![0u8; 16], "wtls-prf/output: zeroed");

    let (s_ptr, s_len, l_ptr, l_len, o_ptr, ol_ptr) = probe(params(
        PointerBytes::present_copy(&[0xB2; 5]),
        PointerBytes::present_copy(&[0xB3; 3]),
        0,
        true,
        true,
    ));
    assert_field("wtls-prf/seed-data", s_ptr, s_len, false, 5);
    assert_field("wtls-prf/label-data", l_ptr, l_len, false, 3);
    assert!(o_ptr.is_null(), "wtls-prf/null-output: must be NULL");
    assert!(ol_ptr.is_null(), "wtls-prf/null-output-len: must be NULL");

    let (s_ptr, s_len, l_ptr, l_len, _, _) = probe(params(
        PointerBytes::present_copy(&[]),
        PointerBytes::present_copy(&[]),
        16,
        false,
        false,
    ));
    assert_field("wtls-prf/empty-seed", s_ptr, s_len, false, 0);
    assert_field("wtls-prf/empty-label", l_ptr, l_len, false, 0);
}

// ---------------------------------------------------------------------------
// WTLS key-mat (S2 §8 tail "key-mat") — incl. returned-material envelope
// ---------------------------------------------------------------------------

#[test]
fn r19_reconstruct_wtls_key_mat() {
    let params = |random: WtlsRandomData, iv: PointerBytes, returned_null: bool| {
        CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
            digest_mechanism: CkMechanismType::SHA256,
            mac_size_bits: 128,
            key_size_bits: 128,
            iv_size_bits: 128,
            sequence_number: 0,
            is_export: false,
            random_info: random,
            mac_secret_handle: CkObjectHandle(0),
            key_handle: CkObjectHandle(0),
            iv_presence: iv,
            returned_key_material_is_null: returned_null,
        })
    };
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_WTLS_KEY_MAT));
        let p: cryptoki_sys::CK_WTLS_KEY_MAT_PARAMS = param_struct(ffi);
        let (c_ptr, c_len, s_ptr, s_len, out_ptr) = (
            p.RandomInfo.pClientRandom,
            p.RandomInfo.ulClientRandomLen,
            p.RandomInfo.pServerRandom,
            p.RandomInfo.ulServerRandomLen,
            p.pReturnedKeyMaterial,
        );
        // SAFETY: by-value copy of the OUT struct (when non-NULL).
        let out = if out_ptr.is_null() { None } else { Some(unsafe { out_ptr.read_unaligned() }) };
        (c_ptr, c_len, s_ptr, s_len, out_ptr, out)
    };
    let (c_ptr, c_len, s_ptr, s_len, out_ptr, out) = probe(params(
        wtls_random(PointerBytes::null_len(20), PointerBytes::null_len(20)),
        PointerBytes::null_len(16),
        false,
    ));
    assert_field("wtls-km/null-client-20", c_ptr, c_len, true, 20);
    assert_field("wtls-km/null-server-20", s_ptr, s_len, true, 20);
    assert!(!out_ptr.is_null(), "wtls-km/out: must be non-NULL");
    let out: cryptoki_sys::CK_WTLS_KEY_MAT_OUT = out.expect("OUT struct must read");
    assert!(out.pIV.is_null(), "wtls-km/null-iv: must be NULL");

    let (_, _, _, _, out_ptr, _) = probe(params(
        wtls_random(
            PointerBytes::present_copy(&[0xB4; 20]),
            PointerBytes::present_copy(&[0xB5; 20]),
        ),
        PointerBytes::null_len(16),
        true,
    ));
    assert!(out_ptr.is_null(), "wtls-km/null-out: must be NULL");

    let iv_input = vec![0xB6; 16];
    let (_, _, _, _, _, out) = probe(params(
        wtls_random(
            PointerBytes::present_copy(&[0xB4; 20]),
            PointerBytes::present_copy(&[0xB5; 20]),
        ),
        PointerBytes::present_copy(&iv_input),
        false,
    ));
    let out: cryptoki_sys::CK_WTLS_KEY_MAT_OUT = out.expect("OUT struct must read");
    assert!(!out.pIV.is_null(), "wtls-km/iv: must be non-NULL");
    assert_eq!(pointee_bytes(out.pIV as *const u8, 16), iv_input);
}

// ---------------------------------------------------------------------------
// OTP (S2 §8 tail "OTP/SP800-108") — counted-array envelope
// ---------------------------------------------------------------------------

fn otp_param(type_: u64, value: PointerBytes) -> OtpParam {
    OtpParam { type_, value_presence: value }
}

#[test]
fn r19_reconstruct_otp() {
    let params = |presence: PointerArray<OtpParam>| {
        CkMechanismParams::Otp(OtpParams { params_presence: presence })
    };
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType(CKM_TEST_OTP));
        let p: cryptoki_sys::CK_OTP_PARAMS = param_struct(ffi);
        (p.pParams, p.ulCount)
    };
    // NULL array + declared count → NULL + count.
    let (ptr, count) = probe(params(PointerArray::null_count(2)));
    assert!(ptr.is_null(), "otp/null-array: must be NULL");
    assert_eq!(count as u64, 2, "otp/null-array: declared count");

    // Present-empty array → stable non-NULL + 0.
    let (ptr, count) = probe(params(PointerArray::present(Vec::new())));
    assert!(!ptr.is_null(), "otp/empty-array: must be non-NULL");
    assert_eq!(count as u64, 0, "otp/empty-array: count");

    // Present elements → exact array; per-element value legs reconstruct
    // (Present bytes verbatim, NULL + length).
    let (ptr, count) = probe(params(PointerArray::present(vec![
        otp_param(1, PointerBytes::present_copy(&[0xC1; 4])),
        otp_param(2, PointerBytes::null_len(6)),
    ])));
    assert!(!ptr.is_null(), "otp/array: must be non-NULL");
    assert_eq!(count as u64, 2, "otp/array: count");
    // SAFETY: `pParams` designates 2 live `CK_OTP_PARAM` elements (the
    // `Vec<CK_OTP_PARAM>` backing is element-aligned by construction);
    // by-value copies carry no provenance.
    let first: cryptoki_sys::CK_OTP_PARAM = unsafe { ptr.read_unaligned() };
    let second: cryptoki_sys::CK_OTP_PARAM = unsafe { ptr.add(1).read_unaligned() };
    let (t0, v0_ptr, v0_len) = (first.type_, first.pValue, first.ulValueLen);
    let (t1, v1_ptr, v1_len) = (second.type_, second.pValue, second.ulValueLen);
    assert_eq!((t0, t1), (1, 2), "otp/array: element types");
    assert_field("otp/elem0-value", v0_ptr as *mut u8, v0_len, false, 4);
    assert_eq!(pointee_bytes(v0_ptr as *const u8, v0_len as u64), vec![0xC1; 4]);
    assert_field("otp/elem1-value", v1_ptr as *mut u8, v1_len, true, 6);
}

// ---------------------------------------------------------------------------
// KIP (S2 §8 tail "KIP") — nesting presence + seed
// ---------------------------------------------------------------------------

fn kip_present_nested(seed: PointerBytes) -> CkMechanismParams {
    CkMechanismParams::Kip(KipParams {
        mechanism: Some(Box::new(CkMechanism {
            mechanism_type: CkMechanismType::SHA256,
            params: None,
        })),
        key_handle: CkObjectHandle(0),
        seed_presence: seed,
    })
}

#[test]
fn r19_reconstruct_kip() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::KIP_DERIVE);
        let p: cryptoki_sys::CK_KIP_PARAMS = param_struct(ffi);
        (p.pMechanism, p.pSeed, p.ulSeedLen)
    };
    // Present nesting + NULL seed: the nested mechanism pointer is live
    // (parameterless SHA-256 → NULL parameter), the seed is NULL + len.
    let (mech_ptr, s_ptr, s_len) = probe(kip_present_nested(PointerBytes::null_len(5)));
    assert!(!mech_ptr.is_null(), "kip/nested: must be non-NULL");
    // SAFETY: `pMechanism` designates the live nested `CK_MECHANISM`.
    let nested: cryptoki_sys::CK_MECHANISM = unsafe { mech_ptr.read_unaligned() };
    assert_eq!(nested.mechanism as u64, CkMechanismType::SHA256.0, "kip/nested: mechanism id");
    assert!(nested.pParameter.is_null(), "kip/nested: parameterless nested has NULL parameter");
    assert_field("kip/null-seed-5", s_ptr, s_len, true, 5);

    // NULL nesting (R19 final form: `None` ⟺ NULL envelope):
    // `pMechanism` is NULL.
    let ffi = convert(
        CkMechanismParams::Kip(KipParams {
            mechanism: None,
            key_handle: CkObjectHandle(0),
            seed_presence: PointerBytes::present_copy(&[0xC2; 5]),
        }),
        CkMechanismType::KIP_DERIVE,
    );
    let p: cryptoki_sys::CK_KIP_PARAMS = param_struct(ffi);
    let (mech_ptr, s_ptr, s_len) = (p.pMechanism, p.pSeed, p.ulSeedLen);
    assert!(mech_ptr.is_null(), "kip/null-nested: must be NULL");
    assert_field("kip/seed-data", s_ptr, s_len, false, 5);
    assert_eq!(pointee_bytes(s_ptr as *const u8, s_len as u64), vec![0xC2; 5]);

    // Present-empty seed → non-NULL + 0.
    let (_, s_ptr, s_len) = probe(kip_present_nested(PointerBytes::present_copy(&[])));
    assert_field("kip/empty-seed", s_ptr, s_len, false, 0);
}

// ---------------------------------------------------------------------------
// SP800-108 KDF (S2 §8 tail "OTP/SP800-108") — data params + derived keys
// ---------------------------------------------------------------------------

fn prf_data(type_: u64, value: PointerBytes) -> PrfDataParam {
    PrfDataParam { type_, value_presence: value }
}

fn derived_key(
    template: PointerArray<CkAttribute>,
    handle: u64,
    ph_key_is_null: bool,
) -> Sp800108DerivedKey {
    Sp800108DerivedKey {
        key_handle: CkObjectHandle(handle),
        template_presence: template,
        ph_key_is_null,
    }
}

fn sp800_kdf(
    data: PointerArray<PrfDataParam>,
    keys: PointerArray<Sp800108DerivedKey>,
) -> CkMechanismParams {
    CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
        prf_type: CkMechanismType::SHA256,
        data_params_presence: data,
        additional_derived_keys_presence: keys,
    })
}

#[test]
fn r19_reconstruct_sp800_108_kdf() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::SP800_108_COUNTER_KDF);
        let p: cryptoki_sys::CK_SP800_108_KDF_PARAMS = param_struct(ffi);
        (p.pDataParams, p.ulNumberOfDataParams, p.pAdditionalDerivedKeys, p.ulAdditionalDerivedKeys)
    };
    // NULL arrays + declared counts → NULL + counts.
    let (d_ptr, d_count, k_ptr, k_count) =
        probe(sp800_kdf(PointerArray::null_count(2), PointerArray::null_count(1)));
    assert!(d_ptr.is_null(), "sp800-kdf/null-data: must be NULL");
    assert_eq!(d_count as u64, 2, "sp800-kdf/null-data: declared count");
    assert!(k_ptr.is_null(), "sp800-kdf/null-keys: must be NULL");
    assert_eq!(k_count as u64, 1, "sp800-kdf/null-keys: declared count");

    // Present-empty arrays → stable non-NULL + 0.
    let (d_ptr, d_count, k_ptr, k_count) =
        probe(sp800_kdf(PointerArray::present(Vec::new()), PointerArray::present(Vec::new())));
    assert!(!d_ptr.is_null(), "sp800-kdf/empty-data: must be non-NULL");
    assert_eq!(d_count as u64, 0, "sp800-kdf/empty-data: count");
    assert!(!k_ptr.is_null(), "sp800-kdf/empty-keys: must be non-NULL");
    assert_eq!(k_count as u64, 0, "sp800-kdf/empty-keys: count");

    // Present data params → exact array; per-element value legs
    // reconstruct (Present bytes verbatim, NULL + length).
    let (d_ptr, d_count, _, _) = probe(sp800_kdf(
        PointerArray::present(vec![
            prf_data(1, PointerBytes::present_copy(&[0xC3; 3])),
            prf_data(2, PointerBytes::null_len(4)),
        ]),
        PointerArray::present(Vec::new()),
    ));
    assert!(!d_ptr.is_null(), "sp800-kdf/data: must be non-NULL");
    assert_eq!(d_count as u64, 2, "sp800-kdf/data: count");
    // SAFETY: `pDataParams` designates 2 live `CK_PRF_DATA_PARAM`
    // elements; by-value copies carry no provenance.
    let first: cryptoki_sys::CK_PRF_DATA_PARAM = unsafe { d_ptr.read_unaligned() };
    let second: cryptoki_sys::CK_PRF_DATA_PARAM = unsafe { d_ptr.add(1).read_unaligned() };
    assert_field("sp800-kdf/elem0-value", first.pValue as *mut u8, first.ulValueLen, false, 3);
    assert_eq!(pointee_bytes(first.pValue as *const u8, first.ulValueLen as u64), vec![0xC3; 3]);
    assert_field("sp800-kdf/elem1-value", second.pValue as *mut u8, second.ulValueLen, true, 4);

    // Present derived keys → exact array: template + count + live `phKey`
    // for a present template; NULL template + count + NULL `phKey` for
    // the NULL-template/PH-key envelopes (the ADR-0010 class-4
    // `pTemplate` null-bit residual, closed end-to-end here).
    let attr = CkAttribute { attr_type: CkAttributeType::LABEL, value: None };
    let (_, _, k_ptr, k_count) = probe(sp800_kdf(
        PointerArray::present(Vec::new()),
        PointerArray::present(vec![
            derived_key(PointerArray::present(vec![attr]), 0, false),
            derived_key(PointerArray::null_count(3), 0, true),
        ]),
    ));
    assert!(!k_ptr.is_null(), "sp800-kdf/keys: must be non-NULL");
    assert_eq!(k_count as u64, 2, "sp800-kdf/keys: count");
    // SAFETY: `pAdditionalDerivedKeys` designates 2 live `CK_DERIVED_KEY`
    // elements; by-value copies carry no provenance.
    let first: cryptoki_sys::CK_DERIVED_KEY = unsafe { k_ptr.read_unaligned() };
    let second: cryptoki_sys::CK_DERIVED_KEY = unsafe { k_ptr.add(1).read_unaligned() };
    assert!(!first.pTemplate.is_null(), "sp800-kdf/key0-template: must be non-NULL");
    assert_eq!(first.ulAttributeCount as u64, 1, "sp800-kdf/key0-template: count");
    assert!(!first.phKey.is_null(), "sp800-kdf/key0-phkey: must be non-NULL");
    assert!(second.pTemplate.is_null(), "sp800-kdf/key1-template: must be NULL");
    assert_eq!(second.ulAttributeCount as u64, 3, "sp800-kdf/key1-template: declared count");
    assert!(second.phKey.is_null(), "sp800-kdf/key1-phkey: must be NULL");
}

// ---------------------------------------------------------------------------
// SP800-108 feedback KDF (S2 §8 tail "OTP/SP800-108") — data + IV + keys
// ---------------------------------------------------------------------------

fn sp800_feedback_kdf(
    data: PointerArray<PrfDataParam>,
    iv: PointerBytes,
    keys: PointerArray<Sp800108DerivedKey>,
) -> CkMechanismParams {
    CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
        prf_type: CkMechanismType::SHA256,
        data_params_presence: data,
        iv_presence: iv,
        additional_derived_keys_presence: keys,
    })
}

#[test]
fn r19_reconstruct_sp800_108_feedback_kdf() {
    let probe = |params: CkMechanismParams| {
        let ffi = convert(params, CkMechanismType::SP800_108_FEEDBACK_KDF);
        let p: cryptoki_sys::CK_SP800_108_FEEDBACK_KDF_PARAMS = param_struct(ffi);
        (
            p.pDataParams,
            p.ulNumberOfDataParams,
            p.pIV,
            p.ulIVLen,
            p.pAdditionalDerivedKeys,
            p.ulAdditionalDerivedKeys,
        )
    };
    // NULL arrays + NULL IV → NULL + declared counts/lengths.
    let (d_ptr, d_count, iv_ptr, iv_len, k_ptr, k_count) = probe(sp800_feedback_kdf(
        PointerArray::null_count(1),
        PointerBytes::null_len(16),
        PointerArray::null_count(2),
    ));
    assert!(d_ptr.is_null(), "sp800-fb/null-data: must be NULL");
    assert_eq!(d_count as u64, 1, "sp800-fb/null-data: declared count");
    assert_field("sp800-fb/null-iv-16", iv_ptr, iv_len, true, 16);
    assert!(k_ptr.is_null(), "sp800-fb/null-keys: must be NULL");
    assert_eq!(k_count as u64, 2, "sp800-fb/null-keys: declared count");

    // Present-empty → stable non-NULL + 0 on all three legs.
    let (d_ptr, d_count, iv_ptr, iv_len, k_ptr, k_count) = probe(sp800_feedback_kdf(
        PointerArray::present(Vec::new()),
        PointerBytes::present_copy(&[]),
        PointerArray::present(Vec::new()),
    ));
    assert!(!d_ptr.is_null(), "sp800-fb/empty-data: must be non-NULL");
    assert_eq!(d_count as u64, 0, "sp800-fb/empty-data: count");
    assert_field("sp800-fb/empty-iv", iv_ptr, iv_len, false, 0);
    assert!(!k_ptr.is_null(), "sp800-fb/empty-keys: must be non-NULL");
    assert_eq!(k_count as u64, 0, "sp800-fb/empty-keys: count");

    // Present data → exact bytes/counts on all three legs.
    let iv_input = vec![0xC4; 16];
    let attr = CkAttribute { attr_type: CkAttributeType::LABEL, value: None };
    let (d_ptr, d_count, iv_ptr, iv_len, k_ptr, k_count) = probe(sp800_feedback_kdf(
        PointerArray::present(vec![prf_data(1, PointerBytes::present_copy(&[0xC5; 3]))]),
        PointerBytes::present_copy(&iv_input),
        PointerArray::present(vec![derived_key(PointerArray::present(vec![attr]), 0, false)]),
    ));
    assert!(!d_ptr.is_null(), "sp800-fb/data: must be non-NULL");
    assert_eq!(d_count as u64, 1, "sp800-fb/data: count");
    assert_field("sp800-fb/iv-data", iv_ptr, iv_len, false, 16);
    assert_eq!(pointee_bytes(iv_ptr as *const u8, iv_len as u64), iv_input);
    assert!(!k_ptr.is_null(), "sp800-fb/keys: must be non-NULL");
    assert_eq!(k_count as u64, 1, "sp800-fb/keys: count");
    // SAFETY: `pAdditionalDerivedKeys` designates 1 live `CK_DERIVED_KEY`.
    let key: cryptoki_sys::CK_DERIVED_KEY = unsafe { k_ptr.read_unaligned() };
    assert!(!key.pTemplate.is_null(), "sp800-fb/key-template: must be non-NULL");
    assert_eq!(key.ulAttributeCount as u64, 1, "sp800-fb/key-template: count");
    assert!(!key.phKey.is_null(), "sp800-fb/key-phkey: must be non-NULL");
}
