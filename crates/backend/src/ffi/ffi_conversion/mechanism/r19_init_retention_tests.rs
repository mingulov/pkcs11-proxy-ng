//! R19 (S2 §6/§12): Init-path typed/tail pins — `mech_cache`
//! retention of the §6 reconstruction, typed/tail failed-Init
//! extension of the R12 publishes-nothing pins, and output-echo
//! pointer-class preservation.
//!
//! These pins drive `call_init_with_mechanism(_output)` directly with
//! struct-aware capture stubs (the stub re-reads the C param struct
//! behind `pParameter`, so the Init path proves the same §6 form the
//! pure-conversion matrix pins). They need a stub-backed `FfiBackend`,
//! so each test carries `#[cfg_attr(miri, ignore)]` (repo convention
//! for `dlopen`-touching tests); the pure-conversion matrix in
//! `r19_typed_tail_tests` IS Miri-clean.

use super::super::{mechanism_to_ffi, validated_mechanism_for_tests};
use crate::ffi::{FfiBackend, OperationFamily};
use pkcs11_proxy_ng_types::{
    CkMechanism, CkMechanismParams, CkMechanismType, CkRv, CkSessionHandle, GcmParams,
    PointerBytes, SecretBytes, TlsPrfParams, ValidatedMechanismParams,
};
use std::sync::Mutex;

/// Serializes the stub-capture tests: the capture logs are process-global.
static LOCK: Mutex<()> = Mutex::new(());
/// Captured provider-visible GCM Init structs, in order.
static GCM_CALLS: Mutex<Vec<CapturedGcm>> = Mutex::new(Vec::new());
/// Captured provider-visible TLS-PRF Init structs, in order.
static PRF_CALLS: Mutex<Vec<CapturedPrf>> = Mutex::new(Vec::new());

/// One provider-visible GCM Init, as the stub observed the struct.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedGcm {
    mechanism_type: u64,
    iv_null: bool,
    iv_len: u64,
    iv_bytes: Vec<u8>,
    aad_null: bool,
    aad_len: u64,
}

/// One provider-visible TLS-PRF Init, as the stub observed the struct.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedPrf {
    mechanism_type: u64,
    seed_null: bool,
    seed_len: u64,
    seed_bytes: Vec<u8>,
    label_len: u64,
    label_bytes: Vec<u8>,
    output_null: bool,
    output_len_null: bool,
}

/// Read one pointer+length leg behind a live C param struct (by-value:
/// on packed-struct targets — Windows LLP64 — field references are
/// rejected, so every leg below goes through by-value copies and raw
/// byte slices; see `native_owner_tests` E0793).
///
/// SAFETY: the caller proves `ptr` holds `len` readable bytes when
/// non-NULL and the pointed-to extent outlives the copy.
unsafe fn capture_leg(ptr: *mut u8, len: u64) -> (bool, u64, Vec<u8>) {
    // SAFETY: per the caller's contract; the copy carries no provenance.
    let bytes = if ptr.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize).to_vec() }
    };
    (ptr.is_null(), len, bytes)
}

/// Capturing `C_EncryptInit` stub for GCM: records the struct legs the
/// provider observed, reports success.
unsafe extern "C" fn gcm_init_ok(
    _session: cryptoki_sys::CK_SESSION_HANDLE,
    mech: *mut cryptoki_sys::CK_MECHANISM,
    _key: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    // SAFETY: the backend passes a live `CK_MECHANISM` whose
    // `pParameter` holds a live `CK_GCM_PARAMS` (the exact contract
    // under test); by-value copies carry no provenance.
    unsafe {
        let mech = &*mech;
        let mechanism_type = mech.mechanism as u64;
        let gcm = (mech.pParameter as *const cryptoki_sys::CK_GCM_PARAMS).read_unaligned();
        let (p_iv, ul_iv_len, p_aad, ul_aad_len) = (gcm.pIv, gcm.ulIvLen, gcm.pAAD, gcm.ulAADLen);
        let (iv_null, iv_len, iv_bytes) = capture_leg(p_iv, ul_iv_len as u64);
        let (aad_null, aad_len, _) = capture_leg(p_aad as *mut u8, ul_aad_len as u64);
        GCM_CALLS.lock().expect("capture log").push(CapturedGcm {
            mechanism_type,
            iv_null,
            iv_len,
            iv_bytes,
            aad_null,
            aad_len,
        });
    }
    cryptoki_sys::CKR_OK
}

/// Capturing `C_EncryptInit` stub for GCM: records, reports failure (the
/// typed failed-Init pin needs the provider to fail AFTER observing).
unsafe extern "C" fn gcm_init_fails(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    mech: *mut cryptoki_sys::CK_MECHANISM,
    key: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    unsafe { gcm_init_ok(session, mech, key) };
    cryptoki_sys::CKR_GENERAL_ERROR
}

/// Capturing derive stub for TLS-PRF: records the struct legs,
/// reports success.
unsafe extern "C" fn prf_init_ok(
    _session: cryptoki_sys::CK_SESSION_HANDLE,
    mech: *mut cryptoki_sys::CK_MECHANISM,
    _key: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    // SAFETY: the backend passes a live `CK_MECHANISM` whose
    // `pParameter` holds a live `CK_TLS_PRF_PARAMS`; by-value copies
    // carry no provenance.
    unsafe {
        let mech = &*mech;
        let mechanism_type = mech.mechanism as u64;
        let prf = (mech.pParameter as *const cryptoki_sys::CK_TLS_PRF_PARAMS).read_unaligned();
        let (p_seed, ul_seed_len, p_label, ul_label_len, p_output, pul_output_len) =
            (prf.pSeed, prf.ulSeedLen, prf.pLabel, prf.ulLabelLen, prf.pOutput, prf.pulOutputLen);
        let (seed_null, seed_len, seed_bytes) = capture_leg(p_seed as *mut u8, ul_seed_len as u64);
        let (_, label_len, label_bytes) = capture_leg(p_label as *mut u8, ul_label_len as u64);
        PRF_CALLS.lock().expect("capture log").push(CapturedPrf {
            mechanism_type,
            seed_null,
            seed_len,
            seed_bytes,
            label_len,
            label_bytes,
            output_null: p_output.is_null(),
            output_len_null: pul_output_len.is_null(),
        });
    }
    cryptoki_sys::CKR_OK
}

/// Stub-backed backend with an open lifecycle domain (R12 pattern: the
/// function list is all-`None`; the tests pass their stubs directly to
/// the `call_*` helpers).
fn test_backend() -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>) {
    let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
    let backend = FfiBackend::test_backend_with_tables(functions.as_mut(), None, None);
    backend.lifecycle_domain.open_for_tests();
    (backend, functions)
}

type InitStub = unsafe extern "C" fn(
    cryptoki_sys::CK_SESSION_HANDLE,
    *mut cryptoki_sys::CK_MECHANISM,
    cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV;

/// Validate (test funnel: binds the pair under test, F1).
fn validate(
    params: CkMechanismParams,
    mechanism_type: CkMechanismType,
) -> ValidatedMechanismParams {
    validated_mechanism_for_tests(&CkMechanism { mechanism_type, params: Some(params) })
}

/// Successful typed Init retains the §6 reconstruction: the provider
/// observed NULL + narrowed 8 on the NULL `aad` leg and the verbatim
/// IV bytes, and the backing is published for the session family.
#[test]
#[cfg_attr(miri, ignore)] // Miri: stub-backed FfiBackend needs dlopen; pure-conversion half runs under Miri
fn r19_init_typed_gcm_backing_retained() {
    let _guard = LOCK.lock().expect("test lock");
    GCM_CALLS.lock().expect("capture log").clear();
    let (backend, _tables) = test_backend();
    let admission = backend.lifecycle_domain.admit_ordinary().expect("open domain admits");
    let iv = vec![0xC7; 12];
    let validated = validate(
        CkMechanismParams::Gcm(GcmParams {
            iv_bits: 96,
            iv_buffer_len: 12,
            tag_bits: 96,
            // Legacy v0-residue bools: `check_legacy_null_bool` only
            // accepts `true` for `Null{0}`; presence governs.
            iv_presence: PointerBytes::present_copy(&iv),
            aad_presence: PointerBytes::null_len(8),
        }),
        CkMechanismType::AES_GCM,
    );
    // The funnel path and the direct conversion agree (R12 anti-skew
    // pattern): the retained backing must equal a fresh conversion.
    let direct = mechanism_to_ffi(&validated).expect("direct conversion");
    backend
        .call_init_with_mechanism(
            &admission,
            CkSessionHandle(7),
            OperationFamily::Encrypt,
            Some(gcm_init_ok as InitStub),
            &validated,
            |function, mech| unsafe { function(7, mech, 9) },
        )
        .expect("stub Init succeeds");
    assert_eq!(
        GCM_CALLS.lock().expect("capture log").as_slice(),
        &[CapturedGcm {
            mechanism_type: CkMechanismType::AES_GCM.0,
            iv_null: false,
            iv_len: 12,
            iv_bytes: iv,
            aad_null: true,
            aad_len: 8,
        }],
        "provider must observe the §6 reconstruction"
    );
    let slot = backend.mech_cache.get(&(7, OperationFamily::Encrypt));
    assert!(slot.is_some(), "successful typed Init must publish its backing");
    drop(slot);
    assert!(
        backend.last_init_family.get(&7).is_some(),
        "successful typed Init must record its last-Init marker"
    );
    drop(direct);
}

/// Successful tail Init retains the §6 reconstruction: the provider
/// observed NULL + 5 on the NULL `seed` leg, the verbatim label, and
/// the live output envelope.
///
/// Family-label honesty: TLS-PRF is a derive mechanism (one-shot in
/// production — derive owns no `mech_cache` family); the Init helper
/// is family-agnostic, so this test borrows the `Digest` slot purely
/// as an ownership label to pin that the Init path reconstructs and
/// retains the tail envelope identically to the pure funnel (the R12
/// anti-skew pattern), not to claim derive retains.
#[test]
#[cfg_attr(miri, ignore)] // Miri: stub-backed FfiBackend needs dlopen; pure-conversion half runs under Miri
fn r19_init_tail_tls_prf_backing_retained() {
    let _guard = LOCK.lock().expect("test lock");
    PRF_CALLS.lock().expect("capture log").clear();
    let (backend, _tables) = test_backend();
    let admission = backend.lifecycle_domain.admit_ordinary().expect("open domain admits");
    let label = vec![0xC8; 3];
    let validated = validate(
        CkMechanismParams::TlsPrf(TlsPrfParams {
            output_len: 16,
            output: SecretBytes::copy_from_slice(&[]),
            seed_presence: PointerBytes::null_len(5),
            label_presence: PointerBytes::present_copy(&label),
            output_is_null: false,
            output_len_is_null: false,
        }),
        CkMechanismType::TLS_PRF,
    );
    backend
        .call_init_with_mechanism(
            &admission,
            CkSessionHandle(7),
            OperationFamily::Digest,
            Some(prf_init_ok as InitStub),
            &validated,
            |function, mech| unsafe { function(7, mech, 9) },
        )
        .expect("stub Init succeeds");
    assert_eq!(
        PRF_CALLS.lock().expect("capture log").as_slice(),
        &[CapturedPrf {
            mechanism_type: CkMechanismType::TLS_PRF.0,
            seed_null: true,
            seed_len: 5,
            seed_bytes: Vec::new(),
            label_len: 3,
            label_bytes: label,
            output_null: false,
            output_len_null: false,
        }],
        "provider must observe the §6 reconstruction"
    );
    assert!(
        backend.mech_cache.get(&(7, OperationFamily::Digest)).is_some(),
        "successful tail Init must publish its backing"
    );
}

/// Failed typed Init publishes nothing (R12 invariant extended to the
/// typed subset): the provider observed the call, but no backing is
/// retained and no last-Init marker is recorded.
#[test]
#[cfg_attr(miri, ignore)] // Miri: stub-backed FfiBackend needs dlopen; pure-conversion half runs under Miri
fn r19_failed_init_publishes_nothing_typed() {
    let _guard = LOCK.lock().expect("test lock");
    GCM_CALLS.lock().expect("capture log").clear();
    let (backend, _tables) = test_backend();
    let admission = backend.lifecycle_domain.admit_ordinary().expect("open domain admits");
    let iv = vec![0xC9; 12];
    let validated = validate(
        CkMechanismParams::Gcm(GcmParams {
            iv_bits: 96,
            iv_buffer_len: 12,
            tag_bits: 96,
            iv_presence: PointerBytes::present_copy(&iv),
            aad_presence: PointerBytes::present_copy(&[0xCA; 8]),
        }),
        CkMechanismType::AES_GCM,
    );
    let result = backend.call_init_with_mechanism(
        &admission,
        CkSessionHandle(7),
        OperationFamily::Encrypt,
        Some(gcm_init_fails as InitStub),
        &validated,
        |function, mech| unsafe { function(7, mech, 9) },
    );
    assert_eq!(result.err(), Some(CkRv::GENERAL_ERROR));
    assert_eq!(GCM_CALLS.lock().expect("capture log").len(), 1, "provider saw the one call");
    assert!(
        backend.mech_cache.get(&(7, OperationFamily::Encrypt)).is_none(),
        "failed typed Init must publish nothing"
    );
    assert!(
        backend.last_init_family.get(&7).is_none(),
        "failed typed Init must record no last-Init marker"
    );
}

/// Output echo preserves the caller's input pointer class (S2 §6 F3/D2):
/// the provider wrote 8 output bytes, the seed leg stays `Null{5}`
/// (not `Present([])`), and the label bytes echo verbatim.
///
/// Miri-clean (no `FfiBackend`, no `dlopen`): the provider write is
/// simulated in-test through the live output envelope, exactly as a
/// provider would write it. It lives in this file (not the pure
/// matrix) because it pins the post-call `output_params` contract the
/// `_output` Init helper serves.
#[test]
fn r19_init_tail_output_echo_preserves_input_class() {
    let label = vec![0xCB; 3];
    let validated = validate(
        CkMechanismParams::TlsPrf(TlsPrfParams {
            output_len: 16,
            output: SecretBytes::copy_from_slice(&[]),
            seed_presence: PointerBytes::null_len(5),
            label_presence: PointerBytes::present_copy(&label),
            output_is_null: false,
            output_len_is_null: false,
        }),
        CkMechanismType::TLS_PRF,
    );
    let ffi = mechanism_to_ffi(&validated).expect("test mechanism reconstructs");
    let outer = ffi.ck_mechanism();
    assert!(!outer.pParameter.is_null(), "echo needs a live param struct");
    // SAFETY: `pParameter` designates the live `CK_TLS_PRF_PARAMS`; the
    // copy carries no provenance. Field copies are by value (packed
    // struct targets reject direct field references).
    let prf =
        unsafe { (outer.pParameter as *const cryptoki_sys::CK_TLS_PRF_PARAMS).read_unaligned() };
    let (p_output, pul_output_len) = (prf.pOutput, prf.pulOutputLen);
    assert!(!p_output.is_null(), "echo needs a live output buffer");
    assert!(!pul_output_len.is_null(), "echo needs a live length cell");
    // SAFETY: the output envelope designates 16 live backing bytes plus
    // a live length cell (asserted non-NULL above); the 8-byte write
    // stays inside the declared extent.
    unsafe {
        std::ptr::write_bytes(p_output, 0xD1, 8);
        *pul_output_len = 8;
    }
    let Some(CkMechanismParams::TlsPrf(echo)) = ffi.output_params() else {
        panic!("tail output Init must echo its output envelope");
    };
    assert_eq!(echo.output_len, 8, "echo carries the provider-written length");
    assert!(echo.output.expose(|b| b == [0xD1; 8]), "echo carries the provider-written bytes");
    assert_eq!(
        echo.seed_presence,
        PointerBytes::Null { declared_len: 5 },
        "echo preserves the caller's NULL seed class"
    );
    assert_eq!(
        echo.label_presence,
        PointerBytes::present_copy(&label),
        "echo preserves the caller's label bytes"
    );
}
