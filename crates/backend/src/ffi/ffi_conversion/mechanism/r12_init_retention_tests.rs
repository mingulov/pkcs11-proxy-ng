//! R12 (S2 §6/§12): Init-path Flat pins — sanitize-OFF one-call
//! forwarding, successful-Init `mech_cache` retention,
//! failed-Init-publishes-nothing, and Flat-output suppression on an Init
//! RPC carrying `mechanism_out`.
//!
//! These pins drive `call_init_with_mechanism(_output)` directly with
//! server-validated Flat (post-R13 shape: the server validates against
//! the real registry and the backend receives the newtype). They need a
//! stub-backed `FfiBackend`, so each test carries
//! `#[cfg_attr(miri, ignore)]` (repo convention for `dlopen`-touching
//! tests — the CI gate's `ffi::ffi_conversion` Tree-Borrows line
//! otherwise matches this module's path and would run them); the
//! pure-conversion pins live in `r12_flat_null_tests` and ARE Miri-clean.

use super::super::mechanism_to_ffi;
use crate::ffi::{FfiBackend, OperationFamily};
use pkcs11_proxy_ng_types::shape_descriptors::{
    Operation, OperationContext, ParamAbi, ShapeResolver,
};
use pkcs11_proxy_ng_types::{
    CkMechanism, CkMechanismParams, CkMechanismType, CkRv, CkSessionHandle, FlatParams,
    MECHANISM_PARAMETER_TRANSPORT_VERSION, MechanismRegistry, SecretBytes,
    ValidatedMechanismParams,
};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Serializes the stub-capture tests: the capture log is process-global.
static LOCK: Mutex<()> = Mutex::new(());
/// Captured provider-visible Init calls, in order.
static CALLS: Mutex<Vec<CapturedInit>> = Mutex::new(Vec::new());

/// One provider-visible Init call, as the stub observed it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedInit {
    mechanism_type: u64,
    null: bool,
    len: u64,
    bytes: Vec<u8>,
}

fn capture(mech: *mut cryptoki_sys::CK_MECHANISM) {
    // SAFETY: the backend passes a live `CK_MECHANISM` whose `pParameter`
    // holds `ulParameterLen` readable bytes when non-NULL (the exact
    // contract under test); the copy carries no provenance. Fields are
    // copied by value: on packed-struct targets (Windows LLP64)
    // referencing them directly is rejected.
    let (mechanism_type, null, len, bytes) = unsafe {
        let mech = &*mech;
        let (ptr, len) = (mech.pParameter, mech.ulParameterLen as u64);
        let mechanism_type = mech.mechanism as u64;
        let bytes = if ptr.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(ptr as *const u8, len as usize).to_vec()
        };
        (mechanism_type, ptr.is_null(), len, bytes)
    };
    CALLS.lock().expect("capture log").push(CapturedInit { mechanism_type, null, len, bytes });
}

/// Capturing `C_SignInit` stub: records the call, reports success.
unsafe extern "C" fn sign_init_ok(
    _session: cryptoki_sys::CK_SESSION_HANDLE,
    mech: *mut cryptoki_sys::CK_MECHANISM,
    _key: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    capture(mech);
    cryptoki_sys::CKR_OK
}

/// Capturing `C_SignInit` stub: records the call, reports failure (the
/// failed-Init-publishes-nothing pin needs the provider to fail AFTER
/// observing the mechanism).
unsafe extern "C" fn sign_init_fails(
    _session: cryptoki_sys::CK_SESSION_HANDLE,
    mech: *mut cryptoki_sys::CK_MECHANISM,
    _key: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    capture(mech);
    cryptoki_sys::CKR_GENERAL_ERROR
}

/// Capturing `C_EncryptInit` stub that MUTATES the parameter extent
/// before succeeding: proves output suppression holds despite an
/// observable provider write.
unsafe extern "C" fn encrypt_init_mutates(
    _session: cryptoki_sys::CK_SESSION_HANDLE,
    mech: *mut cryptoki_sys::CK_MECHANISM,
    _key: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    // SAFETY: same live-parameter argument as `capture`; the overwrite
    // stays inside the declared extent. By-value field copies (packed
    // struct targets reject direct field references).
    unsafe {
        let mech = &*mech;
        let (ptr, len) = (mech.pParameter, mech.ulParameterLen as usize);
        if !ptr.is_null() {
            std::ptr::write_bytes(ptr as *mut u8, 0xEE, len);
        }
    }
    capture(mech);
    cryptoki_sys::CKR_OK
}

/// Registry binding `mech` to the byte-buffer `iv` shape (R9 test pattern).
fn registry_with_iv_binding(mech: u64) -> MechanismRegistry {
    let mut shapes = HashMap::new();
    shapes.insert(mech, "iv".to_string());
    MechanismRegistry::from_parts(
        shapes,
        HashSet::new(),
        HashSet::new(),
        pkcs11_proxy_ng_types::DiscoveryMode::Transparent,
        "r12-test".to_string(),
    )
}

/// Server-validated Flat (post-R13 shape): validated against a bound
/// registry, then handed to the backend newtype as R13 will.
fn validated_flat(mech_type: u64, bytes: &[u8]) -> ValidatedMechanismParams {
    let resolved = ShapeResolver::resolve(
        Some("iv"),
        OperationContext {
            mechanism: mech_type,
            operation: Operation::General,
            length: bytes.len() as u64,
        },
        ParamAbi::Lp64NativeLe,
    )
    .expect("iv descriptor resolves");
    let mech = CkMechanism {
        mechanism_type: CkMechanismType(mech_type),
        params: Some(CkMechanismParams::Flat(FlatParams {
            bytes: SecretBytes::copy_from_slice(bytes),
            declared_len: bytes.len() as u64,
            source_abi: Some(ParamAbi::Lp64NativeLe),
            fingerprint: resolved.fingerprint(ParamAbi::Lp64NativeLe),
            version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
        })),
    };
    ValidatedMechanismParams::validate(
        &mech,
        &registry_with_iv_binding(mech_type),
        Operation::General,
        ParamAbi::Lp64NativeLe,
        ParamAbi::Lp64NativeLe,
    )
    .expect("test Flat validates")
}

/// Stub-backed backend with an open lifecycle domain. The function list
/// is all-`None`: the tests pass their stubs directly to the `call_*`
/// helpers (which take the function as a parameter), so no table
/// installation is needed. Returns the table keeper alongside (it must
/// outlive the backend).
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

/// RULING SPLIT, OFF half (S2 §12 backend FFI tests list "sanitize ON
/// zero-call / OFF one-call", but sanitize is Phase 3): with sanitize
/// OFF (the default — no sanitizer exists pre-R20), a representable Flat
/// Init forwards to exactly one provider call carrying the verbatim
/// bytes. The ON/zero-call half lands in R20 and names this pin; this
/// pin names it back.
#[test]
#[cfg_attr(miri, ignore)] // Miri: stub-backed FfiBackend needs dlopen; pure-conversion half runs under Miri
fn r12_off_one_call_flat_forwards() {
    let _guard = LOCK.lock().expect("test lock");
    CALLS.lock().expect("capture log").clear();
    let (backend, _tables) = test_backend();
    let admission = backend.lifecycle_domain.admit_ordinary().expect("open domain admits");
    let validated = validated_flat(0x0000_1082, &[0xDE, 0xAD, 0xBE, 0xEF]);
    backend
        .call_init_with_mechanism(
            &admission,
            CkSessionHandle(7),
            OperationFamily::Sign,
            Some(sign_init_ok as InitStub),
            &validated,
            |function, mech| unsafe { function(7, mech, 9) },
        )
        .expect("stub Init succeeds");
    let calls = CALLS.lock().expect("capture log");
    assert_eq!(
        calls.as_slice(),
        &[CapturedInit {
            mechanism_type: 0x0000_1082,
            null: false,
            len: 4,
            bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }],
        "OFF forwards to exactly one provider call with verbatim bytes"
    );
}

/// OFF/one-call for the second v1 kind: Null forwards as NULL +
/// narrowed length in exactly one provider call.
#[test]
#[cfg_attr(miri, ignore)] // Miri: stub-backed FfiBackend needs dlopen; pure-conversion half runs under Miri
fn r12_off_one_call_null_forwards() {
    let _guard = LOCK.lock().expect("test lock");
    CALLS.lock().expect("capture log").clear();
    let (backend, _tables) = test_backend();
    let admission = backend.lifecycle_domain.admit_ordinary().expect("open domain admits");
    let mech = CkMechanism {
        mechanism_type: CkMechanismType(0x0000_1082),
        params: Some(CkMechanismParams::Null {
            declared_len: 12,
            version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
        }),
    };
    let validated =
        super::super::validate_for_ffi(&mech).expect("Null validates without a registry");
    backend
        .call_init_with_mechanism(
            &admission,
            CkSessionHandle(7),
            OperationFamily::Sign,
            Some(sign_init_ok as InitStub),
            &validated,
            |function, mech| unsafe { function(7, mech, 9) },
        )
        .expect("stub Init succeeds");
    let calls = CALLS.lock().expect("capture log");
    assert_eq!(
        calls.as_slice(),
        &[CapturedInit { mechanism_type: 0x0000_1082, null: true, len: 12, bytes: vec![] }],
        "OFF forwards Null to exactly one provider call"
    );
}

/// Successful Init retains the Flat backing in `mech_cache` (S2 §6:
/// Flat/typed backing travels through the existing retention): the
/// session-family slot holds the owner after the call returns.
#[test]
#[cfg_attr(miri, ignore)] // Miri: stub-backed FfiBackend needs dlopen; pure-conversion half runs under Miri
fn r12_init_flat_backing_retained() {
    let _guard = LOCK.lock().expect("test lock");
    CALLS.lock().expect("capture log").clear();
    let (backend, _tables) = test_backend();
    let admission = backend.lifecycle_domain.admit_ordinary().expect("open domain admits");
    let validated = validated_flat(0x0000_1082, &[0xA5; 8]);
    backend
        .call_init_with_mechanism(
            &admission,
            CkSessionHandle(7),
            OperationFamily::Sign,
            Some(sign_init_ok as InitStub),
            &validated,
            |function, mech| unsafe { function(7, mech, 9) },
        )
        .expect("stub Init succeeds");
    let slot = backend.mech_cache.get(&(7, OperationFamily::Sign));
    assert!(slot.is_some(), "successful Flat Init must publish its backing");
    drop(slot);
    assert_eq!(CALLS.lock().expect("capture log").len(), 1);
}

/// Failed Init publishes nothing (existing invariant, re-pinned for
/// Flat): the provider observed the call, but no backing is retained
/// and no last-Init marker is recorded.
#[test]
#[cfg_attr(miri, ignore)] // Miri: stub-backed FfiBackend needs dlopen; pure-conversion half runs under Miri
fn r12_failed_init_publishes_nothing_flat() {
    let _guard = LOCK.lock().expect("test lock");
    CALLS.lock().expect("capture log").clear();
    let (backend, _tables) = test_backend();
    let admission = backend.lifecycle_domain.admit_ordinary().expect("open domain admits");
    let validated = validated_flat(0x0000_1082, &[0xA5; 8]);
    let result = backend.call_init_with_mechanism(
        &admission,
        CkSessionHandle(7),
        OperationFamily::Sign,
        Some(sign_init_fails as InitStub),
        &validated,
        |function, mech| unsafe { function(7, mech, 9) },
    );
    assert_eq!(result.err(), Some(CkRv::GENERAL_ERROR));
    assert_eq!(CALLS.lock().expect("capture log").len(), 1, "provider saw the one call");
    assert!(
        backend.mech_cache.get(&(7, OperationFamily::Sign)).is_none(),
        "failed Flat Init must publish nothing"
    );
    assert!(
        backend.last_init_family.get(&7).is_none(),
        "failed Flat Init must record no last-Init marker"
    );
}

/// Flat-output suppression on an Init RPC carrying `mechanism_out`
/// (S2 §6, decided): even though the provider mutated the extent and the
/// `_output` helper returns `output_params()`, Flat yields `None` — while
/// the (mutated) backing is still retained for the session family.
#[test]
#[cfg_attr(miri, ignore)] // Miri: stub-backed FfiBackend needs dlopen; pure-conversion half runs under Miri
fn r12_init_output_flat_suppressed() {
    let _guard = LOCK.lock().expect("test lock");
    CALLS.lock().expect("capture log").clear();
    let (backend, _tables) = test_backend();
    let admission = backend.lifecycle_domain.admit_ordinary().expect("open domain admits");
    let validated = validated_flat(0x0000_1087, &[0x11; 8]);
    let output = backend
        .call_init_with_mechanism_output(
            &admission,
            CkSessionHandle(7),
            OperationFamily::Encrypt,
            Some(encrypt_init_mutates as InitStub),
            &validated,
            |function, mech| unsafe { function(7, mech, 9) },
        )
        .expect("stub Init succeeds");
    assert_eq!(output, None, "Flat output must suppress even on mechanism_out Inits");
    // The mutation landed (stub overwrote the extent) yet nothing echoes.
    assert_eq!(
        CALLS.lock().expect("capture log").as_slice(),
        &[CapturedInit { mechanism_type: 0x0000_1087, null: false, len: 8, bytes: vec![0xEE; 8] }],
        "stub captured its own mutation"
    );
    assert!(
        backend.mech_cache.get(&(7, OperationFamily::Encrypt)).is_some(),
        "suppressed Flat output still retains its backing"
    );
}

/// Sanity: the direct-helper path used above converts identically to the
/// funnel path for typed params (guards against test-harness skew).
#[test]
#[cfg_attr(miri, ignore)] // Miri: stub-backed FfiBackend needs dlopen; pure-conversion half runs under Miri
fn r12_direct_helper_typed_matches_funnel() {
    let _guard = LOCK.lock().expect("test lock");
    CALLS.lock().expect("capture log").clear();
    let (backend, _tables) = test_backend();
    let admission = backend.lifecycle_domain.admit_ordinary().expect("open domain admits");
    let mech = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    let validated = super::super::validate_for_ffi(&mech).expect("parameterless validates");
    let direct = mechanism_to_ffi(&validated).expect("direct conversion");
    // By-value field copies (packed-struct targets reject direct
    // references — same discipline as the `capture` stub above).
    let outer = direct.ck_mechanism();
    let (ptr, len) = (outer.pParameter, outer.ulParameterLen as u64);
    assert!(ptr.is_null());
    assert_eq!(len, 0);
    backend
        .call_init_with_mechanism(
            &admission,
            CkSessionHandle(7),
            OperationFamily::Digest,
            Some(sign_init_ok as InitStub),
            &validated,
            |function, mech| unsafe { function(7, mech, 9) },
        )
        .expect("stub Init succeeds");
    assert_eq!(CALLS.lock().expect("capture log").len(), 1);
}
