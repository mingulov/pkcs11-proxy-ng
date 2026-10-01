//! R20 (S2 §6/§12): sanitize-ON zero-call pins — the R12-deferred
//! half of the S2 §12 "sanitize ON zero-call / OFF one-call" backend FFI
//! pair. OFF/one-call lives in `r12_init_retention_tests.rs`
//! (`r12_off_one_call_flat_forwards` / `r12_off_one_call_null_forwards`);
//! this module pins the ON side: a rejectable parameter is rejected with
//! `PARAM_INVALID` and the provider stub observes ZERO calls.
//!
//! These pins drive `call_init_with_mechanism` directly behind a
//! handler-shaped sanitize gate using the SAME shared policy the server
//! handlers enforce
//! (`ValidatedMechanismParams::check_classic_sanitize_policy`), so a
//! policy drift fails this pin instead of silently passing. They need a
//! stub-backed `FfiBackend`, so each test carries
//! `#[cfg_attr(miri, ignore)]` (repo convention for `dlopen`-touching
//! tests).

use crate::ffi::{FfiBackend, OperationFamily};
use pkcs11_proxy_ng_types::shape_descriptors::{ABI_EXEMPT_FINGERPRINT, Operation, ParamAbi};
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
    // SAFETY: same live-`CK_MECHANISM` contract as the R12 capture stub;
    // fields copied by value (packed-struct targets reject direct field
    // references).
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

/// Registry listing `mech` as parameterless (S2 §4: Flat on a
/// parameterless-listed mechanism validates, then sanitize ON rejects).
fn registry_with_parameterless(mech: u64) -> MechanismRegistry {
    let mut parameterless = HashSet::new();
    parameterless.insert(mech);
    MechanismRegistry::from_parts(
        HashMap::new(),
        parameterless,
        HashSet::new(),
        pkcs11_proxy_ng_types::DiscoveryMode::Transparent,
        "r20-test".to_string(),
    )
}

/// Server-validated parameterless+Flat: validates (parameterless marker
/// carries arbitrary bytes to the cap), then sanitize ON must reject.
fn validated_parameterless_flat(mech_type: u64, bytes: &[u8]) -> ValidatedMechanismParams {
    let mech = CkMechanism {
        mechanism_type: CkMechanismType(mech_type),
        params: Some(CkMechanismParams::Flat(FlatParams {
            bytes: SecretBytes::copy_from_slice(bytes),
            declared_len: bytes.len() as u64,
            source_abi: Some(ParamAbi::Lp64NativeLe),
            fingerprint: ABI_EXEMPT_FINGERPRINT,
            version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
        })),
    };
    ValidatedMechanismParams::validate(
        &mech,
        &registry_with_parameterless(mech_type),
        Operation::General,
        ParamAbi::Lp64NativeLe,
        ParamAbi::Lp64NativeLe,
    )
    .expect("parameterless Flat validates")
}

/// Server-validated outer NULL (needs no descriptor).
fn validated_null(mech_type: u64, declared_len: u64) -> ValidatedMechanismParams {
    let mech = CkMechanism {
        mechanism_type: CkMechanismType(mech_type),
        params: Some(CkMechanismParams::Null {
            declared_len,
            version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
        }),
    };
    ValidatedMechanismParams::validate(
        &mech,
        &registry_with_parameterless(mech_type),
        Operation::General,
        ParamAbi::Lp64NativeLe,
        ParamAbi::Lp64NativeLe,
    )
    .expect("Null validates")
}

/// Stub-backed backend with an open lifecycle domain (R12 pattern: the
/// function list is all-`None`; stubs pass directly to the `call_*`
/// helpers).
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

/// R20 ON/zero-call pin, Flat row (pairs with R12's
/// `r12_off_one_call_flat_forwards`): sanitize ON + parameterless+Flat
/// → `PARAM_INVALID` (never `ARGUMENTS_BAD`) and ZERO provider calls.
#[test]
#[cfg_attr(miri, ignore)] // Miri: stub-backed FfiBackend needs dlopen
fn r20_on_zero_call_parameterless_flat_rejected() {
    let _guard = LOCK.lock().expect("test lock");
    CALLS.lock().expect("capture log").clear();
    let (backend, _tables) = test_backend();
    let admission = backend.lifecycle_domain.admit_ordinary().expect("open domain admits");
    let validated = validated_parameterless_flat(0x0000_1082, &[0xDE, 0xAD, 0xBE, 0xEF]);
    // Handler-shaped gate: sanitize first (shared policy), backend call
    // only when allowed.
    let result = match validated.check_classic_sanitize_policy(true) {
        Err(rv) => Err(rv),
        Ok(()) => backend
            .call_init_with_mechanism(
                &admission,
                CkSessionHandle(7),
                OperationFamily::Sign,
                Some(sign_init_ok as InitStub),
                &validated,
                |function, mech| unsafe { function(7, mech, 9) },
            )
            .map(|_| ()),
    };
    let rv = result.expect_err("ON must reject");
    assert_eq!(rv, CkRv::MECHANISM_PARAM_INVALID, "sanitizer RV");
    assert_ne!(rv, CkRv::ARGUMENTS_BAD, "never ARGUMENTS_BAD");
    assert!(
        CALLS.lock().expect("capture log").is_empty(),
        "ON/zero-call: the provider must observe zero calls"
    );
}

/// R20 ON/zero-call pin, NULL row (pairs with R12's
/// `r12_off_one_call_null_forwards`): sanitize ON + NULL/nonzero →
/// `PARAM_INVALID` and ZERO provider calls.
#[test]
#[cfg_attr(miri, ignore)] // Miri: stub-backed FfiBackend needs dlopen
fn r20_on_zero_call_null_nonzero_rejected() {
    let _guard = LOCK.lock().expect("test lock");
    CALLS.lock().expect("capture log").clear();
    let (backend, _tables) = test_backend();
    let admission = backend.lifecycle_domain.admit_ordinary().expect("open domain admits");
    let validated = validated_null(0x0000_1082, 12);
    // Handler-shaped gate: sanitize first (shared policy), backend call
    // only when allowed.
    let result = match validated.check_classic_sanitize_policy(true) {
        Err(rv) => Err(rv),
        Ok(()) => backend
            .call_init_with_mechanism(
                &admission,
                CkSessionHandle(7),
                OperationFamily::Sign,
                Some(sign_init_ok as InitStub),
                &validated,
                |function, mech| unsafe { function(7, mech, 9) },
            )
            .map(|_| ()),
    };
    let rv = result.expect_err("ON must reject");
    assert_eq!(rv, CkRv::MECHANISM_PARAM_INVALID, "sanitizer RV");
    assert_ne!(rv, CkRv::ARGUMENTS_BAD, "never ARGUMENTS_BAD");
    assert!(
        CALLS.lock().expect("capture log").is_empty(),
        "ON/zero-call: the provider must observe zero calls"
    );
}
