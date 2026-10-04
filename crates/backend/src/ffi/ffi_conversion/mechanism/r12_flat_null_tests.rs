//! R12 (S2 §6): backend Flat/Null FFI reconstruction pins.
//!
//! Pure-conversion half (Miri-clean: no `FfiBackend`, no `dlopen` — the
//! `FfiBackend`-level OFF/one-call + retention pins live in
//! `r12_init_retention_tests`, which needs a stub-backed backend and is
//! therefore outside the Miri scope, like the existing `dlopen`-touching
//! suites).

use super::super::{mechanism_to_ffi, validate_for_ffi};
use pkcs11_proxy_ng_types::shape_descriptors::{
    Operation, OperationContext, ParamAbi, ShapeResolver,
};
use pkcs11_proxy_ng_types::{
    CkMechanism, CkMechanismParams, CkMechanismType, CkObjectHandle, CkRv, FlatParams, IvParams,
    KipParams, MECHANISM_PARAMETER_TRANSPORT_VERSION, MechanismRegistry, PointerBytes, SecretBytes,
    ValidatedMechanismParams,
};
use std::collections::{HashMap, HashSet};

/// Registry binding `mech` to the byte-buffer `iv` shape (R9 test pattern):
/// the descriptor `validate` needs to grant Flat.
fn registry_with_iv_binding(mech: u64) -> MechanismRegistry {
    registry_with_bindings(&[("iv", mech)])
}

/// Multi-binding registry for nested tests (F1: outer and nested nodes
/// each need their own binding — one mech binds one shape).
fn registry_with_bindings(bindings: &[(&str, u64)]) -> MechanismRegistry {
    let mut shapes = HashMap::new();
    for (shape, mech) in bindings {
        shapes.insert(*mech, (*shape).to_string());
    }
    MechanismRegistry::from_parts(
        shapes,
        HashSet::new(),
        HashSet::new(),
        pkcs11_proxy_ng_types::DiscoveryMode::Transparent,
        "r12-test".to_string(),
    )
}

/// A Flat mechanism whose bytes/fingerprint the `iv` descriptor grants.
fn flat_mechanism(mech: u64, bytes: &[u8]) -> CkMechanism {
    let resolved = ShapeResolver::resolve(
        Some("iv"),
        OperationContext {
            mechanism: mech,
            operation: Operation::General,
            length: bytes.len() as u64,
        },
        ParamAbi::Lp64NativeLe,
    )
    .expect("iv descriptor resolves");
    CkMechanism {
        mechanism_type: CkMechanismType(mech),
        params: Some(CkMechanismParams::Flat(FlatParams {
            bytes: SecretBytes::copy_from_slice(bytes),
            declared_len: bytes.len() as u64,
            source_abi: Some(ParamAbi::Lp64NativeLe),
            fingerprint: resolved.fingerprint(ParamAbi::Lp64NativeLe),
            version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
        })),
    }
}

/// Validate like the post-R13 server would (real registry binding): the
/// full Flat path R13/R15/R23 exercise.
fn validated_flat(mech: &CkMechanism) -> ValidatedMechanismParams {
    ValidatedMechanismParams::validate(
        mech,
        &registry_with_iv_binding(mech.mechanism_type.0),
        Operation::General,
        ParamAbi::Lp64NativeLe,
        ParamAbi::Lp64NativeLe,
    )
    .expect("test Flat validates")
}

fn null_mechanism(declared_len: u64) -> CkMechanism {
    CkMechanism {
        mechanism_type: CkMechanismType(0x0000_1082),
        params: Some(CkMechanismParams::Null {
            declared_len,
            version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
        }),
    }
}

/// Copy the outer parameter pointer/length to locals. By value: on
/// packed-struct targets (Windows LLP64) referencing the fields directly
/// is rejected, so every assertion below goes through these locals.
fn outer_param(ffi: &super::FfiMechanism) -> (*mut std::ffi::c_void, u64) {
    let outer = ffi.ck_mechanism();
    (outer.pParameter, outer.ulParameterLen as u64)
}

/// Read back exactly what the provider would read: `ulParameterLen` bytes
/// at `pParameter`. Panics on NULL (callers assert presence first).
fn provider_view(ffi: &super::FfiMechanism) -> Vec<u8> {
    let (ptr, len) = outer_param(ffi);
    assert!(!ptr.is_null(), "provider view needs a non-NULL parameter");
    // SAFETY: `pParameter` points into live FFI backing holding at least
    // `ulParameterLen` bytes; the copy carries no provenance.
    unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize).to_vec() }
}

/// Simulate a provider write into the parameter extent (for the output
/// suppression pins): overwrites the live backing in place.
fn provider_overwrite(ffi: &mut super::FfiMechanism, fill: u8) {
    let (ptr, len) = outer_param(ffi);
    assert!(!ptr.is_null(), "overwrite needs a non-NULL parameter");
    // SAFETY: same live-backing argument as `provider_view`, bytewise.
    unsafe { std::ptr::write_bytes(ptr as *mut u8, fill, len as usize) };
}

/// Validated Flat forwards verbatim — non-NULL pointer, `ulParameterLen`
/// exactly `declared_len`, exact bytes, no client address bits.
#[test]
fn flat_forwards_verbatim() {
    let bytes = [0xDE, 0xAD, 0xBE];
    let ffi = mechanism_to_ffi(&validated_flat(&flat_mechanism(0x0000_1082, &bytes)))
        .expect("validated Flat reconstructs");
    let (ptr, len) = outer_param(&ffi);
    assert!(!ptr.is_null(), "Flat pointer must be non-NULL");
    assert_eq!(len, bytes.len() as u64);
    assert_eq!(provider_view(&ffi), bytes.as_slice());
    // No client address bits: the FFI pointer is freshly mapped storage.
    assert_ne!(ptr as *const u8, bytes.as_ptr());
}

/// Null forwards as NULL + narrowed length (no descriptor needed, S2 §6
/// RV table) — including through the backend-local gate, which needs no
/// registry for Null.
#[test]
fn null_forwards_null_with_narrowed_len() {
    let validated =
        validate_for_ffi(&null_mechanism(12)).expect("Null validates without a registry");
    let ffi = mechanism_to_ffi(&validated).expect("Null reconstructs");
    let (ptr, len) = outer_param(&ffi);
    assert!(ptr.is_null(), "Null must materialize NULL");
    assert_eq!(len, 12);
}

/// Empty Flat is still a non-NULL extent of length zero (S2 §6: pointer
/// non-NULL even at length zero).
#[test]
fn flat_empty_is_non_null_zero() {
    let ffi = mechanism_to_ffi(&validated_flat(&flat_mechanism(0x0000_1082, &[])))
        .expect("empty Flat reconstructs");
    let (ptr, len) = outer_param(&ffi);
    assert!(!ptr.is_null(), "empty Flat must stay non-NULL");
    assert_eq!(len, 0);
}

/// Legacy Raw stays rejected (green before, during, and after R12 — the
/// rejecting layer moved from the FFI match arm to the validation gate,
/// the RV stays `MECHANISM_PARAM_INVALID`; the FFI arm itself stays as
/// unreachable defense-in-depth).
#[test]
fn raw_stays_rejected() {
    let mech = CkMechanism {
        mechanism_type: CkMechanismType(0x0000_1082),
        params: Some(CkMechanismParams::Raw(pkcs11_proxy_ng_types::RawMechanismParams {
            data: SecretBytes::copy_from_slice(&[0x01, 0x02]),
        })),
    };
    assert_eq!(validate_for_ffi(&mech).err(), Some(CkRv::MECHANISM_PARAM_INVALID));
}

/// The backend-local gate denies Flat ALWAYS — even a shape the real
/// registry would grant — because it owns no registry to bind against.
/// Guessing (e.g. the embedded default) would bypass operator exclusion.
/// Server-validated Flat arrives post-R13 via the newtype-taking entries.
#[test]
fn funnel_flat_always_denied() {
    let mech = flat_mechanism(0x0000_1082, &[0xA5; 8]);
    // Sanity: the same value validates under a bound registry ...
    let _ = validated_flat(&mech);
    // ... but the registry-less backend gate fails closed.
    assert_eq!(validate_for_ffi(&mech).err(), Some(CkRv::MECHANISM_PARAM_INVALID));
}

/// Parameterless mechanisms pass the backend-local gate identically:
/// pre-R12 behavior preserved exactly on the FFI path. (F1: typed
/// params need bindings, so the old typed half of this pin moved to
/// `funnel_typed_needs_binding`.)
#[test]
fn funnel_typed_and_none_passthrough() {
    let bare = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    let ffi = mechanism_to_ffi(&validate_for_ffi(&bare).expect("None validates"))
        .expect("parameterless reconstructs");
    let (ptr, len) = outer_param(&ffi);
    assert!(ptr.is_null());
    assert_eq!(len, 0);
}

/// F1: typed params are rejected by the registry-less backstop (no
/// binding exists to authorize them); the same pair validates against
/// a registry binding it, and reconstructs identically.
#[test]
fn funnel_typed_needs_binding() {
    let typed = CkMechanism {
        mechanism_type: CkMechanismType::AES_CBC,
        params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0x11; 16] })),
    };
    assert_eq!(
        validate_for_ffi(&typed).err(),
        Some(CkRv::MECHANISM_PARAM_INVALID),
        "unbound typed must fail closed at the backstop"
    );
    let validated = ValidatedMechanismParams::validate(
        &typed,
        &registry_with_iv_binding(CkMechanismType::AES_CBC.0),
        Operation::General,
        ParamAbi::Lp64NativeLe,
        ParamAbi::Lp64NativeLe,
    )
    .expect("bound typed validates");
    let ffi = mechanism_to_ffi(&validated).expect("typed reconstructs");
    assert_eq!(provider_view(&ffi), vec![0x11; 16]);
}

/// Narrowing failure (S2 §6 RV table): a wire u64 declared length the
/// backend `CK_ULONG` cannot represent fails loudly with
/// `FUNCTION_FAILED`, never truncates. Host-independent: driven by the
/// `backend_abi` parameter, not the test host width.
#[test]
fn null_unnarrowable_is_function_failed() {
    let mech = null_mechanism(u64::MAX);
    let registry = registry_with_iv_binding(mech.mechanism_type.0);
    let result = ValidatedMechanismParams::validate(
        &mech,
        &registry,
        Operation::General,
        ParamAbi::Lp64NativeLe,
        ParamAbi::Ilp32NativeLe,
    );
    assert_eq!(result.err(), Some(CkRv::FUNCTION_FAILED));
    // And a narrowable length under the same narrow ABI validates.
    let mech = null_mechanism(0xFFFF_FFFF);
    let result = ValidatedMechanismParams::validate(
        &mech,
        &registry_with_iv_binding(mech.mechanism_type.0),
        Operation::General,
        ParamAbi::Lp64NativeLe,
        ParamAbi::Ilp32NativeLe,
    );
    assert!(result.is_ok(), "u32-range Null must narrow to ILP32");
}

/// R9 carry (Flat+ILP32 narrowing test): Flat validated for a narrow
/// backend ABI reconstructs with `ulParameterLen` exactly `declared_len`.
#[test]
fn flat_ilp32_narrowing_exact() {
    let mech = flat_mechanism(0x0000_1082, &[0xA5; 24]);
    let validated = ValidatedMechanismParams::validate(
        &mech,
        &registry_with_iv_binding(mech.mechanism_type.0),
        Operation::General,
        ParamAbi::Lp64NativeLe,
        ParamAbi::Ilp32NativeLe,
    )
    .expect("Flat validates for a narrow backend ABI");
    let ffi = mechanism_to_ffi(&validated).expect("ILP32-validated Flat reconstructs");
    let (_, len) = outer_param(&ffi);
    assert_eq!(len, 24);
    assert_eq!(provider_view(&ffi), vec![0xA5; 24]);
}

/// Nested Null converts (uniform rule: NULL + narrowed length needs no
/// descriptor at any depth). New in R12 — pre-R12 every nested v1 value
/// was rejected alongside Flat. (F1: the outer KIP validates against a
/// registry binding its own pair; the nested Null needs no binding.)
#[test]
fn nested_null_converts() {
    let mech = CkMechanism {
        mechanism_type: CkMechanismType::RSA_PKCS,
        params: Some(CkMechanismParams::Kip(KipParams {
            mechanism: Some(Box::new(null_mechanism(7))),
            key_handle: CkObjectHandle(0),
            seed_presence: PointerBytes::present_copy(&[]),
        })),
    };
    let validated = ValidatedMechanismParams::validate(
        &mech,
        &registry_with_bindings(&[("kip", CkMechanismType::RSA_PKCS.0)]),
        Operation::General,
        ParamAbi::Lp64NativeLe,
        ParamAbi::Lp64NativeLe,
    )
    .expect("KIP validates");
    assert!(mechanism_to_ffi(&validated).is_ok(), "nested Null must convert");
}

/// Nested Flat stays rejected at descent unless the request's bindings
/// grant the nested mechanism (F1+F6: the nested node re-validates
/// against the carried snapshot — here the nested 0x1082 is unbound,
/// so no binding, no bypass). Nested Raw stays rejected on every path.
/// Request-validated outers with a bound nested mech accept eligible
/// nested Flat (pinned by the F6 test below).
#[test]
fn nested_flat_and_raw_rejected() {
    for (name, nested) in [
        ("Flat", flat_mechanism(0x0000_1082, &[0xA5; 4])),
        (
            "Raw",
            CkMechanism {
                mechanism_type: CkMechanismType(0x0000_1082),
                params: Some(CkMechanismParams::Raw(pkcs11_proxy_ng_types::RawMechanismParams {
                    data: SecretBytes::copy_from_slice(&[0x01]),
                })),
            },
        ),
    ] {
        let mech = CkMechanism {
            mechanism_type: CkMechanismType::RSA_PKCS,
            params: Some(CkMechanismParams::Kip(KipParams {
                mechanism: Some(Box::new(nested)),
                key_handle: CkObjectHandle(0),
                seed_presence: PointerBytes::present_copy(&[]),
            })),
        };
        // F1: the outer KIP validates against its own binding; the
        // nested node is unbound in this snapshot.
        let validated = ValidatedMechanismParams::validate(
            &mech,
            &registry_with_bindings(&[("kip", CkMechanismType::RSA_PKCS.0)]),
            Operation::General,
            ParamAbi::Lp64NativeLe,
            ParamAbi::Lp64NativeLe,
        )
        .expect("outer KIP validates");
        assert_eq!(
            mechanism_to_ffi(&validated).err(),
            Some(CkRv::MECHANISM_PARAM_INVALID),
            "nested {name} must stay rejected"
        );
    }
}

/// Nested Flat eligible under the request registry converts (F6): the
/// outer KIP is validated against the request snapshot, and descent
/// reuses that snapshot — the empty backstop registry only governs the
/// registry-less `validate_for_ffi` funnel (pinned above). The nested
/// reconstruction and its backing are retained through descent: the
/// inner `CK_MECHANISM` is readable via `pMechanism` with verbatim
/// bytes.
#[test]
fn nested_flat_eligible_under_request_registry_converts() {
    let nested = flat_mechanism(0x0000_1082, &[0xA5; 4]);
    let mech = CkMechanism {
        mechanism_type: CkMechanismType::RSA_PKCS,
        params: Some(CkMechanismParams::Kip(KipParams {
            mechanism: Some(Box::new(nested)),
            key_handle: CkObjectHandle(0),
            seed_presence: PointerBytes::present_copy(&[]),
        })),
    };
    // Like the post-R13 server: validate the outer node against the
    // request's registry snapshot (F1: binding both the outer KIP pair
    // and the nested mechanism).
    let validated = ValidatedMechanismParams::validate(
        &mech,
        &registry_with_bindings(&[("kip", CkMechanismType::RSA_PKCS.0), ("iv", 0x0000_1082)]),
        Operation::General,
        ParamAbi::Lp64NativeLe,
        ParamAbi::Lp64NativeLe,
    )
    .expect("outer KIP validates against request registry");
    let ffi = mechanism_to_ffi(&validated).expect("nested eligible Flat must convert");
    // Retained reconstruction: outer -> CK_KIP_PARAMS -> pMechanism ->
    // inner CK_MECHANISM with the verbatim Flat bytes.
    let outer = ffi.ck_mechanism();
    assert!(!outer.pParameter.is_null(), "KIP params must be present");
    // SAFETY: `pParameter` points at the live `CK_KIP_PARAMS` box.
    let kip: cryptoki_sys::CK_KIP_PARAMS =
        unsafe { (outer.pParameter as *const cryptoki_sys::CK_KIP_PARAMS).read_unaligned() };
    assert!(!kip.pMechanism.is_null(), "nested mechanism pointer must be live");
    // SAFETY: `pMechanism` designates the live nested `CK_MECHANISM`
    // retained in the KIP backing.
    let inner: cryptoki_sys::CK_MECHANISM = unsafe { kip.pMechanism.read_unaligned() };
    assert_eq!(inner.mechanism as u64, 0x0000_1082, "nested mechanism id");
    assert!(!inner.pParameter.is_null(), "nested Flat extent must be non-NULL");
    assert_eq!(inner.ulParameterLen as u64, 4, "nested declared length");
    // SAFETY: the nested extent holds exactly `ulParameterLen` bytes.
    let bytes = unsafe {
        std::slice::from_raw_parts(inner.pParameter as *const u8, inner.ulParameterLen as usize)
            .to_vec()
    };
    assert_eq!(bytes, vec![0xA5; 4], "nested Flat bytes verbatim");
}

/// Nested Flat validates under the carried ABIs (NF2): a Windows
/// RSA-PSS struct-prefix Flat nested in KIP converts when the outer was
/// validated under LLP64-packed — descent reuses the actual ABIs, never
/// infers ILP32 from the 4-byte `CK_ULONG` width (word width alone
/// cannot distinguish ILP32 from LLP64-packed).
#[test]
fn nested_flat_prefix_validates_under_carried_windows_abi() {
    let win = ParamAbi::Llp64Packed1Le;
    let mech = CkMechanismType::RSA_PKCS_PSS.0;
    let resolved = ShapeResolver::resolve(
        Some("rsa_pss"),
        OperationContext { mechanism: mech, operation: Operation::General, length: 1 },
        win,
    )
    .expect("rsa_pss descriptor resolves under Windows ABI");
    let nested = CkMechanism {
        mechanism_type: CkMechanismType(mech),
        params: Some(CkMechanismParams::Flat(FlatParams {
            bytes: SecretBytes::copy_from_slice(&[0x01]),
            declared_len: 1,
            source_abi: Some(win),
            fingerprint: resolved.fingerprint(win),
            version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
        })),
    };
    let outer = CkMechanism {
        mechanism_type: CkMechanismType::RSA_PKCS,
        params: Some(CkMechanismParams::Kip(KipParams {
            mechanism: Some(Box::new(nested)),
            key_handle: CkObjectHandle(0),
            seed_presence: PointerBytes::present_copy(&[]),
        })),
    };
    // Like the post-R13 server on a Windows edge: the outer node is
    // validated under the actual (LLP64-packed) ABIs.
    let validated = ValidatedMechanismParams::validate(
        &outer,
        &registry_with_bindings(&[("kip", CkMechanismType::RSA_PKCS.0), ("rsa_pss", mech)]),
        Operation::General,
        win,
        win,
    )
    .expect("outer KIP validates");
    let ffi = mechanism_to_ffi(&validated)
        .expect("Windows nested prefix must convert under the carried ABI");
    let outer_ffi = ffi.ck_mechanism();
    assert!(!outer_ffi.pParameter.is_null(), "KIP params must be present");
    // SAFETY: `pParameter` points at the live `CK_KIP_PARAMS` box.
    let kip: cryptoki_sys::CK_KIP_PARAMS =
        unsafe { (outer_ffi.pParameter as *const cryptoki_sys::CK_KIP_PARAMS).read_unaligned() };
    assert!(!kip.pMechanism.is_null(), "nested mechanism pointer must be live");
    // SAFETY: `pMechanism` designates the live nested `CK_MECHANISM`
    // retained in the KIP backing.
    let inner: cryptoki_sys::CK_MECHANISM = unsafe { kip.pMechanism.read_unaligned() };
    assert_eq!(inner.mechanism as u64, mech, "nested mechanism id");
    assert!(!inner.pParameter.is_null(), "nested Flat extent must be non-NULL");
    assert_eq!(inner.ulParameterLen as u64, 1, "nested declared length");
    // SAFETY: the nested extent holds exactly `ulParameterLen` bytes.
    let bytes = unsafe {
        std::slice::from_raw_parts(inner.pParameter as *const u8, inner.ulParameterLen as usize)
            .to_vec()
    };
    assert_eq!(bytes, vec![0x01], "nested Flat bytes verbatim");
}

/// Flat output effects, decided (S2 §6): native writes into Flat backing
/// are NOT returned — `output_params()` yields `None` even after the
/// provider mutates every extent byte, and the equality probe agrees.
#[test]
fn flat_output_suppressed() {
    let mut ffi = mechanism_to_ffi(&validated_flat(&flat_mechanism(0x0000_1082, &[0x11; 8])))
        .expect("Flat reconstructs");
    assert_eq!(ffi.output_params(), None, "unmutated Flat has no output params");
    assert!(ffi.output_params_equal(&None));
    provider_overwrite(&mut ffi, 0xEE);
    assert_eq!(provider_view(&ffi), vec![0xEE; 8], "mutation landed in backing");
    assert_eq!(ffi.output_params(), None, "mutated Flat still has no output params");
    assert!(ffi.output_params_equal(&None));
    assert!(!ffi.output_params_equal(&Some(CkMechanismParams::Iv(IvParams { iv: vec![] }))));
}

/// Null (backed by `None` like `no_param`) likewise yields no output.
#[test]
fn null_output_is_none() {
    let validated = validate_for_ffi(&null_mechanism(5)).expect("Null validates");
    let ffi = mechanism_to_ffi(&validated).expect("Null reconstructs");
    assert_eq!(ffi.output_params(), None);
    assert!(ffi.output_params_equal(&None));
}

/// `no_param` still hardcodes zero — `with_null_param` is the only
/// NULL-with-length constructor, and the parameterless path is untouched.
#[test]
fn no_param_still_zero() {
    let bare = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    let validated = validate_for_ffi(&bare).expect("parameterless validates");
    let ffi = mechanism_to_ffi(&validated).expect("parameterless reconstructs");
    let (ptr, len) = outer_param(&ffi);
    assert!(ptr.is_null());
    assert_eq!(len, 0);
}
