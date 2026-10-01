//! Daemon transport validation entry point (S2 §6; R9, wired by R13).
//!
//! [`validate_mechanism_transport`] is the always-on gate every classic
//! handler calls between per-principal authorization and handle remapping.
//! The checks themselves live in
//! [`ValidatedMechanismParams::validate`](pkcs11_proxy_ng_types::ValidatedMechanismParams)
//! (S2 ownership: the opaque type + validating constructor live in
//! `types`, which both edges depend on); this module adapts the
//! server-side call context (registry snapshot, operation, ABIs) and pins
//! the S2 §6 RV table end to end through the server entry point.
//!
//! Handler order (exact, S2 §6): session/key resolution → `parse_mechanism`
//! → [`check_operator_exclusion`] → `mechanism_permitted` → this gate →
//! `remap_mechanism_handles` → [`sanitize_mechanism_input`] → backend call.
//! Every stage shares the request's single [`current_registry_snapshot`].

use pkcs11_proxy_ng_types::shape_descriptors::{Operation, ParamAbi};
use pkcs11_proxy_ng_types::{
    CkMechanism, CkMechanismParams, CkMechanismType, CkRv, MechanismRegistry,
    ValidatedMechanismParams,
};

/// Acquire this request's single registry snapshot (S2 §6: one snapshot
/// per request feeds exclusion, descriptor resolution, and validation —
/// SIGHUP safety). Fail-closed `DEVICE_ERROR` on a poisoned lock (the
/// pre-R13 message-path poison RV, now uniform across handlers).
pub(super) fn current_registry_snapshot(
    ctx: &super::HandlerContext,
) -> Result<std::sync::Arc<MechanismRegistry>, CkRv> {
    ctx.mechanism_registry_source.current_registry().map_err(|_| CkRv::DEVICE_ERROR)
}

/// Operator exclusion (S2 §6): an excluded mechanism is rejected with
/// `MECHANISM_INVALID` BEFORE per-principal authorization. (Transport
/// validation re-checks exclusion from the same snapshot; that inner check
/// is unreachable on this path but keeps the types-layer gate total.)
pub(super) fn check_operator_exclusion(
    registry: &MechanismRegistry,
    mech_type: CkMechanismType,
) -> Result<(), CkRv> {
    if registry.excluded_view().contains(&mech_type.0) {
        return Err(CkRv::MECHANISM_INVALID);
    }
    Ok(())
}

/// The ABIs transport validation decides under (R13): local is this
/// daemon's compiled native ABI; backend is the in-process provider's
/// `CK_ULONG` width (the backend FFI runs in this process, so the
/// daemon's compiled width is the backend's width).
///
/// Big-endian targets (`ParamAbi::native() == None`): v1 layout ABIs are
/// all little-endian, so no Flat image can match — the width-derived
/// fallback below is width-correct for Null narrowing and typed/None
/// paths, and [`validate_mechanism_transport`] rejects Flat outright
/// there (fail closed; BE daemons are outside the supported matrix).
pub(super) fn daemon_validation_abis() -> (ParamAbi, ParamAbi) {
    let width_abi = if pkcs11_proxy_ng_backend::host_abi::host_ulong_size() >= 8 {
        ParamAbi::Lp64NativeLe
    } else {
        ParamAbi::Ilp32NativeLe
    };
    (ParamAbi::native().unwrap_or(width_abi), width_abi)
}

/// Validate one request's mechanism parameters against the daemon's
/// transport contract (S2 §6, always on).
///
/// - `registry` is the [`current_registry_snapshot`] for this request
///   (SIGHUP safety: one snapshot feeds exclusion, descriptor resolution,
///   and validation).
/// - `operation` is the call-site operation context (`WrapKey` selects the
///   GCM/CCM wrap layouts by operation+length; every other call passes
///   `General`).
/// - `local_abi` is this daemon's native ABI; `backend_abi` supplies the
///   backend `CK_ULONG` width for declared-length narrowing.
///
/// Returns the validated newtype R12's FFI boundary accepts. RV mapping
/// is exact per S2 §6 (see
/// [`ValidatedMechanismParams::validate`](pkcs11_proxy_ng_types::ValidatedMechanismParams::validate));
/// the tests below pin every row through this entry point.
pub fn validate_mechanism_transport(
    registry: &MechanismRegistry,
    mechanism: &CkMechanism,
    operation: Operation,
    local_abi: ParamAbi,
    backend_abi: ParamAbi,
) -> Result<ValidatedMechanismParams, CkRv> {
    // Big-endian fail-closed (see `daemon_validation_abis`): v1 ABIs are
    // all little-endian, so a BE daemon must never accept a Flat image.
    if ParamAbi::native().is_none() && matches!(mechanism.params, Some(CkMechanismParams::Flat(_)))
    {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    ValidatedMechanismParams::validate(mechanism, registry, operation, local_abi, backend_abi)
}

/// Optional classic sanitizer — the S2 §6 policy layer (R20).
///
/// Runs between `remap_mechanism_handles` and the backend call at every
/// R13 site (the wrap funnel sanitizes once inside `prepare_wrap` for
/// all four wrap callers). Pure policy over the validated newtype: the
/// matrix itself is
/// [`ValidatedMechanismParams::check_classic_sanitize_policy`](pkcs11_proxy_ng_types::ValidatedMechanismParams),
/// shared with the backend's ON/zero-call pin so both layers enforce one
/// implementation.
///
/// - `sanitize` is the request's `ctx.sanitize_inputs` toggle (ADR-0010,
///   default false). OFF passes the newtype through untouched (bit-for-bit
///   with the pre-R20 path); ON applies the S2 §6 matrix.
/// - Every sanitizer rejection is `PARAM_INVALID` — never `ARGUMENTS_BAD`
///   (that RV stays with the pre-existing whole-mechanism/data-pointer
///   gates, e.g. the whole-NULL-mechanism check at each handler head).
/// - Legacy `Raw` never reaches this function: transport validation
///   rejects it always-on, under both toggle settings (the policy keeps a
///   fail-closed `Raw` arm for defense in depth).
pub fn sanitize_mechanism_input(
    sanitize: bool,
    validated: ValidatedMechanismParams,
) -> Result<ValidatedMechanismParams, CkRv> {
    validated.check_classic_sanitize_policy(sanitize)?;
    Ok(validated)
}

#[cfg(test)]
mod transport_validation_tests {
    use super::*;
    use pkcs11_proxy_ng_types::mechanism_registry::DiscoveryMode;
    use pkcs11_proxy_ng_types::shape_descriptors::{
        ABI_EXEMPT_FINGERPRINT, FlatDecision, FlatDenyReason, OperationContext, ShapeResolver,
        decide_flat_for_registry,
    };
    use pkcs11_proxy_ng_types::{
        CkMechanismParams, CkMechanismType, FlatParams, GcmParams, IvParams,
        MECHANISM_PARAMETER_TRANSPORT_VERSION, PointerBytes, RawMechanismParams, SecretBytes,
    };
    use std::collections::HashMap;

    const AES_CBC: u64 = 0x0000_1082;
    const AES_GCM: u64 = 0x0000_1087;
    const UNKNOWN_MECH: u64 = 0x0000_9999;
    const VENDOR_MECH: u64 = 0x8000_0001;
    const LP64: ParamAbi = ParamAbi::Lp64NativeLe;
    const ILP32: ParamAbi = ParamAbi::Ilp32NativeLe;

    fn registry(
        bindings: &[(&str, u64)],
        parameterless: &[u64],
        excluded: &[u64],
    ) -> MechanismRegistry {
        let shapes: HashMap<u64, String> =
            bindings.iter().map(|(shape, mech)| (*mech, shape.to_string())).collect();
        MechanismRegistry::from_parts(
            shapes,
            parameterless.iter().copied().collect(),
            excluded.iter().copied().collect(),
            DiscoveryMode::Transparent,
            "test".to_string(),
        )
    }

    fn validate(
        registry: &MechanismRegistry,
        mechanism: &CkMechanism,
    ) -> Result<ValidatedMechanismParams, CkRv> {
        validate_mechanism_transport(registry, mechanism, Operation::General, LP64, LP64)
    }

    fn expected_fingerprint(shape: &str, mech: u64, len: u64) -> u64 {
        ShapeResolver::resolve(
            Some(shape),
            OperationContext { mechanism: mech, operation: Operation::General, length: len },
            LP64,
        )
        .unwrap()
        .fingerprint(LP64)
    }

    fn flat_params(len: usize, abi: Option<ParamAbi>, fingerprint: u64) -> FlatParams {
        FlatParams {
            bytes: SecretBytes::copy_from_slice(&vec![0xA5u8; len]),
            declared_len: len as u64,
            source_abi: abi,
            fingerprint,
            version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
        }
    }

    fn flat_mech(mech: u64, shape: &str, len: usize, peer_abi: ParamAbi) -> CkMechanism {
        CkMechanism {
            mechanism_type: CkMechanismType(mech),
            params: Some(CkMechanismParams::Flat(flat_params(
                len,
                Some(peer_abi),
                expected_fingerprint(shape, mech, len as u64),
            ))),
        }
    }

    fn null_mech(mech: u64, declared_len: u64) -> CkMechanism {
        CkMechanism {
            mechanism_type: CkMechanismType(mech),
            params: Some(CkMechanismParams::Null {
                declared_len,
                version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
            }),
        }
    }

    /// Assert the R7 denial reason behind a PARAM_INVALID, so each RV row
    /// below pins its intended check (the RV mapping itself erases reasons).
    fn assert_denied_as(
        registry: &MechanismRegistry,
        mech: u64,
        operation: Operation,
        len: u64,
        fingerprint: u64,
        peer_abi: ParamAbi,
        expected: FlatDenyReason,
    ) {
        assert_eq!(
            decide_flat_for_registry(registry, mech, operation, len, fingerprint, peer_abi, LP64),
            FlatDecision::Denied(expected),
        );
    }

    #[test]
    fn exclusion_reports_mechanism_invalid() {
        let reg = registry(&[], &[], &[AES_CBC]);
        let typed = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Iv(IvParams { iv: vec![1, 2, 3] })),
        };
        let none = CkMechanism { mechanism_type: CkMechanismType(AES_CBC), params: None };
        let flat = flat_mech(AES_CBC, "iv", 16, LP64);
        for (name, mechanism) in [("typed", typed), ("none", none), ("flat", flat)] {
            assert_eq!(
                validate(&reg, &mechanism),
                Err(CkRv::MECHANISM_INVALID),
                "{name} on an excluded mechanism",
            );
        }
    }

    #[test]
    fn unknown_without_params_forwards() {
        let reg = registry(&[], &[], &[]);
        let mechanism = CkMechanism { mechanism_type: CkMechanismType(UNKNOWN_MECH), params: None };
        validate(&reg, &mechanism).unwrap();
    }

    #[test]
    fn unknown_with_flat_and_no_descriptor_is_param_invalid() {
        let reg = registry(&[], &[], &[]);
        let mechanism = flat_mech(UNKNOWN_MECH, "iv", 16, LP64);
        assert_eq!(validate(&reg, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
        assert_denied_as(
            &reg,
            UNKNOWN_MECH,
            Operation::General,
            16,
            ABI_EXEMPT_FINGERPRINT,
            LP64,
            FlatDenyReason::UnknownShape,
        );
    }

    #[test]
    fn unknown_with_null_forwards_without_descriptor() {
        let reg = registry(&[], &[], &[]);
        validate(&reg, &null_mech(UNKNOWN_MECH, 41)).unwrap();
    }

    #[test]
    fn newer_version_is_function_not_supported() {
        let reg = registry(&[("iv", AES_CBC)], &[], &[]);
        let mut flat = flat_mech(AES_CBC, "iv", 16, LP64);
        let CkMechanismParams::Flat(p) = flat.params.as_mut().unwrap() else {
            panic!("test setup must build Flat")
        };
        p.version = 2;
        assert_eq!(validate(&reg, &flat), Err(CkRv::FUNCTION_NOT_SUPPORTED));
        let null = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Null { declared_len: 0, version: u32::MAX }),
        };
        assert_eq!(validate(&reg, &null), Err(CkRv::FUNCTION_NOT_SUPPORTED));
    }

    #[test]
    fn legacy_raw_rejected() {
        let reg = registry(&[("iv", AES_CBC)], &[], &[]);
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Raw(RawMechanismParams {
                data: SecretBytes::copy_from_slice(b"AB"),
            })),
        };
        assert_eq!(validate(&reg, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
    }

    #[test]
    fn nested_or_output_flat_is_param_invalid() {
        let reg = registry(&[("otp", AES_CBC)], &[], &[]);
        let mechanism = flat_mech(AES_CBC, "otp", 8, LP64);
        assert_eq!(validate(&reg, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
        assert_denied_as(
            &reg,
            AES_CBC,
            Operation::General,
            8,
            expected_fingerprint("otp", AES_CBC, 8),
            LP64,
            FlatDenyReason::NestedOrOutput,
        );
    }

    #[test]
    fn vendor_flat_without_allowlist_is_param_invalid() {
        let reg = registry(&[], &[], &[]);
        let mechanism = flat_mech(VENDOR_MECH, "iv", 16, LP64);
        assert_eq!(validate(&reg, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
        assert_denied_as(
            &reg,
            VENDOR_MECH,
            Operation::General,
            16,
            ABI_EXEMPT_FINGERPRINT,
            LP64,
            FlatDenyReason::VendorWithoutAllowlist,
        );
    }

    #[test]
    fn full_native_image_is_param_invalid() {
        // rsa_pss is scalar [Ulong × 3]: LP64 native image is exactly 24.
        let reg = registry(&[("rsa_pss", AES_CBC)], &[], &[]);
        let mechanism = flat_mech(AES_CBC, "rsa_pss", 24, LP64);
        assert_eq!(validate(&reg, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
        assert_denied_as(
            &reg,
            AES_CBC,
            Operation::General,
            24,
            expected_fingerprint("rsa_pss", AES_CBC, 24),
            LP64,
            FlatDenyReason::FullNativeImage,
        );
    }

    #[test]
    fn fingerprint_mismatch_is_param_invalid() {
        let reg = registry(&[("aes_cbc_encrypt_data", AES_CBC)], &[], &[]);
        let good_fp = expected_fingerprint("aes_cbc_encrypt_data", AES_CBC, 8);
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Flat(flat_params(
                8,
                Some(LP64),
                good_fp.wrapping_add(1),
            ))),
        };
        assert_eq!(validate(&reg, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
        assert_denied_as(
            &reg,
            AES_CBC,
            Operation::General,
            8,
            good_fp.wrapping_add(1),
            LP64,
            FlatDenyReason::FingerprintMismatch { expected: good_fp, got: good_fp.wrapping_add(1) },
        );
    }

    #[test]
    fn contradictory_metadata_is_param_invalid() {
        let reg = registry(&[("iv", AES_CBC)], &[], &[]);
        // v1-only member with a legacy stamp.
        let mut flat = flat_mech(AES_CBC, "iv", 16, LP64);
        let CkMechanismParams::Flat(p) = flat.params.as_mut().unwrap() else {
            panic!("test setup must build Flat")
        };
        p.version = 0;
        assert_eq!(validate(&reg, &flat), Err(CkRv::MECHANISM_PARAM_INVALID));
        // Declared length disagreeing with the byte count.
        let mut flat = flat_mech(AES_CBC, "iv", 16, LP64);
        let CkMechanismParams::Flat(p) = flat.params.as_mut().unwrap() else {
            panic!("test setup must build Flat")
        };
        p.declared_len = 15;
        assert_eq!(validate(&reg, &flat), Err(CkRv::MECHANISM_PARAM_INVALID));
        // Flat without a known source ABI.
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Flat(flat_params(16, None, ABI_EXEMPT_FINGERPRINT))),
        };
        assert_eq!(validate(&reg, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
    }

    #[test]
    fn unknown_descriptor_binding_is_param_invalid() {
        let reg = registry(&[("no_such_shape", AES_CBC)], &[], &[]);
        let mechanism = flat_mech(AES_CBC, "iv", 16, LP64);
        assert_eq!(validate(&reg, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
        assert_denied_as(
            &reg,
            AES_CBC,
            Operation::General,
            16,
            ABI_EXEMPT_FINGERPRINT,
            LP64,
            FlatDenyReason::UnknownShape,
        );
    }

    #[test]
    fn abi_mismatch_is_param_invalid() {
        let reg = registry(&[("aes_cbc_encrypt_data", AES_CBC)], &[], &[]);
        let mechanism = flat_mech(AES_CBC, "aes_cbc_encrypt_data", 8, ILP32);
        assert_eq!(validate(&reg, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
        assert_denied_as(
            &reg,
            AES_CBC,
            Operation::General,
            8,
            expected_fingerprint("aes_cbc_encrypt_data", AES_CBC, 8),
            ILP32,
            FlatDenyReason::AbiMismatch { expected: LP64, got: ILP32 },
        );
    }

    #[test]
    fn cap_violation_is_param_invalid() {
        let reg = registry(&[("iv", AES_CBC)], &[], &[]);
        let len = 64 * 1024 + 1;
        let mechanism = flat_mech(AES_CBC, "iv", len, LP64);
        assert_eq!(validate(&reg, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
        assert_denied_as(
            &reg,
            AES_CBC,
            Operation::General,
            len as u64,
            ABI_EXEMPT_FINGERPRINT,
            LP64,
            FlatDenyReason::OverCap,
        );
        // Boundary: exactly 64 KiB still validates.
        validate(&reg, &flat_mech(AES_CBC, "iv", 64 * 1024, LP64)).unwrap();
    }

    #[test]
    fn prefix_past_first_unsafe_offset_is_param_invalid() {
        // aes_cbc_encrypt_data = [Bytes(16), Pointer, Ulong]: first unsafe
        // offset is 16 under LP64, so 16 validates and 17 does not.
        let reg = registry(&[("aes_cbc_encrypt_data", AES_CBC)], &[], &[]);
        validate(&reg, &flat_mech(AES_CBC, "aes_cbc_encrypt_data", 16, LP64)).unwrap();
        let mechanism = flat_mech(AES_CBC, "aes_cbc_encrypt_data", 17, LP64);
        assert_eq!(validate(&reg, &mechanism), Err(CkRv::MECHANISM_PARAM_INVALID));
        assert_denied_as(
            &reg,
            AES_CBC,
            Operation::General,
            17,
            expected_fingerprint("aes_cbc_encrypt_data", AES_CBC, 17),
            LP64,
            FlatDenyReason::PrefixTooLong { declared_len: 17, first_unsafe_offset: 16 },
        );
    }

    #[test]
    fn parameterless_listed_carries_flat_to_cap() {
        let reg = registry(&[], &[AES_CBC], &[]);
        let validated = validate(&reg, &flat_mech(AES_CBC, "iv", 1024, LP64)).unwrap();
        assert_eq!(validated.flat_grant().unwrap().resolved.descriptor.name, "parameterless");
    }

    #[test]
    fn operation_context_selects_wrap_layout() {
        // AES_GCM bound to "gcm", declared length 56 (== gcm_wrap native):
        // General resolves the primary form (prefix denial), WrapKey
        // selects gcm_wrap (full-image denial) — proving the operation is
        // threaded into resolution rather than ignored.
        let reg = registry(&[("gcm", AES_GCM)], &[], &[]);
        let mechanism = flat_mech(AES_GCM, "gcm", 56, LP64);
        let fp = expected_fingerprint("gcm", AES_GCM, 56);
        assert_eq!(
            validate_mechanism_transport(&reg, &mechanism, Operation::General, LP64, LP64),
            Err(CkRv::MECHANISM_PARAM_INVALID)
        );
        assert_denied_as(
            &reg,
            AES_GCM,
            Operation::General,
            56,
            fp,
            LP64,
            FlatDenyReason::PrefixTooLong { declared_len: 56, first_unsafe_offset: 0 },
        );
        assert_eq!(
            validate_mechanism_transport(&reg, &mechanism, Operation::WrapKey, LP64, LP64),
            Err(CkRv::MECHANISM_PARAM_INVALID)
        );
        assert_denied_as(
            &reg,
            AES_GCM,
            Operation::WrapKey,
            56,
            fp,
            LP64,
            FlatDenyReason::FullNativeImage,
        );
    }

    #[test]
    fn unnarrowable_null_length_is_function_failed() {
        let reg = registry(&[], &[], &[]);
        let mechanism = null_mech(AES_CBC, u64::from(u32::MAX) + 1);
        assert_eq!(
            validate_mechanism_transport(&reg, &mechanism, Operation::General, LP64, ILP32),
            Err(CkRv::FUNCTION_FAILED)
        );
        // Same value forwards onto an LP64 backend.
        validate(&reg, &mechanism).unwrap();
    }

    #[test]
    fn null_and_empty_flat_never_conflate() {
        // S2 §10: NULL/non-NULL are never conflated — an empty Flat extent
        // validates as Flat (grant stored), Null{0} as Null (no grant).
        let reg = registry(&[("iv", AES_CBC)], &[], &[]);
        let flat_empty = flat_mech(AES_CBC, "iv", 0, LP64);
        let validated = validate(&reg, &flat_empty).unwrap();
        assert!(validated.flat_grant().is_some());
        assert!(matches!(validated.mechanism().params, Some(CkMechanismParams::Flat(_))));
        let null_zero = null_mech(AES_CBC, 0);
        let validated = validate(&reg, &null_zero).unwrap();
        assert!(validated.flat_grant().is_none());
        assert!(matches!(validated.mechanism().params, Some(CkMechanismParams::Null { .. })));
    }

    #[test]
    fn validated_bytes_pass_through_verbatim() {
        // S2 §10: no client address bits are used or interpreted — even
        // pointer-looking byte patterns validate byte-identically.
        let reg = registry(&[("iv", AES_CBC)], &[], &[]);
        let mut address_like = 0x7ffd_aabb_ccdd_eeffu64.to_le_bytes().to_vec();
        address_like.extend_from_slice(&[0x00; 8]);
        let len = address_like.len();
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Flat(FlatParams {
                bytes: SecretBytes::copy_from_slice(&address_like),
                declared_len: len as u64,
                source_abi: Some(LP64),
                fingerprint: ABI_EXEMPT_FINGERPRINT,
                version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
            })),
        };
        let validated = validate(&reg, &mechanism).unwrap();
        let Some(CkMechanismParams::Flat(back)) = &validated.mechanism().params else {
            panic!("validated output must stay Flat")
        };
        back.bytes.expose(|b| assert_eq!(b, address_like.as_slice()));
    }

    #[test]
    fn typed_and_bare_inputs_validate() {
        let reg = registry(&[("iv", AES_CBC)], &[], &[]);
        let typed = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Iv(IvParams { iv: vec![1, 2, 3] })),
        };
        validate(&reg, &typed).unwrap();
        let none = CkMechanism { mechanism_type: CkMechanismType(AES_CBC), params: None };
        validate(&reg, &none).unwrap();
        validate(&reg, &flat_mech(AES_CBC, "iv", 16, LP64)).unwrap();
        validate(&reg, &null_mech(AES_CBC, 0)).unwrap();
    }

    #[test]
    fn r16_typed_presence_consistency_through_entry_point() {
        // The R16 typed gate (S2 §3 "no dual representations") is enforced
        // through this entry point, not just the pure fn: a NULL IV with a
        // declared length validates (contradictions are unrepresentable
        // post-R19 — the peer is the only member).
        let reg = registry(&[("gcm", AES_GCM)], &[], &[]);
        let gcm = |iv_presence: PointerBytes| CkMechanism {
            mechanism_type: CkMechanismType(AES_GCM),
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv_bits: 96,
                iv_buffer_len: 12,
                tag_bits: 128,
                iv_presence,
                aad_presence: PointerBytes::present_copy(b""),
            })),
        };
        validate(&reg, &gcm(PointerBytes::null_len(0))).unwrap();
        validate(&reg, &gcm(PointerBytes::null_len(41))).unwrap();
        validate(&reg, &gcm(PointerBytes::present_copy(b"iv-bytes"))).unwrap();
    }

    // ─── R20 sanitizer matrix (S2 §6) ────────────────────────────────

    /// D3 probe: NULL lengths above 512 MiB forward by default (OFF) but
    /// reject under sanitize ON (no D3 forwarding under sanitize).
    const D3_HUGE_NULL_LEN: u64 = 512 * 1024 * 1024 + 1;

    fn sanitize_on(validated: &ValidatedMechanismParams) -> Result<ValidatedMechanismParams, CkRv> {
        sanitize_mechanism_input(true, validated.clone())
    }

    fn sanitize_off(
        validated: &ValidatedMechanismParams,
    ) -> Result<ValidatedMechanismParams, CkRv> {
        sanitize_mechanism_input(false, validated.clone())
    }

    /// Every sanitizer rejection is `PARAM_INVALID` — never `ARGUMENTS_BAD`
    /// (that RV stays with the pre-existing whole-mechanism/data-pointer
    /// gates).
    fn assert_sanitizer_reject(result: Result<ValidatedMechanismParams, CkRv>, case: &str) {
        let rv = result.err().unwrap_or_else(|| panic!("{case}: sanitizer ON must reject"));
        assert_eq!(rv, CkRv::MECHANISM_PARAM_INVALID, "{case}: sanitizer RV");
        assert_ne!(rv, CkRv::ARGUMENTS_BAD, "{case}: never ARGUMENTS_BAD");
    }

    fn assert_sanitizer_allow(
        result: Result<ValidatedMechanismParams, CkRv>,
        expected: &ValidatedMechanismParams,
        case: &str,
    ) {
        let back = result.unwrap_or_else(|rv| panic!("{case}: sanitizer must allow, got {rv:?}"));
        assert_eq!(&back, expected, "{case}: allowed values pass through unchanged");
    }

    fn gcm_with_iv(iv_presence: PointerBytes) -> CkMechanism {
        CkMechanism {
            mechanism_type: CkMechanismType(AES_GCM),
            params: Some(CkMechanismParams::Gcm(GcmParams {
                iv_bits: 96,
                iv_buffer_len: 12,
                tag_bits: 128,
                iv_presence,
                aad_presence: PointerBytes::present_copy(b""),
            })),
        }
    }

    #[test]
    fn sanitize_off_forwards_every_matrix_row() {
        // OFF (default false) is bit-for-bit with the pre-R20 path: every
        // validated row forwards untouched.
        let reg_struct = registry(&[("aes_cbc_encrypt_data", AES_CBC)], &[], &[]);
        let reg_bytes = registry(&[("iv", AES_CBC)], &[], &[]);
        let reg_paramless = registry(&[], &[AES_CBC], &[]);
        let reg_gcm = registry(&[("gcm", AES_GCM)], &[], &[]);
        let rows: Vec<(&str, ValidatedMechanismParams)> = vec![
            (
                "parameterless+Flat",
                validate(&reg_paramless, &flat_mech(AES_CBC, "iv", 16, LP64)).unwrap(),
            ),
            (
                "struct-prefix Flat",
                validate(&reg_struct, &flat_mech(AES_CBC, "aes_cbc_encrypt_data", 8, LP64))
                    .unwrap(),
            ),
            (
                "byte-buffer Flat",
                validate(&reg_bytes, &flat_mech(AES_CBC, "iv", 16, LP64)).unwrap(),
            ),
            ("NULL/nonzero", validate(&reg_bytes, &null_mech(AES_CBC, 41)).unwrap()),
            ("NULL/zero", validate(&reg_bytes, &null_mech(AES_CBC, 0)).unwrap()),
            (
                "NULL/huge (D3)",
                validate(&reg_bytes, &null_mech(AES_CBC, D3_HUGE_NULL_LEN)).unwrap(),
            ),
            (
                "no params",
                validate(
                    &reg_bytes,
                    &CkMechanism { mechanism_type: CkMechanismType(AES_CBC), params: None },
                )
                .unwrap(),
            ),
            (
                "typed Iv",
                validate(
                    &reg_bytes,
                    &CkMechanism {
                        mechanism_type: CkMechanismType(AES_CBC),
                        params: Some(CkMechanismParams::Iv(IvParams { iv: vec![1, 2, 3] })),
                    },
                )
                .unwrap(),
            ),
            (
                "typed Gcm with embedded NULL IV",
                validate(&reg_gcm, &gcm_with_iv(PointerBytes::null_len(12))).unwrap(),
            ),
        ];
        for (case, validated) in &rows {
            assert_sanitizer_allow(sanitize_off(validated), validated, case);
        }
    }

    #[test]
    fn sanitize_on_rejects_parameterless_flat() {
        let reg = registry(&[], &[AES_CBC], &[]);
        let validated = validate(&reg, &flat_mech(AES_CBC, "iv", 16, LP64)).unwrap();
        assert_sanitizer_reject(sanitize_on(&validated), "parameterless+Flat");
    }

    #[test]
    fn sanitize_on_rejects_struct_prefix_flat() {
        let reg = registry(&[("aes_cbc_encrypt_data", AES_CBC)], &[], &[]);
        let validated =
            validate(&reg, &flat_mech(AES_CBC, "aes_cbc_encrypt_data", 8, LP64)).unwrap();
        assert_sanitizer_reject(sanitize_on(&validated), "struct-prefix Flat");
    }

    #[test]
    fn sanitize_on_allows_canonical_byte_buffer_flat() {
        let reg = registry(&[("iv", AES_CBC)], &[], &[]);
        for len in [0, 1, 16] {
            let validated = validate(&reg, &flat_mech(AES_CBC, "iv", len, LP64)).unwrap();
            assert_sanitizer_allow(
                sanitize_on(&validated),
                &validated,
                &format!("byte-buffer Flat len {len}"),
            );
        }
    }

    #[test]
    fn sanitize_on_rejects_null_nonzero_allows_null_zero() {
        let reg = registry(&[("iv", AES_CBC)], &[], &[]);
        let nonzero = validate(&reg, &null_mech(AES_CBC, 41)).unwrap();
        assert_sanitizer_reject(sanitize_on(&nonzero), "NULL/nonzero");
        let zero = validate(&reg, &null_mech(AES_CBC, 0)).unwrap();
        assert_sanitizer_allow(sanitize_on(&zero), &zero, "NULL/zero");
    }

    #[test]
    fn sanitize_on_rejects_null_huge_d3() {
        // D3: NULL-huge forwards by default (OFF) but rejects under
        // sanitize ON regardless.
        let reg = registry(&[("iv", AES_CBC)], &[], &[]);
        let huge = validate(&reg, &null_mech(AES_CBC, D3_HUGE_NULL_LEN)).unwrap();
        assert_sanitizer_reject(sanitize_on(&huge), "NULL/huge D3 ON");
        assert_sanitizer_allow(sanitize_off(&huge), &huge, "NULL/huge D3 OFF");
    }

    #[test]
    fn sanitize_on_allows_none_and_typed() {
        // The matrix governs the outer form (Flat/Null/Raw); typed params
        // stay allowed under ON — including embedded NULL-nonzero, which
        // is an R16/R19 typed-path concern, not structure policy. (No
        // provider-specific scalar conformance — forbidden by S2 §6.)
        let reg = registry(&[("iv", AES_CBC)], &[], &[]);
        let none =
            validate(&reg, &CkMechanism { mechanism_type: CkMechanismType(AES_CBC), params: None })
                .unwrap();
        assert_sanitizer_allow(sanitize_on(&none), &none, "no params ON");
        let typed = validate(
            &reg,
            &CkMechanism {
                mechanism_type: CkMechanismType(AES_CBC),
                params: Some(CkMechanismParams::Iv(IvParams { iv: vec![1, 2, 3] })),
            },
        )
        .unwrap();
        assert_sanitizer_allow(sanitize_on(&typed), &typed, "typed Iv ON");
        let reg_gcm = registry(&[("gcm", AES_GCM)], &[], &[]);
        let embedded_null = validate(&reg_gcm, &gcm_with_iv(PointerBytes::null_len(12))).unwrap();
        assert_sanitizer_allow(sanitize_on(&embedded_null), &embedded_null, "typed Gcm+NULL-IV ON");
    }

    #[test]
    fn legacy_raw_always_rejected_regardless_of_toggle() {
        // Legacy Raw fails closed at transport validation — always-on, so
        // the toggle cannot rescue it and the sanitizer never sees it (the
        // policy keeps a fail-closed Raw arm for defense in depth).
        let reg = registry(&[("iv", AES_CBC)], &[], &[]);
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType(AES_CBC),
            params: Some(CkMechanismParams::Raw(RawMechanismParams {
                data: SecretBytes::copy_from_slice(b"AB"),
            })),
        };
        for toggle in [false, true] {
            let rv = validate(&reg, &mechanism)
                .err()
                .unwrap_or_else(|| panic!("legacy Raw must reject with sanitize={toggle}"));
            assert_eq!(rv, CkRv::MECHANISM_PARAM_INVALID, "sanitize={toggle}: Raw RV");
            assert_ne!(rv, CkRv::ARGUMENTS_BAD, "sanitize={toggle}: never ARGUMENTS_BAD");
        }
    }
}
