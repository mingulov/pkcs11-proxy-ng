//! Mechanism-parameter FFI readers: `read_mechanism_for_transport` (S2 §5,
//! single-snapshot outer classification + typed-or-Flat routing) and the
//! per-shape `read_mechanism_with_shape` match (kept flat by design for
//! auditability), plus the shared raw-parameter utilities.

use super::*;
use pkcs11_proxy_ng_types::PointerBytes;
use pkcs11_proxy_ng_types::shape_descriptors::{
    FlatDecision, FlatRequest, Operation, OperationContext, OuterKind, ParamAbi, ResolvedShape,
    ShapeResolver, decide_flat,
};

/// Return `true` when an embedded mechanism-parameter **data** payload (seed,
/// label, AAD, IV, OtherInfo, public-data, password, random, …) has a length
/// that can be materialized and serialized over gRPC.
///
/// These fields are data, not structs; they must not be capped by the much
/// smaller `MAX_MECHANISM_PARAM_STRUCT_LEN`.  An unmaterializable length
/// (> 512 MiB) causes the caller to fall back to the raw-bytes path, returning
/// `MECHANISM_PARAM_INVALID` or a raw forwarding blob instead of calling
/// `from_raw_parts` with an absurd size.  (ADR-0010 transport limit.)
#[inline]
pub(crate) fn embedded_payload_len_ok(len: CK_ULONG) -> bool {
    (len as usize) <= MAX_SERIALIZABLE_BYTES
}

// LLP64 (Windows x64): the app passes these param structs laid out per the
// `#pragma pack(1)` PKCS#11 headers, so the shim's mirror must be packed there
// to read the fields at the right offsets. Natural alignment is correct on
// LP64/ILP32 (ADR-0011 Bucket 2). Fields are read by value (never `&field`),
// so packed access stays E0793-safe.
#[repr(C)]
#[cfg_attr(windows, repr(packed))]
#[derive(Clone, Copy)]
pub(crate) struct CkKmacParams {
    pub(crate) h_key: CK_OBJECT_HANDLE,
    pub(crate) ul_mac_length: CK_ULONG,
    pub(crate) p_customization_string: CK_VOID_PTR,
    pub(crate) ul_customization_string_len: CK_ULONG,
}

#[repr(C)]
#[cfg_attr(windows, repr(packed))] // LLP64: match `#pragma pack(1)` (ADR-0011 Bucket 2)
#[derive(Clone, Copy)]
pub(crate) struct CkMuGenParams {
    pub(crate) h_key: CK_OBJECT_HANDLE,
    pub(crate) p_tr: CK_BYTE_PTR,
    pub(crate) ul_tr_len: CK_ULONG,
    pub(crate) p_ctx: CK_BYTE_PTR,
    pub(crate) ul_ctx_len: CK_ULONG,
}

/// Maximum nested (non-top-level) mechanism nodes a single
/// `read_mechanism_for_transport` traversal will descend into (T03/RV-N2). The 17th
/// nested node — and any repeated active caller address (a reference
/// cycle) — is rejected with `MECHANISM_PARAM_INVALID` before recursion.
/// Recorded as an explicit support limit in the canonical
/// mechanism-coverage documentation.
pub(crate) const MAX_NESTED_MECHANISMS: usize = 16;

/// Recursion budget for nested mechanism reads (KIP `pMechanism`).
/// `active` holds the caller addresses on the current descent stack; its
/// length is the nested depth (top level = 0). The budget is created fresh
/// per top-level read and discarded with it, so an error unwind never
/// needs to rebalance a partially entered stack.
#[derive(Default)]
pub(crate) struct NestingBudget {
    active: Vec<usize>,
}

impl NestingBudget {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Enter one nesting level for the caller struct at `address`,
    /// rejecting depth exhaustion and reference cycles before recursion.
    /// `pub(crate)` so tests can pre-seed budgets (the registry carries
    /// no KIP mapping, so end-to-end deep recursion is unreachable and
    /// the enforcement boundary is pinned directly).
    pub(crate) fn enter(&mut self, address: usize) -> CkResult<()> {
        if self.active.len() >= MAX_NESTED_MECHANISMS || self.active.contains(&address) {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        self.active.push(address);
        Ok(())
    }

    fn exit(&mut self) {
        self.active.pop();
    }
}

/// Copy one caller parameter struct without assuming alignment (T03).
///
/// Validates the struct's extent arithmetic, then performs a single
/// unaligned copy into owned storage; field accesses afterward touch only
/// the copy (the message/exact-path convention). Input-direction only:
/// output records need per-field loads/stores, since a whole copy can
/// read uninitialized OUT fields (T06).
///
/// # Safety
///
/// `ptr` must designate `size_of::<T>()` readable bytes (alignment not
/// required). Length checks at the call site establish the bound; this
/// helper re-validates the extent arithmetic, not the mapping.
pub(crate) unsafe fn read_param_struct<T: Copy>(ptr: *const T) -> CkResult<T> {
    checked_extent(
        ptr as usize,
        std::mem::size_of::<T>() as u64,
        1,
        MAX_MECHANISM_PARAM_STRUCT_LEN,
    )
    .map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
    Ok(unsafe { ptr.read_unaligned() })
}

/// Copy caller payload bytes without assuming anything beyond the FFI
/// readability contract (T03). Total over `(ptr, len)`: NULL with nonzero
/// length and arithmetic-invalid extents are `MECHANISM_PARAM_INVALID`;
/// zero length returns empty without constructing a slice (never a NULL
/// zero-length slice). Callers keep their own NULL-vs-empty branching for
/// null-preservation; this helper only guarantees the copy itself.
///
/// # Safety
///
/// When `ptr` is non-null with nonzero `len`, it must designate `len`
/// readable bytes.
pub(crate) unsafe fn payload_bytes(ptr: *const u8, len: CK_ULONG) -> CkResult<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    let extent = checked_extent(ptr as usize, len as u64, 1, MAX_SERIALIZABLE_BYTES)
        .map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
    Ok(unsafe { std::slice::from_raw_parts(ptr, extent) }.to_vec())
}

/// Read one embedded pointer field under v1 (R17 step-1 discipline,
/// S2 §5): every field INDEPENDENTLY — NULL records its declared
/// length without dereference (D3: no cap, no bytes materialize);
/// non-NULL/zero records `Present(empty)`; non-NULL/positive copies
/// under the 512 MiB ceiling (`PARAM_INVALID` before any dereference
/// past it). Returns the legacy mirror bytes + the authoritative
/// `PointerBytes` peer (the v1 wire encode reads the peer; the legacy
/// bytes mirror it so the value satisfies `check_typed_presence`).
///
/// Byte-governed callers pass the struct's length scalar; bits-governed
/// callers pass the derived byte length (keeping the legacy `>=`
/// ceiling pre-check at the call site); fixed-size callers pass the
/// fixed extent. The S2 §10 shared-length exception is vacuous here —
/// no R17 input-pointer family shares a length (pinned by
/// `r17_shared_length_exception_vacuous_for_v1_input_shapes`;
/// `kea_derive` + `skipjack_private_wrap` are R18 tail).
///
/// # Safety
///
/// When `ptr` is non-null with nonzero `len`, it must designate `len`
/// readable bytes. NULL is never dereferenced at any length.
pub(crate) unsafe fn read_pointer_field_v1(
    ptr: *const u8,
    len: CK_ULONG,
) -> CkResult<(Vec<u8>, PointerBytes)> {
    if ptr.is_null() {
        // NULL: record the declared length, never dereference (S2 §5
        // unreadable-pointer rule). D3 applies no cap: no bytes
        // materialize, so even CK_ULONG::MAX forwards (narrowing is the
        // daemon's job).
        return Ok((Vec::new(), PointerBytes::null_len(len as u64)));
    }
    if !embedded_payload_len_ok(len) {
        // Non-NULL past the ceiling: fail closed before any dereference
        // (the D3 companion rule — a governed companion stays capped).
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    // Safety: non-null (above) + readable for `len` (caller contract);
    // `payload_bytes` re-checks the extent arithmetic + ceiling and
    // returns empty for zero length without constructing a slice.
    let bytes = unsafe { payload_bytes(ptr, len)? };
    let presence = PointerBytes::present_copy(&bytes);
    Ok((bytes, presence))
}

/// Read one C `CK_MECHANISM` for transport in a single snapshot (S2 §5).
///
/// This ONE call replaces the old `validate_mechanism` + `read_mechanism`
/// pair: the outer struct is read exactly once (no validate/read race —
/// the old double outer-struct read is gone), then a single
/// registry/capability/ABI snapshot feeds the whole decision.
///
/// Outer classification (exact): (NULL,0) -> `params=None`; (NULL,n>0) ->
/// `Null`; (non-NULL,0) -> empty Flat; (non-NULL,n>0) -> typed or Flat per
/// descriptor. The old early return collapsing NULL and zero-length is gone.
///
/// `operation` is the call-site operation context (S2 §4): `WrapKey`
/// (exactly the `C_WrapKey` entrypoint, the sole old wrap-shape caller)
/// selects the GCM/CCM wrap layouts by operation+length; every other call
/// passes `General` and never selects wrap layouts.
///
/// Legacy capability preserves the old behavior EXACTLY (including legacy
/// `Raw` emission for old daemons); under v1 the shim NEVER emits legacy
/// `Raw` — unrepresentable inputs fail locally with `PARAM_INVALID`
/// without wire emission.
///
/// # Safety
///
/// `p_mechanism` must point to a valid `CK_MECHANISM` (callers already
/// checked non-null). If the mechanism has parameters, `pParameter` must
/// point to a valid buffer of at least `ulParameterLen` bytes containing
/// the appropriate C struct. Unreadable-pointer rule (exact, S2 §5): the
/// readers validate arithmetic and caps but CANNOT detect an unmapped
/// non-NULL pointer — such an address may fault the caller exactly as in
/// direct loading. Only NULL (never dereferenced) is unconditionally safe.
pub(crate) unsafe fn read_mechanism_for_transport(
    p_mechanism: *const CK_MECHANISM,
    operation: Operation,
) -> CkResult<CkMechanism> {
    let c_mech = unsafe { read_param_struct(p_mechanism)? };
    let capability = crate::interface_probe::mechanism_parameter_transport_version();
    if capability == 0 {
        // Legacy order parity: the old `validate_mechanism` rejected
        // overlong outer lengths BEFORE touching the registry, so a
        // pre-init overlong call answers MPI rather than the pre-init RV.
        // (Under v1 there is no outer length cap: NULL lengths forward
        // uncapped per D3, Flat lengths are decided per descriptor below.)
        let has_params = !c_mech.pParameter.is_null() && c_mech.ulParameterLen > 0;
        if has_params && (c_mech.ulParameterLen as usize) > MAX_MECHANISM_PARAM_STRUCT_LEN {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
    }
    // Pre-init (or racing C_Initialize): no registry installed yet.
    let registry = crate::state::try_mechanism_registry()?;
    let backend_abi = backend_abi_snapshot();
    unsafe {
        read_mechanism_node(
            &c_mech,
            &registry,
            capability,
            ParamAbi::native(),
            backend_abi,
            operation,
            &mut NestingBudget::new(),
            false,
        )
    }
}

/// Snapshot core behind [`read_mechanism_for_transport`] (S2 §5 signature:
/// outer struct + registry/capability/ABI snapshots + operation context).
///
/// Test seam — production enters through the pointer-level wrapper above
/// (nested KIP recursion through `read_nested_mechanism_for_transport`):
/// every snapshot is injected, so the v1/legacy × ABI × operation ×
/// nesting matrices run hermetically with no global state.
///
/// # Safety
///
/// `c_mech` is borrowed (always safe); its `pParameter`, when non-null
/// with nonzero length, must designate `ulParameterLen` readable bytes.
/// Inputs the v1 encoding cannot represent fail with
/// `MECHANISM_PARAM_INVALID`; under v1 no legacy `Raw` is ever produced.
#[cfg(test)]
pub(crate) unsafe fn read_mechanism_for_transport_with_snapshots(
    c_mech: &CK_MECHANISM,
    registry: &MechanismRegistry,
    capability: u32,
    local_abi: Option<ParamAbi>,
    backend_abi: Option<ParamAbi>,
    operation: Operation,
    nested: bool,
    budget: &mut NestingBudget,
) -> CkResult<CkMechanism> {
    unsafe {
        read_mechanism_node(
            c_mech,
            registry,
            capability,
            local_abi,
            backend_abi,
            operation,
            budget,
            nested,
        )
    }
}

/// One mechanism node (top-level or KIP-nested) against explicit snapshots.
///
/// `nested` selects the nested contract (validate-fusion skipped: the old
/// nested read ran no validation, and the daemon's R9 validation does not
/// recurse into nested params).
///
/// # Safety
///
/// Same contract as [`read_mechanism_for_transport`].
unsafe fn read_mechanism_node(
    c_mech: &CK_MECHANISM,
    registry: &MechanismRegistry,
    capability: u32,
    local_abi: Option<ParamAbi>,
    backend_abi: Option<ParamAbi>,
    operation: Operation,
    budget: &mut NestingBudget,
    nested: bool,
) -> CkResult<CkMechanism> {
    if capability == 0 {
        return unsafe { read_mechanism_legacy(c_mech, registry, operation, budget, nested) };
    }
    if !nested {
        let mech_type: u64 = c_mech.mechanism.into();
        if registry.excluded_view().contains(&mech_type) {
            // S2 §4 rule 1: operator exclusion wins (both capabilities; the
            // legacy branch enforces it via `check_operation` with the same
            // log line). Nested nodes skip it (see the `nested` contract).
            tracing::warn!(
                mechanism = format_args!("0x{mech_type:08X}"),
                "rejecting operator-excluded mechanism"
            );
            return Err(CkRv::MECHANISM_INVALID);
        }
    }
    unsafe { read_mechanism_v1(c_mech, registry, local_abi, backend_abi, operation, budget) }
}

/// Legacy-capability behavior (S2 §5: preserved EXACTLY, including legacy
/// `Raw` emission for old daemons): the old `validate_mechanism` +
/// `read_mechanism`/`read_wrap_key_mechanism` logic fused over the single
/// outer read (the only change is the removal of the TOCTOU window —
/// single-threaded behavior is bit-identical).
///
/// `nested` reproduces the old nested read exactly (no validate-fusion:
/// no length cap, no `check_operation` — validation was top-level-only).
///
/// # Safety
///
/// Same contract as [`read_mechanism_for_transport`].
unsafe fn read_mechanism_legacy(
    c_mech: &CK_MECHANISM,
    registry: &MechanismRegistry,
    operation: Operation,
    budget: &mut NestingBudget,
    nested: bool,
) -> CkResult<CkMechanism> {
    if !nested {
        let has_params = !c_mech.pParameter.is_null() && c_mech.ulParameterLen > 0;
        // Reject absurd parameter lengths before we attempt to dereference
        // the parameter buffer.  This prevents undefined behavior when the
        // caller passes a small buffer with an enormous ulParameterLen.
        // (The production entry enforces the same gate pre-registry; this
        // copy covers snapshot-core callers. Same RV either way once the
        // registry is in hand.)
        if has_params && (c_mech.ulParameterLen as usize) > MAX_MECHANISM_PARAM_STRUCT_LEN {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        registry.check_operation(c_mech.mechanism.into(), has_params)?;
    }
    let shape = select_reader_shape(c_mech, registry, operation);
    unsafe { read_mechanism_with_shape_budgeted(c_mech, shape, budget) }
}

/// Reader shape selection shared by the legacy branch and the v1 typed
/// branch: `WrapKey` selects the GCM/CCM wrap layouts by exact local size
/// (S2 §4 operation context — this reconciles the old operation-blind
/// wrap reader with R7's WrapKey gate; the selections are identical),
/// every other case falls back to the registry binding, and `General`
/// NEVER selects wrap layouts (R7
/// `general_operation_ignores_wrap_layouts`).
fn select_reader_shape<'a>(
    c_mech: &CK_MECHANISM,
    registry: &'a MechanismRegistry,
    operation: Operation,
) -> Option<&'a str> {
    if operation == Operation::WrapKey {
        let param_len = c_mech.ulParameterLen as usize;
        match c_mech.mechanism {
            CKM_AES_GCM if param_len == std::mem::size_of::<CK_GCM_WRAP_PARAMS>() => {
                return Some("gcm_wrap");
            }
            CKM_AES_CCM if param_len == std::mem::size_of::<CK_CCM_WRAP_PARAMS>() => {
                return Some("ccm_wrap");
            }
            _ => {}
        }
    }
    registry.param_shape(c_mech.mechanism.into())
}

/// v1-capability read (S2 §5): exact outer classification, per-shape
/// typed-or-Flat routing, legacy `Raw` never emitted.
///
/// # Safety
///
/// Same contract as [`read_mechanism_for_transport`].
unsafe fn read_mechanism_v1(
    c_mech: &CK_MECHANISM,
    registry: &MechanismRegistry,
    local_abi: Option<ParamAbi>,
    backend_abi: Option<ParamAbi>,
    operation: Operation,
    budget: &mut NestingBudget,
) -> CkResult<CkMechanism> {
    let mech_type: u64 = c_mech.mechanism.into();
    let mechanism_type = CkMechanismType(mech_type);
    let declared_len = c_mech.ulParameterLen as u64;
    if c_mech.pParameter.is_null() {
        if declared_len == 0 {
            return Ok(CkMechanism { mechanism_type, params: None });
        }
        // (NULL, n>0) -> Null: the pointer is NEVER dereferenced
        // (unreadable-pointer rule: only NULL is unconditionally safe), no
        // bytes materialize, and no cap applies (D3 — CK_ULONG narrowing
        // is the daemon's job, R9). No descriptor is needed (S2 §6 RV
        // table: unknown mechanisms with Null forward). The D3
        // shared-length exception is vacuous here — no struct is read, so
        // no companion can share this length (R17 enforces it per field
        // on the typed path).
        return Ok(CkMechanism {
            mechanism_type,
            params: Some(CkMechanismParams::Null {
                declared_len,
                version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
            }),
        });
    }
    // Non-NULL below. (non-NULL, 0) -> empty Flat (S2: distinct from None —
    // NULL/non-NULL are never conflated); it routes through the Flat branch
    // like any other noncanonical length (0 is never a native struct size).
    let Some(abi) = local_abi else {
        // No v1 ABI on this target (big-endian): the shim cannot name a
        // source ABI or fingerprint, so it can never emit well-formed Flat.
        // The typed path still works (native mirrors); legacy Raw stays
        // banned; (non-NULL, 0) cannot collapse to None (conflation).
        if declared_len == 0 {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        let shape = select_reader_shape(c_mech, registry, operation);
        return unsafe { read_typed_under_v1(c_mech, shape, budget) };
    };
    let bound_shape = registry.param_shape(mech_type);
    let resolved = ShapeResolver::resolve(
        bound_shape,
        OperationContext { mechanism: mech_type, operation, length: declared_len },
        abi,
    );
    // Typed-or-Flat per descriptor (S2 §5 per-shape algorithm; the
    // typed branch dispatches R17 input-pointer shapes to the step-1
    // readers and every other shape to the existing typed reader):
    // - parameterless forms ride Flat (S2 §4: parameterless-shaped bytes
    //   may carry arbitrary flat bytes to the cap), like the unbound
    //   parameterless-only case below;
    // - byte-buffer forms have no canonical length: every nonzero length
    //   stays typed (Iv bytes keep their legacy typed encoding, still
    //   valid under v1 per S2 §3 newer-accepts-older);
    // - struct forms: exact native size -> canonical -> typed reader;
    //   anything else -> Flat iff R7-eligible, else the forced
    //   transport-limit RV (PARAM_INVALID) — in particular,
    //   pointer-bearing oversized structs stay rejected (residual limit;
    //   typed-plus-tail only on provider evidence, NOT this task);
    // - nested/output forms ride typed envelopes only (R18): until then
    //   the reader keeps its native length tolerance;
    // - unresolvable (unbound/unknown shape) -> Flat branch, where
    //   `decide_flat` grants parameterless-only and denies the rest
    //   (unknown/vendor/nested/over-cap -> PARAM_INVALID).
    let use_typed_reader = match resolved {
        Some(form) => match form.outer_kind() {
            OuterKind::Parameterless => false,
            OuterKind::ByteBuffer => declared_len != 0,
            OuterKind::ScalarStruct | OuterKind::PointerStruct => {
                Some(declared_len) == form.native_size(abi).map(|size| size as u64)
            }
            OuterKind::NestedOrOutput => declared_len != 0,
        },
        None => false,
    };
    if use_typed_reader {
        let shape = select_reader_shape(c_mech, registry, operation);
        return unsafe { read_typed_under_v1(c_mech, shape, budget) };
    }
    unsafe { read_flat_under_v1(c_mech, registry, resolved, abi, backend_abi, operation) }
}

/// Typed branch under v1: R17 input-pointer shapes take the step-1
/// readers ([`read_v1_typed_params`] — NULL-aware, never `Raw`); every
/// other shape takes the EXISTING typed reader unchanged, except its
/// legacy-`Raw` fallbacks, which v1 cannot emit: full-extent or
/// degenerate-struct bytes that would have ridden `Raw` fail locally
/// with `PARAM_INVALID` (no wire emission). `None` is unreachable (the
/// router only sends non-NULL/nonzero here) and fails closed rather
/// than conflate.
///
/// # Safety
///
/// Same contract as [`read_mechanism_for_transport`].
unsafe fn read_typed_under_v1(
    c_mech: &CK_MECHANISM,
    shape: Option<&str>,
    budget: &mut NestingBudget,
) -> CkResult<CkMechanism> {
    if is_r17_v1_shape(shape) {
        let params = unsafe {
            read_v1_typed_params(c_mech.pParameter, c_mech.ulParameterLen as usize, shape)?
        };
        return Ok(CkMechanism {
            mechanism_type: CkMechanismType(c_mech.mechanism.into()),
            params: Some(params),
        });
    }
    let mechanism = unsafe { read_mechanism_with_shape_budgeted(c_mech, shape, budget)? };
    match mechanism.params {
        Some(CkMechanismParams::Raw(_)) => Err(CkRv::MECHANISM_PARAM_INVALID),
        Some(_) => Ok(mechanism),
        None => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

/// Flat branch under v1 (S2 §4 eligibility + S2 §5 width rule): Flat iff
/// R7-eligible, else the forced transport-limit RV (`PARAM_INVALID`,
/// local, no wire emission).
///
/// The Flat decision is embedded-field-independent: only the outer extent
/// is read (verbatim bytes via the capped raw reader); struct contents —
/// including any NULL embedded pointers — are never interpreted (a NULL
/// record would declare its length without dereference; here there is not
/// even a record).
///
/// Width (S2 §5): parameterless and byte-buffer Flat cross ABIs; struct
/// prefixes require identical layouts (`backend_abi == local_abi`), else
/// explicit `PARAM_INVALID`. An unknown backend ABI fails closed for
/// struct prefixes. (The daemon re-validates authoritatively; this is the
/// fail-fast that avoids needless RPCs.)
///
/// # Safety
///
/// `c_mech.pParameter` must be non-null and designate `ulParameterLen`
/// readable bytes (the v1 router guarantees both: NULL routes to Null,
/// and over-cap lengths are denied before any dereference).
unsafe fn read_flat_under_v1(
    c_mech: &CK_MECHANISM,
    registry: &MechanismRegistry,
    resolved: Option<ResolvedShape>,
    local_abi: ParamAbi,
    backend_abi: Option<ParamAbi>,
    operation: Operation,
) -> CkResult<CkMechanism> {
    let mech_type: u64 = c_mech.mechanism.into();
    let declared_len = c_mech.ulParameterLen as u64;
    // `decide_flat` against our own descriptor (S2 §4: each side validates
    // against its own; the shim never re-decides R7 policy): peer == local,
    // so the ABI/fingerprint checks pass trivially and the grant carries
    // the wire fingerprint. (`resolved` is None only for unbound/unknown
    // shapes, where the fingerprint is unused: the parameterless-only arm
    // grants without one and every other arm denies first.)
    let peer_fingerprint = resolved.map(|form| form.fingerprint(local_abi)).unwrap_or(0);
    let grant = match decide_flat(FlatRequest {
        mechanism: mech_type,
        operation,
        declared_len,
        bound_shape: registry.param_shape(mech_type),
        parameterless_listed: registry.is_parameterless(mech_type),
        // Exclusion was decided by the caller (top-level pre-check;
        // nested nodes skip it — see `read_mechanism_node`).
        excluded: false,
        peer_fingerprint,
        peer_abi: local_abi,
        local_abi,
    }) {
        FlatDecision::Eligible(grant) => grant,
        // Unreachable (`excluded: false` above); mapped anyway so a future
        // reorder cannot silently forward (R9 precedent).
        FlatDecision::Excluded => return Err(CkRv::MECHANISM_INVALID),
        // OverCap, VendorWithoutAllowlist, UnknownShape, NestedOrOutput,
        // FullNativeImage, AbiMismatch, FingerprintMismatch, PrefixTooLong:
        // every R7 denial is the forced transport-limit RV (S2 §6 table).
        FlatDecision::Denied(_) => return Err(CkRv::MECHANISM_PARAM_INVALID),
    };
    match grant.resolved.outer_kind() {
        OuterKind::Parameterless | OuterKind::ByteBuffer => {}
        OuterKind::ScalarStruct | OuterKind::PointerStruct => {
            if backend_abi != Some(local_abi) {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
        }
        // Unreachable (`decide_flat` denies nested/output); defense in depth.
        OuterKind::NestedOrOutput => return Err(CkRv::MECHANISM_PARAM_INVALID),
    }
    // Materialize the outer extent verbatim: the grant confines it to the
    // 64 KiB Flat cap, and the capped raw reader re-checks (extent
    // arithmetic + no-deref-before-cap) rather than trust the grant.
    let extent = usize::try_from(declared_len).map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
    let bytes = unsafe { read_raw_bytes(c_mech.pParameter, extent)? };
    Ok(CkMechanism {
        mechanism_type: CkMechanismType(mech_type),
        params: Some(CkMechanismParams::Flat(FlatParams {
            bytes: SecretBytes::copy_from_slice(&bytes),
            declared_len,
            source_abi: Some(local_abi),
            fingerprint: grant.fingerprint,
            version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
        })),
    })
}

/// Nested-node read for KIP `pMechanism` recursion: one snapshot per nested
/// node (the race fix applies per node — each node reads its outer struct
/// once). Nested nodes are never wrap operations (legacy parity: nested
/// reads never wrap-selected) and skip the validate-fusion (legacy parity:
/// validation was top-level-only; the daemon's R9 validation likewise does
/// not recurse into nested params).
///
/// # Safety
///
/// Same contract as [`read_mechanism_for_transport`].
unsafe fn read_nested_mechanism_for_transport(
    p_mechanism: *const CK_MECHANISM,
    budget: &mut NestingBudget,
) -> CkResult<CkMechanism> {
    let c_mech = unsafe { read_param_struct(p_mechanism)? };
    let capability = crate::interface_probe::mechanism_parameter_transport_version();
    let registry = crate::state::try_mechanism_registry()?;
    let backend_abi = backend_abi_snapshot();
    unsafe {
        read_mechanism_node(
            &c_mech,
            &registry,
            capability,
            ParamAbi::native(),
            backend_abi,
            Operation::General,
            budget,
            true,
        )
    }
}

/// Derive the backend's v1 ABI from the probed width/stride snapshot
/// (ADR-0011 D2): exact pairs map to a v1 ABI, anything else (unmapped
/// widths, future layouts) yields `None` and struct-prefix Flat fails
/// closed locally. Pre-probe readers see the D9 fallback width/stride
/// (LP64); the daemon re-validates authoritatively either way.
fn backend_abi_snapshot() -> Option<ParamAbi> {
    match (
        crate::interface_probe::backend_ulong_size(),
        crate::interface_probe::backend_attribute_stride(),
    ) {
        (8, 24) => Some(ParamAbi::Lp64NativeLe),
        (4, 12) => Some(ParamAbi::Ilp32NativeLe),
        (4, 16) => Some(ParamAbi::Llp64Packed1Le),
        _ => None,
    }
}

/// Parse `c_mech` per the registry `shape`, preserving unmodeled params
/// as Raw bytes (W1-L1-04).
///
/// # Safety
///
/// `c_mech` is borrowed (always safe); its `pParameter`, when non-null
/// with nonzero length, must designate `ulParameterLen` readable bytes.
/// Short reads stay Raw, never UB.
/// Test seam: production readers enter through the budgeted path so the
/// KIP nesting budget is always enforced (T03/RV-N2).
#[cfg(test)]
pub(crate) unsafe fn read_mechanism_with_shape(
    c_mech: &CK_MECHANISM,
    shape: Option<&str>,
) -> CkResult<CkMechanism> {
    unsafe { read_mechanism_with_shape_budgeted(c_mech, shape, &mut NestingBudget::new()) }
}

/// Parse a struct-sized GCM parameter buffer (`CK_GCM_PARAMS`), copying the
/// pointed-to IV/AAD bytes into owned storage so no client pointer ever
/// crosses to the backend.
///
/// Shared by the `"gcm"` arm and the `"gcm_compat"` arm (GMAC dual
/// encoding); the arms differ only in how they treat buffers too short to
/// be the struct. Degenerate structs (NULL pointer with nonzero length,
/// unmaterializable payload lengths) fall back to Raw, exactly as the
/// `"gcm"` arm always did.
///
/// # Safety
///
/// `param_ptr` must designate `param_len` readable bytes with
/// `param_len >= size_of::<CK_GCM_PARAMS>()`.
unsafe fn read_gcm_struct_params(
    param_ptr: *mut std::ffi::c_void,
    param_len: usize,
) -> CkResult<CkMechanismParams> {
    // Safety: caller guarantees a struct-sized readable buffer.
    let gcm = unsafe { read_param_struct(param_ptr as *const CK_GCM_PARAMS)? };
    if missing_embedded_pointer(gcm.pIv, gcm.ulIvLen)
        || missing_embedded_pointer(gcm.pAAD, gcm.ulAADLen)
        || !embedded_payload_len_ok(gcm.ulIvLen)
        || !embedded_payload_len_ok(gcm.ulAADLen)
    {
        return raw_mechanism_params(param_ptr, param_len);
    }
    let iv = if gcm.pIv.is_null() || gcm.ulIvLen == 0 {
        Vec::new()
    } else {
        unsafe { payload_bytes(gcm.pIv as *const u8, gcm.ulIvLen)? }
    };
    let aad = if gcm.pAAD.is_null() || gcm.ulAADLen == 0 {
        Vec::new()
    } else {
        unsafe { payload_bytes(gcm.pAAD as *const u8, gcm.ulAADLen)? }
    };
    let iv_presence = PointerBytes::from_legacy(&iv, gcm.pIv.is_null());
    let aad_presence = PointerBytes::from_legacy(&aad, gcm.pAAD.is_null());
    Ok(CkMechanismParams::Gcm(GcmParams {
        iv,
        iv_bits: gcm.ulIvBits as u64,
        iv_buffer_len: gcm_iv_buffer_len(&gcm),
        aad: aad.into(),
        tag_bits: gcm.ulTagBits as u64,
        // F3/D2: (NULL, 0) vs (ptr, 0) must survive the
        // crossing; (NULL, len > 0) took the Raw path above.
        iv_null: gcm.pIv.is_null(),
        aad_null: gcm.pAAD.is_null(),
        iv_presence,
        aad_presence,
    }))
}

/// R17 v1-shape dispatch: the 37 R16 input-pointer shapes plus
/// `gcm_compat` (whose struct half rides the GCM v1 reader) take the
/// step-1 readers; every other shape (scalar, byte-buffer, R18 tail,
/// unknown) keeps the legacy reader with `Raw` mapped to
/// `PARAM_INVALID`. Reviewer-checked against `R16_PRESENCE_TABLE`.
pub(crate) fn is_r17_v1_shape(shape: Option<&str>) -> bool {
    matches!(
        shape,
        Some(
            "gcm"
                | "gcm_compat"
                | "rsa_oaep"
                | "ccm"
                | "ecdh1_derive"
                | "hkdf"
                | "eddsa"
                | "chacha20"
                | "salsa20"
                | "salsa20_chacha20_poly1305"
                | "aes_cbc_encrypt_data"
                | "des_cbc_encrypt_data"
                | "camellia_cbc_encrypt_data"
                | "aria_cbc_encrypt_data"
                | "seed_cbc_encrypt_data"
                | "key_derivation_string"
                | "gcm_wrap"
                | "ccm_wrap"
                | "rc5_cbc"
                | "rsa_aes_key_wrap"
                | "sign_additional_context"
                | "kmac"
                | "mu_gen"
                | "pkcs5_pbkd2"
                | "pbe"
                | "ecdh_aes_key_wrap"
                | "ecdh2_derive"
                | "ecmqv_derive"
                | "x942_dh1_derive"
                | "x942_dh2_derive"
                | "x942_mqv_derive"
                | "gostr3410_derive"
                | "gostr3410_key_wrap"
                | "key_wrap_set_oaep"
                | "ike_prf_derive"
                | "ike1_prf_derive"
                | "ike1_extended_derive"
                | "ike2_prf_plus_derive",
        )
    )
}

/// Parse a struct-sized GCM parameter buffer under v1 (R17 step-1):
/// the IV and AAD are read INDEPENDENTLY — valid-IV + NULL-AAD stays
/// ONE typed message (copied IV + `Null` AAD peer) instead of
/// discarding the IV into `Raw` (the mixed-field fix).
///
/// Shared by the v1 `"gcm"` and `"gcm_compat"` arms.
///
/// # Safety
///
/// `param_ptr` must designate a readable `CK_GCM_PARAMS` (the caller
/// gates the struct size).
unsafe fn read_gcm_struct_params_v1(
    param_ptr: *mut std::ffi::c_void,
) -> CkResult<CkMechanismParams> {
    // Safety: caller guarantees a struct-sized readable buffer.
    let gcm = unsafe { read_param_struct(param_ptr as *const CK_GCM_PARAMS)? };
    let (iv, iv_presence) = unsafe { read_pointer_field_v1(gcm.pIv as *const u8, gcm.ulIvLen)? };
    let (aad, aad_presence) =
        unsafe { read_pointer_field_v1(gcm.pAAD as *const u8, gcm.ulAADLen)? };
    Ok(CkMechanismParams::Gcm(GcmParams {
        iv,
        iv_bits: gcm.ulIvBits as u64,
        iv_buffer_len: gcm_iv_buffer_len(&gcm),
        aad: aad.into(),
        tag_bits: gcm.ulTagBits as u64,
        // v1 is presence-only end-to-end: the legacy bools stay clear
        // (the peer is authoritative) so the value round-trips through
        // the v1 wire encoding bit-identically.
        iv_null: false,
        aad_null: false,
        iv_presence,
        aad_presence,
    }))
}

/// v1 typed readers for the R17 input-pointer shapes (S2 §5 step-1
/// discipline): canonical struct reads with every embedded field
/// independent; short buffers fail closed with `PARAM_INVALID` (never
/// `Raw` — v1 never emits legacy `Raw`); unrepresentable shapes (NULL
/// nested OAEP struct) fail closed the same way. Only routed for
/// [`is_r17_v1_shape`] shapes (the dispatcher guarantees it).
///
/// # Safety
///
/// `param_ptr` must designate `param_len` readable bytes.
unsafe fn read_v1_typed_params(
    param_ptr: *mut std::ffi::c_void,
    param_len: usize,
    shape: Option<&str>,
) -> CkResult<CkMechanismParams> {
    match shape {
        Some("rsa_oaep") => {
            if param_len < std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CK_RSA_PKCS_OAEP_PARAMS.
            let oaep = unsafe { read_param_struct(param_ptr as *const CK_RSA_PKCS_OAEP_PARAMS)? };
            let (source_data, source_data_presence) = unsafe {
                read_pointer_field_v1(oaep.pSourceData as *const u8, oaep.ulSourceDataLen)?
            };
            Ok(CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
                hash_alg: CkMechanismType(oaep.hashAlg as u64),
                mgf: CkMgf(oaep.mgf as u64),
                source: CkOaepSource(oaep.source as u64),
                source_data: source_data.into(),
                // v1 is presence-only end-to-end (see the GCM reader).
                source_null: false,
                source_data_presence,
            }))
        }

        Some("gcm") => {
            if param_len < std::mem::size_of::<CK_GCM_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            unsafe { read_gcm_struct_params_v1(param_ptr) }
        }

        Some("gcm_compat") => {
            // GMAC dual encoding (T20), v1 edition: bare IV bytes stay
            // `Iv`; struct-sized buffers take the v1 GCM struct reader.
            if param_len < std::mem::size_of::<CK_GCM_PARAMS>() {
                let iv = unsafe { read_raw_bytes(param_ptr, param_len)? };
                Ok(CkMechanismParams::Iv(IvParams { iv }))
            } else {
                unsafe { read_gcm_struct_params_v1(param_ptr) }
            }
        }

        Some("ccm") => {
            if param_len < std::mem::size_of::<CK_CCM_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CK_CCM_PARAMS.
            let ccm = unsafe { read_param_struct(param_ptr as *const CK_CCM_PARAMS)? };
            let (nonce, nonce_presence) =
                unsafe { read_pointer_field_v1(ccm.pNonce as *const u8, ccm.ulNonceLen)? };
            let (aad, aad_presence) =
                unsafe { read_pointer_field_v1(ccm.pAAD as *const u8, ccm.ulAADLen)? };
            Ok(CkMechanismParams::Ccm(CcmParams {
                data_len: ccm.ulDataLen as u64,
                nonce,
                aad: aad.into(),
                mac_len: ccm.ulMACLen as u64,
                nonce_null: false,
                aad_null: false,
                nonce_presence,
                aad_presence,
            }))
        }

        Some("ecdh1_derive") => {
            if param_len < std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CK_ECDH1_DERIVE_PARAMS.
            let ecdh = unsafe { read_param_struct(param_ptr as *const CK_ECDH1_DERIVE_PARAMS)? };
            let (shared_data, shared_data_presence) = unsafe {
                read_pointer_field_v1(ecdh.pSharedData as *const u8, ecdh.ulSharedDataLen)?
            };
            let (public_data, public_data_presence) = unsafe {
                read_pointer_field_v1(ecdh.pPublicData as *const u8, ecdh.ulPublicDataLen)?
            };
            Ok(CkMechanismParams::Ecdh1Derive(Ecdh1DeriveParams {
                kdf: CkKdf(ecdh.kdf as u64),
                shared_data: shared_data.into(),
                public_data,
                shared_data_presence,
                public_data_presence,
            }))
        }

        Some("hkdf") => {
            if param_len < std::mem::size_of::<CK_HKDF_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CK_HKDF_PARAMS.
            let hkdf = unsafe { read_param_struct(param_ptr as *const CK_HKDF_PARAMS)? };
            let (salt, salt_presence) =
                unsafe { read_pointer_field_v1(hkdf.pSalt as *const u8, hkdf.ulSaltLen)? };
            let (info, info_presence) =
                unsafe { read_pointer_field_v1(hkdf.pInfo as *const u8, hkdf.ulInfoLen)? };
            Ok(CkMechanismParams::Hkdf(HkdfParams {
                extract: hkdf.bExtract != 0,
                expand: hkdf.bExpand != 0,
                prf_hash_mechanism: CkMechanismType(hkdf.prfHashMechanism as u64),
                salt_type: hkdf.ulSaltType as u64,
                salt: salt.into(),
                salt_key_handle: CkObjectHandle(hkdf.hSaltKey as u64),
                info: info.into(),
                salt_presence,
                info_presence,
            }))
        }

        Some("eddsa") => {
            if param_len < std::mem::size_of::<CK_EDDSA_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CK_EDDSA_PARAMS.
            let eddsa = unsafe { read_param_struct(param_ptr as *const CK_EDDSA_PARAMS)? };
            let (context_data, context_data_presence) = unsafe {
                read_pointer_field_v1(eddsa.pContextData as *const u8, eddsa.ulContextDataLen)?
            };
            Ok(CkMechanismParams::Eddsa(EddsaParams {
                ph_flag: eddsa.phFlag != 0,
                context_data: context_data.into(),
                context_data_presence,
            }))
        }

        Some("chacha20") => {
            if param_len < std::mem::size_of::<CK_CHACHA20_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CK_CHACHA20_PARAMS.
            let ch = unsafe { read_param_struct(param_ptr as *const CK_CHACHA20_PARAMS)? };
            let bc_bytes = (ch.blockCounterBits as usize).div_ceil(8);
            let nonce_bytes = (ch.ulNonceBits as usize).div_ceil(8);
            // `>=`, not `>`: on a 32-bit CK_ULONG target div_ceil(u32::MAX, 8)
            // equals MAX_SERIALIZABLE_BYTES exactly, so `>` is unreachable and
            // the guard would wild-read at the boundary (i686 SIGSEGV).
            if bc_bytes >= MAX_SERIALIZABLE_BYTES || nonce_bytes >= MAX_SERIALIZABLE_BYTES {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Bits-governed: NULL records the derived byte length.
            let (block_counter, block_counter_presence) = unsafe {
                read_pointer_field_v1(ch.pBlockCounter as *const u8, bc_bytes as CK_ULONG)?
            };
            let (nonce, nonce_presence) =
                unsafe { read_pointer_field_v1(ch.pNonce as *const u8, nonce_bytes as CK_ULONG)? };
            Ok(CkMechanismParams::ChaCha20(ChaCha20Params {
                block_counter,
                block_counter_bits: ch.blockCounterBits as u64,
                nonce,
                nonce_bits: ch.ulNonceBits as u64,
                block_counter_presence,
                nonce_presence,
            }))
        }

        Some("salsa20") => {
            if param_len < std::mem::size_of::<CK_SALSA20_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CK_SALSA20_PARAMS.
            let salsa = unsafe { read_param_struct(param_ptr as *const CK_SALSA20_PARAMS)? };
            let nonce_bytes = (salsa.ulNonceBits as usize).div_ceil(8);
            // `>=`, not `>`: see the chacha20 arm (i686 SIGSEGV).
            if nonce_bytes >= MAX_SERIALIZABLE_BYTES {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Fixed 8-byte block counter: NULL records the fixed extent.
            let (block_counter, block_counter_presence) =
                unsafe { read_pointer_field_v1(salsa.pBlockCounter as *const u8, 8)? };
            let (nonce, nonce_presence) = unsafe {
                read_pointer_field_v1(salsa.pNonce as *const u8, nonce_bytes as CK_ULONG)?
            };
            Ok(CkMechanismParams::Salsa20(Salsa20Params {
                block_counter,
                nonce,
                nonce_bits: salsa.ulNonceBits as u64,
                block_counter_presence,
                nonce_presence,
            }))
        }

        Some("salsa20_chacha20_poly1305") => {
            if param_len < std::mem::size_of::<CK_SALSA20_CHACHA20_POLY1305_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid
            // CK_SALSA20_CHACHA20_POLY1305_PARAMS.
            let sp = unsafe {
                read_param_struct(param_ptr as *const CK_SALSA20_CHACHA20_POLY1305_PARAMS)?
            };
            let (nonce, nonce_presence) =
                unsafe { read_pointer_field_v1(sp.pNonce as *const u8, sp.ulNonceLen)? };
            let (aad, aad_presence) =
                unsafe { read_pointer_field_v1(sp.pAAD as *const u8, sp.ulAADLen)? };
            Ok(CkMechanismParams::Salsa20ChaCha20Poly1305(Salsa20ChaCha20Poly1305Params {
                nonce,
                aad: aad.into(),
                nonce_presence,
                aad_presence,
            }))
        }

        Some("aes_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_AES_CBC_ENCRYPT_DATA_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid
            // CK_AES_CBC_ENCRYPT_DATA_PARAMS.
            let s =
                unsafe { read_param_struct(param_ptr as *const CK_AES_CBC_ENCRYPT_DATA_PARAMS)? };
            let (data, data_presence) =
                unsafe { read_pointer_field_v1(s.pData as *const u8, s.length)? };
            Ok(CkMechanismParams::AesCbcEncryptData(AesCbcEncryptDataParams {
                iv: s.iv.to_vec(),
                data: data.into(),
                data_presence,
            }))
        }

        Some("des_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_DES_CBC_ENCRYPT_DATA_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid
            // CK_DES_CBC_ENCRYPT_DATA_PARAMS.
            let s =
                unsafe { read_param_struct(param_ptr as *const CK_DES_CBC_ENCRYPT_DATA_PARAMS)? };
            let (data, data_presence) =
                unsafe { read_pointer_field_v1(s.pData as *const u8, s.length)? };
            Ok(CkMechanismParams::DesCbcEncryptData(DesCbcEncryptDataParams {
                iv: s.iv.to_vec(),
                data: data.into(),
                data_presence,
            }))
        }

        Some("camellia_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid
            // CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS.
            let s = unsafe {
                read_param_struct(param_ptr as *const CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS)?
            };
            let (data, data_presence) =
                unsafe { read_pointer_field_v1(s.pData as *const u8, s.length)? };
            Ok(CkMechanismParams::CamelliaCbcEncryptData(CamelliaCbcEncryptDataParams {
                iv: s.iv.to_vec(),
                data: data.into(),
                data_presence,
            }))
        }

        Some("aria_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid
            // CK_ARIA_CBC_ENCRYPT_DATA_PARAMS.
            let s =
                unsafe { read_param_struct(param_ptr as *const CK_ARIA_CBC_ENCRYPT_DATA_PARAMS)? };
            let (data, data_presence) =
                unsafe { read_pointer_field_v1(s.pData as *const u8, s.length)? };
            Ok(CkMechanismParams::AriaCbcEncryptData(AriaCbcEncryptDataParams {
                iv: s.iv.to_vec(),
                data: data.into(),
                data_presence,
            }))
        }

        Some("seed_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_SEED_CBC_ENCRYPT_DATA_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid
            // CK_SEED_CBC_ENCRYPT_DATA_PARAMS.
            let s =
                unsafe { read_param_struct(param_ptr as *const CK_SEED_CBC_ENCRYPT_DATA_PARAMS)? };
            let (data, data_presence) =
                unsafe { read_pointer_field_v1(s.pData as *const u8, s.length)? };
            Ok(CkMechanismParams::SeedCbcEncryptData(SeedCbcEncryptDataParams {
                iv: s.iv.to_vec(),
                data: data.into(),
                data_presence,
            }))
        }

        Some("key_derivation_string") => {
            if param_len < std::mem::size_of::<CK_KEY_DERIVATION_STRING_DATA>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid
            // CK_KEY_DERIVATION_STRING_DATA.
            let kds =
                unsafe { read_param_struct(param_ptr as *const CK_KEY_DERIVATION_STRING_DATA)? };
            let (data, data_presence) =
                unsafe { read_pointer_field_v1(kds.pData as *const u8, kds.ulLen)? };
            Ok(CkMechanismParams::KeyDerivationString(KeyDerivationStringData {
                data: data.into(),
                data_presence,
            }))
        }

        Some("gcm_wrap") => {
            if param_len < std::mem::size_of::<CK_GCM_WRAP_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CK_GCM_WRAP_PARAMS.
            let gw = unsafe { read_param_struct(param_ptr as *const CK_GCM_WRAP_PARAMS)? };
            let (iv, iv_presence) =
                unsafe { read_pointer_field_v1(gw.pIv as *const u8, gw.ulIvLen)? };
            let (aad, aad_presence) =
                unsafe { read_pointer_field_v1(gw.pAAD as *const u8, gw.ulAADLen)? };
            Ok(CkMechanismParams::GcmWrap(GcmWrapParams {
                iv,
                iv_fixed_bits: gw.ulIvFixedBits as u64,
                iv_generator: CkGeneratorFunction(gw.ivGenerator as u64),
                aad: aad.into(),
                tag_bits: gw.ulTagBits as u64,
                iv_presence,
                aad_presence,
            }))
        }

        Some("ccm_wrap") => {
            if param_len < std::mem::size_of::<CK_CCM_WRAP_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CK_CCM_WRAP_PARAMS.
            let cw = unsafe { read_param_struct(param_ptr as *const CK_CCM_WRAP_PARAMS)? };
            let (nonce, nonce_presence) =
                unsafe { read_pointer_field_v1(cw.pNonce as *const u8, cw.ulNonceLen)? };
            let (aad, aad_presence) =
                unsafe { read_pointer_field_v1(cw.pAAD as *const u8, cw.ulAADLen)? };
            Ok(CkMechanismParams::CcmWrap(CcmWrapParams {
                data_len: cw.ulDataLen as u64,
                nonce,
                nonce_fixed_bits: cw.ulNonceFixedBits as u64,
                nonce_generator: CkGeneratorFunction(cw.nonceGenerator as u64),
                aad: aad.into(),
                mac_len: cw.ulMACLen as u64,
                nonce_presence,
                aad_presence,
            }))
        }

        Some("rc5_cbc") => {
            if param_len < std::mem::size_of::<CK_RC5_CBC_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CK_RC5_CBC_PARAMS.
            let rc5 = unsafe { read_param_struct(param_ptr as *const CK_RC5_CBC_PARAMS)? };
            let (iv, iv_presence) =
                unsafe { read_pointer_field_v1(rc5.pIv as *const u8, rc5.ulIvLen)? };
            Ok(CkMechanismParams::Rc5Cbc(Rc5CbcParams {
                word_size: rc5.ulWordsize as u64,
                rounds: rc5.ulRounds as u64,
                iv,
                iv_presence,
            }))
        }

        Some("rsa_aes_key_wrap") => {
            // CK_RSA_AES_KEY_WRAP_PARAMS: { CK_ULONG ulAESKeyBits,
            //                                CK_RSA_PKCS_OAEP_PARAMS_PTR pOAEPParams }
            // Fields are read manually (not via read_param_struct) so the
            // offsets stay packed-tolerant on LLP64 (W1-C6-03).
            let expected_size =
                std::mem::size_of::<CK_ULONG>() + std::mem::size_of::<*mut std::ffi::c_void>();
            if param_len < expected_size {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Extent first: the offset arithmetic below stays inside a
            // wrap-checked range (T03).
            checked_extent(
                param_ptr as usize,
                expected_size as u64,
                1,
                MAX_MECHANISM_PARAM_STRUCT_LEN,
            )
            .map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
            // Safety: param_ptr is valid for at least expected_size bytes.
            // Unaligned-safe: a pack(1) caller struct may place 8-byte
            // fields at misaligned offsets (W1-C6-03, W1-L1-01).
            let aes_key_bits = unsafe { (param_ptr as *const CK_ULONG).read_unaligned() };
            let oaep_ptr_offset = std::mem::size_of::<CK_ULONG>();
            let oaep_ptr = unsafe {
                (param_ptr.add(oaep_ptr_offset) as *const *const CK_RSA_PKCS_OAEP_PARAMS)
                    .read_unaligned()
            };
            // A NULL nested OAEP struct is unrepresentable in v1 (nested
            // presence is an R18 tail concept) → local MPI, never Raw.
            if oaep_ptr.is_null() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: oaep_ptr is non-null and points to a valid
            // CK_RSA_PKCS_OAEP_PARAMS (caller contract).
            let oaep = unsafe { read_param_struct(oaep_ptr)? };
            let (source_data, source_data_presence) = unsafe {
                read_pointer_field_v1(oaep.pSourceData as *const u8, oaep.ulSourceDataLen)?
            };
            Ok(CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams {
                aes_key_bits: aes_key_bits as u64,
                oaep_params: RsaPkcsOaepParams {
                    hash_alg: CkMechanismType(oaep.hashAlg as u64),
                    mgf: CkMgf(oaep.mgf as u64),
                    source: CkOaepSource(oaep.source as u64),
                    source_data: source_data.into(),
                    source_null: false,
                    source_data_presence,
                },
            }))
        }

        Some("sign_additional_context") => {
            // Accept both CK_SIGN_ADDITIONAL_CONTEXT
            //   { CK_ULONG hedgeVariant, CK_BYTE_PTR pContext, CK_ULONG ulContextLen }
            // and CK_HASH_SIGN_ADDITIONAL_CONTEXT (the same, plus a trailing
            //   CK_MECHANISM_TYPE hash) used by the generic CKM_HASH_ML_DSA /
            // CKM_HASH_SLH_DSA. The larger struct is detected by ulParameterLen.
            let base_size = std::mem::size_of::<CK_ULONG>()
                + std::mem::size_of::<*mut u8>()
                + std::mem::size_of::<CK_ULONG>();
            let hash_size = base_size + std::mem::size_of::<CK_ULONG>();
            if param_len < base_size {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Extent first: the offset arithmetic below stays inside a
            // wrap-checked range (T03). Guarded at hash_size, the
            // largest the reads below ever reach.
            checked_extent(param_ptr as usize, hash_size as u64, 1, MAX_MECHANISM_PARAM_STRUCT_LEN)
                .map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
            // Unaligned-safe: see the rsa_aes_key_wrap arm above (W1-C6-03,
            // W1-L1-01). Offsets unchanged.
            let hedge_variant = unsafe { (param_ptr as *const CK_ULONG).read_unaligned() };
            let ptr_offset = std::mem::size_of::<CK_ULONG>();
            let ctx_ptr =
                unsafe { (param_ptr.add(ptr_offset) as *const *const u8).read_unaligned() };
            let len_offset = ptr_offset + std::mem::size_of::<*const u8>();
            let ctx_len =
                unsafe { (param_ptr.add(len_offset) as *const CK_ULONG).read_unaligned() };
            let (context, context_presence) = unsafe { read_pointer_field_v1(ctx_ptr, ctx_len)? };
            let hash = if param_len >= hash_size {
                let hash_offset = len_offset + std::mem::size_of::<CK_ULONG>();
                unsafe { (param_ptr.add(hash_offset) as *const CK_ULONG).read_unaligned() as u64 }
            } else {
                0
            };
            Ok(CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
                hedge_variant: hedge_variant as u64,
                context: context.into(),
                hash: CkMechanismType(hash),
                context_presence,
            }))
        }

        Some("kmac") => {
            if param_len < std::mem::size_of::<CkKmacParams>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CkKmacParams.
            let p = unsafe { read_param_struct(param_ptr as *const CkKmacParams)? };
            let (customization_string, customization_string_presence) = unsafe {
                read_pointer_field_v1(
                    p.p_customization_string as *const u8,
                    p.ul_customization_string_len,
                )?
            };
            Ok(CkMechanismParams::Kmac(KmacParams {
                key_handle: CkObjectHandle(p.h_key as u64),
                mac_length: p.ul_mac_length as u64,
                customization_string: customization_string.into(),
                customization_string_presence,
            }))
        }

        Some("mu_gen") => {
            if param_len < std::mem::size_of::<CkMuGenParams>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CkMuGenParams.
            let p = unsafe { read_param_struct(param_ptr as *const CkMuGenParams)? };
            let (tr, tr_presence) =
                unsafe { read_pointer_field_v1(p.p_tr as *const u8, p.ul_tr_len)? };
            let (context, context_presence) =
                unsafe { read_pointer_field_v1(p.p_ctx as *const u8, p.ul_ctx_len)? };
            Ok(CkMechanismParams::MuGen(MuGenParams {
                key_handle: CkObjectHandle(p.h_key as u64),
                tr: tr.into(),
                context: context.into(),
                tr_presence,
                context_presence,
            }))
        }

        Some("pkcs5_pbkd2") => {
            if param_len < std::mem::size_of::<CK_PKCS5_PBKD2_PARAMS2>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CK_PKCS5_PBKD2_PARAMS2.
            let p = unsafe { read_param_struct(param_ptr as *const CK_PKCS5_PBKD2_PARAMS2)? };
            let (salt_source_data, salt_source_data_presence) = unsafe {
                read_pointer_field_v1(p.pSaltSourceData as *const u8, p.ulSaltSourceDataLen)?
            };
            let (prf_data, prf_data_presence) =
                unsafe { read_pointer_field_v1(p.pPrfData as *const u8, p.ulPrfDataLen)? };
            let (password, password_presence) =
                unsafe { read_pointer_field_v1(p.pPassword as *const u8, p.ulPasswordLen)? };
            Ok(CkMechanismParams::Pkcs5Pbkd2(Pkcs5Pbkd2Params {
                salt_source: CkPbkdf2SaltSource(p.saltSource as u64),
                salt_source_data: salt_source_data.into(),
                iterations: p.iterations as u64,
                prf: CkPbkdf2Prf(p.prf as u64),
                prf_data: prf_data.into(),
                password: password.into(),
                salt_source_data_presence,
                prf_data_presence,
                password_presence,
            }))
        }

        Some("pbe") => {
            if param_len < std::mem::size_of::<CK_PBE_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CK_PBE_PARAMS.
            let p = unsafe { read_param_struct(param_ptr as *const CK_PBE_PARAMS)? };
            // PBE init vector is typically 8 bytes but length is not explicit
            // in the struct (legacy rule preserved): fixed extent 8, with
            // NULL recording the fixed extent.
            let (init_vector, init_vector_presence) =
                unsafe { read_pointer_field_v1(p.pInitVector as *const u8, 8)? };
            let (password, password_presence) =
                unsafe { read_pointer_field_v1(p.pPassword as *const u8, p.ulPasswordLen)? };
            let (salt, salt_presence) =
                unsafe { read_pointer_field_v1(p.pSalt as *const u8, p.ulSaltLen)? };
            Ok(CkMechanismParams::Pbe(PbeParams {
                init_vector: init_vector.into(),
                password: password.into(),
                salt: salt.into(),
                iteration: p.ulIteration as u64,
                init_vector_presence,
                password_presence,
                salt_presence,
            }))
        }

        Some("ecdh_aes_key_wrap") => {
            if param_len < std::mem::size_of::<CK_ECDH_AES_KEY_WRAP_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid
            // CK_ECDH_AES_KEY_WRAP_PARAMS.
            let p = unsafe { read_param_struct(param_ptr as *const CK_ECDH_AES_KEY_WRAP_PARAMS)? };
            let (shared_data, shared_data_presence) =
                unsafe { read_pointer_field_v1(p.pSharedData as *const u8, p.ulSharedDataLen)? };
            Ok(CkMechanismParams::EcdhAesKeyWrap(EcdhAesKeyWrapParams {
                aes_key_bits: p.ulAESKeyBits as u64,
                kdf: CkKdf(p.kdf as u64),
                shared_data: shared_data.into(),
                shared_data_presence,
            }))
        }

        Some("ecdh2_derive") => {
            if param_len < std::mem::size_of::<CK_ECDH2_DERIVE_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CK_ECDH2_DERIVE_PARAMS.
            let p = unsafe { read_param_struct(param_ptr as *const CK_ECDH2_DERIVE_PARAMS)? };
            let (shared_data, shared_data_presence) =
                unsafe { read_pointer_field_v1(p.pSharedData as *const u8, p.ulSharedDataLen)? };
            let (public_data, public_data_presence) =
                unsafe { read_pointer_field_v1(p.pPublicData as *const u8, p.ulPublicDataLen)? };
            let (public_data2, public_data2_presence) =
                unsafe { read_pointer_field_v1(p.pPublicData2 as *const u8, p.ulPublicDataLen2)? };
            Ok(CkMechanismParams::Ecdh2Derive(Ecdh2DeriveParams {
                kdf: CkKdf(p.kdf as u64),
                shared_data: shared_data.into(),
                public_data,
                private_data_len: p.ulPrivateDataLen as u64,
                private_data_handle: CkObjectHandle(p.hPrivateData as u64),
                public_data2,
                shared_data_presence,
                public_data_presence,
                public_data2_presence,
            }))
        }

        Some("ecmqv_derive") => {
            if param_len < std::mem::size_of::<CK_ECMQV_DERIVE_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CK_ECMQV_DERIVE_PARAMS.
            let p = unsafe { read_param_struct(param_ptr as *const CK_ECMQV_DERIVE_PARAMS)? };
            let (shared_data, shared_data_presence) =
                unsafe { read_pointer_field_v1(p.pSharedData as *const u8, p.ulSharedDataLen)? };
            let (public_data, public_data_presence) =
                unsafe { read_pointer_field_v1(p.pPublicData as *const u8, p.ulPublicDataLen)? };
            let (public_data2, public_data2_presence) =
                unsafe { read_pointer_field_v1(p.pPublicData2 as *const u8, p.ulPublicDataLen2)? };
            Ok(CkMechanismParams::EcmqvDerive(EcmqvDeriveParams {
                kdf: CkKdf(p.kdf as u64),
                shared_data: shared_data.into(),
                public_data,
                private_data_len: p.ulPrivateDataLen as u64,
                private_data_handle: CkObjectHandle(p.hPrivateData as u64),
                public_data2,
                public_key_handle: CkObjectHandle(p.publicKey as u64),
                shared_data_presence,
                public_data_presence,
                public_data2_presence,
            }))
        }

        Some("x942_dh1_derive") => {
            if param_len < std::mem::size_of::<CK_X9_42_DH1_DERIVE_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid
            // CK_X9_42_DH1_DERIVE_PARAMS.
            let p = unsafe { read_param_struct(param_ptr as *const CK_X9_42_DH1_DERIVE_PARAMS)? };
            let (other_info, other_info_presence) =
                unsafe { read_pointer_field_v1(p.pOtherInfo as *const u8, p.ulOtherInfoLen)? };
            let (public_data, public_data_presence) =
                unsafe { read_pointer_field_v1(p.pPublicData as *const u8, p.ulPublicDataLen)? };
            Ok(CkMechanismParams::X942Dh1Derive(X942Dh1DeriveParams {
                kdf: CkKdf(p.kdf as u64),
                other_info: other_info.into(),
                public_data,
                other_info_presence,
                public_data_presence,
            }))
        }

        Some("x942_dh2_derive") => {
            if param_len < std::mem::size_of::<CK_X9_42_DH2_DERIVE_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid
            // CK_X9_42_DH2_DERIVE_PARAMS.
            let p = unsafe { read_param_struct(param_ptr as *const CK_X9_42_DH2_DERIVE_PARAMS)? };
            let (other_info, other_info_presence) =
                unsafe { read_pointer_field_v1(p.pOtherInfo as *const u8, p.ulOtherInfoLen)? };
            let (public_data, public_data_presence) =
                unsafe { read_pointer_field_v1(p.pPublicData as *const u8, p.ulPublicDataLen)? };
            let (public_data2, public_data2_presence) =
                unsafe { read_pointer_field_v1(p.pPublicData2 as *const u8, p.ulPublicDataLen2)? };
            Ok(CkMechanismParams::X942Dh2Derive(X942Dh2DeriveParams {
                kdf: CkKdf(p.kdf as u64),
                other_info: other_info.into(),
                public_data,
                private_data_len: p.ulPrivateDataLen as u64,
                private_data_handle: CkObjectHandle(p.hPrivateData as u64),
                public_data2,
                other_info_presence,
                public_data_presence,
                public_data2_presence,
            }))
        }

        Some("x942_mqv_derive") => {
            if param_len < std::mem::size_of::<CK_X9_42_MQV_DERIVE_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid
            // CK_X9_42_MQV_DERIVE_PARAMS.
            let p = unsafe { read_param_struct(param_ptr as *const CK_X9_42_MQV_DERIVE_PARAMS)? };
            let (other_info, other_info_presence) =
                unsafe { read_pointer_field_v1(p.OtherInfo as *const u8, p.ulOtherInfoLen)? };
            let (public_data, public_data_presence) =
                unsafe { read_pointer_field_v1(p.PublicData as *const u8, p.ulPublicDataLen)? };
            let (public_data2, public_data2_presence) =
                unsafe { read_pointer_field_v1(p.PublicData2 as *const u8, p.ulPublicDataLen2)? };
            Ok(CkMechanismParams::X942MqvDerive(X942MqvDeriveParams {
                kdf: CkKdf(p.kdf as u64),
                other_info: other_info.into(),
                public_data,
                private_data_len: p.ulPrivateDataLen as u64,
                private_data_handle: CkObjectHandle(p.hPrivateData as u64),
                public_data2,
                public_key_handle: CkObjectHandle(p.publicKey as u64),
                other_info_presence,
                public_data_presence,
                public_data2_presence,
            }))
        }

        Some("gostr3410_derive") => {
            if param_len < std::mem::size_of::<CK_GOSTR3410_DERIVE_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid
            // CK_GOSTR3410_DERIVE_PARAMS.
            let p = unsafe { read_param_struct(param_ptr as *const CK_GOSTR3410_DERIVE_PARAMS)? };
            let (public_data, public_data_presence) =
                unsafe { read_pointer_field_v1(p.pPublicData as *const u8, p.ulPublicDataLen)? };
            let (ukm, ukm_presence) =
                unsafe { read_pointer_field_v1(p.pUKM as *const u8, p.ulUKMLen)? };
            Ok(CkMechanismParams::Gostr3410Derive(Gostr3410DeriveParams {
                kdf: CkKdf(p.kdf as u64),
                public_data,
                ukm,
                public_data_presence,
                ukm_presence,
            }))
        }

        Some("gostr3410_key_wrap") => {
            if param_len < std::mem::size_of::<CK_GOSTR3410_KEY_WRAP_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid
            // CK_GOSTR3410_KEY_WRAP_PARAMS.
            let p = unsafe { read_param_struct(param_ptr as *const CK_GOSTR3410_KEY_WRAP_PARAMS)? };
            let (wrap_oid, wrap_oid_presence) =
                unsafe { read_pointer_field_v1(p.pWrapOID as *const u8, p.ulWrapOIDLen)? };
            let (ukm, ukm_presence) =
                unsafe { read_pointer_field_v1(p.pUKM as *const u8, p.ulUKMLen)? };
            Ok(CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
                wrap_oid,
                ukm,
                key_handle: CkObjectHandle(p.hKey as u64),
                wrap_oid_presence,
                ukm_presence,
            }))
        }

        Some("key_wrap_set_oaep") => {
            if param_len < std::mem::size_of::<CK_KEY_WRAP_SET_OAEP_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid
            // CK_KEY_WRAP_SET_OAEP_PARAMS.
            let p = unsafe { read_param_struct(param_ptr as *const CK_KEY_WRAP_SET_OAEP_PARAMS)? };
            let (x, x_presence) = unsafe { read_pointer_field_v1(p.pX as *const u8, p.ulXLen)? };
            Ok(CkMechanismParams::KeyWrapSetOaep(KeyWrapSetOaepParams {
                bc: p.bBC as u32,
                x: x.into(),
                x_presence,
            }))
        }

        Some("ike_prf_derive") => {
            if param_len < std::mem::size_of::<CK_IKE_PRF_DERIVE_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CK_IKE_PRF_DERIVE_PARAMS.
            let p = unsafe { read_param_struct(param_ptr as *const CK_IKE_PRF_DERIVE_PARAMS)? };
            let (ni, ni_presence) =
                unsafe { read_pointer_field_v1(p.pNi as *const u8, p.ulNiLen)? };
            let (nr, nr_presence) =
                unsafe { read_pointer_field_v1(p.pNr as *const u8, p.ulNrLen)? };
            Ok(CkMechanismParams::IkePrfDerive(IkePrfDeriveParams {
                prf_mechanism: CkMechanismType(p.prfMechanism as u64),
                data_as_key: p.bDataAsKey != 0,
                rekey: p.bRekey != 0,
                ni: ni.into(),
                nr: nr.into(),
                new_key_handle: CkObjectHandle(p.hNewKey as u64),
                ni_presence,
                nr_presence,
            }))
        }

        Some("ike1_prf_derive") => {
            if param_len < std::mem::size_of::<CK_IKE1_PRF_DERIVE_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid CK_IKE1_PRF_DERIVE_PARAMS.
            let p = unsafe { read_param_struct(param_ptr as *const CK_IKE1_PRF_DERIVE_PARAMS)? };
            let (ckyi, ckyi_presence) =
                unsafe { read_pointer_field_v1(p.pCKYi as *const u8, p.ulCKYiLen)? };
            let (ckyr, ckyr_presence) =
                unsafe { read_pointer_field_v1(p.pCKYr as *const u8, p.ulCKYrLen)? };
            Ok(CkMechanismParams::Ike1PrfDerive(Ike1PrfDeriveParams {
                prf_mechanism: CkMechanismType(p.prfMechanism as u64),
                has_prev_key: p.bHasPrevKey != 0,
                keygxy_handle: CkObjectHandle(p.hKeygxy as u64),
                prev_key_handle: CkObjectHandle(p.hPrevKey as u64),
                ckyi: ckyi.into(),
                ckyr: ckyr.into(),
                key_number: p.keyNumber as u32,
                ckyi_presence,
                ckyr_presence,
            }))
        }

        Some("ike1_extended_derive") => {
            if param_len < std::mem::size_of::<CK_IKE1_EXTENDED_DERIVE_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid
            // CK_IKE1_EXTENDED_DERIVE_PARAMS.
            let p =
                unsafe { read_param_struct(param_ptr as *const CK_IKE1_EXTENDED_DERIVE_PARAMS)? };
            let (extra_data, extra_data_presence) =
                unsafe { read_pointer_field_v1(p.pExtraData as *const u8, p.ulExtraDataLen)? };
            Ok(CkMechanismParams::Ike1ExtendedDerive(Ike1ExtendedDeriveParams {
                prf_mechanism: CkMechanismType(p.prfMechanism as u64),
                has_keygxy: p.bHasKeygxy != 0,
                keygxy_handle: CkObjectHandle(p.hKeygxy as u64),
                extra_data: extra_data.into(),
                extra_data_presence,
            }))
        }

        Some("ike2_prf_plus_derive") => {
            if param_len < std::mem::size_of::<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            // Safety: pParameter points to a valid
            // CK_IKE2_PRF_PLUS_DERIVE_PARAMS.
            let p =
                unsafe { read_param_struct(param_ptr as *const CK_IKE2_PRF_PLUS_DERIVE_PARAMS)? };
            let (seed_data, seed_data_presence) =
                unsafe { read_pointer_field_v1(p.pSeedData as *const u8, p.ulSeedDataLen)? };
            Ok(CkMechanismParams::Ike2PrfPlusDerive(Ike2PrfPlusDeriveParams {
                prf_mechanism: CkMechanismType(p.prfMechanism as u64),
                has_seed_key: p.bHasSeedKey != 0,
                seed_key_handle: CkObjectHandle(p.hSeedKey as u64),
                seed_data: seed_data.into(),
                seed_data_presence,
            }))
        }

        // Unreachable (the dispatcher only routes v1 shapes here): fail
        // closed rather than conflate.
        _ => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

/// Budget-carrying mechanism-shape reader for nested (KIP) recursion.
/// Production entries always route through here so the nesting budget is
/// enforced; the unbudgeted wrapper is a test-only seam.
///
/// # Safety
///
/// `c_mech.pParameter`, when non-null with nonzero length, must designate
/// `ulParameterLen` readable bytes containing the appropriate C struct.
pub(crate) unsafe fn read_mechanism_with_shape_budgeted(
    c_mech: &CK_MECHANISM,
    shape: Option<&str>,
    budget: &mut NestingBudget,
) -> CkResult<CkMechanism> {
    let mech_type = CkMechanismType(c_mech.mechanism as u64);

    if c_mech.pParameter.is_null() || c_mech.ulParameterLen == 0 {
        return Ok(CkMechanism { mechanism_type: mech_type, params: None });
    }

    let param_ptr = c_mech.pParameter;
    let param_len = c_mech.ulParameterLen as usize;

    let params = match shape {
        Some("iv") => {
            // Raw IV bytes — no struct, just the IV data directly. Routed
            // through the capped raw reader (T03): previously unbounded.
            let iv = unsafe { read_raw_bytes(param_ptr, param_len)? };
            Some(CkMechanismParams::Iv(IvParams { iv }))
        }

        Some("rsa_pss") => {
            if param_len < std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: caller guarantees pParameter points to a valid
                // CK_RSA_PKCS_PSS_PARAMS and ulParameterLen >= sizeof.
                let pss = unsafe { read_param_struct(param_ptr as *const CK_RSA_PKCS_PSS_PARAMS)? };
                Some(CkMechanismParams::RsaPkcsPss(RsaPkcsPssParams {
                    hash_alg: CkMechanismType(pss.hashAlg as u64),
                    mgf: CkMgf(pss.mgf as u64),
                    salt_len: pss.sLen as u64,
                }))
            }
        }

        Some("rsa_oaep") => {
            if param_len < std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: caller guarantees pParameter points to a valid
                // CK_RSA_PKCS_OAEP_PARAMS and ulParameterLen >= sizeof.
                let oaep =
                    unsafe { read_param_struct(param_ptr as *const CK_RSA_PKCS_OAEP_PARAMS)? };
                if missing_embedded_pointer(oaep.pSourceData, oaep.ulSourceDataLen)
                    || !embedded_payload_len_ok(oaep.ulSourceDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let source_data = if oaep.pSourceData.is_null() || oaep.ulSourceDataLen == 0 {
                        Vec::new()
                    } else {
                        // Safety: pSourceData is non-null, ulSourceDataLen > 0,
                        // and ulSourceDataLen <= MAX_SERIALIZABLE_BYTES (guard above).
                        unsafe {
                            payload_bytes(oaep.pSourceData as *const u8, oaep.ulSourceDataLen)?
                        }
                    };
                    let source_data_presence =
                        PointerBytes::from_legacy(&source_data, oaep.pSourceData.is_null());
                    Some(CkMechanismParams::RsaPkcsOaep(RsaPkcsOaepParams {
                        hash_alg: CkMechanismType(oaep.hashAlg as u64),
                        mgf: CkMgf(oaep.mgf as u64),
                        source: CkOaepSource(oaep.source as u64),
                        source_data: source_data.into(),
                        // F3/D2: (NULL, 0) vs (ptr, 0) must survive the
                        // crossing; (NULL, len > 0) took the Raw path above.
                        source_null: oaep.pSourceData.is_null(),
                        source_data_presence,
                    }))
                }
            }
        }

        Some("gcm") => {
            if param_len < std::mem::size_of::<CK_GCM_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                Some(unsafe { read_gcm_struct_params(param_ptr, param_len)? })
            }
        }

        Some("gcm_compat") => {
            // GMAC dual encoding (T20): 2.40-style callers pass bare IV
            // bytes, 3.x-style callers pass a CK_GCM_PARAMS struct. Length
            // tells them apart — anything shorter than the struct cannot
            // be the struct, and is flat pointer-free bytes. Forwarding a
            // struct-sized buffer verbatim would hand the backend stale
            // client pointers (daemon SIGSEGV on freehsm-c), so struct
            // halves are always parsed, never forwarded.
            if param_len < std::mem::size_of::<CK_GCM_PARAMS>() {
                let iv = unsafe { read_raw_bytes(param_ptr, param_len)? };
                Some(CkMechanismParams::Iv(IvParams { iv }))
            } else {
                Some(unsafe { read_gcm_struct_params(param_ptr, param_len)? })
            }
        }

        Some("ccm") => {
            if param_len < std::mem::size_of::<CK_CCM_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_CCM_PARAMS.
                let ccm = unsafe { read_param_struct(param_ptr as *const CK_CCM_PARAMS)? };
                if missing_embedded_pointer(ccm.pNonce, ccm.ulNonceLen)
                    || missing_embedded_pointer(ccm.pAAD, ccm.ulAADLen)
                    || !embedded_payload_len_ok(ccm.ulNonceLen)
                    || !embedded_payload_len_ok(ccm.ulAADLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let nonce = if ccm.pNonce.is_null() || ccm.ulNonceLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(ccm.pNonce as *const u8, ccm.ulNonceLen)? }
                    };
                    let aad = if ccm.pAAD.is_null() || ccm.ulAADLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(ccm.pAAD as *const u8, ccm.ulAADLen)? }
                    };
                    let nonce_presence = PointerBytes::from_legacy(&nonce, ccm.pNonce.is_null());
                    let aad_presence = PointerBytes::from_legacy(&aad, ccm.pAAD.is_null());
                    Some(CkMechanismParams::Ccm(CcmParams {
                        data_len: ccm.ulDataLen as u64,
                        nonce,
                        aad: aad.into(),
                        mac_len: ccm.ulMACLen as u64,
                        nonce_null: ccm.pNonce.is_null(),
                        aad_null: ccm.pAAD.is_null(),
                        nonce_presence,
                        aad_presence,
                    }))
                }
            }
        }

        Some("ecdh1_derive") => {
            if param_len < std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_ECDH1_DERIVE_PARAMS.
                let ecdh =
                    unsafe { read_param_struct(param_ptr as *const CK_ECDH1_DERIVE_PARAMS)? };
                if missing_embedded_pointer(ecdh.pSharedData, ecdh.ulSharedDataLen)
                    || missing_embedded_pointer(ecdh.pPublicData, ecdh.ulPublicDataLen)
                    || !embedded_payload_len_ok(ecdh.ulSharedDataLen)
                    || !embedded_payload_len_ok(ecdh.ulPublicDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let shared_data = if ecdh.pSharedData.is_null() || ecdh.ulSharedDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            payload_bytes(ecdh.pSharedData as *const u8, ecdh.ulSharedDataLen)?
                        }
                    };
                    let public_data = if ecdh.pPublicData.is_null() || ecdh.ulPublicDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            payload_bytes(ecdh.pPublicData as *const u8, ecdh.ulPublicDataLen)?
                        }
                    };
                    let shared_data_presence = PointerBytes::present_copy(&shared_data);
                    let public_data_presence = PointerBytes::present_copy(&public_data);
                    Some(CkMechanismParams::Ecdh1Derive(Ecdh1DeriveParams {
                        kdf: CkKdf(ecdh.kdf as u64),
                        shared_data: shared_data.into(),
                        public_data,
                        shared_data_presence,
                        public_data_presence,
                    }))
                }
            }
        }

        Some("aes_ctr") => {
            if param_len < std::mem::size_of::<CK_AES_CTR_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_AES_CTR_PARAMS.
                let ctr = unsafe { read_param_struct(param_ptr as *const CK_AES_CTR_PARAMS)? };
                Some(CkMechanismParams::AesCtr(AesCtrParams {
                    counter_bits: ctr.ulCounterBits as u64,
                    cb: ctr.cb.to_vec(),
                }))
            }
        }

        Some("camellia_ctr") => {
            if param_len < std::mem::size_of::<CK_CAMELLIA_CTR_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_CAMELLIA_CTR_PARAMS.
                let ctr = unsafe { read_param_struct(param_ptr as *const CK_CAMELLIA_CTR_PARAMS)? };
                Some(CkMechanismParams::CamelliaCtr(CamelliaCtrParams {
                    counter_bits: ctr.ulCounterBits as u64,
                    cb: ctr.cb.to_vec(),
                }))
            }
        }

        Some("hkdf") => {
            if param_len < std::mem::size_of::<CK_HKDF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_HKDF_PARAMS.
                let hkdf = unsafe { read_param_struct(param_ptr as *const CK_HKDF_PARAMS)? };
                if missing_embedded_pointer(hkdf.pSalt, hkdf.ulSaltLen)
                    || missing_embedded_pointer(hkdf.pInfo, hkdf.ulInfoLen)
                    || !embedded_payload_len_ok(hkdf.ulSaltLen)
                    || !embedded_payload_len_ok(hkdf.ulInfoLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let salt = if hkdf.pSalt.is_null() || hkdf.ulSaltLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(hkdf.pSalt as *const u8, hkdf.ulSaltLen)? }
                    };
                    let info = if hkdf.pInfo.is_null() || hkdf.ulInfoLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(hkdf.pInfo as *const u8, hkdf.ulInfoLen)? }
                    };
                    let salt_presence = PointerBytes::present_copy(&salt);
                    let info_presence = PointerBytes::present_copy(&info);
                    Some(CkMechanismParams::Hkdf(HkdfParams {
                        extract: hkdf.bExtract != 0,
                        expand: hkdf.bExpand != 0,
                        prf_hash_mechanism: CkMechanismType(hkdf.prfHashMechanism as u64),
                        salt_type: hkdf.ulSaltType as u64,
                        salt: salt.into(),
                        salt_key_handle: CkObjectHandle(hkdf.hSaltKey as u64),
                        info: info.into(),
                        salt_presence,
                        info_presence,
                    }))
                }
            }
        }

        Some("eddsa") => {
            if param_len < std::mem::size_of::<CK_EDDSA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_EDDSA_PARAMS.
                let eddsa = unsafe { read_param_struct(param_ptr as *const CK_EDDSA_PARAMS)? };
                if missing_embedded_pointer(eddsa.pContextData, eddsa.ulContextDataLen)
                    || !embedded_payload_len_ok(eddsa.ulContextDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let context_data = if eddsa.pContextData.is_null()
                        || eddsa.ulContextDataLen == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            payload_bytes(eddsa.pContextData as *const u8, eddsa.ulContextDataLen)?
                        }
                    };
                    let context_data_presence = PointerBytes::present_copy(&context_data);
                    Some(CkMechanismParams::Eddsa(EddsaParams {
                        ph_flag: eddsa.phFlag != 0,
                        context_data: context_data.into(),
                        context_data_presence,
                    }))
                }
            }
        }

        Some("chacha20") => {
            if param_len < std::mem::size_of::<CK_CHACHA20_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_CHACHA20_PARAMS.
                let ch = unsafe { read_param_struct(param_ptr as *const CK_CHACHA20_PARAMS)? };
                let bc_bytes = (ch.blockCounterBits as usize).div_ceil(8);
                let nonce_bytes = (ch.ulNonceBits as usize).div_ceil(8);
                // `>=`, not `>`: on a 32-bit CK_ULONG target div_ceil(u32::MAX, 8)
                // equals MAX_SERIALIZABLE_BYTES exactly, so `>` is unreachable and
                // the guard would wild-read at the boundary (i686 SIGSEGV).
                if bc_bytes >= MAX_SERIALIZABLE_BYTES || nonce_bytes >= MAX_SERIALIZABLE_BYTES {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let block_counter = if ch.pBlockCounter.is_null() {
                        Vec::new()
                    } else if bc_bytes > 0 {
                        // Safety: pBlockCounter is non-null, bc_bytes <= MAX_SERIALIZABLE_BYTES.
                        unsafe {
                            payload_bytes(ch.pBlockCounter as *const u8, bc_bytes as CK_ULONG)?
                        }
                    } else {
                        Vec::new()
                    };
                    let nonce = if ch.pNonce.is_null() || ch.ulNonceBits == 0 {
                        Vec::new()
                    } else {
                        // Safety: pNonce is non-null, nonce_bytes <= MAX_SERIALIZABLE_BYTES.
                        unsafe { payload_bytes(ch.pNonce as *const u8, nonce_bytes as CK_ULONG)? }
                    };
                    let block_counter_presence = PointerBytes::present_copy(&block_counter);
                    let nonce_presence = PointerBytes::present_copy(&nonce);
                    Some(CkMechanismParams::ChaCha20(ChaCha20Params {
                        block_counter,
                        block_counter_bits: ch.blockCounterBits as u64,
                        nonce,
                        nonce_bits: ch.ulNonceBits as u64,
                        block_counter_presence,
                        nonce_presence,
                    }))
                }
            }
        }

        Some("salsa20") => {
            if param_len < std::mem::size_of::<CK_SALSA20_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let salsa = unsafe { read_param_struct(param_ptr as *const CK_SALSA20_PARAMS)? };
                let nonce_bytes = (salsa.ulNonceBits as usize).div_ceil(8);
                // `>=`, not `>`: on a 32-bit CK_ULONG target div_ceil(u32::MAX, 8)
                // equals MAX_SERIALIZABLE_BYTES exactly, so `>` is unreachable and
                // the guard would wild-read at the boundary (i686 SIGSEGV).
                if salsa.pBlockCounter.is_null()
                    || missing_embedded_pointer(salsa.pNonce, salsa.ulNonceBits)
                    || nonce_bytes >= MAX_SERIALIZABLE_BYTES
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let block_counter =
                        unsafe { payload_bytes(salsa.pBlockCounter as *const u8, 8)? };
                    let nonce = if salsa.pNonce.is_null() || salsa.ulNonceBits == 0 {
                        Vec::new()
                    } else {
                        // Safety: pNonce is non-null, nonce_bytes <= MAX_SERIALIZABLE_BYTES.
                        unsafe {
                            payload_bytes(salsa.pNonce as *const u8, nonce_bytes as CK_ULONG)?
                        }
                    };
                    let block_counter_presence = PointerBytes::present_copy(&block_counter);
                    let nonce_presence = PointerBytes::present_copy(&nonce);
                    Some(CkMechanismParams::Salsa20(Salsa20Params {
                        block_counter,
                        nonce,
                        nonce_bits: salsa.ulNonceBits as u64,
                        block_counter_presence,
                        nonce_presence,
                    }))
                }
            }
        }

        Some("salsa20_chacha20_poly1305") => {
            if param_len < std::mem::size_of::<CK_SALSA20_CHACHA20_POLY1305_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_SALSA20_CHACHA20_POLY1305_PARAMS.
                let sp = unsafe {
                    read_param_struct(param_ptr as *const CK_SALSA20_CHACHA20_POLY1305_PARAMS)?
                };
                if missing_embedded_pointer(sp.pNonce, sp.ulNonceLen)
                    || missing_embedded_pointer(sp.pAAD, sp.ulAADLen)
                    || !embedded_payload_len_ok(sp.ulNonceLen)
                    || !embedded_payload_len_ok(sp.ulAADLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let nonce = if sp.pNonce.is_null() || sp.ulNonceLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(sp.pNonce as *const u8, sp.ulNonceLen)? }
                    };
                    let aad = if sp.pAAD.is_null() || sp.ulAADLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(sp.pAAD as *const u8, sp.ulAADLen)? }
                    };
                    let nonce_presence = PointerBytes::present_copy(&nonce);
                    let aad_presence = PointerBytes::present_copy(&aad);
                    Some(CkMechanismParams::Salsa20ChaCha20Poly1305(
                        Salsa20ChaCha20Poly1305Params {
                            nonce,
                            aad: aad.into(),
                            nonce_presence,
                            aad_presence,
                        },
                    ))
                }
            }
        }

        Some("aes_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_AES_CBC_ENCRYPT_DATA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_AES_CBC_ENCRYPT_DATA_PARAMS.
                let s = unsafe {
                    read_param_struct(param_ptr as *const CK_AES_CBC_ENCRYPT_DATA_PARAMS)?
                };
                if missing_embedded_pointer(s.pData, s.length) || !embedded_payload_len_ok(s.length)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let data = if s.pData.is_null() || s.length == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(s.pData as *const u8, s.length)? }
                    };
                    let data_presence = PointerBytes::present_copy(&data);
                    Some(CkMechanismParams::AesCbcEncryptData(AesCbcEncryptDataParams {
                        iv: s.iv.to_vec(),
                        data: data.into(),
                        data_presence,
                    }))
                }
            }
        }

        Some("des_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_DES_CBC_ENCRYPT_DATA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_DES_CBC_ENCRYPT_DATA_PARAMS.
                let s = unsafe {
                    read_param_struct(param_ptr as *const CK_DES_CBC_ENCRYPT_DATA_PARAMS)?
                };
                if missing_embedded_pointer(s.pData, s.length) || !embedded_payload_len_ok(s.length)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let data = if s.pData.is_null() || s.length == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(s.pData as *const u8, s.length)? }
                    };
                    let data_presence = PointerBytes::present_copy(&data);
                    Some(CkMechanismParams::DesCbcEncryptData(DesCbcEncryptDataParams {
                        iv: s.iv.to_vec(),
                        data: data.into(),
                        data_presence,
                    }))
                }
            }
        }

        Some("camellia_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS.
                let s = unsafe {
                    read_param_struct(param_ptr as *const CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS)?
                };
                if missing_embedded_pointer(s.pData, s.length) || !embedded_payload_len_ok(s.length)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let data = if s.pData.is_null() || s.length == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(s.pData as *const u8, s.length)? }
                    };
                    let data_presence = PointerBytes::present_copy(&data);
                    Some(CkMechanismParams::CamelliaCbcEncryptData(CamelliaCbcEncryptDataParams {
                        iv: s.iv.to_vec(),
                        data: data.into(),
                        data_presence,
                    }))
                }
            }
        }

        Some("aria_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_ARIA_CBC_ENCRYPT_DATA_PARAMS.
                let s = unsafe {
                    read_param_struct(param_ptr as *const CK_ARIA_CBC_ENCRYPT_DATA_PARAMS)?
                };
                if missing_embedded_pointer(s.pData, s.length) || !embedded_payload_len_ok(s.length)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let data = if s.pData.is_null() || s.length == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(s.pData as *const u8, s.length)? }
                    };
                    let data_presence = PointerBytes::present_copy(&data);
                    Some(CkMechanismParams::AriaCbcEncryptData(AriaCbcEncryptDataParams {
                        iv: s.iv.to_vec(),
                        data: data.into(),
                        data_presence,
                    }))
                }
            }
        }

        Some("seed_cbc_encrypt_data") => {
            if param_len < std::mem::size_of::<CK_SEED_CBC_ENCRYPT_DATA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_SEED_CBC_ENCRYPT_DATA_PARAMS.
                let s = unsafe {
                    read_param_struct(param_ptr as *const CK_SEED_CBC_ENCRYPT_DATA_PARAMS)?
                };
                if missing_embedded_pointer(s.pData, s.length) || !embedded_payload_len_ok(s.length)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let data = if s.pData.is_null() || s.length == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(s.pData as *const u8, s.length)? }
                    };
                    let data_presence = PointerBytes::present_copy(&data);
                    Some(CkMechanismParams::SeedCbcEncryptData(SeedCbcEncryptDataParams {
                        iv: s.iv.to_vec(),
                        data: data.into(),
                        data_presence,
                    }))
                }
            }
        }

        Some("mac_general") => {
            if param_len < std::mem::size_of::<CK_MAC_GENERAL_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a CK_MAC_GENERAL_PARAMS
                // (which is a CK_ULONG).
                let val = unsafe { read_param_struct(param_ptr as *const CK_MAC_GENERAL_PARAMS)? };
                Some(CkMechanismParams::MacGeneral(MacGeneralParams { mac_length: val as u64 }))
            }
        }

        Some("object_handle") => {
            if param_len < std::mem::size_of::<CK_OBJECT_HANDLE>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a CK_OBJECT_HANDLE
                // (which is a CK_ULONG).
                let val = unsafe { read_param_struct(param_ptr as *const CK_OBJECT_HANDLE)? };
                Some(CkMechanismParams::ObjectHandle(ObjectHandleParam {
                    handle: CkObjectHandle(val as u64),
                }))
            }
        }

        Some("extract") => {
            if param_len < std::mem::size_of::<CK_EXTRACT_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let val = unsafe { read_param_struct(param_ptr as *const CK_EXTRACT_PARAMS)? };
                Some(CkMechanismParams::Extract(ExtractParams { bit_position: val as u64 }))
            }
        }

        Some("key_derivation_string") => {
            if param_len < std::mem::size_of::<CK_KEY_DERIVATION_STRING_DATA>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid
                // CK_KEY_DERIVATION_STRING_DATA.
                let kds = unsafe {
                    read_param_struct(param_ptr as *const CK_KEY_DERIVATION_STRING_DATA)?
                };
                if missing_embedded_pointer(kds.pData, kds.ulLen)
                    || !embedded_payload_len_ok(kds.ulLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let data = if kds.pData.is_null() || kds.ulLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(kds.pData as *const u8, kds.ulLen)? }
                    };
                    let data_presence = PointerBytes::present_copy(&data);
                    Some(CkMechanismParams::KeyDerivationString(KeyDerivationStringData {
                        data: data.into(),
                        data_presence,
                    }))
                }
            }
        }

        Some("gcm_wrap") => {
            if param_len < std::mem::size_of::<CK_GCM_WRAP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_GCM_WRAP_PARAMS.
                let gw = unsafe { read_param_struct(param_ptr as *const CK_GCM_WRAP_PARAMS)? };
                if missing_embedded_pointer(gw.pIv, gw.ulIvLen)
                    || missing_embedded_pointer(gw.pAAD, gw.ulAADLen)
                    || !embedded_payload_len_ok(gw.ulIvLen)
                    || !embedded_payload_len_ok(gw.ulAADLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let iv = if gw.pIv.is_null() || gw.ulIvLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(gw.pIv as *const u8, gw.ulIvLen)? }
                    };
                    let aad = if gw.pAAD.is_null() || gw.ulAADLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(gw.pAAD as *const u8, gw.ulAADLen)? }
                    };
                    let iv_presence = PointerBytes::present_copy(&iv);
                    let aad_presence = PointerBytes::present_copy(&aad);
                    Some(CkMechanismParams::GcmWrap(GcmWrapParams {
                        iv,
                        iv_fixed_bits: gw.ulIvFixedBits as u64,
                        iv_generator: CkGeneratorFunction(gw.ivGenerator as u64),
                        aad: aad.into(),
                        tag_bits: gw.ulTagBits as u64,
                        iv_presence,
                        aad_presence,
                    }))
                }
            }
        }

        Some("ccm_wrap") => {
            if param_len < std::mem::size_of::<CK_CCM_WRAP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_CCM_WRAP_PARAMS.
                let cw = unsafe { read_param_struct(param_ptr as *const CK_CCM_WRAP_PARAMS)? };
                if missing_embedded_pointer(cw.pNonce, cw.ulNonceLen)
                    || missing_embedded_pointer(cw.pAAD, cw.ulAADLen)
                    || !embedded_payload_len_ok(cw.ulNonceLen)
                    || !embedded_payload_len_ok(cw.ulAADLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let nonce = if cw.pNonce.is_null() || cw.ulNonceLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(cw.pNonce as *const u8, cw.ulNonceLen)? }
                    };
                    let aad = if cw.pAAD.is_null() || cw.ulAADLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(cw.pAAD as *const u8, cw.ulAADLen)? }
                    };
                    let nonce_presence = PointerBytes::present_copy(&nonce);
                    let aad_presence = PointerBytes::present_copy(&aad);
                    Some(CkMechanismParams::CcmWrap(CcmWrapParams {
                        data_len: cw.ulDataLen as u64,
                        nonce,
                        nonce_fixed_bits: cw.ulNonceFixedBits as u64,
                        nonce_generator: CkGeneratorFunction(cw.nonceGenerator as u64),
                        aad: aad.into(),
                        mac_len: cw.ulMACLen as u64,
                        nonce_presence,
                        aad_presence,
                    }))
                }
            }
        }

        Some("rc5") => {
            if param_len < std::mem::size_of::<CK_RC5_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_RC5_PARAMS.
                let rc5 = unsafe { read_param_struct(param_ptr as *const CK_RC5_PARAMS)? };
                Some(CkMechanismParams::Rc5(Rc5Params {
                    word_size: rc5.ulWordsize as u64,
                    rounds: rc5.ulRounds as u64,
                }))
            }
        }

        Some("rc5_mac_general") => {
            if param_len < std::mem::size_of::<CK_RC5_MAC_GENERAL_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let rc5 =
                    unsafe { read_param_struct(param_ptr as *const CK_RC5_MAC_GENERAL_PARAMS)? };
                Some(CkMechanismParams::Rc5MacGeneral(Rc5MacGeneralParams {
                    word_size: rc5.ulWordsize as u64,
                    rounds: rc5.ulRounds as u64,
                    mac_length: rc5.ulMacLength as u64,
                }))
            }
        }

        Some("rc5_cbc") => {
            if param_len < std::mem::size_of::<CK_RC5_CBC_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let rc5 = unsafe { read_param_struct(param_ptr as *const CK_RC5_CBC_PARAMS)? };
                if missing_embedded_pointer(rc5.pIv, rc5.ulIvLen)
                    || !embedded_payload_len_ok(rc5.ulIvLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let iv = if rc5.pIv.is_null() || rc5.ulIvLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(rc5.pIv as *const u8, rc5.ulIvLen)? }
                    };
                    let iv_presence = PointerBytes::present_copy(&iv);
                    Some(CkMechanismParams::Rc5Cbc(Rc5CbcParams {
                        word_size: rc5.ulWordsize as u64,
                        rounds: rc5.ulRounds as u64,
                        iv,
                        iv_presence,
                    }))
                }
            }
        }

        Some("rc2_cbc") => {
            if param_len < std::mem::size_of::<CK_RC2_CBC_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_RC2_CBC_PARAMS.
                let rc2 = unsafe { read_param_struct(param_ptr as *const CK_RC2_CBC_PARAMS)? };
                Some(CkMechanismParams::Rc2Cbc(Rc2CbcParams {
                    effective_bits: rc2.ulEffectiveBits as u64,
                    iv: rc2.iv.to_vec(),
                }))
            }
        }

        Some("rc2_mac_general") => {
            if param_len < std::mem::size_of::<CK_RC2_MAC_GENERAL_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let rc2 =
                    unsafe { read_param_struct(param_ptr as *const CK_RC2_MAC_GENERAL_PARAMS)? };
                Some(CkMechanismParams::Rc2MacGeneral(Rc2MacGeneralParams {
                    effective_bits: rc2.ulEffectiveBits as u64,
                    mac_length: rc2.ulMacLength as u64,
                }))
            }
        }

        Some("xeddsa") => {
            if param_len < std::mem::size_of::<CK_XEDDSA_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_XEDDSA_PARAMS.
                let xed = unsafe { read_param_struct(param_ptr as *const CK_XEDDSA_PARAMS)? };
                Some(CkMechanismParams::Xeddsa(XeddsaParams {
                    hash: CkMechanismType(xed.hash as u64),
                }))
            }
        }

        Some("tls_mac") => {
            if param_len < std::mem::size_of::<CK_TLS_MAC_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Safety: pParameter points to a valid CK_TLS_MAC_PARAMS.
                let tls = unsafe { read_param_struct(param_ptr as *const CK_TLS_MAC_PARAMS)? };
                Some(CkMechanismParams::TlsMac(TlsMacParams {
                    prf_hash_mechanism: CkMechanismType(tls.prfHashMechanism as u64),
                    mac_length: tls.ulMacLength as u64,
                    server_or_client: tls.ulServerOrClient as u64,
                }))
            }
        }

        Some("rsa_aes_key_wrap") => {
            // CK_RSA_AES_KEY_WRAP_PARAMS: { CK_ULONG ulAESKeyBits,
            //                                CK_RSA_PKCS_OAEP_PARAMS_PTR pOAEPParams }
            // Fields are read manually (not via read_param_struct) so the
            // offsets stay packed-tolerant on LLP64 (W1-C6-03).
            let expected_size =
                std::mem::size_of::<CK_ULONG>() + std::mem::size_of::<*mut std::ffi::c_void>();
            if param_len < expected_size {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Extent first: the offset arithmetic below stays inside a
                // wrap-checked range (T03).
                checked_extent(
                    param_ptr as usize,
                    expected_size as u64,
                    1,
                    MAX_MECHANISM_PARAM_STRUCT_LEN,
                )
                .map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
                // Safety: param_ptr is valid for at least expected_size bytes.
                // Unaligned-safe: a pack(1) caller struct may place 8-byte
                // fields at misaligned offsets (W1-C6-03, W1-L1-01).
                let aes_key_bits = unsafe { (param_ptr as *const CK_ULONG).read_unaligned() };
                let oaep_ptr_offset = std::mem::size_of::<CK_ULONG>();
                let oaep_ptr = unsafe {
                    (param_ptr.add(oaep_ptr_offset) as *const *const CK_RSA_PKCS_OAEP_PARAMS)
                        .read_unaligned()
                };
                if oaep_ptr.is_null() {
                    Some(CkMechanismParams::Raw(RawMechanismParams {
                        data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                    }))
                } else {
                    // Safety: oaep_ptr is non-null and points to a valid
                    // CK_RSA_PKCS_OAEP_PARAMS (caller contract).
                    let oaep = unsafe { read_param_struct(oaep_ptr)? };
                    if missing_embedded_pointer(oaep.pSourceData as *const u8, oaep.ulSourceDataLen)
                        || !embedded_payload_len_ok(oaep.ulSourceDataLen)
                    {
                        Some(raw_mechanism_params(param_ptr, param_len)?)
                    } else {
                        let source_data = if oaep.pSourceData.is_null() || oaep.ulSourceDataLen == 0
                        {
                            Vec::new()
                        } else {
                            unsafe {
                                payload_bytes(oaep.pSourceData as *const u8, oaep.ulSourceDataLen)?
                            }
                        };
                        let source_data_presence =
                            PointerBytes::from_legacy(&source_data, oaep.pSourceData.is_null());
                        Some(CkMechanismParams::RsaAesKeyWrap(RsaAesKeyWrapParams {
                            aes_key_bits: aes_key_bits as u64,
                            oaep_params: RsaPkcsOaepParams {
                                hash_alg: CkMechanismType(oaep.hashAlg as u64),
                                mgf: CkMgf(oaep.mgf as u64),
                                source: CkOaepSource(oaep.source as u64),
                                source_data: source_data.into(),
                                source_null: oaep.pSourceData.is_null(),
                                source_data_presence,
                            },
                        }))
                    } // close inner else (source data ok)
                }
            }
        }

        Some("sign_additional_context") => {
            // Accept both CK_SIGN_ADDITIONAL_CONTEXT
            //   { CK_ULONG hedgeVariant, CK_BYTE_PTR pContext, CK_ULONG ulContextLen }
            // and CK_HASH_SIGN_ADDITIONAL_CONTEXT (the same, plus a trailing
            //   CK_MECHANISM_TYPE hash) used by the generic CKM_HASH_ML_DSA /
            // CKM_HASH_SLH_DSA. The larger struct is detected by ulParameterLen.
            let base_size = std::mem::size_of::<CK_ULONG>()
                + std::mem::size_of::<*mut u8>()
                + std::mem::size_of::<CK_ULONG>();
            let hash_size = base_size + std::mem::size_of::<CK_ULONG>();
            if param_len < base_size {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                // Extent first: the offset arithmetic below stays inside a
                // wrap-checked range (T03). Guarded at hash_size, the
                // largest the reads below ever reach.
                checked_extent(
                    param_ptr as usize,
                    hash_size as u64,
                    1,
                    MAX_MECHANISM_PARAM_STRUCT_LEN,
                )
                .map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
                // Unaligned-safe: see the rsa_aes_key_wrap arm above (W1-C6-03,
                // W1-L1-01). Offsets unchanged.
                let hedge_variant = unsafe { (param_ptr as *const CK_ULONG).read_unaligned() };
                let ptr_offset = std::mem::size_of::<CK_ULONG>();
                let ctx_ptr =
                    unsafe { (param_ptr.add(ptr_offset) as *const *const u8).read_unaligned() };
                let len_offset = ptr_offset + std::mem::size_of::<*const u8>();
                let ctx_len =
                    unsafe { (param_ptr.add(len_offset) as *const CK_ULONG).read_unaligned() };
                if missing_embedded_pointer(ctx_ptr, ctx_len) || !embedded_payload_len_ok(ctx_len) {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let context = if ctx_ptr.is_null() || ctx_len == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(ctx_ptr as *const u8, ctx_len)? }
                    };
                    let hash = if param_len >= hash_size {
                        let hash_offset = len_offset + std::mem::size_of::<CK_ULONG>();
                        unsafe {
                            (param_ptr.add(hash_offset) as *const CK_ULONG).read_unaligned() as u64
                        }
                    } else {
                        0
                    };
                    let context_presence = PointerBytes::present_copy(&context);
                    Some(CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
                        hedge_variant: hedge_variant as u64,
                        context: context.into(),
                        hash: CkMechanismType(hash),
                        context_presence,
                    }))
                }
            }
        }

        Some("kmac") => {
            if param_len < std::mem::size_of::<CkKmacParams>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { read_param_struct(param_ptr as *const CkKmacParams)? };
                if missing_embedded_pointer(
                    p.p_customization_string as *const u8,
                    p.ul_customization_string_len,
                ) || !embedded_payload_len_ok(p.ul_customization_string_len)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let customization_string = if p.p_customization_string.is_null()
                        || p.ul_customization_string_len == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            payload_bytes(
                                p.p_customization_string as *const u8,
                                p.ul_customization_string_len,
                            )?
                        }
                    };
                    let customization_string_presence =
                        PointerBytes::present_copy(&customization_string);
                    Some(CkMechanismParams::Kmac(KmacParams {
                        key_handle: CkObjectHandle(p.h_key as u64),
                        mac_length: p.ul_mac_length as u64,
                        customization_string: customization_string.into(),
                        customization_string_presence,
                    }))
                }
            }
        }

        Some("mu_gen") => {
            if param_len < std::mem::size_of::<CkMuGenParams>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { read_param_struct(param_ptr as *const CkMuGenParams)? };
                if missing_embedded_pointer(p.p_tr, p.ul_tr_len)
                    || missing_embedded_pointer(p.p_ctx, p.ul_ctx_len)
                    || !embedded_payload_len_ok(p.ul_tr_len)
                    || !embedded_payload_len_ok(p.ul_ctx_len)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let tr = if p.p_tr.is_null() || p.ul_tr_len == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.p_tr as *const u8, p.ul_tr_len)? }
                    };
                    let context = if p.p_ctx.is_null() || p.ul_ctx_len == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.p_ctx as *const u8, p.ul_ctx_len)? }
                    };
                    let tr_presence = PointerBytes::present_copy(&tr);
                    let context_presence = PointerBytes::present_copy(&context);
                    Some(CkMechanismParams::MuGen(MuGenParams {
                        key_handle: CkObjectHandle(p.h_key as u64),
                        tr: tr.into(),
                        context: context.into(),
                        tr_presence,
                        context_presence,
                    }))
                }
            }
        }

        Some("pkcs5_pbkd2") => {
            if param_len < std::mem::size_of::<CK_PKCS5_PBKD2_PARAMS2>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { read_param_struct(param_ptr as *const CK_PKCS5_PBKD2_PARAMS2)? };
                if missing_embedded_pointer(p.pSaltSourceData as *const u8, p.ulSaltSourceDataLen)
                    || missing_embedded_pointer(p.pPrfData as *const u8, p.ulPrfDataLen)
                    || missing_embedded_pointer(p.pPassword, p.ulPasswordLen)
                    || !embedded_payload_len_ok(p.ulSaltSourceDataLen)
                    || !embedded_payload_len_ok(p.ulPrfDataLen)
                    || !embedded_payload_len_ok(p.ulPasswordLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let salt_source_data = if p.pSaltSourceData.is_null()
                        || p.ulSaltSourceDataLen == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            payload_bytes(p.pSaltSourceData as *const u8, p.ulSaltSourceDataLen)?
                        }
                    };
                    let prf_data = if p.pPrfData.is_null() || p.ulPrfDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pPrfData as *const u8, p.ulPrfDataLen)? }
                    };
                    let password = if p.pPassword.is_null() || p.ulPasswordLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pPassword as *const u8, p.ulPasswordLen)? }
                    };
                    let salt_source_data_presence = PointerBytes::present_copy(&salt_source_data);
                    let prf_data_presence = PointerBytes::present_copy(&prf_data);
                    let password_presence = PointerBytes::present_copy(&password);
                    Some(CkMechanismParams::Pkcs5Pbkd2(Pkcs5Pbkd2Params {
                        salt_source: CkPbkdf2SaltSource(p.saltSource as u64),
                        salt_source_data: salt_source_data.into(),
                        iterations: p.iterations as u64,
                        prf: CkPbkdf2Prf(p.prf as u64),
                        prf_data: prf_data.into(),
                        password: password.into(),
                        salt_source_data_presence,
                        prf_data_presence,
                        password_presence,
                    }))
                }
            }
        }

        Some("wtls_master_key_derive") => {
            if param_len < std::mem::size_of::<CK_WTLS_MASTER_KEY_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe {
                    read_param_struct(param_ptr as *const CK_WTLS_MASTER_KEY_DERIVE_PARAMS)?
                };
                if missing_embedded_pointer(
                    p.RandomInfo.pClientRandom,
                    p.RandomInfo.ulClientRandomLen,
                ) || missing_embedded_pointer(
                    p.RandomInfo.pServerRandom,
                    p.RandomInfo.ulServerRandomLen,
                ) || !embedded_payload_len_ok(p.RandomInfo.ulClientRandomLen)
                    || !embedded_payload_len_ok(p.RandomInfo.ulServerRandomLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let client_random = if p.RandomInfo.pClientRandom.is_null()
                        || p.RandomInfo.ulClientRandomLen == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            payload_bytes(
                                p.RandomInfo.pClientRandom as *const u8,
                                p.RandomInfo.ulClientRandomLen,
                            )?
                        }
                    };
                    let server_random = if p.RandomInfo.pServerRandom.is_null()
                        || p.RandomInfo.ulServerRandomLen == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            payload_bytes(
                                p.RandomInfo.pServerRandom as *const u8,
                                p.RandomInfo.ulServerRandomLen,
                            )?
                        }
                    };
                    let version = if p.pVersion.is_null() {
                        0
                    } else {
                        unsafe { p.pVersion.read_unaligned() as u32 }
                    };
                    Some(CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
                        digest_mechanism: CkMechanismType(p.DigestMechanism as u64),
                        random_info: WtlsRandomData { client_random, server_random },
                        version,
                    }))
                }
            }
        }

        Some("wtls_prf") => {
            if param_len < std::mem::size_of::<CK_WTLS_PRF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { read_param_struct(param_ptr as *const CK_WTLS_PRF_PARAMS)? };
                if missing_embedded_pointer(p.pSeed, p.ulSeedLen)
                    || missing_embedded_pointer(p.pLabel, p.ulLabelLen)
                    || !embedded_payload_len_ok(p.ulSeedLen)
                    || !embedded_payload_len_ok(p.ulLabelLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let seed = if p.pSeed.is_null() || p.ulSeedLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pSeed as *const u8, p.ulSeedLen)? }
                    };
                    let label = if p.pLabel.is_null() || p.ulLabelLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pLabel as *const u8, p.ulLabelLen)? }
                    };
                    let output_len = if p.pulOutputLen.is_null() {
                        0
                    } else {
                        unsafe { p.pulOutputLen.read_unaligned() as u64 }
                    };
                    Some(CkMechanismParams::WtlsPrf(WtlsPrfParams {
                        digest_mechanism: CkMechanismType(p.DigestMechanism as u64),
                        seed: seed.into(),
                        label: label.into(),
                        output_len,
                        // W1-C5-01: `pOutput` is OUT — never read the
                        // caller's uninitialized buffer into the request.
                        output: Vec::new().into(),
                    }))
                }
            }
        }

        Some("wtls_key_mat") => {
            if param_len < std::mem::size_of::<CK_WTLS_KEY_MAT_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { read_param_struct(param_ptr as *const CK_WTLS_KEY_MAT_PARAMS)? };
                let requested_iv_len = ((p.ulIVSizeInBits as usize).saturating_add(7)) / 8;
                if missing_embedded_pointer(
                    p.RandomInfo.pClientRandom,
                    p.RandomInfo.ulClientRandomLen,
                ) || missing_embedded_pointer(
                    p.RandomInfo.pServerRandom,
                    p.RandomInfo.ulServerRandomLen,
                ) || p.pReturnedKeyMaterial.is_null()
                    || requested_iv_len > MAX_SERIALIZABLE_BYTES
                    || !embedded_payload_len_ok(p.RandomInfo.ulClientRandomLen)
                    || !embedded_payload_len_ok(p.RandomInfo.ulServerRandomLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let iv_len = requested_iv_len;
                    let output = unsafe { read_param_struct(p.pReturnedKeyMaterial)? };
                    if missing_embedded_pointer(output.pIV, iv_len as CK_ULONG) {
                        Some(raw_mechanism_params(param_ptr, param_len)?)
                    } else {
                        let client_random = if p.RandomInfo.pClientRandom.is_null()
                            || p.RandomInfo.ulClientRandomLen == 0
                        {
                            Vec::new()
                        } else {
                            unsafe {
                                payload_bytes(
                                    p.RandomInfo.pClientRandom as *const u8,
                                    p.RandomInfo.ulClientRandomLen,
                                )?
                            }
                        };
                        let server_random = if p.RandomInfo.pServerRandom.is_null()
                            || p.RandomInfo.ulServerRandomLen == 0
                        {
                            Vec::new()
                        } else {
                            unsafe {
                                payload_bytes(
                                    p.RandomInfo.pServerRandom as *const u8,
                                    p.RandomInfo.ulServerRandomLen,
                                )?
                            }
                        };
                        let iv = if output.pIV.is_null() || iv_len == 0 {
                            Vec::new()
                        } else {
                            unsafe { payload_bytes(output.pIV as *const u8, iv_len as CK_ULONG)? }
                        };
                        Some(CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
                            digest_mechanism: CkMechanismType(p.DigestMechanism as u64),
                            mac_size_bits: p.ulMacSizeInBits as u64,
                            key_size_bits: p.ulKeySizeInBits as u64,
                            iv_size_bits: p.ulIVSizeInBits as u64,
                            sequence_number: p.ulSequenceNumber as u64,
                            is_export: p.bIsExport != 0,
                            random_info: WtlsRandomData { client_random, server_random },
                            mac_secret_handle: CkObjectHandle(output.hMacSecret as u64),
                            key_handle: CkObjectHandle(output.hKey as u64),
                            iv: iv.into(),
                        }))
                    }
                }
            }
        }

        Some("tls12_master_key_derive") => {
            if param_len < std::mem::size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe {
                    read_param_struct(param_ptr as *const CK_TLS12_MASTER_KEY_DERIVE_PARAMS)?
                };
                if missing_embedded_pointer(
                    p.RandomInfo.pClientRandom,
                    p.RandomInfo.ulClientRandomLen,
                ) || missing_embedded_pointer(
                    p.RandomInfo.pServerRandom,
                    p.RandomInfo.ulServerRandomLen,
                ) || !embedded_payload_len_ok(p.RandomInfo.ulClientRandomLen)
                    || !embedded_payload_len_ok(p.RandomInfo.ulServerRandomLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let client_random = if p.RandomInfo.pClientRandom.is_null()
                        || p.RandomInfo.ulClientRandomLen == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            payload_bytes(
                                p.RandomInfo.pClientRandom as *const u8,
                                p.RandomInfo.ulClientRandomLen,
                            )?
                        }
                    };
                    let server_random = if p.RandomInfo.pServerRandom.is_null()
                        || p.RandomInfo.ulServerRandomLen == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            payload_bytes(
                                p.RandomInfo.pServerRandom as *const u8,
                                p.RandomInfo.ulServerRandomLen,
                            )?
                        }
                    };
                    let (version_major, version_minor) = if p.pVersion.is_null() {
                        (0, 0)
                    } else {
                        let v = unsafe { read_param_struct(p.pVersion as *const CK_VERSION)? };
                        (v.major as u32, v.minor as u32)
                    };
                    Some(CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
                        random_info: SslRandomData { client_random, server_random },
                        version_major,
                        version_minor,
                        prf_hash_mechanism: CkMechanismType(p.prfHashMechanism as u64),
                    }))
                }
            }
        }

        Some("tls_prf") => {
            if param_len < std::mem::size_of::<CK_TLS_PRF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { read_param_struct(param_ptr as *const CK_TLS_PRF_PARAMS)? };
                if missing_embedded_pointer(p.pSeed, p.ulSeedLen)
                    || missing_embedded_pointer(p.pLabel, p.ulLabelLen)
                    || !embedded_payload_len_ok(p.ulSeedLen)
                    || !embedded_payload_len_ok(p.ulLabelLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let seed = if p.pSeed.is_null() || p.ulSeedLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pSeed as *const u8, p.ulSeedLen)? }
                    };
                    let label = if p.pLabel.is_null() || p.ulLabelLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pLabel as *const u8, p.ulLabelLen)? }
                    };
                    let output_len = if p.pulOutputLen.is_null() {
                        0u64
                    } else {
                        (unsafe { p.pulOutputLen.read_unaligned() }) as u64
                    };
                    Some(CkMechanismParams::TlsPrf(TlsPrfParams {
                        seed: seed.into(),
                        label: label.into(),
                        output_len,
                        // W1-C5-01: `pOutput` is OUT — never read the
                        // caller's uninitialized buffer into the request.
                        output: Vec::new().into(),
                    }))
                }
            }
        }

        Some("tls_kdf") => {
            if param_len < std::mem::size_of::<CK_TLS_KDF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { read_param_struct(param_ptr as *const CK_TLS_KDF_PARAMS)? };
                if missing_embedded_pointer(p.pLabel, p.ulLabelLength)
                    || missing_embedded_pointer(
                        p.RandomInfo.pClientRandom,
                        p.RandomInfo.ulClientRandomLen,
                    )
                    || missing_embedded_pointer(
                        p.RandomInfo.pServerRandom,
                        p.RandomInfo.ulServerRandomLen,
                    )
                    || missing_embedded_pointer(p.pContextData, p.ulContextDataLength)
                    || !embedded_payload_len_ok(p.ulLabelLength)
                    || !embedded_payload_len_ok(p.RandomInfo.ulClientRandomLen)
                    || !embedded_payload_len_ok(p.RandomInfo.ulServerRandomLen)
                    || !embedded_payload_len_ok(p.ulContextDataLength)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let label = if p.pLabel.is_null() || p.ulLabelLength == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pLabel as *const u8, p.ulLabelLength)? }
                    };
                    let client_random = if p.RandomInfo.pClientRandom.is_null()
                        || p.RandomInfo.ulClientRandomLen == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            payload_bytes(
                                p.RandomInfo.pClientRandom as *const u8,
                                p.RandomInfo.ulClientRandomLen,
                            )?
                        }
                    };
                    let server_random = if p.RandomInfo.pServerRandom.is_null()
                        || p.RandomInfo.ulServerRandomLen == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            payload_bytes(
                                p.RandomInfo.pServerRandom as *const u8,
                                p.RandomInfo.ulServerRandomLen,
                            )?
                        }
                    };
                    let context_data = if p.pContextData.is_null() || p.ulContextDataLength == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            payload_bytes(p.pContextData as *const u8, p.ulContextDataLength)?
                        }
                    };
                    Some(CkMechanismParams::TlsKdf(TlsKdfParams {
                        prf_mechanism: CkMechanismType(p.prfMechanism as u64),
                        label: label.into(),
                        random_info: SslRandomData { client_random, server_random },
                        context_data: context_data.into(),
                    }))
                }
            }
        }

        Some("ssl3_master_key_derive") => {
            if param_len < std::mem::size_of::<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe {
                    read_param_struct(param_ptr as *const CK_SSL3_MASTER_KEY_DERIVE_PARAMS)?
                };
                if missing_embedded_pointer(
                    p.RandomInfo.pClientRandom,
                    p.RandomInfo.ulClientRandomLen,
                ) || missing_embedded_pointer(
                    p.RandomInfo.pServerRandom,
                    p.RandomInfo.ulServerRandomLen,
                ) || !embedded_payload_len_ok(p.RandomInfo.ulClientRandomLen)
                    || !embedded_payload_len_ok(p.RandomInfo.ulServerRandomLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let client_random = if p.RandomInfo.pClientRandom.is_null()
                        || p.RandomInfo.ulClientRandomLen == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            payload_bytes(
                                p.RandomInfo.pClientRandom as *const u8,
                                p.RandomInfo.ulClientRandomLen,
                            )?
                        }
                    };
                    let server_random = if p.RandomInfo.pServerRandom.is_null()
                        || p.RandomInfo.ulServerRandomLen == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            payload_bytes(
                                p.RandomInfo.pServerRandom as *const u8,
                                p.RandomInfo.ulServerRandomLen,
                            )?
                        }
                    };
                    let (version_major, version_minor) = if p.pVersion.is_null() {
                        (0, 0)
                    } else {
                        let v = unsafe { read_param_struct(p.pVersion as *const CK_VERSION)? };
                        (v.major as u32, v.minor as u32)
                    };
                    Some(CkMechanismParams::Ssl3MasterKeyDerive(Ssl3MasterKeyDeriveParams {
                        random_info: SslRandomData { client_random, server_random },
                        version_major,
                        version_minor,
                    }))
                }
            }
        }

        Some("tls12_extended_master_key_derive") => {
            if param_len < std::mem::size_of::<CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe {
                    read_param_struct(
                        param_ptr as *const CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS,
                    )?
                };
                if missing_embedded_pointer(p.pSessionHash, p.ulSessionHashLen)
                    || !embedded_payload_len_ok(p.ulSessionHashLen)
                {
                    return Ok(CkMechanism {
                        mechanism_type: mech_type,
                        params: Some(raw_mechanism_params(param_ptr, param_len)?),
                    });
                }
                let session_hash = if p.pSessionHash.is_null() || p.ulSessionHashLen == 0 {
                    Vec::new()
                } else {
                    unsafe { payload_bytes(p.pSessionHash as *const u8, p.ulSessionHashLen)? }
                };
                let (version_major, version_minor) = if p.pVersion.is_null() {
                    (0, 0)
                } else {
                    let v = unsafe { read_param_struct(p.pVersion as *const CK_VERSION)? };
                    (v.major as u32, v.minor as u32)
                };
                Some(CkMechanismParams::Tls12ExtendedMasterKeyDerive(
                    Tls12ExtendedMasterKeyDeriveParams {
                        prf_hash_mechanism: CkMechanismType(p.prfHashMechanism as u64),
                        session_hash,
                        version_major,
                        version_minor,
                    },
                ))
            }
        }

        Some("ssl3_key_mat") => {
            // Accept both CK_SSL3_KEY_MAT_PARAMS and CK_TLS12_KEY_MAT_PARAMS.
            // TLS12 is a superset with an extra prfHashMechanism field at the end.
            let ssl3_size = std::mem::size_of::<CK_SSL3_KEY_MAT_PARAMS>();
            let tls12_size = std::mem::size_of::<CK_TLS12_KEY_MAT_PARAMS>();
            if param_len < ssl3_size {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { read_param_struct(param_ptr as *const CK_SSL3_KEY_MAT_PARAMS)? };
                let requested_iv_len = ((p.ulIVSizeInBits as usize).saturating_add(7)) / 8;
                if missing_embedded_pointer(
                    p.RandomInfo.pClientRandom,
                    p.RandomInfo.ulClientRandomLen,
                ) || missing_embedded_pointer(
                    p.RandomInfo.pServerRandom,
                    p.RandomInfo.ulServerRandomLen,
                ) || p.pReturnedKeyMaterial.is_null()
                    || requested_iv_len > MAX_SERIALIZABLE_BYTES
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let output = unsafe { read_param_struct(p.pReturnedKeyMaterial)? };
                    let iv_len = requested_iv_len;
                    if missing_embedded_pointer(output.pIVClient, iv_len as CK_ULONG)
                        || missing_embedded_pointer(output.pIVServer, iv_len as CK_ULONG)
                    {
                        Some(raw_mechanism_params(param_ptr, param_len)?)
                    } else {
                        let client_random = if p.RandomInfo.pClientRandom.is_null()
                            || p.RandomInfo.ulClientRandomLen == 0
                        {
                            Vec::new()
                        } else {
                            unsafe {
                                payload_bytes(
                                    p.RandomInfo.pClientRandom as *const u8,
                                    p.RandomInfo.ulClientRandomLen,
                                )?
                            }
                        };
                        let server_random = if p.RandomInfo.pServerRandom.is_null()
                            || p.RandomInfo.ulServerRandomLen == 0
                        {
                            Vec::new()
                        } else {
                            unsafe {
                                payload_bytes(
                                    p.RandomInfo.pServerRandom as *const u8,
                                    p.RandomInfo.ulServerRandomLen,
                                )?
                            }
                        };
                        let client_iv = if output.pIVClient.is_null() || iv_len == 0 {
                            Vec::new()
                        } else {
                            unsafe {
                                payload_bytes(output.pIVClient as *const u8, iv_len as CK_ULONG)?
                            }
                        };
                        let server_iv = if output.pIVServer.is_null() || iv_len == 0 {
                            Vec::new()
                        } else {
                            unsafe {
                                payload_bytes(output.pIVServer as *const u8, iv_len as CK_ULONG)?
                            }
                        };
                        let prf_hash_mechanism = if param_len >= tls12_size {
                            let t = unsafe {
                                read_param_struct(param_ptr as *const CK_TLS12_KEY_MAT_PARAMS)?
                            };
                            t.prfHashMechanism as u64
                        } else {
                            0
                        };
                        Some(CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
                            mac_size_bits: p.ulMacSizeInBits as u64,
                            key_size_bits: p.ulKeySizeInBits as u64,
                            iv_size_bits: p.ulIVSizeInBits as u64,
                            is_export: p.bIsExport != 0,
                            random_info: SslRandomData { client_random, server_random },
                            prf_hash_mechanism: CkMechanismType(prf_hash_mechanism),
                            client_mac_secret_handle: CkObjectHandle(
                                output.hClientMacSecret as u64,
                            ),
                            server_mac_secret_handle: CkObjectHandle(
                                output.hServerMacSecret as u64,
                            ),
                            client_key_handle: CkObjectHandle(output.hClientKey as u64),
                            server_key_handle: CkObjectHandle(output.hServerKey as u64),
                            client_iv: client_iv.into(),
                            server_iv: server_iv.into(),
                        }))
                    }
                }
            }
        }

        Some("pbe") => {
            if param_len < std::mem::size_of::<CK_PBE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { read_param_struct(param_ptr as *const CK_PBE_PARAMS)? };
                if !embedded_payload_len_ok(p.ulPasswordLen)
                    || !embedded_payload_len_ok(p.ulSaltLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let init_vector = if p.pInitVector.is_null() {
                        Vec::new()
                    } else {
                        // PBE init vector is typically 8 bytes but length is not explicit
                        // in the struct. Use 8 as the standard PBE IV size.
                        unsafe { payload_bytes(p.pInitVector as *const u8, 8)? }
                    };
                    let password = if p.pPassword.is_null() || p.ulPasswordLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pPassword as *const u8, p.ulPasswordLen)? }
                    };
                    let salt = if p.pSalt.is_null() || p.ulSaltLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pSalt as *const u8, p.ulSaltLen)? }
                    };
                    let init_vector_presence = PointerBytes::present_copy(&init_vector);
                    let password_presence = PointerBytes::present_copy(&password);
                    let salt_presence = PointerBytes::present_copy(&salt);
                    Some(CkMechanismParams::Pbe(PbeParams {
                        init_vector: init_vector.into(),
                        password: password.into(),
                        salt: salt.into(),
                        iteration: p.ulIteration as u64,
                        init_vector_presence,
                        password_presence,
                        salt_presence,
                    }))
                }
            }
        }

        Some("ecdh_aes_key_wrap") => {
            if param_len < std::mem::size_of::<CK_ECDH_AES_KEY_WRAP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p =
                    unsafe { read_param_struct(param_ptr as *const CK_ECDH_AES_KEY_WRAP_PARAMS)? };
                if missing_embedded_pointer(p.pSharedData, p.ulSharedDataLen)
                    || !embedded_payload_len_ok(p.ulSharedDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let shared_data = if p.pSharedData.is_null() || p.ulSharedDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pSharedData as *const u8, p.ulSharedDataLen)? }
                    };
                    let shared_data_presence = PointerBytes::present_copy(&shared_data);
                    Some(CkMechanismParams::EcdhAesKeyWrap(EcdhAesKeyWrapParams {
                        aes_key_bits: p.ulAESKeyBits as u64,
                        kdf: CkKdf(p.kdf as u64),
                        shared_data: shared_data.into(),
                        shared_data_presence,
                    }))
                }
            }
        }

        Some("ecdh2_derive") => {
            if param_len < std::mem::size_of::<CK_ECDH2_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { read_param_struct(param_ptr as *const CK_ECDH2_DERIVE_PARAMS)? };
                if missing_embedded_pointer(p.pSharedData, p.ulSharedDataLen)
                    || missing_embedded_pointer(p.pPublicData, p.ulPublicDataLen)
                    || missing_embedded_pointer(p.pPublicData2, p.ulPublicDataLen2)
                    || !embedded_payload_len_ok(p.ulSharedDataLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen2)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let shared_data = if p.pSharedData.is_null() || p.ulSharedDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pSharedData as *const u8, p.ulSharedDataLen)? }
                    };
                    let public_data = if p.pPublicData.is_null() || p.ulPublicDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pPublicData as *const u8, p.ulPublicDataLen)? }
                    };
                    let public_data2 = if p.pPublicData2.is_null() || p.ulPublicDataLen2 == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pPublicData2 as *const u8, p.ulPublicDataLen2)? }
                    };
                    let shared_data_presence = PointerBytes::present_copy(&shared_data);
                    let public_data_presence = PointerBytes::present_copy(&public_data);
                    let public_data2_presence = PointerBytes::present_copy(&public_data2);
                    Some(CkMechanismParams::Ecdh2Derive(Ecdh2DeriveParams {
                        kdf: CkKdf(p.kdf as u64),
                        shared_data: shared_data.into(),
                        public_data,
                        private_data_len: p.ulPrivateDataLen as u64,
                        private_data_handle: CkObjectHandle(p.hPrivateData as u64),
                        public_data2,
                        shared_data_presence,
                        public_data_presence,
                        public_data2_presence,
                    }))
                }
            }
        }

        Some("ecmqv_derive") => {
            if param_len < std::mem::size_of::<CK_ECMQV_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { read_param_struct(param_ptr as *const CK_ECMQV_DERIVE_PARAMS)? };
                if missing_embedded_pointer(p.pSharedData, p.ulSharedDataLen)
                    || missing_embedded_pointer(p.pPublicData, p.ulPublicDataLen)
                    || missing_embedded_pointer(p.pPublicData2, p.ulPublicDataLen2)
                    || !embedded_payload_len_ok(p.ulSharedDataLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen2)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let shared_data = if p.pSharedData.is_null() || p.ulSharedDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pSharedData as *const u8, p.ulSharedDataLen)? }
                    };
                    let public_data = if p.pPublicData.is_null() || p.ulPublicDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pPublicData as *const u8, p.ulPublicDataLen)? }
                    };
                    let public_data2 = if p.pPublicData2.is_null() || p.ulPublicDataLen2 == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pPublicData2 as *const u8, p.ulPublicDataLen2)? }
                    };
                    let shared_data_presence = PointerBytes::present_copy(&shared_data);
                    let public_data_presence = PointerBytes::present_copy(&public_data);
                    let public_data2_presence = PointerBytes::present_copy(&public_data2);
                    Some(CkMechanismParams::EcmqvDerive(EcmqvDeriveParams {
                        kdf: CkKdf(p.kdf as u64),
                        shared_data: shared_data.into(),
                        public_data,
                        private_data_len: p.ulPrivateDataLen as u64,
                        private_data_handle: CkObjectHandle(p.hPrivateData as u64),
                        public_data2,
                        public_key_handle: CkObjectHandle(p.publicKey as u64),
                        shared_data_presence,
                        public_data_presence,
                        public_data2_presence,
                    }))
                }
            }
        }

        Some("x942_dh1_derive") => {
            if param_len < std::mem::size_of::<CK_X9_42_DH1_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p =
                    unsafe { read_param_struct(param_ptr as *const CK_X9_42_DH1_DERIVE_PARAMS)? };
                if missing_embedded_pointer(p.pOtherInfo, p.ulOtherInfoLen)
                    || missing_embedded_pointer(p.pPublicData, p.ulPublicDataLen)
                    || !embedded_payload_len_ok(p.ulOtherInfoLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let other_info = if p.pOtherInfo.is_null() || p.ulOtherInfoLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pOtherInfo as *const u8, p.ulOtherInfoLen)? }
                    };
                    let public_data = if p.pPublicData.is_null() || p.ulPublicDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pPublicData as *const u8, p.ulPublicDataLen)? }
                    };
                    let other_info_presence = PointerBytes::present_copy(&other_info);
                    let public_data_presence = PointerBytes::present_copy(&public_data);
                    Some(CkMechanismParams::X942Dh1Derive(X942Dh1DeriveParams {
                        kdf: CkKdf(p.kdf as u64),
                        other_info: other_info.into(),
                        public_data,
                        other_info_presence,
                        public_data_presence,
                    }))
                }
            }
        }

        Some("x942_dh2_derive") => {
            if param_len < std::mem::size_of::<CK_X9_42_DH2_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p =
                    unsafe { read_param_struct(param_ptr as *const CK_X9_42_DH2_DERIVE_PARAMS)? };
                if missing_embedded_pointer(p.pOtherInfo, p.ulOtherInfoLen)
                    || missing_embedded_pointer(p.pPublicData, p.ulPublicDataLen)
                    || missing_embedded_pointer(p.pPublicData2, p.ulPublicDataLen2)
                    || !embedded_payload_len_ok(p.ulOtherInfoLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen2)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let other_info = if p.pOtherInfo.is_null() || p.ulOtherInfoLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pOtherInfo as *const u8, p.ulOtherInfoLen)? }
                    };
                    let public_data = if p.pPublicData.is_null() || p.ulPublicDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pPublicData as *const u8, p.ulPublicDataLen)? }
                    };
                    let public_data2 = if p.pPublicData2.is_null() || p.ulPublicDataLen2 == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pPublicData2 as *const u8, p.ulPublicDataLen2)? }
                    };
                    let other_info_presence = PointerBytes::present_copy(&other_info);
                    let public_data_presence = PointerBytes::present_copy(&public_data);
                    let public_data2_presence = PointerBytes::present_copy(&public_data2);
                    Some(CkMechanismParams::X942Dh2Derive(X942Dh2DeriveParams {
                        kdf: CkKdf(p.kdf as u64),
                        other_info: other_info.into(),
                        public_data,
                        private_data_len: p.ulPrivateDataLen as u64,
                        private_data_handle: CkObjectHandle(p.hPrivateData as u64),
                        public_data2,
                        other_info_presence,
                        public_data_presence,
                        public_data2_presence,
                    }))
                }
            }
        }

        Some("x942_mqv_derive") => {
            if param_len < std::mem::size_of::<CK_X9_42_MQV_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p =
                    unsafe { read_param_struct(param_ptr as *const CK_X9_42_MQV_DERIVE_PARAMS)? };
                if missing_embedded_pointer(p.OtherInfo, p.ulOtherInfoLen)
                    || missing_embedded_pointer(p.PublicData, p.ulPublicDataLen)
                    || missing_embedded_pointer(p.PublicData2, p.ulPublicDataLen2)
                    || !embedded_payload_len_ok(p.ulOtherInfoLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen2)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let other_info = if p.OtherInfo.is_null() || p.ulOtherInfoLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.OtherInfo as *const u8, p.ulOtherInfoLen)? }
                    };
                    let public_data = if p.PublicData.is_null() || p.ulPublicDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.PublicData as *const u8, p.ulPublicDataLen)? }
                    };
                    let public_data2 = if p.PublicData2.is_null() || p.ulPublicDataLen2 == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.PublicData2 as *const u8, p.ulPublicDataLen2)? }
                    };
                    let other_info_presence = PointerBytes::present_copy(&other_info);
                    let public_data_presence = PointerBytes::present_copy(&public_data);
                    let public_data2_presence = PointerBytes::present_copy(&public_data2);
                    Some(CkMechanismParams::X942MqvDerive(X942MqvDeriveParams {
                        kdf: CkKdf(p.kdf as u64),
                        other_info: other_info.into(),
                        public_data,
                        private_data_len: p.ulPrivateDataLen as u64,
                        private_data_handle: CkObjectHandle(p.hPrivateData as u64),
                        public_data2,
                        public_key_handle: CkObjectHandle(p.publicKey as u64),
                        other_info_presence,
                        public_data_presence,
                        public_data2_presence,
                    }))
                }
            }
        }

        Some("gostr3410_derive") => {
            if param_len < std::mem::size_of::<CK_GOSTR3410_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p =
                    unsafe { read_param_struct(param_ptr as *const CK_GOSTR3410_DERIVE_PARAMS)? };
                if missing_embedded_pointer(p.pPublicData, p.ulPublicDataLen)
                    || missing_embedded_pointer(p.pUKM, p.ulUKMLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                    || !embedded_payload_len_ok(p.ulUKMLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let public_data = if p.pPublicData.is_null() || p.ulPublicDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pPublicData as *const u8, p.ulPublicDataLen)? }
                    };
                    let ukm = if p.pUKM.is_null() || p.ulUKMLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pUKM as *const u8, p.ulUKMLen)? }
                    };
                    let public_data_presence = PointerBytes::present_copy(&public_data);
                    let ukm_presence = PointerBytes::present_copy(&ukm);
                    Some(CkMechanismParams::Gostr3410Derive(Gostr3410DeriveParams {
                        kdf: CkKdf(p.kdf as u64),
                        public_data,
                        ukm,
                        public_data_presence,
                        ukm_presence,
                    }))
                }
            }
        }

        Some("gostr3410_key_wrap") => {
            if param_len < std::mem::size_of::<CK_GOSTR3410_KEY_WRAP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p =
                    unsafe { read_param_struct(param_ptr as *const CK_GOSTR3410_KEY_WRAP_PARAMS)? };
                if missing_embedded_pointer(p.pWrapOID, p.ulWrapOIDLen)
                    || missing_embedded_pointer(p.pUKM, p.ulUKMLen)
                    || !embedded_payload_len_ok(p.ulWrapOIDLen)
                    || !embedded_payload_len_ok(p.ulUKMLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let wrap_oid = if p.pWrapOID.is_null() || p.ulWrapOIDLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pWrapOID as *const u8, p.ulWrapOIDLen)? }
                    };
                    let ukm = if p.pUKM.is_null() || p.ulUKMLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pUKM as *const u8, p.ulUKMLen)? }
                    };
                    let wrap_oid_presence = PointerBytes::present_copy(&wrap_oid);
                    let ukm_presence = PointerBytes::present_copy(&ukm);
                    Some(CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
                        wrap_oid,
                        ukm,
                        key_handle: CkObjectHandle(p.hKey as u64),
                        wrap_oid_presence,
                        ukm_presence,
                    }))
                }
            }
        }

        Some("key_wrap_set_oaep") => {
            if param_len < std::mem::size_of::<CK_KEY_WRAP_SET_OAEP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p =
                    unsafe { read_param_struct(param_ptr as *const CK_KEY_WRAP_SET_OAEP_PARAMS)? };
                if missing_embedded_pointer(p.pX, p.ulXLen) || !embedded_payload_len_ok(p.ulXLen) {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let x = if p.pX.is_null() || p.ulXLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pX as *const u8, p.ulXLen)? }
                    };
                    let x_presence = PointerBytes::present_copy(&x);
                    Some(CkMechanismParams::KeyWrapSetOaep(KeyWrapSetOaepParams {
                        bc: p.bBC as u32,
                        x: x.into(),
                        x_presence,
                    }))
                }
            }
        }

        Some("kea_derive") => {
            if param_len < std::mem::size_of::<CK_KEA_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { read_param_struct(param_ptr as *const CK_KEA_DERIVE_PARAMS)? };
                if !embedded_payload_len_ok(p.ulRandomLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let random_len = p.ulRandomLen as usize;
                    let random_a = if p.RandomA.is_null() || random_len == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.RandomA as *const u8, random_len as CK_ULONG)? }
                    };
                    let random_b = if p.RandomB.is_null() || random_len == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.RandomB as *const u8, random_len as CK_ULONG)? }
                    };
                    let public_data = if p.PublicData.is_null() || p.ulPublicDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.PublicData as *const u8, p.ulPublicDataLen)? }
                    };
                    Some(CkMechanismParams::KeaDerive(KeaDeriveParams {
                        is_sender: p.isSender != 0,
                        random_a,
                        random_b,
                        public_data,
                    }))
                }
            }
        }

        Some("ike_prf_derive") => {
            if param_len < std::mem::size_of::<CK_IKE_PRF_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { read_param_struct(param_ptr as *const CK_IKE_PRF_DERIVE_PARAMS)? };
                if missing_embedded_pointer(p.pNi, p.ulNiLen)
                    || missing_embedded_pointer(p.pNr, p.ulNrLen)
                    || !embedded_payload_len_ok(p.ulNiLen)
                    || !embedded_payload_len_ok(p.ulNrLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let ni = if p.pNi.is_null() || p.ulNiLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pNi as *const u8, p.ulNiLen)? }
                    };
                    let nr = if p.pNr.is_null() || p.ulNrLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pNr as *const u8, p.ulNrLen)? }
                    };
                    let ni_presence = PointerBytes::present_copy(&ni);
                    let nr_presence = PointerBytes::present_copy(&nr);
                    Some(CkMechanismParams::IkePrfDerive(IkePrfDeriveParams {
                        prf_mechanism: CkMechanismType(p.prfMechanism as u64),
                        data_as_key: p.bDataAsKey != 0,
                        rekey: p.bRekey != 0,
                        ni: ni.into(),
                        nr: nr.into(),
                        new_key_handle: CkObjectHandle(p.hNewKey as u64),
                        ni_presence,
                        nr_presence,
                    }))
                }
            }
        }

        Some("ike1_prf_derive") => {
            if param_len < std::mem::size_of::<CK_IKE1_PRF_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p =
                    unsafe { read_param_struct(param_ptr as *const CK_IKE1_PRF_DERIVE_PARAMS)? };
                if missing_embedded_pointer(p.pCKYi, p.ulCKYiLen)
                    || missing_embedded_pointer(p.pCKYr, p.ulCKYrLen)
                    || !embedded_payload_len_ok(p.ulCKYiLen)
                    || !embedded_payload_len_ok(p.ulCKYrLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let ckyi = if p.pCKYi.is_null() || p.ulCKYiLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pCKYi as *const u8, p.ulCKYiLen)? }
                    };
                    let ckyr = if p.pCKYr.is_null() || p.ulCKYrLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pCKYr as *const u8, p.ulCKYrLen)? }
                    };
                    let ckyi_presence = PointerBytes::present_copy(&ckyi);
                    let ckyr_presence = PointerBytes::present_copy(&ckyr);
                    Some(CkMechanismParams::Ike1PrfDerive(Ike1PrfDeriveParams {
                        prf_mechanism: CkMechanismType(p.prfMechanism as u64),
                        has_prev_key: p.bHasPrevKey != 0,
                        keygxy_handle: CkObjectHandle(p.hKeygxy as u64),
                        prev_key_handle: CkObjectHandle(p.hPrevKey as u64),
                        ckyi: ckyi.into(),
                        ckyr: ckyr.into(),
                        key_number: p.keyNumber as u32,
                        ckyi_presence,
                        ckyr_presence,
                    }))
                }
            }
        }

        Some("ike1_extended_derive") => {
            if param_len < std::mem::size_of::<CK_IKE1_EXTENDED_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe {
                    read_param_struct(param_ptr as *const CK_IKE1_EXTENDED_DERIVE_PARAMS)?
                };
                if missing_embedded_pointer(p.pExtraData, p.ulExtraDataLen)
                    || !embedded_payload_len_ok(p.ulExtraDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let extra_data = if p.pExtraData.is_null() || p.ulExtraDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pExtraData as *const u8, p.ulExtraDataLen)? }
                    };
                    let extra_data_presence = PointerBytes::present_copy(&extra_data);
                    Some(CkMechanismParams::Ike1ExtendedDerive(Ike1ExtendedDeriveParams {
                        prf_mechanism: CkMechanismType(p.prfMechanism as u64),
                        has_keygxy: p.bHasKeygxy != 0,
                        keygxy_handle: CkObjectHandle(p.hKeygxy as u64),
                        extra_data: extra_data.into(),
                        extra_data_presence,
                    }))
                }
            }
        }

        Some("ike2_prf_plus_derive") => {
            if param_len < std::mem::size_of::<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe {
                    read_param_struct(param_ptr as *const CK_IKE2_PRF_PLUS_DERIVE_PARAMS)?
                };
                if missing_embedded_pointer(p.pSeedData, p.ulSeedDataLen)
                    || !embedded_payload_len_ok(p.ulSeedDataLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let seed_data = if p.pSeedData.is_null() || p.ulSeedDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pSeedData as *const u8, p.ulSeedDataLen)? }
                    };
                    let seed_data_presence = PointerBytes::present_copy(&seed_data);
                    Some(CkMechanismParams::Ike2PrfPlusDerive(Ike2PrfPlusDeriveParams {
                        prf_mechanism: CkMechanismType(p.prfMechanism as u64),
                        has_seed_key: p.bHasSeedKey != 0,
                        seed_key_handle: CkObjectHandle(p.hSeedKey as u64),
                        seed_data: seed_data.into(),
                        seed_data_presence,
                    }))
                }
            }
        }

        Some("kip") => {
            if param_len < std::mem::size_of::<CK_KIP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { read_param_struct(param_ptr as *const CK_KIP_PARAMS)? };
                // Peek the nested length without assuming alignment; depth
                // and cycle enforcement happen at budget entry below.
                let nested_len_too_large = if p.pMechanism.is_null() {
                    false
                } else {
                    let nested_len = unsafe {
                        std::ptr::addr_of!((*p.pMechanism).ulParameterLen).read_unaligned()
                    };
                    nested_len as usize > MAX_MECHANISM_PARAM_STRUCT_LEN
                };
                if p.pMechanism.is_null()
                    || nested_len_too_large
                    || missing_embedded_pointer(p.pSeed, p.ulSeedLen)
                    || !embedded_payload_len_ok(p.ulSeedLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    budget.enter(p.pMechanism as usize)?;
                    let mechanism =
                        unsafe { read_nested_mechanism_for_transport(p.pMechanism, budget) };
                    budget.exit();
                    let mechanism = mechanism?;
                    let seed = unsafe { payload_bytes(p.pSeed, p.ulSeedLen)? };
                    Some(CkMechanismParams::Kip(KipParams {
                        mechanism: Box::new(mechanism),
                        key_handle: CkObjectHandle(p.hKey as u64),
                        seed: seed.into(),
                    }))
                }
            }
        }

        Some("otp") => {
            if param_len < std::mem::size_of::<CK_OTP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { read_param_struct(param_ptr as *const CK_OTP_PARAMS)? };
                if missing_embedded_pointer(p.pParams, p.ulCount)
                    || p.ulCount as usize > MAX_TEMPLATE_COUNT
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else if p.pParams.is_null() || p.ulCount == 0 {
                    Some(CkMechanismParams::Otp(OtpParams { params: Vec::new() }))
                } else {
                    // Typed caller array: validate the extent, then copy
                    // each element unaligned (never an aligned slice over
                    // caller memory). `ulCount` is already capped at
                    // MAX_TEMPLATE_COUNT by the guard above.
                    checked_extent(
                        p.pParams as usize,
                        p.ulCount as u64,
                        std::mem::size_of::<CK_OTP_PARAM>(),
                        MAX_TEMPLATE_COUNT.saturating_mul(std::mem::size_of::<CK_OTP_PARAM>()),
                    )
                    .map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
                    let count = p.ulCount as usize;
                    let mut params = Vec::with_capacity(count);
                    for index in 0..count {
                        // Safety: index < count, and the checked extent
                        // above covers exactly count elements from pParams.
                        params.push(unsafe { p.pParams.add(index).read_unaligned() });
                    }
                    if params.iter().any(|param| {
                        missing_embedded_pointer(param.pValue as *const u8, param.ulValueLen)
                            || !embedded_payload_len_ok(param.ulValueLen)
                    }) {
                        Some(raw_mechanism_params(param_ptr, param_len)?)
                    } else {
                        let converted: CkResult<Vec<OtpParam>> = params
                            .iter()
                            .map(|param| {
                                let value = unsafe {
                                    payload_bytes(param.pValue as *const u8, param.ulValueLen)?
                                };
                                Ok(OtpParam { type_: param.type_ as u64, value: value.into() })
                            })
                            .collect();
                        Some(CkMechanismParams::Otp(OtpParams { params: converted? }))
                    }
                }
            }
        }

        Some("skipjack_private_wrap") => {
            if param_len < std::mem::size_of::<CK_SKIPJACK_PRIVATE_WRAP_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe {
                    read_param_struct(param_ptr as *const CK_SKIPJACK_PRIVATE_WRAP_PARAMS)?
                };
                if missing_embedded_pointer(p.pPassword, p.ulPasswordLen)
                    || missing_embedded_pointer(p.pPublicData, p.ulPublicDataLen)
                    || missing_embedded_pointer(p.pRandomA, p.ulRandomLen)
                    || missing_embedded_pointer(p.pPrimeP, p.ulPAndGLen)
                    || missing_embedded_pointer(p.pBaseG, p.ulPAndGLen)
                    || missing_embedded_pointer(p.pSubprimeQ, p.ulQLen)
                    || !embedded_payload_len_ok(p.ulPasswordLen)
                    || !embedded_payload_len_ok(p.ulPublicDataLen)
                    || !embedded_payload_len_ok(p.ulRandomLen)
                    || !embedded_payload_len_ok(p.ulPAndGLen)
                    || !embedded_payload_len_ok(p.ulQLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let password = if p.pPassword.is_null() || p.ulPasswordLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pPassword as *const u8, p.ulPasswordLen)? }
                    };
                    let public_data = if p.pPublicData.is_null() || p.ulPublicDataLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pPublicData as *const u8, p.ulPublicDataLen)? }
                    };
                    let random_a = if p.pRandomA.is_null() || p.ulRandomLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pRandomA as *const u8, p.ulRandomLen)? }
                    };
                    let prime_p = if p.pPrimeP.is_null() || p.ulPAndGLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pPrimeP as *const u8, p.ulPAndGLen)? }
                    };
                    let base_g = if p.pBaseG.is_null() || p.ulPAndGLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pBaseG as *const u8, p.ulPAndGLen)? }
                    };
                    let subprime_q = if p.pSubprimeQ.is_null() || p.ulQLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pSubprimeQ as *const u8, p.ulQLen)? }
                    };
                    Some(CkMechanismParams::SkipjackPrivateWrap(SkipjackPrivateWrapParams {
                        password: password.into(),
                        public_data,
                        password_length: p.ulPasswordLen as u64,
                        random_a,
                        prime_p,
                        base_g,
                        subprime_q,
                    }))
                }
            }
        }

        Some("skipjack_relayx") => {
            if param_len < std::mem::size_of::<CK_SKIPJACK_RELAYX_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p =
                    unsafe { read_param_struct(param_ptr as *const CK_SKIPJACK_RELAYX_PARAMS)? };
                if missing_embedded_pointer(p.pOldWrappedX, p.ulOldWrappedXLen)
                    || missing_embedded_pointer(p.pOldPassword, p.ulOldPasswordLen)
                    || missing_embedded_pointer(p.pOldPublicData, p.ulOldPublicDataLen)
                    || missing_embedded_pointer(p.pOldRandomA, p.ulOldRandomLen)
                    || missing_embedded_pointer(p.pNewPassword, p.ulNewPasswordLen)
                    || missing_embedded_pointer(p.pNewPublicData, p.ulNewPublicDataLen)
                    || missing_embedded_pointer(p.pNewRandomA, p.ulNewRandomLen)
                    || !embedded_payload_len_ok(p.ulOldWrappedXLen)
                    || !embedded_payload_len_ok(p.ulOldPasswordLen)
                    || !embedded_payload_len_ok(p.ulOldPublicDataLen)
                    || !embedded_payload_len_ok(p.ulOldRandomLen)
                    || !embedded_payload_len_ok(p.ulNewPasswordLen)
                    || !embedded_payload_len_ok(p.ulNewPublicDataLen)
                    || !embedded_payload_len_ok(p.ulNewRandomLen)
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let old_wrapped_x = if p.pOldWrappedX.is_null() || p.ulOldWrappedXLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pOldWrappedX as *const u8, p.ulOldWrappedXLen)? }
                    };
                    let old_password = if p.pOldPassword.is_null() || p.ulOldPasswordLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pOldPassword as *const u8, p.ulOldPasswordLen)? }
                    };
                    let old_public_data = if p.pOldPublicData.is_null() || p.ulOldPublicDataLen == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            payload_bytes(p.pOldPublicData as *const u8, p.ulOldPublicDataLen)?
                        }
                    };
                    let old_random_a = if p.pOldRandomA.is_null() || p.ulOldRandomLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pOldRandomA as *const u8, p.ulOldRandomLen)? }
                    };
                    let new_password = if p.pNewPassword.is_null() || p.ulNewPasswordLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pNewPassword as *const u8, p.ulNewPasswordLen)? }
                    };
                    let new_public_data = if p.pNewPublicData.is_null() || p.ulNewPublicDataLen == 0
                    {
                        Vec::new()
                    } else {
                        unsafe {
                            payload_bytes(p.pNewPublicData as *const u8, p.ulNewPublicDataLen)?
                        }
                    };
                    let new_random_a = if p.pNewRandomA.is_null() || p.ulNewRandomLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pNewRandomA as *const u8, p.ulNewRandomLen)? }
                    };
                    Some(CkMechanismParams::SkipjackRelayx(SkipjackRelayxParams {
                        old_wrapped_x: old_wrapped_x.into(),
                        old_password: old_password.into(),
                        old_public_data: old_public_data.into(),
                        old_random_a: old_random_a.into(),
                        new_password: new_password.into(),
                        new_public_data: new_public_data.into(),
                        new_random_a: new_random_a.into(),
                    }))
                }
            }
        }

        Some("sp800_108_kdf") => {
            if param_len < std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe { read_param_struct(param_ptr as *const CK_SP800_108_KDF_PARAMS)? };
                if unsafe {
                    sp800_108_data_params_invalid(p.pDataParams, p.ulNumberOfDataParams)
                        || sp800_108_derived_keys_invalid(
                            p.pAdditionalDerivedKeys,
                            p.ulAdditionalDerivedKeys,
                        )
                } {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                        prf_type: CkMechanismType(p.prfType as u64),
                        data_params: unsafe {
                            read_sp800_108_data_params(p.pDataParams, p.ulNumberOfDataParams)?
                        },
                        additional_derived_keys: unsafe {
                            read_sp800_108_derived_keys(
                                p.pAdditionalDerivedKeys,
                                p.ulAdditionalDerivedKeys,
                            )?
                        },
                    }))
                }
            }
        }

        Some("sp800_108_feedback_kdf") => {
            if param_len < std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>() {
                Some(CkMechanismParams::Raw(RawMechanismParams {
                    data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
                }))
            } else {
                let p = unsafe {
                    read_param_struct(param_ptr as *const CK_SP800_108_FEEDBACK_KDF_PARAMS)?
                };
                if missing_embedded_pointer(p.pIV, p.ulIVLen)
                    || !embedded_payload_len_ok(p.ulIVLen)
                    || unsafe {
                        sp800_108_data_params_invalid(p.pDataParams, p.ulNumberOfDataParams)
                            || sp800_108_derived_keys_invalid(
                                p.pAdditionalDerivedKeys,
                                p.ulAdditionalDerivedKeys,
                            )
                    }
                {
                    Some(raw_mechanism_params(param_ptr, param_len)?)
                } else {
                    let iv = if p.pIV.is_null() || p.ulIVLen == 0 {
                        Vec::new()
                    } else {
                        unsafe { payload_bytes(p.pIV as *const u8, p.ulIVLen)? }
                    };
                    Some(CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                        prf_type: CkMechanismType(p.prfType as u64),
                        data_params: unsafe {
                            read_sp800_108_data_params(p.pDataParams, p.ulNumberOfDataParams)?
                        },
                        iv,
                        additional_derived_keys: unsafe {
                            read_sp800_108_derived_keys(
                                p.pAdditionalDerivedKeys,
                                p.ulAdditionalDerivedKeys,
                            )?
                        },
                    }))
                }
            }
        }

        // Unknown shape or no shape registered: preserve raw bytes so they
        // can still reach the server for forwarding.
        Some(_) | None => Some(CkMechanismParams::Raw(RawMechanismParams {
            data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
        })),
    };

    Ok(CkMechanism { mechanism_type: mech_type, params })
}

pub(crate) fn gcm_iv_buffer_len(gcm: &CK_GCM_PARAMS) -> u64 {
    if gcm.pIv.is_null() {
        0
    } else if gcm.ulIvLen > 0 {
        gcm.ulIvLen as u64
    } else {
        ((gcm.ulIvBits as u64).saturating_add(7)) / 8
    }
}

/// Read SP800-108 `CK_PRF_DATA_PARAM` entries into owned values (W1-L1-04).
///
/// # Safety
///
/// A null `data_params` (or zero `count`) yields empty; otherwise the
/// pointer must designate `count` valid entries, and each non-null
/// `pValue` must be readable for `ulValueLen` bytes.
unsafe fn read_sp800_108_data_params(
    data_params: *mut CK_PRF_DATA_PARAM,
    count: CK_ULONG,
) -> CkResult<Vec<PrfDataParam>> {
    if data_params.is_null() || count == 0 {
        return Ok(Vec::new());
    }
    // Typed caller array: extent first, then per-element unaligned copies
    // (never an aligned slice over caller memory). The byte cap subsumes
    // the count cap; the explicit count check below keeps the count
    // invariant independent of future cap changes.
    checked_extent(
        data_params as usize,
        count as u64,
        std::mem::size_of::<CK_PRF_DATA_PARAM>(),
        MAX_TEMPLATE_COUNT.saturating_mul(std::mem::size_of::<CK_PRF_DATA_PARAM>()),
    )
    .map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
    let n = count as usize;
    if n > MAX_TEMPLATE_COUNT {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    let mut out = Vec::with_capacity(n);
    for index in 0..n {
        // Safety: index < n, covered by the checked extent above.
        let param = unsafe { data_params.add(index).read_unaligned() };
        let value = unsafe { payload_bytes(param.pValue as *const u8, param.ulValueLen)? };
        out.push(PrfDataParam { type_: param.type_ as u64, value: value.into() });
    }
    Ok(out)
}

/// Pre-validate SP800-108 data params: null/overlong shapes stay Raw
/// (W1-L1-04).
///
/// # Safety
///
/// Same read contract as [`read_sp800_108_data_params`] (the validator
/// only inspects pointer/length fields, never the payload bytes beyond
/// their declared extents).
unsafe fn sp800_108_data_params_invalid(
    data_params: *mut CK_PRF_DATA_PARAM,
    count: CK_ULONG,
) -> bool {
    if missing_embedded_pointer(data_params, count) {
        return true;
    }
    if data_params.is_null() || count == 0 {
        return false;
    }
    let n = count as usize;
    if n > MAX_TEMPLATE_COUNT {
        return true;
    }
    // Typed caller array: extent first, then per-element unaligned copies.
    // Arithmetic-invalid extents fail closed (invalid → Raw fallback).
    if checked_extent(
        data_params as usize,
        count as u64,
        std::mem::size_of::<CK_PRF_DATA_PARAM>(),
        MAX_TEMPLATE_COUNT.saturating_mul(std::mem::size_of::<CK_PRF_DATA_PARAM>()),
    )
    .is_err()
    {
        return true;
    }
    let mut entries = Vec::with_capacity(n);
    for index in 0..n {
        // Safety: index < n, covered by the checked extent above.
        entries.push(unsafe { data_params.add(index).read_unaligned() });
    }
    entries.iter().any(|param| {
        missing_embedded_pointer(param.pValue as *const u8, param.ulValueLen)
            || !embedded_payload_len_ok(param.ulValueLen)
    })
}

/// Read SP800-108 derived keys, surfacing template errors loudly
/// instead of defaulting them away (W1-L1-04).
///
/// # Safety
///
/// A null `derived_keys` (or zero `count`) yields empty; otherwise the
/// pointer must designate `count` valid entries, each `pTemplate`
/// satisfying the [`ck_attrs_to_rust_checked`] contract for its
/// `ulAttributeCount`, and each non-null `phKey` readable for one
/// handle.
unsafe fn read_sp800_108_derived_keys(
    derived_keys: *mut CK_DERIVED_KEY,
    count: CK_ULONG,
) -> CkResult<Vec<Sp800108DerivedKey>> {
    if derived_keys.is_null() || count == 0 {
        return Ok(Vec::new());
    }
    checked_extent(
        derived_keys as usize,
        count as u64,
        std::mem::size_of::<CK_DERIVED_KEY>(),
        MAX_TEMPLATE_COUNT.saturating_mul(std::mem::size_of::<CK_DERIVED_KEY>()),
    )
    .map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
    let n = count as usize;
    if n > MAX_TEMPLATE_COUNT {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    let mut entries = Vec::with_capacity(n);
    for index in 0..n {
        // Safety: index < n, covered by the checked extent above.
        entries.push(unsafe { derived_keys.add(index).read_unaligned() });
    }
    entries
        .iter()
        .map(|derived| {
            // W1-L12-10: surface template errors instead of swallowing them
            // into an empty vec. The completed pre-validator routes these
            // inputs to the Raw fallback first, so this arm is unreachable
            // in practice — but if it ever fires, the error propagates
            // loudly rather than corrupting the structured params.
            let template =
                unsafe { ck_attrs_to_rust_checked(derived.pTemplate, derived.ulAttributeCount) }?;
            let key_handle = if derived.phKey.is_null() {
                0
            } else {
                unsafe { derived.phKey.read_unaligned() as u64 }
            };
            Ok(Sp800108DerivedKey { template, key_handle: CkObjectHandle(key_handle) })
        })
        .collect()
}

/// Pre-validate SP800-108 derived keys, including template CONTENT
/// the checked reader would reject (W1-L1-04).
///
/// # Safety
///
/// Same read contract as [`read_sp800_108_derived_keys`].
unsafe fn sp800_108_derived_keys_invalid(
    derived_keys: *mut CK_DERIVED_KEY,
    count: CK_ULONG,
) -> bool {
    if missing_embedded_pointer(derived_keys, count) {
        return true;
    }
    if derived_keys.is_null() || count == 0 {
        return false;
    }
    let n = count as usize;
    if n > MAX_TEMPLATE_COUNT {
        return true;
    }
    // Typed caller array: extent first, then per-element unaligned copies.
    // Arithmetic-invalid extents fail closed (invalid → Raw fallback).
    if checked_extent(
        derived_keys as usize,
        count as u64,
        std::mem::size_of::<CK_DERIVED_KEY>(),
        MAX_TEMPLATE_COUNT.saturating_mul(std::mem::size_of::<CK_DERIVED_KEY>()),
    )
    .is_err()
    {
        return true;
    }
    let mut entries = Vec::with_capacity(n);
    for index in 0..n {
        // Safety: index < n, covered by the checked extent above.
        entries.push(unsafe { derived_keys.add(index).read_unaligned() });
    }
    entries.iter().any(|derived| {
        missing_embedded_pointer(derived.pTemplate, derived.ulAttributeCount)
            || (derived.ulAttributeCount as usize) > MAX_TEMPLATE_COUNT
            || derived.phKey.is_null()
            // W1-L12-10: complete the pre-validator — template CONTENT the
            // checked reader would reject (NULL value with nonzero length,
            // overlong payloads, malformed nesting) also stays Raw. Costs
            // one extra template parse per derived key; KDF params are small.
            || unsafe { ck_attrs_to_rust_checked(derived.pTemplate, derived.ulAttributeCount) }
                .is_err()
    })
}

pub(crate) fn missing_embedded_pointer<T>(ptr: *const T, len: CK_ULONG) -> bool {
    ptr.is_null() && len != 0
}

pub(crate) fn raw_mechanism_params(
    param_ptr: *mut std::ffi::c_void,
    param_len: usize,
) -> CkResult<CkMechanismParams> {
    Ok(CkMechanismParams::Raw(RawMechanismParams {
        data: unsafe { read_raw_bytes(param_ptr, param_len)? }.into(),
    }))
}

/// Read raw bytes from a C void pointer into a Vec.
///
/// Lengths above `MAX_MECHANISM_PARAM_STRUCT_LEN` are an explicit
/// `MECHANISM_PARAM_INVALID` error (W1-L12-06: never conflate overlong
/// with empty). The `read_mechanism_for_transport` legacy entry gate
/// already rejects such lengths, so the error arm is unreachable in
/// production and exists as defense-in-depth at the API boundary.
///
/// # Safety
///
/// `ptr` must point to a readable buffer of at least `len` bytes, except
/// that no memory is accessed when `len` is overlong (the error returns
/// before any dereference) or zero.
pub(crate) unsafe fn read_raw_bytes(ptr: *mut std::ffi::c_void, len: usize) -> CkResult<Vec<u8>> {
    // Zero length returns empty without constructing a slice (never a NULL
    // zero-length slice); NULL with nonzero length is rejected outright.
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    // W1-L4-02: hard cap on how much caller memory a single mechanism read
    // may copy. T03: full extent arithmetic (cap, isize::MAX, end wrap).
    checked_extent(ptr as usize, len as u64, 1, MAX_MECHANISM_PARAM_STRUCT_LEN)
        .map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
    Ok(unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }.to_vec())
}

// ---------------------------------------------------------------------------
// Message crypto parameter helpers (CK_*_MESSAGE_PARAMS ↔ structured proto)
// ---------------------------------------------------------------------------
