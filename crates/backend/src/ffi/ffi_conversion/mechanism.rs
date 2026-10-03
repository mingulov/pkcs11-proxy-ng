//! Mechanism parameter conversion Rust -> C: FfiMechanism owns the
//! reconstructed parameter structs; mechanism_to_ffi is ONE flat
//! per-shape match, kept flat by design for auditability (see the
//! contributor rules).

use super::*;
use crate::ffi::native_allocation::NativeAllocation;
use crate::sp800_108_data_values::{
    CK_SP800_108_COUNTER, CK_SP800_108_DKM_LENGTH, CK_SP800_108_ITERATION_VARIABLE,
    CK_SP800_108_KEY_HANDLE, parse_counter_format, parse_dkm_length_format, parse_key_handle_value,
};
use pkcs11_proxy_ng_types::PointerArray;
use pkcs11_proxy_ng_types::PointerBytes;
use pkcs11_proxy_ng_types::shape_descriptors::{Operation, ParamAbi};

// Thread-local `output_params()` call count (W1-C4-04). Thread-local —
// not global — so parallel tests cannot perturb each other's deltas;
// each `#[test]` runs on its own thread and observes only its calls.
#[cfg(test)]
std::thread_local! {
    static OUTPUT_PARAMS_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod native_owner_tests;
#[cfg(test)]
mod r12_flat_null_tests;
#[cfg(test)]
mod r12_init_retention_tests;
#[cfg(test)]
mod r19_init_retention_tests;
#[cfg(test)]
mod r19_typed_tail_tests;
#[cfg(test)]
mod r20_sanitize_tests;
#[cfg(test)]
mod x3dh_tests;

/// Owns the `CK_MECHANISM` and any backing storage that `pParameter` points
/// into.  The C struct fields reference heap allocations inside `_backing`,
/// which stay at a stable address as long as `FfiMechanism` is alive.
///
/// The outer struct itself is heap-allocated too (C3M uniform outer): the
/// address handed to native code must stay valid not only for the call but
/// for every later operation while the owner is retained, because backends
/// may retain the Init root (proven by the retained-mechanism oracle on
/// i686, where a frame-local outer is observably clobbered).  Readers get
/// owned copies only, never a live reference into retained storage.
///
/// **Safety contract:** callers must not move the byte buffers inside
/// `_backing` (no realloc) while the outer is in use.  Since all fields
/// are private and we never push to a Vec after construction, this is
/// upheld automatically.
pub(crate) struct FfiMechanism {
    outer: NativeAllocation<cryptoki_sys::CK_MECHANISM>,
    _backing: FfiParamBacking,
}

impl FfiMechanism {
    /// Owned copy of the heap-allocated outer `CK_MECHANISM`.
    ///
    /// Copies only: no live `&CK_MECHANISM` into retained storage escapes,
    /// per the [`NativeAllocation`] discipline.
    pub(in crate::ffi) fn ck_mechanism(&self) -> cryptoki_sys::CK_MECHANISM {
        // SAFETY: the outer is a valid initialized CK_MECHANISM owned by
        // this allocation; the copy carries no provenance.
        unsafe { self.outer.snapshot() }
    }

    /// Raw pointer to the heap-allocated outer for native entry.
    ///
    /// The address is stable for as long as this owner (and its session
    /// family slot) is alive, across owner moves and later native calls.
    pub(in crate::ffi) fn ck_mechanism_ptr(&self) -> *mut cryptoki_sys::CK_MECHANISM {
        self.outer.root()
    }

    /// Exclusive access to the heap-allocated outer for native entry and
    /// pre/post-call fixups (e.g. the message fallback NULL/empty
    /// acknowledgement).
    ///
    /// Like [`NativeAllocation::root`], the caller must hold the lifecycle
    /// read exclusion (`OrdinaryGuard`). The borrow is live across the
    /// provider call itself — it is the native-call argument at the migrated
    /// entry sites (e.g. `call_helpers::call_unit_with_mechanism`,
    /// `call_init_with_mechanism`, `kem_ops::ffi_encapsulate_key`) — but
    /// no borrow is retained afterwards: the heap address stays stable
    /// while the owner (and its session family slot) is alive, so the
    /// provider's later reads address stable storage with no Rust
    /// borrow outstanding.
    pub(in crate::ffi) fn ck_mechanism_mut(&mut self) -> &mut cryptoki_sys::CK_MECHANISM {
        // SAFETY: owned allocation, valid initialized CK_MECHANISM, unique
        // borrow of the owner; no other reference aliases this storage.
        unsafe { &mut *self.outer.root() }
    }
    pub(in crate::ffi) fn validate_authenticated_inputs(
        &self,
        input: &CkMechanism,
    ) -> CkResult<()> {
        let valid = match (&self._backing, input.params.as_ref()) {
            (FfiParamBacking::None, None) => true,
            (FfiParamBacking::Bytes(bytes), Some(CkMechanismParams::Iv(iv))) => {
                bytes.len() == iv.iv.len()
            }
            (
                FfiParamBacking::Gostr3410KeyWrap(native, oid, ukm),
                Some(CkMechanismParams::Gostr3410KeyWrap(input)),
            ) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let native = unsafe { native.snapshot() };
                // S2 §6 (R19): each leg matches its presence peer exactly
                // (class + declared length + bytes).
                let leg_matches = |pointer: *mut u8,
                                   struct_len: cryptoki_sys::CK_ULONG,
                                   backing: &[u8],
                                   peer: &PointerBytes| {
                    match peer {
                        PointerBytes::Null { declared_len } => {
                            pointer.is_null()
                                && struct_len as u64 == *declared_len
                                && backing.is_empty()
                        }
                        PointerBytes::Present(bytes) => bytes.expose(|b| {
                            !pointer.is_null()
                                && struct_len as u64 == b.len() as u64
                                && backing == b
                        }),
                    }
                };
                leg_matches(native.pWrapOID, native.ulWrapOIDLen, oid, &input.wrap_oid_presence)
                    && leg_matches(native.pUKM, native.ulUKMLen, ukm, &input.ukm_presence)
                    && native.hKey as u64 == input.key_handle.0
            }
            _ => false,
        };
        if valid { Ok(()) } else { Err(CkRv::DEVICE_ERROR) }
    }

    /// Read owned IV bytes only. Never read the native parameter structure as
    /// bytes or return the typed input, which may contain remapped handles.
    pub(in crate::ffi) fn authenticated_output(
        &self,
    ) -> CkResult<pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput> {
        use pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput;
        match &self._backing {
            FfiParamBacking::None | FfiParamBacking::Gostr3410KeyWrap(..) => {
                Ok(AuthenticatedOutput::Unchanged)
            }
            FfiParamBacking::Bytes(iv) => Ok(AuthenticatedOutput::Iv(iv.clone().into())),
            _ => Err(CkRv::MECHANISM_PARAM_INVALID),
        }
    }
    /// Build an `FfiMechanism` from a parameter pointer, length, and backing.
    ///
    /// **SAFETY INVARIANT (callers must uphold):** `ptr` must point into the
    /// `backing` value (typically `Box::into_raw(...)` or the data pointer of
    /// a `Vec` stored inside `backing`), so that the pointer remains valid for
    /// as long as `_backing` is held. Additionally `ptr` must satisfy the
    /// alignment of whatever type the provider reads through it: a byte-`Vec`
    /// data pointer (alignment 1) is UB backing for an integer or struct
    /// read — materialize those via [`Self::from_box`] with a typed
    /// `NativeAllocation` instead (the MacGeneral/Extract/ObjectHandle arms
    /// were fixed for exactly this after Miri flagged the misalignment).
    /// This helper does not enforce the invariant; it only packages the
    /// fields into the `CK_MECHANISM` shape so the 70+ construction sites in
    /// `mechanism_to_ffi` don't repeat the same struct-literal boilerplate.
    fn with_param(
        mech_type: cryptoki_sys::CK_MECHANISM_TYPE,
        ptr: *mut std::ffi::c_void,
        len: usize,
        backing: FfiParamBacking,
    ) -> Self {
        // The outer is heap-allocated (uniform outer): its address must
        // survive the constructing frame for retained providers.
        let outer = NativeAllocation::from_box(Box::new(cryptoki_sys::CK_MECHANISM {
            mechanism: mech_type,
            pParameter: ptr,
            ulParameterLen: len as cryptoki_sys::CK_ULONG,
        }));
        Self { outer, _backing: backing }
    }

    /// Build an `FfiMechanism` with no parameter (`pParameter = NULL`).
    fn no_param(mech_type: cryptoki_sys::CK_MECHANISM_TYPE) -> Self {
        Self::with_param(mech_type, std::ptr::null_mut(), 0, FfiParamBacking::None)
    }

    /// Build an `FfiMechanism` with an explicit NULL parameter carrying a
    /// narrowed length (R12, S2 §6: validated `Null{n}` → NULL + `n`).
    /// Unlike [`Self::no_param`] (which hardcodes zero), the declared
    /// length survives: some providers dereference NULL only when the
    /// length is nonzero, and crash parity needs the exact length.
    fn with_null_param(
        mech_type: cryptoki_sys::CK_MECHANISM_TYPE,
        len: cryptoki_sys::CK_ULONG,
    ) -> Self {
        // The outer is heap-allocated (uniform outer): its address must
        // survive the constructing frame for retained providers. Built
        // directly (not via `with_param`) so the already-narrowed native
        // length is stored exactly, with no `usize` round-trip.
        let outer = NativeAllocation::from_box(Box::new(cryptoki_sys::CK_MECHANISM {
            mechanism: mech_type,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: len,
        }));
        Self { outer, _backing: FfiParamBacking::None }
    }

    /// Build an `FfiMechanism` from a `Box<T>` C-struct: derives the
    /// `pParameter` pointer from the box's heap allocation (stable
    /// address) and the `ulParameterLen` from `size_of::<T>()`.
    /// The caller passes a closure that constructs the matching
    /// `FfiParamBacking` variant from the same box; this keeps the
    /// box and the pointer-into-box tied together in one expression
    /// and removes the `Box::into_raw` / `std::mem::size_of::<...>()`
    /// boilerplate that repeated at 60+ sites in `mechanism_to_ffi`.
    ///
    /// **Provenance (C3M.2, defect I1):** the raw root is projected from
    /// the persistent [`NativeAllocation`] established by a single
    /// `Box::into_raw`, never from a reborrow (`&mut *boxed`) of a box
    /// that is subsequently moved into backing: that reborrow pattern
    /// invalidates pointer provenance under Miri's borrow models as soon
    /// as the box moves. Ownership transfers exactly once into backing,
    /// so one allocation keeps one owner and one final `Drop`.
    ///
    /// **SAFETY INVARIANT:** `make_backing(a)` MUST move `a` into a
    /// variant of `FfiParamBacking` so that the C struct's allocation
    /// (and any pointers the struct itself holds into side-data) stay
    /// live for as long as the returned `FfiMechanism`. The allocation
    /// moves as a [`NativeAllocation`]: its raw root never reborrows, so
    /// later owner moves cannot strand the stored `pParameter`.
    fn from_box<T>(
        mech_type: cryptoki_sys::CK_MECHANISM_TYPE,
        boxed: Box<T>,
        make_backing: impl FnOnce(NativeAllocation<T>) -> FfiParamBacking,
    ) -> Self {
        let len = std::mem::size_of::<T>();
        let allocation = NativeAllocation::from_box(boxed);
        let ptr = allocation.root() as *mut std::ffi::c_void;
        Self::with_param(mech_type, ptr, len, make_backing(allocation))
    }

    /// Allocation-free equality probe against [`Self::output_params`].
    ///
    /// Returns whether `output_params()` would return a value equal to
    /// `expected`, without cloning any backing bytes. W1-C4-04:
    /// `call_bytes_exact_with_mechanism_output` reuses its pre-call
    /// snapshot when this probe reports unchanged, so the common path
    /// snapshots once per call instead of twice. Every arm below mirrors
    /// its `output_params()` counterpart field for field (including the
    /// clamping, null-guards, and empty-set guards); the
    /// `output_params_equal_tests` battery pins agreement on every arm
    /// plus provider-write flips.
    ///
    /// This probe allocates nothing: it compares scalars and byte slices
    /// in place and never builds an owned `CkMechanismParams`.
    pub(in crate::ffi) fn output_params_equal(&self, expected: &Option<CkMechanismParams>) -> bool {
        match &self._backing {
            FfiParamBacking::Gcm(gcm, iv, aad) => {
                let Some(CkMechanismParams::Gcm(e)) = expected else { return false };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let gcm = unsafe { gcm.snapshot() };
                let iv_len = (gcm.ulIvLen as usize).min(iv.len());
                let aad_len = (gcm.ulAADLen as usize).min(aad.len());
                e.iv_bits == gcm.ulIvBits as u64
                    && e.iv_buffer_len == iv.len() as u64
                    && e.tag_bits == gcm.ulTagBits as u64
                    && e.iv_presence
                        == presence_from_ffi(gcm.pIv.is_null(), gcm.ulIvLen, &iv[..iv_len])
                    && e.aad_presence
                        == presence_from_ffi(gcm.pAAD.is_null(), gcm.ulAADLen, &aad[..aad_len])
            }
            FfiParamBacking::Tls12MasterKeyDerive(tls12, client_random, server_random, version) => {
                let Some(CkMechanismParams::Tls12MasterKeyDerive(e)) = expected else {
                    return false;
                };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let tls12 = unsafe { tls12.snapshot() };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let version = version.as_ref().map(|cell| unsafe { cell.snapshot() });
                // A NULL cell echoes zeroed scalars (validation forces the
                // caller's scalars zero under a set null bit, so the echo
                // is exact).
                let (major, minor) = version.map_or((0, 0), |v| (v.major as u32, v.minor as u32));
                e.random_info.client_random_presence
                    == presence_from_ffi(
                        tls12.RandomInfo.pClientRandom.is_null(),
                        tls12.RandomInfo.ulClientRandomLen,
                        client_random.as_slice(),
                    )
                    && e.random_info.server_random_presence
                        == presence_from_ffi(
                            tls12.RandomInfo.pServerRandom.is_null(),
                            tls12.RandomInfo.ulServerRandomLen,
                            server_random.as_slice(),
                        )
                    && e.version_major == major
                    && e.version_minor == minor
                    && e.version_is_null == tls12.pVersion.is_null()
                    && e.prf_hash_mechanism == CkMechanismType(tls12.prfHashMechanism as u64)
            }
            FfiParamBacking::WtlsMasterKeyDerive(wtls, client_random, server_random, version) => {
                let Some(CkMechanismParams::WtlsMasterKeyDerive(e)) = expected else {
                    return false;
                };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let wtls = unsafe { wtls.snapshot() };
                e.digest_mechanism == CkMechanismType(wtls.DigestMechanism as u64)
                    && e.random_info.client_random_presence
                        == presence_from_ffi(
                            wtls.RandomInfo.pClientRandom.is_null(),
                            wtls.RandomInfo.ulClientRandomLen,
                            client_random.as_slice(),
                        )
                    && e.random_info.server_random_presence
                        == presence_from_ffi(
                            wtls.RandomInfo.pServerRandom.is_null(),
                            wtls.RandomInfo.ulServerRandomLen,
                            server_random.as_slice(),
                        )
                    && e.version == version.first().copied().unwrap_or_default() as u32
                    && e.version_is_null == wtls.pVersion.is_null()
            }
            FfiParamBacking::WtlsKeyMat(
                wtls,
                client_random,
                server_random,
                key_mat_out,
                iv,
                iv_stored,
            ) => {
                let Some(CkMechanismParams::WtlsKeyMat(e)) = expected else { return false };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let wtls = unsafe { wtls.snapshot() };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let key_mat_out = key_mat_out.as_ref().map(|out| unsafe { out.snapshot() });
                let iv_len = bits_to_bytes_ceil(wtls.ulIVSizeInBits).min(iv.len());
                // A NULL OUT struct echoes the stored peer verbatim (the
                // provider never saw the IVs); a live one echoes the
                // stored class with the post-call bytes.
                let iv_echo = match key_mat_out {
                    None => iv_stored.clone(),
                    Some(_) => key_mat_iv_echo(iv_stored, iv.as_slice(), iv_len),
                };
                // A NULL OUT struct echoes zeroed handles (validation
                // forces the caller's handles zero under a set null bit,
                // so the echo is exact).
                let (mac, key) = key_mat_out.map_or((0, 0), |o| (o.hMacSecret, o.hKey));
                e.digest_mechanism == CkMechanismType(wtls.DigestMechanism as u64)
                    && e.mac_size_bits == wtls.ulMacSizeInBits as u64
                    && e.key_size_bits == wtls.ulKeySizeInBits as u64
                    && e.iv_size_bits == wtls.ulIVSizeInBits as u64
                    && e.sequence_number == wtls.ulSequenceNumber as u64
                    && e.is_export == (wtls.bIsExport != 0)
                    && e.random_info.client_random_presence
                        == presence_from_ffi(
                            wtls.RandomInfo.pClientRandom.is_null(),
                            wtls.RandomInfo.ulClientRandomLen,
                            client_random.as_slice(),
                        )
                    && e.random_info.server_random_presence
                        == presence_from_ffi(
                            wtls.RandomInfo.pServerRandom.is_null(),
                            wtls.RandomInfo.ulServerRandomLen,
                            server_random.as_slice(),
                        )
                    && e.mac_secret_handle == CkObjectHandle(mac as u64)
                    && e.key_handle == CkObjectHandle(key as u64)
                    && e.returned_key_material_is_null == wtls.pReturnedKeyMaterial.is_null()
                    && e.iv_presence == iv_echo
            }
            FfiParamBacking::Ssl3KeyMat(
                ssl3,
                client_random,
                server_random,
                key_mat_out,
                client_iv,
                server_iv,
                client_iv_stored,
                server_iv_stored,
            ) => {
                let Some(CkMechanismParams::Ssl3KeyMat(e)) = expected else { return false };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let ssl3 = unsafe { ssl3.snapshot() };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let key_mat_out = key_mat_out.as_ref().map(|out| unsafe { out.snapshot() });
                let iv_len = bits_to_bytes_ceil(ssl3.ulIVSizeInBits).min(client_iv.len());
                // A NULL OUT struct echoes the stored peers verbatim (the
                // provider never saw the IVs); a live one echoes the
                // stored classes with the post-call bytes.
                let client_iv_echo = match key_mat_out {
                    None => client_iv_stored.clone(),
                    Some(_) => key_mat_iv_echo(client_iv_stored, client_iv.as_slice(), iv_len),
                };
                let server_iv_echo = match key_mat_out {
                    None => server_iv_stored.clone(),
                    Some(_) => key_mat_iv_echo(
                        server_iv_stored,
                        server_iv.as_slice(),
                        iv_len.min(server_iv.len()),
                    ),
                };
                // A NULL OUT struct echoes zeroed handles (validation
                // forces the caller's handles zero under a set null bit,
                // so the echo is exact).
                let (client_mac, server_mac, client_key, server_key) = key_mat_out
                    .map_or((0, 0, 0, 0), |o| {
                        (o.hClientMacSecret, o.hServerMacSecret, o.hClientKey, o.hServerKey)
                    });
                e.mac_size_bits == ssl3.ulMacSizeInBits as u64
                    && e.key_size_bits == ssl3.ulKeySizeInBits as u64
                    && e.iv_size_bits == ssl3.ulIVSizeInBits as u64
                    && e.is_export == (ssl3.bIsExport != 0)
                    && e.random_info.client_random_presence
                        == presence_from_ffi(
                            ssl3.RandomInfo.pClientRandom.is_null(),
                            ssl3.RandomInfo.ulClientRandomLen,
                            client_random.as_slice(),
                        )
                    && e.random_info.server_random_presence
                        == presence_from_ffi(
                            ssl3.RandomInfo.pServerRandom.is_null(),
                            ssl3.RandomInfo.ulServerRandomLen,
                            server_random.as_slice(),
                        )
                    && e.prf_hash_mechanism == CkMechanismType(0)
                    && e.client_mac_secret_handle == CkObjectHandle(client_mac as u64)
                    && e.server_mac_secret_handle == CkObjectHandle(server_mac as u64)
                    && e.client_key_handle == CkObjectHandle(client_key as u64)
                    && e.server_key_handle == CkObjectHandle(server_key as u64)
                    && e.returned_key_material_is_null == ssl3.pReturnedKeyMaterial.is_null()
                    && e.client_iv_presence == client_iv_echo
                    && e.server_iv_presence == server_iv_echo
            }
            FfiParamBacking::Tls12KeyMat(
                tls12,
                client_random,
                server_random,
                key_mat_out,
                client_iv,
                server_iv,
                client_iv_stored,
                server_iv_stored,
            ) => {
                let Some(CkMechanismParams::Ssl3KeyMat(e)) = expected else { return false };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let tls12 = unsafe { tls12.snapshot() };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let key_mat_out = key_mat_out.as_ref().map(|out| unsafe { out.snapshot() });
                let iv_len = bits_to_bytes_ceil(tls12.ulIVSizeInBits).min(client_iv.len());
                // A NULL OUT struct echoes the stored peers verbatim (the
                // provider never saw the IVs); a live one echoes the
                // stored classes with the post-call bytes.
                let client_iv_echo = match key_mat_out {
                    None => client_iv_stored.clone(),
                    Some(_) => key_mat_iv_echo(client_iv_stored, client_iv.as_slice(), iv_len),
                };
                let server_iv_echo = match key_mat_out {
                    None => server_iv_stored.clone(),
                    Some(_) => key_mat_iv_echo(
                        server_iv_stored,
                        server_iv.as_slice(),
                        iv_len.min(server_iv.len()),
                    ),
                };
                // A NULL OUT struct echoes zeroed handles (validation
                // forces the caller's handles zero under a set null bit,
                // so the echo is exact).
                let (client_mac, server_mac, client_key, server_key) = key_mat_out
                    .map_or((0, 0, 0, 0), |o| {
                        (o.hClientMacSecret, o.hServerMacSecret, o.hClientKey, o.hServerKey)
                    });
                e.mac_size_bits == tls12.ulMacSizeInBits as u64
                    && e.key_size_bits == tls12.ulKeySizeInBits as u64
                    && e.iv_size_bits == tls12.ulIVSizeInBits as u64
                    && e.is_export == (tls12.bIsExport != 0)
                    && e.random_info.client_random_presence
                        == presence_from_ffi(
                            tls12.RandomInfo.pClientRandom.is_null(),
                            tls12.RandomInfo.ulClientRandomLen,
                            client_random.as_slice(),
                        )
                    && e.random_info.server_random_presence
                        == presence_from_ffi(
                            tls12.RandomInfo.pServerRandom.is_null(),
                            tls12.RandomInfo.ulServerRandomLen,
                            server_random.as_slice(),
                        )
                    && e.prf_hash_mechanism == CkMechanismType(tls12.prfHashMechanism as u64)
                    && e.client_mac_secret_handle == CkObjectHandle(client_mac as u64)
                    && e.server_mac_secret_handle == CkObjectHandle(server_mac as u64)
                    && e.client_key_handle == CkObjectHandle(client_key as u64)
                    && e.server_key_handle == CkObjectHandle(server_key as u64)
                    && e.returned_key_material_is_null == tls12.pReturnedKeyMaterial.is_null()
                    && e.client_iv_presence == client_iv_echo
                    && e.server_iv_presence == server_iv_echo
            }
            FfiParamBacking::Sp800108Kdf(
                sp800,
                data_params,
                data_buffers,
                _natives,
                derived_keys,
            ) => {
                // Mirror the `!derived_keys.is_empty()` guard: an empty set
                // falls through to `_ => None` on both sides.
                if derived_keys.is_empty() {
                    return expected.is_none();
                }
                let Some(CkMechanismParams::Sp800108Kdf(e)) = expected else { return false };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let sp800 = unsafe { sp800.snapshot() };
                e.prf_type == CkMechanismType(sp800.prfType as u64)
                    && sp800_108_data_params_equal(
                        data_params,
                        data_buffers,
                        sp800.pDataParams.is_null(),
                        sp800.ulNumberOfDataParams,
                        &e.data_params_presence,
                    )
                    && sp800_108_derived_keys_equal(
                        derived_keys,
                        &e.additional_derived_keys_presence,
                    )
            }
            FfiParamBacking::Sp800108FeedbackKdf(
                sp800,
                data_params,
                data_buffers,
                _natives,
                iv,
                derived_keys,
            ) => {
                if derived_keys.is_empty() {
                    return expected.is_none();
                }
                let Some(CkMechanismParams::Sp800108FeedbackKdf(e)) = expected else {
                    return false;
                };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let sp800 = unsafe { sp800.snapshot() };
                e.prf_type == CkMechanismType(sp800.prfType as u64)
                    && sp800_108_data_params_equal(
                        data_params,
                        data_buffers,
                        sp800.pDataParams.is_null(),
                        sp800.ulNumberOfDataParams,
                        &e.data_params_presence,
                    )
                    && e.iv_presence
                        == presence_from_ffi(sp800.pIV.is_null(), sp800.ulIVLen, iv.as_slice())
                    && sp800_108_derived_keys_equal(
                        derived_keys,
                        &e.additional_derived_keys_presence,
                    )
            }
            FfiParamBacking::TlsPrf(tls, seed, label, output, output_len) => {
                let Some(CkMechanismParams::TlsPrf(e)) = expected else { return false };
                // SAFETY: backing is borrowed alive; the copies carry no provenance.
                let tls = unsafe { tls.snapshot() };
                let written = match output_len.as_ref() {
                    // SAFETY: backing is borrowed alive; the copy carries no provenance.
                    Some(cell) => (unsafe { cell.snapshot() } as usize).min(output.len()),
                    // No length cell: the whole buffer is the written
                    // extent (a NULL `pulOutputLen` forces `output_len`
                    // zero, so the buffer is empty-sized — see the arm).
                    None => output.len(),
                };
                e.seed_presence
                    == presence_from_ffi(tls.pSeed.is_null(), tls.ulSeedLen, seed.as_slice())
                    && e.label_presence
                        == presence_from_ffi(tls.pLabel.is_null(), tls.ulLabelLen, label.as_slice())
                    && e.output_len == written as u64
                    && e.output.expose(|b| b == &output[..written])
                    && e.output_is_null == tls.pOutput.is_null()
                    && e.output_len_is_null == tls.pulOutputLen.is_null()
            }
            FfiParamBacking::WtlsPrf(wtls, seed, label, output, output_len) => {
                let Some(CkMechanismParams::WtlsPrf(e)) = expected else { return false };
                // SAFETY: backing is borrowed alive; the copies carry no provenance.
                let wtls = unsafe { wtls.snapshot() };
                let written = match output_len.as_ref() {
                    // SAFETY: backing is borrowed alive; the copy carries no provenance.
                    Some(cell) => (unsafe { cell.snapshot() } as usize).min(output.len()),
                    // No length cell: the whole buffer is the written
                    // extent (see the TLS-PRF arm above).
                    None => output.len(),
                };
                e.digest_mechanism == CkMechanismType(wtls.DigestMechanism as u64)
                    && e.seed_presence
                        == presence_from_ffi(wtls.pSeed.is_null(), wtls.ulSeedLen, seed.as_slice())
                    && e.label_presence
                        == presence_from_ffi(
                            wtls.pLabel.is_null(),
                            wtls.ulLabelLen,
                            label.as_slice(),
                        )
                    && e.output_len == written as u64
                    && e.output.expose(|b| b == &output[..written])
                    && e.output_is_null == wtls.pOutput.is_null()
                    && e.output_len_is_null == wtls.pulOutputLen.is_null()
            }
            FfiParamBacking::Ssl3MasterKeyDerive(ssl3, client_random, server_random, version) => {
                let Some(CkMechanismParams::Ssl3MasterKeyDerive(e)) = expected else {
                    return false;
                };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let ssl3 = unsafe { ssl3.snapshot() };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let version = version.as_ref().map(|cell| unsafe { cell.snapshot() });
                // A NULL cell echoes zeroed scalars (validation forces the
                // caller's scalars zero under a set null bit, so the echo
                // is exact).
                let (major, minor) = version.map_or((0, 0), |v| (v.major as u32, v.minor as u32));
                e.random_info.client_random_presence
                    == presence_from_ffi(
                        ssl3.RandomInfo.pClientRandom.is_null(),
                        ssl3.RandomInfo.ulClientRandomLen,
                        client_random.as_slice(),
                    )
                    && e.random_info.server_random_presence
                        == presence_from_ffi(
                            ssl3.RandomInfo.pServerRandom.is_null(),
                            ssl3.RandomInfo.ulServerRandomLen,
                            server_random.as_slice(),
                        )
                    && e.version_major == major
                    && e.version_minor == minor
                    && e.version_is_null == ssl3.pVersion.is_null()
            }
            FfiParamBacking::Pbe(pbe, init_vector, _password, _salt) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let pbe = unsafe { pbe.snapshot() };
                if pbe.pInitVector.is_null() {
                    return expected.is_none();
                }
                let Some(CkMechanismParams::Pbe(e)) = expected else { return false };
                // `output_params()` surfaces ONLY the IV (full backing
                // copy); password and salt echo class-faithful redacted
                // peers (NULL-ness + declared lengths read back the
                // provider-untouched input legs; the bytes never echo —
                // AGENTS.md §4).
                e.init_vector_presence == PointerBytes::present_copy(init_vector)
                    && e.password_presence
                        == presence_from_ffi(pbe.pPassword.is_null(), pbe.ulPasswordLen, &[])
                    && e.salt_presence == presence_from_ffi(pbe.pSalt.is_null(), pbe.ulSaltLen, &[])
                    && e.iteration == pbe.ulIteration as u64
            }
            _ => expected.is_none(),
        }
    }

    pub(in crate::ffi) fn output_params(&self) -> Option<CkMechanismParams> {
        #[cfg(test)]
        OUTPUT_PARAMS_CALLS.with(|c| c.set(c.get().saturating_add(1)));
        match &self._backing {
            FfiParamBacking::Gcm(gcm, iv, aad) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let gcm = unsafe { gcm.snapshot() };
                let iv_len = (gcm.ulIvLen as usize).min(iv.len());
                let aad_len = (gcm.ulAADLen as usize).min(aad.len());
                Some(CkMechanismParams::Gcm(GcmParams {
                    iv_bits: gcm.ulIvBits as u64,
                    iv_buffer_len: iv.len() as u64,
                    tag_bits: gcm.ulTagBits as u64,
                    // F3/D2: input pointers are provider-untouched, so the
                    // post-call pointer class still reports the caller's.
                    // S2 §6 (R19): NULL legs echo the STRUCT length (the
                    // caller's declared length survives exactly).
                    iv_presence: presence_from_ffi(gcm.pIv.is_null(), gcm.ulIvLen, &iv[..iv_len]),
                    aad_presence: presence_from_ffi(
                        gcm.pAAD.is_null(),
                        gcm.ulAADLen,
                        &aad[..aad_len],
                    ),
                }))
            }
            FfiParamBacking::Tls12MasterKeyDerive(tls12, client_random, server_random, version) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let tls12 = unsafe { tls12.snapshot() };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let version = version.as_ref().map(|cell| unsafe { cell.snapshot() });
                // CK_TLS12_MASTER_KEY_DERIVE_PARAMS.pVersion is OUT —
                // the HSM writes the negotiated CK_VERSION here when
                // pVersion is non-NULL. Surface the version_major /
                // version_minor back to the caller; the random data
                // and PRF mechanism are unchanged by the derive (those
                // fields are caller-supplied inputs). A NULL cell echoes
                // zeroed scalars (validation forces the caller's scalars
                // zero under a set null bit, so the echo is exact).
                let (major, minor) = version.map_or((0, 0), |v| (v.major as u32, v.minor as u32));
                Some(CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
                    random_info: pkcs11_proxy_ng_types::SslRandomData {
                        client_random_presence: presence_from_ffi(
                            tls12.RandomInfo.pClientRandom.is_null(),
                            tls12.RandomInfo.ulClientRandomLen,
                            client_random.as_slice(),
                        ),
                        server_random_presence: presence_from_ffi(
                            tls12.RandomInfo.pServerRandom.is_null(),
                            tls12.RandomInfo.ulServerRandomLen,
                            server_random.as_slice(),
                        ),
                    },
                    version_major: major,
                    version_minor: minor,
                    prf_hash_mechanism: CkMechanismType(tls12.prfHashMechanism as u64),
                    version_is_null: tls12.pVersion.is_null(),
                }))
            }
            FfiParamBacking::WtlsMasterKeyDerive(wtls, client_random, server_random, version) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let wtls = unsafe { wtls.snapshot() };
                Some(CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
                    digest_mechanism: CkMechanismType(wtls.DigestMechanism as u64),
                    random_info: WtlsRandomData {
                        client_random_presence: presence_from_ffi(
                            wtls.RandomInfo.pClientRandom.is_null(),
                            wtls.RandomInfo.ulClientRandomLen,
                            client_random.as_slice(),
                        ),
                        server_random_presence: presence_from_ffi(
                            wtls.RandomInfo.pServerRandom.is_null(),
                            wtls.RandomInfo.ulServerRandomLen,
                            server_random.as_slice(),
                        ),
                    },
                    version: version.first().copied().unwrap_or_default() as u32,
                    version_is_null: wtls.pVersion.is_null(),
                }))
            }
            FfiParamBacking::WtlsKeyMat(
                wtls,
                client_random,
                server_random,
                key_mat_out,
                iv,
                iv_stored,
            ) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let wtls = unsafe { wtls.snapshot() };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let key_mat_out = key_mat_out.as_ref().map(|out| unsafe { out.snapshot() });
                let iv_len = bits_to_bytes_ceil(wtls.ulIVSizeInBits).min(iv.len());
                // A NULL OUT struct echoes the stored peer verbatim (the
                // provider never saw the IVs); a live one echoes the
                // stored class with the post-call bytes.
                let iv_echo = match key_mat_out {
                    None => iv_stored.clone(),
                    Some(_) => key_mat_iv_echo(iv_stored, iv.as_slice(), iv_len),
                };
                // A NULL OUT struct echoes zeroed handles (validation
                // forces the caller's handles zero under a set null bit,
                // so the echo is exact).
                let (mac, key) = key_mat_out.map_or((0, 0), |o| (o.hMacSecret, o.hKey));
                Some(CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
                    digest_mechanism: CkMechanismType(wtls.DigestMechanism as u64),
                    mac_size_bits: wtls.ulMacSizeInBits as u64,
                    key_size_bits: wtls.ulKeySizeInBits as u64,
                    iv_size_bits: wtls.ulIVSizeInBits as u64,
                    sequence_number: wtls.ulSequenceNumber as u64,
                    is_export: wtls.bIsExport != 0,
                    random_info: WtlsRandomData {
                        client_random_presence: presence_from_ffi(
                            wtls.RandomInfo.pClientRandom.is_null(),
                            wtls.RandomInfo.ulClientRandomLen,
                            client_random.as_slice(),
                        ),
                        server_random_presence: presence_from_ffi(
                            wtls.RandomInfo.pServerRandom.is_null(),
                            wtls.RandomInfo.ulServerRandomLen,
                            server_random.as_slice(),
                        ),
                    },
                    mac_secret_handle: CkObjectHandle(mac as u64),
                    key_handle: CkObjectHandle(key as u64),
                    iv_presence: iv_echo.clone(),
                    returned_key_material_is_null: wtls.pReturnedKeyMaterial.is_null(),
                }))
            }
            FfiParamBacking::Ssl3KeyMat(
                ssl3,
                client_random,
                server_random,
                key_mat_out,
                client_iv,
                server_iv,
                client_iv_stored,
                server_iv_stored,
            ) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let ssl3 = unsafe { ssl3.snapshot() };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let key_mat_out = key_mat_out.as_ref().map(|out| unsafe { out.snapshot() });
                let iv_len = bits_to_bytes_ceil(ssl3.ulIVSizeInBits).min(client_iv.len());
                // A NULL OUT struct echoes the stored peers verbatim (the
                // provider never saw the IVs); a live one echoes the
                // stored classes with the post-call bytes.
                let client_iv_echo = match key_mat_out {
                    None => client_iv_stored.clone(),
                    Some(_) => key_mat_iv_echo(client_iv_stored, client_iv.as_slice(), iv_len),
                };
                let server_iv_echo = match key_mat_out {
                    None => server_iv_stored.clone(),
                    Some(_) => key_mat_iv_echo(
                        server_iv_stored,
                        server_iv.as_slice(),
                        iv_len.min(server_iv.len()),
                    ),
                };
                // A NULL OUT struct echoes zeroed handles (validation
                // forces the caller's handles zero under a set null bit,
                // so the echo is exact).
                let (client_mac, server_mac, client_key, server_key) = key_mat_out
                    .map_or((0, 0, 0, 0), |o| {
                        (o.hClientMacSecret, o.hServerMacSecret, o.hClientKey, o.hServerKey)
                    });
                Some(CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
                    mac_size_bits: ssl3.ulMacSizeInBits as u64,
                    key_size_bits: ssl3.ulKeySizeInBits as u64,
                    iv_size_bits: ssl3.ulIVSizeInBits as u64,
                    is_export: ssl3.bIsExport != 0,
                    random_info: pkcs11_proxy_ng_types::SslRandomData {
                        client_random_presence: presence_from_ffi(
                            ssl3.RandomInfo.pClientRandom.is_null(),
                            ssl3.RandomInfo.ulClientRandomLen,
                            client_random.as_slice(),
                        ),
                        server_random_presence: presence_from_ffi(
                            ssl3.RandomInfo.pServerRandom.is_null(),
                            ssl3.RandomInfo.ulServerRandomLen,
                            server_random.as_slice(),
                        ),
                    },
                    prf_hash_mechanism: CkMechanismType(0),
                    client_mac_secret_handle: CkObjectHandle(client_mac as u64),
                    server_mac_secret_handle: CkObjectHandle(server_mac as u64),
                    client_key_handle: CkObjectHandle(client_key as u64),
                    server_key_handle: CkObjectHandle(server_key as u64),
                    client_iv_presence: client_iv_echo.clone(),
                    server_iv_presence: server_iv_echo.clone(),
                    returned_key_material_is_null: ssl3.pReturnedKeyMaterial.is_null(),
                }))
            }
            FfiParamBacking::Tls12KeyMat(
                tls12,
                client_random,
                server_random,
                key_mat_out,
                client_iv,
                server_iv,
                client_iv_stored,
                server_iv_stored,
            ) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let tls12 = unsafe { tls12.snapshot() };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let key_mat_out = key_mat_out.as_ref().map(|out| unsafe { out.snapshot() });
                let iv_len = bits_to_bytes_ceil(tls12.ulIVSizeInBits).min(client_iv.len());
                // A NULL OUT struct echoes the stored peers verbatim (the
                // provider never saw the IVs); a live one echoes the
                // stored classes with the post-call bytes.
                let client_iv_echo = match key_mat_out {
                    None => client_iv_stored.clone(),
                    Some(_) => key_mat_iv_echo(client_iv_stored, client_iv.as_slice(), iv_len),
                };
                let server_iv_echo = match key_mat_out {
                    None => server_iv_stored.clone(),
                    Some(_) => key_mat_iv_echo(
                        server_iv_stored,
                        server_iv.as_slice(),
                        iv_len.min(server_iv.len()),
                    ),
                };
                // A NULL OUT struct echoes zeroed handles (validation
                // forces the caller's handles zero under a set null bit,
                // so the echo is exact).
                let (client_mac, server_mac, client_key, server_key) = key_mat_out
                    .map_or((0, 0, 0, 0), |o| {
                        (o.hClientMacSecret, o.hServerMacSecret, o.hClientKey, o.hServerKey)
                    });
                Some(CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
                    mac_size_bits: tls12.ulMacSizeInBits as u64,
                    key_size_bits: tls12.ulKeySizeInBits as u64,
                    iv_size_bits: tls12.ulIVSizeInBits as u64,
                    is_export: tls12.bIsExport != 0,
                    random_info: pkcs11_proxy_ng_types::SslRandomData {
                        client_random_presence: presence_from_ffi(
                            tls12.RandomInfo.pClientRandom.is_null(),
                            tls12.RandomInfo.ulClientRandomLen,
                            client_random.as_slice(),
                        ),
                        server_random_presence: presence_from_ffi(
                            tls12.RandomInfo.pServerRandom.is_null(),
                            tls12.RandomInfo.ulServerRandomLen,
                            server_random.as_slice(),
                        ),
                    },
                    prf_hash_mechanism: CkMechanismType(tls12.prfHashMechanism as u64),
                    client_mac_secret_handle: CkObjectHandle(client_mac as u64),
                    server_mac_secret_handle: CkObjectHandle(server_mac as u64),
                    client_key_handle: CkObjectHandle(client_key as u64),
                    server_key_handle: CkObjectHandle(server_key as u64),
                    client_iv_presence: client_iv_echo.clone(),
                    server_iv_presence: server_iv_echo.clone(),
                    returned_key_material_is_null: tls12.pReturnedKeyMaterial.is_null(),
                }))
            }
            FfiParamBacking::Sp800108Kdf(
                sp800,
                data_params,
                data_buffers,
                _natives,
                derived_keys,
            ) if !derived_keys.is_empty() => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let sp800 = unsafe { sp800.snapshot() };
                let data_params = sp800_108_data_params_from_ffi(data_params, data_buffers);
                // The guard guarantees a non-empty derived-keys set, so the
                // keys peer is always `Present` here; the data-params array
                // may still be NULL (inputs round-trip exactly).
                let data_params_presence = if sp800.pDataParams.is_null() {
                    PointerArray::null_count(sp800.ulNumberOfDataParams as u64)
                } else {
                    PointerArray::present(data_params.clone())
                };
                let additional_derived_keys = derived_keys.output_keys();
                Some(CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
                    prf_type: CkMechanismType(sp800.prfType as u64),
                    data_params_presence,
                    additional_derived_keys_presence: PointerArray::present(
                        additional_derived_keys.clone(),
                    ),
                }))
            }
            FfiParamBacking::Sp800108FeedbackKdf(
                sp800,
                data_params,
                data_buffers,
                _natives,
                iv,
                derived_keys,
            ) if !derived_keys.is_empty() => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let sp800 = unsafe { sp800.snapshot() };
                let data_params = sp800_108_data_params_from_ffi(data_params, data_buffers);
                let data_params_presence = if sp800.pDataParams.is_null() {
                    PointerArray::null_count(sp800.ulNumberOfDataParams as u64)
                } else {
                    PointerArray::present(data_params.clone())
                };
                let iv_presence =
                    presence_from_ffi(sp800.pIV.is_null(), sp800.ulIVLen, iv.as_slice());
                let additional_derived_keys = derived_keys.output_keys();
                Some(CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
                    prf_type: CkMechanismType(sp800.prfType as u64),
                    data_params_presence,
                    iv_presence,
                    additional_derived_keys_presence: PointerArray::present(
                        additional_derived_keys.clone(),
                    ),
                }))
            }
            FfiParamBacking::TlsPrf(tls, seed, label, output, output_len) => {
                // SAFETY: backing is borrowed alive; the copies carry no provenance.
                let tls = unsafe { tls.snapshot() };
                // `pOutput`/`*pulOutputLen` are OUT — the provider writes
                // the PRF bytes and the written length (W1-C5-01). Clamp
                // a misbehaving length to the buffer we allocated. With no
                // length cell the whole buffer is the written extent (a
                // NULL `pulOutputLen` forces `output_len` zero, so the
                // buffer is empty-sized — see the arm).
                let written = match output_len.as_ref() {
                    // SAFETY: backing is borrowed alive; the copy carries no provenance.
                    Some(cell) => (unsafe { cell.snapshot() } as usize).min(output.len()),
                    None => output.len(),
                };
                Some(CkMechanismParams::TlsPrf(TlsPrfParams {
                    seed_presence: presence_from_ffi(
                        tls.pSeed.is_null(),
                        tls.ulSeedLen,
                        seed.as_slice(),
                    ),
                    label_presence: presence_from_ffi(
                        tls.pLabel.is_null(),
                        tls.ulLabelLen,
                        label.as_slice(),
                    ),
                    output_len: written as u64,
                    output: output[..written].to_vec().into(),
                    output_is_null: tls.pOutput.is_null(),
                    output_len_is_null: tls.pulOutputLen.is_null(),
                }))
            }
            FfiParamBacking::WtlsPrf(wtls, seed, label, output, output_len) => {
                // SAFETY: backing is borrowed alive; the copies carry no provenance.
                let wtls = unsafe { wtls.snapshot() };
                let written = match output_len.as_ref() {
                    // SAFETY: backing is borrowed alive; the copy carries no provenance.
                    Some(cell) => (unsafe { cell.snapshot() } as usize).min(output.len()),
                    // No length cell: the whole buffer is the written
                    // extent (see the TLS-PRF arm above).
                    None => output.len(),
                };
                Some(CkMechanismParams::WtlsPrf(WtlsPrfParams {
                    digest_mechanism: CkMechanismType(wtls.DigestMechanism as u64),
                    seed_presence: presence_from_ffi(
                        wtls.pSeed.is_null(),
                        wtls.ulSeedLen,
                        seed.as_slice(),
                    ),
                    label_presence: presence_from_ffi(
                        wtls.pLabel.is_null(),
                        wtls.ulLabelLen,
                        label.as_slice(),
                    ),
                    output_len: written as u64,
                    output: output[..written].to_vec().into(),
                    output_is_null: wtls.pOutput.is_null(),
                    output_len_is_null: wtls.pulOutputLen.is_null(),
                }))
            }
            FfiParamBacking::Ssl3MasterKeyDerive(ssl3, client_random, server_random, version) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let ssl3 = unsafe { ssl3.snapshot() };
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let version = version.as_ref().map(|cell| unsafe { cell.snapshot() });
                // CK_SSL3_MASTER_KEY_DERIVE_PARAMS.pVersion is OUT —
                // the provider writes the negotiated CK_VERSION here
                // (W1-C5-01; mirrors the TLS 1.2 arm above). A NULL cell
                // echoes zeroed scalars (validation forces the caller's
                // scalars zero under a set null bit, so the echo is exact).
                let (major, minor) = version.map_or((0, 0), |v| (v.major as u32, v.minor as u32));
                Some(CkMechanismParams::Ssl3MasterKeyDerive(Ssl3MasterKeyDeriveParams {
                    random_info: pkcs11_proxy_ng_types::SslRandomData {
                        client_random_presence: presence_from_ffi(
                            ssl3.RandomInfo.pClientRandom.is_null(),
                            ssl3.RandomInfo.ulClientRandomLen,
                            client_random.as_slice(),
                        ),
                        server_random_presence: presence_from_ffi(
                            ssl3.RandomInfo.pServerRandom.is_null(),
                            ssl3.RandomInfo.ulServerRandomLen,
                            server_random.as_slice(),
                        ),
                    },
                    version_major: major,
                    version_minor: minor,
                    version_is_null: ssl3.pVersion.is_null(),
                }))
            }
            FfiParamBacking::Pbe(pbe, init_vector, _password, _salt) => {
                // SAFETY: backing is borrowed alive; the copy carries no provenance.
                let pbe = unsafe { pbe.snapshot() };
                if pbe.pInitVector.is_null() {
                    return None;
                }
                // CK_PBE_PARAMS.pInitVector is OUT — the HSM writes the generated
                // 8-byte IV here during PBE key generation. Surface ONLY the IV;
                // the password and salt are caller-supplied secrets/inputs and
                // must never be echoed back over the wire (AGENTS.md §4) — they
                // echo class-faithful redacted peers (NULL-ness + declared
                // lengths read back the provider-untouched input legs).
                Some(CkMechanismParams::Pbe(PbeParams {
                    iteration: pbe.ulIteration as u64,
                    init_vector_presence: PointerBytes::present_copy(init_vector),
                    password_presence: presence_from_ffi(
                        pbe.pPassword.is_null(),
                        pbe.ulPasswordLen,
                        &[],
                    ),
                    salt_presence: presence_from_ffi(pbe.pSalt.is_null(), pbe.ulSaltLen, &[]),
                }))
            }
            _ => None,
        }
    }
}

fn sp800_108_data_params_from_ffi(
    params: &[cryptoki_sys::CK_PRF_DATA_PARAM],
    buffers: &[Zeroizing<Vec<u8>>],
) -> Vec<PrfDataParam> {
    params
        .iter()
        .zip(buffers.iter())
        .map(|(param, value)| {
            let value_presence =
                presence_from_ffi(param.pValue.is_null(), param.ulValueLen, value.as_slice());
            PrfDataParam { type_: param.type_ as u64, value_presence }
        })
        .collect()
}

impl FfiMechanism {
    /// Thread-local `output_params()` call count for W1-C4-04
    /// snapshot-count tests.
    #[cfg(test)]
    pub(in crate::ffi) fn output_params_calls_for_tests() -> u64 {
        OUTPUT_PARAMS_CALLS.with(|c| c.get())
    }

    #[cfg(test)]
    pub(in crate::ffi) fn reset_output_params_calls_for_tests() {
        OUTPUT_PARAMS_CALLS.with(|c| c.set(0));
    }
}

/// Key-material IV comparison for [`FfiMechanism::output_params_equal`]:
/// mirrors the `output_params()` null-means-empty / clamped-copy rule
/// without allocating.
/// SP800-108 data-params comparison for
/// [`FfiMechanism::output_params_equal`]: mirrors the echo's array-peer
/// reconstruction without allocating.
fn sp800_108_data_params_equal(
    params: &[cryptoki_sys::CK_PRF_DATA_PARAM],
    buffers: &[Zeroizing<Vec<u8>>],
    struct_null: bool,
    struct_count: cryptoki_sys::CK_ULONG,
    expected: &PointerArray<PrfDataParam>,
) -> bool {
    match expected {
        PointerArray::Null { declared_count } => {
            struct_null
                && params.is_empty()
                && buffers.is_empty()
                && *declared_count == struct_count as u64
        }
        PointerArray::Present(items) => {
            !struct_null
                && params.len() == items.len()
                && buffers.len() == items.len()
                && params.iter().zip(buffers.iter()).zip(items.iter()).all(|((param, value), e)| {
                    e.type_ == param.type_ as u64
                        && e.value_presence
                            == presence_from_ffi(
                                param.pValue.is_null(),
                                param.ulValueLen,
                                value.as_slice(),
                            )
                })
        }
    }
}

/// SP800-108 derived-keys comparison for
/// [`FfiMechanism::output_params_equal`]: mirrors `output_keys`
/// without allocating.
fn sp800_108_derived_keys_equal(
    derived_keys: &FfiSp800108DerivedKeys,
    expected: &PointerArray<Sp800108DerivedKey>,
) -> bool {
    match expected {
        PointerArray::Null { declared_count } => {
            derived_keys.is_null && *declared_count == derived_keys.declared_count as u64
        }
        PointerArray::Present(items) => {
            !derived_keys.is_null
                && derived_keys.original.len() == items.len()
                && derived_keys.handles.len() == items.len()
                && derived_keys.derived_keys.len() == items.len()
                && derived_keys
                    .original
                    .iter()
                    .zip(derived_keys.handles.iter())
                    .zip(derived_keys.derived_keys.iter())
                    .zip(items.iter())
                    .all(|(((original, handle), derived), e)| {
                        e.template_presence == original.template_presence
                            && e.ph_key_is_null == derived.phKey.is_null()
                            && e.key_handle
                                == if derived.phKey.is_null() {
                                    original.key_handle
                                } else {
                                    CkObjectHandle(*handle as u64)
                                }
                    })
        }
    }
}

struct FfiSp800108DerivedKeys {
    original: Vec<Sp800108DerivedKey>,
    _templates: Vec<FfiAttrs>,
    handles: Vec<cryptoki_sys::CK_OBJECT_HANDLE>,
    derived_keys: Vec<cryptoki_sys::CK_DERIVED_KEY>,
    // S2 §6 (R19): the additional-derived-keys array header — NULL-ness
    // plus the declared count (the elements vector is empty for both
    // `Null{..}` and `Present([])`, so the header cannot be re-derived
    // from it).
    is_null: bool,
    declared_count: cryptoki_sys::CK_ULONG,
}

impl FfiSp800108DerivedKeys {
    fn new(keys: &PointerArray<Sp800108DerivedKey>) -> CkResult<Self> {
        let (is_null, declared_count) = array_header(keys)?;
        let present = keys.as_present().map(Vec::as_slice).unwrap_or(&[]);
        let mut templates: Vec<FfiAttrs> = present
            .iter()
            .map(|key| {
                FfiAttrs::from_slice(
                    key.template_presence.as_present().map(Vec::as_slice).unwrap_or(&[]),
                )
            })
            .collect::<CkResult<Vec<_>>>()?;
        let mut handles: Vec<cryptoki_sys::CK_OBJECT_HANDLE> = present
            .iter()
            .map(|key| narrow_wire_ulong(key.key_handle.0))
            .collect::<CkResult<Vec<_>>>()?;
        let handle_ptr = handles.as_mut_ptr();
        let mut derived_keys = Vec::with_capacity(present.len());

        for (index, (key, template)) in present.iter().zip(templates.iter_mut()).enumerate() {
            // S2 §6 (R19): the template leg follows its presence peer —
            // `Null{n}` → NULL + narrowed `n`, `Present` → the attribute
            // array (dangling when empty — `as_mut_ptr` never returns
            // NULL) + exact count. `phKey` is live iff the caller's was
            // (`ph_key_is_null` governs; the handle slot stays reserved
            // so live elements keep their indices).
            let (template_is_null, template_count) = array_header(&key.template_presence)?;
            let template_ptr =
                if template_is_null { std::ptr::null_mut() } else { template.attrs.as_mut_ptr() };
            // SAFETY: `index` is in bounds; `handle_ptr` designates the
            // live `handles` vector, which is never reallocated after
            // this loop (only provider-written through `phKey`).
            let ph_key = if key.ph_key_is_null {
                std::ptr::null_mut()
            } else {
                unsafe { handle_ptr.add(index) }
            };
            derived_keys.push(cryptoki_sys::CK_DERIVED_KEY {
                pTemplate: template_ptr,
                ulAttributeCount: template_count,
                phKey: ph_key,
            });
        }

        Ok(Self {
            original: present.to_vec(),
            _templates: templates,
            handles,
            derived_keys,
            is_null,
            declared_count,
        })
    }

    fn is_empty(&self) -> bool {
        self.derived_keys.is_empty()
    }

    fn ptr(&mut self) -> *mut cryptoki_sys::CK_DERIVED_KEY {
        if self.is_null {
            std::ptr::null_mut()
        } else {
            // `as_mut_ptr` on an empty vector is dangling non-NULL —
            // exactly the S2 §6 `Present([])` form.
            self.derived_keys.as_mut_ptr()
        }
    }

    fn len(&self) -> cryptoki_sys::CK_ULONG {
        self.declared_count
    }

    fn output_keys(&self) -> Vec<Sp800108DerivedKey> {
        self.original
            .iter()
            .zip(self.handles.iter())
            .zip(self.derived_keys.iter())
            .map(|((original, handle), derived)| Sp800108DerivedKey {
                // The template is caller input (provider-untouched), so
                // the echo carries the stored peer verbatim; `phKey`
                // NULL-ness reads back the C struct (which the arm built
                // from the caller's bit), and a NULL `phKey` echoes the
                // caller's handle scalar (the provider wrote nothing).
                key_handle: if derived.phKey.is_null() {
                    original.key_handle
                } else {
                    CkObjectHandle(*handle as u64)
                },
                template_presence: original.template_presence.clone(),
                ph_key_is_null: derived.phKey.is_null(),
            })
            .collect()
    }
}

/// Backing storage variants.  Each variant holds the C param struct and any
/// heap buffers whose addresses are embedded in that struct.
///
/// Every byte buffer is `Zeroizing` (ADR-0013 §5): the retained-owner design
/// embeds raw pointers into these buffers, so they cannot hold `SecretBytes`
/// (closure-scoped access cannot serve a stored pointer). `SecretBytes` is
/// transferred here with `expose`-and-copy at each construction site; the
/// copy is wiped when the owner drops. Safe-metadata buffers (IVs, nonces)
/// are wiped too — uniform and fail-closed, at the cost of one memset per
/// native call.
#[allow(dead_code)]
enum FfiParamBacking {
    /// Parameterless mechanism — no backing needed.
    None,
    /// Raw byte buffer (IV params, raw params). Byte reads only: the
    /// allocation carries alignment 1, so this variant must NEVER back a
    /// `pParameter` the provider reads as an integer or struct (Miri found
    /// the MacGeneral/Extract/ObjectHandle arms doing exactly that).
    Bytes(Zeroizing<Vec<u8>>),
    /// Single native `CK_ULONG` parameter (MacGeneral, Extract,
    /// ObjectHandle): typed, aligned `NativeAllocation`, not a byte Vec.
    Ulong(NativeAllocation<cryptoki_sys::CK_ULONG>),
    /// Validated Flat extent in guarded page storage (R12, S2 §6):
    /// exact bytes ending where the zeroed data mapping ends, followed
    /// by a no-access guard page (see [`GuardedBytes`]). Only ever built
    /// from a [`ValidatedMechanismParams`] Flat — an unvalidated public
    /// `Flat` value can never reach this variant (the constructor takes
    /// the newtype, never a bare `CkMechanism`).
    ///
    /// Output effects (S2 §6, decided): native writes into this backing
    /// are NOT returned — `output_params()` has no arm for `Flat` and
    /// yields `None` via its wildcard, even on Init RPCs whose responses
    /// already carry `mechanism_out`. Pinned by
    /// `r12_flat_output_suppressed*`. Likewise the authenticated-path
    /// probes (`validate_authenticated_inputs`, `authenticated_output`)
    /// hit their wildcards (`DEVICE_ERROR` / `PARAM_INVALID`):
    /// fail-closed until a later phase wires Flat there deliberately.
    Flat(GuardedBytes),
    /// Scalar-only C struct stored as a pinned Box (PSS, RC5, RC2MacGeneral, etc.)
    Pss(NativeAllocation<cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS>),
    Rc5(NativeAllocation<cryptoki_sys::CK_RC5_PARAMS>),
    Rc5MacGeneral(NativeAllocation<cryptoki_sys::CK_RC5_MAC_GENERAL_PARAMS>),
    Rc2MacGeneral(NativeAllocation<cryptoki_sys::CK_RC2_MAC_GENERAL_PARAMS>),
    Xeddsa(NativeAllocation<cryptoki_sys::CK_XEDDSA_PARAMS>),
    TlsMac(NativeAllocation<cryptoki_sys::CK_TLS_MAC_PARAMS>),
    Rc2Cbc(NativeAllocation<cryptoki_sys::CK_RC2_CBC_PARAMS>),
    AesCtr(NativeAllocation<cryptoki_sys::CK_AES_CTR_PARAMS>),
    CamelliaCtr(NativeAllocation<cryptoki_sys::CK_CAMELLIA_CTR_PARAMS>),
    /// Struct with pointer fields — struct + borrowed buffers.
    Oaep(NativeAllocation<cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS>, Zeroizing<Vec<u8>>),
    Gcm(NativeAllocation<cryptoki_sys::CK_GCM_PARAMS>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>),
    Ccm(NativeAllocation<cryptoki_sys::CK_CCM_PARAMS>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>),
    Ecdh1(
        NativeAllocation<cryptoki_sys::CK_ECDH1_DERIVE_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    Rc5Cbc(NativeAllocation<cryptoki_sys::CK_RC5_CBC_PARAMS>, Zeroizing<Vec<u8>>),
    Eddsa(NativeAllocation<cryptoki_sys::CK_EDDSA_PARAMS>, Zeroizing<Vec<u8>>),
    Hkdf(NativeAllocation<cryptoki_sys::CK_HKDF_PARAMS>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>),
    KeyDerivationString(
        NativeAllocation<cryptoki_sys::CK_KEY_DERIVATION_STRING_DATA>,
        Zeroizing<Vec<u8>>,
    ),
    AesCbcEncryptData(
        NativeAllocation<cryptoki_sys::CK_AES_CBC_ENCRYPT_DATA_PARAMS>,
        Zeroizing<Vec<u8>>,
    ),
    DesCbcEncryptData(
        NativeAllocation<cryptoki_sys::CK_DES_CBC_ENCRYPT_DATA_PARAMS>,
        Zeroizing<Vec<u8>>,
    ),
    AriaCbcEncryptData(
        NativeAllocation<cryptoki_sys::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>,
        Zeroizing<Vec<u8>>,
    ),
    CamelliaCbcEncryptData(
        NativeAllocation<cryptoki_sys::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>,
        Zeroizing<Vec<u8>>,
    ),
    SeedCbcEncryptData(
        NativeAllocation<cryptoki_sys::CK_SEED_CBC_ENCRYPT_DATA_PARAMS>,
        Zeroizing<Vec<u8>>,
    ),
    GcmWrap(
        NativeAllocation<cryptoki_sys::CK_GCM_WRAP_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    CcmWrap(
        NativeAllocation<cryptoki_sys::CK_CCM_WRAP_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    ChaCha20(
        NativeAllocation<cryptoki_sys::CK_CHACHA20_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    Salsa20(
        NativeAllocation<cryptoki_sys::CK_SALSA20_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    Salsa20ChaCha20Poly1305(
        NativeAllocation<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    RsaAesKeyWrap(
        NativeAllocation<FfiRsaAesKeyWrapParams>,
        NativeAllocation<cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS>,
        Zeroizing<Vec<u8>>,
    ),
    SignAdditionalContext(NativeAllocation<FfiSignAdditionalContext>, Zeroizing<Vec<u8>>),
    HashSignAdditionalContext(NativeAllocation<FfiHashSignAdditionalContext>, Zeroizing<Vec<u8>>),
    Kmac(NativeAllocation<FfiKmacParams>, Zeroizing<Vec<u8>>),
    MuGen(NativeAllocation<FfiMuGenParams>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>),
    // Last field is the caller password — wiped on drop (E1).
    Pkcs5Pbkd2(
        NativeAllocation<cryptoki_sys::CK_PKCS5_PBKD2_PARAMS2>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    Tls12MasterKeyDerive(
        NativeAllocation<cryptoki_sys::CK_TLS12_MASTER_KEY_DERIVE_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        // S2 §6 (R19): the version OUT cell exists iff the caller's
        // `pVersion` was non-NULL (`None` ⟺ `version_is_null`).
        Option<NativeAllocation<cryptoki_sys::CK_VERSION>>,
    ),
    TlsPrf(
        NativeAllocation<cryptoki_sys::CK_TLS_PRF_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        // S2 §6 (R19): the `*pulOutputLen` cell exists iff the caller's
        // `pulOutputLen` was non-NULL (`None` ⟺ `output_len_is_null`).
        Option<NativeAllocation<cryptoki_sys::CK_ULONG>>,
    ),
    TlsKdf(
        NativeAllocation<cryptoki_sys::CK_TLS_KDF_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    Ssl3MasterKeyDerive(
        NativeAllocation<cryptoki_sys::CK_SSL3_MASTER_KEY_DERIVE_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        // S2 §6 (R19): the version OUT cell exists iff the caller's
        // `pVersion` was non-NULL (`None` ⟺ `version_is_null`).
        Option<NativeAllocation<cryptoki_sys::CK_VERSION>>,
    ),
    Tls12ExtendedMasterKeyDerive(
        NativeAllocation<cryptoki_sys::CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>,
        Zeroizing<Vec<u8>>,
        // S2 §6 (R19): the version OUT cell exists iff the caller's
        // `pVersion` was non-NULL (`None` ⟺ `version_is_null`).
        Option<NativeAllocation<cryptoki_sys::CK_VERSION>>,
    ),
    Ssl3KeyMat(
        NativeAllocation<cryptoki_sys::CK_SSL3_KEY_MAT_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        // S2 §6 (R19): the OUT struct exists iff the caller's
        // `pReturnedKeyMaterial` was non-NULL (`None` ⟺
        // `returned_key_material_is_null`).
        Option<NativeAllocation<cryptoki_sys::CK_SSL3_KEY_MAT_OUT>>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        // S2 §6 (R19): the caller's IV legs (the only class record
        // when the OUT struct is NULL — the IV backings are empty for
        // both `Null{..}` and zero-capacity `Present`).
        PointerBytes,
        PointerBytes,
    ),
    Tls12KeyMat(
        NativeAllocation<cryptoki_sys::CK_TLS12_KEY_MAT_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        // S2 §6 (R19): the OUT struct exists iff the caller's
        // `pReturnedKeyMaterial` was non-NULL (see `Ssl3KeyMat`).
        Option<NativeAllocation<cryptoki_sys::CK_SSL3_KEY_MAT_OUT>>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        // S2 §6 (R19): the caller's IV legs (see `Ssl3KeyMat`).
        PointerBytes,
        PointerBytes,
    ),
    // Middle field is the caller password — wiped on drop (E1).
    Pbe(
        NativeAllocation<cryptoki_sys::CK_PBE_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    EcdhAesKeyWrap(NativeAllocation<cryptoki_sys::CK_ECDH_AES_KEY_WRAP_PARAMS>, Zeroizing<Vec<u8>>),
    Ecdh2Derive(
        NativeAllocation<cryptoki_sys::CK_ECDH2_DERIVE_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    EcmqvDerive(
        NativeAllocation<cryptoki_sys::CK_ECMQV_DERIVE_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    X942Dh1Derive(
        NativeAllocation<cryptoki_sys::CK_X9_42_DH1_DERIVE_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    X942Dh2Derive(
        NativeAllocation<cryptoki_sys::CK_X9_42_DH2_DERIVE_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    X942MqvDerive(
        NativeAllocation<cryptoki_sys::CK_X9_42_MQV_DERIVE_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    Gostr3410Derive(
        NativeAllocation<cryptoki_sys::CK_GOSTR3410_DERIVE_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    Gostr3410KeyWrap(
        NativeAllocation<cryptoki_sys::CK_GOSTR3410_KEY_WRAP_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    KeyWrapSetOaep(NativeAllocation<cryptoki_sys::CK_KEY_WRAP_SET_OAEP_PARAMS>, Zeroizing<Vec<u8>>),
    KeaDerive(
        NativeAllocation<cryptoki_sys::CK_KEA_DERIVE_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    IkePrfDerive(
        NativeAllocation<cryptoki_sys::CK_IKE_PRF_DERIVE_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    Ike1PrfDerive(
        NativeAllocation<cryptoki_sys::CK_IKE1_PRF_DERIVE_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    Ike1ExtendedDerive(
        NativeAllocation<cryptoki_sys::CK_IKE1_EXTENDED_DERIVE_PARAMS>,
        Zeroizing<Vec<u8>>,
    ),
    Ike2PrfPlusDerive(
        NativeAllocation<cryptoki_sys::CK_IKE2_PRF_PLUS_DERIVE_PARAMS>,
        Zeroizing<Vec<u8>>,
    ),
    WtlsMasterKeyDerive(
        NativeAllocation<cryptoki_sys::CK_WTLS_MASTER_KEY_DERIVE_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ),
    WtlsPrf(
        NativeAllocation<cryptoki_sys::CK_WTLS_PRF_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        // S2 §6 (R19): the `*pulOutputLen` cell exists iff the caller's
        // `pulOutputLen` was non-NULL (`None` ⟺ `output_len_is_null`).
        Option<NativeAllocation<cryptoki_sys::CK_ULONG>>,
    ),
    WtlsKeyMat(
        NativeAllocation<cryptoki_sys::CK_WTLS_KEY_MAT_PARAMS>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        // S2 §6 (R19): the OUT struct exists iff the caller's
        // `pReturnedKeyMaterial` was non-NULL (`None` ⟺
        // `returned_key_material_is_null`).
        Option<NativeAllocation<cryptoki_sys::CK_WTLS_KEY_MAT_OUT>>,
        Zeroizing<Vec<u8>>,
        // S2 §6 (R19): the caller's IV leg (see `Ssl3KeyMat`).
        PointerBytes,
    ),
    Sp800108Kdf(
        NativeAllocation<cryptoki_sys::CK_SP800_108_KDF_PARAMS>,
        Vec<cryptoki_sys::CK_PRF_DATA_PARAM>,
        Vec<Zeroizing<Vec<u8>>>,
        // F5: per-leg native value backings, parallel to the params
        // array (`Some` for rebuilt CK_ULONG-bearing payloads —
        // ownership only; the echo path round-trips the untouched
        // client bytes above).
        Vec<Option<Sp800108NativeValue>>,
        FfiSp800108DerivedKeys,
    ),
    Sp800108FeedbackKdf(
        NativeAllocation<cryptoki_sys::CK_SP800_108_FEEDBACK_KDF_PARAMS>,
        Vec<cryptoki_sys::CK_PRF_DATA_PARAM>,
        Vec<Zeroizing<Vec<u8>>>,
        Vec<Option<Sp800108NativeValue>>,
        Zeroizing<Vec<u8>>,
        FfiSp800108DerivedKeys,
    ),
    X3dhInitiate(
        NativeAllocation<cryptoki_sys::CK_X3DH_INITIATE_PARAMS>,
        Zeroizing<Vec<u8>>,
        NativeAllocation<cryptoki_sys::CK_ULONG>,
    ),
    X3dhRespond(
        NativeAllocation<cryptoki_sys::CK_X3DH_RESPOND_PARAMS>,
        NativeAllocation<cryptoki_sys::CK_ULONG>,
        NativeAllocation<cryptoki_sys::CK_ULONG>,
        NativeAllocation<cryptoki_sys::CK_ULONG>,
        NativeAllocation<cryptoki_sys::CK_ULONG>,
    ),
    X2RatchetInitialize(
        NativeAllocation<cryptoki_sys::CK_X2RATCHET_INITIALIZE_PARAMS>,
        Zeroizing<Vec<u8>>,
    ),
    X2RatchetRespond(
        NativeAllocation<cryptoki_sys::CK_X2RATCHET_RESPOND_PARAMS>,
        Zeroizing<Vec<u8>>,
    ),
    Otp(
        NativeAllocation<cryptoki_sys::CK_OTP_PARAMS>,
        Vec<cryptoki_sys::CK_OTP_PARAM>,
        Vec<Zeroizing<Vec<u8>>>,
    ),
    // The nested pair keeps the inner mechanism's C struct and its own
    // parameter backing alive for as long as the KIP params reference it
    // (L8 — replaces a mem::forget that permanently leaked the inner
    // backing). S2 §6 (R19): `None` ⟺ the caller's `pMechanism` was
    // NULL — no inner conversion runs, nothing is retained.
    Kip(
        NativeAllocation<cryptoki_sys::CK_KIP_PARAMS>,
        Option<(NativeAllocation<cryptoki_sys::CK_MECHANISM>, NativeAllocation<FfiParamBacking>)>,
        Zeroizing<Vec<u8>>,
    ),
    CmsSig(
        NativeAllocation<cryptoki_sys::CK_CMS_SIG_PARAMS>,
        NativeAllocation<cryptoki_sys::CK_MECHANISM>,
        NativeAllocation<cryptoki_sys::CK_MECHANISM>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        // Inner signing/digest mechanism backings, kept alive (L8).
        NativeAllocation<FfiParamBacking>,
        NativeAllocation<FfiParamBacking>,
    ),
    SkipjackPrivateWrap(
        NativeAllocation<cryptoki_sys::CK_SKIPJACK_PRIVATE_WRAP_PARAMS>,
        Zeroizing<Vec<u8>>, // password — wiped on drop (E1)
        Zeroizing<Vec<u8>>, // public_data
        Zeroizing<Vec<u8>>, // random_a
        Zeroizing<Vec<u8>>, // prime_p
        Zeroizing<Vec<u8>>, // base_g
        Zeroizing<Vec<u8>>, // subprime_q
    ),
    SkipjackRelayx(
        NativeAllocation<cryptoki_sys::CK_SKIPJACK_RELAYX_PARAMS>,
        Zeroizing<Vec<u8>>, // old_wrapped_x
        Zeroizing<Vec<u8>>, // old_password — wiped on drop (E1)
        Zeroizing<Vec<u8>>, // old_public_data
        Zeroizing<Vec<u8>>, // old_random_a
        Zeroizing<Vec<u8>>, // new_password — wiped on drop (E1)
        Zeroizing<Vec<u8>>, // new_public_data
        Zeroizing<Vec<u8>>, // new_random_a
    ),
}

/// CK_RSA_AES_KEY_WRAP_PARAMS -- not in cryptoki-sys, defined per PKCS#11 v3 spec.
// LLP64 (Windows x64): the PKCS#11 headers `#pragma pack(1)` their structs, so
// a hand-rolled mirror must be packed there to match `ulParameterLen` /
// field offsets. Natural alignment is correct on LP64/ILP32 (ADR-0011 Bucket 2).
#[repr(C)]
#[cfg_attr(windows, repr(packed))]
pub(in crate::ffi) struct FfiRsaAesKeyWrapParams {
    pub(in crate::ffi) ul_aes_key_bits: cryptoki_sys::CK_ULONG,
    pub(in crate::ffi) p_oaep_params: *mut cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS,
}

/// CK_SIGN_ADDITIONAL_CONTEXT — not in cryptoki-sys, defined per PKCS#11 3.2 spec.
#[repr(C)]
#[cfg_attr(windows, repr(packed))] // LLP64: match `#pragma pack(1)` (ADR-0011 Bucket 2)
pub(in crate::ffi) struct FfiSignAdditionalContext {
    pub(in crate::ffi) hedge_variant: cryptoki_sys::CK_ULONG,
    pub(in crate::ffi) p_context: *mut cryptoki_sys::CK_BYTE,
    pub(in crate::ffi) ul_context_len: cryptoki_sys::CK_ULONG,
}

/// CK_HASH_SIGN_ADDITIONAL_CONTEXT — CK_SIGN_ADDITIONAL_CONTEXT plus the explicit
/// `hash` mechanism, for the generic CKM_HASH_ML_DSA / CKM_HASH_SLH_DSA.
#[repr(C)]
#[cfg_attr(windows, repr(packed))] // LLP64: match `#pragma pack(1)` (ADR-0011 Bucket 2)
pub(in crate::ffi) struct FfiHashSignAdditionalContext {
    pub(in crate::ffi) hedge_variant: cryptoki_sys::CK_ULONG,
    pub(in crate::ffi) p_context: *mut cryptoki_sys::CK_BYTE,
    pub(in crate::ffi) ul_context_len: cryptoki_sys::CK_ULONG,
    pub(in crate::ffi) hash: cryptoki_sys::CK_MECHANISM_TYPE,
}

/// CK_KMAC_PARAMS — not in cryptoki-sys, defined by the working OASIS spec.
#[repr(C)]
#[cfg_attr(windows, repr(packed))] // LLP64: match `#pragma pack(1)` (ADR-0011 Bucket 2)
pub(in crate::ffi) struct FfiKmacParams {
    pub(in crate::ffi) h_key: cryptoki_sys::CK_OBJECT_HANDLE,
    pub(in crate::ffi) ul_mac_length: cryptoki_sys::CK_ULONG,
    pub(in crate::ffi) p_customization_string: cryptoki_sys::CK_VOID_PTR,
    pub(in crate::ffi) ul_customization_string_len: cryptoki_sys::CK_ULONG,
}

/// CK_MU_GEN_PARAMS — not in cryptoki-sys, defined by the working OASIS spec.
#[repr(C)]
#[cfg_attr(windows, repr(packed))] // LLP64: match `#pragma pack(1)` (ADR-0011 Bucket 2)
pub(in crate::ffi) struct FfiMuGenParams {
    pub(in crate::ffi) h_key: cryptoki_sys::CK_OBJECT_HANDLE,
    pub(in crate::ffi) p_tr: cryptoki_sys::CK_BYTE_PTR,
    pub(in crate::ffi) ul_tr_len: cryptoki_sys::CK_ULONG,
    pub(in crate::ffi) p_ctx: cryptoki_sys::CK_BYTE_PTR,
    pub(in crate::ffi) ul_ctx_len: cryptoki_sys::CK_ULONG,
}

/// Convert a validated mechanism to an `FfiMechanism` for FFI calls.
///
/// Takes ONLY [`ValidatedMechanismParams`] (R12, S2 §6): a public `Flat`
/// value can never bypass validation, because no constructor from a bare
/// `CkMechanism` exists on this path — every entry funnels through
/// [`validate_for_ffi`] (backend-local backstop) or arrives pre-validated
/// from the server (post-R13).
///
/// Parameterless mechanisms use null `pParameter`.  Parameterized mechanisms
/// allocate the appropriate C struct on the heap (via `Box`) so that
/// `pParameter` has a stable address for the lifetime of the returned
/// `FfiMechanism`.
///
/// Takes `&ValidatedMechanismParams` by reference and clones each parameter
/// buffer (IV, AAD, salt, …) into the `FfiParamBacking`. Taking it *by value* to move those
/// buffers (M10) was evaluated and deliberately not adopted: it would require
/// changing every `Pkcs11Backend` crypto method to own its `CkMechanism`,
/// rippling through all backend implementors and every server call site — the
/// highest-risk FFI boundary — to remove a per-`*Init` copy of small buffers
/// that is already dominated by the protobuf decode which copied the same
/// fields a few microseconds earlier. Revisit only if profiling shows mechanism
/// backing copies as a hotspot (e.g. very large-AAD AEAD workloads).
///
/// W1-C5-B06/W1-L13-05 measured note: every remaining per-call clone on
/// this path was audited and is load-bearing — the C structs hold raw
/// pointers into the backing, so the backing must own stable storage,
/// and `Zeroizing` (wipe-on-drop per AGENTS.md §4) requires owned
/// buffers; borrowing from `&CkMechanism` would thread lifetimes
/// through `FfiMechanism` into every retained owner AND forfeit the
/// wipe for buffers whose source is not itself wiping. The per-arm
/// copies are single (no `clone().to_vec()` doubles remain — pinned by
/// `output_params_has_no_double_copy`). Measured
/// `mechanism_clone_hotspot_measured`: `mechanism_to_ffi` (GCM, 12 B
/// IV + 8 B AAD) + `output_params` + `output_params_equal` ≈ 1 µs/iter
/// (debug build, 2000 iters) — noise next to one protobuf decode plus
/// one backend round-trip per `*Init`.
/// Maximum nested (non-top-level) mechanisms `mechanism_to_ffi` will
/// descend into (T03/RV-N2 backend half). Mirrors the shim reader bound
/// (`MAX_NESTED_MECHANISMS` = 16); the typed tree is owned (acyclic by
/// construction), so a depth counter suffices. The 17th nested mechanism
/// is rejected before recursion.
const MAX_NESTED_MECHANISMS: u8 = 16;

/// Width-derived host ABI shared by the backend-local funnels (see
/// [`validate_for_ffi`): 8-byte `CK_ULONG` behaves as LP64, 4-byte as
/// ILP32 — only `ulong_size()` is ever consulted on these paths. This
/// also keeps big-endian targets working, where `native()` is `None`.
fn funnel_host_abi() -> ParamAbi {
    if std::mem::size_of::<cryptoki_sys::CK_ULONG>() >= 8 {
        ParamAbi::Lp64NativeLe
    } else {
        ParamAbi::Ilp32NativeLe
    }
}

/// Backend-local transport validation (R12, pre-R13 backstop).
///
/// The backend owns no mechanism registry (the daemon's configured
/// registry lives server-side), so this validates against a static EMPTY
/// registry — no bindings, no exclusions — with `Operation::General` and
/// host-width ABIs. Consequences, each load-bearing and pinned:
///
/// * parameterless (`None`) passes through: the backend never enforced
///   operator exclusion at FFI — behavior identical;
/// * typed params are rejected (`PARAM_INVALID`): F1 binds every typed
///   variant to the mechanism, and the EMPTY backstop binds nothing
///   (conversion tests needing typed proofs use
///   [`validated_mechanism_for_tests`], which binds the pair under
///   test);
/// * legacy `Raw` is rejected (`PARAM_INVALID`), exactly as the FFI
///   match arm did before R12 — same RV, earlier layer;
/// * `Flat` is ALWAYS rejected (`PARAM_INVALID` — `UnknownShape`, or
///   `VendorWithoutAllowlist` for vendor IDs; every reason maps to
///   `PARAM_INVALID`): no binding exists to grant it, and validating
///   Flat against a guessed registry (e.g. the embedded default) would
///   bypass operator exclusion — fail closed instead. Server-validated
///   Flat arrives post-R13, when the server passes the newtype itself
///   (R13 removes the top-level uses of this funnel and retypes the
///   backend entries);
/// * `Null` validates fully here: NULL + narrowed length needs no
///   descriptor (S2 §6 RV table), only the member-version check and a
///   width-only narrowing — both registry-independent.
/// * nested nodes (KIP/CMS — the only arms that recurse) are validated
///   at descent against the snapshot the outer value carries
///   ([`ValidatedMechanismParams::registry`], F6): neither the server
///   (typed passthrough, no recursion) nor this layer pre-validates
///   them. Through this funnel the carried snapshot is the EMPTY
///   backstop, so nested `None`/`Null` convert while nested
///   typed/`Flat`/`Raw` stay rejected here; request-validated outers
///   (the post-R13 server path) accept nested typed/Flat exactly when
///   the request's bindings grant them.
///   (R13/R18 nested tracking carry, resolved by F6 for the request
///   path; the registry-less backstop keeps rejecting nested typed,
///   Flat, and Raw.)
///
/// The ABI choice is width-derived (`CK_ULONG` width only) rather than
/// `ParamAbi::native()`: only the width is load-bearing here (Null
/// narrowing is width-only; Flat is always denied so ABI equality is
/// moot; `None` never reads the ABI). This also keeps big-endian
/// targets working, where `native()` is `None`.
///
/// Test-only since F1 retyped `mechanism_to_ffi` to take validated
/// params (the F6 nested path validates at descent instead): the only
/// remaining callers are the test funnel and `#[cfg(test)]` modules.
#[cfg(test)]
pub(in crate::ffi) fn validate_for_ffi(
    mechanism: &CkMechanism,
) -> CkResult<ValidatedMechanismParams> {
    static EMPTY_REGISTRY: std::sync::OnceLock<MechanismRegistry> = std::sync::OnceLock::new();
    let registry = EMPTY_REGISTRY.get_or_init(|| {
        MechanismRegistry::from_parts(
            std::collections::HashMap::new(),
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            DiscoveryMode::Transparent,
            String::from("r12-empty-backstop"),
        )
    });
    let host_abi = funnel_host_abi();
    ValidatedMechanismParams::validate(mechanism, registry, Operation::General, host_abi, host_abi)
}

/// Test funnel: [`validate_for_ffi`] for the registry-independent rows,
/// a minimal one-entry binding registry for typed pairs (F1).
///
/// Every pre-R12 test that fed `&CkMechanism` straight into
/// `mechanism_to_ffi` funnels through here: typed params validate
/// against a registry binding the mechanism to the variant's canonical
/// shape, so conversion tests exercise conversion — binding itself is
/// pinned in the types/server suites, not here. `None`/`Null`
/// validate against the empty backstop; `Flat`/`Raw` behave exactly as
/// through [`validate_for_ffi`] (rejected).
#[cfg(test)]
pub(crate) fn validated_mechanism_for_tests(mechanism: &CkMechanism) -> ValidatedMechanismParams {
    let bound_shape = mechanism.params.as_ref().and_then(|params| params.canonical_shape_name());
    match bound_shape {
        Some(shape) => {
            let mut shapes = std::collections::HashMap::new();
            shapes.insert(mechanism.mechanism_type.0, shape.to_string());
            let registry = MechanismRegistry::from_parts(
                shapes,
                std::collections::HashSet::new(),
                std::collections::HashSet::new(),
                DiscoveryMode::Transparent,
                String::from("test-minimal-binding"),
            );
            let host_abi = funnel_host_abi();
            ValidatedMechanismParams::validate(
                mechanism,
                &registry,
                Operation::General,
                host_abi,
                host_abi,
            )
            .expect("test mechanism validates for FFI")
        }
        None => validate_for_ffi(mechanism).expect("test mechanism validates for FFI"),
    }
}

pub(in crate::ffi) fn mechanism_to_ffi(
    validated: &ValidatedMechanismParams,
) -> CkResult<FfiMechanism> {
    mechanism_to_ffi_at_depth(validated, 0)
}

/// Validate one nested node at descent (F6): same width-derived host
/// ABI as [`validate_for_ffi`], but against the request's snapshot
/// carried by the outer validated value — never the empty backstop —
/// so nested Flat eligibility is decided under the request's bindings.
/// `Operation::General`: nested KIP/CMS nodes carry no wrap context.
/// The nested validated value (with its stored Flat grant, if any)
/// flows into [`mechanism_to_ffi_at_depth`], whose reconstruction and
/// backing the KIP/CMS arms retain.
fn validate_nested_for_ffi(
    mechanism: &CkMechanism,
    registry: &MechanismRegistry,
) -> CkResult<ValidatedMechanismParams> {
    let host_abi = funnel_host_abi();
    ValidatedMechanismParams::validate(mechanism, registry, Operation::General, host_abi, host_abi)
}

/// Recurse one nesting level (KIP/CMS nested mechanisms), rejecting the
/// 17th nested mechanism before descending.
///
/// Nested nodes arrive unvalidated (the server validates the top level
/// only), so each is validated at descent through
/// [`validate_nested_for_ffi`] against the outer value's carried
/// registry snapshot: nested typed/`None` convert exactly like the top
/// level, nested `Null` converts too (NULL + narrowed length needs no
/// descriptor at any depth, so the uniform rule accepts it), nested
/// Flat converts exactly when the carried bindings grant it, and
/// nested `Raw` stays rejected always.
fn nested_mechanism_to_ffi(
    mechanism: &CkMechanism,
    depth: u8,
    registry: &MechanismRegistry,
) -> CkResult<FfiMechanism> {
    if depth >= MAX_NESTED_MECHANISMS {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    let validated = validate_nested_for_ffi(mechanism, registry)?;
    mechanism_to_ffi_at_depth(&validated, depth + 1)
}

fn mechanism_to_ffi_at_depth(
    validated: &ValidatedMechanismParams,
    depth: u8,
) -> CkResult<FfiMechanism> {
    let mechanism = validated.mechanism();
    let mech_type = narrow_wire_ulong(mechanism.mechanism_type.0)?;

    let params = match &mechanism.params {
        None => return Ok(FfiMechanism::no_param(mech_type)),
        Some(p) => p,
    };

    match params {
        // -- IV: raw bytes as the parameter ---------------------------------
        CkMechanismParams::Iv(iv_params) => {
            let mut buf = Zeroizing::new(iv_params.iv.clone());
            let ptr = buf.as_mut_ptr() as *mut std::ffi::c_void;
            let len = buf.len();
            Ok(FfiMechanism::with_param(mech_type, ptr, len, FfiParamBacking::Bytes(buf)))
        }

        // -- RSA-PSS: scalar-only struct ------------------------------------
        CkMechanismParams::RsaPkcsPss(p) => {
            let pss = Box::new(cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS {
                hashAlg: narrow_wire_ulong(p.hash_alg.0)?,
                mgf: narrow_wire_ulong(p.mgf.0)?,
                sLen: narrow_wire_ulong(p.salt_len)?,
            });
            Ok(FfiMechanism::from_box(mech_type, pss, FfiParamBacking::Pss))
        }

        // -- RSA-OAEP: struct with pointer to source_data -------------------
        CkMechanismParams::RsaPkcsOaep(p) => {
            // S2 §6 (R19): the presence peer governs NULL-ness and length.
            let source = input_leg(&p.source_data_presence)?;
            let oaep = Box::new(cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS {
                hashAlg: narrow_wire_ulong(p.hash_alg.0)?,
                mgf: narrow_wire_ulong(p.mgf.0)?,
                source: narrow_wire_ulong(p.source.0)?,
                pSourceData: source.ptr as *mut std::ffi::c_void,
                ulSourceDataLen: source.len,
            });
            Ok(FfiMechanism::from_box(mech_type, oaep, |b| {
                FfiParamBacking::Oaep(b, source.backing)
            }))
        }

        // -- GCM: struct with pointers to IV and AAD ------------------------
        CkMechanismParams::Gcm(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let iv_leg = input_leg(&p.iv_presence)?;
            let aad = input_leg(&p.aad_presence)?;
            // Generated-IV capacity (unchanged): the retained IV buffer
            // keeps max(input, iv_buffer_len) writable bytes while the
            // provider-visible ulIvLen always names the caller input
            // length. A NULL IV carries no buffer to grow (the capacity
            // is still validated — an absurd request rejects before any
            // other allocation either way).
            let input_iv_len = p.iv_presence.as_present().map(|b| b.len()).unwrap_or(0);
            let iv_capacity = gcm_iv_capacity(p.iv_buffer_len, input_iv_len)?;
            let mut iv = iv_leg.backing;
            if !p.iv_presence.is_null() && iv_capacity > iv.len() {
                iv.resize(iv_capacity, 0);
            }
            let iv_ptr = if p.iv_presence.is_null() {
                std::ptr::null_mut()
            } else if iv.is_empty() {
                EMPTY_NON_NULL
            } else {
                iv.as_mut_ptr()
            };
            let gcm = Box::new(cryptoki_sys::CK_GCM_PARAMS {
                pIv: iv_ptr,
                ulIvLen: iv_leg.len,
                ulIvBits: narrow_wire_ulong(p.iv_bits)?,
                pAAD: aad.ptr,
                ulAADLen: aad.len,
                ulTagBits: narrow_wire_ulong(p.tag_bits)?,
            });
            Ok(FfiMechanism::from_box(mech_type, gcm, |b| FfiParamBacking::Gcm(b, iv, aad.backing)))
        }

        // -- CCM: struct with pointers to nonce and AAD ---------------------
        CkMechanismParams::Ccm(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            // (wolfpkcs11 rejects (ptr, 0) at Init but accepts (NULL, 0) —
            // the peer distinction is exactly what the provider needs.)
            let nonce = input_leg(&p.nonce_presence)?;
            let aad = input_leg(&p.aad_presence)?;
            let ccm = Box::new(cryptoki_sys::CK_CCM_PARAMS {
                ulDataLen: narrow_wire_ulong(p.data_len)?,
                pNonce: nonce.ptr,
                ulNonceLen: nonce.len,
                pAAD: aad.ptr,
                ulAADLen: aad.len,
                ulMACLen: narrow_wire_ulong(p.mac_len)?,
            });
            Ok(FfiMechanism::from_box(mech_type, ccm, |b| {
                FfiParamBacking::Ccm(b, nonce.backing, aad.backing)
            }))
        }

        // -- ECDH1 Derive: struct with pointers to shared + public data -----
        CkMechanismParams::Ecdh1Derive(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let shared = input_leg(&p.shared_data_presence)?;
            let public = input_leg(&p.public_data_presence)?;
            let ecdh = Box::new(cryptoki_sys::CK_ECDH1_DERIVE_PARAMS {
                kdf: narrow_wire_ulong(p.kdf.0)?,
                ulSharedDataLen: shared.len,
                pSharedData: shared.ptr,
                ulPublicDataLen: public.len,
                pPublicData: public.ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, ecdh, |b| {
                FfiParamBacking::Ecdh1(b, shared.backing, public.backing)
            }))
        }

        // -- AES-CTR: scalar + fixed 16-byte counter block ------------------
        CkMechanismParams::AesCtr(p) => {
            let mut cb = [0u8; 16];
            let copy_len = p.cb.len().min(16);
            cb[..copy_len].copy_from_slice(&p.cb[..copy_len]);
            let ctr = Box::new(cryptoki_sys::CK_AES_CTR_PARAMS {
                ulCounterBits: narrow_wire_ulong(p.counter_bits)?,
                cb,
            });
            Ok(FfiMechanism::from_box(mech_type, ctr, FfiParamBacking::AesCtr))
        }

        // -- Camellia-CTR: scalar + fixed 16-byte counter block -------------
        CkMechanismParams::CamelliaCtr(p) => {
            let mut cb = [0u8; 16];
            let copy_len = p.cb.len().min(16);
            cb[..copy_len].copy_from_slice(&p.cb[..copy_len]);
            let ctr = Box::new(cryptoki_sys::CK_CAMELLIA_CTR_PARAMS {
                ulCounterBits: narrow_wire_ulong(p.counter_bits)?,
                cb,
            });
            Ok(FfiMechanism::from_box(mech_type, ctr, FfiParamBacking::CamelliaCtr))
        }

        // -- RC2-CBC: scalar + fixed 8-byte IV ------------------------------
        CkMechanismParams::Rc2Cbc(p) => {
            let mut iv = [0u8; 8];
            let copy_len = p.iv.len().min(8);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let rc2 = Box::new(cryptoki_sys::CK_RC2_CBC_PARAMS {
                ulEffectiveBits: narrow_wire_ulong(p.effective_bits)?,
                iv,
            });
            Ok(FfiMechanism::from_box(mech_type, rc2, FfiParamBacking::Rc2Cbc))
        }

        // -- RC5-CBC: scalars + pointer to IV -------------------------------
        CkMechanismParams::Rc5Cbc(p) => {
            // S2 §6 (R19): the presence peer governs NULL-ness and length.
            let iv = input_leg(&p.iv_presence)?;
            let rc5 = Box::new(cryptoki_sys::CK_RC5_CBC_PARAMS {
                ulWordsize: narrow_wire_ulong(p.word_size)?,
                ulRounds: narrow_wire_ulong(p.rounds)?,
                pIv: iv.ptr,
                ulIvLen: iv.len,
            });
            Ok(FfiMechanism::from_box(mech_type, rc5, |b| FfiParamBacking::Rc5Cbc(b, iv.backing)))
        }

        // -- Trivial scalar-only structs ------------------------------------
        CkMechanismParams::Rc5(p) => {
            let rc5 = Box::new(cryptoki_sys::CK_RC5_PARAMS {
                ulWordsize: narrow_wire_ulong(p.word_size)?,
                ulRounds: narrow_wire_ulong(p.rounds)?,
            });
            Ok(FfiMechanism::from_box(mech_type, rc5, FfiParamBacking::Rc5))
        }

        CkMechanismParams::Rc5MacGeneral(p) => {
            let rc5mg = Box::new(cryptoki_sys::CK_RC5_MAC_GENERAL_PARAMS {
                ulWordsize: narrow_wire_ulong(p.word_size)?,
                ulRounds: narrow_wire_ulong(p.rounds)?,
                ulMacLength: narrow_wire_ulong(p.mac_length)?,
            });
            Ok(FfiMechanism::from_box(mech_type, rc5mg, FfiParamBacking::Rc5MacGeneral))
        }

        CkMechanismParams::Rc2MacGeneral(p) => {
            let rc2mg = Box::new(cryptoki_sys::CK_RC2_MAC_GENERAL_PARAMS {
                ulEffectiveBits: narrow_wire_ulong(p.effective_bits)?,
                ulMacLength: narrow_wire_ulong(p.mac_length)?,
            });
            Ok(FfiMechanism::from_box(mech_type, rc2mg, FfiParamBacking::Rc2MacGeneral))
        }

        CkMechanismParams::Xeddsa(p) => {
            let xed =
                Box::new(cryptoki_sys::CK_XEDDSA_PARAMS { hash: narrow_wire_ulong(p.hash.0)? });
            Ok(FfiMechanism::from_box(mech_type, xed, FfiParamBacking::Xeddsa))
        }

        CkMechanismParams::TlsMac(p) => {
            let tls = Box::new(cryptoki_sys::CK_TLS_MAC_PARAMS {
                prfHashMechanism: narrow_wire_ulong(p.prf_hash_mechanism.0)?,
                ulMacLength: narrow_wire_ulong(p.mac_length)?,
                ulServerOrClient: narrow_wire_ulong(p.server_or_client)?,
            });
            Ok(FfiMechanism::from_box(mech_type, tls, FfiParamBacking::TlsMac))
        }

        // -- CBC encrypt data variants (fixed IV + pointer to data) ---------
        CkMechanismParams::AesCbcEncryptData(p) => {
            // S2 §6 (R19): the presence peer governs the data leg's
            // NULL-ness and length; the fixed IV array copies inline.
            let data = input_leg(&p.data_presence)?;
            let mut iv = [0u8; 16];
            let copy_len = p.iv.len().min(16);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let s = Box::new(cryptoki_sys::CK_AES_CBC_ENCRYPT_DATA_PARAMS {
                iv,
                pData: data.ptr,
                length: data.len,
            });
            Ok(FfiMechanism::from_box(mech_type, s, |b| {
                FfiParamBacking::AesCbcEncryptData(b, data.backing)
            }))
        }

        CkMechanismParams::DesCbcEncryptData(p) => {
            // S2 §6 (R19): the presence peer governs the data leg's
            // NULL-ness and length; the fixed IV array copies inline.
            let data = input_leg(&p.data_presence)?;
            let mut iv = [0u8; 8];
            let copy_len = p.iv.len().min(8);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let s = Box::new(cryptoki_sys::CK_DES_CBC_ENCRYPT_DATA_PARAMS {
                iv,
                pData: data.ptr,
                length: data.len,
            });
            Ok(FfiMechanism::from_box(mech_type, s, |b| {
                FfiParamBacking::DesCbcEncryptData(b, data.backing)
            }))
        }

        CkMechanismParams::AriaCbcEncryptData(p) => {
            // S2 §6 (R19): the presence peer governs the data leg's
            // NULL-ness and length; the fixed IV array copies inline.
            let data = input_leg(&p.data_presence)?;
            let mut iv = [0u8; 16];
            let copy_len = p.iv.len().min(16);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let s = Box::new(cryptoki_sys::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS {
                iv,
                pData: data.ptr,
                length: data.len,
            });
            Ok(FfiMechanism::from_box(mech_type, s, |b| {
                FfiParamBacking::AriaCbcEncryptData(b, data.backing)
            }))
        }

        CkMechanismParams::CamelliaCbcEncryptData(p) => {
            // S2 §6 (R19): the presence peer governs the data leg's
            // NULL-ness and length; the fixed IV array copies inline.
            let data = input_leg(&p.data_presence)?;
            let mut iv = [0u8; 16];
            let copy_len = p.iv.len().min(16);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let s = Box::new(cryptoki_sys::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS {
                iv,
                pData: data.ptr,
                length: data.len,
            });
            Ok(FfiMechanism::from_box(mech_type, s, |b| {
                FfiParamBacking::CamelliaCbcEncryptData(b, data.backing)
            }))
        }

        CkMechanismParams::SeedCbcEncryptData(p) => {
            // S2 §6 (R19): the presence peer governs the data leg's
            // NULL-ness and length; the fixed IV array copies inline.
            let data = input_leg(&p.data_presence)?;
            let mut iv = [0u8; 16];
            let copy_len = p.iv.len().min(16);
            iv[..copy_len].copy_from_slice(&p.iv[..copy_len]);
            let s = Box::new(cryptoki_sys::CK_SEED_CBC_ENCRYPT_DATA_PARAMS {
                iv,
                pData: data.ptr,
                length: data.len,
            });
            Ok(FfiMechanism::from_box(mech_type, s, |b| {
                FfiParamBacking::SeedCbcEncryptData(b, data.backing)
            }))
        }

        // -- HKDF: struct with pointers to salt and info --------------------
        CkMechanismParams::Hkdf(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let salt = input_leg(&p.salt_presence)?;
            let info = input_leg(&p.info_presence)?;
            let hkdf = Box::new(cryptoki_sys::CK_HKDF_PARAMS {
                bExtract: if p.extract { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                bExpand: if p.expand { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                prfHashMechanism: narrow_wire_ulong(p.prf_hash_mechanism.0)?,
                ulSaltType: narrow_wire_ulong(p.salt_type)?,
                pSalt: salt.ptr,
                ulSaltLen: salt.len,
                hSaltKey: narrow_wire_ulong(p.salt_key_handle.0)?,
                pInfo: info.ptr,
                ulInfoLen: info.len,
            });
            Ok(FfiMechanism::from_box(mech_type, hkdf, |b| {
                FfiParamBacking::Hkdf(b, salt.backing, info.backing)
            }))
        }

        // -- EdDSA: struct with pointer to context data ---------------------
        CkMechanismParams::Eddsa(p) => {
            // S2 §6 (R19): the presence peer governs NULL-ness and length.
            let ctx = input_leg(&p.context_data_presence)?;
            let eddsa = Box::new(cryptoki_sys::CK_EDDSA_PARAMS {
                phFlag: if p.ph_flag { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                ulContextDataLen: ctx.len,
                pContextData: ctx.ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, eddsa, |b| FfiParamBacking::Eddsa(b, ctx.backing)))
        }

        // -- GCM Wrap: struct with pointers to IV and AAD -------------------
        CkMechanismParams::GcmWrap(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let iv = input_leg(&p.iv_presence)?;
            let aad = input_leg(&p.aad_presence)?;
            let gw = Box::new(cryptoki_sys::CK_GCM_WRAP_PARAMS {
                pIv: iv.ptr,
                ulIvLen: iv.len,
                ulIvFixedBits: narrow_wire_ulong(p.iv_fixed_bits)?,
                ivGenerator: narrow_wire_ulong(p.iv_generator.0)?,
                pAAD: aad.ptr,
                ulAADLen: aad.len,
                ulTagBits: narrow_wire_ulong(p.tag_bits)?,
            });
            Ok(FfiMechanism::from_box(mech_type, gw, |b| {
                FfiParamBacking::GcmWrap(b, iv.backing, aad.backing)
            }))
        }

        // -- CCM Wrap: struct with pointers to nonce and AAD ----------------
        CkMechanismParams::CcmWrap(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let nonce = input_leg(&p.nonce_presence)?;
            let aad = input_leg(&p.aad_presence)?;
            let cw = Box::new(cryptoki_sys::CK_CCM_WRAP_PARAMS {
                ulDataLen: narrow_wire_ulong(p.data_len)?,
                pNonce: nonce.ptr,
                ulNonceLen: nonce.len,
                ulNonceFixedBits: narrow_wire_ulong(p.nonce_fixed_bits)?,
                nonceGenerator: narrow_wire_ulong(p.nonce_generator.0)?,
                pAAD: aad.ptr,
                ulAADLen: aad.len,
                ulMACLen: narrow_wire_ulong(p.mac_len)?,
            });
            Ok(FfiMechanism::from_box(mech_type, cw, |b| {
                FfiParamBacking::CcmWrap(b, nonce.backing, aad.backing)
            }))
        }

        // -- ChaCha20: struct with pointers to block counter and nonce ------
        CkMechanismParams::ChaCha20(p) => {
            // S2 §6 (R19): the presence peers govern pointer NULL-ness;
            // the legs are bits-governed fixed reads (no byte-length
            // fields — the shim's div_ceil(bits, 8) extent), so live
            // legs normalize to exactly the governed size (sound for
            // short/empty inputs). The bits scalars narrow first — the
            // narrowed values size the legs (no 32-bit truncation).
            let bc_bits = narrow_wire_ulong(p.block_counter_bits)?;
            let nonce_bits = narrow_wire_ulong(p.nonce_bits)?;
            let (bc, bc_ptr) = fixed_leg(&p.block_counter_presence, bits_to_bytes_ceil(bc_bits))?;
            let (nonce, nonce_ptr) = fixed_leg(&p.nonce_presence, bits_to_bytes_ceil(nonce_bits))?;
            let ch = Box::new(cryptoki_sys::CK_CHACHA20_PARAMS {
                pBlockCounter: bc_ptr,
                blockCounterBits: bc_bits,
                pNonce: nonce_ptr,
                ulNonceBits: nonce_bits,
            });
            Ok(FfiMechanism::from_box(mech_type, ch, |b| FfiParamBacking::ChaCha20(b, bc, nonce)))
        }

        // -- Salsa20: struct with pointers to block counter and nonce -------
        CkMechanismParams::Salsa20(p) => {
            // S2 §6 (R19): as ChaCha20 — the counter is a fixed 8-byte
            // read (the shim's fixed extent; no bits scalar exists), the
            // nonce is nonce-bits-governed.
            let nonce_bits = narrow_wire_ulong(p.nonce_bits)?;
            let (bc, bc_ptr) = fixed_leg(&p.block_counter_presence, 8)?;
            let (nonce, nonce_ptr) = fixed_leg(&p.nonce_presence, bits_to_bytes_ceil(nonce_bits))?;
            let sa = Box::new(cryptoki_sys::CK_SALSA20_PARAMS {
                pBlockCounter: bc_ptr,
                pNonce: nonce_ptr,
                ulNonceBits: nonce_bits,
            });
            Ok(FfiMechanism::from_box(mech_type, sa, |b| FfiParamBacking::Salsa20(b, bc, nonce)))
        }

        // -- Salsa20/ChaCha20-Poly1305: struct with pointers to nonce + AAD -
        CkMechanismParams::Salsa20ChaCha20Poly1305(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let nonce = input_leg(&p.nonce_presence)?;
            let aad = input_leg(&p.aad_presence)?;
            let sp = Box::new(cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_PARAMS {
                pNonce: nonce.ptr,
                ulNonceLen: nonce.len,
                pAAD: aad.ptr,
                ulAADLen: aad.len,
            });
            Ok(FfiMechanism::from_box(mech_type, sp, |b| {
                FfiParamBacking::Salsa20ChaCha20Poly1305(b, nonce.backing, aad.backing)
            }))
        }

        // -- MacGeneral: single CK_ULONG -----------------------------------
        // Typed allocation: the provider reads `*(CK_ULONG*)pParameter`,
        // so a byte Vec (alignment 1) is UB — Miri caught it.
        CkMechanismParams::MacGeneral(p) => {
            let val = narrow_wire_ulong(p.mac_length)?;
            Ok(FfiMechanism::from_box(mech_type, Box::new(val), FfiParamBacking::Ulong))
        }

        // -- Extract: single CK_ULONG bit position --------------------------
        CkMechanismParams::Extract(p) => {
            let val = narrow_wire_ulong(p.bit_position)?;
            Ok(FfiMechanism::from_box(mech_type, Box::new(val), FfiParamBacking::Ulong))
        }

        // -- KeyDerivationStringData: struct with pointer to data -----------
        CkMechanismParams::KeyDerivationString(p) => {
            // S2 §6 (R19): the presence peer governs NULL-ness and length.
            let data = input_leg(&p.data_presence)?;
            let kds = Box::new(cryptoki_sys::CK_KEY_DERIVATION_STRING_DATA {
                pData: data.ptr,
                ulLen: data.len,
            });
            Ok(FfiMechanism::from_box(mech_type, kds, |b| {
                FfiParamBacking::KeyDerivationString(b, data.backing)
            }))
        }

        // -- RSA-AES key wrap: nested OAEP params pointer ---------------------
        CkMechanismParams::RsaAesKeyWrap(p) => {
            // Build the nested OAEP params first (same §6 pattern as the
            // top-level Oaep arm — same `EMPTY_NON_NULL`, so the nested
            // byte-identity pin holds).
            let source = input_leg(&p.oaep_params.source_data_presence)?;
            let oaep =
                NativeAllocation::from_box(Box::new(cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS {
                    hashAlg: narrow_wire_ulong(p.oaep_params.hash_alg.0)?,
                    mgf: narrow_wire_ulong(p.oaep_params.mgf.0)?,
                    source: narrow_wire_ulong(p.oaep_params.source.0)?,
                    pSourceData: source.ptr as *mut std::ffi::c_void,
                    ulSourceDataLen: source.len,
                }));
            let oaep_ptr = oaep.root() as *mut cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS;

            let wrap = Box::new(FfiRsaAesKeyWrapParams {
                ul_aes_key_bits: narrow_wire_ulong(p.aes_key_bits)?,
                p_oaep_params: oaep_ptr,
            });
            // C3M.2: project the outer root from the persistent allocation,
            // never from a reborrow of the moved box.
            let wrap_allocation = NativeAllocation::from_box(wrap);
            let ptr = wrap_allocation.root() as *mut std::ffi::c_void;
            let len = std::mem::size_of::<FfiRsaAesKeyWrapParams>();
            Ok(FfiMechanism::with_param(
                mech_type,
                ptr,
                len,
                FfiParamBacking::RsaAesKeyWrap(wrap_allocation, oaep, source.backing),
            ))
        }

        // -- ObjectHandle: single CK_OBJECT_HANDLE ----------------------------
        CkMechanismParams::ObjectHandle(p) => {
            let val = narrow_wire_ulong(p.handle.0)?;
            Ok(FfiMechanism::from_box(mech_type, Box::new(val), FfiParamBacking::Ulong))
        }

        // -- SignAdditionalContext: CK_SIGN_ADDITIONAL_CONTEXT (hash == 0) or
        //    CK_HASH_SIGN_ADDITIONAL_CONTEXT (hash != 0, generic CKM_HASH_*_DSA).
        //    `from_box` sets the exact ulParameterLen from the chosen struct.
        CkMechanismParams::SignAdditionalContext(p) => {
            // S2 §6 (R19): the presence peer governs NULL-ness and length.
            let ctx = input_leg(&p.context_presence)?;
            let hedge = narrow_wire_ulong(p.hedge_variant)?;
            if p.hash == CkMechanismType(0) {
                let sac = Box::new(FfiSignAdditionalContext {
                    hedge_variant: hedge,
                    p_context: ctx.ptr,
                    ul_context_len: ctx.len,
                });
                Ok(FfiMechanism::from_box(mech_type, sac, |b| {
                    FfiParamBacking::SignAdditionalContext(b, ctx.backing)
                }))
            } else {
                let sac = Box::new(FfiHashSignAdditionalContext {
                    hedge_variant: hedge,
                    p_context: ctx.ptr,
                    ul_context_len: ctx.len,
                    hash: narrow_wire_ulong(p.hash.0)?,
                });
                Ok(FfiMechanism::from_box(mech_type, sac, |b| {
                    FfiParamBacking::HashSignAdditionalContext(b, ctx.backing)
                }))
            }
        }

        // -- KMAC: CK_KMAC_PARAMS -----------------------------------------
        CkMechanismParams::Kmac(p) => {
            // S2 §6 (R19): the presence peer governs NULL-ness and length.
            let custom = input_leg(&p.customization_string_presence)?;
            let kmac = Box::new(FfiKmacParams {
                h_key: narrow_wire_ulong(p.key_handle.0)?,
                ul_mac_length: narrow_wire_ulong(p.mac_length)?,
                p_customization_string: custom.ptr as cryptoki_sys::CK_VOID_PTR,
                ul_customization_string_len: custom.len,
            });
            Ok(FfiMechanism::from_box(mech_type, kmac, |b| {
                FfiParamBacking::Kmac(b, custom.backing)
            }))
        }

        // -- ML-DSA external mu generation: CK_MU_GEN_PARAMS ---------------
        CkMechanismParams::MuGen(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let tr = input_leg(&p.tr_presence)?;
            let ctx = input_leg(&p.context_presence)?;
            let mu_gen = Box::new(FfiMuGenParams {
                h_key: narrow_wire_ulong(p.key_handle.0)?,
                p_tr: tr.ptr,
                ul_tr_len: tr.len,
                p_ctx: ctx.ptr,
                ul_ctx_len: ctx.len,
            });
            Ok(FfiMechanism::from_box(mech_type, mu_gen, |b| {
                FfiParamBacking::MuGen(b, tr.backing, ctx.backing)
            }))
        }

        // -- Raw: reject at FFI boundary to prevent SIGSEGV ------------------
        // Raw bytes may contain stale pointer values from the client process.
        // If the backend interprets them as a C struct with embedded pointers
        // (e.g., CK_ECDH1_DERIVE_PARAMS.pPublicData), it will dereference
        // garbage addresses and segfault. Safe mechanisms are modeled with
        // explicit parameter shapes that properly serialize pointer-bearing
        // fields. Unknown mechanisms must be added to the TOML registry.
        // STAYS rejecting (R12): validation rejects Raw before this arm is
        // reachable, so this is now defense-in-depth plus exhaustiveness —
        // never a live path, never removed.
        CkMechanismParams::Raw(_) => Err(CkRv::MECHANISM_PARAM_INVALID),

        // -- Flat: guarded reconstruction (R12, S2 §6) ----------------------
        // Validated Flat only (this function takes the newtype): exact
        // bytes into `GuardedBytes`, `ulParameterLen` exactly
        // `declared_len`. Validation guarantees `bytes.len() ==
        // declared_len <= 64 KiB`; the debug assertion pins the shape
        // this arm relies on.
        CkMechanismParams::Flat(p) => {
            debug_assert_eq!(
                p.bytes.expose(|b| b.len()) as u64,
                p.declared_len,
                "validated Flat carries exactly declared_len bytes"
            );
            let guarded = p.bytes.expose(GuardedBytes::new)?;
            let len = guarded.declared_len();
            let ptr = guarded.as_ptr();
            Ok(FfiMechanism::with_param(mech_type, ptr, len, FfiParamBacking::Flat(guarded)))
        }

        // -- Null: NULL + narrowed length (R12, S2 §6) ----------------------
        // No descriptor needed; validation already narrowed for the
        // backend width, so this narrowing is infallible in practice —
        // kept checked (same `FUNCTION_FAILED` RV) as defense in depth.
        CkMechanismParams::Null { declared_len, .. } => {
            let len = narrow_wire_ulong(*declared_len)?;
            Ok(FfiMechanism::with_null_param(mech_type, len))
        }

        // -- TLS 1.2 Master Key Derive: nested SSL3_RANDOM_DATA + pVersion ---
        CkMechanismParams::Tls12MasterKeyDerive(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length;
            // the version OUT cell follows its null bit (not a 0.0
            // sentinel), primed with the caller's scalars.
            let client_random = input_leg(&p.random_info.client_random_presence)?;
            let server_random = input_leg(&p.random_info.server_random_presence)?;
            let version = if p.version_is_null {
                None
            } else {
                Some(NativeAllocation::from_box(Box::new(cryptoki_sys::CK_VERSION {
                    major: narrow_wire_byte(p.version_major)?,
                    minor: narrow_wire_byte(p.version_minor)?,
                })))
            };
            let tls12 = Box::new(cryptoki_sys::CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
                RandomInfo: cryptoki_sys::CK_SSL3_RANDOM_DATA {
                    pClientRandom: client_random.ptr,
                    ulClientRandomLen: client_random.len,
                    pServerRandom: server_random.ptr,
                    ulServerRandomLen: server_random.len,
                },
                pVersion: version
                    .as_ref()
                    .map_or(std::ptr::null_mut(), |cell| cell.root() as *mut _),
                prfHashMechanism: narrow_wire_ulong(p.prf_hash_mechanism.0)?,
            });
            Ok(FfiMechanism::from_box(mech_type, tls12, |b| {
                FfiParamBacking::Tls12MasterKeyDerive(
                    b,
                    client_random.backing,
                    server_random.backing,
                    version,
                )
            }))
        }

        // -- PKCS#5 PBKDF2: struct with 3 embedded pointers ----------------
        CkMechanismParams::Pkcs5Pbkd2(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let salt = input_leg(&p.salt_source_data_presence)?;
            let prf_data = input_leg(&p.prf_data_presence)?;
            let password = input_leg(&p.password_presence)?;
            let pbkd2 = Box::new(cryptoki_sys::CK_PKCS5_PBKD2_PARAMS2 {
                saltSource: narrow_wire_ulong(p.salt_source.0)?,
                pSaltSourceData: salt.ptr as *mut _,
                ulSaltSourceDataLen: salt.len,
                iterations: narrow_wire_ulong(p.iterations)?,
                prf: narrow_wire_ulong(p.prf.0)?,
                pPrfData: prf_data.ptr as *mut _,
                ulPrfDataLen: prf_data.len,
                pPassword: password.ptr,
                ulPasswordLen: password.len,
            });
            Ok(FfiMechanism::from_box(mech_type, pbkd2, |b| {
                FfiParamBacking::Pkcs5Pbkd2(b, salt.backing, prf_data.backing, password.backing)
            }))
        }

        // -- TLS PRF: struct with 4 pointers (seed, label, output, outputLen) --
        CkMechanismParams::TlsPrf(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length;
            // the output envelope (buffer + length cell) follows its null
            // bits, with capacity from the `output_len` scalar.
            let seed = input_leg(&p.seed_presence)?;
            let label = input_leg(&p.label_presence)?;
            let (output, output_ptr) = prf_output_buffer(p.output_len, p.output_is_null)?;
            let output_len = if p.output_len_is_null {
                None
            } else {
                Some(NativeAllocation::from_box(Box::new(narrow_wire_ulong(p.output_len)?)))
            };
            let tls = Box::new(cryptoki_sys::CK_TLS_PRF_PARAMS {
                pSeed: seed.ptr,
                ulSeedLen: seed.len,
                pLabel: label.ptr,
                ulLabelLen: label.len,
                pOutput: output_ptr,
                pulOutputLen: output_len
                    .as_ref()
                    .map_or(std::ptr::null_mut(), |cell| cell.root() as *mut _),
            });
            Ok(FfiMechanism::from_box(mech_type, tls, |b| {
                FfiParamBacking::TlsPrf(b, seed.backing, label.backing, output, output_len)
            }))
        }

        // -- TLS KDF: PRF mechanism + label + nested SSL3_RANDOM_DATA + context --
        CkMechanismParams::TlsKdf(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let label = input_leg(&p.label_presence)?;
            let client_random = input_leg(&p.random_info.client_random_presence)?;
            let server_random = input_leg(&p.random_info.server_random_presence)?;
            let context_data = input_leg(&p.context_data_presence)?;
            let tls = Box::new(cryptoki_sys::CK_TLS_KDF_PARAMS {
                prfMechanism: narrow_wire_ulong(p.prf_mechanism.0)?,
                pLabel: label.ptr,
                ulLabelLength: label.len,
                RandomInfo: cryptoki_sys::CK_SSL3_RANDOM_DATA {
                    pClientRandom: client_random.ptr,
                    ulClientRandomLen: client_random.len,
                    pServerRandom: server_random.ptr,
                    ulServerRandomLen: server_random.len,
                },
                pContextData: context_data.ptr,
                ulContextDataLength: context_data.len,
            });
            Ok(FfiMechanism::from_box(mech_type, tls, |b| {
                FfiParamBacking::TlsKdf(
                    b,
                    label.backing,
                    client_random.backing,
                    server_random.backing,
                    context_data.backing,
                )
            }))
        }

        // -- SSL3 Master Key Derive: nested SSL3_RANDOM_DATA + pVersion ----------
        CkMechanismParams::Ssl3MasterKeyDerive(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length;
            // the version OUT cell follows its null bit (not a 0.0
            // sentinel), primed with the caller's scalars.
            let client_random = input_leg(&p.random_info.client_random_presence)?;
            let server_random = input_leg(&p.random_info.server_random_presence)?;
            let version = if p.version_is_null {
                None
            } else {
                Some(NativeAllocation::from_box(Box::new(cryptoki_sys::CK_VERSION {
                    major: narrow_wire_byte(p.version_major)?,
                    minor: narrow_wire_byte(p.version_minor)?,
                })))
            };
            let ssl3 = Box::new(cryptoki_sys::CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
                RandomInfo: cryptoki_sys::CK_SSL3_RANDOM_DATA {
                    pClientRandom: client_random.ptr,
                    ulClientRandomLen: client_random.len,
                    pServerRandom: server_random.ptr,
                    ulServerRandomLen: server_random.len,
                },
                pVersion: version
                    .as_ref()
                    .map_or(std::ptr::null_mut(), |cell| cell.root() as *mut _),
            });
            Ok(FfiMechanism::from_box(mech_type, ssl3, |b| {
                FfiParamBacking::Ssl3MasterKeyDerive(
                    b,
                    client_random.backing,
                    server_random.backing,
                    version,
                )
            }))
        }

        // -- TLS 1.2 Extended Master Key Derive: PRF + session hash + pVersion ----
        CkMechanismParams::Tls12ExtendedMasterKeyDerive(p) => {
            // S2 §6 (R19): the presence peer governs NULL-ness and length;
            // the version OUT cell follows its null bit (not a 0.0
            // sentinel), primed with the caller's scalars.
            let session_hash = input_leg(&p.session_hash_presence)?;
            let version = if p.version_is_null {
                None
            } else {
                Some(NativeAllocation::from_box(Box::new(cryptoki_sys::CK_VERSION {
                    major: narrow_wire_byte(p.version_major)?,
                    minor: narrow_wire_byte(p.version_minor)?,
                })))
            };
            let ext = Box::new(cryptoki_sys::CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS {
                prfHashMechanism: narrow_wire_ulong(p.prf_hash_mechanism.0)?,
                pSessionHash: session_hash.ptr,
                ulSessionHashLen: session_hash.len,
                pVersion: version
                    .as_ref()
                    .map_or(std::ptr::null_mut(), |cell| cell.root() as *mut _),
            });
            Ok(FfiMechanism::from_box(mech_type, ext, |b| {
                FfiParamBacking::Tls12ExtendedMasterKeyDerive(b, session_hash.backing, version)
            }))
        }

        // -- SSL3/TLS Key Mat: nested random data + output key material -----------
        CkMechanismParams::Ssl3KeyMat(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length;
            // the IV legs are OUT legs with bits-derived capacity (no
            // length field — see `sized_leg`); the OUT struct follows
            // `returned_key_material_is_null`. The IV size narrows first
            // — the narrowed value sizes the legs (no 32-bit truncation,
            // no huge-scalar panic).
            let client_random = input_leg(&p.random_info.client_random_presence)?;
            let server_random = input_leg(&p.random_info.server_random_presence)?;
            let iv_size_bits = narrow_wire_ulong(p.iv_size_bits)?;
            let iv_bytes = bits_to_bytes_ceil(iv_size_bits);
            let out_is_null = p.returned_key_material_is_null;
            let (iv_client, iv_client_ptr) =
                sized_leg(&p.client_iv_presence, iv_bytes, out_is_null)?;
            let (iv_server, iv_server_ptr) =
                sized_leg(&p.server_iv_presence, iv_bytes, out_is_null)?;
            let key_mat_out = if out_is_null {
                None
            } else {
                Some(NativeAllocation::from_box(Box::new(cryptoki_sys::CK_SSL3_KEY_MAT_OUT {
                    hClientMacSecret: narrow_wire_ulong(p.client_mac_secret_handle.0)?,
                    hServerMacSecret: narrow_wire_ulong(p.server_mac_secret_handle.0)?,
                    hClientKey: narrow_wire_ulong(p.client_key_handle.0)?,
                    hServerKey: narrow_wire_ulong(p.server_key_handle.0)?,
                    pIVClient: iv_client_ptr,
                    pIVServer: iv_server_ptr,
                })))
            };
            let out_ptr =
                key_mat_out.as_ref().map_or(std::ptr::null_mut(), |out| out.root() as *mut _);
            // Decide whether to use SSL3 or TLS12 key mat based on prf_hash_mechanism:
            // if prf_hash_mechanism == 0, use CK_SSL3_KEY_MAT_PARAMS; else TLS12.
            if p.prf_hash_mechanism == CkMechanismType(0) {
                let km = Box::new(cryptoki_sys::CK_SSL3_KEY_MAT_PARAMS {
                    ulMacSizeInBits: narrow_wire_ulong(p.mac_size_bits)?,
                    ulKeySizeInBits: narrow_wire_ulong(p.key_size_bits)?,
                    ulIVSizeInBits: iv_size_bits,
                    bIsExport: if p.is_export {
                        cryptoki_sys::CK_TRUE
                    } else {
                        cryptoki_sys::CK_FALSE
                    },
                    RandomInfo: cryptoki_sys::CK_SSL3_RANDOM_DATA {
                        pClientRandom: client_random.ptr,
                        ulClientRandomLen: client_random.len,
                        pServerRandom: server_random.ptr,
                        ulServerRandomLen: server_random.len,
                    },
                    pReturnedKeyMaterial: out_ptr,
                });
                Ok(FfiMechanism::from_box(mech_type, km, |b| {
                    FfiParamBacking::Ssl3KeyMat(
                        b,
                        client_random.backing,
                        server_random.backing,
                        key_mat_out,
                        iv_client,
                        iv_server,
                        p.client_iv_presence.clone(),
                        p.server_iv_presence.clone(),
                    )
                }))
            } else {
                // TLS12 variant: uses CK_TLS12_KEY_MAT_PARAMS (superset of SSL3)
                let km = Box::new(cryptoki_sys::CK_TLS12_KEY_MAT_PARAMS {
                    ulMacSizeInBits: narrow_wire_ulong(p.mac_size_bits)?,
                    ulKeySizeInBits: narrow_wire_ulong(p.key_size_bits)?,
                    ulIVSizeInBits: iv_size_bits,
                    bIsExport: if p.is_export {
                        cryptoki_sys::CK_TRUE
                    } else {
                        cryptoki_sys::CK_FALSE
                    },
                    RandomInfo: cryptoki_sys::CK_SSL3_RANDOM_DATA {
                        pClientRandom: client_random.ptr,
                        ulClientRandomLen: client_random.len,
                        pServerRandom: server_random.ptr,
                        ulServerRandomLen: server_random.len,
                    },
                    pReturnedKeyMaterial: out_ptr,
                    prfHashMechanism: narrow_wire_ulong(p.prf_hash_mechanism.0)?,
                });
                Ok(FfiMechanism::from_box(mech_type, km, |b| {
                    FfiParamBacking::Tls12KeyMat(
                        b,
                        client_random.backing,
                        server_random.backing,
                        key_mat_out,
                        iv_client,
                        iv_server,
                        p.client_iv_presence.clone(),
                        p.server_iv_presence.clone(),
                    )
                }))
            }
        }

        // -- PBE: struct with 3 pointers (init_vector, password, salt) -----------
        CkMechanismParams::Pbe(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            // The IV leg has no length field (the provider reads a fixed
            // 8-byte IV — the shim's fixed extent), so a live IV always
            // normalizes to exactly 8 bytes (sound for short/empty
            // inputs, where an exact-sized backing would over-read or
            // dangle).
            let (init_vector, init_vector_ptr) = fixed_leg(&p.init_vector_presence, 8)?;
            let password = input_leg(&p.password_presence)?;
            let salt = input_leg(&p.salt_presence)?;
            let pbe = Box::new(cryptoki_sys::CK_PBE_PARAMS {
                pInitVector: init_vector_ptr,
                pPassword: password.ptr,
                ulPasswordLen: password.len,
                pSalt: salt.ptr,
                ulSaltLen: salt.len,
                ulIteration: narrow_wire_ulong(p.iteration)?,
            });
            Ok(FfiMechanism::from_box(mech_type, pbe, |b| {
                FfiParamBacking::Pbe(b, init_vector, password.backing, salt.backing)
            }))
        }

        // -- ECDH-AES Key Wrap: struct with 1 pointer ---------------------------
        CkMechanismParams::EcdhAesKeyWrap(p) => {
            // S2 §6 (R19): the presence peer governs NULL-ness and length.
            let shared = input_leg(&p.shared_data_presence)?;
            let ew = Box::new(cryptoki_sys::CK_ECDH_AES_KEY_WRAP_PARAMS {
                ulAESKeyBits: narrow_wire_ulong(p.aes_key_bits)?,
                kdf: narrow_wire_ulong(p.kdf.0)?,
                ulSharedDataLen: shared.len,
                pSharedData: shared.ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, ew, |b| {
                FfiParamBacking::EcdhAesKeyWrap(b, shared.backing)
            }))
        }

        // -- ECDH2 Derive: struct with 3 pointers -------------------------------
        CkMechanismParams::Ecdh2Derive(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let shared = input_leg(&p.shared_data_presence)?;
            let public = input_leg(&p.public_data_presence)?;
            let public2 = input_leg(&p.public_data2_presence)?;
            let ecdh2 = Box::new(cryptoki_sys::CK_ECDH2_DERIVE_PARAMS {
                kdf: narrow_wire_ulong(p.kdf.0)?,
                ulSharedDataLen: shared.len,
                pSharedData: shared.ptr,
                ulPublicDataLen: public.len,
                pPublicData: public.ptr,
                ulPrivateDataLen: narrow_wire_ulong(p.private_data_len)?,
                hPrivateData: narrow_wire_ulong(p.private_data_handle.0)?,
                ulPublicDataLen2: public2.len,
                pPublicData2: public2.ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, ecdh2, |b| {
                FfiParamBacking::Ecdh2Derive(b, shared.backing, public.backing, public2.backing)
            }))
        }

        // -- ECMQV Derive: struct with 3 pointers + handle ---------------------
        CkMechanismParams::EcmqvDerive(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let shared = input_leg(&p.shared_data_presence)?;
            let public = input_leg(&p.public_data_presence)?;
            let public2 = input_leg(&p.public_data2_presence)?;
            let ecmqv = Box::new(cryptoki_sys::CK_ECMQV_DERIVE_PARAMS {
                kdf: narrow_wire_ulong(p.kdf.0)?,
                ulSharedDataLen: shared.len,
                pSharedData: shared.ptr,
                ulPublicDataLen: public.len,
                pPublicData: public.ptr,
                ulPrivateDataLen: narrow_wire_ulong(p.private_data_len)?,
                hPrivateData: narrow_wire_ulong(p.private_data_handle.0)?,
                ulPublicDataLen2: public2.len,
                pPublicData2: public2.ptr,
                publicKey: narrow_wire_ulong(p.public_key_handle.0)?,
            });
            Ok(FfiMechanism::from_box(mech_type, ecmqv, |b| {
                FfiParamBacking::EcmqvDerive(b, shared.backing, public.backing, public2.backing)
            }))
        }

        // -- X9.42 DH1 Derive: struct with 2 pointers ---------------------------
        CkMechanismParams::X942Dh1Derive(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let other_info = input_leg(&p.other_info_presence)?;
            let public_data = input_leg(&p.public_data_presence)?;
            let x942 = Box::new(cryptoki_sys::CK_X9_42_DH1_DERIVE_PARAMS {
                kdf: narrow_wire_ulong(p.kdf.0)?,
                ulOtherInfoLen: other_info.len,
                pOtherInfo: other_info.ptr,
                ulPublicDataLen: public_data.len,
                pPublicData: public_data.ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, x942, |b| {
                FfiParamBacking::X942Dh1Derive(b, other_info.backing, public_data.backing)
            }))
        }

        // -- X9.42 DH2 Derive: struct with 3 pointers + handle ------------------
        CkMechanismParams::X942Dh2Derive(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let other_info = input_leg(&p.other_info_presence)?;
            let public_data = input_leg(&p.public_data_presence)?;
            let public_data2 = input_leg(&p.public_data2_presence)?;
            let x942 = Box::new(cryptoki_sys::CK_X9_42_DH2_DERIVE_PARAMS {
                kdf: narrow_wire_ulong(p.kdf.0)?,
                ulOtherInfoLen: other_info.len,
                pOtherInfo: other_info.ptr,
                ulPublicDataLen: public_data.len,
                pPublicData: public_data.ptr,
                ulPrivateDataLen: narrow_wire_ulong(p.private_data_len)?,
                hPrivateData: narrow_wire_ulong(p.private_data_handle.0)?,
                ulPublicDataLen2: public_data2.len,
                pPublicData2: public_data2.ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, x942, |b| {
                FfiParamBacking::X942Dh2Derive(
                    b,
                    other_info.backing,
                    public_data.backing,
                    public_data2.backing,
                )
            }))
        }

        // -- X9.42 MQV Derive: struct with 3 pointers + 2 handles ---------------
        CkMechanismParams::X942MqvDerive(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let other_info = input_leg(&p.other_info_presence)?;
            let public_data = input_leg(&p.public_data_presence)?;
            let public_data2 = input_leg(&p.public_data2_presence)?;
            let x942 = Box::new(cryptoki_sys::CK_X9_42_MQV_DERIVE_PARAMS {
                kdf: narrow_wire_ulong(p.kdf.0)?,
                ulOtherInfoLen: other_info.len,
                OtherInfo: other_info.ptr,
                ulPublicDataLen: public_data.len,
                PublicData: public_data.ptr,
                ulPrivateDataLen: narrow_wire_ulong(p.private_data_len)?,
                hPrivateData: narrow_wire_ulong(p.private_data_handle.0)?,
                ulPublicDataLen2: public_data2.len,
                PublicData2: public_data2.ptr,
                publicKey: narrow_wire_ulong(p.public_key_handle.0)?,
            });
            Ok(FfiMechanism::from_box(mech_type, x942, |b| {
                FfiParamBacking::X942MqvDerive(
                    b,
                    other_info.backing,
                    public_data.backing,
                    public_data2.backing,
                )
            }))
        }

        // -- GOSTR3410 Derive: struct with 2 pointers ---------------------------
        CkMechanismParams::Gostr3410Derive(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let public_data = input_leg(&p.public_data_presence)?;
            let ukm = input_leg(&p.ukm_presence)?;
            let gost = Box::new(cryptoki_sys::CK_GOSTR3410_DERIVE_PARAMS {
                kdf: narrow_wire_ulong(p.kdf.0)?,
                pPublicData: public_data.ptr,
                ulPublicDataLen: public_data.len,
                pUKM: ukm.ptr,
                ulUKMLen: ukm.len,
            });
            Ok(FfiMechanism::from_box(mech_type, gost, |b| {
                FfiParamBacking::Gostr3410Derive(b, public_data.backing, ukm.backing)
            }))
        }

        // -- GOSTR3410 Key Wrap: struct with 2 pointers + handle ----------------
        CkMechanismParams::Gostr3410KeyWrap(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let wrap_oid = input_leg(&p.wrap_oid_presence)?;
            let ukm = input_leg(&p.ukm_presence)?;
            let gost = Box::new(cryptoki_sys::CK_GOSTR3410_KEY_WRAP_PARAMS {
                pWrapOID: wrap_oid.ptr,
                ulWrapOIDLen: wrap_oid.len,
                pUKM: ukm.ptr,
                ulUKMLen: ukm.len,
                hKey: narrow_wire_ulong(p.key_handle.0)?,
            });
            Ok(FfiMechanism::from_box(mech_type, gost, |b| {
                FfiParamBacking::Gostr3410KeyWrap(b, wrap_oid.backing, ukm.backing)
            }))
        }

        // -- Key Wrap Set OAEP: struct with 1 pointer ---------------------------
        CkMechanismParams::KeyWrapSetOaep(p) => {
            // S2 §6 (R19): the presence peer governs NULL-ness and length.
            let x = input_leg(&p.x_presence)?;
            let kw = Box::new(cryptoki_sys::CK_KEY_WRAP_SET_OAEP_PARAMS {
                bBC: narrow_wire_byte(p.bc)?,
                pX: x.ptr,
                ulXLen: x.len,
            });
            Ok(FfiMechanism::from_box(mech_type, kw, |b| {
                FfiParamBacking::KeyWrapSetOaep(b, x.backing)
            }))
        }

        // -- KEA Derive: struct with 3 pointers ---------------------------------
        CkMechanismParams::KeaDerive(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            // RandomA/B share the one C `ulRandomLen`: v1 decode enforces
            // strict agreement (`check_shared_len_agreement`), and a
            // directly-constructed legacy value with mismatched legs
            // converts with the length following leg A (pinned by
            // `r19_reconstruct_kea_derive_legacy_mismatch_uses_a`).
            let random_a = input_leg(&p.random_a_presence)?;
            let random_b = input_leg(&p.random_b_presence)?;
            let public_data = input_leg(&p.public_data_presence)?;
            let kea = Box::new(cryptoki_sys::CK_KEA_DERIVE_PARAMS {
                isSender: if p.is_sender { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                ulRandomLen: random_a.len,
                RandomA: random_a.ptr,
                RandomB: random_b.ptr,
                ulPublicDataLen: public_data.len,
                PublicData: public_data.ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, kea, |b| {
                FfiParamBacking::KeaDerive(
                    b,
                    random_a.backing,
                    random_b.backing,
                    public_data.backing,
                )
            }))
        }

        // -- IKE PRF Derive: struct with 2 pointers -----------------------------
        CkMechanismParams::IkePrfDerive(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let ni = input_leg(&p.ni_presence)?;
            let nr = input_leg(&p.nr_presence)?;
            let ike = Box::new(cryptoki_sys::CK_IKE_PRF_DERIVE_PARAMS {
                prfMechanism: narrow_wire_ulong(p.prf_mechanism.0)?,
                bDataAsKey: if p.data_as_key {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                bRekey: if p.rekey { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                pNi: ni.ptr,
                ulNiLen: ni.len,
                pNr: nr.ptr,
                ulNrLen: nr.len,
                hNewKey: narrow_wire_ulong(p.new_key_handle.0)?,
            });
            Ok(FfiMechanism::from_box(mech_type, ike, |b| {
                FfiParamBacking::IkePrfDerive(b, ni.backing, nr.backing)
            }))
        }

        // -- IKE1 PRF Derive: struct with 2 pointers + handles ------------------
        CkMechanismParams::Ike1PrfDerive(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let ckyi = input_leg(&p.ckyi_presence)?;
            let ckyr = input_leg(&p.ckyr_presence)?;
            let ike = Box::new(cryptoki_sys::CK_IKE1_PRF_DERIVE_PARAMS {
                prfMechanism: narrow_wire_ulong(p.prf_mechanism.0)?,
                bHasPrevKey: if p.has_prev_key {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                hKeygxy: narrow_wire_ulong(p.keygxy_handle.0)?,
                hPrevKey: narrow_wire_ulong(p.prev_key_handle.0)?,
                pCKYi: ckyi.ptr,
                ulCKYiLen: ckyi.len,
                pCKYr: ckyr.ptr,
                ulCKYrLen: ckyr.len,
                keyNumber: narrow_wire_byte(p.key_number)?,
            });
            Ok(FfiMechanism::from_box(mech_type, ike, |b| {
                FfiParamBacking::Ike1PrfDerive(b, ckyi.backing, ckyr.backing)
            }))
        }

        // -- IKE1 Extended Derive: struct with 1 pointer + handle ---------------
        CkMechanismParams::Ike1ExtendedDerive(p) => {
            // S2 §6 (R19): the presence peer governs NULL-ness and length.
            let extra = input_leg(&p.extra_data_presence)?;
            let ike = Box::new(cryptoki_sys::CK_IKE1_EXTENDED_DERIVE_PARAMS {
                prfMechanism: narrow_wire_ulong(p.prf_mechanism.0)?,
                bHasKeygxy: if p.has_keygxy {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                hKeygxy: narrow_wire_ulong(p.keygxy_handle.0)?,
                pExtraData: extra.ptr,
                ulExtraDataLen: extra.len,
            });
            Ok(FfiMechanism::from_box(mech_type, ike, |b| {
                FfiParamBacking::Ike1ExtendedDerive(b, extra.backing)
            }))
        }

        // -- IKE2 PRF Plus Derive: struct with 1 pointer + handle ---------------
        CkMechanismParams::Ike2PrfPlusDerive(p) => {
            // S2 §6 (R19): the presence peer governs NULL-ness and length.
            let seed = input_leg(&p.seed_data_presence)?;
            let ike = Box::new(cryptoki_sys::CK_IKE2_PRF_PLUS_DERIVE_PARAMS {
                prfMechanism: narrow_wire_ulong(p.prf_mechanism.0)?,
                bHasSeedKey: if p.has_seed_key {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                hSeedKey: narrow_wire_ulong(p.seed_key_handle.0)?,
                pSeedData: seed.ptr,
                ulSeedDataLen: seed.len,
            });
            Ok(FfiMechanism::from_box(mech_type, ike, |b| {
                FfiParamBacking::Ike2PrfPlusDerive(b, seed.backing)
            }))
        }

        // -- WTLS Master Key Derive: digest mechanism + WTLS random data + pVersion --
        CkMechanismParams::WtlsMasterKeyDerive(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length;
            // the version byte cell follows its null bit (empty backing
            // ⟺ NULL), primed with the caller's byte when live.
            let client_random = input_leg(&p.random_info.client_random_presence)?;
            let server_random = input_leg(&p.random_info.server_random_presence)?;
            let mut version_buf = if p.version_is_null {
                Zeroizing::new(Vec::new())
            } else {
                Zeroizing::new(vec![narrow_wire_byte(p.version)?])
            };
            let version_ptr = if version_buf.is_empty() {
                std::ptr::null_mut()
            } else {
                version_buf.as_mut_ptr()
            };
            let wtls = Box::new(cryptoki_sys::CK_WTLS_MASTER_KEY_DERIVE_PARAMS {
                DigestMechanism: narrow_wire_ulong(p.digest_mechanism.0)?,
                RandomInfo: cryptoki_sys::CK_WTLS_RANDOM_DATA {
                    pClientRandom: client_random.ptr,
                    ulClientRandomLen: client_random.len,
                    pServerRandom: server_random.ptr,
                    ulServerRandomLen: server_random.len,
                },
                pVersion: version_ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, wtls, |b| {
                FfiParamBacking::WtlsMasterKeyDerive(
                    b,
                    client_random.backing,
                    server_random.backing,
                    version_buf,
                )
            }))
        }

        // -- WTLS PRF: digest mechanism + seed + label + output -----------------
        CkMechanismParams::WtlsPrf(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length;
            // the output envelope (buffer + length cell) follows its null
            // bits, with capacity from the `output_len` scalar.
            let seed = input_leg(&p.seed_presence)?;
            let label = input_leg(&p.label_presence)?;
            let (output, output_ptr) = prf_output_buffer(p.output_len, p.output_is_null)?;
            let output_len = if p.output_len_is_null {
                None
            } else {
                Some(NativeAllocation::from_box(Box::new(narrow_wire_ulong(p.output_len)?)))
            };
            let wtls = Box::new(cryptoki_sys::CK_WTLS_PRF_PARAMS {
                DigestMechanism: narrow_wire_ulong(p.digest_mechanism.0)?,
                pSeed: seed.ptr,
                ulSeedLen: seed.len,
                pLabel: label.ptr,
                ulLabelLen: label.len,
                pOutput: output_ptr,
                pulOutputLen: output_len
                    .as_ref()
                    .map_or(std::ptr::null_mut(), |cell| cell.root() as *mut _),
            });
            Ok(FfiMechanism::from_box(mech_type, wtls, |b| {
                FfiParamBacking::WtlsPrf(b, seed.backing, label.backing, output, output_len)
            }))
        }

        // -- WTLS Key Mat: digest mechanism + nested random data + output -------
        CkMechanismParams::WtlsKeyMat(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length;
            // the IV leg is an OUT leg with bits-derived capacity (no
            // length field — see `sized_leg`); the OUT struct follows
            // `returned_key_material_is_null`. The IV size narrows first
            // (no 32-bit truncation, no huge-scalar panic).
            let client_random = input_leg(&p.random_info.client_random_presence)?;
            let server_random = input_leg(&p.random_info.server_random_presence)?;
            let iv_size_bits = narrow_wire_ulong(p.iv_size_bits)?;
            let iv_bytes = bits_to_bytes_ceil(iv_size_bits);
            let out_is_null = p.returned_key_material_is_null;
            let (iv_buf, iv_ptr) = sized_leg(&p.iv_presence, iv_bytes, out_is_null)?;
            let kmo = if out_is_null {
                None
            } else {
                Some(NativeAllocation::from_box(Box::new(cryptoki_sys::CK_WTLS_KEY_MAT_OUT {
                    hMacSecret: narrow_wire_ulong(p.mac_secret_handle.0)?,
                    hKey: narrow_wire_ulong(p.key_handle.0)?,
                    pIV: iv_ptr,
                })))
            };
            let wtls = Box::new(cryptoki_sys::CK_WTLS_KEY_MAT_PARAMS {
                DigestMechanism: narrow_wire_ulong(p.digest_mechanism.0)?,
                ulMacSizeInBits: narrow_wire_ulong(p.mac_size_bits)?,
                ulKeySizeInBits: narrow_wire_ulong(p.key_size_bits)?,
                ulIVSizeInBits: iv_size_bits,
                ulSequenceNumber: narrow_wire_ulong(p.sequence_number)?,
                bIsExport: if p.is_export { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE },
                RandomInfo: cryptoki_sys::CK_WTLS_RANDOM_DATA {
                    pClientRandom: client_random.ptr,
                    ulClientRandomLen: client_random.len,
                    pServerRandom: server_random.ptr,
                    ulServerRandomLen: server_random.len,
                },
                pReturnedKeyMaterial: kmo
                    .as_ref()
                    .map_or(std::ptr::null_mut(), |out| out.root() as *mut _),
            });
            Ok(FfiMechanism::from_box(mech_type, wtls, |b| {
                FfiParamBacking::WtlsKeyMat(
                    b,
                    client_random.backing,
                    server_random.backing,
                    kmo,
                    iv_buf,
                    p.iv_presence.clone(),
                )
            }))
        }

        // -- SP800-108 KDF: PRF type + data params array -------------------------
        CkMechanismParams::Sp800108Kdf(p) => {
            // S2 §6 (R19): both counted-array headers follow their
            // presence peers; each data-param value leg follows its own.
            let (data_is_null, data_count) = array_header(&p.data_params_presence)?;
            let present = p.data_params_presence.as_present().map(Vec::as_slice).unwrap_or(&[]);
            // Build CK_PRF_DATA_PARAM array and backing buffers
            let mut buffers: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(present.len());
            let mut c_params: Vec<cryptoki_sys::CK_PRF_DATA_PARAM> =
                Vec::with_capacity(present.len());
            // F5: per-leg native value backings, parallel to `c_params`
            // (`Some` for rebuilt CK_ULONG-bearing payloads — ownership
            // only; the echo path round-trips `buffers`).
            let mut natives: Vec<Option<Sp800108NativeValue>> = Vec::with_capacity(present.len());
            for dp in present {
                // Narrow first: a huge `type_` fails FUNCTION_FAILED
                // exactly as before (the old leg-then-narrow order ran
                // an infallible leg for Present values, so type errors
                // already won these slots).
                let data_type = narrow_wire_ulong(dp.type_)?;
                match sp800_108_value_leg(dp.type_, &dp.value_presence)? {
                    Sp800108ValueLeg::Native { backing, len, echo } => {
                        c_params.push(cryptoki_sys::CK_PRF_DATA_PARAM {
                            type_: data_type,
                            pValue: backing.pvalue(),
                            ulValueLen: len,
                        });
                        buffers.push(echo);
                        natives.push(Some(backing));
                    }
                    Sp800108ValueLeg::Passthrough => {
                        let leg = input_leg(&dp.value_presence)?;
                        c_params.push(cryptoki_sys::CK_PRF_DATA_PARAM {
                            type_: data_type,
                            pValue: leg.ptr as *mut std::ffi::c_void,
                            ulValueLen: leg.len,
                        });
                        buffers.push(leg.backing);
                        natives.push(None);
                    }
                }
            }
            // `as_mut_ptr` on an empty vector is dangling non-NULL —
            // exactly the S2 §6 `Present([])` form.
            let data_ptr = if data_is_null { std::ptr::null_mut() } else { c_params.as_mut_ptr() };
            let mut derived_keys =
                FfiSp800108DerivedKeys::new(&p.additional_derived_keys_presence)?;
            let sp = Box::new(cryptoki_sys::CK_SP800_108_KDF_PARAMS {
                prfType: narrow_wire_ulong(p.prf_type.0)?,
                ulNumberOfDataParams: data_count,
                pDataParams: data_ptr,
                ulAdditionalDerivedKeys: derived_keys.len(),
                pAdditionalDerivedKeys: derived_keys.ptr(),
            });
            Ok(FfiMechanism::from_box(mech_type, sp, |b| {
                FfiParamBacking::Sp800108Kdf(b, c_params, buffers, natives, derived_keys)
            }))
        }

        // -- SP800-108 Feedback KDF: same + IV ----------------------------------
        CkMechanismParams::Sp800108FeedbackKdf(p) => {
            // S2 §6 (R19): both counted-array headers and the IV leg
            // follow their presence peers; each data-param value leg
            // follows its own (F5: CK_ULONG-bearing values rebuild
            // backend-native, as in the Kdf arm above).
            let (data_is_null, data_count) = array_header(&p.data_params_presence)?;
            let present = p.data_params_presence.as_present().map(Vec::as_slice).unwrap_or(&[]);
            let mut buffers: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(present.len());
            let mut c_params: Vec<cryptoki_sys::CK_PRF_DATA_PARAM> =
                Vec::with_capacity(present.len());
            // F5: per-leg native value backings, parallel to `c_params`
            // (see the Kdf arm).
            let mut natives: Vec<Option<Sp800108NativeValue>> = Vec::with_capacity(present.len());
            for dp in present {
                // Narrow first (same error precedence as the Kdf arm).
                let data_type = narrow_wire_ulong(dp.type_)?;
                match sp800_108_value_leg(dp.type_, &dp.value_presence)? {
                    Sp800108ValueLeg::Native { backing, len, echo } => {
                        c_params.push(cryptoki_sys::CK_PRF_DATA_PARAM {
                            type_: data_type,
                            pValue: backing.pvalue(),
                            ulValueLen: len,
                        });
                        buffers.push(echo);
                        natives.push(Some(backing));
                    }
                    Sp800108ValueLeg::Passthrough => {
                        let leg = input_leg(&dp.value_presence)?;
                        c_params.push(cryptoki_sys::CK_PRF_DATA_PARAM {
                            type_: data_type,
                            pValue: leg.ptr as *mut std::ffi::c_void,
                            ulValueLen: leg.len,
                        });
                        buffers.push(leg.backing);
                        natives.push(None);
                    }
                }
            }
            // `as_mut_ptr` on an empty vector is dangling non-NULL —
            // exactly the S2 §6 `Present([])` form.
            let data_ptr = if data_is_null { std::ptr::null_mut() } else { c_params.as_mut_ptr() };
            let iv = input_leg(&p.iv_presence)?;
            let mut derived_keys =
                FfiSp800108DerivedKeys::new(&p.additional_derived_keys_presence)?;
            let sp = Box::new(cryptoki_sys::CK_SP800_108_FEEDBACK_KDF_PARAMS {
                prfType: narrow_wire_ulong(p.prf_type.0)?,
                ulNumberOfDataParams: data_count,
                pDataParams: data_ptr,
                ulIVLen: iv.len,
                pIV: iv.ptr,
                ulAdditionalDerivedKeys: derived_keys.len(),
                pAdditionalDerivedKeys: derived_keys.ptr(),
            });
            Ok(FfiMechanism::from_box(mech_type, sp, |b| {
                FfiParamBacking::Sp800108FeedbackKdf(
                    b,
                    c_params,
                    buffers,
                    natives,
                    iv.backing,
                    derived_keys,
                )
            }))
        }

        // -- X3DH Initiate: struct with 2 pointers + 4 handles ------------------
        CkMechanismParams::X3dhInitiate(p) => {
            let mut prekey_sig = Zeroizing::new(p.prekey_signature.clone());
            let sig_ptr =
                if prekey_sig.is_empty() { std::ptr::null_mut() } else { prekey_sig.as_mut_ptr() };
            // pOnetime_key is a pointer in the C struct — but it represents an
            // object handle packed as a pointer. In PKCS#11, CK_X3DH_INITIATE_PARAMS
            // has pOnetime_key as *mut CK_BYTE. We pass the handle as a pointer.
            // Typed backing: the buffer holds a narrowed handle the provider
            // may read via an aligned CK_ULONG load (same rule as Ulong
            // pParameter/attribute values); byte-Vec backing would be UB.
            let onetime_buf = NativeAllocation::new(narrow_wire_ulong(p.onetime_key_handle.0)?);
            let onetime_ptr = onetime_buf.root() as *mut u8;
            let x3dh = Box::new(cryptoki_sys::CK_X3DH_INITIATE_PARAMS {
                kdf: narrow_wire_ulong(p.kdf)?,
                pPeer_identity: narrow_wire_ulong(p.peer_identity_handle.0)?,
                pPeer_prekey: narrow_wire_ulong(p.peer_prekey_handle.0)?,
                pPrekey_signature: sig_ptr,
                pOnetime_key: onetime_ptr,
                pOwn_identity: narrow_wire_ulong(p.own_identity_handle.0)?,
                pOwn_ephemeral: narrow_wire_ulong(p.own_ephemeral_handle.0)?,
            });
            Ok(FfiMechanism::from_box(mech_type, x3dh, |b| {
                FfiParamBacking::X3dhInitiate(b, prekey_sig, onetime_buf)
            }))
        }

        // -- X3DH Respond: struct with 4 pointers + 2 scalars -------------------
        CkMechanismParams::X3dhRespond(p) => {
            // Typed backing for all four handle buffers (same aligned-load
            // rule as above; handles are non-secret, so no wiping needed).
            let identity_buf = NativeAllocation::new(narrow_wire_ulong(p.identity_handle.0)?);
            let prekey_buf = NativeAllocation::new(narrow_wire_ulong(p.prekey_handle.0)?);
            let onetime_buf = NativeAllocation::new(narrow_wire_ulong(p.onetime_key_handle.0)?);
            // pInitiator_ephemeral is also a *mut CK_BYTE in the C struct
            let ephem_buf =
                NativeAllocation::new(narrow_wire_ulong(p.initiator_ephemeral_handle.0)?);
            // All four buffers have their final size before pointer capture.
            // Each is retained unchanged in the owner until the native call ends.
            let x3dh = Box::new(cryptoki_sys::CK_X3DH_RESPOND_PARAMS {
                kdf: narrow_wire_ulong(p.kdf)?,
                pIdentity_id: identity_buf.root() as *mut u8,
                pPrekey_id: prekey_buf.root() as *mut u8,
                pOnetime_id: onetime_buf.root() as *mut u8,
                pInitiator_identity: narrow_wire_ulong(p.initiator_identity_handle.0)?,
                pInitiator_ephemeral: ephem_buf.root() as *mut u8,
            });
            Ok(FfiMechanism::from_box(mech_type, x3dh, |b| {
                FfiParamBacking::X3dhRespond(b, identity_buf, prekey_buf, onetime_buf, ephem_buf)
            }))
        }

        // -- X2Ratchet Initialize: struct with 1 pointer + handles --------------
        CkMechanismParams::X2RatchetInitialize(p) => {
            let mut sk = p.sk.expose(|b| Zeroizing::new(b.to_vec()));
            let sk_ptr = if sk.is_empty() { std::ptr::null_mut() } else { sk.as_mut_ptr() };
            let x2r = Box::new(cryptoki_sys::CK_X2RATCHET_INITIALIZE_PARAMS {
                sk: sk_ptr,
                peer_public_prekey: narrow_wire_ulong(p.peer_public_prekey_handle.0)?,
                peer_public_identity: narrow_wire_ulong(p.peer_public_identity_handle.0)?,
                own_public_identity: narrow_wire_ulong(p.own_public_identity_handle.0)?,
                bEncryptedHeader: if p.encrypted_header {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                eCurve: narrow_wire_ulong(p.curve)?,
                aeadMechanism: narrow_wire_ulong(p.aead_mechanism.0)?,
                kdfMechanism: narrow_wire_ulong(p.kdf_mechanism.0)?,
            });
            Ok(FfiMechanism::from_box(mech_type, x2r, |b| {
                FfiParamBacking::X2RatchetInitialize(b, sk)
            }))
        }

        // -- X2Ratchet Respond: struct with 1 pointer + handles -----------------
        CkMechanismParams::X2RatchetRespond(p) => {
            let mut sk = p.sk.expose(|b| Zeroizing::new(b.to_vec()));
            let sk_ptr = if sk.is_empty() { std::ptr::null_mut() } else { sk.as_mut_ptr() };
            let x2r = Box::new(cryptoki_sys::CK_X2RATCHET_RESPOND_PARAMS {
                sk: sk_ptr,
                own_prekey: narrow_wire_ulong(p.own_prekey_handle.0)?,
                initiator_identity: narrow_wire_ulong(p.initiator_identity_handle.0)?,
                own_public_identity: narrow_wire_ulong(p.own_identity_handle.0)?,
                bEncryptedHeader: if p.encrypted_header {
                    cryptoki_sys::CK_TRUE
                } else {
                    cryptoki_sys::CK_FALSE
                },
                eCurve: narrow_wire_ulong(p.curve)?,
                aeadMechanism: narrow_wire_ulong(p.aead_mechanism.0)?,
                kdfMechanism: narrow_wire_ulong(p.kdf_mechanism.0)?,
            });
            Ok(FfiMechanism::from_box(mech_type, x2r, |b| FfiParamBacking::X2RatchetRespond(b, sk)))
        }

        // -- OTP: array of CK_OTP_PARAM ----------------------------------------
        CkMechanismParams::Otp(p) => {
            // S2 §6 (R19): the counted-array header follows its presence
            // peer; each element's value leg follows its own peer.
            let (is_null, count) = array_header(&p.params_presence)?;
            let present = p.params_presence.as_present().map(Vec::as_slice).unwrap_or(&[]);
            let mut buffers: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(present.len());
            let mut c_params: Vec<cryptoki_sys::CK_OTP_PARAM> = Vec::with_capacity(present.len());
            for op in present {
                let leg = input_leg(&op.value_presence)?;
                c_params.push(cryptoki_sys::CK_OTP_PARAM {
                    type_: narrow_wire_ulong(op.type_)?,
                    pValue: leg.ptr as *mut std::ffi::c_void,
                    ulValueLen: leg.len,
                });
                buffers.push(leg.backing);
            }
            // `as_mut_ptr` on an empty vector is dangling non-NULL —
            // exactly the S2 §6 `Present([])` form.
            let params_ptr = if is_null { std::ptr::null_mut() } else { c_params.as_mut_ptr() };
            let otp = Box::new(cryptoki_sys::CK_OTP_PARAMS { pParams: params_ptr, ulCount: count });
            Ok(FfiMechanism::from_box(mech_type, otp, |b| {
                FfiParamBacking::Otp(b, c_params, buffers)
            }))
        }

        // -- KIP: nested mechanism pointer + seed + handle ----------------------
        CkMechanismParams::Kip(p) => {
            // S2 §6 (R19): a NULL `pMechanism` runs no inner conversion
            // and retains nothing; the seed follows its presence peer.
            let nested = if let Some(nested_mech) = p.mechanism.as_deref() {
                let inner_ffi = nested_mechanism_to_ffi(nested_mech, depth, validated.registry())?;
                let inner_mech = NativeAllocation::from_box(Box::new(inner_ffi.ck_mechanism()));
                // Keep the inner mechanism's parameter backing alive by
                // moving it into the KIP backing, so any pointers the
                // inner C struct holds stay valid for the call and are
                // freed afterwards (L8 — was a mem::forget that leaked it
                // permanently).
                let inner_backing = NativeAllocation::from_box(Box::new(inner_ffi._backing));
                Some((inner_mech, inner_backing))
            } else {
                None
            };
            let seed = input_leg(&p.seed_presence)?;
            let kip = Box::new(cryptoki_sys::CK_KIP_PARAMS {
                pMechanism: nested
                    .as_ref()
                    .map_or(std::ptr::null_mut(), |nested| nested.0.root() as *mut _),
                hKey: narrow_wire_ulong(p.key_handle.0)?,
                pSeed: seed.ptr,
                ulSeedLen: seed.len,
            });
            Ok(FfiMechanism::from_box(mech_type, kip, |b| {
                FfiParamBacking::Kip(b, nested, seed.backing)
            }))
        }

        // -- CMS Sig: nested mechanisms + content type + attribute buffers -------
        CkMechanismParams::CmsSig(p) => {
            let sign_ffi =
                nested_mechanism_to_ffi(&p.signing_mechanism, depth, validated.registry())?;
            let digest_ffi =
                nested_mechanism_to_ffi(&p.digest_mechanism, depth, validated.registry())?;
            let sign_mech = NativeAllocation::from_box(Box::new(sign_ffi.ck_mechanism()));
            let digest_mech = NativeAllocation::from_box(Box::new(digest_ffi.ck_mechanism()));
            let mut content_type = Zeroizing::new(p.content_type.as_bytes().to_vec());
            content_type.push(0); // null-terminate
            let mut req_attrs = p.requested_attributes.expose(|b| Zeroizing::new(b.to_vec()));
            let mut reqd_attrs = p.required_attributes.expose(|b| Zeroizing::new(b.to_vec()));
            let ct_ptr = content_type.as_mut_ptr();
            let req_ptr =
                if req_attrs.is_empty() { std::ptr::null_mut() } else { req_attrs.as_mut_ptr() };
            let reqd_ptr =
                if reqd_attrs.is_empty() { std::ptr::null_mut() } else { reqd_attrs.as_mut_ptr() };
            let cms = Box::new(cryptoki_sys::CK_CMS_SIG_PARAMS {
                certificateHandle: narrow_wire_ulong(p.certificate_handle.0)?,
                pSigningMechanism: sign_mech.root() as *mut _,
                pDigestMechanism: digest_mech.root() as *mut _,
                pContentType: ct_ptr,
                pRequestedAttributes: req_ptr,
                ulRequestedAttributesLen: req_attrs.len() as cryptoki_sys::CK_ULONG,
                pRequiredAttributes: reqd_ptr,
                ulRequiredAttributesLen: reqd_attrs.len() as cryptoki_sys::CK_ULONG,
            });
            // Keep both inner mechanism backings alive by moving them into the
            // CmsSig backing (L8 — was a mem::forget that leaked them).
            Ok(FfiMechanism::from_box(mech_type, cms, |b| {
                FfiParamBacking::CmsSig(
                    b,
                    sign_mech,
                    digest_mech,
                    content_type,
                    req_attrs,
                    reqd_attrs,
                    NativeAllocation::from_box(Box::new(sign_ffi._backing)),
                    NativeAllocation::from_box(Box::new(digest_ffi._backing)),
                )
            }))
        }

        // -- Skipjack Private Wrap: struct with many pointers -------------------
        CkMechanismParams::SkipjackPrivateWrap(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            // PrimeP/BaseG share the one C `ulPAndGLen`: v1 decode enforces
            // strict agreement (`check_shared_len_agreement`), and a
            // directly-constructed legacy value with mismatched legs
            // converts with the length following PrimeP (pinned by
            // `r19_reconstruct_skipjack_private_wrap_legacy_mismatch_uses_prime_p`).
            // `ulPasswordLen` stays scalar-authoritative (pinned).
            let password = input_leg(&p.password_presence)?;
            let public_data = input_leg(&p.public_data_presence)?;
            let random_a = input_leg(&p.random_a_presence)?;
            let prime_p = input_leg(&p.prime_p_presence)?;
            let base_g = input_leg(&p.base_g_presence)?;
            let subprime_q = input_leg(&p.subprime_q_presence)?;
            let sj = Box::new(cryptoki_sys::CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
                ulPasswordLen: narrow_wire_ulong(p.password_length)?,
                pPassword: password.ptr,
                ulPublicDataLen: public_data.len,
                pPublicData: public_data.ptr,
                ulPAndGLen: prime_p.len,
                ulQLen: subprime_q.len,
                ulRandomLen: random_a.len,
                pRandomA: random_a.ptr,
                pPrimeP: prime_p.ptr,
                pBaseG: base_g.ptr,
                pSubprimeQ: subprime_q.ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, sj, |b| {
                FfiParamBacking::SkipjackPrivateWrap(
                    b,
                    password.backing,
                    public_data.backing,
                    random_a.backing,
                    prime_p.backing,
                    base_g.backing,
                    subprime_q.backing,
                )
            }))
        }

        // -- Skipjack Relayx: struct with 7 pointers ----------------------------
        CkMechanismParams::SkipjackRelayx(p) => {
            // S2 §6 (R19): the presence peers govern NULL-ness and length.
            let old_wrapped_x = input_leg(&p.old_wrapped_x_presence)?;
            let old_password = input_leg(&p.old_password_presence)?;
            let old_public_data = input_leg(&p.old_public_data_presence)?;
            let old_random_a = input_leg(&p.old_random_a_presence)?;
            let new_password = input_leg(&p.new_password_presence)?;
            let new_public_data = input_leg(&p.new_public_data_presence)?;
            let new_random_a = input_leg(&p.new_random_a_presence)?;
            let sj = Box::new(cryptoki_sys::CK_SKIPJACK_RELAYX_PARAMS {
                ulOldWrappedXLen: old_wrapped_x.len,
                pOldWrappedX: old_wrapped_x.ptr,
                ulOldPasswordLen: old_password.len,
                pOldPassword: old_password.ptr,
                ulOldPublicDataLen: old_public_data.len,
                pOldPublicData: old_public_data.ptr,
                ulOldRandomLen: old_random_a.len,
                pOldRandomA: old_random_a.ptr,
                ulNewPasswordLen: new_password.len,
                pNewPassword: new_password.ptr,
                ulNewPublicDataLen: new_public_data.len,
                pNewPublicData: new_public_data.ptr,
                ulNewRandomLen: new_random_a.len,
                pNewRandomA: new_random_a.ptr,
            });
            Ok(FfiMechanism::from_box(mech_type, sj, |b| {
                FfiParamBacking::SkipjackRelayx(
                    b,
                    old_wrapped_x.backing,
                    old_password.backing,
                    old_public_data.backing,
                    old_random_a.backing,
                    new_password.backing,
                    new_public_data.backing,
                    new_random_a.backing,
                )
            }))
        }

        // -- Vendor-specific: these reference nested CkMechanism or complex -----
        // vendor layouts that cannot be safely reconstructed generically.
        CkMechanismParams::Ecies(_)
        | CkMechanismParams::AesCmacKeyDerivation(_)
        | CkMechanismParams::Dilithium(_)
        | CkMechanismParams::Kyber(_)
        | CkMechanismParams::HdKeyDerive(_)
        | CkMechanismParams::VendorObjectExtract(_)
        | CkMechanismParams::VendorObjectInsert(_) => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

fn gcm_iv_capacity(iv_buffer_len: u64, input_len: usize) -> CkResult<usize> {
    let requested = usize::try_from(iv_buffer_len).map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
    let capacity = input_len.max(requested);
    const MAX_GCM_IV_BUFFER_LEN: usize = 512 * 1024 * 1024;
    if capacity > MAX_GCM_IV_BUFFER_LEN {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    Ok(capacity)
}

// -- R19 (S2 §6): typed input-leg reconstruction -------------------------

/// S2 §6 `Present([])` leg: one stable readable non-NULL address shared
/// by every empty-present byte leg (top-level and nested alike — the
/// nested-OAEP byte-identity pin requires top and nested to agree).
/// Length 0 always accompanies it, but providers may probe readability,
/// so this designates a real static byte rather than a dangling address.
static EMPTY_BYTE: u8 = 0;
const EMPTY_NON_NULL: *mut u8 = &EMPTY_BYTE as *const u8 as *mut u8;

/// One reconstructed S2 §6 input byte-leg: the owned backing (populated
/// only for `Present(data)`), the provider-visible pointer, and the
/// declared length.
struct InputLeg {
    backing: Zeroizing<Vec<u8>>,
    ptr: *mut u8,
    len: cryptoki_sys::CK_ULONG,
}

/// Reconstruct one S2 §6 input byte-leg from its presence peer.
/// `Null{n}` → no backing, NULL + narrowed `n` (never allocates — a
/// huge `declared_len` forwards without touching the allocator);
/// `Present([])` → no backing, [`EMPTY_NON_NULL`] + 0; `Present(data)` →
/// owned zeroized copy + exact length (never a client address).
fn input_leg(presence: &PointerBytes) -> CkResult<InputLeg> {
    match presence {
        PointerBytes::Null { declared_len } => Ok(InputLeg {
            backing: Zeroizing::new(Vec::new()),
            ptr: std::ptr::null_mut(),
            len: narrow_wire_ulong(*declared_len)?,
        }),
        PointerBytes::Present(bytes) => {
            let data_len = bytes.len();
            if data_len == 0 {
                Ok(InputLeg { backing: Zeroizing::new(Vec::new()), ptr: EMPTY_NON_NULL, len: 0 })
            } else {
                let mut backing = bytes.expose(|b| Zeroizing::new(b.to_vec()));
                let ptr = backing.as_mut_ptr();
                let len = narrow_wire_ulong(data_len as u64)?;
                Ok(InputLeg { backing, ptr, len })
            }
        }
    }
}

/// One SP800-108 data-param value rebuilt as backend-native storage
/// (F5): the provider reads these payloads via aligned native loads,
/// so they cannot ride in align-1 byte backing (R19 rule). The
/// iteration-variable format shares the counter record.
enum Sp800108NativeValue {
    Counter(NativeAllocation<cryptoki_sys::CK_SP800_108_COUNTER_FORMAT>),
    DkmLength(NativeAllocation<cryptoki_sys::CK_SP800_108_DKM_LENGTH_FORMAT>),
    KeyHandle(NativeAllocation<cryptoki_sys::CK_ULONG>),
}

impl Sp800108NativeValue {
    /// Provider-visible pointer into the owned native allocation.
    fn pvalue(&self) -> *mut std::ffi::c_void {
        match self {
            Sp800108NativeValue::Counter(native) => native.root() as *mut std::ffi::c_void,
            Sp800108NativeValue::DkmLength(native) => native.root() as *mut std::ffi::c_void,
            Sp800108NativeValue::KeyHandle(native) => native.root() as *mut std::ffi::c_void,
        }
    }
}

/// One SP800-108 data-param value leg (F5).
enum Sp800108ValueLeg {
    /// Rebuilt native backing + provider-visible `ulValueLen` (always
    /// the backend-native size — a 4-byte ILP32 key handle bridges to
    /// 8 bytes on an LP64 daemon) + the untouched client bytes the
    /// echo/retention path round-trips (`presence_from_ffi` ignores the
    /// struct length for live pointers, so bridged legs echo exactly).
    Native { backing: Sp800108NativeValue, len: cryptoki_sys::CK_ULONG, echo: Zeroizing<Vec<u8>> },
    /// The generic [`input_leg`] path (NULL legs, empty iteration
    /// variables, BYTE_ARRAY, unknown vendor types).
    Passthrough,
}

/// Route one SP800-108 data-param value (F5): COUNTER, DKM_LENGTH,
/// KEY_HANDLE and non-empty ITERATION_VARIABLE payloads parse (client
/// width inferred from length) and rebuild backend-native; NULL legs,
/// empty iteration variables (mock-blessed leniency for non-counter
/// modes), BYTE_ARRAY and unknown vendor types keep [`input_leg`].
/// Empty COUNTER/DKM_LENGTH/KEY_HANDLE payloads fail closed (OASIS- and
/// mock-invalid) instead of handing the provider an empty extent to
/// read a struct from.
fn sp800_108_value_leg(type_: u64, presence: &PointerBytes) -> CkResult<Sp800108ValueLeg> {
    let PointerBytes::Present(secret) = presence else {
        // NULL legs (incl. OASIS NULL+0 iteration variables) keep the
        // generic NULL leg: NULL-ness follows the presence peer.
        return Ok(Sp800108ValueLeg::Passthrough);
    };
    if secret.is_empty() {
        if matches!(type_, CK_SP800_108_COUNTER | CK_SP800_108_DKM_LENGTH | CK_SP800_108_KEY_HANDLE)
        {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        return Ok(Sp800108ValueLeg::Passthrough);
    }
    match type_ {
        CK_SP800_108_COUNTER | CK_SP800_108_ITERATION_VARIABLE => secret.expose(|value| {
            let format = parse_counter_format(value)?;
            let native =
                NativeAllocation::from_box(Box::new(cryptoki_sys::CK_SP800_108_COUNTER_FORMAT {
                    bLittleEndian: format.little_endian,
                    ulWidthInBits: narrow_wire_ulong(format.width_in_bits)?,
                }));
            Ok(Sp800108ValueLeg::Native {
                backing: Sp800108NativeValue::Counter(native),
                len: narrow_wire_ulong(
                    std::mem::size_of::<cryptoki_sys::CK_SP800_108_COUNTER_FORMAT>() as u64,
                )?,
                echo: Zeroizing::new(value.to_vec()),
            })
        }),
        CK_SP800_108_DKM_LENGTH => secret.expose(|value| {
            let format = parse_dkm_length_format(value)?;
            let native = NativeAllocation::from_box(Box::new(
                cryptoki_sys::CK_SP800_108_DKM_LENGTH_FORMAT {
                    dkmLengthMethod: narrow_wire_ulong(format.method)?,
                    bLittleEndian: format.little_endian,
                    ulWidthInBits: narrow_wire_ulong(format.width_in_bits)?,
                },
            ));
            Ok(Sp800108ValueLeg::Native {
                backing: Sp800108NativeValue::DkmLength(native),
                len: narrow_wire_ulong(std::mem::size_of::<
                    cryptoki_sys::CK_SP800_108_DKM_LENGTH_FORMAT,
                >() as u64)?,
                echo: Zeroizing::new(value.to_vec()),
            })
        }),
        CK_SP800_108_KEY_HANDLE => secret.expose(|value| {
            let handle = parse_key_handle_value(value)?;
            let native = NativeAllocation::new(narrow_wire_ulong(handle)?);
            Ok(Sp800108ValueLeg::Native {
                backing: Sp800108NativeValue::KeyHandle(native),
                len: narrow_wire_ulong(std::mem::size_of::<cryptoki_sys::CK_ULONG>() as u64)?,
                echo: Zeroizing::new(value.to_vec()),
            })
        }),
        // Non-empty BYTE_ARRAY and unknown vendor types stay opaque
        // byte copies (no CK_ULONG content to model).
        _ => Ok(Sp800108ValueLeg::Passthrough),
    }
}

/// S2 §6 counted-array header from the presence peer: NULL-ness +
/// declared count. `Null{n}` → (NULL, narrowed `n`) with no element
/// work; `Present(items)` → (non-NULL, exact count) — the caller
/// converts `items` into an exactly-sized owned `Vec<T>` (element-aligned
/// by construction) and points at it, or at
/// [`EMPTY_NON_NULL`] when empty.
fn array_header<T>(presence: &PointerArray<T>) -> CkResult<(bool, cryptoki_sys::CK_ULONG)> {
    match presence {
        PointerArray::Null { declared_count } => Ok((true, narrow_wire_ulong(*declared_count)?)),
        PointerArray::Present(items) => Ok((false, narrow_wire_ulong(items.len() as u64)?)),
    }
}

/// Reconstruct one S2 §6 PRF output leg from its envelope: NULL (no
/// backing) iff `output_is_null`; otherwise a zeroed `output_len`
/// buffer. The scalar narrows BEFORE allocating (a 32-bit-truncating
/// scalar errors instead of mis-sizing), and the reservation is
/// fallible (`HOST_MEMORY` per the S2 §6 RV table — `output_len` is an
/// uncapped scalar, so `vec![0; n]` would panic on huge values).
/// Returns the backing plus the provider-visible pointer.
fn prf_output_buffer(
    output_len: u64,
    output_is_null: bool,
) -> CkResult<(Zeroizing<Vec<u8>>, *mut u8)> {
    if output_is_null {
        return Ok((Zeroizing::new(Vec::new()), std::ptr::null_mut()));
    }
    let capacity = narrow_wire_ulong(output_len)? as usize;
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(capacity).map_err(|_| CkRv::HOST_MEMORY)?;
    buffer.resize(capacity, 0);
    let mut buffer = Zeroizing::new(buffer);
    let ptr = buffer.as_mut_ptr();
    Ok((buffer, ptr))
}

/// Bits-to-bytes ceiling for bits-governed legs (ChaCha20/Salsa20
/// counters and nonces, key-mat IVs): infallible — the input is an
/// already-narrowed `CK_ULONG`, and `bits / 8 + 1` cannot overflow it.
fn bits_to_bytes_ceil(bits: cryptoki_sys::CK_ULONG) -> usize {
    (bits / 8 + cryptoki_sys::CK_ULONG::from(!bits.is_multiple_of(8))) as usize
}

/// Reconstruct one S2 §6 externally-sized leg (no byte-length field —
/// the provider reads/writes exactly `size_bytes`): `Null{..}` → no
/// backing + NULL (the declared length is opaque — no field carries
/// it); `Present` → live buffer of exactly `size_bytes` (pad/truncate
/// — the provider reads that many regardless, so an exact-sized
/// backing would over-read on short inputs and dangle on empty ones).
/// `Present` is always non-NULL (dangling when `size_bytes` is 0 — the
/// provider touches nothing then). Reservations are fallible
/// (`HOST_MEMORY` per the S2 §6 RV table — the size derives from an
/// uncapped scalar). When `out_is_null` (key-mat IVs with a NULL OUT
/// struct — never provider-visible), the caller's full bytes are kept
/// so the echo round-trips exactly.
fn sized_leg(
    presence: &PointerBytes,
    size_bytes: usize,
    out_is_null: bool,
) -> CkResult<(Zeroizing<Vec<u8>>, *mut u8)> {
    match presence {
        PointerBytes::Null { .. } => Ok((Zeroizing::new(Vec::new()), std::ptr::null_mut())),
        PointerBytes::Present(bytes) => bytes.expose(|b| {
            let mut backing = if b.is_empty() {
                let mut sized = Vec::new();
                sized.try_reserve_exact(size_bytes).map_err(|_| CkRv::HOST_MEMORY)?;
                sized.resize(size_bytes, 0);
                Zeroizing::new(sized)
            } else if out_is_null {
                Zeroizing::new(b.to_vec())
            } else {
                let mut sized = Zeroizing::new(b.to_vec());
                let additional = size_bytes.saturating_sub(sized.len());
                if additional > 0 {
                    sized.try_reserve_exact(additional).map_err(|_| CkRv::HOST_MEMORY)?;
                }
                sized.resize(size_bytes, 0);
                sized
            };
            let ptr = backing.as_mut_ptr();
            Ok((backing, ptr))
        }),
    }
}

/// Reconstruct one S2 §6 fixed-size provider-read leg (PBE IV,
/// ChaCha20/Salsa20 counter and nonce): [`sized_leg`] with a live
/// consumer (caller bytes always normalize to exactly `size_bytes`).
fn fixed_leg(
    presence: &PointerBytes,
    size_bytes: usize,
) -> CkResult<(Zeroizing<Vec<u8>>, *mut u8)> {
    sized_leg(presence, size_bytes, false)
}

/// Echo one S2 §6 input byte-leg from its post-call FFI form (shared by
/// `output_params` and `output_params_equal`): a NULL pointer echoes
/// `Null` with the STRUCT length (provider-untouched for inputs, so
/// the caller's declared length survives exactly); a live pointer
/// echoes the backing bytes as `Present`.
fn presence_from_ffi(
    is_null: bool,
    struct_len: cryptoki_sys::CK_ULONG,
    bytes: &[u8],
) -> PointerBytes {
    if is_null {
        PointerBytes::null_len(struct_len as u64)
    } else {
        PointerBytes::present_copy(bytes)
    }
}

/// Echo one key-mat IV leg (shared by `output_params` and
/// `output_params_equal`): the stored peer carries the caller's class
/// (the only record when the OUT struct is NULL, and robust when it is
/// live — providers write IV bytes, never IV pointers); the backing
/// carries the post-call bytes (provider-written when the OUT struct
/// is live, caller bytes otherwise).
fn key_mat_iv_echo(stored: &PointerBytes, backing: &[u8], iv_len: usize) -> PointerBytes {
    match stored {
        PointerBytes::Null { declared_len } => PointerBytes::null_len(*declared_len),
        PointerBytes::Present(_) => {
            PointerBytes::present_copy(&backing[..iv_len.min(backing.len())])
        }
    }
}
