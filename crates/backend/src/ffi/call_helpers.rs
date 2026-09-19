use super::{
    FfiBackend, OperationFamily,
    ffi_conversion::{mechanism_to_ffi, narrow_wire_ulong},
    native_domain::OrdinaryGuard,
};
use crate::traits::CkDeriveKeyOutputResult;
use pkcs11_proxy_ng_types::*;

/// Maximum output buffer the daemon will allocate for a single PKCS#11 call.
/// Exact paths reject larger capacities before native entry. Convenience
/// two-call helpers retain their separate legacy allocation policy.
pub(super) const MAX_OUTPUT_BUFFER_BYTES: u64 = 512 * 1024 * 1024;

/// Legacy convenience-helper cap. Public exact paths must use checked rejection,
/// never this helper. Backend-only structured-sign helpers remain a follow-up.
pub(super) fn capped_output_len(buffer_len: u64) -> usize {
    buffer_len.min(MAX_OUTPUT_BUFFER_BYTES) as usize
}

impl FfiBackend {
    /// Checked narrowing for handles crossing into native calls. On a
    /// narrow-`CK_ULONG` host an unrepresentable handle fails loudly with
    /// `CKR_FUNCTION_FAILED`, never truncates (same doctrine as
    /// `narrow_wire_ulong`, which these delegate to). On 64-bit hosts this
    /// is an infallible pass-through.
    #[inline]
    pub(super) fn slot_id(slot_id: CkSlotId) -> CkResult<cryptoki_sys::CK_SLOT_ID> {
        narrow_wire_ulong(slot_id.0)
    }

    #[inline]
    pub(super) fn session_handle(
        session: CkSessionHandle,
    ) -> CkResult<cryptoki_sys::CK_SESSION_HANDLE> {
        narrow_wire_ulong(session.0)
    }

    #[inline]
    pub(super) fn object_handle(
        object: CkObjectHandle,
    ) -> CkResult<cryptoki_sys::CK_OBJECT_HANDLE> {
        narrow_wire_ulong(object.0)
    }

    #[inline]
    pub(super) fn mechanism_type(
        mech: CkMechanismType,
    ) -> CkResult<cryptoki_sys::CK_MECHANISM_TYPE> {
        narrow_wire_ulong(mech.0)
    }

    #[inline]
    pub(super) const fn ulong_len(len: usize) -> cryptoki_sys::CK_ULONG {
        len as cryptoki_sys::CK_ULONG
    }

    #[inline]
    pub(super) const fn ulong_len_u64(len: u64) -> cryptoki_sys::CK_ULONG {
        len as cryptoki_sys::CK_ULONG
    }

    /// Map a cryptoki_sys CK_RV to CkResult.
    #[inline]
    pub(super) fn ck_result(rv: cryptoki_sys::CK_RV) -> CkResult<()> {
        if rv == 0 { Ok(()) } else { Err(CkRv(rv as u64)) }
    }

    #[inline]
    pub(super) fn require_fn<T: Copy>(function: Option<T>) -> CkResult<T> {
        function.ok_or(Self::FUNCTION_NOT_SUPPORTED)
    }

    #[inline]
    pub(super) fn call_raw<T, F>(function: Option<T>, call: F) -> CkResult<cryptoki_sys::CK_RV>
    where
        T: Copy,
        F: FnOnce(T) -> cryptoki_sys::CK_RV,
    {
        Ok(call(Self::require_fn(function)?))
    }

    /// F-01 B2 proof token (see `call_bytes`): the caller proves ordinary
    /// admission at compile time and holds read exclusion across the call.
    #[inline]
    pub(super) fn call_unit<T, F>(
        _admission: &OrdinaryGuard,
        function: Option<T>,
        call: F,
    ) -> CkResult<()>
    where
        T: Copy,
        F: FnOnce(T) -> cryptoki_sys::CK_RV,
    {
        Self::ck_result(Self::call_raw(function, call)?)
    }

    /// Control choke: native entries that must NOT prove ordinary admission
    /// — `Initialize`/`Finalize` (exclusive state changers under the write
    /// lock, never holding read) and the stateless probe queries
    /// (`C_GetInfo`, `C_GetSlotInfo`), forwarded regardless of domain state
    /// (providers may still return `CKR_CRYPTOKI_NOT_INITIALIZED`). Taking
    /// no guard is structural: a control path cannot smuggle read exclusion
    /// into a write section through this choke.
    #[inline]
    pub(super) fn call_control_unit<T, F>(function: Option<T>, call: F) -> CkResult<()>
    where
        T: Copy,
        F: FnOnce(T) -> cryptoki_sys::CK_RV,
    {
        Self::ck_result(Self::call_raw(function, call)?)
    }

    /// Shared PKCS#11 "size query, then fill" pattern for variable-length arrays.
    ///
    /// If the second call returns `CKR_BUFFER_TOO_SMALL`, retries once with
    /// the updated size. This handles backends (e.g., NSS softokn with AES-GCM)
    /// that return a smaller size in the query than the actual output.
    pub(super) fn two_call_array<T, F>(mut call: F) -> CkResult<Vec<T>>
    where
        T: Copy + Default,
        F: FnMut(*mut T, &mut cryptoki_sys::CK_ULONG) -> cryptoki_sys::CK_RV,
    {
        let mut count: cryptoki_sys::CK_ULONG = 0;
        Self::ck_result(call(std::ptr::null_mut(), &mut count))?;
        if count == 0 {
            return Ok(vec![]);
        }

        let capped_count =
            (count as u64).min(MAX_OUTPUT_BUFFER_BYTES / std::mem::size_of::<T>() as u64) as usize;
        let mut values = vec![T::default(); capped_count];
        count = capped_count as cryptoki_sys::CK_ULONG;
        let rv = call(values.as_mut_ptr(), &mut count);
        if rv == CkRv::BUFFER_TOO_SMALL.0 as cryptoki_sys::CK_RV && (count as usize) > values.len()
        {
            // Backend needs more space than the size query indicated — retry
            // (still capped to prevent OOM).
            let retry_count = (count as u64)
                .min(MAX_OUTPUT_BUFFER_BYTES / std::mem::size_of::<T>() as u64)
                as usize;
            values.resize(retry_count, T::default());
            count = retry_count as cryptoki_sys::CK_ULONG;
            Self::ck_result(call(values.as_mut_ptr(), &mut count))?;
        } else {
            Self::ck_result(rv)?;
        }
        values.truncate(count as usize);
        Ok(values)
    }

    /// Shared PKCS#11 "size query, then fill" pattern for byte buffers.
    pub(super) fn two_call_bytes<F>(call: F) -> CkResult<SecretBytes>
    where
        F: FnMut(*mut cryptoki_sys::CK_BYTE, &mut cryptoki_sys::CK_ULONG) -> cryptoki_sys::CK_RV,
    {
        // ADR-0013 S5: the provider writes through a raw pointer, which
        // forces a plain Vec for the call window; the allocation is adopted
        // into the wiping owner immediately with no retained copy.
        Ok(SecretBytes::new(Self::two_call_array(call)?))
    }

    pub(super) fn call_array<TFunction, TItem, F>(
        function: Option<TFunction>,
        mut call: F,
    ) -> CkResult<Vec<TItem>>
    where
        TFunction: Copy,
        TItem: Copy + Default,
        F: FnMut(TFunction, *mut TItem, &mut cryptoki_sys::CK_ULONG) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        Self::two_call_array(|values, count| call(function, values, count))
    }

    /// F-01 B2 proof token: `&OrdinaryGuard` is never read — its presence
    /// proves at compile time that the caller admitted this invocation and
    /// holds lifecycle read exclusion across the native call below and the
    /// owned-copy settlement above. Callers admit exactly once at the
    /// `ffi_*` boundary and keep the guard alive until they return.
    pub(super) fn call_bytes<TFunction, F>(
        _admission: &OrdinaryGuard,
        function: Option<TFunction>,
        mut call: F,
    ) -> CkResult<SecretBytes>
    where
        TFunction: Copy,
        F: FnMut(
            TFunction,
            *mut cryptoki_sys::CK_BYTE,
            &mut cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        Self::two_call_bytes(|output, output_len| call(function, output, output_len))
    }

    pub(super) fn fill_bytes<TFunction, F>(
        function: Option<TFunction>,
        len: usize,
        call: F,
    ) -> CkResult<SecretBytes>
    where
        TFunction: Copy,
        F: FnOnce(
            TFunction,
            *mut cryptoki_sys::CK_BYTE,
            cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        let mut bytes = vec![0u8; len];
        Self::ck_result(call(function, bytes.as_mut_ptr(), Self::ulong_len(len)))?;
        // ADR-0013 S5: adopt the provider-written buffer immediately.
        Ok(SecretBytes::new(bytes))
    }

    pub(super) fn session_output<F>(mut call: F) -> CkResult<CkSessionHandle>
    where
        F: FnMut(*mut cryptoki_sys::CK_SESSION_HANDLE) -> cryptoki_sys::CK_RV,
    {
        let mut handle: cryptoki_sys::CK_SESSION_HANDLE = 0;
        Self::ck_result(call(&mut handle))?;
        Ok(CkSessionHandle(handle as u64))
    }

    pub(super) fn call_session_output<TFunction, F>(
        _admission: &OrdinaryGuard,
        function: Option<TFunction>,
        mut call: F,
    ) -> CkResult<CkSessionHandle>
    where
        TFunction: Copy,
        F: FnMut(TFunction, *mut cryptoki_sys::CK_SESSION_HANDLE) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        Self::session_output(|handle| call(function, handle))
    }

    pub(super) fn object_output<F>(mut call: F) -> CkResult<CkObjectHandle>
    where
        F: FnMut(*mut cryptoki_sys::CK_OBJECT_HANDLE) -> cryptoki_sys::CK_RV,
    {
        let mut handle: cryptoki_sys::CK_OBJECT_HANDLE = 0;
        Self::ck_result(call(&mut handle))?;
        Ok(CkObjectHandle(handle as u64))
    }

    pub(super) fn call_object_output<TFunction, F>(
        _admission: &OrdinaryGuard,
        function: Option<TFunction>,
        mut call: F,
    ) -> CkResult<CkObjectHandle>
    where
        TFunction: Copy,
        F: FnMut(TFunction, *mut cryptoki_sys::CK_OBJECT_HANDLE) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        Self::object_output(|handle| call(function, handle))
    }

    pub(super) fn object_pair_output<F>(mut call: F) -> CkResult<(CkObjectHandle, CkObjectHandle)>
    where
        F: FnMut(
            *mut cryptoki_sys::CK_OBJECT_HANDLE,
            *mut cryptoki_sys::CK_OBJECT_HANDLE,
        ) -> cryptoki_sys::CK_RV,
    {
        let mut first: cryptoki_sys::CK_OBJECT_HANDLE = 0;
        let mut second: cryptoki_sys::CK_OBJECT_HANDLE = 0;
        Self::ck_result(call(&mut first, &mut second))?;
        Ok((CkObjectHandle(first as u64), CkObjectHandle(second as u64)))
    }

    pub(super) fn slot_output<F>(mut call: F) -> CkResult<CkSlotId>
    where
        F: FnMut(*mut cryptoki_sys::CK_SLOT_ID) -> cryptoki_sys::CK_RV,
    {
        let mut slot: cryptoki_sys::CK_SLOT_ID = 0;
        Self::ck_result(call(&mut slot))?;
        Ok(CkSlotId(slot as u64))
    }

    pub(super) fn call_slot_output<TFunction, F>(
        _admission: &OrdinaryGuard,
        function: Option<TFunction>,
        mut call: F,
    ) -> CkResult<CkSlotId>
    where
        TFunction: Copy,
        F: FnMut(TFunction, *mut cryptoki_sys::CK_SLOT_ID) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        Self::slot_output(|slot| call(function, slot))
    }

    pub(super) fn ulong_output<F>(mut call: F) -> CkResult<u64>
    where
        F: FnMut(*mut cryptoki_sys::CK_ULONG) -> cryptoki_sys::CK_RV,
    {
        let mut value: cryptoki_sys::CK_ULONG = 0;
        Self::ck_result(call(&mut value))?;
        Ok(value as u64)
    }

    pub(super) fn call_ulong_output<TFunction, F>(
        _admission: &OrdinaryGuard,
        function: Option<TFunction>,
        mut call: F,
    ) -> CkResult<u64>
    where
        TFunction: Copy,
        F: FnMut(TFunction, *mut cryptoki_sys::CK_ULONG) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        Self::ulong_output(|value| call(function, value))
    }

    pub(super) fn call_unit_with_mechanism<TFunction, F>(
        function: Option<TFunction>,
        mechanism: &CkMechanism,
        call: F,
    ) -> CkResult<()>
    where
        TFunction: Copy,
        F: FnOnce(TFunction, &mut cryptoki_sys::CK_MECHANISM) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        let mut ffi_mech = mechanism_to_ffi(mechanism)?;
        Self::ck_result(call(function, ffi_mech.ck_mechanism_mut()))
    }

    /// Like `call_unit_with_mechanism` but caches the `FfiMechanism` in
    /// `mech_cache` on success, keyed by session handle and operation
    /// family (C3M.3). This keeps backing memory (e.g. OAEP pSourceData)
    /// alive until the same family's next Init, cancel, or session close,
    /// for backends that store mechanism pointers. Other families' slots
    /// are untouched, so dual operations (Encrypt + Digest) coexist.
    pub(super) fn call_init_with_mechanism<TFunction, F>(
        &self,
        session: CkSessionHandle,
        family: OperationFamily,
        function: Option<TFunction>,
        mechanism: &CkMechanism,
        call: F,
    ) -> CkResult<()>
    where
        TFunction: Copy,
        F: FnOnce(TFunction, &mut cryptoki_sys::CK_MECHANISM) -> cryptoki_sys::CK_RV,
    {
        let generation = self.lifecycle.current_generation();
        let function = Self::require_fn(function)?;
        let mut ffi_mech = mechanism_to_ffi(mechanism)?;
        Self::ck_result(call(function, ffi_mech.ck_mechanism_mut()))?;
        // Row-10 stale-completion guard: if re-initialization advanced the
        // generation while the native call ran, this completion belongs to
        // a dead incarnation. Retire its owner instead of publishing it —
        // the slot may already belong to a reused handle in the new one.
        if self.lifecycle.current_generation() != generation {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        // Keep the mechanism's backing memory alive in this family's slot.
        self.mech_cache.insert((session.0, family), ffi_mech);
        self.last_init_family.insert(session.0, family);
        Ok(())
    }

    pub(super) fn call_init_with_mechanism_output<TFunction, F>(
        &self,
        session: CkSessionHandle,
        family: OperationFamily,
        function: Option<TFunction>,
        mechanism: &CkMechanism,
        call: F,
    ) -> CkResult<Option<CkMechanismParams>>
    where
        TFunction: Copy,
        F: FnOnce(TFunction, &mut cryptoki_sys::CK_MECHANISM) -> cryptoki_sys::CK_RV,
    {
        let generation = self.lifecycle.current_generation();
        let function = Self::require_fn(function)?;
        let mut ffi_mech = mechanism_to_ffi(mechanism)?;
        Self::ck_result(call(function, ffi_mech.ck_mechanism_mut()))?;
        let output_params = ffi_mech.output_params();
        // Row-10 stale-completion guard: same dead-incarnation refusal as
        // `call_init_with_mechanism` — never publish into a reused slot.
        if self.lifecycle.current_generation() != generation {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        // Keep the mechanism's backing memory alive in this family's slot.
        self.mech_cache.insert((session.0, family), ffi_mech);
        self.last_init_family.insert(session.0, family);
        Ok(output_params)
    }

    /// Retire one family's cached mechanism (called on that family's Init
    /// cancel). Sibling families' slots and the last-Init marker are
    /// untouched: a cancel proves nothing about other families' owners.
    /// If the marker names the retired family, the unscoped read below
    /// yields None rather than a sibling's graph — matching the pre-slot
    /// observable behavior where cancel emptied the whole cache.
    pub(super) fn drop_mech_cache_family(&self, session: CkSessionHandle, family: OperationFamily) {
        self.mech_cache.remove(&(session.0, family));
    }

    /// Drop every cached mechanism of the given session, plus its last-Init
    /// marker (called on session close).
    pub(super) fn drop_mech_cache_session(&self, session: CkSessionHandle) {
        self.mech_cache.retain(|key, _| key.0 != session.0);
        self.last_init_family.remove(&session.0);
    }

    /// Record `session -> slot` for later per-slot eviction in
    /// `C_CloseAllSessions`. Called after a successful `C_OpenSession`. Updates
    /// both the forward map and the `slot -> sessions` reverse index.
    pub(super) fn remember_session_slot(&self, session: CkSessionHandle, slot: CkSlotId) {
        self.session_slot_map.insert(session.0, slot.0);
        self.slot_sessions.entry(slot.0).or_default().insert(session.0);
    }

    /// Forget the `session -> slot` mapping. Called from per-session close paths.
    pub(super) fn forget_session_slot(&self, session: CkSessionHandle) {
        // Remove the forward mapping and, via the slot it pointed to, drop the
        // session from the reverse index. The `get_mut` guard is dropped before
        // `remove_if`, which re-checks emptiness under the shard lock so a
        // concurrent `remember_session_slot` on the same slot is not lost to a
        // stale empty-set removal.
        if let Some((_, slot)) = self.session_slot_map.remove(&session.0) {
            if let Some(mut sessions) = self.slot_sessions.get_mut(&slot) {
                sessions.remove(&session.0);
            }
            self.slot_sessions.remove_if(&slot, |_, sessions| sessions.is_empty());
        }
    }

    /// Drop all `mech_cache` entries belonging to sessions on `slot_id`,
    /// and remove those session-slot mappings. Called from
    /// `C_CloseAllSessions` so the underlying lib's session invalidation
    /// is reflected in our Rust-owned caches.
    pub(super) fn drop_mech_cache_for_slot(&self, slot_id: CkSlotId) {
        // O(sessions-on-slot): take the slot's session set from the reverse
        // index, then evict exactly those sessions' entries — every family
        // slot plus the last-Init marker — from the mechanism cache and
        // the forward map — no full scan of every open session (L4).
        let Some((_, sessions)) = self.slot_sessions.remove(&slot_id.0) else {
            return;
        };
        for session in sessions {
            self.mech_cache.retain(|key, _| key.0 != session);
            self.last_init_family.remove(&session);
            self.session_slot_map.remove(&session);
        }
    }

    /// Clear all `mech_cache` entries and session-slot mappings after
    /// successful `C_Finalize` so Rust-owned mechanism backing memory is
    /// released even when the caller doesn't close sessions individually first.
    /// Also used when a successful `C_Initialize` opens a new incarnation:
    /// bindings cached under the dead generation must not survive it.
    pub(super) fn drop_all_mech_cache(&self) {
        self.mech_cache.clear();
        self.last_init_family.clear();
        self.session_slot_map.clear();
        self.slot_sessions.clear();
    }

    /// Read one family's retained `output_params()`. Returns None when the
    /// family has no live slot — including when a cancel retired it — never
    /// a sibling family's graph.
    pub(super) fn cached_mechanism_output_params_for(
        &self,
        session: CkSessionHandle,
        family: OperationFamily,
    ) -> Option<CkMechanismParams> {
        self.mech_cache.get(&(session.0, family)).and_then(|mechanism| mechanism.output_params())
    }

    pub(super) fn call_bytes_with_mechanism<TFunction, F>(
        function: Option<TFunction>,
        mechanism: &CkMechanism,
        mut call: F,
    ) -> CkResult<SecretBytes>
    where
        TFunction: Copy,
        F: FnMut(
            TFunction,
            &mut cryptoki_sys::CK_MECHANISM,
            *mut cryptoki_sys::CK_BYTE,
            &mut cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        let mut ffi_mech = mechanism_to_ffi(mechanism)?;
        Self::two_call_bytes(|output, output_len| {
            call(function, ffi_mech.ck_mechanism_mut(), output, output_len)
        })
    }

    pub(super) fn call_object_with_mechanism<TFunction, F>(
        function: Option<TFunction>,
        mechanism: &CkMechanism,
        mut call: F,
    ) -> CkResult<CkObjectHandle>
    where
        TFunction: Copy,
        F: FnMut(
            TFunction,
            &mut cryptoki_sys::CK_MECHANISM,
            *mut cryptoki_sys::CK_OBJECT_HANDLE,
        ) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        let mut ffi_mech = mechanism_to_ffi(mechanism)?;
        Self::object_output(|handle| call(function, ffi_mech.ck_mechanism_mut(), handle))
    }

    /// Single FFI call with exact buffer semantics.
    ///
    /// - If `spec.length_pointer_null` is true, preserves the output pointer class and passes a
    ///   NULL length pointer.
    /// - Otherwise, if `spec.buffer_present` is false, passes NULL output for an ordinary size
    ///   query.
    /// - Otherwise, allocates the caller-specified buffer.
    ///
    /// Returns `CkOutputBufferResult` with the exact CK_RV, length, and data.
    pub(super) fn single_call_bytes_exact<F>(
        spec: &CkOutputBufferSpec,
        call: F,
    ) -> CkResult<CkOutputBufferResult>
    where
        F: FnOnce(*mut cryptoki_sys::CK_BYTE, *mut cryptoki_sys::CK_ULONG) -> cryptoki_sys::CK_RV,
    {
        // Preparation is complete before invoking the FnOnce. A resource limit
        // must never change the caller's native capacity.
        let capacity = if spec.buffer_present && !spec.length_pointer_null {
            if spec.buffer_len > MAX_OUTPUT_BUFFER_BYTES {
                // F4/D7: a claimed output capacity above the daemon's
                // materialization ceiling is unforwardable (the exact
                // provider call needs the full buffer to cross), so it is
                // a bad argument, not a failed allocation: answer
                // CKR_ARGUMENTS_BAD per ADR-0010 Limits-(d), mirroring
                // Limits-(a) for absurd inputs and the parameter-roundtrip
                // gate below. A genuine allocation failure under the cap
                // still returns CKR_HOST_MEMORY.
                return Err(CkRv::ARGUMENTS_BAD);
            }
            usize::try_from(spec.buffer_len).map_err(|_| CkRv::HOST_MEMORY)?
        } else {
            0
        };
        let mut length = if spec.buffer_present && !spec.length_pointer_null {
            cryptoki_sys::CK_ULONG::try_from(spec.buffer_len).map_err(|_| CkRv::HOST_MEMORY)?
        } else {
            0
        };
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(capacity).map_err(|_| CkRv::HOST_MEMORY)?;
        bytes.resize(capacity, 0);
        let output = if spec.buffer_present { bytes.as_mut_ptr() } else { std::ptr::null_mut() };
        let length_pointer =
            if spec.length_pointer_null { std::ptr::null_mut() } else { &mut length };
        let rv = CkRv(call(output, length_pointer) as u64);
        // In/out cells are initialized. Query cells are output-only: OK defines
        // the length, otherwise only a changed initialized value proves a store.
        // An error store of zero and no store remain observationally ambiguous.
        let returned_len = (!spec.length_pointer_null
            && (spec.buffer_present || rv == CkRv::OK || length != 0))
            .then_some(length as u64);
        let value = if rv == CkRv::OK
            && !spec.length_pointer_null
            && spec.buffer_present
            && (length as u64) <= capacity as u64
        {
            bytes.truncate(length as usize);
            Some(bytes)
        } else {
            None
        };
        Ok(CkOutputBufferResult { ck_rv: rv, returned_len, value: value.map(SecretBytes::new) })
    }

    /// Resolve a function pointer then call `single_call_bytes_exact`.
    pub(super) fn call_bytes_exact<TFunction, F>(
        function: Option<TFunction>,
        spec: &CkOutputBufferSpec,
        mut call: F,
    ) -> CkResult<CkOutputBufferResult>
    where
        TFunction: Copy,
        F: FnMut(
            TFunction,
            *mut cryptoki_sys::CK_BYTE,
            *mut cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        Self::single_call_bytes_exact(spec, |output, output_len| call(function, output, output_len))
    }

    /// Like `call_bytes_exact` but builds a CK_MECHANISM first.
    pub(super) fn call_bytes_exact_with_mechanism<TFunction, F>(
        function: Option<TFunction>,
        mechanism: &CkMechanism,
        spec: &CkOutputBufferSpec,
        mut call: F,
    ) -> CkResult<CkOutputBufferResult>
    where
        TFunction: Copy,
        F: FnMut(
            TFunction,
            &mut cryptoki_sys::CK_MECHANISM,
            *mut cryptoki_sys::CK_BYTE,
            *mut cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        let mut ffi_mech = mechanism_to_ffi(mechanism)?;
        Self::single_call_bytes_exact(spec, |output, output_len| {
            call(function, ffi_mech.ck_mechanism_mut(), output, output_len)
        })
    }

    /// `C_DeriveKey`-style call with mechanism-param write-back.
    /// Returns the derived key handle plus any HSM-mutated params
    /// (e.g. the negotiated `CK_VERSION` from a TLS 1.2 master-key
    /// derive).  Mirrors [`Self::call_object_with_mechanism`] but
    /// surfaces `output_params()` for callers that need it.
    pub(super) fn call_object_with_mechanism_output<TFunction, F>(
        function: Option<TFunction>,
        mechanism: &CkMechanism,
        mut call: F,
    ) -> CkResult<(CkObjectHandle, Option<CkMechanismParams>)>
    where
        TFunction: Copy,
        F: FnMut(
            TFunction,
            &mut cryptoki_sys::CK_MECHANISM,
            *mut cryptoki_sys::CK_OBJECT_HANDLE,
        ) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        let mut ffi_mech = mechanism_to_ffi(mechanism)?;
        let handle =
            Self::object_output(|handle| call(function, ffi_mech.ck_mechanism_mut(), handle))?;
        Ok((handle, ffi_mech.output_params()))
    }

    /// `C_DeriveKey`-style call with mechanism-param write-back, preserving
    /// post-call output params even when the PKCS#11 return value is not OK.
    pub(super) fn call_object_with_mechanism_output_result<TFunction, F>(
        function: Option<TFunction>,
        mechanism: &CkMechanism,
        mut call: F,
    ) -> CkResult<CkDeriveKeyOutputResult>
    where
        TFunction: Copy,
        F: FnMut(
            TFunction,
            &mut cryptoki_sys::CK_MECHANISM,
            *mut cryptoki_sys::CK_OBJECT_HANDLE,
        ) -> cryptoki_sys::CK_RV,
    {
        let function = match Self::require_fn(function) {
            Ok(function) => function,
            Err(rv) => return Ok(CkDeriveKeyOutputResult::error(rv, None)),
        };
        let mut ffi_mech = match mechanism_to_ffi(mechanism) {
            Ok(ffi_mech) => ffi_mech,
            Err(rv) => return Ok(CkDeriveKeyOutputResult::error(rv, None)),
        };
        let mut handle: cryptoki_sys::CK_OBJECT_HANDLE = 0;
        let rv = CkRv(call(function, ffi_mech.ck_mechanism_mut(), &mut handle) as u64);
        let mechanism_out = ffi_mech.output_params();
        if rv.is_ok() {
            Ok(CkDeriveKeyOutputResult::ok(CkObjectHandle(handle as u64), mechanism_out))
        } else {
            Ok(CkDeriveKeyOutputResult::error(rv, mechanism_out))
        }
    }

    /// Single FFI call with exact buffer semantics AND mechanism param
    /// write-back. Used by single-shot operations whose mechanism can be
    /// mutated by the HSM during the call (e.g. AES-GCM key wrap with
    /// HSM-generated IV).
    ///
    /// Mirrors [`Self::call_bytes_exact_with_mechanism`] but additionally
    /// reads the post-call `output_params()` off the FfiMechanism so
    /// callers can return it to the client.  No `mech_cache` write — the
    /// mechanism is consumed in this one call; if the HSM writes the IV
    /// after returning (CloudHSM Encrypt-time pattern), the caller must
    /// route through the cached `*Init` path instead. Error effects surface
    /// only on data/missing-length calls whose params changed.
    pub(super) fn call_bytes_exact_with_mechanism_output<TFunction, F>(
        function: Option<TFunction>,
        mechanism: &CkMechanism,
        spec: &CkOutputBufferSpec,
        mut call: F,
    ) -> CkResult<(CkOutputBufferResult, Option<CkMechanismParams>)>
    where
        TFunction: Copy,
        F: FnMut(
            TFunction,
            &mut cryptoki_sys::CK_MECHANISM,
            *mut cryptoki_sys::CK_BYTE,
            *mut cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        let mut ffi_mech = mechanism_to_ffi(mechanism)?;
        let before = ffi_mech.output_params();
        let result = Self::single_call_bytes_exact(spec, |output, output_len| {
            call(function, ffi_mech.ck_mechanism_mut(), output, output_len)
        })?;
        // Surface post-call params on data and genuine missing-length calls:
        // always on OK, and on errors iff the params changed since the
        // pre-call snapshot. Ordinary NULL-output size queries suppress them.
        let after = ffi_mech.output_params();
        let mechanism_out = if !(spec.buffer_present || spec.length_pointer_null) {
            None
        } else if result.ck_rv == CkRv::OK || after != before {
            after
        } else {
            None
        };
        Ok((result, mechanism_out))
    }

    /// Single FFI call with exact buffer semantics for BOTH main output AND
    /// parameter write-back.
    ///
    /// PKCS#11 message functions use the same `pParameter`/`ulParameterLen` for
    /// both input and output. This helper:
    /// 1. Prepares the parameter buffer: copies input parameter into a buffer of
    ///    `param_out_spec.buffer_len` if the spec indicates a buffer is present.
    /// 2. Prepares the main output buffer per `output_spec`.
    /// 3. Makes ONE FFI call.
    /// 4. Reads back both the main output and the parameter write-back.
    ///
    /// The `call` closure receives `(param_ptr, param_len, output_ptr, output_len)`
    /// where `param_ptr`/`param_len` are the prepared parameter buffer, and
    /// `output_ptr`/`output_len` are the main output buffer.
    pub(super) fn single_call_parameter_output_exact<F>(
        output_spec: &CkOutputBufferSpec,
        parameter_input: &[u8],
        param_out_spec: &CkParameterRoundtripSpec,
        mut call: F,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)>
    where
        F: FnMut(
            *mut u8,
            cryptoki_sys::CK_ULONG,
            *mut cryptoki_sys::CK_BYTE,
            *mut cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        // Prepare the parameter buffer for dual input/output use.  The
        // roundtrip envelope, not the serialized input bytes, is authoritative
        // for both pointer class and length.
        let param_buf_len = if param_out_spec.buffer_present {
            usize::try_from(param_out_spec.buffer_len).map_err(|_| CkRv::ARGUMENTS_BAD)?
        } else {
            0
        };
        if param_buf_len as u64 > MAX_OUTPUT_BUFFER_BYTES {
            return Err(CkRv::ARGUMENTS_BAD);
        }
        let mut param_buf = vec![0u8; param_buf_len];
        let copy_len = parameter_input.len().min(param_buf_len);
        if copy_len > 0 {
            param_buf[..copy_len].copy_from_slice(&parameter_input[..copy_len]);
        }
        let param_ptr = if !param_out_spec.buffer_present {
            std::ptr::null_mut()
        } else if param_buf_len == 0 {
            std::ptr::NonNull::<u8>::dangling().as_ptr()
        } else {
            param_buf.as_mut_ptr()
        };
        let param_ck_len = cryptoki_sys::CK_ULONG::try_from(param_out_spec.buffer_len)
            .map_err(|_| CkRv::ARGUMENTS_BAD)?;

        let output = Self::single_call_bytes_exact(output_spec, |buffer, length| {
            call(param_ptr, param_ck_len, buffer, length)
        })?;
        let defined = output.ck_rv == CkRv::OK || parameter_input.len() == param_buf_len;
        let parameter = CkParameterRoundtripResult {
            ck_rv: output.ck_rv,
            returned_len: param_out_spec.buffer_len,
            value: (param_out_spec.buffer_present && defined).then_some(param_buf.into()),
        };
        Ok((output, parameter))
    }

    pub(super) fn call_object_pair_with_mechanism<TFunction, F>(
        function: Option<TFunction>,
        mechanism: &CkMechanism,
        mut call: F,
    ) -> CkResult<(CkObjectHandle, CkObjectHandle)>
    where
        TFunction: Copy,
        F: FnMut(
            TFunction,
            &mut cryptoki_sys::CK_MECHANISM,
            *mut cryptoki_sys::CK_OBJECT_HANDLE,
            *mut cryptoki_sys::CK_OBJECT_HANDLE,
        ) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        let mut ffi_mech = mechanism_to_ffi(mechanism)?;
        Self::object_pair_output(|first, second| {
            call(function, ffi_mech.ck_mechanism_mut(), first, second)
        })
    }
}

#[cfg(test)]
mod output_cap_tests {
    use super::{FfiBackend, MAX_OUTPUT_BUFFER_BYTES, capped_output_len};
    use pkcs11_proxy_ng_types::{
        CkObjectHandle, CkOutputBufferSpec, CkParameterRoundtripSpec, CkRv, CkSessionHandle,
        CkSlotId, SecretBytes,
    };

    #[test]
    fn caps_absurd_buffer_len() {
        assert_eq!(capped_output_len(u64::MAX), MAX_OUTPUT_BUFFER_BYTES as usize);
        assert_eq!(capped_output_len(4 * 1024 * 1024 * 1024), MAX_OUTPUT_BUFFER_BYTES as usize);
    }

    #[test]
    fn passes_through_reasonable_buffer_len() {
        assert_eq!(capped_output_len(1024), 1024);
        assert_eq!(capped_output_len(0), 0);
    }

    #[test]
    fn native_owner_convenience_observes_one_two_three_attempt_sequences() {
        // C3M.6 row 11: the query/fill convenience helper makes exactly one
        // native attempt for failed or zero-count sizing, two for an
        // ordinary fill, and three when BUFFER_TOO_SMALL demands a retry.
        // A non-retryable fill error stops after the second attempt.
        // Already-green invariant kept as a named regression.
        use std::cell::Cell;

        // Failed sizing: the query error propagates after one attempt.
        let attempts = Cell::new(0);
        let err = FfiBackend::two_call_array(|_: *mut u8, _: &mut cryptoki_sys::CK_ULONG| {
            attempts.set(attempts.get() + 1);
            cryptoki_sys::CKR_GENERAL_ERROR
        })
        .unwrap_err();
        assert_eq!(attempts.get(), 1);
        assert_eq!(err, CkRv::GENERAL_ERROR);

        // Zero-count sizing: one query, no fill, empty result.
        let attempts = Cell::new(0);
        let empty: Vec<u8> =
            FfiBackend::two_call_array(|values: *mut u8, count: &mut cryptoki_sys::CK_ULONG| {
                attempts.set(attempts.get() + 1);
                assert!(values.is_null(), "zero-count sizing must not reach fill");
                *count = 0;
                cryptoki_sys::CKR_OK
            })
            .expect("zero-count sizing succeeds");
        assert_eq!(attempts.get(), 1);
        assert!(empty.is_empty());

        // Ordinary fill: query plus one fill.
        let attempts = Cell::new(0);
        let filled: Vec<u8> =
            FfiBackend::two_call_array(|values: *mut u8, count: &mut cryptoki_sys::CK_ULONG| {
                attempts.set(attempts.get() + 1);
                if values.is_null() {
                    *count = 3;
                } else {
                    unsafe { std::ptr::copy_nonoverlapping(b"abc".as_ptr(), values, 3) };
                }
                cryptoki_sys::CKR_OK
            })
            .expect("ordinary fill succeeds");
        assert_eq!(attempts.get(), 2);
        assert_eq!(filled, b"abc");

        // BUFFER_TOO_SMALL with a larger count: query, fill, retry fill.
        let attempts = Cell::new(0);
        let grown: Vec<u8> =
            FfiBackend::two_call_array(|values: *mut u8, count: &mut cryptoki_sys::CK_ULONG| {
                let attempt = attempts.get() + 1;
                attempts.set(attempt);
                match attempt {
                    1 => {
                        assert!(values.is_null());
                        *count = 2;
                        cryptoki_sys::CKR_OK
                    }
                    2 => {
                        *count = 5;
                        cryptoki_sys::CKR_BUFFER_TOO_SMALL
                    }
                    _ => {
                        assert_eq!(*count as usize, 5);
                        cryptoki_sys::CKR_OK
                    }
                }
            })
            .expect("retry fill succeeds");
        assert_eq!(attempts.get(), 3);
        assert_eq!(grown.len(), 5);

        // Non-retryable fill error: query plus one failed fill, no retry.
        let attempts = Cell::new(0);
        let err =
            FfiBackend::two_call_array(|values: *mut u8, count: &mut cryptoki_sys::CK_ULONG| {
                attempts.set(attempts.get() + 1);
                if values.is_null() {
                    *count = 2;
                    cryptoki_sys::CKR_OK
                } else {
                    cryptoki_sys::CKR_DEVICE_ERROR
                }
            })
            .unwrap_err();
        assert_eq!(attempts.get(), 2);
        assert_eq!(err, CkRv::DEVICE_ERROR);
    }

    #[test]
    fn null_output_length_shared_helper_preserves_all_three_native_shapes() {
        let missing_len_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true };
        let mut missing_calls = 0;
        let missing = FfiBackend::single_call_bytes_exact(
            &missing_len_spec,
            |output, output_len: *mut cryptoki_sys::CK_ULONG| {
                missing_calls += 1;
                assert!(!output.is_null(), "non-NULL output class must be preserved");
                assert!(output_len.is_null(), "missing length pointer must reach provider as NULL");
                CkRv::ARGUMENTS_BAD.0 as cryptoki_sys::CK_RV
            },
        )
        .expect("provider result envelope");
        assert_eq!(missing_calls, 1);
        assert_eq!(missing.ck_rv, CkRv::ARGUMENTS_BAD);
        assert_eq!(missing.returned_len, None);
        assert_eq!(missing.value, None);

        let size_spec =
            CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: false };
        let mut size_calls = 0;
        let size = FfiBackend::single_call_bytes_exact(
            &size_spec,
            |output, output_len: *mut cryptoki_sys::CK_ULONG| {
                size_calls += 1;
                assert!(output.is_null());
                assert!(!output_len.is_null());
                unsafe { *output_len = 3 };
                CkRv::OK.0 as cryptoki_sys::CK_RV
            },
        )
        .expect("size result");
        assert_eq!(size_calls, 1);
        assert_eq!(size.returned_len, Some(3));
        assert_eq!(size.value, None);

        let data_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 3, length_pointer_null: false };
        let mut data_calls = 0;
        let data = FfiBackend::single_call_bytes_exact(
            &data_spec,
            |output, output_len: *mut cryptoki_sys::CK_ULONG| {
                data_calls += 1;
                assert!(!output.is_null());
                assert!(!output_len.is_null());
                unsafe {
                    std::ptr::copy_nonoverlapping(b"out".as_ptr(), output, 3);
                    *output_len = 3;
                }
                CkRv::OK.0 as cryptoki_sys::CK_RV
            },
        )
        .expect("data result");
        assert_eq!(data_calls, 1);
        assert_eq!(data.value, Some(SecretBytes::copy_from_slice(b"out")));
    }

    #[test]
    fn absurd_output_capacity_is_arguments_bad_before_native_entry() {
        // F4/D7 (ADR-0010 Limits-(d)): a claimed output capacity above the
        // materialization ceiling is answered CKR_ARGUMENTS_BAD without
        // touching the provider — never CKR_HOST_MEMORY, and never a
        // multi-exabyte allocation attempt.
        for buffer_len in [MAX_OUTPUT_BUFFER_BYTES + 1, isize::MAX as u64, u64::MAX] {
            let spec =
                CkOutputBufferSpec { buffer_present: true, buffer_len, length_pointer_null: false };
            let mut calls = 0;
            let err = FfiBackend::single_call_bytes_exact(
                &spec,
                |_: *mut cryptoki_sys::CK_BYTE, _: *mut cryptoki_sys::CK_ULONG| {
                    calls += 1;
                    CkRv::OK.0 as cryptoki_sys::CK_RV
                },
            )
            .unwrap_err();
            assert_eq!(err, CkRv::ARGUMENTS_BAD, "buffer_len = {buffer_len:#x}");
            assert_eq!(calls, 0, "provider must not be entered for {buffer_len:#x}");
        }
    }

    #[test]
    fn null_output_length_parameter_helper_preserves_provider_parameter_output() {
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true };
        let parameter_spec = CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: 3,
            value: Some(vec![1, 2, 3].into()),
        };
        let mut calls = 0;

        let (output, parameter) = parameter_spec
            .value
            .as_ref()
            .unwrap()
            .expose(|raw| {
                FfiBackend::single_call_parameter_output_exact(
                    &output_spec,
                    raw,
                    &parameter_spec,
                    |parameter,
                     parameter_len,
                     main_output,
                     main_output_len: *mut cryptoki_sys::CK_ULONG| {
                        calls += 1;
                        assert!(!parameter.is_null());
                        assert_eq!(parameter_len, 3);
                        assert!(!main_output.is_null());
                        assert!(main_output_len.is_null());
                        unsafe { *parameter.add(1) = 0xA5 };
                        CkRv::OK.0 as cryptoki_sys::CK_RV
                    },
                )
            })
            .expect("provider result and parameter output");

        assert_eq!(calls, 1);
        assert_eq!(output.ck_rv, CkRv::OK);
        assert_eq!(output.returned_len, None);
        assert_eq!(output.value, None);
        assert_eq!(parameter.ck_rv, CkRv::OK);
        assert_eq!(parameter.returned_len, 3);
        assert_eq!(parameter.value, Some(SecretBytes::new(vec![1, 0xA5, 3])));
    }

    #[test]
    fn null_output_length_parameter_helper_preserves_buffer_too_small_and_parameter_output() {
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true };
        let parameter_spec = CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: 3,
            value: Some(vec![1, 2, 3].into()),
        };
        let mut calls = 0;

        let (output, parameter) = parameter_spec
            .value
            .as_ref()
            .unwrap()
            .expose(|raw| {
                FfiBackend::single_call_parameter_output_exact(
                    &output_spec,
                    raw,
                    &parameter_spec,
                    |parameter, _, _, output_len: *mut cryptoki_sys::CK_ULONG| {
                        calls += 1;
                        assert!(output_len.is_null());
                        unsafe { *parameter.add(1) = 0xA5 };
                        CkRv::BUFFER_TOO_SMALL.0 as cryptoki_sys::CK_RV
                    },
                )
            })
            .expect("provider result and parameter output");

        assert_eq!(calls, 1);
        assert_eq!(
            output,
            pkcs11_proxy_ng_types::CkOutputBufferResult {
                ck_rv: CkRv::BUFFER_TOO_SMALL,
                returned_len: None,
                value: None,
            },
        );
        assert_eq!(parameter.ck_rv, CkRv::BUFFER_TOO_SMALL);
        assert_eq!(parameter.returned_len, 3);
        assert_eq!(parameter.value, Some(SecretBytes::new(vec![1, 0xA5, 3])));
    }

    #[test]
    fn parameter_exact_preserves_null_positive_envelope() {
        let output_spec =
            CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: false };
        let parameter_spec =
            CkParameterRoundtripSpec { buffer_present: false, buffer_len: 7, value: None };
        let mut calls = 0;

        let (_, result) = FfiBackend::single_call_parameter_output_exact(
            &output_spec,
            &[],
            &parameter_spec,
            |parameter, parameter_len, output, output_len| {
                calls += 1;
                assert!(parameter.is_null());
                assert_eq!(parameter_len, 7);
                assert!(output.is_null());
                unsafe { *output_len = 0 };
                CkRv::OK.0 as cryptoki_sys::CK_RV
            },
        )
        .expect("provider call");

        assert_eq!(calls, 1);
        assert_eq!(result.ck_rv, CkRv::OK);
        assert_eq!(result.returned_len, 7);
        assert_eq!(result.value, None);
    }

    #[test]
    fn parameter_exact_preserves_null_zero_envelope() {
        let output_spec =
            CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: false };
        let parameter_spec =
            CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None };
        let mut calls = 0;

        let (_, result) = FfiBackend::single_call_parameter_output_exact(
            &output_spec,
            &[],
            &parameter_spec,
            |parameter, parameter_len, _, output_len| {
                calls += 1;
                assert!(parameter.is_null());
                assert_eq!(parameter_len, 0);
                unsafe { *output_len = 0 };
                CkRv::OK.0 as cryptoki_sys::CK_RV
            },
        )
        .expect("provider call");

        assert_eq!(calls, 1);
        assert_eq!(result.returned_len, 0);
        assert_eq!(result.value, None);
    }

    #[test]
    fn parameter_exact_preserves_nonnull_zero_envelope() {
        let output_spec =
            CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: false };
        let parameter_spec =
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 0, value: None };
        let mut calls = 0;

        let (_, result) = FfiBackend::single_call_parameter_output_exact(
            &output_spec,
            &[],
            &parameter_spec,
            |parameter, parameter_len, _, output_len| {
                calls += 1;
                assert!(!parameter.is_null());
                assert_eq!(parameter_len, 0);
                unsafe { *output_len = 0 };
                CkRv::OK.0 as cryptoki_sys::CK_RV
            },
        )
        .expect("provider call");

        assert_eq!(calls, 1);
        assert_eq!(result.returned_len, 0);
        assert_eq!(result.value, Some(SecretBytes::new(Vec::new())));
    }

    #[test]
    fn small_handles_convert_on_all_platforms() {
        assert_eq!(FfiBackend::slot_id(CkSlotId(7)).unwrap(), 7);
        assert_eq!(FfiBackend::session_handle(CkSessionHandle(7)).unwrap(), 7);
        assert_eq!(FfiBackend::object_handle(CkObjectHandle(7)).unwrap(), 7);
    }

    #[test]
    fn oversized_handle_fails_loudly_on_narrow_hosts() {
        // On wide hosts CK_ULONG is 64-bit so every u64 fits (pass-through);
        // on narrow hosts (32-bit CK_ULONG) an unrepresentable handle must
        // fail with FUNCTION_FAILED, never truncate.
        let too_big = u64::from(u32::MAX) + 1;
        if size_of::<cryptoki_sys::CK_ULONG>() >= size_of::<u64>() {
            assert!(FfiBackend::session_handle(CkSessionHandle(too_big)).is_ok());
        } else {
            assert_eq!(
                FfiBackend::session_handle(CkSessionHandle(too_big)),
                Err(CkRv::FUNCTION_FAILED)
            );
            assert_eq!(
                FfiBackend::object_handle(CkObjectHandle(u64::MAX)),
                Err(CkRv::FUNCTION_FAILED)
            );
            assert_eq!(FfiBackend::slot_id(CkSlotId(u64::MAX)), Err(CkRv::FUNCTION_FAILED));
        }
    }
}
