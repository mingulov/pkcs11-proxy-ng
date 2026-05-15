use super::{FfiBackend, ffi_conversion::mechanism_to_ffi};
use pkcs11_proxy_ng_types::*;

/// Maximum output buffer the daemon will allocate for a single PKCS#11 call.
/// Requests claiming larger buffers are capped to this size — no real PKCS#11
/// operation produces output anywhere near 512 MiB.  This prevents OOM/panic
/// when a client sends an absurd `pulOutputLen` (e.g. `isize::MAX + 1`).
pub(super) const MAX_OUTPUT_BUFFER_BYTES: u64 = 512 * 1024 * 1024;

impl FfiBackend {
    #[inline]
    pub(super) const fn slot_id(slot_id: CkSlotId) -> cryptoki_sys::CK_SLOT_ID {
        slot_id.0 as cryptoki_sys::CK_SLOT_ID
    }

    #[inline]
    pub(super) const fn session_handle(
        session: CkSessionHandle,
    ) -> cryptoki_sys::CK_SESSION_HANDLE {
        session.0 as cryptoki_sys::CK_SESSION_HANDLE
    }

    #[inline]
    pub(super) const fn object_handle(object: CkObjectHandle) -> cryptoki_sys::CK_OBJECT_HANDLE {
        object.0 as cryptoki_sys::CK_OBJECT_HANDLE
    }

    #[inline]
    pub(super) const fn ulong_len(len: usize) -> cryptoki_sys::CK_ULONG {
        len as cryptoki_sys::CK_ULONG
    }

    /// Map a cryptoki_sys CK_RV to CkResult.
    #[inline]
    pub(super) fn ck_result(rv: cryptoki_sys::CK_RV) -> CkResult<()> {
        if rv == 0 { Ok(()) } else { Err(CkRv(rv)) }
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

    #[inline]
    pub(super) fn call_unit<T, F>(function: Option<T>, call: F) -> CkResult<()>
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
        if rv == CkRv::BUFFER_TOO_SMALL.0 && (count as usize) > values.len() {
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
    pub(super) fn two_call_bytes<F>(call: F) -> CkResult<Vec<u8>>
    where
        F: FnMut(*mut cryptoki_sys::CK_BYTE, &mut cryptoki_sys::CK_ULONG) -> cryptoki_sys::CK_RV,
    {
        Self::two_call_array(call)
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

    pub(super) fn call_bytes<TFunction, F>(
        function: Option<TFunction>,
        mut call: F,
    ) -> CkResult<Vec<u8>>
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
    ) -> CkResult<Vec<u8>>
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
        Ok(bytes)
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
        Self::ck_result(call(function, &mut ffi_mech.ck_mechanism))
    }

    /// Like `call_unit_with_mechanism` but caches the `FfiMechanism` in
    /// `mech_cache` on success, keyed by session handle. This keeps backing
    /// memory (e.g. OAEP pSourceData) alive until the next Init call or
    /// session close, for backends that store mechanism pointers.
    pub(super) fn call_init_with_mechanism<TFunction, F>(
        &self,
        session: CkSessionHandle,
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
        Self::ck_result(call(function, &mut ffi_mech.ck_mechanism))?;
        // Keep the mechanism's backing memory alive for the session.
        if let Ok(mut cache) = self.mech_cache.lock() {
            cache.insert(session.0, ffi_mech);
        }
        Ok(())
    }

    pub(super) fn call_init_with_mechanism_output<TFunction, F>(
        &self,
        session: CkSessionHandle,
        function: Option<TFunction>,
        mechanism: &CkMechanism,
        call: F,
    ) -> CkResult<Option<CkMechanismParams>>
    where
        TFunction: Copy,
        F: FnOnce(TFunction, &mut cryptoki_sys::CK_MECHANISM) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        let mut ffi_mech = mechanism_to_ffi(mechanism)?;
        Self::ck_result(call(function, &mut ffi_mech.ck_mechanism))?;
        let output_params = ffi_mech.output_params();
        // Keep the mechanism's backing memory alive for the session.
        if let Ok(mut cache) = self.mech_cache.lock() {
            cache.insert(session.0, ffi_mech);
        }
        Ok(output_params)
    }

    /// Drop any cached mechanism for the given session (called on session close).
    pub(super) fn drop_mech_cache(&self, session: CkSessionHandle) {
        if let Ok(mut cache) = self.mech_cache.lock() {
            cache.remove(&session.0);
        }
    }

    pub(super) fn cached_mechanism_output_params(
        &self,
        session: CkSessionHandle,
    ) -> Option<CkMechanismParams> {
        self.mech_cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&session.0).and_then(|mechanism| mechanism.output_params()))
    }

    pub(super) fn call_bytes_with_mechanism<TFunction, F>(
        function: Option<TFunction>,
        mechanism: &CkMechanism,
        mut call: F,
    ) -> CkResult<Vec<u8>>
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
            call(function, &mut ffi_mech.ck_mechanism, output, output_len)
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
        Self::object_output(|handle| call(function, &mut ffi_mech.ck_mechanism, handle))
    }

    /// Single FFI call with exact buffer semantics.
    ///
    /// - If `spec.buffer_present` is false, passes NULL to get the required size.
    /// - If `spec.buffer_present` is true, allocates the caller-specified buffer.
    /// - Returns `CkOutputBufferResult` with the exact CK_RV, length, and data.
    pub(super) fn single_call_bytes_exact<F>(
        spec: &CkOutputBufferSpec,
        mut call: F,
    ) -> CkResult<CkOutputBufferResult>
    where
        F: FnMut(*mut cryptoki_sys::CK_BYTE, &mut cryptoki_sys::CK_ULONG) -> cryptoki_sys::CK_RV,
    {
        let mut out_len: cryptoki_sys::CK_ULONG = 0;

        if !spec.buffer_present {
            // Size query: pass NULL buffer
            let rv = call(std::ptr::null_mut(), &mut out_len);
            if rv == CkRv::OK.0 {
                Ok(CkOutputBufferResult {
                    ck_rv: CkRv::OK,
                    returned_len: out_len as u64,
                    value: None,
                })
            } else {
                // Propagate exact CK_RV from backend
                Err(CkRv(rv))
            }
        } else {
            // Data query: allocate caller-specified buffer, capped to prevent
            // OOM/panic from absurd client-supplied lengths.
            let capped_len = spec.buffer_len.min(MAX_OUTPUT_BUFFER_BYTES);
            out_len = capped_len as cryptoki_sys::CK_ULONG;
            let mut buf = vec![0u8; capped_len as usize];
            let rv = call(buf.as_mut_ptr(), &mut out_len);

            if rv == CkRv::OK.0 {
                buf.truncate(out_len as usize);
                Ok(CkOutputBufferResult {
                    ck_rv: CkRv::OK,
                    returned_len: out_len as u64,
                    value: Some(buf),
                })
            } else if rv == CkRv::BUFFER_TOO_SMALL.0 {
                Ok(CkOutputBufferResult {
                    ck_rv: CkRv::BUFFER_TOO_SMALL,
                    returned_len: out_len as u64,
                    value: None,
                })
            } else {
                Err(CkRv(rv))
            }
        }
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
            &mut cryptoki_sys::CK_ULONG,
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
            &mut cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        let function = Self::require_fn(function)?;
        let mut ffi_mech = mechanism_to_ffi(mechanism)?;
        Self::single_call_bytes_exact(spec, |output, output_len| {
            call(function, &mut ffi_mech.ck_mechanism, output, output_len)
        })
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
            &mut cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        // Prepare the parameter buffer for dual input/output use.
        let param_buf_len = if param_out_spec.buffer_present {
            param_out_spec.buffer_len as usize
        } else {
            parameter_input.len()
        };
        let mut param_buf = vec![0u8; param_buf_len];
        let copy_len = parameter_input.len().min(param_buf_len);
        if copy_len > 0 {
            param_buf[..copy_len].copy_from_slice(&parameter_input[..copy_len]);
        }
        let param_ptr =
            if param_buf_len > 0 { param_buf.as_mut_ptr() } else { std::ptr::null_mut() };
        let param_ck_len = param_buf_len as cryptoki_sys::CK_ULONG;

        // Prepare the main output buffer.
        let mut out_len: cryptoki_sys::CK_ULONG = 0;

        if !output_spec.buffer_present {
            // Size query: pass NULL buffer for main output.
            let rv = call(param_ptr, param_ck_len, std::ptr::null_mut(), &mut out_len);
            if rv == CkRv::OK.0 {
                let output_result = CkOutputBufferResult {
                    ck_rv: CkRv::OK,
                    returned_len: out_len as u64,
                    value: None,
                };
                let param_result = CkParameterRoundtripResult {
                    ck_rv: CkRv::OK,
                    returned_len: param_buf_len as u64,
                    value: if param_out_spec.buffer_present { Some(param_buf) } else { None },
                };
                Ok((output_result, param_result))
            } else {
                Err(CkRv(rv))
            }
        } else {
            // Data query: allocate caller-specified buffer, capped to prevent OOM.
            let capped_len = output_spec.buffer_len.min(MAX_OUTPUT_BUFFER_BYTES);
            out_len = capped_len as cryptoki_sys::CK_ULONG;
            let mut buf = vec![0u8; capped_len as usize];
            let rv = call(param_ptr, param_ck_len, buf.as_mut_ptr(), &mut out_len);

            if rv == CkRv::OK.0 {
                buf.truncate(out_len as usize);
                let output_result = CkOutputBufferResult {
                    ck_rv: CkRv::OK,
                    returned_len: out_len as u64,
                    value: Some(buf),
                };
                let param_result = CkParameterRoundtripResult {
                    ck_rv: CkRv::OK,
                    returned_len: param_buf_len as u64,
                    value: if param_out_spec.buffer_present { Some(param_buf) } else { None },
                };
                Ok((output_result, param_result))
            } else if rv == CkRv::BUFFER_TOO_SMALL.0 {
                let output_result = CkOutputBufferResult {
                    ck_rv: CkRv::BUFFER_TOO_SMALL,
                    returned_len: out_len as u64,
                    value: None,
                };
                let param_result = CkParameterRoundtripResult {
                    ck_rv: CkRv::BUFFER_TOO_SMALL,
                    returned_len: param_buf_len as u64,
                    value: None,
                };
                Ok((output_result, param_result))
            } else {
                Err(CkRv(rv))
            }
        }
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
            call(function, &mut ffi_mech.ck_mechanism, first, second)
        })
    }
}
