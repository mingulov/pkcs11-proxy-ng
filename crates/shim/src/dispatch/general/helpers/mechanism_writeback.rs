//! Transactional mechanism-output writeback (T06).
//!
//! Daemon-returned mechanism outputs (generated IVs/nonces, negotiated
//! versions, derived handles, PRF bytes) are written back into the
//! caller's parameter structs. Every writeback is split into two phases:
//!
//! - [`prepare_mechanism_output_params`] validates the returned shape,
//!   every length, every `u32` byte, and every `u64` native handle/ULONG
//!   WITHOUT performing any store. Malformed output is
//!   [`CkRv::GENERAL_ERROR`]; no clamping, no truncation, no fabricated
//!   lengths.
//! - [`PreparedMechanismOutput::commit`] performs the validated stores
//!   and is infallible: once prepared, commit cannot fail part-way.
//!
//! Destination fields are captured with unaligned loads (never an
//! aligned `&mut *` into caller memory), input padding is preserved
//! (per-field stores only, never whole-struct copies over uninitialized
//! OUT fields), and a declined output (NULL inner pointer) stays a
//! no-op for that field. The prepared plan owns its validated write
//! data and destination addresses for this call only; dropping it
//! without commit writes nothing and retains no pointer.

use super::{
    MAX_MECHANISM_PARAM_STRUCT_LEN, MAX_SERIALIZABLE_BYTES, MAX_TEMPLATE_COUNT, checked_extent,
    narrow_u32_to_u8, narrow_u64_to_native, rv_err, rv_ok, write_exact_output,
    write_object_handle_output,
};
use cryptoki_sys::{
    CK_BYTE, CK_BYTE_PTR, CK_CCM_WRAP_PARAMS, CK_DERIVED_KEY, CK_GCM_PARAMS, CK_GCM_WRAP_PARAMS,
    CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR, CK_PBE_PARAMS, CK_RV,
    CK_SP800_108_FEEDBACK_KDF_PARAMS, CK_SP800_108_KDF_PARAMS, CK_SSL3_KEY_MAT_OUT,
    CK_SSL3_KEY_MAT_PARAMS, CK_SSL3_MASTER_KEY_DERIVE_PARAMS, CK_TLS_PRF_PARAMS,
    CK_TLS12_MASTER_KEY_DERIVE_PARAMS, CK_ULONG, CK_ULONG_PTR, CK_VERSION, CK_VOID_PTR,
    CK_WTLS_KEY_MAT_OUT, CK_WTLS_KEY_MAT_PARAMS, CK_WTLS_MASTER_KEY_DERIVE_PARAMS,
    CK_WTLS_PRF_PARAMS,
};
use pkcs11_proxy_ng_types::{
    CkMechanismParams, CkObjectHandle, CkOutputBufferResult, CkOutputBufferSpec, CkResult, CkRv,
};

/// One validated caller-memory store.
enum MechanismOutWrite {
    Bytes { dest: *mut u8, data: Vec<u8> },
    Ulong { dest: *mut CK_ULONG, value: CK_ULONG },
    Byte { dest: *mut CK_BYTE, value: CK_BYTE },
    Handle { dest: *mut CK_OBJECT_HANDLE, value: CK_OBJECT_HANDLE },
}

/// Validated mechanism-output plan: all-or-nothing caller-memory stores.
///
/// Produced by [`prepare_mechanism_output_params`]; [`commit`](Self::commit)
/// performs the stores infallibly. Dropping without commit writes nothing.
pub(crate) struct PreparedMechanismOutput {
    writes: Vec<MechanismOutWrite>,
}

impl PreparedMechanismOutput {
    fn empty() -> Self {
        Self { writes: Vec::new() }
    }

    /// Perform the validated stores. Infallible: every destination,
    /// length, and value was validated during preparation.
    ///
    /// # Safety
    ///
    /// The caller destinations captured during preparation must still be
    /// valid and writable for the validated extents. Commit promptly on
    /// the same thread; the plan must not cross await points, thread
    /// boundaries, or calls that release/reallocate caller memory.
    pub(crate) unsafe fn commit(self) {
        for write in self.writes {
            match write {
                MechanismOutWrite::Bytes { dest, data } => {
                    if !data.is_empty() {
                        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), dest, data.len()) };
                    }
                }
                MechanismOutWrite::Ulong { dest, value } => unsafe {
                    dest.write_unaligned(value);
                },
                MechanismOutWrite::Byte { dest, value } => unsafe {
                    dest.write_unaligned(value);
                },
                MechanismOutWrite::Handle { dest, value } => unsafe {
                    dest.write_unaligned(value);
                },
            }
        }
    }
}

/// Outer shape gate: NULL params or a short length is malformed output
/// state (GENERAL_ERROR), never a silent skip — the input parse already
/// required this shape, so a mismatch means the daemon lied about the
/// shape or the caller mutated the struct mid-call.
fn shape_gate(p_parameter: CK_VOID_PTR, param_len: CK_ULONG, expect: usize) -> CkResult<*mut u8> {
    if p_parameter.is_null() || param_len < expect as CK_ULONG {
        return Err(CkRv::GENERAL_ERROR);
    }
    // Wrap check before any field load: a base near the top of the
    // address space must not wrap into a readable-looking address.
    checked_extent(p_parameter as usize, expect as u64, 1, MAX_MECHANISM_PARAM_STRUCT_LEN)
        .map_err(|_| CkRv::GENERAL_ERROR)?;
    Ok(p_parameter as *mut u8)
}

/// Validate one scalar destination cell (wrap/isize arithmetic only; the
/// FFI readability contract covers mapping, as on the read side).
fn checked_scalar<T>(dest: *const T) -> CkResult<()> {
    // Explicit NULL rejection: a NULL base with a tiny extent would pass
    // the wrap arithmetic below, so never rely on it alone.
    if dest.is_null() {
        return Err(CkRv::GENERAL_ERROR);
    }
    checked_extent(dest as usize, 1, std::mem::size_of::<T>(), MAX_MECHANISM_PARAM_STRUCT_LEN)
        .map(|_| ())
        .map_err(|_| CkRv::GENERAL_ERROR)
}

/// Plan one caller-buffer copy. The daemon must not exceed the caller
/// capacity (truncating generated crypto output is corruption, not
/// robustness) nor the transport bound.
fn plan_byte_copy(dest: *mut u8, data: Vec<u8>, capacity: usize) -> CkResult<MechanismOutWrite> {
    // NULL destinations are skipped at arm level; fail closed here so a
    // missed check can never plan a NULL store.
    if dest.is_null() || data.len() > capacity || data.len() > MAX_SERIALIZABLE_BYTES {
        return Err(CkRv::GENERAL_ERROR);
    }
    checked_extent(dest as usize, data.len() as u64, 1, capacity)
        .map_err(|_| CkRv::GENERAL_ERROR)?;
    Ok(MechanismOutWrite::Bytes { dest, data })
}

fn plan_ulong(dest: *mut CK_ULONG, value: u64) -> CkResult<MechanismOutWrite> {
    checked_scalar(dest)?;
    Ok(MechanismOutWrite::Ulong { dest, value: narrow_u64_to_native(value)? })
}

fn plan_byte(dest: *mut CK_BYTE, value: u32) -> CkResult<MechanismOutWrite> {
    checked_scalar(dest)?;
    Ok(MechanismOutWrite::Byte {
        dest,
        value: narrow_u32_to_u8(value).map_err(|_| CkRv::GENERAL_ERROR)?,
    })
}

fn plan_handle(dest: *mut CK_OBJECT_HANDLE, handle: CkObjectHandle) -> CkResult<MechanismOutWrite> {
    checked_scalar(dest)?;
    Ok(MechanismOutWrite::Handle { dest, value: narrow_u64_to_native(handle.0)? })
}

/// Caller IV capacity: an explicit length wins, else the bit length
/// rounded up (T03 rule, with checked narrowing for narrow hosts).
fn iv_capacity(ul_len: CK_ULONG, ul_bits: CK_ULONG) -> CkResult<usize> {
    if ul_len > 0 {
        usize::try_from(ul_len).map_err(|_| CkRv::GENERAL_ERROR)
    } else {
        let bytes = u64::from(ul_bits).saturating_add(7) / 8;
        usize::try_from(bytes).map_err(|_| CkRv::GENERAL_ERROR)
    }
}

fn prepare_gcm(
    p_parameter: *mut u8,
    param_len: CK_ULONG,
    out: &pkcs11_proxy_ng_types::GcmParams,
) -> CkResult<Vec<MechanismOutWrite>> {
    shape_gate(p_parameter as CK_VOID_PTR, param_len, std::mem::size_of::<CK_GCM_PARAMS>())?;
    let gcm = p_parameter as *mut CK_GCM_PARAMS;
    let p_iv = unsafe { std::ptr::addr_of!((*gcm).pIv).read_unaligned() };
    let ul_iv_len = unsafe { std::ptr::addr_of!((*gcm).ulIvLen).read_unaligned() };
    let ul_iv_bits = unsafe { std::ptr::addr_of!((*gcm).ulIvBits).read_unaligned() };
    let mut writes = Vec::new();
    if !p_iv.is_null() {
        let capacity = iv_capacity(ul_iv_len, ul_iv_bits)?;
        writes.push(plan_byte_copy(p_iv, out.iv.clone(), capacity)?);
        let dest_len = unsafe { std::ptr::addr_of_mut!((*gcm).ulIvLen) };
        writes.push(plan_ulong(dest_len, out.iv.len() as u64)?);
    }
    let dest_bits = unsafe { std::ptr::addr_of_mut!((*gcm).ulIvBits) };
    writes.push(plan_ulong(dest_bits, out.iv_bits)?);
    let dest_tag = unsafe { std::ptr::addr_of_mut!((*gcm).ulTagBits) };
    writes.push(plan_ulong(dest_tag, out.tag_bits)?);
    Ok(writes)
}

fn prepare_gcm_wrap(
    p_parameter: *mut u8,
    param_len: CK_ULONG,
    out: &pkcs11_proxy_ng_types::GcmWrapParams,
) -> CkResult<Vec<MechanismOutWrite>> {
    shape_gate(p_parameter as CK_VOID_PTR, param_len, std::mem::size_of::<CK_GCM_WRAP_PARAMS>())?;
    let wrap = p_parameter as *mut CK_GCM_WRAP_PARAMS;
    let p_iv = unsafe { std::ptr::addr_of!((*wrap).pIv).read_unaligned() };
    let ul_iv_len = unsafe { std::ptr::addr_of!((*wrap).ulIvLen).read_unaligned() };
    let mut writes = Vec::new();
    if !p_iv.is_null() {
        let capacity = usize::try_from(ul_iv_len).map_err(|_| CkRv::GENERAL_ERROR)?;
        writes.push(plan_byte_copy(p_iv, out.iv.clone(), capacity)?);
        let dest_len = unsafe { std::ptr::addr_of_mut!((*wrap).ulIvLen) };
        writes.push(plan_ulong(dest_len, out.iv.len() as u64)?);
    }
    let dest_fixed = unsafe { std::ptr::addr_of_mut!((*wrap).ulIvFixedBits) };
    writes.push(plan_ulong(dest_fixed, out.iv_fixed_bits)?);
    // CK_GENERATOR_FUNCTION is CK_ULONG-width; narrow then store.
    let dest_gen = unsafe { std::ptr::addr_of_mut!((*wrap).ivGenerator) };
    writes.push(plan_ulong(dest_gen as *mut CK_ULONG, out.iv_generator.0)?);
    let dest_tag = unsafe { std::ptr::addr_of_mut!((*wrap).ulTagBits) };
    writes.push(plan_ulong(dest_tag, out.tag_bits)?);
    Ok(writes)
}

fn prepare_ccm_wrap(
    p_parameter: *mut u8,
    param_len: CK_ULONG,
    out: &pkcs11_proxy_ng_types::CcmWrapParams,
) -> CkResult<Vec<MechanismOutWrite>> {
    shape_gate(p_parameter as CK_VOID_PTR, param_len, std::mem::size_of::<CK_CCM_WRAP_PARAMS>())?;
    let wrap = p_parameter as *mut CK_CCM_WRAP_PARAMS;
    let p_nonce = unsafe { std::ptr::addr_of!((*wrap).pNonce).read_unaligned() };
    let ul_nonce_len = unsafe { std::ptr::addr_of!((*wrap).ulNonceLen).read_unaligned() };
    let mut writes = Vec::new();
    if !p_nonce.is_null() {
        let capacity = usize::try_from(ul_nonce_len).map_err(|_| CkRv::GENERAL_ERROR)?;
        writes.push(plan_byte_copy(p_nonce, out.nonce.clone(), capacity)?);
        let dest_len = unsafe { std::ptr::addr_of_mut!((*wrap).ulNonceLen) };
        writes.push(plan_ulong(dest_len, out.nonce.len() as u64)?);
    }
    let dest_fixed = unsafe { std::ptr::addr_of_mut!((*wrap).ulNonceFixedBits) };
    writes.push(plan_ulong(dest_fixed, out.nonce_fixed_bits)?);
    let dest_gen = unsafe { std::ptr::addr_of_mut!((*wrap).nonceGenerator) };
    writes.push(plan_ulong(dest_gen as *mut CK_ULONG, out.nonce_generator.0)?);
    let dest_mac = unsafe { std::ptr::addr_of_mut!((*wrap).ulMACLen) };
    writes.push(plan_ulong(dest_mac, out.mac_len)?);
    Ok(writes)
}

/// Negotiated (major, minor) version bytes behind a `pVersion` cell.
/// A NULL cell declines the output; otherwise both bytes are narrowed
/// and planned (the single `CK_VERSION` extent check covers both).
fn plan_version_bytes(
    p_version: *mut CK_VERSION,
    major: u32,
    minor: u32,
) -> CkResult<Vec<MechanismOutWrite>> {
    if p_version.is_null() {
        return Ok(Vec::new());
    }
    Ok(vec![
        plan_byte(unsafe { &raw mut (*p_version).major }, major)?,
        plan_byte(unsafe { &raw mut (*p_version).minor }, minor)?,
    ])
}

fn prepare_tls12_master(
    p_parameter: *mut u8,
    param_len: CK_ULONG,
    out: &pkcs11_proxy_ng_types::Tls12MasterKeyDeriveParams,
) -> CkResult<Vec<MechanismOutWrite>> {
    shape_gate(
        p_parameter as CK_VOID_PTR,
        param_len,
        std::mem::size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>(),
    )?;
    let params = p_parameter as *mut CK_TLS12_MASTER_KEY_DERIVE_PARAMS;
    let p_version = unsafe { std::ptr::addr_of!((*params).pVersion).read_unaligned() };
    plan_version_bytes(p_version, out.version_major, out.version_minor)
}

fn prepare_ssl3_master(
    p_parameter: *mut u8,
    param_len: CK_ULONG,
    out: &pkcs11_proxy_ng_types::Ssl3MasterKeyDeriveParams,
) -> CkResult<Vec<MechanismOutWrite>> {
    shape_gate(
        p_parameter as CK_VOID_PTR,
        param_len,
        std::mem::size_of::<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>(),
    )?;
    let params = p_parameter as *mut CK_SSL3_MASTER_KEY_DERIVE_PARAMS;
    let p_version = unsafe { std::ptr::addr_of!((*params).pVersion).read_unaligned() };
    plan_version_bytes(p_version, out.version_major, out.version_minor)
}

fn prepare_wtls_master(
    p_parameter: *mut u8,
    param_len: CK_ULONG,
    out: &pkcs11_proxy_ng_types::WtlsMasterKeyDeriveParams,
) -> CkResult<Vec<MechanismOutWrite>> {
    shape_gate(
        p_parameter as CK_VOID_PTR,
        param_len,
        std::mem::size_of::<CK_WTLS_MASTER_KEY_DERIVE_PARAMS>(),
    )?;
    // WTLS carries a single version byte behind pVersion.
    let params = p_parameter as *mut CK_WTLS_MASTER_KEY_DERIVE_PARAMS;
    let p_version = unsafe { std::ptr::addr_of!((*params).pVersion).read_unaligned() };
    if p_version.is_null() {
        return Ok(Vec::new());
    }
    Ok(vec![plan_byte(p_version, out.version)?])
}

/// PRF output bytes behind a (pOutput, pulOutputLen) cell pair. A NULL
/// cell on either side declines the output (preserved skip); otherwise
/// the daemon output must fit the caller capacity.
fn plan_prf_output(
    p_output: *mut CK_BYTE,
    pul_output_len: *mut CK_ULONG,
    output: &[u8],
) -> CkResult<Vec<MechanismOutWrite>> {
    if p_output.is_null() || pul_output_len.is_null() {
        return Ok(Vec::new());
    }
    let capacity = unsafe { pul_output_len.read_unaligned() };
    let capacity =
        usize::try_from(capacity).map_err(|_| CkRv::GENERAL_ERROR)?.min(MAX_SERIALIZABLE_BYTES);
    Ok(vec![
        plan_byte_copy(p_output, output.to_vec(), capacity)?,
        plan_ulong(pul_output_len, output.len() as u64)?,
    ])
}

fn prepare_tls_prf(
    p_parameter: *mut u8,
    param_len: CK_ULONG,
    out: &pkcs11_proxy_ng_types::TlsPrfParams,
) -> CkResult<Vec<MechanismOutWrite>> {
    shape_gate(p_parameter as CK_VOID_PTR, param_len, std::mem::size_of::<CK_TLS_PRF_PARAMS>())?;
    let prf = p_parameter as *mut CK_TLS_PRF_PARAMS;
    let p_output = unsafe { std::ptr::addr_of!((*prf).pOutput).read_unaligned() };
    let pul_output_len = unsafe { std::ptr::addr_of!((*prf).pulOutputLen).read_unaligned() };
    let output = out.output.expose(|bytes| bytes.to_vec());
    plan_prf_output(p_output, pul_output_len, &output)
}

fn prepare_wtls_prf(
    p_parameter: *mut u8,
    param_len: CK_ULONG,
    out: &pkcs11_proxy_ng_types::WtlsPrfParams,
) -> CkResult<Vec<MechanismOutWrite>> {
    shape_gate(p_parameter as CK_VOID_PTR, param_len, std::mem::size_of::<CK_WTLS_PRF_PARAMS>())?;
    let prf = p_parameter as *mut CK_WTLS_PRF_PARAMS;
    let p_output = unsafe { std::ptr::addr_of!((*prf).pOutput).read_unaligned() };
    let pul_output_len = unsafe { std::ptr::addr_of!((*prf).pulOutputLen).read_unaligned() };
    let output = out.output.expose(|bytes| bytes.to_vec());
    plan_prf_output(p_output, pul_output_len, &output)
}

fn prepare_pbe(
    p_parameter: *mut u8,
    param_len: CK_ULONG,
    out: &pkcs11_proxy_ng_types::PbeParams,
) -> CkResult<Vec<MechanismOutWrite>> {
    shape_gate(p_parameter as CK_VOID_PTR, param_len, std::mem::size_of::<CK_PBE_PARAMS>())?;
    let pbe = p_parameter as *mut CK_PBE_PARAMS;
    let p_iv = unsafe { std::ptr::addr_of!((*pbe).pInitVector).read_unaligned() };
    let iv = out.init_vector.expose(|bytes| bytes.to_vec());
    if p_iv.is_null() || iv.is_empty() {
        return Ok(Vec::new());
    }
    // The DES2/3 IV is exactly 8 bytes; a longer daemon IV is malformed,
    // not something to truncate.
    Ok(vec![plan_byte_copy(p_iv, iv, 8)?])
}

fn prepare_wtls_keymat(
    p_parameter: *mut u8,
    param_len: CK_ULONG,
    out: &pkcs11_proxy_ng_types::WtlsKeyMatParams,
) -> CkResult<Vec<MechanismOutWrite>> {
    shape_gate(
        p_parameter as CK_VOID_PTR,
        param_len,
        std::mem::size_of::<CK_WTLS_KEY_MAT_PARAMS>(),
    )?;
    let params = p_parameter as *mut CK_WTLS_KEY_MAT_PARAMS;
    let p_out = unsafe { std::ptr::addr_of!((*params).pReturnedKeyMaterial).read_unaligned() };
    if p_out.is_null() {
        return Ok(Vec::new());
    }
    let ul_iv_bits = unsafe { std::ptr::addr_of!((*params).ulIVSizeInBits).read_unaligned() };
    let output = p_out as *mut CK_WTLS_KEY_MAT_OUT;
    let mut writes = Vec::new();
    let dest_mac = unsafe { std::ptr::addr_of_mut!((*output).hMacSecret) };
    writes.push(plan_handle(dest_mac, out.mac_secret_handle)?);
    let dest_key = unsafe { std::ptr::addr_of_mut!((*output).hKey) };
    writes.push(plan_handle(dest_key, out.key_handle)?);
    let p_iv = unsafe { std::ptr::addr_of!((*output).pIV).read_unaligned() };
    if !p_iv.is_null() {
        let capacity = iv_capacity(0, ul_iv_bits)?;
        let iv = out.iv.expose(|bytes| bytes.to_vec());
        writes.push(plan_byte_copy(p_iv, iv, capacity)?);
    }
    Ok(writes)
}

fn prepare_ssl3_keymat(
    p_parameter: *mut u8,
    param_len: CK_ULONG,
    out: &pkcs11_proxy_ng_types::Ssl3KeyMatParams,
) -> CkResult<Vec<MechanismOutWrite>> {
    shape_gate(
        p_parameter as CK_VOID_PTR,
        param_len,
        std::mem::size_of::<CK_SSL3_KEY_MAT_PARAMS>(),
    )?;
    let params = p_parameter as *mut CK_SSL3_KEY_MAT_PARAMS;
    let p_out = unsafe { std::ptr::addr_of!((*params).pReturnedKeyMaterial).read_unaligned() };
    if p_out.is_null() {
        return Ok(Vec::new());
    }
    let ul_iv_bits = unsafe { std::ptr::addr_of!((*params).ulIVSizeInBits).read_unaligned() };
    let output = p_out as *mut CK_SSL3_KEY_MAT_OUT;
    let mut writes = Vec::new();
    let dest_client_mac = unsafe { std::ptr::addr_of_mut!((*output).hClientMacSecret) };
    writes.push(plan_handle(dest_client_mac, out.client_mac_secret_handle)?);
    let dest_server_mac = unsafe { std::ptr::addr_of_mut!((*output).hServerMacSecret) };
    writes.push(plan_handle(dest_server_mac, out.server_mac_secret_handle)?);
    let dest_client_key = unsafe { std::ptr::addr_of_mut!((*output).hClientKey) };
    writes.push(plan_handle(dest_client_key, out.client_key_handle)?);
    let dest_server_key = unsafe { std::ptr::addr_of_mut!((*output).hServerKey) };
    writes.push(plan_handle(dest_server_key, out.server_key_handle)?);
    let capacity = iv_capacity(0, ul_iv_bits)?;
    let p_iv_client = unsafe { std::ptr::addr_of!((*output).pIVClient).read_unaligned() };
    if !p_iv_client.is_null() {
        let iv = out.client_iv.expose(|bytes| bytes.to_vec());
        writes.push(plan_byte_copy(p_iv_client, iv, capacity)?);
    }
    let p_iv_server = unsafe { std::ptr::addr_of!((*output).pIVServer).read_unaligned() };
    if !p_iv_server.is_null() {
        let iv = out.server_iv.expose(|bytes| bytes.to_vec());
        writes.push(plan_byte_copy(p_iv_server, iv, capacity)?);
    }
    Ok(writes)
}

/// SP800-108 derived-handle writeback behind a (count, base) cell pair.
/// Mirrors the read-side count discipline: an explicit entry cap plus a
/// checked byte extent, then per-entry unaligned `phKey` loads (never an
/// aligned slice over caller memory). A NULL `phKey` declines that entry.
/// More daemon keys than caller slots is malformed output.
fn plan_sp800_handles(
    base: *mut CK_DERIVED_KEY,
    ul_count: CK_ULONG,
    daemon_keys: &[pkcs11_proxy_ng_types::Sp800108DerivedKey],
) -> CkResult<Vec<MechanismOutWrite>> {
    if base.is_null() || ul_count == 0 {
        return Ok(Vec::new());
    }
    if ul_count as usize > MAX_TEMPLATE_COUNT {
        return Err(CkRv::GENERAL_ERROR);
    }
    checked_extent(
        base as usize,
        ul_count as u64,
        std::mem::size_of::<CK_DERIVED_KEY>(),
        MAX_TEMPLATE_COUNT.saturating_mul(std::mem::size_of::<CK_DERIVED_KEY>()),
    )
    .map_err(|_| CkRv::GENERAL_ERROR)?;
    let count = ul_count as usize;
    if daemon_keys.len() > count {
        return Err(CkRv::GENERAL_ERROR);
    }
    let mut writes = Vec::new();
    for (index, key) in daemon_keys.iter().enumerate() {
        // Safety: index < daemon_keys.len() <= count, and the checked
        // extent above proves base..base+count*stride does not wrap.
        let entry = unsafe { base.add(index) };
        let ph_key = unsafe { std::ptr::addr_of!((*entry).phKey).read_unaligned() };
        if ph_key.is_null() {
            continue;
        }
        writes.push(plan_handle(ph_key, key.key_handle)?);
    }
    Ok(writes)
}

fn prepare_sp800_kdf(
    p_parameter: *mut u8,
    param_len: CK_ULONG,
    out: &pkcs11_proxy_ng_types::Sp800108KdfParams,
) -> CkResult<Vec<MechanismOutWrite>> {
    shape_gate(
        p_parameter as CK_VOID_PTR,
        param_len,
        std::mem::size_of::<CK_SP800_108_KDF_PARAMS>(),
    )?;
    let params = p_parameter as *mut CK_SP800_108_KDF_PARAMS;
    let base = unsafe { std::ptr::addr_of!((*params).pAdditionalDerivedKeys).read_unaligned() };
    let count = unsafe { std::ptr::addr_of!((*params).ulAdditionalDerivedKeys).read_unaligned() };
    plan_sp800_handles(base, count, &out.additional_derived_keys)
}

fn prepare_sp800_feedback_kdf(
    p_parameter: *mut u8,
    param_len: CK_ULONG,
    out: &pkcs11_proxy_ng_types::Sp800108FeedbackKdfParams,
) -> CkResult<Vec<MechanismOutWrite>> {
    shape_gate(
        p_parameter as CK_VOID_PTR,
        param_len,
        std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>(),
    )?;
    let params = p_parameter as *mut CK_SP800_108_FEEDBACK_KDF_PARAMS;
    let base = unsafe { std::ptr::addr_of!((*params).pAdditionalDerivedKeys).read_unaligned() };
    let count = unsafe { std::ptr::addr_of!((*params).ulAdditionalDerivedKeys).read_unaligned() };
    plan_sp800_handles(base, count, &out.additional_derived_keys)
}

/// Validate daemon mechanism outputs against the caller's parameter
/// struct WITHOUT writing anything.
///
/// A NULL mechanism, or a variant without output params, prepares an
/// empty (no-op) plan. Malformed output — shape mismatch, overlong
/// daemon bytes, unrepresentable bytes/handles/lengths — is
/// [`CkRv::GENERAL_ERROR`] before any store.
///
/// # Safety
///
/// `p_mechanism` must be NULL or point to a readable `CK_MECHANISM`
/// whose `pParameter` (when the shape writes) points to a struct of at
/// least the shape's size. Destinations captured into the plan must be
/// writable for the validated extents (alignment not required).
pub(crate) unsafe fn prepare_mechanism_output_params(
    p_mechanism: CK_MECHANISM_PTR,
    params: &CkMechanismParams,
) -> CkResult<PreparedMechanismOutput> {
    if p_mechanism.is_null() {
        return Ok(PreparedMechanismOutput::empty());
    }
    let p_parameter = unsafe { std::ptr::addr_of!((*p_mechanism).pParameter).read_unaligned() };
    let param_len = unsafe { std::ptr::addr_of!((*p_mechanism).ulParameterLen).read_unaligned() };
    let base = p_parameter as *mut u8;
    let writes = match params {
        CkMechanismParams::Gcm(out) => prepare_gcm(base, param_len, out)?,
        CkMechanismParams::GcmWrap(out) => prepare_gcm_wrap(base, param_len, out)?,
        CkMechanismParams::CcmWrap(out) => prepare_ccm_wrap(base, param_len, out)?,
        CkMechanismParams::Tls12MasterKeyDerive(out) => prepare_tls12_master(base, param_len, out)?,
        CkMechanismParams::Ssl3MasterKeyDerive(out) => prepare_ssl3_master(base, param_len, out)?,
        CkMechanismParams::WtlsMasterKeyDerive(out) => prepare_wtls_master(base, param_len, out)?,
        CkMechanismParams::TlsPrf(out) => prepare_tls_prf(base, param_len, out)?,
        CkMechanismParams::WtlsPrf(out) => prepare_wtls_prf(base, param_len, out)?,
        CkMechanismParams::WtlsKeyMat(out) => prepare_wtls_keymat(base, param_len, out)?,
        CkMechanismParams::Ssl3KeyMat(out) => prepare_ssl3_keymat(base, param_len, out)?,
        CkMechanismParams::Sp800108Kdf(out) => prepare_sp800_kdf(base, param_len, out)?,
        CkMechanismParams::Sp800108FeedbackKdf(out) => {
            prepare_sp800_feedback_kdf(base, param_len, out)?
        }
        CkMechanismParams::Pbe(out) => prepare_pbe(base, param_len, out)?,
        _ => Vec::new(),
    };
    Ok(PreparedMechanismOutput { writes })
}

/// `C_WrapKey` post-RPC output orchestration: the mechanism plan is
/// prepared BEFORE the byte plan writes, so malformed mechanism output
/// preserves wrap bytes/length (T06). The gate preserves size-query
/// no-writeback and the missing-length-pointer rule; a non-OK byte
/// result drops the mechanism plan uncommitted.
///
/// # Safety
///
/// Same contract as [`prepare_mechanism_output_params`] plus
/// [`write_exact_output`]: the spec must describe `p_wrapped_key` /
/// `pul_wrapped_key_len` as captured before the RPC.
pub(crate) unsafe fn wrap_key_post_rpc(
    spec: &CkOutputBufferSpec,
    result: &CkOutputBufferResult,
    mechanism_out: Option<&CkMechanismParams>,
    p_mechanism: CK_MECHANISM_PTR,
    p_wrapped_key: CK_BYTE_PTR,
    pul_wrapped_key_len: CK_ULONG_PTR,
) -> CK_RV {
    let mech_plan = match mechanism_out {
        Some(params) if spec.buffer_present || spec.length_pointer_null => {
            match unsafe { prepare_mechanism_output_params(p_mechanism, params) } {
                Ok(plan) => Some(plan),
                Err(_) => return rv_err(CkRv::GENERAL_ERROR),
            }
        }
        _ => None,
    };
    let rv = unsafe { write_exact_output(spec, result, p_wrapped_key, pul_wrapped_key_len) };
    if rv == rv_ok()
        && let Some(plan) = mech_plan
    {
        unsafe { plan.commit() };
    }
    rv
}

/// `C_DeriveKey` post-RPC output orchestration: the mechanism plan is
/// prepared before any store, and the required handle must exist before
/// the mechanism plan commits, so a malformed main response publishes
/// no partial output (T06). On a provider-error path the provider RV is
/// never masked: validated mechanism outputs still commit (preserved
/// behavior), malformed ones are dropped. A NULL `ph_key` keeps its
/// historical meaning (key-material mechanisms report handles via the
/// params) and skips only the single-handle store.
///
/// # Safety
///
/// Same contract as [`prepare_mechanism_output_params`]; when `ph_key`
/// is non-null it must be writable for one handle.
pub(crate) unsafe fn derive_key_post_rpc(
    rv: CkRv,
    key_handle: Option<CkObjectHandle>,
    mechanism_out: Option<&CkMechanismParams>,
    p_mechanism: CK_MECHANISM_PTR,
    ph_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let mech_plan = match mechanism_out {
        Some(params) => match unsafe { prepare_mechanism_output_params(p_mechanism, params) } {
            Ok(plan) => Some(plan),
            Err(_) => {
                if rv.is_ok() {
                    return rv_err(CkRv::GENERAL_ERROR);
                }
                None
            }
        },
        None => None,
    };
    if !rv.is_ok() {
        if let Some(plan) = mech_plan {
            unsafe { plan.commit() };
        }
        return rv_err(rv);
    }
    if ph_key.is_null() {
        if let Some(plan) = mech_plan {
            unsafe { plan.commit() };
        }
        return rv_ok();
    }
    let Some(handle) = key_handle else {
        return rv_err(CkRv::GENERAL_ERROR);
    };
    // Validate the handle before the mechanism plan commits so a narrow
    // unrepresentable handle publishes no partial mechanism output.
    if narrow_u64_to_native::<CK_OBJECT_HANDLE>(handle.0).is_err() {
        return rv_err(CkRv::GENERAL_ERROR);
    }
    if let Some(plan) = mech_plan {
        unsafe { plan.commit() };
    }
    match unsafe { write_object_handle_output(handle, ph_key) } {
        Ok(()) => rv_ok(),
        Err(err) => rv_err(err),
    }
}

/// `C_GenerateKey` post-RPC output orchestration: the handle is
/// validated and the mechanism plan prepared before either writes, so
/// malformed output on either channel writes nothing (T06).
///
/// # Safety
///
/// Same contract as [`prepare_mechanism_output_params`]: `ph_key` must
/// be non-null and writable for one handle.
pub(crate) unsafe fn generate_key_post_rpc(
    handle: CkObjectHandle,
    mechanism_out: Option<&CkMechanismParams>,
    p_mechanism: CK_MECHANISM_PTR,
    ph_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    if narrow_u64_to_native::<CK_OBJECT_HANDLE>(handle.0).is_err() {
        return rv_err(CkRv::GENERAL_ERROR);
    }
    let mech_plan = match mechanism_out {
        Some(params) => match unsafe { prepare_mechanism_output_params(p_mechanism, params) } {
            Ok(plan) => Some(plan),
            Err(_) => return rv_err(CkRv::GENERAL_ERROR),
        },
        None => None,
    };
    if let Some(plan) = mech_plan {
        unsafe { plan.commit() };
    }
    match unsafe { write_object_handle_output(handle, ph_key) } {
        Ok(()) => rv_ok(),
        Err(err) => rv_err(err),
    }
}
