//! Message-based API (v3.0) parameter structs: read GCM/CCM/
//! Salsa-ChaCha message params from caller memory and write results
//! back (incl. the bits-derived-length wild-read guards).

use pkcs11_proxy_ng_proto::convert::message_effects::ParameterEffectCallMode;
use pkcs11_proxy_ng_proto::convert::message_effects::{MessageEffectContext, MessageEffects};
use pkcs11_proxy_ng_proto::convert::message_params::{
    CcmMessageParams, GcmMessageParams, MessageParameter, MessageParameterShape,
    Salsa20ChaCha20Poly1305MessageParams,
};
use pkcs11_proxy_ng_types::{CkResult, CkRv};

use super::*;

// cryptoki-sys mirrors the platform ABI: LP64 Linux uses a 48-byte GCM
// message envelope, i686 ILP32 uses 24, and Windows x64 LLP64 is packed to 32.
// Structured transport must never reinterpret one of these sizes as another.
// s390x is LP64 too, so it shares the 48-byte envelope (BE receipt: this
// assertion compiles the s390x layout into the build).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const _: [(); 48] = [(); std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>()];
#[cfg(all(target_os = "linux", target_arch = "s390x"))]
const _: [(); 48] = [(); std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>()];
#[cfg(all(target_os = "linux", target_arch = "x86"))]
const _: [(); 24] = [(); std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>()];
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const _: [(); 32] = [(); std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>()];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageParameterDirection {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageParameterStage {
    Init,
    OneShot,
    Begin,
    Next { final_part: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallerRangeRole {
    MechanismOuter,
    ParameterOuter,
    EmbeddedParameter,
    AssociatedData,
    MainInput,
    MainOutput,
    OutputLength,
}

#[derive(Debug, Clone, Copy)]
struct CallerRange {
    start: usize,
    end: usize,
    role: CallerRangeRole,
}

/// Additional caller buffers that participate in one message operation.
/// The outer parameter and its embedded buffers are supplied by the shape-
/// bound reader itself; this snapshot adds the surrounding C call's ranges.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MessageCallMemory {
    mechanism_outer: *const u8,
    associated_data: *const u8,
    associated_data_len: u64,
    main_input: *const u8,
    main_input_len: u64,
    main_output: *mut u8,
    main_output_len: u64,
    output_length: CK_ULONG_PTR,
}

impl MessageCallMemory {
    pub(crate) const fn with_mechanism(self, mechanism: CK_MECHANISM_PTR) -> Self {
        Self { mechanism_outer: mechanism.cast(), ..self }
    }
    pub(crate) const fn none() -> Self {
        Self {
            mechanism_outer: std::ptr::null(),
            associated_data: std::ptr::null(),
            associated_data_len: 0,
            main_input: std::ptr::null(),
            main_input_len: 0,
            main_output: std::ptr::null_mut(),
            main_output_len: 0,
            output_length: std::ptr::null_mut(),
        }
    }

    pub(crate) const fn init(mechanism_outer: CK_MECHANISM_PTR) -> Self {
        Self { mechanism_outer: mechanism_outer.cast(), ..Self::none() }
    }

    pub(crate) const fn begin(associated_data: *const u8, associated_data_len: CK_ULONG) -> Self {
        Self { associated_data, associated_data_len: associated_data_len as u64, ..Self::none() }
    }

    pub(crate) const fn output(
        associated_data: *const u8,
        associated_data_len: CK_ULONG,
        main_input: *const u8,
        main_input_len: CK_ULONG,
        main_output: *mut u8,
        main_output_len: u64,
        output_length: CK_ULONG_PTR,
    ) -> Self {
        Self {
            associated_data,
            associated_data_len: associated_data_len as u64,
            main_input,
            main_input_len: main_input_len as u64,
            main_output,
            main_output_len,
            output_length,
            ..Self::none()
        }
    }
}

fn checked_caller_range(
    pointer: *const u8,
    byte_len: u64,
    role: CallerRangeRole,
) -> CkResult<Option<CallerRange>> {
    if pointer.is_null() || byte_len == 0 {
        return Ok(None);
    }
    let len = usize::try_from(byte_len).map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
    if len > isize::MAX as usize {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    let start = pointer as usize;
    let end = start.checked_add(len).ok_or(CkRv::MECHANISM_PARAM_INVALID)?;
    Ok(Some(CallerRange { start, end, role }))
}

fn ranges_overlap(left: CallerRange, right: CallerRange) -> bool {
    left.start < right.end && right.start < left.end
}

fn allowed_in_place_pair(left: CallerRange, right: CallerRange) -> bool {
    matches!(
        (left.role, right.role),
        (CallerRangeRole::MainInput, CallerRangeRole::MainOutput)
            | (CallerRangeRole::MainOutput, CallerRangeRole::MainInput)
    ) && left.start == right.start
}

pub(super) fn validate_message_caller_ranges(
    memory: MessageCallMemory,
    parameter_outer: *const std::ffi::c_void,
    parameter_outer_len: u64,
    embedded: &[(*const u8, u64)],
) -> CkResult<()> {
    let mut ranges = Vec::with_capacity(7 + embedded.len());
    let candidates = [
        (
            memory.mechanism_outer,
            std::mem::size_of::<CK_MECHANISM>() as u64,
            CallerRangeRole::MechanismOuter,
        ),
        (parameter_outer.cast(), parameter_outer_len, CallerRangeRole::ParameterOuter),
        (memory.associated_data, memory.associated_data_len, CallerRangeRole::AssociatedData),
        (memory.main_input, memory.main_input_len, CallerRangeRole::MainInput),
        (memory.main_output.cast_const(), memory.main_output_len, CallerRangeRole::MainOutput),
        (
            memory.output_length.cast_const().cast(),
            if memory.output_length.is_null() { 0 } else { std::mem::size_of::<CK_ULONG>() as u64 },
            CallerRangeRole::OutputLength,
        ),
    ];
    for (pointer, len, role) in candidates {
        if let Some(range) = checked_caller_range(pointer, len, role)? {
            ranges.push(range);
        }
    }
    for &(pointer, len) in embedded {
        if let Some(range) = checked_caller_range(pointer, len, CallerRangeRole::EmbeddedParameter)?
        {
            ranges.push(range);
        }
    }

    for (index, left) in ranges.iter().copied().enumerate() {
        for right in ranges.iter().copied().skip(index + 1) {
            if ranges_overlap(left, right) && !allowed_in_place_pair(left, right) {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_message_mechanism_outer(p_mechanism: CK_MECHANISM_PTR) -> CkResult<()> {
    checked_caller_range(
        p_mechanism.cast(),
        std::mem::size_of::<CK_MECHANISM>() as u64,
        CallerRangeRole::MechanismOuter,
    )?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum MessageParameterWriteback {
    Gcm { iv: *mut CK_BYTE, iv_len: usize, tag: *mut CK_BYTE, tag_len: usize },
    Ccm { nonce: *mut CK_BYTE, nonce_len: usize, mac: *mut CK_BYTE, mac_len: usize },
    SalsaChacha { tag: *mut CK_BYTE, tag_len: usize },
}

/// One immutable caller snapshot used for both request serialization and
/// eventual writeback. Embedded output pointers are copied from the unaligned
/// outer struct exactly once, before the RPC.
#[derive(Debug, Clone)]
pub(crate) struct MessageParameterCall {
    parameter: Option<MessageParameter>,
    writeback: Option<MessageParameterWriteback>,
    direction: MessageParameterDirection,
    stage: MessageParameterStage,
}

impl MessageParameterCall {
    pub(crate) fn parameter(&self) -> Option<&MessageParameter> {
        self.parameter.as_ref()
    }

    pub(crate) fn into_parameter(self) -> Option<MessageParameter> {
        self.parameter
    }
}

pub(crate) fn empty_message_parameter_call(
    direction: MessageParameterDirection,
    stage: MessageParameterStage,
) -> MessageParameterCall {
    MessageParameterCall { parameter: None, writeback: None, direction, stage }
}

impl MessageParameterStage {
    fn reads_authentication_input(self) -> bool {
        matches!(self, Self::OneShot | Self::Next { final_part: true })
    }
}

unsafe fn embedded_bytes(
    pointer: *mut CK_BYTE,
    byte_len: u64,
    read_input: bool,
) -> CkResult<(Vec<u8>, Option<u64>)> {
    if pointer.is_null() {
        return Ok((Vec::new(), Some(byte_len)));
    }
    let len = usize::try_from(byte_len).map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
    if len > MAX_SERIALIZABLE_BYTES || len > isize::MAX as usize {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    checked_caller_range(pointer.cast_const(), byte_len, CallerRangeRole::EmbeddedParameter)?;
    if !read_input {
        return Ok((vec![0; len], None));
    }
    if len == 0 {
        return Ok((Vec::new(), None));
    }
    Ok((unsafe { std::slice::from_raw_parts(pointer.cast_const(), len) }.to_vec(), None))
}

fn generating_prefix_len(generator: u64, fixed_bits: u64, total_len: u64) -> CkResult<u64> {
    if generator > CKG_GENERATE_COUNTER_XOR as u64 || fixed_bits.div_ceil(8) > total_len {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    if matches!(generator, x if x == CKG_NO_GENERATE as u64 || x == CKG_GENERATE_COUNTER_XOR as u64)
    {
        Ok(total_len)
    } else {
        Ok(fixed_bits.div_ceil(8))
    }
}

unsafe fn generated_input_bytes(
    pointer: *mut CK_BYTE,
    total_len: u64,
    fixed_bits: u64,
    generator: u64,
    copy_generated_value: bool,
) -> CkResult<(Vec<u8>, Option<u64>)> {
    if pointer.is_null() {
        return Ok((Vec::new(), Some(total_len)));
    }
    let total = usize::try_from(total_len).map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
    if total > MAX_SERIALIZABLE_BYTES || total > isize::MAX as usize {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    checked_caller_range(pointer.cast_const(), total_len, CallerRangeRole::EmbeddedParameter)?;
    let prefix = if copy_generated_value {
        total_len
    } else {
        generating_prefix_len(generator, fixed_bits, total_len)?
    };
    let prefix = usize::try_from(prefix).map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?;
    let mut result = vec![0; total];
    if prefix > 0 {
        let source = unsafe { std::slice::from_raw_parts(pointer.cast_const(), prefix) };
        result[..prefix].copy_from_slice(source);
    }
    if !copy_generated_value
        && !matches!(generator, x if x == CKG_NO_GENERATE as u64 || x == CKG_GENERATE_COUNTER_XOR as u64)
        && !fixed_bits.is_multiple_of(8)
        && prefix > 0
    {
        result[prefix - 1] &= 0xff << (8 - (fixed_bits % 8));
    }
    Ok((result, None))
}

/// Shape-bound reader with the surrounding C call's memory ranges included
/// in the pre-dereference alias check.
///
/// # Safety
///
/// A non-null, positive-length `p_parameter` must designate the exact outer
/// struct selected by `shape`; every non-null embedded pointer and non-null
/// pointer captured by `memory` must satisfy its PKCS#11 caller contract.
pub(crate) unsafe fn read_message_parameter_call_for_shape_with_memory(
    p_parameter: *const std::ffi::c_void,
    ul_parameter_len: CK_ULONG,
    shape: MessageParameterShape,
    direction: MessageParameterDirection,
    stage: MessageParameterStage,
    memory: MessageCallMemory,
) -> CkResult<MessageParameterCall> {
    if p_parameter.is_null() || ul_parameter_len == 0 {
        validate_message_caller_ranges(memory, p_parameter, ul_parameter_len as u64, &[])?;
        return Ok(MessageParameterCall { parameter: None, writeback: None, direction, stage });
    }

    let (parameter, writeback) = match shape {
        MessageParameterShape::Unmodeled => return Err(CkRv::MECHANISM_PARAM_INVALID),
        MessageParameterShape::Gcm => {
            if ul_parameter_len as usize != std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            checked_caller_range(
                p_parameter.cast(),
                std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as u64,
                CallerRangeRole::ParameterOuter,
            )?;
            let outer =
                unsafe { std::ptr::read_unaligned(p_parameter.cast::<CK_GCM_MESSAGE_PARAMS>()) };
            let iv_len = outer.ulIvLen as u64;
            let tag_bits = outer.ulTagBits as u64;
            let tag_len = tag_bits.div_ceil(8);
            generating_prefix_len(outer.ivGenerator as u64, outer.ulIvFixedBits as u64, iv_len)?;
            if tag_bits > 128 {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            validate_message_caller_ranges(
                memory,
                p_parameter,
                ul_parameter_len as u64,
                &[(outer.pIv.cast_const(), iv_len), (outer.pTag.cast_const(), tag_len)],
            )?;
            // Encrypt may ask the provider to generate the non-fixed suffix,
            // so before Begin only the source-defined prefix is input.  For
            // Decrypt the IV is entirely caller-supplied at every stage.
            // After Begin, Encrypt Next also carries the generated full IV.
            let copy_full_iv = direction == MessageParameterDirection::Decrypt
                || matches!(stage, MessageParameterStage::Next { .. });
            let (iv, iv_null_len) = unsafe {
                generated_input_bytes(
                    outer.pIv,
                    iv_len,
                    outer.ulIvFixedBits as u64,
                    outer.ivGenerator as u64,
                    copy_full_iv,
                )
            }?;
            let read_tag = direction == MessageParameterDirection::Decrypt
                && stage.reads_authentication_input();
            let (tag, tag_null_len) = unsafe { embedded_bytes(outer.pTag, tag_len, read_tag) }?;
            (
                MessageParameter::GcmMessage(GcmMessageParams {
                    iv,
                    iv_null_len,
                    iv_fixed_bits: outer.ulIvFixedBits as u64,
                    iv_generator: outer.ivGenerator as u64,
                    tag,
                    tag_null_len,
                    tag_bits,
                }),
                MessageParameterWriteback::Gcm {
                    iv: outer.pIv,
                    iv_len: usize::try_from(iv_len).map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?,
                    tag: outer.pTag,
                    tag_len: usize::try_from(tag_len).map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?,
                },
            )
        }
        MessageParameterShape::Ccm => {
            if ul_parameter_len as usize != std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            checked_caller_range(
                p_parameter.cast(),
                std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() as u64,
                CallerRangeRole::ParameterOuter,
            )?;
            let outer =
                unsafe { std::ptr::read_unaligned(p_parameter.cast::<CK_CCM_MESSAGE_PARAMS>()) };
            let nonce_len = outer.ulNonceLen as u64;
            let mac_len = outer.ulMACLen as u64;
            if !(7..=13).contains(&nonce_len) || !matches!(mac_len, 4 | 6 | 8 | 10 | 12 | 14 | 16) {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            generating_prefix_len(
                outer.nonceGenerator as u64,
                outer.ulNonceFixedBits as u64,
                nonce_len,
            )?;
            validate_message_caller_ranges(
                memory,
                p_parameter,
                ul_parameter_len as u64,
                &[(outer.pNonce.cast_const(), nonce_len), (outer.pMAC.cast_const(), mac_len)],
            )?;
            // Decrypt nonces are always complete inputs.  Encrypt copies only
            // the fixed prefix until Begin has generated the remaining bytes;
            // every subsequent Next transports the complete generated nonce.
            let copy_full_nonce = direction == MessageParameterDirection::Decrypt
                || matches!(stage, MessageParameterStage::Next { .. });
            let (nonce, nonce_null_len) = unsafe {
                generated_input_bytes(
                    outer.pNonce,
                    nonce_len,
                    outer.ulNonceFixedBits as u64,
                    outer.nonceGenerator as u64,
                    copy_full_nonce,
                )
            }?;
            let read_mac = direction == MessageParameterDirection::Decrypt
                && stage.reads_authentication_input();
            let (mac, mac_null_len) = unsafe { embedded_bytes(outer.pMAC, mac_len, read_mac) }?;
            (
                MessageParameter::CcmMessage(CcmMessageParams {
                    data_len: outer.ulDataLen as u64,
                    nonce,
                    nonce_null_len,
                    nonce_fixed_bits: outer.ulNonceFixedBits as u64,
                    nonce_generator: outer.nonceGenerator as u64,
                    mac,
                    mac_null_len,
                    mac_len,
                }),
                MessageParameterWriteback::Ccm {
                    nonce: outer.pNonce,
                    nonce_len: usize::try_from(nonce_len)
                        .map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?,
                    mac: outer.pMAC,
                    mac_len: usize::try_from(mac_len).map_err(|_| CkRv::MECHANISM_PARAM_INVALID)?,
                },
            )
        }
        MessageParameterShape::SalsaChacha => {
            if ul_parameter_len as usize
                != std::mem::size_of::<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>()
            {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            checked_caller_range(
                p_parameter.cast(),
                std::mem::size_of::<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>() as u64,
                CallerRangeRole::ParameterOuter,
            )?;
            let outer = unsafe {
                std::ptr::read_unaligned(
                    p_parameter.cast::<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>(),
                )
            };
            let nonce_bits = outer.ulNonceLen as u64;
            if !matches!(nonce_bits, 64 | 96 | 192) {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            let nonce_len = nonce_bits.div_ceil(8);
            validate_message_caller_ranges(
                memory,
                p_parameter,
                ul_parameter_len as u64,
                &[(outer.pNonce.cast_const(), nonce_len), (outer.pTag.cast_const(), 16)],
            )?;
            let (nonce, nonce_null_len) = unsafe { embedded_bytes(outer.pNonce, nonce_len, true) }?;
            let read_tag = direction == MessageParameterDirection::Decrypt
                && stage.reads_authentication_input();
            let (tag, tag_null_len) = unsafe { embedded_bytes(outer.pTag, 16, read_tag) }?;
            (
                MessageParameter::SalaChacha(Salsa20ChaCha20Poly1305MessageParams {
                    nonce,
                    nonce_bits,
                    nonce_null_len,
                    tag,
                    tag_null_len,
                }),
                MessageParameterWriteback::SalsaChacha { tag: outer.pTag, tag_len: 16 },
            )
        }
    };
    parameter.validate_structured_shape(shape)?;
    Ok(MessageParameterCall {
        parameter: Some(parameter),
        writeback: Some(writeback),
        direction,
        stage,
    })
}

fn parameter_result_matches_request(
    result: &CkParameterRoundtripResult,
    spec: &CkParameterRoundtripSpec,
    expected_rv: CkRv,
) -> bool {
    result.ck_rv == expected_rv
        && result.returned_len == spec.buffer_len
        && match (spec.buffer_present, result.value.as_ref()) {
            (true, Some(value)) => value.is_empty(),
            (false, None) => true,
            _ => false,
        }
}

pub(super) fn validate_exact_output_result(
    result: &CkOutputBufferResult,
    spec: &CkOutputBufferSpec,
) -> CkResult<()> {
    result.validate_for(spec, CK_ULONG::MAX as u64)
}

unsafe fn copy_message_bytes(target: *mut CK_BYTE, capacity: usize, value: &[u8]) {
    if target.is_null() || value.is_empty() {
        return;
    }
    debug_assert_eq!(capacity, value.len());
    unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), target, value.len()) };
}

pub(super) fn effect_context(
    call: &MessageParameterCall,
    rv: CkRv,
    output_spec: &CkOutputBufferSpec,
) -> MessageEffectContext {
    MessageEffectContext {
        mode: if call.stage == MessageParameterStage::Begin {
            ParameterEffectCallMode::Begin
        } else {
            ParameterEffectCallMode::from_output_spec(output_spec)
        },
        encrypt: call.direction == MessageParameterDirection::Encrypt,
        generated_stage: matches!(
            call.stage,
            MessageParameterStage::OneShot | MessageParameterStage::Begin
        ),
        auth_stage: matches!(
            call.stage,
            MessageParameterStage::OneShot | MessageParameterStage::Next { final_part: true }
        ),
        rv,
    }
}

unsafe fn commit_message_parameter_writeback(
    call: &MessageParameterCall,
    response: &MessageEffects,
) {
    match (call.writeback, response) {
        (
            Some(MessageParameterWriteback::Gcm { iv, iv_len, tag, tag_len }),
            MessageEffects::Gcm { iv: first, tag: second },
        ) => {
            if let Some(value) = first {
                unsafe { copy_message_bytes(iv, iv_len, value) };
            }
            if let Some(value) = second {
                unsafe { copy_message_bytes(tag, tag_len, value) };
            }
        }
        (
            Some(MessageParameterWriteback::Ccm { nonce, nonce_len, mac, mac_len }),
            MessageEffects::Ccm { nonce: first, mac: second },
        ) => {
            if let Some(value) = first {
                unsafe { copy_message_bytes(nonce, nonce_len, value) };
            }
            if let Some(value) = second {
                unsafe { copy_message_bytes(mac, mac_len, value) };
            }
        }
        (
            Some(MessageParameterWriteback::SalsaChacha { tag, tag_len }),
            MessageEffects::Salsa { tag: Some(value) },
        ) => unsafe { copy_message_bytes(tag, tag_len, value) },
        _ => {}
    }
}

/// Validate the complete canonical message response before committing any
/// caller-visible byte or length.  The `MessageParameterCall` supplies the
/// pre-RPC outer/embedded-pointer snapshot, so writeback never re-reads the
/// caller's outer struct.
///
/// # Safety
///
/// `p_output` and `pul_output_len` must be the same writable pointers captured
/// in `output_spec`. Embedded pointers inside `call` must remain writable for
/// their source-declared extents for the duration of the PKCS#11 call.
pub(crate) unsafe fn write_exact_message_output(
    output_spec: &CkOutputBufferSpec,
    parameter_spec: &CkParameterRoundtripSpec,
    call: &MessageParameterCall,
    output_result: &CkOutputBufferResult,
    parameter_result: &CkParameterRoundtripResult,
    response_parameter: Option<&MessageEffects>,
    p_output: CK_BYTE_PTR,
    pul_output_len: CK_ULONG_PTR,
) -> CK_RV {
    if pul_output_len.is_null() != output_spec.length_pointer_null
        || p_output.is_null() == output_spec.buffer_present
    {
        return rv_err(CkRv::GENERAL_ERROR);
    }
    if validate_exact_output_result(output_result, output_spec).is_err() {
        return rv_err(CkRv::GENERAL_ERROR);
    }
    if output_result.ck_rv != CkRv::OK
        && output_result.ck_rv != CkRv::BUFFER_TOO_SMALL
        && output_result.returned_len.is_none()
        && output_result.value.is_none()
        && response_parameter.is_none()
    {
        return rv_err(output_result.ck_rv);
    }
    if !parameter_result_matches_request(parameter_result, parameter_spec, output_result.ck_rv) {
        return rv_err(CkRv::GENERAL_ERROR);
    }

    let response_parameter = match (call.parameter(), response_parameter) {
        (Some(request), Some(response))
            if response
                .validate_for(request, effect_context(call, output_result.ck_rv, output_spec))
                .is_ok() =>
        {
            Some(response)
        }
        (None, None) => None,
        _ => return rv_err(CkRv::GENERAL_ERROR),
    };

    let returned_len = match output_result.returned_len.map(CK_ULONG::try_from).transpose() {
        Ok(len) => len,
        Err(_) => return rv_err(CkRv::GENERAL_ERROR),
    };
    if let Some(response) = response_parameter {
        unsafe { commit_message_parameter_writeback(call, response) };
    }
    if output_spec.length_pointer_null {
        return rv_err(output_result.ck_rv);
    }
    if let Some(value) = output_result.value.as_ref()
        && !value.is_empty()
    {
        value.expose(|raw| unsafe {
            std::ptr::copy_nonoverlapping(raw.as_ptr(), p_output, raw.len())
        });
    }
    if let Some(returned_len) = returned_len {
        unsafe { pul_output_len.write(returned_len) };
    }
    rv_err(output_result.ck_rv)
}

/// Validate and commit a Begin response through the same transactional seam as
/// one-shot/Next. Begin has no main output buffer, so a local zero-length size
/// query stands in for that part of the contract while generated IV/nonce
/// writeback still uses the pre-RPC embedded-pointer snapshot.
pub(crate) unsafe fn write_message_begin_output(
    parameter_spec: &CkParameterRoundtripSpec,
    call: &MessageParameterCall,
    parameter_result: &CkParameterRoundtripResult,
    effects: Option<&MessageEffects>,
) -> CK_RV {
    let output_spec =
        CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: false };
    let output_result =
        CkOutputBufferResult { ck_rv: parameter_result.ck_rv, returned_len: Some(0), value: None };
    let mut output_len = 0;
    unsafe {
        write_exact_message_output(
            &output_spec,
            parameter_spec,
            call,
            &output_result,
            parameter_result,
            effects,
            std::ptr::null_mut(),
            &mut output_len,
        )
    }
}
