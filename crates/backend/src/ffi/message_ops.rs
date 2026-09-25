use super::ffi_conversion::{mechanism_to_ffi, narrow_wire_ulong};
use super::native_allocation::NativeAllocation;
use super::{FfiBackend, call_3x_fn};
use pkcs11_proxy_ng_proto::convert::message_effects::ParameterEffectCallMode;
use pkcs11_proxy_ng_proto::convert::message_effects::{MessageEffectContext, MessageEffects};
use pkcs11_proxy_ng_proto::convert::message_params::{
    CcmMessageParams, GcmMessageParams, MessageParameter, Salsa20ChaCha20Poly1305MessageParams,
};
use pkcs11_proxy_ng_types::*;

/// Two-call FFI pattern for message operations that return
/// `(parameter_out, output_bytes)`.
///
/// Resolves the function pointer from the 3.0 function list, performs
/// a size-query call (null output buffer), allocates, calls again,
/// and reads back the parameter.
///
/// `$pre_args` are the arguments before the output `(ptr, len)` pair,
/// and `$post_args` are any trailing arguments after the output pair
/// (e.g., flags).
macro_rules! two_call_message {
    (
        $admission:expr,
        $self:expr, $func_name:ident, $parameter:expr,
        [ $($pre_arg:expr),+ $(,)? ]
        $(, [ $($post_arg:expr),+ $(,)? ] )?
    ) => {{
        // B2 admission proof (TF01b): ascribed like `call_3x_fn!` — the
        // two-call shape keeps its bespoke sizing/fill inline.
        let _admission: &crate::ffi::native_domain::OrdinaryGuard = $admission;
        let fl = $self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).$func_name }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let mut out_len: cryptoki_sys::CK_ULONG = 0;
        let rv = unsafe {
            f( $($pre_arg,)+ std::ptr::null_mut(), &mut out_len $(, $($post_arg),+ )? )
        };
        FfiBackend::ck_result(rv)?;

        let capped_len = (out_len as u64).min(super::call_helpers::MAX_OUTPUT_BUFFER_BYTES);
        out_len = capped_len as cryptoki_sys::CK_ULONG;
        let mut output = vec![0u8; capped_len as usize];
        let rv = unsafe {
            f( $($pre_arg,)+ output.as_mut_ptr(), &mut out_len $(, $($post_arg),+ )? )
        };
        FfiBackend::ck_result(rv)?;
        output.truncate(out_len as usize);

        let parameter_out = $parameter.to_vec();
        // ADR-0013 S5: adopt both provider-written buffers immediately.
        Ok((SecretBytes::new(parameter_out), SecretBytes::new(output)))
    }};
}

fn message_pointer(buf: &mut [u8], null_len: Option<u64>) -> *mut cryptoki_sys::CK_BYTE {
    if null_len.is_some() {
        std::ptr::null_mut()
    } else if buf.is_empty() {
        std::ptr::NonNull::<u8>::dangling().as_ptr()
    } else {
        buf.as_mut_ptr()
    }
}

fn message_ck_ulong(value: u64) -> CkResult<cryptoki_sys::CK_ULONG> {
    cryptoki_sys::CK_ULONG::try_from(value).map_err(|_| CkRv::MECHANISM_PARAM_INVALID)
}

fn native_ulong_max() -> u64 {
    cryptoki_sys::CK_ULONG::MAX as u64
}

fn native_message_input(
    input: CkInBuf<'_>,
) -> CkResult<(*const cryptoki_sys::CK_BYTE, cryptoki_sys::CK_ULONG)> {
    let (pointer, len) = input.as_ptr_len();
    Ok((pointer, narrow_wire_ulong(len)?))
}

fn native_message_flags(flags: CkFlags) -> CkResult<cryptoki_sys::CK_FLAGS> {
    narrow_wire_ulong(flags.0)
}

fn empty_parameter_pointer(
    spec: &CkParameterRoundtripSpec,
) -> CkResult<(*mut std::ffi::c_void, cryptoki_sys::CK_ULONG)> {
    if spec.value.is_some() || (spec.buffer_present && spec.buffer_len > 0) {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    let pointer = if spec.buffer_present {
        std::ptr::NonNull::<u8>::dangling().as_ptr().cast()
    } else {
        std::ptr::null_mut()
    };
    Ok((pointer, message_ck_ulong(spec.buffer_len)?))
}

fn validate_empty_only_parameter_spec(spec: &CkParameterRoundtripSpec) -> CkResult<()> {
    if spec.buffer_len > 0 || spec.value.is_some() {
        Err(CkRv::MECHANISM_PARAM_INVALID)
    } else {
        Ok(())
    }
}

fn empty_only_parameter_pointer(
    spec: &CkParameterRoundtripSpec,
) -> CkResult<(*mut std::ffi::c_void, cryptoki_sys::CK_ULONG)> {
    validate_empty_only_parameter_spec(spec)?;
    empty_parameter_pointer(spec)
}

fn empty_parameter_ack(spec: &CkParameterRoundtripSpec) -> CkParameterRoundtripResult {
    CkParameterRoundtripResult {
        ck_rv: CkRv::OK,
        returned_len: spec.buffer_len,
        value: spec.buffer_present.then(Vec::new),
    }
}

fn native_message_parameter_len(parameter: &MessageParameter) -> CkResult<u64> {
    match parameter {
        MessageParameter::GcmMessage(_) => {
            Ok(std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>() as u64)
        }
        MessageParameter::CcmMessage(_) => {
            Ok(std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>() as u64)
        }
        MessageParameter::SalaChacha(_) => {
            Ok(std::mem::size_of::<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>() as u64)
        }
        MessageParameter::Raw(_) => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

fn structured_parameter_ack(
    parameter: &MessageParameter,
    provider_spec: &CkParameterRoundtripSpec,
    ck_rv: CkRv,
) -> CkResult<CkParameterRoundtripResult> {
    parameter.validate_structured()?;
    if !provider_spec.buffer_present
        || provider_spec.buffer_len != native_message_parameter_len(parameter)?
        || provider_spec.value.is_some()
    {
        return Err(CkRv::MECHANISM_PARAM_INVALID);
    }
    Ok(CkParameterRoundtripResult {
        ck_rv,
        returned_len: provider_spec.buffer_len,
        value: Some(Vec::new()),
    })
}

fn validate_message_init_provider_ack(
    mechanism: &cryptoki_sys::CK_MECHANISM,
    provider_spec: &CkParameterRoundtripSpec,
) -> CkResult<()> {
    if mechanism.pParameter.is_null() == provider_spec.buffer_present
        || mechanism.ulParameterLen as u64 != provider_spec.buffer_len
    {
        return Err(CkRv::DEVICE_ERROR);
    }
    Ok(())
}

/// Owns a reconstructed `CK_*_MESSAGE_PARAMS` C struct and its backing
/// IV/tag/nonce/MAC buffers so that a `CK_MECHANISM` can reference them across a
/// `C_Message{Encrypt,Decrypt}Init` FFI call. The params struct lives in a
/// persistent [`NativeAllocation`] (stable heap address with no reborrow, so
/// owner moves cannot strand the stored root) and the buffers live in
/// `_buffers`; both survive a move of this holder, so the raw pointers stored
/// in `ck_mechanism` and the params struct stay valid for as long as the
/// holder is alive.
pub(super) struct MessageInitMechanism {
    pub(super) ck_mechanism: cryptoki_sys::CK_MECHANISM,
    _gcm: Option<NativeAllocation<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>>,
    _ccm: Option<NativeAllocation<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>>,
    _salsa: Option<NativeAllocation<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>>,
    _buffers: Vec<Vec<u8>>,
}

impl MessageInitMechanism {
    /// Read only the allocations we own. Native pointer and input scalar
    /// replacement is a provider contract error, never a new memory source.
    pub(super) fn validate_authenticated_inputs(&self, input: &MessageParameter) -> CkResult<()> {
        let [first, second] = self._buffers.as_slice() else {
            return Err(CkRv::DEVICE_ERROR);
        };
        let pointer_matches = |native: cryptoki_sys::CK_BYTE_PTR,
                               buffer: &[u8],
                               null: Option<u64>| {
            if null.is_some() { native.is_null() } else { std::ptr::eq(native, buffer.as_ptr()) }
        };
        let prefix_unchanged = |output: &[u8], input: &[u8], fixed_bits: u64, generator: u64| {
            if generator == cryptoki_sys::CKG_NO_GENERATE as u64 {
                return output == input;
            }
            let bytes = (fixed_bits / 8) as usize;
            let remainder = (fixed_bits % 8) as u32;
            output.get(..bytes) == input.get(..bytes)
                && (remainder == 0
                    || output
                        .get(bytes)
                        .zip(input.get(bytes))
                        .is_some_and(|(out, old)| (out ^ old) & (0xff << (8 - remainder)) == 0))
        };
        let (valid, outer, len) = match (input, &self._gcm, &self._ccm, &self._salsa) {
            (MessageParameter::GcmMessage(p), Some(native), None, None) => {
                // SAFETY: holder is borrowed alive; the copy carries no provenance.
                let snapshot = unsafe { native.snapshot() };
                let valid = pointer_matches(snapshot.pIv, first, p.iv_null_len)
                    && pointer_matches(snapshot.pTag, second, p.tag_null_len)
                    && snapshot.ulIvLen as u64 == p.iv_null_len.unwrap_or(p.iv.len() as u64)
                    && snapshot.ulIvFixedBits as u64 == p.iv_fixed_bits
                    && snapshot.ivGenerator as u64 == p.iv_generator
                    && snapshot.ulTagBits as u64 == p.tag_bits
                    && if p.iv_null_len.is_some() {
                        first.is_empty() && p.iv.is_empty()
                    } else {
                        prefix_unchanged(first, &p.iv, p.iv_fixed_bits, p.iv_generator)
                    };
                (
                    valid,
                    native.root().cast(),
                    std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>(),
                )
            }
            (MessageParameter::CcmMessage(p), None, Some(native), None) => {
                // SAFETY: holder is borrowed alive; the copy carries no provenance.
                let snapshot = unsafe { native.snapshot() };
                let valid = pointer_matches(snapshot.pNonce, first, p.nonce_null_len)
                    && pointer_matches(snapshot.pMAC, second, p.mac_null_len)
                    && snapshot.ulDataLen as u64 == p.data_len
                    && snapshot.ulNonceLen as u64
                        == p.nonce_null_len.unwrap_or(p.nonce.len() as u64)
                    && snapshot.ulNonceFixedBits as u64 == p.nonce_fixed_bits
                    && snapshot.nonceGenerator as u64 == p.nonce_generator
                    && snapshot.ulMACLen as u64 == p.mac_len
                    && if p.nonce_null_len.is_some() {
                        first.is_empty() && p.nonce.is_empty()
                    } else {
                        prefix_unchanged(first, &p.nonce, p.nonce_fixed_bits, p.nonce_generator)
                    };
                (
                    valid,
                    native.root().cast(),
                    std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>(),
                )
            }
            (MessageParameter::SalaChacha(p), None, None, Some(native)) => {
                // SAFETY: holder is borrowed alive; the copy carries no provenance.
                let snapshot = unsafe { native.snapshot() };
                let valid = pointer_matches(snapshot.pNonce, first, p.nonce_null_len)
                    && pointer_matches(snapshot.pTag, second, p.tag_null_len)
                    && snapshot.ulNonceLen as u64 == p.nonce_bits
                    && first == &p.nonce;
                (
                    valid,
                    native.root().cast(),
                    std::mem::size_of::<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>(),
                )
            }
            _ => return Err(CkRv::DEVICE_ERROR),
        };
        if !valid
            || !std::ptr::eq(self.ck_mechanism.pParameter, outer)
            || self.ck_mechanism.ulParameterLen as usize != len
        {
            return Err(CkRv::DEVICE_ERROR);
        }
        Ok(())
    }

    /// Called only after input validation; never follows native pointers.
    pub(super) fn authenticated_output(&self, input: &MessageParameter) -> MessageParameter {
        let mut output = input.clone();
        match &mut output {
            MessageParameter::GcmMessage(p) => {
                p.iv.clone_from(&self._buffers[0]);
                p.tag.clone_from(&self._buffers[1]);
            }
            MessageParameter::CcmMessage(p) => {
                p.nonce.clone_from(&self._buffers[0]);
                p.mac.clone_from(&self._buffers[1]);
            }
            MessageParameter::SalaChacha(p) => {
                p.nonce.clone_from(&self._buffers[0]);
                p.tag.clone_from(&self._buffers[1]);
            }
            _ => {}
        }
        output
    }
}

/// Build a `CK_MECHANISM` pointing at a persistently allocated `T` (stable
/// heap address). The root projects from the allocation, never from a
/// reborrow of a moved box (C3M.2 defect I1 class).
fn message_mechanism_for<T>(
    mech_type: cryptoki_sys::CK_MECHANISM_TYPE,
    allocation: &NativeAllocation<T>,
) -> cryptoki_sys::CK_MECHANISM {
    cryptoki_sys::CK_MECHANISM {
        mechanism: mech_type,
        pParameter: allocation.root().cast(),
        ulParameterLen: std::mem::size_of::<T>() as cryptoki_sys::CK_ULONG,
    }
}

/// Reconstruct an AEAD message-based init mechanism (`CK_GCM_MESSAGE_PARAMS` /
/// `CK_CCM_MESSAGE_PARAMS` / `CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS`) from the
/// structured `MessageParameter` carried alongside a message-init request.
///
/// The server has already derived and validated the registry-selected shape,
/// caller envelope, and structured variant before this boundary. Reconstruct
/// that parameter as a provider-native outer struct and keep the outer value
/// plus all embedded buffers alive for the Init FFI call; raw client ABI bytes
/// never reach this helper.
pub(super) fn build_message_init_mechanism(
    mech_type: u64,
    param: &MessageParameter,
) -> CkResult<MessageInitMechanism> {
    // Vendor mechanism IDs cross into native CK_MECHANISM_TYPE here: fail
    // loudly on narrow hosts, never truncate.
    let mech_type = narrow_wire_ulong(mech_type)?;
    param.validate_for_native_ulong(native_ulong_max())?;
    match param {
        MessageParameter::GcmMessage(gcm) => {
            let iv_len = gcm.iv_null_len.unwrap_or(gcm.iv.len() as u64);
            let ul_iv_len = message_ck_ulong(iv_len)?;
            let ul_iv_fixed_bits = message_ck_ulong(gcm.iv_fixed_bits)?;
            let iv_generator = message_ck_ulong(gcm.iv_generator)?;
            let ul_tag_bits = message_ck_ulong(gcm.tag_bits)?;
            let mut iv = gcm.iv.clone();
            let mut tag = gcm.tag.clone();
            let allocation =
                NativeAllocation::from_box(Box::new(cryptoki_sys::CK_GCM_MESSAGE_PARAMS {
                    pIv: message_pointer(&mut iv, gcm.iv_null_len),
                    ulIvLen: ul_iv_len,
                    ulIvFixedBits: ul_iv_fixed_bits,
                    ivGenerator: iv_generator,
                    pTag: message_pointer(&mut tag, gcm.tag_null_len),
                    ulTagBits: ul_tag_bits,
                }));
            let ck_mechanism = message_mechanism_for(mech_type, &allocation);
            Ok(MessageInitMechanism {
                ck_mechanism,
                _gcm: Some(allocation),
                _ccm: None,
                _salsa: None,
                _buffers: vec![iv, tag],
            })
        }
        MessageParameter::CcmMessage(ccm) => {
            let nonce_len = ccm.nonce_null_len.unwrap_or(ccm.nonce.len() as u64);
            let ul_data_len = message_ck_ulong(ccm.data_len)?;
            let ul_nonce_len = message_ck_ulong(nonce_len)?;
            let ul_nonce_fixed_bits = message_ck_ulong(ccm.nonce_fixed_bits)?;
            let nonce_generator = message_ck_ulong(ccm.nonce_generator)?;
            let ul_mac_len = message_ck_ulong(ccm.mac_len)?;
            let mut nonce = ccm.nonce.clone();
            let mut mac = ccm.mac.clone();
            let allocation =
                NativeAllocation::from_box(Box::new(cryptoki_sys::CK_CCM_MESSAGE_PARAMS {
                    ulDataLen: ul_data_len,
                    pNonce: message_pointer(&mut nonce, ccm.nonce_null_len),
                    ulNonceLen: ul_nonce_len,
                    ulNonceFixedBits: ul_nonce_fixed_bits,
                    nonceGenerator: nonce_generator,
                    pMAC: message_pointer(&mut mac, ccm.mac_null_len),
                    ulMACLen: ul_mac_len,
                }));
            let ck_mechanism = message_mechanism_for(mech_type, &allocation);
            Ok(MessageInitMechanism {
                ck_mechanism,
                _gcm: None,
                _ccm: Some(allocation),
                _salsa: None,
                _buffers: vec![nonce, mac],
            })
        }
        MessageParameter::SalaChacha(s) => {
            let ul_nonce_len = message_ck_ulong(s.nonce_bits)?;
            let mut nonce = s.nonce.clone();
            let mut tag = s.tag.clone();
            let allocation = NativeAllocation::from_box(Box::new(
                cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS {
                    pNonce: message_pointer(&mut nonce, s.nonce_null_len),
                    ulNonceLen: ul_nonce_len,
                    pTag: message_pointer(&mut tag, s.tag_null_len),
                },
            ));
            let ck_mechanism = message_mechanism_for(mech_type, &allocation);
            Ok(MessageInitMechanism {
                ck_mechanism,
                _gcm: None,
                _ccm: None,
                _salsa: Some(allocation),
                _buffers: vec![nonce, tag],
            })
        }
        // Raw bytes can carry an unknown layout (possibly embedded pointers);
        // refuse rather than ship something the backend can't safely interpret.
        MessageParameter::Raw(_) => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

impl FfiBackend {
    // --- Message Encrypt ---

    pub(super) fn ffi_message_encrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        init_param: Option<&MessageParameter>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        match (mechanism, init_param) {
            // AEAD message-based init: reconstruct CK_*_MESSAGE_PARAMS.
            (Some(mech), Some(param)) => {
                let mut init_mech = build_message_init_mechanism(mech.mechanism_type.0, param)?;
                call_3x_fn!(
                    self,
                    func_list_3_0,
                    C_MessageEncryptInit,
                    Self::session_handle(session)?,
                    &mut init_mech.ck_mechanism as *mut cryptoki_sys::CK_MECHANISM,
                    Self::object_handle(key)?
                )
            }
            (Some(mech), None) => {
                let ffi_mech = mechanism_to_ffi(mech)?;
                call_3x_fn!(
                    &admission,
                    self,
                    func_list_3_0,
                    C_MessageEncryptInit,
                    Self::session_handle(session)?,
                    ffi_mech.ck_mechanism_ptr(),
                    Self::object_handle(key)?
                )
            }
            (None, _) => {
                // NULL mechanism = cancel active message-encrypt state
                call_3x_fn!(
                    &admission,
                    self,
                    func_list_3_0,
                    C_MessageEncryptInit,
                    Self::session_handle(session)?,
                    std::ptr::null_mut::<cryptoki_sys::CK_MECHANISM>(),
                    Self::object_handle(key)?
                )
            }
        }
    }

    pub(super) fn ffi_message_encrypt_init_contract(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        init_param: Option<&MessageParameter>,
        key: CkObjectHandle,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        if let Some(param) = init_param {
            let mut init_mech = build_message_init_mechanism(mechanism.mechanism_type.0, param)?;
            if !provider_spec.buffer_present
                || provider_spec.buffer_len != init_mech.ck_mechanism.ulParameterLen as u64
                || provider_spec.value.is_some()
            {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            call_3x_fn!(
                self,
                func_list_3_0,
                C_MessageEncryptInit,
                Self::session_handle(session)?,
                &mut init_mech.ck_mechanism,
                Self::object_handle(key)?
            )?;
            validate_message_init_provider_ack(&init_mech.ck_mechanism, provider_spec)?;
        } else {
            if provider_spec.value.is_some()
                || (provider_spec.buffer_present && provider_spec.buffer_len != 0)
            {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            let mut ffi_mech = mechanism_to_ffi(mechanism)?;
            if ffi_mech.ck_mechanism().pParameter.is_null()
                && ffi_mech.ck_mechanism().ulParameterLen == 0
            {
                ffi_mech.ck_mechanism_mut().pParameter = if provider_spec.buffer_present {
                    std::ptr::NonNull::<u8>::dangling().as_ptr().cast()
                } else {
                    std::ptr::null_mut()
                };
                ffi_mech.ck_mechanism_mut().ulParameterLen =
                    message_ck_ulong(provider_spec.buffer_len)?;
            } else {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            call_3x_fn!(
                self,
                func_list_3_0,
                C_MessageEncryptInit,
                Self::session_handle(session)?,
                ffi_mech.ck_mechanism_ptr(),
                Self::object_handle(key)?
            )?;
            validate_message_init_provider_ack(&ffi_mech.ck_mechanism(), provider_spec)?;
        }
        Ok(CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new),
        })
    }

    pub(super) fn ffi_message_encrypt_final(&self, session: CkSessionHandle) -> CkResult<()> {
        call_3x_fn!(self, func_list_3_0, C_MessageEncryptFinal, Self::session_handle(session)?)
    }

    // --- Message Decrypt ---

    pub(super) fn ffi_message_decrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        init_param: Option<&MessageParameter>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        match (mechanism, init_param) {
            // AEAD message-based init: reconstruct CK_*_MESSAGE_PARAMS.
            (Some(mech), Some(param)) => {
                let mut init_mech = build_message_init_mechanism(mech.mechanism_type.0, param)?;
                call_3x_fn!(
                    self,
                    func_list_3_0,
                    C_MessageDecryptInit,
                    Self::session_handle(session)?,
                    &mut init_mech.ck_mechanism as *mut cryptoki_sys::CK_MECHANISM,
                    Self::object_handle(key)?
                )
            }
            (Some(mech), None) => {
                let ffi_mech = mechanism_to_ffi(mech)?;
                call_3x_fn!(
                    &admission,
                    self,
                    func_list_3_0,
                    C_MessageDecryptInit,
                    Self::session_handle(session)?,
                    ffi_mech.ck_mechanism_ptr(),
                    Self::object_handle(key)?
                )
            }
            (None, _) => {
                // NULL mechanism = cancel active message-decrypt state
                call_3x_fn!(
                    &admission,
                    self,
                    func_list_3_0,
                    C_MessageDecryptInit,
                    Self::session_handle(session)?,
                    std::ptr::null_mut::<cryptoki_sys::CK_MECHANISM>(),
                    Self::object_handle(key)?
                )
            }
        }
    }

    pub(super) fn ffi_message_decrypt_init_contract(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        init_param: Option<&MessageParameter>,
        key: CkObjectHandle,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        if let Some(param) = init_param {
            let mut init_mech = build_message_init_mechanism(mechanism.mechanism_type.0, param)?;
            if !provider_spec.buffer_present
                || provider_spec.buffer_len != init_mech.ck_mechanism.ulParameterLen as u64
                || provider_spec.value.is_some()
            {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            call_3x_fn!(
                self,
                func_list_3_0,
                C_MessageDecryptInit,
                Self::session_handle(session)?,
                &mut init_mech.ck_mechanism,
                Self::object_handle(key)?
            )?;
            validate_message_init_provider_ack(&init_mech.ck_mechanism, provider_spec)?;
        } else {
            if provider_spec.value.is_some()
                || (provider_spec.buffer_present && provider_spec.buffer_len != 0)
            {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            let mut ffi_mech = mechanism_to_ffi(mechanism)?;
            if ffi_mech.ck_mechanism().pParameter.is_null()
                && ffi_mech.ck_mechanism().ulParameterLen == 0
            {
                ffi_mech.ck_mechanism_mut().pParameter = if provider_spec.buffer_present {
                    std::ptr::NonNull::<u8>::dangling().as_ptr().cast()
                } else {
                    std::ptr::null_mut()
                };
                ffi_mech.ck_mechanism_mut().ulParameterLen =
                    message_ck_ulong(provider_spec.buffer_len)?;
            } else {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            call_3x_fn!(
                self,
                func_list_3_0,
                C_MessageDecryptInit,
                Self::session_handle(session)?,
                ffi_mech.ck_mechanism_ptr(),
                Self::object_handle(key)?
            )?;
            validate_message_init_provider_ack(&ffi_mech.ck_mechanism(), provider_spec)?;
        }
        Ok(CkParameterRoundtripResult {
            ck_rv: CkRv::OK,
            returned_len: provider_spec.buffer_len,
            value: provider_spec.buffer_present.then(Vec::new),
        })
    }

    pub(super) fn ffi_message_decrypt_final(&self, session: CkSessionHandle) -> CkResult<()> {
        call_3x_fn!(self, func_list_3_0, C_MessageDecryptFinal, Self::session_handle(session)?)
    }

    // --- Message Sign ---

    pub(super) fn ffi_message_sign_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        match mechanism {
            Some(mech) => {
                let ffi_mech = mechanism_to_ffi(mech)?;
                call_3x_fn!(
                    &admission,
                    self,
                    func_list_3_0,
                    C_MessageSignInit,
                    Self::session_handle(session)?,
                    ffi_mech.ck_mechanism_ptr(),
                    Self::object_handle(key)?
                )
            }
            None => {
                // NULL mechanism = cancel active message-sign state
                call_3x_fn!(
                    &admission,
                    self,
                    func_list_3_0,
                    C_MessageSignInit,
                    Self::session_handle(session)?,
                    std::ptr::null_mut::<cryptoki_sys::CK_MECHANISM>(),
                    Self::object_handle(key)?
                )
            }
        }
    }

    pub(super) fn ffi_message_sign_final(&self, session: CkSessionHandle) -> CkResult<()> {
        call_3x_fn!(self, func_list_3_0, C_MessageSignFinal, Self::session_handle(session)?)
    }

    // --- Message Verify ---

    pub(super) fn ffi_message_verify_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        match mechanism {
            Some(mech) => {
                let ffi_mech = mechanism_to_ffi(mech)?;
                call_3x_fn!(
                    &admission,
                    self,
                    func_list_3_0,
                    C_MessageVerifyInit,
                    Self::session_handle(session)?,
                    ffi_mech.ck_mechanism_ptr(),
                    Self::object_handle(key)?
                )
            }
            None => {
                // NULL mechanism = cancel active message-verify state
                call_3x_fn!(
                    &admission,
                    self,
                    func_list_3_0,
                    C_MessageVerifyInit,
                    Self::session_handle(session)?,
                    std::ptr::null_mut::<cryptoki_sys::CK_MECHANISM>(),
                    Self::object_handle(key)?
                )
            }
        }
    }

    pub(super) fn ffi_message_verify_final(&self, session: CkSessionHandle) -> CkResult<()> {
        call_3x_fn!(self, func_list_3_0, C_MessageVerifyFinal, Self::session_handle(session)?)
    }

    // --- Encrypt Message (one-shot) ---
    // Returns (parameter_out, ciphertext).

    pub(super) fn ffi_encrypt_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: CkInBuf<'_>,
        plaintext: CkInBuf<'_>,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let (aad_ptr, aad_len) = native_message_input(aad)?;
        let (pt_ptr, pt_len) = native_message_input(plaintext)?;
        two_call_message!(
            &admission,
            self,
            C_EncryptMessage,
            parameter,
            [
                Self::session_handle(session)?,
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                aad_ptr as *mut _,
                aad_len,
                pt_ptr as *mut _,
                pt_len,
            ]
        )
    }

    // --- Encrypt Message Begin ---
    // Returns parameter_out.

    pub(super) fn ffi_encrypt_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: CkInBuf<'_>,
    ) -> CkResult<Vec<u8>> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (aad_ptr, aad_len) = native_message_input(aad)?;
        let rv = unsafe {
            f(
                Self::session_handle(session)?,
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                aad_ptr as *mut _,
                aad_len,
            )
        })?;
        Ok(parameter.to_vec().into())
    }

    pub(super) fn ffi_encrypt_message_begin_exact(
        &self,
        session: CkSessionHandle,
        aad: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        self.ffi_message_begin_empty_exact(
            &admission,
            session,
            aad,
            provider_spec,
            |session, parameter, len, aad, aad_len| unsafe {
                f(session, parameter, len, aad, aad_len)
            },
        )
    }

    pub(super) fn ffi_encrypt_message_begin_exact(
        &self,
        session: CkSessionHandle,
        aad: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        self.ffi_message_begin_empty_exact(
            session,
            aad,
            provider_spec,
            |session, parameter, len, aad, aad_len| unsafe {
                f(session, parameter, len, aad, aad_len)
            },
        )
    }

    // --- Encrypt Message Next ---
    // Returns (parameter_out, ciphertext_part).

    pub(super) fn ffi_encrypt_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        plaintext_part: CkInBuf<'_>,
        flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let (pt_ptr, pt_len) = native_message_input(plaintext_part)?;
        let flags = native_message_flags(flags)?;
        two_call_message!(
            &admission,
            self,
            C_EncryptMessageNext,
            parameter,
            [
                Self::session_handle(session)?,
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                pt_ptr as *mut _,
                pt_len,
            ],
            [flags,]
        )
    }

    // --- Decrypt Message (one-shot) ---
    // Returns (parameter_out, plaintext).

    pub(super) fn ffi_decrypt_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: CkInBuf<'_>,
        ciphertext: CkInBuf<'_>,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let (aad_ptr, aad_len) = native_message_input(aad)?;
        let (ct_ptr, ct_len) = native_message_input(ciphertext)?;
        two_call_message!(
            &admission,
            self,
            C_DecryptMessage,
            parameter,
            [
                Self::session_handle(session)?,
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                aad_ptr as *mut _,
                aad_len,
                ct_ptr as *mut _,
                ct_len,
            ]
        )
    }

    // --- Decrypt Message Begin ---
    // Returns parameter_out.

    pub(super) fn ffi_decrypt_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: CkInBuf<'_>,
    ) -> CkResult<Vec<u8>> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (aad_ptr, aad_len) = native_message_input(aad)?;
        let rv = unsafe {
            f(
                Self::session_handle(session)?,
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                aad_ptr as *mut _,
                aad_len,
            )
        })?;
        Ok(parameter.to_vec().into())
    }

    pub(super) fn ffi_decrypt_message_begin_exact(
        &self,
        session: CkSessionHandle,
        aad: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        self.ffi_message_begin_empty_exact(
            &admission,
            session,
            aad,
            provider_spec,
            |session, parameter, len, aad, aad_len| unsafe {
                f(session, parameter, len, aad, aad_len)
            },
        )
    }

    pub(super) fn ffi_decrypt_message_begin_exact(
        &self,
        session: CkSessionHandle,
        aad: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        self.ffi_message_begin_empty_exact(
            session,
            aad,
            provider_spec,
            |session, parameter, len, aad, aad_len| unsafe {
                f(session, parameter, len, aad, aad_len)
            },
        )
    }

    // --- Decrypt Message Next ---
    // Returns (parameter_out, plaintext_part).

    pub(super) fn ffi_decrypt_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        ciphertext_part: CkInBuf<'_>,
        flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let (ct_ptr, ct_len) = native_message_input(ciphertext_part)?;
        let flags = native_message_flags(flags)?;
        two_call_message!(
            &admission,
            self,
            C_DecryptMessageNext,
            parameter,
            [
                Self::session_handle(session)?,
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                ct_ptr as *mut _,
                ct_len,
            ],
            [flags,]
        )
    }

    // --- Sign Message (one-shot) ---
    // Returns (parameter_out, signature).

    pub(super) fn ffi_sign_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        data: CkInBuf<'_>,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let (data_ptr, data_len) = native_message_input(data)?;
        two_call_message!(
            &admission,
            self,
            C_SignMessage,
            parameter,
            [
                Self::session_handle(session)?,
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                data_ptr as *mut _,
                data_len,
            ]
        )
    }

    // --- Sign Message Begin ---
    // Returns parameter_out.

    pub(super) fn ffi_sign_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let rv = unsafe {
            f(
                Self::session_handle(session)?,
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
            )
        };
        Self::ck_result(rv)?;
        Ok(parameter.to_vec())
    }

    pub(super) fn ffi_sign_message_begin_exact(
        &self,
        session: CkSessionHandle,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let (parameter, parameter_len) = empty_only_parameter_pointer(provider_spec)?;
        let rv = unsafe { f(Self::session_handle(session)?, parameter, parameter_len) };
        Self::ck_result(rv)?;
        Ok(empty_parameter_ack(provider_spec))
    }

    // --- Sign Message Next ---
    // Returns (parameter_out, signature).
    // If request_signature is false, signature is empty (more data feeding).

    pub(super) fn ffi_sign_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        data_part: CkInBuf<'_>,
        request_signature: bool,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (dp_ptr, dp_len) = native_message_input(data_part)?;

        if !request_signature {
            // Feed data — pSignature is NULL, pulSignatureLen is NULL
            let rv = unsafe {
                f(
                    Self::session_handle(session)?,
                    parameter.as_mut_ptr() as *mut _,
                    Self::ulong_len(parameter.len()),
                    dp_ptr as *mut _,
                    dp_len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            })?;
            let parameter_out = parameter.to_vec();
            return Ok((parameter_out.into(), Vec::new().into()));
        }

        // Final call — request signature via two-call pattern
        let _session_fence = self.session_fences.enter(&admission, session)?;
        two_call_message!(
            &admission,
            self,
            C_SignMessageNext,
            parameter,
            [
                Self::session_handle(session)?,
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                dp_ptr as *mut _,
                dp_len,
            ]
        )
    }

    pub(super) fn ffi_sign_message_next_feed_exact(
        &self,
        session: CkSessionHandle,
        data_part: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let (parameter, parameter_len) = empty_only_parameter_pointer(provider_spec)?;
        let (data, data_len) = native_message_input(data_part)?;
        let rv = unsafe {
            f(
                Self::session_handle(session)?,
                parameter,
                parameter_len,
                data as *mut _,
                data_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        Self::ck_result(rv)?;
        Ok(empty_parameter_ack(provider_spec))
    }

    // --- Verify Message (one-shot) ---
    // No output buffer. Parameter is input-only.

    pub(super) fn ffi_verify_message(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        data: CkInBuf<'_>,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        let (data_ptr, data_len) = native_message_input(data)?;
        let (sig_ptr, sig_len) = native_message_input(signature)?;
        call_3x_fn!(
            &admission,
            self,
            func_list_3_0,
            C_VerifyMessage,
            Self::session_handle(session)?,
            parameter.as_ptr() as *mut _,
            Self::ulong_len(parameter.len()),
            data_ptr as *mut _,
            data_len,
            sig_ptr as *mut _,
            sig_len
        )
    }

    pub(super) fn ffi_verify_message_exact(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        signature: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_VerifyMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let (parameter, parameter_len) = empty_only_parameter_pointer(provider_spec)?;
        let (data, data_len) = native_message_input(data)?;
        let (signature, signature_len) = native_message_input(signature)?;
        let rv = unsafe {
            f(
                Self::session_handle(session)?,
                parameter,
                parameter_len,
                data as *mut _,
                data_len,
                signature as *mut _,
                signature_len,
            )
        };
        Self::ck_result(rv)?;
        Ok(empty_parameter_ack(provider_spec))
    }

    // --- Verify Message Begin ---
    // No output buffer. Parameter is input-only.

    pub(super) fn ffi_verify_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        call_3x_fn!(
            &admission,
            self,
            func_list_3_0,
            C_VerifyMessageBegin,
            Self::session_handle(session)?,
            parameter.as_ptr() as *mut _,
            Self::ulong_len(parameter.len())
        )
    }

    pub(super) fn ffi_verify_message_begin_exact(
        &self,
        session: CkSessionHandle,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_VerifyMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let (parameter, parameter_len) = empty_only_parameter_pointer(provider_spec)?;
        let rv = unsafe { f(Self::session_handle(session)?, parameter, parameter_len) };
        Self::ck_result(rv)?;
        Ok(empty_parameter_ack(provider_spec))
    }

    // --- Verify Message Next ---
    // No output buffer. Parameter is input-only.
    // If is_final is true, signature is provided for verification.
    // If is_final is false, pSignature is NULL (feed data).

    pub(super) fn ffi_verify_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        data_part: CkInBuf<'_>,
        is_final: bool,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_VerifyMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (dp_ptr, dp_len) = native_message_input(data_part)?;
        let (raw_sig_ptr, raw_sig_len) = signature.as_ptr_len();
        let (sig_ptr, sig_len) = if is_final {
            (raw_sig_ptr as *mut _, narrow_wire_ulong(raw_sig_len)?)
        } else {
            (std::ptr::null_mut(), 0)
        };

        let rv = unsafe {
            f(
                Self::session_handle(session)?,
                parameter.as_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                dp_ptr as *mut _,
                dp_len,
                sig_ptr,
                sig_len,
            )
        })
    }

    pub(super) fn ffi_verify_message_next_exact(
        &self,
        session: CkSessionHandle,
        data_part: CkInBuf<'_>,
        is_final: bool,
        signature: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_VerifyMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let (parameter, parameter_len) = empty_only_parameter_pointer(provider_spec)?;
        let (data, data_len) = native_message_input(data_part)?;
        let (raw_signature, raw_signature_len) = signature.as_ptr_len();
        let (signature, signature_len) = if is_final {
            (raw_signature as *mut _, narrow_wire_ulong(raw_signature_len)?)
        } else {
            (std::ptr::null_mut(), 0)
        };
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(&admission, Some(f), |function| unsafe {
            function(
                h_session,
                parameter,
                parameter_len,
                data as *mut _,
                data_len,
                signature,
                signature_len,
            )
        })?;
        Ok(empty_parameter_ack(provider_spec))
    }

    pub(super) fn ffi_verify_message_next_exact(
        &self,
        session: CkSessionHandle,
        data_part: CkInBuf<'_>,
        is_final: bool,
        signature: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_VerifyMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let (parameter, parameter_len) = empty_only_parameter_pointer(provider_spec)?;
        let (data, data_len) = native_message_input(data_part)?;
        let (raw_signature, raw_signature_len) = signature.as_ptr_len();
        let (signature, signature_len) = if is_final {
            (raw_signature as *mut _, narrow_wire_ulong(raw_signature_len)?)
        } else {
            (std::ptr::null_mut(), 0)
        };
        let rv = unsafe {
            f(
                Self::session_handle(session)?,
                parameter,
                parameter_len,
                data as *mut _,
                data_len,
                signature,
                signature_len,
            )
        };
        Self::ck_result(rv)?;
        Ok(empty_parameter_ack(provider_spec))
    }

    // --- Exact parameter-output message operations (Track C) ---

    pub(super) fn ffi_encrypt_message_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: CkInBuf<'_>,
        plaintext: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (aad_ptr, aad_len) = native_message_input(aad)?;
        let (pt_ptr, pt_len) = native_message_input(plaintext)?;
        let h_session = Self::session_handle(session)?;
        Self::single_call_parameter_output_exact(
            &admission,
            output_spec,
            parameter,
            param_out_spec,
            |param_ptr, param_len, output, output_len| unsafe {
                f(
                    h_session,
                    param_ptr as *mut _,
                    param_len,
                    aad_ptr as *mut _,
                    aad_len,
                    pt_ptr as *mut _,
                    pt_len,
                    output,
                    output_len,
                )
            },
        )
    }

    pub(super) fn ffi_decrypt_message_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: CkInBuf<'_>,
        ciphertext: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (aad_ptr, aad_len) = native_message_input(aad)?;
        let (ct_ptr, ct_len) = native_message_input(ciphertext)?;
        let h_session = Self::session_handle(session)?;
        Self::single_call_parameter_output_exact(
            &admission,
            output_spec,
            parameter,
            param_out_spec,
            |param_ptr, param_len, output, output_len| unsafe {
                f(
                    h_session,
                    param_ptr as *mut _,
                    param_len,
                    aad_ptr as *mut _,
                    aad_len,
                    ct_ptr as *mut _,
                    ct_len,
                    output,
                    output_len,
                )
            },
        )
    }

    pub(super) fn ffi_sign_message_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        data: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        if !parameter.is_empty() {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        validate_empty_only_parameter_spec(param_out_spec)?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (data_ptr, data_len) = native_message_input(data)?;
        let h_session = Self::session_handle(session)?;
        Self::single_call_parameter_output_exact(
            &admission,
            output_spec,
            parameter,
            param_out_spec,
            |param_ptr, param_len, output, output_len| unsafe {
                f(
                    h_session,
                    param_ptr as *mut _,
                    param_len,
                    data_ptr as *mut _,
                    data_len,
                    output,
                    output_len,
                )
            },
        )
    }

    pub(super) fn ffi_encrypt_message_next_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        plaintext_part: CkInBuf<'_>,
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (pt_ptr, pt_len) = native_message_input(plaintext_part)?;
        let flags = native_message_flags(flags)?;
        let h_session = Self::session_handle(session)?;
        Self::single_call_parameter_output_exact(
            &admission,
            output_spec,
            parameter,
            param_out_spec,
            |param_ptr, param_len, output, output_len| unsafe {
                f(
                    h_session,
                    param_ptr as *mut _,
                    param_len,
                    pt_ptr as *mut _,
                    pt_len,
                    output,
                    output_len,
                    flags,
                )
            },
        )
    }

    pub(super) fn ffi_decrypt_message_next_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        ciphertext_part: CkInBuf<'_>,
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (ct_ptr, ct_len) = native_message_input(ciphertext_part)?;
        let flags = native_message_flags(flags)?;
        let h_session = Self::session_handle(session)?;
        Self::single_call_parameter_output_exact(
            &admission,
            output_spec,
            parameter,
            param_out_spec,
            |param_ptr, param_len, output, output_len| unsafe {
                f(
                    h_session,
                    param_ptr as *mut _,
                    param_len,
                    ct_ptr as *mut _,
                    ct_len,
                    output,
                    output_len,
                    flags,
                )
            },
        )
    }

    pub(super) fn ffi_sign_message_next_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        data_part: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        if !parameter.is_empty() {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        validate_empty_only_parameter_spec(param_out_spec)?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (dp_ptr, dp_len) = native_message_input(data_part)?;
        let h_session = Self::session_handle(session)?;
        Self::single_call_parameter_output_exact(
            &admission,
            output_spec,
            parameter,
            param_out_spec,
            |param_ptr, param_len, output, output_len| unsafe {
                f(
                    h_session,
                    param_ptr as *mut _,
                    param_len,
                    dp_ptr as *mut _,
                    dp_len,
                    output,
                    output_len,
                )
            },
        )
    }

    // =======================================================================
    // Structured message-parameter exact operations
    //
    // These take a `MessageParameter` (which carries the actual IV/tag/nonce
    // data safely, without embedded pointers) and reconstruct a valid
    // CK_*_MESSAGE_PARAMS C struct with local pointers for the FFI call.
    // =======================================================================

    fn ffi_message_begin_empty_exact<F>(
        &self,
        session: CkSessionHandle,
        aad: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
        call: F,
    ) -> CkResult<CkParameterRoundtripResult>
    where
        F: FnOnce(
            cryptoki_sys::CK_SESSION_HANDLE,
            *mut std::ffi::c_void,
            cryptoki_sys::CK_ULONG,
            *mut cryptoki_sys::CK_BYTE,
            cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        let (parameter, parameter_len) = empty_parameter_pointer(provider_spec)?;
        let (aad_ptr, aad_len) = native_message_input(aad)?;
        let rv = call(
            Self::session_handle(session)?,
            parameter,
            parameter_len,
            aad_ptr as *mut _,
            aad_len,
        );
        let mut acknowledgement = empty_parameter_ack(provider_spec);
        acknowledgement.ck_rv = CkRv(rv as u64);
        Ok(acknowledgement)
    }

    /// Common helper: call a message crypto FFI function with a GCM message
    /// parameter struct.  Allocates local IV and tag buffers, constructs the
    /// C struct, makes the call, and reads back the (possibly modified) IV
    /// and tag data.
    fn call_with_gcm_message_param<F>(
        &self,
        _admission: &OrdinaryGuard,
        gcm: &GcmMessageParams,
        output_spec: &CkOutputBufferSpec,
        mut call: F,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)>
    where
        F: FnMut(
            *mut cryptoki_sys::CK_GCM_MESSAGE_PARAMS,
            *mut cryptoki_sys::CK_BYTE,
            *mut cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        gcm.validate_for_native_ulong(native_ulong_max())?;
        let iv_len = gcm.iv_null_len.unwrap_or(gcm.iv.len() as u64);
        let ul_iv_len = message_ck_ulong(iv_len)?;
        let ul_iv_fixed_bits = message_ck_ulong(gcm.iv_fixed_bits)?;
        let iv_generator = message_ck_ulong(gcm.iv_generator)?;
        let ul_tag_bits = message_ck_ulong(gcm.tag_bits)?;
        let mut iv_buf = gcm.iv.clone();
        let mut tag_buf = gcm.tag.clone();

        let mut ck_params = cryptoki_sys::CK_GCM_MESSAGE_PARAMS {
            pIv: message_pointer(&mut iv_buf, gcm.iv_null_len),
            ulIvLen: ul_iv_len,
            ulIvFixedBits: ul_iv_fixed_bits,
            ivGenerator: iv_generator,
            pTag: message_pointer(&mut tag_buf, gcm.tag_null_len),
            ulTagBits: ul_tag_bits,
        };

        let mut out_len: cryptoki_sys::CK_ULONG = 0;

        if output_spec.length_pointer_null {
            let output = if output_spec.buffer_present {
                std::ptr::NonNull::<cryptoki_sys::CK_BYTE>::dangling().as_ptr()
            } else {
                std::ptr::null_mut()
            };
            let rv = CkRv(call(&mut ck_params, output, std::ptr::null_mut()) as u64);
            if rv != CkRv::OK && rv != CkRv::BUFFER_TOO_SMALL {
                return Err(rv);
            }
            return Ok((
                CkOutputBufferResult { ck_rv: rv, returned_len: Some(0), value: None },
                MessageParameter::GcmMessage(GcmMessageParams {
                    iv: iv_buf,
                    iv_null_len: gcm.iv_null_len,
                    iv_fixed_bits: gcm.iv_fixed_bits,
                    iv_generator: gcm.iv_generator,
                    tag: tag_buf,
                    tag_null_len: gcm.tag_null_len,
                    tag_bits: gcm.tag_bits,
                }),
            ));
        }

        if !output_spec.buffer_present {
            // Size query
            let rv = call(&mut ck_params, std::ptr::null_mut(), &mut out_len);
            if rv == CkRv::OK.0 as cryptoki_sys::CK_RV {
                let result_gcm = GcmMessageParams {
                    iv: iv_buf,
                    iv_null_len: gcm.iv_null_len,
                    iv_fixed_bits: gcm.iv_fixed_bits,
                    iv_generator: gcm.iv_generator,
                    tag: tag_buf,
                    tag_null_len: gcm.tag_null_len,
                    tag_bits: gcm.tag_bits,
                };
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::OK,
                        returned_len: Some(out_len as u64),
                        value: None,
                    },
                    MessageParameter::GcmMessage(result_gcm),
                ))
            } else {
                Err(CkRv(rv as u64))
            }
        } else {
            let capped = super::call_helpers::capped_output_len(output_spec.buffer_len);
            out_len = capped as cryptoki_sys::CK_ULONG;
            let mut buf = vec![0u8; capped];
            let rv = call(&mut ck_params, buf.as_mut_ptr(), &mut out_len);

            if rv == CkRv::OK.0 as cryptoki_sys::CK_RV {
                buf.truncate(out_len as usize);
                let result_gcm = GcmMessageParams {
                    iv: iv_buf,
                    iv_null_len: gcm.iv_null_len,
                    iv_fixed_bits: gcm.iv_fixed_bits,
                    iv_generator: gcm.iv_generator,
                    tag: tag_buf,
                    tag_null_len: gcm.tag_null_len,
                    tag_bits: gcm.tag_bits,
                };
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::OK,
                        returned_len: Some(out_len as u64),
                        value: Some(buf),
                    },
                    MessageParameter::GcmMessage(result_gcm),
                ))
            } else if rv == CkRv::BUFFER_TOO_SMALL.0 as cryptoki_sys::CK_RV {
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::BUFFER_TOO_SMALL,
                        returned_len: Some(out_len as u64),
                        value: None,
                    },
                    MessageParameter::GcmMessage(GcmMessageParams {
                        iv: iv_buf,
                        iv_null_len: gcm.iv_null_len,
                        iv_fixed_bits: gcm.iv_fixed_bits,
                        iv_generator: gcm.iv_generator,
                        tag: tag_buf,
                        tag_null_len: gcm.tag_null_len,
                        tag_bits: gcm.tag_bits,
                    }),
                ))
            } else {
                Err(CkRv(rv as u64))
            }
        }
    }

    /// Common helper: call a message crypto FFI function with a CCM
    /// message-parameter struct. CCM has a fixed `ulDataLen` (caller
    /// supplies the total ciphertext/plaintext length) and a
    /// HSM-mutable nonce + MAC.  Mirror of
    /// [`Self::call_with_gcm_message_param`].
    fn call_with_ccm_message_param<F>(
        &self,
        _admission: &OrdinaryGuard,
        ccm: &CcmMessageParams,
        output_spec: &CkOutputBufferSpec,
        mut call: F,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)>
    where
        F: FnMut(
            *mut cryptoki_sys::CK_CCM_MESSAGE_PARAMS,
            *mut cryptoki_sys::CK_BYTE,
            *mut cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        ccm.validate_for_native_ulong(native_ulong_max())?;
        let nonce_len = ccm.nonce_null_len.unwrap_or(ccm.nonce.len() as u64);
        let ul_data_len = message_ck_ulong(ccm.data_len)?;
        let ul_nonce_len = message_ck_ulong(nonce_len)?;
        let ul_nonce_fixed_bits = message_ck_ulong(ccm.nonce_fixed_bits)?;
        let nonce_generator = message_ck_ulong(ccm.nonce_generator)?;
        let ul_mac_len = message_ck_ulong(ccm.mac_len)?;
        let mut nonce_buf = ccm.nonce.clone();
        let mut mac_buf = ccm.mac.clone();

        let mut ck_params = cryptoki_sys::CK_CCM_MESSAGE_PARAMS {
            ulDataLen: ul_data_len,
            pNonce: message_pointer(&mut nonce_buf, ccm.nonce_null_len),
            ulNonceLen: ul_nonce_len,
            ulNonceFixedBits: ul_nonce_fixed_bits,
            nonceGenerator: nonce_generator,
            pMAC: message_pointer(&mut mac_buf, ccm.mac_null_len),
            ulMACLen: ul_mac_len,
        };

        let mut out_len: cryptoki_sys::CK_ULONG = 0;
        let snapshot = |nonce_buf: &Vec<u8>, mac_buf: &Vec<u8>| {
            MessageParameter::CcmMessage(CcmMessageParams {
                data_len: ccm.data_len,
                nonce: nonce_buf.clone(),
                nonce_null_len: ccm.nonce_null_len,
                nonce_fixed_bits: ccm.nonce_fixed_bits,
                nonce_generator: ccm.nonce_generator,
                mac: mac_buf.clone(),
                mac_null_len: ccm.mac_null_len,
                mac_len: ccm.mac_len,
            })
        };

        if output_spec.length_pointer_null {
            let output = if output_spec.buffer_present {
                std::ptr::NonNull::<cryptoki_sys::CK_BYTE>::dangling().as_ptr()
            } else {
                std::ptr::null_mut()
            };
            let rv = CkRv(call(&mut ck_params, output, std::ptr::null_mut()) as u64);
            if rv != CkRv::OK && rv != CkRv::BUFFER_TOO_SMALL {
                return Err(rv);
            }
            return Ok((
                CkOutputBufferResult { ck_rv: rv, returned_len: Some(0), value: None },
                snapshot(&nonce_buf, &mac_buf),
            ));
        }

        if !output_spec.buffer_present {
            let rv = call(&mut ck_params, std::ptr::null_mut(), &mut out_len);
            if rv == CkRv::OK.0 as cryptoki_sys::CK_RV {
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::OK,
                        returned_len: Some(out_len as u64),
                        value: None,
                    },
                    snapshot(&nonce_buf, &mac_buf),
                ))
            } else {
                Err(CkRv(rv as u64))
            }
        } else {
            let capped = super::call_helpers::capped_output_len(output_spec.buffer_len);
            out_len = capped as cryptoki_sys::CK_ULONG;
            let mut buf = vec![0u8; capped];
            let rv = call(&mut ck_params, buf.as_mut_ptr(), &mut out_len);
            if rv == CkRv::OK.0 as cryptoki_sys::CK_RV {
                buf.truncate(out_len as usize);
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::OK,
                        returned_len: Some(out_len as u64),
                        value: Some(buf),
                    },
                    snapshot(&nonce_buf, &mac_buf),
                ))
            } else if rv == CkRv::BUFFER_TOO_SMALL.0 as cryptoki_sys::CK_RV {
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::BUFFER_TOO_SMALL,
                        returned_len: Some(out_len as u64),
                        value: None,
                    },
                    snapshot(&nonce_buf, &mac_buf),
                ))
            } else {
                Err(CkRv(rv as u64))
            }
        }
    }

    /// Common helper: call a message crypto FFI function with a
    /// Salsa20/ChaCha20-Poly1305 message-parameter struct.  The C
    /// struct has only `pNonce`/`ulNonceLen`/`pTag` — caller provides
    /// the nonce, HSM populates the tag.
    fn call_with_salsa20_chacha20_poly1305_message_param<F>(
        &self,
        _admission: &OrdinaryGuard,
        params: &Salsa20ChaCha20Poly1305MessageParams,
        output_spec: &CkOutputBufferSpec,
        mut call: F,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)>
    where
        F: FnMut(
            *mut cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS,
            *mut cryptoki_sys::CK_BYTE,
            *mut cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        params.validate_for_native_ulong(native_ulong_max())?;
        let ul_nonce_len = message_ck_ulong(params.nonce_bits)?;
        let mut nonce_buf = params.nonce.clone();
        let mut tag_buf = params.tag.clone();

        let mut ck_params = cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS {
            pNonce: message_pointer(&mut nonce_buf, params.nonce_null_len),
            ulNonceLen: ul_nonce_len,
            pTag: message_pointer(&mut tag_buf, params.tag_null_len),
        };

        let mut out_len: cryptoki_sys::CK_ULONG = 0;
        let snapshot = |nonce_buf: &Vec<u8>, tag_buf: &Vec<u8>| {
            MessageParameter::SalaChacha(Salsa20ChaCha20Poly1305MessageParams {
                nonce: nonce_buf.clone(),
                nonce_bits: params.nonce_bits,
                nonce_null_len: params.nonce_null_len,
                tag: tag_buf.clone(),
                tag_null_len: params.tag_null_len,
            })
        };

        if output_spec.length_pointer_null {
            let output = if output_spec.buffer_present {
                std::ptr::NonNull::<cryptoki_sys::CK_BYTE>::dangling().as_ptr()
            } else {
                std::ptr::null_mut()
            };
            let rv = CkRv(call(&mut ck_params, output, std::ptr::null_mut()) as u64);
            if rv != CkRv::OK && rv != CkRv::BUFFER_TOO_SMALL {
                return Err(rv);
            }
            return Ok((
                CkOutputBufferResult { ck_rv: rv, returned_len: Some(0), value: None },
                snapshot(&nonce_buf, &tag_buf),
            ));
        }

        if !output_spec.buffer_present {
            let rv = call(&mut ck_params, std::ptr::null_mut(), &mut out_len);
            if rv == CkRv::OK.0 as cryptoki_sys::CK_RV {
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::OK,
                        returned_len: Some(out_len as u64),
                        value: None,
                    },
                    snapshot(&nonce_buf, &tag_buf),
                ))
            } else {
                Err(CkRv(rv as u64))
            }
        } else {
            let capped = super::call_helpers::capped_output_len(output_spec.buffer_len);
            out_len = capped as cryptoki_sys::CK_ULONG;
            let mut buf = vec![0u8; capped];
            let rv = call(&mut ck_params, buf.as_mut_ptr(), &mut out_len);
            if rv == CkRv::OK.0 as cryptoki_sys::CK_RV {
                buf.truncate(out_len as usize);
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::OK,
                        returned_len: Some(out_len as u64),
                        value: Some(buf),
                    },
                    snapshot(&nonce_buf, &tag_buf),
                ))
            } else if rv == CkRv::BUFFER_TOO_SMALL.0 as cryptoki_sys::CK_RV {
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::BUFFER_TOO_SMALL,
                        returned_len: Some(out_len as u64),
                        value: None,
                    },
                    snapshot(&nonce_buf, &tag_buf),
                ))
            } else {
                Err(CkRv(rv as u64))
            }
        }
    }

    fn ffi_message_begin_msg_impl<F>(
        &self,
        msg_param: &MessageParameter,
        aad: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
        encrypt: bool,
        mut call: F,
    ) -> CkResult<(CkParameterRoundtripResult, MessageEffects)>
    where
        F: FnMut(
            *mut std::ffi::c_void,
            cryptoki_sys::CK_ULONG,
            *mut cryptoki_sys::CK_BYTE,
            cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        let mut acknowledgement = structured_parameter_ack(msg_param, provider_spec, CkRv::OK)?;
        let (aad_ptr, aad_len) = native_message_input(aad)?;
        let native = build_message_init_mechanism(0, msg_param)?;
        let rv = CkRv(call(
            native.ck_mechanism.pParameter,
            native.ck_mechanism.ulParameterLen,
            aad_ptr.cast_mut(),
            aad_len,
        ) as u64);
        acknowledgement.ck_rv = rv;
        let effects = if native.validate_authenticated_inputs(msg_param).is_ok() {
            MessageEffects::capture(
                msg_param,
                &native.authenticated_output(msg_param),
                MessageEffectContext {
                    mode: ParameterEffectCallMode::Begin,
                    encrypt,
                    generated_stage: true,
                    auth_stage: false,
                    rv,
                },
            )
        } else {
            MessageEffects::Invalid(OutputContractViolation::ParameterIntegrity)
        };
        Ok((acknowledgement, effects))
    }

    pub(super) fn ffi_encrypt_message_begin_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        aad: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkParameterRoundtripResult, MessageEffects)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let h_session = Self::session_handle(session)?;
        self.ffi_message_begin_msg_impl(
            msg_param,
            aad,
            provider_spec,
            true,
            |parameter, len, aad, aad_len| unsafe { f(h_session, parameter, len, aad, aad_len) },
        )
    }

    pub(super) fn ffi_decrypt_message_begin_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        aad: CkInBuf<'_>,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkParameterRoundtripResult, MessageEffects)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let h_session = Self::session_handle(session)?;
        self.ffi_message_begin_msg_impl(
            msg_param,
            aad,
            provider_spec,
            false,
            |parameter, len, aad, aad_len| unsafe { f(h_session, parameter, len, aad, aad_len) },
        )
    }

    /// C_EncryptMessage with structured GCM message parameter.
    pub(super) fn ffi_encrypt_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        aad: CkInBuf<'_>,
        plaintext: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult, MessageEffects)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let acknowledgement = structured_parameter_ack(msg_param, provider_spec, CkRv::OK)?;
        let (input_ptr, input_len) = native_message_input(plaintext)?;
        let (aad_ptr, aad_len) = native_message_input(aad)?;
        let native = build_message_init_mechanism(0, msg_param)?;
        let h_session = Self::session_handle(session)?;
        let output = Self::single_call_bytes_exact(output_spec, |buffer, length| unsafe {
            f(
                h_session,
                native.ck_mechanism.pParameter,
                native.ck_mechanism.ulParameterLen,
                aad_ptr.cast_mut(),
                aad_len,
                input_ptr.cast_mut(),
                input_len,
                buffer,
                length,
            )
        })?;
        let context = MessageEffectContext {
            mode: ParameterEffectCallMode::from_output_spec(output_spec),
            encrypt: true,
            generated_stage: true,
            auth_stage: true,
            rv: output.ck_rv,
        };
        let effects = if native.validate_authenticated_inputs(msg_param).is_ok() {
            MessageEffects::capture(msg_param, &native.authenticated_output(msg_param), context)
        } else {
            MessageEffects::Invalid(OutputContractViolation::ParameterIntegrity)
        };
        let acknowledgement = CkParameterRoundtripResult { ck_rv: output.ck_rv, ..acknowledgement };
        Ok((output, acknowledgement, effects))
    }

    /// C_DecryptMessage with structured message parameter.
    pub(super) fn ffi_decrypt_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        aad: CkInBuf<'_>,
        ciphertext: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult, MessageEffects)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let acknowledgement = structured_parameter_ack(msg_param, provider_spec, CkRv::OK)?;
        let (input_ptr, input_len) = native_message_input(ciphertext)?;
        let (aad_ptr, aad_len) = native_message_input(aad)?;
        let native = build_message_init_mechanism(0, msg_param)?;
        let h_session = Self::session_handle(session)?;
        let output = Self::single_call_bytes_exact(output_spec, |buffer, length| unsafe {
            f(
                h_session,
                native.ck_mechanism.pParameter,
                native.ck_mechanism.ulParameterLen,
                aad_ptr.cast_mut(),
                aad_len,
                input_ptr.cast_mut(),
                input_len,
                buffer,
                length,
            )
        })?;
        let context = MessageEffectContext {
            mode: ParameterEffectCallMode::from_output_spec(output_spec),
            encrypt: false,
            generated_stage: true,
            auth_stage: true,
            rv: output.ck_rv,
        };
        let effects = if native.validate_authenticated_inputs(msg_param).is_ok() {
            MessageEffects::capture(msg_param, &native.authenticated_output(msg_param), context)
        } else {
            MessageEffects::Invalid(OutputContractViolation::ParameterIntegrity)
        };
        let acknowledgement = CkParameterRoundtripResult { ck_rv: output.ck_rv, ..acknowledgement };
        Ok((output, acknowledgement, effects))
    }

    /// C_SignMessage with structured message parameter.
    pub(super) fn ffi_sign_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        data: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (data_ptr, data_len) = native_message_input(data)?;
        let h_session = Self::session_handle(session)?;
        match msg_param {
            MessageParameter::GcmMessage(gcm) => self.call_with_gcm_message_param(
                &admission,
                gcm,
                output_spec,
                |params, output, output_len| unsafe {
                    f(
                        h_session,
                        params as *mut _ as *mut _,
                        std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>()
                            as cryptoki_sys::CK_ULONG,
                        data_ptr as *mut _,
                        data_len,
                        output,
                        output_len,
                    )
                },
            ),
            MessageParameter::CcmMessage(ccm) => self.call_with_ccm_message_param(
                &admission,
                ccm,
                output_spec,
                |params, output, output_len| unsafe {
                    f(
                        h_session,
                        params as *mut _ as *mut _,
                        std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>()
                            as cryptoki_sys::CK_ULONG,
                        data_ptr as *mut _,
                        data_len,
                        output,
                        output_len,
                    )
                },
            ),
            MessageParameter::SalaChacha(params_in) => self
                .call_with_salsa20_chacha20_poly1305_message_param(
                    &admission,
                    params_in,
                    output_spec,
                    |params, output, output_len| unsafe {
                        f(
                            h_session,
                            params as *mut _ as *mut _,
                            std::mem::size_of::<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>()
                                as cryptoki_sys::CK_ULONG,
                            data_ptr as *mut _,
                            data_len,
                            output,
                            output_len,
                        )
                    },
                ),
            _ => Err(CkRv::FUNCTION_NOT_SUPPORTED),
        }
    }

    /// C_EncryptMessageNext with structured message parameter.
    pub(super) fn ffi_encrypt_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        plaintext_part: CkInBuf<'_>,
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult, MessageEffects)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let acknowledgement = structured_parameter_ack(msg_param, provider_spec, CkRv::OK)?;
        let (input_ptr, input_len) = native_message_input(plaintext_part)?;
        let flags = native_message_flags(flags)?;
        let native = build_message_init_mechanism(0, msg_param)?;
        let h_session = Self::session_handle(session)?;
        let output = Self::single_call_bytes_exact(output_spec, |buffer, length| unsafe {
            f(
                h_session,
                native.ck_mechanism.pParameter,
                native.ck_mechanism.ulParameterLen,
                input_ptr.cast_mut(),
                input_len,
                buffer,
                length,
                flags,
            )
        })?;
        let context = MessageEffectContext {
            mode: ParameterEffectCallMode::from_output_spec(output_spec),
            encrypt: true,
            generated_stage: false,
            auth_stage: flags & cryptoki_sys::CKF_END_OF_MESSAGE != 0,
            rv: output.ck_rv,
        };
        let effects = if native.validate_authenticated_inputs(msg_param).is_ok() {
            MessageEffects::capture(msg_param, &native.authenticated_output(msg_param), context)
        } else {
            MessageEffects::Invalid(OutputContractViolation::ParameterIntegrity)
        };
        let acknowledgement = CkParameterRoundtripResult { ck_rv: output.ck_rv, ..acknowledgement };
        Ok((output, acknowledgement, effects))
    }

    /// C_DecryptMessageNext with structured message parameter.
    pub(super) fn ffi_decrypt_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        ciphertext_part: CkInBuf<'_>,
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult, MessageEffects)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let acknowledgement = structured_parameter_ack(msg_param, provider_spec, CkRv::OK)?;
        let (input_ptr, input_len) = native_message_input(ciphertext_part)?;
        let flags = native_message_flags(flags)?;
        let native = build_message_init_mechanism(0, msg_param)?;
        let h_session = Self::session_handle(session)?;
        let output = Self::single_call_bytes_exact(output_spec, |buffer, length| unsafe {
            f(
                h_session,
                native.ck_mechanism.pParameter,
                native.ck_mechanism.ulParameterLen,
                input_ptr.cast_mut(),
                input_len,
                buffer,
                length,
                flags,
            )
        })?;
        let context = MessageEffectContext {
            mode: ParameterEffectCallMode::from_output_spec(output_spec),
            encrypt: false,
            generated_stage: false,
            auth_stage: flags & cryptoki_sys::CKF_END_OF_MESSAGE != 0,
            rv: output.ck_rv,
        };
        let effects = if native.validate_authenticated_inputs(msg_param).is_ok() {
            MessageEffects::capture(msg_param, &native.authenticated_output(msg_param), context)
        } else {
            MessageEffects::Invalid(OutputContractViolation::ParameterIntegrity)
        };
        let acknowledgement = CkParameterRoundtripResult { ck_rv: output.ck_rv, ..acknowledgement };
        Ok((output, acknowledgement, effects))
    }

    /// C_SignMessageNext with structured message parameter.
    pub(super) fn ffi_sign_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        data_part: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (dp_ptr, dp_len) = native_message_input(data_part)?;
        let h_session = Self::session_handle(session)?;
        match msg_param {
            MessageParameter::GcmMessage(gcm) => self.call_with_gcm_message_param(
                &admission,
                gcm,
                output_spec,
                |params, output, output_len| unsafe {
                    f(
                        h_session,
                        params as *mut _ as *mut _,
                        std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>()
                            as cryptoki_sys::CK_ULONG,
                        dp_ptr as *mut _,
                        dp_len,
                        output,
                        output_len,
                    )
                },
            ),
            MessageParameter::CcmMessage(ccm) => self.call_with_ccm_message_param(
                &admission,
                ccm,
                output_spec,
                |params, output, output_len| unsafe {
                    f(
                        h_session,
                        params as *mut _ as *mut _,
                        std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>()
                            as cryptoki_sys::CK_ULONG,
                        dp_ptr as *mut _,
                        dp_len,
                        output,
                        output_len,
                    )
                },
            ),
            MessageParameter::SalaChacha(params_in) => self
                .call_with_salsa20_chacha20_poly1305_message_param(
                    &admission,
                    params_in,
                    output_spec,
                    |params, output, output_len| unsafe {
                        f(
                            h_session,
                            params as *mut _ as *mut _,
                            std::mem::size_of::<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>()
                                as cryptoki_sys::CK_ULONG,
                            dp_ptr as *mut _,
                            dp_len,
                            output,
                            output_len,
                        )
                    },
                ),
            _ => Err(CkRv::FUNCTION_NOT_SUPPORTED),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ENCRYPT_BEGIN_PROVIDER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static ENCRYPT_BEGIN_PARAMETER_PRESENT: AtomicUsize = AtomicUsize::new(0);
    static ENCRYPT_BEGIN_PARAMETER_LEN: AtomicUsize = AtomicUsize::new(0);
    static ENCRYPT_BEGIN_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static SIGN_VERIFY_PROVIDER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SIGN_VERIFY_PARAMETER_PRESENT: AtomicUsize = AtomicUsize::new(0);
    static SIGN_VERIFY_PARAMETER_LEN: AtomicUsize = AtomicUsize::new(0);
    static SIGN_VERIFY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static STRUCTURED_PROVIDER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static STRUCTURED_PROVIDER_OPERATION: AtomicUsize = AtomicUsize::new(0);
    static STRUCTURED_PROVIDER_PARAMETER_PRESENT: AtomicUsize = AtomicUsize::new(0);
    static STRUCTURED_PROVIDER_PARAMETER_LEN: AtomicUsize = AtomicUsize::new(0);
    static STRUCTURED_PROVIDER_PARAMETER_VALID: AtomicUsize = AtomicUsize::new(0);
    static STRUCTURED_PROVIDER_EXPECTED_SHAPE: AtomicUsize = AtomicUsize::new(0);
    static STRUCTURED_PROVIDER_EXPECTED_LEN: AtomicUsize = AtomicUsize::new(0);
    static STRUCTURED_PROVIDER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static MUTATING_INIT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static MUTATING_INIT_MODE: AtomicUsize = AtomicUsize::new(0);
    static MUTATING_INIT_PARAMETER_PRESENT: AtomicUsize = AtomicUsize::new(0);
    static MUTATING_INIT_PARAMETER_LEN: AtomicUsize = AtomicUsize::new(0);
    static MUTATING_INIT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const PROVIDER_ENCRYPT_INIT: usize = 1;
    const PROVIDER_ENCRYPT_ONE_SHOT: usize = 2;
    const PROVIDER_ENCRYPT_BEGIN: usize = 3;
    const PROVIDER_ENCRYPT_NEXT: usize = 4;
    const PROVIDER_DECRYPT_INIT: usize = 5;
    const PROVIDER_DECRYPT_ONE_SHOT: usize = 6;
    const PROVIDER_DECRYPT_BEGIN: usize = 7;
    const PROVIDER_DECRYPT_NEXT: usize = 8;

    fn record_structured_provider_parameter(
        operation: usize,
        parameter: cryptoki_sys::CK_VOID_PTR,
        parameter_len: cryptoki_sys::CK_ULONG,
    ) {
        STRUCTURED_PROVIDER_CALLS.fetch_add(1, Ordering::SeqCst);
        STRUCTURED_PROVIDER_OPERATION.store(operation, Ordering::SeqCst);
        STRUCTURED_PROVIDER_PARAMETER_PRESENT
            .store(usize::from(!parameter.is_null()), Ordering::SeqCst);
        STRUCTURED_PROVIDER_PARAMETER_LEN.store(parameter_len as usize, Ordering::SeqCst);

        let expected_len = STRUCTURED_PROVIDER_EXPECTED_LEN.load(Ordering::SeqCst);
        let valid = if parameter.is_null() || parameter_len as usize != expected_len {
            false
        } else {
            match STRUCTURED_PROVIDER_EXPECTED_SHAPE.load(Ordering::SeqCst) {
                1 => {
                    let params =
                        unsafe { &*parameter.cast::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>() };
                    params.ulIvLen == 12
                        && params.ulIvFixedBits == 32
                        && params.ivGenerator == 1
                        && params.ulTagBits == 128
                        && !params.pIv.is_null()
                        && !params.pTag.is_null()
                        && unsafe { *params.pIv == 0x10 && *params.pTag == 0 }
                }
                2 => {
                    let params =
                        unsafe { &*parameter.cast::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>() };
                    params.ulDataLen == 5
                        && params.ulNonceLen == 13
                        && params.ulNonceFixedBits == 16
                        && params.nonceGenerator == 2
                        && params.ulMACLen == 12
                        && !params.pNonce.is_null()
                        && !params.pMAC.is_null()
                        && unsafe { *params.pNonce == 0x20 && *params.pMAC == 0 }
                }
                3 => {
                    let params = unsafe {
                        &*parameter.cast::<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>()
                    };
                    params.ulNonceLen == 96
                        && !params.pNonce.is_null()
                        && !params.pTag.is_null()
                        && unsafe { *params.pNonce == 0x30 && *params.pTag == 0 }
                }
                _ => false,
            }
        };
        STRUCTURED_PROVIDER_PARAMETER_VALID.store(usize::from(valid), Ordering::SeqCst);
    }

    unsafe fn finish_structured_provider_output(
        input: cryptoki_sys::CK_BYTE_PTR,
        input_len: cryptoki_sys::CK_ULONG,
        output: cryptoki_sys::CK_BYTE_PTR,
        output_len: cryptoki_sys::CK_ULONG_PTR,
    ) -> cryptoki_sys::CK_RV {
        if output_len.is_null() {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }
        let capacity = unsafe { *output_len };
        unsafe { *output_len = input_len };
        if output.is_null() {
            return cryptoki_sys::CKR_OK;
        }
        if capacity < input_len {
            return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
        }
        if input_len > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(input.cast_const(), output, input_len as usize)
            };
        }
        cryptoki_sys::CKR_OK
    }

    unsafe fn structured_message_init(
        operation: usize,
        mechanism: cryptoki_sys::CK_MECHANISM_PTR,
    ) -> cryptoki_sys::CK_RV {
        if mechanism.is_null() {
            record_structured_provider_parameter(operation, std::ptr::null_mut(), 0);
            return cryptoki_sys::CKR_MECHANISM_PARAM_INVALID;
        }
        let mechanism = unsafe { &*mechanism };
        record_structured_provider_parameter(
            operation,
            mechanism.pParameter,
            mechanism.ulParameterLen,
        );
        if STRUCTURED_PROVIDER_PARAMETER_VALID.load(Ordering::SeqCst) == 1 {
            cryptoki_sys::CKR_OK
        } else {
            cryptoki_sys::CKR_MECHANISM_PARAM_INVALID
        }
    }

    unsafe extern "C" fn counted_structured_encrypt_init(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        mechanism: cryptoki_sys::CK_MECHANISM_PTR,
        _key: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        unsafe { structured_message_init(PROVIDER_ENCRYPT_INIT, mechanism) }
    }

    unsafe extern "C" fn counted_structured_decrypt_init(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        mechanism: cryptoki_sys::CK_MECHANISM_PTR,
        _key: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        unsafe { structured_message_init(PROVIDER_DECRYPT_INIT, mechanism) }
    }

    unsafe fn mutate_message_init_mechanism(
        mechanism: cryptoki_sys::CK_MECHANISM_PTR,
    ) -> cryptoki_sys::CK_RV {
        MUTATING_INIT_CALLS.fetch_add(1, Ordering::SeqCst);
        if mechanism.is_null() {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }
        let mechanism = unsafe { &mut *mechanism };
        MUTATING_INIT_PARAMETER_PRESENT
            .store(usize::from(!mechanism.pParameter.is_null()), Ordering::SeqCst);
        MUTATING_INIT_PARAMETER_LEN.store(mechanism.ulParameterLen as usize, Ordering::SeqCst);
        match MUTATING_INIT_MODE.load(Ordering::SeqCst) {
            1 => {
                mechanism.pParameter = if mechanism.pParameter.is_null() {
                    std::ptr::NonNull::<u8>::dangling().as_ptr().cast()
                } else {
                    std::ptr::null_mut()
                };
            }
            2 => mechanism.ulParameterLen = mechanism.ulParameterLen.wrapping_add(1),
            _ => {}
        }
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn mutating_encrypt_init(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        mechanism: cryptoki_sys::CK_MECHANISM_PTR,
        _key: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        unsafe { mutate_message_init_mechanism(mechanism) }
    }

    unsafe extern "C" fn mutating_decrypt_init(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        mechanism: cryptoki_sys::CK_MECHANISM_PTR,
        _key: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        unsafe { mutate_message_init_mechanism(mechanism) }
    }

    unsafe extern "C" fn counted_structured_encrypt_message(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        parameter: cryptoki_sys::CK_VOID_PTR,
        parameter_len: cryptoki_sys::CK_ULONG,
        _aad: cryptoki_sys::CK_BYTE_PTR,
        _aad_len: cryptoki_sys::CK_ULONG,
        plaintext: cryptoki_sys::CK_BYTE_PTR,
        plaintext_len: cryptoki_sys::CK_ULONG,
        ciphertext: cryptoki_sys::CK_BYTE_PTR,
        ciphertext_len: cryptoki_sys::CK_ULONG_PTR,
    ) -> cryptoki_sys::CK_RV {
        record_structured_provider_parameter(PROVIDER_ENCRYPT_ONE_SHOT, parameter, parameter_len);
        if STRUCTURED_PROVIDER_PARAMETER_VALID.load(Ordering::SeqCst) != 1 {
            return cryptoki_sys::CKR_MECHANISM_PARAM_INVALID;
        }
        unsafe {
            finish_structured_provider_output(plaintext, plaintext_len, ciphertext, ciphertext_len)
        }
    }

    unsafe extern "C" fn counted_structured_decrypt_message(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        parameter: cryptoki_sys::CK_VOID_PTR,
        parameter_len: cryptoki_sys::CK_ULONG,
        _aad: cryptoki_sys::CK_BYTE_PTR,
        _aad_len: cryptoki_sys::CK_ULONG,
        ciphertext: cryptoki_sys::CK_BYTE_PTR,
        ciphertext_len: cryptoki_sys::CK_ULONG,
        plaintext: cryptoki_sys::CK_BYTE_PTR,
        plaintext_len: cryptoki_sys::CK_ULONG_PTR,
    ) -> cryptoki_sys::CK_RV {
        record_structured_provider_parameter(PROVIDER_DECRYPT_ONE_SHOT, parameter, parameter_len);
        if STRUCTURED_PROVIDER_PARAMETER_VALID.load(Ordering::SeqCst) != 1 {
            return cryptoki_sys::CKR_MECHANISM_PARAM_INVALID;
        }
        unsafe {
            finish_structured_provider_output(ciphertext, ciphertext_len, plaintext, plaintext_len)
        }
    }

    unsafe extern "C" fn counted_structured_encrypt_begin(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        parameter: cryptoki_sys::CK_VOID_PTR,
        parameter_len: cryptoki_sys::CK_ULONG,
        _aad: cryptoki_sys::CK_BYTE_PTR,
        _aad_len: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        record_structured_provider_parameter(PROVIDER_ENCRYPT_BEGIN, parameter, parameter_len);
        if STRUCTURED_PROVIDER_PARAMETER_VALID.load(Ordering::SeqCst) == 1 {
            cryptoki_sys::CKR_OK
        } else {
            cryptoki_sys::CKR_MECHANISM_PARAM_INVALID
        }
    }

    unsafe extern "C" fn counted_structured_decrypt_begin(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        parameter: cryptoki_sys::CK_VOID_PTR,
        parameter_len: cryptoki_sys::CK_ULONG,
        _aad: cryptoki_sys::CK_BYTE_PTR,
        _aad_len: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        record_structured_provider_parameter(PROVIDER_DECRYPT_BEGIN, parameter, parameter_len);
        if STRUCTURED_PROVIDER_PARAMETER_VALID.load(Ordering::SeqCst) == 1 {
            cryptoki_sys::CKR_OK
        } else {
            cryptoki_sys::CKR_MECHANISM_PARAM_INVALID
        }
    }

    unsafe extern "C" fn counted_structured_encrypt_next(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        parameter: cryptoki_sys::CK_VOID_PTR,
        parameter_len: cryptoki_sys::CK_ULONG,
        plaintext: cryptoki_sys::CK_BYTE_PTR,
        plaintext_len: cryptoki_sys::CK_ULONG,
        ciphertext: cryptoki_sys::CK_BYTE_PTR,
        ciphertext_len: cryptoki_sys::CK_ULONG_PTR,
        _flags: cryptoki_sys::CK_FLAGS,
    ) -> cryptoki_sys::CK_RV {
        record_structured_provider_parameter(PROVIDER_ENCRYPT_NEXT, parameter, parameter_len);
        if STRUCTURED_PROVIDER_PARAMETER_VALID.load(Ordering::SeqCst) != 1 {
            return cryptoki_sys::CKR_MECHANISM_PARAM_INVALID;
        }
        unsafe {
            finish_structured_provider_output(plaintext, plaintext_len, ciphertext, ciphertext_len)
        }
    }

    unsafe extern "C" fn counted_structured_decrypt_next(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        parameter: cryptoki_sys::CK_VOID_PTR,
        parameter_len: cryptoki_sys::CK_ULONG,
        ciphertext: cryptoki_sys::CK_BYTE_PTR,
        ciphertext_len: cryptoki_sys::CK_ULONG,
        plaintext: cryptoki_sys::CK_BYTE_PTR,
        plaintext_len: cryptoki_sys::CK_ULONG_PTR,
        _flags: cryptoki_sys::CK_FLAGS,
    ) -> cryptoki_sys::CK_RV {
        record_structured_provider_parameter(PROVIDER_DECRYPT_NEXT, parameter, parameter_len);
        if STRUCTURED_PROVIDER_PARAMETER_VALID.load(Ordering::SeqCst) != 1 {
            return cryptoki_sys::CKR_MECHANISM_PARAM_INVALID;
        }
        unsafe {
            finish_structured_provider_output(ciphertext, ciphertext_len, plaintext, plaintext_len)
        }
    }

    fn record_sign_verify_parameter(
        parameter: cryptoki_sys::CK_VOID_PTR,
        parameter_len: cryptoki_sys::CK_ULONG,
    ) {
        SIGN_VERIFY_PROVIDER_CALLS.fetch_add(1, Ordering::SeqCst);
        SIGN_VERIFY_PARAMETER_PRESENT.store(usize::from(!parameter.is_null()), Ordering::SeqCst);
        SIGN_VERIFY_PARAMETER_LEN.store(parameter_len as usize, Ordering::SeqCst);
    }

    unsafe fn write_test_signature(
        signature: cryptoki_sys::CK_BYTE_PTR,
        signature_len: cryptoki_sys::CK_ULONG_PTR,
    ) -> cryptoki_sys::CK_RV {
        if signature_len.is_null() {
            return cryptoki_sys::CKR_OK;
        }
        let capacity = unsafe { *signature_len };
        unsafe { *signature_len = 1 };
        if !signature.is_null() && capacity > 0 {
            unsafe { *signature = 0x5a };
        }
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn counted_sign_message(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        parameter: cryptoki_sys::CK_VOID_PTR,
        parameter_len: cryptoki_sys::CK_ULONG,
        _data: cryptoki_sys::CK_BYTE_PTR,
        _data_len: cryptoki_sys::CK_ULONG,
        signature: cryptoki_sys::CK_BYTE_PTR,
        signature_len: cryptoki_sys::CK_ULONG_PTR,
    ) -> cryptoki_sys::CK_RV {
        record_sign_verify_parameter(parameter, parameter_len);
        unsafe { write_test_signature(signature, signature_len) }
    }

    unsafe extern "C" fn counted_sign_message_begin(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        parameter: cryptoki_sys::CK_VOID_PTR,
        parameter_len: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        record_sign_verify_parameter(parameter, parameter_len);
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn counted_sign_message_next(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        parameter: cryptoki_sys::CK_VOID_PTR,
        parameter_len: cryptoki_sys::CK_ULONG,
        _data: cryptoki_sys::CK_BYTE_PTR,
        _data_len: cryptoki_sys::CK_ULONG,
        signature: cryptoki_sys::CK_BYTE_PTR,
        signature_len: cryptoki_sys::CK_ULONG_PTR,
    ) -> cryptoki_sys::CK_RV {
        record_sign_verify_parameter(parameter, parameter_len);
        unsafe { write_test_signature(signature, signature_len) }
    }

    unsafe extern "C" fn counted_verify_message(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        parameter: cryptoki_sys::CK_VOID_PTR,
        parameter_len: cryptoki_sys::CK_ULONG,
        _data: cryptoki_sys::CK_BYTE_PTR,
        _data_len: cryptoki_sys::CK_ULONG,
        _signature: cryptoki_sys::CK_BYTE_PTR,
        _signature_len: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        record_sign_verify_parameter(parameter, parameter_len);
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn counted_verify_message_begin(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        parameter: cryptoki_sys::CK_VOID_PTR,
        parameter_len: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        record_sign_verify_parameter(parameter, parameter_len);
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn counted_verify_message_next(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        parameter: cryptoki_sys::CK_VOID_PTR,
        parameter_len: cryptoki_sys::CK_ULONG,
        _data: cryptoki_sys::CK_BYTE_PTR,
        _data_len: cryptoki_sys::CK_ULONG,
        _signature: cryptoki_sys::CK_BYTE_PTR,
        _signature_len: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        record_sign_verify_parameter(parameter, parameter_len);
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn counted_encrypt_message_begin(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        parameter: cryptoki_sys::CK_VOID_PTR,
        parameter_len: cryptoki_sys::CK_ULONG,
        _aad: cryptoki_sys::CK_BYTE_PTR,
        _aad_len: cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV {
        ENCRYPT_BEGIN_PROVIDER_CALLS.fetch_add(1, Ordering::SeqCst);
        ENCRYPT_BEGIN_PARAMETER_PRESENT.store(usize::from(!parameter.is_null()), Ordering::SeqCst);
        ENCRYPT_BEGIN_PARAMETER_LEN.store(parameter_len as usize, Ordering::SeqCst);
        if !parameter.is_null()
            && parameter_len as usize == std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>()
        {
            let params = unsafe { &mut *parameter.cast::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>() };
            if !params.pIv.is_null() && params.ulIvLen > 0 {
                // Keep the caller's fixed 32-bit prefix unchanged.
                unsafe { *params.pIv.add(4) = 0x7b };
            }
        }
        cryptoki_sys::CKR_OK
    }

    #[cfg(unix)]
    fn backend_with_encrypt_message_begin()
    -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>, Box<cryptoki_sys::CK_FUNCTION_LIST_3_0>)
    {
        let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_0::default());
        functions.C_EncryptMessageBegin = Some(counted_encrypt_message_begin);
        functions.C_DecryptMessageBegin = Some(counted_encrypt_message_begin);
        let backend = FfiBackend {
            _lib: crate::ffi::loading::test_library_handle(),
            func_list: base.as_mut(),
            func_list_3_0: Some(functions.as_ref()),
            func_list_3_2: None,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            // Test-local backend: bypasses the process reservation without
            // consuming it; never backs production dispatch (C3M.4).
            construction: crate::ffi::native_domain::ConstructionPermit::unmanaged_test_only(),
            lifecycle: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
        (backend, base, functions)
    }

    #[cfg(unix)]
    fn backend_with_sign_verify_message_functions()
    -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>, Box<cryptoki_sys::CK_FUNCTION_LIST_3_0>)
    {
        let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_0::default());
        functions.C_SignMessage = Some(counted_sign_message);
        functions.C_SignMessageBegin = Some(counted_sign_message_begin);
        functions.C_SignMessageNext = Some(counted_sign_message_next);
        functions.C_VerifyMessage = Some(counted_verify_message);
        functions.C_VerifyMessageBegin = Some(counted_verify_message_begin);
        functions.C_VerifyMessageNext = Some(counted_verify_message_next);
        let backend = FfiBackend {
            _lib: crate::ffi::loading::test_library_handle(),
            func_list: base.as_mut(),
            func_list_3_0: Some(functions.as_ref()),
            func_list_3_2: None,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            // Test-local backend: bypasses the process reservation without
            // consuming it; never backs production dispatch (C3M.4).
            construction: crate::ffi::native_domain::ConstructionPermit::unmanaged_test_only(),
            lifecycle: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
        (backend, base, functions)
    }

    #[cfg(unix)]
    fn backend_with_structured_message_functions()
    -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>, Box<cryptoki_sys::CK_FUNCTION_LIST_3_0>)
    {
        let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_0::default());
        functions.C_MessageEncryptInit = Some(counted_structured_encrypt_init);
        functions.C_EncryptMessage = Some(counted_structured_encrypt_message);
        functions.C_EncryptMessageBegin = Some(counted_structured_encrypt_begin);
        functions.C_EncryptMessageNext = Some(counted_structured_encrypt_next);
        functions.C_MessageDecryptInit = Some(counted_structured_decrypt_init);
        functions.C_DecryptMessage = Some(counted_structured_decrypt_message);
        functions.C_DecryptMessageBegin = Some(counted_structured_decrypt_begin);
        functions.C_DecryptMessageNext = Some(counted_structured_decrypt_next);
        let backend = FfiBackend {
            _lib: crate::ffi::loading::test_library_handle(),
            func_list: base.as_mut(),
            func_list_3_0: Some(functions.as_ref()),
            func_list_3_2: None,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            // Test-local backend: bypasses the process reservation without
            // consuming it; never backs production dispatch (C3M.4).
            construction: crate::ffi::native_domain::ConstructionPermit::unmanaged_test_only(),
            lifecycle: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
        (backend, base, functions)
    }

    #[cfg(unix)]
    fn backend_with_mutating_init_functions()
    -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>, Box<cryptoki_sys::CK_FUNCTION_LIST_3_0>)
    {
        let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_0::default());
        functions.C_MessageEncryptInit = Some(mutating_encrypt_init);
        functions.C_MessageDecryptInit = Some(mutating_decrypt_init);
        let backend = FfiBackend {
            _lib: crate::ffi::loading::test_library_handle(),
            func_list: base.as_mut(),
            func_list_3_0: Some(functions.as_ref()),
            func_list_3_2: None,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            // Test-local backend: bypasses the process reservation without
            // consuming it; never backs production dispatch (C3M.4).
            construction: crate::ffi::native_domain::ConstructionPermit::unmanaged_test_only(),
            lifecycle: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };
        (backend, base, functions)
    }

    #[cfg(unix)]
    #[test]
    fn null_output_length_structured_helpers_forward_once_and_keep_message_output() {
        let _guard = STRUCTURED_PROVIDER_TEST_LOCK.lock().unwrap();
        let (backend, _base, _functions) = backend_with_structured_message_functions();
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true };
        let mut calls = 0;

        let gcm = GcmMessageParams {
            iv: vec![0x11; 12],
            iv_null_len: None,
            iv_fixed_bits: 96,
            iv_generator: 0,
            tag: vec![0; 16],
            tag_null_len: None,
            tag_bits: 128,
        };
        let (output, returned) = backend
            .call_with_gcm_message_param(
                &gcm,
                &output_spec,
                |params, main_output, main_output_len: *mut cryptoki_sys::CK_ULONG| {
                    calls += 1;
                    assert!(!main_output.is_null());
                    assert!(main_output_len.is_null());
                    unsafe { *(*params).pIv = 0xA1 };
                    cryptoki_sys::CKR_OK
                },
            )
            .expect("GCM provider result envelope");
        assert_eq!(
            output,
            CkOutputBufferResult { ck_rv: CkRv::OK, returned_len: Some(0), value: None }
        );
        let mut expected_gcm = gcm.clone();
        expected_gcm.iv[0] = 0xA1;
        assert_eq!(returned, MessageParameter::GcmMessage(expected_gcm));

        let ccm = CcmMessageParams {
            data_len: 4,
            nonce: vec![0x22; 12],
            nonce_null_len: None,
            nonce_fixed_bits: 96,
            nonce_generator: 0,
            mac: vec![0; 16],
            mac_null_len: None,
            mac_len: 16,
        };
        let (output, returned) = backend
            .call_with_ccm_message_param(
                &ccm,
                &output_spec,
                |params, main_output, main_output_len: *mut cryptoki_sys::CK_ULONG| {
                    calls += 1;
                    assert!(!main_output.is_null());
                    assert!(main_output_len.is_null());
                    unsafe { *(*params).pNonce = 0xA2 };
                    cryptoki_sys::CKR_OK
                },
            )
            .expect("CCM provider result envelope");
        assert_eq!(
            output,
            CkOutputBufferResult { ck_rv: CkRv::OK, returned_len: Some(0), value: None }
        );
        let mut expected_ccm = ccm.clone();
        expected_ccm.nonce[0] = 0xA2;
        assert_eq!(returned, MessageParameter::CcmMessage(expected_ccm));

        let salsa = Salsa20ChaCha20Poly1305MessageParams {
            nonce: vec![0x33; 12],
            nonce_bits: 96,
            nonce_null_len: None,
            tag: vec![0; 16],
            tag_null_len: None,
        };
        let (output, returned) = backend
            .call_with_salsa20_chacha20_poly1305_message_param(
                &salsa,
                &output_spec,
                |params, main_output, main_output_len: *mut cryptoki_sys::CK_ULONG| {
                    calls += 1;
                    assert!(!main_output.is_null());
                    assert!(main_output_len.is_null());
                    unsafe { *(*params).pTag = 0xA3 };
                    cryptoki_sys::CKR_OK
                },
            )
            .expect("Salsa/ChaCha provider result envelope");
        assert_eq!(
            output,
            CkOutputBufferResult { ck_rv: CkRv::OK, returned_len: Some(0), value: None }
        );
        let mut expected_salsa = salsa.clone();
        expected_salsa.tag[0] = 0xA3;
        assert_eq!(returned, MessageParameter::SalaChacha(expected_salsa));
        assert_eq!(calls, 3, "one provider call per structured parameter family");
    }

    #[cfg(unix)]
    #[test]
    fn null_output_length_structured_helpers_preserve_buffer_too_small_and_message_output() {
        let _guard = STRUCTURED_PROVIDER_TEST_LOCK.lock().unwrap();
        let (backend, _base, _functions) = backend_with_structured_message_functions();
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true };
        let mut calls = 0;

        let gcm = GcmMessageParams {
            iv: vec![0x11; 12],
            iv_null_len: None,
            iv_fixed_bits: 96,
            iv_generator: 0,
            tag: vec![0; 16],
            tag_null_len: None,
            tag_bits: 128,
        };
        let (output, returned) = backend
            .call_with_gcm_message_param(&gcm, &output_spec, |params, _, output_len| {
                calls += 1;
                assert!(output_len.is_null());
                unsafe { *(*params).pIv = 0xA1 };
                cryptoki_sys::CKR_BUFFER_TOO_SMALL
            })
            .expect("GCM provider result envelope");
        assert_eq!(output.ck_rv, CkRv::BUFFER_TOO_SMALL);
        let mut expected_gcm = gcm.clone();
        expected_gcm.iv[0] = 0xA1;
        assert_eq!(returned, MessageParameter::GcmMessage(expected_gcm));

        let ccm = CcmMessageParams {
            data_len: 4,
            nonce: vec![0x22; 12],
            nonce_null_len: None,
            nonce_fixed_bits: 96,
            nonce_generator: 0,
            mac: vec![0; 16],
            mac_null_len: None,
            mac_len: 16,
        };
        let (output, returned) = backend
            .call_with_ccm_message_param(&ccm, &output_spec, |params, _, output_len| {
                calls += 1;
                assert!(output_len.is_null());
                unsafe { *(*params).pNonce = 0xA2 };
                cryptoki_sys::CKR_BUFFER_TOO_SMALL
            })
            .expect("CCM provider result envelope");
        assert_eq!(output.ck_rv, CkRv::BUFFER_TOO_SMALL);
        let mut expected_ccm = ccm.clone();
        expected_ccm.nonce[0] = 0xA2;
        assert_eq!(returned, MessageParameter::CcmMessage(expected_ccm));

        let salsa = Salsa20ChaCha20Poly1305MessageParams {
            nonce: vec![0x33; 12],
            nonce_bits: 96,
            nonce_null_len: None,
            tag: vec![0; 16],
            tag_null_len: None,
        };
        let (output, returned) = backend
            .call_with_salsa20_chacha20_poly1305_message_param(
                &salsa,
                &output_spec,
                |params, _, output_len| {
                    calls += 1;
                    assert!(output_len.is_null());
                    unsafe { *(*params).pTag = 0xA3 };
                    cryptoki_sys::CKR_BUFFER_TOO_SMALL
                },
            )
            .expect("Salsa/ChaCha provider result envelope");
        assert_eq!(output.ck_rv, CkRv::BUFFER_TOO_SMALL);
        let mut expected_salsa = salsa.clone();
        expected_salsa.tag[0] = 0xA3;
        assert_eq!(returned, MessageParameter::SalaChacha(expected_salsa));
        assert_eq!(calls, 3, "one provider call per structured parameter family");
    }

    #[cfg(unix)]
    #[test]
    fn message_init_contract_rejects_provider_pointer_class_or_length_mutation() {
        let _guard = MUTATING_INIT_TEST_LOCK.lock().unwrap();
        MUTATING_INIT_CALLS.store(0, Ordering::SeqCst);
        let (backend, _base, _functions) = backend_with_mutating_init_functions();
        let mechanism = CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: None };
        let structured = MessageParameter::GcmMessage(GcmMessageParams {
            iv: vec![0x10; 12],
            iv_null_len: None,
            iv_fixed_bits: 96,
            iv_generator: 0,
            tag: vec![0; 16],
            tag_null_len: None,
            tag_bits: 128,
        });
        let native_len = std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>() as u64;
        let cases = [
            (
                "structured",
                Some(structured),
                CkParameterRoundtripSpec {
                    buffer_present: true,
                    buffer_len: native_len,
                    value: None,
                },
            ),
            (
                "NULL/zero",
                None,
                CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None },
            ),
            (
                "NULL/positive",
                None,
                CkParameterRoundtripSpec { buffer_present: false, buffer_len: 7, value: None },
            ),
            (
                "non-NULL/zero",
                None,
                CkParameterRoundtripSpec { buffer_present: true, buffer_len: 0, value: None },
            ),
        ];

        for encrypt in [true, false] {
            for mutation in [1, 2] {
                for (label, parameter, provider_spec) in &cases {
                    MUTATING_INIT_MODE.store(mutation, Ordering::SeqCst);
                    let before = MUTATING_INIT_CALLS.load(Ordering::SeqCst);
                    let result = if encrypt {
                        backend.ffi_message_encrypt_init_contract(
                            CkSessionHandle(7),
                            &mechanism,
                            parameter.as_ref(),
                            CkObjectHandle(9),
                            provider_spec,
                        )
                    } else {
                        backend.ffi_message_decrypt_init_contract(
                            CkSessionHandle(7),
                            &mechanism,
                            parameter.as_ref(),
                            CkObjectHandle(9),
                            provider_spec,
                        )
                    };
                    assert_eq!(
                        result,
                        Err(CkRv::DEVICE_ERROR),
                        "{} {label} mutation {mutation}",
                        if encrypt { "Encrypt" } else { "Decrypt" },
                    );
                    assert_eq!(
                        MUTATING_INIT_CALLS.load(Ordering::SeqCst),
                        before + 1,
                        "each native Init invokes the provider exactly once",
                    );
                    assert_eq!(
                        MUTATING_INIT_PARAMETER_PRESENT.load(Ordering::SeqCst),
                        usize::from(provider_spec.buffer_present),
                        "provider input pointer class for {label}",
                    );
                    assert_eq!(
                        MUTATING_INIT_PARAMETER_LEN.load(Ordering::SeqCst),
                        provider_spec.buffer_len as usize,
                        "provider input length for {label}",
                    );
                }
            }
        }

        let bad_structured_spec = CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: native_len + 1,
            value: None,
        };
        let bad_empty_spec =
            CkParameterRoundtripSpec { buffer_present: true, buffer_len: 1, value: None };
        let structured = cases[0].1.as_ref().unwrap();
        for encrypt in [true, false] {
            for (parameter, provider_spec) in
                [(Some(structured), &bad_structured_spec), (None, &bad_empty_spec)]
            {
                let before = MUTATING_INIT_CALLS.load(Ordering::SeqCst);
                let result = if encrypt {
                    backend.ffi_message_encrypt_init_contract(
                        CkSessionHandle(7),
                        &mechanism,
                        parameter,
                        CkObjectHandle(9),
                        provider_spec,
                    )
                } else {
                    backend.ffi_message_decrypt_init_contract(
                        CkSessionHandle(7),
                        &mechanism,
                        parameter,
                        CkObjectHandle(9),
                        provider_spec,
                    )
                };
                assert_eq!(result, Err(CkRv::MECHANISM_PARAM_INVALID));
                assert_eq!(
                    MUTATING_INIT_CALLS.load(Ordering::SeqCst),
                    before,
                    "pre-provider contract mismatch must not invoke Init",
                );
            }
        }
    }

    #[cfg(unix)]
    fn assert_one_structured_provider_call(
        before: usize,
        expected_operation: usize,
        expected_len: u64,
        cell: &str,
    ) {
        assert_eq!(
            STRUCTURED_PROVIDER_CALLS.load(Ordering::SeqCst),
            before + 1,
            "{cell} provider call count",
        );
        assert_eq!(
            STRUCTURED_PROVIDER_OPERATION.load(Ordering::SeqCst),
            expected_operation,
            "{cell} provider function",
        );
        assert_eq!(
            STRUCTURED_PROVIDER_PARAMETER_PRESENT.load(Ordering::SeqCst),
            1,
            "{cell} parameter pointer class",
        );
        assert_eq!(
            STRUCTURED_PROVIDER_PARAMETER_LEN.load(Ordering::SeqCst),
            expected_len as usize,
            "{cell} provider-native struct size",
        );
        assert_eq!(
            STRUCTURED_PROVIDER_PARAMETER_VALID.load(Ordering::SeqCst),
            1,
            "{cell} scalar fields and owned backing bytes",
        );
    }

    #[cfg(unix)]
    #[test]
    fn structured_message_matrix_invokes_each_provider_entry_exactly_once() {
        let _guard = STRUCTURED_PROVIDER_TEST_LOCK.lock().unwrap();
        STRUCTURED_PROVIDER_CALLS.store(0, Ordering::SeqCst);
        let (backend, _base, _functions) = backend_with_structured_message_functions();
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 64, length_pointer_null: false };
        let session = CkSessionHandle(7);
        let key = CkObjectHandle(9);

        let cases = [
            (
                "GCM",
                1,
                CkMechanismType::AES_GCM,
                MessageParameter::GcmMessage(GcmMessageParams {
                    iv: vec![0x10; 12],
                    iv_null_len: None,
                    iv_fixed_bits: 32,
                    iv_generator: 1,
                    tag: vec![0; 16],
                    tag_null_len: None,
                    tag_bits: 128,
                }),
                std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>() as u64,
            ),
            (
                "CCM",
                2,
                CkMechanismType::AES_CCM,
                MessageParameter::CcmMessage(CcmMessageParams {
                    data_len: 5,
                    nonce: vec![0x20; 13],
                    nonce_null_len: None,
                    nonce_fixed_bits: 16,
                    nonce_generator: 2,
                    mac: vec![0; 12],
                    mac_null_len: None,
                    mac_len: 12,
                }),
                std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>() as u64,
            ),
            (
                "Salsa/ChaCha",
                3,
                CkMechanismType::CHACHA20_POLY1305,
                MessageParameter::SalaChacha(Salsa20ChaCha20Poly1305MessageParams {
                    nonce: vec![0x30; 12],
                    nonce_bits: 96,
                    nonce_null_len: None,
                    tag: vec![0; 16],
                    tag_null_len: None,
                }),
                std::mem::size_of::<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>() as u64,
            ),
        ];

        let mut exercised_cells = 0;
        for (shape, shape_id, mechanism_type, parameter, native_len) in cases {
            STRUCTURED_PROVIDER_EXPECTED_SHAPE.store(shape_id, Ordering::SeqCst);
            STRUCTURED_PROVIDER_EXPECTED_LEN.store(native_len as usize, Ordering::SeqCst);
            let mechanism = CkMechanism { mechanism_type, params: None };
            let provider_spec = CkParameterRoundtripSpec {
                buffer_present: true,
                buffer_len: native_len,
                value: None,
            };

            for encrypt in [true, false] {
                let direction = if encrypt { "Encrypt" } else { "Decrypt" };

                STRUCTURED_PROVIDER_PARAMETER_VALID.store(0, Ordering::SeqCst);
                let before = STRUCTURED_PROVIDER_CALLS.load(Ordering::SeqCst);
                let init_ack = if encrypt {
                    backend.ffi_message_encrypt_init_contract(
                        session,
                        &mechanism,
                        Some(&parameter),
                        key,
                        &provider_spec,
                    )
                } else {
                    backend.ffi_message_decrypt_init_contract(
                        session,
                        &mechanism,
                        Some(&parameter),
                        key,
                        &provider_spec,
                    )
                }
                .unwrap_or_else(|rv| panic!("{shape} {direction} Init failed: {rv:?}"));
                assert_one_structured_provider_call(
                    before,
                    if encrypt { PROVIDER_ENCRYPT_INIT } else { PROVIDER_DECRYPT_INIT },
                    native_len,
                    &format!("{shape} {direction} Init"),
                );
                assert_eq!(init_ack.returned_len, native_len);
                exercised_cells += 1;

                STRUCTURED_PROVIDER_PARAMETER_VALID.store(0, Ordering::SeqCst);
                let before = STRUCTURED_PROVIDER_CALLS.load(Ordering::SeqCst);
                let (output, ack, returned) = if encrypt {
                    backend.ffi_encrypt_message_exact_msg(
                        session,
                        &parameter,
                        CkInBuf::Bytes(b"aad"),
                        CkInBuf::Bytes(b"input"),
                        &output_spec,
                        &provider_spec,
                    )
                } else {
                    backend.ffi_decrypt_message_exact_msg(
                        session,
                        &parameter,
                        CkInBuf::Bytes(b"aad"),
                        CkInBuf::Bytes(b"input"),
                        &output_spec,
                        &provider_spec,
                    )
                }
                .unwrap_or_else(|rv| panic!("{shape} {direction} one-shot failed: {rv:?}"));
                assert_one_structured_provider_call(
                    before,
                    if encrypt { PROVIDER_ENCRYPT_ONE_SHOT } else { PROVIDER_DECRYPT_ONE_SHOT },
                    native_len,
                    &format!("{shape} {direction} one-shot"),
                );
                assert_eq!(output.ck_rv, CkRv::OK);
                assert_eq!(output.value, Some(b"input".to_vec()));
                assert_eq!(ack.returned_len, native_len);
                returned
                    .validate_for(
                        &parameter,
                        MessageEffectContext {
                            mode: ParameterEffectCallMode::Data,
                            encrypt,
                            generated_stage: true,
                            auth_stage: true,
                            rv: output.ck_rv,
                        },
                    )
                    .unwrap();
                exercised_cells += 1;

                STRUCTURED_PROVIDER_PARAMETER_VALID.store(0, Ordering::SeqCst);
                let before = STRUCTURED_PROVIDER_CALLS.load(Ordering::SeqCst);
                let (ack, returned) = if encrypt {
                    backend.ffi_encrypt_message_begin_msg(
                        session,
                        &parameter,
                        CkInBuf::Bytes(b"aad"),
                        &provider_spec,
                    )
                } else {
                    backend.ffi_decrypt_message_begin_msg(
                        session,
                        &parameter,
                        CkInBuf::Bytes(b"aad"),
                        &provider_spec,
                    )
                }
                .unwrap_or_else(|rv| panic!("{shape} {direction} Begin failed: {rv:?}"));
                assert_one_structured_provider_call(
                    before,
                    if encrypt { PROVIDER_ENCRYPT_BEGIN } else { PROVIDER_DECRYPT_BEGIN },
                    native_len,
                    &format!("{shape} {direction} Begin"),
                );
                assert_eq!(ack.returned_len, native_len);
                returned
                    .validate_for(
                        &parameter,
                        MessageEffectContext {
                            mode: ParameterEffectCallMode::Data,
                            encrypt,
                            generated_stage: true,
                            auth_stage: false,
                            rv: ack.ck_rv,
                        },
                    )
                    .unwrap();
                exercised_cells += 1;

                STRUCTURED_PROVIDER_PARAMETER_VALID.store(0, Ordering::SeqCst);
                let before = STRUCTURED_PROVIDER_CALLS.load(Ordering::SeqCst);
                let (output, ack, returned) = if encrypt {
                    backend.ffi_encrypt_message_next_exact_msg(
                        session,
                        &parameter,
                        CkInBuf::Bytes(b"input"),
                        CkFlags(0),
                        &output_spec,
                        &provider_spec,
                    )
                } else {
                    backend.ffi_decrypt_message_next_exact_msg(
                        session,
                        &parameter,
                        CkInBuf::Bytes(b"input"),
                        CkFlags(0),
                        &output_spec,
                        &provider_spec,
                    )
                }
                .unwrap_or_else(|rv| panic!("{shape} {direction} Next failed: {rv:?}"));
                assert_one_structured_provider_call(
                    before,
                    if encrypt { PROVIDER_ENCRYPT_NEXT } else { PROVIDER_DECRYPT_NEXT },
                    native_len,
                    &format!("{shape} {direction} Next"),
                );
                assert_eq!(output.ck_rv, CkRv::OK);
                assert_eq!(output.value, Some(b"input".to_vec()));
                assert_eq!(ack.returned_len, native_len);
                returned
                    .validate_for(
                        &parameter,
                        MessageEffectContext {
                            mode: ParameterEffectCallMode::Data,
                            encrypt,
                            generated_stage: false,
                            auth_stage: false,
                            rv: output.ck_rv,
                        },
                    )
                    .unwrap();
                exercised_cells += 1;
            }
        }

        assert_eq!(exercised_cells, 24, "three shapes x two directions x Init/one-shot/Begin/Next",);
        assert_eq!(
            STRUCTURED_PROVIDER_CALLS.load(Ordering::SeqCst),
            24,
            "one provider function invocation for every exercised cell",
        );
    }

    #[cfg(unix)]
    #[test]
    fn structured_encrypt_begin_invokes_provider_exactly_once() {
        let _guard = ENCRYPT_BEGIN_TEST_LOCK.lock().unwrap();
        ENCRYPT_BEGIN_PROVIDER_CALLS.store(0, Ordering::SeqCst);
        let (backend, _base, _functions) = backend_with_encrypt_message_begin();
        let parameter = MessageParameter::GcmMessage(GcmMessageParams {
            iv: vec![0x11; 12],
            iv_null_len: None,
            iv_fixed_bits: 32,
            iv_generator: 1,
            tag: vec![0; 16],
            tag_null_len: None,
            tag_bits: 128,
        });
        let provider_spec = CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>() as u64,
            value: None,
        };

        let (ack, returned) = backend
            .ffi_encrypt_message_begin_msg(
                CkSessionHandle(7),
                &parameter,
                CkInBuf::Bytes(b"aad"),
                &provider_spec,
            )
            .unwrap();

        assert_eq!(ENCRYPT_BEGIN_PROVIDER_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(ENCRYPT_BEGIN_PARAMETER_PRESENT.load(Ordering::SeqCst), 1);
        assert_eq!(
            ENCRYPT_BEGIN_PARAMETER_LEN.load(Ordering::SeqCst),
            provider_spec.buffer_len as usize
        );
        assert_eq!(ack.returned_len, provider_spec.buffer_len);
        match returned {
            MessageEffects::Gcm { iv: Some(iv), .. } => assert_eq!(iv[4], 0x7b),
            other => panic!("unexpected parameter: {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn empty_encrypt_decrypt_begin_preserves_provider_pointer_class_and_calls_once() {
        let _guard = ENCRYPT_BEGIN_TEST_LOCK.lock().unwrap();
        let (backend, _base, _functions) = backend_with_encrypt_message_begin();
        for encrypt in [true, false] {
            for (present, len) in [(false, 0), (false, 7), (true, 0)] {
                let before = ENCRYPT_BEGIN_PROVIDER_CALLS.load(Ordering::SeqCst);
                let spec = CkParameterRoundtripSpec {
                    buffer_present: present,
                    buffer_len: len,
                    value: None,
                };

                let ack = if encrypt {
                    backend.ffi_encrypt_message_begin_exact(
                        CkSessionHandle(7),
                        CkInBuf::Bytes(b"aad"),
                        &spec,
                    )
                } else {
                    backend.ffi_decrypt_message_begin_exact(
                        CkSessionHandle(7),
                        CkInBuf::Bytes(b"aad"),
                        &spec,
                    )
                }
                .unwrap();

                assert_eq!(ENCRYPT_BEGIN_PROVIDER_CALLS.load(Ordering::SeqCst), before + 1);
                assert_eq!(
                    ENCRYPT_BEGIN_PARAMETER_PRESENT.load(Ordering::SeqCst),
                    usize::from(present),
                );
                assert_eq!(ENCRYPT_BEGIN_PARAMETER_LEN.load(Ordering::SeqCst), len as usize);
                assert_eq!(ack.returned_len, len);
                assert_eq!(ack.value, present.then(Vec::new));
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn message_input_length_wider_than_native_is_rejected_before_provider_call() {
        let _guard = ENCRYPT_BEGIN_TEST_LOCK.lock().unwrap();
        ENCRYPT_BEGIN_PROVIDER_CALLS.store(0, Ordering::SeqCst);
        let (backend, _base, _functions) = backend_with_encrypt_message_begin();
        let spec = CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None };
        let over_u32 = u32::MAX as u64 + 1;

        let result = backend.ffi_encrypt_message_begin_exact(
            CkSessionHandle(7),
            CkInBuf::Null { len: over_u32 },
            &spec,
        );

        if std::mem::size_of::<cryptoki_sys::CK_ULONG>() == 4 {
            assert_eq!(result.unwrap_err(), CkRv::FUNCTION_FAILED);
            assert_eq!(ENCRYPT_BEGIN_PROVIDER_CALLS.load(Ordering::SeqCst), 0);
        } else {
            assert!(result.is_ok());
            assert_eq!(ENCRYPT_BEGIN_PROVIDER_CALLS.load(Ordering::SeqCst), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn message_flags_wider_than_native_are_rejected_before_provider_call() {
        let _guard = STRUCTURED_PROVIDER_TEST_LOCK.lock().unwrap();
        STRUCTURED_PROVIDER_CALLS.store(0, Ordering::SeqCst);
        let (backend, _base, _functions) = backend_with_structured_message_functions();
        let output_spec =
            CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: false };
        let parameter_spec =
            CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None };
        let over_u32 = u32::MAX as u64 + 1;

        let result = backend.ffi_encrypt_message_next_exact(
            CkSessionHandle(7),
            &[],
            CkInBuf::Bytes(&[]),
            CkFlags(over_u32),
            &output_spec,
            &parameter_spec,
        );

        if std::mem::size_of::<cryptoki_sys::CK_ULONG>() == 4 {
            assert_eq!(result.unwrap_err(), CkRv::FUNCTION_FAILED);
            assert_eq!(STRUCTURED_PROVIDER_CALLS.load(Ordering::SeqCst), 0);
        } else {
            assert_eq!(result.unwrap().0.ck_rv, CkRv::MECHANISM_PARAM_INVALID);
            assert_eq!(STRUCTURED_PROVIDER_CALLS.load(Ordering::SeqCst), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn empty_sign_verify_forms_preserve_pointer_class_and_call_provider_once() {
        let _guard = SIGN_VERIFY_TEST_LOCK.lock().unwrap();
        SIGN_VERIFY_PROVIDER_CALLS.store(0, Ordering::SeqCst);
        let (backend, _base, _functions) = backend_with_sign_verify_message_functions();
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 1, length_pointer_null: false };
        let session = CkSessionHandle(7);

        for buffer_present in [false, true] {
            let spec = CkParameterRoundtripSpec { buffer_present, buffer_len: 0, value: None };
            let assert_one_call = |before: usize| {
                assert_eq!(SIGN_VERIFY_PROVIDER_CALLS.load(Ordering::SeqCst), before + 1);
                assert_eq!(
                    SIGN_VERIFY_PARAMETER_PRESENT.load(Ordering::SeqCst),
                    usize::from(buffer_present),
                );
                assert_eq!(SIGN_VERIFY_PARAMETER_LEN.load(Ordering::SeqCst), 0);
            };

            let before = SIGN_VERIFY_PROVIDER_CALLS.load(Ordering::SeqCst);
            crate::Pkcs11Backend::sign_message_exact(
                &backend,
                session,
                &[],
                CkInBuf::Bytes(b"s"),
                &output_spec,
                &spec,
            )
            .unwrap();
            assert_one_call(before);

            let before = SIGN_VERIFY_PROVIDER_CALLS.load(Ordering::SeqCst);
            crate::Pkcs11Backend::sign_message_begin_exact(&backend, session, &spec).unwrap();
            assert_one_call(before);

            let before = SIGN_VERIFY_PROVIDER_CALLS.load(Ordering::SeqCst);
            crate::Pkcs11Backend::sign_message_next_feed_exact(
                &backend,
                session,
                CkInBuf::Bytes(b"feed"),
                &spec,
            )
            .unwrap();
            assert_one_call(before);

            let before = SIGN_VERIFY_PROVIDER_CALLS.load(Ordering::SeqCst);
            crate::Pkcs11Backend::sign_message_next_exact(
                &backend,
                session,
                &[],
                CkInBuf::Bytes(b"final"),
                &output_spec,
                &spec,
            )
            .unwrap();
            assert_one_call(before);

            let before = SIGN_VERIFY_PROVIDER_CALLS.load(Ordering::SeqCst);
            crate::Pkcs11Backend::verify_message_exact(
                &backend,
                session,
                CkInBuf::Bytes(b"v"),
                CkInBuf::Bytes(b"sig"),
                &spec,
            )
            .unwrap();
            assert_one_call(before);

            let before = SIGN_VERIFY_PROVIDER_CALLS.load(Ordering::SeqCst);
            crate::Pkcs11Backend::verify_message_begin_exact(&backend, session, &spec).unwrap();
            assert_one_call(before);

            for is_final in [false, true] {
                let before = SIGN_VERIFY_PROVIDER_CALLS.load(Ordering::SeqCst);
                crate::Pkcs11Backend::verify_message_next_exact(
                    &backend,
                    session,
                    CkInBuf::Bytes(b"next"),
                    is_final,
                    CkInBuf::Bytes(b"sig"),
                    &spec,
                )
                .unwrap();
                assert_one_call(before);
            }
        }

        let positive =
            CkParameterRoundtripSpec { buffer_present: false, buffer_len: 1, value: None };
        let before = SIGN_VERIFY_PROVIDER_CALLS.load(Ordering::SeqCst);
        assert_eq!(
            crate::Pkcs11Backend::sign_message_exact(
                &backend,
                session,
                &[],
                CkInBuf::Bytes(b"s"),
                &output_spec,
                &positive,
            ),
            Err(CkRv::MECHANISM_PARAM_INVALID),
        );
        assert_eq!(
            crate::Pkcs11Backend::sign_message_begin_exact(&backend, session, &positive),
            Err(CkRv::MECHANISM_PARAM_INVALID),
        );
        assert_eq!(
            crate::Pkcs11Backend::sign_message_next_feed_exact(
                &backend,
                session,
                CkInBuf::Bytes(b"feed"),
                &positive,
            ),
            Err(CkRv::MECHANISM_PARAM_INVALID),
        );
        assert_eq!(
            crate::Pkcs11Backend::sign_message_next_exact(
                &backend,
                session,
                &[],
                CkInBuf::Bytes(b"final"),
                &output_spec,
                &positive,
            ),
            Err(CkRv::MECHANISM_PARAM_INVALID),
        );
        assert_eq!(
            crate::Pkcs11Backend::verify_message_exact(
                &backend,
                session,
                CkInBuf::Bytes(b"v"),
                CkInBuf::Bytes(b"sig"),
                &positive,
            ),
            Err(CkRv::MECHANISM_PARAM_INVALID),
        );
        assert_eq!(
            crate::Pkcs11Backend::verify_message_begin_exact(&backend, session, &positive),
            Err(CkRv::MECHANISM_PARAM_INVALID),
        );
        for is_final in [false, true] {
            assert_eq!(
                crate::Pkcs11Backend::verify_message_next_exact(
                    &backend,
                    session,
                    CkInBuf::Bytes(b"next"),
                    is_final,
                    CkInBuf::Bytes(b"sig"),
                    &positive,
                ),
                Err(CkRv::MECHANISM_PARAM_INVALID),
            );
        }
        assert_eq!(SIGN_VERIFY_PROVIDER_CALLS.load(Ordering::SeqCst), before);
    }

    /// B2: an AEAD message-based init param (`CK_GCM_MESSAGE_PARAMS`) must be
    /// reconstructed into a `CK_MECHANISM` carrying the real message-params C
    /// struct — not the classic `CK_GCM_PARAMS` the registry would pick for the
    /// shared `CKM_AES_GCM` type. Verifies the struct layout, size, and that the
    /// mechanism points at it with HSM-writable tag room.
    #[test]
    fn gcm_message_init_reconstructs_message_params_struct() {
        let iv = vec![0x11u8; 12];
        let param = MessageParameter::GcmMessage(GcmMessageParams {
            iv: iv.clone(),
            iv_null_len: None,
            iv_fixed_bits: 0,
            iv_generator: 0,
            tag: vec![0; 16],
            tag_null_len: None,
            tag_bits: 128,
        });

        let init = build_message_init_mechanism(cryptoki_sys::CKM_AES_GCM as u64, &param)
            .expect("GCM message params reconstruct");

        assert_eq!(u64::from(init.ck_mechanism.mechanism), u64::from(cryptoki_sys::CKM_AES_GCM));
        assert_eq!(
            init.ck_mechanism.ulParameterLen as usize,
            std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>(),
            "init must advertise the MESSAGE params size, not classic CK_GCM_PARAMS",
        );
        assert!(!init.ck_mechanism.pParameter.is_null());

        // The mechanism param must be the reconstructed message struct.
        let p = unsafe {
            &*(init.ck_mechanism.pParameter as *const cryptoki_sys::CK_GCM_MESSAGE_PARAMS)
        };
        assert_eq!(p.ulIvLen as usize, iv.len());
        // E0793: params structs are packed on Windows; assert on by-value copies.
        let ul_tag_bits = p.ulTagBits;
        assert_eq!(ul_tag_bits, 128);
        assert!(!p.pIv.is_null());
        // Tag buffer is zero-padded to ceil(tag_bits/8) so the token has room.
        assert!(!p.pTag.is_null());
        let ivs = unsafe { std::slice::from_raw_parts(p.pIv, p.ulIvLen as usize) };
        assert_eq!(ivs, iv.as_slice());
    }

    /// CCM mirrors GCM: a `CK_CCM_MESSAGE_PARAMS` must round-trip through the
    /// reconstruction with its `ulDataLen` and MAC room intact.
    #[test]
    fn ccm_message_init_reconstructs_message_params_struct() {
        let nonce = vec![0x22u8; 13];
        let param = MessageParameter::CcmMessage(CcmMessageParams {
            data_len: 64,
            nonce: nonce.clone(),
            nonce_null_len: None,
            nonce_fixed_bits: 0,
            nonce_generator: 0,
            mac: vec![0; 16],
            mac_null_len: None,
            mac_len: 16,
        });

        let init = build_message_init_mechanism(cryptoki_sys::CKM_AES_CCM as u64, &param)
            .expect("CCM message params reconstruct");

        assert_eq!(
            init.ck_mechanism.ulParameterLen as usize,
            std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>(),
        );
        let p = unsafe {
            &*(init.ck_mechanism.pParameter as *const cryptoki_sys::CK_CCM_MESSAGE_PARAMS)
        };
        // E0793: params structs are packed on Windows; assert on by-value copies.
        let (ul_data_len, ul_mac_len) = (p.ulDataLen, p.ulMACLen);
        assert_eq!(ul_data_len, 64);
        assert_eq!(p.ulNonceLen as usize, nonce.len());
        assert_eq!(ul_mac_len, 16);
        assert!(!p.pMAC.is_null(), "MAC buffer must be allocated for the token to write");
    }

    /// Raw (unrecognised) message params can't be safely reconstructed into a
    /// typed struct and must be rejected rather than shipped blindly.
    #[test]
    fn raw_message_init_param_is_rejected() {
        let param = MessageParameter::Raw(vec![0u8; 8]);
        let result = build_message_init_mechanism(cryptoki_sys::CKM_AES_GCM as u64, &param);
        assert!(
            matches!(result, Err(CkRv::MECHANISM_PARAM_INVALID)),
            "raw message param must be rejected",
        );
    }

    /// Row-6 retained-envelope gate (C3M.6 order item 6): the GCM and CCM
    /// envelope roots and their output cells must survive production-style
    /// owner moves with stable addresses, and input validation must still
    /// accept the moved holder. Reads use unaligned raw projections, never
    /// typed references into retained storage.
    #[test]
    fn native_owner_message_envelopes_survive_moves_and_validate() {
        let gcm_param = MessageParameter::GcmMessage(GcmMessageParams {
            iv: vec![0x11; 12],
            iv_null_len: None,
            iv_fixed_bits: 0,
            iv_generator: cryptoki_sys::CKG_GENERATE_COUNTER_XOR as u64,
            tag: vec![0; 16],
            tag_null_len: None,
            tag_bits: 128,
        });
        let ccm_param = MessageParameter::CcmMessage(CcmMessageParams {
            data_len: 64,
            nonce: vec![0x22; 12],
            nonce_null_len: None,
            nonce_fixed_bits: 0,
            nonce_generator: cryptoki_sys::CKG_GENERATE_COUNTER_XOR as u64,
            mac: vec![0; 16],
            mac_null_len: None,
            mac_len: 16,
        });
        for (mech_type, param, expected_len) in [
            (
                cryptoki_sys::CKM_AES_GCM as u64,
                &gcm_param,
                std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>(),
            ),
            (
                cryptoki_sys::CKM_AES_CCM as u64,
                &ccm_param,
                std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>(),
            ),
        ] {
            let init =
                build_message_init_mechanism(mech_type, param).expect("envelope reconstructs");
            let root = init.ck_mechanism.pParameter;
            assert!(!root.is_null(), "envelope keeps a live root");
            assert_eq!(
                init.ck_mechanism.ulParameterLen as usize, expected_len,
                "envelope advertises its native struct size"
            );
            // Move the holder the way session caches do: Box, then Vec growth.
            let boxed = Box::new(init);
            let mut holders = Vec::with_capacity(1);
            holders.push(*boxed);
            holders.reserve(8);
            let moved_holder = holders.pop().expect("moved holder remains present");
            // E0793: CK_MECHANISM is packed on Windows; assert on a by-value copy.
            let moved_p_parameter = moved_holder.ck_mechanism.pParameter;
            assert_eq!(moved_p_parameter, root, "owner move preserves the retained envelope root");
            assert_eq!(
                moved_holder.ck_mechanism.ulParameterLen as usize, expected_len,
                "owner move preserves the advertised size"
            );
            moved_holder
                .validate_authenticated_inputs(param)
                .expect("moved envelope still validates its inputs");
        }
    }

    #[cfg(unix)]
    unsafe extern "C" fn message_init_ok(
        _: cryptoki_sys::CK_SESSION_HANDLE,
        _: *mut cryptoki_sys::CK_MECHANISM,
        _: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_OK
    }

    /// Row-11 private-owner gate (C3M.6 order item 11): message Init paths
    /// must use call-scoped private owners, never the shared per-family
    /// mechanism slot. A successful AEAD or plain message Init therefore
    /// leaves `mech_cache` and the last-Init marker empty.
    /// Already-green invariant kept as a named regression.
    #[cfg(unix)]
    #[cfg_attr(miri, ignore = "Miri cannot dlopen; covered natively")]
    #[test]
    fn native_owner_message_envelopes_use_private_owner() {
        let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        let mut functions_3_0 = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_0::default());
        functions_3_0.C_MessageEncryptInit = Some(message_init_ok);
        functions_3_0.C_MessageDecryptInit = Some(message_init_ok);
        let backend = FfiBackend {
            _lib: crate::ffi::loading::test_library_handle(),
            func_list: base.as_mut(),
            func_list_3_0: Some(functions_3_0.as_ref()),
            func_list_3_2: None,
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            last_init_family: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
            // Test-local backend: bypasses the process reservation without
            // consuming it; never backs production dispatch (C3M.4).
            construction: crate::ffi::native_domain::ConstructionPermit::unmanaged_test_only(),
            lifecycle: Default::default(),
            retirement_sentinel: crate::ffi::native_domain::RetirementSentinel::unmanaged_test_only(
            ),
        };

        let gcm_mech = CkMechanism { mechanism_type: CkMechanismType::AES_GCM, params: None };
        let gcm_param = MessageParameter::GcmMessage(GcmMessageParams {
            iv: vec![0x11; 12],
            iv_null_len: None,
            iv_fixed_bits: 0,
            iv_generator: cryptoki_sys::CKG_GENERATE_COUNTER_XOR as u64,
            tag: vec![0; 16],
            tag_null_len: None,
            tag_bits: 128,
        });
        backend
            .ffi_message_encrypt_init(
                CkSessionHandle(7),
                Some(&gcm_mech),
                Some(&gcm_param),
                CkObjectHandle(1),
            )
            .expect("AEAD message Init succeeds");
        backend
            .ffi_message_decrypt_init(
                CkSessionHandle(7),
                Some(&gcm_mech),
                Some(&gcm_param),
                CkObjectHandle(1),
            )
            .expect("AEAD message decrypt Init succeeds");

        let plain_mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
        backend
            .ffi_message_encrypt_init(
                CkSessionHandle(7),
                Some(&plain_mech),
                None,
                CkObjectHandle(1),
            )
            .expect("plain message Init succeeds");

        assert!(
            backend.mech_cache.is_empty(),
            "message Inits must not publish into the shared mechanism slot"
        );
        assert!(
            backend.last_init_family.is_empty(),
            "message Inits must not plant a last-Init marker"
        );
    }
}
