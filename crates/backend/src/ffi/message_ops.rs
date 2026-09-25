use super::ffi_conversion::{mechanism_to_ffi, narrow_wire_ulong};
use super::native_allocation::NativeAllocation;
use super::{FfiBackend, call_3x_fn, native_domain::OrdinaryGuard};
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

/// Returns a writable pointer into `buf`, or NULL for an empty buffer (matching
/// the `call_with_*_message_param` convention).
fn message_buf_ptr(buf: &mut [u8]) -> *mut cryptoki_sys::CK_BYTE {
    if buf.is_empty() { std::ptr::null_mut() } else { buf.as_mut_ptr() }
}

/// Copy `src` into a buffer of exactly `len` bytes (zero-padded / truncated),
/// so HSM-writable fields (tag/MAC) always have room for the token's output.
fn message_buf_sized(src: &[u8], len: usize) -> Vec<u8> {
    if src.len() >= len {
        src.to_vec()
    } else {
        let mut buf = vec![0u8; len];
        buf[..src.len()].copy_from_slice(src);
        buf
    }
}

/// Owns a reconstructed `CK_*_MESSAGE_PARAMS` C struct and its backing
/// IV/tag/nonce/MAC buffers so that a `CK_MECHANISM` can reference them across a
/// `C_Message{Encrypt,Decrypt}Init` FFI call. The params struct is boxed (stable
/// heap address) and the buffers live in `_buffers`; both survive a move of this
/// holder, so the raw pointers stored in `ck_mechanism` and the params struct
/// stay valid for as long as the holder is alive.
struct MessageInitMechanism {
    ck_mechanism: cryptoki_sys::CK_MECHANISM,
    _gcm: Option<Box<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>>,
    _ccm: Option<Box<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>>,
    _salsa: Option<Box<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>>,
    _buffers: Vec<Vec<u8>>,
}

/// Build a `CK_MECHANISM` pointing at a boxed `T` (stable heap address).
fn message_mechanism_for<T>(
    mech_type: cryptoki_sys::CK_MECHANISM_TYPE,
    boxed: &mut Box<T>,
) -> cryptoki_sys::CK_MECHANISM {
    cryptoki_sys::CK_MECHANISM {
        mechanism: mech_type,
        pParameter: (&mut **boxed as *mut T).cast(),
        ulParameterLen: std::mem::size_of::<T>() as cryptoki_sys::CK_ULONG,
    }
}

/// Reconstruct an AEAD message-based init mechanism (`CK_GCM_MESSAGE_PARAMS` /
/// `CK_CCM_MESSAGE_PARAMS` / `CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS`) from the
/// structured `MessageParameter` carried alongside a message-init request.
///
/// The message API passes these params to `C_Message{Encrypt,Decrypt}Init` (not
/// to the per-message call), but the same mechanism type (`CKM_AES_GCM`, …) is
/// also used by classic single-shot encryption, so the param SHAPE cannot be
/// inferred from the mechanism type alone — the shim flags the message variant
/// by sending it through this dedicated init field. Field handling mirrors the
/// `call_with_*_message_param` helpers; the difference is that init keeps the
/// struct alive instead of running an output operation.
fn build_message_init_mechanism(
    mech_type: cryptoki_sys::CK_MECHANISM_TYPE,
    param: &MessageParameter,
) -> CkResult<MessageInitMechanism> {
    match param {
        MessageParameter::GcmMessage(gcm) => {
            let mut iv = gcm.iv.clone();
            let mut tag = message_buf_sized(&gcm.tag, (gcm.tag_bits as usize).div_ceil(8));
            let mut boxed = Box::new(cryptoki_sys::CK_GCM_MESSAGE_PARAMS {
                pIv: message_buf_ptr(&mut iv),
                ulIvLen: iv.len() as cryptoki_sys::CK_ULONG,
                ulIvFixedBits: gcm.iv_fixed_bits as cryptoki_sys::CK_ULONG,
                ivGenerator: gcm.iv_generator as cryptoki_sys::CK_ULONG,
                pTag: message_buf_ptr(&mut tag),
                ulTagBits: gcm.tag_bits as cryptoki_sys::CK_ULONG,
            });
            let ck_mechanism = message_mechanism_for(mech_type, &mut boxed);
            Ok(MessageInitMechanism {
                ck_mechanism,
                _gcm: Some(boxed),
                _ccm: None,
                _salsa: None,
                _buffers: vec![iv, tag],
            })
        }
        MessageParameter::CcmMessage(ccm) => {
            let mut nonce = ccm.nonce.clone();
            let mut mac = message_buf_sized(&ccm.mac, ccm.mac_len as usize);
            let mut boxed = Box::new(cryptoki_sys::CK_CCM_MESSAGE_PARAMS {
                ulDataLen: ccm.data_len as cryptoki_sys::CK_ULONG,
                pNonce: message_buf_ptr(&mut nonce),
                ulNonceLen: nonce.len() as cryptoki_sys::CK_ULONG,
                ulNonceFixedBits: ccm.nonce_fixed_bits as cryptoki_sys::CK_ULONG,
                nonceGenerator: ccm.nonce_generator as cryptoki_sys::CK_GENERATOR_FUNCTION,
                pMAC: message_buf_ptr(&mut mac),
                ulMACLen: ccm.mac_len as cryptoki_sys::CK_ULONG,
            });
            let ck_mechanism = message_mechanism_for(mech_type, &mut boxed);
            Ok(MessageInitMechanism {
                ck_mechanism,
                _gcm: None,
                _ccm: Some(boxed),
                _salsa: None,
                _buffers: vec![nonce, mac],
            })
        }
        MessageParameter::SalaChacha(s) => {
            let mut nonce = s.nonce.clone();
            // Poly1305 tag is always 16 bytes.
            let mut tag = message_buf_sized(&s.tag, 16);
            let mut boxed = Box::new(cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS {
                pNonce: message_buf_ptr(&mut nonce),
                ulNonceLen: nonce.len() as cryptoki_sys::CK_ULONG,
                pTag: message_buf_ptr(&mut tag),
            });
            let ck_mechanism = message_mechanism_for(mech_type, &mut boxed);
            Ok(MessageInitMechanism {
                ck_mechanism,
                _gcm: None,
                _ccm: None,
                _salsa: Some(boxed),
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
                let mech_type = mech.mechanism_type.0 as cryptoki_sys::CK_MECHANISM_TYPE;
                let mut init_mech = build_message_init_mechanism(mech_type, param)?;
                call_3x_fn!(
                    self,
                    func_list_3_0,
                    C_MessageEncryptInit,
                    Self::session_handle(session),
                    &mut init_mech.ck_mechanism as *mut cryptoki_sys::CK_MECHANISM,
                    Self::object_handle(key)
                )
            }
            (Some(mech), None) => {
                let mut ffi_mech = mechanism_to_ffi(mech)?;
                call_3x_fn!(
                    &admission,
                    self,
                    func_list_3_0,
                    C_MessageEncryptInit,
                    Self::session_handle(session)?,
                    &mut init_mech.ck_mechanism as *mut cryptoki_sys::CK_MECHANISM,
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        if let Some(param) = init_param {
            let mut init_mech = build_message_init_mechanism(mechanism.mechanism_type.0, param)?;
            if !provider_spec.buffer_present
                || provider_spec.buffer_len != init_mech.ck_mechanism.ulParameterLen as u64
                || provider_spec.value.is_some()
            {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            let _session_fence = self.session_fences.enter(&admission, session)?;
            call_3x_fn!(
                &admission,
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
                &admission,
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
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        })
    }

    pub(super) fn ffi_message_encrypt_final(&self, session: CkSessionHandle) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        call_3x_fn!(
            &admission,
            self,
            func_list_3_0,
            C_MessageEncryptFinal,
            Self::session_handle(session)?
        )
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
                let mech_type = mech.mechanism_type.0 as cryptoki_sys::CK_MECHANISM_TYPE;
                let mut init_mech = build_message_init_mechanism(mech_type, param)?;
                call_3x_fn!(
                    self,
                    func_list_3_0,
                    C_MessageDecryptInit,
                    Self::session_handle(session),
                    &mut init_mech.ck_mechanism as *mut cryptoki_sys::CK_MECHANISM,
                    Self::object_handle(key)
                )
            }
            (Some(mech), None) => {
                let mut ffi_mech = mechanism_to_ffi(mech)?;
                call_3x_fn!(
                    &admission,
                    self,
                    func_list_3_0,
                    C_MessageDecryptInit,
                    Self::session_handle(session)?,
                    &mut init_mech.ck_mechanism as *mut cryptoki_sys::CK_MECHANISM,
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        if let Some(param) = init_param {
            let mut init_mech = build_message_init_mechanism(mechanism.mechanism_type.0, param)?;
            if !provider_spec.buffer_present
                || provider_spec.buffer_len != init_mech.ck_mechanism.ulParameterLen as u64
                || provider_spec.value.is_some()
            {
                return Err(CkRv::MECHANISM_PARAM_INVALID);
            }
            let _session_fence = self.session_fences.enter(&admission, session)?;
            call_3x_fn!(
                &admission,
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
                &admission,
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
            value: provider_spec.buffer_present.then(Vec::new).map(SecretBytes::new),
        })
    }

    pub(super) fn ffi_message_decrypt_final(&self, session: CkSessionHandle) -> CkResult<()> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        call_3x_fn!(
            &admission,
            self,
            func_list_3_0,
            C_MessageDecryptFinal,
            Self::session_handle(session)?
        )
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
                let _session_fence = self.session_fences.enter(&admission, session)?;
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        call_3x_fn!(
            &admission,
            self,
            func_list_3_0,
            C_MessageSignFinal,
            Self::session_handle(session)?
        )
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
                let _session_fence = self.session_fences.enter(&admission, session)?;
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        call_3x_fn!(
            &admission,
            self,
            func_list_3_0,
            C_MessageVerifyFinal,
            Self::session_handle(session)?
        )
    }

    // --- Encrypt Message (one-shot) ---
    // Returns (parameter_out, ciphertext).

    pub(super) fn ffi_encrypt_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: CkInBuf<'_>,
        plaintext: CkInBuf<'_>,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (aad_ptr, aad_len) = native_message_input(aad)?;
        let (pt_ptr, pt_len) = native_message_input(plaintext)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
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
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (aad_ptr, aad_len) = native_message_input(aad)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(&admission, Some(f), |function| unsafe {
            function(
                h_session,
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

    // --- Encrypt Message Next ---
    // Returns (parameter_out, ciphertext_part).

    pub(super) fn ffi_encrypt_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        plaintext_part: CkInBuf<'_>,
        flags: CkFlags,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (pt_ptr, pt_len) = native_message_input(plaintext_part)?;
        let flags = native_message_flags(flags)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
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
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (aad_ptr, aad_len) = native_message_input(aad)?;
        let (ct_ptr, ct_len) = native_message_input(ciphertext)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
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
    ) -> CkResult<SecretBytes> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (aad_ptr, aad_len) = native_message_input(aad)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(&admission, Some(f), |function| unsafe {
            function(
                h_session,
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

    // --- Decrypt Message Next ---
    // Returns (parameter_out, plaintext_part).

    pub(super) fn ffi_decrypt_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        ciphertext_part: CkInBuf<'_>,
        flags: CkFlags,
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (ct_ptr, ct_len) = native_message_input(ciphertext_part)?;
        let flags = native_message_flags(flags)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
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
    ) -> CkResult<(SecretBytes, SecretBytes)> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (data_ptr, data_len) = native_message_input(data)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
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

        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(&admission, Some(f), |function| unsafe {
            function(h_session, parameter.as_mut_ptr() as *mut _, Self::ulong_len(parameter.len()))
        })?;
        Ok(parameter.to_vec().into())
    }

    pub(super) fn ffi_sign_message_begin_exact(
        &self,
        session: CkSessionHandle,
        provider_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<CkParameterRoundtripResult> {
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let (parameter, parameter_len) = empty_only_parameter_pointer(provider_spec)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(&admission, Some(f), |function| unsafe {
            function(h_session, parameter, parameter_len)
        })?;
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
            let h_session = Self::session_handle(session)?;
            let _session_fence = self.session_fences.enter(&admission, session)?;
            Self::call_unit(&admission, Some(f), |function| unsafe {
                function(
                    h_session,
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let (parameter, parameter_len) = empty_only_parameter_pointer(provider_spec)?;
        let (data, data_len) = native_message_input(data_part)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(&admission, Some(f), |function| unsafe {
            function(
                h_session,
                parameter,
                parameter_len,
                data as *mut _,
                data_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        })?;
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let (data_ptr, data_len) = native_message_input(data)?;
        let (sig_ptr, sig_len) = native_message_input(signature)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_VerifyMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let (parameter, parameter_len) = empty_only_parameter_pointer(provider_spec)?;
        let (data, data_len) = native_message_input(data)?;
        let (signature, signature_len) = native_message_input(signature)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(&admission, Some(f), |function| unsafe {
            function(
                h_session,
                parameter,
                parameter_len,
                data as *mut _,
                data_len,
                signature as *mut _,
                signature_len,
            )
        })?;
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_VerifyMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let (parameter, parameter_len) = empty_only_parameter_pointer(provider_spec)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(&admission, Some(f), |function| unsafe {
            function(h_session, parameter, parameter_len)
        })?;
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

        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        Self::call_unit(&admission, Some(f), |function| unsafe {
            function(
                h_session,
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
        let _session_fence = self.session_fences.enter(&admission, session)?;
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
        let _session_fence = self.session_fences.enter(&admission, session)?;
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        if !parameter.is_empty() {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        validate_empty_only_parameter_spec(param_out_spec)?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (data_ptr, data_len) = native_message_input(data)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
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
        let _session_fence = self.session_fences.enter(&admission, session)?;
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
        let _session_fence = self.session_fences.enter(&admission, session)?;
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        if !parameter.is_empty() {
            return Err(CkRv::MECHANISM_PARAM_INVALID);
        }
        validate_empty_only_parameter_spec(param_out_spec)?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (dp_ptr, dp_len) = native_message_input(data_part)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
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
        _admission: &OrdinaryGuard,
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
            let capped = super::call_helpers::capped_output_len(output_spec.buffer_len as u64);
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
                        value: Some(buf.into()),
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
            let capped = super::call_helpers::capped_output_len(output_spec.buffer_len as u64);
            out_len = capped as cryptoki_sys::CK_ULONG;
            let mut buf = vec![0u8; capped];
            let rv = call(&mut ck_params, buf.as_mut_ptr(), &mut out_len);
            if rv == CkRv::OK.0 as cryptoki_sys::CK_RV {
                buf.truncate(out_len as usize);
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::OK,
                        returned_len: Some(out_len as u64),
                        value: Some(buf.into()),
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
            let capped = super::call_helpers::capped_output_len(output_spec.buffer_len as u64);
            out_len = capped as cryptoki_sys::CK_ULONG;
            let mut buf = vec![0u8; capped];
            let rv = call(&mut ck_params, buf.as_mut_ptr(), &mut out_len);
            if rv == CkRv::OK.0 as cryptoki_sys::CK_RV {
                buf.truncate(out_len as usize);
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::OK,
                        returned_len: Some(out_len as u64),
                        value: Some(buf.into()),
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
        _admission: &OrdinaryGuard,
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        self.ffi_message_begin_msg_impl(
            &admission,
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        self.ffi_message_begin_msg_impl(
            &admission,
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let acknowledgement = structured_parameter_ack(msg_param, provider_spec, CkRv::OK)?;
        let (input_ptr, input_len) = native_message_input(plaintext)?;
        let (aad_ptr, aad_len) = native_message_input(aad)?;
        let native = build_message_init_mechanism(0, msg_param)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        let output =
            Self::single_call_bytes_exact(&admission, output_spec, |buffer, length| unsafe {
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let acknowledgement = structured_parameter_ack(msg_param, provider_spec, CkRv::OK)?;
        let (input_ptr, input_len) = native_message_input(ciphertext)?;
        let (aad_ptr, aad_len) = native_message_input(aad)?;
        let native = build_message_init_mechanism(0, msg_param)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        let output =
            Self::single_call_bytes_exact(&admission, output_spec, |buffer, length| unsafe {
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
        let _session_fence = self.session_fences.enter(&admission, session)?;
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let acknowledgement = structured_parameter_ack(msg_param, provider_spec, CkRv::OK)?;
        let (input_ptr, input_len) = native_message_input(plaintext_part)?;
        let flags = native_message_flags(flags)?;
        let native = build_message_init_mechanism(0, msg_param)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        let output =
            Self::single_call_bytes_exact(&admission, output_spec, |buffer, length| unsafe {
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
        let admission = self.lifecycle_domain.admit_ordinary()?;
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let acknowledgement = structured_parameter_ack(msg_param, provider_spec, CkRv::OK)?;
        let (input_ptr, input_len) = native_message_input(ciphertext_part)?;
        let flags = native_message_flags(flags)?;
        let native = build_message_init_mechanism(0, msg_param)?;
        let h_session = Self::session_handle(session)?;
        let _session_fence = self.session_fences.enter(&admission, session)?;
        let output =
            Self::single_call_bytes_exact(&admission, output_spec, |buffer, length| unsafe {
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
        let _session_fence = self.session_fences.enter(&admission, session)?;
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
            iv_fixed_bits: 0,
            iv_generator: 0,
            tag: Vec::new(), // empty input tag — backend writes it
            tag_bits: 128,
        });

        let init = build_message_init_mechanism(
            cryptoki_sys::CKM_AES_GCM as cryptoki_sys::CK_MECHANISM_TYPE,
            &param,
        )
        .expect("GCM message params reconstruct");

        assert_eq!(
            init.ck_mechanism.mechanism,
            cryptoki_sys::CKM_AES_GCM as cryptoki_sys::CK_MECHANISM_TYPE
        );
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
        assert_eq!(p.ulTagBits, 128);
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
            nonce_fixed_bits: 0,
            nonce_generator: 0,
            mac: Vec::new(),
            mac_len: 16,
        });

        let init = build_message_init_mechanism(
            cryptoki_sys::CKM_AES_CCM as cryptoki_sys::CK_MECHANISM_TYPE,
            &param,
        )
        .expect("CCM message params reconstruct");

        assert_eq!(
            init.ck_mechanism.ulParameterLen as usize,
            std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>(),
        );
        let p = unsafe {
            &*(init.ck_mechanism.pParameter as *const cryptoki_sys::CK_CCM_MESSAGE_PARAMS)
        };
        assert_eq!(p.ulDataLen, 64);
        assert_eq!(p.ulNonceLen as usize, nonce.len());
        assert_eq!(p.ulMACLen, 16);
        assert!(!p.pMAC.is_null(), "MAC buffer must be allocated for the token to write");
    }

    /// Raw (unrecognised) message params can't be safely reconstructed into a
    /// typed struct and must be rejected rather than shipped blindly.
    #[test]
    fn raw_message_init_param_is_rejected() {
        let param = MessageParameter::Raw(vec![0u8; 8]);
        let result = build_message_init_mechanism(
            cryptoki_sys::CKM_AES_GCM as cryptoki_sys::CK_MECHANISM_TYPE,
            &param,
        );
        assert!(
            matches!(result, Err(CkRv::MECHANISM_PARAM_INVALID)),
            "raw message param must be rejected",
        );
    }
}
