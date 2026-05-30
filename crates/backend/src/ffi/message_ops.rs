use super::ffi_conversion::mechanism_to_ffi;
use super::{FfiBackend, call_3x_fn};
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
        $self:expr, $func_name:ident, $parameter:expr,
        [ $($pre_arg:expr),+ $(,)? ]
        $(, [ $($post_arg:expr),+ $(,)? ] )?
    ) => {{
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
        Ok((parameter_out, output))
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
                    self,
                    func_list_3_0,
                    C_MessageEncryptInit,
                    Self::session_handle(session),
                    &mut ffi_mech.ck_mechanism as *mut cryptoki_sys::CK_MECHANISM,
                    Self::object_handle(key)
                )
            }
            (None, _) => {
                // NULL mechanism = cancel active message-encrypt state
                call_3x_fn!(
                    self,
                    func_list_3_0,
                    C_MessageEncryptInit,
                    Self::session_handle(session),
                    std::ptr::null_mut::<cryptoki_sys::CK_MECHANISM>(),
                    Self::object_handle(key)
                )
            }
        }
    }

    pub(super) fn ffi_message_encrypt_final(&self, session: CkSessionHandle) -> CkResult<()> {
        call_3x_fn!(self, func_list_3_0, C_MessageEncryptFinal, Self::session_handle(session))
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
                    self,
                    func_list_3_0,
                    C_MessageDecryptInit,
                    Self::session_handle(session),
                    &mut ffi_mech.ck_mechanism as *mut cryptoki_sys::CK_MECHANISM,
                    Self::object_handle(key)
                )
            }
            (None, _) => {
                // NULL mechanism = cancel active message-decrypt state
                call_3x_fn!(
                    self,
                    func_list_3_0,
                    C_MessageDecryptInit,
                    Self::session_handle(session),
                    std::ptr::null_mut::<cryptoki_sys::CK_MECHANISM>(),
                    Self::object_handle(key)
                )
            }
        }
    }

    pub(super) fn ffi_message_decrypt_final(&self, session: CkSessionHandle) -> CkResult<()> {
        call_3x_fn!(self, func_list_3_0, C_MessageDecryptFinal, Self::session_handle(session))
    }

    // --- Message Sign ---

    pub(super) fn ffi_message_sign_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        match mechanism {
            Some(mech) => {
                let mut ffi_mech = mechanism_to_ffi(mech)?;
                call_3x_fn!(
                    self,
                    func_list_3_0,
                    C_MessageSignInit,
                    Self::session_handle(session),
                    &mut ffi_mech.ck_mechanism as *mut cryptoki_sys::CK_MECHANISM,
                    Self::object_handle(key)
                )
            }
            None => {
                // NULL mechanism = cancel active message-sign state
                call_3x_fn!(
                    self,
                    func_list_3_0,
                    C_MessageSignInit,
                    Self::session_handle(session),
                    std::ptr::null_mut::<cryptoki_sys::CK_MECHANISM>(),
                    Self::object_handle(key)
                )
            }
        }
    }

    pub(super) fn ffi_message_sign_final(&self, session: CkSessionHandle) -> CkResult<()> {
        call_3x_fn!(self, func_list_3_0, C_MessageSignFinal, Self::session_handle(session))
    }

    // --- Message Verify ---

    pub(super) fn ffi_message_verify_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        match mechanism {
            Some(mech) => {
                let mut ffi_mech = mechanism_to_ffi(mech)?;
                call_3x_fn!(
                    self,
                    func_list_3_0,
                    C_MessageVerifyInit,
                    Self::session_handle(session),
                    &mut ffi_mech.ck_mechanism as *mut cryptoki_sys::CK_MECHANISM,
                    Self::object_handle(key)
                )
            }
            None => {
                // NULL mechanism = cancel active message-verify state
                call_3x_fn!(
                    self,
                    func_list_3_0,
                    C_MessageVerifyInit,
                    Self::session_handle(session),
                    std::ptr::null_mut::<cryptoki_sys::CK_MECHANISM>(),
                    Self::object_handle(key)
                )
            }
        }
    }

    pub(super) fn ffi_message_verify_final(&self, session: CkSessionHandle) -> CkResult<()> {
        call_3x_fn!(self, func_list_3_0, C_MessageVerifyFinal, Self::session_handle(session))
    }

    // --- Encrypt Message (one-shot) ---
    // Returns (parameter_out, ciphertext).

    pub(super) fn ffi_encrypt_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        two_call_message!(
            self,
            C_EncryptMessage,
            parameter,
            [
                Self::session_handle(session),
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                aad.as_ptr() as *mut _,
                Self::ulong_len(aad.len()),
                plaintext.as_ptr() as *mut _,
                Self::ulong_len(plaintext.len()),
            ]
        )
    }

    // --- Encrypt Message Begin ---
    // Returns parameter_out.

    pub(super) fn ffi_encrypt_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: &[u8],
    ) -> CkResult<Vec<u8>> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let rv = unsafe {
            f(
                Self::session_handle(session),
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                aad.as_ptr() as *mut _,
                Self::ulong_len(aad.len()),
            )
        };
        Self::ck_result(rv)?;
        Ok(parameter.to_vec())
    }

    // --- Encrypt Message Next ---
    // Returns (parameter_out, ciphertext_part).

    pub(super) fn ffi_encrypt_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        plaintext_part: &[u8],
        flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        two_call_message!(
            self,
            C_EncryptMessageNext,
            parameter,
            [
                Self::session_handle(session),
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                plaintext_part.as_ptr() as *mut _,
                Self::ulong_len(plaintext_part.len()),
            ],
            [flags.0 as cryptoki_sys::CK_FLAGS,]
        )
    }

    // --- Decrypt Message (one-shot) ---
    // Returns (parameter_out, plaintext).

    pub(super) fn ffi_decrypt_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        two_call_message!(
            self,
            C_DecryptMessage,
            parameter,
            [
                Self::session_handle(session),
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                aad.as_ptr() as *mut _,
                Self::ulong_len(aad.len()),
                ciphertext.as_ptr() as *mut _,
                Self::ulong_len(ciphertext.len()),
            ]
        )
    }

    // --- Decrypt Message Begin ---
    // Returns parameter_out.

    pub(super) fn ffi_decrypt_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: &[u8],
    ) -> CkResult<Vec<u8>> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let rv = unsafe {
            f(
                Self::session_handle(session),
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                aad.as_ptr() as *mut _,
                Self::ulong_len(aad.len()),
            )
        };
        Self::ck_result(rv)?;
        Ok(parameter.to_vec())
    }

    // --- Decrypt Message Next ---
    // Returns (parameter_out, plaintext_part).

    pub(super) fn ffi_decrypt_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        ciphertext_part: &[u8],
        flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        two_call_message!(
            self,
            C_DecryptMessageNext,
            parameter,
            [
                Self::session_handle(session),
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                ciphertext_part.as_ptr() as *mut _,
                Self::ulong_len(ciphertext_part.len()),
            ],
            [flags.0 as cryptoki_sys::CK_FLAGS,]
        )
    }

    // --- Sign Message (one-shot) ---
    // Returns (parameter_out, signature).

    pub(super) fn ffi_sign_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        data: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        two_call_message!(
            self,
            C_SignMessage,
            parameter,
            [
                Self::session_handle(session),
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                data.as_ptr() as *mut _,
                Self::ulong_len(data.len()),
            ]
        )
    }

    // --- Sign Message Begin ---
    // Returns parameter_out.

    pub(super) fn ffi_sign_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
    ) -> CkResult<Vec<u8>> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessageBegin }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let rv = unsafe {
            f(
                Self::session_handle(session),
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
            )
        };
        Self::ck_result(rv)?;
        Ok(parameter.to_vec())
    }

    // --- Sign Message Next ---
    // Returns (parameter_out, signature).
    // If request_signature is false, signature is empty (more data feeding).

    pub(super) fn ffi_sign_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        data_part: &[u8],
        request_signature: bool,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        if !request_signature {
            // Feed data — pSignature is NULL, pulSignatureLen is NULL
            let rv = unsafe {
                f(
                    Self::session_handle(session),
                    parameter.as_mut_ptr() as *mut _,
                    Self::ulong_len(parameter.len()),
                    data_part.as_ptr() as *mut _,
                    Self::ulong_len(data_part.len()),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            Self::ck_result(rv)?;
            let parameter_out = parameter.to_vec();
            return Ok((parameter_out, Vec::new()));
        }

        // Final call — request signature via two-call pattern
        two_call_message!(
            self,
            C_SignMessageNext,
            parameter,
            [
                Self::session_handle(session),
                parameter.as_mut_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                data_part.as_ptr() as *mut _,
                Self::ulong_len(data_part.len()),
            ]
        )
    }

    // --- Verify Message (one-shot) ---
    // No output buffer. Parameter is input-only.

    pub(super) fn ffi_verify_message(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> CkResult<()> {
        call_3x_fn!(
            self,
            func_list_3_0,
            C_VerifyMessage,
            Self::session_handle(session),
            parameter.as_ptr() as *mut _,
            Self::ulong_len(parameter.len()),
            data.as_ptr() as *mut _,
            Self::ulong_len(data.len()),
            signature.as_ptr() as *mut _,
            Self::ulong_len(signature.len())
        )
    }

    // --- Verify Message Begin ---
    // No output buffer. Parameter is input-only.

    pub(super) fn ffi_verify_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
    ) -> CkResult<()> {
        call_3x_fn!(
            self,
            func_list_3_0,
            C_VerifyMessageBegin,
            Self::session_handle(session),
            parameter.as_ptr() as *mut _,
            Self::ulong_len(parameter.len())
        )
    }

    // --- Verify Message Next ---
    // No output buffer. Parameter is input-only.
    // If is_final is true, signature is provided for verification.
    // If is_final is false, pSignature is NULL (feed data).

    pub(super) fn ffi_verify_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        data_part: &[u8],
        is_final: bool,
        signature: &[u8],
    ) -> CkResult<()> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_VerifyMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        let (sig_ptr, sig_len) = if is_final {
            (signature.as_ptr() as *mut _, Self::ulong_len(signature.len()))
        } else {
            (std::ptr::null_mut(), 0)
        };

        let rv = unsafe {
            f(
                Self::session_handle(session),
                parameter.as_ptr() as *mut _,
                Self::ulong_len(parameter.len()),
                data_part.as_ptr() as *mut _,
                Self::ulong_len(data_part.len()),
                sig_ptr,
                sig_len,
            )
        };
        Self::ck_result(rv)
    }

    // --- Exact parameter-output message operations (Track C) ---

    pub(super) fn ffi_encrypt_message_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        Self::single_call_parameter_output_exact(
            output_spec,
            parameter,
            param_out_spec,
            |param_ptr, param_len, output, output_len| unsafe {
                f(
                    Self::session_handle(session),
                    param_ptr as *mut _,
                    param_len,
                    aad.as_ptr() as *mut _,
                    Self::ulong_len(aad.len()),
                    plaintext.as_ptr() as *mut _,
                    Self::ulong_len(plaintext.len()),
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
        aad: &[u8],
        ciphertext: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        Self::single_call_parameter_output_exact(
            output_spec,
            parameter,
            param_out_spec,
            |param_ptr, param_len, output, output_len| unsafe {
                f(
                    Self::session_handle(session),
                    param_ptr as *mut _,
                    param_len,
                    aad.as_ptr() as *mut _,
                    Self::ulong_len(aad.len()),
                    ciphertext.as_ptr() as *mut _,
                    Self::ulong_len(ciphertext.len()),
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
        data: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        Self::single_call_parameter_output_exact(
            output_spec,
            parameter,
            param_out_spec,
            |param_ptr, param_len, output, output_len| unsafe {
                f(
                    Self::session_handle(session),
                    param_ptr as *mut _,
                    param_len,
                    data.as_ptr() as *mut _,
                    Self::ulong_len(data.len()),
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
        plaintext_part: &[u8],
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        Self::single_call_parameter_output_exact(
            output_spec,
            parameter,
            param_out_spec,
            |param_ptr, param_len, output, output_len| unsafe {
                f(
                    Self::session_handle(session),
                    param_ptr as *mut _,
                    param_len,
                    plaintext_part.as_ptr() as *mut _,
                    Self::ulong_len(plaintext_part.len()),
                    output,
                    output_len,
                    flags.0 as cryptoki_sys::CK_FLAGS,
                )
            },
        )
    }

    pub(super) fn ffi_decrypt_message_next_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        ciphertext_part: &[u8],
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        Self::single_call_parameter_output_exact(
            output_spec,
            parameter,
            param_out_spec,
            |param_ptr, param_len, output, output_len| unsafe {
                f(
                    Self::session_handle(session),
                    param_ptr as *mut _,
                    param_len,
                    ciphertext_part.as_ptr() as *mut _,
                    Self::ulong_len(ciphertext_part.len()),
                    output,
                    output_len,
                    flags.0 as cryptoki_sys::CK_FLAGS,
                )
            },
        )
    }

    pub(super) fn ffi_sign_message_next_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        data_part: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        Self::single_call_parameter_output_exact(
            output_spec,
            parameter,
            param_out_spec,
            |param_ptr, param_len, output, output_len| unsafe {
                f(
                    Self::session_handle(session),
                    param_ptr as *mut _,
                    param_len,
                    data_part.as_ptr() as *mut _,
                    Self::ulong_len(data_part.len()),
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

    /// Common helper: call a message crypto FFI function with a GCM message
    /// parameter struct.  Allocates local IV and tag buffers, constructs the
    /// C struct, makes the call, and reads back the (possibly modified) IV
    /// and tag data.
    fn call_with_gcm_message_param<F>(
        &self,
        gcm: &GcmMessageParams,
        output_spec: &CkOutputBufferSpec,
        mut call: F,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)>
    where
        F: FnMut(
            *mut cryptoki_sys::CK_GCM_MESSAGE_PARAMS,
            *mut cryptoki_sys::CK_BYTE,
            &mut cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        let mut iv_buf = gcm.iv.clone();
        let tag_bytes = (gcm.tag_bits as usize).div_ceil(8);
        let mut tag_buf = if gcm.tag.len() >= tag_bytes {
            gcm.tag.clone()
        } else {
            let mut buf = vec![0u8; tag_bytes];
            let copy_len = gcm.tag.len().min(tag_bytes);
            buf[..copy_len].copy_from_slice(&gcm.tag[..copy_len]);
            buf
        };

        let mut ck_params = cryptoki_sys::CK_GCM_MESSAGE_PARAMS {
            pIv: if iv_buf.is_empty() { std::ptr::null_mut() } else { iv_buf.as_mut_ptr() },
            ulIvLen: iv_buf.len() as cryptoki_sys::CK_ULONG,
            ulIvFixedBits: gcm.iv_fixed_bits as cryptoki_sys::CK_ULONG,
            ivGenerator: gcm.iv_generator as cryptoki_sys::CK_ULONG,
            pTag: if tag_buf.is_empty() { std::ptr::null_mut() } else { tag_buf.as_mut_ptr() },
            ulTagBits: gcm.tag_bits as cryptoki_sys::CK_ULONG,
        };

        let mut out_len: cryptoki_sys::CK_ULONG = 0;

        if !output_spec.buffer_present {
            // Size query
            let rv = call(&mut ck_params, std::ptr::null_mut(), &mut out_len);
            if rv == CkRv::OK.0 {
                let result_gcm = GcmMessageParams {
                    iv: iv_buf,
                    iv_fixed_bits: gcm.iv_fixed_bits,
                    iv_generator: gcm.iv_generator,
                    tag: tag_buf,
                    tag_bits: gcm.tag_bits,
                };
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::OK,
                        returned_len: out_len as u64,
                        value: None,
                    },
                    MessageParameter::GcmMessage(result_gcm),
                ))
            } else {
                Err(CkRv(rv))
            }
        } else {
            out_len = output_spec.buffer_len as cryptoki_sys::CK_ULONG;
            let mut buf = vec![0u8; output_spec.buffer_len as usize];
            let rv = call(&mut ck_params, buf.as_mut_ptr(), &mut out_len);

            if rv == CkRv::OK.0 {
                buf.truncate(out_len as usize);
                let result_gcm = GcmMessageParams {
                    iv: iv_buf,
                    iv_fixed_bits: gcm.iv_fixed_bits,
                    iv_generator: gcm.iv_generator,
                    tag: tag_buf,
                    tag_bits: gcm.tag_bits,
                };
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::OK,
                        returned_len: out_len as u64,
                        value: Some(buf),
                    },
                    MessageParameter::GcmMessage(result_gcm),
                ))
            } else if rv == CkRv::BUFFER_TOO_SMALL.0 {
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::BUFFER_TOO_SMALL,
                        returned_len: out_len as u64,
                        value: None,
                    },
                    MessageParameter::GcmMessage(GcmMessageParams {
                        iv: iv_buf,
                        iv_fixed_bits: gcm.iv_fixed_bits,
                        iv_generator: gcm.iv_generator,
                        tag: tag_buf,
                        tag_bits: gcm.tag_bits,
                    }),
                ))
            } else {
                Err(CkRv(rv))
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
        ccm: &CcmMessageParams,
        output_spec: &CkOutputBufferSpec,
        mut call: F,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)>
    where
        F: FnMut(
            *mut cryptoki_sys::CK_CCM_MESSAGE_PARAMS,
            *mut cryptoki_sys::CK_BYTE,
            &mut cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        let mut nonce_buf = ccm.nonce.clone();
        let mac_bytes = ccm.mac_len as usize;
        let mut mac_buf = if ccm.mac.len() >= mac_bytes {
            ccm.mac.clone()
        } else {
            let mut buf = vec![0u8; mac_bytes];
            let copy_len = ccm.mac.len().min(mac_bytes);
            buf[..copy_len].copy_from_slice(&ccm.mac[..copy_len]);
            buf
        };

        let mut ck_params = cryptoki_sys::CK_CCM_MESSAGE_PARAMS {
            ulDataLen: ccm.data_len as cryptoki_sys::CK_ULONG,
            pNonce: if nonce_buf.is_empty() {
                std::ptr::null_mut()
            } else {
                nonce_buf.as_mut_ptr()
            },
            ulNonceLen: nonce_buf.len() as cryptoki_sys::CK_ULONG,
            ulNonceFixedBits: ccm.nonce_fixed_bits as cryptoki_sys::CK_ULONG,
            nonceGenerator: ccm.nonce_generator as cryptoki_sys::CK_GENERATOR_FUNCTION,
            pMAC: if mac_buf.is_empty() { std::ptr::null_mut() } else { mac_buf.as_mut_ptr() },
            ulMACLen: ccm.mac_len as cryptoki_sys::CK_ULONG,
        };

        let mut out_len: cryptoki_sys::CK_ULONG = 0;
        let snapshot = |nonce_buf: &Vec<u8>, mac_buf: &Vec<u8>| {
            MessageParameter::CcmMessage(CcmMessageParams {
                data_len: ccm.data_len,
                nonce: nonce_buf.clone(),
                nonce_fixed_bits: ccm.nonce_fixed_bits,
                nonce_generator: ccm.nonce_generator,
                mac: mac_buf.clone(),
                mac_len: ccm.mac_len,
            })
        };

        if !output_spec.buffer_present {
            let rv = call(&mut ck_params, std::ptr::null_mut(), &mut out_len);
            if rv == CkRv::OK.0 {
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::OK,
                        returned_len: out_len as u64,
                        value: None,
                    },
                    snapshot(&nonce_buf, &mac_buf),
                ))
            } else {
                Err(CkRv(rv))
            }
        } else {
            out_len = output_spec.buffer_len as cryptoki_sys::CK_ULONG;
            let mut buf = vec![0u8; output_spec.buffer_len as usize];
            let rv = call(&mut ck_params, buf.as_mut_ptr(), &mut out_len);
            if rv == CkRv::OK.0 {
                buf.truncate(out_len as usize);
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::OK,
                        returned_len: out_len as u64,
                        value: Some(buf),
                    },
                    snapshot(&nonce_buf, &mac_buf),
                ))
            } else if rv == CkRv::BUFFER_TOO_SMALL.0 {
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::BUFFER_TOO_SMALL,
                        returned_len: out_len as u64,
                        value: None,
                    },
                    snapshot(&nonce_buf, &mac_buf),
                ))
            } else {
                Err(CkRv(rv))
            }
        }
    }

    /// Common helper: call a message crypto FFI function with a
    /// Salsa20/ChaCha20-Poly1305 message-parameter struct.  The C
    /// struct has only `pNonce`/`ulNonceLen`/`pTag` — caller provides
    /// the nonce, HSM populates the tag.
    fn call_with_salsa20_chacha20_poly1305_message_param<F>(
        &self,
        params: &Salsa20ChaCha20Poly1305MessageParams,
        output_spec: &CkOutputBufferSpec,
        mut call: F,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)>
    where
        F: FnMut(
            *mut cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS,
            *mut cryptoki_sys::CK_BYTE,
            &mut cryptoki_sys::CK_ULONG,
        ) -> cryptoki_sys::CK_RV,
    {
        let mut nonce_buf = params.nonce.clone();
        // The CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS struct has no
        // explicit tag length — Poly1305 is always 16 bytes.
        const POLY1305_TAG_LEN: usize = 16;
        let mut tag_buf = if params.tag.len() >= POLY1305_TAG_LEN {
            params.tag.clone()
        } else {
            let mut buf = vec![0u8; POLY1305_TAG_LEN];
            let copy_len = params.tag.len().min(POLY1305_TAG_LEN);
            buf[..copy_len].copy_from_slice(&params.tag[..copy_len]);
            buf
        };

        let mut ck_params = cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS {
            pNonce: if nonce_buf.is_empty() {
                std::ptr::null_mut()
            } else {
                nonce_buf.as_mut_ptr()
            },
            ulNonceLen: nonce_buf.len() as cryptoki_sys::CK_ULONG,
            pTag: if tag_buf.is_empty() { std::ptr::null_mut() } else { tag_buf.as_mut_ptr() },
        };

        let mut out_len: cryptoki_sys::CK_ULONG = 0;
        let snapshot = |nonce_buf: &Vec<u8>, tag_buf: &Vec<u8>| {
            MessageParameter::SalaChacha(Salsa20ChaCha20Poly1305MessageParams {
                nonce: nonce_buf.clone(),
                tag: tag_buf.clone(),
            })
        };

        if !output_spec.buffer_present {
            let rv = call(&mut ck_params, std::ptr::null_mut(), &mut out_len);
            if rv == CkRv::OK.0 {
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::OK,
                        returned_len: out_len as u64,
                        value: None,
                    },
                    snapshot(&nonce_buf, &tag_buf),
                ))
            } else {
                Err(CkRv(rv))
            }
        } else {
            out_len = output_spec.buffer_len as cryptoki_sys::CK_ULONG;
            let mut buf = vec![0u8; output_spec.buffer_len as usize];
            let rv = call(&mut ck_params, buf.as_mut_ptr(), &mut out_len);
            if rv == CkRv::OK.0 {
                buf.truncate(out_len as usize);
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::OK,
                        returned_len: out_len as u64,
                        value: Some(buf),
                    },
                    snapshot(&nonce_buf, &tag_buf),
                ))
            } else if rv == CkRv::BUFFER_TOO_SMALL.0 {
                Ok((
                    CkOutputBufferResult {
                        ck_rv: CkRv::BUFFER_TOO_SMALL,
                        returned_len: out_len as u64,
                        value: None,
                    },
                    snapshot(&nonce_buf, &tag_buf),
                ))
            } else {
                Err(CkRv(rv))
            }
        }
    }

    /// C_EncryptMessage with structured GCM message parameter.
    pub(super) fn ffi_encrypt_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        aad: &[u8],
        plaintext: &[u8],
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        match msg_param {
            MessageParameter::GcmMessage(gcm) => self.call_with_gcm_message_param(
                gcm,
                output_spec,
                |params, output, output_len| unsafe {
                    f(
                        Self::session_handle(session),
                        params as *mut _ as *mut _,
                        std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>()
                            as cryptoki_sys::CK_ULONG,
                        aad.as_ptr() as *mut _,
                        Self::ulong_len(aad.len()),
                        plaintext.as_ptr() as *mut _,
                        Self::ulong_len(plaintext.len()),
                        output,
                        output_len,
                    )
                },
            ),
            MessageParameter::CcmMessage(ccm) => self.call_with_ccm_message_param(
                ccm,
                output_spec,
                |params, output, output_len| unsafe {
                    f(
                        Self::session_handle(session),
                        params as *mut _ as *mut _,
                        std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>()
                            as cryptoki_sys::CK_ULONG,
                        aad.as_ptr() as *mut _,
                        Self::ulong_len(aad.len()),
                        plaintext.as_ptr() as *mut _,
                        Self::ulong_len(plaintext.len()),
                        output,
                        output_len,
                    )
                },
            ),
            MessageParameter::SalaChacha(params_in) => self
                .call_with_salsa20_chacha20_poly1305_message_param(
                    params_in,
                    output_spec,
                    |params, output, output_len| unsafe {
                        f(
                            Self::session_handle(session),
                            params as *mut _ as *mut _,
                            std::mem::size_of::<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>()
                                as cryptoki_sys::CK_ULONG,
                            aad.as_ptr() as *mut _,
                            Self::ulong_len(aad.len()),
                            plaintext.as_ptr() as *mut _,
                            Self::ulong_len(plaintext.len()),
                            output,
                            output_len,
                        )
                    },
                ),
            _ => Err(CkRv::FUNCTION_NOT_SUPPORTED),
        }
    }

    /// C_DecryptMessage with structured message parameter.
    pub(super) fn ffi_decrypt_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        aad: &[u8],
        ciphertext: &[u8],
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        match msg_param {
            MessageParameter::GcmMessage(gcm) => self.call_with_gcm_message_param(
                gcm,
                output_spec,
                |params, output, output_len| unsafe {
                    f(
                        Self::session_handle(session),
                        params as *mut _ as *mut _,
                        std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>()
                            as cryptoki_sys::CK_ULONG,
                        aad.as_ptr() as *mut _,
                        Self::ulong_len(aad.len()),
                        ciphertext.as_ptr() as *mut _,
                        Self::ulong_len(ciphertext.len()),
                        output,
                        output_len,
                    )
                },
            ),
            MessageParameter::CcmMessage(ccm) => self.call_with_ccm_message_param(
                ccm,
                output_spec,
                |params, output, output_len| unsafe {
                    f(
                        Self::session_handle(session),
                        params as *mut _ as *mut _,
                        std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>()
                            as cryptoki_sys::CK_ULONG,
                        aad.as_ptr() as *mut _,
                        Self::ulong_len(aad.len()),
                        ciphertext.as_ptr() as *mut _,
                        Self::ulong_len(ciphertext.len()),
                        output,
                        output_len,
                    )
                },
            ),
            MessageParameter::SalaChacha(params_in) => self
                .call_with_salsa20_chacha20_poly1305_message_param(
                    params_in,
                    output_spec,
                    |params, output, output_len| unsafe {
                        f(
                            Self::session_handle(session),
                            params as *mut _ as *mut _,
                            std::mem::size_of::<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>()
                                as cryptoki_sys::CK_ULONG,
                            aad.as_ptr() as *mut _,
                            Self::ulong_len(aad.len()),
                            ciphertext.as_ptr() as *mut _,
                            Self::ulong_len(ciphertext.len()),
                            output,
                            output_len,
                        )
                    },
                ),
            _ => Err(CkRv::FUNCTION_NOT_SUPPORTED),
        }
    }

    /// C_SignMessage with structured message parameter.
    pub(super) fn ffi_sign_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        data: &[u8],
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessage }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        match msg_param {
            MessageParameter::GcmMessage(gcm) => self.call_with_gcm_message_param(
                gcm,
                output_spec,
                |params, output, output_len| unsafe {
                    f(
                        Self::session_handle(session),
                        params as *mut _ as *mut _,
                        std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>()
                            as cryptoki_sys::CK_ULONG,
                        data.as_ptr() as *mut _,
                        Self::ulong_len(data.len()),
                        output,
                        output_len,
                    )
                },
            ),
            MessageParameter::CcmMessage(ccm) => self.call_with_ccm_message_param(
                ccm,
                output_spec,
                |params, output, output_len| unsafe {
                    f(
                        Self::session_handle(session),
                        params as *mut _ as *mut _,
                        std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>()
                            as cryptoki_sys::CK_ULONG,
                        data.as_ptr() as *mut _,
                        Self::ulong_len(data.len()),
                        output,
                        output_len,
                    )
                },
            ),
            MessageParameter::SalaChacha(params_in) => self
                .call_with_salsa20_chacha20_poly1305_message_param(
                    params_in,
                    output_spec,
                    |params, output, output_len| unsafe {
                        f(
                            Self::session_handle(session),
                            params as *mut _ as *mut _,
                            std::mem::size_of::<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>()
                                as cryptoki_sys::CK_ULONG,
                            data.as_ptr() as *mut _,
                            Self::ulong_len(data.len()),
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
        plaintext_part: &[u8],
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_EncryptMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        match msg_param {
            MessageParameter::GcmMessage(gcm) => self.call_with_gcm_message_param(
                gcm,
                output_spec,
                |params, output, output_len| unsafe {
                    f(
                        Self::session_handle(session),
                        params as *mut _ as *mut _,
                        std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>()
                            as cryptoki_sys::CK_ULONG,
                        plaintext_part.as_ptr() as *mut _,
                        Self::ulong_len(plaintext_part.len()),
                        output,
                        output_len,
                        flags.0 as cryptoki_sys::CK_FLAGS,
                    )
                },
            ),
            MessageParameter::CcmMessage(ccm) => self.call_with_ccm_message_param(
                ccm,
                output_spec,
                |params, output, output_len| unsafe {
                    f(
                        Self::session_handle(session),
                        params as *mut _ as *mut _,
                        std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>()
                            as cryptoki_sys::CK_ULONG,
                        plaintext_part.as_ptr() as *mut _,
                        Self::ulong_len(plaintext_part.len()),
                        output,
                        output_len,
                        flags.0 as cryptoki_sys::CK_FLAGS,
                    )
                },
            ),
            MessageParameter::SalaChacha(params_in) => self
                .call_with_salsa20_chacha20_poly1305_message_param(
                    params_in,
                    output_spec,
                    |params, output, output_len| unsafe {
                        f(
                            Self::session_handle(session),
                            params as *mut _ as *mut _,
                            std::mem::size_of::<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>()
                                as cryptoki_sys::CK_ULONG,
                            plaintext_part.as_ptr() as *mut _,
                            Self::ulong_len(plaintext_part.len()),
                            output,
                            output_len,
                            flags.0 as cryptoki_sys::CK_FLAGS,
                        )
                    },
                ),
            _ => Err(CkRv::FUNCTION_NOT_SUPPORTED),
        }
    }

    /// C_DecryptMessageNext with structured message parameter.
    pub(super) fn ffi_decrypt_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        ciphertext_part: &[u8],
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_DecryptMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        match msg_param {
            MessageParameter::GcmMessage(gcm) => self.call_with_gcm_message_param(
                gcm,
                output_spec,
                |params, output, output_len| unsafe {
                    f(
                        Self::session_handle(session),
                        params as *mut _ as *mut _,
                        std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>()
                            as cryptoki_sys::CK_ULONG,
                        ciphertext_part.as_ptr() as *mut _,
                        Self::ulong_len(ciphertext_part.len()),
                        output,
                        output_len,
                        flags.0 as cryptoki_sys::CK_FLAGS,
                    )
                },
            ),
            MessageParameter::CcmMessage(ccm) => self.call_with_ccm_message_param(
                ccm,
                output_spec,
                |params, output, output_len| unsafe {
                    f(
                        Self::session_handle(session),
                        params as *mut _ as *mut _,
                        std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>()
                            as cryptoki_sys::CK_ULONG,
                        ciphertext_part.as_ptr() as *mut _,
                        Self::ulong_len(ciphertext_part.len()),
                        output,
                        output_len,
                        flags.0 as cryptoki_sys::CK_FLAGS,
                    )
                },
            ),
            MessageParameter::SalaChacha(params_in) => self
                .call_with_salsa20_chacha20_poly1305_message_param(
                    params_in,
                    output_spec,
                    |params, output, output_len| unsafe {
                        f(
                            Self::session_handle(session),
                            params as *mut _ as *mut _,
                            std::mem::size_of::<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>()
                                as cryptoki_sys::CK_ULONG,
                            ciphertext_part.as_ptr() as *mut _,
                            Self::ulong_len(ciphertext_part.len()),
                            output,
                            output_len,
                            flags.0 as cryptoki_sys::CK_FLAGS,
                        )
                    },
                ),
            _ => Err(CkRv::FUNCTION_NOT_SUPPORTED),
        }
    }

    /// C_SignMessageNext with structured message parameter.
    pub(super) fn ffi_sign_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &MessageParameter,
        data_part: &[u8],
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, MessageParameter)> {
        let fl = self.func_list_3_0.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
        let f = unsafe { (*fl).C_SignMessageNext }.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;

        match msg_param {
            MessageParameter::GcmMessage(gcm) => self.call_with_gcm_message_param(
                gcm,
                output_spec,
                |params, output, output_len| unsafe {
                    f(
                        Self::session_handle(session),
                        params as *mut _ as *mut _,
                        std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>()
                            as cryptoki_sys::CK_ULONG,
                        data_part.as_ptr() as *mut _,
                        Self::ulong_len(data_part.len()),
                        output,
                        output_len,
                    )
                },
            ),
            MessageParameter::CcmMessage(ccm) => self.call_with_ccm_message_param(
                ccm,
                output_spec,
                |params, output, output_len| unsafe {
                    f(
                        Self::session_handle(session),
                        params as *mut _ as *mut _,
                        std::mem::size_of::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>()
                            as cryptoki_sys::CK_ULONG,
                        data_part.as_ptr() as *mut _,
                        Self::ulong_len(data_part.len()),
                        output,
                        output_len,
                    )
                },
            ),
            MessageParameter::SalaChacha(params_in) => self
                .call_with_salsa20_chacha20_poly1305_message_param(
                    params_in,
                    output_spec,
                    |params, output, output_len| unsafe {
                        f(
                            Self::session_handle(session),
                            params as *mut _ as *mut _,
                            std::mem::size_of::<cryptoki_sys::CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>()
                                as cryptoki_sys::CK_ULONG,
                            data_part.as_ptr() as *mut _,
                            Self::ulong_len(data_part.len()),
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
