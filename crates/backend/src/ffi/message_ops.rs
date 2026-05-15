use super::ffi_conversion::mechanism_to_ffi;
use super::{FfiBackend, call_3x_fn};
use pkcs11_proxy_ng_proto::convert::message_params::{GcmMessageParams, MessageParameter};
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

impl FfiBackend {
    // --- Message Encrypt ---

    pub(super) fn ffi_message_encrypt_init(
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
                    C_MessageEncryptInit,
                    Self::session_handle(session),
                    &mut ffi_mech.ck_mechanism as *mut cryptoki_sys::CK_MECHANISM,
                    Self::object_handle(key)
                )
            }
            None => {
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
        key: CkObjectHandle,
    ) -> CkResult<()> {
        match mechanism {
            Some(mech) => {
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
            None => {
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
            // CCM and Salsa/ChaCha follow the same pattern — for now, fall back
            // to the raw path (which will likely fail for these too, but they're
            // not tested yet). We can add them when needed.
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
            _ => Err(CkRv::FUNCTION_NOT_SUPPORTED),
        }
    }
}
