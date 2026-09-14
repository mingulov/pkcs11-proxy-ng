use super::ffi_conversion::mechanism_to_ffi;
use super::{FfiBackend, call_3x_fn};
use pkcs11_proxy_ng_types::*;

impl FfiBackend {
    pub(super) fn ffi_verify_signature_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        match mechanism {
            Some(mech) => {
                let ffi_mech = mechanism_to_ffi(mech)?;
                let (sig_ptr, sig_len) = signature.as_ptr_len();
                call_3x_fn!(
                    self,
                    func_list_3_2,
                    C_VerifySignatureInit,
                    Self::session_handle(session),
                    ffi_mech.ck_mechanism_ptr(),
                    Self::object_handle(key),
                    sig_ptr as *mut cryptoki_sys::CK_BYTE,
                    Self::ulong_len_u64(sig_len)
                )
            }
            None => {
                // NULL mechanism = cancel active verify-signature state
                call_3x_fn!(
                    self,
                    func_list_3_2,
                    C_VerifySignatureInit,
                    Self::session_handle(session),
                    std::ptr::null_mut::<cryptoki_sys::CK_MECHANISM>(),
                    Self::object_handle(key),
                    std::ptr::null_mut::<cryptoki_sys::CK_BYTE>(),
                    0 as cryptoki_sys::CK_ULONG
                )
            }
        }
    }

    pub(super) fn ffi_verify_signature(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
    ) -> CkResult<()> {
        let (data_ptr, data_len) = data.as_ptr_len();
        call_3x_fn!(
            self,
            func_list_3_2,
            C_VerifySignature,
            Self::session_handle(session),
            data_ptr as *mut cryptoki_sys::CK_BYTE,
            Self::ulong_len_u64(data_len)
        )
    }

    pub(super) fn ffi_verify_signature_update(
        &self,
        session: CkSessionHandle,
        data_part: CkInBuf<'_>,
    ) -> CkResult<()> {
        let (dp_ptr, dp_len) = data_part.as_ptr_len();
        call_3x_fn!(
            self,
            func_list_3_2,
            C_VerifySignatureUpdate,
            Self::session_handle(session),
            dp_ptr as *mut cryptoki_sys::CK_BYTE,
            Self::ulong_len_u64(dp_len)
        )
    }

    pub(super) fn ffi_verify_signature_final(&self, session: CkSessionHandle) -> CkResult<()> {
        call_3x_fn!(self, func_list_3_2, C_VerifySignatureFinal, Self::session_handle(session))
    }
}
