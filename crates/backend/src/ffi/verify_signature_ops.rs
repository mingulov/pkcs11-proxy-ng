use super::ffi_conversion::mechanism_to_ffi;
use super::{FfiBackend, call_3x_fn};
use pkcs11_proxy_ng_types::*;

impl FfiBackend {
    pub(super) fn ffi_verify_signature_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
        signature: &[u8],
    ) -> CkResult<()> {
        match mechanism {
            Some(mech) => {
                let mut ffi_mech = mechanism_to_ffi(mech)?;
                call_3x_fn!(
                    self,
                    func_list_3_2,
                    C_VerifySignatureInit,
                    Self::session_handle(session),
                    &mut ffi_mech.ck_mechanism as *mut cryptoki_sys::CK_MECHANISM,
                    Self::object_handle(key),
                    signature.as_ptr() as *mut cryptoki_sys::CK_BYTE,
                    Self::ulong_len(signature.len())
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
        data: &[u8],
    ) -> CkResult<()> {
        call_3x_fn!(
            self,
            func_list_3_2,
            C_VerifySignature,
            Self::session_handle(session),
            data.as_ptr() as *mut cryptoki_sys::CK_BYTE,
            Self::ulong_len(data.len())
        )
    }

    pub(super) fn ffi_verify_signature_update(
        &self,
        session: CkSessionHandle,
        data_part: &[u8],
    ) -> CkResult<()> {
        call_3x_fn!(
            self,
            func_list_3_2,
            C_VerifySignatureUpdate,
            Self::session_handle(session),
            data_part.as_ptr() as *mut cryptoki_sys::CK_BYTE,
            Self::ulong_len(data_part.len())
        )
    }

    pub(super) fn ffi_verify_signature_final(&self, session: CkSessionHandle) -> CkResult<()> {
        call_3x_fn!(self, func_list_3_2, C_VerifySignatureFinal, Self::session_handle(session))
    }
}
