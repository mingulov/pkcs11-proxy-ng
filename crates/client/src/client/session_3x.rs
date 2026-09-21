//! Client methods for PKCS#11 3.0/3.2 session extensions (Wave 1).
//!
//! - `C_LoginUser`
//! - `C_SessionCancel`
//! - `C_GetSessionValidationFlags`

use pkcs11_proxy_ng_types::*;

use super::Pkcs11Client;
use crate::error::MessageCallError;

impl Pkcs11Client {
    pub async fn login_user(
        &mut self,
        session: CkSessionHandle,
        user_type: CkUserType,
        username: Option<&[u8]>,
        pin: Option<&[u8]>,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::LoginUserRequest {
            client_context_id: ctx,
            session_handle: session.0,
            user_type: user_type as u64,
            pin: pin.map(|p| p.to_vec()),
            username: username.map(|u| u.to_vec()),
        };
        pkcs11_unary_ok!(self.grpc.login_user(req), true)
    }

    pub async fn session_cancel(
        &mut self,
        session: CkSessionHandle,
        flags: CkFlags,
    ) -> CkResult<()> {
        self.session_cancel_stateful(session, flags).await.map_err(|error| error.ck_rv)
    }

    pub async fn session_cancel_stateful(
        &mut self,
        session: CkSessionHandle,
        flags: CkFlags,
    ) -> Result<(), MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let req = pkcs11_proxy_ng_proto::SessionCancelRequest {
            client_context_id: ctx,
            session_handle: session.0,
            flags: flags.0,
        };
        super::stateful_unit_call(self.grpc.session_cancel(req), |response| response.ck_rv).await
    }

    pub async fn get_session_validation_flags(
        &mut self,
        session: CkSessionHandle,
        flags_type: u64,
    ) -> CkResult<u64> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::GetSessionValidationFlagsRequest {
            client_context_id: ctx,
            session_handle: session.0,
            flags_type,
        };
        let resp = pkcs11_unary_call!(self.grpc.get_session_validation_flags(req), true);
        Ok(resp.flags)
    }
}
