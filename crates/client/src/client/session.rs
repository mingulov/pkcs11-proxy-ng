use pkcs11_proxy_ng_types::*;

use super::Pkcs11Client;

impl Pkcs11Client {
    pub async fn open_session(
        &mut self,
        slot_id: CkSlotId,
        flags: CkSessionFlags,
    ) -> CkResult<CkSessionHandle> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::OpenSessionRequest {
            client_context_id: ctx,
            slot_id: slot_id.0,
            flags: flags.0,
        };
        let resp = pkcs11_unary_call!(self.grpc.open_session(req), false);
        Ok(CkSessionHandle(resp.session_handle))
    }

    pub async fn close_session(&mut self, session: CkSessionHandle) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::CloseSessionRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        pkcs11_unary_ok!(self.grpc.close_session(req), true)
    }

    pub async fn close_all_sessions(&mut self, slot_id: CkSlotId) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::CloseAllSessionsRequest {
            client_context_id: ctx,
            slot_id: slot_id.0,
        };
        pkcs11_unary_ok!(self.grpc.close_all_sessions(req), false)
    }

    pub async fn get_session_info(&mut self, session: CkSessionHandle) -> CkResult<CkSessionInfo> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::GetSessionInfoRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        let resp = pkcs11_unary_call!(self.grpc.get_session_info(req), true);
        let info = resp.info.ok_or(CkRv::DEVICE_ERROR)?;
        Ok(CkSessionInfo::from(&info))
    }

    pub async fn login(
        &mut self,
        session: CkSessionHandle,
        user_type: CkUserType,
        pin: Option<&[u8]>,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::LoginRequest {
            client_context_id: ctx,
            session_handle: session.0,
            user_type: user_type as u64,
            pin: pin.map(|p| p.to_vec()),
        };
        pkcs11_unary_ok!(self.grpc.login(req), true)
    }

    pub async fn logout(&mut self, session: CkSessionHandle) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::LogoutRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        pkcs11_unary_ok!(self.grpc.logout(req), true)
    }

    pub async fn init_token(
        &mut self,
        slot_id: CkSlotId,
        so_pin: Option<&[u8]>,
        label: &str,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::InitTokenRequest {
            client_context_id: ctx,
            slot_id: slot_id.0,
            so_pin: so_pin.map(|p| p.to_vec()),
            label: label.to_string(),
        };
        pkcs11_unary_ok!(self.grpc.init_token(req), true)
    }

    pub async fn init_pin(&mut self, session: CkSessionHandle, pin: Option<&[u8]>) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::InitPinRequest {
            client_context_id: ctx,
            session_handle: session.0,
            pin: pin.map(|p| p.to_vec()),
        };
        pkcs11_unary_ok!(self.grpc.init_pin(req), true)
    }

    pub async fn set_pin(
        &mut self,
        session: CkSessionHandle,
        old_pin: Option<&[u8]>,
        new_pin: Option<&[u8]>,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::SetPinRequest {
            client_context_id: ctx,
            session_handle: session.0,
            old_pin: old_pin.map(|p| p.to_vec()),
            new_pin: new_pin.map(|p| p.to_vec()),
        };
        pkcs11_unary_ok!(self.grpc.set_pin(req), true)
    }

    pub async fn get_function_status(&mut self, session: CkSessionHandle) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::GetFunctionStatusRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        pkcs11_unary_ok!(self.grpc.get_function_status(req), true)
    }

    pub async fn cancel_function(&mut self, session: CkSessionHandle) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::CancelFunctionRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        pkcs11_unary_ok!(self.grpc.cancel_function(req), true)
    }
}
