//! Client session methods.
//!
//! PIN/secret handling note (E3): the PIN bytes a caller passes here are copied
//! once, into the prost-generated request struct, and that struct is then moved
//! into the tonic client to be encoded and sent. From that point the client no
//! longer owns the copy, so it cannot wipe it; and the prost field type is
//! deliberately kept a plain `Vec<u8>` (see `crates/proto/build.rs`) rather than
//! a wiping newtype. Wrapping the request field in `Zeroizing` here would only
//! add a second copy without wiping the one tonic holds, so it is intentionally
//! omitted. This is the send-side mirror of the documented receive-side
//! limitation (tonic's transport buffers are not reachable for zeroization); the
//! application owns its own PIN buffer and is responsible for wiping it.

use pkcs11_proxy_ng_types::*;

use super::Pkcs11Client;
use crate::error::MessageCallError;

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
        // Session-scoped (W1-C10-04): `RpcKind::Session` names
        // `C_OpenSession` explicitly — transport failure is DEVICE_ERROR.
        let resp = pkcs11_unary_call!(self.grpc.open_session(req), true);
        Ok(CkSessionHandle(resp.session_handle))
    }

    pub async fn close_session(&mut self, session: CkSessionHandle) -> CkResult<()> {
        self.close_session_stateful(session).await.map_err(|error| error.ck_rv)
    }

    pub async fn close_session_stateful(
        &mut self,
        session: CkSessionHandle,
    ) -> Result<(), MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let req = pkcs11_proxy_ng_proto::CloseSessionRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        super::stateful_unit_call(self.grpc.close_session(req), |response| response.ck_rv).await
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
        // Absent info = uninterpretable daemon payload (W1-L3-06).
        let info = resp.info.ok_or(CkRv::FUNCTION_NOT_SUPPORTED)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::MessageCallErrorOrigin;

    fn dead_channel_client() -> Pkcs11Client {
        // 127.0.0.1:9 (discard) is never served in tests; `connect_lazy`
        // defers the failure to the first RPC, which surfaces as a
        // transport error (same pattern as authenticated_typed tests).
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        Pkcs11Client::from_channel(channel)
    }

    // W1-L11-08 characterization: close_session_stateful and
    // session_cancel_stateful must behave identically (same error shape
    // for the same failure). Must pass before AND after the core DRY.

    #[tokio::test]
    async fn t7_stateful_unit_parity_without_context() {
        let mut client = dead_channel_client();
        let close_err = client.close_session_stateful(CkSessionHandle(1)).await.unwrap_err();
        let cancel_err =
            client.session_cancel_stateful(CkSessionHandle(1), CkFlags(0)).await.unwrap_err();
        assert_eq!(close_err, cancel_err, "both stateful unit calls must fail identically");
        assert_eq!(close_err.ck_rv, CkRv::CRYPTOKI_NOT_INITIALIZED);
        assert_eq!(close_err.origin, MessageCallErrorOrigin::Backend);
    }

    #[tokio::test]
    async fn t7_stateful_unit_parity_on_transport_failure() {
        let mut client = dead_channel_client();
        client.restore_context_id(Some("t7-stateful-parity".into()));
        let close_err = client.close_session_stateful(CkSessionHandle(1)).await.unwrap_err();
        let cancel_err =
            client.session_cancel_stateful(CkSessionHandle(1), CkFlags(0)).await.unwrap_err();
        assert_eq!(close_err, cancel_err, "transport failure must map identically");
        assert_eq!(close_err.origin, MessageCallErrorOrigin::Transport);
        // Refused loopback maps Unavailable -> session-scoped -> DEVICE_ERROR.
        assert_eq!(close_err.ck_rv, CkRv::DEVICE_ERROR);
    }

    // W1-C10-04: open_session is session-scoped per the crate taxonomy
    // (`RpcKind::Session` names `C_OpenSession` explicitly), so a transport
    // failure must map to DEVICE_ERROR, not TOKEN_NOT_PRESENT.
    // Recorded pre-fix state: `open_session(req), false`.
    #[tokio::test]
    async fn open_session_transport_failure_is_session_scoped() {
        let mut client = dead_channel_client();
        client.restore_context_id(Some("c10-04-open-session".into()));
        let err = client
            .open_session(CkSlotId(0), CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
            .await
            .unwrap_err();
        assert_eq!(err, CkRv::DEVICE_ERROR);
    }

    // W1-L3-06: twin of the discovery.rs scan for the 5th absent-info site
    // (get_session_info). Recorded pre-fix state: `ok_or(CkRv::DEVICE_ERROR)`.
    #[test]
    fn absent_session_info_maps_to_function_not_supported() {
        let source = include_str!("session.rs");
        let prod = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            !prod.contains("ok_or(CkRv::DEVICE_ERROR)"),
            "get_session_info must not map absent info to DEVICE_ERROR"
        );
        assert_eq!(
            prod.matches("ok_or(CkRv::FUNCTION_NOT_SUPPORTED)").count(),
            1,
            "get_session_info must map absent info to FUNCTION_NOT_SUPPORTED"
        );
    }
}
