//! Client session methods.
//!
//! PIN/secret handling note (E3, revised W1-L2-10): the PIN bytes a caller
//! passes here are copied once, into the prost-generated request struct,
//! which is then moved into the tonic client to be encoded and sent. That
//! single client-owned copy IS wiped: the five PIN-bearing request
//! messages (`LoginRequest`, `LoginUserRequest`, `InitTokenRequest`,
//! `InitPinRequest`, `SetPinRequest`) derive `Zeroize` + `ZeroizeOnDrop`
//! at codegen time (see `crates/proto/build.rs`, W1-C8-11), so the PIN
//! fields are overwritten when the request drops after encoding instead
//! of being freed plain. The prost field type stays a plain `Vec<u8>` by
//! design — `bytes::Bytes` has no `Zeroize` impl — and the whole-message
//! derive is what covers it, so wrapping the field in `Zeroizing` here
//! would only add a second copy and stays omitted. Pinned by
//! `crates/client/tests/client_pin_zeroize.rs` (canaries + drop bounds)
//! alongside the proto-side `pin_zeroize.rs`.
//!
//! Residuals: the application owns its own PIN buffer (the shim passes a
//! borrow of caller memory; wiping it stays the caller's job), and
//! tonic's encoded wire buffers are unreachable for zeroization — the
//! send-side mirror of the documented receive-side transport-buffer
//! limitation.

use pkcs11_proxy_ng_types::*;

use super::Pkcs11Client;
use crate::error::MessageCallError;

/// Q03 phase 2: build the `InitTokenRequest` label fields — pure
/// policy, unit tested. Negotiated (capability ≥ 1, monotonic: a
/// newer-than-known daemon still gets the v1 shape): the exact field
/// rides alongside the compat string. Unnegotiated: legacy
/// string-only when there is no exact form, or when the exact bytes
/// are valid UTF-8 (the string fallback is lossless by
/// construction); NULL and invalid-encoding inputs fail closed with
/// `ARGUMENTS_BAD` — the documented transport limit, never a
/// rewrite.
fn init_token_label_fields(
    label: InitTokenLabel<'_>,
    exact_token_label_version: u32,
) -> CkResult<(String, Option<Vec<u8>>)> {
    let text = label.text.to_string();
    let Some(exact) = label.exact else { return Ok((text, None)) };
    if exact_token_label_version >= EXACT_TOKEN_LABEL_VERSION {
        let wire = match exact {
            ExactTokenLabel::Null => Vec::new(),
            ExactTokenLabel::Bytes(bytes) => bytes.to_vec(),
        };
        return Ok((text, Some(wire)));
    }
    match exact {
        ExactTokenLabel::Null => Err(CkRv::ARGUMENTS_BAD),
        ExactTokenLabel::Bytes(bytes) if std::str::from_utf8(&bytes).is_ok() => Ok((text, None)),
        ExactTokenLabel::Bytes(_) => Err(CkRv::ARGUMENTS_BAD),
    }
}

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
        super::stateful_unit_call(self.grpc.close_session(req), true, |response| response.ck_rv)
            .await
    }

    pub async fn close_all_sessions(&mut self, slot_id: CkSlotId) -> CkResult<()> {
        self.close_all_sessions_stateful(slot_id).await.map_err(|error| error.ck_rv)
    }

    /// Stateful close-all (Q01): like [`Self::close_session_stateful`], but
    /// slot-scoped — transport failures keep the `CkResult` sibling's
    /// `TOKEN_NOT_PRESENT` mapping. The shim settles its slot caches on the
    /// decoded outcome instead of evicting on the attempt.
    pub async fn close_all_sessions_stateful(
        &mut self,
        slot_id: CkSlotId,
    ) -> Result<(), MessageCallError> {
        let ctx = self.context_id().map_err(MessageCallError::backend)?;
        let req = pkcs11_proxy_ng_proto::CloseAllSessionsRequest {
            client_context_id: ctx,
            slot_id: slot_id.0,
        };
        super::stateful_unit_call(self.grpc.close_all_sessions(req), false, |response| {
            response.ck_rv
        })
        .await
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

    /// Q03 phase 2: initialize the token, forwarding an exact label
    /// when the daemon negotiated `exact_token_label_version` ≥ 1 and
    /// degrading gracefully otherwise. A legacy text-only label always
    /// takes the string path. Unnegotiated, a valid exact label falls
    /// back to the string path losslessly (blank-pad of the trimmed
    /// text reproduces the caller bytes); NULL and invalid-encoding
    /// labels fail closed locally with `CKR_ARGUMENTS_BAD` — a
    /// documented transport limit, never a silent rewrite — before any
    /// RPC is attempted.
    pub async fn init_token(
        &mut self,
        slot_id: CkSlotId,
        so_pin: Option<&[u8]>,
        label: InitTokenLabel<'_>,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let (label, label_exact) =
            init_token_label_fields(label, self.exact_token_label_version())?;
        let req = pkcs11_proxy_ng_proto::InitTokenRequest {
            client_context_id: ctx,
            slot_id: slot_id.0,
            so_pin: so_pin.map(|p| p.to_vec()),
            label,
            label_exact,
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
        let err =
            client.open_session(CkSlotId(0), CkSessionFlags::SERIAL_SESSION).await.unwrap_err();
        assert_eq!(err, CkRv::DEVICE_ERROR);
    }

    fn q03_pad_label(prefix: &[u8]) -> [u8; PKCS11_TOKEN_LABEL_LEN] {
        let mut label = [b' '; PKCS11_TOKEN_LABEL_LEN];
        label[..prefix.len()].copy_from_slice(prefix);
        label
    }

    /// Q03 phase 2: negotiated, the exact field rides alongside the
    /// compat string (NULL as len 0, bytes as len 32); legacy
    /// text-only labels stay string-only at any capability.
    #[test]
    fn init_token_label_fields_negotiated_sends_exact() {
        let valid = q03_pad_label(b"A\t");
        let invalid = q03_pad_label(b"BAD\xff\xfe");
        for version in [EXACT_TOKEN_LABEL_VERSION, EXACT_TOKEN_LABEL_VERSION + 1] {
            assert_eq!(
                super::init_token_label_fields(InitTokenLabel::text_only("A\t"), version),
                Ok(("A\t".to_string(), None)),
                "text-only stays string-only at v{version}"
            );
            assert_eq!(
                super::init_token_label_fields(
                    InitTokenLabel { text: "", exact: Some(ExactTokenLabel::Null) },
                    version,
                ),
                Ok(("".to_string(), Some(Vec::new()))),
                "NULL sends len-0 exact at v{version}"
            );
            assert_eq!(
                super::init_token_label_fields(
                    InitTokenLabel { text: "A\t", exact: Some(ExactTokenLabel::Bytes(valid)) },
                    version,
                ),
                Ok(("A\t".to_string(), Some(valid.to_vec()))),
                "valid bytes send len-32 exact at v{version}"
            );
            assert_eq!(
                super::init_token_label_fields(
                    InitTokenLabel {
                        text: "BAD\u{fffd}",
                        exact: Some(ExactTokenLabel::Bytes(invalid)),
                    },
                    version,
                ),
                Ok(("BAD\u{fffd}".to_string(), Some(invalid.to_vec()))),
                "invalid bytes send len-32 exact at v{version}"
            );
        }
    }

    /// Q03 phase 2: unnegotiated, valid exact bytes fall back to the
    /// string path losslessly, while NULL and invalid-encoding bytes
    /// fail closed with `ARGUMENTS_BAD` — never rewritten.
    #[test]
    fn init_token_label_fields_unnegotiated_falls_back_or_refuses() {
        let valid = q03_pad_label(b"A\t");
        let invalid = q03_pad_label(b"BAD\xff\xfe");
        assert_eq!(
            super::init_token_label_fields(InitTokenLabel::text_only("A\t"), 0),
            Ok(("A\t".to_string(), None)),
            "text-only stays string-only unnegotiated"
        );
        assert_eq!(
            super::init_token_label_fields(
                InitTokenLabel { text: "A\t", exact: Some(ExactTokenLabel::Bytes(valid)) },
                0,
            ),
            Ok(("A\t".to_string(), None)),
            "valid exact bytes fall back to the string path unnegotiated"
        );
        assert_eq!(
            super::init_token_label_fields(
                InitTokenLabel { text: "", exact: Some(ExactTokenLabel::Null) },
                0,
            )
            .unwrap_err(),
            CkRv::ARGUMENTS_BAD,
            "NULL fails closed unnegotiated, never empty-label reinit"
        );
        assert_eq!(
            super::init_token_label_fields(
                InitTokenLabel {
                    text: "BAD\u{fffd}",
                    exact: Some(ExactTokenLabel::Bytes(invalid)),
                },
                0,
            )
            .unwrap_err(),
            CkRv::ARGUMENTS_BAD,
            "invalid bytes fail closed unnegotiated, never U+FFFD-substituted"
        );
    }

    /// Q03 phase 2: the client gate refuses NULL/invalid labels
    /// locally when unnegotiated — `ARGUMENTS_BAD` before any RPC (an
    /// attempted RPC against the dead channel would surface as
    /// transport `DEVICE_ERROR` instead).
    #[tokio::test]
    async fn init_token_unnegotiated_exact_refuses_before_any_rpc() {
        let mut client = dead_channel_client();
        client.restore_context_id(Some("q03-gate".into()));
        assert_eq!(client.exact_token_label_version(), 0);
        let invalid = q03_pad_label(b"BAD\xff\xfe");
        for label in [
            InitTokenLabel { text: "", exact: Some(ExactTokenLabel::Null) },
            InitTokenLabel { text: "BAD\u{fffd}", exact: Some(ExactTokenLabel::Bytes(invalid)) },
        ] {
            assert_eq!(
                client.init_token(CkSlotId(0), Some(b"1234"), label).await.unwrap_err(),
                CkRv::ARGUMENTS_BAD,
                "unnegotiated {label:?} must fail closed before any RPC"
            );
        }
    }

    /// Q03 phase 2: the valid-label string fallback really sends the
    /// RPC unnegotiated — the dead channel answers with transport
    /// `DEVICE_ERROR`, not a local refusal.
    #[tokio::test]
    async fn init_token_unnegotiated_valid_label_sends_string_fallback() {
        let mut client = dead_channel_client();
        client.restore_context_id(Some("q03-fallback".into()));
        let valid = q03_pad_label(b"A\t");
        let err = client
            .init_token(
                CkSlotId(0),
                Some(b"1234"),
                InitTokenLabel { text: "A\t", exact: Some(ExactTokenLabel::Bytes(valid)) },
            )
            .await
            .unwrap_err();
        assert_eq!(err, CkRv::DEVICE_ERROR, "string fallback must attempt the RPC");
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
