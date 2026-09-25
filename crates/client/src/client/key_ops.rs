use pkcs11_proxy_ng_types::*;

use crate::error::{MessageCallError, grpc_status_to_ck_rv};

use super::Pkcs11Client;

#[derive(Debug, Clone, PartialEq)]
pub struct DeriveKeyMechanismOutResult {
    pub rv: CkRv,
    pub key_handle: Option<CkObjectHandle>,
    pub mechanism_out: Option<CkMechanismParams>,
}

impl Pkcs11Client {
    pub async fn wrap_key(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::WrapKeyRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)),
            wrapping_key_handle: wrapping_key.0,
            key_handle: key.0,
        };
        let resp = pkcs11_unary_call!(self.grpc.wrap_key(req), true);
        Ok(resp.wrapped_key)
    }

    pub async fn unwrap_key(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        unwrapping_key: CkObjectHandle,
        wrapped_key: CkInBuf<'_>,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let ctx = self.context_id()?;
        let proto_template = Self::proto_template(template);
        let mut req = pkcs11_proxy_ng_proto::UnwrapKeyRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)),
            unwrapping_key_handle: unwrapping_key.0,
            wrapped_key: Vec::new(),
            template: proto_template,
            wrapped_key_null_len: None,
        };
        Self::fill_input(wrapped_key, &mut req.wrapped_key, &mut req.wrapped_key_null_len);
        let resp = pkcs11_unary_call!(self.grpc.unwrap_key(req), true);
        Ok(CkObjectHandle(resp.key_handle))
    }

    pub async fn derive_key(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        let (handle, _) =
            self.derive_key_with_mechanism_out(session, mechanism, base_key, template).await?;
        Ok(handle)
    }

    /// `C_DeriveKey` returning both the derived key handle AND any
    /// HSM-mutated mechanism params (e.g. the negotiated `CK_VERSION`
    /// written into `CK_TLS12_MASTER_KEY_DERIVE_PARAMS.pVersion`).
    /// Backwards-compatible sibling of [`Self::derive_key`].
    pub async fn derive_key_with_mechanism_out(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<(CkObjectHandle, Option<CkMechanismParams>)> {
        let result = self
            .derive_key_with_mechanism_out_result(session, mechanism, base_key, template)
            .await?;
        if result.rv.is_ok() {
            Ok((result.key_handle.unwrap_or(CkObjectHandle(0)), result.mechanism_out))
        } else {
            Err(result.rv)
        }
    }

    pub async fn derive_key_with_mechanism_out_result(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<DeriveKeyMechanismOutResult> {
        let ctx = self.context_id()?;
        let proto_template = Self::proto_template(template.unwrap_or(&[]));
        let req = pkcs11_proxy_ng_proto::DeriveKeyRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)),
            base_key_handle: base_key.0,
            template: proto_template,
            template_null: template.is_none(),
        };
        let resp = self
            .grpc
            .derive_key(req)
            .await
            .map_err(|status| crate::error::grpc_status_to_ck_rv(status.code(), true))?
            .into_inner();
        let rv = CkRv(resp.ck_rv);
        let mechanism_out = match resp.mechanism_out {
            Some(proto_mech) => CkMechanism::try_from(&proto_mech)?.params,
            None => None,
        };
        Ok(DeriveKeyMechanismOutResult {
            rv,
            key_handle: if rv.is_ok() { Some(CkObjectHandle(resp.key_handle)) } else { None },
            mechanism_out,
        })
    }

    pub async fn generate_key(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.generate_key_with_mechanism_out(session, mechanism, template).await.map(|(h, _)| h)
    }

    /// `C_GenerateKey` returning the key handle plus any HSM-written mechanism
    /// param mutation (e.g. the generated `CK_PBE_PARAMS.pInitVector`). The
    /// mutation is `None` for the common mechanisms without output params.
    /// Mirrors `derive_key_with_mechanism_out_result`.
    pub async fn generate_key_with_mechanism_out(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        template: &[CkAttribute],
    ) -> CkResult<(CkObjectHandle, Option<CkMechanismParams>)> {
        let ctx = self.context_id()?;
        let proto_mech = Self::proto_mechanism(mechanism);
        let proto_template = Self::proto_template(template.unwrap_or(&[]));
        let req = pkcs11_proxy_ng_proto::GenerateKeyRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(proto_mech),
            template: proto_template,
            template_null: template.is_none(),
        };
        let resp = pkcs11_unary_call!(self.grpc.generate_key(req), true);
        let mechanism_out = match resp.mechanism_out {
            Some(proto_mech) => CkMechanism::try_from(&proto_mech)?.params,
            None => None,
        };
        Ok((CkObjectHandle(resp.key_handle), mechanism_out))
    }

    pub async fn generate_key_pair(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        pub_template: Option<&[CkAttribute]>,
        priv_template: Option<&[CkAttribute]>,
    ) -> CkResult<(CkObjectHandle, CkObjectHandle)> {
        let ctx = self.context_id()?;
        let proto_pub = Self::proto_template(pub_template.unwrap_or(&[]));
        let proto_priv = Self::proto_template(priv_template.unwrap_or(&[]));
        let req = pkcs11_proxy_ng_proto::GenerateKeyPairRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)),
            public_key_template: proto_pub,
            public_template_null: pub_template.is_none(),
            private_key_template: proto_priv,
            private_template_null: priv_template.is_none(),
        };
        let resp = pkcs11_unary_call!(self.grpc.generate_key_pair(req), true);
        Ok((CkObjectHandle(resp.public_key_handle), CkObjectHandle(resp.private_key_handle)))
    }

    pub async fn wait_for_slot_event(&mut self, flags: u64) -> CkResult<CkSlotId> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::WaitForSlotEventRequest { client_context_id: ctx, flags };
        let resp = pkcs11_unary_call!(self.grpc.wait_for_slot_event(req), true);
        Ok(CkSlotId(resp.slot_id))
    }

    pub async fn get_operation_state(&mut self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::GetOperationStateRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        let resp = pkcs11_unary_call!(self.grpc.get_operation_state(req), true);
        Ok(resp.operation_state)
    }

    pub async fn set_operation_state(
        &mut self,
        session: CkSessionHandle,
        state: CkInBuf<'_>,
        enc_key: CkObjectHandle,
        auth_key: CkObjectHandle,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::SetOperationStateRequest {
            client_context_id: ctx,
            session_handle: session.0,
            operation_state: Vec::new(),
            encryption_key_handle: enc_key.0,
            authentication_key_handle: auth_key.0,
            operation_state_null_len: None,
        };
        Self::fill_input(state, &mut req.operation_state, &mut req.operation_state_null_len);
        pkcs11_unary_ok!(self.grpc.set_operation_state(req), true)
    }

    pub async fn seed_random(
        &mut self,
        session: CkSessionHandle,
        seed: CkInBuf<'_>,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::SeedRandomRequest {
            client_context_id: ctx,
            session_handle: session.0,
            seed: Vec::new(),
            seed_null_len: None,
        };
        Self::fill_input(seed, &mut req.seed, &mut req.seed_null_len);
        pkcs11_unary_ok!(self.grpc.seed_random(req), true)
    }

    pub async fn generate_random(
        &mut self,
        session: CkSessionHandle,
        len: u32,
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::GenerateRandomRequest {
            client_context_id: ctx,
            session_handle: session.0,
            length: len,
        };
        let resp = pkcs11_unary_call!(self.grpc.generate_random(req), true);
        Ok(resp.random_data)
    }
}
