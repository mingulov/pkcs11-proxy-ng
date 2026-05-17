use pkcs11_proxy_ng_types::*;

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
        wrapped_key: &[u8],
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let ctx = self.context_id()?;
        let proto_template = Self::proto_template(template);
        let req = pkcs11_proxy_ng_proto::UnwrapKeyRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)),
            unwrapping_key_handle: unwrapping_key.0,
            wrapped_key: wrapped_key.to_vec(),
            template: proto_template,
        };
        let resp = pkcs11_unary_call!(self.grpc.unwrap_key(req), true);
        Ok(CkObjectHandle(resp.key_handle))
    }

    pub async fn derive_key(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: &[CkAttribute],
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
        template: &[CkAttribute],
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
        template: &[CkAttribute],
    ) -> CkResult<DeriveKeyMechanismOutResult> {
        let ctx = self.context_id()?;
        let proto_template = Self::proto_template(template);
        let req = pkcs11_proxy_ng_proto::DeriveKeyRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)),
            base_key_handle: base_key.0,
            template: proto_template,
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
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let ctx = self.context_id()?;
        let proto_mech = Self::proto_mechanism(mechanism);
        let proto_template = Self::proto_template(template);
        let req = pkcs11_proxy_ng_proto::GenerateKeyRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(proto_mech),
            template: proto_template,
        };
        let resp = pkcs11_unary_call!(self.grpc.generate_key(req), true);
        Ok(CkObjectHandle(resp.key_handle))
    }

    pub async fn generate_key_pair(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        pub_template: &[CkAttribute],
        priv_template: &[CkAttribute],
    ) -> CkResult<(CkObjectHandle, CkObjectHandle)> {
        let ctx = self.context_id()?;
        let proto_pub = Self::proto_template(pub_template);
        let proto_priv = Self::proto_template(priv_template);
        let req = pkcs11_proxy_ng_proto::GenerateKeyPairRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)),
            public_key_template: proto_pub,
            private_key_template: proto_priv,
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
        state: &[u8],
        enc_key: CkObjectHandle,
        auth_key: CkObjectHandle,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::SetOperationStateRequest {
            client_context_id: ctx,
            session_handle: session.0,
            operation_state: state.to_vec(),
            encryption_key_handle: enc_key.0,
            authentication_key_handle: auth_key.0,
        };
        pkcs11_unary_ok!(self.grpc.set_operation_state(req), true)
    }

    pub async fn seed_random(&mut self, session: CkSessionHandle, seed: &[u8]) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::SeedRandomRequest {
            client_context_id: ctx,
            session_handle: session.0,
            seed: seed.to_vec(),
        };
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
