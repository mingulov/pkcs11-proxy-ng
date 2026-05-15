use pkcs11_proxy_ng_types::*;

use crate::client::Pkcs11Client;

impl Pkcs11Client {
    pub async fn sign_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::SignInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)),
            key_handle: key.0,
        };
        pkcs11_unary_ok!(self.grpc.sign_init(req), true)
    }

    pub async fn sign(&mut self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::SignRequest {
            client_context_id: ctx,
            session_handle: session.0,
            data: data.to_vec(),
        };
        pkcs11_unary_map!(self.grpc.sign(req), true, resp => resp.signature)
    }

    pub async fn sign_update(&mut self, session: CkSessionHandle, part: &[u8]) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::SignUpdateRequest {
            client_context_id: ctx,
            session_handle: session.0,
            part: part.to_vec(),
        };
        pkcs11_unary_ok!(self.grpc.sign_update(req), true)
    }

    pub async fn sign_final(&mut self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::SignFinalRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        pkcs11_unary_map!(self.grpc.sign_final(req), true, resp => resp.signature)
    }

    pub async fn sign_recover_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::SignRecoverInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)),
            key_handle: key.0,
        };
        pkcs11_unary_ok!(self.grpc.sign_recover_init(req), true)
    }

    pub async fn sign_recover(
        &mut self,
        session: CkSessionHandle,
        data: &[u8],
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::SignRecoverRequest {
            client_context_id: ctx,
            session_handle: session.0,
            data: data.to_vec(),
        };
        pkcs11_unary_map!(self.grpc.sign_recover(req), true, resp => resp.signature)
    }

    pub async fn verify_recover_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::VerifyRecoverInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)),
            key_handle: key.0,
        };
        pkcs11_unary_ok!(self.grpc.verify_recover_init(req), true)
    }

    pub async fn verify_recover(
        &mut self,
        session: CkSessionHandle,
        signature: &[u8],
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::VerifyRecoverRequest {
            client_context_id: ctx,
            session_handle: session.0,
            signature: signature.to_vec(),
        };
        pkcs11_unary_map!(self.grpc.verify_recover(req), true, resp => resp.data)
    }

    pub async fn verify_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::VerifyInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)),
            key_handle: key.0,
        };
        pkcs11_unary_ok!(self.grpc.verify_init(req), true)
    }

    pub async fn verify(
        &mut self,
        session: CkSessionHandle,
        data: &[u8],
        signature: &[u8],
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::VerifyRequest {
            client_context_id: ctx,
            session_handle: session.0,
            data: data.to_vec(),
            signature: signature.to_vec(),
        };
        pkcs11_unary_ok!(self.grpc.verify(req), true)
    }

    pub async fn verify_update(&mut self, session: CkSessionHandle, part: &[u8]) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::VerifyUpdateRequest {
            client_context_id: ctx,
            session_handle: session.0,
            part: part.to_vec(),
        };
        pkcs11_unary_ok!(self.grpc.verify_update(req), true)
    }

    pub async fn verify_final(
        &mut self,
        session: CkSessionHandle,
        signature: &[u8],
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::VerifyFinalRequest {
            client_context_id: ctx,
            session_handle: session.0,
            signature: signature.to_vec(),
        };
        pkcs11_unary_ok!(self.grpc.verify_final(req), true)
    }
}
