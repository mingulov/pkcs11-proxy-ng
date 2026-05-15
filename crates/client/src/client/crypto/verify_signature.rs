//! Client methods for PKCS#11 3.2 VerifySignature operations (Wave 5).

use pkcs11_proxy_ng_types::*;

use crate::client::Pkcs11Client;

impl Pkcs11Client {
    // --- C_VerifySignatureInit (optional mechanism — None = cancel) ---

    pub async fn verify_signature_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
        signature: &[u8],
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::VerifySignatureInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: mechanism.map(Self::proto_mechanism),
            key_handle: key.0,
            signature: signature.to_vec(),
        };
        pkcs11_unary_ok!(self.grpc.verify_signature_init(req), true)
    }

    // --- C_VerifySignature (single-part) ---

    pub async fn verify_signature(
        &mut self,
        session: CkSessionHandle,
        data: &[u8],
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::VerifySignatureRequest {
            client_context_id: ctx,
            session_handle: session.0,
            data: data.to_vec(),
        };
        pkcs11_unary_ok!(self.grpc.verify_signature(req), true)
    }

    // --- C_VerifySignatureUpdate (multi-part data feed) ---

    pub async fn verify_signature_update(
        &mut self,
        session: CkSessionHandle,
        data_part: &[u8],
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::VerifySignatureUpdateRequest {
            client_context_id: ctx,
            session_handle: session.0,
            data_part: data_part.to_vec(),
        };
        pkcs11_unary_ok!(self.grpc.verify_signature_update(req), true)
    }

    // --- C_VerifySignatureFinal (completes multi-part) ---

    pub async fn verify_signature_final(&mut self, session: CkSessionHandle) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::VerifySignatureFinalRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        pkcs11_unary_ok!(self.grpc.verify_signature_final(req), true)
    }
}
