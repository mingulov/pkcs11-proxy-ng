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
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::VerifySignatureInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: mechanism.map(Self::proto_mechanism),
            key_handle: key.0,
            signature: Vec::new(),
            signature_null_len: None,
        };
        Self::fill_input(signature, &mut req.signature, &mut req.signature_null_len);
        pkcs11_unary_ok!(self.grpc.verify_signature_init(req), true)
    }

    // --- C_VerifySignature (single-part) ---

    pub async fn verify_signature(
        &mut self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::VerifySignatureRequest {
            client_context_id: ctx,
            session_handle: session.0,
            data: Vec::new(),
            data_null_len: None,
        };
        Self::fill_input(data, &mut req.data, &mut req.data_null_len);
        pkcs11_unary_ok!(self.grpc.verify_signature(req), true)
    }

    // --- C_VerifySignatureUpdate (multi-part data feed) ---

    pub async fn verify_signature_update(
        &mut self,
        session: CkSessionHandle,
        data_part: CkInBuf<'_>,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::VerifySignatureUpdateRequest {
            client_context_id: ctx,
            session_handle: session.0,
            data_part: Vec::new(),
            data_part_null_len: None,
        };
        Self::fill_input(data_part, &mut req.data_part, &mut req.data_part_null_len);
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
