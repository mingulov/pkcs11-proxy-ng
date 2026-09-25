//! Client methods for PKCS#11 3.2 KEM operations (Wave 2).
//!
//! - `C_EncapsulateKey`
//! - `C_DecapsulateKey`

use pkcs11_proxy_ng_types::*;

use super::Pkcs11Client;

impl Pkcs11Client {
    pub async fn encapsulate_key(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        public_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<(Vec<u8>, CkObjectHandle)> {
        let ctx = self.context_id()?;
        let proto_template = Self::proto_template(template.unwrap_or(&[]));
        let req = pkcs11_proxy_ng_proto::EncapsulateKeyRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)?),
            public_key_handle: public_key.0,
            template: proto_template,
            template_null: template.is_none(),
        };
        let resp = pkcs11_unary_call!(self.grpc.encapsulate_key(req), true);
        Ok((resp.ciphertext, CkObjectHandle(resp.key_handle)))
    }

    pub async fn decapsulate_key(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        private_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
        ciphertext: CkInBuf<'_>,
    ) -> CkResult<CkObjectHandle> {
        let ctx = self.context_id()?;
        let proto_template = Self::proto_template(template.unwrap_or(&[]));
        let mut req = pkcs11_proxy_ng_proto::DecapsulateKeyRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)?),
            private_key_handle: private_key.0,
            template: proto_template,
            template_null: template.is_none(),
            ciphertext: Vec::new(),
            ciphertext_null_len: None,
        };
        Self::fill_input(ciphertext, &mut req.ciphertext, &mut req.ciphertext_null_len);
        let resp = pkcs11_unary_call!(self.grpc.decapsulate_key(req), true);
        Ok(CkObjectHandle(resp.key_handle))
    }
}
