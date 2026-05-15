use pkcs11_proxy_ng_types::*;

use crate::client::Pkcs11Client;

impl Pkcs11Client {
    pub async fn digest_encrypt_update(
        &mut self,
        session: CkSessionHandle,
        part: &[u8],
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DigestEncryptUpdateRequest {
            client_context_id: ctx,
            session_handle: session.0,
            part: part.to_vec(),
        };
        pkcs11_unary_map!(self.grpc.digest_encrypt_update(req), true, resp => resp.encrypted_part)
    }

    pub async fn decrypt_digest_update(
        &mut self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DecryptDigestUpdateRequest {
            client_context_id: ctx,
            session_handle: session.0,
            encrypted_part: encrypted_part.to_vec(),
        };
        pkcs11_unary_map!(self.grpc.decrypt_digest_update(req), true, resp => resp.part)
    }

    pub async fn sign_encrypt_update(
        &mut self,
        session: CkSessionHandle,
        part: &[u8],
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::SignEncryptUpdateRequest {
            client_context_id: ctx,
            session_handle: session.0,
            part: part.to_vec(),
        };
        pkcs11_unary_map!(self.grpc.sign_encrypt_update(req), true, resp => resp.encrypted_part)
    }

    pub async fn decrypt_verify_update(
        &mut self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DecryptVerifyUpdateRequest {
            client_context_id: ctx,
            session_handle: session.0,
            encrypted_part: encrypted_part.to_vec(),
        };
        pkcs11_unary_map!(self.grpc.decrypt_verify_update(req), true, resp => resp.part)
    }
}
