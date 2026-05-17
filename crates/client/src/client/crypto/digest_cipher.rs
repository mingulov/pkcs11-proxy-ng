use pkcs11_proxy_ng_types::*;

use crate::client::Pkcs11Client;

impl Pkcs11Client {
    pub async fn digest_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DigestInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)),
        };
        pkcs11_unary_ok!(self.grpc.digest_init(req), true)
    }

    pub async fn digest_init_cancel(&mut self, session: CkSessionHandle) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DigestInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: None,
        };
        pkcs11_unary_ok!(self.grpc.digest_init(req), true)
    }

    pub async fn digest(&mut self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DigestRequest {
            client_context_id: ctx,
            session_handle: session.0,
            data: data.to_vec(),
        };
        pkcs11_unary_map!(self.grpc.digest(req), true, resp => resp.digest)
    }

    pub async fn digest_update(&mut self, session: CkSessionHandle, part: &[u8]) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DigestUpdateRequest {
            client_context_id: ctx,
            session_handle: session.0,
            part: part.to_vec(),
        };
        pkcs11_unary_ok!(self.grpc.digest_update(req), true)
    }

    pub async fn digest_key(
        &mut self,
        session: CkSessionHandle,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DigestKeyRequest {
            client_context_id: ctx,
            session_handle: session.0,
            key_handle: key.0,
        };
        pkcs11_unary_ok!(self.grpc.digest_key(req), true)
    }

    pub async fn digest_final(&mut self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DigestFinalRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        pkcs11_unary_map!(self.grpc.digest_final(req), true, resp => resp.digest)
    }

    pub async fn encrypt_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::EncryptInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)),
            key_handle: key.0,
        };
        let response = pkcs11_unary_call!(self.grpc.encrypt_init(req), true);
        match response.mechanism_out {
            Some(proto_mech) => {
                let mechanism = CkMechanism::try_from(&proto_mech)?;
                Ok(mechanism.params)
            }
            None => Ok(None),
        }
    }

    pub async fn encrypt_init_cancel(&mut self, session: CkSessionHandle) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::EncryptInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: None,
            key_handle: 0,
        };
        pkcs11_unary_ok!(self.grpc.encrypt_init(req), true)
    }

    pub async fn encrypt(&mut self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        let (bytes, _) = self.encrypt_with_mechanism_out(session, data).await?;
        Ok(bytes)
    }

    /// `C_Encrypt` returning ciphertext plus any HSM-mutated mechanism
    /// params (e.g. AES-GCM IV).  Backwards-compatible sibling of
    /// [`Self::encrypt`].
    pub async fn encrypt_with_mechanism_out(
        &mut self,
        session: CkSessionHandle,
        data: &[u8],
    ) -> CkResult<(Vec<u8>, Option<CkMechanismParams>)> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::EncryptRequest {
            client_context_id: ctx,
            session_handle: session.0,
            data: data.to_vec(),
        };
        pkcs11_unary_map!(self.grpc.encrypt(req), true, resp => {
            (resp.encrypted_data, Self::parse_mech_out(resp.mechanism_out)?)
        })
    }

    pub async fn encrypt_update(
        &mut self,
        session: CkSessionHandle,
        part: &[u8],
    ) -> CkResult<Vec<u8>> {
        let (bytes, _) = self.encrypt_update_with_mechanism_out(session, part).await?;
        Ok(bytes)
    }

    /// `C_EncryptUpdate` returning the partial ciphertext plus any
    /// HSM-mutated mechanism params.  Backwards-compatible sibling of
    /// [`Self::encrypt_update`].
    pub async fn encrypt_update_with_mechanism_out(
        &mut self,
        session: CkSessionHandle,
        part: &[u8],
    ) -> CkResult<(Vec<u8>, Option<CkMechanismParams>)> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::EncryptUpdateRequest {
            client_context_id: ctx,
            session_handle: session.0,
            part: part.to_vec(),
        };
        pkcs11_unary_map!(self.grpc.encrypt_update(req), true, resp => {
            (resp.encrypted_part, Self::parse_mech_out(resp.mechanism_out)?)
        })
    }

    pub async fn encrypt_final(&mut self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        let (bytes, _) = self.encrypt_final_with_mechanism_out(session).await?;
        Ok(bytes)
    }

    /// `C_EncryptFinal` returning the trailing ciphertext plus any
    /// HSM-mutated mechanism params.  Backwards-compatible sibling of
    /// [`Self::encrypt_final`].
    pub async fn encrypt_final_with_mechanism_out(
        &mut self,
        session: CkSessionHandle,
    ) -> CkResult<(Vec<u8>, Option<CkMechanismParams>)> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::EncryptFinalRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        pkcs11_unary_map!(self.grpc.encrypt_final(req), true, resp => {
            (resp.last_encrypted_part, Self::parse_mech_out(resp.mechanism_out)?)
        })
    }

    pub async fn decrypt_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.decrypt_init_with_mechanism_out(session, mechanism, key).await.map(|_| ())
    }

    /// `C_DecryptInit` returning any HSM-mutated mechanism params.
    /// Symmetric counterpart to [`Self::encrypt_init`].  Mechanism
    /// parameters mutated during decrypt-init (rare in practice but
    /// permitted by the spec) flow back here.
    pub async fn decrypt_init_with_mechanism_out(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DecryptInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)),
            key_handle: key.0,
        };
        pkcs11_unary_map!(self.grpc.decrypt_init(req), true, resp => {
            Self::parse_mech_out(resp.mechanism_out)?
        })
    }

    pub async fn decrypt_init_cancel(&mut self, session: CkSessionHandle) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DecryptInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: None,
            key_handle: 0,
        };
        pkcs11_unary_ok!(self.grpc.decrypt_init(req), true)
    }

    pub async fn decrypt(
        &mut self,
        session: CkSessionHandle,
        encrypted_data: &[u8],
    ) -> CkResult<Vec<u8>> {
        let (bytes, _) = self.decrypt_with_mechanism_out(session, encrypted_data).await?;
        Ok(bytes)
    }

    /// `C_Decrypt` returning plaintext plus any HSM-mutated mechanism
    /// params.  Backwards-compatible sibling of [`Self::decrypt`].
    pub async fn decrypt_with_mechanism_out(
        &mut self,
        session: CkSessionHandle,
        encrypted_data: &[u8],
    ) -> CkResult<(Vec<u8>, Option<CkMechanismParams>)> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DecryptRequest {
            client_context_id: ctx,
            session_handle: session.0,
            encrypted_data: encrypted_data.to_vec(),
        };
        pkcs11_unary_map!(self.grpc.decrypt(req), true, resp => {
            (resp.data, Self::parse_mech_out(resp.mechanism_out)?)
        })
    }

    pub async fn decrypt_update(
        &mut self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>> {
        let (bytes, _) = self.decrypt_update_with_mechanism_out(session, encrypted_part).await?;
        Ok(bytes)
    }

    /// `C_DecryptUpdate` returning the partial plaintext plus any
    /// HSM-mutated mechanism params.  Backwards-compatible sibling of
    /// [`Self::decrypt_update`].
    pub async fn decrypt_update_with_mechanism_out(
        &mut self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<(Vec<u8>, Option<CkMechanismParams>)> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DecryptUpdateRequest {
            client_context_id: ctx,
            session_handle: session.0,
            encrypted_part: encrypted_part.to_vec(),
        };
        pkcs11_unary_map!(self.grpc.decrypt_update(req), true, resp => {
            (resp.part, Self::parse_mech_out(resp.mechanism_out)?)
        })
    }

    pub async fn decrypt_final(&mut self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        let (bytes, _) = self.decrypt_final_with_mechanism_out(session).await?;
        Ok(bytes)
    }

    /// `C_DecryptFinal` returning the trailing plaintext plus any
    /// HSM-mutated mechanism params.  Backwards-compatible sibling of
    /// [`Self::decrypt_final`].
    pub async fn decrypt_final_with_mechanism_out(
        &mut self,
        session: CkSessionHandle,
    ) -> CkResult<(Vec<u8>, Option<CkMechanismParams>)> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DecryptFinalRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        pkcs11_unary_map!(self.grpc.decrypt_final(req), true, resp => {
            (resp.last_part, Self::parse_mech_out(resp.mechanism_out)?)
        })
    }

    /// Helper to decode an optional `mechanism_out` proto field.
    fn parse_mech_out(
        proto_mech: Option<pkcs11_proxy_ng_proto::Mechanism>,
    ) -> CkResult<Option<CkMechanismParams>> {
        match proto_mech {
            Some(m) => Ok(CkMechanism::try_from(&m)?.params),
            None => Ok(None),
        }
    }
}
