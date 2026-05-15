use pkcs11_proxy_ng_types::*;

use crate::client::Pkcs11Client;

impl Pkcs11Client {
    // --- Message Encrypt Init (optional mechanism — None = cancel) ---

    pub async fn message_encrypt_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::MessageEncryptInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: mechanism.map(Self::proto_mechanism),
            key_handle: key.0,
        };
        pkcs11_unary_ok!(self.grpc.message_encrypt_init(req), true)
    }

    // --- Message Encrypt Final ---

    pub async fn message_encrypt_final(&mut self, session: CkSessionHandle) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::MessageEncryptFinalRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        pkcs11_unary_ok!(self.grpc.message_encrypt_final(req), true)
    }

    // --- Message Decrypt Init (optional mechanism — None = cancel) ---

    pub async fn message_decrypt_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::MessageDecryptInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: mechanism.map(Self::proto_mechanism),
            key_handle: key.0,
        };
        pkcs11_unary_ok!(self.grpc.message_decrypt_init(req), true)
    }

    // --- Message Decrypt Final ---

    pub async fn message_decrypt_final(&mut self, session: CkSessionHandle) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::MessageDecryptFinalRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        pkcs11_unary_ok!(self.grpc.message_decrypt_final(req), true)
    }

    // --- Message Sign Init (optional mechanism — None = cancel) ---

    pub async fn message_sign_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::MessageSignInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: mechanism.map(Self::proto_mechanism),
            key_handle: key.0,
        };
        pkcs11_unary_ok!(self.grpc.message_sign_init(req), true)
    }

    // --- Message Sign Final ---

    pub async fn message_sign_final(&mut self, session: CkSessionHandle) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::MessageSignFinalRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        pkcs11_unary_ok!(self.grpc.message_sign_final(req), true)
    }

    // --- Message Verify Init (optional mechanism — None = cancel) ---

    pub async fn message_verify_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::MessageVerifyInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: mechanism.map(Self::proto_mechanism),
            key_handle: key.0,
        };
        pkcs11_unary_ok!(self.grpc.message_verify_init(req), true)
    }

    // --- Message Verify Final ---

    pub async fn message_verify_final(&mut self, session: CkSessionHandle) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::MessageVerifyFinalRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        pkcs11_unary_ok!(self.grpc.message_verify_final(req), true)
    }

    // =====================================================================
    // One-shot / Begin / Next methods
    // =====================================================================

    // --- C_EncryptMessage — returns (parameter_out, ciphertext) ---

    pub async fn encrypt_message(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::EncryptMessageRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            associated_data: aad.to_vec(),
            plaintext: plaintext.to_vec(),
        };
        let resp = pkcs11_unary_call!(self.grpc.encrypt_message(req), true);
        Ok((resp.parameter_out, resp.ciphertext))
    }

    // --- C_EncryptMessageBegin — returns parameter_out ---

    pub async fn encrypt_message_begin(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: &[u8],
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::EncryptMessageBeginRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            associated_data: aad.to_vec(),
        };
        let resp = pkcs11_unary_call!(self.grpc.encrypt_message_begin(req), true);
        Ok(resp.parameter_out)
    }

    // --- C_EncryptMessageNext — returns (parameter_out, ciphertext_part) ---

    pub async fn encrypt_message_next(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        plaintext_part: &[u8],
        flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::EncryptMessageNextRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            plaintext_part: plaintext_part.to_vec(),
            flags: flags.0,
        };
        let resp = pkcs11_unary_call!(self.grpc.encrypt_message_next(req), true);
        Ok((resp.parameter_out, resp.ciphertext_part))
    }

    // --- C_DecryptMessage — returns (parameter_out, plaintext) ---

    pub async fn decrypt_message(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DecryptMessageRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            associated_data: aad.to_vec(),
            ciphertext: ciphertext.to_vec(),
        };
        let resp = pkcs11_unary_call!(self.grpc.decrypt_message(req), true);
        Ok((resp.parameter_out, resp.plaintext))
    }

    // --- C_DecryptMessageBegin — returns parameter_out ---

    pub async fn decrypt_message_begin(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: &[u8],
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DecryptMessageBeginRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            associated_data: aad.to_vec(),
        };
        let resp = pkcs11_unary_call!(self.grpc.decrypt_message_begin(req), true);
        Ok(resp.parameter_out)
    }

    // --- C_DecryptMessageNext — returns (parameter_out, plaintext_part) ---

    pub async fn decrypt_message_next(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        ciphertext_part: &[u8],
        flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DecryptMessageNextRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            ciphertext_part: ciphertext_part.to_vec(),
            flags: flags.0,
        };
        let resp = pkcs11_unary_call!(self.grpc.decrypt_message_next(req), true);
        Ok((resp.parameter_out, resp.plaintext_part))
    }

    // --- C_SignMessage — returns (parameter_out, signature) ---

    pub async fn sign_message(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        data: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::SignMessageRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            data: data.to_vec(),
        };
        let resp = pkcs11_unary_call!(self.grpc.sign_message(req), true);
        Ok((resp.parameter_out, resp.signature))
    }

    // --- C_SignMessageBegin — returns parameter_out ---

    pub async fn sign_message_begin(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::SignMessageBeginRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
        };
        let resp = pkcs11_unary_call!(self.grpc.sign_message_begin(req), true);
        Ok(resp.parameter_out)
    }

    // --- C_SignMessageNext — returns (parameter_out, signature) ---

    pub async fn sign_message_next(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        data_part: &[u8],
        request_signature: bool,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::SignMessageNextRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            data_part: data_part.to_vec(),
            request_signature,
        };
        let resp = pkcs11_unary_call!(self.grpc.sign_message_next(req), true);
        Ok((resp.parameter_out, resp.signature))
    }

    // --- C_VerifyMessage — unit result, parameter is input-only ---

    pub async fn verify_message(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::VerifyMessageRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            data: data.to_vec(),
            signature: signature.to_vec(),
        };
        pkcs11_unary_ok!(self.grpc.verify_message(req), true)
    }

    // --- C_VerifyMessageBegin — unit result ---

    pub async fn verify_message_begin(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::VerifyMessageBeginRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
        };
        pkcs11_unary_ok!(self.grpc.verify_message_begin(req), true)
    }

    // --- C_VerifyMessageNext — unit result ---

    pub async fn verify_message_next(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        data_part: &[u8],
        is_final: bool,
        signature: &[u8],
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::VerifyMessageNextRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            data_part: data_part.to_vec(),
            is_final,
            signature: signature.to_vec(),
        };
        pkcs11_unary_ok!(self.grpc.verify_message_next(req), true)
    }
}
