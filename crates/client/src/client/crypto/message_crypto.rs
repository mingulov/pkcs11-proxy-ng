use pkcs11_proxy_ng_proto::convert::message_params::MessageParameter;
use pkcs11_proxy_ng_types::*;

use crate::client::Pkcs11Client;

impl Pkcs11Client {
    // --- Message Encrypt Init (optional mechanism — None = cancel) ---

    pub async fn message_encrypt_init(
        &mut self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        init_param: Option<&MessageParameter>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::MessageEncryptInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: mechanism.map(Self::proto_mechanism),
            key_handle: key.0,
            init_message_parameter: init_param.map(Into::into),
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
        init_param: Option<&MessageParameter>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::MessageDecryptInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: mechanism.map(Self::proto_mechanism),
            key_handle: key.0,
            init_message_parameter: init_param.map(Into::into),
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
        aad: CkInBuf<'_>,
        plaintext: CkInBuf<'_>,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::EncryptMessageRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            associated_data: Vec::new(),
            plaintext: Vec::new(),
            associated_data_null_len: None,
            plaintext_null_len: None,
        };
        Self::fill_input(aad, &mut req.associated_data, &mut req.associated_data_null_len);
        Self::fill_input(plaintext, &mut req.plaintext, &mut req.plaintext_null_len);
        let resp = pkcs11_unary_call!(self.grpc.encrypt_message(req), true);
        Ok((resp.parameter_out, resp.ciphertext))
    }

    // --- C_EncryptMessageBegin — returns parameter_out ---

    pub async fn encrypt_message_begin(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: CkInBuf<'_>,
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::EncryptMessageBeginRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            associated_data: Vec::new(),
            associated_data_null_len: None,
        };
        Self::fill_input(aad, &mut req.associated_data, &mut req.associated_data_null_len);
        let resp = pkcs11_unary_call!(self.grpc.encrypt_message_begin(req), true);
        Ok(resp.parameter_out)
    }

    // --- C_EncryptMessageNext — returns (parameter_out, ciphertext_part) ---

    pub async fn encrypt_message_next(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        plaintext_part: CkInBuf<'_>,
        flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::EncryptMessageNextRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            plaintext_part: Vec::new(),
            flags: flags.0,
            plaintext_part_null_len: None,
        };
        Self::fill_input(plaintext_part, &mut req.plaintext_part, &mut req.plaintext_part_null_len);
        let resp = pkcs11_unary_call!(self.grpc.encrypt_message_next(req), true);
        Ok((resp.parameter_out, resp.ciphertext_part))
    }

    // --- C_DecryptMessage — returns (parameter_out, plaintext) ---

    pub async fn decrypt_message(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: CkInBuf<'_>,
        ciphertext: CkInBuf<'_>,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::DecryptMessageRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            associated_data: Vec::new(),
            ciphertext: Vec::new(),
            associated_data_null_len: None,
            ciphertext_null_len: None,
        };
        Self::fill_input(aad, &mut req.associated_data, &mut req.associated_data_null_len);
        Self::fill_input(ciphertext, &mut req.ciphertext, &mut req.ciphertext_null_len);
        let resp = pkcs11_unary_call!(self.grpc.decrypt_message(req), true);
        Ok((resp.parameter_out, resp.plaintext))
    }

    // --- C_DecryptMessageBegin — returns parameter_out ---

    pub async fn decrypt_message_begin(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: CkInBuf<'_>,
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::DecryptMessageBeginRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            associated_data: Vec::new(),
            associated_data_null_len: None,
        };
        Self::fill_input(aad, &mut req.associated_data, &mut req.associated_data_null_len);
        let resp = pkcs11_unary_call!(self.grpc.decrypt_message_begin(req), true);
        Ok(resp.parameter_out)
    }

    // --- C_DecryptMessageNext — returns (parameter_out, plaintext_part) ---

    pub async fn decrypt_message_next(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        ciphertext_part: CkInBuf<'_>,
        flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::DecryptMessageNextRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            ciphertext_part: Vec::new(),
            flags: flags.0,
            ciphertext_part_null_len: None,
        };
        Self::fill_input(
            ciphertext_part,
            &mut req.ciphertext_part,
            &mut req.ciphertext_part_null_len,
        );
        let resp = pkcs11_unary_call!(self.grpc.decrypt_message_next(req), true);
        Ok((resp.parameter_out, resp.plaintext_part))
    }

    // --- C_SignMessage — returns (parameter_out, signature) ---

    pub async fn sign_message(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        data: CkInBuf<'_>,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::SignMessageRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            data: Vec::new(),
            data_null_len: None,
        };
        Self::fill_input(data, &mut req.data, &mut req.data_null_len);
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
        data_part: CkInBuf<'_>,
        request_signature: bool,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::SignMessageNextRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            data_part: Vec::new(),
            request_signature,
            data_part_null_len: None,
        };
        Self::fill_input(data_part, &mut req.data_part, &mut req.data_part_null_len);
        let resp = pkcs11_unary_call!(self.grpc.sign_message_next(req), true);
        Ok((resp.parameter_out, resp.signature))
    }

    // --- C_VerifyMessage — unit result, parameter is input-only ---

    pub async fn verify_message(
        &mut self,
        session: CkSessionHandle,
        parameter: &[u8],
        data: CkInBuf<'_>,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::VerifyMessageRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            data: Vec::new(),
            signature: Vec::new(),
            data_null_len: None,
            signature_null_len: None,
        };
        Self::fill_input(data, &mut req.data, &mut req.data_null_len);
        Self::fill_input(signature, &mut req.signature, &mut req.signature_null_len);
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
        data_part: CkInBuf<'_>,
        is_final: bool,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::VerifyMessageNextRequest {
            client_context_id: ctx,
            session_handle: session.0,
            parameter: parameter.to_vec(),
            data_part: Vec::new(),
            is_final,
            signature: Vec::new(),
            data_part_null_len: None,
            signature_null_len: None,
        };
        Self::fill_input(data_part, &mut req.data_part, &mut req.data_part_null_len);
        Self::fill_input(signature, &mut req.signature, &mut req.signature_null_len);
        pkcs11_unary_ok!(self.grpc.verify_message_next(req), true)
    }
}
