//! Client methods for PKCS#11 3.2 authenticated wrap/unwrap operations (Wave 5).

use pkcs11_proxy_ng_types::*;

use crate::client::Pkcs11Client;

impl Pkcs11Client {
    // --- C_WrapKeyAuthenticated — returns (wrapped_key, mechanism_parameter_out) ---

    pub async fn wrap_key_authenticated(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        if !pkcs11_proxy_ng_proto::convert::authenticated::legacy_parameter_supported(mechanism) {
            return Err(CkRv::FUNCTION_NOT_SUPPORTED);
        }
        let ctx = self.context_id()?;
        let mut req = pkcs11_proxy_ng_proto::WrapKeyAuthenticatedRequest {
            authenticated_parameters: None,
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)?),
            wrapping_key_handle: wrapping_key.0,
            key_handle: key.0,
            associated_data: Vec::new(),
            associated_data_null_len: None,
        };
        Self::fill_input(aad, &mut req.associated_data, &mut req.associated_data_null_len);
        // T12: `WrapKeyAuthenticatedResponse` is `ZeroizeOnDrop`; take owned
        // fields out with `mem::take` instead of moving them.
        let mut resp = pkcs11_unary_call!(self.grpc.wrap_key_authenticated(req), true);
        let wrapped_key = std::mem::take(&mut resp.wrapped_key);
        let parameter_out = std::mem::take(&mut resp.mechanism_parameter_out);
        Ok((wrapped_key, parameter_out))
    }

    // --- C_UnwrapKeyAuthenticated — returns (key_handle, mechanism_parameter_out) ---

    pub async fn unwrap_key_authenticated(
        &mut self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        unwrapping_key: CkObjectHandle,
        wrapped_key: CkInBuf<'_>,
        template: Option<&[CkAttribute]>,
        aad: CkInBuf<'_>,
    ) -> CkResult<(CkObjectHandle, Vec<u8>)> {
        if !pkcs11_proxy_ng_proto::convert::authenticated::legacy_parameter_supported(mechanism) {
            return Err(CkRv::FUNCTION_NOT_SUPPORTED);
        }
        let ctx = self.context_id()?;
        let proto_template = Self::proto_template(template.unwrap_or(&[]));
        let mut req = pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedRequest {
            authenticated_parameters: None,
            client_context_id: ctx,
            session_handle: session.0,
            mechanism: Some(Self::proto_mechanism(mechanism)?),
            unwrapping_key_handle: unwrapping_key.0,
            wrapped_key: Vec::new(),
            template: proto_template,
            template_null: template.is_none(),
            associated_data: Vec::new(),
            wrapped_key_null_len: None,
            associated_data_null_len: None,
        };
        Self::fill_input(wrapped_key, &mut req.wrapped_key, &mut req.wrapped_key_null_len);
        Self::fill_input(aad, &mut req.associated_data, &mut req.associated_data_null_len);
        // T12: `UnwrapKeyAuthenticatedResponse` is `ZeroizeOnDrop`; take
        // the owned field out with `mem::take` instead of moving it.
        let mut resp = pkcs11_unary_call!(self.grpc.unwrap_key_authenticated(req), true);
        Ok((CkObjectHandle(resp.key_handle), std::mem::take(&mut resp.mechanism_parameter_out)))
    }
}
