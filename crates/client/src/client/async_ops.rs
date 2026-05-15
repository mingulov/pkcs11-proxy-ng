//! Client methods for PKCS#11 3.2 async operations (Wave 5, Option B).
//!
//! - `C_AsyncComplete` — real call, passes through `CKR_PENDING`
//! - `C_AsyncGetID` — always returns `CKR_STATE_UNSAVEABLE`
//! - `C_AsyncJoin` — always returns `CKR_SAVED_STATE_INVALID`

use pkcs11_proxy_ng_types::*;

use super::Pkcs11Client;

impl Pkcs11Client {
    // --- C_AsyncComplete — real RPC, may return CKR_PENDING ---

    pub async fn async_complete(
        &mut self,
        session: CkSessionHandle,
        function_name: &str,
    ) -> CkResult<(u64, Vec<u8>, u64, CkObjectHandle, CkObjectHandle)> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::AsyncCompleteRequest {
            client_context_id: ctx,
            session_handle: session.0,
            function_name: function_name.to_string(),
        };
        // Use manual call pattern to pass through CKR_PENDING
        let response = self
            .grpc
            .async_complete(req)
            .await
            .map_err(|status| crate::error::grpc_status_to_ck_rv(status.code(), true))?
            .into_inner();

        let rv = CkRv(response.ck_rv);
        if !rv.is_ok() {
            return Err(rv);
        }

        let data = response.async_data.unwrap_or_default();
        Ok((
            data.version,
            data.value,
            data.value_len,
            CkObjectHandle(data.object_handle),
            CkObjectHandle(data.additional_object_handle),
        ))
    }

    // --- C_AsyncGetID — always CKR_STATE_UNSAVEABLE (Option B) ---

    pub async fn async_get_id(
        &mut self,
        session: CkSessionHandle,
        function_name: &str,
    ) -> CkResult<u64> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::AsyncGetIdRequest {
            client_context_id: ctx,
            session_handle: session.0,
            function_name: function_name.to_string(),
        };
        let resp = pkcs11_unary_call!(self.grpc.async_get_id(req), true);
        Ok(resp.operation_id)
    }

    // --- C_AsyncJoin — always CKR_SAVED_STATE_INVALID (Option B) ---

    pub async fn async_join(
        &mut self,
        session: CkSessionHandle,
        function_name: &str,
        operation_id: u64,
        buffer_size: u64,
    ) -> CkResult<Vec<u8>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::AsyncJoinRequest {
            client_context_id: ctx,
            session_handle: session.0,
            function_name: function_name.to_string(),
            operation_id,
            buffer_size,
        };
        let resp = pkcs11_unary_call!(self.grpc.async_join(req), true);
        Ok(resp.data)
    }
}
