use pkcs11_proxy_ng_types::*;

use super::Pkcs11Client;

impl Pkcs11Client {
    pub async fn find_objects_init(
        &mut self,
        session: CkSessionHandle,
        template: &[CkAttribute],
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let proto_template = Self::proto_template(template);
        let req = pkcs11_proxy_ng_proto::FindObjectsInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            template: proto_template,
        };
        pkcs11_unary_ok!(self.grpc.find_objects_init(req), true)
    }

    pub async fn find_objects(
        &mut self,
        session: CkSessionHandle,
        max_count: u32,
    ) -> CkResult<Vec<CkObjectHandle>> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::FindObjectsRequest {
            client_context_id: ctx,
            session_handle: session.0,
            max_object_count: max_count,
        };
        let resp = pkcs11_unary_call!(self.grpc.find_objects(req), true);
        Ok(resp.object_handles.into_iter().map(CkObjectHandle).collect())
    }

    pub async fn find_objects_final(&mut self, session: CkSessionHandle) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::FindObjectsFinalRequest {
            client_context_id: ctx,
            session_handle: session.0,
        };
        pkcs11_unary_ok!(self.grpc.find_objects_final(req), true)
    }

    pub async fn create_object(
        &mut self,
        session: CkSessionHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let ctx = self.context_id()?;
        let proto_template = Self::proto_template(template);
        let req = pkcs11_proxy_ng_proto::CreateObjectRequest {
            client_context_id: ctx,
            session_handle: session.0,
            template: proto_template,
        };
        let resp = pkcs11_unary_call!(self.grpc.create_object(req), true);
        Ok(CkObjectHandle(resp.object_handle))
    }

    pub async fn copy_object(
        &mut self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let ctx = self.context_id()?;
        let proto_template = Self::proto_template(template);
        let req = pkcs11_proxy_ng_proto::CopyObjectRequest {
            client_context_id: ctx,
            session_handle: session.0,
            object_handle: object.0,
            template: proto_template,
        };
        let resp = pkcs11_unary_call!(self.grpc.copy_object(req), true);
        Ok(CkObjectHandle(resp.new_object_handle))
    }

    pub async fn destroy_object(
        &mut self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::DestroyObjectRequest {
            client_context_id: ctx,
            session_handle: session.0,
            object_handle: object.0,
        };
        pkcs11_unary_ok!(self.grpc.destroy_object(req), true)
    }

    pub async fn get_object_size(
        &mut self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> CkResult<u64> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::GetObjectSizeRequest {
            client_context_id: ctx,
            session_handle: session.0,
            object_handle: object.0,
        };
        let resp = pkcs11_unary_call!(self.grpc.get_object_size(req), true);
        Ok(resp.size)
    }

    pub async fn set_attribute_value(
        &mut self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let proto_template = Self::proto_template(template);
        let req = pkcs11_proxy_ng_proto::SetAttributeValueRequest {
            client_context_id: ctx,
            session_handle: session.0,
            object_handle: object.0,
            template: proto_template,
        };
        pkcs11_unary_ok!(self.grpc.set_attribute_value(req), true)
    }

    /// Retrieve attribute values from an object.
    ///
    /// Returns `(ck_rv, attributes)` on success (i.e. when the server responded).
    /// `ck_rv` may be `CKR_OK`, `CKR_ATTRIBUTE_SENSITIVE`, `CKR_ATTRIBUTE_TYPE_INVALID`, or
    /// `CKR_BUFFER_TOO_SMALL` — in all these cases `attributes` contains the partial results as
    /// required by PKCS#11 §5.7. `Err(rv)` is returned only for fatal transport/protocol errors
    /// that yield no usable template data.
    pub async fn get_attribute_value(
        &mut self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &[CkAttribute],
    ) -> Result<(CkRv, Vec<CkAttribute>), CkRv> {
        let queries = template
            .iter()
            .map(|attr| {
                let (buffer_present, buffer_len) = match &attr.value {
                    Some(CkAttributeValue::Bool(_)) => (true, 1),
                    Some(CkAttributeValue::Ulong(_)) => (true, std::mem::size_of::<usize>() as u64),
                    Some(CkAttributeValue::Bytes(bytes)) => (true, bytes.len() as u64),
                    Some(CkAttributeValue::String(value)) => (true, value.len() as u64),
                    None => (false, 0),
                };
                CkAttributeQuery {
                    attr_type: attr.attr_type,
                    buffer_present,
                    buffer_len,
                    nested: None,
                }
            })
            .collect::<Vec<_>>();

        let (rv, results) = self.get_attribute_value_exact(session, object, &queries).await?;
        Ok((
            rv,
            results
                .into_iter()
                .map(|result| CkAttribute {
                    attr_type: result.attr_type,
                    value: result.value.map(CkAttributeValue::Bytes),
                })
                .collect(),
        ))
    }
}
