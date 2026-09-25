use pkcs11_proxy_ng_types::*;

use super::Pkcs11Client;

impl Pkcs11Client {
    pub async fn find_objects_init(
        &mut self,
        session: CkSessionHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let proto_template = Self::proto_template(template.unwrap_or(&[]));
        let req = pkcs11_proxy_ng_proto::FindObjectsInitRequest {
            client_context_id: ctx,
            session_handle: session.0,
            template: proto_template,
            template_null: template.is_none(),
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
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        let ctx = self.context_id()?;
        let proto_template = Self::proto_template(template.unwrap_or(&[]));
        let req = pkcs11_proxy_ng_proto::CreateObjectRequest {
            client_context_id: ctx,
            session_handle: session.0,
            template: proto_template,
            template_null: template.is_none(),
        };
        let resp = pkcs11_unary_call!(self.grpc.create_object(req), true);
        Ok(CkObjectHandle(resp.object_handle))
    }

    pub async fn copy_object(
        &mut self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        let ctx = self.context_id()?;
        let proto_template = Self::proto_template(template.unwrap_or(&[]));
        let req = pkcs11_proxy_ng_proto::CopyObjectRequest {
            client_context_id: ctx,
            session_handle: session.0,
            object_handle: object.0,
            template: proto_template,
            template_null: template.is_none(),
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
        template: Option<&[CkAttribute]>,
    ) -> CkResult<()> {
        let ctx = self.context_id()?;
        let proto_template = Self::proto_template(template.unwrap_or(&[]));
        let req = pkcs11_proxy_ng_proto::SetAttributeValueRequest {
            client_context_id: ctx,
            session_handle: session.0,
            object_handle: object.0,
            template: proto_template,
            template_null: template.is_none(),
        };
        pkcs11_unary_ok!(self.grpc.set_attribute_value(req), true)
    }
}

/// Decode one exact-path result value into a typed [`CkAttributeValue`]
/// (W1-C10-08).
///
/// The caller's request-template value is a buffer *hint*: an explicit
/// `Bool`/`Ulong`/`String` hint decodes the returned bytes into that same
/// shape, so typed reads round-trip. Unhinted (`None`) size-query reads
/// carry no values from a conforming backend; if bytes arrive anyway they
/// are typed by attribute classifier (`is_bool`/`is_ulong`).
///
/// Remaining erasure (documented): there is no `String` classifier, so a
/// string-typed attribute read without a `String` hint comes back as
/// `Bytes` — callers that need `String` pass a `String` buffer hint.
/// `NestedTemplate` reads are unsupported on this convenience path (the
/// request side already downgrades them to a size query); any surviving
/// bytes come back as `Bytes`. Malformed scalar lengths (bool ≠ 1 byte,
/// ulong ∉ {4, 8}) fall back to `Bytes` rather than corrupt.
fn typed_attribute_value(
    attr_type: CkAttributeType,
    hint: Option<&CkAttributeValue>,
    value: Option<SecretBytes>,
) -> Option<CkAttributeValue> {
    let bytes = value?;
    match hint {
        Some(CkAttributeValue::Bool(_)) => return Some(decode_bool_or_bytes(&bytes)),
        Some(CkAttributeValue::Ulong(_)) => return Some(decode_ulong_or_bytes(&bytes)),
        Some(CkAttributeValue::String(_)) => return Some(CkAttributeValue::String(bytes)),
        Some(CkAttributeValue::Bytes(_)) | Some(CkAttributeValue::NestedTemplate(_)) => {
            return Some(CkAttributeValue::Bytes(bytes));
        }
        None => {}
    }
    if attr_type.is_bool() {
        Some(decode_bool_or_bytes(&bytes))
    } else if attr_type.is_ulong() {
        Some(decode_ulong_or_bytes(&bytes))
    } else {
        Some(CkAttributeValue::Bytes(bytes))
    }
}

/// `CK_BBOOL` is one byte (`0` = false, nonzero = true).
fn decode_bool_or_bytes(bytes: &SecretBytes) -> CkAttributeValue {
    bytes.expose(|raw| match raw {
        [byte] => CkAttributeValue::Bool(*byte != 0),
        _ => CkAttributeValue::Bytes(bytes.clone()),
    })
}

/// Scalar `CK_ULONG` in native byte order at backend width (4 or 8).
/// Native order matches the width bridge's post-probe contract (ADR-0011
/// D6 refuses endian-mismatched peers at probe) and the CLI's
/// `bytes_to_u64` reader on this same path.
fn decode_ulong_or_bytes(bytes: &SecretBytes) -> CkAttributeValue {
    bytes.expose(|raw| {
        let sized: Option<u64> = match raw.len() {
            4 => raw.try_into().ok().map(u32::from_ne_bytes).map(u64::from),
            8 => raw.try_into().ok().map(u64::from_ne_bytes),
            _ => None,
        };
        sized.map(CkAttributeValue::Ulong).unwrap_or_else(|| CkAttributeValue::Bytes(bytes.clone()))
    })
}

impl Pkcs11Client {
    /// Retrieve attribute values from an object.
    ///
    /// Returns `(ck_rv, attributes)` on success (i.e. when the server responded).
    /// `ck_rv` may be `CKR_OK`, `CKR_ATTRIBUTE_SENSITIVE`, `CKR_ATTRIBUTE_TYPE_INVALID`, or
    /// `CKR_BUFFER_TOO_SMALL` — in all these cases `attributes` contains the partial results as
    /// required by PKCS#11 §5.7. `Err(rv)` is returned only for fatal transport/protocol errors
    /// that yield no usable template data.
    ///
    /// Returned values are typed: `Bool`/`Ulong`/`String` buffer hints in
    /// `template` decode into that same shape (W1-C10-08). Unhinted reads
    /// fall back to the attribute classifier; the remaining erasure
    /// (unhinted `String`, nested templates, malformed scalar lengths) is
    /// documented on the decode helper and returns `Bytes`.
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
                    // This convenience read path sizes buffers from the input
                    // value; a nested template's read size is its native
                    // template byte length, which only the shim's exact path
                    // computes. Treat as a size query here.
                    Some(CkAttributeValue::NestedTemplate(_)) => (false, 0),
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
                .enumerate()
                .map(|(index, result)| {
                    // Index-safe: a short template (length-mismatched daemon
                    // reply) decodes unhinted rather than dropping results.
                    let hint = template.get(index).and_then(|attr| attr.value.as_ref());
                    CkAttribute {
                        attr_type: result.attr_type,
                        value: typed_attribute_value(result.attr_type, hint, result.value),
                    }
                })
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(bytes: &[u8]) -> Option<SecretBytes> {
        Some(SecretBytes::copy_from_slice(bytes))
    }

    // W1-C10-08: explicit buffer hints decode into their own shape.
    #[test]
    fn hinted_bool_ulong_string_round_trip() {
        let bool_hint = CkAttributeValue::Bool(false);
        assert_eq!(
            typed_attribute_value(CkAttributeType::TOKEN, Some(&bool_hint), secret(&[1])),
            Some(CkAttributeValue::Bool(true))
        );
        assert_eq!(
            typed_attribute_value(CkAttributeType::TOKEN, Some(&bool_hint), secret(&[0])),
            Some(CkAttributeValue::Bool(false))
        );
        let ulong_hint = CkAttributeValue::Ulong(0);
        assert_eq!(
            typed_attribute_value(
                CkAttributeType::CLASS,
                Some(&ulong_hint),
                secret(&3u64.to_ne_bytes())
            ),
            Some(CkAttributeValue::Ulong(3))
        );
        assert_eq!(
            typed_attribute_value(
                CkAttributeType::CLASS,
                Some(&ulong_hint),
                secret(&7u32.to_ne_bytes())
            ),
            Some(CkAttributeValue::Ulong(7))
        );
        let string_hint = CkAttributeValue::String("....".to_string().into());
        assert_eq!(
            typed_attribute_value(CkAttributeType::LABEL, Some(&string_hint), secret(b"key")),
            Some(CkAttributeValue::String(SecretBytes::copy_from_slice(b"key")))
        );
        let bytes_hint = CkAttributeValue::Bytes(vec![0; 4].into());
        assert!(matches!(
            typed_attribute_value(CkAttributeType::MODULUS, Some(&bytes_hint), secret(&[1, 2, 3])),
            Some(CkAttributeValue::Bytes(_))
        ));
    }

    // W1-C10-08: malformed scalar lengths fall back to Bytes, never corrupt.
    #[test]
    fn malformed_scalar_lengths_fall_back_to_bytes() {
        let bool_hint = CkAttributeValue::Bool(false);
        assert!(matches!(
            typed_attribute_value(CkAttributeType::TOKEN, Some(&bool_hint), secret(&[1, 2])),
            Some(CkAttributeValue::Bytes(_))
        ));
        let ulong_hint = CkAttributeValue::Ulong(0);
        assert!(matches!(
            typed_attribute_value(CkAttributeType::CLASS, Some(&ulong_hint), secret(&[1, 2, 3])),
            Some(CkAttributeValue::Bytes(_))
        ));
    }

    // W1-C10-08: unhinted reads type by classifier where one exists; absent
    // values stay absent; string-typed attrs without a String hint remain
    // Bytes (documented erasure — no String classifier exists).
    #[test]
    fn unhinted_values_type_by_classifier() {
        assert_eq!(
            typed_attribute_value(CkAttributeType::CLASS, None, secret(&4u64.to_ne_bytes())),
            Some(CkAttributeValue::Ulong(4))
        );
        assert_eq!(
            typed_attribute_value(CkAttributeType::TOKEN, None, secret(&[1])),
            Some(CkAttributeValue::Bool(true))
        );
        assert!(matches!(
            typed_attribute_value(CkAttributeType::LABEL, None, secret(b"key")),
            Some(CkAttributeValue::Bytes(_))
        ));
        assert_eq!(typed_attribute_value(CkAttributeType::CLASS, None, None), None);
        let nested_hint = CkAttributeValue::NestedTemplate(vec![]);
        assert!(matches!(
            typed_attribute_value(CkAttributeType::WRAP_TEMPLATE, Some(&nested_hint), secret(&[0])),
            Some(CkAttributeValue::Bytes(_))
        ));
    }
}
