// CK_ULONG is u64 on 64-bit and u32 on 32-bit; the `as u64` casts are
// intentional for cross-platform PKCS#11 portability.
#![allow(clippy::unnecessary_cast)]

use std::mem::size_of;

use pkcs11_proxy_ng_types::*;

use super::{MockAttributeSlot, MockBackend};

impl MockBackend {
    fn attribute_bytes(value: &CkAttributeValue) -> Vec<u8> {
        match value {
            CkAttributeValue::Bool(flag) => {
                if *flag {
                    vec![1]
                } else {
                    vec![0]
                }
            }
            CkAttributeValue::Ulong(value) => value.to_le_bytes().to_vec(),
            CkAttributeValue::Bytes(bytes) => bytes.clone(),
            CkAttributeValue::String(value) => value.as_bytes().to_vec(),
        }
    }

    pub(super) fn find_objects_init_impl(&self) -> CkResult<()> {
        Ok(())
    }

    pub(super) fn find_objects_impl(&self) -> CkResult<Vec<CkObjectHandle>> {
        Ok(vec![])
    }

    pub(super) fn find_objects_final_impl(&self) -> CkResult<()> {
        Ok(())
    }

    pub(super) fn get_attribute_value_impl(
        &self,
        object: CkObjectHandle,
        template: &mut [CkAttribute],
    ) -> CkResult<()> {
        let store = self.attribute_store.lock().unwrap();
        let obj_map = match store.get(&object.0) {
            None => return Ok(()),
            Some(map) => map,
        };
        let mut has_sensitive = false;
        let mut has_invalid = false;
        for attr in template.iter_mut() {
            match obj_map.get(&attr.attr_type.0) {
                Some(MockAttributeSlot::Value(value)) => attr.value = Some(value.clone()),
                Some(MockAttributeSlot::Sensitive) => {
                    attr.value = None;
                    has_sensitive = true;
                }
                Some(MockAttributeSlot::NestedTemplate(_)) => {
                    // Legacy path does not support nested templates; treat as bytes.
                    attr.value = None;
                }
                Some(MockAttributeSlot::InvalidType) | None => {
                    attr.value = None;
                    has_invalid = true;
                }
            }
        }
        if has_sensitive {
            Err(CkRv::ATTRIBUTE_SENSITIVE)
        } else if has_invalid {
            Err(CkRv::ATTRIBUTE_TYPE_INVALID)
        } else {
            Ok(())
        }
    }

    pub(super) fn get_attribute_value_exact_impl(
        &self,
        object: CkObjectHandle,
        queries: &[CkAttributeQuery],
    ) -> CkResult<(CkRv, Vec<CkAttributeQueryResult>)> {
        let store = self.attribute_store.lock().unwrap();
        let Some(obj_map) = store.get(&object.0) else {
            return Err(CkRv::OBJECT_HANDLE_INVALID);
        };

        let mut overall_rv = CkRv::OK;
        let results = queries
            .iter()
            .map(|query| match obj_map.get(&query.attr_type.0) {
                Some(MockAttributeSlot::Value(value)) => {
                    let bytes = Self::attribute_bytes(value);
                    let returned_len = bytes.len() as u64;
                    if !query.buffer_present {
                        CkAttributeQueryResult {
                            attr_type: query.attr_type,
                            returned_len,
                            value: None,
                            ck_rv: None,
                            nested: None,
                        }
                    } else if query.buffer_len < returned_len {
                        overall_rv = CkRv::BUFFER_TOO_SMALL;
                        CkAttributeQueryResult {
                            attr_type: query.attr_type,
                            returned_len: cryptoki_sys::CK_UNAVAILABLE_INFORMATION as u64,
                            value: None,
                            ck_rv: Some(CkRv::BUFFER_TOO_SMALL),
                            nested: None,
                        }
                    } else {
                        CkAttributeQueryResult {
                            attr_type: query.attr_type,
                            returned_len,
                            value: Some(bytes),
                            ck_rv: None,
                            nested: None,
                        }
                    }
                }
                Some(MockAttributeSlot::NestedTemplate(sub_slots)) => {
                    Self::nested_template_result(query, sub_slots, &mut overall_rv)
                }
                Some(MockAttributeSlot::Sensitive) => {
                    if overall_rv == CkRv::OK {
                        overall_rv = CkRv::ATTRIBUTE_SENSITIVE;
                    }
                    CkAttributeQueryResult {
                        attr_type: query.attr_type,
                        returned_len: cryptoki_sys::CK_UNAVAILABLE_INFORMATION as u64,
                        value: None,
                        ck_rv: Some(CkRv::ATTRIBUTE_SENSITIVE),
                        nested: None,
                    }
                }
                Some(MockAttributeSlot::InvalidType) | None => {
                    if overall_rv == CkRv::OK {
                        overall_rv = CkRv::ATTRIBUTE_TYPE_INVALID;
                    }
                    CkAttributeQueryResult {
                        attr_type: query.attr_type,
                        returned_len: cryptoki_sys::CK_UNAVAILABLE_INFORMATION as u64,
                        value: None,
                        ck_rv: Some(CkRv::ATTRIBUTE_TYPE_INVALID),
                        nested: None,
                    }
                }
            })
            .collect();

        Ok((overall_rv, results))
    }

    /// Build a `CkAttributeQueryResult` for a `NestedTemplate` mock slot.
    ///
    /// Simulates PKCS#11 `CKF_ARRAY_ATTRIBUTE` two-call semantics:
    /// - Size query (`!buffer_present`): returns `returned_len = count * sizeof(CK_ATTRIBUTE)`,
    ///   no nested sub-results.
    /// - Data query with nested sub-queries: returns nested `CkAttributeQueryResult` items
    ///   for each sub-attribute, honoring sub-buffer sizes.
    fn nested_template_result(
        query: &CkAttributeQuery,
        sub_slots: &[(CkAttributeType, MockAttributeSlot)],
        overall_rv: &mut CkRv,
    ) -> CkAttributeQueryResult {
        let template_byte_len = (sub_slots.len() * size_of::<cryptoki_sys::CK_ATTRIBUTE>()) as u64;

        // Size query: caller passes pValue=NULL
        if !query.buffer_present {
            return CkAttributeQueryResult {
                attr_type: query.attr_type,
                returned_len: template_byte_len,
                value: None,
                ck_rv: None,
                nested: None,
            };
        }

        // Buffer too small for the outer CK_ATTRIBUTE array
        if query.buffer_len < template_byte_len {
            *overall_rv = CkRv::BUFFER_TOO_SMALL;
            return CkAttributeQueryResult {
                attr_type: query.attr_type,
                returned_len: cryptoki_sys::CK_UNAVAILABLE_INFORMATION as u64,
                value: None,
                ck_rv: Some(CkRv::BUFFER_TOO_SMALL),
                nested: None,
            };
        }

        // Data query: build nested results from sub-slots paired with nested queries
        let nested_queries = query.nested.as_deref().unwrap_or(&[]);
        let mut nested_results = Vec::with_capacity(sub_slots.len());
        let mut has_sub_too_small = false;

        for (i, (sub_type, sub_slot)) in sub_slots.iter().enumerate() {
            let sub_query = nested_queries.get(i);
            let sub_buffer_present = sub_query.is_some_and(|q| q.buffer_present);
            let sub_buffer_len = sub_query.map_or(0, |q| q.buffer_len);

            match sub_slot {
                MockAttributeSlot::Value(value) => {
                    let bytes = Self::attribute_bytes(value);
                    let sub_len = bytes.len() as u64;
                    if !sub_buffer_present {
                        // Sub size query: pValue=NULL inside the nested template
                        nested_results.push(CkAttributeQueryResult {
                            attr_type: *sub_type,
                            returned_len: sub_len,
                            value: None,
                            ck_rv: None,
                            nested: None,
                        });
                    } else if sub_buffer_len < sub_len {
                        has_sub_too_small = true;
                        nested_results.push(CkAttributeQueryResult {
                            attr_type: *sub_type,
                            returned_len: cryptoki_sys::CK_UNAVAILABLE_INFORMATION as u64,
                            value: None,
                            ck_rv: Some(CkRv::BUFFER_TOO_SMALL),
                            nested: None,
                        });
                    } else {
                        nested_results.push(CkAttributeQueryResult {
                            attr_type: *sub_type,
                            returned_len: sub_len,
                            value: Some(bytes),
                            ck_rv: None,
                            nested: None,
                        });
                    }
                }
                _ => {
                    // Nested sub-attributes that are Sensitive/InvalidType/NestedTemplate
                    // are not expected in normal usage; treat as invalid type.
                    nested_results.push(CkAttributeQueryResult {
                        attr_type: *sub_type,
                        returned_len: cryptoki_sys::CK_UNAVAILABLE_INFORMATION as u64,
                        value: None,
                        ck_rv: Some(CkRv::ATTRIBUTE_TYPE_INVALID),
                        nested: None,
                    });
                }
            }
        }

        if has_sub_too_small {
            *overall_rv = CkRv::BUFFER_TOO_SMALL;
        }

        CkAttributeQueryResult {
            attr_type: query.attr_type,
            returned_len: template_byte_len,
            value: None,
            ck_rv: None,
            nested: Some(nested_results),
        }
    }

    pub(super) fn derive_key_impl(&self) -> CkResult<CkObjectHandle> {
        self.allocate_object_locked()
    }

    pub(super) fn wrap_key_impl(&self) -> CkResult<Vec<u8>> {
        Ok(super::crypto_ops::MOCK_WRAP_OUTPUT.to_vec())
    }

    pub(super) fn unwrap_key_impl(&self) -> CkResult<CkObjectHandle> {
        self.allocate_object_locked()
    }

    pub(super) fn generate_key_impl(&self) -> CkResult<CkObjectHandle> {
        self.check_injected()?;
        self.allocate_object_locked()
    }

    pub(super) fn create_object_impl(&self) -> CkResult<CkObjectHandle> {
        self.allocate_object_locked()
    }

    pub(super) fn copy_object_impl(&self) -> CkResult<CkObjectHandle> {
        self.allocate_object_locked()
    }

    pub(super) fn destroy_object_impl(&self, object: CkObjectHandle) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        if state.live_objects.remove(&object.0) { Ok(()) } else { Err(CkRv::OBJECT_HANDLE_INVALID) }
    }

    pub(super) fn object_size(&self, object: CkObjectHandle) -> CkResult<u64> {
        let state = self.state.lock().unwrap();
        self.require_live_object(&state, object)?;
        Ok(0)
    }

    pub(super) fn set_attribute_value_impl(&self, object: CkObjectHandle) -> CkResult<()> {
        let state = self.state.lock().unwrap();
        self.require_live_object(&state, object)
    }

    pub(super) fn generate_key_pair_impl(&self) -> CkResult<(CkObjectHandle, CkObjectHandle)> {
        self.check_injected()?;
        let mut state = self.state.lock().unwrap();
        let public = self.allocate_object(&mut state)?;
        let private = self.allocate_object(&mut state)?;
        Ok((public, private))
    }
}
