// CK_ULONG is u64 on 64-bit and u32 on 32-bit; the `as u64` casts are
// intentional for cross-platform PKCS#11 portability.
#![allow(clippy::unnecessary_cast)]

use pkcs11_proxy_ng_types::*;

use super::{MockAttributeSlot, MockBackend, MultiPartOp};

impl MockBackend {
    fn attribute_bytes(&self, value: &CkAttributeValue) -> Vec<u8> {
        match value {
            CkAttributeValue::Bool(flag) => {
                if *flag {
                    vec![1]
                } else {
                    vec![0]
                }
            }
            // Wire contract (ADR-0011): attribute value bytes carry the
            // backend's native CK_ULONG width — the width of the ABI this
            // mock EMULATES, not necessarily the host's.
            CkAttributeValue::Ulong(value) => self.abi().encode_ulong(*value),
            CkAttributeValue::Bytes(bytes) => bytes.expose(|raw| raw.to_vec()),
            CkAttributeValue::String(value) => value.expose(|raw| raw.to_vec()),
            // Unreachable by construction: store_object_template converts
            // nested-template VALUES into MockAttributeSlot::NestedTemplate,
            // which the exact path serves structurally. Serve the backend-
            // layout byte length equivalent defensively.
            CkAttributeValue::NestedTemplate(subs) => {
                vec![0; subs.len() * self.abi().attribute_stride()]
            }
        }
    }

    pub(super) fn find_objects_init_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        state.begin_op(session, MultiPartOp::FindObjects)?;
        // Reset the cursor so the next search starts from the beginning of the
        // configured override list.
        *self.find_objects_cursor.lock().unwrap() = 0;
        Ok(())
    }

    pub(super) fn find_objects_impl(
        &self,
        session: CkSessionHandle,
        max_count: u32,
    ) -> CkResult<Vec<CkObjectHandle>> {
        use std::sync::atomic::Ordering;
        self.find_objects_calls.fetch_add(1, Ordering::SeqCst);
        let state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        state.require_op(session, MultiPartOp::FindObjects)?;
        drop(state);

        // Return a cursor-based slice of the override list so each call advances
        // through the configured objects. Once all objects have been served, returns
        // an empty vec — the same signal a real backend sends at end-of-search.
        // `find_objects_init` resets the cursor to 0.
        //
        // Tests that configure a small `max_count` relative to the override list
        // length can observe multi-batch behaviour: batch1 → batch2 → [] exhausted.
        let overridden = self.find_objects_override.lock().unwrap().clone();
        if let Some(objects) = overridden {
            // W1-C11-04 harness: an installed gate can reject the most
            // recent init template (e.g. wrong CKA_CLASS), in which case
            // the search misses exactly like a real backend's would.
            if !self.find_template_gate_passes() {
                return Ok(vec![]);
            }
            let mut cursor = self.find_objects_cursor.lock().unwrap();
            let start = *cursor;
            let remaining = objects.len().saturating_sub(start);
            let take = (max_count as usize).min(remaining);
            let batch = objects[start..start + take].to_vec();
            *cursor = start + take;
            return Ok(batch);
        }
        Ok(vec![])
    }

    pub(super) fn find_objects_final_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        state.end_op(session, MultiPartOp::FindObjects)
    }

    pub(super) fn get_attribute_value_impl(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &mut [CkAttribute],
    ) -> CkResult<()> {
        use std::sync::atomic::Ordering;
        self.attr_get_calls.fetch_add(1, Ordering::SeqCst);
        let state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        self.require_live_object(&state, object)?;
        drop(state);

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
        session: CkSessionHandle,
        object: CkObjectHandle,
        queries: &[CkAttributeQuery],
    ) -> CkResult<(CkRv, Vec<CkAttributeQueryResult>)> {
        use std::sync::atomic::Ordering;
        self.attr_get_exact_calls.fetch_add(1, Ordering::SeqCst);
        if !self.state.lock().unwrap().has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        let store = self.attribute_store.lock().unwrap();
        let Some(obj_map) = store.get(&object.0) else {
            return Err(CkRv::OBJECT_HANDLE_INVALID);
        };

        let mut overall_rv = CkRv::OK;
        let results = queries
            .iter()
            .map(|query| match obj_map.get(&query.attr_type.0) {
                Some(MockAttributeSlot::Value(value)) => {
                    let bytes = self.attribute_bytes(value);
                    let returned_len = bytes.len() as u64;
                    if !query.buffer_present {
                        CkAttributeQueryResult {
                            apply_returned_len: true,
                            apply_type: false,
                            attr_type: query.attr_type,
                            returned_len,
                            value: None,
                            ck_rv: None,
                            nested: None,
                        }
                    } else if query.buffer_len < returned_len {
                        overall_rv = CkRv::BUFFER_TOO_SMALL;
                        CkAttributeQueryResult {
                            apply_returned_len: true,
                            apply_type: false,
                            attr_type: query.attr_type,
                            returned_len: u64::MAX,
                            value: None,
                            ck_rv: Some(CkRv::BUFFER_TOO_SMALL),
                            nested: None,
                        }
                    } else {
                        CkAttributeQueryResult {
                            apply_returned_len: true,
                            apply_type: false,
                            attr_type: query.attr_type,
                            returned_len,
                            value: Some(bytes.into()),
                            ck_rv: None,
                            nested: None,
                        }
                    }
                }
                Some(MockAttributeSlot::NestedTemplate(sub_slots)) => {
                    self.nested_template_result(query, sub_slots, &mut overall_rv)
                }
                Some(MockAttributeSlot::Sensitive) => {
                    if overall_rv == CkRv::OK {
                        overall_rv = CkRv::ATTRIBUTE_SENSITIVE;
                    }
                    CkAttributeQueryResult {
                        apply_returned_len: true,
                        apply_type: false,
                        attr_type: query.attr_type,
                        returned_len: u64::MAX,
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
                        apply_returned_len: true,
                        apply_type: false,
                        attr_type: query.attr_type,
                        returned_len: u64::MAX,
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
        &self,
        query: &CkAttributeQuery,
        sub_slots: &[(CkAttributeType, MockAttributeSlot)],
        overall_rv: &mut CkRv,
    ) -> CkAttributeQueryResult {
        // Backend-layout template size: the emulated ABI's CK_ATTRIBUTE stride.
        let template_byte_len = (sub_slots.len() * self.abi().attribute_stride()) as u64;

        // Size query: caller passes pValue=NULL
        if !query.buffer_present {
            return CkAttributeQueryResult {
                apply_returned_len: true,
                apply_type: false,
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
                apply_returned_len: true,
                apply_type: false,
                attr_type: query.attr_type,
                returned_len: u64::MAX,
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
                    let bytes = self.attribute_bytes(value);
                    let sub_len = bytes.len() as u64;
                    if !sub_buffer_present {
                        // Sub size query: pValue=NULL inside the nested template
                        nested_results.push(CkAttributeQueryResult {
                            apply_returned_len: true,
                            apply_type: true,
                            attr_type: *sub_type,
                            returned_len: sub_len,
                            value: None,
                            ck_rv: None,
                            nested: None,
                        });
                    } else if sub_buffer_len < sub_len {
                        has_sub_too_small = true;
                        nested_results.push(CkAttributeQueryResult {
                            apply_returned_len: true,
                            apply_type: true,
                            attr_type: *sub_type,
                            returned_len: u64::MAX,
                            value: None,
                            ck_rv: Some(CkRv::BUFFER_TOO_SMALL),
                            nested: None,
                        });
                    } else {
                        nested_results.push(CkAttributeQueryResult {
                            apply_returned_len: true,
                            apply_type: true,
                            attr_type: *sub_type,
                            returned_len: sub_len,
                            value: Some(bytes.into()),
                            ck_rv: None,
                            nested: None,
                        });
                    }
                }
                _ => {
                    // Nested sub-attributes that are Sensitive/InvalidType/NestedTemplate
                    // are not expected in normal usage; treat as invalid type.
                    nested_results.push(CkAttributeQueryResult {
                        apply_returned_len: true,
                        apply_type: true,
                        attr_type: *sub_type,
                        returned_len: u64::MAX,
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
            apply_returned_len: true,
            apply_type: false,
            attr_type: query.attr_type,
            returned_len: template_byte_len,
            value: None,
            ck_rv: None,
            nested: Some(nested_results),
        }
    }

    pub(super) fn derive_key_impl(
        &self,
        session: CkSessionHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let mut state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        self.allocate_session_object_with_template(&mut state, session, template)
    }

    pub(super) fn wrap_key_impl(&self) -> CkResult<SecretBytes> {
        Ok(super::crypto_ops::MOCK_WRAP_OUTPUT.to_vec().into())
    }

    pub(super) fn unwrap_key_impl(
        &self,
        session: CkSessionHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let mut state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        self.allocate_session_object_with_template(&mut state, session, template)
    }

    pub(super) fn generate_key_impl(
        &self,
        session: CkSessionHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.check_injected()?;
        let mut state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        self.allocate_session_object_with_template(&mut state, session, template)
    }

    pub(super) fn create_object_impl(
        &self,
        session: CkSessionHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let mut state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        self.allocate_session_object_with_template(&mut state, session, template)
    }

    pub(super) fn copy_object_impl(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let mut state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        self.require_live_object(&state, object)?;
        self.allocate_session_object_with_template(&mut state, session, template)
    }

    pub(super) fn destroy_object_impl(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        if state.live_objects.contains(&object.0) {
            self.remove_objects(&mut state, &[object.0]);
            Ok(())
        } else {
            Err(CkRv::OBJECT_HANDLE_INVALID)
        }
    }

    pub(super) fn object_size(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> CkResult<u64> {
        let state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        self.require_live_object(&state, object)?;
        Ok(0)
    }

    pub(super) fn set_attribute_value_impl(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> CkResult<()> {
        let state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        self.require_live_object(&state, object)
    }

    pub(super) fn generate_key_pair_impl(
        &self,
        session: CkSessionHandle,
        public_template: &[CkAttribute],
        private_template: &[CkAttribute],
    ) -> CkResult<(CkObjectHandle, CkObjectHandle)> {
        self.check_injected()?;
        let mut state = self.state.lock().unwrap();
        if !state.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        if self.max_objects > 0 && state.live_objects.len() as u64 + 2 > self.max_objects {
            return Err(CkRv::DEVICE_MEMORY);
        }
        let public =
            self.allocate_session_object_with_template(&mut state, session, public_template)?;
        let private =
            self.allocate_session_object_with_template(&mut state, session, private_template)?;
        Ok((public, private))
    }
}
