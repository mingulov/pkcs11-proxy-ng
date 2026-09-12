//! Attribute materialization at the FFI edge: owned CK_ATTRIBUTE
//! arrays for input templates (incl. structural nested templates,
//! ADR-0011 D8/D4) and exact-query buffers.

use super::*;

pub(in crate::ffi) struct FfiAttrs {
    /// The ready-to-pass attribute array. Pointers inside borrow from the original
    /// `CkAttribute` slice or from `_backing`/`_nested_backing`.
    pub(in crate::ffi) attrs: Vec<cryptoki_sys::CK_ATTRIBUTE>,
    /// Backing byte storage for `Ulong` values whose native size differs from `u64`.
    _backing: Vec<Vec<u8>>,
    /// Backing storage for nested `CK_ATTRIBUTE[]` template VALUES (the
    /// input direction of CKF_ARRAY_ATTRIBUTE attributes): each entry pins
    /// a native sub-attribute array plus its sub-value buffers.
    _nested_backing: Vec<NestedTemplateBacking>,
}

impl FfiAttrs {
    /// `None` values produce a null `pValue` / zero `ulValueLen` (size-query pattern).
    /// `Ulong` values are converted to the correct platform-native `CK_ULONG` width;
    /// a value the native width cannot hold is rejected (D4), never truncated.
    pub(in crate::ffi) fn from_slice(template: &[CkAttribute]) -> CkResult<Self> {
        let mut attrs = Vec::with_capacity(template.len());
        let mut backing: Vec<Vec<u8>> = Vec::new();
        let mut nested_backing: Vec<NestedTemplateBacking> = Vec::new();

        for attr in template {
            let (pvalue, len): (*mut _, cryptoki_sys::CK_ULONG) = match &attr.value {
                None => (std::ptr::null_mut(), 0),
                Some(CkAttributeValue::Bool(b)) => {
                    static TRUE_BYTE: u8 = 1;
                    static FALSE_BYTE: u8 = 0;
                    let ptr = if *b { &TRUE_BYTE as *const u8 } else { &FALSE_BYTE as *const u8 };
                    (ptr as *mut _, 1)
                }
                Some(CkAttributeValue::Ulong(u)) => {
                    let bytes = narrow_wire_ulong(*u)?.to_ne_bytes().to_vec();
                    let len = bytes.len() as cryptoki_sys::CK_ULONG;
                    let ptr = bytes.as_ptr() as *mut _;
                    backing.push(bytes);
                    (ptr, len)
                }
                Some(CkAttributeValue::Bytes(b)) => {
                    (b.as_ptr() as *mut _, b.len() as cryptoki_sys::CK_ULONG)
                }
                Some(CkAttributeValue::String(s)) => {
                    (s.as_ptr() as *mut _, s.len() as cryptoki_sys::CK_ULONG)
                }
                Some(CkAttributeValue::NestedTemplate(subs)) => {
                    // Rebuild a native CK_ATTRIBUTE[] the backend can walk:
                    // the wire carries the template STRUCTURALLY (client
                    // struct bytes never cross — their pointers are
                    // meaningless in this address space). Sub-values follow
                    // the same materialization rules as top-level ones
                    // (native ulong width, checked narrowing per D4).
                    let backing_entry = Self::materialize_nested_template(subs)?;
                    let ptr = backing_entry.template_ptr();
                    let byte_len = (subs.len() * std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>())
                        as cryptoki_sys::CK_ULONG;
                    nested_backing.push(backing_entry);
                    (ptr as *mut _, byte_len)
                }
            };
            attrs.push(cryptoki_sys::CK_ATTRIBUTE {
                type_: narrow_wire_ulong(attr.attr_type.0)?,
                pValue: pvalue,
                ulValueLen: len,
            });
        }

        Ok(Self { attrs, _backing: backing, _nested_backing: nested_backing })
    }
}

/// Backing storage for a single nested `CK_ATTRIBUTE[]` template.
///
/// The boxed slice is pinned at a stable heap address so that the parent
/// attribute's `pValue` pointer remains valid through the FFI call.
/// Sub-buffers hold the `pValue` data for each nested attribute.
struct NestedTemplateBacking {
    /// The nested `CK_ATTRIBUTE` array at a stable heap address.
    _template: std::pin::Pin<Box<[cryptoki_sys::CK_ATTRIBUTE]>>,
    /// Sub-buffers for each nested attribute's `pValue`.
    _sub_buffers: Vec<Vec<u8>>,
}

impl NestedTemplateBacking {
    /// Stable address of the pinned native sub-attribute array.
    fn template_ptr(&self) -> *const cryptoki_sys::CK_ATTRIBUTE {
        self._template.as_ptr()
    }
}

impl FfiAttrs {
    /// Build the pinned native `CK_ATTRIBUTE[]` for a nested template VALUE.
    fn materialize_nested_template(subs: &[CkAttribute]) -> CkResult<NestedTemplateBacking> {
        let mut sub_buffers: Vec<Vec<u8>> = Vec::with_capacity(subs.len());
        let mut native: Vec<cryptoki_sys::CK_ATTRIBUTE> = Vec::with_capacity(subs.len());
        for sub in subs {
            let bytes: Vec<u8> = match &sub.value {
                None => Vec::new(),
                Some(CkAttributeValue::Bool(b)) => vec![u8::from(*b)],
                Some(CkAttributeValue::Ulong(u)) => narrow_wire_ulong(*u)?.to_ne_bytes().to_vec(),
                Some(CkAttributeValue::Bytes(b)) => b.clone(),
                Some(CkAttributeValue::String(s)) => s.as_bytes().to_vec(),
                // D8: refused at the deserialization edge; defensively
                // reject here too rather than recurse.
                Some(CkAttributeValue::NestedTemplate(_)) => {
                    return Err(CkRv::ATTRIBUTE_VALUE_INVALID);
                }
            };
            sub_buffers.push(bytes);
            let stored = sub_buffers.last().expect("just pushed");
            native.push(cryptoki_sys::CK_ATTRIBUTE {
                type_: narrow_wire_ulong(sub.attr_type.0)?,
                pValue: if stored.is_empty() {
                    std::ptr::null_mut()
                } else {
                    stored.as_ptr() as *mut std::ffi::c_void
                },
                ulValueLen: stored.len() as cryptoki_sys::CK_ULONG,
            });
        }
        Ok(NestedTemplateBacking {
            _template: std::pin::Pin::new(native.into_boxed_slice()),
            _sub_buffers: sub_buffers,
        })
    }
}

/// Owns raw `CK_ATTRIBUTE` buffers for exact `C_GetAttributeValue` semantics.
///
/// For attributes with `CKF_ARRAY_ATTRIBUTE`, stores additional nested template
/// arrays and their sub-buffers. Pointer stability is ensured by using pinned
/// `Box<[CK_ATTRIBUTE]>` for nested templates and pre-allocated `Vec<u8>` for
/// all byte buffers.
pub(in crate::ffi) struct FfiAttributeQueries {
    pub(in crate::ffi) attrs: Vec<cryptoki_sys::CK_ATTRIBUTE>,
    _buffers: Vec<Vec<u8>>,
    _nested: Vec<NestedTemplateBacking>,
}

impl FfiAttributeQueries {
    pub(in crate::ffi) fn from_queries(queries: &[CkAttributeQuery]) -> CkResult<Self> {
        let mut attrs = Vec::with_capacity(queries.len());
        let mut buffers = Vec::new();
        let mut nested_backings = Vec::new();

        for query in queries {
            if let Some(nested_queries) = &query.nested {
                // CKF_ARRAY_ATTRIBUTE: allocate a nested CK_ATTRIBUTE[] template
                Self::build_nested_attr(query, nested_queries, &mut attrs, &mut nested_backings)?;
            } else {
                // Flat attribute: allocate a simple byte buffer
                let ul_value_len = cryptoki_sys::CK_ULONG::try_from(query.buffer_len)
                    .map_err(|_| CkRv::HOST_MEMORY)?;
                let (pvalue, len) = if query.buffer_present {
                    let buffer_len =
                        usize::try_from(query.buffer_len).map_err(|_| CkRv::HOST_MEMORY)?;
                    let mut buffer = Vec::new();
                    buffer.try_reserve_exact(buffer_len).map_err(|_| CkRv::HOST_MEMORY)?;
                    buffer.resize(buffer_len, 0);
                    let ptr = buffer.as_mut_ptr() as *mut std::ffi::c_void;
                    buffers.push(buffer);
                    (ptr, ul_value_len)
                } else {
                    (std::ptr::null_mut(), ul_value_len)
                };

                attrs.push(cryptoki_sys::CK_ATTRIBUTE {
                    type_: narrow_wire_ulong(query.attr_type.0)?,
                    pValue: pvalue,
                    ulValueLen: len,
                });
            }
        }

        Ok(Self { attrs, _buffers: buffers, _nested: nested_backings })
    }

    /// Build a `CK_ATTRIBUTE` entry for a nested template attribute.
    ///
    /// Allocates a pinned `CK_ATTRIBUTE[]` array for the sub-template and
    /// byte buffers for each sub-attribute's `pValue`. The parent attribute's
    /// `pValue` points to the nested array and `ulValueLen` is set to
    /// `count * size_of::<CK_ATTRIBUTE>()`.
    fn build_nested_attr(
        query: &CkAttributeQuery,
        nested_queries: &[CkAttributeQuery],
        attrs: &mut Vec<cryptoki_sys::CK_ATTRIBUTE>,
        nested_backings: &mut Vec<NestedTemplateBacking>,
    ) -> CkResult<()> {
        if !query.buffer_present || nested_queries.is_empty() {
            // Size query or empty nested: pValue=NULL, ulValueLen carries the
            // requested/expected length.
            let ul_value_len = cryptoki_sys::CK_ULONG::try_from(query.buffer_len)
                .map_err(|_| CkRv::HOST_MEMORY)?;
            attrs.push(cryptoki_sys::CK_ATTRIBUTE {
                type_: narrow_wire_ulong(query.attr_type.0)?,
                pValue: std::ptr::null_mut(),
                ulValueLen: ul_value_len,
            });
            return Ok(());
        }

        // Allocate sub-buffers first, collecting stable pointers
        let mut sub_buffers: Vec<Vec<u8>> = Vec::with_capacity(nested_queries.len());
        let mut sub_attrs: Vec<cryptoki_sys::CK_ATTRIBUTE> =
            Vec::with_capacity(nested_queries.len());

        for sub_query in nested_queries {
            let sub_ul_value_len = cryptoki_sys::CK_ULONG::try_from(sub_query.buffer_len)
                .map_err(|_| CkRv::HOST_MEMORY)?;

            let (sub_pvalue, sub_len) = if sub_query.buffer_present {
                let sub_buf_len =
                    usize::try_from(sub_query.buffer_len).map_err(|_| CkRv::HOST_MEMORY)?;
                let mut sub_buf = Vec::new();
                sub_buf.try_reserve_exact(sub_buf_len).map_err(|_| CkRv::HOST_MEMORY)?;
                sub_buf.resize(sub_buf_len, 0);
                let ptr = sub_buf.as_mut_ptr() as *mut std::ffi::c_void;
                sub_buffers.push(sub_buf);
                (ptr, sub_ul_value_len)
            } else {
                (std::ptr::null_mut(), sub_ul_value_len)
            };

            sub_attrs.push(cryptoki_sys::CK_ATTRIBUTE {
                type_: narrow_wire_ulong(sub_query.attr_type.0)?,
                pValue: sub_pvalue,
                ulValueLen: sub_len,
            });
        }

        // Pin the sub-attribute array at a stable heap address.
        // We must create the pinned box from the completed array so no
        // further mutations move it.
        let mut template_box: std::pin::Pin<Box<[cryptoki_sys::CK_ATTRIBUTE]>> =
            sub_attrs.into_boxed_slice().into();

        // The parent attribute points into the pinned template.
        let template_ptr = template_box.as_mut_ptr() as *mut std::ffi::c_void;
        let template_byte_len = (template_box.len()
            * std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>())
            as cryptoki_sys::CK_ULONG;

        attrs.push(cryptoki_sys::CK_ATTRIBUTE {
            type_: narrow_wire_ulong(query.attr_type.0)?,
            pValue: template_ptr,
            ulValueLen: template_byte_len,
        });

        nested_backings
            .push(NestedTemplateBacking { _template: template_box, _sub_buffers: sub_buffers });

        Ok(())
    }
}

#[cfg(test)]
mod ffi_attrs_narrowing_tests {
    use pkcs11_proxy_ng_types::{CkAttribute, CkAttributeType, CkAttributeValue, CkRv};

    use super::FfiAttrs;

    fn ulong_template(value: u64) -> [CkAttribute; 1] {
        [CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(value)),
        }]
    }

    fn materialized_ulong(attrs: &FfiAttrs) -> cryptoki_sys::CK_ULONG {
        let attr = &attrs.attrs[0];
        assert_eq!(attr.ulValueLen as usize, std::mem::size_of::<cryptoki_sys::CK_ULONG>());
        let mut bytes = [0u8; std::mem::size_of::<cryptoki_sys::CK_ULONG>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                attr.pValue as *const u8,
                bytes.as_mut_ptr(),
                bytes.len(),
            );
        }
        cryptoki_sys::CK_ULONG::from_ne_bytes(bytes)
    }

    #[test]
    fn ulong_attribute_materializes_at_native_width_value_preserving() {
        let template = ulong_template(1);
        let attrs = FfiAttrs::from_slice(&template).expect("in-range value converts");
        assert_eq!(materialized_ulong(&attrs), 1);
    }

    #[test]
    fn nested_template_value_materializes_native_ck_attribute_array() {
        // Input direction of CKA_*_TEMPLATE: the wire carries a STRUCTURAL
        // template (never raw client struct bytes); the FFI edge rebuilds a
        // native CK_ATTRIBUTE[] the backend can dereference safely.
        let template = [CkAttribute {
            attr_type: CkAttributeType::WRAP_TEMPLATE,
            value: Some(CkAttributeValue::NestedTemplate(vec![
                CkAttribute {
                    attr_type: CkAttributeType::CLASS,
                    value: Some(CkAttributeValue::Ulong(4)),
                },
                CkAttribute {
                    attr_type: CkAttributeType::EXTRACTABLE,
                    value: Some(CkAttributeValue::Bool(true)),
                },
            ])),
        }];
        let attrs = FfiAttrs::from_slice(&template).expect("nested template converts");
        let outer = &attrs.attrs[0];
        assert_eq!(
            outer.ulValueLen as usize,
            2 * std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>(),
            "outer length is the native template byte length"
        );
        let subs = unsafe {
            std::slice::from_raw_parts(outer.pValue as *const cryptoki_sys::CK_ATTRIBUTE, 2)
        };
        assert_eq!(subs[0].type_ as u64, CkAttributeType::CLASS.0);
        assert_eq!(subs[0].ulValueLen as usize, std::mem::size_of::<cryptoki_sys::CK_ULONG>());
        let mut class_bytes = [0u8; std::mem::size_of::<cryptoki_sys::CK_ULONG>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                subs[0].pValue as *const u8,
                class_bytes.as_mut_ptr(),
                class_bytes.len(),
            );
        }
        assert_eq!(cryptoki_sys::CK_ULONG::from_ne_bytes(class_bytes), 4);
        assert_eq!(subs[1].type_ as u64, CkAttributeType::EXTRACTABLE.0);
        assert_eq!(subs[1].ulValueLen, 1);
        assert_eq!(unsafe { *(subs[1].pValue as *const u8) }, 1);
    }

    #[test]
    fn nested_template_ulong_sub_value_wider_than_native_is_rejected() {
        // D4 applies to nested sub-values too.
        let template = [CkAttribute {
            attr_type: CkAttributeType::WRAP_TEMPLATE,
            value: Some(CkAttributeValue::NestedTemplate(vec![CkAttribute {
                attr_type: CkAttributeType::CLASS,
                value: Some(CkAttributeValue::Ulong(0x1_0000_0001)),
            }])),
        }];
        match FfiAttrs::from_slice(&template) {
            Ok(_) => assert_eq!(std::mem::size_of::<cryptoki_sys::CK_ULONG>(), 8),
            Err(rv) => {
                assert_eq!(std::mem::size_of::<cryptoki_sys::CK_ULONG>(), 4);
                assert_eq!(rv, CkRv::FUNCTION_FAILED);
            }
        }
    }

    #[test]
    fn attribute_type_wider_than_native_is_rejected_not_truncated() {
        // 0x1_0000_0000 | CKA_CLASS truncates to CKA_CLASS on a narrow
        // host - the template would silently address a DIFFERENT
        // attribute than the client named. Reject instead.
        let template = [CkAttribute {
            attr_type: CkAttributeType(0x1_0000_0000),
            value: Some(CkAttributeValue::Bytes(vec![1])),
        }];
        match FfiAttrs::from_slice(&template) {
            Ok(attrs) => {
                assert_eq!(std::mem::size_of::<cryptoki_sys::CK_ULONG>(), 8);
                assert_eq!(attrs.attrs[0].type_ as u64, 0x1_0000_0000);
            }
            Err(rv) => {
                assert_eq!(std::mem::size_of::<cryptoki_sys::CK_ULONG>(), 4);
                assert_eq!(rv, CkRv::FUNCTION_FAILED);
            }
        }
    }

    #[test]
    fn ulong_attribute_wider_than_native_is_rejected_not_truncated() {
        // Low word is 1: silent truncation would fabricate a plausible
        // small value. D4 (ADR-0011): value-preserving or a loud reject.
        let template = ulong_template(0x1_0000_0001);
        match FfiAttrs::from_slice(&template) {
            Ok(attrs) => {
                assert_eq!(
                    std::mem::size_of::<cryptoki_sys::CK_ULONG>(),
                    8,
                    "narrow CK_ULONG host must not accept a value > u32::MAX"
                );
                assert_eq!(materialized_ulong(&attrs) as u64, 0x1_0000_0001);
            }
            Err(rv) => {
                assert_eq!(std::mem::size_of::<cryptoki_sys::CK_ULONG>(), 4);
                assert_eq!(rv, CkRv::FUNCTION_FAILED);
            }
        }
    }
}
