//! Attribute materialization at the FFI edge: owned CK_ATTRIBUTE
//! arrays for input templates (incl. structural nested templates,
//! ADR-0011 D8/D4) and exact-query buffers.

use super::*;

pub(in crate::ffi) struct FfiAttrs {
    /// The ready-to-pass attribute array. Pointers inside borrow from
    /// `_backing`/`_secret_backing`/`_nested_backing` (all owned by `self`).
    pub(in crate::ffi) attrs: Vec<cryptoki_sys::CK_ATTRIBUTE>,
    /// Backing byte storage for `Ulong` values whose native size differs from `u64`.
    _backing: Vec<Vec<u8>>,
    /// Wiping backing for `Bytes`/`String` values (ADR-0013 §5). The
    /// `SecretBytes` source cannot serve a stored raw pointer
    /// (closure-scoped access), so each value is copied once into a
    /// `Zeroizing` buffer that is wiped when this owner drops. The source
    /// `SecretBytes` is unaffected and wipes on its own drop.
    _secret_backing: Vec<Zeroizing<Vec<u8>>>,
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
        let mut secret_backing: Vec<Zeroizing<Vec<u8>>> = Vec::new();
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
                // T4-AUDIT site 4: pass NULL for empty values. An empty
                // slice's `as_ptr()` is a dangling non-null pointer; the
                // same NULL+0 encoding `None` uses (and nested sub-values
                // use below) is the backend-safe empty shape.
                Some(CkAttributeValue::Bytes(b)) => Self::push_secret_value(&mut secret_backing, b),
                Some(CkAttributeValue::String(s)) => {
                    Self::push_secret_value(&mut secret_backing, s)
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

        Ok(Self {
            attrs,
            _backing: backing,
            _secret_backing: secret_backing,
            _nested_backing: nested_backing,
        })
    }

    /// Copies a secret attribute value into owned wiping backing and returns
    /// the `(pValue, ulValueLen)` pair, preserving the T4-AUDIT NULL+0 empty
    /// encoding. Pushing to `backing` moves only `Vec` headers; previously
    /// captured heap pointers stay valid.
    fn push_secret_value(
        backing: &mut Vec<Zeroizing<Vec<u8>>>,
        value: &SecretBytes,
    ) -> (*mut std::ffi::c_void, cryptoki_sys::CK_ULONG) {
        if value.is_empty() {
            return (std::ptr::null_mut(), 0);
        }
        let owned = value.expose(|bytes| Zeroizing::new(bytes.to_vec()));
        let len = owned.len() as cryptoki_sys::CK_ULONG;
        let ptr = owned.as_ptr() as *mut _;
        backing.push(owned);
        (ptr, len)
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
    /// Sub-buffers for each nested attribute's `pValue`. Wiping (ADR-0013
    /// §5): sub-values may carry secret key material.
    _sub_buffers: Vec<Zeroizing<Vec<u8>>>,
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
        let mut sub_buffers: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(subs.len());
        let mut native: Vec<cryptoki_sys::CK_ATTRIBUTE> = Vec::with_capacity(subs.len());
        for sub in subs {
            let bytes: Zeroizing<Vec<u8>> = match &sub.value {
                None => Zeroizing::new(Vec::new()),
                Some(CkAttributeValue::Bool(b)) => Zeroizing::new(vec![u8::from(*b)]),
                Some(CkAttributeValue::Ulong(u)) => {
                    Zeroizing::new(narrow_wire_ulong(*u)?.to_ne_bytes().to_vec())
                }
                Some(CkAttributeValue::Bytes(b)) => b.expose(|raw| Zeroizing::new(raw.to_vec())),
                Some(CkAttributeValue::String(s)) => s.expose(|raw| Zeroizing::new(raw.to_vec())),
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
    original: Vec<cryptoki_sys::CK_ATTRIBUTE>,
    nested_originals: Vec<Vec<cryptoki_sys::CK_ATTRIBUTE>>,
    /// Provider-written output buffers. Wiping (ADR-0013 §5): the provider
    /// may write key material here; leftovers are wiped on drop.
    _buffers: Vec<Zeroizing<Vec<u8>>>,
    _nested: Vec<NestedTemplateBacking>,
}

impl FfiAttributeQueries {
    pub(in crate::ffi) fn from_queries(queries: &[CkAttributeQuery]) -> CkResult<Self> {
        let mut attrs = Vec::with_capacity(queries.len());
        let mut buffers = Vec::new();
        let mut nested_backings = Vec::new();

        for query in queries {
            if query.buffer_present
                && query.buffer_len > super::super::call_helpers::MAX_OUTPUT_BUFFER_BYTES
            {
                return Err(CkRv::HOST_MEMORY);
            }
            if let Some(nested_queries) = &query.nested {
                if !query.attr_type.is_attribute_template()
                    || nested_queries.iter().any(|sub| sub.nested.is_some())
                {
                    return Err(CkRv::ARGUMENTS_BAD);
                }
                // CKF_ARRAY_ATTRIBUTE: allocate a nested CK_ATTRIBUTE[] template
                Self::build_nested_attr(query, nested_queries, &mut attrs, &mut nested_backings)?;
            } else {
                // Flat attribute: allocate a simple byte buffer
                let ul_value_len = cryptoki_sys::CK_ULONG::try_from(query.buffer_len)
                    .map_err(|_| CkRv::HOST_MEMORY)?;
                let (pvalue, len) = if query.buffer_present {
                    let buffer_len =
                        usize::try_from(query.buffer_len).map_err(|_| CkRv::HOST_MEMORY)?;
                    let mut buffer = Zeroizing::new(Vec::new());
                    buffer.try_reserve_exact(buffer_len).map_err(|_| CkRv::HOST_MEMORY)?;
                    buffer.resize(buffer_len, 0);
                    // T4-FIX: pass NULL for 0-length buffers. An empty Vec's
                    // `as_mut_ptr()` is a dangling non-null pointer (0x1);
                    // backends that null-check pValue and then write
                    // regardless of length (NSS softokn) segfault on it.
                    let ptr = if buffer.is_empty() {
                        std::ptr::null_mut()
                    } else {
                        buffer.as_mut_ptr() as *mut std::ffi::c_void
                    };
                    buffers.push(buffer);
                    (ptr, ul_value_len)
                } else {
                    (std::ptr::null_mut(), 0)
                };

                attrs.push(cryptoki_sys::CK_ATTRIBUTE {
                    type_: narrow_wire_ulong(query.attr_type.0)?,
                    pValue: pvalue,
                    ulValueLen: len,
                });
            }
        }

        let original = attrs.clone();
        let nested_originals = nested_backings.iter().map(|b| b._template.to_vec()).collect();
        Ok(Self { attrs, original, nested_originals, _buffers: buffers, _nested: nested_backings })
    }

    /// Read only immutable allocation owners, never provider-replaced pointers.
    /// An oversized scalar remains an effect but cannot enlarge an owned slice.
    pub(in crate::ffi) fn readback(
        &self,
        queries: &[CkAttributeQuery],
        rv: CkRv,
    ) -> Vec<CkAttributeQueryResult> {
        let mut results =
            super::super::mapping::exact_attribute_results_from_ffi(queries, &self.attrs, rv);
        let values_defined = pkcs11_proxy_ng_types::attribute_outputs_defined(rv);
        for (((query, native), original), result) in
            queries.iter().zip(&self.attrs).zip(&self.original).zip(&mut results)
        {
            if native.pValue != original.pValue || native.pValue.is_null() {
                continue;
            }
            if let Some(nested_queries) = &query.nested {
                let Some((index, backing)) = self._nested.iter().enumerate().find(|(_, b)| {
                    b._template.as_ptr().cast::<std::ffi::c_void>() == original.pValue
                }) else {
                    continue;
                };
                let stride = std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>();
                let Ok(length) = usize::try_from(result.returned_len) else {
                    continue;
                };
                if length > backing._template.len() * stride || length % stride != 0 {
                    continue;
                }
                let count = length / stride;
                let mut nested = super::super::mapping::exact_attribute_results_from_ffi(
                    &nested_queries[..count.min(nested_queries.len())],
                    &backing._template[..count],
                    rv,
                );
                for (((sub, old), out), query) in backing
                    ._template
                    .iter()
                    .zip(&self.nested_originals[index])
                    .zip(&mut nested)
                    .zip(nested_queries)
                {
                    // Nested type is output-bearing only when attribute results are defined.
                    out.attr_type = if values_defined {
                        CkAttributeType(sub.type_ as u64)
                    } else {
                        CkAttributeType(0)
                    };
                    out.apply_type = values_defined;
                    if values_defined
                        && !out.attr_type.is_attribute_template()
                        && sub.pValue == old.pValue
                        && query.buffer_present
                    {
                        out.value = owned_attribute_bytes(
                            &backing._sub_buffers,
                            old.pValue,
                            out.returned_len,
                        );
                    }
                }
                result.nested = Some(nested);
            } else if values_defined && query.buffer_present {
                result.value =
                    owned_attribute_bytes(&self._buffers, original.pValue, result.returned_len);
            }
        }
        results
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
        if !query.buffer_present {
            // Size query or empty nested: pValue=NULL, ulValueLen carries the
            // requested/expected length.
            attrs.push(cryptoki_sys::CK_ATTRIBUTE {
                type_: narrow_wire_ulong(query.attr_type.0)?,
                pValue: std::ptr::null_mut(),
                ulValueLen: 0,
            });
            return Ok(());
        }

        let native_len = nested_queries
            .len()
            .checked_mul(std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>())
            .ok_or(CkRv::HOST_MEMORY)?;
        if query.buffer_len != native_len as u64 {
            return Err(CkRv::ARGUMENTS_BAD);
        }

        // Allocate sub-buffers first, collecting stable pointers
        let mut sub_buffers: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(nested_queries.len());
        let mut sub_attrs: Vec<cryptoki_sys::CK_ATTRIBUTE> =
            Vec::with_capacity(nested_queries.len());

        for sub_query in nested_queries {
            if sub_query.buffer_present
                && sub_query.buffer_len > super::super::call_helpers::MAX_OUTPUT_BUFFER_BYTES
            {
                return Err(CkRv::HOST_MEMORY);
            }
            let sub_ul_value_len = cryptoki_sys::CK_ULONG::try_from(sub_query.buffer_len)
                .map_err(|_| CkRv::HOST_MEMORY)?;

            let (sub_pvalue, sub_len) = if sub_query.buffer_present {
                let sub_buf_len =
                    usize::try_from(sub_query.buffer_len).map_err(|_| CkRv::HOST_MEMORY)?;
                let mut sub_buf = Zeroizing::new(Vec::new());
                sub_buf.try_reserve_exact(sub_buf_len).map_err(|_| CkRv::HOST_MEMORY)?;
                sub_buf.resize(sub_buf_len, 0);
                // T4-AUDIT site 2: NULL for 0-length sub buffers (same
                // T4-FIX shape as the flat arm: dangling non-null + 0
                // segfaults null-check-then-write backends).
                let ptr = if sub_buf.is_empty() {
                    std::ptr::null_mut()
                } else {
                    sub_buf.as_mut_ptr() as *mut std::ffi::c_void
                };
                sub_buffers.push(sub_buf);
                (ptr, sub_ul_value_len)
            } else {
                (std::ptr::null_mut(), 0)
            };

            sub_attrs.push(cryptoki_sys::CK_ATTRIBUTE {
                // F7/D5: forward the caller-preset nested query type
                // verbatim. Backends such as SoftHSM select the sub-query
                // by it; forcing 0 rewrites the caller's query.
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
        // T4-AUDIT site 5: NULL for a degenerate empty template box
        // (`nested=Some(vec![])` + `buffer_len==0`); an empty box slice's
        // `as_mut_ptr()` is dangling non-null with length 0.
        let template_ptr = if template_box.is_empty() {
            std::ptr::null_mut()
        } else {
            template_box.as_mut_ptr() as *mut std::ffi::c_void
        };
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

fn owned_attribute_bytes(
    buffers: &[Zeroizing<Vec<u8>>],
    pointer: *mut std::ffi::c_void,
    length: u64,
) -> Option<SecretBytes> {
    let length = usize::try_from(length).ok()?;
    let buffer = buffers.iter().find(|buffer| {
        !pointer.is_null() && buffer.as_ptr().cast::<std::ffi::c_void>() == pointer
    })?;
    buffer.get(..length).map(SecretBytes::copy_from_slice)
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
        // E0793: CK_ATTRIBUTE is packed on Windows; assert on a by-value copy.
        let ul_value_len = subs[1].ulValueLen;
        assert_eq!(ul_value_len, 1);
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
            value: Some(CkAttributeValue::Bytes(vec![1].into())),
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
    fn empty_bytes_value_materializes_null_pvalue() {
        // T4-AUDIT site 4: `Some(Bytes(vec![]))` reaches this seam via the
        // in-repo CLI (`create-object --value ""` → `hex::decode("")` is
        // `Ok(vec![])`, no empty check) and must pass NULL, not the dangling
        // empty-slice pointer — the same encoding `None` already uses.
        let template = [CkAttribute {
            attr_type: CkAttributeType::VALUE,
            value: Some(CkAttributeValue::Bytes(Vec::new().into())),
        }];
        let attrs = FfiAttrs::from_slice(&template).expect("empty bytes convert");
        assert!(attrs.attrs[0].pValue.is_null());
        // E0793: CK_ATTRIBUTE is packed on Windows; assert on a by-value copy.
        let ul_value_len = attrs.attrs[0].ulValueLen;
        assert_eq!(ul_value_len, 0);
    }

    #[test]
    fn empty_string_value_materializes_null_pvalue() {
        // T4-AUDIT site 4: `Some(String(""))` reaches this seam via the
        // in-repo CLI (`create-object --label ""`, no empty check) and must
        // pass NULL, not the dangling empty-slice pointer.
        let template = [CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(String::new().into())),
        }];
        let attrs = FfiAttrs::from_slice(&template).expect("empty string converts");
        assert!(attrs.attrs[0].pValue.is_null());
        // E0793: CK_ATTRIBUTE is packed on Windows; assert on a by-value copy.
        let ul_value_len = attrs.attrs[0].ulValueLen;
        assert_eq!(ul_value_len, 0);
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
