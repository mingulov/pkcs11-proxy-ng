//! Captured caller destinations and transactional exact attribute writeback.
use super::*;

use super::super::helpers::{MAX_SERIALIZABLE_BYTES, MAX_TEMPLATE_COUNT};

pub(super) struct AttributeCall {
    pub query: CkAttributeQuery,
    value: CK_VOID_PTR,
    capacity: u64,
    length: CK_ULONG_PTR,
    attr_type: *mut CK_ATTRIBUTE_TYPE,
    nested: Option<Vec<AttributeCall>>,
}

/// Only initialized input fields are read. In particular NULL-value lengths
/// are output-only, so no whole-struct reference exists. A nested `type` is
/// caller input when preset (F7/D5): backends such as SoftHSM select the
/// sub-query by it, so it is forwarded verbatim like a direct call instead
/// of being forced to 0.
///
/// # Safety
///
/// `pointer` must be non-null and point to a readable `CK_ATTRIBUTE`
/// (field reads are unaligned-safe); nested child arrays, when present,
/// must satisfy the same contract per element.
pub(super) unsafe fn capture(
    pointer: CK_ATTRIBUTE_PTR,
    nested: bool,
    client_width: usize,
    backend_width: usize,
    backend_stride: usize,
) -> CkResult<AttributeCall> {
    let value = unsafe { std::ptr::addr_of!((*pointer).pValue).read_unaligned() };
    // `type` is the leading field in the client's layout, which is the
    // compiled layout on this edge (client_width is always size_of::<CK_ULONG>()
    // here), so this read is width-correct cross-width as well; materialized
    // cross-width nested values stay rejected by the gate below.
    let attr_type =
        CkAttributeType(unsafe { std::ptr::addr_of!((*pointer).type_).read_unaligned() } as u64);
    let capacity = if value.is_null() {
        0
    } else {
        (unsafe { std::ptr::addr_of!((*pointer).ulValueLen).read_unaligned() }) as u64
    };
    if capacity > MAX_SERIALIZABLE_BYTES as u64 {
        return Err(CkRv::HOST_MEMORY);
    }
    let mut children = None;
    let mut query = CkAttributeQuery {
        attr_type,
        buffer_present: !value.is_null(),
        buffer_len: capacity,
        nested: None,
    };
    if nested {
        // A materialized nested value cannot be width-bridged without
        // per-child value semantics; only size queries cross widths here.
        // Unknown/vendor top-level attributes never enter this standard path.
        if client_width != backend_width && !value.is_null() {
            return Err(CkRv::FUNCTION_NOT_SUPPORTED);
        }
    } else if attr_type.is_attribute_template() {
        if !value.is_null() {
            let stride = std::mem::size_of::<CK_ATTRIBUTE>();
            let count = usize::try_from(capacity).map_err(|_| CkRv::HOST_MEMORY)? / stride;
            if capacity % stride as u64 != 0 || count > MAX_TEMPLATE_COUNT {
                return Err(CkRv::ARGUMENTS_BAD);
            }
            let mut captured = Vec::with_capacity(count);
            for index in 0..count {
                captured.push(unsafe {
                    capture(
                        value.cast::<CK_ATTRIBUTE>().add(index),
                        true,
                        client_width,
                        backend_width,
                        backend_stride,
                    )
                }?);
            }
            query.buffer_len =
                (count as u64).checked_mul(backend_stride as u64).ok_or(CkRv::HOST_MEMORY)?;
            query.nested = Some(captured.iter().map(|child| child.query.clone()).collect());
            children = Some(captured);
        }
    } else {
        query.buffer_len = super::super::width_bridge::bridge_request_buffer_len(
            attr_type,
            capacity,
            client_width,
            backend_width,
        );
    }
    Ok(AttributeCall {
        query,
        value,
        capacity,
        length: unsafe { std::ptr::addr_of_mut!((*pointer).ulValueLen) },
        attr_type: unsafe { std::ptr::addr_of_mut!((*pointer).type_) },
        nested: children,
    })
}

pub(super) struct AttributeWrite {
    value_pointer: CK_VOID_PTR,
    value: Option<Vec<u8>>,
    length_pointer: CK_ULONG_PTR,
    length: Option<CK_ULONG>,
    type_pointer: *mut CK_ATTRIBUTE_TYPE,
    attr_type: Option<CK_ATTRIBUTE_TYPE>,
}

fn checked_length(value: u64) -> CkResult<CK_ULONG> {
    if value == pkcs11_proxy_ng_types::CANONICAL_UNAVAILABLE {
        return Ok(CK_UNAVAILABLE_INFORMATION);
    }
    CK_ULONG::try_from(value).map_err(|_| CkRv::GENERAL_ERROR)
}

fn prepare_one(
    call: &AttributeCall,
    result: &CkAttributeQueryResult,
    nested: bool,
    values_defined: bool,
    client_width: usize,
    backend_width: usize,
    backend_stride: usize,
    writes: &mut Vec<AttributeWrite>,
) -> CkResult<()> {
    if (!nested && result.attr_type != call.query.attr_type)
        || (!result.apply_returned_len
            && (result.returned_len != 0 || result.value.is_some() || result.nested.is_some()))
        || (!values_defined && (result.value.is_some() || result.apply_type))
        || result.ck_rv.is_some_and(|rv| rv.0 > CK_RV::MAX as u64)
    {
        return Err(CkRv::GENERAL_ERROR);
    }
    let type_effect = if nested && result.apply_type {
        Some(CK_ATTRIBUTE_TYPE::try_from(result.attr_type.0).map_err(|_| CkRv::GENERAL_ERROR)?)
    } else {
        None
    };
    if nested && result.value.is_some() && type_effect.is_none() {
        return Err(CkRv::GENERAL_ERROR);
    }
    let mut length = result.returned_len;
    let mut value = None;
    if call.query.attr_type.is_attribute_template() && !nested {
        if result.value.is_some() {
            return Err(CkRv::GENERAL_ERROR);
        }
        if result.apply_returned_len && length != pkcs11_proxy_ng_types::CANONICAL_UNAVAILABLE {
            if backend_stride == 0 || !length.is_multiple_of(backend_stride as u64) {
                return Err(CkRv::GENERAL_ERROR);
            }
            length = (length / backend_stride as u64)
                .checked_mul(std::mem::size_of::<CK_ATTRIBUTE>() as u64)
                .ok_or(CkRv::GENERAL_ERROR)?;
        }
        if let Some(results) = &result.nested {
            let calls = call.nested.as_ref().ok_or(CkRv::GENERAL_ERROR)?;
            if results.len() > calls.len()
                || results.len() as u64 * std::mem::size_of::<CK_ATTRIBUTE>() as u64 != length
            {
                return Err(CkRv::GENERAL_ERROR);
            }
            for (call, result) in calls.iter().zip(results) {
                prepare_one(
                    call,
                    result,
                    true,
                    values_defined,
                    client_width,
                    backend_width,
                    backend_stride,
                    writes,
                )?;
            }
        }
    } else {
        if result.nested.is_some() {
            return Err(CkRv::GENERAL_ERROR);
        }
        if let Some(bytes) = &result.value
            && (!result.apply_returned_len
                || call.value.is_null()
                || bytes.len() as u64 != result.returned_len
                || bytes.len() as u64 > call.query.buffer_len)
        {
            return Err(CkRv::GENERAL_ERROR);
        }
        let attribute_type = if nested && !result.apply_type {
            CkAttributeType::VENDOR_DEFINED
        } else if nested {
            result.attr_type
        } else {
            call.query.attr_type
        };
        if result.apply_returned_len {
            // All translation and narrowing happens before any caller store.
            let bridged = |value: Option<&[u8]>| {
                super::super::width_bridge::bridge_output_value(
                    attribute_type,
                    value,
                    length,
                    backend_width,
                    client_width,
                )
            };
            let outcome = match &result.value {
                Some(secret) => secret.expose(|raw| bridged(Some(raw))),
                None => bridged(None),
            };
            // W1-L5-02: a genuine backend value that exceeds the client's
            // CK_ULONG range (ADR-0011 D4 overflow) surfaces as
            // CK_UNAVAILABLE_INFORMATION for this attribute only — value
            // dropped, canonical sentinel length — while the other attributes
            // are still returned. Only malformed bridge inputs (misaligned
            // bytes, unsupported widths) fail the whole call.
            (value, length) = match outcome {
                Ok(pair) => pair,
                Err(pkcs11_proxy_ng_types::WidthError::Overflow) => {
                    (None, pkcs11_proxy_ng_types::CANONICAL_UNAVAILABLE)
                }
                Err(_) => return Err(CkRv::GENERAL_ERROR),
            };
        }
        if value.as_ref().is_some_and(|bytes| bytes.len() as u64 > call.capacity) {
            return Err(CkRv::GENERAL_ERROR);
        }
    }
    writes.push(AttributeWrite {
        value_pointer: call.value,
        value,
        length_pointer: call.length,
        length: result.apply_returned_len.then(|| checked_length(length)).transpose()?,
        type_pointer: call.attr_type,
        attr_type: type_effect,
    });
    Ok(())
}

pub(super) fn prepare(
    calls: &[AttributeCall],
    results: &[CkAttributeQueryResult],
    rv: CkRv,
    client_width: usize,
    backend_width: usize,
    backend_stride: usize,
) -> CkResult<Vec<AttributeWrite>> {
    CK_RV::try_from(rv.0).map_err(|_| CkRv::GENERAL_ERROR)?;
    if calls.len() != results.len() {
        // Authorization/remapping/transport suppression contains no effects.
        if rv != CkRv::OK && results.is_empty() {
            return Ok(Vec::new());
        }
        return Err(CkRv::GENERAL_ERROR);
    }
    let defined = pkcs11_proxy_ng_types::attribute_outputs_defined(rv);
    let mut writes = Vec::new();
    for (call, result) in calls.iter().zip(results) {
        prepare_one(
            call,
            result,
            false,
            defined,
            client_width,
            backend_width,
            backend_stride,
            &mut writes,
        )?;
    }
    Ok(writes)
}

/// The prepared plan owns validated bytes and captured destinations. No caller
/// field is re-read; validation failure therefore cannot produce a partial store.
///
/// # Safety
///
/// `writes` must be the validated plan for still-live caller structs:
/// every captured destination writable for its recorded extent, with no
/// aliasing writes since capture.
pub(super) unsafe fn commit(writes: Vec<AttributeWrite>) {
    for write in writes {
        if let Some(value) = write.value {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    value.as_ptr(),
                    write.value_pointer.cast(),
                    value.len(),
                )
            };
        }
        if let Some(attr_type) = write.attr_type {
            unsafe { write.type_pointer.write_unaligned(attr_type) };
        }
        if let Some(length) = write.length {
            unsafe { write.length_pointer.write_unaligned(length) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_standard_nested_preset_type_is_forwarded() {
        // F7/D5: a caller-preset nested `type` is query input (SoftHSM
        // selects the sub-query by it) and must reach the daemon verbatim.
        let width = std::mem::size_of::<CK_ULONG>();
        for (backend_width, materialized) in
            [(width, true), (if width == 8 { 4 } else { 8 }, false)]
        {
            let mut value = [0xa5u8; 4];
            let mut sub = std::mem::MaybeUninit::<CK_ATTRIBUTE>::uninit();
            let pointer = sub.as_mut_ptr();
            unsafe {
                std::ptr::addr_of_mut!((*pointer).type_).write(CKA_SENSITIVE);
                std::ptr::addr_of_mut!((*pointer).pValue).write(if materialized {
                    value.as_mut_ptr().cast()
                } else {
                    std::ptr::null_mut()
                });
                // A materialized length is in/out; a NULL-value length is output-only.
                if materialized {
                    std::ptr::addr_of_mut!((*pointer).ulValueLen).write(4);
                }
            }
            let mut outer = CK_ATTRIBUTE {
                type_: CKA_WRAP_TEMPLATE,
                pValue: pointer.cast(),
                ulValueLen: std::mem::size_of::<CK_ATTRIBUTE>() as CK_ULONG,
            };
            let captured = unsafe {
                capture(
                    &mut outer,
                    false,
                    width,
                    backend_width,
                    std::mem::size_of::<CK_ATTRIBUTE>(),
                )
            }
            .unwrap();
            let query = &captured.query.nested.as_ref().unwrap()[0];
            assert_eq!(query.attr_type, CkAttributeType::SENSITIVE);
            assert_eq!(query.buffer_len, if materialized { 4 } else { 0 });
        }
    }

    #[test]
    fn exact_attribute_query_and_transaction_do_not_reread_caller_lengths() {
        let width = std::mem::size_of::<CK_ULONG>();
        let stride = std::mem::size_of::<CK_ATTRIBUTE>();
        let mut outer = std::mem::MaybeUninit::<CK_ATTRIBUTE>::uninit();
        let pointer = outer.as_mut_ptr();
        unsafe {
            std::ptr::addr_of_mut!((*pointer).type_).write(CKA_LABEL);
            std::ptr::addr_of_mut!((*pointer).pValue).write(std::ptr::null_mut());
        }
        let call = unsafe { capture(pointer, false, width, width, stride) }.unwrap();
        let result = CkAttributeQueryResult {
            attr_type: CkAttributeType::LABEL,
            returned_len: 7,
            apply_returned_len: true,
            apply_type: false,
            value: None,
            ck_rv: None,
            nested: None,
        };
        let writes =
            prepare(&[call], &[result], CkRv::FUNCTION_FAILED, width, width, stride).unwrap();
        unsafe {
            commit(writes);
            assert_eq!(std::ptr::addr_of!((*pointer).ulValueLen).read(), 7);
        }
    }

    #[test]
    fn exact_attribute_all_results_validate_before_any_store() {
        let width = std::mem::size_of::<CK_ULONG>();
        let stride = std::mem::size_of::<CK_ATTRIBUTE>();
        let mut first = [0xa5u8; 4];
        let mut second = [0x5au8; 4];
        let mut attrs = [
            CK_ATTRIBUTE { type_: CKA_LABEL, pValue: first.as_mut_ptr().cast(), ulValueLen: 4 },
            CK_ATTRIBUTE { type_: CKA_LABEL, pValue: second.as_mut_ptr().cast(), ulValueLen: 4 },
        ];
        let calls: Vec<_> = (0..2)
            .map(|i| {
                unsafe { capture(attrs.as_mut_ptr().add(i), false, width, width, stride) }.unwrap()
            })
            .collect();
        let result = CkAttributeQueryResult {
            attr_type: CkAttributeType::LABEL,
            returned_len: 4,
            apply_returned_len: true,
            apply_type: false,
            value: Some(vec![1; 4].into()),
            ck_rv: None,
            nested: None,
        };
        let mut bad = result.clone();
        bad.returned_len = 3;
        assert!(prepare(&calls, &[result, bad], CkRv::OK, width, width, stride).is_err());
        assert_eq!(first, [0xa5; 4]);
        assert_eq!(second, [0x5a; 4]);
        assert_eq!([attrs[0].ulValueLen, attrs[1].ulValueLen], [4, 4]);
    }

    #[test]
    fn exact_bridge_overflow_is_per_attribute_unavailable_not_whole_call_error() {
        // W1-L5-02. Documented contract: `width_bridge::bridge_output_value`'s
        // doc comment — "WidthError::Overflow is returned if a genuine backend
        // value exceeds the client's CK_ULONG range (D4) — the caller surfaces
        // that attribute as CK_UNAVAILABLE_INFORMATION rather than truncating
        // or failing the whole call" (ADR-0011 D4; D10 sentinel encoding via
        // CANONICAL_UNAVAILABLE). Mixed call: one ulong attribute whose 64-bit
        // backend value does not fit a 32-bit client CK_ULONG, plus one valid
        // opaque attribute. The valid attribute must still be returned; the
        // overflowing one gets ulValueLen = CK_UNAVAILABLE_INFORMATION with
        // its buffer untouched; the whole call must not fail.
        let host = std::mem::size_of::<CK_ULONG>();
        let stride = std::mem::size_of::<CK_ATTRIBUTE>();
        // Simulated topology: 32-bit client, 64-bit backend. Capture runs at
        // host width (its width params only gate nested templates); the
        // client/backend widths drive the output bridge in `prepare`.
        let client_width = 4usize;
        let backend_width = 8usize;
        let mut overflow_buf = [0xa5u8; 8];
        let mut label_buf = [0u8; 4];
        let mut attrs = [
            CK_ATTRIBUTE {
                type_: CkAttributeType::CLASS.0 as CK_ATTRIBUTE_TYPE,
                pValue: overflow_buf.as_mut_ptr().cast(),
                ulValueLen: 8,
            },
            CK_ATTRIBUTE { type_: CKA_LABEL, pValue: label_buf.as_mut_ptr().cast(), ulValueLen: 4 },
        ];
        let calls: Vec<_> = (0..2)
            .map(|i| {
                unsafe { capture(attrs.as_mut_ptr().add(i), false, host, host, stride) }.unwrap()
            })
            .collect();
        let big = pkcs11_proxy_ng_types::encode_native_ulong(0x1_0000_0001, 8);
        let results = [
            CkAttributeQueryResult {
                attr_type: CkAttributeType::CLASS,
                returned_len: 8,
                apply_returned_len: true,
                apply_type: false,
                value: Some(big.into()),
                ck_rv: None,
                nested: None,
            },
            CkAttributeQueryResult {
                attr_type: CkAttributeType::LABEL,
                returned_len: 4,
                apply_returned_len: true,
                apply_type: false,
                value: Some(b"test".to_vec().into()),
                ck_rv: None,
                nested: None,
            },
        ];
        let writes = prepare(&calls, &results, CkRv::OK, client_width, backend_width, stride)
            .expect("bridge overflow must be per-attribute, not a whole-call failure");
        unsafe { commit(writes) };
        // E0793: CK_ATTRIBUTE is packed on Windows; assert on by-value copies.
        let overflow_len = attrs[0].ulValueLen;
        assert_eq!(overflow_len, CK_UNAVAILABLE_INFORMATION);
        assert_eq!(overflow_buf, [0xa5; 8], "unavailable value must not touch the buffer");
        let label_len = attrs[1].ulValueLen;
        assert_eq!(label_len, 4);
        assert_eq!(label_buf, *b"test", "valid attribute must still be returned");
    }
}
