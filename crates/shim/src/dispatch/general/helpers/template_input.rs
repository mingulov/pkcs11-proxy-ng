//! Input CK_ATTRIBUTE[] template parsing at the C-ABI edge —
//! structural nested-template handling (ADR-0011 D8) included.

use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use super::*;

/// Maximum template entry count we will serialize.  No real PKCS#11
/// template has more than 64 K attributes.
pub(crate) const MAX_TEMPLATE_COUNT: usize = 65_536;

pub(crate) unsafe fn ck_attrs_to_rust_checked(
    p_template: *const CK_ATTRIBUTE,
    count: CK_ULONG,
) -> CkResult<Vec<CkAttribute>> {
    unsafe { ck_attrs_to_rust_result(p_template, count, true) }
}

unsafe fn ck_attrs_to_rust_result(
    p_template: *const CK_ATTRIBUTE,
    count: CK_ULONG,
    reject_null_nonzero_count: bool,
) -> CkResult<Vec<CkAttribute>> {
    unsafe { ck_attrs_to_rust_at_depth(p_template, count, reject_null_nonzero_count, 0) }
}

unsafe fn ck_attrs_to_rust_at_depth(
    p_template: *const CK_ATTRIBUTE,
    count: CK_ULONG,
    reject_null_nonzero_count: bool,
    depth: u8,
) -> CkResult<Vec<CkAttribute>> {
    if p_template.is_null() {
        return if count == 0 || !reject_null_nonzero_count {
            Ok(Vec::new())
        } else {
            Err(CkRv::ARGUMENTS_BAD)
        };
    }
    if count as usize > MAX_TEMPLATE_COUNT {
        return Err(CkRv::ARGUMENTS_BAD);
    }
    // Width bridge (ADR-0011): a ulong array whose element width differs between
    // this client and the backend is re-encoded here, on the client edge.
    // (Scalar ulongs already travel width-independently as a typed `ulong_value`.)
    let client_ulong_width = std::mem::size_of::<CK_ULONG>();
    let backend_ulong_width = crate::interface_probe::backend_ulong_size();
    let slice = unsafe { std::slice::from_raw_parts(p_template, count as usize) };
    let mut result = Vec::with_capacity(count as usize);
    for attr in slice {
        let ck_type = CkAttributeType(attr.type_ as u64);
        let value = if attr.pValue.is_null() {
            if attr.ulValueLen != 0 && reject_null_nonzero_count {
                return Err(CkRv::ARGUMENTS_BAD);
            }
            None
        } else if attr.ulValueLen == 0 {
            None
        } else {
            let len = attr.ulValueLen as usize;
            if ck_type.is_attribute_template() {
                // Input direction of CKF_ARRAY_ATTRIBUTE: pValue is a nested
                // CK_ATTRIBUTE[] in the CLIENT's layout. Parse it structurally
                // — serializing the raw struct bytes would ship dangling
                // client pointers to the backend. Depth is bounded at one
                // level (ADR-0011 D8).
                if depth > 0 {
                    return Err(CkRv::ATTRIBUTE_VALUE_INVALID);
                }
                let stride = std::mem::size_of::<CK_ATTRIBUTE>();
                if !len.is_multiple_of(stride) {
                    return Err(CkRv::ATTRIBUTE_VALUE_INVALID);
                }
                let n = len / stride;
                if n > MAX_TEMPLATE_COUNT {
                    return Err(CkRv::ARGUMENTS_BAD);
                }
                let subs = unsafe {
                    ck_attrs_to_rust_at_depth(
                        attr.pValue as *const CK_ATTRIBUTE,
                        n as CK_ULONG,
                        reject_null_nonzero_count,
                        depth + 1,
                    )
                }?;
                Some(CkAttributeValue::NestedTemplate(subs))
            } else if ck_type.is_bool() && len == std::mem::size_of::<CK_BBOOL>() {
                let v = unsafe { *(attr.pValue as *const CK_BBOOL) };
                Some(CkAttributeValue::Bool(v != 0))
            } else if ck_type.is_ulong() && len == std::mem::size_of::<CK_ULONG>() {
                // `CK_ULONG` is u32 on narrow (32-bit-CK_ULONG) targets; widen to
                // the wire's u64 so the shim compiles on i686/armv7/Windows-x64.
                let v = unsafe { *(attr.pValue as *const CK_ULONG) };
                Some(CkAttributeValue::Ulong(v as u64))
            } else if len > MAX_SERIALIZABLE_BYTES {
                return Err(CkRv::ARGUMENTS_BAD);
            } else if ck_type.is_ulong_array()
                && client_ulong_width != backend_ulong_width
                && len.is_multiple_of(client_ulong_width)
            {
                // A ulong array (e.g. CKA_ALLOWED_MECHANISMS) whose element width
                // differs from the backend's: re-encode each element to the
                // backend width here, then send as opaque bytes the server writes
                // verbatim (ADR-0011). Same-width arrays fall through to the
                // raw-bytes path below, byte-identical to before.
                let bytes = unsafe { std::slice::from_raw_parts(attr.pValue as *const u8, len) };
                match pkcs11_proxy_ng_types::width::reencode_ulong(
                    bytes,
                    client_ulong_width,
                    backend_ulong_width,
                    pkcs11_proxy_ng_types::width::ByteOrder::Little,
                ) {
                    Ok(reencoded) => Some(CkAttributeValue::Bytes(reencoded)),
                    // D4: an element exceeds the backend's CK_ULONG range.
                    Err(_) => return Err(CkRv::ATTRIBUTE_VALUE_INVALID),
                }
            } else {
                let bytes =
                    unsafe { std::slice::from_raw_parts(attr.pValue as *const u8, len) }.to_vec();
                Some(CkAttributeValue::Bytes(bytes))
            }
        };
        result.push(CkAttribute { attr_type: ck_type, value });
    }
    Ok(result)
}

#[cfg(test)]
mod nested_template_input_tests {
    use cryptoki_sys::*;
    use pkcs11_proxy_ng_types::{CkAttributeType, CkAttributeValue, CkRv};

    use super::ck_attrs_to_rust_checked;

    fn wrap_template_attr(subs: &mut [CK_ATTRIBUTE]) -> CK_ATTRIBUTE {
        CK_ATTRIBUTE {
            type_: cryptoki_sys::CKA_WRAP_TEMPLATE,
            pValue: subs.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: std::mem::size_of_val(subs) as CK_ULONG,
        }
    }

    #[test]
    fn template_attr_parses_structurally_never_as_pointer_bytes() {
        let mut class: CK_ULONG = 4;
        let mut subs = [CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &mut class as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        }];
        let outer = [wrap_template_attr(&mut subs)];
        let parsed = unsafe { ck_attrs_to_rust_checked(outer.as_ptr(), 1) }.expect("parses");
        assert_eq!(parsed[0].attr_type, CkAttributeType::WRAP_TEMPLATE);
        let Some(CkAttributeValue::NestedTemplate(nested)) = &parsed[0].value else {
            panic!(
                "template input must be structural (raw struct bytes would ship dangling client pointers to the backend)"
            );
        };
        assert_eq!(nested.len(), 1);
        assert_eq!(nested[0].attr_type, CkAttributeType::CLASS);
        assert_eq!(nested[0].value, Some(CkAttributeValue::Ulong(4)));
    }

    #[test]
    fn template_attr_with_non_stride_multiple_length_is_rejected() {
        let mut class: CK_ULONG = 4;
        let mut subs = [CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &mut class as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        }];
        let mut outer = wrap_template_attr(&mut subs);
        outer.ulValueLen -= 1;
        let outer = [outer];
        assert_eq!(
            unsafe { ck_attrs_to_rust_checked(outer.as_ptr(), 1) }.unwrap_err(),
            CkRv::ATTRIBUTE_VALUE_INVALID
        );
    }

    #[test]
    fn template_inside_template_is_rejected_d8() {
        let mut class: CK_ULONG = 4;
        let mut inner_subs = [CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &mut class as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        }];
        let mut mid = [wrap_template_attr(&mut inner_subs)];
        let outer = [wrap_template_attr(&mut mid)];
        assert_eq!(
            unsafe { ck_attrs_to_rust_checked(outer.as_ptr(), 1) }.unwrap_err(),
            CkRv::ATTRIBUTE_VALUE_INVALID
        );
    }
}
