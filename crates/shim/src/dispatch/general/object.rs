// CK_ULONG is u64 on 64-bit and u32 on 32-bit; `as u64` casts are intentional
// for cross-platform PKCS#11 portability.
#![allow(clippy::unnecessary_cast)]

use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

#[allow(unused_imports)]
use super::*;

pub unsafe extern "C" fn c_find_objects_init(
    h_session: CK_SESSION_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let template = match unsafe { ck_attrs_to_rust_checked(p_template, ul_count) } {
            Ok(template) => template,
            Err(e) => return rv_err(e),
        };
        unit_result_to_rv(with_client!(client => client.find_objects_init(
            CkSessionHandle(h_session as u64),
            &template,
        )))
    })
}

pub unsafe extern "C" fn c_find_objects(
    h_session: CK_SESSION_HANDLE,
    ph_object: CK_OBJECT_HANDLE_PTR,
    ul_max_object_count: CK_ULONG,
    pul_object_count: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if ph_object.is_null() || pul_object_count.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        match with_client!(client => client.find_objects(
            CkSessionHandle(h_session as u64),
            ul_max_object_count as u32,
        )) {
            Ok(handles) => {
                let count = handles.len().min(ul_max_object_count as usize);
                unsafe {
                    for (i, h) in handles.iter().take(count).enumerate() {
                        *ph_object.add(i) = h.0 as CK_OBJECT_HANDLE;
                    }
                    *pul_object_count = count as CK_ULONG;
                }
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_find_objects_final(h_session: CK_SESSION_HANDLE) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(with_client!(client => client.find_objects_final(
            CkSessionHandle(h_session as u64)
        )))
    })
}

mod exact;

pub unsafe extern "C" fn c_get_attribute_value(
    h_session: CK_SESSION_HANDLE,
    h_object: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let Ok(count) = usize::try_from(ul_count) else {
            return rv_err(CkRv::ARGUMENTS_BAD);
        };
        if (p_template.is_null() && count != 0) || count > MAX_TEMPLATE_COUNT {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let client_width = std::mem::size_of::<CK_ULONG>();
        let backend_width = crate::interface_probe::backend_ulong_size();
        let backend_stride = crate::interface_probe::backend_attribute_stride();
        let mut calls = Vec::with_capacity(count);
        for index in 0..count {
            match unsafe {
                exact::capture(
                    p_template.add(index),
                    false,
                    client_width,
                    backend_width,
                    backend_stride,
                )
            } {
                Ok(call) => calls.push(call),
                Err(rv) => return rv_err(rv),
            }
        }
        let queries: Vec<_> = calls.iter().map(|call| call.query.clone()).collect();
        match with_client!(client => client.get_attribute_value_exact(CkSessionHandle(h_session as u64), CkObjectHandle(h_object as u64), &queries))
        {
            Ok((rv, results)) => match exact::prepare(
                &calls,
                &results,
                rv,
                client_width,
                backend_width,
                backend_stride,
            ) {
                Ok(writes) => {
                    unsafe { exact::commit(writes) };
                    rv_err(rv)
                }
                Err(error) => rv_err(error),
            },
            Err(rv) => rv_err(rv),
        }
    })
}

#[cfg(test)]
fn build_attribute_query(
    a: &CK_ATTRIBUTE,
    client_width: usize,
    backend_width: usize,
    backend_stride: usize,
) -> CkResult<CkAttributeQuery> {
    unsafe {
        exact::capture(
            (a as *const CK_ATTRIBUTE).cast_mut(),
            false,
            client_width,
            backend_width,
            backend_stride,
        )
    }
    .map(|call| call.query)
}

#[cfg(test)]
unsafe fn write_nested_result_to_ffi(
    c_attr: &mut CK_ATTRIBUTE,
    result: &CkAttributeQueryResult,
    client_width: usize,
    backend_width: usize,
) {
    let call = unsafe {
        exact::capture(
            c_attr,
            false,
            client_width,
            backend_width,
            std::mem::size_of::<CK_ATTRIBUTE>(),
        )
    }
    .unwrap();
    let mut result = result.clone();
    if let Some(nested) = &mut result.nested {
        for item in nested {
            item.apply_type = true;
        }
    }
    let writes = exact::prepare(
        &[call],
        &[result],
        CkRv::OK,
        client_width,
        backend_width,
        std::mem::size_of::<CK_ATTRIBUTE>(),
    )
    .unwrap();
    unsafe { exact::commit(writes) };
}

// ---------------------------------------------------------------------------
// Object management
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn c_create_object(
    h_session: CK_SESSION_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
    ph_object: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_panics(|| {
        if ph_object.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let template = match unsafe { ck_attrs_to_rust_checked(p_template, ul_count) } {
            Ok(template) => template,
            Err(e) => return rv_err(e),
        };
        match with_client!(client => client.create_object(CkSessionHandle(h_session as u64), &template))
        {
            Ok(handle) => {
                unsafe { write_object_handle_output(handle, ph_object) };
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_copy_object(
    h_session: CK_SESSION_HANDLE,
    h_object: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
    ph_new_object: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_panics(|| {
        if ph_new_object.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let template = match unsafe { ck_attrs_to_rust_checked(p_template, ul_count) } {
            Ok(template) => template,
            Err(e) => return rv_err(e),
        };
        match with_client!(client => client.copy_object(
            CkSessionHandle(h_session as u64),
            CkObjectHandle(h_object as u64),
            &template,
        )) {
            Ok(handle) => {
                unsafe { write_object_handle_output(handle, ph_new_object) };
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_destroy_object(
    h_session: CK_SESSION_HANDLE,
    h_object: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panics(|| {
        unit_result_to_rv(with_client!(client => client.destroy_object(
            CkSessionHandle(h_session as u64),
            CkObjectHandle(h_object as u64),
        )))
    })
}

pub unsafe extern "C" fn c_get_object_size(
    h_session: CK_SESSION_HANDLE,
    h_object: CK_OBJECT_HANDLE,
    pul_size: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if pul_size.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        match with_client!(client => client.get_object_size(
            CkSessionHandle(h_session as u64),
            CkObjectHandle(h_object as u64),
        )) {
            Ok(size) => {
                unsafe {
                    *pul_size = size as CK_ULONG;
                }
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_set_attribute_value(
    h_session: CK_SESSION_HANDLE,
    h_object: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let template = match unsafe { ck_attrs_to_rust_checked(p_template, ul_count) } {
            Ok(template) => template,
            Err(e) => return rv_err(e),
        };
        unit_result_to_rv(with_client!(client => client.set_attribute_value(
            CkSessionHandle(h_session as u64),
            CkObjectHandle(h_object as u64),
            &template,
        )))
    })
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn exact_standard_nested_query_ignores_input_type() {
        let mut value = [0u8; 8];
        let mut nested =
            CK_ATTRIBUTE { type_: CKA_KEY_TYPE, pValue: value.as_mut_ptr().cast(), ulValueLen: 8 };
        let outer = CK_ATTRIBUTE {
            type_: CKA_WRAP_TEMPLATE,
            pValue: (&mut nested as *mut CK_ATTRIBUTE).cast(),
            ulValueLen: std::mem::size_of::<CK_ATTRIBUTE>() as CK_ULONG,
        };
        let width = std::mem::size_of::<CK_ULONG>();
        let query =
            build_attribute_query(&outer, width, width, std::mem::size_of::<CK_ATTRIBUTE>())
                .unwrap();
        assert_eq!(
            query.nested.unwrap()[0].attr_type,
            CkAttributeType(0),
            "nested type is output-only, not an input schema hint"
        );
    }

    #[test]
    fn exact_standard_mixed_width_materialized_nested_query_rejects_before_native() {
        let mut value = [0xa5u8; 4];
        let mut nested =
            CK_ATTRIBUTE { type_: CKA_KEY_TYPE, pValue: value.as_mut_ptr().cast(), ulValueLen: 4 };
        let outer = CK_ATTRIBUTE {
            type_: CKA_WRAP_TEMPLATE,
            pValue: (&mut nested as *mut CK_ATTRIBUTE).cast(),
            ulValueLen: std::mem::size_of::<CK_ATTRIBUTE>() as CK_ULONG,
        };
        assert_eq!(build_attribute_query(&outer, 4, 8, 24), Err(CkRv::FUNCTION_NOT_SUPPORTED));
        assert_eq!(value, [0xa5; 4]);
        // E0793: CK_ATTRIBUTE is packed on Windows; assert on a by-value copy.
        let ul_value_len = nested.ulValueLen;
        assert_eq!(ul_value_len, 4);
    }

    #[test]
    fn exact_unknown_vendor_array_remains_opaque_across_widths() {
        let mut value = [0xa5u8; 4];
        let vendor_type = CkAttributeType::VENDOR_DEFINED.0 | CKF_ARRAY_ATTRIBUTE as u64 | 0x42;
        let outer = CK_ATTRIBUTE {
            type_: vendor_type as CK_ATTRIBUTE_TYPE,
            pValue: value.as_mut_ptr().cast(),
            ulValueLen: 4,
        };
        let query = build_attribute_query(&outer, 4, 8, 24).unwrap();
        assert_eq!(query.attr_type.0, vendor_type);
        assert_eq!(query.buffer_len, 4);
        assert!(query.nested.is_none());
    }

    // CKA_ALLOWED_MECHANISMS carries the CKF_ARRAY_ATTRIBUTE flag, but its value
    // is a CK_MECHANISM_TYPE[] (an array of CK_ULONG) -- NOT a CK_ATTRIBUTE[]
    // template like CKA_WRAP_TEMPLATE. It must not be parsed as a nested
    // template, which would reject a caller buffer sized for N mechanisms
    // (N * sizeof(CK_ULONG)) because N*8 % sizeof(CK_ATTRIBUTE) != 0.
    #[test]
    fn allowed_mechanisms_is_not_parsed_as_attribute_template() {
        let mut buf = [0u8; 8]; // one CK_MECHANISM_TYPE on a 64-bit client
        let attr = CK_ATTRIBUTE {
            type_: CkAttributeType::ALLOWED_MECHANISMS.0 as CK_ATTRIBUTE_TYPE,
            pValue: buf.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: buf.len() as CK_ULONG,
        };
        let w = std::mem::size_of::<CK_ULONG>();
        let q = build_attribute_query(&attr, w, w, 3 * w)
            .expect("CKA_ALLOWED_MECHANISMS must not be rejected as a malformed template");
        assert!(
            q.nested.is_none(),
            "CKA_ALLOWED_MECHANISMS is a ulong array, not a CK_ATTRIBUTE[] template"
        );
        assert!(q.buffer_present);
        assert_eq!(q.buffer_len, 8);
    }

    // Regression guard: real CK_ATTRIBUTE[] templates must STILL build nested
    // sub-queries after the routing fix.
    #[test]
    fn wrap_template_still_builds_nested_subqueries() {
        let mut sub = CK_ATTRIBUTE {
            type_: CkAttributeType::CLASS.0 as CK_ATTRIBUTE_TYPE,
            pValue: ptr::null_mut(),
            ulValueLen: 0,
        };
        let attr = CK_ATTRIBUTE {
            type_: CkAttributeType::WRAP_TEMPLATE.0 as CK_ATTRIBUTE_TYPE,
            pValue: &mut sub as *mut CK_ATTRIBUTE as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ATTRIBUTE>() as CK_ULONG,
        };
        let w = std::mem::size_of::<CK_ULONG>();
        let q = build_attribute_query(&attr, w, w, 3 * w).expect("WRAP_TEMPLATE must parse");
        let nested = q.nested.expect("WRAP_TEMPLATE must build nested sub-queries");
        assert_eq!(nested.len(), 1);
    }

    // Nested template write-back: each ulong sub-value is bridged and the
    // template length is reported in the client's CK_ATTRIBUTE layout. Exercised
    // here at same width (a no-op for the values); the cross-width re-encode is
    // covered by width_bridge's unit matrix.
    #[test]
    fn write_nested_writes_subattrs_and_client_layout_length() {
        use pkcs11_proxy_ng_types::CkAttributeQueryResult;

        let w = std::mem::size_of::<CK_ULONG>();
        let ck_attr_size = std::mem::size_of::<CK_ATTRIBUTE>();

        // Caller's CK_ATTRIBUTE[2] sub-template: one ulong, one byte-string.
        let mut ul_buf = vec![0u8; w];
        let mut label_buf = [0u8; 8];
        let mut subs = [
            CK_ATTRIBUTE {
                type_: 0, // set on output
                pValue: ul_buf.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: w as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: 0,
                pValue: label_buf.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: label_buf.len() as CK_ULONG,
            },
        ];
        let mut c_attr = CK_ATTRIBUTE {
            type_: CkAttributeType::WRAP_TEMPLATE.0 as CK_ATTRIBUTE_TYPE,
            pValue: subs.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: (2 * ck_attr_size) as CK_ULONG,
        };

        let key_type_bytes = (0x1f as CK_ULONG).to_ne_bytes().to_vec(); // CKK_AES
        let result = CkAttributeQueryResult {
            apply_returned_len: true,
            apply_type: false,
            attr_type: CkAttributeType::WRAP_TEMPLATE,
            returned_len: (2 * ck_attr_size) as u64,
            value: None,
            ck_rv: None,
            nested: Some(vec![
                CkAttributeQueryResult {
                    apply_returned_len: true,
                    apply_type: false,
                    attr_type: CkAttributeType::KEY_TYPE,
                    returned_len: w as u64,
                    value: Some(key_type_bytes.clone().into()),
                    ck_rv: None,
                    nested: None,
                },
                CkAttributeQueryResult {
                    apply_returned_len: true,
                    apply_type: false,
                    attr_type: CkAttributeType::LABEL,
                    returned_len: 1,
                    value: Some(b"k".to_vec().into()),
                    ck_rv: None,
                    nested: None,
                },
            ]),
        };

        unsafe { write_nested_result_to_ffi(&mut c_attr, &result, w, w) };

        assert_eq!(c_attr.ulValueLen as usize, 2 * ck_attr_size, "client-layout template size");
        assert_eq!(subs[0].type_ as u64, CkAttributeType::KEY_TYPE.0);
        assert_eq!(subs[0].ulValueLen as usize, w);
        assert_eq!(ul_buf, key_type_bytes, "ulong sub-value written");
        assert_eq!(subs[1].type_ as u64, CkAttributeType::LABEL.0);
        let ul_value_len = subs[1].ulValueLen;
        assert_eq!(ul_value_len, 1);
        assert_eq!(&label_buf[..1], b"k", "byte sub-value written");
    }
}
