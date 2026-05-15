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
        let template = unsafe { ck_attrs_to_rust(p_template, ul_count) };
        unit_result_to_rv(with_client!(client => client.find_objects_init(
            CkSessionHandle(h_session),
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
            CkSessionHandle(h_session),
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
            CkSessionHandle(h_session)
        )))
    })
}

pub unsafe extern "C" fn c_get_attribute_value(
    h_session: CK_SESSION_HANDLE,
    h_object: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        if p_template.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let n = ul_count as usize;
        if n > MAX_TEMPLATE_COUNT {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let query_result: CkResult<Vec<CkAttributeQuery>> = {
            let slice = unsafe { read_input_slice(p_template, ul_count) };
            slice.iter().map(build_attribute_query).collect()
        };
        let queries: Vec<CkAttributeQuery> = match query_result {
            Ok(queries) => queries,
            Err(rv) => return rv_err(rv),
        };

        match with_client!(client => client.get_attribute_value_exact(
            CkSessionHandle(h_session),
            CkObjectHandle(h_object),
            &queries,
        )) {
            Ok((server_rv, results)) => {
                if results.len() != queries.len() {
                    if server_rv != CkRv::OK && results.is_empty() {
                        return rv_err(server_rv);
                    }
                    return rv_err(CkRv::GENERAL_ERROR);
                }

                unsafe {
                    for (i, query) in queries.iter().enumerate() {
                        let c_attr = &mut *p_template.add(i);
                        let result = &results[i];

                        if query.nested.is_some() {
                            // Nested (CKF_ARRAY_ATTRIBUTE): write back sub-attribute
                            // results into the caller's CK_ATTRIBUTE[] template.
                            write_nested_result_to_ffi(c_attr, result);
                        } else if query.buffer_present
                            && let Some(bytes) = result.value.as_ref()
                            && bytes.len() <= query.buffer_len as usize
                            && !c_attr.pValue.is_null()
                        {
                            std::ptr::copy_nonoverlapping(
                                bytes.as_ptr(),
                                c_attr.pValue as *mut u8,
                                bytes.len(),
                            );
                        }
                        c_attr.ulValueLen = result.returned_len as CK_ULONG;
                    }
                }
                if server_rv == CkRv::OK { rv_ok() } else { rv_err(server_rv) }
            }
            Err(e) => rv_err(e),
        }
    })
}

/// Build a `CkAttributeQuery` from a caller-provided `CK_ATTRIBUTE`.
///
/// If the attribute type has the `CKF_ARRAY_ATTRIBUTE` flag and `pValue` is
/// non-null, interprets `pValue` as a `CK_ATTRIBUTE[]` template and builds
/// nested sub-queries for each entry.
fn build_attribute_query(a: &CK_ATTRIBUTE) -> CkResult<CkAttributeQuery> {
    let attr_type = CkAttributeType(a.type_);
    let buffer_present = !a.pValue.is_null();

    if attr_type.is_array_attribute() && buffer_present {
        let ck_attr_size = std::mem::size_of::<CK_ATTRIBUTE>();
        let raw_len = usize::try_from(a.ulValueLen).map_err(|_| CkRv::ARGUMENTS_BAD)?;
        if ck_attr_size > 0 && raw_len % ck_attr_size != 0 {
            return Err(CkRv::ARGUMENTS_BAD);
        }
        let nested_count = raw_len.checked_div(ck_attr_size).unwrap_or(0);
        if nested_count > MAX_TEMPLATE_COUNT {
            return Err(CkRv::ARGUMENTS_BAD);
        }

        if nested_count > 0 {
            let sub_attrs = unsafe {
                read_input_slice(a.pValue as *const CK_ATTRIBUTE, nested_count as CK_ULONG)
            };
            let nested: Vec<CkAttributeQuery> = sub_attrs
                .iter()
                .map(|sub| CkAttributeQuery {
                    attr_type: CkAttributeType(sub.type_),
                    buffer_present: !sub.pValue.is_null(),
                    buffer_len: sub.ulValueLen as u64,
                    nested: None,
                })
                .collect();
            return Ok(CkAttributeQuery {
                attr_type,
                buffer_present,
                buffer_len: a.ulValueLen as u64,
                nested: Some(nested),
            });
        }
    }

    Ok(CkAttributeQuery {
        attr_type,
        buffer_present,
        buffer_len: a.ulValueLen as u64,
        nested: None,
    })
}

/// Write nested `CkAttributeQueryResult` items back into the caller's
/// `CK_ATTRIBUTE[]` template (the sub-attributes pointed to by `pValue`).
///
/// # Safety
///
/// `c_attr.pValue` must point to a valid `CK_ATTRIBUTE[]` array with at least
/// as many entries as `result.nested` contains.
unsafe fn write_nested_result_to_ffi(c_attr: &mut CK_ATTRIBUTE, result: &CkAttributeQueryResult) {
    let Some(nested_results) = result.nested.as_ref() else {
        return;
    };

    if c_attr.pValue.is_null() {
        return;
    }

    let ck_attr_size = std::mem::size_of::<CK_ATTRIBUTE>();
    let capacity = (c_attr.ulValueLen as usize).checked_div(ck_attr_size).unwrap_or(0);
    let count = nested_results.len().min(capacity);

    let sub_attrs = unsafe { write_output_slice(c_attr.pValue as *mut CK_ATTRIBUTE, count) };

    for (i, sub_result) in nested_results.iter().take(count).enumerate() {
        let sub_attr = &mut sub_attrs[i];
        // Per PKCS#11 spec: type_ is set on output (ignored on input)
        sub_attr.type_ = sub_result.attr_type.0 as CK_ATTRIBUTE_TYPE;

        if let Some(bytes) = sub_result.value.as_ref()
            && !sub_attr.pValue.is_null()
            && bytes.len() <= sub_attr.ulValueLen as usize
        {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    sub_attr.pValue as *mut u8,
                    bytes.len(),
                );
            }
        }
        sub_attr.ulValueLen = sub_result.returned_len as CK_ULONG;
    }
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
        let template = unsafe { ck_attrs_to_rust(p_template, ul_count) };
        match with_client!(client => client.create_object(CkSessionHandle(h_session), &template)) {
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
        let template = unsafe { ck_attrs_to_rust(p_template, ul_count) };
        match with_client!(client => client.copy_object(
            CkSessionHandle(h_session),
            CkObjectHandle(h_object),
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
            CkSessionHandle(h_session),
            CkObjectHandle(h_object),
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
            CkSessionHandle(h_session),
            CkObjectHandle(h_object),
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
        let template = unsafe { ck_attrs_to_rust(p_template, ul_count) };
        unit_result_to_rv(with_client!(client => client.set_attribute_value(
            CkSessionHandle(h_session),
            CkObjectHandle(h_object),
            &template,
        )))
    })
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------
