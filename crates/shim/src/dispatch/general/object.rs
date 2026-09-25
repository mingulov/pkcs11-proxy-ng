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
        if p_template.is_null() && ul_count != 0 {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let n = ul_count as usize;
        if n > MAX_TEMPLATE_COUNT {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        // Width bridge (ADR-0011): the client's own CK_ULONG width vs the
        // backend's advertised width. Equal in the common deployment, in which
        // case every bridge step below is a verified no-op.
        let client_width = std::mem::size_of::<CK_ULONG>();
        let backend_width = crate::interface_probe::backend_ulong_size();
        let client_stride = std::mem::size_of::<CK_ATTRIBUTE>();
        let backend_stride = crate::interface_probe::backend_attribute_stride();
        let query_result: CkResult<Vec<CkAttributeQuery>> = {
            let slice = unsafe { read_input_slice(p_template, ul_count) };
            slice
                .iter()
                .map(|a| build_attribute_query(a, client_width, backend_width, backend_stride))
                .collect()
        };
        let queries: Vec<CkAttributeQuery> = match query_result {
            Ok(queries) => queries,
            Err(rv) => return rv_err(rv),
        };

        match with_client!(client => client.get_attribute_value_exact(
            CkSessionHandle(h_session as u64),
            CkObjectHandle(h_object as u64),
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
                            // Nested CK_ATTRIBUTE[] template: write back the
                            // sub-attribute results (width-bridging each ulong
                            // sub-value and reporting a client-layout length).
                            write_nested_result_to_ffi(c_attr, result, client_width, backend_width);
                            continue;
                        }

                        // A CKA_*_TEMPLATE pure size query (pValue = NULL, so no
                        // nested sub-queries were built) reports the BACKEND-layout
                        // template byte length on the wire; rescale it to the
                        // client's CK_ATTRIBUTE stride.
                        if query.attr_type.is_attribute_template() && result.nested.is_none() {
                            c_attr.ulValueLen = super::width_bridge::bridge_template_output_len(
                                result.returned_len,
                                backend_stride,
                                client_stride,
                            ) as CK_ULONG;
                            continue;
                        }

                        // Width-bridge a ulong-typed value to the client width
                        // (no-op for opaque attributes and same-width edges). The
                        // caller's original buffer length is still in ulValueLen
                        // (we overwrite it last), since query.buffer_len may have
                        // been inflated to the backend width.
                        let caller_buf_len = c_attr.ulValueLen as usize;
                        match super::width_bridge::bridge_output_value(
                            query.attr_type,
                            result.value.as_deref(),
                            result.returned_len,
                            backend_width,
                            client_width,
                        ) {
                            Ok((client_value, client_len)) => {
                                if query.buffer_present
                                    && let Some(bytes) = client_value.as_ref()
                                    && bytes.len() <= caller_buf_len
                                    && !c_attr.pValue.is_null()
                                {
                                    std::ptr::copy_nonoverlapping(
                                        bytes.as_ptr(),
                                        c_attr.pValue as *mut u8,
                                        bytes.len(),
                                    );
                                }
                                c_attr.ulValueLen = client_len as CK_ULONG;
                            }
                            Err(_overflow) => {
                                // D4: a genuine backend value exceeds the client's
                                // CK_ULONG range. Surface the attribute as
                                // unavailable rather than truncating or failing
                                // the whole call (never fires for real providers).
                                c_attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            }
                        }
                    }
                }
                if server_rv == CkRv::OK { rv_ok() } else { rv_err(server_rv) }
            }
        }
    })
}

/// Build a `CkAttributeQuery` from a caller-provided `CK_ATTRIBUTE`.
///
/// If the attribute type is a `CK_ATTRIBUTE[]` template (CKA_WRAP_TEMPLATE /
/// CKA_UNWRAP_TEMPLATE / CKA_DERIVE_TEMPLATE) and `pValue` is non-null,
/// interprets `pValue` as a `CK_ATTRIBUTE[]` template and builds nested
/// sub-queries for each entry. Other array-flagged attributes (e.g.
/// CKA_ALLOWED_MECHANISMS, a `CK_MECHANISM_TYPE[]`) are treated as opaque
/// values, not nested templates.
fn build_attribute_query(
    a: &CK_ATTRIBUTE,
    client_width: usize,
    backend_width: usize,
    backend_stride: usize,
) -> CkResult<CkAttributeQuery> {
    let attr_type = CkAttributeType(a.type_ as u64);
    let buffer_present = !a.pValue.is_null();

    if attr_type.is_attribute_template() && buffer_present {
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
                .map(|sub| {
                    let sub_type = CkAttributeType(sub.type_ as u64);
                    CkAttributeQuery {
                        attr_type: sub_type,
                        buffer_present: !sub.pValue.is_null(),
                        // Inflate a ulong sub-attribute's buffer length to the
                        // backend width (no-op otherwise) so the backend's nested
                        // template buffer holds the full-width value.
                        buffer_len: super::width_bridge::bridge_request_buffer_len(
                            sub_type,
                            sub.ulValueLen as u64,
                            client_width,
                            backend_width,
                        ),
                        nested: None,
                    }
                })
                .collect();
            return Ok(CkAttributeQuery {
                attr_type,
                buffer_present,
                // The outer template buffer length counts CLIENT-layout
                // CK_ATTRIBUTEs; the backend sizes its one exact call in its
                // own layout, so rescale by stride.
                buffer_len: super::width_bridge::bridge_template_request_len(
                    a.ulValueLen as u64,
                    ck_attr_size,
                    backend_stride,
                ),
                nested: Some(nested),
            });
        }
    }

    let buffer_len = if attr_type.is_attribute_template() {
        // Template attr without parsed sub-queries (size query or empty
        // template): the length still counts client-layout CK_ATTRIBUTEs.
        super::width_bridge::bridge_template_request_len(
            a.ulValueLen as u64,
            std::mem::size_of::<CK_ATTRIBUTE>(),
            backend_stride,
        )
    } else {
        // Inflate a ulong-typed buffer length to the backend width so the
        // backend's one exact FFI call allocates enough; no-op otherwise.
        super::width_bridge::bridge_request_buffer_len(
            attr_type,
            a.ulValueLen as u64,
            client_width,
            backend_width,
        )
    };
    Ok(CkAttributeQuery { attr_type, buffer_present, buffer_len, nested: None })
}

/// Write nested `CkAttributeQueryResult` items back into the caller's
/// `CK_ATTRIBUTE[]` template (the sub-attributes pointed to by `pValue`).
///
/// # Safety
///
/// `c_attr.pValue` must point to a valid `CK_ATTRIBUTE[]` array with at least
/// as many entries as `result.nested` contains.
unsafe fn write_nested_result_to_ffi(
    c_attr: &mut CK_ATTRIBUTE,
    result: &CkAttributeQueryResult,
    client_width: usize,
    backend_width: usize,
) {
    let Some(nested_results) = result.nested.as_ref() else {
        // Not actually a nested template result; preserve the backend length.
        c_attr.ulValueLen = result.returned_len as CK_ULONG;
        return;
    };

    let ck_attr_size = std::mem::size_of::<CK_ATTRIBUTE>();
    // The template's required output size is N *client-layout* CK_ATTRIBUTEs. N
    // is the wire result count; the local CK_ATTRIBUTE size (a pointer/packing
    // concern) is the client's own and is independent of the backend's struct
    // size — so this is correct across differing pointer widths, not just
    // differing CK_ULONG widths.
    let needed_len = (nested_results.len() * ck_attr_size) as CK_ULONG;

    if c_attr.pValue.is_null() {
        // Size query: report the client-layout template size.
        c_attr.ulValueLen = needed_len;
        return;
    }

    let capacity = (c_attr.ulValueLen as usize).checked_div(ck_attr_size).unwrap_or(0);
    let count = nested_results.len().min(capacity);

    let sub_attrs = unsafe { write_output_slice(c_attr.pValue as *mut CK_ATTRIBUTE, count) };

    for (i, sub_result) in nested_results.iter().take(count).enumerate() {
        let sub_attr = &mut sub_attrs[i];
        // Per PKCS#11 spec: type_ is set on output (ignored on input)
        sub_attr.type_ = sub_result.attr_type.0 as CK_ATTRIBUTE_TYPE;

        // Caller's original sub-buffer size (we overwrite ulValueLen last).
        let sub_buf_len = sub_attr.ulValueLen as usize;
        // Width-bridge a ulong sub-value to the client width (no-op for opaque
        // sub-attributes and same-width edges).
        match super::width_bridge::bridge_output_value(
            sub_result.attr_type,
            sub_result.value.as_deref(),
            sub_result.returned_len,
            backend_width,
            client_width,
        ) {
            Ok((client_value, client_len)) => {
                if let Some(bytes) = client_value.as_ref()
                    && !sub_attr.pValue.is_null()
                    && bytes.len() <= sub_buf_len
                {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            sub_attr.pValue as *mut u8,
                            bytes.len(),
                        );
                    }
                }
                sub_attr.ulValueLen = client_len as CK_ULONG;
            }
            Err(_overflow) => {
                // D4: a genuine sub-value exceeds the client's CK_ULONG range.
                sub_attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
            }
        }
    }
    // Report the full needed (client-layout) size, even if the caller's buffer
    // held fewer entries — matches PKCS#11 buffer-too-small semantics.
    c_attr.ulValueLen = needed_len;
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
            attr_type: CkAttributeType::WRAP_TEMPLATE,
            returned_len: (2 * ck_attr_size) as u64,
            value: None,
            ck_rv: None,
            nested: Some(vec![
                CkAttributeQueryResult {
                    attr_type: CkAttributeType::KEY_TYPE,
                    returned_len: w as u64,
                    value: Some(key_type_bytes.clone()),
                    ck_rv: None,
                    nested: None,
                },
                CkAttributeQueryResult {
                    attr_type: CkAttributeType::LABEL,
                    returned_len: 1,
                    value: Some(b"k".to_vec()),
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
        assert_eq!(subs[1].ulValueLen, 1);
        assert_eq!(&label_buf[..1], b"k", "byte sub-value written");
    }
}
