// CK_ULONG is u64 on 64-bit and u32 on 32-bit; the `as u64` casts are
// intentional for cross-platform PKCS#11 portability.
#![allow(clippy::unnecessary_cast)]

use pkcs11_proxy_ng_types::*;

use super::ffi_conversion::{session_state_from_ck, utf8_trim};

pub(super) fn info_from_ck(info: &cryptoki_sys::CK_INFO) -> CkInfo {
    CkInfo {
        cryptoki_version: (info.cryptokiVersion.major, info.cryptokiVersion.minor),
        manufacturer_id: utf8_trim(&info.manufacturerID),
        flags: info.flags,
        library_description: utf8_trim(&info.libraryDescription),
        library_version: (info.libraryVersion.major, info.libraryVersion.minor),
    }
}

pub(super) fn slot_info_from_ck(info: &cryptoki_sys::CK_SLOT_INFO) -> CkSlotInfo {
    CkSlotInfo {
        slot_description: utf8_trim(&info.slotDescription),
        manufacturer_id: utf8_trim(&info.manufacturerID),
        flags: CkSlotFlags(info.flags),
        hardware_version: (info.hardwareVersion.major, info.hardwareVersion.minor),
        firmware_version: (info.firmwareVersion.major, info.firmwareVersion.minor),
    }
}

pub(super) fn token_info_from_ck(info: &cryptoki_sys::CK_TOKEN_INFO) -> CkTokenInfo {
    CkTokenInfo {
        label: utf8_trim(&info.label),
        manufacturer_id: utf8_trim(&info.manufacturerID),
        model: utf8_trim(&info.model),
        serial_number: utf8_trim(&info.serialNumber),
        flags: CkTokenFlags(info.flags),
        max_session_count: info.ulMaxSessionCount,
        session_count: info.ulSessionCount,
        max_rw_session_count: info.ulMaxRwSessionCount,
        rw_session_count: info.ulRwSessionCount,
        max_pin_len: info.ulMaxPinLen,
        min_pin_len: info.ulMinPinLen,
        total_public_memory: info.ulTotalPublicMemory,
        free_public_memory: info.ulFreePublicMemory,
        total_private_memory: info.ulTotalPrivateMemory,
        free_private_memory: info.ulFreePrivateMemory,
        hardware_version: (info.hardwareVersion.major, info.hardwareVersion.minor),
        firmware_version: (info.firmwareVersion.major, info.firmwareVersion.minor),
        utc_time: utf8_trim(&info.utcTime),
    }
}

pub(super) fn mechanism_info_from_ck(info: &cryptoki_sys::CK_MECHANISM_INFO) -> CkMechanismInfo {
    CkMechanismInfo {
        min_key_size: info.ulMinKeySize,
        max_key_size: info.ulMaxKeySize,
        flags: CkMechanismFlags(info.flags),
    }
}

pub(super) fn session_info_from_ck(info: &cryptoki_sys::CK_SESSION_INFO) -> CkSessionInfo {
    CkSessionInfo {
        slot_id: CkSlotId(info.slotID),
        state: session_state_from_ck(info.state),
        flags: CkSessionFlags(info.flags),
        device_error: info.ulDeviceError,
    }
}

pub(super) fn update_template_from_ffi(
    template: &mut [CkAttribute],
    attrs: &[cryptoki_sys::CK_ATTRIBUTE],
) {
    for (dst, src) in template.iter_mut().zip(attrs.iter()) {
        if src.ulValueLen == cryptoki_sys::CK_UNAVAILABLE_INFORMATION {
            dst.value = None;
            continue;
        }

        let provided_len = match &dst.value {
            None => None,
            Some(CkAttributeValue::Bool(_)) => Some(1),
            Some(CkAttributeValue::Ulong(_)) => Some(std::mem::size_of::<cryptoki_sys::CK_ULONG>()),
            Some(CkAttributeValue::Bytes(bytes)) => Some(bytes.len()),
            Some(CkAttributeValue::String(value)) => Some(value.len()),
        };
        let returned_len = src.ulValueLen as usize;

        if src.pValue.is_null() || provided_len.is_none() || returned_len > provided_len.unwrap() {
            dst.value = None;
            continue;
        }

        let bytes =
            unsafe { std::slice::from_raw_parts(src.pValue as *const u8, returned_len) }.to_vec();
        dst.value = Some(CkAttributeValue::Bytes(bytes));
    }
}

pub(super) fn exact_attribute_results_from_ffi(
    queries: &[CkAttributeQuery],
    attrs: &[cryptoki_sys::CK_ATTRIBUTE],
    overall_rv: CkRv,
) -> Vec<CkAttributeQueryResult> {
    queries
        .iter()
        .zip(attrs.iter())
        .map(|(query, attr)| {
            // For nested (CKF_ARRAY_ATTRIBUTE) queries with data, read sub-attributes
            if query.nested.is_some() && query.buffer_present && !attr.pValue.is_null() {
                return nested_attribute_result_from_ffi(query, attr, overall_rv);
            }

            let returned_len = attr.ulValueLen as u64;
            let unavailable = attr.ulValueLen == cryptoki_sys::CK_UNAVAILABLE_INFORMATION;
            let too_small = query.buffer_present && returned_len > query.buffer_len;
            let single_query_unavailable_status = if queries.len() == 1 && unavailable {
                match overall_rv {
                    CkRv::ATTRIBUTE_SENSITIVE
                    | CkRv::ATTRIBUTE_TYPE_INVALID
                    | CkRv::BUFFER_TOO_SMALL => Some(overall_rv),
                    _ => None,
                }
            } else {
                None
            };

            let ck_rv = if let Some(status) = single_query_unavailable_status {
                Some(status)
            } else if unavailable {
                None
            } else if too_small {
                Some(CkRv::BUFFER_TOO_SMALL)
            } else {
                None
            };

            let value = if unavailable || attr.pValue.is_null() || too_small {
                None
            } else {
                Some(
                    unsafe {
                        std::slice::from_raw_parts(
                            attr.pValue as *const u8,
                            attr.ulValueLen as usize,
                        )
                    }
                    .to_vec(),
                )
            };

            CkAttributeQueryResult {
                attr_type: query.attr_type,
                returned_len,
                value,
                ck_rv,
                nested: None,
            }
        })
        .collect()
}

/// Read back a nested `CK_ATTRIBUTE[]` result from a parent attribute after
/// the FFI call completes.
///
/// The parent's `pValue` points to the nested `CK_ATTRIBUTE` array that was
/// allocated in `FfiAttributeQueries::build_nested_attr`. The backend has
/// written back `ulValueLen` (and possibly `pValue` data) for each sub-attribute.
fn nested_attribute_result_from_ffi(
    query: &CkAttributeQuery,
    attr: &cryptoki_sys::CK_ATTRIBUTE,
    _overall_rv: CkRv,
) -> CkAttributeQueryResult {
    let returned_len = attr.ulValueLen as u64;
    let unavailable = attr.ulValueLen == cryptoki_sys::CK_UNAVAILABLE_INFORMATION;

    if unavailable {
        return CkAttributeQueryResult {
            attr_type: query.attr_type,
            returned_len,
            value: None,
            ck_rv: None,
            nested: None,
        };
    }

    let ck_attr_size = std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>();
    let nested_count = attr.ulValueLen as usize / ck_attr_size;
    let nested_queries = query.nested.as_deref().unwrap_or(&[]);

    let sub_attrs = unsafe {
        std::slice::from_raw_parts(attr.pValue as *const cryptoki_sys::CK_ATTRIBUTE, nested_count)
    };

    let nested_results: Vec<CkAttributeQueryResult> = sub_attrs
        .iter()
        .enumerate()
        .map(|(i, sub_attr)| {
            let sub_query = nested_queries.get(i);
            let sub_returned_len = sub_attr.ulValueLen as u64;
            let sub_unavailable = sub_attr.ulValueLen == cryptoki_sys::CK_UNAVAILABLE_INFORMATION;
            let sub_buffer_present = sub_query.is_some_and(|q| q.buffer_present);
            let sub_too_small =
                sub_buffer_present && sub_returned_len > sub_query.map_or(0, |q| q.buffer_len);

            let sub_ck_rv = if sub_unavailable {
                None
            } else if sub_too_small {
                Some(CkRv::BUFFER_TOO_SMALL)
            } else {
                None
            };

            let sub_value = if sub_unavailable || sub_attr.pValue.is_null() || sub_too_small {
                None
            } else {
                Some(
                    unsafe {
                        std::slice::from_raw_parts(
                            sub_attr.pValue as *const u8,
                            sub_attr.ulValueLen as usize,
                        )
                    }
                    .to_vec(),
                )
            };

            CkAttributeQueryResult {
                attr_type: CkAttributeType(sub_attr.type_),
                returned_len: sub_returned_len,
                value: sub_value,
                ck_rv: sub_ck_rv,
                nested: None,
            }
        })
        .collect();

    CkAttributeQueryResult {
        attr_type: query.attr_type,
        returned_len,
        value: None,
        ck_rv: None,
        nested: Some(nested_results),
    }
}

#[cfg(test)]
mod tests {
    use super::exact_attribute_results_from_ffi;
    use pkcs11_proxy_ng_types::{CkAttributeQuery, CkAttributeQueryResult, CkAttributeType, CkRv};

    #[test]
    fn exact_results_do_not_synthesize_bytes_for_null_pvalue() {
        let results = exact_attribute_results_from_ffi(
            &[CkAttributeQuery {
                attr_type: CkAttributeType::LABEL,
                buffer_present: false,
                buffer_len: 9,
                nested: None,
            }],
            &[cryptoki_sys::CK_ATTRIBUTE {
                type_: CkAttributeType::LABEL.0,
                pValue: std::ptr::null_mut(),
                ulValueLen: 3,
            }],
            CkRv::OK,
        );

        assert_eq!(
            results,
            vec![CkAttributeQueryResult {
                attr_type: CkAttributeType::LABEL,
                returned_len: 3,
                value: None,
                ck_rv: None,
                nested: None,
            }]
        );
    }

    #[test]
    fn exact_results_recover_single_query_sensitive_status_from_overall_rv() {
        let results = exact_attribute_results_from_ffi(
            &[CkAttributeQuery {
                attr_type: CkAttributeType::VALUE,
                buffer_present: true,
                buffer_len: 2,
                nested: None,
            }],
            &[cryptoki_sys::CK_ATTRIBUTE {
                type_: CkAttributeType::VALUE.0,
                pValue: std::ptr::null_mut(),
                ulValueLen: cryptoki_sys::CK_UNAVAILABLE_INFORMATION,
            }],
            CkRv::ATTRIBUTE_SENSITIVE,
        );

        assert_eq!(
            results,
            vec![CkAttributeQueryResult {
                attr_type: CkAttributeType::VALUE,
                returned_len: u64::MAX,
                value: None,
                ck_rv: Some(CkRv::ATTRIBUTE_SENSITIVE),
                nested: None,
            }]
        );
    }

    #[test]
    fn exact_results_recover_single_query_buffer_too_small_status_from_overall_rv() {
        let results = exact_attribute_results_from_ffi(
            &[CkAttributeQuery {
                attr_type: CkAttributeType::VALUE,
                buffer_present: true,
                buffer_len: 2,
                nested: None,
            }],
            &[cryptoki_sys::CK_ATTRIBUTE {
                type_: CkAttributeType::VALUE.0,
                pValue: std::ptr::null_mut(),
                ulValueLen: cryptoki_sys::CK_UNAVAILABLE_INFORMATION,
            }],
            CkRv::BUFFER_TOO_SMALL,
        );

        assert_eq!(
            results,
            vec![CkAttributeQueryResult {
                attr_type: CkAttributeType::VALUE,
                returned_len: u64::MAX,
                value: None,
                ck_rv: Some(CkRv::BUFFER_TOO_SMALL),
                nested: None,
            }]
        );
    }

    #[test]
    fn exact_results_do_not_infer_ambiguous_multi_query_statuses() {
        let results = exact_attribute_results_from_ffi(
            &[
                CkAttributeQuery {
                    attr_type: CkAttributeType::VALUE,
                    buffer_present: true,
                    buffer_len: 2,
                    nested: None,
                },
                CkAttributeQuery {
                    attr_type: CkAttributeType::LABEL,
                    buffer_present: false,
                    buffer_len: 0,
                    nested: None,
                },
            ],
            &[
                cryptoki_sys::CK_ATTRIBUTE {
                    type_: CkAttributeType::VALUE.0,
                    pValue: std::ptr::null_mut(),
                    ulValueLen: cryptoki_sys::CK_UNAVAILABLE_INFORMATION,
                },
                cryptoki_sys::CK_ATTRIBUTE {
                    type_: CkAttributeType::LABEL.0,
                    pValue: std::ptr::null_mut(),
                    ulValueLen: cryptoki_sys::CK_UNAVAILABLE_INFORMATION,
                },
            ],
            CkRv::ATTRIBUTE_SENSITIVE,
        );

        assert_eq!(
            results,
            vec![
                CkAttributeQueryResult {
                    attr_type: CkAttributeType::VALUE,
                    returned_len: u64::MAX,
                    value: None,
                    ck_rv: None,
                    nested: None,
                },
                CkAttributeQueryResult {
                    attr_type: CkAttributeType::LABEL,
                    returned_len: u64::MAX,
                    value: None,
                    ck_rv: None,
                    nested: None,
                },
            ]
        );
    }

    #[test]
    fn exact_results_recover_single_query_invalid_type_status_from_overall_rv() {
        let results = exact_attribute_results_from_ffi(
            &[CkAttributeQuery {
                attr_type: CkAttributeType::VALUE,
                buffer_present: true,
                buffer_len: 2,
                nested: None,
            }],
            &[cryptoki_sys::CK_ATTRIBUTE {
                type_: CkAttributeType::VALUE.0,
                pValue: std::ptr::null_mut(),
                ulValueLen: cryptoki_sys::CK_UNAVAILABLE_INFORMATION,
            }],
            CkRv::ATTRIBUTE_TYPE_INVALID,
        );

        assert_eq!(
            results,
            vec![CkAttributeQueryResult {
                attr_type: CkAttributeType::VALUE,
                returned_len: u64::MAX,
                value: None,
                ck_rv: Some(CkRv::ATTRIBUTE_TYPE_INVALID),
                nested: None,
            }]
        );
    }
}
