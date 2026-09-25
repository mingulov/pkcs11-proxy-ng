// CK_ULONG is u64 on 64-bit and u32 on 32-bit; the `as u64` casts are
// intentional for cross-platform PKCS#11 portability.
#![allow(clippy::unnecessary_cast)]

use pkcs11_proxy_ng_types::*;

use super::ffi_conversion::{session_state_from_ck, utf8_trim};

pub(super) fn info_from_ck(info: &cryptoki_sys::CK_INFO) -> CkInfo {
    CkInfo {
        cryptoki_version: (info.cryptokiVersion.major, info.cryptokiVersion.minor),
        manufacturer_id: utf8_trim(&info.manufacturerID),
        flags: info.flags as u64,
        library_description: utf8_trim(&info.libraryDescription),
        library_version: (info.libraryVersion.major, info.libraryVersion.minor),
    }
}

pub(super) fn slot_info_from_ck(info: &cryptoki_sys::CK_SLOT_INFO) -> CkSlotInfo {
    CkSlotInfo {
        slot_description: utf8_trim(&info.slotDescription),
        manufacturer_id: utf8_trim(&info.manufacturerID),
        flags: CkSlotFlags(info.flags as u64),
        hardware_version: (info.hardwareVersion.major, info.hardwareVersion.minor),
        firmware_version: (info.firmwareVersion.major, info.firmwareVersion.minor),
    }
}

pub(super) fn token_info_from_ck(info: &cryptoki_sys::CK_TOKEN_INFO) -> CkTokenInfo {
    // The session-count and memory fields may be CK_UNAVAILABLE_INFORMATION
    // (all-ones of the backend's CK_ULONG width). Canonicalise that sentinel to
    // the width-independent wire form so an any-width client recognises it
    // (ADR-0011); the PIN-length, version, and string fields are never the
    // sentinel and pass through unchanged.
    let backend_width = std::mem::size_of::<cryptoki_sys::CK_ULONG>();
    let canon = |v: cryptoki_sys::CK_ULONG| {
        pkcs11_proxy_ng_types::width::canonicalize_ulong(v as u64, backend_width)
    };
    CkTokenInfo {
        label: utf8_trim(&info.label),
        manufacturer_id: utf8_trim(&info.manufacturerID),
        model: utf8_trim(&info.model),
        serial_number: utf8_trim(&info.serialNumber),
        flags: CkTokenFlags(info.flags as u64),
        max_session_count: canon(info.ulMaxSessionCount),
        session_count: canon(info.ulSessionCount),
        max_rw_session_count: canon(info.ulMaxRwSessionCount),
        rw_session_count: canon(info.ulRwSessionCount),
        max_pin_len: info.ulMaxPinLen as u64,
        min_pin_len: info.ulMinPinLen as u64,
        total_public_memory: canon(info.ulTotalPublicMemory),
        free_public_memory: canon(info.ulFreePublicMemory),
        total_private_memory: canon(info.ulTotalPrivateMemory),
        free_private_memory: canon(info.ulFreePrivateMemory),
        hardware_version: (info.hardwareVersion.major, info.hardwareVersion.minor),
        firmware_version: (info.firmwareVersion.major, info.firmwareVersion.minor),
        utc_time: utf8_trim(&info.utcTime),
    }
}

pub(super) fn mechanism_info_from_ck(info: &cryptoki_sys::CK_MECHANISM_INFO) -> CkMechanismInfo {
    CkMechanismInfo {
        min_key_size: info.ulMinKeySize as u64,
        max_key_size: info.ulMaxKeySize as u64,
        flags: CkMechanismFlags(info.flags as u64),
    }
}

pub(super) fn session_info_from_ck(info: &cryptoki_sys::CK_SESSION_INFO) -> CkSessionInfo {
    CkSessionInfo {
        slot_id: CkSlotId(info.slotID as u64),
        state: session_state_from_ck(info.state),
        flags: CkSessionFlags(info.flags as u64),
        device_error: info.ulDeviceError as u64,
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
            // The legacy C_GetAttributeValue path does not carry nested
            // templates (the exact path does); treat as absent.
            Some(CkAttributeValue::NestedTemplate(_)) => None,
        };
        let returned_len = src.ulValueLen as usize;

        if src.pValue.is_null() || provided_len.is_none_or(|len| returned_len > len) {
            dst.value = None;
            continue;
        }

        let bytes =
            unsafe { std::slice::from_raw_parts(src.pValue as *const u8, returned_len) }.to_vec();
        dst.value = Some(CkAttributeValue::Bytes(bytes.into()));
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

            let unavailable = attr.ulValueLen == cryptoki_sys::CK_UNAVAILABLE_INFORMATION;
            // Canonicalise the platform-sized CK_UNAVAILABLE_INFORMATION sentinel
            // to a width-independent wire value (ADR-0011) so any-width client
            // recognises it; non-sentinel lengths stay native for width rescaling.
            let returned_len = if unavailable {
                pkcs11_proxy_ng_types::width::CANONICAL_UNAVAILABLE
            } else {
                attr.ulValueLen as u64
            };
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

            // Values are read separately from FfiAttributeQueries' owned allocations.

            CkAttributeQueryResult {
                apply_returned_len: query.buffer_present
                    || pkcs11_proxy_ng_types::attribute_outputs_defined(overall_rv)
                    || returned_len != 0,
                apply_type: false,
                attr_type: query.attr_type,
                returned_len,
                value: None,
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
    let unavailable = attr.ulValueLen == cryptoki_sys::CK_UNAVAILABLE_INFORMATION;
    let returned_len = if unavailable {
        pkcs11_proxy_ng_types::width::CANONICAL_UNAVAILABLE
    } else {
        attr.ulValueLen as u64
    };

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
            let sub_unavailable = sub_attr.ulValueLen == cryptoki_sys::CK_UNAVAILABLE_INFORMATION;
            let sub_returned_len = if sub_unavailable {
                pkcs11_proxy_ng_types::width::CANONICAL_UNAVAILABLE
            } else {
                sub_attr.ulValueLen as u64
            };
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
                attr_type: CkAttributeType(sub_attr.type_ as u64),
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
                type_: CkAttributeType::LABEL.0 as _,
                pValue: std::ptr::null_mut(),
                ulValueLen: 3,
            }],
            CkRv::OK,
        );

        assert_eq!(
            results,
            vec![CkAttributeQueryResult {
                apply_returned_len: true,
                apply_type: false,
                attr_type: CkAttributeType::LABEL,
                returned_len: 3,
                value: None,
                ck_rv: None,
                nested: None,
            }]
        );
    }

    #[test]
    fn token_info_canonicalizes_unavailable_sentinel_fields() {
        // The eight CK_TOKEN_INFO fields the spec allows to be
        // CK_UNAVAILABLE_INFORMATION must reach the wire as the canonical,
        // width-independent sentinel (u64::MAX) so an any-width client
        // recognises them. On a 32-bit backend the native sentinel is
        // 0xFFFF_FFFF, which a 64-bit client would otherwise read as a literal
        // ~4-billion value rather than "no information available".
        let mut info = cryptoki_sys::CK_TOKEN_INFO::default();
        let unavail = cryptoki_sys::CK_UNAVAILABLE_INFORMATION;
        info.ulMaxSessionCount = unavail;
        info.ulSessionCount = unavail;
        info.ulMaxRwSessionCount = unavail;
        info.ulRwSessionCount = unavail;
        info.ulTotalPublicMemory = unavail;
        info.ulFreePublicMemory = unavail;
        info.ulTotalPrivateMemory = unavail;
        info.ulFreePrivateMemory = unavail;
        // PIN-length fields are never the sentinel; they must pass through.
        info.ulMaxPinLen = 32;
        info.ulMinPinLen = 4;

        let out = super::token_info_from_ck(&info);

        let canon = pkcs11_proxy_ng_types::width::CANONICAL_UNAVAILABLE;
        assert_eq!(out.max_session_count, canon);
        assert_eq!(out.session_count, canon);
        assert_eq!(out.max_rw_session_count, canon);
        assert_eq!(out.rw_session_count, canon);
        assert_eq!(out.total_public_memory, canon);
        assert_eq!(out.free_public_memory, canon);
        assert_eq!(out.total_private_memory, canon);
        assert_eq!(out.free_private_memory, canon);
        assert_eq!(out.max_pin_len, 32);
        assert_eq!(out.min_pin_len, 4);
    }

    #[test]
    fn token_info_passes_through_real_values_and_effectively_infinite() {
        let info = cryptoki_sys::CK_TOKEN_INFO {
            ulMaxSessionCount: 0, // CK_EFFECTIVELY_INFINITE — a real value
            ulSessionCount: 3,
            ulTotalPublicMemory: 4096,
            ..Default::default()
        };

        let out = super::token_info_from_ck(&info);

        assert_eq!(out.max_session_count, 0);
        assert_eq!(out.session_count, 3);
        assert_eq!(out.total_public_memory, 4096);
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
                type_: CkAttributeType::VALUE.0 as _,
                pValue: std::ptr::null_mut(),
                ulValueLen: cryptoki_sys::CK_UNAVAILABLE_INFORMATION,
            }],
            CkRv::ATTRIBUTE_SENSITIVE,
        );

        assert_eq!(
            results,
            vec![CkAttributeQueryResult {
                apply_returned_len: true,
                apply_type: false,
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
                type_: CkAttributeType::VALUE.0 as _,
                pValue: std::ptr::null_mut(),
                ulValueLen: cryptoki_sys::CK_UNAVAILABLE_INFORMATION,
            }],
            CkRv::BUFFER_TOO_SMALL,
        );

        assert_eq!(
            results,
            vec![CkAttributeQueryResult {
                apply_returned_len: true,
                apply_type: false,
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
                    type_: CkAttributeType::VALUE.0 as _,
                    pValue: std::ptr::null_mut(),
                    ulValueLen: cryptoki_sys::CK_UNAVAILABLE_INFORMATION,
                },
                cryptoki_sys::CK_ATTRIBUTE {
                    type_: CkAttributeType::LABEL.0 as _,
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
                    apply_returned_len: true,
                    apply_type: false,
                    attr_type: CkAttributeType::VALUE,
                    returned_len: u64::MAX,
                    value: None,
                    ck_rv: None,
                    nested: None,
                },
                CkAttributeQueryResult {
                    apply_returned_len: true,
                    apply_type: false,
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
                type_: CkAttributeType::VALUE.0 as _,
                pValue: std::ptr::null_mut(),
                ulValueLen: cryptoki_sys::CK_UNAVAILABLE_INFORMATION,
            }],
            CkRv::ATTRIBUTE_TYPE_INVALID,
        );

        assert_eq!(
            results,
            vec![CkAttributeQueryResult {
                apply_returned_len: true,
                apply_type: false,
                attr_type: CkAttributeType::VALUE,
                returned_len: u64::MAX,
                value: None,
                ck_rv: Some(CkRv::ATTRIBUTE_TYPE_INVALID),
                nested: None,
            }]
        );
    }
}
