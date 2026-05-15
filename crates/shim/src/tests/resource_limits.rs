use super::*;

fn nested_attr(type_: CK_ATTRIBUTE_TYPE, ul_value_len: CK_ULONG) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE { type_, pValue: std::ptr::null_mut(), ulValueLen: ul_value_len }
}

#[test]
fn c_get_attribute_value_rejects_malformed_nested_template_length_before_client_use() {
    let _guard = shim_state_test_guard();
    let mut sub_attr = nested_attr(CKA_LABEL, 0);
    let mut attr = CK_ATTRIBUTE {
        type_: pkcs11_proxy_ng_types::CkAttributeType::WRAP_TEMPLATE.0 as CK_ATTRIBUTE_TYPE,
        pValue: (&mut sub_attr as *mut CK_ATTRIBUTE).cast(),
        ulValueLen: (std::mem::size_of::<CK_ATTRIBUTE>() + 1) as CK_ULONG,
    };

    let rv = unsafe { dispatch::general::c_get_attribute_value(0, 0, &mut attr, 1) };

    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_attribute_value_rejects_oversized_nested_template_before_client_use() {
    let _guard = shim_state_test_guard();
    let mut sub_attrs = vec![nested_attr(CKA_LABEL, 0); dispatch::general::MAX_TEMPLATE_COUNT + 1];
    let mut attr = CK_ATTRIBUTE {
        type_: pkcs11_proxy_ng_types::CkAttributeType::WRAP_TEMPLATE.0 as CK_ATTRIBUTE_TYPE,
        pValue: sub_attrs.as_mut_ptr().cast(),
        ulValueLen: (sub_attrs.len() * std::mem::size_of::<CK_ATTRIBUTE>()) as CK_ULONG,
    };

    let rv = unsafe { dispatch::general::c_get_attribute_value(0, 0, &mut attr, 1) };

    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}
