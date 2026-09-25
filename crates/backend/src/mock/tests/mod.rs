//! MockBackend test suite, split by domain. Shared fixtures/helpers
//! live here in `mod.rs`; each child pulls them (plus the mock items)
//! in via `use super::*`.

mod derive;
mod exact_outputs;
mod profiles;
mod rest;
mod session_state;
mod workflows;

use super::*;
use pkcs11_proxy_ng_proto::convert::message_params::{
    CcmMessageParams, GcmMessageParams, MessageParameter, Salsa20ChaCha20Poly1305MessageParams,
};

fn unsupported_mechanism_fixture()
-> (MockBackend, CkSessionHandle, CkObjectHandle, CkObjectHandle, CkMechanism) {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::SHA256]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let key = live_key(&backend, session);
    let other_key = live_key(&backend, session);
    let mechanism = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    (backend, session, key, other_key, mechanism)
}

fn label_attr(label: &str) -> CkAttribute {
    CkAttribute {
        attr_type: CkAttributeType::LABEL,
        value: Some(CkAttributeValue::String(label.to_string())),
    }
}

fn live_key(backend: &MockBackend, session: CkSessionHandle) -> CkObjectHandle {
    backend.create_object(session, &[label_attr("key")]).unwrap()
}

fn exact_size_spec() -> CkOutputBufferSpec {
    CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: false }
}

fn exact_data_spec() -> CkOutputBufferSpec {
    CkOutputBufferSpec { buffer_present: true, buffer_len: 1024, length_pointer_null: false }
}

fn exact_param_size_spec() -> CkParameterRoundtripSpec {
    CkParameterRoundtripSpec { buffer_present: false, buffer_len: 0, value: None }
}

fn exact_param_data_spec() -> CkParameterRoundtripSpec {
    CkParameterRoundtripSpec { buffer_present: true, buffer_len: 1024, value: None }
}

fn assert_exact_byte_result(
    workflow: &str,
    mechanism_type: CkMechanismType,
    buffer_present: bool,
    result: CkOutputBufferResult,
) {
    assert_eq!(result.ck_rv, CkRv::OK, "{workflow} rv for 0x{:08X}", mechanism_type.0);
    if buffer_present {
        let value = result.value.unwrap_or_else(|| {
            panic!("{workflow} data query value for 0x{:08X}", mechanism_type.0)
        });
        assert_eq!(
            result.returned_len as usize,
            value.len(),
            "{workflow} data query length for 0x{:08X}",
            mechanism_type.0
        );
    } else {
        assert!(
            result.value.is_none(),
            "{workflow} size query value for 0x{:08X}",
            mechanism_type.0
        );
    }
}

fn assert_exact_byte_size_and_data<F>(workflow: &str, mechanism_type: CkMechanismType, mut run: F)
where
    F: FnMut(&CkOutputBufferSpec) -> CkResult<CkOutputBufferResult>,
{
    let size_result = run(&exact_size_spec()).unwrap();
    assert_exact_byte_result(workflow, mechanism_type, false, size_result);
    let data_result = run(&exact_data_spec()).unwrap();
    assert_exact_byte_result(workflow, mechanism_type, true, data_result);
}

fn assert_exact_parameter_result(
    workflow: &str,
    mechanism_type: CkMechanismType,
    buffer_present: bool,
    result: CkParameterRoundtripResult,
) {
    assert_eq!(result.ck_rv, CkRv::OK, "{workflow} param rv for 0x{:08X}", mechanism_type.0);
    if buffer_present {
        let value = result
            .value
            .unwrap_or_else(|| panic!("{workflow} param data for 0x{:08X}", mechanism_type.0));
        assert_eq!(
            result.returned_len as usize,
            value.len(),
            "{workflow} param length for 0x{:08X}",
            mechanism_type.0
        );
    } else {
        assert!(
            result.value.is_none(),
            "{workflow} param size value for 0x{:08X}",
            mechanism_type.0
        );
    }
}

fn assert_exact_parameter_size_and_data<F>(
    workflow: &str,
    mechanism_type: CkMechanismType,
    mut run: F,
) where
    F: FnMut(
        &CkOutputBufferSpec,
        &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)>,
{
    let (size_output, size_param) = run(&exact_size_spec(), &exact_param_size_spec()).unwrap();
    assert_exact_byte_result(workflow, mechanism_type, false, size_output);
    assert_exact_parameter_result(workflow, mechanism_type, false, size_param);

    let (data_output, data_param) = run(&exact_data_spec(), &exact_param_data_spec()).unwrap();
    assert_exact_byte_result(workflow, mechanism_type, true, data_output);
    assert_exact_parameter_result(workflow, mechanism_type, true, data_param);
}

fn assert_exact_handle_size_and_data<F>(workflow: &str, mechanism_type: CkMechanismType, mut run: F)
where
    F: FnMut(&CkOutputBufferSpec) -> CkResult<CkOutputAndHandleResult>,
{
    let size_result = run(&exact_size_spec()).unwrap();
    assert_eq!(size_result.ck_rv, CkRv::OK, "{workflow} size rv for 0x{:08X}", mechanism_type.0);
    assert!(size_result.value.is_none(), "{workflow} size value for 0x{:08X}", mechanism_type.0);
    assert_eq!(
        size_result.object_handle,
        CkObjectHandle(0),
        "{workflow} size query handle for 0x{:08X}",
        mechanism_type.0
    );

    let data_result = run(&exact_data_spec()).unwrap();
    assert_eq!(data_result.ck_rv, CkRv::OK, "{workflow} data rv for 0x{:08X}", mechanism_type.0);
    let value = data_result
        .value
        .unwrap_or_else(|| panic!("{workflow} data value for 0x{:08X}", mechanism_type.0));
    assert_eq!(
        data_result.returned_len as usize,
        value.len(),
        "{workflow} data length for 0x{:08X}",
        mechanism_type.0
    );
    assert_ne!(
        data_result.object_handle,
        CkObjectHandle(0),
        "{workflow} data query handle for 0x{:08X}",
        mechanism_type.0
    );
}

fn sp800_108_counter_iteration_param() -> PrfDataParam {
    const CK_SP800_108_ITERATION_VARIABLE: u64 = 0x0000_0001;

    PrfDataParam { type_: CK_SP800_108_ITERATION_VARIABLE, value: sp800_108_counter_format_bytes() }
}

fn sp800_108_null_iteration_param() -> PrfDataParam {
    const CK_SP800_108_ITERATION_VARIABLE: u64 = 0x0000_0001;

    PrfDataParam { type_: CK_SP800_108_ITERATION_VARIABLE, value: Vec::new() }
}

fn sp800_108_counter_format_bytes() -> Vec<u8> {
    vec![0; std::mem::size_of::<cryptoki_sys::CK_SP800_108_COUNTER_FORMAT>()]
}

fn sp800_108_dkm_length_format_bytes() -> Vec<u8> {
    sp800_108_dkm_length_format_bytes_with_method(1)
}

fn sp800_108_dkm_length_format_bytes_with_method(method: u64) -> Vec<u8> {
    let mut bytes = vec![0; std::mem::size_of::<cryptoki_sys::CK_SP800_108_DKM_LENGTH_FORMAT>()];
    match std::mem::size_of::<cryptoki_sys::CK_ULONG>() {
        8 => bytes[..8].copy_from_slice(&method.to_ne_bytes()),
        4 => bytes[..4].copy_from_slice(&(method as u32).to_ne_bytes()),
        _ => unreachable!("unsupported CK_ULONG width"),
    }
    bytes
}

const CKM_SHA256_HMAC: u64 = 0x0000_0251;

fn assert_mock_label(
    backend: &MockBackend,
    session: CkSessionHandle,
    object: CkObjectHandle,
    expected: &str,
) {
    let (rv, results) = backend
        .get_attribute_value_exact(
            session,
            object,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::LABEL,
                buffer_present: true,
                buffer_len: expected.len() as u64,
                nested: None,
            }],
        )
        .unwrap();
    assert_eq!(rv, CkRv::OK);
    assert_eq!(results[0].value, Some(expected.as_bytes().to_vec()));
}

fn assert_invalid_session_does_not_allocate_object<R: std::fmt::Debug>(
    operation: impl FnOnce(&MockBackend, CkSessionHandle, &CkMechanism) -> CkResult<R>,
) {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let invalid_session = CkSessionHandle(999);
    let mechanism =
        CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN, params: None };

    let err = operation(&backend, invalid_session, &mechanism).unwrap_err();

    assert_eq!(err, CkRv::SESSION_HANDLE_INVALID);
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(
        backend.destroy_object(session, CkObjectHandle(1)).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID,
        "invalid-session operation must not allocate a hidden object"
    );
}

fn signal_live_handles(
    backend: &MockBackend,
    session: CkSessionHandle,
    count: usize,
) -> Vec<CkObjectHandle> {
    (0..count).map(|_| live_key(backend, session)).collect()
}

fn expect_signal_derive_param_invalid(
    backend: &MockBackend,
    session: CkSessionHandle,
    mechanism_type: CkMechanismType,
    params: CkMechanismParams,
    label: &str,
) {
    let base_key = live_key(backend, session);
    let mechanism = CkMechanism { mechanism_type, params: Some(params) };

    assert_eq!(
        backend.derive_key(session, &mechanism, base_key, &[label_attr("derived")]).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID,
        "{label} should reject invalid source-defined handle fields"
    );
    assert_eq!(
        backend
            .derive_key_with_output(session, &mechanism, base_key, &[label_attr("derived")])
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID,
        "{label} exact/output path should reject invalid source-defined handle fields"
    );
}

fn cms_sig_mechanism(certificate_handle: CkObjectHandle) -> CkMechanism {
    CkMechanism {
        mechanism_type: CkMechanismType::CMS_SIG,
        params: Some(CkMechanismParams::CmsSig(CmsSigParams {
            certificate_handle: certificate_handle.0,
            signing_mechanism: Box::new(CkMechanism {
                mechanism_type: CkMechanismType::RSA_PKCS,
                params: None,
            }),
            digest_mechanism: Box::new(CkMechanism {
                mechanism_type: CkMechanismType::SHA256,
                params: None,
            }),
            content_type: "application/octet-stream".to_string(),
            requested_attributes: Vec::new(),
            required_attributes: Vec::new(),
        })),
    }
}

fn kip_mechanism(mechanism_type: CkMechanismType, key_handle: CkObjectHandle) -> CkMechanism {
    CkMechanism {
        mechanism_type,
        params: Some(CkMechanismParams::Kip(KipParams {
            mechanism: Box::new(CkMechanism {
                mechanism_type: CkMechanismType::SHA256,
                params: None,
            }),
            key_handle: key_handle.0,
            seed: b"seed".to_vec(),
        })),
    }
}

fn expect_derive_param_handle_invalid(
    backend: &MockBackend,
    session: CkSessionHandle,
    mechanism_type: CkMechanismType,
    params: CkMechanismParams,
    label: &str,
) {
    let base_key = live_key(backend, session);
    let mechanism = CkMechanism { mechanism_type, params: Some(params) };

    assert_eq!(
        backend.derive_key(session, &mechanism, base_key, &[label_attr("derived")]).unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID,
        "{label} should reject an invalid source-defined handle"
    );
    assert_eq!(
        backend
            .derive_key_with_output(session, &mechanism, base_key, &[label_attr("derived")])
            .unwrap_err(),
        CkRv::OBJECT_HANDLE_INVALID,
        "{label} exact/output path should reject an invalid source-defined handle"
    );
}

fn gcm_mechanism_output() -> CkMechanismParams {
    CkMechanismParams::Gcm(GcmParams {
        iv: vec![0xA5; 12],
        iv_bits: 96,
        iv_buffer_len: 12,
        aad: b"mock-aad".to_vec(),
        tag_bits: 128,
    })
}

const CKF_DONT_BLOCK: u64 = 0x0000_0001;
