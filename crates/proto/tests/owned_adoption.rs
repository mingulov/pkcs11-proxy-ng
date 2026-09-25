//! T13: owned conversions adopt secret buffers without copying.
//!
//! Each `*_from_owned` / `try_from_owned` entry point must transfer the wire
//! allocation into the wiping destination (`mem::take` adoption) instead of
//! cloning it. These tests pin allocation identity: the destination's live
//! borrow points at the exact allocation the message held before transfer,
//! and the bytes are unchanged. Error exits return the same `CkRv` as the
//! reviewed borrowed conversions (the moved message drops and wipes via T12).

use pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput;
use pkcs11_proxy_ng_proto::convert::message_params::MessageParameter;
use pkcs11_proxy_ng_proto::convert::output::{
    attribute_query_result_from_owned, output_and_handle_result_from_owned,
    output_buffer_result_from_owned, parameter_roundtrip_result_from_owned,
    parameter_roundtrip_spec_from_owned,
};
use pkcs11_proxy_ng_proto::{
    AttributeQueryResultList, AuthenticatedMechanismOutput, GcmMessageParams,
    MessageParameter as WireMessageParameter, MessageParameterEffects, OutputAndHandleResult,
    OutputBufferResult, ParameterRoundtripResult, ParameterRoundtripSpec,
    authenticated_mechanism_output::Output as WireOutput, message_parameter::Params as WireParams,
};
use pkcs11_proxy_ng_types::{
    CkAttributeQueryResult, CkOutputAndHandleResult, CkOutputBufferResult, CkRv, SecretBytes,
};

/// Non-empty nonzero canary so the allocation (and its pointer) is real.
fn canary() -> Vec<u8> {
    vec![0xA5u8; 16]
}

#[test]
fn take_idiom_empties_source_and_preserves_allocation() {
    // The plan's reference idiom: `mem::take` leaves the source empty and
    // the destination borrows the original allocation (no copy).
    let mut request_bytes = canary();
    let original = request_bytes.as_ptr();
    let secret = SecretBytes::new(std::mem::take(&mut request_bytes));
    assert!(request_bytes.is_empty());
    secret.expose(|bytes| {
        assert_eq!(bytes.as_ptr(), original);
        assert_eq!(bytes, canary().as_slice());
    });
}

#[test]
fn output_buffer_result_adopts_allocation() {
    let message = OutputBufferResult {
        ck_rv: CkRv::OK.0,
        returned_len: 16,
        value: Some(canary()),
        apply_returned_len: Some(true),
    };
    let original = message.value.as_ref().map(Vec::as_ptr).unwrap();
    let out = output_buffer_result_from_owned(message).unwrap();
    assert_eq!(out.ck_rv, CkRv::OK);
    assert_eq!(out.returned_len, Some(16));
    let value = out.value.expect("value must survive adoption");
    value.expose(|bytes| {
        assert_eq!(bytes.as_ptr(), original, "buffer must be adopted, not copied");
        assert_eq!(bytes, canary().as_slice());
    });
}

#[test]
fn output_buffer_result_owned_matches_borrowed_error_exits() {
    // Missing presence bit.
    let missing = OutputBufferResult {
        ck_rv: CkRv::OK.0,
        returned_len: 0,
        value: None,
        apply_returned_len: None,
    };
    assert_eq!(CkOutputBufferResult::try_from(&missing).unwrap_err(), CkRv::FUNCTION_NOT_SUPPORTED);
    assert_eq!(output_buffer_result_from_owned(missing).unwrap_err(), CkRv::FUNCTION_NOT_SUPPORTED);
    // Effects without the apply bit.
    let sneaky = OutputBufferResult {
        ck_rv: CkRv::OK.0,
        returned_len: 4,
        value: Some(canary()),
        apply_returned_len: Some(false),
    };
    assert_eq!(CkOutputBufferResult::try_from(&sneaky).unwrap_err(), CkRv::FUNCTION_NOT_SUPPORTED);
    assert_eq!(output_buffer_result_from_owned(sneaky).unwrap_err(), CkRv::FUNCTION_NOT_SUPPORTED);
}

#[test]
fn parameter_roundtrip_result_and_spec_adopt_allocations() {
    let result =
        ParameterRoundtripResult { ck_rv: CkRv::OK.0, returned_len: 16, value: Some(canary()) };
    let original = result.value.as_ref().map(Vec::as_ptr).unwrap();
    let out = parameter_roundtrip_result_from_owned(result);
    assert_eq!(out.ck_rv, CkRv::OK);
    assert_eq!(out.returned_len, 16);
    out.value.expect("value must survive adoption").expose(|bytes| {
        assert_eq!(bytes.as_ptr(), original, "buffer must be adopted, not copied");
        assert_eq!(bytes, canary().as_slice());
    });

    let spec =
        ParameterRoundtripSpec { buffer_present: true, buffer_len: 16, value: Some(canary()) };
    let original = spec.value.as_ref().map(Vec::as_ptr).unwrap();
    let out = parameter_roundtrip_spec_from_owned(spec);
    assert!(out.buffer_present);
    assert_eq!(out.buffer_len, 16);
    out.value.expect("value must survive adoption").expose(|bytes| {
        assert_eq!(bytes.as_ptr(), original, "buffer must be adopted, not copied");
        assert_eq!(bytes, canary().as_slice());
    });
}

#[test]
fn output_and_handle_result_adopts_opaque_tuple() {
    // Opaque tuple ownership: the secret member is adopted while the public
    // handle member transfers by value.
    let message = OutputAndHandleResult {
        ck_rv: CkRv::OK.0,
        returned_len: 16,
        value: Some(canary()),
        object_handle: 0x1234,
        apply_returned_len: Some(true),
        apply_object_handle: Some(true),
    };
    let original = message.value.as_ref().map(Vec::as_ptr).unwrap();
    let out = output_and_handle_result_from_owned(message).unwrap();
    assert_eq!(out.ck_rv, CkRv::OK);
    assert_eq!(out.returned_len, Some(16));
    assert_eq!(out.object_handle.map(|h| h.0), Some(0x1234));
    out.value.expect("value must survive adoption").expose(|bytes| {
        assert_eq!(bytes.as_ptr(), original, "buffer must be adopted, not copied");
        assert_eq!(bytes, canary().as_slice());
    });
}

#[test]
fn output_and_handle_result_owned_matches_borrowed_error_exits() {
    // Handle claimed on a failing RV.
    let bad_handle = OutputAndHandleResult {
        ck_rv: CkRv::GENERAL_ERROR.0,
        returned_len: 0,
        value: None,
        object_handle: 7,
        apply_returned_len: Some(true),
        apply_object_handle: Some(true),
    };
    assert_eq!(
        CkOutputAndHandleResult::try_from(&bad_handle).unwrap_err(),
        CkRv::FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        output_and_handle_result_from_owned(bad_handle).unwrap_err(),
        CkRv::FUNCTION_NOT_SUPPORTED
    );
    // Missing presence bits.
    let missing = OutputAndHandleResult {
        ck_rv: CkRv::OK.0,
        returned_len: 0,
        value: None,
        object_handle: 0,
        apply_returned_len: None,
        apply_object_handle: Some(false),
    };
    assert_eq!(
        CkOutputAndHandleResult::try_from(&missing).unwrap_err(),
        CkRv::FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        output_and_handle_result_from_owned(missing).unwrap_err(),
        CkRv::FUNCTION_NOT_SUPPORTED
    );
}

#[test]
fn attribute_query_result_adopts_value_and_nested_values() {
    use pkcs11_proxy_ng_proto::AttributeQueryResult as WireResult;

    let nested = WireResult {
        apply_returned_len: Some(true),
        apply_type: Some(true),
        attr_type: 0x11,
        returned_len: 16,
        value: Some(canary()),
        ck_rv: Some(CkRv::OK.0),
        nested: None,
    };
    let nested_original = nested.value.as_ref().map(Vec::as_ptr).unwrap();
    let message = WireResult {
        apply_returned_len: Some(true),
        apply_type: Some(true),
        attr_type: 0x10,
        returned_len: 16,
        value: Some(canary()),
        ck_rv: Some(CkRv::OK.0),
        nested: Some(AttributeQueryResultList { results: vec![nested] }),
    };
    let original = message.value.as_ref().map(Vec::as_ptr).unwrap();
    let out = attribute_query_result_from_owned(message).unwrap();
    assert_eq!(out.attr_type.0, 0x10);
    assert_eq!(out.returned_len, 16);
    assert!(out.apply_returned_len && out.apply_type);
    out.value.expect("value must survive adoption").expose(|bytes| {
        assert_eq!(bytes.as_ptr(), original, "buffer must be adopted, not copied");
        assert_eq!(bytes, canary().as_slice());
    });
    let nested = out.nested.expect("nested list must survive adoption");
    assert_eq!(nested.len(), 1);
    nested.into_iter().next().unwrap().value.expect("nested value must survive adoption").expose(
        |bytes| {
            assert_eq!(bytes.as_ptr(), nested_original, "nested buffer must be adopted");
            assert_eq!(bytes, canary().as_slice());
        },
    );
}

#[test]
fn attribute_query_result_owned_matches_borrowed_error_exits() {
    use pkcs11_proxy_ng_proto::AttributeQueryResult as WireResult;

    // Depth-2 nesting is refused by both forms.
    let deep = WireResult {
        apply_returned_len: Some(true),
        apply_type: Some(true),
        attr_type: 0x10,
        returned_len: 0,
        value: None,
        ck_rv: None,
        nested: Some(AttributeQueryResultList {
            results: vec![WireResult {
                apply_returned_len: Some(true),
                apply_type: Some(true),
                attr_type: 0x11,
                returned_len: 0,
                value: None,
                ck_rv: None,
                nested: Some(AttributeQueryResultList {
                    results: vec![WireResult {
                        apply_returned_len: Some(true),
                        apply_type: Some(true),
                        attr_type: 0x12,
                        returned_len: 0,
                        value: None,
                        ck_rv: None,
                        nested: None,
                    }],
                }),
            }],
        }),
    };
    assert_eq!(CkAttributeQueryResult::try_from(&deep).unwrap_err(), CkRv::FUNCTION_NOT_SUPPORTED);
    assert_eq!(attribute_query_result_from_owned(deep).unwrap_err(), CkRv::FUNCTION_NOT_SUPPORTED);
}

#[test]
fn authenticated_iv_output_adopts_allocation() {
    let message = AuthenticatedMechanismOutput { output: Some(WireOutput::Iv(canary())) };
    let original = match message.output.as_ref() {
        Some(WireOutput::Iv(iv)) => iv.as_ptr(),
        _ => panic!("fixture must hold the Iv arm"),
    };
    match AuthenticatedOutput::try_from_owned(message).unwrap() {
        AuthenticatedOutput::Iv(secret) => secret.expose(|bytes| {
            assert_eq!(bytes.as_ptr(), original, "IV buffer must be adopted, not copied");
            assert_eq!(bytes, canary().as_slice());
        }),
        other => panic!("Iv arm must decode to Iv, got {other:?}"),
    }
}

#[test]
fn authenticated_output_owned_matches_borrowed_error_exits() {
    // Absent oneof.
    let missing = AuthenticatedMechanismOutput { output: None };
    assert_eq!(AuthenticatedOutput::try_from(&missing).unwrap_err(), CkRv::ARGUMENTS_BAD);
    assert_eq!(AuthenticatedOutput::try_from_owned(missing).unwrap_err(), CkRv::ARGUMENTS_BAD);
    // Explicitly declined acknowledgement.
    let declined = AuthenticatedMechanismOutput { output: Some(WireOutput::Unchanged(false)) };
    assert_eq!(
        AuthenticatedOutput::try_from(&declined).unwrap_err(),
        CkRv::MECHANISM_PARAM_INVALID
    );
    assert_eq!(
        AuthenticatedOutput::try_from_owned(declined).unwrap_err(),
        CkRv::MECHANISM_PARAM_INVALID
    );
    // Structured acknowledgement with absent params.
    let empty_message = AuthenticatedMechanismOutput {
        output: Some(WireOutput::MessageParameter(WireMessageParameter { params: None })),
    };
    assert_eq!(AuthenticatedOutput::try_from(&empty_message).unwrap_err(), CkRv::ARGUMENTS_BAD);
    assert_eq!(
        AuthenticatedOutput::try_from_owned(empty_message).unwrap_err(),
        CkRv::ARGUMENTS_BAD
    );
    // Raw bytes are not a structured acknowledgement.
    let raw_message = AuthenticatedMechanismOutput {
        output: Some(WireOutput::MessageParameter(WireMessageParameter {
            params: Some(WireParams::Raw(canary())),
        })),
    };
    assert_eq!(
        AuthenticatedOutput::try_from(&raw_message).unwrap_err(),
        CkRv::MECHANISM_PARAM_INVALID
    );
    assert_eq!(
        AuthenticatedOutput::try_from_owned(raw_message).unwrap_err(),
        CkRv::MECHANISM_PARAM_INVALID
    );
    // Invalid structured arm (tag_bits > 128). Struct-update syntax cannot
    // move fields out of a `ZeroizeOnDrop` message, so mutate a bound default.
    let mut invalid_gcm = GcmMessageParams::default();
    invalid_gcm.tag_bits = 129;
    let bad_gcm = AuthenticatedMechanismOutput {
        output: Some(WireOutput::MessageParameter(WireMessageParameter {
            params: Some(WireParams::GcmMessageParams(invalid_gcm)),
        })),
    };
    assert_eq!(AuthenticatedOutput::try_from(&bad_gcm).unwrap_err(), CkRv::MECHANISM_PARAM_INVALID);
    assert_eq!(
        AuthenticatedOutput::try_from_owned(bad_gcm).unwrap_err(),
        CkRv::MECHANISM_PARAM_INVALID
    );
    // Effects with an absent oneof.
    let bad_effects = AuthenticatedMechanismOutput {
        output: Some(WireOutput::MessageEffects(MessageParameterEffects { effect: None })),
    };
    assert_eq!(AuthenticatedOutput::try_from(&bad_effects).unwrap_err(), CkRv::ARGUMENTS_BAD);
    assert_eq!(AuthenticatedOutput::try_from_owned(bad_effects).unwrap_err(), CkRv::ARGUMENTS_BAD);
}

#[test]
fn message_parameter_owned_matches_borrowed_error_exits() {
    // Absent oneof.
    let missing = WireMessageParameter { params: None };
    assert_eq!(MessageParameter::try_from(&missing).unwrap_err(), CkRv::ARGUMENTS_BAD);
    assert_eq!(MessageParameter::try_from_owned(missing).unwrap_err(), CkRv::ARGUMENTS_BAD);
    // Invalid structured arm (tag_bits > 128). Struct-update syntax cannot
    // move fields out of a `ZeroizeOnDrop` message, so mutate a bound default.
    let mut invalid_gcm = GcmMessageParams::default();
    invalid_gcm.tag_bits = 129;
    let bad_gcm = WireMessageParameter { params: Some(WireParams::GcmMessageParams(invalid_gcm)) };
    assert_eq!(MessageParameter::try_from(&bad_gcm).unwrap_err(), CkRv::MECHANISM_PARAM_INVALID);
    assert_eq!(
        MessageParameter::try_from_owned(bad_gcm).unwrap_err(),
        CkRv::MECHANISM_PARAM_INVALID
    );
}

#[test]
fn message_parameter_raw_adopts_allocation() {
    let message = WireMessageParameter { params: Some(WireParams::Raw(canary())) };
    let original = match message.params.as_ref() {
        Some(WireParams::Raw(data)) => data.as_ptr(),
        _ => panic!("fixture must hold the Raw arm"),
    };
    match MessageParameter::try_from_owned(message).unwrap() {
        MessageParameter::Raw(secret) => secret.expose(|bytes| {
            assert_eq!(bytes.as_ptr(), original, "raw buffer must be adopted, not copied");
            assert_eq!(bytes, canary().as_slice());
        }),
        _ => panic!("Raw arm must decode to Raw"),
    }
}
