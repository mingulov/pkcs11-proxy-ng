use super::{
    MessageCallMemory, MessageParameterCall, MessageParameterDirection, MessageParameterStage,
    empty_message_parameter_roundtrip_spec, message_parameter_roundtrip_spec,
    read_message_parameter_call_for_shape_with_memory,
    write_exact_message_output as commit_exact_effects,
};
use cryptoki_sys::*;
use pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects;
use pkcs11_proxy_ng_proto::convert::message_params::{MessageParameter, MessageParameterShape};
use pkcs11_proxy_ng_types::{CkObjectHandle, CkResult, CkRv, SecretBytes};

#[test]
fn exact_query_parameter_effect_rejection_is_transactional() {
    use pkcs11_proxy_ng_types::{
        CkOutputBufferResult, CkOutputBufferSpec, CkParameterRoundtripResult,
        CkParameterRoundtripSpec,
    };
    let mut iv = [0x11u8; 12];
    let mut tag = [0xa5u8; 16];
    let outer = CK_GCM_MESSAGE_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: 12,
        ulIvFixedBits: 0,
        ivGenerator: CKG_GENERATE_COUNTER_XOR,
        pTag: tag.as_mut_ptr(),
        ulTagBits: 128,
    };
    let call = unsafe {
        read_message_parameter_call_for_shape(
            (&outer as *const CK_GCM_MESSAGE_PARAMS).cast(),
            std::mem::size_of_val(&outer) as CK_ULONG,
            MessageParameterShape::Gcm,
            MessageParameterDirection::Encrypt,
            MessageParameterStage::OneShot,
        )
    }
    .unwrap();
    let spec =
        CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: false };
    let param_spec = CkParameterRoundtripSpec {
        buffer_present: true,
        buffer_len: std::mem::size_of_val(&outer) as u64,
        value: None,
    };
    let output = CkOutputBufferResult { ck_rv: CkRv::OK, returned_len: Some(4), value: None };
    let ack = CkParameterRoundtripResult {
        ck_rv: CkRv::OK,
        returned_len: param_spec.buffer_len,
        value: Some(Vec::new().into()),
    };
    // Initialized IV effects are permitted, but the forbidden output-only tag
    // must reject the entire response before IV, tag, or length stores.
    let invalid = MessageEffects::Gcm { iv: Some(vec![0x42; 12]), tag: Some(vec![0; 16]) };
    let mut length = 0xdead;
    assert_eq!(
        unsafe {
            commit_exact_effects(
                &spec,
                &param_spec,
                &call,
                &output,
                &ack,
                Some(&invalid),
                std::ptr::null_mut(),
                &mut length,
            )
        },
        CKR_GENERAL_ERROR
    );
    assert_eq!((iv, tag, length), ([0x11; 12], [0xa5; 16], 0xdead));
    let valid = MessageEffects::Gcm { iv: Some(vec![0x42; 12]), tag: None };
    assert_eq!(
        unsafe {
            commit_exact_effects(
                &spec,
                &param_spec,
                &call,
                &output,
                &ack,
                Some(&valid),
                std::ptr::null_mut(),
                &mut length,
            )
        },
        CKR_OK
    );
    assert_eq!((iv, tag, length), ([0x42; 12], [0xa5; 16], 4));
}

// Preserve the pre-C3 shape/stage fixtures while invoking the production typed
// commit helper. New effect-contract tests construct their effects explicitly.
#[allow(clippy::too_many_arguments)]
/// Test fixture wrapper capturing effects before the production commit.
///
/// # Safety
///
/// Same contract as the production `write_exact_message_output`:
/// `pointer`/`length` must be the writable output pointers captured in
/// `output_spec`, and embedded pointers inside `call` must remain writable
/// for their source-declared extents.
unsafe fn write_exact_message_output(
    output_spec: &pkcs11_proxy_ng_types::CkOutputBufferSpec,
    parameter_spec: &pkcs11_proxy_ng_types::CkParameterRoundtripSpec,
    call: &MessageParameterCall,
    output: &pkcs11_proxy_ng_types::CkOutputBufferResult,
    ack: &pkcs11_proxy_ng_types::CkParameterRoundtripResult,
    response: Option<&MessageParameter>,
    pointer: CK_BYTE_PTR,
    length: CK_ULONG_PTR,
) -> CK_RV {
    let effects = response.zip(call.parameter()).map(|(response, input)| {
        MessageEffects::capture(
            input,
            response,
            super::message_params::effect_context(call, output.ck_rv, output_spec),
        )
    });
    unsafe {
        commit_exact_effects(
            output_spec,
            parameter_spec,
            call,
            output,
            ack,
            effects.as_ref(),
            pointer,
            length,
        )
    }
}

/// Test read of a message-parameter call with empty call memory.
///
/// # Safety
///
/// Same contract as `read_message_parameter_call_for_shape_with_memory`
/// with `MessageCallMemory::none()`: a non-null, positive-length
/// `p_parameter` must designate the exact outer struct selected by
/// `shape`, and every non-null embedded pointer must satisfy its PKCS#11
/// caller contract.
unsafe fn read_message_parameter_call_for_shape(
    p_parameter: *const std::ffi::c_void,
    ul_parameter_len: CK_ULONG,
    shape: MessageParameterShape,
    direction: MessageParameterDirection,
    stage: MessageParameterStage,
) -> CkResult<MessageParameterCall> {
    unsafe {
        read_message_parameter_call_for_shape_with_memory(
            p_parameter,
            ul_parameter_len,
            shape,
            direction,
            stage,
            MessageCallMemory::none(),
        )
    }
}

/// Test read of a message parameter via `read_message_parameter_call_for_shape`.
///
/// # Safety
///
/// Same contract as `read_message_parameter_call_for_shape`.
unsafe fn read_message_parameter_for_shape(
    p_parameter: *const std::ffi::c_void,
    ul_parameter_len: CK_ULONG,
    shape: MessageParameterShape,
    direction: MessageParameterDirection,
    stage: MessageParameterStage,
) -> CkResult<Option<MessageParameter>> {
    Ok(unsafe {
        read_message_parameter_call_for_shape(
            p_parameter,
            ul_parameter_len,
            shape,
            direction,
            stage,
        )
    }?
    .into_parameter())
}

#[test]
fn empty_sign_verify_parameter_classes_are_preserved_and_positive_is_rejected_without_read() {
    let null_zero =
        unsafe { empty_message_parameter_roundtrip_spec(std::ptr::null_mut(), 0) }.unwrap();
    assert!(!null_zero.buffer_present);
    assert_eq!(null_zero.buffer_len, 0);

    let nonnull_zero = unsafe {
        empty_message_parameter_roundtrip_spec(
            std::ptr::NonNull::<u8>::dangling().as_ptr().cast(),
            0,
        )
    }
    .unwrap();
    assert!(nonnull_zero.buffer_present);
    assert_eq!(nonnull_zero.buffer_len, 0);

    let poison = std::ptr::without_provenance_mut::<std::ffi::c_void>(1);
    assert_eq!(
        unsafe { empty_message_parameter_roundtrip_spec(poison, 1) },
        Err(CkRv::MECHANISM_PARAM_INVALID),
    );
}

#[test]
fn write_exact_message_error_applies_only_permitted_parameter_effects() {
    let mut iv = [0x11; 12];
    let mut tag = [0x22; 16];
    let mut outer = CK_GCM_MESSAGE_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: 12,
        ulIvFixedBits: 0,
        ivGenerator: CKG_GENERATE_COUNTER_XOR,
        pTag: tag.as_mut_ptr(),
        ulTagBits: 128,
    };
    let call = unsafe {
        read_message_parameter_call_for_shape(
            (&mut outer as *mut CK_GCM_MESSAGE_PARAMS).cast(),
            std::mem::size_of_val(&outer) as CK_ULONG,
            MessageParameterShape::Gcm,
            MessageParameterDirection::Encrypt,
            MessageParameterStage::OneShot,
        )
    }
    .unwrap();
    let spec = unsafe {
        message_parameter_roundtrip_spec(
            (&mut outer as *mut CK_GCM_MESSAGE_PARAMS).cast(),
            std::mem::size_of_val(&outer) as CK_ULONG,
        )
    }
    .unwrap();
    let mut returned_iv = vec![0x11; 12];
    returned_iv[0] = 0x42;
    let response = MessageEffects::Gcm { iv: Some(returned_iv), tag: None };
    let output_spec = pkcs11_proxy_ng_types::CkOutputBufferSpec {
        buffer_present: false,
        buffer_len: 0,
        length_pointer_null: false,
    };
    let output = pkcs11_proxy_ng_types::CkOutputBufferResult {
        ck_rv: CkRv::DEVICE_ERROR,
        returned_len: Some(7),
        value: None,
    };
    let ack = pkcs11_proxy_ng_types::CkParameterRoundtripResult {
        ck_rv: CkRv::DEVICE_ERROR,
        returned_len: spec.buffer_len,
        value: Some(vec![].into()),
    };
    let mut length = 99;
    let rv = unsafe {
        commit_exact_effects(
            &output_spec,
            &spec,
            &call,
            &output,
            &ack,
            Some(&response),
            std::ptr::null_mut(),
            &mut length,
        )
    };
    assert_eq!(rv, CKR_DEVICE_ERROR);
    assert_eq!(iv[0], 0x42, "initialized XOR IV effect must survive the native error");
    assert_eq!(tag, [0x22; 16], "output-only tag has no defined ordinary-error effect");
    assert_eq!(length, 7);
}

#[test]
fn transactional_message_output_keeps_all_memory_unchanged_on_malformed_ack() {
    let mut iv = [0x11u8; 12];
    let mut tag = [0x22u8; 16];
    let mut outer = CK_GCM_MESSAGE_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 96,
        ivGenerator: CKG_NO_GENERATE,
        pTag: tag.as_mut_ptr(),
        ulTagBits: 128,
    };
    let call = unsafe {
        read_message_parameter_call_for_shape(
            (&mut outer as *mut CK_GCM_MESSAGE_PARAMS).cast(),
            std::mem::size_of_val(&outer) as CK_ULONG,
            MessageParameterShape::Gcm,
            MessageParameterDirection::Encrypt,
            MessageParameterStage::OneShot,
        )
    }
    .unwrap();
    let request = call.parameter().unwrap().clone();
    let mut response = request.clone();
    let MessageParameter::GcmMessage(response_gcm) = &mut response else { unreachable!() };
    response_gcm.iv.fill(0x33);
    response_gcm.tag.fill(0x44);

    let output_spec = pkcs11_proxy_ng_types::CkOutputBufferSpec {
        buffer_present: true,
        buffer_len: 4,
        length_pointer_null: false,
    };
    let parameter_spec = pkcs11_proxy_ng_types::CkParameterRoundtripSpec {
        buffer_present: true,
        buffer_len: std::mem::size_of_val(&outer) as u64,
        value: None,
    };
    let output_result = pkcs11_proxy_ng_types::CkOutputBufferResult {
        ck_rv: CkRv::OK,
        returned_len: Some(4),
        value: Some(vec![1, 2, 3, 4].into()),
    };
    let malformed_parameter_result = pkcs11_proxy_ng_types::CkParameterRoundtripResult {
        ck_rv: CkRv::OK,
        returned_len: parameter_spec.buffer_len + 1,
        value: Some(Vec::new().into()),
    };
    let mut output = [0xAAu8; 4];
    let mut output_len = output.len() as CK_ULONG;

    let rv = unsafe {
        write_exact_message_output(
            &output_spec,
            &parameter_spec,
            &call,
            &output_result,
            &malformed_parameter_result,
            Some(&response),
            output.as_mut_ptr(),
            &mut output_len,
        )
    };

    assert_eq!(rv, CKR_GENERAL_ERROR as CK_RV);
    assert_eq!(output, [0xAA; 4]);
    assert_eq!(output_len, 4);
    assert_eq!(iv, [0x11; 12]);
    assert_eq!(tag, [0x22; 16]);
}

#[test]
fn transactional_message_output_rejects_malformed_main_value_before_any_write() {
    let mut iv = [0x11u8; 12];
    let mut tag = [0x22u8; 16];
    let mut outer = CK_GCM_MESSAGE_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 96,
        ivGenerator: CKG_NO_GENERATE,
        pTag: tag.as_mut_ptr(),
        ulTagBits: 128,
    };
    let outer_snapshot = (
        outer.pIv,
        outer.ulIvLen,
        outer.ulIvFixedBits,
        outer.ivGenerator,
        outer.pTag,
        outer.ulTagBits,
    );
    let call = unsafe {
        read_message_parameter_call_for_shape(
            (&mut outer as *mut CK_GCM_MESSAGE_PARAMS).cast(),
            std::mem::size_of_val(&outer) as CK_ULONG,
            MessageParameterShape::Gcm,
            MessageParameterDirection::Encrypt,
            MessageParameterStage::OneShot,
        )
    }
    .unwrap();
    let mut response = call.parameter().unwrap().clone();
    let MessageParameter::GcmMessage(response_gcm) = &mut response else { unreachable!() };
    response_gcm.iv.fill(0x33);
    response_gcm.tag.fill(0x44);

    let output_spec = pkcs11_proxy_ng_types::CkOutputBufferSpec {
        buffer_present: true,
        buffer_len: 4,
        length_pointer_null: false,
    };
    let parameter_spec = pkcs11_proxy_ng_types::CkParameterRoundtripSpec {
        buffer_present: true,
        buffer_len: std::mem::size_of_val(&outer) as u64,
        value: None,
    };
    let malformed_output = pkcs11_proxy_ng_types::CkOutputBufferResult {
        ck_rv: CkRv::OK,
        returned_len: Some(4),
        value: Some(vec![1, 2, 3].into()),
    };
    let parameter_result = pkcs11_proxy_ng_types::CkParameterRoundtripResult {
        ck_rv: CkRv::OK,
        returned_len: parameter_spec.buffer_len,
        value: Some(Vec::new().into()),
    };
    let mut output = [0xAAu8; 4];
    let mut output_len = output.len() as CK_ULONG;

    let rv = unsafe {
        write_exact_message_output(
            &output_spec,
            &parameter_spec,
            &call,
            &malformed_output,
            &parameter_result,
            Some(&response),
            output.as_mut_ptr(),
            &mut output_len,
        )
    };

    assert_eq!(rv, CKR_GENERAL_ERROR as CK_RV);
    assert_eq!(output, [0xAA; 4]);
    assert_eq!(output_len, 4);
    assert_eq!(iv, [0x11; 12]);
    assert_eq!(tag, [0x22; 16]);
    assert_eq!(
        (
            outer.pIv,
            outer.ulIvLen,
            outer.ulIvFixedBits,
            outer.ivGenerator,
            outer.pTag,
            outer.ulTagBits,
        ),
        outer_snapshot,
        "validation must not modify the outer parameter snapshot",
    );
}

#[test]
fn transactional_message_size_query_keeps_memory_unchanged_on_bad_pointer_class_ack() {
    let mut iv = [0x11u8; 12];
    let mut tag = [0x22u8; 16];
    let mut outer = CK_GCM_MESSAGE_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 96,
        ivGenerator: CKG_NO_GENERATE,
        pTag: tag.as_mut_ptr(),
        ulTagBits: 128,
    };
    let call = unsafe {
        read_message_parameter_call_for_shape(
            (&mut outer as *mut CK_GCM_MESSAGE_PARAMS).cast(),
            std::mem::size_of_val(&outer) as CK_ULONG,
            MessageParameterShape::Gcm,
            MessageParameterDirection::Encrypt,
            MessageParameterStage::OneShot,
        )
    }
    .unwrap();
    let mut response = call.parameter().unwrap().clone();
    let MessageParameter::GcmMessage(response_gcm) = &mut response else { unreachable!() };
    response_gcm.iv.fill(0x33);
    response_gcm.tag.fill(0x44);

    let output_spec = pkcs11_proxy_ng_types::CkOutputBufferSpec {
        buffer_present: false,
        buffer_len: 0,
        length_pointer_null: false,
    };
    let parameter_spec = pkcs11_proxy_ng_types::CkParameterRoundtripSpec {
        buffer_present: true,
        buffer_len: std::mem::size_of_val(&outer) as u64,
        value: None,
    };
    let output_result = pkcs11_proxy_ng_types::CkOutputBufferResult {
        ck_rv: CkRv::OK,
        returned_len: Some(4),
        value: None,
    };
    let bad_ack = pkcs11_proxy_ng_types::CkParameterRoundtripResult {
        ck_rv: CkRv::OK,
        returned_len: parameter_spec.buffer_len,
        value: None,
    };
    let mut output_len = 0x55 as CK_ULONG;

    let rv = unsafe {
        write_exact_message_output(
            &output_spec,
            &parameter_spec,
            &call,
            &output_result,
            &bad_ack,
            Some(&response),
            std::ptr::null_mut(),
            &mut output_len,
        )
    };

    assert_eq!(rv, CKR_GENERAL_ERROR as CK_RV);
    assert_eq!(output_len, 0x55);
    assert_eq!(iv, [0x11; 12]);
    assert_eq!(tag, [0x22; 16]);
}

#[test]
fn transactional_message_b2s_keeps_all_memory_unchanged_on_bad_ack() {
    let mut iv = [0x11u8; 12];
    let mut tag = [0x22u8; 16];
    let mut outer = CK_GCM_MESSAGE_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 96,
        ivGenerator: CKG_NO_GENERATE,
        pTag: tag.as_mut_ptr(),
        ulTagBits: 128,
    };
    let call = unsafe {
        read_message_parameter_call_for_shape(
            (&mut outer as *mut CK_GCM_MESSAGE_PARAMS).cast(),
            std::mem::size_of_val(&outer) as CK_ULONG,
            MessageParameterShape::Gcm,
            MessageParameterDirection::Encrypt,
            MessageParameterStage::OneShot,
        )
    }
    .unwrap();
    let mut response = call.parameter().unwrap().clone();
    let MessageParameter::GcmMessage(response_gcm) = &mut response else { unreachable!() };
    response_gcm.iv.fill(0x33);
    response_gcm.tag.fill(0x44);

    let output_spec = pkcs11_proxy_ng_types::CkOutputBufferSpec {
        buffer_present: true,
        buffer_len: 2,
        length_pointer_null: false,
    };
    let parameter_spec = pkcs11_proxy_ng_types::CkParameterRoundtripSpec {
        buffer_present: true,
        buffer_len: std::mem::size_of_val(&outer) as u64,
        value: None,
    };
    let output_result = pkcs11_proxy_ng_types::CkOutputBufferResult {
        ck_rv: CkRv::BUFFER_TOO_SMALL,
        returned_len: Some(4),
        value: None,
    };
    let bad_ack = pkcs11_proxy_ng_types::CkParameterRoundtripResult {
        ck_rv: CkRv::OK,
        returned_len: parameter_spec.buffer_len,
        value: Some(Vec::new().into()),
    };
    let mut output = [0xAAu8; 2];
    let mut output_len = output.len() as CK_ULONG;

    let rv = unsafe {
        write_exact_message_output(
            &output_spec,
            &parameter_spec,
            &call,
            &output_result,
            &bad_ack,
            Some(&response),
            output.as_mut_ptr(),
            &mut output_len,
        )
    };

    assert_eq!(rv, CKR_GENERAL_ERROR as CK_RV);
    assert_eq!(output, [0xAA; 2]);
    assert_eq!(output_len, 2);
    assert_eq!(iv, [0x11; 12]);
    assert_eq!(tag, [0x22; 16]);
}

#[test]
fn message_roundtrip_spec_preserves_null_nonzero_without_reading() {
    let spec = unsafe { message_parameter_roundtrip_spec(std::ptr::null_mut(), 7) }.unwrap();

    assert!(!spec.buffer_present);
    assert_eq!(spec.buffer_len, 7);
    assert_eq!(spec.value, None);
}

#[test]
fn message_roundtrip_spec_preserves_nonnull_zero_without_reading() {
    let spec = unsafe { message_parameter_roundtrip_spec(std::ptr::dangling_mut(), 0) }.unwrap();

    assert!(spec.buffer_present);
    assert_eq!(spec.buffer_len, 0);
    assert_eq!(spec.value, None);
}

#[test]
fn message_roundtrip_spec_never_copies_materialized_outer_struct() {
    let spec = unsafe { message_parameter_roundtrip_spec(std::ptr::dangling_mut(), CK_ULONG::MAX) }
        .unwrap();

    assert!(spec.buffer_present);
    assert_eq!(spec.buffer_len, CK_ULONG::MAX as u64);
    assert_eq!(spec.value, None);
}

#[test]
fn shape_bound_reader_rejects_unmodelled_materialized_parameter_without_reading() {
    let result = unsafe {
        read_message_parameter_for_shape(
            std::ptr::dangling(),
            1,
            MessageParameterShape::Unmodeled,
            MessageParameterDirection::Encrypt,
            MessageParameterStage::OneShot,
        )
    };

    assert_eq!(result.unwrap_err(), CkRv::MECHANISM_PARAM_INVALID);
}

#[test]
fn shape_bound_reader_accepts_unaligned_gcm_outer_and_zeroes_encrypt_tag() {
    let mut iv = [0x11u8; 12];
    let mut tag = [0xA5u8; 16];
    let outer = CK_GCM_MESSAGE_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 96,
        ivGenerator: CKG_NO_GENERATE,
        pTag: tag.as_mut_ptr(),
        ulTagBits: 128,
    };
    let mut storage = vec![0u8; std::mem::size_of_val(&outer) + 1];
    let unaligned = unsafe { storage.as_mut_ptr().add(1).cast::<CK_GCM_MESSAGE_PARAMS>() };
    unsafe { std::ptr::write_unaligned(unaligned, outer) };

    let parameter = unsafe {
        read_message_parameter_for_shape(
            unaligned.cast(),
            std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
            MessageParameterShape::Gcm,
            MessageParameterDirection::Encrypt,
            MessageParameterStage::OneShot,
        )
    }
    .unwrap()
    .unwrap();

    let MessageParameter::GcmMessage(parameter) = parameter else { panic!("expected GCM") };
    assert_eq!(parameter.iv, iv);
    assert_eq!(parameter.tag, vec![0; 16], "encrypt output storage must not be read");
}

fn commit_stage_response(
    call: &MessageParameterCall,
    outer_len: usize,
    response: &MessageParameter,
) -> CK_RV {
    let output_spec = pkcs11_proxy_ng_types::CkOutputBufferSpec {
        // Exercise a zero-byte data operation, not a NULL-output size query.
        buffer_present: true,
        buffer_len: 0,
        length_pointer_null: false,
    };
    let parameter_spec = pkcs11_proxy_ng_types::CkParameterRoundtripSpec {
        buffer_present: true,
        buffer_len: outer_len as u64,
        value: None,
    };
    let output_result = pkcs11_proxy_ng_types::CkOutputBufferResult {
        ck_rv: CkRv::OK,
        returned_len: Some(0),
        value: None,
    };
    let parameter_result = pkcs11_proxy_ng_types::CkParameterRoundtripResult {
        ck_rv: CkRv::OK,
        returned_len: outer_len as u64,
        value: Some(Vec::new().into()),
    };
    let mut output_len = 0;
    unsafe {
        write_exact_message_output(
            &output_spec,
            &parameter_spec,
            call,
            &output_result,
            &parameter_result,
            Some(response),
            std::ptr::NonNull::<u8>::dangling().as_ptr(),
            &mut output_len,
        )
    }
}

#[test]
fn shape_bound_reader_covers_all_shapes_directions_and_stages() {
    let stages = [
        ("Init", MessageParameterStage::Init),
        ("one-shot", MessageParameterStage::OneShot),
        ("Begin", MessageParameterStage::Begin),
        ("Next(non-final)", MessageParameterStage::Next { final_part: false }),
        ("Next(final)", MessageParameterStage::Next { final_part: true }),
    ];
    let mut exercised_cells = 0;

    for direction in [MessageParameterDirection::Encrypt, MessageParameterDirection::Decrypt] {
        for (stage_name, stage) in stages {
            let direction_name = match direction {
                MessageParameterDirection::Encrypt => "Encrypt",
                MessageParameterDirection::Decrypt => "Decrypt",
            };
            let reads_auth = direction == MessageParameterDirection::Decrypt
                && matches!(
                    stage,
                    MessageParameterStage::OneShot
                        | MessageParameterStage::Next { final_part: true }
                );
            let reads_full_generated = direction == MessageParameterDirection::Decrypt
                || matches!(stage, MessageParameterStage::Next { .. });
            let writes_generated = direction == MessageParameterDirection::Encrypt
                && matches!(stage, MessageParameterStage::OneShot | MessageParameterStage::Begin);
            let writes_auth = direction == MessageParameterDirection::Encrypt
                && matches!(
                    stage,
                    MessageParameterStage::OneShot
                        | MessageParameterStage::Next { final_part: true }
                );

            let mut iv = [0x31_u8; 12];
            iv[0] = 0xAB;
            iv[1] = 0xCD;
            let original_iv = iv;
            let mut tag = [0x44_u8; 16];
            let original_tag = tag;
            let outer = CK_GCM_MESSAGE_PARAMS {
                pIv: iv.as_mut_ptr(),
                ulIvLen: iv.len() as CK_ULONG,
                ulIvFixedBits: 12,
                ivGenerator: CKG_GENERATE,
                pTag: tag.as_mut_ptr(),
                ulTagBits: 128,
            };
            let call = unsafe {
                read_message_parameter_call_for_shape(
                    (&outer as *const CK_GCM_MESSAGE_PARAMS).cast(),
                    std::mem::size_of_val(&outer) as CK_ULONG,
                    MessageParameterShape::Gcm,
                    direction,
                    stage,
                )
            }
            .unwrap_or_else(|rv| panic!("GCM {direction_name} {stage_name} read: {rv:?}"));
            let request = call.parameter().unwrap().clone();
            let MessageParameter::GcmMessage(request_gcm) = &request else {
                panic!("GCM {direction_name} {stage_name} variant")
            };
            let expected_iv = if reads_full_generated {
                original_iv.to_vec()
            } else {
                let mut prefix = vec![0; original_iv.len()];
                prefix[0] = 0xAB;
                prefix[1] = 0xC0;
                prefix
            };
            assert_eq!(request_gcm.iv, expected_iv, "GCM {direction_name} {stage_name} IV read");
            assert_eq!(
                request_gcm.tag,
                if reads_auth { original_tag.to_vec() } else { vec![0; original_tag.len()] },
                "GCM {direction_name} {stage_name} tag read",
            );
            let mut response = request.clone();
            if direction == MessageParameterDirection::Encrypt {
                let MessageParameter::GcmMessage(response) = &mut response else { unreachable!() };
                response.iv.fill(0x71);
                response.iv[0] = 0xAB;
                response.iv[1] = 0xC1;
                response.tag.fill(0x72);
            }
            assert_eq!(
                commit_stage_response(&call, std::mem::size_of_val(&outer), &response),
                CKR_OK as CK_RV,
                "GCM {direction_name} {stage_name} writeback",
            );
            assert_eq!(
                iv,
                if writes_generated {
                    let mut expected = [0x71; 12];
                    expected[0] = 0xAB;
                    expected[1] = 0xC1;
                    expected
                } else {
                    original_iv
                },
                "GCM {direction_name} {stage_name} IV write timing",
            );
            assert_eq!(
                tag,
                if writes_auth { [0x72; 16] } else { original_tag },
                "GCM {direction_name} {stage_name} tag write timing",
            );
            exercised_cells += 1;

            let mut nonce = [0x32_u8; 13];
            nonce[0] = 0xBC;
            nonce[1] = 0xDE;
            let original_nonce = nonce;
            let mut mac = [0x55_u8; 12];
            let original_mac = mac;
            let outer = CK_CCM_MESSAGE_PARAMS {
                ulDataLen: 5,
                pNonce: nonce.as_mut_ptr(),
                ulNonceLen: nonce.len() as CK_ULONG,
                ulNonceFixedBits: 12,
                nonceGenerator: CKG_GENERATE,
                pMAC: mac.as_mut_ptr(),
                ulMACLen: mac.len() as CK_ULONG,
            };
            let call = unsafe {
                read_message_parameter_call_for_shape(
                    (&outer as *const CK_CCM_MESSAGE_PARAMS).cast(),
                    std::mem::size_of_val(&outer) as CK_ULONG,
                    MessageParameterShape::Ccm,
                    direction,
                    stage,
                )
            }
            .unwrap_or_else(|rv| panic!("CCM {direction_name} {stage_name} read: {rv:?}"));
            let request = call.parameter().unwrap().clone();
            let MessageParameter::CcmMessage(request_ccm) = &request else {
                panic!("CCM {direction_name} {stage_name} variant")
            };
            let expected_nonce = if reads_full_generated {
                original_nonce.to_vec()
            } else {
                let mut prefix = vec![0; original_nonce.len()];
                prefix[0] = 0xBC;
                prefix[1] = 0xD0;
                prefix
            };
            assert_eq!(
                request_ccm.nonce, expected_nonce,
                "CCM {direction_name} {stage_name} nonce read",
            );
            assert_eq!(
                request_ccm.mac,
                if reads_auth { original_mac.to_vec() } else { vec![0; original_mac.len()] },
                "CCM {direction_name} {stage_name} MAC read",
            );
            let mut response = request.clone();
            if direction == MessageParameterDirection::Encrypt {
                let MessageParameter::CcmMessage(response) = &mut response else { unreachable!() };
                response.nonce.fill(0x73);
                response.nonce[0] = 0xBC;
                response.nonce[1] = 0xD3;
                response.mac.fill(0x74);
            }
            assert_eq!(
                commit_stage_response(&call, std::mem::size_of_val(&outer), &response),
                CKR_OK as CK_RV,
                "CCM {direction_name} {stage_name} writeback",
            );
            assert_eq!(
                nonce,
                if writes_generated {
                    let mut expected = [0x73; 13];
                    expected[0] = 0xBC;
                    expected[1] = 0xD3;
                    expected
                } else {
                    original_nonce
                },
                "CCM {direction_name} {stage_name} nonce write timing",
            );
            assert_eq!(
                mac,
                if writes_auth { [0x74; 12] } else { original_mac },
                "CCM {direction_name} {stage_name} MAC write timing",
            );
            exercised_cells += 1;

            let mut salsa_nonce = [0x66_u8; 12];
            let original_salsa_nonce = salsa_nonce;
            let mut salsa_tag = [0x77_u8; 16];
            let original_salsa_tag = salsa_tag;
            let outer = CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS {
                pNonce: salsa_nonce.as_mut_ptr(),
                ulNonceLen: 96,
                pTag: salsa_tag.as_mut_ptr(),
            };
            let call = unsafe {
                read_message_parameter_call_for_shape(
                    (&outer as *const CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS).cast(),
                    std::mem::size_of_val(&outer) as CK_ULONG,
                    MessageParameterShape::SalsaChacha,
                    direction,
                    stage,
                )
            }
            .unwrap_or_else(|rv| panic!("Salsa/ChaCha {direction_name} {stage_name} read: {rv:?}"));
            let request = call.parameter().unwrap().clone();
            let MessageParameter::SalaChacha(request_salsa) = &request else {
                panic!("Salsa/ChaCha {direction_name} {stage_name} variant")
            };
            assert_eq!(
                request_salsa.nonce, original_salsa_nonce,
                "Salsa/ChaCha {direction_name} {stage_name} nonce read",
            );
            assert_eq!(
                request_salsa.tag,
                if reads_auth {
                    original_salsa_tag.to_vec()
                } else {
                    vec![0; original_salsa_tag.len()]
                },
                "Salsa/ChaCha {direction_name} {stage_name} tag read",
            );
            let mut response = request.clone();
            if direction == MessageParameterDirection::Encrypt {
                let MessageParameter::SalaChacha(response) = &mut response else { unreachable!() };
                response.nonce.fill(0x75);
                response.tag.fill(0x76);
            }
            assert_eq!(
                commit_stage_response(&call, std::mem::size_of_val(&outer), &response),
                CKR_OK as CK_RV,
                "Salsa/ChaCha {direction_name} {stage_name} writeback",
            );
            assert_eq!(
                salsa_nonce, original_salsa_nonce,
                "Salsa/ChaCha {direction_name} {stage_name} nonce is input-only",
            );
            assert_eq!(
                salsa_tag,
                if writes_auth { [0x76; 16] } else { original_salsa_tag },
                "Salsa/ChaCha {direction_name} {stage_name} tag write timing",
            );
            exercised_cells += 1;
        }
    }

    assert_eq!(
        exercised_cells, 30,
        "three shapes x two directions x Init/one-shot/Begin/non-final Next/final Next",
    );
}

#[test]
fn shape_bound_reader_rejects_overlapping_embedded_buffers() {
    let mut shared = [0x5Au8; 16];
    let outer = CK_GCM_MESSAGE_PARAMS {
        pIv: shared.as_mut_ptr(),
        ulIvLen: shared.len() as CK_ULONG,
        ulIvFixedBits: 128,
        ivGenerator: CKG_NO_GENERATE,
        pTag: shared.as_mut_ptr(),
        ulTagBits: 128,
    };

    let result = unsafe {
        read_message_parameter_for_shape(
            (&outer as *const CK_GCM_MESSAGE_PARAMS).cast(),
            std::mem::size_of_val(&outer) as CK_ULONG,
            MessageParameterShape::Gcm,
            MessageParameterDirection::Decrypt,
            MessageParameterStage::OneShot,
        )
    };

    assert_eq!(result.unwrap_err(), CkRv::MECHANISM_PARAM_INVALID);
}

#[test]
fn shape_bound_reader_rejects_embedded_range_end_overflow_before_reading() {
    let mut tag = [0x5Au8; 16];
    let outer = CK_GCM_MESSAGE_PARAMS {
        pIv: (usize::MAX - 1) as *mut CK_BYTE,
        ulIvLen: 4,
        ulIvFixedBits: 0,
        ivGenerator: CKG_NO_GENERATE,
        pTag: tag.as_mut_ptr(),
        ulTagBits: 128,
    };

    let result = unsafe {
        read_message_parameter_for_shape(
            (&outer as *const CK_GCM_MESSAGE_PARAMS).cast(),
            std::mem::size_of_val(&outer) as CK_ULONG,
            MessageParameterShape::Gcm,
            MessageParameterDirection::Encrypt,
            MessageParameterStage::OneShot,
        )
    };

    assert_eq!(result.unwrap_err(), CkRv::MECHANISM_PARAM_INVALID);
}

#[test]
fn shape_bound_reader_rejects_outer_and_embedded_overlap() {
    let mut tag = [0x5Au8; 16];
    let mut outer = CK_GCM_MESSAGE_PARAMS {
        pIv: std::ptr::null_mut(),
        ulIvLen: 12,
        ulIvFixedBits: 96,
        ivGenerator: CKG_NO_GENERATE,
        pTag: tag.as_mut_ptr(),
        ulTagBits: 128,
    };
    outer.pIv = (&mut outer as *mut CK_GCM_MESSAGE_PARAMS).cast();

    let result = unsafe {
        read_message_parameter_for_shape(
            (&outer as *const CK_GCM_MESSAGE_PARAMS).cast(),
            std::mem::size_of_val(&outer) as CK_ULONG,
            MessageParameterShape::Gcm,
            MessageParameterDirection::Encrypt,
            MessageParameterStage::OneShot,
        )
    };

    assert_eq!(result.unwrap_err(), CkRv::MECHANISM_PARAM_INVALID);
}

#[test]
fn message_call_ranges_reject_output_length_alias_with_embedded_storage() {
    let mut iv = [0x11u8; 12];
    let mut output_len = 8 as CK_ULONG;
    let outer = CK_GCM_MESSAGE_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 96,
        ivGenerator: CKG_NO_GENERATE,
        pTag: (&mut output_len as CK_ULONG_PTR).cast(),
        ulTagBits: (std::mem::size_of::<CK_ULONG>() * 8) as CK_ULONG,
    };
    let input = [0x22u8; 1];
    let mut output = [0u8; 1];

    let result = unsafe {
        read_message_parameter_call_for_shape_with_memory(
            (&outer as *const CK_GCM_MESSAGE_PARAMS).cast(),
            std::mem::size_of_val(&outer) as CK_ULONG,
            MessageParameterShape::Gcm,
            MessageParameterDirection::Encrypt,
            MessageParameterStage::OneShot,
            MessageCallMemory::output(
                std::ptr::null(),
                0,
                input.as_ptr(),
                input.len() as CK_ULONG,
                output.as_mut_ptr(),
                output.len() as u64,
                &mut output_len,
            ),
        )
    };

    assert_eq!(result.unwrap_err(), CkRv::MECHANISM_PARAM_INVALID);
}

#[test]
fn message_call_ranges_reject_partial_main_buffer_overlap() {
    let mut shared = [0u8; 16];
    let mut output_len = 8 as CK_ULONG;

    let result = unsafe {
        read_message_parameter_call_for_shape_with_memory(
            std::ptr::null(),
            0,
            MessageParameterShape::Gcm,
            MessageParameterDirection::Encrypt,
            MessageParameterStage::OneShot,
            MessageCallMemory::output(
                std::ptr::null(),
                0,
                shared.as_ptr(),
                8,
                shared.as_mut_ptr().add(1),
                8,
                &mut output_len,
            ),
        )
    };

    assert_eq!(result.unwrap_err(), CkRv::MECHANISM_PARAM_INVALID);
}

#[test]
fn message_call_ranges_allow_exact_same_base_main_in_place() {
    let mut shared = [0u8; 16];
    let mut output_len = shared.len() as CK_ULONG;

    let call = unsafe {
        read_message_parameter_call_for_shape_with_memory(
            std::ptr::null(),
            0,
            MessageParameterShape::Gcm,
            MessageParameterDirection::Encrypt,
            MessageParameterStage::OneShot,
            MessageCallMemory::output(
                std::ptr::null(),
                0,
                shared.as_ptr(),
                8,
                shared.as_mut_ptr(),
                shared.len() as u64,
                &mut output_len,
            ),
        )
    }
    .expect("same-base plaintext/ciphertext is the one permitted alias");

    assert!(call.parameter().is_none());
}

#[test]
fn invalid_structured_scalars_reject_poison_pointers_before_reading() {
    let poison = std::ptr::without_provenance_mut::<CK_BYTE>(1);
    let mut iv = [0x11u8; 12];
    let gcm = CK_GCM_MESSAGE_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 96,
        ivGenerator: CKG_NO_GENERATE,
        pTag: poison,
        ulTagBits: 129,
    };
    assert_eq!(
        unsafe {
            read_message_parameter_for_shape(
                (&gcm as *const CK_GCM_MESSAGE_PARAMS).cast(),
                std::mem::size_of_val(&gcm) as CK_ULONG,
                MessageParameterShape::Gcm,
                MessageParameterDirection::Decrypt,
                MessageParameterStage::OneShot,
            )
        }
        .unwrap_err(),
        CkRv::MECHANISM_PARAM_INVALID,
    );

    let mut mac = [0x22u8; 16];
    for nonce_len in [6, 14] {
        let ccm = CK_CCM_MESSAGE_PARAMS {
            ulDataLen: 0,
            pNonce: poison,
            ulNonceLen: nonce_len,
            ulNonceFixedBits: 0,
            nonceGenerator: CKG_NO_GENERATE,
            pMAC: mac.as_mut_ptr(),
            ulMACLen: mac.len() as CK_ULONG,
        };
        assert_eq!(
            unsafe {
                read_message_parameter_for_shape(
                    (&ccm as *const CK_CCM_MESSAGE_PARAMS).cast(),
                    std::mem::size_of_val(&ccm) as CK_ULONG,
                    MessageParameterShape::Ccm,
                    MessageParameterDirection::Decrypt,
                    MessageParameterStage::OneShot,
                )
            }
            .unwrap_err(),
            CkRv::MECHANISM_PARAM_INVALID,
        );
    }

    let mut nonce = [0x33u8; 12];
    let ccm = CK_CCM_MESSAGE_PARAMS {
        ulDataLen: 0,
        pNonce: nonce.as_mut_ptr(),
        ulNonceLen: nonce.len() as CK_ULONG,
        ulNonceFixedBits: 0,
        nonceGenerator: CKG_NO_GENERATE,
        pMAC: poison,
        ulMACLen: 5,
    };
    assert_eq!(
        unsafe {
            read_message_parameter_for_shape(
                (&ccm as *const CK_CCM_MESSAGE_PARAMS).cast(),
                std::mem::size_of_val(&ccm) as CK_ULONG,
                MessageParameterShape::Ccm,
                MessageParameterDirection::Decrypt,
                MessageParameterStage::OneShot,
            )
        }
        .unwrap_err(),
        CkRv::MECHANISM_PARAM_INVALID,
    );

    let salsa =
        CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS { pNonce: poison, ulNonceLen: 128, pTag: poison };
    assert_eq!(
        unsafe {
            read_message_parameter_for_shape(
                (&salsa as *const CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS).cast(),
                std::mem::size_of_val(&salsa) as CK_ULONG,
                MessageParameterShape::SalsaChacha,
                MessageParameterDirection::Decrypt,
                MessageParameterStage::OneShot,
            )
        }
        .unwrap_err(),
        CkRv::MECHANISM_PARAM_INVALID,
    );
}

#[test]
fn null_gcm_extent_avoids_bit_length_overflow_without_allocating() {
    let gcm = CK_GCM_MESSAGE_PARAMS {
        pIv: std::ptr::null_mut(),
        ulIvLen: CK_ULONG::MAX,
        ulIvFixedBits: CK_ULONG::MAX,
        ivGenerator: CKG_NO_GENERATE,
        pTag: std::ptr::null_mut(),
        ulTagBits: 128,
    };

    let parameter = unsafe {
        read_message_parameter_for_shape(
            (&gcm as *const CK_GCM_MESSAGE_PARAMS).cast(),
            std::mem::size_of_val(&gcm) as CK_ULONG,
            MessageParameterShape::Gcm,
            MessageParameterDirection::Encrypt,
            MessageParameterStage::Init,
        )
    }
    .expect("NULL extents allocate no backing buffers")
    .expect("GCM shape should produce a structured parameter");

    let MessageParameter::GcmMessage(parameter) = parameter else {
        panic!("expected GCM message parameter")
    };
    assert_eq!(parameter.iv_null_len, Some(CK_ULONG::MAX as u64));
    assert_eq!(parameter.iv_fixed_bits, CK_ULONG::MAX as u64);
    assert_eq!(parameter.tag_null_len, Some(16));
}

#[test]
fn materialized_embedded_extent_over_transport_ceiling_rejects_poison_before_reading() {
    let poison = std::ptr::without_provenance_mut::<CK_BYTE>(1);
    let mut tag = [0u8; 16];
    let gcm = CK_GCM_MESSAGE_PARAMS {
        pIv: poison,
        ulIvLen: (super::MAX_SERIALIZABLE_BYTES as CK_ULONG) + 1,
        ulIvFixedBits: 0,
        ivGenerator: CKG_NO_GENERATE,
        pTag: tag.as_mut_ptr(),
        ulTagBits: 128,
    };

    assert_eq!(
        unsafe {
            read_message_parameter_for_shape(
                (&gcm as *const CK_GCM_MESSAGE_PARAMS).cast(),
                std::mem::size_of_val(&gcm) as CK_ULONG,
                MessageParameterShape::Gcm,
                MessageParameterDirection::Encrypt,
                MessageParameterStage::OneShot,
            )
        }
        .unwrap_err(),
        CkRv::MECHANISM_PARAM_INVALID,
    );
}

#[test]
fn salsa_reader_treats_nonce_length_as_bits() {
    let mut nonce = [0x33u8; 12];
    let mut tag = [0x44u8; 16];
    let params = CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS {
        pNonce: nonce.as_mut_ptr(),
        ulNonceLen: 96,
        pTag: tag.as_mut_ptr(),
    };

    let parameter = unsafe {
        read_message_parameter_for_shape(
            (&params as *const CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS).cast(),
            std::mem::size_of_val(&params) as CK_ULONG,
            MessageParameterShape::SalsaChacha,
            MessageParameterDirection::Decrypt,
            MessageParameterStage::OneShot,
        )
    }
    .unwrap()
    .unwrap();

    let MessageParameter::SalaChacha(parameter) = parameter else { panic!("expected Salsa") };
    assert_eq!(parameter.nonce_bits, 96);
    assert_eq!(parameter.nonce, nonce);
}

#[test]
fn write_mechanism_output_params_writes_tls12_pversion() {
    // Verify that the shim's writeback function fills in the
    // CK_VERSION buffer pointed at by
    // CK_TLS12_MASTER_KEY_DERIVE_PARAMS.pVersion when the backend
    // returns a Tls12MasterKeyDerive params variant. Without this,
    // applications calling C_DeriveKey on a remote HSM would never
    // learn the negotiated TLS version.
    use pkcs11_proxy_ng_types::{
        CkMechanismParams, CkMechanismType, SslRandomData, Tls12MasterKeyDeriveParams,
    };

    let mut version = CK_VERSION { major: 0, minor: 0 };
    let mut params = CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: std::ptr::null_mut(),
            ulClientRandomLen: 0,
            pServerRandom: std::ptr::null_mut(),
            ulServerRandomLen: 0,
        },
        pVersion: &mut version,
        prfHashMechanism: CkMechanismType::SHA256.0,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::TLS12_MASTER_KEY_DERIVE.0,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
    };

    let mech_out = CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
        random_info: SslRandomData { client_random: vec![], server_random: vec![] },
        version_major: 3,
        version_minor: 3, // TLS 1.2
        prf_hash_mechanism: CkMechanismType::SHA256,
    });

    unsafe {
        super::prepare_mechanism_output_params(&mut mechanism, &mech_out)
            .expect("valid output prepares")
            .commit()
    }

    assert_eq!(version.major, 3);
    assert_eq!(version.minor, 3);
}

#[test]
fn write_mechanism_output_params_writes_pbe_init_vector() {
    // C2: the HSM-generated CK_PBE_PARAMS.pInitVector must be written back
    // into the caller's buffer after PBE key generation. Only the IV is
    // written; pPassword/pSalt are left untouched.
    use pkcs11_proxy_ng_types::{CkMechanismParams, CkMechanismType, PbeParams};

    let mut iv_buf = [0u8; 8];
    let password = *b"secret";
    let salt = *b"saltsalt";
    let mut params = CK_PBE_PARAMS {
        pInitVector: iv_buf.as_mut_ptr(),
        pPassword: password.as_ptr() as *mut _,
        ulPasswordLen: password.len() as CK_ULONG,
        pSalt: salt.as_ptr() as *mut _,
        ulSaltLen: salt.len() as CK_ULONG,
        ulIteration: 1000,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::PBE_SHA1_DES3_EDE_CBC.0,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_PBE_PARAMS>() as CK_ULONG,
    };

    let generated_iv = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    let mech_out = CkMechanismParams::Pbe(PbeParams {
        init_vector: generated_iv.clone().into(),
        password: Vec::new().into(),
        salt: Vec::new().into(),
        iteration: 1000,
    });

    unsafe {
        super::prepare_mechanism_output_params(&mut mechanism, &mech_out)
            .expect("valid output prepares")
            .commit()
    }

    // The generated IV landed in the caller's buffer; password/salt intact.
    assert_eq!(&iv_buf[..], generated_iv.as_slice());
    assert_eq!(&password[..], b"secret");
    assert_eq!(&salt[..], b"saltsalt");
}

#[test]
fn write_mechanism_output_params_pbe_safe_when_init_vector_null() {
    // PBA (HMAC key gen) passes pInitVector = NULL — the writeback must be a
    // no-op rather than dereferencing NULL.
    use pkcs11_proxy_ng_types::{CkMechanismParams, CkMechanismType, PbeParams};

    let mut params = CK_PBE_PARAMS {
        pInitVector: std::ptr::null_mut(),
        pPassword: std::ptr::null_mut(),
        ulPasswordLen: 0,
        pSalt: std::ptr::null_mut(),
        ulSaltLen: 0,
        ulIteration: 1,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::PBA_SHA1_WITH_SHA1_HMAC.0,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_PBE_PARAMS>() as CK_ULONG,
    };
    let mech_out = CkMechanismParams::Pbe(PbeParams {
        init_vector: vec![9u8; 8].into(),
        password: Vec::new().into(),
        salt: Vec::new().into(),
        iteration: 1,
    });
    // Must not panic / deref NULL.
    unsafe {
        super::prepare_mechanism_output_params(&mut mechanism, &mech_out)
            .expect("valid output prepares")
            .commit()
    }
}

#[test]
fn write_mechanism_output_params_writes_tls_prf_output() {
    // W1-C5-01: the daemon-returned PRF bytes land in the caller's
    // pOutput buffer and *pulOutputLen reports the written length.
    use pkcs11_proxy_ng_types::{CkMechanismParams, CkMechanismType, TlsPrfParams};

    let mut out_buf = [0u8; 48];
    let mut out_len = out_buf.len() as CK_ULONG;
    let mut params = CK_TLS_PRF_PARAMS {
        pSeed: std::ptr::null_mut(),
        ulSeedLen: 0,
        pLabel: std::ptr::null_mut(),
        ulLabelLen: 0,
        pOutput: out_buf.as_mut_ptr(),
        pulOutputLen: &mut out_len,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::TLS_PRF.0,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS_PRF_PARAMS>() as CK_ULONG,
    };

    let prf_bytes = vec![0x5Au8; 32];
    let mech_out = CkMechanismParams::TlsPrf(TlsPrfParams {
        seed: Vec::new().into(),
        label: Vec::new().into(),
        output_len: 32,
        output: prf_bytes.clone().into(),
    });

    unsafe {
        super::prepare_mechanism_output_params(&mut mechanism, &mech_out)
            .expect("valid output prepares")
            .commit()
    }

    assert_eq!(&out_buf[..32], prf_bytes.as_slice());
    assert!(out_buf[32..].iter().all(|&b| b == 0), "tail untouched");
    assert_eq!(out_len, 32);
}

#[test]
fn write_mechanism_output_params_writes_wtls_prf_output() {
    // W1-C5-01: WTLS PRF has the same OUT contract as TLS PRF.
    use pkcs11_proxy_ng_types::{CkMechanismParams, CkMechanismType, WtlsPrfParams};

    let mut out_buf = [0u8; 20];
    let mut out_len = out_buf.len() as CK_ULONG;
    let mut params = CK_WTLS_PRF_PARAMS {
        DigestMechanism: CkMechanismType::SHA256.0 as CK_MECHANISM_TYPE,
        pSeed: std::ptr::null_mut(),
        ulSeedLen: 0,
        pLabel: std::ptr::null_mut(),
        ulLabelLen: 0,
        pOutput: out_buf.as_mut_ptr(),
        pulOutputLen: &mut out_len,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::WTLS_PRF.0,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_WTLS_PRF_PARAMS>() as CK_ULONG,
    };

    let prf_bytes = vec![0xA5u8; 20];
    let mech_out = CkMechanismParams::WtlsPrf(WtlsPrfParams {
        digest_mechanism: CkMechanismType::SHA256,
        seed: Vec::new().into(),
        label: Vec::new().into(),
        output_len: 20,
        output: prf_bytes.clone().into(),
    });

    unsafe {
        super::prepare_mechanism_output_params(&mut mechanism, &mech_out)
            .expect("valid output prepares")
            .commit()
    }

    assert_eq!(&out_buf[..], prf_bytes.as_slice());
    assert_eq!(out_len, 20);
}

#[test]
fn write_mechanism_output_params_prf_safe_when_output_null() {
    // W1-C5-01: NULL pOutput/pulOutputLen is a no-op, never a NULL deref.
    use pkcs11_proxy_ng_types::{CkMechanismParams, CkMechanismType, TlsPrfParams};

    let mut params = CK_TLS_PRF_PARAMS {
        pSeed: std::ptr::null_mut(),
        ulSeedLen: 0,
        pLabel: std::ptr::null_mut(),
        ulLabelLen: 0,
        pOutput: std::ptr::null_mut(),
        pulOutputLen: std::ptr::null_mut(),
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::TLS_PRF.0,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS_PRF_PARAMS>() as CK_ULONG,
    };
    let mech_out = CkMechanismParams::TlsPrf(TlsPrfParams {
        seed: Vec::new().into(),
        label: Vec::new().into(),
        output_len: 8,
        output: vec![0x5Au8; 8].into(),
    });
    unsafe {
        super::prepare_mechanism_output_params(&mut mechanism, &mech_out)
            .expect("valid output prepares")
            .commit()
    }
    // Did not crash, did not write through NULL.
}

#[test]
fn write_mechanism_output_params_writes_ssl3_master_key_version() {
    // W1-C5-01: mirrors the TLS 1.2 pVersion writeback for the SSL3
    // master-key-derive shape.
    use pkcs11_proxy_ng_types::{
        CkMechanismParams, CkMechanismType, Ssl3MasterKeyDeriveParams, SslRandomData,
    };

    let mut version = CK_VERSION { major: 0, minor: 0 };
    let mut params = CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: std::ptr::null_mut(),
            ulClientRandomLen: 0,
            pServerRandom: std::ptr::null_mut(),
            ulServerRandomLen: 0,
        },
        pVersion: &mut version,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::SSL3_MASTER_KEY_DERIVE.0,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
    };

    let mech_out = CkMechanismParams::Ssl3MasterKeyDerive(Ssl3MasterKeyDeriveParams {
        random_info: SslRandomData { client_random: vec![], server_random: vec![] },
        version_major: 3,
        version_minor: 0,
    });

    unsafe {
        super::prepare_mechanism_output_params(&mut mechanism, &mech_out)
            .expect("valid output prepares")
            .commit()
    }

    assert_eq!(version.major, 3);
    assert_eq!(version.minor, 0);
}

#[test]
fn write_mechanism_output_params_tls12_safe_when_pversion_null() {
    // The TLS12 writeback path is a no-op when pVersion is NULL —
    // matching the spec which says the caller may pass NULL to
    // suppress version output.  Guard against UB.
    use pkcs11_proxy_ng_types::{
        CkMechanismParams, CkMechanismType, SslRandomData, Tls12MasterKeyDeriveParams,
    };

    let mut params = CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: std::ptr::null_mut(),
            ulClientRandomLen: 0,
            pServerRandom: std::ptr::null_mut(),
            ulServerRandomLen: 0,
        },
        pVersion: std::ptr::null_mut(),
        prfHashMechanism: CkMechanismType::SHA256.0,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CkMechanismType::TLS12_MASTER_KEY_DERIVE.0,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
    };

    let mech_out = CkMechanismParams::Tls12MasterKeyDerive(Tls12MasterKeyDeriveParams {
        random_info: SslRandomData { client_random: vec![], server_random: vec![] },
        version_major: 3,
        version_minor: 3,
        prf_hash_mechanism: CkMechanismType::SHA256,
    });

    unsafe {
        super::prepare_mechanism_output_params(&mut mechanism, &mech_out)
            .expect("valid output prepares")
            .commit()
    }
    // Did not crash, did not write through NULL.
}

#[test]
fn wtls_master_key_derive_reads_version_byte_and_writes_it_back() {
    use pkcs11_proxy_ng_types::{
        CkMechanismParams, CkMechanismType, WtlsMasterKeyDeriveParams, WtlsRandomData,
    };

    const CKM_WTLS_MASTER_KEY_DERIVE: CK_MECHANISM_TYPE = 0x0000_03D1;

    let mut client_random = [0xA1u8, 0xA2, 0xA3];
    let mut server_random = [0xB1u8, 0xB2];
    let mut version = 1u8;
    let mut params = CK_WTLS_MASTER_KEY_DERIVE_PARAMS {
        DigestMechanism: CkMechanismType::SHA256.0,
        RandomInfo: CK_WTLS_RANDOM_DATA {
            pClientRandom: client_random.as_mut_ptr(),
            ulClientRandomLen: client_random.len() as CK_ULONG,
            pServerRandom: server_random.as_mut_ptr(),
            ulServerRandomLen: server_random.len() as CK_ULONG,
        },
        pVersion: &mut version,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_WTLS_MASTER_KEY_DERIVE,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_WTLS_MASTER_KEY_DERIVE_PARAMS>() as CK_ULONG,
    };

    match unsafe { super::read_mechanism_with_shape(&mechanism, Some("wtls_master_key_derive")) }
        .expect("read mechanism")
        .params
        .expect("wtls params")
    {
        CkMechanismParams::WtlsMasterKeyDerive(params) => {
            assert_eq!(params.digest_mechanism.0, CkMechanismType::SHA256.0 as u64);
            assert_eq!(params.random_info.client_random, client_random);
            assert_eq!(params.random_info.server_random, server_random);
            assert_eq!(params.version, 1);
        }
        other => panic!("unexpected WTLS params: {other:?}"),
    }

    let mech_out = CkMechanismParams::WtlsMasterKeyDerive(WtlsMasterKeyDeriveParams {
        digest_mechanism: CkMechanismType::SHA256,
        random_info: WtlsRandomData {
            client_random: client_random.to_vec(),
            server_random: server_random.to_vec(),
        },
        version: 2,
    });
    unsafe {
        super::prepare_mechanism_output_params(&mut mechanism, &mech_out)
            .expect("valid output prepares")
            .commit()
    }

    assert_eq!(version, 2);
}

#[test]
fn wtls_key_mat_reads_caller_stack_params_and_writes_outputs_back() {
    use pkcs11_proxy_ng_types::{
        CkMechanismParams, CkMechanismType, WtlsKeyMatParams, WtlsRandomData,
    };

    const CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE: CK_MECHANISM_TYPE = 0x0000_03D4;

    let mut client_random = [0xC1u8, 0xC2, 0xC3];
    let mut server_random = [0xD1u8, 0xD2];
    let mut iv = [0u8; 4];
    let mut key_mat_out = CK_WTLS_KEY_MAT_OUT { hMacSecret: 0, hKey: 0, pIV: iv.as_mut_ptr() };
    let mut params = CK_WTLS_KEY_MAT_PARAMS {
        DigestMechanism: CkMechanismType::SHA256.0,
        ulMacSizeInBits: 160,
        ulKeySizeInBits: 128,
        ulIVSizeInBits: 32,
        ulSequenceNumber: 7,
        bIsExport: CK_TRUE,
        RandomInfo: CK_WTLS_RANDOM_DATA {
            pClientRandom: client_random.as_mut_ptr(),
            ulClientRandomLen: client_random.len() as CK_ULONG,
            pServerRandom: server_random.as_mut_ptr(),
            ulServerRandomLen: server_random.len() as CK_ULONG,
        },
        pReturnedKeyMaterial: &mut key_mat_out,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_WTLS_KEY_MAT_PARAMS>() as CK_ULONG,
    };

    match unsafe { super::read_mechanism_with_shape(&mechanism, Some("wtls_key_mat")) }
        .expect("read mechanism")
        .params
        .expect("wtls key material params")
    {
        CkMechanismParams::WtlsKeyMat(params) => {
            assert_eq!(params.digest_mechanism.0, CkMechanismType::SHA256.0 as u64);
            assert_eq!(params.mac_size_bits, 160);
            assert_eq!(params.key_size_bits, 128);
            assert_eq!(params.iv_size_bits, 32);
            assert_eq!(params.sequence_number, 7);
            assert!(params.is_export);
            assert_eq!(params.random_info.client_random, client_random);
            assert_eq!(params.random_info.server_random, server_random);
            assert_eq!(params.mac_secret_handle.0, 0);
            assert_eq!(params.key_handle.0, 0);
            assert_eq!(params.iv, SecretBytes::copy_from_slice(&[0u8; 4]));
        }
        other => panic!("unexpected WTLS key material params: {other:?}"),
    }

    let mech_out = CkMechanismParams::WtlsKeyMat(WtlsKeyMatParams {
        digest_mechanism: CkMechanismType::SHA256,
        mac_size_bits: 160,
        key_size_bits: 128,
        iv_size_bits: 32,
        sequence_number: 7,
        is_export: true,
        random_info: WtlsRandomData {
            client_random: client_random.to_vec(),
            server_random: server_random.to_vec(),
        },
        mac_secret_handle: CkObjectHandle(101),
        key_handle: CkObjectHandle(202),
        iv: vec![0xA1, 0xA2, 0xA3, 0xA4].into(),
    });
    unsafe {
        super::prepare_mechanism_output_params(&mut mechanism, &mech_out)
            .expect("valid output prepares")
            .commit()
    }

    // E0793: params structs are packed on Windows; assert on by-value copies.
    let (h_mac_secret, h_key) = (key_mat_out.hMacSecret, key_mat_out.hKey);
    assert_eq!(h_mac_secret, 101);
    assert_eq!(h_key, 202);
    assert_eq!(iv, [0xA1, 0xA2, 0xA3, 0xA4]);
}

#[test]
fn ssl3_key_mat_reads_caller_stack_params_and_writes_outputs_back() {
    use pkcs11_proxy_ng_types::{
        CkMechanismParams, CkMechanismType, Ssl3KeyMatParams, SslRandomData,
    };

    const CKM_TLS12_KEY_AND_MAC_DERIVE: CK_MECHANISM_TYPE = 0x0000_03E1;

    let mut client_random = [0x11u8, 0x12, 0x13];
    let mut server_random = [0x21u8, 0x22];
    let mut client_iv = [0u8; 4];
    let mut server_iv = [0u8; 4];
    let mut key_mat_out = CK_SSL3_KEY_MAT_OUT {
        hClientMacSecret: 0,
        hServerMacSecret: 0,
        hClientKey: 0,
        hServerKey: 0,
        pIVClient: client_iv.as_mut_ptr(),
        pIVServer: server_iv.as_mut_ptr(),
    };
    let mut params = CK_TLS12_KEY_MAT_PARAMS {
        ulMacSizeInBits: 160,
        ulKeySizeInBits: 128,
        ulIVSizeInBits: 32,
        bIsExport: CK_FALSE,
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: client_random.as_mut_ptr(),
            ulClientRandomLen: client_random.len() as CK_ULONG,
            pServerRandom: server_random.as_mut_ptr(),
            ulServerRandomLen: server_random.len() as CK_ULONG,
        },
        pReturnedKeyMaterial: &mut key_mat_out,
        prfHashMechanism: CkMechanismType::SHA256.0,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_TLS12_KEY_AND_MAC_DERIVE,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_TLS12_KEY_MAT_PARAMS>() as CK_ULONG,
    };

    match unsafe { super::read_mechanism_with_shape(&mechanism, Some("ssl3_key_mat")) }
        .expect("read mechanism")
        .params
        .expect("ssl3/tls key material params")
    {
        CkMechanismParams::Ssl3KeyMat(params) => {
            assert_eq!(params.mac_size_bits, 160);
            assert_eq!(params.key_size_bits, 128);
            assert_eq!(params.iv_size_bits, 32);
            assert!(!params.is_export);
            assert_eq!(params.random_info.client_random, client_random);
            assert_eq!(params.random_info.server_random, server_random);
            assert_eq!(params.prf_hash_mechanism.0, CkMechanismType::SHA256.0 as u64);
            assert_eq!(params.client_mac_secret_handle.0, 0);
            assert_eq!(params.server_mac_secret_handle.0, 0);
            assert_eq!(params.client_key_handle.0, 0);
            assert_eq!(params.server_key_handle.0, 0);
            assert_eq!(params.client_iv, SecretBytes::copy_from_slice(&[0u8; 4]));
            assert_eq!(params.server_iv, SecretBytes::copy_from_slice(&[0u8; 4]));
        }
        other => panic!("unexpected SSL3/TLS key material params: {other:?}"),
    }

    let mech_out = CkMechanismParams::Ssl3KeyMat(Ssl3KeyMatParams {
        mac_size_bits: 160,
        key_size_bits: 128,
        iv_size_bits: 32,
        is_export: false,
        random_info: SslRandomData {
            client_random: client_random.to_vec(),
            server_random: server_random.to_vec(),
        },
        prf_hash_mechanism: CkMechanismType::SHA256,
        client_mac_secret_handle: CkObjectHandle(101),
        server_mac_secret_handle: CkObjectHandle(102),
        client_key_handle: CkObjectHandle(201),
        server_key_handle: CkObjectHandle(202),
        client_iv: vec![0xA1, 0xA2, 0xA3, 0xA4].into(),
        server_iv: vec![0xB1, 0xB2, 0xB3, 0xB4].into(),
    });
    unsafe {
        super::prepare_mechanism_output_params(&mut mechanism, &mech_out)
            .expect("valid output prepares")
            .commit()
    }

    let (h_client_mac, h_server_mac, h_client_key, h_server_key) = (
        key_mat_out.hClientMacSecret,
        key_mat_out.hServerMacSecret,
        key_mat_out.hClientKey,
        key_mat_out.hServerKey,
    );
    assert_eq!(h_client_mac, 101);
    assert_eq!(h_server_mac, 102);
    assert_eq!(h_client_key, 201);
    assert_eq!(h_server_key, 202);
    assert_eq!(client_iv, [0xA1, 0xA2, 0xA3, 0xA4]);
    assert_eq!(server_iv, [0xB1, 0xB2, 0xB3, 0xB4]);
}

/// LP64 layout derivation behind the 48-byte GCM envelope pins (Linux
/// x86_64/s390x, macOS aarch64/x86_64): `CK_ULONG`/`CK_GENERATOR_FUNCTION`
/// are 8-byte `c_ulong`, pointers are 8 bytes, so the six fields sit at
/// 0/8/16/24/32/40 with zero padding. Pins the derivation the macOS
/// const asserts rely on; the asserts themselves compile on their targets.
#[cfg(all(target_pointer_width = "64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn gcm_message_params_lp64_layout_derives_48() {
    assert_eq!(std::mem::size_of::<CK_ULONG>(), 8, "LP64 CK_ULONG is 8 bytes");
    assert_eq!(std::mem::size_of::<CK_GENERATOR_FUNCTION>(), 8, "generator fn is CK_ULONG");
    assert_eq!(std::mem::size_of::<*mut CK_BYTE>(), 8, "64-bit pointers are 8 bytes");
    assert_eq!(std::mem::offset_of!(CK_GCM_MESSAGE_PARAMS, pIv), 0);
    assert_eq!(std::mem::offset_of!(CK_GCM_MESSAGE_PARAMS, ulIvLen), 8);
    assert_eq!(std::mem::offset_of!(CK_GCM_MESSAGE_PARAMS, ulIvFixedBits), 16);
    assert_eq!(std::mem::offset_of!(CK_GCM_MESSAGE_PARAMS, ivGenerator), 24);
    assert_eq!(std::mem::offset_of!(CK_GCM_MESSAGE_PARAMS, pTag), 32);
    assert_eq!(std::mem::offset_of!(CK_GCM_MESSAGE_PARAMS, ulTagBits), 40);
    assert_eq!(std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>(), 48, "six 8-byte fields, no padding");
}
