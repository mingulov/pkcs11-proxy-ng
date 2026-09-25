//! Regression observations through the actual native exact-call boundary.
use super::*;
#[path = "../../../../tests/ffi_oracles/exact_outputs/src/lib.rs"]
mod oracle;
use oracle::*;
// W1-L1-05: STATE-touching tests serialize on the oracle's shared test
// lock (the oracle's own poison tests take the same lock in both test
// binaries); no file-local lock domain here.

fn invoke(
    spec: &CkOutputBufferSpec,
    rv: CkRv,
    length: Option<u64>,
) -> (CkResult<CkOutputBufferResult>, ExactOracleObservation) {
    invoke_actions(spec, rv, u32::from(length.is_some()), length.unwrap_or(0), 0)
}

/// `invoke` with full byte-leaf action control (W1-L10-18 hostile matrices).
fn invoke_actions(
    spec: &CkOutputBufferSpec,
    rv: CkRv,
    length_action: u32,
    returned_length: u64,
    output_action: u32,
) -> (CkResult<CkOutputBufferResult>, ExactOracleObservation) {
    unsafe {
        ExactOracle_SetScenario(&ExactOracleScenario {
            rv: rv.0,
            length_action,
            returned_length,
            parameter_action: 0,
            output_action,
            handle_action: 0,
        });
    }
    ExactOracle_ResetObservation();
    // Direct-leaf oracle: admit on a throwaway test domain.
    let choke_domain = crate::ffi::native_domain::LifecycleDomain::new();
    choke_domain.open_for_tests();
    let choke_admission = choke_domain.admit_ordinary().expect("test domain admits");
    let result = FfiBackend::single_call_bytes_exact(&choke_admission, spec, |out, len| unsafe {
        ExactOracle_ByteOutput(out, len)
    });
    let mut observation = ExactOracleObservation::default();
    unsafe {
        ExactOracle_GetObservation(&mut observation);
    }
    (result, observation)
}

#[test]
fn exact_data_error_preserves_provider_length_changed_unchanged_zero_and_all_ones() {
    let _guard = oracle::ORACLE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let spec =
        CkOutputBufferSpec { buffer_present: true, buffer_len: 8, length_pointer_null: false };
    for rv in [CkRv::DEVICE_ERROR, CkRv::ARGUMENTS_BAD, CkRv(0x8000_0017)] {
        for length in [Some(7), Some(8), Some(0), Some(cryptoki_sys::CK_ULONG::MAX as u64), None] {
            let (result, observation) = invoke(&spec, rv, length);
            assert_eq!(observation.calls, 1);
            assert_eq!(observation.incoming_capacity, 8);
            let result = result.expect("a completed native error must retain its envelope");
            assert_eq!(result.ck_rv, rv);
            assert_eq!(result.returned_len, Some(length.unwrap_or(8)));
            assert_eq!(result.value, None);
        }
    }
}

#[test]
fn exact_query_error_preserves_provably_written_length_and_reports_ambiguous_zero() {
    let _guard = oracle::ORACLE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let spec =
        CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: false };
    for length in [Some(7), Some(cryptoki_sys::CK_ULONG::MAX as u64), Some(0), None] {
        let (result, observation) = invoke(&spec, CkRv::DEVICE_ERROR, length);
        assert_eq!(observation.calls, 1);
        assert_eq!(observation.capacity_read, 0);
        assert_eq!(observation.length_stores, u64::from(length.is_some()));
        let result = result.expect("a completed query error must retain its envelope");
        assert_eq!(result.ck_rv, CkRv::DEVICE_ERROR);
        assert_eq!(result.returned_len, length.filter(|n| *n != 0));
        assert_eq!(result.value, None);
    }
}

#[test]
fn exact_over_capacity_length_preserves_rv_without_exposing_storage() {
    let _guard = oracle::ORACLE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let spec =
        CkOutputBufferSpec { buffer_present: true, buffer_len: 4, length_pointer_null: false };
    for rv in [CkRv::OK, CkRv::BUFFER_TOO_SMALL, CkRv::DEVICE_ERROR] {
        let (result, observation) = invoke(&spec, rv, Some(9));
        assert_eq!(observation.calls, 1);
        assert_eq!(observation.output_stores, 0);
        let result = result.expect("completed native envelope");
        assert_eq!(result.ck_rv, rv);
        assert_eq!(result.returned_len, Some(9));
        assert_eq!(result.value, None, "no bounded value exists for an over-capacity result");
    }
}

/// Drive the byte-output oracle directly against a caller-owned buffer and
/// length cell, returning the provider RV, the final cell value, and the
/// sideband observation.
fn drive_oracle_direct(
    buffer: &mut [u8],
    length_action: u32,
    returned_length: u64,
    output_action: u32,
) -> (cryptoki_sys::CK_RV, cryptoki_sys::CK_ULONG, ExactOracleObservation) {
    unsafe {
        ExactOracle_SetScenario(&ExactOracleScenario {
            rv: cryptoki_sys::CKR_OK as u64,
            length_action,
            returned_length,
            parameter_action: 0,
            output_action,
            handle_action: 0,
        });
    }
    ExactOracle_ResetObservation();
    let mut cell = buffer.len() as cryptoki_sys::CK_ULONG;
    let rv = unsafe { ExactOracle_ByteOutput(buffer.as_mut_ptr(), &mut cell) };
    let mut observation = ExactOracleObservation::default();
    unsafe {
        ExactOracle_GetObservation(&mut observation);
    }
    (rv, cell, observation)
}

#[test]
fn exact_oracle_hostile_length_clobbers_cell_with_unavailable() {
    // W1-L10-18 negative control: length_action=2 models a hostile provider
    // that clobbers the length cell with CK_UNAVAILABLE_INFORMATION instead
    // of the scenario length. The old oracle honored only action==1.
    let _guard = oracle::ORACLE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut buffer = [0xAAu8; 8];
    let (_, cell, observation) = drive_oracle_direct(&mut buffer, 2, 7, 0);
    assert_eq!(cell, cryptoki_sys::CK_UNAVAILABLE_INFORMATION, "hostile length clobber");
    assert_eq!(observation.length_stores, 1);
    assert_eq!(buffer, [0xAAu8; 8], "length clobber must not touch the buffer");
}

#[test]
fn exact_oracle_zero_length_write_records_without_storing() {
    // W1-L10-18 negative control: output_action=2 models a provider
    // zero-byte write — no bytes stored, buffer provably untouched, and the
    // zero write recorded (distinguished from "no write attempted").
    let _guard = oracle::ORACLE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut buffer = [0xBBu8; 8];
    let (_, cell, observation) = drive_oracle_direct(&mut buffer, 0, 0, 2);
    assert_eq!(cell, 8, "zero-length write leaves the capacity cell alone");
    assert_eq!(observation.zero_writes, 1);
    assert_eq!(observation.output_stores, 0);
    assert_eq!(buffer, [0xBBu8; 8], "zero-length write stores nothing");
}

#[test]
fn exact_oracle_oversized_write_attempt_is_bounded_and_recorded() {
    // W1-L10-18 negative control: output_action=3 models a provider that
    // attempts capacity+8 bytes. The oracle writes only within capacity
    // (an actual overrun would be UB) and records the attempt, so consumers
    // can prove the backend never exposes the excess.
    let _guard = oracle::ORACLE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut backing = [0xCCu8; 16];
    let (_, cell, observation) = drive_oracle_direct(&mut backing[..8], 0, 0, 3);
    assert_eq!(cell, 8);
    assert_eq!(observation.overrun_attempts, 1);
    assert_eq!(observation.output_stores, 1);
    assert_eq!(&backing[..8], &[0x5Au8; 8], "bounded write fills capacity");
    assert_eq!(&backing[8..], &[0xCCu8; 8], "bytes past capacity must be untouched");
}

#[test]
fn exact_oracle_hostile_fill_covers_capacity() {
    // W1-L10-18 negative control: output_action=4 models a hostile provider
    // filling the whole capacity with garbage (not the 4-byte canary).
    let _guard = oracle::ORACLE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut buffer = [0x00u8; 8];
    let (_, cell, observation) = drive_oracle_direct(&mut buffer, 0, 0, 4);
    assert_eq!(cell, 8);
    assert_eq!(observation.output_stores, 1);
    assert_eq!(buffer, [0xA5u8; 8], "hostile fill covers the full capacity");
}

#[test]
fn exact_oversized_hostile_bytes_forwarded_exactly() {
    // W1-L10-18 consumer: the bounded hostile bytes cross the exact-output
    // boundary byte-identically (no reconstruction, no truncation).
    let _guard = oracle::ORACLE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let spec =
        CkOutputBufferSpec { buffer_present: true, buffer_len: 8, length_pointer_null: false };
    let (result, observation) = invoke_actions(&spec, CkRv::OK, 1, 8, 3);
    assert_eq!(observation.overrun_attempts, 1);
    let result = result.expect("completed native envelope");
    assert_eq!(result.ck_rv, CkRv::OK);
    assert_eq!(result.returned_len, Some(8));
    let value = result.value.expect("bounded hostile bytes have a value");
    assert_eq!(value.len(), 8);
    value.expose(|bytes| assert_eq!(bytes, [0x5Au8; 8]));
}

#[test]
fn exact_unrepresentable_or_over_limit_capacity_rejects_before_native_call() {
    let _guard = oracle::ORACLE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let spec = CkOutputBufferSpec {
        buffer_present: true,
        buffer_len: u64::MAX,
        length_pointer_null: false,
    };
    let (result, observation) = invoke(&spec, CkRv::DEVICE_ERROR, None);
    assert_eq!(
        observation.calls, 0,
        "a resource cap must reject rather than alter the native call"
    );
    // F4/D7 (ADR-0010 Limits-(d)): an unforwardable capacity claim is a bad
    // argument, not a failed allocation.
    assert_eq!(result, Err(CkRv::ARGUMENTS_BAD));
}

#[test]
fn authenticated_null_backing_accepts_aligned_and_partial_fixed_prefixes_without_weakening_rebind_checks()
 {
    use pkcs11_proxy_ng_proto::convert::message_params::{
        CcmMessageParams, GcmMessageParams, MessageParameter,
    };
    for fixed in [0, 1, 8, 9, 96] {
        for parameter in [
            MessageParameter::GcmMessage(GcmMessageParams {
                iv: vec![],
                iv_null_len: Some(12),
                iv_fixed_bits: fixed,
                iv_generator: cryptoki_sys::CKG_GENERATE_RANDOM as u64,
                tag: vec![0; 16],
                tag_null_len: None,
                tag_bits: 128,
            }),
            MessageParameter::CcmMessage(CcmMessageParams {
                data_len: 4,
                nonce: vec![],
                nonce_null_len: Some(12),
                nonce_fixed_bits: fixed,
                nonce_generator: cryptoki_sys::CKG_GENERATE_RANDOM as u64,
                mac: vec![0; 16],
                mac_null_len: None,
                mac_len: 16,
            }),
        ] {
            let native = super::message_ops::build_message_init_mechanism(
                u64::from(cryptoki_sys::CKM_AES_GCM),
                &parameter,
            )
            .unwrap();
            assert_eq!(
                native.validate_authenticated_inputs(&parameter),
                Ok(()),
                "unchanged NULL backing with {fixed} fixed bits"
            );
            // An altered outer pointer remains a rejection even for absent embedded backing.
            let mut rebound = native;
            rebound.ck_mechanism.pParameter = std::ptr::null_mut();
            assert_eq!(rebound.validate_authenticated_inputs(&parameter), Err(CkRv::DEVICE_ERROR));
        }
    }
}

#[test]
fn exact_attribute_nested_over_capacity_length_never_reads_beyond_backing() {
    let sub = CkAttributeQuery {
        attr_type: CkAttributeType::LABEL,
        buffer_present: false,
        buffer_len: 0,
        nested: None,
    };
    let size = std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>() as u64;
    let queries = [CkAttributeQuery {
        attr_type: CkAttributeType::WRAP_TEMPLATE,
        buffer_present: true,
        buffer_len: size,
        nested: Some(vec![sub]),
    }];
    let mut backing = FfiAttributeQueries::from_queries(&queries).unwrap();
    // Two initialized test-owned cells keep the pre-fix read itself valid. The
    // returned count and pointer still exceed the original provider allocation.
    let mut substitute = [cryptoki_sys::CK_ATTRIBUTE::default(); 2];
    backing.attrs[0].pValue = substitute.as_mut_ptr().cast();
    backing.attrs[0].ulValueLen = (2 * size) as cryptoki_sys::CK_ULONG;
    let result = backing.readback(&queries, CkRv::OK);
    assert_eq!(result[0].returned_len, 2 * size);
    assert_eq!(
        result[0].nested, None,
        "do not follow substituted pointer or returned oversized count"
    );
}

#[test]
fn exact_attribute_error_preserves_lengths_without_fabricated_values() {
    let queries = [CkAttributeQuery {
        attr_type: CkAttributeType::LABEL,
        buffer_present: true,
        buffer_len: 4,
        nested: None,
    }];
    let backing = FfiAttributeQueries::from_queries(&queries).unwrap();
    let result = backing.readback(&queries, CkRv::DEVICE_ERROR);
    assert_eq!(result[0].returned_len, 4);
    assert_eq!(result[0].value, None, "untouched daemon zeros are not native error output");
}

#[test]
fn exact_nested_attribute_capacity_must_match_owned_query_count() {
    let query = CkAttributeQuery {
        attr_type: CkAttributeType::WRAP_TEMPLATE,
        buffer_present: true,
        buffer_len: 2 * std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>() as u64,
        nested: Some(vec![CkAttributeQuery {
            attr_type: CkAttributeType(0),
            buffer_present: false,
            buffer_len: 0,
            nested: None,
        }]),
    };
    assert!(
        matches!(FfiAttributeQueries::from_queries(&[query]), Err(CkRv::ARGUMENTS_BAD)),
        "reject inconsistent capacity instead of changing the native call"
    );
}

unsafe extern "C" fn kem_error(
    _: cryptoki_sys::CK_SESSION_HANDLE,
    _: cryptoki_sys::CK_MECHANISM_PTR,
    _: cryptoki_sys::CK_OBJECT_HANDLE,
    _: cryptoki_sys::CK_ATTRIBUTE_PTR,
    _: cryptoki_sys::CK_ULONG,
    output: cryptoki_sys::CK_BYTE_PTR,
    length: cryptoki_sys::CK_ULONG_PTR,
    key: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    if !key.is_null() {
        unsafe { key.write(91) };
    }
    unsafe { ExactOracle_ByteOutput(output, length) }
}

#[test]
fn exact_kem_error_keeps_length_and_never_publishes_output_only_handle() {
    let _guard = oracle::ORACLE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
    let mut table = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_2::default());
    table.C_EncapsulateKey = Some(kem_error);
    let backend = FfiBackend::test_backend_with_tables(base.as_mut(), None, Some(table.as_ref()));
    // Exact paths are ordinary: establish post-Initialize state.
    backend.lifecycle_domain.open_for_tests();
    for (present, missing) in [(true, false), (false, false), (true, true), (false, true)] {
        unsafe {
            ExactOracle_SetScenario(&ExactOracleScenario {
                rv: CkRv::DEVICE_ERROR.0,
                length_action: 1,
                returned_length: 7,
                ..Default::default()
            });
        }
        ExactOracle_ResetObservation();
        let result = backend.ffi_encapsulate_key_exact(
            CkSessionHandle(1),
            &CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None },
            CkObjectHandle(2),
            Some(&[]),
            &CkOutputBufferSpec {
                buffer_present: present,
                buffer_len: 8,
                length_pointer_null: missing,
            },
        );
        let mut observation = ExactOracleObservation::default();
        unsafe {
            ExactOracle_GetObservation(&mut observation);
        }
        assert_eq!(observation.calls, 1);
        let result = result.expect("completed KEM error retains exact envelope");
        assert_eq!(result.returned_len, (!missing).then_some(7));
        assert_eq!(result.object_handle, None, "error handle is output-only and undefined");
        assert_eq!(result.value, None);
    }
}

unsafe extern "C" fn message_error(
    _: cryptoki_sys::CK_SESSION_HANDLE,
    parameter: cryptoki_sys::CK_VOID_PTR,
    _: cryptoki_sys::CK_ULONG,
    _: cryptoki_sys::CK_BYTE_PTR,
    _: cryptoki_sys::CK_ULONG,
    _: cryptoki_sys::CK_BYTE_PTR,
    _: cryptoki_sys::CK_ULONG,
    output: cryptoki_sys::CK_BYTE_PTR,
    length: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    let parameter = unsafe { &*parameter.cast::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>() };
    if !parameter.pIv.is_null() && parameter.ulIvLen != 0 {
        unsafe { parameter.pIv.write(0x42) };
    }
    unsafe { ExactOracle_ByteOutput(output, length) }
}

#[test]
fn exact_parameter_error_preserves_only_defined_initialized_effects() {
    use pkcs11_proxy_ng_proto::convert::message_params::{GcmMessageParams, MessageParameter};
    let _guard = oracle::ORACLE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
    let mut table = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_0::default());
    table.C_EncryptMessage = Some(message_error);
    let backend = FfiBackend::test_backend_with_tables(base.as_mut(), Some(table.as_ref()), None);
    // Exact paths are ordinary: establish post-Initialize state.
    backend.lifecycle_domain.open_for_tests();
    let parameter = MessageParameter::GcmMessage(GcmMessageParams {
        iv: vec![0x11; 12],
        iv_null_len: None,
        iv_fixed_bits: 0,
        iv_generator: cryptoki_sys::CKG_GENERATE_COUNTER_XOR as u64,
        tag: vec![0; 16],
        tag_null_len: None,
        tag_bits: 128,
    });
    unsafe {
        ExactOracle_SetScenario(&ExactOracleScenario {
            rv: CkRv::DEVICE_ERROR.0,
            length_action: 1,
            returned_length: 7,
            ..Default::default()
        });
    }
    ExactOracle_ResetObservation();
    let (output, _, parameter) = backend
        .encrypt_message_exact_msg(
            CkSessionHandle(1),
            &parameter,
            CkInBuf::Bytes(&[]),
            CkInBuf::Bytes(&[]),
            &CkOutputBufferSpec { buffer_present: true, buffer_len: 8, length_pointer_null: false },
            &CkParameterRoundtripSpec {
                buffer_present: true,
                buffer_len: std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>() as u64,
                value: None,
            },
        )
        .expect("completed native message error retains initialized effects");
    assert_eq!(output.ck_rv, CkRv::DEVICE_ERROR);
    assert_eq!(output.returned_len, Some(7));
    let pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects::Gcm { iv: Some(iv), tag } =
        parameter
    else {
        panic!("GCM IV-only effects")
    };
    assert_eq!(iv[0], 0x42);
    assert_eq!(tag, None);
    let mut observation = ExactOracleObservation::default();
    unsafe {
        ExactOracle_GetObservation(&mut observation);
    }
    assert_eq!(observation.calls, 1);
}

unsafe extern "C" fn begin_error(
    _: cryptoki_sys::CK_SESSION_HANDLE,
    parameter: cryptoki_sys::CK_VOID_PTR,
    parameter_len: cryptoki_sys::CK_ULONG,
    _: cryptoki_sys::CK_BYTE_PTR,
    _: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    if !parameter.is_null()
        && parameter_len as usize == std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>()
    {
        let parameter = unsafe { &*parameter.cast::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>() };
        unsafe { parameter.pIv.write(0x42) };
    }
    unsafe { ExactOracle_ByteOutput(std::ptr::null_mut(), std::ptr::null_mut()) }
}

#[test]
fn exact_begin_error_preserves_native_completion_and_initialized_iv() {
    use pkcs11_proxy_ng_proto::convert::message_params::{GcmMessageParams, MessageParameter};
    let _guard = oracle::ORACLE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
    let mut table = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_0::default());
    table.C_EncryptMessageBegin = Some(begin_error);
    let backend = FfiBackend::test_backend_with_tables(base.as_mut(), Some(table.as_ref()), None);
    // Exact paths are ordinary: establish post-Initialize state.
    backend.lifecycle_domain.open_for_tests();
    let parameter = MessageParameter::GcmMessage(GcmMessageParams {
        iv: vec![0x11; 12],
        iv_null_len: None,
        iv_fixed_bits: 0,
        iv_generator: cryptoki_sys::CKG_GENERATE_COUNTER_XOR as u64,
        tag: vec![0; 16],
        tag_null_len: None,
        tag_bits: 128,
    });
    unsafe {
        ExactOracle_SetScenario(&ExactOracleScenario {
            rv: CkRv::FUNCTION_FAILED.0,
            ..Default::default()
        });
    }
    ExactOracle_ResetObservation();
    let completion = backend.encrypt_message_begin_msg(
        CkSessionHandle(1),
        &parameter,
        CkInBuf::Bytes(&[]),
        &CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: std::mem::size_of::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>() as u64,
            value: None,
        },
    );
    let mut observation = ExactOracleObservation::default();
    unsafe {
        ExactOracle_GetObservation(&mut observation);
    }
    assert_eq!(observation.calls, 1);
    let (ack, _) =
        completion.expect("native Begin errors are completions, not pre-native rejection");
    assert_eq!(ack.ck_rv, CkRv::FUNCTION_FAILED);
    for (buffer_present, buffer_len) in [(false, 0), (false, 7), (true, 0)] {
        ExactOracle_ResetObservation();
        let completion = backend.encrypt_message_begin_exact(
            CkSessionHandle(1),
            CkInBuf::Bytes(&[]),
            &CkParameterRoundtripSpec { buffer_present, buffer_len, value: None },
        );
        let mut observation = ExactOracleObservation::default();
        unsafe {
            ExactOracle_GetObservation(&mut observation);
        }
        assert_eq!(observation.calls, 1);
        assert_eq!(
            completion.expect("empty Begin native error is also a completion").ck_rv,
            CkRv::FUNCTION_FAILED
        );
    }
}

#[test]
fn classic_gcm_initialized_error_iv_effect() {
    let mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv: vec![0x11; 12],
            iv_bits: 96,
            iv_buffer_len: 12,
            aad: vec![].into(),
            tag_bits: 128,

            iv_null: false,
            aad_null: false,
        })),
    };
    // Direct-choke unit test: admit on a throwaway test domain.
    let choke_domain = crate::ffi::native_domain::LifecycleDomain::new();
    choke_domain.open_for_tests();
    let choke_admission = choke_domain.admit_ordinary().expect("test domain admits");
    let (output, effects) = FfiBackend::call_bytes_exact_with_mechanism_output(
        &choke_admission,
        Some(()),
        &mechanism,
        &CkOutputBufferSpec { buffer_present: true, buffer_len: 4, length_pointer_null: false },
        |(), native, _, length| {
            // Benign native-provider effect: write within an initialized owned IV.
            let gcm = unsafe { &*native.pParameter.cast::<cryptoki_sys::CK_GCM_PARAMS>() };
            unsafe {
                gcm.pIv.write(0x42);
                length.write(7);
            }
            cryptoki_sys::CKR_FUNCTION_FAILED
        },
    )
    .unwrap();
    assert_eq!(output.ck_rv, CkRv::FUNCTION_FAILED);
    assert_eq!(output.returned_len, Some(7));
    let Some(CkMechanismParams::Gcm(gcm)) = effects else {
        panic!("initialized classic GCM IV error effect must survive");
    };
    assert_eq!(gcm.iv[0], 0x42);
}

#[test]
fn classic_gcm_error_effect_matrix_data_query_and_missing_length() {
    let input = GcmParams {
        iv: vec![0x11; 12],
        iv_bits: 96,
        iv_buffer_len: 12,
        aad: vec![].into(),
        tag_bits: 128,

        iv_null: false,
        aad_null: false,
    };
    let mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(input.clone())),
    };
    let modes = [
        (
            "data",
            CkOutputBufferSpec { buffer_present: true, buffer_len: 4, length_pointer_null: false },
        ),
        (
            "size query",
            CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: false },
        ),
        (
            "missing-length with buffer",
            CkOutputBufferSpec { buffer_present: true, buffer_len: 4, length_pointer_null: true },
        ),
        (
            "missing-length without buffer",
            CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: true },
        ),
    ];
    let rvs = [
        (CkRv::OK, cryptoki_sys::CKR_OK),
        (CkRv::BUFFER_TOO_SMALL, cryptoki_sys::CKR_BUFFER_TOO_SMALL),
        (CkRv::FUNCTION_FAILED, cryptoki_sys::CKR_FUNCTION_FAILED),
        (CkRv::DEVICE_ERROR, cryptoki_sys::CKR_DEVICE_ERROR),
        (CkRv::ARGUMENTS_BAD, cryptoki_sys::CKR_ARGUMENTS_BAD),
        (CkRv(0x8000_0017), 0x8000_0017),
    ];
    for (mode_name, spec) in &modes {
        for (rv, native_rv) in &rvs {
            for write in [true, false] {
                let cell = format!("{mode_name} {rv:?} write={write}");
                // Direct-choke unit test: admit on a throwaway test domain.
                let choke_domain = crate::ffi::native_domain::LifecycleDomain::new();
                choke_domain.open_for_tests();
                let choke_admission = choke_domain.admit_ordinary().expect("test domain admits");
                let (output, effects) = FfiBackend::call_bytes_exact_with_mechanism_output(
                    &choke_admission,
                    Some(()),
                    &mechanism,
                    spec,
                    |(), native, _, length| {
                        if write {
                            // Benign native-provider effect: write within an
                            // initialized owned IV, plus the length cell when one exists.
                            let gcm = unsafe {
                                &*native.pParameter.cast::<cryptoki_sys::CK_GCM_PARAMS>()
                            };
                            unsafe { gcm.pIv.write(0x42) };
                            if !length.is_null() {
                                unsafe { length.write(7) };
                            }
                        }
                        *native_rv
                    },
                )
                .unwrap();
                assert_eq!(output.ck_rv, *rv, "{cell}: rv");
                let (expected_len, expected_value) = if spec.length_pointer_null {
                    (None, None)
                } else if spec.buffer_present {
                    if write {
                        (Some(7), None)
                    } else if *rv == CkRv::OK {
                        (Some(4), Some(vec![0u8; 4]))
                    } else {
                        (Some(4), None)
                    }
                } else if write {
                    (Some(7), None)
                } else if *rv == CkRv::OK {
                    (Some(0), None)
                } else {
                    (None, None)
                };
                assert_eq!(output.returned_len, expected_len, "{cell}: returned_len");
                assert_eq!(output.value, expected_value.map(SecretBytes::new), "{cell}: value");
                let gated = spec.buffer_present || spec.length_pointer_null;
                if !gated {
                    assert_eq!(effects, None, "{cell}: size query suppresses effects");
                } else if write {
                    let Some(CkMechanismParams::Gcm(gcm)) = &effects else {
                        panic!("{cell}: expected mutated GCM effects, got {effects:?}");
                    };
                    assert_eq!(gcm.iv[0], 0x42, "{cell}: mutated IV byte");
                    assert_eq!(gcm.iv.len(), 12, "{cell}: IV length preserved");
                } else if *rv == CkRv::OK {
                    assert_eq!(
                        effects,
                        Some(CkMechanismParams::Gcm(input.clone())),
                        "{cell}: OK echoes unchanged input params"
                    );
                } else {
                    assert_eq!(effects, None, "{cell}: unchanged error surfaces no effects");
                }
            }
        }
    }
}

#[test]
fn classic_gcm_ok_effect_unchanged_data_and_missing_length() {
    let input = GcmParams {
        iv: vec![0x11; 12],
        iv_bits: 96,
        iv_buffer_len: 12,
        aad: vec![].into(),
        tag_bits: 128,

        iv_null: false,
        aad_null: false,
    };
    let mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(input.clone())),
    };
    let modes = [
        (
            "data",
            CkOutputBufferSpec { buffer_present: true, buffer_len: 4, length_pointer_null: false },
            true,
        ),
        (
            "missing-length with buffer",
            CkOutputBufferSpec { buffer_present: true, buffer_len: 4, length_pointer_null: true },
            true,
        ),
        (
            "missing-length without buffer",
            CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: true },
            true,
        ),
        (
            "size query",
            CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: false },
            false,
        ),
    ];
    for (mode_name, spec, expect_echo) in &modes {
        // Direct-choke unit test: admit on a throwaway test domain.
        let choke_domain = crate::ffi::native_domain::LifecycleDomain::new();
        choke_domain.open_for_tests();
        let choke_admission = choke_domain.admit_ordinary().expect("test domain admits");
        let (output, effects) = FfiBackend::call_bytes_exact_with_mechanism_output(
            &choke_admission,
            Some(()),
            &mechanism,
            spec,
            |(), _, _, length| {
                if !length.is_null() {
                    unsafe { length.write(3) };
                }
                cryptoki_sys::CKR_OK
            },
        )
        .unwrap();
        assert_eq!(output.ck_rv, CkRv::OK, "{mode_name}");
        if *expect_echo {
            assert_eq!(
                effects,
                Some(CkMechanismParams::Gcm(input.clone())),
                "{mode_name}: OK echoes unchanged input params"
            );
        } else {
            assert_eq!(effects, None, "{mode_name}: OK size query suppresses effects");
        }
    }
}

#[test]
fn mechanism_output_path_snapshots_once_when_provider_writes_nothing() {
    // W1-C4-04: the exact-with-mechanism-output path must snapshot
    // IV+AAD once per call, not twice (before+after), when the provider
    // leaves the params untouched. Counted on a thread-local so
    // parallel tests cannot perturb the delta.
    use super::ffi_conversion::FfiMechanism;
    let input = GcmParams {
        iv: vec![0x11; 12],
        iv_bits: 96,
        iv_buffer_len: 12,
        aad: vec![].into(),
        tag_bits: 128,
        iv_null: false,
        aad_null: false,
    };
    let mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(input.clone())),
    };
    let choke_domain = crate::ffi::native_domain::LifecycleDomain::new();
    choke_domain.open_for_tests();
    let choke_admission = choke_domain.admit_ordinary().expect("test domain admits");
    FfiMechanism::reset_output_params_calls_for_tests();
    let (output, effects) = FfiBackend::call_bytes_exact_with_mechanism_output(
        &choke_admission,
        Some(()),
        &mechanism,
        &CkOutputBufferSpec { buffer_present: true, buffer_len: 4, length_pointer_null: false },
        |(), _, _, length| {
            if !length.is_null() {
                unsafe { length.write(3) };
            }
            cryptoki_sys::CKR_OK
        },
    )
    .unwrap();
    assert_eq!(output.ck_rv, CkRv::OK);
    assert_eq!(effects, Some(CkMechanismParams::Gcm(input)));
    assert_eq!(
        FfiMechanism::output_params_calls_for_tests(),
        1,
        "unchanged OK call must take exactly one snapshot"
    );
}

#[test]
fn mechanism_output_path_resnapshots_only_when_provider_writes() {
    // W1-C4-04: when the provider DOES mutate the params, the path
    // takes a second snapshot and returns the post-call values.
    use super::ffi_conversion::FfiMechanism;
    let mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv: vec![0x11; 12],
            iv_bits: 96,
            iv_buffer_len: 12,
            aad: vec![].into(),
            tag_bits: 128,
            iv_null: false,
            aad_null: false,
        })),
    };
    let choke_domain = crate::ffi::native_domain::LifecycleDomain::new();
    choke_domain.open_for_tests();
    let choke_admission = choke_domain.admit_ordinary().expect("test domain admits");
    FfiMechanism::reset_output_params_calls_for_tests();
    let (output, effects) = FfiBackend::call_bytes_exact_with_mechanism_output(
        &choke_admission,
        Some(()),
        &mechanism,
        &CkOutputBufferSpec { buffer_present: true, buffer_len: 4, length_pointer_null: false },
        |(), native, _, length| {
            let gcm = unsafe { &*native.pParameter.cast::<cryptoki_sys::CK_GCM_PARAMS>() };
            unsafe {
                gcm.pIv.write(0x42);
                length.write(7);
            }
            cryptoki_sys::CKR_FUNCTION_FAILED
        },
    )
    .unwrap();
    assert_eq!(output.ck_rv, CkRv::FUNCTION_FAILED);
    let Some(CkMechanismParams::Gcm(gcm)) = effects else {
        panic!("provider-written IV must surface on the error path");
    };
    assert_eq!(gcm.iv[0], 0x42);
    assert_eq!(
        FfiMechanism::output_params_calls_for_tests(),
        2,
        "changed error call takes before + after snapshots"
    );
}
