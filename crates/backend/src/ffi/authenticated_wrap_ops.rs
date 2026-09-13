use super::FfiBackend;
use pkcs11_proxy_ng_proto::convert::authenticated::{
    AuthenticatedOutput, legacy_parameter_supported,
};
use pkcs11_proxy_ng_types::*;

/// Legacy wire clients can receive only proven portable byte-array outputs.
fn require_legacy_parameter(mechanism: &CkMechanism) -> CkResult<()> {
    if legacy_parameter_supported(mechanism) { Ok(()) } else { Err(CkRv::FUNCTION_NOT_SUPPORTED) }
}

fn legacy_bytes(output: AuthenticatedOutput) -> CkResult<Vec<u8>> {
    match output {
        AuthenticatedOutput::Iv(iv) => Ok(iv),
        AuthenticatedOutput::Unchanged => Ok(Vec::new()),
        AuthenticatedOutput::Message(_)
        | AuthenticatedOutput::Effects(_)
        | AuthenticatedOutput::Invalid(_) => Err(CkRv::FUNCTION_NOT_SUPPORTED),
    }
}

impl FfiBackend {
    /// Legacy two-call convenience adapter, restricted before native entry.
    pub(super) fn ffi_wrap_key_authenticated(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        require_legacy_parameter(mechanism)?;
        let (bytes, output) =
            self.ffi_wrap_authenticated_typed(session, mechanism, None, wrapping_key, key, aad)?;
        Ok((bytes, legacy_bytes(output)?))
    }

    pub(super) fn ffi_unwrap_key_authenticated(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        unwrapping_key: CkObjectHandle,
        wrapped_key: CkInBuf<'_>,
        template: &[CkAttribute],
        aad: CkInBuf<'_>,
    ) -> CkResult<(CkObjectHandle, Vec<u8>)> {
        require_legacy_parameter(mechanism)?;
        let (key, output) = self.ffi_unwrap_authenticated_typed(
            session,
            mechanism,
            None,
            unwrapping_key,
            wrapped_key,
            template,
            aad,
        )?;
        Ok((key, legacy_bytes(output)?))
    }

    /// Preserve the legacy parameter-envelope semantics using typed owned IV
    /// output. Never read native structure memory, including for legacy peers.
    pub(super) fn ffi_wrap_key_authenticated_exact(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: CkInBuf<'_>,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        require_legacy_parameter(mechanism)?;
        let (main, output) = self.ffi_wrap_authenticated_exact_typed(
            session,
            mechanism,
            None,
            wrapping_key,
            key,
            aad,
            output_spec,
        )?;
        let bytes = match legacy_bytes(output) {
            Ok(bytes) => bytes,
            Err(_) => {
                tracing::warn!(
                    provider_rv = main.ck_rv.0,
                    "native exact parameter contract violation"
                );
                return Ok((
                    CkOutputBufferResult::no_effects(CkRv::DEVICE_ERROR),
                    CkParameterRoundtripResult {
                        ck_rv: CkRv::DEVICE_ERROR,
                        returned_len: 0,
                        value: None,
                    },
                ));
            }
        };
        let returned_len = bytes.len() as u64;
        let value =
            if param_out_spec.buffer_present && !bytes.is_empty() { Some(bytes) } else { None };
        let parameter = CkParameterRoundtripResult { ck_rv: main.ck_rv, returned_len, value };
        Ok((main, parameter))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::Pkcs11Backend;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static OUTPUT_PRESENT: AtomicUsize = AtomicUsize::new(0);
    static LENGTH_NULL: AtomicUsize = AtomicUsize::new(0);
    static RETURN_RV: AtomicUsize = AtomicUsize::new(cryptoki_sys::CKR_OK as usize);
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // Break caught: any authenticated adapter copying a native GOST structure
    // into bytes discloses pointer/handle fields, including native padding.
    // Assertions deliberately never format the returned byte buffer.
    unsafe extern "C" fn pointer_bearing_wrap(
        _: cryptoki_sys::CK_SESSION_HANDLE,
        _: cryptoki_sys::CK_MECHANISM_PTR,
        _: cryptoki_sys::CK_OBJECT_HANDLE,
        _: cryptoki_sys::CK_OBJECT_HANDLE,
        _: cryptoki_sys::CK_BYTE_PTR,
        _: cryptoki_sys::CK_ULONG,
        output: cryptoki_sys::CK_BYTE_PTR,
        length: cryptoki_sys::CK_ULONG_PTR,
    ) -> cryptoki_sys::CK_RV {
        CALLS.fetch_add(1, Ordering::SeqCst);
        if !length.is_null() {
            unsafe { *length = 1 };
            if !output.is_null() {
                unsafe { *output = 0 };
            }
        }
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn pointer_bearing_unwrap(
        _: cryptoki_sys::CK_SESSION_HANDLE,
        _: cryptoki_sys::CK_MECHANISM_PTR,
        _: cryptoki_sys::CK_OBJECT_HANDLE,
        _: cryptoki_sys::CK_BYTE_PTR,
        _: cryptoki_sys::CK_ULONG,
        _: cryptoki_sys::CK_ATTRIBUTE_PTR,
        _: cryptoki_sys::CK_ULONG,
        _: cryptoki_sys::CK_BYTE_PTR,
        _: cryptoki_sys::CK_ULONG,
        key: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
    ) -> cryptoki_sys::CK_RV {
        CALLS.fetch_add(1, Ordering::SeqCst);
        unsafe { *key = 1 };
        cryptoki_sys::CKR_OK
    }

    fn assert_legacy_rejects_native_structure(route: u32) {
        let _guard = TEST_LOCK.lock().unwrap();
        let (backend, _base, mut functions) = backend_with_missing_length_wrap();
        functions.C_WrapKeyAuthenticated = Some(pointer_bearing_wrap);
        functions.C_UnwrapKeyAuthenticated = Some(pointer_bearing_unwrap);
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType::GOSTR3410_KEY_WRAP,
            params: Some(CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
                wrap_oid: vec![1; 3],
                ukm: vec![2; 8],
                key_handle: 7,
            })),
        };
        {
            CALLS.store(0, Ordering::SeqCst);
            let result = match route {
                0 => backend
                    .ffi_wrap_key_authenticated(
                        CkSessionHandle(1),
                        &mechanism,
                        CkObjectHandle(2),
                        CkObjectHandle(3),
                        CkInBuf::Bytes(&[]),
                    )
                    .map(|(_, output)| output.is_empty()),
                1 => backend
                    .ffi_wrap_key_authenticated_exact(
                        CkSessionHandle(1),
                        &mechanism,
                        CkObjectHandle(2),
                        CkObjectHandle(3),
                        CkInBuf::Bytes(&[]),
                        &CkOutputBufferSpec {
                            buffer_present: true,
                            buffer_len: 1,
                            length_pointer_null: false,
                        },
                        &CkParameterRoundtripSpec {
                            buffer_present: true,
                            buffer_len: 64,
                            value: None,
                        },
                    )
                    .map(|(_, output)| output.value.is_none_or(|bytes| bytes.is_empty())),
                _ => backend
                    .ffi_unwrap_key_authenticated(
                        CkSessionHandle(1),
                        &mechanism,
                        CkObjectHandle(2),
                        CkInBuf::Bytes(&[0]),
                        &[],
                        CkInBuf::Bytes(&[]),
                    )
                    .map(|(_, output)| output.is_empty()),
            };
            assert!(
                matches!(result, Err(CkRv::FUNCTION_NOT_SUPPORTED)),
                "legacy authenticated route {route} must reject structure output before native entry"
            );
            assert_eq!(CALLS.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn authenticated_legacy_wrap_rejects_native_structure_images() {
        assert_legacy_rejects_native_structure(0);
    }

    #[test]
    fn authenticated_legacy_exact_rejects_native_structure_images() {
        assert_legacy_rejects_native_structure(1);
    }

    #[test]
    fn authenticated_legacy_unwrap_rejects_native_structure_images() {
        assert_legacy_rejects_native_structure(2);
    }

    #[test]
    fn authenticated_typed_gost_all_adapters_emit_only_no_output_acknowledgment() {
        use crate::Pkcs11Backend;
        use pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput;
        let _guard = TEST_LOCK.lock().unwrap();
        let (backend, _base, mut functions) = backend_with_missing_length_wrap();
        functions.C_WrapKeyAuthenticated = Some(pointer_bearing_wrap);
        functions.C_UnwrapKeyAuthenticated = Some(pointer_bearing_unwrap);
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType::GOSTR3410_KEY_WRAP,
            params: Some(CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
                wrap_oid: vec![1; 3],
                ukm: vec![2; 8],
                key_handle: 7,
            })),
        };
        for route in 0..3 {
            CALLS.store(0, Ordering::SeqCst);
            let result = match route {
                0 => backend
                    .wrap_key_authenticated_typed(
                        CkSessionHandle(1),
                        &mechanism,
                        None,
                        CkObjectHandle(2),
                        CkObjectHandle(3),
                        CkInBuf::Bytes(&[]),
                    )
                    .map(|(_, out)| out),
                1 => backend
                    .wrap_key_authenticated_exact_typed(
                        CkSessionHandle(1),
                        &mechanism,
                        None,
                        CkObjectHandle(2),
                        CkObjectHandle(3),
                        CkInBuf::Bytes(&[]),
                        &CkOutputBufferSpec {
                            buffer_present: true,
                            buffer_len: 1,
                            length_pointer_null: false,
                        },
                    )
                    .map(|(_, out)| out),
                _ => backend
                    .unwrap_key_authenticated_typed(
                        CkSessionHandle(1),
                        &mechanism,
                        None,
                        CkObjectHandle(2),
                        CkInBuf::Bytes(&[0]),
                        &[],
                        CkInBuf::Bytes(&[]),
                    )
                    .map(|(_, out)| out),
            };
            assert!(
                matches!(result, Ok(AuthenticatedOutput::Unchanged)),
                "typed GOST route {route} must emit no pointer, handle, padding, or input fields"
            );
            assert_eq!(CALLS.load(Ordering::SeqCst), if route == 0 { 2 } else { 1 });
        }
    }

    static MODE: AtomicUsize = AtomicUsize::new(0);
    static DESTROYS: AtomicUsize = AtomicUsize::new(0);
    static DESTROY_RV: AtomicUsize = AtomicUsize::new(cryptoki_sys::CKR_OK as usize);

    unsafe extern "C" fn mutate_sizing_input(
        _: cryptoki_sys::CK_SESSION_HANDLE,
        mechanism: cryptoki_sys::CK_MECHANISM_PTR,
        _: cryptoki_sys::CK_OBJECT_HANDLE,
        _: cryptoki_sys::CK_OBJECT_HANDLE,
        _: cryptoki_sys::CK_BYTE_PTR,
        _: cryptoki_sys::CK_ULONG,
        output: cryptoki_sys::CK_BYTE_PTR,
        length: cryptoki_sys::CK_ULONG_PTR,
    ) -> cryptoki_sys::CK_RV {
        let call = CALLS.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            match MODE.load(Ordering::SeqCst) {
                0 => unsafe { (*mechanism).mechanism = cryptoki_sys::CKM_AES_CCM },
                1 => unsafe {
                    let parameter = &mut *(*mechanism)
                        .pParameter
                        .cast::<cryptoki_sys::CK_GOSTR3410_KEY_WRAP_PARAMS>();
                    parameter.hKey += 1;
                    parameter.pUKM = std::ptr::null_mut();
                },
                2 | 14 => unsafe { (*mechanism).pParameter = std::ptr::null_mut() },
                3 => unsafe { (*mechanism).pParameter = std::ptr::dangling_mut::<u8>().cast() },
                4 | 5 | 13 => unsafe { (*mechanism).ulParameterLen += 1 },
                6..=11 => unsafe {
                    let p = &mut *(*mechanism)
                        .pParameter
                        .cast::<cryptoki_sys::CK_GOSTR3410_KEY_WRAP_PARAMS>();
                    match MODE.load(Ordering::SeqCst) {
                        6 => p.pWrapOID = std::ptr::null_mut(),
                        7 => p.ulWrapOIDLen += 1,
                        8 => p.ulUKMLen += 1,
                        9 => *p.pWrapOID ^= 1,
                        10 => *p.pUKM ^= 1,
                        _ => p.hKey += 1,
                    }
                },
                12 | 15 => unsafe {
                    let p =
                        &mut *(*mechanism).pParameter.cast::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>();
                    *p.pIv ^= 0x80;
                },
                _ => unreachable!(),
            }
        }
        if !length.is_null() {
            unsafe { *length = 1 };
        }
        if !output.is_null() {
            unsafe { *output = 0 };
        }
        cryptoki_sys::CKR_OK
    }

    fn run_sizing_mutation(mode: usize) {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (backend, _base, mut functions) = backend_with_missing_length_wrap();
        functions.C_WrapKeyAuthenticated = Some(mutate_sizing_input);
        let (mechanism, parameter) = if mode == 0 || mode >= 12 {
            let (mechanism, mut parameter) = aead_parameter(false);
            if let pkcs11_proxy_ng_proto::convert::message_params::MessageParameter::GcmMessage(p) =
                &mut parameter
            {
                if mode == 12 {
                    p.iv_fixed_bits = 1;
                }
                if mode == 15 {
                    p.iv_generator = 0;
                }
            }
            (mechanism, Some(parameter))
        } else if mode == 1 || (6..=11).contains(&mode) {
            (
                CkMechanism {
                    mechanism_type: CkMechanismType::GOSTR3410_KEY_WRAP,
                    params: Some(CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
                        wrap_oid: vec![1; 3],
                        ukm: vec![2; 8],
                        key_handle: 7,
                    })),
                },
                None,
            )
        } else if mode == 3 || mode == 4 {
            (CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None }, None)
        } else {
            (
                CkMechanism {
                    mechanism_type: CkMechanismType::AES_CBC,
                    params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0; 16] })),
                },
                None,
            )
        };
        MODE.store(mode, Ordering::SeqCst);
        CALLS.store(0, Ordering::SeqCst);
        let result = backend.wrap_key_authenticated_typed(
            CkSessionHandle(1),
            &mechanism,
            parameter.as_ref(),
            CkObjectHandle(2),
            CkObjectHandle(3),
            CkInBuf::Bytes(&[]),
        );
        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            1,
            "provider-mutated input must not reach a second native call"
        );
        assert!(matches!(result, Err(CkRv::DEVICE_ERROR)));
    }

    #[test]
    fn reviewer_authenticated_rejects_sizing_mechanism_discriminator_mutation() {
        run_sizing_mutation(0);
    }

    #[test]
    fn reviewer_authenticated_rejects_sizing_gost_input_rebinding() {
        run_sizing_mutation(1);
    }

    #[test]
    fn reviewer_authenticated_rejects_sizing_iv_outer_rebinding() {
        run_sizing_mutation(2);
    }

    #[test]
    fn reviewer_authenticated_rejects_sizing_input_only_contents_and_all_outer_shapes() {
        // Removing any input check must stop before a second native invocation.
        for mode in 3..=15 {
            run_sizing_mutation(mode);
        }
    }

    unsafe extern "C" fn created_key_and_invalid_parameter(
        _: cryptoki_sys::CK_SESSION_HANDLE,
        mechanism: cryptoki_sys::CK_MECHANISM_PTR,
        _: cryptoki_sys::CK_OBJECT_HANDLE,
        _: cryptoki_sys::CK_BYTE_PTR,
        _: cryptoki_sys::CK_ULONG,
        _: cryptoki_sys::CK_ATTRIBUTE_PTR,
        _: cryptoki_sys::CK_ULONG,
        _: cryptoki_sys::CK_BYTE_PTR,
        _: cryptoki_sys::CK_ULONG,
        handle: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
    ) -> cryptoki_sys::CK_RV {
        CALLS.fetch_add(1, Ordering::SeqCst);
        unsafe {
            let parameter =
                &mut *(*mechanism).pParameter.cast::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>();
            if MODE.load(Ordering::SeqCst) != 99 {
                parameter.pTag = std::ptr::null_mut();
            }
            *handle = 4;
        }
        cryptoki_sys::CKR_OK
    }

    unsafe extern "C" fn destroy_created_key(
        _: cryptoki_sys::CK_SESSION_HANDLE,
        _: cryptoki_sys::CK_OBJECT_HANDLE,
    ) -> cryptoki_sys::CK_RV {
        DESTROYS.fetch_add(1, Ordering::SeqCst);
        DESTROY_RV.load(Ordering::SeqCst) as cryptoki_sys::CK_RV
    }

    #[test]
    fn reviewer_authenticated_unwrap_retains_cleanup_ownership_on_invalid_output() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (backend, mut base, mut functions) = backend_with_missing_length_wrap();
        functions.C_UnwrapKeyAuthenticated = Some(created_key_and_invalid_parameter);
        base.C_DestroyObject = Some(destroy_created_key);
        CALLS.store(0, Ordering::SeqCst);
        DESTROYS.store(0, Ordering::SeqCst);
        DESTROY_RV.store(cryptoki_sys::CKR_OK as usize, Ordering::SeqCst);
        MODE.store(0, Ordering::SeqCst);
        let (mechanism, parameter) = aead_parameter(false);
        let result = backend.unwrap_key_authenticated_typed(
            CkSessionHandle(1),
            &mechanism,
            Some(&parameter),
            CkObjectHandle(2),
            CkInBuf::Bytes(&[0; 8]),
            &[],
            CkInBuf::Bytes(&[]),
        );
        assert!(matches!(result, Err(CkRv::DEVICE_ERROR)));
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(
            DESTROYS.load(Ordering::SeqCst),
            1,
            "a successfully created native key must not become unreachable when output validation rejects it"
        );
    }

    static CORRUPT_PARAMETER: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn reviewer_authenticated_unwrap_quarantines_failed_destroy_and_blocks_new_creates() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (backend, mut base, mut functions) = backend_with_missing_length_wrap();
        functions.C_UnwrapKeyAuthenticated = Some(created_key_and_invalid_parameter);
        base.C_DestroyObject = Some(destroy_created_key);
        CALLS.store(0, Ordering::SeqCst);
        DESTROYS.store(0, Ordering::SeqCst);
        DESTROY_RV.store(cryptoki_sys::CKR_FUNCTION_FAILED as usize, Ordering::SeqCst);
        MODE.store(0, Ordering::SeqCst);
        let (mechanism, parameter) = aead_parameter(false);
        for _ in 0..2 {
            let result = backend.unwrap_key_authenticated_typed(
                CkSessionHandle(1),
                &mechanism,
                Some(&parameter),
                CkObjectHandle(2),
                CkInBuf::Bytes(&[0; 8]),
                &[],
                CkInBuf::Bytes(&[]),
            );
            assert!(matches!(result, Err(CkRv::DEVICE_ERROR)));
        }
        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            1,
            "failed cleanup must quarantine future creation"
        );
        assert_eq!(DESTROYS.load(Ordering::SeqCst), 1, "one cleanup attempt, no blind retry");
    }

    #[test]
    fn reviewer_authenticated_unwrap_transfers_valid_created_object_without_destroy() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (backend, mut base, mut functions) = backend_with_missing_length_wrap();
        functions.C_UnwrapKeyAuthenticated = Some(created_key_and_invalid_parameter);
        base.C_DestroyObject = Some(destroy_created_key);
        CALLS.store(0, Ordering::SeqCst);
        DESTROYS.store(0, Ordering::SeqCst);
        MODE.store(99, Ordering::SeqCst);
        let (mechanism, parameter) = aead_parameter(false);
        let result = backend.unwrap_key_authenticated_typed(
            CkSessionHandle(1),
            &mechanism,
            Some(&parameter),
            CkObjectHandle(2),
            CkInBuf::Bytes(&[0; 8]),
            &[],
            CkInBuf::Bytes(&[]),
        );
        assert!(result.is_ok());
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(DESTROYS.load(Ordering::SeqCst), 0);
    }

    unsafe extern "C" fn aead_wrap(
        _: cryptoki_sys::CK_SESSION_HANDLE,
        mechanism: cryptoki_sys::CK_MECHANISM_PTR,
        _: cryptoki_sys::CK_OBJECT_HANDLE,
        _: cryptoki_sys::CK_OBJECT_HANDLE,
        _: cryptoki_sys::CK_BYTE_PTR,
        _: cryptoki_sys::CK_ULONG,
        output: cryptoki_sys::CK_BYTE_PTR,
        length: cryptoki_sys::CK_ULONG_PTR,
    ) -> cryptoki_sys::CK_RV {
        CALLS.fetch_add(1, Ordering::SeqCst);
        OUTPUT_PRESENT.store(usize::from(!output.is_null()), Ordering::SeqCst);
        LENGTH_NULL.store(usize::from(length.is_null()), Ordering::SeqCst);
        let mechanism = unsafe { &mut *mechanism };
        let (iv, iv_len, tag, tag_len) = if mechanism.mechanism == cryptoki_sys::CKM_AES_GCM {
            let p =
                unsafe { &mut *mechanism.pParameter.cast::<cryptoki_sys::CK_GCM_MESSAGE_PARAMS>() };
            let values = (p.pIv, p.ulIvLen, p.pTag, p.ulTagBits / 8);
            match CORRUPT_PARAMETER.load(Ordering::SeqCst) {
                1 => p.pTag = std::ptr::null_mut(),
                2 => p.ulIvLen += 1,
                _ => {}
            }
            values
        } else {
            let p =
                unsafe { &mut *mechanism.pParameter.cast::<cryptoki_sys::CK_CCM_MESSAGE_PARAMS>() };
            (p.pNonce, p.ulNonceLen, p.pMAC, p.ulMACLen)
        };
        if !iv.is_null() {
            unsafe { std::ptr::write_bytes(iv, 0xa5, iv_len as usize) };
        }
        if !tag.is_null() {
            unsafe { std::ptr::write_bytes(tag, 0x5a, tag_len as usize) };
        }
        let configured = RETURN_RV.load(Ordering::SeqCst) as cryptoki_sys::CK_RV;
        if length.is_null() {
            return configured;
        }
        let capacity = unsafe { *length };
        unsafe { *length = 8 };
        if configured != cryptoki_sys::CKR_OK {
            return configured;
        }
        if output.is_null() {
            return cryptoki_sys::CKR_OK;
        }
        if capacity < 8 {
            return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
        }
        unsafe { std::ptr::write_bytes(output, 0, 8) };
        cryptoki_sys::CKR_OK
    }

    fn aead_parameter(
        ccm: bool,
    ) -> (CkMechanism, pkcs11_proxy_ng_proto::convert::message_params::MessageParameter) {
        use pkcs11_proxy_ng_proto::convert::message_params::*;
        let parameter = if ccm {
            MessageParameter::CcmMessage(CcmMessageParams {
                data_len: 8,
                nonce: vec![0; 12],
                nonce_null_len: None,
                nonce_fixed_bits: 0,
                nonce_generator: 1,
                mac: vec![0; 16],
                mac_null_len: None,
                mac_len: 16,
            })
        } else {
            MessageParameter::GcmMessage(GcmMessageParams {
                iv: vec![0; 12],
                iv_null_len: None,
                iv_fixed_bits: 0,
                iv_generator: 1,
                tag: vec![0; 16],
                tag_null_len: None,
                tag_bits: 128,
            })
        };
        (
            CkMechanism {
                mechanism_type: if ccm {
                    CkMechanismType::AES_CCM
                } else {
                    CkMechanismType::AES_GCM
                },
                params: None,
            },
            parameter,
        )
    }

    #[test]
    fn authenticated_typed_aead_exact_roundtrips_only_owned_buffers_once_for_every_output_shape() {
        use crate::Pkcs11Backend;
        use pkcs11_proxy_ng_proto::convert::{
            authenticated::AuthenticatedOutput, message_effects::MessageEffects,
        };
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (backend, _base, mut functions) = backend_with_missing_length_wrap();
        functions.C_WrapKeyAuthenticated = Some(aead_wrap);
        CORRUPT_PARAMETER.store(0, Ordering::SeqCst);
        RETURN_RV.store(cryptoki_sys::CKR_OK as usize, Ordering::SeqCst);
        for ccm in [false, true] {
            let (mechanism, parameter) = aead_parameter(ccm);
            for (present, len, null, expected_rv, expected_len) in [
                (false, 0, false, CkRv::OK, 8),
                (true, 0, false, CkRv::BUFFER_TOO_SMALL, 8),
                (true, 2, false, CkRv::BUFFER_TOO_SMALL, 8),
                (true, 8, false, CkRv::OK, 8),
                (true, 32, false, CkRv::OK, 8),
                (false, 0, true, CkRv::OK, 0),
                (true, 0, true, CkRv::OK, 0),
            ] {
                CALLS.store(0, Ordering::SeqCst);
                let result = backend.wrap_key_authenticated_exact_typed(
                    CkSessionHandle(1),
                    &mechanism,
                    Some(&parameter),
                    CkObjectHandle(2),
                    CkObjectHandle(3),
                    CkInBuf::Bytes(&[]),
                    &CkOutputBufferSpec {
                        buffer_present: present,
                        buffer_len: len,
                        length_pointer_null: null,
                    },
                );
                assert!(
                    result.is_ok(),
                    "typed AEAD exact operation must support its legal native shape"
                );
                let (main, output) = result.unwrap();
                assert_eq!(
                    (main.ck_rv, main.returned_len),
                    (expected_rv, (!null).then_some(expected_len))
                );
                assert_eq!(CALLS.load(Ordering::SeqCst), 1);
                assert_eq!(OUTPUT_PRESENT.load(Ordering::SeqCst), usize::from(present));
                assert_eq!(LENGTH_NULL.load(Ordering::SeqCst), usize::from(null));
                let wire =
                    pkcs11_proxy_ng_proto::AuthenticatedMechanismOutput::try_from(&output).unwrap();
                let decoded = AuthenticatedOutput::try_from(&wire).unwrap();
                // This fixture deliberately writes output-only storage even for
                // query/missing-length calls; those writes are not defined effects.
                let data_completed = present && !null && expected_rv == CkRv::OK;
                match decoded {
                    AuthenticatedOutput::Effects(MessageEffects::Gcm { iv, tag }) => {
                        assert_eq!(iv, data_completed.then(|| vec![0xa5; 12]));
                        assert_eq!(tag, data_completed.then(|| vec![0x5a; 16]));
                    }
                    AuthenticatedOutput::Effects(MessageEffects::Ccm { nonce, mac }) => {
                        assert_eq!(nonce, data_completed.then(|| vec![0xa5; 12]));
                        assert_eq!(mac, data_completed.then(|| vec![0x5a; 16]));
                    }
                    _ => panic!("expected output-only AEAD transport"),
                }
            }
        }
    }

    #[test]
    fn authenticated_typed_aead_rejects_provider_pointer_or_scalar_rebinding_without_reading_it() {
        use crate::Pkcs11Backend;
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (backend, _base, mut functions) = backend_with_missing_length_wrap();
        functions.C_WrapKeyAuthenticated = Some(aead_wrap);
        RETURN_RV.store(cryptoki_sys::CKR_OK as usize, Ordering::SeqCst);
        let (mechanism, parameter) = aead_parameter(false);
        for corruption in [1, 2] {
            CORRUPT_PARAMETER.store(corruption, Ordering::SeqCst);
            CALLS.store(0, Ordering::SeqCst);
            let result = backend.wrap_key_authenticated_exact_typed(
                CkSessionHandle(1),
                &mechanism,
                Some(&parameter),
                CkObjectHandle(2),
                CkObjectHandle(3),
                CkInBuf::Bytes(&[]),
                &CkOutputBufferSpec {
                    buffer_present: false,
                    buffer_len: 0,
                    length_pointer_null: false,
                },
            );
            assert!(
                matches!(result, Ok((ref output, pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput::Invalid(_))) if output.ck_rv == CkRv::OK),
                "post-native contract violation is a completed native envelope, never a pre-native Err"
            );
            assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        }
        CORRUPT_PARAMETER.store(0, Ordering::SeqCst);
    }

    #[test]
    fn authenticated_typed_ordinary_checks_sizing_parameter_before_second_native_call() {
        use crate::Pkcs11Backend;
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (backend, _base, mut functions) = backend_with_missing_length_wrap();
        functions.C_WrapKeyAuthenticated = Some(aead_wrap);
        RETURN_RV.store(cryptoki_sys::CKR_OK as usize, Ordering::SeqCst);
        CORRUPT_PARAMETER.store(1, Ordering::SeqCst);
        CALLS.store(0, Ordering::SeqCst);
        let (mechanism, parameter) = aead_parameter(false);
        let result = backend.wrap_key_authenticated_typed(
            CkSessionHandle(1),
            &mechanism,
            Some(&parameter),
            CkObjectHandle(2),
            CkObjectHandle(3),
            CkInBuf::Bytes(&[]),
        );
        CORRUPT_PARAMETER.store(0, Ordering::SeqCst);
        assert!(matches!(result, Err(CkRv::DEVICE_ERROR)));
        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            1,
            "sizing must not pass a rebound parameter to another native call"
        );
    }

    unsafe extern "C" fn aead_unwrap(
        session: cryptoki_sys::CK_SESSION_HANDLE,
        mechanism: cryptoki_sys::CK_MECHANISM_PTR,
        key: cryptoki_sys::CK_OBJECT_HANDLE,
        _: cryptoki_sys::CK_BYTE_PTR,
        _: cryptoki_sys::CK_ULONG,
        _: cryptoki_sys::CK_ATTRIBUTE_PTR,
        _: cryptoki_sys::CK_ULONG,
        aad: cryptoki_sys::CK_BYTE_PTR,
        aad_len: cryptoki_sys::CK_ULONG,
        handle: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
    ) -> cryptoki_sys::CK_RV {
        let rv = unsafe {
            aead_wrap(
                session,
                mechanism,
                key,
                0,
                aad,
                aad_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rv == cryptoki_sys::CKR_OK {
            unsafe { *handle = 1 };
        }
        rv
    }

    #[test]
    fn authenticated_typed_unwrap_never_returns_mutated_aead_input_fields() {
        use crate::Pkcs11Backend;
        use pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput;
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (backend, _base, mut functions) = backend_with_missing_length_wrap();
        functions.C_UnwrapKeyAuthenticated = Some(aead_unwrap);
        RETURN_RV.store(cryptoki_sys::CKR_OK as usize, Ordering::SeqCst);
        CORRUPT_PARAMETER.store(0, Ordering::SeqCst);
        for ccm in [false, true] {
            let (mechanism, parameter) = aead_parameter(ccm);
            CALLS.store(0, Ordering::SeqCst);
            let result = backend.unwrap_key_authenticated_typed(
                CkSessionHandle(1),
                &mechanism,
                Some(&parameter),
                CkObjectHandle(2),
                CkInBuf::Bytes(&[0; 8]),
                &[],
                CkInBuf::Bytes(&[]),
            );
            assert!(
                matches!(result, Ok((_, ref output)) if output == &AuthenticatedOutput::Message(parameter)),
                "AEAD unwrap parameter buffers are input-only"
            );
            assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        }
    }

    unsafe extern "C" fn missing_length_wrap(
        _session: cryptoki_sys::CK_SESSION_HANDLE,
        mechanism: cryptoki_sys::CK_MECHANISM_PTR,
        _wrapping_key: cryptoki_sys::CK_OBJECT_HANDLE,
        _key: cryptoki_sys::CK_OBJECT_HANDLE,
        _aad: cryptoki_sys::CK_BYTE_PTR,
        _aad_len: cryptoki_sys::CK_ULONG,
        output: cryptoki_sys::CK_BYTE_PTR,
        output_len: cryptoki_sys::CK_ULONG_PTR,
    ) -> cryptoki_sys::CK_RV {
        CALLS.fetch_add(1, Ordering::SeqCst);
        OUTPUT_PRESENT.store(usize::from(!output.is_null()), Ordering::SeqCst);
        LENGTH_NULL.store(usize::from(output_len.is_null()), Ordering::SeqCst);
        if !mechanism.is_null() {
            let mechanism = unsafe { &mut *mechanism };
            if !mechanism.pParameter.is_null() && mechanism.ulParameterLen > 0 {
                unsafe { *mechanism.pParameter.cast::<u8>() = 0xA5 };
            }
        }
        RETURN_RV.load(Ordering::SeqCst) as cryptoki_sys::CK_RV
    }

    fn backend_with_missing_length_wrap()
    -> (FfiBackend, Box<cryptoki_sys::CK_FUNCTION_LIST>, Box<cryptoki_sys::CK_FUNCTION_LIST_3_2>)
    {
        let mut base = Box::new(cryptoki_sys::CK_FUNCTION_LIST::default());
        let mut functions = Box::new(cryptoki_sys::CK_FUNCTION_LIST_3_2::default());
        functions.C_WrapKeyAuthenticated = Some(missing_length_wrap);
        let backend = FfiBackend {
            _lib: libloading::os::unix::Library::this().into(),
            func_list: base.as_mut(),
            func_list_3_0: None,
            func_list_3_2: Some(functions.as_ref()),
            initialize_args: None,
            mech_cache: dashmap::DashMap::new(),
            session_slot_map: dashmap::DashMap::new(),
            slot_sessions: dashmap::DashMap::new(),
            object_cleanup: Default::default(),
        };
        (backend, base, functions)
    }

    #[test]
    fn null_output_length_authenticated_wrap_forwards_once_and_keeps_parameter_output() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        CALLS.store(0, Ordering::SeqCst);
        OUTPUT_PRESENT.store(0, Ordering::SeqCst);
        LENGTH_NULL.store(0, Ordering::SeqCst);
        RETURN_RV.store(cryptoki_sys::CKR_OK as usize, Ordering::SeqCst);
        let (backend, _base, _functions) = backend_with_missing_length_wrap();
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType::AES_CBC,
            params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0x11; 16] })),
        };
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true };
        let parameter_spec = CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: 16,
            value: Some(vec![0x11; 16]),
        };

        let (output, parameter) = backend
            .ffi_wrap_key_authenticated_exact(
                CkSessionHandle(1),
                &mechanism,
                CkObjectHandle(2),
                CkObjectHandle(3),
                CkInBuf::Bytes(b"aad"),
                &output_spec,
                &parameter_spec,
            )
            .expect("provider result envelope");

        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(OUTPUT_PRESENT.load(Ordering::SeqCst), 1);
        assert_eq!(LENGTH_NULL.load(Ordering::SeqCst), 1);
        assert_eq!(output.ck_rv, CkRv::OK);
        assert_eq!(output.returned_len, None);
        assert_eq!(output.value, None);
        assert_eq!(parameter.ck_rv, CkRv::OK);
        assert_eq!(parameter.returned_len, 16);
        assert_eq!(parameter.value.as_ref().map(|value| value[0]), Some(0xA5));
    }

    #[test]
    fn null_output_length_authenticated_wrap_preserves_buffer_too_small_and_parameter_output() {
        let _guard = TEST_LOCK.lock().unwrap();
        CALLS.store(0, Ordering::SeqCst);
        RETURN_RV.store(cryptoki_sys::CKR_BUFFER_TOO_SMALL as usize, Ordering::SeqCst);
        let (backend, _base, _functions) = backend_with_missing_length_wrap();
        let mechanism = CkMechanism {
            mechanism_type: CkMechanismType::AES_CBC,
            params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0x11; 16] })),
        };
        let output_spec =
            CkOutputBufferSpec { buffer_present: true, buffer_len: 0, length_pointer_null: true };
        let parameter_spec = CkParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: 16,
            value: Some(vec![0x11; 16]),
        };

        let (output, parameter) = backend
            .ffi_wrap_key_authenticated_exact(
                CkSessionHandle(1),
                &mechanism,
                CkObjectHandle(2),
                CkObjectHandle(3),
                CkInBuf::Bytes(b"aad"),
                &output_spec,
                &parameter_spec,
            )
            .expect("provider result envelope");

        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(output.ck_rv, CkRv::BUFFER_TOO_SMALL);
        assert_eq!(output.returned_len, None);
        assert_eq!(output.value, None);
        assert_eq!(parameter.ck_rv, CkRv::BUFFER_TOO_SMALL);
        assert_eq!(parameter.returned_len, 16);
        assert_eq!(parameter.value.as_ref().map(|value| value[0]), Some(0xA5));
    }
}
