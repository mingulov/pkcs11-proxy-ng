use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

#[allow(unused_imports)]
use super::*;

pub unsafe extern "C" fn c_wrap_key(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_wrapping_key: CK_OBJECT_HANDLE,
    h_key: CK_OBJECT_HANDLE,
    p_wrapped_key: CK_BYTE_PTR,
    pul_wrapped_key_len: CK_ULONG_PTR,
) -> CK_RV {
    catch_panics(|| {
        if p_mechanism.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }

        let mech = unsafe { read_wrap_key_mechanism(p_mechanism) };
        let spec = unsafe { output_buffer_spec(p_wrapped_key, pul_wrapped_key_len) };
        let result = with_client!(client => client.byte_output_exact_with_mechanism_out(
            CkSessionHandle(h_session as u64),
            ByteOutputFunction::WrapKey,
            &spec,
            CkInBuf::Bytes(&[]),
            Some(&mech),
            h_wrapping_key.into(),
            h_key.into(),
        ));
        match result {
            Ok((r, mechanism_out)) => {
                let rv =
                    unsafe { write_exact_output(&spec, &r, p_wrapped_key, pul_wrapped_key_len) };
                // A missing length pointer remains a genuine provider call, so
                // preserve any successful mechanism writeback independently of
                // the main output pointer. Ordinary size queries keep the
                // historical no-writeback behavior.
                if rv == rv_ok()
                    && (spec.buffer_present || spec.length_pointer_null)
                    && let Some(params) = mechanism_out
                {
                    unsafe { write_mechanism_output_params(p_mechanism, &params) };
                }
                rv
            }
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_unwrap_key(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_unwrapping_key: CK_OBJECT_HANDLE,
    p_wrapped_key: CK_BYTE_PTR,
    ul_wrapped_key_len: CK_ULONG,
    p_template: CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
    ph_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_panics(|| {
        if p_mechanism.is_null() || ph_key.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let template = match unsafe { ck_attrs_to_rust_checked(p_template, ul_count) } {
            Ok(template) => template,
            Err(e) => return rv_err(e),
        };
        let template_opt = null_preserving_template(&template, p_template);
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        let wrapped_key = match input_buf_to_ck_in_buf(unsafe {
            classify_input(p_wrapped_key, ul_wrapped_key_len)
        }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        match with_client!(client => client.unwrap_key(
            CkSessionHandle(h_session as u64),
            &mech,
            CkObjectHandle(h_unwrapping_key as u64),
            wrapped_key,
            template_opt,
        )) {
            Ok(handle) => {
                unsafe { write_object_handle_output(handle, ph_key) };
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_derive_key(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_base_key: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
    ph_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_panics(|| {
        // `ph_key` may legitimately be NULL: the SSL3/TLS/WTLS key-and-mac
        // "key material" derive mechanisms (e.g. CKM_TLS12_KEY_AND_MAC_DERIVE)
        // return their derived keys through the mechanism parameter's
        // pReturnedKeyMaterial rather than through ph_key, and callers pass NULL
        // there. Don't fabricate CKR_ARGUMENTS_BAD locally — forward the call and
        // let the backend decide (a plain derive with a NULL ph_key still gets
        // the backend's own error, preserving exact CK_RV transparency).
        if p_mechanism.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let template = match unsafe { ck_attrs_to_rust_checked(p_template, ul_count) } {
            Ok(template) => template,
            Err(e) => return rv_err(e),
        };
        let template_opt = null_preserving_template(&template, p_template);
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        match with_client!(client => client.derive_key_with_mechanism_out_result(
            CkSessionHandle(h_session as u64),
            &mech,
            CkObjectHandle(h_base_key as u64),
            template_opt,
        )) {
            Ok(result) => {
                // Write HSM-mutated mechanism fields back into the caller's
                // CK_MECHANISM: TLS12 master-key-derive's pVersion, and the
                // key-and-mac derives' pReturnedKeyMaterial (4 key handles + IVs).
                // A no-op for mechanisms without output params.
                if let Some(params) = result.mechanism_out {
                    unsafe { write_mechanism_output_params(p_mechanism, &params) };
                }
                if result.rv.is_ok() {
                    // A plain C_DeriveKey returns one handle via ph_key; the
                    // key-material mechanisms return theirs via the param above
                    // and pass ph_key == NULL. Only write the single handle when
                    // the caller supplied a location for it.
                    if !ph_key.is_null() {
                        let Some(handle) = result.key_handle else {
                            return rv_err(CkRv::GENERAL_ERROR);
                        };
                        unsafe { write_object_handle_output(handle, ph_key) };
                    }
                    rv_ok()
                } else {
                    rv_err(result.rv)
                }
            }
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_generate_key(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    p_template: CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
    ph_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_panics(|| {
        if p_mechanism.is_null() || ph_key.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let template = match unsafe { ck_attrs_to_rust_checked(p_template, ul_count) } {
            Ok(template) => template,
            Err(e) => return rv_err(e),
        };
        let template_opt = null_preserving_template(&template, p_template);
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        match with_client!(client => client.generate_key_with_mechanism_out(
            CkSessionHandle(h_session as u64),
            &mech,
            template_opt,
        )) {
            Ok((handle, mechanism_out)) => {
                // Write any HSM-mutated mechanism field back into the caller's
                // CK_MECHANISM — for PBE key generation this is the generated
                // CK_PBE_PARAMS.pInitVector. A no-op for mechanisms without
                // output params.
                if let Some(params) = mechanism_out {
                    unsafe { write_mechanism_output_params(p_mechanism, &params) };
                }
                unsafe { write_object_handle_output(handle, ph_key) };
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_generate_key_pair(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    p_public_key_template: CK_ATTRIBUTE_PTR,
    ul_public_key_attribute_count: CK_ULONG,
    p_private_key_template: CK_ATTRIBUTE_PTR,
    ul_private_key_attribute_count: CK_ULONG,
    ph_public_key: CK_OBJECT_HANDLE_PTR,
    ph_private_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    catch_panics(|| {
        if p_mechanism.is_null() || ph_public_key.is_null() || ph_private_key.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let pub_tmpl = match unsafe {
            ck_attrs_to_rust_checked(p_public_key_template, ul_public_key_attribute_count)
        } {
            Ok(template) => template,
            Err(e) => return rv_err(e),
        };
        let pub_opt = null_preserving_template(&pub_tmpl, p_public_key_template);
        let priv_tmpl = match unsafe {
            ck_attrs_to_rust_checked(p_private_key_template, ul_private_key_attribute_count)
        } {
            Ok(template) => template,
            Err(e) => return rv_err(e),
        };
        let priv_opt = null_preserving_template(&priv_tmpl, p_private_key_template);
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        match with_client!(client => client.generate_key_pair(
            CkSessionHandle(h_session as u64),
            &mech,
            pub_opt,
            priv_opt,
        )) {
            Ok((public_handle, private_handle)) => {
                unsafe {
                    write_object_handle_pair_output(
                        public_handle,
                        private_handle,
                        ph_public_key,
                        ph_private_key,
                    )
                };
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

pub unsafe extern "C" fn c_seed_random(
    h_session: CK_SESSION_HANDLE,
    p_seed: CK_BYTE_PTR,
    ul_seed_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        let seed = match input_buf_to_ck_in_buf(unsafe { classify_input(p_seed, ul_seed_len) }) {
            Ok(buf) => buf,
            Err(e) => return rv_err(e),
        };
        unit_result_to_rv(
            with_client!(client => client.seed_random(CkSessionHandle(h_session as u64), seed)),
        )
    })
}

pub unsafe extern "C" fn c_generate_random(
    h_session: CK_SESSION_HANDLE,
    p_random_data: CK_BYTE_PTR,
    ul_random_len: CK_ULONG,
) -> CK_RV {
    catch_panics(|| {
        if p_random_data.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let random_len = match u32::try_from(ul_random_len) {
            Ok(len) => len,
            Err(_) => return rv_err(CkRv::DATA_LEN_RANGE),
        };
        match with_client!(client => client.generate_random(CkSessionHandle(h_session as u64), random_len))
        {
            Ok(data) => {
                if data.len() != random_len as usize {
                    return rv_err(CkRv::DEVICE_ERROR);
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), p_random_data, data.len());
                }
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

// ---------------------------------------------------------------------------
// Combined operations (items 21-24)
// ---------------------------------------------------------------------------
