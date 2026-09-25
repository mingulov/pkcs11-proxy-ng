use cryptoki_sys::*;
use pkcs11_proxy_ng_types::*;

use crate::state;

use super::helpers::{
    catch_panics, ck_attrs_to_rust_checked, classify_input, derive_key_post_rpc,
    generate_key_post_rpc, input_buf_to_ck_in_buf, null_preserving_template, output_buffer_spec,
    read_mechanism, read_wrap_key_mechanism, rv_err, rv_ok, unit_result_to_rv, validate_mechanism,
    with_client, wrap_key_post_rpc, write_object_handle_output, write_object_handle_pair_output,
};

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
        // T07: gate before registry access (validate/read below) so a
        // pre-init call returns CRYPTOKI_NOT_INITIALIZED instead of
        // panicking on the uninstalled registry.
        if !state::is_initialized() {
            return rv_err(CkRv::CRYPTOKI_NOT_INITIALIZED);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }

        let mech = match unsafe { read_wrap_key_mechanism(p_mechanism) } {
            Ok(mech) => mech,
            Err(e) => return rv_err(e),
        };
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
            Ok((r, mechanism_out)) => unsafe {
                // Transactional post-RPC outputs (T06): the mechanism plan
                // prepares before the byte plan writes. A missing length
                // pointer remains a genuine provider call with independent
                // mechanism writeback; ordinary size queries keep the
                // historical no-writeback behavior.
                wrap_key_post_rpc(
                    &spec,
                    &r,
                    mechanism_out.as_ref(),
                    p_mechanism,
                    p_wrapped_key,
                    pul_wrapped_key_len,
                )
            },
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
        // T07: gate after pure-local argument parsing but before registry
        // access (validate/read below) so a pre-init call returns
        // CRYPTOKI_NOT_INITIALIZED instead of panicking on the
        // uninstalled registry.
        if !state::is_initialized() {
            return rv_err(CkRv::CRYPTOKI_NOT_INITIALIZED);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = match unsafe { read_mechanism(p_mechanism) } {
            Ok(mech) => mech,
            Err(e) => return rv_err(e),
        };
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
            Ok(handle) => match unsafe { write_object_handle_output(handle, ph_key) } {
                Ok(()) => rv_ok(),
                Err(e) => rv_err(e),
            },
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
        // T07: gate after pure-local argument parsing but before registry
        // access (validate/read below) so a pre-init call returns
        // CRYPTOKI_NOT_INITIALIZED instead of panicking on the
        // uninstalled registry.
        if !state::is_initialized() {
            return rv_err(CkRv::CRYPTOKI_NOT_INITIALIZED);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = match unsafe { read_mechanism(p_mechanism) } {
            Ok(mech) => mech,
            Err(e) => return rv_err(e),
        };
        match with_client!(client => client.derive_key_with_mechanism_out_result(
            CkSessionHandle(h_session as u64),
            &mech,
            CkObjectHandle(h_base_key as u64),
            template_opt,
        )) {
            // Transactional post-RPC outputs (T06): HSM-mutated mechanism
            // fields (TLS12 pVersion, key-material handles + IVs) prepare
            // before any store; a no-op for mechanisms without outputs.
            Ok(result) => unsafe {
                derive_key_post_rpc(
                    result.rv,
                    result.key_handle,
                    result.mechanism_out.as_ref(),
                    p_mechanism,
                    ph_key,
                )
            },
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
        // T07: gate after pure-local argument parsing but before registry
        // access (validate/read below) so a pre-init call returns
        // CRYPTOKI_NOT_INITIALIZED instead of panicking on the
        // uninstalled registry.
        if !state::is_initialized() {
            return rv_err(CkRv::CRYPTOKI_NOT_INITIALIZED);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = match unsafe { read_mechanism(p_mechanism) } {
            Ok(mech) => mech,
            Err(e) => return rv_err(e),
        };
        match with_client!(client => client.generate_key_with_mechanism_out(
            CkSessionHandle(h_session as u64),
            &mech,
            template_opt,
        )) {
            // Transactional post-RPC outputs (T06): HSM-mutated mechanism
            // fields (PBE pInitVector) and the handle validate before
            // either writes. A no-op for mechanisms without outputs.
            Ok((handle, mechanism_out)) => unsafe {
                generate_key_post_rpc(handle, mechanism_out.as_ref(), p_mechanism, ph_key)
            },
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
        // T07: gate after pure-local argument parsing but before registry
        // access (validate/read below) so a pre-init call returns
        // CRYPTOKI_NOT_INITIALIZED instead of panicking on the
        // uninstalled registry.
        if !state::is_initialized() {
            return rv_err(CkRv::CRYPTOKI_NOT_INITIALIZED);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = match unsafe { read_mechanism(p_mechanism) } {
            Ok(mech) => mech,
            Err(e) => return rv_err(e),
        };
        match with_client!(client => client.generate_key_pair(
            CkSessionHandle(h_session as u64),
            &mech,
            pub_opt,
            priv_opt,
        )) {
            Ok((public_handle, private_handle)) => {
                match unsafe {
                    write_object_handle_pair_output(
                        public_handle,
                        private_handle,
                        ph_public_key,
                        ph_private_key,
                    )
                } {
                    Ok(()) => rv_ok(),
                    Err(e) => rv_err(e),
                }
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
                // W1-L3-08: a daemon response with the wrong length is a
                // protocol violation, not a backend failure — fail closed
                // with GENERAL_ERROR before touching caller memory.
                if data.len() != random_len as usize {
                    return rv_err(CkRv::GENERAL_ERROR);
                }
                // T13: SecretBytes is closure-scoped; the length was
                // already validated against `random_len` above.
                data.expose(|bytes| unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), p_random_data, bytes.len());
                });
                rv_ok()
            }
            Err(e) => rv_err(e),
        }
    })
}

// ---------------------------------------------------------------------------
// Combined operations (items 21-24)
// ---------------------------------------------------------------------------
