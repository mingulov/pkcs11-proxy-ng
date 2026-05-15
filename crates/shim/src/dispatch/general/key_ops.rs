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
        if p_mechanism.is_null() || pul_wrapped_key_len.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }

        let mech = unsafe { read_mechanism(p_mechanism) };
        let spec = unsafe { output_buffer_spec(p_wrapped_key, pul_wrapped_key_len) };
        let result = with_client!(client => client.byte_output_exact(
            CkSessionHandle(h_session),
            ByteOutputFunction::WrapKey,
            &spec,
            &[],
            Some(&mech),
            h_wrapping_key,
            h_key,
        ));
        match result {
            Ok(r) => unsafe { write_exact_output(&r, p_wrapped_key, pul_wrapped_key_len) },
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
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        let wrapped_key = unsafe { read_input_slice(p_wrapped_key, ul_wrapped_key_len) };
        let template = unsafe { ck_attrs_to_rust(p_template, ul_count) };
        match with_client!(client => client.unwrap_key(
            CkSessionHandle(h_session),
            &mech,
            CkObjectHandle(h_unwrapping_key),
            wrapped_key,
            &template,
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
        if p_mechanism.is_null() || ph_key.is_null() {
            return rv_err(CkRv::ARGUMENTS_BAD);
        }
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        let template = unsafe { ck_attrs_to_rust(p_template, ul_count) };
        match with_client!(client => client.derive_key(
            CkSessionHandle(h_session),
            &mech,
            CkObjectHandle(h_base_key),
            &template,
        )) {
            Ok(handle) => {
                unsafe { write_object_handle_output(handle, ph_key) };
                rv_ok()
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
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        let template = unsafe { ck_attrs_to_rust(p_template, ul_count) };
        match with_client!(client => client.generate_key(CkSessionHandle(h_session), &mech, &template))
        {
            Ok(handle) => {
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
        let rv = unsafe { validate_mechanism(p_mechanism) };
        if rv != rv_ok() {
            return rv;
        }
        let mech = unsafe { read_mechanism(p_mechanism) };
        let pub_tmpl =
            unsafe { ck_attrs_to_rust(p_public_key_template, ul_public_key_attribute_count) };
        let priv_tmpl =
            unsafe { ck_attrs_to_rust(p_private_key_template, ul_private_key_attribute_count) };
        match with_client!(client => client.generate_key_pair(
            CkSessionHandle(h_session),
            &mech,
            &pub_tmpl,
            &priv_tmpl,
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
        let seed = unsafe { read_input_slice(p_seed, ul_seed_len) };
        unit_result_to_rv(
            with_client!(client => client.seed_random(CkSessionHandle(h_session), seed)),
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
        match with_client!(client => client.generate_random(CkSessionHandle(h_session), ul_random_len as u32))
        {
            Ok(data) => {
                if data.len() != ul_random_len as usize {
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
