// crates/pkcs11-backend/src/ffi.rs
use crate::traits::Pkcs11Backend;
use libloading::Library;
use pkcs11_proxy_ng_types::*;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Mutex;

#[path = "ffi/authenticated_wrap_ops.rs"]
mod authenticated_wrap_ops;
#[path = "ffi/call_helpers.rs"]
mod call_helpers;
#[path = "ffi/crypto_ops.rs"]
mod crypto_ops;
#[path = "ffi/ffi_conversion.rs"]
mod ffi_conversion;
#[path = "ffi/function_field_tables.rs"]
mod function_field_tables;
#[path = "ffi/interface_caps.rs"]
mod interface_caps;
#[path = "ffi/kem_ops.rs"]
mod kem_ops;
#[path = "ffi/key_state_ops.rs"]
mod key_state_ops;
#[path = "ffi/loading.rs"]
mod loading;
#[path = "ffi/mapping.rs"]
mod mapping;
#[path = "ffi/message_ops.rs"]
mod message_ops;
#[path = "ffi/object_ops.rs"]
mod object_ops;
#[path = "ffi/session_3x_ops.rs"]
mod session_3x_ops;
#[path = "ffi/session_ops.rs"]
mod session_ops;
#[path = "ffi/verify_signature_ops.rs"]
mod verify_signature_ops;

use ffi_conversion::{FfiAttributeQueries, FfiAttrs, space_pad};
use mapping::{
    exact_attribute_results_from_ffi, info_from_ck, mechanism_info_from_ck, session_info_from_ck,
    slot_info_from_ck, token_info_from_ck, update_template_from_ffi,
};

macro_rules! session_bytes_input {
    ($session:expr, $input:expr, $function:ident, $output:ident, $output_len:ident) => {
        unsafe {
            $function(
                Self::session_handle($session),
                $input.as_ptr() as *mut _,
                Self::ulong_len($input.len()),
                $output,
                $output_len,
            )
        }
    };
}
pub(crate) use session_bytes_input;

macro_rules! session_unit_input {
    ($session:expr, $input:expr, $function:ident) => {
        unsafe {
            $function(
                Self::session_handle($session),
                $input.as_ptr() as *mut _,
                Self::ulong_len($input.len()),
            )
        }
    };
}
pub(crate) use session_unit_input;

macro_rules! mechanism_key_init {
    ($session:expr, $mechanism:expr, $key:expr, $function:ident, $mech:ident) => {
        unsafe { $function(Self::session_handle($session), $mech, Self::object_handle($key)) }
    };
}
pub(crate) use mechanism_key_init;

macro_rules! session_bytes_final {
    ($session:expr, $function:ident, $output:ident, $output_len:ident) => {
        unsafe { $function(Self::session_handle($session), $output, $output_len) }
    };
}
pub(crate) use session_bytes_final;

macro_rules! session_object_unit {
    ($session:expr, $object:expr, $function:ident) => {
        unsafe { $function(Self::session_handle($session), Self::object_handle($object)) }
    };
}
pub(crate) use session_object_unit;

/// Dispatch a call through a 3.x function list pointer.
///
/// Returns `Err(CkRv::FUNCTION_NOT_SUPPORTED)` if the function list is `None`
/// (module only supports 2.40) or if the specific function slot is `None`.
///
/// # Safety
/// The caller must ensure arguments satisfy the PKCS#11 C ABI contract for the
/// target function. The function list pointer must remain valid for the
/// lifetime of `$self` (guaranteed by `_lib` keeping the module loaded).
// The macro and re-export are used by sibling modules that implement 3.x
// backend trait methods (added in subsequent tasks).
#[allow(unused_macros)]
macro_rules! call_3x_fn {
    ($self:expr, $list_field:ident, $fn_name:ident $(, $arg:expr)*) => {{
        let fl = match $self.$list_field {
            Some(fl) => fl,
            None => return Err(CkRv::FUNCTION_NOT_SUPPORTED),
        };
        let f = match unsafe { (*fl).$fn_name } {
            Some(f) => f,
            None => return Err(CkRv::FUNCTION_NOT_SUPPORTED),
        };
        let rv = unsafe { f($($arg),*) };
        FfiBackend::ck_result(rv)
    }};
}
#[allow(unused_imports)]
pub(crate) use call_3x_fn;

/// FFI backend that loads a PKCS#11 shared library via dlopen (ADR-0004 §2).
pub struct FfiBackend {
    _lib: Library, // kept alive to prevent unloading
    func_list: *mut cryptoki_sys::CK_FUNCTION_LIST,
    /// PKCS#11 3.0 function list, if the module supports `C_GetInterface`.
    func_list_3_0: Option<*const cryptoki_sys::CK_FUNCTION_LIST_3_0>,
    /// PKCS#11 3.2 function list, if the module supports `C_GetInterface`.
    func_list_3_2: Option<*const cryptoki_sys::CK_FUNCTION_LIST_3_2>,
    initialize_args: Option<CString>,
    /// Per-session mechanism parameter cache.  Some backends (OpenCryptoki)
    /// store pointers from the mechanism struct passed to *Init calls and
    /// dereference them during the subsequent operation (Encrypt/Decrypt/…).
    /// The spec says backends should copy, but for compatibility we keep the
    /// FfiMechanism (and its backing `Vec<u8>` buffers) alive until the next
    /// Init call or session close replaces it.
    mech_cache: Mutex<HashMap<u64, ffi_conversion::FfiMechanism>>,
}

// Safety: PKCS#11 spec requires modules loaded with CKF_OS_LOCKING_OK to be
// thread-safe. We enforce this flag in C_Initialize via initialize().
// The raw pointers (func_list, func_list_3_0, func_list_3_2) all point into
// the loaded module's static data; the module is kept alive by `_lib`.
unsafe impl Send for FfiBackend {}
unsafe impl Sync for FfiBackend {}

impl FfiBackend {
    const FUNCTION_NOT_SUPPORTED: CkRv = CkRv::FUNCTION_NOT_SUPPORTED;

    fn ffi_attr_ptr(ffi_attrs: &FfiAttrs) -> *mut cryptoki_sys::CK_ATTRIBUTE {
        ffi_attrs.attrs.as_ptr() as *mut _
    }

    fn ffi_attr_len(ffi_attrs: &FfiAttrs) -> cryptoki_sys::CK_ULONG {
        Self::ulong_len(ffi_attrs.attrs.len())
    }
}

impl Pkcs11Backend for FfiBackend {
    fn initialize(&self) -> CkResult<()> {
        let mut args = cryptoki_sys::CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: cryptoki_sys::CKF_OS_LOCKING_OK,
            pReserved: self
                .initialize_args
                .as_ref()
                .map(|s| s.as_ptr() as *mut std::ffi::c_void)
                .unwrap_or(std::ptr::null_mut()),
        };
        Self::call_unit(unsafe { (*self.func_list).C_Initialize }, |function| unsafe {
            function(&mut args as *mut _ as cryptoki_sys::CK_VOID_PTR)
        })
    }

    fn finalize(&self) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_Finalize }, |function| unsafe {
            function(std::ptr::null_mut())
        })
    }

    fn get_info(&self) -> CkResult<CkInfo> {
        self.ffi_get_info()
    }

    fn get_slot_list(&self, token_present: bool) -> CkResult<Vec<CkSlotId>> {
        self.ffi_get_slot_list(token_present)
    }

    fn get_slot_info(&self, slot_id: CkSlotId) -> CkResult<CkSlotInfo> {
        self.ffi_get_slot_info(slot_id)
    }

    fn get_token_info(&self, slot_id: CkSlotId) -> CkResult<CkTokenInfo> {
        self.ffi_get_token_info(slot_id)
    }

    fn get_mechanism_list(&self, slot_id: CkSlotId) -> CkResult<Vec<CkMechanismType>> {
        self.ffi_get_mechanism_list(slot_id)
    }

    fn get_mechanism_info(
        &self,
        slot_id: CkSlotId,
        mech: CkMechanismType,
    ) -> CkResult<CkMechanismInfo> {
        self.ffi_get_mechanism_info(slot_id, mech)
    }

    fn init_token(&self, slot_id: CkSlotId, so_pin: Option<&[u8]>, label: &str) -> CkResult<()> {
        self.ffi_init_token(slot_id, so_pin, label)
    }

    fn init_pin(&self, session: CkSessionHandle, pin: Option<&[u8]>) -> CkResult<()> {
        self.ffi_init_pin(session, pin)
    }

    fn set_pin(
        &self,
        session: CkSessionHandle,
        old_pin: Option<&[u8]>,
        new_pin: Option<&[u8]>,
    ) -> CkResult<()> {
        self.ffi_set_pin(session, old_pin, new_pin)
    }

    fn open_session(&self, slot_id: CkSlotId, flags: CkSessionFlags) -> CkResult<CkSessionHandle> {
        self.ffi_open_session(slot_id, flags)
    }

    fn close_session(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_close_session(session)
    }

    fn close_all_sessions(&self, slot_id: CkSlotId) -> CkResult<()> {
        self.ffi_close_all_sessions(slot_id)
    }

    fn get_session_info(&self, session: CkSessionHandle) -> CkResult<CkSessionInfo> {
        self.ffi_get_session_info(session)
    }

    fn login(
        &self,
        session: CkSessionHandle,
        user_type: CkUserType,
        pin: Option<&[u8]>,
    ) -> CkResult<()> {
        self.ffi_login(session, user_type, pin)
    }

    fn logout(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_logout(session)
    }

    fn find_objects_init(
        &self,
        session: CkSessionHandle,
        template: &[CkAttribute],
    ) -> CkResult<()> {
        self.ffi_find_objects_init(session, template)
    }

    fn find_objects(
        &self,
        session: CkSessionHandle,
        max_count: u32,
    ) -> CkResult<Vec<CkObjectHandle>> {
        self.ffi_find_objects(session, max_count)
    }

    fn find_objects_final(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_find_objects_final(session)
    }

    fn get_attribute_value(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &mut [CkAttribute],
    ) -> CkResult<()> {
        self.ffi_get_attribute_value(session, object, template)
    }
    fn get_attribute_value_exact(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        queries: &[CkAttributeQuery],
    ) -> CkResult<(CkRv, Vec<CkAttributeQueryResult>)> {
        self.ffi_get_attribute_value_exact(session, object, queries)
    }

    fn sign_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_sign_init(session, mechanism, key)
    }

    fn sign(&self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        self.ffi_sign(session, data)
    }

    fn sign_update(&self, session: CkSessionHandle, part: &[u8]) -> CkResult<()> {
        self.ffi_sign_update(session, part)
    }

    fn sign_final(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.ffi_sign_final(session)
    }

    fn sign_recover_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_sign_recover_init(session, mechanism, key)
    }

    fn sign_recover(&self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        self.ffi_sign_recover(session, data)
    }

    fn sign_exact(
        &self,
        session: CkSessionHandle,
        data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_sign_exact(session, data, spec)
    }

    fn sign_final_exact(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_sign_final_exact(session, spec)
    }

    fn sign_recover_exact(
        &self,
        session: CkSessionHandle,
        data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_sign_recover_exact(session, data, spec)
    }

    fn verify_recover_exact(
        &self,
        session: CkSessionHandle,
        signature: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_verify_recover_exact(session, signature, spec)
    }

    fn verify_recover_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_verify_recover_init(session, mechanism, key)
    }

    fn verify_recover(&self, session: CkSessionHandle, signature: &[u8]) -> CkResult<Vec<u8>> {
        self.ffi_verify_recover(session, signature)
    }

    fn verify_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_verify_init(session, mechanism, key)
    }

    fn verify(&self, session: CkSessionHandle, data: &[u8], signature: &[u8]) -> CkResult<()> {
        self.ffi_verify(session, data, signature)
    }

    fn verify_update(&self, session: CkSessionHandle, part: &[u8]) -> CkResult<()> {
        self.ffi_verify_update(session, part)
    }

    fn verify_final(&self, session: CkSessionHandle, signature: &[u8]) -> CkResult<()> {
        self.ffi_verify_final(session, signature)
    }

    fn digest_init(&self, session: CkSessionHandle, mechanism: &CkMechanism) -> CkResult<()> {
        self.ffi_digest_init(session, mechanism)
    }

    fn digest(&self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        self.ffi_digest(session, data)
    }

    fn digest_update(&self, session: CkSessionHandle, part: &[u8]) -> CkResult<()> {
        self.ffi_digest_update(session, part)
    }

    fn digest_key(&self, session: CkSessionHandle, key: CkObjectHandle) -> CkResult<()> {
        self.ffi_digest_key(session, key)
    }

    fn digest_final(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.ffi_digest_final(session)
    }

    fn digest_exact(
        &self,
        session: CkSessionHandle,
        data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_digest_exact(session, data, spec)
    }

    fn digest_final_exact(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_digest_final_exact(session, spec)
    }

    fn encrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>> {
        self.ffi_encrypt_init_with_output(session, mechanism, key)
    }

    fn encrypt(&self, session: CkSessionHandle, data: &[u8]) -> CkResult<Vec<u8>> {
        self.ffi_encrypt(session, data)
    }

    fn encrypt_update(&self, session: CkSessionHandle, part: &[u8]) -> CkResult<Vec<u8>> {
        self.ffi_encrypt_update(session, part)
    }

    fn encrypt_final(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.ffi_encrypt_final(session)
    }

    fn decrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_decrypt_init(session, mechanism, key)
    }

    fn decrypt(&self, session: CkSessionHandle, encrypted_data: &[u8]) -> CkResult<Vec<u8>> {
        self.ffi_decrypt(session, encrypted_data)
    }

    fn decrypt_update(&self, session: CkSessionHandle, encrypted_part: &[u8]) -> CkResult<Vec<u8>> {
        self.ffi_decrypt_update(session, encrypted_part)
    }

    fn decrypt_final(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.ffi_decrypt_final(session)
    }

    fn encrypt_exact(
        &self,
        session: CkSessionHandle,
        data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_encrypt_exact(session, data, spec)
    }

    fn encrypt_exact_with_output(
        &self,
        session: CkSessionHandle,
        data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<(CkOutputBufferResult, Option<CkMechanismParams>)> {
        self.ffi_encrypt_exact_with_output(session, data, spec)
    }

    fn encrypt_update_exact(
        &self,
        session: CkSessionHandle,
        part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_encrypt_update_exact(session, part, spec)
    }

    fn encrypt_final_exact(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_encrypt_final_exact(session, spec)
    }

    fn decrypt_exact(
        &self,
        session: CkSessionHandle,
        encrypted_data: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_decrypt_exact(session, encrypted_data, spec)
    }

    fn decrypt_update_exact(
        &self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_decrypt_update_exact(session, encrypted_part, spec)
    }

    fn decrypt_final_exact(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_decrypt_final_exact(session, spec)
    }

    fn derive_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        base_key: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.ffi_derive_key(session, mechanism, base_key, template)
    }

    fn wrap_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
    ) -> CkResult<Vec<u8>> {
        self.ffi_wrap_key(session, mechanism, wrapping_key, key)
    }

    fn wrap_key_exact(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_wrap_key_exact(session, mechanism, wrapping_key, key, spec)
    }

    fn unwrap_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        unwrapping_key: CkObjectHandle,
        wrapped_key: &[u8],
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.ffi_unwrap_key(session, mechanism, unwrapping_key, wrapped_key, template)
    }

    fn generate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.ffi_generate_key(session, mechanism, template)
    }

    fn create_object(
        &self,
        session: CkSessionHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.ffi_create_object(session, template)
    }

    fn copy_object(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        self.ffi_copy_object(session, object, template)
    }

    fn destroy_object(&self, session: CkSessionHandle, object: CkObjectHandle) -> CkResult<()> {
        self.ffi_destroy_object(session, object)
    }

    fn get_object_size(&self, session: CkSessionHandle, object: CkObjectHandle) -> CkResult<u64> {
        self.ffi_get_object_size(session, object)
    }

    fn set_attribute_value(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<()> {
        self.ffi_set_attribute_value(session, object, template)
    }

    fn generate_key_pair(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        pub_template: &[CkAttribute],
        priv_template: &[CkAttribute],
    ) -> CkResult<(CkObjectHandle, CkObjectHandle)> {
        self.ffi_generate_key_pair(session, mechanism, pub_template, priv_template)
    }

    fn wait_for_slot_event(&self, flags: u64) -> CkResult<CkSlotId> {
        self.ffi_wait_for_slot_event(flags)
    }

    fn get_operation_state(&self, session: CkSessionHandle) -> CkResult<Vec<u8>> {
        self.ffi_get_operation_state(session)
    }

    fn get_operation_state_exact(
        &self,
        session: CkSessionHandle,
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_get_operation_state_exact(session, spec)
    }

    fn set_operation_state(
        &self,
        session: CkSessionHandle,
        state: &[u8],
        enc_key: CkObjectHandle,
        auth_key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_set_operation_state(session, state, enc_key, auth_key)
    }

    fn seed_random(&self, session: CkSessionHandle, seed: &[u8]) -> CkResult<()> {
        self.ffi_seed_random(session, seed)
    }

    fn generate_random(&self, session: CkSessionHandle, len: u32) -> CkResult<Vec<u8>> {
        self.ffi_generate_random(session, len)
    }

    fn get_function_status(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_get_function_status(session)
    }

    fn cancel_function(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_cancel_function(session)
    }

    fn digest_encrypt_update(&self, session: CkSessionHandle, part: &[u8]) -> CkResult<Vec<u8>> {
        self.ffi_digest_encrypt_update(session, part)
    }

    fn digest_encrypt_update_exact(
        &self,
        session: CkSessionHandle,
        part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_digest_encrypt_update_exact(session, part, spec)
    }

    fn decrypt_digest_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>> {
        self.ffi_decrypt_digest_update(session, encrypted_part)
    }

    fn decrypt_digest_update_exact(
        &self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_decrypt_digest_update_exact(session, encrypted_part, spec)
    }

    fn sign_encrypt_update(&self, session: CkSessionHandle, part: &[u8]) -> CkResult<Vec<u8>> {
        self.ffi_sign_encrypt_update(session, part)
    }

    fn sign_encrypt_update_exact(
        &self,
        session: CkSessionHandle,
        part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_sign_encrypt_update_exact(session, part, spec)
    }

    fn decrypt_verify_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
    ) -> CkResult<Vec<u8>> {
        self.ffi_decrypt_verify_update(session, encrypted_part)
    }

    fn decrypt_verify_update_exact(
        &self,
        session: CkSessionHandle,
        encrypted_part: &[u8],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputBufferResult> {
        self.ffi_decrypt_verify_update_exact(session, encrypted_part, spec)
    }

    // --- PKCS#11 3.0/3.2 overrides ---

    fn login_user(
        &self,
        session: CkSessionHandle,
        user_type: CkUserType,
        username: &[u8],
        pin: &[u8],
    ) -> CkResult<()> {
        self.ffi_login_user(session, user_type, username, pin)
    }

    fn session_cancel(&self, session: CkSessionHandle, flags: CkFlags) -> CkResult<()> {
        self.ffi_session_cancel(session, flags)
    }

    fn get_session_validation_flags(
        &self,
        session: CkSessionHandle,
        flags_type: u64,
    ) -> CkResult<u64> {
        self.ffi_get_session_validation_flags(session, flags_type)
    }

    fn encapsulate_key_exact(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        public_key: CkObjectHandle,
        template: &[CkAttribute],
        spec: &CkOutputBufferSpec,
    ) -> CkResult<CkOutputAndHandleResult> {
        self.ffi_encapsulate_key_exact(session, mechanism, public_key, template, spec)
    }

    fn encapsulate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        public_key: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<(Vec<u8>, CkObjectHandle)> {
        self.ffi_encapsulate_key(session, mechanism, public_key, template)
    }

    fn decapsulate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        private_key: CkObjectHandle,
        template: &[CkAttribute],
        ciphertext: &[u8],
    ) -> CkResult<CkObjectHandle> {
        self.ffi_decapsulate_key(session, mechanism, private_key, template, ciphertext)
    }

    // --- PKCS#11 3.0 message init/final overrides ---

    fn message_encrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_message_encrypt_init(session, mechanism, key)
    }

    fn message_encrypt_final(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_message_encrypt_final(session)
    }

    fn message_decrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_message_decrypt_init(session, mechanism, key)
    }

    fn message_decrypt_final(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_message_decrypt_final(session)
    }

    fn message_sign_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_message_sign_init(session, mechanism, key)
    }

    fn message_sign_final(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_message_sign_final(session)
    }

    fn message_verify_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.ffi_message_verify_init(session, mechanism, key)
    }

    fn message_verify_final(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_message_verify_final(session)
    }

    // --- PKCS#11 3.0 message one-shot/begin/next overrides ---

    fn encrypt_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        self.ffi_encrypt_message(session, parameter, aad, plaintext)
    }

    fn encrypt_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: &[u8],
    ) -> CkResult<Vec<u8>> {
        self.ffi_encrypt_message_begin(session, parameter, aad)
    }

    fn encrypt_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        plaintext_part: &[u8],
        flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        self.ffi_encrypt_message_next(session, parameter, plaintext_part, flags)
    }

    fn decrypt_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        self.ffi_decrypt_message(session, parameter, aad, ciphertext)
    }

    fn decrypt_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        aad: &[u8],
    ) -> CkResult<Vec<u8>> {
        self.ffi_decrypt_message_begin(session, parameter, aad)
    }

    fn decrypt_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        ciphertext_part: &[u8],
        flags: CkFlags,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        self.ffi_decrypt_message_next(session, parameter, ciphertext_part, flags)
    }

    fn sign_message(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        data: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        self.ffi_sign_message(session, parameter, data)
    }

    fn sign_message_begin(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
    ) -> CkResult<Vec<u8>> {
        self.ffi_sign_message_begin(session, parameter)
    }

    fn sign_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &mut [u8],
        data_part: &[u8],
        request_signature: bool,
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        self.ffi_sign_message_next(session, parameter, data_part, request_signature)
    }

    fn verify_message(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> CkResult<()> {
        self.ffi_verify_message(session, parameter, data, signature)
    }

    fn verify_message_begin(&self, session: CkSessionHandle, parameter: &[u8]) -> CkResult<()> {
        self.ffi_verify_message_begin(session, parameter)
    }

    fn verify_message_next(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        data_part: &[u8],
        is_final: bool,
        signature: &[u8],
    ) -> CkResult<()> {
        self.ffi_verify_message_next(session, parameter, data_part, is_final, signature)
    }

    // --- PKCS#11 3.2 VerifySignature overrides ---

    fn verify_signature_init(
        &self,
        session: CkSessionHandle,
        mechanism: Option<&CkMechanism>,
        key: CkObjectHandle,
        signature: &[u8],
    ) -> CkResult<()> {
        self.ffi_verify_signature_init(session, mechanism, key, signature)
    }

    fn verify_signature(&self, session: CkSessionHandle, data: &[u8]) -> CkResult<()> {
        self.ffi_verify_signature(session, data)
    }

    fn verify_signature_update(&self, session: CkSessionHandle, data_part: &[u8]) -> CkResult<()> {
        self.ffi_verify_signature_update(session, data_part)
    }

    fn verify_signature_final(&self, session: CkSessionHandle) -> CkResult<()> {
        self.ffi_verify_signature_final(session)
    }

    // --- PKCS#11 3.2 Authenticated wrap overrides ---

    fn wrap_key_authenticated(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: &[u8],
    ) -> CkResult<(Vec<u8>, Vec<u8>)> {
        self.ffi_wrap_key_authenticated(session, mechanism, wrapping_key, key, aad)
    }

    fn unwrap_key_authenticated(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        unwrapping_key: CkObjectHandle,
        wrapped_key: &[u8],
        template: &[CkAttribute],
        aad: &[u8],
    ) -> CkResult<(CkObjectHandle, Vec<u8>)> {
        self.ffi_unwrap_key_authenticated(
            session,
            mechanism,
            unwrapping_key,
            wrapped_key,
            template,
            aad,
        )
    }

    // --- Track C: Exact parameter-output overrides ---

    fn encrypt_message_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.ffi_encrypt_message_exact(
            session,
            parameter,
            aad,
            plaintext,
            output_spec,
            param_out_spec,
        )
    }

    fn decrypt_message_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.ffi_decrypt_message_exact(
            session,
            parameter,
            aad,
            ciphertext,
            output_spec,
            param_out_spec,
        )
    }

    fn sign_message_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        data: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.ffi_sign_message_exact(session, parameter, data, output_spec, param_out_spec)
    }

    fn encrypt_message_next_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        plaintext_part: &[u8],
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.ffi_encrypt_message_next_exact(
            session,
            parameter,
            plaintext_part,
            flags,
            output_spec,
            param_out_spec,
        )
    }

    fn decrypt_message_next_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        ciphertext_part: &[u8],
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.ffi_decrypt_message_next_exact(
            session,
            parameter,
            ciphertext_part,
            flags,
            output_spec,
            param_out_spec,
        )
    }

    fn sign_message_next_exact(
        &self,
        session: CkSessionHandle,
        parameter: &[u8],
        data_part: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.ffi_sign_message_next_exact(session, parameter, data_part, output_spec, param_out_spec)
    }

    fn wrap_key_authenticated_exact(
        &self,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        aad: &[u8],
        output_spec: &CkOutputBufferSpec,
        param_out_spec: &CkParameterRoundtripSpec,
    ) -> CkResult<(CkOutputBufferResult, CkParameterRoundtripResult)> {
        self.ffi_wrap_key_authenticated_exact(
            session,
            mechanism,
            wrapping_key,
            key,
            aad,
            output_spec,
            param_out_spec,
        )
    }

    // --- Structured message parameter variants ---

    fn encrypt_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        aad: &[u8],
        plaintext: &[u8],
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    )> {
        self.ffi_encrypt_message_exact_msg(session, msg_param, aad, plaintext, output_spec)
    }

    fn decrypt_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        aad: &[u8],
        ciphertext: &[u8],
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    )> {
        self.ffi_decrypt_message_exact_msg(session, msg_param, aad, ciphertext, output_spec)
    }

    fn sign_message_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        data: &[u8],
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    )> {
        self.ffi_sign_message_exact_msg(session, msg_param, data, output_spec)
    }

    fn encrypt_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        plaintext_part: &[u8],
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    )> {
        self.ffi_encrypt_message_next_exact_msg(
            session,
            msg_param,
            plaintext_part,
            flags,
            output_spec,
        )
    }

    fn decrypt_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        ciphertext_part: &[u8],
        flags: CkFlags,
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    )> {
        self.ffi_decrypt_message_next_exact_msg(
            session,
            msg_param,
            ciphertext_part,
            flags,
            output_spec,
        )
    }

    fn sign_message_next_exact_msg(
        &self,
        session: CkSessionHandle,
        msg_param: &pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
        data_part: &[u8],
        output_spec: &CkOutputBufferSpec,
    ) -> CkResult<(
        CkOutputBufferResult,
        pkcs11_proxy_ng_proto::convert::message_params::MessageParameter,
    )> {
        self.ffi_sign_message_next_exact_msg(session, msg_param, data_part, output_spec)
    }

    // --- BUG-001: Interface version transparency ---

    fn get_interface_capabilities(&self) -> InterfaceCapabilities {
        self.detect_interface_capabilities()
    }
}
