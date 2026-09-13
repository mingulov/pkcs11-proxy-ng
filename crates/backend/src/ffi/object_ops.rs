use super::*;

/// Upper bound on the number of object handles a single `C_FindObjects` call
/// may allocate, mirroring the array cap in `call_helpers` (512 MiB worth of
/// `CK_OBJECT_HANDLE`). PKCS#11 permits returning fewer than `ulMaxObjectCount`
/// per call, so a caller wanting more simply calls `C_FindObjects` again.
pub(super) const MAX_FIND_OBJECTS_PER_CALL: usize = super::call_helpers::MAX_OUTPUT_BUFFER_BYTES
    as usize
    / std::mem::size_of::<cryptoki_sys::CK_OBJECT_HANDLE>();

/// Clamp a client-supplied `ulMaxObjectCount` to a bounded allocation size so
/// one request cannot drive a multi-GB allocation in the shared daemon.
pub(super) fn cap_find_objects_count(max_count: u32) -> usize {
    (max_count as usize).min(MAX_FIND_OBJECTS_PER_CALL)
}

impl FfiBackend {
    pub(super) fn ffi_find_objects_init(
        &self,
        session: CkSessionHandle,
        template: &[CkAttribute],
    ) -> CkResult<()> {
        let ffi_attrs = FfiAttrs::from_slice(template)?;
        let ck_attrs = &ffi_attrs.attrs;
        Self::call_unit(unsafe { (*self.func_list).C_FindObjectsInit }, |function| unsafe {
            function(
                Self::session_handle(session),
                ck_attrs.as_ptr() as *mut _,
                Self::ulong_len(ck_attrs.len()),
            )
        })
    }

    pub(super) fn ffi_find_objects(
        &self,
        session: CkSessionHandle,
        max_count: u32,
    ) -> CkResult<Vec<CkObjectHandle>> {
        let cap = cap_find_objects_count(max_count);
        let mut handles = vec![0 as cryptoki_sys::CK_OBJECT_HANDLE; cap];
        let mut found: cryptoki_sys::CK_ULONG = 0;
        Self::call_unit(unsafe { (*self.func_list).C_FindObjects }, |function| unsafe {
            function(
                Self::session_handle(session),
                handles.as_mut_ptr(),
                cap as cryptoki_sys::CK_ULONG,
                &mut found,
            )
        })?;
        // A conformant backend writes at most `cap` handles; clamp `found`
        // defensively so a buggy backend cannot drive an out-of-bounds slice.
        let n = (found as usize).min(cap);
        Ok(handles[..n].iter().map(|&h| CkObjectHandle(h as u64)).collect())
    }

    pub(super) fn ffi_find_objects_final(&self, session: CkSessionHandle) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_FindObjectsFinal }, |function| unsafe {
            function(Self::session_handle(session))
        })
    }

    pub(super) fn ffi_get_attribute_value(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &mut [CkAttribute],
    ) -> CkResult<()> {
        let mut ffi_attrs = FfiAttrs::from_slice(template)?;
        let rv =
            Self::call_raw(unsafe { (*self.func_list).C_GetAttributeValue }, |function| unsafe {
                function(
                    Self::session_handle(session),
                    Self::object_handle(object),
                    ffi_attrs.attrs.as_mut_ptr(),
                    Self::ulong_len(ffi_attrs.attrs.len()),
                )
            })?;
        update_template_from_ffi(template, &ffi_attrs.attrs);
        Self::ck_result(rv)
    }

    pub(super) fn ffi_get_attribute_value_exact(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        queries: &[CkAttributeQuery],
    ) -> CkResult<(CkRv, Vec<CkAttributeQueryResult>)> {
        let mut ffi_queries = FfiAttributeQueries::from_queries(queries)?;
        let rv =
            Self::call_raw(unsafe { (*self.func_list).C_GetAttributeValue }, |function| unsafe {
                function(
                    Self::session_handle(session),
                    Self::object_handle(object),
                    ffi_queries.attrs.as_mut_ptr(),
                    Self::ulong_len(ffi_queries.attrs.len()),
                )
            })?;
        let rv = CkRv(rv as u64);
        Ok((rv, ffi_queries.readback(queries, rv)))
    }

    pub(super) fn ffi_create_object(
        &self,
        session: CkSessionHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let ffi_attrs = FfiAttrs::from_slice(template)?;
        Self::call_object_output(
            unsafe { (*self.func_list).C_CreateObject },
            |function, handle| unsafe {
                function(
                    Self::session_handle(session),
                    Self::ffi_attr_ptr(&ffi_attrs),
                    Self::ffi_attr_len(&ffi_attrs),
                    handle,
                )
            },
        )
    }

    pub(super) fn ffi_copy_object(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let ffi_attrs = FfiAttrs::from_slice(template)?;
        Self::call_object_output(
            unsafe { (*self.func_list).C_CopyObject },
            |function, new_handle| unsafe {
                function(
                    Self::session_handle(session),
                    Self::object_handle(object),
                    Self::ffi_attr_ptr(&ffi_attrs),
                    Self::ffi_attr_len(&ffi_attrs),
                    new_handle,
                )
            },
        )
    }

    pub(super) fn ffi_destroy_object(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_DestroyObject }, |function| unsafe {
            function(Self::session_handle(session), Self::object_handle(object))
        })
    }

    pub(super) fn ffi_get_object_size(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> CkResult<u64> {
        Self::call_ulong_output(
            unsafe { (*self.func_list).C_GetObjectSize },
            |function, size| unsafe {
                function(Self::session_handle(session), Self::object_handle(object), size)
            },
        )
    }

    pub(super) fn ffi_set_attribute_value(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &[CkAttribute],
    ) -> CkResult<()> {
        let ffi_attrs = FfiAttrs::from_slice(template)?;
        Self::call_unit(unsafe { (*self.func_list).C_SetAttributeValue }, |function| unsafe {
            function(
                Self::session_handle(session),
                Self::object_handle(object),
                Self::ffi_attr_ptr(&ffi_attrs),
                Self::ffi_attr_len(&ffi_attrs),
            )
        })
    }
}

#[cfg(test)]
mod find_objects_cap_tests {
    use super::{MAX_FIND_OBJECTS_PER_CALL, cap_find_objects_count};

    #[test]
    fn caps_absurd_count_to_bound() {
        // A malicious uint32 (~4.29 billion handles ≈ 34 GB) must be clamped.
        assert_eq!(cap_find_objects_count(u32::MAX), MAX_FIND_OBJECTS_PER_CALL);
    }

    #[test]
    fn passes_through_reasonable_count() {
        assert_eq!(cap_find_objects_count(10), 10);
        assert_eq!(cap_find_objects_count(0), 0);
    }

    #[test]
    fn bound_is_a_tiny_fraction_of_u32_max() {
        assert!(MAX_FIND_OBJECTS_PER_CALL < u32::MAX as usize);
        assert_eq!(
            MAX_FIND_OBJECTS_PER_CALL,
            512 * 1024 * 1024 / std::mem::size_of::<cryptoki_sys::CK_OBJECT_HANDLE>()
        );
    }
}
