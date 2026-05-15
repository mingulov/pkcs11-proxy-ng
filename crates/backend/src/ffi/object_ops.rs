use super::*;

impl FfiBackend {
    pub(super) fn ffi_find_objects_init(
        &self,
        session: CkSessionHandle,
        template: &[CkAttribute],
    ) -> CkResult<()> {
        let ffi_attrs = FfiAttrs::from_slice(template);
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
        let mut handles = vec![0 as cryptoki_sys::CK_OBJECT_HANDLE; max_count as usize];
        let mut found: cryptoki_sys::CK_ULONG = 0;
        Self::call_unit(unsafe { (*self.func_list).C_FindObjects }, |function| unsafe {
            function(
                Self::session_handle(session),
                handles.as_mut_ptr(),
                max_count as cryptoki_sys::CK_ULONG,
                &mut found,
            )
        })?;
        Ok(handles[..found as usize].iter().map(|&h| CkObjectHandle(h)).collect())
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
        let mut ffi_attrs = FfiAttrs::from_slice(template);
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
        let rv = CkRv(rv);
        Ok((rv, exact_attribute_results_from_ffi(queries, &ffi_queries.attrs, rv)))
    }

    pub(super) fn ffi_create_object(
        &self,
        session: CkSessionHandle,
        template: &[CkAttribute],
    ) -> CkResult<CkObjectHandle> {
        let ffi_attrs = FfiAttrs::from_slice(template);
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
        let ffi_attrs = FfiAttrs::from_slice(template);
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
        let ffi_attrs = FfiAttrs::from_slice(template);
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
