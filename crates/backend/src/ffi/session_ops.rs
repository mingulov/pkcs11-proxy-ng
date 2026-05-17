use super::*;

impl FfiBackend {
    pub(super) fn ffi_get_info(&self) -> CkResult<CkInfo> {
        let mut info = cryptoki_sys::CK_INFO::default();
        Self::call_unit(unsafe { (*self.func_list).C_GetInfo }, |function| unsafe {
            function(&mut info)
        })?;
        Ok(info_from_ck(&info))
    }

    pub(super) fn ffi_get_slot_list(&self, token_present: bool) -> CkResult<Vec<CkSlotId>> {
        let token_present_flag =
            if token_present { cryptoki_sys::CK_TRUE } else { cryptoki_sys::CK_FALSE };
        let slots = Self::call_array::<_, cryptoki_sys::CK_SLOT_ID, _>(
            unsafe { (*self.func_list).C_GetSlotList },
            |function, slots, count| unsafe { function(token_present_flag, slots, count) },
        )?;
        Ok(slots.into_iter().map(CkSlotId).collect())
    }

    pub(super) fn ffi_get_slot_info(&self, slot_id: CkSlotId) -> CkResult<CkSlotInfo> {
        let mut info = cryptoki_sys::CK_SLOT_INFO::default();
        Self::call_unit(unsafe { (*self.func_list).C_GetSlotInfo }, |function| unsafe {
            function(Self::slot_id(slot_id), &mut info)
        })?;
        Ok(slot_info_from_ck(&info))
    }

    pub(super) fn ffi_get_token_info(&self, slot_id: CkSlotId) -> CkResult<CkTokenInfo> {
        let mut info = cryptoki_sys::CK_TOKEN_INFO::default();
        Self::call_unit(unsafe { (*self.func_list).C_GetTokenInfo }, |function| unsafe {
            function(Self::slot_id(slot_id), &mut info)
        })?;
        Ok(token_info_from_ck(&info))
    }

    pub(super) fn ffi_get_mechanism_list(
        &self,
        slot_id: CkSlotId,
    ) -> CkResult<Vec<CkMechanismType>> {
        let mechanisms = Self::call_array::<_, cryptoki_sys::CK_MECHANISM_TYPE, _>(
            unsafe { (*self.func_list).C_GetMechanismList },
            |function, mechanisms, count| unsafe {
                function(Self::slot_id(slot_id), mechanisms, count)
            },
        )?;
        Ok(mechanisms.into_iter().map(CkMechanismType).collect())
    }

    pub(super) fn ffi_get_mechanism_info(
        &self,
        slot_id: CkSlotId,
        mech: CkMechanismType,
    ) -> CkResult<CkMechanismInfo> {
        let mut info = cryptoki_sys::CK_MECHANISM_INFO::default();
        Self::call_unit(unsafe { (*self.func_list).C_GetMechanismInfo }, |function| unsafe {
            function(Self::slot_id(slot_id), mech.0 as cryptoki_sys::CK_MECHANISM_TYPE, &mut info)
        })?;
        Ok(mechanism_info_from_ck(&info))
    }

    pub(super) fn ffi_init_token(
        &self,
        slot_id: CkSlotId,
        so_pin: Option<&[u8]>,
        label: &str,
    ) -> CkResult<()> {
        let mut label_buf = space_pad::<32>(label);
        let (pin_ptr, pin_len) = match so_pin {
            Some(p) => (p.as_ptr() as *mut _, Self::ulong_len(p.len())),
            None => (std::ptr::null_mut(), 0),
        };
        Self::call_unit(unsafe { (*self.func_list).C_InitToken }, |function| unsafe {
            function(Self::slot_id(slot_id), pin_ptr, pin_len, label_buf.as_mut_ptr())
        })
    }

    pub(super) fn ffi_init_pin(
        &self,
        session: CkSessionHandle,
        pin: Option<&[u8]>,
    ) -> CkResult<()> {
        let (pin_ptr, pin_len) = match pin {
            Some(p) => (p.as_ptr() as *mut _, Self::ulong_len(p.len())),
            None => (std::ptr::null_mut(), 0),
        };
        Self::call_unit(unsafe { (*self.func_list).C_InitPIN }, |function| unsafe {
            function(Self::session_handle(session), pin_ptr, pin_len)
        })
    }

    pub(super) fn ffi_set_pin(
        &self,
        session: CkSessionHandle,
        old_pin: Option<&[u8]>,
        new_pin: Option<&[u8]>,
    ) -> CkResult<()> {
        let (old_ptr, old_len) = match old_pin {
            Some(p) => (p.as_ptr() as *mut _, Self::ulong_len(p.len())),
            None => (std::ptr::null_mut(), 0),
        };
        let (new_ptr, new_len) = match new_pin {
            Some(p) => (p.as_ptr() as *mut _, Self::ulong_len(p.len())),
            None => (std::ptr::null_mut(), 0),
        };
        Self::call_unit(unsafe { (*self.func_list).C_SetPIN }, |function| unsafe {
            function(Self::session_handle(session), old_ptr, old_len, new_ptr, new_len)
        })
    }

    pub(super) fn ffi_open_session(
        &self,
        slot_id: CkSlotId,
        flags: CkSessionFlags,
    ) -> CkResult<CkSessionHandle> {
        let handle = Self::call_session_output(
            unsafe { (*self.func_list).C_OpenSession },
            |function, handle| unsafe {
                function(
                    Self::slot_id(slot_id),
                    flags.0 as cryptoki_sys::CK_FLAGS,
                    std::ptr::null_mut(),
                    None,
                    handle,
                )
            },
        )?;
        // Record the session->slot binding so we can drop per-slot
        // `mech_cache` entries in `C_CloseAllSessions`.
        self.remember_session_slot(handle, slot_id);
        Ok(handle)
    }

    pub(super) fn ffi_close_session(&self, session: CkSessionHandle) -> CkResult<()> {
        self.drop_mech_cache(session);
        self.forget_session_slot(session);
        Self::call_unit(unsafe { (*self.func_list).C_CloseSession }, |function| unsafe {
            function(Self::session_handle(session))
        })
    }

    pub(super) fn ffi_close_all_sessions(&self, slot_id: CkSlotId) -> CkResult<()> {
        // Drop our Rust-owned `mech_cache` entries for the slot first; the
        // underlying lib's `C_CloseAllSessions` then invalidates the session
        // handles. Even if the underlying call fails, the application's
        // notion of which sessions are valid is already in disarray.
        self.drop_mech_cache_for_slot(slot_id);
        Self::call_unit(unsafe { (*self.func_list).C_CloseAllSessions }, |function| unsafe {
            function(Self::slot_id(slot_id))
        })
    }

    pub(super) fn ffi_get_session_info(&self, session: CkSessionHandle) -> CkResult<CkSessionInfo> {
        let mut info = cryptoki_sys::CK_SESSION_INFO::default();
        Self::call_unit(unsafe { (*self.func_list).C_GetSessionInfo }, |function| unsafe {
            function(Self::session_handle(session), &mut info)
        })?;
        Ok(session_info_from_ck(&info))
    }

    pub(super) fn ffi_login(
        &self,
        session: CkSessionHandle,
        user_type: CkUserType,
        pin: Option<&[u8]>,
    ) -> CkResult<()> {
        let (pin_ptr, pin_len) = match pin {
            Some(p) => (p.as_ptr() as *mut _, Self::ulong_len(p.len())),
            None => (std::ptr::null_mut(), 0),
        };
        Self::call_unit(unsafe { (*self.func_list).C_Login }, |function| unsafe {
            function(
                Self::session_handle(session),
                user_type as cryptoki_sys::CK_USER_TYPE,
                pin_ptr,
                pin_len,
            )
        })
    }

    pub(super) fn ffi_logout(&self, session: CkSessionHandle) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_Logout }, |function| unsafe {
            function(Self::session_handle(session))
        })
    }

    pub(super) fn ffi_get_function_status(&self, session: CkSessionHandle) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_GetFunctionStatus }, |function| unsafe {
            function(Self::session_handle(session))
        })
    }

    pub(super) fn ffi_cancel_function(&self, session: CkSessionHandle) -> CkResult<()> {
        Self::call_unit(unsafe { (*self.func_list).C_CancelFunction }, |function| unsafe {
            function(Self::session_handle(session))
        })
    }
}
