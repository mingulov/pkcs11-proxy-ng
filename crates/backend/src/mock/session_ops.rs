use pkcs11_proxy_ng_types::*;

use super::{MockBackend, compute_session_state};

impl MockBackend {
    pub(super) fn noop_ok(&self) -> CkResult<()> {
        Ok(())
    }

    pub(super) fn initialize_backend(&self) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        if state.initialized {
            return Err(CkRv::CRYPTOKI_ALREADY_INITIALIZED);
        }
        state.initialized = true;
        Ok(())
    }

    pub(super) fn finalize_backend(&self) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        if !state.initialized {
            return Err(CkRv::CRYPTOKI_NOT_INITIALIZED);
        }
        state.initialized = false;
        state.open_sessions.clear();
        state.login_state.clear();
        state.live_objects.clear();
        state.active_ops.clear();
        Ok(())
    }

    pub(super) fn backend_info(&self) -> CkResult<CkInfo> {
        Ok(CkInfo {
            cryptoki_version: (3, 0),
            manufacturer_id: "MockBackend".into(),
            flags: 0,
            library_description: "Mock PKCS#11 for testing".into(),
            library_version: (0, 1),
        })
    }

    pub(super) fn slot_list(&self) -> CkResult<Vec<CkSlotId>> {
        Ok(self.slots.clone())
    }

    pub(super) fn slot_list_for_presence(&self, token_present: bool) -> CkResult<Vec<CkSlotId>> {
        if token_present {
            Ok(self
                .slots
                .iter()
                .copied()
                .filter(|slot| self.token_present_for_slot(*slot))
                .collect())
        } else {
            self.slot_list()
        }
    }

    pub(super) fn slot_info(&self, slot_id: CkSlotId) -> CkResult<CkSlotInfo> {
        self.check_injected()?;
        self.require_known_slot(slot_id)?;
        let mut flags = CkSlotFlags::HW_SLOT;
        if self.token_present_for_slot(slot_id) {
            flags |= CkSlotFlags::TOKEN_PRESENT;
        }
        Ok(CkSlotInfo {
            slot_description: format!("Mock Slot {}", slot_id.0),
            manufacturer_id: "Mock".into(),
            flags: CkSlotFlags(flags),
            hardware_version: (1, 0),
            firmware_version: (1, 0),
        })
    }

    pub(super) fn token_info(&self, slot_id: CkSlotId) -> CkResult<CkTokenInfo> {
        self.check_injected()?;
        self.require_known_slot(slot_id)?;
        self.require_token_present(slot_id)?;
        Ok(CkTokenInfo {
            label: "MockToken".into(),
            manufacturer_id: "Mock".into(),
            model: "Software".into(),
            serial_number: "0001".into(),
            flags: CkTokenFlags(CkTokenFlags::TOKEN_INITIALIZED),
            max_session_count: 256,
            session_count: 0,
            max_rw_session_count: 256,
            rw_session_count: 0,
            max_pin_len: 64,
            min_pin_len: 4,
            total_public_memory: u64::MAX,
            free_public_memory: u64::MAX,
            total_private_memory: u64::MAX,
            free_private_memory: u64::MAX,
            hardware_version: (1, 0),
            firmware_version: (1, 0),
            utc_time: String::new(),
        })
    }

    pub(super) fn mechanism_list(&self, slot_id: CkSlotId) -> CkResult<Vec<CkMechanismType>> {
        self.check_injected()?;
        self.require_known_slot(slot_id)?;
        self.require_token_present(slot_id)?;
        Ok(self.mechanisms_for_slot(slot_id))
    }

    pub(super) fn mechanism_info(
        &self,
        slot_id: CkSlotId,
        mech: CkMechanismType,
    ) -> CkResult<CkMechanismInfo> {
        self.check_injected()?;
        self.require_known_slot(slot_id)?;
        self.require_token_present(slot_id)?;
        if !self.mechanisms_for_slot(slot_id).contains(&mech) {
            return Err(CkRv::MECHANISM_INVALID);
        }
        Ok(CkMechanismInfo {
            min_key_size: 2048,
            max_key_size: 4096,
            flags: CkMechanismFlags(CkMechanismFlags::SIGN | CkMechanismFlags::VERIFY),
        })
    }

    pub(super) fn open_session_impl(
        &self,
        slot_id: CkSlotId,
        flags: CkSessionFlags,
    ) -> CkResult<CkSessionHandle> {
        self.check_injected()?;
        self.require_known_slot(slot_id)?;
        self.require_token_present(slot_id)?;
        let mut state = self.state.lock().unwrap();
        if self.max_sessions > 0 && state.open_sessions.len() as u64 >= self.max_sessions {
            return Err(CkRv::SESSION_COUNT);
        }
        let handle = CkSessionHandle(state.next_session);
        state.next_session += 1;
        state.open_sessions.push((handle, slot_id, flags));
        Ok(handle)
    }

    pub(super) fn close_session_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        if let Some(pos) = state.open_sessions.iter().position(|(handle, _, _)| *handle == session)
        {
            let (_, slot_id, _) = state.open_sessions.remove(pos);
            state.active_ops.remove(&session.0);
            if !state.open_sessions.iter().any(|(_, open_slot, _)| *open_slot == slot_id) {
                state.login_state.remove(&slot_id);
            }
            Ok(())
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    pub(super) fn close_all_sessions_impl(&self, slot_id: CkSlotId) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        let closing: Vec<u64> = state
            .open_sessions
            .iter()
            .filter(|(_, open_slot, _)| *open_slot == slot_id)
            .map(|(handle, _, _)| handle.0)
            .collect();
        state.open_sessions.retain(|(_, open_slot, _)| *open_slot != slot_id);
        for handle in closing {
            state.active_ops.remove(&handle);
        }
        state.login_state.remove(&slot_id);
        Ok(())
    }

    pub(super) fn session_info(&self, session: CkSessionHandle) -> CkResult<CkSessionInfo> {
        let state = self.state.lock().unwrap();
        if let Some((slot_id, flags)) = state.session_record(session) {
            let login_user = state.login_state.get(&slot_id).copied();
            Ok(CkSessionInfo {
                slot_id,
                state: compute_session_state(flags, login_user),
                flags: CkSessionFlags(flags.0 | CkSessionFlags::SERIAL_SESSION),
                device_error: 0,
            })
        } else {
            Err(CkRv::SESSION_HANDLE_INVALID)
        }
    }

    pub(super) fn login_impl(
        &self,
        session: CkSessionHandle,
        user_type: CkUserType,
    ) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        let slot_id = match state.session_record(session) {
            Some((slot_id, _)) => slot_id,
            None => return Err(CkRv::SESSION_HANDLE_INVALID),
        };
        if state.login_state.contains_key(&slot_id) {
            return Err(CkRv::USER_ALREADY_LOGGED_IN);
        }
        state.login_state.insert(slot_id, user_type);
        Ok(())
    }

    pub(super) fn logout_impl(&self, session: CkSessionHandle) -> CkResult<()> {
        let mut state = self.state.lock().unwrap();
        let slot_id = match state.session_record(session) {
            Some((slot_id, _)) => slot_id,
            None => return Err(CkRv::SESSION_HANDLE_INVALID),
        };
        if state.login_state.remove(&slot_id).is_none() {
            return Err(CkRv::USER_NOT_LOGGED_IN);
        }
        Ok(())
    }

    pub(super) fn wait_for_slot_event_impl(&self) -> CkResult<CkSlotId> {
        match self.slot_event_queue.lock().unwrap().pop_front() {
            Some(slot) => Ok(slot),
            None => Err(CkRv::NO_EVENT),
        }
    }
}
