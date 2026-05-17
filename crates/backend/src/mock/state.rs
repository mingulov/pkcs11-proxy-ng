use std::collections::{HashMap, HashSet};

use pkcs11_proxy_ng_types::*;

use super::mock_types::MultiPartOp;

pub(super) struct MockState {
    pub(super) initialized: bool,
    pub(super) next_session: u64,
    pub(super) next_object: u64,
    pub(super) open_sessions: Vec<(CkSessionHandle, CkSlotId, CkSessionFlags)>,
    pub(super) login_state: HashMap<CkSlotId, CkUserType>,
    pub(super) live_objects: HashSet<u64>,
    /// Session object ownership: object handle -> creating session handle.
    ///
    /// Objects absent from this map are token-scoped for mock lifecycle purposes.
    pub(super) session_objects: HashMap<u64, u64>,
    pub(super) active_ops: HashMap<u64, MultiPartOp>,
}

impl MockState {
    /// Start a multi-part operation on a session.
    /// Returns OPERATION_ACTIVE if another operation is already in progress.
    pub(super) fn begin_op(&mut self, session: CkSessionHandle, op: MultiPartOp) -> CkResult<()> {
        if self.active_ops.contains_key(&session.0) {
            return Err(CkRv::OPERATION_ACTIVE);
        }
        self.active_ops.insert(session.0, op);
        Ok(())
    }

    /// Assert an operation of the given type is active; return OPERATION_NOT_INITIALIZED if not.
    pub(super) fn require_op(&self, session: CkSessionHandle, op: MultiPartOp) -> CkResult<()> {
        if !self.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        match self.active_ops.get(&session.0) {
            Some(active) if *active == op => Ok(()),
            _ => Err(CkRv::OPERATION_NOT_INITIALIZED),
        }
    }

    /// End the active operation on a session (called on Final or single-pass).
    pub(super) fn end_op(&mut self, session: CkSessionHandle, op: MultiPartOp) -> CkResult<()> {
        if !self.has_session(session) {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        match self.active_ops.get(&session.0) {
            Some(active) if *active == op => {
                self.active_ops.remove(&session.0);
                Ok(())
            }
            _ => Err(CkRv::OPERATION_NOT_INITIALIZED),
        }
    }

    pub(super) fn cancel_op_if_active(&mut self, session: CkSessionHandle, op: MultiPartOp) {
        if matches!(self.active_ops.get(&session.0), Some(active) if *active == op) {
            self.active_ops.remove(&session.0);
        }
    }

    pub(super) fn session_record(
        &self,
        session: CkSessionHandle,
    ) -> Option<(CkSlotId, CkSessionFlags)> {
        self.open_sessions
            .iter()
            .find(|(handle, _, _)| *handle == session)
            .map(|(_, slot_id, flags)| (*slot_id, *flags))
    }

    pub(super) fn has_session(&self, session: CkSessionHandle) -> bool {
        self.open_sessions.iter().any(|(handle, _, _)| *handle == session)
    }
}

/// Compute the PKCS#11 session state from the session's RO/RW flag and the
/// token-level login state (PKCS#11 §5.4, table of session states).
pub(super) fn compute_session_state(
    flags: CkSessionFlags,
    login_user: Option<CkUserType>,
) -> CkSessionState {
    let is_rw = flags.is_rw();
    match login_user {
        None => {
            if is_rw {
                CkSessionState::RwPublic
            } else {
                CkSessionState::RoPublic
            }
        }
        Some(CkUserType::User) | Some(CkUserType::ContextSpecific) => {
            if is_rw {
                CkSessionState::RwUser
            } else {
                CkSessionState::RoUser
            }
        }
        Some(CkUserType::So) => CkSessionState::RwSo,
    }
}
