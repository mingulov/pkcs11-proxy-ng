//! Metadata-only wrap dispatch observations; these are not native FFI counts.
//! Exact-with-output delegates to exact, which records once before validation.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MockWrapEntry {
    Wrap,
    Authenticated,
    Exact,
    AuthenticatedExact,
    UnwrapAuthenticated,
}

#[derive(Clone, Copy)]
pub enum MockWrapAction {
    Return(CkRv),
    Panic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MockWrapObservation {
    pub route: MockWrapEntry,
    pub session: u64,
    pub wrapping_key: u64,
    pub key: u64,
    pub mechanism_type: u64,
    pub embedded_key: Option<u64>,
    pub parameter_present: bool,
    /// (Buffer present, capacity, length pointer NULL).
    pub output: Option<(bool, u64, bool)>,
    /// (Pointer present, length); never bytes.
    pub aad: Option<(bool, u64)>,
}

impl MockBackend {
    pub fn wrap_observations(&self) -> Vec<MockWrapObservation> {
        self.wrap_entries.lock().unwrap().clone()
    }

    /// One-shot result or panic at wrap entry, before validation or state locks.
    pub fn set_wrap_action(&self, action: MockWrapAction) {
        *self.wrap_action.lock().unwrap() = Some(action);
    }

    pub(super) fn record_wrap_entry(
        &self,
        route: MockWrapEntry,
        session: CkSessionHandle,
        mechanism: &CkMechanism,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
        output: Option<&CkOutputBufferSpec>,
        aad: Option<CkInBuf<'_>>,
    ) -> CkResult<()> {
        self.wrap_entries.lock().unwrap().push(MockWrapObservation {
            route,
            session: session.0,
            wrapping_key: wrapping_key.0,
            key: key.0,
            mechanism_type: mechanism.mechanism_type.0,
            embedded_key: match mechanism.params.as_ref() {
                Some(CkMechanismParams::Gostr3410KeyWrap(p)) => Some(p.key_handle),
                _ => None,
            },
            parameter_present: mechanism.params.is_some(),
            output: output.map(|s| (s.buffer_present, s.buffer_len, s.length_pointer_null)),
            aad: aad.map(|a| match a {
                CkInBuf::Bytes(b) => (true, b.len() as u64),
                CkInBuf::Null { len } => (false, len),
            }),
        });
        let action = self.wrap_action.lock().unwrap().take();
        match action {
            Some(MockWrapAction::Return(rv)) if rv != CkRv::OK => Err(rv),
            Some(MockWrapAction::Panic) => panic!("injected wrap failure"),
            _ => Ok(()),
        }
    }
}
