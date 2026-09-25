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
    /// Test-provider seam: create normally, then return an invalid typed
    /// acknowledgment and configure the resulting cleanup outcome.
    pub fn set_authenticated_unwrap_fault(&self, cleanup_rv: CkRv) {
        *self.authenticated_unwrap_fault.lock().unwrap() = Some(cleanup_rv);
    }

    pub fn destroy_call_count(&self) -> usize {
        self.destroy_calls.load(Ordering::SeqCst)
    }

    pub(super) fn authenticated_output(
        &self,
        mechanism: &CkMechanism,
        parameter: Option<&pkcs11_proxy_ng_proto::convert::message_params::MessageParameter>,
    ) -> CkResult<pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput> {
        use pkcs11_proxy_ng_proto::convert::authenticated::{AuthenticatedOutput, validate_input};
        validate_input(mechanism, parameter)?;
        Ok(if let Some(parameter) = parameter {
            AuthenticatedOutput::Message(parameter.clone())
        } else if let Some(CkMechanismParams::Iv(iv)) = &mechanism.params {
            AuthenticatedOutput::Iv(iv.iv.clone())
        } else {
            AuthenticatedOutput::Unchanged
        })
    }
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
