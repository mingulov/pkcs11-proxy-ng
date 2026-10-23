//! Expected native effects are hand specified here, without product map helpers.
use super::oracle_types::*;
use pkcs11_proxy_ng_types::{CkRv, CkSessionFlags};

pub const RW_FLAGS: u64 = CkSessionFlags::SERIAL_SESSION.0 | CkSessionFlags::RW_SESSION.0;
pub const RO_FLAGS: u64 = CkSessionFlags::SERIAL_SESSION.0;

pub fn require(condition: bool, message: impl Into<String>) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message.into()) }
}

pub fn validate_snapshot(
    observation: &ObservationV1,
    sessions: &[SessionV1],
    logged_in: bool,
    pending: u32,
    holders: u64,
) -> Result<(), String> {
    require(
        observation.version == VERSION
            && observation.size as usize == std::mem::size_of::<ObservationV1>(),
        "native observation ABI mismatch",
    )?;
    require(
        observation.overflow == 0
            && observation.event_count as usize <= MAX_EVENTS
            && observation.session_count as usize <= MAX_SESSIONS,
        "native observation overflow",
    )?;
    require(
        observation.session_count as usize == sessions.len(),
        "native session history count mismatch",
    )?;
    require(
        &observation.sessions[..sessions.len()] == sessions,
        "native session settlement mismatch",
    )?;
    require(
        observation.initialized == 1 && observation.logged_in == u32::from(logged_in),
        "native login/lifecycle mismatch",
    )?;
    require(
        observation.pending_closes == pending && observation.gate_holders == holders,
        "native close ownership mismatch",
    )?;
    for (index, event) in observation.events[..observation.event_count as usize].iter().enumerate()
    {
        require(event.sequence == index as u64 + 1, "native observation sequence gap")?;
    }
    Ok(())
}

pub fn validate_events(
    observation: &ObservationV1,
    cursor: usize,
    expected: &[EventV1],
) -> Result<(), String> {
    require(
        observation.overflow == 0 && observation.event_count as usize <= MAX_EVENTS,
        "native event overflow",
    )?;
    require(
        observation.event_count as usize == cursor + expected.len(),
        format!(
            "native event count mismatch: cursor={cursor} expected={} observed={}",
            expected.len(),
            observation.event_count
        ),
    )?;
    for (actual, expected) in
        observation.events[cursor..cursor + expected.len()].iter().zip(expected)
    {
        let actual = EventV1 { sequence: 0, ..*actual };
        require(
            actual == *expected,
            format!("native event mismatch: expected={expected:?} actual={actual:?}"),
        )?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Lease {
    pub tag: u8,
    pub virtual_id: u64,
    pub raw: u64,
    pub incarnation: u64,
    pub live: bool,
}

#[derive(Default)]
pub struct Model {
    pub leases: Vec<Lease>,
    pub native: Vec<SessionV1>,
    pub logged_in: bool,
    pub logical_login: bool,
    next_raw: u64,
    next_incarnation: u64,
}

impl Model {
    pub fn new() -> Self {
        Self { next_raw: 101, next_incarnation: 1, ..Self::default() }
    }
    pub fn lease(&self, tag: u8) -> Result<Lease, String> {
        self.leases
            .iter()
            .find(|l| l.tag == tag)
            .cloned()
            .ok_or_else(|| format!("unknown tag S{tag}"))
    }
    pub fn live(&self) -> Vec<Lease> {
        self.leases.iter().filter(|l| l.live).cloned().collect()
    }
    pub fn next_tag(&self) -> u8 {
        self.leases.iter().map(|l| l.tag).max().map_or(0, |tag| tag + 1)
    }
    pub fn event(&self, kind: u32, phase: u32, raw: u64, rv: CkRv, flags: u64) -> EventV1 {
        EventV1 {
            sequence: 0,
            kind,
            phase,
            session: raw,
            rv: rv.0,
            flags,
            incarnation: self
                .native
                .iter()
                .rev()
                .find(|s| s.raw == raw)
                .map_or(0, |s| s.incarnation),
        }
    }
    fn native_open(&mut self, raw: Option<u64>, flags: u64) -> SessionV1 {
        let raw = raw.unwrap_or_else(|| {
            let raw = self.next_raw;
            self.next_raw += 1;
            raw
        });
        let session =
            SessionV1 { raw, incarnation: self.next_incarnation, flags, live: 1, reserved: 0 };
        self.next_incarnation += 1;
        self.native.push(session);
        session
    }
    pub fn open(
        &mut self,
        tag: u8,
        virtual_id: u64,
        reuse: Option<u64>,
    ) -> Result<Vec<EventV1>, String> {
        require(
            virtual_id != 0 && !self.leases.iter().any(|l| l.virtual_id == virtual_id),
            "new native incarnation reused an old virtual handle",
        )?;
        require(
            self.live().len() < 3 && !self.leases.iter().any(|l| l.tag == tag),
            "lease bound exceeded",
        )?;
        let native = self.native_open(reuse, RW_FLAGS);
        self.leases.push(Lease {
            tag,
            virtual_id,
            raw: native.raw,
            incarnation: native.incarnation,
            live: true,
        });
        Ok(vec![self.event(OPEN, COMPLETED, native.raw, CkRv::OK, RW_FLAGS)])
    }
    pub fn member_close(&self, lease: &Lease, rv: CkRv) -> Vec<EventV1> {
        vec![
            self.event(CLOSE, ENTRY, lease.raw, CkRv::OK, 0),
            self.event(CLOSE, COMPLETED, lease.raw, rv, 0),
        ]
    }
    pub fn settle_member(&mut self, tag: u8, rv: CkRv) -> Result<(), String> {
        require(rv == CkRv::OK || rv == CkRv::FUNCTION_FAILED, "unsupported close model RV")?;
        if rv == CkRv::OK {
            let lease = self.leases.iter_mut().find(|l| l.tag == tag).ok_or("missing lease")?;
            lease.live = false;
            let native = self
                .native
                .iter_mut()
                .rev()
                .find(|s| s.raw == lease.raw && s.live == 1)
                .ok_or("missing native lease")?;
            native.live = 0;
        }
        Ok(())
    }
    pub fn last_holder_release(&mut self) -> Vec<EventV1> {
        if !self.logical_login || !self.live().is_empty() {
            return Vec::new();
        }
        self.logical_login = false;
        let carrier = self.native_open(None, RO_FLAGS);
        let events = vec![
            self.event(OPEN, COMPLETED, carrier.raw, CkRv::OK, RO_FLAGS),
            self.event(LOGOUT, COMPLETED, carrier.raw, CkRv::OK, 0),
            self.event(CLOSE, ENTRY, carrier.raw, CkRv::OK, 0),
            self.event(CLOSE, COMPLETED, carrier.raw, CkRv::OK, 0),
        ];
        self.native.last_mut().expect("just opened carrier").live = 0;
        self.logged_in = false;
        events
    }
    pub fn validate(&self, observation: &ObservationV1) -> Result<(), String> {
        validate_snapshot(observation, &self.native, self.logged_in, 0, 0)?;
        require(observation.gate_session == 0, "gate retained after settled action")
    }
}

#[cfg(test)]
mod sensitivity {
    use super::*;

    /// Missing native completion must not be accepted as a complete member close.
    #[test]
    fn missing_member_completion_is_rejected() {
        let mut observation = ObservationV1 { event_count: 2, ..Default::default() };
        let expected = [
            EventV1 { kind: CLOSE, phase: ENTRY, session: 101, ..Default::default() },
            EventV1 { kind: CLOSE, phase: COMPLETED, session: 101, ..Default::default() },
        ];
        observation.events[0] = EventV1 { sequence: 1, ..expected[0] };
        observation.events[1] = EventV1 { sequence: 2, ..expected[1] };
        assert!(
            validate_events(&observation, 0, &expected).is_ok(),
            "positive complete-close control failed"
        );
        observation.event_count = 1;
        let result = validate_events(&observation, 0, &expected);
        assert!(result.is_err(), "missing native close completion was accepted");
    }

    /// Wrong settlement observation: a transient close must retain its native lease.
    #[test]
    fn transient_close_retirement_is_rejected() {
        let expected =
            SessionV1 { raw: 101, incarnation: 1, flags: RW_FLAGS, live: 1, reserved: 0 };
        let mut observation =
            ObservationV1 { initialized: 1, session_count: 1, ..Default::default() };
        observation.sessions[0] = SessionV1 { live: 0, ..expected };
        assert!(
            validate_snapshot(
                &ObservationV1 {
                    sessions: {
                        let mut sessions = [SessionV1::default(); MAX_SESSIONS];
                        sessions[0] = expected;
                        sessions
                    },
                    ..observation
                },
                &[expected],
                false,
                0,
                0
            )
            .is_ok(),
            "positive live-lease control failed"
        );
        let result = validate_snapshot(&observation, &[expected], false, 0, 0);
        assert!(result.is_err(), "retired transient-close native lease was accepted");
    }
}
