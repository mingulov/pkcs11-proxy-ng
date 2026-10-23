//! Versioned, bounded control ABI. No PIN or request bytes enter observations.
pub const VERSION: u32 = 1;
pub const MAX_SESSIONS: usize = 64;
pub const MAX_EVENTS: usize = 512;
pub const SET_CLOSE_RV: u32 = 1;
pub const SET_RANDOM_RV: u32 = 2;
pub const REUSE_NEXT_OPEN: u32 = 3;
pub const ARM_CLOSE_GATE: u32 = 4;
pub const RELEASE_CLOSE_GATE: u32 = 5;
pub const OPEN: u32 = 1;
pub const CLOSE: u32 = 2;
pub const LOGIN: u32 = 3;
pub const LOGOUT: u32 = 4;
pub const INFO: u32 = 5;
pub const RANDOM: u32 = 6;
pub const CLOSE_ALL: u32 = 7;
pub const ENTRY: u32 = 1;
pub const COMPLETED: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CommandV1 {
    pub version: u32,
    pub size: u32,
    pub command: u32,
    pub reserved: u32,
    pub session: u64,
    pub value: u64,
}

impl CommandV1 {
    pub fn new(command: u32, session: u64, value: u64) -> Self {
        Self {
            version: VERSION,
            size: std::mem::size_of::<Self>() as u32,
            command,
            reserved: 0,
            session,
            value,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionV1 {
    pub raw: u64,
    pub incarnation: u64,
    pub flags: u64,
    pub live: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EventV1 {
    pub sequence: u64,
    pub kind: u32,
    pub phase: u32,
    pub session: u64,
    pub incarnation: u64,
    pub rv: u64,
    pub flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ObservationV1 {
    pub version: u32,
    pub size: u32,
    pub initialized: u32,
    pub logged_in: u32,
    pub session_count: u32,
    pub event_count: u32,
    pub overflow: u32,
    pub pending_closes: u32,
    pub gate_session: u64,
    pub gate_holders: u64,
    pub sessions: [SessionV1; MAX_SESSIONS],
    pub events: [EventV1; MAX_EVENTS],
}

impl Default for ObservationV1 {
    fn default() -> Self {
        Self {
            version: VERSION,
            size: std::mem::size_of::<Self>() as u32,
            initialized: 0,
            logged_in: 0,
            session_count: 0,
            event_count: 0,
            overflow: 0,
            pending_closes: 0,
            gate_session: 0,
            gate_holders: 0,
            sessions: [SessionV1::default(); MAX_SESSIONS],
            events: [EventV1::default(); MAX_EVENTS],
        }
    }
}
