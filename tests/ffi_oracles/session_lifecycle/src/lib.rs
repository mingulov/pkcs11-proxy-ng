//! Bounded native session lifecycle oracle. This fixture performs no cryptography.
#![allow(non_snake_case, clippy::missing_safety_doc, clippy::unnecessary_cast)]

use std::sync::{Condvar, LazyLock, Mutex};
use types::*;

pub mod provider;
pub mod types;

#[derive(Default)]
struct State {
    initialized: bool,
    logged_in: bool,
    sessions: Vec<SessionV1>,
    events: Vec<EventV1>,
    next_raw: u64,
    next_incarnation: u64,
    next_reuse: Option<u64>,
    close_rvs: Vec<(u64, u64)>,
    random_rv: Option<u64>,
    pending: Vec<u64>,
    gate_session: u64,
    gate_holders: u64,
    overflow: bool,
}

impl State {
    fn fresh() -> Self {
        Self { next_raw: 101, next_incarnation: 1, ..Self::default() }
    }

    fn live(&self, raw: u64) -> Option<SessionV1> {
        self.sessions.iter().rev().find(|s| s.raw == raw && s.live == 1).copied()
    }

    fn record(&mut self, kind: u32, phase: u32, raw: u64, rv: u64, flags: u64) {
        if self.events.len() == MAX_EVENTS {
            self.overflow = true;
            return;
        }
        let incarnation =
            self.sessions.iter().rev().find(|s| s.raw == raw).map_or(0, |s| s.incarnation);
        self.events.push(EventV1 {
            sequence: self.events.len() as u64 + 1,
            kind,
            phase,
            session: raw,
            incarnation,
            rv,
            flags,
        });
    }
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| Mutex::new(State::fresh()));
static RELEASED: Condvar = Condvar::new();

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Full reset refuses initialized, live, or pending work. Release is explicit.
#[unsafe(no_mangle)]
pub extern "C" fn SessionOracle_ResetV1() -> u32 {
    let mut state = state();
    if state.initialized
        || state.sessions.iter().any(|s| s.live != 0)
        || !state.pending.is_empty()
        || state.gate_holders != 0
    {
        return 1;
    }
    *state = State::fresh();
    0
}

/// Observation reset never changes sessions, login, scripts, or gate state.
#[unsafe(no_mangle)]
pub extern "C" fn SessionOracle_ResetObservationV1() -> u32 {
    let mut state = state();
    if !state.pending.is_empty() || state.gate_holders != 0 {
        return 1;
    }
    state.events.clear();
    state.overflow = false;
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn SessionOracle_CommandV1(command: *const CommandV1) -> u32 {
    if command.is_null() {
        return 1;
    }
    let command = unsafe { *command };
    if command.version != VERSION
        || command.size as usize != std::mem::size_of::<CommandV1>()
        || command.reserved != 0
    {
        return 1;
    }
    let mut state = state();
    match command.command {
        SET_CLOSE_RV
            if state.live(command.session).is_some()
                && !state.pending.contains(&command.session)
                && cryptoki_sys::CK_RV::try_from(command.value).is_ok() =>
        {
            state.close_rvs.retain(|(raw, _)| *raw != command.session);
            state.close_rvs.push((command.session, command.value));
        }
        SET_RANDOM_RV if cryptoki_sys::CK_RV::try_from(command.value).is_ok() => {
            state.random_rv = Some(command.value);
        }
        REUSE_NEXT_OPEN
            if state.live(command.session).is_none()
                && !state.pending.contains(&command.session)
                && state.sessions.iter().any(|s| s.raw == command.session && s.live == 0) =>
        {
            state.next_reuse = Some(command.session);
        }
        ARM_CLOSE_GATE
            if state.gate_session == 0
                && state.gate_holders == 0
                && state.live(command.session).is_some() =>
        {
            state.gate_session = command.session;
        }
        RELEASE_CLOSE_GATE => {
            state.gate_session = 0;
            RELEASED.notify_all();
        }
        _ => return 1,
    }
    0
}

/// Caller size is checked before writing the separate V1 observation layout.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SessionOracle_GetObservationV1(
    output: *mut ObservationV1,
    size: u32,
) -> u32 {
    if output.is_null() || size as usize != std::mem::size_of::<ObservationV1>() {
        return 1;
    }
    let state = state();
    let mut observation = ObservationV1 {
        initialized: u32::from(state.initialized),
        logged_in: u32::from(state.logged_in),
        session_count: state.sessions.len() as u32,
        event_count: state.events.len() as u32,
        overflow: u32::from(state.overflow),
        pending_closes: state.pending.len() as u32,
        gate_session: state.gate_session,
        gate_holders: state.gate_holders,
        ..ObservationV1::default()
    };
    observation.sessions[..state.sessions.len()].copy_from_slice(&state.sessions);
    observation.events[..state.events.len()].copy_from_slice(&state.events);
    unsafe { output.write(observation) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki_sys::*;
    use std::time::{Duration, Instant};
    static SERIAL: Mutex<()> = Mutex::new(());

    fn open() -> CK_SESSION_HANDLE {
        let mut session = 0;
        assert_eq!(
            unsafe {
                provider::open_session(
                    1,
                    CKF_SERIAL_SESSION | CKF_RW_SESSION,
                    std::ptr::null_mut(),
                    None,
                    &mut session,
                )
            },
            CKR_OK
        );
        session
    }
    fn command(kind: u32, raw: u64, value: u64) -> u32 {
        unsafe { SessionOracle_CommandV1(&CommandV1::new(kind, raw, value)) }
    }
    fn observe() -> ObservationV1 {
        let mut observation = ObservationV1::default();
        assert_eq!(
            unsafe {
                SessionOracle_GetObservationV1(
                    &mut observation,
                    std::mem::size_of::<ObservationV1>() as u32,
                )
            },
            0
        );
        observation
    }
    fn start() {
        assert_eq!(SessionOracle_ResetV1(), 0);
        assert_eq!(unsafe { provider::initialize(std::ptr::null_mut()) }, CKR_OK);
    }
    fn finish() {
        assert_eq!(unsafe { provider::finalize(std::ptr::null_mut()) }, CKR_OK);
        assert_eq!(SessionOracle_ResetV1(), 0);
    }

    /// Broken settlement: closing a live native session must really retire it.
    #[test]
    fn native_close_retires_session_and_rejects_subsequent_use() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        start();
        let session = open();
        assert_ne!(session, 0);
        assert_eq!(unsafe { provider::close_session(session) }, CKR_OK);
        let mut info = CK_SESSION_INFO::default();
        assert_eq!(
            unsafe { provider::get_session_info(session, &mut info) },
            CKR_SESSION_HANDLE_INVALID
        );
        finish();
    }

    /// An error-returning native close must preserve token login and its session.
    #[test]
    fn transient_native_close_retains_login_and_retry_retires_once() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        start();
        let session = open();
        let mut pin = b"correct-oracle-pin".to_vec();
        assert_eq!(
            unsafe { provider::login(session, CKU_USER, pin.as_mut_ptr(), pin.len() as CK_ULONG) },
            CKR_OK
        );
        assert_eq!(command(SET_CLOSE_RV, session as u64, CKR_FUNCTION_FAILED as u64), 0);
        assert_eq!(unsafe { provider::close_session(session) }, CKR_FUNCTION_FAILED);
        let mut info = CK_SESSION_INFO::default();
        assert_eq!(unsafe { provider::get_session_info(session, &mut info) }, CKR_OK);
        assert_eq!(info.state, CKS_RW_USER_FUNCTIONS);
        assert_eq!(unsafe { provider::close_session(session) }, CKR_OK);
        let observation = observe();
        assert_eq!(
            observation.logged_in, 1,
            "no automatic last-close logout hides missing carrier"
        );
        assert_eq!(
            observation.events[..observation.event_count as usize]
                .iter()
                .filter(|e| e.kind == CLOSE && e.phase == COMPLETED)
                .map(|e| e.rv)
                .collect::<Vec<_>>(),
            vec![CKR_FUNCTION_FAILED as u64, CKR_OK as u64]
        );
        finish();
    }

    /// Reusing a live raw handle would make the reuse test vacuous or invalid.
    #[test]
    fn reuse_requires_retirement_and_mints_a_new_native_incarnation() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        start();
        let first = open();
        assert_eq!(command(REUSE_NEXT_OPEN, first as u64, 0), 1);
        assert_eq!(unsafe { provider::close_session(first) }, CKR_OK);
        assert_eq!(command(REUSE_NEXT_OPEN, first as u64, 0), 0);
        let next = open();
        assert_eq!(next, first);
        let observation = observe();
        assert_eq!(observation.sessions[0].incarnation, 1);
        assert_eq!(observation.sessions[1].incarnation, 2);
        assert_eq!(observation.sessions[0].live, 0);
        assert_eq!(observation.sessions[1].live, 1);
        assert_eq!(unsafe { provider::close_session(next) }, CKR_OK);
        finish();
    }

    /// A held entry must not block observation or let reset destroy pending work.
    #[test]
    fn close_gate_keeps_observers_live_and_reset_refuses_pending_work() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        start();
        let session = open();
        assert_eq!(command(ARM_CLOSE_GATE, session as u64, 0), 0);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let rv = unsafe { provider::close_session(session) };
            let _ = done_tx.send(rv);
        });
        let start = Instant::now();
        while observe().gate_holders != 1 && start.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(1));
        }
        let held = observe();
        let reset = SessionOracle_ResetV1();
        let reset_observation = SessionOracle_ResetObservationV1();
        let reuse = command(REUSE_NEXT_OPEN, session as u64, 0);
        let early = done_rx.try_recv();
        // Release before asserting, so even a broken observer cannot strand a thread.
        assert_eq!(command(RELEASE_CLOSE_GATE, 0, 0), 0);
        let done = done_rx.recv_timeout(Duration::from_secs(2));
        worker.join().unwrap();
        assert_eq!((held.gate_holders, held.pending_closes), (1, 1));
        assert_eq!((reset, reset_observation, reuse), (1, 1, 1));
        assert!(early.is_err());
        assert_eq!(done.unwrap(), CKR_OK);
        assert_eq!(observe().pending_closes, 0);
        finish();
    }

    /// Truncated observations cannot silently pass a supposedly exact trace check.
    #[test]
    fn overflow_is_reported_and_invalid_control_layouts_are_refused() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        start();
        let session = open();
        let mut info = CK_SESSION_INFO::default();
        for _ in 0..MAX_EVENTS {
            assert_eq!(unsafe { provider::get_session_info(session, &mut info) }, CKR_OK);
        }
        assert_eq!(observe().overflow, 1);
        assert_eq!(SessionOracle_ResetV1(), 1);
        assert_eq!(SessionOracle_ResetObservationV1(), 0);
        assert_eq!(observe().overflow, 0);
        let mut wrong = CommandV1::new(SET_RANDOM_RV, 0, CKR_OK as u64);
        wrong.version = 2;
        assert_eq!(unsafe { SessionOracle_CommandV1(&wrong) }, 1);
        assert_eq!(unsafe { SessionOracle_GetObservationV1(std::ptr::null_mut(), 0) }, 1);
        assert_eq!(unsafe { provider::close_session(session) }, CKR_OK);
        finish();
    }
}
