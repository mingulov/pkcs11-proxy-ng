//! Small symbolic traces, literal outcomes, and deterministic bounded suffixes.
use super::{
    harness::{DEADLINE, Harness},
    model::*,
    oracle_types::*,
};
use pkcs11_proxy_ng_proto::{CloseSessionRequest, Pkcs11Proxy};
use pkcs11_proxy_ng_types::*;
use std::collections::BTreeSet;
use tonic::Request;

pub const SEEDS: [u64; 3] = [1, 0x5eed, 0xdead_beef];
#[derive(Clone, Copy, Debug)]
pub enum Action {
    Open(u8),
    Login(u8, bool),
    Logout(u8),
    Info(u8),
    Random(u8, CkRv),
    Close(u8, CkRv),
    CloseAll(Option<u8>),
    Reuse(u8, u8),
    CancelClose(u8, CkRv),
}

fn unit(got: CkResult<()>, want: CkRv) -> Result<(), String> {
    let got = got.err().unwrap_or(CkRv::OK);
    require(got == want, format!("exact RV mismatch: expected={want} actual={got}"))
}
fn cursor(harness: &Harness) -> Result<usize, String> {
    let observation = harness.control.observe()?;
    require(
        observation.event_count as usize <= MAX_EVENTS && observation.overflow == 0,
        "native event overflow",
    )?;
    Ok(observation.event_count as usize)
}

async fn info(harness: &mut Harness, model: &Model, lease: &Lease) -> Result<Vec<EventV1>, String> {
    let result = harness.client.get_session_info(CkSessionHandle(lease.virtual_id)).await;
    if !lease.live {
        return match result {
            Err(rv) if rv == CkRv::SESSION_HANDLE_INVALID => Ok(Vec::new()),
            _ => Err(format!("retired S{} did not remain handle-invalid", lease.tag)),
        };
    }
    let info = result.map_err(|rv| format!("live S{} info failed: {rv}", lease.tag))?;
    let state = if model.logged_in { CkSessionState::RwUser } else { CkSessionState::RwPublic };
    require(
        info.state == state && info.slot_id == harness.slot && info.flags.0 == RW_FLAGS,
        format!("S{} native session-info state/slot/flags mismatch", lease.tag),
    )?;
    Ok(vec![model.event(INFO, COMPLETED, lease.raw, CkRv::OK, 0)])
}

async fn random(
    harness: &mut Harness,
    model: &Model,
    lease: &Lease,
    rv: CkRv,
) -> Result<Vec<EventV1>, String> {
    if lease.live {
        harness.control.command(SET_RANDOM_RV, 0, rv.0)?;
    }
    let want = if lease.live { rv } else { CkRv::SESSION_HANDLE_INVALID };
    let result = harness.client.generate_random(CkSessionHandle(lease.virtual_id), 8).await;
    match result {
        Ok(bytes) if want == CkRv::OK => {
            require(
                bytes.expose(|raw| raw == [lease.incarnation as u8; 8]),
                format!("S{} random output was not the exact native incarnation canary", lease.tag),
            )?;
        }
        Err(actual) if actual == want => {}
        _ => {
            return Err(format!("S{} random exact RV/output mismatch; expected={want}", lease.tag));
        }
    }
    Ok(if lease.live { vec![model.event(RANDOM, COMPLETED, lease.raw, rv, 8)] } else { Vec::new() })
}

async fn cancel_close(
    harness: &mut Harness,
    model: &mut Model,
    lease: &Lease,
    rv: CkRv,
    start: usize,
) -> Result<Vec<EventV1>, String> {
    require(
        model.live().len() == 1 && model.logical_login,
        "cancel prefix must have one logged-in member",
    )?;
    harness.control.command(SET_CLOSE_RV, lease.raw, rv.0)?;
    harness.control.command(ARM_CLOSE_GATE, lease.raw, 0)?;
    let service = harness.service.clone();
    let context = harness.client.context_id_opt().ok_or("missing initialized context")?;
    let virtual_id = lease.virtual_id;
    harness.handler = Some(tokio::spawn(async move {
        service
            .close_session(Request::new(CloseSessionRequest {
                client_context_id: context,
                session_handle: virtual_id,
            }))
            .await
    }));
    let held = harness.control.wait("native close entry", |o| o.gate_holders == 1).await?;
    validate_snapshot(&held, &model.native, model.logged_in, 1, 1)?;
    validate_events(&held, start, &[model.event(CLOSE, ENTRY, lease.raw, CkRv::OK, 0)])?;
    let task = harness.handler.as_mut().ok_or("missing close handler")?;
    task.abort();
    let joined =
        tokio::time::timeout(DEADLINE, task).await.map_err(|_| "cancelled handler did not join")?;
    require(
        matches!(joined, Err(ref error) if error.is_cancelled()),
        "actual service future was not cancelled",
    )?;
    harness.handler.take();

    // Preserve current auth/suspended scope: only generic session and batch paths are probed.
    match harness.client.get_session_info(CkSessionHandle(virtual_id)).await {
        Err(error) if error == CkRv::FUNCTION_FAILED => {}
        _ => return Err("suspended info did not remain outcome-ambiguous".into()),
    }
    match harness.client.generate_random(CkSessionHandle(virtual_id), 8).await {
        Err(error) if error == CkRv::FUNCTION_FAILED => {}
        _ => return Err("suspended random did not remain outcome-ambiguous".into()),
    }
    unit(harness.client.close_all_sessions(harness.slot).await, CkRv::FUNCTION_FAILED)?;
    let still_held = harness.control.observe()?;
    validate_events(&still_held, start, &[model.event(CLOSE, ENTRY, lease.raw, CkRv::OK, 0)])?;
    validate_snapshot(&still_held, &model.native, model.logged_in, 1, 1)?;
    harness.control.command(RELEASE_CLOSE_GATE, 0, 0)?;
    let mut expected = model.member_close(lease, rv);
    model.settle_member(lease.tag, rv)?;
    expected.extend(model.last_holder_release());
    harness
        .control
        .wait("native close completion and owned carrier", |o| {
            o.pending_closes == 0
                && o.gate_holders == 0
                && o.event_count as usize >= start + expected.len()
        })
        .await?;
    // Native return precedes logical settlement. Poll without mistaking pending for terminal.
    tokio::time::timeout(DEADLINE, async {
        loop {
            match harness.client.get_session_info(CkSessionHandle(virtual_id)).await {
                Err(error) if error == CkRv::FUNCTION_FAILED => {
                    tokio::task::yield_now().await;
                }
                Err(error) if rv == CkRv::OK && error == CkRv::SESSION_HANDLE_INVALID => {
                    return Ok(());
                }
                Ok(info) if rv == CkRv::FUNCTION_FAILED => {
                    require(
                        info.state == CkSessionState::RwUser
                            && info.slot_id == harness.slot
                            && info.flags.0 == RW_FLAGS,
                        "late transient close lost native login",
                    )?;
                    expected.push(model.event(INFO, COMPLETED, lease.raw, CkRv::OK, 0));
                    return Ok(());
                }
                _ => return Err("late close settled to the wrong visible state".to_string()),
            }
        }
    })
    .await
    .map_err(|_| "late close mapping did not settle")??;
    Ok(expected)
}

pub async fn apply(harness: &mut Harness, model: &mut Model, action: Action) -> Result<(), String> {
    let start = cursor(harness)?;
    let expected = match action {
        Action::Open(tag) | Action::Reuse(_, tag) => {
            let reuse = if let Action::Reuse(old, _) = action {
                let old = model.lease(old)?;
                require(!old.live, "reuse requires a terminal logical member")?;
                let observed = harness.control.observe()?;
                model.validate(&observed)?;
                harness.control.command(REUSE_NEXT_OPEN, old.raw, 0)?;
                Some(old.raw)
            } else {
                None
            };
            let opened = harness
                .client
                .open_session(harness.slot, CkSessionFlags(RW_FLAGS))
                .await
                .map_err(|rv| format!("open S{tag}: {rv}"))?;
            model.open(tag, opened.0, reuse)?
        }
        Action::Login(tag, correct) => {
            let lease = model.lease(tag)?;
            let want = if !lease.live {
                CkRv::SESSION_HANDLE_INVALID
            } else if !correct {
                CkRv::PIN_INCORRECT
            } else if model.logged_in {
                CkRv::USER_ALREADY_LOGGED_IN
            } else {
                CkRv::OK
            };
            let pin: &[u8] = if correct { b"correct-oracle-pin" } else { b"wrong-oracle-pin" };
            unit(
                harness
                    .client
                    .login(CkSessionHandle(lease.virtual_id), CkUserType::User, Some(pin))
                    .await,
                want,
            )?;
            if want == CkRv::OK {
                model.logical_login = true;
                model.logged_in = true;
            }
            if lease.live {
                vec![model.event(LOGIN, COMPLETED, lease.raw, want, 0)]
            } else {
                Vec::new()
            }
        }
        Action::Logout(tag) => {
            let lease = model.lease(tag)?;
            let want = if !lease.live {
                CkRv::SESSION_HANDLE_INVALID
            } else if model.logged_in {
                CkRv::OK
            } else {
                CkRv::USER_NOT_LOGGED_IN
            };
            unit(harness.client.logout(CkSessionHandle(lease.virtual_id)).await, want)?;
            if want == CkRv::OK {
                model.logical_login = false;
                model.logged_in = false;
            }
            if lease.live {
                vec![model.event(LOGOUT, COMPLETED, lease.raw, want, 0)]
            } else {
                Vec::new()
            }
        }
        Action::Info(tag) => {
            let lease = model.lease(tag)?;
            info(harness, model, &lease).await?
        }
        Action::Random(tag, rv) => {
            let lease = model.lease(tag)?;
            random(harness, model, &lease, rv).await?
        }
        Action::Close(tag, rv) => {
            let lease = model.lease(tag)?;
            if lease.live {
                harness.control.command(SET_CLOSE_RV, lease.raw, rv.0)?;
                unit(harness.client.close_session(CkSessionHandle(lease.virtual_id)).await, rv)?;
                let mut expected = model.member_close(&lease, rv);
                model.settle_member(tag, rv)?;
                expected.extend(model.last_holder_release());
                expected
            } else {
                unit(
                    harness.client.close_session(CkSessionHandle(lease.virtual_id)).await,
                    CkRv::SESSION_HANDLE_INVALID,
                )?;
                Vec::new()
            }
        }
        Action::CloseAll(fail) => {
            let members = model.live();
            if let Some(tag) = fail {
                let lease = model.lease(tag)?;
                require(lease.live, "partial batch failure must target a live member")?;
                harness.control.command(SET_CLOSE_RV, lease.raw, CkRv::FUNCTION_FAILED.0)?;
            }
            let want = if fail.is_some() { CkRv::FUNCTION_FAILED } else { CkRv::OK };
            unit(harness.client.close_all_sessions(harness.slot).await, want)?;
            let observation = harness.control.observe()?;
            let count = observation.event_count as usize;
            require(
                count >= start + members.len() * 2 && count <= MAX_EVENTS,
                "partial batch event truncation",
            )?;
            let mut seen = BTreeSet::new();
            let mut expected = Vec::new();
            // Choose only the permitted member order; every pair's semantics remain exact.
            for index in 0..members.len() {
                let entry = &observation.events[start + index * 2];
                let member = members
                    .iter()
                    .find(|l| l.raw == entry.session)
                    .ok_or("batch closed a native non-member")?;
                require(seen.insert(member.raw), "batch closed one native member twice")?;
                let rv = if fail == Some(member.tag) { CkRv::FUNCTION_FAILED } else { CkRv::OK };
                expected.extend(model.member_close(member, rv));
            }
            require(seen.len() == members.len(), "batch omitted a native member")?;
            for member in members {
                model.settle_member(
                    member.tag,
                    if fail == Some(member.tag) { CkRv::FUNCTION_FAILED } else { CkRv::OK },
                )?;
            }
            expected.extend(model.last_holder_release());
            expected
        }
        Action::CancelClose(tag, rv) => {
            let lease = model.lease(tag)?;
            cancel_close(harness, model, &lease, rv, start).await?
        }
    };
    let observation = harness.control.observe()?;
    validate_events(&observation, start, &expected)?;
    model.validate(&observation)?;
    // Check every logical lease through the public client, including stale ids after raw reuse.
    for lease in model.leases.clone() {
        let before = cursor(harness)?;
        let expected = info(harness, model, &lease).await?;
        validate_events(&*harness.control.observe()?, before, &expected)?;
    }
    Ok(())
}

pub fn suffix(model: &Model, rng: &mut u64) -> Action {
    *rng ^= *rng << 13;
    *rng ^= *rng >> 7;
    *rng ^= *rng << 17;
    let live = model.live();
    if live.is_empty() {
        return Action::Open(model.next_tag());
    }
    let lease = &live[(*rng >> 8) as usize % live.len()];
    match *rng % 8 {
        0 if live.len() < 3 => Action::Open(model.next_tag()),
        1 => Action::Login(lease.tag, *rng & 16 != 0),
        2 => Action::Logout(lease.tag),
        3 => Action::Info(model.leases[(*rng >> 16) as usize % model.leases.len()].tag),
        4 => Action::Random(
            lease.tag,
            [CkRv::OK, CkRv::ARGUMENTS_BAD, CkRv::OPERATION_NOT_INITIALIZED, CkRv::FUNCTION_FAILED]
                [(*rng >> 16) as usize % 4],
        ),
        5 => {
            Action::Close(lease.tag, if *rng & 16 == 0 { CkRv::OK } else { CkRv::FUNCTION_FAILED })
        }
        6 => Action::CloseAll(if *rng & 16 == 0 { None } else { Some(lease.tag) }),
        7 if live.len() < 3 => {
            match model
                .leases
                .iter()
                .rev()
                .find(|l| !l.live && !live.iter().any(|other| other.raw == l.raw))
            {
                Some(old) => Action::Reuse(old.tag, model.next_tag()),
                None => Action::Random(lease.tag, CkRv::OK),
            }
        }
        _ => Action::Info(lease.tag),
    }
}

pub struct Replay {
    pub seeds: Vec<u64>,
    pub prefix: Option<usize>,
    pub selected: bool,
}
impl Replay {
    pub fn read() -> Result<Self, String> {
        fn selector(name: &str) -> Result<Option<String>, String> {
            match std::env::var(name) {
                Ok(value) => Ok(Some(value)),
                Err(std::env::VarError::NotPresent) => Ok(None),
                Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} is not UTF-8")),
            }
        }
        let seed = selector("PKCS11_PROXY_SEQUENCE_SEED")?;
        let prefix = selector("PKCS11_PROXY_SEQUENCE_PREFIX")?;
        require(prefix.is_none() || seed.is_some(), "prefix replay requires an explicit seed")?;
        let seeds = if let Some(seed) = seed.as_ref() {
            let parsed = if let Some(hex) = seed.strip_prefix("0x") {
                u64::from_str_radix(hex, 16)
            } else {
                seed.parse()
            }
            .map_err(|_| "replay seed must be a u64")?;
            vec![parsed]
        } else {
            SEEDS.to_vec()
        };
        let prefix = prefix
            .map(|value| value.parse::<usize>().map_err(|_| "replay prefix must be an integer"))
            .transpose()?;
        require(
            prefix.is_none_or(|value| value > 0 && value <= 64),
            "replay prefix must be 1..=64",
        )?;
        Ok(Self { seeds, prefix, selected: seed.is_some() })
    }
}

#[derive(Debug)]
pub struct TraceStats {
    pub actions: usize,
    pub max_live: usize,
    pub native_events: usize,
}

pub async fn run_trace(
    prefix: &[Action],
    seed: u64,
    limit: Option<usize>,
) -> Result<TraceStats, String> {
    require(prefix.len() + 16 <= 64, "trace exceeds diagnostic bound")?;
    require(
        limit.is_none_or(|limit| limit <= prefix.len() + 16),
        "replay prefix exceeds this trace",
    )?;
    let mut harness = Harness::start().await?;
    let mut model = Model::new();
    let mut rng = seed;
    let mut trace = Vec::new();
    let mut max_live = 0;
    let count = limit.unwrap_or(prefix.len() + 16);
    let result = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        for step in 0..count {
            let action = if step < prefix.len() { prefix[step] } else { suffix(&model, &mut rng) };
            trace.push(action);
            apply(&mut harness, &mut model, action)
                .await
                .map_err(|error| format!("seed={seed:#x} step={step} prefix={trace:?}: {error}"))?;
            max_live = max_live.max(model.live().len());
        }
        let observation = harness.control.observe()?;
        Ok(TraceStats {
            actions: trace.len(),
            max_live,
            native_events: observation.event_count as usize,
        })
    })
    .await
    .unwrap_or_else(|_| Err(format!("seed={seed:#x} prefix={trace:?}: trace exceeded 15 seconds")));
    let cleanup = harness.finish().await;
    match (result, cleanup) {
        (Ok(stats), Ok(())) => Ok(stats),
        (Err(error), Ok(())) => Err(error),
        (result, Err(cleanup)) => {
            Err(format!("sequence={result:?}; checked cleanup failed: {cleanup}"))
        }
    }
}
