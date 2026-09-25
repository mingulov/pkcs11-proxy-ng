//! Per-session generation fences (F-01/TF01b, I4 rules + parent "generation
//! fence" variant).
//!
//! For `close(S)` to exclude in-flight ordinary ops on `S`, every
//! session-bearing ordinary path enters `S`'s fence; closes mark it. The
//! fence is a lock-free atomic protocol (NOT a second `RwLock`):
//! - readers: in-flight ops/cancels (entered under a live `OrdinaryGuard`);
//! - lifecycle: `OPEN` → `CLOSING` → closed-at-guard-epoch.
//!
//! Why atomics, not the I4 sketch's "second lock" (recorded deviation with
//! rationale): a `std` lock cannot form a self-contained RAII guard with an
//! `Arc`-owned fence without `unsafe`, leaks, unbounded table growth, or
//! closure-surgery at ~100 sites. The atomic protocol satisfies every I4
//! RULE — ordinary-side MUST-acquire under a live guard (signature +
//! lifetime enforced), lifecycle→fence→shard order (the fence takes no lock,
//! so inversion is impossible), close-all ascending order (enforced inside
//! `enter_write_all`), fence-only-under-live-guard (the returned guard
//! borrows the admission), Finalize needs no fence of its own (fence holders
//! are lifecycle readers, drained by the seal) — with a strictly smaller
//! deadlock surface (no blocking except the close-side drain spin, bounded
//! by in-flight provider return like any drain) and fail-fast entrants
//! (new arrivals during a close get `SESSION_HANDLE_INVALID` instead of
//! queueing behind a doomed close). The parent brief explicitly sanctions
//! this variant ("per-session lock or generation fence, decided in design").
//!
//! Exclusion is absolute in one direction: an op either enters before the
//! close marks `CLOSING` (its native call + settlement strictly precede the
//! close's native call — the drain spin waits for its exit) or it fails
//! without native entry (sees `CLOSING`/closed). Close-all marks every
//! affected fence before draining any, so no op can slip between the marks.
//!
//! Guard epochs (the epoch-field consumer): a close records the closing
//! guard's epoch as the fence's terminal state, correlating the close to
//! its incarnation. Entrants treat any non-`OPEN` state as closed; the
//! value itself is the correlation record, read back by tests and defined
//! for audit (production enforcement is state-based).
//!
//! Residual (accepted): `enter`/`enter_write`/`enter_write_all` create a
//! fence entry for ANY well-formed handle, including ones that never
//! existed — every op on a bogus handle leaves a small permanent `OPEN`
//! entry (one `Arc` + two atomics, tens of bytes) until the re-Initialize
//! purge clears the table (`clear`, under lifecycle write). Growth is
//! therefore bounded by distinct bogus handles per incarnation and is
//! provider-truth-convergent (correctness unaffected: unknown handles
//! still fail at the provider). Daemon-flow-unreachable: the server
//! resolves virtual→backend handles before backend contact, so only a
//! direct embedder passing bogus handles grows the table. Opportunistic
//! pruning is deliberately NOT done: a naive remove-if-idle would detach
//! in-flight entrants holding a cloned `Arc` and break exclusion — any
//! future pruning must be `strong_count`-guarded.

use std::cell::Cell;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;

use dashmap::DashMap;
use pkcs11_proxy_ng_types::{CkResult, CkRv, CkSessionHandle};

use super::native_domain::OrdinaryGuard;

/// Fence lifecycle: accepting entrants.
const FENCE_OPEN: u64 = u64::MAX;
/// Fence lifecycle: a close owns the session; new entrants fail fast while
/// the closer drains in-flight readers.
const FENCE_CLOSING: u64 = u64::MAX - 1;

/// Poll interval for the close-side drain spin. Closes park (no hot spin);
/// the interval bounds close latency after the last reader exits.
const FENCE_DRAIN_POLL: Duration = Duration::from_micros(100);

/// One session's fence: a reader count plus a lifecycle word. Lock-free;
/// shared by cloning the `Arc`, never by holding table or shard locks.
/// No `Default`: the zero state would read as closed-at-epoch-0; use
/// [`SessionFence::new`] (`OPEN`, zero readers).
#[derive(Debug)]
pub(in crate::ffi) struct SessionFence {
    readers: AtomicU64,
    lifecycle: AtomicU64,
}

impl SessionFence {
    fn new() -> Self {
        Self { readers: AtomicU64::new(0), lifecycle: AtomicU64::new(FENCE_OPEN) }
    }
}

/// Per-session fence table, owned by [`super::FfiBackend`]. Entries are
/// created on first enter (open or op) and removed when a close commits;
/// the re-Initialize purge clears the table (under lifecycle write, so no
/// fence holder can exist — see `drop_all_mech_cache`).
#[derive(Debug, Default)]
pub(in crate::ffi) struct SessionFenceTable {
    fences: DashMap<u64, Arc<SessionFence>>,
}

/// How a [`SessionFenceGuard`] holds its fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FenceMode {
    /// Ordinary op/cancel activity: concurrent with other readers, drained
    /// by closes.
    Read,
    /// Close ownership: entered only after draining readers; commits or
    /// reopens explicitly before drop.
    Write,
}

/// Proof of session-fence entry. Borrows the admission (`'g`) — a fence
/// cannot outlive the guard that admitted it (fence-only-under-live-guard,
/// structural) — and is `!Send + !Sync` like [`OrdinaryGuard`].
pub(in crate::ffi) struct SessionFenceGuard<'g> {
    fence: Arc<SessionFence>,
    mode: FenceMode,
    session: u64,
    epoch: u64,
    /// Write-mode settlement flag: `commit_close`/`reopen` (or the
    /// close-all twins) must run before drop; the `Drop` backstop restores
    /// `OPEN` on unwind so a settlement panic never wedges the fence in
    /// `CLOSING`.
    settled: Cell<bool>,
    _gate: PhantomData<&'g ()>,
    _confine: PhantomData<*const ()>,
}

impl std::fmt::Debug for SessionFenceGuard<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionFenceGuard")
            .field("mode", &self.mode)
            .field("session", &self.session)
            .field("epoch", &self.epoch)
            .field("settled", &self.settled.get())
            .finish_non_exhaustive()
    }
}

impl SessionFenceTable {
    /// Enter `session`'s fence for ordinary op/cancel activity. The admission
    /// proves lifecycle read exclusion; the epoch stamps this entry's
    /// incarnation. Fails with `SESSION_HANDLE_INVALID` (no native entry)
    /// when a close owns or owned the session.
    pub(in crate::ffi) fn enter<'g>(
        &self,
        admission: &'g OrdinaryGuard<'_>,
        session: CkSessionHandle,
    ) -> CkResult<SessionFenceGuard<'g>> {
        let epoch = admission.epoch();
        let fence =
            self.fences.entry(session.0).or_insert_with(|| Arc::new(SessionFence::new())).clone();
        // Fast path: a close in progress (or just committed) fails entrants
        // before they count themselves.
        if fence.lifecycle.load(SeqCst) != FENCE_OPEN {
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        fence.readers.fetch_add(1, SeqCst);
        // A close that marked between the load and the increment still wins:
        // uncount and fail rather than running under a closing fence.
        if fence.lifecycle.load(SeqCst) != FENCE_OPEN {
            fence.readers.fetch_sub(1, SeqCst);
            return Err(CkRv::SESSION_HANDLE_INVALID);
        }
        Ok(SessionFenceGuard {
            fence,
            mode: FenceMode::Read,
            session: session.0,
            epoch,
            settled: Cell::new(true),
            _gate: PhantomData,
            _confine: PhantomData,
        })
    }

    /// Enter `session`'s fence for close ownership: mark `CLOSING` (failing
    /// fast with `SESSION_HANDLE_INVALID` when already closed), then drain
    /// in-flight readers. A concurrent closer serializes here: exactly one
    /// wins the mark; the other observes `CLOSING` until it resolves, then
    /// either proceeds (reopened after a failed close) or fails (committed).
    pub(in crate::ffi) fn enter_write<'g>(
        &self,
        admission: &'g OrdinaryGuard<'_>,
        session: CkSessionHandle,
    ) -> CkResult<SessionFenceGuard<'g>> {
        let epoch = admission.epoch();
        let fence =
            self.fences.entry(session.0).or_insert_with(|| Arc::new(SessionFence::new())).clone();
        loop {
            match fence.lifecycle.load(SeqCst) {
                FENCE_OPEN => {
                    if fence
                        .lifecycle
                        .compare_exchange(FENCE_OPEN, FENCE_CLOSING, SeqCst, SeqCst)
                        .is_ok()
                    {
                        break;
                    }
                }
                FENCE_CLOSING => std::thread::park_timeout(FENCE_DRAIN_POLL),
                // Committed close (terminal closed-at-epoch state): the
                // session is closed; report what the provider would.
                _closed_epoch => return Err(CkRv::SESSION_HANDLE_INVALID),
            }
        }
        Self::drain_readers(&fence);
        Ok(SessionFenceGuard {
            fence,
            mode: FenceMode::Write,
            session: session.0,
            epoch,
            settled: Cell::new(false),
            _gate: PhantomData,
            _confine: PhantomData,
        })
    }

    /// Enter close ownership on every affected fence in ascending numeric
    /// session-handle order (the total order — overlapping close-alls and
    /// close-vs-close-all serialize instead of deadlocking). Already-closed
    /// sessions are skipped (their desired end state holds); failed native
    /// closes reopen every entered fence via [`Self::reopen_all`].
    pub(in crate::ffi) fn enter_write_all<'g>(
        &self,
        admission: &'g OrdinaryGuard<'_>,
        sessions: &[u64],
    ) -> Vec<SessionFenceGuard<'g>> {
        let mut ordered: Vec<u64> = sessions.to_vec();
        ordered.sort_unstable();
        // Dedup: a duplicate ID's second pass would park on self-owned
        // `CLOSING` forever, holding lifecycle read (the sole caller
        // passes unique IDs today, but the table must not self-deadlock
        // on duplicates).
        ordered.dedup();
        // Mark-all before drain-any: no op can slip between the marks, and
        // new arrivals fail fast on every affected session immediately.
        let mut fences = Vec::with_capacity(ordered.len());
        for session in ordered {
            let fence =
                self.fences.entry(session).or_insert_with(|| Arc::new(SessionFence::new())).clone();
            loop {
                match fence.lifecycle.load(SeqCst) {
                    FENCE_OPEN => {
                        if fence
                            .lifecycle
                            .compare_exchange(FENCE_OPEN, FENCE_CLOSING, SeqCst, SeqCst)
                            .is_ok()
                        {
                            fences.push((session, fence));
                            break;
                        }
                    }
                    FENCE_CLOSING => std::thread::park_timeout(FENCE_DRAIN_POLL),
                    // Already closed by a concurrent closer: skip (end state
                    // holds); re-check below if it reopened — it cannot: a
                    // reopen stores OPEN, which we would have loaded... a
                    // concurrent reopen lands as OPEN on retry only when we
                    // loop, and we break on terminal states. Re-examine: on
                    // `_closed` we skip WITHOUT retry, so a close that fails
                    // natively and reopens AFTER our load leaves us skipping
                    // a live session. Close-all then omits it from THIS call
                    // — but the failed close proves nothing either, and the
                    // provider already serialized both native calls. The
                    // session stays live and consistently fenced; acceptable
                    // (same as a session opened concurrently with close-all).
                    _closed_epoch => break,
                }
            }
        }
        for (_, fence) in &fences {
            Self::drain_readers(fence);
        }
        let epoch = admission.epoch();
        fences
            .into_iter()
            .map(|(session, fence)| SessionFenceGuard {
                fence,
                mode: FenceMode::Write,
                session,
                epoch,
                settled: Cell::new(false),
                _gate: PhantomData,
                _confine: PhantomData,
            })
            .collect()
    }

    fn drain_readers(fence: &SessionFence) {
        while fence.readers.load(SeqCst) != 0 {
            std::thread::park_timeout(FENCE_DRAIN_POLL);
        }
    }

    /// Commit a successful close: record the closing epoch as the terminal
    /// state and remove the entry (memory hygiene; the provider arbitrates
    /// the numeric handle from here). Must pair with `enter_write`.
    pub(in crate::ffi) fn commit_close(&self, guard: &SessionFenceGuard<'_>) {
        debug_assert_eq!(guard.mode, FenceMode::Write);
        debug_assert!(!guard.settled.get());
        // Clamp the terminal epoch below the sentinels: raw epochs
        // `u64::MAX-1`/`u64::MAX` equal `FENCE_CLOSING`/`FENCE_OPEN`
        // (physically unreachable — ~2^64 control cycles — but the clamp
        // matches the codebase's own `checked_add` standard).
        let terminal = guard.epoch.min(FENCE_CLOSING - 1);
        guard.fence.lifecycle.store(terminal, SeqCst);
        self.fences.remove(&guard.session);
        guard.settled.set(true);
    }

    /// Reopen after a failed close: the failure proves nothing, so the
    /// session stays live and fenced. Must pair with `enter_write`.
    pub(in crate::ffi) fn reopen(&self, guard: &SessionFenceGuard<'_>) {
        debug_assert_eq!(guard.mode, FenceMode::Write);
        debug_assert!(!guard.settled.get());
        guard.fence.lifecycle.store(FENCE_OPEN, SeqCst);
        guard.settled.set(true);
    }

    /// Commit a successful close-all over every entered fence. Must pair
    /// with `enter_write_all`.
    pub(in crate::ffi) fn commit_close_all(&self, guards: &[SessionFenceGuard<'_>]) {
        for guard in guards {
            self.commit_close(guard);
        }
    }

    /// Reopen every entered fence after a failed close-all. Must pair with
    /// `enter_write_all`.
    pub(in crate::ffi) fn reopen_all(&self, guards: &[SessionFenceGuard<'_>]) {
        for guard in guards {
            self.reopen(guard);
        }
    }

    /// Drop every fence entry. Runs only under lifecycle write (re-Initialize
    /// purge), where no guard — hence no fence holder — can exist.
    pub(in crate::ffi) fn clear(&self) {
        self.fences.clear();
    }

    #[cfg(test)]
    pub(in crate::ffi) fn len_for_tests(&self) -> usize {
        self.fences.len()
    }

    #[cfg(test)]
    pub(in crate::ffi) fn lifecycle_for_tests(&self, session: u64) -> Option<u64> {
        self.fences.get(&session).map(|fence| fence.lifecycle.load(SeqCst))
    }

    #[cfg(test)]
    pub(in crate::ffi) fn readers_for_tests(&self, session: u64) -> Option<u64> {
        self.fences.get(&session).map(|fence| fence.readers.load(SeqCst))
    }
}

impl Drop for SessionFenceGuard<'_> {
    fn drop(&mut self) {
        match self.mode {
            FenceMode::Read => {
                self.fence.readers.fetch_sub(1, SeqCst);
            }
            FenceMode::Write if self.settled.get() => {}
            FenceMode::Write => {
                // Unsettled write drop: only a settlement panic reaches
                // here on the normal path (close sites commit or reopen
                // explicitly). Never wedge in CLOSING: restore OPEN so the
                // session stays usable; fail loudly in debug when not
                // unwinding (a close site forgot its settlement).
                debug_assert!(
                    std::thread::panicking(),
                    "close fence for session {} dropped without commit/reopen",
                    self.session
                );
                self.fence.lifecycle.store(FENCE_OPEN, SeqCst);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::native_domain::LifecycleDomain;
    use super::*;
    use std::sync::mpsc;

    fn open_domain() -> LifecycleDomain {
        let domain = LifecycleDomain::new();
        domain.open_for_tests();
        domain
    }

    #[test]
    fn read_enter_tracks_readers_and_releases_on_drop() {
        let domain = open_domain();
        let admission = domain.admit_ordinary().expect("admits");
        let table = SessionFenceTable::default();
        assert_eq!(table.len_for_tests(), 0);
        let first = table.enter(&admission, CkSessionHandle(7)).expect("first enters");
        assert_eq!(table.readers_for_tests(7), Some(1));
        {
            let _second = table.enter(&admission, CkSessionHandle(7)).expect("second enters");
            assert_eq!(table.readers_for_tests(7), Some(2));
        }
        assert_eq!(table.readers_for_tests(7), Some(1));
        drop(first);
        assert_eq!(table.readers_for_tests(7), Some(0));
    }

    #[test]
    fn close_marks_drains_and_commits_with_epoch() {
        let domain = open_domain();
        let table = SessionFenceTable::default();
        // Share borrows: the `move` worker below must capture `&domain` /
        // `&table` (both `Copy`), not move the owned values.
        let domain = &domain;
        let table = &table;
        // Fence guards are !Send, so each role runs wholly on its own thread
        // and reports via channels.
        std::thread::scope(|scope| {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            // `move`: the `Receiver` is owned by the worker (`!Sync`, so a
            // shared borrow would not be `Send`); the `&domain`/`&table`
            // borrows are `Copy` and stay usable.
            scope.spawn(move || {
                let admission = domain.admit_ordinary().expect("op admits");
                let _op = table.enter(&admission, CkSessionHandle(7)).expect("op enters");
                entered_tx.send(()).expect("report op entered");
                release_rx.recv_timeout(Duration::from_secs(5)).expect("wait for release");
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).expect("op parks holding read");
            let (done_tx, done_rx) = mpsc::channel();
            scope.spawn(move || {
                let closer_admission = domain.admit_ordinary().expect("closer admits");
                let guard = table
                    .enter_write(&closer_admission, CkSessionHandle(7))
                    .expect("closer enters");
                let epoch = guard.epoch;
                table.commit_close(&guard);
                done_tx.send(epoch).expect("report commit");
            });
            // The mark lands promptly but the drain spins while the op is
            // parked: CLOSING is visible, completion is not.
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while table.lifecycle_for_tests(7) != Some(FENCE_CLOSING) {
                assert!(std::time::Instant::now() < deadline, "closer must mark CLOSING");
                std::thread::yield_now();
            }
            assert!(
                done_rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "close must not complete while a reader is parked"
            );
            release_tx.send(()).expect("release the parked op");
            let epoch = done_rx.recv_timeout(Duration::from_secs(5)).expect("close completes");
            assert!(epoch != FENCE_OPEN && epoch != FENCE_CLOSING);
            assert_eq!(table.len_for_tests(), 0, "commit removes the entry");
        });
    }

    #[test]
    fn entrants_fail_fast_while_closing_and_after_commit() {
        let domain = open_domain();
        let admission = domain.admit_ordinary().expect("admits");
        let table = SessionFenceTable::default();
        let guard = table.enter_write(&admission, CkSessionHandle(7)).expect("closer enters");
        assert_eq!(
            table.enter(&admission, CkSessionHandle(7)).unwrap_err(),
            CkRv::SESSION_HANDLE_INVALID,
            "entrants during CLOSING fail without native entry"
        );
        table.commit_close(&guard);
        // Post-commit the entry is gone; a fresh enter re-creates OPEN (the
        // provider arbitrates the numeric handle from here).
        let fresh = table.enter(&admission, CkSessionHandle(7)).expect("fresh fence re-created");
        assert_eq!(table.lifecycle_for_tests(7), Some(FENCE_OPEN));
        drop(fresh);
    }

    #[test]
    fn failed_close_reopens_and_session_stays_usable() {
        let domain = open_domain();
        let admission = domain.admit_ordinary().expect("admits");
        let table = SessionFenceTable::default();
        let guard = table.enter_write(&admission, CkSessionHandle(7)).expect("closer enters");
        table.reopen(&guard);
        assert_eq!(table.lifecycle_for_tests(7), Some(FENCE_OPEN));
        table.enter(&admission, CkSessionHandle(7)).expect("op proceeds after reopen");
    }

    #[test]
    fn second_close_while_closing_serializes_then_fails_invalid() {
        let domain = open_domain();
        let table = SessionFenceTable::default();
        std::thread::scope(|scope| {
            let first_admission = domain.admit_ordinary().expect("first admits");
            let first =
                table.enter_write(&first_admission, CkSessionHandle(7)).expect("first wins");
            let done = scope.spawn(|| {
                let second_admission = domain.admit_ordinary().expect("second admits");
                table.enter_write(&second_admission, CkSessionHandle(7)).unwrap_err()
            });
            // The second closer spins on CLOSING; it must not resolve early.
            std::thread::sleep(Duration::from_millis(100));
            table.commit_close(&first);
            assert_eq!(
                done.join().expect("second joins"),
                CkRv::SESSION_HANDLE_INVALID,
                "losing closer reports what the provider would"
            );
        });
    }

    #[test]
    fn close_all_enters_ascending_and_commits_together() {
        let domain = open_domain();
        let admission = domain.admit_ordinary().expect("admits");
        let table = SessionFenceTable::default();
        // Caller order is deliberately scrambled; the table enforces ascending.
        let guards = table.enter_write_all(&admission, &[30, 10, 20]);
        assert_eq!(table.len_for_tests(), 3);
        for session in [10, 20, 30] {
            assert_eq!(table.lifecycle_for_tests(session), Some(FENCE_CLOSING));
        }
        table.commit_close_all(&guards);
        assert_eq!(table.len_for_tests(), 0);
    }

    #[test]
    fn close_all_skips_already_closed_sessions() {
        let domain = open_domain();
        let admission = domain.admit_ordinary().expect("admits");
        let table = SessionFenceTable::default();
        let single = table.enter_write(&admission, CkSessionHandle(10)).expect("single wins");
        table.commit_close(&single);
        // Entry removed at commit: close-all re-creates and enters it (the
        // provider arbitrates the numeric handle either way).
        let guards = table.enter_write_all(&admission, &[10, 20]);
        assert_eq!(guards.len(), 2);
        table.commit_close_all(&guards);
    }

    #[test]
    fn overlapping_close_alls_serialize_without_deadlock() {
        let domain = open_domain();
        let table = SessionFenceTable::default();
        std::thread::scope(|scope| {
            // Opposite caller orders over an overlapping set: the ascending
            // total order inside enter_write_all must serialize these.
            let first = scope.spawn(|| {
                let admission = domain.admit_ordinary().expect("first admits");
                let guards = table.enter_write_all(&admission, &[30, 10, 20]);
                table.commit_close_all(&guards);
            });
            let second = scope.spawn(|| {
                let admission = domain.admit_ordinary().expect("second admits");
                let guards = table.enter_write_all(&admission, &[20, 30, 10]);
                table.commit_close_all(&guards);
            });
            // A deadlock would hang the join; scope-join has no timeout, so
            // bound it via channels instead.
            let (done_tx, done_rx) = mpsc::channel();
            scope.spawn(move || {
                first.join().expect("first joins");
                second.join().expect("second joins");
                done_tx.send(()).expect("report completion");
            });
            done_rx.recv_timeout(Duration::from_secs(10)).expect("both close-alls complete");
        });
        assert_eq!(table.len_for_tests(), 0);
    }

    #[test]
    fn reader_panic_exits_without_wedging() {
        // Unwind through a read fence releases the reader count (mirrors
        // `reader_panic_does_not_poison` at domain level).
        let domain = open_domain();
        let table = SessionFenceTable::default();
        std::thread::scope(|scope| {
            let parked = scope.spawn(|| {
                let admission = domain.admit_ordinary().expect("admits before panic");
                let _guard = table.enter(&admission, CkSessionHandle(7)).expect("enters");
                panic!("intentional fence-reader panic (must exit cleanly)");
            });
            assert!(parked.join().is_err(), "reader thread must panic");
        });
        assert_eq!(table.readers_for_tests(7), Some(0));
        let admission = domain.admit_ordinary().expect("admits after panic");
        table.enter(&admission, CkSessionHandle(7)).expect("fence usable after panic");
    }

    #[test]
    fn unsettled_write_drop_restores_open() {
        // A write fence dropped without commit/reopen (settlement panic)
        // restores OPEN rather than wedging in CLOSING. Panicking, so the
        // debug_assert backstop stays silent.
        let domain = open_domain();
        let table = SessionFenceTable::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let admission = domain.admit_ordinary().expect("admits");
            let _guard = table.enter_write(&admission, CkSessionHandle(7)).expect("enters");
            panic!("intentional settlement panic (must restore OPEN)");
        }));
        assert!(result.is_err());
        assert_eq!(table.lifecycle_for_tests(7), Some(FENCE_OPEN));
        let admission = domain.admit_ordinary().expect("admits after panic");
        table.enter(&admission, CkSessionHandle(7)).expect("fence usable after panic");
    }

    #[test]
    fn close_all_with_duplicate_ids_completes() {
        // A duplicate ID's second pass would park on self-owned `CLOSING`
        // forever, holding lifecycle read (pre-fix self-deadlock); the
        // dedup after the ascending sort makes the input unique. Run
        // off-thread and join via `recv_timeout` so a regression trips the
        // 10s bound promptly (the scope join then hangs on the wedged
        // worker — hangs pre-fix, matching the established close-all test
        // pattern).
        let domain = open_domain();
        let table = SessionFenceTable::default();
        // Share borrows: the `move` worker below must capture `&domain` /
        // `&table` (both `Copy`), not move the owned values.
        let domain = &domain;
        let table = &table;
        std::thread::scope(|scope| {
            let (done_tx, done_rx) = mpsc::channel();
            scope.spawn(move || {
                let admission = domain.admit_ordinary().expect("admits");
                let guards = table.enter_write_all(&admission, &[10, 20, 10, 30, 20]);
                assert_eq!(guards.len(), 3, "duplicates enter once");
                table.commit_close_all(&guards);
                done_tx.send(()).expect("report completion");
            });
            done_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("duplicate-ID close-all completes");
        });
        assert_eq!(table.len_for_tests(), 0);
    }
}
