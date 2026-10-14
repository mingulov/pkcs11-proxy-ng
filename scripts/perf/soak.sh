#!/usr/bin/env bash
# Soak test.
#
# Drives sustained RPS of C_Sign load through the shim against a
# daemon backed by SoftHSM2 for DURATION seconds, sampling daemon
# RSS + open FD count every SOAK_SAMPLE_INTERVAL_SECS.
#
# Unlike the original driver, the load worker is an owned foreground
# `docker exec` the harness joins under a bound before reading its
# result: no detached work, no DURATION vs DURATION+10 race, no fixed
# cross-run result filename. Unavailable measurements stay empty (never
# fabricated zeros), and every verdict limit is a recorded input.
#
# Usage:
#   DURATION=3600 RPS=50 scripts/perf/soak.sh
#
# Output:
#   scripts/perf/results/soak_samples.csv  (elapsed,RSS,FD rows)
#   scripts/perf/results/soak.json         (summary + verdict)
#
# Environment (all optional; validated before anything runs):
#   DURATION (default 3600), RPS (default 50),
#   SOAK_SETUP_TIMEOUT_SECS (120), SOAK_SAMPLE_TIMEOUT_SECS (30),
#   SOAK_WORKER_GRACE_SECS (120), SOAK_OP_TIMEOUT_SECS (30),
#   SOAK_CLEANUP_GRACE_SECS (5), SOAK_WARMUP_SECS (300),
#   SOAK_SAMPLE_INTERVAL_SECS (60), SOAK_WINDOW_SAMPLES (5),
#   SOAK_MAX_RSS_GROWTH_MB (50), SOAK_MAX_FD_GROWTH (100),
#   SOAK_PROC_ROOT (/proc), SOAK_STAT_READER (cat).
# TEST ONLY seams (fault injection; never set in production):
#   SOAK_UPTIME_PATH, SOAK_PUBLISH_HOLD, SOAK_REMOVAL_HOLD.
#
# Exit codes: 0 PASS; 1 any FAIL_* verdict (summary published);
# 2 invalid input or setup refusal (nothing ran, no summary);
# 130/143 interrupted (terminal summary published).

set -euo pipefail

# Each background job runs in its own process group, so escalation can
# signal whole jobs (TERM/KILL to the group) without /proc enumeration:
# whatever the reader cannot see, the group still reaches. Group members
# are only ever signaled for jobs this script has not yet reaped and
# released, bounding group-id reuse to the same TOCTOU class as PID kill.
if ! set -m; then
    echo "error: job control is unavailable; per-job ownership needs it" >&2
    exit 2
fi

# Measurement parsing must not depend on the operator's locale.
export LC_ALL=C

canon_int() { # $1=value; echo canonical decimal or fail
    local val="$1"
    [[ "$val" =~ ^[0-9]+$ ]] || return 1
    [ "${#val}" -le 18 ] || return 1
    printf '%d\n' "$((10#$val))"
}

canon_bound() { # $1=value $2=name $3=max; echo canonical or fail
    local canon
    canon="$(canon_int "$1")" || canon=""
    if [ -z "$canon" ] || [ "$canon" -gt "$3" ]; then
        echo "error: $2 must be an integer between 0 and $3, got '$1'" >&2
        return 1
    fi
    echo "$canon"
}

DURATION="$(canon_bound "${DURATION-3600}" DURATION 31536000)" || exit 2
RPS="$(canon_bound "${RPS-50}" RPS 1000000)" || exit 2
if [ "$RPS" -lt 1 ]; then
    echo "error: RPS must be a positive integer, got '${RPS-}'" >&2
    exit 2
fi
SETUP_TIMEOUT="$(canon_bound "${SOAK_SETUP_TIMEOUT_SECS-120}" SOAK_SETUP_TIMEOUT_SECS 31536000)" || exit 2
SAMPLE_TIMEOUT="$(canon_bound "${SOAK_SAMPLE_TIMEOUT_SECS-30}" SOAK_SAMPLE_TIMEOUT_SECS 31536000)" || exit 2
WORKER_GRACE="$(canon_bound "${SOAK_WORKER_GRACE_SECS-120}" SOAK_WORKER_GRACE_SECS 31536000)" || exit 2
OP_TIMEOUT="$(canon_bound "${SOAK_OP_TIMEOUT_SECS-30}" SOAK_OP_TIMEOUT_SECS 86400)" || exit 2
CLEANUP_GRACE="$(canon_bound "${SOAK_CLEANUP_GRACE_SECS-5}" SOAK_CLEANUP_GRACE_SECS 31536000)" || exit 2
WARMUP="$(canon_bound "${SOAK_WARMUP_SECS-300}" SOAK_WARMUP_SECS 31536000)" || exit 2
SAMPLE_INTERVAL="$(canon_bound "${SOAK_SAMPLE_INTERVAL_SECS-60}" SOAK_SAMPLE_INTERVAL_SECS 3600)" || exit 2
if [ "$SAMPLE_INTERVAL" -lt 1 ]; then
    echo "error: SOAK_SAMPLE_INTERVAL_SECS must be a positive integer, got '${SOAK_SAMPLE_INTERVAL_SECS-}'" >&2
    exit 2
fi
WINDOW="$(canon_bound "${SOAK_WINDOW_SAMPLES-5}" SOAK_WINDOW_SAMPLES 1000000)" || exit 2
if [ "$WINDOW" -lt 1 ]; then
    echo "error: SOAK_WINDOW_SAMPLES must be a positive integer, got '${SOAK_WINDOW_SAMPLES-}'" >&2
    exit 2
fi
if [ -n "${SOAK_MAX_RSS_GROWTH_MB+x}" ]; then RSS_PROV="explicit"; else RSS_PROV="default"; fi
if [ -n "${SOAK_MAX_FD_GROWTH+x}" ]; then FD_PROV="explicit"; else FD_PROV="default"; fi
MAX_RSS_GROWTH="$(canon_bound "${SOAK_MAX_RSS_GROWTH_MB-50}" SOAK_MAX_RSS_GROWTH_MB 1000000)" || exit 2
MAX_FD_GROWTH="$(canon_bound "${SOAK_MAX_FD_GROWTH-100}" SOAK_MAX_FD_GROWTH 10000000)" || exit 2
if [ "$RSS_PROV" = "$FD_PROV" ]; then LIMITS_PROV="$RSS_PROV"; else LIMITS_PROV="mixed"; fi

PROC_ROOT="${SOAK_PROC_ROOT-/proc}"
if [ -z "$PROC_ROOT" ] || [ ! -d "$PROC_ROOT" ]; then
    echo "error: SOAK_PROC_ROOT must be an existing proc tree, got '$PROC_ROOT'" >&2
    exit 2
fi
STAT_READER="${SOAK_STAT_READER-cat}"
if ! command -v "$STAT_READER" >/dev/null 2>&1; then
    echo "error: SOAK_STAT_READER must name an available command, got '$STAT_READER'" >&2
    exit 2
fi

# Host tools the controller itself invokes. `date` is deliberately
# absent: the controller is monotonic-clock-only (every bound and
# timestamp uses /proc/uptime); realtime `date` runs only inside the
# worker container, which carries its own. `timeout` is likewise
# worker-side only.
for tool in docker awk sort mktemp rm mkdir mv cat touch dirname sleep cksum python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: required tool '$tool' not found in PATH" >&2
        exit 2
    fi
done

# --- Monotonic clock --------------------------------------------------
# Safety bounds use the monotonic clock (/proc/uptime), never the
# realtime clock: a stepped or skewed `date` must not stall a bound.
mono_now() { # echo whole monotonic seconds or fail
    awk '{print int($1)}' "${SOAK_UPTIME_PATH:-/proc/uptime}" 2>/dev/null
}
deadline_after() { # $1=seconds; echo monotonic deadline or fail
    local now_s
    now_s=$(mono_now) || return 1
    echo $(( now_s + $1 ))
}
if ! mono_now >/dev/null 2>&1; then
    echo "error: monotonic clock (${SOAK_UPTIME_PATH:-/proc/uptime}) is unreadable" >&2
    exit 2
fi

JOIN_POLL_SECS="0.05"

if ! WORK="$(mktemp -d)"; then
    echo "error: could not create a scratch directory" >&2
    exit 2
fi
OUT_DIR="$(cd "$(dirname "$0")" && pwd)/results"
if ! mkdir -p "$OUT_DIR"; then
    echo "error: could not create results directory '$OUT_DIR'" >&2
    rm -rf "$WORK" 2>/dev/null || true
    exit 2
fi
# This run owns the output directory: a previous run's summary is
# removed now, so the file's existence always identifies THIS run's
# terminal record (the signal trap skips writing when one exists).
rm -f "$OUT_DIR/soak.json"

# Prove the state reader up front: if even our own state is unreadable,
# every later `gone` is unverified and the run cannot claim clean
# cleanup. (The reader functions are defined below; the check itself
# needs only $WORK and $STAT_READER.)
if ! "$STAT_READER" "/proc/$$/stat" >/dev/null 2>&1; then
    touch "$WORK/.reader_fault" 2>/dev/null || true
fi

# Use the consumers fixture daemon (Alpine, softhsm2 backend).
COMPOSE=(docker compose -f "$(cd "$(dirname "$0")/../.." && pwd)/tests/consumers/docker-compose.yml")
CONSUMERS_DIR="$(cd "$(dirname "$0")/../.." && pwd)/tests/consumers"

# --- Owned-child tracking ----------------------------------------------
# Every background process this script starts is recorded here and only
# here; joins and signal cleanup act on exactly these PIDs, which are
# released (cleared) as soon as their owners reap them so a reused PID
# is never signalled. The sampler runs inline (its per-sample docker
# exec is a tracked, bounded step), so only one worker subshell, one
# sample-wait sleep, plus transient setup/sample/removal helpers are
# ever tracked.
WORKER_PID=""
SETUP_PID=""
RM_PID=""
SLEEP_PID=""
RECOVER_PID=""
# Settlement grace sleeps live on their own stack, never in a job
# slot: recovery settles helpers while the interval wait is still
# live in SLEEP_PID, and a signal can nest a recovery settle inside
# a main-flow one. LIFO push/pop keeps every grace owned.
SETTLE_PIDS=()
CLEANUP_DONE=0
CLEANUP_SAW_FAULT=false
UNRESOLVED_PIDS=()
JOIN_KILLED=0
JOIN_TIMED_OUT=0
JOIN_UNRESOLVED=()
REAP_RESULT=""
PHASE="startup"
SUMMARY_DONE=""
# Validated worker outcomes, carried for signal-time records. An
# interruption after validation publishes these instead of nulls
# (known evidence is never re-nulled); before validation they stay
# empty and the interrupted record reports nulls honestly.
HAVE_COUNTS=false
RESULT_RUN_ID=""
RESULT_OFFERED=""
R_SUCCESS=""; R_TIMEOUT=""; R_ERROR=""; R_UNKNOWN=""; R_UNFINISHED=""
RESULT_BUSY_US=""
RESULT_ELAPSED_S=""
RESULT_CLAMPED_OPS=""
RESULT_COMPLETE=""
RESULT_ERROR=""
WORKER_ACKED=false
WORKER_EXIT=""
WORKER_TIMED_OUT=0
WORKER_KILLED=0
WORKER_LATE=false

# proc_state PID: echo one of: gone | zombie | alive | unknown.
# Only gone (no /proc entry) and zombie (state Z) are positive; a
# present-but-unreadable process is unknown and must never be treated
# as gone (reaping it with `wait` could block unboundedly). A read
# that fails because the entry vanished mid-check is a benign exit
# race (bash also reaps finished children opportunistically, so
# `gone` is the common observation for just-exited children); only a
# still-present-but-unreadable entry records a reader fault.
proc_state() {
    local pid="$1" content rest state
    [ -n "$pid" ] || { echo gone; return 0; }
    [ -d "/proc/$pid" ] || { echo gone; return 0; }
    if content=$("$STAT_READER" "/proc/$pid/stat" 2>/dev/null) && [ -n "$content" ]; then
        rest="${content##*) }"
        state="${rest%% *}"
        if [ "$state" = "Z" ]; then
            echo zombie
        else
            echo alive
        fi
    elif [ -d "/proc/$pid" ]; then
        # Still present but unreadable: genuinely unknown. Record the
        # verification gap on disk: this function runs in command
        # substitutions, so a variable would not propagate.
        touch "$WORK/.reader_fault" 2>/dev/null || true
        echo unknown
    else
        echo gone
    fi
}

# descendants PID: print current descendant PIDs (parent before child).
# Returns nonzero when a children list of this live PID was unreadable.
# Genuinely unreadable entries (still present) record a reader fault;
# entries that vanished mid-walk are benign exit races.
descendants() {
    local pid="$1" task kids child failed=0
    local -a kid_list
    [ -d "/proc/$pid" ] || return 0
    for task in /proc/"$pid"/task/*/children; do
        if [ -r "$task" ]; then
            if kids=$("$STAT_READER" "$task" 2>/dev/null); then
                [ -n "$kids" ] || continue
                read -ra kid_list <<< "$kids"
                for child in "${kid_list[@]}"; do
                    printf '%s\n' "$child"
                    descendants "$child" || failed=1
                done
            elif [ -e "$task" ]; then
                touch "$WORK/.reader_fault" 2>/dev/null || true
                failed=1
            fi
        elif [ -e "$task" ]; then
            touch "$WORK/.reader_fault" 2>/dev/null || true
            failed=1
        fi
    done
    return "$failed"
}

# reader_faulted: true once any /proc read through $STAT_READER has
# genuinely failed (present-but-unreadable), as opposed to racing an
# exit. Sticky for the run: while blind, tree cleanup cannot be
# verified, so the cleanup verdict fails closed.
reader_faulted() {
    [ -f "$WORK/.reader_fault" ]
}

# kill_tree SIGNAL PID...: signal each PID and its current descendants,
# deepest first (a reparented orphan is still killed by PID). PID
# signals only, never group signals; only ever aimed at owned host
# jobs (container-side termination is by container removal — the
# harness never host-signals container processes). Never fails.
kill_tree() {
    local sig="$1"
    shift
    local pid child
    local -a order
    local i
    for pid in "$@"; do
        [ -n "$pid" ] || continue
        order=()
        while IFS= read -r child; do
            order+=("$child")
        done < <(descendants "$pid" || true)
        for (( i=${#order[@]}-1; i>=0; i-- )); do
            kill "-$sig" "${order[$i]}" 2>/dev/null || true
        done
        kill "-$sig" "$pid" 2>/dev/null || true
    done
}

# kill_owned SIGNAL PID...: signal each owned job's tree plus its whole
# job group (group members enumeration missed while blind). Per-PID and
# per-group signals are idempotent, so the healthy overlap is harmless.
# Only for jobs this script spawned (their groups are ours). Never fails.
kill_owned() {
    local sig="$1"
    shift
    local pid
    kill_tree "$sig" "$@"
    for pid in "$@"; do
        [ -n "$pid" ] || continue
        kill "-$sig" -- "-$pid" 2>/dev/null || true
    done
}

# wait_until_gone DEADLINE_MONO PID...: true when every PID is gone or
# zombie before the monotonic deadline. Unknown states keep polling;
# an unreadable clock expires the bound immediately (fail closed).
wait_until_gone() {
    local deadline="$1"
    shift
    local pid state now_s pending
    while :; do
        pending=0
        for pid in "$@"; do
            [ -n "$pid" ] || continue
            state=$(proc_state "$pid")
            if [ "$state" != "gone" ] && [ "$state" != "zombie" ]; then
                pending=1
                break
            fi
        done
        [ "$pending" -eq 0 ] && return 0
        now_s=$(mono_now) || return 1
        [ "$now_s" -ge "$deadline" ] && return 1
        sleep "$JOIN_POLL_SECS"
    done
}

# reap PID: wait for an owned child that already exited; print its exit
# status (127 if already reaped). Only call on gone-or-zombie PIDs:
# waiting on a running child would block. Never fails.
reap() {
    local pid="$1" code=0
    [ -n "$pid" ] || { echo 127; return 0; }
    wait "$pid" 2>/dev/null || code=$?
    echo "$code"
}

# reap_parent PID: reap a tracked parent when it is gone or zombie and
# set REAP_RESULT to its exit status; otherwise append it to
# UNRESOLVED_PIDS and set REAP_RESULT to "unreaped". A `wait` status of
# 127 means the PID is not (or no longer) our child, so the code is
# unknowable. When the reader has faulted, the reaped code is still
# real (`wait` is ground truth, not a /proc inference) but the process
# tree around it could not be verified, so the PID stays unresolved.
# Never fails. (A global, not stdout: callers must not run this in a
# subshell.)
reap_parent() {
    local pid="$1" state
    state=$(proc_state "$pid")
    if [ "$state" = "gone" ] || [ "$state" = "zombie" ]; then
        REAP_RESULT=$(reap "$pid")
        if [ "$REAP_RESULT" = "127" ]; then
            UNRESOLVED_PIDS+=("$pid")
            REAP_RESULT="unreaped"
        elif reader_faulted; then
            UNRESOLVED_PIDS+=("$pid")
        fi
    else
        UNRESOLVED_PIDS+=("$pid")
        REAP_RESULT="unreaped"
    fi
}

# join_or_terminate DEADLINE_MONO PID...: wait for natural completion,
# else TERM, grace, KILL, grace over parents plus retained descendants.
# Descendant zombies are reaped; parents are left for the caller to
# reap (it owns their exit codes). Sets JOIN_KILLED (escalation fired),
# JOIN_TIMED_OUT (a parent was confirmed alive at the deadline, as
# opposed to merely unverifiable), and JOIN_UNRESOLVED (non-parent
# leftovers). Never fails.
join_or_terminate() {
    local deadline="$1"
    shift
    local -a parents=("$@") watched=()
    local pid d dlist term_settled
    JOIN_KILLED=0
    JOIN_TIMED_OUT=0
    JOIN_UNRESOLVED=()
    [ "${#parents[@]}" -eq 0 ] && return 0
    if wait_until_gone "$deadline" "${parents[@]}"; then
        return 0
    fi
    # The deadline expired: snapshot liveness now. Only a positively
    # alive parent counts as a timeout; unknown states are unverifiable,
    # not evidence the bound was exceeded.
    for pid in "${parents[@]}"; do
        [ -n "$pid" ] || continue
        if [ "$(proc_state "$pid")" = "alive" ]; then
            JOIN_TIMED_OUT=1
            break
        fi
    done
    JOIN_KILLED=1
    watched=("${parents[@]}")
    for pid in "${parents[@]}"; do
        dlist=$(descendants "$pid" 2>/dev/null || true)
        while IFS= read -r d; do
            [ -n "$d" ] && watched+=("$d")
        done <<< "$dlist"
    done
    kill_owned TERM "${watched[@]}"
    term_settled=true
    if ! wait_until_gone "$(deadline_after "$CLEANUP_GRACE" || echo 0)" "${watched[@]}"; then
        term_settled=false
    fi
    if [ "$term_settled" = false ] || reader_faulted; then
        # Re-scan for children forked after the first snapshot, then KILL.
        # The KILL round also runs when the TERM round settled but blind:
        # watched tops may be gone while unenumerated group members linger.
        for pid in "${parents[@]}"; do
            dlist=$(descendants "$pid" 2>/dev/null || true)
            while IFS= read -r d; do
                [ -n "$d" ] && watched+=("$d")
            done <<< "$dlist"
        done
        kill_owned KILL "${watched[@]}"
        wait_until_gone "$(deadline_after "$CLEANUP_GRACE" || echo 0)" "${watched[@]}" || true
    fi
    local state is_parent p
    for d in "${watched[@]}"; do
        is_parent=0
        for p in "${parents[@]}"; do
            [ "$d" = "$p" ] && is_parent=1
        done
        [ "$is_parent" -eq 1 ] && continue
        state=$(proc_state "$d")
        if [ "$state" = "gone" ] || [ "$state" = "zombie" ]; then
            reap "$d" >/dev/null
            if reader_faulted; then
                JOIN_UNRESOLVED+=("$d")
            fi
        else
            JOIN_UNRESOLVED+=("$d")
        fi
    done
    # Explicit zero: the loops above end in short-circuited lists whose
    # nonzero status must never become this never-fails function's own.
    return 0
}

# settle_unverified PID...: stop processes whose completion is proven by a
# done-file but whose state is unverifiable: TERM, one grace, KILL, then
# record every PID unresolved (blind verification can confirm nothing).
# Never fails.
settle_unverified() {
    local pid grace_deadline grace_pid
    [ "$#" -eq 0 ] && return 0
    kill_owned TERM "$@"
    # The grace itself is bounded monotonically (a stalled sleep must
    # not hang settlement): join_or_terminate waits for natural
    # completion and escalates past the deadline. A bare `wait` here
    # would hang unboundedly. The grace is pushed on the settle
    # stack (trap-visible for a nested signal) and popped after its
    # reap — never parked in a job slot another wait may own.
    sleep "$CLEANUP_GRACE" &
    grace_pid=$!
    SETTLE_PIDS+=("$grace_pid")
    grace_deadline=$(deadline_after "$CLEANUP_GRACE") || grace_deadline=0
    join_or_terminate "$grace_deadline" "$grace_pid"
    reap_parent "$grace_pid"
    unset "SETTLE_PIDS[$((${#SETTLE_PIDS[@]}-1))]"
    kill_owned KILL "$@"
    for pid in "$@"; do
        [ -n "$pid" ] && UNRESOLVED_PIDS+=("$pid")
    done
    return 0
}

# clock_failed_settle PID: the monotonic clock went unreadable mid-await,
# so no bound can be measured: settle the helper with immediate
# escalation instead of abandoning it, then reap what can be reaped and
# record the rest. JOIN_TIMED_OUT stays 0 — an unmeasurable bound is not
# a timeout. Never fails.
clock_failed_settle() {
    local pid="$1"
    [ -n "$pid" ] || return 0
    join_or_terminate 0 "$pid"
    JOIN_TIMED_OUT=0
    reap_parent "$pid"
    if [ "${#JOIN_UNRESOLVED[@]}" -gt 0 ]; then
        UNRESOLVED_PIDS+=("${JOIN_UNRESOLVED[@]}")
    fi
    return 0
}

# await_step TIMEOUT PID DONEFILE: join one backgrounded step: wait for
# its done-file or for the process to exit, bounded monotonically, then
# settle (reap the verifiable, blind-stop the unverifiable, escalate a
# still-alive remainder). Completion is file-observable, so an
# unverifiable process state never burns the whole timeout. Sets
# AWAIT_CODE (done-file content or empty), REAP_RESULT, and the JOIN_*
# globals; harvests non-parent leftovers into UNRESOLVED_PIDS. Returns
# 1 only when the monotonic clock is unreadable; the helper is settled
# before that return, so callers release their PID tracking without
# re-settling. Never exits (callers apply their own failure policy).
AWAIT_CODE=""
await_step() {
    local timeout="$1" pid="$2" done_file="$3"
    local deadline now_s state settle_deadline
    AWAIT_CODE=""
    JOIN_TIMED_OUT=0
    JOIN_KILLED=0
    JOIN_UNRESOLVED=()
    # SETTLE_PIDS is deliberately not reset: a signal can nest this
    # await inside a main-flow settle, and the outer grace must stay
    # tracked (LIFO pop restores the stack on the way out).
    if ! deadline=$(deadline_after "$timeout"); then
        clock_failed_settle "$pid"
        return 1
    fi
    while [ ! -f "$done_file" ]; do
        state=$(proc_state "$pid")
        [ "$state" = "gone" ] || [ "$state" = "zombie" ] && break
        if ! now_s=$(mono_now); then
            clock_failed_settle "$pid"
            return 1
        fi
        [ "$now_s" -ge "$deadline" ] && break
        sleep "$JOIN_POLL_SECS"
    done
    if [ -f "$done_file" ]; then
        AWAIT_CODE=$(cat "$done_file" 2>/dev/null || echo "")
        state=$(proc_state "$pid")
        case "$state" in
            gone|zombie)
                reap_parent "$pid"
                ;;
            unknown)
                settle_unverified "$pid"
                REAP_RESULT="unreaped"
                ;;
            *)
                if ! settle_deadline=$(deadline_after "$CLEANUP_GRACE"); then
                    settle_deadline=0
                fi
                join_or_terminate "$settle_deadline" "$pid"
                reap_parent "$pid"
                ;;
        esac
    else
        if ! settle_deadline=$(deadline_after 0); then
            settle_deadline=0
        fi
        join_or_terminate "$settle_deadline" "$pid"
        reap_parent "$pid"
    fi
    if [ "${#JOIN_UNRESOLVED[@]}" -gt 0 ]; then
        UNRESOLVED_PIDS+=("${JOIN_UNRESOLVED[@]}")
    fi
    return 0
}

# run_setup_step DESC TIMEOUT CMD...: run CMD in the background under a
# monotonic bound so signals stay prompt; show its full output when it
# fails. Exits 2 when the step fails, when a confirmed-alive step
# outlasts its bound, or when a finished step proves a failure; warns
# and continues (leaving the PID unresolved for a FAIL_CLEANUP verdict)
# when a step finished successfully but its process state cannot be
# verified.
run_setup_step() {
    local desc="$1" timeout="$2"
    shift 2
    local log done_file
    log="$WORK/setup-$desc.log"
    done_file="$WORK/setup-$desc.done"
    rm -f "$done_file"
    ( set +e; "$@" >"$log" 2>&1; step_code=$?; echo "$step_code" >"$done_file"; exit "$step_code" ) &
    SETUP_PID=$!
    if ! await_step "$timeout" "$SETUP_PID" "$done_file"; then
        echo "error: monotonic clock unreadable during setup step '$desc'" >&2
        # await_step settled the helper already: release the tracking so
        # the exit trap does not re-settle (a second reap would record a
        # false unresolved via wait status 127).
        SETUP_PID=""
        exit 2
    fi
    SETUP_PID=""
    if [ "$JOIN_TIMED_OUT" -eq 1 ]; then
        echo "error: setup step '$desc' timed out after ${timeout}s" >&2
        cat "$log" >&2 || true
        exit 2
    fi
    if [ -n "$AWAIT_CODE" ] && [ "$AWAIT_CODE" -ne 0 ]; then
        echo "error: setup step '$desc' failed with status $AWAIT_CODE" >&2
        cat "$log" >&2 || true
        exit 2
    fi
    if [ "$REAP_RESULT" = "unreaped" ]; then
        echo "warning: setup step '$desc' finished but its process state is unverifiable; continuing" >&2
        return 0
    fi
    if [ "$REAP_RESULT" -ne 0 ]; then
        echo "error: setup step '$desc' failed with status $REAP_RESULT" >&2
        cat "$log" >&2 || true
        exit 2
    fi
}

# Container-side ownership: the worker runs inside an exclusively owned
# disposable worker container (a child of the container runtime, not of
# this script), so a killed `docker exec` CLI does not imply a dead
# worker. After the join and on signals, the harness removes the worker
# container authoritatively through the container runtime, which stops
# everything inside regardless of host privileges or /proc readability;
# a removal that cannot be confirmed sets CONTAINER_UNVERIFIED for a
# fail-closed FAIL_CLEANUP. The harness never host-signals container
# processes and never selects processes by command text.
CONTAINER_UNVERIFIED=false
RUN_NAME=""
RUN_IMAGE=""
RUN_CREATED=0
RUN_DISPATCHED=0
RM_PID=""
RM_ATTEMPT=0
RM_REMOVED=false

# attempt_rm: one bounded `docker rm -f` attempt with per-attempt
# completion evidence (overlapping attempts never share a done-file).
# The helper stays in trap-visible RM_PID until settled. Sets
# RM_REMOVED=true on a confirmed removal. `docker rm -f` is idempotent
# (removing an absent container succeeds), so no absent-tolerance is
# needed; anything but exit 0 fails closed. Never fails, never exits.
attempt_rm() {
    RM_ATTEMPT=$((RM_ATTEMPT + 1))
    local log done_file
    log="$WORK/container-rm-$RM_ATTEMPT.log"
    done_file="$WORK/container-rm-$RM_ATTEMPT.done"
    rm -f "$done_file"
    ( set +e; docker rm -f "$RUN_NAME" >"$log" 2>&1; code=$?; echo "$code" >"$done_file"; exit "$code" ) &
    RM_PID=$!
    # A clock failure returns 1 with the helper already settled: name it
    # (an unmeasurable bound is not a timeout) and fail closed below.
    if ! await_step "$CLEANUP_GRACE" "$RM_PID" "$done_file"; then
        echo "error: monotonic clock unreadable during container removal" >&2
    fi
    RM_PID=""
    RM_REMOVED=false
    if [ -n "$AWAIT_CODE" ] && [ "$AWAIT_CODE" = "0" ]; then
        RM_REMOVED=true
    fi
    return 0
}

# remove_run_container: remove the owned worker container and release
# ownership. A confirmed creation is removed directly; a dispatched
# but unconfirmed creation is reconciled first (label-verified inspect:
# absent means nothing was created, a verified label means ours to
# remove, anything else is left in place and fails closed). No-op
# unless creation was attempted. Never fails, never exits.
remove_run_container() {
    if [ "$RUN_CREATED" -eq 0 ] && [ "$RUN_DISPATCHED" -eq 0 ]; then
        return 0
    fi
    if [ -z "$RUN_NAME" ]; then
        CONTAINER_UNVERIFIED=true
        RUN_CREATED=0
        RUN_DISPATCHED=0
        return 0
    fi
    if [ "$RUN_CREATED" -eq 1 ]; then
        attempt_rm
        if [ "$RM_REMOVED" = true ]; then
            RUN_CREATED=0
            RUN_DISPATCHED=0
        else
            CONTAINER_UNVERIFIED=true
        fi
        return 0
    fi
    local log done_file label label_all
    log="$WORK/container-reconcile.log"
    done_file="$WORK/container-reconcile.done"
    rm -f "$done_file"
    ( set +e; docker inspect --format '{{index .Config.Labels "soak-run-id"}}' "$RUN_NAME" >"$log" 2>&1; code=$?; echo "$code" >"$done_file"; exit "$code" ) &
    RM_PID=$!
    # A clock failure returns 1 with the helper already settled: the
    # torn log must not be matched for absence (a partial line could
    # misread), so skip straight to unverified and fail closed.
    if ! await_step "$CLEANUP_GRACE" "$RM_PID" "$done_file"; then
        RM_PID=""
        echo "error: monotonic clock unreadable during worker-container reconcile" >&2
        echo "warning: worker container '$RUN_NAME' may exist but its state is unverifiable; leaving it in place" >&2
        CONTAINER_UNVERIFIED=true
        return 0
    fi
    RM_PID=""
    if [ -n "$AWAIT_CODE" ] && [ "$AWAIT_CODE" = "0" ]; then
        label_all=$(cat "$log" 2>/dev/null || true)
        label="${label_all%%$'\n'*}"
        label="${label//[[:space:]]/}"
        if [ "$label" = "$RUN_NAME" ]; then
            attempt_rm
            if [ "$RM_REMOVED" = true ]; then
                RUN_CREATED=0
                RUN_DISPATCHED=0
            else
                CONTAINER_UNVERIFIED=true
            fi
            return 0
        fi
        echo "warning: worker container '$RUN_NAME' exists but its ownership label is unverifiable; leaving it in place" >&2
        CONTAINER_UNVERIFIED=true
        RUN_DISPATCHED=0
        return 0
    fi
    label_all=$(cat "$log" 2>/dev/null || true)
    # Absence evidence reads narrowly: only diagnostics that name our
    # own container ID ("No such container: <id>") or use Docker's
    # canonical absent-object phrasing ("No such container", "No such
    # object", Docker 29.8.2). Transport failures ("Cannot connect to
    # the Docker daemon", DNS "no such host", proxy errors) describe
    # the road to the daemon, not the container, so anything but the
    # canonical phrasing stays unverified and the run fails closed.
    # The "no such host" wording is deliberately excluded: daemon
    # proxies and DNS resolvers emit it for lookup failures, and
    # matching it as absence would clear ownership of a container
    # that may still exist.
    case "$label_all" in
        *[Nn]o[[:space:]][Ss]uch[[:space:]][Cc]ontainer*|*[Nn]o[[:space:]][Ss]uch[[:space:]][Oo]bject*)
            RUN_CREATED=0
            RUN_DISPATCHED=0
            ;;
        *)
            # Unknown outcome (inspect failed or timed out): the flags
            # stay set for any later caller, and cleanup fails closed.
            echo "warning: worker container '$RUN_NAME' may exist but its state is unverifiable; leaving it in place" >&2
            CONTAINER_UNVERIFIED=true
            ;;
    esac
    return 0
}

# terminate_owned: stop every tracked child (TERM, grace, KILL, grace),
# reap what can be reaped, record the rest, release all ownership.
# Never fails.
# shellcheck disable=SC2329 # reached only via the EXIT/INT/TERM traps below
terminate_owned() {
    local -a all_pids=()
    local pid deadline
    [ -n "$WORKER_PID" ] && all_pids+=("$WORKER_PID")
    [ -n "$SETUP_PID" ] && all_pids+=("$SETUP_PID")
    [ -n "$RM_PID" ] && all_pids+=("$RM_PID")
    [ -n "$SLEEP_PID" ] && all_pids+=("$SLEEP_PID")
    [ "${#SETTLE_PIDS[@]}" -gt 0 ] && all_pids+=("${SETTLE_PIDS[@]}")
    [ "${#all_pids[@]}" -eq 0 ] && return 0
    deadline=$(deadline_after 0) || deadline=0
    join_or_terminate "$deadline" "${all_pids[@]}"
    if [ "${#JOIN_UNRESOLVED[@]}" -gt 0 ]; then
        UNRESOLVED_PIDS+=("${JOIN_UNRESOLVED[@]}")
    fi
    for pid in "${all_pids[@]}"; do
        reap_parent "$pid"
    done
    WORKER_PID=""
    SETUP_PID=""
    RM_PID=""
    SLEEP_PID=""
    SETTLE_PIDS=()
}

# cleanup_once: terminate ownership and remove scratch state, exactly once.
# Never fails.
# shellcheck disable=SC2329 # reached only via the EXIT/INT/TERM traps below
cleanup_once() {
    if [ "$CLEANUP_DONE" -eq 0 ]; then
        CLEANUP_DONE=1
        terminate_owned
        remove_run_container
        if reader_faulted; then
            CLEANUP_SAW_FAULT=true
        fi
        rm -rf "$WORK" 2>/dev/null || true
    fi
}

# json_escape STR: quote any string for JSON, completely. Used with
# reason texts built from constant fragments and canonical integers,
# the controller-generated run id, and the observed result run id
# (foreign bytes: newlines, tabs, and control bytes round-trip here).
# Shell substitution cannot enumerate every control byte, so encoding
# is delegated to python3 (already a required tool): a hostile id can
# neither inject JSON nor break the terminal record. (NUL cannot travel
# a shell variable at all, so it truncates at capture; every other byte
# survives.)
json_escape() {
    printf '%s' "$1" | python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.stdin.read()))'
}

# json_or_null VALUE: print VALUE (a canonical integer or "true") or null.
json_or_null() {
    if [ -n "${1-}" ]; then
        printf '%s' "$1"
    else
        printf 'null'
    fi
}

# compute_rates: derive completed counts and throughput rates from the
# validated worker outcomes (HAVE_COUNTS and the RESULT_* globals).
# Safe in trap context (no files, no background jobs): awk only.
# Completed means successfully measured (success/timeout/error);
# unknown outcomes finished but unclassified, so they count as bad,
# not completed. Wall rates use the worker's measured elapsed (the
# matched population interval), never the controller's sampling
# window. A zero/unmeasured elapsed, no completed work, no busy time,
# or any clamped op leaves its rate null (never zero, never mixed).
# Overflow: the validator caps offered at int64max and enforces
# conservation, so every sum below is bounded by offered; busy_us is
# capped so the microsecond-to-nanosecond scaling cannot wrap.
compute_rates() {
    COMPLETED=""; BAD_OUTCOMES=""; BUSY_NS=""
    COMPLETED_PER_WALL=""; OK_PER_WALL=""; COMPLETED_PER_BUSY=""
    if [ "$HAVE_COUNTS" != true ]; then
        return 0
    fi
    COMPLETED=$((R_SUCCESS + R_TIMEOUT + R_ERROR))
    BAD_OUTCOMES=$((R_TIMEOUT + R_ERROR + R_UNKNOWN + R_UNFINISHED))
    BUSY_NS=$((RESULT_BUSY_US * 1000))
    if [ "$RESULT_ELAPSED_S" -gt 0 ]; then
        COMPLETED_PER_WALL=$(awk "BEGIN { printf \"%.9f\", $COMPLETED / $RESULT_ELAPSED_S }")
        OK_PER_WALL=$(awk "BEGIN { printf \"%.9f\", $R_SUCCESS / $RESULT_ELAPSED_S }")
    fi
    if [ "$COMPLETED" -gt 0 ] && [ "$BUSY_NS" -gt 0 ] && [ "$RESULT_CLAMPED_OPS" -eq 0 ]; then
        COMPLETED_PER_BUSY=$(awk "BEGIN { printf \"%.9f\", $COMPLETED / ($BUSY_NS / 1000000000) }")
    fi
    return 0
}

# Defined early: trap-time recovery calls it before the main flow
# reaches step 12, and bash must execute a definition before any
# call (a trap firing mid-run would otherwise see no such command).
# validate_result_file: strict validation (exact schema, run match,
# outcome conservation, representable bounds). The worker is ours
# (provisioned bytes in an owned container), so any deviation —
# including extra keys — is a foreign or corrupt record, not a
# version to tolerate. A run-matching partial checkpoint
# (complete:false) validates: its finished outcomes are published
# with complete:false, never silently dropped.
validate_result_file() {
    # $1 = result path. Shared by the main flow and trap-time
    # recovery: the same validator and the same bounds, so a
    # recovered checkpoint is held to the identical bar. (Body keeps
    # its historical indentation from the inline block.)
    # Trap-safe: files under $WORK (present before cleanup), fresh
    # python3 children, no background jobs, no signals.
    local result_path="$1"
    [ -z "$RESULT_ERROR" ] || return 0
    # The validator speaks JSON only: one envelope object on stdout
    # (validated fields, or the fixed-vocabulary defect plus the
    # observed run id for debugging). Foreign bytes never travel
    # shell-parsed key=value lines, so a hostile run id can inject no
    # counts; it is extracted below as an opaque string and encoded
    # completely at publication. Unbounded Python integers are checked
    # against int64 before any shell arithmetic sees them (bash would
    # wrap them into false outcomes), including the busy-time scaling.
    VALIDATED=""
    VALIDATED="$(python3 - "$result_path" "$RUN_NAME" <<'PYEOF' 2>"$WORK/result-validate.err"
import json, sys
path, run = sys.argv[1], sys.argv[2]
INT64MAX = 2**63 - 1
BUSY_US_MAX = INT64MAX // 1000
envelope = {"ok": False, "defect": "worker result invalid: validator failed", "observed_run_id": None}
def fail(message):
    envelope["defect"] = message
    print(json.dumps(envelope))
    sys.exit(1)
try:
    with open(path) as handle:
        record = json.load(handle)
except (OSError, ValueError):
    fail("worker result invalid: not parseable JSON")
if not isinstance(record, dict):
    fail("worker result invalid: not a JSON object")
observed = record.get("run_id")
if isinstance(observed, str):
    envelope["observed_run_id"] = observed
if set(record) != {"schema", "run_id", "complete", "offered", "counts", "busy_us", "elapsed_s", "clamped_ops"}:
    fail("worker result invalid: schema keys mismatch")
if record["schema"] != "soak-worker-result/1":
    fail("worker result invalid: schema mismatch")
if record["run_id"] != run:
    fail("worker result invalid: run id mismatch")
if record["complete"] is not True and record["complete"] is not False:
    fail("worker result invalid: complete must be boolean")
def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)
counts = record["counts"]
if not isinstance(counts, dict) or set(counts) != {"success", "timeout", "error", "unknown", "unfinished"}:
    fail("worker result invalid: counts keys mismatch")
values = {}
for key in ("success", "timeout", "error", "unknown", "unfinished"):
    value = counts[key]
    if not is_int(value) or value < 0:
        fail("worker result invalid: counts must be non-negative integers")
    values[key] = value
offered = record["offered"]
if not is_int(offered) or offered < 0:
    fail("worker result invalid: offered must be a non-negative integer")
if sum(values.values()) != offered:
    fail("worker result invalid: counts do not sum to offered")
for key in ("busy_us", "elapsed_s", "clamped_ops"):
    if not is_int(record[key]) or record[key] < 0:
        fail(f"worker result invalid: {key} must be a non-negative integer")
if offered > INT64MAX:
    fail("worker result invalid: offered exceeds representable bounds")
if record["busy_us"] > BUSY_US_MAX:
    fail("worker result invalid: busy time exceeds representable bounds")
if record["elapsed_s"] > INT64MAX or record["clamped_ops"] > INT64MAX:
    fail("worker result invalid: timing exceeds representable bounds")
print(json.dumps({
    "ok": True,
    "complete": record["complete"],
    "offered": offered,
    "success": values["success"],
    "timeout": values["timeout"],
    "error": values["error"],
    "unknown": values["unknown"],
    "unfinished": values["unfinished"],
    "busy_us": record["busy_us"],
    "elapsed_s": record["elapsed_s"],
    "clamped_ops": record["clamped_ops"],
    "observed_run_id": observed,
}))
PYEOF
)" || true
    printf '%s' "$VALIDATED" > "$WORK/result-validated.json"
    # Verified extraction: the extractor prints shell lines for fields
    # it re-checks (ints, booleans, the fixed-vocabulary defect) and
    # fails otherwise, so the shell loop below never parses foreign
    # bytes. The observed run id travels separately, as an opaque
    # string that is captured whole, never parsed.
    v_extract=""
    v_extract=$(python3 - "$WORK/result-validated.json" <<'PYEOF' 2>/dev/null || true
import json, sys
def fail():
    sys.exit(1)
try:
    with open(sys.argv[1]) as handle:
        doc = json.load(handle)
except (OSError, ValueError):
    fail()
if not isinstance(doc, dict):
    fail()
if doc.get("ok") is True:
    out = ["ok=true"]
    complete = doc.get("complete")
    if complete is True:
        out.append("complete=true")
    elif complete is False:
        out.append("complete=false")
    else:
        fail()
    for key in ("offered", "success", "timeout", "error", "unknown", "unfinished", "busy_us", "elapsed_s", "clamped_ops"):
        value = doc.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            fail()
        out.append("%s=%d" % (key, value))
    print("\n".join(out))
elif doc.get("ok") is False:
    defect = doc.get("defect", "")
    if not isinstance(defect, str) or "\n" in defect:
        fail()
    print("ok=false")
    print("defect=%s" % defect)
else:
    fail()
PYEOF
)
    v_key=""; v_val=""; v_ok=""
    while IFS='=' read -r v_key v_val || [ -n "$v_key" ]; do
        case "$v_key" in
            ok) v_ok="$v_val" ;;
            defect)
                RESULT_ERROR="$v_val"
                ;;
            offered) RESULT_OFFERED="$v_val" ;;
            success) R_SUCCESS="$v_val" ;;
            timeout) R_TIMEOUT="$v_val" ;;
            error) R_ERROR="$v_val" ;;
            unknown) R_UNKNOWN="$v_val" ;;
            unfinished) R_UNFINISHED="$v_val" ;;
            busy_us) RESULT_BUSY_US="$v_val" ;;
            elapsed_s) RESULT_ELAPSED_S="$v_val" ;;
            clamped_ops) RESULT_CLAMPED_OPS="$v_val" ;;
            complete) RESULT_COMPLETE="$v_val" ;;
        esac
    done <<< "$v_extract"
    RESULT_RUN_ID=$(python3 -c 'import json,sys; doc=json.load(open(sys.argv[1])); observed=doc.get("observed_run_id") if isinstance(doc,dict) else None; sys.stdout.write(observed if isinstance(observed,str) else "")' "$WORK/result-validated.json" 2>/dev/null || true)
    if [ "$v_ok" = true ]; then
        # Validated fields are carried above; open the carry window
        # at once, so a signal after validation (even before the
        # verdict math) publishes known outcomes instead of nulls.
        HAVE_COUNTS=true
    elif [ "$v_ok" = false ]; then
        if [ -z "$RESULT_ERROR" ]; then
            RESULT_ERROR="worker result invalid: validator failed"
        fi
        cat "$WORK/result-validate.err" >&2 2>/dev/null || true
    else
        RESULT_ERROR="worker result invalid: validator failed"
        cat "$WORK/result-validate.err" >&2 2>/dev/null || true
    fi
}

# bounds_json: the effective numeric bounds. Only called after input
# validation, so every value is a canonical integer.
bounds_json() {
    printf '{"setup_timeout_s": %s, "sample_timeout_s": %s, "worker_grace_s": %s, "op_timeout_s": %s, "cleanup_grace_s": %s, "warmup_s": %s, "sample_interval_s": %s, "window_samples": %s}' \
        "$SETUP_TIMEOUT" "$SAMPLE_TIMEOUT" "$WORKER_GRACE" "$OP_TIMEOUT" "$CLEANUP_GRACE" "$WARMUP" "$SAMPLE_INTERVAL" "$WINDOW"
}

# unresolved_json: the recorded-unresolved PID list (canonical integers).
unresolved_json() {
    local out
    if [ "${#UNRESOLVED_PIDS[@]}" -eq 0 ]; then
        echo "[]"
    else
        # Set semantics: overlapping terminations may record the same
        # PID twice; the report lists each once, numerically sorted.
        out=$(printf '%s\n' "${UNRESOLVED_PIDS[@]}" | sort -nu | awk 'BEGIN { ORS="," } { print }')
        echo "[${out%,}]"
    fi
}

# write_interrupted SIGNAL_NAME: publish the terminal FAIL_INTERRUPTED
# record. Runs in trap context after ownership was terminated, so
# cleanup_ok/unresolved_pids describe the real post-signal state.
# Setup-phase identities that were already measured are published, and
# worker outcomes validated before the signal are carried (never
# re-nulled); every other field stays null. Never fails.
# shellcheck disable=SC2329 # reached only via the INT/TERM traps below
write_interrupted() {
    local sig_name="$1" reader_fault="$2" tmp
    local cleanup_ok unresolved reasons
    if [ "${#UNRESOLVED_PIDS[@]}" -eq 0 ] && [ "$reader_fault" != true ] && [ "$CONTAINER_UNVERIFIED" != true ]; then
        cleanup_ok=true
    else
        cleanup_ok=false
    fi
    unresolved=$(unresolved_json)
    reasons=$(json_escape "interrupted by $sig_name during $PHASE")
    if [ "${#UNRESOLVED_PIDS[@]}" -gt 0 ]; then
        reasons="$reasons, $(json_escape "unresolved owned processes: ${#UNRESOLVED_PIDS[@]}")"
    fi
    if [ "$reader_fault" = true ]; then
        reasons="$reasons, $(json_escape "owned process states could not be verified: /proc reads failed")"
    fi
    if [ "$CONTAINER_UNVERIFIED" = true ]; then
        reasons="$reasons, $(json_escape "container-side termination could not be verified")"
    fi
    if [ "$HAVE_COUNTS" = true ] && [ "$RESULT_COMPLETE" != true ]; then
        reasons="$reasons, $(json_escape "worker result is a partial checkpoint (interrupted before any terminal record)")"
    fi
    local run_json="null" module_json="null" image_json="null" config_json="null"
    local revision_json="null" corpus_json="null" samples_n="null"
    if [ -n "$RUN_NAME" ]; then run_json=$(json_escape "$RUN_NAME"); fi
    if [ -n "${MODULE_PATH-}" ]; then module_json=$(json_escape "$MODULE_PATH"); fi
    if [ -n "${IMAGE_ID-}" ]; then image_json=$(json_escape "$IMAGE_ID"); fi
    if [ -n "${IMAGE_ID-}" ]; then config_json=$(json_escape "$IMAGE_ID"); fi
    if [ -n "${REVISION-}" ]; then revision_json=$(json_escape "$REVISION"); fi
    if [ -n "${CORPUS_HASH-}" ]; then corpus_json=$(json_escape "$CORPUS_HASH"); fi
    if [ -f "$OUT_DIR/soak_samples.csv" ]; then
        samples_n=$(awk 'END { print (NR > 0 ? NR - 1 : 0) }' "$OUT_DIR/soak_samples.csv" 2>/dev/null || echo "null")
        [[ "$samples_n" =~ ^[0-9]+$ ]] || samples_n="null"
    fi
    # Carried outcomes: validated before the signal, published as-is.
    # (compute_rates touches no files, so it is trap-safe.)
    local worker_exit_json="null" worker_complete="null" result_run_json="null" elapsed_json="null"
    local offered_json="null" counts_json="null" completed_json="null"
    local ok_signs="null" fail_signs="null" busy_json="null"
    local per_wall="" ok_wall="" per_busy=""
    if [ -n "$WORKER_EXIT" ]; then worker_exit_json="$WORKER_EXIT"; fi
    if [ -n "$RESULT_RUN_ID" ]; then result_run_json=$(json_escape "$RESULT_RUN_ID"); fi
    if [ -n "$RESULT_ELAPSED_S" ]; then elapsed_json="$RESULT_ELAPSED_S"; fi
    if [ "$HAVE_COUNTS" = true ]; then
        compute_rates
        worker_complete="$RESULT_COMPLETE"
        offered_json="$RESULT_OFFERED"
        counts_json="{\"success\": $R_SUCCESS, \"timeout\": $R_TIMEOUT, \"error\": $R_ERROR, \"unknown\": $R_UNKNOWN, \"unfinished\": $R_UNFINISHED, \"censored\": 0, \"total\": $RESULT_OFFERED}"
        completed_json="$COMPLETED"
        ok_signs="$R_SUCCESS"
        fail_signs="$BAD_OUTCOMES"
        busy_json="$BUSY_NS"
        per_wall="$COMPLETED_PER_WALL"; ok_wall="$OK_PER_WALL"; per_busy="$COMPLETED_PER_BUSY"
    fi
    tmp="$OUT_DIR/.soak.json.tmp"
    cat > "$tmp" <<EOF || return 0
{
  "schema": "soak-summary/1",
  "verdict": "FAIL_INTERRUPTED",
  "signal": "$sig_name",
  "run_id": $run_json,
  "duration_s": $DURATION,
  "target_rps": $RPS,
  "warmup_s": $WARMUP,
  "sample_interval_s": $SAMPLE_INTERVAL,
  "worker_grace_s": $WORKER_GRACE,
  "op_timeout_s": $OP_TIMEOUT,
  "limits": {"max_rss_growth_mb": $MAX_RSS_GROWTH, "max_fd_growth": $MAX_FD_GROWTH, "provenance": "$LIMITS_PROV"},
  "identities": {"receipt_version": "soak/1", "mode": "proxied", "provider": {"module": $module_json, "image": $image_json, "config_fingerprint": $config_json}, "workload": {"revision": $revision_json, "corpus_hash": $corpus_json}},
  "worker": {"exit": $worker_exit_json, "acked": $WORKER_ACKED, "complete": $worker_complete, "result_run_id": $result_run_json, "elapsed_s": $elapsed_json},
  "offered": $offered_json,
  "counts": $counts_json,
  "completed": $completed_json,
  "completed_per_wall_s": $(json_or_null "$per_wall"),
  "ok_per_wall_s": $(json_or_null "$ok_wall"),
  "completed_per_busy_s": $(json_or_null "$per_busy"),
  "busy_ns": $busy_json,
  "wall_s": null,
  "samples": {"n": $samples_n, "n_warmup_excluded": null, "baseline": {"start_s": null, "end_s": null, "n": 0, "rss_kb": null, "fds": null}, "final": {"start_s": null, "end_s": null, "n": 0, "rss_kb": null, "fds": null}, "peak_rss_kb": null, "peak_fds": null},
  "ok_signs": $ok_signs,
  "fail_signs": $fail_signs,
  "initial_rss_kb": null,
  "final_rss_kb": null,
  "delta_rss_mb": null,
  "final_open_fds": null,
  "cleanup_ok": $cleanup_ok,
  "unresolved_pids": $unresolved,
  "bounds": $(bounds_json),
  "reasons": [$reasons]
}
EOF
    mv "$tmp" "$OUT_DIR/soak.json" 2>/dev/null || true
}

# shellcheck disable=SC2329 # invoked indirectly via the EXIT trap
on_exit() {
    local code=$?
    cleanup_once
    exit "$code"
}

# on_signal CODE NAME: stop everything, publish the terminal record
# (unless the run already published one), and keep the 128+signal exit
# status. Further INT/TERM are neutralized first so the bounded
# escalation below always runs to completion.
# recover_checkpoint: salvage the worker's latest checkpoint before
# destructive signal cleanup deletes it. Bounded and best-effort: a
# frozen (stopped) container is copied and the record validated to the
# identical bar; any failure leaves HAVE_COUNTS false (nulls,
# honestly). Only runs pre-validation (post-validation counts are
# never replaced). Never fails. Trap-called with signals neutralized.
# shellcheck disable=SC2329 # reached only via on_signal below
recover_checkpoint() {
    local stop_ok cp_ok prior_result_error
    [ "$RUN_CREATED" = 1 ] || return 0
    [ "$HAVE_COUNTS" = true ] && return 0
    # A signal between container creation and worker spawn has no
    # result path yet (nothing could have checkpointed).
    [ -n "${RESULT_PATH-}" ] || return 0
    rm -f "$WORK/recover-stop.done" "$WORK/recover.done" "$WORK/recover.json"
    ( set +e; docker stop -t 1 "$RUN_NAME" >"$WORK/recover-stop.log" 2>&1; code=$?; echo "$code" >"$WORK/recover-stop.done"; exit "$code" ) &
    RECOVER_PID=$!
    stop_ok=false
    if await_step 6 "$RECOVER_PID" "$WORK/recover-stop.done"; then
        if [ "$JOIN_TIMED_OUT" -eq 0 ] && [ -n "$AWAIT_CODE" ] && [ "$AWAIT_CODE" -eq 0 ]; then
            stop_ok=true
        fi
    fi
    RECOVER_PID=""
    [ "$stop_ok" = true ] || return 0
    ( set +e; docker cp "$RUN_NAME:$RESULT_PATH" "$WORK/recover.json" >"$WORK/recover.log" 2>&1; code=$?; echo "$code" >"$WORK/recover.done"; exit "$code" ) &
    RECOVER_PID=$!
    cp_ok=false
    if await_step 5 "$RECOVER_PID" "$WORK/recover.done"; then
        if [ "$JOIN_TIMED_OUT" -eq 0 ] && [ -n "$AWAIT_CODE" ] && [ "$AWAIT_CODE" -eq 0 ]; then
            cp_ok=true
        fi
    fi
    RECOVER_PID=""
    [ "$cp_ok" = true ] || return 0
    # A stale main-flow error (failed retirement/copy) must not veto
    # this fresh record: validate the just-copied file on its own
    # merits. First-error-wins is preserved only when the fresh
    # validation fails (nothing new to carry); on success the fresh
    # outcomes supersede the stale diagnostic.
    prior_result_error="$RESULT_ERROR"
    RESULT_ERROR=""
    validate_result_file "$WORK/recover.json" || true
    if [ "$HAVE_COUNTS" != true ] && [ -n "$prior_result_error" ]; then
        RESULT_ERROR="$prior_result_error"
    fi
    return 0
}

# shellcheck disable=SC2329 # invoked indirectly via the INT/TERM traps
on_signal() {
    local code="$1" sig_name="$2"
    local reader_fault=false
    trap '' INT TERM
    # Salvage first: a checkpoint validated before destructive cleanup
    # becomes carried outcomes instead of nulls.
    recover_checkpoint || true
    # Snapshot the verification state around cleanup (which removes
    # $WORK): a faulted reader means the joins cannot verify their kills.
    # (If-form, not &&: a failing function probe in statement &&-position
    # trips set -e in nested trap contexts.)
    if reader_faulted; then
        reader_fault=true
    fi
    if [ "$CLEANUP_DONE" -eq 1 ]; then
        # A later signal landed inside exit-trap cleanup, which runs
        # exactly once: settle any in-flight helpers directly so none
        # is orphaned, and finish the scratch removal the abandoned
        # cleanup never reached. A removal helper killed here is
        # unconfirmed (no fresh attempt follows — the ack may already
        # have been written, but that is unknowable from here), so
        # removal fails closed. (A second signal during signal-trap
        # cleanup cannot arrive: further INT/TERM are neutralized
        # above.)
        # Obligation, not helper presence: a signal can land after a
        # helper was reaped but before its outcome is accounted with
        # nothing tracked but the container obligation still open. The
        # flags clear only on terminal confirmation (confirmed removal,
        # confirmed absence), so any set flag here means unverified.
        # (RM_PID set implies flags set — helpers dispatch only under an
        # open obligation — so the flags subsume the old helper-presence
        # check.)
        if [ "$RUN_CREATED" -eq 1 ] || [ "$RUN_DISPATCHED" -eq 1 ]; then
            CONTAINER_UNVERIFIED=true
        fi
        terminate_owned
        rm -rf "$WORK" 2>/dev/null || true
    fi
    cleanup_once
    [ "$CLEANUP_SAW_FAULT" = true ] && reader_fault=true
    # A published terminal record is never overwritten: the latch
    # commits only after this write succeeds, and the file check
    # closes the microsecond between the main flow's rename and its
    # own latch write (a signal landing there keeps the published
    # record and only the exit status reports the interruption).
    if [ -z "$SUMMARY_DONE" ] && [ ! -f "$OUT_DIR/soak.json" ]; then
        write_interrupted "$sig_name" "$reader_fault" || true
        SUMMARY_DONE=1
        echo "soak $sig_name during $PHASE; terminal summary written" >&2 || true
    else
        echo "soak $sig_name during $PHASE; terminal summary already published" >&2 || true
    fi
    exit "$code"
}
# shellcheck disable=SC2329 # invoked indirectly via trap
on_int() { on_signal 130 SIGINT; }
# shellcheck disable=SC2329 # invoked indirectly via trap
on_term() { on_signal 143 SIGTERM; }
trap on_exit EXIT
trap on_int INT
trap on_term TERM

echo "=== Soak: ${DURATION}s @ ${RPS}rps ==="

# 1. Bring up daemon-softhsm2 + a single consumer-shell container that
#    donates the worker container's image, proxy env, and network
#    namespace. Each setup step runs in the background under its own
#    monotonic bound so signals stay prompt.
PHASE="setup:compose-up"
run_setup_step compose-up "$SETUP_TIMEOUT" "${COMPOSE[@]}" --profile softhsm2 up -d daemon-softhsm2 consumer-shell
PHASE="setup:startup-sleep"
run_setup_step startup-sleep "$SETUP_TIMEOUT" sleep 5

# 2. Find the daemon's PID (host) for RSS sampling, and refuse to run
#    blind when it cannot be measured.
PHASE="setup:inspect"
run_setup_step inspect "$SETUP_TIMEOUT" docker inspect --format '{{.State.Pid}}' consumer-matrix-daemon
inspect_raw=$(cat "$WORK/setup-inspect.log")
daemon_pid="${inspect_raw//[[:space:]]/}"
if ! daemon_pid="$(canon_int "$daemon_pid")" || [ "$daemon_pid" -lt 1 ]; then
    echo "error: daemon PID from 'docker inspect' is not a positive integer: '$inspect_raw'" >&2
    exit 2
fi
echo "daemon PID (host): $daemon_pid"
# The gate measures: a readable status file without a usable VmRSS
# line refuses exactly like a missing one (readability alone would
# admit a daemon whose RSS can never be sampled).
daemon_rss_gate="$(awk '/^VmRSS:/ { print $2 }' "$PROC_ROOT/$daemon_pid/status" 2>/dev/null || true)"
daemon_rss_gate="${daemon_rss_gate//[[:space:]]/}"
if ! daemon_rss_gate="$(canon_int "$daemon_rss_gate")" || [ -z "$daemon_rss_gate" ]; then
    echo "error: daemon PID $daemon_pid has no usable VmRSS measurement via '$PROC_ROOT/$daemon_pid/status'" >&2
    exit 2
fi

# 3. Read the donor shell's image and env. The shim module path is
#    required (the worker cannot sign without it); the proxy env is
#    forwarded by allowlist so the script never hardcodes coordinates.
PHASE="setup:inspect-shell"
run_setup_step inspect-shell "$SETUP_TIMEOUT" docker inspect --format '{{println .Config.Image}}{{range .Config.Env}}{{println .}}{{end}}' consumer-matrix-shell
shell_raw=$(cat "$WORK/setup-inspect-shell.log")
RUN_IMAGE=""
RUN_ENV_ARGS=()
MODULE_PATH=""
shell_first=true
shell_line=""
shell_key=""
while IFS= read -r shell_line || [ -n "$shell_line" ]; do
    if [ "$shell_first" = true ]; then
        shell_first=false
        RUN_IMAGE="$shell_line"
        continue
    fi
    if [ -z "$shell_line" ]; then
        continue
    fi
    case "$shell_line" in
        *=*)
            shell_key="${shell_line%%=*}"
            if [[ ! "$shell_key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
                echo "error: shell env key is not a valid identifier: '$shell_key'" >&2
                exit 2
            fi
            case "$shell_key" in
                PKCS11_PROXY_ENDPOINT|PKCS11_PROXY_CONNECT_TIMEOUT|PKCS11_MODULE_PATH|DAEMON_HOST|DAEMON_PORT|RUST_LOG)
                    RUN_ENV_ARGS+=(-e "$shell_line")
                    if [ "$shell_key" = "PKCS11_MODULE_PATH" ]; then
                        MODULE_PATH="${shell_line#*=}"
                    fi
                    ;;
                *)
                    echo "warning: not forwarding shell env '$shell_key'" >&2
                    ;;
            esac
            ;;
        *)
            echo "error: malformed shell env line (no '='): '$shell_line'" >&2
            exit 2
            ;;
    esac
done <<< "$shell_raw"
if [[ ! "$RUN_IMAGE" =~ ^[A-Za-z0-9][A-Za-z0-9./:@_+-]*$ ]]; then
    echo "error: shell image is not a valid image reference: '$RUN_IMAGE'" >&2
    exit 2
fi
if [ -z "$MODULE_PATH" ]; then
    echo "error: donor shell has no PKCS11_MODULE_PATH; the worker could not sign" >&2
    exit 2
fi

# 4. Read the daemon's image id (the provider/config fingerprint: the
#    daemon config is baked into its image at build time). Descriptive
#    only: a fast refusal nulls the identity with a recorded reason and
#    the run continues; a hung inspect means a sick daemon and refuses.
PHASE="setup:inspect-image"
IMAGE_ID=""
IMAGE_REASON=""
image_log="$WORK/setup-inspect-image.log"
image_done="$WORK/setup-inspect-image.done"
rm -f "$image_done"
( set +e; docker inspect --format '{{.Image}}' consumer-matrix-daemon >"$image_log" 2>&1; code=$?; echo "$code" >"$image_done"; exit "$code" ) &
SETUP_PID=$!
if ! await_step "$SETUP_TIMEOUT" "$SETUP_PID" "$image_done"; then
    echo "error: monotonic clock unreadable during setup step 'inspect-image'" >&2
    SETUP_PID=""
    exit 2
fi
SETUP_PID=""
if [ "$JOIN_TIMED_OUT" -eq 1 ]; then
    echo "error: setup step 'inspect-image' timed out after ${SETUP_TIMEOUT}s" >&2
    cat "$image_log" >&2 || true
    exit 2
fi
image_failed=0
if [ -n "$AWAIT_CODE" ] && [ "$AWAIT_CODE" -ne 0 ]; then image_failed=1; fi
if [ "$REAP_RESULT" != "unreaped" ] && [ "$REAP_RESULT" -ne 0 ]; then image_failed=1; fi
if [ "$image_failed" -eq 1 ]; then
    echo "warning: daemon image inspect failed; provider identity will be null" >&2
    cat "$image_log" >&2 || true
    IMAGE_REASON="provider image unmeasurable: inspect failed"
elif [ "$REAP_RESULT" = "unreaped" ]; then
    echo "warning: setup step 'inspect-image' finished but its process state is unverifiable; continuing" >&2
    image_raw=$(cat "$image_log" 2>/dev/null || true)
    IMAGE_ID="${image_raw%%$'\n'*}"
    IMAGE_ID="${IMAGE_ID//[[:space:]]/}"
    if [ -z "$IMAGE_ID" ]; then
        IMAGE_REASON="provider image unmeasurable: inspect output empty"
    fi
else
    image_raw=$(cat "$image_log")
    IMAGE_ID="${image_raw%%$'\n'*}"
    IMAGE_ID="${IMAGE_ID//[[:space:]]/}"
    if [ -z "$IMAGE_ID" ]; then
        IMAGE_REASON="provider image unmeasurable: inspect output empty"
    fi
fi

# Daemon FD-count payload. The daemon image's sh is BusyBox ash, which
# has no pipefail, so the ls status propagates explicitly: an ls
# failure exits 1 (an empty cell, never wc's fabricated zero). Single
# quotes are deliberate: the payload expands on the daemon, not here.
# shellcheck disable=SC2016 # expansion happens inside the daemon container
FD_PAYLOAD='out=$(ls /proc/1/fd 2>/dev/null) || exit 1; if [ -z "$out" ]; then echo 0; else printf "%s\n" "$out" | wc -l; fi'

# 5. Prove the FD dimension measurable before any work runs: one exec
#    read, refused outright when it fails.
PHASE="setup:fd-gate"
run_setup_step fd-gate "$SETUP_TIMEOUT" docker exec consumer-matrix-daemon sh -c "$FD_PAYLOAD"
fd_gate_raw=$(cat "$WORK/setup-fd-gate.log")
fd_gate="${fd_gate_raw//[[:space:]]/}"
if ! fd_gate="$(canon_int "$fd_gate")"; then
    echo "error: daemon FD count is not measurable: '$fd_gate_raw'" >&2
    exit 2
fi

# 6. Create the exclusively owned worker container that hosts this
#    run's load. It shares the consumer-shell network namespace (so
#    `daemon` resolves) and forwards the shell's proxy env plus the
#    token coordinates from the shared consumer defaults. Removal is
#    authoritative (phase 9 plus the exit trap).
# shellcheck disable=SC1091 # tests/consumers/scripts/common.sh is a repo sibling
. "$CONSUMERS_DIR/scripts/common.sh"
RUN_NAME="soak-$$-$RANDOM$RANDOM"
RESULT_PATH="/tmp/soak_result-$RUN_NAME.txt"
# Run-unique key coordinates (the token label/pin stay shared
# defaults): one fresh pair per run, never deleted, never reused.
KEY_LABEL="matrix-key-$RUN_NAME"
KEY_ID_HEX=$(printf '%s' "$RUN_NAME" | cksum | awk '{ printf "%08x", $1 }')
# No --rm: retirement stops the container and copies the frozen
# result out of it, so the stopped container must persist until the
# explicit authoritative removal (auto-remove would race the copy).
run_cmd=(docker run -d --name "$RUN_NAME" --network container:consumer-matrix-shell --label "soak-run-id=$RUN_NAME")
if [ "${#RUN_ENV_ARGS[@]}" -gt 0 ]; then
    run_cmd+=("${RUN_ENV_ARGS[@]}")
fi
run_cmd+=(-e "TOKEN_LABEL=$TOKEN_LABEL" -e "USER_PIN=$USER_PIN" -e "KEY_LABEL=$KEY_LABEL" -e "KEY_ID=$KEY_ID_HEX")
run_cmd+=("$RUN_IMAGE" sleep infinity)
PHASE="setup:run-container"
# The attempt is registered before dispatch: if the client is killed
# or stalls after the daemon commits, the exit trap reconciles the
# ambiguous creation by its ownership label instead of skipping it.
RUN_DISPATCHED=1
run_setup_step run-container "$SETUP_TIMEOUT" "${run_cmd[@]}"
RUN_CREATED=1
RUN_DISPATCHED=0

# 7. Write the worker script (static bytes: every parameter arrives via
#    argv so the revision fingerprint is stable) and the fixed sign
#    corpus, then pipe both into the worker container.
WORKER_SCRIPT="$WORK/soak_worker.sh"
cat > "$WORKER_SCRIPT" <<'WORKER_EOF'
#!/bin/bash
# Soak worker: paced C_Sign loop with per-op timeouts, periodic
# checkpoints, and a terminal JSON result. Args: DURATION_SECS RPS
# OP_TIMEOUT_SECS RESULT_PATH.
# Bash-only: op timing needs EPOCHREALTIME (BusyBox date has no %N,
# so date-based timing would collapse to whole seconds). All timing
# is realtime-sourced: a backward clock step clamps an op's busy time
# to zero and counts the op as clamped (the controller nulls the busy
# rate when any op clamped), and the controller's monotonic join bound
# backstops a worker whose loop outlasts its window.
# Checkpoints (complete:false partials at the result path, rewritten
# after every finished op) preserve finished work when the worker dies
# before its terminal record; every write is atomic (tmp file plus
# rename), so a reader sees a whole record or the previous one, never
# a torn mix. The uncovered suffix is bounded by the in-flight write
# (at most one op, and the record is explicit about partiality). The
# terminal record is complete:true.
# Exits 0 after writing the result; nonzero without one. The run id is
# derived from the result path (no extra parameter to skew).
set -u
export LC_ALL=C
DUR="$1"; RPS="$2"; OP_TO="$3"; RESULT="$4"
# Container tmp for the input/output files (TEST ONLY override: the
# stub redirects it at its shared tmp; unset means /tmp).
CTMP=${SOAK_CONTAINER_TMP:-/tmp}
INPUT=$CTMP/soak_in.bin
SIG=$CTMP/soak_sig.bin
[ -f "$INPUT" ] || exit 1
DELAY=$(awk "BEGIN { printf \"%.6f\", 1.0 / $RPS }")
OFFERED=0; OK=0; TO=0; ERR=0; UNK=0; BUSY_US=0; CLAMPED=0
RUN_ID=${RESULT##*/}; RUN_ID=${RUN_ID#soak_result-}; RUN_ID=${RUN_ID%.txt}
write_record() { # $1=true|false (terminal or checkpoint)
    local complete="$1" now_s elapsed
    now_s=${EPOCHREALTIME%.*}
    elapsed=$((now_s - START))
    printf '{"schema": "soak-worker-result/1", "run_id": "%s", "complete": %s, "offered": %d, "counts": {"success": %d, "timeout": %d, "error": %d, "unknown": %d, "unfinished": %d}, "busy_us": %d, "elapsed_s": %d, "clamped_ops": %d}\n' \
        "$RUN_ID" "$complete" "$OFFERED" "$OK" "$TO" "$ERR" "$UNK" 0 "$BUSY_US" "$elapsed" "$CLAMPED" > "$RESULT.tmp" && mv "$RESULT.tmp" "$RESULT"
}
# The window starts after every setup cost (the awk spawn included):
# a bounded setup stall shrinks the window, never zeroes it.
START=${EPOCHREALTIME%.*}
END=$((START + DUR))
while [ "${EPOCHREALTIME%.*}" -lt "$END" ]; do
  OFFERED=$((OFFERED + 1))
  T0=${EPOCHREALTIME/.}
  if timeout -k 5 "$OP_TO" pkcs11-tool --module "$PKCS11_MODULE_PATH" \
      --token-label "$TOKEN_LABEL" --login --pin "$USER_PIN" \
      --sign --mechanism SHA256-RSA-PKCS --id "$KEY_ID" \
      --input-file "$INPUT" --output-file "$SIG" >/dev/null 2>&1; then
    EC=0
  else
    EC=$?
  fi
  T1=${EPOCHREALTIME/.}
  DT=$((T1 - T0))
  if [ "$DT" -lt 0 ]; then DT=0; CLAMPED=$((CLAMPED + 1)); fi
  BUSY_US=$((BUSY_US + DT))
  case $EC in
    0) OK=$((OK + 1));;
    124) TO=$((TO + 1));;
    127) UNK=$((UNK + 1));;
    *) ERR=$((ERR + 1));;
  esac
  # Checkpoint every finished op (best-effort: a failed checkpoint
  # must not kill the loop; the terminal record still lands).
  write_record false || true
  sleep "$DELAY"
done
write_record true
WORKER_EOF
WORKER_INPUT="$WORK/soak_in.bin"
printf '%s' "soak-test-data-v1:fixed-corpus-for-receipt-identity-0123456789abcd" > "$WORKER_INPUT"
# shellcheck disable=SC2329 # invoked by name via run_setup_step below
provision_worker_file() {
    # Plain `docker exec` has no -T flag (that is compose-only); -i
    # forwards the piped stdin the provisioned file comes from.
    docker exec -i "$RUN_NAME" sh -c "cat > $1" < "$2"
}
# shellcheck disable=SC2329 # invoked by name via run_setup_step below
provision_key() {
    # /scripts is baked into the consumer image (Dockerfile.consumer.shell),
    # so the worker carries the same shared defaults the shell uses. The
    # key is unique per run (no cleanup/delete cycle: deletes poison the
    # proxy's subsequent finds in the observed stack) and a trial sign
    # proves it usable before any load runs (refuse-before-work).
    docker exec "$RUN_NAME" sh -c '. /scripts/common.sh; ensure_rsa_key && pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$TOKEN_LABEL" --login --pin "$USER_PIN" --sign --mechanism SHA256-RSA-PKCS --id "$KEY_ID" --input-file /tmp/soak_in.bin --output-file /tmp/soak_trial.sig'
}
PHASE="setup:provision"
run_setup_step provision-worker "$SETUP_TIMEOUT" provision_worker_file /tmp/soak_worker.sh "$WORKER_SCRIPT"
run_setup_step provision-input "$SETUP_TIMEOUT" provision_worker_file /tmp/soak_in.bin "$WORKER_INPUT"
run_setup_step provision-key "$SETUP_TIMEOUT" provision_key

# 8. Fingerprint the provisioned bytes (cksum CRC + size): the workload
#    receipt identities. The controller checksums its own copies, which
#    are byte-identical to what the pipe delivered (the provision steps
#    above either transferred them whole or failed their exit status).
REVISION=$(cksum < "$WORKER_SCRIPT" | awk '{ print $1"-"$2 }')
CORPUS_HASH=$(cksum < "$WORKER_INPUT" | awk '{ print $1"-"$2 }')
if [ -z "$REVISION" ] || [ -z "$CORPUS_HASH" ]; then
    echo "error: could not fingerprint the provisioned worker bytes" >&2
    exit 2
fi

# --- Sampling ----------------------------------------------------------
# Empty fields mean "unavailable", never zero; corrupt (nonempty,
# non-canonical) tool output empties exactly its field so rows keep
# their shape. sample_rss echoes one value (possibly empty); sample_fds
# sets SAMPLE_FDS (never in a substitution: its helper must stay
# trap-visible and its unresolved harvest must reach the parent).
# Neither ever fails. The FD read is a tracked, bounded step: a sick
# daemon costs one empty cell, never the sampling loop.
SAMPLE_CLOCK_FAILED=0
SAMPLE_WAIT_TIMED_OUT=0
FD_SEQ=0
SAMPLE_FDS=""
sample_rss() {
    local rss
    rss=$(awk '/^VmRSS:/ { print $2 }' "$PROC_ROOT/$daemon_pid/status" 2>/dev/null || true)
    if [ -n "$rss" ]; then
        [[ "$rss" =~ ^(0|[1-9][0-9]*)$ ]] || rss=""
    fi
    printf '%s' "$rss"
    return 0
}
sample_fds() {
    local log done_file fds_raw fds
    FD_SEQ=$((FD_SEQ + 1))
    log="$WORK/sample-fd-$FD_SEQ.log"
    done_file="$WORK/sample-fd-$FD_SEQ.done"
    rm -f "$done_file"
    ( set +e; docker exec consumer-matrix-daemon sh -c "$FD_PAYLOAD" >"$log" 2>&1; code=$?; echo "$code" >"$done_file"; exit "$code" ) &
    SETUP_PID=$!
    # A clock failure returns 1 with the helper already settled: the
    # cell stays empty and the loop head trips the sampling latch on
    # its next read.
    if ! await_step "$SAMPLE_TIMEOUT" "$SETUP_PID" "$done_file"; then
        SETUP_PID=""
        SAMPLE_FDS=""
        return 0
    fi
    SETUP_PID=""
    fds=""
    if [ -n "$AWAIT_CODE" ] && [ "$AWAIT_CODE" = "0" ]; then
        fds_raw=$(cat "$log" 2>/dev/null || true)
        fds="${fds_raw//[[:space:]]/}"
        [[ "$fds" =~ ^(0|[1-9][0-9]*)$ ]] || fds=""
    fi
    SAMPLE_FDS="$fds"
    return 0
}

# 9. Spawn the owned worker (foreground exec: the CLI blocks until the
#    worker exits and the subshell records its real exit status), then
#    sample around it for DURATION monotonic seconds.
PHASE="run:spawn"
if ! sample_start=$(mono_now); then
    echo "error: monotonic clock unreadable at sampling start" >&2
    exit 2
fi
sample_end=$((sample_start + DURATION))
WORKER_DONE="$WORK/worker.done"
rm -f "$WORKER_DONE"
( set +e; docker exec "$RUN_NAME" bash /tmp/soak_worker.sh "$DURATION" "$RPS" "$OP_TIMEOUT" "$RESULT_PATH" >/dev/null 2>&1; code=$?; echo "$code" >"$WORKER_DONE"; exit "$code" ) &
WORKER_PID=$!

PHASE="run:sampling"
samples_csv="$OUT_DIR/soak_samples.csv"
echo "elapsed_s,rss_kb,open_fds" > "$samples_csv"
while :; do
    if ! now_s=$(mono_now); then
        echo "warning: monotonic clock unreadable during soak sampling; stopping early" >&2
        SAMPLE_CLOCK_FAILED=1
        break
    fi
    [ "$now_s" -ge "$sample_end" ] && break
    elapsed=$((now_s - sample_start))
    rss=$(sample_rss)
    sample_fds
    fds="$SAMPLE_FDS"
    printf '%s,%s,%s\n' "$elapsed" "$rss" "$fds" >> "$samples_csv"
    # Coarse log line every 5 min.
    if [ $((elapsed % 300)) -eq 0 ]; then
        echo "[elapsed=${elapsed}s] rss=${rss:-?}kB fds=${fds:-?}"
    fi
    # Bounded interruptible wait: the sleep runs as a tracked step
    # under the borrowed bounded-await machinery (done-file plus
    # monotonic deadline). A foreground sleep would defer signals; a
    # bare `wait` would hang unboundedly on a stalled sleep. The
    # bound exceeds the sleep by a fixed margin: a real sleep lands
    # on its mark plus scheduling overshoot, so an exact bound would
    # execute a finishing sleep.
    sample_sleep_done="$WORK/sample-sleep.done"
    sample_sleep_pid="$WORK/sample-sleep.pid"
    rm -f "$sample_sleep_done" "$sample_sleep_pid"
    # The interval sleep announces its own pid pre-exec (the exec
    # keeps the pid): the pidfile plus an exec-shaped command line
    # proves the specific wait is sleeping, not a transient poll.
    ( set +e; SAMPLE_SLEEP_PIDFILE="$sample_sleep_pid" bash -c 'echo $$ > "$SAMPLE_SLEEP_PIDFILE"; exec sleep "$1"' _ "$SAMPLE_INTERVAL"; code=$?; echo "$code" >"$sample_sleep_done"; exit "$code" ) &
    SLEEP_PID=$!
    if ! await_step "$((SAMPLE_INTERVAL + 5))" "$SLEEP_PID" "$sample_sleep_done"; then
        echo "error: monotonic clock unreadable during sample wait" >&2
        SAMPLE_CLOCK_FAILED=1
        SLEEP_PID=""
        break
    fi
    SLEEP_PID=""
    if [ "$JOIN_TIMED_OUT" -eq 1 ]; then
        SAMPLE_WAIT_TIMED_OUT=1
    fi
done
if ! wall_end=$(mono_now); then
    echo "warning: monotonic clock unreadable at sampling end" >&2
    SAMPLE_CLOCK_FAILED=1
    wall_end=""
fi

# 10. Join the worker: a bounded terminal acknowledgement (the done-file
#     with the real exit status) before the result is read. A worker
#     that never acknowledges is unfinished, however its result reads.
PHASE="run:join"
JOIN_CLOCK_FAILED=0
if ! await_step "$WORKER_GRACE" "$WORKER_PID" "$WORKER_DONE"; then
    echo "error: monotonic clock unreadable during worker join" >&2
    JOIN_CLOCK_FAILED=1
fi
WORKER_PID=""
WORKER_TIMED_OUT="$JOIN_TIMED_OUT"
WORKER_KILLED="$JOIN_KILLED"
if [ -f "$WORKER_DONE" ]; then
    done_code=$(cat "$WORKER_DONE" 2>/dev/null || echo "")
    if [[ "$done_code" =~ ^(0|[1-9][0-9]*)$ ]] && [ "$done_code" -le 255 ]; then
        WORKER_ACKED=true
        WORKER_EXIT="$done_code"
        # Defensive: the ack arrived but the bound had already expired
        # (the worker exited between grace expiry and escalation — a
        # microsecond race, untestable by construction). The ack is
        # real, the bound violation is recorded.
        if [ "$WORKER_TIMED_OUT" -eq 1 ]; then
            WORKER_LATE=true
        fi
    fi
fi

# 11. Retire the worker container, then copy its frozen result. A
#     settled host CLI does not establish actual-worker completion,
#     so the result is never read from a live filesystem: `docker
#     stop` freezes the worker (TERM, grace, KILL inside the runtime)
#     while retaining its filesystem, and `docker cp` copies the
#     frozen record. Removal still follows (authoritative cleanup).
PHASE="run:retire"
RESULT_JSON="$WORK/result.json"
RESULT_ERROR=""
RESULT_CLOCK_FAILED=0
RESULT_TIMED_OUT=0
RESULT_CODE=""
RETIRE_TIMED_OUT=0
stop_log="$WORK/retire.log"
stop_done="$WORK/retire.done"
rm -f "$stop_done"
( set +e; docker stop -t "$CLEANUP_GRACE" "$RUN_NAME" >"$stop_log" 2>&1; code=$?; echo "$code" >"$stop_done"; exit "$code" ) &
SETUP_PID=$!
if ! await_step "$((CLEANUP_GRACE + 5))" "$SETUP_PID" "$stop_done"; then
    echo "error: monotonic clock unreadable during worker retirement" >&2
    SAMPLE_CLOCK_FAILED=1
    RESULT_CLOCK_FAILED=1
fi
SETUP_PID=""
RETIRE_TIMED_OUT="$JOIN_TIMED_OUT"
RETIRE_CODE="$AWAIT_CODE"
if [ "$RESULT_CLOCK_FAILED" -eq 1 ]; then
    RESULT_ERROR="worker result unavailable: monotonic clock failed during retirement"
elif [ "$RETIRE_TIMED_OUT" -eq 1 ]; then
    RESULT_ERROR="worker result unavailable: container retirement timed out"
elif [ -z "$RETIRE_CODE" ] || [ "$RETIRE_CODE" -ne 0 ]; then
    RESULT_ERROR="worker result unavailable: container retirement failed"
fi
if [ -n "$RESULT_ERROR" ]; then
    cat "$stop_log" >&2 2>/dev/null || true
fi
# 11b. Copy the frozen result (unique per-run filename). Skipped when
#      retirement already failed: without a frozen filesystem there
#      is nothing sound to read.
PHASE="run:result"
result_log="$WORK/result-fetch.log"
result_done="$WORK/result-fetch.done"
if [ -z "$RESULT_ERROR" ]; then
    rm -f "$result_done" "$RESULT_JSON"
    ( set +e; docker cp "$RUN_NAME:$RESULT_PATH" "$RESULT_JSON" >"$result_log" 2>&1; code=$?; echo "$code" >"$result_done"; exit "$code" ) &
    SETUP_PID=$!
    if ! await_step "$SAMPLE_TIMEOUT" "$SETUP_PID" "$result_done"; then
        echo "error: monotonic clock unreadable during result copy" >&2
        SAMPLE_CLOCK_FAILED=1
        RESULT_CLOCK_FAILED=1
    fi
    SETUP_PID=""
    RESULT_TIMED_OUT="$JOIN_TIMED_OUT"
    RESULT_CODE="$AWAIT_CODE"
    if [ "$RESULT_CLOCK_FAILED" -eq 1 ]; then
        RESULT_ERROR="worker result unreadable: monotonic clock failed during copy"
    elif [ "$RESULT_TIMED_OUT" -eq 1 ]; then
        RESULT_ERROR="worker result unreadable: copy timed out after ${SAMPLE_TIMEOUT}s"
    elif [ -z "$RESULT_CODE" ] || [ "$RESULT_CODE" -ne 0 ]; then
        RESULT_ERROR="worker result missing: container copy failed"
    fi
    if [ -n "$RESULT_ERROR" ]; then
        cat "$result_log" >&2 2>/dev/null || true
    fi
fi

# 12. Validate the copied result.
validate_result_file "$RESULT_JSON"

# 13. Analyze the samples: warmup split, positional baseline/final
#     windows (first/last $WINDOW post-warmup rows; each value is the
#     median of the usable cells within, null when the window holds
#     none), endpoints (first/last usable overall), peaks, counts.
#     Medians use the nearest-rank middle (compare.py's p50), computed
#     over sort -n (awk holds no portable sort).
PHASE="run:analyze"
S_N=""; S_EXCL=""
S_BASE_START=""; S_BASE_END=""; S_BASE_N=""; S_BASE_RSS=""; S_BASE_FDS=""
S_FINAL_START=""; S_FINAL_END=""; S_FINAL_N=""; S_FINAL_RSS=""; S_FINAL_FDS=""
S_PEAK_RSS=""; S_PEAK_FDS=""
S_FIRST_RSS=""; S_LAST_RSS=""; S_LAST_FDS=""
S_DELTA_MB=""
analyze_vars="$(awk -F, -v warmup="$WARMUP" -v window="$WINDOW" -v work="$WORK" '
NR == 1 { next }
{
    if ($1 !~ /^(0|[1-9][0-9]*)$/) { next }
    elapsed = $1 + 0
    n++
    rss_ok = ($2 ~ /^(0|[1-9][0-9]*)$/)
    fds_ok = ($3 ~ /^(0|[1-9][0-9]*)$/)
    # Endpoints and peaks cover every row (warmup included): the
    # first/last usable reads overall anchor the raw delta.
    if (rss_ok) {
        if (initial_rss == "") { initial_rss = $2 + 0 }
        final_rss = $2 + 0
        if (peak_rss == "" || $2 + 0 > peak_rss) { peak_rss = $2 + 0 }
    }
    if (fds_ok) {
        final_fds = $3 + 0
        if (peak_fds == "" || $3 + 0 > peak_fds) { peak_fds = $3 + 0 }
    }
    if (elapsed < warmup) { excluded++; next }
    post++
    post_elapsed[post] = elapsed
    if (rss_ok) { post_rss[post] = $2 + 0 }
    if (fds_ok) { post_fds[post] = $3 + 0 }
    next
}
END {
    print "n=" (n + 0)
    print "excluded=" (excluded + 0)
    base_count = (post < window ? post : window)
    final_count = base_count
    final_from = post - final_count + 1
    if (post > 0) {
        print "base_start=" post_elapsed[1]
        print "base_end=" post_elapsed[base_count]
        print "final_start=" post_elapsed[final_from]
        print "final_end=" post_elapsed[post]
    }
    for (i = 1; i <= base_count; i++) {
        if (i in post_rss) { print post_rss[i] > (work "/base-rss.vals") }
        if (i in post_fds) { print post_fds[i] > (work "/base-fds.vals") }
    }
    for (i = final_from; i <= post; i++) {
        if (i in post_rss) { print post_rss[i] > (work "/final-rss.vals") }
        if (i in post_fds) { print post_fds[i] > (work "/final-fds.vals") }
    }
    print "base_n=" base_count
    print "final_n=" final_count
    if (initial_rss != "") { print "initial_rss=" initial_rss }
    if (final_rss != "") { print "final_rss=" final_rss }
    if (final_fds != "") { print "final_fds=" final_fds }
    if (peak_rss != "") { print "peak_rss=" peak_rss }
    if (peak_fds != "") { print "peak_fds=" peak_fds }
}
' "$samples_csv" 2>/dev/null || true)"
a_key=""; a_val=""
while IFS='=' read -r a_key a_val || [ -n "$a_key" ]; do
    case "$a_key" in
        n) S_N="$a_val" ;;
        excluded) S_EXCL="$a_val" ;;
        base_start) S_BASE_START="$a_val" ;;
        base_end) S_BASE_END="$a_val" ;;
        final_start) S_FINAL_START="$a_val" ;;
        final_end) S_FINAL_END="$a_val" ;;
        base_n) S_BASE_N="$a_val" ;;
        final_n) S_FINAL_N="$a_val" ;;
        initial_rss) S_FIRST_RSS="$a_val" ;;
        final_rss) S_LAST_RSS="$a_val" ;;
        final_fds) S_LAST_FDS="$a_val" ;;
        peak_rss) S_PEAK_RSS="$a_val" ;;
        peak_fds) S_PEAK_FDS="$a_val" ;;
    esac
done <<< "$analyze_vars"
# Median of a sorted value file (nearest-rank middle; empty when none).
median_of() {
    local file="$1"
    if [ ! -s "$file" ]; then
        printf ''
        return 0
    fi
    sort -n "$file" | awk '{ a[NR] = $1 } END { if (NR > 0) { print a[int((NR + 1) / 2)] } }'
    return 0
}
S_BASE_RSS=$(median_of "$WORK/base-rss.vals")
S_BASE_FDS=$(median_of "$WORK/base-fds.vals")
S_FINAL_RSS=$(median_of "$WORK/final-rss.vals")
S_FINAL_FDS=$(median_of "$WORK/final-fds.vals")
if [ -n "$S_FIRST_RSS" ] && [ -n "$S_LAST_RSS" ]; then
    S_DELTA_MB=$(( (S_LAST_RSS - S_FIRST_RSS) / 1024 ))
fi

# 14. Remove the worker container authoritatively (its record is
#     already fetched), then judge the run.
PHASE="run:cleanup"
if [ -n "${SOAK_REMOVAL_HOLD-}" ]; then
    # TEST ONLY: hold the pre-removal point while the marker exists
    # (signal-during-removal tests); one-second steps stay prompt.
    # The trap path never holds: removal under signal runs at once.
    # The arrival file lets tests barrier on the hold itself.
    : > "$SOAK_REMOVAL_HOLD.ack" 2>/dev/null || true
    while [ -e "$SOAK_REMOVAL_HOLD" ]; do sleep 1; done
fi
remove_run_container

PHASE="run:verdict"
REASONS=()
if [ -n "$IMAGE_REASON" ]; then
    REASONS+=("$IMAGE_REASON")
fi
# No reset: HAVE_COUNTS latches true at validation (a signal between
# a clear and its re-derivation would publish nulls over validated
# outcomes). It is false here exactly when validation never ran.
compute_rates
WORKLOAD_BAD=false
if [ "$WORKER_ACKED" != true ]; then
    WORKLOAD_BAD=true
    if [ "$WORKER_KILLED" -eq 1 ]; then
        REASONS+=("worker unfinished: no terminal acknowledgement (join escalated)")
    else
        REASONS+=("worker unfinished: no terminal acknowledgement")
    fi
fi
if [ "$WORKER_LATE" = true ]; then
    WORKLOAD_BAD=true
    REASONS+=("worker acknowledgement arrived after the ${WORKER_GRACE}s join bound")
fi
if [ "$WORKER_ACKED" = true ] && [ -n "$WORKER_EXIT" ] && [ "$WORKER_EXIT" -ne 0 ]; then
    WORKLOAD_BAD=true
    REASONS+=("worker exit status $WORKER_EXIT")
fi
if [ "$HAVE_COUNTS" = true ]; then
    if [ "$RESULT_COMPLETE" != true ]; then
        WORKLOAD_BAD=true
        REASONS+=("worker unfinished: result is a partial checkpoint, no terminal record")
    fi
    if [ "$BAD_OUTCOMES" -gt 0 ]; then
        WORKLOAD_BAD=true
        REASONS+=("workload failures: $R_TIMEOUT timeout, $R_ERROR error, $R_UNKNOWN unknown, $R_UNFINISHED unfinished (of $RESULT_OFFERED offered)")
    fi
    if [ "$COMPLETED" -eq 0 ]; then
        WORKLOAD_BAD=true
        REASONS+=("no completed work: 0 of $RESULT_OFFERED offered finished")
    fi
    # Verdict-neutral: the work finished, but the busy denominator is
    # untrusted (compute_rates already nulled the busy rate).
    if [ "$RESULT_CLAMPED_OPS" -gt 0 ]; then
        REASONS+=("op timing clamped for $RESULT_CLAMPED_OPS ops; busy rate unavailable")
    fi
fi
RESULT_BAD=false
if [ -n "$RESULT_ERROR" ]; then
    RESULT_BAD=true
    REASONS+=("$RESULT_ERROR")
fi
CLEANUP_BAD=false
if [ "${#UNRESOLVED_PIDS[@]}" -gt 0 ]; then
    CLEANUP_BAD=true
    REASONS+=("unresolved owned processes: ${#UNRESOLVED_PIDS[@]}")
fi
if reader_faulted; then
    CLEANUP_BAD=true
    REASONS+=("owned process states could not be verified: /proc reads failed")
fi
if [ "$CONTAINER_UNVERIFIED" = true ]; then
    CLEANUP_BAD=true
    REASONS+=("container-side termination could not be verified")
fi
RSS_BAD=false
if [ -n "$S_BASE_RSS" ] && [ -n "$S_FINAL_RSS" ]; then
    # Compared in KiB against limit*1024: truncating to MB first would
    # pass growth the limit forbids (a zero limit forbids any positive
    # growth at all).
    RSS_GROWTH_KB=$((S_FINAL_RSS - S_BASE_RSS))
    if [ "$RSS_GROWTH_KB" -gt $((MAX_RSS_GROWTH * 1024)) ]; then
        RSS_BAD=true
        REASONS+=("RSS growth ${RSS_GROWTH_KB} KiB exceeds the $((MAX_RSS_GROWTH * 1024)) KiB limit")
    fi
fi
FD_BAD=false
if [ -n "$S_BASE_FDS" ] && [ -n "$S_FINAL_FDS" ]; then
    FD_GROWTH=$((S_FINAL_FDS - S_BASE_FDS))
    if [ "$FD_GROWTH" -gt "$MAX_FD_GROWTH" ]; then
        FD_BAD=true
        REASONS+=("open-FD growth $FD_GROWTH exceeds the $MAX_FD_GROWTH limit")
    fi
fi
SAMPLER_BAD=false
if [ "$SAMPLE_CLOCK_FAILED" -eq 1 ]; then
    SAMPLER_BAD=true
    REASONS+=("monotonic clock unreadable during soak sampling")
fi
if [ "$JOIN_CLOCK_FAILED" -eq 1 ]; then
    SAMPLER_BAD=true
    REASONS+=("monotonic clock unreadable during worker join")
fi
if [ "$SAMPLE_WAIT_TIMED_OUT" -eq 1 ]; then
    SAMPLER_BAD=true
    REASONS+=("sample wait exceeded its ${SAMPLE_INTERVAL}s bound")
fi
if [ -z "$S_BASE_RSS" ]; then
    SAMPLER_BAD=true
    REASONS+=("baseline window has no usable RSS samples")
fi
if [ -z "$S_FINAL_RSS" ]; then
    SAMPLER_BAD=true
    REASONS+=("final window has no usable RSS samples")
fi
if [ -z "$S_BASE_FDS" ]; then
    SAMPLER_BAD=true
    REASONS+=("baseline window has no usable FD samples")
fi
if [ -z "$S_FINAL_FDS" ]; then
    SAMPLER_BAD=true
    REASONS+=("final window has no usable FD samples")
fi
VERDICT="PASS"
if [ "$WORKLOAD_BAD" = true ]; then
    VERDICT="FAIL_WORKLOAD"
elif [ "$RESULT_BAD" = true ]; then
    VERDICT="FAIL_RESULT"
elif [ "$CLEANUP_BAD" = true ]; then
    VERDICT="FAIL_CLEANUP"
elif [ "$RSS_BAD" = true ]; then
    VERDICT="FAIL_RSS_GROWTH"
elif [ "$FD_BAD" = true ]; then
    VERDICT="FAIL_FD_GROWTH"
elif [ "$SAMPLER_BAD" = true ]; then
    VERDICT="FAIL_SAMPLER"
fi

# The controller's sampling-window wall time (reported, never a rate
# denominator: compute_rates already derived the rates from the
# worker's measured elapsed).
WALL_S=""
if [ -n "$wall_end" ]; then
    WALL_S=$((wall_end - sample_start))
fi

# 15. Publish the terminal record atomically.
if [ -n "${SOAK_PUBLISH_HOLD-}" ]; then
    # TEST ONLY: hold the pre-publication point while the marker
    # exists (signal-during-publish tests); one-second steps stay
    # prompt. The arrival file lets tests barrier on the hold itself.
    : > "$SOAK_PUBLISH_HOLD.ack" 2>/dev/null || true
    while [ -e "$SOAK_PUBLISH_HOLD" ]; do sleep 1; done
fi
if [ "$CLEANUP_BAD" = true ]; then cleanup_ok=false; else cleanup_ok=true; fi
unresolved=$(unresolved_json)
reasons_json=""
for reason in ${REASONS[@]+"${REASONS[@]}"}; do
    if [ -n "$reasons_json" ]; then reasons_json="$reasons_json, "; fi
    reasons_json="$reasons_json$(json_escape "$reason")"
done
module_json="null"; image_json="null"; config_json="null"
if [ -n "$MODULE_PATH" ]; then module_json=$(json_escape "$MODULE_PATH"); fi
if [ -n "$IMAGE_ID" ]; then image_json=$(json_escape "$IMAGE_ID"); fi
if [ -n "$IMAGE_ID" ]; then config_json=$(json_escape "$IMAGE_ID"); fi
worker_complete="null"; counts_json="null"
offered_json="null"; completed_json="null"; ok_signs="null"; fail_signs="null"
busy_json="null"; elapsed_json="null"
if [ "$HAVE_COUNTS" = true ]; then
    worker_complete="$RESULT_COMPLETE"
    counts_json="{\"success\": $R_SUCCESS, \"timeout\": $R_TIMEOUT, \"error\": $R_ERROR, \"unknown\": $R_UNKNOWN, \"unfinished\": $R_UNFINISHED, \"censored\": 0, \"total\": $RESULT_OFFERED}"
    offered_json="$RESULT_OFFERED"
    completed_json="$COMPLETED"
    ok_signs="$R_SUCCESS"
    fail_signs="$BAD_OUTCOMES"
    busy_json="$BUSY_NS"
fi
worker_exit_json="null"; result_run_json="null"
if [ -n "$WORKER_EXIT" ]; then worker_exit_json="$WORKER_EXIT"; fi
if [ -n "$RESULT_RUN_ID" ]; then result_run_json=$(json_escape "$RESULT_RUN_ID"); fi
if [ -n "$RESULT_ELAPSED_S" ]; then elapsed_json="$RESULT_ELAPSED_S"; fi
tmp="$OUT_DIR/.soak.json.tmp"
cat > "$tmp" <<EOF
{
  "schema": "soak-summary/1",
  "verdict": "$VERDICT",
  "signal": null,
  "run_id": $(json_escape "$RUN_NAME"),
  "duration_s": $DURATION,
  "target_rps": $RPS,
  "warmup_s": $WARMUP,
  "sample_interval_s": $SAMPLE_INTERVAL,
  "worker_grace_s": $WORKER_GRACE,
  "op_timeout_s": $OP_TIMEOUT,
  "limits": {"max_rss_growth_mb": $MAX_RSS_GROWTH, "max_fd_growth": $MAX_FD_GROWTH, "provenance": "$LIMITS_PROV"},
  "identities": {"receipt_version": "soak/1", "mode": "proxied", "provider": {"module": $module_json, "image": $image_json, "config_fingerprint": $config_json}, "workload": {"revision": $(json_escape "$REVISION"), "corpus_hash": $(json_escape "$CORPUS_HASH")}},
  "worker": {"exit": $worker_exit_json, "acked": $WORKER_ACKED, "complete": $worker_complete, "result_run_id": $result_run_json, "elapsed_s": $elapsed_json},
  "offered": $offered_json,
  "counts": $counts_json,
  "completed": $completed_json,
  "completed_per_wall_s": $(json_or_null "$COMPLETED_PER_WALL"),
  "ok_per_wall_s": $(json_or_null "$OK_PER_WALL"),
  "completed_per_busy_s": $(json_or_null "$COMPLETED_PER_BUSY"),
  "busy_ns": $busy_json,
  "wall_s": $(json_or_null "$WALL_S"),
  "samples": {"n": $(json_or_null "$S_N"), "n_warmup_excluded": $(json_or_null "$S_EXCL"), "baseline": {"start_s": $(json_or_null "$S_BASE_START"), "end_s": $(json_or_null "$S_BASE_END"), "n": $(json_or_null "$S_BASE_N"), "rss_kb": $(json_or_null "$S_BASE_RSS"), "fds": $(json_or_null "$S_BASE_FDS")}, "final": {"start_s": $(json_or_null "$S_FINAL_START"), "end_s": $(json_or_null "$S_FINAL_END"), "n": $(json_or_null "$S_FINAL_N"), "rss_kb": $(json_or_null "$S_FINAL_RSS"), "fds": $(json_or_null "$S_FINAL_FDS")}, "peak_rss_kb": $(json_or_null "$S_PEAK_RSS"), "peak_fds": $(json_or_null "$S_PEAK_FDS")},
  "ok_signs": $ok_signs,
  "fail_signs": $fail_signs,
  "initial_rss_kb": $(json_or_null "$S_FIRST_RSS"),
  "final_rss_kb": $(json_or_null "$S_LAST_RSS"),
  "delta_rss_mb": $(json_or_null "$S_DELTA_MB"),
  "final_open_fds": $(json_or_null "$S_LAST_FDS"),
  "cleanup_ok": $cleanup_ok,
  "unresolved_pids": $unresolved,
  "bounds": $(bounds_json),
  "reasons": [$reasons_json]
}
EOF
mv "$tmp" "$OUT_DIR/soak.json"
# The publication latch commits only after the rename succeeds: a
# signal before this point publishes FAIL_INTERRUPTED instead.
SUMMARY_DONE=1

echo
cat "$OUT_DIR/soak.json"
echo
echo "Samples: $samples_csv"

if [ "$VERDICT" = "PASS" ]; then
    exit 0
else
    exit 1
fi
