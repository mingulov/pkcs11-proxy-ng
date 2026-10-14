#!/usr/bin/env bash
# Cold-start storm.
#
# Spawn N fresh shim processes simultaneously, all of which call
# C_Initialize against the same daemon over loopback. Captures:
#   - per-process wall-time
#   - per-process exit status
#   - daemon CPU + RSS peak during the storm (sampled)
#
# Support contract: v0.2 supports one logical client per daemon/process
# (see the submodule AGENTS.md). Runs with N > 1 are DIAGNOSTIC ONLY;
# publish support acceptance from an N=1 run. The summary records which
# contract the run falls under in `workload_contract`.
#
# Completion contract: the script tracks exactly the children it started
# (setup steps, N workload processes, one sampler), joins each under a
# monotonic wall bound, and always reports a terminal valid JSON summary
# for a started run. Shims run in an exclusively owned disposable run
# container that is removed authoritatively at the end, so no host
# signal ever touches a container process. Signals produce a
# FAIL_INTERRUPTED record and keep their 128+signal exit status. A
# process that is present but unreadable
# is unknown, never gone: while any /proc read genuinely fails, tree
# cleanup cannot be verified and the verdict fails closed to
# FAIL_CLEANUP. Missing measurements are reported as unavailable (null),
# never zero. Wall-time quantiles use the nearest-rank convention over
# successful rows only: rank = ceil(p/100 * n), 1-based over ascending
# values. All numerics in the summary are canonical decimal (no leading
# zeros); non-canonical inputs are normalized or rejected before any
# work starts.
#
# Usage:
#   Build the consumer fixture images as described in
#   tests/consumers/README.md. Then:
#     scripts/perf/cold_start_storm.sh [N=100]
#
# Output:
#   scripts/perf/results/cold_start.csv  (one row per shim, index order)
#   scripts/perf/results/cold_start.json (summary, written atomically)
#
# Environment (defaults are the production values; overrides exist so the
# harness itself can be tested deterministically):
#   COLD_START_SETUP_TIMEOUT_SECS=120  wall bound per setup step
#   COLD_START_STARTUP_SLEEP=5         compose-startup wait, seconds
#   COLD_START_SAMPLE_INTERVAL=0.1     sampler period, seconds
#   COLD_START_STORM_TIMEOUT_SECS=600  wall bound for workload completion
#   COLD_START_SAMPLER_TIMEOUT_SECS=30 wall bound for sampler shutdown
#   COLD_START_CLEANUP_GRACE_SECS=5    TERM-to-KILL grace for owned children
#   COLD_START_PROC_ROOT=/proc         proc tree for daemon RSS reads
#   COLD_START_STAT_READER=cat         TEST ONLY: command used to read
#                                      /proc state (failure injection)
#   COLD_START_UPTIME_PATH=/proc/uptime TEST ONLY: uptime file read as the
#                                      monotonic clock (failure injection)
#   COLD_START_CLEANUP_HOLD_FILE=     TEST ONLY: when set, container
#                                      accounting windows announce
#                                      themselves here and pause
#                                      (count-bounded) for signal tests
#   COLD_START_STORM_ENTRY_HOLD_FILE= TEST ONLY: same pause before the
#                                      storm bound is computed
#   COLD_START_SAMPLER_ENTRY_HOLD_FILE= TEST ONLY: same pause before the
#                                      sampler-stop bound is computed
#
# Exit status: 0 on PASS; 1 on a FAIL_* verdict (valid JSON written);
# 2 on usage/setup errors (nothing ran, no summary); 128+sig on signals
# (FAIL_INTERRUPTED record written).

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

# --- Input validation -------------------------------------------------
# All integers are canonicalized (explicit base 10, no octal holes, no
# leading zeros into the JSON) and range-checked before any work starts.
canon_int() { # $1=value; echo canonical decimal or fail
    local val="$1"
    [[ "$val" =~ ^[0-9]+$ ]] || return 1
    [ "${#val}" -le 18 ] || return 1
    printf '%d\n' "$((10#$val))"
}

N="$(canon_int "${1-100}")" || N=""
if [ -z "$N" ] || [ "$N" -lt 1 ] || [ "$N" -gt 100000 ]; then
    echo "error: N must be a positive integer between 1 and 100000, got '${1-}'" >&2
    exit 2
fi

is_nonneg_number() { [[ "${1-}" =~ ^([0-9]+(\.[0-9]*)?|\.[0-9]+)$ ]]; }
is_positive_number() { is_nonneg_number "${1-}" && ! [[ "${1-}" =~ ^0*(\.0*)?$ ]]; }
in_range() { # $1=value (regex-checked) $2=max; true when value <= max
    awk -v v="$1" -v max="$2" 'BEGIN { exit !(v + 0 <= max + 0) }'
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

SETUP_TIMEOUT="$(canon_bound "${COLD_START_SETUP_TIMEOUT_SECS-120}" COLD_START_SETUP_TIMEOUT_SECS 31536000)" || exit 2
STORM_TIMEOUT="$(canon_bound "${COLD_START_STORM_TIMEOUT_SECS-600}" COLD_START_STORM_TIMEOUT_SECS 31536000)" || exit 2
SAMPLER_TIMEOUT="$(canon_bound "${COLD_START_SAMPLER_TIMEOUT_SECS-30}" COLD_START_SAMPLER_TIMEOUT_SECS 31536000)" || exit 2
CLEANUP_GRACE="$(canon_bound "${COLD_START_CLEANUP_GRACE_SECS-5}" COLD_START_CLEANUP_GRACE_SECS 31536000)" || exit 2

STARTUP_SLEEP="${COLD_START_STARTUP_SLEEP-5}"
SAMPLE_INTERVAL="${COLD_START_SAMPLE_INTERVAL-0.1}"
if ! is_nonneg_number "$STARTUP_SLEEP" || ! in_range "$STARTUP_SLEEP" 3600; then
    echo "error: COLD_START_STARTUP_SLEEP must be a number of seconds between 0 and 3600, got '$STARTUP_SLEEP'" >&2
    exit 2
fi
if ! is_positive_number "$SAMPLE_INTERVAL" || ! in_range "$SAMPLE_INTERVAL" 3600; then
    echo "error: COLD_START_SAMPLE_INTERVAL must be a positive number of seconds up to 3600, got '$SAMPLE_INTERVAL'" >&2
    exit 2
fi
PROC_ROOT="${COLD_START_PROC_ROOT-/proc}"
if [ -z "$PROC_ROOT" ] || [ ! -d "$PROC_ROOT" ]; then
    echo "error: COLD_START_PROC_ROOT must be an existing proc tree, got '$PROC_ROOT'" >&2
    exit 2
fi
STAT_READER="${COLD_START_STAT_READER-cat}"
if ! command -v "$STAT_READER" >/dev/null 2>&1; then
    echo "error: COLD_START_STAT_READER must name an available command, got '$STAT_READER'" >&2
    exit 2
fi

for tool in docker awk date seq sort mktemp rm mkdir mv cat touch dirname sleep top; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: required tool '$tool' not found in PATH" >&2
        exit 2
    fi
done

# --- Monotonic clock --------------------------------------------------
# Safety bounds use the monotonic clock (/proc/uptime), never the
# realtime clock: a stepped or skewed `date` must not stall a bound.
mono_now() { # echo whole monotonic seconds or fail
    awk '{print int($1)}' "${COLD_START_UPTIME_PATH:-/proc/uptime}" 2>/dev/null
}
deadline_after() { # $1=seconds; echo monotonic deadline or fail
    local now_s
    now_s=$(mono_now) || return 1
    echo $(( now_s + $1 ))
}
if ! mono_now >/dev/null 2>&1; then
    echo "error: monotonic clock (${COLD_START_UPTIME_PATH:-/proc/uptime}) is unreadable" >&2
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

# Prove the state reader up front: if even our own state is unreadable,
# every later `gone` is unverified and the run cannot claim clean
# cleanup. (The reader functions are defined below; the check itself
# needs only $WORK and $STAT_READER.)
if ! "$STAT_READER" "/proc/$$/stat" >/dev/null 2>&1; then
    touch "$WORK/.reader_fault" 2>/dev/null || true
fi

# Use the consumers fixture daemon (Alpine, softhsm2 backend).
COMPOSE=(docker compose -f "$(cd "$(dirname "$0")/../.." && pwd)/tests/consumers/docker-compose.yml")

# --- Owned-child tracking ----------------------------------------------
# Every background process this script starts is recorded here and only
# here; joins and signal cleanup act on exactly these PIDs, which are
# released (cleared) as soon as their owners reap them so a reused PID
# is never signalled. Foreground commands are short-lived by
# construction (bounded sleeps and instant tools) and need no tracking.
SAMPLER_PID=""
WORKLOAD_PIDS=()
SETUP_PID=""
CLEANUP_DONE=0
CLEANUP_SAW_FAULT=false
UNRESOLVED_PIDS=()
JOIN_KILLED=0
JOIN_TIMED_OUT=0
JOIN_UNRESOLVED=()
REAP_RESULT=""
PHASE="startup"
SUMMARY_DONE=""

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
    local pid
    [ "$#" -eq 0 ] && return 0
    kill_owned TERM "$@"
    sleep "$CLEANUP_GRACE"
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

# Container-side ownership: workload shims run inside an exclusively
# owned disposable run container (children of the container runtime, not
# of this script), so a killed `docker exec` CLI does not imply dead
# shims. After the storm and on signals, the harness removes the run
# container authoritatively through the container runtime, which stops
# every shim inside regardless of host privileges or /proc readability;
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

# gap_hold HOLDFILE: TEST ONLY: announce arrival at a window that is
# otherwise microseconds of builtins (no external barrier could time
# it) and pause while the hold file exists, so a signal or fault lands
# deterministically. The pause is count-bounded (~5s), so a leaked
# setting delays the run by seconds, never hangs it; an empty path is
# one builtin test. Never fails.
gap_hold() {
    local hold_file="$1" spins
    [ -n "$hold_file" ] || return 0
    echo "open" >"$hold_file" 2>/dev/null || return 0
    spins=0
    while [ -f "$hold_file" ] && [ "$spins" -lt 100 ]; do
        spins=$((spins + 1))
        sleep "$JOIN_POLL_SECS"
    done
    return 0
}

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
    # Window (b): the helper is settled and untracked; its outcome is
    # still unaccounted. TEST ONLY hold (no-op unless configured).
    gap_hold "${COLD_START_CLEANUP_HOLD_FILE:-}"
    RM_REMOVED=false
    if [ -n "$AWAIT_CODE" ] && [ "$AWAIT_CODE" = "0" ]; then
        RM_REMOVED=true
    fi
    return 0
}

# remove_run_container: remove the owned run container and release
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
    ( set +e; docker inspect --format '{{index .Config.Labels "coldstart-run-id"}}' "$RUN_NAME" >"$log" 2>&1; code=$?; echo "$code" >"$done_file"; exit "$code" ) &
    RM_PID=$!
    # A clock failure returns 1 with the helper already settled: the
    # torn log must not be matched for absence (a partial line could
    # misread), so skip straight to unverified and fail closed.
    if ! await_step "$CLEANUP_GRACE" "$RM_PID" "$done_file"; then
        RM_PID=""
        echo "error: monotonic clock unreadable during run-container reconcile" >&2
        echo "warning: run container '$RUN_NAME' may exist but its state is unverifiable; leaving it in place" >&2
        CONTAINER_UNVERIFIED=true
        return 0
    fi
    RM_PID=""
    if [ -n "$AWAIT_CODE" ] && [ "$AWAIT_CODE" = "0" ]; then
        label_all=$(cat "$log" 2>/dev/null || true)
        label="${label_all%%$'\n'*}"
        label="${label//[[:space:]]/}"
        if [ "$label" = "$RUN_NAME" ]; then
            # Window (a): the reconcile is confirmed but the removal
            # has not dispatched. TEST ONLY hold (no-op unless configured).
            gap_hold "${COLD_START_CLEANUP_HOLD_FILE:-}"
            attempt_rm
            if [ "$RM_REMOVED" = true ]; then
                RUN_CREATED=0
                RUN_DISPATCHED=0
            else
                CONTAINER_UNVERIFIED=true
            fi
            return 0
        fi
        echo "warning: run container '$RUN_NAME' exists but its ownership label is unverifiable; leaving it in place" >&2
        # Window (c): the mismatch is detected but not yet recorded.
        # TEST ONLY hold (no-op unless configured).
        gap_hold "${COLD_START_CLEANUP_HOLD_FILE:-}"
        CONTAINER_UNVERIFIED=true
        RUN_DISPATCHED=0
        return 0
    fi
    label_all=$(cat "$log" 2>/dev/null || true)
    # Absence evidence reads narrowly: only diagnostics that name our
    # own run-container ID ("No such container: <id>") or use Docker's
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
            echo "warning: run container '$RUN_NAME' may exist but its state is unverifiable; leaving it in place" >&2
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
    [ -n "$SAMPLER_PID" ] && all_pids+=("$SAMPLER_PID")
    if [ "${#WORKLOAD_PIDS[@]}" -gt 0 ]; then
        all_pids+=("${WORKLOAD_PIDS[@]}")
    fi
    [ -n "$SETUP_PID" ] && all_pids+=("$SETUP_PID")
    [ -n "$RM_PID" ] && all_pids+=("$RM_PID")
    [ "${#all_pids[@]}" -eq 0 ] && return 0
    deadline=$(deadline_after 0) || deadline=0
    join_or_terminate "$deadline" "${all_pids[@]}"
    if [ "${#JOIN_UNRESOLVED[@]}" -gt 0 ]; then
        UNRESOLVED_PIDS+=("${JOIN_UNRESOLVED[@]}")
    fi
    for pid in "${all_pids[@]}"; do
        reap_parent "$pid"
    done
    SAMPLER_PID=""
    WORKLOAD_PIDS=()
    SETUP_PID=""
    RM_PID=""
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

# json_escape STR: quote a fixed-vocabulary string for JSON. Only used
# with reason texts built from constant fragments and canonical
# integers, which carry no quoting hazards; the replacer is
# defense-in-depth.
json_escape() {
    local text="$1"
    text="${text//\\/\\\\}"
    text="${text//\"/\\\"}"
    printf '"%s"' "$text"
}

# bounds_json: the effective numeric bounds. Only called after input
# validation, so every value is a canonical integer.
bounds_json() {
    printf '{"setup_timeout_s": %s, "storm_timeout_s": %s, "sampler_timeout_s": %s, "cleanup_grace_s": %s}' \
        "$SETUP_TIMEOUT" "$STORM_TIMEOUT" "$SAMPLER_TIMEOUT" "$CLEANUP_GRACE"
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
# cleanup_ok/unresolved_pids describe the real post-signal state; every
# unmeasured field stays null. Never fails.
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
    local run_container_json="null"
    if [ -n "$RUN_NAME" ]; then
        run_container_json=$(json_escape "$RUN_NAME")
    fi
    tmp="$OUT_DIR/.cold_start.json.tmp"
    cat > "$tmp" <<EOF || return 0
{
  "schema": "cold-start-summary/1",
  "verdict": "FAIL_INTERRUPTED",
  "signal": "$sig_name",
  "n": $N,
  "completed": null,
  "ok": null,
  "fail": null,
  "malformed_rows": null,
  "malformed_samples": null,
  "workload_timeout": false,
  "workload_contract": null,
  "sampler_exit": null,
  "sampler_killed": false,
  "sampler_ok": false,
  "total_samples": null,
  "rss_samples": null,
  "cpu_samples": null,
  "cleanup_ok": $cleanup_ok,
  "unresolved_pids": $unresolved,
  "storm_elapsed_ms": null,
  "max_wall_ms": null,
  "p99_wall_ms": null,
  "peak_rss_kb": null,
  "peak_cpu_pct": null,
  "quantile": {
    "convention": "nearest-rank",
    "population": "successful rows only"
  },
  "bounds": $(bounds_json),
  "run_container": $run_container_json,
  "reasons": [$reasons]
}
EOF
    mv "$tmp" "$OUT_DIR/cold_start.json" 2>/dev/null || true
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
# shellcheck disable=SC2329 # invoked indirectly via the INT/TERM traps
on_signal() {
    local code="$1" sig_name="$2"
    local reader_fault=false
    trap '' INT TERM
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
        # helper was reaped but before its outcome is accounted (the
        # reconcile→removal gap, a failed removal's accounting, a
        # mismatch's accounting) with nothing tracked but the container
        # obligation still open. The flags clear only on terminal
        # confirmation (confirmed removal, confirmed absence), so any
        # set flag here means unverified. (RM_PID set implies flags
        # set — helpers dispatch only under an open obligation — so the
        # flags subsume the old helper-presence check.)
        if [ "$RUN_CREATED" -eq 1 ] || [ "$RUN_DISPATCHED" -eq 1 ]; then
            CONTAINER_UNVERIFIED=true
        fi
        terminate_owned
        rm -rf "$WORK" 2>/dev/null || true
    fi
    cleanup_once
    [ "$CLEANUP_SAW_FAULT" = true ] && reader_fault=true
    if [ -z "$SUMMARY_DONE" ]; then
        SUMMARY_DONE=1
        write_interrupted "$sig_name" "$reader_fault" || true
    fi
    echo "cold-start storm $sig_name during $PHASE; terminal summary written" >&2 || true
    exit "$code"
}
# shellcheck disable=SC2329 # invoked indirectly via trap
on_int() { on_signal 130 SIGINT; }
# shellcheck disable=SC2329 # invoked indirectly via trap
on_term() { on_signal 143 SIGTERM; }
trap on_exit EXIT
trap on_int INT
trap on_term TERM

echo "=== Cold-start storm: $N shims ==="

# 1. Bring up daemon-softhsm2 + a single consumer-shell container that
#    donates the run container's image, proxy env, and network namespace.
#    Each setup step runs in the background under its own monotonic bound
#    so signals stay prompt.
PHASE="setup:compose-up"
run_setup_step compose-up "$SETUP_TIMEOUT" "${COMPOSE[@]}" --profile softhsm2 up -d daemon-softhsm2 consumer-shell
PHASE="setup:startup-sleep"
run_setup_step startup-sleep "$SETUP_TIMEOUT" sleep "$STARTUP_SLEEP"

# 2. Find the daemon's PID (inside the container) for CPU+RSS sampling,
#    and refuse to run blind when it cannot be measured.
PHASE="setup:inspect"
run_setup_step inspect "$SETUP_TIMEOUT" docker inspect --format '{{.State.Pid}}' consumer-matrix-daemon
inspect_raw=$(cat "$WORK/setup-inspect.log")
daemon_pid="${inspect_raw//[[:space:]]/}"
if ! daemon_pid="$(canon_int "$daemon_pid")" || [ "$daemon_pid" -lt 1 ]; then
    echo "error: daemon PID from 'docker inspect' is not a positive integer: '$inspect_raw'" >&2
    exit 2
fi
echo "daemon PID (host): $daemon_pid"
if [ ! -r "$PROC_ROOT/$daemon_pid/status" ]; then
    echo "error: daemon PID $daemon_pid is not measurable via '$PROC_ROOT/$daemon_pid/status'" >&2
    exit 2
fi

# 2b. Create the exclusively owned run container that hosts this run's
#     shims. It shares the consumer-shell network namespace (so `daemon`
#     resolves) and forwards the shell's proxy env; the image and env
#     come from the shell container itself so the script never hardcodes
#     farm coordinates. Removal is authoritative (phase 6b plus the exit
#     trap), so no host signal ever touches a container process.
PHASE="setup:inspect-shell"
run_setup_step inspect-shell "$SETUP_TIMEOUT" docker inspect --format '{{println .Config.Image}}{{range .Config.Env}}{{println .}}{{end}}' consumer-matrix-shell
shell_raw=$(cat "$WORK/setup-inspect-shell.log")
RUN_IMAGE=""
RUN_ENV_ARGS=()
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
                PKCS11_PROXY_ENDPOINT|PKCS11_PROXY_CONNECT_TIMEOUT|DAEMON_HOST|DAEMON_PORT|RUST_LOG)
                    RUN_ENV_ARGS+=(-e "$shell_line")
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
if ! run_epoch=$(date +%s); then
    echo "error: realtime clock read failed while naming the run container" >&2
    exit 2
fi
RUN_NAME="coldstart-$$-$run_epoch-$RANDOM"
run_cmd=(docker run -d --rm --name "$RUN_NAME" --network container:consumer-matrix-shell --label "coldstart-run-id=$RUN_NAME")
if [ "${#RUN_ENV_ARGS[@]}" -gt 0 ]; then
    run_cmd+=("${RUN_ENV_ARGS[@]}")
fi
run_cmd+=("$RUN_IMAGE" sleep 31536000)
PHASE="setup:run-container"
# The attempt is registered before dispatch: if the client is killed
# or stalls after the daemon commits, the exit trap reconciles the
# ambiguous creation by its ownership label instead of skipping it.
RUN_DISPATCHED=1
run_setup_step run-container "$SETUP_TIMEOUT" "${run_cmd[@]}"
RUN_CREATED=1
RUN_DISPATCHED=0

# 3. Sample daemon RSS + CPU during the storm. Empty fields mean
#    "unavailable", never zero; corrupt (nonempty, non-canonical) tool
#    output empties exactly its field so rows keep their shape.
PHASE="storm:sampler"
samples="$WORK/samples.csv"
echo "ts_us,rss_kb,cpu_pct" > "$samples"

run_sampler() {
    local ts rss cpu
    while sleep "$SAMPLE_INTERVAL"; do
        ts=$(date +%s%6N) || exit 3
        rss=$(awk '/^VmRSS:/ { print $2 }' "$PROC_ROOT/$daemon_pid/status" 2>/dev/null || true)
        cpu=$(top -b -n 1 -p "$daemon_pid" 2>/dev/null | awk -v pid="$daemon_pid" '$1==pid { print $9 }' || true)
        # A corrupt (nonempty, non-canonical) tool reading is unavailable,
        # never a measurement: empty exactly that field so the row keeps
        # its three-field shape and the usable-count verdict sees the gap.
        if [ -n "$rss" ]; then
            [[ "$rss" =~ ^(0|[1-9][0-9]*)$ ]] || rss=""
        fi
        if [ -n "$cpu" ]; then
            [[ "$cpu" =~ ^(0|[1-9][0-9]*)(\.[0-9]+)?$ ]] || cpu=""
        fi
        printf '%s,%s,%s\n' "$ts" "$rss" "$cpu" >> "$samples"
        [ -f "$WORK/stop" ] && break
    done
}
sampler_done="$WORK/sampler.done"
rm -f "$sampler_done"
( set +e; run_sampler; sampler_code=$?; echo "$sampler_code" >"$sampler_done"; exit "$sampler_code" ) &
SAMPLER_PID=$!

# 4. Spawn N shim processes in the owned run container,
#    capturing each one's wall-time + exit code.
results="$OUT_DIR/cold_start.csv"
echo "idx,wall_us,exit_code" > "$results"

# Build a small shell function inside the run container that just opens
# a session and exits — the cheapest "did C_Initialize succeed" probe.
# shellcheck disable=SC2329 # invoked by name via run_setup_step below
provision_consumer() {
    # Plain `docker exec` has no -T flag (that is compose-only); the
    # non-interactive invocation needs none.
    docker exec "$RUN_NAME" sh -c "cat > /tmp/spawn_one.sh <<'EOF'
#!/bin/sh
# Exits 0 iff C_Initialize + C_GetSlotList succeed. We use
# pkcs11-tool --list-slots; the binary does Initialize + GetSlotList
# + Finalize.
exec pkcs11-tool --module /usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so --list-slots
EOF
chmod +x /tmp/spawn_one.sh"
}
PHASE="setup:provision"
run_setup_step provision "$SETUP_TIMEOUT" provision_consumer

PHASE="storm:workload"
# TEST ONLY context for clock failure injection (see STUB_DATE_FAIL_CALLER):
# names the current boundary-clock call for the stub.
COLD_START_CLOCK_CALLER="storm-start"
export COLD_START_CLOCK_CALLER
if ! storm_start=$(date +%s%6N); then
    echo "error: realtime clock read failed at storm start" >&2
    exit 2
fi
unset COLD_START_CLOCK_CALLER
WORKLOAD_PIDS=()
for i in $(seq 1 "$N"); do
    (
        # COLD_START_SHIM_INDEX is visible only to local test doubles:
        # `docker exec` is not passed -e, so it is not forwarded into
        # the container. COLD_START_CLOCK_CALLER names each boundary
        # clock call for the stub (deterministic duration injection).
        export COLD_START_SHIM_INDEX="$i"
        export COLD_START_CLOCK_CALLER="worker-t0"
        t0=$(date +%s%6N) || exit 3
        if docker exec "$RUN_NAME" sh /tmp/spawn_one.sh >/dev/null 2>&1; then
            ec=0
        else
            ec=$?
        fi
        export COLD_START_CLOCK_CALLER="worker-t1"
        t1=$(date +%s%6N) || exit 3
        echo "$i,$((t1-t0)),$ec" > "$WORK/row.$i"
    ) &
    WORKLOAD_PIDS+=($!)
done

# 5. Bounded storm join. Completion needs every row file AND no
#    confirmed-alive worker: rows prove the work finished, process
#    state proves the children are gone. A confirmed-alive worker at
#    the deadline is a storm timeout; unverifiable states are
#    blind-stopped and recorded, never mistaken for a timeout.
# Window (e): workers spawned but the storm bound not yet computed.
# TEST ONLY hold (no-op unless configured).
gap_hold "${COLD_START_STORM_ENTRY_HOLD_FILE:-}"
# A monotonic failure in a started phase latches (never exits): the run
# settles what it can without a measurable bound and still publishes
# its terminal summary. A voided bound reads 0, so a recovered clock
# escalates immediately instead of waiting out a bound it never measured.
storm_mono_failed=false
if ! storm_deadline=$(deadline_after "$STORM_TIMEOUT"); then
    echo "error: monotonic clock unreadable at storm start" >&2
    storm_deadline=0
    storm_mono_failed=true
fi
workload_timeout=false
JOIN_TIMED_OUT=0
rows_complete=false
any_alive=true
while :; do
    rows_complete=true
    for i in $(seq 1 "$N"); do
        [ -f "$WORK/row.$i" ] || { rows_complete=false; break; }
    done
    any_alive=false
    for pid in "${WORKLOAD_PIDS[@]}"; do
        [ "$(proc_state "$pid")" = "alive" ] && { any_alive=true; break; }
    done
    if [ "$rows_complete" = true ] && [ "$any_alive" = false ]; then
        break
    fi
    if ! now_s=$(mono_now); then
        echo "error: monotonic clock unreadable during storm join" >&2
        storm_mono_failed=true
        break
    fi
    [ "$now_s" -ge "$storm_deadline" ] && break
    sleep "$JOIN_POLL_SECS"
done
if [ "$rows_complete" = true ] && [ "$any_alive" = false ]; then
    for pid in "${WORKLOAD_PIDS[@]}"; do
        state=$(proc_state "$pid")
        case "$state" in
            gone|zombie)
                reap_parent "$pid"
                ;;
            unknown)
                settle_unverified "$pid"
                ;;
            *)
                join_or_terminate "$(deadline_after "$CLEANUP_GRACE" || echo 0)" "$pid"
                if [ "${#JOIN_UNRESOLVED[@]}" -gt 0 ]; then
                    UNRESOLVED_PIDS+=("${JOIN_UNRESOLVED[@]}")
                fi
                reap_parent "$pid"
                ;;
        esac
    done
else
    join_or_terminate "$(deadline_after 0 || echo 0)" "${WORKLOAD_PIDS[@]}"
    # An unmeasurable bound is not a timeout: escalation after a clock
    # failure never reports one (the latch carries the reason instead).
    [ "$JOIN_TIMED_OUT" -eq 1 ] && [ "$storm_mono_failed" != true ] && workload_timeout=true
    if [ "${#JOIN_UNRESOLVED[@]}" -gt 0 ]; then
        UNRESOLVED_PIDS+=("${JOIN_UNRESOLVED[@]}")
    fi
    for pid in "${WORKLOAD_PIDS[@]}"; do
        reap_parent "$pid"
    done
fi
WORKLOAD_PIDS=()

# 6. Stop the sampler and join it under its own bound, independently of
#    how the workload finished. The done-file proves clean shutdown;
#    its absence at the bound means the sampler is hung, not done.
PHASE="storm:sampler-stop"
touch "$WORK/stop"
sampler_exit=""
sampler_killed=false
sampler_mono_failed=false
JOIN_TIMED_OUT=0
# Window (d): sampler stop entered but its bound not yet computed.
# TEST ONLY hold (no-op unless configured).
gap_hold "${COLD_START_SAMPLER_ENTRY_HOLD_FILE:-}"
if ! sampler_deadline=$(deadline_after "$SAMPLER_TIMEOUT"); then
    echo "error: monotonic clock unreadable at sampler stop" >&2
    sampler_deadline=0
    sampler_mono_failed=true
fi
while [ ! -f "$sampler_done" ]; do
    state=$(proc_state "$SAMPLER_PID")
    [ "$state" = "gone" ] || [ "$state" = "zombie" ] && break
    if ! now_s=$(mono_now); then
        echo "error: monotonic clock unreadable during sampler join" >&2
        sampler_mono_failed=true
        break
    fi
    [ "$now_s" -ge "$sampler_deadline" ] && break
    sleep "$JOIN_POLL_SECS"
done
if [ -f "$sampler_done" ]; then
    state=$(proc_state "$SAMPLER_PID")
    case "$state" in
        gone|zombie)
            reap_parent "$SAMPLER_PID"
            [ "$REAP_RESULT" = "unreaped" ] && sampler_exit="" || sampler_exit="$REAP_RESULT"
            ;;
        unknown)
            settle_unverified "$SAMPLER_PID"
            sampler_exit=""
            ;;
        *)
            join_or_terminate "$(deadline_after "$CLEANUP_GRACE" || echo 0)" "$SAMPLER_PID"
            [ "$JOIN_KILLED" -eq 1 ] && sampler_killed=true
            if [ "${#JOIN_UNRESOLVED[@]}" -gt 0 ]; then
                UNRESOLVED_PIDS+=("${JOIN_UNRESOLVED[@]}")
            fi
            reap_parent "$SAMPLER_PID"
            [ "$REAP_RESULT" = "unreaped" ] && sampler_exit="" || sampler_exit="$REAP_RESULT"
            ;;
    esac
else
    join_or_terminate "$(deadline_after 0 || echo 0)" "$SAMPLER_PID"
    [ "$JOIN_KILLED" -eq 1 ] && sampler_killed=true
    if [ "${#JOIN_UNRESOLVED[@]}" -gt 0 ]; then
        UNRESOLVED_PIDS+=("${JOIN_UNRESOLVED[@]}")
    fi
    reap_parent "$SAMPLER_PID"
    [ "$REAP_RESULT" = "unreaped" ] && sampler_exit="" || sampler_exit="$REAP_RESULT"
fi
SAMPLER_PID=""

COLD_START_CLOCK_CALLER="storm-end"
export COLD_START_CLOCK_CALLER
clock_failed=false
if ! storm_end=$(date +%s%6N); then
    # Post-start clock failure routes through the terminal record, not a
    # silent exit: the rows exist, only the aggregate elapsed is lost.
    echo "warning: realtime clock read failed at storm end; elapsed stays null" >&2
    storm_end=""
    clock_failed=true
fi
unset COLD_START_CLOCK_CALLER
if [ "$clock_failed" = true ]; then
    storm_elapsed_ms=""
else
    storm_elapsed_ms=$(( (storm_end - storm_start) / 1000 ))
fi

mv "$samples" "$OUT_DIR/cold_start_daemon_samples.csv"
samples_out="$OUT_DIR/cold_start_daemon_samples.csv"

# 6b. Container-side removal: a killed `docker exec` CLI does not
#     imply dead shims, so the owned run container (with every shim in
#     it) is removed authoritatively; an unconfirmed removal fails
#     cleanup closed below.
PHASE="cleanup:container-remove"
remove_run_container

# 7. Assemble the per-shim rows in index order. Rows come from our own
#    children, but a stepped realtime clock can still produce a negative
#    wall time; refuse to compute on malformed rows instead of silently
#    skewing the summary.
PHASE="summarize"
completed=0
ok_count=0
fail_count=0
malformed=0
for i in $(seq 1 "$N"); do
    row_file="$WORK/row.$i"
    [ -f "$row_file" ] || continue
    row=$(cat "$row_file")
    if [[ "$row" =~ ^[0-9]+,[0-9]+,[0-9]+$ ]]; then
        echo "$row" >> "$results"
        completed=$((completed + 1))
        ec="${row##*,}"
        if [ "$ec" = "0" ]; then
            ok_count=$((ok_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
    else
        malformed=$((malformed + 1))
    fi
done

# 8. Compute the summary. Quantiles use nearest-rank over successful rows
#    only; unavailable measurements stay empty and render as null.
#    Sampler rows are shape-checked strictly: exactly three fields, a
#    canonical timestamp, canonical-or-empty measurements.
awk -F, 'NR>1 && $3==0 {print $2}' "$results" | sort -n > "$WORK/successful_walls.txt"
p99_wall_ms=$(awk -v p=99 '{a[NR]=$1} END {n=NR; if (n==0) exit 1; rank=int((p*n+99)/100); if (rank<1) rank=1; if (rank>n) rank=n; printf "%.0f", a[rank]/1000}' "$WORK/successful_walls.txt" 2>/dev/null || true)
max_wall_ms=$(awk '{m=$1} END {if (NR>0) printf "%.0f", m/1000}' "$WORK/successful_walls.txt")
malformed_samples=0
total_samples=0
rss_samples=0
cpu_samples=0
peak_rss_kb=""
peak_cpu_pct=""
samples_bad_header=false
eval "$(awk -F, '
NR==1 {
    if ($0 != "ts_us,rss_kb,cpu_pct") { print "samples_bad_header=true" }
    next
}
{
    if (NF != 3 || $1 !~ /^(0|[1-9][0-9]*)$/) { mal++; next }
    if ($2 != "" && $2 !~ /^(0|[1-9][0-9]*)$/) { mal++; next }
    if ($3 != "" && $3 !~ /^(0|[1-9][0-9]*)(\.[0-9]+)?$/) { mal++; next }
    total++
    if ($2 != "") { rss++; if (!seen_r || $2 + 0 > peak_r + 0) { peak_r = $2; seen_r = 1 } }
    if ($3 != "") { cpu++; if (!seen_c || $3 + 0 > peak_c + 0) { peak_c = $3; seen_c = 1 } }
}
END {
    printf "malformed_samples=%d\n", mal + 0
    printf "total_samples=%d\n", total + 0
    printf "rss_samples=%d\n", rss + 0
    printf "cpu_samples=%d\n", cpu + 0
    if (seen_r) printf "peak_rss_kb=%s\n", peak_r
    if (seen_c) printf "peak_cpu_pct=%s\n", peak_c
}' "$samples_out")"

reasons=()
workload_bad=false
if [ "$workload_timeout" = true ] || [ "$fail_count" -gt 0 ] || [ "$completed" -lt "$N" ] || [ "$malformed" -gt 0 ] || [ "$clock_failed" = true ] || [ "$storm_mono_failed" = true ]; then
    workload_bad=true
    [ "$workload_timeout" = true ] && reasons+=("storm bound exceeded: ${STORM_TIMEOUT}s")
    [ "$fail_count" -gt 0 ] && reasons+=("workload failures: $fail_count of $N")
    [ "$completed" -lt "$N" ] && reasons+=("recorded workload rows: $completed of $N")
    [ "$malformed" -gt 0 ] && reasons+=("malformed workload rows: $malformed")
    [ "$clock_failed" = true ] && reasons+=("storm elapsed time could not be measured: realtime clock read failed")
    [ "$storm_mono_failed" = true ] && reasons+=("monotonic clock unreadable during storm join: storm bound could not be measured")
fi

reader_fault=false
if reader_faulted; then
    reader_fault=true
fi
work_removed=true
rm -rf "$WORK" 2>/dev/null || work_removed=false
cleanup_ok=true
if [ "${#UNRESOLVED_PIDS[@]}" -gt 0 ] || [ "$work_removed" = false ] || [ "$reader_fault" = true ] || [ "$CONTAINER_UNVERIFIED" = true ]; then
    cleanup_ok=false
fi
if [ "$cleanup_ok" = false ]; then
    [ "${#UNRESOLVED_PIDS[@]}" -gt 0 ] && reasons+=("unresolved owned processes: ${#UNRESOLVED_PIDS[@]}")
    [ "$work_removed" = false ] && reasons+=("scratch directory could not be removed")
    [ "$reader_fault" = true ] && reasons+=("owned process states could not be verified: /proc reads failed")
    [ "$CONTAINER_UNVERIFIED" = true ] && reasons+=("container-side termination could not be verified")
fi

sampler_ok=true
if [ -z "$sampler_exit" ] || [ "$sampler_exit" -ne 0 ]; then
    sampler_ok=false
fi
if [ "$rss_samples" -eq 0 ] || [ "$cpu_samples" -eq 0 ]; then
    sampler_ok=false
fi
if [ "$malformed_samples" -gt 0 ] || [ "$samples_bad_header" = true ]; then
    sampler_ok=false
fi
if [ "$sampler_mono_failed" = true ]; then
    sampler_ok=false
fi
if [ "$sampler_ok" = false ]; then
    [ -n "$sampler_exit" ] && [ "$sampler_exit" -ne 0 ] && reasons+=("sampler exit status: $sampler_exit")
    [ -z "$sampler_exit" ] && reasons+=("sampler could not be joined")
    [ "$sampler_mono_failed" = true ] && reasons+=("monotonic clock unreadable during sampler join: sampler bound could not be measured")
    [ "$sampler_killed" = true ] && [ "$sampler_mono_failed" != true ] && reasons+=("sampler shutdown bound exceeded: ${SAMPLER_TIMEOUT}s")
    [ "$rss_samples" -eq 0 ] && reasons+=("no usable RSS samples were recorded")
    [ "$cpu_samples" -eq 0 ] && reasons+=("no usable CPU samples were recorded")
    [ "$malformed_samples" -gt 0 ] && reasons+=("malformed sampler rows: $malformed_samples")
    [ "$samples_bad_header" = true ] && reasons+=("sampler evidence header is corrupt")
fi

# Verdict precedence: a failed workload outranks everything (the run did
# not do its job); unverifiable cleanup outranks bad measurements (the
# run itself is unverified); sampler failures come last.
verdict="PASS"
[ "$workload_bad" = true ] && verdict="FAIL_WORKLOAD"
[ "$cleanup_ok" = false ] && [ "$verdict" = "PASS" ] && verdict="FAIL_CLEANUP"
[ "$sampler_ok" = false ] && [ "$verdict" = "PASS" ] && verdict="FAIL_SAMPLER"

if [ "$N" -eq 1 ]; then
    workload_contract="supported-single-client"
else
    workload_contract="diagnostic-multi-client"
fi

if [ "${#reasons[@]}" -eq 0 ]; then
    reasons_json="[]"
else
    reasons_json=""
    for reason in "${reasons[@]}"; do
        reasons_json="$reasons_json$(json_escape "$reason"),"
    done
    reasons_json="[${reasons_json%,}]"
fi
unresolved_json_value=$(unresolved_json)
if [ -n "$RUN_NAME" ]; then
    run_container_json=$(json_escape "$RUN_NAME")
else
    run_container_json="null"
fi

tmp_json="$OUT_DIR/.cold_start.json.tmp"
if ! cat > "$tmp_json" <<EOF; then
{
  "schema": "cold-start-summary/1",
  "n": $N,
  "completed": $completed,
  "ok": $ok_count,
  "fail": $fail_count,
  "malformed_rows": $malformed,
  "malformed_samples": $malformed_samples,
  "workload_timeout": $workload_timeout,
  "workload_contract": "$workload_contract",
  "sampler_exit": ${sampler_exit:-null},
  "sampler_killed": $sampler_killed,
  "sampler_ok": $sampler_ok,
  "total_samples": $total_samples,
  "rss_samples": $rss_samples,
  "cpu_samples": $cpu_samples,
  "cleanup_ok": $cleanup_ok,
  "unresolved_pids": $unresolved_json_value,
  "storm_elapsed_ms": ${storm_elapsed_ms:-null},
  "max_wall_ms": ${max_wall_ms:-null},
  "p99_wall_ms": ${p99_wall_ms:-null},
  "peak_rss_kb": ${peak_rss_kb:-null},
  "peak_cpu_pct": ${peak_cpu_pct:-null},
  "quantile": {
    "convention": "nearest-rank",
    "population": "successful rows only"
  },
  "bounds": $(bounds_json),
  "signal": null,
  "run_container": $run_container_json,
  "verdict": "$verdict",
  "reasons": $reasons_json
}
EOF
    echo "error: could not write the summary file" >&2
    exit 1
fi
if ! mv "$tmp_json" "$OUT_DIR/cold_start.json"; then
    echo "error: could not publish the summary file" >&2
    exit 1
fi

SUMMARY_DONE=1
CLEANUP_DONE=1

echo
cat "$OUT_DIR/cold_start.json"
echo
echo "Per-process timings: $results"
echo "Daemon samples:      $OUT_DIR/cold_start_daemon_samples.csv"
echo "Summary:             $OUT_DIR/cold_start.json"

if [ "$verdict" = "PASS" ]; then
    exit 0
else
    exit 1
fi
