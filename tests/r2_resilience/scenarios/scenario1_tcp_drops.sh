#!/usr/bin/env bash
# Scenario 1: 1-second TCP drop every 30 seconds for 10 minutes, with
# continuous sign operations from the shim.
#
# Reduced to 1-second-drop-every-15-seconds-for-90-seconds in this
# script — same shape, fits within a CI budget. The 10-minute spec is
# the production smoke; reproduce it manually by setting
# DROP_INTERVAL_S, DROP_DURATION_S, TOTAL_DURATION_S in the env.
#
# The drop is packet-level: a pair of `timeout` toxics (upstream +
# downstream) stalls in-flight traffic and breaks the affected
# connections while the toxiproxy LISTENER stays up — unlike taking
# the whole proxy down. Signs issued during a drop fail with a
# transport-mapped RV; once the toxics clear, tonic reconnects
# transparently and the proxy preserves the client_context_id within
# lease_seconds.
#
# Expected behaviour:
# - In-flight signs during a drop fail with one of the transport
#   families below (each counted separately).
# - Subsequent signs (after the drop heals) succeed without app
#   intervention.
# - No unrecoverable errors at the end of the run.

set -euo pipefail
. "$(dirname "$0")/_common.sh"

DROP_INTERVAL_S="${DROP_INTERVAL_S:-15}"
DROP_DURATION_S="${DROP_DURATION_S:-1}"
TOTAL_DURATION_S="${TOTAL_DURATION_S:-90}"
DROP_DURATION_MS=$(( DROP_DURATION_S * 1000 ))
# The toxic's own close timer must fire well INSIDE the drop window:
# each connection stalls TOXIC_MS then breaks, so signs overlapping
# the window fail instead of merely stalling until clear_toxics heals
# them. Clamped to sane bounds for tiny/huge drop durations.
TOXIC_MS=$(( DROP_DURATION_MS / 4 ))
if [[ $TOXIC_MS -lt 50 ]]; then TOXIC_MS=50; fi
if [[ $TOXIC_MS -gt 1000 ]]; then TOXIC_MS=1000; fi

wait_for_toxiproxy
clear_toxics
ensure_test_key

echo "scenario1: starting ${TOTAL_DURATION_S}s sign loop with ${DROP_DURATION_S}s drops every ${DROP_INTERVAL_S}s"

success=0
device_error=0
general_error=0
not_initialized=0
token_not_present=0
other_fail=0

# One RV family per counter (W1-L10-07): a mid-sign RPC break is
# CKR_DEVICE_ERROR (session class), a broken C_Initialize is
# CKR_GENERAL_ERROR (lifecycle class), a broken slot/token query
# is CKR_TOKEN_NOT_PRESENT (slot class), and a reconnect that
# outruns the lease is CKR_CRYPTOKI_NOT_INITIALIZED. First match
# wins so every failure lands in exactly one bucket.
run_one_sign() {
    if shim_sign_once; then
        success=$(( success + 1 ))
    elif log_mentions_ckr "CKR_DEVICE_ERROR"; then
        device_error=$(( device_error + 1 ))
    elif log_mentions_ckr "CKR_GENERAL_ERROR"; then
        general_error=$(( general_error + 1 ))
    elif log_mentions_ckr "CKR_CRYPTOKI_NOT_INITIALIZED"; then
        not_initialized=$(( not_initialized + 1 ))
    elif log_mentions_ckr "CKR_TOKEN_NOT_PRESENT"; then
        token_not_present=$(( token_not_present + 1 ))
    else
        other_fail=$(( other_fail + 1 ))
        echo "scenario1: unexpected error during sign:" >&2
        cat "$SHIM_SIGN_LOG" >&2
    fi
}

end=$(( $(date +%s) + TOTAL_DURATION_S ))
next_drop=$(( $(date +%s) + DROP_INTERVAL_S ))

while [[ $(date +%s) -lt $end ]]; do
    now=$(date +%s)
    # Schedule a drop? Signs must run DURING the armed window —
    # sleeping through the drop (then signing after the heal) would
    # observe nothing and pass vacuously.
    if [[ $now -ge $next_drop ]]; then
        echo "scenario1: dropping packets for ${DROP_DURATION_S}s at $(date -u +%H:%M:%S)"
        add_toxic "{\"name\": \"drop_down\", \"type\": \"timeout\", \"stream\": \"downstream\", \"attributes\": { \"timeout\": ${TOXIC_MS} }}"
        add_toxic "{\"name\": \"drop_up\", \"type\": \"timeout\", \"stream\": \"upstream\", \"attributes\": { \"timeout\": ${TOXIC_MS} }}"
        drop_end=$(( now + DROP_DURATION_S ))
        while [[ $(date +%s) -lt $drop_end ]]; do
            run_one_sign
        done
        clear_toxics
        next_drop=$(( $(date +%s) + DROP_INTERVAL_S ))
        continue
    fi

    run_one_sign
    sleep 0.3
done

clear_toxics

echo "scenario1: signs ok=${success} device_err=${device_error} general_err=${general_error} not_init=${not_initialized} token_absent=${token_not_present} other_fail=${other_fail}"

# Acceptance criteria:
# 1. There must be SOME successful signs (the shim recovers).
# 2. Errors must all be the expected transport families — no random
#    other errors.
# 3. At least one expected-family error occurred (the drops actually
#    injected faults — guards silent toxic misconfiguration).
if [[ $success -lt 5 ]]; then
    echo "fail: scenario1 — only ${success} successful signs (need >=5)" >&2
    exit 1
fi
if [[ $other_fail -gt 0 ]]; then
    echo "fail: scenario1 — ${other_fail} unexpected error types" >&2
    exit 1
fi
if [[ $(( device_error + general_error + not_initialized + token_not_present )) -eq 0 ]]; then
    echo "fail: scenario1 — no drop-induced errors observed (fault injection suspect)" >&2
    exit 1
fi
echo "pass: scenario1"
