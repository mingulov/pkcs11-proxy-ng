#!/usr/bin/env bash
# Scenario 1: 1-second TCP drop every 30 seconds for 10 minutes, with
# continuous sign operations from the shim.
#
# Reduced to 1-second-drop-every-15-seconds-for-90-seconds in this
# script — same shape, fits within a CI budget. The 10-minute spec is
# the production smoke; reproduce it manually by setting
# DROP_INTERVAL_S, DROP_DURATION_S, TOTAL_DURATION_S in the env.
#
# Expected behaviour:
# - In-flight signs during a drop return CKR_DEVICE_ERROR.
# - Subsequent signs (after the drop heals) succeed without app
#   intervention — tonic's HTTP/2 layer reconnects transparently, and
#   the proxy preserves the client_context_id within lease_seconds.
# - No unrecoverable errors at the end of the run.

set -euo pipefail
. "$(dirname "$0")/_common.sh"

DROP_INTERVAL_S="${DROP_INTERVAL_S:-15}"
DROP_DURATION_S="${DROP_DURATION_S:-1}"
TOTAL_DURATION_S="${TOTAL_DURATION_S:-90}"

wait_for_toxiproxy
clear_toxics
ensure_test_key

echo "scenario1: starting ${TOTAL_DURATION_S}s sign loop with ${DROP_DURATION_S}s drops every ${DROP_INTERVAL_S}s"

success=0
device_error=0
other_fail=0

end=$(( $(date +%s) + TOTAL_DURATION_S ))
next_drop=$(( $(date +%s) + DROP_INTERVAL_S ))

while [[ $(date +%s) -lt $end ]]; do
    now=$(date +%s)
    # Schedule a drop?
    if [[ $now -ge $next_drop ]]; then
        echo "scenario1: dropping connection for ${DROP_DURATION_S}s at $(date -u +%H:%M:%S)"
        disable_proxy
        sleep "$DROP_DURATION_S"
        enable_proxy
        next_drop=$(( $(date +%s) + DROP_INTERVAL_S ))
    fi

    if shim_sign_once; then
        success=$(( success + 1 ))
    elif log_mentions_ckr CKR_DEVICE_ERROR \
        || log_mentions_ckr "CKR_GENERAL_ERROR" \
        || log_mentions_ckr "CKR_CRYPTOKI_NOT_INITIALIZED" ; then
        device_error=$(( device_error + 1 ))
    else
        other_fail=$(( other_fail + 1 ))
        echo "scenario1: unexpected error during sign:" >&2
        cat /tmp/shim_sign.log >&2
    fi
    sleep 0.3
done

clear_toxics

echo "scenario1: signs ok=${success} device_err=${device_error} other_fail=${other_fail}"

# Acceptance criteria:
# 1. There must be SOME successful signs (the shim recovers).
# 2. Errors must all be the expected CKR_DEVICE_ERROR /
#    CKR_CRYPTOKI_NOT_INITIALIZED family — no random other errors.
if [[ $success -lt 5 ]]; then
    echo "fail: scenario1 — only ${success} successful signs (need >=5)" >&2
    exit 1
fi
if [[ $other_fail -gt 0 ]]; then
    echo "fail: scenario1 — ${other_fail} unexpected error types" >&2
    exit 1
fi
echo "pass: scenario1"
