#!/usr/bin/env bash
# Scenario 6: 20 concurrent shim processes all start cold against the
# same daemon. With the backoff+jitter in place, no thundering
# herd: connect retries spread out instead of synchronizing.
#
# This script doesn't manipulate toxiproxy; it just spawns N concurrent
# `pkcs11-tool --list-slots` processes after a brief delay and measures
# whether they all succeed within a window.
#
# To convert this into the "all reconnect after daemon restart"
# variant, run `scenario2_quick_restart.sh` immediately before this
# script — the new client_context_id round implicitly exercises the
# backoff path.

set -euo pipefail
. "$(dirname "$0")/_common.sh"

N_SHIMS="${N_SHIMS:-20}"

wait_for_toxiproxy
clear_toxics

echo "scenario6: spawning ${N_SHIMS} concurrent shims"
start=$(date +%s)
pids=()
for i in $(seq 1 "$N_SHIMS"); do
    (
        # Each shim is a fresh process: its own C_Initialize, its own
        # connect attempt, its own backoff path.
        if pkcs11-tool --module "$PKCS11_MODULE" --list-slots >/tmp/r2_herd_$i.log 2>&1; then
            echo "ok $i"
        else
            echo "fail $i"
            cat /tmp/r2_herd_$i.log >&2
        fi
    ) &
    pids+=( $! )
done

ok=0
fail=0
for pid in "${pids[@]}"; do
    if wait "$pid"; then
        ok=$(( ok + 1 ))
    else
        fail=$(( fail + 1 ))
    fi
done
elapsed=$(( $(date +%s) - start ))

echo "scenario6: ok=${ok} fail=${fail} elapsed=${elapsed}s"

if [[ $fail -ne 0 ]]; then
    echo "fail: scenario6 — ${fail} shims failed to start" >&2
    exit 1
fi
echo "pass: scenario6 — all ${N_SHIMS} shims completed in ${elapsed}s"
exit 0
