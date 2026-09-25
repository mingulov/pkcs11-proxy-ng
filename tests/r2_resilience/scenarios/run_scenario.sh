#!/usr/bin/env bash
# Dispatcher: `run_scenario.sh N` runs scenario N (1..6) and prints
# pass/fail/skip lines. The fixture's docker-compose.yml mounts this
# script into the runner image.

set -euo pipefail
n="${1:-}"
case "$n" in
    1) exec /scenarios/scenario1_tcp_drops.sh "$@" ;;
    2) exec /scenarios/scenario2_quick_restart.sh "$@" ;;
    3) exec /scenarios/scenario3_lease_expiry.sh "$@" ;;
    4) exec /scenarios/scenario4_dns_change.sh "$@" ;;
    5) exec /scenarios/scenario5_slow_backend.sh "$@" ;;
    6) exec /scenarios/scenario6_thundering_herd.sh "$@" ;;
    all)
        rc=0
        for i in 1 2 3 4 5 6; do
            echo "--- scenario $i ---"
            "$0" "$i" || rc=$?
        done
        exit "$rc"
        ;;
    *)
        echo "usage: $0 <1..6|all>" >&2
        exit 64
        ;;
esac
