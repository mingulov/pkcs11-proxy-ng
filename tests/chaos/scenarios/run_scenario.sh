#!/bin/sh
# R8 chaos scenario dispatcher.
#
# Usage: run_scenario.sh <N>     # N in {1..6}
#        run_scenario.sh all     # run all scenarios sequentially

set -u

DIR="$(dirname "$0")"

case "${1:-}" in
    1) exec "$DIR/scenario1_backend_hang.sh" ;;
    2) exec "$DIR/scenario2_backend_oom.sh" ;;
    3) exec "$DIR/scenario3_sigstop_daemon.sh" ;;
    4) exec "$DIR/scenario4_disk_full_or_mid_write.sh" ;;
    5) exec "$DIR/scenario4_disk_full_or_mid_write.sh" ;;  # 4 covers 5
    6) exec "$DIR/scenario6_tls_cert_expiry.sh" ;;
    all)
        rc=0
        for n in 1 2 3 4 6; do
            echo
            "$DIR/run_scenario.sh" "$n" || rc=$?
        done
        exit $rc
        ;;
    *)
        echo "Usage: $0 <N|all>   N in {1,2,3,4,6}"
        exit 2
        ;;
esac
