#!/bin/sh
# consumer: ThalesGroup/crypto11 Go wrapper.
set -u
. /scripts/common.sh

backend="${1:-softhsm2}"
echo "== crypto11 vs $backend =="
wait_for_daemon "${DAEMON_HOST:-daemon}" "${DAEMON_PORT:-7512}" || exit 1

if harness_crypto11; then
    echo "crypto11/$backend: PASS"
else
    echo "crypto11/$backend: FAIL"
    exit 1
fi
