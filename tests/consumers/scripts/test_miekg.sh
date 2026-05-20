#!/bin/sh
# R5 consumer: miekg/pkcs11 Go binding (direct).
set -u
. /scripts/common.sh

backend="${1:-softhsm2}"
echo "== miekg/pkcs11 vs $backend =="
wait_for_daemon "${DAEMON_HOST:-daemon}" "${DAEMON_PORT:-7512}" || exit 1

if harness_miekg; then
    echo "miekg/$backend: PASS"
else
    echo "miekg/$backend: FAIL"
    exit 1
fi
