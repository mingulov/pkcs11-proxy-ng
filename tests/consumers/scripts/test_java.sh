#!/bin/sh
# R5 consumer: Java SunPKCS11 provider.
set -u
. /scripts/common.sh

backend="${1:-softhsm2}"
echo "== java SunPKCS11 vs $backend =="
wait_for_daemon "${DAEMON_HOST:-daemon}" "${DAEMON_PORT:-7512}" || exit 1

if java -cp /usr/local/lib/harness.jar Harness \
        "$PKCS11_MODULE_PATH" "$TOKEN_LABEL" "$USER_PIN"; then
    echo "java/$backend: PASS"
else
    echo "java/$backend: FAIL"
    exit 1
fi
