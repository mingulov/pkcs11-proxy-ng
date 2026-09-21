#!/bin/sh
# Scenario 1: backend hang.
#
# Set SLOW_BACKEND_SIGN_DELAY_MS=120000 on the chaos-daemon. Drive a
# consumer C_Sign. Verify the shim returns CKR_FUNCTION_FAILED
# promptly (W1-L3-01: a backend timeout is outcome-ambiguous — the
# wedged call may still complete — so it surfaces as FUNCTION_FAILED,
# not DEVICE_ERROR), the daemon stays alive, and future calls succeed
# once the delay is dropped.

set -u
. "$(dirname "$0")/_common.sh"

echo "=== Scenario 1: backend hang ==="

# One consumer C_Sign through the shim against the stub's fixed key.
drive_sign() {
    runner_exec pkcs11-tool \
        --module /usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so \
        --login --pin 1234 \
        --sign --mechanism SHA256-RSA-PKCS \
        --label slow-backend-key \
        --input-file /etc/hostname \
        --output-file /tmp/scenario1.sig
}

# (1) Set 120 s sign delay on the daemon. Re-create daemon with new env.
docker compose -f "$COMPOSE_FILE" stop chaos-daemon >/dev/null
docker compose -f "$COMPOSE_FILE" rm -f chaos-daemon >/dev/null
SLOW_BACKEND_SIGN_DELAY_MS=120000 \
docker compose -f "$COMPOSE_FILE" up -d chaos-daemon >/dev/null
if ! wait_for_daemon_healthy "$DAEMON_CONTAINER" 30; then
    echo "  daemon never became healthy after recreate: FAIL"
    exit 1
fi

# (2) Consumer C_Sign — must fail within the bounded timeout regime,
# never hang for the 120 s backend delay.
echo "  driving C_Sign (expect CKR_FUNCTION_FAILED, well under 120 s)..."
start_ms=$(now_ms)
output=$(drive_sign 2>&1)
rc=$?
end_ms=$(now_ms)
elapsed_ms=$((end_ms - start_ms))
echo "  sign returned rc=$rc in ${elapsed_ms}ms"
echo "$output" | head -5 | sed 's/^/    | /'

# pkcs11-tool retries one-shot C_Sign via SignUpdate/SignFinal, so the
# measured wall time spans two daemon request timeouts (2 s each in
# the chaos config) plus init/login/find/finalize overhead: ~4-5 s
# observed. 30 s bounds that regime with ample CI slack while still
# proving the call never waited out the 120 s backend hang.
if [ "$rc" -eq 0 ]; then
    echo "  sign unexpectedly succeeded against a hung backend: FAIL"
    exit 1
fi
if ! echo "$output" | grep -q "CKR_FUNCTION_FAILED"; then
    echo "  sign failed without CKR_FUNCTION_FAILED: FAIL"
    exit 1
fi
if [ "$elapsed_ms" -gt 30000 ]; then
    echo "  sign took ${elapsed_ms}ms (bound 30000ms): FAIL"
    exit 1
fi
echo "  hung-backend sign failed fast with CKR_FUNCTION_FAILED: PASS"

# (3) Daemon must still be alive.
if docker inspect --format '{{.State.Running}}' "$DAEMON_CONTAINER" 2>&1 | grep -q true; then
    echo "  daemon still alive: PASS"
else
    echo "  daemon still alive: FAIL"
    exit 1
fi

# (4) Drop the delay and verify recovery.
echo "  dropping delay; verifying recovery..."
docker compose -f "$COMPOSE_FILE" stop chaos-daemon >/dev/null
docker compose -f "$COMPOSE_FILE" rm -f chaos-daemon >/dev/null
SLOW_BACKEND_SIGN_DELAY_MS=0 \
docker compose -f "$COMPOSE_FILE" up -d chaos-daemon >/dev/null
if ! wait_for_daemon_healthy "$DAEMON_CONTAINER" 30; then
    echo "  daemon never became healthy after delay drop: FAIL"
    exit 1
fi

if drive_sign >/dev/null 2>&1; then
    echo "  post-recovery sign: PASS"
    echo "scenario1: PASS"
else
    echo "  post-recovery sign: FAIL"
    echo "scenario1: FAIL"
    exit 1
fi
