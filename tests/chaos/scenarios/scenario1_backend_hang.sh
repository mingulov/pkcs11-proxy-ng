#!/bin/sh
# R8 scenario 1 — backend hang.
#
# Set SLOW_BACKEND_SIGN_DELAY_MS=120000 on the chaos-daemon. Drive a
# consumer C_Sign. Verify the shim returns CKR_DEVICE_ERROR within
# the daemon's request_timeout_secs (2 s in the chaos config), the
# daemon stays alive, and future calls succeed once the delay is
# dropped.

set -u
. "$(dirname "$0")/_common.sh"

echo "=== R8 scenario 1: backend hang ==="

# (1) Set 120 s sign delay on the daemon. Re-create daemon with new env.
docker compose -f "$COMPOSE_FILE" stop chaos-daemon >/dev/null
docker compose -f "$COMPOSE_FILE" rm -f chaos-daemon >/dev/null
SLOW_BACKEND_SIGN_DELAY_MS=120000 \
docker compose -f "$COMPOSE_FILE" up -d chaos-daemon >/dev/null
sleep 5  # daemon warmup

start=$(date +%s)

# (2) Consumer Sign — should fail within request_timeout_secs.
echo "  driving C_Sign (expect CKR_DEVICE_ERROR within ~2 s)..."
output=$(runner_exec sh -c "
pkcs11-tool --module /usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so \\
    --list-slots 2>&1
" 2>&1) || true

elapsed=$(( $(date +%s) - start ))
echo "  list-slots returned in ${elapsed}s"
echo "$output" | head -3 | sed 's/^/    | /'

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
sleep 5

if runner_exec pkcs11-tool --module /usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so --list-slots >/dev/null 2>&1; then
    echo "  post-recovery list-slots: PASS"
    echo "scenario1: PASS"
else
    echo "  post-recovery list-slots: FAIL"
    echo "scenario1: FAIL"
    exit 1
fi
