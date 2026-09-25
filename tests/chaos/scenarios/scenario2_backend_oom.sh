#!/bin/sh
# Scenario 2: backend OOM (CKR_HOST_MEMORY).
#
# Recreate the daemon with SLOW_BACKEND_BREAK_AFTER_CALLS so the stub
# backend serves startup + warmup normally, then every subsequent call
# fails fast with SLOW_BACKEND_BREAK_RV_HEX (0x2 = CKR_HOST_MEMORY).
# Drive consecutive consumer C_Sign attempts and verify:
#   - each post-break attempt fails with CKR_HOST_MEMORY,
#   - the daemon's tonic-health flips to NOT_SERVING after
#     backend_health_consecutive_failures (2 in the chaos config),
#   - the daemon stays alive; future calls succeed once the fault is
#     dropped (daemon recreated without the break env).

set -u
. "$(dirname "$0")/_common.sh"

echo "=== Scenario 2: backend OOM ==="

# One consumer C_Sign through the shim against the stub's fixed key.
drive_sign() {
    runner_exec pkcs11-tool \
        --module /usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so \
        --login --pin 1234 \
        --sign --mechanism SHA256-RSA-PKCS \
        --label slow-backend-key \
        --input-file /etc/hostname \
        --output-file /tmp/scenario2.sig
}

# Serves SERVING (rc 0) / NOT_SERVING (rc 1) from inside the daemon netns.
daemon_health() {
    docker exec "$DAEMON_CONTAINER" pkcs11-proxy-ng-cli health 2>&1
}

recreate_daemon() {
    docker compose -f "$COMPOSE_FILE" stop chaos-daemon >/dev/null
    docker compose -f "$COMPOSE_FILE" rm -f chaos-daemon >/dev/null
    env "$@" docker compose -f "$COMPOSE_FILE" up -d chaos-daemon >/dev/null
}

OUT=$(mktemp /tmp/scenario2.XXXXXX.out)
trap 'rm -f "$OUT"' EXIT INT TERM

# (1) Baseline without the fault: stack works, health SERVING.
recreate_daemon SLOW_BACKEND_SIGN_DELAY_MS=0
if ! wait_for_daemon_healthy "$DAEMON_CONTAINER" 30; then
    echo "  baseline daemon never became healthy: FAIL"
    exit 1
fi
if ! drive_sign >/dev/null 2>&1; then
    echo "  baseline sign failed without any fault: FAIL"
    exit 1
fi
echo "  baseline sign + SERVING health: PASS"

# (2) Recreate with the break armed. Startup + the first calls consume
# a handful of backend ops; the trip lands mid-run deterministically
# (the stub latches BROKEN past the threshold), so loop until the
# consecutive-failure streak below is observed instead of counting ops.
recreate_daemon SLOW_BACKEND_BREAK_AFTER_CALLS=20 SLOW_BACKEND_BREAK_RV_HEX=0x2
if ! wait_for_daemon_healthy "$DAEMON_CONTAINER" 30; then
    echo "  break-armed daemon never became healthy: FAIL"
    exit 1
fi

echo "  driving signs until 3 consecutive CKR_HOST_MEMORY failures..."
streak=0
attempt=0
while [ "$attempt" -lt 12 ]; do
    attempt=$((attempt + 1))
    if drive_sign >"$OUT" 2>&1; then
        echo "    attempt $attempt: ok (pre-break warmup)"
        streak=0
    elif grep -q "CKR_HOST_MEMORY" "$OUT"; then
        streak=$((streak + 1))
        echo "    attempt $attempt: CKR_HOST_MEMORY (streak $streak)"
    else
        echo "    attempt $attempt: unexpected failure: FAIL"
        sed 's/^/      | /' "$OUT" | head -5
        exit 1
    fi
    if [ "$streak" -ge 3 ]; then
        break
    fi
done
if [ "$streak" -lt 3 ]; then
    echo "  never observed 3 consecutive CKR_HOST_MEMORY failures: FAIL"
    exit 1
fi
echo "  consecutive CKR_HOST_MEMORY failures: PASS"

# (3) The health gate flips asynchronously: poll for NOT_SERVING.
echo "  waiting for health gate to flip to NOT_SERVING..."
flipped=false
i=0
while [ "$i" -lt 15 ]; do
    if daemon_health | grep -q "NOT_SERVING"; then
        flipped=true
        break
    fi
    sleep 1
    i=$((i + 1))
done
if [ "$flipped" = true ]; then
    echo "  health gate flipped to NOT_SERVING: PASS"
else
    echo "  health gate never flipped: FAIL"
    daemon_health | sed 's/^/    | /'
    exit 1
fi

# (4) Daemon must still be alive.
if docker inspect --format '{{.State.Running}}' "$DAEMON_CONTAINER" 2>&1 | grep -q true; then
    echo "  daemon still alive: PASS"
else
    echo "  daemon still alive: FAIL"
    exit 1
fi

# (5) Drop the fault and verify recovery.
echo "  dropping fault; verifying recovery..."
recreate_daemon SLOW_BACKEND_SIGN_DELAY_MS=0
if ! wait_for_daemon_healthy "$DAEMON_CONTAINER" 30; then
    echo "  daemon never recovered to SERVING: FAIL"
    exit 1
fi
if drive_sign >/dev/null 2>&1; then
    echo "  post-recovery sign: PASS"
    echo "scenario2: PASS"
else
    echo "  post-recovery sign: FAIL"
    echo "scenario2: FAIL"
    exit 1
fi
