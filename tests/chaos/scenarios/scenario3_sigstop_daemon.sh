#!/bin/sh
# Scenario 3: SIGSTOP daemon.
#
# Pause daemon 60s; resume. Verify the shim's http2 keepalive trips
# (a sign issued mid-STOP fails with CKR_GENERAL_ERROR well under the
# 60 s RPC deadline — a silently wedged channel would hang to the
# deadline instead), the shim reconnects on the next call, and
# operations resume within a bounded window.

set -u
. "$(dirname "$0")/_common.sh"

echo "=== Scenario 3: SIGSTOP daemon ==="

# One consumer C_Sign through the shim against the stub's fixed key.
drive_sign() {
    runner_exec pkcs11-tool \
        --module /usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so \
        --login --pin 1234 \
        --sign --mechanism SHA256-RSA-PKCS \
        --label slow-backend-key \
        --input-file /etc/hostname \
        --output-file /tmp/scenario3.sig
}

# Resolve the daemon PID inside its container — never assume PID 1.
PID=$(daemon_pid)
if [ -z "$PID" ]; then
    echo "  cannot resolve daemon PID in '$DAEMON_CONTAINER': FAIL"
    exit 1
fi
echo "  daemon PID in container: $PID"

# Ensure daemon is up + responsive.
docker exec "$DAEMON_CONTAINER" kill -CONT "$PID" 2>/dev/null || true
if ! wait_for_daemon_healthy "$DAEMON_CONTAINER" 30; then
    echo "  daemon never became healthy pre-STOP: FAIL"
    exit 1
fi

# (1) Baseline: sign works.
if drive_sign >/dev/null 2>&1; then
    echo "  baseline sign: PASS"
else
    echo "  baseline sign: FAIL"
    exit 1
fi

# (2) SIGSTOP daemon (pause) for 60 s total.
echo "  SIGSTOP daemon for 60s..."
stop_ms=$(now_ms)
docker exec "$DAEMON_CONTAINER" kill -STOP "$PID" 2>&1 || true
sleep 5

# (3) Mid-STOP sign: keepalive (10 s interval + 5 s timeout) must trip
# the stalled channel, so this fails with the lifecycle transport RV
# in ~30 s — proving the trip rather than a hang to the 60 s RPC
# deadline.
echo "  driving mid-STOP sign (expect CKR_GENERAL_ERROR, < 50 s)..."
start_ms=$(now_ms)
output=$(drive_sign 2>&1)
rc=$?
end_ms=$(now_ms)
elapsed_ms=$((end_ms - start_ms))
echo "  mid-STOP sign returned rc=$rc in ${elapsed_ms}ms"
if [ "$rc" -eq 0 ]; then
    echo "  mid-STOP sign unexpectedly succeeded: FAIL"
    docker exec "$DAEMON_CONTAINER" kill -CONT "$PID" 2>&1 || true
    exit 1
fi
if ! echo "$output" | grep -q "CKR_GENERAL_ERROR"; then
    echo "  mid-STOP sign failed without CKR_GENERAL_ERROR: FAIL"
    echo "$output" | head -5 | sed 's/^/    | /'
    docker exec "$DAEMON_CONTAINER" kill -CONT "$PID" 2>&1 || true
    exit 1
fi
if [ "$elapsed_ms" -gt 50000 ]; then
    echo "  mid-STOP sign took ${elapsed_ms}ms (bound 50000ms): keepalive trip suspect: FAIL"
    docker exec "$DAEMON_CONTAINER" kill -CONT "$PID" 2>&1 || true
    exit 1
fi
echo "  keepalive trip during STOP: PASS"

# Hold the STOP for the full 60 s before resuming.
elapsed_stop_ms=$(($(now_ms) - stop_ms))
remaining_ms=$((60000 - elapsed_stop_ms))
if [ "$remaining_ms" -gt 0 ]; then
    sleep $(( (remaining_ms + 999) / 1000 ))
fi

# (4) SIGCONT.
echo "  SIGCONT daemon"
docker exec "$DAEMON_CONTAINER" kill -CONT "$PID" 2>&1 || true

# (5) The shim must reconnect: retry the SIGN path (not list-slots)
# with a bounded window and assert the reconnect timing.
echo "  retrying sign path (up to 30 s)..."
ok=false
rec_ms=$(now_ms)
attempt=0
while [ "$attempt" -lt 6 ]; do
    attempt=$((attempt + 1))
    if drive_sign >/dev/null 2>&1; then
        ok=true
        break
    fi
    sleep 5
done
rec_elapsed_ms=$(($(now_ms) - rec_ms))

if [ "$ok" = true ]; then
    echo "  post-SIGCONT sign recovered in ${rec_elapsed_ms}ms (attempt $attempt): PASS"
    echo "scenario3: PASS"
else
    echo "  post-SIGCONT sign never recovered: FAIL"
    echo "scenario3: FAIL"
    exit 1
fi
