#!/usr/bin/env bash
# Scenario 3: Daemon restart BEYOND lease_seconds.
# Expected: shim's first post-restart RPC returns
# CKR_CRYPTOKI_NOT_INITIALIZED; calling C_Finalize + C_Initialize
# recovers (the test proves this by running the second pkcs11-tool
# invocation, which goes through a fresh C_Initialize on its own).

set -euo pipefail
. "$(dirname "$0")/_common.sh"

DAEMON_CONTAINER="${DAEMON_CONTAINER:-r2-daemon}"
LEASE_S="${LEASE_S:-30}"
WAIT_S=$(( LEASE_S + 5 ))

wait_for_toxiproxy
clear_toxics
ensure_test_key

# Baseline sign.
shim_sign_once || { echo "fail: scenario3 — pre-restart sign failed" >&2; exit 1; }

echo "scenario3: stopping daemon for ${WAIT_S}s (longer than lease ${LEASE_S}s)"
docker stop -t 2 "$DAEMON_CONTAINER" >/dev/null
sleep "$WAIT_S"
docker start "$DAEMON_CONTAINER" >/dev/null

# Wait for daemon to be reachable again.
for _ in $(seq 1 30); do
    if pkcs11-proxy-ng-cli --endpoint "$PKCS11_PROXY_ENDPOINT" \
            list-slots >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

# Each pkcs11-tool invocation calls C_Initialize itself, so this run
# uses a FRESH client_context_id and should succeed cleanly.
if shim_sign_once; then
    echo "pass: scenario3 — fresh C_Initialize recovered after lease expiry"
    exit 0
fi
echo "fail: scenario3 — recovery flow did not succeed" >&2
cat /tmp/shim_sign.log >&2
exit 1
