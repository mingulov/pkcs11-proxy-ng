#!/usr/bin/env bash
# Scenario 2: Daemon restart inside lease_seconds (30s default).
# Expected: PKCS#11 sessions survive — the same client_context_id
# stays valid after the daemon comes back, so post-restart signs
# succeed without C_Finalize+C_Initialize.
#
# Implementation note: docker-compose's `restart` is asynchronous and
# returns before the new daemon binds the port. We poll the daemon's
# new TCP socket via toxiproxy to know when traffic flows again.

set -euo pipefail
. "$(dirname "$0")/_common.sh"

DAEMON_CONTAINER="${DAEMON_CONTAINER:-r2-daemon}"

wait_for_toxiproxy
clear_toxics
ensure_test_key

# Take a sign baseline (proves the path works pre-restart).
shim_sign_once || { echo "fail: scenario2 — pre-restart sign failed" >&2; exit 1; }

echo "scenario2: restarting ${DAEMON_CONTAINER} (quick — inside lease_seconds)"
restart_t0=$(date +%s)
docker restart -t 2 "$DAEMON_CONTAINER" >/dev/null

# Spin until the daemon's gRPC port is back behind toxiproxy. Toxiproxy
# keeps its own connection to upstream so we cannot rely on its
# `enabled` flag alone — try the actual probe RPC via pkcs11-proxy-ng-cli.
for _ in $(seq 1 30); do
    if pkcs11-proxy-ng-cli --endpoint "$PKCS11_PROXY_ENDPOINT" \
            list-slots >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done
restart_t1=$(date +%s)
echo "scenario2: daemon back after $((restart_t1 - restart_t0))s"

# Now run a sign with the SAME shim process. The shim's cached client
# may need a reconnect; tonic should retry transparently and the
# daemon should accept the previously-issued client_context_id IF the
# lease has not expired. We allow a short retry loop because the
# transport may take a few moments to settle.
attempt=0
while :; do
    attempt=$(( attempt + 1 ))
    if shim_sign_once; then
        echo "pass: scenario2 — post-restart sign succeeded on attempt ${attempt}"
        exit 0
    fi
    # Application-level recovery is OUT-OF-SCOPE for scenario 2 — the
    # whole point is sessions must survive. If we see CKR_CRYPTOKI_NOT_INITIALIZED
    # here, the lease was lost (or the daemon doesn't preserve context
    # across restarts), which IS a failure of this scenario.
    if log_mentions_ckr "CKR_CRYPTOKI_NOT_INITIALIZED"; then
        echo "fail: scenario2 — lease lost across restart (saw CKR_CRYPTOKI_NOT_INITIALIZED)" >&2
        exit 1
    fi
    if [[ $attempt -ge 5 ]]; then
        echo "fail: scenario2 — sign did not recover after restart" >&2
        cat /tmp/shim_sign.log >&2
        exit 1
    fi
    sleep 1
done
