#!/usr/bin/env bash
# Scenario 6: TLS cert expiry.
#
# Mint a CA, a SHORT-LIVED server cert (default 60s), and a longer-
# lived client cert via the rcgen-based cert-minter helper. Start a
# daemon variant with mTLS using those certs. Run a 90-second
# consumer probe loop. Capture the connect/handshake outcome each
# tick; expect probes to succeed before t=60s and fail after.
#
# The probe is a real client-path call (pkcs11-proxy-ng-cli
# list-slots over mTLS), not a bare TLS-handshake probe: expiry must
# be proven through the stack the application uses.
#
# Pass criteria:
#   - At least one client call succeeds before t=cert-expiry.
#   - At least one client call FAILS after t=cert-expiry.
#   - Daemon does NOT crash.
#
# Replaces the day-granular openssl -days flag — FOLLOWUP-tls-
# cert-expiry-minter is closed by this script.

set -euo pipefail

WORK="$(mktemp -d)"
SCENARIO_DIR="$(cd "$(dirname "$0")" && pwd)"
SUBMODULE_ROOT="$(cd "$SCENARIO_DIR/../../.." && pwd)"
MINTER="$SUBMODULE_ROOT/tests/chaos/cert_minter/target/release/cert-minter"
CLI="${PKCS11_PROXY_NG_CLI:-$SUBMODULE_ROOT/target/release/pkcs11-proxy-ng-cli}"
SERVER_TTL="${SERVER_TTL:-60}"
PROBE_SECS="${PROBE_SECS:-90}"
PROBE_INTERVAL="${PROBE_INTERVAL:-3}"
ENDPOINT="https://127.0.0.1:7512"

echo "=== Scenario 6: TLS cert expiry ==="
echo "  work dir:     $WORK"
echo "  server TTL:   ${SERVER_TTL}s"
echo "  probe window: ${PROBE_SECS}s @ ${PROBE_INTERVAL}s ticks"

if [ ! -x "$MINTER" ]; then
    echo ">>> Building cert-minter (rcgen helper, one-shot)…"
    (cd "$SUBMODULE_ROOT/tests/chaos/cert_minter" && cargo build --release)
fi
if [ ! -x "$CLI" ]; then
    echo ">>> Building pkcs11-proxy-ng-cli (mTLS probe, one-shot)…"
    (cd "$SUBMODULE_ROOT" && cargo build --release -p pkcs11-proxy-ng-cli)
fi

"$MINTER" \
    --out-dir "$WORK" \
    --server-expires-in-seconds "$SERVER_TTL" \
    --client-expires-in-seconds 600 \
    --ca-expires-in-seconds 3600

cat > "$WORK/proxy.toml" <<EOF
[backend]
module = "/opt/slow_backend/libslow_backend.so"

[proxy]
request_timeout_secs = 5
startup_timeout_secs = 10
shutdown_grace_secs = 1
backend_health_consecutive_failures = 3

[listener.remote]
bind = "0.0.0.0:7512"
auth = "mtls"
ca_cert = "/etc/r8/ca.crt"
server_cert = "/etc/r8/server.crt"
server_key = "/etc/r8/server.key"
allow_insecure_tcp = false

[auth]
allow_all_authenticated = true
EOF

docker rm -f r8-tls-daemon >/dev/null 2>&1 || true
docker run -d --name r8-tls-daemon \
    --network host \
    -v "$WORK:/etc/r8:ro" \
    -v "$SUBMODULE_ROOT/tests/r2_resilience/slow_backend/target/release:/opt/slow_backend:ro" \
    --entrypoint /usr/bin/pkcs11-proxy-ng \
    pkcs11-proxy-ng:chaos-daemon /etc/r8/proxy.toml >/dev/null

# One client-path probe: full mTLS handshake + C_Initialize + RPC.
probe_once() {
    "$CLI" --endpoint "$ENDPOINT" \
        --tls-ca-cert "$WORK/ca.crt" \
        --tls-client-cert "$WORK/client.crt" \
        --tls-client-key "$WORK/client.key" \
        list-slots >/dev/null 2>&1
}

# Readiness: the cert is already aging, so poll (no fixed sleep).
ready=false
for _ in $(seq 1 30); do
    if probe_once; then
        ready=true
        break
    fi
    sleep 1
done
if [ "$ready" != true ]; then
    echo "  daemon never became ready under mTLS: FAIL"
    docker rm -f r8-tls-daemon >/dev/null 2>&1 || true
    exit 1
fi

start_ts=$(date +%s)
end_ts=$(( start_ts + PROBE_SECS ))
first_ok_t=
last_ok_t=
first_fail_t=

echo "=== consumer probe loop ==="
while [ "$(date +%s)" -lt "$end_ts" ]; do
    now=$(date +%s)
    elapsed=$(( now - start_ts ))
    if probe_once; then
        echo "[t=${elapsed}s] client call OK"
        if [ -z "$first_ok_t" ]; then first_ok_t=$elapsed; fi
        last_ok_t=$elapsed
    else
        echo "[t=${elapsed}s] client call FAIL"
        if [ -z "$first_fail_t" ]; then first_fail_t=$elapsed; fi
    fi
    sleep "$PROBE_INTERVAL"
done

echo
echo "=== verdict ==="
verdict_failed=0
if docker inspect --format '{{.State.Running}}' r8-tls-daemon | grep -q true; then
    echo "  daemon survived ${PROBE_SECS}s mTLS probing: PASS"
else
    echo "  daemon died: FAIL"
    verdict_failed=1
fi

if [ -n "$first_ok_t" ]; then
    echo "  first client call OK at t=${first_ok_t}s: PASS"
else
    echo "  no client call ever succeeded: FAIL"
    verdict_failed=1
fi

# Verify OK→FAIL transition: cert was honoured at start, then post-expiry
# failures observed. Wall-clock timing varies by ~10s (cert is minted before
# daemon container starts), so we don't pin the exact t-value.
if [ -n "$first_fail_t" ] && [ -n "$last_ok_t" ] && [ "$first_fail_t" -gt "$last_ok_t" ]; then
    echo "  OK→FAIL transition: last OK at t=${last_ok_t}s, first FAIL at t=${first_fail_t}s: PASS"
elif [ -n "$first_fail_t" ]; then
    echo "  first FAIL at t=${first_fail_t}s but no OK before it: FAIL"
    verdict_failed=1
else
    echo "  no client-call failure observed in ${PROBE_SECS}s probe window: FAIL"
    verdict_failed=1
fi

echo "  cert lifetime ${SERVER_TTL}s; last OK t=${last_ok_t:-none}s; first FAIL t=${first_fail_t:-none}s"

docker logs r8-tls-daemon 2>&1 | tail -20 > "$WORK/daemon.log"
echo "  daemon log tail: $WORK/daemon.log"

docker rm -f r8-tls-daemon >/dev/null 2>&1 || true

if [ "$verdict_failed" -eq 0 ]; then
    echo "  OVERALL: PASS"
    rm -rf "$WORK"
    exit 0
else
    echo "  OVERALL: FAIL  (work dir kept: $WORK)"
    exit 1
fi
