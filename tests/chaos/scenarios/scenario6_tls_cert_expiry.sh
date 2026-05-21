#!/usr/bin/env bash
# R8 scenario 6 — TLS cert expiry.
#
# Mint a CA, a 60-second-lifetime server cert (signed by CA), and a
# long-lived client cert (signed by CA). Start a daemon variant with
# mTLS using those certs. Run a consumer probe loop for 90 seconds.
# Capture the CK_RV / connect error the consumer sees post-expiry.
#
# Pass criteria:
#   - Before expiry: probe succeeds.
#   - After expiry: NEW connection attempts fail at TLS handshake.
#     The shim's bounded-backoff retry loop trips its budget and
#     returns CKR_DEVICE_ERROR (lifecycle path: CKR_GENERAL_ERROR
#     per the R3 spec-conformance rule).
#   - Daemon does NOT crash.

set -euo pipefail

WORK="$(mktemp -d)"
SCENARIO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== R8 scenario 6: TLS cert expiry ==="
echo "  work dir: $WORK"

# ─── Mint certs (short-lived server, long-lived CA + client) ──────────────
openssl genrsa -out "$WORK/ca.key" 2048 >/dev/null 2>&1
openssl req -new -x509 -days 7 -key "$WORK/ca.key" \
    -out "$WORK/ca.crt" -subj "/CN=r8-test-ca" >/dev/null 2>&1

# Server: 60-second lifetime.
openssl genrsa -out "$WORK/server.key" 2048 >/dev/null 2>&1
openssl req -new -key "$WORK/server.key" \
    -out "$WORK/server.csr" -subj "/CN=chaos-daemon" >/dev/null 2>&1
cat > "$WORK/server.ext" <<EOF
subjectAltName = DNS:chaos-daemon,DNS:localhost,IP:127.0.0.1
EOF
# OpenSSL's -days flag has 1-day granularity; use -enddate for seconds.
# Computed below by formatting `date +%Y%m%d%H%M%SZ` for now+60s.
# OpenSSL CLI signs with day-granular -days. For sub-day expiry we'd
# need `faketime` (or libfaketime preload) to backdate the issuing
# clock, OR a small custom minter (Python cryptography / Rust rcgen).
# Neither is in the test host's dependencies by default; tagged
# R8-FOLLOWUP-tls-cert-expiry-minter.
#
# As a workable approximation: mint with -days 1 and SLEEP 23h59m
# between mint and probe — practical only as a slow soak. The
# default below uses -days 1 so the script SUCCEEDS at the cert
# mint step; the 90-second probe loop will see all-OK handshakes.
# Operators running this scenario for real should swap in faketime
# (`faketime '1d ago' openssl x509 -req ...`) before calling the
# x509 -req line below.
openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
    -CAcreateserial -out "$WORK/server.crt" \
    -extfile "$WORK/server.ext" -days 1 >/dev/null 2>&1

# Client: 7-day lifetime.
openssl genrsa -out "$WORK/client.key" 2048 >/dev/null 2>&1
openssl req -new -key "$WORK/client.key" \
    -out "$WORK/client.csr" -subj "/CN=r8-test-client" >/dev/null 2>&1
openssl x509 -req -in "$WORK/client.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
    -CAserial "$WORK/ca.srl" -days 7 -out "$WORK/client.crt" >/dev/null 2>&1

# mTLS private key MUST be 0600 (R9 hardening).
chmod 0600 "$WORK/server.key" "$WORK/client.key"

server_expiry=$(openssl x509 -enddate -noout -in "$WORK/server.crt" | sed 's/notAfter=//')
echo "  CA       : $WORK/ca.crt"
echo "  server   : $WORK/server.crt  expires=$server_expiry"
echo "  client   : $WORK/client.crt"

# ─── Bring up daemon variant with mTLS + chaos-daemon image ──────────────
# We can't reuse the chaos-daemon image directly because it bakes in
# auth="none". Mount-override the proxy.toml + cert files.
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
    -v "$SCENARIO_DIR/../../../tests/r2_resilience/slow_backend/target/release:/opt/slow_backend:ro" \
    --entrypoint /usr/bin/pkcs11-proxy-ng \
    pkcs11-proxy-ng:chaos-daemon /etc/r8/proxy.toml >/dev/null 2>&1
sleep 4

echo "=== consumer probe loop (90 s) ==="
end=$(( $(date +%s) + 90 ))
first_fail_t=
while [ "$(date +%s)" -lt "$end" ]; do
    elapsed=$(( 90 - (end - $(date +%s)) ))
    if openssl s_client -connect 127.0.0.1:7512 -CAfile "$WORK/ca.crt" \
            -cert "$WORK/client.crt" -key "$WORK/client.key" \
            -tls1_2 -verify_return_error </dev/null >/dev/null 2>&1; then
        echo "[t=${elapsed}s] handshake OK"
    else
        if [ -z "$first_fail_t" ]; then first_fail_t=$elapsed; fi
        echo "[t=${elapsed}s] handshake FAIL"
    fi
    sleep 5
done

echo "=== verdict ==="
if docker inspect --format '{{.State.Running}}' r8-tls-daemon | grep -q true; then
    echo "  daemon survived 90 s mTLS probing: PASS"
else
    echo "  daemon died: FAIL"
fi

# With -days 1 (no sub-day minter), all handshakes should have
# succeeded — that's the smoke-test bar. Expiry-time observation
# only happens when faketime is wired up (R8-FOLLOWUP-tls-cert-
# expiry-minter).
if [ -z "$first_fail_t" ]; then
    echo "  no handshake failures observed (cert valid for full 90 s): scenario6 = PARTIAL"
    echo "  full expiry-mode behaviour observation defers to R8-FOLLOWUP-tls-cert-expiry-minter"
else
    echo "  first handshake failure at t=${first_fail_t}s: $first_fail_t"
fi

docker rm -f r8-tls-daemon >/dev/null 2>&1 || true
rm -rf "$WORK"
