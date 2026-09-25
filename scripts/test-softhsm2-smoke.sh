#!/usr/bin/env bash
# End-to-end smoke test: start a pkcs11-proxy-ng daemon backed by
# SoftHSM2 with auth="none" and use the shim to perform a real RSA
# sign via pkcs11-tool. Exercises:
#
#   - daemon config loading (incl. placeholder check, registry load)
#   - SIGHUP-safe graceful shutdown path (we send SIGTERM at the end)
#   - shim ↔ daemon GetBackendInterfaces probe + server registry
#     consumption
#   - shim's C_GetSlotList → C_OpenSession → C_Login → C_GenerateKey
#     → C_SignInit / C_Sign chain end-to-end against a real backend
#
# The script uses host-installed softhsm2-util + pkcs11-tool. It
# expects the workspace to already have been built once
# (target/release/pkcs11-proxy-ng and libpkcs11_proxy_ng_shim.so);
# scripts/release-dry-run.sh is the standard way to produce them.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_ROOT="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"
case "$TARGET_ROOT" in
    /*) ;;
    *) TARGET_ROOT="$ROOT_DIR/$TARGET_ROOT" ;;
esac
RELEASE_DIR="$TARGET_ROOT/release"
DAEMON_BIN="$RELEASE_DIR/pkcs11-proxy-ng"
SHIM_LIB="$RELEASE_DIR/libpkcs11_proxy_ng_shim.so"

# Pick a SoftHSM2 .so the host actually has.
SOFTHSM2_LIB=""
for cand in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/local/lib/softhsm/libsofthsm2.so; do
    [[ -f "$cand" ]] && SOFTHSM2_LIB="$cand" && break
done
[[ -z "$SOFTHSM2_LIB" ]] && {
    echo "SoftHSM2 module not found; install softhsm2 first" >&2
    exit 1
}

for cmd in softhsm2-util pkcs11-tool; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "Required command not found: $cmd" >&2
        exit 1
    }
done

[[ -x "$DAEMON_BIN" ]] || {
    echo "Daemon binary not found at $DAEMON_BIN" >&2
    echo "Run scripts/release-dry-run.sh first." >&2
    exit 1
}
[[ -f "$SHIM_LIB" ]] || {
    echo "Shim library not found at $SHIM_LIB" >&2
    echo "Run scripts/release-dry-run.sh first." >&2
    exit 1
}

WORKDIR="$(mktemp -d)"
trap 'cleanup' EXIT

DAEMON_PID=""

cleanup() {
    set +e
    if [[ -n "${DAEMON_PID}" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -TERM "$DAEMON_PID" 2>/dev/null
        # Give the daemon up to its full shutdown_grace_secs (default
        # 30) to drain before SIGKILL — the test exercises the
        # graceful-shutdown code path.
        for _ in $(seq 1 30); do
            kill -0 "$DAEMON_PID" 2>/dev/null || break
            sleep 1
        done
        kill -0 "$DAEMON_PID" 2>/dev/null && kill -KILL "$DAEMON_PID" 2>/dev/null
    fi
    rm -rf "$WORKDIR"
}

# Use a process-local SoftHSM2 token dir so nothing leaks between
# test runs and the host's own SoftHSM2 store stays untouched.
export SOFTHSM2_CONF="$WORKDIR/softhsm2.conf"
TOKEN_DIR="$WORKDIR/tokens"
mkdir -p "$TOKEN_DIR"
cat >"$SOFTHSM2_CONF" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
log.level = INFO
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF

USER_PIN="1234"
SO_PIN="abcd"
TOKEN_LABEL="r1-smoke"

echo "[1/5] Initializing SoftHSM2 token in $TOKEN_DIR …"
softhsm2-util --init-token --free \
    --label "$TOKEN_LABEL" \
    --so-pin "$SO_PIN" \
    --pin "$USER_PIN" >/dev/null

# Pick a random free TCP port so concurrent runs don't collide.
BIND_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
DAEMON_BIND="127.0.0.1:${BIND_PORT}"
DAEMON_ENDPOINT="http://${DAEMON_BIND}"

cat >"$WORKDIR/proxy.toml" <<EOF
[backend]
module = "$SOFTHSM2_LIB"

[proxy]
request_timeout_secs = 30
startup_timeout_secs = 30
shutdown_grace_secs = 30
backend_health_consecutive_failures = 3

[listener.remote]
bind = "$DAEMON_BIND"
auth = "none"
allow_insecure_tcp = true

[auth]
EOF

echo "[2/5] Starting pkcs11-proxy-ng daemon at $DAEMON_ENDPOINT (auth=\"none\", SoftHSM2 backend) …"
RUST_LOG="${RUST_LOG:-pkcs11_proxy_ng=info}" \
    "$DAEMON_BIN" "$WORKDIR/proxy.toml" \
    >"$WORKDIR/daemon.log" 2>&1 &
DAEMON_PID=$!

# Wait for the daemon to bind the port (max 15 s).
for i in $(seq 1 30); do
    if (echo >"/dev/tcp/127.0.0.1/${BIND_PORT}") 2>/dev/null; then
        break
    fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "Daemon exited during startup; tail of daemon log:" >&2
        tail -50 "$WORKDIR/daemon.log" >&2 || true
        exit 1
    fi
    sleep 0.5
    if [[ "$i" -eq 30 ]]; then
        echo "Daemon did not bind $DAEMON_BIND within 15s; daemon log:" >&2
        tail -50 "$WORKDIR/daemon.log" >&2 || true
        exit 1
    fi
done

# Confirm the expected insecure-TCP startup WARN actually fired.
grep -q "listening on tcp without authentication" "$WORKDIR/daemon.log" || {
    echo "Daemon did not emit the documented insecure-TCP startup warning;" >&2
    echo "smoke-test failed (operational visibility regression):" >&2
    tail -50 "$WORKDIR/daemon.log" >&2 || true
    exit 1
}
echo "    insecure-TCP startup WARN observed."

# Confirm the registry payload was loaded.
grep -q "mechanism registry ready" "$WORKDIR/daemon.log" || {
    echo "Daemon did not log registry load; smoke-test failed:" >&2
    tail -50 "$WORKDIR/daemon.log" >&2 || true
    exit 1
}
echo "    mechanism registry log line observed."

# All subsequent pkcs11-tool invocations talk to the shim, which is
# configured purely by env vars (the design's PKCS11_PROXY_ENDPOINT /
# PKCS11_PROXY_SOCKET contract).
export PKCS11_PROXY_ENDPOINT="$DAEMON_ENDPOINT"
export PKCS11_PROXY_CONNECT_TIMEOUT=10

echo "[3/5] Listing slots via the shim (proves probe + slot pass-through) …"
pkcs11-tool --module "$SHIM_LIB" --list-slots >"$WORKDIR/slots.txt"
grep -q "$TOKEN_LABEL" "$WORKDIR/slots.txt" || {
    echo "Expected token label '$TOKEN_LABEL' missing from --list-slots output:" >&2
    cat "$WORKDIR/slots.txt" >&2
    exit 1
}
echo "    slot with token '$TOKEN_LABEL' visible through the shim."

echo "[4/5] Generating an RSA-2048 key in the proxied token …"
pkcs11-tool --module "$SHIM_LIB" \
    --token-label "$TOKEN_LABEL" \
    --login --pin "$USER_PIN" \
    --keypairgen --key-type rsa:2048 \
    --label r1-smoke-key --id 01 >"$WORKDIR/keygen.txt" 2>&1 || {
    echo "Key generation failed:" >&2
    cat "$WORKDIR/keygen.txt" >&2
    exit 1
}

echo "[5/5] Signing a 256-byte message through the shim …"
DATA="$WORKDIR/data.bin"
SIG="$WORKDIR/sig.bin"
head -c 256 /dev/urandom >"$DATA"
pkcs11-tool --module "$SHIM_LIB" \
    --token-label "$TOKEN_LABEL" \
    --login --pin "$USER_PIN" \
    --sign --mechanism SHA256-RSA-PKCS \
    --input-file "$DATA" \
    --output-file "$SIG" >"$WORKDIR/sign.txt" 2>&1 || {
    echo "Sign failed:" >&2
    cat "$WORKDIR/sign.txt" >&2
    exit 1
}
[[ -s "$SIG" ]] || {
    echo "Signature file empty after sign step" >&2
    exit 1
}
SIG_SIZE="$(stat -c%s "$SIG")"
[[ "$SIG_SIZE" -ge 200 ]] || {
    echo "Signature size $SIG_SIZE looks too small for RSA-2048" >&2
    exit 1
}
echo "    produced $SIG_SIZE-byte RSA-2048 signature."

cat <<EOF

SoftHSM2 end-to-end smoke test PASSED.

The pkcs11-proxy-ng daemon (running with auth="none", SoftHSM2
backend) successfully served:
  - slot discovery,
  - login,
  - RSA-2048 key generation,
  - SHA256-RSA-PKCS sign

through the libpkcs11_proxy_ng_shim.so shim, including the
documented insecure-TCP startup warning and server-published
mechanism registry log lines.
EOF
