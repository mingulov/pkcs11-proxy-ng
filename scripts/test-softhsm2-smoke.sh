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
# Set PKCS11_PROXY_NG_DAEMON_BIN / PKCS11_PROXY_NG_SHIM_LIB to run the
# same flow against explicit artifact paths (e.g. extracted bundle
# binaries) instead of the workspace release defaults. The existing
# PKCS11_PROXY_BACKEND_MODULE override selects an explicit SoftHSM2 module.
# After checked daemon retirement, sign directly with the same scratch key,
# export its public key, verify both signatures with OpenSSL, and compare
# the deterministic SHA256-RSA-PKCS results.
#
# PKCS11_PROXY_SMOKE_COMMAND_SECS / PKCS11_PROXY_SMOKE_SHUTDOWN_SECS
# accept integers 1..30 (default 30). The daemon's configured shutdown
# grace remains 30 seconds; a forced kill always fails this smoke.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_ROOT="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"
case "$TARGET_ROOT" in
    /*) ;;
    *) TARGET_ROOT="$ROOT_DIR/$TARGET_ROOT" ;;
esac
RELEASE_DIR="$TARGET_ROOT/release"
DAEMON_BIN="${PKCS11_PROXY_NG_DAEMON_BIN:-$RELEASE_DIR/pkcs11-proxy-ng}"
SHIM_LIB="${PKCS11_PROXY_NG_SHIM_LIB:-$RELEASE_DIR/libpkcs11_proxy_ng_shim.so}"
COMMAND_SECS="${PKCS11_PROXY_SMOKE_COMMAND_SECS-30}"
SHUTDOWN_SECS="${PKCS11_PROXY_SMOKE_SHUTDOWN_SECS-30}"

validate_seconds() {
    case "$2" in
        [1-9]|[12][0-9]|30) ;;
        *) echo "$1 must be an integer from 1 to 30" >&2; exit 1 ;;
    esac
}
validate_seconds PKCS11_PROXY_SMOKE_COMMAND_SECS "$COMMAND_SECS"
validate_seconds PKCS11_PROXY_SMOKE_SHUTDOWN_SECS "$SHUTDOWN_SECS"

# Pick a SoftHSM2 .so the host actually has.
SOFTHSM2_LIB="${PKCS11_PROXY_BACKEND_MODULE:-}"
if [[ -z "$SOFTHSM2_LIB" ]]; then
    for cand in \
        /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so; do
        [[ -f "$cand" ]] && SOFTHSM2_LIB="$cand" && break
    done
fi
[[ ! -f "$SOFTHSM2_LIB" ]] && {
    echo "SoftHSM2 module not found; install softhsm2 first" >&2
    exit 1
}

for cmd in softhsm2-util pkcs11-tool openssl python3 timeout cmp; do
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
DAEMON_PID=""

# Check wait status even after the child disappears: retirement alone does
# not establish successful graceful shutdown. Keep the PID until reaped.
stop_daemon() {
    [[ -n "$DAEMON_PID" ]] || return 0
    local failed=0 tick status
    if kill -0 "$DAEMON_PID" 2>/dev/null; then
        if ! kill -TERM "$DAEMON_PID" 2>/dev/null; then
            echo "Could not send SIGTERM to owned daemon $DAEMON_PID" >&2
            failed=1
        fi
        for ((tick = 0; tick < SHUTDOWN_SECS * 10; tick++)); do
            kill -0 "$DAEMON_PID" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$DAEMON_PID" 2>/dev/null; then
            echo "Daemon did not stop within ${SHUTDOWN_SECS}s; forcing SIGKILL (smoke failed)" >&2
            failed=1
            kill -KILL "$DAEMON_PID" 2>/dev/null || {
                echo "Could not send SIGKILL to owned daemon $DAEMON_PID" >&2
            }
            for ((tick = 0; tick < 20; tick++)); do
                kill -0 "$DAEMON_PID" 2>/dev/null || break
                sleep 0.1
            done
        fi
    else
        echo "Daemon exited before requested shutdown" >&2
        failed=1
    fi
    if kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "Owned daemon $DAEMON_PID could not be retired/reaped" >&2
        return 1
    fi
    if wait "$DAEMON_PID"; then
        status=0
    else
        status=$?
        echo "Daemon wait failed with status $status" >&2
        failed=1
    fi
    DAEMON_PID=""
    return "$failed"
}

cleanup() {
    local status=0
    stop_daemon || status=$?
    if [[ -n "$DAEMON_PID" ]]; then
        echo "Retaining scratch store $WORKDIR while daemon retirement is unresolved" >&2
        return 1
    fi
    if [[ -n "$WORKDIR" ]]; then
        if timeout --kill-after=1s "${COMMAND_SECS}s" rm -rf "$WORKDIR"; then
            WORKDIR=""
        else
            echo "Scratch cleanup failed for $WORKDIR" >&2
            status=1
        fi
    fi
    return "$status"
}

on_exit() {
    # Finish the bounded stop/reap even if another handled signal arrives.
    # Capture the entry status in the trap argument before changing traps.
    trap '' EXIT INT TERM
    local status="$1" cleanup_status=0
    cleanup || cleanup_status=$?
    if [[ "$status" -eq 0 && "$cleanup_status" -ne 0 ]]; then
        status="$cleanup_status"
    fi
    exit "$status"
}
trap 'on_exit "$?"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_step() {
    local label="$1" log="$2" status
    shift 2
    if timeout --kill-after=1s "${COMMAND_SECS}s" "$@" >"$log" 2>&1; then
        return 0
    else
        status=$?
        echo "$label failed (status $status):" >&2
        cat "$log" >&2
        return "$status"
    fi
}

require_signature() {
    local size=0
    if [[ -s "$1" ]]; then
        size="$(stat -c%s "$1")"
    fi
    if [[ "$size" -ne 256 ]]; then
        echo "Expected a 256-byte RSA-2048 signature at $1; got $size bytes" >&2
        return 1
    fi
}

require_public_key() {
    local size=0
    if [[ -s "$1" ]]; then
        size="$(stat -c%s "$1")"
    fi
    if [[ "$size" -lt 256 || "$size" -gt 2048 ]]; then
        echo "Expected a nonempty RSA-2048 public key at $1 (256..2048 bytes); got $size bytes" >&2
        return 1
    fi
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

echo "[1/8] Initializing SoftHSM2 token in $TOKEN_DIR …"
run_step "Token initialization" "$WORKDIR/init.txt" softhsm2-util --init-token --free \
    --label "$TOKEN_LABEL" \
    --so-pin "$SO_PIN" \
    --pin "$USER_PIN"

# Pick a random free TCP port so concurrent runs don't collide.
BIND_PORT="$(timeout --kill-after=1s "${COMMAND_SECS}s" python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
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

echo "[2/8] Starting pkcs11-proxy-ng daemon at $DAEMON_ENDPOINT (auth=\"none\", SoftHSM2 backend) …"
RUST_LOG="${RUST_LOG:-pkcs11_proxy_ng=info}" \
    "$DAEMON_BIN" "$WORKDIR/proxy.toml" \
    >"$WORKDIR/daemon.log" 2>&1 &
DAEMON_PID=$!

# Wait for the daemon to bind the port (max 15 s).
for ((i = 1; i <= 150; i++)); do
    if (echo >"/dev/tcp/127.0.0.1/${BIND_PORT}") 2>/dev/null; then
        break
    fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "Daemon exited during startup; tail of daemon log:" >&2
        tail -50 "$WORKDIR/daemon.log" >&2 || true
        exit 1
    fi
    sleep 0.1
    if [[ "$i" -eq 150 ]]; then
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

# Proxied pkcs11-tool invocations talk to the shim, which is
# configured purely by env vars (the design's PKCS11_PROXY_ENDPOINT /
# PKCS11_PROXY_SOCKET contract).
export PKCS11_PROXY_ENDPOINT="$DAEMON_ENDPOINT"
export PKCS11_PROXY_CONNECT_TIMEOUT=10

echo "[3/8] Listing slots via the shim (proves probe + slot pass-through) …"
run_step "Slot listing" "$WORKDIR/slots.txt" pkcs11-tool --module "$SHIM_LIB" --list-slots
grep -q "$TOKEN_LABEL" "$WORKDIR/slots.txt" || {
    echo "Expected token label '$TOKEN_LABEL' missing from --list-slots output:" >&2
    cat "$WORKDIR/slots.txt" >&2
    exit 1
}
echo "    slot with token '$TOKEN_LABEL' visible through the shim."

echo "[4/8] Generating an RSA-2048 key in the proxied token …"
run_step "Key generation" "$WORKDIR/keygen.txt" pkcs11-tool --module "$SHIM_LIB" \
    --token-label "$TOKEN_LABEL" \
    --login --pin "$USER_PIN" \
    --keypairgen --key-type rsa:2048 \
    --label r1-smoke-key --id 01

echo "[5/8] Signing a 256-byte message through the shim …"
DATA="$WORKDIR/data.bin"
SIG="$WORKDIR/sig.bin"
head -c 256 /dev/urandom >"$DATA"
run_step "Proxy sign" "$WORKDIR/sign.txt" pkcs11-tool --module "$SHIM_LIB" \
    --token-label "$TOKEN_LABEL" \
    --login --pin "$USER_PIN" \
    --sign --mechanism SHA256-RSA-PKCS \
    --input-file "$DATA" \
    --output-file "$SIG" --id 01
require_signature "$SIG"

echo "[6/8] Stopping and reaping the daemon before direct token access …"
stop_daemon
unset PKCS11_PROXY_ENDPOINT

echo "[7/8] Signing the same message/key directly and exporting its public key …"
DIRECT_SIG="$WORKDIR/direct-sig.bin"
PUBLIC_DER="$WORKDIR/public.der"
PUBLIC_PEM="$WORKDIR/public.pem"
run_step "Direct sign" "$WORKDIR/direct-sign.txt" pkcs11-tool --module "$SOFTHSM2_LIB" \
    --token-label "$TOKEN_LABEL" --login --pin "$USER_PIN" \
    --sign --mechanism SHA256-RSA-PKCS \
    --input-file "$DATA" --output-file "$DIRECT_SIG" --id 01
require_signature "$DIRECT_SIG"
run_step "Public key export" "$WORKDIR/read-public.txt" pkcs11-tool --module "$SOFTHSM2_LIB" \
    --token-label "$TOKEN_LABEL" --login --pin "$USER_PIN" \
    --read-object --type pubkey --id 01 --output-file "$PUBLIC_DER"
require_public_key "$PUBLIC_DER"
run_step "Public key conversion" "$WORKDIR/convert-public.txt" openssl rsa \
    -inform DER -outform PEM -in "$PUBLIC_DER" -pubin -out "$PUBLIC_PEM"
require_public_key "$PUBLIC_PEM"

echo "[8/8] Independently verifying both signatures and comparing deterministic results …"
run_step "Proxy signature verification" "$WORKDIR/verify-proxy.txt" openssl dgst \
    -sha256 -verify "$PUBLIC_PEM" -signature "$SIG" "$DATA"
run_step "Direct signature verification" "$WORKDIR/verify-direct.txt" openssl dgst \
    -sha256 -verify "$PUBLIC_PEM" -signature "$DIRECT_SIG" "$DATA"
if ! cmp -s "$SIG" "$DIRECT_SIG"; then
    echo "Verified deterministic SHA256-RSA-PKCS signatures differ" >&2
    exit 1
fi

# Passing completion comes after checked cleanup, including the error path.
CLEANUP_STATUS=0
cleanup || CLEANUP_STATUS=$?
trap - EXIT
[[ "$CLEANUP_STATUS" -eq 0 ]] || exit "$CLEANUP_STATUS"

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
mechanism registry log lines. After successful daemon shutdown and
reaping, a direct signature using the same scratch key and message
matched the proxy signature; OpenSSL independently verified both
with the exported public key. Scratch cleanup completed successfully.
EOF
