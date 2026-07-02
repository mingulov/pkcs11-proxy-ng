#!/usr/bin/env bash
# LLP64 runtime smoke under wine (ADR-0011 Phase D).
#
# Proves the Windows shim DLL drives the width bridge at runtime: the
# cross_width_smoke.exe client (x86_64-pc-windows-msvc: 32-bit CK_ULONG,
# 64-bit pointers, packed structs) runs under wine in a container and
# talks to a live 64-bit Linux daemon backed by SoftHSM2.
#
# Legs:
#   1. Native Linux control  — same smoke client logic, native .so
#      (validates the harness independently of wine).
#   2. Wine LLP64            — smoke.exe + shim DLL under wine
#      (client width 4 vs daemon width 8: the bridge is engaged).
#
# Skips cleanly when Docker, a wine image, cargo-xwin, or SoftHSM2 is
# unavailable. Wine reproduces the LLP64 layout/width ABI faithfully but
# is not a Windows conformance gate — keep a real-Windows pass for final
# sign-off.
set -euo pipefail

cd "$(dirname "$0")/.."

WINE_IMAGE="${PKCS11_PROXY_WINE_IMAGE:-pkcs11check-wine}"

# ── Skip-clean prerequisites ─────────────────────────────────────────
SOFTHSM_MODULE=""
for candidate in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib64/pkcs11/libsofthsm2.so; do
    [[ -f "$candidate" ]] && SOFTHSM_MODULE="$candidate" && break
done
if [[ -z "$SOFTHSM_MODULE" ]] || ! command -v softhsm2-util >/dev/null 2>&1; then
    echo "SKIP: SoftHSM2 not installed"
    exit 0
fi
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "SKIP: docker unavailable"
    exit 0
fi
if ! docker image inspect "$WINE_IMAGE" >/dev/null 2>&1; then
    echo "SKIP: wine image '$WINE_IMAGE' not present (set PKCS11_PROXY_WINE_IMAGE)"
    exit 0
fi
if ! command -v cargo-xwin >/dev/null 2>&1; then
    echo "SKIP: cargo-xwin not installed"
    exit 0
fi

# ── Build all artifacts ──────────────────────────────────────────────
echo "--- building daemon (native), smoke client (native + Windows), shim .so/DLL ---"
# Explicit shim builds: an `--example`-only invocation does NOT refresh the
# shim cdylib, and a stale library silently tests old code.
cargo build -p pkcs11-proxy-ng -p pkcs11-proxy-ng-shim >/dev/null
cargo build -p pkcs11-proxy-ng-shim --example cross_width_smoke >/dev/null
cargo xwin build --target x86_64-pc-windows-msvc \
    -p pkcs11-proxy-ng-shim >/dev/null
cargo xwin build --target x86_64-pc-windows-msvc \
    -p pkcs11-proxy-ng-shim --example cross_width_smoke >/dev/null

# ── Workspace: throwaway token + daemon on insecure localhost TCP ────
WORK="$(mktemp -d /tmp/pkcs11-llp64-smoke.XXXXXX)"
DAEMON_PID=""
cleanup() {
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/tokens" "$WORK/stage"
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $WORK/tokens
objectstore.backend = file
log.level = ERROR
EOF
softhsm2-util --init-token --free --label llp64-smoke \
    --so-pin 12345678 --pin 12345678 >/dev/null

PORT=$(( 20000 + RANDOM % 20000 ))
cat > "$WORK/proxy-config.toml" <<EOF
[backend]
module = "$SOFTHSM_MODULE"

[proxy]
mechanism_discovery = "transparent"

[listener.remote]
bind = "127.0.0.1:$PORT"
auth = "none"
allow_insecure_tcp = true
EOF

target/debug/pkcs11-proxy-ng "$WORK/proxy-config.toml" > "$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
        exec 3>&- 3<&-
        break
    fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "FAIL: daemon exited during startup; log follows" >&2
        cat "$WORK/daemon.log" >&2
        exit 1
    fi
    sleep 0.2
done
ENDPOINT="http://127.0.0.1:$PORT"

# ── Leg 1: native Linux control ──────────────────────────────────────
echo "--- leg 1: native control (same-width, dlopen path) ---"
PKCS11_PROXY_ENDPOINT="$ENDPOINT" \
    target/debug/examples/cross_width_smoke \
    target/debug/libpkcs11_proxy_ng_shim.so

# ── Leg 2: LLP64 under wine ──────────────────────────────────────────
echo "--- leg 2: LLP64 smoke.exe + shim DLL under wine ---"
cp target/x86_64-pc-windows-msvc/debug/examples/cross_width_smoke.exe "$WORK/stage/"
cp target/x86_64-pc-windows-msvc/debug/pkcs11_proxy_ng_shim.dll "$WORK/stage/"
# LoadLibrary resolves a bare DLL name against the exe's own directory,
# so staging both side by side avoids unix<->windows path translation.
docker run --rm --network host \
    -v "$WORK/stage:/stage:ro" \
    -e WINEDEBUG=-all \
    -e PKCS11_PROXY_ENDPOINT="$ENDPOINT" \
    --entrypoint /bin/sh \
    "$WINE_IMAGE" \
    -c 'cd /stage && wine cross_width_smoke.exe pkcs11_proxy_ng_shim.dll'

echo "PASS: LLP64 wine smoke complete"
