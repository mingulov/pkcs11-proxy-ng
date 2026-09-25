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
# shellcheck source=lib/live-harness.sh
source "$(dirname "$0")/lib/live-harness.sh"

WINE_IMAGE="${PKCS11_PROXY_WINE_IMAGE:-pkcs11check-wine}"

harness_locate_softhsm64
if [[ -z "$SOFTHSM_MODULE_64" ]] || ! command -v softhsm2-util >/dev/null 2>&1; then
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

echo "--- building daemon (native), smoke client (native + Windows), shim .so/DLL ---"
# Explicit shim builds: an `--example`-only invocation does NOT refresh the
# shim cdylib, and a stale library silently tests old code.
cargo build -p pkcs11-proxy-ng -p pkcs11-proxy-ng-shim >/dev/null
cargo build -p pkcs11-proxy-ng-shim --example cross_width_smoke >/dev/null
cargo xwin build --target x86_64-pc-windows-msvc \
    -p pkcs11-proxy-ng-shim >/dev/null
cargo xwin build --target x86_64-pc-windows-msvc \
    -p pkcs11-proxy-ng-shim --example cross_width_smoke >/dev/null

harness_init_workspace llp64-smoke
mkdir -p "$WORK/stage"

PORT=$(harness_pick_port)
harness_start_daemon target/debug/pkcs11-proxy-ng "$SOFTHSM_MODULE_64" "$PORT"
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
