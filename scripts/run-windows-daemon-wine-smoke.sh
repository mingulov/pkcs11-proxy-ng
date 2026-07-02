#!/usr/bin/env bash
# Windows daemon runtime smoke under wine (ADR-0011 D3: Windows daemon host).
#
# Runs the cross-compiled pkcs11-proxy-ng.exe under wine, loading the
# Windows SoftHSM2 DLL (a real LLP64 PKCS#11 backend: 32-bit CK_ULONG,
# 64-bit pointers, packed structs), listening on insecure localhost TCP
# inside a --network host container. Then:
#
#   1. Native Linux client (width 8) <-> wine daemon (backend width 4):
#      the reverse bridge + D4 checked narrowing live through a REAL
#      Windows PKCS#11 DLL, plus the D2 width-advertisement check.
#   2. LLP64 smoke.exe + shim DLL under wine <-> wine daemon:
#      the all-Windows client/daemon pairing (4/4 same-width).
#
# Skips cleanly when Docker, the wine image, or cargo-xwin is missing.
# Wine reproduces the LLP64 ABI faithfully but is not a Windows
# conformance gate — keep a real-Windows pass for final sign-off.
set -euo pipefail

cd "$(dirname "$0")/.."

WINE_IMAGE="${PKCS11_PROXY_WINE_IMAGE:-pkcs11check-wine}"

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

echo "--- building Windows daemon + shim DLL + smoke clients ---"
cargo xwin build --target x86_64-pc-windows-msvc \
    -p pkcs11-proxy-ng -p pkcs11-proxy-ng-shim >/dev/null
cargo xwin build --target x86_64-pc-windows-msvc \
    -p pkcs11-proxy-ng-shim --example cross_width_smoke >/dev/null
cargo build -p pkcs11-proxy-ng-shim >/dev/null
cargo build -p pkcs11-proxy-ng-shim --example cross_width_smoke >/dev/null

WORK="$(mktemp -d /tmp/pkcs11-win-daemon.XXXXXX)"
CONTAINER=""
cleanup() {
    [[ -n "$CONTAINER" ]] && docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

PORT=$(( 20000 + RANDOM % 20000 ))
mkdir -p "$WORK/stage"
cp target/x86_64-pc-windows-msvc/debug/pkcs11-proxy-ng.exe "$WORK/stage/"
cp target/x86_64-pc-windows-msvc/debug/pkcs11_proxy_ng_shim.dll "$WORK/stage/"
cp target/x86_64-pc-windows-msvc/debug/examples/cross_width_smoke.exe "$WORK/stage/"

# Daemon config: Windows path to the SoftHSM2 DLL baked into the image.
cat > "$WORK/stage/proxy-config.toml" <<EOF
[backend]
module = 'Z:\\opt\\SoftHSM2\\lib\\softhsm2-x64.dll'

[proxy]
mechanism_discovery = "transparent"

[listener.remote]
bind = "127.0.0.1:$PORT"
auth = "none"
allow_insecure_tcp = true
EOF

# One long-lived container running the daemon in the foreground. The image
# bakes a provisioned SoftHSM2 token (Z:\opt\softhsm2.conf, initialized at
# image build via the DLL's own C_* exports — softhsm2-util.exe's DLL
# search is brittle under wine). SOFTHSM2_CONF is a Windows path because
# the DLL resolves it with Win32 file APIs; the smoke only creates session
# objects, so the baked token is not modified.
echo "--- starting wine daemon (Windows SoftHSM2 backend) on :$PORT ---"
CONTAINER=$(docker run -d --network host \
    -v "$WORK/stage:/stage:ro" \
    -e WINEDEBUG=-all \
    -e SOFTHSM2_CONF='Z:\opt\softhsm2.conf' \
    --entrypoint /bin/sh \
    "$WINE_IMAGE" \
    -c 'exec wine /stage/pkcs11-proxy-ng.exe "Z:\\stage\\proxy-config.toml"')

for i in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
        exec 3>&- 3<&-
        break
    fi
    if ! docker ps -q --no-trunc | grep -q "$CONTAINER"; then
        echo "FAIL: wine daemon container exited; log follows" >&2
        docker logs "$CONTAINER" >&2 || true
        exit 1
    fi
    if [[ $i -eq 100 ]]; then
        echo "FAIL: wine daemon did not start listening; log follows" >&2
        docker logs "$CONTAINER" >&2 || true
        exit 1
    fi
    sleep 0.3
done

export PKCS11_PROXY_ENDPOINT="http://127.0.0.1:$PORT"

# ── Leg 1: native Linux client (8) <-> wine daemon (4) ───────────────
echo "--- leg 1: x86_64 Linux client (8) <-> wine Windows daemon (4) ---"
PKCS11_PROXY_CROSS_TEST=1 PKCS11_PROXY_CROSS_EXPECT_BACKEND_WIDTH=4 \
    cargo test -p pkcs11-proxy-ng-shim --lib \
    tests::cross_width_live -- --ignored --test-threads=1
PKCS11_PROXY_ENDPOINT="$PKCS11_PROXY_ENDPOINT" \
    target/debug/examples/cross_width_smoke \
    target/debug/libpkcs11_proxy_ng_shim.so

# ── Leg 2: LLP64 client under wine <-> wine daemon (4/4) ─────────────
echo "--- leg 2: LLP64 smoke.exe under wine <-> wine Windows daemon ---"
docker run --rm --network host \
    -v "$WORK/stage:/stage:ro" \
    -e WINEDEBUG=-all \
    -e PKCS11_PROXY_ENDPOINT="$PKCS11_PROXY_ENDPOINT" \
    --entrypoint /bin/sh \
    "$WINE_IMAGE" \
    -c 'cd /stage && wine cross_width_smoke.exe pkcs11_proxy_ng_shim.dll'

echo "PASS: Windows daemon wine smoke complete"
