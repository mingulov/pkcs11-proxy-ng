#!/usr/bin/env bash
# Live cross-width topology tests (ADR-0011 Phases A + B, D3 targets).
#
# Runs the shim's env-gated live tests against out-of-process daemons so
# the client and backend CK_ULONG widths genuinely differ, covering every
# Linux width topology:
#
#   1. i686 client   <-> x86_64 daemon   (32c/64b — narrow-client bridge)
#   2. x86_64 client <-> x86_64 daemon   (64/64 same-width control)
#   3. x86_64 client <-> i686 daemon     (64c/32b — reverse bridge + D4
#                                          server-input checked narrowing)
#   4. i686 client   <-> i686 daemon     (32/32 narrow-native control)
#
# Legs 3-4 need the 32-bit SoftHSM2 library (extracted libsofthsm2:i386)
# and are skipped with a notice when it is absent. The whole script skips
# cleanly when SoftHSM2 or the i686 Rust target is unavailable.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=lib/live-harness.sh
source "$(dirname "$0")/lib/live-harness.sh"

harness_locate_softhsm64
if [[ -z "$SOFTHSM_MODULE_64" ]] || ! command -v softhsm2-util >/dev/null 2>&1; then
    echo "SKIP: SoftHSM2 not installed; cross-width live test not run"
    exit 0
fi
harness_locate_softhsm32

HAVE_I686=0
if rustup target list --installed 2>/dev/null | grep -q '^i686-unknown-linux-gnu$'; then
    HAVE_I686=1
fi

harness_init_workspace cross-width

# Explicit cdylib/daemon builds — an `--example`-only build does NOT
# refresh the shim library, and stale artifacts test nothing.
echo "--- building daemons + shim (native$( [[ $HAVE_I686 -eq 1 ]] && echo ' + i686')) ---"
cargo build -p pkcs11-proxy-ng -p pkcs11-proxy-ng-shim >/dev/null
if [[ $HAVE_I686 -eq 1 ]]; then
    cargo build --target i686-unknown-linux-gnu \
        -p pkcs11-proxy-ng -p pkcs11-proxy-ng-shim >/dev/null
fi

run_leg() {
    local label="$1" backend_width="$2"; shift 2
    echo "--- live test: $label ---"
    PKCS11_PROXY_CROSS_EXPECT_BACKEND_WIDTH="$backend_width" \
        cargo test "$@" -p pkcs11-proxy-ng-shim --lib \
        tests::cross_width_live -- --ignored --test-threads=1
}

export PKCS11_PROXY_CROSS_TEST=1

# ── 64-bit daemon: legs 1-2 ──────────────────────────────────────────
PORT=$(harness_pick_port)
export PKCS11_PROXY_ENDPOINT="http://127.0.0.1:$PORT"
harness_start_daemon target/debug/pkcs11-proxy-ng "$SOFTHSM_MODULE_64" "$PORT"

if [[ $HAVE_I686 -eq 1 ]]; then
    run_leg "leg 1: i686 client (4) <-> x86_64 daemon (8)" 8 \
        --target i686-unknown-linux-gnu
else
    echo "SKIP leg 1: i686-unknown-linux-gnu target not installed"
fi
run_leg "leg 2: x86_64 client <-> x86_64 daemon (same-width control)" 8
harness_stop_daemon

# ── 32-bit daemon: legs 3-4 ──────────────────────────────────────────
if [[ $HAVE_I686 -eq 1 && -n "$SOFTHSM_MODULE_32" ]]; then
    PORT=$(harness_pick_port)
    export PKCS11_PROXY_ENDPOINT="http://127.0.0.1:$PORT"
    harness_start_daemon target/i686-unknown-linux-gnu/debug/pkcs11-proxy-ng \
        "$SOFTHSM_MODULE_32" "$PORT"

    run_leg "leg 3: x86_64 client (8) <-> i686 daemon (4) — reverse bridge + D4" 4
    run_leg "leg 4: i686 client <-> i686 daemon (narrow-native control)" 4 \
        --target i686-unknown-linux-gnu
    harness_stop_daemon
else
    echo "SKIP legs 3-4: need the i686 Rust target and an i386 libsofthsm2"
fi

echo "PASS: cross-width live test complete"
