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

expect_elf_width() {
    local artifact="$1" want="$2" label="$3"
    local desc
    desc=$(file -b "$artifact")
    if ! grep -q "ELF $want-bit" <<<"$desc"; then
        echo "FAIL: $label: $artifact is not ELF $want-bit ($desc)" >&2
        exit 1
    fi
    echo "  width receipt: $artifact -> $desc"
}

# Stale artifacts test nothing: every daemon binary must be newer than
# every source that feeds it (see the row-12 runner for rationale).
assert_fresh() {
    local artifact="$1" label="$2"
    local newer
    newer=$(find crates Cargo.toml Cargo.lock -type f -newer "$artifact" 2>/dev/null | head -3)
    if [[ -n "$newer" ]]; then
        echo "FAIL: $label: $artifact predates changed sources (stale binary):" >&2
        echo "$newer" >&2
        exit 1
    fi
}

# Per-daemon receipts: freshness, ELF width, and the provider module
# mapped in the daemon process.
prove_daemon() {
    local label="$1" daemon_bin="$2" module="$3" expect_width="$4"
    assert_fresh "$daemon_bin" "$label daemon"
    expect_elf_width "$daemon_bin" "$expect_width" "$label daemon"
    local base
    base=$(basename "$module")
    if ! grep -q "$base" "/proc/$DAEMON_PID/maps"; then
        echo "FAIL: $label: $base not mapped in daemon pid $DAEMON_PID" >&2
        harness_stop_daemon
        exit 1
    fi
    echo "  maps receipt: $label daemon maps $base"
}

run_leg() {
    local label="$1" backend_width="$2"; shift 2
    echo "--- live test: $label ---"
    local output
    if ! output=$(PKCS11_PROXY_CROSS_EXPECT_BACKEND_WIDTH="$backend_width" \
        cargo test "$@" -p pkcs11-proxy-ng-shim --lib \
        tests::cross_width_live -- --ignored --test-threads=1 --nocapture 2>&1); then
        echo "$output" | tail -20
        echo "FAIL: $label" >&2
        exit 1
    fi
    # Execution proof: every passing test printed its marker, so a
    # leg-gated early return (which also reports ok) cannot pass the gate.
    local passed markers
    passed=$(sed -n 's/.*test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' <<<"$output")
    markers=$(grep -c "cross-width-executed=" <<<"$output" || true)
    if [[ -z "$passed" || "$passed" == "0" || "$passed" != "$markers" ]]; then
        echo "FAIL: $label executed $markers/$passed tests (vacuous ok)" >&2
        exit 1
    fi
    echo "$output" | grep -E "test result|cross-width-executed" | head -8
}

export PKCS11_PROXY_CROSS_TEST=1
export PKCS11_PROXY_CROSS_PROVIDER=softhsm2

# ── 64-bit daemon: legs 1-2 ──────────────────────────────────────────
PORT=$(harness_pick_port)
export PKCS11_PROXY_ENDPOINT="http://127.0.0.1:$PORT"
harness_start_daemon target/debug/pkcs11-proxy-ng "$SOFTHSM_MODULE_64" "$PORT"
prove_daemon "64-bit daemon" target/debug/pkcs11-proxy-ng "$SOFTHSM_MODULE_64" 64

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
    # Extracted (non-system) i386 providers carry their dependency closure
    # beside the module (libcrypto.so.3, ...); the wide loader ignores
    # wrong-arch entries, so scoping it to legs 3-4 is safe.
    SOFTHSM32_LIBDIR=$(dirname "$(dirname "$SOFTHSM_MODULE_32")")
    SOFTHSM32_SAVED_LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}"
    export LD_LIBRARY_PATH="$SOFTHSM32_LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    PORT=$(harness_pick_port)
    export PKCS11_PROXY_ENDPOINT="http://127.0.0.1:$PORT"
    harness_start_daemon target/i686-unknown-linux-gnu/debug/pkcs11-proxy-ng \
        "$SOFTHSM_MODULE_32" "$PORT"
    prove_daemon "32-bit daemon" target/i686-unknown-linux-gnu/debug/pkcs11-proxy-ng \
        "$SOFTHSM_MODULE_32" 32

    run_leg "leg 3: x86_64 client (8) <-> i686 daemon (4) — reverse bridge + D4" 4
    run_leg "leg 4: i686 client <-> i686 daemon (narrow-native control)" 4 \
        --target i686-unknown-linux-gnu
    harness_stop_daemon
    if [[ -n "$SOFTHSM32_SAVED_LD_LIBRARY_PATH" ]]; then
        export LD_LIBRARY_PATH="$SOFTHSM32_SAVED_LD_LIBRARY_PATH"
    else
        unset LD_LIBRARY_PATH
    fi
else
    echo "SKIP legs 3-4: need the i686 Rust target and an i386 libsofthsm2"
fi

echo "PASS: cross-width live test complete"
