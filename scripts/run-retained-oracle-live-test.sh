#!/usr/bin/env bash
# Live retained-oracle topology tests (C3M.6 row 12).
#
# Runs the shim's env-gated retained-oracle live tests against
# out-of-process daemons loaded with the deliberately retaining oracle
# cdylib, covering every Linux width topology:
#
#   1. i686 client   <-> x86_64 daemon   (32c/64b)
#   2. x86_64 client <-> x86_64 daemon   (64/64 control)
#   3. x86_64 client <-> i686 daemon     (64c/32b)
#   4. i686 client   <-> i686 daemon     (32/32 control)
#
# Each topology runs two scenario legs: `roundtrip` (canary served with
# the retained-root identity gate armed) and `error` (every C_Encrypt
# fails with CKR_DEVICE_ERROR, then cleanup must still work). The daemon
# steers the oracle through RETAINED_ORACLE_* env (read once at the
# oracle's C_Initialize); the shim leg is selected with
# RETAINED_ORACLE_LEG. Every run asserts its execution marker so a
# leg-gated early return (which also reports ok) cannot pass the gate.
#
# Legs 3-4 need the i686 Rust target and are skipped with a notice when
# it is absent. The whole script skips cleanly when cargo/rustc for a
# needed width is unavailable.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=lib/live-harness.sh
source "$(dirname "$0")/lib/live-harness.sh"

ORACLE_DIR="tests/ffi_oracles/retained_mechanisms"
ORACLE_SO_64="$ORACLE_DIR/target/debug/libpkcs11_retained_mechanism_oracle.so"
ORACLE_SO_32="$ORACLE_DIR/target/i686-unknown-linux-gnu/debug/libpkcs11_retained_mechanism_oracle.so"

HAVE_I686=0
if rustup target list --installed 2>/dev/null | grep -q '^i686-unknown-linux-gnu$'; then
    HAVE_I686=1
fi

echo "--- building oracle cdylib + daemons + shim (native$( [[ $HAVE_I686 -eq 1 ]] && echo ' + i686')) ---"
cargo build --locked --offline --manifest-path "$ORACLE_DIR/Cargo.toml"
cargo build --locked -p pkcs11-proxy-ng -p pkcs11-proxy-ng-shim >/dev/null
if [[ $HAVE_I686 -eq 1 ]]; then
    cargo build --locked --offline --manifest-path "$ORACLE_DIR/Cargo.toml" \
        --target i686-unknown-linux-gnu
    cargo build --locked --target i686-unknown-linux-gnu \
        -p pkcs11-proxy-ng -p pkcs11-proxy-ng-shim >/dev/null
fi
[[ -f "$ORACLE_SO_64" ]] || { echo "SKIP: oracle cdylib missing ($ORACLE_SO_64)"; exit 0; }

# Own workspace (no SoftHSM provisioning needed for the oracle).
WORK="$(mktemp -d "/tmp/pkcs11-oracle-harness.XXXXXX")"
trap _harness_cleanup EXIT

run_leg() {
    local label="$1" daemon_bin="$2" oracle_so="$3" scenario="$4" leg="$5"
    shift 5
    echo "--- live test: $label (scenario=$scenario) ---"
    local port
    port=$(harness_pick_port)
    export PKCS11_PROXY_CROSS_TEST=1
    export PKCS11_PROXY_ENDPOINT="http://127.0.0.1:$port"
    export RETAINED_ORACLE_LEG="$leg"
    export RETAINED_ORACLE_OUTPUT_LEN=16
    export RETAINED_ORACLE_FAIL_UNLESS_PTR_EQUAL=1
    if [[ "$scenario" == "error" ]]; then
        # CKR_DEVICE_ERROR.
        export RETAINED_ORACLE_ENCRYPT_RV=48
    else
        export RETAINED_ORACLE_ENCRYPT_RV=0
    fi
    harness_start_daemon "$daemon_bin" "$oracle_so" "$port"
    local output
    if ! output=$(cargo test --locked "$@" -p pkcs11-proxy-ng-shim --lib \
        retained_oracle_live -- --ignored --test-threads=1 --nocapture 2>&1); then
        echo "$output" | tail -20
        echo "FAIL: $label" >&2
        harness_stop_daemon
        exit 1
    fi
    if ! grep -q "retained-oracle-executed=$leg" <<<"$output"; then
        echo "FAIL: $label ran without executing its leg (vacuous ok)" >&2
        harness_stop_daemon
        exit 1
    fi
    echo "$output" | grep -E "test result|retained-oracle-executed" | head -4
    harness_stop_daemon
}

DAEMON_64="target/debug/pkcs11-proxy-ng"
DAEMON_32="target/i686-unknown-linux-gnu/debug/pkcs11-proxy-ng"

# ── 64-bit daemon: legs 1-2 ──────────────────────────────────────────
if [[ $HAVE_I686 -eq 1 ]]; then
    run_leg "leg 1: i686 client <-> x86_64 oracle daemon" \
        "$DAEMON_64" "$ORACLE_SO_64" roundtrip roundtrip --target i686-unknown-linux-gnu
    run_leg "leg 1e: i686 client <-> x86_64 oracle daemon" \
        "$DAEMON_64" "$ORACLE_SO_64" error error --target i686-unknown-linux-gnu
else
    echo "SKIP legs 1/1e: i686-unknown-linux-gnu target not installed"
fi
run_leg "leg 2: x86_64 client <-> x86_64 oracle daemon" \
    "$DAEMON_64" "$ORACLE_SO_64" roundtrip roundtrip
run_leg "leg 2e: x86_64 client <-> x86_64 oracle daemon" \
    "$DAEMON_64" "$ORACLE_SO_64" error error

# ── 32-bit daemon: legs 3-4 ──────────────────────────────────────────
if [[ $HAVE_I686 -eq 1 && -f "$ORACLE_SO_32" ]]; then
    run_leg "leg 3: x86_64 client <-> i686 oracle daemon" \
        "$DAEMON_32" "$ORACLE_SO_32" roundtrip roundtrip
    run_leg "leg 3e: x86_64 client <-> i686 oracle daemon" \
        "$DAEMON_32" "$ORACLE_SO_32" error error
    run_leg "leg 4: i686 client <-> i686 oracle daemon" \
        "$DAEMON_32" "$ORACLE_SO_32" roundtrip roundtrip --target i686-unknown-linux-gnu
    run_leg "leg 4e: i686 client <-> i686 oracle daemon" \
        "$DAEMON_32" "$ORACLE_SO_32" error error --target i686-unknown-linux-gnu
else
    echo "SKIP legs 3/3e/4/4e: need the i686 Rust target and an i686 oracle cdylib"
fi

echo "PASS: retained-oracle live test complete"
