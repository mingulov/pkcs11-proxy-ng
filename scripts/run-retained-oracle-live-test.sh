#!/usr/bin/env bash
# Live retained-oracle topology tests (C3M.6 row 12; TO26b group 3).
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
# fails with CKR_DEVICE_ERROR, then cleanup must still work), plus one
# control-channel leg driving the hook-gated control plane end to end.
# The daemon steers the oracle through RETAINED_ORACLE_* env (read once
# at the oracle's C_Initialize); the shim leg is selected with
# RETAINED_ORACLE_LEG. Every run asserts its execution marker so a
# leg-gated early return (which also reports ok) cannot pass the gate.
#
# TO26b battery shape: every leg runs a matching-width hook-enabled
# daemon (`native-owner-test-hooks`, isolated target dir so the normal
# build is never clobbered) with the width-matching oracle loaded IN
# that process plus a private per-leg control socket. Each leg proves:
# ELF widths of daemon+oracle (`file`), the oracle mapped in the daemon
# (`/proc/<pid>/maps`), a live control channel (instance id recorded;
# distinct across daemon restarts), and — via the shim tests — that the
# caller loads no oracle itself. A closing negative leg proves a normal
# production daemon refuses a configured control socket (fail-closed).
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

# Own workspace (no SoftHSM provisioning needed for the oracle).
WORK="$(mktemp -d "/tmp/pkcs11-oracle-harness.XXXXXX")"
trap _harness_cleanup EXIT
HOOK_TARGET_DIR="$WORK/hook-target"
INSTANCE_IDS="$WORK/instance-ids.txt"
: >"$INSTANCE_IDS"

echo "--- building oracle cdylib + daemons + shim (native$( [[ $HAVE_I686 -eq 1 ]] && echo ' + i686')) ---"
cargo build --locked --offline --manifest-path "$ORACLE_DIR/Cargo.toml"
cargo build --locked -p pkcs11-proxy-ng -p pkcs11-proxy-ng-shim >/dev/null
# Hook-enabled daemons in an isolated target dir (never clobbers the
# normal build the negative leg needs below).
CARGO_TARGET_DIR="$HOOK_TARGET_DIR" \
    cargo build --locked -p pkcs11-proxy-ng --features native-owner-test-hooks >/dev/null
if [[ $HAVE_I686 -eq 1 ]]; then
    cargo build --locked --offline --manifest-path "$ORACLE_DIR/Cargo.toml" \
        --target i686-unknown-linux-gnu
    cargo build --locked --target i686-unknown-linux-gnu \
        -p pkcs11-proxy-ng -p pkcs11-proxy-ng-shim >/dev/null
    CARGO_TARGET_DIR="$HOOK_TARGET_DIR" \
        cargo build --locked --target i686-unknown-linux-gnu \
        -p pkcs11-proxy-ng --features native-owner-test-hooks >/dev/null
fi
[[ -f "$ORACLE_SO_64" ]] || { echo "SKIP: oracle cdylib missing ($ORACLE_SO_64)"; exit 0; }

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
# every source that feeds it (catches target-dir misconfigurations where
# `cargo build` refreshes a different tree than the legs execute).
assert_fresh() {
    local artifact="$1" label="$2"
    local newer
    newer=$(find crates Cargo.toml Cargo.lock "$ORACLE_DIR/src" "$ORACLE_DIR/Cargo.toml" \
        -type f -newer "$artifact" 2>/dev/null | head -3)
    if [[ -n "$newer" ]]; then
        echo "FAIL: $label: $artifact predates changed sources (stale binary):" >&2
        echo "$newer" >&2
        exit 1
    fi
}

control_get() {
    local socket="$1" path="$2"
    curl -s --unix-socket "$socket" "http://localhost$path"
}

run_leg() {
    local label="$1" daemon_bin="$2" oracle_so="$3" scenario="$4" leg="$5" test_filter="$6" marker="$7"
    local expect_width="$8"
    shift 8
    echo "--- live test: $label (scenario=$scenario) ---"
    assert_fresh "$daemon_bin" "$label daemon"
    assert_fresh "$oracle_so" "$label oracle"
    expect_elf_width "$daemon_bin" "$expect_width" "$label daemon"
    expect_elf_width "$oracle_so" "$expect_width" "$label oracle"
    local port sock
    port=$(harness_pick_port)
    sock="$WORK/control-${label//[^a-zA-Z0-9]/_}.sock"
    rm -f "$sock"
    export PKCS11_PROXY_CROSS_TEST=1
    export PKCS11_PROXY_ENDPOINT="http://127.0.0.1:$port"
    export PKCS11_PROXY_TEST_HOOKS_CONTROL_SOCKET="$sock"
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
    # Oracle-in-daemon proof: the cdylib is mapped in the daemon process.
    if ! grep -q "libpkcs11_retained_mechanism_oracle" "/proc/$DAEMON_PID/maps"; then
        echo "FAIL: $label: oracle not mapped in daemon pid $DAEMON_PID" >&2
        harness_stop_daemon
        exit 1
    fi
    # Control-channel proof: live instance identity, recorded per leg.
    local instance_body instance_id
    instance_body=$(control_get "$sock" "/hooks/instance")
    instance_id=$(sed -n 's/.*"instance_id":\([0-9]*\).*/\1/p' <<<"$instance_body")
    if [[ -z "$instance_id" || "$instance_id" == "0" ]]; then
        echo "FAIL: $label: no live control-channel instance ($instance_body)" >&2
        harness_stop_daemon
        exit 1
    fi
    echo "$label $instance_id" >>"$INSTANCE_IDS"
    echo "  control receipt: $label instance_id=$instance_id"
    local output
    if ! output=$(cargo test --locked "$@" -p pkcs11-proxy-ng-shim --lib \
        "$test_filter" -- --ignored --test-threads=1 --nocapture 2>&1); then
        echo "$output" | tail -20
        echo "FAIL: $label" >&2
        harness_stop_daemon
        exit 1
    fi
    if ! grep -q "$marker" <<<"$output"; then
        echo "FAIL: $label ran without executing its leg (vacuous ok)" >&2
        harness_stop_daemon
        exit 1
    fi
    echo "$output" | grep -E "test result|executed=" | head -4
    harness_stop_daemon
    unset PKCS11_PROXY_TEST_HOOKS_CONTROL_SOCKET
}

DAEMON_64="$HOOK_TARGET_DIR/debug/pkcs11-proxy-ng"
DAEMON_32="$HOOK_TARGET_DIR/i686-unknown-linux-gnu/debug/pkcs11-proxy-ng"
NORMAL_DAEMON_64="target/debug/pkcs11-proxy-ng"

# ── 64-bit daemon: legs 1-2 ──────────────────────────────────────────
if [[ $HAVE_I686 -eq 1 ]]; then
    run_leg "leg 1: i686 client <-> x86_64 oracle daemon" \
        "$DAEMON_64" "$ORACLE_SO_64" roundtrip roundtrip \
        retained_oracle_live 'retained-oracle-executed=roundtrip' 64 \
        --target i686-unknown-linux-gnu
    run_leg "leg 1e: i686 client <-> x86_64 oracle daemon" \
        "$DAEMON_64" "$ORACLE_SO_64" error error \
        retained_oracle_live 'retained-oracle-executed=error' 64 \
        --target i686-unknown-linux-gnu
    run_leg "leg 1c: i686 client <-> x86_64 hook daemon, control loop" \
        "$DAEMON_64" "$ORACLE_SO_64" roundtrip roundtrip \
        control_channel_live 'control-channel-executed=close-loop' 64 \
        --target i686-unknown-linux-gnu
else
    echo "SKIP legs 1/1e/1c: i686-unknown-linux-gnu target not installed"
fi
run_leg "leg 2: x86_64 client <-> x86_64 oracle daemon" \
    "$DAEMON_64" "$ORACLE_SO_64" roundtrip roundtrip \
    retained_oracle_live 'retained-oracle-executed=roundtrip' 64
run_leg "leg 2e: x86_64 client <-> x86_64 oracle daemon" \
    "$DAEMON_64" "$ORACLE_SO_64" error error \
    retained_oracle_live 'retained-oracle-executed=error' 64
run_leg "leg 2c: x86_64 client <-> x86_64 hook daemon, control loop" \
    "$DAEMON_64" "$ORACLE_SO_64" roundtrip roundtrip \
    control_channel_live 'control-channel-executed=close-loop' 64

# ── 32-bit daemon: legs 3-4 ──────────────────────────────────────────
if [[ $HAVE_I686 -eq 1 && -f "$ORACLE_SO_32" ]]; then
    run_leg "leg 3: x86_64 client <-> i686 oracle daemon" \
        "$DAEMON_32" "$ORACLE_SO_32" roundtrip roundtrip \
        retained_oracle_live 'retained-oracle-executed=roundtrip' 32
    run_leg "leg 3e: x86_64 client <-> i686 oracle daemon" \
        "$DAEMON_32" "$ORACLE_SO_32" error error \
        retained_oracle_live 'retained-oracle-executed=error' 32
    run_leg "leg 3c: x86_64 client <-> i686 hook daemon, control loop" \
        "$DAEMON_32" "$ORACLE_SO_32" roundtrip roundtrip \
        control_channel_live 'control-channel-executed=close-loop' 32
    run_leg "leg 4: i686 client <-> i686 oracle daemon" \
        "$DAEMON_32" "$ORACLE_SO_32" roundtrip roundtrip \
        retained_oracle_live 'retained-oracle-executed=roundtrip' 32 \
        --target i686-unknown-linux-gnu
    run_leg "leg 4e: i686 client <-> i686 oracle daemon" \
        "$DAEMON_32" "$ORACLE_SO_32" error error \
        retained_oracle_live 'retained-oracle-executed=error' 32 \
        --target i686-unknown-linux-gnu
    run_leg "leg 4c: i686 client <-> i686 hook daemon, control loop" \
        "$DAEMON_32" "$ORACLE_SO_32" roundtrip roundtrip \
        control_channel_live 'control-channel-executed=close-loop' 32 \
        --target i686-unknown-linux-gnu
else
    echo "SKIP legs 3/3e/3c/4/4e/4c: need the i686 Rust target and an i686 oracle cdylib"
fi

# Control-channel restart proof: every leg saw a distinct daemon instance
# (a repeated id would mean a stale daemon still serving its socket).
echo "--- control-channel instance audit ---"
cat "$INSTANCE_IDS"
if [[ $(awk '{print $NF}' "$INSTANCE_IDS" | sort -u | wc -l) != $(wc -l <"$INSTANCE_IDS") ]]; then
    echo "FAIL: duplicate control-channel instance ids across legs" >&2
    exit 1
fi

# Negative leg: a NORMAL production daemon refuses a configured control
# socket (fail-closed, no listener).
echo "--- negative leg: normal daemon + control socket refuses ---"
NEG_SOCK="$WORK/control-negative.sock"
rm -f "$NEG_SOCK"
export PKCS11_PROXY_TEST_HOOKS_CONTROL_SOCKET="$NEG_SOCK"
NEG_PORT=$(harness_pick_port)
harness_write_daemon_config "$ORACLE_SO_64" "$NEG_PORT"
NEG_CODE=0
"$NORMAL_DAEMON_64" "$WORK/proxy-config.toml" >"$WORK/negative.log" 2>&1 || NEG_CODE=$?
if [[ $NEG_CODE != 1 ]]; then
    echo "FAIL: normal daemon + control socket exited $NEG_CODE, want plain 1" >&2
    cat "$WORK/negative.log" >&2
    exit 1
fi
if ! grep -q "native-owner-test-hooks" "$WORK/negative.log"; then
    echo "FAIL: normal-daemon refusal must name the missing feature build" >&2
    cat "$WORK/negative.log" >&2
    exit 1
fi
[[ -e "$NEG_SOCK" ]] && { echo "FAIL: normal daemon created a control socket" >&2; exit 1; }
echo "  negative receipt: $(grep -o 'test_hooks.control_socket[^"]*' "$WORK/negative.log" | head -1)"
unset PKCS11_PROXY_TEST_HOOKS_CONTROL_SOCKET

echo "PASS: retained-oracle live test complete"
