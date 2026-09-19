#!/usr/bin/env bash
# Live cross-width topology tests against the second 32-bit provider
# (NSS i386 softokn) — the T4 leg of the width matrix.
#
# Runs the shim's env-gated live tests against an out-of-process i686
# daemon so the client and backend CK_ULONG widths genuinely differ:
#
#   1. x86_64 client <-> i686 daemon (64c/32b — reverse bridge + D4
#                                     server-input checked narrowing)
#   2. i686 client   <-> i686 daemon (32/32 narrow-native control)
#
# Same build/daemon/test-leg structure as run-cross-width-live-test.sh
# (whose legs 3-4 cover the same topologies against SoftHSM2); the NSS
# fixture DB is created fresh at script start per
# scripts/test-nss-fixtures.sh Fixture 1 (`certutil -N` on a sql: DB).
#
# Needs the i386 NSS module (extracted libnss3:i386 plus its NSPR and
# SQLite i386 closure, or a system i386 install), certutil for the
# fixture, and the i686 Rust target; skips cleanly with a notice when
# any of those is absent.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=lib/live-harness.sh
source "$(dirname "$0")/lib/live-harness.sh"

harness_locate_nss32
if [[ -z "$NSS_MODULE_32" ]]; then
    echo "SKIP: i386 NSS softokn module not found; cross-width NSS32 live test not run"
    exit 0
fi
if ! command -v certutil >/dev/null 2>&1; then
    echo "SKIP: certutil not installed; cannot create the NSS fixture DB"
    exit 0
fi
if ! rustup target list --installed 2>/dev/null | grep -q '^i686-unknown-linux-gnu$'; then
    echo "SKIP: i686-unknown-linux-gnu target not installed; cross-width NSS32 live test not run"
    exit 0
fi

# Workspace without a SoftHSM token (this leg needs none): $WORK plus
# the shared EXIT trap for daemon cleanup.
WORK="$(mktemp -d "/tmp/pkcs11-nss32-harness.XXXXXX")"
trap _harness_cleanup EXIT

# Skip honesty (same tally as the sibling runners; this script's skips
# all exit before the first leg, so a reached final line implies
# skipped=0 — stated explicitly for the receipt).
LEGS_RUN=0
LEGS_SKIPPED=0

# NSS sql-DB fixture (Fixture 1 shape): fresh empty-password DB.
NSSDB="$WORK/nssdb"
mkdir -p "$NSSDB"
certutil -N -d "sql:$NSSDB" --empty-password

# Explicit cdylib/daemon builds — an `--example`-only build does NOT
# refresh the shim library, and stale artifacts test nothing.
echo "--- building daemons + shim (native + i686) ---"
cargo build -p pkcs11-proxy-ng -p pkcs11-proxy-ng-shim >/dev/null
cargo build --target i686-unknown-linux-gnu \
    -p pkcs11-proxy-ng -p pkcs11-proxy-ng-shim >/dev/null

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
    LEGS_RUN=$((LEGS_RUN + 1))
}

export PKCS11_PROXY_CROSS_TEST=1
export PKCS11_PROXY_CROSS_PROVIDER=nss
# The i386 NSS closure lives beside the module (nightly extract or a
# pre-exported copy); the i686 daemon resolves it via LD_LIBRARY_PATH.
NSS_LIBDIR="$(dirname "$NSS_MODULE_32")"
export LD_LIBRARY_PATH="$NSS_LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PKCS11_PROXY_BACKEND_ARGS="configDir='sql:$NSSDB' certPrefix='' keyPrefix='' secmod='secmod.db' flags=forceOpen,optimizeSpace tokenDescription='nss32-live'"

PORT=$(harness_pick_port)
export PKCS11_PROXY_ENDPOINT="http://127.0.0.1:$PORT"
I686_DAEMON="target/i686-unknown-linux-gnu/debug/pkcs11-proxy-ng"
harness_start_daemon "$I686_DAEMON" "$NSS_MODULE_32" "$PORT"
assert_fresh "$I686_DAEMON" "i686 NSS daemon"
expect_elf_width "$I686_DAEMON" 32 "i686 NSS daemon"
if ! grep -q "libsoftokn3" "/proc/$DAEMON_PID/maps"; then
    echo "FAIL: i386 NSS module not mapped in daemon pid $DAEMON_PID" >&2
    harness_stop_daemon
    exit 1
fi
echo "  maps receipt: i686 daemon maps libsoftokn3.so"

run_leg "leg 1: x86_64 client (8) <-> i686 daemon (4) over i386 NSS — reverse bridge + D4" 4
run_leg "leg 2: i686 client <-> i686 daemon (narrow-native control) over i386 NSS" 4 \
    --target i686-unknown-linux-gnu
harness_stop_daemon

echo "legs: run=$LEGS_RUN skipped=$LEGS_SKIPPED"
if [[ $LEGS_SKIPPED -gt 0 ]]; then
    echo "PASS-WITH-SKIPS: cross-width NSS32 live test complete ($LEGS_SKIPPED legs skipped)"
else
    echo "PASS: cross-width NSS32 live test complete"
fi
