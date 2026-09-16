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

run_leg() {
    local label="$1" backend_width="$2"; shift 2
    echo "--- live test: $label ---"
    PKCS11_PROXY_CROSS_EXPECT_BACKEND_WIDTH="$backend_width" \
        cargo test "$@" -p pkcs11-proxy-ng-shim --lib \
        tests::cross_width_live -- --ignored --test-threads=1
}

export PKCS11_PROXY_CROSS_TEST=1
# The i386 NSS closure lives beside the module (nightly extract or a
# pre-exported copy); the i686 daemon resolves it via LD_LIBRARY_PATH.
NSS_LIBDIR="$(dirname "$NSS_MODULE_32")"
export LD_LIBRARY_PATH="$NSS_LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PKCS11_PROXY_BACKEND_ARGS="configDir='sql:$NSSDB' certPrefix='' keyPrefix='' secmod='secmod.db' flags=forceOpen,optimizeSpace tokenDescription='nss32-live'"

PORT=$(harness_pick_port)
export PKCS11_PROXY_ENDPOINT="http://127.0.0.1:$PORT"
harness_start_daemon target/i686-unknown-linux-gnu/debug/pkcs11-proxy-ng \
    "$NSS_MODULE_32" "$PORT"

run_leg "leg 1: x86_64 client (8) <-> i686 daemon (4) over i386 NSS — reverse bridge + D4" 4
run_leg "leg 2: i686 client <-> i686 daemon (narrow-native control) over i386 NSS" 4 \
    --target i686-unknown-linux-gnu
harness_stop_daemon

echo "PASS: cross-width NSS32 live test complete"
