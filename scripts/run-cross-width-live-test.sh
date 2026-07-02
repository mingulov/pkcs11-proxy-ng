#!/usr/bin/env bash
# Live cross-width topology test (ADR-0011 Phase A).
#
# Starts the native x86_64 daemon against a throwaway SoftHSM2 token and
# runs the shim's env-gated live test twice:
#   1. --target i686-unknown-linux-gnu  -> client CK_ULONG width 4 vs the
#      daemon's advertised width 8: the width bridge is engaged for real.
#   2. native x86_64                    -> same-width control (bridge no-op).
#
# Skips cleanly (exit 0 with a notice) when SoftHSM2 is not installed.
# The i686 leg is skipped with a notice when the i686 Rust target or the
# 32-bit toolchain is unavailable; the control leg still runs.
set -euo pipefail

cd "$(dirname "$0")/.."

# ── Locate SoftHSM2 ──────────────────────────────────────────────────
SOFTHSM_MODULE=""
for candidate in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib64/pkcs11/libsofthsm2.so \
    /usr/local/lib/softhsm/libsofthsm2.so; do
    if [[ -f "$candidate" ]]; then
        SOFTHSM_MODULE="$candidate"
        break
    fi
done
if [[ -z "$SOFTHSM_MODULE" ]] || ! command -v softhsm2-util >/dev/null 2>&1; then
    echo "SKIP: SoftHSM2 not installed; cross-width live test not run"
    exit 0
fi

# ── Workspace ────────────────────────────────────────────────────────
WORK="$(mktemp -d /tmp/pkcs11-cross-width.XXXXXX)"
DAEMON_PID=""
cleanup() {
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/tokens"
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $WORK/tokens
objectstore.backend = file
log.level = ERROR
EOF
softhsm2-util --init-token --free --label cross-width \
    --so-pin 12345678 --pin 12345678 >/dev/null

# ── Daemon (native x86_64, insecure localhost TCP for the test only) ─
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

echo "--- building native daemon ---"
cargo build -p pkcs11-proxy-ng >/dev/null
target/debug/pkcs11-proxy-ng "$WORK/proxy-config.toml" \
    > "$WORK/daemon.log" 2>&1 &
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

export PKCS11_PROXY_CROSS_TEST=1
export PKCS11_PROXY_ENDPOINT="http://127.0.0.1:$PORT"

run_leg() {
    local label="$1"; shift
    echo "--- live test: $label ---"
    cargo test "$@" -p pkcs11-proxy-ng-shim --lib \
        tests::cross_width_live -- --ignored --test-threads=1
}

# ── Leg 1: i686 narrow client (the real bridge path) ────────────────
if rustup target list --installed 2>/dev/null | grep -q '^i686-unknown-linux-gnu$'; then
    run_leg "i686 client (width 4) <-> x86_64 daemon (width 8)" \
        --target i686-unknown-linux-gnu
else
    echo "SKIP: i686-unknown-linux-gnu target not installed; narrow leg not run"
fi

# ── Leg 2: native same-width control ─────────────────────────────────
run_leg "x86_64 client <-> x86_64 daemon (same-width control)"

echo "PASS: cross-width live test complete"
