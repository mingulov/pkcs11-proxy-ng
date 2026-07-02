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
# Legs 3-4 need the 32-bit SoftHSM2 library (libsofthsm2:i386) and are
# skipped with a notice when it is absent. The whole script skips cleanly
# when SoftHSM2 or the i686 Rust target is unavailable.
set -euo pipefail

cd "$(dirname "$0")/.."

# ── Locate SoftHSM2 (64-bit mandatory, 32-bit optional) ──────────────
SOFTHSM_MODULE_64=""
for candidate in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib64/pkcs11/libsofthsm2.so \
    /usr/local/lib/softhsm/libsofthsm2.so; do
    [[ -f "$candidate" ]] && SOFTHSM_MODULE_64="$candidate" && break
done
if [[ -z "$SOFTHSM_MODULE_64" ]] || ! command -v softhsm2-util >/dev/null 2>&1; then
    echo "SKIP: SoftHSM2 not installed; cross-width live test not run"
    exit 0
fi
SOFTHSM_MODULE_32=""
for candidate in \
    /usr/lib/i386-linux-gnu/softhsm/libsofthsm2.so \
    /opt/softhsm2-i386/usr/lib/i386-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib32/softhsm/libsofthsm2.so; do
    [[ -f "$candidate" ]] && SOFTHSM_MODULE_32="$candidate" && break
done

HAVE_I686=0
if rustup target list --installed 2>/dev/null | grep -q '^i686-unknown-linux-gnu$'; then
    HAVE_I686=1
fi

# ── Workspace ────────────────────────────────────────────────────────
WORK="$(mktemp -d /tmp/pkcs11-cross-width.XXXXXX)"
DAEMON_PID=""
stop_daemon() {
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    DAEMON_PID=""
}
cleanup() {
    stop_daemon
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

# ── Builds (explicit cdylib/daemon builds — an `--example`-only build
#    does NOT refresh the shim library and stale artifacts test nothing) ─
echo "--- building daemons + shim (native$( [[ $HAVE_I686 -eq 1 ]] && echo ' + i686')) ---"
cargo build -p pkcs11-proxy-ng -p pkcs11-proxy-ng-shim >/dev/null
if [[ $HAVE_I686 -eq 1 ]]; then
    cargo build --target i686-unknown-linux-gnu \
        -p pkcs11-proxy-ng -p pkcs11-proxy-ng-shim >/dev/null
fi

start_daemon() {
    local daemon_bin="$1" module="$2" port="$3"
    cat > "$WORK/proxy-config.toml" <<EOF
[backend]
module = "$module"

[proxy]
mechanism_discovery = "transparent"

[listener.remote]
bind = "127.0.0.1:$port"
auth = "none"
allow_insecure_tcp = true
EOF
    "$daemon_bin" "$WORK/proxy-config.toml" > "$WORK/daemon.log" 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 1 50); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            exec 3>&- 3<&-
            return 0
        fi
        if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
            echo "FAIL: daemon exited during startup; log follows" >&2
            cat "$WORK/daemon.log" >&2
            exit 1
        fi
        sleep 0.2
    done
    echo "FAIL: daemon did not start listening" >&2
    exit 1
}

run_leg() {
    local label="$1" backend_width="$2"; shift 2
    echo "--- live test: $label ---"
    PKCS11_PROXY_CROSS_EXPECT_BACKEND_WIDTH="$backend_width" \
        cargo test "$@" -p pkcs11-proxy-ng-shim --lib \
        tests::cross_width_live -- --ignored --test-threads=1
}

export PKCS11_PROXY_CROSS_TEST=1

# ── 64-bit daemon: legs 1-2 ──────────────────────────────────────────
PORT=$(( 20000 + RANDOM % 20000 ))
export PKCS11_PROXY_ENDPOINT="http://127.0.0.1:$PORT"
start_daemon target/debug/pkcs11-proxy-ng "$SOFTHSM_MODULE_64" "$PORT"

if [[ $HAVE_I686 -eq 1 ]]; then
    run_leg "leg 1: i686 client (4) <-> x86_64 daemon (8)" 8 \
        --target i686-unknown-linux-gnu
else
    echo "SKIP leg 1: i686-unknown-linux-gnu target not installed"
fi
run_leg "leg 2: x86_64 client <-> x86_64 daemon (same-width control)" 8
stop_daemon

# ── 32-bit daemon: legs 3-4 ──────────────────────────────────────────
if [[ $HAVE_I686 -eq 1 && -n "$SOFTHSM_MODULE_32" ]]; then
    PORT=$(( 20000 + RANDOM % 20000 ))
    export PKCS11_PROXY_ENDPOINT="http://127.0.0.1:$PORT"
    start_daemon target/i686-unknown-linux-gnu/debug/pkcs11-proxy-ng \
        "$SOFTHSM_MODULE_32" "$PORT"

    run_leg "leg 3: x86_64 client (8) <-> i686 daemon (4) — reverse bridge + D4" 4
    run_leg "leg 4: i686 client <-> i686 daemon (narrow-native control)" 4 \
        --target i686-unknown-linux-gnu
    stop_daemon
else
    echo "SKIP legs 3-4: need the i686 Rust target and libsofthsm2:i386"
fi

echo "PASS: cross-width live test complete"
