#!/usr/bin/env bash
# Regression: a healthy daemon must leave startup lines in its log.
#
# Defect: the daemon installed
#   EnvFilter::from_default_env()
# which defaults to ERROR when RUST_LOG is unset, so every `info!`
# startup line ("Slot map populated", "Backend module loaded and
# initialized", ...) was suppressed and a serving daemon produced a
# completely empty log. Operators could not tell "healthy" apart
# from "logging broken".
#
# Acceptance:
#   * With RUST_LOG explicitly unset, the daemon starts, binds, and
#     its log contains the "Backend module loaded and initialized"
#     startup line.
#   * The daemon exits 0/143 on SIGTERM (no crash).
#
# Live-tier script: skips cleanly (exit 0) when SoftHSM2 or the daemon
# binary is absent. Release binaries are the default;
# DAEMON_BIN overrides for local iteration.
#
# Runs against the host's local binaries, like
# scripts/test-sigterm-mid-call.sh. No Docker required.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DAEMON_BIN="${DAEMON_BIN:-$ROOT_DIR/target/release/pkcs11-proxy-ng}"

SOFTHSM2_LIB=""
for cand in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/local/lib/softhsm/libsofthsm2.so; do
    [[ -f "$cand" ]] && SOFTHSM2_LIB="$cand" && break
done
[[ -z "$SOFTHSM2_LIB" ]] && { echo "SKIP: SoftHSM2 not installed; startup-logging test not run"; exit 0; }
[[ -x "$DAEMON_BIN" ]] || { echo "SKIP: daemon binary missing at $DAEMON_BIN; build first"; exit 0; }

WORKDIR="$(mktemp -d)"
DAEMON_PID=""

cleanup() {
    set +e
    [[ -n "$DAEMON_PID" ]] && kill -KILL "$DAEMON_PID" 2>/dev/null
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

export SOFTHSM2_CONF="$WORKDIR/softhsm2.conf"
mkdir -p "$WORKDIR/tokens"
cat >"$SOFTHSM2_CONF" <<EOF
directories.tokendir = $WORKDIR/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF
softhsm2-util --init-token --free \
    --label startup-log --so-pin abcd --pin 1234 >/dev/null

PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"

cat >"$WORKDIR/proxy.toml" <<EOF
[backend]
module = "$SOFTHSM2_LIB"

[proxy]
startup_timeout_secs = 30

[listener.remote]
bind = "127.0.0.1:${PORT}"
auth = "none"
allow_insecure_tcp = true

[auth]
EOF

echo "[1/3] Starting daemon on port ${PORT} with RUST_LOG unset"
# The bug condition: no RUST_LOG in the environment at all.
env -u RUST_LOG "$DAEMON_BIN" "$WORKDIR/proxy.toml" >"$WORKDIR/daemon.log" 2>&1 &
DAEMON_PID=$!

# Wait for the listener to bind.
for _ in $(seq 1 50); do
    if (echo >"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then break; fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "fail: daemon exited during startup; tail:" >&2
        tail -50 "$WORKDIR/daemon.log" >&2
        exit 1
    fi
    sleep 0.2
done
(echo >"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null || {
    echo "fail: daemon did not bind :${PORT}" >&2
    tail -50 "$WORKDIR/daemon.log" >&2
    exit 1
}

echo "[2/3] Daemon serving; checking startup lines in daemon.log"
grep -q "Backend module loaded and initialized" "$WORKDIR/daemon.log" || {
    echo "fail: healthy daemon left no startup line in its log:" >&2
    echo "--- daemon.log ($(wc -c <"$WORKDIR/daemon.log") bytes) ---" >&2
    cat "$WORKDIR/daemon.log" >&2
    exit 1
}

echo "[3/3] Stopping daemon"
kill -TERM "$DAEMON_PID"
daemon_status=0
wait "$DAEMON_PID" 2>/dev/null || daemon_status=$?
DAEMON_PID=""
if (( daemon_status != 0 && daemon_status != 143 )); then
    echo "fail: daemon exited with unexpected status ${daemon_status}" >&2
    exit 1
fi

echo
echo "STARTUP-LOGGING PASS"
echo "  startup line observed with RUST_LOG unset"
echo "  daemon exit: ${daemon_status} (clean)"
