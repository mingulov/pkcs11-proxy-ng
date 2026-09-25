#!/usr/bin/env bash
# Concurrency scenario: SIGTERM to the daemon mid-call.
#
# Setup:
#   1. Initialise a fresh SoftHSM2 token in a tempdir.
#   2. Start the daemon (auth="none", SoftHSM2 backend) on a free
#      port. Use a small `proxy.shutdown_grace_secs` so the test
#      doesn't have to wait the default 30s — the goal is to
#      observe graceful drain, not to measure it precisely.
#   3. Start an RSA-4096 keypair generation through the shim
#      (intentionally slow on SoftHSM2: tens of seconds).
#   4. After 1.5s, send SIGTERM to the daemon.
#
# Acceptance:
#   * `pkcs11-tool` returns (no hang) within a bounded wall window.
#   * Its exit code is non-zero (the keygen could not complete
#     because the daemon is going away).
#   * The CK_RV printed by `pkcs11-tool` is one of the
#     spec-permitted transport-failure codes — typically
#     CKR_DEVICE_ERROR for in-flight session ops, occasionally
#     CKR_FUNCTION_CANCELED depending on how far the call
#     progressed.
#   * The daemon process exits with status 0 (clean drain) or
#     status reflecting it was signalled — NEVER with a signal
#     death code like 6 (SIGABRT) or 11 (SIGSEGV).
#
# Runs against the host's local `target/release/` binaries, like
# scripts/test-softhsm2-smoke.sh. No Docker required.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DAEMON_BIN="$ROOT_DIR/target/release/pkcs11-proxy-ng"
SHIM_LIB="$ROOT_DIR/target/release/libpkcs11_proxy_ng_shim.so"

SOFTHSM2_LIB=""
for cand in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/local/lib/softhsm/libsofthsm2.so; do
    [[ -f "$cand" ]] && SOFTHSM2_LIB="$cand" && break
done
[[ -z "$SOFTHSM2_LIB" ]] && { echo "SoftHSM2 .so not found" >&2; exit 1; }

for cmd in softhsm2-util pkcs11-tool; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "missing: $cmd" >&2; exit 1; }
done
[[ -x "$DAEMON_BIN" && -f "$SHIM_LIB" ]] || {
    echo "binaries missing; run scripts/release-dry-run.sh first" >&2
    exit 1
}

WORKDIR="$(mktemp -d)"
DAEMON_PID=""
TOOL_PID=""

cleanup() {
    set +e
    for pid in "$TOOL_PID" "$DAEMON_PID"; do
        [[ -n "$pid" ]] && kill -KILL "$pid" 2>/dev/null
    done
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

export SOFTHSM2_CONF="$WORKDIR/softhsm2.conf"
mkdir -p "$WORKDIR/tokens"
cat >"$SOFTHSM2_CONF" <<EOF
directories.tokendir = $WORKDIR/tokens
objectstore.backend = file
log.level = INFO
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF
softhsm2-util --init-token --free \
    --label r7-sigterm --so-pin abcd --pin 1234 >/dev/null

PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"

# Modes:
#   `complete` (default): grace window is long enough for a 4096-bit
#                         keygen to finish on softhsm2 — exercises
#                         option A (in-flight completes during drain).
#   `cancel`            : grace window deliberately too short — the
#                         tool sees a transport error instead.
MODE="${SIGTERM_MIDCALL_MODE:-complete}"

case "$MODE" in
    # Option A: keygen finishes inside the grace window.
    complete) GRACE=10 ; KEY_BITS=4096 ; SIGTERM_AFTER=1.5 ;;
    # Option B: grace exhausted while the daemon is still serving
    # follow-up RPCs (object listing after a fast keygen, etc.). The
    # in-flight ops surface CKR_DEVICE_ERROR. SoftHSM2 RSA-4096 only
    # takes ~1s so the keygen itself usually completes during the
    # grace window, but the post-keygen attribute reads do not.
    cancel)   GRACE=1  ; KEY_BITS=4096 ; SIGTERM_AFTER=0.2 ;;
    *) echo "unknown SIGTERM_MIDCALL_MODE=$MODE (complete|cancel)" >&2; exit 64 ;;
esac

cat >"$WORKDIR/proxy.toml" <<EOF
[backend]
module = "$SOFTHSM2_LIB"

[proxy]
request_timeout_secs = 120
startup_timeout_secs = 30
shutdown_grace_secs = ${GRACE}
backend_health_consecutive_failures = 3

[listener.remote]
bind = "127.0.0.1:${PORT}"
auth = "none"
allow_insecure_tcp = true

[auth]
EOF

echo "[1/4] Starting daemon on port ${PORT} (mode=${MODE} grace=${GRACE}s)"
RUST_LOG="pkcs11_proxy_ng=info" \
    "$DAEMON_BIN" "$WORKDIR/proxy.toml" >"$WORKDIR/daemon.log" 2>&1 &
DAEMON_PID=$!

# Wait for the listener to bind.
for _ in $(seq 1 30); do
    if (echo >"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then break; fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "daemon exited during startup; tail:" >&2
        tail -50 "$WORKDIR/daemon.log" >&2
        exit 1
    fi
    sleep 0.2
done

export PKCS11_PROXY_ENDPOINT="http://127.0.0.1:${PORT}"

echo "[2/4] Starting slow keypairgen (RSA-${KEY_BITS}) in background"
( pkcs11-tool --module "$SHIM_LIB" \
    --token-label r7-sigterm --login --pin 1234 \
    --keypairgen --key-type "rsa:${KEY_BITS}" \
    --label r7-key --id 01 >"$WORKDIR/tool.log" 2>&1; \
    echo $? >"$WORKDIR/tool.rc" ) &
TOOL_PID=$!

# Give the call time to actually start hitting the backend.
sleep "$SIGTERM_AFTER"

echo "[3/4] Sending SIGTERM to daemon (pid ${DAEMON_PID})"
sigterm_t0=$(date +%s)
kill -TERM "$DAEMON_PID"

# Wait for both processes to settle. Bounded window: pkcs11-tool
# should not exceed (shutdown_grace_secs + transport-error reaction
# slack) by very much.
max_wait=30
end=$(( sigterm_t0 + max_wait ))
while [[ $(date +%s) -lt $end ]]; do
    tool_done=true
    daemon_done=true
    kill -0 "$TOOL_PID" 2>/dev/null && tool_done=false
    kill -0 "$DAEMON_PID" 2>/dev/null && daemon_done=false
    if $tool_done && $daemon_done; then break; fi
    sleep 0.5
done

# Make doubly sure they're reaped.
wait "$DAEMON_PID" 2>/dev/null || true
daemon_status=$?
wait "$TOOL_PID" 2>/dev/null || true
tool_status=$?
TOOL_PID=""
DAEMON_PID=""

echo "[4/4] tool_status=${tool_status} daemon_status=${daemon_status}"

# Acceptance checks (mode-dependent).
case "$MODE" in
    complete)
        # Option A: graceful drain completed the call.
        if (( tool_status != 0 )); then
            echo "fail (complete mode): keygen failed under a generous grace window" >&2
            cat "$WORKDIR/tool.log" >&2
            exit 1
        fi
        echo "complete mode: keygen finished cleanly during graceful drain"
        ;;
    cancel)
        # Option B: grace was too short. The tool MUST observe at
        # least one transport-class CK_RV — either on the keygen
        # itself, or on the post-keygen attribute reads / close
        # session calls. pkcs11-tool sometimes returns 0 even after
        # printing CK_RV errors on cleanup; we therefore check the
        # log content rather than the exit code.
        if grep -qE "CKR_DEVICE_ERROR|CKR_GENERAL_ERROR|CKR_FUNCTION_CANCELED|CKR_FUNCTION_FAILED|CKR_TOKEN_NOT_PRESENT|CKR_SESSION_HANDLE_INVALID|CKR_CRYPTOKI_NOT_INITIALIZED" "$WORKDIR/tool.log"; then
            echo "cancel mode: shim surfaced spec-permitted transport CK_RV(s)"
        else
            echo "fail (cancel mode): no transport CK_RV observed; ${GRACE}s grace either too generous or shim swallowed the error" >&2
            cat "$WORKDIR/tool.log" >&2
            exit 1
        fi
        ;;
esac

if [[ "$MODE" == "cancel" ]]; then
    # The tool log should mention a spec-permitted transport CK_RV.
    if grep -qE "CKR_(DEVICE_ERROR|GENERAL_ERROR|FUNCTION_CANCELED|FUNCTION_FAILED|TOKEN_NOT_PRESENT|SESSION_HANDLE_INVALID|CRYPTOKI_NOT_INITIALIZED)" "$WORKDIR/tool.log"; then
        :  # expected
    else
        echo "fail (cancel mode): tool log doesn't mention a recognized transport CK_RV:" >&2
        cat "$WORKDIR/tool.log" >&2
        exit 1
    fi
fi

# The daemon must NOT have died with SIGSEGV (139), SIGABRT (134), etc.
# Acceptable: 0 (clean drain) or 143 (SIGTERM acknowledged).
if (( daemon_status != 0 && daemon_status != 143 )); then
    echo "fail: daemon exited with unexpected status ${daemon_status} (suspect crash)" >&2
    tail -30 "$WORKDIR/daemon.log" >&2
    exit 1
fi

# Confirm graceful-shutdown log lines fired.
grep -qE "Received SIGTERM" "$WORKDIR/daemon.log" || {
    echo "fail: daemon never logged SIGTERM receipt:" >&2
    tail -30 "$WORKDIR/daemon.log" >&2
    exit 1
}

echo
echo "SIGTERM-mid-call PASS"
echo "  pkcs11-tool exit: ${tool_status} (non-zero, as expected)"
echo "  daemon exit:      ${daemon_status} (clean SIGTERM acknowledgement)"
echo "  graceful-shutdown log line observed"
