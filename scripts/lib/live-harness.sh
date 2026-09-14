# Shared helpers for the live cross-ABI harness scripts. Source, don't run:
#
#   source "$(dirname "$0")/lib/live-harness.sh"
#
# Provides SoftHSM2 discovery, a temp workspace with token + cleanup trap,
# daemon config generation, and daemon start/stop with port readiness.
# Callers needing extra teardown (e.g. docker containers) define
# `harness_extra_cleanup()` before calling `harness_init_workspace`.

# ── SoftHSM2 discovery ───────────────────────────────────────────────
# Sets SOFTHSM_MODULE_64 ("" when absent). A pre-exported non-empty
# SOFTHSM_MODULE_64 is honoured as-is (non-root extracted copies).
harness_locate_softhsm64() {
    [[ -n "${SOFTHSM_MODULE_64:-}" ]] && return 0
    SOFTHSM_MODULE_64=""
    local candidate
    for candidate in \
        /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib64/pkcs11/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so; do
        [[ -f "$candidate" ]] && SOFTHSM_MODULE_64="$candidate" && break
    done
    # Absence is a normal outcome (caller prints SKIP); never fail under set -e.
    return 0
}

# Sets SOFTHSM_MODULE_32 ("" when absent). The i386 package conflicts with
# the amd64 one, so an extracted copy under /opt is probed too. A
# pre-exported non-empty SOFTHSM_MODULE_32 is honoured as-is (non-root
# extracted copies).
harness_locate_softhsm32() {
    [[ -n "${SOFTHSM_MODULE_32:-}" ]] && return 0
    SOFTHSM_MODULE_32=""
    local candidate
    for candidate in \
        /usr/lib/i386-linux-gnu/softhsm/libsofthsm2.so \
        /opt/softhsm2-i386/usr/lib/i386-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib32/softhsm/libsofthsm2.so; do
        [[ -f "$candidate" ]] && SOFTHSM_MODULE_32="$candidate" && break
    done
    # Absence is a normal outcome (caller prints SKIP); never fail under set -e.
    return 0
}

# ── Workspace, token, cleanup ────────────────────────────────────────
DAEMON_PID=""

harness_stop_daemon() {
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    DAEMON_PID=""
}

_harness_cleanup() {
    harness_stop_daemon
    if declare -F harness_extra_cleanup >/dev/null; then
        harness_extra_cleanup
    fi
    [[ -n "${WORK:-}" ]] && rm -rf "$WORK"
}

# Creates $WORK, installs the EXIT trap, provisions a throwaway SoftHSM2
# token (label = $1) and exports SOFTHSM2_CONF for it.
harness_init_workspace() {
    local label="$1"
    WORK="$(mktemp -d "/tmp/pkcs11-live-harness.XXXXXX")"
    trap _harness_cleanup EXIT
    mkdir -p "$WORK/tokens"
    export SOFTHSM2_CONF="$WORK/softhsm2.conf"
    cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $WORK/tokens
objectstore.backend = file
log.level = ERROR
EOF
    softhsm2-util --init-token --free --label "$label" \
        --so-pin 12345678 --pin 12345678 >/dev/null
}

# ── Daemon lifecycle ─────────────────────────────────────────────────
harness_pick_port() {
    echo $(( 20000 + RANDOM % 20000 ))
}

# Writes $WORK/proxy-config.toml for an insecure-localhost test daemon.
harness_write_daemon_config() {
    local module="$1" port="$2"
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
}

# Starts `daemon_bin` on `port` against `module`; waits for readiness and
# fails loudly (with the daemon log) on startup errors.
harness_start_daemon() {
    local daemon_bin="$1" module="$2" port="$3"
    harness_write_daemon_config "$module" "$port"
    "$daemon_bin" "$WORK/proxy-config.toml" > "$WORK/daemon.log" 2>&1 &
    DAEMON_PID=$!
    local i
    for i in $(seq 1 50); do
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
    echo "FAIL: daemon did not start listening on :$port" >&2
    exit 1
}
