# shellcheck shell=bash
# Shared helpers for the live cross-ABI harness scripts. Source, don't run:
#
#   source "$(dirname "$0")/lib/live-harness.sh"
#
# Provides SoftHSM2 discovery, a temp workspace with token + cleanup trap,
# daemon config generation, and daemon start/stop with port readiness.
# Callers needing extra teardown (e.g. docker containers) define
# `harness_extra_cleanup()` before calling `harness_init_workspace`.

# ── SoftHSM2 discovery ───────────────────────────────────────────────
# Prints the first candidate that exists (nothing when absent).
# Absence is a normal outcome (caller prints SKIP); always returns 0
# so callers under `set -e` survive it.
harness_first_existing() {
    local candidate
    for candidate in "$@"; do
        if [[ -f "$candidate" ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 0
}

# Sets SOFTHSM_MODULE_64 ("" when absent). A pre-exported non-empty
# SOFTHSM_MODULE_64 is honoured as-is (non-root extracted copies).
harness_locate_softhsm64() {
    [[ -n "${SOFTHSM_MODULE_64:-}" ]] && return 0
    SOFTHSM_MODULE_64="$(harness_first_existing \
        /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib64/pkcs11/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so)"
}

# Sets SOFTHSM_MODULE_32 ("" when absent). The i386 package conflicts with
# the amd64 one, so an extracted copy under /opt is probed too. A
# pre-exported non-empty SOFTHSM_MODULE_32 is honoured as-is (non-root
# extracted copies).
harness_locate_softhsm32() {
    [[ -n "${SOFTHSM_MODULE_32:-}" ]] && return 0
    SOFTHSM_MODULE_32="$(harness_first_existing \
        /usr/lib/i386-linux-gnu/softhsm/libsofthsm2.so \
        /opt/softhsm2-i386/usr/lib/i386-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib32/softhsm/libsofthsm2.so)"
}

# Sets NSS_MODULE_32 ("" when absent). Probes a system i386 install
# first, then the nightly extract path (/opt: the i386 NSS closure is
# extracted beside the system, like the i386 SoftHSM2 copy). A
# pre-exported non-empty NSS_MODULE_32 is honoured as-is (non-root
# extracted copies).
harness_locate_nss32() {
    [[ -n "${NSS_MODULE_32:-}" ]] && return 0
    NSS_MODULE_32="$(harness_first_existing \
        /usr/lib/i386-linux-gnu/libsoftokn3.so \
        /opt/nss32-i386/usr/lib/i386-linux-gnu/libsoftokn3.so)"
}

# Fails before daemon startup when a provider has an unresolved dynamic
# dependency. This keeps loader errors attributable to the extracted provider
# closure instead of surfacing later as a generic module-load failure.
harness_require_resolved_dependencies() {
    local module="$1" label="${2:-$1}" output missing
    if ! output="$(LC_ALL=C ldd "$module" 2>&1)"; then
        echo "FAIL: $label: unable to inspect shared-library dependencies" >&2
        echo "$output" >&2
        return 1
    fi

    missing="$(grep -E '=>[[:space:]]+not found([[:space:]]|$)' <<<"$output" || true)"
    if [[ -n "$missing" ]]; then
        echo "FAIL: $label has unresolved shared-library dependencies:" >&2
        echo "$missing" >&2
        return 1
    fi
    echo "  dependency receipt: $label closure resolved"
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
    echo "FAIL: daemon did not start listening on :$port" >&2
    exit 1
}
