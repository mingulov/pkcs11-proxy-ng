# shellcheck shell=sh
# Sourced by every chaos scenario. Keeps the container / env names
# in one place so renaming the compose service doesn't require touching
# each script.
#
# POSIX sh only — most chaos scenarios run under `#!/bin/sh`.

DAEMON_CONTAINER="${DAEMON_CONTAINER:-r8-chaos-daemon}"
RUNNER_CONTAINER="${RUNNER_CONTAINER:-r8-chaos-runner}"

# Compose file for the chaos fixture (stop/rm/up the daemon with
# per-scenario SLOW_BACKEND_* env). Overridable for custom topologies.
if [ -z "${COMPOSE_FILE:-}" ]; then
    COMPOSE_FILE="$(cd "$(dirname "$0")" && pwd)/../docker-compose.yml"
fi
if [ ! -f "$COMPOSE_FILE" ]; then
    echo "FAIL: chaos compose file not found: '$COMPOSE_FILE'." >&2
    echo "      Set COMPOSE_FILE explicitly." >&2
    exit 2
fi

# Run a consumer command inside the runner container (W1-L10-01).
runner_exec() {
    docker exec "$RUNNER_CONTAINER" "$@"
}

# Millisecond wall clock (W1-L10-10). GNU and busybox `date` both
# support %s and %N; degrade to second precision otherwise.
now_ms() {
    _s=$(date +%s)
    _n=$(date +%N 2>/dev/null)
    case $_n in
        ''|%N|*[!0-9]*) printf '%s000' "$_s" ;;
        *) printf '%s%.3s' "$_s" "$_n" ;;
    esac
    unset _s _n
}

# PID of the daemon process inside its container (W1-L10-19) — never
# assume PID 1. Prints the PID, or nothing when not found.
daemon_pid() {
    docker exec "$DAEMON_CONTAINER" pidof pkcs11-proxy-ng 2>/dev/null | awk '{print $1}'
}

# Poll the daemon's gRPC health gate until SERVING or timeout (W1-L10-10).
# Usage: wait_for_daemon_healthy [container] [timeout_s]
wait_for_daemon_healthy() {
    _c=${1:-$DAEMON_CONTAINER}
    _t=${2:-30}
    _i=0
    while [ "$_i" -lt "$_t" ]; do
        if docker exec "$_c" pkcs11-proxy-ng-cli health >/dev/null 2>&1; then
            unset _c _t _i
            return 0
        fi
        sleep 1
        _i=$((_i + 1))
    done
    unset _c _t _i
    return 1
}

# Poll `docker logs` for a BRE pattern until it appears or timeout
# (W1-L10-10). Usage: wait_for_log_line <container> <pattern> [timeout_s]
wait_for_log_line() {
    _c=$1
    _pat=$2
    _t=${3:-15}
    _i=0
    while [ "$_i" -lt "$_t" ]; do
        if docker logs "$_c" 2>&1 | grep -q "$_pat"; then
            unset _c _pat _t _i
            return 0
        fi
        sleep 1
        _i=$((_i + 1))
    done
    unset _c _pat _t _i
    return 1
}

# Fail loudly if the fixture isn't up yet — saves a confusing
# `docker exec: no such container` later in the script.
if ! docker inspect "$DAEMON_CONTAINER" >/dev/null 2>&1; then
    echo "FAIL: chaos fixture not running (no container '$DAEMON_CONTAINER')." >&2
    echo "      Bring it up with:" >&2
    echo "         docker compose -f tests/chaos/docker-compose.yml up -d" >&2
    exit 2
fi
