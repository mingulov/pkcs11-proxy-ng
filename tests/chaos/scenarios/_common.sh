# Sourced by every chaos scenario. Keeps the container / env names
# in one place so renaming the compose service doesn't require touching
# each script.

DAEMON_CONTAINER="${DAEMON_CONTAINER:-r8-chaos-daemon}"
RUNNER_CONTAINER="${RUNNER_CONTAINER:-r8-chaos-runner}"

# Fail loudly if the fixture isn't up yet — saves a confusing
# `docker exec: no such container` later in the script.
if ! docker inspect "$DAEMON_CONTAINER" >/dev/null 2>&1; then
    echo "FAIL: chaos fixture not running (no container '$DAEMON_CONTAINER')." >&2
    echo "      Bring it up with:" >&2
    echo "         docker compose -f tests/chaos/docker-compose.yml up -d" >&2
    exit 2
fi
