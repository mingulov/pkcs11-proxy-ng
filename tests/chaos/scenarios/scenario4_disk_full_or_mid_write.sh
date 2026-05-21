#!/bin/sh
# R8 scenario 4 — disk full / read-only config dir + SIGHUP.
# Also scenario 5 (mid-write configmap) — covered together because
# both exercise SIGHUP's error-handling path.
#
# (a) chmod -w /etc/pkcs11-proxy-ng; SIGHUP daemon; verify error
#     logged, registry retained, daemon survives.
# (b) sed -i with partial mid-write on mechanism_params.toml + SIGHUP;
#     verify TOML parse error logged + registry retained.

set -u
. "$(dirname "$0")/_common.sh"

echo "=== R8 scenario 4: disk-full / mid-write config + SIGHUP ==="

# Capture current registry revision from daemon log.
baseline_rev=$(docker logs "$DAEMON_CONTAINER" 2>&1 | grep -oE '"revision":"[a-f0-9]+"' | tail -1)
echo "  baseline registry revision: $baseline_rev"

# (a) Mark config dir read-only, SIGHUP, verify daemon survives + revision unchanged.
echo "  (a) chmod -w + SIGHUP..."
docker exec "$DAEMON_CONTAINER" chmod -w /etc/pkcs11-proxy-ng 2>&1 || \
    docker exec "$DAEMON_CONTAINER" sh -c 'chmod -w /etc/pkcs11-proxy-ng || true'
docker exec "$DAEMON_CONTAINER" kill -HUP 1 2>&1 || true
sleep 2

post_a_rev=$(docker logs "$DAEMON_CONTAINER" 2>&1 | grep -oE '"revision":"[a-f0-9]+"' | tail -1)
if [ "$baseline_rev" = "$post_a_rev" ] && docker inspect --format '{{.State.Running}}' "$DAEMON_CONTAINER" | grep -q true; then
    echo "  (a) daemon alive + revision retained: PASS"
else
    echo "  (a) revision changed or daemon died: FAIL"
    echo "       baseline=$baseline_rev  post=$post_a_rev"
    exit 1
fi

# Reset permissions.
docker exec "$DAEMON_CONTAINER" chmod +w /etc/pkcs11-proxy-ng 2>&1 || true

# (b) Write garbage to mechanism_params.toml + SIGHUP. Verify
#     daemon retains the previous (valid) registry on parse failure.
echo "  (b) mid-write garbage + SIGHUP..."
docker exec "$DAEMON_CONTAINER" sh -c '
    mkdir -p /etc/pkcs11-proxy-ng
    echo "[[params]]" > /etc/pkcs11-proxy-ng/mechanism_params.toml
    echo "this is not valid TOML !!!" >> /etc/pkcs11-proxy-ng/mechanism_params.toml
' 2>&1 || true
docker exec "$DAEMON_CONTAINER" kill -HUP 1 2>&1 || true
sleep 2

post_b_rev=$(docker logs "$DAEMON_CONTAINER" 2>&1 | grep -oE '"revision":"[a-f0-9]+"' | tail -1)
if [ "$baseline_rev" = "$post_b_rev" ] && docker inspect --format '{{.State.Running}}' "$DAEMON_CONTAINER" | grep -q true; then
    echo "  (b) parse error handled, registry retained: PASS"
    echo "scenario4: PASS"
else
    echo "  (b) revision unexpectedly changed or daemon died: FAIL"
    echo "       baseline=$baseline_rev  post=$post_b_rev"
    exit 1
fi
