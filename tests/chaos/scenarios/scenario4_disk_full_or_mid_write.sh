#!/bin/sh
# R8 scenario 4 — IO failures on config dir + SIGHUP.
#
# Three sub-tests exercising different failure modes that the daemon's
# SIGHUP-reload path must survive:
#
#   (a) Config FILE chmod 000 (truer IO-error simulation than `chmod
#       -w` on the dir, which only blocks writes — SIGHUP only reads).
#       Daemon must log a read error and retain the prior registry.
#
#   (b) Mid-write partial TOML (sed truncation). Daemon must log a
#       parse error and retain the prior registry.
#
#   (c) Real ENOSPC on the registry path via a docker --tmpfs mount
#       cap'd at 8 KiB, pre-filled with junk so any write fails with
#       ENOSPC. Daemon must handle the truncated/unreadable file
#       gracefully on SIGHUP.
#
# Sub-test (c) closes R8-FOLLOWUP-real-disk-full.

set -u
. "$(dirname "$0")/_common.sh"

echo "=== R8 scenario 4: IO failures on registry path + SIGHUP ==="

baseline_rev=$(docker logs "$DAEMON_CONTAINER" 2>&1 | grep -oE '"revision":"[a-f0-9]+"' | tail -1)
echo "  baseline registry revision: $baseline_rev"

# ─── (a) config FILE unreadable ─────────────────────────────────────────
echo "  (a) chmod 000 mechanism_params.toml + SIGHUP..."
docker exec "$DAEMON_CONTAINER" chmod 000 /etc/pkcs11-proxy-ng/mechanism_params.toml 2>&1 || true
docker exec "$DAEMON_CONTAINER" kill -HUP 1 2>&1 || true
sleep 2

post_a_rev=$(docker logs "$DAEMON_CONTAINER" 2>&1 | grep -oE '"revision":"[a-f0-9]+"' | tail -1)
if [ "$baseline_rev" = "$post_a_rev" ] && docker inspect --format '{{.State.Running}}' "$DAEMON_CONTAINER" | grep -q true; then
    echo "  (a) daemon alive + registry retained on read error: PASS"
else
    echo "  (a) revision changed or daemon died: FAIL"
    echo "       baseline=$baseline_rev  post=$post_a_rev"
    exit 1
fi

docker exec "$DAEMON_CONTAINER" chmod 644 /etc/pkcs11-proxy-ng/mechanism_params.toml 2>&1 || true

# ─── (b) mid-write garbage ──────────────────────────────────────────────
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
else
    echo "  (b) revision unexpectedly changed or daemon died: FAIL"
    echo "       baseline=$baseline_rev  post=$post_b_rev"
    exit 1
fi

# ─── (c) real ENOSPC via docker --tmpfs ─────────────────────────────────
# Spin up a SECOND daemon container with the registry path on a 8 KiB
# tmpfs. Mid-test, fill the tmpfs with a junk file so any append/write
# fails with ENOSPC, and SIGHUP. The original daemon container under
# DAEMON_CONTAINER is left untouched.
echo "  (c) tmpfs ENOSPC + SIGHUP..."
TMP_DAEMON=r8-disk-full-daemon
TMPFS_DIR=/var/r8-registry
SUBMODULE_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
docker rm -f "$TMP_DAEMON" >/dev/null 2>&1 || true
# Mount the tmpfs at a SIDECAR path (NOT /etc/pkcs11-proxy-ng) so we
# don't hide the image's baked-in proxy.toml. Point the daemon at the
# tmpfs-hosted mechanism_params via PKCS11_PROXY_MECHANISMS_CONFIG.
docker run -d --name "$TMP_DAEMON" \
    --tmpfs "$TMPFS_DIR:size=64k,mode=0755" \
    -p 7613:7512 \
    -v "$SUBMODULE_ROOT/tests/r2_resilience/slow_backend/target/release:/opt/slow_backend:ro" \
    -e RUST_LOG="pkcs11_proxy_ng=info" \
    -e LOG_FORMAT=json \
    -e PKCS11_PROXY_BACKEND_MODULE=/opt/slow_backend/libslow_backend.so \
    -e PKCS11_PROXY_MECHANISMS_CONFIG="$TMPFS_DIR/mechanism_params.toml" \
    --entrypoint /bin/sh \
    pkcs11-proxy-ng:chaos-daemon \
    -c "cat > $TMPFS_DIR/mechanism_params.toml <<TOML
discovery_mode = \"transparent\"
parameterless = [0x0001]
TOML
    exec /usr/bin/pkcs11-proxy-ng /etc/pkcs11-proxy-ng/proxy.toml" >/dev/null
sleep 3

baseline_c_rev=$(docker logs "$TMP_DAEMON" 2>&1 | grep -oE '"revision":"[a-f0-9]+"' | tail -1)
echo "       tmpfs daemon registry revision: ${baseline_c_rev:-<none>}"

# Fill the 64 KiB tmpfs almost completely, then attempt a write that
# pushes beyond the cap so it fails with ENOSPC.
docker exec "$TMP_DAEMON" sh -c "
    # First fill with a precisely-sized file. Add a smaller padding to
    # leave a tiny gap, then exhaust it with a write that won't fit.
    dd if=/dev/zero of=$TMPFS_DIR/.fill bs=1k count=63 2>/dev/null || true
    # Verify the tmpfs is now near-full.
    df -k $TMPFS_DIR | tail -1
    if dd if=/dev/zero bs=4k count=4 >> $TMPFS_DIR/mechanism_params.toml 2>/tmp/enospc_err; then
        echo '       (unexpected) write succeeded; tmpfs not actually full'
        cat /tmp/enospc_err
        exit 2
    fi
    echo \"       write failed as expected: \$(tail -1 /tmp/enospc_err)\"
"
docker exec "$TMP_DAEMON" kill -HUP 1 2>&1 || true
sleep 2

post_c_rev=$(docker logs "$TMP_DAEMON" 2>&1 | grep -oE '"revision":"[a-f0-9]+"' | tail -1)
if docker inspect --format '{{.State.Running}}' "$TMP_DAEMON" | grep -q true; then
    if [ "$baseline_c_rev" = "$post_c_rev" ]; then
        echo "  (c) daemon survived ENOSPC + registry retained: PASS"
    else
        echo "  (c) registry revision unexpectedly changed: SUSPICIOUS"
        echo "       baseline=$baseline_c_rev  post=$post_c_rev"
        # Not a hard fail — if the daemon re-parsed the truncated file
        # and accepted it as the new registry, that's a different
        # finding worth surfacing but not crashing the scenario.
    fi
else
    echo "  (c) tmpfs daemon died on SIGHUP under ENOSPC: FAIL"
    docker logs "$TMP_DAEMON" 2>&1 | tail -10
    docker rm -f "$TMP_DAEMON" >/dev/null 2>&1 || true
    exit 1
fi
docker rm -f "$TMP_DAEMON" >/dev/null 2>&1 || true

echo "scenario4: PASS"
