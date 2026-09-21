#!/bin/sh
# Scenario 4: IO failures on config dir + SIGHUP.
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
#       cap'd at 64 KiB, pre-filled with junk so any write fails with
#       ENOSPC. Daemon must handle the truncated/unreadable file
#       gracefully on SIGHUP.
#
# Sub-test (c) closes FOLLOWUP-real-disk-full.

set -u
. "$(dirname "$0")/_common.sh"

echo "=== Scenario 4: IO failures on registry path + SIGHUP ==="

REG_PATH=/etc/pkcs11-proxy-ng/mechanism_params.toml

# Expected registry revision for a file's CURRENT bytes (W1-L10-09):
# sha256(content)[..16] is the daemon's compute_revision, so deriving
# the expectation from file state (not from an earlier log line)
# keeps the comparison non-vacuous — an empty baseline can no longer
# "equal" an empty post-reload read.
expected_revision() {
    docker exec "$1" cat "$2" 2>/dev/null | sha256sum | cut -c1-16
}

# Latest revision the DAEMON reported serving (startup or reload line).
reported_revision() {
    docker logs "$1" 2>&1 | grep -oE '"revision":"[a-f0-9]+"' | tail -1 | sed -E 's/.*"revision":"([a-f0-9]+)".*/\1/'
}

# Keep the fixture daemon's registry file pristine across legs (and
# re-runs): snapshot it now, restore content + mode after leg (b).
ORIG_TOML=$(mktemp /tmp/scenario4.XXXXXX.toml)
trap 'rm -f "$ORIG_TOML"' EXIT INT TERM
if ! docker exec "$DAEMON_CONTAINER" cat "$REG_PATH" > "$ORIG_TOML" 2>/dev/null; then
    echo "  cannot snapshot $REG_PATH from fixture daemon: FAIL"
    exit 1
fi
restore_registry() {
    docker exec "$DAEMON_CONTAINER" sh -c "cat > $REG_PATH" < "$ORIG_TOML" 2>&1
    docker exec "$DAEMON_CONTAINER" chmod 644 "$REG_PATH" 2>&1 || true
}

# Anchor: the daemon must currently serve exactly the on-disk state.
expected=$(expected_revision "$DAEMON_CONTAINER" "$REG_PATH")
reported=$(reported_revision "$DAEMON_CONTAINER")
echo "  on-disk revision: $expected; daemon-served revision: ${reported:-<none>}"
if [ -z "$expected" ] || [ "$reported" != "$expected" ]; then
    echo "  daemon is not serving the on-disk registry state: FAIL"
    exit 1
fi

# ─── (a) config FILE unreadable ─────────────────────────────────────────
echo "  (a) chmod 000 mechanism_params.toml + SIGHUP..."
docker exec "$DAEMON_CONTAINER" chmod 000 "$REG_PATH" 2>&1 || true
docker exec "$DAEMON_CONTAINER" kill -HUP 1 2>&1 || true
if ! wait_for_log_line "$DAEMON_CONTAINER" "mechanism registry reload failed" 15; then
    echo "  (a) no reload-failure outcome logged: FAIL"
    docker exec "$DAEMON_CONTAINER" chmod 644 "$REG_PATH" 2>&1 || true
    exit 1
fi

post_a_rev=$(reported_revision "$DAEMON_CONTAINER")
if [ "$expected" = "$post_a_rev" ] && docker inspect --format '{{.State.Running}}' "$DAEMON_CONTAINER" | grep -q true; then
    echo "  (a) daemon alive + registry retained on read error: PASS"
else
    echo "  (a) revision changed or daemon died: FAIL"
    echo "       expected=$expected  post=$post_a_rev"
    docker exec "$DAEMON_CONTAINER" chmod 644 "$REG_PATH" 2>&1 || true
    exit 1
fi

docker exec "$DAEMON_CONTAINER" chmod 644 "$REG_PATH" 2>&1 || true

# ─── (b) mid-write garbage ──────────────────────────────────────────────
echo "  (b) mid-write garbage + SIGHUP..."
docker exec "$DAEMON_CONTAINER" sh -c '
    echo "[[params]]" > /etc/pkcs11-proxy-ng/mechanism_params.toml
    echo "this is not valid TOML !!!" >> /etc/pkcs11-proxy-ng/mechanism_params.toml
' 2>&1 || true
docker exec "$DAEMON_CONTAINER" kill -HUP 1 2>&1 || true
if ! wait_for_log_line "$DAEMON_CONTAINER" "mechanism registry reload failed" 15; then
    echo "  (b) no reload-failure outcome logged: FAIL"
    restore_registry >/dev/null
    exit 1
fi

post_b_rev=$(reported_revision "$DAEMON_CONTAINER")
if [ "$expected" = "$post_b_rev" ] && docker inspect --format '{{.State.Running}}' "$DAEMON_CONTAINER" | grep -q true; then
    echo "  (b) parse error handled, registry retained: PASS"
else
    echo "  (b) revision unexpectedly changed or daemon died: FAIL"
    echo "       expected=$expected  post=$post_b_rev"
    restore_registry >/dev/null
    exit 1
fi
restore_registry >/dev/null

# ─── (c) real ENOSPC via docker --tmpfs ─────────────────────────────────
# Spin up a SECOND daemon container with the registry path on a 64 KiB
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
# No published port: the leg signals and queries the daemon via
# `docker exec` only, so nothing pins a host port.
docker run -d --name "$TMP_DAEMON" \
    --tmpfs "$TMPFS_DIR:size=64k,mode=0755" \
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
    exec /usr/bin/pkcs11-proxy-ng /etc/proxy.toml" >/dev/null
if ! wait_for_daemon_healthy "$TMP_DAEMON" 30; then
    echo "  (c) tmpfs daemon never became healthy: FAIL"
    docker logs "$TMP_DAEMON" 2>&1 | tail -10
    docker rm -f "$TMP_DAEMON" >/dev/null 2>&1 || true
    exit 1
fi

expected_c=$(expected_revision "$TMP_DAEMON" "$TMPFS_DIR/mechanism_params.toml")
reported_c=$(reported_revision "$TMP_DAEMON")
echo "       tmpfs on-disk revision: $expected_c; daemon-served: ${reported_c:-<none>}"
if [ -z "$expected_c" ] || [ "$reported_c" != "$expected_c" ]; then
    echo "  (c) tmpfs daemon is not serving the on-disk state: FAIL"
    docker rm -f "$TMP_DAEMON" >/dev/null 2>&1 || true
    exit 1
fi

# Fill the 64 KiB tmpfs almost completely, then attempt a write that
# pushes beyond the cap so it fails with ENOSPC.
if docker exec "$TMP_DAEMON" sh -c "
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
"; then
    : # ENOSPC observed — continue to SIGHUP below.
else
    echo "  (c) tmpfs did not fill; ENOSPC was never exercised: FAIL"
    docker rm -f "$TMP_DAEMON" >/dev/null 2>&1 || true
    exit 1
fi
docker exec "$TMP_DAEMON" kill -HUP 1 2>&1 || true
if ! wait_for_log_line "$TMP_DAEMON" "mechanism registry reload failed" 15; then
    echo "  (c) no reload-failure outcome logged: FAIL"
    docker rm -f "$TMP_DAEMON" >/dev/null 2>&1 || true
    exit 1
fi

post_c_rev=$(reported_revision "$TMP_DAEMON")
if docker inspect --format '{{.State.Running}}' "$TMP_DAEMON" | grep -q true; then
    if [ "$expected_c" = "$post_c_rev" ]; then
        echo "  (c) daemon survived ENOSPC + registry retained: PASS"
    else
        echo "  (c) registry revision changed under ENOSPC: FAIL"
        echo "       expected=$expected_c  post=$post_c_rev"
        docker rm -f "$TMP_DAEMON" >/dev/null 2>&1 || true
        exit 1
    fi
else
    echo "  (c) tmpfs daemon died on SIGHUP under ENOSPC: FAIL"
    docker logs "$TMP_DAEMON" 2>&1 | tail -10
    docker rm -f "$TMP_DAEMON" >/dev/null 2>&1 || true
    exit 1
fi
docker rm -f "$TMP_DAEMON" >/dev/null 2>&1 || true

echo "scenario4: PASS"
