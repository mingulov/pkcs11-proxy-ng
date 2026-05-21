#!/bin/sh
# R8 scenario 3 — SIGSTOP daemon.
#
# Pause daemon 60s; resume. Verify shim's http2 keepalive trips,
# shim reconnects on next call (R6-9 dns-reresolve path), and
# operations resume.

set -u
. "$(dirname "$0")/_common.sh"

echo "=== R8 scenario 3: SIGSTOP daemon ==="

# Ensure daemon is up + responsive.
docker exec "$DAEMON_CONTAINER" kill -CONT 1 2>/dev/null || true
sleep 2

# (1) Baseline: list-slots works.
if runner_exec pkcs11-tool --module /usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so --list-slots >/dev/null 2>&1; then
    echo "  baseline list-slots: PASS"
else
    echo "  baseline list-slots: FAIL"
    exit 1
fi

# (2) SIGSTOP daemon (pause).
echo "  SIGSTOP daemon for 60s..."
docker exec "$DAEMON_CONTAINER" kill -STOP 1 2>&1 || true
sleep 60

# (3) SIGCONT.
echo "  SIGCONT daemon"
docker exec "$DAEMON_CONTAINER" kill -CONT 1 2>&1 || true
sleep 3

# (4) shim should reconnect — give it up to 30 s of attempts.
ok=false
for _ in 1 2 3 4 5 6; do
    if runner_exec pkcs11-tool --module /usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so --list-slots >/dev/null 2>&1; then
        ok=true
        break
    fi
    sleep 5
done

if [ "$ok" = true ]; then
    echo "  post-SIGCONT list-slots: PASS"
    echo "scenario3: PASS"
else
    echo "  post-SIGCONT list-slots: FAIL"
    echo "scenario3: FAIL"
    exit 1
fi
