#!/usr/bin/env bash
# Scenario 3: Daemon restart BEYOND lease_seconds, observed through ONE
# held C_Initialize.
#
# A background CLI signer initializes NOW, then blocks reading its PIN
# from a fifo — the CLI resolves --pin-stdin strictly after its
# C_Initialize RPC, so the blocked wait holds exactly one
# client_context_id open across the outage. The daemon then stops for
# longer than lease_seconds and restarts. Once it is back, the PIN is
# released and the held signer proceeds with its STALE context: its
# first post-restart RPC must fail with CKR_CRYPTOKI_NOT_INITIALIZED
# (0x190), proving the daemon forgot the expired context instead of
# resurrecting it. A fresh pkcs11-tool sign afterwards must succeed,
# proving C_Finalize + C_Initialize recovers.

set -euo pipefail
. "$(dirname "$0")/_common.sh"

DAEMON_CONTAINER="${DAEMON_CONTAINER:-r2-daemon}"
LEASE_S="${LEASE_S:-30}"
WAIT_S=$(( LEASE_S + 5 ))
INIT_SETTLE_S="${INIT_SETTLE_S:-5}"

wait_for_toxiproxy
clear_toxics
ensure_test_key

# Baseline sign (proves the path works pre-restart).
shim_sign_once || { echo "fail: scenario3 — pre-restart sign failed" >&2; exit 1; }

# Discover the virtual slot id (1-based; single-token fixture ⇒ 1).
SLOT_ID="${SLOT_ID:-}"
if [[ -z "$SLOT_ID" ]]; then
    SLOT_ID=$(pkcs11-proxy-ng-cli --endpoint "$PKCS11_PROXY_ENDPOINT" \
        list-slots --token-present 2>/dev/null | awk '/^Slot /{print $2; exit}') || true
fi
if [[ -z "$SLOT_ID" ]]; then
    echo "fail: scenario3 — could not discover a slot id" >&2
    exit 1
fi
echo "scenario3: using slot $SLOT_ID, key label r2-key"

WORK=$(mktemp -d /tmp/scenario3.XXXXXX)
PIN_FIFO="$WORK/pin.fifo"
mkfifo "$PIN_FIFO"
printf 'deadbeef' > "$WORK/input.hex"
HELD_PID=""
cleanup() {
    if [[ -n "$HELD_PID" ]] && kill -0 "$HELD_PID" 2>/dev/null; then
        kill "$HELD_PID" 2>/dev/null || true
    fi
    exec 9>&- 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# Start the held signer: C_Initialize runs immediately, then the CLI
# blocks reading --pin-stdin (no EOF while our write end stays open).
pkcs11-proxy-ng-cli --endpoint "$PKCS11_PROXY_ENDPOINT" sign \
    --slot-id "$SLOT_ID" --pin-stdin \
    --key-label r2-key --mechanism SHA256_RSA_PKCS \
    --input-file "$WORK/input.hex" \
    <"$PIN_FIFO" >"$WORK/held.log" 2>&1 &
HELD_PID=$!
# Open the write end (lets the CLI start) and hold it: no data, no EOF.
exec 9>"$PIN_FIFO"

# Bounded settle so the held C_Initialize lands before the outage. A
# slow box can only fail this scenario loudly (step below), never
# pass it: an uninitialized holder would recover trivially and miss
# the stale-context assertion.
sleep "$INIT_SETTLE_S"
if ! kill -0 "$HELD_PID" 2>/dev/null; then
    echo "fail: scenario3 — held signer exited before the restart (init failed?)" >&2
    cat "$WORK/held.log" >&2
    exit 1
fi

echo "scenario3: stopping daemon for ${WAIT_S}s (longer than lease ${LEASE_S}s)"
docker stop -t 2 "$DAEMON_CONTAINER" >/dev/null
sleep "$WAIT_S"
docker start "$DAEMON_CONTAINER" >/dev/null

# Wait for daemon to be reachable again.
for _ in $(seq 1 30); do
    if pkcs11-proxy-ng-cli --endpoint "$PKCS11_PROXY_ENDPOINT" \
            list-slots >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

# Release the PIN: the held signer proceeds with its stale context.
echo "scenario3: releasing held signer against restarted daemon"
printf '1234\n' >&9
exec 9>&-
held_rc=0
wait "$HELD_PID" || held_rc=$?
HELD_PID=""

if [[ $held_rc -eq 0 ]]; then
    echo "fail: scenario3 — held signer unexpectedly succeeded with a stale context" >&2
    exit 1
fi
if grep -qE "CRYPTOKI_NOT_INITIALIZED|0x00000190" "$WORK/held.log"; then
    echo "scenario3: stale context rejected with CKR_CRYPTOKI_NOT_INITIALIZED: PASS"
else
    echo "fail: scenario3 — held signer failed without the stale-context RV" >&2
    cat "$WORK/held.log" >&2
    exit 1
fi

# Fresh C_Initialize must recover.
if shim_sign_once; then
    echo "pass: scenario3 — stale context rejected, fresh C_Initialize recovered"
    exit 0
fi
echo "fail: scenario3 — recovery flow did not succeed" >&2
cat "$SHIM_SIGN_LOG" >&2
exit 1
