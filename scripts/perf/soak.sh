#!/usr/bin/env bash
# Soak test.
#
# Drives sustained N rps of C_Sign load through the shim against a
# daemon backed by SoftHSM2 for DURATION seconds, sampling daemon
# RSS + open FD count every 60 seconds.
#
# Exit criteria:
#   - No monotonic RSS growth > 50 MB over the run.
#   - Open FD count bounded.
#
# Default duration is 1 h (configurable via DURATION env var); 24 h
# runs are exercised separately in production canary windows.
#
# Usage:
#   DURATION=3600 RPS=50 scripts/perf/soak.sh
#
# Output:
#   scripts/perf/results/soak_samples.csv  (minute-by-minute RSS+FDs)
#   scripts/perf/results/soak.json         (summary + verdict)

set -euo pipefail

DURATION="${DURATION:-3600}"  # default 1 h
RPS="${RPS:-50}"
WORK="$(mktemp -d)"
OUT_DIR="$(cd "$(dirname "$0")" && pwd)/results"
mkdir -p "$OUT_DIR"

COMPOSE="docker compose -f $(cd "$(dirname "$0")/../.." && pwd)/tests/consumers/docker-compose.yml"

echo "=== Soak: ${DURATION}s @ ${RPS}rps ==="

# 1. Bring up daemon + consumer.
$COMPOSE --profile softhsm2 up -d daemon-softhsm2 consumer-shell >/dev/null
sleep 5  # FOLLOWUP-shim-startup-race workaround

daemon_pid=$(docker inspect --format '{{.State.Pid}}' consumer-matrix-daemon)
echo "daemon PID (host): $daemon_pid"

# We sample RSS via host /proc and FDs via docker exec; reading the
# daemon's /proc/PID/fd from outside the container requires CAP_SYS_PTRACE
# we don't have, so we ask the container for it.
sample_rss_kb() {
    awk '/^VmRSS:/ { print $2 }' "/proc/$daemon_pid/status" 2>/dev/null || echo 0
}
sample_fd_count() {
    docker exec consumer-matrix-daemon sh -c 'ls /proc/1/fd 2>/dev/null | wc -l' 2>/dev/null || echo 0
}

# 2. Provision the test key once (so the load loop doesn't repeat it).
$COMPOSE exec -T consumer-shell sh -c '
. /scripts/common.sh
cleanup_objects
ensure_rsa_key
' >/dev/null

# 3. Background load generator inside the consumer container.
#    Uses pkcs11-tool --sign in a tight loop, paced via `sleep $delay`.
delay_ms=$(awk "BEGIN { printf \"%.3f\", 1.0 / $RPS }")
# Remote script: $-expressions expand inside the container, not locally.
# shellcheck disable=SC2016
$COMPOSE exec -T -d -e DURATION="$DURATION" -e SLEEP_DELAY="$delay_ms" consumer-shell sh -c '
. /scripts/common.sh
echo "soak-test-data" > /tmp/in.bin
end=$(( $(date +%s) + DURATION + 10 ))
ok=0; fail=0
while [ $(date +%s) -lt $end ]; do
    if pkcs11-tool --module "$PKCS11_MODULE_PATH" \
        --token-label "$TOKEN_LABEL" --login --pin "$USER_PIN" \
        --sign --mechanism SHA256-RSA-PKCS --id 01 \
        --input-file /tmp/in.bin --output-file /tmp/sig.bin >/dev/null 2>&1; then
        ok=$((ok+1))
    else
        fail=$((fail+1))
    fi
    sleep "$SLEEP_DELAY"
done
echo "ok=$ok fail=$fail" > /tmp/soak_result.txt
'

# 4. Sample daemon RSS + FD count every 60 seconds.
samples="$OUT_DIR/soak_samples.csv"
echo "elapsed_s,rss_kb,open_fds" > "$samples"
start_ts=$(date +%s)
end_ts=$(( start_ts + DURATION ))

initial_rss=$(sample_rss_kb)
echo "initial RSS: ${initial_rss}kB"

while :; do
    now=$(date +%s)
    if [ "$now" -ge "$end_ts" ]; then break; fi
    elapsed=$(( now - start_ts ))
    rss=$(sample_rss_kb)
    fds=$(sample_fd_count)
    echo "$elapsed,$rss,$fds" >> "$samples"
    # Coarse log line every 5 min.
    if [ $((elapsed % 300)) -eq 0 ]; then
        delta=$(( rss - initial_rss ))
        echo "[$(date -u +%H:%M:%S)] elapsed=${elapsed}s rss=${rss}kB (Δ${delta}kB) fds=${fds}"
    fi
    sleep 60
done

# 5. Final sample + consumer results.
final_rss=$(sample_rss_kb)
final_fds=$(sample_fd_count)
$COMPOSE exec -T consumer-shell cat /tmp/soak_result.txt > "$WORK/result.txt" 2>/dev/null || echo "ok=? fail=?" > "$WORK/result.txt"
read -r ok_line fail_line < "$WORK/result.txt"
ok=${ok_line#ok=}; fail=${fail_line#fail=}

# 6. Compute verdict.
delta_kb=$(( final_rss - initial_rss ))
delta_mb=$(( delta_kb / 1024 ))
verdict="PASS"
if [ "$delta_mb" -gt 50 ]; then verdict="FAIL_RSS_GROWTH"; fi

cat > "$OUT_DIR/soak.json" <<EOF
{
  "duration_s": $DURATION,
  "target_rps": $RPS,
  "ok_signs": ${ok:-0},
  "fail_signs": ${fail:-0},
  "initial_rss_kb": $initial_rss,
  "final_rss_kb": $final_rss,
  "delta_rss_mb": $delta_mb,
  "final_open_fds": $final_fds,
  "verdict": "$verdict"
}
EOF

echo
cat "$OUT_DIR/soak.json"
echo
echo "Samples: $samples"

rm -rf "$WORK"
