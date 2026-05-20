#!/usr/bin/env bash
# R6 — cold-start storm.
#
# Spawn N fresh shim processes simultaneously, all of which call
# C_Initialize against the same daemon over loopback. Captures:
#   - per-process wall-time
#   - per-process exit status
#   - daemon CPU + RSS peak during the storm (sampled at 100 ms)
#
# Exit criterion (R6): every process completes within
# `proxy.request_timeout_secs` (default 60), reporting CKR_OK.
#
# Usage:
#   tests/r2_resilience must have been built so the daemon image
#   exists. Then:
#     scripts/perf/cold_start_storm.sh [N=100]
#
# Output:
#   scripts/perf/results/cold_start.csv  (one row per shim)
#   scripts/perf/results/cold_start.json (summary)

set -euo pipefail

N="${1:-100}"
WORK="$(mktemp -d)"
OUT_DIR="$(cd "$(dirname "$0")" && pwd)/results"
mkdir -p "$OUT_DIR"

# Use the consumers fixture daemon (Alpine, softhsm2 backend).
COMPOSE="docker compose -f $(cd "$(dirname "$0")/../.." && pwd)/tests/consumers/docker-compose.yml"

echo "=== R6 cold-start storm: $N shims ==="

# 1. Bring up daemon-softhsm2 + a single consumer-shell container we
#    can exec into to spawn shim processes.
$COMPOSE --profile softhsm2 up -d daemon-softhsm2 consumer-shell >/dev/null
sleep 5  # workaround for R5-FOLLOWUP-shim-startup-race; remove when fixed.

# 2. Find the daemon's PID (inside the container) for CPU+RSS sampling.
daemon_pid=$(docker inspect --format '{{.State.Pid}}' r5-daemon)
echo "daemon PID (host): $daemon_pid"

# 3. Sample daemon RSS + CPU during the storm.
samples="$WORK/samples.csv"
echo "ts_us,rss_kb,cpu_pct" > "$samples"
(
    while sleep 0.1; do
        ts=$(date +%s%6N)
        rss=$(awk '/^VmRSS:/ { print $2 }' "/proc/$daemon_pid/status" 2>/dev/null || echo 0)
        cpu=$(top -b -n 1 -p "$daemon_pid" 2>/dev/null \
                | awk -v pid="$daemon_pid" '$1==pid { print $9 }' || echo 0)
        echo "$ts,$rss,$cpu" >> "$samples"
        [ -f "$WORK/stop" ] && break
    done
) &
SAMPLER=$!

# 4. Spawn N shim processes in the consumer-shell container,
#    capturing each one's wall-time + exit code.
results="$OUT_DIR/cold_start.csv"
echo "idx,wall_us,exit_code" > "$results"

# Build a small shell function inside the container that just opens
# a session and exits — the cheapest "did C_Initialize succeed" probe.
$COMPOSE exec -T consumer-shell sh -c "cat > /tmp/spawn_one.sh <<'EOF'
#!/bin/sh
# Exits 0 iff C_Initialize + C_GetSlotList succeed. We use
# pkcs11-tool --list-slots; the binary does Initialize + GetSlotList
# + Finalize.
exec pkcs11-tool --module /usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so --list-slots
EOF
chmod +x /tmp/spawn_one.sh"

storm_start=$(date +%s%6N)
{
    for i in $(seq 1 "$N"); do
        (
            t0=$(date +%s%6N)
            if $COMPOSE exec -T consumer-shell sh /tmp/spawn_one.sh >/dev/null 2>&1; then
                ec=0
            else
                ec=$?
            fi
            t1=$(date +%s%6N)
            echo "$i,$((t1-t0)),$ec"
        ) &
    done
    wait
} >> "$results"
storm_end=$(date +%s%6N)
storm_elapsed_ms=$(( (storm_end - storm_start) / 1000 ))

# 5. Stop sampling.
touch "$WORK/stop"
wait "$SAMPLER" 2>/dev/null || true
mv "$samples" "$OUT_DIR/cold_start_daemon_samples.csv"

# 6. Compute summary.
total_ok=$(awk -F, '$3 == 0 {c++} END {print c+0}' "$results")
total_fail=$(awk -F, '$3 != 0 && NR>1 {c++} END {print c+0}' "$results")
max_wall_ms=$(awk -F, 'NR>1 {if ($2 > m) m=$2} END {printf "%.0f\n", m/1000}' "$results")
p99_wall_ms=$(awk -F, 'NR>1 {a[NR-1]=$2} END {
    n = NR-1
    asort(a)
    if (n > 0) printf "%.0f\n", a[int(n*0.99)]/1000
    else print 0
}' "$results")
peak_rss_kb=$(awk -F, 'NR>1 {if ($2 > p) p=$2} END {print p+0}' "$OUT_DIR/cold_start_daemon_samples.csv")
peak_cpu_pct=$(awk -F, 'NR>1 {if ($3 > p) p=$3} END {print p+0}' "$OUT_DIR/cold_start_daemon_samples.csv")

cat > "$OUT_DIR/cold_start.json" <<EOF
{
  "n": $N,
  "ok": $total_ok,
  "fail": $total_fail,
  "storm_elapsed_ms": $storm_elapsed_ms,
  "max_wall_ms": $max_wall_ms,
  "p99_wall_ms": $p99_wall_ms,
  "peak_rss_kb": $peak_rss_kb,
  "peak_cpu_pct": $peak_cpu_pct
}
EOF

echo
cat "$OUT_DIR/cold_start.json"
echo
echo "Per-process timings: $results"
echo "Daemon samples:      $OUT_DIR/cold_start_daemon_samples.csv"
echo "Summary:             $OUT_DIR/cold_start.json"

rm -rf "$WORK"
