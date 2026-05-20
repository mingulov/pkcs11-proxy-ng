#!/usr/bin/env bash
# Run the R5 consumer × backend matrix. Per cell:
#   1. Bring up the matching `daemon-<backend>` profile.
#   2. exec the relevant test script(s) inside the appropriate
#      consumer container.
#   3. Capture PASS/FAIL into results.txt.
#
# Usage:
#   tests/consumers/run_matrix.sh [results-file]
#
# Defaults to writing to tests/consumers/results.txt.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="docker compose -f $SCRIPT_DIR/docker-compose.yml"
RESULTS="${1:-$SCRIPT_DIR/results.txt}"

# Backend → consumer-shell TOKEN_LABEL/PIN overrides.
# NSS softokn exposes its own slot labels; others use r5-token.
backend_env() {
    case "$1" in
        nss)
            echo 'TOKEN_LABEL=NSS Certificate DB' ;;
        *) ;;
    esac
}

# Tests per consumer type.
shell_tests=(test_pkcs11tool.sh test_p11tool.sh test_openssl_engine.sh test_openssl_provider.sh)
go_tests=(harness_miekg harness_crypto11)
java_tests=(test_java.sh)

run_cell() {
    local backend="$1" consumer="$2" testname="$3"
    local env_pairs=$(backend_env "$backend")
    local cmd
    if [[ "$consumer" == consumer-go ]]; then
        cmd="$testname"
    else
        cmd="/scripts/$testname"
    fi
    local env_args=""
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        env_args+=" -e $line"
    done <<< "$env_pairs"

    if eval "$COMPOSE exec -T $env_args $consumer $cmd $backend" >/tmp/cell.log 2>&1; then
        echo "PASS  $testname / $backend"
        echo "PASS  $testname / $backend" >> "$RESULTS"
    else
        echo "FAIL  $testname / $backend"
        echo "FAIL  $testname / $backend" >> "$RESULTS"
        echo "      $(tail -1 /tmp/cell.log)" >> "$RESULTS"
    fi
}

: > "$RESULTS"
echo "R5 consumer-matrix run started $(date -u +'%Y-%m-%dT%H:%M:%SZ')" >> "$RESULTS"
echo "" >> "$RESULTS"

backends=(softhsm2 nss p11kit kryoptic softhsm2-patched)

for backend in "${backends[@]}"; do
    echo "=== Backend: $backend ==="
    # Tear down previous daemon (if any).
    docker rm -f r5-daemon >/dev/null 2>&1 || true
    # Bring up the relevant daemon.
    $COMPOSE --profile "$backend" up -d "daemon-$backend" >/dev/null
    $COMPOSE --profile "$backend" up -d consumer-shell consumer-go consumer-java >/dev/null
    sleep 5  # daemon warmup

    for t in "${shell_tests[@]}"; do
        run_cell "$backend" consumer-shell "$t"
    done
    for t in "${go_tests[@]}"; do
        run_cell "$backend" consumer-go "$t"
    done
    for t in "${java_tests[@]}"; do
        run_cell "$backend" consumer-java "$t"
    done
    echo "" >> "$RESULTS"
done

# Vendor extension flow (only valid against patched-softhsm2).
echo "=== Vendor extension flow ==="
$COMPOSE --profile softhsm2-patched up -d daemon-softhsm2-patched consumer-shell consumer-go >/dev/null
sleep 5
for mode in visibility end_to_end; do
    if $COMPOSE exec -T consumer-shell /scripts/test_vendor_extension.sh "$mode" softhsm2-patched >/tmp/cell.log 2>&1; then
        echo "PASS  vendor-ext-$mode / softhsm2-patched" | tee -a "$RESULTS"
    else
        echo "FAIL  vendor-ext-$mode / softhsm2-patched" | tee -a "$RESULTS"
    fi
done
if $COMPOSE exec -T consumer-go harness_vendor >/tmp/cell.log 2>&1; then
    echo "PASS  harness_vendor / softhsm2-patched" | tee -a "$RESULTS"
else
    echo "FAIL  harness_vendor / softhsm2-patched" | tee -a "$RESULTS"
fi

echo ""
echo "Done. See $RESULTS"
