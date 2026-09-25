#!/usr/bin/env bash
# Scenario 5: severe latency on the shim↔daemon link.
#
# Toxiproxy injects latency on the NETWORK path, not inside the
# daemon's FFI calls to the backend .so. True "backend-slow" coverage
# lives in the slow_backend rig (tests/r2_resilience/slow_backend/,
# driven by chaos scenario 1: backend_hang) — the rig exists, so the
# old note claiming backend-slowness was untestable is closed.
#
# What we DO exercise here:
#   - Under sustained latency exceeding every establishment budget,
#     C_Initialize fails cleanly (no hang) with exactly
#     CKR_GENERAL_ERROR: no TCP→gRPC establishment can complete while
#     each upstream packet costs LATENCY_MS (5 s connect timeout per
#     attempt; http2 keepalive 10 s/5 s trips stalled channels), and
#     the lifecycle transport mapping (ADR-0003 §3) yields
#     GENERAL_ERROR for C_Initialize — never TOKEN_NOT_PRESENT,
#     DEVICE_ERROR, or FUNCTION_CANCELED, which belong to other
#     entry-point classes.
#   - The failure lands within a derived bound (10 attempts × 5 s
#     connect timeout + backoff ≈ 30 s observed; bound 60 s).
#   - When latency clears, a subsequent C_Initialize succeeds —
#     proving the shim's retry path is properly bounded and does NOT
#     latch a permanent failure state.

set -euo pipefail
. "$(dirname "$0")/_common.sh"

LATENCY_MS="${LATENCY_MS:-15000}"

wait_for_toxiproxy
clear_toxics
ensure_test_key

echo "scenario5: injecting ${LATENCY_MS}ms latency upstream"
add_toxic "{
    \"name\": \"slow_backend\",
    \"type\": \"latency\",
    \"stream\": \"upstream\",
    \"attributes\": { \"latency\": ${LATENCY_MS}, \"jitter\": 0 }
}"

set +e
start_ms=$(now_ms)
shim_sign_once
rc=$?
end_ms=$(now_ms)
elapsed_ms=$(( end_ms - start_ms ))
set -e

clear_toxics

if [[ $rc -eq 0 ]]; then
    echo "fail: scenario5 — sign unexpectedly succeeded under ${LATENCY_MS}ms latency" >&2
    exit 1
fi

# The shim's connect_with_retry caps at MAX_ATTEMPTS (10 by default),
# each attempt bounded by PKCS11_PROXY_CONNECT_TIMEOUT (5s), plus
# capped exponential backoff: ~30 s observed wall time. 60 s bounds
# the regime with CI slack while proving the shim never hangs.
max_ms=60000
if [[ $elapsed_ms -gt $max_ms ]]; then
    echo "fail: scenario5 — shim hung for ${elapsed_ms}ms (max expected ${max_ms}ms)" >&2
    exit 1
fi

# Exactly one RV is possible here: C_Initialize is the first call the
# shim issues, it cannot establish under sustained 15 s latency, and
# the Lifecycle transport class maps every such failure to
# CKR_GENERAL_ERROR (client/error.rs). Any other RV — or none —
# means the failure surfaced somewhere unexpected.
if log_mentions_ckr CKR_GENERAL_ERROR; then
    : # expected
else
    echo "fail: scenario5 — sign failed without the expected CKR_GENERAL_ERROR" >&2
    cat "$SHIM_SIGN_LOG" >&2
    exit 1
fi

# Sanity: a follow-up sign with no latency must succeed — the shim's
# retry path must NOT latch a permanent failure.
if shim_sign_once; then
    echo "pass: scenario5 — latency injection produced clean error semantics (elapsed ${elapsed_ms}ms), recovery works"
    exit 0
fi
echo "fail: scenario5 — post-latency recovery sign failed" >&2
cat "$SHIM_SIGN_LOG" >&2
exit 1
