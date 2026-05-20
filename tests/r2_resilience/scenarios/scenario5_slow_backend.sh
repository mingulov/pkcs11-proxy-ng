#!/usr/bin/env bash
# Scenario 5: severe latency on the shim↔daemon link.
#
# Originally specified as "slow backend" but toxiproxy can only inject
# latency on the network path, not inside the daemon's FFI calls to
# the backend .so. A true "backend-slow" test requires a mock backend
# module that intentionally sleeps in C_Sign — tracked as
# R2-FOLLOWUP-slow-backend.
#
# What we DO exercise here:
#   - Under sustained latency exceeding the shim's connect timeout,
#     C_Initialize fails cleanly (no hang) within the bounded
#     backoff window.
#   - Per ADR-0003 §3, a non-session-scoped RPC failure under
#     `Code::Unavailable` surfaces as CKR_TOKEN_NOT_PRESENT.
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
start=$(date +%s)
shim_sign_once
rc=$?
elapsed=$(( $(date +%s) - start ))
set -e

clear_toxics

if [[ $rc -eq 0 ]]; then
    echo "fail: scenario5 — sign unexpectedly succeeded under ${LATENCY_MS}ms latency" >&2
    exit 1
fi

# The shim's connect_with_retry caps at MAX_ATTEMPTS (10 by default),
# each attempt bounded by PKCS11_PROXY_CONNECT_TIMEOUT (5s). Total
# wall time is < 60s even under pathological latency.
max_seconds=60
if [[ $elapsed -gt $max_seconds ]]; then
    echo "fail: scenario5 — shim hung for ${elapsed}s (max expected ${max_seconds}s)" >&2
    exit 1
fi

# Per PKCS#11 v3.0 §5.4 the C_Initialize permitted-returns set does
# NOT include CKR_TOKEN_NOT_PRESENT or CKR_DEVICE_ERROR. The shim now
# maps a transport-Unavailable on C_Initialize to CKR_GENERAL_ERROR,
# and DeadlineExceeded / unknown-code to CKR_FUNCTION_FAILED. Accept
# either, plus the pre-existing DEVICE_ERROR / TOKEN_NOT_PRESENT for
# the rare case the failure surfaces at a slot/session RPC instead.
if log_mentions_ckr CKR_GENERAL_ERROR \
    || log_mentions_ckr CKR_FUNCTION_FAILED \
    || log_mentions_ckr CKR_TOKEN_NOT_PRESENT \
    || log_mentions_ckr CKR_DEVICE_ERROR \
    || log_mentions_ckr CKR_FUNCTION_CANCELED ; then
    : # expected
else
    echo "fail: scenario5 — sign failed with unexpected CK_RV" >&2
    cat /tmp/shim_sign.log >&2
    exit 1
fi

# Sanity: a follow-up sign with no latency must succeed — the shim's
# retry path must NOT latch a permanent failure.
if shim_sign_once; then
    echo "pass: scenario5 — latency injection produced clean error semantics (elapsed ${elapsed}s), recovery works"
    exit 0
fi
echo "fail: scenario5 — post-latency recovery sign failed" >&2
cat /tmp/shim_sign.log >&2
exit 1
