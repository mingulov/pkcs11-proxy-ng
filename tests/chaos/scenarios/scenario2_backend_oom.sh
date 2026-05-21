#!/bin/sh
# R8 scenario 2 — backend OOM (CKR_HOST_MEMORY).
#
# The slow_backend stub currently doesn't have a CKR_HOST_MEMORY mode.
# This scenario is structured but defers the actual fault injection
# until the slow_backend gains an SLOW_BACKEND_RETURN_RV env var (or
# similar) to control the CK_RV returned from C_Sign.
#
# Pass criteria (when implemented):
#   - N consecutive sign attempts return CKR_HOST_MEMORY/CKR_DEVICE_ERROR
#   - daemon's tonic-health flips to NOT_SERVING after
#     backend_health_consecutive_failures (default 2 in chaos config)
#   - daemon stays alive; future calls succeed once the fault is dropped

set -u
. "$(dirname "$0")/_common.sh"

echo "=== R8 scenario 2: backend OOM (DEFERRED) ==="
echo "  slow_backend currently returns CKR_OK from C_Sign; needs a"
echo "  SLOW_BACKEND_RETURN_RV env-var to inject CKR_HOST_MEMORY."
echo "  Tracked as R8-FOLLOWUP-slow-backend-rv-injection."
echo "scenario2: DEFER (slow_backend feature missing)"
exit 0
