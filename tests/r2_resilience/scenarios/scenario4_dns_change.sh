#!/usr/bin/env bash
# Scenario 4: DNS A-record change mid-session.
#
# This scenario is DEFERRED in the local runner because Docker's
# embedded DNS does not support runtime A-record mutation. Faithfully
# reproducing it requires either:
#   - a dedicated CoreDNS sidecar with hot-reload config, OR
#   - swapping the daemon container behind a stable hostname via a
#     k8s Service rollout.
#
# Both are within scope of R6 / R12 but outside the local toxiproxy
# rig. The script below records the deferral so `run_scenario.sh 4`
# reports a clean "skip" rather than a silent pass.

set -euo pipefail
. "$(dirname "$0")/_common.sh"

cat <<EOF
skip: scenario4 — Docker's embedded DNS doesn't support A-record
mutation at runtime; deferred to R6/R12 with a CoreDNS sidecar or
k8s Service. See doc/audit/r2-resilience.md and the R2-FOLLOWUP tags
in crates/shim/src/state.rs / crates/client/src/client/lifecycle.rs.
EOF
exit 0
