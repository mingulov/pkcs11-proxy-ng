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
# Both are out of scope for the local toxiproxy
# rig. The script below records the deferral so `run_scenario.sh 4`
# reports a clean "skip" rather than a silent pass.

set -euo pipefail
. "$(dirname "$0")/_common.sh"

cat <<EOF
skip: scenario4 — Docker's embedded DNS doesn't support A-record
mutation at runtime; deferred (CoreDNS sidecar or
k8s Service. See the FOLLOWUP tags
in crates/shim/src/state.rs / crates/client/src/client/lifecycle.rs.
EOF
exit 0
