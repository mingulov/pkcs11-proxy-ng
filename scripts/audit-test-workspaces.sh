#!/usr/bin/env bash
# W1-L16-14: run cargo audit + cargo deny over the standalone test
# workspaces (each carries its own Cargo.lock outside the root
# workspace, so the root `cargo audit` / `cargo deny check` never see
# them). Called by the CI audit/deny jobs and test-matrix.sh fast
# checks; safe to run locally.
#
# Usage: scripts/audit-test-workspaces.sh [audit|deny|all]   (default: all)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-all}"

case "$MODE" in
    audit|deny|all) ;;
    -h|--help)
        echo "Usage: scripts/audit-test-workspaces.sh [audit|deny|all]"
        exit 0
        ;;
    *)
        echo "Unknown mode: $MODE (want audit|deny|all)" >&2
        exit 1
        ;;
esac

# The four standalone test workspaces (each has [workspace] + own lock).
WORKSPACES=(
    tests/chaos/cert_minter
    tests/r2_resilience/slow_backend
    tests/ffi_oracles/exact_outputs
    tests/ffi_oracles/retained_mechanisms
)

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Required command not found: $1" >&2
        exit 1
    fi
}

[[ "$MODE" == "deny" ]] || require_cmd cargo-audit
[[ "$MODE" == "audit" ]] || require_cmd cargo-deny

fail=0
for ws in "${WORKSPACES[@]}"; do
    if [[ ! -f "$ROOT_DIR/$ws/Cargo.toml" ]]; then
        echo "Missing workspace manifest: $ws/Cargo.toml" >&2
        fail=1
        continue
    fi
    if [[ "$MODE" != "deny" ]]; then
        echo "==> cargo audit ($ws)"
        (cd "$ROOT_DIR/$ws" && cargo audit) || fail=1
    fi
    if [[ "$MODE" != "audit" ]]; then
        echo "==> cargo deny check ($ws)"
        # deny-wrapped: the standalone graph is checked against the
        # root policy file (licenses/bans/sources/advisories).
        cargo deny \
            --manifest-path "$ROOT_DIR/$ws/Cargo.toml" \
            --config "$ROOT_DIR/deny.toml" \
            check || fail=1
    fi
done

exit "$fail"
