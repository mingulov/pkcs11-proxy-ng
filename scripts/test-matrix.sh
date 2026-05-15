#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

run_fast_checks=1
run_consumers=1
run_optional_providers=1
collect_bundle_on_fail=1
fast_only=0

usage() {
    cat <<'EOF'
Usage: scripts/test-matrix.sh [options]

Options:
  --fast-only                 Run only CI Tier 0 fmt/audit/build/test/clippy checks
  --skip-fast                 Skip fmt/audit/build/test/clippy
  --skip-consumers            Skip external consumer smoke tests
  --skip-optional-providers   Skip optional NSS/Kryoptic suites
  --no-debug-bundle           Don't collect debug bundle on failure
  -h, --help                  Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fast-only)
            fast_only=1
            run_consumers=0
            run_optional_providers=0
            ;;
        --skip-fast)
            run_fast_checks=0
            ;;
        --skip-consumers)
            run_consumers=0
            ;;
        --skip-optional-providers)
            run_optional_providers=0
            ;;
        --no-debug-bundle)
            collect_bundle_on_fail=0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

if [[ "$fast_only" -eq 1 && "$run_fast_checks" -eq 0 ]]; then
    echo "--fast-only cannot be combined with --skip-fast" >&2
    usage >&2
    exit 1
fi

cd "$ROOT_DIR"

# Capture logs for debug bundles
LOG_DIR="$(mktemp -d)"
trap 'rm -rf "$LOG_DIR"' EXIT

# Run a step, capturing output. On failure, collect debug bundle.
run_step() {
    local label="$1"
    shift
    local logfile="$LOG_DIR/${label// /-}.log"
    echo "==> $label"
    if "$@" 2>&1 | tee "$logfile"; then
        return 0
    else
        local rc=$?
        echo "FAILED: $label (exit $rc)" >&2
        if [[ "$collect_bundle_on_fail" -eq 1 ]]; then
            echo "Collecting debug bundle..." >&2
            "$ROOT_DIR/scripts/collect-debug-bundle.sh" --include-logs "$LOG_DIR" || true
        fi
        return $rc
    fi
}

if [[ "$run_fast_checks" -eq 1 ]]; then
    run_step "cargo fmt check" cargo fmt --all -- --check
    run_step "cargo audit" cargo audit
    run_step "cargo build" cargo build --workspace
    run_step "cargo test" cargo test --workspace
    run_step "cargo clippy" cargo clippy --workspace --all-targets --all-features -- -D warnings
fi

if [[ "$fast_only" -eq 1 ]]; then
    exit 0
fi

run_step "concurrency tests" \
    cargo test -p pkcs11-proxy-ng --test concurrency_and_recovery_test -- --ignored --test-threads=1

if [[ "$run_optional_providers" -eq 1 ]]; then
    run_step "provider backends" "$ROOT_DIR/scripts/test-provider-backends.sh"
    # NSS fixture modes are covered by nss_mechanism_coverage_test above.
    # The dedicated fixture script hangs in Docker (cargo recompilation issue).
    # Run it only when explicitly requested via --run-nss-fixtures.
    if [[ "${RUN_NSS_FIXTURES:-0}" == "1" ]]; then
        run_step "NSS fixture modes" timeout 180 "$ROOT_DIR/scripts/test-nss-fixtures.sh"
    else
        echo "  [skip] NSS fixture modes (set RUN_NSS_FIXTURES=1 to enable)"
    fi
else
    run_step "integration tests" \
        cargo test -p pkcs11-proxy-ng --test integration_test -- --ignored --test-threads=1
fi

if [[ "$run_consumers" -eq 1 ]]; then
    run_step "consumer tests" "$ROOT_DIR/scripts/test-consumers.sh"
    run_step "shim parameterized" "$ROOT_DIR/scripts/test-shim-parameterized.sh"
fi
