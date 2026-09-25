#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

run_fast_checks=1
run_consumers=1
run_optional_providers=1
run_nss_fixtures=1
collect_bundle_on_fail=1
fast_only=0

usage() {
    cat <<'EOF'
Usage: scripts/test-matrix.sh [options]

Options:
  --fast-only                 Run only CI Tier 0 fmt/audit/deny/build/test/clippy checks
  --skip-fast                 Skip fmt/audit/deny/build/test/clippy
  --skip-consumers            Skip external consumer smoke tests
  --skip-optional-providers   Skip optional NSS/Kryoptic suites
  --skip-nss-fixtures         Skip the NSS fixture-mode lane
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
        --skip-nss-fixtures)
            run_nss_fixtures=0
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

# Capture logs for local test output. Diagnostic bundles intentionally do not
# ingest arbitrary logs; review and attach these separately when appropriate.
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
            "$ROOT_DIR/scripts/collect-debug-bundle.sh" || true
        fi
        return $rc
    fi
}

if [[ "$run_fast_checks" -eq 1 ]]; then
    run_step "cargo fmt check" cargo fmt --all -- --check
    run_step "cargo audit" cargo audit
    run_step "cargo deny check" cargo deny check
    run_step "standalone audit+deny" "$ROOT_DIR/scripts/audit-test-workspaces.sh"
    run_step "cargo build" cargo build --workspace --locked
    run_step "cargo test" cargo test --workspace --locked
    run_step "cargo clippy" cargo clippy --workspace --locked --all-targets --all-features -- -D warnings
    run_step "packaging smoke" "$ROOT_DIR/scripts/packaging-smoke.sh"
fi

if [[ "$fast_only" -eq 1 ]]; then
    exit 0
fi

run_step "concurrency tests" \
    cargo test --locked -p pkcs11-proxy-ng --test concurrency_and_recovery_test -- --ignored --test-threads=1

if [[ "$run_optional_providers" -eq 1 ]]; then
    run_step "provider backends" "$ROOT_DIR/scripts/test-provider-backends.sh"
    # W1-L17-11: the NSS fixture lane runs by default. Its old hang was
    # certutil -S spinning on an infinite -z /dev/urandom noise file (NSS
    # reads to EOF); the fixture script now seeds from a finite noise
    # file. The lane stays bounded by timeout 180 and exits 0 when NSS is
    # absent. Opt out with the real --skip-nss-fixtures flag (no env-var gate).
    if [[ "$run_nss_fixtures" -eq 1 ]]; then
        run_step "NSS fixture modes" timeout 180 "$ROOT_DIR/scripts/test-nss-fixtures.sh"
    else
        echo "  [skip] NSS fixture modes (--skip-nss-fixtures)"
    fi
else
    run_step "integration tests" \
        cargo test --locked -p pkcs11-proxy-ng --test integration_test -- --ignored --test-threads=1
fi

if [[ "$run_consumers" -eq 1 ]]; then
    run_step "consumer tests" "$ROOT_DIR/scripts/test-consumers.sh"
    run_step "shim parameterized" "$ROOT_DIR/scripts/test-shim-parameterized.sh"
fi
