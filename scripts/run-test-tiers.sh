#!/usr/bin/env bash
# Tiered test runner (mock-ABI test infrastructure design, 2026-07-02).
#
# Tiers (module/naming convention — no cargo features):
#   unit         pure logic: types + backend libs, shim dispatch units
#   integration  in-process TestDaemon suites (shim tests::), incl. the
#                cross-ABI topology suite (tests::cross_abi)
#   regression   named defect pins: tests::regression plus the canonical
#                defect tests matched by name (*_not_wild_read,
#                *_wider_than_native_*, cross_abi)
#   live         env-gated real-binary harnesses (daemons + SoftHSM2 /
#                wine); each script skips cleanly when its tooling is
#                absent
#   all          unit + integration + regression (the plain-CI surface)
#
# Plain `cargo test --workspace` runs everything except `live`.
set -euo pipefail

cd "$(dirname "$0")/.."

tier="${1:-all}"

run_unit() {
    echo "=== tier: unit ==="
    cargo test -p pkcs11-proxy-ng-types
    cargo test -p pkcs11-proxy-ng-backend --lib
    cargo test -p pkcs11-proxy-ng --lib
    cargo test -p pkcs11-proxy-ng-shim --lib dispatch::
}

run_integration() {
    echo "=== tier: integration ==="
    cargo test -p pkcs11-proxy-ng-shim --lib tests::
}

run_regression() {
    echo "=== tier: regression ==="
    cargo test -p pkcs11-proxy-ng-shim --lib tests::regression
    cargo test -p pkcs11-proxy-ng-shim --lib tests::cross_abi
    # Canonical defect tests kept in their natural modules, by name:
    cargo test -p pkcs11-proxy-ng-shim --lib -- not_wild_read
    cargo test -p pkcs11-proxy-ng-backend --lib -- wider_than_native
}

run_live() {
    echo "=== tier: live (skip-clean when tooling is absent) ==="
    scripts/run-cross-width-live-test.sh
    scripts/run-llp64-wine-smoke.sh
    scripts/run-windows-daemon-wine-smoke.sh
}

case "$tier" in
    unit) run_unit ;;
    integration) run_integration ;;
    regression) run_regression ;;
    live) run_live ;;
    all)
        run_unit
        run_integration
        run_regression
        ;;
    *)
        echo "usage: $0 [unit|integration|regression|live|all]" >&2
        exit 2
        ;;
esac
echo "PASS: tier '$tier' complete"
