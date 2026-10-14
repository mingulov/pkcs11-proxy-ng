#!/usr/bin/env bash
# Tiered test runner (mock-ABI test infrastructure design, 2026-07-02).
#
# Tiers (module/naming convention — no cargo features):
#   unit         scoped lib sweep: full suites for types, proto, client,
#                cli and audit, plus backend/server libs and the shim
#                dispatch units (pkcs11-module now lives upstream in
#                pkcs11-components and is covered by that repo's own CI).
#                A fast subset, not the whole non-live suite.
#   integration  in-process TestDaemon suites (shim tests::), incl. the
#                cross-ABI topology suite (tests::cross_abi)
#   regression   named defect pins: tests::regression plus the canonical
#                defect tests matched by name (*_not_wild_read,
#                *_wider_than_native_*, cross_abi). Deliberately overlaps
#                unit/integration for standalone re-runs; `all` does not
#                compose these tiers.
#   live         env-gated real-binary harnesses (daemons + SoftHSM2 /
#                wine, retained-oracle topologies, SIGTERM drain); each
#                script skips cleanly when its tooling is absent
#   all          the plain-CI surface: one canonical
#                `cargo test --workspace --locked` pass. Cargo enumerates
#                every current and future test target itself, so this —
#                not a composition of the focused tiers — is the complete
#                non-live gate.
#
# Plain `cargo test --workspace` runs everything except `live`.
# `#[ignore]`-gated tests (e.g. shim fork_after_init) are excluded from
# both `all` and plain CI; run them explicitly per lane, as CI does:
#   cargo test --locked -p pkcs11-proxy-ng-shim --test fork_after_init -- --ignored
set -euo pipefail

cd "$(dirname "$0")/.."

tier="${1:-all}"

run_unit() {
    echo "=== tier: unit ==="
    cargo test -p pkcs11-proxy-ng-types
    cargo test -p pkcs11-proxy-ng-backend --lib
    cargo test -p pkcs11-proxy-ng --lib
    cargo test -p pkcs11-proxy-ng-proto
    cargo test -p pkcs11-proxy-ng-client
    cargo test -p pkcs11-proxy-ng-cli
    cargo test -p pkcs11-proxy-ng-audit
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

run_all() {
    echo "=== tier: all (canonical workspace suite, once) ==="
    cargo test --workspace --locked
}

run_live() {
    echo "=== tier: live (skip-clean when tooling is absent) ==="
    scripts/test-daemon-startup-logging.sh
    scripts/test-live-harness-locators.sh
    scripts/run-cross-width-live-test.sh
    scripts/run-cross-width-nss32-live-test.sh
    # W1-L17-22: the retained-oracle topology proof and the SIGTERM
    # mid-call drain proof ran only by hand; both are live legs now.
    scripts/run-retained-oracle-live-test.sh
    scripts/test-sigterm-mid-call.sh
    scripts/run-llp64-wine-smoke.sh
    scripts/run-windows-daemon-wine-smoke.sh
}

case "$tier" in
    unit) run_unit ;;
    integration) run_integration ;;
    regression) run_regression ;;
    live) run_live ;;
    all)
        run_all
        ;;
    *)
        echo "usage: $0 [unit|integration|regression|live|all]" >&2
        exit 2
        ;;
esac
echo "PASS: tier '$tier' complete"
