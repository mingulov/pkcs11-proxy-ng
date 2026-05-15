#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"

KRYOPTIC_TMPDIR=""

cleanup() {
    if [[ -n "$KRYOPTIC_TMPDIR" ]]; then
        rm -rf "$KRYOPTIC_TMPDIR"
    fi
}
trap cleanup EXIT

if [[ -z "${PKCS11_PROXY_KRYOPTIC_MODULE:-}" ]] && [[ -f /opt/kryoptic/target/release/libkryoptic_pkcs11.so ]]; then
    export PKCS11_PROXY_KRYOPTIC_MODULE=/opt/kryoptic/target/release/libkryoptic_pkcs11.so
fi

if [[ -n "${PKCS11_PROXY_KRYOPTIC_MODULE:-}" ]] && [[ -f "${PKCS11_PROXY_KRYOPTIC_MODULE}" ]]; then
    kryoptic_run_id="$(date +%s)$$"
    if [[ -z "${PKCS11_PROXY_KRYOPTIC_INIT_ARGS:-}" ]]; then
        KRYOPTIC_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/pkcs11-proxy-ng-kryoptic.XXXXXX")"
        export PKCS11_PROXY_KRYOPTIC_INIT_ARGS="$KRYOPTIC_TMPDIR/token.sql"
    fi
    export PKCS11_PROXY_KRYOPTIC_INIT_TOKEN="${PKCS11_PROXY_KRYOPTIC_INIT_TOKEN:-1}"
    export PKCS11_PROXY_KRYOPTIC_TOKEN_LABEL="${PKCS11_PROXY_KRYOPTIC_TOKEN_LABEL:-kryoptic-token-$kryoptic_run_id}"
    export PKCS11_PROXY_KRYOPTIC_USER_PIN="${PKCS11_PROXY_KRYOPTIC_USER_PIN:-1$kryoptic_run_id}"
    export PKCS11_PROXY_KRYOPTIC_SO_PIN="${PKCS11_PROXY_KRYOPTIC_SO_PIN:-9$kryoptic_run_id}"
    mkdir -p "$(dirname "$PKCS11_PROXY_KRYOPTIC_INIT_ARGS")"
fi

cargo test -p pkcs11-proxy-ng --test integration_test -- --ignored --test-threads=1
cargo test -p pkcs11-proxy-ng --test provider_matrix_test nss_softokn_smoke_suite -- --ignored --test-threads=1
cargo test -p pkcs11-proxy-ng --test nss_mechanism_coverage_test -- --ignored --test-threads=1

if [[ -n "${PKCS11_PROXY_KRYOPTIC_MODULE:-}" ]] && [[ -f "${PKCS11_PROXY_KRYOPTIC_MODULE}" ]]; then
    cargo test -p pkcs11-proxy-ng --test provider_matrix_test kryoptic_smoke_suite -- --ignored --test-threads=1
else
    echo "[provider-matrix] kryoptic skipped (module not available)"
fi
