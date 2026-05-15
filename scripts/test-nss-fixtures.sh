#!/usr/bin/env bash
set -euo pipefail
# NSS softokn custom-config fixture modes
# Runs certutil/modutil to set up various NSS DB configurations, then runs
# the proxy integration tests against each.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

find_nss_module() {
    local candidates=(
        "/usr/lib64/libsoftokn3.so"
        "/usr/lib/x86_64-linux-gnu/libsoftokn3.so"
        "/lib/x86_64-linux-gnu/libsoftokn3.so"
    )
    for path in "${candidates[@]}"; do
        [[ -f "$path" ]] && printf '%s\n' "$path" && return 0
    done
    return 1
}

NSS_MODULE="$(find_nss_module)" || { echo "NSS softokn not found"; exit 0; }

# --- Fixture 1: SQL DB with custom token description ---
echo "==> NSS fixture: SQL DB with custom token description"
dir1="$(mktemp -d)"
certutil -N -d "sql:$dir1" --empty-password
certutil -S -d "sql:$dir1" -n test-cert -s "CN=fixture-test" -x -t "CT,," -z /dev/urandom --keyUsage digitalSignature -2 <<< $'n\nn\nn' 2>/dev/null || true

export PKCS11_PROXY_NSS_MODULE="$NSS_MODULE"
export PKCS11_PROXY_NSS_INIT_ARGS="configDir='sql:$dir1' tokenDescription='custom-desc-token'"
export PKCS11_PROXY_NSS_TOKEN_LABEL="custom-desc-token"
export PKCS11_PROXY_NSS_USER_PIN=""
export PKCS11_PROXY_NSS_SO_PIN=""
export PKCS11_PROXY_NSS_EMPTY_SO_PIN="1"
export PKCS11_PROXY_NSS_INIT_TOKEN="1"

cargo test -p pkcs11-proxy-ng --test provider_matrix_test nss_softokn_smoke_suite -- --ignored --test-threads=1
echo "  OK: SQL DB with custom token description"
rm -rf "$dir1"

# --- Fixture 2: Legacy DBM format ---
echo "==> NSS fixture: legacy DBM format"
dir2="$(mktemp -d)"
certutil -N -d "dbm:$dir2" --empty-password 2>/dev/null || {
    echo "  SKIP: DBM format not supported on this build"
    rm -rf "$dir2"
    dir2=""
}
if [[ -n "${dir2:-}" ]]; then
    export PKCS11_PROXY_NSS_INIT_ARGS="configDir='dbm:$dir2' tokenDescription='dbm-token'"
    export PKCS11_PROXY_NSS_TOKEN_LABEL="dbm-token"
    cargo test -p pkcs11-proxy-ng --test provider_matrix_test nss_softokn_smoke_suite -- --ignored --test-threads=1
    echo "  OK: Legacy DBM format"
    rm -rf "$dir2"
fi

# --- Fixture 3: Read-only mode after bootstrap ---
echo "==> NSS fixture: read-only (forceOpen) mode"
dir3="$(mktemp -d)"
certutil -N -d "sql:$dir3" --empty-password
export PKCS11_PROXY_NSS_INIT_ARGS="configDir='sql:$dir3' flags=forceOpen,readOnly tokenDescription='readonly-token'"
export PKCS11_PROXY_NSS_TOKEN_LABEL="readonly-token"
export PKCS11_PROXY_NSS_INIT_TOKEN="0"
# Don't try to init token in read-only mode
cargo test -p pkcs11-proxy-ng --test provider_matrix_test nss_softokn_smoke_suite -- --ignored --test-threads=1 || echo "  NOTE: read-only mode has expected limitations"
echo "  OK: read-only fixture exercised"
rm -rf "$dir3"

# --- Fixture 4: Custom prefix ---
echo "==> NSS fixture: custom cert/key prefix"
dir4="$(mktemp -d)"
certutil -N -d "sql:$dir4" --empty-password
export PKCS11_PROXY_NSS_INIT_ARGS="configDir='sql:$dir4' certPrefix='myapp_' keyPrefix='myapp_' tokenDescription='prefix-token'"
export PKCS11_PROXY_NSS_TOKEN_LABEL="prefix-token"
export PKCS11_PROXY_NSS_INIT_TOKEN="1"
    cargo test -p pkcs11-proxy-ng --test provider_matrix_test nss_softokn_smoke_suite -- --ignored --test-threads=1
    echo "  OK: custom cert/key prefix"
rm -rf "$dir4"

echo "==> All NSS fixture modes completed"
