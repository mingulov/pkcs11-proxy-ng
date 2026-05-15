#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_ROOT="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"
PREFIX=""
SKIP_BUILD=0

usage() {
    cat <<'EOF'
Usage: scripts/release-dry-run.sh [options]

Build release artifacts, verify their expected names, and smoke-test a staged
install layout without requiring a PKCS#11 provider.

Options:
  --prefix DIR   Stage artifacts under DIR instead of a temporary directory
  --skip-build   Verify and install existing target/release artifacts
  -h, --help     Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            PREFIX="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=1
            shift
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
done

case "$TARGET_ROOT" in
    /*) ;;
    *) TARGET_ROOT="$ROOT_DIR/$TARGET_ROOT" ;;
esac

RELEASE_DIR="$TARGET_ROOT/release"
DAEMON_BIN="$RELEASE_DIR/pkcs11-proxy-ng"
CLI_BIN="$RELEASE_DIR/pkcs11-proxy-ng-cli"
SHIM_LIB="$RELEASE_DIR/libpkcs11_proxy_ng_shim.so"

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Required command not found: $1" >&2
        exit 1
    fi
}

require_file() {
    if [[ ! -f "$1" ]]; then
        echo "Missing artifact: $1" >&2
        exit 1
    fi
}

require_executable() {
    require_file "$1"
    if [[ ! -x "$1" ]]; then
        echo "Artifact is not executable: $1" >&2
        exit 1
    fi
}

cd "$ROOT_DIR"

require_cmd cargo
require_cmd install

if [[ "$SKIP_BUILD" -eq 0 ]]; then
    cargo build --release --workspace
fi

require_executable "$DAEMON_BIN"
require_executable "$CLI_BIN"
require_file "$SHIM_LIB"

cleanup_dir=""
if [[ -z "$PREFIX" ]]; then
    cleanup_dir="$(mktemp -d)"
    PREFIX="$cleanup_dir/prefix"
fi

install -d "$PREFIX/bin" "$PREFIX/lib/pkcs11"
install -m 0755 "$DAEMON_BIN" "$PREFIX/bin/pkcs11-proxy-ng"
install -m 0755 "$CLI_BIN" "$PREFIX/bin/pkcs11-proxy-ng-cli"
install -m 0755 "$SHIM_LIB" "$PREFIX/lib/pkcs11/libpkcs11_proxy_ng_shim.so"

"$PREFIX/bin/pkcs11-proxy-ng" --version >/dev/null
"$PREFIX/bin/pkcs11-proxy-ng-cli" --version >/dev/null
test -s "$PREFIX/lib/pkcs11/libpkcs11_proxy_ng_shim.so"

cat <<EOF
Release dry run passed.

Artifacts:
  $DAEMON_BIN
  $CLI_BIN
  $SHIM_LIB

Install layout:
  $PREFIX/bin/pkcs11-proxy-ng
  $PREFIX/bin/pkcs11-proxy-ng-cli
  $PREFIX/lib/pkcs11/libpkcs11_proxy_ng_shim.so
EOF

if [[ -n "$cleanup_dir" ]]; then
    rm -rf "$cleanup_dir"
fi
