#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/version-mirrors.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/version-mirrors.sh"
TARGET_ROOT="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"
TARGET_TRIPLE="x86_64-pc-windows-msvc"
PREFIX=""
SKIP_BUILD=0
PREPARED_BINARIES=""
PROVENANCE=""
NOTICES=""
INVENTORY=""
PACKAGE_DIR=""
TIMESTAMP=""

usage() {
    cat <<'EOF'
Usage: scripts/release-windows.sh [options]

Build a local source-based Windows dry-run ZIP, or stage already prepared
registry/archive binaries with matching provenance and notices. No path
implicitly turns checkout binaries into registry-source artifacts.

Options:
  --prefix DIR             Write the ZIP and checksum under DIR
  --skip-build             Use existing local target binaries (source unverified)
  --prepared-binaries DIR  Explicit release binary directory
  --provenance PATH        Matching portable build-provenance.json
  --notices DIR            Matching generated notice directory
  --inventory PATH        Required with registry-source provenance
  --package-dir DIR        Required with registry-source provenance
  --timestamp EPOCH        Deterministic ZIP timestamp for prepared mode
  -h, --help               Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        --prepared-binaries) PREPARED_BINARIES="$2"; shift 2 ;;
        --provenance) PROVENANCE="$2"; shift 2 ;;
        --notices) NOTICES="$2"; shift 2 ;;
        --inventory) INVENTORY="$2"; shift 2 ;;
        --package-dir) PACKAGE_DIR="$2"; shift 2 ;;
        --timestamp) TIMESTAMP="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

cd "$ROOT_DIR"
if [[ -z "$PREFIX" ]]; then
    DIST_COPY=1
    STAGING_ROOT="$(mktemp -d)"
    PREFIX="$STAGING_ROOT/bundle"
else
    DIST_COPY=0
    STAGING_ROOT=""
fi
cleanup_staging_root() {
    if [[ -n "$STAGING_ROOT" ]]; then
        rm -rf -- "$STAGING_ROOT"
    fi
    if [[ -n "${LOCAL_INPUT_ROOT:-}" ]]; then
        rm -rf -- "$LOCAL_INPUT_ROOT"
    fi
}
trap cleanup_staging_root EXIT

if [[ -n "$PREPARED_BINARIES" || -n "$PROVENANCE" || -n "$NOTICES" ]]; then
    if [[ -z "$PREPARED_BINARIES" || -z "$PROVENANCE" || -z "$NOTICES" || -z "$TIMESTAMP" ]]; then
        echo "Prepared staging requires binaries, provenance, notices, and timestamp" >&2
        exit 1
    fi
    if [[ "$SKIP_BUILD" -ne 0 ]]; then
        echo "--skip-build applies only to local workspace builds" >&2
        exit 1
    fi
    BINARY_DIR="$PREPARED_BINARIES"
    PROVENANCE_PATH="$PROVENANCE"
    NOTICES_DIR="$NOTICES"
else
    if [[ -n "$INVENTORY" || -n "$PACKAGE_DIR" || -n "$TIMESTAMP" ]]; then
        echo "Inventory, package directory and timestamp require prepared binaries" >&2
        exit 1
    fi
    case "$TARGET_ROOT" in
        /*) ;;
        *) TARGET_ROOT="$ROOT_DIR/$TARGET_ROOT" ;;
    esac
    release_version="$(cargo pkgid -p pkcs11-proxy-ng | sed -E 's/.*@//')"
    check_version_mirrors "$release_version"
    if [[ "$SKIP_BUILD" -eq 0 ]]; then
        cargo xwin build --release --locked --target "$TARGET_TRIPLE" \
            -p pkcs11-proxy-ng -p pkcs11-proxy-ng-cli -p pkcs11-proxy-ng-shim
        cargo xwin build --release --locked --target "$TARGET_TRIPLE" \
            -p pkcs11-proxy-ng-shim --example cross_width_smoke
    fi
    RELEASE_DIR="$TARGET_ROOT/$TARGET_TRIPLE/release"
    LOCAL_INPUT_ROOT="$(mktemp -d)"
    BINARY_DIR="$LOCAL_INPUT_ROOT/prepared"
    mkdir -p "$BINARY_DIR"
    install -m 0755 "$RELEASE_DIR/pkcs11-proxy-ng.exe" "$BINARY_DIR/"
    install -m 0755 "$RELEASE_DIR/pkcs11-proxy-ng-cli.exe" "$BINARY_DIR/"
    install -m 0755 "$RELEASE_DIR/pkcs11_proxy_ng_shim.dll" "$BINARY_DIR/"
    install -m 0755 "$RELEASE_DIR/examples/cross_width_smoke.exe" "$BINARY_DIR/"
    python3 scripts/release_checks.py workspace-notices \
        --binaries "$BINARY_DIR" --target "$TARGET_TRIPLE" \
        --inputs-output "$LOCAL_INPUT_ROOT/inputs" \
        --output "$LOCAL_INPUT_ROOT/notices"
    PROVENANCE_PATH="$LOCAL_INPUT_ROOT/inputs/build-provenance.json"
    NOTICES_DIR="$LOCAL_INPUT_ROOT/notices"
    TIMESTAMP="$(git log -1 --format=%ct)"
fi

bundle_args=(bundle --binaries "$BINARY_DIR" --provenance "$PROVENANCE_PATH"
             --notices "$NOTICES_DIR" --output "$PREFIX" --timestamp "$TIMESTAMP")
if [[ -n "$INVENTORY" || -n "$PACKAGE_DIR" ]]; then
    if [[ -z "$INVENTORY" || -z "$PACKAGE_DIR" ]]; then
        echo "Registry source validation needs both inventory and package directory" >&2
        exit 1
    fi
    bundle_args+=(--inventory "$INVENTORY" --package-dir "$PACKAGE_DIR")
fi
BUNDLE_RESULT="$(python3 scripts/release_checks.py "${bundle_args[@]}")"
ZIP_PATH="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["bundle"])' <<<"$BUNDLE_RESULT")"
if [[ -z "$ZIP_PATH" || ! -s "$ZIP_PATH" ]]; then
    echo "ZIP bundle was not created" >&2
    exit 1
fi
( cd "$PREFIX" && sha256sum "$(basename "$ZIP_PATH")" > SHA256SUMS-windows )
SUMS_PATH="$PREFIX/SHA256SUMS-windows"
if [[ "$DIST_COPY" -eq 1 ]]; then
    mkdir -p "$ROOT_DIR/dist"
    cp "$ZIP_PATH" "$SUMS_PATH" "$ROOT_DIR/dist/"
    ZIP_PATH="$ROOT_DIR/dist/$(basename "$ZIP_PATH")"
    SUMS_PATH="$ROOT_DIR/dist/SHA256SUMS-windows"
fi
printf 'Windows bundle: %s\nChecksums: %s\n' "$ZIP_PATH" "$SUMS_PATH"
