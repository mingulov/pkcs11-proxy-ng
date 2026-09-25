#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/version-mirrors.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/version-mirrors.sh"
TARGET_ROOT="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"
TARGET_TRIPLE="x86_64-pc-windows-msvc"
PREFIX=""
SKIP_BUILD=0

usage() {
    cat <<'EOF'
Usage: scripts/release-windows.sh [options]

Cross-compile the Windows x64 (MSVC) release artifacts with cargo-xwin,
stage the deterministic asset bundle layout, and emit a reproducible ZIP
plus SHA256SUMS-windows without requiring a Windows runner or Wine.

Options:
  --prefix DIR   Stage artifacts under DIR instead of a temporary directory
  --skip-build   Verify and package existing target/<triple>/release artifacts
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

RELEASE_DIR="$TARGET_ROOT/$TARGET_TRIPLE/release"
DAEMON_BIN="$RELEASE_DIR/pkcs11-proxy-ng.exe"
CLI_BIN="$RELEASE_DIR/pkcs11-proxy-ng-cli.exe"
SHIM_DLL="$RELEASE_DIR/pkcs11_proxy_ng_shim.dll"
SMOKE_BIN="$RELEASE_DIR/examples/cross_width_smoke.exe"

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

require_nonempty() {
    require_file "$1"
    if [[ ! -s "$1" ]]; then
        echo "Artifact is empty: $1" >&2
        exit 1
    fi
}

cd "$ROOT_DIR"

require_cmd cargo
require_cmd install
require_cmd python3
require_cmd sha256sum
release_version="$(cargo pkgid -p pkcs11-proxy-ng | sed -E 's/.*@//')"

for manifest in crates/*/Cargo.toml; do
    for key in version edition rust-version license; do
        grep -qx "${key}.workspace = true" "$manifest" || {
            echo "$manifest must inherit $key from workspace.package" >&2
            exit 1
        }
    done
done

packages=(
    pkcs11-proxy-ng-audit pkcs11-proxy-ng-types pkcs11-proxy-ng-proto \
    pkcs11-proxy-ng-backend pkcs11-proxy-ng pkcs11-proxy-ng-client \
    pkcs11-proxy-ng-cli pkcs11-proxy-ng-shim
)
expected_packages="$(printf '%s\n' "${packages[@]}" | sort)"
actual_packages="$(cargo tree --workspace --depth 0 --prefix none | sed -E '/^$/d; s/ .*$//' | sort)"
[[ "$actual_packages" == "$expected_packages" ]] || {
    echo "Workspace package set does not match the release package set" >&2
    exit 1
}

for package in "${packages[@]}"; do
    test "$(cargo pkgid -p "$package" | sed -E 's/.*@//')" = "$release_version"
done

check_version_mirrors "$release_version" || exit 1

if grep -Eq 'pkcs11-proxy-ng-[0-9]+\.[0-9]+\.[0-9]+' packaging/amazon/Dockerfile.amazon; then
    echo "Amazon Dockerfile versioned paths must derive from APP_VERSION" >&2
    exit 1
fi

if [[ "$SKIP_BUILD" -eq 0 ]]; then
    require_cmd cargo-xwin
    cargo xwin build --release --target "$TARGET_TRIPLE" \
        -p pkcs11-proxy-ng -p pkcs11-proxy-ng-cli -p pkcs11-proxy-ng-shim
    cargo xwin build --release --target "$TARGET_TRIPLE" \
        -p pkcs11-proxy-ng-shim --example cross_width_smoke
fi

require_nonempty "$DAEMON_BIN"
require_nonempty "$CLI_BIN"
require_nonempty "$SHIM_DLL"
require_nonempty "$SMOKE_BIN"

BUNDLE="pkcs11-proxy-ng-v${release_version}-${TARGET_TRIPLE}"

cleanup_dir=""
DIST_COPY=""
if [[ -z "$PREFIX" ]]; then
    cleanup_dir="$(mktemp -d)"
    PREFIX="$cleanup_dir/stage"
    DIST_COPY=1
fi

STAGE="$PREFIX/$BUNDLE"
ZIP_PATH="$PREFIX/${BUNDLE}.zip"
SUMS_PATH="$PREFIX/SHA256SUMS-windows"

install -d "$STAGE/bin" "$STAGE/lib"
install -m 0755 "$DAEMON_BIN" "$STAGE/bin/pkcs11-proxy-ng.exe"
install -m 0755 "$CLI_BIN" "$STAGE/bin/pkcs11-proxy-ng-cli.exe"
install -m 0755 "$SMOKE_BIN" "$STAGE/bin/cross_width_smoke.exe"
install -m 0755 "$SHIM_DLL" "$STAGE/lib/pkcs11_proxy_ng_shim.dll"
install -m 0644 README.md CHANGELOG.md LICENSE-APACHE LICENSE-MIT "$STAGE/"

ZIP_DATE="$(git log -1 --format=%cI)"

python3 - "$STAGE" "$ZIP_PATH" "$ZIP_DATE" <<'EOF'
import datetime
import os
import sys
import zipfile

stage_dir, zip_path, datestr = sys.argv[1], sys.argv[2], sys.argv[3]

# The tag-commit date (same discipline as the tarball --mtime) pins every
# entry timestamp, so the ZIP is byte-reproducible for a given commit.
dt = datetime.datetime.fromisoformat(datestr.replace("Z", "+00:00"))
date_time = (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)

top = os.path.basename(os.path.normpath(stage_dir))
entries = [
    ("bin/pkcs11-proxy-ng.exe", 0o755),
    ("bin/pkcs11-proxy-ng-cli.exe", 0o755),
    ("bin/cross_width_smoke.exe", 0o755),
    ("lib/pkcs11_proxy_ng_shim.dll", 0o755),
    ("README.md", 0o644),
    ("CHANGELOG.md", 0o644),
    ("LICENSE-APACHE", 0o644),
    ("LICENSE-MIT", 0o644),
]

with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for relpath, mode in sorted(entries):
        src = os.path.join(stage_dir, relpath)
        if not os.path.isfile(src) or os.path.getsize(src) == 0:
            raise SystemExit(f"Missing or empty staged file: {src}")
        arcname = f"{top}/{relpath}"
        info = zipfile.ZipInfo(arcname, date_time=date_time)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.create_system = 3  # Unix, so external_attr carries mode bits
        info.external_attr = (mode & 0xFFFF) << 16
        with open(src, "rb") as fh:
            zf.writestr(info, fh.read())

with zipfile.ZipFile(zip_path) as zf:
    names = zf.namelist()
    expected = sorted(f"{top}/{relpath}" for relpath, _ in entries)
    if names != expected:
        raise SystemExit(f"ZIP layout mismatch: {names!r} != {expected!r}")
    bad = zf.testzip()
    if bad is not None:
        raise SystemExit(f"ZIP integrity check failed on entry: {bad}")
EOF

( cd "$PREFIX" && sha256sum "${BUNDLE}.zip" > SHA256SUMS-windows )
test -s "$ZIP_PATH"
test -s "$SUMS_PATH"

# Linux-side smoke check: ZIP integrity via the stdlib (no Wine here).
python3 -c 'import sys, zipfile; sys.exit(0 if zipfile.ZipFile(sys.argv[1]).testzip() is None else 1)' "$ZIP_PATH"

if [[ -n "$DIST_COPY" ]]; then
    mkdir -p "$ROOT_DIR/dist"
    cp "$ZIP_PATH" "$SUMS_PATH" "$ROOT_DIR/dist/"
    ZIP_PATH="$ROOT_DIR/dist/${BUNDLE}.zip"
    SUMS_PATH="$ROOT_DIR/dist/SHA256SUMS-windows"
fi

cat <<EOF
Release windows dry run passed.

Artifacts:
  $DAEMON_BIN
  $CLI_BIN
  $SHIM_DLL
  $SMOKE_BIN

Install layout:
  $STAGE/bin/pkcs11-proxy-ng.exe
  $STAGE/bin/pkcs11-proxy-ng-cli.exe
  $STAGE/bin/cross_width_smoke.exe
  $STAGE/lib/pkcs11_proxy_ng_shim.dll
  $STAGE/README.md
  $STAGE/CHANGELOG.md
  $STAGE/LICENSE-APACHE
  $STAGE/LICENSE-MIT

Bundle:
  $ZIP_PATH
  $SUMS_PATH
EOF

ls -la "$(dirname "$ZIP_PATH")"
cat "$SUMS_PATH"

if [[ -n "$cleanup_dir" ]]; then
    rm -rf "$cleanup_dir"
fi
