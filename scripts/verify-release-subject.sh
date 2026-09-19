#!/usr/bin/env bash
# Verify that a release tag names the same subject as the checked-out source.
#
# Usage: scripts/verify-release-subject.sh [TAG]
# TAG defaults to $GITHUB_REF_NAME. Exits 0 only when ALL of these hold:
#   (a) the tag matches ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$
#   (b) the Cargo workspace version equals the tag's base version
#       (leading "v" and any "-suffix" stripped)
#   (c) CHANGELOG.md contains a heading exactly "## [<base>] - YYYY-MM-DD"
#   (d) the four packaging mirrors equal the Cargo workspace version
#
# Every failure prints a "::error::" line plus the expected literal and
# exits 1. Called by .github/workflows/release.yml before any build step.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TAG="${1:-${GITHUB_REF_NAME:-}}"
if [[ -z "$TAG" ]]; then
    echo "::error::no tag supplied (expected \$1 or \$GITHUB_REF_NAME)" >&2
    echo "expected a tag like v0.2.0" >&2
    exit 1
fi

if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "::error::tag '$TAG' does not match vMAJOR.MINOR.PATCH[-suffix]; refusing to release." >&2
    echo "expected a tag like v0.2.0" >&2
    exit 1
fi

BASE="${TAG#v}"
BASE="${BASE%%-*}"

if ! command -v cargo >/dev/null 2>&1; then
    echo "::error::required command not found: cargo" >&2
    exit 1
fi
CARGO_VERSION="$(cargo pkgid -p pkcs11-proxy-ng | sed -E 's/.*@//')"

if [[ "$CARGO_VERSION" != "$BASE" ]]; then
    echo "::error::tag '$TAG' names version $BASE but Cargo workspace is $CARGO_VERSION; refusing to release." >&2
    echo "expected Cargo version $BASE" >&2
    exit 1
fi

if ! grep -Eq "^## \\[${BASE}\\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" CHANGELOG.md; then
    echo "::error::CHANGELOG.md has no dated section for version ${BASE}; refusing to release." >&2
    echo "expected a heading like: ## [${BASE}] - YYYY-MM-DD" >&2
    exit 1
fi

for mirror in \
    ".gitlab-ci.yml:$(sed -nE 's/^  APP_VERSION: \"([^\"]+)\"$/\1/p' .gitlab-ci.yml)" \
    "packaging/alpine/APKBUILD:$(sed -nE 's/^pkgver=([^[:space:]]+)$/\1/p' packaging/alpine/APKBUILD)" \
    "packaging/amazon/pkcs11-proxy-ng.spec:$(sed -nE 's/^Version:[[:space:]]+([^[:space:]]+)[[:space:]]*$/\1/p' packaging/amazon/pkcs11-proxy-ng.spec)" \
    "packaging/amazon/Dockerfile.amazon:$(sed -nE 's/^ARG APP_VERSION=([^[:space:]]+)$/\1/p' packaging/amazon/Dockerfile.amazon)"; do
    mirror_path="${mirror%%:*}"
    mirror_version="${mirror#*:}"
    if [[ "$mirror_version" != "$CARGO_VERSION" ]]; then
        echo "::error::$mirror_path version $mirror_version does not match Cargo $CARGO_VERSION; refusing to release." >&2
        echo "expected $mirror_path version $CARGO_VERSION" >&2
        exit 1
    fi
done

echo "release subject verified: tag $TAG matches Cargo $CARGO_VERSION"
