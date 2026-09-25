#!/usr/bin/env bash
# W1-L17-05: per-PR packaging smoke signal.
#
# Full Alpine-APK / Amazon-RPM carrier builds run in external GitLab
# (.gitlab-ci.yml) by design; this script is the fast GitHub-side signal
# (ci.yml `packaging-smoke` job + test-matrix.sh fast checks). It fails
# fast on:
#   (a) APKBUILD/spec shape breakage, and
#   (b) version drift between the Cargo workspace and the four packaging
#       mirrors (.gitlab-ci.yml APP_VERSION, APKBUILD pkgver, spec
#       Version, Dockerfile.amazon ARG APP_VERSION).
#
# The Cargo version is read straight from the workspace Cargo.toml so the
# smoke needs no Rust toolchain (checkout + bash only).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/version-mirrors.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/version-mirrors.sh"
cd "$ROOT_DIR"

# (a) APKBUILD is sourced by abuild as shell: it must parse.
bash -n packaging/alpine/APKBUILD

# The RPM spec must carry its required tags and sections. (Full rpmbuild
# stays in GitLab; this is the shape half of the smoke.)
for tag in '^Name:' '^Version:' '^Release:' '^Summary:' '^License:' '^Source0:'; do
    grep -Eq "$tag" packaging/amazon/pkcs11-proxy-ng.spec || {
        echo "spec is missing required tag $tag" >&2
        exit 1
    }
done
for section in '^%description' '^%build' '^%install' '^%files'; do
    grep -Eq "$section" packaging/amazon/pkcs11-proxy-ng.spec || {
        echo "spec is missing required section $section" >&2
        exit 1
    }
done

# (b) Version mirrors agree with the workspace Cargo version (shared
# W1-L17-10 check: one mirror definition for all release tooling).
CARGO_VERSION="$(sed -nE 's/^version = "([^"]+)"$/\1/p' Cargo.toml)"
if [[ -z "$CARGO_VERSION" ]]; then
    echo "cannot read workspace version from Cargo.toml" >&2
    exit 1
fi
check_version_mirrors "$CARGO_VERSION" || exit 1

echo "packaging smoke passed (mirrors at $CARGO_VERSION)"
