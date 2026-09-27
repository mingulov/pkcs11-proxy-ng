#!/usr/bin/env bash
# W1-L17-05: per-PR packaging smoke signal.
#
# Full Alpine-APK / Amazon-RPM carrier builds run in external GitLab
# (.gitlab-ci.yml) by design; this script is the fast GitHub-side signal
# (ci.yml `packaging-smoke` job + test-matrix.sh fast checks). Stage B
# adds a GitHub APK build/install/sign lane alongside (ci.yml
# `smoke-apk-alpine`); full Amazon RPM build/install stays in GitLab.
# It fails fast on:
#   (a) APKBUILD/spec shape breakage, and
#   (b) version drift between the Cargo workspace and the four packaging
#       mirrors (.gitlab-ci.yml APP_VERSION, APKBUILD pkgver, spec
#       Version, Dockerfile.amazon ARG APP_VERSION).
#
# The Cargo version is read straight from the workspace Cargo.toml so the
# smoke needs no Rust toolchain (checkout + bash + Python 3.11+).
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

# Each code-bearing package needs installed files, not just license
# metadata. The executable APK function and RPM list tests check contents.
for part in shim daemon cli; do
    grep -Fq "_install_notices \"\$subpkgdir\" \"\$pkgname-$part\"" packaging/alpine/APKBUILD || {
        echo "APK $part omits notice installation" >&2
        exit 1
    }
    for item in LICENSE-APACHE LICENSE-MIT THIRD_PARTY_NOTICES license-material \
                notice-inventory.json build-provenance.json; do
        grep -Eq "^%license .*%\{name\}-$part/$item$" packaging/amazon/pkcs11-proxy-ng.spec || {
            echo "RPM $part omits $item" >&2
            exit 1
        }
    done
done
# The dollar signs are literal APKBUILD text, not shell expansions here.
# shellcheck disable=SC2016
grep -Fq 'depends="$pkgname-shim=$pkgver-r$pkgrel"' packaging/alpine/APKBUILD || {
    echo "APK compat must require the exact shim version" >&2
    exit 1
}
python3 -B scripts/release_checks.py notices --help >/dev/null
python3 -B scripts/release_checks.py workspace-notices --help >/dev/null
python3 -B scripts/release_checks.py bundle --help >/dev/null

# (b) Version mirrors agree with the workspace Cargo version (shared
# W1-L17-10 check: one mirror definition for all release tooling).
CARGO_VERSION="$(sed -nE 's/^version = "([^"]+)"$/\1/p' Cargo.toml)"
if [[ -z "$CARGO_VERSION" ]]; then
    echo "cannot read workspace version from Cargo.toml" >&2
    exit 1
fi
check_version_mirrors "$CARGO_VERSION" || exit 1

echo "packaging smoke passed (mirrors at $CARGO_VERSION)"
