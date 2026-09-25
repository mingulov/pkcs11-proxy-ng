# shellcheck shell=bash
# Shared 4-mirror version check (W1-L17-10). Source, don't run:
#
#   # shellcheck source=lib/version-mirrors.sh
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/version-mirrors.sh"
#   check_version_mirrors "$cargo_version" || exit 1
#
# Single definition of the four packaging version mirrors (path + sed
# extraction program each). A fifth mirror needs one edit here; every
# consumer (release-dry-run.sh, release-windows.sh,
# verify-release-subject.sh, packaging-smoke.sh) follows automatically.

# Each entry: "<path>|<sed -nE program>". `|` separates the halves (neither
# side uses it); paths are relative to the repository root (callers cd
# there before checking).
VERSION_MIRRORS=(
    '.gitlab-ci.yml|s/^  APP_VERSION: "([^"]+)"$/\1/p'
    'packaging/alpine/APKBUILD|s/^pkgver=([^[:space:]]+)$/\1/p'
    'packaging/amazon/pkcs11-proxy-ng.spec|s/^Version:[[:space:]]+([^[:space:]]+)[[:space:]]*$/\1/p'
    'packaging/amazon/Dockerfile.amazon|s/^ARG APP_VERSION=([^[:space:]]+)$/\1/p'
)

# check_version_mirrors <expected-cargo-version>: every mirror must extract
# to exactly the expected version. Fails closed (return 1 + diagnostics)
# on drift AND on unreadable mirrors.
check_version_mirrors() {
    local expected="$1" fail=0 entry path prog found
    for entry in "${VERSION_MIRRORS[@]}"; do
        path="${entry%%|*}"
        prog="${entry#*|}"
        found="$(sed -nE -e "$prog" "$path" 2>/dev/null)" || found=""
        if [[ -z "$found" ]]; then
            echo "version-mirrors: cannot read a version from $path" >&2
            fail=1
        elif [[ "$found" != "$expected" ]]; then
            echo "version-mirrors: $path version $found does not match Cargo $expected" >&2
            fail=1
        fi
    done
    return "$fail"
}
