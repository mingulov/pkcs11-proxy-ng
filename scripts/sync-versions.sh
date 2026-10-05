#!/usr/bin/env bash
# Single-command version bump: the workspace Cargo.toml version is the one
# source of truth; every other version mirror derives from it.
#
#   scripts/sync-versions.sh 0.2.3   # bump everything to 0.2.3
#   scripts/sync-versions.sh --check # verify mirrors match Cargo (CI-safe)
#
# Mirrors written (compare scripts/lib/version-mirrors.sh, which checks the
# packaging four; this script writes those four plus the rest):
#   Cargo.toml [workspace.package] version              (the source)
#   crates/*/Cargo.toml internal "=X.Y.Z" path-dep pins (exact requirements
#       are policy — caret ranges would admit mixed crate versions, which
#       the wire contract forbids)
#   packaging/alpine/APKBUILD pkgver
#   packaging/amazon/pkcs11-proxy-ng.spec Version tag
#   packaging/amazon/Dockerfile.amazon ARG APP_VERSION
#   .gitlab-ci.yml APP_VERSION
#   README.md current-source-version token
#   Cargo.lock + fuzz/Cargo.lock (regenerated via cargo, offline)
#
# Deliberately NOT touched (authentic per-release history, written by hand):
#   CHANGELOG.md sections, doc/release/v0.* notes/receipts, the RPM
#   %changelog stanza (add an entry per release), doc/release/current.md
#   (repoint at the new notes). Prose elsewhere is version-free by
#   construction and never needs a bump.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/version-mirrors.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/version-mirrors.sh"
cd "$ROOT_DIR"

usage() {
    echo "usage: $0 <X.Y.Z> | --check" >&2
    exit 2
}

cargo_version() {
    sed -nE 's/^version = "([^"]+)"$/\1/p' Cargo.toml | head -n 1
}

CRATE_MANIFESTS=(
    crates/audit/Cargo.toml crates/types/Cargo.toml crates/proto/Cargo.toml
    crates/backend/Cargo.toml crates/server/Cargo.toml crates/client/Cargo.toml
    crates/cli/Cargo.toml crates/shim/Cargo.toml
)

# check_pins <expected>: every internal pkcs11-proxy-ng path-dep pin must be
# exactly "=<expected>". Fails closed on drift AND on unparseable manifests.
check_pins() {
    local expected="$1" fail=0 manifest
    for manifest in "${CRATE_MANIFESTS[@]}"; do
        while IFS= read -r line; do
            case "$line" in
                *'version = "='"${expected}"'"'*'path = "../'*) ;;
                *)
                    echo "sync-versions: $manifest has a drifting internal pin: $line" >&2
                    fail=1
                    ;;
            esac
        done < <(grep -E 'version = "=' "$manifest" | grep -E 'path = "\.\./' || true)
    done
    return "$fail"
}

# check_token: the README version token must match Cargo.
check_token() {
    local expected="$1" found
    found="$(sed -nE 's/.*<!-- SYNC-VERSION -->([0-9]+\.[0-9]+\.[0-9]+)<!-- \/SYNC-VERSION -->.*/\1/p' README.md | head -n 1)"
    if [[ -z "$found" ]]; then
        echo "sync-versions: README.md has no SYNC-VERSION token" >&2
        return 1
    elif [[ "$found" != "$expected" ]]; then
        echo "sync-versions: README token $found does not match Cargo $expected" >&2
        return 1
    fi
    return 0
}

do_check() {
    local expected fail=0
    expected="$(cargo_version)"
    if [[ -z "$expected" ]]; then
        echo "sync-versions: cannot read workspace version from Cargo.toml" >&2
        return 1
    fi
    check_version_mirrors "$expected" || fail=1
    check_pins "$expected" || fail=1
    check_token "$expected" || fail=1
    if [[ "$fail" -eq 0 ]]; then
        echo "sync-versions: all mirrors match Cargo $expected"
    fi
    return "$fail"
}

[[ $# -eq 1 ]] || usage
if [[ "$1" == "--check" ]]; then
    do_check
    exit $?
fi

NEW="$1"
if [[ ! "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "sync-versions: refusing '$NEW' (want strict X.Y.Z)" >&2
    exit 1
fi

# 1. The source of truth.
python3 - "$NEW" <<'EOF'
import re, sys
new = sys.argv[1]
path = "Cargo.toml"
text = open(path).read()
updated, count = re.subn(r'(?m)^version = "[0-9]+\.[0-9]+\.[0-9]+"$',
                          f'version = "{new}"', text, count=1)
assert count == 1, "workspace version line not found"
open(path, "w").write(updated)
EOF

# 2. Internal "=X.Y.Z" pins (path deps only; first-party crates only).
for manifest in "${CRATE_MANIFESTS[@]}"; do
    python3 - "$manifest" "$NEW" <<'EOF'
import re, sys
path, new = sys.argv[1], sys.argv[2]
lines = open(path).read().splitlines(keepends=True)
out = []
for line in lines:
    if 'path = "../' in line and 'version = "=' in line \
            and "pkcs11-proxy-ng" in line:
        line, count = re.subn(r'version = "=[^"]+"', f'version = "={new}"',
                              line, count=1)
        assert count == 1, f"pin not rewritten: {path}: {line.rstrip()}"
    out.append(line)
open(path, "w").write("".join(out))
EOF
done

# 3. The four packaging mirrors (same files version-mirrors.sh checks).
python3 - "$NEW" <<'EOF'
import re, sys
new = sys.argv[1]
edits = {
    ".gitlab-ci.yml": (r'(?m)^  APP_VERSION: "[0-9]+\.[0-9]+\.[0-9]+"$',
                       f'  APP_VERSION: "{new}"'),
    "packaging/alpine/APKBUILD": (r'(?m)^pkgver=[0-9]+\.[0-9]+\.[0-9]+$',
                                  f'pkgver={new}'),
    "packaging/amazon/pkcs11-proxy-ng.spec": (r'(?m)^Version:\s+[0-9]+\.[0-9]+\.[0-9]+\s*$',
                                              f'Version:        {new}'),
    "packaging/amazon/Dockerfile.amazon": (r'(?m)^ARG APP_VERSION=[0-9]+\.[0-9]+\.[0-9]+$',
                                           f'ARG APP_VERSION={new}'),
}
for path, (pattern, replacement) in edits.items():
    text = open(path).read()
    updated, count = re.subn(pattern, replacement, text, count=1)
    assert count == 1, f"mirror not rewritten: {path}"
    open(path, "w").write(updated)
EOF

# 4. README token.
python3 - "$NEW" <<'EOF'
import re, sys
new = sys.argv[1]
path = "README.md"
text = open(path).read()
pattern = r'(<!-- SYNC-VERSION -->)[0-9]+\.[0-9]+\.[0-9]+(<!-- /SYNC-VERSION -->)'
updated, count = re.subn(pattern, rf'\g<1>{new}\g<2>', text, count=1)
assert count == 1, "README token not found"
open(path, "w").write(updated)
EOF

# 5. Lockfiles (offline: version-only change needs no network).
cargo check --workspace --offline >/dev/null
(cd fuzz && cargo metadata --offline --format-version 1 >/dev/null)

# 6. Self-verify: read everything back through the checkers.
do_check
