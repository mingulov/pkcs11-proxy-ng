#!/usr/bin/env bash
#
# Fixture battery for the shared release receipt guard (G-3).
#
# The battery executes the shipped helper against fixture git topologies.
# Optional --real checks the current worktree (valid only at a tag candidate:
#                  receipt subject_sha == HEAD~1, top diff receipt/CHANGELOG-only)
# Cases:
#   synthetic-pass HEAD names HEAD~1, all gates pass, receipt-only top diff -> 0
#   changelog-in-delta top diff touches receipt + CHANGELOG.md -> 0
#   stale-subject  receipt names HEAD~2 -> 1 (SHA mismatch refusal)
#   malformed-receipt receipt present but no subject_sha line -> 1 (SHA refusal)
#   non-pass-gate  one gate not exactly pass -> 1 (gate refusal)
#   pass-then-fail one gate 'pass-then-fail ...' -> 1 (anchored verdict refusal)
#   pass-paren     one gate 'pass (x)' detail suffix -> 1 (anchored verdict refusal)
#   multiline-gate duplicate gate line (multiline value) -> 1 (verdict refusal)
#   exact-pass     every gate exactly 'pass' -> 0
#   version-param-v030  GITHUB_REF_NAME=v0.3.0 resolves the v0.3.0 receipt -> 0
#   version-param-suffix GITHUB_REF_NAME=v0.3.0-rc1 resolves v0.3.0 receipt -> 0
#   version-param-missing tag v0.3.0 with only a v0.2.0 receipt -> 1 (missing)
#   code-in-delta  top diff touches a code file -> 1 (delta refusal)
#   missing-receipt no receipt file -> 1 (missing refusal)
#
# Every synthetic case runs in a fresh temp git repo; the worktree is never
# modified. Fixture repos are removed on exit via a trap. Exit 0 only if
# every case behaves as specified.
set -euo pipefail

# Fixture-repo cleanup: new_repo() runs inside command substitution (a
# subshell), so an in-memory list would not propagate to the parent — track
# the temp dirs in a file instead and remove them on EXIT.
FIXTURE_LIST="$(mktemp)"
cleanup_fixtures() {
  if [[ -s "$FIXTURE_LIST" ]]; then
    xargs -r rm -rf <"$FIXTURE_LIST"
  fi
  rm -f "$FIXTURE_LIST"
}
trap cleanup_fixtures EXIT

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$REPO/scripts/verify-quality-receipt.sh"
# W1-L17-02: the helper derives the receipt path from its tag argument, so the
# battery pins the tag per case (default v0.2.0) and derives the receipt
# path the same way (strip leading v and any -suffix).
FIXTURE_TAG="v0.2.0"
RECEIPT_REL="doc/release/v0.2.0-quality-receipt.md"
set_fixture_tag() {
  FIXTURE_TAG="$1"
  local version="${FIXTURE_TAG#v}"
  version="${version%%-*}"
  RECEIPT_REL="doc/release/v${version}-quality-receipt.md"
}

if [[ ! -x "$HELPER" ]]; then
  echo "battery error: receipt helper is not executable: $HELPER" >&2
  exit 2
fi

g() {
  git -c user.name=fixture -c user.email=fixture@example.com \
      -c commit.gpgsign=false -c init.defaultBranch=main "$@"
}

new_repo() {
  local dir
  dir="$(mktemp -d)"
  echo "$dir" >>"$FIXTURE_LIST"
  g -C "$dir" init -q
  echo "$dir"
}

# write_receipt <dir> <subject-sha> [gate-overrides... as "name: value"]
write_receipt() {
  local dir="$1" subject="$2"
  shift 2
  {
    echo "# v0.2.0 quality receipt"
    echo ""
    echo "subject_sha: $subject"
    echo "fmt: pass"
    echo "check: pass"
    echo "test: pass"
    echo "clippy: pass"
    echo "msrv: pass"
    echo "audit: pass"
    echo "deny: pass"
    echo "release_dry_run: pass"
  } >"$dir/$RECEIPT_REL"
  local override name value
  for override in "$@"; do
    name="${override%%:*}"
    value="${override#*: }"
    sed -i -E "s|^${name}: .*$|${name}: ${value}|" "$dir/$RECEIPT_REL"
  done
}

run_step() {
  (cd "$1" && "$HELPER" "$FIXTURE_TAG")
}

PASS=0
FAIL=0

expect() {
  local case="$1" want_exit="$2" want_text="$3" dir="$4"
  local got_exit=0 output=""
  output="$(run_step "$dir" 2>&1)" || got_exit=$?
  if [[ "$got_exit" != "$want_exit" ]]; then
    echo "FAIL $case: exit $got_exit, want $want_exit"
    echo "$output" | head -5
    FAIL=$((FAIL + 1))
    return 0
  fi
  if [[ -n "$want_text" ]] && ! grep -qF "$want_text" <<<"$output"; then
    echo "FAIL $case: exit $got_exit but output lacks '$want_text'"
    echo "$output" | head -5
    FAIL=$((FAIL + 1))
    return 0
  fi
  echo "ok $case: exit $got_exit"
  echo "$output" | head -2 | sed 's/^/    /'
  PASS=$((PASS + 1))
}

if [[ "${1:-}" == "--real" ]]; then
  expect "real-topology" 0 "quality receipt verified for subject" "$REPO"
elif [[ $# -ne 0 ]]; then
  echo "usage: $0 [--real]" >&2
  exit 2
fi

# Case: synthetic pass — docs-only refresh atop a content commit.
D="$(new_repo)"
mkdir -p "$D/doc/release"
echo "fn main() {}" >"$D/src.rs"
g -C "$D" add src.rs && g -C "$D" commit -qm "content"
C1="$(g -C "$D" rev-parse HEAD)"
write_receipt "$D" "$C1"
g -C "$D" add "$RECEIPT_REL" && g -C "$D" commit -qm "refresh"
expect "synthetic-pass" 0 "quality receipt verified for subject" "$D"

# Case: CHANGELOG in the tag-commit delta — exercises the CHANGELOG arm of
# the receipt/CHANGELOG allowlist; must pass.
D="$(new_repo)"
mkdir -p "$D/doc/release"
echo "v1" >"$D/src.rs"
echo "# changelog" >"$D/CHANGELOG.md"
g -C "$D" add src.rs CHANGELOG.md && g -C "$D" commit -qm "content"
C1="$(g -C "$D" rev-parse HEAD)"
write_receipt "$D" "$C1"
echo "more" >>"$D/CHANGELOG.md"
g -C "$D" add "$RECEIPT_REL" CHANGELOG.md && g -C "$D" commit -qm "refresh+changelog"
expect "changelog-in-delta" 0 "quality receipt verified for subject" "$D"

# Case: stale subject — receipt names HEAD~2 instead of HEAD~1.
D="$(new_repo)"
mkdir -p "$D/doc/release"
echo "v1" >"$D/src.rs"
g -C "$D" add src.rs && g -C "$D" commit -qm "content 1"
STALE="$(g -C "$D" rev-parse HEAD)"
echo "v2" >"$D/src.rs"
g -C "$D" commit -qam "content 2"
write_receipt "$D" "$STALE"
g -C "$D" add "$RECEIPT_REL" && g -C "$D" commit -qm "refresh"
expect "stale-subject" 1 "does not equal frozen subject" "$D"

# Case: malformed receipt — file present but no subject_sha line, so the
# extracted SHA is empty and must mismatch the frozen subject.
D="$(new_repo)"
mkdir -p "$D/doc/release"
echo "v1" >"$D/src.rs"
g -C "$D" add src.rs && g -C "$D" commit -qm "content"
C1="$(g -C "$D" rev-parse HEAD)"
write_receipt "$D" "$C1"
sed -i '/^subject_sha: /d' "$D/$RECEIPT_REL"
g -C "$D" add "$RECEIPT_REL" && g -C "$D" commit -qm "refresh"
expect "malformed-receipt" 1 "does not equal frozen subject" "$D"

# Case: non-pass gate — top diff and SHA are fine, one gate fails.
D="$(new_repo)"
mkdir -p "$D/doc/release"
echo "v1" >"$D/src.rs"
g -C "$D" add src.rs && g -C "$D" commit -qm "content"
C1="$(g -C "$D" rev-parse HEAD)"
write_receipt "$D" "$C1" "test: fail 0/1/0 (fixture)"
g -C "$D" add "$RECEIPT_REL" && g -C "$D" commit -qm "refresh"
expect "non-pass-gate" 1 "verdict is not exactly 'pass'" "$D"

# Case: pass-then-fail gate — the unanchored `pass*)` glob accepts this;
# the anchored verdict must refuse it.
D="$(new_repo)"
mkdir -p "$D/doc/release"
echo "v1" >"$D/src.rs"
g -C "$D" add src.rs && g -C "$D" commit -qm "content"
C1="$(g -C "$D" rev-parse HEAD)"
write_receipt "$D" "$C1" "test: pass-then-fail 0/1/0 (fixture)"
g -C "$D" add "$RECEIPT_REL" && g -C "$D" commit -qm "refresh"
expect "pass-then-fail" 1 "verdict is not exactly 'pass'" "$D"

# Case: pass-with-detail gate — a `pass (x)` suffix must also be refused;
# only the exact single-line verdict `pass` is accepted.
D="$(new_repo)"
mkdir -p "$D/doc/release"
echo "v1" >"$D/src.rs"
g -C "$D" add src.rs && g -C "$D" commit -qm "content"
C1="$(g -C "$D" rev-parse HEAD)"
write_receipt "$D" "$C1"
sed -i -E "s|^fmt: .*$|fmt: pass (x)|" "$D/$RECEIPT_REL"
g -C "$D" add "$RECEIPT_REL" && g -C "$D" commit -qm "refresh"
expect "pass-paren" 1 "verdict is not exactly 'pass'" "$D"

# Case: multiline gate value — a duplicate gate line makes the extracted
# value multiline; the anchored single-line verdict must refuse it.
D="$(new_repo)"
mkdir -p "$D/doc/release"
echo "v1" >"$D/src.rs"
g -C "$D" add src.rs && g -C "$D" commit -qm "content"
C1="$(g -C "$D" rev-parse HEAD)"
write_receipt "$D" "$C1"
echo "test: fail (injected second line)" >>"$D/$RECEIPT_REL"
g -C "$D" add "$RECEIPT_REL" && g -C "$D" commit -qm "refresh"
expect "multiline-gate" 1 "verdict is not exactly 'pass'" "$D"

# Case: exact pass — every gate is exactly `pass`; must be accepted.
D="$(new_repo)"
mkdir -p "$D/doc/release"
echo "v1" >"$D/src.rs"
g -C "$D" add src.rs && g -C "$D" commit -qm "content"
C1="$(g -C "$D" rev-parse HEAD)"
write_receipt "$D" "$C1"
sed -i -E "s/^(fmt|check|test|clippy|msrv|audit|deny|release_dry_run): .*$/\1: pass/" "$D/$RECEIPT_REL"
g -C "$D" add "$RECEIPT_REL" && g -C "$D" commit -qm "refresh"
expect "exact-pass" 0 "quality receipt verified for subject" "$D"

# Case: version-parameterized receipt — a v0.3.0-style tag resolves its own
# receipt path (and delta allowlist) with no workflow edit.
set_fixture_tag v0.3.0
D="$(new_repo)"
mkdir -p "$D/doc/release"
echo "v1" >"$D/src.rs"
g -C "$D" add src.rs && g -C "$D" commit -qm "content"
C1="$(g -C "$D" rev-parse HEAD)"
write_receipt "$D" "$C1"
g -C "$D" add "$RECEIPT_REL" && g -C "$D" commit -qm "refresh"
expect "version-param-v030" 0 "quality receipt verified for subject" "$D"

# Case: suffixed tag — v0.3.0-rc1 resolves the v0.3.0 receipt (suffix
# stripped, same rule as verify-release-subject.sh).
set_fixture_tag v0.3.0-rc1
D="$(new_repo)"
mkdir -p "$D/doc/release"
echo "v1" >"$D/src.rs"
g -C "$D" add src.rs && g -C "$D" commit -qm "content"
C1="$(g -C "$D" rev-parse HEAD)"
write_receipt "$D" "$C1"
g -C "$D" add "$RECEIPT_REL" && g -C "$D" commit -qm "refresh"
expect "version-param-suffix" 0 "quality receipt verified for subject" "$D"

# Case: wrong-version receipt only — tag v0.3.0 with just a v0.2.0 receipt
# present must refuse (missing), proving the path follows the tag.
set_fixture_tag v0.3.0
D="$(new_repo)"
mkdir -p "$D/doc/release"
echo "v1" >"$D/src.rs"
g -C "$D" add src.rs && g -C "$D" commit -qm "content"
C1="$(g -C "$D" rev-parse HEAD)"
RECEIPT_REL="doc/release/v0.2.0-quality-receipt.md" write_receipt "$D" "$C1"
g -C "$D" add doc/release/v0.2.0-quality-receipt.md && g -C "$D" commit -qm "refresh"
expect "version-param-missing" 1 "is missing; refusing to release" "$D"
set_fixture_tag v0.2.0

# Case: code file in the tag-commit delta — SHA and gates fine.
D="$(new_repo)"
mkdir -p "$D/doc/release"
echo "v1" >"$D/src.rs"
g -C "$D" add src.rs && g -C "$D" commit -qm "content"
C1="$(g -C "$D" rev-parse HEAD)"
write_receipt "$D" "$C1"
echo "v2" >"$D/src.rs"
g -C "$D" add "$RECEIPT_REL" src.rs && g -C "$D" commit -qm "refresh+code"
expect "code-in-delta" 1 "outside the receipt/CHANGELOG bookkeeping delta" "$D"

# Case: missing receipt — CHANGELOG-only top diff, no receipt file.
D="$(new_repo)"
echo "v1" >"$D/src.rs"
echo "# changelog" >"$D/CHANGELOG.md"
g -C "$D" add src.rs CHANGELOG.md && g -C "$D" commit -qm "content"
echo "more" >>"$D/CHANGELOG.md"
g -C "$D" commit -qam "changelog"
expect "missing-receipt" 1 "is missing; refusing to release" "$D"

echo "battery: $PASS passed, $FAIL failed"
[[ "$FAIL" == 0 ]]
