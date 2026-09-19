#!/usr/bin/env bash
#
# Fixture battery for the release.yml "Verify quality receipt" step (G-3).
#
# The battery extracts the step's `run` block from
# .github/workflows/release.yml and executes that exact text against fixture
# git topologies, so it always tests the shipped step (no logic duplicate
# that can drift). Cases:
#   real-topology  current worktree passes (valid only at a tag candidate:
#                  receipt subject_sha == HEAD~1, top diff receipt/CHANGELOG-only)
#   synthetic-pass HEAD names HEAD~1, all gates pass, receipt-only top diff -> 0
#   stale-subject  receipt names HEAD~2 -> 1 (SHA mismatch refusal)
#   non-pass-gate  one gate not pass-prefixed -> 1 (gate refusal)
#   code-in-delta  top diff touches a code file -> 1 (delta refusal)
#   missing-receipt no receipt file -> 1 (missing refusal)
#
# Every synthetic case runs in a fresh temp git repo; the worktree is never
# modified. Exit 0 only if every case behaves as specified.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$REPO/.github/workflows/release.yml"
STEP_NAME="Verify quality receipt"
RECEIPT_REL="doc/release/v0.2.0-quality-receipt.md"

extract_step() {
  awk -v name="$STEP_NAME" '
    $0 == "      - name: " name { in_step = 1; next }
    in_step && /^      - name: / { exit }
    in_step && /^          / { sub(/^          /, ""); print }
  ' "$WORKFLOW"
}

STEP="$(extract_step)"
# Fail closed if the extraction missed (e.g. YAML reindented): the battery
# must never execute a truncated step and call it a pass.
for anchor in 'subject_sha' 'HEAD~1' 'release_dry_run' 'git diff --name-only'; do
  if ! grep -qF "$anchor" <<<"$STEP"; then
    echo "battery error: extracted step is missing '$anchor'; refusing to run." >&2
    exit 2
  fi
done

g() {
  git -c user.name=fixture -c user.email=fixture@example.com \
      -c commit.gpgsign=false -c init.defaultBranch=main "$@"
}

new_repo() {
  local dir
  dir="$(mktemp -d)"
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
    echo "fmt: pass (fixture)"
    echo "check: pass (fixture)"
    echo "test: pass 1/0/0 (fixture)"
    echo "clippy: pass (fixture)"
    echo "msrv: pass (fixture)"
    echo "audit: pass 0 vulns / 0 warnings (fixture)"
    echo "deny: pass (fixture)"
    echo "release_dry_run: pass (fixture)"
  } >"$dir/$RECEIPT_REL"
  local override name value
  for override in "$@"; do
    name="${override%%:*}"
    value="${override#*: }"
    sed -i -E "s|^${name}: .*$|${name}: ${value}|" "$dir/$RECEIPT_REL"
  done
}

run_step() {
  (cd "$1" && bash -c "$STEP")
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

# Case: real freeze topology — the current worktree must pass.
expect "real-topology" 0 "quality receipt verified for subject" "$REPO"

# Case: synthetic pass — docs-only refresh atop a content commit.
D="$(new_repo)"
mkdir -p "$D/doc/release"
echo "fn main() {}" >"$D/src.rs"
g -C "$D" add src.rs && g -C "$D" commit -qm "content"
C1="$(g -C "$D" rev-parse HEAD)"
write_receipt "$D" "$C1"
g -C "$D" add "$RECEIPT_REL" && g -C "$D" commit -qm "refresh"
expect "synthetic-pass" 0 "quality receipt verified for subject" "$D"

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

# Case: non-pass gate — top diff and SHA are fine, one gate fails.
D="$(new_repo)"
mkdir -p "$D/doc/release"
echo "v1" >"$D/src.rs"
g -C "$D" add src.rs && g -C "$D" commit -qm "content"
C1="$(g -C "$D" rev-parse HEAD)"
write_receipt "$D" "$C1" "test: fail 0/1/0 (fixture)"
g -C "$D" add "$RECEIPT_REL" && g -C "$D" commit -qm "refresh"
expect "non-pass-gate" 1 "gate 'test' is not pass-prefixed" "$D"

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
