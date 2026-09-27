#!/usr/bin/env bash
# Verify that the tag commit only records a receipt for its frozen parent.
# Runs from the current working directory for fixture repositories as well as CI.
set -euo pipefail

TAG="${1:-${GITHUB_REF_NAME:-}}"
TAG_VERSION="${TAG#v}"
TAG_VERSION="${TAG_VERSION%%-*}"
if [[ ! "$TAG_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::tag '$TAG' does not name a MAJOR.MINOR.PATCH version; refusing to release." >&2
  exit 1
fi
RECEIPT="doc/release/v${TAG_VERSION}-quality-receipt.md"
if [[ ! -f "$RECEIPT" ]]; then
  echo "::error::quality receipt $RECEIPT is missing; refusing to release." >&2
  exit 1
fi
SUBJECT_SHA="$(sed -nE 's/^subject_sha: ([0-9a-fA-F]+)$/\1/p' "$RECEIPT")"
SUBJECT_COMMIT="$(git rev-parse HEAD~1)"
TAG_COMMIT="$(git rev-parse HEAD)"
if [[ "$SUBJECT_SHA" != "$SUBJECT_COMMIT" ]]; then
  echo "::error::quality receipt subject_sha '$SUBJECT_SHA' does not equal frozen subject '$SUBJECT_COMMIT' (HEAD~1 of tag commit '$TAG_COMMIT'); refusing to release." >&2
  exit 1
fi
for gate in fmt check test clippy msrv audit deny release_dry_run; do
  value="$(sed -nE "s/^${gate}: (.*)$/\1/p" "$RECEIPT")"
  case "$value" in
    pass) ;;
    *)
      echo "::error::quality receipt gate '$gate' verdict is not exactly 'pass' (got '$value'); refusing to release." >&2
      exit 1
      ;;
  esac
done
DELTA_PATHS="$(git diff --name-only "$SUBJECT_COMMIT" "$TAG_COMMIT")"
while IFS= read -r path; do
  if [[ -z "$path" ]]; then continue; fi
  case "$path" in
    "$RECEIPT"|CHANGELOG.md) ;;
    *)
      echo "::error::tag commit '$TAG_COMMIT' changes '$path', outside the receipt/CHANGELOG bookkeeping delta; refusing to release." >&2
      exit 1
      ;;
  esac
done <<<"$DELTA_PATHS"
echo "quality receipt verified for subject $SUBJECT_COMMIT at tag commit $TAG_COMMIT"
