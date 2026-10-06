#!/usr/bin/env bash
# Upload staged release assets with retries.
#
# Replaces softprops/action-gh-release, whose fixed 10s connect timeout
# and lack of retries failed v0.2.2 on a transient uploads.github.com
# stall (neither the action nor gh expose a timeout knob). Semantics
# mirror the old step: create-or-extend the tag release, upload exactly
# the staged files, touch nothing else. The compare step already proved
# the staged files missing-only (divergent bytes refuse there), so
# re-uploading after a mid-batch stall only ever rewrites identical
# bytes via --clobber; gh uploads sequentially, which is gentler on
# the flaky endpoint than the old parallel fan-out.
#
# Env in: RELEASE_TAG (required), RELEASE_TITLE (required),
# RELEASE_NOTES (required notes file), STAGE_DIR (default stage).
# UPLOAD_ATTEMPTS (default 5), UPLOAD_WINDOW (default 600, per-attempt
# seconds), UPLOAD_BACKOFF (default 15, linear base seconds) tune retries.
set -euo pipefail

: "${RELEASE_TAG:?RELEASE_TAG must be set}"
: "${RELEASE_TITLE:?RELEASE_TITLE must be set}"
: "${RELEASE_NOTES:?RELEASE_NOTES must be set}"
STAGE_DIR="${STAGE_DIR:-stage}"
UPLOAD_ATTEMPTS="${UPLOAD_ATTEMPTS:-5}"
UPLOAD_WINDOW="${UPLOAD_WINDOW:-600}"
UPLOAD_BACKOFF="${UPLOAD_BACKOFF:-15}"

for tool in gh timeout; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: need $tool on PATH" >&2
        exit 1
    fi
done
if [ ! -s "$RELEASE_NOTES" ]; then
    echo "error: release notes file $RELEASE_NOTES missing or empty" >&2
    exit 1
fi

if ! gh release view "$RELEASE_TAG" >/dev/null 2>&1; then
    # A parallel publish may win the create race; re-check before failing.
    gh release create "$RELEASE_TAG" --title "$RELEASE_TITLE" \
        --notes-file "$RELEASE_NOTES" \
        || gh release view "$RELEASE_TAG" >/dev/null 2>&1
fi

shopt -s nullglob
FILES=("$STAGE_DIR"/*.tar.gz "$STAGE_DIR"/*.zip "$STAGE_DIR"/*.json)
if [ "${#FILES[@]}" -eq 0 ]; then
    echo "::error::no staged files in $STAGE_DIR (compare gated this step non-empty)" >&2
    exit 1
fi

attempt=1
while [ "$attempt" -le "$UPLOAD_ATTEMPTS" ]; do
    if timeout "$UPLOAD_WINDOW" gh release upload "$RELEASE_TAG" "${FILES[@]}" --clobber; then
        echo "upload succeeded on attempt $attempt (${#FILES[@]} files)"
        exit 0
    fi
    if [ "$attempt" -eq "$UPLOAD_ATTEMPTS" ]; then
        echo "::error::release upload failed after $UPLOAD_ATTEMPTS attempts" >&2
        exit 1
    fi
    sleep $((attempt * UPLOAD_BACKOFF))
    attempt=$((attempt + 1))
done
