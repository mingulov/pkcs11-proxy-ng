#!/usr/bin/env bash
# Compatibility entrypoint; descriptor-safe collection lives in Python stdlib.

set -euo pipefail

SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
if [[ "$SCRIPT_DIR" == "${BASH_SOURCE[0]}" ]]; then
    SCRIPT_DIR="."
fi
SCRIPT_DIR="$(cd -- "$SCRIPT_DIR" && pwd -P)"

exec python3 "$SCRIPT_DIR/collect_debug_bundle.py" "$@"
