#!/usr/bin/env bash
# Report pkcs11test filter coverage statistics
set -euo pipefail

FILTER_FILE="${1:-$(dirname "$0")/pkcs11test-filter.txt}"

total=$(grep -cE '^[^#[:space:]]' "$FILTER_FILE" || true)
categories=$(grep -cE '^\*\.' "$FILTER_FILE" 2>/dev/null || true)
wildcards=$(grep -cE '/\*$' "$FILTER_FILE" || true)
exact=$(( total - wildcards ))

echo "pkcs11test filter coverage:"
echo "  Total entries: $total"
echo "  Wildcard patterns: $wildcards"
echo "  Exact test names: $exact"
echo ""
echo "Test categories covered:"
grep -oP '^[A-Za-z]+(?=[\./])' "$FILTER_FILE" | sort -u | sed 's/^/  - /'
