#!/usr/bin/env bash
# Regression: harness SoftHSM2 discovery must survive absence under `set -e`.
#
# Defect: the locators ended with a `for` loop whose last probe failed
# when no module was installed, so the function returned 1 and any
# caller under `set -e` died silently (no SKIP, no error). Fixed with
# an explicit `return 0` plus a pre-export override; the probe loop
# itself lives in `harness_first_existing` so the absent/present
# behaviour is unit-testable without depending on machine paths.
#
# Method note: this script itself runs under `set -e`, so any
# set-e-unsafety in the harness kills the test exactly as it killed
# production callers. Progress lines show how far it got.
#
# Acceptance:
#   * `harness_first_existing` prints the first existing candidate and
#     returns 0; with no hit it prints nothing and still returns 0 —
#     even inside a `set -e` caller (the killer property).
#   * The 64/32 locators honour a pre-exported override as-is.
#   * The 64/32 locators return 0 with a sane value ("" or a file).
#   * Dependency closure validation accepts resolved modules and rejects a
#     missing shared object with the unresolved name in its diagnostic, and
#     reports an `ldd` inspection failure without accepting the module.
#
# Pure shell, no tooling needed: safe in the live tier everywhere.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib/live-harness.sh"

TDIR="$(mktemp -d)"
trap 'rm -rf "$TDIR"' EXIT
touch "$TDIR/second.so"

# 1. Helper: first hit wins.
[[ "$(harness_first_existing "$TDIR/missing.so" "$TDIR/second.so")" == "$TDIR/second.so" ]]
echo "ok: first existing candidate wins"

# 2. Helper: no hit prints nothing but still returns 0.
[[ -z "$(harness_first_existing "$TDIR/nope-a.so" "$TDIR/nope-b.so")" ]]
echo "ok: no hit prints nothing"
harness_first_existing "$TDIR/nope-a.so" >/dev/null
echo "ok: no hit still returns 0"

# 3. The killer property: a `set -e` caller survives absence.
set_e_survives_absence() {
    set -e
    harness_first_existing "$TDIR/nope-a.so" >/dev/null
    echo survived
}
[[ "$(set_e_survives_absence)" == "survived" ]]
echo "ok: absent probe survives under set -e"

# 4. Locators honour a pre-exported override without probing.
SOFTHSM_MODULE_64="/custom/extracted/libsofthsm2.so"
harness_locate_softhsm64
[[ "$SOFTHSM_MODULE_64" == "/custom/extracted/libsofthsm2.so" ]]
echo "ok: 64-bit locator honours override"
SOFTHSM_MODULE_32="/custom/extracted32/libsofthsm2.so"
harness_locate_softhsm32
[[ "$SOFTHSM_MODULE_32" == "/custom/extracted32/libsofthsm2.so" ]]
echo "ok: 32-bit locator honours override"

# 5. Locators return 0 with a sane value on this machine.
unset SOFTHSM_MODULE_64 SOFTHSM_MODULE_32
harness_locate_softhsm64
[[ -z "$SOFTHSM_MODULE_64" || -f "$SOFTHSM_MODULE_64" ]]
echo "ok: 64-bit locator returns 0 with sane value ($SOFTHSM_MODULE_64)"
harness_locate_softhsm32
[[ -z "$SOFTHSM_MODULE_32" || -f "$SOFTHSM_MODULE_32" ]]
echo "ok: 32-bit locator returns 0 with sane value ($SOFTHSM_MODULE_32)"

# 6. Provider dependency closure fails before daemon startup. Shadow ldd so
# the parser is deterministic and independent of this host's architecture.
mkdir -p "$TDIR/bin"
touch "$TDIR/module.so"
cat > "$TDIR/bin/ldd" <<'EOF'
#!/usr/bin/env bash
if [[ "${HARNESS_TEST_LDD_MODE:-resolved}" == "error" ]]; then
    echo "synthetic ldd inspection failure" >&2
    exit 1
elif [[ "${HARNESS_TEST_LDD_MODE:-resolved}" == "missing" ]]; then
    cat <<'OUTPUT'
libcrypto.so.3 => not found
libstdc++.so.6 => /lib/libstdc++.so.6 (0xf00)
OUTPUT
else
    cat <<'OUTPUT'
libcrypto.so.3 => /lib/libcrypto.so.3 (0xf00)
libstdc++.so.6 => /lib/libstdc++.so.6 (0xf01)
OUTPUT
fi
EOF
chmod +x "$TDIR/bin/ldd"

PATH="$TDIR/bin:$PATH" HARNESS_TEST_LDD_MODE=resolved \
    harness_require_resolved_dependencies "$TDIR/module.so" "test module"
echo "ok: resolved dependency closure accepted"

if PATH="$TDIR/bin:$PATH" HARNESS_TEST_LDD_MODE=missing \
    harness_require_resolved_dependencies "$TDIR/module.so" "test module" \
    >"$TDIR/missing.out" 2>&1; then
    echo "FAIL: unresolved dependency closure was accepted" >&2
    exit 1
fi
grep -q "libcrypto.so.3 => not found" "$TDIR/missing.out"
echo "ok: unresolved dependency closure rejected with diagnostic"

if PATH="$TDIR/bin:$PATH" HARNESS_TEST_LDD_MODE=error \
    harness_require_resolved_dependencies "$TDIR/module.so" "test module" \
    >"$TDIR/error.out" 2>&1; then
    echo "FAIL: failed dependency inspection was accepted" >&2
    exit 1
fi
grep -q "unable to inspect shared-library dependencies" "$TDIR/error.out"
grep -q "synthetic ldd inspection failure" "$TDIR/error.out"
echo "ok: failed dependency inspection rejected with diagnostic"

echo
echo "LOCATORS PASS"
