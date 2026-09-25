#!/usr/bin/env bash
# musl-dynamic-link-flags.sh — RUSTFLAGS for musl-dynamic links (T4).
#
# Serves every musl-target artifact that must NOT link statically: the
# shim cdylib (cdylib cannot link statically) and the musl-dynamic
# daemon (a static daemon cannot dlopen provider modules — musl
# answers "Dynamic loading not supported" — so the serving daemon
# stays musl-dynamic, the same shape the Alpine APKBUILD builds).
# Both build with `-C target-feature=-crt-static`. For that shape
# rustc passes an explicit dynamic `-lgcc_s`, but the cross musl-gcc
# wrapper (Debian/Ubuntu musl-tools) cannot resolve it: gcc's private
# libgcc_s.so is a linker script whose libgcc_s.so.1 target directory
# is not in musl-gcc's search path, so the link fails with ld
# "cannot find libgcc_s.so.1" (and `-static-libgcc` does not rewrite
# rustc's explicit `-lgcc_s`).
#
# This script materializes a linker-script redirect: a `libgcc_s.so`
# GROUP file resolving to gcc's STATIC libgcc.a plus the REAL
# libgcc_s.so.1 shared library (absolute path). Effects:
#   * arithmetic/frame routines come from the static archive;
#   * the unwinder (_Unwind_*) binds to libgcc_s.so.1, recording a
#     DT_NEEDED on its SONAME — the standard cdylib shape (the
#     native-Alpine APKBUILD shim carries the same NEEDED).
# Only `@@GCC_*` symbol versions are taken from the build-host
# libgcc_s (asserted below); its `libc.so.6` edge is transitive and
# does NOT transfer to the shim. At run time on Alpine the loader
# satisfies the SONAME with Alpine's musl-built libgcc_s
# (`apk add libgcc` — a documented runtime dependency), so the shim
# stays free of any glibc edge. The Alpine proof stage of
# scripts/run-musl-test.sh asserts exactly that (musl-only ldd, no
# libc.so.6) plus a full pkcs11-tool smoke on a glibc-less box.
#
# Rejected alternatives (see T4 work notes): GROUP(libgcc.a) alone
# leaves _Unwind_* undefined with no DT_NEEDED to load a provider
# (BIND_NOW load failure); adding libgcc_eh.a pulls its
# unwind-dw2-fde-dip.o, whose strong _dl_find_object reference
# (glibc>=2.35 only) makes the .so unloadable on musl.
#
# Usage:
#   RUSTFLAGS="$(scripts/musl-dynamic-link-flags.sh [LINK_DIR])" \
#       cargo build --release --target x86_64-unknown-linux-musl \
#           -p pkcs11-proxy-ng-shim
#
# LINK_DIR defaults to /tmp/musl-shim-link. The directory must stay
# alive for the duration of the build.

set -euo pipefail

LINK_DIR="${1:-${MUSL_SHIM_LINK_DIR:-/tmp/musl-shim-link}}"

command -v gcc >/dev/null 2>&1 || {
    echo "musl-dynamic-link-flags.sh: gcc not found (need its libgcc files)" >&2
    exit 2
}

LIBGCC_A="$(gcc -print-file-name=libgcc.a)"
[[ -f "$LIBGCC_A" ]] || {
    echo "musl-dynamic-link-flags.sh: static archive missing: $LIBGCC_A" >&2
    exit 2
}

# The real shared libgcc_s (absolute, symlink-resolved). Only its
# @@GCC_* unwind symbols are consumed; see the header comment.
LIBGCC_S_SO1="$(readlink -f "$(gcc -print-file-name=libgcc_s.so.1)")"
[[ -f "$LIBGCC_S_SO1" ]] || {
    echo "musl-dynamic-link-flags.sh: shared libgcc missing: $LIBGCC_S_SO1" >&2
    exit 2
}
command -v readelf >/dev/null 2>&1 || {
    echo "musl-dynamic-link-flags.sh: readelf not found (need binutils for the SONAME check)" >&2
    exit 2
}
readelf -d "$LIBGCC_S_SO1" | grep -q "SONAME.*libgcc_s.so.1" || {
    echo "musl-dynamic-link-flags.sh: not a libgcc_s: $LIBGCC_S_SO1" >&2
    exit 2
}

mkdir -p "$LINK_DIR"
printf 'GROUP ( %s %s )\n' "$LIBGCC_A" "$LIBGCC_S_SO1" >"$LINK_DIR/libgcc_s.so"

printf '%s' "-C target-feature=-crt-static -C link-arg=-L$LINK_DIR"
