#!/usr/bin/env bash
# run-musl-test.sh — musl build + Alpine proof without tribal knowledge (T4).
#
# Builds the release bundle for x86_64-unknown-linux-musl and proves
# the artifacts execute natively on Alpine (no glibc). Two build
# modes, like run-be-qemu-test.sh:
#   * host mode: used when the host already has the musl target and
#     musl-gcc installed (rustup + musl-tools route);
#   * docker mode (default fallback): builds/uses the Dockerfile.musl
#     image, which carries the whole toolchain. Force it with
#     MUSL_MODE=docker; force host mode with MUSL_MODE=host.
#
# The Alpine proof stage always uses docker (stock alpine:<ver>
# container); --build-only skips it.
#
# Linkage split (see doc/release/musl-tier.md for the full tier table):
#   * daemon + CLI build FULLY STATIC first (the static route);
#   * the shim cdylib and a second daemon build stay MUSL-DYNAMIC
#     (`-C target-feature=-crt-static` via
#     scripts/musl-dynamic-link-flags.sh). The dynamic daemon is the
#     serving shape: a static binary cannot dlopen provider modules
#     (musl answers "Dynamic loading not supported"), so only the
#     dynamic daemon can boot against a backend — the same shape the
#     Alpine APKBUILD ships. The CLI never dlopens, so the static CLI
#     drives the whole live smoke.
#
# What runs:
#   1. cargo build --release --target x86_64-unknown-linux-musl of the
#      daemon + CLI (fully static binaries) — the exact CI-leg commands.
#   2. Same-target release build of the shim cdylib (musl-dynamic .so).
#   3. Same-target release build of the musl-dynamic daemon (the
#      serving shape); the static daemon is preserved alongside.
#   4. `file` receipts: static daemon + CLI must report static linkage
#      with no interpreter; dynamic daemon + shim must resolve to the
#      musl loader.
#   5. Alpine proof (amd64, no glibc): --version for all three
#      binaries; a negative receipt that the static daemon cannot load
#      a backend (musl limitation, asserted load-bearingly); dynamic
#      daemon boot against a SoftHSM2 backend; CLI-driven live ops
#      (list-slots, token-info) from the STATIC CLI; and the full
#      SoftHSM2 shim smoke (pkcs11-tool through the musl shim .so:
#      slot list, RSA-2048 keygen, SHA256-RSA-PKCS sign).
#
# Environment:
#   MUSL_MODE          host | docker | auto (default: auto)
#   MUSL_IMAGE         docker image tag (default: pkcs11-proxy-ng-musl)
#   MUSL_CARGO_VOLUME  named volume for the cargo cache (docker mode)
#   MUSL_TARGET_VOLUME named volume for the musl target dir (docker mode)
#   MUSL_STAGE_DIR     host dir receiving the staged artifacts
#                      (default: fresh mktemp dir, removed afterwards
#                      unless MUSL_KEEP_STAGE=1)
#   MUSL_KEEP_STAGE    1 keeps the staged artifacts for inspection
#   MUSL_ALPINE_VER    Alpine version for the proof stage (default: 3.23)
#
# The docker build mounts the workspace read-only and keeps all build
# output in containers/volumes, so the host tree is never dirtied.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="x86_64-unknown-linux-musl"
IMAGE="${MUSL_IMAGE:-pkcs11-proxy-ng-musl}"
MODE="${MUSL_MODE:-auto}"
ALPINE_VER="${MUSL_ALPINE_VER:-3.23}"

build_only=0
quick=0

usage() {
    cat <<'EOF'
Usage: scripts/run-musl-test.sh [options]

Options:
  --build-only          Build + file receipts only; skip the Alpine proof stage
  --quick               Alpine smoke without the RSA keygen + sign steps
  -h, --help            Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-only)
            build_only=1
            ;;
        --quick)
            quick=1
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

host_has_tooling() {
    command -v cargo >/dev/null 2>&1 \
        && command -v rustc >/dev/null 2>&1 \
        && rustup target list --installed 2>/dev/null | grep "$TARGET" >/dev/null \
        && command -v musl-gcc >/dev/null 2>&1 \
        && command -v protoc >/dev/null 2>&1
}

resolve_runner() {
    case "$MODE" in
        host)
            if ! host_has_tooling; then
                echo "MUSL_MODE=host but the host lacks the musl toolchain." >&2
                echo "Install: rustup target add $TARGET, musl-tools," >&2
                echo "protobuf-compiler, and set the target linker/CC, or unset" >&2
                echo "MUSL_MODE to use docker mode." >&2
                exit 2
            fi
            echo "host"
            ;;
        docker)
            echo "docker"
            ;;
        auto)
            if host_has_tooling; then
                echo "host"
            else
                echo "docker"
            fi
            ;;
        *)
            echo "unknown MUSL_MODE: $MODE (want host|docker|auto)" >&2
            exit 2
            ;;
    esac
}

RUN_MODE="$(resolve_runner)"
echo "[musl] build mode: $RUN_MODE (target $TARGET)"

if [[ "$RUN_MODE" == "docker" ]]; then
    if ! command -v docker >/dev/null 2>&1; then
        echo "docker mode needs the docker CLI." >&2
        exit 2
    fi
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        echo "[musl] building image $IMAGE ..."
        docker build -f "$ROOT_DIR/Dockerfile.musl" -t "$IMAGE" "$ROOT_DIR"
    fi
    CARGO_VOLUME="${MUSL_CARGO_VOLUME:-musl-cargo-cache}"
    TARGET_VOLUME="${MUSL_TARGET_VOLUME:-musl-target}"
    # shellcheck disable=SC2086
    musl_cargo() {
        docker run --rm \
            -v "$ROOT_DIR:/workspace:ro" \
            -v "$CARGO_VOLUME:/root/.cargo" \
            -v "$TARGET_VOLUME:/tmp/musl-target" \
            -e CARGO_TARGET_DIR=/tmp/musl-target \
            ${MUSL_EXTRA_DOCKER_ARGS:-} \
            "$IMAGE" \
            cargo "$@"
    }
    # shellcheck disable=SC2086
    musl_cmd() {
        docker run --rm \
            -v "$ROOT_DIR:/workspace:ro" \
            -v "$CARGO_VOLUME:/root/.cargo" \
            -v "$TARGET_VOLUME:/tmp/musl-target" \
            -e CARGO_TARGET_DIR=/tmp/musl-target \
            ${MUSL_EXTRA_DOCKER_ARGS:-} \
            "$IMAGE" \
            "$@"
    }
    # Same as musl_cargo but with the musl-dynamic RUSTFLAGS (expanded
    # at call time; DYNAMIC_RUSTFLAGS is set in step 2 below).
    # shellcheck disable=SC2086
    musl_cargo_dynamic() {
        docker run --rm \
            -v "$ROOT_DIR:/workspace:ro" \
            -v "$CARGO_VOLUME:/root/.cargo" \
            -v "$TARGET_VOLUME:/tmp/musl-target" \
            -e CARGO_TARGET_DIR=/tmp/musl-target \
            -e RUSTFLAGS="$DYNAMIC_RUSTFLAGS" \
            ${MUSL_EXTRA_DOCKER_ARGS:-} \
            "$IMAGE" \
            cargo "$@"
    }
    RELEASE_DIR="/tmp/musl-target/$TARGET/release"
    STATIC_SAVE_DIR="/tmp/musl-target/$TARGET/static-save"
    DYNAMIC_LINK_DIR="/tmp/musl-target/musl-dynamic-link"
    RELEASE_DIR_DESC="in $IMAGE ($TARGET_VOLUME volume)"
else
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER:-musl-gcc}"
    export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-musl-gcc}"
    musl_cargo() {
        (cd "$ROOT_DIR" && cargo "$@")
    }
    musl_cargo_dynamic() {
        (cd "$ROOT_DIR" && RUSTFLAGS="$DYNAMIC_RUSTFLAGS" cargo "$@")
    }
    musl_cmd() {
        (cd "$ROOT_DIR" && "$@")
    }
    RELEASE_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/target}/$TARGET/release"
    STATIC_SAVE_DIR="$(dirname "$RELEASE_DIR")/static-save"
    DYNAMIC_LINK_DIR=""
    RELEASE_DIR_DESC="under $RELEASE_DIR"
fi

cd "$ROOT_DIR"

echo "[musl] toolchain provenance:"
musl_cmd rustc --version
# No `| head -1` here: under pipefail an early-closing pipe consumer
# can SIGPIPE a still-writing producer and fail the run (same reason
# all `| grep -q` uses below grep a capture instead of the live pipe).
MUSL_GCC_V="$(musl_cmd musl-gcc --version)"
echo "${MUSL_GCC_V%%$'\n'*}"
musl_cmd protoc --version

echo "[musl] (1/5) building release daemon + CLI for $TARGET (static) ..."
musl_cargo build --release --target "$TARGET" \
    -p pkcs11-proxy-ng -p pkcs11-proxy-ng-cli

# Dynamic flags come from scripts/musl-dynamic-link-flags.sh:
# -crt-static off (musl-dynamic) plus a -L redirect resolving rustc's
# explicit -lgcc_s — the cross musl-gcc wrapper cannot resolve it on
# its own (see that script's header for the mechanism and the
# rejected alternatives). Same script feeds the CI leg and both
# dynamic builds below, so all three stay in sync.
if [[ "$RUN_MODE" == "docker" ]]; then
    # Materialize the redirect inside the target volume (it persists
    # across the one-shot containers; container /tmp would not).
    DYNAMIC_RUSTFLAGS="$(musl_cmd /workspace/scripts/musl-dynamic-link-flags.sh "$DYNAMIC_LINK_DIR")"
else
    DYNAMIC_RUSTFLAGS="$("$ROOT_DIR/scripts/musl-dynamic-link-flags.sh")"
fi
echo "[musl] dynamic RUSTFLAGS: $DYNAMIC_RUSTFLAGS"

echo "[musl] (2/5) building release shim cdylib for $TARGET (musl-dynamic) ..."
# Cargo does not track the GROUP file, so drop the previous .so
# outputs: identical RUSTFLAGS would otherwise reuse a stale link.
musl_cmd rm -f "$RELEASE_DIR/deps/libpkcs11_proxy_ng_shim.so" \
    "$RELEASE_DIR/libpkcs11_proxy_ng_shim.so"
musl_cargo_dynamic build --release --target "$TARGET" -p pkcs11-proxy-ng-shim

echo "[musl] (3/5) building release daemon for $TARGET (musl-dynamic) ..."
# The dynamic daemon overwrites the static one at
# $RELEASE_DIR/pkcs11-proxy-ng (same output path, different
# fingerprint), so preserve the static binary first.
musl_cmd mkdir -p "$STATIC_SAVE_DIR"
musl_cmd cp "$RELEASE_DIR/pkcs11-proxy-ng" "$STATIC_SAVE_DIR/pkcs11-proxy-ng"
musl_cargo_dynamic build --release --target "$TARGET" -p pkcs11-proxy-ng

echo "[musl] (4/5) linkage receipts ($RELEASE_DIR_DESC):"
musl_cmd file \
    "$STATIC_SAVE_DIR/pkcs11-proxy-ng" \
    "$RELEASE_DIR/pkcs11-proxy-ng-cli" \
    "$RELEASE_DIR/pkcs11-proxy-ng" \
    "$RELEASE_DIR/libpkcs11_proxy_ng_shim.so"
# Newer `file` reports static PIE as "static-pie linked", older as
# "statically linked" — accept both, and require no interpreter line
# (no loader needed at all). Grep a capture, never the live pipe
# (SIGPIPE/pipefail race, see above).
STATIC_RE="statically linked|static-pie linked"
STATIC_FILE_OUT="$(musl_cmd file \
    "$STATIC_SAVE_DIR/pkcs11-proxy-ng" \
    "$RELEASE_DIR/pkcs11-proxy-ng-cli")"
grep -Eq "$STATIC_RE" <<<"$STATIC_FILE_OUT" || {
    echo "static daemon + CLI are NOT statically linked" >&2
    exit 1
}
if grep -q "interpreter" <<<"$STATIC_FILE_OUT"; then
    echo "static daemon/CLI carry a program interpreter (not static)" >&2
    exit 1
fi
echo "[musl] static daemon + CLI are statically linked (no interpreter)."
# The dynamic daemon must use the musl program interpreter (it is
# what loads provider .so files on Alpine); the shim must be a
# dynamically linked shared object.
DYNAMIC_FILE_OUT="$(musl_cmd file \
    "$RELEASE_DIR/pkcs11-proxy-ng" \
    "$RELEASE_DIR/libpkcs11_proxy_ng_shim.so")"
grep -q "interpreter /lib/ld-musl-" <<<"$DYNAMIC_FILE_OUT" || {
    echo "dynamic daemon does not use the musl interpreter" >&2
    exit 1
}
grep -q "shared object" <<<"$DYNAMIC_FILE_OUT" || {
    echo "shim is not a shared object" >&2
    exit 1
}
echo "[musl] dynamic daemon + shim resolve to the musl loader."

if [[ "$build_only" == "1" ]]; then
    echo "[musl] build-only done."
    exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "the Alpine proof stage needs the docker CLI (--build-only skips it)." >&2
    exit 2
fi

STAGE_DIR="${MUSL_STAGE_DIR:-}"
STAGE_TMP=""
if [[ -z "$STAGE_DIR" ]]; then
    STAGE_TMP="$(mktemp -d)"
    STAGE_DIR="$STAGE_TMP/musl-stage"
fi
mkdir -p "$STAGE_DIR"
if [[ "${MUSL_KEEP_STAGE:-0}" != "1" && -n "$STAGE_TMP" ]]; then
    trap 'rm -rf "$STAGE_TMP"' EXIT
fi

echo "[musl] staging artifacts under $STAGE_DIR ..."
# The dynamic daemon keeps the canonical artifact name (it is the
# serving shape); the static daemon is staged suffixed.
if [[ "$RUN_MODE" == "docker" ]]; then
    # shellcheck disable=SC2086
    docker run --rm \
        -v "$TARGET_VOLUME:/tmp/musl-target:ro" \
        -v "$STAGE_DIR:/stage" \
        ${MUSL_EXTRA_DOCKER_ARGS:-} \
        "$IMAGE" \
        sh -c 'cp /tmp/musl-target/'"$TARGET"'/static-save/pkcs11-proxy-ng /stage/pkcs11-proxy-ng-static && cp /tmp/musl-target/'"$TARGET"'/release/pkcs11-proxy-ng /tmp/musl-target/'"$TARGET"'/release/pkcs11-proxy-ng-cli /tmp/musl-target/'"$TARGET"'/release/libpkcs11_proxy_ng_shim.so /stage/ && chmod 0755 /stage/pkcs11-proxy-ng /stage/pkcs11-proxy-ng-static /stage/pkcs11-proxy-ng-cli /stage/libpkcs11_proxy_ng_shim.so'
else
    cp "$STATIC_SAVE_DIR/pkcs11-proxy-ng" "$STAGE_DIR/pkcs11-proxy-ng-static"
    cp "$RELEASE_DIR/pkcs11-proxy-ng" \
        "$RELEASE_DIR/pkcs11-proxy-ng-cli" \
        "$RELEASE_DIR/libpkcs11_proxy_ng_shim.so" \
        "$STAGE_DIR/"
fi
ls -la "$STAGE_DIR"

echo "[musl] (5/5) Alpine $ALPINE_VER proof (amd64, no glibc) ..."
# NOTE: -i is load-bearing — without it the container's stdin is closed
# and `sh -s` exits 0 having executed nothing (vacuous green). The
# MUSL SMOKE PASSED marker below is a second guard against that.
ALPINE_LOG="$(mktemp)"
# shellcheck disable=SC2086
docker run --rm -i --platform linux/amd64 \
    -v "$STAGE_DIR:/artifacts:ro" \
    ${MUSL_EXTRA_DOCKER_ARGS:-} \
    "alpine:$ALPINE_VER" \
    sh -s "$quick" 2>&1 <<'ALPINE_EOF' | tee "$ALPINE_LOG"
set -euo pipefail
quick="$1"

echo "[alpine] provenance:"
cat /etc/alpine-release
# libgcc is a runtime dependency of the musl shim .so (its _Unwind_*
# symbols bind to the platform libgcc_s — the standard cdylib shape,
# same as the APKBUILD-native shim).
apk add --no-cache softhsm opensc file libgcc >/dev/null
apk list --installed 2>/dev/null | grep -E '^(softhsm|opensc|musl|musl-utils|file|libgcc)-' || true
ls -la /lib/ld-musl-*.so.1
test ! -e /lib/x86_64-linux-gnu/libc.so.6 && test ! -e /lib64/libc.so.6 \
    && echo "[alpine] no glibc loader present (musl-only)."

echo "[alpine] file receipts:"
file /artifacts/pkcs11-proxy-ng-static /artifacts/pkcs11-proxy-ng-cli /artifacts/pkcs11-proxy-ng /artifacts/libpkcs11_proxy_ng_shim.so
# Match a capture via case, never `producer | grep -q` (an early grep
# exit SIGPIPEs the producer and trips pipefail).
STATIC_FILE_OUT="$(file /artifacts/pkcs11-proxy-ng-static /artifacts/pkcs11-proxy-ng-cli)"
case "$STATIC_FILE_OUT" in
    *statically\ linked* | *static-pie\ linked*) ;;
    *)
        echo "static daemon + CLI are NOT statically linked" >&2
        exit 1
        ;;
esac
case "$STATIC_FILE_OUT" in
    *interpreter*)
        echo "static daemon/CLI carry a program interpreter (not static)" >&2
        exit 1
        ;;
esac
DYNAMIC_FILE_OUT="$(file /artifacts/pkcs11-proxy-ng /artifacts/libpkcs11_proxy_ng_shim.so)"
case "$DYNAMIC_FILE_OUT" in
    *interpreter\ /lib/ld-musl-*) ;;
    *)
        echo "dynamic daemon does not use the musl interpreter" >&2
        exit 1
        ;;
esac
case "$DYNAMIC_FILE_OUT" in
    *shared\ object*) ;;
    *)
        echo "shim is not a shared object" >&2
        exit 1
        ;;
esac

echo "[alpine] --version receipts:"
echo "    static daemon: $(/artifacts/pkcs11-proxy-ng-static --version)"
echo "    dynamic daemon: $(/artifacts/pkcs11-proxy-ng --version)"
echo "    static CLI: $(/artifacts/pkcs11-proxy-ng-cli --version)"

SOFTHSM2_LIB=/usr/lib/softhsm/libsofthsm2.so
test -f "$SOFTHSM2_LIB"

WORKDIR="$(mktemp -d)"
DAEMON_PID=""
cleanup() {
    set +e
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -TERM "$DAEMON_PID" 2>/dev/null
        for _ in $(seq 1 30); do
            kill -0 "$DAEMON_PID" 2>/dev/null || break
            sleep 1
        done
        kill -0 "$DAEMON_PID" 2>/dev/null && kill -KILL "$DAEMON_PID" 2>/dev/null
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "[alpine] dynamic linkage (musl only, no glibc edge):"
for artifact in libpkcs11_proxy_ng_shim.so pkcs11-proxy-ng; do
    ldd "/artifacts/$artifact" >"$WORKDIR/ldd-$artifact.txt" 2>&1
    echo "--- $artifact:"
    cat "$WORKDIR/ldd-$artifact.txt"
    grep -qi musl "$WORKDIR/ldd-$artifact.txt"
    if grep -q "libc.so.6" "$WORKDIR/ldd-$artifact.txt"; then
        echo "$artifact links against glibc!" >&2
        exit 1
    fi
    if grep -q "not found" "$WORKDIR/ldd-$artifact.txt"; then
        echo "$artifact has unresolved libraries!" >&2
        exit 1
    fi
done
# The shim binds its unwinder to the platform libgcc_s (standard
# cdylib shape); libgcc stays a documented runtime dependency.
grep -q "libgcc_s" "$WORKDIR/ldd-libpkcs11_proxy_ng_shim.so.txt"

export SOFTHSM2_CONF="$WORKDIR/softhsm2.conf"
TOKEN_DIR="$WORKDIR/tokens"
mkdir -p "$TOKEN_DIR"
cat >"$SOFTHSM2_CONF" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
log.level = INFO
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF

TOKEN_LABEL="musl-smoke"
echo "[alpine] initializing SoftHSM2 token ..."
softhsm2-util --init-token --free --label "$TOKEN_LABEL" \
    --so-pin abcd --pin 1234 >/dev/null

BIND_PORT=17512
cat >"$WORKDIR/proxy.toml" <<EOF
[backend]
module = "$SOFTHSM2_LIB"

[proxy]
request_timeout_secs = 30
startup_timeout_secs = 30
shutdown_grace_secs = 30
backend_health_consecutive_failures = 3

[listener.remote]
bind = "127.0.0.1:$BIND_PORT"
auth = "none"
allow_insecure_tcp = true

[auth]
EOF

echo "[alpine] negative receipt: the static daemon cannot load a backend ..."
STATIC_RC=0
timeout 20 /artifacts/pkcs11-proxy-ng-static "$WORKDIR/proxy.toml" \
    >"$WORKDIR/static-daemon.log" 2>&1 || STATIC_RC=$?
echo "    static daemon exit: $STATIC_RC (expected non-zero)"
cat "$WORKDIR/static-daemon.log"
test "$STATIC_RC" -ne 0
grep -q "Dynamic loading not supported" "$WORKDIR/static-daemon.log"
echo "    musl static-dlopen limit confirmed (see musl-tier.md)."

echo "[alpine] booting musl-dynamic daemon ..."
RUST_LOG="${RUST_LOG:-pkcs11_proxy_ng=info}" \
    /artifacts/pkcs11-proxy-ng "$WORKDIR/proxy.toml" \
    >"$WORKDIR/daemon.log" 2>&1 &
DAEMON_PID=$!

export PKCS11_PROXY_ENDPOINT="http://127.0.0.1:$BIND_PORT"
export PKCS11_PROXY_CONNECT_TIMEOUT=10

# Readiness = the static CLI completing a real RPC (a curl probe does
# not work: tonic speaks h2 with prior knowledge and curl's HTTP/1.1
# GET fails with "Received HTTP/0.9 when not allowed" even though the
# port is bound).
for i in $(seq 1 30); do
    if /artifacts/pkcs11-proxy-ng-cli list-slots >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "daemon exited during startup; tail of daemon log:" >&2
        tail -50 "$WORKDIR/daemon.log" >&2 || true
        exit 1
    fi
    sleep 0.5
    if [ "$i" -eq 30 ]; then
        echo "daemon did not serve RPCs within 15s; daemon log:" >&2
        tail -50 "$WORKDIR/daemon.log" >&2 || true
        exit 1
    fi
done
grep -q "listening on tcp without authentication" "$WORKDIR/daemon.log"
echo "    insecure-TCP startup WARN observed."
grep -q "mechanism registry ready" "$WORKDIR/daemon.log"
echo "    mechanism registry log line observed."

echo "[alpine] CLI live ops against the musl daemon (STATIC CLI):"
/artifacts/pkcs11-proxy-ng-cli list-slots >"$WORKDIR/cli-slots.txt"
cat "$WORKDIR/cli-slots.txt"
SLOT_ID="$(awk '/^Slot [0-9]+$/ { print $2; exit }' "$WORKDIR/cli-slots.txt")"
test -n "$SLOT_ID"
echo "    using slot $SLOT_ID for token-info:"
/artifacts/pkcs11-proxy-ng-cli token-info --slot-id "$SLOT_ID" >"$WORKDIR/cli-token.txt"
cat "$WORKDIR/cli-token.txt"
grep -q "$TOKEN_LABEL" "$WORKDIR/cli-token.txt"

echo "[alpine] shim smoke via pkcs11-tool (proves the musl .so end to end):"
export PKCS11_PROXY_ENDPOINT
pkcs11-tool --module /artifacts/libpkcs11_proxy_ng_shim.so --list-slots >"$WORKDIR/slots.txt"
cat "$WORKDIR/slots.txt"
grep -q "$TOKEN_LABEL" "$WORKDIR/slots.txt"

if [ "$quick" = "1" ]; then
    echo "[alpine] --quick: skipping keygen + sign."
else
    echo "[alpine] generating RSA-2048 via the shim ..."
    pkcs11-tool --module /artifacts/libpkcs11_proxy_ng_shim.so \
        --token-label "$TOKEN_LABEL" --login --pin 1234 \
        --keypairgen --key-type rsa:2048 \
        --label musl-smoke-key --id 01
    echo "[alpine] signing 256 bytes via the shim ..."
    head -c 256 /dev/urandom >"$WORKDIR/data.bin"
    pkcs11-tool --module /artifacts/libpkcs11_proxy_ng_shim.so \
        --token-label "$TOKEN_LABEL" --login --pin 1234 \
        --sign --mechanism SHA256-RSA-PKCS \
        --input-file "$WORKDIR/data.bin" \
        --output-file "$WORKDIR/sig.bin"
    SIG_SIZE="$(stat -c%s "$WORKDIR/sig.bin")"
    echo "    produced $SIG_SIZE-byte signature."
    test "$SIG_SIZE" -ge 200
fi

echo "[alpine] MUSL SMOKE PASSED."
ALPINE_EOF

grep -q "MUSL SMOKE PASSED" "$ALPINE_LOG" || {
    echo "Alpine proof stage produced no success marker (vacuous run?)" >&2
    exit 1
}
rm -f "$ALPINE_LOG"

echo "[musl] ALL GREEN on $TARGET (build + Alpine $ALPINE_VER proof)."
if [[ "${MUSL_KEEP_STAGE:-0}" == "1" || -n "${MUSL_STAGE_DIR:-}" ]]; then
    echo "[musl] staged artifacts kept under $STAGE_DIR."
fi
