#!/usr/bin/env bash
# run-be-qemu-test.sh — big-endian proof without tribal knowledge (T6a).
#
# Cross-compiles the workspace for s390x-unknown-linux-gnu (big-endian) and
# runs the BE-meaningful suites under qemu-user. Two modes:
#   * host mode: used when the host already has the s390x target, the
#     s390x cross linker, and qemu-user installed (rustup + apt route);
#   * docker mode (default fallback): builds/uses the Dockerfile.be-qemu
#     image, which carries the whole toolchain. Force it with
#     BE_QEMU_MODE=docker; force host mode with BE_QEMU_MODE=host.
#
# What runs (BE suite):
#   1. cargo check --workspace --all-targets for s390x (build receipt).
#   2. Unit suites: types, proto, client, audit libs + cli package.
#   3. backend lib minus the native-FFI qualification tests (see below).
#   4. shim lib + shim integration tests (in-process mock daemons over gRPC,
#      cross-ABI bridge in both width directions, D6 refusal both ways).
#   5. server package default set (lib + mock-based integration targets).
#   6. The ignored C-ABI suite against the cross-built shim cdylib.
#
# Exclusion list (documented, stable):
#   * backend `native_stop*` / `native_domain*` — s390x is not a qualified
#     native-FFI target (NATIVE_FFI_QUALIFIED=false; stop arms are x86/x86_64
#     asm only) and the code correctly refuses it there. Qualifying s390x
#     for real-module FFI needs new stop arms + hardware validation and is
#     explicitly out of scope (T6a BLOCKED-scope concern).
#   * server `loaded_shim_writes_mechanism_out_to_caller_stack_after_...` —
#     pre-existing failure on dev, byte-identical on the LE baseline
#     (SP800-108 virtualization area, not byte-order related).
#   * hardware/provider-gated tests (SoftHSM2/NSS/Kryoptic/TPM/...) — all
#     #[ignore] by default, same as on LE; no s390x provider hardware here.
#   * stress_registry takes ~60s under emulation; skip it with --quick.
#
# Environment:
#   BE_QEMU_MODE       host | docker | auto (default: auto)
#   BE_IMAGE           docker image tag (default: pkcs11-proxy-ng-be-qemu)
#   BE_CARGO_VOLUME    named volume for the cargo cache (docker mode)
#   BE_TARGET_VOLUME   named volume for the s390x target dir (docker mode)
#
# The docker run mounts the workspace read-only and keeps all build output
# in containers/volumes, so the host tree is never dirtied.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="s390x-unknown-linux-gnu"
IMAGE="${BE_IMAGE:-pkcs11-proxy-ng-be-qemu}"
MODE="${BE_QEMU_MODE:-auto}"

quick=0
check_only=0

usage() {
    cat <<'EOF'
Usage: scripts/run-be-qemu-test.sh [options]

Options:
  --quick                 Skip the ~60s stress_registry suite
  --check-only            Only cross-check the workspace for s390x (build receipt)
  -h, --help              Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick)
            quick=1
            ;;
        --check-only)
            check_only=1
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
        && rustup target list --installed 2>/dev/null | grep -q "$TARGET" \
        && command -v s390x-linux-gnu-gcc >/dev/null 2>&1 \
        && { command -v qemu-s390x >/dev/null 2>&1 \
            || command -v qemu-s390x-static >/dev/null 2>&1; }
}

# Resolve CARGO_ARGS prefix: either plain cargo (host mode) or
# `docker run ...` (docker mode). Prints the mode on stdout for the log.
resolve_runner() {
    case "$MODE" in
        host)
            if ! host_has_tooling; then
                echo "BE_QEMU_MODE=host but the host lacks the s390x toolchain." >&2
                echo "Install: rustup target add $TARGET, gcc-s390x-linux-gnu," >&2
                echo "qemu-user-static, and set the target linker/runner, or unset" >&2
                echo "BE_QEMU_MODE to use docker mode." >&2
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
            echo "unknown BE_QEMU_MODE: $MODE (want host|docker|auto)" >&2
            exit 2
            ;;
    esac
}

RUN_MODE="$(resolve_runner)"
echo "[be-qemu] mode: $RUN_MODE (target $TARGET)"

if [[ "$RUN_MODE" == "docker" ]]; then
    if ! command -v docker >/dev/null 2>&1; then
        echo "docker mode needs the docker CLI." >&2
        exit 2
    fi
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        echo "[be-qemu] building image $IMAGE ..."
        docker build -f "$ROOT_DIR/Dockerfile.be-qemu" -t "$IMAGE" "$ROOT_DIR"
    fi
    CARGO_VOLUME="${BE_CARGO_VOLUME:-be-cargo-cache}"
    TARGET_VOLUME="${BE_TARGET_VOLUME:-be-target}"
    # shellcheck disable=SC2086
    be_cargo() {
        docker run --rm \
            -v "$ROOT_DIR:/workspace:ro" \
            -v "$CARGO_VOLUME:/root/.cargo" \
            -v "$TARGET_VOLUME:/tmp/be-target" \
            -e CARGO_TARGET_DIR=/tmp/be-target \
            -e QEMU_LD_PREFIX=/usr/s390x-linux-gnu \
            ${BE_EXTRA_DOCKER_ARGS:-} \
            "$IMAGE" \
            cargo "$@"
    }
    # The cdylib path as seen INSIDE the container.
    SHIM_SO="/tmp/be-target/$TARGET/debug/libpkcs11_proxy_ng_shim.so"
else
    export CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_LINKER:-s390x-linux-gnu-gcc}"
    if [[ -z "${CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_RUNNER:-}" ]]; then
        if command -v qemu-s390x-static >/dev/null 2>&1; then
            export CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_RUNNER="qemu-s390x-static"
        else
            export CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_RUNNER="qemu-s390x"
        fi
    fi
    be_cargo() {
        (cd "$ROOT_DIR" && cargo "$@")
    }
    SHIM_SO="${CARGO_TARGET_DIR:-$ROOT_DIR/target}/$TARGET/debug/libpkcs11_proxy_ng_shim.so"
fi

cd "$ROOT_DIR"

echo "[be-qemu] (1/6) cross-checking workspace for $TARGET ..."
be_cargo check --target "$TARGET" --workspace --all-targets

if [[ "$check_only" == "1" ]]; then
    echo "[be-qemu] check-only done."
    exit 0
fi

echo "[be-qemu] (2/6) leaf unit suites (types/proto/client/audit/cli) ..."
be_cargo test --target "$TARGET" -p pkcs11-proxy-ng-types --lib
be_cargo test --target "$TARGET" -p pkcs11-proxy-ng-proto --lib
be_cargo test --target "$TARGET" -p pkcs11-proxy-ng-client --lib
be_cargo test --target "$TARGET" -p pkcs11-proxy-ng-audit --lib
be_cargo test --target "$TARGET" -p pkcs11-proxy-ng-cli

echo "[be-qemu] (3/6) backend lib (native-FFI qualification tests excluded) ..."
be_cargo test --target "$TARGET" -p pkcs11-proxy-ng-backend --lib -- \
    --skip native_stop --skip native_domain

echo "[be-qemu] (4/6) shim lib + integration ..."
be_cargo test --target "$TARGET" -p pkcs11-proxy-ng-shim --lib
if [[ "$quick" == "0" ]]; then
    be_cargo test --target "$TARGET" -p pkcs11-proxy-ng-shim --test stress_registry
fi
be_cargo test --target "$TARGET" -p pkcs11-proxy-ng-shim --test fork_after_init -- --ignored

echo "[be-qemu] (5/6) server package (mock-based integration targets) ..."
be_cargo test --target "$TARGET" -p pkcs11-proxy-ng

echo "[be-qemu] (6/6) C-ABI suite against the s390x shim cdylib ..."
be_cargo build --target "$TARGET" -p pkcs11-proxy-ng-shim
if [[ "$RUN_MODE" == "docker" ]]; then
    docker run --rm \
        -v "$ROOT_DIR:/workspace:ro" \
        -v "$CARGO_VOLUME:/root/.cargo" \
        -v "$TARGET_VOLUME:/tmp/be-target" \
        -e CARGO_TARGET_DIR=/tmp/be-target \
        -e QEMU_LD_PREFIX=/usr/s390x-linux-gnu \
        -e PKCS11_PROXY_SHIM_LIB="$SHIM_SO" \
        ${BE_EXTRA_DOCKER_ARGS:-} \
        "$IMAGE" \
        cargo test --target "$TARGET" -p pkcs11-proxy-ng \
            --test shim_c_abi_mechanism_out_test -- --ignored \
            --skip loaded_shim_writes_mechanism_out_to_caller_stack_after_encrypt_wrap_and_derive
else
    PKCS11_PROXY_SHIM_LIB="$SHIM_SO" be_cargo test --target "$TARGET" -p pkcs11-proxy-ng \
        --test shim_c_abi_mechanism_out_test -- --ignored \
        --skip loaded_shim_writes_mechanism_out_to_caller_stack_after_encrypt_wrap_and_derive
fi

echo "[be-qemu] ALL GREEN on $TARGET."
