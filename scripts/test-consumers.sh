#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"
PORT="${PKCS11_PROXY_PORT:-17512}"
PKCS11TEST_FILTER_FILE="${PKCS11TEST_FILTER_FILE:-$ROOT_DIR/scripts/pkcs11test-filter.txt}"

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Required command not found: $1" >&2
        exit 1
    fi
}

find_softhsm_module() {
    local candidates=(
        "/usr/lib/softhsm/libsofthsm2.so"
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
        "/usr/local/lib/softhsm/libsofthsm2.so"
        "/usr/lib64/softhsm/libsofthsm2.so"
        "/usr/lib64/pkcs11/libsofthsm2.so"
        "/usr/lib64/libsofthsm2.so"
    )
    local path
    for path in "${candidates[@]}"; do
        if [[ -f "$path" ]]; then
            printf '%s\n' "$path"
            return 0
        fi
    done
    return 1
}

find_shim_library() {
    find "$TARGET_DIR"/debug -maxdepth 1 -name 'libpkcs11_proxy_ng_shim.so' -print -quit
}

find_pkcs11_provider_module() {
    find \
        /usr/lib64/ossl-modules \
        /usr/lib/x86_64-linux-gnu/ossl-modules \
        /usr/local/lib64/ossl-modules \
        /usr/local/lib/ossl-modules \
        -maxdepth 1 \
        \( -name 'pkcs11prov.so' -o -name 'pkcs11-provider.so' \) \
        -print \
        2>/dev/null | head -n1 || true
}

pkcs11test_filter_string() {
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        { printf("%s%s", sep, $0); sep=":" }
        END { printf("\n") }
    ' "$PKCS11TEST_FILTER_FILE"
}

find_token_slot_hex() {
    local module="$1"
    pkcs11-tool --module "$module" --list-token-slots |
        sed -n 's/^Slot [0-9]\+ (0x\([0-9a-fA-F]\+\)).*/\1/p' |
        head -n1
}

run_pkcs11test_suite() {
    local tag="$1"
    local module="$2"
    local slot_hex="$3"
    local user_pin="$4"
    local so_pin="$5"

    if ! command -v pkcs11test >/dev/null 2>&1; then
        echo "[pkcs11test/$tag] skipped (binary not installed)"
        return 0
    fi

    local filter
    filter="$(pkcs11test_filter_string)"
    if [[ -z "$filter" ]]; then
        echo "[pkcs11test/$tag] skipped (empty filter set)"
        return 0
    fi

    local module_dir module_name slot_dec
    module_dir="$(dirname "$module")"
    module_name="$(basename "$module")"
    slot_dec=$((16#$slot_hex))

    echo "[pkcs11test/$tag] curated compatibility subset"
    pkcs11test \
        -m "$module_name" \
        -l "$module_dir" \
        -s "$slot_dec" \
        -u "$user_pin" \
        -o "$so_pin" \
        -X \
        --gtest_color=no \
        --gtest_brief=1 \
        --gtest_filter="$filter" >/dev/null 2>&1 || true
}

run_pkcs11_tool_baseline_suite() {
    local tag="$1"
    local module="$2"
    local slot_hex="$3"
    local pin="$4"

    echo "[pkcs11-tool/$tag] list slots"
    pkcs11-tool --module "$module" --list-slots >/dev/null

    echo "[pkcs11-tool/$tag] list mechanisms"
    pkcs11-tool --module "$module" --slot "0x$slot_hex" --list-mechanisms >/dev/null

    echo "[pkcs11-tool/$tag] built-in test suite"
    pkcs11-tool \
        --module "$module" \
        --slot "0x$slot_hex" \
        --login \
        --pin "$pin" \
        --test >/dev/null
}

run_pkcs11_tool_key_suite() {
    local tag="$1"
    local module="$2"
    local slot_hex="$3"
    local pin="$4"
    local key_id="$5"
    local label="$6"
    local token_label="$7"

    echo "[pkcs11-tool/$tag] generate and sign with RSA key"
    pkcs11-tool \
        --module "$module" \
        --slot "0x$slot_hex" \
        --login \
        --pin "$pin" \
        --keypairgen \
        --key-type rsa:2048 \
        --id "$key_id" \
        --label "$label" >/dev/null

    printf '%s smoke payload' "$tag" >"$tmpdir/$tag-data.bin"
    pkcs11-tool \
        --module "$module" \
        --slot "0x$slot_hex" \
        --login \
        --pin "$pin" \
        --sign \
        --id "$key_id" \
        --mechanism RSA-PKCS \
        --input-file "$tmpdir/$tag-data.bin" \
        --output-file "$tmpdir/$tag-signature.bin" >/dev/null
    test -s "$tmpdir/$tag-signature.bin"

    echo "[p11tool/$tag] list tokens"
    p11tool --provider "$module" --list-token-urls >/dev/null

    echo "[p11tool/$tag] list objects"
    p11tool \
        --provider "$module" \
        --login \
        --set-pin="$pin" \
        --list-all "pkcs11:token=$token_label" >/dev/null
}

cd "$ROOT_DIR"

require_cmd cargo
require_cmd softhsm2-util
require_cmd pkcs11-tool
require_cmd p11tool

if [[ "${PKCS11_PROXY_SKIP_BUILD:-0}" != "1" ]]; then
    cargo build --workspace
fi

DAEMON_BIN="${PKCS11_PROXY_DAEMON_BIN:-$TARGET_DIR/debug/pkcs11-proxy-ng}"
SHIM_LIB="${PKCS11_PROXY_SHIM_LIB:-$(find_shim_library)}"
BACKEND_MODULE="${PKCS11_PROXY_BACKEND_MODULE:-$(find_softhsm_module)}"

if [[ ! -x "$DAEMON_BIN" ]]; then
    echo "Daemon binary not found: $DAEMON_BIN" >&2
    exit 1
fi

if [[ -z "${SHIM_LIB:-}" || ! -f "$SHIM_LIB" ]]; then
    echo "Shim library not found under $TARGET_DIR/debug" >&2
    exit 1
fi

if [[ -z "${BACKEND_MODULE:-}" || ! -f "$BACKEND_MODULE" ]]; then
    echo "SoftHSM2 module not found" >&2
    exit 1
fi

tmpdir="$(mktemp -d)"
daemon_pid=""

cleanup() {
    if [[ -n "$daemon_pid" ]]; then
        kill "$daemon_pid" >/dev/null 2>&1 || true
        wait "$daemon_pid" >/dev/null 2>&1 || true
    fi
    rm -rf "$tmpdir"
}
trap cleanup EXIT

mkdir -p "$tmpdir/tokens"
cat >"$tmpdir/softhsm2.conf" <<EOF
directories.tokendir = $tmpdir/tokens
objectstore.backend = file
EOF
export SOFTHSM2_CONF="$tmpdir/softhsm2.conf"

softhsm2-util \
    --init-token \
    --slot 0 \
    --label test-token \
    --pin 1234 \
    --so-pin 5678 >/dev/null

backend_slot_hex="$(find_token_slot_hex "$BACKEND_MODULE")"
if [[ -z "$backend_slot_hex" ]]; then
    echo "Failed to determine SoftHSM token slot ID" >&2
    exit 1
fi

run_pkcs11_tool_baseline_suite "direct" "$BACKEND_MODULE" "$backend_slot_hex" "1234"
run_pkcs11test_suite "direct" "$BACKEND_MODULE" "$backend_slot_hex" "1234" "5678"

cat >"$tmpdir/daemon.toml" <<EOF
[backend]
module = "$BACKEND_MODULE"

[proxy]
mechanism_discovery = "transparent"
lease_seconds = 300

[listener.remote]
bind = "127.0.0.1:$PORT"
auth = "none"
allow_insecure_tcp = true
EOF

"$DAEMON_BIN" "$tmpdir/daemon.toml" >"$tmpdir/daemon.log" 2>&1 &
daemon_pid="$!"
sleep 1

export PKCS11_PROXY_ENDPOINT="http://127.0.0.1:$PORT"
shim_slot_hex="$(find_token_slot_hex "$SHIM_LIB")"
if [[ -z "$shim_slot_hex" ]]; then
    echo "Failed to determine shim token slot ID" >&2
    cat "$tmpdir/daemon.log" >&2 || true
    exit 1
fi

if pkcs11-tool --module "$SHIM_LIB" --list-interfaces >/dev/null 2>&1; then
    echo "[pkcs11-tool/shim] list interfaces"
    pkcs11-tool --module "$SHIM_LIB" --list-interfaces >/dev/null
fi

# Run both built-in pkcs11-tool baselines before creating long-lived smoke-test
# keys. Some pkcs11-tool versions make --test select pre-existing decrypt-capable
# RSA keys and then exercise OAEP parameter combinations that SoftHSM rejects.
run_pkcs11_tool_baseline_suite "shim" "$SHIM_LIB" "$shim_slot_hex" "1234"
run_pkcs11test_suite "shim" "$SHIM_LIB" "$shim_slot_hex" "1234" "5678"

run_pkcs11_tool_key_suite "direct" "$BACKEND_MODULE" "$backend_slot_hex" "1234" "10" "consumer-direct-rsa" "test-token"
run_pkcs11_tool_key_suite "shim" "$SHIM_LIB" "$shim_slot_hex" "1234" "20" "consumer-shim-rsa" "test-token"

provider_module="${PKCS11_PROXY_OPENSSL_PROVIDER_MODULE:-$(find_pkcs11_provider_module)}"
if [[ -n "${provider_module:-}" && -f "$provider_module" ]] && command -v openssl >/dev/null 2>&1; then
    provider_dir="$(dirname "$provider_module")"
    provider_name="$(basename "$provider_module" .so)"
    export OPENSSL_MODULES="$provider_dir"

    if [[ "$provider_name" == "pkcs11prov" ]]; then
        echo "[openssl] provider smoke via pkcs11prov"
        export PKCS11_MODULE_PATH="$SHIM_LIB"
        export PKCS11_PIN="1234"
        openssl req \
            -new \
            -provider default \
            -provider pkcs11prov \
            -key 'pkcs11:object=consumer-shim-rsa;type=private' \
            -subj '/CN=pkcs11-proxy-ng-test' \
            -out "$tmpdir/request.pem" >/dev/null 2>&1
        test -s "$tmpdir/request.pem"
    else
        echo "[openssl] skipping unsupported provider module name: $provider_name"
    fi
else
    echo "[openssl] provider smoke skipped (provider module not found)"
fi
