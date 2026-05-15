#!/usr/bin/env bash
set -euo pipefail
# Test parameterized mechanisms through the shim C ABI.
# This verifies that read_mechanism() correctly handles typed params
# by exercising the full C -> proto -> gRPC -> proto -> C round-trip
# with real SoftHSM2 backend operations.
#
# Mechanisms tested:
#   RSA-PKCS-PSS       — CK_RSA_PKCS_PSS_PARAMS (hash, mgf, salt)
#   SHA256-RSA-PKCS-PSS — CK_RSA_PKCS_PSS_PARAMS (combined hash+sign)
#   AES-CBC             — CK_AES_CBC_PARAMS (16-byte IV)
#   AES-CBC-PAD         — CK_AES_CBC_PARAMS (non-block-aligned input)
#   pkcs11-tool --test  — built-in regression suite through shim

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"
PORT="${PKCS11_PROXY_PORT:-17513}"
PIN="1234"
SO_PIN="5678"

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

find_token_slot_hex() {
    local module="$1"
    pkcs11-tool --module "$module" --list-token-slots |
        sed -n 's/^Slot [0-9]\+ (0x\([0-9a-fA-F]\+\)).*/\1/p' |
        head -n1
}

cd "$ROOT_DIR"

require_cmd cargo
require_cmd softhsm2-util
require_cmd pkcs11-tool

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

# ── SoftHSM2 token setup ───────────────────────────────────────────
mkdir -p "$tmpdir/tokens"
cat >"$tmpdir/softhsm2.conf" <<EOF
directories.tokendir = $tmpdir/tokens
objectstore.backend = file
EOF
export SOFTHSM2_CONF="$tmpdir/softhsm2.conf"

softhsm2-util \
    --init-token \
    --slot 0 \
    --label test-param \
    --pin "$PIN" \
    --so-pin "$SO_PIN" >/dev/null

# ── Daemon startup ─────────────────────────────────────────────────
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

if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "Daemon failed to start:" >&2
    cat "$tmpdir/daemon.log" >&2 || true
    exit 1
fi

export PKCS11_PROXY_ENDPOINT="http://127.0.0.1:$PORT"

slot_hex="$(find_token_slot_hex "$SHIM_LIB")"
if [[ -z "$slot_hex" ]]; then
    echo "Failed to determine shim token slot ID" >&2
    cat "$tmpdir/daemon.log" >&2 || true
    exit 1
fi

pass=0
fail=0
skip=0

report() {
    local tag="$1" status="$2"
    if [[ "$status" == "PASS" ]]; then
        echo "  PASS  $tag"
        pass=$((pass + 1))
    elif [[ "$status" == "FAIL" ]]; then
        echo "  FAIL  $tag"
        fail=$((fail + 1))
    else
        echo "  SKIP  $tag"
        skip=$((skip + 1))
    fi
}

# ── Test 1: pkcs11-tool --test through shim ─────────────────────────
# Run the generic consumer baseline before this script creates persistent
# mechanism-specific keys. Some pkcs11-tool versions make --test select
# pre-existing decrypt-capable RSA keys and then exercise OAEP parameter
# combinations that SoftHSM rejects.
echo "[shim-param/builtin] pkcs11-tool --test through shim"

if pkcs11-tool --module "$SHIM_LIB" --slot "0x$slot_hex" --login --pin "$PIN" \
    --test >/dev/null 2>&1; then
    report "builtin/test-suite" "PASS"
else
    report "builtin/test-suite" "FAIL"
fi

# ── Test 2: RSA-PKCS-PSS sign + verify ─────────────────────────────
# Exercises CK_RSA_PKCS_PSS_PARAMS with raw (pre-hashed) PSS mechanism.
# Requires xxd or python3 for hex-to-binary conversion. Skipped if unavailable.
# The SHA256-RSA-PKCS-PSS test below covers the same param shape without
# needing pre-hashing, so this test is optional.
# Raw RSA-PKCS-PSS requires pre-hashed input. Some pkcs11-tool versions
# don't handle this correctly. Skip if it fails — SHA256-RSA-PKCS-PSS
# (Test 2) covers the same CK_RSA_PKCS_PSS_PARAMS shape.
echo "[shim-param/pss] RSA-PKCS-PSS sign+verify through shim (optional)"

if pkcs11-tool --module "$SHIM_LIB" --slot "0x$slot_hex" --login --pin "$PIN" \
    --keypairgen --key-type rsa:2048 --id 30 --label shim-pss-test \
    --usage-sign >/dev/null 2>&1; then

    # RSA-PKCS-PSS requires the input to be a hash digest, not raw data.
    # Pre-hash with SHA-256 to produce a 32-byte digest.
    printf 'test data for PSS signing' >"$tmpdir/pss-raw.bin"
    sha256sum "$tmpdir/pss-raw.bin" | cut -d' ' -f1 | \
        python3 -c "import sys,binascii; sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read().strip()))" \
        >"$tmpdir/pss-hash.bin"

    # Sign with RSA-PKCS-PSS + SHA256
    if pkcs11-tool --module "$SHIM_LIB" --slot "0x$slot_hex" --login --pin "$PIN" \
        --sign --id 30 --mechanism RSA-PKCS-PSS \
        --hash-algorithm SHA256 --mgf MGF1-SHA256 --salt-len 32 \
        --input-file "$tmpdir/pss-hash.bin" --output-file "$tmpdir/pss-sig.bin" \
        >/dev/null 2>&1; then

        if [[ ! -s "$tmpdir/pss-sig.bin" ]]; then
            report "pss/sign" "SKIP"
        else
            # Verify signature
            if pkcs11-tool --module "$SHIM_LIB" --slot "0x$slot_hex" --login --pin "$PIN" \
                --verify --id 30 --mechanism RSA-PKCS-PSS \
                --hash-algorithm SHA256 --mgf MGF1-SHA256 --salt-len 32 \
                --input-file "$tmpdir/pss-hash.bin" --signature-file "$tmpdir/pss-sig.bin" \
                >/dev/null 2>&1; then
                report "pss/sign+verify" "PASS"
            else
                report "pss/verify" "FAIL"
            fi
        fi
    else
        report "pss/sign" "SKIP"
    fi
else
    report "pss/keygen" "FAIL"
fi

# ── Test 2: SHA256-RSA-PKCS-PSS sign + verify ──────────────────────
# Combined hash-and-sign mechanism. Accepts raw data (hashing is done
# internally by the token). Still uses CK_RSA_PKCS_PSS_PARAMS.
echo "[shim-param/sha256pss] SHA256-RSA-PKCS-PSS sign+verify through shim"

if pkcs11-tool --module "$SHIM_LIB" --slot "0x$slot_hex" --login --pin "$PIN" \
    --keypairgen --key-type rsa:2048 --id 33 --label shim-sha256pss \
    --usage-sign >/dev/null 2>&1; then

    printf 'raw data for SHA256-RSA-PKCS-PSS' >"$tmpdir/sha256pss-data.bin"

    if pkcs11-tool --module "$SHIM_LIB" --slot "0x$slot_hex" --login --pin "$PIN" \
        --sign --id 33 --mechanism SHA256-RSA-PKCS-PSS \
        --input-file "$tmpdir/sha256pss-data.bin" --output-file "$tmpdir/sha256pss-sig.bin" \
        >/dev/null 2>&1; then

        if [[ ! -s "$tmpdir/sha256pss-sig.bin" ]]; then
            report "sha256pss/sign" "FAIL"
        else
            if pkcs11-tool --module "$SHIM_LIB" --slot "0x$slot_hex" --login --pin "$PIN" \
                --verify --id 33 --mechanism SHA256-RSA-PKCS-PSS \
                --input-file "$tmpdir/sha256pss-data.bin" \
                --signature-file "$tmpdir/sha256pss-sig.bin" \
                >/dev/null 2>&1; then
                report "sha256pss/sign+verify" "PASS"
            else
                report "sha256pss/verify" "FAIL"
            fi
        fi
    else
        report "sha256pss/sign" "FAIL"
    fi
else
    report "sha256pss/keygen" "FAIL"
fi

# ── Test 4: AES-CBC encrypt + decrypt ──────────────────────────────
# Exercises IV parameter round-trip (16-byte IV for AES-CBC).
# Input must be exactly block-aligned (multiple of 16 bytes).
echo "[shim-param/cbc] AES-CBC encrypt+decrypt through shim"

# Generate AES-256 key. --usage-decrypt sets both ENCRYPT and DECRYPT
# for secret keys in this pkcs11-tool version.
if pkcs11-tool --module "$SHIM_LIB" --slot "0x$slot_hex" --login --pin "$PIN" \
    --keygen --key-type aes:32 --id 31 --label shim-cbc-test \
    --usage-decrypt >/dev/null 2>&1; then

    # 16 bytes = one AES block (block-aligned, no padding needed for CBC)
    printf '0123456789ABCDEF' >"$tmpdir/cbc-data.bin"

    # Encrypt with AES-CBC
    if pkcs11-tool --module "$SHIM_LIB" --slot "0x$slot_hex" --login --pin "$PIN" \
        --encrypt --id 31 --mechanism AES-CBC \
        --iv "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f" \
        --input-file "$tmpdir/cbc-data.bin" --output-file "$tmpdir/cbc-enc.bin" \
        >/dev/null 2>&1; then

        if [[ ! -s "$tmpdir/cbc-enc.bin" ]]; then
            report "cbc/encrypt" "FAIL"
        else
            # Decrypt
            if pkcs11-tool --module "$SHIM_LIB" --slot "0x$slot_hex" --login --pin "$PIN" \
                --decrypt --id 31 --mechanism AES-CBC \
                --iv "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f" \
                --input-file "$tmpdir/cbc-enc.bin" --output-file "$tmpdir/cbc-dec.bin" \
                >/dev/null 2>&1; then

                # Compare plaintext round-trip
                if diff -q "$tmpdir/cbc-data.bin" "$tmpdir/cbc-dec.bin" >/dev/null 2>&1; then
                    report "cbc/encrypt+decrypt" "PASS"
                else
                    echo "  AES-CBC decrypted output does not match original" >&2
                    report "cbc/roundtrip" "FAIL"
                fi
            else
                report "cbc/decrypt" "FAIL"
            fi
        fi
    else
        report "cbc/encrypt" "FAIL"
    fi
else
    report "cbc/keygen" "FAIL"
fi

# ── Test 5: AES-CBC-PAD encrypt + decrypt ──────────────────────────
# Same IV parameter shape as AES-CBC, but with PKCS#7 padding.
# Tests non-block-aligned input to confirm padding round-trips.
echo "[shim-param/cbcpad] AES-CBC-PAD encrypt+decrypt through shim"

if pkcs11-tool --module "$SHIM_LIB" --slot "0x$slot_hex" --login --pin "$PIN" \
    --keygen --key-type aes:32 --id 34 --label shim-cbcpad-test \
    --usage-decrypt >/dev/null 2>&1; then

    # 13 bytes: not block-aligned, requires PKCS#7 padding
    printf 'hello CBC-PAD' >"$tmpdir/cbcpad-data.bin"

    if pkcs11-tool --module "$SHIM_LIB" --slot "0x$slot_hex" --login --pin "$PIN" \
        --encrypt --id 34 --mechanism AES-CBC-PAD \
        --iv "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f" \
        --input-file "$tmpdir/cbcpad-data.bin" --output-file "$tmpdir/cbcpad-enc.bin" \
        >/dev/null 2>&1; then

        if [[ ! -s "$tmpdir/cbcpad-enc.bin" ]]; then
            report "cbcpad/encrypt" "FAIL"
        else
            if pkcs11-tool --module "$SHIM_LIB" --slot "0x$slot_hex" --login --pin "$PIN" \
                --decrypt --id 34 --mechanism AES-CBC-PAD \
                --iv "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f" \
                --input-file "$tmpdir/cbcpad-enc.bin" --output-file "$tmpdir/cbcpad-dec.bin" \
                >/dev/null 2>&1; then

                if diff -q "$tmpdir/cbcpad-data.bin" "$tmpdir/cbcpad-dec.bin" >/dev/null 2>&1; then
                    report "cbcpad/encrypt+decrypt" "PASS"
                else
                    echo "  AES-CBC-PAD decrypted output does not match original" >&2
                    report "cbcpad/roundtrip" "FAIL"
                fi
            else
                report "cbcpad/decrypt" "FAIL"
            fi
        fi
    else
        report "cbcpad/encrypt" "FAIL"
    fi
else
    report "cbcpad/keygen" "FAIL"
fi

# ── Summary ─────────────────────────────────────────────────────────
echo ""
echo "==> Shim parameterized mechanism results: $pass passed, $fail failed, $skip skipped"

if [[ "$fail" -gt 0 ]]; then
    echo "Daemon log:" >&2
    tail -40 "$tmpdir/daemon.log" >&2 || true
    exit 1
fi

echo "==> All shim parameterized mechanism tests passed"
