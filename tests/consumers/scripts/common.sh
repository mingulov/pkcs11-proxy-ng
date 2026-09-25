#!/bin/sh
# Shared helpers for Consumer scripts.
# Conventions:
#   PKCS11_MODULE_PATH        — shim .so (set by image)
#   PKCS11_PROXY_ENDPOINT     — daemon URL (set by compose)
#   TOKEN_LABEL               — "matrix-token"
#   USER_PIN                  — "1234"
#   SO_PIN                    — "abcd"
#   KEY_LABEL                 — "matrix-key"

: "${TOKEN_LABEL:=matrix-token}"
: "${USER_PIN:=1234}"
: "${SO_PIN:=abcd}"
: "${KEY_LABEL:=matrix-key}"
: "${KEY_ID:=01}"

export TOKEN_LABEL USER_PIN SO_PIN KEY_LABEL KEY_ID

# Wait for the daemon TCP listener. Uses pkcs11-tool --list-slots
# probe — works without bash /dev/tcp. If pkcs11-tool fails for any
# reason other than connection refused, the test step itself will
# fail with a clearer message.
wait_for_daemon() {
    host="${1:-daemon}"; port="${2:-7512}"
    # bash's /dev/tcp/ works if bash is available, otherwise fall
    # back to pkcs11-tool -L which makes an actual gRPC call.
    if command -v bash >/dev/null 2>&1; then
        for _ in $(seq 1 60); do
            if bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null; then return 0; fi
            sleep 1
        done
    else
        for _ in $(seq 1 60); do
            if pkcs11-tool --module "$PKCS11_MODULE_PATH" --list-slots \
                >/dev/null 2>&1; then return 0; fi
            sleep 1
        done
    fi
    echo "FAIL: daemon $host:$port not reachable" >&2
    return 1
}

# Best-effort cleanup of stale objects with our label.
cleanup_objects() {
    pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$TOKEN_LABEL" \
        --login --pin "$USER_PIN" --delete-object --type privkey \
        --label "$KEY_LABEL" 2>/dev/null || true
    pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$TOKEN_LABEL" \
        --login --pin "$USER_PIN" --delete-object --type pubkey \
        --label "$KEY_LABEL" 2>/dev/null || true
    pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$TOKEN_LABEL" \
        --login --pin "$USER_PIN" --delete-object --type secrkey \
        --label "${KEY_LABEL}-aes" 2>/dev/null || true
}

ensure_rsa_key() {
    if pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$TOKEN_LABEL" \
        --login --pin "$USER_PIN" --list-objects --type privkey 2>/dev/null \
        | grep -q "label:.*$KEY_LABEL"; then
        return 0
    fi
    pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$TOKEN_LABEL" \
        --login --pin "$USER_PIN" \
        --keypairgen --key-type rsa:2048 \
        --label "$KEY_LABEL" --id "$KEY_ID" >/dev/null
}

ensure_aes_key() {
    label="${KEY_LABEL}-aes"
    if pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$TOKEN_LABEL" \
        --login --pin "$USER_PIN" --list-objects --type secrkey 2>/dev/null \
        | grep -q "label:.*$label"; then
        return 0
    fi
    pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$TOKEN_LABEL" \
        --login --pin "$USER_PIN" \
        --keygen --key-type aes:32 \
        --label "$label" --id "02" >/dev/null
}

# Compact test step output: name + PASS/FAIL on one line.
step() {
    name="$1"; shift
    if "$@" >/tmp/step.log 2>&1; then
        echo "  $name: PASS"
        return 0
    else
        echo "  $name: FAIL"
        sed 's/^/    | /' /tmp/step.log
        return 1
    fi
}
