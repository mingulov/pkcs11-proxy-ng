#!/bin/sh
# R5 consumer: pkcs11-tool (OpenSC).
# Exercises: -L (list slots), -O (list objects), -G (keygen),
# -s (sign), --decrypt, -p (login).

set -u
. /scripts/common.sh

backend="${1:-softhsm2}"
echo "== pkcs11-tool vs $backend =="
wait_for_daemon "${DAEMON_HOST:-daemon}" "${DAEMON_PORT:-7512}" || exit 1
cleanup_objects

fail=0

step list_slots \
    pkcs11-tool --module "$PKCS11_MODULE_PATH" --list-slots || fail=1

step list_mechanisms \
    pkcs11-tool --module "$PKCS11_MODULE_PATH" -M || fail=1

step rsa_keygen \
    pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$TOKEN_LABEL" \
        --login --pin "$USER_PIN" \
        --keypairgen --key-type rsa:2048 --label "$KEY_LABEL" --id "$KEY_ID" \
    || fail=1

step list_objects \
    pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$TOKEN_LABEL" \
        --login --pin "$USER_PIN" --list-objects || fail=1

# RSA sign input can be any length; the AES-ECB tests need a
# block-aligned input (16-byte multiples), so use a 32-byte buffer.
printf '%s' 'r5-test-data-pkcs11tool-32bytes!' > /tmp/in.bin

step rsa_sign \
    pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$TOKEN_LABEL" \
        --login --pin "$USER_PIN" \
        --sign --mechanism SHA256-RSA-PKCS \
        --id "$KEY_ID" \
        --input-file /tmp/in.bin --output-file /tmp/sig.bin || fail=1

step rsa_verify \
    pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$TOKEN_LABEL" \
        --login --pin "$USER_PIN" \
        --verify --mechanism SHA256-RSA-PKCS \
        --id "$KEY_ID" \
        --input-file /tmp/in.bin --signature-file /tmp/sig.bin || fail=1

# AES keygen, wrap (encrypt) test-data with AES.
step aes_keygen \
    pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$TOKEN_LABEL" \
        --login --pin "$USER_PIN" \
        --keygen --key-type aes:32 --label "${KEY_LABEL}-aes" --id "02" \
    || fail=1

# Encrypt with AES-CBC (most basic) then decrypt.
step aes_encrypt \
    pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$TOKEN_LABEL" \
        --login --pin "$USER_PIN" \
        --encrypt --mechanism AES-ECB \
        --id "02" \
        --input-file /tmp/in.bin --output-file /tmp/enc.bin || fail=1

step aes_decrypt \
    pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$TOKEN_LABEL" \
        --login --pin "$USER_PIN" \
        --decrypt --mechanism AES-ECB \
        --id "02" \
        --input-file /tmp/enc.bin --output-file /tmp/dec.bin || fail=1

step roundtrip_check \
    cmp /tmp/in.bin /tmp/dec.bin || fail=1

if [ $fail -eq 0 ]; then
    echo "pkcs11-tool/$backend: PASS"
else
    echo "pkcs11-tool/$backend: FAIL"
fi
exit $fail
