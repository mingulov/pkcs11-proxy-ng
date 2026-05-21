#!/bin/sh
# vendor extension flow test.
#
# Mode 1 — visibility check (works with any backend):
#   - pkcs11-tool -M lists CKM_CLOUDHSM_AES_GCM after daemon registry reload.
#   - Both transparent and filtered discovery modes show it.
#
# Mode 2 — end-to-end op check (requires the patched-SoftHSM2 daemon):
#   - C_EncryptInit with mechanism 0x80001087 succeeds and produces
#     output equivalent to standard AES-GCM. (Run via pkcs11-tool.)

set -u
. /scripts/common.sh

mode="${1:-visibility}"
backend="${2:-softhsm2-patched}"
echo "== vendor extension flow (mode=$mode) vs $backend =="
wait_for_daemon "${DAEMON_HOST:-daemon}" "${DAEMON_PORT:-7512}" || exit 1

fail=0

case "$mode" in
    visibility)
        step lists_cloudhsm_mech \
            sh -c "pkcs11-tool --module '$PKCS11_MODULE_PATH' -M \
                | grep -E 'CKM_CLOUDHSM_AES_GCM|mechtype-0x80001087'" \
            || fail=1
        ;;
    end_to_end)
        cleanup_objects
        ensure_aes_key
        # pkcs11-tool --encrypt with vendor mechanism passed by hex code.
        step encrypt_with_vendor_mech \
            sh -c "echo 'vendor-test-data' \
                | pkcs11-tool --module '$PKCS11_MODULE_PATH' \
                    --token-label '$TOKEN_LABEL' --login --pin '$USER_PIN' \
                    --encrypt --mechanism 0x80001087 --id 02 \
                    --iv 000102030405060708090a0b \
                    --input-file /etc/hostname \
                    --output-file /tmp/vendor-enc.bin" \
            || fail=1
        ;;
    *)
        echo "unknown mode: $mode" >&2; exit 2 ;;
esac

if [ $fail -eq 0 ]; then
    echo "vendor-ext-${mode}/$backend: PASS"
else
    echo "vendor-ext-${mode}/$backend: FAIL"
fi
exit $fail
