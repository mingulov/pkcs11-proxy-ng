#!/bin/sh
# consumer: p11tool (GnuTLS).
# p11tool uses p11-kit's module discovery — we point it at the shim
# via a synthetic p11-kit module file. p11tool's natural sign test is
# `--test-sign`, which performs sign + verify in one operation.

set -u
. /scripts/common.sh

backend="${1:-softhsm2}"
echo "== p11tool vs $backend =="
wait_for_daemon "${DAEMON_HOST:-daemon}" "${DAEMON_PORT:-7512}" || exit 1
cleanup_objects
ensure_rsa_key  # plant a key via pkcs11-tool first

fail=0

mkdir -p /etc/pkcs11/modules
cat > /etc/pkcs11/modules/pkcs11-proxy-ng.module <<EOF
module: $PKCS11_MODULE_PATH
EOF

export GNUTLS_PIN="$USER_PIN"

# p11tool requires PKCS#11-URI-encoded labels (spec RFC 7512).
# Spaces and other reserved characters must be percent-encoded.
url_encode() {
    printf '%s' "$1" | awk 'BEGIN {
        for (i = 0; i < 256; i++) ord[sprintf("%c", i)] = i
    }
    {
        out = ""
        for (i = 1; i <= length($0); i++) {
            c = substr($0, i, 1)
            if (c ~ /[A-Za-z0-9._~-]/) out = out c
            else out = out sprintf("%%%02X", ord[c])
        }
        print out
    }'
}

token_enc=$(url_encode "$TOKEN_LABEL")
key_enc=$(url_encode "$KEY_LABEL")

step list_tokens \
    p11tool --list-tokens || fail=1

step list_all \
    p11tool --list-all --login \
        "pkcs11:token=${token_enc}" || fail=1

step export_pubkey \
    p11tool --export-pubkey --login \
        --outfile=/tmp/pub.pem \
        "pkcs11:token=${token_enc};object=${key_enc};type=public" || fail=1

step test_sign \
    p11tool --test-sign --login \
        "pkcs11:token=${token_enc};object=${key_enc};type=private" || fail=1

unset GNUTLS_PIN

if [ $fail -eq 0 ]; then
    echo "p11tool/$backend: PASS"
else
    echo "p11tool/$backend: FAIL"
fi
exit $fail
