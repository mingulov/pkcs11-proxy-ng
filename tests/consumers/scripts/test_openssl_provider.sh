#!/bin/sh
# consumer: OpenSSL pkcs11 provider (libp11 ≥ 0.4.16 / pkcs11prov.so).
# Configured via OPENSSL_CONF that loads the pkcs11 provider and
# points it at our shim.

set -u
. /scripts/common.sh

backend="${1:-softhsm2}"
echo "== openssl provider (libp11) vs $backend =="
wait_for_daemon "${DAEMON_HOST:-daemon}" "${DAEMON_PORT:-7512}" || exit 1
cleanup_objects
ensure_rsa_key

fail=0

# Locate the pkcs11 provider .so.
provider_so=""
for cand in \
    /usr/lib/ossl-modules/pkcs11.so \
    /usr/lib/ssl3/providers/pkcs11.so \
    /usr/lib/ossl-modules/pkcs11prov.so; do
    if [ -f "$cand" ]; then provider_so="$cand"; break; fi
done
if [ -z "$provider_so" ]; then
    echo "  libp11 pkcs11 provider not found; SKIP"
    echo "openssl-provider/$backend: SKIP (provider not packaged)"
    exit 0
fi
echo "  provider .so: $provider_so"

cat > /tmp/openssl-provider.cnf <<EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_section

[provider_section]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = $provider_so
pkcs11-module-path = $PKCS11_MODULE_PATH
activate = 1
EOF

export OPENSSL_CONF=/tmp/openssl-provider.cnf

step provider_loads \
    openssl list -providers || fail=1

key_uri="pkcs11:token=${TOKEN_LABEL};object=${KEY_LABEL};type=private;pin-value=${USER_PIN}"

echo "openssl-provider-data" > /tmp/in.bin

step sign \
    openssl dgst -sha256 -sign "$key_uri" \
        -out /tmp/sig.bin /tmp/in.bin \
    || fail=1

step export_pubkey \
    openssl pkey -in "pkcs11:token=${TOKEN_LABEL};object=${KEY_LABEL};type=public;pin-value=${USER_PIN}" \
        -pubout -out /tmp/pub.pem \
    || fail=1

step verify \
    openssl dgst -sha256 -verify /tmp/pub.pem \
        -signature /tmp/sig.bin /tmp/in.bin \
    || fail=1

unset OPENSSL_CONF
if [ $fail -eq 0 ]; then
    echo "openssl-provider/$backend: PASS"
else
    echo "openssl-provider/$backend: FAIL"
fi
exit $fail
