#!/bin/sh
# R5 consumer: OpenSSL pkcs11 engine (libp11).
# OpenSSL 3.x deprecates engines in favour of providers but still
# supports them via openssl.cnf. We bootstrap a minimal config that
# loads the libp11 engine and points it at our shim.

set -u
. /scripts/common.sh

backend="${1:-softhsm2}"
echo "== openssl engine (libp11) vs $backend =="
wait_for_daemon "${DAEMON_HOST:-daemon}" "${DAEMON_PORT:-7512}" || exit 1
cleanup_objects
ensure_rsa_key

fail=0

# Locate the libp11 engine .so. Path differs per distro/version.
engine_so=""
for cand in \
    /usr/lib/engines-3/pkcs11.so \
    /usr/lib/engines-3/libpkcs11.so \
    /usr/lib/ssl-modules/pkcs11.so \
    /usr/lib/engines/engine_pkcs11.so \
    /usr/lib/engines-1.1/pkcs11.so; do
    if [ -f "$cand" ]; then engine_so="$cand"; break; fi
done
if [ -z "$engine_so" ]; then
    echo "  libp11 engine .so not found; FAIL"
    echo "openssl-engine/$backend: FAIL"
    exit 1
fi
echo "  engine .so: $engine_so"

cat > /tmp/openssl-engine.cnf <<EOF
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_engine

[pkcs11_engine]
engine_id = pkcs11
dynamic_path = $engine_so
MODULE_PATH = $PKCS11_MODULE_PATH
PIN = $USER_PIN
init = 0
EOF

export OPENSSL_CONF=/tmp/openssl-engine.cnf

step engine_loads \
    openssl engine -tt -v pkcs11 || fail=1

key_uri="pkcs11:token=${TOKEN_LABEL};object=${KEY_LABEL};type=private;pin-value=${USER_PIN}"

echo "openssl-engine-data" > /tmp/in.bin

# `openssl dgst` hashes + signs in one step; the engine handles the
# private-key URI. Verify with the exported pubkey using standard
# (no-engine) openssl.
step sign \
    openssl dgst -engine pkcs11 -keyform engine \
        -sha256 -sign "$key_uri" \
        -out /tmp/sig.bin /tmp/in.bin \
    || fail=1

step export_pubkey \
    openssl pkey -engine pkcs11 -inform engine \
        -in "pkcs11:token=${TOKEN_LABEL};object=${KEY_LABEL};type=public;pin-value=${USER_PIN}" \
        -pubout -out /tmp/pub.pem \
    || fail=1

step verify \
    openssl dgst -sha256 -verify /tmp/pub.pem \
        -signature /tmp/sig.bin /tmp/in.bin \
    || fail=1

unset OPENSSL_CONF
if [ $fail -eq 0 ]; then
    echo "openssl-engine/$backend: PASS"
else
    echo "openssl-engine/$backend: FAIL"
fi
exit $fail
