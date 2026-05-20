# Shared helpers for R2 resilience scenarios.
#
# Conventions:
# - Every scenario runs inside the `runner` container; the daemon and
#   toxiproxy are sibling containers on the `r2net` Docker network.
# - The shim talks to `toxiproxy:7512`; scenarios poke
#   `toxiproxy:8474` to add/remove toxics.
# - Each scenario MUST log its outcome with `pass:`/`fail:` so the
#   master `run_scenario.sh` can grep it.

set -euo pipefail

TOXIPROXY_HOST="${TOXIPROXY_HOST:-toxiproxy}"
TOXIPROXY_ADMIN="http://${TOXIPROXY_HOST}:8474"
TOXIPROXY_PROXY="daemon"

PKCS11_MODULE="${PKCS11_MODULE_PATH:-/usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so}"
TOKEN_LABEL="r2-resilience"
USER_PIN="1234"

# Wait for the toxiproxy admin endpoint to come up. The daemon is fast
# enough that the order in docker-compose.yml is usually fine, but
# fresh `up -d` can race.
wait_for_toxiproxy() {
    for _ in $(seq 1 30); do
        if curl -sf "${TOXIPROXY_ADMIN}/proxies" >/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    echo "fail: toxiproxy admin never came up" >&2
    return 1
}

# Add a toxic to the proxy; first arg is the JSON body.
add_toxic() {
    local body=$1
    curl -sf -X POST -H 'Content-Type: application/json' \
        -d "$body" \
        "${TOXIPROXY_ADMIN}/proxies/${TOXIPROXY_PROXY}/toxics" >/dev/null
}

# Delete every toxic on the proxy (between sub-scenarios).
clear_toxics() {
    local names
    names=$(curl -sf "${TOXIPROXY_ADMIN}/proxies/${TOXIPROXY_PROXY}/toxics" \
        | jq -r '.[].name // empty')
    for n in $names; do
        curl -sf -X DELETE "${TOXIPROXY_ADMIN}/proxies/${TOXIPROXY_PROXY}/toxics/${n}" >/dev/null
    done
}

# Disable / enable the proxy itself — used by scenarios that simulate
# the daemon being temporarily unreachable (different from a slow link).
disable_proxy() {
    curl -sf -X POST -H 'Content-Type: application/json' \
        -d '{"enabled":false}' \
        "${TOXIPROXY_ADMIN}/proxies/${TOXIPROXY_PROXY}" >/dev/null
}
enable_proxy() {
    curl -sf -X POST -H 'Content-Type: application/json' \
        -d '{"enabled":true}' \
        "${TOXIPROXY_ADMIN}/proxies/${TOXIPROXY_PROXY}" >/dev/null
}

# Run one pkcs11-tool sign through the shim against the proxied daemon.
# Returns 0 on success, prints the captured stderr+stdout to stderr on
# failure (so the scenario can grep for CK_RV strings).
shim_sign_once() {
    local outfile
    outfile=$(mktemp)
    if pkcs11-tool --module "$PKCS11_MODULE" \
            --token-label "$TOKEN_LABEL" \
            --login --pin "$USER_PIN" \
            --sign --mechanism SHA256-RSA-PKCS \
            --input-file /etc/hostname \
            --output-file "$outfile" >/tmp/shim_sign.log 2>&1; then
        rm -f "$outfile"
        return 0
    fi
    cat /tmp/shim_sign.log >&2
    rm -f "$outfile"
    return 1
}

# Ensure the consumer test key exists (idempotent). Re-runs the
# fixture's key-generation if not.
ensure_test_key() {
    if pkcs11-tool --module "$PKCS11_MODULE" \
            --token-label "$TOKEN_LABEL" \
            --login --pin "$USER_PIN" \
            --list-objects 2>&1 | grep -q "label:[[:space:]]*r2-key"; then
        return 0
    fi
    pkcs11-tool --module "$PKCS11_MODULE" \
        --token-label "$TOKEN_LABEL" \
        --login --pin "$USER_PIN" \
        --keypairgen --key-type rsa:2048 \
        --label r2-key --id 01 >/dev/null
}

# Returns 0 if the most-recent shim_sign log includes the named CK_RV
# (e.g. CKR_DEVICE_ERROR). Helpful for asserting scenario-specific
# error semantics without parsing fragile pkcs11-tool exit codes.
log_mentions_ckr() {
    grep -q "$1" /tmp/shim_sign.log
}
