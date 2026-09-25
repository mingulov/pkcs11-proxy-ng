# FIPS-flavored example config

This directory contains a paired example for running pkcs11-proxy-ng
in front of a FIPS-validated backend (NSS softokn 3 in FIPS mode, or
any FIPS 140-3 validated HSM).

```
proxy.toml                # daemon config (mTLS, NSS softokn FIPS DB)
mechanism_params.toml     # discovery_mode = "filtered" + FIPS-approved
                          # mechanism allow-list (parameterless + shapes)
```

## Interlock contract

The "FIPS interlock" between the proxy and the backend is:

1. **Backend in FIPS mode.** NSS softokn — or any FIPS HSM —
   enforces approved algorithms at the cryptographic-operation
   boundary. Non-approved operations return CKR_FUNCTION_NOT_PERMITTED
   (NSS) or the vendor's equivalent.
2. **Proxy in `discovery_mode = "filtered"`.** The proxy's
   `C_GetMechanismList` only advertises mechanisms whose parameter
   shape it understands AND whose mechanism number is listed in the
   merged registry (default + override file).
3. **Mechanism allow-list pinned to FIPS subset.** This directory's
   `mechanism_params.toml` lists only NIST-approved mechanisms.

The resulting visible mechanism set to a downstream consumer is:

    advertised = (backend reports)
                ∩ (proxy registry's known mechanisms)
                ∩ (FIPS allow-list)

Because the backend has already filtered to "FIPS-approved + supported
by the slot" in step 1, and the proxy filters to "FIPS-approved + has
a known parameter shape" in step 2+3, the published set is the safe
intersection.

## Caveats

- **Not a CMVP certification.** This config does not certify the
  daemon as FIPS-compliant. A real audit goes through the CMVP-
  validated module's documentation. The proxy is a transport layer
  that does not perform cryptographic operations itself.
- **NSS softokn FIPS gating** is enforced at operation time, not
  discovery time. `C_GetMechanismList` on a FIPS NSS DB still returns
  the full mechanism list — non-approved operations fail later. The
  proxy's filtered allow-list is what enforces discovery-time
  hygiene; do not skip it.
- **Password required.** FIPS softokn refuses an empty DB password.
  Initialise with `certutil -d sql:/path -W` before first daemon
  start.
- **3-key TDEA only.** 2-key 3DES is not FIPS-approved; the allow-list
  exposes CKM_DES3_* but the backend must police key length.
- **SHA-1 for digital signature is dropped.** SHA-1 HMAC is still
  acceptable pre-2030 but is also omitted here for simplicity. Add
  CKM_SHA_1_HMAC manually if a legacy verifier needs it.

## Verifying the interlock locally

Quick smoke check (NSS softokn in FIPS mode on a Linux box with
`certutil`/`modutil`/`pkcs11-tool` installed):

```bash
# 1. Set up a FIPS NSS DB.
mkdir -p /tmp/fips-nssdb
certutil -N -d sql:/tmp/fips-nssdb --empty-password   # init
modutil -fips true -dbdir sql:/tmp/fips-nssdb         # flip FIPS on
certutil -d sql:/tmp/fips-nssdb -W                    # set FIPS pin

# 2. Run the daemon pointing at this config tree (CONFIG is a positional arg).
pkcs11-proxy-ng examples/configs/fips/proxy.toml

# 3. Query the published mechanism list from a client.
# (--endpoint is a global option: it goes before the subcommand.
# Every slot-taking command uses --slot-id; list slots first.)
pkcs11-proxy-ng-cli --endpoint http://127.0.0.1:7512 list-slots
pkcs11-proxy-ng-cli --endpoint http://127.0.0.1:7512 list-mechanisms --slot-id <slot-id>

# Expected: no MD2/MD4/MD5, no SHA-1 signatures, no RC2/RC4/DES,
# no Skipjack/CAST/IDEA. AES/RSA/ECDSA/SHA-2/SHA-3/HKDF/HMAC remain.
```

If a non-approved mechanism appears in step 3, the registry override
in this directory was not picked up — check `[mechanisms].config_path`
in proxy.toml and the daemon's startup log line "mechanism registry
loaded".
