# FIPS deployment example

These files illustrate a daemon connected to an NSS softokn FIPS database.
Adapt them to the exact validated backend and security policy you use.

```
proxy.toml                # daemon config (mTLS, NSS softokn FIPS DB)
mechanism_params.toml     # filtered discovery and explicit mechanism exclusions
```

## How the settings work

The backend enforces its own FIPS policy when an operation runs. The proxy's
`discovery_mode = "filtered"` limits `C_GetMechanismList` to mechanisms the
provider reports and the merged registry recognizes. The example registry
also has an explicit `exclude` list: those mechanisms are hidden from
discovery and rejected when called directly. Check both the provider's
approved services and the complete merged registry for your deployment;
filtered discovery alone is not an operation-time allow-list.

## Caveats

- **Check the module's certificate.** This example does not certify the
  daemon or a deployment. Use the exact backend version and approved-service
  conditions in its CMVP documentation.
- **NSS softokn checks operations.** Its mechanism list may still include
  algorithms that FIPS mode refuses when called. Inspect the list returned
  through the proxy and the `exclude` entries for your policy.
- **Password required.** FIPS softokn refuses an empty DB password.
  Initialise with `certutil -d sql:/path -W` before first daemon
  start.
- **Check 3DES key length.** DES3 mechanisms remain visible; the backend must
  enforce the key lengths approved for its validated mode.
- **Review SHA-1 separately.** The registry merges with embedded defaults,
  which include SHA-1 mechanisms. Add explicit exclusions as required by
  your module's approved-service policy.

## Verifying the configuration

Before running the daemon, install the mTLS files named in `proxy.toml`,
copy `mechanism_params.toml` to its configured path, and add an
`[[auth.policy]]` entry for your client certificate and token. Follow the
[mTLS guide](../../../doc/release/mtls-setup.md). The example denies all
clients until you add a policy. Initialize the NSS database at the
`/var/lib/pkcs11-proxy-ng/fipsdb` path configured in `proxy.toml`, or change
that path in the config. Ensure the daemon can read these files and the user
running the setup can write the database. On Linux with `certutil`, `modutil`,
and the proxy CLI installed:

```bash
# 1. Set up a FIPS NSS DB.
mkdir -p /var/lib/pkcs11-proxy-ng/fipsdb
certutil -N -d sql:/var/lib/pkcs11-proxy-ng/fipsdb --empty-password
modutil -fips true -dbdir sql:/var/lib/pkcs11-proxy-ng/fipsdb
certutil -d sql:/var/lib/pkcs11-proxy-ng/fipsdb -W

# 2. Run the daemon pointing at this config tree (CONFIG is a positional arg).
pkcs11-proxy-ng examples/configs/fips/proxy.toml

# 3. Query the published mechanism list from an authorized client.
# Replace the certificate paths and domain with those you configured.
pkcs11-proxy-ng-cli --endpoint https://127.0.0.1:7512 \
  --tls-domain proxy.example.internal \
  --tls-ca-cert /path/to/ca.crt --tls-client-cert /path/to/client.crt \
  --tls-client-key /path/to/client.key list-slots
pkcs11-proxy-ng-cli --endpoint https://127.0.0.1:7512 \
  --tls-domain proxy.example.internal \
  --tls-ca-cert /path/to/ca.crt --tls-client-cert /path/to/client.crt \
  --tls-client-key /path/to/client.key list-mechanisms --slot-id <slot-id>

# Compare the output with your approved-service policy and exclusion list.
```

If an excluded mechanism appears, check `[mechanisms].config_path` in
`proxy.toml` and the daemon's registry startup log.
