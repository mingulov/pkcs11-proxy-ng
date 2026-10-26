# Install from a release bundle

This guide installs `pkcs11-proxy-ng` from a downloaded binary bundle
(a `pkcs11-proxy-ng-v<version>-<target>.tar.gz` archive) with no source
checkout and no `cargo` build. It covers one daemon plus one logical
client in one trusted security domain — the
[supported testing scope](beta-support-matrix.md#unreleased-testing-scope).
For design background and qualification status, see the
[release notes](v0.3.0-release-notes.md) shipped in the same archive.

Windows operators: the Windows ZIP carries its own
`proxy.toml.template` plus the `Run-Pkcs11ProxyNg.ps1` supervisor, and
the [operator runbook](../runbooks/operating-pkcs11-proxy-ng.md#4b-windows-daemon-operations-x64msvc)
covers Windows daemon operations. The steps below target the Linux and
macOS tarballs.

## 1. Unpack and inspect

```bash
tar -xzf pkcs11-proxy-ng-v0.3.0-x86_64-unknown-linux-gnu.tar.gz
cd pkcs11-proxy-ng-v0.3.0-x86_64-unknown-linux-gnu
ls bin lib examples/configs doc/release
```

| Path | Contents |
| --- | --- |
| `bin/pkcs11-proxy-ng` | gRPC proxy daemon |
| `bin/pkcs11-proxy-ng-cli` | administrative CLI (health, slots, tokens) |
| `lib/pkcs11/libpkcs11_proxy_ng_shim.so` | loadable PKCS#11 shim (`.dylib` on macOS) |
| `INSTALL.md` | this guide |
| `examples/configs/bundle/proxy.toml` | secure starting config (mTLS + Unix socket) |
| `examples/configs/prod/proxy.toml` | hardened production shape (explicit grants) |
| `examples/configs/staging/proxy.toml` | staging shape (software token) |
| `doc/release/mtls-setup.md` | certificate creation for mTLS |
| `doc/release/pool-evidence.json` | pooled provider-evidence export (empty until the first qualification round) |
| `doc/runbooks/operating-pkcs11-proxy-ng.md` | deploy, roll out, troubleshoot |
| `doc/error-reference.md` | every `CK_RV`, with operator actions |

Before proceeding, verify the download against the published release
(checksums and Sigstore attestation), as described in the
[publication guide](crates-io-publishing.md#registry-source-binaries-and-github-release).

## 2. Certificates (mTLS path only)

Same-host Unix-socket deployments need no certificates — skip to
step 3 and comment out `[listener.remote]`. For TCP, create a CA, a
server certificate, and one client certificate per the bundled
[mTLS setup](mtls-setup.md). Use a **dedicated CA** that signs only
this deployment's daemon and client certificates: any CA-trusted
identity can reserve the single admitted context (see
[step 3](#3-configure)), even before it is granted any token.

Lock down private keys (the daemon refuses a group- or
world-accessible server key):

```bash
chmod 0600 /etc/pkcs11-proxy-ng/tls/server.key /etc/pkcs11-proxy-ng/tls/client.key
chmod 0644 /etc/pkcs11-proxy-ng/tls/server.crt /etc/pkcs11-proxy-ng/tls/ca.crt
```

## 3. Configure

Copy the bundle template and edit the marked values:

```bash
cp examples/configs/bundle/proxy.toml proxy.toml
```

| Setting | Substitute |
| --- | --- |
| `[backend] module` | path to the backend PKCS#11 `.so` (HSM driver, SoftHSM2, NSS softokn) |
| `[listener.remote] bind` | `127.0.0.1:7512` for same-host; the daemon address for remote clients |
| `[listener.remote] ca_cert` | path to `ca.crt` |
| `[listener.remote] server_cert` | path to `server.crt` |
| `[listener.remote] server_key` | path to `server.key` (mode `0600`) |
| `[listener.local] path` | socket path, e.g. `/run/pkcs11-proxy-ng/proxy.sock` |

The template sets `[proxy] max_contexts = 1`. That is an admission
guardrail for the one-client scope above: a second concurrent client
is refused instead of silently sharing the daemon. It is not
isolation — restart the daemon and provider before handing the
instance to an independent client or domain. The template accepts any
CA-signed client (`allow_all_authenticated = true`); restrict each
identity to explicit token grants before production, following the
[production example](../../examples/configs/prod/proxy.toml) and the
[operator runbook](../runbooks/operating-pkcs11-proxy-ng.md).

## 4. Start the daemon

SoftHSM-class backends read their token store from `SOFTHSM2_CONF`
at process start. When the configured backend is SoftHSM2,
provision a scratch store **before** starting the daemon — an
export after startup cannot change the running daemon's provider
environment:

```bash
export SOFTHSM2_CONF="$HOME/softhsm2.conf"
mkdir -p "$HOME/softhsm-tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' \
  "$HOME/softhsm-tokens" > "$SOFTHSM2_CONF"
softhsm2-util --init-token --slot 0 --label bundle-demo \
  --so-pin 1234 --pin 1234
```

The `1234` PINs above are scratch-token placeholders, never
production values. Then start the daemon with the same
configuration explicitly in its environment:

```bash
SOFTHSM2_CONF="$HOME/softhsm2.conf" RUST_LOG=pkcs11_proxy_ng=info \
  LOG_FORMAT=plain ./bin/pkcs11-proxy-ng proxy.toml
```

(HSM drivers and NSS softokn need no `SOFTHSM2_CONF`; drop that
assignment when the backend is not SoftHSM2.)

Expect `mechanism registry ready` followed by `listening on tcp`
(auth `Mtls`) and `listening on unix socket` (auth `PeerCred`). A
`listening on tcp without authentication` warning means the active
config is plaintext — stop and re-check step 3.

## 5. Connect a consumer

Point the application at the extracted shim. Select the shim this
archive ships — the Linux and macOS tarballs differ:

```bash
# Linux:
SHIM=./lib/pkcs11/libpkcs11_proxy_ng_shim.so
# macOS:
# SHIM=./lib/pkcs11/libpkcs11_proxy_ng_shim.dylib
```

Over mTLS:

```bash
export PKCS11_PROXY_ENDPOINT=https://127.0.0.1:7512
export PKCS11_PROXY_TLS_CA_CERT=/etc/pkcs11-proxy-ng/tls/ca.crt
export PKCS11_PROXY_TLS_CLIENT_CERT=/etc/pkcs11-proxy-ng/tls/client.crt
export PKCS11_PROXY_TLS_CLIENT_KEY=/etc/pkcs11-proxy-ng/tls/client.key
# Only if the server certificate name differs from the endpoint host:
export PKCS11_PROXY_TLS_DOMAIN=proxy.example.internal
```

Over the same-host Unix socket (no certificates; the daemon
authenticates the peer by OS credentials):

```bash
export PKCS11_PROXY_ENDPOINT=unix:/run/pkcs11-proxy-ng/proxy.sock
```

Verify with a slot listing (here with OpenSC's `pkcs11-tool` as an
ordinary consumer):

```bash
pkcs11-tool --module "$SHIM" --list-slots
```

A token listing over the configured transport confirms the handshake
and authorization path. To exercise login and signing, run the
keygen/sign flow against the scratch SoftHSM2 token provisioned in
step 4:

```bash
pkcs11-tool --module "$SHIM" \
  --token-label bundle-demo --login --pin 1234 --keypairgen \
  --key-type rsa:2048 --label bundle-key --id 01
echo -n "bundle smoke" > data.bin
pkcs11-tool --module "$SHIM" \
  --token-label bundle-demo --login --pin 1234 --sign \
  --mechanism SHA256-RSA-PKCS --input-file data.bin \
  --output-file sig.bin
pkcs11-tool --module "$SHIM" \
  --token-label bundle-demo --login --pin 1234 --verify \
  --mechanism SHA256-RSA-PKCS --input-file data.bin \
  --signature-file sig.bin
```

Check daemon readiness with the CLI over the same mTLS listener
(exit `0` when SERVING, `1` when NOT_SERVING, `2` when the probe
itself fails):

```bash
./bin/pkcs11-proxy-ng-cli --endpoint https://127.0.0.1:7512 \
  --tls-ca-cert /etc/pkcs11-proxy-ng/tls/ca.crt \
  --tls-client-cert /etc/pkcs11-proxy-ng/tls/client.crt \
  --tls-client-key /etc/pkcs11-proxy-ng/tls/client.key \
  --tls-domain proxy.example.internal health
```

The probe is passive: it never initializes a PKCS#11 context, so it
is safe under `max_contexts = 1`. A plaintext
`--endpoint http://127.0.0.1:7512` probe against this mTLS listener
fails by design — there is no unauthenticated health port.

## 6. Recovery

Sessions, logins, and object handles do not survive a daemon
restart: after any restart, reopen sessions and rediscover objects
(the slot listing above is the reconnect check). Client `C_Finalize`
retires the logical context but does not reset provider token
storage. If the daemon exits with status `70`, native shutdown could
not finish safely — the supervisor must restart it (never resume
against the stopped instance). Details and crash-isolation guidance
are in the [operator runbook](../runbooks/operating-pkcs11-proxy-ng.md)
and [error reference](../../doc/error-reference.md).

## 7. Harden for production

- Start from [prod](../../examples/configs/prod/proxy.toml) (or
  [staging](../../examples/configs/staging/proxy.toml)) instead of
  the bundle template, with per-identity token grants and a
  dedicated CA.
- Keep shim and daemon versions matched; mixed versions are
  unsupported.
- Stay within the [support matrix](beta-support-matrix.md) and the
  [parity scope](parity-validation.md): unvalidated providers may
  work but carry no support claim.
