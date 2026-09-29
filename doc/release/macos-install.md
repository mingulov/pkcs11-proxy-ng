# macOS Install (arm64)

This bundle (`pkcs11-proxy-ng-v<version>-aarch64-apple-darwin.tar.gz`)
ships the daemon, the CLI, and the PKCS#11 shim dylib for Apple-silicon
Macs. Intel Macs are not shipped: every bundle is executed natively in
CI, and there is no Rosetta-covered lane.

Bundle layout after extraction:

```text
bin/pkcs11-proxy-ng                 # daemon
bin/pkcs11-proxy-ng-cli             # operator CLI
lib/pkcs11/libpkcs11_proxy_ng_shim.dylib   # PKCS#11 shim for consumers
doc/                                # release docs, incl. this file
```

## 1. Quarantine

Binaries downloaded from the internet arrive quarantined; Gatekeeper
kills quarantined executables (`Killed: 9`) and refuses quarantined
dylibs at `dlopen`. The bundle is not notarized, so clear the tag
after verifying the published sha256:

```bash
tar -xzf pkcs11-proxy-ng-v<version>-aarch64-apple-darwin.tar.gz
xattr -cr pkcs11-proxy-ng-v<version>-aarch64-apple-darwin
./pkcs11-proxy-ng-v<version>-aarch64-apple-darwin/bin/pkcs11-proxy-ng --version
```

## 2. Install paths

There is no installer; copy the files where your setup expects them:

```bash
PREFIX=/usr/local
sudo cp bin/pkcs11-proxy-ng bin/pkcs11-proxy-ng-cli "$PREFIX/bin/"
sudo mkdir -p "$PREFIX/lib/pkcs11"
sudo cp lib/pkcs11/libpkcs11_proxy_ng_shim.dylib "$PREFIX/lib/pkcs11/"
```

Point PKCS#11 consumers at the dylib by absolute path; that works
regardless of `install_name` handling. Consumers that resolve the
module by bare name need its directory on their search path.

## 3. Daemon config

The daemon takes a TOML config file as its single argument. Minimal
same-host shape (the unix listener authenticates by peer credentials;
see `mtls-setup.md` for TCP):

```toml
[backend]
# brew's SoftHSM layout varies by version; resolve the live path with:
#   ls "$(brew --prefix softhsm)"/lib/softhsm/libsofthsm2.*
module = "/opt/homebrew/lib/softhsm/libsofthsm2.so"

[listener.local]
path = "/run/pkcs11-proxy/proxy.sock"
auth = "peer_cred"
```

```bash
pkcs11-proxy-ng /path/to/proxy.toml
```

Peer-credential auth works on macOS (via the platform peer-credential
API); the `[listener.local]` rejection noted for Windows does not
apply here.

## 4. Consumer env

```bash
export PKCS11_PROXY_ENDPOINT="unix:/run/pkcs11-proxy/proxy.sock"
```

Remote daemons use `PKCS11_PROXY_ENDPOINT=https://…` plus the
`PKCS11_PROXY_TLS_*` files, as on Linux.

## 5. Smoke test with SoftHSM

```bash
brew install softhsm opensc
export SOFTHSM2_CONF="$PWD/softhsm2.conf"
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$PWD/tokens" > "$SOFTHSM2_CONF"
mkdir -p tokens
softhsm2-util --init-token --slot 0 --label smoke --pin 1234 --so-pin 5678
# start the daemon against the SoftHSM module, then:
pkcs11-tool --module /usr/local/lib/pkcs11/libpkcs11_proxy_ng_shim.dylib \
  --token-label smoke --login --pin 1234 --list-objects
```

## 6. Troubleshooting

- `Killed: 9` on first run: quarantine (step 1).
- `dlopen … code signature … not valid`: same cause — clear xattrs,
  do not ad-hoc re-sign over them blindly.
- `CKR_CRYPTOKI_NOT_INITIALIZED` after a daemon restart: expected —
  reopen sessions and log in again (handles do not survive restarts).
