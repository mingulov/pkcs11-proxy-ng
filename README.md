# pkcs11-proxy-ng

A PKCS#11 remote proxy written in Rust. Applications load the shim library in
place of a local PKCS#11 module. The shim forwards calls over gRPC to a daemon
connected to the token or HSM, preserving the backend's results within the
[documented support limits](./doc/release/v0.2.0-release-notes.md#current-limits).

```
app ──dlopen──▶ libpkcs11_proxy_ng_shim.so ──gRPC/TLS──▶ pkcs11-proxy-ng (daemon) ──FFI──▶ backend .so (HSM/token)
```

**Latest release: `v0.1.0`.** This branch prepares `v0.2.0`, an unreleased
testing candidate that still needs final validation and provider comparisons.

Use **one logical client in one trusted security domain per daemon/provider
instance**. Do not share it with mutually untrusted clients. Restart the daemon
and provider before switching independent clients or domains.
`[proxy] max_contexts = 1` limits admission; it does not establish isolation.
Multi-client isolation is planned for [v0.3](./doc/release/v0.3.0-scope.md).

## Quick start

This local example uses SoftHSM2 and OpenSC's `pkcs11-tool`.

```bash
# 1. Install prerequisites on Debian/Ubuntu.
# Install Rust through rustup first; see doc/development.md.
sudo apt install -y build-essential pkg-config protobuf-compiler \
    softhsm2 opensc gnutls-bin

# 2. Initialise a test token. Use these PINs only for local development.
softhsm2-util --init-token --slot 0 --label dev \
    --so-pin 1234 --pin 1234

# 3. Build.
cargo build --workspace --release --locked

# 4. Start the daemon with the dev config (loopback, no TLS).
RUST_LOG=pkcs11_proxy_ng=info LOG_FORMAT=plain \
    ./target/release/pkcs11-proxy-ng examples/configs/dev/proxy.toml &

# 5. List slots through the proxy.
PKCS11_PROXY_ENDPOINT=http://127.0.0.1:7512 \
    pkcs11-tool --module ./target/release/libpkcs11_proxy_ng_shim.so \
    --list-slots
```

See [configuration examples](./examples/configs/) for local, mTLS, and
Unix-socket setups. The `staging` and `prod` example names describe settings;
v0.2 remains a single-client testing candidate.

## Beta scope

The published **v0.1.0** beta covers Linux x86_64 with SoftHSM2, NSS softokn,
and Kryoptic. Supported transports are TCP with mTLS and Unix-domain sockets
with peer-credential authentication. Other providers and platforms, plain
unauthenticated TCP, and general production readiness are outside that claim.
See the [support matrix](./doc/release/beta-support-matrix.md).

The **v0.2.0 candidate** adds authorization policies, audit logging, resilience
controls, native-lifetime fixes, and platform work. Its
[release notes](./doc/release/v0.2.0-release-notes.md) describe the remaining
limits and validation work.

## Documentation

- [Development](./doc/development.md) — tools, build, and tests
- [Operations](./doc/runbooks/operating-pkcs11-proxy-ng.md) — configuration,
  deployment, and troubleshooting
- [Error reference](./doc/error-reference.md) — return codes and what to do
- [PKCS#11 coverage](./doc/oasis-profile-coverage.md) — interfaces, mechanism
  parameters, and test coverage
- [Release documentation](./doc/release/) — support, validation, and packaging
- [Scripts](./scripts/README.md) — CI, release, and manual tools

Design and planning material lives in the separate `pkcs11-proxy-ng-ws`
workspace. This repository builds, tests, and packages independently.

## Release dry run

Build and stage the Linux release artifacts without a PKCS#11 provider:

```bash
scripts/release-dry-run.sh
```

The script checks and stages these files:

| Artifact | Purpose |
| --- | --- |
| `target/release/pkcs11-proxy-ng` | gRPC proxy daemon |
| `target/release/pkcs11-proxy-ng-cli` | administrative and smoke-test CLI |
| `target/release/libpkcs11_proxy_ng_shim.so` | loadable PKCS#11 shim library |

Use `--prefix /tmp/pkcs11-proxy-ng-install` to keep the staged layout, or
`--skip-build` to check existing `target/release` artifacts. See the
[development guide](./doc/development.md#provider-tests) for provider tests.

## Contributor rules

Read [AGENTS.md](./AGENTS.md) before contributing.

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
