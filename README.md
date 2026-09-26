# pkcs11-proxy-ng

A PKCS#11 remote proxy written in Rust. Applications load the shim library in
place of a local PKCS#11 module. The shim forwards calls over gRPC to a daemon
connected to the token or HSM, preserving the backend's results within the
[documented support limits](./doc/release/beta-support-matrix.md).

```
app ──dlopen──▶ libpkcs11_proxy_ng_shim.so ──gRPC/TLS──▶ pkcs11-proxy-ng (daemon) ──FFI──▶ backend .so (HSM/token)
```

**Current source version: `v0.2.0` (unpublished candidate).** See
[GitHub Releases](https://github.com/mingulov/pkcs11-proxy-ng/releases) for
published versions, the [support matrix](./doc/release/beta-support-matrix.md)
for supported environments, and [release documentation](./doc/release/) for
qualification status.

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

For anything beyond local dev, start from a template in
[`examples/configs/`](./examples/configs/) (dev / staging / prod) rather than
hand-rolling a config.

## Beta scope

The selected v0.2 [native ownership contract](./doc/release/native-mechanism-ownership.md)
is partially implemented locally and unreleased: mechanism roots and nested
output cells live in persistent native allocations (Miri-checked under both
borrow models), one provider chain per process is enforced by the
constructor domain with lifecycle-honest retirement, and wire widths are
checked with rejection proven on i686 hardware. Still pending: DONT_BLOCK-only
slot waits with shared native event flags, the qualified Linux
whole-process lifetime stop, session operation slots, subprocess/topology
qualification, and the provider parity round. The v0.2.0 tail stretch
(implemented 2026-09-17) evidences Windows x64/MSVC daemon + shim in both interoperation
directions on real Windows Server 2022
(`artifacts/v020-tail-windows-2026-09-16/` legs A/B/C at the workspace root),
the 32-bit/mixed width claim (four Linux legs plus the NSS-i386 second
provider, `scripts/run-cross-width-*-live-test.sh` in nightly), the per-PR
Tier 0f `windows-client-llp64` `--all-targets` gate, and the deterministic
Windows ZIP bundle (`scripts/release-windows.sh`, `SHA256SUMS-windows`).
This is not a v0.2 parity/support receipt.

**Public `v0.1.0` support**

- Linux `x86_64`
- Remote daemon over **TCP + mTLS** (baseline public transport), and
  **Unix-domain socket + peer-credential auth** for same-host deployments
- Backends validated with direct-vs-proxied parity: **SoftHSM2**, **NSS
  softokn**, **Kryoptic**
- The released daemon, client, CLI, and shim architecture and TOML config model

**Explicitly not claimed for this beta**

- General production-readiness / operational guarantees
- Windows GNU, 32-bit Windows (PE32), and macOS/ARM/big-endian runtime claims
- Plain TCP **without** mTLS as a public-supported mode (undecided)
- Backends beyond the validated matrix (others may work but are unvalidated)

The public `v0.1.0` beta claim — "the proxy does not materially change observed PKCS#11
behavior for the validated providers" — is backed by repeatable direct-vs-proxied
checking, not by assertion. See the full
[beta support matrix](./doc/release/beta-support-matrix.md) and the
[parity methodology](./doc/release/parity-validation.md).

The local `v0.2.0` target adds opt-in gateway, authorization, resilience, and
audit increments. They remain unreleased until the release blockers in the
candidate [release notes](./doc/release/v0.2.0-release-notes.md) are satisfied.

## Documentation

- [`doc/development.md`](./doc/development.md) — native tools, optional mise
  setup, MSRV, and local validation commands
- [`doc/error-reference.md`](./doc/error-reference.md) — every `CK_RV` the proxy
  can return, with cause + operator action + application action
- [`doc/runbooks/operating-pkcs11-proxy-ng.md`](./doc/runbooks/operating-pkcs11-proxy-ng.md)
  — deploy, configure, roll out, troubleshoot; daemon and shim env vars
- [`doc/provider-support-tables.md`](./doc/provider-support-tables.md) /
  [`doc/oasis-profile-coverage.md`](./doc/oasis-profile-coverage.md) — provider
  and PKCS#11 spec coverage
- [`doc/release/`](./doc/release/) — beta support matrix, mTLS setup, parity
  validation methodology, and the `0.x` release checklist. Scope rule for
  every direct-vs-proxied mismatch: proxy bugs get fixed here,
  provider-conformance issues go upstream — never normalized by the proxy
  ([parity triage](./doc/release/parity-validation.md#triage-of-mismatches))

The PRD, ADRs, architecture overview, audits, and follow-up notes are maintained
in the separate `pkcs11-proxy-ng-ws` planning workspace. This repository builds,
tests, and packages releases independently. See the
[script inventory](./scripts/README.md) for CI, release, and manual tooling.
See [configuration examples](./examples/configs/) for local, mTLS, and
Unix-socket setups. The `staging` and `prod` example names describe settings;
the current source remains a single-client testing candidate.

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

This validates packaging only; provider parity and publication readiness are
separate release gates.

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
