# pkcs11-proxy-ng

A memory-safe **PKCS#11 remoting proxy** written in Rust. An application loads a
drop-in shim `.so` in place of its PKCS#11 module; the shim forwards each call
over gRPC to a daemon that performs the operation against the real backend
token/HSM and returns the exact result. The goal is **transparency**: an
application should not be able to tell it is loading the shim rather than the
backend module directly, apart from network latency.

```
app ──dlopen──▶ libpkcs11_proxy_ng_shim.so ──gRPC/TLS──▶ pkcs11-proxy-ng (daemon) ──FFI──▶ backend .so (HSM/token)
```

> **Public latest: `v0.1.0`.**
>
> The local target is `v0.2.0`; its gateway, authorization, resilience, and audit
> work is implemented locally, partially covered, and unreleased. Local unit and
> integration coverage is not a
> provenance-complete transparency matrix, so there is no public `v0.2.0` parity
> or support claim. See [Beta scope](#beta-scope).

## Quick start (local dev, no Kubernetes)

The fastest end-to-end path on a laptop, using SoftHSM2 as the backend and
`pkcs11-tool` as the consumer.

```bash
# 1. System prereqs (Debian/Ubuntu — adjust for your distro).
# Install Rust stable through rustup first; see doc/development.md.
sudo apt install -y build-essential pkg-config protobuf-compiler \
    softhsm2 opensc gnutls-bin

# 2. Initialise a SoftHSM2 token. The PIN here is for local dev only.
softhsm2-util --init-token --slot 0 --label dev \
    --so-pin 1234 --pin 1234

# 3. Build (~5 min cold).
cargo build --workspace --release

# 4. Start the daemon with the dev config (loopback, no TLS).
RUST_LOG=pkcs11_proxy_ng=info LOG_FORMAT=plain \
    ./target/release/pkcs11-proxy-ng examples/configs/dev/proxy.toml &

# 5. Verify the shim reaches the daemon and backend (list slots).
PKCS11_PROXY_ENDPOINT=http://127.0.0.1:7512 \
    pkcs11-tool --module ./target/release/libpkcs11_proxy_ng_shim.so \
    --list-slots
# (then exercise crypto, e.g. --login --pin 1234 --sign --mechanism RSA-PKCS ...)
```

For anything beyond local dev, start from a template in
[`examples/configs/`](./examples/configs/) (dev / staging / prod) rather than
hand-rolling a config.

## Beta scope

The selected v0.2 [native ownership contract](./doc/release/native-mechanism-ownership.md)
is awaiting implementation and native qualification: one provider chain per
process, DONT_BLOCK-only slot waits with shared native event flags, checked
widths, and a qualified Linux whole-process lifetime stop. Windows native
daemon support is deferred; portable Windows clients and mock-only builds
remain. This is not a v0.2 parity/support receipt.

**Public `v0.1.0` support**

- Linux `x86_64`
- Remote daemon over **TCP + mTLS** (baseline public transport), and
  **Unix-domain socket + peer-credential auth** for same-host deployments
- Backends validated with direct-vs-proxied parity: **SoftHSM2**, **NSS
  softokn**, **Kryoptic**
- The released daemon, client, CLI, and shim architecture and TOML config model

**Explicitly not claimed for this beta**

- General production-readiness / operational guarantees
- 32-bit or mixed 32/64-bit deployments (deferred — see
  [ADR-0006](./doc/adr/ADR-0006-32-64-bit-cross-platform-compatibility.md))
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
- [`prd.md`](./prd.md) — product requirements
- [`doc/architecture-overview.md`](./doc/architecture-overview.md) — how the
  shim, daemon, and backend fit together
- [`doc/adr/`](./doc/adr/) — architecture decision records (error model, handle
  identity, authorization, backend integration, …)
- [`doc/error-reference.md`](./doc/error-reference.md) — every `CK_RV` the proxy
  can return, with cause + operator action + application action
- [`doc/runbooks/operating-pkcs11-proxy-ng.md`](./doc/runbooks/operating-pkcs11-proxy-ng.md)
  — deploy, configure, roll out, troubleshoot; daemon and shim env vars
- [`doc/provider-support-tables.md`](./doc/provider-support-tables.md) /
  [`doc/oasis-profile-coverage.md`](./doc/oasis-profile-coverage.md) — provider
  and PKCS#11 spec coverage
- [`doc/release/`](./doc/release/) — beta support matrix, mTLS setup, parity
  validation methodology, and the `0.x` release checklist

## Release dry run

Run the local release dry run before packaging or milestone handoff (no PKCS#11
provider required):

```bash
scripts/release-dry-run.sh
```

It builds the release workspace, verifies the expected artifact names, and
stages them into a temporary install layout.

| Artifact | Purpose |
| --- | --- |
| `target/release/pkcs11-proxy-ng` | gRPC proxy daemon |
| `target/release/pkcs11-proxy-ng-cli` | administrative and smoke-test CLI |
| `target/release/libpkcs11_proxy_ng_shim.so` | loadable PKCS#11 shim library |

```text
bin/pkcs11-proxy-ng
bin/pkcs11-proxy-ng-cli
lib/pkcs11/libpkcs11_proxy_ng_shim.so
```

Use `--prefix /tmp/pkcs11-proxy-ng-install` to keep the staged layout, or
`--skip-build` to check existing `target/release` artifacts. Provider-backed
consumer tests are separate and require SoftHSM2 / OpenSC / GnuTLS:

```bash
scripts/test-consumers.sh
scripts/test-provider-backends.sh
```

## Contributor rules

All contributors — including AI agents and automation — must follow
[AGENTS.md](./AGENTS.md), the mandatory implementation ruleset for this
repository. Read it before changing code, running refactors, or committing.

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
