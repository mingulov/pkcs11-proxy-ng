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

> **Current source version: `v0.2.0`.**
>
> This is the `v0.2.0` release line. Until the annotated `v0.2.0` tag and its
> release artifacts are published, an untagged checkout is a release candidate.
> Release qualification still requires the source-bound receipt and provider
> evidence in the [`0.x` release checklist](./doc/release/0.x-beta-release-checklist.md).

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

## Release dry run

Run the local release dry run before packaging or milestone handoff (no PKCS#11
provider required):

```bash
scripts/release-dry-run.sh
```

It builds the release workspace, verifies the expected artifact names, and
stages them into a temporary install layout.

The dry run checks packaging, not provider parity or publication readiness. The
complete freeze, receipt, tag, and publication procedure is in the
[`0.x` release checklist](./doc/release/0.x-beta-release-checklist.md).

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
