# pkcs11-proxy-ng

Rust PKCS#11 remote proxy implementation workspace.

## Quick start (local dev, no Kubernetes)

The fastest end-to-end path on a laptop, using SoftHSM2 as the
backend and `pkcs11-tool` as the consumer.

```bash
# 1. System prereqs (Debian/Ubuntu — adjust for your distro).
sudo apt install -y softhsm2 opensc gnutls-bin

# 2. Initialise a SoftHSM2 token. The PIN here is for local dev only.
softhsm2-util --init-token --slot 0 --label dev \
    --so-pin 1234 --pin 1234

# 3. Build the workspace (~5 min cold).
cargo build --workspace --release

# 4. Start the daemon with the dev config (loopback, no TLS).
RUST_LOG=pkcs11_proxy_ng=info LOG_FORMAT=plain \
    ./target/release/pkcs11-proxy-ng examples/configs/dev/proxy.toml &

# 5. Drive a sign through the shim.
PKCS11_PROXY_ENDPOINT=http://127.0.0.1:7512 \
    pkcs11-tool --module ./target/release/libpkcs11_proxy_ng_shim.so \
    --pin 1234 --list-slots
```

Things to read next:

- [`examples/configs/`](./examples/configs/) — dev / staging / prod
  TOML templates (use them as starting points, don't hand-roll).
- [Runbook](./doc/runbooks/operating-pkcs11-proxy-ng.md) — operations
  guide (deploy, rollout, ConfigMap edits, troubleshooting).
  See §8a for daemon env vars (`PKCS11_PROXY_BIND`,
  `PKCS11_PROXY_BACKEND_MODULE`, …) and §8b for shim env vars
  (`PKCS11_PROXY_ENDPOINT`, `PKCS11_PROXY_TLS_*`, …).
- [Error reference](./doc/error-reference.md) — every `CK_RV` the
  proxy can return, cause + operator action + application action.
- [`doc/oasis-profile-coverage.md`](./doc/oasis-profile-coverage.md) — PKCS#11 spec coverage matrix.

## Release Dry Run

Run the local release dry run before packaging or milestone handoff:

```bash
scripts/release-dry-run.sh
```

The script builds the release workspace, verifies the expected artifact names,
and stages them into a temporary install layout. It does not require a PKCS#11
provider.

Expected release artifacts:

| Artifact | Purpose |
| --- | --- |
| `target/release/pkcs11-proxy-ng` | gRPC proxy daemon |
| `target/release/pkcs11-proxy-ng-cli` | administrative and smoke-test CLI |
| `target/release/libpkcs11_proxy_ng_shim.so` | loadable PKCS#11 shim library |

Staged install layout:

```text
bin/pkcs11-proxy-ng
bin/pkcs11-proxy-ng-cli
lib/pkcs11/libpkcs11_proxy_ng_shim.so
```

Use `scripts/release-dry-run.sh --prefix /tmp/pkcs11-proxy-ng-install` to keep
the staged layout for manual inspection. Use `--skip-build` to check existing
`target/release` artifacts.

Provider-backed consumer tests are separate from the provider-free release dry
run. They require SoftHSM2, OpenSC/GnuTLS tools, and optional provider modules:

```bash
scripts/test-consumers.sh
scripts/test-provider-backends.sh
```

## Contributor Rules

All contributors, including AI agents and automation, must follow:

- [AGENTS.md](./AGENTS.md)

`AGENTS.md` is the mandatory implementation-level ruleset for this submodule.
If you change code under `pkcs11-proxy-ng/`, follow those rules before making
changes, running refactors, or submitting commits.

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
