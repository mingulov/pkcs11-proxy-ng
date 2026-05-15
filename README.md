# pkcs11-proxy-ng

Rust PKCS#11 remote proxy implementation workspace.

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
