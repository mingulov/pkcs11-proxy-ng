# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-15

Initial release of the Rust PKCS#11 remote proxy.

### Added

- **`pkcs11-proxy-ng`** daemon: gRPC/protobuf server that forwards PKCS#11
  operations from clients to backend tokens and HSMs.
- **`pkcs11-proxy-ng-cli`**: administrative and smoke-test command-line tool
  for managing daemon configuration, auth policy, and provider backends.
- **`libpkcs11_proxy_ng_shim.so`**: loadable PKCS#11 v2.40 / v3.0 / v3.2 shim
  library that consumers (NSS, OpenSC, GnuTLS, application code) link against
  to talk to the daemon. 105 functions implemented across all three interface
  versions.
- mTLS-authenticated transport with configurable authorization policy and
  identity-based access control.
- Provider isolation: per-backend test state and capability matrix probes.
- Hardening passes covering session lifecycle, attribute-template validation,
  wrap-handle return-value priority, NULL PIN pointer preservation, admin
  entrypoint guards, and sensitive config debug redaction.
- Concurrency stress, resource exhaustion, and config validation test suites.
- Protobuf contract drift checks ratcheted in CI.
- Provider-free release dry run (`scripts/release-dry-run.sh`) producing
  daemon, CLI, and shim artifacts under a staged install layout.
- Consumer integration scripts for SoftHSM2, NSS, OpenSC/GnuTLS, Python,
  and provider-backed end-to-end tests.
- Clippy static gate, local CI parity gate, and nightly workflow.

[0.1.0]: https://github.com/mingulov/pkcs11-proxy-ng/releases/tag/v0.1.0
