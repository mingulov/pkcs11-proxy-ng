# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Local-only, unreleased opt-in gateway authorization: leaf-SPKI identity
  policies with legacy dual-accept; deny-default unmatched identities when an
  authenticated policy is present; explicit `allow_all_authenticated` override
  for authenticated identities; and an audit-label-only `anonymous_principal`
  that is never a grant. No-policy unauthenticated dev transport remains allowed
  subject to listener safety config, while config rejects policy or allow-all on
  unauthenticated listeners. Coarse and fine object/class/mechanism/extract
  grants and per-principal rate/session quotas with a per-slot failed-login
  budget are implemented locally.
- Local-only, unreleased resilience: pathological-object-population detection,
  authenticated local metrics, and opt-in context-scoped attribute coalescing.
- Local-only, unreleased tamper-evident audit: hash chain, signed checkpoints,
  operational metadata only (never PINs, key material, or raw request payloads),
  opt-in data-plane records with fail-open gap reporting, and fail-closed
  security classes that can reject after a backend side effect. `EventClass::Deny`
  remains reserved rather than emitted.
- Local-only, unreleased startup backend attestation: module hash plus library
  and token identity fields. It has no config hash or reconnect/hot-swap
  re-attestation.
- `sanitize_inputs` daemon config option (default `false`). When enabled, the
  daemon rejects NULL data pointers with non-zero length and NULL mechanism
  pointers on init with `CKR_ARGUMENTS_BAD` before they reach the backend
  module, trading transparency for availability. See ADR-0010 for the
  accepted divergence (a sanitize-mode reject does not terminate the active
  backend operation). Configure via `[proxy] sanitize_inputs = true`.
- Server-driven mechanism registry. The daemon now reads
  `mechanism_params.toml` (or the embedded default) at startup,
  computes a SHA-256-truncated revision string, and publishes the
  payload on every `GetBackendInterfaces` RPC. Shims consume the
  payload during `interface_probe::ensure_probed()` and atomically
  swap their in-memory registry to match. SIGHUP triggers a daemon
  reload with no restart. Workflow: edit TOML → `kill -HUP daemon` →
  rolling-restart consumer services.
- Loud one-time WARN at daemon startup when running with
  `auth = "none"` + `allow_insecure_tcp = true`. Documents the SaaS
  trust model in operator logs.
- New ProxyConfig knobs with defaults:
  - `startup_timeout_secs = 30` wraps `populate_slots()` so a backend
    hang fails the daemon at startup rather than hanging the process.
  - `shutdown_grace_secs = 30` controls graceful-shutdown drain on
    SIGTERM/SIGINT.
  - `backend_health_consecutive_failures = 3` gating threshold for
    `tonic-health` (wiring follows in a separate commit).
- Daemon refuses to start when `backend.module` is still the shipped
  placeholder (`/CHANGE_ME/path/to/backend.so`).
- Shim accepts the legacy `PKCS11_PROXY_SOCKET=tcp://host:port` env
  var as a back-compat alias for `PKCS11_PROXY_ENDPOINT=http://host:port`.
  `PKCS11_PROXY_ENDPOINT` always wins when both are set.
- `PKCS11_PROXY_DISABLE_SERVER_REGISTRY=1` opts out of the server
  payload for test/debug, restoring purely embedded-default behaviour.
- Packaging under `packaging/{alpine,amazon,config}/`. Alpine APK
  build (3.22, 3.23) and Amazon Linux 2023 RPM build, each producing
  a `FROM scratch` carrier image at `/apk` or `/rpm` for downstream
  Dockerfiles to bind-mount. Three-way subpackage split
  (`-shim` / `-daemon` / `-cli`) plus an optional `-compat`
  subpackage that adds `/usr/lib/libpkcs11-proxy.so` symlink for
  legacy consumer Dockerfiles.
- `.gitlab-ci.yml` Phase-1 matrix: `alpine_3_22`, `alpine_3_23`,
  `amazon_2023`.

### Changed

- Workspace MSRV is `1.88`; Alpine 3.22 and Amazon Linux 2023 use a
  rustup-managed toolchain because their stock Rust is older. Edition `2024` is
  preserved. See `AGENTS.md` rule 5 for the rationale.
- `[profile.release]` now sets `lto = "thin"`, `strip = "symbols"`, and
  `codegen-units = 1`. The shim cdylib and daemon binary shrink ~25-30%
  at the cost of ~30s additional CI build time.
- Shim's `MECHANISM_REGISTRY` storage changed from
  `OnceLock<MechanismRegistry>` to
  `OnceLock<RwLock<Arc<MechanismRegistry>>>` so the registry can be
  atomically swapped on reprobe. `state::mechanism_registry()` now
  returns `Arc<MechanismRegistry>` (cheap clone); callers never hold
  the read lock across FFI/RPC calls.
- `Pkcs11Client::get_backend_interfaces()` now returns a
  `BackendProbe { interfaces, mechanism_registry }` struct.
  `BackendProbe` is re-exported from the client crate.
- `Pkcs11ProxyService::new()` gains a `MechanismRegistrySource`
  argument; test helpers use the embedded default.
- Split the shim's 6078-line `helpers.rs` into a `helpers/` directory
  module (no behavior change).
- tonic features are now selected per-crate, so client-side artifacts
  no longer pull in the server stack.
- Workspace builds clippy-clean under `-D warnings`.

### Removed

- `state::init_mechanism_registry` (the back-compat wrapper) — all
  callers migrated to `replace_mechanism_registry`.

### Fixed

- NULL data-input pointers now reach the backend module verbatim (Bug B;
  ADR-0010 Scope 2). The shim serializes `(NULL pointer, claimed length N)`
  as distinct from an empty byte slice via additive `*_null_len` proto fields;
  the daemon reconstructs the exact `(NULL, N)` FFI call. Null-argument
  rejection RVs and operation termination semantics now come from the module
  rather than being synthesized by the shim.
- Unreadable data-input lengths (valid pointer, byte size > 512 MiB
  `MAX_SERIALIZABLE_BYTES` or overflowing) now return stable
  `CKR_ARGUMENTS_BAD` instead of `CKR_GENERAL_ERROR` (the previous panic-guard
  path). This is the documented transport-impossible limit per ADR-0010.
- Absurd lengths on embedded mechanism-parameter payload fields (GCM/CCM AAD,
  PBE salt, GOST IV/UKM, IKE/KEA public data, derived-key nonce/tag, and ~25
  others) no longer cause a wild memory read that crashed the client process.
  The shim now guards all ~30 previously unguarded embedded payload reads;
  the daemon rejects oversized embedded params with
  `CKR_MECHANISM_PARAM_INVALID` at the FFI reconstruction boundary.
- Legitimate embedded mechanism-parameter payloads larger than 64 KiB (e.g.
  valid GCM/CCM AAD) are no longer rejected. The constant
  `MAX_MECHANISM_PARAM_STRUCT_LEN` (renamed from `MAX_MECHANISM_PARAM_LEN`)
  now bounds only the parameter-STRUCT length; embedded data fields are
  bounded by `MAX_SERIALIZABLE_BYTES` (512 MiB).
- `C_VerifyInit`/`C_DigestInit` with a NULL mechanism pointer are now
  forwarded verbatim to the backend module, like the five sibling init
  paths, so the module's native `CK_RV` (`CKR_ARGUMENTS_BAD`,
  `CKR_MECHANISM_INVALID`, or a native digest cancel) reaches the
  client instead of a `C_SessionCancel`-derived result
  (`CKR_FUNCTION_NOT_SUPPORTED` on 2.40 modules, `CKR_OK` on 3.0
  modules). Establishes the transparent-forwarding-by-default policy;
  see ADR-0010 for the decision and the accepted crash trade-off.
- Shim two-call session caches are now evicted on the close attempt for
  `C_CloseSession` / `C_CloseAllSessions`, regardless of the returned
  `CK_RV`, matching the documented eviction contract. Failed closes no
  longer leave stale per-session cache entries behind.
- The OASIS coverage inventory script, the source-scan quality gates,
  and ADR-0006 were updated for the `helpers.rs` → `helpers/` module
  split, which had left them pointing at the removed file.
- The CI MSRV job now matches the declared `rust-version` (it previously built
  with 1.94, leaving the declared MSRV unverified). The declared MSRV was
  corrected for let-chains; see `AGENTS.md` rule 5.

### Security

- Completed the 2026-06 security review remediation (52 findings, all
  closed). Highlights: cross-client logical-login PIN validation and
  per-request context ownership enforcement (ADR-0009); object handles
  virtualized everywhere, including handles embedded in mechanism
  parameters; injective mTLS identity keys and validation of every
  certificate in a PEM bundle; zeroization of password material held in
  FFI parameter backings; fork-safe current-thread runtime in the shim;
  per-context concurrency caps; per-slot login/logout serialization
  closing a first-login race; bind-time umask for UDS socket
  permissions; `C_WaitForSlotEvent` authorization with unauthorized
  slot events suppressed; strict `cargo-deny` policy.

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
