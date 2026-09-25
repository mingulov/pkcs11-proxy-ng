# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-15

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
    `tonic-health`.
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
- Operator mechanism exclusion: the mechanism registry override file
  accepts an `exclude = [...]` list of `CK_MECHANISM_TYPE` values.
  Excluded mechanisms are rejected at operation time with
  `CKR_MECHANISM_INVALID` (even parameterless) and hidden from
  discovery in every discovery mode — unlike a filtered allowlist,
  which only hides. Exclusions travel to shims in the new
  `MechanismRegistryPayload.excluded` field (absent from older
  daemons, treated as empty). The FIPS example hard-excludes 74
  historical mechanisms (MD2/MD5, RC2/RC4, single-DES, CAST, IDEA,
  SEED, Camellia, ARIA, including parameterized variants) so a FIPS
  deployment no longer forwards them on direct invocation.
- `LOG_FORMAT` is honored by the daemon: `LOG_FORMAT=plain` selects
  human-readable log lines (the README dev flow now works as
  documented); unset or any other value keeps the historical JSON
  default that the prod/staging examples set explicitly.
- Windows x64/MSVC native daemon consuming Windows provider DLLs, with the
  Windows x64 PKCS#11 client shim, in both interoperation directions —
  qualified on real Windows Server 2022 (T6 legs A/B/C receipts).
- Per-PR Tier 0f `windows-client-llp64` Windows compile gate
  (`cargo xwin build --target x86_64-pc-windows-msvc --all-targets`).
- Deterministic Windows ZIP bundle via `scripts/release-windows.sh`
  (`pkcs11-proxy-ng-v0.2.0-x86_64-pc-windows-msvc.zip` + `SHA256SUMS-windows`),
  appended to the tag release by the `release-windows` job.
- 32-bit NSS-i386 second-provider width leg
  (`scripts/run-cross-width-nss32-live-test.sh`, nightly) alongside the four
  Linux legs in `scripts/run-cross-width-live-test.sh`.
- Windows abnormal-stop contract: `TerminateProcess(GetCurrentProcess(), 70)`
  backstop arm on the qualified Windows host (see the native ownership
  contract); `abort()` ruled out.
- Linux abnormal native-lifetime stop: raw `exit_group(70)` stubs (x86_64
  syscall 231 / i686 int 0x80 252), a final-owner Drop guard, and a 30-second
  shutdown-deadline controller, per the native ownership contract; qualified
  by the stop-topology receipts (C3M Tasks 3-4, 32/32 on all four
  x86_64/i686 x gnu/musl variants).
- X3DH key-exchange mechanism support (`CKM_X3DH_INITIALIZE`/`RESPOND`),
  with FFI conversion and proto round-trips; re-verified on x86_64 and i686
  plus both Miri models (C3M Task 6, no waiver).
- Mechanism-registry coverage for the Wave 3 gaps: single-DES CFB/OFB IV
  shapes, SSL3/TLS keygen and MAC version/length shapes, CAMELLIA/ARIA/SEED
  `ECB_ENCRYPT_DATA` derivation, and documented vendor overlays (BouncyHSM
  BLAKE2B, opencryptoki ECDH-X/COF) as operator opt-ins.
- Tenancy model: object-path logical-login enforcement, last-context-out
  backend logout, faithful `ALREADY_LOGGED_IN` mapping, and refcounted
  teardown reaping (ADR-0002 rewrite; ADR-0008 superseded).
- Release evidence: 30-provider pooled transparency matrix (~3.39M tests
  through the proxy at `bd95ffa`), verdict DONE_WITH_CONCERNS; see the
  umbrella release-record pack `2026-09-16-v020-release-execution-plan`
  (`c3m-wave3-report-final.md`, review, erratum, `c3m-35-reverification.md`).

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
- `pkcs11-module` is now consumed as a rev-pinned git dependency from
  `https://github.com/mingulov/pkcs11-components` (which also provides the
  `pkcs11-abi` layout catalog) instead of the nested `crates/module`; the
  nested crate is removed. The backend keeps using the same
  `pkcs11_module::{function_list, tables::{...}}` API via the upstream
  re-export, so runtime behavior is unchanged. `pkcs11-proxy-ng-types` stays
  nested: it carries proxy-specific exact-output contracts and registry
  policy (effect validation, apply flags, operator exclusion, wiping secret
  owners) that the generic upstream `pkcs11-types` does not provide.
- `C_Login` on a slot held by another live context returns
  `CKR_USER_ALREADY_LOGGED_IN` faithfully and mints no logical login; the
  cached-PIN verifier is removed (ADR-0008 superseded by the ADR-0002
  rewrite). One-login-holder-per-slot is the mandated trade-off, bounded by
  the last-context-out and refcounted-teardown release paths. Login also
  self-heals a holderless-but-logged-in backend (F-01 reconcile: one logout
  + single retry → `OK`).

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
- Slot, session, object, and mechanism-type handles crossing into
  native calls are now range-checked: an unrepresentable `u64` on a
  narrow-`CK_ULONG` host fails with `CKR_FUNCTION_FAILED` instead of
  silently truncating (same fail-loud doctrine as the existing
  `narrow_wire_ulong` conversions). No behavior change on 64-bit
  hosts, where the checks are pass-throughs.
- Daemon SIGSEGV on 0-length attribute buffers: empty exact-output buffers now
  cross FFI as NULL `pValue`, and the daemon synthesizes
  `CKR_BUFFER_TOO_SMALL` for lenient backends instead of crashing.
- Remaining empty-buffer FFI conversion sites hardened to the same NULL
  convention.
- C3M review findings: `Retiring` occupancy across dependent retirement and
  dlclose (F-02); failed `C_Initialize` poisons instead of recycling the
  reservation (F-03); checked lifecycle generation plus refusal of re-init
  after a failed `C_Finalize` (F-08); FIPS hard-excludes restored for the
  missing ARIA/SEED/Camellia family members (F-09/F-10).
- Caller-NULL templates and empty GCM IV/AAD and OAEP source pointers now
  cross the wire with null bits and materialize as NULL on the daemon,
  instead of conflating NULL with empty (D2/F3).
- The daemon rejects downgraded `C_GetInterface` answers whose leading
  `CK_VERSION` is below the requested version, instead of publishing a
  phantom interface list (D3/F5).
- SSL3/TLS/WTLS key-material OUT handles from derive operations are
  virtualized like SP800-108 additional handles (D4/F6).
- Caller-preset nested `GetAttributeValue` query types are forwarded instead
  of being forced to 0 (D5/F7).
- Absurd output capacities answer `CKR_ARGUMENTS_BAD` at the output-spec
  boundary instead of `CKR_HOST_MEMORY` (D7/F4; ADR-0010 Limits-(d)).
- Find-enumeration login filtering (tenancy F-04): `C_FindObjects` results
  are filtered by the querying context's login state — a logged-out context
  observes only known-public objects' handles and counts, closing the
  existence oracle that leaked private objects' bare handles while another
  tenant held the backend logged in. Unknown privacy hides fail-closed;
  logged-in behavior is unchanged.
- Logged-out USE of virtualized key-mat/SP800-108 handles now refuses: the handles are recorded private at registration, closing the fail-open hole on failing backend probes (review-A m-1).
- `C_CloseAllSessions` releases the last-holder backend login before the batch close, silencing the routine operator WARN on ordinary logged-in close-all (review-A m-5).
- `C_CloseSession` of the last session releases the last-holder backend login before the backend close via the closing session as carrier, silencing the same routine operator WARN on the singular path (T5F follow-up to review-A m-5).
- Lifecycle read exclusion for retained native roots (C3M F-01): every
  admitted ordinary invocation now holds lifecycle read exclusion through
  native return, validation and settlement (compile-time-enforced guard
  proof at each native entry); `Finalize` seals admission and drains
  in-flight work before its exclusive native call; closes/cancels ride
  per-session fences; destructor cleanup rides the enclosing exclusion
  and backend `Drop` probes domain quiescence. The P0
  lifecycle-exclusion clause is implemented; the ownership-doc clause is
  marked IMPLEMENTED.

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
- Daemon login-family secret holders (login PIN, SO PIN, user PIN,
  old/new PINs, protected-auth username) moved from `Zeroizing` to
  the redacting `SecretBytes` owner: buffers are still wiped on drop
  and now also redact in `Debug`, so no current or future log line
  capturing a holder can leak secret bytes. The unused `zeroize`
  dependency was removed from the server crate.
- ADR-0013 secret migration complete: all 162 manifest-secret fields travel
  in wiping `SecretBytes` owners from the conversion boundary to the PKCS#11
  ABI with 0 waivers; secret wire messages carry redacted `Debug`; and a
  descriptor-aware pre-decode tower layer rejects duplicate fields, repeated
  oneof members, groups, truncation, and depth bombs before prost allocates.
  Independent 7.4 security review ACCEPT (0 Critical); all findings addressed.
- Privacy verification evidence (C3M Task 8): audit suites, 6-canary 0-leak
  checks, 5-drop sentinels, exit-70 honesty, and 34/34 + 32/32 static audits
  re-derived by the reviewer, mapped in `privacy.md`; plus a handler-level
  fail-closed-after-side-effect regression test.
- Closed the Wave 3 F1 authorization hole: a logically logged-out context's
  private-object create/copy/use is refused with `CKR_USER_NOT_LOGGED_IN`
  even when another tenant holds the backend logged in (D6; re-verified live
  on kryoptic, regressions 1→0).

### Known limitations

- Message-API AEAD Init shapes (§7.3) stay OPEN: the proxy strictly requires
  message structs on `C_MessageEncrypt/DecryptInit` by documented fail-closed
  design, while kryoptic/NSS leniently accept classic structs and the
  pkcs11-check `ccm` recipe packs the classic struct — a framework-recipe bug
  observed through deliberate proxy strictness (report erratum E1; framework
  fix drafted upstream, and the strictness is now documented in ADR-0010
  Limits-(c) and the runbook). No proxy-leniency diff in v0.2.0 (Ruling 3).
- Windows guest re-validation at the freeze HEAD is a follow-up: v0.2.0 ships
  on the Wave-1 T6 real-Windows receipts plus a green Windows-target compile
  check at freeze (Ruling 4). Pooled pkcs11-check suites on Windows have no
  plan-defined runner yet.
- Static musl proxy binaries are proven: the musl release build runs in the
  per-PR Tier 0g `musl-x86_64` CI job (musl target + `musl-gcc` linker; the
  freeze-gate failure was the nonexistent `x86_64-linux-musl-gcc` name) and
  the artifacts execute natively on Alpine — see
  `doc/release/musl-tier.md`. Linkage split: daemon + CLI build fully
  static, while the serving daemon and the shim stay musl-dynamic (a static
  binary cannot `dlopen` — musl answers "Dynamic loading not supported" —
  so the static daemon executes but cannot serve; the CLI never dlopens
  and drives the live smoke). The static CLI, dynamic daemon, and shim
  complete a live SoftHSM2-backed smoke on glibc-less Alpine; D8 is
  live-proven (Ruling 5).
- Backend bugs found by the matrix are filed as upstream drafts, not sent:
  opencryptoki AES-KWP heap overflow (F8, CVE-candidate), wolf curve-less EC
  crash (F9), opensc ECDH crash (F10), NSS ML-DSA short-signature accept with
  an open mechanism (F11 — no ML-DSA verify soundness claim shippable).
  Drafts live under `doc/vendors/upstream-drafts/` in the umbrella.
- D2 null-fidelity scope (m-2/m-3): class-4 null-bit coverage is GCM/OAEP
  only (classic GCM proven; CCM empty-field behavior untested — CCM/wrap
  shapes still conflate (NULL,0)/(ptr,0) at daemon materialization).
  `GetAttributeValue` query probes likewise still collapse (NULL,0) to
  (ptr,0) (no `template_null` bit on the query path). Disclosure only; no
  wire expansion.
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
