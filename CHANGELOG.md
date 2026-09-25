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
  `ECB_ENCRYPT_DATA` derivation. Standard BLAKE2B HMAC_GENERAL and ECDH-X/COF
  AES-wrap parameter layouts are now in the default registry; existing
  operator overlays remain compatible.
- Context/login infrastructure: object-path checks, last-context-out backend
  logout, backend-authoritative login and refcounted teardown reaping
  (ADR-0002; ADR-0008 superseded). These mechanisms do not establish
  multi-client isolation for the v0.2 testing baseline.
- Historical provider testing at `bd95ffa`: a 30-provider pooled run recorded
  DONE_WITH_CONCERNS. This historical development result does not qualify the
  current candidate. The last 30-provider comparison run ended with all 30 comparisons incomplete;
  see the [candidate notes](doc/release/v0.2.0-release-notes.md).

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
- v0.2.0 is an unreleased single-logical-client testing baseline in one trusted
  security domain per daemon/provider. Restart both before changing independent
  clients or domains. `max_contexts = 1` is only an admission guardrail;
  multi-client authentication-state and privacy isolation remain
  [v0.3 work](doc/release/v0.3.0-scope.md).
- Admitted `C_Login`/`C_LoginUser` attempts reach the backend even when the
  same or another context holds the slot login. Provider return values,
  including PIN errors and `ALREADY` variants, are preserved; `ALREADY` does
  not establish logical login. The holderless-backend reconciliation path
  remains one logout plus one login retry. See ADR-0002.
- `pkcs11-module` is now consumed as a rev-pinned git dependency from
  `https://github.com/mingulov/pkcs11-components` (which also provides the
  `pkcs11-abi` layout catalog) instead of the nested `crates/module`; the
  nested crate is removed. The backend keeps using the same
  `pkcs11_module::{function_list, tables::{...}}` API via the upstream
  re-export, so runtime behavior is unchanged. `pkcs11-proxy-ng-types` stays
  nested: it carries proxy-specific exact-output contracts and registry
  policy (effect validation, apply flags, operator exclusion, wiping secret
  owners) that the generic upstream `pkcs11-types` does not provide.
- Secret-classified `Pkcs11Client` results now return the wiping
  `SecretBytes` owner instead of `Vec<u8>` (T13; pre-release API migration,
  no compatibility shim): `wrap_key`, `wrap_key_authenticated` (both tuple
  members), `wrap_key_authenticated_typed` (wrapped blob),
  `unwrap_key_authenticated` (opaque parameter member),
  `get_operation_state`, `generate_random`, `async_complete` (payload
  member), `async_join`, the decrypt family (`decrypt`, `decrypt_update`,
  `decrypt_final`, the three `*_with_mechanism_out` byte members,
  `decrypt_digest_update`, `decrypt_verify_update`), `verify_recover`,
  and the message-API opaque members (`encrypt_message`,
  `encrypt_message_begin/next`, `decrypt_message`,
  `decrypt_message_begin/next` bytes and recovered data, `sign_message`,
  `sign_message_begin/next` parameter members). Read bytes inside
  `SecretBytes::expose`; exact-output result shapes are unchanged and
  their buffers are now adopted without copying. Public outputs stay
  plain `Vec<u8>`: ciphertext, digests, signatures, KEM ciphertext, and
  generated mechanism parameters (IVs).

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
- `C_FindObjects` filtering uses the querying context's login state and object
  classification. For logged-out queries, storage objects with unknown privacy
  are hidden; recognized non-storage metadata classes have separate visibility
  rules. This find-filter behavior does not establish multi-client privacy or
  authorization isolation, which remains v0.3 work.
- Virtualized key-material/SP800-108 handles are recorded private at registration.
  Their use follows the private-object admission checks; this metadata does not
  by itself establish cross-client isolation.
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

- Present zero-capacity attribute buffers retain their original native capacity
  and output-length semantics; fixed-size scalar scratch storage does not
  promote them into larger caller buffers. Focused same-width SoftHSM2 checks
  cover this correction; cross-ABI and live NSS coverage are not established
  by those checks.
- Successful `C_CopyObject` results use the copied object's actual `CKA_TOKEN`
  value when available, including inherited defaults and explicit overrides.
  If lifetime cannot be established from provider metadata or an explicit
  valid template value, native success is preserved with a session-scoped
  virtual handle that may expire on copying-session close even when the native
  object persists. See the candidate notes for this metadata limit.

- Derivation with an explicitly destroyed base-key handle returns the
  key-specific `CKR_KEY_HANDLE_INVALID` through the key resolver, preserving
  the distinction from object-handle errors.
- Credential NULL pointers with nonzero lengths are refused locally with
  `CKR_ARGUMENTS_BAD` because the credential wire representation cannot preserve
  that shape. This is a supported-input limit, not a universal PKCS#11
  invalidity rule; protected-authentication paths may ignore a NULL PIN's length.

### Security

- Historical 2026-06-04 review remediation recorded 67 findings closed at its
  reviewed source. This is not a current-candidate security completion claim.
  Highlights: cross-client logical-login PIN validation and
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
  The historical 7.4 review recorded ACCEPT for its reviewed source; this is
  not qualification of the current candidate's multi-client isolation.
- Privacy verification evidence (C3M Task 8): audit suites, 6-canary 0-leak
  checks, 5-drop sentinels, exit-70 honesty, and 34/34 + 32/32 static audits
  re-derived by the reviewer, mapped in `privacy.md`; plus a handler-level
  fail-closed-after-side-effect regression test.
- Added private-object create/copy/use checks against cross-context borrowing
  of a live backend login. The current candidate forwards to the backend when
  no other live context holds that login. Review findings about default
  attributes and native-lifetime login synchronization are deferred to v0.3;
  this entry is not a claim that multi-client isolation is repaired or verified.

### Known limitations

- Message-API AEAD Init shapes (§7.3) stay OPEN: the proxy strictly requires
  message structs on `C_MessageEncrypt/DecryptInit` by documented fail-closed
  design, while kryoptic/NSS leniently accept classic structs and the
  pkcs11-check `ccm` recipe packs the classic struct — a framework-recipe bug
  observed through deliberate proxy strictness (report erratum E1; framework
  fix drafted upstream, and the strictness is now documented in ADR-0010
  Limits-(c) and the runbook). No proxy-leniency diff in v0.2.0 (Ruling 3).
- Windows historical interoperation receipts and compile gates do not
  establish qualification of the final candidate. Retain the scope of each
  runtime comparison and the separate win32 stub-provider tier; no general
  Windows provider-matrix claim is made.
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
  These historical findings are retained in private development records;
  this repository does not claim that upstream reports were submitted.
- Classic CCM IV/AAD NULL flags now travel through the mechanism conversion
  paths. A real Kryoptic client → gRPC → server → FFI AES-CCM check exercised
  encrypt/decrypt with a valid 12-byte nonce and empty AAD supplied as either
  NULL or a present pointer: both round trips recovered the plaintext and
  produced ciphertext with a 16-byte MAC. Kryoptic accepts both forms, so
  those live operations do not distinguish native pointer identity; separate
  shim/protobuf/FFI structural tests check pointer presence. This does not
  qualify other CCM pointer shapes, CCM/wrap layouts, or providers. The local NSS and SoftHSM2
  modules do not advertise CCM; no CCM result is claimed for them.
- Pointer-fidelity limits remain for unqualified mechanism/wrap shapes.
  `GetAttributeValue` query probes still collapse (NULL,0) to (ptr,0)
  (no `template_null` bit on the query path). Mixed-version shim/daemon peers
  remain unsupported; pointer-shape differences can change acceptance as well
  as returned errors. See the runbook's lockstep warning.

## [0.1.0] - 2026-05-15

Initial release of the Rust PKCS#11 remote proxy.

### Added

- **`pkcs11-proxy-ng`** daemon: gRPC/protobuf server that forwards PKCS#11
  operations from clients to backend tokens and HSMs.
- **`pkcs11-proxy-ng-cli`**: administrative and smoke-test command-line tool
  for managing daemon configuration, auth policy, and provider backends.
- **`libpkcs11_proxy_ng_shim.so`**: loadable PKCS#11 v2.40 / v3.0 / v3.2 shim
  library that consumers (NSS, OpenSC, GnuTLS, application code) link against
  to talk to the daemon. 104 functions implemented across all three interface
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
