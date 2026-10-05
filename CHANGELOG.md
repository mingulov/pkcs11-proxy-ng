# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] - 2026-10-05

v0.2.2 is a testing candidate that follows the published v0.2.1
release. Its theme is client-blocker repair: three v0.2.1 regressions
reported against a real client project are fixed with failing-first
regression tests and A/B base-vs-patched validation. See the [candidate
notes](doc/release/v0.2.2-release-notes.md).

### Fixed

- Daemon crash on `C_MessageEncryptInit` with `CK_CHACHA20_PARAMS` (#37):
  unmodeled message-opaque parameter bytes are no longer forwarded
  verbatim when the mechanism declares a pointer-struct shape. A strict
  shape gate (`message_opaque_admits_shape`) admits only byte-buffer and
  parameterless shapes and fails closed on unknown shapes; the shim
  refuses locally with `CKR_MECHANISM_PARAM_INVALID` (zero RPC), and the
  server backstop refuses opaque struct images at message-init, plain
  encrypt/decrypt init, and authenticated-wrap validation. Flat-byte
  opaque (e.g. CBC IV) and typed classic ChaCha20 paths are unchanged.
- Private `CKO_DATA` objects lost across logout/login (#35): providers
  that rotate private handles at logout no longer strand session-scoped
  objects. Positively session-scoped (`CKA_TOKEN=false`) unmapped
  handles are admitted when the session is the sole holder on the slot,
  with post-scan re-verification; shared-slot handles stay hidden per
  CROSS-PROC-001 isolation.
- `CKO_CERTIFICATE` objects never found (#36): providers that omit
  `CKA_PRIVATE` when unset (absent means public) are honored via the
  mint-record fallback, which admits recorded-public objects and keeps
  recorded-private, unrecorded, and foreign handles hidden.
- Last-mile message-opaque backstop (review F-01): fresh message-init
  construction re-checks admission against the request registry
  snapshot carried by the validated mechanism — the same snapshot the
  server gate used, so the two cannot disagree. Begin/Next/OneShot
  byte-reuse splits into a separate documented constructor.
- Cross-context destroy eviction (review F-02): `C_DestroyObject`
  now evicts the backend handle's mappings, privacy bits, and cached
  metadata in every context, closing the daemon-mediated
  handle-recycling ABA leg. Out-of-band provider mutation stays an
  accepted residual (see notes).

### Known limitations

- All v0.2.1 limits carry forward, including the single logical client in
  one trusted security domain per daemon/provider instance. The v1
  typed-presence wire is decode-side only at the Phase-2 gate where
  noted; mixed shim/daemon versions are unsupported. Backend token
  objects outlive the client's Finalize/Initialize cycle (#27);
  stale-session message calls answer SHI by default and may differ
  from args-first native providers (#23 defect 4).
- Message-path mechanisms whose parameter shape is unmodeled are refused
  with `CKR_MECHANISM_PARAM_INVALID` instead of forwarding caller bytes;
  typed support for additional message parameter shapes is future work.

## [0.2.1] - 2026-10-04

v0.2.1 is a release that supersedes the published v0.2.0
release. Its theme is shape truthfulness: caller-NULL versus empty
distinctions are now preserved exactly across the shim, wire, daemon, and
backend FFI, with machine-checkable mechanism-parameter shapes and
transport validation at every server site. See the [release
notes](doc/release/v0.2.1-release-notes.md).

### Added

- Typed presence v1 wire schema (`Flat`/`Null`, version 83) with a
  machine-checkable mechanism-parameter manifest: shared shape
  descriptors, resolver, fingerprints, and a Phase-2 gate. The shim emits
  typed v1 readers with presence; the server validates transport shape
  (`PointerBytes`, `ValidatedMechanismParams`) at every handler site; the
  backend reconstructs Flat/Null at the FFI boundary with guarded backing.
  Verbatim and completeness quality gates pin the behavior, and exotic-tail
  envelopes cover the remaining input-pointer tail under decision D1(a).
- End-to-end `C_GetAttributeValue` template presence (FIX-1): a
  `template_null` wire bit travels from the shim through the daemon to the
  backend FFI, which materializes a real NULL for absent templates. The
  daemon fail-closed rejects an absent marker with a non-empty payload.
  Proven against a real Kryoptic backend, where NULL versus empty is
  provider-observable.
- Truthful 3.0 advertisement from slot provenance with 3.0 to 3.1 to 3.2
  dispatch, plus discovery of explicit `{3,1}` interfaces.
- Packed-32 (win32 ILP32) as a fourth v1 ABI, with
  `ParamAbi::native()` for 32-bit Windows.
- Shim regression nets: read-after-destroy canary (#26), NULL-shape
  termination/parity net (#30, #31), blocking slot-wait refusal with
  finalize regression (#25), async fixed-refusal 16-leg matrix (#24), and
  post-restart stale-handle `0x82` regression (#32).
- Assurance: cargo-fuzz harnesses with corrected seeds, expanded Miri
  scope, Kani proofs adopted for the width-translation laws, a coverage
  ratchet, and secret-boundary canaries with attribute classifier laws.
- Performance instrumentation: T1 comparator with receipts, RSA/EC keygen
  template parity gate, sign-pair latency bench receipts, degraded-
  operation control qualification (T3), and direct-leg bench mode (T4).
- macOS arm64 bundle packaging with smoke, CI lanes, and install doc.
- Release engineering: single-invocation workspace repackaging, tag
  checkout with out-of-repo artifact staging, CI candidate resolution from
  the green tag run, and cut-release dispatch fixes.

### Fixed

- Message-path shape handling: request-shape validation before session
  resolution (S1D4), residual auth-blocking gates hoisted above the
  session lock (SDD T4), NULL/nonzero preservation on `VerifyMessageNext`
  (S1D3), CK_ULONG-aligned provider-written query output (SDD T5), Raw
  auth-input negative branch coverage (SDD T1), Raw message parameters
  accepted at the backend FFI boundary, and D6(1)-gated operations
  forwarded after a contended PIN login.
- Verify-then-fix campaigns for independent review findings (F1-F6,
  NF1-NF7) and the deferred-minor wave (R16/R18/R19/R21/R23).
- Pre-existing i686/Windows test failures, win32 `ParamAbi::native()`,
  and win32 manifest failures on CRLF checkouts.
- Recorded decisions: RF-MC-ORDER option (a) — session arms stay
  SHI-first with an arm-difference pin; S1D4 AB-beats-stale-session
  scoped to `sanitize_inputs` on with a spec-precedence pin (#23).
- Solved decisions: memory token objects survive the client
  Finalize/Initialize cycle by design, pinned by a restart-lifecycle
  lock test (#27, known issue); #23 defect 4 solved as an accepted
  limitation — default SHI-first per spec §5.1.7 with a sanitize-on
  AB-first exception, native Kryoptic args-first order pinned as
  provider evidence.

### Known limitations

- All v0.2.0 limits carry forward, including the single logical client in
  one trusted security domain per daemon/provider instance. The v1
  typed-presence wire is decode-side only at the Phase-2 gate where
  noted; mixed shim/daemon versions are unsupported. Backend token
  objects outlive the client's Finalize/Initialize cycle (#27);
  stale-session message calls answer SHI by default and may differ
  from args-first native providers (#23 defect 4).

## [0.2.0] - 2026-09-28

v0.2.0 is a release for one logical client in one trusted security
domain per daemon/provider instance. Restart both before switching independent
clients or domains. Multi-client isolation and final platform/provider
validation remain open; see the [release notes](doc/release/v0.2.0-release-notes.md).

### Added

- Optional authorization policies based on client certificate identity, with
  object, class, mechanism, and extraction grants; per-principal rate and
  session quotas; and per-slot failed-login limits. Unmatched identities are
  denied when a policy is configured. `allow_all_authenticated` is an explicit
  override; `anonymous_principal` is an audit label and never grants access.
  Policies and allow-all settings require authenticated listeners.
- Tamper-evident audit logs with a hash chain and signed checkpoints. Records
  contain operational metadata, never PINs, keys, or raw payloads. Data-plane
  records can be dropped with gap reporting; fail-closed security records can
  reject a request after a backend side effect.
- Startup backend attestation using the module hash and library/token identity.
  Configuration hashes and reconnect/hot-swap re-attestation are not included.
- Backend object-population limits, authenticated local metrics, and optional
  context-scoped attribute coalescing.
- `[proxy] sanitize_inputs = true` to reject NULL data pointers with nonzero
  lengths and NULL init mechanism pointers before calling the provider. It
  defaults to `false`. Rejections return `CKR_ARGUMENTS_BAD` and leave the
  active backend operation intact.
- Server-managed mechanism registry, reloadable with SIGHUP and distributed
  to shims through `GetBackendInterfaces`. Operator exclusions hide mechanisms
  from discovery and reject their use with `CKR_MECHANISM_INVALID`.
  `PKCS11_PROXY_DISABLE_SERVER_REGISTRY=1` selects the local registry for testing.
- Startup and shutdown timeouts (30 seconds by default), a configurable backend
  health failure threshold, rejection of the shipped placeholder module path,
  and a startup warning for explicitly enabled unauthenticated TCP.
- Legacy `PKCS11_PROXY_SOCKET=tcp://host:port` support.
  `PKCS11_PROXY_ENDPOINT` takes precedence when both are set.
  `LOG_FORMAT=plain` selects readable logs; JSON remains the default.
- Alpine 3.22/3.23 APK and Amazon Linux 2023 RPM builds in GitLab CI. Packages
  are split into shim, daemon, and CLI, with an optional compatibility symlink
  package. Carrier images expose packages at `/apk` or `/rpm`.
- Windows x64/MSVC daemon and shim builds, a Windows ZIP release bundle, and
  additional Linux cross-width, musl, and platform checks. Validation limits
  are listed in the [release notes](doc/release/v0.2.0-release-notes.md).
- Typed X3DH transport and backend FFI conversion. The shim still rejects
  direct parameterized X3DH calls because their caller pointers lack bounded
  lengths; see [parameter support](doc/oasis-profile-coverage.md).
- Mechanism parameter layouts for DES CFB/OFB, SSL3/TLS keygen and MAC,
  CAMELLIA/ARIA/SEED encrypt-data derivation, BLAKE2B HMAC_GENERAL, and
  ECDH-X/COF AES-wrap.

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
- `C_Login` on a slot held by another live context returns
  `CKR_USER_ALREADY_LOGGED_IN` faithfully and mints no logical login; the
  cached-PIN verifier is removed (ADR-0008 superseded by the ADR-0002
  rewrite). One-login-holder-per-slot is the mandated trade-off, bounded by
  the last-context-out and refcounted-teardown release paths. Login also
  self-heals a holderless-but-logged-in backend (F-01 reconcile: one logout
  + single retry → `OK`).
- `pkcs11-module` is now consumed from crates.io (version 0.2, which also
  provides the `pkcs11-abi` layout catalog) instead of the nested
  `crates/module`; the nested crate is removed. The backend keeps using the same
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
- The minimum Rust version is 1.88, with edition 2024. CI checks that version;
  packaging uses rustup where the distribution compiler is older.
- Release builds use thin LTO, symbol stripping, and one codegen unit.
  Client artifacts no longer include the server's tonic features.
- The shim replaces its mechanism registry atomically when reprobed.
  `state::mechanism_registry()` now returns `Arc<MechanismRegistry>`;
  `replace_mechanism_registry` replaces `init_mechanism_registry`.
- `Pkcs11Client::get_backend_interfaces()` returns `BackendProbe`, containing
  interfaces and the mechanism registry. `Pkcs11ProxyService::new()` takes a
  `MechanismRegistrySource`.
- Module loading and ABI layouts come from the published
  [pkcs11-components](https://github.com/mingulov/pkcs11-components) crates
  on crates.io (version 0.2).
  Proxy-specific types remain in this repository.
- Admitted `C_Login` and `C_LoginUser` calls reach the backend even when a
  context already holds the slot login. Provider PIN errors and `ALREADY`
  results are preserved; `ALREADY` does not establish a logical login.
  Reconciliation of a backend login with no logical holder still uses one
  logout and one login retry.
- Secret-classified `Pkcs11Client` results return `SecretBytes` instead of
  `Vec<u8>`. Read them through `SecretBytes::expose`. This affects
  `wrap_key`, `wrap_key_authenticated` (both tuple members),
  `wrap_key_authenticated_typed` (wrapped blob),
  `unwrap_key_authenticated` (opaque parameter), `get_operation_state`,
  `generate_random`, `async_complete` (payload), `async_join`, the decrypt
  family (including `*_with_mechanism_out`, `decrypt_digest_update`, and
  `decrypt_verify_update`), `verify_recover`, and opaque or recovered-data
  members of message encrypt/decrypt/sign results. Ciphertext, digests,
  signatures, KEM ciphertext, and generated IVs remain plain `Vec<u8>`.

### Fixed

- NULL data pointers and NULL `C_VerifyInit`/`C_DigestInit` mechanism pointers
  reach the backend with their original lengths when sanitization is disabled.
  The backend determines the return value and operation state.
- Oversized or overflowing input lengths return `CKR_ARGUMENTS_BAD`.
  Embedded mechanism data is checked before reading; oversized parameters
  return `CKR_MECHANISM_PARAM_INVALID`. The 64 KiB struct limit no longer
  rejects valid embedded data, which has a separate 512 MiB transport limit.
- Native handles and mechanism IDs are range-checked before conversion to
  narrower `CK_ULONG` values, returning `CKR_FUNCTION_FAILED` on overflow.
- Native allocations remain owned while a provider may retain their pointers.
  Finalization closes admission and drains active calls before native cleanup.
  Failed initialization/finalization cannot recycle unsafe state. Unresolved
  retention uses the platform-specific whole-process stop described in the
  [ownership contract](doc/release/native-mechanism-ownership.md).
- Caller-NULL templates, empty GCM/CCM IV and AAD pointers, and OAEP source
  pointers retain their NULL/present distinction in the covered conversion
  paths.
- Interface discovery rejects a backend interface older than the requested
  version.
- SSL3/TLS/WTLS and SP800-108 derived output handles are virtualized and
  registered as private.
- Nested attribute queries preserve the caller's requested attribute types.
  Present zero-capacity attribute buffers keep their original capacity and
  output-length semantics. Oversized output capacities return
  `CKR_ARGUMENTS_BAD`.
- `C_FindObjects` uses the querying context's login state and object class.
  Storage objects with unknown privacy are hidden from logged-out queries.
  These checks do not establish multi-client isolation.
- Session cache eviction occurs on every close attempt. Closing the final
  session or all sessions releases the last logical holder's backend login
  before closing the native session.
- Successful `C_CopyObject` uses the copied object's `CKA_TOKEN` value when
  available. If its lifetime cannot be determined, native success is retained
  with a session-scoped virtual handle that may expire before the native object.
- Deriving with an explicitly destroyed base-key handle returns
  `CKR_KEY_HANDLE_INVALID`.
- NULL credential pointers with nonzero lengths are rejected locally with
  `CKR_ARGUMENTS_BAD` because the wire format cannot preserve that shape.
  This is a transport limit; protected-authentication providers may accept
  such inputs directly.
- Restored missing ARIA, SEED, and Camellia exclusions in the FIPS example.

### Security

- Completed the 2026-06-04 full-project review remediation (67 verified
  findings, all closed). Highlights: cross-client logical-login PIN validation and
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
- Added request-context ownership checks, object-handle virtualization,
  certificate-bundle validation, per-context concurrency limits, serialized
  slot login/logout, and bind-time Unix-socket permissions. Multi-client
  authentication-state and privacy isolation still require the v0.3 work.
- Secret buffers use wiping owners with redacted `Debug` output. Secret wire
  fields are classified, and malformed or ambiguous protobuf input is rejected
  before secret-bearing generated messages are allocated. See the
  [privacy contract](doc/release/privacy.md) for memory-lifetime limits.
- Added private-object create/copy/use checks for attempts to borrow another
  context's backend login.

### Known limitations

- `C_WaitForSlotEvent` accepts nonblocking calls only; blocking calls return
  `CKR_FUNCTION_NOT_SUPPORTED`.
- Message-AEAD parameter shapes and unqualified mechanism/wrap pointer shapes
  have compatibility limits. `GetAttributeValue` query probes still collapse
  a NULL zero-length template to a present zero-length template. See the
  [runbook](doc/runbooks/operating-pkcs11-proxy-ng.md). Shim and daemon versions
  must match.
- The musl daemon must use dynamic linking to load providers. The static CLI
  can be used with it; a static daemon cannot serve native modules.
- Platform builds, stub tests, and historical provider runs do not qualify the
  final candidate. Current evidence and remaining release work are listed in
  the [release notes](doc/release/v0.2.0-release-notes.md).

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
[0.2.0]: https://github.com/mingulov/pkcs11-proxy-ng/releases/tag/v0.2.0
