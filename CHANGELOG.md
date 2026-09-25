# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

v0.2.0 is a testing candidate for one logical client in one trusted security
domain per daemon/provider instance. Restart both before switching independent
clients or domains. Multi-client isolation and final platform/provider
validation remain open; see the [candidate notes](doc/release/v0.2.0-release-notes.md).

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
  are listed in the [candidate notes](doc/release/v0.2.0-release-notes.md).
- Typed X3DH transport and backend FFI conversion. The shim still rejects
  direct parameterized X3DH calls because their caller pointers lack bounded
  lengths; see [parameter support](doc/oasis-profile-coverage.md).
- Mechanism parameter layouts for DES CFB/OFB, SSL3/TLS keygen and MAC,
  CAMELLIA/ARIA/SEED encrypt-data derivation, BLAKE2B HMAC_GENERAL, and
  ECDH-X/COF AES-wrap.

### Changed

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
- Module loading and ABI layouts come from the revision-pinned
  [pkcs11-components](https://github.com/mingulov/pkcs11-components) dependency.
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
  the [candidate notes](doc/release/v0.2.0-release-notes.md).

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
