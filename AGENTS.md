# Contributor Rules

These rules are mandatory for anyone changing code in `pkcs11-proxy-ng/`, including
AI agents, automation, and human contributors.

## 1. Follow The Existing Design

- Treat the current code and in-tree user/release docs as the active standalone
  contract. The PRD, ADRs, and architecture overview live in the private
  `pkcs11-proxy-ng-ws` planning workspace; consult them for design work there.
- Do not change handle semantics, error semantics, authorization semantics, or
  mechanism-policy behavior implicitly.
- If a change alters architecture or externally visible behavior, update the
  relevant ADR in that planning workspace before or alongside the code change,
  and document the resulting public behavior here.

## 2. Preserve PKCS#11 Semantics

- **The shim must behave identically to a native PKCS#11 module from the
  application's perspective.** An application loading the shim .so should not
  be able to distinguish it from loading the real backend .so directly, except
  for network latency and explicitly documented support/transport limits. This
  is the primary correctness requirement within the supported scope.
- The selected v0.2 P0 amendment deliberately limits `C_WaitForSlotEvent` to
  `CKF_DONT_BLOCK`, with shared native event flags, checked widths and documented
  local refusals. It also requires one managed provider chain and a qualified
  Linux whole-process lifetime stop. These contracts are implemented in the
  unreleased v0.2 testing candidate; historical acceptance evidence does not
  establish qualification of each later revision. Follow
  `doc/release/native-mechanism-ownership.md` and the amended ADRs.
- The shim uses exact/raw output semantics: it sends the caller's buffer
  specification to the backend, the backend performs one PKCS#11 call with
  those exact parameters, and the shim writes back the exact result. The shim
  must never locally reconstruct `CKR_BUFFER_TOO_SMALL`, fabricate output
  lengths, or invent per-attribute results.
- Preserve exact `CK_RV` values whenever possible; do not collapse multiple
  PKCS#11 errors into one generic error.
- Scope split: a difference the provider shows without the proxy is a
  **provider** matter, not a proxy bug — triage every direct-vs-proxied
  mismatch per [parity-validation](./doc/release/parity-validation.md),
  fix proxy bugs in the proxy, and report provider-conformance issues
  upstream. Never normalize provider behavior inside the proxy:
  provider conformance fixes are out of proxy scope.
- Do not invent compatibility claims such as “full PKCS#11 support”.
- Keep the current discovery and mechanism policy intact unless a design change
  is explicitly intended and documented.

### v0.2 testing scope

- v0.2 supports one logical client in one trusted security domain per
  daemon/provider instance. Mutually untrusted clients and independent domains
  must not share it. Restart the daemon/provider before switching independent
  clients or domains.
- `max_contexts = 1` is an admission guardrail, not an isolation repair.
  Multi-client authentication-state and object-privacy work is deferred to
  `doc/release/v0.3.0-scope.md`; do not describe it as completed.
- Preserve native semantics within the stated scope. A narrower testing scope
  does not authorize removing authorization checks or normalizing provider RVs.

## 3. FFI Safety Is Non-Negotiable

- Never allow a Rust panic to unwind across an `extern "C"` boundary.
- Keep null-pointer checks, buffer-length checks, and two-call output semantics
  explicit and correct.
- Do not weaken ABI compatibility for PKCS#11 2.40, 3.0, or 3.2 interfaces.
- Avoid undefined behavior even if a caller is buggy; where that is impossible,
  fail early and conservatively.
- When adding new mechanism parameter types, ensure BOTH directions work:
  - Proto→Rust (`TryFrom<&proto::Mechanism>`) for server-side deserialization
  - Rust→C struct (`mechanism_to_ffi()` in `ffi/ffi_conversion.rs`) for backend FFI calls
  - Rust→Proto (`From<&CkMechanism>`) for client-side serialization
  Missing any direction causes silent failures at runtime.

## 4. Security Rules

- Never log PINs, keys, raw secrets, certificates’ private material, or other
  sensitive request payloads.
- Do not switch the release profile to `panic = "abort"`. Several PIN/key
  handling structs in `crates/types/src/mechanism.rs` rely on
  `ZeroizeOnDrop` running during stack unwinding to wipe password buffers
  on panic. With `panic = "abort"` those drops do not run.
- The selected abnormal native-lifetime stop is the explicit exception to
  normal wiping/destruction: unresolved retained storage must not be wiped or
  freed. It preserves unwinding for ordinary panics and requires the exact
  target/environment/retirement contract in the native-ownership document.
- Never add `Debug` logging of PKCS#11 request types that can contain secret
  fields.
- Preserve existing mTLS, peer-credential, and policy boundaries.
- Do not add insecure defaults for transport, auth, or token access.

## 5. Rust Design Rules

- Keep files focused by responsibility. If a file becomes broad, split it.
- Prefer small helper functions or focused modules over copy-paste.
- Use macros only when they clearly reduce boilerplate without hiding behavior.
- Avoid “clever” abstractions that make PKCS#11 call flow harder to audit.
- Prefer named PKCS#11 constants and typed wrappers; do not introduce magic
  numbers for `CKR_*`, mechanisms, attributes, or object classes.
- Maintain edition `2024` and MSRV `1.88` compatibility. MSRV is set
  to 1.88 to enable let-chains (`if cond && let X = e { ... }`), which
  the codebase already uses in 7+ places. The previous declared MSRV
  of 1.85 was aspirational — let-chains stabilised in Rust 1.88
  (May 2025), so 1.85 was inconsistent with actual usage. Distribution
  matrix:
  * **Alpine 3.23** — stock `rustc` ≥ 1.91; supported. CI uses a
    `rustup`-managed stable toolchain uniformly across the Alpine matrix.
  * **Alpine 3.22** — stock `rustc` 1.87; supported via the
    `rustup`-managed toolchain because stock Rust is below MSRV.
  * **Amazon Linux 2023** — stock `rustc` ~1.86; **install Rust via
    `rustup`** rather than relying on the system package.
  If a supported build target's stock Rust is older than 1.88, install a
  `rustup`-managed toolchain. New code may not use language or library
  features stabilised after Rust 1.88.

## 6. Refactor Rules

- Structural refactors must be behavior-preserving unless explicitly stated
  otherwise.
- After refactors that move files, update source-scan tests, consistency checks,
  and any `include_str!` paths in the same change.
- Do not leave the tree in a partially migrated state.

## 7. Testing Rules

- At minimum, run `cargo fmt --all` and `cargo check` for every touched crate.
- Run the most relevant tests for the changed area before finishing.
- If a full suite cannot run because of environment limits, say so explicitly.
- Do not merge changes that break the consistency checks or ABI audit tests.
- New behavior, bug fixes, and security-sensitive paths should come with tests.
- When adding new mechanism parameter support, test with a REAL backend
  (SoftHSM2 or NSS softokn), not just MockBackend/unit tests. Proto
  round-trip unit tests passing does NOT guarantee the FFI path works.
- For parameterized mechanisms, test the full stack: client → gRPC → server
  → FFI backend → real PKCS#11 module → result → reverse path.

## 8. Documentation Rules

- Update docs when behavior, scope, interfaces, or contributor workflow changes.
- User-facing docs (development setup, support references, runbooks, and release
  docs) live in this repository's `doc/` tree and must stay current with the code.
- Planning/design docs (PRD, ADRs, architecture overview, audits, and follow-up
  notes) live in `pkcs11-proxy-ng-ws`. Do not duplicate them here or make this
  repository's builds, tests, release packaging, or public links depend on that
  private workspace. Its `scripts/test_planning_docs.py` checks the design docs.
- Do not vendor or fetch OASIS specification sources into this repository.
  Source-grounded OASIS inventory checks read an externally supplied spec tree
  via `PKCS11_PROXY_NG_OASIS_ROOT` and skip cleanly when it is absent, so the
  repo builds and tests standalone from its own sources plus `cryptoki-sys` /
  provider headers.
- Do not add project documents under vendored spec directories.

## 9. Git Rules

- Keep each commit focused and self-contained; do not mix unrelated changes.
- Do not rewrite unrelated user changes.
- Do not use destructive Git commands unless explicitly requested.

## 10. AI Agent Rules

- Read the local code before proposing or making changes.
- Do not guess PKCS#11 behavior when the codebase or spec can answer it.
- Prefer completing a coherent, validated change over leaving partial edits.
- When a change is risky, state the risk directly and constrain the scope.
- If you touch a high-risk boundary, especially FFI, auth, or error mapping,
  explain what invariant you preserved.

## 11. Preferred Change Order

When a task spans multiple concerns, use this order:

1. Update design/docs if the behavior changes.
2. Implement the code change in the smallest coherent scope.
3. Update tests and consistency checks.
4. Run formatting and validation.
5. Commit the change.

If a proposed change conflicts with these rules, stop and resolve the conflict
explicitly instead of proceeding by assumption.

## 12. Mechanism Parameter Rules

When adding a new mechanism parameter shape:

1. Add the proto message to `mechanism_params.proto`
2. Add it to the `Mechanism.params` oneof in `types.proto`
3. Add the Rust struct + `CkMechanismParams` variant in `types`
4. Add bidirectional From/TryFrom in `proto` conversion code
5. Add the C struct reconstruction in `mechanism_to_ffi()` (`ffi/ffi_conversion.rs`)
6. Add to `mechanism_params_default.toml` for spec-defined mechanisms.
   Vendor-defined mechanisms (e.g. CloudHSM, Thales) belong in the
   daemon's runtime registry file (point `[mechanisms].config_path` at
   it; the embedded default applies when `[mechanisms].config_path` is
   unset) and are served to shims over gRPC.
   Vendor mechanisms that reuse an existing parameter shape need no code
   changes — only a TOML entry. New shapes still require steps 1–5 above.
   Exception — intentionally undocumented mechanisms need no TOML entry:
   `CK_CMS_SIG_PARAMS` / `CK_X3DH_*` / `CK_X2RATCHET_*` shapes carry
   unbounded caller pointers the shim must not parse
   (`do_not_parse_unbounded_caller_pointers_in_shim`), and working-spec
   names without published `CKM_*` values (`CKM_KMAC128/256`,
   `CKM_ML_DSA_EXTERNAL_MU[_GEN]`, `CKM_SHAKE_128/256`) must not get
   project-local numbers (`do_not_assign_project_local_ckm_values`).
   Record any new intentional omission in
   `doc/oasis-profile-coverage.md` instead of adding a TOML shape.
7. Add a round-trip unit test in `proto`
8. Add a real-backend integration test if possible

Missing step 5 is the most dangerous — proto tests pass but operations
fail silently at the FFI boundary with `CKR_MECHANISM_PARAM_INVALID`.

## 13. Architecture Quick Reference

- **Shim** (`crates/shim`, package `pkcs11-proxy-ng-shim`): C ABI → client → gRPC. Loads
  `MechanismRegistry` from config. Does mechanism filtering and
  param validation. Uses the `catch_panics` fn + `with_client!` macro.
- **Server** (`crates/server`, package `pkcs11-proxy-ng`): gRPC → backend. Pure proxy for mechanism
  discovery (no filtering). Backend calls via `spawn_backend()` with
  timeout + circuit breaker.
- **FFI backend** (`crates/backend`, package `pkcs11-proxy-ng-backend`): Rust → C via `dlopen`. Uses
  `call_3x_fn!` for 3.0/3.2 functions. `mechanism_to_ffi()` converts
  Rust params to C structs.
- **Module loader** (package `pkcs11-module`, rev-pinned git dependency from
  `pkcs11-components`, with `pkcs11-abi` layouts): shared module-FFI
  *facts* — raw `C_GetFunctionList`/`C_GetInterfaceList` acquisition,
  function-list field-offset tables, provenance/version → table selection
  (`tables_for`), unaligned-safe readers. No proto/tonic dependencies; also
  consumed externally (pkcs11-scope's discover helper) via git dependency.
  Interface-*selection* policy stays in the backend.
- **Config**: server publishes `MechanismRegistry` over `GetBackendInterfaces`
  RPC from the file at `[mechanisms].config_path` (the embedded default
  when `[mechanisms].config_path` is unset). The shim consumes
  it during `interface_probe::ensure_probed()` and falls back to the
  embedded `mechanism_params_default.toml` plus `PKCS11_PROXY_MECHANISMS`
  env override only when the daemon is unreachable or omits the field.
  `PKCS11_PROXY_DISABLE_SERVER_REGISTRY=1` forces the fallback path
  (test/debug use).
- **Session caches**: Cleaned on `c_close_session` via `evict_session_caches()`.
- **104 standard PKCS#11 function-list fields** represented across all layers
  (2.40 + 3.0 + 3.2).
- **6 `C_DigestXof*` spec-only functions** tracked as explicit ABI gaps because
  the current published function-list headers and `cryptoki-sys` bindings do
  not expose standard slots for them.
- **79 mechanism parameter shapes** and **3 message parameter shapes** with
  serialization, FFI conversion, and shim-safety coverage tracked by the OASIS
  inventory.
- **Exact output semantics**: 27 output-bearing functions use the exact/raw
  path via 4 dedicated RPCs (`GetAttributeValueExact`, `ByteOutputExact`,
  `ParameterOutputExact`, `EncapsulateKeyExact`). The backend performs one
  FFI call per shim request; the shim does not cache or reconstruct output.
