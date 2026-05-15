# Contributor Rules

These rules are mandatory for anyone changing code in `pkcs11-proxy/`, including
AI agents, automation, and human contributors.

## 1. Follow The Existing Design

- Treat the PRD, ADRs, and current code as the active design contract.
- Do not change handle semantics, error semantics, authorization semantics, or
  mechanism-policy behavior implicitly.
- If a change alters architecture or externally visible behavior, update the
  relevant ADR or add a new one before or alongside the code change.

## 2. Preserve PKCS#11 Semantics

- **The shim must behave identically to a native PKCS#11 module from the
  application's perspective.** An application loading the shim .so should not
  be able to distinguish it from loading the real backend .so directly, except
  for network latency. This is the primary correctness requirement.
- The shim uses exact/raw output semantics: it sends the caller's buffer
  specification to the backend, the backend performs one PKCS#11 call with
  those exact parameters, and the shim writes back the exact result. The shim
  must never locally reconstruct `CKR_BUFFER_TOO_SMALL`, fabricate output
  lengths, or invent per-attribute results.
- Preserve exact `CK_RV` values whenever possible; do not collapse multiple
  PKCS#11 errors into one generic error.
- Do not invent compatibility claims such as “full PKCS#11 support”.
- Keep the current discovery and mechanism policy intact unless a design change
  is explicitly intended and documented.
- When in doubt, use the vendored OASIS PKCS#11 spec in
  `../doc/oasis-tcs-pkcs11/working/doc/spec/` as the source of truth.

## 3. FFI Safety Is Non-Negotiable

- Never allow a Rust panic to unwind across an `extern "C"` boundary.
- Keep null-pointer checks, buffer-length checks, and two-call output semantics
  explicit and correct.
- Do not weaken ABI compatibility for PKCS#11 2.40, 3.0, or 3.2 interfaces.
- Avoid undefined behavior even if a caller is buggy; where that is impossible,
  fail early and conservatively.
- When adding new mechanism parameter types, ensure BOTH directions work:
  - Proto→Rust (`TryFrom<&proto::Mechanism>`) for server-side deserialization
  - Rust→C struct (`mechanism_to_ffi()` in `ffi/helpers.rs`) for backend FFI calls
  - Rust→Proto (`From<&CkMechanism>`) for client-side serialization
  Missing any direction causes silent failures at runtime.

## 4. Security Rules

- Never log PINs, keys, raw secrets, certificates’ private material, or other
  sensitive request payloads.
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
- Maintain edition `2024` and MSRV `1.94` compatibility.

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
- Keep planning material in the root repo; keep implementation guidance in this
  submodule.
- Do not add project documents under vendored spec directories.

## 9. Git Rules

- Commit in this submodule first; update the root submodule pointer afterward.
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
5. Commit the submodule change.

If a proposed change conflicts with these rules, stop and resolve the conflict
explicitly instead of proceeding by assumption.

## 12. Mechanism Parameter Rules

When adding a new mechanism parameter shape:

1. Add the proto message to `mechanism_params.proto`
2. Add it to the `Mechanism.params` oneof in `types.proto`
3. Add the Rust struct + `CkMechanismParams` variant in `types`
4. Add bidirectional From/TryFrom in `proto` conversion code
5. Add the C struct reconstruction in `mechanism_to_ffi()` (`ffi/helpers.rs`)
6. Add to `mechanism_params_default.toml` (or a vendor override)
7. Add a round-trip unit test in `proto`
8. Add a real-backend integration test if possible

Missing step 5 is the most dangerous — proto tests pass but operations
fail silently at the FFI boundary with `CKR_MECHANISM_PARAM_INVALID`.

Vendor mechanisms that reuse standard parameter shapes need only a config
entry in `mechanism_params.toml` (step 6) — no code changes.

## 13. Architecture Quick Reference

- **Shim** (`crates/shim`, package `pkcs11-proxy-ng-shim`): C ABI → client → gRPC. Loads
  `MechanismRegistry` from config. Does mechanism filtering and
  param validation. Uses `catch_panics` + `with_client!` macros.
- **Server** (`crates/server`, package `pkcs11-proxy-ng`): gRPC → backend. Pure proxy for mechanism
  discovery (no filtering). Backend calls via `spawn_backend()` with
  timeout + circuit breaker.
- **FFI backend** (`crates/backend`, package `pkcs11-proxy-ng-backend`): Rust → C via `dlopen`. Uses
  `call_3x_fn!` for 3.0/3.2 functions. `mechanism_to_ffi()` converts
  Rust params to C structs.
- **Config**: `mechanism_params.toml` embedded default + env override
  (`PKCS11_PROXY_MECHANISMS`). Additive merge.
- **Session caches**: Cleaned on `c_close_session` via `evict_session_caches()`.
- **105 PKCS#11 functions** implemented across all layers (2.40 + 3.0 + 3.2).
- **75 mechanism parameter shapes** with full serialization.
- **Exact output semantics**: 27 output-bearing functions use the exact/raw
  path via 4 dedicated RPCs (`GetAttributeValueExact`, `ByteOutputExact`,
  `ParameterOutputExact`, `EncapsulateKeyExact`). The backend performs one
  FFI call per shim request; the shim does not cache or reconstruct output.
