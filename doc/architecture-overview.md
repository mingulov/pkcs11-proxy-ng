# Architecture Overview

Quick reference for the PKCS#11 Remote Proxy architecture. For full details,
see the individual ADRs in `doc/adr/`.

## Components

```
┌─────────────────────────────┐    ┌──────────────────────────────┐
│        Client Machine       │    │       Server Machine         │
│                             │    │                              │
│  App ──► pkcs11-proxy-ng-shim  │    │   pkcs11-proxy-ng (daemon)      │
│  CLI ──► pkcs11-proxy-ng-client│───►│     ├── context manager      │
│          (Rust gRPC client) │gRPC│     ├── session manager       │
│                             │    │     ├── handle virtualization │
│                             │    │     ├── mechanism filter      │
│                             │    │     └── auth layer            │
│                             │    │            │                  │
│                             │    │     Pkcs11Backend trait       │
│                             │    │            │ (FFI / dlopen)   │
│                             │    │     Any PKCS#11 .so           │
│                             │    │     (vendor HSM, SoftHSM2,    │
│                             │    │      p11-kit-proxy.so, ...)   │
└─────────────────────────────┘    └──────────────────────────────┘
```

## Current Crate Structure

| Crate | Type | Purpose |
|-------|------|---------|
| `audit` | lib | Tamper-evident audit records, hash chain, signed checkpoints, verification |
| `types` | lib | Pure Rust PKCS#11 type definitions (CK_RV, mechanisms, attributes) |
| `proto` | lib | Protobuf definitions + tonic generated code + type conversions |
| `backend` | lib | Backend trait + FFI (dlopen) implementation + mock backend |
| `pkcs11-module` / `pkcs11-abi` | external git dep | Shared module-FFI facts from `pkcs11-components` (rev-pinned): raw function-table acquisition, field-offset tables, layout selection; consumed by backend |
| `pkcs11-proxy-ng` | bin | Daemon: gRPC server, context/session management, auth |
| `pkcs11-proxy-ng-client` | lib | Rust client library: gRPC client, error mapping, reconnect |
| `pkcs11-proxy-ng-cli` | bin | CLI tool for diagnostics and automation |
| `pkcs11-proxy-ng-shim` | cdylib | Drop-in PKCS#11 module (C ABI) backed by the client library |

## Key Architectural Decisions

Full details in `doc/adr/`:

**ADR-0001 — Function & Mechanism Coverage Policy**
- The standard `cryptoki-sys` function-list tables expose 104 PKCS#11 fields,
  all represented by the proxy with local test citations. Six `C_DigestXof*`
  declarations remain explicit spec-only gaps because the published headers and
  bindings provide no standard function-list slots for them.
- Parameter modeling covers 79 mechanism shapes and three message-parameter
  shapes. See `doc/oasis-profile-coverage.md` for generated, source-grounded
  coverage and the exact-output inventory.
- Parameterless mechanism calls always forwarded (no parameter data to interpret).
- Parameterized mechanisms require explicit protobuf modeling; unmodeled params
  rejected with `CKR_MECHANISM_PARAM_INVALID`.
- Two discovery modes: **transparent** (default for all clients including the
  shim — full backend list; operation-time safety still applies) and
  **filtered** (opt-in for strict environments — only proxy-supported mechanisms
  advertised).
- **No-raw-forward rule:** proxy never forwards raw parameter bytes it cannot
  parse and reconstruct.

**ADR-0002 — Handle & Session Identity Model**
- Logical client instance (server-issued `client_context_id`) is the PKCS#11
  "application" boundary — not the transport connection or mTLS identity.
- Session and object handles are virtualized per logical client instance; backend
  handles never exposed.
- Login state scoped to logical client instance + token.
- Lease-based reconnect preserves state across transient transport interruptions.
- v0.2 selects one managed provider chain per embedding process, with separate
  daemons for independent chains. Another loader handle is not isolation.
  Worker isolation and independent per-client event streams remain deferred.

**ADR-0003 — Error Model**
- `ck_rv` field (uint64) in every protobuf response carries the exact PKCS#11
  result. gRPC status is always `OK` when a valid `ck_rv` is available.
- gRPC status codes reserved for transport/proxy failures with no valid PKCS#11
  result.
- Client shim maps gRPC failures to most appropriate standard `CK_RV` per
  function category.
- Backend vendor-defined CKR values pass through unchanged.

**ADR-0004 — Backend Integration Model**
- Abstract `Pkcs11Backend` trait as the daemon's internal interface.
- Primary implementation: direct FFI via `dlopen` (`libloading` crate).
- Any PKCS#11 `.so` is a valid backend: vendor HSM libs, SoftHSM2, p11-kit.
- p11-kit is just one example module path, not an architectural dependency.
- One managed chain per embedding process, including aggregator dependencies
  and direct-backend users. Share through Arc; one linked backend runtime and
  exclusive provider access are required.

**ADR-0005 — Phase 1 Authorization Model**
- Three auth modes per listener: `none` (dev only), `peer_cred` (Unix
  socket), `mtls` (TCP).
- Defaults: `peer_cred` for Unix, `mtls` for TCP. `none` never default.
- Coarse token-level access policy (identity → allowed token set).
- `client_context_id` bound to authenticated identity at creation.
- Transport authentication failures use gRPC status. Token visibility failures
  on PKCS#11 calls are mapped to PKCS#11 return values that hide unauthorized
  slots.
- ADR-0012 extends this with opt-in mTLS leaf-SPKI identities, deny-default
  class/mechanism/object policy, extract denial, rate/session quotas, login
  budgets, tamper-evident auditing, and the attribute cache.

### Current Listener Support Matrix

Runtime support and production intent are tracked separately.

| Listener | Intended use | Current runtime behavior |
| --- | --- | --- |
| TCP with `auth = "mtls"` | Production remote transport | Starts with tonic/rustls mTLS, requires CA/server cert/server key, and binds peer certificate identity to `client_context_id` |
| TCP with `auth = "none"` and `allow_insecure_tcp = true` | Development and local integration tests | Starts only with the explicit unsafe opt-in |
| Unix socket with `auth = "peer_cred"` | Authenticated local transport on supported Unix platforms | Implemented; binds kernel-supplied UID identity, validates policy identity form, and creates the socket with restrictive permissions |
| Unix socket with `auth = "none"` | Development and local integration tests | Implemented only with explicit insecure configuration and emits a startup warning |

Unauthenticated Unix sockets are not a production security boundary. Production
local deployments use `peer_cred`; unauthenticated mode remains an explicit
development escape hatch.

## Tech Stack

- **Rust** (stable) — implementation language
- **tonic + prost** — gRPC server and client, protobuf codegen
- **libloading** — portable dlopen for PKCS#11 module loading
- **tokio** — async runtime
- **clap** — CLI argument parsing
- **serde + toml** — configuration parsing
- **tracing** — structured logging
- **ed25519-dalek + sha2** — signed checkpoints and audit hash-chain integrity
- **rustls** — TLS 1.3 for mTLS
- **nix** — SO_PEERCRED for Unix socket peer credentials
- **cryptoki-sys** — raw PKCS#11 C FFI type definitions

## Current Scope

**In scope:** Linux daemon and shim, Rust client library, CLI, gRPC over mTLS
TCP and authenticated Unix sockets, represented PKCS#11 2.40/3.x function-list
coverage, explicitly modeled mechanisms, exact-output semantics, SoftHSM2/NSS
integration, and optional gateway/audit controls.

**Out of scope:** Windows/macOS native-provider daemon targets, automatic support for future
PKCS#11 versions or unmodeled parameter layouts, backend worker-process
isolation, callbacks, and multi-module aggregation within a single daemon.
The proxy is a forwarding layer; provider conformance is validated externally.

### Selected v0.2 native contract (implementation/qualification pending)

The [native ownership contract](release/native-mechanism-ownership.md)
requires constructor reservation before loading/discovery, epoch-qualified
workers/frames and explicit retirement before storage/library destruction.
Slot waiting supports DONT_BLOCK only; blocking mode returns local
FUNCTION_NOT_SUPPORTED without polling. One waiter keeps ordinary lifecycle
exclusion through settlement and cannot overlap native Finalize. Checked
input/output/RV widths and the specified local-refusal order are mandatory.
Logical clients compete for shared native pending flags; logical Initialize
creates no independent bitmap or full native per-application event equivalence.

Live FFI qualification is Linux GNU/musl x86_64/64-bit and x86/32-bit only.
This supersedes ADR-0011/0006's Windows native-provider daemon scope for v0.2.
Portable Windows client/shim/proto/types, mock-only backend/server builds and
Windows-client/Linux-daemon interoperation remain. Native Windows is deferred,
lower priority/stretch. Nonqualified hosts must refuse construction before
loading; all four Linux width pairs need native loaded-shim receipts.

Unresolved shutdown or final-domain Drop without private quiescence proof
selects return-aware raw Linux `exit_group(70)` for the whole embedding thread
group. Its target/seccomp/environment contract is explicit; it promises no
wiping, complete audit tail, cleanup, token deletion, strict disappearance
deadline or global no-core policy. The controller must progress without stalled
native/session/registry locks. These are required future enforcement and test
gates, not claims that this documentation amendment implements them.
