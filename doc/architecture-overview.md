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

## Planned Crate Structure (pkcs11-proxy-ng/ workspace)

| Crate | Type | Purpose |
|-------|------|---------|
| `types` | lib | Pure Rust PKCS#11 type definitions (CK_RV, mechanisms, attributes) |
| `proto` | lib | Protobuf definitions + tonic generated code + type conversions |
| `backend` | lib | Backend trait + FFI (dlopen) implementation + mock backend |
| `pkcs11-proxy-ng` | bin | Daemon: gRPC server, context/session management, auth |
| `pkcs11-proxy-ng-client` | lib | Rust client library: gRPC client, error mapping, reconnect |
| `pkcs11-proxy-ng-cli` | bin | CLI tool for diagnostics and automation |
| `pkcs11-proxy-ng-shim` | cdylib | Drop-in PKCS#11 module (C ABI) backed by the client library |

## Key Architectural Decisions

Full details in `doc/adr/`:

**ADR-0001 — Function & Mechanism Coverage Policy**
- Phase 1 targets an explicit seed set of ~28 PKCS#11 functions; long-term goal
  is complete coverage of 2.40 through 3.2.
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
- Backend isolation fallback ladder: shared process → separate module instance
  → separate worker process (Phase 1 implements shared-process tier).

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
- Single backend module per daemon instance in Phase 1.

**ADR-0005 — Phase 1 Authorization Model**
- Three auth modes per listener: `none` (dev only), `peer_cred` (Unix
  socket), `mtls` (TCP).
- Defaults: `peer_cred` for Unix, `mtls` for TCP. `none` never default.
- Coarse token-level access policy (identity → allowed token set).
- `client_context_id` bound to authenticated identity at creation.
- Transport authentication failures use gRPC status. Token visibility failures
  on PKCS#11 calls are mapped to PKCS#11 return values that hide unauthorized
  slots.

### Current Listener Support Matrix

Runtime support and production intent are tracked separately.

| Listener | Intended use | Current runtime behavior |
| --- | --- | --- |
| TCP with `auth = "mtls"` | Production remote transport | Starts with tonic/rustls mTLS, requires CA/server cert/server key, and binds peer certificate identity to `client_context_id` |
| TCP with `auth = "none"` and `allow_insecure_tcp = true` | Development and local integration tests | Starts only with the explicit unsafe opt-in |
| Unix socket | Development and test-only local transport | Fails closed in the production daemon; any future implementation must require an explicit dev/test opt-in and socket permissions |

Unix sockets are not a production security boundary for this project. If a Unix
listener is enabled for tests later, the daemon must print a startup warning and
bind the socket with restrictive permissions such as `0600` for single-user
tests or `0660` for a dedicated test group.

## Tech Stack

- **Rust** (stable) — implementation language
- **tonic + prost** — gRPC server and client, protobuf codegen
- **libloading** — portable dlopen for PKCS#11 module loading
- **tokio** — async runtime
- **clap** — CLI argument parsing
- **serde + toml** — configuration parsing
- **tracing** — structured logging
- **rustls** — TLS 1.3 for mTLS
- **nix** — SO_PEERCRED for Unix socket peer credentials
- **cryptoki-sys** — raw PKCS#11 C FFI type definitions

## Phase 1 Scope

**In scope:** Linux daemon, Linux shim, Rust client lib, CLI, gRPC over TCP,
mTLS TCP transport, PKCS#11 2.40 full function coverage plus 3.0/3.2
functions (message-based APIs, KEM, VerifySignature, authenticated wrap, async
polling), SoftHSM2 integration tests, pkcs11-tool / p11tool compatibility
validation.

**Out of scope:** Windows/macOS, full PKCS#11 conformance across every mechanism
and parameter structure, automatic support for future PKCS#11 versions,
C_AsyncGetID/C_AsyncJoin persistence (returns spec-compliant refusal codes),
callbacks, multi-module aggregation within a single daemon.
