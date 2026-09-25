# Architecture Decision Records

Use this directory for short architecture decisions tied to the PKCS#11 proxy
workspace.

Current ADRs:

| ADR | Decision |
|-----|----------|
| [ADR-0001](ADR-0001-function-mechanism-coverage-policy.md) | All functions (phased); operation-time mechanism enforcement; dual-mode discovery (filtered/transparent); no raw parameter forwarding |
| [ADR-0002](ADR-0002-handle-session-identity-model.md) | Logical client instance model; virtual handles; lease-based reconnect; backend isolation fallback ladder |
| [ADR-0003](ADR-0003-error-model.md) | Hybrid errors — `ck_rv` in payload for PKCS#11 results, gRPC status for transport/proxy failures only |
| [ADR-0004](ADR-0004-backend-integration-model.md) | Abstract backend trait; direct FFI via `dlopen`; p11-kit is just another `.so` |
| [ADR-0005](ADR-0005-phase-1-authorization-model.md) | Configurable auth (none/peer_cred/mtls); coarse token-level policy; context binding |
| [ADR-0006](ADR-0006-32-64-bit-cross-platform-compatibility.md) | 32/64-bit cross-platform strategy; `CK_ULONG` width handled at the FFI boundary |
| [ADR-0007](ADR-0007-backend-process-isolation.md) | Deferred: in-process backend worker; multi-daemon partitioning + client reconnect instead |
| [ADR-0008](ADR-0008-cross-client-login-pin-verifier.md) | ~~Cross-client logical-login PIN verifier~~ SUPERSEDED by Wave 3.5 D6(3) backend-authoritative login (see ADR-0002 §6) |
| [ADR-0009](ADR-0009-per-request-context-ownership.md) | Per-request context ownership; handles validated against the owning client context |
| [ADR-0010](ADR-0010-transparent-forwarding-by-default.md) | Transparent forwarding by default — parameters cross the wire verbatim (NULL stays NULL), backend's native `CK_RV` untranslated; daemon-side `sanitize_inputs` opt-in |
| [ADR-0011](ADR-0011-narrow-ck-ulong-client-width-bridging.md) | Narrow-`CK_ULONG` client support and width bridging |
| [ADR-0012](ADR-0012-gateway-and-resilience-modes.md) | Opt-in gateway, authorization, resilience, audit, and attestation modes |
| [ADR-0013](ADR-0013-secret-ownership-and-diagnostics.md) | Exhaustive secret-field classification, wiping ownership, and diagnostic redaction |
| [ADR-0014](ADR-0014-v020-tail-platform-stretch.md) | Re-admitted Windows native and 32-bit/mixed scope as the v0.2.0 tail stretch |

Each ADR records its own status (Proposed / Accepted / Deferred) in its
**Status** section.
