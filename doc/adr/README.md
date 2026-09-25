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

All ADRs are in **Proposed** status (2026-03-12).
