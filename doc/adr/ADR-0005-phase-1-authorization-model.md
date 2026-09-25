# ADR-0005: Phase 1 Authorization Model

## Status
Proposed

## Context

Wrapping adapters share admission in this order: context/session and direct
objects, mechanism parsing, embedded-handle remapping and authorization,
mechanism permission, then extraction permission for the wrapped object.
This covers ordinary/exact `C_WrapKey` and `C_WrapKeyAuthenticated` identically;
authenticated unwrap also remaps embedded handles before native entry. Object
and class-only policy both apply. AAD sanitation remains adapter-local, after
shared wrapping admission. Denied/unknown direct handles retain ADR-0012's
zero-handle forwarding and provider RV precedence; denied/foreign nonzero
embedded handles fail with `CKR_OBJECT_HANDLE_INVALID` before native wrap.
Zero forwarding preserves provider precedence when no independent mechanism
or extraction denial applies. In particular, an unknown wrapped object cannot
resolve its UID; an active per-object extraction override then fails closed
with `CKR_KEY_FUNCTION_NOT_PERMITTED`, matching ordinary wrapping. Visibility
denial alone does not imply extraction denial for a mapped object whose UID
can still be resolved.

The PKCS#11 proxy daemon exposes remote access to PKCS#11 tokens and HSMs over Unix sockets and TCP. Before any production deployment, the daemon needs authentication and authorization to prevent unauthorized access to cryptographic material.

The design tension is between security completeness and Phase 1 pragmatism. The project has one design partner and needs a working, auditable auth layer -- not a full multi-tenant RBAC system. The authorization model must be layered and configurable so that development, single-machine, and networked deployments each use the appropriate level of security without requiring code changes.

Several constraints shape this decision:

1. **Unix socket and TCP are both supported transports.** They have different trust properties and should default to different auth modes.

2. **Multiple processes may share a certificate.** As established in ADR-0002, mTLS identity is an authentication credential, not a PKCS#11 session owner. The logical client instance (`client_context_id`) is the session-ownership boundary. Auth must work with that model, not against it.

3. **The proxy controls access to real HSM key material.** Even Phase 1 must make it difficult to accidentally deploy without authentication. The "no auth" path must be explicitly opted into and never be the default for network-reachable listeners.

4. **Phase 2+ will need finer-grained controls.** The Phase 1 model should not foreclose per-operation RBAC, multi-tenant isolation, or external policy engines. It should establish the identity and policy attachment points that future phases will extend.

## Decision

### 1. Three authentication modes, selected per listener

Each listener in the daemon configuration specifies one of three authentication modes:

#### `none` -- No authentication

No client identity is established. Intended exclusively for development and testing. The daemon refuses to start if `auth = "none"` is configured on a TCP listener unless a separate `allow_insecure_tcp = true` flag is also set (this flag exists only to support rare integration-test scenarios and emits a startup warning). For Unix socket or loopback-only use.

#### `peer_cred` -- Unix socket peer credentials

Uses `SO_PEERCRED` (Linux) to identify the connecting process by UID and GID. The authenticated identity is represented as `uid=<N>` (e.g., `uid=1000`); GID is available for logging and future policy extensions but is not a policy key in Phase 1. This mechanism is Linux-specific, which is consistent with the project's Linux-first target. Appropriate for same-machine deployments where the daemon and clients share a trusted host and the operating system enforces process identity.

#### `mtls` -- Mutual TLS

Both the daemon and the client present X.509 certificates. The daemon validates
the client certificate against a configured CA certificate. The authenticated
identity is represented in a canonical form derived from the certificate
**issuer** and **subject**, for example:

`x509:issuer=CN=Example Root,O=Example;subject=CN=pki-service,O=Example`

The daemon canonicalizes issuer and subject using the RFC 4514 string form
(via `x509-parser`) before building the identity string. Within that identity
string a literal `\` and `;` in either DN are escaped (`\\`, `\;`) so the
`;subject=` join delimiter is unambiguous: the string form is **injective**
(distinct issuer/subject DN pairs can never collide on the same key, which would
otherwise let one certificate match another's policy entry or slip past the
per-request ownership check of ADR-0009). A certificate with an **empty subject
DN** is rejected — Phase 1 does not consult the SubjectAltName, and an empty
subject would collapse every such certificate from a CA onto one identity. This
mTLS mode is required for any TCP listener that carries production traffic.

### 2. Default behavior per listener type

| Listener type | Default auth mode | Rationale |
|---------------|-------------------|-----------|
| Unix socket   | `peer_cred`       | OS-enforced identity is available and lightweight |
| TCP           | `mtls`            | Network listeners must authenticate by default |

`auth = "none"` is never a default. It must be explicitly configured.

### 3. Coarse token-level access policy

Phase 1 provides a single policy dimension: which authenticated identities may
access which tokens.

- **Granularity:** identity to allowed token selector set (a list of stable
  token selectors, or the keyword `"all"`).
- **Selector format:** policy entries should use stable token selectors such as
  PKCS#11 URI fragments, token serials, or token labels. Raw numeric slot IDs
  are not the preferred policy key because slot numbering is not stable enough.
- **No per-operation restrictions.** There is no read-only vs. key-management
  distinction in Phase 1. An identity that can access a token can perform any
  PKCS#11 operation the backend permits on that token.
- **Discovery filtering:** `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`,
  `C_GetMechanismList`, and `C_GetMechanismInfo` are filtered so that callers
  only see tokens they are authorized to use.
- **Default when no policy is configured:** deny token access by default. A
  deployment may opt into broad access with an explicit
  `allow_all_authenticated = true` setting.
- **Unauthenticated callers (auth = "none"):** bypass the policy layer entirely. There is no identity to match against policy rules.

### 4. Context binding (relationship to ADR-0002)

The `client_context_id` issued by the daemon (see ADR-0002) is bound to the authenticated identity at creation time:

- The daemon records which authenticated identity created each context.
- A request that presents a `client_context_id` created by a different identity is rejected. One client cannot adopt, resume, or inspect another client's context.
- A single authenticated identity may hold multiple concurrent contexts. This is normal when the same identity is used by multiple processes or service replicas.
- **Per-request identity ownership** is enforced on every request: a request is
  re-bound to the caller's transport identity and rejected on mismatch (ADR-0009).
- **Token-access policy** is enforced at the points where a client *gains*
  access to a token — slot/token/mechanism **discovery** and **C_OpenSession /
  C_InitToken** all run `slot_is_authorized` against the bound identity
  (`C_WaitForSlotEvent` too; see M13). Operations on an **already-open session**
  (crypto, object access) are not re-evaluated against the policy per request;
  they inherit the authorization established when the session was opened.
  Consequently a policy *tightening* does not retroactively revoke an open
  session — its effective revocation latency is the session's lifetime, and a
  client must reopen to pick up the change. Per-request policy re-evaluation is
  deliberately deferred for Phase 1 because it would add a backend
  `C_GetTokenInfo` to every crypto/object call (the M14 decision).

  This coarse session grant is separate from the opt-in per-mechanism and
  per-object/class restrictions in ADR-0012. Mechanism-bearing initializers
  enforce the calling identity's mechanism grant against the session's recorded
  backend slot. `C_DigestInit`, `C_VerifySignatureInit`, `C_EncapsulateKey`,
  `C_DecapsulateKey`, and exact encapsulation reject a denied mechanism with
  `CKR_MECHANISM_INVALID` before native initialization. A failed token-metadata
  lookup also denies; cold lookups use the backend slot, never its virtual ID.
  Session and primary-object resolution retain their existing precedence.
  NULL-mechanism cancellation bypasses mechanism admission; updates, finals,
  and combined operations consume initialized state. Restoring opaque state
  with `C_SetOperationState` is not a mechanism-policy enforcement boundary.

  The corrected initializers translate typed embedded object handles through the calling
  context and enforce either active object or class restrictions. A missing or
  denied nonzero embedded handle returns `CKR_OBJECT_HANDLE_INVALID` before
  native dispatch; it must not be rewritten to the optional-zero parameter.
  Explicit optional zeros retain their existing meaning. SP800-108 derivation
  applies the same denial rule to byte-encoded input handles, preserves 4/8-byte
  encoding, rejects narrowing overflow, and uses the real native session for
  metadata reads. See the [operation coverage](../release/mechanism-authorization.md)
  for adapter boundaries and remaining gaps.

### 5. Auth failure error mapping (relationship to ADR-0003)

Authentication and authorization failures are transport-level concerns, not PKCS#11-level concerns:

- **Missing or invalid credentials** (bad certificate, unknown UID, failed TLS handshake): the daemon returns gRPC status `UNAUTHENTICATED`. No `CK_RV` value is involved because the request never reaches the PKCS#11 layer.
- **Authenticated identity denied by policy during discovery:** the daemon
  filters the unauthorized token out of the response instead of returning an
  error where practical.
- **Authenticated identity denied by policy for an explicit slot/session/object
  operation:** the daemon returns gRPC status `PERMISSION_DENIED`.
- **Context ownership mismatch** (valid identity attempts to use another identity's `client_context_id`): the daemon returns gRPC status `PERMISSION_DENIED`.

These are not mapped to `CKR_*` values at the daemon level. The client-side shim library translates them into `CK_RV` values using the client-side mapping table defined in ADR-0003 (section 3), with diagnostic logging where available.

### 6. Example configuration

```toml
# --- Listeners ---

[listener.local]
type = "unix"
path = "/run/pkcs11-proxy-ng.sock"
auth = "peer_cred"        # default for unix; shown explicitly for clarity

[listener.remote]
type = "tcp"
bind = "0.0.0.0:7512"
auth = "mtls"             # default for tcp; shown explicitly for clarity
ca_cert = "/etc/pkcs11-proxy/ca.pem"
server_cert = "/etc/pkcs11-proxy/server.pem"
server_key = "/etc/pkcs11-proxy/server-key.pem"

[auth]
allow_all_authenticated = false

[listener.dev]
type = "unix"
path = "/tmp/pkcs11-proxy-ng-dev.sock"
auth = "none"             # DEVELOPMENT ONLY -- never use in production

# --- Optional token-level access policy ---

[auth.policy]
# Keys are authenticated identity strings.
# Values specify which tokens the identity may access.

"x509:issuer=CN=Example Root,O=Example;subject=CN=pki-service,O=Example" = { tokens = "all" }
"x509:issuer=CN=Example Root,O=Example;subject=CN=audit-reader,O=Example" = { tokens = ["pkcs11:token=Audit;serial=1234"] }
"uid=1000" = { tokens = "all" }
```

### 7. Configuration validation rules

The daemon validates auth configuration at startup and refuses to start if any of the following are true:

- A TCP listener has `auth = "none"` without `allow_insecure_tcp = true`.
- A listener has `auth = "mtls"` but is missing `ca_cert`, `server_cert`, or `server_key`.
- An authenticated listener exists with no policy entries and
  `allow_all_authenticated` is not explicitly set to `true`.
- A policy entry references an identity format that no configured listener could
  produce.

Validation failures produce clear error messages identifying the problematic listener or policy entry.

**Note on development ergonomics:** When using `auth = "peer_cred"` on a Unix
socket, the default-deny policy requires either explicit policy entries or
`allow_all_authenticated = true` before the daemon will start. This adds
friction for local development but ensures no deployment accidentally exposes
tokens without an explicit access decision. A future improvement could provide a
`--dev` CLI flag or a minimal example config that sets `allow_all_authenticated`
for local-only listeners.

### 8. What is deferred to Phase 2+

The following capabilities are explicitly out of scope for Phase 1. They are listed here to confirm they have been considered and to identify where they attach to the Phase 1 model:

- **Per-operation RBAC.** Roles such as read-only, key-generation, and admin
  that restrict which PKCS#11 operations an identity may invoke. The
  token-level policy is the natural extension point.
- **Multi-tenant key visibility isolation.** Separate tenants seeing different object sets on the same token. Requires object-level filtering that is not part of Phase 1.
- **External policy engine integration.** Delegation to OPA, Cedar, or similar
  systems for authorization decisions. The identity-to-token policy check is
  the integration point.
- **Certificate rotation and trust bootstrapping.** Automated CA rotation, short-lived client certificates, and initial trust establishment. Phase 1 assumes manually provisioned, long-lived certificates.
- **Alternate X.509 identity extractors.** Using SAN URIs, SPIFFE IDs,
  certificate fingerprints, or other certificate fields as identity. Phase 1
  uses canonical issuer+subject form; the identity representation format is
  designed to be extensible.
- **Audit logging of auth decisions.** Recording accepted and rejected auth attempts. This should be part of the observability design and is important for production, but is not part of the auth model itself.

### 9. Rejected alternatives

- **No authentication at all.** Unsafe for any deployment that handles real key material. Even a single-user development setup benefits from having an explicit "I know this is insecure" opt-in rather than silent default exposure.
- **Full RBAC in Phase 1.** Per-operation role definitions, role hierarchies,
  and policy languages add substantial design and implementation complexity.
  With one design partner and a small number of identities, coarse token-level
  policy is sufficient. The policy attachment point supports future RBAC
  extension without redesign.
- **mTLS identity as the PKCS#11 session owner.** As analyzed in ADR-0002, certificate identity is too coarse for session ownership when multiple processes or replicas share a certificate. Using it as the session key causes accidental state sharing. The logical client instance (`client_context_id`) is the correct session-ownership boundary; mTLS identity is the correct authentication and authorization boundary.

## Consequences

### What becomes easier

- **Safe-by-default deployment.** TCP listeners require mTLS out of the box. There is no accidental path to running an unauthenticated daemon on the network.
- **Incremental policy adoption.** Deployments can start with explicit broad
  access (`allow_all_authenticated = true`) and later add token-level
  restrictions without changing the auth mode or the daemon binary.
- **Clean separation of concerns.** Authentication (who is the caller?) is handled at the listener level. Authorization (what may the caller do?) is handled by policy. Session ownership (which PKCS#11 state belongs to the caller?) is handled by context binding. These are independent and composable.
- **Phase 2 extensibility.** The identity string format, the policy attachment point, and the context-binding mechanism are all designed to support finer-grained controls without architectural changes.

### What becomes harder

- **Development friction.** Developers must either use a Unix socket with `auth = "none"` or provision certificates for TCP testing. This is intentional: the friction is proportional to the security risk.
- **Certificate management.** mTLS requires a CA, server certificate, and client certificates. Phase 1 does not automate any of this. Operators must provision and distribute certificates manually.
- **Multi-identity policy management.** As the number of distinct identities grows, the flat TOML policy section becomes unwieldy. This is acceptable for Phase 1 with one design partner but motivates the Phase 2 move to external policy engines.

### What becomes riskier

- **Issuer/subject collisions.** If two unrelated clients end up with the same
  canonical issuer+subject pair, they are treated as the same identity for
  policy purposes (though their contexts remain isolated per ADR-0002).
  Operators must ensure client-certificate identity uniqueness within their PKI.
- **`peer_cred` trust boundary.** `SO_PEERCRED` trusts the local kernel's process identity. If the host is compromised, `peer_cred` provides no protection. This is inherent to Unix socket peer credentials and is acceptable for same-machine deployments where host compromise is already a catastrophic event.
- **PIN handling is out of scope.** This ADR does not cover PKCS#11 `C_Login` PIN handling. PINs are passed through to the backend as opaque data. The security properties of PIN transmission depend on the transport encryption (TLS for TCP, filesystem permissions for Unix sockets) and are not further constrained by this authorization model.

## Implementation status (2026-05-30)

The Unix-socket (`peer_cred`) transport described above is now **wired and
verified**, alongside the pre-existing TCP/mTLS path:

- **Server.** The daemon binds TCP and/or a Unix `UnixListener` from
  `[listener.remote]` / `[listener.local]` and serves them concurrently under a
  shared shutdown signal. The socket is created owner-only (`0600`), a stale
  socket from a prior run is removed (a non-socket path is never clobbered, and
  `lstat`/`symlink_metadata` avoids following a symlink), and the socket file is
  removed on shutdown.
- **Authentication.** tonic surfaces `SO_PEERCRED` as `UdsConnectInfo`; the
  daemon derives `AuthenticatedIdentity::PeerCred { uid }` (or `Unauthenticated`
  for `auth = "none"`; `peer_cred` with no kernel credentials fails closed) and
  feeds the existing token policy. **No mTLS over the Unix socket** — a local
  socket has no network to secure, and `SO_PEERCRED` is the unforgeable
  local-IPC equivalent of mutual auth; the `UnixAuthMode` type has no `Mtls`
  variant by construction.
- **Client / shim.** A `unix:/path` (or `unix:///path`) endpoint dials the
  socket via a custom connector; `PKCS11_PROXY_ENDPOINT=unix:/run/…sock` flows
  through the shim unchanged. TLS configuration is ignored for `unix:` endpoints.

**Scope.** The Unix socket is intended for **same-host, single-user** use (and
is ssh-forwardable). The multi-client production path remains TCP + mTLS. A
multi-uid socket permission knob (group/mode) was deliberately left out of scope
for this local transport; broadening it is a future option if a multi-uid local
deployment emerges. The PKCS#11 PIN (`C_Login`) remains the independent,
end-to-end gate on key material regardless of transport.
