# Mechanism admission coverage

The daemon checks a configured mechanism grant against the authenticated
client and the session's backend slot before sending an admitted call to the
provider. This check does not establish that the provider supports that
mechanism for the requested operation. The provider makes that decision.
Object handles must also belong to the client and pass object policy checks.

| Operation | Where admission occurs | Object checks |
| --- | --- | --- |
| Digest, sign, verify, sign-recover, verify-recover, verify-signature, encrypt, and decrypt initialization | Handler before provider call | Key where applicable; embedded handles in mechanism parameters |
| Message encrypt, decrypt, sign, and verify initialization | Handler before provider call | Key and embedded handles |
| Key generation and key-pair generation | Handler before provider call | Embedded handles |
| Derive key | Handler before provider call | Base key and embedded handles, including SP800-108 byte references |
| Encapsulate and decapsulate key, including exact output | Handler before provider call | Public or private key and embedded handles |
| Ordinary wrap and unwrap | Handler before provider call | Wrapping or unwrapping key, wrapped key, and embedded handles |
| Authenticated wrap/unwrap and exact wrap adapters | Partial coverage; see below | Further handle remapping and admission work remains |

Authenticated wrapping and unwrapping still need handle remapping and audit
parity checks. Exact wrapping adapters still need complete mechanism extraction
and admission checks. Authenticated native parameter-image writeback also
needs a separate correction. These routes are not release-qualified by the
admission checks listed above.

Cancellation with a NULL mechanism keeps its existing path. Update, final,
single-part continuation, and combined operations use an already initialized
operation; they do not request a new mechanism grant. `SetOperationState`
restores opaque provider state and does not infer policy from its bytes.

The `mechanism_authorization_test` suite checks two mTLS identities with
opposite grants, virtual-to-backend slot mapping, denial outputs,
cancellation, and backend errors. Mock checks establish the authorization
path; they do not prove native provider support or qualify the remaining
wrap routes.
