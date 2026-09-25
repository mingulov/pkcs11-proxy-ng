# Mechanism admission coverage

The configured mechanism grant is checked against the authenticated context and
the session's recorded backend slot. It does not establish native support for a
mechanism/operation pairing. The provider remains responsible for that decision.
Primary handles use the existing object-resolution gate; embedded nonzero handles
must belong to the context and pass object/class policy before native entry.

The following inventory covers represented mechanism-bearing entry points.
"Shared" means `grpc_service/mechanism_handles.rs`; each handler owns its gate
and calls `spawn_backend` only after preparation. Operation-specific ordering is
preserved: existing handlers can remap before mechanism admission, while the
corrected digest, signature, generation, and KEM routes admit mechanisms first.

| Entry points | Admission owner | Primary object gate | Embedded handles | Native boundary |
|---|---|---|---|---|
| DigestInit | `digest_cipher/digest.rs` | None | Shared | `digest_init` |
| SignInit, VerifyInit | `sign_verify/sign.rs`, `verify.rs` | Key | Shared | Respective initializer |
| SignRecoverInit, VerifyRecoverInit | Same sign/verify handlers | Key | Shared | Respective recovery initializer |
| VerifySignatureInit | `sign_verify/verify_signature.rs` | Key | Shared | `verify_signature_init` |
| EncryptInit, DecryptInit | `digest_cipher/cipher.rs` | Key | Shared | Respective initializer/output wrapper |
| MessageEncryptInit, MessageDecryptInit, MessageSignInit, MessageVerifyInit | `message_crypto/mod.rs` | Key | Shared | Respective message initializer/contract |
| GenerateKey, GenerateKeyPair | `key_ops/generation.rs` | None | Shared | Generation/output wrapper |
| DeriveKey | `key_ops/generation.rs` | Base key | Shared and SP800-108 byte resolver | Derive output wrapper |
| EncapsulateKey, DecapsulateKey, EncapsulateKeyExact | `key_ops/kem.rs` | Public/private key | Shared | Respective KEM method; exact has one dispatch |
| WrapKey, UnwrapKey | `key_ops/wrapping.rs` | Both keys / unwrapping key | Shared | Ordinary convenience method |
| WrapKeyAuthenticated, UnwrapKeyAuthenticated | `key_ops/authenticated_wrap.rs` | Both keys / unwrapping key | Remapping repair pending | Authenticated method |
| Exact WrapKey and exact WrapKeyAuthenticated | `byte_output_exact.rs`, `parameter_output_exact.rs` | Adapter-local | Shared preparation repair pending | Exact method |

Exact wrapping mechanism/extraction admission, authenticated wrapping/unwrapping
remapping, and wrap audit parity remain separate corrections. Authenticated native
parameter-image writeback also requires a separate correction. This table is not a
claim that those adapters are release-qualified.

NULL-mechanism cancellation retains its existing path. Update, final, single-part
continuation, and combined operations use previously initialized state; they do
not take a new mechanism grant. `SetOperationState` restores opaque provider state
and does not enforce a mechanism policy inferred from those bytes.

The public `mechanism_authorization_test` suite exercises two real mTLS identities
with opposite grants, backend slots `[42, 1]` mapped to virtual slots `[1, 2]`, warm
and cold token metadata, exact denial output, cancellation, and backend errors.
Metadata-only mock entry counters distinguish initializer dispatch from policy
metadata reads. Typed probes record only embedded handle integers and encoded
widths. Permissive mock SHA identifiers used for KEM/generation test authorization;
they do not prove real-provider compatibility or native FFI call counts.

KEM and authenticated-unwrapping audit parity, native completion/cancellation
audit, session/admission lifetimes, output effects/budgets, identifier exhaustion,
and the full provider matrix are outside this correction's evidence.
