# ADR-0013: Secret Ownership and Diagnostic Redaction

## Status

**Accepted (2026-09-13), implementation staged for v0.2.0.** The classification
manifest and common wiping owner are implemented by this decision. The public
v0.2.0 release remains blocked until generated protobuf messages, conversion
paths, client/server owners, and FFI backing allocations apply the manifest and
the associated lifetime tests pass.

## Context

PKCS#11 transports more than PINs. Attribute templates can contain imported
private keys; output attributes can disclose key material; encrypt/sign/digest
requests carry application plaintext; decrypt responses return plaintext; RNG
and operation-state calls carry sensitive state; and vendor mechanisms can give
opaque byte fields new meanings.

The code already uses `Zeroizing<Vec<u8>>` or `ZeroizeOnDrop` at selected PIN
and password sites. That is useful but incomplete:

- ad hoc wrapping is easy to omit when a new field is added;
- wrapping at handler entry is too late if prost already allocated a plain
  `Vec<u8>` while decoding;
- derived `Debug` on a containing request can reveal an otherwise wiping
  field; and
- a default-public classification is unsafe for polymorphic attribute and
  vendor fields.

The project needs one auditable classification and one narrow ownership type
before migrating the full call graph.

## Decision

1. **Classify every wire byte/string field explicitly.**
   `crates/proto/secret-fields.toml` is the source of truth. Every protobuf
   `bytes` and `string` field occurs exactly once under `secret` or
   `safe_metadata`. Build/consistency checks reject missing, duplicate, or stale
   entries. New fields do not inherit a permissive default.

2. **Fail closed for polymorphic and vendor data.** PIN/authentication material,
   key/attribute values, seed/state, plaintext/decrypted content, and unknown
   mechanism/attribute/vendor bytes are secret. A field is safe metadata only
   when its wire meaning is unambiguously limited to ciphertext, a public
   cryptographic result/parameter, or an operational identifier.

3. **Safe metadata is not a diagnostic capability.** The classification only
   decides wiping ownership. Logging, caching, persistence, audit emission, and
   debug-bundle inclusion require separate allowlists and reviews. Ciphertext,
   token labels, and client context IDs are not automatically loggable merely
   because they are not secret owners.

4. **Use one common project-owned byte type.** `SecretBytes` is exactly a
   `Zeroizing<Vec<u8>>` owner. It offers closure-scoped immutable/mutable slice
   access and consuming transfer as another `Zeroizing<Vec<u8>>`. It does not
   expose `Deref`, `AsRef`, serialization, or extraction into a plain `Vec`.
   `Debug` emits only `SecretBytes { len: N }`.

5. **Preserve wiping across ownership changes.** Conversion paths consume a
   secret owner where possible instead of cloning. If an external API forces a
   plain allocation, the caller documents that boundary, minimizes its
   lifetime, and establishes the next wiping owner immediately. The v0.2.0
   protected-decode work will reject dangerous duplicate-field encodings before
   prost can replace a long secret with a shorter allocation.

6. **Make the guarantee precise.** The project guarantees best-effort wiping of
   its currently owned and addressable secret allocations before normal or
   proven-quiescent deallocation, including permitted ordinary unwinding.
   It does not claim to wipe application/provider memory, previous allocations
   abandoned during reallocation, tonic/prost transport buffers, kernel/TLS
   buffers, swap, crash dumps, or remote systems. Panic remains unwinding so
   destructors run; the release profile must not use `panic = "abort"`.
   The selected v0.2 native-lifetime exception below must not wipe or free
   still-retained storage merely to satisfy a general Drop guarantee.

7. **Treat protected decode and lifetime migration as a release gate.** This
   decision's owner and manifest do not retroactively protect existing
   prost-generated `Vec<u8>` fields. Descriptor-aware pre-decode validation,
   redacted generated-message diagnostics, wipe-before-replacement behavior,
   and end-to-end owner migration are required before making the v0.2.0 privacy
   claim.

## v0.2 abnormal native-lifetime exception (2026-09-13)

The [native ownership contract](../release/native-mechanism-ownership.md)
selects a private return-aware raw Linux `exit_group(70)` for unresolved
shutdown or final-owner destruction without quiescence proof. Implementation
and target/native qualification remain pending. The stop initiates no wiping,
unwind, destructor, audit flush, native Finalize or provider cleanup. It does
not promise token deletion or a complete audit tail. Normal pre-entry failures
and ordinary panics retain their wiping/unwinding behavior; the release panic
profile is unchanged.

No core is intentionally triggered by this normal-exit syscall path, but it
does not enforce global dump suppression or erase previously captured memory.
Operators own crash collectors (including piped core handlers), tracing, swap
and storage policy; `RLIMIT_CORE=0` alone does not disable every collector.
No signal-handler/core-policy mutation occurs secretly in a backend destructor.
The final-owner guard must run before dependent destruction; it cannot undo
earlier destructors. Full placement, predicate and environment limits are in
the linked contract.

## Alternatives considered

### Keep ad hoc `Zeroizing` wrappers

This has the smallest patch but no completeness property. New messages can
silently bypass wiping and a surrounding derived `Debug` can still disclose
contents. Rejected.

### List only known secret fields and treat every other field as public

This is compact and conventional for serializers. It is unsafe for PKCS#11:
attribute, parameter, and vendor fields are intentionally extensible, so an
unknown field may contain key material. Rejected.

### Treat every byte/string field as secret

This is the most conservative lifetime policy and remains safer than guessing.
It would also force wiping ownership onto stable identifiers, ciphertext,
signatures, provider descriptions, and public nonces, increasing allocation and
conversion cost without protecting secret content. The selected design instead
uses an exhaustive, reviewed safe-metadata allowlist; uncertain fields remain
secret.

### Return a plain `Vec<u8>` from `SecretBytes`

This simplifies integration with existing APIs but silently ends the wiping
contract at the most common transfer point. Rejected. Explicit transfer retains
a `Zeroizing<Vec<u8>>`; unavoidable plain-buffer boundaries must remain visible
in their callers.

## Consequences

- Adding a protobuf byte/string field requires an explicit privacy decision.
- Secret `Debug` output is useful for sizing/flow diagnosis without containing
  payload material.
- Wiping is observable in tests before deallocation; tests never read freed
  memory.
- Some data classified secret is not cryptographic key material. That
  conservatism is intentional because privacy-sensitive content deserves the
  same short lifetime.
- Full adoption spans generated code and many call paths, so it is staged after
  this common definition and requires independent security review.

## Operational guidance

See [`doc/release/privacy.md`](../release/privacy.md) for the release-facing
contract, environmental limits, and operator controls.
