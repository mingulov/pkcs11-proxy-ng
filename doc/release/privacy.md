# Privacy and Secret-Lifetime Contract

`pkcs11-proxy-ng` transports data that can include PINs, key material, and
application plaintext. The v0.2.0 privacy contract is data minimization: do not
log secret payloads, keep project-owned secret copies short-lived, and wipe
their current allocations before normal or proven-quiescent deallocation.
Ordinary permitted unwinding retains this wiping behavior; unresolved native
retention follows the abnormal-stop exception below.

This is a memory-hygiene guarantee, not a claim that the process is resistant
to memory inspection by a privileged attacker.

## Classification

[`crates/proto/secret-fields.toml`](../../crates/proto/secret-fields.toml) is
the machine-readable classification for every protobuf `bytes` and `string`
field. Each field occurs exactly once. Adding an unclassified field is an
error; there is no implicit public fallback.

Secret categories cover:

- PINs, passwords, user-authentication material, and OTP values;
- attribute values that may be keys or unknown vendor data;
- imported, unwrapped, derived, or provider-specific key material;
- random seeds, generated random output, operation state, KDF state, and
  opaque asynchronous state;
- plaintext inputs and decrypted outputs, including content being signed,
  verified, digested, or encrypted; and
- raw or polymorphic mechanism, parameter, message, and vendor fields whose
  safety cannot be established from the field alone.

The manifest also explicitly enumerates safe metadata: ordinary ciphertext,
signatures/digests/tags, public cryptographic parameters, and protocol
identifiers. Wrapped-key blobs remain key material and are secret-owned even
though they are encrypted. “Safe metadata” means only that this wiping policy
does not require secret ownership. It is not permission to log, cache, persist,
export, or disclose the value. Operational diagnostics use their own
allowlists.

## Project-owned buffers

Secret byte allocations owned by project code use
`pkcs11_proxy_ng_types::SecretBytes`. The type:

- owns a `Zeroizing<Vec<u8>>`;
- permits immutable or mutable access only through a closure-scoped slice;
- has no `Deref`, `AsRef`, serialization, or plain-`Vec` extraction API;
- transfers ownership only as `Zeroizing<Vec<u8>>`, retaining wiping; and
- renders `Debug` as its type and length, never its contents.

Dropping the owner wipes the initialized length and spare capacity before the
vector allocation is freed. Code should allocate the final capacity before
copying secret data: zeroization cannot erase an older allocation abandoned by
a prior reallocation.

The classification and `SecretBytes` definition are the first stage of the
v0.2.0 work. Generated protobuf requests and responses must not be treated as
protected merely because a handler later wraps one of their fields. The release
gate includes migrating all classified secret owners and validating protobuf
wire input before secret-bearing generated messages are allocated.

## Diagnostics

- Never derive or implement content-bearing `Debug` for a secret owner.
- Never log request or response bodies, attribute values, mechanism parameters,
  PINs, keys, plaintext, decrypted output, or raw provider values.
- Errors and trace spans contain operation metadata, not request/response
  payload fragments. A valid textual peer `x-request-id` is currently retained
  for cross-service correlation; otherwise the daemon generates a UUID. A
  retained peer value is untrusted diagnostic metadata and is not proof that
  the identifier was generated locally. The preferred later hardening is to
  always generate a local diagnostic identifier and, where cross-service
  correlation is required, retain a validated peer identifier in a separate,
  explicitly untrusted field.
- Debug bundles are private and allowlist-driven. They do not promise to
  sanitize arbitrary logs or configuration files after secrets were written.
- “Safe metadata” values remain absent from diagnostics unless a separate,
  reviewed allowlist explicitly includes them.

## Boundary of the guarantee

The selected v0.2 [native ownership contract](native-mechanism-ownership.md)
requires a private return-aware raw Linux `exit_group(70)` when shutdown cannot
establish native quiescence or final-domain Drop lacks its proof. This contract
is implemented (`crates/backend/src/ffi/native_stop.rs`, Tasks 3–4) and
natively qualified (stop-topology-oracle receipt, 2026-09-17: GNU/musl stop
suites green 32/32 native on both widths). Still-retained roots
must not be wiped or freed first. The path initiates no unwinding, user-space
destruction, provider cleanup, native Finalize, logging or audit flush. It
promises no wiping, token deletion or complete audit tail. The release panic
strategy remains unwinding for ordinary panics.

The normal-exit syscall does not intentionally trigger a core, but no global
no-dumps guarantee follows. External signals, other crash paths, tracing and
system collectors can still capture secrets; a piped core handler is not
disabled by `RLIMIT_CORE=0` alone. Operators must manage the complete
dump/storage/inspection policy. Direct backend users must accept termination
of the whole embedding application's thread group under the Linux/seccomp
environment, including unrelated threads; there is no strict disappearance
deadline or support for arbitrary syscall-denial/interception policies.

The proxy can wipe only memory that it owns and can still address. The wiping
guarantee does not cover:

- buffers retained by the calling application or provider module;
- tonic/prost borrowed frames, encoder scratch space, kernel socket buffers,
  TLS-library internals, or remote peer memory;
- copies created by an allocator, operating system, hypervisor, swap, core
  dump, hibernation image, or crash collector; or
- secret values copied through an API that does not preserve wiping ownership;
  or
- abnormal native-lifetime stopping while project memory remains retained.

TLS or mTLS protects bytes in transit but does not replace memory hygiene.
Unix-domain sockets with peer credentials protect a local transport boundary;
they likewise do not wipe endpoints' memory. Operators should disable core
dumps, protect or disable swap as appropriate to their threat model, restrict
process inspection, keep diagnostic collection private, and avoid injecting
secrets through command-line arguments or environment variables.

See [ADR-0013](../adr/ADR-0013-secret-ownership-and-diagnostics.md) for the
decision and accepted trade-offs.
