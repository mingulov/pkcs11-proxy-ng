# Privacy and Secret-Lifetime Contract

The proxy handles PINs, keys, and application plaintext. It avoids logging
secret payloads and wipes project-owned secret buffers on normal release.
Memory held by native code during an unsafe shutdown follows the exception
below. These measures do not protect against a privileged process inspector.

## Client isolation scope

Use one logical client in one trusted security domain per daemon/provider
instance. Restart both before an independent client or domain takes over.
`[proxy] max_contexts = 1` limits admission but does not clear native login
state or establish cross-client object privacy. Multi-client isolation is
deferred to the [v0.3 scope](v0.3.0-scope.md).

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

This classification and `SecretBytes` type alone do not protect generated
protobuf requests and responses. Release qualification also requires
migration of classified secret owners and validation of protobuf wire input
before secret-bearing generated messages are allocated.

## Diagnostics

- Never derive or implement content-bearing `Debug` for a secret owner.
- Never log request or response bodies, attribute values, mechanism parameters,
  PINs, keys, plaintext, decrypted output, or raw provider values.
- Errors and trace spans contain operation metadata, not request or response
  payloads. The daemon may retain a valid textual peer `x-request-id` for
  correlation; treat it as untrusted metadata. Otherwise it generates a UUID.
- Debug bundles are private and allowlist-driven. They do not promise to
  sanitize arbitrary logs or configuration files after secrets were written.
- “Safe metadata” values remain absent from diagnostics unless a separate,
  reviewed allowlist explicitly includes them.

## Boundary of the guarantee

The [native ownership contract](native-mechanism-ownership.md) requires an
attempted whole-process stop with status 70 when shutdown cannot prove native
code has released its references. If the Linux syscall is denied or
intercepted, a return-aware loop prevents unsafe fallthrough but cannot force
termination. There is no strict disappearance deadline. Still-retained memory
must not be wiped or freed first. This path does not unwind, clean up the
provider, finalize PKCS#11, or flush logs and audits. Token effects and audit
records may remain unresolved. Ordinary panics retain the normal unwinding
strategy.

The stop does not intentionally trigger a core dump, but other crashes,
signals, tracing, and collectors may capture secrets. `RLIMIT_CORE=0` alone
does not disable piped core collectors. Operators must control dump storage,
swap, and process inspection. A direct embedding can terminate unrelated
threads in its process; syscall filters must permit the stop.

The proxy can wipe only memory that it owns and can still address. The wiping
guarantee does not cover:

- buffers retained by the calling application or provider module;
- tonic/prost borrowed frames, encoder scratch space, kernel socket buffers,
  TLS-library internals, or remote peer memory;
- copies created by an allocator, operating system, hypervisor, swap, core
  dump, hibernation image, or crash collector;
- secret values copied through an API that does not preserve wiping ownership;
- abnormal native-lifetime stopping while project memory remains retained.

TLS or mTLS protects bytes in transit but does not replace memory hygiene.
Unix-domain sockets with peer credentials protect a local transport boundary;
they likewise do not wipe endpoints' memory. Operators should disable core
dumps, protect or disable swap as appropriate to their threat model, restrict
process inspection, keep diagnostic collection private, and avoid injecting
secrets through command-line arguments or environment variables.
