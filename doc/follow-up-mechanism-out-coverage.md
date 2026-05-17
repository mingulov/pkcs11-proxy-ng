# Follow-up: mechanism_out coverage gaps

**Date:** 2026-05-15
**Status:** Wave 1 + Wave 2 landed. All six verified-real findings from
the 2026-05-15 red-team audit are now closed.  This document is kept
as the audit record + the false-positive register so future audits
don't re-discover the same items.

## Why this exists

A red-team audit run on 2026-05-15 enumerated places where the proxy
silently drops `mechanism_out` updates that a native PKCS#11 module
would surface to the caller. The audit produced 27 raw findings across
two parallel passes; triage filtered out false positives (race-on-shim
slot reuse, gRPC error mapping speculation, integer-overflow defenses
that already use `try_from`, etc.) and verified the residual items
against actual code.

## Wave 1 (shipped 2026-05-15)

| Commit | Closes | Summary |
|---|---|---|
| `1c487c6` | R1#4, R1#5 | `mech_cache` cleanup on `C_CloseAllSessions` + `C_Finalize` |
| `00fb886` | R1#2 | `C_WrapKey` mechanism_out round-trip |

## Wave 2 (shipped 2026-05-15)

| Commit | Closes | Summary |
|---|---|---|
| `9579dac` | R1#1, R1#7 | `DecryptInit` symmetry + simple Encrypt/Decrypt/Update/Final RPC mechanism_out fields; new `session_output_mechanism_params` trait helper |
| `14ecef8` | R1#3 | `C_DeriveKey` mechanism_out — covers TLS12 master-key-derive `pVersion` writeback via new `derive_key_with_output` trait + FfiMechanism `Tls12MasterKeyDerive` output_params case |
| `060d33c` | R1#6 | CCM + ChaCha20-Poly1305 (Salsa20-Poly1305) variants for all six message-based crypto FFI helpers |

Coverage status after Wave 2: every `CK_*_PARAMS` shape modeled in the
proto and types crate flows back through the response messages.  The
only "Partial" row in `oasis-profile-coverage.md` is `C_DeriveKey` for
non-TLS12 derive mechanisms that mutate their params — those follow
the same pattern and can be added by extending
`FfiMechanism::output_params()` if a real provider exercises them.

## Provider-backed coverage note (2026-05-16)

`crates/server/tests/mechanism_out_gcm_iv_test.rs` uses the
`pkcs11-check/docker/softhsm2/patches/0001-simulate-aes-gcm-generated-iv.patch`
simulator to cover AES-GCM init-time IV writeback through the daemon and
SDK client. The AWS-style convention test now also decrypts the ciphertext
with the returned IV, so byte-shape-only IV transport bugs are less likely
to pass unnoticed.

That simulator generates the IV during `C_EncryptInit`; it does not cover
providers that write the generated IV only after `C_Encrypt`. The true
late-IV path is covered by mock-backed `ByteOutputExact` gRPC tests, shim
output-semantics tests, and an ignored loaded-shim C ABI test that mutates
caller-owned `CK_GCM_PARAMS` through the exported `CK_FUNCTION_LIST`.
The simple `EncryptResponse.mechanism_out` gRPC path is also covered by a
mock-backed test that reads cached session mechanism output through the SDK
client's `encrypt_with_mechanism_out` helper.
`C_WrapKey` has the same internal coverage now: a mock backend can return
delayed AES-GCM mechanism output through `wrap_key_exact_with_output`, and
the loaded-shim C ABI test verifies the caller stack is mutated only on the
buffer-present wrap call. These paths are still not covered by a real
provider integration; that would require a provider or simulator that
mutates `CK_GCM_PARAMS` during `C_Encrypt` or `C_WrapKey`.

## Audit findings — closed by commit

### 1. ✅ `C_DeriveKey` mechanism_out (R1#3) — closed in `14ecef8`

TLS12 master-key-derive's `pVersion` writeback now round-trips.
Implementation pattern:
- New trait method `derive_key_with_output` (default delegates to
  `derive_key` with `None` so unrelated backends compile unchanged).
- New helper `call_object_with_mechanism_output` in `call_helpers.rs`.
- `FfiMechanism::output_params()` learns the `Tls12MasterKeyDerive`
  case — reads back `CK_VERSION.major`/`.minor` from the pinned
  `Box<CK_VERSION>` in the backing tuple.
- Server's `derive_key` handler routes through the `_with_output`
  variant and populates `DeriveKeyResponse.mechanism_out`.

Adding more derive-with-output variants in the future (PBKD2 if a
provider ever mutates its params, SSL3 master-key-derive, etc.) is now
a one-arm extension of `output_params()`.

### 2. ✅ Simple `Encrypt` / `Decrypt` / `Update` / `Final` mechanism_out parity (R1#7) — closed in `9579dac`

All six simple RPC responses gained `optional Mechanism mechanism_out`.
Server populates from a new trait method
`session_output_mechanism_params(session)` which delegates to the
existing `FfiBackend::cached_mechanism_output_params` so the mechanism
the last `*_init` call cached is surfaced after each subsequent op.

`Pkcs11Client::encrypt`/`decrypt`/`encrypt_update`/etc. keep their
existing `CkResult<Vec<u8>>` signatures (backwards-compatible); the
proto field is wired so SDK consumers can build a richer wrapper if
they want the mechanism_out.

### 3. ✅ `C_DecryptInit` mechanism_out symmetry (R1#1) — closed in `9579dac`

`DecryptInitResponse` gained `optional Mechanism mechanism_out` and
the trait method `Pkcs11Backend::decrypt_init` now returns
`CkResult<Option<CkMechanismParams>>`, matching `encrypt_init` exactly.
`FfiBackend::ffi_decrypt_init` uses `call_init_with_mechanism_output`
instead of `call_init_with_mechanism`.

### 4. ✅ CCM + ChaCha20-Poly1305 message-ops (R1#6) — closed in `060d33c`

All six `ffi_*_message_*_exact_msg` helpers learned to dispatch on the
non-Gcm `MessageParameter` variants.  New helpers
`call_with_ccm_message_param` and
`call_with_salsa20_chacha20_poly1305_message_param` mirror the existing
GCM helper.  `CKM_AES_CCM` and `CKM_CHACHA20_POLY1305` now work
through the v3.0+ message interface against any provider that supports
them.

## Remaining items (not bugs)

### 5. `panic!()` for oversized buffers in shim helpers (style only)

`crates/shim/src/dispatch/general/helpers.rs:55,68` panics when the
caller passes a buffer length above `MAX_SERIALIZABLE_BYTES` (512 MiB).
The panic is caught by `catch_panics` and converted to
`CKR_GENERAL_ERROR`, so there's no UB risk despite the red-team
agent's initial concern.  Cleaner style would be to return
`CKR_ARGUMENTS_BAD` directly.

**Impact:** none — purely stylistic.  Left as documented hygiene
item; safe to refactor if anyone touches that file.

## False positives confirmed during triage

For the record so future audits don't re-flag these:

| Audit claim | Why dismissed |
|---|---|
| Duplicate `EncryptInit` overwrites cache (R1#6) | Underlying lib returns `CKR_OPERATION_ACTIVE`; insert never reached |
| Delayed GCM writeback race / stale pointer (R2#3) | PKCS#11 forbids concurrent ops on same session; serialization protects |
| `GetAttributeValue` partial-success collapse (R2#5) | `object.rs:101-119` already writes per-attribute `ulValueLen`; aggregate `CK_RV` is preserved |
| Shim eviction misses `delayed_gcm` on `CloseAllSessions` (R2#7) | `state.rs:355-370` iterates slot's sessions and calls `clear_delayed_gcm_writeback` for each |
| gRPC error → CK_RV mapping incomplete (R2#8) | Speculative; `unit_result_to_rv` handles tonic Status conversion |
| Vendor mechanism shape misconfig (R2#9) | Operator config error, not a proxy bug |
| NULL check in `write_mechanism_output_params` (R2#11) | Function already null-guards (`helpers.rs` `if p_mechanism.is_null() { return }`) |
| Re-init after Finalize reuses registry (R2#12) | Intentional design — `OnceLock`-backed; documented |
| Session slot map race (R2#13) | PKCS#11 serialization handles it |
| `u64 → usize` panic risk (R2#14) | Already uses `try_from()` correctly |
