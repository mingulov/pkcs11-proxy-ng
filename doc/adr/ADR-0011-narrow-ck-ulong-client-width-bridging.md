# Narrow-`CK_ULONG` Client Support & Width Bridging

**Document:** ADR-0011
**Status:** Accepted (decisions D1–D4 recorded 2026-06-28; implementation pending)
**Date:** 2026-06-28
**Relates to:** [ADR-0006](./ADR-0006-32-64-bit-cross-platform-compatibility.md)
(supersedes its "narrow-client NOT SUPPORTED" row for the bridged topology),
[ADR-0002](./ADR-0002-handle-session-identity-model.md) (handle virtualization),
ADR-0010 (transparent verbatim forwarding — this ADR defines a narrow,
explicit exception to it).
**Companion analysis:** umbrella `doc/plans/2026-06-28-windows-client-shim-gap-analysis.md`.

---

## Decision (summary)

**v0.2 P0 amendment (2026-09-13; selected contract, implementation pending):**
Production live FFI is restricted to qualified Linux GNU/musl x86_64 with
64-bit pointers and x86 with 32-bit pointers. This explicitly supersedes D3's
Windows native-provider daemon support for v0.2. Windows native loading is
deferred, lower priority/stretch work. Existing portable Windows
client/shim/proto/types, mock-only backend/server builds and Windows-client to
qualified-Linux-daemon interoperation remain. Nonqualified-host construction
must fail before loading/discovery; keep portable compile CI and add a no-loader
constructor-refusal test. No unsafe legacy FFI or abort fallback is permitted.
The [native ownership contract](../release/native-mechanism-ownership.md)
defines exact cfg/environment gates, checked Wait widths and all four required
Linux topology receipts. Earlier bridge/Wine results do not qualify this new
native lifetime/stop implementation, which remains unimplemented.

[Tail-stretch closure, 2026-09-17: the Windows-daemon-host deferral in this
amendment is closed — [ADR-0014](./ADR-0014-v020-tail-platform-stretch.md) is
Implemented, with real-Windows (non-Wine) daemon-host receipts in
workspace-root `artifacts/v020-tail-windows-2026-09-16/` legs A and C, and
shim-direction receipts in leg B. The wine smokes below remain dev-only
smokes, never conformance evidence.]

Support **narrow-`CK_ULONG` clients** — clients whose native `CK_ULONG` is
32-bit (`i686-unknown-linux-gnu`, `armv7-unknown-linux-gnueabihf`, and
`x86_64-pc-windows-msvc`/LLP64) — talking to a 64-bit Linux server+backend, via a
**client-side, transparent width bridge confined to the shim's C-ABI edge**.
The design generalizes to **bidirectional** cross-width (the principle is "ABI
width normalization at each C-ABI boundary"; see Bidirectionality). Historical
bridge validation covered all four combinations (D3 amendment, 2026-07-02):
narrow clients (`32c/64b`), the reverse direction (`64c/32b`, a
narrow-`CK_ULONG` daemon host with D4 checked input narrowing), and both
same-width controls. The historical Windows mTLS-TCP daemon scope is superseded
for v0.2 by the amendment above.

- **The wire and the server do not change.** They remain `u64`-everywhere and
  width-agnostic. The client does **not** advertise its width *to* the server
  for the server to act on. (See D2 for an optional *server→client* backend-width
  advertisement used only for a safety assertion.)
- The bridge translates **only** `CK_ULONG`-semantic *attribute values* returned
  by `C_GetAttributeValue`, because those are the **sole** outputs that travel as
  raw backend-width bytes. Every other output (`CK_*_INFO` structs, slot/mechanism
  lists, all lengths/counts, typed mechanism-param write-backs) is typed rather
  than raw attribute bytes. A typed `as CK_ULONG` cast alone does not prove
  representability. In particular, v0.2 Wait input flags, response RV and
  successful virtual-slot output require new checked conversions under the
  exact lifecycle -> width -> mode -> contention order in the linked contract.
- This is an explicit, bounded exception to ADR-0010's verbatim rule, justified
  because transparency (Contributor Rule §2 — "indistinguishable from a native
  module") *requires* a 32-bit client to receive 32-bit `CK_ULONG` attribute
  values. It is **representational** fidelity, not a change in **semantic**
  fidelity (which RVs are returned, which backend call runs).

**Decisions recorded 2026-06-28** (see the resolved list at the end): D1 — the
ADR-0010 carve-out is **ratified** as a scoped, representational-fidelity
exception; D2 — **server→client backend-width advertisement**; D3 — targets
`i686-unknown-linux-gnu` + `armv7-unknown-linux-gnueabihf` +
`x86_64-pc-windows-msvc`; D4 — **checked, value-preserving narrowing** (reject on
genuine `> u32::MAX` overflow). Implementation is pending.

---

## Context

### Two distinct narrow-client ABIs, one shared core

| Target | `CK_ULONG` | Pointer | Struct packing | Transport | TLS toolchain |
|---|---|---|---|---|---|
| `i686-unknown-linux-gnu` (Tier 1; the "standard" 32-bit) | 32-bit | 32-bit | natural (`#[repr(C)]`) | UDS **or** TCP/mTLS | `ring` via gcc `-m32` multilib |
| `armv7-unknown-linux-gnueabihf` (Tier 2) | 32-bit | 32-bit | natural | UDS **or** TCP/mTLS | `ring` via arm cross gcc |
| `x86_64-pc-windows-msvc` (LLP64) | 32-bit | **64-bit** | **`#[repr(C, packed)]`** (`#pragma pack(1)`) | TCP/mTLS only | `ring` via MSVC + NASM |

The **shared core problem is narrow `CK_ULONG`**. The Windows-specific axes
(64-bit pointer, `pack(1)`, no UDS, MSVC toolchain) are covered in the companion
gap-analysis doc; 32-bit Unix avoids all of them and is therefore the *simpler*
first target.

### Already handled (verified)

- **Handles:** virtualized per client by the daemon from a small monotonic
  counter (ADR-0002; `handle_map.rs` `next_id: 1, += 1`). A narrow client never
  sees a backend handle, so handle truncation does not occur.
- **Wire/core compiles for narrow targets:** `cargo check` of `types` + `proto`
  (+ tokio/tonic/hyper/h2) is clean for both `i686-unknown-linux-gnu` and
  `x86_64-pc-windows-msvc`. The only dependency-graph blocker is `ring`'s native
  build (toolchain, not code).
- **All non-attribute outputs are field-typed** (`CK_INFO`, `CK_SLOT_INFO`,
  `CK_TOKEN_INFO`, `CK_SESSION_INFO`, `CK_MECHANISM_INFO`; `C_GetSlotList` /
  `C_GetMechanismList` arrays; `*pul*` lengths/counts; GCM/CCM param write-backs)
  → width-correct on narrow clients with no change.

### The gap (verified, and widened by adversarial review)

`C_GetAttributeValue` returns each value as **raw bytes** with
`returned_len = backend ulValueLen` (proto `AttributeQueryResult{value: bytes,
returned_len: uint64}`). A 64-bit backend returns **8 bytes / len=8** for a
`CK_ULONG`-typed attribute; a narrow client expects **4**. Without bridging, a
narrow client's correctly-sized 4-byte buffer yields
`CKR_BUFFER_TOO_SMALL, len=8` and ordinary attribute reads break. Review widened
the original "few sites" framing into the following defect set, which this ADR
must address:

- **Incomplete classification (C1/H3).** `CkAttributeType::is_ulong()` lists only
  5 of ~30 ulong-typed attributes (missing e.g. `CKA_VALUE_BITS`,
  `CKA_PRIME_BITS`, `CKA_SUB_PRIME_BITS`, `CKA_KEY_GEN_MECHANISM`,
  `CKA_MECHANISM_TYPE`, `CKA_HW_FEATURE_TYPE`, `CKA_PROFILE_ID`, the `CKA_OTP_*`
  and HW-feature display attrs). The predicate is used on **both input and
  output**; a missed ulong attr corrupts width symmetrically (wrong value sent to
  the backend; wrong value/len returned to the app).
- **`CKA_ALLOWED_MECHANISMS` mis-routed (C2 — pre-existing, width-independent).**
  It carries `CKF_ARRAY_ATTRIBUTE` but is a `CK_MECHANISM_TYPE[]` (ulong array),
  yet `build_attribute_query` routes *all* array attributes as `CK_ATTRIBUTE[]`
  nested templates (`ulValueLen / size_of::<CK_ATTRIBUTE>()`) → already broken on
  64-bit (`8 % 24 != 0` → `CKR_ARGUMENTS_BAD`). Needs a distinct
  `is_ulong_array()`.
- **Array width is per-element (H1):** `n·8 ↔ n·4`, not a fixed `8↔4`.
- **Nested-template ulong sub-attributes unhandled both directions (H2).**
- **Sentinel hazard (C4):** `CK_UNAVAILABLE_INFORMATION` (`u64::MAX`) currently
  narrows correctly to `0xFFFF_FFFF` by `as CK_ULONG` truncation; a naïve
  "return 4 for ulong" size-query rule would destroy it.
- **Exact-output conflict (C3):** bridging necessarily rewrites `buffer_len`,
  re-encodes the value, recomputes `ulValueLen`, and (because the server's
  per-attribute `too_small` test runs against the inflated `buffer_len`)
  synthesizes `CKR_BUFFER_TOO_SMALL` locally. This is the ADR-0010 tension.
- **Does not compile yet (M2):** `helpers/mod.rs:3694`
  `Some(CkAttributeValue::Ulong(v))` (`v: CK_ULONG`) into a `Ulong(u64)` variant
  lacks an `as u64` — a hard error on narrow targets. The narrow build has never
  been compiled; CI must include it before this logic is reviewable.

---

## The bridge design

### Trigger

Bridge active whenever **client `CK_ULONG` width ≠ backend `CK_ULONG` width**
(either direction); each ulong-typed value is translated into the *destination*
edge's native width. Client width is a compile-time constant; the backend
(= server-process) width is learned from the D2 advertisement, with per-attribute
`returned_len` as ground truth. Equal widths → a true no-op.

> **Correction (adversarial review).** An earlier draft said "translate only when
> `backend > client`; a 64-bit client is a no-op." That is **wrong**: for a
> 64-bit client / 32-bit backend the backend returns a 4-byte value, and a naïve
> no-op copies 4 bytes into the app's 8-byte `CK_ULONG`, reports `len = 4`, and
> leaves the high word **garbage**. The trigger is width-*inequality*; the action
> (narrow vs widen) is chosen per direction. See "Bidirectionality" below.

### What is translated — and what is not

| Attribute class | Example | Bridged? |
|---|---|---|
| ulong scalar | `CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_VALUE_LEN`, `CKA_MODULUS_BITS`, `CKA_KEY_GEN_MECHANISM`, … (complete set) | **Yes** — re-encode width |
| ulong array | `CKA_ALLOWED_MECHANISMS` (`CK_MECHANISM_TYPE[]`) | **Yes** — per-element re-encode |
| nested template | `CKA_WRAP_TEMPLATE`, `CKA_UNWRAP_TEMPLATE`, `CKA_DERIVE_TEMPLATE` | **Yes** — recurse per sub-attribute |
| bool | `CKA_TOKEN`, `CKA_SENSITIVE`, … (`CK_BBOOL`, 1 byte) | No — width-invariant |
| byte/string | `CKA_LABEL`, `CKA_ID`, `CKA_VALUE` | No — opaque bytes |
| big-integer | `CKA_MODULUS`, `CKA_PUBLIC_EXPONENT` | No — big-endian byte array |
| date/struct | `CKA_START_DATE`/`CKA_END_DATE` (`CK_DATE`, 8-byte char array) | No — fixed-layout bytes |

The translated set **must be sourced authoritatively from the OASIS inventory**
(not the current hand-rolled 5-entry list), with a consistency test that fails
if a spec ulong/ulong-array attribute is unclassified. Classification is applied
**symmetrically** on input (template marshalling, `ck_attrs_to_rust_checked`) and
output.

### Mechanics

**Request (output-bearing reads):** only when the **client is narrower** than the
backend, a ulong / ulong-array / nested-ulong attribute with a non-NULL caller
buffer must be requested with `buffer_len` sized for the **backend** width
(scalar: `≥ backend_width`; array: `element_count · backend_width`; nested:
recurse), so the wider backend returns the value instead of
`CKR_BUFFER_TOO_SMALL`. When the client is **wider** (64c/32b) no inflation is
needed (the client buffer already exceeds the backend value). A NULL caller
buffer (size query) is forwarded as a size query; its returned length is reported
in **client** width.

**Output (`C_GetAttributeValue`) — bidirectional:** for a ulong-typed attr,
decode `returned_len` bytes as an integer in the **advertised backend byte
order** (D6 — *not* a hard-coded `from_le_bytes`; all current targets are LE but
the order must be advertised, not assumed), re-encode into the **client's** native
`CK_ULONG` width and byte order, write to the caller buffer, and set `ulValueLen`
to the **client** width (scalar: `size_of::<client CK_ULONG>()`; array:
`element_count · client_width`). This covers both **narrowing** (client < backend)
and **widening** (client > backend). Recurse for nested templates, and
**recompute the parent `ulValueLen` as `client_count · size_of::<client
CK_ATTRIBUTE>()`** — never forward the backend's byte-length, which is in backend
`CK_ATTRIBUTE`-size units (12 on i686, 24 on x86_64) and would mis-count elements
in *both* directions (review defect #3). On Windows honor the packed
`CK_ATTRIBUTE` layout (copies only, no references to packed fields).

**Sentinel `CK_UNAVAILABLE_INFORMATION` — asymmetric (review).** It is
platform-sized all-ones and travels as a *length*, not a typed value, so
classification does not catch it:
- **Narrowing** (32c/64b): `0xFFFF_FFFF_FFFF_FFFF as u32 = 0xFFFF_FFFF` — correct
  for free by truncation.
- **Widening** (64c/32b): a 32-bit backend reports `returned_len = 0xFFFF_FFFF`;
  zero-extending to `0x0000_0000_FFFF_FFFF` ≠ the 64-bit sentinel, so the app
  would not recognise "sensitive/unavailable." The widening edge **must
  explicitly map backend all-ones (`returned_len == 2^{8·backend_width} − 1`) to
  client all-ones.** This refutes "widening is always lossless." Relay the
  backend's per-attribute `ck_rv` verbatim; a caller buffer smaller than the
  client width is a genuine `CKR_BUFFER_TOO_SMALL` reported honestly.

**Reject lives at *two* edges (review).** The checked-narrowing/reject (D4/D5) is
not client-only — it runs **wherever narrowing physically occurs**:
- **32c/64b** narrows on the **client output** edge (`object.rs`).
- **64c/32b** narrows on the **server *input*** edge — `ffi_conversion.rs:70`
  currently does an **unchecked** `*u as cryptoki_sys::CK_ULONG` (`u64 → u32`
  silent truncation). A 64-bit client sending a `> u32::MAX` ulong value would be
  corrupted silently. Fix: `CK_ULONG::try_from(*u)` + reject there too. Rule:
  *reject whenever the destination edge is narrower than the source value.*

**Overflow — checked, value-preserving narrowing (D4):** decode the backend
bytes to an integer (`u64::from_le_bytes`), then narrow with a **checked**
conversion (`CK_ULONG::try_from`), then `to_le_bytes`. This converts the *value*,
not "some 4 bytes", so a real value of `1` (`01 00 00 00 00 00 00 00`) is
**guaranteed** to arrive as `1`. A value `> u32::MAX` (e.g. `0x1_0000_0001`,
whose low word is also `1`) does **not** silently become `1`: the checked
conversion fails and the shim **rejects** (`CKR_FUNCTION_FAILED`) rather than
fabricate a misleading small value. No spec `CK_ULONG` attribute exceeds 2³² in
practice, so the reject branch should never fire — but if it does it is loud and
safe, not silently wrong. (A native 32-bit module's `CK_ULONG` could not hold the
value either.)

**Out of scope / hard-reject:** the vendor *raw message-parameter* path
(`helpers/mod.rs:3643`) can embed `CK_ULONG` fields in an opaque struct the proxy
does not model. For narrow clients this must be a **hard reject**
(`CKR_MECHANISM_PARAM_INVALID`/`CKR_FUNCTION_NOT_SUPPORTED`), never a silent
backend-width pass-through. Mixed-endian (BE backend or BE client) is out of
scope.

---

## Bidirectionality, its asymmetries, and the wire-format choice

The bridge supports all four width combinations — `64c/64b` (native),
`32c/64b` (narrow client), `64c/32b` (narrow backend), `32c/32b` — under one
principle: **ABI width normalization at each C-ABI boundary, with the gRPC wire
as the canonical width-independent interchange.** Each edge translates ulong
values between its own native width and the wire form; neither edge assumes the
other's width except via the D2 advertisement (request sizing) and per-attribute
`returned_len` (ground truth). The server/backend output edge is *already*
self-width-correct (keyed on `cryptoki_sys::CK_ULONG`, `mapping.rs`); the width
logic to add is almost entirely the **client shim** plus the server *input* edge
narrowing-check (`ffi_conversion.rs:70`).

**Wire format: raw bytes (Option A), not typed (Option B) — decided.** The wire
keeps attribute *values* as raw bytes (`AttributeQueryResult.value` +
`returned_len`); input templates already carry a *typed* `ulong_value`. This
input-typed / output-raw asymmetry is intentional and correct:

- Option A keeps the **server verbatim & width-agnostic** (ADR-0010), confines
  width logic to each edge behind one shared classifier, and preserves
  opaque/vendor byte-strings exactly.
- Option B (typed ulong on the wire) would push classification into the server,
  risk a server-side misclassification **corrupting** an opaque/vendor value, and
  solve nothing the D6 byte-order field does not solve better. Rejected.

**It is NOT a fully symmetric design.** Two irreducible asymmetries (review):

1. **The narrowing/reject edge moves with direction** — client-output for
   `32c/64b`, server-input for `64c/32b`. The D4/D5 reject must exist in **both**
   places.
2. **The platform-sized sentinel** is preserved for *free* when narrowing
   (truncation) but must be **explicitly expanded** when widening (all-ones map).

Plus an asymmetric **deployment cost**: `32c/64b` needs only a 32-bit *client
shim*; `64c/32b` needs a 32-bit **server + backend + `ring`** stack that
**ADR-0006 defers and that has never been compiled or tested** (only
`types`/`proto`/`shim` have been narrow-checked; a scan found no obvious code
blocker in `server`/`backend`, but it is unverified). Therefore `64c/32b` is
**design-acknowledged but deployment-gated** on a separate 32-bit-server track —
not a shipping target of this ADR. The *shipping* target remains the narrow
client (`32c/64b`) against the standard x86_64 Linux server.

**Endianness.** Raw wire bytes are the backend's host byte order, not a
normalized integer, so the bridge decodes/encodes using the **advertised** order
(D6), never a hard-coded LE assumption. All current targets are LE; mixed-endian
stays out of scope but is now *detected and refused at probe* rather than
silently corrupting.

---

## ABI axes: `CK_ULONG` width vs local layout — and the LLP64 (Windows) server

A narrow-`CK_ULONG` edge is **not** the same as a 32-bit-pointer edge. There are
three real ABIs, and **any edge (client *or* server/backend) may be any of them**:

| ABI | `CK_ULONG` | pointer | struct packing | examples |
|---|---|---|---|---|
| **LP64** | 64 | 64 | natural | Linux/macOS x86_64, aarch64 |
| **ILP32** | 32 | 32 | natural | i686-linux, armv7-linux |
| **LLP64** | **32** | **64** | **`pack(1)`** | **Windows x64** |

The crucial decomposition — **two orthogonal axes**:

1. **`CK_ULONG` width + byte order** — the *only* properties that cross the wire.
   They drive the value bridge (this ADR) and are advertised (D2/D6). For the
   bridge, **LLP64 ≡ ILP32** (both are "narrow `CK_ULONG` = 4, LE"): a Windows
   backend advertises `width = 4, order = LE`, identical to i686, and the client
   bridges identically.
2. **Pointer width + struct packing** — **purely local** to each edge. Pointers
   and C structs never cross the wire: it carries semantic proto fields (+ scalar
   value bytes), handles are virtualised to small `u64`, and mechanism params are
   dereferenced locally and sent as values. So these are handled entirely by
   `cryptoki-sys`'s per-target bindings + packed-field handling at that edge's
   build — **independent of the other edge and of the wire.**

**Invariant:** the wire/bridge depends *only* on each edge's `(CK_ULONG width,
byte order)` — never on pointer width or packing. This is what lets one bridge
cover all 3×3 ABI combinations without special cases.

**So is an LLP64 (Windows) server "a different case"?** For the **bridge: no** —
it is a narrow-`CK_ULONG` backend, already handled (same math as i686). For the
**local ABI: yes** — it carries Windows pointer/packing concerns, but those are
the *same* ones already analysed for the Windows **client** (companion doc), now
on the server's backend-FFI side. A Windows (LLP64) server splits into three
buckets:

- **Bucket 1 — narrow `CK_ULONG` (this ADR's bridge):** no new work; advertise
  `width = 4`.
- **Bucket 2 — LLP64 local ABI (= Windows-client analysis, server side):** the
  **5 hand-rolled `#[repr(C)]` structs** `FfiRsaAesKeyWrapParams`,
  `FfiSignAdditionalContext`, `FfiHashSignAdditionalContext`, `FfiKmacParams`,
  `FfiMuGenParams` (`ffi_conversion.rs:733-774`) need
  `#[cfg_attr(windows, repr(C, packed))]` (else `size_of` yields the wrong
  `ulParameterLen`). Packed-field access is **already E0793-safe** — the backend
  reads cryptoki-sys param structs by cast-and-deref, never `&field`; all sizes
  are `size_of::<T>()`; `cryptoki-sys` structs self-adjust. So Bucket 2 ≈ 5
  annotations + a size round-trip test.
- **Bucket 3 — Windows OS port of the *server* (the real lift):** the Unix
  signal and file-mode paths are **already `#[cfg(unix)]`-gated**; the structural
  blockers are the **UDS listener + `SO_PEERCRED` peer-cred auth**
  (`auth/peer_cred.rs`, `nix`) — impossible on Windows. So a Windows server is
  **mTLS-over-TCP only** and its config **must** provide `[listener.remote]`
  (reject `[listener.local]`). Functional limitation: **SIGHUP mechanism-registry
  hot-reload is lost** (operator restarts to reload). `libloading` already loads a
  `.dll` cross-platform; `ring` needs the MSVC+NASM toolchain.

A Windows-server deployment is thus **design-covered** (Buckets 1+2 reuse existing
analyses; Bucket 3 is a bounded OS port), but — like `64c/32b` generally —
**not a shipping target here**: it is gated on the Windows-server port and the
32-bit-server track (ADR-0006).

---

## Real-provider value-range analysis (does any real provider exceed 32 bits?)

**Answer: not in practice — but the spec *permits* it, so the design must not
rely on that.** (This corrects an earlier overstatement that called the 32-bit
limit a normative requirement.) Evidence:

1. **The 32-bit limit is a *de-facto convention*, not normative.** The PKCS#11
   *normative* spec defines `CK_ULONG` only as "an unsigned value, at least 32
   bits long" and **does not** cap data values at 32 bits (verified: neither the
   v2.40 base spec nor the v3.1 spec contains a "0xffffffff" rule). The "use only
   the least significant 32 bits, to permit lossless 32↔64-bit conversion"
   guidance is a **2013 OASIS TC mailing-list proposal** (Chris Zimman, "CK_ULONG
   considered harmful?"), widely followed but never ratified. **A 64-bit provider
   returning a `> 2³²` value would therefore be spec-legal, not non-conformant**
   — which is exactly why the bridge keeps a *checked* path (D4/D5) instead of a
   blind low-word cast.
2. **Vendor ranges are bit-31, not bit-32+.** Every `*_VENDOR_DEFINED` base
   (CKA/CKC/CKH/CKK/CKM/CKO/CKP/CKR) is `0x80000000UL` — *inside* 32 bits —
   verified in the OASIS header. Vendors add small offsets (NSS `CKM_NSS_*`,
   AWS `CKM_CLOUDHSM_*`, nCipher, Luna/SafeNet) and stay `< 2³²`. The proxy's own
   tables agree (largest standard `CKM_*` ≈ `0x403A`; object classes 0–4; key
   types ≤ `0x3C`). No `CK_*` data constant in the header exceeds `0xFFFFFFFF`.
3. **Length/bits attributes are crypto-bounded.** `CKA_VALUE_LEN`,
   `CKA_MODULUS_BITS`, `CKA_*_BITS` are bounded by key/data sizes (KB / ≤ ~16384
   bits) — orders of magnitude below `2³²`. (These are already guarded as
   `is_allocation_size()` against absurd values that would overflow backend
   allocations and abort the daemon.)
4. **The only all-bits value is the sentinel** `CK_UNAVAILABLE_INFORMATION`
   (`~0UL`), handled separately by truncating passthrough (→ `0xFFFF_FFFF`).

**Residual risk = providers that use the spec's full `CK_ULONG` range**
(spec-legal, convention-discouraged), in two shapes — which is why the bridge
keeps a *checked* path rather than a blind cast:

- **Dirty high 32 bits** — a provider writes an 8-byte `CK_ULONG` without zeroing
  the top word (a known interop hazard). The *intended* value is the low word.
- **Genuine `> 2³²` value** — discouraged by convention but spec-permitted;
  un-representable on any 32-bit client (a native 32-bit module's `CK_ULONG`
  could not hold it either).

**Lengths are a separate category from values — and not a narrow-client width
problem.** The "≤ 2³²" observation above is about ulong *attribute values*
(enums, key/cert types, bit counts). *Length* parameters (`ulRandomLen`,
`ulValueLen`, data sizes) are also `CK_ULONG` and on a 64-bit client genuinely
*can* exceed 2³² — e.g. `C_GenerateRandom` for 5 GiB. This is **not** a
width-bridge concern: (a) a narrow client's `CK_ULONG` is 32-bit, so it cannot
even *express* a length > 4 GiB − 1; and (b) the proxy caps every transfer far
below that anyway — gRPC `max_message_bytes` defaults to **4 MiB** and the shim's
`MAX_SERIALIZABLE_BYTES` guard is **512 MiB** — so a 5 GiB request fails with a
transport/size error for *all* clients. (`c_generate_random` also does
`ul_random_len as u32`; with the transport cap, random output is effectively
bounded well under 4 MiB by default.)

These motivate **decision D5** (high-bits policy) below. Note: `pkcs11-check`'s
vendor headers were not available in this environment, so the vendor-range claim
rests on the OASIS convention + the standard header + the proxy's tables rather
than a per-vendor header diff; a vendor-header survey is a cheap future
confirmation but is not expected to change the conclusion.

---

## Relationship to ADR-0010 (the carve-out — Decision D1)

ADR-0010 mandates verbatim forwarding: no synthesized/translated RVs, no
locally-reconstructed `CKR_BUFFER_TOO_SMALL`, no fabricated lengths. The bridge
appears to violate all of these. The resolution:

- ADR-0010 governs **semantic** fidelity: *which* `CK_RV` is returned and *which*
  backend operation runs. The bridge changes **neither** — it relays the
  backend's per-attribute `ck_rv` and runs exactly one backend call per request.
- The bridge changes only **representation**: expressing the same integer value
  in the caller's native `CK_ULONG` width, exactly as a native 32-bit module
  would. Contributor Rule §2 (indistinguishable from native) *requires* this; a
  verbatim 8-byte length to a 32-bit caller is, paradoxically, the
  *non-transparent* behavior.
- The local `CKR_BUFFER_TOO_SMALL` is synthesized only against the **caller's
  real** buffer vs the **client** width — i.e., the value a native module would
  itself compute — not to mask backend behavior.

D1 asks the maintainer to ratify this scoping as an explicit, bounded exception
to ADR-0010, limited to `CK_ULONG`-semantic attribute values on narrow clients.

---

## Width negotiation (Decision D2)

Three options were considered:

- **(a) Fully transparent, compile-time only.** No protocol change; client width
  is a constant; backend width assumed 8. Simplest; silently corrupts if the
  backend is ever not 8-byte.
- **(b) Transparent bridge + server→client backend-width advertisement
  (recommended).** The server publishes its backend `sizeof(CK_ULONG)` in the
  existing `GetBackendInterfaces` probe; the client asserts its bridging
  assumption and refuses to run (clear error) on mismatch. One-way, stateless,
  server stays width-agnostic about *clients*.
- **(c) Client→server width negotiation (rejected).** Client tells the server its
  width and the server narrows. Makes the server per-client stateful, leaks
  client ABI into the protocol, and conflicts more deeply with ADR-0010. The
  maintainer's instinct ("better not") matches this rejection.

**Decision: (b)** — keeps all translation client-side while removing the
unguarded "backend is 8 bytes" invariant. The client refuses to run (clear error
at probe time) if the advertised backend width is incompatible with its bridging
assumption.

---

## Scope / targets (Decision D3)

- **In scope:** `i686-unknown-linux-gnu` (standard 32-bit; also serves 32-bit
  apps on 64-bit hosts via multilib), `armv7-unknown-linux-gnueabihf`, and
  `x86_64-pc-windows-msvc` (with the extra Windows ABI work in the companion
  doc).
- **Out of scope:** `x86_64-pc-windows-gnu` (no guaranteed-correct pregenerated
  `cryptoki-sys` bindings → `generic.rs` fallback), 32-bit Windows
  (`i686-pc-windows-msvc`: calling-convention wrinkles), big-endian / mixed-endian
  topologies, and any 32-bit *backend/server* track.

---

## Consequences

**Positive**
- Narrow clients become transparent for attribute reads — the one thing that was
  actually broken — while ~90% of the surface needs no change.
- Server, wire, and all other shims are untouched; multi-client safety preserved.
- Fixes a real pre-existing 64-bit bug (`CKA_ALLOWED_MECHANISMS`, C2) as a
  by-product of completing classification.

**Negative / risks**
- Introduces an ADR-0010 exception that must be tightly scoped and tested or it
  becomes a transparency hole.
- Requires a **complete, spec-sourced** attribute classification; an omission is
  a silent correctness bug (mitigated by an OASIS-inventory consistency test).
- Adds Windows-`pack(1)` reconstruction surface in the nested path (UB risk if
  any packed-field reference creeps in; copies only).
- Build/CI cost: native toolchains for `ring` per target.

---

## Implementation plan (review-hardened order)

1. **Compile a narrow target & add CI (M2 first).** Fix `as u64`/width spots
   (e.g. `helpers/mod.rs:3694`); add `i686-unknown-linux-gnu` `cargo check`/test
   to CI. This surfaces the true scope before any bridge logic.
2. **Complete & source the classification (C1/H3).** Replace `is_ulong()` with a
   spec-derived table; add `is_ulong_array()` (C2); symmetric input/output.
   **Extend the OASIS inventory** — `scripts/oasis-coverage-inventory.py` +
   `crates/server/tests/local_quality_gate_test.rs` currently enumerate
   functions/mechanisms/params/flags but **not attribute value-types**; add an
   attribute-type inventory + a consistency test that fails if any spec
   ulong/ulong-array/bool/date attribute is unclassified.
3. **Fix `CKA_ALLOWED_MECHANISMS` routing (C2)** — independent correctness fix,
   landable on its own with a 64-bit regression test.
4. **Implement the client bridge** (the `32c/64b` shipping direction): request
   inflation (only when client < backend) + output re-encode, scalar → array (H1)
   → nested recursion (H2). **Trigger on width-*inequality*, not `backend >
   client`.** Recompute nested parent `ulValueLen` in **client** `CK_ATTRIBUTE`
   units (review #3). Decode/encode by **advertised byte order** (not literal LE).
   Hard-reject the vendor raw message-param path for narrow clients.
5. **Sentinel handling, both directions (review #2).** Narrowing: truncation is
   correct. Widening: explicitly map backend all-ones → client all-ones. Add
   round-trip tests for `CK_UNAVAILABLE_INFORMATION` in *both* directions.
6. **D2/D6 advertisement (review #9/#10):** **add** `backend_ulong_size` +
   `byte_order` to `GetBackendInterfacesResponse` (they do not exist yet); client
   asserts at probe; fall back to "8 / LE + warning" for older daemons.
7. **Test on Linux CI without a 32-bit box:** a test-only **simulated narrow
   `CK_ULONG`** seam to exercise inflate/re-encode/sentinel/array/nested in both
   directions; plus a real `i686` *client* build and a cross-topology smoke test
   (`pkcs11-tool` → narrow shim → 64-bit server + software token, vs the `_base`).
8. **Windows track** per the companion doc (transport cfg-gating, packed param
   structs, MSVC+NASM CI) once the 32-bit-Unix client bridge is proven.
9. **Reverse direction `64c/32b` (deployment-gated, separate track).** Only if a
   32-bit-backend deployment is actually needed: add the **server input** checked
   narrowing at `ffi_conversion.rs:70` (`CK_ULONG::try_from` + reject — review
   #4), then stand up and verify a 32-bit (i686) **server + backend + `ring`**
   build (never compiled; gated by ADR-0006's deferred 32-bit-server track).

---

## Decisions (resolved 2026-06-28)

- **D1 — ADR-0010 carve-out: RATIFIED.** A scoped, representational-fidelity
  exception is permitted for `CK_ULONG`-semantic attribute values on narrow
  clients (required by Rule §2 — without it narrow clients cannot be transparent).
- **D2 — Negotiation: (b).** Server advertises its backend `sizeof(CK_ULONG)`
  **and byte order** (D6) to the client. This requires **adding** optional
  `backend_ulong_size` + `byte_order` fields to `GetBackendInterfacesResponse` —
  they do **not** exist today (the message carries only `interfaces` +
  `mechanism_registry`). The client asserts at probe; against an older daemon
  that omits them it falls back to "8 / little-endian + warning" (D9). No
  client→server width signalling.
- **D3 — Targets (2026-09-13 supersedes 2026-07-02 native-host scope).** Client targets:
  `i686-unknown-linux-gnu` + `armv7-unknown-linux-gnueabihf` +
  `x86_64-pc-windows-msvc`. Daemon hosts: 64-bit Linux (primary),
  **narrow-`CK_ULONG` Linux** (i686-class), only on the qualified GNU/musl
  x86_64/64-bit and x86/32-bit targets. Historical cross-width legs are bridge
  evidence; fresh native owner/stop qualification is required for v0.2.
  **Windows x64 native-provider daemon support is withdrawn/deferred for v0.2**;
  portable and mock-only builds remain. Existing client exclusions remain:
  `pc-windows-gnu`, 32-bit Windows, big-/mixed-endian. Native-host exclusions
  additionally include x32, other architectures/environments and non-Linux.
  [2026-09-17: the Windows-daemon-host deferral is closed by the T6
  real-Windows conformance pass (workspace-root
  `artifacts/v020-tail-windows-2026-09-16/` legs A + C); the Windows-shim
  direction is evidenced by leg B. The client exclusions
  (`pc-windows-gnu`, 32-bit Windows, big-/mixed-endian) and the remaining
  native-host exclusions stand.]
- **D4 — Overflow: checked, value-preserving narrowing.** Convert the integer
  value with a checked `CK_ULONG::try_from`; reject (`CKR_FUNCTION_FAILED`) on a
  genuine `> u32::MAX` value rather than silently truncate. Guarantees `1 → 1`
  and never fabricates a small value from a large one. The reject branch is
  **necessary, not merely defensive**: the spec *permits* wider `CK_ULONG` values
  (the 32-bit limit is only a de-facto convention — see value-range analysis), so
  the bridge must not assume conformance. It should nonetheless never fire for any
  real-world provider.
- **D5 — High-bits / non-conformant values: checked-reject by default; optional
  per-backend lenient mask.** A `CK_ULONG` attribute value with non-zero high
  bits (`> u32::MAX`) is **rejected** (`CKR_FUNCTION_FAILED`) by default,
  honoring "never let a large value masquerade as a small one." An explicit,
  documented per-backend **lenient mode** may instead mask to the low 32 bits
  (per the OASIS convention) for providers known to leave the high word dirty;
  it relaxes the D4 guarantee and is **off by default**.
- **D6 — Endianness guard.** The D2 advertisement also carries backend byte
  order; the client refuses at probe on an LE/BE mismatch rather than silently
  corrupting. All supported targets are LE; this guards a future BE backend.
  (BE since proven at the build+QEMU tier — see [be-qemu-tier.md](../release/be-qemu-tier.md);
  live mixed-endian bridging remains refused by design.)
- **D7 — Vendor / unknown attributes: opaque-bytes by default; operator-declared
  types later.** The proxy cannot infer a `CKA_VENDOR_DEFINED`/unknown
  attribute's value type, so it passes such attributes through as opaque bytes
  (no width bridge) — a documented limitation (a vendor *ulong* attribute is not
  narrowed). Operators MAY later declare per-vendor-attribute value types via the
  **same server-published registry already used for vendor mechanism params**,
  which the bridge would then honor. Registry extension is deferred; bytes-only
  ships first.
- **D8 — Nested-template recursion bound.** `CKA_*_TEMPLATE` reconstruction is
  bounded to a small fixed depth (reject beyond it) to avoid pathological inputs.
- **D9 — Servers without width advertisement (older daemons).** A narrow client
  talking to a daemon that does not advertise its backend width falls back to
  assuming 8 bytes **with a warning** (correct for every supported x86_64 Linux
  server) rather than refusing — graceful degradation.
- **D10 — `CK_UNAVAILABLE_INFORMATION` sentinel: canonicalized on the wire
  (width-independent), implemented 2026-06-29.** The "no information" sentinel is
  all-ones of the *native* `CK_ULONG` width — `0xFFFF_FFFF` on a 32-bit edge,
  `u64::MAX` on a 64-bit edge. Real ulong values cross the wire as native bytes
  interpreted via the D2 width, so a naively widened 32-bit sentinel
  (`0x0000_0000_FFFF_FFFF`) would be read by a 64-bit client as a literal
  ~4-billion value, not "unavailable" (narrowing the other way survives only by
  the accident of truncation). To make the sentinel robust **independently of
  D2** — so it survives even the D9 fallback or a mis-advertising daemon — the
  *length/sentinel* fields are canonicalized at the backend edge to one
  width-independent wire value `CANONICAL_UNAVAILABLE = u64::MAX`
  (`width::canonicalize_ulong`) and mapped back to the destination-width
  all-ones at the client edge (`width::decanonicalize_ulong` /
  `width::narrow_info_field`). Scope: (a) the per-attribute `returned_len`
  "unavailable" marker in the exact `C_GetAttributeValue` path
  (`backend/ffi/mapping.rs`), and (b) the `CK_TOKEN_INFO` session-count and
  memory fields the spec allows to be `CK_UNAVAILABLE_INFORMATION`
  (`token_info_from_ck` → shim `c_get_token_info`). It touches **only**
  length/status and genuine `CK_ULONG` info fields — **never** opaque attribute
  *value* bytes — so it does not weaken the Option-A backend-verbatim principle
  (real values still travel native and are bridged via D2). For info fields with
  **no caller buffer** to reject against (`narrow_info_field`), a genuine value
  exceeding a narrower client's `CK_ULONG` range is **also** reported as
  `CK_UNAVAILABLE_INFORMATION` rather than truncated: D4's hard reject would
  break the must-succeed `C_GetTokenInfo`, and "the value exists but cannot be
  represented for you" is exactly what that sentinel means. The full
  cross-width matrix is unit-tested in `types/src/width.rs`; on same-width
  topologies every transform is a verified no-op.

  **Classification completeness is a correctness prerequisite (not just an
  optimization).** The input path reads a ulong attribute at the client's native
  `CK_ULONG` width *only* when `CkAttributeType::is_ulong()` (or the new
  `is_ulong_array()`) returns true; otherwise it falls back to raw opaque bytes
  (D7). At **same** width raw bytes are byte-identical to the typed read, so a
  missing classifier entry is **invisible** — but cross-width a 32-bit client's
  4-byte value then reaches a 64-bit backend as a malformed 8-byte `CK_ULONG`.
  The classifier is therefore sourced exhaustively from the OASIS attribute-type
  tables and guarded by a consistency test, so the set cannot silently drift.

## Implementation status (2026-07-02)

**Done & committed** (submodule):
- Pure width-translation core (`types/src/width.rs`) with the full cross-width
  unit matrix.
- `CK_UNAVAILABLE_INFORMATION` canonicalization (D10) — attribute `returned_len`
  and `CK_TOKEN_INFO` fields.
- Attribute classifier: `is_ulong()` complete (50 scalar) + `is_ulong_array()`
  (3), OASIS-sourced, pinned by a `cryptoki-sys`-cross-checked consistency test.
- D2/D6 advertisement: `backend_ulong_size` + `backend_byte_order` on
  `GetBackendInterfacesResponse`; backend `host_abi`; server fills; client
  `BackendProbe`; shim probe consumes (D9 fallback / D6 refuse-mismatch).
- Value bridge: shim `width_bridge` wired into `C_GetAttributeValue` output
  (scalar + array) and ulong-array input re-encode in `ck_attrs_to_rust_result`.
  Scalar input is width-independent via the typed `ulong_value`.
- Nested `CK_ATTRIBUTE[]` templates (`CKA_*_TEMPLATE`): each ulong sub-value is
  bridged on output and the template length is reported in the client's
  `CK_ATTRIBUTE` layout (`N * sizeof(client CK_ATTRIBUTE)`, from the wire result
  count) — correct across differing pointer widths, not just `CK_ULONG` widths.
- LLP64 Bucket 2: `#[cfg_attr(windows, repr(packed))]` on the 7 hand-rolled
  `#[repr(C)]` param structs (5 backend + 2 shim).
- Windows **client** shim compiles for `x86_64-pc-windows-msvc` (UDS path
  cfg-gated to Unix; tcp/mTLS-only on Windows); verified via `cargo xwin` and
  gated in CI.
- MockBackend emits ulong attribute values at the **host's native `CK_ULONG`
  width** (the wire contract above), so same-width narrow topologies stay
  bridging-free; an always-8-byte encoding was fixed after the full i686 suite
  flagged it in the nested-template integration tests.
- i686 gate runs the **full** shim lib suite (dispatch units + TestDaemon
  integration modules), the backend lib suite, the types suite, and a client
  ABI compile. An earlier claim that the TestDaemon fixture "hangs on i686"
  was a misdiagnosis: the suite was slow on **every** architecture because
  parallel tests raced on the process-global `PKCS11_PROXY_ENDPOINT` and each
  race victim slept through the full connect backoff (~21 s x queued tests).
  Fixed via `PKCS11_PROXY_CONNECT_ATTEMPTS` (lower-only retry-cap override)
  plus test-guard hygiene; the suite now completes in well under a minute on
  x86_64 and i686 alike.

**Historical implementation record, 2026-07-02 (not v0.2 P0 qualification):**
- **D4 server-input checked narrowing** (`ffi_conversion.rs`): covered wire u64
  materialization into native `CK_ULONG` — attribute values and CK_ULONG
  type-alias casts (mechanism types, attribute types, param-embedded object/
  session handles, kdf/prf/generator/hash enums, ~150 sites) — through
  `narrow_wire_ulong` (checked; `CKR_FUNCTION_FAILED` on overflow, never
  truncation). On the 64-bit backend it is an infallible pass-through.
  Pinned by narrow-host reject tests; the widened i686 CI gate runs them.
  The former claim that this covered every wire u64 was too broad: Wait's
  flag cast and shim slot/RV casts remain unchecked in the inspected source.
  The new checked Wait contract is required implementation, not a preserved
  property of those casts. A wide error must never truncate into CKR_OK;
  caller-width failure is local FUNCTION_FAILED with unchanged output canary
  and the original provider RV retained in the completion observation.
- Windows **server** OS port (Bucket 3): UDS listener + `SO_PEERCRED` are
  `#[cfg(unix)]`; `[listener.local]` is rejected on non-Unix (mTLS TCP only);
  the daemon cross-compiles for `x86_64-pc-windows-msvc` in CI.
- Runtime cross-topology integration, both live-verified against a real
  daemon + SoftHSM2:
  - `scripts/run-cross-width-live-test.sh` — i686 shim (width 4) <-> x86_64
    daemon (width 8), plus a same-width control leg.
  - `scripts/run-llp64-wine-smoke.sh` — Windows shim DLL + smoke .exe under
    wine (LLP64: `CK_ULONG` 4 / pointers 8 / packed structs) <-> Linux
    daemon, loaded through the public C ABI (`LoadLibrary` +
    `C_GetFunctionList`), plus a native dlopen control leg.
    [2026-09-17: retained as a dev-only smoke, never conformance evidence;
    the Windows-shim conformance evidence is T6 leg B on real Windows.]

**Historical D3 execution record (2026-07-02):** narrow-`CK_ULONG` Linux daemon
and Windows daemon bridge runs were recorded below. The Windows native-provider
support claim is superseded for v0.2; these results do not qualify the new P0
native owner/termination contract:
- `scripts/run-cross-width-live-test.sh` now covers all four Linux width
  topologies (32c/64b, 64/64, **64c/32b** via an i686 daemon + i386
  SoftHSM2 — the reverse bridge and server-side D4 narrowing live — and
  32/32), each leg also pinning the D2 width advertisement.
- `scripts/run-windows-daemon-wine-smoke.sh` runs `pkcs11-proxy-ng.exe`
  under wine loading the **Windows SoftHSM2 DLL** (real LLP64 backend,
  width 4): native Linux client (8) exercises the reverse bridge + D4
  through a genuine Windows PKCS#11 DLL, and an all-Windows LLP64
  client/daemon pairing passes as well.
  [2026-09-17: superseded for the daemon host by the T6 real-Windows legs
  (A: SoftHSM2-win; C: BouncyHsm-win) — Wine is no longer the daemon-host
  evidence. The wine smokes stay as dev-only smokes, never evidence.]
- The per-PR i686 CI gate additionally runs the server lib suite and
  builds the i686 daemon.

**Remaining:**
- v0.2 checked Wait input/output/RV, common domain and platform/stop enforcement,
  all four Linux loaded-shim topologies and native GNU/musl stop receipts.
- Windows native-provider daemon support — CLOSED 2026-09-17: restored with a
  separately reviewed whole-process stop (Windows
  `TerminateProcess(GetCurrentProcess(), 70)` arm; Linux `exit_group(70)`
  backstop) plus real-Windows (non-Wine) conformance receipts:
  workspace-root `artifacts/v020-tail-windows-2026-09-16/` leg A (Windows
  daemon + SoftHSM2-win DLL over mTLS, Linux client), leg B (Windows shim
  DLL vs Linux daemon), and leg C (BouncyHsm-win second provider).
