# 32/64-bit Cross-Platform Compatibility Strategy

**Document:** ADR-0006  
**Status:** Accepted — 32-bit / mixed-arch **deferred** for public `v0.1.0`; v0.2 scope amended below

**Date:** 2026-03-29 (decision recorded 2026-06-04)

---

## Decision (scope for the beta)

The public `v0.1.0` beta supports **Linux `x86_64` only**. 32-bit and mixed
32/64-bit deployments are **deferred**: they are not supported and not a beta
claim (see [beta support matrix](../release/beta-support-matrix.md)).

The analysis below — in particular the `CK_UNAVAILABLE_INFORMATION` /
platform-sized-sentinel issue — is retained because it documents *why* mixed
architecture is deferred and what a future 32-bit track must handle. It is not a
present-scope commitment.

Note on handles: session and object handles are **virtualized per logical client
instance** by the daemon (see
[ADR-0002](./ADR-0002-handle-session-identity-model.md)); backend handle values
are not exposed to clients. Handle-width concerns therefore live at the
daemon↔backend boundary, not on the wire to the client.

---

## Amendment (2026-06-29): narrow-`CK_ULONG` bridging & the three ABIs → see ADR-0011

**v0.2 superseding amendment (2026-09-13; implementation/qualification pending):**
Production live FFI is limited to qualified Linux GNU/musl x86_64/64-bit and
x86/32-bit (i686). This supersedes the Windows native-provider daemon support
intent below and in ADR-0011 for v0.2. Windows native loading is deferred,
lower priority/stretch work. Portable Windows client/shim/proto/types,
mock-only backend/server builds and Windows-client/Linux-daemon interoperation
remain under their existing contracts. Nonqualified hosts must refuse FFI
construction before loading/discovery; retain Windows compile CI and add that
refusal coverage. No unsafe fallback is selected. See the exact platform,
native-width/slot-event and evidence rules in the
[native ownership contract](../release/native-mechanism-ownership.md).
The ABI analysis below does not itself qualify any v0.2 native runtime.

[Tail-stretch closure, 2026-09-17: the Windows-native-loading deferral in
this amendment — and the "Deferred for v0.2" Windows x64/LLP64
native-provider-server row in the support-intent table below — is closed:
[ADR-0014](./ADR-0014-v020-tail-platform-stretch.md) is Implemented, with
real-Windows daemon-host receipts in workspace-root
`artifacts/v020-tail-windows-2026-09-16/` legs A and C, and shim-direction
receipts in leg B. The amendment text and bridge analysis are retained as
history.]

This ADR's original analysis modelled two ABIs on a single axis (LP64 vs ILP32,
where pointer width and `CK_ULONG` width move *together*). That is incomplete:
**Windows x64 is LLP64** — `CK_ULONG` is 32-bit while pointers are 64-bit and
structs are `pack(1)` — so **`CK_ULONG` width is independent of pointer width**.

[ADR-0011](./ADR-0011-narrow-ck-ulong-client-width-bridging.md) supersedes the
"NOT SUPPORTED" rows of the matrix below for the **bridged** cases. Key results:

- The gRPC wire is width-agnostic (`u64`); the only properties that cross the
  wire are each edge's **`CK_ULONG` width + byte order**. **Pointer width and
  struct packing are purely local** to each edge (handled by `cryptoki-sys`
  per-target bindings), so they never reach the wire.
- A width bridge translates `CK_ULONG`-semantic *attribute values* (the only
  outputs carried as raw native-width bytes) to the destination width — **both
  directions** — with checked narrowing and explicit sentinel handling. The
  narrowing/reject edge moves with direction (client-output for a narrow client;
  server-*input* for a narrow backend). Handles remain virtualised (per ADR-0002).
- Three ABIs (LP64 / ILP32 / **LLP64**) may appear on **either** edge; one bridge
  covers all combinations. A 32-bit-`CK_ULONG` **server** is therefore possible —
  notably a **Windows x64 (LLP64) server** proxying a Windows-only PKCS#11 `.dll`.

**Updated support intent** (still beta-gated on the standard x86_64 Linux build):

| Topology | Status |
|---|---|
| 64-bit client ↔ 64-bit Linux server/backend | Supported (beta) |
| **32-bit-`CK_ULONG` client** (i686, armv7, Windows x64) ↔ 64-bit server | **Designed (ADR-0011); the narrow-client shipping track** |
| 64-bit client ↔ **32-bit-`CK_ULONG` Linux server/backend** (i686) | v0.2 qualification target; complete native owner/stop receipts required |
| Client ↔ **Windows x64/LLP64 native-provider server** | Deferred for v0.2 by the 2026-09-13 amendment; historical bridge/port analysis retained |
| mixed / big-endian | Out of scope — detected & refused at probe (D6) |

The `CK_UNAVAILABLE_INFORMATION` sentinel analysis below remains the reference for
*why* widths matter; ADR-0011 specifies the bidirectional handling (narrow = free
truncation; widen = explicit all-ones mapping).

---

## Context

The pkcs11-proxy-ng project implements PKCS#11 remote proxying over gRPC. PKCS#11 uses platform-dependent types:

- `CK_ULONG` = `unsigned long` (32-bit on 32-bit systems, 64-bit on 64-bit systems)
- `CK_SESSION_HANDLE`, `CK_OBJECT_HANDLE` = `CK_ULONG`
- `CK_SLOT_ID` = `CK_ULONG`

This creates potential compatibility issues when:
- 32-bit client connects to 64-bit server
- 64-bit server returns handles > 0xFFFFFFFF
- Cross-platform deployments with mixed architectures

---

## Current Architecture Assessment

### Shared target-layout facts

Target-memory layout facts live in the rev-pinned upstream `pkcs11-abi`
crate (consumed from `pkcs11-components` via `crates/backend/Cargo.toml`),
not in this repository. Its default `native` feature provides
compiler-derived offsets from the `cryptoki-sys` bindings; with default
features disabled it is `no_std` and dependency-free and exposes
allocation-free facts for conventional little-endian Linux LP64 and ILP32
function lists and `CK_INTERFACE` entries. One ordered 104-name catalog
generates both the native offset tables and pure name/ordinal lookup, and the
shared version/provenance selector feeds the native `tables_for` adapter, so
the layout facts do not change which legacy or standard-interface versions
may be walked. This is a layout primitive for consumers that read another
process. It does not itself identify a process ABI, authorize a provider
interface, read process memory, or establish 32-bit runtime support.

### ✅ Strengths

1. **Wire Protocol Uses u64 Exclusively**
   - All protobuf definitions use `uint64` for CK_ULONG-derived types
   - ~200+ CK_ fields are uint64, 0 are int64
   - No signed/unsigned confusion in protobuf

2. **Rust Internal Types**
   - All CK_ types defined as `u64` regardless of platform:
   ```rust
   pub struct CkSessionHandle(pub u64);
   pub struct CkObjectHandle(pub u64);
   pub struct CkSlotId(pub u64);
   ```

3. **Explicit FFI Boundaries**
   - Platform-sized types (`CK_ULONG`) handled explicitly at C boundaries
   - Uses `as CK_ULONG` casts with platform-aware behavior
   - ABI audit tests verify truncation detection

### ⚠️ CRITICAL: CK_UNAVAILABLE_INFORMATION Mismatch

**Discovery:** `CK_UNAVAILABLE_INFORMATION` is defined as `(~0UL)` — platform-sized:
- **32-bit:** `0xFFFFFFFF` (32 bits all set)
- **64-bit:** `0xFFFFFFFFFFFFFFFF` (64 bits all set)

**This breaks mixed 32/64-bit deployments:**

**Scenario 1: 32-bit Client → 64-bit Server (Attribute Read)**
```
64-bit Backend: Sets ulValueLen = 0xFFFFFFFFFFFFFFFF (CK_UNAVAILABLE_INFORMATION)
Server (64-bit): Sends 0xFFFFFFFFFFFFFFFF via protobuf
Wire: uint64 = 0xFFFFFFFFFFFFFFFF
32-bit Shim: Receives u64::MAX, converts to CK_ULONG
  -> 0xFFFFFFFFFFFFFFFF as CK_ULONG (32-bit) = 0xFFFFFFFF
Client: Compares with CK_UNAVAILABLE_INFORMATION (0xFFFFFFFF) ✓ WORKS
```
**Result:** Accidentally works due to truncation!

**Scenario 2: 64-bit Client → 32-bit Server (Attribute Read)**
```
32-bit Backend: Sets ulValueLen = 0xFFFFFFFF (CK_UNAVAILABLE_INFORMATION)
Server (32-bit): Sends 0xFFFFFFFF via protobuf
Wire: uint64 = 0x00000000FFFFFFFF
64-bit Shim: Receives 0x00000000FFFFFFFF
Client: Compares with CK_UNAVAILABLE_INFORMATION (0xFFFFFFFFFFFFFFFF) ✗ FAILS
```
**Result:** Client fails to recognize CK_UNAVAILABLE_INFORMATION!

**Code Location:** 
- `crates/backend/src/ffi/mapping.rs:70` — compares `src.ulValueLen == cryptoki_sys::CK_UNAVAILABLE_INFORMATION`
- This comparison is platform-dependent
- Test at `crates/proto/src/convert/attribute.rs:81-89` assumes `u64::MAX` (64-bit value)

**Impact:** Attribute reads fail to detect sensitive/invalid attributes when 64-bit client talks to 32-bit backend.

### ⚠️ Handle Truncation on 32-bit Systems
- If 64-bit backend assigns handle > 0xFFFFFFFF
- 32-bit client will truncate via `handle.0 as CK_SESSION_HANDLE`
- Results in handle corruption and session/object loss

2. **No 32-bit CI Testing**
   - Current CI only tests x86_64
   - No cross-compilation to i686, armv7, or other 32-bit targets
   - No mixed-architecture integration tests

3. **Handle Range Assumptions**
   - Some backends (especially HSMs) may use full 64-bit handle space
   - SoftHSM2 uses sequential integers starting at 1 (32-bit safe)
   - Vendor HSMs may use random 64-bit values (not 32-bit safe)

---

## Compatibility Matrix

### Supported Scenarios (Phase 1 & 2)

| Client | Server | Backend | Status | Notes |
|--------|--------|---------|--------|-------|
| 64-bit | 64-bit | 64-bit | ✅ **FULL** | Native deployment — **RECOMMENDED** |
| 64-bit | 64-bit | 32-bit | ✅ **FULL** | Server handles 32→64 conversion |
| 32-bit | 32-bit | 32-bit | ⚠️ **SUPPORTED** | Homogeneous 32-bit — requires CI testing |
| 32-bit | 64-bit | 64-bit | ❌ **NOT SUPPORTED** | CK_UNAVAILABLE_INFORMATION mismatch |
| 32-bit | 64-bit | 32-bit | ❌ **NOT SUPPORTED** | CK_UNAVAILABLE_INFORMATION mismatch |
| 64-bit | 32-bit | Any | ❌ **NOT SUPPORTED** | Server would need truncation logic |

**Key:** Only homogeneous architectures (all 64-bit or all 32-bit) are supported in Phase 1/2.

### Risk by Handle Type

| Handle Type | Assigned By | 32-bit Safe? | Mitigation |
|-------------|-------------|--------------|------------|
| Virtual Slot ID | Shim | ✅ Yes | Sequential, configurable |
| Session Handle | Backend | ⚠️ Depends | Range check in shim (homogeneous only) |
| Object Handle | Backend | ⚠️ Depends | Range check in shim (homogeneous only) |
| Mechanism Type | Constants | ✅ Yes | Always use u64 |

**Note:** CK_UNAVAILABLE_INFORMATION values differ between 32-bit (0xFFFFFFFF) and 64-bit (0xFFFFFFFFFFFFFFFF), causing attribute read failures in mixed deployments.

---

## Recommendations

### CRITICAL Decision: Postpone Mixed 32/64-bit Support

**Decision:** For Phase 1 and Phase 2, **do NOT support mixed 32/64-bit client/server deployments**.

**Rationale:**
1. **CK_UNAVAILABLE_INFORMATION mismatch** — Fundamental incompatibility in PKCS#11 spec
2. **No current demand** — All pilot customers use 64-bit everywhere
3. **Complexity vs benefit** — Would require protocol changes or translation layer
4. **Workaround exists** — Deploy same architecture on both sides

**Supported Configurations:**
- ✅ 64-bit Client → 64-bit Server → 64-bit Backend (FULL SUPPORT)
- ✅ 32-bit Client → 32-bit Server → 32-bit Backend (SUPPORTED with testing)
- ❌ Mixed 32/64-bit Client/Server (NOT SUPPORTED in Phase 1/2)

**Future:** Revisit in Phase 3 if customer demand arises with business justification.

---

### HIGH Priority (Phase 2)

#### 1. Add 32-bit CI Target (32-bit everywhere support)

**Action:** Add i686 target to CI matrix for 32-bit homogeneous deployments

```yaml
# .github/workflows/ci.yml
strategy:
  matrix:
    include:
      - target: x86_64-unknown-linux-gnu
        os: ubuntu-24.04
      - target: i686-unknown-linux-gnu  # NEW
        os: ubuntu-24.04
      
steps:
  - name: Install 32-bit toolchain
    run: |
      rustup target add i686-unknown-linux-gnu
      sudo apt-get install gcc-multilib
      
  - name: Build (32-bit)
    run: cargo build --target i686-unknown-linux-gnu
    
  - name: Test (32-bit unit tests only)
    run: cargo test --lib --target i686-unknown-linux-gnu
```

**Rationale:** Ensure code compiles and unit tests pass on 32-bit. FFI tests may require 32-bit SoftHSM2.

#### 2. Add Handle Range Validation

**Action:** Add debug assertions in shim

```rust
// In shim dispatch code
debug_assert!(
    handle.0 <= u32::MAX as u64 || cfg!(target_pointer_width = "64"),
    "Backend returned 64-bit handle (0x{:016X}) to 32-bit client. \
     This will truncate and cause handle corruption. \
     Consider using 64-bit client or backend that assigns 32-bit handles.",
    handle.0
);
```

**Location:** `crates/shim/src/dispatch/general/helpers/mod.rs`  
**Impact:** Developer experience — clear error message when truncation would occur

#### 3. Document Handle Range Requirements

**Action:** Add ADR-0006 documenting this strategy

```markdown
## Decision: Mixed Architecture Support

**Status:** Phase 1 supports 64-bit everywhere with 32-bit client limitations.

**32-bit Client Constraints:**
- Backend handles MUST stay within 0..0xFFFFFFFF range
- SoftHSM2 satisfies this (sequential from 1)
- Vendor HSMs may not (random 64-bit allocation)

**Future:** Phase 2 may add full 32-bit server support if demand exists.
```

### MEDIUM Priority (Phase 2)

#### 4. Add Cross-Platform Integration Tests

**Action:** Test 32-bit client → 64-bit server workflow

```rust
#[test]
#[ignore = "requires 32-bit build"]
fn cross_platform_handle_roundtrip() {
    // Start 64-bit server with SoftHSM2
    // Use 32-bit shim to connect
    // Verify handles round-trip correctly
}
```

**Setup:** Docker-based test with multi-arch support

#### 5. Virtual Handle Management

**Action:** Ensure shim-assigned virtual handles fit in 32 bits

**Current:** Virtual slot IDs assigned by shim are sequential  
**Verify:** Counter wraps or stays below u32::MAX

### LOW Priority (Future)

#### 6. Consider 32-bit Server Support

**Action:** Only if customer demand exists

**Impact:** Would require:
- Truncation logic in server
- Handle mapping tables
- Increased complexity

**Recommendation:** Defer until business case proven

---

## Implementation Plan

### Phase 1 Completion (Immediate)

- [x] 32/64-bit compatibility analysis — **DONE**
- [ ] Add ADR-0006 documentation — **TODO**
- [ ] Add 32-bit CI target — **TODO**
- [ ] Add handle range assertions — **TODO**
- [ ] Document in deployment guide — **TODO**

### Phase 2 (If Required)

- [ ] Full 32-bit server support
- [ ] Cross-platform integration test matrix
- [ ] Vendor HSM handle range testing
- [ ] Performance comparison 32 vs 64 bit

---

## Test Strategy

### Unit Tests (Platform Independent)

```rust
#[test]
fn u64_roundtrip_preserves_value() {
    let original: u64 = 0xDEADBEEFCAFEBABE;
    let proto = original as u64;  // proto is always u64
    let back = proto as u64;
    assert_eq!(original, back);
}
```

### FFI Tests (Platform Dependent)

```rust
#[test]
#[cfg(target_pointer_width = "32")]
fn handle_truncation_on_32bit() {
    let large: u64 = 0x1_0000_0000;  // 33rd bit set
    let truncated = large as CK_SESSION_HANDLE;
    assert_eq!(truncated, 0);  // Upper bits lost
}
```

### Integration Tests (Cross-Platform)

```rust
#[tokio::test]
#[ignore = "requires multi-arch setup"]
async fn cross_platform_session_lifecycle() {
    // 64-bit server
    // 32-bit client shim
    // Verify: open_session, operations, close_session work
}
```

---

## Conclusion

The pkcs11-proxy-ng project has a **sound architecture** for 32/64-bit compatibility:

- ✅ Wire protocol uses u64 exclusively (no sign issues)
- ✅ Rust internal types are u64 (consistent)
- ✅ FFI boundaries handle platform-sized types explicitly
- ✅ SoftHSM2 (main test backend) uses 32-bit safe handles

**Primary Risk:** Vendor HSMs assigning 64-bit handles > 0xFFFFFFFF will cause truncation on 32-bit clients.

**Mitigation:** 
1. Document the limitation
2. Add CI testing for 32-bit compilation
3. Add runtime assertions in debug builds
4. Monitor for customer demand for full 32-bit support

**Recommendation:** Proceed with Phase 1 release. Mixed 32/64-bit deployments are supported with documented constraints.
