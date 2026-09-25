# Native stop codegen + final-link review (TO26b group 7)

Point-in-time review of the abnormal-stop machine code in the FINAL
LINKED daemon binaries: exact debug/release/MSRV codegen plus the
release GNU/musl variants on x86_64 and i686. Battery item: "Exact
debug/release/MSRV code-generation and final-link review ...
narrowed to the compiled stop stubs/loop/predicate contract, with
receipts recorded".

- Reviewed commit: `f6920ff` (tree clean; every binary verified newer
  than all sources it was built from).
- Review date: 2026-09-19. Reviewer: TO26b battery implementer (single
  review; the ownership doc's independent-review requirement stands
  alongside — see the trailing paragraph).
- Toolchains: stable rustc 1.98.1 (48a229cea 2026-09-01), MSRV rustc
  1.88.0 (6b00bc388 2025-06-23), Alpine rustc 1.91.1 (i686-musl native
  container), GNU objdump 2.46.
- Release profile: thin LTO, `strip = "symbols"`, `codegen-units = 1`
  (workspace `Cargo.toml`).

## Reviewed binaries (sha256)

| Binary | sha256 |
|---|---|
| x86_64 GNU debug daemon | `57546f9a…963cd6a` |
| x86_64 GNU release daemon (ship) | `4fb511ae…9536df53b0` |
| i686 GNU debug daemon | `886e652c…6523d4ca2` |
| i686 GNU release daemon (ship) | `f750e654…06ca84a75e` |
| x86_64 MSRV debug daemon | `eadb3a09…3479a80b2dc` |
| i686 MSRV debug daemon | `3f6b3a61…eacbf043b` |
| x86_64 musl release static daemon | `990fb58b…4bde046e1b` |
| i686 musl release daemon (Alpine 1.91.1) | `c8404b37…2b208aece0` |

(Full hashes in the TO26b report receipts.)

## Contract under review

Source: `crates/backend/src/ffi/native_stop.rs`
(`raw_exit_group_70` per-arch stubs + `abnormal_stop_native_lifetime`
retry loop), contract rows in
`doc/release/native-mechanism-ownership.md`:

- x86_64: `syscall` nr 231, status 70 in RDI, RCX/R11 clobbered,
  `nostack`; models a return (never `noreturn`-folded).
- i686: `int 0x80` nr 252, status 70 via ECX into EBX, balanced
  push/pop (PIC base preserved), models a return.
- No `noreturn`/`pure`/`nomem`/`readonly` asm options, no
  `unreachable_unchecked`, no libc/abort/signal fallback on the stop
  path; the retry loop contains every return (call + jump-back, no
  fallthrough to dependent destruction).

## Source checklist (all targets)

- `options(...)` in `native_stop.rs`: exactly one — `options(nostack)`
  on the x86_64 `syscall` (the i686 arm takes default options; its
  push/pop balance is the contract, verified below).
- `noreturn`, `pure`, `nomem`, `readonly`, `unreachable_unchecked`,
  `libc::`, `abort(`, `raise(`, signal installation: ABSENT from the
  file except two comments (the macOS rationale naming the REJECTED
  `abort()`/SIGABRT alternative, and the anti-fold comment).
- `core::arch::asm!` blocks: exactly 2 (x86_64 + i686).
- Fallback arm (`unimplemented!`): `cfg(not(any(...)))` complement of
  the four qualified arms; unreachable on stop-qualified targets (the
  cfg-partition test pins arm selection per target).

## Per-variant findings

### x86_64 GNU debug + MSRV debug (symbols)

Stub (`arch::raw_exit_group_70`), identical shape on 1.98.1 and 1.88.0:

```text
movq   $0xe7,-0x8(%rsp)   # 231 = exit_group
mov    -0x8(%rsp),%rax
mov    $0x46,%edi         # 70 = status
syscall
mov    %rax,-0x8(%rsp)    # modeled return preserved
mov    -0x8(%rsp),%rax
ret
```

Loop (`abnormal_stop_native_lifetime`): `call stub; mov; jmp call` —
contained, no fallthrough. VERDICT: pass on both toolchains.

### x86_64 GNU release, stripped ship binary (pattern + twin)

- The ship binary contains EXACTLY ONE `syscall` instruction:
  `mov $0xe7,%eax; mov $0x46,%edi; syscall; ret`. No second raw-exit
  site exists to confuse with a fallback.
- Four call sites, each `call stub; jmp call` (contained retry, no
  fallthrough). An unstripped twin (same rustc flags,
  `CARGO_PROFILE_RELEASE_STRIP=none` only) attributes them:
  - `controller_loop` — `native_stop.rs:446` (ShutdownDeadlineExpired);
  - `FfiBackend::finalize` ← inlined sealer — `native_domain.rs:1014`
    (ShutdownDeadlineExpired, drain overrun);
  - `FfiBackend::drop` ×2 — `loading.rs:285` (stop-fire condition)
    and `:319` (quiescence poison), both UnprovenFinalOwner.
- The twin's stub bytes are identical to the ship binary's
  (`b8 e7 00 00 00; bf 46 00 00 00; 0f 05; c3`), so the symbol review
  transfers to the shipped bytes.
- NOTE on counting: the ownership doc names two production caller
  CONTEXTS (final-owner guard, shutdown-deadline machinery); the
  machine code has four SITES because there are four SOURCE sites
  (guard×2, controller×1, sealer×1) — no LTO duplication, no missing
  or extra loop. VERDICT: pass.

### i686 GNU debug + MSRV debug (symbols)

Stub, identical shape on 1.98.1 and 1.88.0:

```text
movl   $0xfc,0x8(%esp)    # 252 = exit_group
mov    0x8(%esp),%eax
mov    $0x46,%ecx         # 70 = status
push   %ebx
mov    %ecx,%ebx
int    $0x80
pop    %ebx               # balanced: PIC base intact
mov    %eax,0x8(%esp)
mov    0x8(%esp),%eax
ret
```

Loop: `call stub; mov; jmp call`, contained. Compiler spills are
`%esp`-relative (no EBX use outside the asm). VERDICT: pass.

### i686 GNU release, stripped ship binary (pattern)

- EXACTLY ONE `int $0x80` in the binary, with the reviewed sequence
  (`mov $0xfc,%eax; mov $0x46,%ecx; push %ebx; mov %ecx,%ebx;
  int $0x80; pop %ebx; …; ret`).
- Four call sites, each `call; jmp call` (same 4-source-site shape as
  x86_64). VERDICT: pass.

### x86_64 musl release, static (pattern)

- The static binary links musl libc in (134 `syscall` sites, mostly
  libc wrappers). The stop stub is identified by the hardcoded pair:
  `mov $0xe7,%eax; mov $0x46,%edi; syscall; ret` at `0x6ad460`.
- musl's OWN exit_group wrapper (at `0x92965b`) also uses nr 231 but
  takes the status from `%edi` (parameterized normal-exit path) — it
  is correctly NOT the stop stub (no hardcoded 70, different site).
- Four call sites to the stop stub, each `call; jmp call`.
- VERDICT: pass — same arm (`any(gnu, musl)`), same bytes.

### i686 musl release, dynamic, Alpine rustc 1.91.1 (pattern)

- EXACTLY ONE `int $0x80` (dynamic binary, libc outside):
  `mov $0xfc,%eax; mov $0x46,%ecx; push %ebx; mov %ecx,%ebx;
  int $0x80; pop %ebx; …; ret`, with a frame-pointer prologue
  (compiler-version codegen choice; EBX still balanced).
- Four call sites, each `call; jmp call`. VERDICT: pass.

## Native execution (same battery item)

STOP-suite execution receipts (same binaries' test targets):

| Variant | Command | Result |
|---|---|---|
| x86_64 GNU | `cargo test -p pkcs11-proxy-ng-backend --lib -- native_stop` | 50 pass |
| i686 GNU (native) | `cargo test --target i686-unknown-linux-gnu … -- native_stop` | 50 pass |
| x86_64 musl (Alpine 3.23) | static test binary, `--test-threads=4 native_stop` | 48 pass, M9 pair N/A |
| i686 musl (linux/386 Alpine, rustc 1.91.1) | native `cargo test … -- native_stop` | 48 pass, M9 pair N/A |

The M9 `on_exit` pair is `cfg(all(linux, gnu))` — glibc-only "where
available" per the battery; musl has no `on_exit(3)`. Handler
suppression on musl is covered by the M3 `atexit` pair (green).
Full backend suites on the same runners: 641/643/639/641 green
respectively (deltas are exactly the M9 pair).

## Verdict

PASS on all eight codegen/final-link variants and all four native
execution variants. The shipped release bytes contain exactly one raw
stop site per arch with the contracted registers, and every retry loop
is contained with no fallthrough. Out of scope (unchanged, still
excluded): Windows/macOS arms (cross, not natively executed here),
non-x86 Linux (fallback arm, compile-only).

## Addendum: T10 re-verification (2026-09-22)

The stop-path sources changed after `f6920ff` (aarch64 arm row 5 in
`b19ca20`, the W1-C4-08 const-qualification refactor, and T10's
`begin_finalize` → `begin_finalize_with_deadline` split plus a
caller-census doc fix), so the point-in-time review above went stale
on the source checklist (2 → 3 `asm!` blocks, 4 → 5 qualified arms)
and on call-site line numbers. T10 re-verified the locally-runnable
subset on the T10 tree (this commit) with the SAME toolchain as the
original review (stable rustc 1.98.1 `48a229cea`, GNU objdump 2.46),
so the bytes below are directly comparable.

Source checklist (current `native_stop.rs`):

- `core::arch::asm!` blocks: exactly 3 (x86_64 + i686 + aarch64;
  the +1 is the `b19ca20` arm, pre-T10).
- `options(nostack)`: x86_64 and aarch64 stubs only; the i686 arm
  keeps default options with the push/pop balance contract.
- `noreturn`, `pure`, `nomem`, `readonly`,
  `unreachable_unchecked`, `libc::`, `abort(`, `raise(`: ABSENT
  except the same two reviewed comments (macOS rationale, anti-fold
  note).
- Fallback arm: `cfg(not(any(...)))` complement of the five
  qualified arms; the cfg-partition test pins arm selection.
- Production `abnormal_stop_native_lifetime` call sites: still
  exactly 4 (guard×2 in `loading.rs`, controller×1 in
  `native_stop.rs`, sealer×1 now in
  `LifecycleDomain::begin_finalize_with_deadline`). The x86_64 stub
  body is byte-identical to `f6920ff` (md5 `e09341cb…` both).
- T10's own stop-path delta is codegen-neutral: a doc comment in
  `native_stop.rs`, six `#[cfg(test)]` →
  `#[cfg(any(test, feature = "native-owner-test-hooks"))]`
  widenings across three files (3 in `loading.rs`, 2 in
  `native_domain.rs`, 1 in `ffi.rs`; test-only helpers), three new
  hooks-gated helpers (2 test constructors + the `stop_qualified_target`
  predicate read, all cfg'd out of default builds), and the
  `begin_finalize` wrapper split in `native_domain.rs` (the arm-1
  suicide call itself is unchanged, line moved).

x86_64 GNU debug daemon (symbols): stub
`movq $0xe7,-0x8(%rsp); mov -0x8(%rsp),%rax; mov $0x46,%edi;
syscall; mov %rax,…; ret` — identical shape to the reviewed bytes;
loop `call stub; mov; jmp call`, contained. VERDICT: pass.

x86_64 GNU release, stripped ship binary (pattern + twin): EXACTLY
ONE `syscall` (`b8 e7 00 00 00; bf 46 00 00 00; 0f 05`); four call
sites, each `call; jmp call`. The unstripped twin (same flags,
`CARGO_PROFILE_RELEASE_STRIP=none` only) has identical stub bytes
and attributes the sites: `controller_loop`,
`LifecycleDomain::begin_finalize_with_deadline` (T10 rename of the
reviewed `begin_finalize` sealer), `FfiBackend::drop` ×2 — four
machine sites for four source sites, no LTO duplication, none
missing. VERDICT: pass.

i686 GNU release, stripped ship binary (pattern): EXACTLY ONE
`int $0x80` with the reviewed sequence
(`mov $0xfc,%eax; mov $0x46,%ecx; push %ebx; mov %ecx,%ebx;
int $0x80; pop %ebx`) — plus a `sub $0xc,%esp` function-entry
prologue (compiler-version codegen choice; EBX still balanced, so
callers target the entry one instruction above the reviewed bytes).
Four call sites, each `call; jmp call`, contained. VERDICT: pass.

aarch64 Linux (NEW — the arm postdates the original review):
`cargo check -p pkcs11-proxy-ng-backend --tests --target
aarch64-unknown-linux-gnu` passes (in-tree const pins:
`NATIVE_FFI_QUALIFIED`, `NATIVE_STOP_QUALIFIED`, arm name), and the
cross-built backend rlib disassembles (llvm-objdump) to exactly ONE
`svc #0` in the whole archive with the contracted registers
(`mov w8,#70` → X0 status, `mov w8,#94` → X8 nr, `svc #0`,
modeled X0 return preserved) plus a contained `bl; stur; b` retry
loop (the `bl` target is an unrelocated placeholder, as expected in
an unlinked object). Native execution still impossible on x86_64
hosts. VERDICT: pass (object-level; link + exec remain out of
scope).

Native execution (current tree):

| Variant | Command | Result |
|---|---|---|
| x86_64 GNU | `cargo test -p pkcs11-proxy-ng-backend --lib -- native_stop` | 52 pass |
| i686 GNU (native exec on x86_64 host) | `cargo test --target i686-unknown-linux-gnu … -- native_stop` | 52 pass |

The 50 → 52 growth since September is two stop-qualification pin
tests landed pre-T10 (W1-C4-08 era). VERDICT: pass.

Still out of scope (unchanged): MSRV 1.88 codegen, musl variants,
Windows/macOS arms, aarch64 link + native execution.

Addendum verdict: PASS. The T10 tree's stop machine code upholds
every reviewed contract row; the sealer rename is the only
symbol-level change and the twin attributes it.
