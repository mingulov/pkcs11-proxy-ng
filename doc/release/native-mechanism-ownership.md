# Native Ownership and v0.2 FFI Contract

**Status (2026-09-13): selected contract; implementation and qualification
pending.** This amendment specifies the v0.2 native-owner correction. It does
not describe completed production enforcement or establish provider parity.
Independent contract review, the complete owner migration, native receipts and
independent implementation review remain release gates. Historical width-bridge
and provider tests do not qualify this new lifetime/termination contract.

## Supported deployment boundary

Production live FFI for v0.2 is limited to qualified targets satisfying all of:

- `target_os = "linux"`;
- `target_env = "gnu"` or `"musl"`; and
- `target_arch = "x86_64"` with `target_pointer_width = "64"`, or
  `target_arch = "x86"` with `target_pointer_width = "32"` (i686).

These are qualification targets until the native evidence below exists. x32,
other architectures/environments and non-Linux native loading are excluded.
This explicitly supersedes Windows native-provider daemon support in
[ADR-0011](../adr/ADR-0011-narrow-ck-ulong-client-width-bridging.md) and
[ADR-0006](../adr/ADR-0006-32-64-bit-cross-platform-compatibility.md) for v0.2.
Windows native-provider daemon work is re-admitted as committed v0.2.0 tail
stretch (low priority, before the comprehensive matrix gate) per
[ADR-0014](../adr/ADR-0014-v020-tail-platform-stretch.md); until that tail
work lands, the constructor refusal below stays in force.
macOS native-provider daemon work is likewise in progress: the code
load-qualifies macOS on aarch64/x86_64 with 64-bit pointers (the macOS
leg of `NATIVE_FFI_QUALIFIED`) and implements the macOS stop arm below,
but macOS is NOT runtime-qualified — the macOS-leg compile proof and
any live stop receipt ride the cross-platform CI macOS leg (T2run; see
the pending proof in the macOS stop section). Until that proof lands,
macOS load/stop behavior is code-complete but unqualified.

Portable Windows client/shim/proto/types builds and their existing contracts
remain; a Windows client may interoperate with a qualified Linux daemon.
Portable backend trait/mock and mock-only server builds remain available.
Nonqualified-host FfiBackend construction must return a local platform-support
error before loading, discovery or provider entry. Retain meaningful Windows
compile CI and add constructor-refusal/no-loader-attempt coverage. Do not
globally gate portable crates, remove all Windows CI, or introduce an unsafe
legacy-FFI feature or portable abort fallback. Platform enforcement is part of
the pending implementation, not supplied by this document.

## One provider chain per embedding process

The supported host supplies exactly one linked backend runtime instance and
grants it exclusive lifecycle/native access to one project-managed provider
chain: the selected module and all providers/dependencies it aggregates.
Every public FfiBackend constructor uses the same private reservation authority.
An independent second load fails locally even for a different module path.
Share the first backend through `Arc`; multiple logical clients and sessions
use that same native domain, lifecycle gate, waiter reservation and epoch.

Another linked backend runtime copy/version in a DSO, unmanaged provider calls,
or another aggregator sharing a downstream provider is outside this safety
contract. The runtime registry cannot detect or enforce those exclusions.
A second loader handle, alternate pathname, `RTLD_LOCAL` or separate Rust value
does not create a separate provider instance. Use separate processes for
independent chains. Direct embedders must also accept the whole-process stop
below, including its effect on unrelated application threads.

### Constructor reservation and retirement

Use a private short-held registry with metadata only, no owning `Arc`:
`Vacant(next_epoch)`, `Reserved(epoch)`, `Active(epoch)`, `Retiring(epoch)`,
`Poisoned(epoch)`. Registry state and the module lifecycle state below are
different authorities: occupancy prevents independent construction; it is not
a proof of native quiescence. Epoch allocation is checked and monotonic;
exhaustion rejects construction rather than wrapping or reusing an identity.
The registry epoch identifies a load reservation and is immutable until unload.
Within that reservation a separate checked lifecycle generation identifies each
initialization. Worker/wait/proof identities carry both; neither counter wraps.
Reinitialization advances the lifecycle generation only after complete old
generation settlement, without releasing the load reservation or permitting
another constructor. A new load after unload receives a new registry epoch.

1. Validate platform/configuration locally, then reserve `Vacant -> Reserved`
   before `Library::new`/`dlopen`, discovery, callbacks or initialization.
   Competing constructors in every occupied state return a documented local
   construction error through the constructor's `Result`, with zero loader or
   provider attempts. They do not fabricate a provider `CK_RV`.
2. Release the registry mutex immediately. Never hold it across loading,
   discovery, native calls, waits, callbacks, retirement or unload. Preallocate
   the domain shell/guard and constructor bookkeeping before exposing project
   storage to native code. Transfer the reservation into that actual common
   domain; it cannot reside only on an earlier-dropping public wrapper.
3. Publish `Active(epoch)` when construction hands out the managed backend.
   Every wrapper, native/control worker, retained frame and shutdown controller
   holds the same domain/epoch or a proven enclosing lifetime. No ownership
   cycle may keep a domain alive merely to evade final Drop.
4. A pre-native failure may roll back its reservation. Once loading/discovery
   has started, rollback requires the supported synchronous loading/discovery
   contract to establish no unresolved native user, safe dependent retirement
   and completed normal library close. An error RV or absence of Initialize
   alone does not prove constructor-created background activity has ended.
5. Invalidate the private destruction proof before initialization or any
   possible native retention attempt. Failed/unknown initialization, unwind
   after possible retention, failed Finalize or unknown unload completion never
   recycles the reservation. Retain ownership; if controlled termination cannot
   establish quiescence, use the selected abnormal stop. Reservation Drop must
   not invent Finalize, unload the library or free live native storage.
6. Handle mutex poison or inconsistent registry metadata without `unwrap`,
   replacement or treating it as Vacant: deny new loads until restart. A live
   domain remains owned and its stop/predicate needs no registry lock. Proven
   quiescent teardown may retire storage despite bookkeeping failure, but must
   leave future loading disabled.
7. After successful explicit Finalize and full settlement, remain occupied as
   `Retiring(epoch)` throughout dependent retirement and library close. Only
   the exact epoch owner may publish the next Vacant epoch after completed
   normal unload. Old library destructors, late workers and controllers cannot
   overlap a new load. Safe never-initialized rollback obeys the same retirement
   rule. Stale release or failed retirement cannot publish a reusable slot.

## Module lifecycle and native storage

The private module states are `LoadedUninitialized`, `Initializing`, `Open`,
`Draining`, `Finalizing`, `Finalized` and `Uncertain`. Initialize is exclusive;
only Open admits ordinary work. Admission checks the module state/epoch under
the same short authority that seals it. Every admitted ordinary invocation
holds lifecycle read exclusion through actual native return, validation and
settlement; session calls also hold their generation-qualified session guard.
Finalize seals admission, drains ordinary workers, then uses exclusive native
access. Its own native call runs in a tracked worker.

Retain all project-owned native graphs, actual nested/attribute buffers,
input/output cells, library and control contexts through their termination
receipts. A pointer may not be retained to a local stack cell. Park complete
frames before native entry and publish successful Init ownership infallibly
before fallible readback. Snapshot under the same guard into owned output;
snapshotting does not retire or reborrow a retained native root. Wiping/freeing
requires proof that native retention ended.

The five existing retained classic families (Encrypt, Decrypt, Digest, Sign,
Verify) keep separate owners. Dual operations retain both. Message, recovery,
VerifySignature and one-shot migration does not claim new arbitrary post-Init
retention support. A `CKR_PENDING` result, unknown entry or unwind after entry
keeps the complete frame and affected owners; zero running counters or empty
maps are insufficient. Native AsyncComplete support remains unimplemented;
see [the async decision](../adr/async-persistence-decision.md).

Normal teardown issues a private epoch-qualified destruction proof only for a
safe never-initialized/unentered loading state under the loading contract, or
successful native Finalize plus actual settlement of every ordinary/control
worker and terminal memory-retention receipts for every frame/graph. Pending,
poisoned, failed-Finalize, stale-generation and returned-but-unsettled states
cannot satisfy it. New native exposure invalidates it first. Reinitialize only
after successful old-epoch Finalize and all old work, observations, controls
and roots settle, using a new checked lifecycle generation; never reinitialize
automatically after timeout, failed Finalize or uncertainty. Registry occupancy remains held
while the same loaded chain is reused; only completed unload frees that slot.

Explicit shutdown performs native cleanup. Final-domain Drop checks its private
proof before any dependent field can drop, without allocation, panic or waiting
on registry/lifecycle/session locks. A false predicate invokes the abnormal
stop. No initialized-but-idle shortcut, reusable public proof, implicit native
cleanup in Drop, second Finalize, leak or `mem::forget` is a substitute.
Safe ordinary pre-entry failures retain normal wiping/unwinding behavior.
Memory retirement is not proof of deletion of a persistent token object.

## Slot-event scope, precedence and output

v0.2 supports `C_WaitForSlotEvent` only with `CKF_DONT_BLOCK` set. Blocking
mode returns local `CKR_FUNCTION_NOT_SUPPORTED` before native entry, with no
caller output. Retain the exported ABI/function-list entry. This is a deliberate
capability limit relative to providers supporting blocking waits. No repeated
polling, automatic retry, rewritten flags or blocking facade is selected.

Logical clients share the one native application's per-slot pending-event
flags. A successful wait consumes a native pending flag; clients compete for
that source. Logical Initialize does not create or clear a fresh independent
per-client bitmap. There is no lossless event queue, chronological ordering or
one-delivery-per-physical-event promise. This shared-source limit remains even
for nonblocking calls and prevents full native per-application event equivalence.
Logical Finalize removes that client's context and arranges session cleanup;
it is not native module Finalize or a blocking-wait cancellation mechanism.

The following ordering is mandatory. Existing transport authentication,
authenticated ownership, quota and logical-context checks remain ahead of
backend capability results; they cannot be bypassed to reveal module state.

| Boundary / ordered check | Result; provider attempts |
| --- | --- |
| Shim `pSlot == NULL` or `pReserved != NULL` | Local `CKR_ARGUMENTS_BAD`, even before shim initialization; no RPC/native entry. |
| Valid pointer classes, uninitialized shim | Local `CKR_CRYPTOKI_NOT_INITIALIZED`; no RPC. |
| Absent server logical context | `CKR_CRYPTOKI_NOT_INITIALIZED`; no backend entry. Wrong authenticated owner retains its existing transport rejection. |
| Module LoadedUninitialized, Initializing, Draining, Finalizing or Finalized | Local `CKR_CRYPTOKI_NOT_INITIALIZED`; zero native attempts. |
| Module Uncertain | Local `CKR_DEVICE_ERROR`; zero native attempts. |
| Open, flags do not fit native `CK_FLAGS` | Checked `narrow_wire_ulong` failure: local `CKR_FUNCTION_FAILED`; zero native attempts. |
| Open, representable flags, DONT_BLOCK clear | Local `CKR_FUNCTION_NOT_SUPPORTED`, even if a supported waiter is busy; zero native attempts. |
| Open, representable DONT_BLOCK, waiter already reserved | Local `CKR_FUNCTION_FAILED`; zero native attempts. |
| Open, representable DONT_BLOCK, sole reservation acquired | One native invocation preserving every original flag bit, or existing missing-function refusal with no native entry. |

Thus lifecycle precedes width, width precedes mode, and mode precedes contention.
On an Open i686 backend `2^32` and `2^32 | CKF_DONT_BLOCK` fail narrowing;
`0` is unsupported. Sealed state refuses either before narrowing; busy state
does not override narrowing. A representable unknown flag bit is forwarded
unchanged with DONT_BLOCK, leaving the provider to determine its result.
The service must enforce the same mode boundary for older clients and custom
backends; direct FfiBackend calls also use the native-width check. Service
admission and the FFI check must preserve this ordering, not introduce an early
service mode refusal that masks native-width or module-state errors.

One domain-owned waiter record holds a checked wait ID/epoch, original flags,
preallocated native output cell, module ownership and completion observation.
Its states are Reserved, NativeCallCommitted, Returned and Settled. Acquire
ordinary lifecycle access before reservation and retain it through settlement,
including after RPC cancellation/timeout. Hold the sole waiter reservation
until settlement too. A short record mutex is never held while waiting for a
native call or lifecycle drain.

Admission and seal have one linearization point. If seal wins before admission,
refuse with zero native entry. If admission wins, even a worker preempted just
before C keeps ordinary exclusion through actual completion; Finalize cannot
overtake it. No native wait overlaps native Finalize. A wrapper commitment is
not proof of provider enrollment, and this design does not rely on the OASIS
exception for a thread already blocking in Wait. A provider ignoring DONT_BLOCK
may hang; retain its frame/gate and let the independent grace controller stop
the process without calling Finalize over it.

Check response RV against caller `CK_RV` before returning it; check an authorized
successful virtual slot against caller `CK_SLOT_ID` before writing `pSlot`.
Unrepresentable RV or successful slot produces local `CKR_FUNCTION_FAILED` and
leaves `pSlot` unchanged. Never truncate a nonzero wide error into `CKR_OK`.
Preserve the original provider RV in the completion observation. Representable
provider errors pass through unchanged. NO_EVENT, any error, local refusal or
width failure writes no caller slot, even if the fixture changed its native
output cell. Slot zero may be valid; a protobuf error's zero slot is not a write
instruction. Do not read an output-only caller buffer to preserve its canary.

Unmapped or policy-suppressed events retain `CKR_NO_EVENT`. Native authorization
follow-up must acquire ordinary admission too. If an otherwise successful wait
needs a native policy query after seal, return local NOT_INITIALIZED with no
slot output and retain the wait's actual OK observation; issue no late query.
An already safely authorized/mapped result may publish without another native
call. A disappeared context gets NOT_INITIALIZED. Native success does not
guarantee event delivery; timeout response and actual completion remain distinct.

## Abnormal native-lifetime stop

Select one private `native_stop::abnormal_stop_native_lifetime(reason) -> !`:
a direct, return-aware Linux `exit_group(70)` loop on the qualified targets.
It applies both when controlled shutdown cannot establish native quiescence
and when the final native owner lacks its proof. It is unconditional native
lifetime protection, not an opt-in gateway capability. Grace/stuck settings
control proactive stopping; disabling them never permits unsafe final Drop.
The release panic strategy remains unwinding everywhere else.

The exact instruction contract to implement and review is:

| Linux target ABI | One raw attempt |
| --- | --- |
| x86_64 / 64-bit pointers, GNU or musl | `syscall`, number 231 in RAX, status 70 in RDI; RAX is return-clobbered, RCX and R11 are clobbered; `nostack` is permitted. |
| x86 / 32-bit pointers (i686), GNU or musl | `int 0x80`, number 252 in EAX; save EBX, move status 70 from ECX into EBX, then restore EBX on hypothetical return, with balanced push/pop preserving PIC use. No `nostack`. |

Both stubs model a possible return, preserve required registers/stack and
default assembly memory effects, and return to the outer retry loop. No
`noreturn` asm option, `pure`, `nomem`, `readonly`, `unreachable_unchecked`,
libc call, abort instruction or signal fallback is permitted. A returning or
intercepted syscall never reaches caller fallthrough or dependent destruction.
The loop is containment on return, not proof of termination under a denied
syscall. Bind constants to reviewed Linux UAPI and review final linked code,
including debug/release/MSRV and LTO configuration, before qualification.

The stop initiates no Rust unwind, panic hook, user-space destructor, C exit
handler, ELF finalizer, native Finalize/session cleanup, provider callback,
logging, formatting, allocation, wiping or flush. It is not normal process
exit through libc/std, nor raw thread-only Linux `exit`. The predicate and
stop must not wait for a constructor, native/session/lifecycle lock, worker
pool or stalled runtime. An independent shutdown deadline controller must
remain able to stop a stuck native call or stuck Finalize worker.

### Environment and operational limits

Every possible invoking thread, including after later-installed filters, must
be allowed to execute its architecture's actual `exit_group(70)`. Strict
seccomp is unsupported. Errno denial, SIGSYS handlers, thread-only killing,
tracing, syscall emulation or user notification do not satisfy that contract.
`Seccomp: 2` and a startup child probe do not prove future per-thread permission.
No protection is promised against a hostile in-process provider changing code,
memory, stacks, signal state or thread policy, nor external forced exec or
kernel failure. This is not a general signal-handler-safe shutdown API.

When allowed and completed, the kernel ends the calling thread group with
ordinary exit status 70; this is not SIGABRT. A concurrent fatal signal/exit
may win the observed status. The path initiates no signal handler but cannot
stop callbacks or unrelated handlers already running before group exit takes
effect. Scheduling, kernel resource release, device drivers and uninterruptible
tasks prevent a strict wall-clock disappearance bound. Kernel cleanup and
external HSM operations may have effects after user-space work ends.

Supervise the actual daemon and propagate its status through entrypoints.
systemd `Restart=on-failure` or `always` can cover exit 70;
`on-abnormal`/`on-abort` alone do not. Success/restart-prevention settings,
rate limits and explicit operator stops can prevent restart. Docker likewise
requires an appropriate policy; restart is not promised after manual stops.
PID-namespace init termination affects the container's other processes; global
host init is outside this deployment contract. ADR-0007's separate daemons
remain the selected way to limit cross-client failure impact.

No wiping, complete audit tail, provider cleanup, token deletion or global
core-dump suppression is promised. No audit flush or diagnostic work may delay
the mandatory stop; an earlier metadata notice is best effort and status 70 is
the selected terminal status channel. This path does not intentionally trigger
a core, but other signals, crash paths, tracing and system collectors remain.
`RLIMIT_CORE=0` alone does not disable piped core collectors. Operators own the
complete dump/storage/inspection policy; see [privacy.md](privacy.md). The
stop cannot retroactively prevent destructors that ran before its guard, so
placement and pre-entry publication are part of the implementation proof.

### Windows abnormal-stop contract

On qualified Windows (MSVC, x86_64 with 64-bit pointers or x86 with
32-bit pointers — the Windows leg of `NATIVE_FFI_QUALIFIED`), the
backstop's one raw attempt is
`TerminateProcess(GetCurrentProcess(), 70)` via a hand-declared
`#[link(name = "kernel32")] unsafe extern "system"` block with
`type HANDLE = *mut c_void` (no new crate; see the Windows `mod arch`
arm in `crates/backend/src/ffi/native_stop.rs`), followed by a modeled
non-return spin: `TerminateProcess` never returns on success, and a
hypothetical return must spin rather than fall through to dependent
destruction. This is the faithful `exit_group` analog: whole-process,
immediate, with no DLL detach routines, C exit handlers, or Rust
destructors running, and it preserves status 70 for supervisor
`Restart=on-failure` handling with identical receipt criteria. `abort()`
was ruled out (reviewer Q3): it risks provider-handler interference and
loses the 70 channel (SIGABRT/abnormal instead of a plain exit status),
so `on-abnormal`/`on-abort`-only supervision would be required instead
of `on-failure`.

This arm is strictly weaker than the Linux contract above and claims
less. Non-claims, each explicit: no seccomp or per-thread permission
model applies on Windows; no memory wiping is performed; no audit tail
is flushed or promised (status 70 is the terminal status channel, as on
Linux); no core-dump suppression is configured (no WER policy is
touched). The shutdown-deadline controller and the final-owner guard
predicate keep their Linux semantics (lock-free, no registry or
lifecycle waits); only the raw attempt differs.

Receipt criteria (supervisor side, no in-process observation): the
process dies (reaped, no lingering threads); no hang (a supervisor
timeout bounds the stop); exit-70 evidence is captured from the
supervisor side (exit code 70 observed by the parent via wait status).

### macOS abnormal-stop contract

On qualified macOS (aarch64 or x86_64 with 64-bit pointers — the macOS
leg of `NATIVE_FFI_QUALIFIED`), the backstop's one raw attempt is
libSystem `_exit(70)` via a hand-declared `unsafe extern "C"` block (no
new crate; see the macOS `mod arch` arm in
`crates/backend/src/ffi/native_stop.rs`). The call diverges (`__dead2`):
a return is unrepresentable, so no spin loop is needed — the Windows
arm's trailing `loop {}` exists only because `TerminateProcess` returns
`BOOL`. This is the faithful `exit_group` analog macOS allows:
whole-process, immediate, with no atexit handlers, stdio flush, ELF
finalizers, or Rust destructors running, and it preserves status 70 for
supervisor handling with identical receipt criteria. Raw macOS syscalls
were ruled out (no stable ABI — libSystem is the stable interface);
`std::process::exit` was ruled out (runs atexit handlers and flushes
stdio); `abort()` was ruled out (loses the 70 channel, same Q3 reasoning
as Windows).

This arm is strictly weaker than the Linux contract above and claims
less. Non-claims, each explicit: the stop traverses libSystem userspace
(a thin wrapper, but not a raw trap — a hostile in-process provider
could interpose it, in the same class as the documented no-protection
rule); no seccomp or per-thread permission model applies on macOS; no
memory wiping is performed; no audit tail is flushed or promised (status
70 is the terminal status channel, as on Linux); no core-dump
suppression is configured. The shutdown-deadline controller and the
final-owner guard predicate keep their Linux semantics (lock-free, no
registry or lifecycle waits); only the raw attempt differs.

Tested/untested boundary (same precedent as the Windows arm): the stub
itself never runs in-process in unit tests — it would end the test
process. What is tested is the supervisor-side record: the existing
STOP-C1 child scenarios plus the S8 controller-deadline child exercise
the real arm in a re-spawned child and assert normal exit 70, no
signal/core, pipe EOF, and reaping. Those tests are `cfg(unix)`, so they
compile on macOS; executing them there rides the T2run carry below.

Status: IMPLEMENTED, NOT runtime-qualified. No live macOS execution
exists. Qualification needs the T2run carry: (1) macOS-leg compile
proof — the cross-platform CI macOS leg (aarch64) building the backend
and shim touched crates; (2) live-stop receipts — the STOP-C1/S8 child
tests executing on that leg, which requires the leg to run the backend
lib suite (it currently only builds plus runs the comparison script).
The x86_64 macOS arch has no hosted CI runner, so its compile proof is a
local cross-target check only, recorded — never claimed as CI evidence.

Receipt criteria (supervisor side, no in-process observation): the
process dies (reaped, no lingering threads); no hang (a supervisor
timeout bounds the stop); exit-70 evidence is captured from the
supervisor side (exit code 70 observed by the parent via wait status).

### Controller and guard on unqualified targets

Where no stop arm exists, the final-owner guard cfg-compiles out and
the `Drop` body keeps the poison path (retain ownership, deny new loads
until restart). The fallback `unimplemented!()` in `native_stop.rs` has
no production path to it: `check_native_platform` refuses construction
before any deadline can arm. Its only reachability is test-only
unmanaged backends arming an expired deadline, in which case the
controller thread panics loudly on the fallback. That panic is
contained to the controller thread (the default hook prints, the thread
unwinds to its start; no FFI crossing, no UB); the process survives
with the deadline unenforced — the same best-effort posture as a
controller spawn failure.

Since the macOS arm landed, the stop arms cover exactly the
load-qualified set, so no load-qualified-but-stop-unqualified target
remains; the residual unqualified set is precisely the complement of
`NATIVE_FFI_QUALIFIED`, enumerated from code:

- Linux with a non-GNU/musl `target_env` (any arch), or with an
  arch/width outside x86_64-64/x86-32 — s390x, aarch64, riscv64, ... (the
  s390x BE tier stays load-refused; live-BE-FFI remains BLOCKED-scope);
- Windows with a non-MSVC `target_env`, or with an arch/width outside
  x86_64-64/x86-32 (notably aarch64 Windows);
- macOS with an arch outside aarch64/x86_64 or non-64-bit pointers (no
  such Rust target in practice);
- every other `target_os`.

## Required acceptance evidence

All cases below remain required future tests, not receipts from this amendment.
Use synthetic canaries, deterministic gates, actual production owner seams and
immutable same-source binaries, hashes, ELF widths, commands/test counts,
toolchains, libc/kernel/environment records and child wait/marker results.

- Constructor races/second loads: identical, relative, symlink, hardlink and
  genuinely different paths; Reserved/Active/Retiring contention; no second
  loader/discovery/Initialize attempt, including while Finalize is held.
  Arc clones share the domain. Test safe pre-entry rollback, proven discovery
  failure unload before reuse, fresh-epoch reload, stale-release rejection,
  epoch exhaustion, mutex poison, unknown initialization and failed Finalize.
  Uncertain paths cannot unload or reopen construction. Singleton tests do not
  prove cross-DSO enforcement.
- Wait direct-backend, gRPC and actual loaded-shim cases: every pairwise
  precedence conflict; `0`, DONT_BLOCK, DONT_BLOCK plus a representable unknown
  bit, `2^32`, `2^32 | DONT_BLOCK`; successful slot zero, wide slot/RV, NO_EVENT
  with modified native output and a sentinel provider error. Check original
  bits, exact native counts, output canaries, local origin/provider observations
  and policy output. Seal before admission, after admission before C, inside C
  and after return before settlement; no Finalize overlap. Abort/timeout keeps
  the ordinary owner; no policy query crosses seal; stale epochs cannot enter.
- All four Linux caller/daemon pairs: x86_64/x86_64, i686/i686,
  i686/x86_64 and x86_64/i686. Launch a matching-width daemon with the oracle
  loaded in that process and a private feature-enabled control channel; do not
  load a separate oracle in the caller to pretend to control the daemon.
  A normal production build has no test hook/listener. Cross-compilation,
  simulated widths or backend-only tests do not replace loaded-shim receipts.
- Stop child tests from main and nonleader worker: multiple live threads,
  normal exit 70, no signal/core wait status, pipe closure and process reaping.
  Test actual never-initialized/quiescent normal Drop and abnormal final-owner
  cases: retained/poisoned/pending graphs, unknown entry, failed Finalize,
  returned-but-unsettled work, proof invalidation and a gated DONT_BLOCK waiter.
  A fixture hang under DONT_BLOCK is fault injection, not provider qualification.
- Absent Rust stack/domain/TLS Drop, panic hook, C atexit/on-exit where
  available, ELF unload, provider Finalize and callback markers on stop.
  Positive normal-drop/join/finalize/unload/exit controls must prove each marker
  works. A stuck native call and stuck Finalize cannot block the independent
  stop controller. Track prior Finalize count so no extra cleanup is measurable.
- A returning SIGABRT-handler control, actual wait status and recorded core
  policy; no host sysctl changes. Controlled seccomp errno-denial negatives must
  never fall through to Drop, but require external parent termination and are
  labeled unsupported-environment failures of the termination guarantee.
- Exact debug/release/MSRV code-generation and final-link review plus native
  x86_64 and i686 execution for the release's GNU/musl variants. Static assembly
  probes are not native receipts. Native provider neighbors/parity classify
  blocking Wait as excluded scope and separately qualify nonblocking events;
  crypto-only success or a provider's own unsupported Wait proves no event path.

The full per-variant/consumer ownership inventory, associated exact-output
effects, created-object cleanup, cancellation/retirement tests and independent
review remain required alongside P0. This document does not accept the common
owner repair, async completion, later lifecycle/privacy/budget integration,
Windows native loading or a release.
