# Development environment

Use the pinned Rust toolchain through rustup (`rust-toolchain.toml`
selects it automatically), with `rustfmt` and `clippy`. The minimum
supported Rust version is **1.88.0**, including when updating dependencies.
The repository builds independently of the umbrella workspace and OASIS
specification checkout.

## Ubuntu 24.04 / 26.04

Install the compiler and the tools used by local provider and consumer tests:

```bash
sudo apt update
sudo apt install build-essential pkg-config protobuf-compiler \
    softhsm2 opensc gnutls-bin libnss3-tools
rustup toolchain install 1.98.1 --component rustfmt --component clippy
rustup toolchain install 1.88.0 --profile minimal
cargo install cargo-audit cargo-deny --locked
```

You can also install `protoc` and ShellCheck with
[mise](https://mise.jdx.dev/dev-tools/). Install the provider packages above
separately.

```bash
mise trust
mise install
mise exec -- protoc --version
mise exec -- cargo check --workspace --all-targets --locked
```

Use `mise exec --` when mise is not activated in your shell.

## Core checks

Run commands from this repository. For an edit, start with the affected crate
and its specific regression instead of repeating packaging and platform builds:

```bash
cargo check --locked -p pkcs11-proxy-ng-client --all-targets
cargo test --locked -p pkcs11-proxy-ng-client
```

Replace the package with the crate you changed. A selected Cargo filter that
matches no tests is missing evidence; inspect the reported count. Shared
types/protocol, native ownership, authorization and output changes also need
their consuming-crate tests and the relevant native contracts.

The compact native-contract gate builds the shim, recording providers and test
executables once, then runs an explicit case manifest in bounded child
processes. It requires Linux with working pidfd and child-subreaper support,
Python 3.12 or newer, and the normal Rust/C/protobuf build tools. It needs no
external token or provider installation:

```bash
python3 scripts/run-native-contracts.py --output target/native-contracts/receipt.json
```

The strict default fails for missing artifacts, mismatched or empty selections,
missing semantic completion, failed tests and incomplete runner-owned child or
temporary-directory cleanup. `--list` and
`--no-run` are diagnostic/build modes and do not establish passing native
contracts. The receipt lists the selected and executed cases and their source
and artifact identities. These fixture observations cover their declared
native boundaries; they do not qualify real providers, unexecuted platforms or
a release package.

For script and workflow changes, use an activated Python virtual environment:

```bash
python3 -m pip install -r requirements-script-tests.txt
python3 scripts/run-script-tests.py
```

This runs the complete public Python regression suite with mandatory tool and
dependency checks, nonzero collection and no unexpected skips. See the runner's
prerequisite diagnostics for missing tools. CI executes both regression and
native-contract gates as required jobs.

Before completing a change, run the canonical workspace validation:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Run the remaining policy, compatibility and packaging checks for the candidate
being qualified, including after dependency/build/platform changes:

```bash
cargo audit
cargo deny check
cargo +1.88.0 build --workspace --locked --all-targets
cargo +1.88.0 test --workspace --locked
scripts/release-dry-run.sh
```

Set `CARGO_BUILD_JOBS=2` if memory is limited. Measure compilation separately
from warmed test execution when comparing changes. Full provider parity,
installed-consumer, native platform, performance and release evidence remain
separate gates; a fast selected run cannot satisfy their unexecuted scope.

## Replayable session sequences

The native gate includes five session lifecycle sequences through the real
service and FFI backend, using a deterministic native fixture. They check failed
close retries, partial close-all survivors, operation errors, raw-handle reuse,
and late native outcomes after handler cancellation. Expectations come from an
independent logical-session model and native observations.

Three fixed seeds and bounded action suffixes keep canonical runs small. For a
failure, replay one seed and optionally an action prefix using the commands in
[the fixture guide](../tests/ffi_oracles/session_lifecycle/README.md). Replays
emit a diagnostic completion marker and do not qualify the canonical gate. These
checks exercise native ownership and session semantics; real-provider behavior
remains a separate gate.

## Selected feedback and test timings

For script work, select exact local modules and retain a timing receipt:

```bash
mkdir -p target/script-feedback
python3 scripts/run-script-tests.py \
    --module test_ci_feedback.py \
    --module test_perf_compare.py \
    --module test_support_matrix.py \
    --timings-json target/script-feedback/selected.json
```

A selected receipt names its modules and exact collected/executed test IDs. It
is selected-scope evidence; the no-argument command remains the complete required
CI regression gate. Timing receipts retain failing outcomes too. Module totals
are summed test durations and exclude import/module/class fixture time. Profile
the complete run when that work is authorized before choosing parallelism or
changing CI selection.

## Small mutation panel

The manual panel checks two specific mistakes: stale HandleMap reverse-binding
removal and bypassed protected-wire scanning. Commit the development source first;
the tool checks an immutable Git snapshot and refuses relevant dirty source.
Direct canonical relative links to committed regular source files are materialized
with link/target provenance; escaping links, link chains and directory links are
refused. Cache symlinks remain refused.
It builds and runs each baseline, mutated primary test and positive control in
separate temporary source/output trees. A compilation error, timeout, wrong panic,
zero test or failed cleanup is an error, never a killed mutant.

```bash
python3 scripts/run-mutation-panel.py \
    --output /tmp/pkcs11-mutation-panel.json \
    --source-ref HEAD \
    --seed-target "$PWD/target" \
    --timeout 240
```

The optional seed target must be a quiescent cache. Seeding requires supported
reflinks and independent output files; it never uses hardlinks into normal build
outputs or silently falls back to a large copy. Without a seed, compilation may
take longer. Receipt output must be outside the checkout and donor cache.
Compilation and test execution have separate bounded phases. Temporary-tree
removal has a separate 60-second safety cap and must finish before success.
Panel success proves
that these named assertions detect these mutations, not complete mutation coverage
or real-provider correctness. Keep the ordinary full Rust/Python, platform and
release validation contracts for their separately authorized runs.

## Prepared provider smoke

`scripts/test-softhsm2-smoke.sh` is the small standalone-daemon/shim workflow for
later real-provider execution. Use explicit prebuilt daemon/shim paths and, if
needed, `PKCS11_PROXY_BACKEND_MODULE` to select the intended SoftHSM2 library.
It uses a scratch token, generates and signs through the proxy, retires/reaps the
daemon, then signs directly with the same key. Exported-key OpenSSL verification
and deterministic signature comparison must both succeed before the smoke passes.
The command shapes follow the [OpenSC tool and OpenSSL guide](https://github.com/OpenSC/OpenSC/wiki/Using-pkcs11-tool-and-OpenSSL).

Preparing or exercising the script with controlled tool fixtures does not qualify
SoftHSM2, the daemon binary or a release package. Run the actual provider workflow
when provider execution is authorized; it is separate from the synthetic native
session/ownership gate and the full matrix.

## Extending mechanism parameter support

New `CK_MECHANISM` parameter shapes follow the complete recipe in
[mechanism-parameter-extension.md](mechanism-parameter-extension.md)
(mandatory checklist: `AGENTS.md` §12). It names every edit point and
gate owner — proto, domain, conversions, shim reader, shape descriptor,
manifest binding and regeneration, native reconstruction,
validation/sanitize/remap classification, ownership/output/handle
semantics, registry binding, and tests — plus the verification commands
to run from a fresh standalone checkout.

## Provider tests

These scripts create temporary development tokens and configurations:

```bash
scripts/test-consumers.sh
scripts/test-shim-parameterized.sh
scripts/test-provider-backends.sh
```

The first two accept `PKCS11_PROXY_BACKEND_MODULE=/absolute/path/to/libsofthsm2.so`.
Keep consumer executables on `PATH`. Other tests search system library paths,
so install your distribution's SoftHSM2 package. NSS tests need `certutil`;
Kryoptic tests use `PKCS11_PROXY_KRYOPTIC_MODULE`.

See the [test guide](../crates/server/tests/README.md) for individual suites
and prerequisites. For broader provider testing, see
[pkcs11-check](https://github.com/mingulov/pkcs11-check).

For manual SoftHSM2 tests, set `SOFTHSM2_CONF` to a configuration with a
user-owned token directory. The scripts above create temporary configurations
and do not need access to the system token store.

## Additional CI lanes

For Linux i686 ABI checks:

```bash
sudo apt install gcc-multilib libc6-dev-i386
rustup target add i686-unknown-linux-gnu
```

For Windows cross-compilation:

```bash
sudo apt install clang lld nasm
rustup target add x86_64-pc-windows-msvc
cargo install cargo-xwin --locked
```

For coverage and Miri:

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
rustup toolchain install nightly --component miri --component rust-src
```

For fuzzing (nightly only; `fuzz/` is excluded from the stable workspace):

```bash
cargo install cargo-fuzz --locked
```

## Fuzzing, Miri, and coverage

The nightly pipeline runs three complementary dynamic gates; all reproduce
locally with the tooling above.

**Fuzz smoke** (`fuzz/`): five libFuzzer harnesses over untrusted-input
edges — `fuzz_width` (cross-ABI `CK_ULONG` translation),
`fuzz_registry` (registry TOML load + queries),
`fuzz_attribute` (attribute proto edge incl. the D8 nesting refusal),
`fuzz_mechanism` (hostile-wire `Mechanism` decode + `CkMechanism`
round-trip over all 79 param shapes), and `fuzz_protected_decode`
(pre-decode wire scanner). Each asserts totality (typed errors, never a
panic) plus edge-specific round-trip invariants. Every target ships
checked-in seeds (`fuzz/seeds/<target>/`); the parser-shaped targets
add libFuzzer dictionaries (`fuzz/dict/*.dict`).

```bash
cargo +nightly fuzz build
for t in fuzz_width fuzz_registry fuzz_attribute fuzz_protected_decode fuzz_mechanism; do
  mkdir -p fuzz/corpus/$t
  cp fuzz/seeds/$t/* fuzz/corpus/$t/
done
cargo +nightly fuzz run fuzz_width -- -max_total_time=90
cargo +nightly fuzz run fuzz_registry -- -max_total_time=90 -dict=fuzz/dict/registry.dict
```

Crashes land in `fuzz/artifacts/<target>/` (git-ignored); reproduce one
with `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>`.
Corpus coverage: `cargo +nightly fuzz coverage <target>` (needs the
`llvm-tools` nightly component), then `llvm-cov report` against the binary
under `target/<triple>/coverage/<triple>/release/<target>`.

**Miri**: the types crate (all but the TOML-bound registry and manifest
suites, whose parses stall the interpreter), the shim's raw-pointer
parse paths and pure `tests::` suites (ABI audit, null-pointer
handling, classifier, dispatch shape, endpoint parsing, poison
recovery, regressions, resource limits), and the backend
lifecycle/registry state-machine, FFI-materialization, and `mock::`
(per-file lines; the one-line form stalls) suites run under the UB
interpreter across three nightly legs (types, shim, backend).
Five registry/official-list matrix tests are Miri-ignored
with measured notes (each 240+ s standalone; zero `unsafe` in `mock/`).
Daemon/socket/fs dependent tests self-gate
(`#[cfg(not(miri))]` modules, `cfg_attr(miri, ignore)`, or `cfg!(miri)`
skips); the daemon probe is a no-op under Miri (daemon-down fallback,
same as unreachable-daemon). The FFI-materialization line runs with
`-Zmiri-tree-borrows`: its Pin-stabilized capture-then-move idiom is
sound but Stacked-dirty, and Tree Borrows caught a real `pParameter`
misalignment there. The exact filter lists live in `nightly.yml` (keep
them in sync when adding UB-relevant pure logic).

**Kani**: `crates/types/src/kani_proofs.rs` proves 31 harnesses:
width-translation "never silently truncate" laws,
attribute-classifier laws, mechanism vendor/flag laws, `SecretBytes`
length/content laws, output/session/slot/object gating laws, `CkRv`
ok/err + vendor-range + spec-table laws, `CkInBuf` NULL/bytes pointer
laws, and the official-mechanism table law. Run
`cargo kani -p pkcs11-proxy-ng-types` (pinned verifier; see
`nightly.yml`). Each harness covers its modeled inputs exhaustively,
but the models are bounded where CBMC needs a bound: fully symbolic
scalars/ids for the classifier, vendor, flag-predicate, `CkRv`,
`CkInBuf`, and length-translation proofs; fixed 8/12/6-byte inputs for
the reencode proofs; a concrete invalid-width set; fixed 4/8-byte plus
0..=8-byte variable-length `SecretBytes` models; a concrete flag table
with pairwise distinctness; and one symbolic index into the asserted-
nonempty official-mechanism table. Registry-query and proto-crate
proofs were attempted and removed as CBMC-intractable
(nondet-SipHash blowup; details in `kani_proofs.rs`) — those edges
stay covered by fuzzing instead.

**Coverage ratchet**: `cargo llvm-cov --workspace` must stay at or above
84% lines (`--fail-under-lines 84` in `nightly.yml`; baseline 85.20% on
2026-09-28). Bump the floor up as coverage sustainably improves; never
lower it to fit a change — add tests instead.

**Known limits** (recorded for the step-20 audit; scope as of this
tree): fuzzing covers the types + proto crates only — the five `fuzz/`
targets link just those two crates, so daemon, client, shim-dispatch,
and backend-FFI paths are outside the fuzz corpus; nightly runs a
90 s/target smoke, with longer campaigns on demand. Kani covers the
types crate only (31 harnesses over bounded models); registry-query
and proto proofs were attempted and removed as CBMC-intractable (see
`kani_proofs.rs`), leaving those edges to fuzzing. Miri runs three
legs — types (all but the two TOML suites), the shim's raw-pointer
parse paths and pure `tests::` suites, and the backend
lifecycle/registry/mock suites plus the Tree Borrows FFI-materializer
line; the server, client, CLI, and proto crates have no Miri leg.
Under Miri, real `dlopen` is unsupported, so dlopen-dependent tests
self-skip (`cfg!(miri)` early returns, covered natively), as do
daemon/socket/fs/time-dependent tests via per-test gates
(`cfg_attr(miri, ignore)` with measured notes) and `#[cfg(not(miri))]`
modules; the TOML suites and the backend FFI suites that need
`dlopen(NULL)` stay native-only.

Target-specific commands are in [ci.yml](../.github/workflows/ci.yml) and
[nightly.yml](../.github/workflows/nightly.yml). Live tests may also need
provider images, 32-bit libraries, or Wine; see the [test guide](../crates/server/tests/README.md).
