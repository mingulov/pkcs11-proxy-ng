# Session lifecycle native oracle

This unpublished deterministic PKCS#11 module is a session/login/error oracle,
with fixed public canaries instead of cryptography. It runs below the production
FFI backend. Native close errors occur inside `C_CloseSession`; they do not use
the backend's pre-entry failure hook. Token login deliberately survives the last
native member close so missing explicit carrier logout remains observable.

The canonical standalone entrypoint builds the fixture and executes five exact
session tests as part of the declared native contracts:

```sh
python3 scripts/run-native-contracts.py --output target/native-contracts/receipt.json
```

To build and run only this fixture and the session target from the public root:

```sh
export CARGO_TARGET_DIR="$PWD/target"
export CARGO_BUILD_BUILD_DIR="$PWD/target/build"
export CARGO_BUILD_JOBS=2
flock /tmp/pkcs11-proxy-testing-feedback-cargo.lock \
  cargo build --locked --manifest-path tests/ffi_oracles/session_lifecycle/Cargo.toml
flock /tmp/pkcs11-proxy-testing-feedback-cargo.lock \
  cargo test --locked -p pkcs11-proxy-ng --test session_sequence_test --no-run
PKCS11_PROXY_SESSION_ORACLE_LIB="$PWD/target/debug/libpkcs11_session_lifecycle_oracle.so" \
  timeout --kill-after=5s 45s \
  flock /tmp/pkcs11-proxy-testing-feedback-cargo.lock \
  cargo test --locked -p pkcs11-proxy-ng --test session_sequence_test \
  -- --ignored --test-threads=1 --nocapture
```

The direct/debug execution above needs its external process bound: unresolved
native work remains owned until settlement or process stop. Compilation is
separate from that45-second execution budget. The canonical gate supplies its
own45-second bound for each exact case; a raw unbounded Cargo invocation is not
a substitute for that process boundary.

Six fixture-only tests also run with `cargo test --locked --manifest-path
 tests/ffi_oracles/session_lifecycle/Cargo.toml --lib -- --test-threads=1`.
They check real retirement, native transient failure/login preservation, retired
handle reuse, gate/reset ownership, native thread ownership after a deadline, and observation overflow. The server target
adds named negative controls that reject a missing native member completion and
an observation retiring a transient-close lease. These controls validate the
observation checks; they are not production mutant-kill evidence.

The distinct V1 control ABI is defined in `src/types.rs`:

- `SessionOracle_CommandV1` checks version, size, reserved fields and command
  prerequisites. Commands set one-shot close RVs by handle, a one-shot random
  RV, the next retired raw handle to reuse, or the close entry/release gate.
- `SessionOracle_GetObservationV1` checks caller size and returns a bounded
  session history and native event log, native login, gate holders and pending
  closes. Overflow is explicit and causes the sequence checks to fail.
- `SessionOracle_ResetV1` refuses initialized/live/pending work.
  `SessionOracle_ResetObservationV1` refuses pending native work and otherwise
  resets only event observations, preserving sessions/login/scripts/gate state.
- `C_Finalize` refuses live sessions or pending closes. No reset or finalizer
  silently discards them. The gate wait releases the state mutex so observation
  and explicit gate release remain available.

Traces use symbolic session tags, exact expected RVs, eight-byte native
incarnation canaries, three seeds and at most16 generated suffix actions, with
at most3 live sessions. `PKCS11_PROXY_SEQUENCE_SEED=0x5eed` selects one seed;
`PKCS11_PROXY_SEQUENCE_PREFIX=5` additionally limits its action prefix. Such
runs print `session-sequence-replay-complete`, never a canonical completion
marker. Failures report the seed, step and symbolic prefix without PIN bytes.
The canonical native runner scrubs these inherited selectors.

Ordinary cases run through the real loopback client/service/FFI path. The
cancellation case aborts the public service future after observed native entry,
then releases the native gate and checks late terminal and transient outcomes.
Auth on suspended sessions, concurrent ABA reuse, real-provider cryptography,
shim and standalone-daemon qualification remain outside these tests.

Cleanup retains each native worker handle across local deadlines. It explicitly
releases the fixture gate and joins before finalization; a missed deadline stays
a failure even if later settlement succeeds. Work that remains blocked after the
recovery deadline stays owned at the outer process timeout, preventing normal
finalization/unload. Dropping an unjoined native-owner guard fail-stops this test
process with exit71. Fixture gate controls likewise join only after proven thread
completion; expiry uses that failing process boundary, never an unbounded join.
Short channel-based controls exercise these transitions without a long wedge.
