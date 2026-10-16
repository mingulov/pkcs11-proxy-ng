# Adding a mechanism parameter shape

This is the complete recipe for extending classic `CK_MECHANISM`
parameter support. `AGENTS.md` §12 states the mandatory checklist;
this guide names every edit point and gate owner behind it. All paths
are relative to this repository root; run every command from the root.
The repository builds and tests standalone: no planning workspace or
OASIS checkout is needed.

Message-operation parameters (`CK_GCM_MESSAGE_PARAMS` and friends)
are a separate surface with their own matrix; this recipe covers only
classic `CK_MECHANISM` parameters.

## Step 0 — New compiled shape or runtime alias?

A vendor mechanism that reuses an **already compiled** parameter
layout needs **no code changes**: add only a registry binding
(step 10). A runtime alias never creates or alters a descriptor —
`SHAPE_DESCRIPTORS` is immutable compiled data, and the TOML
registry only binds mechanisms to already compiled shapes.

Follow steps 1–11 only when no compiled shape models the layout.
If the layout carries unbounded caller pointers the shim must not
parse, or the mechanism name has no published `CKM_*` value, stop
and use the intentional-omission path instead (see
[Intentional omissions](#intentional-omissions)).

## Step 1 — Proto message and oneof member

1. Add the wire message to
   `crates/proto/proto/pkcs11-proxy-ng/v1/mechanism_params.proto`.
   Model every pointer/length pair with an explicit NULL peer
   (`bytes` payload plus `bool xxx_null` and, where a nonzero
   declared length can accompany NULL, an `optional uint64`
   declared length); follow `GcmParams` (`iv`/`iv_null`/
   `iv_null_len`, `aad`/`aad_null`/`aad_null_len`). NULL,
   non-NULL-empty, and (NULL, nonzero) are three distinct states
   end to end — never conflate them.
2. Add the message to the `Mechanism.params` oneof in
   `crates/proto/proto/pkcs11-proxy-ng/v1/types.proto` with the
   next free field number. Field 1 is `mechanism_type` and field
   83 is `parameter_encoding_version` (outside the oneof); the
   highest oneof number at the time of writing is 82, so a new
   member takes 84. Verify before numbering — never reuse a
   number:
   `grep -o '= [0-9]*;' crates/proto/proto/pkcs11-proxy-ng/v1/types.proto | sort -t' ' -k2 -n | tail -3`.

3. Classify every new `bytes`/`string` wire field in
   `crates/proto/secret-fields.toml`, exactly once: `secret`
   (fields requiring redacted diagnostics and wiping
   ownership) or `safe_metadata` (wiping not required — which
   does not authorize logging, persistence, caching, or
   disclosure). GCM shows both sides: `GcmParams.aad` is
   `secret` (`plaintext_decrypted`), `GcmParams.iv` is
   `safe_metadata` (`public_parameters`).

Gates: the prost build, the build-time oneof cross-validation in
`crates/proto/src/oneof_check.rs` (redacted-`Debug` coverage for
the new oneof arm), the manifest cross-checks in
`crates/types/src/mechanism_param_manifest.rs` (`manifest_tests`
matches every binding's wire-message names against the `.proto`
sources, including oneof membership), and
`manifest_classifies_every_bytes_and_string_field_exactly_once`
in `crates/types/tests/secret.rs`, which rejects any
unclassified (or stale) wire field while
`unclassified_field_policy = "reject"`.

## Step 2 — Domain type and enum variant

In `crates/types/src/mechanism.rs`:

1. Add the parameter struct. Use the field vocabulary the
   validation, conversion, and FFI layers already understand:
   `PointerBytes` / `PointerArray` for pointer/length peers
   (`mechanism.rs`, non-contradictory by construction),
   `SecretBytes` (`secret.rs`) for secret material (directly or
   inside `PointerBytes` / `PointerArray` peers), `CkObjectHandle`
   (`object.rs`) for handles, `u64` for wire scalars narrowed at
   the FFI boundary.
2. Add the `CkMechanismParams` enum variant.
3. Add the `canonical_shape_name()` arm returning the compiled
   shape name (step 5). The backend test funnel
   (`validated_mechanism_for_tests`) binds through it.

Gates: the new variant fails to compile until it is classified
at every exhaustive site — `canonical_shape_name`,
`check_typed_presence`, `zero_embedded_handles`,
`typed_has_nonzero_embedded_null`, the typed list in
`check_classic_sanitize_policy` (all in `mechanism.rs`), both
conversion directions (step 3), `mechanism_to_ffi_at_depth`
(step 7), and the server remapper lists (step 8). The compiler
is the inventory; there is no wildcard to hide behind at these
sites.

## Step 3 — Conversions in both directions

In `crates/proto/src/convert/mechanism/` (`mod.rs` plus the
family submodules `advanced_params.rs`, `derivation_params.rs`,
`tls_params.rs`):

1. `impl TryFrom<&CkMechanism> for v1_proto::Mechanism`
   (client-side serialization, `mod.rs`). This is the legacy
   v0-shaped encode: it sets the `*_null` bools and clears
   every declared-length envelope (e.g. GCM's `iv_null_len:
   None`).
2. `impl TryFrom<&v1_proto::Mechanism> for CkMechanism`
   (server-side deserialization, `mod.rs`).
3. The negotiated v1 encode behind
   `to_wire_with_transport_version` (`mod.rs`) — the
   production serializer the shim uses. At capability < 1 it
   takes the identical legacy path above; at capability ≥ 1
   each input-pointer family encodes presence-based (NULL =
   empty bytes + envelope) with the outer stamp 1. Add the
   shape's arm to the applicable helper: `encode_r17_v1_params`
   for input-pointer shapes (inline arm, or a `ToWireV1` impl
   in the shape's family module for delegated families) or
   `encode_r18_tail_v1_params` for tail shapes. A v1 encoder
   MUST leave legacy `*_null` bools unset (S2 §3) and preserve
   the declared-length envelopes the legacy encoder clears.
   Both helpers end in a wildcard (`_ => None`) that falls
   back to the legacy encode, so the compiler does not
   inventory this omission: a missing v1 arm silently loses
   NULL/nonzero-length semantics on v1 transports.
4. Add a round-trip unit test in
   `crates/proto/src/convert/mechanism/tests.rs` covering the
   NULL/empty edges of every pointer peer (see
   `mechanism_gcm_round_trip` and
   `mechanism_gcm_empty_aad_round_trip`), plus a v1-encode
   test through `to_wire_with_transport_version` proving the
   version stamp, the preserved envelopes, and the unset
   legacy bools (see `encode_v1_gcm`).

Missing any encode direction causes silent runtime failures;
the round-trip test is the minimum proof the `TryFrom` pair
exists, and the v1-encode test is the minimum proof the
negotiated path preserves the shape.

## Step 4 — Shim reader

In `crates/shim/src/dispatch/general/helpers/mechanism_read.rs`:

1. Add a `Some("shape")` arm to
   `read_mechanism_with_shape_budgeted` with a dedicated typed
   parse function (see `read_gcm_struct_params`). Every embedded
   field is read independently: valid bytes in one field must
   survive a NULL peer in another. Bound every read with
   `embedded_payload_len_ok` / `MAX_MECHANISM_PARAM_STRUCT_LEN`
   and reject absurd lengths before dereferencing.
2. Add the v1 step-1 reader and route the shape: input-pointer
   shapes join `is_r17_v1_shape`, exotic-tail shapes join
   `is_r18_tail_shape` (disjoint lists; scalar and byte-buffer
   shapes keep the legacy reader with `Raw` mapped to
   `PARAM_INVALID` under v1).
3. Preserve the NULL/empty distinction into `PointerBytes` peers
   (`PointerBytes::from_legacy`, `read_pointer_field_v1`).

Gates: `crates/server/tests/local_shape_gate_test.rs` requires
a shim `Some("shape")` arm for every default-registry shape,
and the manifest presence-field checks require the shim reader
for every manifest shape. Add C-stack read tests in
`mechanism_parameter_tests.rs` beside the existing per-shape
tests.

Never parse unbounded caller pointers in the shim: shapes like
`CK_CMS_SIG_PARAMS` / `CK_X3DH_*` / `CK_X2RATCHET_*` are
intentional omissions (below), not reader work.

## Step 5 — Compiled shape descriptor and ABI classification

In `crates/types/src/shape_descriptors.rs`, add one
`SHAPE_DESCRIPTORS` entry (the table is sorted by name for
binary search; use the matching constructor helper such as
`pointer_shape`, `scalar_shape`, or `pointer_shape_with_handle`):

1. `OuterKind`: `Parameterless`, `ByteBuffer`, `ScalarStruct`,
   `PointerStruct`, or `NestedOrOutput`. The kind decides
   transport routing: `NestedOrOutput` shapes ride typed
   envelopes only and are never Flat-eligible.
2. `FieldClass` sequence in native field order: `Ulong`,
   `Handle`, `Pointer`, `U8`, `Bytes(n)`, `Nested(&[...])`
   (depth 1 only). Field *classes*, never byte offsets — all
   four v1 ABIs (`ParamAbi`: LP64, ILP32, LLP64-pack1,
   ILP32-pack1) derive from this one reviewed sequence.
3. Operation contexts: `ALL_OPERATIONS`, `WRAP_ONLY_OPERATIONS`,
   or a narrower set, plus any shared-length companion groups
   and `contains_virtual_handle` for handle-bearing layouts.
4. Cite the OASIS struct and its field order in the entry
   comment, as the existing rows do.

Native sizes, first-unsafe offsets, and layout fingerprints
derive from the classification; `decide_flat` /
`decide_flat_for_registry` are generic over descriptors, so
they need no per-shape edit — but the classification is the
review step that decides Flat eligibility, the safe prefix,
and cross-ABI equality. A new enum arm is not automatically a
safe prefix, an admitted Flat form, or an output-writeback
contract.

Gates: host/cryptoki-sys layout cross-checks, fingerprint
tests, and the manifest regeneration diff (step 6), which
surfaces every layout consequence item by item.

## Step 6 — Manifest binding and regeneration

In `crates/types/src/mechanism_param_manifest.rs`, add one
`SHAPE_BINDINGS` row via `bind(...)`: the shape name, the wire
message names from step 1 (empty only for the `parameterless`
marker, which rides the unset `params` oneof), `Complete`
status, the reviewed output-field indices (step 9; `&[]` when
the provider writes nothing), and `V1` minimum transport
version. The bindings are the single human edit point; every
other manifest field derives from the descriptors.

A new shape also needs its manual coverage row — regeneration
does not write these. All owners live in
`crates/types/src/mechanism_param_manifest.rs` (`manifest_tests`):
a `Complete` `PointerStruct` joins `R16_PRESENCE_TABLE`
(`presence_table_covers_every_input_pointer_shape` asserts the
table equals the `Complete` `PointerStruct` set minus the R18
TLS set, so a missing row fails the equality); a tail shape
joins `R18_TAIL_TABLE` (`tail_table_covers_every_tail_shape`);
a scalar or byte-buffer shape joins
`R21_NO_ENVELOPE_SHAPES` with its no-envelope reason. The
shape's S2 §8 family must appear in
`S2_SECTION_8_FAMILIES`, and
`envelope_union_covers_every_manifest_shape` pins the union
plus the manifest shape count. Update each applicable table
as a reviewed coverage change — never alter a pin merely to
obtain green tests.

Then regenerate the checked-in snapshot from the repository
root and review the diff — any diff is a contract change:

```bash
UPDATE_MANIFEST=1 cargo test -p pkcs11-proxy-ng-types manifest
```

This run rewrites
`crates/types/src/mechanism_param_manifest.toml` and still
fails against the stale embedded copy; the next run is green
on the byte-exact snapshot assertion only. The header of
`render_manifest` carries this command verbatim. Regeneration
bytes do not update the freeze digest: `manifest_digest_freeze`
still fails until the manifest change is reviewed against S2
§8 and the S2 §3 version rule and the freeze-vs-new-version
decision is made explicitly — re-freeze `MANIFEST_DIGEST`
only for a reviewed additive change that keeps the current
transport version, never to silence the gate.

Gates: `generated_manifest_matches_checked_in_file_byte_exact`
(byte-exact snapshot), the wire-message/oneof cross-checks,
the presence/tail/no-envelope table-equality tests, the S2 §8
family-coverage test, `manifest_complete` (asserted at
advertisement time — v1 is not advertised while false), and
`manifest_digest_freeze`.

## Step 7 — Native reconstruction

In `crates/backend/src/ffi/ffi_conversion/mechanism.rs`:

1. Add the `mechanism_to_ffi_at_depth` arm. It receives a
   `ValidatedMechanismParams` — never a bare `CkMechanism` —
   and returns an `FfiMechanism` whose `FfiParamBacking`
   variant owns every buffer the native call touches. (The
   backend funnel is `validate_for_ffi`, host ABI on both
   edges; daemon ingress validates separately under the
   local/backend ABI pair.)
2. Add the `FfiParamBacking` variant. Ownership rules:
   `NativeAllocation` for structs and aligned scalars (never a
   byte `Vec` behind a `pParameter` the provider reads as an
   integer or struct), `Zeroizing<Vec<u8>>` for byte payloads so
   secrets wipe on drop.
3. Rebuild the NULL/empty distinction natively: NULL peers
   materialize null pointers, empty non-NULL peers materialize
   `EMPTY_NON_NULL`, lengths come from the presence legs
   (`input_leg`, `sized_leg`, `fixed_leg`). Narrow every wire
   scalar with `narrow_wire_ulong` (`ffi_conversion/mod.rs`) —
   oversized values reject, never truncate.

Gates: backend conversion tests in
`crates/backend/src/ffi/ffi_conversion/tests.rs` (including
NULL-materialization and ulong-narrowing cases) and the
real-backend tests in step 11.

Missing this step is the most dangerous omission in the whole
recipe: proto round-trip tests pass, but operations fail at
the FFI boundary with `CKR_MECHANISM_PARAM_INVALID`.

## Step 8 — Validation, sanitize, and remap classification

The newtype `ValidatedMechanismParams` (`mechanism.rs`) is the
opaque admission value both edges share. Classify the new
variant at each of its gates (all exhaustive — the compiler
rejects omissions):

1. `check_typed_presence` — null-bit/scalar agreement for the
   shape's fields. Presence peers are non-contradictory by
   construction and need no validation of their own.
2. `typed_has_nonzero_embedded_null` — the F2 sanitize scan:
   which embedded NULL peers with nonzero declared
   length/count reject under sanitize-ON.
3. The typed-variant list in `check_classic_sanitize_policy`
   — the new variant joins the explicit list; there is no
   catch-all.
4. `zero_embedded_handles` (behind
   `normalized_for_handle_compare`) — zero every embedded
   `CK_OBJECT_HANDLE` field so the `substitute_handles` debug
   assertion can prove handle substitution preserves every
   other validated property.
5. The server remapper,
   `crates/server/src/server/grpc_service/mechanism_handles.rs`:
   add the variant to `push_param_handles` (handle-bearing
   arms push, the rest join the explicit no-handle list) and
   to `remap_param_handles` (substitute virtual→backend values
   in handle fields only). The two lists mirror
   `zero_embedded_handles`; keep all three in agreement.

`substitute_handles` consumes the newtype and returns it: the
closure may rewrite embedded handle fields only. Flat, Null,
and None carry no handles.

## Step 9 — Ownership, output, handle, and NULL semantics review

This step has no single owner; it is the explicit review of
the semantics the earlier steps encoded:

1. **Reviewed output fields.** The manifest `output_fields`
   indices name the top-level fields the provider may write —
   and only `NestedOrOutput` (tail) shapes carry them: any
   other shape must bind `&[]`, and every listed index is
   `Pointer`-class in every form (both test-enforced), so an
   empty list on an input-pointer shape says nothing about
   provider-written output. GCM is such a case: it binds
   `&[]` yet supports provider-generated IV output through
   writable IV capacity (`iv_buffer_len` sizing the retained
   buffer via `gcm_iv_capacity`) with post-call
   reconstruction in the `output_params` and
   `output_params_equal` `Gcm` arms of
   `ffi_conversion/mechanism.rs`. For output-capable shapes,
   add matching `output_params` and `output_params_equal`
   arms there: both matches have wildcards (`None` /
   `expected.is_none()`) that fail closed, so a new
   output-capable variant silently reports no output until its
   arms exist. The `output_params_equal_tests` battery pins
   arm-for-arm agreement including provider-write flips.
2. **Secret ownership.** Secret-carrying fields are `SecretBytes`
   in the domain type (directly or inside presence peers) and
   `Zeroizing<Vec<u8>>` in FFI backing, so secrets wipe on
   drop; their wire peers carry the matching `secret`
   classification in `secret-fields.toml` (step 1). Never log
   request payloads (`AGENTS.md` §4); keep the release
   profile's unwinding so `ZeroizeOnDrop` runs.
3. **Handle translation.** Handle-bearing shapes set
   `contains_virtual_handle` (step 5), classify in
   `zero_embedded_handles` and the server remapper (step 8),
   and travel through `substitute_handles`. The native
   ownership contract lives in
   [release/native-mechanism-ownership.md](release/native-mechanism-ownership.md).
4. **NULL / non-NULL-empty semantics.** The three states —
   `(NULL, 0)`, `(non-NULL, 0)`, `(NULL, n > 0)` — stay
   distinct from the shim reader (step 4) through the wire
   flags (step 1), the presence peers (step 2), validation
   (step 8), and native reconstruction (step 7). Providers
   differ here (some reject `(ptr, 0)` but accept `(NULL, 0)`);
   the proxy transports the caller's exact choice and never
   normalizes it.

## Step 10 — Registry binding

1. Spec-defined mechanisms go in the embedded default
   `crates/types/src/mechanism_params_default.toml` as a
   `[[params]]` entry (`shape` plus numeric `mechanisms`
   with `CKM_*` comments).
2. Vendor-defined mechanisms (CloudHSM, Thales, …) belong in
   the daemon's runtime registry file: point
   `[mechanisms].config_path` at it (the embedded default
   applies when unset). The daemon serves the registry to
   shims over `GetBackendInterfaces`; the shim falls back to
   the embedded default plus the `PKCS11_PROXY_MECHANISMS`
   env override only when the daemon is unreachable or omits
   the field, and `PKCS11_PROXY_DISABLE_SERVER_REGISTRY=1`
   forces the fallback path for test/debug use.
3. Vendor mechanisms reusing an existing shape need only the
   TOML entry — that is the step-0 alias path, not a shape
   extension.

Gates: `local_shape_gate_test` requires every default-TOML
shape to have a shim reader arm, and every shim arm to
resolve to a TOML shape except the reviewed `NON_DEFAULT_ARMS`
runtime-only / operator-configured shapes; the
default-registry suites pin load and query behavior.

## Step 11 — Tests: round-trip, real backend, width

1. **Round-trip unit test** (step 3): proto conversions both
   ways, NULL/empty edges included. Necessary, never
   sufficient.
2. **Real-backend integration test.** Add a
   `crates/server/tests/support/shape_matrix.rs` driver entry
   (`variant: "Variant"`) so `softhsm_all_param_shapes_execute`
   in `crates/server/tests/parameterized_mechanism_test.rs`
   executes the shape against SoftHSM2; add a dedicated
   SoftHSM2 or NSS test beside the existing per-shape tests
   where the shape has meaningful success behavior. Test the
   full stack — client → gRPC → server → FFI backend → real
   PKCS#11 module → result → reverse path — never MockBackend
   or unit tests alone. `local_shape_gate_test` fails while
   any enum variant lacks a driver entry (except the
   transport-only `Flat`/`Null`).
3. **Width tests.** `CK_ULONG` is 4 bytes on ILP32/LLP64 and 8
   on LP64; every scalar crossing must narrow loudly. Cover
   the new shape with the established width surfaces: the
   shim width-matrix tests in `mechanism_parameter_tests.rs`
   (`width_same_abi_struct_prefix_ok` /
   `width_cross_abi_struct_prefix_rejected` pattern), backend
   ulong-narrowing tests in `ffi_conversion/tests.rs`
   (`ulong_mechanism_scalar_wider_than_native_is_rejected_not_truncated`
   pattern); the `crates/types/src/width.rs` translation-law
   suites pin the underlying `CK_ULONG` helpers.

## Step 12 — Verify from a fresh standalone checkout

Clone this repository alone (no planning workspace, no OASIS
tree) and run the focused gates from its root:

```bash
cargo test -p pkcs11-proxy-ng-types manifest
cargo test -p pkcs11-proxy-ng-types
cargo test -p pkcs11-proxy-ng-proto mechanism
cargo test -p pkcs11-proxy-ng-backend ffi_conversion
cargo test -p pkcs11-proxy-ng-shim mechanism
cargo test -p pkcs11-proxy-ng --test local_shape_gate_test
cargo test -p pkcs11-proxy-ng --test parameterized_mechanism_test softhsm_all_param_shapes_execute -- --test-threads=1
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

The `parameterized_mechanism_test` line needs SoftHSM2
(`libsofthsm2.so` + `softhsm2-util`); everything else runs
with the pinned toolchain plus `protoc` (see
[development.md](development.md)). Finish with the full
workspace suite: `cargo test --workspace --locked`.

## Intentional omissions

Two omission policies stay explicit; a shape under either
one gets no TOML entry and no reader work:

1. `do_not_parse_unbounded_caller_pointers_in_shim` —
   `CK_CMS_SIG_PARAMS` / `CK_X3DH_*` / `CK_X2RATCHET_*`
   shapes carry unbounded caller pointers the shim must not
   parse. Direct shim C ABI entrypoints reject these
   parameterized mechanisms with
   `CKR_MECHANISM_PARAM_INVALID` instead of guessing pointer
   lengths.
2. `do_not_assign_project_local_ckm_values` — working-spec
   names without published `CKM_*` values (`CKM_KMAC128/256`,
   `CKM_ML_DSA_EXTERNAL_MU[_GEN]`, `CKM_SHAKE_128/256`) must
   not get project-local numbers that could collide with
   future OASIS assignments.

Record any new intentional omission in
[oasis-profile-coverage.md](oasis-profile-coverage.md)
instead of adding a TOML shape.

## Reference walkthrough shape: `gcm`

`CK_GCM_PARAMS` (`CKM_AES_GCM`) is the representative
pointer-bearing shape to compare a new extension against.
Each recipe step resolves to these existing owners:

| Step | Owner for `gcm` |
|------|-----------------|
| 1 — proto | `GcmParams` in `mechanism_params.proto`; `gcm_params = 4` in the `Mechanism.params` oneof; `GcmParams.aad` = secret / `GcmParams.iv` = safe_metadata in `secret-fields.toml` |
| 2 — domain | `GcmParams` struct + `CkMechanismParams::Gcm` in `crates/types/src/mechanism.rs`; `canonical_shape_name` → `"gcm"` |
| 3 — conversions | Both `TryFrom` impls + `encode_r17_v1_params` `Gcm` arm behind `to_wire_with_transport_version` in `crates/proto/src/convert/mechanism/mod.rs`; `mechanism_gcm_round_trip` + `mechanism_gcm_empty_aad_round_trip` + `encode_v1_gcm` in `tests.rs` |
| 4 — reader | `Some("gcm")` arm + `read_gcm_struct_params` / `read_gcm_struct_params_v1` in `mechanism_read.rs`; `"gcm"` in the `is_r17_v1_shape` body |
| 5 — descriptor | `pointer_shape("gcm", GCM_FIELDS)` in `SHAPE_DESCRIPTORS` (`shape_descriptors.rs`) |
| 6 — manifest | `bind("gcm", &["GcmParams"], Complete, &[], V1)` in `SHAPE_BINDINGS`; `gcm` row in `R16_PRESENCE_TABLE`; union + `MANIFEST_DIGEST` pins |
| 7 — reconstruction | `CkMechanismParams::Gcm` arm in `mechanism_to_ffi_at_depth` + `FfiParamBacking::Gcm` in `crates/backend/src/ffi/ffi_conversion/mechanism.rs`; `gcm_null_flags_materialize_null_pointers` in `tests.rs` |
| 8 — validation | `P::Gcm` arms in `check_typed_presence`, `typed_has_nonzero_embedded_null`, `check_classic_sanitize_policy`, `zero_embedded_handles`; no-handle listings in `mechanism_handles.rs` |
| 9 — semantics | `output_fields = &[]` (empty by rule: only tail shapes carry the list); writable IV capacity via `gcm_iv_capacity` + `output_params` / `output_params_equal` `Gcm` arms; NULL/empty peers end to end |
| 10 — registry | `shape = "gcm"` + `0x1087 # CKM_AES_GCM` in `mechanism_params_default.toml` |
| 11 — tests | `variant: "Gcm"` in `shape_matrix.rs`; AES-GCM SoftHSM2 tests in `parameterized_mechanism_test.rs` |
| 12 — verify | Step-12 command block above |
