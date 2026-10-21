# Licensing and source provenance

The eight `pkcs11-proxy-ng` packages keep the project's `Apache-2.0 OR MIT`
license expression, with both license texts in each source archive. Those
licenses describe project-owned code. Source citations and third-party
notices below do not relicense upstream material under that expression.

## Historical mechanism table

`crates/backend/src/mock/historical_flags.rs` is a committed 105-row mock
workflow fallback table. The maintainer reports that its original development
used public-domain sources. Separately, all 105 numeric mechanism identifiers
were checked against the public-domain `vendor/pkcs11.h` used by
`cryptoki-sys 0.5.0` (header SHA-256
`109694093a511866c966d94b1a69f2bca0477e9041cfe883607cdc4f54100633`).
That agreement verifies identifiers, not the historical authorship of their
operation mappings. The table's behavior is retained; this source check is not
a legal-clearance or independent-rewrite claim.

## Other source references

The numeric PKCS#11 3.2 mechanism catalog in `crates/types` and the CLI names
table were derived through `pkcs11-check` from the [latchset public-domain 3.2
header at `c5e61990c5621a9b955fc208644fe8145ac0a75d`](https://github.com/latchset/pkcs11-headers/blob/c5e61990c5621a9b955fc208644fe8145ac0a75d/public-domain/3.2/pkcs11.h).
This is a separate public-domain numeric-header source.

The [coverage reference](../oasis-profile-coverage.md) records a dated
external-reference snapshot. Its OASIS Markdown and published headers are not
in this standalone repository or the eight source archives. Standard citations,
API identifiers, and numeric facts do not by themselves establish source-code
provenance. Genuine third-party source material keeps its own applicable terms.

The test-only [SoftHSM patch provenance](../../tests/consumers/backends/softhsm2-patched/PROVENANCE.md)
records the upstream source, tag, and license. Its derived test image carries
the upstream license with the installed provider. Normal proxy distributions
do not bundle a provider: an operator-supplied provider loaded from a local
path remains subject to that provider's own terms.

## Distribution boundary

Source `.crate` archives include both project license texts. A binary bundle
or package must carry applicable license and notice text for code actually
included in that target and artifact, including Rust dependencies and standard
library material. A Cargo SPDX field or `Cargo.lock` entry alone is not a
readable dependency notice.

`scripts/release_checks.py notices --build-inputs PATH --output DIR` uses a
prepared target build's exact Cargo metadata, feature tree, original locks,
checksum-bound crate archives, binary hashes, and Rust sysroot. It writes
`THIRD_PARTY_NOTICES`, `license-material/`, and `notice-inventory.json`.
The notice inventory records the input and portable provenance hashes, target,
toolchain, package source checksums, scopes, and every copied material hash.
Runtime, build, and Windows example/development edges are separate; ring's
full pinned-source supplement is marked conservative. An engineering graph
does not prove every source object was linked and is not legal clearance.

Three pinned published crates lack license files in their own archives:
`asn1-rs-impl 0.2.0`, `tonic-prost 0.14.6`, and
`tonic-prost-build 0.14.6`. For these exact versions, the generator checks
their published source revision and uses hash-verified upstream license files
from the reviewed `asn1-rs 0.7.2` or `tonic 0.14.6` sibling in the same
target graph. Other missing or empty upstream license material stops the
build. The selected Rust 1.98.1 sysroot must contain
`share/doc/rust/COPYRIGHT-library.html`; its exact hash is recorded.

The dependency notice review was refreshed on 2026-10-21 against the exact
published `.crate` bytes and their `Cargo.lock` SHA-256 checksums:

- `asn1-rs-impl 0.2.0` still records revision
  [`a20e5f7`](https://github.com/rusticata/asn1-rs/tree/a20e5f7319c896737ad0f2557037817b91ad854f).
  Its reviewed root `LICENSE-APACHE` and `LICENSE-MIT` files are byte-identical
  to both the old `asn1-rs 0.7.1` donor and the new `asn1-rs 0.7.2` archive,
  whose revision is
  [`84c7ac4`](https://github.com/rusticata/asn1-rs/tree/84c7ac4cc40616497d922c7e5730fb75cff59256).
  The existing two license hashes and the leaf revision guard are unchanged.
- `tonic-prost`, `tonic-prost-build`, and their `tonic` donor at `0.14.6`
  all record revision
  [`6cb6056`](https://github.com/hyperium/tonic/tree/6cb6056b5a748bc5a29bd48f4602dbc4e552bb7d).
  The leaf archives still omit standalone license files. The donor `LICENSE`
  matches that revision's root license and the previous `0.14.5` donor
  byte-for-byte, so its existing SHA-256 guard is unchanged.
- `rustls-webpki 0.103.16` records revision
  [`8ecdcc7`](https://github.com/rustls/webpki/tree/8ecdcc76f56b68fda67a6adf7976f5eed5006a4c).
  Its `LICENSE`, all collected copyright headers, and every module/test file
  checked by the notice generator are byte-identical to `0.103.15`.
  The Chromium algorithm fixtures and adapted DNS cases remain test-only;
  production CRL and subject-name copyright notices remain required. The
  patch adds certificate public-key distrust data, not a new license file
  or a change to that Chromium source boundary. Only the exact reviewed
  version guard changes; other versions still require a fresh review.

Linux and Windows bundles contain both project licenses, all generated
notice material, the notice inventory, and portable build provenance alongside
the binaries. APK and RPM daemon, CLI, and shim subpackages each install those
materials under `/usr/share/licenses/<subpackage>/`. The symlink-only compat
subpackage requires the exact shim version. OS package builds use
`workspace-notices` to record their own local target/feature closure and
`source_mode=workspace`; this cannot establish registry-source binary
provenance. Archive-mode pre-publication bundles likewise remain candidates.
Registry publication is gated separately on all eight verified source
archives and the final binary-provenance checks.

System libraries, Microsoft runtime DLLs, and operator-provided PKCS#11
modules are external runtime prerequisites where dynamically supplied.
Normal bundles and these OS packages do not silently copy them.
