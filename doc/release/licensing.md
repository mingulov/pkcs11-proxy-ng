# Licensing and source provenance

The eight `pkcs11-proxy-ng` packages keep the project's `Apache-2.0 OR MIT`
license expression, with both license texts in each source archive. Those
licenses describe project-owned code. Source citations and third-party
notices below do not relicense upstream material under that expression.

## Historical mechanism table

`crates/backend/src/mock/historical_flags.rs` is a 105-row Rust workflow table
derived from the Mechanisms-vs-Functions table in [PKCS #11 Cryptographic
Token Interface Historical Mechanisms Specification Version 3.0, OASIS
Standard, 15 June 2020](https://docs.oasis-open.org/pkcs11/pkcs11-hist/v3.0/os/pkcs11-hist-v3.0-os.html).
The published `/os/` URL is the canonical immutable citation. The generator's
actual cached HTML input, `pkcs11-hist/v3.0/pkcs11-hist-v3.0.html`, had SHA-256
`53db1b1fe37e61d74ea2bc86742019e85a25aac8fc648e884abbb204858cf47c`.
That cached file is not asserted to be byte-identical to the official `/os/`
HTML. The numeric input was the OASIS checkout's
`published/2-40-errata-1/pkcs11t.h` at git revision
`48fa09240cc64ec1cd4c559b6af6642a2cdd13ae`, SHA-256
`5b58736b6d23f12b4d9492cd24b06b9d11056c3153afc4e89b1fe564749e71a2`.
The generated table and generator record these separate origins. Regeneration
requires externally supplied source inputs; ordinary builds, tests, and crate
packaging use the committed Rust file and fetch no OASIS source.

The complete OASIS copyright and Notices section accompanies the table in
[`crates/backend/NOTICE`](../../crates/backend/NOTICE), including in the
backend source archive. Binary distributions containing this table must also
carry the applicable notice. Attribution and the package metadata's treatment
of the derived table remain a release-qualification review item; the published
Notices permit implementation-assisting derivatives with notice carriage and
do not, by themselves, settle every characterization or metadata question.

## Other source references

The numeric PKCS#11 3.2 mechanism catalog in `crates/types` and the CLI names
table were derived through `pkcs11-check` from the [latchset public-domain 3.2
header at `c5e61990c5621a9b955fc208644fe8145ac0a75d`](https://github.com/latchset/pkcs11-headers/blob/c5e61990c5621a9b955fc208644fe8145ac0a75d/public-domain/3.2/pkcs11.h).
This is a separate numeric-header source from the OASIS historical table.

The [OASIS coverage inventory](../oasis-profile-coverage.md) counts an
external reference snapshot supplied to the optional inventory script. Its
OASIS Markdown and published headers are not in this standalone repository or
the eight source archives. Normal PKCS#11 standard citations, API identifiers,
and numeric facts should be distinguished from copied upstream prose, tables,
or headers; copied material needs its own source attribution and applicable
notice review.

The test-only [SoftHSM patch provenance](../../tests/consumers/backends/softhsm2-patched/PROVENANCE.md)
records the upstream source, tag, and license. Its derived test image carries
the upstream license with the installed provider. Normal proxy distributions
do not bundle a provider: an operator-supplied provider loaded from a local
path remains subject to that provider's own terms.

## Distribution boundary

Source `.crate` archives include project license texts; the backend archive
also includes the OASIS `NOTICE`. A binary bundle or package has a different
obligation: it must carry notices and license text for code actually included
in that target and artifact, including applicable Rust dependency and standard
library material. A Cargo SPDX field or `Cargo.lock` entry alone is not a
readable dependency notice. The separate binary-notice work must derive the
dependency closure for each release target and verify final bundle and package
contents; this source-provenance document is not that inventory.
