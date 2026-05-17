# OASIS coverage completion audit

Date: 2026-05-17

Status: internal coverage complete; provider-backed gaps remain separate

This document maps the active OASIS coverage goal to concrete artifacts. It is
not a provider-conformance claim and does not replace the generated inventory.
Its job is to make the internal MockBackend/proxy decisions, intentional
unsupported rows, and remaining provider artifact gaps visible.

## Current generated counts

- Official PKCS#11 functions in OASIS inventory: 110
- Represented standard function-list fields: 104
- Standard interface catalog entries: 3
- Official mechanism values from published headers: 463
- Official mechanism names/aliases in matrix: 479
- Provider-gap mechanism names/aliases: 164
- Spec-only `C_DigestXof*` functions without local function-list ABI slots: 6
- Spec parameter structs in OASIS inventory: 64
- Mechanism parameter shapes: 79
- Message parameter shapes: 3
- Source-grounded MockBackend semantic rows covered: 358
- Actionable MockBackend semantic gaps: 0
- Intentional no-source workflow rejections: 121
- Intentional unsupported function-list gaps: 6
- Intentional unsupported numeric-value gaps: 6
- Intentional unsupported workflow gaps: 121
- Internal completion open items: 0
- Strict completion open items including provider gaps: 164

## Prompt-to-artifact checklist

| Requirement | Evidence | Status |
| --- | --- | --- |
| Source-grounded OASIS inventory for functions, interfaces, mechanisms, aliases, parameters, and gaps | `scripts/oasis-coverage-inventory.py`, `doc/oasis-profile-coverage.md` | Covered by generated JSON/Markdown plus `local_quality_gate_test` inventory checks |
| Machine-readable completion gap summary | `completion_gap_summary` in `scripts/oasis-coverage-inventory.py --format json`; includes `missing_local_test_citation_counts`, `intentional_unsupported_function_list_gap_names`, `intentional_unsupported_function_list_gap_count`, `intentional_unsupported_numeric_value_gap_names`, `intentional_unsupported_numeric_value_gap_count`, `intentional_unsupported_workflow_gap_names`, `intentional_unsupported_workflow_gap_count`, `strict_completion_open_items`, `strict_completion_open_item_counts`, `internal_completion_open_item_count`, `strict_completion_open_item_count`, `actionable_mockbackend_semantic_gap_count`, `intentional_no_source_workflow_rejection_count`, working-spec mechanisms without published values, no-source workflow rows, provider gaps, and missing parameter-shape counts | Covered as a derived summary of existing matrices; useful for audit triage but not a completion claim by itself |
| Published-header annotations are preserved instead of flattened away | Mechanism matrix rows expose published-header annotations, including `Historical` and `Deprecated`, so source status can distinguish official-but-historical/deprecated mechanisms from unsupported or vendor-defined entries | Covered by generated inventory checks; annotations are evidence only, not workflow inference |
| XOF APIs need a deliberate function-list/ABI decision | `C_DigestXof*` rows in the function matrix carry `cryptoki_sys_missing_function_list_field` and `do_not_add_out_of_band_exports_or_custom_function_list_layout`; ignored loaded-shim test `loaded_shim_does_not_export_digest_xof_out_of_band_symbols` checks no out-of-band exports exist | Explicitly tracked; not implemented as non-standard exports |
| SP800-108 multi-output handles need deeper modeling | `doc/mock-backend-mechanism-workflow-audit.md`, SP800-108 tests cited by the parameter-shape matrix | Covered for Counter, Feedback, and Double Pipeline additional output handles, error-output writeback, key-handle data params, quota all-or-nothing behavior, and session-object cleanup |
| Provider-backed gaps remain separate from internal MockBackend coverage | `provider_mechanism_summary` in `scripts/oasis-coverage-inventory.py`, `doc/oasis-profile-coverage.md` | Covered; provider-backed gaps remain separate from MockBackend internal coverage |
| MockBackend deterministic internal coverage for official mechanism catalog | `doc/mock-backend-mechanism-workflow-audit.md`, backend tests cited from the mechanism matrix, `MockBackend::with_official_mechanism_catalog_smoke()` | Covered as catalog smoke for represented published mechanism names/aliases; working-spec-only names without numeric values stay unadvertised |
| Source-grounded MockBackend semantic workflow coverage | `mock_backend_internal_coverage.workflow_semantics_status`, `semantic_constructor`, `source_grounded_workflow_enforcement_test`, `source_grounded_workflows`, backend test `official_source_grounded_mock_enforces_mechanism_workflow_flags`, and exhaustive no-source rejection test `official_source_grounded_mock_rejects_all_no_source_workflow_mechanisms` | Covered only where OASIS workflow evidence exists; `MockBackend::with_official_mechanisms()` rejects workflows without source-backed flags and catalog smoke coverage is not semantic coverage |
| Internal shim/backend/gRPC coverage for mutable and output parameters | `doc/oasis-profile-coverage.md`, ignored loaded-shim tests, MockBackend gRPC tests, shim helper tests | Covered for modeled safe shapes; unsafe lengthless caller pointers are intentionally rejected |
| Verification gate before any completion claim | `scripts/test-matrix.sh --fast-only` plus focused loaded-shim ignored tests when C ABI writeback is touched | Required before completion; passing the gate alone is not enough to close this goal |

## Remaining Provider And Intentional Gaps

- Actionable MockBackend semantic gaps are zero. That is not a standalone
  conformance claim; it means source-grounded MockBackend semantic rows are
  covered according to the current inventory policy.
- The generated inventory still has six spec-only `C_DigestXof*` functions
  because the current published OASIS function-list headers and local
  `cryptoki-sys` function-list structs do not expose standard ABI slots. These
  rows are classified as intentional unsupported function-list gaps, not strict
  open implementation gaps, because the local ABI decision is explicit and
  tested.
- Six working-spec mechanism names do not have published numeric
  `CK_MECHANISM_TYPE` values in the vendored headers. They remain visible in
  the matrix with the policy not to assign project-local values, and are
  classified as intentional unsupported numeric-value gaps rather than strict
  open implementation gaps.
- Mechanism-info flags and source-grounded MockBackend workflow acceptance are
  source-grounded only where the vendored sources provide workflow evidence.
  Rows without such evidence keep zero flags, are rejected by
  `MockBackend::with_official_mechanisms()`, and carry a
  `do_not_infer_ckf_flags_from_mechanism_name_or_header_presence` decision.
  The exhaustive backend test
  `official_source_grounded_mock_rejects_all_no_source_workflow_mechanisms`
  pins that rejection behavior across mechanism-bearing workflows. These rows
  are intentional unsupported workflow gaps, not internal open implementation
  gaps.
- The all-official MockBackend workflow tests are catalog-smoke coverage for
  advertised `CKM_*` values. They do not become semantic workflow coverage for
  the 121 mechanism-info rows where OASIS gives no source workflow evidence.
- Provider-backed validation is still separate from internal MockBackend
  coverage. Current provider artifacts leave 164 official mechanism
  names/aliases as provider gaps.
- The generated strict open-item count is 164 when provider gaps are included,
  and 0 for internal inventory/proxy decisions before provider evidence.

## Completion Rule

This internal coverage goal is complete only together with the generated
inventory and verification evidence: every explicit internal requirement is
implemented with evidence or intentionally unsupported with source-grounded
reasoning and tests that prevent silent drift. Provider artifact gaps remain
tracked separately and do not imply missing MockBackend/proxy behavior.
