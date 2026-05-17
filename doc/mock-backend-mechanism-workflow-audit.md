# MockBackend mechanism workflow audit

Date: 2026-05-17

## Scope

`MockBackend` is a deterministic PKCS#11 protocol simulator. It is not a
cryptographic provider and should not try to implement the real algorithmic
semantics of every mechanism. Its job is to make proxy workflows testable
without host-specific HSM or software-token state.

For mechanism support, "complete" means:

- every mechanism registered in the embedded mechanism registry can be
  advertised by `MockBackend`;
- every official PKCS#11 v3.2 mechanism ID can be advertised by explicit
  all-official simulator constructors, even when no provider in the local
  `pkcs11-check` artifact matrix exposes it;
- vendor override mechanisms can be included by passing an explicit
  `MechanismRegistry`;
- every advertised mechanism can exercise catalog-smoke backend workflows
  without `CKR_MECHANISM_INVALID`;
- the source-grounded all-official constructor rejects workflows that are not
  present in the mechanism's source-backed `CK_MECHANISM_INFO` flags;
- exact-output `C_WrapKey` can exercise every advertised mechanism;
- PKCS#11 3.x provider-gap workflows have deterministic internal simulator
  coverage, rather than depending only on `TestBackend3x`;
- provider-specific output-parameter behavior is modeled by explicit hooks,
  not by hard-coding a real provider.

The local `../pkcs11-check/artifacts/*/coverage.json` snapshot was used as
provider-gap input. The generated inventory now emits provider-summary counts
from the same mechanism matrix used for per-row coverage. In the current
snapshot, 463 unique official mechanism values were parsed from the PKCS#11
v3.2 headers and expanded to 479 official mechanism names/aliases in the matrix;
315 of those names/aliases are advertised by at least one artifact-backed
provider and 164 are not. Examples include
`CKM_HASH_ML_DSA`, `CKM_SLH_DSA`, WTLS key-material mechanisms,
`CKM_AES_XCBC_MAC_96`, `CKM_XMSSMT`, and `CKM_PUB_KEY_FROM_PRIV_KEY`.

OASIS source inconsistencies are part of the audit surface. MockBackend
coverage should be extended from concrete source evidence: published numeric
IDs, concrete C ABI structs, and function-list fields where they exist. Working
spec prose that lacks those details is tracked as an explicit gap, alias, or
placeholder instead of being promoted into a local ABI by assumption.

## Audit Findings

| Area | Finding | Resolution |
|------|---------|------------|
| Registry inventory | The mechanism registry had no public way to return the full registered mechanism set. | Added `MechanismRegistry::registered_mechanisms()`, sorted and deduplicated. |
| Full-registry mock | `MockBackend` had no constructor for "all proxy-known official mechanisms" or vendor override registries. | Added `MockBackend::with_mechanism_registry()` and `MockBackend::with_default_mechanism_registry()`. |
| Official mechanism inventory | The default registry intentionally tracks proxy-understood parameter shapes, not every official mechanism ID, so provider-gap IDs had no stable simulator catalog. | Added a generated PKCS#11 v3.2 official mechanism inventory, `MockBackend::with_official_mechanism_catalog_smoke()` for broad protocol exercise, and `MockBackend::with_official_mechanisms()` for source-grounded workflow enforcement. |
| Vendor support | Tests could not build a mock backend from an override registry containing vendor mechanisms. | Added vendor override coverage for parameterless and AES-GCM-shaped vendor mechanisms. |
| Slot-scoped workflows | `C_InitToken` and `C_CloseAllSessions` could succeed against a slot ID that the mock did not advertise. | Added `slot_scoped_workflows_reject_invalid_slot`; those paths now return `CKR_SLOT_ID_INVALID` for unknown slots without closing sessions on known slots. |
| Workflow flags | `get_mechanism_info` previously used a broad simulator flag mask instead of mechanism-specific source evidence, which could overstate unsupported workflows. The OASIS sources are not fully consistent here: for example the working AES table spells `CKM_AES_EC` while the published headers define `CKM_AES_ECB`, some AES mode prose is narrower than the mechanism/function tables, the GCM/CCM and ChaCha20/Salsa20-Poly1305 tables omit message-operation marks even though the same spec files define message-operation flows, the Poly1305 mechanism summary table conflicts with its MAC prose and C_Sign/C_Verify function table, PBE uses a combined `GENK & GENKP` table column while the prose defines key/IV generation, `CKM_CAMELLIA_CTR` has parameters/header values without a current workflow-table row, current working Markdown gives example-backed workflow evidence for `CKM_DES_KEY_GEN`, `CKM_DES_ECB`, `CKM_DES_CBC_PAD`, and `CKM_DES_MAC` but not enough evidence for `CKM_DES_CBC` or `CKM_DES_MAC_GENERAL`, and `CKM_ECDSA_KEY_PAIR_GEN` is a deprecated published alias not named in the working EC workflow table. The mechanism-table `ENCS`/`DECS` column is encapsulate/decapsulate, not message encrypt/decrypt. | Mock mechanism info now has source-grounded flags for the proxy seed mechanisms, includes the official PKCS#11 3.x message-operation, KEM, EC-capability, and extension flag constants, maps the AES-ECB typo to the published `CKM_AES_ECB` value, uses explicit AES/ARIA/Camellia/SEED/DES-family/Blowfish/Twofish/EC/DH/X9.42/RSA/GOST/PBE/CMS/null/ratchet mechanism-function tables, adds example-backed single-DES key generation, ECB/CBC-PAD encryption/decryption, and MAC sign/verify rows, adds the generic-secret GENK row, simple-key-derivation DRV rows, HKDF GENK/DRV rows, CT-KIP DRV/WRP/SIG rows, IKE DRV rows, SHAKE key-derivation DRV rows, OTP GENK/SIG rows, HSS/XMSS stateful hash signature GENKP/SIG rows, historical MD digest rows, deprecated MD2/MD5/RIPEMD RSA hash-signature SIG rows, and SSL/TLS/WTLS GENK/DRV/SIG rows where the working spec has mechanism-function table evidence or, for deprecated `CKM_TLS_PRF`, explicit C_DeriveKey prose evidence, uses GCM/CCM and ChaCha20/Salsa20-Poly1305 prose evidence for message encrypt/decrypt flags, uses Poly1305 MAC prose/function-table evidence for sign/verify instead of the conflicting summary row, keeps PBE/PBKD2 as generate-only based on key/IV-generation prose, and uses the `ENCS`/`DECS` mechanism-table column for KEM/RSA/EC/DH encapsulate and decapsulate flags. Mechanisms whose workflow flags are not source-grounded return an empty flag mask rather than an invented all-workflows mask. |
| Mechanism-info flag coverage matrix | Generic MockBackend workflow tests could make `C_GetMechanismInfo` look semantically complete even when mechanism-specific flags were still missing. | The generated inventory now has a dedicated mechanism-info flag coverage matrix. It maps source workflow columns and explicit source-discrepancy overrides to expected `CKF_*` flags, records source-grounded local tests separately from no-source-evidence rows, and currently reports 358 represented mechanisms with expected flags, 358 source-grounded mechanism-info flag rows, and 0 not-yet-source-grounded rows. The remaining 121 no-source rows are deliberately split into 119 published-header-only gaps and 2 working-Markdown-without-workflow gaps; each carries a `source_gap_decision` that cites the checked evidence and pins the policy not to infer `CKF_*` flags from mechanism names or header presence alone. Backend, gRPC, and loaded-shim C ABI tests pin representative zero-flag behavior, including `CKM_CAMELLIA_CTR` and `CKM_DES_CBC` for the two working-Markdown/no-workflow rows; an exhaustive backend test also rejects every zero-flag official mechanism across mechanism-bearing workflows through `MockBackend::with_official_mechanisms()`. These rows are reported as intentional unsupported workflow gaps rather than open MockBackend implementation gaps. The mechanism matrix now also separates `catalog_smoke_workflows` from `source_grounded_workflows`, lists the semantic constructor and enforcement test, and keeps all-official catalog runs from being counted as semantic workflow evidence for header-only or otherwise incomplete OASIS rows. |
| Mechanism catalog semantics | Mechanism-bearing operations could succeed with a mechanism the session's slot did not advertise, making the mock catalog weaker than real token behavior. Source-grounded mechanisms could also use workflows that their own `CK_MECHANISM_INFO` flags did not advertise. | Added `mechanism_bearing_workflows_reject_unadvertised_mechanisms`; mechanism-bearing init, key, wrap, KEM, message-init, authenticated-wrap, and exact-output paths now return `CKR_MECHANISM_INVALID` for unadvertised mechanisms. Added `official_source_grounded_mock_enforces_mechanism_workflow_flags`; `MockBackend::with_official_mechanisms()` now rejects unsupported workflows such as sign with AES keygen, encrypt with SHA-256 digest, encrypt with ML-KEM, and any operation for no-source rows such as `CKM_BATON_KEY_GEN`, while accepting source-backed workflows such as AES-GCM encrypt/decrypt/wrap/message-encrypt and ML-KEM encapsulate/decapsulate. Broad all-official core/exact-output simulator tests use `MockBackend::with_official_mechanism_catalog_smoke()` explicitly. |
| Session mechanism-output lifecycle | The new session-level mechanism-output cache was not cleared on close/finalize. | Cache is now cleared on `close_session`, matching-slot `close_all_sessions`, and `finalize`. |
| Core workflows | There was no single test proving every registered mechanism can traverse core mock workflows. | Added full-registry workflow coverage across sign, verify, digest, encrypt, decrypt, derive, generate, wrap, and unwrap. |
| Exact-output workflows | Exact output paths are mechanism-bearing and need size-query/data-query coverage across the simulator catalog, not only one-off mechanism examples. | Added full-registry exact wrap coverage and all-official exact-output coverage for byte-output, handle-output, and parameter-output workflows. |
| PKCS#11 3.x workflows | `MockBackend` itself still returned `CKR_FUNCTION_NOT_SUPPORTED` for several message, KEM, authenticated-wrap, verify-signature, session-extension, and async methods; tests used `TestBackend3x` instead. | Added deterministic MockBackend implementations for those workflows and a provider-gap workflow test. KEM encapsulation now returns a live mock object with template attributes on successful data queries, while exact size-query and buffer-too-small calls return no key handle and do not allocate a hidden object. MockBackend now also reports 2.40, 3.0, and 3.2 interface capabilities by default, so loaded-shim C ABI tests can reach the 3.2 function list through the normal endpoint-probed catalog. |
| Source inventory drift | The project had no generated check comparing vendored OASIS Markdown/published headers with local function lists, interface entries, mechanism parameter shapes, message parameter shapes, and layer wiring. | Added `scripts/oasis-coverage-inventory.py` and local quality tests. The current matrix finds 110 spec functions, 104 published/local function-list fields, three standard `PKCS 11` interface entries, 79 modeled mechanism parameter shapes, three message parameter shapes, 64 spec mechanism parameter structs, six explicit `C_DigestXof*` spec-only function gaps, 463 published mechanism values, 119 published-header mechanism names or aliases absent from working Markdown, and six working-spec mechanism names without published numeric values. Header-only official mechanisms are marked represented with `oasis_published_header_not_in_working_markdown`; published-header `Historical` and `Deprecated` annotations are exposed per mechanism name/alias so old official rows stay visible without inferred workflow support. Working-spec-only mechanisms without numeric values remain spec-only with `oasis_working_spec_lacks_published_numeric_value`, carry `do_not_assign_project_local_ckm_values_for_working_spec_names`, and are classified as intentional unsupported numeric-value gaps so MockBackend does not invent colliding `CKM_*` values. `C_DigestXof*` rows now carry a structured local ABI decision that cites the working spec declaration, all published `pkcs11f.h` headers checked, the local function-list field table, the generated inventory guard, an ignored loaded-shim export-surface test, and the policy not to add custom out-of-band exports or non-standard `CK_FUNCTION_LIST` layouts. Mechanism-row parameter struct associations are parsed from source-local prose instead of file-wide `CK_*PARAMS` tokens, so parameterless mechanisms such as `CKM_AES_KEY_GEN`, `CKM_AES_MAC`, `CKM_RSA_PKCS`, and `CKM_SHA1_RSA_PKCS` do not inherit unrelated AES/RSA parameter structs from the same Markdown file. `C_GetFunctionList`, `C_GetInterfaceList`, and `C_GetInterface` are marked as shim-local function catalog entry points with local ABI tests instead of being counted as missing proxy-layer RPCs. Every represented function row cites local test evidence, and the JSON matrix reports stale function test citations through `local_tests_missing`. |
| Default mechanism registry placeholders | The embedded mechanism-parameter registry used placeholder values for EC and IKE shapes, and some placeholders collided with published mechanisms such as `CKM_DES3_ECB_ENCRYPT_DATA`, BLAKE2B key mechanisms, `CKM_SALSA20`, and `CKM_X3DH_INITIALIZE`. | Default registry entries now use published `CKM_*` values only. IKE shapes use the OASIS v3.1/v3.2 values at `0x402e..0x4031`, Salsa20 and DES/DES3 ECB encrypt-data map to their real parameter shapes, `CKM_ECMQV_DERIVE` maps to `CK_ECMQV_DERIVE_PARAMS`, and `CK_ECDH2_DERIVE_PARAMS` stays represented as a typed transport/helper shape without a default project-local mechanism value. |
| MockBackend inherited trait defaults | Official functions inherited from `Pkcs11Backend` defaults could look like unreviewed missing simulator coverage. | Added `mock_backend_default_trait_decisions` to the generated inventory. It derives inherited default error returns from the trait and `MockBackend` implementation, currently records only `C_GetFunctionStatus` and `C_CancelFunction` returning `CKR_FUNCTION_NOT_PARALLEL`, and cites backend unit coverage. |
| Parameter-shape gaps | The project did not have a row-per-shape comparison for Rust/proto/FFI/shim safety, so unmodeled official parameter structs were easy to hide behind broad mechanism coverage. | The generated parameter-shape matrix now records Rust enum variant, Rust struct, OASIS `CK_*PARAMS` evidence, proto message and oneof field, backend FFI conversion, shim read/writeback support, mutable-output behavior, nested SP800-108 input/output handles, explicit unsupported reasons for raw/vendor-only shapes, structured shim-read safety decisions for official structs with unbounded caller-owned pointers, explicit aliases, and explicit placeholder exclusions. `CK_EXTRACT_PARAMS`, `CK_KMAC_PARAMS`, and `CK_MU_GEN_PARAMS` are now represented by typed parameter shapes; raw IV parameters, scalar `CK_OBJECT_HANDLE` parameters, `CK_KEY_DERIVATION_STRING_DATA`, and `CK_SIGN_ADDITIONAL_CONTEXT` now cite local proto, backend-FFI, and shim-read evidence. Unsupported raw and vendor-specific transport-only parameter variants now cite backend FFI rejection coverage, so the rows are executable `CKR_MECHANISM_PARAM_INVALID` decisions rather than uncited classifications. `CK_X3DH_*`, `CK_X2RATCHET_*`, and `CK_CMS_SIG_PARAMS` rows carry `do_not_parse_unbounded_caller_pointers_in_shim`; helper and loaded-shim C ABI tests prove direct C-stack calls return `CKR_MECHANISM_PARAM_INVALID` instead of guessing lengths. MockBackend now validates the X3DH/X2Ratchet fields that OASIS defines as object handles during derive workflows while leaving lengthless byte-pointer fields opaque, validates EC/X9.42 dual-party derive `hPrivateData` handles and MQV `publicKey` handles, validates nonzero CMS `certificateHandle` values across sign/verify/recover init workflows while accepting zero as the absent-certificate transport value, validates the scalar `CKM_CONCATENATE_BASE_AND_KEY` object-handle parameter, and validates CT-KIP `hKey` only for derive/MAC because the wrap prose says the field is unused there. `CK_CHACHA20POLY1305_PARAMS` is classified as a working-spec prose alias for the published `CK_SALSA20_CHACHA20_POLY1305_PARAMS`; `CK_XXX_MESSAGE_PARAMS` is classified as authenticated-wrap prose placeholder text, not a concrete ABI struct; message-operation structs such as GCM, CCM, and Salsa/ChaCha Poly1305 are split into a message-parameter matrix instead of being counted as `CK_MECHANISM` gaps, and those rows cite MockBackend typed exact-path tests for structured parameter writeback. |
| Provider vs. internal evidence | Provider artifact gaps and MockBackend workflow coverage were described in prose but not separated on each mechanism row. | The generated mechanism matrix now carries provider artifact status separately from `mock_backend_internal_coverage`, including the tests that advertise every official mechanism and run the official catalog through core and exact-output simulator workflows. It labels those broad runs as catalog-smoke coverage and records `workflow_semantics_status`, semantic constructor, workflow-enforcement test, and `semantic_limitation` next to them. |
| Operation cancel lifecycle | `session_cancel` cleared active operations and `mechanism_out` but did not clear the separate `C_VerifySignature*` state maps. | Added `session_cancel_clears_all_session_scoped_mock_state` and centralized session-side-state cleanup. |
| AES-GCM encrypt `mechanism_out` workflows | The internal gRPC coverage exercised init-time GCM output, one-shot encrypt, and exact-output encrypt/writeback, but did not call the multipart `C_EncryptUpdate`/`C_EncryptFinal` response fields that were wired for mechanism-output propagation. MockBackend also lacked a hook for late simple/multipart encrypt output outside the exact-output shim path. | Added `multipart_encrypt_returns_cached_gcm_output_params_through_grpc`, `simple_encrypt_returns_late_gcm_output_params_through_grpc`, and `multipart_encrypt_returns_late_gcm_output_params_through_grpc`, and cited them from the generated parameter-shape matrix. MockBackend can now cache synthetic GCM output after successful simple/multipart encrypt operations, so internal tests can exercise CloudHSM-style delayed mechanism output without relying on provider patches. This is simulator behavior, not a cryptographic correctness claim. |
| Object and key workflows | Several object/key creation paths allocated live handles but discarded caller templates, so internal tests could not inspect attributes on generated, derived, copied, unwrapped, decapsulated, or key-pair objects. Some object-management and key-producing paths also accepted invalid sessions or invalid source handles and could allocate, mutate, or report success; key-pair generation could leave a partial public object when the private allocation hit the mock object quota. | `C_CreateObject`, `C_CopyObject`, `C_GenerateKey`, `C_DeriveKey`, `C_UnwrapKey`, authenticated unwrap, KEM encapsulate/decapsulate, and `C_GenerateKeyPair` now preserve caller template attributes where they return objects, reject invalid sessions with `CKR_SESSION_HANDLE_INVALID`, and do not allocate hidden objects on invalid-session failures. Object find, attribute read/exact read, size, set-attribute, copy-source, and destroy paths reject invalid object handles with `CKR_OBJECT_HANDLE_INVALID`; live objects that have no mock attribute-store entry still return the existing no-op attribute-read behavior. Key-pair generation preflights capacity for both handles and returns `CKR_DEVICE_MEMORY` without leaking a partial object. |
| Stateless session workflows | Several deterministic no-op or synthetic-output paths ignored the session handle, so invalid-session tests could miss mocked success for PIN, recover, random, wrap, authenticated-wrap exact, and combined update workflows. | Added `stateless_session_workflows_reject_invalid_session`; these paths now require an open session before returning `CKR_OK`, exact-output metadata, random bytes, or synthetic wrapped/recovered data. |
| DeriveKey output parameters | TLS/WTLS/PBE mutable parameter writeback was harder to exercise through MockBackend than through one-off unit doubles. | Added `MockBackend::set_derive_key_output`, backend unit tests for TLS/PBE/WTLS output params, MockBackend gRPC tests for PBE IV, TLS/WTLS `pVersion`, and SSL3/TLS/WTLS key-material handle/IV `mechanism_out`, plus shim helper coverage for caller-stack writeback. |
| SP800-108 multi-key derives | `CK_SP800_108_*_KDF` modeled only PRF/data params, missed nested `CK_DERIVED_KEY[]`, and mapped feedback mode to the non-IV parameter shape. | Added SP800-108 additional-derived-key modeling across types/proto/FFI/shim, split feedback KDF into its IV-bearing parameter shape, added MockBackend/gRPC plus loaded-shim C ABI coverage for synthetic additional key handles across Counter, Feedback, and Double Pipeline KDF modes, records each additional handle as a live mock object with its template attributes available through exact attribute queries, resolves/validates `CK_PRF_DATA_PARAM` entries of type `CK_SP800_108_KEY_HANDLE` before backend calls, enforces source-grounded SP800-108 PRF-type allow-list validation, mode data-param rules for mandatory `CK_SP800_108_ITERATION_VARIABLE`, Counter Mode rejection of `CK_SP800_108_COUNTER`, counter/DKM payload sizes, DKM length method values, non-empty `CK_SP800_108_BYTE_ARRAY`, and singleton counter/DKM fields, and preflights primary-plus-additional object quota so failed derives do not leave partial mock objects behind. Feedback and Double Pipeline iteration-variable payloads deliberately accept both NULL/0 and counter-format shapes because the OASIS field prose conflicts with the mode tables/examples. The generated inventory also marks and cites the source-defined error-output behavior: a template-caused multi-key failure sets the corresponding `CK_DERIVED_KEY.phKey` to `CK_INVALID_HANDLE`, with MockBackend, gRPC, FFI backend result-shape, and loaded-shim C ABI support for carrying `mechanism_out` on non-`CKR_OK` returns. |
| Session object lifecycle | Mock object handles were global once allocated, so session objects created by derive/generate/unwrap/KEM paths could outlive `C_CloseSession`, and destroyed objects could leave stale template attributes in the mock attribute store. | Added session-object ownership tracking keyed by creating session. Objects without `CKA_TOKEN=true` are removed, with their stored attributes, on `close_session`, `close_all_sessions`, and `finalize`; token objects remain until explicit destroy/finalize. The loaded-shim SP800-108 C ABI test now leaves primary and additional derived session keys live through `C_CloseSession`, opens a fresh session, and verifies the old caller-visible handles return `CKR_OBJECT_HANDLE_INVALID`. |

## Vendor Behavior Model

Mock vendor/provider behavior is intentionally hook-driven:

- init-time output params: `set_encrypt_init_output`;
- late `C_Encrypt` output params: `set_encrypt_exact_output`;
- late `C_WrapKey` output params: `set_wrap_key_exact_output`;
- `C_DeriveKey` output params: `set_derive_key_output`;
- vendor mechanism catalog: pass an override-aware `MechanismRegistry` to
  `MockBackend::with_mechanism_registry`.

This allows CloudHSM-style and SoftHSM-style flows to be tested locally
without pretending that the mock performs real AES-GCM, TLS, KEM, or
vendor-specific cryptography.

The all-official constructors are intentionally separate from the mechanism
parameter registry. `MockBackend::with_official_mechanism_catalog_smoke()`
gives protocol and exact-output tests a full permissive catalog of official
mechanism IDs. `MockBackend::with_official_mechanisms()` uses the same catalog
but enforces source-grounded workflow flags before accepting
mechanism-bearing operations. Both leave parameter-shape validation
conservative: unknown pointer-bearing mechanism parameters are still not
treated as safely modeled by default.

## Non-Goals

- Real cryptographic correctness for every mechanism.
- A conformance claim for every provider.
- Replacing SoftHSM2, NSS softokn, Kryoptic, or real HSM provider tests.
- Treating vendored-spec entries that are absent from current `cryptoki-sys`
  function-list structs as implemented. The `C_DigestXof*` family is tracked
  as a source-level gap with the generated
  `cryptoki_sys_missing_function_list_field` reason and a structured
  `local_abi_decision`; it stays unimplemented until the standard function-list
  ABI surface exists locally.
- Advertising working-spec mechanism names before they have a concrete
  published `CK_MECHANISM_TYPE` value in the vendored OASIS headers. These rows
  carry a structured local numeric decision instead of project-assigned `CKM_*`
  values.
- Treating published-header mechanisms that are absent from working Markdown as
  local implementation-only behavior. They remain official source evidence and
  carry an explicit source-discrepancy reason in the generated matrix.

Real provider validation remains in provider-backed integration lanes.

## Verification Targets

Focused gates for this audit:

```bash
cargo test -p pkcs11-proxy-ng-types registered_mechanisms_returns_parameterless_and_parameterized_union -- --nocapture
cargo test -p pkcs11-proxy-ng-types official_mechanisms_include_provider_gap_examples -- --nocapture
cargo test -p pkcs11-proxy-ng-types standard_simple_key_derivation_constants_match_spec -- --nocapture
cargo test -p pkcs11-proxy-ng-types standard_hkdf_constants_match_spec -- --nocapture
cargo test -p pkcs11-proxy-ng-types standard_kip_constants_match_spec -- --nocapture
cargo test -p pkcs11-proxy-ng-types standard_ike_constants_match_spec -- --nocapture
cargo test -p pkcs11-proxy-ng-types standard_shake_key_derivation_constants_match_spec -- --nocapture
cargo test -p pkcs11-proxy-ng-types standard_otp_constants_match_spec -- --nocapture
cargo test -p pkcs11-proxy-ng-types standard_stateful_hash_signature_constants_match_spec -- --nocapture
cargo test -p pkcs11-proxy-ng-types standard_tls_ssl_wtls_constants_match_spec -- --nocapture
cargo test -p pkcs11-proxy-ng-types standard_diffie_hellman_constants_match_spec -- --nocapture
cargo test -p pkcs11-proxy-ng-types standard_remaining_table_backed_constants_match_spec -- --nocapture
cargo test -p pkcs11-proxy-ng-backend slot_scoped_workflows_reject_invalid_slot -- --nocapture
cargo test -p pkcs11-proxy-ng-backend full_registry_mock -- --nocapture
cargo test -p pkcs11-proxy-ng-backend official_mechanism_mock -- --nocapture
cargo test -p pkcs11-proxy-ng-backend mock_mechanism_info_uses_source_grounded_workflow_flags -- --nocapture
cargo test -p pkcs11-proxy-ng-backend mock_backend_supports_provider_gap_3x_workflows -- --nocapture
cargo test -p pkcs11-proxy-ng-backend official_source_grounded_mock_enforces_mechanism_workflow_flags -- --nocapture
cargo test -p pkcs11-proxy-ng-backend full_registry_mock_accepts_every_registered_mechanism_across_core_workflows -- --nocapture
cargo test -p pkcs11-proxy-ng-backend official_mechanism_mock_accepts_every_official_mechanism_across_core_workflows -- --nocapture
cargo test -p pkcs11-proxy-ng-backend official_mechanism_mock_accepts_every_official_mechanism_across_exact_output_workflows -- --nocapture
cargo test -p pkcs11-proxy-ng-backend encapsulate_key_ -- --nocapture
cargo test -p pkcs11-proxy-ng-backend full_registry_mock_accepts_every_registered_mechanism_for_exact_wrap_workflow -- --nocapture
cargo test -p pkcs11-proxy-ng-backend session_mechanism_output -- --nocapture
cargo test -p pkcs11-proxy-ng-backend session_cancel_clears_all_session_scoped_mock_state -- --nocapture
cargo test -p pkcs11-proxy-ng-backend object_and_key_creation_workflows_preserve_template_attributes -- --nocapture
cargo test -p pkcs11-proxy-ng-backend object_and_key_creation_workflows_reject_invalid_session_without_allocating -- --nocapture
cargo test -p pkcs11-proxy-ng-backend object_management_workflows_reject_invalid_session_without_mutating_objects -- --nocapture
cargo test -p pkcs11-proxy-ng-backend handle_returns_error -- --nocapture
cargo test -p pkcs11-proxy-ng-backend stateless_session_workflows_reject_invalid_session -- --nocapture
cargo test -p pkcs11-proxy-ng-backend mock_legacy_parallel_functions_return_function_not_parallel -- --nocapture
cargo test -p pkcs11-proxy-ng-backend generate_key_pair_does_not_partially_allocate_on_quota_failure -- --nocapture
cargo test -p pkcs11-proxy-ng-backend derive_key_with_output_returns_configured -- --nocapture
cargo test -p pkcs11-proxy-ng-backend derive_key_with_sp800_108_additional_keys_allocates_output_handles -- --nocapture
cargo test -p pkcs11-proxy-ng-backend derive_key_with_sp800_108_enforces_mode_data_param_rules -- --nocapture
cargo test -p pkcs11-proxy-ng-backend derive_key_with_sp800_108_validates_data_param_payload_shapes_and_singletons -- --nocapture
cargo test -p pkcs11-proxy-ng-backend derive_key_with_sp800_108_additional_keys_does_not_partially_allocate_on_quota_failure -- --nocapture
cargo test -p pkcs11-proxy-ng-backend sp800_108_key_handle_data_param -- --nocapture
cargo test -p pkcs11-proxy-ng-backend reconstructs -- --nocapture
cargo test -p pkcs11-proxy-ng-shim reads_handle_string_and_sign_context_parameter_structs -- --nocapture
cargo test -p pkcs11-proxy-ng --test wave6_3x_integration_test late_gcm_output_params -- --nocapture
cargo test -p pkcs11-proxy-ng --test wave6_3x_integration_test multipart_encrypt_returns_cached_gcm_output_params_through_grpc -- --nocapture
cargo test -p pkcs11-proxy-ng --test mechanism_out_derive_mock_test -- --nocapture
cargo test -p pkcs11-proxy-ng-shim sp800_108_feedback_reads_additional_keys_and_writes_handles_back -- --nocapture
cargo test -p pkcs11-proxy-ng --test shim_c_abi_mechanism_out_test loaded_shim_writes_mechanism_out_to_caller_stack_after_encrypt_wrap_and_derive -- --ignored --nocapture --test-threads=1
cargo test -p pkcs11-proxy-ng --test local_quality_gate_test oasis_inventory -- --nocapture
```
