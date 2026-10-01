//! R14 verbatim gate (S2 §12): every classic Init path forwards a
//! representable Flat/Null/typed mechanism parameter to the provider FFI
//! exactly.
//!
//! Shape of the proof, in two halves:
//!
//! * The funnel itself — `mechanism_to_ffi` — is proven verbatim by R12's
//!   stub-backed tests: `r12_off_one_call_flat_forwards`
//!   and `r12_off_one_call_null_forwards` (capturing `C_SignInit` stubs
//!   asserting exact pointer/length/bytes in
//!   `ffi_conversion/mechanism/r12_init_retention_tests.rs`) plus the
//!   pure-conversion pins in `r12_flat_null_tests.rs`. This gate asserts
//!   those anchor tests still exist, so the evidence cannot be deleted
//!   while the routing scan below stays green.
//! * This gate proves every Init path routes through that proven funnel:
//!   it discovers every `ffi_*` entry taking the validated newtype and
//!   asserts each converts via the funnel (directly, via a
//!   `call_*_with_mechanism*` helper, or via the authenticated
//!   `with_parameter`/`NativeParameter` path — each itself pinned to
//!   terminate at `mechanism_to_ffi`) and never hand-builds a provider
//!   `CK_MECHANISM`.
//!
//! Why a source scan and not live stubs here: the stub-backend
//! constructor (`FfiBackend::test_backend_with_tables`) is
//! `cfg(any(test, feature = "native-owner-test-hooks"))`-gated, so an
//! integration test cannot reach it without widening production
//! visibility — forbidden to this test-only task. The live-stub half
//! therefore stays in-module (R12, cited above); this gate pins every
//! family onto it. It mirrors the ADR-0010
//! `ffi_init_cancel_paths_forward_null_mechanism_init_verbatim` precedent:
//! a path-filtered source walk with an exact expected matrix.
//!
//! Coverage is self-pinned: the discovered entry set must equal the
//! matrix exactly, so a new Init path (or a removed matrix row) fails
//! the gate naming the gap (R14 RED proof (b)).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// One matrix row: an `ffi_*` entry taking the validated newtype.
struct MatrixRow {
    file: &'static str,
    name: &'static str,
    /// Direct entries convert through a funnel token; adapters only
    /// forward the newtype to another matrix entry.
    adapter: bool,
}

/// The 33 mechanism-taking `ffi_*` entries (R13 retyping): every classic
/// Init family from the R14 brief (sign, sign-recover, verify,
/// verify-recover, encrypt, decrypt, digest, wrap, unwrap, derive,
/// generate, KEM) plus the message/v3 Init paths and the authenticated
/// wrap adapters, which share the same funnel. A new mechanism-taking
/// entry fails the gate until it is listed here AND funneled.
const MATRIX: &[MatrixRow] = &[
    // crypto_ops.rs — the seven classic Init entries.
    MatrixRow { file: "crypto_ops.rs", name: "ffi_sign_init", adapter: false },
    MatrixRow { file: "crypto_ops.rs", name: "ffi_sign_recover_init", adapter: false },
    MatrixRow { file: "crypto_ops.rs", name: "ffi_verify_recover_init", adapter: false },
    MatrixRow { file: "crypto_ops.rs", name: "ffi_verify_init", adapter: false },
    MatrixRow { file: "crypto_ops.rs", name: "ffi_digest_init", adapter: false },
    MatrixRow { file: "crypto_ops.rs", name: "ffi_encrypt_init_with_output", adapter: false },
    MatrixRow { file: "crypto_ops.rs", name: "ffi_decrypt_init", adapter: false },
    // key_state_ops.rs — derive / wrap / unwrap / generate.
    MatrixRow { file: "key_state_ops.rs", name: "ffi_derive_key", adapter: false },
    MatrixRow { file: "key_state_ops.rs", name: "ffi_derive_key_with_output", adapter: false },
    MatrixRow {
        file: "key_state_ops.rs",
        name: "ffi_derive_key_with_output_result",
        adapter: false,
    },
    MatrixRow { file: "key_state_ops.rs", name: "ffi_wrap_key", adapter: false },
    MatrixRow { file: "key_state_ops.rs", name: "ffi_wrap_key_exact", adapter: false },
    MatrixRow { file: "key_state_ops.rs", name: "ffi_wrap_key_exact_with_output", adapter: false },
    MatrixRow { file: "key_state_ops.rs", name: "ffi_unwrap_key", adapter: false },
    MatrixRow { file: "key_state_ops.rs", name: "ffi_generate_key", adapter: false },
    MatrixRow { file: "key_state_ops.rs", name: "ffi_generate_key_with_output", adapter: false },
    MatrixRow { file: "key_state_ops.rs", name: "ffi_generate_key_pair", adapter: false },
    // kem_ops.rs — KEM entries convert directly.
    MatrixRow { file: "kem_ops.rs", name: "ffi_encapsulate_key_exact", adapter: false },
    MatrixRow { file: "kem_ops.rs", name: "ffi_encapsulate_key", adapter: false },
    MatrixRow { file: "kem_ops.rs", name: "ffi_decapsulate_key", adapter: false },
    // message_ops.rs — v3 message Inits: the classic leg (`(Some, None)`
    // and the contract `else` arm) converts via `mechanism_to_ffi`; the
    // message-param arm reconstructs from `MessageParameter` (not a
    // classic representable param) and the `None` arm forwards NULL.
    MatrixRow { file: "message_ops.rs", name: "ffi_message_encrypt_init", adapter: false },
    MatrixRow { file: "message_ops.rs", name: "ffi_message_encrypt_init_contract", adapter: false },
    MatrixRow { file: "message_ops.rs", name: "ffi_message_decrypt_init", adapter: false },
    MatrixRow { file: "message_ops.rs", name: "ffi_message_decrypt_init_contract", adapter: false },
    MatrixRow { file: "message_ops.rs", name: "ffi_message_sign_init", adapter: false },
    MatrixRow { file: "message_ops.rs", name: "ffi_message_verify_init", adapter: false },
    // verify_signature_ops.rs — v3 verify-signature Init.
    MatrixRow {
        file: "verify_signature_ops.rs",
        name: "ffi_verify_signature_init",
        adapter: false,
    },
    // authenticated_typed_ops.rs — via `with_parameter`/`NativeParameter`.
    MatrixRow {
        file: "authenticated_typed_ops.rs",
        name: "ffi_wrap_authenticated_typed",
        adapter: false,
    },
    MatrixRow {
        file: "authenticated_typed_ops.rs",
        name: "ffi_wrap_authenticated_exact_typed",
        adapter: false,
    },
    MatrixRow {
        file: "authenticated_typed_ops.rs",
        name: "ffi_unwrap_authenticated_typed",
        adapter: false,
    },
    // authenticated_wrap_ops.rs — pure adapters delegating to the typed
    // entries above (no provider call of their own).
    MatrixRow {
        file: "authenticated_wrap_ops.rs",
        name: "ffi_wrap_key_authenticated",
        adapter: true,
    },
    MatrixRow {
        file: "authenticated_wrap_ops.rs",
        name: "ffi_unwrap_key_authenticated",
        adapter: true,
    },
    MatrixRow {
        file: "authenticated_wrap_ops.rs",
        name: "ffi_wrap_key_authenticated_exact",
        adapter: true,
    },
];

/// Funnel tokens: a direct entry body must mention at least one —
/// `mechanism_to_ffi` (direct conversion), `with_mechanism` (a
/// `call_*_with_mechanism*` helper), or `with_parameter`/`NativeParameter`
/// (the authenticated path). Every token's target is pinned below to
/// terminate at `mechanism_to_ffi`.
const FUNNEL_TOKENS: &[&str] =
    &["mechanism_to_ffi", "with_mechanism", "with_parameter", "NativeParameter"];

/// The `call_*_with_mechanism*` helpers: exact set, each terminating at
/// `mechanism_to_ffi`. A new helper bypassing the funnel fails here.
const FUNNEL_HELPERS: &[&str] = &[
    "call_unit_with_mechanism",
    "call_init_with_mechanism",
    "call_init_with_mechanism_output",
    "call_bytes_with_mechanism",
    "call_object_with_mechanism",
    "call_bytes_exact_with_mechanism",
    "call_object_with_mechanism_output",
    "call_object_with_mechanism_output_result",
    "call_bytes_exact_with_mechanism_output",
    "call_object_pair_with_mechanism",
];

/// R12 stub-backed proof tests this gate routes every family onto: they
/// must keep existing (name-pinned so the evidence cannot silently go).
const FUNNEL_PROOF_TESTS: &[&str] =
    &["r12_off_one_call_flat_forwards", "r12_off_one_call_null_forwards"];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root should resolve")
}

fn rust_sources_under(root: &Path) -> Vec<PathBuf> {
    fn visit(path: &Path, output: &mut Vec<PathBuf>) {
        let metadata = fs::metadata(path).expect("source path should be readable");
        if metadata.is_dir() {
            for entry in fs::read_dir(path).expect("source directory should be readable") {
                visit(&entry.expect("directory entry should be readable").path(), output);
            }
            return;
        }
        if path.extension().is_some_and(|extension| extension == "rs") {
            output.push(path.to_path_buf());
        }
    }

    let mut sources = Vec::new();
    visit(root, &mut sources);
    sources.sort();
    sources
}

/// Production head of a source file: cut the `cfg(test)`-gated test
/// module tail (both `#[cfg(test)]` and `#[cfg(all(test, ...))]`
/// spellings — but only when the attribute gates a `mod`, never a
/// test-only `use` at file top).
fn prod_head(text: &str) -> &str {
    let mut cut = text.len();
    for spelling in ["#[cfg(test)]", "#[cfg(all(test"] {
        let mut search = 0;
        while let Some(found) = text[search..].find(spelling) {
            let attr_at = search + found;
            let rest = &text[attr_at..];
            let attr_end = rest.find(']').map(|i| attr_at + i + 1).unwrap_or(text.len());
            let after = text[attr_end..].trim_start_matches([' ', '\t', '\r', '\n']);
            if after.starts_with("mod ") {
                cut = cut.min(attr_at);
                break;
            }
            search = attr_end;
        }
    }
    // A test module without a same-file cfg attribute (included via a
    // cfg-gated `mod` declaration) is out of scope here: whole-file test
    // sources are skipped by name before this runs.
    text[..cut].trim_end()
}

/// Split the production head into `(fn_name, signature, body)` triples for
/// every method-level `fn` (exactly 4-space indent — entry methods and
/// helpers; free functions are handled by their own anchors).
fn method_windows(prod: &str) -> Vec<(String, String, String)> {
    let mut starts = Vec::new();
    for (index, line) in prod.lines().enumerate() {
        let stripped = line.strip_prefix("    ").unwrap_or(line);
        let stripped = stripped.strip_prefix("pub(super) ").unwrap_or(stripped);
        let stripped = stripped.strip_prefix("pub(crate) ").unwrap_or(stripped);
        let stripped = stripped.strip_prefix("pub ").unwrap_or(stripped);
        if let Some(rest) = stripped.strip_prefix("fn ")
            && let Some(name_end) = rest.find('(')
        {
            let name = rest[..name_end].split('<').next().unwrap_or("").trim().to_string();
            if !name.is_empty() {
                starts.push((index, name));
            }
        }
    }
    let lines: Vec<&str> = prod.lines().collect();
    starts
        .iter()
        .enumerate()
        .map(|(i, (line_index, name))| {
            let end = starts.get(i + 1).map(|(next, _)| *next).unwrap_or(lines.len());
            let window = lines[*line_index..end].join("\n");
            let brace = window.find('{').unwrap_or(window.len());
            (name.clone(), window[..brace].to_string(), window[brace..].to_string())
        })
        .collect()
}

#[test]
fn ffi_classic_init_paths_forward_representable_mechanism_params_verbatim() {
    let root = workspace_root();
    let ffi_root = root.join("crates/backend/src/ffi");

    // Anchor 1: the R12 stub-backed funnel proofs still exist. The
    // retention file carries the capturing-stub OFF/one-call pins for
    // Flat and Null; the conversion file pins every typed/variant arm.
    let retention =
        fs::read_to_string(ffi_root.join("ffi_conversion/mechanism/r12_init_retention_tests.rs"))
            .expect("r12 retention proofs should exist");
    for proof in FUNNEL_PROOF_TESTS {
        assert!(
            retention.contains(&format!("fn {proof}(")),
            "R12 funnel proof {proof} must keep existing — this gate routes every family onto it"
        );
    }
    assert!(
        ffi_root.join("ffi_conversion/mechanism/r12_flat_null_tests.rs").is_file(),
        "r12 conversion pins must keep existing — this gate routes every family onto them"
    );

    // Anchor 2: discover every mechanism-taking entry and match the matrix.
    let mut discovered: BTreeSet<(String, String)> = BTreeSet::new();
    let mut bodies: Vec<(String, String, String)> = Vec::new();
    for source in rust_sources_under(&ffi_root) {
        let file_name = source.file_name().expect("source file name").to_string_lossy().to_string();
        if file_name.contains("tests") || file_name == "tests.rs" {
            continue;
        }
        let text = fs::read_to_string(&source).expect("Rust source should be readable");
        let prod = prod_head(&text);
        for (name, signature, body) in method_windows(prod) {
            if !name.starts_with("ffi_") || !signature.contains("ValidatedMechanismParams") {
                continue;
            }
            discovered.insert((file_name.clone(), name.clone()));
            bodies.push((file_name.clone(), name, body));
        }
    }
    let expected: BTreeSet<(String, String)> =
        MATRIX.iter().map(|row| (row.file.to_string(), row.name.to_string())).collect();
    let unlisted: Vec<_> = discovered.difference(&expected).collect();
    assert!(
        unlisted.is_empty(),
        "Init path(s) missing from the verbatim matrix — funnel them through mechanism_to_ffi and list them: {unlisted:?}"
    );
    let stale: Vec<_> = expected.difference(&discovered).collect();
    assert!(
        stale.is_empty(),
        "verbatim matrix row(s) with no matching entry — rename or drop them: {stale:?}"
    );

    // Anchor 3: every entry funnels; none hand-builds a provider mechanism.
    let direct: BTreeSet<&str> =
        MATRIX.iter().filter(|row| !row.adapter).map(|row| row.name).collect();
    for (file, name, body) in &bodies {
        assert!(
            !body.contains("CK_MECHANISM {") && !body.contains("CK_MECHANISM{"),
            "{file}::{name} must not hand-build a provider CK_MECHANISM — convert via the funnel"
        );
        if direct.contains(name.as_str()) {
            assert!(
                FUNNEL_TOKENS.iter().any(|token| body.contains(token)),
                "{file}::{name} must route its mechanism through the funnel ({FUNNEL_TOKENS:?})"
            );
        } else {
            let delegates: Vec<&str> = body
                .match_indices("self.ffi_")
                .map(|(index, _)| {
                    let rest = &body[index + "self.".len()..];
                    let end = rest.find('(').unwrap_or(rest.len());
                    rest[..end].trim()
                })
                .collect();
            assert!(
                !delegates.is_empty() && delegates.iter().all(|target| direct.contains(target)),
                "{file}::{name} is a pure adapter: it must forward the newtype to a funneled matrix entry, found: {delegates:?}"
            );
        }
    }

    // Anchor 4: every funnel helper terminates at `mechanism_to_ffi`.
    let helpers_text = fs::read_to_string(ffi_root.join("call_helpers.rs"))
        .expect("call_helpers.rs should be readable");
    let helper_windows = method_windows(prod_head(&helpers_text));
    let found_helpers: BTreeSet<&str> = helper_windows
        .iter()
        .map(|(name, _, _)| name.as_str())
        .filter(|name| name.contains("with_mechanism"))
        .collect();
    let expected_helpers: BTreeSet<&str> = FUNNEL_HELPERS.iter().copied().collect();
    assert_eq!(
        found_helpers, expected_helpers,
        "funnel helper set changed — a new with_mechanism helper must terminate at mechanism_to_ffi"
    );
    for (name, _, body) in &helper_windows {
        if expected_helpers.contains(name.as_str()) {
            assert!(
                body.contains("mechanism_to_ffi("),
                "call_helpers::{name} must terminate at mechanism_to_ffi"
            );
        }
    }
    let typed_text = fs::read_to_string(ffi_root.join("authenticated_typed_ops.rs"))
        .expect("authenticated_typed_ops.rs should be readable");
    let typed_prod = prod_head(&typed_text);
    // `NativeParameter::new` converts via `mechanism_to_ffi` (classic
    // arm); `with_parameter` delegates to `NativeParameter::new`.
    for (anchor, token) in
        [("fn with_parameter", "NativeParameter"), ("fn new(", "mechanism_to_ffi(")]
    {
        let start = typed_prod
            .find(anchor)
            .unwrap_or_else(|| panic!("authenticated_typed_ops should define {anchor}"));
        let tail = &typed_prod[start..];
        let after = &tail[anchor.len()..];
        let next = ["\n    fn ", "\n    pub(super) fn ", "\nfn ", "\nimpl ", "\n#[cfg"]
            .iter()
            .filter_map(|pattern| after.find(pattern))
            .min()
            .map(|i| i + anchor.len())
            .unwrap_or(tail.len());
        assert!(
            tail[..next].contains(token),
            "authenticated_typed_ops {anchor} must terminate at {token}"
        );
    }
}
