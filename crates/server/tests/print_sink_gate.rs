//! Workspace print/dbg sink gate (W1-L12-03 + W1-L2-08).
//!
//! `println!`/`eprintln!`/`dbg!` bypass `tracing` entirely, so the
//! `pin_leak_test` tracing capture cannot see them: a `println!("{pin}")`
//! in a PIN handler would exfiltrate past that test. Two layers close the
//! hole, and this gate pins both under plain `cargo test` (no clippy
//! required):
//!
//! 1. The workspace `[lints]` table in the root `Cargo.toml` denies
//!    `clippy::print_stdout`, `clippy::print_stderr`, and
//!    `clippy::dbg_macro` for every member crate, so a new print/dbg sink
//!    fails the CI clippy gate (`--all-targets --all-features`).
//! 2. Every `allow` of those lints is enumerated in
//!    [`EXPECTED_ALLOW_FILES`]:Printing without an allow fails here (and
//!    under clippy), and adding an allow outside the enumerated set fails
//!    here. Shrinking the set (fewer allows) also fails until the set is
//!    updated deliberately, so the list cannot drift silently.
//!
//! Legitimate sinks stay allowed where stdout/stderr IS the interface
//! (the CLI's user output, pre-tracing daemon warnings, test/bench
//! diagnostics) — each with a justification comment in
//! [`EXPECTED_ALLOW_FILES`]. Build-script `println!("cargo:...")`
//! directives are exempted narrowly by [`line_is_build_directive`]
//! instead: clippy does not lint build scripts for `print_stdout`, so an
//! allow there would be unenforced theater.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Workspace-relative paths of the `.rs` files allowed to name one of the
/// three print/dbg lints in an `allow` attribute, with the justification
/// for each. Exact set: additions and removals both fail
/// `print_lint_allows_are_enumerated` until this list is updated
/// deliberately (the compiled gate is `cargo clippy --all-targets
/// --all-features`, which trips on any unlisted print/dbg sink first).
const EXPECTED_ALLOW_FILES: &[&str] = &[
    // The CLI's whole job is printing to stdout/stderr (bin-root allow).
    // Secret display itself is W1-L2-12 (P3), not this gate.
    "crates/cli/src/main.rs",
    // Pre-tracing daemon warnings (W1-L8-15): tracing is not initialized
    // yet, so stderr is the only channel. Function-scoped.
    "crates/server/src/main.rs",
    // NOTE: `crates/proto/build.rs` is deliberately NOT in this set.
    // Clippy does not lint build scripts for `print_stdout` (verified:
    // downgrading to `warn` emits nothing), so an allow there would be
    // theater. Its `println!("cargo:...")` directives are exempted
    // narrowly by `line_is_build_directive` instead — any other print in
    // a build script still trips.
    // Backend test diagnostics (skip notices, live-load reports).
    "crates/backend/src/ffi/loading.rs",
    "crates/backend/src/ffi/constructor_child_tests.rs",
    "crates/backend/src/ffi/native_domain_tests.rs",
    "crates/backend/src/ffi/retained_owner_contract_tests.rs",
    // Perf-measurement printout (W1-C4-04): the ns/iter report IS the
    // measurement test's output (read with `-- --nocapture`).
    "crates/backend/src/ffi/ffi_conversion/tests.rs",
    // Benchmark report lines.
    "crates/server/benches/proxy_latency_histogram.rs",
    "crates/server/benches/proxy_throughput.rs",
    "crates/server/benches/registry_payload_size.rs",
    // Integration-test diagnostics (skip notices, progress, summaries).
    "crates/server/tests/support/skip.rs",
    "crates/server/tests/cli_hardening_test.rs",
    "crates/server/tests/concurrency_and_recovery_test.rs",
    "crates/server/tests/consumer_p11tool_test.rs",
    "crates/server/tests/consumer_pkcs11_tool_test.rs",
    "crates/server/tests/consumer_python_test.rs",
    "crates/server/tests/kryoptic_mechanism_test.rs",
    // Only the exercised CCM AAD shape and ciphertext length, never contents.
    "crates/server/tests/ccm_pointer_presence_test.rs",
    "crates/server/tests/nss_mechanism_coverage_test.rs",
    "crates/server/tests/provider_matrix_test.rs",
    // Re-entrant child-entry diagnostics (unknown-scenario / fixture
    // reservation failures before tracing exists; exit codes are the
    // parent-visible signal). Block-scoped allows.
    "crates/server/tests/shutdown_lifetime_test.rs",
    "crates/server/tests/template_compat_test.rs",
    "crates/server/tests/exact_output_error/fix_round_one.rs",
    "crates/server/tests/noncontract_begin_health_test.rs",
    "crates/server/tests/shim_c_abi_mechanism_out_test.rs",
    "crates/server/tests/parameterized_mechanism_test.rs",
    "crates/server/tests/nss_tls_mkd_mechanism_out_test.rs",
    "crates/server/tests/pin_leak_test.rs",
    "crates/server/tests/local_quality_gate_test.rs",
    // Example smoke output.
    "crates/shim/examples/cross_width_smoke.rs",
    // Shim live-test diagnostics (ignored-by-default provider tests).
    "crates/shim/src/tests/retained_oracle_live.rs",
    "crates/shim/src/tests/cross_width_live.rs",
    "crates/shim/src/tests/control_channel_live.rs",
    "crates/shim/tests/stress_registry.rs",
];

/// This gate names the three lint paths to audit them, so it excludes
/// itself from the allow-file set scan. It carries no print macro tokens
/// itself (fixtures are string literals, which the scan strips), and the
/// per-file allow check still applies to it.
const SELF_PATH_SUFFIX: &str = "crates/server/tests/print_sink_gate.rs";

/// True when the workspace manifest carries the print/dbg deny table
/// (W1-L12-03): a `[workspace.lints.clippy]` section denying all three
/// sinks. Member crates opt in with `[lints] workspace = true`.
fn manifest_has_print_deny(manifest: &str) -> bool {
    manifest.contains("[workspace.lints.clippy]")
        && manifest.contains("print_stdout")
        && manifest.contains("print_stderr")
        && manifest.contains("dbg_macro")
        && manifest.matches("\"deny\"").count() >= 3
}

/// Which stdout/stderr/debug sink a macro token writes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrintKind {
    Stdout,
    Stderr,
    Dbg,
}

impl PrintKind {
    /// The clippy lint path governing this sink.
    fn lint_path(self) -> &'static str {
        match self {
            PrintKind::Stdout => "clippy::print_stdout",
            PrintKind::Stderr => "clippy::print_stderr",
            PrintKind::Dbg => "clippy::dbg_macro",
        }
    }
}

/// Strip `//` comments, `"..."` string literals (with `\"` escapes), and
/// same-line `/* ... */` comments from one source line so the token scan
/// sees code, not prose. A print macro named inside a string or a comment
/// (e.g. the `DEBUG_SINKS` const in `abi_audit.rs`) is not a sink.
fn strip_line(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut index = 0;
    let mut in_string = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if byte == b'\\' {
                index += 2;
                continue;
            }
            if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if byte == b'/' && index + 1 < bytes.len() {
            if bytes[index + 1] == b'/' {
                break;
            }
            if bytes[index + 1] == b'*' {
                index += 2;
                while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                {
                    index += 1;
                }
                index = (index + 2).min(bytes.len());
                continue;
            }
        }
        out.push(byte as char);
        index += 1;
    }
    out
}

/// True for `[A-Za-z0-9_]` (macro-name constituent).
fn is_ident_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Print-macro tokens on one stripped code line, with a left token
/// boundary so `my_println!` does not count as `println!`.
fn print_tokens_in(code: &str) -> Vec<PrintKind> {
    const TOKENS: &[(&str, PrintKind)] = &[
        ("println!", PrintKind::Stdout),
        ("print!", PrintKind::Stdout),
        ("eprintln!", PrintKind::Stderr),
        ("eprint!", PrintKind::Stderr),
        ("dbg!", PrintKind::Dbg),
    ];
    let bytes = code.as_bytes();
    let mut kinds = Vec::new();
    for (token, kind) in TOKENS {
        // `print!` is not a substring of `println!` (`!` must follow
        // `print` immediately), so plain substring matching is exact.
        let mut from = 0;
        while let Some(relative) = code[from..].find(token) {
            let start = from + relative;
            if start == 0 || !is_ident_char(bytes[start - 1]) {
                kinds.push(*kind);
            }
            from = start + 1;
        }
    }
    kinds
}

/// True when the file allows `kind`'s lint anywhere (any `allow` spelling
/// naming the lint path; the file must also be in [`EXPECTED_ALLOW_FILES`]
/// for the workspace scan to pass).
fn file_allows_kind(src: &str, kind: PrintKind) -> bool {
    src.contains(kind.lint_path())
}

/// `(line number, kind)` of every print sink in the file whose lint the
/// file does not allow. Empty means every sink in the file carries its
/// matching allow (or the file has no sinks).
fn file_print_violations(src: &str) -> Vec<(usize, PrintKind)> {
    let mut violations = Vec::new();
    for (lineno, line) in src.lines().enumerate() {
        for kind in print_tokens_in(&strip_line(line)) {
            if !file_allows_kind(src, kind) {
                violations.push((lineno + 1, kind));
            }
        }
    }
    violations
}

/// True for a `println!("cargo:...")` build-driver directive: only in a
/// file named `build.rs`, and only on lines carrying the `cargo:`
/// directive marker. Clippy does not lint build scripts for
/// `print_stdout` (verified empirically), so these lines are exempted
/// here instead of via an `allow` that the compiler would ignore; any
/// other print in a build script still trips the per-file check.
fn line_is_build_directive(path: &str, line: &str) -> bool {
    path.ends_with("build.rs") && line.contains("cargo:")
}

/// True when the file names any of the three lint paths (in any attribute
/// or position — the gate audits allows, whatever their spelling).
fn file_mentions_print_lint(src: &str) -> bool {
    [PrintKind::Stdout, PrintKind::Stderr, PrintKind::Dbg]
        .iter()
        .any(|kind| src.contains(kind.lint_path()))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Never descend into build output.
            if path.file_name().and_then(|n| n.to_str()) == Some("target") {
                continue;
            }
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn workspace_lints_deny_print_and_dbg() {
    // W1-L12-03: the deny table must exist in the workspace manifest so
    // `cargo clippy --all-targets --all-features` fails the build on any
    // print/dbg sink (these lints are allow-by-default, so `-D warnings`
    // alone does not enable them).
    let root = workspace_root();
    let manifest =
        std::fs::read_to_string(root.join("Cargo.toml")).expect("read workspace Cargo.toml");
    assert!(
        manifest_has_print_deny(&manifest),
        "workspace Cargo.toml must carry [workspace.lints.clippy] denying \
         print_stdout, print_stderr, and dbg_macro (W1-L12-03)"
    );

    // Every member must opt into the workspace table, or the deny has a
    // hole. The member list is read from the manifest itself so a new
    // member cannot dodge this check.
    let mut members = Vec::new();
    let mut in_members = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed == "members = [" {
            in_members = true;
            continue;
        }
        if in_members {
            if trimmed.starts_with(']') {
                break;
            }
            let member = trimmed.trim_matches(|c| c == '"' || c == ',' || c == ' ');
            if !member.is_empty() {
                members.push(member.to_string());
            }
        }
    }
    assert!(!members.is_empty(), "workspace member list must not be empty");
    for member in &members {
        let manifest_path = root.join(member).join("Cargo.toml");
        let member_manifest =
            std::fs::read_to_string(&manifest_path).expect("read member Cargo.toml");
        assert!(
            member_manifest.contains("[lints]")
                && member_manifest.replace(' ', "").contains("workspace=true"),
            "{}/Cargo.toml must opt into the workspace lint table with \
             `[lints] workspace = true` (W1-L12-03)",
            member,
        );
    }
}

#[test]
fn print_lint_allows_are_enumerated() {
    // W1-L12-03 + W1-L2-08: the set of files naming a print/dbg lint must
    // equal EXPECTED_ALLOW_FILES exactly — a new allow (the only way to
    // add a print sink past clippy) fails here until it is justified in
    // that list.
    let root = workspace_root();
    let crates_dir = root.join("crates");
    let mut files = Vec::new();
    collect_rs_files(&crates_dir, &mut files);
    assert!(!files.is_empty(), "no .rs files found under crates/");

    let mut actual = BTreeSet::new();
    for path in &files {
        let relative = path.strip_prefix(&root).expect("workspace-relative path");
        if relative.to_string_lossy() == SELF_PATH_SUFFIX {
            continue;
        }
        let src = std::fs::read_to_string(path).expect("read source file");
        // `clippy::restriction` would silently re-allow all three lints
        // (they live in the restriction group); no file may name it.
        assert!(
            !src.contains("clippy::restriction"),
            "{} names clippy::restriction, which would bypass the print/dbg deny",
            relative.display(),
        );
        if file_mentions_print_lint(&src) {
            actual.insert(relative.to_string_lossy().replace('\\', "/"));
        }
    }

    let expected: BTreeSet<String> = EXPECTED_ALLOW_FILES.iter().map(|s| s.to_string()).collect();
    let unlisted: Vec<_> = actual.difference(&expected).collect();
    let stale: Vec<_> = expected.difference(&actual).collect();
    assert!(
        unlisted.is_empty() && stale.is_empty(),
        "print/dbg allow set drift: unlisted files naming a print lint: {unlisted:?}; \
         expected files no longer naming one: {stale:?}"
    );
}

#[test]
fn every_print_sink_carries_its_allow() {
    // W1-L2-08: every real print/dbg sink must live in a file that allows
    // its lint — the in-tree mirror of the clippy deny, so the sink trips
    // under plain `cargo test` too. (Clippy itself is the build gate; this
    // test pins the same invariant without requiring clippy installed.)
    let root = workspace_root();
    let crates_dir = root.join("crates");
    let mut files = Vec::new();
    collect_rs_files(&crates_dir, &mut files);
    assert!(!files.is_empty(), "no .rs files found under crates/");

    // The CLI binary allows both print lints once at its root (`main.rs`
    // covers the `handlers/` modules, whose whole job is user output);
    // CLI sources are therefore audited against the bin-root allow
    // instead of their own text. (`main.rs` itself must name the allow
    // for the workspace scan to pass — the set test pins that.)
    let cli_root_src =
        std::fs::read_to_string(root.join("crates/cli/src/main.rs")).expect("read cli main.rs");

    let mut violations = Vec::new();
    for path in &files {
        let relative = path.strip_prefix(&root).expect("workspace-relative path");
        let src = std::fs::read_to_string(path).expect("read source file");
        let allow_src = if relative.starts_with("crates/cli/src/") { &cli_root_src } else { &src };
        let relative_str = relative.to_string_lossy().replace('\\', "/");
        for (lineno, line) in src.lines().enumerate() {
            if line_is_build_directive(&relative_str, line) {
                continue;
            }
            for kind in print_tokens_in(&strip_line(line)) {
                if !file_allows_kind(allow_src, kind) {
                    violations.push(format!(
                        "{}:{}: {:?} sink without matching allow({})",
                        relative.display(),
                        lineno + 1,
                        kind,
                        kind.lint_path(),
                    ));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "print/dbg sinks without a matching lint allow (W1-L2-08):\n{}",
        violations.join("\n"),
    );
}

// ---- negative controls --------------------------------------------------

#[test]
fn gate_trips_on_missing_deny_table() {
    // A manifest without the workspace lint table must fail the config
    // check (this is the pre-W1-L12-03 state).
    assert!(!manifest_has_print_deny("[workspace]\nresolver = \"2\"\n"));
    assert!(!manifest_has_print_deny("[workspace.lints.clippy]\nprint_stdout = \"deny\"\n"));
    assert!(manifest_has_print_deny(
        "[workspace.lints.clippy]\nprint_stdout = \"deny\"\nprint_stderr = \"deny\"\n\
         dbg_macro = \"deny\"\n"
    ));
}

#[test]
fn gate_trips_on_unlisted_allow() {
    // A file naming a print lint outside the expected set must be
    // collected as an allow-file (the set comparison then trips).
    assert!(file_mentions_print_lint("#[allow(clippy::print_stdout)]\nfn f() {}"));
    assert!(file_mentions_print_lint("#![allow(clippy::print_stderr)]\nfn f() {}"));
    assert!(!file_mentions_print_lint("fn f() {}"));
}

#[test]
fn gate_trips_on_unallowed_println_pin_exfil() {
    // W1-L2-08 core case: a println exfiltrating a PIN with no allow must
    // trip; the same sink with its allow passes.
    let exfil = "fn leak(pin: &[u8]) {\n    println!(\"pin={pin:?}\");\n}\n";
    let violations = file_print_violations(exfil);
    assert_eq!(violations.len(), 1, "planted println PIN exfil must trip");
    assert_eq!(violations[0].0, 2);
    assert_eq!(violations[0].1, PrintKind::Stdout);

    let allowed = "#[allow(clippy::print_stdout)]\nfn leak(pin: &[u8]) {\n    println!(\"pin={pin:?}\");\n}\n";
    assert!(
        file_print_violations(allowed).is_empty(),
        "allow-listed sink must pass the per-file check (the set test audits the allow)"
    );

    // A stderr allow does not cover a stdout sink.
    let mismatched = "#[allow(clippy::print_stderr)]\nfn f() {\n    println!(\"hi\");\n}\n";
    assert_eq!(file_print_violations(mismatched).len(), 1, "lint/kind mismatch must trip");

    // dbg! is a sink too.
    assert_eq!(file_print_violations("fn f(pin: &[u8]) {\n    dbg!(pin);\n}\n").len(), 1);
    assert!(
        file_print_violations(
            "#[allow(clippy::dbg_macro)]\nfn f(pin: &[u8]) {\n    dbg!(pin);\n}\n"
        )
        .is_empty()
    );
}

#[test]
fn gate_exempts_only_cargo_directives_in_build_scripts() {
    // `println!("cargo:...")` in build.rs passes; anything else there trips.
    assert!(line_is_build_directive(
        "crates/proto/build.rs",
        "    println!(\"cargo:rerun-if-changed=x\");"
    ));
    assert!(!line_is_build_directive("crates/proto/build.rs", "    println!(\"hello\");"));
    assert!(!line_is_build_directive(
        "crates/server/src/main.rs",
        "    println!(\"cargo:warning=x\");"
    ));
}

#[test]
fn gate_ignores_quoted_and_commented_sinks() {
    // String literals and comments naming print macros are not sinks.
    assert!(
        file_print_violations("const S: &[&str] = &[\"dbg!(\", \"println!\", \"eprintln!\"];\n")
            .is_empty()
    );
    assert!(file_print_violations("// println!(\"debug\")\nfn f() {}\n").is_empty());
    assert!(
        file_print_violations("/// Emitted via `eprintln!` naming the var\nfn f() {}\n").is_empty()
    );
    assert!(file_print_violations("fn f() {\n    /* dbg!(x); */\n}\n").is_empty());
    // An identifier merely containing the token is not a sink.
    assert!(file_print_violations("fn f() {\n    my_println!(\"hi\");\n}\n").is_empty());
    // `print!` is not a substring match inside `println!` (no double count).
    assert_eq!(file_print_violations("fn f() {\n    println!(\"hi\");\n}\n").len(), 1);
}
