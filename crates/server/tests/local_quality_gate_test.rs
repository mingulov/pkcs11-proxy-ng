use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const CI_TIER0_COMMANDS: &[&str] = &[
    "cargo fmt --all -- --check",
    "cargo audit",
    // W1-L16-07: the deny policy gate is part of Tier 0 (CI needs + matrix).
    "cargo deny check",
    // W1-L16-06: Tier 0 builds/tests run --locked.
    "cargo build --workspace --locked",
    "cargo test --workspace --locked",
    "cargo clippy --workspace --locked --all-targets --all-features -- -D warnings",
    // W1-L17-05: the packaging smoke is part of Tier 0 (CI job + matrix).
    "scripts/packaging-smoke.sh",
];

struct IgnoredTestLane {
    file: &'static str,
    reason: &'static str,
    commands: &'static [&'static str],
    requirements: &'static [&'static str],
}

const IGNORED_TEST_TAXONOMY: &[IgnoredTestLane] = &[
    IgnoredTestLane {
        file: "crates/server/tests/ccm_pointer_presence_test.rs",
        reason: "Kryoptic AES-CCM empty-AAD round trips",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test ccm_pointer_presence_test -- --ignored --test-threads=1",
        ],
        requirements: &[
            "Kryoptic module via PKCS11_PROXY_KRYOPTIC_MODULE",
            "initialized token and PKCS11_PROXY_KRYOPTIC_* settings",
        ],
    },
    IgnoredTestLane {
        file: "crates/server/tests/cli_hardening_test.rs",
        reason: "CLI subprocess tests using SoftHSM2",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test cli_hardening_test -- --ignored --test-threads=1",
        ],
        requirements: &["SoftHSM2 module and softhsm2-util", "built workspace binaries"],
    },
    IgnoredTestLane {
        file: "crates/server/tests/concurrency_and_recovery_test.rs",
        reason: "Multi-client and recovery tests using SoftHSM2",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test concurrency_and_recovery_test -- --ignored --test-threads=1",
        ],
        requirements: &["SoftHSM2 module and softhsm2-util"],
    },
    IgnoredTestLane {
        file: "crates/server/tests/consumer_p11tool_test.rs",
        reason: "GnuTLS p11tool tests using SoftHSM2",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test consumer_p11tool_test -- --ignored --test-threads=1",
        ],
        requirements: &[
            "SoftHSM2 module and softhsm2-util",
            "GnuTLS p11tool",
            "built workspace binaries",
        ],
    },
    IgnoredTestLane {
        file: "crates/server/tests/consumer_pkcs11_tool_test.rs",
        reason: "OpenSC pkcs11-tool tests using SoftHSM2",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test consumer_pkcs11_tool_test -- --ignored --test-threads=1",
        ],
        requirements: &[
            "SoftHSM2 module and softhsm2-util",
            "OpenSC pkcs11-tool",
            "built workspace binaries",
        ],
    },
    IgnoredTestLane {
        file: "crates/server/tests/consumer_python_test.rs",
        reason: "Python PyKCS11 tests using SoftHSM2",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test consumer_python_test -- --ignored --test-threads=1",
        ],
        requirements: &[
            "SoftHSM2 module and softhsm2-util",
            "python3 with PyKCS11",
            "built workspace binaries",
        ],
    },
    IgnoredTestLane {
        file: "crates/server/tests/integration_test.rs",
        reason: "Smoke tests using SoftHSM2 and NSS softokn",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test integration_test softhsm_smoke_workflow -- --ignored --test-threads=1",
            "cargo test -p pkcs11-proxy-ng --test integration_test nss_sign_recover_and_verify_recover -- --ignored --test-threads=1",
        ],
        requirements: &[
            "SoftHSM2 module and softhsm2-util",
            "NSS softokn libsoftokn3.so and certutil",
        ],
    },
    IgnoredTestLane {
        file: "crates/server/tests/kryoptic_mechanism_test.rs",
        reason: "Kryoptic provider mechanism coverage",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test kryoptic_mechanism_test -- --ignored --test-threads=1",
        ],
        requirements: &["Kryoptic module via PKCS11_PROXY_KRYOPTIC_MODULE"],
    },
    IgnoredTestLane {
        file: "crates/server/tests/mechanism_out_gcm_iv_test.rs",
        reason: "AES-GCM generated-IV output using patched SoftHSM2",
        commands: &["SOFTHSM2_GCM_IV_SIM_LIB=/path/to/patched/libsofthsm2.so \
             cargo test -p pkcs11-proxy-ng --test mechanism_out_gcm_iv_test \
             -- --ignored --test-threads=1"],
        requirements: &[
            "Patched libsofthsm2.so built from [pkcs11-check](https://github.com/mingulov/pkcs11-check) \
             `docker/softhsm2/patches/`; set SOFTHSM2_GCM_IV_SIM_LIB to its path",
            "softhsm2-util",
        ],
    },
    IgnoredTestLane {
        file: "crates/server/tests/shim_c_abi_mechanism_out_test.rs",
        reason: "Loaded-shim C ABI mechanism-output, C_GetMechanismInfo zero-flag, \
                 and C_WaitForSlotEvent lifecycle coverage",
        commands: &[
            "cargo build -p pkcs11-proxy-ng-shim",
            "cargo test -p pkcs11-proxy-ng --test shim_c_abi_mechanism_out_test -- --ignored --test-threads=1",
        ],
        requirements: &[
            "Built shim shared library from cargo build -p pkcs11-proxy-ng-shim or PKCS11_PROXY_SHIM_LIB",
        ],
    },
    IgnoredTestLane {
        file: "crates/server/tests/noncontract_begin_health_test.rs",
        reason: "Native-oracle legacy Begin completion-health coverage",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test noncontract_begin_health_test -- --ignored --test-threads=1",
        ],
        requirements: &[
            "Normal and missing-message-begin oracle builds via PKCS11_PROXY_EXACT_ORACLE_LIB and PKCS11_PROXY_MISSING_BEGIN_ORACLE_LIB",
        ],
    },
    IgnoredTestLane {
        file: "crates/server/tests/nss_mechanism_coverage_test.rs",
        reason: "NSS softokn mechanism coverage",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test nss_mechanism_coverage_test -- --ignored --test-threads=1",
        ],
        requirements: &["NSS softokn libsoftokn3.so and certutil"],
    },
    IgnoredTestLane {
        file: "crates/server/tests/nss_tls_mkd_mechanism_out_test.rs",
        reason: "NSS softokn SSL3 master-key-derive mechanism-output coverage",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test nss_tls_mkd_mechanism_out_test -- --ignored --test-threads=1",
        ],
        requirements: &["NSS softokn libsoftokn3.so and certutil"],
    },
    IgnoredTestLane {
        file: "crates/server/tests/provider_matrix_test.rs",
        reason: "Optional NSS and Kryoptic provider matrix smoke coverage",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test provider_matrix_test nss_softokn_smoke_suite -- --ignored --test-threads=1",
            "cargo test -p pkcs11-proxy-ng --test provider_matrix_test kryoptic_smoke_suite -- --ignored --test-threads=1",
        ],
        requirements: &[
            "NSS softokn libsoftokn3.so and certutil",
            "Kryoptic module via PKCS11_PROXY_KRYOPTIC_MODULE",
        ],
    },
    IgnoredTestLane {
        file: "crates/server/tests/softhsm_fixture_test.rs",
        reason: "SoftHSM2 fixture variant coverage",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test softhsm_fixture_test -- --ignored --test-threads=1",
        ],
        requirements: &["SoftHSM2 module and softhsm2-util"],
    },
    IgnoredTestLane {
        file: "crates/server/tests/template_compat_test.rs",
        reason: "Template compatibility tests using SoftHSM2",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test template_compat_test -- --ignored --test-threads=1",
        ],
        requirements: &["SoftHSM2 module and softhsm2-util"],
    },
    IgnoredTestLane {
        file: "crates/server/tests/test_hooks_topology_test.rs",
        reason: "Hook-gated control-plane topology coverage (real daemon subprocess)",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --features native-owner-test-hooks --test test_hooks_topology_test -- --ignored --test-threads=1",
        ],
        requirements: &[
            "SoftHSM2 module and softhsm2-util",
            "native-owner-test-hooks feature build",
            "built workspace binaries",
        ],
    },
];

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
    sources
}

#[test]
fn supply_chain_pins_are_consistent() {
    // W1-L16-09/10/13: one pinned toolchain, one protoc version, zero
    // floating action tags. mise.toml is canonical for protoc;
    // rust-toolchain.toml is canonical for the Rust channel.
    let root = workspace_root();
    let workflows_dir = root.join(".github/workflows");
    let mut workflow_texts = Vec::new();
    for entry in fs::read_dir(&workflows_dir).expect("workflows directory should be readable") {
        let path = entry.expect("workflow entry should be readable").path();
        if path.extension().is_some_and(|extension| extension == "yml") {
            workflow_texts.push(fs::read_to_string(&path).expect("workflow should be readable"));
        }
    }
    assert!(!workflow_texts.is_empty(), "expected workflow files");

    // Protoc: single version across mise, setup-protoc steps, Dockerfile.
    let mise = fs::read_to_string(root.join("mise.toml")).expect("mise.toml should be readable");
    let mise_version = mise
        .lines()
        .find_map(|line| line.strip_prefix("protoc = \"")?.strip_suffix('"'))
        .expect("mise.toml should pin protoc");
    for text in &workflow_texts {
        assert!(
            !text.contains("protobuf-compiler"),
            "workflows should use pinned setup-protoc, not distro protobuf-compiler"
        );
    }
    let dockerfile = fs::read_to_string(root.join("Dockerfile.test"))
        .expect("Dockerfile.test should be readable");
    assert!(
        !dockerfile.contains("protobuf-compiler"),
        "Dockerfile.test should use pinned protoc, not distro protobuf-compiler"
    );
    assert!(
        dockerfile.contains(&format!("ARG PROTOC_VERSION={mise_version}")),
        "Dockerfile.test protoc should match mise.toml ({mise_version})"
    );
    let mut setup_protoc_steps = 0;
    for text in &workflow_texts {
        setup_protoc_steps += text.matches("uses: arduino/setup-protoc@").count();
    }
    assert!(setup_protoc_steps > 0, "expected setup-protoc steps");
    let mut pinned_protoc_steps = 0;
    for text in &workflow_texts {
        pinned_protoc_steps += text.matches(&format!("version: \"{mise_version}\"")).count();
    }
    assert_eq!(
        pinned_protoc_steps, setup_protoc_steps,
        "every setup-protoc step should pin protoc {mise_version}"
    );

    // Toolchain: rust-toolchain.toml channel mirrored in CI + Dockerfile.
    let toolchain_file = fs::read_to_string(root.join("rust-toolchain.toml"))
        .expect("rust-toolchain.toml should exist");
    let channel = toolchain_file
        .lines()
        .find_map(|line| line.strip_prefix("channel = \"")?.strip_suffix('"'))
        .expect("rust-toolchain.toml should pin a channel");
    assert_ne!(channel, "stable", "toolchain pin should not float on stable");
    for text in &workflow_texts {
        assert!(
            !text.contains("dtolnay/rust-toolchain@stable"),
            "workflows should not float the toolchain action on @stable"
        );
        assert!(
            !text.contains("dtolnay/rust-toolchain@nightly"),
            "workflows should not float the toolchain action on @nightly"
        );
    }
    assert!(
        dockerfile.contains(&format!("ARG RUST_TOOLCHAIN={channel}")),
        "Dockerfile.test toolchain should match rust-toolchain.toml ({channel})"
    );
    assert!(
        workflow_texts.iter().any(|text| text.contains("toolchain: 1.88")),
        "MSRV job should keep Rust 1.88"
    );

    // Actions: pinned to SHAs, never floating major tags. Local
    // reusable-workflow calls (./.github/workflows/...) carry no remote
    // reference and are exempt.
    for text in &workflow_texts {
        for line in text.lines().map(str::trim) {
            let Some(pinned) =
                line.strip_prefix("- uses: ").or_else(|| line.strip_prefix("uses: "))
            else {
                continue;
            };
            if pinned.starts_with("./") {
                continue;
            }
            let reference =
                pinned.split('#').next().unwrap_or("").trim().split('@').nth(1).unwrap_or("");
            assert!(
                reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit()),
                "action `{pinned}` should be pinned to a 40-char commit SHA"
            );
        }
    }
}

#[test]
fn packaging_and_aux_images_are_pinned() {
    // Deferred T22 F6: packaging + aux Dockerfiles pin bases by digest
    // (tag kept for readability; the digest is what Docker pulls) and
    // install a pinned Rust toolchain via the versioned, SHA-verified
    // rustup-init bootstrap (the Dockerfile.test convention); GitLab
    // pins its docker images the same way. `scratch` needs no digest
    // (not a registry ref). Digests are format-checked here; values
    // were resolved live at pin time (see the group-T22 report).
    let root = workspace_root();
    let toolchain_file = fs::read_to_string(root.join("rust-toolchain.toml"))
        .expect("rust-toolchain.toml should exist");
    let channel = toolchain_file
        .lines()
        .find_map(|line| line.strip_prefix("channel = \"")?.strip_suffix('"'))
        .expect("rust-toolchain.toml should pin a channel");

    for dockerfile_rel in [
        "packaging/alpine/Dockerfile.alpine",
        "packaging/amazon/Dockerfile.amazon",
        "Dockerfile.be-qemu",
        "Dockerfile.musl",
    ] {
        let path = root.join(dockerfile_rel);
        let dockerfile = fs::read_to_string(&path).expect("Dockerfile should be readable");
        assert!(
            !dockerfile.contains("sh.rustup.rs"),
            "{dockerfile_rel} should use the versioned rustup-init bootstrap, not sh.rustup.rs"
        );
        assert!(
            !dockerfile.contains("--default-toolchain stable"),
            "{dockerfile_rel} should pin a toolchain version, not stable"
        );
        assert!(
            dockerfile.contains(&format!("ARG RUST_TOOLCHAIN={channel}")),
            "{dockerfile_rel} toolchain should match rust-toolchain.toml ({channel})"
        );
        assert!(
            dockerfile.contains("RUSTUP_VERSION=") && dockerfile.contains("sha256sum -c"),
            "{dockerfile_rel} should verify the rustup-init download by SHA256"
        );
        for line in dockerfile.lines().map(str::trim) {
            if !line.starts_with("FROM ") {
                continue;
            }
            let reference = line.split_whitespace().nth(1).unwrap_or("");
            if reference == "scratch" || reference.starts_with('$') {
                continue;
            }
            assert!(
                reference.contains("@sha256:"),
                "{dockerfile_rel}: FROM `{reference}` should be digest-pinned"
            );
        }
        for line in dockerfile.lines().map(str::trim) {
            if line.starts_with("ARG ALPINE_BUILD_IMAGE=")
                || line.starts_with("ARG AMAZON_BUILD_IMAGE=")
            {
                let digest = line.split("@sha256:").nth(1).unwrap_or("");
                assert!(
                    digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit()),
                    "{dockerfile_rel}: `{line}` should default to a digest-pinned image"
                );
            }
        }
    }

    let gitlab =
        fs::read_to_string(root.join(".gitlab-ci.yml")).expect(".gitlab-ci.yml should be readable");
    for line in gitlab.lines().map(str::trim) {
        if line.starts_with("image:") && line.contains("docker:") || line.starts_with("- docker:") {
            assert!(line.contains("@sha256:"), ".gitlab-ci.yml: `{line}` should be digest-pinned");
        }
        if line.contains("ALPINE_BUILD_IMAGE:") || line.contains("AMAZON_BUILD_IMAGE:") {
            assert!(
                line.contains("@sha256:"),
                ".gitlab-ci.yml: `{line}` should pass a digest-pinned image"
            );
        }
    }
    assert!(!gitlab.contains("docker:latest"), ".gitlab-ci.yml should not float on docker:latest");
    assert!(
        gitlab.contains("--build-arg ALPINE_BUILD_IMAGE="),
        ".gitlab-ci.yml should pass the pinned Alpine build image"
    );
    assert!(
        gitlab.contains("--build-arg AMAZON_BUILD_IMAGE="),
        ".gitlab-ci.yml should pass the pinned Amazon build image"
    );
}

#[test]
fn shim_cdylib_tokio_closure_stays_minimal() {
    // W1-L6-11: confirm Task 22 (W1-L16-15) tokio scoping still covers
    // the shim cdylib — the server-only surface (signal/process, plus
    // full/rt-multi-thread/fs per the Task 22 cargo-tree check) must
    // not creep into the first-party manifests whose feature union
    // forms the cdylib build. Only `[dependencies]` is scanned:
    // dev/build deps (shim test harness, proto codegen) never link
    // into the shipped cdylib. Manifests are parsed as TOML (T30 M1),
    // not line-matched, so multi-line declarations cannot evade the
    // scan. Third-party unions (tonic/hyper) are verified out-of-band
    // via `cargo tree -p pkcs11-proxy-ng-shim -e normal` (no
    // signal/process/full — recheck when adding client-side deps).
    let root = workspace_root();

    // Workspace base must stay featureless.
    let workspace = fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml readable");
    let violations = workspace_tokio_base_violations(&workspace);
    assert!(violations.is_empty(), "workspace tokio violations:\n{}", violations.join("\n"));

    // First-party crates feeding the cdylib (shim + its path deps).
    for member in [
        "crates/shim/Cargo.toml",
        "crates/client/Cargo.toml",
        "crates/proto/Cargo.toml",
        "crates/types/Cargo.toml",
    ] {
        let manifest = fs::read_to_string(root.join(member)).expect("member manifest readable");
        let violations = tokio_manifest_violations(&manifest, member);
        assert!(violations.is_empty(), "{member} tokio violations:\n{}", violations.join("\n"));
    }
}

const BANNED_TOKIO_FEATURES: &[&str] = &["full", "signal", "process", "rt-multi-thread", "fs"];

/// Deferred T30 M1: violations of the cdylib tokio rules in one member
/// manifest's `[dependencies]` tokio entry (empty = clean). Split out so
/// synthetic fixtures can drive the gate directly. Parsed as TOML (not
/// line-matched), so multi-line declarations (array continuations,
/// `[dependencies.tokio]` sections) cannot evade the banned-feature
/// scan. Unparseable manifests fail closed (reported, never skipped).
fn tokio_manifest_violations(manifest_text: &str, member: &str) -> Vec<String> {
    let manifest: toml::Value = match manifest_text.parse() {
        Ok(value) => value,
        Err(err) => return vec![format!("{member}: manifest must parse as TOML: {err}")],
    };
    let tokio = manifest.get("dependencies").and_then(|deps| deps.get("tokio"));
    let Some(tokio) = tokio else { return Vec::new() };
    let Some(table) = tokio.as_table() else {
        // Bare `tokio = "1"` enables default features (the banned surface).
        return vec![format!(
            "{member}: tokio must inherit the featureless workspace base (bare version enables default features)"
        )];
    };
    let mut violations = Vec::new();
    let inherits_base = table.get("workspace").and_then(toml::Value::as_bool).unwrap_or(false)
        || table.get("default-features").and_then(toml::Value::as_bool) == Some(false);
    if !inherits_base {
        violations
            .push(format!("{member}: tokio must inherit the featureless workspace base: {tokio}"));
    }
    if let Some(features) = table.get("features").and_then(toml::Value::as_array) {
        for feature in features.iter().filter_map(toml::Value::as_str) {
            if BANNED_TOKIO_FEATURES.contains(&feature) {
                violations.push(format!(
                    "{member}: banned tokio feature \"{feature}\" in the cdylib closure"
                ));
            }
        }
    }
    violations
}

/// Deferred T30 M1: violations of the workspace tokio-base rule (empty =
/// clean). The shared base must stay featureless so inheriting members
/// cannot pull the server-only surface through the workspace. Parsed as
/// TOML so a multi-line base declaration is scanned whole.
fn workspace_tokio_base_violations(workspace_text: &str) -> Vec<String> {
    let manifest: toml::Value = match workspace_text.parse() {
        Ok(value) => value,
        Err(err) => return vec![format!("workspace Cargo.toml must parse as TOML: {err}")],
    };
    let tokio = manifest
        .get("workspace")
        .and_then(|ws| ws.get("dependencies"))
        .and_then(|deps| deps.get("tokio"));
    let Some(table) = tokio.and_then(toml::Value::as_table) else {
        return vec!["workspace must declare shared tokio as a featureless table".to_string()];
    };
    let mut violations = Vec::new();
    if table.get("default-features").and_then(toml::Value::as_bool) != Some(false) {
        violations.push(format!("workspace tokio must keep default-features = false: {tokio:?}"));
    }
    if let Some(features) = table.get("features").and_then(toml::Value::as_array) {
        for feature in features.iter().filter_map(toml::Value::as_str) {
            if BANNED_TOKIO_FEATURES.contains(&feature) {
                violations.push(format!(
                    "workspace tokio base must not enable banned feature \"{feature}\""
                ));
            }
        }
    }
    violations
}

#[test]
fn tokio_gate_catches_multiline_banned_feature() {
    // Deferred T30 M1: a banned feature on a continuation line of a
    // multi-line inline table must not evade the scan.
    let manifest = "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
        \n[dependencies]\ntokio = { workspace = true, features = [\n  \"rt\",\n  \"signal\",\n] }\n";
    let violations = tokio_manifest_violations(manifest, "fixture/Cargo.toml");
    assert!(
        violations.iter().any(|v| v.contains("signal")),
        "multi-line banned feature must be caught, got: {violations:?}"
    );
    // The workspace base was line-parsed too — a multi-line base with a
    // banned feature must be caught as well (newline inside the features
    // array: valid TOML 1.0, invisible to the old line matcher).
    let workspace = "[workspace]\n[workspace.dependencies]\ntokio = { version = \"1\", default-features = false, features = [\n  \"process\"\n] }\n";
    let ws_violations = workspace_tokio_base_violations(workspace);
    assert!(
        ws_violations.iter().any(|v| v.contains("process")),
        "multi-line workspace base must be scanned whole, got: {ws_violations:?}"
    );
}

#[test]
fn tokio_gate_catches_dependency_table_section() {
    // Deferred T30 M1: the `[dependencies.tokio]` table form is
    // inherently multi-line and must be scanned too.
    let manifest = "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
        \n[dependencies.tokio]\nversion = \"1\"\ndefault-features = false\nfeatures = [\"full\"]\n";
    let violations = tokio_manifest_violations(manifest, "fixture/Cargo.toml");
    assert!(
        violations.iter().any(|v| v.contains("full")),
        "table-section banned feature must be caught, got: {violations:?}"
    );
}

#[test]
fn tokio_gate_accepts_clean_manifests() {
    // Deferred T30 M1: clean declarations — single-line, multi-line, or
    // absent tokio — must stay green.
    for manifest in [
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
        \n[dependencies]\ntokio = { workspace = true, features = [\"rt\", \"sync\"] }\n",
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
        \n[dependencies]\ntokio = { workspace = true, features = [\n  \"rt\",\n  \"sync\",\n] }\n",
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nserde = \"1\"\n",
    ] {
        assert!(
            tokio_manifest_violations(manifest, "fixture/Cargo.toml").is_empty(),
            "clean manifest must stay green: {manifest:?}"
        );
    }
    assert!(
        workspace_tokio_base_violations(
            "[workspace.dependencies]\ntokio = { version = \"1\", default-features = false }\n"
        )
        .is_empty()
    );
}

#[test]
fn tokio_gate_catches_bare_version_enabling_default_features() {
    // Deferred T30 M1: parity with the pre-change gate — a bare
    // `tokio = "1"` (default features on) never inherits the
    // featureless base.
    let manifest = "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ntokio = \"1\"\n";
    assert!(
        !tokio_manifest_violations(manifest, "fixture/Cargo.toml").is_empty(),
        "bare tokio version must be flagged"
    );
}

#[test]
fn test_matrix_fast_only_matches_ci_tier0_commands() {
    let root = workspace_root();
    let test_matrix = fs::read_to_string(root.join("scripts/test-matrix.sh"))
        .expect("scripts/test-matrix.sh should be readable");
    let ci_workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .expect(".github/workflows/ci.yml should be readable");

    assert!(
        test_matrix.contains("--fast-only"),
        "scripts/test-matrix.sh should expose an explicit local CI parity gate"
    );
    assert!(
        test_matrix.contains("fast_only"),
        "scripts/test-matrix.sh should implement the --fast-only mode explicitly"
    );

    let mut previous_position = 0;
    for command in CI_TIER0_COMMANDS {
        assert!(
            ci_workflow.contains(command),
            "CI workflow should keep Tier 0 command `{command}`"
        );
        let position = test_matrix.find(command).unwrap_or_else(|| {
            panic!("local test matrix should run CI Tier 0 command `{command}`")
        });
        assert!(
            position >= previous_position,
            "local test matrix should run Tier 0 commands in CI order"
        );
        previous_position = position;
    }
}

#[test]
fn test_matrix_usage_names_fast_check_set_consistently() {
    // Deferred T22 F5: --skip-fast skips exactly the fast set --fast-only
    // runs, so both usage lines must name the same checks.
    let root = workspace_root();
    let test_matrix = fs::read_to_string(root.join("scripts/test-matrix.sh"))
        .expect("scripts/test-matrix.sh should be readable");
    let usage_line = |flag: &str| {
        test_matrix
            .lines()
            .find(|line| line.trim_start().starts_with(&format!("{flag} ")))
            .unwrap_or_else(|| panic!("test-matrix.sh usage should document {flag}"))
            .to_string()
    };
    let fast_only = usage_line("--fast-only");
    let skip_fast = usage_line("--skip-fast");
    for check in ["fmt", "audit", "deny", "build", "test", "clippy"] {
        assert!(
            fast_only.contains(check),
            "--fast-only usage should name `{check}`: `{fast_only}`"
        );
        assert!(
            skip_fast.contains(check),
            "--skip-fast usage should name `{check}`: `{skip_fast}`"
        );
    }
}

#[test]
fn ci_workflow_runs_cargo_audit_before_build_and_test() {
    let root = workspace_root();
    let ci_workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .expect(".github/workflows/ci.yml should be readable");

    assert!(
        ci_workflow.contains("name: Cargo Audit"),
        "CI should have a dedicated cargo audit job"
    );
    assert!(ci_workflow.contains("cargo audit"), "CI should run cargo audit");
    // W1-L16-07: the deny policy gate blocks the main leg like audit does.
    assert!(ci_workflow.contains("name: Cargo Deny"), "CI should have a dedicated cargo deny job");
    assert!(ci_workflow.contains("cargo deny check"), "CI should run cargo deny check");
    assert!(
        ci_workflow.contains("needs: [fmt, audit, deny]"),
        "build-and-test should depend on fmt, audit, and deny"
    );
}

#[test]
fn ci_workflow_does_not_checkout_oasis_specs() {
    let root = workspace_root();
    let ci_workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .expect(".github/workflows/ci.yml should be readable");

    assert!(
        !ci_workflow.contains("PKCS11_PROXY_NG_OASIS_ROOT"),
        "submodule CI should not require or configure an OASIS source checkout"
    );
    assert!(
        !ci_workflow.contains("repository: oasis-tcs/pkcs11"),
        "submodule CI should not checkout the OASIS PKCS#11 spec repository"
    );
    assert!(
        !ci_workflow.contains("Checkout OASIS PKCS#11 spec source"),
        "submodule CI should not fetch OASIS spec sources"
    );
}

#[test]
fn dockerfile_test_references_current_workspace_crates() {
    let root = workspace_root();
    let dockerfile = fs::read_to_string(root.join("Dockerfile.test"))
        .expect("Dockerfile.test should be readable");

    let mut crate_dirs = BTreeSet::new();
    let mut package_names = BTreeSet::new();
    for entry in fs::read_dir(root.join("crates")).expect("crates directory should be readable") {
        let path = entry.expect("crate directory entry should be readable").path();
        let manifest = path.join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }

        let crate_dir = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("crate directory name should be UTF-8")
            .to_string();
        crate_dirs.insert(crate_dir);

        let manifest_text =
            fs::read_to_string(&manifest).expect("crate Cargo.toml should be readable");
        let parsed_manifest: toml::Value =
            manifest_text.parse().expect("crate Cargo.toml should be valid TOML");
        let package_name = parsed_manifest
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(|name| name.as_str())
            .expect("crate manifest should have a package name")
            .to_string();
        package_names.insert(package_name);
    }

    for line in dockerfile
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("COPY crates/") && line.contains("/Cargo.toml"))
    {
        let source =
            line.split_whitespace().nth(1).expect("Dockerfile COPY should have a source path");
        assert!(
            root.join(source).is_file(),
            "Dockerfile.test references missing crate manifest `{source}`"
        );
    }

    for crate_dir in crate_dirs {
        let manifest_copy = format!("COPY crates/{crate_dir}/Cargo.toml");
        assert!(
            dockerfile.contains(&manifest_copy),
            "Dockerfile.test should copy `{manifest_copy}` for dependency caching"
        );
    }

    for package_name in package_names {
        assert!(
            // W1-L16-06: workspace builds in Dockerfile.test run --locked.
            dockerfile.contains("cargo build --locked --workspace")
                || dockerfile.contains(&format!("-p {package_name}")),
            "Dockerfile.test should build package `{package_name}` by name or build the workspace"
        );
    }
}

// ── W1-L17 (Task 23): release determinism + consumer-tier honesty ──────────

/// Body of a named workflow step: the de-indented `run` lines between
/// `      - name: <name>` and the next step header.
fn workflow_step_body(workflow: &str, name: &str) -> String {
    let header = format!("      - name: {name}");
    let mut body = String::new();
    let mut in_step = false;
    for line in workflow.lines() {
        if line == header {
            in_step = true;
            continue;
        }
        if in_step {
            if line.starts_with("      - name: ") {
                break;
            }
            if let Some(code) = line.strip_prefix("          ") {
                body.push_str(code);
                body.push('\n');
            }
        }
    }
    assert!(!body.is_empty(), "workflow step `{name}` should exist with a run body");
    body
}

/// Body of a top-level shell function: from `<name>() {` through the closing
/// `}` at column 0.
fn shell_function_body(script: &str, name: &str) -> String {
    let header = format!("{name}() {{");
    let mut body = String::new();
    let mut in_function = false;
    for line in script.lines() {
        if line == header {
            in_function = true;
        }
        if in_function {
            body.push_str(line);
            body.push('\n');
            if line == "}" {
                break;
            }
        }
    }
    assert!(!body.is_empty(), "shell function `{name}` should exist");
    body
}

#[test]
fn ci_locked_builds_match_documented_gate_set() {
    // W1-L17-01: Task 22 (L16-06) put --locked on every CI build/test/check/
    // clippy line; this gate confirms that coverage holds and that
    // doc/development.md's G-7 gate text (notably the MSRV lines) matches
    // the enforced CI commands.
    const GATED_VERBS: &[&str] = &[
        "cargo build",
        "cargo test",
        "cargo check",
        "cargo clippy",
        "cargo xwin",
        "cargo install",
    ];
    let root = workspace_root();
    let ci_workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .expect(".github/workflows/ci.yml should be readable");
    for line in ci_workflow.lines() {
        let trimmed = line.trim();
        // Comments describe gates; step names label them; neither executes.
        if trimmed.starts_with('#')
            || trimmed.starts_with("- name:")
            || trimmed.starts_with("name:")
        {
            continue;
        }
        if GATED_VERBS.iter().any(|verb| trimmed.contains(verb)) {
            assert!(trimmed.contains("--locked"), "CI cargo line should run --locked: `{trimmed}`");
        }
    }

    // Deferred T22 F3: nightly's llvm-cov/miri lines run --locked too
    // (same lockfile, no nightly conflict). `cargo llvm-cov report`
    // accepts --locked (listed in its --help alongside the other
    // subcommands) and `cargo miri test` supports the same flags as
    // `cargo test`, so every cargo line here carries it.
    const NIGHTLY_GATED_VERBS: &[&str] = &[
        "cargo build",
        "cargo test",
        "cargo check",
        "cargo clippy",
        "cargo xwin",
        "cargo install",
        "cargo llvm-cov",
        "miri test",
    ];
    let nightly = fs::read_to_string(root.join(".github/workflows/nightly.yml"))
        .expect(".github/workflows/nightly.yml should be readable");
    for line in nightly.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#')
            || trimmed.starts_with("- name:")
            || trimmed.starts_with("name:")
        {
            continue;
        }
        if NIGHTLY_GATED_VERBS.iter().any(|verb| trimmed.contains(verb)) {
            assert!(
                trimmed.contains("--locked"),
                "nightly cargo line should run --locked: `{trimmed}`"
            );
        }
    }

    let development = fs::read_to_string(root.join("doc/development.md"))
        .expect("doc/development.md should be readable");
    let mut in_fence = false;
    for line in development.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence {
            continue;
        }
        if GATED_VERBS.iter().any(|verb| line.contains(verb)) {
            assert!(
                line.contains("--locked"),
                "development.md cargo line should run --locked: `{line}`"
            );
        }
    }
    // The MSRV lines must mirror the enforced CI MSRV job (locked
    // all-targets build plus the locked test suite), not a bare build.
    for msrv_command in [
        "cargo +1.88.0 build --workspace --locked --all-targets",
        "cargo +1.88.0 test --workspace --locked",
    ] {
        assert!(
            development.contains(msrv_command),
            "development.md should document the enforced MSRV command `{msrv_command}`"
        );
    }
    assert!(
        ci_workflow.contains("cargo build --workspace --locked --all-targets"),
        "CI MSRV job should keep the locked all-targets build"
    );
    assert!(
        ci_workflow.contains("cargo test --workspace --locked"),
        "CI MSRV job should keep the locked test suite"
    );
}

#[test]
fn release_receipt_path_is_version_parameterized() {
    // W1-L17-02: the shared helper owns receipt path and delta checks.
    // scripts/test-verify-quality-receipt.sh exercises its version fixtures.
    // Stage C: release.yml is workflow_call plus exact-tag manual retry, so
    // the guard takes the validated tag input — GITHUB_REF_NAME names the
    // caller's ref and must not select the release subject here.
    let root = workspace_root();
    let release = fs::read_to_string(root.join(".github/workflows/release.yml"))
        .expect(".github/workflows/release.yml should be readable");
    assert!(
        release.contains("scripts/verify-quality-receipt.sh \"$RECOVER_TAG\""),
        "release workflow should invoke the shipped receipt guard with the validated tag"
    );
    assert!(
        !release.contains("verify-quality-receipt.sh \"$GITHUB_REF_NAME\""),
        "receipt guard must not take the caller-controlled GITHUB_REF_NAME"
    );
}

#[test]
fn release_bundle_uses_pinned_timestamp_helper() {
    // W1-L17-04, Stage C: byte-reproducible bundles moved out of inline
    // YAML tar into scripts/release/package_bundles.py (gzip filename "",
    // mtime 0, tar uid/gid 0, member mtime pinned). The workflow must route
    // both targets through that helper with the tag date — never inline
    // tar packaging and never a wall-clock timestamp.
    let root = workspace_root();
    let release = fs::read_to_string(root.join(".github/workflows/release.yml"))
        .expect(".github/workflows/release.yml should be readable");
    assert!(
        !release.contains("tar -c"),
        "release workflow should not package bundles with inline tar"
    );
    assert!(
        !release.contains("GZIP="),
        "release workflow should not set GZIP outside the bundle helper"
    );
    assert!(
        release.matches("bundle --binaries").count() >= 2,
        "both binary jobs should stage bundles through the helper"
    );
    assert!(
        release.contains("--timestamp \"$TAG_DATE\""),
        "bundle helper should pin member timestamps to the tag date"
    );
}

#[test]
fn packaging_split_is_explicit_with_per_pr_smoke() {
    // W1-L17-05: full APK/RPM carrier builds stay in external GitLab by
    // design; the split is documented there and GitHub runs a per-PR
    // packaging smoke (mirror + syntax) instead.
    let root = workspace_root();
    let gitlab =
        fs::read_to_string(root.join(".gitlab-ci.yml")).expect(".gitlab-ci.yml should be readable");
    assert!(
        gitlab.contains("packaging-smoke"),
        ".gitlab-ci.yml should document the by-design split and name the GitHub per-PR smoke"
    );
    let ci_workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .expect(".github/workflows/ci.yml should be readable");
    assert!(
        ci_workflow.contains("scripts/packaging-smoke.sh"),
        "CI should run the per-PR packaging smoke"
    );
    let smoke = root.join("scripts/packaging-smoke.sh");
    assert!(smoke.is_file(), "scripts/packaging-smoke.sh should exist");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&smoke)
            .expect("packaging smoke script should be readable")
            .permissions()
            .mode();
        assert!(mode & 0o111 != 0, "scripts/packaging-smoke.sh should be executable");
    }
}

#[test]
fn ci_jobs_all_set_timeouts() {
    // W1-L17-07: every ci.yml job sets timeout-minutes; none inherits the
    // 6h default.
    let root = workspace_root();
    let ci_workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .expect(".github/workflows/ci.yml should be readable");
    let mut jobs: Vec<(String, bool)> = Vec::new();
    let mut in_jobs = false;
    for line in ci_workflow.lines() {
        if line == "jobs:" {
            in_jobs = true;
            continue;
        }
        if !in_jobs {
            continue;
        }
        let trimmed = line.trim_start();
        if line.starts_with("  ")
            && !line.starts_with("   ")
            && line.ends_with(':')
            && !trimmed.starts_with('#')
        {
            jobs.push((trimmed.trim_end_matches(':').to_string(), false));
            continue;
        }
        if let Some(current) = jobs.last_mut()
            && !current.1
            && let Some(value) = line.strip_prefix("    timeout-minutes: ")
        {
            let minutes: u32 = value.trim().parse().expect("timeout-minutes should be numeric");
            assert!(
                (5..=120).contains(&minutes),
                "timeout-minutes should be a bounded non-default value, got {minutes}"
            );
            current.1 = true;
        }
    }
    assert!(!jobs.is_empty(), "expected ci.yml jobs");
    for (name, has_timeout) in &jobs {
        assert!(has_timeout, "ci.yml job `{name}` should set timeout-minutes");
    }
}

/// Inner texts of every `(not ...)` atom in a pkcs11-check `--match`
/// expression, via paren matching.
fn not_atoms(match_expr: &str) -> Vec<String> {
    let bytes = match_expr.as_bytes();
    let mut atoms = Vec::new();
    let mut i = 0;
    while i + 5 <= bytes.len() {
        if bytes[i..i + 5] == *b"(not " {
            let mut depth = 1;
            let mut j = i + 5;
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            assert_eq!(depth, 0, "unbalanced parens in exclusion expression");
            atoms.push(match_expr[i + 5..j - 1].to_string());
            i = j;
        } else {
            i += match_expr[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
        }
    }
    atoms
}

// W1-L17-09: the cross-platform exclusion record. Every exclusion is
// provider/framework-side only (proven red WITHOUT the proxy); proxy bugs
// are never excluded. Changing the workflow list requires updating this
// record + its justification together, so exclusion edits trip review.
const XPLAT_PINNED_EXCLUSIONS: &[&str] = &[
    "test_ckr_digest",
    "test_ckr_keygen",
    "test_ckr_sign",
    "test_ckr_verify",
    "test_arithmetic_overflow",
    "test_cve_regression",
    "test_ffi_length_boundary",
    "test_padding_oracle",
    "test_parameter_validation",
    "test_scalar_attr_length_extended",
    "test_tookan",
    "test_mech_negative",
    "test_operation_termination",
    "test_set_attribute or test_set_attribute_after_destroy or test_set_attribute_token_object_in_ro_fails",
    "test_verify_operability",
    "(test_ckr_decrypt and test_key_type_inconsistent)",
    "(test_ckr_encrypt and test_key_size_range)",
    "test_bad_mechanism_with_bad_key_size",
    "(test_null_template_nonzero_count and C_GenerateKey)",
    "test_dh_rejects_tiny_prime",
];

#[test]
fn xplat_exclusion_list_matches_pinned_record() {
    // W1-L17-09: the exclusion list is gated — any add/remove fails here
    // until the pinned record + justification move together. The KAT-only
    // residual itself stays narrowed explicitly (gate-script docstring),
    // never widened silently.
    let root = workspace_root();
    let xplat = fs::read_to_string(root.join(".github/workflows/cross-platform.yml"))
        .expect(".github/workflows/cross-platform.yml should be readable");
    assert!(
        xplat.contains("Owner rule:"),
        "cross-platform.yml should keep the exclusion owner rule"
    );
    assert!(
        xplat.contains("xplat_exclusion_list_matches_pinned_record"),
        "cross-platform.yml should point exclusion edits at the pinned-record gate test"
    );
    let match_line = xplat
        .lines()
        .find(|line| line.contains("EXTRA_P11CHECK_ARGS"))
        .expect("cross-platform.yml should set EXTRA_P11CHECK_ARGS");
    let mut atoms = not_atoms(match_line);
    atoms.sort();
    let mut pinned: Vec<String> = XPLAT_PINNED_EXCLUSIONS.iter().map(ToString::to_string).collect();
    pinned.sort();
    assert_eq!(
        atoms, pinned,
        "EXTRA_P11CHECK_ARGS exclusions should match the pinned record (update both + justification together)"
    );
    let gate = fs::read_to_string(root.join("scripts/ci-direct-vs-proxy.py"))
        .expect("scripts/ci-direct-vs-proxy.py should be readable");
    assert!(
        gate.contains("Known residual"),
        "gate script should keep documenting the KAT-only residual scope"
    );
}

#[test]
fn version_mirror_check_is_shared() {
    // W1-L17-10: one 4-mirror version definition, sourced by all three
    // release scripts (plus the L17-05 packaging smoke).
    let root = workspace_root();
    let lib = fs::read_to_string(root.join("scripts/lib/version-mirrors.sh"))
        .expect("scripts/lib/version-mirrors.sh should exist");
    assert!(
        lib.contains("check_version_mirrors"),
        "shared lib should define check_version_mirrors"
    );
    for mirror in [
        ".gitlab-ci.yml",
        "packaging/alpine/APKBUILD",
        "packaging/amazon/pkcs11-proxy-ng.spec",
        "packaging/amazon/Dockerfile.amazon",
    ] {
        assert!(lib.contains(mirror), "shared lib should define the {mirror} mirror");
    }
    // The Dockerfile-ARG extraction program is the canary: it must exist in
    // exactly one place (the lib), never inlined per script.
    let mut definitions = lib.matches("ARG APP_VERSION=([^[:space:]]+)").count();
    for script in [
        "scripts/release-dry-run.sh",
        "scripts/release-windows.sh",
        "scripts/verify-release-subject.sh",
        "scripts/packaging-smoke.sh",
    ] {
        let text =
            fs::read_to_string(root.join(script)).expect("release script should be readable");
        assert!(
            text.contains("version-mirrors.sh"),
            "{script} should source the shared mirror check"
        );
        definitions += text.matches("ARG APP_VERSION=([^[:space:]]+)").count();
    }
    assert_eq!(definitions, 1, "the 4-mirror definition should live in exactly one place");
}

#[test]
fn nss_fixture_lane_runs_by_default() {
    // W1-L17-11: the NSS fixture lane runs in a default test-matrix run;
    // the opt-out is a real --skip-nss-fixtures flag, not an unset var.
    let root = workspace_root();
    let matrix = fs::read_to_string(root.join("scripts/test-matrix.sh"))
        .expect("scripts/test-matrix.sh should be readable");
    assert!(
        matrix.contains("test-nss-fixtures.sh"),
        "test-matrix.sh should wire the NSS fixture lane"
    );
    assert!(
        matrix.contains("--skip-nss-fixtures"),
        "test-matrix.sh should offer a real --skip-nss-fixtures flag"
    );
    assert!(
        matrix.matches("--skip-nss-fixtures").count() >= 2,
        "--skip-nss-fixtures should appear in both usage and the parser"
    );
    assert!(matrix.contains("run_nss_fixtures=1"), "NSS fixture lane should default on");
    assert!(!matrix.contains("RUN_NSS_FIXTURES"), "NSS lane should not gate on an env var");
    assert!(
        !matrix.contains("--run-nss-fixtures"),
        "test-matrix.sh should not cite a nonexistent flag"
    );
    // The lane's old Docker hang was certutil -S reading an infinite -z
    // noise file (NSS reads to EOF; /dev/urandom never EOFs): pin the
    // finite-noise fix.
    let fixtures = fs::read_to_string(root.join("scripts/test-nss-fixtures.sh"))
        .expect("scripts/test-nss-fixtures.sh should be readable");
    assert!(
        !fixtures.contains("-z /dev/urandom"),
        "fixture cert seeding must use a finite noise file, never /dev/urandom"
    );
}

#[test]
fn consumer_tier_fails_on_pkcs11test_failure() {
    // W1-L17-23: a failing pkcs11test fails the consumer tier; its output
    // is captured to a per-tag log, not discarded with || true.
    let root = workspace_root();
    let consumers = fs::read_to_string(root.join("scripts/test-consumers.sh"))
        .expect("scripts/test-consumers.sh should be readable");
    let suite = shell_function_body(&consumers, "run_pkcs11test_suite");
    let code: String = suite
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!code.contains("|| true"), "pkcs11test must not force success with || true");
    assert!(
        suite.contains("pkcs11test-$tag.log"),
        "pkcs11test output should be captured to a per-tag log"
    );
    assert!(
        suite.contains("return \"$rc\""),
        "pkcs11test failure should propagate its exit status"
    );
}

#[test]
fn consumer_tier_daemon_boot_uses_readiness_probe() {
    // W1-L17-24: daemon boot waits on a readiness probe (port + liveness),
    // not a fixed sleep.
    let root = workspace_root();
    let consumers = fs::read_to_string(root.join("scripts/test-consumers.sh"))
        .expect("scripts/test-consumers.sh should be readable");
    assert!(!consumers.contains("sleep 1"), "daemon boot should not use a fixed sleep");
    assert!(
        consumers.contains("wait_for_daemon() {"),
        "test-consumers.sh should define a daemon readiness probe"
    );
    assert!(
        consumers.contains("wait_for_daemon \"$daemon_pid\" \"$PORT\""),
        "daemon boot should wait on the readiness probe"
    );
}

#[test]
fn ignored_test_taxonomy_covers_all_ignored_rust_lanes() {
    let root = workspace_root();
    let tests_dir = root.join("crates/server/tests");
    let readme = fs::read_to_string(tests_dir.join("README.md"))
        .expect("crates/server/tests/README.md should be readable");

    let ignored_files: BTreeSet<String> = fs::read_dir(&tests_dir)
        .expect("crates/server/tests should be readable")
        .map(|entry| entry.expect("test directory entry should be readable").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .filter(|path| path.file_name().is_some_and(|name| name != "local_quality_gate_test.rs"))
        .filter(|path| {
            fs::read_to_string(path)
                .expect("Rust test file should be readable")
                .contains("#[ignore")
        })
        .map(|path| {
            format!(
                "crates/server/tests/{}",
                path.file_name().expect("test file should have a name").to_string_lossy()
            )
        })
        .collect();

    let taxonomy_files: BTreeSet<String> =
        IGNORED_TEST_TAXONOMY.iter().map(|lane| lane.file.to_string()).collect();
    assert_eq!(
        ignored_files, taxonomy_files,
        "every ignored Rust test file should have exactly one taxonomy entry"
    );

    assert!(
        readme.contains("## Ignored test taxonomy"),
        "test README should document the ignored test taxonomy"
    );
    for lane in IGNORED_TEST_TAXONOMY {
        assert!(readme.contains(lane.file), "README should document {}", lane.file);
        assert!(readme.contains(lane.reason), "README should document reason for {}", lane.file);
        for command in lane.commands {
            assert!(
                readme.contains(command),
                "README should document command `{command}` for {}",
                lane.file
            );
        }
        for requirement in lane.requirements {
            assert!(
                readme.contains(requirement),
                "README should document requirement `{requirement}` for {}",
                lane.file
            );
        }
    }
}

#[test]
fn provider_backend_script_uses_ephemeral_kryoptic_defaults() {
    let root = workspace_root();
    let script = fs::read_to_string(root.join("scripts/test-provider-backends.sh"))
        .expect("scripts/test-provider-backends.sh should be readable");

    assert!(
        !script.contains("/tmp/kryoptic"),
        "provider backend script must not default Kryoptic tests to persistent /tmp state"
    );
    assert!(
        script.contains("mktemp -d"),
        "provider backend script should create an isolated Kryoptic token directory"
    );
    assert!(
        script.contains("rm -rf"),
        "provider backend script should clean up its isolated Kryoptic token directory"
    );
    assert!(
        !script.contains("PKCS11_PROXY_KRYOPTIC_TOKEN_LABEL:-kryoptic-token}"),
        "provider backend script must not reuse a fixed Kryoptic token label by default"
    );
    assert!(
        !script.contains("PKCS11_PROXY_KRYOPTIC_USER_PIN:-12345678"),
        "provider backend script must not reuse a fixed Kryoptic user PIN by default"
    );
    assert!(
        !script.contains("PKCS11_PROXY_KRYOPTIC_SO_PIN:-87654321"),
        "provider backend script must not reuse a fixed Kryoptic SO PIN by default"
    );
}

#[test]
fn env_driven_provider_fixtures_do_not_synthesize_shared_credentials() {
    let root = workspace_root();
    let source = fs::read_to_string(root.join("crates/server/tests/support/providers.rs"))
        .expect("provider fixture source should be readable");

    assert!(
        !source.contains("unwrap_or_else(|_| \"test-token\".into())"),
        "env-driven provider fixtures should require an explicit token label"
    );
    assert!(
        !source.contains("unwrap_or_else(|_| \"1234\".into())"),
        "env-driven provider fixtures should require an explicit user PIN"
    );
    assert!(
        !source.contains("unwrap_or_else(|_| \"5678\".into())"),
        "env-driven provider fixtures should require an explicit SO PIN"
    );
}

#[test]
fn shim_raw_slice_construction_stays_centralized() {
    let root = workspace_root();
    // The audited raw-slice constructions live in the helpers module family
    // (split from the former single helpers/mod.rs in 2026-07); everything
    // else in the shim must go through those helpers.
    let allowed_dir = root.join("crates/shim/src/dispatch/general/helpers");
    let mut offenders = Vec::new();

    for source in rust_sources_under(&root.join("crates/shim/src")) {
        if source.starts_with(&allowed_dir) {
            continue;
        }
        let text = fs::read_to_string(&source).expect("Rust source should be readable");
        if text.contains("from_raw_parts(") || text.contains("from_raw_parts_mut(") {
            offenders.push(
                source
                    .strip_prefix(&root)
                    .expect("source should be under workspace root")
                    .display()
                    .to_string(),
            );
        }
    }

    assert!(
        offenders.is_empty(),
        "raw FFI slice construction should stay in the helpers module; offenders: {offenders:?}"
    );
}

#[test]
fn debug_bundle_archive_omits_environment_values() {
    let root = workspace_root();
    let output_dir = tempfile::tempdir().expect("temp output dir should be created");
    let extraction_dir = tempfile::tempdir().expect("temp extraction dir should be created");
    let pin_canary = "secret-pin-value";
    let registry_canary = "secret-registry-token";
    let endpoint_canary = "http://user:secret-endpoint@example.invalid";

    let status = Command::new(root.join("scripts/collect-debug-bundle.sh"))
        .arg("--output-dir")
        .arg(output_dir.path())
        .env("PKCS11_PROXY_PIN", pin_canary)
        .env("CARGO_REGISTRIES_PRIVATE_TOKEN", registry_canary)
        .env("PKCS11_PROXY_ENDPOINT", endpoint_canary)
        .status()
        .expect("debug bundle script should run");
    assert!(status.success(), "debug bundle script should exit successfully");

    let archive = fs::read_dir(output_dir.path())
        .expect("output dir should be readable")
        .map(|entry| entry.expect("bundle entry should be readable").path())
        .find(|path| path.extension().is_some_and(|ext| ext == "gz"))
        .expect("debug bundle archive should exist");

    let output = Command::new("tar")
        .arg("-xzf")
        .arg(&archive)
        .arg("-C")
        .arg(extraction_dir.path())
        .output()
        .expect("tar should extract the debug bundle");
    assert!(output.status.success(), "tar should extract the debug bundle");

    let mut pending = vec![extraction_dir.path().to_path_buf()];
    let mut files_seen = 0;
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).expect("extracted directory should be readable") {
            let entry = entry.expect("extracted entry should be readable");
            if entry.file_type().expect("entry type should be readable").is_dir() {
                pending.push(entry.path());
                continue;
            }
            let contents = fs::read(entry.path()).expect("bundle file should be readable");
            for canary in [pin_canary, registry_canary, endpoint_canary] {
                assert!(
                    !contents.windows(canary.len()).any(|window| window == canary.as_bytes()),
                    "environment value must not be archived: {}",
                    entry.path().display()
                );
            }
            files_seen += 1;
        }
    }
    assert!(files_seen > 0, "the extracted archive should contain metadata files");
}

#[test]
fn ffi_init_cancel_paths_forward_null_mechanism_init_verbatim() {
    // ADR-0010: a NULL-mechanism C_*Init must reach the backend module as the
    // original call so its native CK_RV (or crash) is what the client
    // observes. Routing any of these through C_SessionCancel substitutes
    // proxy policy for module behavior and regresses transparency both ways
    // (FUNCTION_NOT_SUPPORTED on 2.40 modules, CKR_OK on 3.0 modules).
    let root = workspace_root();
    let source = fs::read_to_string(root.join("crates/backend/src/ffi/crypto_ops.rs"))
        .expect("crates/backend/src/ffi/crypto_ops.rs should be readable");

    assert!(
        !source.contains("ffi_session_cancel"),
        "init-cancel paths in crypto_ops.rs must not route through C_SessionCancel (ADR-0010)"
    );
    for (cancel_fn, forwarded_init) in [
        ("ffi_sign_init_cancel", "C_SignInit"),
        ("ffi_sign_recover_init_cancel", "C_SignRecoverInit"),
        ("ffi_verify_init_cancel", "C_VerifyInit"),
        ("ffi_verify_recover_init_cancel", "C_VerifyRecoverInit"),
        ("ffi_digest_init_cancel", "C_DigestInit"),
        ("ffi_encrypt_init_cancel", "C_EncryptInit"),
        ("ffi_decrypt_init_cancel", "C_DecryptInit"),
    ] {
        let start = source
            .find(&format!("fn {cancel_fn}("))
            .unwrap_or_else(|| panic!("{cancel_fn} should exist in crypto_ops.rs"));
        let body = &source[start..];
        let body = &body[..body[1..].find("pub(super) fn ").map(|i| i + 1).unwrap_or(body.len())];
        assert!(
            body.contains(forwarded_init) && body.contains("null_mut"),
            "{cancel_fn} must forward {forwarded_init}(NULL mechanism) verbatim (ADR-0010)"
        );
    }
}

/// ADR-0010 Scope 2 completeness gate: every class-1 data-input dispatch site
/// must use `classify_input` instead of `read_input_slice` so that NULL
/// pointers are forwarded faithfully to the backend rather than silently
/// flattened to an empty slice.
///
/// Lines reading `p_parameter` are class-5 message parameters — exempt here.
/// PIN/template readers (admin.rs, object.rs, session*.rs) are classes 2-3
/// and are also exempt.
///
/// Run it with:
///
/// ```text
/// cargo test -p pkcs11-proxy-ng --test local_quality_gate_test class1 2>&1 | tail -5
/// ```
#[test]
fn class1_dispatch_sites_use_classified_input_reader() {
    let root = workspace_root();
    for file in [
        "crates/shim/src/dispatch/general/digest_cipher.rs",
        "crates/shim/src/dispatch/general/sign_verify.rs",
        "crates/shim/src/dispatch/general/verify_signature.rs",
        "crates/shim/src/dispatch/general/combined.rs",
        "crates/shim/src/dispatch/general/key_ops.rs",
        "crates/shim/src/dispatch/general/kem.rs",
        "crates/shim/src/dispatch/general/state_ops.rs",
        "crates/shim/src/dispatch/general/message_crypto.rs",
        "crates/shim/src/dispatch/general/authenticated_wrap.rs",
    ] {
        let src = fs::read_to_string(root.join(file)).expect(file);
        for (i, line) in src.lines().enumerate() {
            if line.contains("read_input_slice") && !line.contains("p_parameter") {
                panic!(
                    "{file}:{} still uses read_input_slice for a class-1 input — use classify_input (ADR-0010)",
                    i + 1
                );
            }
        }
    }
}

/// W1-L11-21: the shim-dead per-function byte-output RPCs are retained
/// for CLI/compat under ONE documented decision — not silently.
///
/// * `service.proto` carries the retention notice: it names every legacy
///   RPC plus the removal version (delimited BEGIN/END block).
/// * Every corresponding server handler carries the uniform legacy
///   marker (same text everywhere = handled consistently).
///
/// Covering a new per-function RPC with the Exact family without
/// retiring it or listing it here fails this gate.
#[test]
fn legacy_per_function_rpcs_have_documented_retention() {
    // (rpc name, handler source file, handler fn anchor)
    const LEGACY: &[(&str, &str, &str)] = &[
        ("Sign", "crates/server/src/server/grpc_service/sign_verify/sign.rs", "async fn sign("),
        (
            "SignFinal",
            "crates/server/src/server/grpc_service/sign_verify/sign.rs",
            "async fn sign_final(",
        ),
        (
            "SignRecover",
            "crates/server/src/server/grpc_service/sign_verify/sign.rs",
            "async fn sign_recover(",
        ),
        (
            "VerifyRecover",
            "crates/server/src/server/grpc_service/sign_verify/verify.rs",
            "async fn verify_recover(",
        ),
        (
            "Digest",
            "crates/server/src/server/grpc_service/digest_cipher/digest.rs",
            "async fn digest(",
        ),
        (
            "DigestFinal",
            "crates/server/src/server/grpc_service/digest_cipher/digest.rs",
            "async fn digest_final(",
        ),
        (
            "Encrypt",
            "crates/server/src/server/grpc_service/digest_cipher/cipher.rs",
            "async fn encrypt(",
        ),
        (
            "EncryptUpdate",
            "crates/server/src/server/grpc_service/digest_cipher/cipher.rs",
            "async fn encrypt_update(",
        ),
        (
            "EncryptFinal",
            "crates/server/src/server/grpc_service/digest_cipher/cipher.rs",
            "async fn encrypt_final(",
        ),
        (
            "Decrypt",
            "crates/server/src/server/grpc_service/digest_cipher/cipher.rs",
            "async fn decrypt(",
        ),
        (
            "DecryptUpdate",
            "crates/server/src/server/grpc_service/digest_cipher/cipher.rs",
            "async fn decrypt_update(",
        ),
        (
            "DecryptFinal",
            "crates/server/src/server/grpc_service/digest_cipher/cipher.rs",
            "async fn decrypt_final(",
        ),
        (
            "DigestEncryptUpdate",
            "crates/server/src/server/grpc_service/combined/sign_encrypt.rs",
            "async fn digest_encrypt_update(",
        ),
        (
            "SignEncryptUpdate",
            "crates/server/src/server/grpc_service/combined/sign_encrypt.rs",
            "async fn sign_encrypt_update(",
        ),
        (
            "DecryptDigestUpdate",
            "crates/server/src/server/grpc_service/combined/decrypt_digest.rs",
            "async fn decrypt_digest_update(",
        ),
        (
            "DecryptVerifyUpdate",
            "crates/server/src/server/grpc_service/combined/decrypt_digest.rs",
            "async fn decrypt_verify_update(",
        ),
        (
            "GetOperationState",
            "crates/server/src/server/grpc_service/state_ops/operation_state.rs",
            "async fn get_operation_state(",
        ),
        (
            "WrapKey",
            "crates/server/src/server/grpc_service/key_ops/wrapping.rs",
            "async fn wrap_key(",
        ),
        (
            "EncapsulateKey",
            "crates/server/src/server/grpc_service/key_ops/kem.rs",
            "async fn encapsulate_key(",
        ),
    ];
    const MARKER: &str = "NOTE: legacy per-op RPC (W1-L11-21 retention; see service.proto)";

    let root = workspace_root();
    let proto =
        fs::read_to_string(root.join("crates/proto/proto/pkcs11-proxy-ng/v1/service.proto"))
            .expect("service.proto should be readable");
    let begin = proto
        .find("Legacy per-function retention (W1-L11-21) - BEGIN")
        .expect("service.proto must carry the legacy retention notice block");
    let end = proto
        .find("Legacy per-function retention (W1-L11-21) - END")
        .expect("service.proto retention notice must be delimited");
    assert!(begin < end, "retention notice delimiters out of order");
    let notice = &proto[begin..end];
    assert!(notice.contains("v0.4.0"), "retention notice must state the removal version");
    for (rpc, _, _) in LEGACY {
        assert!(notice.contains(rpc), "retention notice must name the legacy rpc {rpc}");
    }

    for (rpc, file, anchor) in LEGACY {
        let src = fs::read_to_string(root.join(file)).expect("handler source readable");
        let at = src.find(anchor).unwrap_or_else(|| panic!("{file} must define {anchor}"));
        let window_start = at.saturating_sub(600);
        assert!(
            src[window_start..at].contains(MARKER),
            "{file} handler for legacy rpc {rpc} must carry the uniform legacy marker"
        );
    }
}

// ── W1-L17/L16 (Task 44): CI hygiene (shellcheck, versions, perms, wiring) ──

#[test]
fn ci_runs_pinned_shellcheck_over_all_scripts() {
    // W1-L17-12: a CI job runs the mise-pinned shellcheck (0.11.0) over
    // every scripts/**/*.sh; failures block CI. The step enumerates via
    // find so newly added scripts are covered without a workflow edit.
    let root = workspace_root();
    let mise = fs::read_to_string(root.join("mise.toml")).expect("mise.toml should be readable");
    assert!(
        mise.contains("shellcheck = \"0.11.0\""),
        "mise.toml should pin shellcheck 0.11.0 (single version everywhere)"
    );
    let ci_workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .expect(".github/workflows/ci.yml should be readable");
    assert!(
        ci_workflow.contains("  shellcheck:"),
        "ci.yml should carry a shellcheck job so script regressions block CI"
    );
    let install = workflow_step_body(&ci_workflow, "Install shellcheck (pinned)");
    assert!(
        install.contains("0.11.0") && install.contains("sha256sum"),
        "shellcheck install step should pin 0.11.0 with hash verification"
    );
    let run = workflow_step_body(&ci_workflow, "shellcheck all scripts");
    assert!(
        run.contains("find scripts") && run.contains("shellcheck"),
        "shellcheck step should enumerate scripts via find, not a hardcoded list"
    );
    let scripts: Vec<PathBuf> = {
        fn visit(path: &Path, output: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(path).expect("scripts dir should be readable") {
                let path = entry.expect("entry should be readable").path();
                if path.is_dir() {
                    visit(&path, output);
                } else if path.extension().is_some_and(|ext| ext == "sh") {
                    output.push(path);
                }
            }
        }
        let mut out = Vec::new();
        visit(&root.join("scripts"), &mut out);
        out
    };
    assert!(
        scripts.len() >= 30,
        "expected at least the 30 audited shell scripts, found {len}",
        len = scripts.len()
    );
}

#[test]
fn artifact_action_versions_are_uniform() {
    // W1-L17-13: every actions/upload-artifact site pins the same v5 SHA
    // (nightly/xplat lagged on v4 while release/cache used v5).
    let root = workspace_root();
    let mut pins: Vec<(String, String)> = Vec::new();
    for workflow in ["ci.yml", "nightly.yml", "release.yml", "cross-platform.yml"] {
        let text = fs::read_to_string(root.join(format!(".github/workflows/{workflow}")))
            .expect("workflow should be readable");
        for line in text.lines() {
            let Some(at) = line.find("actions/upload-artifact@") else {
                continue;
            };
            let rest = &line[at + "actions/upload-artifact@".len()..];
            let sha: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            assert_eq!(sha.len(), 40, "upload-artifact pin should be a full SHA: `{line}`");
            pins.push((workflow.to_string(), sha));
            assert!(
                line.contains("# v5"),
                "{workflow} upload-artifact pin should be tagged v5: `{line}`"
            );
        }
    }
    assert!(!pins.is_empty(), "expected upload-artifact sites");
    for (workflow, sha) in &pins {
        assert_eq!(
            sha, &pins[0].1,
            "{workflow} upload-artifact SHA should match the single pinned version"
        );
    }
}

#[test]
fn deny_blocks_main_leg_with_standalone_coverage() {
    // W1-L17-15: Task 22 put deny on the build-and-test needs edge; this
    // gate confirms that coverage holds and closes the nightly residual
    // (Tier-0 sanity ran `cargo deny check` but skipped the standalone
    // test-workspace locks that ci.yml covers).
    let root = workspace_root();
    let ci_workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .expect(".github/workflows/ci.yml should be readable");
    assert!(
        ci_workflow.contains("needs: [fmt, audit, deny]"),
        "build-and-test should wait on the deny job, not report green-then-red"
    );
    let nightly = fs::read_to_string(root.join(".github/workflows/nightly.yml"))
        .expect(".github/workflows/nightly.yml should be readable");
    assert!(
        nightly.contains("scripts/audit-test-workspaces.sh deny"),
        "nightly Tier-0 sanity should cover the standalone test-workspace locks like ci.yml"
    );
}

#[test]
fn release_notes_awk_matches_version_literally() {
    // W1-L17-17: the release-notes awk interpolated the version as regex,
    // so 0.2.0 also matched a hypothetical ## [0x2x0] heading. The version
    // is dot-escaped before interpolation (same rule as
    // verify-release-subject.sh BASE_ESCAPED); the tag-format validation
    // above it guarantees the remaining charset is regex-literal.
    // Stage C: the step reads the validated exact-tag input (workflow_call
    // callers control GITHUB_REF_NAME) and writes RELEASE_NOTES.md for the
    // combined asset path; the literal-match rule is unchanged.
    let root = workspace_root();
    let release = fs::read_to_string(root.join(".github/workflows/release.yml"))
        .expect(".github/workflows/release.yml should be readable");
    let step = workflow_step_body(&release, "Extract release notes from CHANGELOG.md");
    assert!(
        step.contains("${RELEASE_VERSION//./"),
        "extraction step should dot-escape the version before awk interpolation"
    );
    assert!(
        !step.contains("-v ver="),
        "awk should receive the escaped version, not the raw dotted one"
    );
    #[cfg(unix)]
    {
        // Fixture proof: execute the workflow's own script text with a
        // decoy heading that the old regex matched.
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("CHANGELOG.md"),
            "# Changelog\n\n## [0x2x0] - 2000-01-01\n\nDECOY notes.\n\n\
             ## [0.2.0] - 2026-01-01\n\nReal notes.\n",
        )
        .expect("fixture CHANGELOG");
        let status = Command::new("bash")
            .arg("-c")
            .arg(&step)
            .current_dir(dir.path())
            .env("RELEASE_TAG", "v0.2.0")
            .status()
            .expect("bash should run the extraction step");
        assert!(status.success(), "extraction step should succeed on the fixture");
        let notes = fs::read_to_string(dir.path().join("RELEASE_NOTES.md"))
            .expect("RELEASE_NOTES.md should be written");
        assert!(
            notes.contains("Real notes.") && !notes.contains("DECOY"),
            "extraction should match only the literal heading, got: {notes:?}"
        );
    }
}

#[test]
fn win32_stub_proof_uses_machine_readable_assertion() {
    // W1-L17-18: the stub proof keyed on libtest's human-readable
    // "1 passed" summary. --format json is nightly-only (stable libtest
    // rejects it), so the pass signal is the exit code (pipefail) plus
    // the test's own machine-readable receipt line, with --exact pinning
    // the filter so a rename/typo cannot silently match zero tests.
    let root = workspace_root();
    let xplat = fs::read_to_string(root.join(".github/workflows/cross-platform.yml"))
        .expect(".github/workflows/cross-platform.yml should be readable");
    let step = workflow_step_body(&xplat, "Win32 stub live-load proof");
    assert!(step.contains("--exact"), "stub proof should pin the filter with --exact");
    assert!(step.contains("pipefail"), "stub proof should fail on the cargo exit code");
    assert!(
        !step.contains("1 passed"),
        "stub proof should not depend on the human-readable summary"
    );
    assert!(
        step.contains("win32-stub-live-load: ok"),
        "stub proof should assert the test's own receipt line"
    );
}

#[test]
fn dockerfile_test_surfaces_precompile_errors() {
    // W1-L17-19: the dependency-cache layer discarded stderr and forced
    // success, misattributing broken manifests to the later source build.
    // (Base-image digest pinning landed in Task 22; this closes the
    // masking residual only.)
    let root = workspace_root();
    let dockerfile = fs::read_to_string(root.join("Dockerfile.test"))
        .expect("Dockerfile.test should be readable");
    let mut cargo_builds = 0;
    for line in dockerfile.lines() {
        if line.contains("cargo build") {
            cargo_builds += 1;
            assert!(
                !line.contains("|| true"),
                "Dockerfile.test cargo build should fail the image, not force success: `{line}`"
            );
            assert!(
                !line.contains("2>/dev/null"),
                "Dockerfile.test cargo build should surface stderr: `{line}`"
            );
        }
    }
    assert!(cargo_builds >= 2, "expected the cache + source cargo builds");
    // The unmasked cache layer resolves declared targets at
    // manifest-parse time, so every [[bench]] in server/Cargo.toml needs
    // a stub here (see the Dockerfile comment); pin the correspondence
    // per-PR since the image itself builds only in nightly.
    let server_manifest =
        fs::read_to_string(root.join("crates/server/Cargo.toml")).expect("server manifest");
    let mut in_bench = false;
    let mut benches = 0;
    for line in server_manifest.lines() {
        if line == "[[bench]]" {
            in_bench = true;
            continue;
        }
        if line.starts_with('[') {
            in_bench = false;
            continue;
        }
        if in_bench && let Some(name) = line.strip_prefix("name = ") {
            let name = name.trim_matches('"');
            benches += 1;
            assert!(
                dockerfile.contains(name),
                "Dockerfile.test should stub the `{name}` bench target"
            );
        }
    }
    assert!(benches >= 1, "expected [[bench]] targets in server/Cargo.toml");
}

#[test]
fn ci_cancels_superseded_pr_runs() {
    // W1-L17-20: rapid PR pushes stacked full matrices behind superseded
    // runs; cancel-in-progress is scoped to pull_request so main/dev
    // pushes are never cancelled.
    let root = workspace_root();
    let ci_workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .expect(".github/workflows/ci.yml should be readable");
    let head = ci_workflow.split("\njobs:").next().expect("ci.yml should have a jobs section");
    assert!(head.contains("concurrency:"), "ci.yml should set top-level concurrency");
    assert!(
        head.contains("cancel-in-progress:"),
        "ci.yml concurrency should cancel superseded runs"
    );
    assert!(head.contains("pull_request"), "cancel-in-progress should be scoped to PR pushes");
}

#[test]
fn release_write_permission_scoped_to_publish() {
    // W1-L17-21: contents:write sat at workflow scope though only the
    // publish job (softprops/action-gh-release) needs it; build jobs run
    // least-privilege read.
    let root = workspace_root();
    let release = fs::read_to_string(root.join(".github/workflows/release.yml"))
        .expect(".github/workflows/release.yml should be readable");
    let mut parts = release.splitn(2, "\njobs:");
    let head = parts.next().expect("release.yml should have a preamble");
    let jobs = parts.next().expect("release.yml should have a jobs section");
    assert!(
        !head.contains("contents: write"),
        "workflow-scope permissions should not grant contents:write"
    );
    assert!(
        head.contains("contents: read"),
        "workflow-scope permissions should grant least-privilege read for checkout"
    );
    let mut job_parts = jobs.splitn(2, "  publish:");
    let pre_publish = job_parts.next().expect("release.yml should have build jobs");
    let publish = job_parts.next().expect("release.yml should have a publish job");
    assert!(!pre_publish.contains("contents: write"), "build jobs should not carry contents:write");
    assert!(
        publish.contains("contents: write"),
        "publish job should carry the contents:write it needs for the release"
    );
}

#[test]
fn live_tier_wires_retained_oracle_and_sigterm() {
    // W1-L17-22: the retained-oracle topology proof and the SIGTERM
    // mid-call drain proof ran only by hand; both are live-tier legs now
    // (each skips cleanly when its tooling is absent), executed by the
    // nightly cross-width job.
    let root = workspace_root();
    let tiers = fs::read_to_string(root.join("scripts/run-test-tiers.sh"))
        .expect("scripts/run-test-tiers.sh should be readable");
    let live = shell_function_body(&tiers, "run_live");
    for script in ["run-retained-oracle-live-test.sh", "test-sigterm-mid-call.sh"] {
        assert!(live.contains(script), "live tier should wire {script}");
        assert!(root.join("scripts").join(script).is_file(), "scripts/{script} should exist");
    }
    let nightly = fs::read_to_string(root.join(".github/workflows/nightly.yml"))
        .expect(".github/workflows/nightly.yml should be readable");
    assert!(
        nightly.contains("scripts/run-test-tiers.sh live"),
        "nightly should execute the live tier"
    );
}

#[test]
fn nightly_extracts_noble_softhsm_i386_runtime_dependency_closure() {
    let root = workspace_root();
    let nightly = fs::read_to_string(root.join(".github/workflows/nightly.yml"))
        .expect(".github/workflows/nightly.yml should be readable");

    assert!(
        nightly.contains("libssl3t64:i386"),
        "the extracted i386 SoftHSM package needs its libssl3t64 runtime dependency"
    );
    assert!(
        nightly.contains("dpkg -x libssl3t64_*i386.deb /opt/softhsm2-i386/"),
        "the i386 libssl/libcrypto package should be extracted beside SoftHSM"
    );
    for newer_suite_package in ["zlib1g:i386", "libzstd1:i386", "openssl-provider-legacy:i386"] {
        assert!(
            !nightly.contains(newer_suite_package),
            "{newer_suite_package} is not part of the Ubuntu 24.04 Noble libssl closure"
        );
    }
}

#[test]
fn deny_allows_no_unused_licenses() {
    // W1-L17-27: Unicode-DFS-2016 was allowlisted-but-unused (the quality
    // receipt's own unmatched-allowance note), and tree drift had orphaned
    // BSD-2-Clause / MPL-2.0 / CC0-1.0 the same way (`cargo deny check`
    // reported all four as license-not-encountered). The allowlist carries
    // only encountered licenses now; each removal was verified unused in
    // the root tree and all four standalone test-workspace trees.
    let root = workspace_root();
    let deny = fs::read_to_string(root.join("deny.toml")).expect("deny.toml should be readable");
    for unused in ["Unicode-DFS-2016", "BSD-2-Clause", "MPL-2.0", "CC0-1.0"] {
        for line in deny.lines() {
            let code = line.split('#').next().unwrap_or("");
            assert!(
                !code.contains(unused),
                "deny.toml should not allowlist the unused {unused} license: `{line}`"
            );
        }
    }
}

#[test]
fn pkcs11_module_dep_documents_single_maintainer_residual() {
    // W1-L16-17 (P2→P3, narrowed): the backend's pkcs11-module crates.io
    // dependency tracks a single-maintainer project with no org-owned
    // mirror. Downgraded to an explicit residual: the dependency site
    // records the concentration risk and the fallback plan
    // (re-publish/mirror + vendor path).
    let root = workspace_root();
    let backend = fs::read_to_string(root.join("crates/backend/Cargo.toml"))
        .expect("crates/backend/Cargo.toml should be readable");
    let lowered = backend.to_lowercase();
    assert!(
        lowered.contains("single-maintainer"),
        "backend Cargo.toml should name the single-maintainer residual"
    );
    assert!(lowered.contains("fallback"), "backend Cargo.toml should record the fallback plan");
}
