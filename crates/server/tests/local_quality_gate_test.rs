use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const CI_TIER0_COMMANDS: &[&str] = &[
    "cargo fmt --all -- --check",
    "cargo audit",
    "cargo build --workspace",
    "cargo test --workspace",
    "cargo clippy --workspace --all-targets --all-features -- -D warnings",
];

struct IgnoredTestLane {
    file: &'static str,
    reason: &'static str,
    commands: &'static [&'static str],
    requirements: &'static [&'static str],
}

const IGNORED_TEST_TAXONOMY: &[IgnoredTestLane] = &[
    IgnoredTestLane {
        file: "crates/server/tests/cli_hardening_test.rs",
        reason: "SoftHSM2-backed CLI subprocess coverage",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test cli_hardening_test -- --ignored --test-threads=1",
        ],
        requirements: &["SoftHSM2 module and softhsm2-util", "built workspace binaries"],
    },
    IgnoredTestLane {
        file: "crates/server/tests/concurrency_and_recovery_test.rs",
        reason: "SoftHSM2-backed multi-client and recovery coverage",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test concurrency_and_recovery_test -- --ignored --test-threads=1",
        ],
        requirements: &["SoftHSM2 module and softhsm2-util"],
    },
    IgnoredTestLane {
        file: "crates/server/tests/consumer_p11tool_test.rs",
        reason: "SoftHSM2-backed GnuTLS p11tool consumer coverage",
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
        reason: "SoftHSM2-backed OpenSC pkcs11-tool consumer coverage",
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
        reason: "SoftHSM2-backed Python PyKCS11 consumer coverage",
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
        reason: "Split SoftHSM2 and NSS real-backend smoke coverage",
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
        file: "crates/server/tests/nss_mechanism_coverage_test.rs",
        reason: "NSS softokn mechanism coverage",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test nss_mechanism_coverage_test -- --ignored --test-threads=1",
        ],
        requirements: &["NSS softokn libsoftokn3.so and certutil"],
    },
    IgnoredTestLane {
        file: "crates/server/tests/parameterized_mechanism_test.rs",
        reason: "SoftHSM2-backed parameterized mechanism coverage",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test parameterized_mechanism_test -- --ignored --test-threads=1",
        ],
        requirements: &["SoftHSM2 module and softhsm2-util"],
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
        reason: "SoftHSM2-backed template compatibility coverage",
        commands: &[
            "cargo test -p pkcs11-proxy-ng --test template_compat_test -- --ignored --test-threads=1",
        ],
        requirements: &["SoftHSM2 module and softhsm2-util"],
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
fn ci_workflow_runs_cargo_audit_before_build_and_test() {
    let root = workspace_root();
    let ci_workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .expect(".github/workflows/ci.yml should be readable");

    assert!(
        ci_workflow.contains("name: Cargo Audit"),
        "CI should have a dedicated cargo audit job"
    );
    assert!(ci_workflow.contains("cargo audit"), "CI should run cargo audit");
    assert!(
        ci_workflow.contains("needs: [fmt, audit]"),
        "build-and-test should depend on fmt and audit"
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
    let allowed = root.join("crates/shim/src/dispatch/general/helpers.rs");
    let mut offenders = Vec::new();

    for source in rust_sources_under(&root.join("crates/shim/src")) {
        if source == allowed {
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
        "raw FFI slice construction should stay in helpers.rs; offenders: {offenders:?}"
    );
}

#[test]
fn debug_bundle_redacts_sensitive_pkcs11_proxy_environment() {
    let root = workspace_root();
    let script = fs::read_to_string(root.join("scripts/collect-debug-bundle.sh"))
        .expect("scripts/collect-debug-bundle.sh should be readable");

    assert!(
        !script.contains("env | grep -i \"^PKCS11_PROXY\" | sort"),
        "debug bundle must not write raw PKCS11_PROXY_* environment variables"
    );
    assert!(
        script.contains("redact_pkcs11_proxy_env"),
        "debug bundle should centralize PKCS11_PROXY_* redaction"
    );
    for sensitive_name in [
        "PKCS11_PROXY_PIN",
        "PKCS11_PROXY_SO_PIN",
        "PKCS11_PROXY_NEW_PIN",
        "PKCS11_PROXY_SEED",
        "PKCS11_PROXY_KRYOPTIC_USER_PIN",
        "PKCS11_PROXY_KRYOPTIC_SO_PIN",
        "PKCS11_PROXY_KRYOPTIC_INIT_ARGS",
        "PKCS11_PROXY_NSS_USER_PIN",
        "PKCS11_PROXY_NSS_SO_PIN",
        "PKCS11_PROXY_NSS_INIT_ARGS",
        "PKCS11_PROXY_TLS_CLIENT_KEY",
    ] {
        assert!(
            script.contains(sensitive_name),
            "debug bundle redaction should cover {sensitive_name}"
        );
    }
}

#[test]
fn debug_bundle_archive_redacts_sensitive_environment_values() {
    let root = workspace_root();
    let output_dir = tempfile::tempdir().expect("temp output dir should be created");

    let status = Command::new(root.join("scripts/collect-debug-bundle.sh"))
        .arg("--output-dir")
        .arg(output_dir.path())
        .env("PKCS11_PROXY_PIN", "secret-pin-value")
        .env("PKCS11_PROXY_TLS_CLIENT_KEY", "/tmp/client-key.pem")
        .env("PKCS11_PROXY_ENDPOINT", "http://127.0.0.1:7512")
        .status()
        .expect("debug bundle script should run");
    assert!(status.success(), "debug bundle script should exit successfully");

    let archive = fs::read_dir(output_dir.path())
        .expect("output dir should be readable")
        .map(|entry| entry.expect("bundle entry should be readable").path())
        .find(|path| path.extension().is_some_and(|ext| ext == "gz"))
        .expect("debug bundle archive should exist");

    let output = Command::new("tar")
        .arg("-xOzf")
        .arg(&archive)
        .arg("--wildcards")
        .arg("*/environment.txt")
        .output()
        .expect("tar should extract environment.txt");
    assert!(output.status.success(), "tar should read environment.txt from bundle");

    let environment = String::from_utf8(output.stdout).expect("environment.txt should be UTF-8");
    assert!(!environment.contains("secret-pin-value"), "PIN value must not be archived");
    assert!(!environment.contains("/tmp/client-key.pem"), "TLS key path must not be archived");
    assert!(environment.contains("PKCS11_PROXY_PIN=<redacted>"));
    assert!(environment.contains("PKCS11_PROXY_TLS_CLIENT_KEY=<redacted>"));
    assert!(environment.contains("PKCS11_PROXY_ENDPOINT=http://127.0.0.1:7512"));
}
