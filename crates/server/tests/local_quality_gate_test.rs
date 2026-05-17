use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::Value;

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
        file: "crates/server/tests/mechanism_out_gcm_iv_test.rs",
        reason: "Patched-SoftHSM2-backed AES-GCM init-time generated-IV coverage \
                 for the Wave 1 + Wave 2 mechanism_out work",
        commands: &["SOFTHSM2_GCM_IV_SIM_LIB=/path/to/patched/libsofthsm2.so \
             cargo test -p pkcs11-proxy-ng --test mechanism_out_gcm_iv_test \
             -- --ignored --test-threads=1"],
        requirements: &[
            "Patched libsofthsm2.so built from pkcs11-check/docker/softhsm2/patches/ \
             with SOFTHSM2_GCM_IV_SIM_LIB pointing at it",
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

fn oasis_specs_dir(root: &Path) -> PathBuf {
    std::env::var_os("PKCS11_PROXY_NG_OASIS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("../doc/oasis-tcs-pkcs11"))
        .join("working/doc/spec")
}

fn skip_oasis_inventory_if_unavailable(root: &Path, test_name: &str) -> bool {
    let spec_dir = oasis_specs_dir(root);
    if spec_dir.is_dir() {
        return false;
    }

    eprintln!("skipping {test_name}: OASIS spec source not available at {}", spec_dir.display());
    true
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
fn ci_workflow_does_not_checkout_oasis_specs_for_inventory_tests() {
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
            dockerfile.contains("cargo build --workspace")
                || dockerfile.contains(&format!("-p {package_name}")),
            "Dockerfile.test should build package `{package_name}` by name or build the workspace"
        );
    }
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

fn json_array_field_contains(json: &str, field: &str, value: &str) -> bool {
    let Some(field_index) = json.find(&format!("\"{field}\"")) else {
        return false;
    };
    let Some(array_start) = json[field_index..].find('[').map(|offset| field_index + offset) else {
        return false;
    };

    let mut depth = 0usize;
    for (relative_index, ch) in json[array_start..].char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let array = &json[array_start..=array_start + relative_index];
                    return array.contains(&format!("\"{value}\""));
                }
            }
            _ => {}
        }
    }
    false
}

#[test]
fn oasis_inventory_reports_spec_and_implementation_function_drift() {
    let root = workspace_root();
    if skip_oasis_inventory_if_unavailable(
        &root,
        "oasis_inventory_reports_spec_and_implementation_function_drift",
    ) {
        return;
    }

    let inventory_script = root.join("scripts/oasis-coverage-inventory.py");
    assert!(
        inventory_script.exists(),
        "scripts/oasis-coverage-inventory.py should generate the source-grounded coverage inventory"
    );

    let output = Command::new("python3")
        .arg(&inventory_script)
        .arg("--format")
        .arg("json")
        .current_dir(&root)
        .output()
        .expect("oasis coverage inventory script should run");
    assert!(
        output.status.success(),
        "oasis coverage inventory script failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let json = String::from_utf8(output.stdout).expect("inventory JSON should be UTF-8");
    for function in ["C_Initialize", "C_GetInterface", "C_WrapKeyAuthenticated", "C_DigestXofInit"]
    {
        assert!(
            json_array_field_contains(&json, "spec_functions", function),
            "OASIS inventory should include spec function {function}; JSON was:\n{json}"
        );
    }
    assert!(
        json_array_field_contains(
            &json,
            "spec_functions_missing_from_function_lists",
            "C_DigestXofInit"
        ),
        "XOF digest APIs appear in the vendored spec but not current CK_FUNCTION_LIST tables"
    );
    assert!(
        json.contains("\"official_mechanism_inventory_count\": 463"),
        "official mechanism inventory count should stay visible for drift checks; JSON was:\n{json}"
    );
}

#[test]
fn submodule_agents_quick_reference_matches_oasis_inventory_counts() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };
    let function_list_field_count = inventory["function_list_field_count"]
        .as_u64()
        .expect("function_list_field_count should be a u64");
    let xof_gap_count = inventory["spec_functions_missing_from_function_lists"]
        .as_array()
        .expect("spec_functions_missing_from_function_lists should be an array")
        .len();
    let parameter_shape_count = inventory["mechanism_parameter_shape_count"]
        .as_u64()
        .expect("mechanism_parameter_shape_count should be a u64");
    let message_parameter_shape_count = inventory["message_parameter_shape_count"]
        .as_u64()
        .expect("message_parameter_shape_count should be a u64");
    let agents = fs::read_to_string(root.join("AGENTS.md")).expect("AGENTS.md should be readable");

    assert!(agents.contains(&format!(
        "**{function_list_field_count} standard PKCS#11 function-list fields** represented"
    )));
    assert!(
        agents.contains(&format!("**{xof_gap_count} `C_DigestXof*` spec-only functions** tracked"))
    );
    assert!(agents.contains(&format!(
        "**{parameter_shape_count} mechanism parameter shapes** and \
         **{message_parameter_shape_count} message parameter shapes**"
    )));
}

#[test]
fn oasis_coverage_completion_audit_maps_goal_to_artifacts() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };
    let spec_function_count =
        inventory["spec_function_count"].as_u64().expect("spec_function_count should be a u64");
    let function_list_field_count = inventory["function_list_field_count"]
        .as_u64()
        .expect("function_list_field_count should be a u64");
    let interface_entry_count = inventory["interface_catalog_entry_count"]
        .as_u64()
        .expect("interface_catalog_entry_count should be a u64");
    let xof_gap_count = inventory["spec_functions_missing_from_function_lists"]
        .as_array()
        .expect("spec_functions_missing_from_function_lists should be an array")
        .len();
    let parameter_shape_count = inventory["mechanism_parameter_shape_count"]
        .as_u64()
        .expect("mechanism_parameter_shape_count should be a u64");
    let message_parameter_shape_count = inventory["message_parameter_shape_count"]
        .as_u64()
        .expect("message_parameter_shape_count should be a u64");
    let parameter_struct_count = inventory["spec_parameter_struct_base_count"]
        .as_u64()
        .expect("spec_parameter_struct_base_count should be a u64");
    let provider_artifact_count = inventory["provider_artifact_evidence"]["coverage_file_count"]
        .as_u64()
        .expect("coverage_file_count should be a u64");
    let provider_summary = &inventory["provider_mechanism_summary"];
    let official_value_count = provider_summary["official_mechanism_value_count"]
        .as_u64()
        .expect("official_mechanism_value_count should be a u64");
    let official_name_count = provider_summary["official_mechanism_name_count"]
        .as_u64()
        .expect("official_mechanism_name_count should be a u64");
    let provider_gap_count = provider_summary["provider_gap_count"]
        .as_u64()
        .expect("provider_gap_count should be a u64");
    let completion_summary = &inventory["completion_gap_summary"];
    let source_grounded_semantic_count =
        completion_summary["source_grounded_mockbackend_semantic_covered_count"]
            .as_u64()
            .expect("source_grounded_mockbackend_semantic_covered_count should be a u64");
    let actionable_semantic_gap_count =
        completion_summary["actionable_mockbackend_semantic_gap_count"]
            .as_u64()
            .expect("actionable_mockbackend_semantic_gap_count should be a u64");
    let intentional_no_source_count =
        completion_summary["intentional_no_source_workflow_rejection_count"]
            .as_u64()
            .expect("intentional_no_source_workflow_rejection_count should be a u64");
    let internal_open_item_count = completion_summary["internal_completion_open_item_count"]
        .as_u64()
        .expect("internal_completion_open_item_count should be a u64");
    let strict_open_item_count = completion_summary["strict_completion_open_item_count"]
        .as_u64()
        .expect("strict_completion_open_item_count should be a u64");
    let audit_path = root.join("doc/oasis-coverage-completion-audit.md");
    let audit = fs::read_to_string(&audit_path)
        .unwrap_or_else(|err| panic!("{} should be readable: {err}", audit_path.display()));

    for required in [
        "Prompt-to-artifact checklist",
        "Status: internal coverage complete; provider-backed gaps remain separate",
        "scripts/oasis-coverage-inventory.py",
        "completion_gap_summary",
        "missing_local_test_citation_counts",
        "strict_completion_open_items",
        "strict_completion_open_item_counts",
        "intentional_unsupported_function_list_gap_names",
        "intentional_unsupported_function_list_gap_count",
        "intentional_unsupported_numeric_value_gap_names",
        "intentional_unsupported_numeric_value_gap_count",
        "intentional_unsupported_workflow_gap_names",
        "intentional_unsupported_workflow_gap_count",
        "internal_completion_open_item_count",
        "strict_completion_open_item_count",
        "actionable_mockbackend_semantic_gap_count",
        "intentional_no_source_workflow_rejection_count",
        "doc/oasis-profile-coverage.md",
        "doc/mock-backend-mechanism-workflow-audit.md",
        "C_DigestXof*",
        "do_not_add_out_of_band_exports_or_custom_function_list_layout",
        "SP800-108",
        "provider-backed gaps remain separate",
        "MockBackend::with_official_mechanism_catalog_smoke()",
        "MockBackend::with_official_mechanisms()",
        "official_source_grounded_mock_enforces_mechanism_workflow_flags",
        "official_source_grounded_mock_rejects_all_no_source_workflow_mechanisms",
        "catalog smoke coverage is not semantic coverage",
        "Actionable MockBackend semantic gaps are zero",
        "published-header annotations",
        "Historical",
        "Deprecated",
        "scripts/test-matrix.sh --fast-only",
    ] {
        assert!(audit.contains(required), "completion audit should mention {required}");
    }
    assert!(audit.contains(&format!(
        "Official PKCS#11 functions in OASIS inventory: {spec_function_count}"
    )));
    assert!(audit.contains(&format!(
        "Represented standard function-list fields: {function_list_field_count}"
    )));
    assert!(
        audit.contains(&format!("Standard interface catalog entries: {interface_entry_count}"))
    );
    assert!(audit.contains(&format!(
        "Official mechanism values from published headers: {official_value_count}"
    )));
    assert!(
        audit.contains(&format!(
            "Official mechanism names/aliases in matrix: {official_name_count}"
        ))
    );
    if provider_artifact_count > 0 {
        assert!(
            audit.contains(&format!("Provider-gap mechanism names/aliases: {provider_gap_count}"))
        );
    } else {
        assert!(
            audit.contains("Provider-gap mechanism names/aliases:"),
            "completion audit should expose the provider-gap count label even when CI has no provider artifacts"
        );
    }
    assert!(audit.contains(&format!(
        "Spec-only `C_DigestXof*` functions without local function-list ABI slots: {xof_gap_count}"
    )));
    assert!(audit.contains(&format!("Mechanism parameter shapes: {parameter_shape_count}")));
    assert!(audit.contains(&format!("Message parameter shapes: {message_parameter_shape_count}")));
    assert!(
        audit.contains(&format!(
            "Spec parameter structs in OASIS inventory: {parameter_struct_count}"
        ))
    );
    assert!(audit.contains(&format!(
        "Source-grounded MockBackend semantic rows covered: {source_grounded_semantic_count}"
    )));
    assert!(audit.contains(&format!(
        "Actionable MockBackend semantic gaps: {actionable_semantic_gap_count}"
    )));
    assert!(audit.contains(&format!(
        "Intentional no-source workflow rejections: {intentional_no_source_count}"
    )));
    assert!(audit.contains(&format!("Internal completion open items: {internal_open_item_count}")));
    if provider_artifact_count > 0 {
        assert!(audit.contains(&format!(
            "Strict completion open items including provider gaps: {strict_open_item_count}"
        )));
    } else {
        assert!(
            audit.contains("Strict completion open items including provider gaps:"),
            "completion audit should expose the strict provider-inclusive count label even when CI has no provider artifacts"
        );
    }
}

#[test]
fn oasis_inventory_exposes_completion_gap_summary() {
    fn missing_local_test_count(matrix: &Value) -> u64 {
        matrix
            .as_array()
            .expect("matrix should be an array")
            .iter()
            .filter(|entry| {
                !entry["local_tests_missing"]
                    .as_array()
                    .expect("local_tests_missing should be an array")
                    .is_empty()
            })
            .count() as u64
    }

    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };
    let summary = inventory["completion_gap_summary"]
        .as_object()
        .expect("inventory should expose completion_gap_summary");
    let missing = summary["missing_local_test_citation_counts"]
        .as_object()
        .expect("completion gap summary should expose missing local test citation counts");
    let open_item_counts = summary["strict_completion_open_item_counts"]
        .as_object()
        .expect("completion gap summary should expose strict completion open item counts");
    let open_items = summary["strict_completion_open_items"]
        .as_object()
        .expect("completion gap summary should expose strict completion open item names");

    assert_eq!(
        summary["spec_only_function_list_gap_names"],
        inventory["spec_functions_missing_from_function_lists"]
    );
    assert_eq!(
        summary["intentional_unsupported_function_list_gap_names"],
        inventory["spec_functions_missing_from_function_lists"]
    );
    assert_eq!(
        summary["intentional_unsupported_function_list_gap_count"].as_u64(),
        Some(
            inventory["spec_functions_missing_from_function_lists"]
                .as_array()
                .expect("spec_functions_missing_from_function_lists should be an array")
                .len() as u64
        )
    );
    assert_eq!(
        summary["working_spec_mechanisms_without_published_values"],
        inventory["spec_mechanisms_missing_from_official_inventory_by_name"]
    );
    assert_eq!(
        summary["intentional_unsupported_numeric_value_gap_names"],
        summary["working_spec_mechanisms_without_published_values"]
    );
    assert_eq!(
        summary["intentional_unsupported_numeric_value_gap_count"].as_u64(),
        Some(
            summary["working_spec_mechanisms_without_published_values"]
                .as_array()
                .expect("working_spec_mechanisms_without_published_values should be an array")
                .len() as u64
        )
    );
    assert_eq!(
        summary["no_source_workflow_evidence_count"],
        inventory["mechanism_info_flag_coverage_summary"]["no_source_workflow_evidence_count"]
    );
    assert_eq!(
        summary["source_grounded_mockbackend_semantic_covered_count"].as_u64(),
        Some(
            inventory["mechanism_matrix"]
                .as_array()
                .expect("mechanism_matrix should be an array")
                .iter()
                .filter(|entry| {
                    entry["mock_backend_internal_coverage"]["workflow_semantics_status"]
                        == "source_grounded"
                })
                .count() as u64
        )
    );
    assert_eq!(
        summary["actionable_mockbackend_semantic_gap_count"].as_u64(),
        Some(
            inventory["mechanism_matrix"]
                .as_array()
                .expect("mechanism_matrix should be an array")
                .iter()
                .filter(|entry| {
                    entry["mock_backend_internal_coverage"]["workflow_semantics_status"]
                        == "not_yet_source_grounded"
                })
                .count() as u64
        )
    );
    assert_eq!(
        summary["intentional_no_source_workflow_rejection_count"],
        summary["no_source_workflow_evidence_count"]
    );
    assert_eq!(
        summary["intentional_unsupported_workflow_gap_names"],
        summary["intentional_no_source_workflow_rejection_names"]
    );
    assert_eq!(
        summary["intentional_unsupported_workflow_gap_count"],
        summary["intentional_no_source_workflow_rejection_count"]
    );
    assert_eq!(
        summary["no_published_value_mechanism_count"].as_u64(),
        Some(
            inventory["mechanism_matrix"]
                .as_array()
                .expect("mechanism_matrix should be an array")
                .iter()
                .filter(|entry| {
                    entry["mock_backend_internal_coverage"]["workflow_semantics_status"]
                        == "no_published_ck_mechanism_type_value"
                })
                .count() as u64
        )
    );
    assert_eq!(
        summary["provider_gap_count"],
        inventory["provider_mechanism_summary"]["provider_gap_count"]
    );
    assert_eq!(
        summary["spec_parameter_structs_missing_modeled_shape_count"]
            .as_u64()
            .expect("spec parameter struct missing count should be a u64"),
        inventory["mechanism_parameter_struct_comparison"]
            ["spec_parameter_structs_missing_modeled_shape"]
            .as_array()
            .expect("spec_parameter_structs_missing_modeled_shape should be an array")
            .len() as u64
    );
    assert_eq!(
        missing["function_matrix"].as_u64(),
        Some(missing_local_test_count(&inventory["function_matrix"]))
    );
    assert_eq!(
        missing["mechanism_parameter_shape_matrix"].as_u64(),
        Some(missing_local_test_count(&inventory["mechanism_parameter_shape_matrix"]))
    );
    assert_eq!(
        missing["message_parameter_shape_matrix"].as_u64(),
        Some(missing_local_test_count(&inventory["message_parameter_shape_matrix"]))
    );
    assert_eq!(
        missing["mechanism_info_flag_coverage_matrix"].as_u64(),
        Some(missing_local_test_count(&inventory["mechanism_info_flag_coverage_matrix"]))
    );
    let mock_missing_count = inventory["mechanism_matrix"]
        .as_array()
        .expect("mechanism_matrix should be an array")
        .iter()
        .filter(|entry| {
            !entry["mock_backend_internal_coverage"]["local_tests_missing"]
                .as_array()
                .expect("MockBackend local_tests_missing should be an array")
                .is_empty()
        })
        .count() as u64;
    assert_eq!(missing["mock_backend_internal_coverage"].as_u64(), Some(mock_missing_count));
    let missing_local_test_total =
        missing.values().map(|value| value.as_u64().expect("missing counts are u64")).sum::<u64>();
    assert!(
        !open_item_counts.contains_key("spec_only_function_list_gaps"),
        "XOF function-list omissions have an intentional ABI decision and should not be counted as open"
    );
    assert!(
        !open_items.contains_key("spec_only_function_list_gaps"),
        "XOF function-list omissions have an intentional ABI decision and should not be listed as open"
    );
    assert!(
        !open_item_counts.contains_key("working_spec_mechanisms_without_published_values"),
        "working-spec mechanism names without published numeric values have an intentional numeric decision and should not be counted as open"
    );
    assert!(
        !open_items.contains_key("working_spec_mechanisms_without_published_values"),
        "working-spec mechanism names without published numeric values have an intentional numeric decision and should not be listed as open"
    );
    assert!(
        !open_item_counts.contains_key("intentional_no_source_workflow_rejections"),
        "no-source workflow rejections have explicit unsupported decisions and should not be counted as open"
    );
    assert!(
        !open_items.contains_key("intentional_no_source_workflow_rejections"),
        "no-source workflow rejections have explicit unsupported decisions and should not be listed as open"
    );
    let no_source_names = inventory["mechanism_matrix"]
        .as_array()
        .expect("mechanism_matrix should be an array")
        .iter()
        .filter(|entry| {
            entry["mock_backend_internal_coverage"]["workflow_semantics_status"]
                == "no_source_workflow_evidence"
        })
        .map(|entry| entry["name"].as_str().expect("mechanism name should be a string"))
        .collect::<Vec<_>>();
    for expected in ["CKM_CAMELLIA_CTR", "CKM_DES_CBC"] {
        assert!(
            summary["intentional_unsupported_workflow_gap_names"]
                .as_array()
                .expect("intentional unsupported workflow gaps should be an array")
                .iter()
                .any(|name| name == expected),
            "{expected} should be named as an intentional unsupported workflow gap"
        );
    }
    assert_eq!(
        summary["intentional_unsupported_workflow_gap_names"]
            .as_array()
            .expect("intentional unsupported workflow gaps should be an array")
            .len(),
        no_source_names.len()
    );
    assert_eq!(open_item_counts["provider_artifact_gaps"], summary["provider_gap_count"]);
    assert_eq!(
        open_items["provider_artifact_gaps"],
        inventory["provider_mechanism_summary"]["provider_gap_names"]
    );
    assert_eq!(
        open_item_counts["spec_parameter_structs_missing_modeled_shape"],
        summary["spec_parameter_structs_missing_modeled_shape_count"]
    );
    assert_eq!(
        open_items["spec_parameter_structs_missing_modeled_shape"],
        summary["spec_parameter_structs_missing_modeled_shape"]
    );
    assert_eq!(
        open_item_counts["missing_local_test_citations"].as_u64(),
        Some(missing_local_test_total)
    );
    let missing_local_test_items = open_items["missing_local_test_citations"]
        .as_object()
        .expect("missing local test open items should be grouped by matrix");
    assert_eq!(missing_local_test_items.len(), missing.len());
    for (matrix, count) in missing {
        assert_eq!(
            missing_local_test_items[matrix]
                .as_array()
                .expect("missing local test item list should be an array")
                .len() as u64,
            count.as_u64().expect("missing count should be u64"),
            "{matrix} missing-local-test item names should match the count"
        );
    }
    assert_eq!(
        open_item_counts["actionable_mockbackend_semantic_gaps"],
        summary["actionable_mockbackend_semantic_gap_count"]
    );
    assert_eq!(
        open_items["actionable_mockbackend_semantic_gaps"]
            .as_array()
            .expect("actionable MockBackend open items should be an array")
            .len() as u64,
        summary["actionable_mockbackend_semantic_gap_count"]
            .as_u64()
            .expect("actionable MockBackend count should be u64")
    );
    assert_eq!(
        open_item_counts["not_yet_source_grounded_mechanism_info_flags"],
        summary["not_yet_source_grounded_mechanism_info_flag_count"]
    );
    assert_eq!(
        open_items["not_yet_source_grounded_mechanism_info_flags"]
            .as_array()
            .expect("mechanism-info open items should be an array")
            .len() as u64,
        summary["not_yet_source_grounded_mechanism_info_flag_count"]
            .as_u64()
            .expect("mechanism-info count should be u64")
    );
    let internal_open_item_count = open_item_counts
        .iter()
        .filter(|(key, _)| key.as_str() != "provider_artifact_gaps")
        .map(|(_, value)| value.as_u64().expect("open item counts are u64"))
        .sum::<u64>();
    assert_eq!(
        summary["internal_completion_open_item_count"].as_u64(),
        Some(internal_open_item_count)
    );
    assert_eq!(
        summary["strict_completion_open_item_count"].as_u64(),
        Some(
            internal_open_item_count
                + summary["provider_gap_count"].as_u64().expect("provider_gap_count is u64")
        )
    );
}

#[test]
fn oasis_inventory_filters_template_and_vendor_mechanism_tokens() {
    let root = workspace_root();
    if skip_oasis_inventory_if_unavailable(
        &root,
        "oasis_inventory_filters_template_and_vendor_mechanism_tokens",
    ) {
        return;
    }

    let output = Command::new("python3")
        .arg(root.join("scripts/oasis-coverage-inventory.py"))
        .arg("--format")
        .arg("json")
        .current_dir(&root)
        .output()
        .expect("oasis coverage inventory script should run");
    assert!(
        output.status.success(),
        "oasis coverage inventory script failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let json = String::from_utf8(output.stdout).expect("inventory JSON should be UTF-8");
    for non_mechanism in [
        "CKM_VENDOR_DEFINED",
        "CKM_AES_EC",
        "CKM_DSA_",
        "CKM_ECDH",
        "CKM_ECDSA_",
        "CKM_HASH_ML_DSA_",
        "CKM_HASH_SLH_DSA_",
        "CKM_KMAC_256",
        "CKM_PBE",
        "CKM_SHA512_",
    ] {
        assert!(
            !json_array_field_contains(&json, "spec_mechanisms", non_mechanism),
            "inventory should not treat template/vendor token {non_mechanism} as an official mechanism"
        );
    }
}

fn oasis_inventory_json(root: &Path) -> Option<Value> {
    if skip_oasis_inventory_if_unavailable(root, "OASIS inventory test") {
        return None;
    }

    let output = Command::new("python3")
        .arg(root.join("scripts/oasis-coverage-inventory.py"))
        .arg("--format")
        .arg("json")
        .current_dir(root)
        .output()
        .expect("oasis coverage inventory script should run");
    assert!(
        output.status.success(),
        "oasis coverage inventory script failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Some(serde_json::from_slice(&output.stdout).expect("inventory output should be valid JSON"))
}

fn function_matrix_entry<'a>(inventory: &'a Value, name: &str) -> &'a Value {
    inventory["function_matrix"]
        .as_array()
        .expect("function_matrix should be an array")
        .iter()
        .find(|entry| entry["name"] == name)
        .unwrap_or_else(|| panic!("function_matrix should contain {name}"))
}

fn mechanism_matrix_entry<'a>(inventory: &'a Value, name: &str) -> &'a Value {
    inventory["mechanism_matrix"]
        .as_array()
        .expect("mechanism_matrix should be an array")
        .iter()
        .find(|entry| entry["name"] == name)
        .unwrap_or_else(|| panic!("mechanism_matrix should contain {name}"))
}

fn interface_matrix_entry<'a>(inventory: &'a Value, version: &str) -> &'a Value {
    inventory["interface_matrix"]
        .as_array()
        .expect("interface_matrix should be an array")
        .iter()
        .find(|entry| entry["version"] == version)
        .unwrap_or_else(|| panic!("interface_matrix should contain PKCS 11 version {version}"))
}

fn parameter_shape_matrix_entry<'a>(inventory: &'a Value, rust_variant: &str) -> &'a Value {
    inventory["mechanism_parameter_shape_matrix"]
        .as_array()
        .expect("mechanism_parameter_shape_matrix should be an array")
        .iter()
        .find(|entry| entry["rust_variant"] == rust_variant)
        .unwrap_or_else(|| panic!("mechanism_parameter_shape_matrix should contain {rust_variant}"))
}

fn message_parameter_shape_matrix_entry<'a>(inventory: &'a Value, rust_variant: &str) -> &'a Value {
    inventory["message_parameter_shape_matrix"]
        .as_array()
        .expect("message_parameter_shape_matrix should be an array")
        .iter()
        .find(|entry| entry["rust_variant"] == rust_variant)
        .unwrap_or_else(|| panic!("message_parameter_shape_matrix should contain {rust_variant}"))
}

fn mock_backend_default_trait_decision_entry<'a>(
    inventory: &'a Value,
    backend_trait_method: &str,
) -> &'a Value {
    inventory["mock_backend_default_trait_decisions"]
        .as_array()
        .expect("mock_backend_default_trait_decisions should be an array")
        .iter()
        .find(|entry| entry["backend_trait_method"] == backend_trait_method)
        .unwrap_or_else(|| {
            panic!("mock_backend_default_trait_decisions should contain {backend_trait_method}")
        })
}

fn mechanism_info_flag_coverage_entry<'a>(inventory: &'a Value, name: &str) -> &'a Value {
    inventory["mechanism_info_flag_coverage_matrix"]
        .as_array()
        .expect("mechanism_info_flag_coverage_matrix should be an array")
        .iter()
        .find(|entry| entry["name"] == name)
        .unwrap_or_else(|| panic!("mechanism_info_flag_coverage_matrix should contain {name}"))
}

fn official_mechanism_entry<'a>(inventory: &'a Value, name: &str) -> &'a Value {
    inventory["official_mechanism_inventory_entries"]
        .as_array()
        .expect("official_mechanism_inventory_entries should be an array")
        .iter()
        .find(|entry| {
            entry["names"]
                .as_array()
                .expect("mechanism names should be an array")
                .iter()
                .any(|candidate| candidate == name)
        })
        .unwrap_or_else(|| panic!("official mechanism inventory should contain {name}"))
}

const DIGEST_XOF_FUNCTIONS: [&str; 6] = [
    "C_DigestXof",
    "C_DigestXofExtract",
    "C_DigestXofFinal",
    "C_DigestXofInit",
    "C_DigestXofKeyValue",
    "C_DigestXofUpdate",
];

#[test]
fn oasis_inventory_function_matrix_tracks_proxy_layers() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    let authenticated_wrap = function_matrix_entry(&inventory, "C_WrapKeyAuthenticated");
    assert_eq!(authenticated_wrap["status"], "represented");
    assert_eq!(authenticated_wrap["function_list_field"], true);
    assert_eq!(authenticated_wrap["proto_rpc"], "WrapKeyAuthenticated");
    assert_eq!(authenticated_wrap["backend_trait_method"], "wrap_key_authenticated");
    assert_eq!(authenticated_wrap["client_method"], "wrap_key_authenticated");
    assert_eq!(authenticated_wrap["shim_dispatch_function"], "c_wrap_key_authenticated");

    let xof_init = function_matrix_entry(&inventory, "C_DigestXofInit");
    assert_eq!(xof_init["status"], "spec_only");
    assert_eq!(xof_init["function_list_field"], false);
    assert_eq!(xof_init["proto_rpc"], Value::Null);
    assert_eq!(xof_init["backend_trait_method"], Value::Null);
    assert_eq!(xof_init["client_method"], Value::Null);
    assert_eq!(xof_init["shim_dispatch_function"], Value::Null);
}

#[test]
fn oasis_inventory_cites_3x_behavioral_function_tests() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for (function, expected_test) in [
        ("C_AsyncComplete", "async_complete_returns_result"),
        ("C_AsyncGetID", "async_get_id_returns_state_unsaveable"),
        ("C_AsyncJoin", "async_join_returns_saved_state_invalid"),
        ("C_EncapsulateKey", "encapsulate_key_returns_synthetic_result_through_full_stack"),
        ("C_DecapsulateKey", "decapsulate_key_returns_synthetic_handle_through_full_stack"),
        ("C_WrapKeyAuthenticated", "wrap_unwrap_key_authenticated_round_trip"),
        ("C_UnwrapKeyAuthenticated", "wrap_unwrap_key_authenticated_round_trip"),
        ("C_MessageEncryptInit", "message_encrypt_decrypt_round_trip"),
        ("C_EncryptMessage", "message_encrypt_decrypt_round_trip"),
        ("C_EncryptMessageBegin", "message_encrypt_decrypt_begin_next_round_trip"),
        ("C_EncryptMessageNext", "message_encrypt_decrypt_begin_next_round_trip"),
        ("C_MessageEncryptFinal", "message_encrypt_decrypt_round_trip"),
        ("C_MessageDecryptInit", "message_encrypt_decrypt_round_trip"),
        ("C_DecryptMessage", "message_encrypt_decrypt_round_trip"),
        ("C_DecryptMessageBegin", "message_encrypt_decrypt_begin_next_round_trip"),
        ("C_DecryptMessageNext", "message_encrypt_decrypt_begin_next_round_trip"),
        ("C_MessageDecryptFinal", "message_encrypt_decrypt_round_trip"),
        ("C_MessageSignInit", "message_sign_verify_round_trip"),
        ("C_SignMessage", "message_sign_verify_round_trip"),
        ("C_SignMessageBegin", "message_sign_verify_begin_next_round_trip"),
        ("C_SignMessageNext", "message_sign_verify_begin_next_round_trip"),
        ("C_MessageSignFinal", "message_sign_verify_round_trip"),
        ("C_MessageVerifyInit", "message_sign_verify_round_trip"),
        ("C_VerifyMessage", "message_sign_verify_round_trip"),
        ("C_VerifyMessageBegin", "message_sign_verify_begin_next_round_trip"),
        ("C_VerifyMessageNext", "message_sign_verify_begin_next_round_trip"),
        ("C_MessageVerifyFinal", "message_sign_verify_round_trip"),
    ] {
        let entry = function_matrix_entry(&inventory, function);
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == expected_test),
            "{function} should cite behavioral gRPC test {expected_test}"
        );
    }
}

#[test]
fn oasis_inventory_marks_function_list_apis_as_shim_local_entrypoints() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for (function, expected_test) in [
        ("C_GetFunctionList", "get_function_list_returns_nonnull_pointer"),
        ("C_GetInterfaceList", "get_interface_list_count_only_mode"),
        ("C_GetInterface", "get_interface_default_returns_3_2"),
    ] {
        let entry = function_matrix_entry(&inventory, function);
        assert_eq!(entry["status"], "represented");
        assert_eq!(entry["function_list_field"], true);
        assert_eq!(entry["shim_entrypoint_function"], function);
        assert_eq!(entry["local_abi_reason"], "shim_local_function_catalog_entrypoint");
        assert_eq!(entry["proto_rpc"], Value::Null);
        assert_eq!(entry["backend_trait_method"], Value::Null);
        assert_eq!(entry["client_method"], Value::Null);
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == expected_test),
            "{function} should cite local shim coverage {expected_test}"
        );
    }
}

#[test]
fn oasis_inventory_cites_mockbackend_find_objects_state_machine() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for function in ["C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal"] {
        let entry = function_matrix_entry(&inventory, function);
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == "find_objects_tracks_active_search_operation"),
            "{function} should cite MockBackend object-search operation-state coverage"
        );
    }
}

#[test]
fn oasis_inventory_cites_mockbackend_slot_event_blocking_workflow() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    let entry = function_matrix_entry(&inventory, "C_WaitForSlotEvent");
    let local_tests = entry["local_tests"].as_array().expect("local_tests should be an array");
    for expected in [
        "wait_for_slot_event_blocks_until_event_when_flag_zero",
        "wait_for_slot_event_blocking_returns_not_initialized_after_finalize",
        "wait_for_slot_event_before_initialize_returns_cryptoki_not_initialized",
        "finalize_clears_pending_slot_events",
        "initialize_clears_pending_slot_events",
        "loaded_shim_writes_mechanism_out_to_caller_stack_after_encrypt_wrap_and_derive",
        "c_wait_for_slot_event_nonnull_reserved_returns_bad_args",
    ] {
        assert!(
            local_tests.iter().any(|test| test == expected),
            "C_WaitForSlotEvent should cite {expected}"
        );
    }
}

#[test]
fn oasis_inventory_cites_loaded_shim_message_begin_next_function_tests() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for function in [
        "C_EncryptMessageBegin",
        "C_EncryptMessageNext",
        "C_DecryptMessageBegin",
        "C_DecryptMessageNext",
        "C_SignMessageBegin",
        "C_SignMessageNext",
        "C_VerifyMessageBegin",
        "C_VerifyMessageNext",
    ] {
        let entry = function_matrix_entry(&inventory, function);
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == "loaded_shim_message_begin_next_round_trips_c_stack_params"),
            "{function} should cite loaded-shim C ABI Begin/Next coverage"
        );
    }
}

#[test]
fn oasis_inventory_cites_finalize_reserved_pointer_validation() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    let entry = function_matrix_entry(&inventory, "C_Finalize");
    assert!(
        entry["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|test| test == "finalize_p_reserved_nonnull_returns_bad_args"),
        "C_Finalize should cite reserved-pointer C ABI validation"
    );
}

#[test]
fn oasis_inventory_cites_local_tests_for_represented_functions() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    let missing: Vec<String> = inventory["function_matrix"]
        .as_array()
        .expect("function_matrix should be an array")
        .iter()
        .filter(|entry| entry["status"] == "represented")
        .filter(|entry| {
            entry["local_tests"].as_array().expect("local_tests should be an array").is_empty()
        })
        .map(|entry| entry["name"].as_str().expect("function name should be a string").to_owned())
        .collect();
    assert!(
        missing.is_empty(),
        "represented functions should cite local test evidence: {missing:?}"
    );

    let stale: Vec<String> = inventory["function_matrix"]
        .as_array()
        .expect("function_matrix should be an array")
        .iter()
        .flat_map(|entry| {
            entry["local_tests_missing"]
                .as_array()
                .expect("local_tests_missing should be an array")
                .iter()
                .map(|test| {
                    format!(
                        "{}:{}",
                        entry["name"].as_str().expect("function name should be a string"),
                        test.as_str().expect("test name should be a string")
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(stale.is_empty(), "function matrix cites stale local tests: {stale:?}");
}

#[test]
fn oasis_inventory_sources_function_entries_from_vendored_oasis_headers() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    let source_headers = inventory["source"]["official_function_headers"]
        .as_array()
        .expect("inventory should expose source OASIS function headers");
    for header in [
        "../doc/oasis-tcs-pkcs11/published/2-40-errata-1/pkcs11f.h",
        "../doc/oasis-tcs-pkcs11/published/3-00/pkcs11f.h",
        "../doc/oasis-tcs-pkcs11/published/3-01/pkcs11f.h",
        "../doc/oasis-tcs-pkcs11/published/3-02/pkcs11f.h",
    ] {
        assert!(
            source_headers.iter().any(|value| value == header),
            "inventory should cite vendored OASIS function header {header}"
        );
    }

    let initialize = function_matrix_entry(&inventory, "C_Initialize");
    assert_eq!(initialize["published_function_list_present"], true);
    assert_eq!(initialize["published_function_version_introduced"], "2.40");

    let get_interface = function_matrix_entry(&inventory, "C_GetInterface");
    assert_eq!(get_interface["published_function_list_present"], true);
    assert_eq!(get_interface["published_function_version_introduced"], "3.0");

    let authenticated_wrap = function_matrix_entry(&inventory, "C_WrapKeyAuthenticated");
    assert_eq!(authenticated_wrap["published_function_list_present"], true);
    assert_eq!(authenticated_wrap["published_function_version_introduced"], "3.2");

    let xof_init = function_matrix_entry(&inventory, "C_DigestXofInit");
    assert_eq!(xof_init["published_function_list_present"], false);
    assert_eq!(xof_init["published_function_version_introduced"], Value::Null);
}

#[test]
fn oasis_inventory_compares_local_function_fields_to_oasis_headers() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };
    let comparison = &inventory["function_list_field_comparison"];

    assert_eq!(comparison["matches"], true);
    assert!(
        comparison["oasis_3_2_functions_missing_from_local_fields"]
            .as_array()
            .expect("oasis_3_2_functions_missing_from_local_fields should be an array")
            .is_empty()
    );
    assert!(
        comparison["local_fields_missing_from_oasis_3_2_headers"]
            .as_array()
            .expect("local_fields_missing_from_oasis_3_2_headers should be an array")
            .is_empty()
    );
}

#[test]
fn oasis_inventory_tracks_standard_interface_catalog_entries() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    assert_eq!(inventory["interface_catalog_entry_count"], 3);
    let interface_matrix =
        inventory["interface_matrix"].as_array().expect("interface_matrix should be an array");
    assert_eq!(interface_matrix.len(), 3);

    let v2_40 = interface_matrix_entry(&inventory, "2.40");
    assert_eq!(v2_40["interface_name"], "PKCS 11");
    assert_eq!(v2_40["function_list_type"], "CK_FUNCTION_LIST");
    assert_eq!(v2_40["shim_catalog_present"], true);
    assert_eq!(v2_40["mock_backend_default_capability"], true);
    assert_eq!(v2_40["default_interface"], false);
    assert!(
        v2_40["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|test| test == "get_interface_list_first_entry_is_2_40")
    );
    assert!(
        v2_40["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|test| test == "get_interface_pkcs11_version_2_40")
    );

    let v3_0 = interface_matrix_entry(&inventory, "3.0");
    assert_eq!(v3_0["interface_name"], "PKCS 11");
    assert_eq!(v3_0["function_list_type"], "CK_FUNCTION_LIST_3_0");
    assert_eq!(v3_0["shim_catalog_present"], true);
    assert_eq!(v3_0["mock_backend_default_capability"], true);
    assert_eq!(v3_0["default_interface"], false);
    assert!(
        v3_0["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|test| test == "get_interface_list_second_entry_is_3_0")
    );
    assert!(
        v3_0["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|test| test == "get_interface_pkcs11_version_3_0")
    );

    let v3_2 = interface_matrix_entry(&inventory, "3.2");
    assert_eq!(v3_2["interface_name"], "PKCS 11");
    assert_eq!(v3_2["function_list_type"], "CK_FUNCTION_LIST_3_2");
    assert_eq!(v3_2["shim_catalog_present"], true);
    assert_eq!(v3_2["mock_backend_default_capability"], true);
    assert_eq!(v3_2["default_interface"], true);
    for test_name in [
        "get_interface_list_third_entry_is_3_2",
        "get_interface_3_2_by_version",
        "get_interface_default_returns_3_2",
        "mock_backend_reports_3x_interface_capabilities_by_default",
    ] {
        assert!(
            v3_2["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == test_name),
            "3.2 interface coverage should cite {test_name}"
        );
    }

    for version in ["2.40", "3.0"] {
        let entry = interface_matrix_entry(&inventory, version);
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == "mock_backend_reports_3x_interface_capabilities_by_default"),
            "{version} interface coverage should cite MockBackend default capability coverage"
        );
    }
}

#[test]
fn oasis_inventory_sources_interface_entries_from_spec_and_shim() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    let source_specs = inventory["source"]["interface_spec_sources"]
        .as_array()
        .expect("interface_spec_sources should be an array");
    for source in ["general_data_types.md", "general_purpose_functions.md"] {
        assert!(
            source_specs.iter().any(|entry| entry == source),
            "interface inventory should cite OASIS spec source {source}"
        );
    }

    let shim_sources = inventory["source"]["interface_shim_sources"]
        .as_array()
        .expect("interface_shim_sources should be an array");
    for source in ["crates/shim/src/interface_probe.rs", "crates/shim/src/tests/interface.rs"] {
        assert!(
            shim_sources.iter().any(|entry| entry == source),
            "interface inventory should cite shim source {source}"
        );
    }

    for version in ["2.40", "3.0", "3.2"] {
        let entry = interface_matrix_entry(&inventory, version);
        assert!(
            entry["spec_sources"]
                .as_array()
                .expect("spec_sources should be an array")
                .iter()
                .any(|source| source == "general_data_types.md")
        );
        assert!(
            entry["spec_sources"]
                .as_array()
                .expect("spec_sources should be an array")
                .iter()
                .any(|source| source == "general_purpose_functions.md")
        );
        assert_eq!(entry["reserved_standard_name"], true);
        assert_eq!(entry["flags"], Value::Array(Vec::new()));
    }
}

#[test]
fn oasis_inventory_tracks_mechanism_parameter_shape_layers() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    assert_eq!(inventory["mechanism_parameter_shape_count"], 79);
    assert_eq!(inventory["spec_parameter_struct_base_count"], 64);

    let gcm = parameter_shape_matrix_entry(&inventory, "Gcm");
    assert_eq!(gcm["rust_struct"], "GcmParams");
    assert!(gcm["pkcs11_structs"].as_array().unwrap().iter().any(|value| value == "CK_GCM_PARAMS"));
    assert_eq!(gcm["spec_present"], true);
    assert_eq!(gcm["proto_message"], "GcmParams");
    assert_eq!(gcm["proto_oneof_field"], "gcm_params");
    assert_eq!(gcm["backend_ffi_conversion"], true);
    assert_eq!(gcm["shim_read_support"], true);
    assert_eq!(gcm["shim_writeback_support"], true);
    assert!(
        gcm["mutable_output_behavior"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "CK_GCM_PARAMS.pIv")
    );

    let tls12 = parameter_shape_matrix_entry(&inventory, "Tls12MasterKeyDerive");
    assert_eq!(tls12["rust_struct"], "Tls12MasterKeyDeriveParams");
    assert!(
        tls12["pkcs11_structs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| { value == "CK_TLS12_MASTER_KEY_DERIVE_PARAMS" })
    );
    assert_eq!(tls12["proto_message"], "Tls12MasterKeyDeriveParams");
    assert_eq!(tls12["proto_oneof_field"], "tls12_master_key_derive_params");
    assert_eq!(tls12["backend_ffi_conversion"], true);
    assert_eq!(tls12["shim_read_support"], true);
    assert_eq!(tls12["shim_writeback_support"], true);
    assert!(
        tls12["mutable_output_behavior"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "CK_TLS12_MASTER_KEY_DERIVE_PARAMS.pVersion")
    );

    let wtls = parameter_shape_matrix_entry(&inventory, "WtlsMasterKeyDerive");
    assert_eq!(wtls["rust_struct"], "WtlsMasterKeyDeriveParams");
    assert!(
        wtls["pkcs11_structs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| { value == "CK_WTLS_MASTER_KEY_DERIVE_PARAMS" })
    );
    assert_eq!(wtls["proto_message"], "WtlsMasterKeyDeriveParams");
    assert_eq!(wtls["proto_oneof_field"], "wtls_master_key_derive_params");
    assert_eq!(wtls["backend_ffi_conversion"], true);
    assert_eq!(wtls["shim_read_support"], true);
    assert_eq!(wtls["shim_writeback_support"], true);
    assert!(
        wtls["mutable_output_behavior"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "CK_WTLS_MASTER_KEY_DERIVE_PARAMS.pVersion")
    );
    for expected_test in [
        "derive_key_mechanism_out_surfaces_wtls_version_through_mock_grpc_stack",
        "wtls_master_key_derive_output_params_surface_mutated_version_byte",
        "wtls_master_key_derive_reads_version_byte_and_writes_it_back",
    ] {
        assert!(
            wtls["local_tests"].as_array().unwrap().iter().any(|value| value == expected_test),
            "WTLS master-key derive row should cite {expected_test}"
        );
    }

    let wtls_key_mat = parameter_shape_matrix_entry(&inventory, "WtlsKeyMat");
    assert_eq!(wtls_key_mat["rust_struct"], "WtlsKeyMatParams");
    assert!(
        wtls_key_mat["pkcs11_structs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| { value == "CK_WTLS_KEY_MAT_PARAMS" })
    );
    assert_eq!(wtls_key_mat["proto_message"], "WtlsKeyMatParams");
    assert_eq!(wtls_key_mat["proto_oneof_field"], "wtls_key_mat_params");
    assert_eq!(wtls_key_mat["backend_ffi_conversion"], true);
    assert_eq!(wtls_key_mat["shim_read_support"], true);
    assert_eq!(wtls_key_mat["shim_writeback_support"], true);
    for expected_behavior in
        ["CK_WTLS_KEY_MAT_OUT.hMacSecret", "CK_WTLS_KEY_MAT_OUT.hKey", "CK_WTLS_KEY_MAT_OUT.pIV"]
    {
        assert!(
            wtls_key_mat["mutable_output_behavior"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == expected_behavior),
            "WTLS key material row should track {expected_behavior}"
        );
    }
    for expected_test in [
        "derive_key_mechanism_out_surfaces_wtls_key_material_through_mock_grpc_stack",
        "wtls_key_mat_output_params_surface_mutated_handles_and_iv",
        "wtls_key_mat_reads_caller_stack_params_and_writes_outputs_back",
    ] {
        assert!(
            wtls_key_mat["local_tests"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == expected_test),
            "WTLS key material row should cite {expected_test}"
        );
    }

    let wtls_prf = parameter_shape_matrix_entry(&inventory, "WtlsPrf");
    assert_eq!(wtls_prf["rust_struct"], "WtlsPrfParams");
    assert!(
        wtls_prf["pkcs11_structs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| { value == "CK_WTLS_PRF_PARAMS" })
    );
    assert_eq!(wtls_prf["proto_message"], "WtlsPrfParams");
    assert_eq!(wtls_prf["proto_oneof_field"], "wtls_prf_params");
    assert_eq!(wtls_prf["backend_ffi_conversion"], true);
    assert_eq!(wtls_prf["shim_read_support"], true);
    assert_eq!(wtls_prf["shim_writeback_support"], false);
    for expected_test in
        ["wtls_prf_params_round_trip", "reads_wtls_prf_and_x942_mqv_parameter_structs"]
    {
        assert!(
            wtls_prf["local_tests"].as_array().unwrap().iter().any(|value| value == expected_test),
            "WTLS PRF row should cite {expected_test}"
        );
    }

    let x942_mqv = parameter_shape_matrix_entry(&inventory, "X942MqvDerive");
    assert_eq!(x942_mqv["rust_struct"], "X942MqvDeriveParams");
    assert!(
        x942_mqv["pkcs11_structs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| { value == "CK_X9_42_MQV_DERIVE_PARAMS" })
    );
    assert_eq!(x942_mqv["proto_message"], "X942MqvDeriveParams");
    assert_eq!(x942_mqv["proto_oneof_field"], "x942_mqv_derive_params");
    assert_eq!(x942_mqv["backend_ffi_conversion"], true);
    assert_eq!(x942_mqv["shim_read_support"], true);
    assert_eq!(x942_mqv["shim_writeback_support"], false);
    for expected_test in [
        "x942_mqv_derive_round_trip",
        "reads_wtls_prf_and_x942_mqv_parameter_structs",
        "derive_key_validates_dual_ec_and_x942_parameter_handles",
    ] {
        assert!(
            x942_mqv["local_tests"].as_array().unwrap().iter().any(|value| value == expected_test),
            "X9.42 MQV row should cite {expected_test}"
        );
    }

    for (variant, pkcs11_struct, proto_field, proto_test) in [
        ("Kip", "CK_KIP_PARAMS", "kip_params", "kip_params_round_trip"),
        ("Otp", "CK_OTP_PARAMS", "otp_params", "otp_params_round_trip"),
        (
            "SkipjackPrivateWrap",
            "CK_SKIPJACK_PRIVATE_WRAP_PARAMS",
            "skipjack_private_wrap_params",
            "skipjack_private_wrap_round_trip",
        ),
        (
            "SkipjackRelayx",
            "CK_SKIPJACK_RELAYX_PARAMS",
            "skipjack_relayx_params",
            "skipjack_relayx_round_trip",
        ),
    ] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert!(
            entry["pkcs11_structs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| { value == pkcs11_struct }),
            "{variant} should cite {pkcs11_struct}"
        );
        assert_eq!(entry["proto_message"], format!("{variant}Params"));
        assert_eq!(entry["proto_oneof_field"], proto_field);
        assert_eq!(entry["backend_ffi_conversion"], true);
        assert_eq!(entry["shim_read_support"], true);
        assert_eq!(entry["shim_writeback_support"], false);

        let local_tests = entry["local_tests"].as_array().expect("local_tests should be an array");
        assert!(
            local_tests.iter().any(|value| value == proto_test),
            "{variant} row should cite proto round-trip coverage"
        );
        let shim_test = if variant == "Kip" {
            "reads_kip_parameter_struct_with_nested_mechanism"
        } else {
            "reads_otp_and_skipjack_parameter_structs"
        };
        assert!(
            local_tests.iter().any(|value| value == shim_test),
            "{variant} row should cite shim C-stack reader coverage"
        );
        if variant == "Kip" {
            assert!(
                local_tests.iter().any(|value| {
                    value == "kip_derive_and_mac_validate_hkey_but_wrap_does_not_use_it"
                }),
                "Kip row should cite MockBackend hKey semantic coverage"
            );
        }
    }

    let ssl3_key_mat = parameter_shape_matrix_entry(&inventory, "Ssl3KeyMat");
    assert_eq!(ssl3_key_mat["rust_struct"], "Ssl3KeyMatParams");
    assert!(
        ssl3_key_mat["pkcs11_structs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| { value == "CK_SSL3_KEY_MAT_PARAMS" })
    );
    assert_eq!(ssl3_key_mat["proto_message"], "Ssl3KeyMatParams");
    assert_eq!(ssl3_key_mat["proto_oneof_field"], "ssl3_key_mat_params");
    assert_eq!(ssl3_key_mat["backend_ffi_conversion"], true);
    assert_eq!(ssl3_key_mat["shim_read_support"], true);
    assert_eq!(ssl3_key_mat["shim_writeback_support"], true);
    for expected_behavior in [
        "CK_SSL3_KEY_MAT_OUT.hClientMacSecret",
        "CK_SSL3_KEY_MAT_OUT.hServerMacSecret",
        "CK_SSL3_KEY_MAT_OUT.hClientKey",
        "CK_SSL3_KEY_MAT_OUT.hServerKey",
        "CK_SSL3_KEY_MAT_OUT.pIVClient",
        "CK_SSL3_KEY_MAT_OUT.pIVServer",
    ] {
        assert!(
            ssl3_key_mat["mutable_output_behavior"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == expected_behavior),
            "SSL3/TLS key material row should track {expected_behavior}"
        );
    }
    for expected_test in [
        "derive_key_mechanism_out_surfaces_tls_key_material_through_mock_grpc_stack",
        "ssl3_key_mat_output_params_surface_mutated_handles_and_ivs",
        "tls12_key_mat_output_params_surface_mutated_handles_and_ivs",
        "ssl3_key_mat_reads_caller_stack_params_and_writes_outputs_back",
    ] {
        assert!(
            ssl3_key_mat["local_tests"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == expected_test),
            "SSL3/TLS key material row should cite {expected_test}"
        );
    }

    let pbe = parameter_shape_matrix_entry(&inventory, "Pbe");
    assert_eq!(pbe["rust_struct"], "PbeParams");
    assert!(
        pbe["pkcs11_structs"].as_array().unwrap().iter().any(|value| { value == "CK_PBE_PARAMS" })
    );
    assert_eq!(pbe["proto_message"], "PbeParams");
    assert_eq!(pbe["proto_oneof_field"], "pbe_params");
    assert_eq!(pbe["backend_ffi_conversion"], true);
    assert_eq!(pbe["shim_read_support"], true);
    assert_eq!(pbe["shim_writeback_support"], false);

    let extract = parameter_shape_matrix_entry(&inventory, "Extract");
    assert_eq!(extract["rust_struct"], "ExtractParams");
    assert!(
        extract["pkcs11_structs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "CK_EXTRACT_PARAMS")
    );
    assert_eq!(extract["spec_present"], true);
    assert_eq!(extract["proto_message"], "ExtractParams");
    assert_eq!(extract["proto_oneof_field"], "extract_params");
    assert_eq!(extract["backend_ffi_conversion"], true);
    assert_eq!(extract["shim_read_support"], true);
    assert_eq!(extract["shim_writeback_support"], false);

    let object_handle = parameter_shape_matrix_entry(&inventory, "ObjectHandle");
    assert_eq!(object_handle["rust_struct"], "ObjectHandleParam");
    assert!(
        object_handle["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|value| value == "derive_key_validates_concatenate_base_and_key_parameter_handle"),
        "ObjectHandle row should cite MockBackend derive parameter handle validation"
    );
}

#[test]
fn oasis_inventory_cites_local_tests_for_safe_represented_parameter_shapes() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    let missing: Vec<_> = inventory["mechanism_parameter_shape_matrix"]
        .as_array()
        .expect("mechanism_parameter_shape_matrix should be an array")
        .iter()
        .filter(|entry| {
            entry["backend_ffi_conversion"] == true
                && entry["proto_message"].is_string()
                && entry["shim_read_support"] == true
                && entry["unsupported_reason"].is_null()
                && entry["shim_read_unsupported_reason"].is_null()
                && entry["local_tests"]
                    .as_array()
                    .expect("local_tests should be an array")
                    .is_empty()
        })
        .map(|entry| entry["rust_variant"].as_str().unwrap_or("<unknown>").to_owned())
        .collect();

    assert!(
        missing.is_empty(),
        "safe represented parameter shapes should cite local tests: {missing:?}"
    );
}

#[test]
fn oasis_inventory_reports_stale_shape_test_citations() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for matrix_name in ["mechanism_parameter_shape_matrix", "message_parameter_shape_matrix"] {
        let stale: Vec<String> = inventory[matrix_name]
            .as_array()
            .unwrap_or_else(|| panic!("{matrix_name} should be an array"))
            .iter()
            .flat_map(|entry| {
                entry["local_tests_missing"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{matrix_name} rows should report stale tests"))
                    .iter()
                    .map(|test| {
                        format!(
                            "{}:{}",
                            entry["rust_variant"]
                                .as_str()
                                .expect("rust_variant should be a string"),
                            test.as_str().expect("missing test should be a string")
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(stale.is_empty(), "{matrix_name} cites stale local tests: {stale:?}");
    }
}

#[test]
fn oasis_inventory_marks_sp800108_nested_output_parameter_shapes() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for (variant, pkcs11_struct, proto_field) in [
        ("Sp800108Kdf", "CK_SP800_108_KDF_PARAMS", "sp800_108_kdf_params"),
        (
            "Sp800108FeedbackKdf",
            "CK_SP800_108_FEEDBACK_KDF_PARAMS",
            "sp800_108_feedback_kdf_params",
        ),
    ] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert!(
            entry["pkcs11_structs"].as_array().unwrap().iter().any(|value| value == pkcs11_struct),
            "{variant} should cite {pkcs11_struct}"
        );
        assert_eq!(entry["proto_oneof_field"], proto_field);
        assert_eq!(entry["backend_ffi_conversion"], true);
        assert_eq!(entry["shim_read_support"], true);
        assert_eq!(entry["shim_writeback_support"], true);
        assert_eq!(entry["nested_output_handles"], true);
        assert!(
            entry["nested_input_handles"]
                .as_array()
                .expect("nested_input_handles should be an array")
                .iter()
                .any(|handle| handle == "CK_PRF_DATA_PARAM.CK_SP800_108_KEY_HANDLE"),
            "{variant} should track SP800-108 key-handle data-param resolution"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test
                    == "sp800_108_feedback_reads_additional_keys_and_writes_handles_back"),
            "{variant} should cite loaded-shim SP800-108 writeback coverage"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test
                    == "derive_key_with_sp800_108_key_handle_data_param_requires_live_input_key"),
            "{variant} should cite MockBackend SP800-108 input handle validation coverage"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test
                    == "derive_key_with_sp800_108_additional_key_handles_preserves_templates"),
            "{variant} should cite MockBackend SP800-108 template-preservation coverage"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test
                    == "derive_key_with_sp800_108_additional_keys_does_not_partially_allocate_on_quota_failure"),
            "{variant} should cite MockBackend SP800-108 all-or-nothing quota coverage"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == "derive_key_with_sp800_108_enforces_mode_data_param_rules"),
            "{variant} should cite MockBackend SP800-108 mode data-param validation coverage"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == "derive_key_with_sp800_108_rejects_unsupported_prf_type"),
            "{variant} should cite MockBackend SP800-108 PRF type validation coverage"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test
                    == "derive_key_with_sp800_108_validates_data_param_payload_shapes_and_singletons"),
            "{variant} should cite MockBackend SP800-108 data-param payload validation coverage"
        );
        let grpc_virtualization_test = match variant {
            "Sp800108Kdf" => {
                "derive_key_mechanism_out_virtualizes_sp800_108_additional_key_handles"
            }
            "Sp800108FeedbackKdf" => {
                "derive_key_mechanism_out_virtualizes_sp800_108_feedback_additional_key_handles"
            }
            other => panic!("unexpected SP800-108 variant {other}"),
        };
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == grpc_virtualization_test),
            "{variant} should cite gRPC virtual-handle coverage for additional derived keys"
        );
        if variant == "Sp800108Kdf" {
            assert!(
                entry["local_tests"]
                    .as_array()
                    .expect("local_tests should be an array")
                    .iter()
                    .any(|test| test
                        == "derive_key_mechanism_out_virtualizes_sp800_108_double_pipeline_additional_key_handles"),
                "Sp800108Kdf should cite dedicated double-pipeline gRPC virtual-handle coverage"
            );
        }
    }
}

#[test]
fn oasis_inventory_marks_sp800108_error_output_writeback_coverage() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for variant in ["Sp800108Kdf", "Sp800108FeedbackKdf"] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        let limitation = &entry["error_output_behavior"];

        assert_eq!(
            limitation["source_behavior"],
            "CK_DERIVED_KEY.phKey set to CK_INVALID_HANDLE on template-caused multi-key derive failure",
            "{variant} should record the source-defined failure-time output behavior"
        );
        assert_eq!(limitation["current_support"], "supported");
        assert_eq!(
            limitation["reason"],
            "derive mechanism_out is preserved through non-CKR_OK proxy paths"
        );
        assert!(
            limitation["implementation_gap_paths"]
                .as_array()
                .expect("implementation_gap_paths should be an array")
                .is_empty(),
            "{variant} should no longer report implementation gap paths"
        );
        assert!(
            limitation["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test
                    == "derive_key_with_sp800_108_template_failure_reports_invalid_additional_handle"),
            "{variant} should cite MockBackend error-output coverage"
        );
        assert!(
            limitation["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test
                    == "derive_key_mechanism_out_surfaces_sp800_108_template_failure_handle"),
            "{variant} should cite gRPC error-output coverage"
        );
        assert!(
            limitation["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test
                    == "loaded_shim_writes_mechanism_out_to_caller_stack_after_encrypt_wrap_and_derive"),
            "{variant} should cite loaded-shim error-output coverage"
        );
    }
}

#[test]
fn oasis_inventory_cites_authenticated_wrap_parameter_shape_tests() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for (variant, pkcs11_struct, proto_test) in [
        ("GcmWrap", "CK_GCM_WRAP_PARAMS", "gcm_wrap_params_round_trip"),
        ("CcmWrap", "CK_CCM_WRAP_PARAMS", "ccm_wrap_params_round_trip"),
    ] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert!(
            entry["pkcs11_structs"].as_array().unwrap().iter().any(|value| value == pkcs11_struct),
            "{variant} should cite {pkcs11_struct}"
        );
        assert_eq!(entry["backend_ffi_conversion"], true);
        assert_eq!(entry["shim_read_support"], true);
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == proto_test),
            "{variant} should cite proto parameter round-trip coverage"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == "reads_authenticated_wrap_parameter_structs"),
            "{variant} should cite shim C ABI parameter reader coverage"
        );
    }
}

#[test]
fn oasis_inventory_cites_aead_and_chacha_parameter_shape_tests() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for (variant, pkcs11_struct, proto_test) in [
        ("Ccm", "CK_CCM_PARAMS", "ccm_params_round_trip"),
        ("ChaCha20", "CK_CHACHA20_PARAMS", "chacha20_params_round_trip"),
        (
            "Salsa20ChaCha20Poly1305",
            "CK_SALSA20_CHACHA20_POLY1305_PARAMS",
            "salsa20_chacha20_poly1305_params_round_trip",
        ),
    ] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert!(
            entry["pkcs11_structs"].as_array().unwrap().iter().any(|value| value == pkcs11_struct),
            "{variant} should cite {pkcs11_struct}"
        );
        assert_eq!(entry["backend_ffi_conversion"], true);
        assert_eq!(entry["shim_read_support"], true);
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == proto_test),
            "{variant} should cite proto parameter round-trip coverage"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == "reads_aead_and_chacha_parameter_structs"),
            "{variant} should cite shim C ABI parameter reader coverage"
        );
    }
}

#[test]
fn oasis_inventory_cites_counter_and_encrypt_data_parameter_shape_tests() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for (variant, pkcs11_struct, proto_test) in [
        ("AesCtr", "CK_AES_CTR_PARAMS", "aes_ctr_params_round_trip"),
        ("CamelliaCtr", "CK_CAMELLIA_CTR_PARAMS", "camellia_ctr_params_round_trip"),
        (
            "AesCbcEncryptData",
            "CK_AES_CBC_ENCRYPT_DATA_PARAMS",
            "aes_cbc_encrypt_data_params_round_trip",
        ),
        (
            "DesCbcEncryptData",
            "CK_DES_CBC_ENCRYPT_DATA_PARAMS",
            "des_cbc_encrypt_data_params_round_trip",
        ),
        (
            "AriaCbcEncryptData",
            "CK_ARIA_CBC_ENCRYPT_DATA_PARAMS",
            "aria_cbc_encrypt_data_params_round_trip",
        ),
        (
            "CamelliaCbcEncryptData",
            "CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS",
            "camellia_cbc_encrypt_data_params_round_trip",
        ),
        (
            "SeedCbcEncryptData",
            "CK_SEED_CBC_ENCRYPT_DATA_PARAMS",
            "seed_cbc_encrypt_data_params_round_trip",
        ),
    ] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert!(
            entry["pkcs11_structs"].as_array().unwrap().iter().any(|value| value == pkcs11_struct),
            "{variant} should cite {pkcs11_struct}"
        );
        assert_eq!(entry["backend_ffi_conversion"], true);
        assert_eq!(entry["shim_read_support"], true);
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == proto_test),
            "{variant} should cite proto parameter round-trip coverage"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == "reads_counter_and_encrypt_data_parameter_structs"),
            "{variant} should cite shim C ABI parameter reader coverage"
        );
    }
}

#[test]
fn oasis_inventory_cites_rsa_and_wrap_parameter_shape_tests() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for (variant, pkcs11_struct, proto_test, shim_test) in [
        (
            "RsaPkcsPss",
            "CK_RSA_PKCS_PSS_PARAMS",
            "mechanism_pss_round_trip",
            "reads_common_mechanism_parameter_structs",
        ),
        (
            "RsaPkcsOaep",
            "CK_RSA_PKCS_OAEP_PARAMS",
            "mechanism_oaep_round_trip",
            "reads_common_mechanism_parameter_structs",
        ),
        (
            "RsaAesKeyWrap",
            "CK_RSA_AES_KEY_WRAP_PARAMS",
            "rsa_aes_key_wrap_round_trip",
            "reads_rsa_wrap_parameter_structs",
        ),
        (
            "KeyWrapSetOaep",
            "CK_KEY_WRAP_SET_OAEP_PARAMS",
            "key_wrap_set_oaep_round_trip",
            "reads_rsa_wrap_parameter_structs",
        ),
    ] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert!(
            entry["pkcs11_structs"].as_array().unwrap().iter().any(|value| value == pkcs11_struct),
            "{variant} should cite {pkcs11_struct}"
        );
        assert_eq!(entry["published_header_present"], true);
        assert_eq!(entry["backend_ffi_conversion"], true);
        assert_eq!(entry["shim_read_support"], true);
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == proto_test),
            "{variant} should cite proto parameter round-trip coverage"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == shim_test),
            "{variant} should cite shim C ABI parameter reader coverage"
        );
    }

    let key_wrap_set_oaep = parameter_shape_matrix_entry(&inventory, "KeyWrapSetOaep");
    assert!(
        key_wrap_set_oaep["spec_sources"].as_array().unwrap().is_empty(),
        "CK_KEY_WRAP_SET_OAEP_PARAMS is published-header evidence, not working-spec evidence"
    );
}

#[test]
fn oasis_inventory_cites_legacy_rc_and_mac_general_parameter_shape_tests() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for (variant, pkcs11_struct, proto_test) in [
        ("Rc5", "CK_RC5_PARAMS", "rc5_params_round_trip"),
        ("Rc2Cbc", "CK_RC2_CBC_PARAMS", "rc2_cbc_params_round_trip"),
        ("MacGeneral", "CK_MAC_GENERAL_PARAMS", "mac_general_params_round_trip"),
    ] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert!(
            entry["pkcs11_structs"].as_array().unwrap().iter().any(|value| value == pkcs11_struct),
            "{variant} should cite {pkcs11_struct}"
        );
        assert_eq!(entry["published_header_present"], true);
        assert_eq!(entry["backend_ffi_conversion"], true);
        assert_eq!(entry["shim_read_support"], true);
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == proto_test),
            "{variant} should cite proto parameter round-trip coverage"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == "reads_legacy_rc2_rc5_and_salsa20_parameter_structs"),
            "{variant} should cite shim C ABI parameter reader coverage"
        );
    }

    for variant in ["Rc5", "Rc2Cbc"] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert!(
            entry["spec_sources"].as_array().unwrap().is_empty(),
            "{variant} is published-header evidence, not working-spec evidence"
        );
    }
    let mac_general = parameter_shape_matrix_entry(&inventory, "MacGeneral");
    assert!(
        !mac_general["spec_sources"].as_array().unwrap().is_empty(),
        "MacGeneral should cite working-spec evidence in addition to published headers"
    );
}

#[test]
fn oasis_inventory_cites_tls_ssl_parameter_shape_tests() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for (variant, pkcs11_struct, proto_test) in [
        ("TlsMac", "CK_TLS_MAC_PARAMS", "tls_mac_params_round_trip"),
        ("TlsPrf", "CK_TLS_PRF_PARAMS", "tls_prf_params_round_trip"),
        ("TlsKdf", "CK_TLS_KDF_PARAMS", "tls_kdf_params_round_trip"),
        (
            "Ssl3MasterKeyDerive",
            "CK_SSL3_MASTER_KEY_DERIVE_PARAMS",
            "ssl3_master_key_derive_round_trip",
        ),
        (
            "Tls12ExtendedMasterKeyDerive",
            "CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS",
            "tls12_extended_master_key_derive_round_trip",
        ),
    ] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert!(
            entry["pkcs11_structs"].as_array().unwrap().iter().any(|value| value == pkcs11_struct),
            "{variant} should cite {pkcs11_struct}"
        );
        assert_eq!(entry["published_header_present"], true);
        assert!(
            !entry["spec_sources"].as_array().unwrap().is_empty(),
            "{variant} should cite working-spec evidence"
        );
        assert_eq!(entry["backend_ffi_conversion"], true);
        assert_eq!(entry["shim_read_support"], true);
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == proto_test),
            "{variant} should cite proto parameter round-trip coverage"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == "reads_tls_ssl_parameter_structs"),
            "{variant} should cite shim C ABI parameter reader coverage"
        );
    }
}

#[test]
fn oasis_inventory_cites_kdf_and_legacy_agreement_parameter_shape_tests() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for (variant, pkcs11_struct, proto_test) in [
        ("Hkdf", "CK_HKDF_PARAMS", "hkdf_round_trip"),
        ("Gostr3410Derive", "CK_GOSTR3410_DERIVE_PARAMS", "gostr3410_derive_round_trip"),
        ("Gostr3410KeyWrap", "CK_GOSTR3410_KEY_WRAP_PARAMS", "gostr3410_key_wrap_round_trip"),
        ("KeaDerive", "CK_KEA_DERIVE_PARAMS", "kea_derive_round_trip"),
        ("Pkcs5Pbkd2", "CK_PKCS5_PBKD2_PARAMS2", "pkcs5_pbkd2_round_trip"),
    ] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert!(
            entry["pkcs11_structs"].as_array().unwrap().iter().any(|value| value == pkcs11_struct),
            "{variant} should cite {pkcs11_struct}"
        );
        assert_eq!(entry["published_header_present"], true);
        assert_eq!(entry["backend_ffi_conversion"], true);
        assert_eq!(entry["shim_read_support"], true);
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == proto_test),
            "{variant} should cite proto parameter round-trip coverage"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == "reads_kdf_and_legacy_agreement_parameter_structs"),
            "{variant} should cite shim C ABI parameter reader coverage"
        );
    }

    for variant in ["Hkdf", "Gostr3410Derive", "Gostr3410KeyWrap", "Pkcs5Pbkd2"] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert!(
            !entry["spec_sources"].as_array().unwrap().is_empty(),
            "{variant} should cite working-spec evidence"
        );
    }
    let kea = parameter_shape_matrix_entry(&inventory, "KeaDerive");
    assert!(
        kea["spec_sources"].as_array().unwrap().is_empty(),
        "KEA derive is published-header evidence, not working-spec evidence"
    );

    let pbkd2 = parameter_shape_matrix_entry(&inventory, "Pkcs5Pbkd2");
    assert!(
        pbkd2["pkcs11_structs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "CK_PKCS5_PBKD2_PARAMS"),
        "PKCS#5 PBKD2 should retain the legacy published-header struct alias"
    );
}

#[test]
fn oasis_inventory_cites_ecdh_and_x942_parameter_shape_tests() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for (variant, pkcs11_struct, proto_test) in [
        ("Ecdh1Derive", "CK_ECDH1_DERIVE_PARAMS", "mechanism_ecdh1_derive_round_trip"),
        ("Ecdh2Derive", "CK_ECDH2_DERIVE_PARAMS", "ecdh2_derive_round_trip"),
        ("EcmqvDerive", "CK_ECMQV_DERIVE_PARAMS", "ecmqv_derive_round_trip"),
        ("EcdhAesKeyWrap", "CK_ECDH_AES_KEY_WRAP_PARAMS", "ecdh_aes_key_wrap_round_trip"),
        ("X942Dh1Derive", "CK_X9_42_DH1_DERIVE_PARAMS", "x942_dh1_derive_round_trip"),
        ("X942Dh2Derive", "CK_X9_42_DH2_DERIVE_PARAMS", "x942_dh2_derive_round_trip"),
    ] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert!(
            entry["pkcs11_structs"].as_array().unwrap().iter().any(|value| value == pkcs11_struct),
            "{variant} should cite {pkcs11_struct}"
        );
        assert_eq!(entry["published_header_present"], true);
        assert!(
            !entry["spec_sources"].as_array().unwrap().is_empty(),
            "{variant} should cite working-spec evidence"
        );
        assert_eq!(entry["backend_ffi_conversion"], true);
        assert_eq!(entry["shim_read_support"], true);
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == proto_test),
            "{variant} should cite proto parameter round-trip coverage"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == "reads_ecdh_and_x942_parameter_structs"),
            "{variant} should cite shim C ABI parameter reader coverage"
        );
        if matches!(variant, "Ecdh2Derive" | "EcmqvDerive" | "X942Dh2Derive") {
            assert!(
                entry["local_tests"]
                    .as_array()
                    .expect("local_tests should be an array")
                    .iter()
                    .any(|test| test == "derive_key_validates_dual_ec_and_x942_parameter_handles"),
                "{variant} should cite MockBackend source-defined handle validation coverage"
            );
        }
    }
}

#[test]
fn oasis_inventory_cites_ike_parameter_shape_tests() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for (variant, pkcs11_struct, proto_test) in [
        ("IkePrfDerive", "CK_IKE_PRF_DERIVE_PARAMS", "ike_prf_derive_round_trip"),
        ("Ike1PrfDerive", "CK_IKE1_PRF_DERIVE_PARAMS", "ike1_prf_derive_round_trip"),
        ("Ike1ExtendedDerive", "CK_IKE1_EXTENDED_DERIVE_PARAMS", "ike1_extended_derive_round_trip"),
        ("Ike2PrfPlusDerive", "CK_IKE2_PRF_PLUS_DERIVE_PARAMS", "ike2_prf_plus_derive_round_trip"),
    ] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert!(
            entry["pkcs11_structs"].as_array().unwrap().iter().any(|value| value == pkcs11_struct),
            "{variant} should cite {pkcs11_struct}"
        );
        assert_eq!(entry["published_header_present"], true);
        assert!(
            !entry["spec_sources"].as_array().unwrap().is_empty(),
            "{variant} should cite working-spec evidence"
        );
        assert_eq!(entry["backend_ffi_conversion"], true);
        assert_eq!(entry["shim_read_support"], true);
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == proto_test),
            "{variant} should cite proto parameter round-trip coverage"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == "reads_ike_parameter_structs"),
            "{variant} should cite shim C ABI parameter reader coverage"
        );
    }
}

#[test]
fn oasis_inventory_cites_signature_parameter_shape_tests() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for (variant, pkcs11_struct, proto_test) in [
        ("Eddsa", "CK_EDDSA_PARAMS", "eddsa_round_trip"),
        ("Xeddsa", "CK_XEDDSA_PARAMS", "xeddsa_params_round_trip"),
    ] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert!(
            entry["pkcs11_structs"].as_array().unwrap().iter().any(|value| value == pkcs11_struct),
            "{variant} should cite {pkcs11_struct}"
        );
        assert_eq!(entry["published_header_present"], true);
        assert!(
            !entry["spec_sources"].as_array().unwrap().is_empty(),
            "{variant} should cite working-spec evidence"
        );
        assert_eq!(entry["backend_ffi_conversion"], true);
        assert_eq!(entry["shim_read_support"], true);
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == proto_test),
            "{variant} should cite proto parameter round-trip coverage"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == "reads_signature_parameter_structs"),
            "{variant} should cite shim C ABI parameter reader coverage"
        );
    }

    let cms = parameter_shape_matrix_entry(&inventory, "CmsSig");
    assert!(
        cms["pkcs11_structs"].as_array().unwrap().iter().any(|value| value == "CK_CMS_SIG_PARAMS"),
        "CmsSig should cite CK_CMS_SIG_PARAMS"
    );
    assert_eq!(cms["published_header_present"], true);
    assert!(
        !cms["spec_sources"].as_array().unwrap().is_empty(),
        "CmsSig should cite working-spec evidence"
    );
    assert_eq!(cms["backend_ffi_conversion"], true);
    assert_eq!(cms["shim_read_support"], false);
    assert_eq!(
        cms["shim_read_unsupported_reason"],
        "null_terminated_content_type_without_bounded_length"
    );
    for local_test in [
        "cms_sig_params_round_trip",
        "cms_sig_workflows_validate_optional_certificate_handle",
        "oasis_inventory_classifies_unsafe_shim_parameter_read_gaps",
    ] {
        assert!(
            cms["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == local_test),
            "CmsSig should cite {local_test}"
        );
    }
}

#[test]
fn oasis_inventory_cites_signal_parameter_shape_unsafe_shim_gaps() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for (variant, pkcs11_struct, proto_test, reason) in [
        (
            "X3dhInitiate",
            "CK_X3DH_INITIATE_PARAMS",
            "x3dh_initiate_round_trip",
            "lengthless_x3dh_byte_pointer_fields",
        ),
        (
            "X3dhRespond",
            "CK_X3DH_RESPOND_PARAMS",
            "x3dh_respond_round_trip",
            "lengthless_x3dh_byte_pointer_fields",
        ),
        (
            "X2RatchetInitialize",
            "CK_X2RATCHET_INITIALIZE_PARAMS",
            "x2_ratchet_initialize_round_trip",
            "lengthless_shared_secret_pointer",
        ),
        (
            "X2RatchetRespond",
            "CK_X2RATCHET_RESPOND_PARAMS",
            "x2_ratchet_respond_round_trip",
            "lengthless_shared_secret_pointer",
        ),
    ] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert!(
            entry["pkcs11_structs"].as_array().unwrap().iter().any(|value| value == pkcs11_struct),
            "{variant} should cite {pkcs11_struct}"
        );
        assert_eq!(entry["published_header_present"], true);
        assert!(
            !entry["spec_sources"].as_array().unwrap().is_empty(),
            "{variant} should cite working-spec evidence"
        );
        assert_eq!(entry["backend_ffi_conversion"], true);
        assert_eq!(entry["shim_read_support"], false);
        assert_eq!(entry["shim_read_unsupported_reason"], reason);
        for local_test in [
            proto_test,
            "derive_key_validates_source_grounded_signal_parameter_handles",
            "oasis_inventory_classifies_unsafe_shim_parameter_read_gaps",
        ] {
            assert!(
                entry["local_tests"]
                    .as_array()
                    .expect("local_tests should be an array")
                    .iter()
                    .any(|test| test == local_test),
                "{variant} should cite {local_test}"
            );
        }
        if matches!(variant, "X3dhInitiate" | "X3dhRespond") {
            assert!(
                entry["local_tests"]
                    .as_array()
                    .expect("local_tests should be an array")
                    .iter()
                    .any(|test| test
                        == "derive_key_leaves_lengthless_signal_byte_fields_unvalidated"),
                "{variant} should cite lengthless byte-field non-validation coverage"
            );
        }
    }
}

#[test]
fn oasis_inventory_marks_unmodeled_official_parameter_structs_explicitly() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };
    let comparison = &inventory["mechanism_parameter_struct_comparison"];

    let missing = comparison["spec_parameter_structs_missing_modeled_shape"]
        .as_array()
        .expect("spec_parameter_structs_missing_modeled_shape should be an array");
    assert!(
        missing.is_empty(),
        "all concrete spec parameter structs should be modeled or classified"
    );
    assert!(
        !missing.iter().any(|value| value == "CK_EXTRACT_PARAMS"),
        "CK_EXTRACT_PARAMS should be represented as a typed Extract parameter shape"
    );
    assert!(
        !missing.iter().any(|value| value == "CK_CHACHA20POLY1305_PARAMS"),
        "CK_CHACHA20POLY1305_PARAMS is a working-spec prose alias for an already modeled struct"
    );
    assert!(
        !missing.iter().any(|value| value == "CK_XXX_MESSAGE_PARAMS"),
        "CK_XXX_MESSAGE_PARAMS is a prose placeholder, not a concrete ABI struct"
    );

    let aliases = comparison["spec_parameter_structs_modeled_as_aliases"]
        .as_array()
        .expect("spec_parameter_structs_modeled_as_aliases should be an array");
    let chacha_alias = aliases
        .iter()
        .find(|entry| entry["spec_struct"] == "CK_CHACHA20POLY1305_PARAMS")
        .expect("CK_CHACHA20POLY1305_PARAMS should be an explicit alias row");
    assert_eq!(chacha_alias["modeled_as"], "CK_SALSA20_CHACHA20_POLY1305_PARAMS");
    assert_eq!(chacha_alias["rust_variant"], "Salsa20ChaCha20Poly1305");
    assert_eq!(chacha_alias["reason"], "working_spec_prose_alias_not_published_header_struct");

    let placeholders = comparison["spec_parameter_structs_excluded_placeholders"]
        .as_array()
        .expect("spec_parameter_structs_excluded_placeholders should be an array");
    let xxx_placeholder = placeholders
        .iter()
        .find(|entry| entry["spec_struct"] == "CK_XXX_MESSAGE_PARAMS")
        .expect("CK_XXX_MESSAGE_PARAMS should be an explicit placeholder row");
    assert_eq!(
        xxx_placeholder["reason"],
        "prose_placeholder_for_mechanism_specific_message_params"
    );
    assert!(
        xxx_placeholder["sources"]
            .as_array()
            .expect("placeholder sources should be an array")
            .iter()
            .any(|source| source == "key_management_functions.md")
    );

    let raw = parameter_shape_matrix_entry(&inventory, "Raw");
    assert_eq!(raw["spec_present"], false);
    assert_eq!(raw["proto_message"], "RawMechanismParams");
    assert_eq!(raw["backend_ffi_conversion"], false);
    assert_eq!(raw["shim_read_support"], true);
    assert_eq!(raw["unsupported_reason"], "opaque_raw_params_not_safe_for_backend_ffi");
    assert!(
        raw["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|test| test == "unsupported_mechanism_params_are_rejected_by_backend_ffi"),
        "Raw should cite backend FFI rejection coverage"
    );

    for variant in [
        "Ecies",
        "AesCmacKeyDerivation",
        "Dilithium",
        "Kyber",
        "HdKeyDerive",
        "VendorObjectExtract",
        "VendorObjectInsert",
    ] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert_eq!(
            entry["unsupported_reason"], "vendor_specific_param_not_safe_for_backend_ffi",
            "{variant} should be explicitly classified as vendor-specific FFI-unsafe"
        );
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|test| test == "unsupported_mechanism_params_are_rejected_by_backend_ffi"),
            "{variant} should cite backend FFI rejection coverage"
        );
    }

    for (variant, pkcs11_struct, proto_field) in
        [("Kmac", "CK_KMAC_PARAMS", "kmac_params"), ("MuGen", "CK_MU_GEN_PARAMS", "mu_gen_params")]
    {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert_eq!(entry["spec_present"], true);
        assert!(
            entry["pkcs11_structs"]
                .as_array()
                .expect("pkcs11_structs should be an array")
                .iter()
                .any(|candidate| candidate == pkcs11_struct),
            "{variant} should cite {pkcs11_struct}"
        );
        assert_eq!(entry["proto_oneof_field"], proto_field);
        assert_eq!(entry["backend_ffi_conversion"], true);
        assert_eq!(entry["shim_read_support"], true);
        assert_eq!(entry["shim_writeback_support"], false);
        assert!(
            !entry["local_tests"].as_array().expect("local_tests should be an array").is_empty(),
            "{variant} should cite local unit coverage"
        );
    }

    for (variant, pkcs11_struct, proto_field, proto_test) in [
        (
            "Rc2MacGeneral",
            "CK_RC2_MAC_GENERAL_PARAMS",
            "rc2_mac_general_params",
            "rc2_mac_general_params_round_trip",
        ),
        (
            "Rc5MacGeneral",
            "CK_RC5_MAC_GENERAL_PARAMS",
            "rc5_mac_general_params",
            "rc5_mac_general_params_round_trip",
        ),
        ("Rc5Cbc", "CK_RC5_CBC_PARAMS", "rc5_cbc_params", "rc5_cbc_params_round_trip"),
        ("Salsa20", "CK_SALSA20_PARAMS", "salsa20_params", "salsa20_params_round_trip"),
    ] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert_eq!(entry["published_header_present"], true);
        assert!(
            entry["spec_present"] == true || entry["published_header_present"] == true,
            "{variant} should be grounded in the working spec or published OASIS headers"
        );
        assert!(
            entry["pkcs11_structs"]
                .as_array()
                .expect("pkcs11_structs should be an array")
                .iter()
                .any(|candidate| candidate == pkcs11_struct),
            "{variant} should cite {pkcs11_struct}"
        );
        assert_eq!(entry["proto_oneof_field"], proto_field);
        assert_eq!(entry["backend_ffi_conversion"], true);
        assert_eq!(entry["shim_read_support"], true);
        assert_eq!(entry["shim_writeback_support"], false);

        let local_tests = entry["local_tests"].as_array().expect("local_tests should be an array");
        assert!(
            local_tests.iter().any(|candidate| candidate == proto_test),
            "{variant} should cite proto round-trip coverage"
        );
        assert!(
            local_tests
                .iter()
                .any(|candidate| candidate == "reads_legacy_rc2_rc5_and_salsa20_parameter_structs"),
            "{variant} should cite shim C-stack reader coverage"
        );
    }
}

#[test]
fn oasis_inventory_tracks_message_parameter_shape_layers() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    assert_eq!(inventory["message_parameter_shape_count"], 3);

    let gcm = message_parameter_shape_matrix_entry(&inventory, "GcmMessage");
    assert_eq!(gcm["rust_struct"], "GcmMessageParams");
    assert_eq!(gcm["pkcs11_struct"], "CK_GCM_MESSAGE_PARAMS");
    assert_eq!(gcm["spec_present"], true);
    assert_eq!(gcm["proto_message"], "GcmMessageParams");
    assert_eq!(gcm["proto_oneof_field"], "gcm_message_params");
    assert_eq!(gcm["backend_ffi_message_conversion"], true);
    assert_eq!(gcm["shim_read_support"], true);
    assert_eq!(gcm["shim_writeback_support"], true);
    assert!(
        gcm["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|test| test == "typed_message_exact_paths_return_structured_mock_outputs"),
        "GCM message row should cite MockBackend typed exact-path coverage"
    );
    for output in ["CK_GCM_MESSAGE_PARAMS.pIv", "CK_GCM_MESSAGE_PARAMS.pTag"] {
        assert!(
            gcm["mutable_output_behavior"].as_array().unwrap().iter().any(|value| value == output),
            "GCM message row should record mutable output {output}"
        );
    }

    let ccm = message_parameter_shape_matrix_entry(&inventory, "CcmMessage");
    assert_eq!(ccm["rust_struct"], "CcmMessageParams");
    assert_eq!(ccm["pkcs11_struct"], "CK_CCM_MESSAGE_PARAMS");
    assert_eq!(ccm["proto_message"], "CcmMessageParams");
    assert_eq!(ccm["proto_oneof_field"], "ccm_message_params");
    assert_eq!(ccm["backend_ffi_message_conversion"], true);
    assert_eq!(ccm["shim_read_support"], true);
    assert_eq!(ccm["shim_writeback_support"], true);
    assert!(
        ccm["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|test| test == "typed_message_exact_paths_return_structured_mock_outputs"),
        "CCM message row should cite MockBackend typed exact-path coverage"
    );

    let salsa = message_parameter_shape_matrix_entry(&inventory, "SalaChacha");
    assert_eq!(salsa["rust_struct"], "Salsa20ChaCha20Poly1305MessageParams");
    assert_eq!(salsa["pkcs11_struct"], "CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS");
    assert_eq!(salsa["proto_message"], "Salsa20ChaCha20Poly1305MessageParams");
    assert_eq!(salsa["proto_oneof_field"], "salsa_chacha_message_params");
    assert_eq!(salsa["backend_ffi_message_conversion"], true);
    assert_eq!(salsa["shim_read_support"], true);
    assert_eq!(salsa["shim_writeback_support"], true);
    assert!(
        salsa["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|test| test == "typed_message_exact_paths_return_structured_mock_outputs"),
        "Salsa/ChaCha message row should cite MockBackend typed exact-path coverage"
    );
}

#[test]
fn oasis_inventory_classifies_unsafe_shim_parameter_read_gaps() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for (variant, reason) in [
        ("CmsSig", "null_terminated_content_type_without_bounded_length"),
        ("X2RatchetInitialize", "lengthless_shared_secret_pointer"),
        ("X2RatchetRespond", "lengthless_shared_secret_pointer"),
        ("X3dhInitiate", "lengthless_x3dh_byte_pointer_fields"),
        ("X3dhRespond", "lengthless_x3dh_byte_pointer_fields"),
    ] {
        let entry = parameter_shape_matrix_entry(&inventory, variant);
        assert_eq!(entry["backend_ffi_conversion"], true);
        assert_eq!(entry["proto_message"], format!("{variant}Params"));
        assert_eq!(entry["shim_read_support"], false);
        assert_eq!(entry["shim_read_unsupported_reason"], reason);
        let decision = &entry["shim_read_decision"];
        assert_eq!(
            decision["policy"], "do_not_parse_unbounded_caller_pointers_in_shim",
            "{variant} should pin the C-stack pointer safety policy"
        );
        assert_eq!(
            decision["fallback"], "preserve_raw_mechanism_params_for_proxying",
            "{variant} should document the shim fallback for unsafe typed reads"
        );
        assert_eq!(
            decision["caller_visible_outcome"],
            "direct_shim_parameterized_calls_return_CKR_MECHANISM_PARAM_INVALID",
            "{variant} should document the direct C ABI behavior for unsafe typed reads"
        );
        assert!(
            decision["local_tests"]
                .as_array()
                .expect("shim read decision local_tests should be an array")
                .iter()
                .any(|test| test
                    == "unsafe_official_lengthless_parameter_shapes_are_rejected_before_shim_read"),
            "{variant} should cite the shim helper policy test for unsupported unsafe shapes"
        );
        assert!(
            decision["local_tests"]
                .as_array()
                .expect("shim read decision local_tests should be an array")
                .iter()
                .any(|test| test
                    == "loaded_shim_rejects_unsafe_official_lengthless_parameter_shapes"),
            "{variant} should cite the loaded-shim C ABI policy test for unsupported unsafe shapes"
        );
        assert_eq!(
            decision["compatibility_risk"],
            "typed_shim_read_would_require_guessing_pointer_lengths",
            "{variant} should document why typed shim parsing is not acceptable"
        );
        assert!(
            decision["evidence"]
                .as_array()
                .expect("shim read decision evidence should be an array")
                .iter()
                .any(|source| source == "crates/shim/src/dispatch/general/helpers.rs"),
            "{variant} should cite the shim reader implementation"
        );
    }

    let unclassified: Vec<_> = inventory["mechanism_parameter_shape_matrix"]
        .as_array()
        .expect("mechanism_parameter_shape_matrix should be an array")
        .iter()
        .filter(|entry| {
            entry["backend_ffi_conversion"] == true
                && entry["proto_message"].is_string()
                && entry["shim_read_support"] == false
                && (entry["spec_present"] == true || entry["published_header_present"] == true)
                && entry["shim_read_unsupported_reason"].is_null()
        })
        .map(|entry| entry["rust_variant"].as_str().unwrap_or("<unknown>").to_owned())
        .collect();
    assert!(unclassified.is_empty(), "unclassified shim read gaps: {unclassified:?}");
}

#[test]
fn oasis_inventory_does_not_count_message_params_as_mechanism_shape_gaps() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };
    let comparison = &inventory["mechanism_parameter_struct_comparison"];

    let missing = comparison["spec_parameter_structs_missing_modeled_shape"]
        .as_array()
        .expect("spec_parameter_structs_missing_modeled_shape should be an array");
    for message_struct in [
        "CK_GCM_MESSAGE_PARAMS",
        "CK_CCM_MESSAGE_PARAMS",
        "CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS",
    ] {
        assert!(
            !missing.iter().any(|value| value == message_struct),
            "{message_struct} should be represented by message_parameter_shape_matrix, not counted as a mechanism-parameter gap"
        );
    }

    let message_structs = comparison["spec_parameter_structs_modeled_as_message_parameters"]
        .as_array()
        .expect("spec_parameter_structs_modeled_as_message_parameters should be an array");
    for message_struct in [
        "CK_GCM_MESSAGE_PARAMS",
        "CK_CCM_MESSAGE_PARAMS",
        "CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS",
    ] {
        assert!(
            message_structs.iter().any(|value| value == message_struct),
            "{message_struct} should be explicitly listed as a message parameter shape"
        );
    }
}

#[test]
fn oasis_inventory_tracks_digest_xof_as_explicit_abi_decision() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    let missing: Vec<&str> = inventory["spec_functions_missing_from_function_lists"]
        .as_array()
        .expect("missing function list should be an array")
        .iter()
        .map(|value| value.as_str().expect("missing function should be a string"))
        .filter(|name| name.contains("DigestXof"))
        .collect();
    assert_eq!(missing, DIGEST_XOF_FUNCTIONS);

    for function in DIGEST_XOF_FUNCTIONS {
        let entry = function_matrix_entry(&inventory, function);
        assert_eq!(entry["status"], "spec_only", "{function} should stay spec-only");
        assert_eq!(entry["function_list_field"], false, "{function} has no ABI field");
        assert_eq!(
            entry["unsupported_reason"], "cryptoki_sys_missing_function_list_field",
            "{function} should carry the explicit ABI decision reason"
        );
        let decision = &entry["local_abi_decision"];
        assert_eq!(
            decision["policy"], "do_not_add_out_of_band_exports_or_custom_function_list_layout",
            "{function} should pin the ABI policy instead of leaving it implicit"
        );
        assert_eq!(
            decision["reason"], "working_spec_declares_function_but_standard_function_lists_do_not",
            "{function} should distinguish the OASIS source inconsistency from local omission"
        );
        assert_eq!(
            decision["compatibility_risk"],
            "custom_ck_function_list_layout_would_break_standard_pkcs11_abi",
            "{function} should document why local struct extension is not acceptable"
        );
        assert!(
            decision["evidence"]
                .as_array()
                .expect("XOF ABI decision evidence should be an array")
                .iter()
                .any(|source| source == "working/doc/spec/message_digesting_functions.md"),
            "{function} should cite the working spec declaration"
        );
        assert!(
            decision["evidence"]
                .as_array()
                .expect("XOF ABI decision evidence should be an array")
                .iter()
                .any(|source| source == "crates/backend/src/ffi/function_field_tables.rs"),
            "{function} should cite the local function-list field table checked for ABI exposure"
        );
        assert!(
            entry["spec_sources"]
                .as_array()
                .expect("spec_sources should be an array")
                .iter()
                .any(|source| source == "message_digesting_functions.md"),
            "{function} should be sourced to the digest XOF spec section"
        );
        assert!(
            entry["local_tests"].as_array().expect("local_tests should be an array").iter().any(
                |candidate| {
                    candidate == "loaded_shim_does_not_export_digest_xof_out_of_band_symbols"
                }
            ),
            "{function} should cite loaded-shim export-surface coverage"
        );
    }
}

#[test]
fn oasis_inventory_tracks_intentional_mockbackend_trait_defaults() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    let decisions = inventory["mock_backend_default_trait_decisions"]
        .as_array()
        .expect("mock_backend_default_trait_decisions should be an array");
    let methods: Vec<&str> = decisions
        .iter()
        .map(|entry| entry["backend_trait_method"].as_str().expect("method should be a string"))
        .collect();
    assert_eq!(methods, ["cancel_function", "get_function_status"]);

    const LEGACY_PARALLEL_DEFAULTS: [(&str, &str); 2] =
        [("cancel_function", "C_CancelFunction"), ("get_function_status", "C_GetFunctionStatus")];

    for (method, c_function) in LEGACY_PARALLEL_DEFAULTS {
        let entry = mock_backend_default_trait_decision_entry(&inventory, method);
        assert_eq!(entry["c_function"], c_function);
        assert_eq!(entry["returned_rv"], "CKR_FUNCTION_NOT_PARALLEL");
        assert_eq!(entry["reason"], "legacy_parallel_operation_status_api");
        assert_eq!(entry["spec_present"], true);
        assert_eq!(entry["function_list_field"], true);
        let local_tests = entry["local_tests"].as_array().expect("local_tests should be an array");
        assert!(
            local_tests
                .iter()
                .any(|test| test == "mock_legacy_parallel_functions_return_function_not_parallel"),
            "{method} should cite MockBackend behavior coverage"
        );
        assert!(
            entry["local_tests_missing"]
                .as_array()
                .expect("local_tests_missing should be an array")
                .is_empty(),
            "{method} should not cite stale local tests"
        );
    }
}

#[test]
fn oasis_inventory_sources_mechanism_values_from_vendored_oasis_headers() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    let source_headers = inventory["source"]["official_mechanism_headers"]
        .as_array()
        .expect("inventory should expose source OASIS mechanism headers");
    for header in [
        "../doc/oasis-tcs-pkcs11/published/2-40-errata-1/pkcs11t.h",
        "../doc/oasis-tcs-pkcs11/published/3-00/pkcs11t.h",
        "../doc/oasis-tcs-pkcs11/published/3-01/pkcs11t.h",
        "../doc/oasis-tcs-pkcs11/published/3-02/pkcs11t.h",
    ] {
        assert!(
            source_headers.iter().any(|value| value == header),
            "inventory should cite vendored OASIS header {header}; source was {source_headers:?}"
        );
    }

    let aes_gcm = official_mechanism_entry(&inventory, "CKM_AES_GCM");
    assert_eq!(aes_gcm["value"], "0x00001087");
    assert_eq!(aes_gcm["version_introduced"], "2.40");
    assert!(
        aes_gcm["source_versions"]
            .as_array()
            .expect("source_versions should be an array")
            .iter()
            .any(|version| version == "2.40")
    );

    let shake_key_derivation = official_mechanism_entry(&inventory, "CKM_SHAKE_128_KEY_DERIVATION");
    assert_eq!(shake_key_derivation["value"], "0x0000039B");
    assert_eq!(shake_key_derivation["version_introduced"], "3.0");
    assert!(
        shake_key_derivation["names"]
            .as_array()
            .expect("names should be an array")
            .iter()
            .any(|name| name == "CKM_SHAKE_128_KEY_DERIVE"),
        "aliases from OASIS headers should stay visible"
    );

    let ml_kem = official_mechanism_entry(&inventory, "CKM_ML_KEM");
    assert_eq!(ml_kem["value"], "0x00000017");
    assert_eq!(ml_kem["version_introduced"], "3.2");
}

#[test]
fn oasis_inventory_compares_rust_official_mechanisms_to_oasis_headers() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };
    let comparison = &inventory["rust_official_mechanism_inventory_comparison"];

    assert_eq!(comparison["matches"], true);
    assert!(
        comparison["oasis_values_missing_from_rust"]
            .as_array()
            .expect("oasis_values_missing_from_rust should be an array")
            .is_empty()
    );
    assert!(
        comparison["rust_values_missing_from_oasis_headers"]
            .as_array()
            .expect("rust_values_missing_from_oasis_headers should be an array")
            .is_empty()
    );
    assert!(
        comparison["oasis_names_missing_from_rust"]
            .as_array()
            .expect("oasis_names_missing_from_rust should be an array")
            .is_empty()
    );
    assert!(
        comparison["rust_names_missing_from_oasis_headers"]
            .as_array()
            .expect("rust_names_missing_from_oasis_headers should be an array")
            .is_empty()
    );
}

#[test]
fn oasis_inventory_marks_working_spec_mechanisms_without_published_values() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for mechanism in ["CKM_KMAC128", "CKM_SHAKE_128", "CKM_ML_DSA_EXTERNAL_MU"] {
        let entry = mechanism_matrix_entry(&inventory, mechanism);
        assert_eq!(entry["status"], "spec_only", "{mechanism} should be working-spec-only");
        assert_eq!(entry["official_inventory_present"], false);
        assert_eq!(
            entry["unsupported_reason"], "oasis_working_spec_lacks_published_numeric_value",
            "{mechanism} should explain why MockBackend cannot advertise it"
        );
        let decision = &entry["local_numeric_decision"];
        assert_eq!(
            decision["policy"], "do_not_assign_project_local_ckm_values_for_working_spec_names",
            "{mechanism} should pin the numeric-value policy"
        );
        assert_eq!(
            decision["reason"], "working_spec_mechanism_name_lacks_published_ck_mechanism_type",
            "{mechanism} should distinguish source drift from implementation omission"
        );
        assert_eq!(
            decision["compatibility_risk"],
            "locally_assigned_ckm_values_could_collide_with_future_oasis_or_vendor_values",
            "{mechanism} should document why local numeric allocation is unsafe"
        );
        let spec_sources =
            entry["spec_sources"].as_array().expect("spec_sources should be an array");
        assert!(
            decision["evidence"]
                .as_array()
                .expect("numeric decision evidence should be an array")
                .iter()
                .any(|source| spec_sources.contains(source)),
            "{mechanism} should cite its working spec source"
        );
    }
}

#[test]
fn oasis_inventory_marks_published_header_only_mechanisms_as_source_discrepancies() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for mechanism in
        ["CKM_CAST5_CBC", "CKM_RC2_CBC", "CKM_SHA3_256_KEY_DERIVE", "CKM_TLS_MASTER_KEY_DERIVE"]
    {
        let entry = mechanism_matrix_entry(&inventory, mechanism);
        assert_eq!(entry["spec_present"], false);
        assert_eq!(entry["official_inventory_present"], true);
        assert_eq!(entry["status"], "represented");
        assert_eq!(
            entry["source_discrepancy_reason"],
            "oasis_published_header_not_in_working_markdown"
        );
        assert!(entry["value"].is_string());
        assert!(entry["version_introduced"].is_string());
        assert_eq!(
            entry["mock_backend_internal_coverage"]["advertised_by_official_constructor"],
            true
        );
    }

    let working_spec_only = mechanism_matrix_entry(&inventory, "CKM_KMAC128");
    assert_eq!(working_spec_only["status"], "spec_only");
    assert_eq!(
        working_spec_only["unsupported_reason"],
        "oasis_working_spec_lacks_published_numeric_value"
    );
    assert_eq!(working_spec_only["source_discrepancy_reason"], Value::Null);
}

#[test]
fn oasis_inventory_mechanism_matrix_exposes_values_aliases_and_versions() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    let aes_gcm = mechanism_matrix_entry(&inventory, "CKM_AES_GCM");
    assert_eq!(aes_gcm["value"], "0x00001087");
    assert_eq!(aes_gcm["version_introduced"], "2.40");
    assert_eq!(aes_gcm["name_version_introduced"], "2.40");
    assert!(
        aes_gcm["header_annotations"]
            .as_array()
            .expect("header_annotations should be an array")
            .is_empty(),
        "current AES-GCM published headers should not carry Historical/Deprecated annotations"
    );
    assert!(
        aes_gcm["aliases"]
            .as_array()
            .expect("aliases should be an array")
            .iter()
            .any(|alias| alias == "CKM_AES_GCM")
    );

    let shake_alias = mechanism_matrix_entry(&inventory, "CKM_SHAKE_128_KEY_DERIVE");
    assert_eq!(shake_alias["value"], "0x0000039B");
    assert_eq!(shake_alias["version_introduced"], "3.0");
    assert_eq!(shake_alias["name_version_introduced"], "3.0");
    for alias in ["CKM_SHAKE_128_KEY_DERIVATION", "CKM_SHAKE_128_KEY_DERIVE"] {
        assert!(
            shake_alias["aliases"]
                .as_array()
                .expect("aliases should be an array")
                .iter()
                .any(|candidate| candidate == alias),
            "mechanism matrix should retain alias {alias}"
        );
    }

    let cast5_cbc = mechanism_matrix_entry(&inventory, "CKM_CAST5_CBC");
    assert!(
        cast5_cbc["header_annotations"]
            .as_array()
            .expect("header_annotations should be an array")
            .iter()
            .any(|annotation| annotation == "Deprecated"),
        "CKM_CAST5_CBC should expose the published Deprecated header annotation"
    );

    let cast128_cbc = mechanism_matrix_entry(&inventory, "CKM_CAST128_CBC");
    assert!(
        cast128_cbc["header_annotations"]
            .as_array()
            .expect("header_annotations should be an array")
            .iter()
            .any(|annotation| annotation == "Historical"),
        "CKM_CAST128_CBC should expose the published Historical header annotation"
    );

    let des_cbc = mechanism_matrix_entry(&inventory, "CKM_DES_CBC");
    assert!(
        des_cbc["header_annotations"]
            .as_array()
            .expect("header_annotations should be an array")
            .iter()
            .any(|annotation| annotation == "Historical"),
        "CKM_DES_CBC should expose the published Historical header annotation"
    );

    let working_spec_only = mechanism_matrix_entry(&inventory, "CKM_KMAC128");
    assert_eq!(working_spec_only["value"], Value::Null);
    assert_eq!(working_spec_only["version_introduced"], Value::Null);
    assert!(
        working_spec_only["aliases"].as_array().expect("aliases should be an array").is_empty()
    );
}

#[test]
fn oasis_inventory_mechanism_parameter_structs_are_not_file_wide_polluted() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for mechanism in ["CKM_AES_KEY_GEN", "CKM_AES_MAC", "CKM_RSA_PKCS", "CKM_SHA1_RSA_PKCS"] {
        let entry = mechanism_matrix_entry(&inventory, mechanism);
        assert_eq!(
            entry["parameter_structs"].as_array().expect("parameter_structs should be an array"),
            &Vec::<Value>::new(),
            "{mechanism} should not inherit unrelated parameter structs from its spec file"
        );
    }

    for (mechanism, expected, unexpected) in [
        ("CKM_AES_MAC_GENERAL", &["CK_MAC_GENERAL_PARAMS"][..], &["CK_AES_CTR_PARAMS"][..]),
        ("CKM_AES_CTR", &["CK_AES_CTR_PARAMS"], &["CK_MAC_GENERAL_PARAMS"]),
        (
            "CKM_AES_GCM",
            &["CK_GCM_PARAMS", "CK_GCM_MESSAGE_PARAMS", "CK_GCM_WRAP_PARAMS"],
            &["CK_CCM_PARAMS", "CK_CCM_MESSAGE_PARAMS", "CK_CCM_WRAP_PARAMS"],
        ),
        (
            "CKM_AES_CCM",
            &["CK_CCM_PARAMS", "CK_CCM_MESSAGE_PARAMS", "CK_CCM_WRAP_PARAMS"],
            &["CK_GCM_PARAMS", "CK_GCM_MESSAGE_PARAMS", "CK_GCM_WRAP_PARAMS"],
        ),
        (
            "CKM_RSA_PKCS_OAEP",
            &["CK_RSA_PKCS_OAEP_PARAMS"],
            &["CK_RSA_PKCS_PSS_PARAMS", "CK_RSA_AES_KEY_WRAP_PARAMS"],
        ),
        (
            "CKM_RSA_PKCS_PSS",
            &["CK_RSA_PKCS_PSS_PARAMS"],
            &["CK_RSA_PKCS_OAEP_PARAMS", "CK_RSA_AES_KEY_WRAP_PARAMS"],
        ),
        (
            "CKM_SHA1_RSA_PKCS_PSS",
            &["CK_RSA_PKCS_PSS_PARAMS"],
            &["CK_RSA_PKCS_OAEP_PARAMS", "CK_RSA_AES_KEY_WRAP_PARAMS"],
        ),
        (
            "CKM_RSA_AES_KEY_WRAP",
            &["CK_RSA_AES_KEY_WRAP_PARAMS"],
            &["CK_RSA_PKCS_OAEP_PARAMS", "CK_RSA_PKCS_PSS_PARAMS"],
        ),
        ("CKM_TLS_PRF", &["CK_TLS_PRF_PARAMS"], &["CK_TLS_MAC_PARAMS"]),
        ("CKM_TLS_MAC", &["CK_TLS_MAC_PARAMS"], &["CK_TLS_PRF_PARAMS"]),
        ("CKM_TLS12_MAC", &["CK_TLS_MAC_PARAMS"], &["CK_TLS_PRF_PARAMS"]),
        ("CKM_AES_GMAC", &["CK_GCM_PARAMS"], &["CK_GCM_MESSAGE_PARAMS", "CK_GCM_WRAP_PARAMS"]),
    ] {
        let entry = mechanism_matrix_entry(&inventory, mechanism);
        let structs =
            entry["parameter_structs"].as_array().expect("parameter_structs should be an array");
        for expected_struct in expected {
            assert!(
                structs.iter().any(|candidate| candidate == expected_struct),
                "{mechanism} should cite source-local parameter struct {expected_struct}; got {structs:?}"
            );
        }
        for unexpected_struct in unexpected {
            assert!(
                !structs.iter().any(|candidate| candidate == unexpected_struct),
                "{mechanism} should not cite unrelated parameter struct {unexpected_struct}; got {structs:?}"
            );
        }
    }
}

#[test]
fn oasis_inventory_labels_encapsulate_decapsulate_workflow_column() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    for mechanism in ["CKM_ML_KEM", "CKM_RSA_PKCS"] {
        let entry = mechanism_matrix_entry(&inventory, mechanism);
        let workflows = entry["workflows"].as_array().expect("workflows should be an array");
        assert!(
            workflows.iter().any(|workflow| workflow == "encapsulate_decapsulate"),
            "{mechanism} should mark the ENCS/DECS table column as encapsulate/decapsulate"
        );
        assert!(
            !workflows.iter().any(|workflow| workflow == "message_encrypt_decrypt"),
            "{mechanism} should not classify the ENCS/DECS table column as message operations"
        );
    }
}

#[test]
fn oasis_inventory_tracks_mechanism_info_flag_semantic_gaps() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };
    let summary = &inventory["mechanism_info_flag_coverage_summary"];

    assert!(
        summary["represented_expected_flag_count"].as_u64().expect("count should be u64") > 300
    );
    assert!(summary["source_grounded_count"].as_u64().expect("count should be u64") > 0);
    assert_eq!(summary["not_yet_source_grounded_count"].as_u64().expect("count should be u64"), 0);

    let ml_kem = mechanism_info_flag_coverage_entry(&inventory, "CKM_ML_KEM");
    assert_eq!(ml_kem["status"], "source_grounded");
    for flag in ["CKF_ENCAPSULATE", "CKF_DECAPSULATE"] {
        assert!(
            ml_kem["expected_flag_names"]
                .as_array()
                .expect("expected_flag_names should be an array")
                .iter()
                .any(|candidate| candidate == flag),
            "CKM_ML_KEM should expect {flag}"
        );
    }
    assert!(
        ml_kem["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|candidate| candidate == "mock_mechanism_info_uses_source_grounded_workflow_flags")
    );

    let acti = mechanism_info_flag_coverage_entry(&inventory, "CKM_ACTI");
    assert_eq!(acti["status"], "source_grounded");
    for flag in ["CKF_SIGN", "CKF_VERIFY"] {
        assert!(
            acti["expected_flag_names"]
                .as_array()
                .expect("expected_flag_names should be an array")
                .iter()
                .any(|candidate| candidate == flag),
            "CKM_ACTI should expect {flag}"
        );
    }
    assert!(
        acti["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|candidate| candidate == "mock_mechanism_info_uses_source_grounded_workflow_flags")
    );

    let acti_key_gen = mechanism_info_flag_coverage_entry(&inventory, "CKM_ACTI_KEY_GEN");
    assert_eq!(acti_key_gen["status"], "source_grounded");
    assert!(
        acti_key_gen["expected_flag_names"]
            .as_array()
            .expect("expected_flag_names should be an array")
            .iter()
            .any(|candidate| candidate == "CKF_GENERATE"),
        "CKM_ACTI_KEY_GEN should expect CKF_GENERATE"
    );
    assert!(
        acti_key_gen["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|candidate| candidate == "mock_mechanism_info_uses_source_grounded_workflow_flags")
    );

    let hash_family_cases: &[(&str, &[&str])] = &[
        ("CKM_BLAKE2B_160", &["CKF_DIGEST"]),
        ("CKM_BLAKE2B_160_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_BLAKE2B_160_HMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_BLAKE2B_160_KEY_DERIVE", &["CKF_DERIVE"]),
        ("CKM_BLAKE2B_160_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_BLAKE2B_256", &["CKF_DIGEST"]),
        ("CKM_BLAKE2B_256_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_BLAKE2B_256_HMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_BLAKE2B_256_KEY_DERIVE", &["CKF_DERIVE"]),
        ("CKM_BLAKE2B_256_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_BLAKE2B_384", &["CKF_DIGEST"]),
        ("CKM_BLAKE2B_384_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_BLAKE2B_384_HMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_BLAKE2B_384_KEY_DERIVE", &["CKF_DERIVE"]),
        ("CKM_BLAKE2B_384_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_BLAKE2B_512", &["CKF_DIGEST"]),
        ("CKM_BLAKE2B_512_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_BLAKE2B_512_HMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_BLAKE2B_512_KEY_DERIVE", &["CKF_DERIVE"]),
        ("CKM_BLAKE2B_512_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_RSA_X9_31_KEY_PAIR_GEN", &["CKF_GENERATE_KEY_PAIR"]),
        ("CKM_RSA_9796", &["CKF_SIGN", "CKF_VERIFY", "CKF_SIGN_RECOVER", "CKF_VERIFY_RECOVER"]),
        (
            "CKM_RSA_X_509",
            &[
                "CKF_ENCRYPT",
                "CKF_DECRYPT",
                "CKF_SIGN",
                "CKF_VERIFY",
                "CKF_SIGN_RECOVER",
                "CKF_VERIFY_RECOVER",
                "CKF_WRAP",
                "CKF_UNWRAP",
                "CKF_ENCAPSULATE",
                "CKF_DECAPSULATE",
            ],
        ),
        ("CKM_RSA_X9_31", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_RSA_PKCS_TPM_1_1", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_RSA_PKCS_OAEP_TPM_1_1", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_RSA_AES_KEY_WRAP", &["CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_CMS_SIG", &["CKF_SIGN", "CKF_VERIFY", "CKF_SIGN_RECOVER", "CKF_VERIFY_RECOVER"]),
        ("CKM_PBE_SHA1_DES3_EDE_CBC", &["CKF_GENERATE"]),
        ("CKM_PBE_SHA1_DES2_EDE_CBC", &["CKF_GENERATE"]),
        ("CKM_PKCS5_PBKD2", &["CKF_GENERATE"]),
        ("CKM_PBA_SHA1_WITH_SHA1_HMAC", &["CKF_GENERATE"]),
        (
            "CKM_NULL",
            &[
                "CKF_ENCRYPT",
                "CKF_DECRYPT",
                "CKF_SIGN",
                "CKF_VERIFY",
                "CKF_SIGN_RECOVER",
                "CKF_VERIFY_RECOVER",
                "CKF_DIGEST",
                "CKF_WRAP",
                "CKF_UNWRAP",
                "CKF_DERIVE",
            ],
        ),
        ("CKM_RSA_PKCS_PSS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_MD2_RSA_PKCS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_MD5_RSA_PKCS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_RIPEMD128_RSA_PKCS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_RIPEMD160_RSA_PKCS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA1_RSA_PKCS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA1_RSA_PKCS_PSS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA1_RSA_X9_31", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA224_RSA_PKCS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA224_RSA_PKCS_PSS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA256_RSA_PKCS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA256_RSA_PKCS_PSS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA384_RSA_PKCS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA384_RSA_PKCS_PSS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA512_RSA_PKCS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA512_RSA_PKCS_PSS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA3_224_RSA_PKCS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA3_224_RSA_PKCS_PSS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA3_256_RSA_PKCS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA3_256_RSA_PKCS_PSS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA3_384_RSA_PKCS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA3_384_RSA_PKCS_PSS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA3_512_RSA_PKCS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA3_512_RSA_PKCS_PSS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_DSA_KEY_PAIR_GEN", &["CKF_GENERATE_KEY_PAIR"]),
        ("CKM_DSA_PARAMETER_GEN", &["CKF_GENERATE", "CKF_GENERATE_KEY_PAIR"]),
        ("CKM_DSA_PROBABILISTIC_PARAMETER_GEN", &["CKF_GENERATE", "CKF_GENERATE_KEY_PAIR"]),
        ("CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN", &["CKF_GENERATE", "CKF_GENERATE_KEY_PAIR"]),
        ("CKM_DSA_FIPS_G_GEN", &["CKF_GENERATE", "CKF_GENERATE_KEY_PAIR"]),
        ("CKM_DSA", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_DSA_SHA1", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_DSA_SHA224", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_DSA_SHA256", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_DSA_SHA384", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_DSA_SHA512", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_DSA_SHA3_224", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_DSA_SHA3_256", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_DSA_SHA3_384", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_DSA_SHA3_512", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_ML_DSA_KEY_PAIR_GEN", &["CKF_GENERATE_KEY_PAIR"]),
        ("CKM_ML_DSA", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_ML_DSA", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_ML_DSA_SHA224", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_ML_DSA_SHA256", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_ML_DSA_SHA384", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_ML_DSA_SHA512", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_ML_DSA_SHA3_224", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_ML_DSA_SHA3_256", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_ML_DSA_SHA3_384", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_ML_DSA_SHA3_512", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_ML_DSA_SHAKE128", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_ML_DSA_SHAKE256", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SLH_DSA_KEY_PAIR_GEN", &["CKF_GENERATE_KEY_PAIR"]),
        ("CKM_SLH_DSA", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_SLH_DSA", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_SLH_DSA_SHA224", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_SLH_DSA_SHA256", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_SLH_DSA_SHA384", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_SLH_DSA_SHA512", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_SLH_DSA_SHA3_224", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_SLH_DSA_SHA3_256", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_SLH_DSA_SHA3_384", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_SLH_DSA_SHA3_512", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_SLH_DSA_SHAKE128", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HASH_SLH_DSA_SHAKE256", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_MD2", &["CKF_DIGEST"]),
        ("CKM_MD5", &["CKF_DIGEST"]),
        ("CKM_SHA_1", &["CKF_DIGEST"]),
        ("CKM_SHA_1_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA_1_HMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA_1_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_SHA1_KEY_DERIVATION", &["CKF_DERIVE"]),
        ("CKM_SHA224", &["CKF_DIGEST"]),
        ("CKM_SHA224_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA224_HMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA224_KEY_DERIVATION", &["CKF_DERIVE"]),
        ("CKM_SHA224_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_SHA256", &["CKF_DIGEST"]),
        ("CKM_SHA256_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA256_HMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA256_KEY_DERIVATION", &["CKF_DERIVE"]),
        ("CKM_SHA256_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_SHA384", &["CKF_DIGEST"]),
        ("CKM_SHA384_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA384_HMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA384_KEY_DERIVATION", &["CKF_DERIVE"]),
        ("CKM_SHA384_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_SHA512", &["CKF_DIGEST"]),
        ("CKM_SHA512_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA512_HMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA512_KEY_DERIVATION", &["CKF_DERIVE"]),
        ("CKM_SHA512_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_SHA512_224", &["CKF_DIGEST"]),
        ("CKM_SHA512_224_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA512_224_HMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA512_224_KEY_DERIVATION", &["CKF_DERIVE"]),
        ("CKM_SHA512_224_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_SHA512_256", &["CKF_DIGEST"]),
        ("CKM_SHA512_256_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA512_256_HMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA512_256_KEY_DERIVATION", &["CKF_DERIVE"]),
        ("CKM_SHA512_256_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_SHA512_T", &["CKF_DIGEST"]),
        ("CKM_SHA512_T_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA512_T_HMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA512_T_KEY_DERIVATION", &["CKF_DERIVE"]),
        ("CKM_SHA512_T_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_SHA3_224", &["CKF_DIGEST"]),
        ("CKM_SHA3_224_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA3_224_HMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA3_224_KEY_DERIVATION", &["CKF_DERIVE"]),
        ("CKM_SHA3_224_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_SHA3_256", &["CKF_DIGEST"]),
        ("CKM_SHA3_256_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA3_256_HMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA3_256_KEY_DERIVATION", &["CKF_DERIVE"]),
        ("CKM_SHA3_256_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_SHA3_384", &["CKF_DIGEST"]),
        ("CKM_SHA3_384_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA3_384_HMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA3_384_KEY_DERIVATION", &["CKF_DERIVE"]),
        ("CKM_SHA3_384_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_SHA3_512", &["CKF_DIGEST"]),
        ("CKM_SHA3_512_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA3_512_HMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SHA3_512_KEY_DERIVATION", &["CKF_DERIVE"]),
        ("CKM_SHA3_512_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_AES_CBC", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_AES_CBC_PAD", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_AES_CTR", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_AES_CTS", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_AES_XTS", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_AES_OFB", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_AES_CFB64", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_AES_CFB8", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_AES_CFB128", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_AES_CFB1", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        (
            "CKM_AES_CCM",
            &[
                "CKF_ENCRYPT",
                "CKF_DECRYPT",
                "CKF_WRAP",
                "CKF_UNWRAP",
                "CKF_MESSAGE_ENCRYPT",
                "CKF_MESSAGE_DECRYPT",
            ],
        ),
        ("CKM_AES_KEY_WRAP", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_AES_KEY_WRAP_PAD", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_AES_KEY_WRAP_KWP", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_AES_KEY_WRAP_PKCS7", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_AES_MAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_AES_MAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_AES_CMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_AES_CMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_AES_XCBC_MAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_AES_XCBC_MAC_96", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_AES_GMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_AES_XTS_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_AES_ECB_ENCRYPT_DATA", &["CKF_DERIVE"]),
        ("CKM_AES_CBC_ENCRYPT_DATA", &["CKF_DERIVE"]),
        ("CKM_CHACHA20", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_CHACHA20_KEY_GEN", &["CKF_GENERATE"]),
        (
            "CKM_CHACHA20_POLY1305",
            &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_MESSAGE_ENCRYPT", "CKF_MESSAGE_DECRYPT"],
        ),
        ("CKM_SALSA20", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_SALSA20_KEY_GEN", &["CKF_GENERATE"]),
        (
            "CKM_SALSA20_POLY1305",
            &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_MESSAGE_ENCRYPT", "CKF_MESSAGE_DECRYPT"],
        ),
        ("CKM_POLY1305", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_POLY1305_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_ARIA_ECB", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_ARIA_CBC", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_ARIA_CBC_PAD", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_ARIA_MAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_ARIA_MAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_ARIA_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_ARIA_ECB_ENCRYPT_DATA", &["CKF_DERIVE"]),
        ("CKM_ARIA_CBC_ENCRYPT_DATA", &["CKF_DERIVE"]),
        ("CKM_CAMELLIA_ECB", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_CAMELLIA_CBC", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_CAMELLIA_CBC_PAD", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_CAMELLIA_MAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_CAMELLIA_MAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_CAMELLIA_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_CAMELLIA_ECB_ENCRYPT_DATA", &["CKF_DERIVE"]),
        ("CKM_CAMELLIA_CBC_ENCRYPT_DATA", &["CKF_DERIVE"]),
        ("CKM_SEED_ECB", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_SEED_CBC", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_SEED_CBC_PAD", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_SEED_MAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SEED_MAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SEED_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_SEED_ECB_ENCRYPT_DATA", &["CKF_DERIVE"]),
        ("CKM_SEED_CBC_ENCRYPT_DATA", &["CKF_DERIVE"]),
        ("CKM_DES2_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_DES3_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_DES_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_DES_ECB", &["CKF_ENCRYPT", "CKF_DECRYPT"]),
        ("CKM_DES_CBC_PAD", &["CKF_ENCRYPT", "CKF_DECRYPT"]),
        ("CKM_DES_MAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_DES3_ECB", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_DES3_CBC", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_DES3_CBC_PAD", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_DES3_MAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_DES3_MAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_DES3_CMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_DES3_CMAC_GENERAL", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_DES_OFB64", &["CKF_ENCRYPT", "CKF_DECRYPT"]),
        ("CKM_DES_OFB8", &["CKF_ENCRYPT", "CKF_DECRYPT"]),
        ("CKM_DES_CFB64", &["CKF_ENCRYPT", "CKF_DECRYPT"]),
        ("CKM_DES_CFB8", &["CKF_ENCRYPT", "CKF_DECRYPT"]),
        ("CKM_DES_ECB_ENCRYPT_DATA", &["CKF_DERIVE"]),
        ("CKM_DES_CBC_ENCRYPT_DATA", &["CKF_DERIVE"]),
        ("CKM_DES3_ECB_ENCRYPT_DATA", &["CKF_DERIVE"]),
        ("CKM_DES3_CBC_ENCRYPT_DATA", &["CKF_DERIVE"]),
        ("CKM_EC_KEY_PAIR_GEN", &["CKF_GENERATE_KEY_PAIR"]),
        ("CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS", &["CKF_GENERATE", "CKF_GENERATE_KEY_PAIR"]),
        ("CKM_EC_EDWARDS_KEY_PAIR_GEN", &["CKF_GENERATE_KEY_PAIR"]),
        ("CKM_EC_MONTGOMERY_KEY_PAIR_GEN", &["CKF_GENERATE_KEY_PAIR"]),
        ("CKM_ECDSA", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_ECDSA_SHA1", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_ECDSA_SHA224", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_ECDSA_SHA256", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_ECDSA_SHA384", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_ECDSA_SHA512", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_ECDSA_SHA3_224", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_ECDSA_SHA3_256", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_ECDSA_SHA3_384", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_ECDSA_SHA3_512", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_EDDSA", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_XEDDSA", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_ECDH1_DERIVE", &["CKF_DERIVE", "CKF_ENCAPSULATE", "CKF_DECAPSULATE"]),
        ("CKM_ECDH1_COFACTOR_DERIVE", &["CKF_DERIVE", "CKF_ENCAPSULATE", "CKF_DECAPSULATE"]),
        ("CKM_ECMQV_DERIVE", &["CKF_DERIVE"]),
        ("CKM_ECDH_AES_KEY_WRAP", &["CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_ECDH_COF_AES_KEY_WRAP", &["CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_ECDH_X_AES_KEY_WRAP", &["CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_DH_PKCS_KEY_PAIR_GEN", &["CKF_GENERATE_KEY_PAIR"]),
        ("CKM_DH_PKCS_PARAMETER_GEN", &["CKF_GENERATE", "CKF_GENERATE_KEY_PAIR"]),
        ("CKM_DH_PKCS_DERIVE", &["CKF_DERIVE", "CKF_ENCAPSULATE", "CKF_DECAPSULATE"]),
        ("CKM_X9_42_DH_KEY_PAIR_GEN", &["CKF_GENERATE_KEY_PAIR"]),
        ("CKM_X9_42_DH_PARAMETER_GEN", &["CKF_GENERATE", "CKF_GENERATE_KEY_PAIR"]),
        ("CKM_X9_42_DH_DERIVE", &["CKF_DERIVE", "CKF_ENCAPSULATE", "CKF_DECAPSULATE"]),
        ("CKM_X9_42_DH_HYBRID_DERIVE", &["CKF_DERIVE"]),
        ("CKM_X9_42_MQV_DERIVE", &["CKF_DERIVE"]),
        ("CKM_GOST28147_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_GOST28147_ECB", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_GOST28147", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_GOST28147_MAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_GOST28147_KEY_WRAP", &["CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_GOSTR3410_KEY_PAIR_GEN", &["CKF_GENERATE_KEY_PAIR"]),
        ("CKM_GOSTR3410", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_GOSTR3410_WITH_GOSTR3411", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_GOSTR3410_KEY_WRAP", &["CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_GOSTR3410_DERIVE", &["CKF_DERIVE"]),
        ("CKM_GOSTR3411", &["CKF_DIGEST"]),
        ("CKM_GOSTR3411_HMAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_X3DH_INITIALIZE", &["CKF_DERIVE"]),
        ("CKM_X3DH_RESPOND", &["CKF_DERIVE"]),
        ("CKM_X2RATCHET_INITIALIZE", &["CKF_DERIVE"]),
        ("CKM_X2RATCHET_RESPOND", &["CKF_DERIVE"]),
        ("CKM_X2RATCHET_ENCRYPT", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_X2RATCHET_DECRYPT", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_BLOWFISH_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_BLOWFISH_CBC", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_BLOWFISH_CBC_PAD", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_TWOFISH_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_TWOFISH_CBC", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_TWOFISH_CBC_PAD", &["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_GENERIC_SECRET_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_CONCATENATE_BASE_AND_KEY", &["CKF_DERIVE"]),
        ("CKM_CONCATENATE_BASE_AND_DATA", &["CKF_DERIVE"]),
        ("CKM_CONCATENATE_DATA_AND_BASE", &["CKF_DERIVE"]),
        ("CKM_XOR_BASE_AND_DATA", &["CKF_DERIVE"]),
        ("CKM_EXTRACT_KEY_FROM_KEY", &["CKF_DERIVE"]),
        ("CKM_PUB_KEY_FROM_PRIV_KEY", &["CKF_DERIVE"]),
        ("CKM_HKDF_DERIVE", &["CKF_DERIVE"]),
        ("CKM_HKDF_DATA", &["CKF_DERIVE"]),
        ("CKM_HKDF_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_KIP_DERIVE", &["CKF_DERIVE"]),
        ("CKM_KIP_WRAP", &["CKF_WRAP", "CKF_UNWRAP"]),
        ("CKM_KIP_MAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_IKE2_PRF_PLUS_DERIVE", &["CKF_DERIVE"]),
        ("CKM_IKE_PRF_DERIVE", &["CKF_DERIVE"]),
        ("CKM_IKE1_PRF_DERIVE", &["CKF_DERIVE"]),
        ("CKM_IKE1_EXTENDED_DERIVE", &["CKF_DERIVE"]),
        ("CKM_SHAKE_128_KEY_DERIVATION", &["CKF_DERIVE"]),
        ("CKM_SHAKE_256_KEY_DERIVATION", &["CKF_DERIVE"]),
        ("CKM_HSS_KEY_PAIR_GEN", &["CKF_GENERATE_KEY_PAIR"]),
        ("CKM_HSS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_XMSS_KEY_PAIR_GEN", &["CKF_GENERATE_KEY_PAIR"]),
        ("CKM_XMSSMT_KEY_PAIR_GEN", &["CKF_GENERATE_KEY_PAIR"]),
        ("CKM_XMSS", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_XMSSMT", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SSL3_PRE_MASTER_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_SSL3_MASTER_KEY_DERIVE", &["CKF_DERIVE"]),
        ("CKM_SSL3_MASTER_KEY_DERIVE_DH", &["CKF_DERIVE"]),
        ("CKM_SSL3_KEY_AND_MAC_DERIVE", &["CKF_DERIVE"]),
        ("CKM_SSL3_MD5_MAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SSL3_SHA1_MAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_TLS_PRE_MASTER_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE", &["CKF_DERIVE"]),
        ("CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH", &["CKF_DERIVE"]),
        ("CKM_TLS12_MASTER_KEY_DERIVE", &["CKF_DERIVE"]),
        ("CKM_TLS12_MASTER_KEY_DERIVE_DH", &["CKF_DERIVE"]),
        ("CKM_TLS12_KEY_AND_MAC_DERIVE", &["CKF_DERIVE"]),
        ("CKM_TLS12_KEY_SAFE_DERIVE", &["CKF_DERIVE"]),
        ("CKM_TLS_PRF", &["CKF_DERIVE"]),
        ("CKM_TLS_KDF", &["CKF_DERIVE"]),
        ("CKM_TLS12_KDF", &["CKF_DERIVE"]),
        ("CKM_TLS_MAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_TLS12_MAC", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_WTLS_PRE_MASTER_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_WTLS_MASTER_KEY_DERIVE", &["CKF_DERIVE"]),
        ("CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC", &["CKF_DERIVE"]),
        ("CKM_WTLS_PRF", &["CKF_DERIVE"]),
        ("CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE", &["CKF_DERIVE"]),
        ("CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE", &["CKF_DERIVE"]),
        ("CKM_SECURID_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_SECURID", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HOTP_KEY_GEN", &["CKF_GENERATE"]),
        ("CKM_HOTP", &["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_SP800_108_COUNTER_KDF", &["CKF_DERIVE"]),
        ("CKM_SP800_108_FEEDBACK_KDF", &["CKF_DERIVE"]),
        ("CKM_SP800_108_DOUBLE_PIPELINE_KDF", &["CKF_DERIVE"]),
    ];
    for (name, expected_flags) in hash_family_cases.iter().copied() {
        let entry = mechanism_info_flag_coverage_entry(&inventory, name);
        assert_eq!(entry["status"], "source_grounded");
        for flag in expected_flags {
            assert!(
                entry["expected_flag_names"]
                    .as_array()
                    .expect("expected_flag_names should be an array")
                    .iter()
                    .any(|candidate| candidate == flag),
                "{name} should expect {flag}"
            );
        }
        assert!(
            entry["local_tests"]
                .as_array()
                .expect("local_tests should be an array")
                .iter()
                .any(|candidate| candidate
                    == "mock_mechanism_info_uses_source_grounded_workflow_flags"),
            "{name} should cite mechanism-info source-grounding test"
        );
    }

    let poly1305 = mechanism_info_flag_coverage_entry(&inventory, "CKM_POLY1305");
    for flag in ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"] {
        assert!(
            !poly1305["expected_flag_names"]
                .as_array()
                .expect("expected_flag_names should be an array")
                .iter()
                .any(|candidate| candidate == flag),
            "CKM_POLY1305 should not inherit the conflicting ENC/WRP table flag {flag}"
        );
    }

    let poly1305_matrix = mechanism_matrix_entry(&inventory, "CKM_POLY1305");
    assert_eq!(
        poly1305_matrix["source_discrepancy_reason"],
        "working_poly1305_mechanism_table_conflicts_with_mac_prose"
    );

    for name in [
        "CKM_PBE_SHA1_DES3_EDE_CBC",
        "CKM_PBE_SHA1_DES2_EDE_CBC",
        "CKM_PKCS5_PBKD2",
        "CKM_PBA_SHA1_WITH_SHA1_HMAC",
    ] {
        let entry = mechanism_info_flag_coverage_entry(&inventory, name);
        assert!(
            !entry["expected_flag_names"]
                .as_array()
                .expect("expected_flag_names should be an array")
                .iter()
                .any(|candidate| candidate == "CKF_GENERATE_KEY_PAIR"),
            "{name} should not infer key-pair generation from the combined PBE GENK/GENKP column"
        );
    }

    let working_spec_only = mechanism_info_flag_coverage_entry(&inventory, "CKM_KMAC128");
    assert_eq!(working_spec_only["status"], "no_published_ck_mechanism_type_value");

    let no_source = mechanism_info_flag_coverage_entry(&inventory, "CKM_BATON_KEY_GEN");
    assert_eq!(no_source["status"], "no_source_workflow_evidence");
    assert_eq!(no_source["expected_flag_names"].as_array().unwrap().len(), 0);
    assert_eq!(
        no_source["source_gap_kind"],
        "published_header_only_no_working_markdown_workflow_source"
    );
    assert_eq!(
        no_source["source_gap_decision"]["policy"],
        "do_not_infer_ckf_flags_from_mechanism_name_or_header_presence"
    );
    assert_eq!(
        no_source["source_gap_decision"]["reason"],
        "published_header_mechanism_absent_from_working_markdown"
    );
    assert!(
        no_source["source_gap_decision"]["evidence"]
            .as_array()
            .expect("source gap evidence should be an array")
            .iter()
            .any(|source| source
                .as_str()
                .expect("source should be a string")
                .contains("published")),
        "header-only no-source rows should cite published header evidence"
    );
    assert!(
        no_source["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|candidate| candidate
                == "mock_mechanism_info_leaves_flags_empty_without_source_workflow_evidence"),
        "no-source mechanism-info rows should cite the zero-flag policy test"
    );
    assert!(
        no_source["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|candidate| candidate
                == "grpc_mechanism_info_preserves_zero_flags_without_source_workflow_evidence"),
        "no-source mechanism-info rows should cite the gRPC zero-flag test"
    );
    assert!(
        no_source["local_tests"].as_array().expect("local_tests should be an array").iter().any(
            |candidate| {
                candidate == "loaded_shim_preserves_no_source_mechanism_info_zero_flags"
            }
        ),
        "no-source mechanism-info rows should cite the loaded-shim C ABI zero-flag test"
    );
    assert!(
        no_source["local_tests"].as_array().expect("local_tests should be an array").iter().any(
            |candidate| {
                candidate
                    == "official_source_grounded_mock_rejects_all_no_source_workflow_mechanisms"
            }
        ),
        "no-source mechanism-info rows should cite the exhaustive MockBackend rejection test"
    );

    let camellia_ctr = mechanism_info_flag_coverage_entry(&inventory, "CKM_CAMELLIA_CTR");
    assert_eq!(camellia_ctr["status"], "no_source_workflow_evidence");
    assert_eq!(
        camellia_ctr["source_gap_kind"],
        "working_markdown_mentions_mechanism_without_workflow_flags"
    );
    assert_eq!(
        camellia_ctr["source_gap_decision"]["reason"],
        "working_markdown_mentions_mechanism_but_no_source_workflow_flags"
    );
    assert!(
        camellia_ctr["source_gap_decision"]["evidence"]
            .as_array()
            .expect("source gap evidence should be an array")
            .iter()
            .any(|source| source == "camellia.md"),
        "working-spec no-source rows should cite the Markdown source that mentioned the mechanism"
    );

    for entry in inventory["mechanism_info_flag_coverage_matrix"]
        .as_array()
        .expect("mechanism_info_flag_coverage_matrix should be an array")
    {
        assert!(
            entry["local_tests_missing"]
                .as_array()
                .expect("local_tests_missing should be an array")
                .is_empty(),
            "{} should not cite stale mechanism-info flag tests",
            entry["name"]
        );
    }
}

#[test]
fn oasis_inventory_separates_provider_gap_from_mockbackend_internal_coverage() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    let provider_gap = mechanism_matrix_entry(&inventory, "CKM_ACTI");
    assert_eq!(provider_gap["provider_artifact_present"], false);
    assert_eq!(provider_gap["provider_gap"], true);
    let mock_coverage = &provider_gap["mock_backend_internal_coverage"];
    assert_eq!(mock_coverage["advertised_by_official_constructor"], true);
    assert_eq!(
        mock_coverage["advertisement_test"],
        "official_mechanism_mock_advertises_provider_gap_mechanisms"
    );
    assert_eq!(
        mock_coverage["core_workflow_test"],
        "official_mechanism_mock_accepts_every_official_mechanism_across_core_workflows"
    );
    assert_eq!(
        mock_coverage["exact_output_workflow_test"],
        "official_mechanism_mock_accepts_every_official_mechanism_across_exact_output_workflows"
    );
    assert!(
        mock_coverage["local_tests"]
            .as_array()
            .expect("MockBackend coverage local_tests should be an array")
            .iter()
            .any(|candidate| {
                candidate == "mechanism_bearing_workflows_reject_unadvertised_mechanisms"
            }),
        "internal MockBackend coverage should cite negative mechanism catalog semantics"
    );
    assert!(
        mock_coverage["local_tests"]
            .as_array()
            .expect("MockBackend coverage local_tests should be an array")
            .iter()
            .any(|candidate| {
                candidate == "mock_mechanism_info_uses_source_grounded_workflow_flags"
            }),
        "internal MockBackend coverage should cite source-grounded mechanism info flags"
    );
    assert!(
        mock_coverage["local_tests_missing"]
            .as_array()
            .expect("MockBackend coverage should report stale test citations")
            .is_empty(),
        "MockBackend coverage citations should resolve to local tests"
    );
    for workflow in [
        "sign",
        "sign_recover",
        "sign_update_final",
        "verify",
        "verify_recover",
        "verify_update_final",
        "digest",
        "digest_update_final",
        "encrypt",
        "encrypt_update_final",
        "decrypt",
        "decrypt_update_final",
        "derive",
        "generate_key",
        "generate_key_pair",
        "wrap",
        "unwrap",
        "authenticated_wrap_unwrap",
        "kem_encapsulate_decapsulate",
        "message_encrypt_decrypt",
        "message_sign_verify",
        "verify_signature",
        "async_complete",
    ] {
        assert!(
            mock_coverage["core_workflows"]
                .as_array()
                .expect("core_workflows should be an array")
                .iter()
                .any(|candidate| candidate == workflow),
            "internal MockBackend coverage should list {workflow}"
        );
    }
    for workflow in [
        "sign_exact",
        "sign_final_exact",
        "sign_recover_exact",
        "verify_recover_exact",
        "digest_exact",
        "digest_final_exact",
        "encrypt_exact",
        "encrypt_update_exact",
        "encrypt_final_exact",
        "decrypt_exact",
        "decrypt_update_exact",
        "decrypt_final_exact",
        "combined_update_exact",
        "wrap_key_exact",
        "get_operation_state_exact",
        "encapsulate_key_exact",
        "parameter_output_exact",
        "parameter_output_next_exact",
        "authenticated_wrap_exact",
    ] {
        assert!(
            mock_coverage["exact_output_workflows"]
                .as_array()
                .expect("exact_output_workflows should be an array")
                .iter()
                .any(|candidate| candidate == workflow),
            "internal MockBackend exact-output coverage should list {workflow}"
        );
    }

    let working_spec_only = mechanism_matrix_entry(&inventory, "CKM_KMAC128");
    assert_eq!(working_spec_only["provider_gap"], false);
    assert_eq!(
        working_spec_only["unsupported_reason"],
        "oasis_working_spec_lacks_published_numeric_value"
    );
    let working_mock_coverage = &working_spec_only["mock_backend_internal_coverage"];
    assert_eq!(working_mock_coverage["advertised_by_official_constructor"], false);
    assert_eq!(working_mock_coverage["core_workflows"].as_array().unwrap().len(), 0);
    assert_eq!(working_mock_coverage["limitation"], "no_published_ck_mechanism_type_value");
    assert!(
        working_mock_coverage["local_tests_missing"]
            .as_array()
            .expect("spec-only MockBackend coverage should report stale test citations")
            .is_empty()
    );
}

#[test]
fn oasis_inventory_distinguishes_mockbackend_smoke_from_source_grounded_semantics() {
    let root = workspace_root();
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };

    let no_source = mechanism_matrix_entry(&inventory, "CKM_BATON_KEY_GEN");
    let no_source_mock_coverage = &no_source["mock_backend_internal_coverage"];
    assert_eq!(no_source_mock_coverage["workflow_semantics_status"], "no_source_workflow_evidence");
    assert_eq!(
        no_source_mock_coverage["semantic_limitation"],
        "no_source_workflow_flags_available"
    );
    assert_eq!(
        no_source_mock_coverage["source_grounded_workflow_enforcement_test"],
        "official_source_grounded_mock_enforces_mechanism_workflow_flags"
    );
    assert!(
        no_source_mock_coverage["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|candidate| candidate
                == "official_source_grounded_mock_rejects_all_no_source_workflow_mechanisms"),
        "no-source MockBackend coverage should cite exhaustive source-grounded rejection coverage"
    );
    assert!(
        no_source_mock_coverage["catalog_smoke_workflows"]
            .as_array()
            .expect("catalog_smoke_workflows should be an array")
            .iter()
            .any(|candidate| candidate == "generate_key"),
        "official catalog smoke should still exercise header-only mechanisms generically"
    );
    assert!(
        no_source_mock_coverage["source_grounded_workflows"]
            .as_array()
            .expect("source_grounded_workflows should be an array")
            .is_empty(),
        "header-only mechanisms without workflow evidence must not be counted as semantic workflow coverage"
    );

    let source_grounded = mechanism_matrix_entry(&inventory, "CKM_AES_GCM");
    let source_grounded_mock_coverage = &source_grounded["mock_backend_internal_coverage"];
    assert_eq!(source_grounded_mock_coverage["workflow_semantics_status"], "source_grounded");
    assert_eq!(source_grounded_mock_coverage["semantic_limitation"], Value::Null);
    assert_eq!(
        source_grounded_mock_coverage["catalog_smoke_constructor"],
        "MockBackend::with_official_mechanism_catalog_smoke"
    );
    assert_eq!(
        source_grounded_mock_coverage["semantic_constructor"],
        "MockBackend::with_official_mechanisms"
    );
    assert_eq!(
        source_grounded_mock_coverage["source_grounded_workflow_enforcement_test"],
        "official_source_grounded_mock_enforces_mechanism_workflow_flags"
    );
    assert!(
        source_grounded_mock_coverage["local_tests"]
            .as_array()
            .expect("local_tests should be an array")
            .iter()
            .any(|candidate| candidate
                == "official_source_grounded_mock_enforces_mechanism_workflow_flags"),
        "semantic MockBackend coverage should cite the workflow enforcement test"
    );
    for workflow in ["encrypt_decrypt", "wrap_unwrap"] {
        assert!(
            source_grounded_mock_coverage["source_grounded_workflows"]
                .as_array()
                .expect("source_grounded_workflows should be an array")
                .iter()
                .any(|candidate| candidate == workflow),
            "source-grounded MockBackend coverage should list {workflow}"
        );
    }
    assert!(
        source_grounded_mock_coverage["source_grounded_workflows"]
            .as_array()
            .expect("source_grounded_workflows should be an array")
            .iter()
            .any(|candidate| candidate == "message_encrypt_decrypt"),
        "explicit source-grounded message-operation flags should be reflected as semantic workflow coverage"
    );
}

#[test]
fn oasis_inventory_markdown_exposes_human_readable_matrices() {
    let root = workspace_root();
    if skip_oasis_inventory_if_unavailable(
        &root,
        "oasis_inventory_markdown_exposes_human_readable_matrices",
    ) {
        return;
    }

    let output = Command::new("python3")
        .arg(root.join("scripts/oasis-coverage-inventory.py"))
        .arg("--format")
        .arg("markdown")
        .current_dir(&root)
        .output()
        .expect("oasis coverage inventory script should run");
    assert!(
        output.status.success(),
        "oasis coverage inventory script failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let markdown = String::from_utf8(output.stdout).expect("inventory Markdown should be UTF-8");
    let Some(inventory) = oasis_inventory_json(&root) else {
        return;
    };
    let provider_summary = &inventory["provider_mechanism_summary"];
    let official_mechanism_value_count = provider_summary["official_mechanism_value_count"]
        .as_u64()
        .expect("provider_mechanism_summary.official_mechanism_value_count should be a u64");
    let official_mechanism_name_count = provider_summary["official_mechanism_name_count"]
        .as_u64()
        .expect("provider_mechanism_summary.official_mechanism_name_count should be a u64");
    let provider_present_count = provider_summary["provider_artifact_present_count"]
        .as_u64()
        .expect("provider_mechanism_summary.provider_artifact_present_count should be a u64");
    let provider_gap_count = provider_summary["provider_gap_count"]
        .as_u64()
        .expect("provider_mechanism_summary.provider_gap_count should be a u64");
    let mechanism_rows =
        inventory["mechanism_matrix"].as_array().expect("mechanism_matrix should be an array");
    assert_eq!(
        official_mechanism_value_count,
        inventory["official_mechanism_inventory_count"]
            .as_u64()
            .expect("official_mechanism_inventory_count should be a u64")
    );
    assert_eq!(
        official_mechanism_name_count,
        mechanism_rows.iter().filter(|entry| entry["official_inventory_present"] == true).count()
            as u64
    );
    assert_eq!(
        provider_present_count,
        mechanism_rows.iter().filter(|entry| entry["provider_artifact_present"] == true).count()
            as u64
    );
    assert_eq!(
        provider_gap_count,
        mechanism_rows.iter().filter(|entry| entry["provider_gap"] == true).count() as u64
    );
    assert!(
        provider_gap_count > 0,
        "current pkcs11-check artifacts should leave some official mechanisms uncovered by providers"
    );
    let flag_summary = &inventory["mechanism_info_flag_coverage_summary"];
    let no_source_workflow_count = flag_summary["no_source_workflow_evidence_count"]
        .as_u64()
        .expect("no_source_workflow_evidence_count should be a u64");
    let no_published_value_count = flag_summary["no_published_ck_mechanism_type_value_count"]
        .as_u64()
        .expect("no_published_ck_mechanism_type_value_count should be a u64");
    assert!(
        no_source_workflow_count > 0,
        "inventory should retain at least one published-header mechanism without working-spec workflow evidence"
    );
    assert!(
        no_published_value_count > 0,
        "inventory should retain at least one working-spec mechanism without a published CKM value"
    );
    assert!(markdown.contains(&format!(
        "- No-source workflow evidence mechanisms: {no_source_workflow_count}"
    )));
    assert!(markdown.contains(&format!(
        "- No published CK_MECHANISM_TYPE value mechanisms: {no_published_value_count}"
    )));
    assert!(markdown.contains(&format!(
        "- Official mechanism values from published headers: {official_mechanism_value_count}"
    )));
    assert!(markdown.contains(&format!(
        "- Official mechanism names/aliases in matrix: {official_mechanism_name_count}"
    )));
    assert!(markdown.contains(&format!(
        "- Official mechanism names/aliases with provider artifact coverage: {provider_present_count}"
    )));
    assert!(markdown.contains(&format!(
        "- Official mechanism names/aliases absent from provider artifacts: {provider_gap_count}"
    )));
    let completion_summary = &inventory["completion_gap_summary"];
    let spec_only_function_gap_count = completion_summary["spec_only_function_list_gap_names"]
        .as_array()
        .expect("spec_only_function_list_gap_names should be an array")
        .len();
    let working_spec_without_value_count =
        completion_summary["working_spec_mechanisms_without_published_values"]
            .as_array()
            .expect("working_spec_mechanisms_without_published_values should be an array")
            .len();
    let missing_local_tests = &completion_summary["missing_local_test_citation_counts"];
    assert!(markdown.contains("## Completion Gap Summary"));
    assert!(markdown.contains(&format!(
        "- Spec-only function-list gap functions: {spec_only_function_gap_count}"
    )));
    assert!(markdown.contains(&format!(
        "- Working-spec mechanisms without published CK_MECHANISM_TYPE values: \
         {working_spec_without_value_count}"
    )));
    assert!(markdown.contains(&format!(
        "- Spec parameter structs missing modeled shape: {}",
        completion_summary["spec_parameter_structs_missing_modeled_shape_count"]
            .as_u64()
            .expect("spec_parameter_structs_missing_modeled_shape_count should be a u64")
    )));
    assert!(markdown.contains(&format!(
        "- Source-grounded MockBackend semantic rows covered: {}",
        completion_summary["source_grounded_mockbackend_semantic_covered_count"]
            .as_u64()
            .expect("source_grounded_mockbackend_semantic_covered_count should be a u64")
    )));
    assert!(markdown.contains(&format!(
        "- Actionable MockBackend semantic gaps: {}",
        completion_summary["actionable_mockbackend_semantic_gap_count"]
            .as_u64()
            .expect("actionable_mockbackend_semantic_gap_count should be a u64")
    )));
    assert!(markdown.contains(&format!(
        "- Intentional no-source workflow rejections: {}",
        completion_summary["intentional_no_source_workflow_rejection_count"]
            .as_u64()
            .expect("intentional_no_source_workflow_rejection_count should be a u64")
    )));
    assert!(markdown.contains(&format!(
        "- Intentional unsupported workflow gaps: {}",
        completion_summary["intentional_unsupported_workflow_gap_count"]
            .as_u64()
            .expect("intentional_unsupported_workflow_gap_count should be a u64")
    )));
    assert!(markdown.contains(&format!(
        "- No-published-value mechanism rows: {}",
        completion_summary["no_published_value_mechanism_count"]
            .as_u64()
            .expect("no_published_value_mechanism_count should be a u64")
    )));
    assert!(markdown.contains(&format!(
        "- Intentional unsupported function-list gaps: {}",
        completion_summary["intentional_unsupported_function_list_gap_count"]
            .as_u64()
            .expect("intentional_unsupported_function_list_gap_count should be a u64")
    )));
    assert!(markdown.contains(&format!(
        "- Intentional unsupported numeric-value gaps: {}",
        completion_summary["intentional_unsupported_numeric_value_gap_count"]
            .as_u64()
            .expect("intentional_unsupported_numeric_value_gap_count should be a u64")
    )));
    assert!(markdown.contains(&format!(
        "- Internal completion open items: {}",
        completion_summary["internal_completion_open_item_count"]
            .as_u64()
            .expect("internal_completion_open_item_count should be a u64")
    )));
    assert!(markdown.contains(&format!(
        "- Strict completion open items including provider gaps: {}",
        completion_summary["strict_completion_open_item_count"]
            .as_u64()
            .expect("strict_completion_open_item_count should be a u64")
    )));
    assert!(!markdown.contains("spec_only_function_list_gaps:"));
    assert!(!markdown.contains("working_spec_mechanisms_without_published_values:"));
    assert!(!markdown.contains("intentional_no_source_workflow_rejections:"));
    assert!(markdown.contains("provider_artifact_gaps:"));
    assert!(markdown.contains(&format!(
        "- Local-test citation gaps: function_matrix={}, \
         mechanism_parameter_shape_matrix={}, message_parameter_shape_matrix={}, \
         mechanism_info_flag_coverage_matrix={}, mock_backend_internal_coverage={}",
        missing_local_tests["function_matrix"]
            .as_u64()
            .expect("function_matrix missing count should be a u64"),
        missing_local_tests["mechanism_parameter_shape_matrix"]
            .as_u64()
            .expect("mechanism_parameter_shape_matrix missing count should be a u64"),
        missing_local_tests["message_parameter_shape_matrix"]
            .as_u64()
            .expect("message_parameter_shape_matrix missing count should be a u64"),
        missing_local_tests["mechanism_info_flag_coverage_matrix"]
            .as_u64()
            .expect("mechanism_info_flag_coverage_matrix missing count should be a u64"),
        missing_local_tests["mock_backend_internal_coverage"]
            .as_u64()
            .expect("mock_backend_internal_coverage missing count should be a u64"),
    )));
    assert!(markdown.contains(
        "- No-source workflow gap classes: published_header_only_no_working_markdown_workflow_source:"
    ));
    assert!(markdown.contains("working_markdown_mentions_mechanism_without_workflow_flags:"));
    assert!(markdown.contains("## Function Matrix"));
    assert!(markdown.contains(
        "| C_WrapKeyAuthenticated | represented | yes (3.2) | yes | 3.2 | \
         WrapKeyAuthenticated | wrap_key_authenticated | wrap_key_authenticated | \
         c_wrap_key_authenticated |"
    ));
    assert!(markdown.contains("| C_DigestXofInit | spec_only | no | no | - | - | - | - | - |"));
    assert!(markdown.contains("## Spec-Only Function ABI Decisions"));
    assert!(markdown.contains("| C_DigestXofInit | cryptoki_sys_missing_function_list_field |"));
    assert!(markdown.contains("## Interface Matrix"));
    assert!(markdown.contains("| PKCS 11 | 3.2 | CK_FUNCTION_LIST_3_2 | yes | yes | yes |"));
    assert!(markdown.contains("## Mechanism Parameter Shape Matrix"));
    assert!(markdown.contains("| Gcm | GcmParams | `CK_GCM_PARAMS` | yes | yes | GcmParams |"));
    assert!(markdown.contains(
        "| Sp800108FeedbackKdf | Sp800108FeedbackKdfParams | \
         `CK_SP800_108_FEEDBACK_KDF_PARAMS` | yes | yes | Sp800108FeedbackKdfParams |"
    ));
    assert!(markdown.contains(
        "| Extract | ExtractParams | `CK_EXTRACT_PARAMS` | yes | yes | ExtractParams | \
         extract_params |"
    ));
    assert!(markdown.contains("| Kmac | KmacParams | `CK_KMAC_PARAMS` | yes | no | KmacParams |"));
    assert!(
        markdown.contains("| MuGen | MuGenParams | `CK_MU_GEN_PARAMS` | yes | no | MuGenParams |")
    );
    assert!(markdown.contains("## Parameter Struct Placeholders Excluded From ABI Matrix"));
    assert!(markdown.contains(
        "| CK_XXX_MESSAGE_PARAMS | prose_placeholder_for_mechanism_specific_message_params |"
    ));
    assert!(markdown.contains("## Message Parameter Shape Matrix"));
    assert!(markdown.contains(
        "| GcmMessage | GcmMessageParams | CK_GCM_MESSAGE_PARAMS | yes | GcmMessageParams |"
    ));
    assert!(markdown.contains(
        "| GcmMessage | GcmMessageParams | CK_GCM_MESSAGE_PARAMS | yes | GcmMessageParams | \
         gcm_message_params | yes | yes | yes | \
         `CK_GCM_MESSAGE_PARAMS.pIv`, `CK_GCM_MESSAGE_PARAMS.pTag` | \
         `gcm_message_params_round_trip`, `message_parameter_gcm_round_trip`, \
         `typed_message_exact_paths_return_structured_mock_outputs` |"
    ));
    assert!(markdown.contains(
        "| CKM_BATON_KEY_GEN | no_source_workflow_evidence | - | \
         published_header_only_no_working_markdown_workflow_source | - | \
         no_source_workflow_flags_available | \
         `mock_mechanism_info_leaves_flags_empty_without_source_workflow_evidence`, \
         `grpc_mechanism_info_preserves_zero_flags_without_source_workflow_evidence`, \
         `loaded_shim_preserves_no_source_mechanism_info_zero_flags`, \
         `official_source_grounded_mock_rejects_all_no_source_workflow_mechanisms` |"
    ));
    assert!(markdown.contains("## Mechanism Matrix"));
    assert!(markdown.contains(
        "| Mechanism | Status | Official Inventory | Value | Version | Header Annotations | \
         Workflows | Parameter Structs | MockBackend Catalog Smoke | \
         MockBackend Source-Grounded | MockBackend Semantics Status | \
         MockBackend Semantic Constructor | MockBackend Workflow Enforcement | \
         MockBackend Semantic Limitation | MockBackend Exact Output |"
    ));
    assert!(markdown.contains(
        "| CKM_BATON_KEY_GEN | represented | yes | 0x00001030 | 2.40 | `Historical` | - | - | \
         `sign`, `sign_recover`, `sign_update_final`"
    ));
    assert!(markdown.contains(
        "| no_source_workflow_evidence | MockBackend::with_official_mechanisms | \
         official_source_grounded_mock_enforces_mechanism_workflow_flags | \
         no_source_workflow_flags_available | \
         `sign_exact`, `sign_final_exact`, `sign_recover_exact`"
    ));
    assert!(markdown.contains("| CKM_AES_GCM | represented | yes |"));
}
