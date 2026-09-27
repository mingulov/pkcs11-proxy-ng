use std::{collections::BTreeSet, fs, path::PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn quoted_after<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    line.trim().strip_prefix(prefix)?.split('"').next()
}

fn enum_variants(source: &str) -> BTreeSet<String> {
    let mut inside = false;
    let mut variants = BTreeSet::new();
    for line in source.lines() {
        let line = line.trim();
        if line == "pub enum CkMechanismParams {" {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if line == "}" {
            break;
        }
        if let Some((name, _)) = line.split_once('(')
            && name.chars().next().is_some_and(char::is_uppercase)
        {
            variants.insert(name.to_owned());
        }
    }
    variants
}

fn local_shape_issues(
    enum_source: &str,
    toml_source: &str,
    shim_source: &str,
    driver_source: &str,
) -> Vec<String> {
    // These reader arms are deliberate runtime-only or operator-configured
    // shapes. They do not belong in the embedded default registry.
    const NON_DEFAULT_ARMS: &[&str] = &[
        "ccm_wrap",
        "ecdh2_derive",
        "gcm_wrap",
        "kip",
        "kmac",
        "mu_gen",
        "otp",
        "skipjack_private_wrap",
        "skipjack_relayx",
        "wtls_prf",
        "x942_mqv_derive",
    ];
    let variants = enum_variants(enum_source);
    let toml_shapes: BTreeSet<String> = toml_source
        .lines()
        .filter_map(|line| quoted_after(line, "shape = \""))
        .map(str::to_owned)
        .collect();
    let shim_shapes: BTreeSet<String> = shim_source
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix("Some(\"")
                .and_then(|rest| rest.split_once('"'))
                .filter(|(_, suffix)| suffix.starts_with(") => {"))
                .map(|(shape, _)| shape.to_owned())
        })
        .collect();
    let driver_variants: BTreeSet<String> = driver_source
        .lines()
        .filter_map(|line| quoted_after(line, "variant: \""))
        .map(str::to_owned)
        .collect();
    let mut issues = Vec::new();
    if variants.is_empty()
        || toml_shapes.is_empty()
        || shim_shapes.is_empty()
        || driver_variants.is_empty()
    {
        issues.push("one or more local shape inventories are empty".to_owned());
    }
    for variant in variants.difference(&driver_variants) {
        issues.push(format!("real-backend driver missing enum variant {variant}"));
    }
    for variant in driver_variants.difference(&variants) {
        issues.push(format!("real-backend driver has stale variant {variant}"));
    }
    for shape in &shim_shapes {
        if !NON_DEFAULT_ARMS.contains(&shape.as_str()) && !toml_shapes.contains(shape) {
            issues.push(format!("default TOML missing shim shape {shape}"));
        }
    }
    for shape in toml_shapes.difference(&shim_shapes) {
        issues.push(format!("default TOML has no shim arm for {shape}"));
    }
    issues
}

#[test]
fn local_parameter_shapes_match_default_registry_and_real_backend_driver() {
    let root = root();
    let enum_source = fs::read_to_string(root.join("crates/types/src/mechanism.rs")).unwrap();
    let toml_source =
        fs::read_to_string(root.join("crates/types/src/mechanism_params_default.toml")).unwrap();
    let shim_source =
        fs::read_to_string(root.join("crates/shim/src/dispatch/general/helpers/mechanism_read.rs"))
            .unwrap();
    let driver_source =
        fs::read_to_string(root.join("crates/server/tests/support/shape_matrix.rs")).unwrap();
    let driver_test =
        fs::read_to_string(root.join("crates/server/tests/parameterized_mechanism_test.rs"))
            .unwrap();
    assert!(driver_test.contains("fn softhsm_all_param_shapes_execute"));
    let issues = local_shape_issues(&enum_source, &toml_source, &shim_source, &driver_source);
    assert!(issues.is_empty(), "local parameter-shape gaps: {issues:?}");
}

#[test]
fn local_shape_gate_detects_missing_toml_shape_and_stale_driver_entry() {
    let root = root();
    let enum_source = fs::read_to_string(root.join("crates/types/src/mechanism.rs")).unwrap();
    let toml_source =
        fs::read_to_string(root.join("crates/types/src/mechanism_params_default.toml")).unwrap();
    let shim_source =
        fs::read_to_string(root.join("crates/shim/src/dispatch/general/helpers/mechanism_read.rs"))
            .unwrap();
    let driver_source =
        fs::read_to_string(root.join("crates/server/tests/support/shape_matrix.rs")).unwrap();
    let issues = local_shape_issues(
        &enum_source,
        &toml_source.replace("shape = \"gcm\"", "shape = \"removed_gcm\""),
        &shim_source,
        &driver_source.replace("variant: \"Gcm\"", "variant: \"Stale\""),
    );
    assert!(issues.contains(&"default TOML missing shim shape gcm".to_owned()));
    assert!(issues.contains(&"default TOML has no shim arm for removed_gcm".to_owned()));
    assert!(issues.contains(&"real-backend driver missing enum variant Gcm".to_owned()));
    assert!(issues.contains(&"real-backend driver has stale variant Stale".to_owned()));
}
