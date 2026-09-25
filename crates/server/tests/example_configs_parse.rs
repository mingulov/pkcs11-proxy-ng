//! Example configs dry-run + forward-compat check.
//!
//! For each `examples/configs/<tier>/proxy.toml`, verify that the
//! daemon's `DaemonConfig::load` parses it cleanly. We patch the
//! backend.module path to a known-existing file so validate()'s
//! existence check passes (the shipped paths point at vendor .sos
//! that may not be present on every test host).
//!
//! Forward-compat: round-trip the resilience-fixture's proxy.toml
//! (the oldest TOML we ship) through the current daemon's parser.
//! Any schema drift that breaks older deployments shows up here.

use std::path::PathBuf;

fn submodule_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn dummy_backend_module() -> String {
    if PathBuf::from("/bin/sh").exists() {
        "/bin/sh".to_string()
    } else {
        "/usr/bin/env".to_string()
    }
}

fn rewrite_for_test(orig: &str) -> String {
    // Patch backend.module to a known-existing file (the shipped paths
    // point at vendor .sos that may not exist). Also strip the
    // mechanisms.config_path = "..." line if present (would otherwise
    // fail the file-exists check; mechanism registry handling is
    // tested elsewhere).
    let mut out = String::with_capacity(orig.len());
    // T16: `[[auth.policy]]` blocks are commented out while set — policy
    // entries are refused on the downgraded auth="none" listener (same H1
    // rationale as allow-all below). The undowngraded mTLS posture is
    // covered by example_prod_staging_mtls_policy_parses.
    let mut in_policy_block = false;
    for line in orig.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("[[auth.policy]]") {
            in_policy_block = true;
            out.push_str("# stripped for downgraded test parse: [[auth.policy]]\n");
            continue;
        }
        if in_policy_block {
            if trimmed.starts_with('[') {
                in_policy_block = false;
            } else {
                out.push_str("# stripped for downgraded test parse\n");
                continue;
            }
        }
        if trimmed.starts_with("module ") || trimmed.starts_with("module=") {
            out.push_str(&format!("module = \"{}\"\n", dummy_backend_module()));
        } else if trimmed.starts_with("config_path ") || trimmed.starts_with("config_path=") {
            out.push_str("# config_path = stripped for test\n");
        } else if trimmed.starts_with("ca_cert ")
            || trimmed.starts_with("ca_cert=")
            || trimmed.starts_with("server_cert ")
            || trimmed.starts_with("server_cert=")
            || trimmed.starts_with("server_key ")
            || trimmed.starts_with("server_key=")
        {
            // mTLS files don't exist on the test host; the
            // permission check + actual TLS load run only when
            // server_tls_config is invoked, not during config parse.
            // Strip these so DaemonConfig::load doesn't reject them
            // via a future cert-existence check.
            out.push_str(&format!("# {line}\n"));
        } else if trimmed.starts_with("auth = \"mtls\"") {
            // With certs stripped, switch to insecure-tcp so the
            // config validates as a "syntactically OK" example.
            out.push_str("auth = \"none\"\n");
        } else if trimmed.starts_with("allow_insecure_tcp ")
            || trimmed.starts_with("allow_insecure_tcp=")
        {
            // Force allow_insecure_tcp = true to pair with the
            // auth = "none" rewrite above.
            out.push_str("allow_insecure_tcp = true\n");
        } else if trimmed.starts_with("allow_all_authenticated ")
            || trimmed.starts_with("allow_all_authenticated=")
        {
            // Strip allow_all_authenticated when mTLS has been downgraded to
            // auth = "none" above; the combination is rejected by the H1 guard.
            // The example files are correct (mTLS is authenticated); this rewrite
            // is an artefact of the test harness stripping cert paths.
            out.push_str(&format!("# {line}  # stripped for test (mTLS downgraded)\n"));
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn write_temp(toml: &str) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(toml.as_bytes()).unwrap();
    f
}

fn assert_example_parses(tier: &str) {
    let p = submodule_root().join(format!("examples/configs/{tier}/proxy.toml"));
    let raw = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{tier}/proxy.toml: {e}"));
    let patched = rewrite_for_test(&raw);
    let tmp = write_temp(&patched);
    pkcs11_proxy_ng::config::DaemonConfig::load(tmp.path())
        .unwrap_or_else(|e| panic!("{tier} parses: {e:?}"));
}

#[test]
fn example_dev_parses() {
    assert_example_parses("dev");
}

#[test]
fn example_staging_parses() {
    assert_example_parses("staging");
}

#[test]
fn example_prod_parses() {
    assert_example_parses("prod");
}

#[test]
fn example_fips_parses() {
    assert_example_parses("fips");
}

/// T16: prod/staging guidance shows explicit mTLS identity/token grants
/// and deliberate quotas — validate the REAL posture, not just the
/// downgraded parse. Only filesystem paths are redirected (module,
/// certs) to test doubles; auth=mtls, the policy, and the quotas load
/// exactly as shipped. (The intentional auth="none" fixtures — dev,
/// k8s, r2 — are covered by their own tests; nothing here prohibits
/// them.)
#[test]
fn example_prod_staging_mtls_policy_parses() {
    for tier in ["prod", "staging"] {
        let p = submodule_root().join(format!("examples/configs/{tier}/proxy.toml"));
        let raw = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{tier}/proxy.toml: {e}"));
        assert!(
            raw.contains("auth = \"mtls\""),
            "{tier} guidance must stay mTLS (fixture posture lives in dev/k8s)"
        );
        let dir = tempfile::tempdir().expect("tempdir");
        // Existence-only doubles: `load` checks cert files exist;
        // permission/content checks run at TLS load, not parse.
        for name in ["ca.crt", "server.crt", "server.key"] {
            std::fs::write(dir.path().join(name), b"test double").expect("write cert double");
        }
        let mut out = String::with_capacity(raw.len());
        for line in raw.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("module ") || trimmed.starts_with("module=") {
                out.push_str(&format!("module = \"{}\"\n", dummy_backend_module()));
            } else if trimmed.starts_with("config_path ") || trimmed.starts_with("config_path=") {
                out.push_str("# config_path = stripped for test\n");
            } else if let Some(key) = ["ca_cert", "server_cert", "server_key"].iter().find(|k| {
                trimmed.starts_with(&format!("{k} ")) || trimmed.starts_with(&format!("{k}="))
            }) {
                let file = match *key {
                    "ca_cert" => "ca.crt",
                    "server_cert" => "server.crt",
                    _ => "server.key",
                };
                out.push_str(&format!("{key} = \"{}\"\n", dir.path().join(file).display()));
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        let tmp = write_temp(&out);
        let cfg = pkcs11_proxy_ng::config::DaemonConfig::load(tmp.path())
            .unwrap_or_else(|e| panic!("{tier} mTLS posture parses: {e:?}"));
        // Explicit grants, no allow-all baseline (a successful load
        // already ran the full policy validation: identity form, token
        // selectors, classes, mechanisms, extract).
        assert!(!cfg.auth.allow_all_authenticated, "{tier} must not allow-all");
        assert_eq!(cfg.auth.policy.len(), 1, "{tier} must carry one explicit policy");
        assert!(
            cfg.auth.policy[0].identity.starts_with("x509:spki="),
            "{tier} identity must be an SPKI pin"
        );
        match &cfg.auth.policy[0].tokens {
            pkcs11_proxy_ng::config::TokenAccessSpec::Specific(grants) => {
                assert!(!grants.is_empty(), "{tier} policy must grant tokens");
            }
            pkcs11_proxy_ng::config::TokenAccessSpec::All(_) => {
                panic!("{tier} guidance must show explicit grants, not tokens = \"all\"")
            }
        }
        // Deliberate quotas, pinned per tier (an absent section would be
        // all-None = no limiting at all).
        let (in_flight, sessions, budget, cooldown) = match tier {
            "prod" => (64usize, 16usize, 10u32, 60u64 * 5),
            _ => (256usize, 64usize, 50u32, 60u64),
        };
        assert_eq!(cfg.rate_limit.per_principal_max_in_flight, Some(in_flight), "{tier} quota");
        assert_eq!(cfg.rate_limit.per_principal_max_sessions, Some(sessions), "{tier} quota");
        assert_eq!(cfg.rate_limit.per_slot_failed_login_budget, Some(budget), "{tier} quota");
        assert_eq!(
            cfg.rate_limit.per_slot_failed_login_cooldown_secs,
            Some(cooldown),
            "{tier} quota"
        );
    }
}

#[test]
fn example_fips_mechanism_params_parses() {
    use pkcs11_proxy_ng_types::MechanismRegistry;
    let p = submodule_root().join("examples/configs/fips/mechanism_params.toml");
    let registry =
        MechanismRegistry::load(Some(&p)).expect("fips/mechanism_params.toml must parse");
    // The FIPS allow-list must be in Filtered discovery mode (the
    // whole point — without it the daemon would advertise more than
    // the FIPS subset).
    assert_eq!(
        registry.discovery_mode(),
        pkcs11_proxy_ng_types::DiscoveryMode::Filtered,
        "fips registry must enable filtered discovery"
    );

    // Positive membership: representative FIPS-approved mechanisms
    // explicitly named in the FIPS toml MUST be present (silently
    // dropping AES_GCM or ECDSA would defeat the FIPS interlock).
    // CKM_AES_GCM = 0x00001087, CKM_ECDSA_SHA256 = 0x00001044.
    for (mech, name) in &[(0x0000_1087u64, "CKM_AES_GCM"), (0x0000_1044, "CKM_ECDSA_SHA256")] {
        assert!(
            registry.is_parameterless(*mech) || registry.param_shape(*mech).is_some(),
            "{name} ({mech:#010x}) must be in the FIPS registry"
        );
    }
    // Operation-time gate: the FIPS file hard-excludes historical
    // mechanisms via `exclude`, so direct invocations are rejected even
    // though the additive merge keeps the embedded default's shapes.
    // (Filtered discovery alone only hides them from C_GetMechanismList.)
    for (mech, name) in &[(0x0111u64, "CKM_RC4"), (0x0210, "CKM_MD5"), (0x0122, "CKM_DES_CBC")] {
        assert_eq!(
            registry.check_operation(*mech, false),
            Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID),
            "{name} ({mech:#010x}) must be hard-excluded by the FIPS registry"
        );
    }
    // F-09 regression pins: the ARIA/SEED/Camellia family members once
    // missing from the FIPS `exclude` list (sequences must not jump).
    // CKM_CAMELLIA_ECB_ENCRYPT_DATA = 0x0556,
    // CKM_ARIA_MAC_GENERAL = 0x0564, CKM_ARIA_ECB_ENCRYPT_DATA = 0x0566,
    // CKM_SEED_ECB_ENCRYPT_DATA = 0x0656.
    for (mech, name) in &[
        (0x0556u64, "CKM_CAMELLIA_ECB_ENCRYPT_DATA"),
        (0x0564, "CKM_ARIA_MAC_GENERAL"),
        (0x0566, "CKM_ARIA_ECB_ENCRYPT_DATA"),
        (0x0656, "CKM_SEED_ECB_ENCRYPT_DATA"),
    ] {
        assert_eq!(
            registry.check_operation(*mech, false),
            Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID),
            "{name} ({mech:#010x}) must be hard-excluded by the FIPS registry"
        );
    }
    // Exclusion wins over the default's shapes, so parameterized
    // invocations are rejected too.
    assert_eq!(
        registry.check_operation(0x0122, true),
        Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID),
        "CKM_DES_CBC with params must be hard-excluded"
    );
    // F-09 mechanism: the embedded default models 0x0564 under
    // `mac_general`, so without the FIPS remap
    // `check_operation(0x0564, true)` returned `Ok` and a
    // parameterized invocation of a non-approved mechanism was still
    // forwarded. All four restored members must reject with params.
    for (mech, name) in &[
        (0x0556u64, "CKM_CAMELLIA_ECB_ENCRYPT_DATA"),
        (0x0564, "CKM_ARIA_MAC_GENERAL"),
        (0x0566, "CKM_ARIA_ECB_ENCRYPT_DATA"),
        (0x0656, "CKM_SEED_ECB_ENCRYPT_DATA"),
    ] {
        assert_eq!(
            registry.check_operation(*mech, true),
            Err(pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID),
            "{name} ({mech:#010x}) with params must be hard-excluded"
        );
    }
    // Excluded mechanisms stay out of discovery as well.
    assert!(
        registry.filter_mechanisms(&[0x0111, 0x1087]).iter().all(|m| *m != 0x0111),
        "CKM_RC4 must not be advertised by the FIPS registry"
    );
}

/// FIPS example: every `[[params]]` shape must resolve to a known shim
/// arm, and historically mislabeled entries must stay fixed. The file
/// once used PascalCase shape names (which never match the snake_case
/// arms, silently degrading those mechanisms to Raw-then-rejected via
/// the override-wins merge) and listed real PQC hash IDs as HKDF.
#[test]
fn example_fips_mechanism_shapes_resolve() {
    use pkcs11_proxy_ng_types::MechanismRegistry;
    use std::collections::HashSet;
    let default = MechanismRegistry::load(None).expect("embedded default must load");
    let known: HashSet<&str> = default.param_shapes_view().values().map(|s| s.as_str()).collect();
    let p = submodule_root().join("examples/configs/fips/mechanism_params.toml");
    let src = std::fs::read_to_string(&p).expect("read fips mechanism toml");
    let fips = MechanismRegistry::load(Some(&p)).expect("fips must parse");
    for (mech, shape) in fips.param_shapes_view() {
        assert!(
            known.contains(shape.as_str()),
            "FIPS shape {shape} for {mech:#x} must resolve to a known arm"
        );
    }
    // Spot-check the previously-PascalCase mappings (override wins, so
    // these must equal the default's correct snake_case names).
    assert_eq!(fips.param_shape(0x000Du64), Some("rsa_pss"));
    assert_eq!(fips.param_shape(0x1087u64), Some("gcm"));
    assert_eq!(fips.param_shape(0x0021u64), Some("iv"));
    assert_eq!(fips.param_shape(0x0031u64), Some("x942_dh1_derive"));
    // Real HKDF IDs per OASIS pkcs11t.h 3.02 (0x402A/B/C) — never the
    // 0x0028-0x002A values, which are PQC hash mechanisms.
    assert_eq!(fips.param_shape(0x402Au64), Some("hkdf"));
    assert!(src.contains("0x402A"), "FIPS file must reference real HKDF IDs");
    assert!(
        !src.contains("0x0028,  # CKM_HKDF"),
        "FIPS file must not mislabel PQC hash IDs as HKDF"
    );
    // Parameterized AES modes must not sit in the file's own
    // parameterless list (section ends at the first [[params]]).
    let head = src.split("[[params]]").next().unwrap_or("");
    for id in ["0x1086", "0x108B", "0x108E"] {
        assert!(!head.contains(id), "FIPS parameterless must not list parameterized {id}");
    }
}

/// Vendor/example TOMLs: every `shape = "..."` literal (commented or
/// not — templates are meant to be uncommented) must either resolve to
/// a known registry shape, or the file must carry an explicit
/// `# NOT-YET-IMPLEMENTED(<shape>): <reason>` marker. This keeps
/// shipped examples honest: an unresolvable shape without a marker is
/// a typo-grade trap (it degrades to Raw-then-rejected at runtime).
#[test]
fn example_vendor_shape_names_resolve_or_marked() {
    use pkcs11_proxy_ng_types::MechanismRegistry;
    use std::collections::HashSet;
    let default = MechanismRegistry::load(None).expect("embedded default must load");
    let known: HashSet<&str> = default.param_shapes_view().values().map(|s| s.as_str()).collect();
    let root = submodule_root();
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(root.join("examples/vendors"))
        .expect("vendors dir must exist")
        .map(|e| e.expect("vendor entry must read").path())
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
        .collect();
    files.push(root.join("packaging/config/mechanism_params.cloudhsm.toml.example"));
    files.push(root.join("examples/k8s/10-configmap.yaml"));
    assert!(!files.is_empty(), "must scan at least one example file");
    for path in &files {
        let src = std::fs::read_to_string(path)
            .unwrap_or_else(|_| panic!("example file must read: {}", path.display()));
        let mut shapes = HashSet::new();
        for line in src.lines() {
            let t = line.trim().trim_start_matches('#').trim();
            let rest = match t.strip_prefix("shape") {
                Some(r) => r.trim(),
                None => continue,
            };
            let rest = match rest.strip_prefix('=') {
                Some(r) => r.trim(),
                None => continue,
            };
            if let Some(name) = rest.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
                shapes.insert(name.to_string());
            }
        }
        for shape in &shapes {
            if known.contains(shape.as_str()) {
                continue;
            }
            assert!(
                src.contains(&format!("NOT-YET-IMPLEMENTED({shape})")),
                "{}: shape {shape} resolves nowhere and carries no NOT-YET-IMPLEMENTED marker",
                path.display()
            );
        }
    }
}

/// Forward-compat: an older shipped proxy.toml (the one used by the
/// resilience fixture, predating later-added fields) must still
/// parse cleanly with the current daemon. New fields default.
#[test]
fn forward_compat_r2_fixture_proxy_toml_parses() {
    // The resilience fixture embeds its proxy.toml directly in the daemon
    // Dockerfile (heredoc). We reproduce the same TOML body here so
    // the test is independent of Docker.
    let older_toml = r#"
[backend]
module = "/bin/sh"

[proxy]
request_timeout_secs = 60
startup_timeout_secs = 30
shutdown_grace_secs = 5
backend_health_consecutive_failures = 3

[listener.remote]
bind = "0.0.0.0:7512"
auth = "none"
allow_insecure_tcp = true

[auth]
"#;
    let tmp = write_temp(older_toml);
    let cfg = pkcs11_proxy_ng::config::DaemonConfig::load(tmp.path())
        .expect("older proxy.toml must still parse");
    // Spot-check a few fields filled in from defaults:
    assert!(cfg.proxy.rate_limit_window_secs > 0);
    assert_eq!(cfg.proxy.rate_limit_get_backend_interfaces, 0);
}
