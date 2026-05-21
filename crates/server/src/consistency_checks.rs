//! Static analysis tests that catch drift between layers.
//!
//! These tests scan source code to verify that the proto service,
//! backend trait, gRPC handlers, and client all stay in sync.
//! They prevent silent feature gaps where a new RPC is added to one
//! layer but not wired through all layers.

/// Extract method names from the Pkcs11Backend trait source.
fn backend_trait_methods() -> Vec<String> {
    let src = include_str!("../../backend/src/traits.rs");
    let mut methods = Vec::new();
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("fn ") && trimmed.contains('(') {
            let name = trimmed.strip_prefix("fn ").unwrap().split('(').next().unwrap().trim();
            methods.push(name.to_string());
        }
    }
    methods
}

/// Extract RPC names from the proto service definition.
fn proto_rpc_names() -> Vec<String> {
    let src = include_str!("../../../proto/pkcs11-proxy-ng/v1/service.proto");
    let mut rpcs = Vec::new();
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("rpc ") {
            let name = trimmed.strip_prefix("rpc ").unwrap().split('(').next().unwrap().trim();
            rpcs.push(name.to_string());
        }
    }
    rpcs
}

/// List protobuf source files that should feed code generation.
fn proto_source_paths() -> Vec<String> {
    let proto_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proto/pkcs11-proxy-ng/v1");
    let mut paths: Vec<String> = std::fs::read_dir(&proto_dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", proto_dir.display()))
        .filter_map(|entry| {
            let path = entry.expect("dir entry").path();
            (path.extension().and_then(|e| e.to_str()) == Some("proto")).then(|| {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                format!("../../proto/pkcs11-proxy-ng/v1/{name}")
            })
        })
        .collect();
    paths.sort();
    paths
}

/// Extract handler delegation lines from the gRPC service implementation.
fn grpc_handler_rpcs() -> Vec<String> {
    let src = include_str!("server/grpc_service/mod.rs");
    let mut handlers = Vec::new();

    for line in src.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("async fn ") {
            let name = rest.split('(').next().unwrap().trim();
            if name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                && !handlers.iter().any(|handler| handler == name)
            {
                handlers.push(name.to_string());
            }
        }
    }

    let invocation = src
        .rsplit_once("impl_proxy_service!(")
        .map(|(_, rest)| rest)
        .expect("impl_proxy_service! invocation missing");

    let mut tuple = String::new();
    let mut depth = 0usize;

    for ch in invocation.chars() {
        match ch {
            '(' => {
                depth += 1;
                if depth == 1 {
                    tuple.clear();
                } else {
                    tuple.push(ch);
                }
            }
            ')' => {
                if depth == 1 {
                    let name = tuple.split(',').next().unwrap().trim();
                    if name.chars().next().map(|c| c.is_ascii_lowercase()).unwrap_or(false)
                        && !handlers.iter().any(|handler| handler == name)
                    {
                        handlers.push(name.to_string());
                    }
                    tuple.clear();
                } else if depth > 1 {
                    tuple.push(ch);
                }
                depth = depth.saturating_sub(1);
            }
            _ if depth >= 1 => tuple.push(ch),
            _ => {}
        }
    }
    handlers
}

/// Convert snake_case to PascalCase for name comparison.
fn snake_to_pascal(s: &str) -> String {
    s.split('_')
        .map(|part| {
            let mut c = part.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect()
}

/// Convert PascalCase to snake_case.
///
/// Handles acronyms correctly: `AsyncGetID` becomes `async_get_id` (not `async_get_i_d`).
fn pascal_to_snake(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut result = String::new();
    for (i, &ch) in chars.iter().enumerate() {
        if ch.is_uppercase() && i > 0 {
            let prev_upper = chars[i - 1].is_uppercase();
            let next_lower = chars.get(i + 1).is_some_and(|c| c.is_lowercase());
            // Insert '_' before an uppercase letter if:
            // - previous char was lowercase (normal word boundary), OR
            // - previous char was uppercase AND next char is lowercase (end of acronym)
            if !prev_upper || next_lower {
                result.push('_');
            }
        }
        result.push(ch.to_lowercase().next().unwrap());
    }
    result
}

/// Scan shim dispatch directory for all `pub unsafe extern "C" fn c_*` functions.
fn shim_dispatch_functions() -> Vec<String> {
    let dispatch_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../shim/src/dispatch/general");
    let mut fns = Vec::new();
    for entry in std::fs::read_dir(&dispatch_dir).expect("cannot read shim dispatch dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let content = std::fs::read_to_string(&path).expect("cannot read file");
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("pub unsafe extern")
                && trimmed.contains("fn c_")
                && let Some(after_fn) = trimmed.split("fn ").nth(1)
                && let Some(name) = after_fn.split('(').next()
            {
                let name = name.trim();
                if !name.starts_with("c_not_supported") {
                    fns.push(name.to_string());
                }
            }
        }
    }
    fns
}

fn client_method_names() -> Vec<String> {
    fn collect_methods(dir: &std::path::Path, methods: &mut Vec<String>) {
        for entry in
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                collect_methods(&path, methods);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            methods.extend(src.lines().filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.starts_with("pub async fn ") {
                    let name = trimmed.strip_prefix("pub async fn ")?.split('(').next()?.trim();
                    Some(name.to_string())
                } else {
                    None
                }
            }));
        }
    }

    let client_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/src/client");
    let mut methods = Vec::new();
    collect_methods(&client_dir, &mut methods);
    methods.sort();
    methods
}

#[test]
fn proto_build_script_tracks_all_proto_sources() {
    let build_rs = include_str!("../../proto/build.rs");
    for path in proto_source_paths() {
        assert!(
            build_rs.contains(&format!("cargo:rerun-if-changed={path}")),
            "crates/proto/build.rs must rerun when {path} changes"
        );
        assert!(
            build_rs.contains(&format!("\"{path}\"")),
            "crates/proto/build.rs must pass {path} to tonic_prost_build::compile_protos"
        );
    }
}

#[test]
fn backend_methods_have_proto_rpcs() {
    let backend = backend_trait_methods();
    let rpcs = proto_rpc_names();
    let rpc_pascal: Vec<String> = rpcs.iter().map(|r| r.to_lowercase()).collect();

    // Methods exempt from the "must have a matching proto RPC" check:
    // - initialize/finalize: handled specially in the proto (C_Initialize/C_Finalize)
    // - get_interface_capabilities: internal BUG-001 RPC, not a PKCS#11 function
    // - *_exact: these are exact-output variants that share the ByteOutputExact
    //   or GetAttributeValueExact multiplexed RPCs, not individual RPCs
    let exempt = [
        "initialize",
        "finalize",
        "get_interface_capabilities",
        // Exact-output trait method shared via EncapsulateKeyExact RPC
        "encapsulate_key_exact",
        // Exact-output trait methods shared via ByteOutputExact RPC
        "sign_exact",
        "sign_final_exact",
        "sign_recover_exact",
        "verify_recover_exact",
        "digest_exact",
        "digest_final_exact",
        "encrypt_exact",
        "encrypt_exact_with_output",
        "encrypt_update_exact",
        "encrypt_final_exact",
        "decrypt_exact",
        "decrypt_update_exact",
        "decrypt_final_exact",
        "digest_encrypt_update_exact",
        "decrypt_digest_update_exact",
        "sign_encrypt_update_exact",
        "decrypt_verify_update_exact",
        "wrap_key_exact",
        "wrap_key_exact_with_output",
        "derive_key_with_output",
        "derive_key_with_output_result",
        "get_operation_state_exact",
        // Helper used by the simple Encrypt/Decrypt + Update/Final RPCs to
        // surface HSM-mutated mechanism params. Not its own RPC; populates
        // the `mechanism_out` field of the existing crypto-op responses.
        "session_output_mechanism_params",
        // NULL-mechanism init cancellation is carried by the existing *Init
        // RPCs with `mechanism: None`, not by separate proto methods.
        "sign_init_cancel",
        "verify_init_cancel",
        "sign_recover_init_cancel",
        "verify_recover_init_cancel",
        "digest_init_cancel",
        "encrypt_init_cancel",
        "decrypt_init_cancel",
        // Exact-output trait method for GetAttributeValueExact RPC
        "get_attribute_value_exact",
        // Exact-output trait methods shared via ParameterOutputExact RPC
        "encrypt_message_exact",
        "decrypt_message_exact",
        "sign_message_exact",
        "encrypt_message_next_exact",
        "decrypt_message_next_exact",
        "sign_message_next_exact",
        "wrap_key_authenticated_exact",
        // Batch close via CloseAllSessions RPC
        "close_sessions",
        // Structured message parameter variants (also via ParameterOutputExact RPC)
        "encrypt_message_exact_msg",
        "decrypt_message_exact_msg",
        "sign_message_exact_msg",
        "encrypt_message_next_exact_msg",
        "decrypt_message_next_exact_msg",
        "sign_message_next_exact_msg",
    ];

    let mut missing = Vec::new();
    for method in &backend {
        if exempt.contains(&method.as_str()) {
            continue;
        }
        let pascal = snake_to_pascal(method);
        if !rpcs.contains(&pascal) {
            let lower = method.replace('_', "");
            if !rpc_pascal.iter().any(|r| r == &lower) {
                missing.push(method.as_str());
            }
        }
    }
    assert!(
        missing.is_empty(),
        "Backend trait methods without matching proto RPCs: {:?}\n\
         Backend methods: {:?}\n\
         Proto RPCs: {:?}",
        missing,
        backend,
        rpcs
    );
}

#[test]
fn proto_rpcs_have_grpc_handlers() {
    let rpcs = proto_rpc_names();
    let handlers = grpc_handler_rpcs();
    let handler_pascal: Vec<String> = handlers.iter().map(|h| snake_to_pascal(h)).collect();

    let mut missing = Vec::new();
    for rpc in &rpcs {
        // Case-insensitive comparison: tonic lowercases acronyms like ID → Id
        let rpc_lower = rpc.to_lowercase();
        if !handler_pascal.iter().any(|h| h.to_lowercase() == rpc_lower) {
            missing.push(rpc.as_str());
        }
    }
    assert!(
        missing.is_empty(),
        "Proto RPCs without gRPC handler: {:?}\n\
         Proto RPCs: {:?}\n\
         Handlers: {:?}",
        missing,
        rpcs,
        handlers
    );
}

#[test]
fn grpc_handlers_have_proto_rpcs() {
    let rpcs = proto_rpc_names();
    let handlers = grpc_handler_rpcs();

    let mut orphaned = Vec::new();
    for handler in &handlers {
        let pascal = snake_to_pascal(handler);
        // Case-insensitive: tonic lowercases acronyms like ID → Id
        let pascal_lower = pascal.to_lowercase();
        if !rpcs.iter().any(|r| r.to_lowercase() == pascal_lower) {
            orphaned.push(handler.as_str());
        }
    }
    assert!(orphaned.is_empty(), "gRPC handlers without matching proto RPC: {:?}", orphaned);
}

#[test]
fn proto_rpc_count_matches_handler_count() {
    let rpcs = proto_rpc_names();
    let handlers = grpc_handler_rpcs();
    assert_eq!(
        rpcs.len(),
        handlers.len(),
        "Proto has {} RPCs but gRPC service has {} handlers.\n\
         RPCs: {:?}\n\
         Handlers: {:?}",
        rpcs.len(),
        handlers.len(),
        rpcs,
        handlers
    );
}

#[test]
fn config_proxy_fields_all_have_defaults() {
    let config = crate::config::ProxyConfig::default();
    // mechanism_discovery is kept for backward-compatible config parsing but is
    // ignored at runtime (server is now a pure proxy for mechanism discovery).
    assert_eq!(config.mechanism_discovery, crate::config::MechanismDiscovery::Transparent);
    assert!(config.lease_seconds > 0);
    assert!(config.max_message_bytes > 0);
    assert!(config.request_timeout_secs > 0);
    assert!(config.max_concurrent_backend_calls > 0);
    assert!(config.max_blocking_threads > 0);
    assert!(config.max_concurrent_backend_calls <= config.max_blocking_threads);
}

// doc/completed/ and doc/adr/ live in the umbrella workspace one level above
// the submodule. They're reachable when this crate is built inside the
// workspace checkout, but not in a standalone submodule clone (e.g. CI).
// These checks enforce workspace docs hygiene when reachable, and silently
// skip otherwise so the test suite stays green outside the workspace.

#[test]
fn completion_docs_directory_is_not_empty() {
    let completed_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../doc/completed");
    if !completed_dir.exists() {
        eprintln!(
            "skipping completion_docs_directory_is_not_empty: {} not reachable from submodule-only checkout",
            completed_dir.display()
        );
        return;
    }
    let count = std::fs::read_dir(&completed_dir)
        .expect("cannot read doc/completed/")
        .filter(|e| {
            e.as_ref().map(|e| e.file_name().to_string_lossy().ends_with(".md")).unwrap_or(false)
        })
        .count();
    assert!(count >= 10, "doc/completed/ should have many completion notes, found only {count}");
}

#[test]
fn adr_files_exist() {
    let adr_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../doc/adr");
    if !adr_dir.exists() {
        eprintln!(
            "skipping adr_files_exist: {} not reachable from submodule-only checkout",
            adr_dir.display()
        );
        return;
    }
    let expected = [
        "ADR-0001-function-mechanism-coverage-policy.md",
        "ADR-0002-handle-session-identity-model.md",
        "ADR-0003-error-model.md",
        "ADR-0004-backend-integration-model.md",
        "ADR-0005-phase-1-authorization-model.md",
    ];
    for name in &expected {
        let path = adr_dir.join(name);
        assert!(path.exists(), "ADR file missing: {} (expected at {})", name, path.display());
    }
}

#[test]
fn generated_support_table_is_complete() {
    let rpcs = proto_rpc_names();
    let backend = backend_trait_methods();
    let handlers = grpc_handler_rpcs();
    let shim_fns = shim_dispatch_functions();

    // RPCs exempt from shim/client alignment checks.
    // - GetBackendInterfaces: proxy-internal RPC (BUG-001) that doesn't correspond
    //   to a PKCS#11 C_ function — called by the shim's interface_probe module.
    // - GetAttributeValueExact: exact-output RPC called internally from existing
    //   shim c_get_attribute_value, not a separate extern "C" function.
    // - ByteOutputExact: multiplexed exact-output RPC called internally from existing
    //   shim c_sign/c_encrypt/etc., not a separate extern "C" function.
    let exempt_rpcs: [&str; 5] = [
        "GetBackendInterfaces",
        "GetAttributeValueExact",
        "ByteOutputExact",
        "ParameterOutputExact",
        "EncapsulateKeyExact",
    ];

    let mut missing_shim = Vec::new();
    for rpc in &rpcs {
        if exempt_rpcs.contains(&rpc.as_str()) {
            continue;
        }
        let c_fn = format!("c_{}", pascal_to_snake(rpc));
        if !shim_fns.iter().any(|f| f == &c_fn) {
            missing_shim.push(format!("{rpc} (expected {c_fn})"));
        }
    }
    assert!(
        missing_shim.is_empty(),
        "Proto RPCs without shim C_ function: {:?}\n\
         Shim functions: {:?}",
        missing_shim,
        shim_fns
    );

    let client_methods = client_method_names();

    let non_exempt_rpc_count = rpcs.len() - exempt_rpcs.len();
    assert!(backend.len() >= 2, "Backend should have methods");
    assert_eq!(rpcs.len(), handlers.len(), "Proto RPCs and handlers must match");
    assert!(
        shim_fns.len() >= non_exempt_rpc_count,
        "Shim should have at least {} C_ functions (has {})",
        non_exempt_rpc_count,
        shim_fns.len()
    );
    // Client methods must cover at least the non-exempt RPCs.
    // Exempt RPCs (3.x functions) get client methods in later implementation waves.
    assert!(
        client_methods.len() >= non_exempt_rpc_count,
        "Client should have at least {} methods (has {})\n\
         Client methods: {:?}",
        non_exempt_rpc_count,
        client_methods.len(),
        client_methods
    );
}

fn example_config_with_existing_placeholder_paths(content: &str) -> String {
    let mut value: toml::Value = toml::from_str(content).expect("example config TOML");

    if let Some(backend) = value.get_mut("backend").and_then(toml::Value::as_table_mut) {
        backend.insert("module".to_string(), toml::Value::String("/dev/null".to_string()));
    }

    if let Some(remote) = value
        .get_mut("listener")
        .and_then(toml::Value::as_table_mut)
        .and_then(|listener| listener.get_mut("remote"))
        .and_then(toml::Value::as_table_mut)
    {
        for key in ["ca_cert", "server_cert", "server_key"] {
            if remote.contains_key(key) {
                remote.insert(key.to_string(), toml::Value::String("/dev/null".to_string()));
            }
        }
    }

    toml::to_string(&value).expect("serialize normalized example config")
}

#[test]
fn example_configs_parse_and_validate_without_errors() {
    let examples_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    assert!(examples_dir.exists(), "examples/ directory must exist: {}", examples_dir.display());
    let tempdir = tempfile::tempdir().expect("tempdir for normalized example configs");
    let mut count = 0;
    for entry in std::fs::read_dir(&examples_dir).expect("cannot read examples/") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            // Skip non-daemon-config TOML files (mechanism overrides, etc.)
            if !name.starts_with("config") {
                continue;
            }
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            let normalized = example_config_with_existing_placeholder_paths(&content);
            let normalized_path = tempdir
                .path()
                .join(std::path::Path::new(path.file_name().expect("example config file name")));
            std::fs::write(&normalized_path, normalized)
                .unwrap_or_else(|e| panic!("cannot write {}: {e}", normalized_path.display()));
            let _config = crate::config::DaemonConfig::load(&normalized_path)
                .unwrap_or_else(|e| panic!("{} failed to validate: {e}", path.display()));
            count += 1;
        }
    }
    assert!(count >= 3, "examples/ should have at least 3 reference configs, found {count}");
}
