//! Static analysis tests that catch drift between layers.
//!
//! These tests scan source code to verify that the proto service,
//! backend trait, gRPC handlers, and client all stay in sync.
//! They prevent silent feature gaps where a new RPC is added to one
//! layer but not wired through all layers.

use std::collections::BTreeSet;

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
    // Only methods inside the `impl Pkcs11Proxy for ...` trait block are RPC
    // handlers. Inherent helpers on the service (e.g. `check_context_owner`)
    // are also `async fn` but must not be counted as handlers.
    let mut in_trait_impl = false;

    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("impl Pkcs11Proxy for ") {
            in_trait_impl = true;
        }
        if in_trait_impl && let Some(rest) = trimmed.strip_prefix("async fn ") {
            let name = rest.split('(').next().unwrap().trim();
            if name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                && !handlers.contains(&name.to_string())
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
                    if name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                        && !handlers.contains(&name.to_string())
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

/// Strip `//` comments and `"..."` string contents from one source line so
/// brace counting and keyword detection see code only, not prose.
/// (Hand-written RPC bodies contain comments naming `client_context_id` and
/// `begin_operation`; without stripping, those would misclassify bodies.)
fn code_only(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut in_string = false;
    while let Some(ch) = chars.next() {
        if in_string {
            if ch == '\\' {
                chars.next(); // skip escaped char (keeps `\"` from ending the string)
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            break; // line comment: ignore the rest
        }
        out.push(ch);
    }
    out
}

/// One hand-written RPC method: its name plus its source lines (signature
/// through the closing brace). Each line carries the brace depth at line
/// start so nesting checks can tell "inside the scoped block" from "hoisted
/// outside it".
struct HandWrittenRpc {
    name: String,
    /// (raw trimmed line, comment/string-stripped line, brace depth at line start)
    lines: Vec<(String, String, i32)>,
}

/// Extract the hand-written `async fn` methods from the `impl Pkcs11Proxy`
/// block in grpc_service/mod.rs: everything between the trait-impl line and
/// the `$(` line that starts the macro-generated repetition.
fn hand_written_rpcs() -> Vec<HandWrittenRpc> {
    let src = include_str!("server/grpc_service/mod.rs");
    let lines: Vec<&str> = src.lines().collect();
    let mut rpcs = Vec::new();
    let mut i = 0;
    while i < lines.len() && !lines[i].trim().starts_with("impl Pkcs11Proxy for ") {
        i += 1;
    }
    assert!(i < lines.len(), "impl Pkcs11Proxy block not found in grpc_service/mod.rs");
    i += 1;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed == "$(" {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("async fn ") {
            let name = rest.split('(').next().unwrap().trim().to_string();
            let mut body = Vec::new();
            let mut depth: i32 = 0;
            let mut entered = false;
            while i < lines.len() {
                let raw = lines[i].trim().to_string();
                let code = code_only(&raw);
                body.push((raw, code.clone(), depth));
                depth += code.chars().filter(|&c| c == '{').count() as i32;
                depth -= code.chars().filter(|&c| c == '}').count() as i32;
                i += 1;
                if depth > 0 {
                    entered = true;
                }
                if entered && depth == 0 {
                    break;
                }
            }
            assert!(entered, "hand-written RPC {name} has no body block");
            rpcs.push(HandWrittenRpc { name, lines: body });
            continue;
        }
        i += 1;
    }
    assert!(!rpcs.is_empty(), "no hand-written RPCs found in grpc_service/mod.rs");
    rpcs
}

/// A hand-written RPC is context-carrying when its code (comments stripped)
/// touches `client_context_id`. Pre-context RPCs (`initialize`,
/// `get_backend_interfaces`) never do.
fn is_context_carrying(rpc: &HandWrittenRpc) -> bool {
    rpc.lines.iter().any(|(_, code, _)| code.contains("client_context_id"))
}

/// Parse the `HAND_WRITTEN_RPCS` string list from the scoped-dispatch test
/// module in grpc_service/mod.rs. Entries must stay bare `"name",` literals
/// (see that const's doc comment) so this parser keeps working.
fn test_enumerated_rpc_names() -> Vec<String> {
    let src = include_str!("server/grpc_service/mod.rs");
    let mut names = Vec::new();
    let mut in_list = false;
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("const HAND_WRITTEN_RPCS") {
            in_list = true;
            continue;
        }
        if in_list {
            if trimmed.starts_with("];") {
                break;
            }
            let entry = trimmed.trim_end_matches(',').trim();
            if let Some(name) = entry.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                names.push(name.to_string());
            } else if !entry.is_empty() {
                panic!("HAND_WRITTEN_RPCS entry is not a bare string literal: {entry:?}");
            }
        }
    }
    assert!(!names.is_empty(), "HAND_WRITTEN_RPCS list not found in grpc_service/mod.rs");
    names
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
        // ABI advertisement metadata (ADR-0011 D2/D6): carried inside the
        // GetBackendInterfaces response, not PKCS#11 functions.
        "abi_ulong_size",
        "abi_byte_order",
        "abi_attribute_stride",
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
        // Reuses the GenerateKey RPC, surfacing HSM-written mechanism params
        // (CK_PBE_PARAMS.pInitVector) via GenerateKeyResponse.mechanism_out.
        "generate_key_with_output",
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
        // Typed authenticated envelopes reuse the existing authenticated RPCs
        // and ParameterOutputExact rather than introducing function-list slots.
        "wrap_key_authenticated_typed",
        "wrap_key_authenticated_exact_typed",
        "unwrap_key_authenticated_typed",
        // Batch close via CloseAllSessions RPC
        "close_sessions",
        // Structured message parameter variants (also via ParameterOutputExact RPC)
        "encrypt_message_exact_msg",
        "decrypt_message_exact_msg",
        "sign_message_exact_msg",
        "encrypt_message_next_exact_msg",
        "decrypt_message_next_exact_msg",
        "sign_message_next_exact_msg",
        // Structured/transactional helpers carried by the named message RPCs,
        // not additional wire methods.
        "message_encrypt_init_contract",
        "message_decrypt_init_contract",
        "encrypt_message_begin_exact",
        "decrypt_message_begin_exact",
        "encrypt_message_begin_msg",
        "decrypt_message_begin_msg",
        "sign_message_begin_exact",
        "sign_message_next_feed_exact",
        "verify_message_exact",
        "verify_message_begin_exact",
        "verify_message_next_exact",
        // Drop-path destroy (F-01 Drop-may-never-admit): destructor cleanup
        // rides the enclosing op's exclusion and RPC; never itself on the
        // wire, so no proto method exists for it.
        "destroy_quarantined_object",
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

// Public docs ship INSIDE this repository (doc/, prd.md, README.md). These
// checks verify the released repo is self-describing: they resolve paths from
// the repo root and no longer reach into any outer planning workspace, so they
// pass in a standalone clone of this repository.

/// Repo root, derived from the server crate's manifest dir
/// (`<repo>/crates/server`).
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn public_docs_present() {
    let root = repo_root();
    for rel in ["README.md", "prd.md", "doc/architecture-overview.md", "doc/adr/README.md"] {
        let path = root.join(rel);
        assert!(path.exists(), "public doc missing: {} (expected at {})", rel, path.display());
    }
}

#[test]
fn adr_index_covers_every_numbered_adr() {
    let root = repo_root();
    let index = std::fs::read_to_string(root.join("doc/adr/README.md")).unwrap();
    for entry in std::fs::read_dir(root.join("doc/adr")).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if name.starts_with("ADR-") && name.ends_with(".md") {
            assert!(index.contains(&format!("]({name})")), "ADR index does not link {name}");
        }
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

fn example_config_with_existing_placeholder_paths(content: &str, stub_path: &str) -> String {
    let mut value: toml::Value = toml::from_str(content).expect("example config TOML");
    // T2run win32: the caller passes a freshly-created 0600 stub file —
    // `/dev/null` does not exist on Windows and red-lined this test there,
    // and `load()` perm-guards the module path (with a `/dev/null`-only
    // exemption), so the stub must be a tight-permissioned real file.
    // Serialization re-escapes Windows backslashes automatically.
    let existing_stub = || toml::Value::String(stub_path.to_string());

    if let Some(backend) = value.get_mut("backend").and_then(toml::Value::as_table_mut) {
        backend.insert("module".to_string(), existing_stub());
    }

    if let Some(remote) = value
        .get_mut("listener")
        .and_then(toml::Value::as_table_mut)
        .and_then(|listener| listener.get_mut("remote"))
        .and_then(toml::Value::as_table_mut)
    {
        for key in ["ca_cert", "server_cert", "server_key"] {
            if remote.contains_key(key) {
                remote.insert(key.to_string(), existing_stub());
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
    // Tight-permissioned stub satisfying both the existence check in
    // `validate()` and the perm guard in `load()` on every platform.
    let stub_path = tempdir.path().join("module.stub");
    std::fs::write(&stub_path, b"T2run existing-path stub")
        .unwrap_or_else(|e| panic!("cannot write {}: {e}", stub_path.display()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub_path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|e| panic!("cannot chmod {}: {e}", stub_path.display()));
    }
    let stub_path = stub_path.to_str().expect("stub path must be UTF-8").to_string();
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
            let normalized = example_config_with_existing_placeholder_paths(&content, &stub_path);
            let normalized_path = tempdir
                .path()
                .join(std::path::Path::new(path.file_name().expect("example config file name")));
            std::fs::write(&normalized_path, normalized)
                .unwrap_or_else(|e| panic!("cannot write {}: {e}", normalized_path.display()));
            // The perm-guard in load() rejects group/world-writable files.
            // Temp files created by std::fs::write use the process umask and
            // may be 0664; set them to 0600 so the check passes here.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&normalized_path, std::fs::Permissions::from_mode(0o600))
                    .unwrap_or_else(|e| panic!("cannot chmod {}: {e}", normalized_path.display()));
            }
            let _config = crate::config::DaemonConfig::load(&normalized_path)
                .unwrap_or_else(|e| panic!("{} failed to validate: {e}", path.display()));
            count += 1;
        }
    }
    assert!(count >= 3, "examples/ should have at least 3 reference configs, found {count}");
}

/// I-1 (W1-L6-01 follow-up): the scoped-dispatch test enumeration must cover
/// exactly the hand-written, context-carrying RPCs in the trait impl — a 10th
/// hand-written RPC (or a removal) must fail here, never silently drop
/// coverage. The two pre-context RPCs are pinned as explicit exemptions so a
/// new unguarded-looking method also forces triage instead of passing quietly.
#[test]
fn hand_written_context_rpcs_match_test_enumeration() {
    let rpcs = hand_written_rpcs();
    let impl_names: BTreeSet<&str> =
        rpcs.iter().filter(|rpc| is_context_carrying(rpc)).map(|rpc| rpc.name.as_str()).collect();
    let listed_vec = test_enumerated_rpc_names();
    let listed: BTreeSet<&str> = listed_vec.iter().map(String::as_str).collect();
    let missing_from_tests: Vec<&&str> = impl_names.difference(&listed).collect();
    let extra_in_tests: Vec<&&str> = listed.difference(&impl_names).collect();

    let all_impl: BTreeSet<&str> = rpcs.iter().map(|rpc| rpc.name.as_str()).collect();
    let mut expected_all = listed.clone();
    expected_all.insert("initialize");
    expected_all.insert("get_backend_interfaces");
    let untriaged: Vec<&&str> = all_impl.difference(&expected_all).collect();
    let stale_exempt: Vec<&&str> = expected_all.difference(&all_impl).collect();

    assert!(
        missing_from_tests.is_empty()
            && extra_in_tests.is_empty()
            && untriaged.is_empty()
            && stale_exempt.is_empty(),
        "HAND_WRITTEN_RPCS drift vs trait impl:\n\
         in impl but not tested: {missing_from_tests:?}\n\
         tested but not in impl: {extra_in_tests:?}\n\
         hand-written but neither tested nor exempt: {untriaged:?}\n\
         exempt/tested but no longer hand-written: {stale_exempt:?}\n\
         impl context-carrying fns: {impl_names:?}\n\
         HAND_WRITTEN_RPCS: {listed:?}"
    );
}

/// I-2 (W1-L6-01 follow-up): every hand-written, context-carrying RPC body
/// must route its handler call through exactly one `run_context_scoped` — the
/// `*_with_policy` handler invocation must sit INSIDE the scoped async block
/// (later line, deeper brace depth than the `run_context_scoped(` line), so a
/// future edit cannot keep M2 admission while hoisting the handler outside
/// the scope.
#[test]
fn hand_written_context_rpcs_route_through_scope_guard() {
    let rpcs = hand_written_rpcs();
    let mut failures = Vec::new();
    for rpc in &rpcs {
        if !is_context_carrying(rpc) {
            continue;
        }
        let scoped: Vec<(usize, i32)> = rpc
            .lines
            .iter()
            .enumerate()
            .filter(|(_, (_, code, _))| code.contains("run_context_scoped("))
            .map(|(idx, (_, _, depth))| (idx, *depth))
            .collect();
        if scoped.len() != 1 {
            failures.push(format!(
                "{}: expected exactly one `run_context_scoped(` call, found {}",
                rpc.name,
                scoped.len()
            ));
            continue;
        }
        let (scoped_idx, scoped_depth) = scoped[0];
        let handler_calls: Vec<(usize, i32)> = rpc
            .lines
            .iter()
            .enumerate()
            .filter(|(_, (_, code, _))| code.contains("_with_policy("))
            .map(|(idx, (_, _, depth))| (idx, *depth))
            .collect();
        if handler_calls.is_empty() {
            failures.push(format!(
                "{}: no `*_with_policy(` handler call found in body — if the handler \
                 was renamed, extend this scanner's handler-call marker",
                rpc.name
            ));
            continue;
        }
        for (idx, depth) in handler_calls {
            if idx <= scoped_idx || depth <= scoped_depth {
                failures.push(format!(
                    "{}: handler call on body line {} is not nested inside the \
                     `run_context_scoped` async block (handler depth {depth} vs \
                     scoped-call depth {scoped_depth})",
                    rpc.name,
                    idx + 1,
                ));
            }
        }
    }
    assert!(failures.is_empty(), "scope-guard routing drift:\n  {}", failures.join("\n  "));
}
