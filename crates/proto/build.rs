fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/service.proto");
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/types.proto");
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/mechanism_params.proto");
    println!("cargo:rerun-if-changed=secret-fields.toml");

    let redacted = redacted_messages();
    emit_redacted_debug(&redacted)?;

    let schema = parse_schema();
    emit_protected_decode_tables(&schema)?;

    // FOLLOWUP-proto-bytes (deferred, multi-PR project)
    //
    // Migrating selected `bytes` proto fields from `Vec<u8>` to
    // `prost::bytes::Bytes` saves one full-payload memcpy on the
    // gRPC decode path (tonic delivers a `Bytes` slice over the
    // network receive buffer; prost can reference it directly).
    // The win is meaningful for large payloads — `C_Sign` /
    // `C_Decrypt` results, `CKA_VALUE` attribute reads, wrapped-key
    // blobs — potentially MB per call. Negligible for small fields
    // (IVs, nonces, AADs, handles, mechanism IDs).
    //
    // ------------------------------------------------------------------
    // SECURITY: 11 `bytes` fields hold PIN / password material and are
    // wrapped in `Zeroizing<Vec<u8>>` on the server, or live inside
    // `ZeroizeOnDrop`-deriving Rust types in `crates/types`. The
    // `bytes::Bytes` type has NO `Zeroize` impl, and its backing buffer
    // lives in tonic's network receive pool that we cannot reach to
    // wipe. These fields MUST stay `Vec<u8>` to preserve PIN-zeroization
    // (see AGENTS.md §4 and the `panic = "abort"` ban):
    //
    //   * service.proto: LoginRequest.pin
    //   * service.proto: LoginUserRequest.{pin, username}
    //   * service.proto: InitTokenRequest.so_pin
    //   * service.proto: InitPinRequest.pin
    //   * service.proto: SetPinRequest.{old_pin, new_pin}
    //   * mechanism_params.proto: PbeParams.password
    //   * mechanism_params.proto: Pkcs5Pbkd2Params.password
    //   * mechanism_params.proto: SkipjackPrivateWrapParams.password
    //   * mechanism_params.proto: SkipjackRelayxParams.{old_password,
    //                                                     new_password}
    //
    // A global `.bytes(".")` flip would silently regress all of these.
    // That is NOT the destination of this migration.
    // ------------------------------------------------------------------
    //
    // The right shape of the migration:
    //
    // 1. Add a `criterion` bench in `crates/proto` measuring decode-side
    //    allocations at 4 KiB / 64 KiB / 1 MiB / 4 MiB payloads.
    //    Commit baseline numbers BEFORE any flip. Without this, every
    //    per-field migration is unverified.
    //
    // 2. Migrate one field per PR via prost-build's per-field path
    //    override:
    //
    //        tonic_prost_build::configure()
    //            .bytes(&[".pkcs11_proxy_ng.v1.ByteOutputExactResponse.value",
    //                     ...])
    //            ...
    //
    //    NOT `.bytes(".")` — the destination is per-field forever.
    //
    // 3. Each per-field PR MUST land the full cascade together so the
    //    client public API doesn't reintroduce the memcpy via
    //    `Bytes::to_vec()` to preserve its `Vec<u8>` signature:
    //
    //    a. proto field override (this build.rs)
    //    b. the corresponding `crates/types` field
    //       (e.g. `CkOutputBufferResult.value`, `CkAttributeValue::Bytes`)
    //    c. proto `From`/`TryFrom` conversion code
    //    d. client public API return types
    //       (e.g. `client/src/client/crypto/sign_verify.rs`)
    //    e. shim helper signatures
    //       (`shim/src/dispatch/general/helpers/mod.rs::write_exact_output`)
    //    f. all `vec![..]` test literals on that field
    //       → `Bytes::from(vec![..])`
    //
    // Quick-win candidates (large payload, non-sensitive, isolated):
    //
    //   * `ByteOutputExactResponse.value` — covers Sign / Decrypt /
    //     Digest / Encrypt / WrapKey and 13 more via the exact path.
    //   * `AttributeQueryResult.value` — `C_GetAttributeValueExact`.
    //
    // Skip per the security list above. Skip every mechanism-param
    // byte field that is an IV / nonce / AAD / short scalar — no win.
    //
    // Until that PR series lands, keep `Vec<u8>` everywhere — the
    // consistency is more valuable than a half-measure.
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        // W1-C8-02 (D3-S2 codegen Zeroize): decoded password buffers must
        // wipe on drop. The borrow-based conversions copy secrets out of
        // these messages; without drop-wiping the source `Vec`s free plain.
        // Field-covering derive, so future secret fields wipe with no drift.
        .type_attribute(
            ".pkcs11_proxy_ng.v1.SkipjackPrivateWrapParams",
            "#[derive(::zeroize::Zeroize, ::zeroize::ZeroizeOnDrop)]",
        )
        .type_attribute(
            ".pkcs11_proxy_ng.v1.SkipjackRelayxParams",
            "#[derive(::zeroize::Zeroize, ::zeroize::ZeroizeOnDrop)]",
        )
        .skip_debug(redacted.iter().map(|message| format!(".pkcs11_proxy_ng.v1.{message}")))
        .compile_protos(
            &[
                "../../proto/pkcs11-proxy-ng/v1/service.proto",
                "../../proto/pkcs11-proxy-ng/v1/types.proto",
                "../../proto/pkcs11-proxy-ng/v1/mechanism_params.proto",
            ],
            &["../../proto"],
        )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// ADR-0013 redacted generated-message diagnostics (C3M Task 7.2).
//
// prost generates a `Debug` impl for every message and oneof enum, printing
// every field — including secret-classified bytes. The messages in the
// returned set get `skip_debug` above plus a whole-message
// `TypeName([REDACTED])` manual impl emitted below, so no secret payload is
// reachable from any generated `Debug`. The set is derived from the
// classification manifest on every build: a new secret field redacts its
// owner message automatically, with no code change and no permissive default.
// ---------------------------------------------------------------------------

/// Messages redacted at BASE for defense-in-depth although none of their own
/// bytes/string fields is secret-classified (authentication tag/parameter
/// envelopes). Kept so the manifest-driven set never regresses reviewed
/// BASE behavior.
const EXTRA_REDACTED_MESSAGES: &[&str] = &[
    "AuthenticatedParameters",
    "CcmMessageEffects",
    "GcmMessageEffects",
    "MessageParameterEffects",
    "SalsaMessageEffects",
];

const PROTO_FILES: &[&str] = &[
    "../../proto/pkcs11-proxy-ng/v1/service.proto",
    "../../proto/pkcs11-proxy-ng/v1/types.proto",
    "../../proto/pkcs11-proxy-ng/v1/mechanism_params.proto",
];

/// Every secret-bearing message plus [`EXTRA_REDACTED_MESSAGES`], sorted.
fn redacted_messages() -> Vec<String> {
    let manifest = std::fs::read_to_string("secret-fields.toml").expect("read secret-fields.toml");
    let mut in_secret = false;
    let mut messages = std::collections::BTreeSet::new();
    for (line_number, line) in manifest.lines().enumerate() {
        let line = line.trim();
        if line == "[secret]" {
            in_secret = true;
            continue;
        }
        if line.starts_with('[') {
            in_secret = false;
            continue;
        }
        if !in_secret || !line.starts_with('"') {
            continue;
        }
        let field = line
            .split('"')
            .nth(1)
            .unwrap_or_else(|| panic!("malformed manifest line {}", line_number + 1));
        let mut parts = field.split('.');
        match (parts.next(), parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some("pkcs11_proxy_ng"), Some("v1"), Some(message), Some(_), None) => {
                messages.insert(message.to_owned());
            }
            _ => panic!("malformed manifest entry {field:?}"),
        }
    }
    assert!(!messages.is_empty(), "secret-fields.toml [secret] table must not be empty");
    messages.extend(EXTRA_REDACTED_MESSAGES.iter().map(ToString::to_string));
    messages.into_iter().collect()
}

/// Parses `message Parent { ... oneof name { ... } ... }` from the schema.
/// Messages are top-level only; nested messages fail the build so the
/// generator (and its prost module-path mapping) is extended deliberately.
fn message_oneofs() -> Vec<(String, String)> {
    let mut oneofs = Vec::new();
    for path in PROTO_FILES {
        let source = std::fs::read_to_string(path).unwrap_or_else(|_| panic!("read {path}"));
        let mut tokens = Vec::new();
        for line in source.lines() {
            let mut word = String::new();
            for ch in line.split("//").next().unwrap_or_default().chars() {
                if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
                    word.push(ch);
                    continue;
                }
                if !word.is_empty() {
                    tokens.push(std::mem::take(&mut word));
                }
                if ch == '{' || ch == '}' || ch == ';' || ch == '=' {
                    tokens.push(ch.to_string());
                }
            }
            if !word.is_empty() {
                tokens.push(word);
            }
        }
        let mut depth = 0_usize;
        let mut enclosing: Vec<(String, usize)> = Vec::new();
        let mut index = 0;
        while index < tokens.len() {
            match tokens[index].as_str() {
                "message" => {
                    let name = tokens
                        .get(index + 1)
                        .unwrap_or_else(|| panic!("invalid message declaration in {path}"));
                    assert!(
                        !is_message_context(&enclosing),
                        "nested message {name} in {path}: extend the redaction generator first"
                    );
                    enclosing.push((format!("message:{name}"), depth + 1));
                    index += 2;
                }
                "oneof" => {
                    let name = tokens
                        .get(index + 1)
                        .unwrap_or_else(|| panic!("invalid oneof declaration in {path}"));
                    let parent = enclosing
                        .iter()
                        .rev()
                        .find_map(|(context, _)| context.strip_prefix("message:"));
                    let parent = parent
                        .unwrap_or_else(|| panic!("oneof {name} outside a message in {path}"));
                    oneofs.push((parent.to_owned(), name.clone()));
                    index += 2;
                }
                "{" => {
                    depth += 1;
                    index += 1;
                }
                "}" => {
                    depth = depth.checked_sub(1).expect("unbalanced closing brace");
                    enclosing.retain(|(_, message_depth)| *message_depth <= depth);
                    index += 1;
                }
                _ => index += 1,
            }
        }
        assert_eq!(depth, 0, "unbalanced opening brace in {path}");
    }
    oneofs.sort();
    oneofs.dedup();
    oneofs
}

fn is_message_context(enclosing: &[(String, usize)]) -> bool {
    enclosing.iter().any(|(context, _)| context.starts_with("message:"))
}

/// prost module for a message (`AuthenticatedMechanismOutput` ->
/// `authenticated_mechanism_output`) and enum name for a oneof
/// (`output` -> `Output`).
fn prost_oneof_path(parent: &str, oneof: &str) -> String {
    let mut module = String::new();
    let chars: Vec<char> = parent.chars().collect();
    for (index, ch) in chars.iter().enumerate() {
        if ch.is_ascii_uppercase() {
            let prev_lower_or_digit = index > 0
                && (chars[index - 1].is_ascii_lowercase() || chars[index - 1].is_ascii_digit());
            let next_lower = chars.get(index + 1).is_some_and(|next| next.is_ascii_lowercase());
            let prev_upper = index > 0 && chars[index - 1].is_ascii_uppercase();
            if prev_lower_or_digit || (prev_upper && next_lower) {
                module.push('_');
            }
            module.push(ch.to_ascii_lowercase());
        } else {
            module.push(*ch);
        }
    }
    let enumeration: String = oneof
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect();
    format!("{module}::{enumeration}")
}

/// Emits whole-message `TypeName([REDACTED])` impls for every redacted
/// message and every oneof enum under a redacted parent, plus the
/// `REDACTED_WIRE_MESSAGES` const the redaction test audits against the
/// manifest. Included at the crate root by `lib.rs`.
fn emit_redacted_debug(redacted: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let redacted_set: std::collections::BTreeSet<&str> =
        redacted.iter().map(String::as_str).collect();
    let mut out = String::from(
        "// Generated by crates/proto/build.rs from secret-fields.toml + the\n\
         // protobuf schema. Do not edit: change the manifest or schema instead.\n\
         //\n\
         // ADR-0013 redacted generated-message diagnostics. Every message with\n\
         // a secret-classified bytes/string field (plus a fixed set of\n\
         // authentication-envelope extras) has its prost `Debug` skipped and\n\
         // prints only `TypeName([REDACTED])`, so request/response logging and\n\
         // `expect`/`unwrap` payloads cannot disclose secret bytes.\n\
         /// Names of the wire messages whose `Debug` is redacted.\n\
         ///\n\
         /// Audited by `crates/proto/tests/redacted_debug.rs` against\n\
         /// `secret-fields.toml`: every secret-bearing message must occur here.\n\
         pub const REDACTED_WIRE_MESSAGES: &[&str] = &[\n",
    );
    for message in redacted {
        out.push_str(&format!("    \"{message}\",\n"));
    }
    out.push_str("];\n");
    for message in redacted {
        out.push_str(&format!(
            "\nimpl ::std::fmt::Debug for crate::pkcs11_proxy_ng::v1::{message} {{\n\
             \x20   fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {{\n\
             \x20       f.write_str(\"{message}([REDACTED])\")\n\
             \x20   }}\n\
             }}\n"
        ));
    }
    for (parent, oneof) in
        message_oneofs().into_iter().filter(|(parent, _)| redacted_set.contains(parent.as_str()))
    {
        let path = prost_oneof_path(&parent, &oneof);
        let rendered = path.replace("::", ".");
        out.push_str(&format!(
            "\nimpl ::std::fmt::Debug for crate::pkcs11_proxy_ng::v1::{path} {{\n\
             \x20   fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {{\n\
             \x20       f.write_str(\"{rendered}([REDACTED])\")\n\
             \x20   }}\n\
             }}\n"
        ));
    }
    let out_dir = std::env::var("OUT_DIR")?;
    std::fs::write(std::path::Path::new(&out_dir).join("redacted_debug_gen.rs"), out)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// ADR-0013 descriptor-aware pre-decode validation (C3M Task 7.2).
//
// prost decodes a duplicate singular field by replacing the first allocation,
// freeing a possibly long secret buffer without wiping. The daemon therefore
// scans the raw request wire bytes BEFORE tonic/prost decode and rejects
// dangerous encodings. The tables below are the build-time descriptor index
// for that scan: every message's fields (number, repeated label, nested
// message link, oneof membership) plus the gRPC path -> request-message map.
// The validator (`crates/proto/src/protected_decode.rs`) enforces one
// uniform rule: every field number occurs at most once per message level
// except `repeated` fields, every oneof carries at most one member, and
// groups are rejected. No conforming client emits duplicates, so the rule
// has no interop cost. Constructs the validator cannot reason about
// (`map<>`, nested messages, streaming) fail the BUILD, never silently.
// ---------------------------------------------------------------------------

struct SchemaField {
    type_name: String,
    number: u32,
    repeated: bool,
    oneof: Option<String>,
}

struct SchemaMessage {
    name: String,
    fields: Vec<SchemaField>,
    oneofs: Vec<String>,
}

struct Schema {
    package: String,
    service: String,
    messages: Vec<SchemaMessage>,
    enums: Vec<String>,
    rpcs: Vec<(String, String)>,
}

fn tokenize_proto(path: &str) -> Vec<String> {
    let source = std::fs::read_to_string(path).unwrap_or_else(|_| panic!("read {path}"));
    let mut tokens = Vec::new();
    for line in source.lines() {
        let mut word = String::new();
        for ch in line.split("//").next().unwrap_or_default().chars() {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
                word.push(ch);
                continue;
            }
            if !word.is_empty() {
                tokens.push(std::mem::take(&mut word));
            }
            if matches!(ch, '{' | '}' | ';' | '=' | '(' | ')') {
                tokens.push(ch.to_string());
            }
        }
        if !word.is_empty() {
            tokens.push(word);
        }
    }
    tokens
}

fn parse_schema() -> Schema {
    let mut schema = Schema {
        package: String::new(),
        service: String::new(),
        messages: Vec::new(),
        enums: Vec::new(),
        rpcs: Vec::new(),
    };
    for path in PROTO_FILES {
        let tokens = tokenize_proto(path);
        // Block stack: (kind, name). Statements are collected between `;`,
        // `{`, and `}` boundaries and interpreted against the innermost block.
        let mut blocks: Vec<(String, String)> = Vec::new();
        let mut statement: Vec<String> = Vec::new();
        let mut index = 0;
        while index < tokens.len() {
            let token = tokens[index].as_str();
            match token {
                "{" => {
                    assert_eq!(
                        statement.len(),
                        2,
                        "malformed block header {statement:?} in {path}"
                    );
                    let kind = [statement[0].as_str(), statement[1].as_str()];
                    match kind {
                        ["message", message] => {
                            assert!(
                                !blocks.iter().any(|(kind, _)| kind == "message"),
                                "nested message {message} in {path}: extend the generators first"
                            );
                            schema.messages.push(SchemaMessage {
                                name: message.to_owned(),
                                fields: Vec::new(),
                                oneofs: Vec::new(),
                            });
                            blocks.push(("message".to_owned(), message.to_owned()));
                        }
                        ["enum", name] | ["service", name] => {
                            blocks.push((kind[0].to_owned(), name.to_owned()));
                        }
                        ["oneof", name] => {
                            assert!(
                                blocks.last().is_some_and(|(kind, _)| kind == "message"),
                                "oneof {name} outside a message in {path}"
                            );
                            let message = schema.messages.last_mut().expect("message context");
                            assert!(
                                !message.oneofs.iter().any(|oneof| oneof == name),
                                "duplicate oneof {name} in {path}"
                            );
                            message.oneofs.push(name.to_owned());
                            blocks.push(("oneof".to_owned(), name.to_owned()));
                        }
                        _ => panic!("unexpected block header {kind:?} in {path}"),
                    }
                    statement.clear();
                    index += 1;
                }
                "}" => {
                    assert!(statement.is_empty(), "unterminated statement in {path}");
                    let (kind, name) = blocks.pop().expect("unbalanced closing brace");
                    if kind == "enum" {
                        schema.enums.push(name);
                    } else if kind == "service" {
                        assert!(
                            schema.service.is_empty(),
                            "second service block in {path}: extend the generator first"
                        );
                        schema.service = name;
                    }
                    index += 1;
                }
                ";" => {
                    interpret_statement(&mut schema, &blocks, &statement, path);
                    statement.clear();
                    index += 1;
                }
                _ => {
                    statement.push(tokens[index].clone());
                    index += 1;
                }
            }
        }
        assert!(blocks.is_empty(), "unbalanced opening brace in {path}");
    }
    assert!(!schema.package.is_empty(), "missing package declaration");
    assert!(!schema.service.is_empty(), "missing service declaration");
    assert!(!schema.messages.is_empty(), "no messages parsed");
    assert!(!schema.rpcs.is_empty(), "no rpc methods parsed");
    schema.messages.sort_by(|left, right| left.name.cmp(&right.name));
    schema.rpcs.sort();
    schema
}

fn interpret_statement(
    schema: &mut Schema,
    blocks: &[(String, String)],
    statement: &[String],
    path: &str,
) {
    if statement.is_empty() {
        return;
    }
    let words: Vec<&str> = statement.iter().map(String::as_str).collect();
    match blocks.last() {
        None => {
            // File level: only `package` / `syntax` / `import` may appear.
            if words[0] == "package" {
                assert_eq!(words.len(), 2, "malformed package declaration in {path}");
                if schema.package.is_empty() {
                    schema.package = words[1].to_owned();
                } else {
                    assert_eq!(schema.package, words[1], "second package in {path}");
                }
            }
        }
        Some((kind, _)) if kind == "enum" => {}
        Some((kind, _)) if kind == "service" => match &words[..] {
            ["rpc", _method, "(", request, ")", "returns", "(", _response, ")"] => {
                assert!(
                    !request.contains("stream"),
                    "streaming rpc in {path}: extend the validator first"
                );
                schema.rpcs.push((words[1].to_owned(), (*request).to_owned()));
            }
            _ => panic!("unexpected service statement {words:?} in {path}"),
        },
        Some((kind, name)) if kind == "message" || kind == "oneof" => {
            // Owner message: the block itself for `message`, the enclosing
            // block for `oneof` (oneofs nest exactly one level deep).
            let owner = if *kind == "message" {
                name
            } else {
                assert!(blocks.len() >= 2, "oneof {name} outside a message in {path}");
                assert_eq!(blocks[blocks.len() - 2].0, "message");
                &blocks[blocks.len() - 2].1
            };
            let (repeated, rest) = match &words[..] {
                ["repeated", rest @ ..] => (true, rest),
                ["optional", rest @ ..] => (false, rest),
                _ => (false, &words[..]),
            };
            match rest {
                [type_name, _field, "=", number] => {
                    assert!(
                        !type_name.starts_with("map"),
                        "map field in {path}: extend the validator first"
                    );
                    let number: u32 =
                        number.parse().unwrap_or_else(|_| panic!("bad field number in {path}"));
                    assert!((1..536_870_912).contains(&number), "field number out of range");
                    let message = schema.messages.last_mut().expect("message context");
                    assert_eq!(&message.name, owner, "message context drift in {path}");
                    assert!(
                        message.fields.iter().all(|field| field.number != number),
                        "duplicate field number {number} in {path}"
                    );
                    if *kind == "oneof" {
                        assert!(!repeated, "repeated oneof member in {path}");
                    }
                    message.fields.push(SchemaField {
                        type_name: (*type_name).to_owned(),
                        number,
                        repeated,
                        oneof: if *kind == "oneof" { Some(name.clone()) } else { None },
                    });
                }
                _ => panic!("unexpected message statement {words:?} in {path}"),
            }
        }
        Some((kind, _)) => panic!("unexpected {kind} statement {words:?} in {path}"),
    }
}

const SCALAR_TYPES: &[&str] = &[
    "double", "float", "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32",
    "fixed64", "sfixed32", "sfixed64", "bool", "string", "bytes",
];

/// Message index for a field type, or `u32::MAX` for scalars/bytes/enums.
fn nested_index(schema: &Schema, type_name: &str, path: &str) -> u32 {
    let short = type_name.rsplit('.').next().unwrap_or(type_name);
    if SCALAR_TYPES.contains(&short) || schema.enums.iter().any(|name| name == short) {
        return u32::MAX;
    }
    schema
        .messages
        .iter()
        .position(|message| message.name == short)
        .unwrap_or_else(|| panic!("unknown field type {type_name} ({path})")) as u32
}

fn emit_protected_decode_tables(schema: &Schema) -> Result<(), Box<dyn std::error::Error>> {
    let mut out = String::from(
        "// Generated by crates/proto/build.rs from the protobuf schema. Do not edit.\n\
         //\n\
         // Descriptor index for `super::protected_decode`: per-message field\n\
         // numbers with their `repeated` label, nested-message link, and oneof\n\
         // membership, plus the gRPC path -> request-message map.\n\
         pub(crate) struct MessageDesc {\n\
         \x20   pub name: &'static str,\n\
         \x20   pub fields: &'static [FieldDesc],\n\
         }\n\
         pub(crate) struct FieldDesc {\n\
         \x20   pub number: u32,\n\
         \x20   pub repeated: bool,\n\
         \x20   pub nested: u32,\n\
         \x20   pub oneof: u32,\n\
         }\n\
         pub(crate) const NO_NESTED: u32 = u32::MAX;\n\
         pub(crate) const NO_ONEOF: u32 = u32::MAX;\n\
         pub(crate) static REQUEST_MESSAGES: &[(&str, u32)] = &[\n",
    );
    for (method, request) in &schema.rpcs {
        let index = schema
            .messages
            .iter()
            .position(|message| &message.name == request)
            .unwrap_or_else(|| panic!("unknown request type {request}"));
        out.push_str(&format!(
            "    (\"/{}.{}/{method}\", {index}),\n",
            schema.package, schema.service
        ));
    }
    out.push_str("];\n    pub(crate) static MESSAGE_DESCRIPTORS: &[MessageDesc] = &[\n");
    for message in &schema.messages {
        let mut fields = message.fields.iter().collect::<Vec<_>>();
        fields.sort_by_key(|field| field.number);
        out.push_str(&format!("    MessageDesc {{ name: \"{}\", fields: &[\n", message.name));
        for field in fields {
            let nested = nested_index(schema, &field.type_name, &message.name);
            let nested =
                if nested == u32::MAX { "NO_NESTED".to_owned() } else { nested.to_string() };
            let oneof = field.oneof.as_ref().map_or("NO_ONEOF".to_owned(), |name| {
                message
                    .oneofs
                    .iter()
                    .position(|oneof| oneof == name)
                    .expect("oneof context")
                    .to_string()
            });
            out.push_str(&format!(
                "        FieldDesc {{ number: {}, repeated: {}, nested: {nested}, oneof: {oneof} }},\n",
                field.number, field.repeated
            ));
        }
        out.push_str("    ] },\n");
    }
    out.push_str("];\n");
    // Fail closed if a future schema edit introduces nesting the tables
    // cannot express (oneof members already assert non-repeated above).
    let out_dir = std::env::var("OUT_DIR")?;
    std::fs::write(std::path::Path::new(&out_dir).join("protected_decode_tables.rs"), out)?;
    Ok(())
}
