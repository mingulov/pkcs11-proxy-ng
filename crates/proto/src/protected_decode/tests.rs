//! White-box descriptor-table tests. Behavioral wire tests live in
//! `crates/proto/tests/protected_decode.rs`.

use std::collections::{BTreeMap, BTreeSet};

use super::{FieldDesc, MESSAGE_DESCRIPTORS, MessageDesc, NO_NESTED, NO_ONEOF, REQUEST_MESSAGES};

#[test]
fn request_table_covers_every_rpc_method() {
    assert_eq!(REQUEST_MESSAGES.len(), 106);
    let mut paths: Vec<&str> = REQUEST_MESSAGES.iter().map(|(path, _)| *path).collect();
    let sorted = {
        let mut sorted = paths.clone();
        sorted.sort();
        sorted
    };
    assert_eq!(paths, sorted, "REQUEST_MESSAGES must be sorted for binary search");
    paths.dedup();
    assert_eq!(paths.len(), 106, "duplicate request paths");
    assert!(
        REQUEST_MESSAGES
            .iter()
            .all(|(path, _)| path.starts_with("/pkcs11_proxy_ng.v1.Pkcs11Proxy/")),
        "unexpected service path prefix"
    );
    assert!(
        REQUEST_MESSAGES.contains(&("/pkcs11_proxy_ng.v1.Pkcs11Proxy/Login", 0))
            || REQUEST_MESSAGES.iter().any(|(path, _)| path.ends_with("/Login")),
        "Login must be covered"
    );
}

#[test]
fn message_descriptors_match_schema_spot_checks() {
    let login = MESSAGE_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.name == "LoginRequest")
        .expect("LoginRequest descriptor");
    assert_eq!(login.fields.len(), 4);
    assert!(login.fields.iter().all(|field| !field.repeated));
    assert!(login.fields.iter().all(|field| field.nested == NO_NESTED));
    assert!(login.fields.iter().all(|field| field.oneof == NO_ONEOF));

    let attribute = MESSAGE_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.name == "Attribute")
        .expect("Attribute descriptor");
    assert_eq!(attribute.fields.len(), 6);
    // attr_type is a plain singular scalar; the rest share one oneof.
    assert_eq!(attribute.fields[0].number, 1);
    assert_eq!(attribute.fields[0].oneof, NO_ONEOF);
    for field in &attribute.fields[1..] {
        assert_eq!(field.oneof, 0, "field {} must be in oneof 0", field.number);
        assert!(!field.repeated);
    }
    // nested_template links to the NestedAttributes descriptor.
    let nested = MESSAGE_DESCRIPTORS
        .iter()
        .position(|descriptor| descriptor.name == "NestedAttributes")
        .expect("NestedAttributes descriptor") as u32;
    assert_eq!(attribute.fields[5].nested, nested);

    let find = MESSAGE_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.name == "FindObjectsInitRequest")
        .expect("FindObjectsInitRequest descriptor");
    let template = find.fields.iter().find(|field| field.number == 3).expect("template");
    assert!(template.repeated);
    assert_ne!(template.nested, NO_NESTED);
}

#[test]
fn nested_links_resolve_inside_the_table() {
    for descriptor in MESSAGE_DESCRIPTORS {
        for field in descriptor.fields {
            if field.nested != NO_NESTED {
                assert!(
                    (field.nested as usize) < MESSAGE_DESCRIPTORS.len(),
                    "dangling nested link in {}",
                    descriptor.name
                );
            }
        }
    }
    for (_, index) in REQUEST_MESSAGES {
        assert!((*index as usize) < MESSAGE_DESCRIPTORS.len(), "dangling request link");
    }
}

// ---------------------------------------------------------------------------
// Exhaustive descriptor-table-vs-prost-tag cross-validation (C3M Task 7 fix).
//
// `build.rs` parses the `.proto` schema with its own tokenizer while prost
// parses it with `protoc`-grade machinery. A silent `build.rs` mis-parse — a
// dropped field, a wrong number, a missed `repeated`/`oneof` label, a bad
// nested link — would fail open: the validator would enforce prost's
// replace/append/discard semantics against the wrong descriptor. These tests
// close that gap by asserting the generated tables against prost's own
// attributes in the generated `pkcs11_proxy_ng.v1.rs` for EVERY message: the
// committed form of the implementer-run 328/328 check, extended to the 3
// oneof-only messages (whose members live in `tags = "..."` lists), exact
// nested-link targets, and the rpc-path table.
// ---------------------------------------------------------------------------

/// prost's CamelCase mapping turns `ID` into `Id` in Rust type names. The
/// renames are descriptor-irrelevant (field numbers are what matter) but are
/// mapped explicitly so a future silent rename fails closed as a message
/// mismatch instead of passing silently.
const PROST_RENAMES: &[(&str, &str)] =
    &[("AsyncGetIDRequest", "AsyncGetIdRequest"), ("AsyncGetIDResponse", "AsyncGetIdResponse")];

fn prost_name_for(schema_name: &str) -> &str {
    PROST_RENAMES
        .iter()
        .find(|(source, _)| *source == schema_name)
        .map(|(_, target)| *target)
        .unwrap_or(schema_name)
}

fn schema_name_for(prost_name: &str) -> &str {
    PROST_RENAMES
        .iter()
        .find(|(_, target)| *target == prost_name)
        .map(|(source, _)| *source)
        .unwrap_or(prost_name)
}

fn nested_target(field: &FieldDesc) -> Option<&'static str> {
    if field.nested == NO_NESTED {
        None
    } else {
        Some(
            MESSAGE_DESCRIPTORS
                .get(field.nested as usize)
                .unwrap_or_else(|| panic!("dangling nested link {}", field.nested))
                .name,
        )
    }
}

#[test]
fn message_descriptors_match_prost_tags_exhaustively() {
    let generated = std::fs::read_to_string(concat!(env!("OUT_DIR"), "/pkcs11_proxy_ng.v1.rs"))
        .expect("prost output must exist: build.rs compiles the protos before tests run");
    let (prost_messages, oneof_modules) = parse_prost_generated(&generated);

    let mut prost_by_name = BTreeMap::new();
    for message in &prost_messages {
        assert!(
            prost_by_name.insert(message.name.as_str(), message).is_none(),
            "duplicate prost struct {}",
            message.name
        );
    }
    let mut descriptor_names = BTreeSet::new();
    let mut renames_used = BTreeSet::new();
    let mut referenced_modules = BTreeSet::new();
    for descriptor in MESSAGE_DESCRIPTORS {
        assert!(
            descriptor_names.insert(descriptor.name),
            "duplicate descriptor {}",
            descriptor.name
        );
        let expected = prost_name_for(descriptor.name);
        if expected != descriptor.name {
            renames_used.insert(descriptor.name);
        }
        let prost = prost_by_name.get(expected).unwrap_or_else(|| {
            panic!("descriptor {} has no prost struct (expected {expected})", descriptor.name)
        });
        compare_message(descriptor, prost, &oneof_modules, &mut referenced_modules);
    }
    assert_eq!(
        renames_used.len(),
        PROST_RENAMES.len(),
        "prost rename map drifted: used {renames_used:?}, declared {PROST_RENAMES:?}"
    );
    for message in &prost_messages {
        assert!(
            descriptor_names.contains(schema_name_for(&message.name)),
            "prost struct {} has no descriptor",
            message.name
        );
    }
    assert_eq!(
        referenced_modules,
        oneof_modules.keys().cloned().collect::<BTreeSet<_>>(),
        "oneof module reference drift"
    );
    assert_eq!(prost_messages.len(), MESSAGE_DESCRIPTORS.len(), "message count drift");
}

#[test]
fn request_table_matches_service_definition_exhaustively() {
    let service = include_str!("../../../../proto/pkcs11-proxy-ng/v1/service.proto");
    let mut rpcs = BTreeMap::new();
    for line in service.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("rpc ") else { continue };
        // `Method(Request) returns (Response);`
        let (method, rest) = rest.split_once('(').expect("malformed rpc line");
        let (request, _) = rest.split_once(')').expect("malformed rpc line");
        assert!(
            rpcs.insert(method.to_owned(), request.to_owned()).is_none(),
            "duplicate rpc {method}"
        );
    }
    assert_eq!(rpcs.len(), REQUEST_MESSAGES.len(), "rpc count drift");
    for (path, index) in REQUEST_MESSAGES {
        let method = path.rsplit('/').next().expect("malformed path");
        let request =
            rpcs.get(method).unwrap_or_else(|| panic!("request path without rpc def: {path}"));
        let descriptor = MESSAGE_DESCRIPTORS.get(*index as usize).expect("dangling request link");
        assert_eq!(&descriptor.name, request, "wrong request type for {path}");
    }
}

fn compare_message(
    descriptor: &MessageDesc,
    prost: &ProstMessage,
    oneof_modules: &BTreeMap<String, Vec<ProstVariant>>,
    referenced_modules: &mut BTreeSet<String>,
) {
    // Regular fields: number + repeated label + exact nested target.
    let mut expected_regular: Vec<(u32, bool, Option<&str>)> = descriptor
        .fields
        .iter()
        .filter(|field| field.oneof == NO_ONEOF)
        .map(|field| (field.number, field.repeated, nested_target(field)))
        .collect();
    expected_regular.sort();
    let mut actual_regular: Vec<(u32, bool, Option<&str>)> = prost
        .fields
        .iter()
        .map(|field| (field.number, field.repeated, field.message.as_deref().map(schema_name_for)))
        .collect();
    actual_regular.sort();
    assert_eq!(actual_regular, expected_regular, "descriptor drift for {}", descriptor.name);

    // Oneof members: the union of prost `tags` lists must equal the
    // descriptor's oneof numbers; each list must match its enum module
    // exactly; members are never repeated and resolve to the exact nested
    // target.
    let descriptor_oneof: Vec<&FieldDesc> =
        descriptor.fields.iter().filter(|field| field.oneof != NO_ONEOF).collect();
    for field in &descriptor_oneof {
        assert!(!field.repeated, "repeated oneof member {} in {}", field.number, descriptor.name);
    }
    let mut group_indices = BTreeSet::new();
    let mut actual_tags = Vec::new();
    for oneof in &prost.oneofs {
        assert!(
            referenced_modules.insert(oneof.module.clone()),
            "oneof module {} referenced twice",
            oneof.module
        );
        let variants = oneof_modules
            .get(&oneof.module)
            .unwrap_or_else(|| panic!("prost oneof module {} without enum", oneof.module));
        let mut variant_tags: Vec<u32> = variants.iter().map(|variant| variant.number).collect();
        variant_tags.sort();
        let mut listed = oneof.tags.clone();
        listed.sort();
        assert_eq!(
            listed, variant_tags,
            "tags list drift for {}.{}",
            descriptor.name, oneof.module
        );
        // Members of one list share one descriptor oneof index.
        let mut indices = BTreeSet::new();
        for number in &listed {
            let field = descriptor_oneof
                .iter()
                .find(|field| field.number == *number)
                .unwrap_or_else(|| {
                    panic!(
                        "prost oneof member {number} of {} missing from descriptor",
                        descriptor.name
                    )
                });
            indices.insert(field.oneof);
            let expected = nested_target(field);
            let actual = variants
                .iter()
                .find(|variant| variant.number == *number)
                .and_then(|variant| variant.message.as_deref())
                .map(schema_name_for);
            assert_eq!(
                actual, expected,
                "nested target drift for oneof member {number} of {}",
                descriptor.name
            );
        }
        assert_eq!(
            indices.len(),
            1,
            "oneof list split across descriptor groups in {}",
            descriptor.name
        );
        group_indices.insert(*indices.iter().next().expect("oneof list must not be empty"));
        actual_tags.extend(listed);
    }
    assert_eq!(
        group_indices.len(),
        prost.oneofs.len(),
        "oneof lists share a descriptor group in {}",
        descriptor.name
    );
    let mut expected_tags: Vec<u32> = descriptor_oneof.iter().map(|field| field.number).collect();
    expected_tags.sort();
    actual_tags.sort();
    assert_eq!(actual_tags, expected_tags, "oneof member drift for {}", descriptor.name);
}

struct ProstField {
    number: u32,
    repeated: bool,
    message: Option<String>,
}

struct ProstOneof {
    module: String,
    tags: Vec<u32>,
}

struct ProstMessage {
    name: String,
    fields: Vec<ProstField>,
    oneofs: Vec<ProstOneof>,
}

struct ProstVariant {
    number: u32,
    message: Option<String>,
}

struct ProstAttr {
    tag: Option<u32>,
    tags: Vec<u32>,
    oneof: Option<String>,
    repeated: bool,
    message: bool,
}

enum Pending {
    Field { number: u32, repeated: bool },
    Variant { number: u32 },
}

/// Parses message structs and oneof-enum modules out of the generated
/// `pkcs11_proxy_ng.v1.rs`. Fails closed: any construct it does not
/// understand panics instead of being skipped.
fn parse_prost_generated(source: &str) -> (Vec<ProstMessage>, BTreeMap<String, Vec<ProstVariant>>) {
    /// Tonic service modules: traversed only for brace matching, never mined.
    const SERVICE_MODULES: &[&str] = &["pkcs11_proxy_client", "pkcs11_proxy_server"];

    #[derive(Debug, PartialEq, Eq)]
    enum State {
        Outside,
        Struct,
        Module,
        Enum,
        Impl,
    }

    let mut messages = Vec::new();
    let mut oneof_modules: BTreeMap<String, Vec<ProstVariant>> = BTreeMap::new();
    let mut service_seen = BTreeSet::new();

    let mut state = State::Outside;
    let mut message = None::<ProstMessage>;
    // Oneof module under construction: (name, variants, enum seen).
    let mut module = None::<(String, Vec<ProstVariant>, bool)>;
    let mut module_skipped = false;
    let mut attr = String::new();
    let mut pending = None::<Pending>;
    let mut decl = String::new();

    for (index, line) in source.lines().enumerate() {
        let at = index + 1;
        let trimmed = line.trim();

        // Multi-line `#[prost(...)]` continuation (rustfmt splits long oneof tags).
        if !attr.is_empty() {
            assert!(
                matches!(state, State::Struct | State::Module),
                "stray attribute continuation at generated line {at}"
            );
            assert!(
                !trimmed.starts_with("#[prost("),
                "nested prost attribute at generated line {at}"
            );
            attr.push(' ');
            attr.push_str(trimmed);
            if trimmed.ends_with(")]") {
                let joined = std::mem::take(&mut attr);
                let info = parse_prost_attr(&joined, at);
                finish_attr(info, &joined, at, &mut message, &mut module, &mut pending);
            }
            continue;
        }

        if trimmed.starts_with("#[prost(") {
            assert!(pending.is_none(), "missing declaration after message type at line {at}");
            // Redacted oneof enums carry `skip_debug` inside their module.
            if trimmed == "#[prost(skip_debug)]" && state == State::Module && !module_skipped {
                continue;
            }
            let mined = state == State::Struct || (state == State::Module && !module_skipped);
            if mined {
                attr.push_str(trimmed);
                if trimmed.ends_with(")]") {
                    let joined = std::mem::take(&mut attr);
                    let info = parse_prost_attr(&joined, at);
                    finish_attr(info, &joined, at, &mut message, &mut module, &mut pending);
                }
            } else if state == State::Outside {
                assert_eq!(
                    trimmed, "#[prost(skip_debug)]",
                    "unexpected top-level prost attribute at generated line {at}: {trimmed:?}"
                );
            } else {
                panic!("unexpected prost attribute at generated line {at}: {trimmed:?}");
            }
            continue;
        }

        // Declaration lines following a message-typed attribute carry its
        // type (rustfmt may split long types across lines: complete at a
        // trailing comma with balanced brackets).
        if pending.is_some() && !trimmed.is_empty() {
            assert!(trimmed != "}", "missing declaration after message type at line {at}");
            decl.push(' ');
            decl.push_str(trimmed);
            let balanced = |open: char, close: char| {
                decl.chars().filter(|ch| *ch == open).count()
                    == decl.chars().filter(|ch| *ch == close).count()
            };
            if !(trimmed.ends_with(',') && balanced('<', '>') && balanced('(', ')')) {
                continue;
            }
            let joined_decl = std::mem::take(&mut decl);
            let joined_decl = joined_decl.trim();
            match pending.take() {
                Some(Pending::Field { number, repeated }) => {
                    assert_eq!(state, State::Struct, "stray field type at line {at}");
                    let ty = field_message_type(joined_decl, at);
                    message
                        .as_mut()
                        .expect("field type outside a struct")
                        .fields
                        .push(ProstField { number, repeated, message: Some(ty) });
                }
                Some(Pending::Variant { number }) => {
                    assert_eq!(state, State::Module, "stray variant type at line {at}");
                    let ty = variant_message_type(joined_decl, at);
                    module
                        .as_mut()
                        .expect("variant type outside a module")
                        .1
                        .push(ProstVariant { number, message: Some(ty) });
                }
                None => unreachable!("pending checked above"),
            }
            continue;
        }

        if line == "}" {
            assert!(pending.is_none(), "missing declaration after message type at line {at}");
            match state {
                State::Outside => panic!("unmatched closing brace at generated line {at}"),
                State::Struct => {
                    messages.push(message.take().expect("struct close without a struct"));
                    state = State::Outside;
                }
                State::Module => {
                    if module_skipped {
                        module_skipped = false;
                    } else {
                        let (name, variants, enum_seen) =
                            module.take().expect("module close without a module");
                        assert!(enum_seen, "non-enum module {name} at generated line {at}");
                        assert!(
                            oneof_modules.insert(name.clone(), variants).is_none(),
                            "duplicate module {name}"
                        );
                    }
                    state = State::Outside;
                }
                State::Enum | State::Impl => state = State::Outside,
            }
            continue;
        }

        match state {
            State::Outside => {
                if trimmed.is_empty() || trimmed.starts_with("///") || trimmed.starts_with("//") {
                    continue;
                }
                assert!(
                    !line.starts_with(' ') && !line.starts_with('\t'),
                    "indented line outside any item at generated line {at}: {trimmed:?}"
                );
                if let Some(rest) = line.strip_prefix("pub struct ") {
                    let name = rest.split([' ', '<', '{']).next().unwrap_or_default();
                    assert!(!name.is_empty(), "malformed struct header at line {at}");
                    // Empty messages are emitted one-line (`pub struct Name {}`).
                    if line.trim_end().ends_with("{}") {
                        messages.push(ProstMessage {
                            name: name.to_owned(),
                            fields: Vec::new(),
                            oneofs: Vec::new(),
                        });
                        continue;
                    }
                    message = Some(ProstMessage {
                        name: name.to_owned(),
                        fields: Vec::new(),
                        oneofs: Vec::new(),
                    });
                    state = State::Struct;
                } else if let Some(rest) = line.strip_prefix("pub mod ") {
                    let name = rest.split([' ', '{']).next().unwrap_or_default();
                    assert!(!name.is_empty(), "malformed module header at line {at}");
                    if SERVICE_MODULES.contains(&name) {
                        service_seen.insert(name.to_owned());
                        module_skipped = true;
                    } else {
                        module = Some((name.to_owned(), Vec::new(), false));
                    }
                    state = State::Module;
                } else if line.starts_with("pub enum ") {
                    state = State::Enum;
                } else if line.starts_with("impl ") {
                    state = State::Impl;
                } else if line.starts_with("#[") {
                    assert!(
                        line.starts_with("#[derive") || line == "#[repr(i32)]",
                        "unexpected top-level attribute at generated line {at}: {trimmed:?}"
                    );
                } else {
                    panic!("unexpected top-level line at generated line {at}: {trimmed:?}");
                }
            }
            State::Struct | State::Module | State::Enum | State::Impl => {
                assert!(
                    line.is_empty() || line.starts_with(' ') || line.starts_with('\t'),
                    "top-level line inside an item at generated line {at}: {trimmed:?}"
                );
                if state == State::Module && !module_skipped {
                    if trimmed.starts_with("pub enum ") {
                        let module = module.as_mut().expect("enum outside a module");
                        assert!(!module.2, "second enum in module {}", module.0);
                        module.2 = true;
                    } else {
                        assert!(
                            !trimmed.starts_with("pub struct ") && !trimmed.starts_with("pub mod "),
                            "unexpected item in module at generated line {at}: {trimmed:?}"
                        );
                    }
                } else if state == State::Struct {
                    assert!(
                        !trimmed.starts_with("pub struct ")
                            && !trimmed.starts_with("pub mod ")
                            && !trimmed.starts_with("pub enum "),
                        "unexpected item in struct at generated line {at}: {trimmed:?}"
                    );
                }
            }
        }
    }

    assert_eq!(state, State::Outside, "unterminated item in generated prost output");
    assert!(attr.is_empty(), "unterminated prost attribute in generated output");
    assert!(pending.is_none(), "trailing message type without a declaration");
    assert!(decl.is_empty(), "trailing declaration without a terminator");
    assert_eq!(
        service_seen,
        BTreeSet::from(["pkcs11_proxy_client".to_owned(), "pkcs11_proxy_server".to_owned()]),
        "tonic service module drift"
    );
    (messages, oneof_modules)
}

fn finish_attr(
    info: ProstAttr,
    joined: &str,
    at: usize,
    message: &mut Option<ProstMessage>,
    module: &mut Option<(String, Vec<ProstVariant>, bool)>,
    pending: &mut Option<Pending>,
) {
    // Struct-field attributes carry `tag` or (`oneof` + `tags`); oneof-enum
    // variant attributes carry `tag` only. The two states are distinguished
    // by which slot is under construction.
    if message.is_some() {
        let message = message.as_mut().expect("struct attribute without a struct");
        match (info.tag, info.oneof) {
            (Some(number), None) => {
                assert!(info.tags.is_empty(), "field with tags list at line {at}: {joined:?}");
                if info.message {
                    *pending = Some(Pending::Field { number, repeated: info.repeated });
                } else {
                    message.fields.push(ProstField {
                        number,
                        repeated: info.repeated,
                        message: None,
                    });
                }
            }
            (None, Some(oneof)) => {
                assert!(
                    !info.message && !info.repeated,
                    "qualified oneof attribute at line {at}: {joined:?}"
                );
                assert!(!info.tags.is_empty(), "oneof without tags at line {at}: {joined:?}");
                let (module_name, _) = oneof
                    .split_once("::")
                    .unwrap_or_else(|| panic!("malformed oneof path at line {at}: {joined:?}"));
                message.oneofs.push(ProstOneof { module: module_name.to_owned(), tags: info.tags });
            }
            _ => panic!("prost attribute is neither field nor oneof at line {at}: {joined:?}"),
        }
    } else {
        let module = module.as_mut().expect("variant attribute outside a module");
        let number =
            info.tag.unwrap_or_else(|| panic!("variant without tag at line {at}: {joined:?}"));
        assert!(
            info.tags.is_empty() && info.oneof.is_none(),
            "qualified variant at line {at}: {joined:?}"
        );
        assert!(!info.repeated, "repeated variant at line {at}: {joined:?}");
        if info.message {
            *pending = Some(Pending::Variant { number });
        } else {
            module.1.push(ProstVariant { number, message: None });
        }
    }
}

fn parse_prost_attr(joined: &str, at: usize) -> ProstAttr {
    let inner = joined
        .strip_prefix("#[prost(")
        .and_then(|rest| rest.strip_suffix(")]"))
        .unwrap_or_else(|| panic!("malformed prost attribute at generated line {at}: {joined:?}"));
    assert!(!inner.contains('\\'), "unexpected escape at generated line {at}: {joined:?}");
    let mut attr =
        ProstAttr { tag: None, tags: Vec::new(), oneof: None, repeated: false, message: false };
    for part in split_top_level_commas(inner) {
        let part = part.trim();
        if part == "message" {
            attr.message = true;
        } else if part == "repeated" {
            attr.repeated = true;
        } else if let Some(number) = part.strip_prefix("tag = ") {
            assert!(attr.tag.is_none(), "duplicate tag at line {at}: {joined:?}");
            attr.tag = Some(parse_quoted_u32(number, joined, at));
        } else if let Some(list) = part.strip_prefix("tags = ") {
            assert!(attr.tags.is_empty(), "duplicate tags at line {at}: {joined:?}");
            let list = list
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
                .unwrap_or_else(|| panic!("malformed tags list at line {at}: {joined:?}"));
            attr.tags = list
                .split(',')
                .map(|number| {
                    number
                        .trim()
                        .parse()
                        .unwrap_or_else(|_| panic!("bad tag number at line {at}: {joined:?}"))
                })
                .collect();
        } else if let Some(path) = part.strip_prefix("oneof = ") {
            assert!(attr.oneof.is_none(), "duplicate oneof at line {at}: {joined:?}");
            let path = path
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
                .unwrap_or_else(|| panic!("malformed oneof path at line {at}: {joined:?}"));
            attr.oneof = Some(path.to_owned());
        } else if part == "optional"
            || part == "boxed"
            || part.starts_with("enumeration")
            || matches!(
                part,
                "bool"
                    | "string"
                    | "bytes"
                    | "bytes = \"vec\""
                    | "float"
                    | "double"
                    | "int32"
                    | "int64"
                    | "uint32"
                    | "uint64"
                    | "sint32"
                    | "sint64"
                    | "fixed32"
                    | "fixed64"
                    | "sfixed32"
                    | "sfixed64"
            )
        {
            // Scalar kind or encoding detail the descriptor does not model.
        } else {
            panic!("unrecognized prost attribute part at line {at}: {part:?} ({joined:?})");
        }
    }
    attr
}

fn split_top_level_commas(attr: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    for (index, ch) in attr.char_indices() {
        if ch == '"' {
            quoted = !quoted;
        } else if ch == ',' && !quoted {
            parts.push(&attr[start..index]);
            start = index + 1;
        }
    }
    parts.push(&attr[start..]);
    parts
}

fn parse_quoted_u32(quoted: &str, joined: &str, at: usize) -> u32 {
    let number = quoted
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or_else(|| panic!("malformed tag number at line {at}: {joined:?}"));
    number.parse().unwrap_or_else(|_| panic!("bad tag number at line {at}: {joined:?}"))
}

/// Extracts the bare message name from a struct field declaration
/// (`pub name: [Option<Vec<Box>>...<]Message>,`).
fn field_message_type(decl: &str, at: usize) -> String {
    let ty = decl
        .split_once(':')
        .unwrap_or_else(|| panic!("malformed field declaration at line {at}: {decl:?}"))
        .1;
    let ty = ty
        .trim()
        .strip_suffix(',')
        .unwrap_or_else(|| {
            panic!("field declaration without trailing comma at line {at}: {decl:?}")
        })
        .trim();
    let normalized = normalize_type(ty);
    bare_message_name(unwrap_containers(&normalized, decl, at), decl, at)
}

/// Collapses rustfmt's multi-line generic layout (`Option<\n Box<X>,\n>`)
/// back to single-line form. Single-line types pass through unchanged.
fn normalize_type(ty: &str) -> String {
    ty.replace(char::is_whitespace, "").replace(",>", ">")
}

fn unwrap_containers<'a>(mut ty: &'a str, decl: &str, at: usize) -> &'a str {
    for _ in 0..8 {
        let mut inner = None;
        for prefix in
            ["::core::option::Option<", "::prost::alloc::vec::Vec<", "::prost::alloc::boxed::Box<"]
        {
            if let Some(rest) = ty.strip_prefix(prefix) {
                inner =
                    Some(rest.strip_suffix('>').unwrap_or_else(|| {
                        panic!("unbalanced container type at line {at}: {decl:?}")
                    }));
                break;
            }
        }
        match inner {
            Some(rest) => ty = rest.trim(),
            None => return ty,
        }
    }
    panic!("container nesting too deep at line {at}: {decl:?}")
}

/// Extracts the bare message name from a oneof variant declaration
/// (`Variant([super::]Message),`).
fn variant_message_type(decl: &str, at: usize) -> String {
    let args = decl
        .split_once('(')
        .unwrap_or_else(|| panic!("malformed variant declaration at line {at}: {decl:?}"))
        .1;
    let inner = args
        .strip_suffix(',')
        .unwrap_or_else(|| panic!("variant without trailing comma at line {at}: {decl:?}"))
        .strip_suffix(')')
        .unwrap_or_else(|| panic!("malformed variant declaration at line {at}: {decl:?}"))
        .trim();
    let normalized = normalize_type(inner);
    bare_message_name(unwrap_containers(&normalized, decl, at), decl, at)
}

fn bare_message_name(mut ty: &str, decl: &str, at: usize) -> String {
    while let Some(rest) = ty.strip_prefix("super::") {
        ty = rest;
    }
    assert!(is_bare_ident(ty), "unexpected message type spelling at line {at}: {decl:?}");
    ty.to_owned()
}

fn is_bare_ident(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}
