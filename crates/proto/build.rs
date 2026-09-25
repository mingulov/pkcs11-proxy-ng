#[path = "src/oneof_check.rs"]
mod oneof_check;

use heck::ToUpperCamelCase as _;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/service.proto");
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/types.proto");
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/mechanism_params.proto");
    println!("cargo:rerun-if-changed=secret-fields.toml");

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
    // SECURITY: 13 `bytes` fields hold PIN / password material and are
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
    //   * mechanism_params.proto: OtpParam.value (W1-L2-09)
    //
    // A global `.bytes(".")` flip would silently regress all of these.
    // That is NOT the destination of this migration.
    //
    // T12 (closes the W1-L2-09 residual and FOLLOWUP-zeroize-broader-
    // coverage): the derive set below is no longer a hardcoded PIN list.
    // `zeroize_closure_messages` derives `Zeroize` + `ZeroizeOnDrop` on
    // every secret-bearing owner in the enabled manifest categories plus
    // the transitive message-typed-field closure (nested messages and
    // oneof arms — a derived owner needs every field type to impl
    // `Zeroize`). The same `Vec<u8>` requirement therefore extends from
    // the PIN fields above to EVERY secret-classified `bytes` field in
    // `secret-fields.toml`: a global `.bytes(".")` flip would silently
    // regress all of them, so the per-field rule stands a fortiori.
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
    let redacted = redacted_messages();
    let schema = parse_schema();
    // T12: manifest-driven wipe closure (replaces the 10 hardcoded
    // `pin_auth` derives). Every `[secret]` owner plus the transitive
    // message-typed-field closure derives `Zeroize`, and every member but
    // the prost-`Copy` ones (see "Copy-aware emission" below) also derives
    // `ZeroizeOnDrop`, so decoded buffers the borrow-based conversions copy
    // out of are overwritten on drop instead of freed plain. Field-covering
    // derive, so future secret fields wipe with no drift.
    //
    // NOTE: the derived `Drop` forbids moving fields out of these
    // messages and forbids struct-update syntax on them; handlers take
    // secret buffers with `mem::take` instead.
    //
    // Copy-aware emission: prost derives `Copy` on all-scalar messages
    // and oneof enums, which conflicts with the `Drop` that
    // `ZeroizeOnDrop` generates (E0184). Copy-eligible members therefore
    // get `Zeroize` alone (enough for parent recursion; nothing heap
    // lives in them to wipe on drop) while every other member gets the
    // full pair. Parents use `message_attribute` (message-only) and
    // oneofs use explicit `.pkg.Parent.oneof` `type_attribute` paths so
    // each level is controlled independently — a shared parent path
    // would leak the pair onto all-scalar oneofs via prefix matching.
    let zeroized = zeroize_closure_messages(&schema);
    let mut prost = tonic_prost_build::configure();
    for message in &zeroized {
        prost = prost.message_attribute(
            format!(".{}.{message}", schema.package),
            zeroize_attr_for_message(&schema, message),
        );
    }
    for (parent, oneof) in
        message_oneofs().into_iter().filter(|(parent, _)| zeroized.contains(parent))
    {
        prost = prost.type_attribute(
            format!(".{}.{parent}.{oneof}", schema.package),
            zeroize_attr_for_oneof(&schema, &parent, &oneof),
        );
    }
    // T12: `#[zeroize(skip)]` on auto-boxed back-edge fields. Prost boxes a
    // message-typed field when its target reaches the container
    // (`MessageGraph::is_nested`, mirrored by `has_ref_path`), producing
    // `Option<Box<Target>>` — and `zeroize` implements `Zeroize` for neither
    // `Box<T>` nor (transitively) the `Option`, so the derive would fail with
    // E0599. Skipping the field is sound: the boxed target is in the closure
    // and derives the full wipe pair (asserted per site below — every cycle
    // member is non-`Copy`, so no skipped target can hold `Zeroize` alone),
    // hence the target's own `Drop` wipes it when the box drops with the
    // parent. Only explicit `.zeroize()` propagation into the box is lost,
    // which no caller relies on (this design wipes on drop).
    //
    // Only `Option<Box<Target>>` STRUCT fields need `skip`. Boxed oneof arms
    // (prost `should_box_oneof_field`, e.g. `mechanism::Params::KipParams`)
    // hold a bare `Box<Target>`, and `zeroize_derive` emits method-call
    // syntax (`binding.zeroize()`), which auto-derefs through the box to the
    // target's own `Zeroize` impl — so boxed arms compile AND explicit
    // `.zeroize()` propagates into them. Do NOT add `skip` to oneof arms:
    // that would silently stop the propagation that works today. Repeated
    // fields live in `Vec<T: Zeroize>`. A future `Option<Box<T>>` struct
    // field the rule misses fails the build at the derive (E0599), never
    // silently.
    let edges = message_ref_edges(&schema);
    let mut skipped_boxed = std::collections::BTreeSet::new();
    for message in &schema.messages {
        if !zeroized.contains(&message.name) {
            continue;
        }
        for field in &message.fields {
            if field.oneof.is_some() || field.repeated {
                continue;
            }
            let Some(target) = message_field_target(&schema, &field.type_name) else {
                continue;
            };
            if !has_ref_path(&edges, &target, &message.name) {
                continue;
            }
            assert!(
                zeroized.contains(&target)
                    && zeroize_attr_for_message(&schema, &target) == ZEROIZE_PAIR,
                "boxed {}.{} skips a target without the wipe pair: {target}",
                message.name,
                field.name,
            );
            skipped_boxed.insert(format!("{}.{}", message.name, field.name));
            prost = prost.field_attribute(
                format!(".{}.{}.{}", schema.package, message.name, field.name),
                "#[zeroize(skip)]",
            );
        }
    }
    prost
        .build_server(true)
        .build_client(true)
        .skip_debug(redacted.iter().map(|message| format!(".pkcs11_proxy_ng.v1.{message}")))
        .compile_protos(
            &[
                "../../proto/pkcs11-proxy-ng/v1/service.proto",
                "../../proto/pkcs11-proxy-ng/v1/types.proto",
                "../../proto/pkcs11-proxy-ng/v1/mechanism_params.proto",
            ],
            &["../../proto"],
        )?;

    // W1-C8-07: the oneof cross-validation reads prost's output, so it runs
    // after codegen and before the redacted-`Debug` emission it protects.
    cross_validate_oneofs_against_prost();
    cross_validate_copy_mirror_against_prost(&schema);
    emit_redacted_debug(&redacted)?;

    emit_protected_decode_tables(&schema)?;
    emit_zeroized_list(&zeroized, &skipped_boxed)?;
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

// ---------------------------------------------------------------------------
// T12 manifest-driven wipe closure.
//
// The `[secret]` manifest categories whose owners (plus the transitive
// message-typed-field closure) derive `Zeroize` + `ZeroizeOnDrop`.
// Checkpoints land in validated-plan order: `pin_auth` behavior first
// (byte-identical to the 10 previously hardcoded derives — asserted
// below), then `key_attributes_material`, `seed_state`,
// `plaintext_decrypted`, `unknown_vendor`. Consumer migrations
// (`mem::take` at compiler-reported move sites) land with each
// checkpoint so every intermediate tree compiles and passes.
// ---------------------------------------------------------------------------

/// Owner messages of EVERY `[secret]` category: message part of each
/// `pkcs11_proxy_ng.v1.Message.field` entry. Same line format as
/// [`redacted_messages`]; malformed entries fail the build loudly.
///
/// Steady state (T12 final checkpoint): the wipe closure covers all
/// `[secret]` categories dynamically, exactly like redaction — a new secret
/// field or category is wiped with no code change. The per-category
/// checkpoint tests in `tests/pin_zeroize.rs` pin the reviewed category set,
/// so a new category fails loudly there until it gains its own checkpoint.
fn manifest_secret_owners() -> std::collections::BTreeSet<String> {
    let manifest = std::fs::read_to_string("secret-fields.toml").expect("read secret-fields.toml");
    let mut owners = std::collections::BTreeSet::new();
    let mut in_secret = false;
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
                owners.insert(message.to_owned());
            }
            _ => panic!("malformed manifest entry {field:?}"),
        }
    }
    assert!(!owners.is_empty(), "no secret owners parsed from [secret]");
    owners
}

/// Field type is a message (not a scalar/enum): same rule as
/// [`nested_index`] — scalars and schema enums are terminal, every
/// other named type must resolve to a schema message.
fn message_field_target(schema: &Schema, type_name: &str) -> Option<String> {
    let short = type_name.rsplit('.').next().unwrap_or(type_name);
    if SCALAR_TYPES.contains(&short) || schema.enums.iter().any(|name| name == short) {
        return None;
    }
    schema
        .messages
        .iter()
        .find(|message| message.name == short)
        .map(|message| message.name.clone())
        .or_else(|| panic!("unknown field type {type_name}"))
}

/// Every message deriving the wipe pair: `[secret]` owners plus
/// the transitive closure over message-typed fields (nested messages,
/// oneof arms, repeated element types — the schema parser records all
/// three uniformly). A derived owner needs every field type to impl
/// `Zeroize`, so transit vessels that carry no secret bytes of their
/// own still join the set (wiping non-secret bytes is harmless).
/// Cycles (`Attribute` ↔ `NestedAttributes`) terminate via the visited
/// set; prost enums surface as `i32` and are terminal.
fn zeroize_closure_messages(schema: &Schema) -> std::collections::BTreeSet<String> {
    let seeds = manifest_secret_owners();
    let by_name: std::collections::HashMap<&str, &SchemaMessage> =
        schema.messages.iter().map(|message| (message.name.as_str(), message)).collect();
    let mut closure = std::collections::BTreeSet::new();
    let mut stack: Vec<String> = seeds.into_iter().collect();
    while let Some(name) = stack.pop() {
        if !closure.insert(name.clone()) {
            continue;
        }
        let message = by_name
            .get(name.as_str())
            .unwrap_or_else(|| panic!("manifest owner {name} is not a schema message"));
        for field in &message.fields {
            if let Some(target) = message_field_target(schema, &field.type_name)
                && !closure.contains(&target)
            {
                stack.push(target);
            }
        }
    }
    closure
}

/// prost `Copy`-eligible scalar field types (prost-build 0.14.3
/// `can_field_derive_copy` whitelist — notably WITHOUT string/bytes,
/// which surface as the non-`Copy` `Vec<u8>`/`String`).
const COPY_SCALARS: &[&str] = &[
    "double", "float", "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32",
    "fixed64", "sfixed32", "sfixed64", "bool",
];

/// Derive text: the full wipe pair, or `Zeroize` alone for `Copy`
/// members (whose prost `Copy` forbids the `Drop`).
const ZEROIZE_PAIR: &str = "#[derive(::zeroize::Zeroize, ::zeroize::ZeroizeOnDrop)]";
const ZEROIZE_ONLY: &str = "#[derive(::zeroize::Zeroize)]";

fn zeroize_attr_for_message(schema: &Schema, message: &str) -> &'static str {
    if message_can_copy(schema, message) { ZEROIZE_ONLY } else { ZEROIZE_PAIR }
}

fn zeroize_attr_for_oneof(schema: &Schema, parent: &str, oneof: &str) -> &'static str {
    if oneof_can_copy(schema, parent, oneof) { ZEROIZE_ONLY } else { ZEROIZE_PAIR }
}

/// Reference edges mirroring prost's `MessageGraph`: M -> T for every
/// NON-REPEATED message-typed field (oneof members included — they are
/// non-repeated descriptor fields). Repeated message fields live in a
/// `Vec` and need no boxing edge, exactly as in prost.
fn message_ref_edges(schema: &Schema) -> std::collections::HashMap<&str, Vec<&str>> {
    let mut edges: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
    for message in &schema.messages {
        let mut targets = Vec::new();
        for field in &message.fields {
            if field.repeated {
                continue;
            }
            if let Some(target) = message_field_target(schema, &field.type_name) {
                targets.push(
                    schema
                        .messages
                        .iter()
                        .find(|candidate| candidate.name == target)
                        .map(|candidate| candidate.name.as_str())
                        .expect("closure target"),
                );
            }
        }
        edges.insert(message.name.as_str(), targets);
    }
    edges
}

/// Graph reachability mirroring petgraph `has_path_connecting` over the
/// reference edges (prost `MessageGraph::is_nested`).
fn has_ref_path(edges: &std::collections::HashMap<&str, Vec<&str>>, from: &str, to: &str) -> bool {
    let mut visited = std::collections::HashSet::new();
    let mut stack = vec![from];
    while let Some(node) = stack.pop() {
        if node == to {
            return true;
        }
        if !visited.insert(node) {
            continue;
        }
        if let Some(targets) = edges.get(node) {
            stack.extend(targets.iter().copied());
        }
    }
    false
}

/// Mirror of prost-build 0.14.3 `can_message_derive_copy` /
/// `can_field_derive_copy`: repeated is never `Copy`; scalars per
/// [`COPY_SCALARS`] plus schema enums (prost surfaces enum fields as
/// `i32`) are `Copy`; message fields recurse unless the target reaches
/// the container (recursive fields are auto-boxed, and `Box` is never
/// `Copy`). Termination mirrors prost's own recursion: each step
/// extends a chain the reachability guard keeps acyclic.
fn message_can_copy(schema: &Schema, message: &str) -> bool {
    let edges = message_ref_edges(schema);
    message_can_copy_inner(schema, &edges, message)
}

fn message_can_copy_inner(
    schema: &Schema,
    edges: &std::collections::HashMap<&str, Vec<&str>>,
    message: &str,
) -> bool {
    let message =
        schema.messages.iter().find(|candidate| candidate.name == message).expect("schema message");
    message.fields.iter().all(|field| field_can_copy_inner(schema, edges, &message.name, field))
}

fn field_can_copy_inner(
    schema: &Schema,
    edges: &std::collections::HashMap<&str, Vec<&str>>,
    container: &str,
    field: &SchemaField,
) -> bool {
    if field.repeated {
        return false;
    }
    let short = field.type_name.rsplit('.').next().unwrap_or(&field.type_name);
    if COPY_SCALARS.contains(&short) || schema.enums.iter().any(|name| name == short) {
        return true;
    }
    match message_field_target(schema, &field.type_name) {
        Some(target) => {
            !has_ref_path(edges, &target, container)
                && message_can_copy_inner(schema, edges, &target)
        }
        None => false,
    }
}

/// Cross-validates the `Copy` mirror against prost's actual output: the
/// set of messages/oneofs prost derived `Copy` on must equal the
/// mirror's prediction exactly. A prost upgrade that changes the rule
/// fails the build loudly here instead of producing E0184 (`Copy` +
/// `Drop`) or silently missing a wipe.
fn cross_validate_copy_mirror_against_prost(schema: &Schema) {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR must be set for the build script");
    let generated_path = std::path::Path::new(&out_dir).join("pkcs11_proxy_ng.v1.rs");
    let generated = std::fs::read_to_string(&generated_path).expect("read prost output");
    let mut prost_copy_messages = std::collections::BTreeSet::new();
    let mut prost_copy_oneofs = std::collections::BTreeSet::new();
    let mut module: Option<String> = None;
    let lines: Vec<&str> = generated.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("pub mod ") {
            module = Some(rest.strip_suffix(" {").unwrap_or(rest).to_owned());
            continue;
        }
        if line == "}" {
            module = None;
            continue;
        }
        let (Some(name), is_enum) = (
            line.strip_prefix("pub struct ")
                .map(|rest| rest.split([' ', '<', '(']).next().unwrap_or_default().to_owned())
                .or_else(|| {
                    line.strip_prefix("pub enum ").map(|rest| {
                        rest.split([' ', '<', '(']).next().unwrap_or_default().to_owned()
                    })
                }),
            line.starts_with("pub enum "),
        ) else {
            continue;
        };
        // Walk upward through CONSECUTIVE `#[...]` attribute lines only.
        // A fixed N-line window bleeds across single-line unit structs
        // (`pub struct Empty {}` + neighbor's `Copy` derive), recording a
        // false `Copy` for the following message (observed: `InterfaceInfo`
        // inheriting `GetBackendInterfacesRequest`'s derive). Prost (plus our
        // `type_attribute` additions) always emits derives directly above the
        // item, so any non-attribute line ends the run. `Copy` matches as an
        // exact derive token, not a substring.
        let mut derives_copy = false;
        let mut cursor = index;
        while cursor > 0 {
            cursor -= 1;
            let Some(above) = lines.get(cursor).map(|line| line.trim()) else {
                break;
            };
            if !above.starts_with("#[") {
                break;
            }
            if let Some(derives) =
                above.strip_prefix("#[derive(").and_then(|rest| rest.strip_suffix(")]"))
                && derives.split(',').any(|token| token.trim() == "Copy")
            {
                derives_copy = true;
                break;
            }
        }
        if !derives_copy {
            continue;
        }
        if is_enum {
            // Top-level `pub enum`s are plain proto enums (always
            // prost-`Copy`), not oneofs: skip them. Only enums nested in a
            // `pub mod` are oneof enums (the authoritative discriminator
            // lives in `oneof_check::parse_prost_oneof_enums`, which runs in
            // this same build and fails closed; any scanner/mirror
            // imprecision here fires the `assert_eq!` below loudly).
            if let Some(parent) = module.as_deref() {
                prost_copy_oneofs.insert(format!("{parent}::{name}"));
            }
        } else if module.is_none() {
            prost_copy_messages.insert(name);
        }
    }
    assert!(
        !prost_copy_messages.is_empty(),
        "Copy cross-validation found no prost Copy structs: extend deliberately, do not pass vacuously"
    );
    let mut mirror_messages = std::collections::BTreeSet::new();
    for message in &schema.messages {
        if message_can_copy(schema, &message.name) {
            // Compare prost-Rust spellings, not proto spellings: prost maps
            // message names through `heck::ToUpperCamelCase`
            // (`AsyncGetIDResponse` -> `AsyncGetIdResponse`). `sanitize_identifier`
            // needs no mirror (no message name is a Rust keyword), and this
            // assert guards any future drift loudly.
            mirror_messages.insert(message.name.to_upper_camel_case());
        }
    }
    assert_eq!(
        mirror_messages, prost_copy_messages,
        "Copy mirror diverged from prost on messages: extend the mirror deliberately"
    );
    let mut mirror_oneofs = std::collections::BTreeSet::new();
    for (parent, oneof) in message_oneofs() {
        if oneof_can_copy(schema, &parent, &oneof) {
            mirror_oneofs.insert(oneof_check::prost_oneof_path(&parent, &oneof));
        }
    }
    assert_eq!(
        mirror_oneofs, prost_copy_oneofs,
        "Copy mirror diverged from prost on oneof enums: extend the mirror deliberately"
    );
}

/// Mirror of the oneof-`Copy` rule (`append_oneof`): all member fields
/// `Copy` with the PARENT as the cycle guard.
fn oneof_can_copy(schema: &Schema, parent: &str, oneof: &str) -> bool {
    let edges = message_ref_edges(schema);
    let message =
        schema.messages.iter().find(|candidate| candidate.name == parent).expect("oneof parent");
    message
        .fields
        .iter()
        .filter(|field| field.oneof.as_deref() == Some(oneof))
        .all(|field| field_can_copy_inner(schema, &edges, parent, field))
}

/// Emits the `ZEROIZED_WIRE_MESSAGES` const audited by
/// `crates/proto/tests/pin_zeroize.rs` against `secret-fields.toml`.
/// Included at the crate root by `lib.rs`.
fn emit_zeroized_list(
    zeroized: &std::collections::BTreeSet<String>,
    skipped_boxed: &std::collections::BTreeSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut out = String::from(
        "// Generated by crates/proto/build.rs from secret-fields.toml + the\n\
         // protobuf schema. Do not edit: change the manifest or schema instead.\n\
         //\n\
         // T12 wipe closure: all `[secret]` owners plus the transitive\n\
         // message-typed-field closure. Every member derives `Zeroize`;\n\
         // every member but the prost-`Copy` ones also derives\n\
         // `ZeroizeOnDrop` (a `Copy` type cannot carry the `Drop`).\n\
         /// Names of the wire messages in the wipe closure.\n\
         ///\n\
         /// Audited by `crates/proto/tests/pin_zeroize.rs` against\n\
         /// `secret-fields.toml`: every `[secret]` owner must occur here.\n\
         pub const ZEROIZED_WIRE_MESSAGES: &[&str] = &[\n",
    );
    for message in zeroized {
        out.push_str(&format!("    \"{message}\",\n"));
    }
    out.push_str(
        "];\n\
         /// `Message.field` sites carrying `#[zeroize(skip)]`: auto-boxed\n\
         /// (`Option<Box<T>>`) back-edges whose target self-wipes via its own\n\
         /// `ZeroizeOnDrop` (asserted per site at codegen). Audited by\n\
         /// `crates/proto/tests/pin_zeroize.rs`: every entry must name a\n\
         /// message in `ZEROIZED_WIRE_MESSAGES`.\n\
         pub const ZEROIZE_SKIPPED_BOXED_FIELDS: &[&str] = &[\n",
    );
    for site in skipped_boxed {
        out.push_str(&format!("    \"{site}\",\n"));
    }
    out.push_str("];\n");
    let out_dir = std::env::var("OUT_DIR")?;
    std::fs::write(std::path::Path::new(&out_dir).join("zeroized_gen.rs"), out)?;
    Ok(())
}

/// Parses `message Parent { ... oneof name { ... } ... }` from the schema.
/// Messages are top-level only; nested messages fail the build so the
/// generator (and its prost module-path mapping) is extended deliberately.
/// The per-file tokenizer lives in `oneof_check` so unit tests pin the same
/// core the build runs (W1-C8-07).
fn message_oneofs() -> Vec<(String, String)> {
    let mut oneofs = Vec::new();
    for path in PROTO_FILES {
        let source = std::fs::read_to_string(path).unwrap_or_else(|_| panic!("read {path}"));
        oneofs.extend(oneof_check::parse_oneofs_in_source(&source, path));
    }
    oneofs.sort();
    oneofs.dedup();
    oneofs
}

/// W1-C8-07: cross-validates the schema oneof tokenizer against prost's
/// actual output. A tokenizer miss would silently leave a payload-printing
/// derived `Debug` on the missed oneof enum (no redacted impl is emitted
/// for it), so any drift fails the build loudly instead.
fn cross_validate_oneofs_against_prost() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR must be set for the build script");
    let generated_path = std::path::Path::new(&out_dir).join("pkcs11_proxy_ng.v1.rs");
    let generated = std::fs::read_to_string(&generated_path).unwrap_or_else(|_| {
        panic!(
            "read {}: build.rs must compile the protos before validating oneofs",
            generated_path.display()
        )
    });
    let enums = oneof_check::parse_prost_oneof_enums(&generated);
    assert!(
        !enums.is_empty(),
        "oneof cross-validation found no prost oneof enums in {}: extend the scanner deliberately, do not pass vacuously",
        generated_path.display()
    );
    let oneofs = message_oneofs();
    assert!(
        !oneofs.is_empty(),
        "schema tokenizer found no oneofs: extend the tokenizer deliberately, do not pass vacuously"
    );
    let missing = oneof_check::missing_oneofs(&oneofs, &enums);
    assert!(
        missing.is_empty(),
        "message_oneofs() missed oneof enums prost generated: {missing:?}: extend the redaction tokenizer first (a missed oneof keeps payload-printing derived Debug)"
    );
    let stale = oneof_check::stale_oneofs(&oneofs, &enums);
    assert!(
        stale.is_empty(),
        "schema tokenizer lists oneofs prost did not generate: {stale:?}: extend the cross-validation deliberately"
    );
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
        let path = oneof_check::prost_oneof_path(&parent, &oneof);
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
    name: String,
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
                [type_name, field, "=", number] => {
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
                        name: (*field).to_owned(),
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
