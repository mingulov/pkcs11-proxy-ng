use std::{
    alloc::{GlobalAlloc, Layout, System},
    collections::{BTreeMap, BTreeSet},
    path::Path,
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};

use pkcs11_proxy_ng_types::SecretBytes;

struct ObservingAllocator;

static OBSERVED_PTR: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static OBSERVED_DEALLOCATION: AtomicBool = AtomicBool::new(false);
static OBSERVED_ALL_ZERO: AtomicBool = AtomicBool::new(false);

// SAFETY: this delegates allocation to `System`. During deallocation it
// reads only the allocation identified by the test, before delegating its
// deallocation. It never retains or reads the pointer after deallocation.
unsafe impl GlobalAlloc for ObservingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegated with the allocator contract unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, allocation: *mut u8, layout: Layout) {
        if OBSERVED_PTR.compare_exchange(
            allocation,
            ptr::null_mut(),
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) == Ok(allocation)
        {
            // SAFETY: the test registers only its fully initialized
            // `Vec<u8>` allocation. The allocation is still live and the
            // read occurs before `System.dealloc` below.
            let bytes = unsafe { std::slice::from_raw_parts(allocation, layout.size()) };
            OBSERVED_ALL_ZERO.store(bytes.iter().all(|byte| *byte == 0), Ordering::SeqCst);
            OBSERVED_DEALLOCATION.store(true, Ordering::SeqCst);
        }

        // SAFETY: delegated once with the original pointer and layout.
        unsafe { System.dealloc(allocation, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ObservingAllocator = ObservingAllocator;

#[test]
fn debug_reports_only_type_and_length() {
    let secret = SecretBytes::new(b"debug-canary".to_vec());

    let rendered = format!("{secret:?}");

    assert_eq!(rendered, "SecretBytes { len: 12 }");
    assert!(!rendered.contains("debug-canary"));
}

#[test]
fn access_is_closure_scoped_and_ownership_transfer_stays_wiping() {
    let mut secret = SecretBytes::copy_from_slice(b"secret");
    assert_eq!(secret.expose(|bytes| bytes.len()), 6);
    secret.expose_mut(|bytes| bytes[0] = b'S');
    assert_eq!(secret.expose(<[u8]>::to_vec), b"Secret");

    let transferred = secret.into_zeroizing();
    assert_eq!(transferred.as_slice(), b"Secret");
}

#[test]
fn wiping_owner_zeroes_full_allocation_before_deallocation() {
    const CAPACITY: usize = 4093;
    let mut bytes = Vec::with_capacity(CAPACITY);
    bytes.resize(CAPACITY, 0xA5);
    let allocation = bytes.as_mut_ptr();
    assert_eq!(bytes.capacity(), CAPACITY);

    OBSERVED_DEALLOCATION.store(false, Ordering::SeqCst);
    OBSERVED_ALL_ZERO.store(false, Ordering::SeqCst);
    OBSERVED_PTR.store(allocation, Ordering::SeqCst);

    drop(SecretBytes::new(bytes));

    assert!(OBSERVED_DEALLOCATION.load(Ordering::SeqCst));
    assert!(OBSERVED_ALL_ZERO.load(Ordering::SeqCst));
    assert!(OBSERVED_PTR.load(Ordering::SeqCst).is_null());
}

#[test]
fn manifest_classifies_every_bytes_and_string_field_exactly_once() {
    let manifest: toml::Value = include_str!("../../proto/secret-fields.toml")
        .parse()
        .expect("secret-fields.toml must parse");
    assert_eq!(manifest.get("schema_version").and_then(toml::Value::as_integer), Some(1));
    assert_eq!(
        manifest.get("unclassified_field_policy").and_then(toml::Value::as_str),
        Some("reject")
    );
    assert_eq!(
        manifest
            .as_table()
            .expect("manifest root must be a table")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["safe_metadata", "schema_version", "secret", "unclassified_field_policy"])
    );

    let secret = classified_fields(&manifest, "secret");
    let safe = classified_fields(&manifest, "safe_metadata");
    assert!(!secret.is_empty());
    assert!(!safe.is_empty());

    let overlap = secret.keys().filter(|field| safe.contains_key(*field)).collect::<Vec<_>>();
    assert!(overlap.is_empty(), "fields classified both secret and safe: {overlap:?}");

    let classified = secret.keys().chain(safe.keys()).cloned().collect::<BTreeSet<_>>();
    let declared = declared_wire_fields();
    let missing = declared.difference(&classified).cloned().collect::<Vec<_>>();
    let stale = classified.difference(&declared).cloned().collect::<Vec<_>>();
    assert!(missing.is_empty(), "unclassified bytes/string fields: {missing:#?}");
    assert!(stale.is_empty(), "manifest fields absent from protobuf schema: {stale:#?}");
    assert_eq!(classified.len(), declared.len());

    assert_eq!(secret.get("pkcs11_proxy_ng.v1.LoginRequest.pin"), Some(&"pin_auth"));
    assert_eq!(
        secret.get("pkcs11_proxy_ng.v1.Attribute.bytes_value"),
        Some(&"key_attributes_material")
    );
    assert_eq!(
        secret.get("pkcs11_proxy_ng.v1.WrapKeyResponse.wrapped_key"),
        Some(&"key_attributes_material")
    );
    assert_eq!(
        secret.get("pkcs11_proxy_ng.v1.SkipjackRelayxParams.old_wrapped_x"),
        Some(&"key_attributes_material")
    );
    assert_eq!(secret.get("pkcs11_proxy_ng.v1.SeedRandomRequest.seed"), Some(&"seed_state"));
    assert_eq!(secret.get("pkcs11_proxy_ng.v1.DecryptResponse.data"), Some(&"plaintext_decrypted"));
    assert_eq!(secret.get("pkcs11_proxy_ng.v1.RawMechanismParams.data"), Some(&"unknown_vendor"));
    assert_eq!(safe.get("pkcs11_proxy_ng.v1.EncryptResponse.encrypted_data"), Some(&"ciphertext"));
}

fn classified_fields<'a>(manifest: &'a toml::Value, table_name: &str) -> BTreeMap<String, &'a str> {
    let table = manifest
        .get(table_name)
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| panic!("missing [{table_name}] table"));
    let expected_categories = match table_name {
        "secret" => BTreeSet::from([
            "key_attributes_material",
            "pin_auth",
            "plaintext_decrypted",
            "seed_state",
            "unknown_vendor",
        ]),
        "safe_metadata" => {
            BTreeSet::from(["ciphertext", "identifiers", "public_parameters", "signature_digest"])
        }
        _ => unreachable!("only known classification tables are requested"),
    };
    assert_eq!(
        table.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        expected_categories,
        "unexpected categories in [{table_name}]"
    );
    let mut result = BTreeMap::new();
    for (category, value) in table {
        let values =
            value.as_array().unwrap_or_else(|| panic!("{table_name}.{category} must be an array"));
        assert!(!values.is_empty(), "{table_name}.{category} must not be empty");
        for value in values {
            let field = value
                .as_str()
                .unwrap_or_else(|| panic!("{table_name}.{category} entries must be strings"));
            assert!(
                result.insert(field.to_owned(), category.as_str()).is_none(),
                "duplicate classification for {field}"
            );
        }
    }
    result
}

fn declared_wire_fields() -> BTreeSet<String> {
    [
        (
            "mechanism_params.proto",
            include_str!("../../../proto/pkcs11-proxy-ng/v1/mechanism_params.proto"),
        ),
        ("types.proto", include_str!("../../../proto/pkcs11-proxy-ng/v1/types.proto")),
        ("service.proto", include_str!("../../../proto/pkcs11-proxy-ng/v1/service.proto")),
    ]
    .into_iter()
    .flat_map(|(name, source)| parse_wire_fields(Path::new(name), source))
    .collect()
}

fn parse_wire_fields(path: &Path, source: &str) -> Vec<String> {
    let tokens = proto_tokens(source);
    let mut messages = Vec::<(String, usize)>::new();
    let mut pending_message = None::<String>;
    let mut depth = 0_usize;
    let mut fields = Vec::new();

    let mut index = 0;
    while index < tokens.len() {
        match tokens[index].as_str() {
            "message" => {
                pending_message = Some(
                    tokens
                        .get(index + 1)
                        .filter(|name| is_identifier(name))
                        .unwrap_or_else(|| {
                            panic!("invalid message declaration in {}", path.display())
                        })
                        .clone(),
                );
                index += 2;
            }
            "{" => {
                depth += 1;
                if let Some(name) = pending_message.take() {
                    let qualified = messages
                        .last()
                        .map(|(parent, _)| format!("{parent}.{name}"))
                        .unwrap_or(name);
                    messages.push((qualified, depth));
                }
                index += 1;
            }
            "}" => {
                if messages.last().is_some_and(|(_, message_depth)| *message_depth == depth) {
                    messages.pop();
                }
                depth = depth
                    .checked_sub(1)
                    .unwrap_or_else(|| panic!("unbalanced closing brace in {}", path.display()));
                index += 1;
            }
            "bytes" | "string" if !messages.is_empty() => {
                let field =
                    tokens.get(index + 1).filter(|field| is_identifier(field)).unwrap_or_else(
                        || panic!("invalid byte/string field declaration in {}", path.display()),
                    );
                fields.push(format!("pkcs11_proxy_ng.v1.{}.{}", messages.last().unwrap().0, field));
                index += 2;
            }
            _ => index += 1,
        }
    }

    assert_eq!(depth, 0, "unbalanced opening brace in {}", path.display());
    assert!(messages.is_empty(), "unterminated message in {}", path.display());
    fields
}

fn proto_tokens(source: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    for line in source.lines() {
        let mut identifier = String::new();
        for ch in line.split("//").next().unwrap_or_default().chars() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                identifier.push(ch);
                continue;
            }
            if !identifier.is_empty() {
                tokens.push(std::mem::take(&mut identifier));
            }
            if ch == '{' || ch == '}' {
                tokens.push(ch.to_string());
            }
        }
        if !identifier.is_empty() {
            tokens.push(identifier);
        }
    }
    tokens
}

fn is_identifier(token: &str) -> bool {
    token.starts_with(|ch: char| ch.is_ascii_alphabetic() || ch == '_')
        && token.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}
