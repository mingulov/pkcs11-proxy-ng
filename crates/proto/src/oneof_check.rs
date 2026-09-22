//! Build-time oneof cross-validation core (W1-C8-07).
//!
//! [`parse_oneofs_in_source`] tokenizes the protobuf schema for
//! `(parent, oneof)` pairs; that list drives the redacted-`Debug` impls
//! `build.rs` emits. A tokenizer miss would silently leave a
//! payload-printing derived `Debug` on the missed oneof enum, so `build.rs`
//! cross-validates the tokenizer list against what prost actually generated
//! ([`parse_prost_oneof_enums`] over `OUT_DIR/pkcs11_proxy_ng.v1.rs`) and
//! fails the build on any drift ([`missing_oneofs`] / [`stale_oneofs`]).
//!
//! This module is compiled twice — once into `build.rs` via `#[path]`, once
//! into the crate's test target — so the same core the build runs is pinned
//! by the unit tests below, including the negative control (a simulated
//! tokenizer miss is reported by name). It must stay dependency-free (`std`
//! only): `build.rs` cannot use the crate's dependencies.

use std::collections::BTreeSet;

/// Tokenizes one protobuf schema file for `(parent message, oneof)` pairs.
///
/// Moved verbatim from `build.rs::message_oneofs` (which now only loops
/// over files): messages are top-level only and nested messages fail the
/// build so the redaction generator is extended deliberately.
pub(crate) fn parse_oneofs_in_source(source: &str, path: &str) -> Vec<(String, String)> {
    let mut oneofs = Vec::new();
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
                let parent =
                    parent.unwrap_or_else(|| panic!("oneof {name} outside a message in {path}"));
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
    oneofs
}

fn is_message_context(enclosing: &[(String, usize)]) -> bool {
    enclosing.iter().any(|(context, _)| context.starts_with("message:"))
}

/// prost module for a message (`AuthenticatedMechanismOutput` ->
/// `authenticated_mechanism_output`) and enum name for a oneof
/// (`output` -> `Output`).
pub(crate) fn prost_oneof_path(parent: &str, oneof: &str) -> String {
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

/// Extracts the `module::Enum` paths of every oneof enum prost generated.
///
/// A oneof enum is a `pub enum` nested inside a `pub mod` (prost emits one
/// module per oneof parent) carrying the `::prost::Oneof` derive. Top-level
/// `pub enum`s are plain proto enums, not oneofs, and the tonic service
/// modules are brace-matched but never mined (mirroring the
/// `SERVICE_MODULES` precedent in the `protected_decode` white-box tests).
/// Fails closed: any construct it does not understand panics instead of
/// being skipped.
pub(crate) fn parse_prost_oneof_enums(generated: &str) -> Vec<String> {
    /// Tonic service modules: traversed only for brace matching, never mined.
    const SERVICE_MODULES: &[&str] = &["pkcs11_proxy_client", "pkcs11_proxy_server"];

    let mut oneofs = Vec::new();
    // Open `pub mod` names with the brace depth at which each opened.
    let mut modules: Vec<(String, usize)> = Vec::new();
    let mut depth = 0_usize;
    // Consecutive `#[...]` lines preceding the current line.
    let mut attributes = String::new();
    for (index, line) in generated.lines().enumerate() {
        let at = index + 1;
        // Generated code carries no `//` inside string literals; stripping
        // comments keeps doc braces out of the depth count and doc prose
        // out of the declaration match.
        let code = line.split("//").next().unwrap_or_default();
        let trimmed = code.trim();
        if trimmed.starts_with("#[") {
            attributes.push_str(trimmed);
            attributes.push('\n');
            continue;
        }
        if let Some(name) = trimmed.strip_prefix("pub mod ") {
            let name = name.strip_suffix(" {").unwrap_or_else(|| {
                panic!("generated line {at}: malformed module declaration {trimmed:?}")
            });
            assert!(is_bare_ident(name), "generated line {at}: unexpected module name {name:?}");
            modules.push((name.to_owned(), depth));
        } else if let Some(rest) = trimmed.strip_prefix("pub enum ") {
            let name = rest.split([' ', '{']).next().unwrap_or_default();
            assert!(
                is_bare_ident(name),
                "generated line {at}: malformed enum declaration {trimmed:?}"
            );
            match modules.last().map(|(name, _)| name.as_str()) {
                // Top-level prost enum (e.g. `ByteOutputFunction`): a plain
                // proto enum, not a oneof.
                None => {}
                Some(module) if SERVICE_MODULES.contains(&module) => {
                    panic!(
                        "generated line {at}: unexpected enum {name} inside tonic service module {module}"
                    );
                }
                Some(module) => {
                    assert!(
                        attributes.contains("prost::Oneof"),
                        "generated line {at}: enum {name} inside module {module} lacks the prost::Oneof derive: extend the scanner deliberately"
                    );
                    oneofs.push(format!("{module}::{name}"));
                }
            }
        }
        attributes.clear();
        depth += trimmed.chars().filter(|ch| *ch == '{').count();
        let closing = trimmed.chars().filter(|ch| *ch == '}').count();
        depth = depth
            .checked_sub(closing)
            .unwrap_or_else(|| panic!("generated line {at}: unbalanced closing brace"));
        while modules.last().is_some_and(|(_, opened)| *opened >= depth) {
            modules.pop();
        }
    }
    assert_eq!(depth, 0, "unbalanced opening brace in prost output");
    oneofs.sort();
    oneofs.dedup();
    oneofs
}

fn is_bare_ident(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

/// Rendered `module::Enum` paths the schema tokenizer expects prost to have
/// generated, sorted.
pub(crate) fn expected_oneof_paths(oneofs: &[(String, String)]) -> Vec<String> {
    let mut expected: Vec<String> =
        oneofs.iter().map(|(parent, oneof)| prost_oneof_path(parent, oneof)).collect();
    expected.sort();
    expected.dedup();
    expected
}

/// Generated oneof enums the schema tokenizer missed, sorted. A nonempty
/// result must fail the build: the missed oneof keeps a payload-printing
/// derived `Debug`.
pub(crate) fn missing_oneofs(oneofs: &[(String, String)], generated: &[String]) -> Vec<String> {
    let expected: BTreeSet<String> = expected_oneof_paths(oneofs).into_iter().collect();
    let mut missing: Vec<String> =
        generated.iter().filter(|path| !expected.contains(*path)).cloned().collect();
    missing.sort();
    missing
}

/// Schema-tokenizer entries prost did not generate, sorted. A nonempty
/// result must fail the build: the tokenizer (or the mapping) drifted from
/// prost's actual output.
pub(crate) fn stale_oneofs(oneofs: &[(String, String)], generated: &[String]) -> Vec<String> {
    let generated: BTreeSet<&str> = generated.iter().map(String::as_str).collect();
    let mut stale: Vec<String> = expected_oneof_paths(oneofs)
        .into_iter()
        .filter(|path| !generated.contains(path.as_str()))
        .collect();
    stale.sort();
    stale
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `(parent message, oneof)` pair in the schema. A new schema
    /// oneof lands here via the tokenizer test below and fails until this
    /// list (and the prost-enum list) is extended with review.
    const EXPECTED_SCHEMA_ONEOFS: &[(&str, &str)] = &[
        ("Attribute", "value"),
        ("AttributeResult", "result"),
        ("AuthenticatedMechanismOutput", "output"),
        ("Mechanism", "params"),
        ("MessageParameter", "params"),
        ("MessageParameterEffects", "effect"),
        ("Sp800108Attribute", "value"),
    ];

    /// Every oneof enum prost must generate, as `module::Enum` paths.
    const EXPECTED_PROST_ENUMS: &[&str] = &[
        "attribute::Value",
        "attribute_result::Result",
        "authenticated_mechanism_output::Output",
        "mechanism::Params",
        "message_parameter::Params",
        "message_parameter_effects::Effect",
        "sp800108_attribute::Value",
    ];

    fn schema_oneofs() -> Vec<(String, String)> {
        let mut oneofs = Vec::new();
        for source in [
            include_str!("../../../proto/pkcs11-proxy-ng/v1/service.proto"),
            include_str!("../../../proto/pkcs11-proxy-ng/v1/types.proto"),
            include_str!("../../../proto/pkcs11-proxy-ng/v1/mechanism_params.proto"),
        ] {
            oneofs.extend(parse_oneofs_in_source(source, "test schema"));
        }
        oneofs.sort();
        oneofs.dedup();
        oneofs
    }

    fn prost_enums() -> Vec<String> {
        let generated = std::fs::read_to_string(concat!(env!("OUT_DIR"), "/pkcs11_proxy_ng.v1.rs"))
            .expect("prost output must exist: build.rs compiles the protos before tests run");
        parse_prost_oneof_enums(&generated)
    }

    #[test]
    fn schema_tokenizer_finds_all_schema_oneofs() {
        let expected: Vec<(String, String)> = EXPECTED_SCHEMA_ONEOFS
            .iter()
            .map(|(parent, oneof)| ((*parent).to_owned(), (*oneof).to_owned()))
            .collect();
        assert_eq!(schema_oneofs(), expected);
    }

    #[test]
    fn prost_scan_finds_all_generated_oneof_enums() {
        assert_eq!(prost_enums(), EXPECTED_PROST_ENUMS);
    }

    #[test]
    fn cross_validation_passes_on_real_artifacts() {
        let oneofs = schema_oneofs();
        let generated = prost_enums();
        assert!(missing_oneofs(&oneofs, &generated).is_empty());
        assert!(stale_oneofs(&oneofs, &generated).is_empty());
    }

    /// Minimal prost-shaped fixture: two oneof enums, one top-level plain
    /// enum, and one tonic service module (brace-matched, never mined).
    const FIXTURE_GENERATED: &str = r#"
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlainEnum {
    Zero = 0,
}
pub mod alpha_parent {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Choice {
        #[prost(string, tag = "1")]
        A(::prost::alloc::string::String),
    }
}
pub mod pkcs11_proxy_client {
    #[derive(Debug, Clone)]
    pub struct Client {
    }
}
pub mod beta_parent {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Selection {
        #[prost(bool, tag = "1")]
        B(bool),
    }
}
"#;

    #[test]
    fn prost_scan_fixture_extracts_only_oneof_enums() {
        assert_eq!(
            parse_prost_oneof_enums(FIXTURE_GENERATED),
            ["alpha_parent::Choice", "beta_parent::Selection"]
        );
    }

    /// Negative control (W1-C8-07 acceptance): a tokenizer list missing a
    /// generated oneof is reported by name, so the build failure names the
    /// exact enum that would keep a payload-printing derived `Debug`.
    #[test]
    fn missing_oneof_is_reported_by_name() {
        let generated = parse_prost_oneof_enums(FIXTURE_GENERATED);
        // Simulate the tokenizer missing `beta_parent::Selection`.
        let oneofs = [("AlphaParent".to_owned(), "choice".to_owned())];
        assert_eq!(missing_oneofs(&oneofs, &generated), ["beta_parent::Selection"]);
        assert!(stale_oneofs(&oneofs, &generated).is_empty());
    }

    #[test]
    fn stale_tokenizer_entry_is_reported_by_name() {
        let generated = parse_prost_oneof_enums(FIXTURE_GENERATED);
        let oneofs = [
            ("AlphaParent".to_owned(), "choice".to_owned()),
            ("BetaParent".to_owned(), "selection".to_owned()),
            ("Ghost".to_owned(), "thing".to_owned()),
        ];
        assert!(missing_oneofs(&oneofs, &generated).is_empty());
        assert_eq!(stale_oneofs(&oneofs, &generated), ["ghost::Thing"]);
    }

    #[test]
    #[should_panic(expected = "lacks the prost::Oneof derive")]
    fn module_enum_without_oneof_derive_fails_closed() {
        parse_prost_oneof_enums(
            "pub mod nested_plain {\n    #[derive(Clone, Copy)]\n    pub enum Plain {\n        A = 0,\n    }\n}\n",
        );
    }
}
