use super::super::grant::{ExtractPolicy, ObjectAcl, TokenGrant, parse_class, parse_mechanism};
use super::*;
use pkcs11_proxy_ng_types::{CkMechanismType, CkObjectClass};

/// Test-local discovery filter. The production server filters tokens per-slot
/// via `slot_is_authorized`, so this mirrors that intent over the public
/// `allows` to exercise the real authorization path against multi-token
/// matrices (L9: the former `TokenPolicy::visible_tokens` was production dead
/// code referenced only by these tests).
fn visible_tokens<'a>(
    policy: &TokenPolicy,
    identity: &AuthenticatedIdentity,
    tokens: &'a [(String, String)],
) -> Vec<&'a (String, String)> {
    tokens.iter().filter(|(label, serial)| policy.allows(identity, label, serial)).collect()
}

// Helper: make a `TokenAccess::Specific` from bare `TokenSelector`s (back-compat form).
fn specific(selectors: Vec<TokenSelector>) -> TokenAccess {
    TokenAccess::Specific(selectors.into_iter().map(TokenGrant::simple).collect())
}

#[test]
fn unauthenticated_always_allowed() {
    let policy = TokenPolicy {
        rules: HashMap::new(),
        allow_all_authenticated: false,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    assert!(policy.allows(&AuthenticatedIdentity::Unauthenticated, "any", "any"));
}

#[test]
fn allow_all_authenticated_bypasses_rules() {
    let policy = TokenPolicy {
        rules: HashMap::new(),
        allow_all_authenticated: true,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(policy.allows(&id, "token1", "serial1"));
}

#[test]
fn default_deny_for_unknown_identity() {
    let policy = TokenPolicy {
        rules: HashMap::new(),
        allow_all_authenticated: false,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(!policy.allows(&id, "token1", "serial1"));
}

#[test]
fn label_selector_matches() {
    let mut rules = HashMap::new();
    rules.insert("uid=1000".into(), specific(vec![TokenSelector::Label("my-token".into())]));
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(policy.allows(&id, "my-token", "any-serial"));
    assert!(!policy.allows(&id, "other-token", "any-serial"));
}

#[test]
fn serial_selector_matches() {
    let mut rules = HashMap::new();
    rules.insert("uid=1000".into(), specific(vec![TokenSelector::Serial("SN123".into())]));
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(policy.allows(&id, "any-label", "SN123"));
    assert!(!policy.allows(&id, "any-label", "SN999"));
}

#[test]
fn all_access_matches_everything() {
    let mut rules = HashMap::new();
    rules.insert("uid=0".into(), TokenAccess::All);
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 0 };
    assert!(policy.allows(&id, "any", "any"));
}

#[test]
fn mtls_identity_display_format() {
    let id = AuthenticatedIdentity::Mtls {
        issuer: "CN=TestCA".into(),
        subject: "CN=client1".into(),
        spki_sha256: "".into(),
    };
    assert_eq!(id.to_string(), "x509:issuer=CN=TestCA;subject=CN=client1");
}

#[test]
fn pkcs11_uri_selectors_rejected_at_parse() {
    // W1-C3-17: the unconstructible TokenSelector::Uri variant is gone
    // (there is no matches() arm left to hardcode); pkcs11: URIs fail
    // loudly at parse — use label:/serial:.
    let err = TokenSelector::parse("pkcs11:token=foo").unwrap_err();
    assert!(err.contains("not yet supported"), "error: {err}");
}

#[test]
fn from_config_builds_policy() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::Specific(vec![
                crate::config::GrantSpec::Bare("label:my-token".into()),
                crate::config::GrantSpec::Bare("serial:SN456".into()),
                crate::config::GrantSpec::Bare("bare-label".into()),
            ]),
        }],
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(policy.allows(&id, "my-token", "any"));
    assert!(policy.allows(&id, "any", "SN456"));
    assert!(policy.allows(&id, "bare-label", "any"));
    assert!(!policy.allows(&id, "other", "other"));
}

#[test]
fn mtls_identity_matches_policy_by_display_key() {
    let mtls_key = "x509:issuer=CN=Root CA;subject=CN=client1";
    let mut rules = HashMap::new();
    rules.insert(mtls_key.to_string(), TokenAccess::All);
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };

    let allowed = AuthenticatedIdentity::Mtls {
        issuer: "CN=Root CA".into(),
        subject: "CN=client1".into(),
        spki_sha256: "".into(),
    };
    let wrong_subject = AuthenticatedIdentity::Mtls {
        issuer: "CN=Root CA".into(),
        subject: "CN=other".into(),
        spki_sha256: "".into(),
    };
    assert!(policy.allows(&allowed, "any", "any"));
    assert!(!policy.allows(&wrong_subject, "any", "any"));
}

#[test]
fn multiple_identities_independent_access() {
    let mut rules = HashMap::new();
    rules.insert("uid=1000".into(), TokenAccess::All);
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };

    let allowed = AuthenticatedIdentity::PeerCred { uid: 1000 };
    let denied = AuthenticatedIdentity::PeerCred { uid: 2000 };
    assert!(policy.allows(&allowed, "any", "any"));
    assert!(!policy.allows(&denied, "any", "any"));
}

#[test]
fn specific_access_empty_selectors_denies_everything() {
    let mut rules = HashMap::new();
    rules.insert("uid=1000".into(), TokenAccess::Specific(vec![]));
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(!policy.allows(&id, "any-label", "any-serial"));
}

#[test]
fn multiple_selectors_any_match_wins() {
    let mut rules = HashMap::new();
    rules.insert(
        "uid=1000".into(),
        specific(vec![
            TokenSelector::Label("token-a".into()),
            TokenSelector::Serial("SN-A".into()),
        ]),
    );
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };

    assert!(policy.allows(&id, "token-a", "unrelated-serial"));
    assert!(policy.allows(&id, "unrelated-label", "SN-A"));
    assert!(!policy.allows(&id, "other-label", "other-serial"));
}

#[test]
fn from_config_with_all_access() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=0".into(),
            tokens: crate::config::TokenAccessSpec::All("*".into()),
        }],
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    let root = AuthenticatedIdentity::PeerCred { uid: 0 };
    assert!(policy.allows(&root, "anything", "anything"));
}

#[test]
fn token_selector_label_case_sensitive() {
    let selector = TokenSelector::Label("MyToken".into());
    assert!(selector.matches("MyToken", "any"));
    assert!(!selector.matches("mytoken", "any"));
    assert!(!selector.matches("MYTOKEN", "any"));
}

#[test]
fn token_selector_serial_case_sensitive() {
    let selector = TokenSelector::Serial("ABC123".into());
    assert!(selector.matches("any", "ABC123"));
    assert!(!selector.matches("any", "abc123"));
}

#[test]
fn root_uid_denied_when_not_in_policy() {
    let policy = TokenPolicy {
        rules: HashMap::new(),
        allow_all_authenticated: false,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let root = AuthenticatedIdentity::PeerCred { uid: 0 };
    assert!(!policy.allows(&root, "any", "any"));
}

#[test]
fn parse_label_selector() {
    let s = TokenSelector::parse("label:MyToken").unwrap();
    assert_eq!(s, TokenSelector::Label("MyToken".into()));
}

#[test]
fn parse_serial_selector() {
    let s = TokenSelector::parse("serial:SN123").unwrap();
    assert_eq!(s, TokenSelector::Serial("SN123".into()));
}

#[test]
fn parse_bare_string_defaults_to_label() {
    let s = TokenSelector::parse("bare-token").unwrap();
    assert_eq!(s, TokenSelector::Label("bare-token".into()));
}

#[test]
fn parse_rejects_pkcs11_uri_selector() {
    // pkcs11: URI selectors are not implemented; they would match nothing and
    // silently deny, locking the operator out. parse() must reject them loudly
    // at config load instead.
    let err = TokenSelector::parse("pkcs11:token=foo;serial=bar").unwrap_err();
    assert!(err.contains("pkcs11:"), "error should name the unsupported form: {err}");
}

#[test]
fn parse_empty_selector_rejected() {
    assert!(TokenSelector::parse("").is_err());
    assert!(TokenSelector::parse("   ").is_err());
}

#[test]
fn parse_empty_label_value_rejected() {
    assert!(TokenSelector::parse("label:").is_err());
    assert!(TokenSelector::parse("label:   ").is_err());
}

#[test]
fn parse_empty_serial_value_rejected() {
    assert!(TokenSelector::parse("serial:").is_err());
    assert!(TokenSelector::parse("serial:  ").is_err());
}

#[test]
fn parse_unrecognized_prefix_rejected() {
    let err = TokenSelector::parse("lable:foo").unwrap_err();
    assert!(err.contains("unrecognized selector prefix"), "error: {err}");
}

#[test]
fn parse_trims_trailing_padding_only() {
    // W1-C3-37 reverses the old trim-everything behavior this test
    // pinned: leading characters are significant per backend semantics
    // (blank-padded fields pad only the trailing end), so leading
    // whitespace is preserved in values, and a leading-whitespace
    // prefix is rejected loudly instead of silently matching the
    // unpadded label (the old direction was over-permissive).
    let s = TokenSelector::parse("label:Token  ").unwrap();
    assert_eq!(s, TokenSelector::Label("Token".into()));
    let s = TokenSelector::parse("label:  Token").unwrap();
    assert_eq!(s, TokenSelector::Label("  Token".into()));
    assert!(TokenSelector::parse("  label:Token").is_err());
}

#[test]
fn from_config_rejects_empty_selector() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::Specific(vec![crate::config::GrantSpec::Bare(
                "".into(),
            )]),
        }],
    };
    let err = TokenPolicy::from_config(&auth).unwrap_err();
    assert!(err.contains("empty"), "error should mention empty: {err}");
}

#[test]
fn from_config_rejects_typo_prefix() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::Specific(vec![crate::config::GrantSpec::Bare(
                "lable:foo".into(),
            )]),
        }],
    };
    let err = TokenPolicy::from_config(&auth).unwrap_err();
    assert!(err.contains("unrecognized"), "error should mention unrecognized: {err}");
}

fn matrix_policy() -> TokenPolicy {
    let mut rules = HashMap::new();
    rules.insert(
        "uid=1000".into(),
        specific(vec![
            TokenSelector::Label("token-a".into()),
            TokenSelector::Serial("SN-B".into()),
        ]),
    );
    rules.insert("uid=2000".into(), specific(vec![TokenSelector::Label("token-c".into())]));
    rules.insert("x509:issuer=CN=Root;subject=CN=admin".into(), TokenAccess::All);
    rules.insert(
        "x509:issuer=CN=Root;subject=CN=reader".into(),
        specific(vec![TokenSelector::Label("token-a".into())]),
    );
    rules.insert("uid=9999".into(), TokenAccess::Specific(vec![]));
    TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    }
}

fn token_list() -> Vec<(String, String)> {
    vec![
        ("token-a".into(), "SN-A".into()),
        ("token-b".into(), "SN-B".into()),
        ("token-c".into(), "SN-C".into()),
        ("token-d".into(), "SN-D".into()),
    ]
}

#[test]
fn discovery_uid1000_sees_token_a_and_b() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    let tokens = token_list();
    let visible = visible_tokens(&policy, &id, &tokens);
    let labels: Vec<&str> = visible.iter().map(|(l, _)| l.as_str()).collect();
    assert_eq!(labels, vec!["token-a", "token-b"]);
}

#[test]
fn discovery_uid2000_sees_only_token_c() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 2000 };
    let tokens = token_list();
    let visible = visible_tokens(&policy, &id, &tokens);
    let labels: Vec<&str> = visible.iter().map(|(l, _)| l.as_str()).collect();
    assert_eq!(labels, vec!["token-c"]);
}

#[test]
fn discovery_admin_mtls_sees_all() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::Mtls {
        issuer: "CN=Root".into(),
        subject: "CN=admin".into(),
        spki_sha256: "".into(),
    };
    let tokens = token_list();
    let visible = visible_tokens(&policy, &id, &tokens);
    assert_eq!(visible.len(), 4, "admin should see all 4 tokens");
}

#[test]
fn discovery_reader_mtls_sees_one() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::Mtls {
        issuer: "CN=Root".into(),
        subject: "CN=reader".into(),
        spki_sha256: "".into(),
    };
    let tokens = token_list();
    let visible = visible_tokens(&policy, &id, &tokens);
    let labels: Vec<&str> = visible.iter().map(|(l, _)| l.as_str()).collect();
    assert_eq!(labels, vec!["token-a"]);
}

#[test]
fn discovery_unknown_uid_sees_nothing() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 5000 };
    let tokens = token_list();
    let visible = visible_tokens(&policy, &id, &tokens);
    assert!(visible.is_empty(), "unknown identity should see no tokens");
}

#[test]
fn discovery_explicit_deny_sees_nothing() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 9999 };
    let tokens = token_list();
    let visible = visible_tokens(&policy, &id, &tokens);
    assert!(visible.is_empty(), "identity with empty selectors should see no tokens");
}

#[test]
fn discovery_unauthenticated_sees_all() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::Unauthenticated;
    let tokens = token_list();
    let visible = visible_tokens(&policy, &id, &tokens);
    assert_eq!(visible.len(), 4, "unauthenticated mode bypasses policy, sees all tokens");
}

#[test]
fn discovery_empty_token_list() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    let visible = visible_tokens(&policy, &id, &[]);
    assert!(visible.is_empty());
}

#[test]
fn denial_uid1000_denied_token_c() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(!policy.allows(&id, "token-c", "SN-C"), "uid=1000 must not access token-c");
}

#[test]
fn denial_uid1000_denied_token_d() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(!policy.allows(&id, "token-d", "SN-D"), "uid=1000 must not access token-d");
}

#[test]
fn denial_uid2000_denied_token_a() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 2000 };
    assert!(!policy.allows(&id, "token-a", "SN-A"), "uid=2000 must not access token-a");
}

#[test]
fn denial_reader_denied_token_b() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::Mtls {
        issuer: "CN=Root".into(),
        subject: "CN=reader".into(),
        spki_sha256: "".into(),
    };
    assert!(!policy.allows(&id, "token-b", "SN-B"), "reader should not access token-b");
}

#[test]
fn mtls_issuer_mismatch_denied() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::Mtls {
        issuer: "CN=Other CA".into(),
        subject: "CN=admin".into(),
        spki_sha256: "".into(),
    };
    assert!(!policy.allows(&id, "token-a", "SN-A"), "wrong issuer must be denied");
}

#[test]
fn mtls_subject_mismatch_denied() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::Mtls {
        issuer: "CN=Root".into(),
        subject: "CN=attacker".into(),
        spki_sha256: "".into(),
    };
    assert!(!policy.allows(&id, "token-a", "SN-A"), "wrong subject must be denied");
}

#[test]
fn peer_cred_vs_mtls_identity_collision_impossible() {
    let peer = AuthenticatedIdentity::PeerCred { uid: 1000 };
    let mtls = AuthenticatedIdentity::Mtls {
        issuer: "uid=1000".into(),
        subject: "".into(),
        spki_sha256: "".into(),
    };
    assert_ne!(
        peer.to_string(),
        mtls.to_string(),
        "PeerCred and Mtls must produce distinct display strings"
    );
}

#[test]
fn cross_identity_no_leakage() {
    let policy = matrix_policy();
    let tokens = token_list();

    struct Case {
        id: AuthenticatedIdentity,
        expected_labels: Vec<&'static str>,
    }

    let cases = [
        Case {
            id: AuthenticatedIdentity::PeerCred { uid: 1000 },
            expected_labels: vec!["token-a", "token-b"],
        },
        Case {
            id: AuthenticatedIdentity::PeerCred { uid: 2000 },
            expected_labels: vec!["token-c"],
        },
        Case {
            id: AuthenticatedIdentity::Mtls {
                issuer: "CN=Root".into(),
                subject: "CN=admin".into(),
                spki_sha256: "".into(),
            },
            expected_labels: vec!["token-a", "token-b", "token-c", "token-d"],
        },
        Case {
            id: AuthenticatedIdentity::Mtls {
                issuer: "CN=Root".into(),
                subject: "CN=reader".into(),
                spki_sha256: "".into(),
            },
            expected_labels: vec!["token-a"],
        },
        Case { id: AuthenticatedIdentity::PeerCred { uid: 5000 }, expected_labels: vec![] },
        Case { id: AuthenticatedIdentity::PeerCred { uid: 9999 }, expected_labels: vec![] },
    ];

    for (i, case) in cases.iter().enumerate() {
        let visible = visible_tokens(&policy, &case.id, &tokens);
        let labels: Vec<&str> = visible.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(
            labels, case.expected_labels,
            "case {i}: identity {} saw {:?}, expected {:?}",
            case.id, labels, case.expected_labels
        );
    }
}

#[test]
fn allow_all_authenticated_overrides_restrictive_rules() {
    let mut rules = HashMap::new();
    rules.insert("uid=1000".into(), specific(vec![TokenSelector::Label("token-a".into())]));
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: true,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(policy.allows(&id, "token-b", "SN-B"));
}

#[test]
fn allow_all_authenticated_allows_unknown_identity() {
    let policy = TokenPolicy {
        rules: HashMap::new(),
        allow_all_authenticated: true,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 99999 };
    assert!(
        policy.allows(&id, "any", "any"),
        "allow_all_authenticated should permit even unlisted identities"
    );
}

#[test]
fn allow_all_authenticated_does_not_affect_unauthenticated() {
    for flag in [true, false] {
        let policy = TokenPolicy {
            rules: HashMap::new(),
            allow_all_authenticated: flag,
            has_policy: false,
            anonymous_principal: None,
            per_object_active_cache: false,
            per_class_active_cache: false,
            per_mechanism_active_cache: false,
        };
        assert!(policy.allows(&AuthenticatedIdentity::Unauthenticated, "any", "any"));
    }
}

#[test]
fn serial_selector_grants_regardless_of_label() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(policy.allows(&id, "renamed-token", "SN-B"));
    assert!(policy.allows(&id, "", "SN-B"));
}

#[test]
fn duplicate_identity_in_config_is_rejected_loudly() {
    // W1-C3-05: duplicate identities fail load (naming the identity) instead
    // of the former silent last-wins overwrite, which dropped the first
    // entry's grants without warning.
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![
            crate::config::PolicyEntry {
                identity: "uid=1000".into(),
                tokens: crate::config::TokenAccessSpec::Specific(vec![
                    crate::config::GrantSpec::Bare("label:token-a".into()),
                ]),
            },
            crate::config::PolicyEntry {
                identity: "uid=1000".into(),
                tokens: crate::config::TokenAccessSpec::Specific(vec![
                    crate::config::GrantSpec::Bare("label:token-b".into()),
                ]),
            },
        ],
    };
    let err = TokenPolicy::from_config(&auth).unwrap_err();
    assert!(
        err.contains("duplicate") && err.contains("uid=1000"),
        "duplicate identity must fail load naming the identity, got: {err}"
    );
}

#[test]
fn unauthenticated_decision_routes_through_single_flip_point() {
    // `allows()` for an Unauthenticated identity must equal `allows_unauthenticated()`
    // (the single G2-PR2 deny-default flip-point) — not an independent inline `true`.
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        policy: vec![],
        anonymous_principal: None,
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    let unauth = AuthenticatedIdentity::Unauthenticated;
    assert_eq!(
        policy.allows(&unauth, "any", "any"),
        policy.allows_unauthenticated(),
        "the Unauthenticated case must delegate to the single flip-point"
    );
    // G2-PR2 is now deployed: no-policy (transport) mode still allows (has_policy=false).
    assert!(
        policy.allows_unauthenticated(),
        "no-policy transport mode must allow unauthenticated peers"
    );
}

#[test]
fn allow_all_authenticated_does_not_depend_on_unauthenticated_path() {
    // With allow_all_authenticated=true, an AUTHENTICATED identity is allowed via
    // the allow_all branch; the Unauthenticated branch is handled separately by the
    // flip-point, so allow_all never independently authorizes an unauthenticated peer.
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: true,
        policy: vec![],
        anonymous_principal: None,
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    let authed = AuthenticatedIdentity::PeerCred { uid: 42 };
    assert!(policy.allows(&authed, "any", "any"), "allow_all applies to authenticated");
    // Unauthenticated still routes through the flip-point, independent of allow_all.
    let unauth = AuthenticatedIdentity::Unauthenticated;
    assert_eq!(policy.allows(&unauth, "any", "any"), policy.allows_unauthenticated());
}

#[test]
fn dual_accept_emits_deprecation_warning_for_legacy_dn_key() {
    // A policy with a legacy x509:issuer=...;subject=... key authorizes via the
    // dual-accept fallback. The primary SPKI lookup misses; the legacy DN lookup hits.
    let legacy_key = "x509:issuer=CN=DualAccept CA;subject=CN=transition-client";
    let mut rules = HashMap::new();
    rules.insert(legacy_key.to_string(), TokenAccess::All);
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };

    // Identity with both SPKI and DN — the SPKI key won't be in rules, but the DN key will.
    let id = AuthenticatedIdentity::Mtls {
        issuer: "CN=DualAccept CA".into(),
        subject: "CN=transition-client".into(),
        spki_sha256: "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666000077778888aaaa".into(),
    };
    // Dual-accept: legacy key hit even though SPKI key is absent
    assert!(policy.allows(&id, "any", "any"), "dual-accept must authorize via legacy DN key");

    // A DIFFERENT cert with the SAME DN but different SPKI would also get authorized via
    // the legacy DN lookup — this is the documented transition risk (operators should migrate
    // to x509:spki= to close the spoof window).
    let id_spoof = AuthenticatedIdentity::Mtls {
        issuer: "CN=DualAccept CA".into(),
        subject: "CN=transition-client".into(),
        spki_sha256: "bbbb2222cccc3333dddd4444eeee5555ffff6666000077778888aaaa9999bbbb".into(),
    };
    assert!(
        policy.allows(&id_spoof, "any", "any"),
        "legacy DN policy matches ANY cert with that DN (documented transition risk; use SPKI to close)"
    );
}

// --- G2-PR2: deny-default flip-point tests ---

#[test]
fn allows_unauthenticated_no_policy_no_anon_is_true() {
    // Transport mode: no policy → unauthenticated allowed (legacy behaviour preserved).
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        policy: vec![],
        anonymous_principal: None,
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    assert!(
        policy.allows_unauthenticated(),
        "no-policy transport mode must allow unauthenticated peers"
    );
}

#[test]
fn allows_unauthenticated_policy_set_no_anon_is_false() {
    // Policy configured, no anonymous_principal → deny-default for unauthenticated peers.
    // (Validation normally prevents this combo with an auth=none listener, but the
    // flip-point must work correctly at the pure policy level regardless.)
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::All("all".into()),
        }],
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    assert!(
        !policy.allows_unauthenticated(),
        "policy-configured mode without anonymous_principal must deny unauthenticated peers"
    );
    // And allows() routes through the flip-point, so unauthenticated is denied there too.
    assert!(
        !policy.allows(&AuthenticatedIdentity::Unauthenticated, "any", "any"),
        "allows() for Unauthenticated must honour the deny-default flip"
    );
}

#[test]
fn allows_unauthenticated_policy_set_with_anon_is_true() {
    // Policy + anonymous_principal: operator has named the audit identity; allow.
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: Some("anon-client".into()),
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::All("all".into()),
        }],
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    assert!(
        policy.allows_unauthenticated(),
        "policy + anonymous_principal must allow unauthenticated peers"
    );
}

#[test]
fn allows_unauthenticated_no_policy_with_anon_is_true() {
    // No policy, but anonymous_principal set: allowed (no-policy is already allow;
    // anon name is carried for audit labelling).
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: Some("anon-client".into()),
        policy: vec![],
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    assert!(
        policy.allows_unauthenticated(),
        "no-policy + anonymous_principal must allow unauthenticated peers"
    );
}

#[test]
fn audit_identity_substitutes_anon_name_for_unauthenticated() {
    // When anonymous_principal is set, audit_identity() substitutes the configured
    // name for "unauthenticated" and None (audit-identity only path).
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: Some("anon-label".into()),
        policy: vec![],
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    assert_eq!(
        policy.audit_identity(Some("unauthenticated")),
        Some("anon-label".into()),
        "audit_identity should substitute anon name for 'unauthenticated'"
    );
    assert_eq!(
        policy.audit_identity(None),
        Some("anon-label".into()),
        "audit_identity should substitute anon name for None context"
    );
    // Authenticated identities are passed through unchanged.
    assert_eq!(
        policy.audit_identity(Some("uid=1000")),
        Some("uid=1000".into()),
        "audit_identity must not alter authenticated identities"
    );
}

#[test]
fn audit_identity_without_anon_returns_stored() {
    // No anonymous_principal: audit_identity() returns the stored value verbatim.
    let policy = TokenPolicy {
        rules: HashMap::new(),
        allow_all_authenticated: false,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    assert_eq!(policy.audit_identity(Some("unauthenticated")), Some("unauthenticated".into()));
    assert_eq!(policy.audit_identity(None), None);
    assert_eq!(policy.audit_identity(Some("uid=42")), Some("uid=42".into()));
}

// ============================================================================
// Task 4 — class/mechanism/extract grant model tests
// ============================================================================

/// Build a policy that has a richer grant: access to "label:Prod" is restricted
/// to secret_key + private_key classes, CKM_AES_GCM mechanism, with extract=Deny.
fn rich_grant_policy() -> TokenPolicy {
    let grant = TokenGrant {
        selector: TokenSelector::Label("Prod".into()),
        classes: Some(vec![CkObjectClass::SECRET_KEY, CkObjectClass::PRIVATE_KEY]),
        mechanisms: Some(vec![CkMechanismType::AES_GCM]),
        extract: ExtractPolicy::Deny,
        objects: None,
    };
    let mut rules = HashMap::new();
    rules.insert("uid=1000".into(), TokenAccess::Specific(vec![grant]));
    rules.insert("uid=9000".into(), TokenAccess::All);
    TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: true,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    }
}

// --- Back-compat: string forms parse to grants with extract=Allow, classes/mechs=None ---

#[test]
fn backcompat_all_access_spec_parses() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1".into(),
            tokens: crate::config::TokenAccessSpec::All("all".into()),
        }],
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    let id = AuthenticatedIdentity::PeerCred { uid: 1 };
    // All → extract allowed, any class, any mechanism
    assert!(policy.extract_allowed(&id, "any", "any"));
    assert!(policy.allows_class(&id, "any", "any", CkObjectClass::SECRET_KEY));
    assert!(policy.allows_mechanism(&id, "any", "any", CkMechanismType::AES_GCM));
}

#[test]
fn backcompat_bare_string_grants_have_no_restrictions() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::Specific(vec![crate::config::GrantSpec::Bare(
                "label:Prod".into(),
            )]),
        }],
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    // Bare string → extract=Allow, classes=None, mechanisms=None
    assert!(policy.allows(&id, "Prod", "any-serial"));
    assert!(policy.extract_allowed(&id, "Prod", "any-serial"));
    assert!(policy.allows_class(&id, "Prod", "any-serial", CkObjectClass::CERTIFICATE));
    assert!(policy.allows_mechanism(&id, "Prod", "any-serial", CkMechanismType::RSA_PKCS));
}

// --- Richer grant form: class/mechanism/extract restrictions ---

#[test]
fn rich_grant_extract_denied_for_matched_token() {
    let policy = rich_grant_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    // Token-level access is granted
    assert!(policy.allows(&id, "Prod", "any-serial"));
    // But extract is denied by the grant
    assert!(!policy.extract_allowed(&id, "Prod", "any-serial"));
}

#[test]
fn rich_grant_extract_allowed_for_unmatched_token() {
    let policy = rich_grant_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    // Token "Dev" not in grants → extract_allowed returns true (no restriction = default allow)
    assert!(policy.extract_allowed(&id, "Dev", "any-serial"));
}

#[test]
fn rich_grant_extract_allowed_for_different_identity() {
    let policy = rich_grant_policy();
    // uid=9000 has TokenAccess::All → no extract restriction
    let id = AuthenticatedIdentity::PeerCred { uid: 9000 };
    assert!(policy.extract_allowed(&id, "Prod", "any-serial"));
}

#[test]
fn rich_grant_extract_allowed_for_unauthenticated() {
    let policy = rich_grant_policy();
    let unauth = AuthenticatedIdentity::Unauthenticated;
    // Unauthenticated → extract always allowed (extract-deny is authenticated-identity opt-in)
    assert!(policy.extract_allowed(&unauth, "Prod", "any-serial"));
}

#[test]
fn rich_grant_allows_mechanism_listed() {
    let policy = rich_grant_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    // AES_GCM is listed → allowed
    assert!(policy.allows_mechanism(&id, "Prod", "any-serial", CkMechanismType::AES_GCM));
}

#[test]
fn rich_grant_denies_mechanism_not_listed() {
    let policy = rich_grant_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    // RSA_PKCS is not in the list → denied
    assert!(!policy.allows_mechanism(&id, "Prod", "any-serial", CkMechanismType::RSA_PKCS));
}

#[test]
fn rich_grant_allows_class_listed() {
    let policy = rich_grant_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(policy.allows_class(&id, "Prod", "any-serial", CkObjectClass::SECRET_KEY));
    assert!(policy.allows_class(&id, "Prod", "any-serial", CkObjectClass::PRIVATE_KEY));
}

#[test]
fn rich_grant_denies_class_not_listed() {
    let policy = rich_grant_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    // CERTIFICATE not in classes list → denied
    assert!(!policy.allows_class(&id, "Prod", "any-serial", CkObjectClass::CERTIFICATE));
    assert!(!policy.allows_class(&id, "Prod", "any-serial", CkObjectClass::PUBLIC_KEY));
}

#[test]
fn rich_grant_all_access_allows_any_class_and_mechanism() {
    let policy = rich_grant_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 9000 }; // TokenAccess::All
    assert!(policy.allows_class(&id, "Prod", "any-serial", CkObjectClass::DATA));
    assert!(policy.allows_mechanism(&id, "Prod", "any-serial", CkMechanismType::ECDSA));
}

#[test]
fn rich_grant_none_classes_means_all() {
    // A grant with classes=None allows every object class.
    let grant = TokenGrant {
        selector: TokenSelector::Label("MyToken".into()),
        classes: None,
        mechanisms: None,
        extract: ExtractPolicy::Allow,
        objects: None,
    };
    let mut rules = HashMap::new();
    rules.insert("uid=42".into(), TokenAccess::Specific(vec![grant]));
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: true,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 42 };
    assert!(policy.allows_class(&id, "MyToken", "any", CkObjectClass::DATA));
    assert!(policy.allows_class(&id, "MyToken", "any", CkObjectClass::CERTIFICATE));
    assert!(policy.allows_class(&id, "MyToken", "any", CkObjectClass::SECRET_KEY));
    assert!(policy.extract_allowed(&id, "MyToken", "any"));
}

// --- Config round-trip: richer form parses correctly ---

#[test]
fn from_config_rich_grant_parses() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::Specific(vec![crate::config::GrantSpec::Rich(
                crate::config::RichGrantConfig {
                    token: "label:Prod".into(),
                    classes: Some(vec!["secret_key".into(), "private_key".into()]),
                    mechanisms: Some(vec!["CKM_AES_GCM".into()]),
                    extract: crate::config::ExtractPolicyConfig::Deny,
                    objects: None,
                },
            )]),
        }],
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };

    // Token-level access
    assert!(policy.allows(&id, "Prod", "any-serial"));
    // Extract denied
    assert!(!policy.extract_allowed(&id, "Prod", "any-serial"));
    // Class restrictions
    assert!(policy.allows_class(&id, "Prod", "any-serial", CkObjectClass::SECRET_KEY));
    assert!(!policy.allows_class(&id, "Prod", "any-serial", CkObjectClass::CERTIFICATE));
    // Mechanism restrictions
    assert!(policy.allows_mechanism(&id, "Prod", "any-serial", CkMechanismType::AES_GCM));
    assert!(!policy.allows_mechanism(&id, "Prod", "any-serial", CkMechanismType::RSA_PKCS));
}

#[test]
fn from_config_mixed_bare_and_rich_grants() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::Specific(vec![
                // Bare grant: no restrictions on "Dev"
                crate::config::GrantSpec::Bare("label:Dev".into()),
                // Rich grant: restricted on "Prod"
                crate::config::GrantSpec::Rich(crate::config::RichGrantConfig {
                    token: "label:Prod".into(),
                    classes: Some(vec!["secret_key".into()]),
                    mechanisms: None,
                    extract: crate::config::ExtractPolicyConfig::Deny,
                    objects: None,
                }),
            ]),
        }],
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };

    // Dev token: no restrictions
    assert!(policy.allows(&id, "Dev", "any"));
    assert!(policy.extract_allowed(&id, "Dev", "any"));
    assert!(policy.allows_class(&id, "Dev", "any", CkObjectClass::CERTIFICATE));

    // Prod token: class and extract restricted
    assert!(policy.allows(&id, "Prod", "any"));
    assert!(!policy.extract_allowed(&id, "Prod", "any"));
    assert!(policy.allows_class(&id, "Prod", "any", CkObjectClass::SECRET_KEY));
    assert!(!policy.allows_class(&id, "Prod", "any", CkObjectClass::CERTIFICATE));
}

// --- Name parsing ---

#[test]
fn parse_class_named_forms() {
    assert_eq!(parse_class("data").unwrap(), CkObjectClass::DATA);
    assert_eq!(parse_class("certificate").unwrap(), CkObjectClass::CERTIFICATE);
    assert_eq!(parse_class("public_key").unwrap(), CkObjectClass::PUBLIC_KEY);
    assert_eq!(parse_class("private_key").unwrap(), CkObjectClass::PRIVATE_KEY);
    assert_eq!(parse_class("secret_key").unwrap(), CkObjectClass::SECRET_KEY);
    assert_eq!(parse_class("CKO_DATA").unwrap(), CkObjectClass::DATA);
    assert_eq!(parse_class("CKO_CERTIFICATE").unwrap(), CkObjectClass::CERTIFICATE);
    assert_eq!(parse_class("CKO_PUBLIC_KEY").unwrap(), CkObjectClass::PUBLIC_KEY);
    assert_eq!(parse_class("CKO_PRIVATE_KEY").unwrap(), CkObjectClass::PRIVATE_KEY);
    assert_eq!(parse_class("CKO_SECRET_KEY").unwrap(), CkObjectClass::SECRET_KEY);
}

#[test]
fn parse_class_hex_and_decimal() {
    assert_eq!(parse_class("0x00000003").unwrap(), CkObjectClass::PRIVATE_KEY);
    assert_eq!(parse_class("3").unwrap(), CkObjectClass::PRIVATE_KEY);
    assert_eq!(parse_class("0x00000004").unwrap(), CkObjectClass::SECRET_KEY);
}

#[test]
fn parse_class_unknown_name_returns_error() {
    let err = parse_class("not_a_class").unwrap_err();
    assert!(err.contains("unknown object class"), "error: {err}");
    assert!(err.contains("not_a_class"), "error: {err}");
}

// W1-C3-20: the unknown-class error must list every accepted name,
// including vendor_defined (which parses successfully).
#[test]
fn parse_class_error_lists_vendor_defined() {
    assert_eq!(parse_class("vendor_defined").unwrap(), CkObjectClass::VENDOR_DEFINED);
    assert_eq!(parse_class("CKO_VENDOR_DEFINED").unwrap(), CkObjectClass::VENDOR_DEFINED);
    let err = parse_class("not_a_class").unwrap_err();
    for name in ["data", "certificate", "public_key", "private_key", "secret_key", "vendor_defined"]
    {
        assert!(err.contains(name), "error must list '{name}': {err}");
    }
}

#[test]
fn parse_mechanism_named_forms() {
    assert_eq!(parse_mechanism("CKM_AES_GCM").unwrap(), CkMechanismType::AES_GCM);
    assert_eq!(parse_mechanism("CKM_RSA_PKCS").unwrap(), CkMechanismType::RSA_PKCS);
    assert_eq!(parse_mechanism("CKM_ECDSA_SHA256").unwrap(), CkMechanismType::ECDSA_SHA256);
}

#[test]
fn parse_mechanism_hex_and_decimal() {
    assert_eq!(parse_mechanism("0x00001087").unwrap(), CkMechanismType::AES_GCM);
    assert_eq!(parse_mechanism("4231").unwrap(), CkMechanismType(4231));
}

#[test]
fn parse_mechanism_unknown_name_returns_error() {
    let err = parse_mechanism("CKM_TOTALLY_FAKE").unwrap_err();
    assert!(err.contains("unknown mechanism"), "error: {err}");
    assert!(err.contains("CKM_TOTALLY_FAKE"), "error: {err}");
}

#[test]
fn from_config_rich_grant_unknown_class_rejected() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::Specific(vec![crate::config::GrantSpec::Rich(
                crate::config::RichGrantConfig {
                    token: "label:Prod".into(),
                    classes: Some(vec!["not_a_real_class".into()]),
                    mechanisms: None,
                    extract: crate::config::ExtractPolicyConfig::Allow,
                    objects: None,
                },
            )]),
        }],
    };
    let err = TokenPolicy::from_config(&auth).unwrap_err();
    assert!(err.contains("unknown object class"), "error: {err}");
}

#[test]
fn from_config_rich_grant_unknown_mechanism_rejected() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::Specific(vec![crate::config::GrantSpec::Rich(
                crate::config::RichGrantConfig {
                    token: "label:Prod".into(),
                    classes: None,
                    mechanisms: Some(vec!["CKM_DOES_NOT_EXIST".into()]),
                    extract: crate::config::ExtractPolicyConfig::Allow,
                    objects: None,
                },
            )]),
        }],
    };
    let err = TokenPolicy::from_config(&auth).unwrap_err();
    assert!(err.contains("unknown mechanism"), "error: {err}");
}

#[test]
fn extract_allowed_returns_true_when_allow_all_authenticated() {
    // allow_all_authenticated bypasses per-grant extract restriction
    let grant = TokenGrant {
        selector: TokenSelector::Label("Prod".into()),
        classes: None,
        mechanisms: None,
        extract: ExtractPolicy::Deny,
        objects: None,
    };
    let mut rules = HashMap::new();
    rules.insert("uid=1".into(), TokenAccess::Specific(vec![grant]));
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: true, // blanket
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 1 };
    assert!(policy.extract_allowed(&id, "Prod", "any"));
}

// ============================================================================
// G3-PR1 — CKA_UNIQUE_ID + per-object allow-list grant model
// ============================================================================

// --- parse_object_unique_id ---

#[test]
fn parse_object_unique_id_valid_hex() {
    use super::super::grant::parse_object_unique_id;
    assert_eq!(parse_object_unique_id("a1b2").unwrap(), vec![0xa1u8, 0xb2u8]);
    assert_eq!(parse_object_unique_id("00ff").unwrap(), vec![0x00u8, 0xffu8]);
    // Trimming whitespace around valid hex
    assert_eq!(parse_object_unique_id("  a1b2  ").unwrap(), vec![0xa1u8, 0xb2u8]);
    // Empty string is rejected (M2): matches nothing but activates per-object authz.
    assert!(parse_object_unique_id("").is_err(), "empty string must be rejected (M2)");
}

#[test]
fn parse_object_unique_id_odd_length_rejected() {
    use super::super::grant::parse_object_unique_id;
    let err = parse_object_unique_id("a1b").unwrap_err();
    assert!(err.contains("a1b"), "error must name the bad value: {err}");
}

#[test]
fn parse_object_unique_id_non_hex_rejected() {
    use super::super::grant::parse_object_unique_id;
    let err = parse_object_unique_id("xyz").unwrap_err();
    assert!(err.contains("xyz"), "error must name the bad value: {err}");
}

// --- Config: objects field parsing ---

#[test]
fn from_config_objects_parses_hex_bytes() {
    // A rich grant with objects = ["a1b2"] must parse to a byte list.
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::Specific(vec![crate::config::GrantSpec::Rich(
                crate::config::RichGrantConfig {
                    token: "label:P".into(),
                    classes: None,
                    mechanisms: None,
                    extract: crate::config::ExtractPolicyConfig::Allow,
                    objects: Some(vec![crate::config::ObjectAclSpec::Bare("a1b2".into())]),
                },
            )]),
        }],
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    // Verify the parsed bytes: uid [0xa1, 0xb2] is in the list → allowed.
    assert!(policy.allows_object_use(&id, "P", "any", &[0xa1u8, 0xb2u8]));
    // Different uid → denied.
    assert!(!policy.allows_object_use(&id, "P", "any", &[0x00u8]));
}

#[test]
fn from_config_objects_bad_hex_rejected() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::Specific(vec![crate::config::GrantSpec::Rich(
                crate::config::RichGrantConfig {
                    token: "label:P".into(),
                    classes: None,
                    mechanisms: None,
                    extract: crate::config::ExtractPolicyConfig::Allow,
                    objects: Some(vec![crate::config::ObjectAclSpec::Bare("xyz".into())]), // not valid hex
                },
            )]),
        }],
    };
    let err = TokenPolicy::from_config(&auth).unwrap_err();
    assert!(err.contains("xyz"), "error must name the bad value: {err}");
}

#[test]
fn from_config_objects_absent_is_none() {
    // A rich grant without `objects` must have objects=None in the grant model.
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::Specific(vec![crate::config::GrantSpec::Rich(
                crate::config::RichGrantConfig {
                    token: "label:P".into(),
                    classes: None,
                    mechanisms: None,
                    extract: crate::config::ExtractPolicyConfig::Allow,
                    objects: None,
                },
            )]),
        }],
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    // objects=None → all objects allowed
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(policy.allows_object_use(&id, "P", "any", &[0xdeu8, 0xadu8]));
    assert!(!policy.per_object_active(), "no objects list → per_object_active must be false");
}

#[test]
fn from_config_objects_bare_string_form_is_none() {
    // Bare string grant form → objects=None.
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::Specific(vec![crate::config::GrantSpec::Bare(
                "label:P".into(),
            )]),
        }],
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(policy.allows_object_use(&id, "P", "any", &[0xffu8]));
    assert!(!policy.per_object_active());
}

// --- per_object_active ---

#[test]
fn per_object_active_false_when_no_objects_field() {
    // No grant in any rule has objects set → false.
    let grant = TokenGrant {
        selector: TokenSelector::Label("Prod".into()),
        classes: None,
        mechanisms: None,
        extract: ExtractPolicy::Allow,
        objects: None,
    };
    let mut rules = HashMap::new();
    rules.insert("uid=1".into(), TokenAccess::Specific(vec![grant]));
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: true,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    assert!(!policy.per_object_active());
}

#[test]
fn per_object_active_false_for_all_access_variant() {
    // TokenAccess::All is never per-object restricted → false.
    let mut rules = HashMap::new();
    rules.insert("uid=0".into(), TokenAccess::All);
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: true,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    assert!(!policy.per_object_active());
}

#[test]
fn per_object_active_true_when_any_grant_has_objects() {
    // Even one grant with objects=Some(…) makes per_object_active() true (M1).
    // Use from_config so the cache is correctly populated.
    use crate::config::{
        AuthConfig, ExtractPolicyConfig, GrantSpec, PolicyEntry, RichGrantConfig, TokenAccessSpec,
    };
    let policy = TokenPolicy::from_config(&AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![PolicyEntry {
            identity: "uid=1".into(),
            tokens: TokenAccessSpec::Specific(vec![GrantSpec::Rich(RichGrantConfig {
                token: "label:Prod".into(),
                classes: None,
                mechanisms: None,
                extract: ExtractPolicyConfig::Allow,
                objects: Some(vec![crate::config::ObjectAclSpec::Bare("a1b2".into())]),
            })]),
        }],
    })
    .expect("policy parses");
    assert!(policy.per_object_active());
}

// --- allows_object_use ---

#[test]
fn allows_object_use_none_objects_allows_any_id() {
    // Grant with objects=None → all objects permitted regardless of unique_id.
    let grant = TokenGrant {
        selector: TokenSelector::Label("Prod".into()),
        classes: None,
        mechanisms: None,
        extract: ExtractPolicy::Allow,
        objects: None,
    };
    let mut rules = HashMap::new();
    rules.insert("uid=1".into(), TokenAccess::Specific(vec![grant]));
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: true,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 1 };
    assert!(policy.allows_object_use(&id, "Prod", "any", &[0x00u8]));
    assert!(policy.allows_object_use(&id, "Prod", "any", &[0xffu8, 0xffu8]));
}

#[test]
fn allows_object_use_some_list_allows_matching_id() {
    let bytes = vec![0xa1u8, 0xb2u8];
    let grant = TokenGrant {
        selector: TokenSelector::Label("Prod".into()),
        classes: None,
        mechanisms: None,
        extract: ExtractPolicy::Allow,
        objects: Some(vec![ObjectAcl { unique_id: bytes.clone(), extract: None }]),
    };
    let mut rules = HashMap::new();
    rules.insert("uid=1".into(), TokenAccess::Specific(vec![grant]));
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: true,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 1 };
    // Exact match → allowed
    assert!(policy.allows_object_use(&id, "Prod", "any", &[0xa1u8, 0xb2u8]));
}

#[test]
fn allows_object_use_some_list_denies_non_matching_id() {
    let grant = TokenGrant {
        selector: TokenSelector::Label("Prod".into()),
        classes: None,
        mechanisms: None,
        extract: ExtractPolicy::Allow,
        objects: Some(vec![ObjectAcl { unique_id: vec![0xa1u8, 0xb2u8], extract: None }]),
    };
    let mut rules = HashMap::new();
    rules.insert("uid=1".into(), TokenAccess::Specific(vec![grant]));
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: true,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 1 };
    // Different unique_id → denied
    assert!(!policy.allows_object_use(&id, "Prod", "any", &[0x00u8]));
    assert!(!policy.allows_object_use(&id, "Prod", "any", &[0xa1u8])); // prefix-only
    assert!(!policy.allows_object_use(&id, "Prod", "any", &[0xa1u8, 0xb2u8, 0x00u8])); // superset
}

#[test]
fn allows_object_use_token_access_all_always_true() {
    // TokenAccess::All → per-object is unrestricted.
    let mut rules = HashMap::new();
    rules.insert("uid=0".into(), TokenAccess::All);
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: true,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 0 };
    assert!(policy.allows_object_use(&id, "any", "any", &[0x00u8]));
}

#[test]
fn allows_object_use_unauthenticated_always_true() {
    // Unauthenticated → per-object is always allowed (opt-in does not create new denials).
    let grant = TokenGrant {
        selector: TokenSelector::Label("Prod".into()),
        classes: None,
        mechanisms: None,
        extract: ExtractPolicy::Allow,
        objects: Some(vec![ObjectAcl { unique_id: vec![0xffu8], extract: None }]),
    };
    let mut rules = HashMap::new();
    rules.insert("uid=1".into(), TokenAccess::Specific(vec![grant]));
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: false, // transport mode
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let unauth = AuthenticatedIdentity::Unauthenticated;
    assert!(policy.allows_object_use(&unauth, "Prod", "any", &[0x00u8]));
}

#[test]
fn allows_object_use_allow_all_authenticated_always_true() {
    // allow_all_authenticated bypasses per-object restriction.
    let grant = TokenGrant {
        selector: TokenSelector::Label("Prod".into()),
        classes: None,
        mechanisms: None,
        extract: ExtractPolicy::Allow,
        objects: Some(vec![ObjectAcl { unique_id: vec![0xffu8], extract: None }]),
    };
    let mut rules = HashMap::new();
    rules.insert("uid=1".into(), TokenAccess::Specific(vec![grant]));
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: true,
        has_policy: false,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 99 };
    assert!(policy.allows_object_use(&id, "Prod", "any", &[0x00u8]));
}

#[test]
fn allows_object_use_no_matching_grant_is_permissive() {
    // If the principal's grants don't match the token at all → true (no restriction).
    let grant = TokenGrant {
        selector: TokenSelector::Label("OtherToken".into()),
        classes: None,
        mechanisms: None,
        extract: ExtractPolicy::Allow,
        objects: Some(vec![ObjectAcl { unique_id: vec![0xffu8], extract: None }]),
    };
    let mut rules = HashMap::new();
    rules.insert("uid=1".into(), TokenAccess::Specific(vec![grant]));
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: true,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 1 };
    // Token "DifferentToken" doesn't match "OtherToken" selector → no restriction → true
    assert!(policy.allows_object_use(&id, "DifferentToken", "any", &[0x00u8]));
}

#[test]
fn allows_object_use_no_rule_for_identity_is_permissive() {
    // Principal not in rules at all → resolve_access returns None → true.
    let policy = TokenPolicy {
        rules: HashMap::new(),
        allow_all_authenticated: false,
        has_policy: true,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 42 };
    assert!(policy.allows_object_use(&id, "any", "any", &[0x00u8]));
}

// --- extract_allowed_for_object ---

/// Build a TokenPolicy with one grant for uid=1 on token "Prod" that has an
/// objects list containing `acls`. The grant-level extract policy is `grant_extract`.
fn policy_with_object_acls(grant_extract: ExtractPolicy, acls: Vec<ObjectAcl>) -> TokenPolicy {
    let grant = TokenGrant {
        selector: TokenSelector::Label("Prod".into()),
        classes: None,
        mechanisms: None,
        extract: grant_extract,
        objects: Some(acls),
    };
    let mut rules = HashMap::new();
    rules.insert("uid=1".into(), TokenAccess::Specific(vec![grant]));
    TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: true,
        anonymous_principal: None,
        per_object_active_cache: true,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    }
}

#[test]
fn extract_allowed_for_object_per_object_deny_overrides_grant_allow() {
    // Grant-level extract=Allow, but this object has extract=Deny override.
    let uid = vec![0xaau8, 0xbbu8];
    let policy = policy_with_object_acls(
        ExtractPolicy::Allow,
        vec![ObjectAcl { unique_id: uid.clone(), extract: Some(ExtractPolicy::Deny) }],
    );
    let id = AuthenticatedIdentity::PeerCred { uid: 1 };
    assert!(
        !policy.extract_allowed_for_object(&id, "Prod", "any", &uid),
        "per-object Deny must override grant-level Allow"
    );
}

#[test]
fn extract_allowed_for_object_per_object_allow_overrides_grant_deny() {
    // Grant-level extract=Deny, but this object has extract=Allow override.
    let uid = vec![0x11u8, 0x22u8];
    let policy = policy_with_object_acls(
        ExtractPolicy::Deny,
        vec![ObjectAcl { unique_id: uid.clone(), extract: Some(ExtractPolicy::Allow) }],
    );
    let id = AuthenticatedIdentity::PeerCred { uid: 1 };
    assert!(
        policy.extract_allowed_for_object(&id, "Prod", "any", &uid),
        "per-object Allow must override grant-level Deny"
    );
}

#[test]
fn extract_allowed_for_object_none_override_inherits_grant_level() {
    // Object in list with extract=None → inherits grant-level policy.
    let uid = vec![0x33u8];
    // Grant-level Allow → should allow.
    let policy_allow = policy_with_object_acls(
        ExtractPolicy::Allow,
        vec![ObjectAcl { unique_id: uid.clone(), extract: None }],
    );
    let id = AuthenticatedIdentity::PeerCred { uid: 1 };
    assert!(
        policy_allow.extract_allowed_for_object(&id, "Prod", "any", &uid),
        "None override with grant Allow must allow"
    );

    // Grant-level Deny → should deny.
    let policy_deny = policy_with_object_acls(
        ExtractPolicy::Deny,
        vec![ObjectAcl { unique_id: uid.clone(), extract: None }],
    );
    assert!(
        !policy_deny.extract_allowed_for_object(&id, "Prod", "any", &uid),
        "None override with grant Deny must deny"
    );
}

#[test]
fn extract_allowed_for_object_deny_beats_allow_across_grants() {
    // Two grants for the same token: one has per-object Allow, the other has
    // per-object Deny for the same uid. Security-conservative: deny beats allow.
    let uid = vec![0x44u8, 0x55u8];
    let grant_allow = TokenGrant {
        selector: TokenSelector::Label("Prod".into()),
        classes: None,
        mechanisms: None,
        extract: ExtractPolicy::Allow,
        objects: Some(vec![ObjectAcl {
            unique_id: uid.clone(),
            extract: Some(ExtractPolicy::Allow),
        }]),
    };
    let grant_deny = TokenGrant {
        selector: TokenSelector::Label("Prod".into()),
        classes: None,
        mechanisms: None,
        extract: ExtractPolicy::Allow,
        objects: Some(vec![ObjectAcl {
            unique_id: uid.clone(),
            extract: Some(ExtractPolicy::Deny),
        }]),
    };
    let mut rules = HashMap::new();
    rules.insert("uid=1".into(), TokenAccess::Specific(vec![grant_allow, grant_deny]));
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: true,
        anonymous_principal: None,
        per_object_active_cache: true,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 1 };
    assert!(
        !policy.extract_allowed_for_object(&id, "Prod", "any", &uid),
        "explicit deny in any grant must beat explicit allow in another grant"
    );
}

#[test]
fn extract_allowed_for_object_unauthenticated_always_true() {
    // Unauthenticated peers bypass per-object extract checks entirely.
    let uid = vec![0xffu8];
    let policy = policy_with_object_acls(
        ExtractPolicy::Deny,
        vec![ObjectAcl { unique_id: uid.clone(), extract: Some(ExtractPolicy::Deny) }],
    );
    let unauth = AuthenticatedIdentity::Unauthenticated;
    assert!(
        policy.extract_allowed_for_object(&unauth, "Prod", "any", &uid),
        "unauthenticated peer must always be permitted (per-object extract is opt-in)"
    );
}

// ---------------------------------------------------------------------------
// W1-C3-05: duplicate [[auth.policy]] identities must be rejected loudly
// instead of silently overwriting the first entry's grants.
// ---------------------------------------------------------------------------

#[test]
fn from_config_rejects_duplicate_identity() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![
            crate::config::PolicyEntry {
                identity: "uid=1000".into(),
                tokens: crate::config::TokenAccessSpec::Specific(vec![
                    crate::config::GrantSpec::Bare("label:token-a".into()),
                ]),
            },
            crate::config::PolicyEntry {
                identity: "uid=1000".into(),
                tokens: crate::config::TokenAccessSpec::Specific(vec![
                    crate::config::GrantSpec::Bare("label:token-b".into()),
                ]),
            },
        ],
    };
    let err = TokenPolicy::from_config(&auth).unwrap_err();
    assert!(
        err.contains("uid=1000"),
        "duplicate-identity error must name the identity, got: {err}"
    );
}

#[test]
fn from_config_rejects_identities_duplicate_after_normalization() {
    // W1-C3-05 + W1-C3-06: uid=01000 and uid=1000 normalize to the same
    // runtime key, so configuring both is a duplicate, not two grants.
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![
            crate::config::PolicyEntry {
                identity: "uid=01000".into(),
                tokens: crate::config::TokenAccessSpec::Specific(vec![
                    crate::config::GrantSpec::Bare("label:token-a".into()),
                ]),
            },
            crate::config::PolicyEntry {
                identity: "uid=1000".into(),
                tokens: crate::config::TokenAccessSpec::Specific(vec![
                    crate::config::GrantSpec::Bare("label:token-b".into()),
                ]),
            },
        ],
    };
    let err = TokenPolicy::from_config(&auth).unwrap_err();
    assert!(
        err.contains("duplicate"),
        "normalization-colliding identities must be rejected, got: {err}"
    );
}

#[test]
fn from_config_accepts_unique_identities() {
    // Preservation control: distinct identities load exactly as before.
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        anonymous_principal: None,
        policy: vec![
            crate::config::PolicyEntry {
                identity: "uid=1000".into(),
                tokens: crate::config::TokenAccessSpec::Specific(vec![
                    crate::config::GrantSpec::Bare("label:token-a".into()),
                ]),
            },
            crate::config::PolicyEntry {
                identity: "uid=2000".into(),
                tokens: crate::config::TokenAccessSpec::Specific(vec![
                    crate::config::GrantSpec::Bare("label:token-b".into()),
                ]),
            },
        ],
    };
    let policy = TokenPolicy::from_config(&auth).expect("unique identities must load");
    assert!(policy.allows(&AuthenticatedIdentity::PeerCred { uid: 1000 }, "token-a", "any"));
    assert!(policy.allows(&AuthenticatedIdentity::PeerCred { uid: 2000 }, "token-b", "any"));
}

// ---------------------------------------------------------------------------
// W1-C3-10: LOGGED_SPKI / WARNED_LEGACY must be bounded (cap + eviction) so
// sustained unique peers cannot grow them without limit. Dedup behavior is
// preserved: repeats stay silent, evicted keys may log once more.
// ---------------------------------------------------------------------------

#[test]
fn log_dedup_set_dedups_repeats() {
    let mut set = super::LogDedupSet::new();
    assert!(set.insert("peer-a".to_string()), "first sighting logs");
    assert!(!set.insert("peer-a".to_string()), "repeat must stay silent");
    assert_eq!(set.len(), 1);
}

#[test]
fn log_dedup_set_evicts_oldest_past_cap() {
    let mut set = super::LogDedupSet::new();
    for i in 0..super::LOG_DEDUP_CAP {
        assert!(set.insert(format!("peer-{i:06}")));
    }
    assert_eq!(set.len(), super::LOG_DEDUP_CAP);
    // One past the cap: oldest entry evicted, size stays bounded.
    assert!(set.insert("peer-new".to_string()));
    assert_eq!(set.len(), super::LOG_DEDUP_CAP);
    // The evicted oldest key may log once more (bounded-memory tradeoff).
    assert!(set.insert("peer-000000".to_string()), "evicted key re-admitted");
    assert_eq!(set.len(), super::LOG_DEDUP_CAP);
    // A retained key still dedups.
    assert!(!set.insert("peer-new".to_string()), "retained key must stay silent");
}

#[test]
fn sustained_unique_spki_peers_keep_logged_set_bounded() {
    use std::collections::HashMap;
    // Policy with no SPKI rules: every peer still records its SPKI in the
    // dedup set via the log-once path in `allows`, then is denied.
    let policy = TokenPolicy {
        rules: HashMap::new(),
        allow_all_authenticated: false,
        has_policy: true,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    for i in 0..(super::LOG_DEDUP_CAP + 256) {
        let id = AuthenticatedIdentity::Mtls {
            issuer: format!("CN=ca-{i}"),
            subject: format!("CN=peer-{i}"),
            spki_sha256: format!("c310-spki-{i:08}"),
        };
        assert!(!policy.allows(&id, "any", "any"));
    }
    assert!(
        super::logged_spki_len() <= super::LOG_DEDUP_CAP,
        "LOGGED_SPKI must stay bounded under sustained unique peers"
    );
}

#[test]
fn sustained_unique_legacy_peers_keep_warned_set_bounded() {
    use std::collections::HashMap;
    // One legacy DN rule per peer so each `allows` traverses the
    // warn-once path for a distinct legacy key.
    let mut rules = HashMap::new();
    for i in 0..(super::LOG_DEDUP_CAP + 256) {
        rules.insert(
            format!("x509:issuer=CN=c310-ca;subject=CN=c310-legacy-{i:08}"),
            TokenAccess::All,
        );
    }
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: true,
        anonymous_principal: None,
        per_object_active_cache: false,
        per_class_active_cache: false,
        per_mechanism_active_cache: false,
    };
    for i in 0..(super::LOG_DEDUP_CAP + 256) {
        let id = AuthenticatedIdentity::Mtls {
            issuer: "CN=c310-ca".to_string(),
            subject: format!("CN=c310-legacy-{i:08}"),
            spki_sha256: String::new(),
        };
        assert!(policy.allows(&id, "any", "any"));
    }
    assert!(
        super::warned_legacy_len() <= super::LOG_DEDUP_CAP,
        "WARNED_LEGACY must stay bounded under sustained unique peers"
    );
}
