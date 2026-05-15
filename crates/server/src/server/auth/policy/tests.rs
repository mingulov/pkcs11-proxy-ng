use super::*;

#[test]
fn unauthenticated_always_allowed() {
    let policy = TokenPolicy { rules: HashMap::new(), allow_all_authenticated: false };
    assert!(policy.allows(&AuthenticatedIdentity::Unauthenticated, "any", "any"));
}

#[test]
fn allow_all_authenticated_bypasses_rules() {
    let policy = TokenPolicy { rules: HashMap::new(), allow_all_authenticated: true };
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(policy.allows(&id, "token1", "serial1"));
}

#[test]
fn default_deny_for_unknown_identity() {
    let policy = TokenPolicy { rules: HashMap::new(), allow_all_authenticated: false };
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(!policy.allows(&id, "token1", "serial1"));
}

#[test]
fn label_selector_matches() {
    let mut rules = HashMap::new();
    rules.insert(
        "uid=1000".into(),
        TokenAccess::Specific(vec![TokenSelector::Label("my-token".into())]),
    );
    let policy = TokenPolicy { rules, allow_all_authenticated: false };
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(policy.allows(&id, "my-token", "any-serial"));
    assert!(!policy.allows(&id, "other-token", "any-serial"));
}

#[test]
fn serial_selector_matches() {
    let mut rules = HashMap::new();
    rules.insert(
        "uid=1000".into(),
        TokenAccess::Specific(vec![TokenSelector::Serial("SN123".into())]),
    );
    let policy = TokenPolicy { rules, allow_all_authenticated: false };
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(policy.allows(&id, "any-label", "SN123"));
    assert!(!policy.allows(&id, "any-label", "SN999"));
}

#[test]
fn all_access_matches_everything() {
    let mut rules = HashMap::new();
    rules.insert("uid=0".into(), TokenAccess::All);
    let policy = TokenPolicy { rules, allow_all_authenticated: false };
    let id = AuthenticatedIdentity::PeerCred { uid: 0 };
    assert!(policy.allows(&id, "any", "any"));
}

#[test]
fn mtls_identity_display_format() {
    let id =
        AuthenticatedIdentity::Mtls { issuer: "CN=TestCA".into(), subject: "CN=client1".into() };
    assert_eq!(id.to_string(), "x509:issuer=CN=TestCA;subject=CN=client1");
}

#[test]
fn uri_selector_deferred() {
    let selector = TokenSelector::Uri("pkcs11:token=foo".into());
    assert!(!selector.matches("foo", "bar"));
}

#[test]
fn from_config_builds_policy() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::Specific(vec![
                "label:my-token".into(),
                "serial:SN456".into(),
                "bare-label".into(),
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
    let policy = TokenPolicy { rules, allow_all_authenticated: false };

    let allowed =
        AuthenticatedIdentity::Mtls { issuer: "CN=Root CA".into(), subject: "CN=client1".into() };
    let wrong_subject =
        AuthenticatedIdentity::Mtls { issuer: "CN=Root CA".into(), subject: "CN=other".into() };
    assert!(policy.allows(&allowed, "any", "any"));
    assert!(!policy.allows(&wrong_subject, "any", "any"));
}

#[test]
fn multiple_identities_independent_access() {
    let mut rules = HashMap::new();
    rules.insert("uid=1000".into(), TokenAccess::All);
    let policy = TokenPolicy { rules, allow_all_authenticated: false };

    let allowed = AuthenticatedIdentity::PeerCred { uid: 1000 };
    let denied = AuthenticatedIdentity::PeerCred { uid: 2000 };
    assert!(policy.allows(&allowed, "any", "any"));
    assert!(!policy.allows(&denied, "any", "any"));
}

#[test]
fn specific_access_empty_selectors_denies_everything() {
    let mut rules = HashMap::new();
    rules.insert("uid=1000".into(), TokenAccess::Specific(vec![]));
    let policy = TokenPolicy { rules, allow_all_authenticated: false };
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(!policy.allows(&id, "any-label", "any-serial"));
}

#[test]
fn multiple_selectors_any_match_wins() {
    let mut rules = HashMap::new();
    rules.insert(
        "uid=1000".into(),
        TokenAccess::Specific(vec![
            TokenSelector::Label("token-a".into()),
            TokenSelector::Serial("SN-A".into()),
        ]),
    );
    let policy = TokenPolicy { rules, allow_all_authenticated: false };
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };

    assert!(policy.allows(&id, "token-a", "unrelated-serial"));
    assert!(policy.allows(&id, "unrelated-label", "SN-A"));
    assert!(!policy.allows(&id, "other-label", "other-serial"));
}

#[test]
fn from_config_with_all_access() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
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
    let policy = TokenPolicy { rules: HashMap::new(), allow_all_authenticated: false };
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
fn parse_pkcs11_uri_selector() {
    let s = TokenSelector::parse("pkcs11:token=foo;serial=bar").unwrap();
    assert_eq!(s, TokenSelector::Uri("pkcs11:token=foo;serial=bar".into()));
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
fn parse_trims_whitespace() {
    let s = TokenSelector::parse("  label:  Token  ").unwrap();
    assert_eq!(s, TokenSelector::Label("Token".into()));
}

#[test]
fn from_config_rejects_empty_selector() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::Specific(vec!["".into()]),
        }],
    };
    let err = TokenPolicy::from_config(&auth).unwrap_err();
    assert!(err.contains("empty"), "error should mention empty: {err}");
}

#[test]
fn from_config_rejects_typo_prefix() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        policy: vec![crate::config::PolicyEntry {
            identity: "uid=1000".into(),
            tokens: crate::config::TokenAccessSpec::Specific(vec!["lable:foo".into()]),
        }],
    };
    let err = TokenPolicy::from_config(&auth).unwrap_err();
    assert!(err.contains("unrecognized"), "error should mention unrecognized: {err}");
}

fn matrix_policy() -> TokenPolicy {
    let mut rules = HashMap::new();
    rules.insert(
        "uid=1000".into(),
        TokenAccess::Specific(vec![
            TokenSelector::Label("token-a".into()),
            TokenSelector::Serial("SN-B".into()),
        ]),
    );
    rules.insert(
        "uid=2000".into(),
        TokenAccess::Specific(vec![TokenSelector::Label("token-c".into())]),
    );
    rules.insert("x509:issuer=CN=Root;subject=CN=admin".into(), TokenAccess::All);
    rules.insert(
        "x509:issuer=CN=Root;subject=CN=reader".into(),
        TokenAccess::Specific(vec![TokenSelector::Label("token-a".into())]),
    );
    rules.insert("uid=9999".into(), TokenAccess::Specific(vec![]));
    TokenPolicy { rules, allow_all_authenticated: false }
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
    let visible = policy.visible_tokens(&id, &tokens);
    let labels: Vec<&str> = visible.iter().map(|(l, _)| l.as_str()).collect();
    assert_eq!(labels, vec!["token-a", "token-b"]);
}

#[test]
fn discovery_uid2000_sees_only_token_c() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 2000 };
    let tokens = token_list();
    let visible = policy.visible_tokens(&id, &tokens);
    let labels: Vec<&str> = visible.iter().map(|(l, _)| l.as_str()).collect();
    assert_eq!(labels, vec!["token-c"]);
}

#[test]
fn discovery_admin_mtls_sees_all() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::Mtls { issuer: "CN=Root".into(), subject: "CN=admin".into() };
    let tokens = token_list();
    let visible = policy.visible_tokens(&id, &tokens);
    assert_eq!(visible.len(), 4, "admin should see all 4 tokens");
}

#[test]
fn discovery_reader_mtls_sees_one() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::Mtls { issuer: "CN=Root".into(), subject: "CN=reader".into() };
    let tokens = token_list();
    let visible = policy.visible_tokens(&id, &tokens);
    let labels: Vec<&str> = visible.iter().map(|(l, _)| l.as_str()).collect();
    assert_eq!(labels, vec!["token-a"]);
}

#[test]
fn discovery_unknown_uid_sees_nothing() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 5000 };
    let tokens = token_list();
    let visible = policy.visible_tokens(&id, &tokens);
    assert!(visible.is_empty(), "unknown identity should see no tokens");
}

#[test]
fn discovery_explicit_deny_sees_nothing() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 9999 };
    let tokens = token_list();
    let visible = policy.visible_tokens(&id, &tokens);
    assert!(visible.is_empty(), "identity with empty selectors should see no tokens");
}

#[test]
fn discovery_unauthenticated_sees_all() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::Unauthenticated;
    let tokens = token_list();
    let visible = policy.visible_tokens(&id, &tokens);
    assert_eq!(visible.len(), 4, "unauthenticated mode bypasses policy, sees all tokens");
}

#[test]
fn discovery_empty_token_list() {
    let policy = matrix_policy();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    let visible = policy.visible_tokens(&id, &[]);
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
    let id = AuthenticatedIdentity::Mtls { issuer: "CN=Root".into(), subject: "CN=reader".into() };
    assert!(!policy.allows(&id, "token-b", "SN-B"), "reader should not access token-b");
}

#[test]
fn mtls_issuer_mismatch_denied() {
    let policy = matrix_policy();
    let id =
        AuthenticatedIdentity::Mtls { issuer: "CN=Other CA".into(), subject: "CN=admin".into() };
    assert!(!policy.allows(&id, "token-a", "SN-A"), "wrong issuer must be denied");
}

#[test]
fn mtls_subject_mismatch_denied() {
    let policy = matrix_policy();
    let id =
        AuthenticatedIdentity::Mtls { issuer: "CN=Root".into(), subject: "CN=attacker".into() };
    assert!(!policy.allows(&id, "token-a", "SN-A"), "wrong subject must be denied");
}

#[test]
fn peer_cred_vs_mtls_identity_collision_impossible() {
    let peer = AuthenticatedIdentity::PeerCred { uid: 1000 };
    let mtls = AuthenticatedIdentity::Mtls { issuer: "uid=1000".into(), subject: "".into() };
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
            },
            expected_labels: vec!["token-a", "token-b", "token-c", "token-d"],
        },
        Case {
            id: AuthenticatedIdentity::Mtls {
                issuer: "CN=Root".into(),
                subject: "CN=reader".into(),
            },
            expected_labels: vec!["token-a"],
        },
        Case { id: AuthenticatedIdentity::PeerCred { uid: 5000 }, expected_labels: vec![] },
        Case { id: AuthenticatedIdentity::PeerCred { uid: 9999 }, expected_labels: vec![] },
    ];

    for (i, case) in cases.iter().enumerate() {
        let visible = policy.visible_tokens(&case.id, &tokens);
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
    rules.insert(
        "uid=1000".into(),
        TokenAccess::Specific(vec![TokenSelector::Label("token-a".into())]),
    );
    let policy = TokenPolicy { rules, allow_all_authenticated: true };
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(policy.allows(&id, "token-b", "SN-B"));
}

#[test]
fn allow_all_authenticated_allows_unknown_identity() {
    let policy = TokenPolicy { rules: HashMap::new(), allow_all_authenticated: true };
    let id = AuthenticatedIdentity::PeerCred { uid: 99999 };
    assert!(
        policy.allows(&id, "any", "any"),
        "allow_all_authenticated should permit even unlisted identities"
    );
}

#[test]
fn allow_all_authenticated_does_not_affect_unauthenticated() {
    for flag in [true, false] {
        let policy = TokenPolicy { rules: HashMap::new(), allow_all_authenticated: flag };
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
fn duplicate_identity_in_config_last_wins() {
    let auth = crate::config::AuthConfig {
        allow_all_authenticated: false,
        policy: vec![
            crate::config::PolicyEntry {
                identity: "uid=1000".into(),
                tokens: crate::config::TokenAccessSpec::Specific(vec!["label:token-a".into()]),
            },
            crate::config::PolicyEntry {
                identity: "uid=1000".into(),
                tokens: crate::config::TokenAccessSpec::Specific(vec!["label:token-b".into()]),
            },
        ],
    };
    let policy = TokenPolicy::from_config(&auth).unwrap();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(!policy.allows(&id, "token-a", "any"), "first entry should be overwritten");
    assert!(policy.allows(&id, "token-b", "any"), "last entry should apply");
}
