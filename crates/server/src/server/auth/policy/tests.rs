use super::super::grant::{ExtractPolicy, TokenGrant, parse_class, parse_mechanism};
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
fn uri_selector_deferred() {
    let selector = TokenSelector::Uri("pkcs11:token=foo".into());
    assert!(!selector.matches("foo", "bar"));
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
fn parse_trims_whitespace() {
    let s = TokenSelector::parse("  label:  Token  ").unwrap();
    assert_eq!(s, TokenSelector::Label("Token".into()));
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
fn duplicate_identity_in_config_last_wins() {
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
    let policy = TokenPolicy::from_config(&auth).unwrap();
    let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
    assert!(!policy.allows(&id, "token-a", "any"), "first entry should be overwritten");
    assert!(policy.allows(&id, "token-b", "any"), "last entry should apply");
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
    };
    let mut rules = HashMap::new();
    rules.insert("uid=1000".into(), TokenAccess::Specific(vec![grant]));
    rules.insert("uid=9000".into(), TokenAccess::All);
    TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: true,
        anonymous_principal: None,
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
    };
    let mut rules = HashMap::new();
    rules.insert("uid=42".into(), TokenAccess::Specific(vec![grant]));
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: false,
        has_policy: true,
        anonymous_principal: None,
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
    };
    let mut rules = HashMap::new();
    rules.insert("uid=1".into(), TokenAccess::Specific(vec![grant]));
    let policy = TokenPolicy {
        rules,
        allow_all_authenticated: true, // blanket
        has_policy: false,
        anonymous_principal: None,
    };
    let id = AuthenticatedIdentity::PeerCred { uid: 1 };
    assert!(policy.extract_allowed(&id, "Prod", "any"));
}
