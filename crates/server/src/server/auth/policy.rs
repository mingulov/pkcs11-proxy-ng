use super::grant::{
    ExtractPolicy, TokenGrant, parse_class, parse_mechanism, parse_object_unique_id,
};
use super::identity::AuthenticatedIdentity;
pub use super::token_selector::TokenSelector;
use pkcs11_proxy_ng_types::{CkMechanismType, CkObjectClass};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

#[derive(Debug)]
pub struct TokenPolicy {
    pub(crate) rules: HashMap<String, TokenAccess>,
    pub(crate) allow_all_authenticated: bool,
    /// True when at least one `[[auth.policy]]` entry is configured.
    /// Drives the deny-default flip: when a policy is present and no
    /// `anonymous_principal` is named, unauthenticated peers are denied.
    pub(crate) has_policy: bool,
    /// Audit-identity label for unauthenticated peers. When set,
    /// `audit_identity()` substitutes this string in the audit record
    /// instead of the raw `"unauthenticated"` marker. This is NEVER a
    /// grant: authz still routes through `allows_unauthenticated()`.
    pub(crate) anonymous_principal: Option<String>,
}

/// Per-identity token-access rule.
///
/// `All` is a blanket grant (all tokens, all classes, all mechanisms, extract=Allow).
/// `Specific` holds a list of `TokenGrant`s; any matching grant authorizes the token.
#[derive(Debug)]
pub enum TokenAccess {
    All,
    Specific(Vec<TokenGrant>),
}

/// Tracks SPKI hashes for which we've already emitted the "mTLS auth" info log.
/// Prevents flooding the log when the same certificate connects repeatedly.
static LOGGED_SPKI: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

/// Tracks legacy DN keys for which we've already emitted the deprecation warning.
static WARNED_LEGACY: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

impl TokenPolicy {
    /// Build from parsed config, validating all selectors.
    pub fn from_config(auth: &crate::config::AuthConfig) -> Result<Self, String> {
        let mut rules = HashMap::new();
        for entry in &auth.policy {
            let access = Self::parse_access(&entry.identity, &entry.tokens)?;
            rules.insert(entry.identity.clone(), access);
        }
        let has_policy = !rules.is_empty();
        Ok(Self {
            rules,
            allow_all_authenticated: auth.allow_all_authenticated,
            has_policy,
            anonymous_principal: auth.anonymous_principal.clone(),
        })
    }

    /// Whether an **unauthenticated** peer is allowed.
    ///
    /// This is the SINGLE deny-default flip-point (G2-PR2, ADR-0012). Both
    /// `allows()` and `grpc_service::authorization::slot_is_authorized` route
    /// the unauthenticated case through THIS method — never add an independent
    /// inline `Unauthenticated ⇒ true` elsewhere.
    ///
    /// Decision table:
    ///  - No policy (`has_policy = false`): transport/dev mode — allow (legacy behaviour).
    ///  - Policy set, no `anonymous_principal`: deny-default (G2-PR2 enforcement).
    ///  - Policy set + `anonymous_principal` named: allow (operator has explicitly
    ///    identified unauthenticated peers for audit; the anon name is audit-only,
    ///    never a grant).
    ///  - No policy + `anonymous_principal`: allow (meaningless but not an error;
    ///    the anon name is still used for audit labelling).
    pub fn allows_unauthenticated(&self) -> bool {
        !self.has_policy || self.anonymous_principal.is_some()
    }

    /// Returns the audit-identity string for a context.
    ///
    /// When the stored identity is `None` (no identity recorded) or
    /// `"unauthenticated"`, and an `anonymous_principal` is configured, this
    /// substitutes the anonymous name in the audit record instead of the raw
    /// `"unauthenticated"` marker. This is **audit-identity only** — the authz
    /// path always calls `allows_unauthenticated()` and never calls this method.
    pub fn audit_identity(&self, stored: Option<&str>) -> Option<String> {
        match stored {
            Some("unauthenticated") | None => {
                self.anonymous_principal.clone().or_else(|| stored.map(|s| s.to_string()))
            }
            _ => stored.map(|s| s.to_string()),
        }
    }

    /// Whether the identity is authorized to access a token.
    ///
    /// This is the token-level gate: it does **not** enforce class, mechanism,
    /// or extract policy — those are checked by the dedicated query methods.
    pub fn allows(
        &self,
        identity: &AuthenticatedIdentity,
        token_label: &str,
        token_serial: &str,
    ) -> bool {
        if matches!(identity, AuthenticatedIdentity::Unauthenticated) {
            return self.allows_unauthenticated();
        }
        if self.allow_all_authenticated {
            return true;
        }

        match identity {
            AuthenticatedIdentity::Mtls { spki_sha256, .. } => {
                // Primary lookup: by SPKI fingerprint (the cryptographic identity).
                if !spki_sha256.is_empty() {
                    let spki_key = format!("x509:spki={spki_sha256}");
                    // Log once per unique SPKI so operators can populate SPKI-form policy entries.
                    let logged = LOGGED_SPKI.get_or_init(|| Mutex::new(HashSet::new()));
                    if let Ok(mut set) = logged.lock()
                        && set.insert(spki_sha256.clone())
                    {
                        tracing::info!(
                            spki_key = %spki_key,
                            "mTLS peer identified; use this key in [auth.policy] to migrate to SPKI-pinned identity (x509:spki=<fingerprint>)"
                        );
                    }
                    if let Some(access) = self.rules.get(&spki_key) {
                        return Self::check_access(access, token_label, token_serial);
                    }
                }
                // Dual-accept fallback: legacy DN-keyed policy entry.
                // Only triggered when the identity carries the DN (i.e., freshly constructed
                // from a cert or parsed from an enriched stored-context string). When
                // legacy_dn_key() returns None (empty DN), skip silently.
                if let Some(legacy_key) = identity.legacy_dn_key()
                    && let Some(access) = self.rules.get(&legacy_key)
                {
                    // Warn once per legacy key so operators know to migrate.
                    let warned = WARNED_LEGACY.get_or_init(|| Mutex::new(HashSet::new()));
                    if let Ok(mut set) = warned.lock()
                        && set.insert(legacy_key.clone())
                    {
                        let spki_display = if !spki_sha256.is_empty() {
                            format!("x509:spki={spki_sha256}")
                        } else {
                            "(SPKI unavailable — identity parsed from legacy stored string)"
                                .to_string()
                        };
                        tracing::warn!(
                            legacy_key = %legacy_key,
                            spki_key = %spki_display,
                            "deprecated DN-based mTLS policy identity '{}'; migrate the [auth.policy] entry to '{}' (see the daemon logs for the peer's SPKI hash)",
                            legacy_key, spki_display
                        );
                    }
                    return Self::check_access(access, token_label, token_serial);
                }
                false // default deny
            }
            _ => {
                // PeerCred (and Unauthenticated already handled above)
                let key = identity.to_string();
                match self.rules.get(&key) {
                    Some(TokenAccess::All) => true,
                    Some(TokenAccess::Specific(grants)) => {
                        grants.iter().any(|g| g.matches_token(token_label, token_serial))
                    }
                    None => false,
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Grant-level query methods (Task 6 enforcement + G3 future use)
    // -----------------------------------------------------------------------
    //
    // These methods are called AFTER `allows()` returns true (token-level
    // gate already passed). They inspect the matching `TokenGrant`(s) for
    // sub-token restrictions.
    //
    // Semantics for `Specific` grants when multiple grants match the token:
    //   extract_allowed   — false if ANY matching grant has `extract = Deny`
    //   allows_mechanism  — true if ANY matching grant has `mechanisms = None`
    //                        OR contains the given mechanism
    //   allows_class      — true if ANY matching grant has `classes = None`
    //                        OR contains the given class
    //
    // For `TokenAccess::All`, unauthenticated peers, and `allow_all_authenticated`
    // all three methods return `true` (no sub-token restrictions).

    /// Whether the identity is allowed to extract sensitive key material from the
    /// matched token.
    ///
    /// Returns `true` by default; `false` only when a matching grant explicitly
    /// sets `extract = "deny"`. `TokenAccess::All` / no matching grant / unauthenticated
    /// → always `true` (extract-deny is opt-in).
    pub fn extract_allowed(
        &self,
        identity: &AuthenticatedIdentity,
        token_label: &str,
        token_serial: &str,
    ) -> bool {
        if matches!(identity, AuthenticatedIdentity::Unauthenticated) {
            return true;
        }
        if self.allow_all_authenticated {
            return true;
        }
        match self.resolve_access(identity) {
            None | Some(TokenAccess::All) => true,
            Some(TokenAccess::Specific(grants)) => !grants
                .iter()
                .filter(|g| g.matches_token(token_label, token_serial))
                .any(|g| g.extract == ExtractPolicy::Deny),
        }
    }

    /// Whether the identity is allowed to use the given mechanism on the matched token.
    ///
    /// Returns `true` when `mechanisms = None` in all matching grants (no restriction)
    /// or at least one matching grant explicitly lists this mechanism.
    /// `TokenAccess::All` / no matching grant → `true`.
    pub fn allows_mechanism(
        &self,
        identity: &AuthenticatedIdentity,
        token_label: &str,
        token_serial: &str,
        mech: CkMechanismType,
    ) -> bool {
        if matches!(identity, AuthenticatedIdentity::Unauthenticated) {
            return true;
        }
        if self.allow_all_authenticated {
            return true;
        }
        match self.resolve_access(identity) {
            None | Some(TokenAccess::All) => true,
            Some(TokenAccess::Specific(grants)) => {
                let matching: Vec<&TokenGrant> =
                    grants.iter().filter(|g| g.matches_token(token_label, token_serial)).collect();
                if matching.is_empty() {
                    return true; // no grants matched → no restriction
                }
                matching.iter().any(|g| match &g.mechanisms {
                    None => true,
                    Some(list) => list.contains(&mech),
                })
            }
        }
    }

    /// Whether the identity is allowed to access objects of the given class on the
    /// matched token.
    ///
    /// Returns `true` when `classes = None` in all matching grants (no restriction)
    /// or at least one matching grant explicitly lists this class.
    /// `TokenAccess::All` / no matching grant → `true`.
    pub fn allows_class(
        &self,
        identity: &AuthenticatedIdentity,
        token_label: &str,
        token_serial: &str,
        class: CkObjectClass,
    ) -> bool {
        if matches!(identity, AuthenticatedIdentity::Unauthenticated) {
            return true;
        }
        if self.allow_all_authenticated {
            return true;
        }
        match self.resolve_access(identity) {
            None | Some(TokenAccess::All) => true,
            Some(TokenAccess::Specific(grants)) => {
                let matching: Vec<&TokenGrant> =
                    grants.iter().filter(|g| g.matches_token(token_label, token_serial)).collect();
                if matching.is_empty() {
                    return true; // no grants matched → no restriction
                }
                matching.iter().any(|g| match &g.classes {
                    None => true,
                    Some(list) => list.contains(&class),
                })
            }
        }
    }

    /// Whether any grant in any policy rule has a non-`None` `objects` list.
    ///
    /// When `false`, the per-object authorization layer is entirely dormant and
    /// the `allows_object_use` check can be skipped. When `true`, at least one
    /// grant restricts access to specific objects by `CKA_UNIQUE_ID`, so the
    /// enforcement path must be consulted.
    ///
    /// This is an opt-in feature: the value is `false` when no `objects` field
    /// appears anywhere in the loaded config (i.e., all existing deployments
    /// until they explicitly add an `objects` list to a grant).
    pub fn per_object_active(&self) -> bool {
        self.rules.values().any(|access| {
            if let TokenAccess::Specific(grants) = access {
                grants.iter().any(|g| g.objects.is_some())
            } else {
                false
            }
        })
    }

    /// Whether the identity is allowed to use an object with the given
    /// `CKA_UNIQUE_ID` value on the matched token.
    ///
    /// Per-object authorization is **opt-in** (an additive refinement of the
    /// token-level grant): a grant without an `objects` list permits all objects,
    /// preserving backward compatibility. Principals without a matching grant,
    /// `TokenAccess::All`, `allow_all_authenticated`, and unauthenticated peers
    /// all receive `true` — per-object is never a new denial for principals
    /// who have no `objects` restriction configured.
    ///
    /// When a grant DOES have `Some(list)`, only objects whose `unique_id`
    /// byte slice appears in `list` are permitted by that grant.
    pub fn allows_object_use(
        &self,
        identity: &AuthenticatedIdentity,
        token_label: &str,
        token_serial: &str,
        unique_id: &[u8],
    ) -> bool {
        if matches!(identity, AuthenticatedIdentity::Unauthenticated) {
            return true;
        }
        if self.allow_all_authenticated {
            return true;
        }
        match self.resolve_access(identity) {
            None | Some(TokenAccess::All) => true,
            Some(TokenAccess::Specific(grants)) => {
                let matching: Vec<&TokenGrant> =
                    grants.iter().filter(|g| g.matches_token(token_label, token_serial)).collect();
                if matching.is_empty() {
                    return true; // no grants matched → no restriction
                }
                matching.iter().any(|g| match &g.objects {
                    None => true, // unrestricted grant permits all objects
                    Some(list) => list.iter().any(|u| u.as_slice() == unique_id),
                })
            }
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Resolve the `TokenAccess` for an authenticated identity without side
    /// effects (no logging, no deprecation warnings). Used by the query methods
    /// (`extract_allowed`, `allows_mechanism`, `allows_class`).
    fn resolve_access(&self, identity: &AuthenticatedIdentity) -> Option<&TokenAccess> {
        match identity {
            AuthenticatedIdentity::Unauthenticated => None,
            AuthenticatedIdentity::Mtls { spki_sha256, .. } => {
                if !spki_sha256.is_empty() {
                    let spki_key = format!("x509:spki={spki_sha256}");
                    if let Some(access) = self.rules.get(&spki_key) {
                        return Some(access);
                    }
                }
                if let Some(legacy_key) = identity.legacy_dn_key()
                    && let Some(access) = self.rules.get(&legacy_key)
                {
                    return Some(access);
                }
                None
            }
            _ => {
                let key = identity.to_string();
                self.rules.get(&key)
            }
        }
    }

    fn check_access(access: &TokenAccess, token_label: &str, token_serial: &str) -> bool {
        match access {
            TokenAccess::All => true,
            TokenAccess::Specific(grants) => {
                grants.iter().any(|g| g.matches_token(token_label, token_serial))
            }
        }
    }

    fn parse_access(
        identity: &str,
        access: &crate::config::TokenAccessSpec,
    ) -> Result<TokenAccess, String> {
        match access {
            crate::config::TokenAccessSpec::All(keyword) => {
                let keyword = keyword.trim();
                if keyword == "all" || keyword == "*" {
                    Ok(TokenAccess::All)
                } else {
                    Err(format!(
                        "policy for '{identity}': invalid scalar tokens value '{keyword}'; \
                         use tokens = \"all\" for broad access or tokens = [\"label:...\"] \
                         for token selectors"
                    ))
                }
            }
            crate::config::TokenAccessSpec::Specific(grant_specs) => {
                let grants = grant_specs
                    .iter()
                    .map(|spec| Self::parse_grant(identity, spec))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(TokenAccess::Specific(grants))
            }
        }
    }

    /// Parse a single `GrantSpec` (bare string or rich table) into a `TokenGrant`.
    fn parse_grant(identity: &str, spec: &crate::config::GrantSpec) -> Result<TokenGrant, String> {
        match spec {
            crate::config::GrantSpec::Bare(selector_str) => {
                let selector = TokenSelector::parse(selector_str).map_err(|error| {
                    format!("policy for '{identity}': invalid selector '{selector_str}': {error}")
                })?;
                Ok(TokenGrant::simple(selector))
            }
            crate::config::GrantSpec::Rich(rich) => {
                let selector = TokenSelector::parse(&rich.token).map_err(|error| {
                    format!(
                        "policy for '{identity}': invalid token selector '{}': {error}",
                        rich.token
                    )
                })?;

                let classes = match &rich.classes {
                    None => None,
                    Some(strs) => Some(
                        strs.iter()
                            .map(|s| {
                                parse_class(s).map_err(|e| format!("policy for '{identity}': {e}"))
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                    ),
                };

                let mechanisms = match &rich.mechanisms {
                    None => None,
                    Some(strs) => Some(
                        strs.iter()
                            .map(|s| {
                                parse_mechanism(s)
                                    .map_err(|e| format!("policy for '{identity}': {e}"))
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                    ),
                };

                let extract = match rich.extract {
                    crate::config::ExtractPolicyConfig::Allow => ExtractPolicy::Allow,
                    crate::config::ExtractPolicyConfig::Deny => ExtractPolicy::Deny,
                };

                let objects = match &rich.objects {
                    None => None,
                    Some(strs) => Some(
                        strs.iter()
                            .map(|s| {
                                parse_object_unique_id(s)
                                    .map_err(|e| format!("policy for '{identity}': {e}"))
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                    ),
                };

                Ok(TokenGrant { selector, classes, mechanisms, extract, objects })
            }
        }
    }
}

#[cfg(test)]
mod tests;
