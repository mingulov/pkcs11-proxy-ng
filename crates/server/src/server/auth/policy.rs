use super::grant::{
    ExtractPolicy, ObjectAcl, TokenGrant, parse_class, parse_mechanism, parse_object_unique_id,
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
    /// Pre-computed at `from_config`: true when at least one grant has a
    /// non-`None` `objects` list. Cached so the per-object gate check on
    /// every object-resolving RPC is a single `bool` load rather than a
    /// full scan of all grants (M1 perf fix).
    pub(crate) per_object_active_cache: bool,
    /// Pre-computed at `from_config`: true when at least one grant has a
    /// non-`None` `classes` list. Cached so the per-class gate check on
    /// every object-resolving RPC is a single `bool` load (M1 perf fix).
    pub(crate) per_class_active_cache: bool,
    /// Pre-computed at `from_config`: true when at least one grant has a
    /// non-`None` `mechanisms` list. Cached so the per-mechanism gate check
    /// on every crypto-init RPC is a single `bool` load rather than a full
    /// grant scan (M1 perf fix). When `false`, all mechanism checks are
    /// entirely skipped — zero overhead for deployments with no mechanism
    /// grants (G3 Task 3).
    pub(crate) per_mechanism_active_cache: bool,
}

impl Default for TokenPolicy {
    /// Returns a zero-access policy: no rules, no allow-all, no anonymous principal.
    /// Intended for test construction via struct update syntax (`..Default::default()`).
    fn default() -> Self {
        Self {
            rules: HashMap::new(),
            allow_all_authenticated: false,
            has_policy: false,
            anonymous_principal: None,
            per_object_active_cache: false,
            per_class_active_cache: false,
            per_mechanism_active_cache: false,
        }
    }
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
        let per_object_active_cache = rules.values().any(|access| {
            if let TokenAccess::Specific(grants) = access {
                grants.iter().any(|g| g.objects.is_some())
            } else {
                false
            }
        });
        let per_class_active_cache = rules.values().any(|access| {
            if let TokenAccess::Specific(grants) = access {
                grants.iter().any(|g| g.classes.is_some())
            } else {
                false
            }
        });
        let per_mechanism_active_cache = rules.values().any(|access| {
            if let TokenAccess::Specific(grants) = access {
                grants.iter().any(|g| g.mechanisms.is_some())
            } else {
                false
            }
        });
        Ok(Self {
            rules,
            allow_all_authenticated: auth.allow_all_authenticated,
            has_policy,
            anonymous_principal: auth.anonymous_principal.clone(),
            per_object_active_cache,
            per_class_active_cache,
            per_mechanism_active_cache,
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
                    Some(specs) => Some(
                        specs
                            .iter()
                            .map(|spec| -> Result<ObjectAcl, String> {
                                match spec {
                                    crate::config::ObjectAclSpec::Bare(s) => {
                                        let uid = parse_object_unique_id(s)
                                            .map_err(|e| format!("policy for '{identity}': {e}"))?;
                                        Ok(ObjectAcl { unique_id: uid, extract: None })
                                    }
                                    crate::config::ObjectAclSpec::Rich(r) => {
                                        let uid = parse_object_unique_id(&r.id)
                                            .map_err(|e| format!("policy for '{identity}': {e}"))?;
                                        let per_obj_extract = r.extract.map(|e| match e {
                                            crate::config::ExtractPolicyConfig::Allow => {
                                                ExtractPolicy::Allow
                                            }
                                            crate::config::ExtractPolicyConfig::Deny => {
                                                ExtractPolicy::Deny
                                            }
                                        });
                                        Ok(ObjectAcl { unique_id: uid, extract: per_obj_extract })
                                    }
                                }
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
