use super::grant::{
    ExtractPolicy, ObjectAcl, TokenGrant, parse_class, parse_mechanism, parse_object_unique_id,
};
use super::identity::AuthenticatedIdentity;
pub use super::token_selector::TokenSelector;
use pkcs11_proxy_ng_types::{CkMechanismType, CkObjectClass};
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
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

/// Cap on log-dedup set size (W1-C3-10). Each set holds at most this many
/// peer-identity keys (tens of KB worst case); past the cap the oldest key
/// is evicted (FIFO) so sustained unique peers cannot grow memory without
/// bound. An evicted key may log once more — the bounded-memory tradeoff —
/// and eviction itself logs at debug, never warn-spam.
const LOG_DEDUP_CAP: usize = 1024;

/// FIFO-bounded set of already-logged peer identities (W1-C3-10).
///
/// Behaves like a `HashSet` for the log-once pattern (`insert` returns true
/// only for a new key) but evicts the oldest key past [`LOG_DEDUP_CAP`] so
/// the process cannot accumulate one entry per unique peer forever.
struct LogDedupSet {
    seen: HashSet<String>,
    order: VecDeque<String>,
}

impl LogDedupSet {
    fn new() -> Self {
        Self { seen: HashSet::new(), order: VecDeque::new() }
    }

    /// Record `key`. Returns true when newly inserted (the caller should
    /// log) or false when already present (the caller stays silent).
    fn insert(&mut self, key: String) -> bool {
        if !self.seen.insert(key.clone()) {
            return false;
        }
        self.order.push_back(key);
        while self.order.len() > LOG_DEDUP_CAP {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
                tracing::debug!(evicted = %oldest, "log-dedup set full; evicted oldest entry");
            }
        }
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        debug_assert_eq!(self.seen.len(), self.order.len());
        self.seen.len()
    }
}

/// Tracks SPKI hashes for which we've already emitted the "mTLS auth" info log.
/// Prevents flooding the log when the same certificate connects repeatedly.
static LOGGED_SPKI: OnceLock<Mutex<LogDedupSet>> = OnceLock::new();

/// Tracks legacy DN keys for which we've already emitted the deprecation warning.
static WARNED_LEGACY: OnceLock<Mutex<LogDedupSet>> = OnceLock::new();

#[cfg(test)]
fn logged_spki_len() -> usize {
    LOGGED_SPKI.get().and_then(|m| m.lock().ok()).map(|set| set.len()).unwrap_or(0)
}

#[cfg(test)]
fn warned_legacy_len() -> usize {
    WARNED_LEGACY.get().and_then(|m| m.lock().ok()).map(|set| set.len()).unwrap_or(0)
}

impl TokenPolicy {
    /// Build from parsed config, validating all selectors.
    pub fn from_config(auth: &crate::config::AuthConfig) -> Result<Self, String> {
        let mut rules = HashMap::new();
        for entry in &auth.policy {
            let access = Self::parse_access(&entry.identity, &entry.tokens)?;
            // W1-C3-06: store under the canonical key so accepted identities
            // match runtime keys (uid=01000 → uid=1000).
            let key = crate::config::normalize_policy_identity(&entry.identity);
            // W1-C3-05: reject duplicates loudly — a silent overwrite drops
            // the first entry's grants (false security). Comparison is on
            // the normalized key so uid=01000 + uid=1000 also collide.
            if rules.contains_key(&key) {
                return Err(format!(
                    "duplicate [[auth.policy]] identity '{}': each identity may appear only \
                     once; merge the grants into a single entry",
                    entry.identity
                ));
            }
            rules.insert(key, access);
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
                    let logged = LOGGED_SPKI.get_or_init(|| Mutex::new(LogDedupSet::new()));
                    if let Ok(mut dedup) = logged.lock()
                        && dedup.insert(spki_sha256.clone())
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
                    let warned = WARNED_LEGACY.get_or_init(|| Mutex::new(LogDedupSet::new()));
                    if let Ok(mut dedup) = warned.lock()
                        && dedup.insert(legacy_key.clone())
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

    /// Whether extraction of key material is permitted for a specific object identified
    /// by its `CKA_UNIQUE_ID` byte value.
    ///
    /// This is the per-object extract gate (Task 4): it refines the grant-level
    /// `extract_allowed` decision with object-level overrides from `ObjectAcl::extract`.
    ///
    /// Decision order for each matching grant that has `Some(objects)` list:
    /// 1. If the object appears with `extract = Some(Deny)` → vote deny.
    /// 2. If the object appears with `extract = Some(Allow)` → vote allow.
    /// 3. If the object appears with `extract = None` → inherit grant-level.
    ///
    /// When multiple grants conflict, deny beats allow (security-conservative).
    /// If no grant has a per-object override, falls back to the grant-level
    /// `extract_allowed` decision.
    ///
    /// **Transparent when inactive:** callers should check `per_object_active()`
    /// first and skip this method when `false` (no objects lists in any grant).
    ///
    /// Returns `true` (permissive) for: unauthenticated, `allow_all_authenticated`,
    /// `TokenAccess::All`, no matching grant, object not in any list.
    pub fn extract_allowed_for_object(
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

                // Scan for per-object overrides across all matching grants.
                // Security-conservative: explicit deny beats explicit allow.
                let mut has_explicit_deny = false;
                let mut has_explicit_allow = false;

                for grant in &matching {
                    if let Some(list) = &grant.objects {
                        for acl in list {
                            if acl.unique_id.as_slice() == unique_id {
                                match acl.extract {
                                    Some(ExtractPolicy::Deny) => has_explicit_deny = true,
                                    Some(ExtractPolicy::Allow) => has_explicit_allow = true,
                                    None => {} // inherit grant-level; handled below
                                }
                            }
                        }
                    }
                }

                if has_explicit_deny {
                    return false; // deny beats allow
                }
                if has_explicit_allow {
                    return true; // explicit per-object allow
                }

                // No per-object override found; fall back to grant-level extract policy.
                !matching.iter().any(|g| g.extract == ExtractPolicy::Deny)
            }
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
    ///
    /// The result is pre-computed at `from_config` (M1) so that per-object gate
    /// callers pay only a single `bool` load per RPC, not a full grant scan.
    pub fn per_object_active(&self) -> bool {
        self.per_object_active_cache
    }

    /// Whether any grant in any policy rule has a non-`None` `classes` list.
    ///
    /// When `false`, the per-class authorization check inside the object gate
    /// is skipped entirely (transparent). When `true`, at least one grant
    /// restricts access by `CKA_CLASS`, so the `allows_class` check is enforced
    /// after the unique-id check passes.
    ///
    /// Like `per_object_active`, this is opt-in and pre-computed at `from_config`
    /// (M1) for zero-cost when no class grants are configured.
    pub fn per_class_active(&self) -> bool {
        self.per_class_active_cache
    }

    /// Whether any grant in any policy rule has a non-`None` `mechanisms` list.
    ///
    /// When `false`, the per-mechanism enforcement layer is entirely dormant and
    /// `mechanism_permitted` returns `true` immediately (transparent). When
    /// `true`, at least one grant restricts which mechanisms the identity may use,
    /// so the enforcement path must be consulted on every crypto-init RPC.
    ///
    /// This is opt-in and pre-computed at `from_config` (M1): `false` for all
    /// existing deployments until they explicitly add a `mechanisms` list to a
    /// grant, giving zero overhead on the critical crypto-init path.
    pub fn per_mechanism_active(&self) -> bool {
        self.per_mechanism_active_cache
    }

    /// Whether the principal's matching grant has any `ObjectAcl` entry with an
    /// explicit per-object extract override (`extract.is_some()`).
    ///
    /// Used by `extract_is_permitted` to decide what to do when the uid cannot
    /// be resolved (transient fetch failure or `ATTRIBUTE_SENSITIVE`):
    /// - `true` → at least one per-object extract override exists for this token;
    ///   the uid is needed to evaluate it, so fail-closed (DENY) to prevent
    ///   exporting a key that may be covered by a per-object extract=Deny.
    /// - `false` → no per-object overrides exist; fall through to the grant-level
    ///   `extract_allowed` decision (do NOT over-deny on transient fetch failure).
    ///
    /// Returns `false` for unauthenticated, `allow_all_authenticated`, and
    /// `TokenAccess::All` (those paths have no per-object ACL lists).
    pub fn has_object_extract_override(
        &self,
        identity: &AuthenticatedIdentity,
        token_label: &str,
        token_serial: &str,
    ) -> bool {
        if matches!(identity, AuthenticatedIdentity::Unauthenticated) {
            return false;
        }
        if self.allow_all_authenticated {
            return false;
        }
        match self.resolve_access(identity) {
            None | Some(TokenAccess::All) => false,
            Some(TokenAccess::Specific(grants)) => {
                grants.iter().filter(|g| g.matches_token(token_label, token_serial)).any(|g| {
                    g.objects
                        .as_ref()
                        .is_some_and(|list| list.iter().any(|acl| acl.extract.is_some()))
                })
            }
        }
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
                    Some(list) => list.iter().any(|acl| acl.unique_id.as_slice() == unique_id),
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
                         use tokens = \"all\" (or \"*\") for broad access or tokens = \
                         [\"label:...\"] for token selectors"
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
