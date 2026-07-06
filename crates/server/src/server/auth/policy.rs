use super::identity::AuthenticatedIdentity;
pub use super::token_selector::TokenSelector;
use std::collections::HashMap;

#[derive(Debug)]
pub struct TokenPolicy {
    pub(crate) rules: HashMap<String, TokenAccess>,
    pub(crate) allow_all_authenticated: bool,
}

#[derive(Debug)]
pub enum TokenAccess {
    All,
    Specific(Vec<TokenSelector>),
}

impl TokenPolicy {
    /// Build from parsed config, validating all selectors.
    pub fn from_config(auth: &crate::config::AuthConfig) -> Result<Self, String> {
        let mut rules = HashMap::new();
        for entry in &auth.policy {
            let access = Self::parse_access(&entry.identity, &entry.tokens)?;
            rules.insert(entry.identity.clone(), access);
        }
        Ok(Self { rules, allow_all_authenticated: auth.allow_all_authenticated })
    }

    /// Whether an **unauthenticated** peer is allowed (no-auth / dev mode).
    ///
    /// This is the SINGLE deny-default flip-point for G2-PR2 (ADR-0012): today
    /// it returns `true` (no-auth mode bypasses policy, preserving current
    /// behavior). When the G2-PR2 authorization-enforcement model lands, change
    /// this to `false` and route unauthenticated peers through an explicit
    /// `anonymous_principal` (audit-identity only). Both `allows()` and
    /// `grpc_service::authorization::slot_is_authorized` route the
    /// unauthenticated case through THIS method, so the flip happens in exactly
    /// one place — never delete an inline `Unauthenticated ⇒ true` at only one
    /// of the (previously three) sites.
    pub fn allows_unauthenticated(&self) -> bool {
        true
    }

    pub fn allows(
        &self,
        identity: &AuthenticatedIdentity,
        token_label: &str,
        token_serial: &str,
    ) -> bool {
        if matches!(identity, AuthenticatedIdentity::Unauthenticated) {
            return self.allows_unauthenticated();
        }
        // `allow_all_authenticated` applies ONLY to genuinely-authenticated
        // identities; the unauthenticated case is handled above via the single
        // flip-point, so this can never blanket-authorize an unauthenticated peer.
        if self.allow_all_authenticated {
            return true;
        }
        let key = identity.to_string();
        match self.rules.get(&key) {
            Some(TokenAccess::All) => true,
            Some(TokenAccess::Specific(selectors)) => {
                selectors.iter().any(|s| s.matches(token_label, token_serial))
            }
            None => false, // default deny
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
            crate::config::TokenAccessSpec::Specific(selectors) => {
                let parsed = selectors
                    .iter()
                    .map(|selector| {
                        TokenSelector::parse(selector).map_err(|error| {
                            format!(
                                "policy for '{}': invalid selector '{}': {error}",
                                identity, selector
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(TokenAccess::Specific(parsed))
            }
        }
    }
}

#[cfg(test)]
mod tests;
