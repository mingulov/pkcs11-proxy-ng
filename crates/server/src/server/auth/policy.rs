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

    pub fn allows(
        &self,
        identity: &AuthenticatedIdentity,
        token_label: &str,
        token_serial: &str,
    ) -> bool {
        if matches!(identity, AuthenticatedIdentity::Unauthenticated) {
            return true; // no-auth mode bypasses policy
        }
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

    /// Filter a list of tokens to only those the identity is authorized to see.
    ///
    /// Used for discovery filtering (ADR-0005 §3): `C_GetSlotList`,
    /// `C_GetTokenInfo`, etc. return only tokens the caller may access.
    /// Each token is represented as `(label, serial)`.
    pub fn visible_tokens<'a>(
        &self,
        identity: &AuthenticatedIdentity,
        tokens: &'a [(String, String)],
    ) -> Vec<&'a (String, String)> {
        tokens.iter().filter(|(label, serial)| self.allows(identity, label, serial)).collect()
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
