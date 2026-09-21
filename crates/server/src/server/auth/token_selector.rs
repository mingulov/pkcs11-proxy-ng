#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSelector {
    Label(String),
    Serial(String),
}

/// Strip PKCS#11 field padding (trailing spaces and NULs) for
/// comparison and parsing (W1-C3-37).
///
/// Token labels and serials live in blank-padded fixed-width backend
/// fields, so trailing spaces/NULs are padding and insignificant —
/// but leading characters are significant. Only the trailing end is
/// ever normalized.
fn trim_field_padding(s: &str) -> &str {
    s.trim_end_matches([' ', '\0'])
}

impl TokenSelector {
    /// Parse a selector string into a `TokenSelector`.
    ///
    /// Accepted forms:
    /// - `label:<value>` — match by token label (case-sensitive)
    /// - `serial:<value>` — match by token serial (case-sensitive)
    /// - `pkcs11:<rest>` — rejected at parse: URI matching is not yet
    ///   implemented (it would match nothing and silently deny); use
    ///   `label:` / `serial:`
    /// - bare string without a recognized prefix — defaults to label match
    ///
    /// Trailing spaces/NULs are padding and trimmed; leading characters
    /// are significant and preserved (so leading-space labels stay
    /// expressible). Returns `Err` for empty selectors (after padding is
    /// trimmed) or ambiguous prefixes.
    pub fn parse(selector: &str) -> Result<Self, String> {
        let trimmed = trim_field_padding(selector);
        if trimmed.is_empty() {
            return Err("selector must not be empty".into());
        }
        if let Some(label) = trimmed.strip_prefix("label:") {
            let label = trim_field_padding(label);
            if label.is_empty() {
                return Err("label: selector value must not be empty".into());
            }
            Ok(Self::Label(label.to_string()))
        } else if let Some(serial) = trimmed.strip_prefix("serial:") {
            let serial = trim_field_padding(serial);
            if serial.is_empty() {
                return Err("serial: selector value must not be empty".into());
            }
            Ok(Self::Serial(serial.to_string()))
        } else if trimmed.starts_with("pkcs11:") {
            Err("pkcs11: URI selectors are not yet supported; use 'label:' or 'serial:'".into())
        } else if trimmed.contains(':') {
            let prefix = trimmed.split(':').next().unwrap_or("");
            Err(format!(
                "unrecognized selector prefix '{prefix}:' — use 'label:', 'serial:', or 'pkcs11:'"
            ))
        } else {
            Ok(Self::Label(trimmed.to_string()))
        }
    }

    /// Whether this selector matches the given token label and serial.
    ///
    /// Comparison normalizes PKCS#11 field padding (trailing spaces/NULs
    /// on either side are insignificant); leading characters are
    /// significant (W1-C3-37).
    pub fn matches(&self, token_label: &str, token_serial: &str) -> bool {
        // W1-C3-17: the unconstructible Uri variant (whose arm hardcoded
        // false) is deleted; pkcs11: URIs are rejected in parse().
        match self {
            Self::Label(label) => trim_field_padding(label) == trim_field_padding(token_label),
            Self::Serial(serial) => trim_field_padding(serial) == trim_field_padding(token_serial),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // W1-L8-12: the ADR-0005 §6 policy example must use selector forms
    // this parser accepts. Pins the exact example strings so a future
    // doc edit that reintroduces pkcs11: URIs fails here.
    #[test]
    fn adr_example_selectors_parse() {
        assert!(matches!(TokenSelector::parse("label:Audit"), Ok(TokenSelector::Label(_))));
        assert!(matches!(TokenSelector::parse("serial:1234"), Ok(TokenSelector::Serial(_))));
        assert!(TokenSelector::parse("pkcs11:token=Audit;serial=1234").is_err());
    }

    // W1-C3-37: matching normalizes PKCS#11 field padding — trailing
    // spaces/NULs on either side are insignificant (blank-padded
    // fixed-width token fields).
    #[test]
    fn matches_ignores_trailing_padding() {
        let label = TokenSelector::Label("Audit".into());
        assert!(label.matches("Audit", "x"));
        assert!(label.matches("Audit   ", "x"));
        assert!(label.matches("Audit\0\0", "x"));
        assert!(label.matches("Audit  \0", "x"));
        let padded_selector = TokenSelector::Label("Audit  ".into());
        assert!(padded_selector.matches("Audit", "x"));
        let serial = TokenSelector::Serial("1234".into());
        assert!(serial.matches("x", "1234  "));
        assert!(serial.matches("x", "1234\0"));
    }

    // W1-C3-37: leading characters are significant per backend
    // semantics — only the trailing end is padding.
    #[test]
    fn matches_treats_leading_characters_as_significant() {
        let label = TokenSelector::Label("Audit".into());
        assert!(!label.matches(" Audit", "x"));
        assert!(!label.matches("\0Audit", "x"));
        let leading = TokenSelector::Label(" Audit".into());
        assert!(leading.matches(" Audit", "x"));
        assert!(leading.matches(" Audit  ", "x"));
        assert!(!leading.matches("Audit", "x"));
    }

    // W1-C3-37: parsing trims trailing padding but preserves leading
    // characters so leading-space labels stay expressible.
    #[test]
    fn parse_preserves_leading_but_trims_trailing_padding() {
        assert_eq!(
            TokenSelector::parse("label: Audit").unwrap(),
            TokenSelector::Label(" Audit".into())
        );
        assert_eq!(
            TokenSelector::parse("label:Audit  ").unwrap(),
            TokenSelector::Label("Audit".into())
        );
        assert_eq!(
            TokenSelector::parse("serial:1234\0").unwrap(),
            TokenSelector::Serial("1234".into())
        );
        assert_eq!(TokenSelector::parse("Audit  ").unwrap(), TokenSelector::Label("Audit".into()));
        assert_eq!(TokenSelector::parse(" Audit").unwrap(), TokenSelector::Label(" Audit".into()));
    }

    // W1-C3-37 preservation control: empty selectors are still rejected
    // after the trim-direction change.
    #[test]
    fn parse_still_rejects_empty_selectors() {
        assert!(TokenSelector::parse("").is_err());
        assert!(TokenSelector::parse("   ").is_err());
        assert!(TokenSelector::parse("label:").is_err());
        assert!(TokenSelector::parse("label:   ").is_err());
        assert!(TokenSelector::parse("serial:").is_err());
    }
}
