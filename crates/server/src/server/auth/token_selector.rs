#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSelector {
    Label(String),
    Serial(String),
    Uri(String),
}

impl TokenSelector {
    /// Parse a selector string into a `TokenSelector`.
    ///
    /// Accepted forms:
    /// - `label:<value>` — match by token label (case-sensitive)
    /// - `serial:<value>` — match by token serial (case-sensitive)
    /// - `pkcs11:<rest>` — PKCS#11 URI selector (matching deferred to Phase 2)
    /// - bare string without a recognized prefix — defaults to label match
    ///
    /// Returns `Err` for empty, whitespace-only, or ambiguous selectors.
    pub fn parse(selector: &str) -> Result<Self, String> {
        let trimmed = selector.trim();
        if trimmed.is_empty() {
            return Err("selector must not be empty".into());
        }
        if let Some(label) = trimmed.strip_prefix("label:") {
            let label = label.trim();
            if label.is_empty() {
                return Err("label: selector value must not be empty".into());
            }
            Ok(Self::Label(label.to_string()))
        } else if let Some(serial) = trimmed.strip_prefix("serial:") {
            let serial = serial.trim();
            if serial.is_empty() {
                return Err("serial: selector value must not be empty".into());
            }
            Ok(Self::Serial(serial.to_string()))
        } else if trimmed.starts_with("pkcs11:") {
            Ok(Self::Uri(trimmed.to_string()))
        } else if trimmed.contains(':') {
            let prefix = trimmed.split(':').next().unwrap_or("");
            Err(format!(
                "unrecognized selector prefix '{prefix}:' — use 'label:', 'serial:', or 'pkcs11:'"
            ))
        } else {
            Ok(Self::Label(trimmed.to_string()))
        }
    }

    pub fn matches(&self, token_label: &str, token_serial: &str) -> bool {
        match self {
            Self::Label(label) => label == token_label,
            Self::Serial(serial) => serial == token_serial,
            Self::Uri(_) => false,
        }
    }
}
