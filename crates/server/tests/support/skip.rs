use std::process::Command;

/// Reason a test is skipped or expected to fail.
#[derive(Debug, Clone)]
pub enum SkipReason {
    /// Required external tool is not installed.
    ToolMissing(&'static str),
    /// Required backend/provider module is not available.
    ProviderMissing(&'static str),
    /// The mechanism is not supported by the provider.
    MechanismUnsupported { provider: &'static str, mechanism: &'static str },
    /// Known incompatibility between the proxy and a specific provider.
    KnownIncompat { provider: &'static str, description: &'static str },
    /// The test exercises a feature blocked by a fundamental limitation.
    FundamentalLimitation(&'static str),
    /// Environment variable or config not set.
    EnvNotSet(&'static str),
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolMissing(tool) => write!(f, "SKIP: required tool not installed: {tool}"),
            Self::ProviderMissing(provider) => {
                write!(f, "SKIP: provider not available: {provider}")
            }
            Self::MechanismUnsupported { provider, mechanism } => {
                write!(f, "SKIP: {provider} does not support {mechanism}")
            }
            Self::KnownIncompat { provider, description } => {
                write!(f, "XFAIL: {provider}: {description}")
            }
            Self::FundamentalLimitation(desc) => {
                write!(f, "XFAIL: fundamental limitation: {desc}")
            }
            Self::EnvNotSet(var) => write!(f, "SKIP: environment variable not set: {var}"),
        }
    }
}

/// Record a skip or expected failure visibly in test output.
///
/// Usage:
/// ```ignore
/// record_skip!(SkipReason::ToolMissing("pkcs11-tool"));
/// return Ok(());
/// ```
#[macro_export]
macro_rules! record_skip {
    ($reason:expr) => {{
        let reason: $crate::support::SkipReason = $reason;
        eprintln!("⚠  {reason}");
    }};
}

/// Check whether a command-line tool is available on PATH.
pub fn tool_available(name: &str) -> bool {
    Command::new("which").arg(name).output().map(|o| o.status.success()).unwrap_or(false)
}
