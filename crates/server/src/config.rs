use serde::Deserialize;
use std::{fmt, path::PathBuf};

#[derive(Debug, Deserialize)]
pub struct DaemonConfig {
    pub backend: BackendConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub listener: ListenerGroup,
    #[serde(default)]
    pub auth: AuthConfig,
}

/// Authorization configuration (ADR-0005).
#[derive(Debug, Deserialize, Default)]
pub struct AuthConfig {
    #[serde(default)]
    pub allow_all_authenticated: bool,
    #[serde(default)]
    pub policy: Vec<PolicyEntry>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyEntry {
    pub identity: String,
    pub tokens: TokenAccessSpec,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TokenAccessSpec {
    All(String),
    Specific(Vec<String>),
}

#[derive(Deserialize)]
pub struct BackendConfig {
    pub module: PathBuf,
    pub initialize_args: Option<String>,
}

struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Debug for BackendConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let initialize_args = self.initialize_args.as_ref().map(|_| Redacted);
        f.debug_struct("BackendConfig")
            .field("module", &self.module)
            .field("initialize_args", &initialize_args)
            .finish()
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MechanismDiscovery {
    Filtered,
    #[default]
    Transparent,
}

impl MechanismDiscovery {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Filtered => "filtered",
            Self::Transparent => "transparent",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ProxyConfig {
    #[serde(default)]
    pub mechanism_discovery: MechanismDiscovery,
    #[serde(default = "default_lease_seconds")]
    pub lease_seconds: u64,
    #[serde(default = "default_max_message_bytes")]
    pub max_message_bytes: usize,
    /// Backend call timeout in seconds. Operations exceeding this are
    /// abandoned (thread orphaned) and `CKR_DEVICE_ERROR` returned.
    /// Also used as the gRPC-level request timeout.
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// Maximum concurrent backend calls before the circuit breaker trips.
    /// Tune based on HSM capacity: for a hardware HSM supporting 10
    /// simultaneous connections, set this to ~20 (some headroom). Default
    /// 200 is suitable for software tokens like SoftHSM.
    #[serde(default = "default_max_concurrent_backend_calls")]
    pub max_concurrent_backend_calls: usize,
    /// Size of the tokio blocking thread pool used for backend FFI calls.
    /// Must be >= max_concurrent_backend_calls. Default 512 (tokio default).
    /// Increase if you need more concurrent backend calls.
    #[serde(default = "default_max_blocking_threads")]
    pub max_blocking_threads: usize,
    /// How often (in seconds) the eviction task sweeps for expired contexts.
    #[serde(default = "default_eviction_interval_secs")]
    pub eviction_interval_secs: u64,
    /// Maximum number of active contexts. 0 = unlimited.
    #[serde(default = "default_max_contexts")]
    pub max_contexts: usize,
    /// HTTP/2 keepalive ping interval (seconds). 0 = disabled.
    #[serde(default = "default_http2_keepalive_interval_secs")]
    pub http2_keepalive_interval_secs: u64,
    /// HTTP/2 keepalive ping timeout (seconds).
    #[serde(default = "default_http2_keepalive_timeout_secs")]
    pub http2_keepalive_timeout_secs: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            mechanism_discovery: MechanismDiscovery::Transparent,
            lease_seconds: default_lease_seconds(),
            max_message_bytes: default_max_message_bytes(),
            request_timeout_secs: default_request_timeout_secs(),
            max_concurrent_backend_calls: default_max_concurrent_backend_calls(),
            max_blocking_threads: default_max_blocking_threads(),
            eviction_interval_secs: default_eviction_interval_secs(),
            max_contexts: default_max_contexts(),
            http2_keepalive_interval_secs: default_http2_keepalive_interval_secs(),
            http2_keepalive_timeout_secs: default_http2_keepalive_timeout_secs(),
        }
    }
}

fn default_lease_seconds() -> u64 {
    30
}
fn default_max_message_bytes() -> usize {
    4 * 1024 * 1024 // 4 MiB — tonic default
}
fn default_request_timeout_secs() -> u64 {
    60
}
fn default_max_concurrent_backend_calls() -> usize {
    200
}
fn default_max_blocking_threads() -> usize {
    512 // tokio default
}
fn default_eviction_interval_secs() -> u64 {
    5
}
fn default_max_contexts() -> usize {
    1000
}
fn default_http2_keepalive_interval_secs() -> u64 {
    15
}
fn default_http2_keepalive_timeout_secs() -> u64 {
    5
}

#[derive(Debug, Deserialize, Default)]
pub struct ListenerGroup {
    pub local: Option<UnixListenerConfig>,
    pub remote: Option<TcpListenerConfig>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UnixAuthMode {
    #[default]
    PeerCred,
    None,
}

#[derive(Debug, Deserialize)]
pub struct UnixListenerConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub auth: UnixAuthMode,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TcpAuthMode {
    #[default]
    Mtls,
    None,
}

#[derive(Deserialize)]
pub struct TcpListenerConfig {
    pub bind: String,
    #[serde(default)]
    pub auth: TcpAuthMode,
    pub ca_cert: Option<PathBuf>,
    pub server_cert: Option<PathBuf>,
    pub server_key: Option<PathBuf>,
    #[serde(default)]
    pub allow_insecure_tcp: bool,
}

impl fmt::Debug for TcpListenerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let server_key = self.server_key.as_ref().map(|_| Redacted);
        f.debug_struct("TcpListenerConfig")
            .field("bind", &self.bind)
            .field("auth", &self.auth)
            .field("ca_cert", &self.ca_cert)
            .field("server_cert", &self.server_cert)
            .field("server_key", &server_key)
            .field("allow_insecure_tcp", &self.allow_insecure_tcp)
            .finish()
    }
}

impl UnixAuthMode {
    pub const fn is_authenticated(self) -> bool {
        matches!(self, Self::PeerCred)
    }
}

impl TcpAuthMode {
    pub const fn is_authenticated(self) -> bool {
        matches!(self, Self::Mtls)
    }
}

#[derive(Clone, Copy)]
enum PolicyIdentitySource {
    PeerCred,
    Mtls,
}

impl PolicyIdentitySource {
    const fn listener_setting(self) -> &'static str {
        match self {
            Self::PeerCred => "listener.local.auth = 'peer_cred'",
            Self::Mtls => "listener.remote.auth = 'mtls'",
        }
    }

    const fn expected_format(self) -> &'static str {
        match self {
            Self::PeerCred => "uid=<numeric-uid>",
            Self::Mtls => "x509:issuer=<issuer-dn>;subject=<subject-dn>",
        }
    }

    fn can_produce(self, identity: &str) -> bool {
        match self {
            Self::PeerCred => {
                identity.strip_prefix("uid=").is_some_and(|uid| uid.parse::<u32>().is_ok())
            }
            Self::Mtls => {
                identity.strip_prefix("x509:issuer=").is_some_and(|rest| rest.contains(";subject="))
            }
        }
    }
}

impl DaemonConfig {
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config '{}': {e}", path.display()))?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| format!("Failed to parse config '{}': {e}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        if self.proxy.lease_seconds == 0 {
            return Err(
                "proxy.lease_seconds must be > 0 (context leases cannot be disabled)".into()
            );
        }
        // Validate max_message_bytes
        if self.proxy.max_message_bytes == 0 {
            return Err("proxy.max_message_bytes must be > 0".into());
        }
        if self.proxy.max_message_bytes > 64 * 1024 * 1024 {
            return Err("proxy.max_message_bytes must be <= 64 MiB (67108864 bytes)".into());
        }
        // Validate request_timeout_secs
        if self.proxy.request_timeout_secs == 0 {
            return Err("proxy.request_timeout_secs must be > 0".into());
        }
        // Validate max_concurrent_backend_calls
        if self.proxy.max_concurrent_backend_calls == 0 {
            return Err("proxy.max_concurrent_backend_calls must be > 0".into());
        }
        // Validate max_blocking_threads
        if self.proxy.max_blocking_threads == 0 {
            return Err("proxy.max_blocking_threads must be > 0".into());
        }
        if self.proxy.max_concurrent_backend_calls > self.proxy.max_blocking_threads {
            return Err(format!(
                "proxy.max_concurrent_backend_calls ({}) must be <= proxy.max_blocking_threads ({}). \
                 The circuit breaker limit cannot exceed the thread pool size.",
                self.proxy.max_concurrent_backend_calls, self.proxy.max_blocking_threads
            ));
        }
        // Validate eviction_interval_secs
        if self.proxy.eviction_interval_secs == 0 {
            return Err("proxy.eviction_interval_secs must be > 0".into());
        }
        // Validate backend module path exists
        if !self.backend.module.exists() {
            return Err(format!(
                "backend.module path does not exist: {}",
                self.backend.module.display()
            ));
        }
        if let Some(ref tcp) = self.listener.remote {
            if matches!(tcp.auth, TcpAuthMode::None) && !tcp.allow_insecure_tcp {
                return Err("TCP listener with auth='none' requires allow_insecure_tcp=true".into());
            }
            if matches!(tcp.auth, TcpAuthMode::Mtls) {
                if tcp.ca_cert.is_none() || tcp.server_cert.is_none() || tcp.server_key.is_none() {
                    return Err(
                        "TCP auth='mtls' requires ca_cert, server_cert, and server_key".into()
                    );
                }
                // Validate TLS cert/key files exist
                for (name, path_opt) in [
                    ("ca_cert", &tcp.ca_cert),
                    ("server_cert", &tcp.server_cert),
                    ("server_key", &tcp.server_key),
                ] {
                    if let Some(path) = path_opt.as_ref().filter(|p| !p.exists()) {
                        return Err(format!(
                            "listener.remote.{name} path does not exist: {}",
                            path.display()
                        ));
                    }
                }
            }
            // Validate bind address has host:port format
            if !tcp.bind.contains(':') {
                return Err(format!(
                    "listener.remote.bind must be in host:port format, got '{}'",
                    tcp.bind
                ));
            }
        }
        // Warn (via error) if no listeners are configured
        if self.listener.local.is_none() && self.listener.remote.is_none() {
            return Err(
                "No listeners configured. Set [listener.local] and/or [listener.remote].".into()
            );
        }
        let has_authenticated_listener =
            self.listener.local.as_ref().is_some_and(|l| l.auth.is_authenticated())
                || self.listener.remote.as_ref().is_some_and(|r| r.auth.is_authenticated());
        if has_authenticated_listener
            && self.auth.policy.is_empty()
            && !self.auth.allow_all_authenticated
        {
            return Err("Authenticated listener configured but no auth policy entries \
                 and allow_all_authenticated is false. Either add [auth.policy] \
                 entries or set auth.allow_all_authenticated = true."
                .into());
        }
        self.validate_policy_identities()?;
        crate::server::auth::policy::TokenPolicy::from_config(&self.auth)?;
        Ok(())
    }

    fn configured_policy_identity_sources(&self) -> Vec<PolicyIdentitySource> {
        let mut sources = Vec::new();
        if self.listener.local.as_ref().is_some_and(|l| matches!(l.auth, UnixAuthMode::PeerCred)) {
            sources.push(PolicyIdentitySource::PeerCred);
        }
        if self.listener.remote.as_ref().is_some_and(|r| matches!(r.auth, TcpAuthMode::Mtls)) {
            sources.push(PolicyIdentitySource::Mtls);
        }
        sources
    }

    fn validate_policy_identities(&self) -> Result<(), String> {
        if self.auth.policy.is_empty() {
            return Ok(());
        }

        let sources = self.configured_policy_identity_sources();
        for (index, entry) in self.auth.policy.iter().enumerate() {
            if sources.iter().any(|source| source.can_produce(&entry.identity)) {
                continue;
            }

            let configured = if sources.is_empty() {
                "no authenticated listeners; auth = 'none' bypasses auth policy".to_string()
            } else {
                sources
                    .iter()
                    .map(|source| source.listener_setting())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let expected = if sources.is_empty() {
                "enable listener.local.auth = 'peer_cred' for uid=<numeric-uid> identities or \
                 listener.remote.auth = 'mtls' for x509:issuer=<issuer-dn>;subject=<subject-dn> \
                 identities"
                    .to_string()
            } else {
                sources
                    .iter()
                    .map(|source| source.expected_format())
                    .collect::<Vec<_>>()
                    .join(" or ")
            };

            return Err(format!(
                "auth.policy[{index}].identity = '{}' cannot be produced by configured listeners \
                 ({configured}); expected {expected}.",
                entry.identity
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
