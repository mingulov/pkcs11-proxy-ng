use serde::Deserialize;
use std::{fmt, path::PathBuf};

/// Human-readable table of env vars the daemon honours, printed by
/// `pkcs11-proxy-ng --print-env-vars`. Keep this aligned with the body
/// of [`DaemonConfig::apply_env_overrides`].
pub fn env_var_help() -> String {
    let rows: &[(&str, &str, &str)] = &[
        (
            "PKCS11_PROXY_BIND",
            "listener.remote.bind",
            "TCP listen address; with no [listener.remote] block it creates an unauthenticated listener only if PKCS11_PROXY_ALLOW_INSECURE=1.",
        ),
        (
            "PKCS11_PROXY_BACKEND_MODULE",
            "backend.module",
            "Absolute path to the backend PKCS#11 .so the daemon dlopens.",
        ),
        (
            "PKCS11_PROXY_BACKEND_ARGS",
            "backend.initialize_args",
            "Backend-specific C_Initialize args string (e.g. NSS config dir spec).",
        ),
        (
            "PKCS11_PROXY_MECHANISMS_CONFIG",
            "mechanisms.config_path",
            "Path to the mechanism_params.toml registry served to shims.",
        ),
        (
            "PKCS11_PROXY_ALLOW_INSECURE",
            "listener.remote.allow_insecure_tcp",
            "Set to 1 to let PKCS11_PROXY_BIND create an unauthenticated TCP listener.",
        ),
        (
            "PKCS11_PROXY_RESILIENCE_METRICS_SOCKET",
            "resilience.metrics_socket",
            "Unix-domain metrics endpoint path; serves Prometheus text on GET /metrics (mode 0600).",
        ),
        (
            "PKCS11_PROXY_RESILIENCE_FIND_THRESHOLD",
            "resilience.find_result_warn_threshold",
            "C_FindObjects result size above which a pathological-population event is counted and logged.",
        ),
        (
            "PKCS11_PROXY_TEST_HOOKS_CONTROL_SOCKET",
            "test_hooks.control_socket",
            "Hook-gated control endpoint path (mode 0600); requires a native-owner-test-hooks build, default builds fail closed.",
        ),
    ];
    let var_w = rows.iter().map(|r| r.0.len()).max().unwrap_or(0);
    let field_w = rows.iter().map(|r| r.1.len()).max().unwrap_or(0);
    let mut out = String::new();
    out.push_str("Environment variables (override the corresponding TOML field):\n\n");
    for (var, field, desc) in rows {
        out.push_str(&format!("  {var:var_w$}  →  {field:field_w$}    {desc}\n"));
    }
    out.push_str("\nPrecedence (lowest → highest): TOML defaults < TOML file < environment.\n");
    out
}

#[derive(Debug, Deserialize)]
pub struct DaemonConfig {
    pub backend: BackendConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub listener: ListenerGroup,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub mechanisms: MechanismsConfig,
    #[serde(default)]
    pub resilience: ResilienceConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub test_hooks: TestHooksConfig,
}

/// Hook-gated daemon control plane (C3M.6 row 18). Absent section => all
/// fields `None` => inert (byte-identical to today). A configured control
/// socket requires a `native-owner-test-hooks` build; default builds fail
/// closed at startup (see `server::validate_test_hooks_config`) instead of
/// silently ignoring it.
#[derive(Debug, Deserialize, Default)]
pub struct TestHooksConfig {
    /// If set, a Unix-domain control endpoint (mode 0600) is bound here,
    /// serving the hook surface (`GET /hooks/instance`,
    /// `GET /hooks/last-mechanism`, `POST /hooks/fail-next-close`) for
    /// subprocess/topology fault-injection tests.
    pub control_socket: Option<PathBuf>,
}

/// Mechanism registry source. The daemon loads the file at startup and
/// serves the resulting registry to shims over `GetBackendInterfaces`.
/// If `config_path` is absent the daemon serves the embedded default
/// registry (revision = "embedded-default").
#[derive(Debug, Deserialize, Default)]
pub struct MechanismsConfig {
    pub config_path: Option<PathBuf>,
}

/// Placeholder backend module path shipped in the default proxy.toml.
/// The daemon refuses to start if `backend.module` is still this value
/// so misconfigurations fail loud at startup rather than at first call.
pub const BACKEND_MODULE_PLACEHOLDER: &str = "/CHANGE_ME/path/to/backend.so";

/// Authorization configuration (ADR-0005).
#[derive(Debug, Deserialize, Default)]
pub struct AuthConfig {
    #[serde(default)]
    pub allow_all_authenticated: bool,
    #[serde(default)]
    pub policy: Vec<PolicyEntry>,
    /// Audit-identity label used for unauthenticated peers when `[audit]` is
    /// enabled and at least one unauthenticated listener is present. Setting
    /// this name relaxes the H2 guard (audit+auth=none → refuse to start)
    /// because the operator has explicitly named how unauthenticated peers
    /// will appear in audit records, avoiding the "identity=None" compliance
    /// gap that guard protects against. **Audit-identity only** — this is
    /// never an authz grant. Authz for unauthenticated peers is still
    /// controlled by `allows_unauthenticated()` in `TokenPolicy`.
    #[serde(default)]
    pub anonymous_principal: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyEntry {
    pub identity: String,
    pub tokens: TokenAccessSpec,
}

/// A single element in a `tokens = [...]` list.
///
/// Two forms are accepted:
///
/// **Bare string** (back-compat sugar):
/// ```toml
/// tokens = ["label:Prod", "serial:SN123"]
/// ```
///
/// **Rich grant table** (class/mechanism/extract scoping):
/// ```toml
/// tokens = [
///   { token = "label:Prod", classes = ["secret_key","private_key"],
///     mechanisms = ["CKM_AES_GCM"], extract = "deny" }
/// ]
/// ```
///
/// The two forms can be mixed inside the same list.
#[derive(Debug)]
pub enum GrantSpec {
    /// A bare token-selector string; equivalent to a rich grant with
    /// `classes = None`, `mechanisms = None`, `extract = "allow"`.
    Bare(String),
    /// A full grant table with optional class/mechanism lists and an extract policy.
    Rich(RichGrantConfig),
}

// Manual `Deserialize` (in place of `#[serde(untagged)]`) so a malformed rich
// table — e.g. an unknown key rejected by `deny_unknown_fields` — surfaces
// the inner error naming the key. A derived untagged impl discards
// per-variant errors and reports only "data did not match any variant",
// which would hide the typo'd key. Accepted shapes are unchanged: a string
// or a table.
impl<'de> Deserialize<'de> for GrantSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct GrantSpecVisitor;

        impl<'de> serde::de::Visitor<'de> for GrantSpecVisitor {
            type Value = GrantSpec;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a token selector string or a rich grant table")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(GrantSpec::Bare(v.to_owned()))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(GrantSpec::Bare(v))
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                RichGrantConfig::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    .map(GrantSpec::Rich)
            }
        }

        deserializer.deserialize_any(GrantSpecVisitor)
    }
}

/// Rich grant table element for `tokens = [{ token = "...", ... }]`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RichGrantConfig {
    /// Token selector string (same syntax as bare strings: `"label:X"`, `"serial:Y"`, etc.)
    pub token: String,
    /// Object classes this grant permits. `None` (field absent) = all classes.
    #[serde(default)]
    pub classes: Option<Vec<String>>,
    /// Mechanisms this grant permits. `None` (field absent) = all mechanisms.
    #[serde(default)]
    pub mechanisms: Option<Vec<String>>,
    /// Whether extraction of sensitive key material is permitted. Defaults to `"allow"`.
    #[serde(default)]
    pub extract: ExtractPolicyConfig,
    /// CKA_UNIQUE_ID allow-list. Each entry is either a bare hex string
    /// (e.g. `"a1b2c3"`) or a table `{ id = "a1b2c3", extract = "deny" }`.
    /// `None` (field absent) = all objects permitted (back-compat default).
    /// `Some(list)` = only objects whose CKA_UNIQUE_ID byte value matches an
    /// entry (hex-decoded) are permitted. Requires backend PKCS#11 v3.0+.
    #[serde(default)]
    pub objects: Option<Vec<ObjectAclSpec>>,
}

/// Serde config form for extract policy (maps to `ExtractPolicy` at runtime).
#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExtractPolicyConfig {
    #[default]
    Allow,
    Deny,
}

/// A single entry in the `objects` allow-list.
///
/// Two forms accepted in TOML:
/// - Bare hex string: `"a1b2c3"` — inherits grant-level extract policy.
/// - Rich table: `{ id = "a1b2c3", extract = "deny" }` — per-object override.
#[derive(Debug)]
pub enum ObjectAclSpec {
    /// A bare CKA_UNIQUE_ID hex string; inherits grant-level extract policy.
    Bare(String),
    /// A rich table with an optional per-object extract-policy override.
    Rich(ObjectAclRichConfig),
}

// Manual `Deserialize` (in place of `#[serde(untagged)]`); same rationale as
// `GrantSpec` above — unknown keys must surface naming the key. Accepted
// shapes are unchanged: a string or a table.
impl<'de> Deserialize<'de> for ObjectAclSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ObjectAclSpecVisitor;

        impl<'de> serde::de::Visitor<'de> for ObjectAclSpecVisitor {
            type Value = ObjectAclSpec;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a CKA_UNIQUE_ID hex string or a rich objects entry")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ObjectAclSpec::Bare(v.to_owned()))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ObjectAclSpec::Bare(v))
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                ObjectAclRichConfig::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    .map(ObjectAclSpec::Rich)
            }
        }

        deserializer.deserialize_any(ObjectAclSpecVisitor)
    }
}

/// Rich form of an `objects` allow-list entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectAclRichConfig {
    /// CKA_UNIQUE_ID as a hex byte string (e.g. `"a1b2c3"`).
    pub id: String,
    /// Per-object extract policy override. `None` (field absent) = inherit
    /// the grant-level extract policy.
    #[serde(default)]
    pub extract: Option<ExtractPolicyConfig>,
}

/// Token-access specification in `[[auth.policy]]`.
///
/// Three valid forms:
/// - `tokens = "all"` — blanket access to all tokens.
/// - `tokens = ["label:X", "serial:Y"]` — list of bare selector strings.
/// - `tokens = [{ token = "label:X", classes = [...], mechanisms = [...], extract = "deny" }]`
///   — list of rich grant tables (may be mixed with bare strings).
#[derive(Debug)]
pub enum TokenAccessSpec {
    All(String),
    Specific(Vec<GrantSpec>),
}

// Manual `Deserialize` (in place of `#[serde(untagged)]`); same rationale as
// `GrantSpec` above — this is the outer layer wrapping rich grants, so a
// derived untagged impl here would swallow the key-naming error from the
// inner grant layer. Accepted shapes are unchanged: a string or an array.
impl<'de> Deserialize<'de> for TokenAccessSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TokenAccessSpecVisitor;

        impl<'de> serde::de::Visitor<'de> for TokenAccessSpecVisitor {
            type Value = TokenAccessSpec;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("`\"all\"` or a list of token selectors / rich grant tables")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(TokenAccessSpec::All(v.to_owned()))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(TokenAccessSpec::All(v))
            }

            fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                Vec::<GrantSpec>::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
                    .map(TokenAccessSpec::Specific)
            }
        }

        deserializer.deserialize_any(TokenAccessSpecVisitor)
    }
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
    /// Maximum time (seconds) the daemon waits for `populate_slots` to
    /// complete at startup. On timeout the daemon exits 1.
    #[serde(default = "default_startup_timeout_secs")]
    pub startup_timeout_secs: u64,
    /// On SIGTERM/SIGINT, drain in-flight RPCs for up to this many
    /// seconds before forcing shutdown. k8s
    /// `terminationGracePeriodSeconds` should be at least this value.
    #[serde(default = "default_shutdown_grace_secs")]
    pub shutdown_grace_secs: u64,
    /// Consecutive backend-call failures before `tonic-health` flips to
    /// NOT_SERVING. The next successful backend call flips it back.
    /// Drives k8s readiness probes when the daemon is up but the
    /// backend HSM is unresponsive.
    #[serde(default = "default_backend_health_consecutive_failures")]
    pub backend_health_consecutive_failures: u32,
    /// Max GetBackendInterfaces RPCs allowed per peer IP per
    /// `rate_limit_window_secs` window. Closes FOLLOWUP-rate-limit
    /// — defends against a noisy peer spamming the discovery RPC.
    /// 0 = disabled (default; trust the network boundary).
    #[serde(default = "default_rate_limit_get_backend_interfaces")]
    pub rate_limit_get_backend_interfaces: u32,
    /// Window length for the per-peer rate limiter, in seconds.
    #[serde(default = "default_rate_limit_window_secs")]
    pub rate_limit_window_secs: u64,
    /// Reject spec-invalid inputs (NULL data pointer with len>0, NULL mechanism
    /// on operation init) with CKR_ARGUMENTS_BAD at the daemon, before they
    /// reach the module — protects a shared daemon from modules that crash on
    /// them. OFF by default per ADR-0010 (trades transparency for availability).
    /// NOTE: a sanitize-mode reject does NOT terminate the active backend
    /// operation the way a module-returned error would (documented divergence).
    #[serde(default)]
    pub sanitize_inputs: bool,
    /// If set, the daemon exits (nonzero) once the number of stuck backend
    /// calls — calls that outlived `request_timeout_secs` and are still
    /// wedged inside the token — exceeds this limit, so a supervisor
    /// (systemd/k8s) restarts it. This is the restart-based recovery for a
    /// PERMANENTLY wedged token (see ADR-0011 A2 alignment); opt-in only.
    /// Unset (default) = never self-exit; the daemon keeps serving other
    /// tokens and self-recovers if the wedged one unsticks.
    #[serde(default)]
    pub max_stuck_backend_calls: Option<u64>,
    /// How long (in seconds) to hold the per-slot login lock while a
    /// `C_Login` or `C_Logout` is in flight. Used by the slot-login
    /// serialization logic to prevent concurrent login/logout races on
    /// shared slots. Default 10 seconds.
    #[serde(default = "default_login_lock_timeout_secs")]
    pub login_lock_timeout_secs: u64,
}

/// Whether the daemon should self-exit given the stuck-call gauge and the
/// configured limit. Pure so the policy is unit-tested without a process
/// exit; the single caller performs the actual exit.
pub fn should_exit_on_stuck_calls(stuck: u64, limit: Option<u64>) -> bool {
    matches!(limit, Some(max) if stuck > max)
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
            startup_timeout_secs: default_startup_timeout_secs(),
            shutdown_grace_secs: default_shutdown_grace_secs(),
            backend_health_consecutive_failures: default_backend_health_consecutive_failures(),
            rate_limit_get_backend_interfaces: default_rate_limit_get_backend_interfaces(),
            rate_limit_window_secs: default_rate_limit_window_secs(),
            sanitize_inputs: false,
            max_stuck_backend_calls: None,
            login_lock_timeout_secs: default_login_lock_timeout_secs(),
        }
    }
}

fn default_rate_limit_get_backend_interfaces() -> u32 {
    0 // disabled by default; existing deployments don't see surprise rejections
}

fn default_rate_limit_window_secs() -> u64 {
    1
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
fn default_startup_timeout_secs() -> u64 {
    30
}
fn default_shutdown_grace_secs() -> u64 {
    30
}
fn default_backend_health_consecutive_failures() -> u32 {
    3
}
fn default_login_lock_timeout_secs() -> u64 {
    10
}

#[derive(Debug, Deserialize, Default)]
pub struct ListenerGroup {
    pub local: Option<UnixListenerConfig>,
    pub remote: Option<TcpListenerConfig>,
}

/// Opt-in pathological-object-population detection + local metrics endpoint.
/// Absent section => all fields `None` => feature inert (byte-identical to today).
#[derive(Debug, Deserialize, Default)]
pub struct ResilienceConfig {
    /// If set, a `C_FindObjects` result larger than this is counted as a
    /// pathological-population event and logged. Count-only: NO extra backend calls.
    /// The same value also bounds each `find_objects` filter scan (W1-C1-07):
    /// past the bound the scan stops with a loud failure instead of draining
    /// an adversarial population unboundedly. Unset = unbounded, as before.
    pub find_result_warn_threshold: Option<usize>,
    /// If set, a Unix-domain metrics endpoint (mode 0600) is bound here, serving
    /// Prometheus text on `GET /metrics`.
    pub metrics_socket: Option<PathBuf>,
    /// Opt-in session-scoped attribute result coalescer (R2). Default `false`
    /// (off). When `true`, the daemon caches per-`(session, object, attribute)`
    /// backend results and serves repeated `C_GetAttributeValue` calls for the
    /// **same** `(session, object, attribute)` triple from the in-memory cache
    /// rather than forwarding them to the backend, eliminating round-trips for
    /// repeated reads of the same attribute.
    ///
    /// **Non-security attributes only.** Value-bearing-secret attributes (V5:
    /// `CKA_VALUE`, `CKA_PRIVATE_EXPONENT`, etc.) and `CKR_ATTRIBUTE_SENSITIVE`
    /// results are never cached. Only non-sensitive, non-extractable-secret
    /// attribute results enter the cache.
    ///
    /// **Cache hits are byte-identical to the backend response.** The raw
    /// per-attribute byte sequence returned by the backend is stored verbatim
    /// and reconstructed identically on a hit — the client cannot distinguish
    /// a cached response from a live one.
    ///
    /// **Invalidation:** the cache is cleared on `C_SetAttributeValue`,
    /// `C_DestroyObject`, and session close. It is NOT invalidated when another
    /// client mutates a shared token object; see the multi-client caveat below.
    ///
    /// **Multi-client staleness caveat (opt-in rationale).** The cache is
    /// per logical client context. If a different client context modifies a
    /// token object, this context's cache entry for that object is NOT
    /// invalidated — it will serve stale data until session close or logout.
    /// For this reason the feature is **opt-in** and should only be enabled in
    /// **read-heavy, single-writer** workloads (e.g. read-only access to
    /// immutable certificate metadata). It is **not suitable** for multi-writer
    /// shared-token scenarios. Cross-context isolation (different identities
    /// having separate contexts) is enforced regardless of this setting.
    ///
    /// This counter is observable at the metrics endpoint as
    /// `pkcs11_proxy_attr_coalesce_hits_total` and
    /// `pkcs11_proxy_attr_coalesce_misses_total`.
    #[serde(default)]
    pub coalesce_attributes: bool,
}

/// Opt-in per-principal in-flight / session-quota limiter and per-slot
/// failed-login budget (G2-PR3). All fields are `None` by default: an absent
/// `[rate_limit]` section is byte-identical to having no rate limiting at all.
#[derive(Debug, Deserialize, Default)]
pub struct RateLimitConfig {
    /// Maximum concurrent in-flight operations per principal (identified by
    /// mTLS SPKI or Unix peer-cred). `None` (default) → no cap.
    pub per_principal_max_in_flight: Option<usize>,
    /// Maximum concurrent open sessions per principal. `None` (default) → no cap.
    pub per_principal_max_sessions: Option<usize>,
    /// Number of consecutive failed `C_Login` attempts per slot before the slot
    /// enters a failed-login cooldown. `None` (default) → no budget enforced.
    pub per_slot_failed_login_budget: Option<u32>,
    /// Cooldown duration (seconds) after `per_slot_failed_login_budget` is
    /// exhausted. Defaults to 60 s when a budget is set; has no effect when
    /// `per_slot_failed_login_budget` is `None`.
    pub per_slot_failed_login_cooldown_secs: Option<u64>,
}

/// Opt-in tamper-evident audit stream (ADR-0012, G1). Off unless `dir` is set.
#[derive(Debug, Deserialize)]
pub struct AuditConfig {
    /// Directory the daemon writes rotated JSONL audit logs + the anchor into.
    /// Absent => audit disabled (byte-identical to today).
    #[serde(default)]
    pub dir: Option<PathBuf>,
    /// Ed25519 private key (raw 32-byte seed) used to sign periodic checkpoints.
    /// Absent => hash chain only (no signed checkpoints). Loaded, never generated.
    #[serde(default)]
    pub signing_key: Option<PathBuf>,
    #[serde(default = "default_audit_rotate_max_bytes")]
    pub rotate_max_bytes: u64,
    #[serde(default = "default_audit_rotate_keep_files")]
    pub rotate_keep_files: u32,
    /// How often (in seconds) to write a signed checkpoint regardless of the
    /// record-count trigger. `0` disables the time trigger. Default 300 (5 min).
    /// Only effective when `signing_key` is set; a time-triggered checkpoint
    /// without a signer has no value since there is nothing to sign.
    #[serde(default = "default_audit_checkpoint_interval_secs")]
    pub checkpoint_interval_secs: u64,
    /// Opt-in data-plane audit emission. When `false` (default) DataPlane-class
    /// records are not emitted; when `true` they are subject to fail-open
    /// admission (dropped if channel is near capacity rather than blocking).
    #[serde(default)]
    pub data_plane: bool,
    /// Capacity of the bounded MPSC channel between emitters and the writer task.
    /// Default 4096; raise for high-volume deployments with data-plane audit on.
    #[serde(default = "default_audit_channel_capacity")]
    pub channel_capacity: usize,
    /// Number of channel slots reserved exclusively for fail-closed record classes
    /// (Auth, KeyMgmt, System, Deny).  When available capacity drops to or below
    /// this reserve, DataPlane `emit` is rejected fail-open WITHOUT occupying a
    /// slot, guaranteeing room for security-critical records even under a
    /// data-plane flood (C1 finding).  Must be strictly less than `channel_capacity`.
    #[serde(default = "default_audit_fail_closed_reserve")]
    pub fail_closed_reserve: usize,
}

impl AuditConfig {
    /// Validate derived invariants.  Returns `Err` if the configuration is
    /// self-inconsistent; the message is human-readable for operator display.
    pub fn validate(&self) -> Result<(), String> {
        // W1-C2-05: zero rotation knobs are never valid — 0 keep disables
        // pruning (unbounded disk growth) and 0 max-bytes rotates on every
        // record (fsync+rename storm). Reject loudly at load, not silently.
        if self.rotate_max_bytes == 0 {
            return Err("audit.rotate_max_bytes must be > 0 \
                 (0 would rotate the audit log on every record)"
                .into());
        }
        if self.rotate_keep_files == 0 {
            return Err("audit.rotate_keep_files must be > 0 \
                 (0 disables pruning; audit logs would grow without bound)"
                .into());
        }
        if self.channel_capacity == 0 {
            return Err("audit.channel_capacity must be > 0 \
                 (tokio::sync::mpsc::channel(0) panics at startup)"
                .into());
        }
        if self.fail_closed_reserve >= self.channel_capacity {
            return Err(format!(
                "audit.fail_closed_reserve ({}) must be strictly less than \
                 audit.channel_capacity ({})",
                self.fail_closed_reserve, self.channel_capacity
            ));
        }
        Ok(())
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            dir: None,
            signing_key: None,
            rotate_max_bytes: default_audit_rotate_max_bytes(),
            rotate_keep_files: default_audit_rotate_keep_files(),
            checkpoint_interval_secs: default_audit_checkpoint_interval_secs(),
            data_plane: false,
            channel_capacity: default_audit_channel_capacity(),
            fail_closed_reserve: default_audit_fail_closed_reserve(),
        }
    }
}

fn default_audit_rotate_max_bytes() -> u64 {
    64 * 1024 * 1024
}

fn default_audit_rotate_keep_files() -> u32 {
    10
}

fn default_audit_checkpoint_interval_secs() -> u64 {
    300 // 5 minutes
}

fn default_audit_channel_capacity() -> usize {
    4096
}

fn default_audit_fail_closed_reserve() -> usize {
    256
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
    /// Explicit opt-in required to run a Unix listener with `auth = "none"`,
    /// which disables peer-credential authentication and lets every local user
    /// reach every token. Mirrors `allow_insecure_tcp`.
    #[serde(default)]
    pub allow_insecure_unix: bool,
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

/// Canonicalize a `[[auth.policy]]` identity for rules-map storage (W1-C3-06).
///
/// Runtime peer-cred keys render canonically (`uid=1000`), but TOML accepts
/// any `u32`-parseable spelling — `uid=01000`, `uid=+1000` — which would
/// then never match at runtime (a silently dead grant). Parsing and
/// re-rendering here makes every accepted uid identity matchable.
/// Non-uid identities pass through unchanged.
pub(crate) fn normalize_policy_identity(identity: &str) -> String {
    if let Some(uid) = identity.strip_prefix("uid=")
        && let Ok(n) = uid.parse::<u32>()
    {
        return format!("uid={n}");
    }
    identity.to_string()
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
            Self::Mtls => {
                "x509:spki=<hex-fingerprint> (new) or x509:issuer=<issuer-dn>;subject=<subject-dn> (legacy)"
            }
        }
    }

    fn can_produce(self, identity: &str) -> bool {
        match self {
            Self::PeerCred => {
                // W1-C3-06: judge the normalized form so every accepted
                // identity matches a runtime key (uid=01000 → uid=1000).
                normalize_policy_identity(identity)
                    .strip_prefix("uid=")
                    .is_some_and(|uid| uid.parse::<u32>().is_ok())
            }
            Self::Mtls => {
                // New SPKI-keyed form: x509:spki=<hash> (short) or x509:spki=<hash>;issuer=...;subject=... (enriched)
                let is_spki_form = identity
                    .strip_prefix("x509:spki=")
                    .is_some_and(|rest| !rest.split(';').next().unwrap_or("").is_empty());
                // Legacy DN form: x509:issuer=<esc_issuer>;subject=<esc_subject>
                let is_dn_form = identity
                    .strip_prefix("x509:issuer=")
                    .is_some_and(|rest| rest.contains(";subject="));
                is_spki_form || is_dn_form
            }
        }
    }
}

/// Refuse to use `path` if it is group-writable or other-writable.
///
/// A group/world-writable config file or backend module is a code-execution
/// surface reachable by unprivileged users — reject early so the operator
/// sees a clear message at startup rather than a silent privilege escalation.
///
/// Non-Unix platforms: always succeeds (permission bits are not meaningful).
pub(crate) fn check_not_group_or_world_writable(
    path: &std::path::Path,
    what: &str,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("refuse: cannot stat {what} '{}': {e}", path.display()))?;
        let mode = meta.mode();
        if mode & 0o022 != 0 {
            return Err(format!(
                "refuse: {what} '{}' is group/world-writable (mode {:04o}); \
                 a writable code-execution surface. chmod go-w {}",
                path.display(),
                mode & 0o7777,
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, what);
    }
    Ok(())
}

impl DaemonConfig {
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config '{}': {e}", path.display()))?;
        let mut config: Self = toml::from_str(&content)
            .map_err(|e| format!("Failed to parse config '{}': {e}", path.display()))?;
        config.apply_env_overrides()?;
        // Security: refuse to start if config file or backend module is group/world-writable
        // — a writable code-execution surface reachable by unprivileged users.
        check_not_group_or_world_writable(path, "config file")?;
        if config.backend.module.as_os_str() != BACKEND_MODULE_PLACEHOLDER
            && config.backend.module != std::path::Path::new("/dev/null")
        {
            check_not_group_or_world_writable(&config.backend.module, "backend module")?;
        }
        config.validate()?;
        Ok(config)
    }

    /// Apply documented env-var overrides on top of the TOML-parsed config.
    /// Precedence: env > TOML > default. The set is intentionally small —
    /// the daemon's primary config surface is the TOML file (mounted via
    /// k8s ConfigMap in production). Env vars are reserved for the
    /// highest-traffic operational tweaks (`PKCS11_PROXY_BIND` for
    /// per-replica port tuning, `PKCS11_PROXY_BACKEND_MODULE` for swapping
    /// HSM .sos without rewriting the ConfigMap, etc.).
    ///
    /// Documented env vars:
    /// - `PKCS11_PROXY_BIND`                          → `listener.remote.bind`
    /// - `PKCS11_PROXY_BACKEND_MODULE`                → `backend.module`
    /// - `PKCS11_PROXY_BACKEND_ARGS`                  → `backend.initialize_args`
    /// - `PKCS11_PROXY_MECHANISMS_CONFIG`             → `mechanisms.config_path`
    /// - `PKCS11_PROXY_ALLOW_INSECURE`                → `listener.remote.allow_insecure_tcp`
    /// - `PKCS11_PROXY_RESILIENCE_METRICS_SOCKET`     → `resilience.metrics_socket`
    /// - `PKCS11_PROXY_RESILIENCE_FIND_THRESHOLD`     → `resilience.find_result_warn_threshold`
    /// - `PKCS11_PROXY_TEST_HOOKS_CONTROL_SOCKET`     → `test_hooks.control_socket`
    pub fn apply_env_overrides(&mut self) -> Result<(), String> {
        self.apply_env_overrides_with(|key| std::env::var(key).ok())
    }

    /// Same as [`DaemonConfig::apply_env_overrides`] but reads from `get`
    /// instead of the process environment, so tests can exercise the override
    /// logic hermetically without `set_var` (which would race parallel tests
    /// in the same binary that call `load()`).
    fn apply_env_overrides_with(
        &mut self,
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<(), String> {
        // Keep this list in sync with env_var_help() below — both surface the
        // same canonical env-var → TOML-field mapping.
        if let Some(v) = get("PKCS11_PROXY_BACKEND_MODULE") {
            self.backend.module = std::path::PathBuf::from(v);
        }
        if let Some(v) = get("PKCS11_PROXY_BACKEND_ARGS") {
            self.backend.initialize_args = Some(v);
        }
        if let Some(v) = get("PKCS11_PROXY_MECHANISMS_CONFIG") {
            self.mechanisms.config_path = Some(std::path::PathBuf::from(v));
        }
        if let Some(v) = get("PKCS11_PROXY_BIND") {
            // Bind override applies to whichever TCP listener is already
            // configured; if there's no [listener.remote] block, the env var
            // creates an unauthenticated TCP listener — but only when
            // PKCS11_PROXY_ALLOW_INSECURE is explicitly set; otherwise
            // validate() rejects it, so a single env var can never silently
            // provision an open listener. Tighter listener semantics (auth,
            // TLS) still have to come from the TOML.
            match self.listener.remote.as_mut() {
                Some(tcp) => {
                    tcp.bind = v;
                    // W1-L8-01: honor the documented PKCS11_PROXY_ALLOW_INSECURE
                    // override here too (env > TOML). Unset => the TOML value
                    // is kept, so this can never silently enable an insecure
                    // listener. Parse matches the `None` branch below.
                    if let Some(val) = get("PKCS11_PROXY_ALLOW_INSECURE") {
                        tcp.allow_insecure_tcp = val == "1" || val.eq_ignore_ascii_case("true");
                    }
                }
                None => {
                    let allow_insecure_tcp = get("PKCS11_PROXY_ALLOW_INSECURE")
                        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
                        .unwrap_or(false);
                    self.listener.remote = Some(TcpListenerConfig {
                        bind: v,
                        auth: TcpAuthMode::None,
                        ca_cert: None,
                        server_cert: None,
                        server_key: None,
                        allow_insecure_tcp,
                    });
                }
            }
        }
        if let Some(v) = get("PKCS11_PROXY_RESILIENCE_METRICS_SOCKET") {
            self.resilience.metrics_socket = Some(std::path::PathBuf::from(v));
        }
        if let Some(v) = get("PKCS11_PROXY_RESILIENCE_FIND_THRESHOLD") {
            // W1-C3-08: error loudly on unparseable values instead of
            // silently keeping the TOML value (the operator would believe
            // the override applied).
            match v.parse::<usize>() {
                Ok(n) => self.resilience.find_result_warn_threshold = Some(n),
                Err(_) => {
                    return Err(format!(
                        "PKCS11_PROXY_RESILIENCE_FIND_THRESHOLD='{v}' is not a valid \
                         non-negative integer for resilience.find_result_warn_threshold"
                    ));
                }
            }
        }
        if let Some(v) = get("PKCS11_PROXY_TEST_HOOKS_CONTROL_SOCKET") {
            self.test_hooks.control_socket = Some(std::path::PathBuf::from(v));
        }
        Ok(())
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
        // Validate max_stuck_backend_calls (opt-in; 0 would exit immediately
        // on the first stuck call, which is never the intent — unset it to
        // disable instead).
        if self.proxy.max_stuck_backend_calls == Some(0) {
            return Err(
                "proxy.max_stuck_backend_calls must be > 0 (omit it to disable self-exit)".into()
            );
        }
        // Validate max_blocking_threads
        if self.proxy.max_blocking_threads == 0 {
            return Err("proxy.max_blocking_threads must be > 0".into());
        }
        // Validate rate_limit fields: Some(0) would silently block every request
        // because the cap is set but set to zero. The correct way to disable a limit
        // is to omit the field (None). Reject Some(0) loudly at startup.
        if self.rate_limit.per_principal_max_in_flight == Some(0) {
            return Err("rate_limit.per_principal_max_in_flight must be > 0; \
                 omit the field to disable the limit (0 would block all requests)"
                .into());
        }
        if self.rate_limit.per_principal_max_sessions == Some(0) {
            return Err("rate_limit.per_principal_max_sessions must be > 0; \
                 omit the field to disable the limit (0 would block all requests)"
                .into());
        }
        if self.rate_limit.per_slot_failed_login_budget == Some(0) {
            return Err("rate_limit.per_slot_failed_login_budget must be > 0; \
                 omit the field to disable the limit (0 would block all requests)"
                .into());
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
        // Refuse to start if backend.module is still the shipped
        // placeholder — fail loud at startup rather than at first call.
        if self.backend.module.as_os_str() == BACKEND_MODULE_PLACEHOLDER {
            return Err(format!(
                "backend.module is still the shipped placeholder ({BACKEND_MODULE_PLACEHOLDER}). \
                 Edit /etc/pkcs11-proxy-ng/proxy.toml or set the PKCS11_PROXY_BACKEND_MODULE \
                 env var to point at a real PKCS#11 .so before starting the daemon."
            ));
        }
        // Validate backend module path exists
        if !self.backend.module.exists() {
            return Err(format!(
                "backend.module path does not exist: {}",
                self.backend.module.display()
            ));
        }
        // Validate lifecycle/health knobs
        if self.proxy.startup_timeout_secs == 0 {
            return Err("proxy.startup_timeout_secs must be > 0".into());
        }
        if self.proxy.shutdown_grace_secs == 0 {
            return Err("proxy.shutdown_grace_secs must be > 0 (set to 1 if you really want \
                 effectively-immediate shutdown)"
                .into());
        }
        if self.proxy.backend_health_consecutive_failures == 0 {
            return Err("proxy.backend_health_consecutive_failures must be > 0 \
                 (the readiness gate cannot trip on zero failures)"
                .into());
        }
        // Validate the mechanism-registry config path if set.
        if let Some(path) = &self.mechanisms.config_path
            && !path.exists()
        {
            return Err(format!(
                "mechanisms.config_path points at a missing file: {}",
                path.display()
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
            // W1-C3-13: validate the bind as a real SocketAddr. A mere
            // contains(':') check lets "localhost:50051" pass here only to
            // die later in main.rs's `parse::<SocketAddr>()` with a confusing
            // error. Hostnames are rejected (use an IP:port); the daemon does
            // not resolve DNS for its listen address.
            if let Err(e) = tcp.bind.parse::<std::net::SocketAddr>() {
                return Err(format!(
                    "listener.remote.bind must be an IP:port SocketAddr in host:port format \
                     (hostnames are not resolved), got '{}': {e}",
                    tcp.bind
                ));
            }
        }
        if let Some(ref local) = self.listener.local
            && matches!(local.auth, UnixAuthMode::None)
            && !local.allow_insecure_unix
        {
            return Err("Unix listener with auth='none' requires allow_insecure_unix=true".into());
        }
        // Warn (via error) if no listeners are configured
        if self.listener.local.is_none() && self.listener.remote.is_none() {
            return Err(
                "No listeners configured. Set [listener.local] and/or [listener.remote].".into()
            );
        }
        let has_unauthenticated_listener =
            self.listener.local.as_ref().is_some_and(|l| !l.auth.is_authenticated())
                || self.listener.remote.as_ref().is_some_and(|r| !r.auth.is_authenticated());
        // M3: a per-object `objects` grant on an auth="none" listener is silently
        // inert — `allows_object_use` returns true for Unauthenticated, so the
        // per-object restriction is bypassed entirely. Refuse to start to prevent
        // false security.
        //
        // W1-C3-04: this check MUST precede the generic policy+auth=none reject
        // below: every M3 combo also satisfies that guard, so placing this
        // after it would shadow the M3 error forever. Order is load-bearing;
        // do not move this below the generic reject. All current rejects are
        // preserved: M3 combos now hit this specific error, everything else
        // falls through to the generic one.
        if has_unauthenticated_listener {
            for (index, entry) in self.auth.policy.iter().enumerate() {
                if let TokenAccessSpec::Specific(ref grants) = entry.tokens {
                    for grant in grants {
                        if let GrantSpec::Rich(rich) = grant
                            && rich.objects.is_some()
                        {
                            return Err(format!(
                                "auth.policy[{index}]: per-object `objects` grant with an \
                                 auth=\"none\" listener is silently inert — unauthenticated \
                                 peers bypass per-object authz (allows_object_use returns \
                                 true for Unauthenticated). Use an authenticated listener \
                                 (peer_cred / mtls) or remove the `objects` restriction."
                            ));
                        }
                    }
                }
            }
        }
        // An authorization policy cannot apply to an unauthenticated peer: refuse
        // to start if any listener uses auth = "none" while [auth.policy] is set.
        if !self.auth.policy.is_empty() && has_unauthenticated_listener {
            return Err("[auth.policy] is set but a listener uses auth = \"none\"; an \
                 authorization policy cannot apply to unauthenticated peers. Use an \
                 authenticated listener (peer_cred / mtls) or remove the policy."
                .into());
        }
        if self.auth.allow_all_authenticated && has_unauthenticated_listener {
            return Err("allow_all_authenticated = true with an auth=\"none\" listener grants \
                 every unauthenticated peer full token access. Use an authenticated listener \
                 or disable allow_all_authenticated."
                .into());
        }
        // H2 guard: audit + unauthenticated listener is normally refused because
        // every operation would be recorded as identity=None (false compliance).
        // EXCEPTION: when anonymous_principal is set the operator has explicitly
        // named the audit identity for unauthenticated peers, so the concern is
        // addressed and we allow the combination.
        if self.audit.dir.is_some()
            && has_unauthenticated_listener
            && self.auth.anonymous_principal.is_none()
        {
            return Err("[audit] is enabled with an auth=\"none\" listener; every operation \
                 would be recorded as identity=None, giving false compliance assurance. \
                 Use an authenticated listener, or set auth.anonymous_principal to name \
                 the audit identity for unauthenticated peers."
                .into());
        }
        // anonymous_principal must not also appear as a policy grant key — it is
        // audit-identity only, never an authz grant.
        if let Some(ref anon) = self.auth.anonymous_principal
            && self.auth.policy.iter().any(|e| &e.identity == anon)
        {
            return Err(format!(
                "auth.anonymous_principal '{anon}' also appears as an [auth.policy] \
                 entry identity; anonymous_principal is audit-only and must not be \
                 used as a policy grant key"
            ));
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
        // NOTE: per-mechanism (`mechanisms`) enforcement is now wired (G3 Task 3)
        // and the startup refuse-to-start guard has been removed. Mechanism grants
        // are fully enforced at every crypto-init RPC (encrypt_init, sign_init,
        // generate_key, wrap_key, etc.) via `mechanism_permitted` in
        // `grpc_service/authorization.rs`.
        self.validate_policy_identities()?;
        crate::server::auth::policy::TokenPolicy::from_config(&self.auth)?;
        self.audit.validate()?;
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
                 listener.remote.auth = 'mtls' for x509:spki=<fingerprint> or \
                 x509:issuer=<issuer-dn>;subject=<subject-dn> identities"
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
