use pkcs11_proxy_ng_proto::{MechanismRegistryPayload, Pkcs11ProxyClient as GrpcClient};
use pkcs11_proxy_ng_types::*;
use tonic::transport::Channel;

use super::deadline::{DEFAULT_RPC_TIMEOUT, RpcDeadline};
use super::{ConnectionSource, Pkcs11Client};
use crate::error::{RpcKind, grpc_status_to_ck_rv_kind};

/// Per-call message size cap (64 MiB), matching the server's
/// `proxy.max_message_bytes` ceiling defined in `crates/server/src/config.rs`.
///
/// Tonic's default decode limit is 4 MiB, so without this an operator
/// who raises the server's `max_message_bytes` (e.g. for large
/// `C_Decrypt` plaintexts or wrapped-key blobs) would silently get a
/// `CKR_GENERAL_ERROR` on the client side from the decode-too-large
/// status. Keep the client cap aligned with the server's cap so large
/// payloads succeed end-to-end and oversized payloads fail at the
/// server (where the operator can configure the bound) rather than
/// invisibly at the client.
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

fn new_grpc_client(
    channel: Channel,
    rpc_timeout: std::time::Duration,
) -> GrpcClient<RpcDeadline<Channel>> {
    GrpcClient::new(RpcDeadline::new(channel, rpc_timeout))
        .max_decoding_message_size(MAX_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_MESSAGE_BYTES)
}

/// Dial-time transport timeouts (W1-C10-12 operator knobs): the dial
/// timeout, the HTTP/2 keepalive pair, and the mTLS handshake timeout.
/// Applied by one shared helper, so the TCP and Unix-socket constructors
/// cannot desync. Defaults preserve the previously hardcoded values
/// (dial 5 s, keepalive 10 s / 5 s, handshake 10 s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectTimeouts {
    /// Dial timeout for establishing the transport connection.
    pub connect: std::time::Duration,
    /// HTTP/2 keepalive ping interval on idle connections.
    pub http2_keep_alive_interval: std::time::Duration,
    /// HTTP/2 keepalive ping acknowledgement timeout.
    pub keep_alive_timeout: std::time::Duration,
    /// mTLS handshake timeout (TCP+TLS endpoints only).
    pub tls_handshake: std::time::Duration,
}

impl Default for ConnectTimeouts {
    fn default() -> Self {
        Self {
            connect: std::time::Duration::from_secs(5),
            http2_keep_alive_interval: std::time::Duration::from_secs(10),
            keep_alive_timeout: std::time::Duration::from_secs(5),
            tls_handshake: crate::tls::DEFAULT_TLS_HANDSHAKE_TIMEOUT,
        }
    }
}

/// Apply dial-time timeouts to a tonic endpoint (W1-C10-12): the single
/// definition shared by the TCP and Unix-socket constructors.
fn apply_connect_timeouts(
    builder: tonic::transport::Endpoint,
    timeouts: &ConnectTimeouts,
) -> tonic::transport::Endpoint {
    builder
        .connect_timeout(timeouts.connect)
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(timeouts.http2_keep_alive_interval)
        .keep_alive_timeout(timeouts.keep_alive_timeout)
}

/// One backend interface version from a `get_backend_interfaces` probe:
/// the PKCS#11 version plus the function names that are NULL in the
/// backend's function list for that version. Field names mirror the
/// backend-side `InterfaceInfo` sibling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendInterface {
    pub version_major: u8,
    pub version_minor: u8,
    pub null_functions: Vec<String>,
}

/// Result of a `get_backend_interfaces` probe — the backend's interface
/// capabilities plus the server's mechanism registry payload (absent on
/// older daemons predating the field).
#[derive(Debug, Clone)]
pub struct BackendProbe {
    pub exact_output_effects_version: Option<u32>,
    pub interfaces: Vec<BackendInterface>,
    pub mechanism_registry: Option<MechanismRegistryPayload>,
    /// Backend `sizeof(CK_ULONG)` in bytes (4 or 8), advertised for the width
    /// bridge (ADR-0011 D2). `None` against an older daemon that predates the
    /// field — the caller falls back to 8 with a warning (D9).
    pub backend_ulong_size: Option<u32>,
    /// Backend `CK_ULONG` byte order (1 = little, 2 = big; ADR-0011 D6).
    /// `None` against an older daemon.
    pub backend_byte_order: Option<u32>,
    /// The backend's native sizeof(CK_ATTRIBUTE) (D2 extension), if advertised.
    pub backend_attribute_stride: Option<u32>,
    /// True only when the daemon supports shape-bound message parameters.
    /// Older daemons omit the field and are therefore unsafe.
    pub pointer_safe_message_parameters: bool,
    pub pointer_safe_authenticated_parameters: bool,
}

fn pointer_safe_message_parameters_from_wire(advertised: Option<bool>) -> bool {
    advertised.unwrap_or(false)
}

/// Validate the daemon's init version range (W1-L5-05): overlap negotiates
/// (returns the agreed version), disjoint ranges fail loudly with
/// FUNCTION_NOT_SUPPORTED before any context is stored. `None` bounds mean
/// a legacy daemon, treated as v1-only.
fn negotiate_init_version(daemon_min: Option<u32>, daemon_max: Option<u32>) -> CkResult<u32> {
    pkcs11_proxy_ng_proto::version::negotiate_effects_version(
        pkcs11_proxy_ng_proto::version::EXACT_OUTPUT_EFFECTS_VERSION_MIN,
        pkcs11_proxy_ng_proto::version::EXACT_OUTPUT_EFFECTS_VERSION_MAX,
        daemon_min,
        daemon_max,
    )
    .ok_or(CkRv::FUNCTION_NOT_SUPPORTED)
}

/// Typed `connect` / `get_backend_interfaces` failure (W1-C10-07):
/// callers can distinguish retryable transport failures from
/// configuration/permanent ones instead of parsing a `String`.
///
/// `Display` preserves the pre-existing messages verbatim so log output
/// and `%e`/`{e}` call sites are unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// Retryable: dial refused/timed out, transport reset, or a retryable
    /// gRPC status from the interfaces probe.
    Transient(String),
    /// Config or permanent: malformed endpoint, TLS misconfiguration,
    /// unsupported platform, or a non-retryable probe status.
    Permanent(String),
}

impl ConnectError {
    pub fn transient(message: impl Into<String>) -> Self {
        Self::Transient(message.into())
    }

    pub fn permanent(message: impl Into<String>) -> Self {
        Self::Permanent(message.into())
    }

    /// True for failures worth retrying (with backoff).
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transient(_))
    }

    /// True for failures that will not clear on retry (fix the config).
    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent(_))
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Transient(message) | Self::Permanent(message) => message,
        }
    }

    /// Classify a `GetBackendInterfaces` probe failure: the classic
    /// retryable gRPC codes are transient, everything else permanent.
    pub(crate) fn from_probe_status(status: &tonic::Status) -> Self {
        let message = format!("GetBackendInterfaces failed: {status}");
        match status.code() {
            tonic::Code::Cancelled
            | tonic::Code::DeadlineExceeded
            | tonic::Code::Aborted
            | tonic::Code::Unavailable
            | tonic::Code::ResourceExhausted => Self::transient(message),
            _ => Self::permanent(message),
        }
    }
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for ConnectError {}

// `String` compat so `?` keeps working in `Result<_, String>` helpers
// (e.g. test harnesses); the message is the preserved `Display` text.
impl From<ConnectError> for String {
    fn from(error: ConnectError) -> Self {
        error.to_string()
    }
}

async fn connect_channel(
    endpoint: &str,
    tls_files: Option<crate::tls::ClientTlsFiles>,
    timeouts: &ConnectTimeouts,
) -> Result<Channel, ConnectError> {
    // Unix-domain-socket endpoint (`unix:/abs/path` or `unix:///abs/path`):
    // dial the local socket. No TLS — a Unix socket carries no network to
    // secure; the daemon authenticates the peer via SO_PEERCRED. Intended for
    // local-user / ssh-forwarded use. Windows has no UDS peer-cred path, so a
    // Windows client is tcp/mTLS-only (ADR-0011 Bucket 3, client side).
    if let Some(path) = endpoint.strip_prefix("unix:") {
        #[cfg(unix)]
        {
            if tls_files.is_some() {
                tracing::debug!(
                    "TLS configuration ignored for unix-socket endpoint (peer-cred auth)"
                );
            }
            return connect_unix_channel(path, timeouts).await;
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(ConnectError::permanent(
                "unix-domain-socket endpoints are not supported on this platform; \
                        use a tcp/mTLS endpoint such as https://host:port",
            ));
        }
    }

    let mut builder = tonic::transport::Endpoint::from_shared(endpoint.to_owned())
        .map_err(|e| ConnectError::permanent(format!("invalid endpoint: {e}")))?;
    if let Some(tls_files) = tls_files {
        let tls_config = tls_files
            .into_tonic_config_with_handshake_timeout(timeouts.tls_handshake)
            .map_err(ConnectError::permanent)?;
        builder = builder
            .tls_config(tls_config)
            .map_err(|e| ConnectError::permanent(format!("invalid TLS config: {e}")))?;
    }

    apply_connect_timeouts(builder, timeouts)
        .connect()
        .await
        .map_err(|e| ConnectError::transient(format!("gRPC connect failed: {e}")))
}

/// Connect a gRPC channel over a Unix-domain socket at `raw_path`.
#[cfg(unix)]
async fn connect_unix_channel(
    raw_path: &str,
    timeouts: &ConnectTimeouts,
) -> Result<Channel, ConnectError> {
    // Tolerate the authority form `unix://<path>` by dropping a leading "//".
    let path = raw_path.strip_prefix("//").unwrap_or(raw_path).to_owned();
    if path.is_empty() {
        return Err(ConnectError::permanent("unix endpoint has an empty socket path"));
    }

    // The HTTP/2 `:authority` is unused for a UDS connector, but tonic still
    // needs a syntactically valid Endpoint to carry the connection settings.
    let endpoint = tonic::transport::Endpoint::try_from("http://pkcs11-proxy-ng.local")
        .map_err(|e| ConnectError::permanent(format!("invalid unix endpoint base: {e}")))?;
    apply_connect_timeouts(endpoint, timeouts)
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let path = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(&path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .map_err(|e| ConnectError::transient(format!("unix gRPC connect failed: {e}")))
}

impl Pkcs11Client {
    /// Connect to the proxy daemon at `endpoint` (e.g. `"http://127.0.0.1:50051"`).
    pub async fn connect(endpoint: &str) -> Result<Self, ConnectError> {
        let timeouts = ConnectTimeouts::default();
        let channel = connect_channel(endpoint, None, &timeouts).await?;
        let grpc = new_grpc_client(channel.clone(), DEFAULT_RPC_TIMEOUT);
        Ok(Self {
            exact_effects_version: Default::default(),
            typed_auth_capability: Default::default(),
            grpc,
            channel,
            context_id: None,
            source: ConnectionSource::Endpoint { endpoint: endpoint.to_owned(), tls_files: None },
            rpc_timeout: DEFAULT_RPC_TIMEOUT,
            connect_timeouts: timeouts,
        })
    }

    /// Connect to the proxy daemon using mTLS credentials from files.
    pub async fn connect_with_tls_files(
        endpoint: &str,
        tls_files: crate::tls::ClientTlsFiles,
    ) -> Result<Self, ConnectError> {
        let timeouts = ConnectTimeouts::default();
        let channel = connect_channel(endpoint, Some(tls_files.clone()), &timeouts).await?;
        let grpc = new_grpc_client(channel.clone(), DEFAULT_RPC_TIMEOUT);
        Ok(Self {
            exact_effects_version: Default::default(),
            typed_auth_capability: Default::default(),
            grpc,
            channel,
            context_id: None,
            source: ConnectionSource::Endpoint {
                endpoint: endpoint.to_owned(),
                tls_files: Some(tls_files),
            },
            rpc_timeout: DEFAULT_RPC_TIMEOUT,
            connect_timeouts: timeouts,
        })
    }

    /// Build a client from an already-established channel (e.g. for tests or
    /// channel sharing). Reconnection will not be available.
    pub fn from_channel(channel: tonic::transport::Channel) -> Self {
        Self {
            exact_effects_version: Default::default(),
            typed_auth_capability: Default::default(),
            grpc: new_grpc_client(channel.clone(), DEFAULT_RPC_TIMEOUT),
            channel,
            context_id: None,
            source: ConnectionSource::SharedChannel,
            rpc_timeout: DEFAULT_RPC_TIMEOUT,
            connect_timeouts: ConnectTimeouts::default(),
        }
    }

    /// The per-RPC deadline currently enforced on every call
    /// ([`DEFAULT_RPC_TIMEOUT`] unless changed).
    pub fn rpc_timeout(&self) -> std::time::Duration {
        self.rpc_timeout
    }

    /// Replace the per-RPC deadline, effective immediately on the live
    /// channel (the gRPC client is rebuilt around the same connection, so
    /// in-flight HTTP/2 streams are preserved) and preserved across
    /// [`reconnect`][Self::reconnect].
    pub fn set_rpc_timeout(&mut self, timeout: std::time::Duration) {
        self.grpc = new_grpc_client(self.channel.clone(), timeout);
        self.rpc_timeout = timeout;
    }

    /// Builder form of [`set_rpc_timeout`][Self::set_rpc_timeout].
    pub fn with_rpc_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.set_rpc_timeout(timeout);
        self
    }

    /// The dial-time transport timeouts ([`ConnectTimeouts::default`]
    /// unless changed).
    pub fn connect_timeouts(&self) -> ConnectTimeouts {
        self.connect_timeouts
    }

    /// Replace the dial-time transport timeouts, effective on the next
    /// dial — i.e. the next [`reconnect`][Self::reconnect], since the live
    /// channel's endpoint settings were fixed when it was established.
    /// Unlike [`set_rpc_timeout`][Self::set_rpc_timeout] this never touches
    /// the live connection (re-dialing would drop in-flight calls).
    pub fn set_connect_timeouts(&mut self, timeouts: ConnectTimeouts) {
        self.connect_timeouts = timeouts;
    }

    /// Builder form of [`set_connect_timeouts`][Self::set_connect_timeouts].
    pub fn with_connect_timeouts(mut self, timeouts: ConnectTimeouts) -> Self {
        self.set_connect_timeouts(timeouts);
        self
    }

    /// Call `C_Initialize` on the proxy. Stores the returned `context_id` for
    /// use in all subsequent requests.
    ///
    /// Transport errors are mapped via `RpcKind::Lifecycle` because
    /// `C_Initialize` has a stricter spec-permitted CK_RV set than the
    /// session-scoped RPCs (PKCS#11 v3.0 §5.4): `CKR_TOKEN_NOT_PRESENT`
    /// is NOT in that set, so a daemon-unreachable failure surfaces as
    /// `CKR_GENERAL_ERROR` instead.
    pub async fn initialize(&mut self) -> CkResult<()> {
        // W1-L5-05: advertise our effects range; the daemon negotiates the
        // highest mutual version and rejects disjoint ranges loudly.
        let req = pkcs11_proxy_ng_proto::InitializeRequest {
            client_context_id: String::new(),
            client_effects_version_min: Some(
                pkcs11_proxy_ng_proto::version::EXACT_OUTPUT_EFFECTS_VERSION_MIN,
            ),
            client_effects_version_max: Some(
                pkcs11_proxy_ng_proto::version::EXACT_OUTPUT_EFFECTS_VERSION_MAX,
            ),
        };
        let response = self
            .grpc
            .initialize(req)
            .await
            .map_err(|status| grpc_status_to_ck_rv_kind(status.code(), RpcKind::Lifecycle))?
            .into_inner();
        let rv = CkRv(response.ck_rv);
        if rv.is_err() {
            return Err(rv);
        }
        // W1-L5-05: validate the daemon's range before storing the context —
        // a disjoint range fails loudly here, never per-RPC later.
        // T29 M2: the agreed version is deliberately discarded — correct
        // while v1 is the only version; the bump procedure in
        // `pkcs11_proxy_ng_proto::version` names this site for plumbing on
        // the first real bump.
        let _negotiated = negotiate_init_version(
            response.daemon_effects_version_min,
            response.daemon_effects_version_max,
        )?;
        self.context_id = Some(response.client_context_id);
        Ok(())
    }

    /// Call `C_Finalize` on the proxy. Clears the stored `context_id`.
    ///
    /// Like `initialize`, uses `RpcKind::Lifecycle` for transport-error
    /// mapping per PKCS#11 v3.0 §5.5.
    pub async fn finalize(&mut self) -> CkResult<()> {
        let ctx = self.context_id()?;
        let req = pkcs11_proxy_ng_proto::FinalizeRequest { client_context_id: ctx };
        let response = self
            .grpc
            .finalize(req)
            .await
            .map_err(|status| grpc_status_to_ck_rv_kind(status.code(), RpcKind::Lifecycle))?
            .into_inner();
        let rv = CkRv(response.ck_rv);
        if rv.is_err() {
            return Err(rv);
        }
        self.context_id = None;
        Ok(())
    }

    /// Record a fresh `GetBackendInterfaces` probe (W1-C10-03): the
    /// effects version and the typed-auth capability are always refreshed
    /// together from the same probe, so a version change can never leave a
    /// stale capability behind.
    pub(crate) fn note_backend_probe(&self, effects_version: u32, auth_capable: bool) {
        self.exact_effects_version.store(effects_version, std::sync::atomic::Ordering::Release);
        self.note_typed_auth_capability(auth_capable);
    }

    /// Query the daemon for the backend's interface capabilities. Also
    /// pulls the server-published mechanism registry payload when the
    /// daemon includes it (older daemons predate the field and the
    /// caller must fall back to its embedded default).
    ///
    /// Context-free (no `C_Initialize` required); safe to call before
    /// `initialize()`.
    pub async fn get_backend_interfaces(&mut self) -> Result<BackendProbe, ConnectError> {
        let req = pkcs11_proxy_ng_proto::GetBackendInterfacesRequest {};
        let resp = self
            .grpc
            .get_backend_interfaces(req)
            .await
            .map_err(|status| ConnectError::from_probe_status(&status))?
            .into_inner();

        let probe = BackendProbe {
            exact_output_effects_version: resp.exact_output_effects_version,
            pointer_safe_authenticated_parameters: resp.pointer_safe_authenticated_parameters
                == Some(true),
            interfaces: resp
                .interfaces
                .into_iter()
                .map(|info| BackendInterface {
                    version_major: info.version_major as u8,
                    version_minor: info.version_minor as u8,
                    null_functions: info.null_functions,
                })
                .collect(),
            mechanism_registry: resp.mechanism_registry,
            backend_ulong_size: resp.backend_ulong_size,
            backend_byte_order: resp.backend_byte_order,
            backend_attribute_stride: resp.backend_attribute_stride,
            pointer_safe_message_parameters: pointer_safe_message_parameters_from_wire(
                resp.pointer_safe_message_parameters,
            ),
        };
        self.note_backend_probe(
            probe.exact_output_effects_version.unwrap_or(0),
            probe.pointer_safe_authenticated_parameters,
        );
        Ok(probe)
    }

    /// Re-dial the endpoint (if it was created via `connect`) and
    /// revalidate the logical context by probing with the pre-reconnect
    /// `context_id`.
    ///
    /// When the daemon rejects the probe as a stale context
    /// (`CKR_CRYPTOKI_NOT_INITIALIZED` — e.g. after a daemon restart the
    /// old id is unknown server-side), re-initialize with a fresh context
    /// (W1-C10-02) instead of failing the reconnect. A probe that succeeds
    /// keeps the old id (transport-only failure with the server context
    /// intact, preserving W1-L6-29 session continuity). Any other probe
    /// failure propagates without re-init — a fresh context would fail the
    /// same way, so re-initializing would only mask the real error.
    pub async fn reconnect(&mut self) -> CkResult<()> {
        match &self.source {
            ConnectionSource::Endpoint { endpoint, tls_files } => {
                let channel = connect_channel(endpoint, tls_files.clone(), &self.connect_timeouts)
                    .await
                    .map_err(|_| CkRv::DEVICE_ERROR)?;
                self.grpc = new_grpc_client(channel.clone(), self.rpc_timeout);
                self.channel = channel;
                self.exact_effects_version = Default::default();
                self.invalidate_typed_auth_capability();
                if let Some(ref ctx) = self.context_id {
                    let req = pkcs11_proxy_ng_proto::GetSlotListRequest {
                        client_context_id: ctx.clone(),
                        token_present: false,
                    };
                    // Call the unary prologue directly (not via
                    // `pkcs11_unary_ok!`, whose `?` would propagate past this
                    // match): only a stale-context rejection triggers a
                    // fresh `initialize()`; any other outcome is returned
                    // as-is.
                    let probe =
                        super::unary_prologue(self.grpc.get_slot_list(req), false, |response| {
                            response.ck_rv
                        })
                        .await;
                    match probe {
                        Ok(_) => {}
                        Err(rv) if rv == CkRv::CRYPTOKI_NOT_INITIALIZED => {
                            self.initialize().await?;
                        }
                        Err(other) => return Err(other),
                    }
                }
                Ok(())
            }
            ConnectionSource::SharedChannel => Err(CkRv::GENERAL_ERROR),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_RPC_TIMEOUT, Pkcs11Client, pointer_safe_message_parameters_from_wire};

    // W1-C10-01: the default deadline is pinned (60s: bounds a wedged
    // daemon without tripping slow-but-healthy HSM operations) and every
    // constructor carries it; set/with round-trip through the getter.
    #[test]
    fn default_rpc_timeout_is_sixty_seconds() {
        assert_eq!(DEFAULT_RPC_TIMEOUT, std::time::Duration::from_secs(60));
    }

    #[tokio::test]
    async fn rpc_timeout_defaults_and_round_trips() {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        let mut client = Pkcs11Client::from_channel(channel);
        assert_eq!(client.rpc_timeout(), DEFAULT_RPC_TIMEOUT);
        client.set_rpc_timeout(std::time::Duration::from_millis(100));
        assert_eq!(client.rpc_timeout(), std::time::Duration::from_millis(100));
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        let client =
            Pkcs11Client::from_channel(channel).with_rpc_timeout(std::time::Duration::from_secs(7));
        assert_eq!(client.rpc_timeout(), std::time::Duration::from_secs(7));
    }

    // W1-C10-07: connect/TLS/interfaces failures are typed —
    // transient (retryable) vs permanent (config), with the pre-existing
    // messages preserved verbatim in `Display`.
    #[test]
    fn connect_error_classifies_probe_statuses() {
        use super::ConnectError;
        for code in [
            tonic::Code::Cancelled,
            tonic::Code::DeadlineExceeded,
            tonic::Code::Aborted,
            tonic::Code::Unavailable,
            tonic::Code::ResourceExhausted,
        ] {
            let err = ConnectError::from_probe_status(&tonic::Status::new(code, "probe down"));
            assert!(err.is_transient(), "{code:?} must be transient");
            assert!(!err.is_permanent());
            assert!(err.to_string().starts_with("GetBackendInterfaces failed: "), "{err}");
            assert!(err.to_string().contains("probe down"), "{err}");
        }
        for code in [
            tonic::Code::InvalidArgument,
            tonic::Code::NotFound,
            tonic::Code::PermissionDenied,
            tonic::Code::Unauthenticated,
            tonic::Code::Unimplemented,
            tonic::Code::Internal,
        ] {
            let err = ConnectError::from_probe_status(&tonic::Status::new(code, "bad probe"));
            assert!(err.is_permanent(), "{code:?} must be permanent");
            assert!(!err.is_transient());
        }
    }

    #[tokio::test]
    async fn refused_dial_is_a_transient_connect_error() {
        let err = Pkcs11Client::connect("http://127.0.0.1:9").await.unwrap_err();
        assert!(err.is_transient());
        assert!(err.to_string().starts_with("gRPC connect failed: "), "{err}");
    }

    #[tokio::test]
    async fn unparseable_endpoint_is_a_permanent_connect_error() {
        let err = Pkcs11Client::connect("http://exa mple.com:1").await.unwrap_err();
        assert!(err.is_permanent());
        assert!(err.to_string().starts_with("invalid endpoint: "), "{err}");
    }

    #[tokio::test]
    async fn empty_unix_path_is_a_permanent_connect_error() {
        // Empty socket path (unix) / unsupported platform (non-unix) are
        // both permanent config failures, so this holds on every target.
        let err = Pkcs11Client::connect("unix:").await.unwrap_err();
        assert!(err.is_permanent());
        assert!(!err.is_transient());
    }

    #[tokio::test]
    async fn missing_tls_files_are_a_permanent_connect_error() {
        let tls_files = crate::tls::ClientTlsFiles {
            ca_cert: "/nonexistent/ca.pem".into(),
            client_cert: "/nonexistent/client.pem".into(),
            client_key: "/nonexistent/client-key.pem".into(),
            domain_name: None,
        };
        let err = Pkcs11Client::connect_with_tls_files("http://127.0.0.1:9", tls_files)
            .await
            .unwrap_err();
        assert!(err.is_permanent());
        assert!(err.to_string().contains("failed to read"), "{err}");
    }

    #[tokio::test]
    async fn dead_channel_probe_is_a_transient_connect_error() {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        let mut client = Pkcs11Client::from_channel(channel);
        let err = client.get_backend_interfaces().await.unwrap_err();
        assert!(err.is_transient());
    }

    // W1-C10-03: every probe refreshes version + capability together, so
    // neither a same-version re-probe nor a version change can leave a
    // stale capability behind.
    #[tokio::test]
    async fn probe_note_refreshes_version_and_capability_together() {
        use std::sync::atomic::Ordering;
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        let client = Pkcs11Client::from_channel(channel);
        client.note_backend_probe(1, true);
        assert_eq!(client.exact_effects_version.load(Ordering::Acquire), 1);
        assert_eq!(client.cached_typed_auth_capability(), Some(true));
        // Same-version re-probe still overwrites with the fresh value.
        client.note_backend_probe(1, false);
        assert_eq!(client.cached_typed_auth_capability(), Some(false));
        // Version change carries the new version's capability.
        client.note_backend_probe(2, true);
        assert_eq!(client.exact_effects_version.load(Ordering::Acquire), 2);
        assert_eq!(client.cached_typed_auth_capability(), Some(true));
    }

    #[test]
    fn pointer_safe_message_absent_capability_is_unsafe() {
        assert!(!pointer_safe_message_parameters_from_wire(None));
    }

    #[test]
    fn pointer_safe_message_explicitly_false_capability_is_unsafe() {
        assert!(!pointer_safe_message_parameters_from_wire(Some(false)));
    }

    #[test]
    fn pointer_safe_message_advertised_capability_is_safe() {
        assert!(pointer_safe_message_parameters_from_wire(Some(true)));
    }

    /// W1-C10-10: `BackendProbe.interfaces` must use the named struct —
    /// no positional version/null-list tuple may remain at any use site.
    #[test]
    fn t32_interfaces_use_named_backend_interface() {
        let src = include_str!("lifecycle.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        // Concat-built so the pattern cannot match its own source text.
        let tuple = ["(u8, u8, Vec<", "String>)"].concat();
        assert!(!prod.contains(&tuple), "positional tuple must become the named struct");
        assert!(
            prod.contains("pub struct BackendInterface"),
            "BackendProbe.interfaces must be Vec<BackendInterface>"
        );
    }

    /// W1-C10-12: the TCP and UDS constructors must share one timeout
    /// definition — a single helper, called by both, with no duplicated
    /// literal blocks.
    #[test]
    fn t32_tcp_and_uds_share_one_timeout_definition() {
        let src = include_str!("lifecycle.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert_eq!(
            prod.matches("apply_connect_timeouts").count(),
            3,
            "one definition + two call sites (TCP + UDS)"
        );
        assert_eq!(
            prod.matches("connect_timeout(").count(),
            1,
            "connect_timeout applied once, inside the shared helper"
        );
        assert_eq!(
            prod.matches("http2_keep_alive_interval(").count(),
            1,
            "keepalive interval applied once, inside the shared helper"
        );
        assert_eq!(
            prod.matches("keep_alive_timeout(").count(),
            1,
            "keepalive timeout applied once, inside the shared helper"
        );
    }

    /// W1-C10-10: the interface triple carries named fields — no
    /// positional misread possible at any use site.
    #[test]
    fn t32_backend_interface_fields_are_named() {
        use super::BackendInterface;
        let iface = BackendInterface {
            version_major: 3,
            version_minor: 0,
            null_functions: vec!["C_SeedRandom".to_string()],
        };
        assert_eq!(iface.version_major, 3);
        assert_eq!(iface.version_minor, 0);
        assert_eq!(iface.null_functions, ["C_SeedRandom".to_string()]);
    }

    /// W1-C10-12: the connect-timeout knobs default to today's hardcoded
    /// values (connect 5 s, keepalive 10 s / 5 s, TLS handshake 10 s) —
    /// configurability must not silently change defaults.
    #[test]
    fn t32_connect_timeouts_have_documented_defaults() {
        use super::ConnectTimeouts;
        use std::time::Duration;
        let defaults = ConnectTimeouts::default();
        assert_eq!(defaults.connect, Duration::from_secs(5));
        assert_eq!(defaults.http2_keep_alive_interval, Duration::from_secs(10));
        assert_eq!(defaults.keep_alive_timeout, Duration::from_secs(5));
        assert_eq!(defaults.tls_handshake, Duration::from_secs(10));
    }

    /// W1-C10-12: the knobs round-trip through the getter/setter/builder
    /// (the `rpc_timeout` pattern from W1-C10-01).
    #[tokio::test]
    async fn t32_connect_timeouts_round_trip() {
        use super::ConnectTimeouts;
        use std::time::Duration;
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        let mut client = Pkcs11Client::from_channel(channel);
        assert_eq!(client.connect_timeouts(), ConnectTimeouts::default());
        let custom = ConnectTimeouts {
            connect: Duration::from_secs(2),
            http2_keep_alive_interval: Duration::from_secs(20),
            keep_alive_timeout: Duration::from_secs(3),
            tls_handshake: Duration::from_secs(7),
        };
        client.set_connect_timeouts(custom);
        assert_eq!(client.connect_timeouts(), custom);
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        let client = Pkcs11Client::from_channel(channel).with_connect_timeouts(custom);
        assert_eq!(client.connect_timeouts(), custom);
    }

    /// W1-L5-05: the client validates the daemon's init version range —
    /// overlap negotiates, disjoint fails loudly without storing a context.
    /// `None` bounds = legacy daemon = v1-only.
    #[test]
    fn negotiate_init_version_overlaps_or_rejects() {
        use pkcs11_proxy_ng_types::CkRv;
        assert_eq!(super::negotiate_init_version(None, None), Ok(1));
        assert_eq!(super::negotiate_init_version(Some(1), Some(1)), Ok(1));
        assert_eq!(
            super::negotiate_init_version(Some(1), Some(2)),
            Ok(1),
            "future daemon overlapping our range degrades to our max"
        );
        assert_eq!(
            super::negotiate_init_version(Some(99), Some(99)),
            Err(CkRv::FUNCTION_NOT_SUPPORTED),
            "disjoint daemon range must fail loudly at init"
        );
        assert_eq!(
            super::negotiate_init_version(Some(2), Some(3)),
            Err(CkRv::FUNCTION_NOT_SUPPORTED)
        );
    }
}
