use clap::Parser;
use std::sync::Arc;
use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

use pkcs11_proxy_ng::config;
use pkcs11_proxy_ng::mechanism_registry_source::MechanismRegistrySource;
use pkcs11_proxy_ng::server;
use pkcs11_proxy_ng::server::health;

type BoxError = Box<dyn core::error::Error>;
type Backend = Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend>;

#[derive(Debug, Parser)]
#[command(name = "pkcs11-proxy-ng", about = "PKCS#11 remote proxy daemon", version)]
struct Args {
    /// Path to daemon TOML config.
    #[arg(value_name = "CONFIG", default_value = "config.toml", value_hint = clap::ValueHint::FilePath)]
    config: std::path::PathBuf,

    /// Print the table of environment variables the daemon recognises
    /// (and the TOML field each one overrides), then exit. Closes
    /// FOLLOWUP-env-var-cli-help.
    #[arg(long)]
    print_env_vars: bool,
}

/// Wait for either SIGINT (ctrl-c) or SIGTERM, then log and return.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => tracing::info!("Received SIGINT, shutting down"),
            _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
        tracing::info!("Received SIGINT, shutting down");
    }
}

/// Log line format selected by the `LOG_FORMAT` environment variable.
/// Only `Plain` deviates from the historical JSON default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    Json,
    Plain,
}

/// Parse `LOG_FORMAT`: only `plain` (case-insensitive, surrounding
/// whitespace ignored) selects human-readable output; unset or any other
/// value keeps the historical JSON default.
fn parse_log_format(raw: Option<&str>) -> LogFormat {
    match raw.map(str::trim).map(str::to_lowercase).as_deref() {
        Some("plain") => LogFormat::Plain,
        _ => LogFormat::Json,
    }
}

fn init_tracing() {
    // Default to INFO when RUST_LOG is unset: from_default_env() falls
    // back to ERROR, which suppressed every startup line and left a
    // healthy daemon with a 0-byte log. An explicit RUST_LOG still wins.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // LOG_FORMAT=plain selects human-readable lines (README dev flow);
    // unset or anything else keeps the historical JSON default that the
    // prod/staging examples and compose files already set explicitly.
    match parse_log_format(std::env::var("LOG_FORMAT").ok().as_deref()) {
        LogFormat::Plain => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
        LogFormat::Json => {
            tracing_subscriber::fmt().with_env_filter(filter).json().init();
        }
    }
}

fn load_backend(config: &config::DaemonConfig) -> Result<Backend, BoxError> {
    let backend: Backend = Arc::new(pkcs11_proxy_ng_backend::FfiBackend::load_with_init_args(
        &config.backend.module,
        config.backend.initialize_args.as_deref(),
    )?);
    backend.initialize().map_err(|rv| format!("C_Initialize failed: {rv}"))?;
    Ok(backend)
}

async fn build_service(
    config: &config::DaemonConfig,
    backend: &Backend,
    audit_sink: Option<server::audit::AuditSink>,
) -> Result<
    (
        pkcs11_proxy_ng_proto::Pkcs11ProxyServer<server::grpc_service::Pkcs11ProxyService>,
        Arc<server::context_manager::ContextManager>,
        MechanismRegistrySource,
    ),
    BoxError,
> {
    // Warn if the deprecated mechanism_discovery setting is explicitly set to
    // a non-default value.  The server is now a pure proxy for mechanism
    // discovery; filtering has moved to the client shim.
    if config.proxy.mechanism_discovery != config::MechanismDiscovery::default() {
        tracing::warn!(
            "proxy.mechanism_discovery is deprecated and ignored; \
             the server now proxies all backend mechanisms. \
             Mechanism filtering has moved to the client shim."
        );
    }

    let context_manager = Arc::new(server::context_manager::ContextManager::new(
        std::time::Duration::from_secs(config.proxy.lease_seconds),
        config.proxy.max_contexts,
    ));

    // Backend-probe startup timeout (config.proxy.startup_timeout_secs).
    // If populate_slots takes too long the daemon exits 1 so the operator
    // sees a clear startup failure rather than a hung process.
    let startup_timeout = std::time::Duration::from_secs(config.proxy.startup_timeout_secs);
    match tokio::time::timeout(startup_timeout, context_manager.populate_slots(backend)).await {
        Ok(Ok(())) => {
            tracing::info!("Slot map populated");
        }
        Ok(Err(rv)) => {
            return Err(format!("Slot population failed: {rv}").into());
        }
        Err(_) => {
            return Err(format!(
                "Slot population exceeded proxy.startup_timeout_secs={}s; daemon refusing to start",
                config.proxy.startup_timeout_secs
            )
            .into());
        }
    }

    // Load mechanism registry from configured file (or embedded default).
    // Logged so the operator can see the served revision at startup.
    let registry_source = MechanismRegistrySource::load(config.mechanisms.config_path.as_deref())
        .map_err(|e| format!("Mechanism registry load failed: {e}"))?;
    {
        let payload = registry_source.current();
        tracing::info!(
            revision = %payload.revision,
            discovery_mode = %payload.discovery_mode,
            parameterless = payload.parameterless.len(),
            param_shapes = payload.params.len(),
            "mechanism registry ready"
        );
    }

    // The authorization (token) policy is loaded ONCE at startup and is NOT
    // reloaded on SIGHUP (unlike the mechanism registry — see
    // spawn_sighup_handler). Changing `[auth.policy]` therefore requires a
    // daemon restart, and contexts already open keep the grants captured at
    // their `C_Initialize`. (Hot policy reload is a deliberate Phase-2 item.)
    let token_policy = Arc::new(
        server::auth::policy::TokenPolicy::from_config(&config.auth)
            .map_err(std::io::Error::other)?,
    );
    // G3-PR1: refuse to start when per-object authz is configured against a
    // pre-3.0 backend that does not populate CKA_UNIQUE_ID (the gate would
    // fail-closed for every object, silently breaking all operations).
    check_per_object_version_requirement(&token_policy, backend.as_ref())?;
    let tcp_auth_mode =
        config.listener.remote.as_ref().map_or(config::TcpAuthMode::None, |tcp| tcp.auth);
    let unix_auth_mode =
        config.listener.local.as_ref().map_or(config::UnixAuthMode::PeerCred, |uds| uds.auth);
    let sanitize_inputs = config.proxy.sanitize_inputs;
    let service = {
        let svc = server::grpc_service::Pkcs11ProxyService::new(
            context_manager.clone(),
            backend.clone(),
            tcp_auth_mode,
            unix_auth_mode,
            token_policy,
            registry_source.clone(),
            audit_sink,
        );
        if sanitize_inputs { svc.with_sanitize_inputs() } else { svc }
    };
    let grpc_service = pkcs11_proxy_ng_proto::Pkcs11ProxyServer::new(service)
        .max_decoding_message_size(config.proxy.max_message_bytes)
        .max_encoding_message_size(config.proxy.max_message_bytes);

    Ok((grpc_service, context_manager, registry_source))
}

/// Apply the configured transport concurrency limits to a tonic server
/// builder (W1-L6-20). Shared by every listener so TCP and Unix get
/// identical flood bounds: per-connection request cap + HTTP/2 max
/// concurrent streams + load shedding (reject-over-limit with
/// `RESOURCE_EXHAUSTED` instead of buffering unboundedly).
fn apply_transport_limits(builder: Server, config: &config::DaemonConfig) -> Server {
    builder
        .concurrency_limit_per_connection(config.proxy.grpc_concurrency_limit_per_connection)
        .max_concurrent_streams(config.proxy.grpc_max_concurrent_streams)
        .load_shed(config.proxy.grpc_load_shed)
}

/// Apply the configured HTTP/2 keepalive settings to a tonic server builder.
/// Shared by every listener so TCP and Unix get identical keepalive behaviour.
fn apply_http2_keepalive(builder: Server, config: &config::DaemonConfig) -> Server {
    if config.proxy.http2_keepalive_interval_secs > 0 {
        builder
            .http2_keepalive_interval(Some(std::time::Duration::from_secs(
                config.proxy.http2_keepalive_interval_secs,
            )))
            .http2_keepalive_timeout(Some(std::time::Duration::from_secs(
                config.proxy.http2_keepalive_timeout_secs,
            )))
    } else {
        builder
    }
}

/// A per-listener graceful-shutdown future driven by the shared signal channel.
/// Resolves when the OS-signal task flips the watch value (or drops the sender).
async fn listener_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    let _ = rx.changed().await;
}

type ServeFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(), tonic::transport::Error>> + Send>,
>;

/// Serve until the shutdown signal, then drain bounded by
/// `proxy.shutdown_grace_secs` (W1-L6-07).
///
/// The grace clock starts at **signal receipt**, not at startup: the join
/// over the serve futures races the `signal` future, and only the
/// post-signal drain runs under `timeout(grace, …)`. Pre-signal serve
/// time is unbounded (a listener that never exits and no signal means
/// the daemon keeps serving); a join that completes on its own
/// (listener error exit) propagates immediately without waiting for
/// the signal.
///
/// Returns `Some(outcome)` when the join finishes — either before the
/// signal or inside the post-signal grace (errors propagate unchanged);
/// returns `None` when the post-signal grace expires first — the serve
/// futures are then dropped, aborting in-flight connections, and the
/// caller proceeds with forced shutdown (socket cleanup, audit flush,
/// backend finalize) instead of pinning SIGTERM forever on a wedged
/// backend.
async fn serve_with_grace(
    serve_futures: Vec<ServeFuture>,
    signal: impl std::future::Future<Output = ()>,
    grace: std::time::Duration,
) -> Option<Result<Vec<()>, tonic::transport::Error>> {
    let mut drain = Box::pin(futures::future::try_join_all(serve_futures));
    tokio::pin!(signal);
    // Phase 1 (unbounded): serve until the listeners exit on their own
    // or the shutdown signal arrives, whichever comes first. Biased
    // toward the listener outcome so a concurrent listener error still
    // propagates as the exit cause.
    let pre_signal_outcome = tokio::select! {
        biased;
        outcome = &mut drain => Some(outcome),
        () = &mut signal => None,
    };
    // Phase 2 (bounded): only after the signal, drain under the grace.
    // (A separate step rather than a third select branch so `drain`
    // moves into the timeout cleanly once the phase-1 borrows end.)
    match pre_signal_outcome {
        Some(outcome) => Some(outcome),
        None => match tokio::time::timeout(grace, drain).await {
            Ok(outcome) => Some(outcome),
            Err(_elapsed) => {
                tracing::error!(
                    grace_secs = grace.as_secs(),
                    "shutdown grace expired with listeners still draining; \
                     forcing shutdown (in-flight connections aborted)"
                );
                None
            }
        },
    }
}

/// G3-PR1: refuse to start when per-object authorization is configured but the
/// backend does not support PKCS#11 v3.0+.
///
/// Per-object authorization relies on `CKA_UNIQUE_ID`, which was introduced in
/// PKCS#11 v3.0.  A pre-3.0 backend will never populate the attribute, so the
/// gate would fail-closed for every object — silently breaking all operations.
/// Refusing to start gives operators an immediate, actionable error instead of
/// a silent runtime outage.
///
/// Extracted as a pure function so it can be unit-tested without loading a real
/// PKCS#11 module.
fn check_per_object_version_requirement(
    token_policy: &server::auth::policy::TokenPolicy,
    backend: &dyn pkcs11_proxy_ng_backend::Pkcs11Backend,
) -> Result<(), BoxError> {
    if !token_policy.per_object_active() {
        return Ok(());
    }
    let info = backend.get_info().map_err(|rv| format!("C_GetInfo failed: {rv}"))?;
    let (maj, min) = info.cryptoki_version;
    if (maj, min) < (3, 0) {
        return Err(format!(
            "per-object authorization ([auth.policy] grants with `objects`) requires a \
             PKCS#11 v3.0+ token that populates CKA_UNIQUE_ID; this backend reports \
             v{maj}.{min}. Remove the `objects` grants or use a v3.0+ token."
        )
        .into());
    }
    Ok(())
}

/// Early, friendly validation of runtime listener support. The Unix socket
/// transport is now wired (peer-cred auth); this only surfaces a clear error
/// when the configured socket's parent directory does not exist, rather than
/// failing deep inside `bind()`.
fn validate_runtime_listener_support(config: &config::DaemonConfig) -> Result<(), BoxError> {
    // The Unix-socket transport (and its SO_PEERCRED authentication) does not
    // exist on non-Unix hosts; a Windows daemon serves mTLS TCP only.
    #[cfg(not(unix))]
    if config.listener.local.is_some() {
        return Err("[listener.local] (unix socket + peer-cred) is not supported on this OS; \
             configure [listener.remote] with auth = 'mtls' instead"
            .into());
    }
    if let Some(ref uds) = config.listener.local
        && let Some(parent) = uds.path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.is_dir()
    {
        return Err(format!(
            "unix socket directory does not exist: {} (for listener.local.path = {})",
            parent.display(),
            uds.path.display()
        )
        .into());
    }
    Ok(())
}

/// On SIGHUP the daemon reloads `mechanisms.config_path` and swaps the
/// served payload atomically. Reload failures retain the current
/// registry — the daemon must never crash because the operator pushed
/// a malformed TOML file mid-rollout.
///
/// NOTE: only the mechanism registry is reloaded. The `[auth.policy]`
/// authorization policy is load-once (see `token_policy` in `main`); changing
/// it requires a daemon restart.
#[cfg(unix)]
fn spawn_sighup_handler(registry_source: MechanismRegistrySource) {
    tokio::spawn(async move {
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "failed to install SIGHUP handler");
                return;
            }
        };
        while sighup.recv().await.is_some() {
            match registry_source.reload() {
                Ok(payload) => tracing::info!(
                    revision = %payload.revision,
                    discovery_mode = %payload.discovery_mode,
                    parameterless = payload.parameterless.len(),
                    param_shapes = payload.params.len(),
                    "mechanism registry reloaded"
                ),
                Err(e) => tracing::error!(
                    error = %e,
                    config_path = ?registry_source.config_path(),
                    "mechanism registry reload failed; retaining previous registry"
                ),
            }
        }
    });
}

/// Bridge between `spawn_backend`'s outcome channel and the
/// `tonic-health` reporter. Counts consecutive backend failures; flips
/// the per-service health status to `NOT_SERVING` once the count
/// reaches `threshold`, and flips it back to `SERVING` on the next
/// successful backend call. Driven by `proxy.backend_health_consecutive_failures`.
fn spawn_backend_health_gate(
    mut rx: tokio::sync::mpsc::Receiver<server::grpc_service::service_utils::BackendHealthEvent>,
    mut reporter: tonic_health::server::HealthReporter,
    threshold: u32,
) {
    tracing::info!(threshold, "backend health gate starting");
    tokio::spawn(async move {
        use server::grpc_service::service_utils::BackendHealthEvent;
        let mut consecutive_failures: u32 = 0;
        // We assume the daemon enters this task already in the SERVING
        // state — the spawn point in `async_main` calls
        // `health::set_serving` immediately before us.
        let mut currently_serving = true;
        while let Some(event) = rx.recv().await {
            tracing::debug!(?event, consecutive_failures, "backend health event received");
            match event {
                BackendHealthEvent::Success => {
                    let prior_failures = consecutive_failures;
                    consecutive_failures = 0;
                    if !currently_serving {
                        tracing::info!(
                            recovered_after = prior_failures,
                            "backend recovered; flipping readiness back to SERVING"
                        );
                        health::set_serving(&mut reporter).await;
                        currently_serving = true;
                    }
                }
                BackendHealthEvent::Failure => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    if currently_serving && consecutive_failures >= threshold {
                        tracing::warn!(
                            consecutive_failures,
                            threshold,
                            "backend exceeded failure threshold; flipping readiness to NOT_SERVING"
                        );
                        health::set_not_serving(&mut reporter).await;
                        currently_serving = false;
                    }
                }
            }
        }
        tracing::debug!("backend health-gate channel closed; task exiting");
    });
}

fn spawn_eviction_task(
    context_manager: Arc<server::context_manager::ContextManager>,
    backend: Backend,
    eviction_interval_secs: u64,
    max_contexts: usize,
    max_concurrent_backend_calls: usize,
    max_stuck_backend_calls: Option<u64>,
) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(eviction_interval_secs));
        loop {
            interval.tick().await;
            let expired = context_manager.evict_expired(&backend).await;
            if !expired.is_empty() {
                tracing::info!(count = expired.len(), "Evicted expired contexts");
            }

            // Resource-aware logging
            let ctx_count = context_manager.context_count();
            if max_contexts > 0 && ctx_count > max_contexts * 80 / 100 {
                tracing::warn!(contexts = ctx_count, max = max_contexts, "context usage above 80%");
            }
            let in_flight = server::grpc_service::service_utils::backend_in_flight();
            if in_flight > max_concurrent_backend_calls * 80 / 100 {
                tracing::warn!(
                    in_flight,
                    max = max_concurrent_backend_calls,
                    "backend call usage above 80%"
                );
            }

            // Opt-in fail-fast: a token wedged past the configured stuck-call
            // limit is a permanent condition the daemon can only escape via a
            // supervisor restart. Exit nonzero so systemd/k8s recycles us.
            let stuck = server::grpc_service::service_utils::stuck_backend_calls();
            if stuck > 0 {
                tracing::warn!(stuck_calls = stuck, "backend calls wedged past their timeout");
            }
            if config::should_exit_on_stuck_calls(stuck as u64, max_stuck_backend_calls) {
                tracing::error!(
                    stuck_calls = stuck,
                    limit = ?max_stuck_backend_calls,
                    "stuck backend calls exceeded proxy.max_stuck_backend_calls; \
                     exiting for supervisor restart"
                );
                std::process::exit(70); // EX_SOFTWARE
            }
        }
    });
}

fn main() -> Result<(), BoxError> {
    // Parse early so --print-env-vars doesn't pull in JSON tracing.
    let args = Args::parse();
    if args.print_env_vars {
        print!("{}", config::env_var_help());
        return Ok(());
    }
    init_tracing();

    let config = config::DaemonConfig::load(&args.config)?;
    validate_runtime_listener_support(&config)?;
    // Hook-gated control plane (C3M.6 row 18): fail closed BEFORE backend
    // load. Validating after the load (TO26b negative-leg finding) drops
    // a live backend on the error path, so the final-owner guard
    // stop-fires 70 and swallows this message; refusing here exits 1 with
    // the message intact and never touches provider code.
    server::validate_test_hooks_config(&config).map_err(std::io::Error::other)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(config.proxy.max_blocking_threads)
        .build()?;

    runtime.block_on(async_main(config))
}

async fn async_main(config: config::DaemonConfig) -> Result<(), BoxError> {
    validate_runtime_listener_support(&config)?;

    // Initialise the audit sink (off by default → Ok(None); zero behaviour change
    // when [audit] is absent or audit.dir is not set).
    let audit_sink = server::audit::spawn_audit_sink(&config.audit)
        .map_err(|e| format!("audit sink failed to initialise: {e}"))?;

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health::set_not_serving(&mut health_reporter).await;

    let backend = load_backend(&config)?;
    tracing::info!("Backend module loaded and initialized");

    server::grpc_service::service_utils::configure_backend_guard(
        config.proxy.request_timeout_secs,
        config.proxy.max_concurrent_backend_calls,
    );
    server::grpc_service::service_utils::configure_login_lock_timeout(
        config.proxy.login_lock_timeout_secs,
    );

    // Configure per-peer rate limiter for GetBackendInterfaces.
    // Disabled by default (max_per_window=0); production deployments
    // can set proxy.rate_limit_get_backend_interfaces to enable.
    // (Unauthenticated Initialize has its own always-on per-IP budget —
    // W1-L7-03 — which needs no configuration.)
    server::rate_limit::configure(
        std::time::Duration::from_secs(config.proxy.rate_limit_window_secs),
        config.proxy.rate_limit_get_backend_interfaces,
    );

    server::resilience::configure(
        config.resilience.find_result_warn_threshold,
        config.resilience.coalesce_attributes,
    );
    server::rate_quota::configure(&config.rate_limit);

    if let Some(ref sock) = config.resilience.metrics_socket {
        server::resilience::spawn_metrics_endpoint(sock.clone())
            .await
            .map_err(|e| format!("failed to bind metrics socket {}: {e}", sock.display()))?;
        tracing::info!(path = %sock.display(), "resilience metrics endpoint bound");
    }

    // Hook-gated control plane (C3M.6 row 18): the fail-closed check ran
    // in `main` before backend load; bind the control socket here.
    #[cfg(feature = "native-owner-test-hooks")]
    if let Some(ref sock) = config.test_hooks.control_socket {
        server::control::spawn_control_endpoint(sock.clone())
            .await
            .map_err(|e| format!("failed to bind control socket {}: {e}", sock.display()))?;
        tracing::info!(path = %sock.display(), "test-hooks control endpoint bound");
    }

    let (svc, context_manager, registry_source) =
        build_service(&config, &backend, audit_sink.clone()).await?;

    // Emit startup attestation (ADR-0012 G1 §3): captures module hash,
    // library version, and token serial/model/firmware at load time.
    // Best-effort: a dropped record is logged but does NOT abort startup.
    server::attestation::emit_startup_attestation(&audit_sink, &backend, &config).await;

    // Loud one-time warning if TCP listener is running without auth
    // (the design's default for SaaS deployments behind external
    // network protection). Stays visible in operator log scans.
    if let Some(tcp) = config.listener.remote.as_ref()
        && matches!(tcp.auth, config::TcpAuthMode::None)
        && tcp.allow_insecure_tcp
    {
        tracing::warn!(
            bind = %tcp.bind,
            "listening on tcp without authentication; relying on external network \
             protection (k8s NetworkPolicy / VPC). do not use in untrusted networks."
        );
    }

    // Loud one-time warning if the Unix listener runs without peer-credential
    // auth (requires the explicit allow_insecure_unix opt-in to even start).
    if let Some(local) = config.listener.local.as_ref()
        && matches!(local.auth, config::UnixAuthMode::None)
        && local.allow_insecure_unix
    {
        tracing::warn!(
            path = %local.path.display(),
            "listening on unix socket without peer-credential authentication; every \
             local user can reach every token. only for trusted single-user hosts."
        );
    }

    // Wire backend-health gating: spawn_backend reports each outcome
    // through a BOUNDED channel (L11 — never grows without bound under a failure
    // storm); this task counts consecutive transport-level failures and flips
    // tonic-health to NOT_SERVING once
    // `proxy.backend_health_consecutive_failures` is exceeded. The producer uses
    // try_send, dropping on a full buffer (safe: Success is coalesced to rare
    // transitions, and a full buffer already holds far more failures than the
    // flip threshold).
    let (health_tx, health_rx) = tokio::sync::mpsc::channel(256);
    server::grpc_service::service_utils::configure_backend_health_events(health_tx);
    spawn_backend_health_gate(
        health_rx,
        health_reporter.clone(),
        config.proxy.backend_health_consecutive_failures,
    );

    // Install SIGHUP handler so operators can reload the mechanism
    // registry without restarting the daemon. Reload failure retains
    // the current registry and logs an error rather than crashing.
    #[cfg(unix)]
    spawn_sighup_handler(registry_source.clone());
    // No SIGHUP on non-Unix hosts: the registry stays as loaded at startup;
    // a registry change requires a daemon restart there.
    #[cfg(not(unix))]
    let _ = &registry_source;
    // One OS-signal future fans out to every listener via a watch channel so
    // the TCP and Unix listeners shut down together on SIGINT/SIGTERM.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    // Bind every configured listener *before* flipping Health/SERVING. The
    // consumer matrix surfaced a race where shim consumers saw the gRPC health
    // probe report SERVING but their connect was refused because tonic hadn't
    // bound yet. Binding here makes the SERVING flip below truthful: by the
    // time external probes can see it, accept() is already running.
    let mut serve_futures: Vec<ServeFuture> = Vec::new();

    // TCP listener (mTLS / insecure-tcp), when [listener.remote] is configured.
    if let Some(ref tcp_cfg) = config.listener.remote {
        let addr: std::net::SocketAddr = tcp_cfg.bind.parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr().unwrap_or(addr);
        let mut builder = Server::builder();
        if let Some(tls_config) =
            server::transport::server_tls_config(tcp_cfg).map_err(std::io::Error::other)?
        {
            builder = builder.tls_config(tls_config)?;
        }
        let router = apply_transport_limits(apply_http2_keepalive(builder, &config), &config)
            .layer(server::trace_id::TraceIdLayer)
            // ADR-0013 pre-decode validation inside the trace layer so
            // rejections inherit the request_id span. First `.layer()` is
            // outermost: trace wraps validation wraps the routes.
            .layer(server::protected_decode::ProtectedDecodeLayer::new(
                config.proxy.max_message_bytes,
            ))
            .add_service(health_service.clone())
            .add_service(svc.clone());
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let shutdown = listener_shutdown(shutdown_rx.clone());
        tracing::info!(addr = %local_addr, auth = ?tcp_cfg.auth, "listening on tcp");
        serve_futures.push(Box::pin(router.serve_with_incoming_shutdown(incoming, shutdown)));
    }

    // Unix-domain-socket listener (peer-cred / none), when [listener.local] is
    // configured. No TLS: SO_PEERCRED is the local-IPC authentication (ADR-0005).
    // Not compiled on non-Unix hosts — validate_runtime_listener_support has
    // already rejected a [listener.local] config there.
    #[cfg(unix)]
    if let Some(ref uds_cfg) = config.listener.local {
        let listener = server::transport::bind_unix_listener(&uds_cfg.path)?;
        let router =
            apply_transport_limits(apply_http2_keepalive(Server::builder(), &config), &config)
                .layer(server::trace_id::TraceIdLayer)
                // ADR-0013 pre-decode validation (see the TCP listener above for
                // the layer-order rationale).
                .layer(server::protected_decode::ProtectedDecodeLayer::new(
                    config.proxy.max_message_bytes,
                ))
                .add_service(health_service.clone())
                .add_service(svc.clone());
        let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);
        let shutdown = listener_shutdown(shutdown_rx.clone());
        tracing::info!(path = %uds_cfg.path.display(), auth = ?uds_cfg.auth, "listening on unix socket");
        serve_futures.push(Box::pin(router.serve_with_incoming_shutdown(incoming, shutdown)));
    }

    health::set_serving(&mut health_reporter).await;
    spawn_eviction_task(
        context_manager,
        backend.clone(),
        config.proxy.eviction_interval_secs,
        config.proxy.max_contexts,
        config.proxy.max_concurrent_backend_calls,
        config.proxy.max_stuck_backend_calls,
    );

    tracing::info!(
        lease_seconds = config.proxy.lease_seconds,
        max_message_bytes = config.proxy.max_message_bytes,
        request_timeout_secs = config.proxy.request_timeout_secs,
        max_concurrent_backend_calls = config.proxy.max_concurrent_backend_calls,
        max_blocking_threads = config.proxy.max_blocking_threads,
        eviction_interval_secs = config.proxy.eviction_interval_secs,
        max_contexts = config.proxy.max_contexts,
        http2_keepalive_interval_secs = config.proxy.http2_keepalive_interval_secs,
        http2_keepalive_timeout_secs = config.proxy.http2_keepalive_timeout_secs,
        grpc_concurrency_limit_per_connection = config.proxy.grpc_concurrency_limit_per_connection,
        grpc_max_concurrent_streams = config.proxy.grpc_max_concurrent_streams,
        grpc_load_shed = config.proxy.grpc_load_shed,
        "Starting gRPC server"
    );
    // NOTE: No tonic server-level .timeout() — request timeouts are handled
    // inside spawn_backend() via tokio::time::timeout. A tonic-level timeout
    // would cancel the handler Future before spawn_backend can decrement
    // IN_FLIGHT, causing circuit breaker leaks under heavy load.
    // W1-L6-07: the post-signal drain honors proxy.shutdown_grace_secs
    // (previously the validated knob was never read and a wedged backend
    // pinned SIGTERM forever). The grace clock starts when the shared
    // signal channel flips — pre-signal serve time is unbounded — and on
    // expiry the serve futures are dropped (aborting in-flight
    // connections) and shutdown proceeds forced.
    let serve_result = serve_with_grace(
        serve_futures,
        listener_shutdown(shutdown_rx),
        std::time::Duration::from_secs(config.proxy.shutdown_grace_secs),
    )
    .await;

    // Best-effort: remove the Unix socket file on shutdown so a restart can
    // rebind cleanly (the path persists in the filesystem after the fd closes).
    #[cfg(unix)]
    if let Some(ref uds_cfg) = config.listener.local {
        let _ = std::fs::remove_file(&uds_cfg.path);
    }
    if let Some(result) = serve_result {
        result?;
    }

    // Flush the audit log before finalising the backend.
    if let Some(ref s) = audit_sink
        && let Err(e) = s.flush().await
    {
        tracing::error!(error = %e, "audit flush on shutdown failed");
    }

    let finalize_outcome = backend.finalize();
    if let Err(rv) = &finalize_outcome {
        tracing::error!(error = %rv, "C_Finalize failed; backend drop follows");
    }
    finalize_outcome.map_err(|rv| format!("C_Finalize failed: {rv}"))?;
    tracing::info!("Daemon stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_config(toml: &str) -> config::DaemonConfig {
        toml::from_str(toml).expect("test config should parse")
    }

    #[test]
    fn runtime_accepts_mtls_listener_when_transport_is_wired() {
        let cfg = parse_config(
            r#"
[backend]
module = "/dev/null"

[listener.remote]
bind = "127.0.0.1:50051"
auth = "mtls"
ca_cert = "/dev/null"
server_cert = "/dev/null"
server_key = "/dev/null"

[auth]
allow_all_authenticated = true
"#,
        );

        validate_runtime_listener_support(&cfg).expect("mTLS runtime support is wired");
    }

    #[test]
    fn runtime_accepts_explicit_insecure_tcp_listener() {
        let cfg = parse_config(
            r#"
[backend]
module = "/dev/null"

[listener.remote]
bind = "127.0.0.1:50051"
auth = "none"
allow_insecure_tcp = true
"#,
        );

        validate_runtime_listener_support(&cfg).expect("explicit insecure TCP dev mode");
    }

    #[test]
    fn runtime_accepts_unix_listener_with_existing_dir() {
        // The Unix transport is now wired (peer-cred auth); a socket in an
        // existing directory must pass runtime validation.
        let cfg = parse_config(
            r#"
[backend]
module = "/dev/null"

[listener.local]
path = "/tmp/pkcs11-proxy-ng-test.sock"
auth = "peer_cred"
"#,
        );

        validate_runtime_listener_support(&cfg)
            .expect("unix listener with an existing parent dir is supported");
    }

    #[test]
    fn runtime_rejects_unix_listener_with_missing_dir() {
        // A missing socket directory should fail fast with a clear message
        // rather than deep inside bind().
        let cfg = parse_config(
            r#"
[backend]
module = "/dev/null"

[listener.local]
path = "/nonexistent-dir-pkcs11-proxy-ng/sock"
auth = "peer_cred"
"#,
        );

        let err = validate_runtime_listener_support(&cfg).unwrap_err().to_string();
        assert!(err.contains("unix socket directory does not exist"), "clear dir error: {err}");
    }

    // --- per-object version guard tests ---

    fn per_object_policy() -> server::auth::policy::TokenPolicy {
        use pkcs11_proxy_ng::config::{
            AuthConfig, ExtractPolicyConfig, GrantSpec, PolicyEntry, RichGrantConfig,
            TokenAccessSpec,
        };
        server::auth::policy::TokenPolicy::from_config(&AuthConfig {
            allow_all_authenticated: false,
            anonymous_principal: None,
            policy: vec![PolicyEntry {
                identity: "uid=1000".into(),
                tokens: TokenAccessSpec::Specific(vec![GrantSpec::Rich(RichGrantConfig {
                    token: "label:TestToken".into(),
                    classes: None,
                    mechanisms: None,
                    extract: ExtractPolicyConfig::Allow,
                    objects: Some(vec![pkcs11_proxy_ng::config::ObjectAclSpec::Bare(
                        "aabbcc".into(),
                    )]),
                })]),
            }],
        })
        .expect("policy parses")
    }

    fn no_objects_policy() -> server::auth::policy::TokenPolicy {
        server::auth::policy::TokenPolicy::from_config(
            &pkcs11_proxy_ng::config::AuthConfig::default(),
        )
        .expect("default policy parses")
    }

    #[test]
    fn startup_refuses_v240_backend_when_per_object_policy_configured() {
        // G3-PR1: a v2.40 backend does not populate CKA_UNIQUE_ID; the daemon
        // must refuse to start rather than silently fail-closing every object.
        let mock = pkcs11_proxy_ng_backend::MockBackend::new(
            vec![pkcs11_proxy_ng_types::CkSlotId(0)],
            vec![],
        )
        .with_cryptoki_version(2, 40);
        let policy = per_object_policy();
        let err = check_per_object_version_requirement(&policy, &mock).unwrap_err().to_string();
        assert!(err.contains("v2.40"), "error message must mention the backend version: {err}");
        assert!(
            err.contains("CKA_UNIQUE_ID") || err.contains("v3.0"),
            "error message must reference v3.0+ requirement: {err}"
        );
    }

    #[test]
    fn startup_allows_v30_backend_with_per_object_policy() {
        // A v3.0 backend can populate CKA_UNIQUE_ID — the check must pass.
        let mock = pkcs11_proxy_ng_backend::MockBackend::new(
            vec![pkcs11_proxy_ng_types::CkSlotId(0)],
            vec![],
        );
        // MockBackend default is (3,0).
        let policy = per_object_policy();
        check_per_object_version_requirement(&policy, &mock)
            .expect("v3.0 backend with per-object policy must start");
    }

    /// `LOG_FORMAT` selects the daemon's log line format. Only `plain`
    /// (case-insensitive, surrounding whitespace ignored) selects
    /// human-readable output; unset or any other value keeps the
    /// historical JSON default — so existing `LOG_FORMAT=json`
    /// deployments and the hardcoded-JSON past behave identically.
    #[test]
    fn log_format_parses_documented_values() {
        assert_eq!(parse_log_format(None), LogFormat::Json);
        assert_eq!(parse_log_format(Some("json")), LogFormat::Json);
        assert_eq!(parse_log_format(Some("plain")), LogFormat::Plain);
        assert_eq!(parse_log_format(Some("  PLAIN  ")), LogFormat::Plain);
        assert_eq!(parse_log_format(Some("xml")), LogFormat::Json);
        assert_eq!(parse_log_format(Some("")), LogFormat::Json);
    }

    #[test]
    fn startup_allows_v240_backend_without_per_object_policy() {
        // When no `objects` grants are configured, the version check is skipped
        // entirely — existing deployments without per-object policy must not be
        // broken.
        let mock = pkcs11_proxy_ng_backend::MockBackend::new(
            vec![pkcs11_proxy_ng_types::CkSlotId(0)],
            vec![],
        )
        .with_cryptoki_version(2, 40);
        let policy = no_objects_policy();
        check_per_object_version_requirement(&policy, &mock)
            .expect("v2.40 backend without per-object policy must start");
    }

    /// W1-L6-07: listeners that exit on their own (pre-signal) return
    /// their `try_join_all` outcome unchanged, without waiting for the
    /// signal.
    #[tokio::test]
    async fn serve_with_grace_returns_outcome_when_drained_in_time() {
        let futures: Vec<ServeFuture> =
            vec![Box::pin(async { Ok(()) }), Box::pin(async { Ok(()) })];
        let outcome =
            serve_with_grace(futures, std::future::pending(), std::time::Duration::from_secs(30))
                .await;
        assert!(matches!(outcome, Some(Ok(_))), "drained listeners must propagate Ok");
    }

    /// W1-L6-07: after the signal, a wedged listener (never resolves)
    /// must not pin SIGTERM forever — the grace bounds the post-signal
    /// drain, then the serve futures are dropped (aborting in-flight
    /// connections) and shutdown proceeds.
    #[tokio::test]
    async fn serve_with_grace_bounds_a_wedged_listener() {
        let futures: Vec<ServeFuture> =
            vec![Box::pin(async { Ok(()) }), Box::pin(std::future::pending())];
        let start = std::time::Instant::now();
        let outcome =
            serve_with_grace(futures, std::future::ready(()), std::time::Duration::from_millis(50))
                .await;
        assert!(outcome.is_none(), "wedged listeners must time out to forced shutdown");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "grace wait must be bounded, took {:?}",
            start.elapsed()
        );
    }

    /// W1-L6-07: a pre-signal serve error propagates immediately (the
    /// daemon must exit on listener failure without waiting for a
    /// signal that may never come).
    #[tokio::test]
    async fn serve_with_grace_propagates_serve_errors() {
        // try_join_all short-circuits on the first error; a ready error
        // must surface even with ample grace left. (A malformed endpoint
        // URI is the cheapest way to fabricate a transport::Error.)
        let err = tonic::transport::Endpoint::from_shared("http://exa mple.com").unwrap_err();
        let futures: Vec<ServeFuture> = vec![Box::pin(async move { Err(err) })];
        let outcome =
            serve_with_grace(futures, std::future::pending(), std::time::Duration::from_secs(30))
                .await;
        assert!(matches!(outcome, Some(Err(_))), "serve errors must propagate");
    }

    /// W1-L6-07 fix round: the grace clock must start at signal receipt,
    /// not at startup. With no signal and no listener exit, the helper
    /// stays pending far past the grace (pre-signal serve time is
    /// unbounded) — the daemon must not force-exit `grace` after boot.
    #[tokio::test]
    async fn serve_with_grace_does_not_bound_pre_signal_uptime() {
        let futures: Vec<ServeFuture> = vec![Box::pin(std::future::pending())];
        let outcome = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            serve_with_grace(futures, std::future::pending(), std::time::Duration::from_millis(50)),
        )
        .await;
        assert!(
            outcome.is_err(),
            "pre-signal serve must stay pending past the grace (10x overrun)"
        );
    }

    /// W1-L6-07 fix round: post-signal drain obeys the grace the other
    /// way — a drain that finishes inside the grace returns its outcome
    /// (the wedged-listener test above pins the expiry way).
    #[tokio::test]
    async fn serve_with_grace_returns_post_signal_drain_outcome() {
        let (tx, mut signal_rx) = tokio::sync::watch::channel(false);
        let mut serve_rx = tx.subscribe();
        // Signal future: resolves when the "SIGTERM" flips the channel.
        let signal = async move {
            let _ = signal_rx.changed().await;
        };
        // Serve future: drains only after the signal, then succeeds
        // inside the grace.
        let serve: ServeFuture = Box::pin(async move {
            let _ = serve_rx.changed().await;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            Ok(())
        });
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let _ = tx.send(true);
        });
        let outcome =
            serve_with_grace(vec![serve], signal, std::time::Duration::from_secs(5)).await;
        assert!(
            matches!(outcome, Some(Ok(_))),
            "post-signal drain inside the grace must propagate Ok"
        );
    }
}
